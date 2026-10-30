package sentinelplugin

import (
    "bufio"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
)

const PersistentProtocolVersion = 1
const maxPersistentFrame = 32768

// PersistentHandler handles commands without restarting the plugin process.
// Host APIs are explicitly brokered and require capabilities in plugin.yaml.
type PersistentHandler func(map[string]string, *HostServices) (Result,error)

type PersistentApp struct {
    commands map[string]PersistentHandler
    onStart func() error
    onStop func()
}
func NewPersistent() *PersistentApp {return &PersistentApp{commands:make(map[string]PersistentHandler)}}
// OnStart registers a process-local initialization hook. It runs once before
// the RPC health handshake succeeds. Registration is not a host capability.
func (a *PersistentApp) OnStart(fn func() error) {
    a.onStart = fn
}

// OnStop registers a best-effort cleanup hook for clean EOF or handler errors.
// Abrupt process termination and OS kills cannot guarantee execution.
func (a *PersistentApp) OnStop(fn func()) {
    a.onStop = fn
}

func (a *PersistentApp) Command(name string,fn PersistentHandler) error {
    if !commandName.MatchString(name)||fn==nil{return errors.New("invalid persistent plugin handler")}
    if _,ok:=a.commands[name];ok{return errors.New("duplicate command")}
    a.commands[name]=fn
    return nil
}

type persistentFrame struct {
    Version int `json:"version"`
    Type string `json:"type"`
    Token string `json:"token"`
    ID string `json:"id,omitempty"`
    Command string `json:"command,omitempty"`
    Args map[string]string `json:"args,omitempty"`
    Text string `json:"text,omitempty"`
    View string `json:"view,omitempty"`
    Values map[string]string `json:"values,omitempty"`
    Error string `json:"error,omitempty"`
    Service string `json:"service,omitempty"`
    Key string `json:"key,omitempty"`
    Data json.RawMessage `json:"data,omitempty"`
    Found bool `json:"found,omitempty"`
    Topic string `json:"topic,omitempty"`
    Detail string `json:"detail,omitempty"`
}
type HostServices struct {
    token string
    input *bufio.Scanner
    output *json.Encoder
    sequence int
}
func (h *HostServices)call(request persistentFrame)(persistentFrame,error){
    h.sequence++
    request.Version=PersistentProtocolVersion
    request.Type="service"
    request.Token=h.token
    request.ID=fmt.Sprintf("%d",h.sequence)
    if err:=h.output.Encode(request);err!=nil{return persistentFrame{},err}
    if !h.input.Scan(){return persistentFrame{},errors.New("host service channel closed")}
    var result persistentFrame
    if err:=json.Unmarshal(h.input.Bytes(),&result);err!=nil{return result,err}
    if result.Version!=PersistentProtocolVersion||result.Type!="service-result"||result.Token!=h.token||result.ID!=request.ID||result.Service!=request.Service{
        return result,errors.New("host service response mismatched")
    }
    if result.Error!=""{return result,fmt.Errorf("host service denied: %.180s",result.Error)}
    return result,nil
}
func(h *HostServices)Get(key string)(json.RawMessage,bool,error){
    r,err:=h.call(persistentFrame{Service:"storage.get",Key:key})
    return r.Data,r.Found,err
}
func(h *HostServices)Put(key string,data json.RawMessage)error{
    if len(data)==0||len(data)>8192||!json.Valid(data){return errors.New("invalid host storage payload")}
    _,err:=h.call(persistentFrame{Service:"storage.put",Key:key,Data:data})
    return err
}
func(h *HostServices)Delete(key string)error{
    _,err:=h.call(persistentFrame{Service:"storage.delete",Key:key})
    return err
}
func(h *HostServices)Publish(topic,detail string)error{
    _,err:=h.call(persistentFrame{Service:"events.publish",Topic:topic,Detail:detail})
    return err
}

// ServerMetrics exposes safe, coarse server metrics through an explicit
// server.metrics manifest grant. It never includes user identities or secrets.
type ServerMetrics struct {
    ActiveSessions int64 `json:"active_sessions"`
    UptimeSeconds int64 `json:"uptime_seconds"`
}
func (h *HostServices) ServerMetrics() (ServerMetrics,error) {
    response,err:=h.call(persistentFrame{Service:"server.metrics"})
    if err!=nil{return ServerMetrics{},err}
    var metrics ServerMetrics
    if err:=json.Unmarshal(response.Data,&metrics);err!=nil{return ServerMetrics{},err}
    return metrics,nil
}

// PublishUI updates bounded display-only values in the plugin's own namespace.
// Values expire automatically unless refreshed. Requires ui.publish in plugin.yaml.
func(h *HostServices)PublishUI(values map[string]string)error{
 data,err:=json.Marshal(values)
 if err!=nil || len(data)>8192{return errors.New("invalid UI publish payload")}
 _,err=h.call(persistentFrame{Service:"ui.publish",Data:data})
 return err
}

// Serve handles sequential JSON-line requests on the authenticated pipe.
func(a *PersistentApp)Serve()error{return a.ServeIO(os.Stdin,os.Stdout)}
func(a *PersistentApp)ServeIO(in io.Reader,out io.Writer)error{
    if a.onStart != nil {
        if err:=a.onStart();err!=nil{return fmt.Errorf("plugin startup failed: %w",err)}
    }
    if a.onStop != nil {defer a.onStop()}
    reader:=bufio.NewScanner(in)
    reader.Buffer(make([]byte,4096),maxPersistentFrame)
    writer:=json.NewEncoder(out)
    for reader.Scan(){
        var request persistentFrame
        if err:=json.Unmarshal(reader.Bytes(),&request);err!=nil{return err}
        if request.Version!=PersistentProtocolVersion||request.Type!="command"||len(request.Token)!=64 {
            return errors.New("invalid host command frame")
        }
        reply:=persistentFrame{Version:PersistentProtocolVersion,Type:"result",Token:request.Token}
        if request.Command=="__health__" {
            reply.Text="ready"
            if err:=writer.Encode(reply);err!=nil{return err}
            continue
        }
        handler,found:=a.commands[request.Command]
        if !found {reply.Error="unknown plugin command"} else {
            host:=&HostServices{token:request.Token,input:reader,output:writer}
            result,err:=handler(request.Args,host)
            if err!=nil {
                reply.Error=err.Error()
            } else {
                reply.Text=result.Text
                reply.View=result.View
                reply.Values=result.Values
            }
        }
        if err:=writer.Encode(reply);err!=nil{return err}
    }
    return reader.Err()
}

// CallHost invokes a manifest-granted RPC service with a bounded JSON payload.
// Privileged account and policy services are additionally checked by Sentinel
// against the authenticated caller's current permissions on every request.
// No plugin can grant itself these capabilities by sending a service name.
func (h *HostServices) CallHost(service string, payload any, out any) error {
    var data json.RawMessage
    if payload != nil {
        encoded,err:=json.Marshal(payload)
        if err!=nil{return err}
        if len(encoded)>8192{return errors.New("host service payload too large")}
        data=encoded
    }
    response,err:=h.call(persistentFrame{Service:service,Data:data})
    if err!=nil{return err}
    if out!=nil {
        if len(response.Data)==0{return errors.New("empty host service response")}
        return json.Unmarshal(response.Data,out)
    }
    return nil
}

// CheckPermission checks the currently authenticated user's built-in or
// namespaced custom capability. The caller's username cannot be spoofed.
func (h *HostServices) CheckPermission(permission string) (bool,error) {
    var out struct {Allowed bool `json:"allowed"`}
    err:=h.CallHost("permissions.check",map[string]string{"permission":permission},&out)
    return out.Allowed,err
}
func (h *HostServices) ListPermissions() ([]string,error) {
    var out struct {Permissions []string `json:"permissions"`}
    err:=h.CallHost("permissions.list",nil,&out)
    return out.Permissions,err
}

// AccountCreate is an account provisioning request. A password or SSH public
// key is required. All requested roles, rank grants and custom permissions
// remain subject to the host's role ceiling and last-admin safeguards.
type AccountCreate struct {
    Username string `json:"username"`
    Role string `json:"role"`
    Rank string `json:"rank,omitempty"`
    Plan string `json:"plan,omitempty"`
    Password string `json:"password,omitempty"`
    PublicKey string `json:"public_key,omitempty"`
    ExpiresAt string `json:"expires_at,omitempty"`
    CustomPermissions []string `json:"custom_permissions,omitempty"`
    DeniedPermissions []string `json:"denied_permissions,omitempty"`
}
// AccountUpdate deliberately uses pointer fields so omissions do not
// accidentally erase an existing account's role, rank or policy.
type AccountUpdate struct {
    Username string `json:"username"`
    Role *string `json:"role,omitempty"`
    Rank *string `json:"rank,omitempty"`
    Plan *string `json:"plan,omitempty"`
    Locked *bool `json:"locked,omitempty"`
    ExpiresAt *string `json:"expires_at,omitempty"`
    CustomPermissions *[]string `json:"custom_permissions,omitempty"`
    DeniedPermissions *[]string `json:"denied_permissions,omitempty"`
}
type Rank struct {
    Label string `json:"label"`
    Color string `json:"color,omitempty"`
    Permissions []string `json:"permissions,omitempty"`
    CustomPermissions []string `json:"custom_permissions,omitempty"`
}
type Plan struct {
    Label string `json:"label"`
    DurationDays int `json:"duration_days"`
    Permissions []string `json:"permissions,omitempty"`
    CustomPermissions []string `json:"custom_permissions,omitempty"`
}
func (h *HostServices) CreateAccount(req AccountCreate) error {
    return h.CallHost("accounts.create",req,nil)
}
func (h *HostServices) UpdateAccount(req AccountUpdate) error {
    return h.CallHost("accounts.update",req,nil)
}
func (h *HostServices) DeleteAccount(username string) error {
    return h.CallHost("accounts.delete",map[string]string{"username":username},nil)
}
func (h *HostServices) UpsertRank(name string,rank Rank) error {
    return h.CallHost("ranks.upsert",struct{
        Name string `json:"name"`
        Rank Rank `json:"rank"`
    }{name,rank},nil)
}
func (h *HostServices) DeleteRank(name string) error {
    return h.CallHost("ranks.delete",map[string]string{"name":name},nil)
}
func (h *HostServices) UpsertPlan(name string,plan Plan) error {
    return h.CallHost("plans.upsert",struct{
        Name string `json:"name"`
        Plan Plan `json:"plan"`
    }{name,plan},nil)
}
func (h *HostServices) DeletePlan(name string) error {
    return h.CallHost("plans.delete",map[string]string{"name":name},nil)
}
