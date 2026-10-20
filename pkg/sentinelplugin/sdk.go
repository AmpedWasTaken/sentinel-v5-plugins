// Package sentinelplugin is a small, language-neutral SDK for trusted code
// plugins. A plugin executable reads one JSON request, returns one JSON response
// and exits. It cannot register privileged Sentinel operations by itself.
package sentinelplugin

import (
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "regexp"
    "strings"
)

const ProtocolVersion = 1
const maxMessage = 16 * 1024

var commandName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,23}$`)

// Request is provided by the Sentinel host after authentication and RBAC.
type Request struct {
    Version int `json:"version"`
    Command string `json:"command"`
    Actor string `json:"actor"`
    Role string `json:"role"`
    Args map[string]string `json:"args"`
}

// Result is safe, structured data. The host chooses only local plugin SML
// views and sanitizes/limits all output before presenting it to a user.
type Result struct {
    Text string `json:"text,omitempty"`
    View string `json:"view,omitempty"`
    Values map[string]string `json:"values,omitempty"`
}

type Response struct {
    Version int `json:"version"`
    Result Result `json:"result"`
    Error string `json:"error,omitempty"`
}

type Handler func(Request) (Result,error)

// App is the WordPress-style registration surface for Go code plugins.
type App struct { commands map[string]Handler }

func New() *App {return &App{commands:map[string]Handler{}}}

// Command registers a handler. Names must also be declared in plugin.yaml so
// unregistered commands cannot be invoked through Sentinel.
func (a *App) Command(name string, handler Handler) error {
    if !commandName.MatchString(name)||handler==nil{return errors.New("invalid plugin command/handler")}
    if _,exists:=a.commands[name];exists{return fmt.Errorf("duplicate plugin command %q",name)}
    a.commands[name]=handler
    return nil
}

func (a *App) Handle(req Request) Response {
    out:=Response{Version:ProtocolVersion}
    if req.Version!=ProtocolVersion {out.Error="unsupported plugin protocol";return out}
    handler,ok:=a.commands[req.Command]
    if !ok {out.Error="unknown plugin command";return out}
    result,err:=handler(req)
    if err!=nil {out.Error=err.Error();return out}
    out.Result=result
    return out
}

// Serve reads one message from stdin and emits exactly one JSON message.
// To support Python/PHP/JS, implement this same JSON protocol in that language.
func (a *App) Serve() error {
    return a.ServeIO(os.Stdin,os.Stdout)
}

func (a *App) ServeIO(in io.Reader,out io.Writer) error {
    data,err:=io.ReadAll(io.LimitReader(in,maxMessage+1))
    if err!=nil{return err}
    response:=Response{Version:ProtocolVersion}
    if len(data)>maxMessage {
        response.Error="plugin request too large"
    }else{
        dec:=json.NewDecoder(strings.NewReader(string(data)))
        dec.DisallowUnknownFields()
        var req Request
        if err:=dec.Decode(&req);err!=nil{response.Error="invalid plugin request"}else{
            var extra any
            if err:=dec.Decode(&extra);err!=io.EOF{response.Error="multiple plugin request documents"}else{
                response=a.Handle(req)
            }
        }
    }
    return json.NewEncoder(out).Encode(response)
}
