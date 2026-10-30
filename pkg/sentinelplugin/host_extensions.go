package sentinelplugin

import (
    "encoding/json"
    "time"
)

// HostEvent is a bounded, best-effort event delivered by the Sentinel host.
// Poll subscriptions are not durable; events can be dropped on overflow.
type HostEvent struct {
    Topic string `json:"topic"`
    PluginID string `json:"plugin_id"`
    Actor string `json:"actor,omitempty"`
    Timestamp time.Time `json:"timestamp"`
    Detail string `json:"detail,omitempty"`
}

func (h *HostServices) SubscribeEvent(topic string)(string,error){
    var out struct {SubscriptionID string `json:"subscription_id"`}
    err:=h.CallHost("events.subscribe",map[string]string{"topic":topic},&out)
    return out.SubscriptionID,err
}
func (h *HostServices) PollEvents(subscriptionID string,limit int)([]HostEvent,error){
    var out struct {Events []HostEvent `json:"events"`}
    err:=h.CallHost("events.poll",map[string]any{"subscription_id":subscriptionID,"limit":limit},&out)
    return out.Events,err
}
func (h *HostServices) UnsubscribeEvent(subscriptionID string)error{
    return h.CallHost("events.unsubscribe",map[string]string{"subscription_id":subscriptionID},nil)
}

// PluginDatabaseRecord contains user-defined JSON only; there is no raw SQL.
type PluginDatabaseRecord struct {
    ID string `json:"id"`
    Value json.RawMessage `json:"value"`
}
type PluginDatabasePage struct {
    Items []PluginDatabaseRecord `json:"items"`
    Next string `json:"next,omitempty"`
}
func(h *HostServices) DatabasePut(collection,id string,value any)error{
    return h.CallHost("db.put",map[string]any{"collection":collection,"id":id,"value":value},nil)
}
func(h *HostServices) DatabaseGet(collection,id string)(json.RawMessage,bool,error){
    var out struct {
        Found bool `json:"found"`
        Value json.RawMessage `json:"value"`
    }
    err:=h.CallHost("db.get",map[string]string{"collection":collection,"id":id},&out)
    return out.Value,out.Found,err
}
func(h *HostServices) DatabaseDelete(collection,id string)(bool,error){
    var out struct {Deleted bool `json:"deleted"`}
    err:=h.CallHost("db.delete",map[string]string{"collection":collection,"id":id},&out)
    return out.Deleted,err
}
func(h *HostServices) DatabaseList(collection,after string,limit int)(PluginDatabasePage,error){
    var out PluginDatabasePage
    err:=h.CallHost("db.list",map[string]any{"collection":collection,"after":after,"limit":limit},&out)
    return out,err
}

// HostSession contains a filtered SSH session snapshot. Sensitive remote
// metadata is available only with the user's sessions.read.all permission.
type HostSession struct {
    ID string `json:"id"`
    Username string `json:"username"`
    Remote string `json:"remote"`
    Client string `json:"client,omitempty"`
    Connected time.Time `json:"connected"`
    LastActive time.Time `json:"last_active"`
    LastCommand string `json:"last_command,omitempty"`
}
func(h *HostServices) ListSessions(limit int)([]HostSession,error){
    var out struct {Sessions []HostSession `json:"sessions"`}
    err:=h.CallHost("sessions.list",map[string]int{"limit":limit},&out)
    return out.Sessions,err
}
func(h *HostServices) KickSession(id,reason string)error{
    return h.CallHost("sessions.kick",map[string]string{"id":id,"reason":reason},nil)
}
