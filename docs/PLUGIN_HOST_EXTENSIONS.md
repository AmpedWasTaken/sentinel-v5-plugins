# Plugin SDK: events, database and session management

These host services require the corresponding Sentinel V5 core changes and a trusted persistent exec-rpc plugin with explicitly granted runtime.capabilities.

**Events:** SubscribeEvent(topic), PollEvents(id, limit) and UnsubscribeEvent(id) use bounded, best-effort polling subscriptions. Allowed topics include the plugin's own exact plugin.<plugin-id>.<name> events; core session events require sessions.read.all and core account events require accounts.read. No wildcard or cross-plugin subscriptions. Subscriptions expire after 30 minutes without polling; no automatic callback execution or durable replay is promised.

**Database:** DatabasePut(collection,id,value), DatabaseGet(collection,id), DatabaseList(collection,after,limit), DatabaseDelete(collection,id) use host-owned SQLite and fixed, parameterized CRUD. No arbitrary SQL. Records are scoped to the authenticated plugin namespace, each value <=8 KiB, max 512 records and 2 MiB per plugin, and list pages max 3 records.

**Sessions:** ListSessions(limit) returns authorized session snapshots, scoped to the caller when sessions.read.all is missing. KickSession(id,reason) requires sessions.kick; all actions recheck the authenticated actor. Session data for own-only reads omits remote IP/client/last-command fields.

Example:

~~~go
_ = app.Command("check", func(args map[string]string, host *sentinelplugin.HostServices) (sentinelplugin.Result,error){
    if err:=host.DatabasePut("settings","status",map[string]bool{"enabled":true});err!=nil{
        return sentinelplugin.Result{},err
    }
    eventsID,err:=host.SubscribeEvent("plugin.my-plugin.updated")
    if err!=nil{return sentinelplugin.Result{},err}
    events,err:=host.PollEvents(eventsID,8)
    if err!=nil{return sentinelplugin.Result{},err}
    return sentinelplugin.Result{Text:fmt.Sprintf("%d events",len(events))},nil
})
~~~

Never assume that a manifest capability alone conveys administrator permission, that an event subscription survives a restart, or that the trusted-code worker is an OS sandbox.
