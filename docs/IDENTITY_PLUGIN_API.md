# Account and permission host services (Sentinel V5)

Persistent Go plugins can request limited, audited host services using HostServices.CallHost. Requires a Sentinel V5 host with the plugin identity API enabled and an explicit runtime capability grant.

The authenticated SSH actor is provided by the host context, not the worker process. Built-in permissions and custom permission keys are checked again by the host for each call. Plugins do not gain unrestricted administrator access just because their manifest requests a capability.

Available services:

- permissions.check / permissions.list: self-only capability checks; CheckPermission and ListPermissions SDK helpers.
- accounts.list / accounts.create / accounts.update / accounts.delete: requires accounts.read or accounts.write as appropriate; use CreateAccount, UpdateAccount, DeleteAccount.
- ranks.list / ranks.upsert / ranks.delete: requires ranks.manage; use UpsertRank and DeleteRank.
- plans.list / plans.upsert / plans.delete: requires settings.write; use UpsertPlan and DeletePlan.

Use HostServices.CallHost for generic typed responses, e.g.:

~~~go
var response struct {
    Total int `json:"total"`
    Items []struct {
        Username string `json:"username"`
        Role string `json:"role"`
    } `json:"items"`
}
err := host.CallHost("accounts.list", map[string]int{"offset":0,"limit":25}, &response)
~~~

To require a namespaced custom permission at the command boundary, add a field such as requires_permission: custom.myplugin.manage to the command in plugin.yaml. Grants can be configured through a user, rank or plan; the core role ceiling remains enforced for built-in privileges.

CreateAccount requires a password or SSH public key and automatically applies the selected plan's expiry, or the Sentinel default account lifetime. Do not log passwords or put them in shared CLI argument history. AccountUpdate uses pointer fields to distinguish omitted from explicit empty/false values.

Trusted code is not an OS sandbox. Never install unreviewed community binaries just because they claim a limited list of host capabilities.
