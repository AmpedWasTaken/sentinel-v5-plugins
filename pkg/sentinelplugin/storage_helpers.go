package sentinelplugin

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ReadJSON decodes a plugin-owned, capability-gated storage value. It cannot
// choose a namespace: the host broker supplies the authenticated plugin ID.
// Missing keys return found=false and a zero value.
func ReadJSON[T any](host *HostServices, key string) (T, bool, error) {
	var zero T
	if host == nil {return zero,false,errors.New("plugin host services unavailable")}
	raw,found,err:=host.Get(key)
	if err!=nil || !found {return zero,found,err}
	var value T
	if err:=json.Unmarshal(raw,&value);err!=nil {
		return zero,true,fmt.Errorf("invalid plugin-owned JSON at key %q: %w",key,err)
	}
	return value,true,nil
}

// WriteJSON encodes typed application state through the existing quota-limited
// storage.put capability, without exposing paths or filesystem access.
func WriteJSON(host *HostServices, key string, value any) error {
	if host==nil{return errors.New("plugin host services unavailable")}
	data,err:=json.Marshal(value)
	if err!=nil{return fmt.Errorf("encode plugin storage JSON: %w",err)}
	return host.Put(key,data)
}
