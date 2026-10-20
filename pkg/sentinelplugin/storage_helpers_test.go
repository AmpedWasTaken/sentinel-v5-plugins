package sentinelplugin

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func fakeStorageHost(service, data string) (*HostServices,*bytes.Buffer) {
	token:=strings.Repeat("a",64)
	reply:=persistentFrame{
		Version:PersistentProtocolVersion,
		Type:"service-result",
		Token:token,
		ID:"1",
		Service:service,
		Found:true,
	}
	if data!="" {reply.Data=json.RawMessage(data)}
	encoded,_:=json.Marshal(reply)
	var out bytes.Buffer
	return &HostServices{
		token:token,
		input:bufio.NewScanner(strings.NewReader(string(encoded)+"\n")),
		output:json.NewEncoder(&out),
	},&out
}

func TestTypedStorageRead(t *testing.T) {
	h,_:=fakeStorageHost("storage.get",`{"enabled":true,"name":"demo"}`)
	type state struct {Enabled bool `json:"enabled"`; Name string `json:"name"`}
	got,found,err:=ReadJSON[state](h,"config")
	if err!=nil||!found||!got.Enabled||got.Name!="demo"{t.Fatalf("read: %+v found=%v error=%v",got,found,err)}
}

func TestTypedStorageWrite(t *testing.T) {
	h,out:=fakeStorageHost("storage.put","")
	err:=WriteJSON(h,"counter",struct{Count int `json:"count"`}{Count:12})
	if err!=nil{t.Fatal(err)}
	var frame persistentFrame
	if err:=json.Unmarshal(bytes.TrimSpace(out.Bytes()),&frame);err!=nil{t.Fatal(err)}
	if frame.Service!="storage.put"||frame.Key!="counter"||string(frame.Data)!=`{"count":12}`{
		t.Fatalf("unexpected host service request: %+v",frame)
	}
}

func TestTypedStorageRejectsInvalidPayloads(t *testing.T) {
	if _,_,err:=ReadJSON[int](nil,"key");err==nil{t.Fatal("nil host permitted")}
	if err:=WriteJSON(nil,"key",1);err==nil{t.Fatal("nil host permitted")}
	h,_:=fakeStorageHost("storage.get",`"not-an-integer"`)
	if _,_,err:=ReadJSON[int](h,"counter");err==nil{t.Fatal("invalid typed JSON accepted")}
}
