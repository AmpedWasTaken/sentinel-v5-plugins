package sentinelplugin

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestPersistentLifecycleHooks(t *testing.T) {
	app:=NewPersistent()
	started,stopped:=0,0
	app.OnStart(func() error {started++;return nil})
	app.OnStop(func() {stopped++})
	token:=strings.Repeat("a",64)
	request:=fmt.Sprintf("{\"version\":1,\"type\":\"command\",\"token\":\"%s\",\"command\":\"__health__\"}\n",token)
	var out bytes.Buffer
	if err:=app.ServeIO(strings.NewReader(request),&out);err!=nil{t.Fatal(err)}
	if started!=1||stopped!=1{t.Fatalf("unexpected lifecycle start=%d stop=%d",started,stopped)}
	if !strings.Contains(out.String(),"\"ready\""){t.Fatalf("health handshake failed: %s",out.String())}
}

func TestPersistentStartupFailureBlocksHealthHandshake(t *testing.T) {
	app:=NewPersistent()
	stopped:=false
	app.OnStart(func()error{return errors.New("missing configuration")})
	app.OnStop(func(){stopped=true})
	var out bytes.Buffer
	if err:=app.ServeIO(strings.NewReader(""),&out);err==nil{t.Fatal("accepted unhealthy worker")}
	if stopped||out.Len()!=0{t.Fatal("startup failure should not advertise readiness")}
}
