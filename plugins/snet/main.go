package main

import (
 "errors"
 "fmt"
 "io"
 "net"
 "strconv"
 "strings"
 "time"

 "github.com/AmpedWasTaken/sentinel-v5-plugins/pkg/sentinelplugin"
)

const maxRead = 2048

func timeout(a map[string]string) (time.Duration,error) {
 value:=a["timeout"]
 if value=="" {return 3*time.Second,nil}
 n,err:=strconv.Atoi(value)
 if err!=nil || n<1 || n>8 {return 0,errors.New("timeout must be 1..8 seconds")}
 return time.Duration(n)*time.Second,nil
}
func only(a map[string]string, allowed ...string) error {
 valid:=map[string]bool{}
 for _,k:=range allowed {valid[k]=true}
 for k:=range a {if !valid[k] {return fmt.Errorf("unknown argument %q",k)}}
 return nil
}
func address(a map[string]string) (string,error) {
 host:=strings.TrimSpace(a["host"])
 if len(host)==0 || len(host)>253 || strings.ContainsAny(host," \t\r\n/\\") {return "",errors.New("host must be a valid hostname or IP")}
 port,err:=strconv.Atoi(a["port"])
 if err!=nil || port<1 || port>65535 {return "",errors.New("port must be 1..65535")}
 return net.JoinHostPort(host,strconv.Itoa(port)),nil
}
func payload(a map[string]string) ([]byte,error) {
 s:=a["data"]
 if len(s)>1024 {return nil,errors.New("data exceeds 1024 bytes")}
 if a["crlf"]=="true" {s=strings.TrimSuffix(s,"\n")+"\r\n"} else if a["crlf"]!="" && a["crlf"]!="false" {return nil,errors.New("crlf must be true or false")}
 return []byte(s),nil
}
func printable(b []byte) string {
 var out strings.Builder
 for _,c:=range b {
  switch {
  case c==9 || c==10 || c==13: out.WriteByte(c)
  case c>=32 && c<=126: out.WriteByte(c)
  default: out.WriteString(fmt.Sprintf("\\x%02x",c))
  }
 }
 return out.String()
}
func read(conn net.Conn) (string,error) {
 b:=make([]byte,maxRead)
 n,err:=conn.Read(b)
 if err!=nil && !errors.Is(err,io.EOF) {
  if e,ok:=err.(net.Error);ok && e.Timeout() {return "(no response before timeout)",nil}
  return "",err
 }
 if n==0 {return "(connection closed without data)",nil}
 return printable(b[:n]),nil
}
func connect(req sentinelplugin.Request) (sentinelplugin.Result,error) {
 a:=req.Args
 if err:=only(a,"host","port","timeout","data","crlf");err!=nil{return sentinelplugin.Result{},err}
 addr,err:=address(a);if err!=nil{return sentinelplugin.Result{},err}
 t,err:=timeout(a);if err!=nil{return sentinelplugin.Result{},err}
 data,err:=payload(a);if err!=nil{return sentinelplugin.Result{},err}
 c,err:=net.DialTimeout("tcp",addr,t);if err!=nil{return sentinelplugin.Result{},fmt.Errorf("TCP connection failed: %w",err)}
 defer c.Close()
 _=c.SetDeadline(time.Now().Add(t))
 if len(data)>0 {if _,err=c.Write(data);err!=nil{return sentinelplugin.Result{},err}}
 reply,err:=read(c);if err!=nil{return sentinelplugin.Result{},err}
 return sentinelplugin.Result{Text:fmt.Sprintf("TCP %s -> %s\nSent %d bytes\nReceived: %s",c.LocalAddr(),c.RemoteAddr(),len(data),reply)},nil
}
func banner(req sentinelplugin.Request)(sentinelplugin.Result,error) {
 if err:=only(req.Args,"host","port","timeout");err!=nil{return sentinelplugin.Result{},err}
 addr,err:=address(req.Args);if err!=nil{return sentinelplugin.Result{},err}
 t,err:=timeout(req.Args);if err!=nil{return sentinelplugin.Result{},err}
 c,err:=net.DialTimeout("tcp",addr,t);if err!=nil{return sentinelplugin.Result{},err}
 defer c.Close()
 _=c.SetReadDeadline(time.Now().Add(t))
 value,err:=read(c);if err!=nil{return sentinelplugin.Result{},err}
 return sentinelplugin.Result{Text:fmt.Sprintf("Banner from %s:\n%s",addr,value)},nil
}
func scan(req sentinelplugin.Request)(sentinelplugin.Result,error) {
 a:=req.Args
 if err:=only(a,"host","ports","timeout");err!=nil{return sentinelplugin.Result{},err}
 host:=strings.TrimSpace(a["host"])
 if host=="" || len(host)>253 || strings.ContainsAny(host," \t\r\n/\\") {return sentinelplugin.Result{},errors.New("invalid host")}
 t,err:=timeout(a);if err!=nil{return sentinelplugin.Result{},err}
 raw:=strings.Split(a["ports"],",")
 if len(raw)==0 || len(raw)>32 || a["ports"]=="" {return sentinelplugin.Result{},errors.New("ports must be a comma-separated list of 1..32 ports")}
 var output strings.Builder
 for _,p:=range raw {
  n,e:=strconv.Atoi(strings.TrimSpace(p))
  if e!=nil || n<1 || n>65535{return sentinelplugin.Result{},errors.New("invalid port")}
 }
 for _,p:=range raw {
  n,_:=strconv.Atoi(strings.TrimSpace(p))
  addr:=net.JoinHostPort(host,strconv.Itoa(n))
  c,e:=net.DialTimeout("tcp",addr,t)
  state:="closed or filtered"
  if e==nil {state="open"; _=c.Close()}
  fmt.Fprintf(&output,"%s %s\n",addr,state)
 }
 return sentinelplugin.Result{Text:strings.TrimSpace(output.String())},nil
}
func udp(req sentinelplugin.Request)(sentinelplugin.Result,error) {
 a:=req.Args
 if err:=only(a,"host","port","timeout","data","crlf");err!=nil{return sentinelplugin.Result{},err}
 addr,err:=address(a);if err!=nil{return sentinelplugin.Result{},err}
 t,err:=timeout(a);if err!=nil{return sentinelplugin.Result{},err}
 data,err:=payload(a);if err!=nil{return sentinelplugin.Result{},err}
 c,err:=net.DialTimeout("udp",addr,t);if err!=nil{return sentinelplugin.Result{},err}
 defer c.Close()
 _=c.SetDeadline(time.Now().Add(t))
 if _,err=c.Write(data);err!=nil{return sentinelplugin.Result{},err}
 response,err:=read(c);if err!=nil{return sentinelplugin.Result{},err}
 return sentinelplugin.Result{Text:fmt.Sprintf("UDP datagram sent to %s (%d bytes)\nResponse: %s\nNote: a timeout does not prove a UDP port is closed.",addr,len(data),response)},nil
}
func listen(req sentinelplugin.Request)(sentinelplugin.Result,error) {
 a:=req.Args
 if err:=only(a,"port","timeout");err!=nil{return sentinelplugin.Result{},err}
 n,err:=strconv.Atoi(a["port"]);if err!=nil || n<1024 || n>65535 {return sentinelplugin.Result{},errors.New("listener port must be 1024..65535")}
 t,err:=timeout(a);if err!=nil{return sentinelplugin.Result{},err}
 listener,err:=net.Listen("tcp",net.JoinHostPort("127.0.0.1",strconv.Itoa(n)))
 if err!=nil{return sentinelplugin.Result{},err}
 defer listener.Close()
 tcp:=listener.(*net.TCPListener)
 _=tcp.SetDeadline(time.Now().Add(t))
 c,err:=tcp.Accept()
 if err!=nil {
  if e,ok:=err.(net.Error);ok && e.Timeout(){return sentinelplugin.Result{Text:fmt.Sprintf("No connection to 127.0.0.1:%d within %s",n,t)},nil}
  return sentinelplugin.Result{},err
 }
 defer c.Close()
 _=c.SetReadDeadline(time.Now().Add(t))
 data,err:=read(c);if err!=nil{return sentinelplugin.Result{},err}
 return sentinelplugin.Result{Text:fmt.Sprintf("Received one TCP connection on 127.0.0.1:%d from %s\nData: %s",n,c.RemoteAddr(),data)},nil
}
func main() {
 app:=sentinelplugin.New()
 for _,item:=range []struct{name string; handler sentinelplugin.Handler}{
  {"connect",connect},{"scan",scan},{"banner",banner},{"udp",udp},{"listen",listen},
 } {
  if err:=app.Command(item.name,item.handler);err!=nil{panic(err)}
 }
 if err:=app.Serve();err!=nil{panic(err)}
}
