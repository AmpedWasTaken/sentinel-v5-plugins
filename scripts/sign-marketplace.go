package main

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
)
type Artifact struct {
 OS string `json:"os"`
 Arch string `json:"arch"`
 SHA256 string `json:"sha256"`
 Signature string `json:"signature,omitempty"`
 URL string `json:"url"`
}
type Plugin struct {
 ID string `json:"id"`
 Publisher string `json:"publisher"`
 Version string `json:"version"`
 Artifacts []Artifact `json:"artifacts"`
}
type Catalog struct {
 Version int `json:"version"`
 Plugins []Plugin `json:"plugins"`
}
func check(err error){if err!=nil{panic(err)}}
func main(){
 root:="release-plugins"
 in,err:=os.ReadFile(filepath.Join(root,"catalog.json"));check(err)
 var catalog Catalog
 check(json.Unmarshal(in,&catalog))
 if catalog.Version!=1||len(catalog.Plugins)!=3 {panic("unexpected beta catalog")}
 seed:=make([]byte,ed25519.SeedSize)
 if secret:=os.Getenv("SENTINEL_PUBLISHER_SEED_B64");secret!=""{
  seed,err=base64.StdEncoding.DecodeString(secret);check(err)
  if len(seed)!=ed25519.SeedSize {panic("publisher seed must be exactly 32 bytes")}
 }else{
  _,err=rand.Read(seed);check(err)
  fmt.Println("NOTICE: release-scoped ephemeral signer; approval does not transfer to subsequent releases")
 }
 private:=ed25519.NewKeyFromSeed(seed)
 public:=private.Public().(ed25519.PublicKey)
 for i:=range catalog.Plugins {
  p:=&catalog.Plugins[i]
  if p.Publisher!="sentinel-community-beta" {panic("publisher mismatch")}
  for j:=range p.Artifacts {
   a:=&p.Artifacts[j]
   if len(a.SHA256)!=64 {panic("missing SHA-256")}
   msg:=[]byte(fmt.Sprintf("sentinel-v5-marketplace-artifact-v1\n%s\n%s\n%s\n%s\n%s\n",p.ID,p.Version,a.OS,a.Arch,a.SHA256))
   signature:=ed25519.Sign(private,msg)
   if !ed25519.Verify(public,msg,signature){panic("failed to verify signature")}
   a.Signature=base64.StdEncoding.EncodeToString(signature)
  }
 }
 encoded,err:=json.MarshalIndent(catalog,"","  ");check(err)
 check(os.WriteFile(filepath.Join(root,"catalog.json"),append(encoded,'\n'),0600))
 key:=base64.StdEncoding.EncodeToString(public)
 pubStore:=map[string]any{
  "version":1,
  "publishers":[]map[string]string{{"id":"sentinel-community-beta","public_key":key}},
 }
 published,err:=json.MarshalIndent(pubStore,"","  ");check(err)
 check(os.WriteFile(filepath.Join(root,"trusted-publishers.json"),append(published,'\n'),0600))
 for i:=range seed {seed[i]=0}
 fmt.Println("Signed marketplace artifacts; private signing key not shipped")
}
