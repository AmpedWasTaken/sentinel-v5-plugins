// Sign the exact reviewed marketplace catalog using a persistent publisher seed.
// The seed must be provisioned independently as a GitHub Actions secret.
package main

import (
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "path/filepath"
)

type artifact struct {
    OS string `json:"os"`
    Arch string `json:"arch"`
    SHA256 string `json:"sha256"`
    Signature string `json:"signature,omitempty"`
    URL string `json:"url"`
}
type entry struct {
    ID string `json:"id"`
    Version string `json:"version"`
    Publisher string `json:"publisher"`
    Artifacts []artifact `json:"artifacts"`
}
type catalog struct {
    Version int `json:"version"`
    Plugins []entry `json:"plugins"`
}

func main() {
    if err := run(); err != nil {
        fmt.Fprintln(os.Stderr, "release signing failed:", err)
        os.Exit(1)
    }
}
func run() error {
    encoded := os.Getenv("SENTINEL_PUBLISHER_SEED_B64")
    if encoded == "" {
        return errors.New("SENTINEL_PUBLISHER_SEED_B64 is required; refusing ephemeral signing")
    }
    seed, err := base64.StdEncoding.DecodeString(encoded)
    if err != nil || len(seed) != ed25519.SeedSize {
        return errors.New("publisher seed must be 32 bytes in standard base64")
    }
    defer func() {for i := range seed { seed[i] = 0 }}()
    key := ed25519.NewKeyFromSeed(seed)
    defer func() {for i := range key { key[i] = 0 }}()
    publicKey := key.Public().(ed25519.PublicKey)
    filename := filepath.Join("release-plugins", "catalog.json")
    raw, err := os.ReadFile(filename)
    if err != nil {return err}
    var index catalog
    if err := json.Unmarshal(raw, &index); err != nil {return err}
    if index.Version != 1 || len(index.Plugins) != 3 {return errors.New("unexpected curated catalog")}
    expected := []string{"hashkit","jsonfix","hookbin"}
    for i := range index.Plugins {
        p := &index.Plugins[i]
        if p.ID != expected[i] || p.Version != "0.2.0" || p.Publisher != "sentinel-community-v2" || len(p.Artifacts) != 2 {
            return fmt.Errorf("unreviewed catalog entry %q",p.ID)
        }
        for j := range p.Artifacts {
            a := &p.Artifacts[j]
            if a.OS != "linux" || (a.Arch != "amd64" && a.Arch != "arm64") ||
                len(a.SHA256) != 64 || len(a.URL) == 0 {
                return fmt.Errorf("invalid catalog artifact %s/%s",p.ID,a.Arch)
            }
            message := []byte(fmt.Sprintf("sentinel-v5-marketplace-artifact-v1\n%s\n%s\n%s\n%s\n%s\n",
                p.ID,p.Version,a.OS,a.Arch,a.SHA256))
            sig := ed25519.Sign(key,message)
            if !ed25519.Verify(publicKey,message,sig) {return errors.New("internal signature verification failed")}
            a.Signature = base64.StdEncoding.EncodeToString(sig)
        }
    }
    updated,err := json.MarshalIndent(index,"","  ")
    if err != nil {return err}
    if err := os.WriteFile(filename,append(updated,'\n'),0600);err != nil{return err}
    trust := map[string]any{
        "version": 1,
        "publishers": []map[string]string{{
            "id": "sentinel-community-v2",
            "public_key": base64.StdEncoding.EncodeToString(publicKey),
        }},
    }
    trustBytes,err := json.MarshalIndent(trust,"","  ")
    if err != nil{return err}
    if err := os.WriteFile(filepath.Join("release-plugins","trusted-publishers.json"),append(trustBytes,'\n'),0600);err != nil{return err}
    fingerprint := sha256.Sum256(publicKey)
    fmt.Println("Signed six curated artifacts; publisher key SHA-256 fingerprint:",hex.EncodeToString(fingerprint[:]))
    return nil
}
