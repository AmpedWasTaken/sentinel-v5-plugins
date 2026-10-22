#!/usr/bin/env python3
"""Validate initial curated marketplace release before public publication."""
import base64,hashlib,json,pathlib,zipfile
root=pathlib.Path("release-plugins")
catalog=json.loads((root/"catalog.json").read_text())
trust=json.loads((root/"trusted-publishers.json").read_text())
assert catalog["version"]==trust["version"]==1
assert len(trust["publishers"])==1 and trust["publishers"][0]["id"]=="sentinel-community-beta"
assert len(base64.b64decode(trust["publishers"][0]["public_key"],validate=True))==32
assert [p["id"] for p in catalog["plugins"]]==["hashkit","jsonfix","uptimez"]
targets={("linux","amd64"),("linux","arm64"),("windows","amd64")}
for p in catalog["plugins"]:
    assert p["version"]=="0.1.0" and p["publisher"]=="sentinel-community-beta"
    assert {(a["os"],a["arch"]) for a in p["artifacts"]}==targets
    for a in p["artifacts"]:
        filename=f"{p['id']}-{a['os']}-{a['arch']}.zip"
        url=f"https://github.com/AmpedWasTaken/sentinel-v5-plugins/releases/download/plugins-v0.1.0/{filename}"
        assert a["url"]==url and len(a["sha256"])==64
        assert len(base64.b64decode(a["signature"],validate=True))==64
        archive=root/filename
        assert 0<archive.stat().st_size<16*1024*1024
        assert hashlib.sha256(archive.read_bytes()).hexdigest()==a["sha256"]
        ext=".exe" if a["os"]=="windows" else ""
        executable="bin/"+p["id"]+ext
        with zipfile.ZipFile(archive) as z:
            assert set(z.namelist())=={"plugin.yaml",executable},filename
            m=z.read("plugin.yaml").decode("utf-8")
            assert f"id: {p['id']}\n" in m and "enabled: false\n" in m
            bininfo=z.getinfo(executable)
            assert 0<bininfo.file_size<12*1024*1024
            if not ext:assert bininfo.external_attr>>16 & 0o111
files=sorted(f for f in root.iterdir() if f.is_file())
(root/"SHA256SUMS").write_text("".join(
    f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}\n"
    for f in files if f.name!="SHA256SUMS"
))
print("Verified 9 packages, hashes, signatures and publisher metadata.")
