#!/usr/bin/env python3
"""Package 3 reviewed plugin binaries with platform-specific SHA-256 pins."""
import hashlib,json,pathlib,sys,zipfile
r=json.loads(pathlib.Path("release-manifests/plugins-v0.1.0.json").read_text())
ids=("hashkit","jsonfix","uptimez")
targets=(("linux","amd64"),("linux","arm64"),("windows","amd64"))
if r["tag"]!="plugins-v0.1.0" or tuple(r["plugins"])!=ids or tuple(map(tuple,r["targets"]))!=targets:sys.exit("unexpected release manifest")
root=pathlib.Path("release-plugins");root.mkdir(exist_ok=True)
plugins=[]
for name in ids:
    m=(pathlib.Path("plugins")/name/"plugin.yaml").read_bytes()
    if f"id: {name}\n".encode() not in m or b"enabled: false\n" not in m:sys.exit("unreviewed manifest "+name)
    artifacts=[]
    for os_name,arch in targets:
        ext=".exe" if os_name=="windows" else ""
        binary=pathlib.Path("build-plugins")/f"{os_name}-{arch}"/(name+ext)
        if not binary.is_file() or not 0<binary.stat().st_size<12*1024*1024:sys.exit("missing/oversized binary "+str(binary))
        fn=f"{name}-{os_name}-{arch}.zip"
        with zipfile.ZipFile(root/fn,"w",zipfile.ZIP_DEFLATED,compresslevel=9) as z:
            for path,content,mode in (("plugin.yaml",m,0o100644),("bin/"+name+ext,binary.read_bytes(),0o100644 if ext else 0o100755)):
                info=zipfile.ZipInfo(path);info.create_system=3;info.external_attr=mode<<16;info.compress_type=zipfile.ZIP_DEFLATED
                z.writestr(info,content)
        digest=hashlib.sha256((root/fn).read_bytes()).hexdigest()
        artifacts.append({"os":os_name,"arch":arch,"url":f"https://github.com/AmpedWasTaken/sentinel-v5-plugins/releases/download/plugins-v0.1.0/{fn}","sha256":digest})
    plugins.append({"id":name,"version":"0.1.0","publisher":"sentinel-community-beta","artifacts":artifacts})
(root/"catalog.json").write_text(json.dumps({"version":1,"plugins":plugins},indent=2)+"\n")
print("Packaged nine reviewed, disabled-by-default platform ZIPs.")
