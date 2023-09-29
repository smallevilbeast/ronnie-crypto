
### how to install openssl on windows

1. install vcpkg
```bash
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install
```

2. install openssl
```bash
vcpkg install openssl:x64-windows-static
```

3. compile static 
```bash
# set env
set RUSTFLAGS=-Ctarget-feature=+crt-static
# or powershell
$env:RUSTFLAGS="-Ctarget-feature=+crt-static"
```

4. compile dynamic 
```bash
# install openssl dynamic
vcpkg install openssl:x64-windows

# set env
set VCPKGRS_DYNAMIC=1
# or powershell
$env:VCPKGRS_DYNAMIC=1
```