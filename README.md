### windows 安装 openssl

1. 安装vcpkg
```bash
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install
```

2. 安装openssl
```bash
vcpkg install openssl:x64-windows-static
```

3. 静态编译参数
```bash
# cmd 
set RUSTFLAGS=-Ctarget-feature=+crt-static

# powershell
$env:RUSTFLAGS="-Ctarget-feature=+crt-static"
```

4. 动态编译 


```bash
# 安装动态库
vcpkg install openssl:x64-windows

# 设置编译成动态库
set VCPKGRS_DYNAMIC=1

# powershell
$env:VCPKGRS_DYNAMIC=1
```