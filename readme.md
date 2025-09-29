# SignatureStealer

Sig Steal is a tool that steals a signature from a file and copy it to whathever file you want.
Beyond Stealing, Sig Steal goes a step further by Windows Internal to trick the system to treat the copied signature as valid.

Obs: We can only clone a x32 binary to x32 , and x64 binary to x64

# Compile Binary
```
g++ main.cpp steal.cpp -o sigsteal.exe
```
## Compile without having to deal with dependencies, recommended.
```
g++ main.cpp steal.cpp -o SignatureKidProperties.exe -lws2_32 -lkernel32 -luser32
```
# Usage
```
sigsteal.exe GoogleChrome.exe fakeFile.exe
```

# Usage
```
sigsteal.exe kernel32.dll fakeDll.dll
```
