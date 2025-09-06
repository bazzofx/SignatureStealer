# SignatureStealer

Sig Steal is a tool that steals a signature from a file and copy it to whathever file you want.
Beyond Stealing, Sig Steal goes a step further by Windows Internal to trick the system to treat the copied signature as valid.


# Compile Binary
```
g++ main.cpp steal.cpp -o sigsteal.exe
```

# Usage
```
sigsteal.exe GoogleChrome.exe fakeFile.exe
```

# Usage
```
sigsteal.exe kernel32.dll fakeDll.dll
```
