# SignatureStealer

Signature Kid is a header only tool that steals a signature from a file and copy it to whathever file you want.

Beyond Stealing, Signature Kid goes a step further by Windows Internal to trick the system to treat the copied signature as valid.

## Build it
```
g++ main.cpp -o SignatureKid.exe
```

## How to use it
```
\SignatureKid.exe kernel32.dll C:\temp\NotSigned.dll
```
