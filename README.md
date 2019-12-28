# DotNetHole

It's like Pi-hole, but like... .NET and stuff.

This is a proof of concept. Code quality is out of the question.  
Seriously, don't actually use this as-is.

## Build

```
dotnet publish -r win-x64 -c Release
```

## Install as service

```
sc create DotNetHole BinPath=C:\Path\To\DotNetHole.exe
```