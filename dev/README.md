# Development Utilities

This directory contains some utility programs to ease the development of the
OpenSSL bindings.

## NID enumeration generator

The file `gennids.go` contains a simple program that reads `openssl/obj_mac.h`
and generates a go language file defining the `NID` enumeration for all of the
NIDs defined in that file.

Generally, this utility only needs to be run when updating the bindings to
support a new version of OpenSSL.

To update `nid.go`, run the following from the project root directory:

```
go run dev/gennids.go --output nid.go
```

If `obj_mac.h` is not located at `/usr/include/openssl/obj_mac.h` on your system,
you may specify the path by adding `--header "/path/to/openssl/obj_mac.h"`.