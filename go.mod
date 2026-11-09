module github.com/natesales/yk-wireguard

go 1.23.1

require (
	github.com/ElMostafaIdrassi/goscard v1.0.0
	golang.org/x/term v0.32.0
	golang.zx2c4.com/wireguard v0.0.0-20261024220952-b3bc704ef0ee
)

require (
	github.com/ebitengine/purego v0.8.2 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace golang.zx2c4.com/wireguard => ./wireguard-go
