- [wg-dynamic-allowedips](#wg-dynamic-allowedips)
  - [Usage](#usage)
  - [Build](#build)
  - [Run as system service](#run-as-system-service)
    - [Systemd service](#systemd-service)
    - [start-stop-daemon](#start-stop-daemon)

# wg-dynamic-allowedips

Daemon to watch Linux kernel routes and dynamically update WireGuard peer's `allowed-ips`.
It's intended to be used to help run BGP / OSPF over WireGuard mesh network.

Written by Gemini 3.1 Pro.

How it works:
1. Run `ip monitor route` to watch main routing table changes.
2. After any `wg*` interface related routing table change detected, it runs `ip route show table main` to
   get full system routing info, recognize `192.168.1.0/24 via 192.168.100.10 dev wg0 proto bird` style
   routing records, then run `wg set wg0 peer <peer_public_key> allowed-ips 192.168.100.10,192.168.1.0/24` to
   update peer's `allowed-ips`.

Where:

- `192.168.100.10` : the peer's private /32 ip, which should be defined statically in `AllowedIPs = ` line
  of `/etc/wireguard/<interface>.conf` WireGuard / wg-quick config file.
- `192.168.1.0/24 via 192.168.100.10 dev wg0 proto bird` : system routing table record to route
  the `192.168.1.0/24` subnet through `192.168.100.10` peer. While the `via <peer_ip>` directive itself has
  no effect to WireGuard, this program uses it to associate the subnet with the peer.
  The routing table records are expected to be added by Bird using BGP / OSPF.

## Usage

Just run `wg-dynamic-allowedips` to start the daemon. No flag is mandatory.

```
./wg-dynamic-allowedips -h

Usage: wg-dynamic-allowedips [OPTIONS]

Options:
  -i, --interface <INTERFACE>    Specific WireGuard interface to watch (e.g., wg0). Watches all wg* interfaces if omitted
  -c, --config-dir <CONFIG_DIR>  Directory containing WireGuard .conf files for static routing base. Set to "none" to disable parsing and only use the /32 anchor IP [default: /etc/wireguard]
  -h, --help                     Print help
  -V, --version                  Print version
```

## Build

Install Rust. Then install [cross](https://crates.io/crates/cross): `cargo install cross`. Note `cross` uses Docker.

Build Linux amd64:

```
cross build --target x86_64-unknown-linux-musl --release
```

Build Linux arm64:

```
cross build --target aarch64-unknown-linux-musl --release
```

Build Linux mipsle (soft float):

```
cross +nightly build --target mipsel-unknown-linux-musl \
  -Z build-std=std,core,alloc,panic_unwind \
  --release
```

The built binary can be found in `target/x86_64-unknown-linux-musl/release` dir.

[bird]: https://bird.network.cz/

## Run as system service

### Systemd service

/etc/systemd/system/wg-dynamic-allowedips.service :

```
# systemd service
# put binary to: /usr/bin/wg-dynamic-allowedips
# put this file to: /etc/systemd/system/wg-dynamic-allowedips.service
# then run:
#   systemctl daemon-reload && systemctl enable --now wg-dynamic-allowedips

[Unit]
Description=WireGuard Dynamic AllowedIPs Daemon
After=network.target

[Service]
ExecStart=/usr/bin/wg-dynamic-allowedips
Restart=always
User=root
# Adjust Environment if wg is not in standard path
# Environment="PATH=/usr/bin:/usr/local/bin"

[Install]
WantedBy=multi-user.target

```

### start-stop-daemon

```sh
# start
start-stop-daemon -S -b -x wg-dynamic-allowedips

# stop
start-stop-daemon -K -x wg-dynamic-allowedips
```
