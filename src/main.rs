use clap::Parser;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, about = r#"
Daemon to watch Linux kernel routes and dynamically update WireGuard peer's `allowed-ips`.
It's intended to be used to help run BGP / OSPF over WireGuard mesh network.

How it works:
1. Run `ip monitor route` to watch main routing table changes.
2. After any `wg*` interface related routing table change detected, it runs `ip route show table main` to
   get full system routing info, recognize `192.168.1.0/24 via 192.168.100.10 dev wg0 proto bird` style
   routing records, then run `wg set wg0 peer <peer_public_key> allowed-ips 192.168.100.10,192.168.1.0/24` to
   update peer's `allowed-ips`.

Where:
- `192.168.100.10` : the peer's private /32 ip, which should be defined statically in `AllowedIPs = ` line
  of `/etc/wireguard/<interface>.conf` wireguard / wg-quick config file.
- `192.168.1.0/24 via 192.168.100.10 dev wg0 proto bird` : system routing table record to route
  the `192.168.1.0/24` subnet through `192.168.100.10` peer. While the `via <peer_ip>` directive itself has
  no effect to wireguard, this program uses it to associate the subnet with the peer.
  The routing table records are expected to be added by Bird using BGP / OSPF.
"#)]
struct Args {
    /// Specific WireGuard interface to watch (e.g., wg0). Watches all wg* interfaces if omitted.
    #[arg(short, long)]
    interface: Option<String>,

    /// Directory containing WireGuard .conf files for static routing base.
    /// Set to "none" to disable parsing and only use the /32 anchor IP.
    #[arg(short, long, default_value = "/etc/wireguard")]
    config_dir: String,
}

#[derive(Debug, Clone)]
struct Route {
    prefix: String,
    via_ip: String,
    dev: String,
}

#[derive(Debug)]
struct PeerState {
    pubkey: String,
    anchor_ip_stripped: String,
    anchor_with_mask: String,
    current_ips: Vec<String>,
}

fn main() {
    let args = Args::parse();

    println!("Starting wg-dynamic-allowedips...");
    if let Some(ref iface) = args.interface {
        println!("Watching specific interface: {}", iface);
    } else {
        println!("Watching all wg* interfaces.");
    }

    if args.config_dir.to_lowercase() == "none" {
        println!("Static config parsing disabled. Base state is anchor IP only.");
    } else {
        println!("Reading static config base from: {}", args.config_dir);
    }

    // 1. Run a full scan and update on program start
    sync_state(&args.interface, &args.config_dir);

    // 2. Setup channel for triggers
    let (tx, rx) = mpsc::channel();
    let target_iface_clone = args.interface.clone();

    // 3. Spawn a thread to monitor 'ip monitor route'
    thread::spawn(move || {
        let mut child = Command::new("ip")
            .args(["monitor", "route"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start 'ip monitor route'");

        let stdout = child.stdout.take().expect("Failed to open stdout");
        let reader = BufReader::new(stdout);

        for line in reader.lines() {
            if let Ok(line) = line {
                let is_match = match &target_iface_clone {
                    Some(iface) => line.contains(&format!("dev {}", iface)),
                    None => line.contains("dev wg"),
                };

                if is_match {
                    let _ = tx.send(());
                }
            }
        }
    });

    // 4. Main loop with debounce logic
    loop {
        if rx.recv().is_ok() {
            loop {
                match rx.recv_timeout(Duration::from_millis(500)) {
                    Ok(_) => continue,
                    Err(mpsc::RecvTimeoutError::Timeout) => break,
                    Err(_) => return,
                }
            }

            println!("\nRouting change detected and debounced. Synchronizing...");
            sync_state(&args.interface, &args.config_dir);
        }
    }
}

fn sync_state(target_interface: &Option<String>, config_dir: &str) {
    let routes = get_bird_routes();

    let mut ifaces_to_update = HashSet::new();
    for route in &routes {
        let matches_filter = match target_interface {
            Some(iface) => &route.dev == iface,
            None => route.dev.starts_with("wg"),
        };
        if matches_filter {
            ifaces_to_update.insert(route.dev.clone());
        }
    }

    // If an interface was explicitly passed, ensure we check it even if no dynamic routes exist yet
    if let Some(iface) = target_interface {
        ifaces_to_update.insert(iface.clone());
    }

    for iface in ifaces_to_update {
        update_wireguard_interface(&iface, &routes, config_dir);
    }
}

fn get_bird_routes() -> Vec<Route> {
    let output = Command::new("ip")
        .args(["route", "show", "table", "main"])
        .output()
        .expect("Failed to execute 'ip route'");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut routes = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();

        let via_pos = parts.iter().position(|&r| r == "via");
        let dev_pos = parts.iter().position(|&r| r == "dev");

        if let (Some(v_idx), Some(d_idx)) = (via_pos, dev_pos) {
            if v_idx + 1 < parts.len() && d_idx + 1 < parts.len() {
                let mut prefix = parts[0].to_string();
                if prefix == "default" {
                    prefix = "0.0.0.0/0".to_string();
                }

                routes.push(Route {
                    prefix,
                    via_ip: parts[v_idx + 1].to_string(),
                    dev: parts[d_idx + 1].to_string(),
                });
            }
        }
    }
    routes
}

/// Parses the wg.conf file to extract static AllowedIPs for each public key
fn parse_wg_conf(path: &str) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Warning: Could not open static config {}: {}", path, e);
            return map;
        }
    };

    let reader = BufReader::new(file);
    let mut current_pubkey: Option<String> = None;

    for line in reader.lines().filter_map(Result::ok) {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        if line.starts_with("[Peer]") {
            current_pubkey = None;
        } else if line.to_lowercase().starts_with("publickey") {
            // FIXED: Use split_once to avoid stripping Base64 '=' padding
            if let Some((_, key)) = line.split_once('=') {
                current_pubkey = Some(key.trim().to_string());
            }
        } else if line.to_lowercase().starts_with("allowedips") {
            if let Some(pubkey) = &current_pubkey {
                // FIXED: Use split_once here as well for safety
                if let Some((_, ips_str)) = line.split_once('=') {
                    let ips: Vec<String> = ips_str
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();

                    map.entry(pubkey.clone())
                        .or_insert_with(Vec::new)
                        .extend(ips);
                }
            }
        }
    }
    map
}

fn update_wireguard_interface(iface: &str, all_routes: &[Route], config_dir: &str) {
    let output = Command::new("wg")
        .args(["show", iface, "allowed-ips"])
        .output();

    if output.is_err() {
        eprintln!("Failed to run wg show for {}", iface);
        return;
    }

    let out = output.unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);

    let mut active_peers: Vec<PeerState> = Vec::new();

    // 1. Get current state from wg show
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let pubkey = parts[0].to_string();
        if parts[1] == "(none)" {
            continue;
        }

        let anchor_with_mask = parts[1].to_string();
        let anchor_ip_stripped = anchor_with_mask.split('/').next().unwrap_or("").to_string();
        let current_ips: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();

        active_peers.push(PeerState {
            pubkey,
            anchor_ip_stripped,
            anchor_with_mask,
            current_ips,
        });
    }

    // 2. Load Static Base State
    let static_config = if config_dir.to_lowercase() != "none" {
        let conf_path = format!("{}/{}.conf", config_dir, iface);
        parse_wg_conf(&conf_path)
    } else {
        HashMap::new()
    };

    // 3. Calculate Desired State and Apply
    for peer in active_peers {
        let mut target_ips_set: HashSet<String> = HashSet::new();

        // A. Add Static IPs from config
        if let Some(static_ips) = static_config.get(&peer.pubkey) {
            for ip in static_ips {
                target_ips_set.insert(ip.clone());
            }
        }

        // B. ALWAYS ensure the anchor IP is in the target list
        target_ips_set.insert(peer.anchor_with_mask.clone());

        // C. Add Active Dynamic Routes
        for route in all_routes {
            if route.dev == iface && route.via_ip == peer.anchor_ip_stripped {
                target_ips_set.insert(route.prefix.clone());
            }
        }

        // 4. Compare using HashSets to ignore ordering differences from 'wg show'
        let current_ips_set: HashSet<String> = peer.current_ips.iter().cloned().collect();

        if target_ips_set != current_ips_set {
            // Filter out the anchor IP from the rest of the list so we can sort them
            let mut remaining_ips: Vec<String> = target_ips_set
                .iter()
                .filter(|ip| **ip != peer.anchor_with_mask)
                .cloned()
                .collect();

            // Sort the dynamic/static routes alphabetically for clean output
            remaining_ips.sort();

            // Reconstruct the final list: Anchor IP ALWAYS goes first
            let mut final_ips_vec = vec![peer.anchor_with_mask.clone()];
            final_ips_vec.extend(remaining_ips);

            let joined_ips = final_ips_vec.join(",");

            println!("State change for peer {}:", &peer.pubkey[..8]);
            println!("  Old: {}", peer.current_ips.join(","));
            println!("  New: {}", joined_ips);

            let status = Command::new("wg")
                .args([
                    "set",
                    iface,
                    "peer",
                    &peer.pubkey,
                    "allowed-ips",
                    &joined_ips,
                ])
                .status();

            if let Err(e) = status {
                eprintln!("Failed to update WireGuard peer {}: {}", peer.pubkey, e);
            }
        }
    }
}
