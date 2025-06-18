# DNS Firewall & Forwarder with DNS-over-HTTPS (DoH)

This project implements a DNS forwarder with **firewall blocking** and optional **DNS-over-HTTPS (DoH)** support. It allows DNS queries to be filtered against a deny list and forwarded to a resolver using traditional DNS or encrypted DoH.

## 🔧 Features

- Denies DNS queries for domains listed in `deny_list.txt`
- Responds with `NXDOMAIN` for denied domains
- Supports forwarding:
  - To another DNS server (e.g., 8.8.8.8)
  - Via DNS-over-HTTPS using Google's or custom DoH server
- Logging of allowed/denied queries
- Written in both **C (main version)** and **Python (alternative)**

---

## 📂 Project Structure

| File | Description |
|------|-------------|
| `dns_forwarder.c` | Main DNS forwarder implementation with firewall and DoH support |
| `dns_forwarder.py` | Alternative lightweight version in Python |
| `deny_list.txt` | List of domain names to block |
| `Makefile` | Compilation rules for building the C-based forwarder |
| `queries.log` | (Generated) log of allowed/denied domain queries |

---

## 🛠️ Build Instructions (C Version)

```bash
make
```

This builds the executable (e.g., `dns_forwarder`).

---

## 🚀 Running the DNS Forwarder

### Basic usage (forward to DNS server):
```bash
./dns_forwarder -d 8.8.8.8 -f deny_list.txt -l queries.log
```

### With DNS-over-HTTPS:
```bash
./dns_forwarder -f deny_list.txt -l queries.log --doh --doh_server_address dns.google
```

- `-d`: Destination IP for normal DNS forwarding
- `-f`: Path to deny list file
- `-l`: Log file path
- `--doh`: Enable DoH mode
- `--doh_server_address`: Use custom DoH server (default: `8.8.8.8`)

---

## 🧪 Sample Deny List

```
www.example.com
cobweb.cs.uga.edu
yahoo.co.jp
```

Any query matching these domains will be blocked with an `NXDOMAIN` response.

---

## 📜 License

This project is for educational use and demonstration purposes.

---

## 👩‍💻 Author

Sharvani Chelumalla  
M.S. in Computer Science – University of Georgia