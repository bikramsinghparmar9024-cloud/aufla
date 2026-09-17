# Live log sources in Docker

Real services, producing real logs, which AUFLA ingests by tailing the files
they write. No service here knows AUFLA exists — each one logs the way it
would in production, and the framework reads what lands on disk.

## Run

```bash
docker compose -f docker/docker-compose.yml up -d
```

```bash
python -m aufla.cli watch --dir docker/logs
```

Then generate some traffic so the logs are not empty:

```bash
curl http://localhost:8081/ && curl http://localhost:8081/missing-on-purpose
```

```bash
ssh -p 2222 -o StrictHostKeyChecking=no nosuchuser@localhost
```

## What each service gives you

| Service | Writes | Ingested as | OCSF class |
| --- | --- | --- | --- |
| nginx | `access.log`, `error.log` | `nginx_access`, `nginx_error` | 4002, 2004 |
| squid | `access.log` | `squid_access` | 4002 |
| postfix | `maillog` | `postfix_maillog` | 2004 |
| sshd | `openssh.log` | `openssh_auth` | 3002 |
| suricata | `eve.json` | `suricata_eve` | 2004, 4001 |
| zeek | `conn.log` | `zeek_conn` | 4001 |
| nftables | `kernel.log` | `iptables` | 4001 |

## Honest notes on the limits

**Suricata and Zeek read a pcap, not a live interface.** Capturing from a host
NIC needs privileges that differ across Linux, macOS and Windows, and would
make this stack unrunnable for anyone evaluating it. Drop a capture at
`docker/pcap/sample.pcap` and both will analyse it. To read a live interface
instead, change the `-r /pcap/sample.pcap` argument to `-i eth0` and add
`network_mode: host` — the log output is byte-identical either way, which is
the only thing that matters downstream.

**auditd is not in this stack.** The Linux audit subsystem talks to the kernel
over a netlink socket, and a container does not have its own audit namespace —
running it inside Docker either fails or reports the *host's* events, which
would be misleading. On a real Linux deployment auditd runs on the host and
AUFLA tails `/var/log/audit/audit.log` directly. The mapping
(`sources/linux_auditd.yaml`) is written and tested against real auditd format;
only the container is missing, because a container is the wrong place for it.

**nftables logs via the kernel ring buffer.** On a real host, rsyslog routes
`kern.*` to a file already. Inside a container there is no syslog daemon, so
the script drains `dmesg` into a file instead. The log lines themselves are
exactly what netfilter emits.

## If Docker is unavailable

Everything above is also covered by `samples/live/`, which holds
format-faithful samples of each of these logs. They exercise the same parsers
and mappings:

```bash
python -m aufla.cli ingest samples/live/nginx_access.log --source nginx_access
```

That is how the mappings were developed and tested; the containers prove the
same path works when the producer is a real daemon rather than a file.
