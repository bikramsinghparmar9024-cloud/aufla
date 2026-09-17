"""Generate true-to-format sample logs for every supported source.

These are *format-faithful* samples, written to match what each product
actually emits -- Zeek's tab-separated conn.log with its real ``#fields``
header, nginx's combined format with its quoted request line, auditd's nested
``msg='...'`` quoting, and so on. They exist so the parsers and mappings can be
verified against the awkward parts of each format without needing every one of
those products installed and running.

They are not a substitute for live capture. `docker/` runs the real services;
this is what lets the pipeline be developed and tested when those are not up.
"""

from __future__ import annotations

import json
import random
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INTERNAL = [f"10.0.{s}.{h}" for s in (0, 1, 2) for h in range(5, 60)]
EXTERNAL = ["203.0.113.9", "198.51.100.23", "8.8.8.8", "1.1.1.1", "93.184.216.34"]
HOSTILE = ["198.18.0.9", "198.18.7.41", "45.83.64.12"]


def write(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"  {path.relative_to(ROOT).as_posix():<42} {len(lines):>5} lines")


def build(rng: random.Random, now: int) -> None:
    def ts(i: int, n: int = 200) -> int:
        return now - (n - i) * 7

    live = ROOT / "samples" / "live"

    # --- Zeek conn.log ---------------------------------------------------
    # Real Zeek emits the #fields header; a mapping that assumed column order
    # without it would break on a version bump, so it is kept in the sample.
    zeek = [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        "#path\tconn",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\t"
        "service\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\t"
        "local_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\t"
        "resp_ip_bytes",
    ]
    for i in range(200):
        zeek.append("\t".join([
            f"{ts(i)}.{rng.randint(100000, 999999)}",
            f"C{rng.randint(10**9, 10**10)}",
            rng.choice(INTERNAL), str(rng.randint(1024, 65535)),
            rng.choice(EXTERNAL), str(rng.choice([443, 80, 53, 22])),
            "tcp", rng.choice(["http", "ssl", "dns", "-"]),
            f"{rng.uniform(0.01, 9):.6f}",
            str(rng.randint(100, 50000)), str(rng.randint(100, 900000)),
            rng.choice(["SF"] * 7 + ["REJ", "S0", "RSTO"]),
            "T", "F", "0", rng.choice(["ShADadFf", "S0", "Sr"]),
            str(rng.randint(2, 50)), str(rng.randint(200, 60000)),
            str(rng.randint(2, 50)), str(rng.randint(200, 900000)),
        ]))
    write(live / "zeek_conn.log", zeek)

    # --- iptables / nftables --------------------------------------------
    ipt = []
    for i in range(200):
        drop = rng.random() < 0.45
        src = rng.choice(HOSTILE if drop else INTERNAL)
        dst = rng.choice(INTERNAL if drop else EXTERNAL)
        proto = rng.choice(["TCP"] * 8 + ["UDP", "ICMP"])
        verdict = "Dropped" if drop else "Accepted"
        stamp = time.strftime("%b %d %H:%M:%S", time.gmtime(ts(i)))
        line = (
            f"<4>{stamp} gw kernel: [{rng.randint(10000, 99999)}."
            f"{rng.randint(100000, 999999)}] IPTables-{verdict}: IN=eth0 OUT=eth1 "
            f"MAC=00:1a:2b:3c:4d:5e SRC={src} DST={dst} "
            f"LEN={rng.randint(40, 1500)} TOS=0x00 PREC=0x00 "
            f"TTL={rng.randint(32, 64)} ID={rng.randint(1, 65535)} PROTO={proto}"
        )
        if proto in ("TCP", "UDP"):
            line += (
                f" SPT={rng.randint(1024, 65535)} "
                f"DPT={rng.choice([22, 80, 443, 3389, 445])}"
            )
            if proto == "TCP":
                line += " WINDOW=64240 RES=0x00 SYN URGP=0"
        ipt.append(line)
    write(live / "iptables.log", ipt)

    # --- nginx access, combined format -----------------------------------
    quote = '"'
    paths = ["/", "/index.html", "/api/v1/status", "/assets/app.js", "/admin"]
    agents = ["Mozilla/5.0 (X11; Linux x86_64)", "curl/8.4.0", "python-requests/2.31"]
    acc = []
    for i in range(200):
        stamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime(ts(i)))
        method = rng.choice(["GET"] * 9 + ["POST", "HEAD"])
        acc.append(
            f"{rng.choice(INTERNAL)} - {rng.choice(['-', '-', 'alice', 'bob'])} "
            f"[{stamp}] {quote}{method} {rng.choice(paths)} HTTP/1.1{quote} "
            f"{rng.choice([200] * 12 + [304, 404, 403, 500, 502])} "
            f"{rng.randint(120, 90000)} "
            f"{quote}{rng.choice(['-', 'https://intranet.test/'])}{quote} "
            f"{quote}{rng.choice(agents)}{quote}"
        )
    write(live / "nginx_access.log", acc)

    # --- nginx error ------------------------------------------------------
    messages = [
        'open() "/usr/share/nginx/html/missing" failed '
        "(2: No such file or directory)",
        "upstream timed out (110: Connection timed out) while reading "
        "response header from upstream",
        'directory index of "/var/www/" is forbidden',
    ]
    err = []
    for i in range(120):
        stamp = time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(ts(i, 120)))
        level = rng.choice(["error"] * 6 + ["warn", "crit", "notice"])
        err.append(
            f"{stamp} [{level}] {rng.randint(1000, 9999)}#0: "
            f"*{rng.randint(1, 9999)} {rng.choice(messages)}, "
            f"client: {rng.choice(INTERNAL + HOSTILE)}, server: _, "
            f"request: {quote}GET /x HTTP/1.1{quote}, host: {quote}intranet.test{quote}"
        )
    write(live / "nginx_error.log", err)

    # --- postfix ----------------------------------------------------------
    pf = []
    for i in range(150):
        stamp = time.strftime("%b %d %H:%M:%S", time.gmtime(ts(i, 150)))
        daemon = rng.choice(["smtpd", "smtp", "qmgr"])
        host = f"mail postfix/{daemon}[{rng.randint(1000, 9999)}]"
        if rng.random() < 0.4:
            pf.append(
                f"{stamp} {host}: NOQUEUE: reject: RCPT from "
                f"unknown[{rng.choice(HOSTILE)}]: 554 5.7.1 "
                f"<spam{i}@bad.test>: Relay access denied; "
                f"from=<spam{i}@bad.test> to=<user@corp.test> "
                f"proto=ESMTP helo=<bad.test>"
            )
        else:
            pf.append(
                f"{stamp} {host}: {rng.randint(10**6, 10**7):X}: "
                f"to=<user{i}@corp.test>, relay=mx.corp.test"
                f"[{rng.choice(EXTERNAL)}]:25, delay={rng.uniform(0.1, 5):.2f}, "
                f"status={rng.choice(['sent'] * 7 + ['deferred', 'bounced'])} "
                f"(250 2.0.0 OK)"
            )
    write(live / "postfix.log", pf)

    # --- auditd -----------------------------------------------------------
    # auditd nests single-quoted msg='...' inside the record, which is the
    # part naive key-value parsers get wrong.
    aud = []
    for i in range(150):
        serial = f"{ts(i, 150)}.{rng.randint(100, 999)}:{rng.randint(100, 9999)}"
        if rng.random() < 0.5:
            account = rng.choice(["root", "deploy", "admin", "svc-backup"])
            result = rng.choice(["success"] * 6 + ["failed"] * 4)
            aud.append(
                f"type=USER_LOGIN msg=audit({serial}): "
                f"pid={rng.randint(1000, 9999)} uid=0 "
                f"auid={rng.choice([0, 1000, 1001])} ses={rng.randint(1, 50)} "
                f"msg='op=login acct=\"{account}\" exe=\"/usr/sbin/sshd\" "
                f"hostname=? addr={rng.choice(INTERNAL + HOSTILE)} "
                f"terminal=ssh res={result}'"
            )
        else:
            aud.append(
                f"type={rng.choice(['SYSCALL', 'PATH', 'CONFIG_CHANGE', 'AVC'])} "
                f"msg=audit({serial}): pid={rng.randint(1000, 9999)} "
                f"uid={rng.choice([0, 1000])} "
                f"comm=\"{rng.choice(['sshd', 'sudo', 'cat', 'systemd'])}\" "
                f"exe=\"/usr/bin/{rng.choice(['sudo', 'cat', 'systemctl'])}\" "
                f"key=\"privileged\""
            )
    write(live / "auditd.log", aud)

    # --- OpenSSH ----------------------------------------------------------
    ssh = []
    for i in range(200):
        stamp = time.strftime("%b %d %H:%M:%S", time.gmtime(ts(i)))
        host = f"srv01 sshd[{rng.randint(1000, 9999)}]"
        roll = rng.random()
        if roll < 0.5:
            user = rng.choice(["admin", "root", "test", "oracle", "ubuntu"])
            # OpenSSH inserts "invalid user" only for accounts that do not
            # exist -- exactly the lines that matter in a brute-force.
            invalid = "invalid user " if rng.random() < 0.6 else ""
            ssh.append(
                f"{stamp} {host}: Failed password for {invalid}{user} "
                f"from {rng.choice(HOSTILE)} port {rng.randint(30000, 65535)} ssh2"
            )
        elif roll < 0.8:
            method = rng.choice(["publickey", "password"])
            tail = ""
            if method == "publickey":
                digest = "".join(rng.choice("abcdef0123456789") for _ in range(20))
                tail = f": RSA SHA256:{digest}"
            ssh.append(
                f"{stamp} {host}: Accepted {method} for "
                f"{rng.choice(['deploy', 'alice', 'bob'])} "
                f"from {rng.choice(INTERNAL)} port "
                f"{rng.randint(30000, 65535)} ssh2{tail}"
            )
        else:
            ssh.append(
                f"{stamp} {host}: Connection closed by authenticating user root "
                f"{rng.choice(HOSTILE)} port {rng.randint(30000, 65535)} [preauth]"
            )
    write(live / "openssh_auth.log", ssh)

    build_replay(rng, now, ts)
    build_unknown(rng, now, ts)


def build_replay(rng: random.Random, now: int, ts) -> None:
    """Vendor formats replayed from samples rather than run live."""
    replay = ROOT / "samples" / "replay"

    # --- Palo Alto PAN-OS traffic (CSV) ----------------------------------
    pan = []
    for i in range(150):
        stamp = time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(ts(i, 150)))
        action = rng.choice(["allow"] * 7 + ["deny", "drop"])
        pan.append(
            f"1,{stamp},{rng.randint(10**11, 10**12)},TRAFFIC,end,2561,{stamp},"
            f"{rng.choice(INTERNAL)},{rng.choice(EXTERNAL)},0.0.0.0,0.0.0.0,"
            f"rule-{rng.randint(1, 20)},,,{rng.choice(['web-browsing', 'ssl', 'dns'])},"
            f"vsys1,trust,untrust,ethernet1/1,ethernet1/2,LogForwarding,{stamp},"
            f"{rng.randint(1000, 99999)},1,{rng.randint(1024, 65535)},"
            f"{rng.choice([443, 80, 53])},0,0,0x0,tcp,{action},"
            f"{rng.randint(200, 900000)},{rng.randint(100, 5000)},"
            f"{rng.randint(100, 5000)},{rng.randint(2, 200)}"
        )
    write(replay / "paloalto_traffic.csv", pan)

    # --- Cisco ASA --------------------------------------------------------
    asa = []
    for i in range(150):
        stamp = time.strftime("%b %d %Y %H:%M:%S", time.gmtime(ts(i, 150)))
        if rng.random() < 0.45:
            asa.append(
                f"{stamp} asa01 : %ASA-6-302013: Built outbound TCP connection "
                f"{rng.randint(10000, 999999)} for outside:{rng.choice(EXTERNAL)}/"
                f"{rng.choice([443, 80])} ({rng.choice(EXTERNAL)}/"
                f"{rng.choice([443, 80])}) to inside:{rng.choice(INTERNAL)}/"
                f"{rng.randint(1024, 65535)} ({rng.choice(INTERNAL)}/"
                f"{rng.randint(1024, 65535)})"
            )
        else:
            asa.append(
                f"{stamp} asa01 : %ASA-4-106023: Deny tcp src "
                f"outside:{rng.choice(HOSTILE)}/{rng.randint(1024, 65535)} dst "
                f"inside:{rng.choice(INTERNAL)}/{rng.choice([22, 445, 3389])} "
                f"by access-group \"outside_access_in\" [0x0, 0x0]"
            )
    write(replay / "cisco_asa.log", asa)

    # --- FortiGate (native key=value) ------------------------------------
    fg = []
    for i in range(150):
        t = time.gmtime(ts(i, 150))
        action = rng.choice(["accept"] * 7 + ["deny", "close"])
        fg.append(
            f"date={time.strftime('%Y-%m-%d', t)} "
            f"time={time.strftime('%H:%M:%S', t)} "
            f"devname=\"FGT60F\" devid=\"FG60FTK20000000\" "
            f"logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" "
            f"srcip={rng.choice(INTERNAL)} srcport={rng.randint(1024, 65535)} "
            f"srcintf=\"internal\" dstip={rng.choice(EXTERNAL)} "
            f"dstport={rng.choice([443, 80, 53])} dstintf=\"wan1\" "
            f"proto=6 action=\"{action}\" policyid={rng.randint(1, 30)} "
            f"service=\"HTTPS\" sentbyte={rng.randint(200, 90000)} "
            f"rcvdbyte={rng.randint(200, 900000)} "
            f"sentpkt={rng.randint(2, 200)} rcvdpkt={rng.randint(2, 200)}"
        )
    write(replay / "fortigate.log", fg)

    # --- ArcSight CEF -----------------------------------------------------
    cef = []
    for i in range(120):
        sev = rng.randint(1, 10)
        cef.append(
            f"CEF:0|Vendor|SecureAppliance|2.4|{rng.randint(100, 999)}|"
            f"{rng.choice(['Port scan detected', 'Policy violation', 'Malware blocked'])}|"
            f"{sev}|src={rng.choice(HOSTILE)} dst={rng.choice(INTERNAL)} "
            f"spt={rng.randint(1024, 65535)} dpt={rng.choice([22, 443, 445])} "
            f"proto=TCP act={rng.choice(['blocked', 'allowed'])} "
            f"rt={ts(i, 120) * 1000}"
        )
    write(replay / "arcsight_cef.log", cef)

    # --- QRadar LEEF ------------------------------------------------------
    tab = "\t"
    leef = []
    for i in range(120):
        leef.append(
            f"LEEF:2.0|Vendor|Appliance|1.0|{rng.randint(1000, 9999)}|"
            f"devTime={ts(i, 120) * 1000}{tab}src={rng.choice(HOSTILE)}{tab}"
            f"dst={rng.choice(INTERNAL)}{tab}srcPort={rng.randint(1024, 65535)}{tab}"
            f"dstPort={rng.choice([22, 443, 3389])}{tab}proto=TCP{tab}"
            f"sev={rng.randint(1, 10)}{tab}"
            f"cat={rng.choice(['Authentication', 'Firewall', 'IDS'])}"
        )
    write(replay / "qradar_leef.log", leef)

    # --- Windows Security EVTX (XML export) -------------------------------
    # The shape wevtutil produces: repeated <Data Name="..."> children, which
    # is precisely what a naive XML walk collapses.
    evtx = []
    for i in range(120):
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S.000000000Z", time.gmtime(ts(i, 120)))
        failed = rng.random() < 0.55
        event_id = 4625 if failed else 4624
        user = rng.choice(["Administrator", "svc_backup", "jdoe", "guest"])
        addr = rng.choice(HOSTILE if failed else INTERNAL)
        logon_type = rng.choice([3, 10, 2])
        extra = (
            '<Data Name="Status">0xc000006d</Data>'
            '<Data Name="SubStatus">0xc0000064</Data>' if failed else
            '<Data Name="LogonGuid">{00000000-0000-0000-0000-000000000000}</Data>'
        )
        evtx.append(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            f"<System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
            f"<EventID>{event_id}</EventID><Level>0</Level>"
            f"<TimeCreated SystemTime='{stamp}'/>"
            f"<EventRecordID>{500000 + i}</EventRecordID>"
            f"<Channel>Security</Channel><Computer>DC01.corp.test</Computer>"
            "</System><EventData>"
            '<Data Name="SubjectUserSid">S-1-5-18</Data>'
            f'<Data Name="TargetUserName">{user}</Data>'
            '<Data Name="TargetDomainName">CORP</Data>'
            f'<Data Name="LogonType">{logon_type}</Data>'
            f'<Data Name="IpAddress">{addr}</Data>'
            f'<Data Name="IpPort">{rng.randint(1024, 65535)}</Data>'
            '<Data Name="AuthenticationPackageName">NTLM</Data>'
            f"{extra}</EventData></Event>"
        )
    write(replay / "windows_security_evtx.xml", evtx)


def build_unknown(rng: random.Random, now: int, ts) -> None:
    """Formats deliberately left unmapped, to exercise the discovery lane."""
    unknown = ROOT / "samples" / "unknown"

    # --- MikroTik RouterOS ------------------------------------------------
    mt = []
    for i in range(120):
        stamp = time.strftime("%b/%d/%Y %H:%M:%S", time.gmtime(ts(i, 120)))
        mt.append(
            f"{stamp} firewall,info {rng.choice(['forward', 'input', 'output'])}: "
            f"in:ether1 out:ether2, connection-state:new "
            f"src-mac 00:0c:42:{rng.randint(10, 99)}:{rng.randint(10, 99)}:"
            f"{rng.randint(10, 99)}, proto TCP (SYN), "
            f"{rng.choice(INTERNAL)}:{rng.randint(1024, 65535)}->"
            f"{rng.choice(EXTERNAL)}:{rng.choice([443, 80, 22])}, "
            f"len {rng.randint(40, 1500)}"
        )
    write(unknown / "mikrotik_routeros.log", mt)

    # --- Kubernetes audit (JSON) ------------------------------------------
    k8s = []
    for i in range(120):
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts(i, 120)))
        k8s.append(json.dumps({
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "level": "RequestResponse",
            "auditID": f"{rng.randint(10**7, 10**8)}-audit",
            "stage": "ResponseComplete",
            "requestURI": rng.choice([
                "/api/v1/namespaces/default/pods",
                "/api/v1/secrets",
                "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
            ]),
            "verb": rng.choice(["get", "list", "create", "delete"]),
            "user": {
                "username": rng.choice(
                    ["system:serviceaccount:kube-system:default", "alice", "admin"]
                ),
                "groups": ["system:authenticated"],
            },
            "sourceIPs": [rng.choice(INTERNAL + HOSTILE)],
            "userAgent": "kubectl/v1.29.0",
            "responseStatus": {"code": rng.choice([200, 201, 403, 404])},
            "requestReceivedTimestamp": stamp,
            "stageTimestamp": stamp,
        }))
    write(unknown / "k8s_audit.json", k8s)


def main() -> int:
    rng = random.Random(20260917)
    now = int(time.time())
    print("generating format-faithful samples:")
    build(rng, now)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
