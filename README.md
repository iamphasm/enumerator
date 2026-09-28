# vscan: service enumeration and outdated-software check

`vscan.py` runs `nmap -sV` and `nikto` against a host and lists every product and
version it can identify. It then looks each one up in a local database of release
sources and marks it as outdated or up to date. The report is saved to
`scans/<YYYY-MM-DD_HH-MM-SS>.scan`. When the target is the machine running the scan,
it also writes `scans/<YYYY-MM-DD_HH-MM-SS>_update.sh`, which upgrades the outdated packages.

Only scan hosts you own or are authorised to test.

## Requirements

- Python 3.8+ (standard library only)
- `nmap` and `nikto` on `PATH`

## Usage

```bash
python3 vscan.py 192.168.1.10                     # scan a host
python3 vscan.py 127.0.0.1                        # scan this machine; also writes an update script
python3 vscan.py 10.0.0.5 --nmap-args "-p- -T4"   # extra nmap arguments
python3 vscan.py 10.0.0.5 --nikto-maxtime 10m     # cap nikto's run time
python3 vscan.py 10.0.0.5 --no-nikto              # nmap only
python3 vscan.py 10.0.0.5 --refresh               # ignore cached release versions
```

Other options: `--nikto-all`, `--nmap-timeout`, `--nikto-timeout`, `--out-dir`,
`--local` / `--remote` (override local detection). The exit code is 1 if anything is outdated.

How it works:

1. `nmap -sV <target>` is parsed from its XML output. Product names, versions,
   CPE identifiers and the "extra info" field are all used.
2. `nikto -h <target> -p <web ports>` runs only against the web ports nmap found.
   The `Server:` and `X-Powered-By` banners and nikto's "appears to be outdated"
   notes are parsed.
3. Each product is reduced to a software name by matching it against the database
   aliases. For example, `Apache httpd`, `Apache/2.4.41` and `cpe:/a:apache:http_server`
   all become `apache-httpd`.
4. The release page for that software is fetched, all versions are pulled out with
   the stored regex, and the installed version is compared with the newest one.

### Statuses

| Status        | Meaning |
|---------------|---------|
| OUTDATED      | A newer release exists in the same release branch |
| OLD BRANCH    | Newest in its branch, but a newer major/minor branch exists |
| UP-TO-DATE    | Installed version is the newest known |
| NO VERSION    | Software was identified but its version was hidden |
| NOT IN DB     | No database entry matches the product. Add one (see below) |
| LOOKUP FAILED | The release page could not be fetched or the regex matched nothing |

Linux distributions often backport security fixes without changing the upstream
version number. The report notes when a version string looks like a distro build
(for example `8.9p1 Ubuntu 3ubuntu0.10`), because "outdated" may then be a false alarm.

## The update script

This is only generated when the target resolves to this machine, such as
`127.0.0.1`, `localhost` or one of its own interface IPs. The script:

- detects apt, dnf, yum, pacman, zypper or apk at run time
- upgrades only packages that are already installed and never installs new ones
- restarts the affected systemd services that are running
- lists software without a package mapping as needing a manual update

```bash
./scans/2026-09-28_10-31-27_update.sh --dry-run   # show what it would do
sudo ./scans/2026-09-28_10-31-27_update.sh        # asks before upgrading
sudo ./scans/2026-09-28_10-31-27_update.sh --yes  # no prompt
```

Distro repositories can lag upstream, so a package can still show as outdated after
the upgrade. Review the script before running it.

## The database

`data/software.db` is an SQLite database built from `data/seed.json`. It is created
automatically on first run. Each entry has:

| Field          | Purpose |
|----------------|---------|
| `name`         | Canonical software name |
| `aliases`      | Lowercase names matched against nmap/nikto products. Entries with `:` are CPE `vendor:product` pairs |
| `url`          | Page or API that lists releases |
| `regex`        | Exactly one capture group that matches a version |
| `branch_depth` | `0` compares with the newest release, `1` with the same major, `2` with the same major.minor |
| `packages`     | Package names per manager (`apt`, `dnf`, `pacman`, `zypper`, `apk`) |
| `services`     | systemd units to restart after upgrading |
| `notes`        | Shown in the report |

Fetched release lists are cached in the database for 12 hours.

```bash
python3 swdb.py list                 # all entries
python3 swdb.py show nginx           # one entry
python3 swdb.py check                # fetch every source and report failures
python3 swdb.py check nginx php      # check specific entries
python3 swdb.py add gitea \
    --url "https://api.github.com/repos/go-gitea/gitea/releases?per_page=100" \
    --regex '"tag_name":\s*"v(\d+\.\d+\.\d+)"' \
    --alias gitea --apt gitea --dnf gitea --service gitea
python3 swdb.py remove gitea
python3 swdb.py export data/seed.json  # write the database back to the seed file
python3 swdb.py init --force           # rebuild the database from the seed file
```

Run `python3 swdb.py check` now and then. Project websites change, and a failing
regex shows up there as `FAIL`. GitHub API sources allow 60 unauthenticated
requests per hour. Set `GITHUB_TOKEN` to raise that limit.

Seeded software (35 entries): apache-httpd, apache-tomcat, bind, caddy, cups,
dnsmasq, dovecot, elasticsearch, exim, grafana, haproxy, jenkins, jetty, lighttpd,
mariadb, memcached, mongodb, mysql, nginx, nodejs, openssh, openssl, php, postfix,
postgresql, proftpd, pure-ftpd, python, rabbitmq, redis, samba, squid, unrealircd,
vsftpd, wordpress.

## Troubleshooting

- **Host shows as down or every port is "filtered".** Add `--nmap-args -Pn`. Under
  WSL or in containers, raw sockets may not work, so also add `--unprivileged` to
  force a connect scan.
- **nikto takes very long.** Use `--nikto-maxtime 5m`.
