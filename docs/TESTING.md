# Testing

```bash
bash dev/test.sh linux
```

This runs the complete Linux suite: Python tests, Ruff lint/format checks, ty,
Caddy, isolated FirewallD packet tests, and the original host FirewallD Bash suite.
GitHub Actions runs these same checks in parallel on every PR, push to `main`,
and manual workflow run. The host job installs and starts FirewallD on its own
disposable GitHub-hosted Linux runner and invokes `dev/firewalld_integration_test.sh`
directly. Host D-Bus access and the default zone-target case are required checks,
alongside the real packet tests. There is no emulation or VM boot step in the workflow.

After dependency updates, run `uv sync --locked --all-groups` before the Python
checks so validation uses the committed dependency and tool versions. If your
environment overrides `TMPDIR` outside the permitted whitelist storage roots,
run with `TMPDIR=/tmp` so temporary whitelist fixtures remain valid.

For environments without a host FirewallD daemon, run the portable subset:

```bash
bash dev/test.sh                 # Python and both isolated integration modes
bash dev/test.sh isolated        # the same portable subset, explicitly
```

Requirements: uv, Python 3.13+, Linux Docker 27+ with a kernel supporting
namespaced nftables and IPv6, and Docker Compose v2.20.2+. Docker Desktop provides a
Linux daemon too. The isolated suites do not require host FirewallD or systemd.
Unsupported firewall/kernel capabilities fail the suite rather than skip it.
The full `linux` mode additionally requires the host prerequisites described below;
it fails if the host suite cannot run, rather than falling back to the subset.

## Required integration suites

```bash
bash dev/integration_tests.sh caddy       # real Caddy authentication
bash dev/integration_tests.sh firewalld   # real FirewallD and packet filtering
bash dev/integration_tests.sh all         # both modes
```

`dev/local_integration_tests.sh` is the Caddy wrapper. Both isolated stacks have
unique Compose project names and disposable data volumes; they wait for readiness
and remove their own containers, networks, volumes and built image on success or
failure. Failures print service logs and the container-local firewall state.

`dev/docker-compose.ci.yml` runs Caddy and its HTTP client on an internal bridge.
`dev/docker-compose.firewalld-ci.yml` runs the production Knocker image, a private
system D-Bus daemon, FirewallD, protected echo services and two unprivileged clients
on an internal Docker dual-stack bridge. IPv4 and IPv6 addresses are allocated by
Docker. Test listeners bind their assigned container addresses, with a loopback
API listener for health checks. Only the firewall server receives `NET_ADMIN`.
Neither CI stack publishes host ports, uses host networking or mounts host D-Bus
or the Docker socket. The controller verifies the isolation before sending traffic.

| Suite | Coverage |
| --- | --- |
| Python | Configuration, rule construction, application behavior, rollback, concurrency and persistence |
| Caddy | Unauthorized/authorized access, public paths, forwarded addresses, remote grants, key permissions and TTL validation/capping |
| Isolated FirewallD | TCP/UDP blocking and authorization, IPv4/IPv6 expiry, source isolation, spoofed forwarded headers, remote/CIDR grants, shorter TTL replacement, reload/restart recovery, readiness and daemon failure |
| Host FirewallD | Original Linux Bash suite: host D-Bus/permissions, zone creation and default target, priority/sources, all monitored rules, grants/expiry/replacement, recovery, rejected keys/permissions and readiness |

TCP 9000 and UDP 9001 are protected. TCP 9002 is an unmonitored control that must
remain reachable. Negative probes require socket timeouts; successful probes
require the echo payload. All probes use fresh connections. Control/TCP/UDP probes
run concurrently within one client invocation, avoiding repeated Docker execs and
serial timeout waits. Expiry checks poll the actual daemon with bounded deadlines.
The Python reconciliation regression also checks that recognizing existing
canonical rich rules does not issue any `--add-rich-rule=` commands.
Rule-builder tests retain invalid IP, port, and protocol validation coverage.

## Required host FirewallD checks

The original host integration entry point remains:

```bash
bash dev/firewalld_integration_test.sh
```

It uses `dev/docker-compose.yml` and the host system D-Bus socket. It requires a
running host FirewallD 2.0+ daemon, uv, and root or passwordless sudo for zone cleanup.
The suite checks the actual host daemon, default zone target/priority/sources,
every IPv4/IPv6 TCP/UDP rule, expiry and shorter TTL replacement, recovery of all
eight timed rules with unchanged persistence, rejected keys/remote permissions,
and readiness when protection is missing. The shorter-TTL replacement uses a
15-second grant against an original 120-second grant: replacing four rules
requires twelve CLI calls, so a six-second grant can expire before persistence
on slower hosts. The expiry check remains bounded to 20 seconds.
As in the original host test, requests through the development Caddy proxy use
a simulated documentation address; real peer/packet checks live in the CI suite.
The host test client disables its container AppArmor profile to reach the host
system bus; the isolated CI stack retains Docker's default confinement.

Each run creates a unique zone and uses documentation-only source addresses.
Cleanup removes only that run's zone, containers and volume, and never stops the
host daemon. The suite performs real FirewallD reloads; use a dedicated development
host. This supplements the CI packet tests with host D-Bus and host policy checks;
external routing and Docker DNAT/FORWARD topology still need deployment validation.

The **Run Tests** workflow runs this exact Bash suite on every PR. It has its own
runner and runs alongside the isolated suites, so host checks do not add a serial
wait after the packet tests. No checkbox or manual invocation is needed in CI.

## Dependency maintenance

Dependabot checks Python dependencies, GitHub Actions, and Docker images weekly.
The uv entry includes indirect dependencies and groups Python updates into one PR,
so packages such as Pydantic, pydantic-core, and Starlette do not remain at older
lockfile versions when their parent dependency still permits newer releases.
Docker updates cover both the production Dockerfile and the Caddy test stacks in
`dev/`. The uv binary version/checksums in `Dockerfile` and the cosign binary
version in the publishing workflow require a manual check when refreshing tools.

To refresh Python dependencies deliberately:

```bash
uv lock --upgrade
uv sync --locked --all-groups
bash dev/test.sh linux
```

The production image uses Python 3.15 and uv 0.13.8. Pydantic 2.14.3 pins
pydantic-core 2.50.4, whose Python 3.15 wheels cover amd64, arm64, and arm/v7;
this avoids requiring a Rust/C compiler in the slim runtime image. Tests use
httpx2 2.16.0, the supported TestClient dependency in Starlette 1.10.0. The Caddy
stacks use 2.11.9, pinned to its multi-architecture image digest. Publication uses
cosign 3.1.4; release signing still requires the GitHub Actions OIDC identity and
registry write access and is not exercised by the local application test suites.

A dependency refresh must pass the complete Linux suite and the three-architecture
Docker build before release. Python checks alone can use cached locally built
wheels and do not prove a clean slim image can install dependencies.

## Runtime and builds

The required `test` check aggregates Python, both isolated integration jobs, and
the complete host FirewallD job.
Any failed, cancelled or skipped required suite fails the gate. Each integration
job has an eight-minute limit, Python has five minutes and the gate has one minute.
Older runs of the same PR are cancelled when a new commit arrives.
Manual runs use a separate concurrency group so a push cannot interrupt them.

GitHub Actions builds and loads the production image from the PR checkout with
BuildKit caching. Each mode has its own cache scope. No host CA bundle, custom
certificate path or environment-specific build configuration is required.

To reuse an image during local development:

```bash
docker build -t knocker-dev .
KNOCKER_TEST_IMAGE=knocker-dev bash dev/integration_tests.sh all
```

The runner preserves caller-provided images. CI always builds the current checkout
before supplying an image, so a stale local image cannot make PR checks pass.
