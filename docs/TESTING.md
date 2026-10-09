# Running the full suite

```bash
bash dev/test.sh
```

This runs the locked Python tests, Ruff lint/format checks, ty, and both live
integration suites. Requirements: uv, Python 3.13+, Linux Docker with endpoint
sysctl support (Docker 27+), Compose v2.27+ (`driver_opts` and `up --wait`),
Buildx/BuildKit for build secrets, and a kernel supporting IPv6 and namespaced nftables.
Docker Desktop's Linux VM can provide these capabilities.
The host does not need FirewallD, systemd, or a D-Bus socket. A rootless or locked
down Docker installation that forbids namespaced `NET_ADMIN` cannot run the live
firewall suite; it must run on a Docker runner that provides that capability.
The runner fails rather than silently skipping firewall tests.

Some sandboxes expose only part of the Linux nftables API. A successful Docker
build or `NET_ADMIN` grant does not prove the kernel can run FirewallD: for
example, missing nftables rejection support prevents the daemon from starting.
Use a disposable Linux VM in that case. Run the same checkout and commands
inside the VM, with Docker managing only the VM's firewall. QEMU user networking
can provide the VM's management connection without host TAP devices or firewall
changes. This is a kernel compatibility fallback, not a mocked firewall mode.

Individual commands:

```bash
uv run pytest                            # fast tests; no firewall privileges
bash dev/local_integration_tests.sh       # real Caddy authentication
bash dev/firewalld_integration_test.sh    # real FirewallD packet filtering
bash dev/integration_tests.sh all         # both integration suites
```

The wrappers work from any working directory. Each starts the required services,
waits for readiness, and cleans up on success, failure, or a handled signal.
Failures print Compose logs and, for FirewallD, the container's zone state.
Container health checks stay cheap; the firewall controller explicitly asserts
full readiness before packet tests and after recovery. Firewall scenarios use one
ordered fixture and stop at the first failure.

For a slow emulated VM, extend health checks and scale the firewall test TTLs
and probe deadlines together:

```bash
KNOCKER_TEST_HEALTH_TIMEOUT=60s KNOCKER_E2E_TIME_SCALE=4 \
  bash dev/firewalld_integration_test.sh
```

The assertions remain the same; scaling prevents grants expiring while the slow
machine is still executing the corresponding knock and packet probes.

## Firewall isolation

`dev/docker-compose.yml` runs the production image with a private system D-Bus
daemon, FirewallD, Knocker, protected echo services, and an unmonitored control
service. FirewallD programs nftables in that container's network namespace.
Separate unprivileged `client` and `stranger` containers originate real packets.
Their fresh sockets avoid reusing established connections when checking expiry.

Only the server receives `NET_ADMIN`. No container uses `privileged`, host
networking, a host D-Bus socket, the Docker socket, or published host ports.
The E2E controller verifies these properties and that server/client namespaces
differ from one another and the controller. The network is internal; Docker
allocates a distinct IPv4 subnet per run. IPv6 uses real link-local addresses on
the private bridge, enabled with container-local and endpoint sysctls. This avoids requiring
IPv6 NAT or legacy IPv6 firewall modules on the Docker daemon host. Scoped
addresses are used only for client connections; Knocker receives the actual
IPv6 peer address. The controller refreshes server addresses after restarts,
since Docker can regenerate a MAC and link-local address. Unique project names keep concurrent
runs and cleanup separate. Configuration, rules, and whitelist files disappear
with the project's containers and volume. Docker's ordinary bridge management
still runs on its daemon host; test FirewallD never manages the host rules.

Both integration stacks use disposable named data volumes and test-only API keys.
The Caddy stack trusts its internal proxy network; firewall tests trust no proxy
and use actual socket peers. Never use these configurations for a deployment.

## Coverage

| Layer | What it proves |
| --- | --- |
| Python tests | Configuration, rule construction, application behavior, error paths, rollback, concurrency, and persistence |
| Caddy integration | Unauthorized/authorized access, public paths, forwarded client addresses, remote grants, key permissions, and TTL validation/capping |
| FirewallD integration | Actual TCP/UDP blocking before a knock, authorized traffic, other clients remaining blocked, IPv4/IPv6 expiry, shorter TTL replacement, remote/CIDR grants, reload/restart recovery without extending TTL, readiness checks, and no persisted grant after daemon failure |

The protected listeners use TCP 9000 and UDP 9001; TCP 9002 is an unmonitored
control that must remain reachable. A blocked result must be a socket timeout,
not connection refusal or an unreachable service. Successful probes require the
expected echo payload, so rule listings alone cannot make the suite pass.
This exercises filtering in the server's INPUT path, with link-local IPv6 peers.
Host Docker DNAT/FORWARD
behavior, external routing, and distribution-specific host policies need separate
deployment validation; this suite does not claim to cover every deployment topology.

## CI and builds

`.github/workflows/tests.yml` runs on every pull request, pushes to `main`, and
manual dispatches. Python checks and the Caddy/FirewallD matrix jobs run
independently, with `fail-fast: false` so both integration results are reported.
No privileged or dedicated host FirewallD runner is required.
The original `test` check now aggregates Python and both integration jobs, and
fails if any dependency fails, is cancelled, or is skipped. Existing branch
protection requiring `test` therefore covers both modes without a settings change.

On environments with an HTTPS interception proxy, Compose mounts
`CODEX_PROXY_CERT` as the optional BuildKit `proxy_ca` secret, falling back to the
host CA bundle. The Dockerfile uses that certificate for curl and uv downloads
with TLS verification enabled. The mount exists only during the build and is
not stored in the image. Preserve Docker's configured proxy settings.
