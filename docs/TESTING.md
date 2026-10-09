# Testing

```bash
bash dev/test.sh
```

This runs Python tests, Ruff lint/format checks, ty, and the two required live
integration suites. GitHub Actions runs Python checks and both integration modes
in parallel on every PR. There is no emulation or VM boot step in the workflow.

Requirements: uv, Python 3.13+, Linux Docker 27+ with a kernel supporting
namespaced nftables and IPv6, and Docker Compose v2. Docker Desktop provides a
Linux daemon too. The isolated suites do not require host FirewallD or systemd.
Unsupported firewall/kernel capabilities fail the suite rather than skip it.

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

TCP 9000 and UDP 9001 are protected. TCP 9002 is an unmonitored control that must
remain reachable. Negative probes require socket timeouts; successful probes
require the echo payload. All probes use fresh connections. Control/TCP/UDP probes
run concurrently within one client invocation, avoiding repeated Docker execs and
serial timeout waits. Expiry checks poll the actual daemon with bounded deadlines.

## Additional host FirewallD checks

The original host integration entry point remains:

```bash
bash dev/firewalld_integration_test.sh
```

It uses `dev/docker-compose.yml` and the host system D-Bus socket. It requires a
running host FirewallD daemon, uv, and root or passwordless sudo for zone cleanup.
The suite checks the actual host daemon, default zone target/priority/sources,
every IPv4/IPv6 TCP/UDP rule, expiry and shorter TTL replacement, recovery of all
eight timed rules with unchanged persistence, rejected keys/remote permissions,
and readiness when protection is missing.
The host test client disables its container AppArmor profile to reach the host
system bus; the isolated CI stack retains Docker's default confinement.

Each run creates a unique zone and uses documentation-only source addresses.
Cleanup removes only that run's zone, containers and volume, and never stops the
host daemon. The suite performs real FirewallD reloads; use a dedicated development
host. This supplements the CI packet tests with host D-Bus and host policy checks;
external routing and Docker DNAT/FORWARD topology still need deployment validation.

The **Run Tests** workflow also offers a manual `run_host_firewalld` checkbox to
run this suite on a disposable GitHub-hosted runner. It adds no work to PR runs.

## Runtime and builds

The required `test` check aggregates Python and both isolated integration jobs.
Any failed, cancelled or skipped required suite fails the gate. Each integration
job has an eight-minute limit, Python has five minutes and the gate has one minute.
Older runs of the same PR are cancelled when a new commit arrives.

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
