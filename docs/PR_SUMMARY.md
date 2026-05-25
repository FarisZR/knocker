# PR Summary

- Removed the duplicate `dev/*.localtest*` compose files and wrapper scripts.
- Moved the non-conflicting host ports into the standard test stacks:
  - `dev/docker-compose.yml`
  - `dev/docker-compose.ci.yml`
- Standardized the dev test entrypoints on:
  - `http://localhost:18080`
  - `https://localhost:18443`
- Updated `dev/local_integration_tests.sh` and `dev/firewalld_integration_test.sh` to use the standard stacks and ports directly.
- Updated agent guidance and user-facing docs to reflect the single-stack test workflow.
