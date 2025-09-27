# Interactive API Documentation

Knocker now publishes its OpenAPI specification automatically at runtime. The schema is regenerated during application startup using FastAPI's router metadata, ensuring the documentation always matches the deployed API surface.

## Generated artifacts

- **OpenAPI document**: Served at `/openapi.json` and persisted to the filesystem path configured by `documentation.openapi_output_path` (defaults to `docs/openapi.json`).
- **Swagger UI**: Available at `/docs`, providing an interactive request explorer powered by the generated OpenAPI document.
- **ReDoc**: Available at `/redoc`, offering a documentation-first rendering of the same specification.

The generated file is safe to regenerate on every launch and is ignored by version control so runtime refreshes never pollute your working tree.

## Configuration

Add the `documentation` block to `knocker.yaml` (or update your existing configuration) to control where the generated schema is written:

```yaml
documentation:
  openapi_output_path: "docs/openapi.json"
```

Paths may be absolute or relative to the service's working directory. If the file is missing when `/openapi.json` is requested, Knocker will regenerate it on demand.
