# Deployment guide

## Deployment status

The application is ready for a single-instance hackathon/demo deployment. The production
container was smoke-tested locally: it builds the React application, serves it from
FastAPI, binds to the platform `PORT`, returns `200` from `/api/health`, emits WebMCP and
browser security headers, and stores SQLite state at `/data/security_workspace.db`.

The configured GitHub remote is reachable, but this local repository currently has no
commits and the remote has no refs. A GitHub-backed Railway deployment therefore cannot
start until the project has an initial commit and push. No commit, push, or Railway
deployment was performed during this review.

It is not an enterprise multi-tenant SOC deployment. Authentication, RBAC, tenant
isolation, CSRF protection, rate limiting, centralized audit export, PostgreSQL
migrations, and a secrets-management integration are intentionally outside the current
demo boundary. Do not expose real customer telemetry through this build.

## Recommended host: Railway

Railway is the shortest reliable path for this project because it builds the checked-in
Dockerfile, provides managed HTTPS required by WebMCP, supports a persistent volume, and
can health-check `/api/health`.

1. Commit the reviewed project locally, then push it to the configured GitHub remote.
2. In Railway, create a project and choose **Deploy from GitHub repo**.
3. Select this repository. Keep the service source directory at the repository root;
   Railway automatically detects the root `Dockerfile`.
4. Add a volume to the service and mount it at `/data`.
5. Confirm the service variable:

   ```text
   DATABASE_URL=sqlite:////data/security_workspace.db
   ```

   The Docker image already supplies this default, but setting it explicitly documents
   the storage contract in the platform configuration.
6. Keep the service at **one replica**. SQLite and a single attached volume are not a
   horizontal-scaling design.
7. Under **Networking → Public Networking**, generate a Railway domain. Railway supplies
   HTTPS automatically.
8. In **Settings → Deploy**, set the health-check path to `/api/health` and keep the
   default 300-second timeout. Optionally set the restart policy to **On failure** with a
   maximum of five retries.
9. Open the HTTPS domain, connect the three telemetry sources, and verify the workflow.

The fully ingested local SQLite database is currently about 57 MB, so Railway's current
0.5 GB free/trial volume allowance is sufficient for this bounded demo. Monitor volume
usage and keep backups if the deployed investigation state matters.

### Railway configuration note (September 2026)

Do not rely on the checked-in `railway.json` when creating a new service. Railway has
deprecated legacy Config as Code, does not allow new services to opt into it, and will
stop supporting existing opt-ins on 1 December 2026. It remains in this workspace only
as a legacy reference; the deployment path above uses Railway's automatic root
`Dockerfile` detection plus explicit dashboard settings. If this project later needs
fully versioned Railway infrastructure, migrate those settings to Railway's current
`.railway/railway.ts` Infrastructure as Code workflow.

Official references: [Dockerfile detection](https://docs.railway.com/builds/dockerfiles),
[health checks and `PORT`](https://docs.railway.com/deployments/healthchecks),
[persistent-volume limits](https://docs.railway.com/volumes/reference), and
[Config as Code deprecation](https://docs.railway.com/config-as-code).

## Post-deployment verification

Run these checks against the generated domain:

```bash
curl -fsS https://YOUR-DOMAIN/api/health
curl -fsS -D - -o /dev/null https://YOUR-DOMAIN/
```

The health response must be `{"status":"ok"}`. The document response should include:

```text
Permissions-Policy: tools=(self)
Origin-Agent-Cluster: ?1
Content-Security-Policy: ...
Strict-Transport-Security: ...
```

In WebMCP-enabled Chrome, inspect:

```js
window.isSecureContext
document.modelContext ?? navigator.modelContext
window.__aegisWebMcpStatus
```

Expected results are `true`, a model-context object, and eight registered tools.

## Other viable hosts

- **Render:** use the Dockerfile and attach a persistent disk mounted at `/data`. An
  ephemeral/free filesystem will lose the SQLite workspace during replacement or restart.
- **Fly.io:** deploy the Docker image and mount a Fly Volume at `/data`. Keep one machine
  while the application uses SQLite.
- **Any container host:** provide HTTPS at the edge, forward the platform `PORT`, preserve
  `/data`, and keep a single writer.

For real production evolution, move state to managed PostgreSQL before adding replicas.
