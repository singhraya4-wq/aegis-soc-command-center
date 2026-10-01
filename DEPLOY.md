# Deploy AEGIS SOC v2

## Local
```bash
pip install -r requirements.txt
./run.sh
```
Open `http://localhost:8080`.

## Docker
```bash
docker build -t aegis-soc .
docker run --rm -p 8080:8080 aegis-soc
```

## Render / similar Docker host
1. Put this folder in a Git repository.
2. Create a Docker web service from the repository.
3. Use port `8080`.
4. Health check: `/api/health`.
5. The included `render.yaml` documents the service configuration.

The package is deployment-ready, but it is not publicly hosted from this chat because publishing requires access to your hosting account/repository credentials.
