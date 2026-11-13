# Amit_AI-Bug-Hunter

A mobile-friendly dashboard and a small API for **authorized, non-invasive website checks**.

## Current features
- HTTP response status checks
- Common security-header presence checks
- Basic HTML title, meta description and image-alt checks
- Heuristic checks for password forms and mixed content
- Limited same-host link checks
- JSON report export in the dashboard
- GitHub Actions safety-test workflow

## Safety limits
Only scan websites you own or have explicit permission to assess. The scanner blocks localhost, private and non-public IP addresses, custom ports, and cross-host redirects. It is not a penetration-testing tool and does not attempt exploitation, brute force, login bypass, or destructive actions. Findings are heuristic indicators and must be manually verified.

## Run the API
From the backend directory:
```bash
pip install -r requirements.txt
uvicorn main:app --reload
```
Open `/docs` for interactive API documentation and `/health` for its health check.

## Deploy the API
A Render blueprint is included in `render.yaml`. Review provider pricing and service limits before deployment. After deployment, set the API URL in `frontend/app.js` as `API_BASE`. Restrict CORS to the exact frontend origin before production.

## Dashboard
Serve the contents of `frontend/` with a static host such as GitHub Pages. The dashboard is mobile-friendly and includes JSON report export. A native Android APK wrapper is a separate future build step; this repository does not yet contain an APK.

## Development
GitHub Actions runs backend safety tests on pushes and pull requests to `main`.
