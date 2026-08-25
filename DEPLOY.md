# Deploying RepoSentinel — Free Tier Guide

## Services used (all free)

| Service | Platform | URL |
|---|---|---|
| MongoDB | MongoDB Atlas | cloud.mongodb.com |
| Redis | Upstash | upstash.com |
| Node API + Worker | Render | render.com |
| Python Engine | Render | render.com |
| Frontend | Vercel | vercel.com |

Total cost: $0

---

## Step 1 — MongoDB Atlas

1. Go to https://cloud.mongodb.com → create account
2. Create a project → Build a Database → **M0 Free** tier
3. Choose a cloud region (any)
4. Create a database user:
   - Username: `reposentinel`
   - Password: generate a strong one, save it
5. Network Access → Add IP Address → **Allow access from anywhere** (`0.0.0.0/0`)
6. Connect → Drivers → copy the connection string:
   ```
   mongodb+srv://reposentinel:<password>@cluster0.xxxxx.mongodb.net/reposentinel
   ```
   Replace `<password>` with your password.

---

## Step 2 — Upstash Redis

1. Go to https://upstash.com → create account
2. Create Database → type **Redis** → pick a region
3. Go to the database → **Details** tab
4. Copy these values:
   - `Endpoint` → this is your `REDIS_HOST`
   - `Port` → this is your `REDIS_PORT`
   - `Password` → this is your `REDIS_PASSWORD`

---

## Step 3 — Render: Python Engine

1. Go to https://render.com → sign in with GitHub
2. New → **Web Service** → connect your repo
3. Settings:
   - Name: `reposentinel-engine`
   - Root Directory: `ml-service`
   - Runtime: **Python 3**
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - Instance Type: **Free**
4. Deploy → wait for it to go live
5. Copy the URL: `https://reposentinel-engine.onrender.com`

---

## Step 4 — Render: Node API + Worker

1. New → **Web Service** → same repo
2. Settings:
   - Name: `reposentinel-api`
   - Root Directory: `node-service`
   - Runtime: **Node**
   - Build Command: `npm install`
   - Start Command: `node server.js`
   - Instance Type: **Free**
3. Environment Variables — add all of these:
   ```
   MONGO_URI        = mongodb+srv://reposentinel:<password>@...
   REDIS_HOST       = <upstash endpoint>
   REDIS_PORT       = <upstash port>
   REDIS_PASSWORD   = <upstash password>
   ML_SERVICE_URL   = https://reposentinel-engine.onrender.com
   PORT             = 4000
   ```
4. Deploy → wait for it to go live
5. Copy the URL: `https://reposentinel-api.onrender.com`

> Note: Render free tier uses ephemeral storage. The worker clones repos to /tmp which is fine — it cleans up after each scan. Do NOT store anything permanently to disk.

---

## Step 5 — Vercel: Frontend

1. Go to https://vercel.com → sign in with GitHub
2. New Project → import your repo
3. Configure:
   - Root Directory: `frontend`
   - Framework Preset: **Vite**
4. Environment Variables — add:
   ```
   VITE_API_URL = https://reposentinel-api.onrender.com/api
   ```
5. Deploy

Your live URL will be something like `https://reposentinel.vercel.app`

---

## Cold start warning

Render free tier spins down services after **15 minutes of inactivity**.
The first request after idle takes ~30 seconds to wake up.

For a resume demo, just open the Render dashboard and hit the health check
endpoint before showing it to someone:
- `https://reposentinel-api.onrender.com/health`
- `https://reposentinel-engine.onrender.com/health`

Both should return `{"ok":true}` — once they do, the app is warm.

---

## Environment variables summary

### Node API (Render)
```
MONGO_URI         mongodb+srv://...
REDIS_HOST        your-upstash-host.upstash.io
REDIS_PORT        6379
REDIS_PASSWORD    your-upstash-password
ML_SERVICE_URL    https://reposentinel-engine.onrender.com
PORT              4000
```

### Frontend (Vercel)
```
VITE_API_URL      https://reposentinel-api.onrender.com/api
```

### Python Engine (Render)
No environment variables needed.

---

## Local development (unchanged)

```bash
docker compose up --build
```
Frontend → http://localhost:5173
