# ScamShield

ScamShield is a cybersecurity-awareness web app that helps users review suspicious messages and URLs and learn safer online habits. Its detection engine uses deterministic JavaScript rules; general cybersecurity chat is handled by NVIDIA NIM.

## Architecture

- **Frontend:** static HTML, CSS and JavaScript in `public/`, hosted on Render.
- **Backend:** Vercel serverless functions under `api/`.
- **Detection:** deterministic message and URL heuristics under `lib/`; submitted URLs are inspected structurally, not opened by the rules engine.
- **AI chat:** NVIDIA NIM, using `openai/gpt-oss-20b` by default.

## API endpoints

- `POST /api/analyse` — message/URL screening. Accepts `{ "type": "message" | "url", "text": "..." }` (the canonical engine field `content` is also supported).
- `POST /api/chat` — general cybersecurity Q&A. Accepts `{ "message": "..." }` and returns an `answer`/`reply`.
- `GET /api/health` — backend availability and AI-provider configuration status.

## Configuration

Configure these variables in **Vercel** (backend), not in the frontend:

- `NVIDIA_API_KEY` — required for NVIDIA NIM chat.
- `NVIDIA_MODEL` — optional; defaults to `openai/gpt-oss-20b`.
- `FRONTEND_ORIGIN` — the exact deployed Render origin, such as `https://your-site.onrender.com`. For multiple allowed origins, separate them with commas.

The Render frontend uses `public/config.js` to find the backend. Before deploying, set `window.SCAMSHIELD_API_BASE_URL` to your actual Vercel deployment origin, such as `https://your-project.vercel.app`, without a trailing slash. The URL is public configuration, not a secret. Never place `NVIDIA_API_KEY` or other credentials in frontend files.

## Important limitations

ScamShield is an awareness aid, not a certified security scanner. Heuristic risk scores are not probabilities and a low-risk result does not prove that a message or URL is safe. The frontend's recent-check history is stored in the user's browser; text sent for chat is processed by the configured backend/provider.
