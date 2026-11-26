# CYBERSHIELD

CYBERSHIELD checks a message or URL text for potential scam indicators using
the Gemini API. It does not open or verify websites or senders, and its score
is not a calibrated probability.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:GEMINI_API_KEY = "your-gemini-api-key"
python cybershield_server.py
```

Open `http://127.0.0.1:8000`.

## Deploy to Vercel

Import this repository in Vercel and set the project root to the repository
root. Add `GEMINI_API_KEY` under **Project Settings → Environment Variables**.
`GEMINI_MODEL` is optional and defaults to `gemini-2.5-flash`. Redeploy after
adding or changing environment variables.

Keep API keys in environment variables; never commit them to this repository.
