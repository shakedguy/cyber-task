# Cyber Task

### For running the code:

1. Run the server
```bash
  cd server && uvicorn src.main:app --port 8000
```

2. Run the reverse proxy
```bash
  cd reverse-proxy && uvicorn src.main:app --port 9000
```

3. Run the client
```bash
  cd client && uv run attack.py --type <attac_type> --url <url> --rate <rate>
```