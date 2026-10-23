# API Security Framework
## Automated OWASP ZAP and Postman Checks for BOLA

This educational project template demonstrates a safe workflow for testing API authorization, particularly Broken Object Level Authorization (BOLA), using an authorized staging API, dedicated test identities, and synthetic records.

### Included files

- `api_security_framework.py` — Python test-plan runner for non-destructive GET/HEAD authorization checks.
- `test_plan.example.json` — example JSON plan; replace placeholder paths and object IDs.
- `requirements.pdf` — hardware, software, and validation requirements.
- `project_report.pdf` — project report with the supplied Sandip University logo.
- `sandip_university_logo.png` — logo asset.

### Safety and scope

Run only against APIs you own or have written permission to test. Use a staging environment, synthetic objects, and dedicated test accounts. The included Python tool does not discover endpoints, mutate data, create accounts, or run destructive requests. It reports a potential BOLA review signal when both configured identities receive a successful response; this is not proof of a vulnerability. Shared or public objects may be legitimately accessible.

### Requirements

- Python 3.10 or newer
- No third-party Python packages required for the Python script
- Authorized API test/staging endpoint
- Two dedicated test identities with separate bearer tokens
- Optional: OWASP ZAP and Postman for complementary manual/automated test workflows

### Configure test tokens

Set environment variables rather than hardcoding tokens.

**Windows PowerShell**
```powershell
$env:API_TEST_TOKEN_A = "your-test-token-for-user-a"
$env:API_TEST_TOKEN_B = "your-test-token-for-user-b"
```

**macOS/Linux**
```bash
export API_TEST_TOKEN_A='your-test-token-for-user-a'
export API_TEST_TOKEN_B='your-test-token-for-user-b'
```

Never commit real tokens, cookies, API keys, or production credentials to GitHub.

### Configure the test plan

Edit `test_plan.example.json`. Use a relative path to an object owned by `user_a`. Keep paths relative to `--base-url`; the script rejects absolute URLs in the test plan to reduce the risk of sending credentials to an unintended host.

### Run

```bash
python api_security_framework.py --base-url https://staging-api.example.test --plan test_plan.example.json --output api_security_report.json
```

The report contains status codes and SHA-256 fingerprints of response bodies, but not the response bodies themselves. Review results manually against the API's intended authorization model.

### Suggested OWASP ZAP and Postman workflow

1. Define the permitted API scope and obtain written authorization.
2. Import the staging API definition into Postman or OWASP ZAP.
3. Configure separate test identities and environment variables; do not store secrets in shared collections.
4. Create positive tests (owner can read their object) and negative tests (another user should not read that object).
5. Run the included Python test-plan runner for the configured GET/HEAD cases.
6. Compare results with ZAP/Postman test results and server-side authorization logs.
7. Document verified findings and retest after fixes.

### Limitations

- This is a minimal template, not a complete API security scanner.
- It supports GET and HEAD only and does not enumerate endpoints.
- A 2xx response does not prove data exposure or BOLA; authorization semantics and response content must be verified safely.
- OWASP ZAP and Postman are optional external tools and are not installed or invoked automatically by this script.

### License

Educational project template. Add an appropriate license before redistribution.
