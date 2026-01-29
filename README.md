### uv setup
- `uv init # create in repo`
- `uv sync # create venv`

### get running
- `colima start`
- `docker-compose up -d`

## debugging

- `docker-compose logs --tail=100 2>&1`
- `docker-compose logs -f ollama-pull`

### test APIs
check health:

`curl -s http://localhost:8000/health | python3 -m json.tool`

analyze email:
```
curl -s -X POST http://localhost:8000/api/v1/analyze \
     -H "Content-Type: application/json" \
     -d '{
       "from": "security@paypa1-verify.xyz",
       "to": ["victim@company.com"],
       "subject": "URGENT: Your account has been suspended - Verify immediately",
       "body": "Dear Valued Customer,\n\nWe have detected unusual activity on your PayPal account. Your account has been temporarily suspended.\n\nTo restore access to your
   account, please verify your identity immediately by clicking the link below:\n\nhttp://192.168.1.100/paypal/verify?user=victim@company.com\n\nIf you do not verify within 24
   hours, your account will be permanently closed.\n\nPayPal Security Team",
       "headers": {
         "Authentication-Results": "spf=fail; dkim=fail",
         "Reply-To": "scammer@gmail.com"
       },
       "attachments": []
     }' | python3 -m json.tool
```