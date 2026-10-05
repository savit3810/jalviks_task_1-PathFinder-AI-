.PHONY: up down build logs test scan-sast scan-sca certs secrets

up: certs secrets
	docker-compose up -d

build: certs secrets
	docker-compose build

down:
	docker-compose down

logs:
	docker-compose logs -f

certs:
	bash scripts/gen-certs.sh

secrets:
	bash scripts/gen-secrets.sh

test:
	pytest tests/security/

scan-sast:
	# Run semgrep locally if installed
	semgrep scan --config=p/owasp-top-ten --config=p/python --config=p/typescript --config=p/react --config=p/jwt --config=p/secrets

scan-sca:
	pip-audit -r api/requirements.txt --desc on
	npm audit --audit-level=high
