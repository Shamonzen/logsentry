.PHONY: lab attack down logs

lab:
	docker compose up -d --build

attack:
	docker compose run --rm attacker run_all.sh

down:
	docker compose down

logs:
	docker compose logs -f logsentry-tail
