.PHONY: up down build test seed reset clean logs

up:
	docker compose up --build

down:
	docker compose down

build:
	docker compose build

test:
	pytest -v

seed:
	python scripts/seed_users.py

reset:
	python scripts/reset_lab.py

clean:
	docker compose down -v

logs:
	docker compose logs -f
