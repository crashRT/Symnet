.PHONY: help up down build run shell logs clean

up:
	@echo "Starting Symnet container..."
	@docker compose up -d

down:
	@echo "Stopping Symnet container..."
	@docker compose down

build:
	@echo "Building Symnet container..."
	docker build -t johscheuer/symnet .

sh:
	@echo "Opening shell in Symnet container..."
	@docker exec -it symnet /bin/bash

sample:
	@echo "Running sample code in Symnet container..."
	@docker exec symnet sbt sample