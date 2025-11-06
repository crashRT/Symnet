run-%:
	@echo "run ${@:run-%=%}"
	@docker compose run --rm symnet sbt ${@:run-%=%}