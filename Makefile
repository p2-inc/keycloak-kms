.PHONY: dev start stop restart logs clean package test verify format

# Build the jar and start Keycloak + LocalStack in the foreground.
dev: package
	docker compose up --force-recreate

# The same, detached.
start: package
	docker compose up --force-recreate -d
	@echo ""
	@echo "  Admin console : http://localhost:8080/admin   (admin / admin)"
	@echo "  LocalStack    : http://localhost:4566"
	@echo ""
	@echo "  Realm 'dev' has stock keys, with private material in the database. Migrate it:"
	@echo "    ./docker/migrate-dev.sh"
	@echo ""
	@echo "  Run 'make logs' to follow Keycloak."

stop:
	docker compose down

restart: stop dev

logs:
	docker compose logs -f keycloak

# Stop, drop volumes, and clean the build.
clean:
	docker compose down -v
	mvn clean

# Build the extension jar. Tests are skipped; `make verify` runs them.
package:
	mvn package -DskipTests

# Unit tests only. Fast, no Docker.
test:
	mvn test

# Everything, including the LocalStack and Keycloak integration suites. Needs Docker.
verify:
	mvn verify

format:
	mvn com.spotify.fmt:fmt-maven-plugin:format
