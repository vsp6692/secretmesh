SHELL := /bin/bash
COMPOSE := docker compose -f deployments/docker/compose.yaml
GOLANGCI_LINT_VERSION := v2.15.0
GOVULNCHECK_VERSION := v1.9.0
GITLEAKS_VERSION := v8.30.1

-include .env
export

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show targets
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.env:
	cp .env.example .env

## ---- Development ----

.PHONY: dev
dev: .env deps-up migrate ## Start dependencies, migrate, run API and web
	@$(MAKE) -j2 api web

.PHONY: deps-up
deps-up: ## Start Postgres, Keycloak, the AWS emulator and the mail catcher
	$(COMPOSE) up -d --wait postgres
	$(COMPOSE) up -d keycloak moto mailpit

.PHONY: deps-down
deps-down: ## Stop dependencies (keeps data)
	$(COMPOSE) down

.PHONY: deps-reset
deps-reset: ## Stop dependencies and delete their data
	$(COMPOSE) down -v

.PHONY: migrate
migrate: .env ## Apply database migrations
	go run ./apps/api migrate

.PHONY: api
api: ## Run the API
	go run ./apps/api serve

.PHONY: web
web: apps/web/node_modules ## Run the web app
	cd apps/web && npm run dev

apps/web/node_modules: apps/web/package-lock.json
	cd apps/web && npm ci
	@touch $@

## ---- Build & test ----

.PHONY: generate
generate: ## Regenerate code from the OpenAPI contract
	go generate ./...

.PHONY: build
build: ## Build API binary and web app
	CGO_ENABLED=0 go build -trimpath -o bin/secretmesh-api ./apps/api
	cd apps/web && npm run build

.PHONY: test
test: ## Unit tests (integration tests skip without a database or AWS emulator)
	SECRETMESH_TEST_DATABASE_URL= SECRETMESH_TEST_AWS_ENDPOINT= go test -race ./...

TEST_COMPOSE := docker compose -f deployments/docker/compose.test.yaml
# Minimum total statement coverage; keep in sync with COVER_MIN in .github/workflows/ci.yml.
COVER_MIN := 74
TEST_DB := postgres://postgres:postgres@localhost:5439/postgres?sslmode=disable

.PHONY: test-stack-up
test-stack-up: ## Start the throwaway test stack (Postgres, LocalStack, Moto)
	$(TEST_COMPOSE) up -d --wait

.PHONY: test-stack-down
test-stack-down: ## Remove the test stack
	$(TEST_COMPOSE) down -v

.PHONY: test-localstack
test-localstack: ## Full suite on LocalStack (run test-stack-up first); no skips allowed
	SECRETMESH_TEST_DATABASE_URL='$(TEST_DB)' SECRETMESH_TEST_AWS_ENDPOINT=http://127.0.0.1:4566 COVER_MIN=$(COVER_MIN) scripts/go-test-strict.sh

.PHONY: test-moto
test-moto: ## Full suite on Moto (run test-stack-up first); no skips allowed
	SECRETMESH_TEST_DATABASE_URL='$(TEST_DB)' SECRETMESH_TEST_AWS_ENDPOINT=http://127.0.0.1:5051 COVER_MIN=$(COVER_MIN) scripts/go-test-strict.sh

.PHONY: test-integration
test-integration: test-stack-up ## Full suite on LocalStack and Moto, starting the test stack
	@echo "== LocalStack" && $(MAKE) --no-print-directory test-localstack
	@echo "== Moto" && $(MAKE) --no-print-directory test-moto

.PHONY: hooks
hooks: ## Install the git hooks (pre-commit, commit-msg, pre-push)
	git config core.hooksPath .githooks
	@echo "Hooks installed. pre-commit checks every commit; pre-push runs the integration suite."

.PHONY: verify
verify: lint security legal-check license-check license-verify test-integration ## Everything CI checks, locally
	cd apps/web && npm run build

.PHONY: lint
lint: ## Go and web linters
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run
	cd apps/web && npm run lint && npm run typecheck

.PHONY: license-check license-report license-verify license-headers license-texts sbom legal-check
license-check: ## Dependency licences follow docs/legal/license-policy.json
	go run ./scripts/licenses check

license-report: ## Regenerate the dependency tables in docs/legal/THIRD_PARTY_LICENSES.md
	go run ./scripts/licenses update

license-verify: ## Fail if THIRD_PARTY_LICENSES.md is out of date
	go run ./scripts/licenses verify

license-headers: ## Add or update the SPDX licence header in source files
	go run ./scripts/licenses headers-apply

license-texts: ## Collect dependency licence texts into build/licenses (what images ship under /licenses)
	scripts/license-texts.sh

sbom: ## CycloneDX SBOMs for the API and the web console in build/sbom
	scripts/sbom.sh

legal-check: ## Licensing documents complete and consistent; every source file has its header
	scripts/check-legal-files.sh
	go run ./scripts/licenses headers-check

.PHONY: security
security: ## Secret scan and Go vulnerability check
	go run github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION) dir . --no-banner --redact --config .gitleaks.toml
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

.PHONY: docker-build
docker-build: ## Build container images
	docker build -f deployments/docker/api.Dockerfile -t secretmesh/api:dev .
	docker build -f deployments/docker/web.Dockerfile -t secretmesh/web:dev .
