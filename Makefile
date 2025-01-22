TEST_LOG_PARAMS=RUST_LOG_SPAN_EVENTS=new,close RUST_LOG=debug

POSTGRES_CRATES := ./src/e2e/app/postgres

KAMU_CONTAINER_RUNTIME_TYPE ?= podman

###############################################################################
# Lint
###############################################################################

.PHONY: lint
lint:
	cargo fmt --check
	cargo test -p kamu-repo-tools
	cargo deny check --hide-inclusion-graph
	cargo clippy --workspace --all-targets -- -D warnings


###############################################################################
# Lint (with fixes)
###############################################################################

.PHONY: lint-fix
lint-fix:
	cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged --broken-code
	cargo fmt --all



###############################################################################
# Sqlx Local Setup (create databases for local work)
###############################################################################

define Setup_EnvFile
echo "DATABASE_URL=$(1)://root:root@localhost:$(2)/kamu" > $(3)/.env;
echo "SQLX_OFFLINE=false" >> $(3)/.env;
endef

define Setup_EnvFile_Sqlite
echo "DATABASE_URL=sqlite://$(1)/kamu.sqlite.db" > $(2)/.env;
echo "SQLX_OFFLINE=false" >> $(2)/.env;
endef

.PHONY: sqlx-local-setup
sqlx-local-setup: sqlx-local-setup-postgres sqlx-local-setup-mariadb sqlx-local-setup-sqlite

.PHONY: sqlx-local-setup-postgres
sqlx-local-setup-postgres:
	$(KAMU_CONTAINER_RUNTIME_TYPE) pull postgres:latest
	$(KAMU_CONTAINER_RUNTIME_TYPE) stop kamu-postgres || true && $(KAMU_CONTAINER_RUNTIME_TYPE) rm kamu-postgres || true
	$(KAMU_CONTAINER_RUNTIME_TYPE) run --name kamu-postgres -p 5432:5432 -e POSTGRES_USER=root -e POSTGRES_PASSWORD=root -d postgres:latest
	$(foreach crate,$(POSTGRES_CRATES),$(call Setup_EnvFile,postgres,5432,$(crate)))
	sleep 3  # Letting the container to start
	until PGPASSWORD=root psql -h localhost -U root -p 5432 -d root -c '\q'; do sleep 3; done
	sqlx database create --database-url postgres://root:root@localhost:5432/kamu

.PHONY: sqlx-local-setup-sqlite
sqlx-local-setup-sqlite:
	sqlx database drop -y --database-url sqlite://kamu.sqlite.db
	sqlx database create --database-url sqlite://kamu.sqlite.db
	sqlx migrate run --source ./migrations/sqlite --database-url sqlite://kamu.sqlite.db
	$(foreach crate,$(SQLITE_CRATES),$(call Setup_EnvFile_Sqlite,$(shell pwd),$(crate)))

.PHONY: sqlx-local-clean-postgres
sqlx-local-clean-postgres:
	$(KAMU_CONTAINER_RUNTIME_TYPE) stop kamu-postgres || true && $(KAMU_CONTAINER_RUNTIME_TYPE) rm kamu-postgres || true
	$(foreach crate,$(POSTGRES_CRATES),rm $(crate)/.env -f ;)

.PHONY: sqlx-local-clean-sqlite
sqlx-local-clean-sqlite:
	sqlx database drop -y --database-url sqlite://kamu.sqlite.db
	$(foreach crate,$(SQLITE_CRATES),rm $(crate)/.env -f ;)


###############################################################################
# Test
###############################################################################

.PHONY: test
test:
	$(TEST_LOG_PARAMS) cargo nextest run

.PHONY: test-e2e
test-e2e:
	$(TEST_LOG_PARAMS) cargo nextest run -E 'test(::e2e::)'

.PHONY: test-no-oracle
test-no-oracle:
	$(TEST_LOG_PARAMS) cargo nextest run -E 'not test(::oracle::)'


###############################################################################
# Generated resources
###############################################################################

.PHONY: resources
resources:
	$(TEST_LOG_PARAMS) cargo nextest run -E 'test(::resourcegen::)'


###############################################################################
# Release
###############################################################################

.PHONY: release-patch
release-patch:
	cargo run -p kamu-repo-tools --bin release -- --patch

.PHONY: release-minor
release-minor:
	cargo run -p kamu-repo-tools --bin release -- --minor

.PHONY: release-major
release-major:
	cargo run -p kamu-repo-tools --bin release -- --major
