
# generate setup
# riscof setup --dutname=spike

all: run

validate:
	riscof --verbose info validateyaml --config=config.ini

# Cloning the Architectural Tests
arch_test_clone:
	riscof --verbose info arch-test --clone

testlists_gen:
	riscof testlist --config=config.ini --suite=riscv-arch-test/riscv-test-suite/ --env=riscv-arch-test/riscv-test-suite/env

run: kloug_fesvr
	riscof --verbose debug run --no-browser --config=config.ini --suite=riscv-arch-test/riscv-test-suite/ --env=riscv-arch-test/riscv-test-suite/env

kloug_fesvr:
	make -C $(PROJECT_DIR)/kloug_fesvr

.phony: validate arch_test_clone testlists_gen run