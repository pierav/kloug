EXEC = build/kloug_sim
LIB = build/libkloug.a

SRC = $(wildcard *.c)
OBJ = $(patsubst %.c, build/%.o, $(SRC))

all: $(EXEC) $(LIB)

build/%.o: %.c
	@mkdir -p $(@D)
	gcc -I. -c $< -o $@ 

$(LIB): $(OBJ)
	rm -rf $@
	ar -cvr $@ $^

$(EXEC): $(OBJ)
	gcc $^ -o $@

BENCH = $(PROJECT_DIR)/tmp/riscv-tests/build/isa/rv64ui-p-sub
# BENCH = $(PROJECT_DIR)/apps/dhrystone.rv64im-htif

run: $(EXEC)
	cd build && ./kloug_sim $(BENCH)

clean:
	rm -r build