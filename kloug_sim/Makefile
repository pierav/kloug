EXEC = build/kloug_sim
LIB = build/libkloug.a

SRC = $(wildcard *.c)
OBJ = $(patsubst %.c, build/%.o, $(SRC))

CFLAGS = -MMD -MP -O2

all: $(EXEC) $(LIB)

build/kloug_arch.o: kloug_arch.c $(PROJECT_DIR)/kloug_bootrom/gen/c/bootrom.h
	@mkdir -p $(@D)
	gcc $(CFLAGS) -I. -I$(PROJECT_DIR)/kloug_bootrom/gen/c -c $< -o $@ 

$(PROJECT_DIR)/kloug_bootrom/gen/c/bootrom.h: force
	@make -C $(PROJECT_DIR)/kloug_bootrom

build/%.o: %.c
	@mkdir -p $(@D)
	gcc $(CFLAGS) -I. -c $< -o $@ 

$(LIB): $(OBJ)
	rm -rf $@
	ar -cvr $@ $^

$(EXEC): $(OBJ)
	gcc $(CFLAGS) $^ -o $@

BENCH = $(PROJECT_DIR)/tmp/riscv-tests/build/isa/rv64ui-p-sub
# BENCH = $(PROJECT_DIR)/apps/dhrystone.rv64im-htif

run: $(EXEC)
	cd build && ./kloug_sim $(BENCH)

clean:
	rm -rf build

force:
	@: