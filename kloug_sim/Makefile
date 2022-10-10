EXEC = build/kloug_sim
LIB = build/libkloug.a

all: $(EXEC) $(LIB)

build/%.o: %.c
	@mkdir -p $(@D)
	gcc -I. -c $< -o $@ 

$(LIB): build/kloug.o
	rm -rf $@
	ar -cvq $@ $^

$(EXEC): build/kloug.o build/main.o
	gcc $^ -o $@

run: $(EXEC)
	cd build && ./kloug_sim $(PROJECT_DIR)/tmp/riscv-tests/build/isa/rv64ui-p-sub

clean:
	rm -r build