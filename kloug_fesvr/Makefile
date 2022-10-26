CPPFLAGS = $(shell pkg-config riscv-fesvr --libs --cflags)
EXEC = build/kloug_fesvr

all: $(EXEC)

$(EXEC): main.cc $(PROJECT_DIR)/kloug_sim/build/libkloug.a
	mkdir -p $(@D)
	g++ $^ -I$(PROJECT_DIR)/kloug_sim $(CPPFLAGS) -o $(EXEC)

$(PROJECT_DIR)/kloug_sim/build/libkloug.a: force
	make -C $(PROJECT_DIR)/kloug_sim

clean:
	rm -rf build
force:
	@: