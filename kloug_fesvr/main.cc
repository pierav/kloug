#include "intf.h"
#include <fesvr/context.h>
#include <fesvr/htif.h>
#include <iostream>

#define SIM_XLEN       64
#define SIM_ENDIANESS  memif_endianness_little
#define SIM_INTERLEAVE (1024 * 16)

// Reference instanciation of htif
// https://github.com/riscv-software-src/riscv-isa-sim/blob/master/disasm/disasm.cc

void sim_thread_main(void *arg);

// this class encapsulates the processors and memory in a RISC-V machine.
class sim_t : public htif_t {
  public:
    sim_t(int argc, char **argv) : htif_t(argc, argv) {
        printf("Init sim_t...\n");
        htif_t::set_expected_xlen(SIM_XLEN);
    }
    ~sim_t(){};
    int run() {
        // host = context_t::current();
        // target.init(sim_thread_main, this);
        host = context_t::current();
        target.init(sim_thread_main, this);
        return htif_t::run();
    }

    void main() {
        while (!done()) {
            for (size_t i = 0; i < SIM_INTERLEAVE; i++) {
                step();
            }
            host->switch_to();
        }
    }

  private:
    context_t          target;
    context_t         *host;
    void               reset() { intf_proc_reset(); }
    void               idle() { target.switch_to(); }
    void               step();
    void               read_chunk(addr_t taddr, size_t len, void *dst);
    void               write_chunk(addr_t taddr, size_t len, const void *src);
    size_t             chunk_align() { return 8; };
    size_t             chunk_max_size() { return 8; }
    memif_endianness_t get_target_endianness() const { return SIM_ENDIANESS; }
};

void sim_thread_main(void *arg) { ((sim_t *)arg)->main(); }

void sim_t::step(void) { intf_proc_step(); }

void sim_t::read_chunk(addr_t taddr, size_t len, void *dst) {
    assert(len == 8);
    void *data = intf_proc_mem_proxy(taddr);
    memcpy(dst, data, len);
    // printf("read_chunk @ = %x D = %x\n", taddr, *(uint64_t*)dst);
}

void sim_t::write_chunk(addr_t taddr, size_t len, const void *src) {
    assert(len == 8);
    void *data = intf_proc_mem_proxy(taddr);
    memcpy(data, src, len);
    // printf("write chunck @ = %x D = %x\n", taddr, *(uint64_t*)src);
}

int main(int argc, char **argv) {
    sim_t sim = sim_t(argc, argv);
    sim.run();
}