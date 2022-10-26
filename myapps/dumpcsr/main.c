#include "encoding.h"
#include "util.h"


uint64_t trap_taken;

uintptr_t handle_trap(uintptr_t cause, uintptr_t epc, uintptr_t regs[32])
{
  //printf("trap cause=%x epc=%x\n", cause, epc);
  trap_taken = 1;
  return epc + 4;
  //tohost_exit(1337);
}

char* display(uint64_t csr){
    switch (csr){
        #define DECLARE_CSR(name, num) case num: return #name;
        #include "encoding.h"
        #undef DECLARE_CSR
        default:
            return 0;
    }
}

#define STR(x) #x

#define DECLARE_CSR(csr, num) \
     do{ \
        trap_taken = 0; \
        unsigned long __tmp = 0; \
        asm volatile ("csrr %0, " STR(num) : "=r"(__tmp)); \
        asm volatile ("nop"); \
        char *s = trap_taken ? "[UNIMPLEMENTED]" : ""; \
        printf("%20s (0x%03x): 0x%016x %s\n", #csr, num, __tmp, s); \
    } while(0);

int main(void){
    printf("Hello World!\n");
    #include "encoding.h"
}