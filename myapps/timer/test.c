#include <stdint.h>
#include "util.h"

void debug_printf(const char* str, ...);


volatile uint64_t * mtime = (volatile uint64_t *)(0x02000000 + 0xbff8);
volatile uint64_t * mtimecmp = (volatile uint64_t *)(0x02000000 + 0x4000);

#define  mtime_INTERRUPT_PERIOD  1200000   

void interruptHandler() __attribute__ ((interrupt));
void interruptHandler() {
    *mtimecmp = *mtime + mtime_INTERRUPT_PERIOD;
    printf("MINT\n");
}

void printf_status(uint64_t mstatus, uint64_t mie, uint64_t mip, uint64_t mcause) {
    asm volatile ("csrr %[reg], mie" : [reg] "=r" (mie));
    asm volatile ("csrr %[reg], mip" : [reg] "=r" (mip));
    asm volatile ("csrr %[reg], mstatus" : [reg] "=r" (mstatus));
    asm volatile ("csrr %[reg], mcause" : [reg] "=r" (mcause));
    printf("mie=%x, mip=%x, mstatus=%x, mcause=%x\r\n", mie, mip, mstatus, mcause);
}

int main() {

    uint64_t mstatus, mie, mip, mcause, mtvec;
    printf_status(mstatus, mie, mip, mcause);
    
    // basic (non vectored) interrupt handler (to force non vectored,
    // set 0 to lower two bits of mtvec, so force 4 byte aligned on linker script
    // for interrupt handler)
    asm volatile ("csrw mtvec, %[reg]" : : [reg] "r" ((uint64_t) interruptHandler));
    asm volatile ("csrr %[reg], mtvec" : [reg] "=r" (mtvec));
    printf("mtvec=%x\r\n", mtvec);
    // return 0;
    // machine interrupt enable
    asm volatile ("csrw mie, %[reg]" : : [reg] "r" ((uint32_t) 0x80));
    asm volatile ("csrsi mstatus, 8");

    printf("OK\n\n");
    // configure interrupt period
    *mtimecmp = *mtime + mtime_INTERRUPT_PERIOD;
    // sleep
    while (1){
        asm volatile ("wfi");
    }  
    
    return 0;
}