#include "encoding.h"
#include <stdint.h>


char DISPLAY_MPRIV[] = {'U', 'S', 'X', 'M'};


const char* DISPLAY_MCAUSE[] = {
    [0]="MISALIGNED_FETCH",
    [1]="FAULT_FETCH",
    [2]="ILLEGAL_INSTRUCTION",
    [3]="BREAKPOINT",
    [4]="MISALIGNED_LOAD",
    [5]="FAULT_LOAD",
    [6]="MISALIGNED_STORE",
    [7]="FAULT_STORE",
    [8]="ECALL_U",
    [9]="ECALL_S",
    [11]="ECALL_M",
    [12]="PAGE_FAULT_INST",
    [13]="PAGE_FAULT_LOAD",
    [15]="PAGE_FAULT_STORE"
};

char* display_csr(uint64_t csr){
    switch (csr){
        #define DECLARE_CSR(name, num) case num: return #name;
        #include "encoding.h"
        #undef DECLARE_CSR
        default:
            return "Invalid CSR";
    }
}