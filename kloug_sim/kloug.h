#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

// TLB
#define MMU_TLB_ENTRIES 64

// IO
#define PO_MEM_SIZE     (1024 * 1024 * 64)
#define PO_MEM_BASE     0x80000000
#define BOOTROM_BASE    0x1000
#define CLINT_BASE 0x02000000
#define CLINT_SIZE 0x000c0000

// CPU Frequencies
#define CPU_HZ 1000000000 // 1GHz CPU
#define INSNS_PER_RTC_TICK 100 // 10 MHz clock for 1 BIPS core
//#define CLINT_REAL_TIME 1
#define FREQ_HZ (CPU_HZ / INSNS_PER_RTC_TICK)

// api
int kloug_init(void *args);
void  kloug_reset(void);
void  kloug_step(void);
void *kloug_mem_proxy(uint64_t addr);
uint64_t *kloug_access_mip(void);
