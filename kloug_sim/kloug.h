#pragma once

#include <stdint.h>

#define MMU_TLB_ENTRIES 64
#define PO_MEM_SIZE     (1024 * 1024 * 64)
#define PO_MEM_BASE     0x80000000

#define BOOTROM_BASE 0x10000

void  kloug_reset(void);
void  kloug_step(void);
void *kloug_mem_proxy(uint64_t addr);