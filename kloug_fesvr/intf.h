#pragma once


extern "C" {
#include "kloug.h"
}

void intf_proc_reset(void) { kloug_reset(); }
void  intf_proc_step(void) { kloug_step(); }
void *intf_proc_mem_proxy(uint32_t addr) { return kloug_mem_proxy(addr); }