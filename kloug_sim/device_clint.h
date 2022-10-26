#pragma once
#include <stdint.h>

typedef char processor_t;

void *clint_init(uint64_t nr_procs, processor_t** procs);
bool clint_load(void *device, uint64_t addr, uint64_t *data, uint8_t width);
bool clint_store(void *device, uint64_t addr, uint64_t data, uint8_t width);
void clint_increment(void *device, uint64_t inc);