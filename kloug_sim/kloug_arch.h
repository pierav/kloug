#pragma once

#include <stdint.h>
#include <stdbool.h>

bool bus_write(uint64_t addr, uint64_t data, uint8_t width);
bool bus_read(uint64_t addr, uint64_t *data, uint8_t width, bool sign);
bool bus_valid_addr(uint64_t addr);
void* bus_proxy(uint64_t addr);
void bus_display(void);