#pragma once


#include <stdint.h>
#include <stdbool.h>

typedef struct bus_t bus_t;

bus_t *bus_init(void);
bool bus_valid_addr(bus_t *bus, uint64_t addr);
void* bus_proxy(bus_t *bus, uint64_t addr);
bool bus_read(bus_t *bus, uint64_t addr, uint64_t *data, uint8_t width, bool sign);
bool bus_write(bus_t *bus, uint64_t addr, uint64_t data, uint8_t width);
void bus_display(bus_t *bus);

void bus_increment(bus_t *bus, uint64_t inc);