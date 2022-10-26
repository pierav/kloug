#pragma once
#include <stdlib.h>
#include <string.h>

typedef struct rom_t{
    uint8_t *data;
    uint64_t attributes;
}rom_t;


rom_t *rom_init(uint8_t *data){
    rom_t *rom = calloc(1, sizeof(rom_t));
    assert(rom);
    rom->data =data;
    rom->attributes = 0xABCDEF; // Placeholdder
    return rom;
}

bool rom_read(void *device, uint64_t addr, uint64_t *data, uint8_t width){
    rom_t *rom = device;
    // Check addr alignement
    if(addr & log2mask[width] != 0)
        return false;
    memcpy(data, rom->data + addr, width);
    return true;
}

void *rom_proxy(void *device, uint64_t addr) {
    rom_t *rom = device;
    return rom->data + addr;
}

