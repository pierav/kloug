#pragma once
#include <stdlib.h>
#include <string.h>

uint8_t log2mask[]={
    [1] = 0b0,
    [2] = 0b1,
    [4] = 0b11,
    [8] = 0b111,
};

typedef struct ram_t{
    uint8_t *data;
    uint64_t attributes;
}ram_t;


// void *args, void* (*callback)(void *args)

ram_t *ram_init(uint64_t ram_size){
    ram_t *ram = calloc(1, sizeof(ram_t));
    assert(ram);
    ram->data = calloc(1, ram_size);
    assert(ram->data);
    ram->attributes = 0xABCDEF; // Placeholdder
    return ram;
}

bool ram_read(void *device, uint64_t addr, uint64_t *data, uint8_t width){
    ram_t *ram = device;
    // Check addr alignement
    if(addr & log2mask[width] != 0)
        return false;
    memcpy(data, ram->data + addr, width);
    return true;
}

bool ram_write(void *device, uint64_t addr, uint64_t data, uint8_t width){
    ram_t *ram = device;
    // Check addr alignement
    if(addr & log2mask[width] != 0)
        return false;
    memcpy(ram->data + addr, &data, width);
    return true;
}

void *ram_proxy(void *device, uint64_t addr) {
    ram_t *ram = device;
    return ram->data + addr;
}

