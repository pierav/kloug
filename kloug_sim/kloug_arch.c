#include "kloug.h"
#include "kloug_arch.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

// Main memory

static uint8_t po_mem[PO_MEM_SIZE];

bool mem_write8(uint64_t addr, uint8_t data) {
    po_mem[addr] = data;
    return true;
}

bool mem_read8(uint64_t addr, uint8_t *data) {
    *data = po_mem[addr];
    return true;
}

bool mem_write16(uint64_t addr, uint16_t data) {
    if ((addr & 0b1) == 0) {
        ((uint16_t *)po_mem)[(addr) >> 1] = data;
        return true;
    }
    return false;
}

bool mem_read16(uint64_t addr, uint16_t *data) {
    if ((addr & 0b1) == 0) {
        *data = ((uint16_t *)po_mem)[(addr) >> 1];
        return true;
    }
    return false;
}

bool mem_write32(uint64_t addr, uint32_t data) {
    if ((addr & 0b11) == 0) {
        ((uint32_t *)po_mem)[(addr) >> 2] = data;
        return true;
    }
    return false;
}

bool mem_read32(uint64_t addr, uint32_t *data) {
    if ((addr & 0b11) == 0) {
        *data = ((uint32_t *)po_mem)[(addr) >> 2];
        return true;
    }
    return false;
}

bool mem_write64(uint64_t addr, uint64_t data) {
    if ((addr & 0b111) == 0) {
        ((uint64_t *)po_mem)[(addr) >> 3] = data;
        return true;
    }
    return false;
}

bool mem_read64(uint64_t addr, uint64_t *data) {
    if ((addr & 0b111) == 0) {
        *data = ((uint64_t *)po_mem)[(addr) >> 3];
        return true;
    }
    return false;
}

void *mem_proxy(uint64_t addr) {
    return po_mem + addr;
}


// device
struct device_slave_t{
    char *name;
    uint64_t base_addr;
    uint64_t end_addr;
    bool (*write64)(uint64_t addr, uint64_t data);
    bool (*write32)(uint64_t addr, uint32_t data);
    bool (*write16)(uint64_t addr, uint16_t data);
    bool (*write8)(uint64_t addr, uint8_t data);
    bool (*read64)(uint64_t addr, uint64_t *data);
    bool (*read32)(uint64_t addr, uint32_t *data);
    bool (*read16)(uint64_t addr, uint16_t *data);
    bool (*read8)(uint64_t addr, uint8_t *data);
    void* (*proxy)(uint64_t addr);
};


#define NR_DEVICES 1
static struct device_slave_t device_slave_list[NR_DEVICES]={
    {
        .name="ram",
        .base_addr=PO_MEM_BASE,
        .end_addr=PO_MEM_BASE + PO_MEM_SIZE,
        .write64=mem_write64,
        .write32=mem_write32,
        .write16=mem_write16,
        .write8=mem_write8,
        .read64=mem_read64,
        .read32=mem_read32,
        .read16=mem_read16,
        .read8=mem_read8,
        .proxy=mem_proxy
    }
};

struct device_slave_t* bus_get_device(uint64_t addr);

struct device_slave_t* bus_get_device(uint64_t addr){
    for(int i = 0; i < NR_DEVICES; i++){
        struct device_slave_t* device = &device_slave_list[i];
        // printf("device <%s> [%x %x]\n", device->name, device->base_addr, device->end_addr);
        if(addr >= device->base_addr && addr < device->end_addr){
            return device;
        }
    }
    return NULL;
}

bool bus_valid_addr(uint64_t addr) {
    return bus_get_device(addr) != NULL;
}

void* bus_proxy(uint64_t addr){
    struct device_slave_t* device = bus_get_device(addr);
    assert(device); // Device must exist !
    return device->proxy(addr - device->base_addr);
}
bool bus_read(uint64_t addr, uint64_t *data, uint8_t width, bool sign){
    struct device_slave_t* device = bus_get_device(addr);
    if(!device){
        return 0;
    }
    addr -= device->base_addr;
    switch (width) {
        case 8: {
            device->read64(addr, data);
        } break;
        case 4: {
            uint32_t dw = 0;
            device->read32(addr, &dw);
            *data = dw;
            if (sign && ((*data) & (1 << 31))) {
                *data |= 0xFFFFFFFF00000000;
            }
        } break;
        case 2: {
            uint16_t dh = 0;
            device->read16(addr, &dh);
            *data |= dh;
            if (sign && ((*data) & (1 << 15))) {
                *data |= 0xFFFFFFFFFFFF0000;
            }
        } break;
        case 1: {
            uint8_t db = 0;
            device->read8(addr, &db);
            *data |= ((uint32_t)db << 0);
            if (sign && ((*data) & (1 << 7))) {
                *data |= 0xFFFFFFFFFFFFFF00;
            }
        } break;
        default: {
            assert(!"Invalid");
        } break;
    }
    return 1;
}

bool bus_write(uint64_t addr, uint64_t data, uint8_t width){
    struct device_slave_t* device = bus_get_device(addr);
    if(!device){
        return 0;
    }    
    addr -= device->base_addr;
    switch (width) {
    case 8:
        device->write64(addr, data);
        break;
    case 4:
        device->write32(addr, data & 0xFFFFFFFF);
        break;
    case 2:
        device->write16(addr, data & 0xFFFF);
        break;
    case 1:
        device->write8(addr + 0, data & 0xFF);
        break;
    default:
        assert(!"Invalid");
        break;
    }
    return 1;
}


