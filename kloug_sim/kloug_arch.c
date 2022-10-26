#include "kloug.h"
#include "kloug_arch.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

// device
typedef struct device_slave_t{
    void *device;
    char *name;
    uint64_t base_addr;
    uint64_t end_addr;
    bool (*write)(void *device, uint64_t addr, uint64_t data, uint8_t width);
    bool (*read)(void *device, uint64_t addr, uint64_t *data, uint8_t width);
    void* (*proxy)(void *device, uint64_t addr);
}device_slave_t;

struct bus_t{
    device_slave_t *device_slave_list;
    uint64_t nr_devices;
};

#include "device_ram.h"
#include "device_rom.h"
#include "bootrom.h"
#include "device_clint.h"


bus_t *bus_init(void){
    bus_t *bus = calloc(1, sizeof(bus_t));
    assert(bus);
    bus->nr_devices = 3;

    // Create device list
    bus->device_slave_list = calloc(bus->nr_devices, sizeof(device_slave_t));
    
    // RAM
    ram_t* ram = ram_init(PO_MEM_SIZE);
    bus->device_slave_list[0].device = ram;
    bus->device_slave_list[0].name = "ram";
    bus->device_slave_list[0].base_addr = PO_MEM_BASE;
    bus->device_slave_list[0].end_addr = PO_MEM_BASE + PO_MEM_SIZE;
    bus->device_slave_list[0].write = ram_write;
    bus->device_slave_list[0].read = ram_read;
    bus->device_slave_list[0].proxy = ram_proxy;

    // ROM
    rom_t* rom = rom_init(bootrom);
    bus->device_slave_list[1].device = rom;
    bus->device_slave_list[1].name = "bootrom";
    bus->device_slave_list[1].base_addr = BOOTROM_BASE;
    bus->device_slave_list[1].end_addr = BOOTROM_BASE + sizeof(bootrom);
    bus->device_slave_list[1].write = NULL;
    bus->device_slave_list[1].read = rom_read;
    bus->device_slave_list[1].proxy = rom_proxy;

    // CLINT
    bus->device_slave_list[2].device = clint_init(1, NULL /* TODO */);
    bus->device_slave_list[2].name = "clint (w/! int)";
    bus->device_slave_list[2].base_addr = CLINT_BASE;
    bus->device_slave_list[2].end_addr = CLINT_BASE + CLINT_SIZE;
    bus->device_slave_list[2].write = clint_store;
    bus->device_slave_list[2].read = clint_load;
    bus->device_slave_list[2].proxy = NULL;
    return bus;
}


struct device_slave_t* bus_get_device(bus_t *bus, uint64_t addr);

struct device_slave_t* bus_get_device(bus_t *bus, uint64_t addr){
    for(int i = 0; i < bus->nr_devices; i++){
        struct device_slave_t* device = &bus->device_slave_list[i];
        if(addr >= device->base_addr && addr < device->end_addr){
            return device;
        }
    }
    return NULL;
}

bool bus_valid_addr(bus_t *bus, uint64_t addr) {
    return bus_get_device(bus, addr) != NULL;
}

void* bus_proxy(bus_t *bus, uint64_t addr){
    struct device_slave_t* device = bus_get_device(bus, addr);
    if(!device){
        fprintf(stderr, "No device at @ %x\n", addr);
    }
    assert(device); // Device must exist !
    assert(device->proxy); // Device must proxy
    return device->proxy(device->device, addr - device->base_addr);
}

bool bus_read(bus_t *bus, uint64_t addr, uint64_t *data, uint8_t width, bool sign){
    struct device_slave_t* device = bus_get_device(bus, addr);
    if(!device){
        printf("NO DEVICEEEEEEEE @ %x\n\n", addr);
        return 0;
        
    }
    if(!device->read){
        printf("NO READDDDDDDDDDD\n\n");
        return 0;
    }
    addr -= device->base_addr;
    if(!device->read(device->device, addr, data, width)){
        printf("DEVICE <%s> FAILURE @ %x\n\n", device->name, addr);
        assert(0);
        return 0;
    }
    switch (width) {
        case 8: {
        } break;
        case 4: {
            if (sign && ((*data) & (1 << 31))) {
                *data |= 0xFFFFFFFF00000000;
            }
        } break;
        case 2: {
            if (sign && ((*data) & (1 << 15))) {
                *data |= 0xFFFFFFFFFFFF0000;
            }
        } break;
        case 1: {
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

bool bus_write(bus_t *bus, uint64_t addr, uint64_t data, uint8_t width){
    struct device_slave_t* device = bus_get_device(bus, addr);
    if(!device){
        return 0;
    } 
    if(!device->write){
        return 0;
    }
    addr -= device->base_addr;
    switch (width) {
    case 8:
        break;
    case 4:
        data &= 0xFFFFFFFF;
        break;
    case 2:
        data &= 0xFFFF;
        break;
    case 1:
        data &= 0xFF;
        break;
    default:
        assert(!"Invalid");
        break;
    }
    if(!device->write(device->device, addr, data, width)){
        printf("DEVICE <%s> FAILURE W @=%x D=%x\n", device->name, addr, data);
        assert(0);
    }
    return 1;
}

void bus_display(bus_t *bus){
    for(int i = 0; i < bus->nr_devices; i++){
        struct device_slave_t* device = &bus->device_slave_list[i];
        printf("device <%16s> [%x %x]\n", device->name, device->base_addr, device->end_addr);
    }
}

void bus_increment(bus_t *bus, uint64_t inc){
    clint_increment(bus->device_slave_list[2].device, inc);
}
