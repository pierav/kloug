#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "kloug.h"
#include "isa.h"
#include "device_clint.h"


typedef uint64_t mtime_t;
typedef uint64_t mtimecmp_t;
typedef uint32_t msip_t;

typedef struct clint_t{  
  mtime_t mtime;
  mtimecmp_t *mtimecmp;
  processor_t** procs;
  uint64_t nr_procs;
  struct timeval base;
}clint_t;


void *clint_init(
  uint64_t nr_procs,
  processor_t** procs)
{
  clint_t *clint = calloc(1, sizeof(clint_t));
  assert(clint);
  clint->nr_procs = nr_procs;
  clint->procs = procs;
  clint->mtime = 0;
  clint->mtimecmp = calloc(nr_procs, sizeof(mtimecmp_t));
  assert(clint->mtimecmp);
  gettimeofday(&clint->base, NULL);
  return clint;
}

/* 0000 msip hart 0
 * 0004 msip hart 1
 * 4000 mtimecmp hart 0 lo
 * 4004 mtimecmp hart 0 hi
 * 4008 mtimecmp hart 1 lo
 * 400c mtimecmp hart 1 hi
 * bff8 mtime lo
 * bffc mtime hi
 */

#define MSIP_BASE	0x0
#define MTIMECMP_BASE	0x4000
#define MTIME_BASE	0xbff8

bool clint_load(void *device, uint64_t addr, uint64_t *data, uint8_t width)
{
  // printf("CLINT LOAD @=%x width=%x\n", addr, width);
  clint_t *clint = device;
  clint_increment(clint, 0);
  
  if (addr >= MSIP_BASE && addr + width <= MSIP_BASE + clint->nr_procs*sizeof(msip_t)) {
    uint64_t *mip = kloug_access_mip();
    uint64_t s = !!(*mip & SR_IP_MSIP);
    memcpy(data, &s, width);
  } else if (addr >= MTIMECMP_BASE && addr + width <= MTIMECMP_BASE + clint->nr_procs*sizeof(mtimecmp_t)) {
    memcpy(data, (uint8_t*)clint->mtimecmp + addr - MTIMECMP_BASE, width);
  } else if (addr >= MTIME_BASE && addr + width <= MTIME_BASE + sizeof(mtime_t)) {
    memcpy(data, (uint8_t*)&clint->mtime + addr - MTIME_BASE, width);
  } else {
    return false;
  }
  return true;
}

bool clint_store(void *device, uint64_t addr, uint64_t data, uint8_t width)
{
  clint_t *clint = device;
  //printf("CLINT STORE @=%x, D=%x, width=%x\n", addr, data, width);
  if (addr >= MSIP_BASE && addr + width <= MSIP_BASE + clint->nr_procs*sizeof(msip_t)) {
    assert( clint->nr_procs == 1);
    uint64_t *mip = kloug_access_mip();
    if (data){
        *mip = *mip | SR_IP_MSIP;
    } else {
        *mip = *mip & ~SR_IP_MSIP;
    }
    
  } else if (addr >= MTIMECMP_BASE && addr + width <= MTIMECMP_BASE + clint->nr_procs*sizeof(mtimecmp_t)) {
    memcpy((uint8_t*)clint->mtimecmp + addr - MTIMECMP_BASE, &data, width);
  } else if (addr >= MTIME_BASE && addr + width <= MTIME_BASE + sizeof(mtime_t)) {
    memcpy((uint8_t*)&clint->mtime + addr - MTIME_BASE, &data, width);
  } else {
    return false;
  }
  clint_increment(clint, 0);
  return true;
}

void clint_increment(void *device, uint64_t inc)
{
  clint_t *clint = device;
  /*
  if (CLINT_REAL_TIME) {
   struct timeval now;
   uint64_t diff_usecs;
   gettimeofday(&now, NULL);
   diff_usecs = ((now.tv_sec - clint->base.tv_sec) * 1000000) + (now.tv_usec - clint->base.tv_usec);
   clint->mtime = diff_usecs * FREQ_HZ / 1000000;
  } else 
  */
  {
    clint->mtime += inc;
  }
  assert( clint->nr_procs == 1);
  uint64_t *mip = kloug_access_mip();
  if (clint->mtime >= clint->mtimecmp[0]){
    *mip = *mip | SR_IP_MTIP;
  } else {
    *mip = *mip & ~SR_IP_MTIP;
  }
}