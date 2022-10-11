
#include "kloug.h"
#include "isa.h"
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

int      mmu_read_word(uint64_t address, uint64_t *val);
void     mmu_flush(void);
uint64_t mmu_walk(uint64_t addr);
int      mmu_i_translate(uint64_t addr, uint64_t *physical);
int      mmu_d_translate(uint64_t pc, uint64_t addr, uint64_t *physical,
                         int writeNotRead);

void exception(uint64_t cause, uint64_t pc, uint64_t badaddr);

bool error(bool terminal, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("KlougError: ");
    vprintf(fmt, args);
    va_end(args);
    raise(SIGINT);
    return true;
}

////////////////////////////////////////////////////////////////////////////////
// PO fake memory
////////////////////////////////////////////////////////////////////////////////

static uint8_t po_mem[PO_MEM_SIZE];

void kloug_mem_init(void *mem, uint64_t size) {
    assert(PO_MEM_SIZE >= size);
    memcpy(po_mem, mem, size);
}

void *kloug_mem_proxy(uint32_t addr) {
    if ((addr - PO_MEM_BASE) > PO_MEM_SIZE) {
        fprintf(stderr, "SimError: addr(%x) > PO_MEM_SIZE(%x)\n",
                addr - PO_MEM_BASE, PO_MEM_SIZE);
        abort();
    }
    return po_mem + addr - PO_MEM_BASE;
}

bool mem_valid_addr(uint64_t addr) {
    return (addr >= PO_MEM_BASE) && (addr < (PO_MEM_BASE + PO_MEM_SIZE));
}

void mem_reset(void) { memset(po_mem, 0, sizeof(po_mem)); }

bool mem_write8(uint64_t addr, uint8_t data) {
    if (mem_valid_addr(addr)) {
        po_mem[addr - PO_MEM_BASE] = data;
        return true;
    }
    return false;
}

bool mem_read8(uint64_t addr, uint8_t *data) {
    if (mem_valid_addr(addr)) {
        *data = po_mem[addr - PO_MEM_BASE];
        return true;
    }
    return false;
}

bool mem_write16(uint64_t addr, uint16_t data) {
    if (mem_valid_addr(addr) && (addr & 0b1) == 0) {
        ((uint16_t *)po_mem)[(addr - PO_MEM_BASE) >> 1] = data;
        return true;
    }
    return false;
}

bool mem_read16(uint64_t addr, uint16_t *data) {
    if (mem_valid_addr(addr) && (addr & 0b1) == 0) {
        *data = ((uint16_t *)po_mem)[(addr - PO_MEM_BASE) >> 1];
        return true;
    }
    return false;
}

bool mem_write32(uint64_t addr, uint32_t data) {
    if (mem_valid_addr(addr) && (addr & 0b11) == 0) {
        ((uint32_t *)po_mem)[(addr - PO_MEM_BASE) >> 2] = data;
        return true;
    }
    return false;
}

bool mem_read32(uint64_t addr, uint32_t *data) {
    if (mem_valid_addr(addr) && (addr & 0b11) == 0) {
        *data = ((uint32_t *)po_mem)[(addr - PO_MEM_BASE) >> 2];
        return true;
    }
    return false;
}

bool mem_write64(uint64_t addr, uint64_t data) {
    if (mem_valid_addr(addr) && (addr & 0b111) == 0) {
        ((uint64_t *)po_mem)[(addr - PO_MEM_BASE) >> 3] = data;
        return true;
    }
    return false;
}

bool mem_read64(uint64_t addr, uint64_t *data) {
    if (mem_valid_addr(addr) && (addr & 0b111) == 0) {
        *data = ((uint64_t *)po_mem)[(addr - PO_MEM_BASE) >> 3];
        return true;
    }
    return false;
}

////////////////////////////////////////////////////////////////////////////////
// PO fake uart
////////////////////////////////////////////////////////////////////////////////

void uart_putchar(char c) { fprintf(stdout, "%c", c); }

char uart_getchar(void) { return getchar(); }

////////////////////////////////////////////////////////////////////////////////
// PO bus
////////////////////////////////////////////////////////////////////////////////

void bus_write64(uint64_t addr, uint64_t data) {}

////////////////////////////////////////////////////////////////////////////////
// PO cpu
////////////////////////////////////////////////////////////////////////////////

#define LOG_INST      (1 << 0)
#define LOG_OPCODES   (1 << 1)
#define LOG_REGISTERS (1 << 2)
#define LOG_MEM       (1 << 3)
#define LOG_MMU       (1 << 4)
#define LOG_ARCH      (1 << 5)

uint32_t trace_cfg = 0xFFFFFFFF * 0 + LOG_INST + LOG_MEM + LOG_ARCH;

#define LOG(l, format, ...)                \
    do {                                   \
        if (trace_cfg & l)                 \
            printf(format, ##__VA_ARGS__); \
    } while (0)
#define TRACE_ENABLED(l) (trace_cfg & l)
#define INST_STAT(l)

////////////////////////////////////////////////////////////////////////////////
// Constructor
////////////////////////////////////////////////////////////////////////////////

// CPU Registers
uint64_t m_gpr[32];
uint64_t m_pc;
uint64_t m_pc_x;
uint64_t m_load_res;

// CSR - Machine
uint64_t m_csr_mepc;
uint64_t m_csr_mcause;
uint64_t m_csr_msr;
uint64_t m_csr_mpriv;
uint64_t m_csr_mevec;
uint64_t m_csr_mtval;
uint64_t m_csr_mie;
uint64_t m_csr_mip;
uint64_t m_csr_mtime;
uint64_t m_csr_mtimecmp;
bool     m_csr_mtime_ie;
uint64_t m_csr_mscratch;
uint64_t m_csr_mideleg;
uint64_t m_csr_medeleg;

uint64_t m_csr_mcycle;
uint64_t m_csr_minstret;

uint64_t m_csr_pmpaddr0;
uint64_t m_csr_pmpcfg0;

// CSR - Supervisor
uint64_t m_csr_sepc;
uint64_t m_csr_sevec;
uint64_t m_csr_scause;
uint64_t m_csr_stval;
uint64_t m_csr_satp;
uint64_t m_csr_sscratch;

// TLB cache
uint64_t m_mmu_addr[MMU_TLB_ENTRIES];
uint64_t m_mmu_pte[MMU_TLB_ENTRIES];

// Settings
bool m_enable_mtimecmp = false;
bool m_break;
bool m_fault;

void kloug_reset(void) {
    m_pc       = PO_MEM_BASE;
    m_load_res = 0;

    for (int i = 0; i < REGISTERS; i++) {
        m_gpr[i] = 0;
    }

    m_csr_mpriv   = PRIV_MACHINE;
    m_csr_msr     = 0;
    m_csr_mideleg = 0;
    m_csr_medeleg = 0;

    m_csr_mepc     = 0;
    m_csr_mie      = 0;
    m_csr_mip      = 0;
    m_csr_mcause   = 0;
    m_csr_mevec    = 0;
    m_csr_mtval    = 0;
    m_csr_mtime    = 0;
    m_csr_mtimecmp = 0;
    m_csr_mtime_ie = false;
    m_csr_mscratch = 0;
    m_csr_minstret = 0;

    m_csr_sepc     = 0;
    m_csr_sevec    = 0;
    m_csr_scause   = 0;
    m_csr_stval    = 0;
    m_csr_satp     = 0;
    m_csr_sscratch = 0;

    m_csr_pmpaddr0 = 0;
    m_csr_pmpcfg0  = 0;

    m_csr_mcycle = 0;
    m_fault      = false;
    m_break      = false;

    mmu_flush();
}

////////////////////////////////////////////////////////////////////////////////
// mmu
////////////////////////////////////////////////////////////////////////////////

int mmu_read_word(uint64_t address, uint64_t *val) {
    return mem_read64(address, val);
}

void mmu_flush(void) {
    for (int i = 0; i < MMU_TLB_ENTRIES; i++) {
        m_mmu_addr[i] = 0;
        m_mmu_pte[i]  = 0;
    }
}

uint64_t mmu_walk(uint64_t addr) {
    uint64_t pte = 0;

    LOG(LOG_MMU, "MMU: Walk %x\n", addr);

    if ((m_csr_satp & SATP_MODE) == 0) // Bare mode
    {
        pte = PAGE_PRESENT | PAGE_READ | PAGE_WRITE | PAGE_EXEC | PAGE_USER |
              ((addr >> MMU_PGSHIFT) << MMU_PGSHIFT);
        LOG(LOG_MMU, "MMU: MMU not enabled\n");
    } else {
        // Fast path lookup in TLBs
        uint32_t tlb_entry = (addr >> MMU_PGSHIFT) & (MMU_TLB_ENTRIES - 1);
        uint64_t tlb_match = (addr >> MMU_PGSHIFT);
        if (m_mmu_addr[tlb_entry] == tlb_match && m_mmu_pte[tlb_entry] != 0)
            return m_mmu_pte[tlb_entry];

        uint64_t base =
            ((m_csr_satp >> SATP_PPN_SHIFT) & SATP_PPN_MASK) * PAGE_SIZE;
        uint64_t asid = ((m_csr_satp >> SATP_ASID_SHIFT) & SATP_ASID_MASK);

        LOG(LOG_MMU, "MMU: MMU enabled - base 0x%08x\n", base);

        uint64_t i;
        for (i = MMU_LEVELS - 1; i >= 0; i--) {
            int      ptshift = i * MMU_PTIDXBITS;
            uint64_t idx =
                (addr >> (MMU_PGSHIFT + ptshift)) & ((1 << MMU_PTIDXBITS) - 1);
            uint64_t pte_addr = base + (idx * MMU_PTESIZE);

            // Read PTE
            if (!mmu_read_word(pte_addr, &pte)) {
                LOG(LOG_MMU, "MMU: Cannot read PTE entry %x\n", pte_addr);
                pte = 0;
                break;
            }

            LOG(LOG_MMU, "MMU: PTE value = 0x%08x @ 0x%08x\n", pte, pte_addr);

            uint64_t ppn = pte >> PAGE_PFN_SHIFT;

            // Invalid mapping
            if (!(pte & PAGE_PRESENT)) {
                LOG(LOG_MMU, "MMU: Invalid mapping %x\n", pte_addr);
                pte = 0;
                break;
            }
            // Next level of page table
            else if (!(pte & (PAGE_READ | PAGE_WRITE | PAGE_EXEC))) {
                base = ppn << MMU_PGSHIFT;
                LOG(LOG_MMU, "MMU: Next level of page table %x\n", base);
            }
            // The actual PTE
            else {
                // Keep permission bits
                pte &= PAGE_FLAGS;

                // if this PTE is from a larger PT, fake a leaf
                // PTE so the TLB will work right
                uint64_t vpn = addr >> MMU_PGSHIFT;
                uint64_t value =
                    (ppn | (vpn & ((((uint64_t)1) << ptshift) - 1)))
                    << MMU_PGSHIFT;

                // Add back in permission bits
                value |= pte;

                assert((value >> 32) == 0);
                pte = value;

                uint64_t ptd_addr = ((pte >> MMU_PGSHIFT) << MMU_PGSHIFT);

                LOG(LOG_MMU, "MMU: PTE addr %x (%x)\n", ptd_addr, pte);

                // fault if physical addr is out of range
                if (mem_valid_addr(ptd_addr)) {
                    LOG(LOG_MMU, "MMU: PTE entry found %x\n", pte);
                } else {
                    LOG(LOG_MMU, "MMU: PTE access out of range %x\n",
                        ((pte >> MMU_PGSHIFT) << MMU_PGSHIFT));
                    pte = 0;
                    error(false, "%08x: PTE access out of range %x\n", m_pc,
                          addr);
                }

                m_mmu_addr[tlb_entry] = tlb_match;
                m_mmu_pte[tlb_entry]  = pte;
                break;
            }
        }
    }

    LOG(LOG_MMU, "MMU: pte %x\n", pte);
    return pte;
}

int mmu_i_translate(uint64_t addr, uint64_t *physical) {
    bool page_fault = false;

    // Machine - no MMU
    if (m_csr_mpriv > PRIV_SUPER) {
        *physical = addr;
        return 1;
    }

    uint64_t pte = mmu_walk(addr);

    // Reserved configurations
    if (((pte & (PAGE_EXEC | PAGE_READ | PAGE_WRITE)) == PAGE_WRITE) ||
        ((pte & (PAGE_EXEC | PAGE_READ | PAGE_WRITE)) ==
         (PAGE_EXEC | PAGE_WRITE))) {
        page_fault = true;
    }
    // Supervisor mode
    else if (m_csr_mpriv == PRIV_SUPER) {
        // Supervisor attempts to execute user mode page
        if (pte & PAGE_USER) {
            error(false, "IMMU: Attempt to execute user page 0x%08x\n", addr);
            page_fault = true;
        }
        // Page not executable
        else if ((pte & (PAGE_EXEC)) != (PAGE_EXEC)) {
            page_fault = true;
        }
    }
    // User mode
    else {
        // User mode page not executable
        if ((pte & (PAGE_EXEC | PAGE_USER)) != (PAGE_EXEC | PAGE_USER)) {
            page_fault = true;
        }
    }

    if (page_fault) {
        *physical = 0xFFFFFFFF;
        exception(MCAUSE_PAGE_FAULT_INST, addr, addr);
        return 0;
    }

    uint64_t pgoff  = addr & (MMU_PGSIZE - 1);
    uint64_t pgbase = pte >> MMU_PGSHIFT << MMU_PGSHIFT;
    uint64_t paddr  = pgbase + pgoff;

    LOG(LOG_MMU, "IMMU: Lookup VA %x -|> PA %x\n", addr, paddr);

    *physical = paddr;
    return 1;
}

int mmu_d_translate(uint64_t pc, uint64_t addr, uint64_t *physical,
                    int writeNotRead) {
    bool     page_fault = false;
    uint32_t priv       = m_csr_mpriv;

    // Modify data access privilege level (allows machine mode to use MMU)
    if (m_csr_msr & SR_MPRV)
        priv = SR_GET_MPP(m_csr_msr);

    // Machine - no MMU
    if (priv > PRIV_SUPER) {
        *physical = addr;
        return 1;
    }

    uint64_t pte = mmu_walk(addr);

    // MXR: Loads from pages marked either readable or executable (R=1 or X=1)
    // will succeed.
    if ((m_csr_msr & SR_MXR) && (pte & PAGE_EXEC))
        pte |= PAGE_READ;

    // Reserved configurations
    if (((pte & (PAGE_EXEC | PAGE_READ | PAGE_WRITE)) == PAGE_WRITE) ||
        ((pte & (PAGE_EXEC | PAGE_READ | PAGE_WRITE)) ==
         (PAGE_EXEC | PAGE_WRITE))) {
        page_fault = true;
    }
    // Supervisor mode
    else if (priv == PRIV_SUPER) {
        // User page access - super mode access not enabled
        if ((pte & PAGE_USER) && !(m_csr_msr & SR_SUM)) {
            error(false,
                  "MMU_D: PC=%08x Access %08x - User page access by super\n",
                  pc, addr);
        } else if ((writeNotRead && ((pte & (PAGE_WRITE)) != (PAGE_WRITE))) ||
                   (!writeNotRead && ((pte & (PAGE_READ)) != (PAGE_READ)))) {
            page_fault = true;
        }
    }
    // User mode
    else {
        if ((writeNotRead &&
             ((pte & (PAGE_WRITE | PAGE_USER)) != (PAGE_WRITE | PAGE_USER))) ||
            (!writeNotRead &&
             ((pte & (PAGE_READ | PAGE_USER)) != (PAGE_READ | PAGE_USER)))) {
            page_fault = true;
        }
    }

    if (page_fault) {
        *physical = 0xFFFFFFFF;
        exception(writeNotRead ? MCAUSE_PAGE_FAULT_STORE
                               : MCAUSE_PAGE_FAULT_LOAD,
                  pc, addr);
        return 0;
    }

    uint64_t pgoff  = addr & (MMU_PGSIZE - 1);
    uint64_t pgbase = pte >> MMU_PGSHIFT << MMU_PGSHIFT;
    uint64_t paddr  = pgbase + pgoff;

    LOG(LOG_MMU, "DMMU: Lookup VA %x -|> PA %x\n", addr, paddr);

    *physical = paddr;
    return 1;
}

////////////////////////////////////////////////////////////////////////////////
// LSU  (with optional MMU lookup)
////////////////////////////////////////////////////////////////////////////////
int load(uint64_t pc, uint64_t address, uint64_t *result, int width,
         bool signedLoad) {
    uint64_t physical = address;

    // Translate addresses if required
    if (!mmu_d_translate(pc, address, &physical, 0)) {
        return 0;
    }

    LOG(LOG_MEM, "LOAD: VA 0x%08x PA 0x%08x Width %d\n", address, physical,
        width);
    *result = 0;

    // Detect misaligned load
    if (((address & 0b111) != 0 && width == 8) ||
        ((address & 0b011) != 0 && width == 4) ||
        ((address & 0b001) != 0 && width == 2)) {
        exception(MCAUSE_MISALIGNED_LOAD, pc, address);
        return 0;
    }

    // Invalid load
    if (!mem_valid_addr(physical)) {
        exception(MCAUSE_FAULT_LOAD, pc, address);
        error(false, "%08x: Bad memory access 0x%x\n", pc, address);
        return 0;
    }

    switch (width) {
    case 8: {
        mem_read64(physical, result);
    } break;
    case 4: {
        uint32_t dw = 0;
        mem_read32(physical, &dw);
        *result = dw;
        if (signedLoad && ((*result) & (1 << 31))) {
            *result |= 0xFFFFFFFF00000000;
        }
    } break;
    case 2: {
        uint16_t dh = 0;
        mem_read16(physical, &dh);
        *result |= dh;
        if (signedLoad && ((*result) & (1 << 15))) {
            *result |= 0xFFFFFFFFFFFF0000;
        }
    } break;
    case 1: {
        uint8_t db = 0;
        mem_read8(physical, &db);
        *result |= ((uint32_t)db << 0);
        if (signedLoad && ((*result) & (1 << 7))) {
            *result |= 0xFFFFFFFFFFFFFF00;
        }
    } break;
    default:
        assert(!"Invalid");
        break;
    }

    LOG(LOG_MEM, "LOAD_RESULT: 0x%08x\n", *result);
    return 1;
}

int store(uint64_t pc, uint64_t address, uint64_t data, int width) {
    uint64_t physical = address;

    // Translate addresses if required
    if (!mmu_d_translate(pc, address, &physical, 1)) {
        return 0;
    }

    LOG(LOG_MEM, "STORE: VA 0x%08x PA 0x%08x Value 0x%08x Width %d\n", address,
        physical, data, width);

    // Detect misaligned load
    if (((address & 0b111) != 0 && width == 8) ||
        ((address & 0b011) != 0 && width == 4) ||
        ((address & 0b001) != 0 && width == 2)) {        
        exception(MCAUSE_MISALIGNED_STORE, pc, address);
        return 0;
    }

    // Invalid load
    if (!mem_valid_addr(physical)) {
        exception(MCAUSE_FAULT_STORE, pc, address);
        error(false, "%08x: Bad memory access 0x%x\n", pc, address);
        return 0;
    }

    switch (width) {
    case 8:
        mem_write64(physical, data);
        break;
    case 4:
        mem_write32(physical, data & 0xFFFFFFFF);
        break;
    case 2:
        mem_write16(physical, data & 0xFFFF);
        break;
    case 1:
        mem_write8(physical + 0, data & 0xFF);
        break;
    default:
        assert(!"Invalid");
        break;
    }
    return 1;
}

////////////////////////////////////////////////////////////////////////////////
// CSR Perform CSR access
////////////////////////////////////////////////////////////////////////////////

#define CSR_STD(name, var_name) \
    case CSR_##name: {          \
        *result = var_name;     \
        if (set && clr)         \
            var_name = data;    \
        else if (set)           \
            var_name |= data;   \
        else if (clr)           \
            var_name &= ~data;  \
    } break;

#define CSR_STDS(name, var_name) \
    case CSR_##name: {           \
        *result = var_name;      \
        if (set && clr)          \
            var_name = data;     \
        else if (set)            \
            var_name |= data;    \
        else if (clr)            \
            var_name &= ~data;   \
    } break;

#define CSR_STDx(name, var_name, cval) \
    case CSR_##name: {                 \
        data |= cval;                  \
        *result = var_name;            \
        *result |= cval;               \
        if (set && clr)                \
            var_name = data;           \
        else if (set)                  \
            var_name |= data;          \
        else if (clr)                  \
            var_name &= ~data;         \
    } break;

#define CSR_CONST(name, value) \
    case CSR_##name: {         \
        *result = value;       \
    } break;

bool access_csr(uint64_t address, uint64_t data, bool set, bool clr,
                uint64_t *result) {
    *result = 0;

    // Apply CSR access permissions
    uint32_t csr_priv      = (address >> 8) & 0x3;
    uint32_t csr_read_only = ((address >> 10) & 0x3) == 3;
    if (((set || clr) && csr_read_only) || m_csr_mpriv < csr_priv) {
        LOG(LOG_INST,
            "-|> CSR %08x access fault - permission level %d required %d\n",
            address & 0xFFF, m_csr_mpriv, csr_priv);
        return true;
    }

    // SATP write - flush cached TLBs
    if (((address & 0xFFF) == CSR_SATP) && (set || clr)) {
        mmu_flush();
    }

    switch (address & 0xFFF) {
        // Standard - Machine
        CSR_STD(MEPC, m_csr_mepc);
        CSR_STD(MTVEC, m_csr_mevec);
        CSR_STD(MTVAL, m_csr_mtval);
        CSR_STD(MCAUSE, m_csr_mcause);
        CSR_STDx(MSTATUS, m_csr_msr, SR_XLEN64);
        CSR_STD(MIP, m_csr_mip);
        CSR_STD(MIE, m_csr_mie);
        CSR_CONST(MISA, MISA_VALUE);
        CSR_STD(MIDELEG, m_csr_mideleg);
        CSR_STD(MEDELEG, m_csr_medeleg);
        CSR_STD(MSCRATCH, m_csr_mscratch);
        CSR_CONST(MHARTID, 0);

        CSR_STD(PMPADDR0, m_csr_pmpaddr0);
        CSR_STD(PMPCFG0, m_csr_pmpcfg0);
        CSR_STD(MCYCLE, m_csr_mcycle);
        CSR_STD(MISNTRET, m_csr_minstret);

        // Standard - Supervisor
        CSR_STD(SEPC, m_csr_sepc);
        CSR_STD(STVEC, m_csr_sevec);
        CSR_STD(SCAUSE, m_csr_scause);
        CSR_STDS(SIP, m_csr_mip);
        CSR_STDS(SIE, m_csr_mie);
        CSR_STD(SATP, m_csr_satp);
        CSR_STD(STVAL, m_csr_stval);
        CSR_STD(SSCRATCH, m_csr_sscratch);
        CSR_STDS(SSTATUS, m_csr_msr);

    default:
        error(false, "*** CSR address not supported %08x [PC=%08x]\n", address,
              m_pc);
        break;
    }

    return false;
}

////////////////////////////////////////////////////////////////////////////////
// exception: Handle an exception or interrupt
////////////////////////////////////////////////////////////////////////////////

void exception(uint64_t cause, uint64_t pc, uint64_t badaddr) {
    uint64_t deleg;
    uint64_t bit;

    if (cause >= MCAUSE_INTERRUPT) { // Interrupt
        deleg = m_csr_mideleg;
        bit   = 1 << (cause - MCAUSE_INTERRUPT);
        LOG(LOG_ARCH, "interruption %x, pc %x, badaddr %x\n",
            (cause - MCAUSE_INTERRUPT), pc, badaddr);
    } else { // Exception
        deleg = m_csr_medeleg;
        bit   = 1 << cause;
        LOG(LOG_ARCH, "exception %s, pc %x, badaddr %x\n", DISPLAY_MCAUSE[cause], pc, badaddr);
    }

    // Exception delegated to
    if (m_csr_mpriv <= PRIV_SUPER && (deleg & bit)) { // supervisor mode
        uint64_t s = m_csr_msr;
        // Interrupt save and disable
        s &= ~SR_SPIE;
        s |= (s & SR_SIE) ? SR_SPIE : 0;
        s &= ~SR_SIE;
        // Record previous priviledge level
        s &= ~SR_SPP;
        s |= (m_csr_mpriv == PRIV_SUPER) ? SR_SPP : 0;
        // Raise priviledge to supervisor level
        m_csr_mpriv  = PRIV_SUPER;
        m_csr_msr    = s;
        m_csr_sepc   = pc;
        m_csr_scause = cause;
        m_csr_stval  = badaddr;
        // Set new PC
        m_pc = m_csr_sevec;
    } else { // Machine mode
        uint64_t s = m_csr_msr;
        // Interrupt save and disable
        s &= ~SR_MPIE;
        s |= (s & SR_MIE) ? SR_MPIE : 0;
        s &= ~SR_MIE;
        // Record previous priviledge level
        s &= ~SR_MPP;
        s |= (m_csr_mpriv << SR_MPP_SHIFT);
        // Raise priviledge to machine level
        m_csr_mpriv  = PRIV_MACHINE;
        m_csr_msr    = s;
        m_csr_mepc   = pc;
        m_csr_mcause = cause;
        m_csr_mtval  = badaddr;
        // Set new PC
        m_pc = m_csr_mevec;
    }
}

bool execute(void) {
    LOG(LOG_ARCH, "--- clock ---\n");
    LOG(LOG_ARCH, "LEVEL = %c = %d\n",
        m_csr_mpriv == PRIV_MACHINE ? 'M'
        : m_csr_mpriv == PRIV_SUPER ? 'S'
                                    : 'U',
        m_csr_mpriv);
    // Increment cycles
    m_csr_mcycle++;

    /********************** IF **********************/
    uint64_t phy_pc = m_pc;
    // Translate PC to physical address
    if (!mmu_i_translate(m_pc, &phy_pc)) {
        return false;
    }
    // Misaligned PC
    if (m_pc & 1) {
        exception(MCAUSE_MISALIGNED_FETCH, m_pc, m_pc);
        return false;
    }
    LOG(LOG_OPCODES, "PC = %x\n", m_pc);
    // Get opcode at current PC
    uint64_t opcode = 0;
    if ((phy_pc & 2) == 0) {
        mem_read32(phy_pc, (uint32_t *)&opcode);
    } else {
        // assert(0);
        uint16_t op1 = 0, op2 = 0;
        mem_read16(phy_pc + 0, &op1);
        mem_read16(phy_pc + 2, &op2);
        opcode = ((uint64_t)op1 << 0) + ((uint64_t)op2 << 16);
    }

    LOG(LOG_OPCODES, "%08x: %08x\n", m_pc, opcode);

    /********************** ID **********************/
    int     rd  = (opcode & OPCODE_RD_MASK) >> OPCODE_RD_SHIFT;
    int     rs1 = (opcode & OPCODE_RS1_MASK) >> OPCODE_RS1_SHIFT;
    int     rs2 = (opcode & OPCODE_RS2_MASK) >> OPCODE_RS2_SHIFT;
    int64_t typei_imm =
        SEXT32(opcode & OPCODE_TYPEI_IMM_MASK) >> OPCODE_TYPEI_IMM_SHIFT;
    int64_t typeu_imm =
        SEXT32(opcode & OPCODE_TYPEU_IMM_MASK) >> OPCODE_TYPEU_IMM_SHIFT;
    int64_t imm20    = typeu_imm << OPCODE_TYPEU_IMM_SHIFT;
    int64_t imm12    = typei_imm;
    int64_t bimm     = OPCODE_SBTYPE_IMM(opcode);
    int64_t jimm20   = OPCODE_UJTYPE_IMM(opcode);
    int64_t storeimm = OPCODE_STYPE_IMM(opcode);
    int shamt = ((signed)(opcode & OPCODE_SHAMT_MASK)) >> OPCODE_SHAMT_SHIFT;

    /********************** RR **********************/
    // Register Read
    uint64_t reg_rd         = 0;
    uint64_t reg_rs1        = m_gpr[rs1];
    uint64_t reg_rs2        = m_gpr[rs2];
    uint64_t pc             = m_pc;
    bool     take_exception = false;

    LOG(LOG_OPCODES, "        rd(%d) r%d = %d, r%d = %d\n", rd, rs1, reg_rs1,
        rs2, reg_rs2);

    /********************** EX **********************/
    if (opcode == 0) {
        error(false, "Bad instruction @ %x\n", pc);
        exception(MCAUSE_ILLEGAL_INSTRUCTION, pc, opcode);
        m_fault        = true;
        take_exception = true;
    } else if ((opcode & INST_ANDI_MASK) == INST_ANDI) {
        LOG(LOG_INST, "%016llx: andi r%d, r%d, %d\n", pc, rd, rs1, imm12);
        INST_STAT(ENUM_INST_ANDI);
        reg_rd = reg_rs1 & imm12;
        pc += 4;
    } else if ((opcode & INST_ORI_MASK) == INST_ORI) {
        LOG(LOG_INST, "%016llx: ori r%d, r%d, %d\n", pc, rd, rs1, imm12);
        INST_STAT(ENUM_INST_ORI);
        reg_rd = reg_rs1 | imm12;
        pc += 4;
    } else if ((opcode & INST_XORI_MASK) == INST_XORI) {
        LOG(LOG_INST, "%016llx: xori r%d, r%d, %d\n", pc, rd, rs1, imm12);
        INST_STAT(ENUM_INST_XORI);
        reg_rd = reg_rs1 ^ imm12;
        pc += 4;
    } else if ((opcode & INST_ADDI_MASK) == INST_ADDI) {
        LOG(LOG_INST, "%016llx: addi r%d, r%d, %d\n", pc, rd, rs1, imm12);
        INST_STAT(ENUM_INST_ADDI);
        reg_rd = reg_rs1 + imm12;
        pc += 4;
    } else if ((opcode & INST_SLTI_MASK) == INST_SLTI) {
        LOG(LOG_INST, "%016llx: slti r%d, r%d, %d\n", pc, rd, rs1, imm12);
        INST_STAT(ENUM_INST_SLTI);
        reg_rd = (int64_t)reg_rs1 < (int64_t)imm12;
        pc += 4;
    } else if ((opcode & INST_SLTIU_MASK) == INST_SLTIU) {
        LOG(LOG_INST, "%016llx: sltiu r%d, r%d, %d\n", pc, rd, rs1,
            (uint64_t)imm12);
        INST_STAT(ENUM_INST_SLTIU);
        reg_rd = (uint64_t)reg_rs1 < (uint64_t)imm12;
        pc += 4;
    } else if ((opcode & INST_SLLI_MASK) == INST_SLLI) {
        LOG(LOG_INST, "%016llx: slli r%d, r%d, %d\n", pc, rd, rs1, shamt);
        INST_STAT(ENUM_INST_SLLI);
        reg_rd = reg_rs1 << shamt;
        pc += 4;
    } else if ((opcode & INST_SRLI_MASK) == INST_SRLI) {
        LOG(LOG_INST, "%016llx: srli r%d, r%d, %d\n", pc, rd, rs1, shamt);
        INST_STAT(ENUM_INST_SRLI);
        reg_rd = (uint64_t)reg_rs1 >> shamt;
        pc += 4;
    } else if ((opcode & INST_SRAI_MASK) == INST_SRAI) {
        LOG(LOG_INST, "%016llx: srai r%d, r%d, %d\n", pc, rd, rs1, shamt);
        INST_STAT(ENUM_INST_SRAI);
        reg_rd = (int64_t)reg_rs1 >> shamt;
        pc += 4;
    } else if ((opcode & INST_LUI_MASK) == INST_LUI) {
        LOG(LOG_INST, "%016llx: lui r%d, 0x%x\n", pc, rd, imm20);
        INST_STAT(ENUM_INST_LUI);
        reg_rd = imm20;
        pc += 4;
    } else if ((opcode & INST_AUIPC_MASK) == INST_AUIPC) {
        LOG(LOG_INST, "%016llx: auipc r%d, 0x%x\n", pc, rd, imm20);
        INST_STAT(ENUM_INST_AUIPC);
        reg_rd = imm20 + pc;
        pc += 4;
    } else if ((opcode & INST_ADD_MASK) == INST_ADD) {
        LOG(LOG_INST, "%016llx: add r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_ADD);
        reg_rd = reg_rs1 + reg_rs2;
        pc += 4;
    } else if ((opcode & INST_SUB_MASK) == INST_SUB) {
        LOG(LOG_INST, "%016llx: sub r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_SUB);
        reg_rd = reg_rs1 - reg_rs2;
        pc += 4;
    } else if ((opcode & INST_SLT_MASK) == INST_SLT) {
        LOG(LOG_INST, "%016llx: slt r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_SLT);
        reg_rd = (int64_t)reg_rs1 < (int64_t)reg_rs2;
        pc += 4;
    } else if ((opcode & INST_SLTU_MASK) == INST_SLTU) {
        LOG(LOG_INST, "%016llx: sltu r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_SLTU);
        reg_rd = (uint64_t)reg_rs1 < (uint64_t)reg_rs2;
        pc += 4;
    } else if ((opcode & INST_XOR_MASK) == INST_XOR) {
        LOG(LOG_INST, "%016llx: xor r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_XOR);
        reg_rd = reg_rs1 ^ reg_rs2;
        pc += 4;
    } else if ((opcode & INST_OR_MASK) == INST_OR) {
        LOG(LOG_INST, "%016llx: or r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_OR);
        reg_rd = reg_rs1 | reg_rs2;
        pc += 4;
    } else if ((opcode & INST_AND_MASK) == INST_AND) {
        LOG(LOG_INST, "%016llx: and r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_AND);
        reg_rd = reg_rs1 & reg_rs2;
        pc += 4;
    } else if ((opcode & INST_SLL_MASK) == INST_SLL) {
        LOG(LOG_INST, "%016llx: sll r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_SLL);
        reg_rd = reg_rs1 << reg_rs2;
        pc += 4;
    } else if ((opcode & INST_SRL_MASK) == INST_SRL) {
        LOG(LOG_INST, "%016llx: srl r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_SRL);
        reg_rd = (uint64_t)reg_rs1 >> reg_rs2;
        pc += 4;
    } else if ((opcode & INST_SRA_MASK) == INST_SRA) {
        LOG(LOG_INST, "%016llx: sra r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_SRA);
        reg_rd = (int64_t)reg_rs1 >> reg_rs2;
        pc += 4;
    } else if ((opcode & INST_JAL_MASK) == INST_JAL) {
        LOG(LOG_INST, "%016llx: jal r%d, %d\n", pc, rd, jimm20);
        INST_STAT(ENUM_INST_JAL);
        reg_rd = pc + 4;
        pc += jimm20;
    } else if ((opcode & INST_JALR_MASK) == INST_JALR) {
        LOG(LOG_INST, "%016llx: jalr r%d, r%d\n", pc, rs1, imm12);
        INST_STAT(ENUM_INST_JALR);
        reg_rd = pc + 4;
        pc     = (reg_rs1 + imm12) & ~1;
    } else if ((opcode & INST_BEQ_MASK) == INST_BEQ) {
        LOG(LOG_INST, "%016llx: beq r%d, r%d, %d\n", pc, rs1, rs2, bimm);
        INST_STAT(ENUM_INST_BEQ);
        pc += (reg_rs1 == reg_rs2) ? bimm : 4;
        rd = 0;
    } else if ((opcode & INST_BNE_MASK) == INST_BNE) {
        LOG(LOG_INST, "%016llx: bne r%d, r%d, %d\n", pc, rs1, rs2, bimm);
        INST_STAT(ENUM_INST_BNE);
        pc += (reg_rs1 != reg_rs2) ? bimm : 4;
        rd = 0;
    } else if ((opcode & INST_BLT_MASK) == INST_BLT) {
        LOG(LOG_INST, "%016llx: blt r%d, r%d, %d\n", pc, rs1, rs2, bimm);
        INST_STAT(ENUM_INST_BLT);
        pc += ((int64_t)reg_rs1 < (int64_t)reg_rs2) ? bimm : 4;
        rd = 0;
    } else if ((opcode & INST_BGE_MASK) == INST_BGE) {
        LOG(LOG_INST, "%016llx: bge r%d, r%d, %d\n", pc, rs1, rs2, bimm);
        INST_STAT(ENUM_INST_BGE);
        pc += ((int64_t)reg_rs1 >= (int64_t)reg_rs2) ? bimm : 4;
        rd = 0;
    } else if ((opcode & INST_BLTU_MASK) == INST_BLTU) {
        LOG(LOG_INST, "%016llx: bltu r%d, r%d, %d\n", pc, rs1, rs2, bimm);
        INST_STAT(ENUM_INST_BLTU);
        pc += ((uint64_t)reg_rs1 < (uint64_t)reg_rs2) ? bimm : 4;
        rd = 0;
    } else if ((opcode & INST_BGEU_MASK) == INST_BGEU) {
        LOG(LOG_INST, "%016llx: bgeu r%d, r%d, %d\n", pc, rs1, rs2, bimm);
        INST_STAT(ENUM_INST_BGEU);
        pc += ((uint64_t)reg_rs1 >= (uint64_t)reg_rs2) ? bimm : 4;
        rd = 0;
    } else if ((opcode & INST_LB_MASK) == INST_LB) {
        LOG(LOG_INST, "%016llx: lb r%d, %d(r%d)\n", pc, rd, imm12, rs1);
        INST_STAT(ENUM_INST_LB);
        if(load(pc, reg_rs1 + imm12, &reg_rd, 1, true))
            pc += 4;
        else
            return false;
    } else if ((opcode & INST_LH_MASK) == INST_LH) {
        LOG(LOG_INST, "%016llx: lh r%d, %d(r%d)\n", pc, rd, imm12, rs1);
        INST_STAT(ENUM_INST_LH);
        if(load(pc, reg_rs1 + imm12, &reg_rd, 2, true))
            pc += 4;
        else
            return false;
    } else if ((opcode & INST_LW_MASK) == INST_LW) {
        INST_STAT(ENUM_INST_LW);
        LOG(LOG_INST, "%016llx: lw r%d, %d(r%d)\n", pc, rd, imm12, rs1);
        if(load(pc, reg_rs1 + imm12, &reg_rd, 4, true))
            pc += 4;
        else
            return false;
    } else if ((opcode & INST_LBU_MASK) == INST_LBU) {
        LOG(LOG_INST, "%016llx: lbu r%d, %d(r%d)\n", pc, rd, imm12, rs1);
        INST_STAT(ENUM_INST_LBU);
        if(load(pc, reg_rs1 + imm12, &reg_rd, 1, false))
            pc += 4;
        else
            return false;
    } else if ((opcode & INST_LHU_MASK) == INST_LHU) {
        LOG(LOG_INST, "%016llx: lhu r%d, %d(r%d)\n", pc, rd, imm12, rs1);
        INST_STAT(ENUM_INST_LHU);
        if(load(pc, reg_rs1 + imm12, &reg_rd, 2, false))
            pc += 4;    
        else
            return false;
    } else if ((opcode & INST_LWU_MASK) == INST_LWU) {
        LOG(LOG_INST, "%016llx: lwu r%d, %d(r%d)\n", pc, rd, imm12, rs1);
        INST_STAT(ENUM_INST_LWU);
        if(load(pc, reg_rs1 + imm12, &reg_rd, 4, false))
            pc += 4;
        else
            return false;
    } else if ((opcode & INST_SB_MASK) == INST_SB) {
        LOG(LOG_INST, "%016llx: sb %d(r%d), r%d\n", pc, storeimm, rs1, rs2);
        INST_STAT(ENUM_INST_SB);
        if(store(pc, reg_rs1 + storeimm, reg_rs2, 1))
            pc += 4;
        else
            return false;
        rd = 0;
    } else if ((opcode & INST_SH_MASK) == INST_SH) {
        LOG(LOG_INST, "%016llx: sh %d(r%d), r%d\n", pc, storeimm, rs1, rs2);
        INST_STAT(ENUM_INST_SH);
        if(store(pc, reg_rs1 + storeimm, reg_rs2, 2))
            pc += 4;
        else
            return false;
        rd = 0;
    } else if ((opcode & INST_SW_MASK) == INST_SW) {
        LOG(LOG_INST, "%016llx: sw %d(r%d), r%d\n", pc, storeimm, rs1, rs2);
        INST_STAT(ENUM_INST_SW);
        if(store(pc, reg_rs1 + storeimm, reg_rs2, 4))
            pc += 4;
        else
            return false;
        rd = 0;
    } else if ((opcode & INST_MUL_MASK) == INST_MUL) {
        LOG(LOG_INST, "%016llx: mul r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_MUL);
        reg_rd = (int64_t)reg_rs1 * (int64_t)reg_rs2;
        pc += 4;
    } else if ((opcode & INST_MULH_MASK) == INST_MULH) {
        LOG(LOG_INST, "%016llx: mulh r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_MULH);
        signed __int128 res =((signed __int128)(int64_t)reg_rs1) * ((signed __int128)(int64_t)reg_rs2);
        reg_rd = (int64_t)(res >> 64);
        pc += 4;
    } else if ((opcode & INST_MULHSU_MASK) == INST_MULHSU) {
        LOG(LOG_INST, "%016llx: mulhsu r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_MULHSU);
        signed __int128 res = ((signed __int128)(int64_t)reg_rs1) * ((unsigned __int128)(uint64_t)reg_rs2);
        reg_rd = (int64_t)(res >> 64);
        pc += 4;
    } else if ((opcode & INST_MULHU_MASK) == INST_MULHU) {
        LOG(LOG_INST, "%016llx: mulhu r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_MULHU);
        unsigned __int128 res = ((unsigned __int128)(uint64_t)reg_rs1) * ((unsigned __int128)(uint64_t)reg_rs2);
        reg_rd = (uint64_t)(res >> 64);
        pc += 4;
    } else if ((opcode & INST_DIV_MASK) == INST_DIV) {
        LOG(LOG_INST, "%016llx: div r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_DIV);
        if ((int64_t)reg_rs1 == INT64_MIN && (int64_t)reg_rs2 == -1)
            reg_rd = reg_rs1;
        else if (reg_rs2 != 0)
            reg_rd = (int64_t)reg_rs1 / (int64_t)reg_rs2;
        else
            reg_rd = (uint64_t)-1;
        pc += 4;
    } else if ((opcode & INST_DIVU_MASK) == INST_DIVU) {
        LOG(LOG_INST, "%016llx: divu r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_DIVU);
        if (reg_rs2 != 0)
            reg_rd = (uint64_t)reg_rs1 / (uint64_t)reg_rs2;
        else
            reg_rd = (uint64_t)-1;
        pc += 4;
    } else if ((opcode & INST_REM_MASK) == INST_REM) {
        LOG(LOG_INST, "%016llx: rem r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_REM);
        if ((int64_t)reg_rs1 == INT64_MIN && (int64_t)reg_rs2 == -1)
            reg_rd = 0;
        else if (reg_rs2 != 0)
            reg_rd = (int64_t)reg_rs1 % (int64_t)reg_rs2;
        else
            reg_rd = reg_rs1;
        pc += 4;
    } else if ((opcode & INST_REMU_MASK) == INST_REMU) {
        LOG(LOG_INST, "%016llx: remu r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_REMU);
        if (reg_rs2 != 0)
            reg_rd = (uint64_t)reg_rs1 % (uint64_t)reg_rs2;
        else
            reg_rd = reg_rs1;
        pc += 4;
    } else if ((opcode & INST_ECALL_MASK) == INST_ECALL) {
        LOG(LOG_INST, "%016llx: ecall\n", pc);
        INST_STAT(ENUM_INST_ECALL);
        exception(MCAUSE_ECALL_U + m_csr_mpriv, pc, 0);
        take_exception = true;
    } else if ((opcode & INST_EBREAK_MASK) == INST_EBREAK) {
        LOG(LOG_INST, "%016llx: ebreak\n", pc);
        INST_STAT(ENUM_INST_EBREAK);
        exception(MCAUSE_BREAKPOINT, pc, 0);
        take_exception = true;
        m_break        = true;
    } else if ((opcode & INST_MRET_MASK) == INST_MRET) {
        LOG(LOG_INST, "%016llx: mret\n", pc);
        INST_STAT(ENUM_INST_MRET);
        assert(m_csr_mpriv == PRIV_MACHINE);
        uint64_t s        = m_csr_msr;
        uint64_t prev_prv = SR_GET_MPP(m_csr_msr);
        // Interrupt enable pop
        s &= ~SR_MIE;
        s |= (s & SR_MPIE) ? SR_MIE : 0;
        s |= SR_MPIE;
        // Set next MPP to user mode
        s &= ~SR_MPP;
        s |= SR_MPP_U;
        // Set privilege level to previous MPP
        m_csr_mpriv = prev_prv;
        m_csr_msr   = s;
        // Return to EPC
        pc = m_csr_mepc;
    } else if ((opcode & INST_SRET_MASK) == INST_SRET) {
        LOG(LOG_INST, "%016llx: sret\n", pc);
        INST_STAT(ENUM_INST_SRET);
        assert(m_csr_mpriv == PRIV_SUPER);
        uint64_t s        = m_csr_msr;
        uint64_t prev_prv = (m_csr_msr & SR_SPP) ? PRIV_SUPER : PRIV_USER;
        // Interrupt enable pop
        s &= ~SR_SIE;
        s |= (s & SR_SPIE) ? SR_SIE : 0;
        s |= SR_SPIE;
        // Set next SPP to user mode
        s &= ~SR_SPP;
        // Set privilege level to previous MPP
        m_csr_mpriv = prev_prv;
        m_csr_msr   = s;
        // Return to EPC
        pc = m_csr_sepc;
    } else if (((opcode & INST_SFENCE_MASK) == INST_SFENCE) ||
               ((opcode & INST_FENCE_MASK) == INST_FENCE) ||
               ((opcode & INST_IFENCE_MASK) == INST_IFENCE)) {
        LOG(LOG_INST, "%016llx: fence\n", pc);
        INST_STAT(ENUM_INST_FENCE);
        // SFENCE.VMA
        if ((opcode & INST_SFENCE_MASK) == INST_SFENCE)
            mmu_flush();
        pc += 4;
    } else if ((opcode & INST_CSRRW_MASK) == INST_CSRRW) {
        LOG(LOG_INST, "%016llx: csrw r%d, r%d, 0x%x\n", pc, rd, rs1, imm12);
        INST_STAT(ENUM_INST_CSRRW);
        take_exception = access_csr(imm12, reg_rs1, true, true, &reg_rd);
        if (take_exception)
            exception(MCAUSE_ILLEGAL_INSTRUCTION, pc, opcode);
        else
            pc += 4;
    } else if ((opcode & INST_CSRRS_MASK) == INST_CSRRS) {
        LOG(LOG_INST, "%016llx: csrs r%d, r%d, 0x%x\n", pc, rd, rs1, imm12);
        INST_STAT(ENUM_INST_CSRRS);
        take_exception = access_csr(imm12, reg_rs1, (rs1 != 0), false, &reg_rd);
        if (take_exception)
            exception(MCAUSE_ILLEGAL_INSTRUCTION, pc, opcode);
        else
            pc += 4;
    } else if ((opcode & INST_CSRRC_MASK) == INST_CSRRC) {
        LOG(LOG_INST, "%016llx: csrc r%d, r%d, 0x%x\n", pc, rd, rs1, imm12);
        INST_STAT(ENUM_INST_CSRRC);
        take_exception = access_csr(imm12, reg_rs1, false, (rs1 != 0), &reg_rd);
        if (take_exception)
            exception(MCAUSE_ILLEGAL_INSTRUCTION, pc, opcode);
        else
            pc += 4;
    } else if ((opcode & INST_CSRRWI_MASK) == INST_CSRRWI) {
        LOG(LOG_INST, "%016llx: csrwi r%d, %d, 0x%x\n", pc, rd, rs1, imm12);
        INST_STAT(ENUM_INST_CSRRWI);
        take_exception = access_csr(imm12, rs1, true, true, &reg_rd);
        if (take_exception)
            exception(MCAUSE_ILLEGAL_INSTRUCTION, pc, opcode);
        else
            pc += 4;
    } else if ((opcode & INST_CSRRSI_MASK) == INST_CSRRSI) {
        LOG(LOG_INST, "%016llx: csrsi r%d, %d, 0x%x\n", pc, rd, rs1, imm12);
        INST_STAT(ENUM_INST_CSRRSI);
        take_exception = access_csr(imm12, rs1, (rs1 != 0), false, &reg_rd);
        if (take_exception)
            exception(MCAUSE_ILLEGAL_INSTRUCTION, pc, opcode);
        else
            pc += 4;
    } else if ((opcode & INST_CSRRCI_MASK) == INST_CSRRCI) {
        LOG(LOG_INST, "%016llx: csrci r%d, %d, 0x%x\n", pc, rd, rs1, imm12);
        INST_STAT(ENUM_INST_CSRRCI);
        take_exception = access_csr(imm12, rs1, false, (rs1 != 0), &reg_rd);
        if (take_exception)
            exception(MCAUSE_ILLEGAL_INSTRUCTION, pc, opcode);
        else
            pc += 4;
    } else if ((opcode & INST_WFI_MASK) == INST_WFI) {
        LOG(LOG_INST, "%016llx: wfi\n", pc);
        INST_STAT(ENUM_INST_WFI);
        pc += 4;
    } else if ((opcode & INST_SD_MASK) == INST_SD) {
        LOG(LOG_INST, "%016llx: sd %d(r%d), r%d\n", pc, storeimm, rs1, rs2);
        INST_STAT(ENUM_INST_SD);
        if(store(pc, reg_rs1 + storeimm, reg_rs2, 8))
            pc += 4;
        else
            return false;
        rd = 0;
    } else if ((opcode & INST_LD_MASK) == INST_LD) {
        LOG(LOG_INST, "%016llx: ld r%d, %d(r%d)\n", pc, rd, imm12, rs1);
        INST_STAT(ENUM_INST_LD);
        if(load(pc, reg_rs1 + imm12, &reg_rd, 8, true))
            pc += 4;
        else
            return false;
    } else if ((opcode & INST_ADDIW_MASK) == INST_ADDIW) {
        LOG(LOG_INST, "%016llx: addiw r%d, r%d, %d\n", pc, rd, rs1, imm12);
        INST_STAT(ENUM_INST_ADDIW);
        reg_rd = SEXT32(reg_rs1 + imm12);
        pc += 4;
    } else if ((opcode & INST_ADDW_MASK) == INST_ADDW) {
        LOG(LOG_INST, "%016llx: addw r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_ADDW);
        reg_rd = SEXT32(reg_rs1 + reg_rs2);
        pc += 4;
    } else if ((opcode & INST_SUBW_MASK) == INST_SUBW) {
        LOG(LOG_INST, "%016llx: subw r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_SUBW);
        reg_rd = SEXT32(reg_rs1 - reg_rs2);
        pc += 4;
    } else if ((opcode & INST_SLLIW_MASK) == INST_SLLIW) {
        LOG(LOG_INST, "%016llx: slliw r%d, r%d, %d\n", pc, rd, rs1, shamt);
        INST_STAT(ENUM_INST_SLLIW);
        reg_rs1 &= 0xFFFFFFFF;
        shamt &= SHIFT_MASK32;
        reg_rd = SEXT32(reg_rs1 << shamt);
        pc += 4;
    } else if ((opcode & INST_SRLIW_MASK) == INST_SRLIW) {
        LOG(LOG_INST, "%016llx: srliw r%d, r%d, %d\n", pc, rd, rs1, shamt);
        INST_STAT(ENUM_INST_SRLIW);
        shamt &= SHIFT_MASK32;
        reg_rs1 &= 0xFFFFFFFF;
        reg_rd = SEXT32((uint64_t)reg_rs1 >> shamt);
        pc += 4;
    } else if ((opcode & INST_SRAIW_MASK) == INST_SRAIW) {
        LOG(LOG_INST, "%016llx: sraiw r%d, r%d, %d\n", pc, rd, rs1, shamt);
        INST_STAT(ENUM_INST_SRAIW);
        reg_rs1 &= 0xFFFFFFFF;
        shamt &= SHIFT_MASK32;
        reg_rd = SEXT32((int32_t)reg_rs1 >> shamt);
        pc += 4;
    } else if ((opcode & INST_SLLW_MASK) == INST_SLLW) {
        LOG(LOG_INST, "%016llx: sllw r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_SLLW);
        reg_rs2 &= SHIFT_MASK32;
        reg_rd = SEXT32(reg_rs1 << reg_rs2);
        pc += 4;
    } else if ((opcode & INST_SRLW_MASK) == INST_SRLW) {
        LOG(LOG_INST, "%016llx: srlw r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_SRLW);
        reg_rs1 &= 0xFFFFFFFF;
        reg_rs2 &= SHIFT_MASK32;
        reg_rd = SEXT32((uint64_t)reg_rs1 >> reg_rs2);
        pc += 4;
    } else if ((opcode & INST_SRAW_MASK) == INST_SRAW) {
        LOG(LOG_INST, "%016llx: sraw r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_SRAW);
        reg_rd = SEXT32((int64_t)(int32_t)reg_rs1 >> (reg_rs2 & SHIFT_MASK32));
        pc += 4;
    } else if ((opcode & INST_MULW_MASK) == INST_MULW) {
        LOG(LOG_INST, "%016llx: mulw r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_MULW);
        reg_rd = SEXT32((int64_t)reg_rs1 * (int64_t)reg_rs2);
        pc += 4;
    } else if ((opcode & INST_DIVW_MASK) == INST_DIVW) {
        LOG(LOG_INST, "%016llx: divw r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_DIVW);
        if ((int64_t)(int32_t)reg_rs2 != 0)
            reg_rd =
                SEXT32((int64_t)(int32_t)reg_rs1 / (int64_t)(int32_t)reg_rs2);
        else
            reg_rd = (uint64_t)-1;
        pc += 4;
    } else if ((opcode & INST_DIVUW_MASK) == INST_DIVUW) {
        LOG(LOG_INST, "%016llx: divuw r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_DIVUW);
        if ((uint32_t)reg_rs2 != 0)
            reg_rd = SEXT32((uint32_t)reg_rs1 / (uint32_t)reg_rs2);
        else
            reg_rd = (uint64_t)-1;
        pc += 4;
    } else if ((opcode & INST_REMW_MASK) == INST_REMW) {
        LOG(LOG_INST, "%016llx: remw r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_REMW);
        if ((int64_t)(int32_t)reg_rs2 != 0)
            reg_rd = SEXT32((int32_t)reg_rs1 % (int32_t)reg_rs2);
        else
            reg_rd = SEXT32(reg_rs1);
        pc += 4;
    } else if ((opcode & INST_REMUW_MASK) == INST_REMUW) {
        LOG(LOG_INST, "%016llx: remuw r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_REMUW);
        if ((uint32_t)reg_rs2 != 0)
            reg_rd = SEXT32((uint32_t)reg_rs1 % (uint32_t)reg_rs2);
        else
            reg_rd = SEXT32(reg_rs1);
        pc += 4;
    }
    // A Extension
    else if ((opcode & INST_AMOADD_W_MASK) == INST_AMOADD_W) {
        LOG(LOG_INST, "%016llx: amoadd.w r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_ADD);
        INST_STAT(ENUM_INST_LW);
        INST_STAT(ENUM_INST_SW);
        load(pc, reg_rs1, &reg_rd, 4, true);
        uint32_t val = reg_rd + reg_rs2;
        store(pc, reg_rs1, val, 4);
        pc += 4;
    } else if ((opcode & INST_AMOXOR_W_MASK) == INST_AMOXOR_W) {
        LOG(LOG_INST, "%016llx: amoxor.w r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_XOR);
        INST_STAT(ENUM_INST_LW);
        INST_STAT(ENUM_INST_SW);
        load(pc, reg_rs1, &reg_rd, 4, true);
        uint32_t val = reg_rd ^ reg_rs2;
        store(pc, reg_rs1, val, 4);
        pc += 4;
    } else if ((opcode & INST_AMOOR_W_MASK) == INST_AMOOR_W) {
        LOG(LOG_INST, "%016llx: amoor.w r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 4, true);
        uint32_t val = reg_rd | reg_rs2;
        store(pc, reg_rs1, val, 4);
        INST_STAT(ENUM_INST_OR);
        INST_STAT(ENUM_INST_LW);
        INST_STAT(ENUM_INST_SW);
        pc += 4;
    } else if ((opcode & INST_AMOAND_W_MASK) == INST_AMOAND_W) {
        LOG(LOG_INST, "%016llx: amoand.w r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 4, true);
        uint32_t val = reg_rd & reg_rs2;
        store(pc, reg_rs1, val, 4);
        INST_STAT(ENUM_INST_AND);
        INST_STAT(ENUM_INST_LW);
        INST_STAT(ENUM_INST_SW);
        pc += 4;
    } else if ((opcode & INST_AMOMIN_W_MASK) == INST_AMOMIN_W) {
        LOG(LOG_INST, "%016llx: amomin.w r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 4, true);
        uint32_t val = ((int32_t)reg_rd < (int32_t)reg_rs2) ? reg_rd : reg_rs2;
        store(pc, reg_rs1, val, 4);
        INST_STAT(ENUM_INST_LW);
        INST_STAT(ENUM_INST_SW);
        pc += 4;
    } else if ((opcode & INST_AMOMAX_W_MASK) == INST_AMOMAX_W) {
        LOG(LOG_INST, "%016llx: amomax.w r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 4, true);
        uint32_t val = ((int32_t)reg_rd > (int32_t)reg_rs2) ? reg_rd : reg_rs2;
        store(pc, reg_rs1, val, 4);
        INST_STAT(ENUM_INST_LW);
        INST_STAT(ENUM_INST_SW);
        pc += 4;
    } else if ((opcode & INST_AMOMINU_W_MASK) == INST_AMOMINU_W) {
        LOG(LOG_INST, "%016llx: amominu.w r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 4, true);
        uint32_t val =
            ((uint32_t)reg_rd < (uint32_t)reg_rs2) ? reg_rd : reg_rs2;
        store(pc, reg_rs1, val, 4);
        INST_STAT(ENUM_INST_LW);
        INST_STAT(ENUM_INST_SW);
        pc += 4;
    } else if ((opcode & INST_AMOMAXU_W_MASK) == INST_AMOMAXU_W) {
        LOG(LOG_INST, "%016llx: amomaxu.w r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 4, true);
        uint32_t val =
            ((uint32_t)reg_rd > (uint32_t)reg_rs2) ? reg_rd : reg_rs2;
        store(pc, reg_rs1, val, 4);
        INST_STAT(ENUM_INST_LW);
        INST_STAT(ENUM_INST_SW);
        pc += 4;
    } else if ((opcode & INST_AMOSWAP_W_MASK) == INST_AMOSWAP_W) {
        LOG(LOG_INST, "%016llx: amoswap.w r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 4, true);
        store(pc, reg_rs1, reg_rs2, 4);
        INST_STAT(ENUM_INST_LW);
        INST_STAT(ENUM_INST_SW);
        pc += 4;
    } else if ((opcode & INST_LR_W_MASK) == INST_LR_W) {
        LOG(LOG_INST, "%016llx: lr.w r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 4, true);
        // Record load address
        m_load_res = reg_rs1;
        INST_STAT(ENUM_INST_LW);
        pc += 4;
    } else if ((opcode & INST_SC_W_MASK) == INST_SC_W) {
        LOG(LOG_INST, "%016llx: sc.w r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        if (m_load_res == reg_rs1) {
            store(pc, reg_rs1, reg_rs2, 4);
            reg_rd = 0;
        } else {
            reg_rd = 1;
        }
        m_load_res = 0;
        INST_STAT(ENUM_INST_SW);
        pc += 4;
    } else if ((opcode & INST_AMOADD_D_MASK) == INST_AMOADD_D) {
        LOG(LOG_INST, "%016llx: amoadd.w r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 8, true);
        uint64_t val = reg_rd + reg_rs2;
        store(pc, reg_rs1, val, 8);
        INST_STAT(ENUM_INST_ADD);
        INST_STAT(ENUM_INST_LD);
        INST_STAT(ENUM_INST_SD);
        pc += 4;
    } else if ((opcode & INST_AMOXOR_D_MASK) == INST_AMOXOR_D) {
        LOG(LOG_INST, "%016llx: amoxor.d r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 8, true);
        uint64_t val = reg_rd ^ reg_rs2;
        store(pc, reg_rs1, val, 8);
        INST_STAT(ENUM_INST_XOR);
        INST_STAT(ENUM_INST_LD);
        INST_STAT(ENUM_INST_SD);
        pc += 4;
    } else if ((opcode & INST_AMOOR_D_MASK) == INST_AMOOR_D) {
        LOG(LOG_INST, "%016llx: amoor.d r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 8, true);
        uint64_t val = reg_rd | reg_rs2;
        store(pc, reg_rs1, val, 8);
        INST_STAT(ENUM_INST_OR);
        INST_STAT(ENUM_INST_LD);
        INST_STAT(ENUM_INST_SD);
        pc += 4;
    } else if ((opcode & INST_AMOAND_D_MASK) == INST_AMOAND_D) {
        LOG(LOG_INST, "%016llx: amoand.d r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 8, true);
        uint64_t val = reg_rd & reg_rs2;
        store(pc, reg_rs1, val, 8);
        INST_STAT(ENUM_INST_AND);
        INST_STAT(ENUM_INST_LD);
        INST_STAT(ENUM_INST_SD);
        pc += 4;
    } else if ((opcode & INST_AMOMIN_D_MASK) == INST_AMOMIN_D) {
        LOG(LOG_INST, "%016llx: amomin.d r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 8, true);
        uint64_t val = reg_rs2;
        if ((int64_t)reg_rd < (int64_t)reg_rs2)
            val = reg_rd;
        store(pc, reg_rs1, val, 8);
        INST_STAT(ENUM_INST_LD);
        INST_STAT(ENUM_INST_SD);
        pc += 4;
    } else if ((opcode & INST_AMOMAX_D_MASK) == INST_AMOMAX_D) {
        LOG(LOG_INST, "%016llx: amomax.d r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 8, true);
        uint64_t val = reg_rs2;
        if ((int64_t)reg_rd > (int64_t)reg_rs2)
            val = reg_rd;
        store(pc, reg_rs1, val, 8);
        INST_STAT(ENUM_INST_LD);
        INST_STAT(ENUM_INST_SD);
        pc += 4;
    } else if ((opcode & INST_AMOMINU_D_MASK) == INST_AMOMINU_D) {
        LOG(LOG_INST, "%016llx: amominu.d r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 8, true);
        uint64_t val = reg_rs2;
        if ((uint64_t)reg_rd < (uint64_t)reg_rs2)
            val = reg_rd;
        store(pc, reg_rs1, val, 8);
        INST_STAT(ENUM_INST_LD);
        INST_STAT(ENUM_INST_SD);
        pc += 4;
    } else if ((opcode & INST_AMOMAXU_D_MASK) == INST_AMOMAXU_D) {
        LOG(LOG_INST, "%016llx: amomaxu.d r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 8, true);
        uint64_t val = reg_rs2;
        if ((uint64_t)reg_rd > (uint64_t)reg_rs2)
            val = reg_rd;
        store(pc, reg_rs1, val, 8);
        INST_STAT(ENUM_INST_LD);
        INST_STAT(ENUM_INST_SD);
        pc += 4;
    } else if ((opcode & INST_AMOSWAP_D_MASK) == INST_AMOSWAP_D) {
        LOG(LOG_INST, "%016llx: amoswap.d r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 8, true);
        store(pc, reg_rs1, reg_rs2, 8);
        INST_STAT(ENUM_INST_LD);
        INST_STAT(ENUM_INST_SD);
        pc += 4;
    } else if ((opcode & INST_LR_D_MASK) == INST_LR_D) {
        LOG(LOG_INST, "%016llx: lr.d r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        load(pc, reg_rs1, &reg_rd, 8, true);
        // Record load address
        m_load_res = reg_rs1;
        INST_STAT(ENUM_INST_LD);
        pc += 4;
    } else if ((opcode & INST_SC_D_MASK) == INST_SC_D) {
        LOG(LOG_INST, "%016llx: sc.d r%d, r%d, r%d\n", pc, rd, rs1, rs2);
        INST_STAT(ENUM_INST_SD);
        if (m_load_res == reg_rs1) {
            store(pc, reg_rs1, reg_rs2, 8);
            reg_rd = 0;
        } else {
            reg_rd = 1;
        }
        m_load_res = 0;
        pc += 4;
    }
    // C Extension
    // RVC - Quadrant 0
    else if ((opcode & 3) == 0) {
        opcode &= 0xFFFF;
        rs1     = RVC_rs1s(opcode);
        rs2     = RVC_rs2s(opcode);
        rd      = rs2;
        reg_rs1 = m_gpr[rs1];
        reg_rs2 = m_gpr[rs2];

        if ((opcode >> 13) == 0 && opcode != 0) {
            rs1     = RISCV_REG_SP;
            reg_rs1 = m_gpr[rs1];

            uint64_t imm = RVC_addi4spn_imm(opcode);
            LOG(LOG_INST, "%016llx: c.addi4spn r%d,r%d,%d\n", pc, rd, rs1, imm);
            INST_STAT(ENUM_INST_ADDI);
            reg_rd = reg_rs1 + imm;
            pc += 2;
        } else if ((opcode >> 13) == 2) {
            uint64_t imm = RVC_lw_imm(opcode);
            LOG(LOG_INST, "%016llx: c.lw r%d, %d(r%d)\n", pc, rd, imm, rs1);
            INST_STAT(ENUM_INST_LW);
            if (load(pc, reg_rs1 + imm, &reg_rd, 4, true))
                pc += 2;
            else
                return false;
        } else if ((opcode >> 13) == 3) {
            uint64_t imm = RVC_ld_imm(opcode);
            LOG(LOG_INST, "%016llx: c.ld r%d, %d(r%d)\n", pc, rd, imm, rs1);
            INST_STAT(ENUM_INST_LD);
            if (load(pc, reg_rs1 + imm, &reg_rd, 8, true))
                pc += 2;
            else
                return false;
        } else if ((opcode >> 13) == 6) {
            uint64_t imm = RVC_lw_imm(opcode);
            LOG(LOG_INST, "%016llx: c.sw %d(r%d), r%d\n", pc, imm, rs1, rd);
            INST_STAT(ENUM_INST_SW);
            if (store(pc, reg_rs1 + imm, reg_rs2, 4))
                pc += 2;
            else
                return false;

            // No writeback
            rd = 0;
        } else if ((opcode >> 13) == 7) {
            uint64_t imm = RVC_ld_imm(opcode);
            LOG(LOG_INST, "%016llx: c.sd %d(r%d), r%d\n", pc, imm, rs1, rd);
            INST_STAT(ENUM_INST_SD);
            if (store(pc, reg_rs1 + imm, reg_rs2, 8))
                pc += 2;
            else
                return false;
            // No writeback
            rd = 0;
        }
        // Illegal instruction
        else {
            error(false, "Bad instruction @ %x (opcode %x)\n", pc, opcode);
            exception(MCAUSE_ILLEGAL_INSTRUCTION, pc, opcode);
            m_fault        = true;
            take_exception = true;
        }
    } else if (((opcode & 3) == 1) &&
               (((opcode & 0xFFFF) >> 13) <
                4)) { // RVC - Quadrant 1 (top half - c.nop - c.lui)
        opcode &= 0xFFFF;
        rs1     = RVC_rs1(opcode);
        rs2     = RVC_rs2(opcode);
        rd      = rs1;
        reg_rs1 = m_gpr[rs1];
        reg_rs2 = m_gpr[rs2];

        if ((opcode >> 13) == 0 && opcode == 0) {
            LOG(LOG_INST, "%016llx: c.nop\n", pc);
            INST_STAT(ENUM_INST_ADDI);
            pc += 2;
        } else if ((opcode >> 13) == 0) {
            int64_t imm = RVC_imm(opcode);
            LOG(LOG_INST, "%016llx: c.addi r%d, %d\n", pc, rs1, imm);
            INST_STAT(ENUM_INST_ADDI);
            reg_rd = reg_rs1 + imm;
            pc += 2;
        } else if ((opcode >> 13) == 1) {
            int64_t imm = RVC_imm(opcode);
            LOG(LOG_INST, "%016llx: c.addiw r%d, %d\n", pc, rs1, imm);
            INST_STAT(ENUM_INST_ADDIW);
            reg_rd = SEXT32(reg_rs1 + imm);
            pc += 2;
        } else if ((opcode >> 13) == 2) {
            uint64_t imm = RVC_imm(opcode);
            LOG(LOG_INST, "%016llx: c.li r%d, %d\n", pc, rd, imm);
            INST_STAT(ENUM_INST_LUI);
            reg_rd = imm;
            pc += 2;
        } else if ((opcode >> 13) == 3 && ((opcode >> 7) & 0x1f) == 2) {
            uint64_t imm = RVC_addi16sp_imm(opcode);
            rd           = RISCV_REG_SP;
            rs1          = RISCV_REG_SP;
            reg_rs1      = m_gpr[rs1];
            LOG(LOG_INST, "%016llx: c.addi16sp r%d, r%d, %d\n", pc, rd, rs1,
                imm);
            INST_STAT(ENUM_INST_ADDI);
            reg_rd = reg_rs1 + imm;
            pc += 2;
        } else if ((opcode >> 13) == 3) {
            uint64_t imm = RVC_imm(opcode) << 12;
            LOG(LOG_INST, "%016llx: c.lui r%d, 0x%x\n", pc, rd, imm);
            INST_STAT(ENUM_INST_LUI);
            reg_rd = imm;
            pc += 2;
        }
        // Illegal instruction
        else {
            error(false, "Bad instruction @ %x (opcode %x)\n", pc, opcode);
            exception(MCAUSE_ILLEGAL_INSTRUCTION, pc, opcode);
            m_fault        = true;
            take_exception = true;
        }
    } else if ((opcode & 3) == 1) { // RVC - Quadrant 1 (bottom half - c.srli -)
        opcode &= 0xFFFF;
        rs1     = RVC_rs1s(opcode);
        rs2     = RVC_rs2s(opcode);
        rd      = rs1;
        reg_rs1 = m_gpr[rs1];
        reg_rs2 = m_gpr[rs2];

        if ((opcode >> 13) == 4 && ((opcode >> 10) & 0x3) == 0) {
            uint64_t imm = RVC_zimm(opcode);
            LOG(LOG_INST, "%016llx: c.srli r%d, %d\n", pc, rd, imm);
            INST_STAT(ENUM_INST_SRLI);
            reg_rd = (uint64_t)reg_rs1 >> imm;
            pc += 2;
        } else if ((opcode >> 13) == 4 && ((opcode >> 10) & 0x3) == 1) {
            uint64_t imm = RVC_zimm(opcode);
            LOG(LOG_INST, "%016llx: c.srai r%d, %d\n", pc, rd, imm);
            INST_STAT(ENUM_INST_SRAI);
            reg_rd = (int64_t)reg_rs1 >> imm;
            pc += 2;
        } else if ((opcode >> 13) == 4 && ((opcode >> 10) & 0x3) == 2) {
            uint64_t imm = RVC_imm(opcode);
            LOG(LOG_INST, "%016llx: c.andi r%d, 0x%08x\n", pc, rd, imm);
            INST_STAT(ENUM_INST_ANDI);
            reg_rd = reg_rs1 & imm;
            pc += 2;
        } else if ((opcode >> 13) == 4 && ((opcode >> 10) & 0x7) == 3 &&
                   ((opcode >> 5) & 0x3) == 0) {
            LOG(LOG_INST, "%016llx: c.sub r%d, r%d\n", pc, rs1, rs2);
            INST_STAT(ENUM_INST_SUB);
            reg_rd = (int64_t)(reg_rs1 - reg_rs2);
            pc += 2;
        } else if ((opcode >> 13) == 4 && ((opcode >> 10) & 0x7) == 3 &&
                   ((opcode >> 5) & 0x3) == 1) {
            LOG(LOG_INST, "%016llx: c.xor r%d, r%d\n", pc, rs1, rs2);
            INST_STAT(ENUM_INST_XOR);
            reg_rd = reg_rs1 ^ reg_rs2;
            pc += 2;
        } else if ((opcode >> 13) == 4 && ((opcode >> 10) & 0x7) == 3 &&
                   ((opcode >> 5) & 0x3) == 2) {
            LOG(LOG_INST, "%016llx: c.or r%d, r%d\n", pc, rs1, rs2);
            INST_STAT(ENUM_INST_OR);
            reg_rd = reg_rs1 | reg_rs2;
            pc += 2;
        } else if ((opcode >> 13) == 4 && ((opcode >> 10) & 0x7) == 3 &&
                   ((opcode >> 5) & 0x3) == 3) {
            LOG(LOG_INST, "%016llx: c.and r%d, r%d\n", pc, rs1, rs2);
            INST_STAT(ENUM_INST_AND);
            reg_rd = reg_rs1 & reg_rs2;
            pc += 2;
        } else if ((opcode >> 13) == 4 && ((opcode >> 10) & 0x7) == 7 &&
                   ((opcode >> 5) & 0x3) == 0) {
            LOG(LOG_INST, "%016llx: c.subw r%d, r%d\n", pc, rs1, rs2);
            INST_STAT(ENUM_INST_SUBW);
            reg_rd = SEXT32(reg_rs1 - reg_rs2);
            pc += 2;
        } else if ((opcode >> 13) == 4 && ((opcode >> 10) & 0x7) == 7 &&
                   ((opcode >> 5) & 0x3) == 1) {
            LOG(LOG_INST, "%016llx: c.addw r%d, r%d, r%d\n", pc, rd, rs1, rs2);
            INST_STAT(ENUM_INST_ADDW);
            reg_rd = SEXT32(reg_rs1 + reg_rs2);
            pc += 2;
        } else if ((opcode >> 13) == 5) {
            uint64_t imm = RVC_j_imm(opcode);
            LOG(LOG_INST, "%016llx: c.j 0x%08x\n", pc, pc + imm);
            INST_STAT(ENUM_INST_J);
            pc += imm;
            rd = 0;
        } else if ((opcode >> 13) == 6) {
            uint64_t imm = RVC_b_imm(opcode);
            LOG(LOG_INST, "%016llx: c.beqz r%d, %d\n", pc, rs1, imm);
            INST_STAT(ENUM_INST_BEQ);
            bool take_branch = (reg_rs1 == 0);
            if (take_branch)
                pc += imm;
            else
                pc += 2;
            rd = 0;
        } else if ((opcode >> 13) == 7) {
            uint64_t imm = RVC_b_imm(opcode);
            LOG(LOG_INST, "%016llx: c.bnez r%d, %d\n", pc, rs1, imm);
            INST_STAT(ENUM_INST_BNE);
            bool take_branch = (reg_rs1 != 0);
            if (take_branch)
                pc += imm;
            else
                pc += 2;
            rd = 0;
        }
        // Illegal instruction
        else {
            error(false, "Bad instruction @ %x (opcode %x)\n", pc, opcode);
            exception(MCAUSE_ILLEGAL_INSTRUCTION, pc, opcode);
            m_fault        = true;
            take_exception = true;
        }
    } else if ((opcode & 3) == 2) { // RVC - Quadrant 2
        opcode &= 0xFFFF;
        rs1     = RVC_rs1(opcode);
        rs2     = RVC_rs2(opcode);
        rd      = rs1;
        reg_rs1 = m_gpr[rs1];
        reg_rs2 = m_gpr[rs2];

        if ((opcode >> 13) == 0) {
            uint64_t imm = RVC_zimm(opcode);
            LOG(LOG_INST, "%016llx: c.slli r%d, %d\n", pc, rs1, imm);
            INST_STAT(ENUM_INST_SLLI);
            reg_rd = reg_rs1 << imm;
            pc += 2;
        } else if ((opcode >> 13) == 2) {
            uint64_t imm = RVC_lwsp_imm(opcode);
            rs1          = RISCV_REG_SP;
            reg_rs1      = m_gpr[rs1];

            LOG(LOG_INST, "%016llx: c.lwsp r%d, %d(r%d)\n", pc, rd, imm, rs1);
            INST_STAT(ENUM_INST_LW);
            if (load(pc, reg_rs1 + imm, &reg_rd, 4, true))
                pc += 2;
            else
                return false;
        } else if ((opcode >> 13) == 3) {
            uint64_t imm = RVC_ldsp_imm(opcode);
            rs1          = RISCV_REG_SP;
            reg_rs1      = m_gpr[rs1];

            LOG(LOG_INST, "%016llx: c.ldsp r%d, %d(r%d)\n", pc, rd, imm, rs1);
            INST_STAT(ENUM_INST_LW);
            if (load(pc, reg_rs1 + imm, &reg_rd, 8, true))
                pc += 2;
            else
                return false;
        } else if ((opcode >> 13) == 4) {
            if (!(opcode & (1 << 12))) {
                if (((opcode >> 2) & 0x1F) == 0) {
                    rd = 0;
                    LOG(LOG_INST, "%016llx: c.jr r%d\n", pc, rs1);
                    INST_STAT(ENUM_INST_J);
                    pc = reg_rs1 & ~1;
                } else {
                    LOG(LOG_INST, "%016llx: c.mv r%d, r%d\n", pc, rd, rs2);
                    INST_STAT(ENUM_INST_ADD);
                    pc += 2;
                    reg_rd = reg_rs2;
                }
            } else {
                if (((opcode >> 7) & 0x1F) == 0 &&
                    ((opcode >> 2) & 0x1F) == 0) {
                    rd = 0;
                    LOG(LOG_INST, "%016llx: c.ebreak\n", pc);
                    INST_STAT(ENUM_INST_EBREAK);
                    exception(MCAUSE_BREAKPOINT, pc, 0);
                    take_exception = true;
                    m_break        = true;
                } else if (((opcode >> 2) & 0x1F) == 0) {
                    rd = RISCV_REG_RA;
                    LOG(LOG_INST, "%016llx: c.jalr r%d, r%d\n", pc, rd, rs1);
                    INST_STAT(ENUM_INST_JALR);
                    reg_rd = pc + 2;
                    pc     = reg_rs1 & ~1;
                } else {
                    LOG(LOG_INST, "%016llx: c.add r%d, r%d, r%d\n", pc, rd, rs1,
                        rs2);
                    INST_STAT(ENUM_INST_ADD);
                    reg_rd = reg_rs1 + reg_rs2;
                    pc += 2;
                }
            }
        } else if ((opcode >> 13) == 6) {
            uint64_t uimm = RVC_swsp_imm(opcode);
            rs1           = RISCV_REG_SP;
            reg_rs1       = m_gpr[rs1];
            LOG(LOG_INST, "%016llx: c.swsp r%d, %d(r%d)\n", pc, rs2, uimm, rs1);
            INST_STAT(ENUM_INST_SW);

            if (store(pc, reg_rs1 + uimm, reg_rs2, 4))
                pc += 2;
            else
                return false;

            // No writeback
            rd = 0;
        } else if ((opcode >> 13) == 7) {
            uint64_t uimm = RVC_sdsp_imm(opcode);
            rs1           = RISCV_REG_SP;
            reg_rs1       = m_gpr[rs1];
            LOG(LOG_INST, "%016llx: c.sdsp r%d, %d(r%d)\n", pc, rs2, uimm, rs1);
            INST_STAT(ENUM_INST_SW);

            if (store(pc, reg_rs1 + uimm, reg_rs2, 8))
                pc += 2;
            else
                return false;

            // No writeback
            rd = 0;
        }
        // Illegal instruction
        else {
            error(false, "Bad instruction @ %x (opcode %x)\n", pc, opcode);
            exception(MCAUSE_ILLEGAL_INSTRUCTION, pc, opcode);
            m_fault        = true;
            take_exception = true;
        }
    } else {
        exception(MCAUSE_ILLEGAL_INSTRUCTION, pc, opcode);
        take_exception = true;
    }

    /********************** WB **********************/
    if (rd != 0 && !take_exception)
        m_gpr[rd] = reg_rd;

    // Pending interrupt
    if (!take_exception && (m_csr_mip & m_csr_mie)) {
        uint64_t pending_interrupts = (m_csr_mip & m_csr_mie);
        uint64_t m_enabled =
            m_csr_mpriv < PRIV_MACHINE ||
            (m_csr_mpriv == PRIV_MACHINE && (m_csr_msr & SR_MIE));
        uint64_t s_enabled =
            m_csr_mpriv < PRIV_SUPER ||
            (m_csr_mpriv == PRIV_SUPER && (m_csr_msr & SR_SIE));
        uint64_t m_interrupts =
            pending_interrupts & ~m_csr_mideleg & -m_enabled;
        uint64_t s_interrupts = pending_interrupts & m_csr_mideleg & -s_enabled;
        uint64_t interrupts   = m_interrupts ? m_interrupts : s_interrupts;

        // Interrupt pending and mask enabled
        if (interrupts) {
            LOG(LOG_ARCH, "Take Interrupt...: %08x\n", interrupts);
            int i;
            for (i = IRQ_MIN; i < IRQ_MAX; i++) {
                if (interrupts & (1 << i)) {
                    // Only service one interrupt per cycle
                    LOG(LOG_ARCH, "Interrupt%d taken...\n", i);
                    exception(MCAUSE_INTERRUPT + i, pc, 0);
                    take_exception = true;
                    break;
                }
            }
        }
    }

    if (!take_exception)
        m_pc = pc;

    return true;
}

////////////////////////////////////////////////////////////////////////////////
// step: Step through one instruction
////////////////////////////////////////////////////////////////////////////////

void kloug_step(void) {
    // Execute instruction at current PC
    int max_steps = 2;
    while (max_steps-- && !execute()) {
    }
    // Increment instructions-retired counter
    m_csr_minstret++;
    // Increment timer counter
    m_csr_mtime++;
    // Non-std: Timer should generate an internal interrupt?
    if (m_enable_mtimecmp) {
        if (m_csr_mtime == m_csr_mtimecmp && m_csr_mtime_ie) {
            m_csr_mip |= SR_IP_MTIP;
            m_csr_mtime_ie = false;
        }
    }

    // Dump state
    if (TRACE_ENABLED(LOG_REGISTERS)) {
        // Register trace
        int i;
        for (i = 0; i < REGISTERS; i += 4) {
            LOG(LOG_REGISTERS, " %2d: ", i);
            LOG(LOG_REGISTERS, " %016lx %016lx %016lx %016lx\n", m_gpr[i + 0],
                m_gpr[i + 1], m_gpr[i + 2], m_gpr[i + 3]);
        }
    }
}