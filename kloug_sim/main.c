#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EI_MAG0       0x00
#define EI_MAG1       0x01
#define EI_MAG2       0x02
#define EI_MAG3       0x03
#define EI_CLASS      0x04
#define EI_DATA       0x05
#define EI_VERSION    0x06
#define EI_OSABI      0x07
#define EI_ABIVERSION 0x08
#define EI_PAD        0x09

#define ET_NONE 0x00 /* Unknown. */
#define ET_REL  0x01 /* Relocatable file */
#define ET_EXEC 0x02 /* Executable file. */
#define ET_DYN  0x03 /* Shared object. */
#define ET_CORE 0x04 /* Core file. */
#define ET_LOOS \
    0xFE00 /* Reserved inclusive range. Operating system specific. */
#define ET_HIOS   0xFEFF /* */
#define ET_LOPROC 0xFF00 /* Reserved inclusive range. Processor specific. */
#define ET_HIPROC 0xFFFF

#define SHT_NULL          0x0
#define SHT_PROGBITS      0x1
#define SHT_SYMTAB        0x2
#define SHT_STRTAB        0x3
#define SHT_RELA          0x4
#define SHT_HASH          0x5
#define SHT_DYNAMIC       0x6
#define SHT_NOTE          0x7
#define SHT_NOBITS        0x8
#define SHT_REL           0x9
#define SHT_SHLIB         0x0A
#define SHT_DYNSYM        0x0B
#define SHT_INIT_ARRAY    0x0E
#define SHT_FINI_ARRAY    0x0F
#define SHT_PREINIT_ARRAY 0x10
#define SHT_GROUP         0x11
#define SHT_SYMTAB_SHNDX  0x12
#define SHT_NUM           0x13

#define MAX(a, b) ((a) > (b) ? (a) : (b))

struct elf_t {
    uint8_t                     *fcontent;
    struct elf_header_t         *header;
    struct elf_program_header_t *phent;
    struct elf_section_header_t *shent;
};

typedef struct elf_t elf_t;

struct elf_header_t {
    uint8_t  e_ident[10];
    uint16_t e_type;    /* Identifies object file type. */
    uint16_t e_machine; /* Specifies target instruction set architecture. */
    uint32_t e_version; /* Set to 1 for the original version of ELF. */
    uint64_t e_entry;  /* entry point from where the process starts executing */
    uint64_t e_phoff;  /* Points to the start of the program header table. */
    uint64_t e_shoff;  /* Points to the start of the section header table. */
    uint32_t e_flags;  /* Interpretation of this field depends on the target
                          architecture. */
    uint16_t e_ehsize; /* Contains the size of this header, normally 64 Bytes
                          for 64-bit and 52 Bytes for 32-bit format. */
    uint16_t
        e_phentsize;  /* Contains the size of a program header table entry. */
    uint16_t e_phnum; /* Contains the number of entries in the program header
                         table. */
    uint16_t
        e_shentsize;  /* Contains the size of a section header table entry. */
    uint16_t e_shnum; /* Contains the number of entries in the section header
                         table. */
    uint16_t e_shstrndx; /* Contains index of the section header table entry
                            that contains the section names. */
};

struct elf_program_header_t {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

struct elf_section_header_t {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct elf_sim_t {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

#define ST_BIND(info)       ((info) >> 4)
#define ST_TYPE(info)       ((info)&0xf)
#define ST_INFO(bind, type) (((bind) << 4) + ((type)&0xf))

#define STT_NOTYPE         0
#define STT_OBJECT         1
#define STT_FUNC           2
#define STT_SECTION        3
#define STT_FILE           4
#define STT_COMMON         5
#define STT_LOOS           10
#define STT_HIOS           12
#define STT_LOPROC         13
#define STT_SPARC_REGISTER 13
#define STT_HIPROC         15

const char *STT_TO_STRING[] = {
    [STT_NOTYPE] = "NOTYPE", [STT_OBJECT] = "OBJECT",
    [STT_FUNC] = "FUNC",     [STT_SECTION] = "SECTION",
    [STT_FILE] = "FILE",     [STT_COMMON] = "COMMON",
    [STT_LOOS] = "LOOS",     [STT_HIOS] = "HIOS",
    [STT_LOPROC] = "LOPROC", [STT_SPARC_REGISTER] = "SPARC_REGISTER",
    [STT_HIPROC] = "HIPROC"};

#ifdef TODO
// ELF API
uint16_t elf_addr_get_section_index(struct elf_t elf, uint64_t addr);
uint16_t elf_addr_get_program_index(struct elf_t elf, uint64_t addr);
void     elf_addr_debug(struct elf_t elf, uint64_t addr);
// char elf_addr_is_r(uint64_t addr);
char elf_addr_is_w(struct elf_t elf, uint64_t addr);
// Memory interface
uint8_t mem_read(uint64_t addr);
void    mem_write(uint64_t addr);
#endif

struct elf_t *elf_from_file(char *filename) {
    // Open file
    FILE *fp = fopen(filename, "r");
    assert(fp);
    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    // Allocations

    elf_t *elf = malloc(sizeof(elf_t));
    assert(elf);
    elf->fcontent = malloc(size);
    assert(elf->fcontent);
    fread(elf->fcontent, 1, size, fp);
    // header
    elf->header = (struct elf_header_t *)elf->fcontent;
    assert(elf->header->e_ident[EI_MAG0] == 0x7F);
    assert(elf->header->e_ident[EI_MAG1] == 'E');
    assert(elf->header->e_ident[EI_MAG2] == 'L');
    assert(elf->header->e_ident[EI_MAG3] == 'F');
    assert(elf->header->e_ident[EI_CLASS] == 2); // 64 bits
    assert(elf->header->e_ident[EI_DATA] == 1);  // Little endian
    assert(elf->header->e_ident[EI_VERSION] == 1);

    // program header
    assert(sizeof(struct elf_program_header_t) == elf->header->e_phentsize);
    elf->phent =
        (struct elf_program_header_t *)(elf->fcontent + elf->header->e_phoff);

    // section header
    assert(sizeof(struct elf_section_header_t) == elf->header->e_shentsize);
    elf->shent =
        (struct elf_section_header_t *)(elf->fcontent + elf->header->e_shoff);

    return elf;
}

char *elf_get_name(elf_t *elf, uint64_t s_name) {
    return (char *)elf->fcontent +
           ((uint64_t)elf->shent[elf->header->e_shstrndx].sh_offset + s_name);
}

void elf_display(elf_t *elf) {
    printf("%c%c%c\n", elf->header->e_ident[EI_MAG1],
           elf->header->e_ident[EI_MAG2], elf->header->e_ident[EI_MAG3]);
    printf("EI_CLASS        %d\n", elf->header->e_ident[EI_CLASS]);
    printf("EI_DATA         %d\n", elf->header->e_ident[EI_DATA]);
    printf("EI_VERSION      %d\n", elf->header->e_ident[EI_VERSION]);
    printf("EI_OSABI        %d\n", elf->header->e_ident[EI_OSABI]);
    printf("EI_ABIVERSION   %d\n", elf->header->e_ident[EI_ABIVERSION]);
    printf("EI_PAD          %d\n", elf->header->e_ident[EI_PAD]);

    printf("e_type          %x\n", elf->header->e_type);
    printf("e_machine       %x\n", elf->header->e_machine);
    printf("e_version       %x\n", elf->header->e_version);
    printf("e_entry         %x\n", elf->header->e_entry);
    printf("e_phoff         %x\n", elf->header->e_phoff);
    printf("e_shoff         %x\n", elf->header->e_shoff);
    printf("e_flags         %x\n", elf->header->e_flags);
    printf("e_ehsize        %x\n", elf->header->e_ehsize);
    printf("e_phentsize     %x\n", elf->header->e_phentsize);
    printf("e_phnum         %x\n", elf->header->e_phnum);
    printf("e_shentsize     %x\n", elf->header->e_shentsize);
    printf("e_shnum         %x\n", elf->header->e_shnum);
    printf("e_shstrndx      %x\n", elf->header->e_shstrndx);

    for (uint16_t e_phnum_i = 0; e_phnum_i < elf->header->e_phnum;
         e_phnum_i++) {
        printf("------------------------ program %d\n", e_phnum_i);
        printf("[%d]p_type   %x\n", e_phnum_i, elf->phent[e_phnum_i].p_type);
        printf("[%d]p_flags  %x\n", e_phnum_i, elf->phent[e_phnum_i].p_flags);
        printf("[%d]p_offset %x\n", e_phnum_i, elf->phent[e_phnum_i].p_offset);
        printf("[%d]p_vaddr  %x\n", e_phnum_i, elf->phent[e_phnum_i].p_vaddr);
        printf("[%d]p_paddr  %x\n", e_phnum_i, elf->phent[e_phnum_i].p_paddr);
        printf("[%d]p_filesz %x\n", e_phnum_i, elf->phent[e_phnum_i].p_filesz);
        printf("[%d]p_memsz  %x\n", e_phnum_i, elf->phent[e_phnum_i].p_memsz);
        printf("[%d]p_align  %x\n", e_phnum_i, elf->phent[e_phnum_i].p_align);
    }

    for (uint16_t e_shnum_i = 0; e_shnum_i < elf->header->e_shnum;
         e_shnum_i++) {
        uint32_t name_off = elf->shent[elf->header->e_shstrndx].sh_offset +
                            elf->shent[e_shnum_i].sh_name;
        printf("------------------------ section %s\n",
               elf->fcontent + name_off);
        printf("[%d]sh_name         %x\n", e_shnum_i,
               elf->shent[e_shnum_i].sh_name);
        printf("[%d]sh_type         %x\n", e_shnum_i,
               elf->shent[e_shnum_i].sh_type);
        printf("[%d]sh_flags        %x\n", e_shnum_i,
               elf->shent[e_shnum_i].sh_flags);
        printf("[%d]sh_addr         %x\n", e_shnum_i,
               elf->shent[e_shnum_i].sh_addr);
        printf("[%d]sh_offset       %x\n", e_shnum_i,
               elf->shent[e_shnum_i].sh_offset);
        printf("[%d]sh_size         %x\n", e_shnum_i,
               elf->shent[e_shnum_i].sh_size);
        printf("[%d]sh_link         %x\n", e_shnum_i,
               elf->shent[e_shnum_i].sh_link);
        printf("[%d]sh_info         %x\n", e_shnum_i,
               elf->shent[e_shnum_i].sh_info);
        printf("[%d]sh_addralign    %x\n", e_shnum_i,
               elf->shent[e_shnum_i].sh_addralign);
        printf("[%d]sh_entsize      %x\n", e_shnum_i,
               elf->shent[e_shnum_i].sh_entsize);
    }

    uint64_t symtab = 0, shstrtab = 0, strtab = 0;
    for (uint16_t e_shnum_i = 0; e_shnum_i < elf->header->e_shnum;
         e_shnum_i++) {
        uint32_t name_off = elf->shent[elf->header->e_shstrndx].sh_offset +
                            elf->shent[e_shnum_i].sh_name;
        char *section_name = (char *)elf->fcontent + name_off;
        if (strcmp(section_name, ".symtab") == 0) {
            symtab = elf->shent[e_shnum_i].sh_offset;
        }
        if (strcmp(section_name, ".shstrtab") == 0) {
            shstrtab = elf->shent[e_shnum_i].sh_offset;
        }
        if (strcmp(section_name, ".strtab") == 0) {
            assert(strtab == 0);
            strtab = elf->shent[e_shnum_i].sh_offset;
        }
    }

    uint64_t shstrtab_e = elf->shent[elf->header->e_shstrndx].sh_offset;
    printf(".symtab     is @ %x\n", symtab);
    printf(".shstrtab   is @ %x\n", shstrtab);
    printf(".strtab     is @ %x\n", strtab);
    printf(".shstrtab e is @ %x\n", shstrtab_e);
    assert(strtab != 0);
    assert(shstrtab == shstrtab_e);

    for (uint16_t e_shnum_i = 0; e_shnum_i < elf->header->e_shnum;
         e_shnum_i++) {
        if (elf->shent[e_shnum_i].sh_type == SHT_SYMTAB) {
            uint32_t name_off = elf->shent[elf->header->e_shstrndx].sh_offset +
                                elf->shent[e_shnum_i].sh_name;
            uint32_t count =
                elf->shent[e_shnum_i].sh_size / sizeof(struct elf_sim_t);
            printf("Symbol table [%s] # %d\n", elf->fcontent + name_off, count);
            for (uint32_t i = 0; i < count; i++) {
                struct elf_sim_t *sim =
                    (struct elf_sim_t *)(elf->fcontent +
                                         elf->shent[e_shnum_i].sh_offset) +
                    i;
                char       *sym_name = elf->fcontent + strtab + sim->st_name;
                const char *sym_type_name =
                    STT_TO_STRING[ST_TYPE(sim->st_info)];
                // printf("%d -> st_name %x\n", i, sim->st_name);
                // printf("%d -> st_info %x -> %s\n", i, sim->st_info,
                // STT_TO_STRING[ST_TYPE(sim->st_info)]); printf("%d -> st_other
                // %x\n", i, sim->st_other); printf("%d -> st_shndx %x\n", i,
                // sim->st_shndx); printf("%d -> st_value %x\n", i,
                // sim->st_value);
                // printf("%d -> st_size %x\n", i, sim->st_size);
                printf("- (%10s) %20s = %x\n", sym_type_name, sym_name,
                       sim->st_value);
            }
        }
    }
}

uint8_t elf_to_memory(elf_t *elf, uint8_t **memimage, uint64_t *memimage_size,
                      char *filename) {
    printf("elf_to_memory...\n");
    uint64_t base_addr, end_addr = 0;
    for (uint16_t e_phnum_i = 0; e_phnum_i < elf->header->e_phnum;
         e_phnum_i++) {
        if (elf->phent[e_phnum_i].p_filesz) {
            end_addr = MAX(elf->phent[e_phnum_i].p_vaddr +
                               elf->phent[e_phnum_i].p_filesz,
                           end_addr);
        }
    }
    base_addr      = elf->header->e_entry;
    *memimage_size = end_addr - base_addr;
    printf("image [%8x %8x] # %d\n", base_addr, end_addr, *memimage_size);
    *memimage = calloc(1, *memimage_size);
    for (uint16_t e_phnum_i = 0; e_phnum_i < elf->header->e_phnum;
         e_phnum_i++) {
        if (elf->phent[e_phnum_i].p_filesz) {
            memcpy(*memimage + elf->phent[e_phnum_i].p_vaddr - base_addr,
                   elf->fcontent + elf->phent[e_phnum_i].p_offset,
                   elf->phent[e_phnum_i].p_filesz);
        }
    }
    if (filename) {
        printf("Write %s\n", filename);
        FILE *fp_mem = fopen(filename, "w");
        assert(fp_mem);
        fwrite(*memimage, *memimage_size, 1, fp_mem);
        fclose(fp_mem);
    }
    return 0;
}

uint64_t elf_get_entry(elf_t *elf) { return elf->header->e_entry; }

// 64k
#define MEM_SIZE (64 * 1024)

#include "kloug.h"

int main(int argc, char *argv[]) {
    assert(argc == 2);
    char *filename = argv[1];
    printf("open %s\n", filename);

    /*
    int size;
    struct stat s;
    int fd = open (argv[1], O_RDONLY);
    int status = fstat (fd, & s);
    int size = s.st_size;
    char *fcontent = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
    */

    struct elf_t *elf = elf_from_file(filename);
    elf_display(elf);
    uint8_t *memimage;
    uint64_t memimage_size;
    elf_to_memory(elf, &memimage, &memimage_size, "todo.mem");
    uint64_t mem_base_addr = elf_get_entry(elf);
    uint64_t pc            = mem_base_addr;
    printf("MEM # = %x entry = %x\n", memimage_size, mem_base_addr);
    
    // Run proc
    kloug_init(NULL);
    printf("Reset ...\n");
    kloug_reset();
    printf("Load image in memory ...\n");
    assert(mem_base_addr == PO_MEM_BASE);
    assert(memimage_size < PO_MEM_SIZE);
    memcpy(kloug_mem_proxy(mem_base_addr), memimage, memimage_size);
    printf("Run ...\n");
// #define getchar() 1
    while (getchar()) {
        kloug_step();
    }
    return 0;
}
