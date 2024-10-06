#include <elf.h>

#ifndef ELF_GENERIC_TYPES_H
#define ELF_GENERIC_TYPES_H

typedef struct elf_ehdr
{
  unsigned char e_ident[EI_NIDENT]; /* ELF "magic number" and other identification */
  Elf64_Half e_type;                /* Object file type */
  Elf64_Half e_machine;             /* Architecture (e.g., x86_64) */
  Elf64_Word e_version;             /* Object file version */
  Elf64_Addr e_entry;               /* Entry point virtual address */
  Elf64_Off e_phoff;                /* Program header table file offset */
  Elf64_Off e_shoff;                /* Section header table file offset */
  Elf64_Word e_flags;               /* Processor-specific flags */
  Elf64_Half e_ehsize;              /* ELF header size in bytes */
  Elf64_Half e_phentsize;           /* Program header table entry size */
  Elf64_Half e_phnum;               /* Number of entries in the program header table */
  Elf64_Half e_shentsize;           /* Section header table entry size */
  Elf64_Half e_shnum;               /* Number of entries in the section header table */
  Elf64_Half e_shstrndx;            /* Section header string table index */
} Elf_Ehdr;

typedef struct elf_phdr
{
  uint32_t p_type;      /* Segment type */
  uint32_t p_flags;     /* Segment flags, I.E execute|read|write */
  Elf64_Off p_offset;   /* Segment offset */
  Elf64_Addr p_vaddr;   /* Segment virtual address */
  Elf64_Addr p_paddr;   /* Segment physical address */
  uint64_t p_filesz;    /* Size of segment in the file */
  uint64_t p_memsz;     /* Size of segment in memory */
  uint64_t p_align;     /* Segment alignment in memory */
} Elf_Phdr;

typedef struct elf_shdr
{
  uint32_t sh_name;     /* offset into shdr string table for shdr name */
  uint32_t sh_type;     /* shdr type I.E SHT_PROGBITS */
  uint64_t sh_flags;    /* shdr flags I.E SHT_WRITE|SHT_ALLOC */
  Elf64_Addr sh_addr;   /* address of where section begins */
  Elf64_Off sh_offset;  /* offset of shdr from beginning of file */
  uint64_t sh_size;     /* size that section takes up on disk */
  uint32_t sh_link;     /* points to another section (depends on the type) */
  uint32_t sh_info;     /* interpretation depends on section type */
  uint64_t sh_addralign;/* alignment for address of section */
  uint64_t sh_entsize;  /* size of each certain entries that may be in section */
} Elf_Shdr;

typedef struct elf_sym
{
  uint32_t st_name;       /* Symbol name (index into string table) */
  unsigned char st_info;  /* Symbol's type and binding attributes */
  unsigned char st_other; /* Symbol visibility */
  uint16_t st_shndx;      /* Section index where the symbol is defined */
  Elf64_Addr st_value;    /* Symbol value (address or absolute value) */
  uint64_t st_size;       /* Symbol size (e.g., size of data or function) */
} Elf_Sym;

typedef struct elf_rel
{
  Elf64_Addr  r_offset; /* Offset of the place to apply the relocation */
  uint64_t    r_info;   /* Relocation type and symbol index */
} Elf_Rel;

typedef struct elf_rela
{
  Elf64_Addr  r_offset; /* Offset of the place to apply the relocation */
  uint64_t    r_info;   /* Relocation type and symbol index */
  int64_t     r_addend; /* Constant addend used to compute the final value */
} Elf_Rela;

typedef struct elf_dyn
{
  Elf64_Sxword  d_tag;   /* Dynamic entry type (e.g., DT_NEEDED, DT_STRTAB) */
  union {
    Elf64_Xword d_val;   /* Integer value */
    Elf64_Addr  d_ptr;   /* Address value */
  } d_un;                /* Union of values: used based on the type of entry */
} Elf_Dyn;

#endif
