#include "elf_generic_types.h"
#include <stdio.h>
#include <string.h>
#include "memory_management.h"
#include "file_management.h"

#ifndef ELF_PARSER_H
#define ELF_PARSER_H


// Some lost defines

// .note.gnu.property notes sections.
#ifndef PT_GNU_PROPERTY
#define PT_GNU_PROPERTY 0x6474e553
#endif

// Fill with random data.
#ifndef PT_OPENBSD_RANDOMIZE
#define PT_OPENBSD_RANDOMIZE 0x65a3dbe6
#endif

// Program does W^X violations.
#ifndef PT_OPENBSD_WXNEEDED
#define PT_OPENBSD_WXNEEDED 0x65a3dbe7
#endif

// Section for boot arguments.
#ifndef PT_OPENBSD_BOOTDATA
#define PT_OPENBSD_BOOTDATA 0x65a41be6
#endif

// ARM program header types.
// Platform architecture compatibility info
#ifndef PT_ARM_ARCHEXT
#define PT_ARM_ARCHEXT 0x70000000
#endif


int parse_elf(const char *pathname);

/***
 * Elf header parsing, useful functions
 * and printing
 */

/**
 * Elf header parsing, the ELF header points to all
 * the other headers in the file, as well as it contains
 * the sizes of these headers (in bytes). At the beginning
 * of the structure we have information about the ELF
 * file, if it is an executable, shared object, for which
 * machine is compiled for, etc.
 * Check `Elf_Ehdr` structure for more information.
 * 
 * @param buf_ptr pointer to the mapped ELF file
 * @param file_size size of the file for checks
 * @return check for errors, 0 if everything was correct, -1 otherwise
 */
int parse_elf_ehdr(uint8_t *buf_ptr, size_t file_size);

/**
 * Check if the binary is a 32 bit binary.
 * 
 * @return 1 if binary is 32 bit binary, 0 if not, -1 if there was an error.
 */
int is_32_bit_binary();

/**
 * Check if the binary is a 64 bit binary.
 * 
 * @return 1 if binary is 64 bit binary, 0 if not, -1 if there was an error.
 */
int is_64_bit_binary();

/**
 * Get the read `Elf_Ehdr` structure.
 * 
 * @return constant pointer to `Elf_Ehdr` structure
 */
const Elf_Ehdr *get_elf_ehdr_read();

void print_elf_ehdr();

/***
 * Elf header
 * Interesting functions for python
 * binding.
 */
int is_magic_elf();
unsigned char e_ident(size_t nident);
Elf64_Addr e_type();
Elf64_Half e_machine();
Elf64_Word e_version();
Elf64_Addr e_entry();
Elf64_Off e_phoff();
Elf64_Off e_shoff();
Elf64_Word e_flags();
Elf64_Half e_ehsize();
Elf64_Half e_phentsize();
Elf64_Half e_phnum();
Elf64_Half e_shentsize();
Elf64_Half e_shnum();
Elf64_Half e_shstrndx();

/***
 * Program header parsing and printing
 */

/**
 * Program header parsing, the program header represents
 * the segments that are loaded in memory, inside of these
 * segments we have the sections, but we do not need these
 * sections in run-time, since that is information for
 * linker, or debuggers, etc.
 * 
 * @param buf_ptr pointer to the elf file on disk
 * @param file_size size of the file for checks
 * @return error code, 0 if everything was well, -1 otherwise
 */
int parse_elf_phdr(uint8_t *buf_ptr, size_t file_size);
void print_elf_phdr();

/***
 * Elf program header
 * Interesting functions for python
 * binding.
 */
uint32_t p_type(size_t header);
uint32_t p_flags(size_t header);
Elf64_Off p_offset(size_t header);
Elf64_Addr p_vaddr(size_t header);
Elf64_Addr p_paddr(size_t header);
uint64_t p_filesz(size_t header);
uint64_t p_memsz(size_t header);
uint64_t p_align(size_t header);

/***
 * Section header parsing and printing
 */
int parse_elf_shdr(uint8_t *buf_ptr, size_t file_size);
void print_elf_shdr();

/***
 * Elf section header
 * Interesting functions for python
 * binding.
 */
uint32_t sh_name(size_t header);
const char* sh_name_s(size_t header);
uint32_t sh_type(size_t header);
uint64_t sh_flags(size_t header);
Elf64_Addr sh_addr(size_t header);
Elf64_Off sh_offset(size_t header);
uint64_t sh_size(size_t header);
uint32_t sh_link(size_t header);
uint32_t sh_info(size_t header);
uint64_t sh_addralign(size_t header);
uint64_t sh_entsize(size_t header);

/***
 * Symbols header parsing and printing
 */

/**
 * Parsing of different symbol tables, these tables
 * are taken from the different section headers. For
 * the moment, we parse SHT_DYNSYM and SHT_SYMTAB.
 * 
 * @param buf_ptr pointer to the bytes with the elf file
 * @return error code, 0 if everything was well, -1 otherwise
 */
int parse_elf_sym(uint8_t *buf_ptr);
void print_elf_sym();

/***
 * Elf Dynamic Symbol header
 * Interesting functions for python
 * binding
 */
size_t dynamic_sym_length();
uint32_t dynamic_st_name(size_t header);
const char* dynamic_st_name_s(size_t header);
unsigned char dynamic_st_info(size_t header);
unsigned char dynamic_st_other(size_t header);
uint16_t dynamic_st_shndx(size_t header);
Elf64_Addr dynamic_st_value(size_t header);
uint64_t dynamic_st_size(size_t header);

/***
 * Elf Symtab Symbol header
 * Interesting functions for python
 * binding
 */
size_t symtab_sym_length();
uint32_t symtab_st_name(size_t header);
const char* symtab_st_name_s(size_t header);
unsigned char symtab_st_info(size_t header);
unsigned char symtab_st_other(size_t header);
uint16_t symtab_st_shndx(size_t header);
Elf64_Addr symtab_st_value(size_t header);
uint64_t symtab_st_size(size_t header);

/***
 * Relocation header parsing and printing
 */

/**
 * Parse all the relocations from the sections,
 * the sections can be divided into SHT_REL and
 * SHT_RELA.
 * 
 * @param buf_ptr pointer to the bytes of the elf file
 * @param file_size size of the file for checks
 * @return error code, 0 if everything was well, -1 otherwise
 */
int parse_elf_rel_a(uint8_t *buf_ptr, size_t file_size);
void print_elf_rel_a();

/***
 * Elf Rel header
 * Interesting functions for python
 * binding
 */
Elf64_Addr  rel_r_offset(size_t header, size_t index);
uint64_t    rel_r_info(size_t header, size_t index);

size_t      rel_32_size();
size_t      rel_64_size();

/***
 * Elf Rela header
 * Interesting functions for python
 * binding
 */
Elf64_Addr  rela_r_offset(size_t header, size_t index);
uint64_t    rela_r_info(size_t header, size_t index);
int64_t     rela_r_addend(size_t header, size_t index);

size_t      rela_32_size();
size_t      rela_64_size();

/***
 * DYNAMIC Program header parsing and printing
 */

/**
 * Sections exists only in the file on disk, so when a program
 * is loaded into memory the dynamic linker will need a dynamic
 * segment with information to load all the functions imported
 * from other libraries. Because this is a segment, it will be
 * loaded into memory.
 * 
 * @param buf_ptr pointer to the bytes from the file
 * @param file_size size of the file for checks.
 * @return error code, 0 if everything was well, -1 otherwise
 */
int parse_elf_dynamic(uint8_t *buf_ptr, size_t file_size);
void print_elf_dynamic();

/***
 * Printer functions, good for analsts
 */
void print_imported_libraries();
void print_imported_functions();

void print_exported_libraries();
void print_exported_functions();


void close_everything();

#endif