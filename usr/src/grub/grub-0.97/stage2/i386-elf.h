/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2001,2002  Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* 32-bit data types */

typedef unsigned long Elf32_Addr;
typedef unsigned short Elf32_Half;
typedef unsigned long Elf32_Off;
typedef signed long Elf32_Sword;
typedef unsigned long Elf32_Word;
/* "unsigned char" already exists */

/* ELF header */
typedef struct
{
  
#define EI_NIDENT 16
  
  /* first four characters are defined below */
#define EI_MAG0		0
#define ELFMAG0		0x7f
#define EI_MAG1		1
#define ELFMAG1		'E'
#define EI_MAG2		2
#define ELFMAG2		'L'
#define EI_MAG3		3
#define ELFMAG3		'F'
  
#define EI_CLASS	4	/* data sizes */
#define ELFCLASS32	1	/* i386 -- up to 32-bit data sizes present */
  
#define EI_DATA		5	/* data type and ordering */
#define ELFDATA2LSB	1	/* i386 -- LSB 2's complement */
  
#define EI_VERSION	6	/* version number.  "e_version" must be the same */
#define EV_CURRENT      1	/* current version number */

#define EI_OSABI	7	/* operating system/ABI indication */
#define ELFOSABI_FREEBSD	9
  
#define EI_ABIVERSION	8	/* ABI version */
  
#define EI_PAD		9	/* from here in is just padding */
  
#define EI_BRAND	8	/* start of OS branding (This is
				   obviously illegal against the ELF
				   standard.) */
  
  unsigned char e_ident[EI_NIDENT];	/* basic identification block */
  
#define ET_EXEC		2	/* we only care about executable types */
  Elf32_Half e_type;		/* file types */
  
#define EM_386		3	/* i386 -- obviously use this one */
  Elf32_Half e_machine;	/* machine types */
  Elf32_Word e_version;	/* use same as "EI_VERSION" above */
  Elf32_Addr e_entry;		/* entry point of the program */
  Elf32_Off e_phoff;		/* program header table file offset */
  Elf32_Off e_shoff;		/* section header table file offset */
  Elf32_Word e_flags;		/* flags */
  Elf32_Half e_ehsize;		/* elf header size in bytes */
  Elf32_Half e_phentsize;	/* program header entry size */
  Elf32_Half e_phnum;		/* number of entries in program header */
  Elf32_Half e_shentsize;	/* section header entry size */
  Elf32_Half e_shnum;		/* number of entries in section header */
  
#define SHN_UNDEF       0
#define SHN_LORESERVE   0xff00
#define SHN_LOPROC      0xff00
#define SHN_HIPROC      0xff1f
#define SHN_ABS         0xfff1
#define SHN_COMMON      0xfff2
#define SHN_HIRESERVE   0xffff
  Elf32_Half e_shstrndx;	/* section header table index */
}
Elf32_Ehdr;


#define BOOTABLE_I386_ELF(h) \
 ((h.e_ident[EI_MAG0] == ELFMAG0) & (h.e_ident[EI_MAG1] == ELFMAG1) \
  & (h.e_ident[EI_MAG2] == ELFMAG2) & (h.e_ident[EI_MAG3] == ELFMAG3) \
  & (h.e_ident[EI_CLASS] == ELFCLASS32) & (h.e_ident[EI_DATA] == ELFDATA2LSB) \
  & (h.e_ident[EI_VERSION] == EV_CURRENT) & (h.e_type == ET_EXEC) \
  & (h.e_machine == EM_386) & (h.e_version == EV_CURRENT))

/* section table - ? */
typedef struct
{
  Elf32_Word	sh_name;		/* Section name (string tbl index) */
  Elf32_Word	sh_type;		/* Section type */
  Elf32_Word	sh_flags;		/* Section flags */
  Elf32_Addr	sh_addr;		/* Section virtual addr at execution */
  Elf32_Off	sh_offset;		/* Section file offset */
  Elf32_Word	sh_size;		/* Section size in bytes */
  Elf32_Word	sh_link;		/* Link to another section */
  Elf32_Word	sh_info;		/* Additional section information */
  Elf32_Word	sh_addralign;		/* Section alignment */
  Elf32_Word	sh_entsize;		/* Entry size if section holds table */
}
Elf32_Shdr;

/* symbol table - page 4-25, figure 4-15 */
typedef struct
{
  Elf32_Word st_name;
  Elf32_Addr st_value;
  Elf32_Word st_size;
  unsigned char st_info;
  unsigned char st_other;
  Elf32_Half st_shndx;
}
Elf32_Sym;

/* symbol type and binding attributes - page 4-26 */

#define ELF32_ST_BIND(i)    ((i) >> 4)
#define ELF32_ST_TYPE(i)    ((i) & 0xf)
#define ELF32_ST_INFO(b,t)  (((b)<<4)+((t)&0xf))

/* symbol binding - page 4-26, figure 4-16 */

#define STB_LOCAL    0
#define STB_GLOBAL   1
#define STB_WEAK     2
#define STB_LOPROC  13
#define STB_HIPROC  15

/* symbol types - page 4-28, figure 4-17 */

#define STT_NOTYPE   0
#define STT_OBJECT   1
#define STT_FUNC     2
#define STT_SECTION  3
#define STT_FILE     4
#define STT_LOPROC  13
#define STT_HIPROC  15


/* Macros to split/combine relocation type and symbol page 4-32 */

#define ELF32_R_SYM(__i)	((__i)>>8)
#define ELF32_R_TYPE(__i)	((unsigned char) (__i))
#define ELF32_R_INFO(__s, __t)	(((__s)<<8) + (unsigned char) (__t))


/* program header - page 5-2, figure 5-1 */

typedef struct
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
}
Elf32_Phdr;

/* segment types - page 5-3, figure 5-2 */

#define PT_NULL		0
#define PT_LOAD		1
#define PT_DYNAMIC	2
#define PT_INTERP	3
#define PT_NOTE		4
#define PT_SHLIB	5
#define PT_PHDR		6

#define PT_LOPROC	0x70000000
#define PT_HIPROC	0x7fffffff

/* segment permissions - page 5-6 */

#define PF_X		0x1
#define PF_W		0x2
#define PF_R		0x4
#define PF_MASKPROC	0xf0000000


/* dynamic structure - page 5-15, figure 5-9 */

typedef struct
{
  Elf32_Sword d_tag;
  union
  {
    Elf32_Word d_val;
    Elf32_Addr d_ptr;
  }
  d_un;
}
Elf32_Dyn;

/* Dynamic array tags - page 5-16, figure 5-10.  */

#define DT_NULL		0
#define DT_NEEDED	1
#define DT_PLTRELSZ	2
#define DT_PLTGOT	3
#define DT_HASH		4
#define DT_STRTAB	5
#define DT_SYMTAB	6
#define DT_RELA		7
#define DT_RELASZ	8
#define DT_RELAENT      9
#define DT_STRSZ	10
#define DT_SYMENT	11
#define DT_INIT		12
#define DT_FINI		13
#define DT_SONAME	14
#define DT_RPATH	15
#define DT_SYMBOLIC	16
#define DT_REL		17
#define DT_RELSZ	18
#define DT_RELENT	19
#define DT_PLTREL	20
#define DT_DEBUG	21
#define DT_TEXTREL	22
#define DT_JMPREL	23
