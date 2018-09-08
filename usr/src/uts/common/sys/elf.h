/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 */
/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


#ifndef _SYS_ELF_H
#define	_SYS_ELF_H

#include <sys/elftypes.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ELF32_FSZ_ADDR	4
#define	ELF32_FSZ_HALF	2
#define	ELF32_FSZ_OFF	4
#define	ELF32_FSZ_SWORD	4
#define	ELF32_FSZ_WORD	4

#define	ELF64_FSZ_ADDR	8
#define	ELF64_FSZ_HALF	2
#define	ELF64_FSZ_OFF	8
#define	ELF64_FSZ_SWORD	4
#define	ELF64_FSZ_WORD	4
#define	ELF64_FSZ_SXWORD 8
#define	ELF64_FSZ_XWORD	8

/*
 *	"Enumerations" below use ...NUM as the number of
 *	values in the list.  It should be 1 greater than the
 *	highest "real" value.
 */

/*
 *	ELF header
 */

#define	EI_NIDENT	16

typedef struct {
	unsigned char	e_ident[EI_NIDENT];	/* ident bytes */
	Elf32_Half	e_type;			/* file type */
	Elf32_Half	e_machine;		/* target machine */
	Elf32_Word	e_version;		/* file version */
	Elf32_Addr	e_entry;		/* start address */
	Elf32_Off	e_phoff;		/* phdr file offset */
	Elf32_Off	e_shoff;		/* shdr file offset */
	Elf32_Word	e_flags;		/* file flags */
	Elf32_Half	e_ehsize;		/* sizeof ehdr */
	Elf32_Half	e_phentsize;		/* sizeof phdr */
	Elf32_Half	e_phnum;		/* number phdrs */
	Elf32_Half	e_shentsize;		/* sizeof shdr */
	Elf32_Half	e_shnum;		/* number shdrs */
	Elf32_Half	e_shstrndx;		/* shdr string index */
} Elf32_Ehdr;

#if defined(_LP64) || defined(_LONGLONG_TYPE)
typedef struct {
	unsigned char	e_ident[EI_NIDENT];	/* ident bytes */
	Elf64_Half	e_type;			/* file type */
	Elf64_Half	e_machine;		/* target machine */
	Elf64_Word	e_version;		/* file version */
	Elf64_Addr	e_entry;		/* start address */
	Elf64_Off	e_phoff;		/* phdr file offset */
	Elf64_Off	e_shoff;		/* shdr file offset */
	Elf64_Word	e_flags;		/* file flags */
	Elf64_Half	e_ehsize;		/* sizeof ehdr */
	Elf64_Half	e_phentsize;		/* sizeof phdr */
	Elf64_Half	e_phnum;		/* number phdrs */
	Elf64_Half	e_shentsize;		/* sizeof shdr */
	Elf64_Half	e_shnum;		/* number shdrs */
	Elf64_Half	e_shstrndx;		/* shdr string index */
} Elf64_Ehdr;
#endif	/* defined(_LP64) || defined(_LONGLONG_TYPE) */


#define	EI_MAG0		0	/* e_ident[] indexes */
#define	EI_MAG1		1
#define	EI_MAG2		2
#define	EI_MAG3		3
#define	EI_CLASS	4	/* File class */
#define	EI_DATA		5	/* Data encoding */
#define	EI_VERSION	6	/* File version */
#define	EI_OSABI	7	/* Operating system/ABI identification */
#define	EI_ABIVERSION	8	/* ABI version */
#define	EI_PAD		9	/* Start of padding bytes */

#define	ELFMAG0		0x7f		/* EI_MAG */
#define	ELFMAG1		'E'
#define	ELFMAG2		'L'
#define	ELFMAG3		'F'
#define	ELFMAG		"\177ELF"
#define	SELFMAG		4

#define	ELFCLASSNONE	0		/* EI_CLASS */
#define	ELFCLASS32	1
#define	ELFCLASS64	2
#define	ELFCLASSNUM	3

#define	ELFDATANONE	0		/* EI_DATA */
#define	ELFDATA2LSB	1
#define	ELFDATA2MSB	2
#define	ELFDATANUM	3

#define	ET_NONE		0		/* e_type */
#define	ET_REL		1
#define	ET_EXEC		2
#define	ET_DYN		3
#define	ET_CORE		4
#define	ET_NUM		5
#define	ET_LOOS		0xfe00		/* OS specific range */
#define	ET_LOSUNW	0xfeff
#define	ET_SUNWPSEUDO	0xfeff
#define	ET_HISUNW	0xfeff
#define	ET_HIOS		0xfeff
#define	ET_LOPROC	0xff00		/* processor specific range */
#define	ET_HIPROC	0xffff

#define	ET_LOPROC	0xff00		/* processor specific range */
#define	ET_HIPROC	0xffff

#define	EM_NONE		0	/* e_machine */
#define	EM_M32		1	/* AT&T WE 32100 */
#define	EM_SPARC	2	/* Sun SPARC */
#define	EM_386		3	/* Intel 80386 */
#define	EM_68K		4	/* Motorola 68000 */
#define	EM_88K		5	/* Motorola 88000 */
#define	EM_486		6	/* Intel 80486 */
#define	EM_860		7	/* Intel i860 */
#define	EM_MIPS		8	/* MIPS RS3000 Big-Endian */
#define	EM_S370		9	/* IBM System/370 Processor */
#define	EM_MIPS_RS3_LE	10	/* MIPS RS3000 Little-Endian */
#define	EM_RS6000	11	/* RS6000 */
#define	EM_UNKNOWN12	12
#define	EM_UNKNOWN13	13
#define	EM_UNKNOWN14	14
#define	EM_PA_RISC	15	/* PA-RISC */
#define	EM_PARISC	EM_PA_RISC	/* Alias: GNU compatibility */
#define	EM_nCUBE	16	/* nCUBE */
#define	EM_VPP500	17	/* Fujitsu VPP500 */
#define	EM_SPARC32PLUS	18	/* Sun SPARC 32+ */
#define	EM_960		19	/* Intel 80960 */
#define	EM_PPC		20	/* PowerPC */
#define	EM_PPC64	21	/* 64-bit PowerPC */
#define	EM_S390		22	/* IBM System/390 Processor */
#define	EM_UNKNOWN22	EM_S390		/* Alias: Older published name */
#define	EM_UNKNOWN23	23
#define	EM_UNKNOWN24	24
#define	EM_UNKNOWN25	25
#define	EM_UNKNOWN26	26
#define	EM_UNKNOWN27	27
#define	EM_UNKNOWN28	28
#define	EM_UNKNOWN29	29
#define	EM_UNKNOWN30	30
#define	EM_UNKNOWN31	31
#define	EM_UNKNOWN32	32
#define	EM_UNKNOWN33	33
#define	EM_UNKNOWN34	34
#define	EM_UNKNOWN35	35
#define	EM_V800		36	/* NEX V800 */
#define	EM_FR20		37	/* Fujitsu FR20 */
#define	EM_RH32		38	/* TRW RH-32 */
#define	EM_RCE		39	/* Motorola RCE */
#define	EM_ARM		40	/* Advanced RISC Marchines ARM */
#define	EM_ALPHA	41	/* Digital Alpha */
#define	EM_SH		42	/* Hitachi SH */
#define	EM_SPARCV9	43	/* Sun SPARC V9 (64-bit) */
#define	EM_TRICORE	44	/* Siemens Tricore embedded processor */
#define	EM_ARC		45	/* Argonaut RISC Core, */
				/*	Argonaut Technologies Inc. */
#define	EM_H8_300	46	/* Hitachi H8/300 */
#define	EM_H8_300H	47	/* Hitachi H8/300H */
#define	EM_H8S		48	/* Hitachi H8S */
#define	EM_H8_500	49	/* Hitachi H8/500 */
#define	EM_IA_64	50	/* Intel IA64 */
#define	EM_MIPS_X	51	/* Stanford MIPS-X */
#define	EM_COLDFIRE	52	/* Motorola ColdFire */
#define	EM_68HC12	53	/* Motorola M68HC12 */
#define	EM_MMA		54	/* Fujitsu MMA Mulimedia Accelerator */
#define	EM_PCP		55	/* Siemens PCP */
#define	EM_NCPU		56	/* Sony nCPU embedded RISC processor */
#define	EM_NDR1		57	/* Denso NDR1 microprocessor */
#define	EM_STARCORE	58	/* Motorola Star*Core processor */
#define	EM_ME16		59	/* Toyota ME16 processor */
#define	EM_ST100	60	/* STMicroelectronics ST100 processor */
#define	EM_TINYJ	61	/* Advanced Logic Corp. TinyJ */
				/*	embedded processor family */
#define	EM_AMD64	62	/* AMDs x86-64 architecture */
#define	EM_X86_64	EM_AMD64	/* (compatibility) */

#define	EM_PDSP		63	/* Sony DSP Processor */
#define	EM_UNKNOWN64	64
#define	EM_UNKNOWN65	65
#define	EM_FX66		66	/* Siemens FX66 microcontroller */
#define	EM_ST9PLUS	67	/* STMicroelectronics ST9+8/16 bit */
				/*	microcontroller */
#define	EM_ST7		68	/* STMicroelectronics ST7 8-bit */
				/*	microcontroller */
#define	EM_68HC16	69	/* Motorola MC68HC16 Microcontroller */
#define	EM_68HC11	70	/* Motorola MC68HC11 Microcontroller */
#define	EM_68HC08	71	/* Motorola MC68HC08 Microcontroller */
#define	EM_68HC05	72	/* Motorola MC68HC05 Microcontroller */
#define	EM_SVX		73	/* Silicon Graphics SVx */
#define	EM_ST19		74	/* STMicroelectronics ST19 8-bit */
				/*	microcontroller */
#define	EM_VAX		75	/* Digital VAX */
#define	EM_CRIS		76	/* Axis Communications 32-bit */
				/*	embedded processor */
#define	EM_JAVELIN	77	/* Infineon Technologies 32-bit */
				/*	embedded processor */
#define	EM_FIREPATH	78	/* Element 14 64-bit DSP Processor */
#define	EM_ZSP		79	/* LSI Logic 16-bit DSP Processor */
#define	EM_MMIX		80	/* Donald Knuth's educational */
				/*	64-bit processor */
#define	EM_HUANY	81	/* Harvard University */
				/*	machine-independent */
				/*	object files */
#define	EM_PRISM	82	/* SiTera Prism */
#define	EM_AVR		83	/* Atmel AVR 8-bit microcontroller */
#define	EM_FR30		84	/* Fujitsu FR30 */
#define	EM_D10V		85	/* Mitsubishi D10V */
#define	EM_D30V		86	/* Mitsubishi D30V */
#define	EM_V850		87	/* NEC v850 */
#define	EM_M32R		88	/* Mitsubishi M32R */
#define	EM_MN10300	89	/* Matsushita MN10300 */
#define	EM_MN10200	90	/* Matsushita MN10200 */
#define	EM_PJ		91	/* picoJava */
#define	EM_OPENRISC	92	/* OpenRISC 32-bit embedded processor */
#define	EM_ARC_A5	93	/* ARC Cores Tangent-A5 */
#define	EM_XTENSA	94	/* Tensilica Xtensa architecture */

#define	EM_VIDEOCORE	95	/* Alphamosaic VideoCore processor */
#define	EM_TMM_GPP	96	/* Thompson Multimedia General Purpose */
				/* Processor */
#define	EM_NS32K	97	/* National Semiconductor 32000 series */
#define	EM_TPC		98	/* Tenor Network TPC processor */
#define	EM_SNP1K	99	/* Trebia SNP 1000 processor */
#define	EM_ST200	100	/* STMicroelectronics (www.st.com) ST200 */
				/* microcontroller */
#define	EM_IP2K		101	/* Ubicom IP2xxx microcontroller family */
#define	EM_MAX		102	/* MAX Processor */
#define	EM_CR		103	/* National Semiconductor CompactRISC */
				/* microprocessor */
#define	EM_F2MC16	104	/* Fujitsu F2MC16 */
#define	EM_MSP430	105	/* Texas Instruments embedded microcontroller */
				/* msp430 */
#define	EM_BLACKFIN	106	/* Analog Devices Blackfin (DSP) processor */
#define	EM_SE_C33	107	/* S1C33 Family of Seiko Epson processors */
#define	EM_SEP		108	/* Sharp embedded microprocessor */
#define	EM_ARCA		109	/* Arca RISC Microprocessor */
#define	EM_UNICORE	110	/* Microprocessor series from PKU-Unity Ltd. */
				/* and MPRC of Peking University */
#define	EM_EXCESS	111	/* eXcess: 16/32/64-bit configurable embedded */
				/* CPU */
#define	EM_DXP		112	/* Icera Semiconductor Inc. Deep Execution */
				/* Processor */
#define	EM_ALTERA_NIOS2	113	/* Altera Nios II soft-core processor */
#define	EM_CRX		114	/* National Semiconductor CompactRISC CRX */
				/* microprocessor */
#define	EM_XGATE	115	/* Motorola XGATE embedded processor */
#define	EM_C166		116	/* Infineon C16x/XC16x processor */
#define	EM_M16C		117	/* Renesas M16C series microprocessors */
#define	EM_DSPIC30F	118	/* Microchip Technology dsPIC30F Digital */
				/* Signal Controller */
#define	EM_CE		119	/* Freescale Communication Engine RISC core */
#define	EM_M32C		120	/* Renesas M32C series microprocessors */

#define	EM_TSK3000	131	/* Altium TSK3000 core */
#define	EM_RS08		132	/* Freescale RS08 embedded processor */
#define	EM_SHARC	133	/* Analog Devices SHARC family of 32-bit DSP */
				/* processors */
#define	EM_ECOG2	134	/* Cyan Technology eCOG2 microprocessor */
#define	EM_SCORE7	135	/* Sunplus S+core7 RISC processor */
#define	EM_DSP24	136	/* New Japan Radio (NJR) 24-bit DSP Processor */
#define	EM_VIDEOCORE3	137	/* Broadcom VideoCore III processor */
#define	EM_LATTICEMICO32	138	/* RISC processor for Lattice FPGA */
					/* architecture */
#define	EM_SE_C17	139	/* Seiko Epson C17 family */
#define	EM_TI_C6000	140	/* The Texas Instruments TMS320C6000 DSP */
				/* family */
#define	EM_TI_C2000	141	/* The Texas Instruments TMS320C2000 DSP */
				/* family */
#define	EM_TI_C5500	142	/* The Texas Instruments TMS320C55x DSP */
				/* family */
#define	EM_TI_ARP32	143	/* Texas Instruments Application Specific */
				/* RISC Processor, 32bit fetch */
#define	EM_TI_PRU	144	/* Texas Instruments Programmable Realtime */
				/* Unit */

#define	EM_MMDSP_PLUS	160	/* STMicroelectronics 64bit VLIW Data Signal */
				/* Processor */
#define	EM_CYPRESS_M8C	161	/* Cypress M8C microprocessor */
#define	EM_R32C		162	/* Renesas R32C series microprocessors */
#define	EM_TRIMEDIA	163	/* NXP Semiconductors TriMedia architecture */
				/* family */
#define	EM_QDSP6	164	/* QUALCOMM DSP6 Processor */
#define	EM_8051		165	/* Intel 8051 and variants */
#define	EM_STXP7X	166	/* STMicroelectronics STxP7x family of */
				/* configurable and extensible RISC */
				/* processors */
#define	EM_NDS32	167	/* Andes Technology compact code size */
				/* embedded RISC processor family */
#define	EM_ECOG1	168	/* Cyan Technology eCOG1X family */
#define	EM_ECOG1X	EM_EC0G1X	/* Cyan Technology eCOG1X family */
#define	EM_MAXQ30	169	/* Dallas Semiconductor MAXQ30 Core */
				/* Micro-controllers */
#define	EM_XIMO16	170	/* New Japan Radio (NJR) 16-bit DSP Processor */
#define	EM_MANIK	171	/* M2000 Reconfigurable RISC Microprocessor */
#define	EM_CRAYNV2	172	/* Cray Inc. NV2 vector architecture */
#define	EM_RX		173	/* Renesas RX family */
#define	EM_METAG	174	/* Imagination Technologies META processor */
				/* architecture */
#define	EM_MCST_ELBRUS	175	/* MCST Elbrus general purpose hardware */
				/* architecture */
#define	EM_ECOG16	176	/* Cyan Technology eCOG16 family */
#define	EM_CR16		177	/* National Semiconductor CompactRISC */
				/* CR16 16-bit microprocessor */
#define	EM_ETPU		178	/* Freescale Extended Time Processing Unit */
#define	EM_SLE9X	179	/* Infineon Technologies SLE9X core */
#define	EM_L10M		180	/* Intel L10M */
#define	EM_K10M		181	/* Intel K10M */

#define	EM_AARCH64	183	/* ARM 64-bit architecture (AARCH64) */

#define	EM_AVR32	185	/* Atmel Corporation 32-bit microprocessor */
				/* family */
#define	EM_STM8		186	/* STMicroeletronics STM8 8-bit */
				/* microcontroller */
#define	EM_TILE64	187	/* Tilera TILE64 multicore architecture */
				/* family */
#define	EM_TILEPRO	188	/* Tilera TILEPro multicore architecture */
				/* family */
#define	EM_MICROBLAZE	189	/* Xilinx MicroBlaze 32-bit RISC soft */
				/* processor core */
#define	EM_CUDA		190	/* NVIDIA CUDA architecture */
#define	EM_TILEGX	191	/* Tilera TILE-Gx multicore architecture */
				/* family */
#define	EM_CLOUDSHIELD	192	/* CloudShield architecture family */
#define	EM_COREA_1ST	193	/* KIPO-KAIST Core-A 1st generation processor */
				/* family */
#define	EM_COREA_2ND	194	/* KIPO-KAIST Core-A 2nd generation processor */
				/* family */
#define	EM_ARC_COMPACT2	195	/* Synopsys ARCompact V2 */
#define	EM_OPEN8	196	/* Open8 8-bit RISC soft processor core */
#define	EM_RL78		197	/* Renesas RL78 family */
#define	EM_VIDEOCORE5	198	/* Broadcom VideoCore V processor */
#define	EM_78KOR	199	/* Renesas 78KOR family */
#define	EM_56800EX	200	/* Freescale 56800EX Digital Signal */
				/* Controller (DSC) */
#define	EM_BA1		201	/* Beyond BA1 CPU architecture */
#define	EM_BA2		202	/* Beyond BA2 CPU architecture */
#define	EM_XCORE	203	/* XMOS xCORE processor family */
#define	EM_MCHP_PIC	204	/* Microchip 8-bit PIC(r) family */
#define	EM_INTEL205	205	/* Reserved by Intel */
#define	EM_INTEL206	206	/* Reserved by Intel */
#define	EM_INTEL207	207	/* Reserved by Intel */
#define	EM_INTEL208	208	/* Reserved by Intel */
#define	EM_INTEL209	209	/* Reserved by Intel */
#define	EM_KM32		210	/* KM211 KM32 32-bit processor */
#define	EM_KMX32	211	/* KM211 KMX32 32-bit processor */
#define	EM_KMX16	212	/* KM211 KMX16 16-bit processor */
#define	EM_KMX8		213	/* KM211 KMX8 8-bit processor */
#define	EM_KVARC	214	/* KM211 KVARC processor */
#define	EM_CDP		215	/* Paneve CDP architecture family */
#define	EM_COGE		216	/* Cognitive Smart Memory Processor */
#define	EM_COOL		217	/* Bluechip Systems CoolEngine */
#define	EM_NORC		218	/* Nanoradio Optimized RISC */
#define	EM_CSR_KALIMBA	219	/* CSR Kalimba architecture family */
#define	EM_Z80		220	/* Zilog Z80 */
#define	EM_VISIUM	221	/* Controls and Data Services VISIUMcore */
				/* processor */
#define	EM_FT32		222	/* FTDI Chip FT32 high performance 32-bit */
				/* RISC architecture */
#define	EM_MOXIE	223	/* Moxie processor family */
#define	EM_AMDGPU	224	/* AMD GPU architecture */

#define	EM_RISCV	243	/* RISC-V */

#define	EM_NUM		244

#define	EV_NONE		0		/* e_version, EI_VERSION */
#define	EV_CURRENT	1
#define	EV_NUM		2


#define	ELFOSABI_NONE		0	/* No extensions or unspecified */
#define	ELFOSABI_SYSV		ELFOSABI_NONE
#define	ELFOSABI_HPUX		1	/* Hewlett-Packard HP-UX */
#define	ELFOSABI_NETBSD		2	/* NetBSD */
#define	ELFOSABI_LINUX		3	/* Linux */
#define	ELFOSABI_UNKNOWN4	4
#define	ELFOSABI_UNKNOWN5	5
#define	ELFOSABI_SOLARIS	6	/* Sun Solaris */
#define	ELFOSABI_AIX		7	/* AIX */
#define	ELFOSABI_IRIX		8	/* IRIX */
#define	ELFOSABI_FREEBSD	9	/* FreeBSD */
#define	ELFOSABI_TRU64		10	/* Compaq TRU64 UNIX */
#define	ELFOSABI_MODESTO	11	/* Novell Modesto */
#define	ELFOSABI_OPENBSD	12	/* Open BSD */
#define	ELFOSABI_OPENVMS	13	/* Open VMS */
#define	ELFOSABI_NSK		14	/* Hewlett-Packard Non-Stop Kernel */
#define	ELFOSABI_AROS		15	/* Amiga Research OS */
#define	ELFOSABI_FENIXOS 	16 	/* The FenixOS highly scalable */
					/* multi-core OS */
#define	ELFOSABI_CLOUDABI 	17 	/* Nuxi CloudABI */
#define	ELFOSABI_OPENVOS 	18 	/* Stratus Technologies OpenVOS */
#define	ELFOSABI_ARM		97	/* ARM */
#define	ELFOSABI_STANDALONE	255	/* standalone (embedded) application */

#define	EAV_SUNW_NONE		0	/* EI_ABIVERSION */
#define	EAV_SUNW_CURRENT	1
#define	EAV_SUNW_NUM		2


/*
 *	Program header
 */

typedef struct {
	Elf32_Word	p_type;		/* entry type */
	Elf32_Off	p_offset;	/* file offset */
	Elf32_Addr	p_vaddr;	/* virtual address */
	Elf32_Addr	p_paddr;	/* physical address */
	Elf32_Word	p_filesz;	/* file size */
	Elf32_Word	p_memsz;	/* memory size */
	Elf32_Word	p_flags;	/* entry flags */
	Elf32_Word	p_align;	/* memory/file alignment */
} Elf32_Phdr;

#if defined(_LP64) || defined(_LONGLONG_TYPE)
typedef struct {
	Elf64_Word	p_type;		/* entry type */
	Elf64_Word	p_flags;	/* entry flags */
	Elf64_Off	p_offset;	/* file offset */
	Elf64_Addr	p_vaddr;	/* virtual address */
	Elf64_Addr	p_paddr;	/* physical address */
	Elf64_Xword	p_filesz;	/* file size */
	Elf64_Xword	p_memsz;	/* memory size */
	Elf64_Xword	p_align;	/* memory/file alignment */
} Elf64_Phdr;
#endif	/* defined(_LP64) || defined(_LONGLONG_TYPE) */


#define	PT_NULL		0		/* p_type */
#define	PT_LOAD		1
#define	PT_DYNAMIC	2
#define	PT_INTERP	3
#define	PT_NOTE		4
#define	PT_SHLIB	5
#define	PT_PHDR		6
#define	PT_TLS		7
#define	PT_NUM		8

#define	PT_LOOS		0x60000000	/* OS specific range */

/*
 * PT_SUNW_UNWIND and PT_SUNW_EH_FRAME perform the same function,
 * providing access to the .eh_frame_hdr section of the object.
 * PT_SUNW_UNWIND is the original value, while PT_SUNW_EH_FRAME is
 * required by the amd64 psABI. The Solaris link-editor (ld) tags output
 * objects with PT_SUNW_UNWIND, but the Solaris runtime linker (ld.so.1)
 * will accept and use either value.
 */
#define	PT_SUNW_UNWIND		0x6464e550
#define	PT_SUNW_EH_FRAME	0x6474e550
#define	PT_GNU_EH_FRAME		PT_SUNW_EH_FRAME

/*
 * Linux specific program headers not currently used by Solaris
 */
#define	PT_GNU_STACK	0x6474e551	/* Indicates stack executability */
#define	PT_GNU_RELRO	0x6474e552	/* Read-only after relocation */

#define	PT_LOSUNW	0x6ffffffa
#define	PT_SUNWBSS	0x6ffffffa	/* Sun Specific segment (unused) */
#define	PT_SUNWSTACK	0x6ffffffb	/* describes the stack segment */
#define	PT_SUNWDTRACE	0x6ffffffc	/* private */
#define	PT_SUNWCAP	0x6ffffffd	/* hard/soft capabilities segment */
#define	PT_HISUNW	0x6fffffff
#define	PT_HIOS		0x6fffffff

#define	PT_LOPROC	0x70000000	/* processor specific range */
#define	PT_HIPROC	0x7fffffff

#define	PF_R		0x4		/* p_flags */
#define	PF_W		0x2
#define	PF_X		0x1

#define	PF_MASKOS	0x0ff00000	/* OS specific values */
#define	PF_MASKPROC	0xf0000000	/* processor specific values */

#define	PF_SUNW_FAILURE	0x00100000	/* mapping absent due to failure */
#define	PF_SUNW_KILLED	0x00200000	/* signal received during dump */
#define	PF_SUNW_SIGINFO	0x00400000	/* segment has killing sig's siginfo */

#define	PN_XNUM		0xffff		/* extended program header index */

/*
 *	Section header
 */

typedef struct {
	Elf32_Word	sh_name;	/* section name */
	Elf32_Word	sh_type;	/* SHT_... */
	Elf32_Word	sh_flags;	/* SHF_... */
	Elf32_Addr	sh_addr;	/* virtual address */
	Elf32_Off	sh_offset;	/* file offset */
	Elf32_Word	sh_size;	/* section size */
	Elf32_Word	sh_link;	/* misc info */
	Elf32_Word	sh_info;	/* misc info */
	Elf32_Word	sh_addralign;	/* memory alignment */
	Elf32_Word	sh_entsize;	/* entry size if table */
} Elf32_Shdr;

#if defined(_LP64) || defined(_LONGLONG_TYPE)
typedef struct {
	Elf64_Word	sh_name;	/* section name */
	Elf64_Word	sh_type;	/* SHT_... */
	Elf64_Xword	sh_flags;	/* SHF_... */
	Elf64_Addr	sh_addr;	/* virtual address */
	Elf64_Off	sh_offset;	/* file offset */
	Elf64_Xword	sh_size;	/* section size */
	Elf64_Word	sh_link;	/* misc info */
	Elf64_Word	sh_info;	/* misc info */
	Elf64_Xword	sh_addralign;	/* memory alignment */
	Elf64_Xword	sh_entsize;	/* entry size if table */
} Elf64_Shdr;
#endif	/* defined(_LP64) || defined(_LONGLONG_TYPE) */

#define	SHT_NULL		0		/* sh_type */
#define	SHT_PROGBITS		1
#define	SHT_SYMTAB		2
#define	SHT_STRTAB		3
#define	SHT_RELA		4
#define	SHT_HASH		5
#define	SHT_DYNAMIC		6
#define	SHT_NOTE		7
#define	SHT_NOBITS		8
#define	SHT_REL			9
#define	SHT_SHLIB		10
#define	SHT_DYNSYM		11
#define	SHT_UNKNOWN12		12
#define	SHT_UNKNOWN13		13
#define	SHT_INIT_ARRAY		14
#define	SHT_FINI_ARRAY		15
#define	SHT_PREINIT_ARRAY	16
#define	SHT_GROUP		17
#define	SHT_SYMTAB_SHNDX	18
#define	SHT_NUM			19

/* Solaris ABI specific values */
#define	SHT_LOOS		0x60000000	/* OS specific range */
#define	SHT_LOSUNW		0x6fffffef
#define	SHT_SUNW_capchain	0x6fffffef
#define	SHT_SUNW_capinfo	0x6ffffff0
#define	SHT_SUNW_symsort	0x6ffffff1
#define	SHT_SUNW_tlssort	0x6ffffff2
#define	SHT_SUNW_LDYNSYM	0x6ffffff3
#define	SHT_SUNW_dof		0x6ffffff4
#define	SHT_SUNW_cap		0x6ffffff5
#define	SHT_SUNW_SIGNATURE	0x6ffffff6
#define	SHT_SUNW_ANNOTATE	0x6ffffff7
#define	SHT_SUNW_DEBUGSTR	0x6ffffff8
#define	SHT_SUNW_DEBUG		0x6ffffff9
#define	SHT_SUNW_move		0x6ffffffa
#define	SHT_SUNW_COMDAT		0x6ffffffb
#define	SHT_SUNW_syminfo	0x6ffffffc
#define	SHT_SUNW_verdef		0x6ffffffd
#define	SHT_GNU_verdef		SHT_SUNW_verdef
#define	SHT_SUNW_verneed	0x6ffffffe
#define	SHT_GNU_verneed		SHT_SUNW_verneed
#define	SHT_SUNW_versym		0x6fffffff
#define	SHT_GNU_versym		SHT_SUNW_versym
#define	SHT_HISUNW		0x6fffffff
#define	SHT_HIOS		0x6fffffff

/*
 * GNU/Linux OSABI specific values with different meanings than under Solaris.
 * Due to the overlap in assigned values with the Solaris OSABI, correct
 * interpretation of these values requires knowledge of the OSABI used by
 * the object.
 */
#define	SHT_GNU_ATTRIBUTES	0x6ffffff5	/* Object attributes */
#define	SHT_GNU_HASH		0x6ffffff6	/* GNU-style hash table */
#define	SHT_GNU_LIBLIST		0x6ffffff7	/* Prelink library list */
#define	SHT_CHECKSUM		0x6ffffff8	/* Checksum for DSO content */

#define	SHT_LOPROC	0x70000000	/* processor specific range */
#define	SHT_HIPROC	0x7fffffff

#define	SHT_LOUSER	0x80000000
#define	SHT_HIUSER	0xffffffff

#define	SHF_WRITE		0x01		/* sh_flags */
#define	SHF_ALLOC		0x02
#define	SHF_EXECINSTR		0x04
#define	SHF_MERGE		0x10
#define	SHF_STRINGS		0x20
#define	SHF_INFO_LINK		0x40
#define	SHF_LINK_ORDER		0x80
#define	SHF_OS_NONCONFORMING	0x100
#define	SHF_GROUP		0x200
#define	SHF_TLS			0x400

#define	SHF_MASKOS	0x0ff00000	/* OS specific values */


#define	SHF_MASKPROC	0xf0000000	/* processor specific values */

#define	SHN_UNDEF	0		/* special section numbers */
#define	SHN_LORESERVE	0xff00
#define	SHN_LOPROC	0xff00		/* processor specific range */
#define	SHN_HIPROC	0xff1f
#define	SHN_LOOS	0xff20		/* OS specific range */
#define	SHN_LOSUNW	0xff3f
#define	SHN_SUNW_IGNORE	0xff3f
#define	SHN_HISUNW	0xff3f
#define	SHN_HIOS	0xff3f
#define	SHN_ABS		0xfff1
#define	SHN_COMMON	0xfff2
#define	SHN_XINDEX	0xffff		/* extended sect index */
#define	SHN_HIRESERVE	0xffff



/*
 *	Symbol table
 */

typedef struct {
	Elf32_Word	st_name;
	Elf32_Addr	st_value;
	Elf32_Word	st_size;
	unsigned char	st_info;	/* bind, type: ELF_32_ST_... */
	unsigned char	st_other;
	Elf32_Half	st_shndx;	/* SHN_... */
} Elf32_Sym;

#if defined(_LP64) || defined(_LONGLONG_TYPE)
typedef struct {
	Elf64_Word	st_name;
	unsigned char	st_info;	/* bind, type: ELF_64_ST_... */
	unsigned char	st_other;
	Elf64_Half	st_shndx;	/* SHN_... */
	Elf64_Addr	st_value;
	Elf64_Xword	st_size;
} Elf64_Sym;
#endif	/* defined(_LP64) || defined(_LONGLONG_TYPE) */

#define	STN_UNDEF	0

/*
 *	Macros to compose and decompose values for S.st_info
 *
 *	bind = ELF32_ST_BIND(S.st_info)
 *	type = ELF32_ST_TYPE(S.st_info)
 *	S.st_info = ELF32_ST_INFO(bind, type)
 */

#define	ELF32_ST_BIND(info)		((info) >> 4)
#define	ELF32_ST_TYPE(info)		((info) & 0xf)
#define	ELF32_ST_INFO(bind, type)	(((bind)<<4)+((type)&0xf))

#define	ELF64_ST_BIND(info)		((info) >> 4)
#define	ELF64_ST_TYPE(info)		((info) & 0xf)
#define	ELF64_ST_INFO(bind, type)	(((bind)<<4)+((type)&0xf))


#define	STB_LOCAL	0		/* BIND */
#define	STB_GLOBAL	1
#define	STB_WEAK	2
#define	STB_NUM		3

#define	STB_LOPROC	13		/* processor specific range */
#define	STB_HIPROC	15

#define	STT_NOTYPE	0		/* symbol type is unspecified */
#define	STT_OBJECT	1		/* data object */
#define	STT_FUNC	2		/* code object */
#define	STT_SECTION	3		/* symbol identifies an ELF section */
#define	STT_FILE	4		/* symbol's name is file name */
#define	STT_COMMON	5		/* common data object */
#define	STT_TLS		6		/* thread-local data object */
#define	STT_NUM		7		/* # defined types in generic range */
#define	STT_LOOS	10		/* OS specific range */
#define	STT_HIOS	12
#define	STT_LOPROC	13		/* processor specific range */
#define	STT_HIPROC	15

/*
 *	Macros to decompose values for S.st_other
 *
 *	visibility = ELF32_ST_VISIBILITY(S.st_other)
 */
#define	ELF32_ST_VISIBILITY(other)	((other)&0x7)
#define	ELF64_ST_VISIBILITY(other)	((other)&0x7)

#define	STV_DEFAULT	0
#define	STV_INTERNAL	1
#define	STV_HIDDEN	2
#define	STV_PROTECTED	3
#define	STV_EXPORTED	4
#define	STV_SINGLETON	5
#define	STV_ELIMINATE	6

#define	STV_NUM		7

/*
 *	Relocation
 */

typedef struct {
	Elf32_Addr	r_offset;
	Elf32_Word	r_info;		/* sym, type: ELF32_R_... */
} Elf32_Rel;

typedef struct {
	Elf32_Addr	r_offset;
	Elf32_Word	r_info;		/* sym, type: ELF32_R_... */
	Elf32_Sword	r_addend;
} Elf32_Rela;

#if defined(_LP64) || defined(_LONGLONG_TYPE)
typedef struct {
	Elf64_Addr	r_offset;
	Elf64_Xword	r_info;		/* sym, type: ELF64_R_... */
} Elf64_Rel;

typedef struct {
	Elf64_Addr	r_offset;
	Elf64_Xword	r_info;		/* sym, type: ELF64_R_... */
	Elf64_Sxword	r_addend;
} Elf64_Rela;
#endif	/* defined(_LP64) || defined(_LONGLONG_TYPE) */


/*
 *	Macros to compose and decompose values for Rel.r_info, Rela.f_info
 *
 *	sym = ELF32_R_SYM(R.r_info)
 *	type = ELF32_R_TYPE(R.r_info)
 *	R.r_info = ELF32_R_INFO(sym, type)
 */

#define	ELF32_R_SYM(info)	((info)>>8)
#define	ELF32_R_TYPE(info)	((unsigned char)(info))
#define	ELF32_R_INFO(sym, type)	(((sym)<<8)+(unsigned char)(type))

#define	ELF64_R_SYM(info)	((info)>>32)
#define	ELF64_R_TYPE(info)    	((Elf64_Word)(info))
#define	ELF64_R_INFO(sym, type)	(((Elf64_Xword)(sym)<<32)+(Elf64_Xword)(type))


/*
 * The r_info field is composed of two 32-bit components: the symbol
 * table index and the relocation type.  The relocation type for SPARC V9
 * is further decomposed into an 8-bit type identifier and a 24-bit type
 * dependent data field.  For the existing Elf32 relocation types,
 * that data field is zero.
 */
#define	ELF64_R_TYPE_DATA(info)	(((Elf64_Xword)(info)<<32)>>40)
#define	ELF64_R_TYPE_ID(info)	(((Elf64_Xword)(info)<<56)>>56)
#define	ELF64_R_TYPE_INFO(data, type)	\
		(((Elf64_Xword)(data)<<8)+(Elf64_Xword)(type))


/*
 * Section Group Flags (SHT_GROUP)
 */
#define	GRP_COMDAT	0x01


/*
 *	Note entry header
 */

typedef struct {
	Elf32_Word	n_namesz;	/* length of note's name */
	Elf32_Word	n_descsz;	/* length of note's "desc" */
	Elf32_Word	n_type;		/* type of note */
} Elf32_Nhdr;

#if defined(_LP64) || defined(_LONGLONG_TYPE)
typedef struct {
	Elf64_Word	n_namesz;	/* length of note's name */
	Elf64_Word	n_descsz;	/* length of note's "desc" */
	Elf64_Word	n_type;		/* type of note */
} Elf64_Nhdr;
#endif	/* defined(_LP64) || defined(_LONGLONG_TYPE) */

/*
 *	Move entry
 */
#if defined(_LP64) || defined(_LONGLONG_TYPE)
typedef struct {
	Elf32_Lword	m_value;	/* symbol value */
	Elf32_Word 	m_info;		/* size + index */
	Elf32_Word	m_poffset;	/* symbol offset */
	Elf32_Half	m_repeat;	/* repeat count */
	Elf32_Half	m_stride;	/* stride info */
} Elf32_Move;

/*
 *	Macros to compose and decompose values for Move.r_info
 *
 *	sym = ELF32_M_SYM(M.m_info)
 *	size = ELF32_M_SIZE(M.m_info)
 *	M.m_info = ELF32_M_INFO(sym, size)
 */
#define	ELF32_M_SYM(info)	((info)>>8)
#define	ELF32_M_SIZE(info)	((unsigned char)(info))
#define	ELF32_M_INFO(sym, size)	(((sym)<<8)+(unsigned char)(size))

typedef struct {
	Elf64_Lword	m_value;	/* symbol value */
	Elf64_Xword 	m_info;		/* size + index */
	Elf64_Xword	m_poffset;	/* symbol offset */
	Elf64_Half	m_repeat;	/* repeat count */
	Elf64_Half	m_stride;	/* stride info */
} Elf64_Move;
#define	ELF64_M_SYM(info)	((info)>>8)
#define	ELF64_M_SIZE(info)	((unsigned char)(info))
#define	ELF64_M_INFO(sym, size)	(((sym)<<8)+(unsigned char)(size))

#endif	/* defined(_LP64) || defined(_LONGLONG_TYPE) */


/*
 *	Capabilities entry, Capabilities info and Capabilities chain.
 */
#ifndef	_ASM
typedef struct {
	Elf32_Word	c_tag;		/* how to interpret value */
	union {
		Elf32_Word	c_val;
		Elf32_Addr	c_ptr;
	} c_un;
} Elf32_Cap;

typedef	Elf32_Word	Elf32_Capinfo;
typedef	Elf32_Word	Elf32_Capchain;

/*
 *	Macros to compose and decompose values for capabilities info.
 *
 *	sym = ELF32_C_SYM(info)
 *	grp = ELF32_C_GROUP(info)
 *	info = ELF32_C_INFO(sym, grp)
 */
#define	ELF32_C_SYM(info)	((info)>>8)
#define	ELF32_C_GROUP(info)	((unsigned char)(info))
#define	ELF32_C_INFO(sym, grp)	(((sym)<<8)+(unsigned char)(grp))


#if defined(_LP64) || defined(_LONGLONG_TYPE)
typedef struct {
	Elf64_Xword	c_tag;		/* how to interpret value */
	union {
		Elf64_Xword	c_val;
		Elf64_Addr	c_ptr;
	} c_un;
} Elf64_Cap;

typedef	Elf64_Xword	Elf64_Capinfo;
typedef	Elf64_Word	Elf64_Capchain;

/*
 *	Macros to compose and decompose values for capabilities info.
 *
 *	sym = ELF64_C_SYM(info)
 *	grp = ELF64_C_GROUP(info)
 *	info = ELF64_C_INFO(sym, grp)
 */
#define	ELF64_C_SYM(info)	((info)>>32)
#define	ELF64_C_GROUP(info)    	((Elf64_Word)(info))
#define	ELF64_C_INFO(sym, grp)	(((Elf64_Xword)(sym)<<32)+(Elf64_Xword)(grp))

#endif	/* defined(_LP64) || defined(_LONGLONG_TYPE) */
#endif

/*
 * Version numbers for SHT_SUNW_capinfo and SHT_SUNW_capchain.
 */
#define	CAPINFO_NONE		0
#define	CAPINFO_CURRENT		1
#define	CAPINFO_NUM		2

#define	CAPCHAIN_NONE		0
#define	CAPCHAIN_CURRENT	1
#define	CAPCHAIN_NUM		2

/*
 * A SHT_SUNW_capinfo table mirrors a symbol table.  A capabilities symbol has
 * a SHT_SUNW_capinfo table entry that provides an index into the associated
 * SHT_SUNW_cap capabilities group, and the symbol index of the associated lead
 * symbol.  A capabilities symbol is a local symbol.  A global lead capabilities
 * symbol is tagged with a group CAPINFO_SUNW_GLOB.
 */
#define	CAPINFO_SUNW_GLOB	0xff

/*
 * Capabilities values.
 */
#define	CA_SUNW_NULL	0
#define	CA_SUNW_HW_1	1		/* first hardware capabilities entry */
#define	CA_SUNW_SF_1	2		/* first software capabilities entry */
#define	CA_SUNW_HW_2	3		/* second hardware capabilities entry */
#define	CA_SUNW_PLAT	4		/* platform capability entry */
#define	CA_SUNW_MACH	5		/* machine capability entry */
#define	CA_SUNW_ID	6		/* capability identifier */
#define	CA_SUNW_NUM	7

/*
 * Define software capabilities (CA_SUNW_SF_1 values).  Note, hardware
 * capabilities (CA_SUNW_HW_1 values) are taken directly from sys/auxv_$MACH.h.
 */
#define	SF1_SUNW_FPKNWN	0x001		/* frame pointer usage is known */
#define	SF1_SUNW_FPUSED	0x002		/* frame pointer is in use */
#define	SF1_SUNW_ADDR32	0x004		/* 32-bit address space requirement */
#define	SF1_SUNW_MASK	0x007		/* known software capabilities mask */

/*
 *	Known values for note entry types (e_type == ET_CORE)
 */
#define	NT_PRSTATUS	1	/* prstatus_t	<sys/old_procfs.h>	*/
#define	NT_PRFPREG	2	/* prfpregset_t	<sys/old_procfs.h>	*/
#define	NT_PRPSINFO	3	/* prpsinfo_t	<sys/old_procfs.h>	*/
#define	NT_PRXREG	4	/* prxregset_t	<sys/procfs.h>		*/
#define	NT_PLATFORM	5	/* string from sysinfo(SI_PLATFORM)	*/
#define	NT_AUXV		6	/* auxv_t array	<sys/auxv.h>		*/
#define	NT_GWINDOWS	7	/* gwindows_t	SPARC only		*/
#define	NT_ASRS		8	/* asrset_t	SPARC V9 only		*/
#define	NT_LDT		9	/* ssd array	<sys/sysi86.h> IA32 only */
#define	NT_PSTATUS	10	/* pstatus_t	<sys/procfs.h>		*/
#define	NT_PSINFO	13	/* psinfo_t	<sys/procfs.h>		*/
#define	NT_PRCRED	14	/* prcred_t	<sys/procfs.h>		*/
#define	NT_UTSNAME	15	/* struct utsname <sys/utsname.h>	*/
#define	NT_LWPSTATUS	16	/* lwpstatus_t	<sys/procfs.h>		*/
#define	NT_LWPSINFO	17	/* lwpsinfo_t	<sys/procfs.h>		*/
#define	NT_PRPRIV	18	/* prpriv_t	<sys/procfs.h>		*/
#define	NT_PRPRIVINFO	19	/* priv_impl_info_t <sys/priv.h>	*/
#define	NT_CONTENT	20	/* core_content_t <sys/corectl.h>	*/
#define	NT_ZONENAME	21	/* string from getzonenamebyid(3C)	*/
#define	NT_FDINFO	22	/* open fd info 			*/
#define	NT_SPYMASTER	23	/* psinfo_t for agent LWP spymaster	*/
#define	NT_SECFLAGS	24	/* process security-flags */
#define	NT_NUM		24


#ifdef _KERNEL
/*
 * The following routine checks the processor-specific
 * fields of an ELF header.
 */
int	elfheadcheck(unsigned char, Elf32_Half, Elf32_Word);
#endif

#ifdef	__cplusplus
}
#endif

#if defined(ELF_TARGET_ALL) || defined(ELF_TARGET_SPARC)
#include <sys/elf_SPARC.h>
#endif

#if defined(ELF_TARGET_ALL) || defined(ELF_TARGET_386)
#include <sys/elf_386.h>
#endif

#if defined(ELF_TARGET_ALL) || defined(ELF_TARGET_AMD64)
#include <sys/elf_amd64.h>
#endif

#endif	/* _SYS_ELF_H */
