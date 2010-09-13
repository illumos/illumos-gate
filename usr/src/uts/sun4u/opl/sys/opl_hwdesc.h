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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_OPL_HWDESC_H
#define	_SYS_OPL_HWDESC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Hardware Descriptor.
 */

#define	HWD_SBS_PER_DOMAIN		32  /* System boards per domain */
#define	HWD_CPUS_PER_CORE		4   /* Strands per physical core */
#define	HWD_CORES_PER_CPU_CHIP		4   /* Cores per processor chip */
#define	HWD_CPU_CHIPS_PER_CMU		4   /* Processor chips per CMU */
#define	HWD_SCS_PER_CMU			4   /* System controllers per CMU */
#define	HWD_DIMMS_PER_CMU		32  /* Memory DIMMs per CMU */
#define	HWD_IOCS_PER_IOU		2   /* Oberon chips per I/O unit */
#define	HWD_PCI_CHANNELS_PER_IOC	2   /* PCI channels per Oberon chip */
#define	HWD_LEAVES_PER_PCI_CHANNEL	2   /* Leaves per PCI channel */
#define	HWD_PCI_CHANNELS_PER_SB		4   /* PCI channels per system board */
#define	HWD_CMU_CHANNEL			4   /* CMU channel number */
#define	HWD_IO_BOATS_PER_IOU		6   /* I/O boats per I/O unit */
#define	HWD_BANKS_PER_CMU		8   /* Memory banks per CMU */
#define	HWD_MAX_MEM_CHUNKS		8   /* Chunks per board */

typedef uint32_t	hwd_stat_t;	/* component status */

/*
 * Values for hwd_stat_t.
 */
#define	HWD_STAT_UNKNOWN	0x0000	/* No status yet */
#define	HWD_STAT_PRESENT	0x0001	/* Present */
#define	HWD_STAT_MISS		0x0002	/* Missing */
#define	HWD_STAT_MISCONFIG	0x0003	/* Misconfigured */
#define	HWD_STAT_PASS		0x0004	/* Ok */
#define	HWD_STAT_FAIL		0x0080	/* Failed by XSCF */
#define	HWD_STAT_FAIL_OBP	0x0081	/* Failed by POST/OBP */
#define	HWD_STAT_FAIL_OS	0x0082	/* Failed by OS */

#define	HWD_STAT_FAILED		0x0080

#define	HWD_MASK_NOT_USED	0x8000	/* If this bit is set, the component */
					/* is not used (even if it presents) */

#define	HWD_STATUS_FAILED(stat)		((stat) & HWD_STAT_FAILED)
#define	HWD_STATUS_OK(stat)		((stat) == HWD_STAT_PASS)
#define	HWD_STATUS_PRESENT(stat)	\
		((stat) & (HWD_STAT_PRESENT | HWD_STAT_PASS))
#define	HWD_STATUS_NONE(stat)			\
		(((stat) == HWD_STAT_UNKNOWN) || ((stat) == HWD_STAT_MISS))

#define	HWD_VERSION_MAJOR	1
#define	HWD_VERSION_MINOR	1

/*
 * Hardware Descriptor Header.
 *
 * Some fields occur repeatedly in different structures:
 *
 * spare*	This field is for future use.
 *
 * filler*	This field is used to show alignment. This could also
 *		be used in the future for something.
 *
 * check_sum	This contains the check sum of the structure it resides in.
 */
typedef struct {
	uint32_t	hdr_magic;		/* magic code ('HWDE') */
	struct hwdesc_version {
		uint16_t	major;
		uint16_t	minor;
	} hdr_version;		/* structure version */

	/*
	 * Domain Identifier. The OPL system can have
	 * upto 24 domains so domain id can be 0 - 23.
	 */
	uint8_t		hdr_domain_id;
	char		hdr_filler[3];

	/*
	 * offsets from the beginning of the header to:
	 * - SB status information (hwd_sb_status_t)
	 * - domain information (hwd_domain_info_t)
	 * - SB information (hwd_sb_info_t).
	 */
	uint32_t	hdr_sb_status_offset;
	uint32_t	hdr_domain_info_offset;
	uint32_t	hdr_sb_info_offset;

	uint32_t	hdr_spare[9];
	uint32_t	hdr_check_sum;
} hwd_header_t;

/*
 * SB Status
 */
typedef struct {
	hwd_stat_t	sb_status[HWD_SBS_PER_DOMAIN];	/* status of all LSBs */
	/* PSB number of respective LSB */
	uint8_t		sb_psb_number[HWD_SBS_PER_DOMAIN];
	uint32_t	sb_spare[7];
	uint32_t	sb_check_sum;
} hwd_sb_status_t;

/*
 * SP -> Domain Information.
 */
typedef struct {
	uint32_t	dinf_reset_factor;	/* domain reset reason */
	uint32_t	dinf_host_id;		/* domain unique id */
	uint64_t	dinf_system_frequency;	/* Hz */
	uint64_t	dinf_stick_frequency;	/* Hz */
	uint32_t	dinf_scf_command_timeout; /* SCF i/f timeout seconds */
	uint32_t	dinf_model_info;	/* FF1/2 DC1/2/3 */
	uint8_t		dinf_mac_address[6];	/* system MAC address */
	uint8_t		dinf_filler1[10];
	uint8_t		dinf_dr_status;		/* 0: DR capable, !0: no DR */
	uint8_t		dinf_filler2[7];
	/*
	 * Specification of degeneracy operation of POST by XSCF
	 *	0x00: off
	 *	0x20: component
	 *	0x40: board
	 *	0x80: system
	 */
	uint8_t		dinf_config_policy;
	/*
	 * Specification of diagnosis operation of POST by XSCF
	 *	0x00: off
	 *	0x20: min
	 *	0x40: max
	 */
	uint8_t		dinf_diag_level;
	/*
	 * Specification of boot operation of OBP by XSCF
	 *	0x00: It follows other settings.
	 *	0x80: Auto boot is not done.
	 */
	uint8_t		dinf_boot_mode;
	uint8_t		dinf_spare1[5];
	int64_t		dinf_cpu_start_time;	/* seconds since the Epoch */
	char		dinf_banner_name[64];	/* system banner string */
	char		dinf_platform_token[64]; /* platform name */
	uint32_t	dinf_floating_board_bitmap;	/* bit 0 = SB0 ... */
	char		dinf_chassis_sn[16];
	uint32_t	dinf_brand_control;
	uint32_t	dinf_spare2[7];
	uint32_t	dinf_check_sum;
} hwd_domain_info_t;

/*
 * CPU Strand
 */
typedef struct {
	hwd_stat_t	cpu_status;
	char		cpu_component_name[32];
	uint16_t	cpu_cpuid;		/* 0x0000, 0x0001, ... 0x01ff */
	uint16_t	cpu_filler;
	uint32_t	cpu_spare[6];
} hwd_cpu_t;

/*
 * CPU Core
 */
typedef struct {
	hwd_stat_t	core_status;
	char		core_component_name[32];
	uint32_t	core_filler1;
	uint64_t	core_frequency;			/* Hz */
	uint64_t	core_config;			/* bus config reg */
	uint64_t	core_version;			/* processor VER */
	uint16_t	core_manufacturer;		/* VER.manuf */
	uint16_t	core_implementation;		/* VER.impl */
	uint8_t		core_mask;			/* VER.mask */
	uint8_t		core_filler2[3];
	uint32_t	core_l1_icache_size;
	uint16_t	core_l1_icache_line_size;
	uint16_t	core_l1_icache_associativity;
	uint32_t	core_num_itlb_entries;
	uint32_t	core_l1_dcache_size;
	uint16_t	core_l1_dcache_line_size;
	uint16_t	core_l1_dcache_associativity;
	uint32_t	core_num_dtlb_entries;
	uint32_t	core_spare1[4];
	uint32_t	core_l2_cache_size;
	uint16_t	core_l2_cache_line_size;
	uint16_t	core_l2_cache_associativity;
	uint32_t	core_l2_cache_sharing;		/* bit N:coreN */
	uint32_t	core_spare2[5];
	hwd_cpu_t	core_cpus[HWD_CPUS_PER_CORE];
	uint32_t	core_spare3[4];
} hwd_core_t;

/*
 * CPU Chip
 */
typedef struct {
	hwd_stat_t	chip_status;
	char		chip_component_name[32]; /* example: "CPU#x" */
	char		chip_fru_name[32];	/* example: "CPU#x" */
	char		chip_compatible[32];	/* example: "FJSV,SPARC64-VI" */
	/*
	 * Jupiter Bus Device ID
	 * 0x0400, 0x0408, ... , 0x05f8
	 */
	uint16_t	chip_portid;
	uint16_t	chip_filler;
	uint32_t	chip_spare1[6];
	hwd_core_t	chip_cores[HWD_CORES_PER_CPU_CHIP];
	uint32_t	chip_spare2[4];
} hwd_cpu_chip_t;

/*
 * SC
 */
typedef struct {
	hwd_stat_t	sc_status;
	uint32_t	sc_filler;
	/*
	 * Top address of SC registers in this XSB
	 */
	uint64_t	sc_register_address;
} hwd_sc_t;

/*
 * Bank
 */
typedef struct {
	hwd_stat_t	bank_status;
	hwd_stat_t	bank_cs_status[2];	/* DIMM pair status */
	uint32_t	bank_filler1;
	uint64_t	bank_register_address;	/* address of mem patrol regs */
	uint8_t		bank_mac_ocd;		/* calibrated MAC OCD value */
	uint8_t		bank_filler2[3];
	uint8_t		bank_dimm_ocd[4][2];	/* calibrated DIMM OCD value */
	uint32_t	bank_tune;		/* for POST use */
	uint32_t	bank_spare[2];
} hwd_bank_t;

/*
 * Chunk
 */
typedef struct {
	uint64_t	chnk_start_address;
	uint64_t	chnk_size;
} hwd_chunk_t;

/*
 * Dimm
 */
typedef struct {
	hwd_stat_t	dimm_status;
	uint32_t	dimm_filler1;
	uint64_t	dimm_capacity;			/* bytes */
	uint64_t	dimm_available_capacity;	/* bytes */
	uint8_t		dimm_rank;			/* 1 or 2 */
	uint8_t		dimm_filler2[7];
	char		dimm_component_name[32];	/* "MEM#xyz" */
	char		dimm_fru_name[32];		/* "MEM#xyz" */
} hwd_dimm_t;

/*
 * CS
 */
typedef struct {
	hwd_stat_t	cs_status;
	uint8_t		cs_number_of_dimms;
	uint8_t		cs_filler[3];
	uint64_t	cs_available_capacity;
	uint64_t	cs_dimm_capacity;
	uint8_t		cs_dimm_badd[8];   /* Value to initialize MAC by POST */
	uint16_t	cs_dimm_add[8];    /* Value to initialize MAC by POST */
	uint8_t		cs_pa_mac_table[64]; /* PA <-> MAC address conversion */
} hwd_cs_t;

/*
 * Memory
 */
typedef struct {
	uint64_t	mem_start_address;	/* Memory start for this LSB */
	uint64_t	mem_size;		/* Memory size for this LSB */
	hwd_bank_t	mem_banks[HWD_BANKS_PER_CMU];
	/*
	 * Mirroring mode:
	 *	0x00 or 0x01
	 *	0x00 : not 'memory mirror mode'
	 *	0x01 : 'memory mirror mode'
	 */
	uint8_t		mem_mirror_mode;	/* mirroring mode */
	/*
	 * Memory configuration:
	 *	0x01 : 1 divided mode
	 *	0x02 : 2 divided mode
	 *	0x04 : 4 divided mode
	 *
	 * It is always set to 0x04 at the XSB mode.
	 */
	uint8_t		mem_division_mode;
	uint8_t		mem_piece_number;	/* 0-3 memory slot group used */
	uint8_t		mem_cs_interleave;	/* 1:cs interleave, 0:not */
	uint32_t	mem_filler[3];
	uint8_t		mem_available_bitmap[512];	/* for POST use */
	uint8_t		mem_degrade_bitmap[16384];	/* for POST use */
	hwd_chunk_t	mem_chunks[HWD_MAX_MEM_CHUNKS];
	hwd_dimm_t	mem_dimms[HWD_DIMMS_PER_CMU];
	hwd_cs_t	mem_cs[2];
} hwd_memory_t;

typedef struct {
	hwd_stat_t	scf_status;
	char		scf_component_name[32];		/* "SCFI#z" */
} hwd_scf_interface_t;

typedef struct {
	hwd_stat_t	tty_status;
	char		tty_component_name[32];		/* "TTY#z" */
} hwd_tty_t;

typedef struct {
	uint8_t		fver_major;		/* firmware major version */
	uint8_t		fver_minor;		/* firmware minor version */
	uint8_t		fver_local;		/* firmware local version */
	uint8_t		fver_filler;
} hwd_fmem_version_t;

typedef struct {
	hwd_stat_t		fmem_status;	/* status of flash */
	char			fmem_component_name[32];
	uint8_t			fmem_used;	/* non-zero: fmem is used */
	uint8_t			fmem_filler[3];
	hwd_fmem_version_t	fmem_version;
	uint32_t		fmem_spare;
} hwd_fmem_t;

/*
 * CMU CH
 */
typedef struct {
	hwd_stat_t		chan_status;
	/*
	 * CMU_CH port ID
	 *	LSB0 is 0x0008, LSB1 is 0x0018, ... , LSB15 is 0x00f8
	 */
	uint16_t		chan_portid;
	uint16_t		chan_filler;
	char			chan_component_name[32];	/* "U2P#z" */
	hwd_scf_interface_t	chan_scf_interface;
	hwd_tty_t		chan_serial;
	hwd_fmem_t		chan_fmem[2];
} hwd_cmu_chan_t;

/*
 * CMU
 */
typedef struct {
	char		cmu_component_name[32];	/* example: "CxS0y" */
	char		cmu_fru_name[32];	/* example: "Cabinet#x-CMU#y" */

	hwd_cpu_chip_t	cmu_cpu_chips[HWD_CPU_CHIPS_PER_CMU];	/* CPU */
	hwd_sc_t	cmu_scs[HWD_SCS_PER_CMU];		/* SC */
	hwd_memory_t	cmu_memory;				/* Memory */
	hwd_cmu_chan_t	cmu_ch;					/* CMU CH */
	uint32_t	cmu_spare[32];
} hwd_cmu_t;

typedef struct {
	hwd_stat_t	slot_status;
	char		slot_name[16];
} hwd_slot_t;

/*
 * IO Boat
 */
typedef struct {
	hwd_stat_t	iob_status;
	char		iob_component_name[32];
	char		iob_fru_name[32];
	/*
	 * IO_Boat type
	 *	0x01 : PCI-X Slot Type
	 *	0x02 : PCI Express Slot Type
	 */
	uint32_t	iob_type;		/* PCI-X or PCI Express */
	uint64_t	iob_io_box_info;	/* location of I/O */
	/*
	 * Information of switch on IO_boat
	 * use only switch_status[0] when PCI-X type IO_boat
	 */
	hwd_stat_t	iob_switch_status[3];	/* PCIE switch statuses */
	/*
	 * Information of bridge on IO_boat
	 * use only when PCI-X type IO_boat
	 */
	hwd_stat_t	iob_bridge_status[3];	/* PCIX bridge statuses */
	hwd_slot_t	iob_slot[6];		/* PCI slot names */
	uint32_t	iob_spare[8];
} hwd_io_boat_t;

/* IOU PCI Express Slot */
typedef struct {
	uint32_t	iou_type;    /* 0: empty, 1: card, 2: IO boat */
	hwd_slot_t	iou_slot;
	hwd_io_boat_t	iou_io_boat;
} hwd_iou_slot_t;

typedef struct {
	hwd_stat_t	ff_onb_switch_status;
	uint8_t		ff_onb_filler[64];
	hwd_stat_t	ff_onb_bridge_status;
	hwd_stat_t	ff_onb_sas_status;
	hwd_stat_t	ff_onb_gbe_status;
	hwd_iou_slot_t	ff_onb_slot;
	hwd_slot_t	ff_onb_xslot;
} hwd_ff_onboard_t;

typedef struct {
	hwd_stat_t	ioua_status; /* IOUA status */
	char		ioua_component_name[32];
	char		ioua_fru_name[32];
	hwd_stat_t	ioua_bridge_status;
	hwd_stat_t	ioua_sas_status;
	hwd_stat_t	ioua_gbe_status;
} hwd_ioua_t;

typedef struct {
	uint8_t		iou_desc_filler[80];
	hwd_iou_slot_t	iou_desc_slot;
} hwd_iou_slot_desc_t;

typedef struct {
	hwd_stat_t	leaf_status;
	uint16_t	leaf_port_id;		/* portid (logical leaf id) */
	uint8_t		leaf_filler[6];
	uint32_t	leaf_slot_type;		/* card or boat */
	union {
		hwd_ff_onboard_t	leaf_ff_onboard;
		hwd_ioua_t		leaf_ioua;
		hwd_iou_slot_desc_t	leaf_iou_slot;
		uint8_t			leaf_spare[448];
	} leaf_u;
	uint64_t	leaf_cfgio_offset;	/* config space offset */
	uint64_t	leaf_cfgio_size;	/* config space size */
	uint64_t	leaf_mem32_offset;	/* offset of mem32 area */
	uint64_t	leaf_mem32_size;	/* size of mem32 area */
	uint64_t	leaf_mem64_offset;	/* offset of mem64 area */
	uint64_t	leaf_mem64_size;	/* size of mem64 area */
} hwd_leaf_t;

/*
 * PCI CH
 */
typedef struct {
	hwd_stat_t	pci_status;		/* PCI CH status */
	char		pci_component_name[32];
	char		pci_fru_name[32];
	uint8_t		pci_filler[12];
	hwd_leaf_t	pci_leaf[HWD_LEAVES_PER_PCI_CHANNEL];
} hwd_pci_ch_t;

/*
 * System Board
 */
typedef struct {
	/*
	 * SB
	 */
	hwd_stat_t	sb_status;
	uint8_t		sb_mode;		/* 0:PSB 1:XSB */
	uint8_t		sb_psb_number;		/* PSB number for this LSB */
	uint8_t		sb_filler1[10];

	hwd_cmu_t	sb_cmu;				/* CMU */

	hwd_pci_ch_t	sb_pci_ch[HWD_PCI_CHANNELS_PER_SB]; /* PCI CH */

	uint32_t	sb_spare[31];
	uint32_t	sb_check_sum;
} hwd_sb_t;

#define	HWD_DATA_SIZE	(36 * 1024)   /* Size of HWD data from SCF */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_OPL_HWDESC_H */
