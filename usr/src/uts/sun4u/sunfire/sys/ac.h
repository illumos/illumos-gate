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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_AC_H
#define	_SYS_AC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* useful debugging stuff */
#define	AC_ATTACH_DEBUG		0x1
#define	AC_REGISTERS_DEBUG	0x2

/*
 * OBP supplies us with two register sets for the AC nodes. They are:
 *
 *	0		miscellaneous regs
 *	1		Cache tags
 *
 * We do not use the cache tags for anything in the kernel, so we
 * do not map them in.
 */

/* Macros for physical acccess, fhc.h has to be present */
#define	AC_OFFSET		0x00001000000ull
#define	AC_CENTRAL		0x80000000
#define	AC_ARB_FAST		0x00002000
#define	AC_BCSR(board)		(FHC_BOARD_BASE(2*(board)) + FHC_OFFSET + \
				AC_OFFSET + AC_OFF_BCSR)

/* Register set 0 Offsets */
#define	AC_OFF_BRCS		0x10
#define	AC_OFF_BCSR		0x20
#define	AC_OFF_ESR		0x30
#define	AC_OFF_EMR		0x40
#define	AC_OFF_MEMCTL		0x60
#define	AC_OFF_MEMDEC0		0x70
#define	AC_OFF_MEMDEC1		0x80
#define	AC_OFF_UPA0		0x2000
#define	AC_OFF_UPA1		0x4000
#define	AC_OFF_CNTR		0x6000
#define	AC_OFF_MCCR		0x6020

/* Use predefined strings to name the kstats from this driver. */
#define	AC_KSTAT_NAME		"address_controller"
#define	MEMCTL_KSTAT_NAMED	"acmemctl"
#define	MEMDECODE0_KSTAT_NAMED	"acmemdecode0"
#define	MEMDECODE1_KSTAT_NAMED	"acmemdecode1"
#define	CNTR_KSTAT_NAMED	"accounter"
#define	MCCR_KSTAT_NAMED	"acmccr"
#define	BANK_0_KSTAT_NAMED	"acbank0"
#define	BANK_1_KSTAT_NAMED	"acbank1"

/* used for the picN kstats */
#define	AC_NUM_PICS	2
#define	AC_COUNTER_TO_PIC0(CNTR)	((CNTR) & 0xFFFFFFFFULL)
#define	AC_COUNTER_TO_PIC1(CNTR)	((CNTR) >> 32)

/* used to clear/set the pcr */
#define	AC_CLEAR_PCR(PCR)		((PCR) & ~(0x3F3F))
#define	AC_SET_HOT_PLUG(PCR)		((PCR) | (0x3F3F))

/* used for programming the pic */
#define	AC_SET_PIC_BUS_PAUSE(BRD)	(0x80000000LL - 0x9ac4 - ((BRD) << 3))

/* defines for AC Board Configuration and Status Register */
#define	NO_CACHE	0
#define	CACHE_512K	2
#define	CACHE_1M	3
#define	CACHE_2M	4
#define	CACHE_4M	5
#define	CACHE_8M	6
#define	CACHE_16M	7

#define	ARB_MASTER	0x8000
#define	ARB_INIT	0x4000
#define	ARB_FAST	0x2000
#define	FTC_CPAR	0x0200

#define	AC_CSR_REFEN		(1ULL << 27)

/* defines for Memory decode registers */
#define	AC_MEM_VALID		0x8000000000000000ULL

/* size of a memory SIMM group */
#define	RASIZE0(memctl)		(8 << ((((memctl) >> 8) & 0x7) << 1))
#define	RASIZE1(memctl)		(8 << ((((memctl) >> 11) & 0x7) << 1))
#define	RATBL0(memctl)		(((memctl) >> 8) & 0x7)
#define	RATBL1(memctl)		(((memctl) >> 11) & 0x7)

/*
 * Interleave factor of a memory SIMM group.
 * Possible values are 1, 2, 4, 8, and 16. 1 means not interleaved.
 * Larger groups can be interleaved with smaller groups. Groups
 * on the same board can be interleaved as well.
 */
#define	INTLV0(memctl)		(1 << ((memctl) & 0x7))
#define	INTLV1(memctl)		(1 << (((memctl) >> 3) & 0x7))
#define	INTVAL0(memctl)		((memctl) & 0x7)
#define	INTVAL1(memctl)		(((memctl) >> 3) & 0x7)

/*
 * Physical base mask of a memory SIMM group. Note that this is
 * not the real physical base, and is just used to match up the
 * interleaving of groups. The mask bits (UK) are used to mask
 * out the match (UM) field so that the bases can be compared.
 */
#define	GRP_UK(memdec)	(((memdec) >> 39) & 0xFFF)
#define	GRP_UM(memdec)	(((memdec) >> 12) & 0x7FFF)
#define	GRP_BASE(memdec) (GRP_UM(memdec) & ~(GRP_UK(memdec)))
#define	GRP_LK(memdec)	(((memdec) >> 6) & 0xf)
#define	GRP_LM(memdec)	((memdec) & 0xf)
#define	GRP_LBASE(memdec) (GRP_LM(memdec) & ~(GRP_LK(memdec)))
#define	GRP_REALBASE(m) ((GRP_BASE(m) << 26) | (GRP_LBASE(m) << 6))
#define	GRP_UK2SPAN(memdec) ((GRP_UK(memdec) + 1) << 26)
#define	GRP_SPANMB(memdec) (GRP_UK2SPAN(memdec) >> 20)

/*
 * memory states and conditions for sunfire memory system
 */
enum ac_bank_id { Bank0 = 0, Bank1 = 1 };
enum ac_bank_status { StUnknown = 0, StNoMem, StBad, StActive, StSpare };
enum ac_bank_condition { ConUnknown = 0, ConOK, ConFailing, ConFailed,
			ConTest, ConBad };

/*
 * AC memory bank ioctl interface.
 */

/* 'G' (for gigabytes!) does not appear to be used elsewhere in the kernel */
#define	AC_IOC		('G'<<8)

/*
 * For all AC_MEM_ ioctls the arg pointer points to a sysc_cfga_cmd_t
 * except for AC_MEM_ADMIN_VER. The private pointer then points to a
 * structure of the appropriate type, if required.
 */
#define	AC_MEM_ADMIN_VER	(AC_IOC|0)	/* arg is &ac_mem_version_t */
#define	AC_MEM_CONFIGURE	(AC_IOC|1)	/* private == NULL */
#define	AC_MEM_UNCONFIGURE	(AC_IOC|2)	/* private == NULL */
#define	AC_MEM_STAT		(AC_IOC|3)	/* ac_stat_t */
#define	AC_MEM_TEST_START	(AC_IOC|4)	/* ac_mem_test_start_t */
#define	AC_MEM_TEST_STOP	(AC_IOC|5)	/* ac_mem_test_stop_t */
#define	AC_MEM_TEST_READ	(AC_IOC|6)	/* ac_mem_test_read_t */
#define	AC_MEM_TEST_WRITE	(AC_IOC|7)	/* ac_mem_test_write_t */
#define	AC_MEM_EXERCISE		(AC_IOC|128)	/* various */

#define	AC_OUTPUT_LEN		MAXPATHLEN		/* output str len */

typedef enum {
	AC_ERR_DEFAULT = 0,	/* generic errors */
	AC_ERR_INTRANS,		/* hardware in transition */
	AC_ERR_UTHREAD,		/* can't stop user thread */
	AC_ERR_KTHREAD,		/* can't stop kernel thread */
	AC_ERR_SUSPEND,		/* can't suspend a device */
	AC_ERR_RESUME,		/* can't resume a device */
	AC_ERR_POWER,		/* not enough power for slot */
	AC_ERR_COOLING,		/* not enough cooling for slot */
	AC_ERR_PRECHARGE,	/* not enough precharge for slot */
	AC_ERR_HOTPLUG,		/* Hot Plug Unavailable */
	AC_ERR_HW_COMPAT,	/* incompatible hardware found during dr */
	AC_ERR_NON_DR_PROM,	/* prom not support Dynamic Reconfiguration */
	AC_ERR_CORE_RESOURCE,	/* core resource cannot be removed */
	AC_ERR_PROM,		/* error encountered in OBP/POST */
	AC_ERR_DR_INIT,		/* error encountered in sysc_dr_init op */
	AC_ERR_NDI_ATTACH,	/* error encountered in NDI attach operations */
	AC_ERR_NDI_DETACH,	/* error encountered in NDI detach operations */
	AC_ERR_RSTATE,		/* wrong receptacle state */
	AC_ERR_OSTATE,		/* wrong occupant state */
	AC_ERR_COND,		/* invalid condition */
	AC_ERR_BD,		/* invalid board id */
	AC_ERR_BD_TYPE,		/* invalid board type */
	AC_ERR_BD_STATE,	/* invalid board state */
	AC_ERR_MEM_PERM,	/* no write permission */
	AC_ERR_MEM_BK,		/* invalid memory bank */
	AC_ERR_MEM_TEST,	/* invalid memory test id */
	AC_ERR_MEM_TEST_PAR,	/* invalid memory test parameter(s) */
	AC_ERR_KPM_CANCELLED,	/* kphysm_del_cancel (for complete) */
	AC_ERR_KPM_REFUSED,	/* kphysm_pre_del failed (for complete) */
	AC_ERR_KPM_SPAN,	/* memory already in use (add) */
	AC_ERR_KPM_DUP,		/* memory span duplicate (delete) */
	AC_ERR_KPM_FAULT,	/* memory access test failed (add) */
	AC_ERR_KPM_RESOURCE,	/* some resource was not available */
	AC_ERR_KPM_NOTSUP,	/* operation not supported */
	AC_ERR_KPM_NOHANDLES,	/* cannot allocate any more handles */
	AC_ERR_KPM_NONRELOC,	/* non-relocatable pages in span */
	AC_ERR_KPM_HANDLE,	/* bad handle supplied */
	AC_ERR_KPM_BUSY,	/* memory in span is being deleted */
	AC_ERR_KPM_NOTVIABLE,	/* vM viability test failed */
	AC_ERR_KPM_SEQUENCE,	/* function called out of sequence */
	AC_ERR_KPM_NOWORK,	/* no pages to delete */
	AC_ERR_KPM_NOTFINISHED,	/* thread not finished */
	AC_ERR_KPM_NOTRUNNING,	/* thread not running */
	AC_ERR_VMEM,		/* insufficient virtual memory */
	AC_ERR_INTR,		/* delete interrupt by user */
	AC_ERR_TIMEOUT,		/* delete timed out */
	AC_ERR_MEM_DEINTLV	/* could not de-interleave memory */
} ac_err_t;

/*
 * Config admin command structure for AC_MEM ioctls.
 */
typedef struct ac_cfga_cmd {
	uint_t		force:1;	/* force this state transition */
	uint_t		test:1;		/* Need to test hardware */
	int		arg;		/* generic data for test */
	ac_err_t	errtype;	/* error code returned */
	char		*outputstr;	/* output returned from ioctl */
	void		*private;	/* command private data */
} ac_cfga_cmd_t;

typedef struct ac_cfga_cmd32 {
	uint_t		force:1;	/* force this state transition */
	uint_t		test:1;		/* Need to test hardware */
	int		arg;		/* generic data for test */
	ac_err_t	errtype;	/* error code returned */
	caddr32_t	outputstr;	/* output returned from ioctl */
	caddr32_t	private;	/* command private data */
} ac_cfga_cmd32_t;

typedef uint_t ac_mem_version_t;		/* platform interface rev */
#define	AC_MEM_ADMIN_VERSION	1

typedef uint_t mem_test_handle_t;

typedef struct {
	uint64_t		module_id;
	uint64_t		afsr;
	uint64_t		afar;
	uint64_t		udbh_error_reg;
	uint64_t		udbl_error_reg;
} sunfire_processor_error_regs_t;

/*
 * page_size gives the requires size for the read or write buffer.
 * A read can be restricted to one or more line_size units starting
 * at a multiple of line_size units from the start of the page.
 * afar_base is the physical base of the bank being tested so
 * that the afar value can be translated to an offset into the bank.
 */
typedef struct {
	mem_test_handle_t	handle;
	pid_t			tester_pid;	/* PID of test starter */
	sysc_cfga_cond_t	prev_condition;
	u_longlong_t		bank_size;	/* bytes */
	uint_t			page_size;	/* bytes */
	uint_t			line_size;	/* bytes */
	u_longlong_t		afar_base;
} ac_mem_test_start_t;

typedef struct {
	mem_test_handle_t	handle;
	sysc_cfga_cond_t	condition;
} ac_mem_test_stop_t;

/*
 * line_offset is in the range 0 - (page_size/line_size)-1
 * line_count is in the range 1 - (page_size/line_size)
 */
typedef struct {
	u_longlong_t		page_num;
	uint_t			line_offset;
	uint_t			line_count;
} ac_test_addr_t;

/*
 * Data will be transferred in/out of the buffer at:
 * 		(page_buf + (line_offset*line_size))
 */
typedef struct {
	mem_test_handle_t	handle;
	void			*page_buf;
	ac_test_addr_t		address;
	sunfire_processor_error_regs_t	*error_buf;
} ac_mem_test_read_t;

typedef struct {
	mem_test_handle_t	handle;
	void			*page_buf;
	ac_test_addr_t		address;
} ac_mem_test_write_t;

#ifdef _SYSCALL32

/* Kernel's view of ILP32 structure version. */

typedef struct {
	mem_test_handle_t	handle;
	caddr32_t		page_buf;		/* void * */
	ac_test_addr_t		address;
	caddr32_t		error_buf; /* sunfire_processor_error_regs_t */
} ac_mem_test_read32_t;

typedef struct {
	mem_test_handle_t	handle;
	caddr32_t		page_buf;		/* void * */
	ac_test_addr_t		address;
} ac_mem_test_write32_t;

#endif /* _SYSCALL32 */

/* structure returned from AC_MEM_STAT ioctl */
typedef struct {
	sysc_cfga_rstate_t	rstate;
	sysc_cfga_ostate_t	ostate;
	sysc_cfga_cond_t	condition;
	time_t			status_time;
	uint_t			board;
	uint_t			real_size;
	uint_t			use_size;
	uint_t			busy;		/* add/delete in progress */
	uint_t			page_size;	/* bytes */
	uint64_t		phys_pages;
	uint64_t		managed;
	uint64_t		nonrelocatable;
	/* to supply address, group, info */
	uint64_t		ac_memctl;
	uint64_t		ac_decode0;
	uint64_t		ac_decode1;
} ac_stat_t;

#ifdef _SYSCALL32

/* Kernel's view of ILP32 structure version. */

typedef struct {
	sysc_cfga_rstate_t	rstate;
	sysc_cfga_ostate_t	ostate;
	sysc_cfga_cond_t	condition;
	time32_t		status_time;
	uint_t			board;
	uint_t			real_size;
	uint_t			use_size;
	uint_t			busy;		/* add/delete in progress */
	uint_t			page_size;	/* bytes */
	uint64_t		phys_pages;
	uint64_t		managed;
	uint64_t		nonrelocatable;
	/* to supply address, group, info */
	uint64_t		ac_memctl;
	uint64_t		ac_decode0;
	uint64_t		ac_decode1;
} ac_stat32_t;

#endif /* _SYSCALL32 */

/* Command values in cmd_cfga.arg for the AC_MEM_EXERCISE ioctl. */
#define	AC_MEMX_RELOCATE_ALL	0

/* Stats structure for AC_MEMX_RELOCATE_ALL (cmd_cfga.private != NULL). */
struct ac_memx_relocate_stats {
	uint_t		base;
	uint_t		npgs;
	uint_t		nopaget;
	uint_t		nolock;
	uint_t		isfree;
	uint_t		reloc;
	uint_t		noreloc;
};

/* End of ioctl interface. */

#if defined(_KERNEL)

typedef struct {
	ac_cfga_cmd_t	cmd_cfga;
	char		*errbuf;	/* internal error buffer */
	struct ac_soft_state *softsp;
	uint_t		bank;		/* Decoded bank number. */
} ac_cfga_pkt_t;

#define	AC_ERR_SET(pkt, err)	(pkt)->cmd_cfga.errtype = (err)

#define	MEM_BOARD_VISIBLE(BD) \
		((BD)->sc.rstate == SYSC_CFGA_RSTATE_CONNECTED && \
		(BD)->sc.ostate == SYSC_CFGA_OSTATE_CONFIGURED)

#ifndef	TRUE
#define	TRUE (1)
#endif
#ifndef	FALSE
#define	FALSE (0)
#endif

#define	AC_BANK0_STATUS		"bank-0-status"
#define	AC_BANK1_STATUS		"bank-1-status"
#define	AC_BANK_NOMEM		"nomem"
#define	AC_BANK_OK		"ok"
#define	AC_BANK_SPARE		"spare"
#define	AC_BANK_FAILED		"failed"

/*
 * Test for a valid size setting. The size must be set as
 * a contiguous number of bits starting at the least significant bit.
 * Adding one to such a number causes a carry to be propagated to
 * the first zero bit, eg 00111 -> 01000. Thus for a correctly
 * formed value, the AND of the two numbers is 0.
 */
#define	GRP_SIZE_IS_SET(memdec)	((GRP_UK(memdec) & (GRP_UK(memdec) + 1)) == 0)

/* set the decode register bits according to the desired bank layout */
#define	SETUP_DECODE(addr, mb, intlv, group) \
	((((addr) >> 26) & 0x7fffULL) << 12) |			/* UM */ \
	((((mb) >> 6) - 1ULL) << 39) |				/* UK */ \
	((group) & 0xfULL) |					/* LM */ \
	((0xfULL << (intlv) & 0xfULL) << 6)			/* LK */

/*
 * Driver minor number macros.
 */
#define	AC_GETINSTANCE(M)	((M) >> 1)
#define	AC_GETBANK(M)		((M) & 1)
#define	AC_PUTINSTANCE(I)	((I) << 1)

/*
 * Attachment point names.
 */
#define	NAME_BANK0	"bank0"
#define	NAME_BANK1	"bank1"

/*
 * Memory Database
 * This information is generally accessed through the bd_list so we will
 * just protect it by that for now.
 */
struct ac_mem_info {
	int busy;				/* A bank is in transition */
	time_t status_change;			/* Time of last change */

	sysc_cfga_rstate_t rstate;
	sysc_cfga_ostate_t ostate;
	sysc_cfga_cond_t condition;
	uint_t real_size;			/* Real size in MB of bank */
	uint_t use_size;			/* In use size in MB */
};

/* Structures used in the driver to manage the hardware */
struct ac_soft_state {
	dev_info_t *dip;	/* dev info of myself */
	dev_info_t *pdip;	/* dev info of my parent */
	int board;		/* Board number for this AC */

	/* fields protected by bd_list lock */
	struct ac_mem_info bank[2];	/* memory bank information */

	/* Mapped addresses of registers */
	void *ac_base;		/* Base address of Address Controller */
	volatile uint32_t *ac_id;		/* ID register */
	volatile uint64_t *ac_memctl;		/* Memory Control */
	volatile uint64_t *ac_memdecode0;	/* Memory Decode 0 */
	volatile uint64_t *ac_memdecode1;	/* Memory Decode 1 */
	volatile uint64_t *ac_counter;		/* AC counter register */
	volatile uint32_t *ac_mccr;		/* AC Counter control */
	kstat_t *ac_ksp;
	kstat_t	*ac_counters_ksp;		/* performance counter kstat */
};

extern void	ac_blkcopy(caddr_t, caddr_t, uint_t, uint_t);
extern void	ac_mapin(uint64_t, caddr_t);
extern void	ac_unmap(caddr_t);

/* kstat structure used by ac to pass data to user programs. */
struct ac_kstat {
	struct kstat_named ac_memctl;		/* AC Memory control */
	struct kstat_named ac_memdecode0;	/* AC Memory Decode Bank 0 */
	struct kstat_named ac_memdecode1;	/* AC Memory Decode Bank 1 */
	struct kstat_named ac_mccr;		/* AC Mem Counter Control */
	struct kstat_named ac_counter;		/* AC Counter */
	struct kstat_named ac_bank0_status;
	struct kstat_named ac_bank1_status;
};

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AC_H */
