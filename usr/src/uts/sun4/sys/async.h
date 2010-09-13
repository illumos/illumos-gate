/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_ASYNC_H
#define	_SYS_ASYNC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/privregs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_ASM

#include <sys/errorq.h>

/*
 * The async_flt structure is used to record all pertinent information about
 * an asynchronous CPU or bus-related memory error.  Typically, the structure
 * is initialized by a high-level interrupt or trap handler, and then enqueued
 * for later processing.  Separate queues are maintained for correctable and
 * uncorrectable errors.  The current CPU module determines the size of the
 * queue elements, so that it may declare a CPU-specific fault structure
 * which contains a struct async_flt as its first member.  Each async_flt also
 * contains a callback function (flt_func) that is invoked by the processing
 * code in order to actually log messages when the event is dequeued.  This
 * function may be called from a softint, from trap() as part of AST handling
 * before the victim thread returns to userland, or as part of panic().  As
 * such, the flt_func should basically only be calling cmn_err (but NOT with
 * the CE_PANIC flag).  It must not call panic(), acquire locks, or block.
 * The owner of the event is responsible for determining whether the event is
 * fatal; if so, the owner should set flt_panic and panic() after enqueuing
 * the event.  The event will then be dequeued and logged as part of panic
 * processing.  If flt_panic is not set, the queue function will schedule a
 * soft interrupt to process the event.
 */

struct async_flt;
typedef void (*async_func_t)(struct async_flt *, char *);

struct async_flt {
	uint64_t	flt_id;		/* gethrtime() at time of fault */
	uint64_t	flt_stat;	/* async fault status register */
	uint64_t	flt_addr;	/* async fault address register */
	caddr_t		flt_pc;		/* program counter from error trap */
	async_func_t	flt_func;	/* logging function */
	uint_t		flt_bus_id;	/* hardware bus id# of cpu/sbus/pci */
	uint_t		flt_inst;	/* software instance of cpu/sbus/pci */
	ushort_t	flt_status;	/* error information */
	ushort_t	flt_synd;	/* ECC syndrome */
	uchar_t		flt_in_memory;	/* fault occurred in memory if != 0 */
	uchar_t		flt_class;	/* fault class (cpu or bus) */
	uchar_t		flt_prot;	/* type of fault protection (if any) */
	uchar_t		flt_priv;	/* fault occurred in kernel if != 0 */
	uchar_t		flt_panic;	/* fault caused owner to panic() */
	uchar_t		flt_tl;		/* fault occurred at TL > 0 */
	uchar_t		flt_core;	/* fault occurred during core() dump */
	uchar_t		flt_pad;	/* reserved for future use */
	uint64_t	flt_disp;	/* error disposition information */
	uint64_t	flt_payload;	/* ereport payload information */
	char		*flt_erpt_class; /* ereport class string */
};

/*
 * Bus nexus drivers can use the bus_func_register() interface to register
 * callback functions for error handling and panic handling.  The handler
 * functions should be registered and unregistered from driver attach and
 * detach context, where it is safe to perform a sleeping allocation.  The
 * callbacks themselves can be invoked from panic, or from the CPU module's
 * asynchronous trap handler at high PIL.  As such, these routines may only
 * test for errors and enqueue async_flt events.  They may not grab adaptive
 * locks, call panic(), or invoke bus_func_register() or bus_func_unregister().
 * Each callback function should return one of the BF_* return status values
 * below.  The bus_func_invoke() function calls all the registered handlers of
 * the specified type, and returns the maximum of their return values (e.g.
 * BF_FATAL if any callback returned BF_FATAL).  If any callback returns
 * BF_FATAL, the system will panic at the end of callback processing.
 */

typedef	uint_t (*busfunc_t)(void *);

#define	BF_TYPE_UE		1	/* check for uncorrectable errors */
#define	BF_TYPE_ERRDIS		2	/* disable error detection */
#define	BF_TYPE_RESINTR		3	/* reset interrupts */

#define	BF_NONE			0	/* no errors were detected */
#define	BF_NONFATAL		1	/* one or more non-fatal errors found */
#define	BF_FATAL		2	/* one or more fatal errors found */

typedef struct bus_func_desc {
	int bf_type;			/* type of function (see above) */
	busfunc_t bf_func;		/* function to call */
	void *bf_arg;			/* function argument */
	struct bus_func_desc *bf_next;	/* pointer to next registered desc */
} bus_func_desc_t;

extern void bus_func_register(int, busfunc_t, void *);
extern void bus_func_unregister(int, busfunc_t, void *);
extern void bus_async_log_err(struct async_flt *);
extern uint_t bus_func_invoke(int);

extern void ecc_cpu_call(struct async_flt *, char *, int);

extern void ce_scrub(struct async_flt *);
extern void ecc_page_zero(void *);

extern void error_init(void);

extern	int	ce_verbose_memory;
extern	int	ce_verbose_other;
extern	int	ce_show_data;
extern	int	ce_debug;
extern	int	ue_debug;

extern	int	aft_verbose;
extern	int	aft_panic;
extern	int	aft_testfatal;

extern struct async_flt panic_aflt;

extern errorq_t *ce_queue;
extern errorq_t *ue_queue;

#endif	/* !_ASM */

/*
 * ECC or parity error status for async_flt.flt_status.
 */
#define	ECC_C_TRAP		0x0001	/* Trap 0x63 Corrected ECC Error */
#define	ECC_I_TRAP		0x0002	/* Trap 0x0A Instr Access Error */
#define	ECC_ECACHE		0x0004	/* Ecache ECC Error */
#define	ECC_IOBUS		0x0008	/* Pci or sysio ECC Error */
#define	ECC_INTERMITTENT	0x0010	/* Intermittent ECC Error */
#define	ECC_PERSISTENT		0x0020	/* Persistent ECC Error */
#define	ECC_STICKY		0x0040	/* Sticky ECC Error */
#define	ECC_D_TRAP		0x0080	/* Trap 0x32 Data Access Error */
#define	ECC_F_TRAP		0x0100	/* Cheetah Trap 0x70 Fast ECC Error */
#define	ECC_DP_TRAP		0x0200	/* Cheetah+ Trap 0x71 D$ Parity Error */
#define	ECC_IP_TRAP		0x0400	/* Cheetah+ Trap 0x72 I$ Parity Error */
#define	ECC_ITLB_TRAP		0x0800	/* Panther ITLB Parity Error */
#define	ECC_DTLB_TRAP		0x1000	/* Panther DTLB Parity Error */
#define	ECC_IO_CE		0x2000	/* Pci or sysio CE */
#define	ECC_IO_UE		0x4000	/* Pci or sysio UE */

/*
 * Trap type numbers corresponding to the fault types defined above.
 */
#define	TRAP_TYPE_ECC_I		0x0A
#define	TRAP_TYPE_ECC_D		0x32
#define	TRAP_TYPE_ECC_F		0x70
#define	TRAP_TYPE_ECC_C		0x63
#define	TRAP_TYPE_ECC_DP	0x71
#define	TRAP_TYPE_ECC_IP	0x72
#define	TRAP_TYPE_ECC_ITLB	0x08
#define	TRAP_TYPE_ECC_DTLB	0x30
#define	TRAP_TYPE_UNKNOWN	0

/*
 * Fault classes for async_flt.flt_class.
 */
#define	BUS_FAULT		0	/* originating from bus drivers */
#define	CPU_FAULT		1	/* originating from CPUs */
#define	RECIRC_BUS_FAULT	2	/* scheduled diagnostic */
#define	RECIRC_CPU_FAULT	3	/* scheduled diagnostic */

/*
 * Invalid or unknown physical address for async_flt.flt_addr.
 */
#define	AFLT_INV_ADDR	(-1ULL)

/*
 * Fault protection values for async_flt.flt_prot.  The async error handling
 * code may be able to recover from errors when kernel code has explicitly
 * protected itself using one of the mechanisms specified here.
 */
#define	AFLT_PROT_NONE		0	/* no protection active */
#define	AFLT_PROT_ACCESS	1	/* on_trap OT_DATA_ACCESS protection */
#define	AFLT_PROT_EC		2	/* on_trap OT_DATA_EC protection */
#define	AFLT_PROT_COPY		3	/* t_lofault protection (ucopy, etc.) */

/*
 * These flags are used to indicate the validity of certain data based on
 * the various overwrite priority features of the AFSR/AFAR:
 * AFAR, ESYND and MSYND, each of which have different overwrite priorities.
 *
 * Given a specific afsr error bit and the entire afsr, there are three cases:
 *   INVALID:	The specified bit is lower overwrite priority than some other
 *		error bit which is on in the afsr (or IVU/IVC).
 *   VALID:	The specified bit is higher priority than all other error bits
 *		which are on in the afsr.
 *   AMBIGUOUS: Another error bit (or bits) of equal priority to the specified
 *		bit is on in the afsr.
 *
 * NB: The domain-to-SC communications depend on these values. If they are
 * changed, plat_ecc_unum.[ch] must be updated to match.
 */
#define	AFLT_STAT_INVALID	0	/* higher priority afsr bit is on */
#define	AFLT_STAT_VALID		1	/* this is highest priority afsr bit */
#define	AFLT_STAT_AMBIGUOUS	2	/* two afsr bits of equal priority */

/*
 * Maximum length of unum string.
 */
#define	UNUM_NAMLEN	60

/*
 * Maximum length of a DIMM serial id string + null
 */
#define	DIMM_SERIAL_ID_LEN	16

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ASYNC_H */
