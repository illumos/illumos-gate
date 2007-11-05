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

#ifndef _SYS_OPL_MODULE_H
#define	_SYS_OPL_MODULE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/async.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * Sets trap table entry ttentry by overwriting eight instructions from ttlabel.
 */
#define	OPL_SET_TRAP(ttentry, ttlabel)					\
		bcopy((const void *)&ttlabel, &ttentry, 32);		\
		flush_instr_mem((caddr_t)&ttentry, 32);

/*
 * The same thing as above, but to patch 7 instructions.
 */
#define	OPL_PATCH_28(ttentry, ttlabel)					\
		bcopy((const void *)&ttlabel, &ttentry, 28);		\
		flush_instr_mem((caddr_t)&ttentry, 28);

/*
 * Define for max size of "reason" string in panic flows.  Since this is on
 * the stack, we want to keep it as small as is reasonable.
 */
#define	MAX_REASON_STRING	40

/*
 * These error types are specific to Olympus and are used internally for the
 * opl fault structure flt_type field.
 */
#define	OPL_CPU_SYNC_UE		1
#define	OPL_CPU_SYNC_OTHERS	2
#define	OPL_CPU_URGENT		3
#define	OPL_CPU_INV_SFSR	4
#define	OPL_CPU_INV_UGESR	5

#ifndef _ASM

/*
 * Define Olympus family (SPARC64-VI) specific asynchronous error structure
 */
typedef struct olympus_async_flt {
	struct async_flt cmn_asyncflt;  /* common - see sun4u/sys/async.h */
	ushort_t flt_type;		/* types of faults - cpu specific */
	uint64_t flt_bit;		/* fault bit for this log msg */
	ushort_t flt_eid_mod;		/* module ID (type of hardware) */
	ushort_t flt_eid_sid;		/* source ID */
} opl_async_flt_t;

/*
 * Error type table struct.
 */
typedef struct ecc_type_to_info {
	uint64_t	ec_afsr_bit;	/* SFSR bit of error */
	char		*ec_reason;	/* Short error description */
	uint_t		ec_flags;	/* Trap type error should be seen at */
	int		ec_flt_type;	/* Used for error logging */
	char		*ec_desc;	/* Long error description */
	uint64_t	ec_err_payload;	/* FM ereport payload information */
	char		*ec_err_class;	/* FM ereport class */
} ecc_type_to_info_t;

/*
 * Redefine fault status bit field definitions taken from
 * "async.h". Reused reserved Ultrasparc3 specific fault status
 * bits here since they are by definition mutually exclusive
 * w.r.t. OPL
 */
#define	OPL_ECC_ISYNC_TRAP	0x0100
#define	OPL_ECC_DSYNC_TRAP	0x0200
#define	OPL_ECC_SYNC_TRAP	(OPL_ECC_ISYNC_TRAP|OPL_ECC_DSYNC_TRAP)
#define	OPL_ECC_URGENT_TRAP	0x0400

#define	TRAP_TYPE_URGENT	0x40

/*
 * Since all the files share a bunch of routines between each other
 * we will put all the "extern" definitions in this header file so that we
 * don't have to repeat it all in every file.
 */

/*
 * functions that are defined in the OPL,SPARC64-VI cpu module:
 */
extern void shipit(int, int);
extern void cpu_page_retire(opl_async_flt_t *opl_flt);
extern void cpu_init_trap(void);
extern void cpu_error_ecache_flush(void);
extern void flush_ecache(uint64_t physaddr, size_t ecachesize, size_t linesize);
extern void stick_adj(int64_t skew);
extern void stick_timestamp(int64_t *ts);
extern void hwblkpagecopy(const void *src, void *dst);
extern void opl_error_setup(uint64_t);
extern void opl_mpg_enable(void);
extern int  cpu_queue_events(opl_async_flt_t *, char *, uint64_t);
extern void ras_cntr_reset(void *);

/*
 * variables and structures that are defined outside the FJSV,SPARC64-VI
 * cpu module:
 */
extern uint64_t xc_tick_limit;
extern uint64_t xc_tick_jump_limit;

/*
 * Labels used for the trap_table patching
 */
extern uint32_t tt0_iae;
extern uint32_t tt1_iae;
extern uint32_t tt0_dae;
extern uint32_t tt1_dae;
extern uint32_t tt0_asdat;
extern uint32_t tt1_asdat;

extern uint32_t tt0_flushw;
extern uint32_t opl_cleanw_patch;

extern void opl_serr_instr(void);
extern void opl_ugerr_instr(void);

extern void opl_ta3_instr(void);
extern void opl_ta4_instr(void);

/*
 * D$ and I$ global parameters.
 */
extern int dcache_size;
extern int dcache_linesize;
extern int icache_size;
extern int icache_linesize;

#endif /* _ASM */

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_OPL_MODULE_H */
