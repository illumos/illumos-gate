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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MACHCPUVAR_H
#define	_SYS_MACHCPUVAR_H

#include <sys/intr.h>
#include <sys/clock.h>
#include <sys/machparam.h>
#include <sys/machpcb.h>
#include <sys/privregs.h>
#include <sys/machlock.h>
#include <sys/async.h>
#include <sys/error.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_ASM

#include <sys/obpdefs.h>
#include <sys/async.h>
#include <sys/fm/protocol.h>

/*
 * CPU state ptl1_panic save.
 */
typedef struct ptl1_trapregs {
	uint32_t	ptl1_tl;
	uint32_t	ptl1_tt;
	uint64_t	ptl1_tstate;
	uint64_t	ptl1_tpc;
	uint64_t	ptl1_tnpc;
} ptl1_trapregs_t;

typedef struct ptl1_gregs {
	uint64_t	ptl1_gl;
	uint64_t	ptl1_g1;
	uint64_t	ptl1_g2;
	uint64_t	ptl1_g3;
	uint64_t	ptl1_g4;
	uint64_t	ptl1_g5;
	uint64_t	ptl1_g6;
	uint64_t	ptl1_g7;
} ptl1_gregs_t;

typedef struct ptl1_regs {
	ptl1_trapregs_t	ptl1_trap_regs[PTL1_MAXTL];
	ptl1_gregs_t	ptl1_gregs[PTL1_MAXGL + 1];
	uint64_t	ptl1_tick;
	uint64_t	ptl1_dmmu_type;
	uint64_t	ptl1_dmmu_addr;
	uint64_t	ptl1_dmmu_ctx;
	uint64_t	ptl1_immu_type;
	uint64_t	ptl1_immu_addr;
	uint64_t	ptl1_immu_ctx;
	struct rwindow	ptl1_rwindow[MAXWIN];
	uint32_t	ptl1_softint;
	uint16_t	ptl1_pstate;
	uint8_t		ptl1_pil;
	uint8_t		ptl1_cwp;
	uint8_t		ptl1_wstate;
	uint8_t		ptl1_otherwin;
	uint8_t		ptl1_cleanwin;
	uint8_t		ptl1_cansave;
	uint8_t		ptl1_canrestore;
} ptl1_regs_t;

typedef struct ptl1_state {
	ptl1_regs_t	ptl1_regs;
	uint32_t	ptl1_entry_count;
	uintptr_t	ptl1_stktop;
	ulong_t		ptl1_stk[1];
} ptl1_state_t;

/*
 * For cpu_chip and cpu_core in machcpu structure if we cannot get
 * any chip id or core id information from MD.
 */
#define	CPU_CHIPID_INVALID	-1
#define	CPU_COREID_INVALID	-1
#define	CPU_L2_CACHEID_INVALID	-1

/*
 * Machine specific fields of the cpu struct
 * defined in common/sys/cpuvar.h.
 */
struct	machcpu {
	struct machpcb	*mpcb;
	uint64_t	mpcb_pa;
	int		mutex_ready;
	int		in_prom;
	int		tl1_hdlr;
	char		cpu_tstat_flags;	/* tstat flags */
	uint16_t	divisor;	/* Estar %tick clock ratio */
	uint8_t		intrcnt;	/* number of back-to-back interrupts */
	u_longlong_t	tmp1;		/* per-cpu tmps */
	u_longlong_t	tmp2;		/*  used in trap processing */
	u_longlong_t	tmp3;
	u_longlong_t	tmp4;

	label_t		*ofd[HIGH_LEVELS];	/* saved pil ofd */
	uintptr_t	lfd[HIGH_LEVELS];	/* saved ret PC */
	struct on_trap_data *otd[HIGH_LEVELS];	/* saved pil otd */

	struct intr_vec	*intr_head[PIL_LEVELS];	/* intr queue heads per pil */
	struct intr_vec	*intr_tail[PIL_LEVELS];	/* intr queue tails per pil */
	boolean_t	poke_cpu_outstanding;
	/*
	 * The cpu module allocates a private data structure for the
	 * E$ data, which is needed for the specific cpu type.
	 */
	void		*cpu_private;		/* ptr to cpu private data */
	/*
	 * per-MMU ctxdom CPU data.
	 */
	uint_t		cpu_mmu_idx;
	struct mmu_ctx	*cpu_mmu_ctxp;

	ptl1_state_t	ptl1_state;

	uint64_t	pil_high_start[HIGH_LEVELS];	/* high-level intrs */

	/*
	 * intrstat[][] is used to keep track of ticks used at a given pil
	 * level. intrstat[pil][0] is cumulative and exported via kstats.
	 * intrstat[pil][1] is used in intr_get_time() and is private.
	 * 2-dimensional array improves cache locality.
	 */

	uint64_t	intrstat[PIL_MAX+1][2];

	int		kwbuf_full;
	caddr_t		kwbuf_sp;
	struct rwindow	kwbuf;

	caddr_t		cpu_q_va;	/* cpu intrq base VA */
	caddr_t		dev_q_va;	/* dev intrq base VA */
	uint64_t	cpu_q_base_pa;	/* cpu intrq base PA */
	uint64_t	cpu_q_size;
	uint64_t	dev_q_base_pa;	/* dev intrq base PA */
	uint64_t	dev_q_size;
	caddr_t		cpu_rq_va;	/* resumable Q base VA */
	caddr_t		cpu_nrq_va;	/* nonresumable Q base VA */
	uint64_t	cpu_rq_base_pa;	/* resumable Q base PA */
	uint64_t	cpu_rq_size;	/* resumable Q size */
	uint64_t	cpu_nrq_base_pa;	/* nonresumable Q base PA */
	uint64_t	cpu_nrq_size;		/* nonresumable Q size */
	errh_er_t	*cpu_rq_lastre;		/* most recent RE */
	errh_er_t	*cpu_nrq_lastnre;	/* most recent NRE */
	caddr_t		mondo_data;		/* send mondo data */
	uint64_t	mondo_data_ra;		/* mono data pa */
	uint16_t	*cpu_list;		/* uint16_t [NCPU] */
	uint64_t	cpu_list_ra;		/* cpu list ra */
	id_t		cpu_ipipe;		/* cpu int exec unit id */
	id_t		cpu_mpipe;		/* cpu memory pipe id */
	id_t		cpu_fpu;		/* cpu fpu unit id */
	id_t		cpu_core;		/* cpu core id */
	id_t		cpu_chip;		/* cpu chip id */
	kthread_t	*startup_thread;
	uint64_t	cpu_nre_error;		/* nonresumable error */
};

typedef	struct machcpu	machcpu_t;

#define	cpu_startup_thread	cpu_m.startup_thread
#define	CPU_MMU_IDX(cp)		((cp)->cpu_m.cpu_mmu_idx)
#define	CPU_MMU_CTXP(cp)	((cp)->cpu_m.cpu_mmu_ctxp)
#define	NINTR_THREADS	(LOCK_LEVEL)	/* number of interrupt threads */

/*
 * Macro to access the "cpu private" data structure.
 */
#define	CPU_PRIVATE(cp)		((cp)->cpu_m.cpu_private)

/*
 * The OpenBoot Standalone Interface supplies the kernel with
 * implementation dependent parameters through the devinfo/property mechanism
 */
#define	MAXSYSNAME	20

/*
 * Used to indicate busy/idle state of a cpu.
 * msram field will be set with ECACHE_CPU_MIRROR if we are on
 * mirrored sram module.
 */
#define	ECACHE_CPU_IDLE		0x0		/* CPU is idle */
#define	ECACHE_CPU_BUSY		0x1		/* CPU is busy */
#define	ECACHE_CPU_MIRROR 	0x2		/* E$ is mirrored */
#define	ECACHE_CPU_NON_MIRROR	0x3		/* E$ is not mirrored */

/*
 * A CPU FRU FMRI string minus the unum component.
 */
#define	CPU_FRU_FMRI		FM_FMRI_SCHEME_HC":///" \
    FM_FMRI_LEGACY_HC"="

struct cpu_node {
	char	name[MAXSYSNAME];
	char	fru_fmri[sizeof (CPU_FRU_FMRI) + UNUM_NAMLEN];
	int	cpuid;
	pnode_t	nodeid;
	uint64_t	clock_freq;
	uint_t	tick_nsec_scale;
	union {
		int	dummy;
	}	u_info;
	int	ecache_size;
	int	ecache_linesize;
	int	ecache_associativity;
	int	ecache_setsize;
	uint64_t	device_id;
	id_t	exec_unit_mapping;
	id_t	fpu_mapping;
	id_t	l2_cache_mapping;
	id_t	core_mapping;
};

extern struct cpu_node cpunodes[];

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MACHCPUVAR_H */
