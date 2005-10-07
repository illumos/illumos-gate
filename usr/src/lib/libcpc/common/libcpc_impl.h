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

#ifndef	_LIBCPC_IMPL_H
#define	_LIBCPC_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libcpc.h>
#include <inttypes.h>
#include <thread.h>
#include <synch.h>
#include <sys/types.h>
#include <sys/cpc_impl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	CPC_VER_1 1
#define	CPC1_BUFSIZE (2 * sizeof (uint64_t))

struct _cpc_attr {
	char			ca_name[CPC_MAX_ATTR_LEN];
	uint64_t		ca_val;
};

typedef struct __cpc_request cpc_request_t;

struct __cpc_request {
	char			cr_event[CPC_MAX_EVENT_LEN];
	uint64_t		cr_preset;	/* Initial value */
	uint16_t		cr_index;	/* Index of request in data */
	uint_t			cr_flags;
	uint_t			cr_nattrs;	/* # CPU-specific attrs */
	kcpc_attr_t		*cr_attr;
	cpc_request_t		*cr_next;	/* next request in set */
};

struct __cpc_buf {
	uint64_t		*cb_data;	/* Pointer to data store */
	hrtime_t		cb_hrtime;	/* hrtime at last sample */
	uint64_t		cb_tick;	/* virtualized tsc/tick */
	size_t			cb_size;	/* Size of data store, bytes */
	cpc_buf_t		*cb_next;	/* List of all bufs */
};

/*
 * Possible cpc_set_t states:
 */
typedef enum {
	CS_UNBOUND,		/* Set is not currently bound */
	CS_BOUND_CURLWP,	/* Set has been bound to curlwp */
	CS_BOUND_PCTX,		/* Set has been bound via libpctx */
	CS_BOUND_CPU		/* Set has been bound to a CPU */
} __cpc_state_t;

struct __cpc_set {
	cpc_request_t		*cs_request;	/* linked list of requests */
	__cpc_state_t		cs_state;	/* State of this set */
	int			cs_nreqs;	/* Number of requests in set */
	int			cs_fd;		/* file descriptor of cpc dev */
	processorid_t		cs_obind;	/* previous proc binding */
	pctx_t			*cs_pctx;	/* pctx of process bound to */
	id_t			cs_id;		/* lwp ID of pctx binding */
	thread_t		cs_thr;		/* thread ID which bound set */
	cpc_set_t		*cs_next;	/* Linked list of all sets */
};

struct __cpc {
	cpc_set_t		*cpc_sets;	/* List of existing sets */
	cpc_buf_t		*cpc_bufs;	/* List of existing bufs */
	cpc_errhndlr_t		*cpc_errfn;	/* Handles library errors */
	mutex_t			cpc_lock;	/* Protect various ops */
	char			*cpc_attrlist;	/* List of supported attrs */
	char			**cpc_evlist;	/* List of events per pic */
	char			cpc_cpuref[CPC_MAX_CPUREF];
	char			cpc_cciname[CPC_MAX_IMPL_NAME];
	uint_t			cpc_caps;
	uint_t			cpc_npic;
};

/*
 * cpc_t handle for CPCv1 clients.
 */
extern cpc_t *__cpc;

/*PRINTFLIKE2*/
extern void __cpc_error(const char *fn, const char *fmt, ...);

extern const char *__cpc_reg_to_name(int cpuver, int regno, uint8_t bits);
extern int __cpc_name_to_reg(int cpuver, int regno,
    const char *name, uint8_t *bits);

extern uint_t __cpc_workver;
extern int __cpc_v1_cpuver;
#ifdef __sparc
extern uint64_t __cpc_v1_pcr;
#else
extern uint32_t __cpc_v1_pes[2];
#endif /* __sparc */

extern char *__cpc_pack_set(cpc_set_t *set, uint_t flags, size_t *buflen);

typedef struct __cpc_strhash cpc_strhash_t;

struct __cpc_strhash {
	char *str;
	struct __cpc_strhash *cur;
	struct __cpc_strhash *next;
};

extern cpc_strhash_t *__cpc_strhash_alloc(void);
extern void __cpc_strhash_free(cpc_strhash_t *hash);
extern int __cpc_strhash_add(cpc_strhash_t *hash, char *key);
extern char *__cpc_strhash_next(cpc_strhash_t *hash);

/*
 * Implementation-private system call used by libcpc
 */
struct __cpc;
extern int __pctx_cpc(pctx_t *pctx, struct __cpc *cpc, int cmd, id_t lwpid,
    void *data1, void *data2, void *data3, int bufsize);

#define	CPUDRV				"/devices/pseudo/cpc@0"
#define	CPUDRV_SHARED			CPUDRV":shared"

#if defined(__sparc) || defined(__i386)
/*
 * These two are only used for backwards compatibility to the Obsolete CPCv1.
 */
extern int __cpc_init(void);
extern cpc_set_t *__cpc_eventtoset(cpc_t *cpc, cpc_event_t *event, int flags);

/*
 * ce_cpuver values
 */
#define	CPC_ULTRA1		1000
#define	CPC_ULTRA2		1001	/* same as ultra1 for these purposes */
#define	CPC_ULTRA3		1002
#define	CPC_ULTRA3_PLUS		1003
#define	CPC_ULTRA3_I		1004
#define	CPC_ULTRA4_PLUS		1005

#define	CPC_PENTIUM		2000
#define	CPC_PENTIUM_MMX		2001
#define	CPC_PENTIUM_PRO		2002
#define	CPC_PENTIUM_PRO_MMX	2003

#define	CPC_SPARC64_III		3000
#define	CPC_SPARC64_V		3002

#endif /* __sparc || __i386 */

#if defined(__i386) || defined(__amd64)
/*
 * This is common between i386 and amd64, because amd64 implements %tick.
 * Currently only used by the cpc tools to print the label atop the CPU ticks
 * column on amd64.
 */
#define	CPC_TICKREG_NAME	"tsc"
#endif /* __i386 || __amd64 */

#if defined(__sparc)

/*
 * UltraSPARC I, II, III and IV processors
 *
 * The performance counters on these processors allow up to two 32-bit
 * performance events to be captured simultaneously from a selection
 * of metrics.   The metrics are selected by writing to the performance
 * control register, and subsequent values collected by reading from the
 * performance instrumentation counter registers.  Both registers are
 * priviliged by default, and implemented as ASRs.
 */

struct _cpc_event {
	int ce_cpuver;
	hrtime_t ce_hrt;	/* gethrtime() */
	uint64_t ce_tick;	/* virtualized %tick */
	uint64_t ce_pic[2];	/* virtualized %pic */
	uint64_t ce_pcr;	/* %pcr */
};

#define	CPC_TICKREG(ev)		((ev)->ce_tick)
#define	CPC_TICKREG_NAME	"%tick"

/*
 * "Well known" bitfields in the UltraSPARC %pcr register
 * The interfaces in libcpc should make these #defines uninteresting.
 */
#define	CPC_ULTRA_PCR_USR		2
#define	CPC_ULTRA_PCR_SYS		1
#define	CPC_ULTRA_PCR_PRIVPIC		0

#define	CPC_ULTRA_PCR_PIC0_SHIFT	4
#define	CPC_ULTRA2_PCR_PIC0_MASK	UINT64_C(0xf)
#define	CPC_ULTRA3_PCR_PIC0_MASK	UINT64_C(0x3f)
#define	CPC_ULTRA_PCR_PIC1_SHIFT	11
#define	CPC_ULTRA2_PCR_PIC1_MASK	UINT64_C(0xf)
#define	CPC_ULTRA3_PCR_PIC1_MASK	UINT64_C(0x3f)

#elif defined(__i386)

/*
 * Pentium I, II and III processors
 *
 * These CPUs allow pairs of events to captured.
 * The hardware counters count up to 40-bits of significance, but
 * only allow 32 (signed) bits to be programmed into them.
 * Pentium I and Pentium II processors are programmed differently, but
 * the resulting counters and timestamps can be handled portably.
 */

struct _cpc_event {
	int ce_cpuver;
	hrtime_t ce_hrt;	/* gethrtime() */
	uint64_t ce_tsc;	/* virtualized rdtsc value */
	uint64_t ce_pic[2];	/* virtualized PerfCtr[01] */
	uint32_t ce_pes[2];	/* Pentium II */
#define	ce_cesr	ce_pes[0]	/* Pentium I */
};

#define	CPC_TICKREG(ev)		((ev)->ce_tsc)

/*
 * "Well known" bit fields in the Pentium CES register
 * The interfaces in libcpc should make these #defines uninteresting.
 */
#define	CPC_P5_CESR_ES0_SHIFT	0
#define	CPC_P5_CESR_ES0_MASK	0x3f
#define	CPC_P5_CESR_ES1_SHIFT	16
#define	CPC_P5_CESR_ES1_MASK	0x3f

#define	CPC_P5_CESR_OS0		6
#define	CPC_P5_CESR_USR0	7
#define	CPC_P5_CESR_CLK0	8
#define	CPC_P5_CESR_PC0		9
#define	CPC_P5_CESR_OS1		(CPC_P5_CESR_OS0 + 16)
#define	CPC_P5_CESR_USR1	(CPC_P5_CESR_USR0 + 16)
#define	CPC_P5_CESR_CLK1	(CPC_P5_CESR_CLK0 + 16)
#define	CPC_P5_CESR_PC1		(CPC_P5_CESR_PC0 + 16)

/*
 * "Well known" bit fields in the Pentium Pro PerfEvtSel registers
 * The interfaces in libcpc should make these #defines uninteresting.
 */
#define	CPC_P6_PES_INV		23
#define	CPC_P6_PES_EN		22
#define	CPC_P6_PES_INT		20
#define	CPC_P6_PES_PC		19
#define	CPC_P6_PES_E		18
#define	CPC_P6_PES_OS		17
#define	CPC_P6_PES_USR		16

#define	CPC_P6_PES_UMASK_SHIFT	8
#define	CPC_P6_PES_UMASK_MASK	(0xffu)

#define	CPC_P6_PES_CMASK_SHIFT	24
#define	CPC_P6_PES_CMASK_MASK	(0xffu)

#define	CPC_P6_PES_PIC0_MASK	(0xffu)
#define	CPC_P6_PES_PIC1_MASK	(0xffu)

#endif /* __i386 */

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBCPC_IMPL_H */
