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

#ifndef	_FASTTRAP_IMPL_H
#define	_FASTTRAP_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/dtrace.h>
#include <sys/proc.h>
#include <sys/fasttrap.h>
#include <sys/fasttrap_isa.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Interfaces for fasttrap_isa.c to consume.
 */
typedef struct fasttrap_provider fasttrap_provider_t;

struct fasttrap_provider {
	pid_t ftp_pid;				/* process ID for this prov. */
	char ftp_name[DTRACE_PROVNAMELEN];	/* prov. name (w/o the pid) */
	dtrace_provider_id_t ftp_provid;	/* DTrace provider handle */
	uint_t ftp_marked;			/* mark for possible removal */
	uint_t ftp_defunct;			/* denotes a lame duck prov. */
	kmutex_t ftp_mtx;			/* provider lock */
	uint64_t ftp_rcount;			/* enabled probes ref count */
	uint64_t ftp_ccount;			/* consumers creating probes */
	fasttrap_provider_t *ftp_next;		/* next prov. in hash chain */
};

typedef struct fasttrap_id fasttrap_id_t;
typedef struct fasttrap_probe fasttrap_probe_t;
typedef struct fasttrap_tracepoint fasttrap_tracepoint_t;

struct fasttrap_id {
	fasttrap_probe_t *fti_probe;		/* referrring probe */
	fasttrap_id_t *fti_next;		/* enabled probe list on tp */
};

typedef struct fasttrap_id_tp {
	fasttrap_id_t fit_id;
	fasttrap_tracepoint_t *fit_tp;
} fasttrap_id_tp_t;

struct fasttrap_probe {
	dtrace_id_t ftp_id;			/* DTrace probe identifier */
	pid_t ftp_pid;				/* pid for this probe */
	fasttrap_provider_t *ftp_prov;		/* this probe's provider */
	uintptr_t ftp_faddr;			/* associated function's addr */
	size_t ftp_fsize;			/* associated function's size */
	fasttrap_probe_type_t ftp_type;		/* type of probe */
	uint_t ftp_enabled;			/* is this probe enabled */
	uint64_t ftp_gen;			/* modification generation */
	uint64_t ftp_ntps;			/* number of tracepoints */
	uint8_t *ftp_argmap;			/* native to translated args */
	uint8_t ftp_nargs;			/* translated argument count */
	char *ftp_xtypes;			/* translated types index */
	char *ftp_ntypes;			/* native types index */
	fasttrap_id_tp_t ftp_tps[1];		/* flexible array */
};

#define	FASTTRAP_ID_INDEX(id)	\
((fasttrap_id_tp_t *)(((char *)(id) - offsetof(fasttrap_id_tp_t, fit_id))) - \
&(id)->fti_probe->ftp_tps[0])

struct fasttrap_tracepoint {
	fasttrap_provider_t	*ftt_prov;	/* tracepoint's provider */
	uintptr_t		ftt_pc;		/* address of tracepoint */
	pid_t			ftt_pid;	/* pid of tracepoint */
	fasttrap_machtp_t	ftt_mtp;	/* ISA-specific portion */
	fasttrap_id_t		*ftt_ids;	/* NULL-terminated list */
	fasttrap_id_t		*ftt_retids;	/* NULL-terminated list */
	fasttrap_tracepoint_t	*ftt_next;	/* link in global hash */
};

typedef struct fasttrap_bucket {
	kmutex_t		ftb_mtx;
	void 			*ftb_data;

	uint8_t		ftb_pad[64 - sizeof (kmutex_t) - sizeof (void *)];
} fasttrap_bucket_t;

typedef struct fasttrap_hash {
	ulong_t			fth_nent;
	ulong_t			fth_mask;
	fasttrap_bucket_t	*fth_table;
} fasttrap_hash_t;

/*
 * If at some future point these assembly functions become observable by
 * DTrace, then these defines should become separate functions so that the
 * fasttrap provider doesn't trigger probes during internal operations.
 */
#define	fasttrap_copyout	copyout
#define	fasttrap_fuword32	fuword32
#define	fasttrap_suword32	suword32

#define	fasttrap_fulword	fulword
#define	fasttrap_sulword	sulword

extern void fasttrap_sigtrap(proc_t *, kthread_t *, uintptr_t);

extern dtrace_id_t 		fasttrap_probe_id;
extern fasttrap_hash_t		fasttrap_tpoints;

#define	FASTTRAP_TPOINTS_INDEX(pid, pc) \
	(((pc) / sizeof (fasttrap_instr_t) + (pid)) & fasttrap_tpoints.fth_mask)

/*
 * Must be implemented by fasttrap_isa.c
 */
extern int fasttrap_tracepoint_init(proc_t *, fasttrap_probe_t *,
    fasttrap_tracepoint_t *, uintptr_t);
extern int fasttrap_tracepoint_install(proc_t *, fasttrap_tracepoint_t *);
extern int fasttrap_tracepoint_remove(proc_t *, fasttrap_tracepoint_t *);

extern int fasttrap_probe(struct regs *);
extern int fasttrap_pid_probe(struct regs *);
extern int fasttrap_return_probe(struct regs *);

extern uint64_t fasttrap_getarg(void *, dtrace_id_t, void *, int, int);
extern uint64_t fasttrap_usdt_getarg(void *, dtrace_id_t, void *, int, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _FASTTRAP_IMPL_H */
