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
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef _SYS_VMSYSTM_H
#define	_SYS_VMSYSTM_H

#include <sys/proc.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Miscellaneous virtual memory subsystem variables and structures.
 */
#ifdef _KERNEL
extern pgcnt_t	freemem;	/* remaining blocks of free memory */
extern pgcnt_t	avefree;	/* 5 sec moving average of free memory */
extern pgcnt_t	avefree30;	/* 30 sec moving average of free memory */
extern pgcnt_t	deficit;	/* estimate of needs of new swapped in procs */
extern pgcnt_t	nscan;		/* number of scans in last second */
extern pgcnt_t	desscan;	/* desired pages scanned per second */
extern pgcnt_t	slowscan;
extern pgcnt_t	fastscan;
extern pgcnt_t	pushes;		/* number of pages pushed to swap device */

/* writable copies of tunables */
extern pgcnt_t	maxpgio;	/* max paging i/o per sec before start swaps */
extern pgcnt_t	lotsfree;	/* max free before clock freezes */
extern pgcnt_t	desfree;	/* minimum free pages before swapping begins */
extern pgcnt_t	minfree;	/* no of pages to try to keep free via daemon */
extern pgcnt_t	needfree;	/* no of pages currently being waited for */
extern pgcnt_t	throttlefree;	/* point at which we block PG_WAIT calls */
extern pgcnt_t	pageout_reserve; /* point at which we deny non-PG_WAIT calls */
extern pgcnt_t	pages_before_pager; /* XXX */

/*
 * TRUE if the pageout daemon, fsflush daemon or the scheduler.  These
 * processes can't sleep while trying to free up memory since a deadlock
 * will occur if they do sleep.
 */
#define	NOMEMWAIT() (ttoproc(curthread) == proc_pageout || \
			ttoproc(curthread) == proc_fsflush || \
			ttoproc(curthread) == proc_sched)

/* insure non-zero */
#define	nz(x)	((x) != 0 ? (x) : 1)

/*
 * Flags passed by the swapper to swapout routines of each
 * scheduling class.
 */
#define	HARDSWAP	1
#define	SOFTSWAP	2

/*
 * Values returned by valid_usr_range()
 */
#define	RANGE_OKAY	(0)
#define	RANGE_BADADDR	(1)
#define	RANGE_BADPROT	(2)

/*
 * map_pgsz: temporary - subject to change.
 */
#define	MAPPGSZ_VA	0x01
#define	MAPPGSZ_STK	0x02
#define	MAPPGSZ_HEAP	0x04
#define	MAPPGSZ_ISM	0x08

/*
 * Flags for map_pgszcvec
 */
#define	MAPPGSZC_SHM	0x01
#define	MAPPGSZC_PRIVM	0x02
#define	MAPPGSZC_STACK	0x04
#define	MAPPGSZC_HEAP	0x08

/*
 * vacalign values for choose_addr
 */
#define	ADDR_NOVACALIGN	0
#define	ADDR_VACALIGN	1

struct as;
struct page;
struct anon;

extern int maxslp;
extern ulong_t pginrate;
extern ulong_t pgoutrate;
extern void swapout_lwp(klwp_t *);

extern	int valid_va_range(caddr_t *basep, size_t *lenp, size_t minlen,
		int dir);
extern	int valid_va_range_aligned(caddr_t *basep, size_t *lenp,
    size_t minlen, int dir, size_t align, size_t redzone, size_t off);

extern	int valid_usr_range(caddr_t, size_t, uint_t, struct as *, caddr_t);
extern	int useracc(void *, size_t, int);
extern	size_t map_pgsz(int maptype, struct proc *p, caddr_t addr, size_t len,
    int memcntl);
extern	uint_t map_pgszcvec(caddr_t addr, size_t size, uintptr_t off, int flags,
    int type, int memcntl);
extern int choose_addr(struct as *as, caddr_t *addrp, size_t len, offset_t off,
    int vacalign, uint_t flags);
extern	void map_addr(caddr_t *addrp, size_t len, offset_t off, int vacalign,
    uint_t flags);
extern	int map_addr_vacalign_check(caddr_t, u_offset_t);
extern	void map_addr_proc(caddr_t *addrp, size_t len, offset_t off,
    int vacalign, caddr_t userlimit, struct proc *p, uint_t flags);
extern	void vmmeter(void);
extern	int cow_mapin(struct as *, caddr_t, caddr_t, struct page **,
	struct anon **, size_t *, int);

extern	caddr_t	ppmapin(struct page *, uint_t, caddr_t);
extern	void	ppmapout(caddr_t);

extern	int pf_is_memory(pfn_t);

extern	void	dcache_flushall(void);

extern	void	*boot_virt_alloc(void *addr, size_t size);

extern	size_t	exec_get_spslew(void);

extern	caddr_t	map_userlimit(proc_t *pp, struct as *as, int flags);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VMSYSTM_H */
