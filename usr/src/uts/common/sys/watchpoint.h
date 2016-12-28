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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_WATCHPOINT_H
#define	_SYS_WATCHPOINT_H

#include <sys/types.h>
#include <vm/seg_enum.h>
#include <sys/copyops.h>
#include <sys/avl.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definitions for the VM implementation of watchpoints.
 * See proc(4) and <sys/procfs.h> for definitions of the user interface.
 */

/*
 * Each process with watchpoints has a linked list of watched areas.
 * The list is kept sorted by user-level virtual address.
 */
typedef struct watched_area {
	avl_node_t wa_link;	/* link in AVL tree */
	caddr_t	wa_vaddr;	/* virtual address of watched area */
	caddr_t	wa_eaddr;	/* virtual address plus size */
	ulong_t	wa_flags;	/* watch type flags (see <sys/procfs.h>) */
} watched_area_t;

/*
 * The list of watched areas maps into a list of pages with modified
 * protections.  The list is kept sorted by user-level virtual address.
 */
typedef struct watched_page {
	avl_node_t wp_link;	/* Link in AVL tree */
	struct watched_page *wp_list;	/* link in p_wprot */
	caddr_t	wp_vaddr;	/* virtual address of this page */
	uchar_t	wp_prot;	/* modified protection bits */
	uchar_t	wp_oprot;	/* original protection bits */
	uchar_t	wp_umap[3];	/* reference counts of user pr_mappage()s */
	uchar_t	wp_kmap[3];	/* reference counts of kernel pr_mappage()s */
	ushort_t wp_flags;	/* see below */
	short	wp_read;	/* number of WA_READ areas in this page */
	short	wp_write;	/* number of WA_WRITE areas in this page */
	short	wp_exec;	/* number of WA_EXEC areas in this page */
} watched_page_t;

/* wp_flags */
#define	WP_NOWATCH	0x01	/* protections temporarily restored */
#define	WP_SETPROT	0x02	/* SEGOP_SETPROT() needed on this page */

#ifdef	_KERNEL

/*
 * These functions handle the necessary logic to perform the copy operation
 * while ignoring watchpoints.
 */
extern int copyin_nowatch(const void *, void *, size_t);
extern int copyout_nowatch(const void *, void *, size_t);
extern int fuword32_nowatch(const void *, uint32_t *);
extern int suword32_nowatch(void *, uint32_t);
#ifdef _LP64
extern int suword64_nowatch(void *, uint64_t);
extern int fuword64_nowatch(const void *, uint64_t *);
#endif

/*
 * Disable watchpoints for a given region of memory.  When bracketed by these
 * calls, functions can use copyops and ignore watchpoints.
 */
extern int watch_disable_addr(const void *, size_t, enum seg_rw);
extern void watch_enable_addr(const void *, size_t, enum seg_rw);

/*
 * Enable/Disable watchpoints for an entire thread.
 */
extern	void	watch_enable(kthread_id_t);
extern	void	watch_disable(kthread_id_t);

struct as;
struct proc;
struct k_siginfo;
extern	void	setallwatch(void);
extern	int	pr_is_watchpage(caddr_t, enum seg_rw);
extern	int	pr_is_watchpage_as(caddr_t, enum seg_rw, struct as *);
extern	int	pr_is_watchpoint(caddr_t *, int *, size_t, size_t *,
			enum seg_rw);
extern	void	do_watch_step(caddr_t, size_t, enum seg_rw, int, greg_t);
extern	int	undo_watch_step(struct k_siginfo *);
extern	int	wp_compare(const void *, const void *);
extern	int	wa_compare(const void *, const void *);

extern	struct copyops watch_copyops;

extern watched_area_t *pr_find_watched_area(struct proc *, watched_area_t *,
    avl_index_t *);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_WATCHPOINT_H */
