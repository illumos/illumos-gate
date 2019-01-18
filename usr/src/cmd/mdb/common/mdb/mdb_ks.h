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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2019, Joyent, Inc.
 */

#ifndef	_MDB_KS_H
#define	_MDB_KS_H

#include <sys/types.h>
#include <sys/int_types.h>
#include <sys/stream.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/dumphdr.h>
#include <sys/auxv.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * MDB Kernel Support Interfaces:
 *
 * Debugger modules for kernel crash dumps can make use of these utility
 * functions.  This module also provides support for <mdb/mdb_param.h>.
 */

extern int mdb_vnode2path(uintptr_t, char *, size_t);

extern uintptr_t mdb_page_lookup(uintptr_t, u_offset_t);

extern pfn_t mdb_page2pfn(uintptr_t);
extern uintptr_t mdb_pfn2page(pfn_t);

extern uintptr_t mdb_pid2proc(pid_t, proc_t *);
extern char mdb_vtype2chr(vtype_t, mode_t);
extern uintptr_t mdb_addr2modctl(uintptr_t);

extern ssize_t mdb_read_refstr(uintptr_t, char *, size_t);

extern int mdb_name_to_major(const char *, major_t *);
extern const char *mdb_major_to_name(major_t);

extern int mdb_devinfo2driver(uintptr_t, char *, size_t);
extern int mdb_devinfo2statep(uintptr_t, char *, uintptr_t *);

extern int mdb_cpu2cpuid(uintptr_t);

extern int mdb_cpuset_find(uintptr_t);

extern hrtime_t mdb_gethrtime(void);
extern int64_t mdb_get_lbolt(void);

/*
 * Returns a pointer to the top of the soft state struct for the instance
 * specified, given the address of the global soft state pointer and size
 * of the struct.  Also fills in the buffer pointed to by state_buf_p (if
 * non-NULL) with the contents of the state struct.
 */
extern int mdb_get_soft_state_byaddr(uintptr_t, uint_t, uintptr_t *, void *,
    size_t);

/*
 * Returns a pointer to the top of the soft state struct for the instance
 * specified, given the name of the global soft state pointer and size
 * of the struct.  Also fills in the buffer pointed to by state_buf_p (if
 * non-NULL) with the contents of the state struct.
 */
extern int mdb_get_soft_state_byname(char *, uint_t, uintptr_t *, void *,
    size_t);

/*
 * Returns the pathname from the root devinfo node to the dip supplied.
 * Just like ddi_pathname in sunddi.c.
 */
extern char *mdb_ddi_pathname(uintptr_t, char *, size_t);

/*
 * MDB Kernel STREAMS Subsystem:
 *
 * Debugger modules such as ip can provide facilities for decoding private
 * q_ptr data for STREAMS queues using this mechanism.  The module first
 * registers a set of functions which may be invoked when q->q_qinfo matches
 * a given qinit address (such as ip`winit).  The q_info function provides
 * a way for the module to return an information string about the particular
 * queue.  The q_rnext and q_wnext functions provide a way for the generic
 * queue walker to ask how to proceed deeper in the STREAM when q_next is
 * NULL.  This allows ip, for example, to provide access to the link-layer
 * queues beneath the ip-client queue.
 */

typedef struct mdb_qops {
	void (*q_info)(const queue_t *, char *, size_t);
	uintptr_t (*q_rnext)(const queue_t *);
	uintptr_t (*q_wnext)(const queue_t *);
} mdb_qops_t;

extern void mdb_qops_install(const mdb_qops_t *, uintptr_t);
extern void mdb_qops_remove(const mdb_qops_t *, uintptr_t);

extern char *mdb_qname(const queue_t *, char *, size_t);
extern void mdb_qinfo(const queue_t *, char *, size_t);

extern uintptr_t mdb_qrnext(const queue_t *);
extern uintptr_t mdb_qwnext(const queue_t *);

/*
 * These functions, provided by mdb_ks, may be used to fill in the q_rnext
 * and q_wnext members of mdb_qops_t, in the case where the client wishes
 * to simply return q->q_next:
 */
extern uintptr_t mdb_qrnext_default(const queue_t *);
extern uintptr_t mdb_qwnext_default(const queue_t *);

extern int mdb_mblk_count(const mblk_t *);

/* DLPI primitive to string; returns NULL for unknown primitives */
extern const char *mdb_dlpi_prim(int);

/* Generic function for working with MAC (network layer 2) addresses. */
extern void mdb_mac_addr(const uint8_t *, size_t, char *, size_t);

extern void mdb_print_gitstatus(void);

/*
 * Target-specific interfaces
 *
 * The existence and accessibility of the functions listed below is relied upon
 * by the indicated targets.  The targets look up and invoke these functions in
 * mdb_ks so that dependencies on the current kernel implementation are
 * isolated in mdb_ks.
 */

/*
 * MDB KPROC Target Interface:
 * (user processes from kernel crash dump)
 */

struct mdb_map; /* Private between kproc and ks */

extern int mdb_kproc_asiter(uintptr_t,
    void (*)(const struct mdb_map *, void *), void *);
extern int mdb_kproc_auxv(uintptr_t, auxv_t *);
extern uintptr_t mdb_kproc_as(uintptr_t);
extern pid_t mdb_kproc_pid(uintptr_t);


/*
 * MDB KVM Target Interface:
 * (kernel dump)
 */

extern void mdb_dump_print_content(dumphdr_t *, pid_t);
extern int mdb_dump_find_curproc(void);

/*
 * KMDB Target Interface:
 */
#ifdef _KMDB
extern const mdb_modinfo_t *mdb_ks_init(void);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_KS_H */
