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

#ifndef	_DEVINFO_H
#define	_DEVINFO_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <mdb/mdb_modapi.h>

/*
 * Options for prtconf/devinfo/hotplug dcmd.
 */
#define	DEVINFO_VERBOSE		0x1
#define	DEVINFO_PARENT		0x2
#define	DEVINFO_CHILD		0x4
#define	DEVINFO_ALLBOLD		0x8
#define	DEVINFO_SUMMARY		0x10
#define	DEVINFO_HP_PHYSICAL	0x20
#define	DEVINFO_PIPE		0x40

typedef struct devinfo_cb_data {
	uintptr_t	di_base;
	uint_t		di_flags;
	char 		*di_filter;
} devinfo_cb_data_t;

extern int devinfo_walk_init(mdb_walk_state_t *);
extern int devinfo_walk_step(mdb_walk_state_t *);
extern void devinfo_walk_fini(mdb_walk_state_t *);

extern int devinfo_parents_walk_init(mdb_walk_state_t *);
extern int devinfo_parents_walk_step(mdb_walk_state_t *);
extern void devinfo_parents_walk_fini(mdb_walk_state_t *);

extern int devinfo_children_walk_init(mdb_walk_state_t *);
extern int devinfo_children_walk_step(mdb_walk_state_t *);
extern void devinfo_children_walk_fini(mdb_walk_state_t *);

extern int devinfo2driver(uintptr_t, uint_t, int, const mdb_arg_t *);

extern int devnames_walk_init(mdb_walk_state_t *);
extern int devnames_walk_step(mdb_walk_state_t *);
extern void devnames_walk_fini(mdb_walk_state_t *);

extern int devinfo_siblings_walk_init(mdb_walk_state_t *);
extern int devinfo_siblings_walk_step(mdb_walk_state_t *);

extern int devi_next_walk_step(mdb_walk_state_t *);

extern int prtconf(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int devinfo(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int modctl2devinfo(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int devnames(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int devbindings(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int name2major(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int major2name(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int major2snode(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int dev2major(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int dev2minor(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int dev2snode(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int devt(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int softstate(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int devinfo_fm(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int devinfo_fmce(uintptr_t, uint_t, int, const mdb_arg_t *);

extern int soft_state_walk_init(mdb_walk_state_t *);
extern int soft_state_walk_step(mdb_walk_state_t *);
extern int soft_state_all_walk_step(mdb_walk_state_t *);
extern void soft_state_walk_fini(mdb_walk_state_t *);

extern int devinfo_fmc_walk_init(mdb_walk_state_t *);
extern int devinfo_fmc_walk_step(mdb_walk_state_t *);

extern int binding_hash_walk_init(mdb_walk_state_t *);
extern int binding_hash_walk_step(mdb_walk_state_t *);
extern void binding_hash_walk_fini(mdb_walk_state_t *);
extern int binding_hash_entry(uintptr_t, uint_t, int, const mdb_arg_t *);

extern int devinfo_audit(uintptr_t, uint_t, int, const mdb_arg_t *);

extern int devinfo_audit_log_walk_init(mdb_walk_state_t *);
extern int devinfo_audit_log_walk_step(mdb_walk_state_t *);
extern void devinfo_audit_log_walk_fini(mdb_walk_state_t *);
extern int devinfo_audit_log(uintptr_t, uint_t, int, const mdb_arg_t *);

extern int devinfo_audit_node_walk_init(mdb_walk_state_t *);
extern int devinfo_audit_node_walk_step(mdb_walk_state_t *);
extern void devinfo_audit_node_walk_fini(mdb_walk_state_t *);
extern int devinfo_audit_node(uintptr_t, uint_t, int, const mdb_arg_t *);

extern int minornode_walk_init(mdb_walk_state_t *);
extern int minornode_walk_step(mdb_walk_state_t *);
extern int minornodes(uintptr_t, uint_t, int, const mdb_arg_t *);

extern void prtconf_help(void);
extern void devinfo_help(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _DEVINFO_H */
