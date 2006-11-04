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

#ifndef _TOPO_MODULE_H
#define	_TOPO_MODULE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/topo_mod.h>

#include <topo_list.h>
#include <topo_tree.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct topo_imodops {
	int (*mop_init)(struct topo_mod *, topo_version_t version);
	int (*mop_fini)(struct topo_mod *);
} topo_imodops_t;

#define	TOPO_HASH_BUCKETS	3

struct topo_modhash {
	pthread_mutex_t mh_lock;	/* hash lock */
	struct topo_mod **mh_hash;	/* hash bucket array */
	uint_t mh_hashlen;		/* size of hash bucket array */
	uint_t mh_nelems;		/* number of modules in hash */
};

typedef struct topo_imod_info {
	char *tmi_desc;			/* module description */
	char *tmi_scheme;		/* enumeration scheme-type */
	topo_version_t tmi_version;	/* module version */
	topo_modops_t *tmi_ops;		/* module ops vector */
} topo_imodinfo_t;

struct topo_mod {
	pthread_mutex_t tm_lock;	/* Lock for tm_cv/owner/flags/refs */
	pthread_cond_t tm_cv;		/* Module condition variable */
	uint_t tm_busy;			/* Busy indicator */
	struct topo_mod *tm_next;	/* Next module in hash chain */
	topo_hdl_t *tm_hdl;		/* Topo handle for this module */
	topo_alloc_t *tm_alloc;		/* Allocators */
	char *tm_name;			/* Basename of module */
	char *tm_path;			/* Full pathname of module file */
	char *tm_rootdir;		/* Relative root directory of module */
	void *tm_priv;			/* Module private data */
	uint_t tm_refs;			/* Module reference count */
	uint_t tm_flags;		/* Miscellaneous flags (see below) */
	uint_t tm_debug;		/* Debug printf mask */
	void *tm_data;			/* Private rtld/builtin data */
	topo_imodops_t *tm_mops;	/* Module class ops vector */
	topo_imodinfo_t *tm_info;	/* Module info registered with handle */
	int tm_errno;			/* Module error */
};

#define	TOPO_MOD_INIT	0x001		/* Module init completed */
#define	TOPO_MOD_FINI	0x002		/* Module fini completed */
#define	TOPO_MOD_REG	0x004		/* topo_modinfo_t registered */
#define	TOPO_MOD_UNREG	0x008		/* Module unregistered */

extern const topo_imodops_t topo_rtld_ops;

extern void topo_mod_enter(topo_mod_t *);
extern void topo_mod_exit(topo_mod_t *);
extern void topo_mod_hold(topo_mod_t *);
extern void topo_mod_rele(topo_mod_t *);

extern topo_modhash_t *topo_modhash_create(topo_hdl_t *);
extern void topo_modhash_destroy(topo_hdl_t *);
extern topo_mod_t *topo_modhash_lookup(topo_modhash_t *, const char *);
extern topo_mod_t *topo_modhash_load(topo_hdl_t *, const char *, const char *,
    const topo_imodops_t *, topo_version_t);
extern void topo_modhash_unload(topo_mod_t *);
extern void topo_modhash_unload_all(topo_hdl_t *);

extern void topo_mod_release(topo_mod_t *, tnode_t *);
extern topo_mod_t *topo_mod_lookup(topo_hdl_t *, const char *, int);

#ifdef __cplusplus
}
#endif

#endif	/* _TOPO_MODULE_H */
