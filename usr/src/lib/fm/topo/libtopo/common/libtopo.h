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

#ifndef _LIBTOPO_H
#define	_LIBTOPO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/nvpair.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	TOPO_VERSION	1	/* Library ABI Interface Version */

typedef struct topo_hdl topo_hdl_t;
typedef struct topo_node tnode_t;
typedef struct topo_walk topo_walk_t;
typedef int32_t topo_instance_t;
typedef uint32_t topo_version_t;

/*
 * Topo stability attributes
 *
 * Each topology node advertises the name and data stability of each of its
 * modules and properties. (see attributes(5))
 */

typedef enum topo_stability {
	TOPO_STABILITY_INTERNAL = 0,	/* private to libtopo */
	TOPO_STABILITY_PRIVATE,		/* private to Sun */
	TOPO_STABILITY_OBSOLETE,	/* scheduled for removal */
	TOPO_STABILITY_EXTERNAL,	/* not controlled by Sun */
	TOPO_STABILITY_UNSTABLE,	/* new or rapidly changing */
	TOPO_STABILITY_EVOLVING,	/* less rapidly changing */
	TOPO_STABILITY_STABLE,		/* mature interface from Sun */
	TOPO_STABILITY_STANDARD,	/* industry standard */
	TOPO_STABILITY_MAX		/* end */
} topo_stability_t;

#define	TOPO_STABILITY_MAX   TOPO_STABILITY_STANDARD /* max valid stability */

typedef enum {
	TOPO_TYPE_INVALID = 0,
	TOPO_TYPE_BOOLEAN,	/* boolean */
	TOPO_TYPE_INT32,	/* int32_t */
	TOPO_TYPE_UINT32,	/* uint32_t */
	TOPO_TYPE_INT64,	/* int64_t */
	TOPO_TYPE_UINT64,	/* uint64_t */
	TOPO_TYPE_STRING,	/* const char* */
	TOPO_TYPE_TIME,		/* uint64_t */
	TOPO_TYPE_SIZE,		/* uint64_t */
	TOPO_TYPE_FMRI		/* nvlist_t */
} topo_type_t;

typedef int (*topo_walk_cb_t)(topo_hdl_t *, tnode_t *, void *);

extern topo_hdl_t *topo_open(int, const char *, int *);
extern void topo_close(topo_hdl_t *);
extern char *topo_snap_hold(topo_hdl_t *, const char *, int *);
extern void topo_snap_release(topo_hdl_t *);
extern topo_walk_t *topo_walk_init(topo_hdl_t *, const char *, topo_walk_cb_t,
    void *, int *);
extern int topo_walk_step(topo_walk_t *, int);
extern void topo_walk_fini(topo_walk_t *);

#define	TOPO_WALK_ERR		-1
#define	TOPO_WALK_NEXT		0
#define	TOPO_WALK_TERMINATE	1

#define	TOPO_WALK_CHILD		0x0001
#define	TOPO_WALK_SIBLING	0x0002

extern int topo_fmri_present(topo_hdl_t *, nvlist_t *, int *);
extern int topo_fmri_contains(topo_hdl_t *, nvlist_t *, nvlist_t *, int *);
extern int topo_fmri_unusable(topo_hdl_t *, nvlist_t *, int *);
extern int topo_fmri_nvl2str(topo_hdl_t *, nvlist_t *, char **, int *);
extern int topo_fmri_str2nvl(topo_hdl_t *, const char *, nvlist_t **, int *);
extern int topo_fmri_asru(topo_hdl_t *, nvlist_t *, nvlist_t **, int *);
extern int topo_fmri_fru(topo_hdl_t *, nvlist_t *, nvlist_t **,
    int *);
extern int topo_fmri_compare(topo_hdl_t *, nvlist_t *, nvlist_t *, int *);
extern int topo_fmri_invoke(topo_hdl_t *, nvlist_t *, topo_walk_cb_t, void *,
    int *);
extern nvlist_t *topo_fmri_create(topo_hdl_t *, const char *, const char *,
    topo_instance_t, nvlist_t *, int *);

/*
 * Topo node utilities: callable from topo_walk_step() callback or module
 * enumeration, topo_mod_enumerate()
 */
extern char *topo_node_name(tnode_t *);
extern topo_instance_t topo_node_instance(tnode_t *);
extern void *topo_node_private(tnode_t *);
extern int topo_node_asru(tnode_t *, nvlist_t **, nvlist_t *, int *);
extern int topo_node_fru(tnode_t *, nvlist_t **, nvlist_t *, int *);
extern int topo_node_resource(tnode_t *, nvlist_t **, int *);
extern int topo_node_label(tnode_t *, char **, int *);
extern int topo_node_asru_set(tnode_t *node, nvlist_t *, int, int *);
extern int topo_node_fru_set(tnode_t *node, nvlist_t *, int, int *);
extern int topo_node_label_set(tnode_t *node, char *, int *);
extern int topo_method_invoke(tnode_t *node, const char *, topo_version_t,
    nvlist_t *, nvlist_t **, int *);

extern int topo_pgroup_create(tnode_t *, const char *, topo_stability_t, int *);
extern void topo_pgroup_destroy(tnode_t *, const char *);
extern int topo_prop_get_int32(tnode_t *, const char *, const char *,
    int32_t *, int *);
extern int topo_prop_get_uint32(tnode_t *, const char *, const char *,
    uint32_t *, int *);
extern int topo_prop_get_int64(tnode_t *, const char *, const char *,
    int64_t *, int *);
extern int topo_prop_get_uint64(tnode_t *, const char *, const char *,
    uint64_t *, int *);
extern int topo_prop_get_string(tnode_t *, const char *, const char *,
    char **, int *);
extern int topo_prop_get_fmri(tnode_t *, const char *, const char *,
    nvlist_t **, int *);
extern int topo_prop_set_int32(tnode_t *, const char *, const char *, int,
    int32_t, int *);
extern int topo_prop_set_uint32(tnode_t *, const char *, const char *, int,
    uint32_t, int *);
extern int topo_prop_set_int64(tnode_t *, const char *, const char *,
    int, int64_t, int *);
extern int topo_prop_set_uint64(tnode_t *, const char *, const char *,
    int, uint64_t, int *);
extern int topo_prop_set_string(tnode_t *, const char *, const char *,
    int, const char *, int *);
extern int topo_prop_set_fmri(tnode_t *, const char *, const char *,
    int, const nvlist_t *, int *);
extern int topo_prop_stability(tnode_t *, const char *, topo_stability_t *);
extern nvlist_t *topo_prop_get_all(topo_hdl_t *, tnode_t *);
extern int topo_prop_inherit(tnode_t *, const char *, const char *, int *);

#define	TOPO_PROP_SET_ONCE	0
#define	TOPO_PROP_SET_MULTIPLE	1

#define	TOPO_ASRU_COMPUTE	0x0001  /* Compute ASRU dynamically */
#define	TOPO_FRU_COMPUTE	0x0002  /* Compute FRU dynamically */

/* Protocol property group and property names */
#define	TOPO_PGROUP_PROTOCOL	"protocol"	/* Required property group */
#define	TOPO_PROP_RESOURCE	"resource"	/* resource FMRI */
#define	TOPO_PROP_ASRU		"ASRU"		/* ASRU FMRI */
#define	TOPO_PROP_FRU		"FRU"		/* FRU FMRI */
#define	TOPO_PROP_MOD		"module"	/* software module FMRI */
#define	TOPO_PROP_PKG		"package"	/* software package FMRI */
#define	TOPO_PROP_LABEL		"label"		/*  property LABEL */

/*
 * Legacy TOPO property group: this group supports legacy platform.topo
 * property names
 */
#define	TOPO_PGROUP_LEGACY	"legacy"	/* Legacy property group */
#define	TOPO_PROP_PLATASRU	"PLAT-ASRU"
#define	TOPO_PROP_PLATFRU	"PLAT-FRU"

/*
 * System property group
 */
#define	TOPO_PGROUP_SYSTEM	"system"
#define	TOPO_PROP_PLATFORM	"platform"
#define	TOPO_PROP_ISA		"isa"
#define	TOPO_PROP_MACHINE	"machine"

/* Property node NVL names */
#define	TOPO_PROP_GROUP		"property-group"
#define	TOPO_PROP_GROUP_NAME	"property-group-name"
#define	TOPO_PROP_VAL		"property"
#define	TOPO_PROP_VAL_NAME	"property-name"
#define	TOPO_PROP_VAL_VAL	"property-value"

extern const char *topo_strerror(int);
extern void topo_debug_set(topo_hdl_t *, int, char *);
extern void *topo_hdl_alloc(topo_hdl_t *, size_t);
extern void *topo_hdl_zalloc(topo_hdl_t *, size_t);
extern void topo_hdl_free(topo_hdl_t *, void *, size_t);
extern int topo_hdl_nvalloc(topo_hdl_t *, nvlist_t **, uint_t);
extern int topo_hdl_nvdup(topo_hdl_t *, nvlist_t *, nvlist_t **);
extern char *topo_hdl_strdup(topo_hdl_t *, const char *);
extern void topo_hdl_strfree(topo_hdl_t *, char *);

#define	TOPO_DBG_ERR	0x0001	/* enable error handling debug messages */
#define	TOPO_DBG_MOD	0x0002	/* enable module subsystem debug messages */
#define	TOPO_DBG_LOG	0x0004	/* enable log subsystem debug messages */
#define	TOPO_DBG_WALK	0x0008	/* enable walker subsystem debug messages */
#define	TOPO_DBG_TREE	0x0010	/* enable tree subsystem debug messages */
#define	TOPO_DBG_ALL	0xffff	/* enable all debug modes */

#ifdef __cplusplus
}
#endif

#endif /* _LIBTOPO_H */
