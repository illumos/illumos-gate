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

#ifndef _LIBTOPO_H
#define	_LIBTOPO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/nvpair.h>
#include <stdio.h>

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
 * The following functions, error codes and data structures are private
 * to libtopo snapshot consumers and enumerator modules.
 */
extern topo_hdl_t *topo_open(int, const char *, int *);
extern void topo_close(topo_hdl_t *);
extern char *topo_snap_hold(topo_hdl_t *, const char *, int *);
extern void topo_snap_release(topo_hdl_t *);

/*
 * Snapshot walker support
 */
typedef int (*topo_walk_cb_t)(topo_hdl_t *, tnode_t *, void *);

extern topo_walk_t *topo_walk_init(topo_hdl_t *, const char *, topo_walk_cb_t,
    void *, int *);
extern int topo_walk_step(topo_walk_t *, int);
extern void topo_walk_fini(topo_walk_t *);

/*
 * Walk status returned from walker
 */
#define	TOPO_WALK_ERR		-1
#define	TOPO_WALK_NEXT		0
#define	TOPO_WALK_TERMINATE	1

/*
 * Types of walks: depth-first (child) or breadth-first (sibling)
 */
#define	TOPO_WALK_CHILD		0x0001
#define	TOPO_WALK_SIBLING	0x0002

/*
 * FMRI helper routines
 */
extern int topo_fmri_present(topo_hdl_t *, nvlist_t *, int *);
extern int topo_fmri_contains(topo_hdl_t *, nvlist_t *, nvlist_t *, int *);
extern int topo_fmri_expand(topo_hdl_t *, nvlist_t *, int *);
extern int topo_fmri_unusable(topo_hdl_t *, nvlist_t *, int *);
extern int topo_fmri_nvl2str(topo_hdl_t *, nvlist_t *, char **, int *);
extern int topo_fmri_str2nvl(topo_hdl_t *, const char *, nvlist_t **, int *);
extern int topo_fmri_asru(topo_hdl_t *, nvlist_t *, nvlist_t **, int *);
extern int topo_fmri_fru(topo_hdl_t *, nvlist_t *, nvlist_t **,
    int *);
extern int topo_fmri_label(topo_hdl_t *, nvlist_t *, char **, int *);
extern int topo_fmri_serial(topo_hdl_t *, nvlist_t *, char **, int *);
extern int topo_fmri_compare(topo_hdl_t *, nvlist_t *, nvlist_t *, int *);

/*
 * Topo node utilities: callable from topo_walk_step() callback or module
 * enumeration, topo_mod_enumerate()
 */
extern char *topo_node_name(tnode_t *);
extern topo_instance_t topo_node_instance(tnode_t *);
extern tnode_t *topo_node_parent(tnode_t *);
extern void *topo_node_private(tnode_t *);
extern int topo_node_asru(tnode_t *, nvlist_t **, nvlist_t *, int *);
extern int topo_node_fru(tnode_t *, nvlist_t **, nvlist_t *, int *);
extern int topo_node_resource(tnode_t *, nvlist_t **, int *);
extern int topo_node_label(tnode_t *, char **, int *);
extern int topo_method_invoke(tnode_t *node, const char *, topo_version_t,
    nvlist_t *, nvlist_t **, int *);

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
extern int topo_prop_get_int32_array(tnode_t *, const char *, const char *,
    int32_t **, uint_t *, int *);
extern int topo_prop_get_uint32_array(tnode_t *, const char *, const char *,
    uint32_t **, uint_t *, int *);
extern int topo_prop_get_int64_array(tnode_t *, const char *, const char *,
    int64_t **, uint_t *, int *);
extern int topo_prop_get_uint64_array(tnode_t *, const char *, const char *,
    uint64_t **, uint_t *, int *);
extern int topo_prop_get_string_array(tnode_t *, const char *, const char *,
    char ***, uint_t *, int *);
extern int topo_prop_get_fmri_array(tnode_t *, const char *, const char *,
    nvlist_t ***, uint_t *, int *);

#define	TOPO_PROP_IMMUTABLE	0
#define	TOPO_PROP_MUTABLE	1

/* Protocol property group and property names */
#define	TOPO_PGROUP_PROTOCOL	"protocol"	/* Required property group */
#define	TOPO_PROP_RESOURCE	"resource"	/* resource FMRI */
#define	TOPO_PROP_ASRU		"ASRU"		/* ASRU FMRI */
#define	TOPO_PROP_FRU		"FRU"		/* FRU FMRI */
#define	TOPO_PROP_MOD		"module"	/* software module FMRI */
#define	TOPO_PROP_PKG		"package"	/* software package FMRI */
#define	TOPO_PROP_LABEL		"label"		/*  property LABEL */

/*
 * System property group
 */
#define	TOPO_PGROUP_SYSTEM	"system"
#define	TOPO_PROP_ISA		"isa"
#define	TOPO_PROP_MACHINE	"machine"

/*
 * These enum definitions are used to define a set of error tags associated with
 * libtopo error conditions occuring during the adminstration of
 * properties, invocation of methods and fmri-based queries.  The shell script
 * mkerror.sh is used to parse this file and create a corresponding topo_error.c
 * source file.
 *
 * If you do something other than add a new error tag here, you may need to
 * update the mkerror shell script as it is based upon simple regexps.
 */
typedef enum topo_prop_errno {
    ETOPO_PROP_UNKNOWN = 3000, /* unknown topo prop error */
    ETOPO_PROP_NOENT,   /* undefined property or property group */
    ETOPO_PROP_DEFD,    /* static property already defined */
    ETOPO_PROP_NOMEM,   /* memory limit exceeded during property allocation */
    ETOPO_PROP_TYPE,    /* invalid property type */
    ETOPO_PROP_NAME,    /* invalid property name */
    ETOPO_PROP_NOINHERIT, /* can not inherit property */
    ETOPO_PROP_NVL,	/* malformed property nvlist */
    ETOPO_PROP_METHOD,	/* get property method failed */
    ETOPO_PROP_END	/* end of prop errno list (to ease auto-merge) */
} topo_prop_errno_t;

typedef enum topo_method_errno {
    ETOPO_METHOD_UNKNOWN = 3100, /* unknown topo method error */
    ETOPO_METHOD_INVAL,		/* invalid method registration */
    ETOPO_METHOD_NOTSUP,	/* method not supported */
    ETOPO_METHOD_FAIL,		/* method failed */
    ETOPO_METHOD_VEROLD,	/* app is compiled to use obsolete method */
    ETOPO_METHOD_VERNEW,	/* app is compiled to use obsolete method */
    ETOPO_METHOD_NOMEM,		/* memory limit exceeded during method op */
    ETOPO_METHOD_DEFD,		/* method op already defined */
    ETOPO_METHOD_END		/* end of method errno list */
} topo_method_errno_t;

typedef enum topo_fmri_errno {
    ETOPO_FMRI_UNKNOWN = 3200, /* unknown topo fmri error */
    ETOPO_FMRI_NVL,		/* nvlist allocation failure for FMRI */
    ETOPO_FMRI_VERSION,		/* invalid FMRI scheme version */
    ETOPO_FMRI_MALFORM,		/* malformed FMRI */
    ETOPO_FMRI_NOMEM,		/* memory limit exceeded */
    ETOPO_FMRI_END		/* end of fmri errno list */
} topo_fmri_errno_t;

typedef enum topo_hdl_errno {
    ETOPO_HDL_UNKNOWN = 3300,	/* unknown topo handle error */
    ETOPO_HDL_ABIVER,		/* handle opened with invalid ABI version */
    ETOPO_HDL_SNAP,		/* snapshot already taken */
    ETOPO_HDL_INVAL,		/* invalid argument specified */
    ETOPO_HDL_UUID,		/* uuid already set */
    ETOPO_HDL_NOMEM,		/* memory limit exceeded */
    ETOPO_HDL_END		/* end of handle errno list */
} topo_hdl_errno_t;

extern const char *topo_strerror(int);
extern void topo_hdl_strfree(topo_hdl_t *, char *);
extern void topo_debug_set(topo_hdl_t *, const char *, const char *);

/*
 * The following functions and data structures to support property
 * observability are private to the fmtopo command.
 */

/*
 * Each topology node advertises the name and data stability of each of its
 * modules and properties. (see attributes(5)).
 */

/*
 * Topo stability attributes
 */
typedef enum topo_stability {
	TOPO_STABILITY_UNKNOWN = 0,	/* private to libtopo */
	TOPO_STABILITY_INTERNAL,	/* private to libtopo */
	TOPO_STABILITY_PRIVATE,		/* private to Sun */
	TOPO_STABILITY_OBSOLETE,	/* scheduled for removal */
	TOPO_STABILITY_EXTERNAL,	/* not controlled by Sun */
	TOPO_STABILITY_UNSTABLE,	/* new or rapidly changing */
	TOPO_STABILITY_EVOLVING,	/* less rapidly changing */
	TOPO_STABILITY_STABLE,		/* mature interface from Sun */
	TOPO_STABILITY_STANDARD		/* industry standard */
} topo_stability_t;

#define	TOPO_STABILITY_MAX	TOPO_STABILITY_STANDARD	/* max valid stab */

typedef struct topo_pgroup_info {
	const char *tpi_name;		/* property group name */
	topo_stability_t tpi_namestab;	/* stability of group name */
	topo_stability_t tpi_datastab;	/* stability of all property values */
	topo_version_t tpi_version;	/* version of pgroup definition */
} topo_pgroup_info_t;

extern topo_stability_t topo_name2stability(const char *);
extern const char *topo_stability2name(topo_stability_t);
extern void topo_pgroup_destroy(tnode_t *, const char *);
extern topo_pgroup_info_t *topo_pgroup_info(tnode_t *, const char *, int *);

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
	TOPO_TYPE_FMRI,		/* nvlist_t */
	TOPO_TYPE_INT32_ARRAY,	/* array of int32_t */
	TOPO_TYPE_UINT32_ARRAY,	/* array of uint32_t */
	TOPO_TYPE_INT64_ARRAY,	/* array of int64_t */
	TOPO_TYPE_UINT64_ARRAY,	/* array of uint64_t */
	TOPO_TYPE_STRING_ARRAY,	/* array of const char* */
	TOPO_TYPE_FMRI_ARRAY	/* array of nvlist_t */
} topo_type_t;

extern nvlist_t *topo_prop_getprops(tnode_t *, int *err);
extern int topo_prop_getprop(tnode_t *, const char *, const char *,
    nvlist_t *, nvlist_t **, int *);
extern int topo_prop_getpgrp(tnode_t *, const char *, nvlist_t **, int *);
extern int topo_prop_setprop(tnode_t *, const char *, nvlist_t *,
    int, nvlist_t *, int *);
extern int topo_fmri_getprop(topo_hdl_t *, nvlist_t *, const char *,
    const char *, nvlist_t *,  nvlist_t **, int *);
extern int topo_fmri_getpgrp(topo_hdl_t *, nvlist_t *, const char *,
    nvlist_t **, int *);
extern int topo_fmri_setprop(topo_hdl_t *, nvlist_t *, const char *,
    nvlist_t *, int, nvlist_t *, int *);

/* Property node NVL names used in topo_prop_getprops */
#define	TOPO_PROP_GROUP		"property-group"
#define	TOPO_PROP_GROUP_NAME	"property-group-name"
#define	TOPO_PROP_GROUP_DSTAB	"property-group-data-stability"
#define	TOPO_PROP_GROUP_NSTAB	"property-group-name-stability"
#define	TOPO_PROP_GROUP_VERSION	"property-group-version"
#define	TOPO_PROP_VAL		"property"
#define	TOPO_PROP_VAL_NAME	"property-name"
#define	TOPO_PROP_VAL_VAL	"property-value"
#define	TOPO_PROP_VAL_TYPE	"property-type"
#define	TOPO_PROP_FLAG		"property-flag"

/*
 * ARGS list used in topo property methods
 */
#define	TOPO_PROP_ARGS	"args"
#define	TOPO_PROP_PARGS	"private-args"

extern int topo_xml_print(topo_hdl_t *, FILE *, const char *scheme, int *);

extern void *topo_hdl_alloc(topo_hdl_t *, size_t);
extern void *topo_hdl_zalloc(topo_hdl_t *, size_t);
extern void topo_hdl_free(topo_hdl_t *, void *, size_t);
extern int topo_hdl_nvalloc(topo_hdl_t *, nvlist_t **, uint_t);
extern int topo_hdl_nvdup(topo_hdl_t *, nvlist_t *, nvlist_t **);
extern char *topo_hdl_strdup(topo_hdl_t *, const char *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBTOPO_H */
