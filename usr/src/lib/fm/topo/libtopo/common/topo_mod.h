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

#ifndef _TOPO_MOD_H
#define	_TOPO_MOD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/libtopo.h>
#include <libnvpair.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Enumerator and method supplier module API
 */
typedef struct topo_mod topo_mod_t;

typedef int topo_method_f(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
typedef int topo_enum_f(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *);
typedef void topo_release_f(topo_mod_t *, tnode_t *);

typedef struct topo_method {
	const char *tm_name;			/* Method name */
	const char *tm_desc;			/* Method description */
	const topo_version_t tm_version;	/* Method version */
	const topo_stability_t tm_stability;	/* Attributes of method */
	topo_method_f *tm_func;			/* Method function */
} topo_method_t;

typedef struct topo_mod_info {
	char *tmi_desc;			/* Client module description */
	topo_version_t tmi_version;	/* Client module version */
	topo_enum_f *tmi_enum;		/* enumerator function */
	topo_release_f *tmi_release;	/* de-enumerator function */
} topo_modinfo_t;

extern topo_mod_t *topo_mod_load(topo_mod_t *, const char *);
extern void topo_mod_unload(topo_mod_t *);
extern int topo_mod_register(topo_mod_t *, const topo_modinfo_t *, void *);
extern void topo_mod_unregister(topo_mod_t *);
extern int topo_mod_enumerate(topo_mod_t *, tnode_t *, const char *,
    const char *, topo_instance_t, topo_instance_t);
extern void topo_mod_release(topo_mod_t *, tnode_t *);
extern char *topo_mod_rootdir(topo_mod_t *);
extern void *topo_mod_private(topo_mod_t *);
extern topo_hdl_t *topo_mod_handle(topo_mod_t *);

extern int topo_method_register(topo_mod_t *, tnode_t *, const topo_method_t *);
extern void topo_method_unregister(topo_mod_t *, tnode_t *, const char *);
extern void topo_method_unregister_all(topo_mod_t *, tnode_t *);

/*
 * FMRI methods
 */
#define	TOPO_METH_ASRU_COMPUTE		"topo_asru_compute"
#define	TOPO_METH_FRU_COMPUTE		"topo_fru_compute"
#define	TOPO_METH_FMRI			"topo_fmri"
#define	TOPO_METH_LABEL			"topo_label"
#define	TOPO_METH_NVL2STR		"topo_nvl2str"
#define	TOPO_METH_STR2NVL		"topo_str2nvl"
#define	TOPO_METH_PRESENT		"topo_present"
#define	TOPO_METH_CONTAINS		"topo_contains"
#define	TOPO_METH_UNUSABLE		"topo_unusable"
#define	TOPO_METH_EXPAND		"topo_expand"
#define	TOPO_METH_COMPARE		"topo_compare"

#define	TOPO_METH_FMRI_VERSION			0
#define	TOPO_METH_LABEL_VERSION			0
#define	TOPO_METH_FRU_COMPUTE_VERSION		0
#define	TOPO_METH_ASRU_COMPUTE_VERSION		0
#define	TOPO_METH_NVL2STR_VERSION		0
#define	TOPO_METH_STR2NVL_VERSION		0
#define	TOPO_METH_PRESENT_VERSION		0
#define	TOPO_METH_CONTAINS_VERSION		0
#define	TOPO_METH_UNUSABLE_VERSION		0
#define	TOPO_METH_EXPAND_VERSION		0
#define	TOPO_METH_COMPARE_VERSION		0

#define	TOPO_METH_ASRU_COMPUTE_DESC		"Dynamic ASRU constructor"
#define	TOPO_METH_FRU_COMPUTE_DESC		"Dynamic FRU constructor"
#define	TOPO_METH_FMRI_DESC			"Dynamic FMRI constructor"
#define	TOPO_METH_LABEL_DESC			"Dynamic label discovery"
#define	TOPO_METH_NVL2STR_DESC			"FMRI to string"
#define	TOPO_METH_STR2NVL_DESC			"string to FMRI"
#define	TOPO_METH_PRESENT_DESC			"FMRI is present"
#define	TOPO_METH_CONTAINS_DESC			"FMRI contains sub-FMRI"
#define	TOPO_METH_UNUSABLE_DESC			"FMRI is unusable"
#define	TOPO_METH_EXPAND_DESC			"expand FMRI"
#define	TOPO_METH_COMPARE_DESC			"compare two FMRIs"

#define	TOPO_METH_FMRI_ARG_NAME		"child-name"
#define	TOPO_METH_FMRI_ARG_INST		"child-inst"
#define	TOPO_METH_FMRI_ARG_NVL		"args"
#define	TOPO_METH_FMRI_ARG_PARENT	"parent-fmri"
#define	TOPO_METH_FMRI_ARG_AUTH		"auth"
#define	TOPO_METH_FMRI_ARG_PART		"part"
#define	TOPO_METH_FMRI_ARG_REV		"rev"
#define	TOPO_METH_FMRI_ARG_SER		"serial"

#define	TOPO_METH_LABEL_ARG_NVL		"label-private"
#define	TOPO_METH_LABEL_RET_STR		"label-string"

extern void *topo_mod_alloc(topo_mod_t *, size_t);
extern void *topo_mod_zalloc(topo_mod_t *, size_t);
extern void topo_mod_free(topo_mod_t *, void *, size_t);
extern char *topo_mod_strdup(topo_mod_t *, const char *);
extern void topo_mod_strfree(topo_mod_t *, char *);
extern int topo_mod_nvalloc(topo_mod_t *, nvlist_t **, uint_t);
extern int topo_mod_nvdup(topo_mod_t *, nvlist_t *, nvlist_t **);

extern void topo_mod_clrdebug(topo_mod_t *);
extern void topo_mod_setdebug(topo_mod_t *, int);
extern void topo_mod_dprintf(topo_mod_t *, const char *, ...);
extern const char *topo_mod_errmsg(topo_mod_t *);
extern int topo_mod_errno(topo_mod_t *);

/*
 * Topo node utilities: callable from module enumeration, topo_mod_enumerate()
 */
extern int topo_node_range_create(topo_mod_t *, tnode_t *, const char *,
    topo_instance_t, topo_instance_t);
extern void topo_node_range_destroy(tnode_t *, const char *);
extern tnode_t *topo_node_bind(topo_mod_t *, tnode_t *, const char *,
    topo_instance_t, nvlist_t *, void *);
extern void topo_node_unbind(tnode_t *);

/*
 * This enum definition is used to define a set of error tags associated with
 * the fmd daemon's various error conditions.  The shell script mkerror.sh is
 * used to parse this file and create a corresponding topo_error.c source file.
 * If you do something other than add a new error tag here, you may need to
 * update the mkerror shell script as it is based upon simple regexps.
 */
typedef enum topo_mod_errno {
    EMOD_UNKNOWN = 2000, /* unknown libtopo error */
    EMOD_NOMEM,			/* module memory limit exceeded */
    EMOD_PARTIAL_ENUM,		/* module completed partial enumeration */
    EMOD_METHOD_INVAL,		/* method arguments invalid */
    EMOD_METHOD_NOTSUP,		/* method not supported */
    EMOD_FMRI_NVL,		/* nvlist allocation failure for FMRI */
    EMOD_FMRI_VERSION,		/* invalid FMRI scheme version */
    EMOD_FMRI_MALFORM,		/* malformed FMRI */
    EMOD_VER_OLD,		/* module compiled using an obsolete topo ABI */
    EMOD_VER_NEW,		/* module is compiled using a newer topo ABI */
    EMOD_NVL_INVAL,		/* invalid nvlist */
    EMOD_NONCANON,		/* non-canonical component name requested */
    EMOD_END			/* end of mod errno list (to ease auto-merge) */
} topo_mod_errno_t;

extern int topo_mod_seterrno(topo_mod_t *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _TOPO_MOD_H */
