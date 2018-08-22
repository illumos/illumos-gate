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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2018, Joyent, Inc. All rights reserved.
 */

#ifndef _TOPO_MOD_H
#define	_TOPO_MOD_H

#include <fm/libtopo.h>
#include <fm/topo_hc.h>
#include <libipmi.h>
#include <libnvpair.h>
#include <libdevinfo.h>
#include <smbios.h>
#include <pcidb.h>

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
    topo_instance_t, void *, void *);
typedef void topo_release_f(topo_mod_t *, tnode_t *);

typedef struct topo_method {
	const char *tm_name;			/* Method name */
	const char *tm_desc;			/* Method description */
	const topo_version_t tm_version;	/* Method version */
	const topo_stability_t tm_stability;	/* Attributes of method */
	topo_method_f *tm_func;			/* Method function */
} topo_method_t;

typedef struct topo_modops {
	topo_enum_f *tmo_enum;		/* enumeration op */
	topo_release_f *tmo_release;	/* resource release op */
} topo_modops_t;

typedef struct topo_mod_info {
	const char *tmi_desc;		/* module description */
	const char *tmi_scheme;		/* enumeration scheme type  */
	topo_version_t tmi_version;	/* module version */
	const topo_modops_t *tmi_ops;	/* module ops vector */
} topo_modinfo_t;

extern topo_mod_t *topo_mod_load(topo_mod_t *, const char *, topo_version_t);
extern void topo_mod_unload(topo_mod_t *);
extern int topo_mod_register(topo_mod_t *, const topo_modinfo_t *,
    topo_version_t);
extern void topo_mod_unregister(topo_mod_t *);
extern int topo_mod_enumerate(topo_mod_t *, tnode_t *, const char *,
    const char *, topo_instance_t, topo_instance_t, void *);
extern int topo_mod_enummap(topo_mod_t *mod, tnode_t *, const char *,
    const char *);
extern void topo_mod_release(topo_mod_t *, tnode_t *);
extern void topo_mod_setspecific(topo_mod_t *, void *);
extern void *topo_mod_getspecific(topo_mod_t *);

extern nvlist_t *topo_mod_cpufmri(topo_mod_t *, int, uint32_t, uint8_t,
    const char *);
extern nvlist_t *topo_mod_devfmri(topo_mod_t *, int, const char *,
    const char *);
extern nvlist_t *topo_mod_hcfmri(topo_mod_t *, tnode_t *, int, const char *,
    topo_instance_t, nvlist_t *, nvlist_t *, const char *, const char *,
    const char *);
extern nvlist_t *topo_mod_memfmri(topo_mod_t *, int, uint64_t, uint64_t,
    const char *, int);
extern nvlist_t *topo_mod_modfmri(topo_mod_t *, int, const char *);
extern nvlist_t *topo_mod_pkgfmri(topo_mod_t *, int, const char *);
extern nvlist_t *topo_mod_swfmri(topo_mod_t *, int,
    char *, char *, nvlist_t *,
    char *, char *, char *, char *, int64_t,
    char *, char *, int64_t, char *, int64_t, char **, uint_t);
extern int topo_mod_nvl2str(topo_mod_t *, nvlist_t *, char **);
extern int topo_mod_str2nvl(topo_mod_t *, const char *,  nvlist_t **);
extern int topo_prop_setmutable(tnode_t *node, const char *pgname,
    const char *pname, int *err);
extern int topo_prop_setnonvolatile(tnode_t *node, const char *pgname,
    const char *pname, int *err);
/*
 * Snapshot walker support
 */
typedef int (*topo_mod_walk_cb_t)(topo_mod_t *, tnode_t *, void *);

extern topo_walk_t *topo_mod_walk_init(topo_mod_t *, tnode_t *,
    topo_mod_walk_cb_t, void *, int *);

/*
 * Flags for topo_mod_memfmri
 */
#define	TOPO_MEMFMRI_PA		0x0001	/* Valid physical address */
#define	TOPO_MEMFMRI_OFFSET	0x0002	/* Valid offset */

extern int topo_method_register(topo_mod_t *, tnode_t *, const topo_method_t *);
extern void topo_method_unregister(topo_mod_t *, tnode_t *, const char *);
extern void topo_method_unregister_all(topo_mod_t *, tnode_t *);

extern di_node_t topo_mod_devinfo(topo_mod_t *);
extern ipmi_handle_t *topo_mod_ipmi_hold(topo_mod_t *);
extern void topo_mod_ipmi_rele(topo_mod_t *);
extern smbios_hdl_t *topo_mod_smbios(topo_mod_t *);
extern pcidb_hdl_t *topo_mod_pcidb(topo_mod_t *);
extern di_prom_handle_t topo_mod_prominfo(topo_mod_t *);
extern nvlist_t *topo_mod_auth(topo_mod_t *, tnode_t *);

extern int topo_method_sensor_failure(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

/*
 * FMRI methods
 */
#define	TOPO_METH_LABEL			"topo_label"
#define	TOPO_METH_LABEL_DESC		"label constructor"
#define	TOPO_METH_LABEL_VERSION0	0
#define	TOPO_METH_LABEL_VERSION		TOPO_METH_LABEL_VERSION0
#define	TOPO_METH_LABEL_ARG_NVL		"label-specific"
#define	TOPO_METH_LABEL_RET_STR		"label-string"

#define	TOPO_METH_PRESENT		"topo_present"
#define	TOPO_METH_PRESENT_DESC		"presence indicator"
#define	TOPO_METH_PRESENT_VERSION0	0
#define	TOPO_METH_PRESENT_VERSION	TOPO_METH_PRESENT_VERSION0
#define	TOPO_METH_PRESENT_RET		"present-ret"

#define	TOPO_METH_REPLACED		"topo_replaced"
#define	TOPO_METH_REPLACED_DESC		"replaced indicator"
#define	TOPO_METH_REPLACED_VERSION0	0
#define	TOPO_METH_REPLACED_VERSION	TOPO_METH_REPLACED_VERSION0
#define	TOPO_METH_REPLACED_RET		"replaced-ret"

#define	TOPO_METH_UNUSABLE		"topo_unusable"
#define	TOPO_METH_UNUSABLE_DESC		"unusable indicator"
#define	TOPO_METH_UNUSABLE_VERSION0	0
#define	TOPO_METH_UNUSABLE_VERSION	TOPO_METH_UNUSABLE_VERSION0
#define	TOPO_METH_UNUSABLE_RET		"unusable-ret"

#define	TOPO_METH_SERVICE_STATE		"topo_service_state"
#define	TOPO_METH_SERVICE_STATE_DESC	"service_state indicator"
#define	TOPO_METH_SERVICE_STATE_VERSION0	0
#define	TOPO_METH_SERVICE_STATE_VERSION	TOPO_METH_SERVICE_STATE_VERSION0
#define	TOPO_METH_SERVICE_STATE_RET	"service_state-ret"

#define	TOPO_METH_RETIRE		"topo_retire"
#define	TOPO_METH_RETIRE_DESC		"retire action"
#define	TOPO_METH_RETIRE_VERSION0	0
#define	TOPO_METH_RETIRE_VERSION	TOPO_METH_RETIRE_VERSION0
#define	TOPO_METH_RETIRE_RET		"retire-ret"

#define	TOPO_METH_UNRETIRE		"topo_unretire"
#define	TOPO_METH_UNRETIRE_DESC		"unretire action"
#define	TOPO_METH_UNRETIRE_VERSION0	0
#define	TOPO_METH_UNRETIRE_VERSION	TOPO_METH_UNRETIRE_VERSION0
#define	TOPO_METH_UNRETIRE_RET		"unretire-ret"

#define	TOPO_METH_EXPAND		"topo_expand"
#define	TOPO_METH_EXPAND_DESC		"expand FMRI"
#define	TOPO_METH_EXPAND_VERSION0	0
#define	TOPO_METH_EXPAND_VERSION	TOPO_METH_EXPAND_VERSION0

#define	TOPO_METH_CONTAINS		"topo_contains"
#define	TOPO_METH_CONTAINS_DESC		"FMRI contains sub-FMRI"
#define	TOPO_METH_CONTAINS_VERSION0	0
#define	TOPO_METH_CONTAINS_VERSION	TOPO_METH_CONTAINS_VERSION0
#define	TOPO_METH_CONTAINS_RET		"contains-return"
#define	TOPO_METH_FMRI_ARG_FMRI		"fmri"
#define	TOPO_METH_FMRI_ARG_SUBFMRI	"sub-fmri"

#define	TOPO_METH_ASRU_COMPUTE		"topo_asru_compute"
#define	TOPO_METH_ASRU_COMPUTE_VERSION	0
#define	TOPO_METH_ASRU_COMPUTE_DESC	"Dynamic ASRU constructor"

#define	TOPO_METH_FRU_COMPUTE		"topo_fru_compute"
#define	TOPO_METH_FRU_COMPUTE_VERSION	0
#define	TOPO_METH_FRU_COMPUTE_DESC	"Dynamic FRU constructor"

#define	TOPO_METH_DISK_STATUS		"topo_disk_status"
#define	TOPO_METH_DISK_STATUS_VERSION	0
#define	TOPO_METH_DISK_STATUS_DESC	"Disk status"

#define	TOPO_METH_SENSOR_FAILURE	"topo_sensor_failure"
#define	TOPO_METH_SENSOR_FAILURE_VERSION	0
#define	TOPO_METH_SENSOR_FAILURE_DESC	"Sensor failure state"

#define	TOPO_PROP_METH_DESC		"Dynamic Property method"

#define	TOPO_METH_IPMI_ENTITY		"ipmi_entity"
#define	TOPO_METH_FAC_ENUM_DESC		"Facility Enumerator"

extern void *topo_mod_alloc(topo_mod_t *, size_t);
extern void *topo_mod_zalloc(topo_mod_t *, size_t);
extern void topo_mod_free(topo_mod_t *, void *, size_t);
extern char *topo_mod_strdup(topo_mod_t *, const char *);
extern void topo_mod_strfree(topo_mod_t *, char *);
extern int topo_mod_nvalloc(topo_mod_t *, nvlist_t **, uint_t);
extern int topo_mod_nvdup(topo_mod_t *, nvlist_t *, nvlist_t **);

extern void topo_mod_clrdebug(topo_mod_t *);
extern void topo_mod_setdebug(topo_mod_t *);
extern void topo_mod_dprintf(topo_mod_t *, const char *, ...);
extern const char *topo_mod_errmsg(topo_mod_t *);
extern int topo_mod_errno(topo_mod_t *);
extern char *topo_mod_clean_str(topo_mod_t *, const char *);

/*
 * Topo node utilities: callable from module enumeration, topo_mod_enumerate()
 */
extern int topo_node_range_create(topo_mod_t *, tnode_t *, const char *,
    topo_instance_t, topo_instance_t);
extern void topo_node_range_destroy(tnode_t *, const char *);
extern tnode_t *topo_node_bind(topo_mod_t *, tnode_t *, const char *,
    topo_instance_t, nvlist_t *);
extern tnode_t *topo_node_facbind(topo_mod_t *, tnode_t *, const char *,
    const char *);
extern void topo_node_unbind(tnode_t *);
extern void topo_node_setspecific(tnode_t *, void *);
extern void *topo_node_getspecific(tnode_t *);
extern int topo_node_asru_set(tnode_t *node, nvlist_t *, int, int *);
extern int topo_node_fru_set(tnode_t *node, nvlist_t *, int, int *);
extern int topo_node_label_set(tnode_t *node, char *, int *);

#define	TOPO_ASRU_COMPUTE	0x0001	/* Compute ASRU dynamically */
#define	TOPO_FRU_COMPUTE	0x0002	/* Compute FRU dynamically */

extern int topo_prop_inherit(tnode_t *, const char *, const char *, int *);
extern int topo_pgroup_create(tnode_t *, const topo_pgroup_info_t *, int *);

/*
 * Topo property method registration
 */
extern int topo_prop_method_register(tnode_t *, const char *, const char *,
    topo_type_t, const char *, const nvlist_t *, int *);
extern void topo_prop_method_unregister(tnode_t *, const char *, const char *);

/*
 * This enum definition is used to define a set of error tags associated with
 * the module api error conditions.  The shell script mkerror.sh is
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
    EMOD_NODE_BOUND,		/* node already bound */
    EMOD_NODE_DUP,		/* duplicate node */
    EMOD_NODE_NOENT,		/* node not found */
    EMOD_NODE_RANGE,		/* invalid node range */
    EMOD_VER_ABI,		/* registered with invalid ABI version */
    EMOD_VER_OLD,		/* attempt to load obsolete module */
    EMOD_VER_NEW,		/* attempt to load a newer module */
    EMOD_NVL_INVAL,		/* invalid nvlist */
    EMOD_NONCANON,		/* non-canonical component name requested */
    EMOD_MOD_NOENT,		/* module lookup failed */
    EMOD_UKNOWN_ENUM,		/* unknown enumeration error */
    EMOD_END			/* end of mod errno list (to ease auto-merge) */
} topo_mod_errno_t;

extern int topo_mod_seterrno(topo_mod_t *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _TOPO_MOD_H */
