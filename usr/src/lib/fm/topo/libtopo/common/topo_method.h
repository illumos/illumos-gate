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
/*
 * Copyright (c) 2018, Joyent, Inc.
 */
#ifndef _TOPO_METHOD_H
#define	_TOPO_METHOD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <fm/topo_list.h>

typedef struct topo_imethod {
	topo_list_t tim_list;		/* next/prev pointers */
	pthread_mutex_t tim_lock;	/* method entry lock */
	pthread_cond_t  tim_cv;		/* method entry cv */
	uint_t tim_busy;		/* method entry busy indicator */
	char *tim_name;			/* Method name */
	topo_version_t tim_version;	/* Method version */
	topo_stability_t tim_stability;	/* SMI stability of method */
	char *tim_desc;			/* Method description */
	topo_method_f *tim_func;	/* Method function */
	struct topo_mod *tim_mod;	/* Ptr to controlling module */
} topo_imethod_t;

extern int topo_method_call(tnode_t *, const char *, topo_version_t, nvlist_t *,
    nvlist_t **, int *);
extern topo_imethod_t *topo_method_lookup(tnode_t *, const char *);
extern int topo_prop_method_version_register(tnode_t *, const char *,
    const char *, topo_type_t, const char *, topo_version_t, const nvlist_t *,
    int *);

/*
 * These are for the private consumption of the sensor-transport fmd plugin
 * and topo_method_sensor_failure()
 */
#define	ST_SPOOF_FMRI		"spoof_resource_fmri"
#define	ST_SPOOF_SENSOR		"spoof_sensor_name"
#define	ST_SPOOF_STATE		"spoof_sensor_state"

/*
 * FMRI methods
 */
#define	TOPO_METH_ASRU_COMPUTE		"topo_asru_compute"
#define	TOPO_METH_FRU_COMPUTE		"topo_fru_compute"
#define	TOPO_METH_FMRI			"topo_fmri"
#define	TOPO_METH_NVL2STR		"topo_nvl2str"
#define	TOPO_METH_STR2NVL		"topo_str2nvl"
#define	TOPO_METH_COMPARE		"topo_compare"
#define	TOPO_METH_PROP_GET		"topo_prop_get"
#define	TOPO_METH_PGRP_GET		"topo_pgrp_get"
#define	TOPO_METH_PROP_SET		"topo_prop_set"
#define	TOPO_METH_FACILITY		"topo_facility"

#define	TOPO_METH_FMRI_VERSION			0
#define	TOPO_METH_FRU_COMPUTE_VERSION		0
#define	TOPO_METH_ASRU_COMPUTE_VERSION		0
#define	TOPO_METH_NVL2STR_VERSION		0
#define	TOPO_METH_STR2NVL_VERSION		0
#define	TOPO_METH_COMPARE_VERSION		0
#define	TOPO_METH_PROP_GET_VERSION		0
#define	TOPO_METH_PGRP_GET_VERSION		0
#define	TOPO_METH_PROP_SET_VERSION		0
#define	TOPO_METH_FACILITY_VERSION		0

#define	TOPO_METH_ASRU_COMPUTE_DESC	"Dynamic ASRU constructor"
#define	TOPO_METH_FRU_COMPUTE_DESC	"Dynamic FRU constructor"
#define	TOPO_METH_FMRI_DESC		"Dynamic FMRI constructor"
#define	TOPO_METH_NVL2STR_DESC		"FMRI to string"
#define	TOPO_METH_STR2NVL_DESC		"string to FMRI"
#define	TOPO_METH_COMPARE_DESC		"compare two FMRIs"
#define	TOPO_METH_PROP_GET_DESC		"get properties for FMRI"
#define	TOPO_METH_PGRP_GET_DESC		"get property group for FMRI"
#define	TOPO_METH_PROP_SET_DESC		"set properties for FMRI"
#define	TOPO_METH_FACILITY_DESC		"get facility for FMRI"

#define	TOPO_METH_COMPARE_RET		"compare-return"

#define	TOPO_METH_FMRI_ARG_NAME		"child-name"
#define	TOPO_METH_FMRI_ARG_INST		"child-inst"
#define	TOPO_METH_FMRI_ARG_NVL		"args"
#define	TOPO_METH_FMRI_ARG_PARENT	"parent-fmri"
#define	TOPO_METH_FMRI_ARG_AUTH		"auth"
#define	TOPO_METH_FMRI_ARG_PART		"part"
#define	TOPO_METH_FMRI_ARG_REV		"rev"
#define	TOPO_METH_FMRI_ARG_SER		"serial"
#define	TOPO_METH_FMRI_ARG_HCS		"hc-specific"
#define	TOPO_METH_FMRI_ARG_FMRI		"fmri"
#define	TOPO_METH_FMRI_ARG_SUBFMRI	"sub-fmri"
#define	TOPO_METH_FMRI_ARG_NV1		"nv1"
#define	TOPO_METH_FMRI_ARG_NV2		"nv2"

#ifdef	__cplusplus
}
#endif

#endif	/* _TOPO_METHOD_H */
