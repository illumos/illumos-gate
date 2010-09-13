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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_CPU_MODULE_MS_IMPL_H
#define	_CPU_MODULE_MS_IMPL_H

#include <sys/cpu_module_ms.h>
#include <sys/cpuvar.h>
#include <sys/x86_archext.h>
#include <sys/nvpair.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef uint32_t cms_api_ver_t;

#define	_CMS_API_VERSION_MAGIC	0xc5500000
#define	_CMS_API_VERSION(n)	(_CMS_API_VERSION_MAGIC | (n))

#define	CMS_API_VERSION_CHKMAGIC(v) \
	(((v) & 0xfff00000) == _CMS_API_VERSION_MAGIC)
#define	CMS_API_VERSION_TOPRINT(v) ((v) & 0x000fffff)

#define	CMS_API_VERSION_2	_CMS_API_VERSION(2)

#define	CMS_API_VERSION		CMS_API_VERSION_2

typedef struct cms_ops {
	int (*cms_init)(cmi_hdl_t, void **);
	void (*cms_post_startup)(cmi_hdl_t);
	void (*cms_post_mpstartup)(cmi_hdl_t);
	size_t (*cms_logout_size)(cmi_hdl_t);
	uint64_t (*cms_mcgctl_val)(cmi_hdl_t, int, uint64_t);
	boolean_t (*cms_bankctl_skipinit)(cmi_hdl_t, int);
	uint64_t (*cms_bankctl_val)(cmi_hdl_t, int, uint64_t);
	boolean_t (*cms_bankstatus_skipinit)(cmi_hdl_t, int);
	uint64_t (*cms_bankstatus_val)(cmi_hdl_t, int, uint64_t);
	void (*cms_mca_init)(cmi_hdl_t, int);
	uint64_t (*cms_poll_ownermask)(cmi_hdl_t, hrtime_t);
	void (*cms_bank_logout)(cmi_hdl_t, int, uint64_t,
	    uint64_t, uint64_t, void *);
	uint32_t (*cms_error_action)(cmi_hdl_t, int, int, uint64_t,
	    uint64_t, uint64_t, void *);
	cms_cookie_t (*cms_disp_match)(cmi_hdl_t, int, int, uint64_t, uint64_t,
	    uint64_t, void *);
	void (*cms_ereport_class)(cmi_hdl_t, cms_cookie_t, const char **,
	    const char **);
	nvlist_t *(*cms_ereport_detector)(cmi_hdl_t, int, cms_cookie_t,
	    nv_alloc_t *);
	boolean_t (*cms_ereport_includestack)(cmi_hdl_t, cms_cookie_t);
	void (*cms_ereport_add_logout)(cmi_hdl_t, nvlist_t *,
	    nv_alloc_t *, int, uint64_t, uint64_t, uint64_t, void *,
	    cms_cookie_t);
	cms_errno_t (*cms_msrinject)(cmi_hdl_t, uint_t, uint64_t);
	void (*cms_fini)(cmi_hdl_t);
} cms_ops_t;

#ifdef	__cplusplus
}
#endif

#endif /* _CPU_MODULE_MS_IMPL_H */
