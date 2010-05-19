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

#ifndef	_CPU_MODULE_MS_H
#define	_CPU_MODULE_MS_H

#include <sys/types.h>
#include <sys/cpuvar.h>
#include <sys/nvpair.h>
#include <sys/cpu_module.h>

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#define	CMSERR_BASE 0xe000

typedef enum cms_errno {
	CMS_SUCCESS = 0,
	CMSERR_UNKNOWN = CMSERR_BASE,	/* No specific error reason given */
	CMSERR_NOTSUP,			/* Unsupported operation */
	CMSERR_BADMSRWRITE		/* Error on wrmsr */

} cms_errno_t;

extern void cms_init(cmi_hdl_t);
extern boolean_t cms_present(cmi_hdl_t);
extern void *cms_hdl_getcmsdata(cmi_hdl_t);
extern void cms_post_startup(cmi_hdl_t);
extern void cms_post_mpstartup(cmi_hdl_t);

extern size_t cms_logout_size(cmi_hdl_t);

extern uint64_t cms_mcgctl_val(cmi_hdl_t, int, uint64_t);

extern boolean_t cms_bankctl_skipinit(cmi_hdl_t, int);
extern uint64_t cms_bankctl_val(cmi_hdl_t, int, uint64_t);
extern boolean_t cms_bankstatus_skipinit(cmi_hdl_t, int);
extern uint64_t cms_bankstatus_val(cmi_hdl_t, int, uint64_t);

extern void cms_mca_init(cmi_hdl_t, int);

extern uint64_t cms_poll_ownermask(cmi_hdl_t, hrtime_t);

extern void cms_bank_logout(cmi_hdl_t, int, uint64_t, uint64_t, uint64_t,
    void *);

extern cms_errno_t cms_msrinject(cmi_hdl_t, uint_t, uint64_t);

extern void cms_fini(cmi_hdl_t);

/*
 * Return flags for cms_error_action.  The model-specific implementation
 * can perform additional error handling during this call (e.g., cache
 * flush). but it needs to return an indication to the caller as to
 * the high-level impact of the error.
 *
 * CMS_ERRSCOPE_CLEAREDUC indicates that a UC error has in some way
 * been cleared by the model-specific handling, and that no bad data
 * remains in the system as far as this error is concerned.
 *
 * CMS_ERRSCOPE_POISONED indicates that the uncorrected data has
 * been marked in some way to ensure that is cannot subsequently be mistaken
 * for good data.
 *
 * CMS_ERRSCOPE_CURCONTEXT_OK indicates that the interrupted context is
 * unaffected by the uncorrected error.
 *
 * CMS_ERRSCOPE_IGNORE_ERR indicates that the error should be ignored,
 * regardless of apparent current context status and presence of uncorrected
 * data.
 *
 * CMS_ERRSCOPE_FORCE_FATAL indicates that the error should be considered
 * terminal, even if no uncorrected data is present and context appears ok
 */

#define	CMS_ERRSCOPE_CLEARED_UC		0x01
#define	CMS_ERRSCOPE_POISONED		0x02
#define	CMS_ERRSCOPE_CURCONTEXT_OK	0x04
#define	CMS_ERRSCOPE_IGNORE_ERR		0x08
#define	CMS_ERRSCOPE_FORCE_FATAL	0x10

typedef void *cms_cookie_t;

extern uint32_t cms_error_action(cmi_hdl_t, int, int, uint64_t, uint64_t,
    uint64_t, void *);

extern cms_cookie_t cms_disp_match(cmi_hdl_t, int, int, uint64_t, uint64_t,
    uint64_t, void *);
extern void cms_ereport_class(cmi_hdl_t, cms_cookie_t, const char **,
    const char **);
extern nvlist_t *cms_ereport_detector(cmi_hdl_t, int, cms_cookie_t,
    nv_alloc_t *);
extern boolean_t cms_ereport_includestack(cmi_hdl_t, cms_cookie_t);
extern void cms_ereport_add_logout(cmi_hdl_t, nvlist_t *, nv_alloc_t *, int,
    uint64_t, uint64_t, uint64_t, void *, cms_cookie_t);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _CPU_MODULE_MS_H */
