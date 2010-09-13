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

#ifndef _SYS_CPU_MODULE_IMPL_H
#define	_SYS_CPU_MODULE_IMPL_H

#include <sys/cpu_module.h>
#include <sys/cpuvar.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t cmi_api_ver_t;

#define	_CMI_API_VERSION_MAGIC	0xa5100000
#define	_CMI_API_VERSION(n)	(_CMI_API_VERSION_MAGIC | (n))

#define	CMI_API_VERSION_CHKMAGIC(v) \
	(((v) & 0xfff00000) == _CMI_API_VERSION_MAGIC)
#define	CMI_API_VERSION_TOPRINT(v) ((v) & 0x000fffff)

#define	CMI_API_VERSION_0	_CMI_API_VERSION(0)
#define	CMI_API_VERSION_1	_CMI_API_VERSION(1)
#define	CMI_API_VERSION_2	_CMI_API_VERSION(2)
#define	CMI_API_VERSION_3	_CMI_API_VERSION(3)

#define	CMI_API_VERSION		CMI_API_VERSION_3

typedef struct cmi_ops {
	int (*cmi_init)(cmi_hdl_t, void **);
	void (*cmi_post_startup)(cmi_hdl_t);
	void (*cmi_post_mpstartup)(cmi_hdl_t);
	void (*cmi_faulted_enter)(cmi_hdl_t);
	void (*cmi_faulted_exit)(cmi_hdl_t);
	void (*cmi_mca_init)(cmi_hdl_t);
	uint64_t (*cmi_mca_trap)(cmi_hdl_t, struct regs *);
	void (*cmi_cmci_trap)();
	cmi_errno_t (*cmi_msrinject)(cmi_hdl_t, cmi_mca_regs_t *, uint_t, int);
	void (*cmi_hdl_poke)(cmi_hdl_t);
	void (*cmi_fini)(cmi_hdl_t);
	void (*cmi_panic_callback)(void);
} cmi_ops_t;

/*
 * Utility functions provided by the cpu module interface for the sole
 * use of cpu module implementations.
 */
extern int cmi_mce_response(struct regs *, uint64_t);

/*
 * Terminal dispositions to be returned by cmi_mca_trap entry point
 */
#define	CMI_ERRDISP_CURCTXBAD		0x00000001ULL
#define	CMI_ERRDISP_RIPV_INVALID	0x00000002ULL
#define	CMI_ERRDISP_UC_UNCONSTRAINED	0x00000004ULL
#define	CMI_ERRDISP_FORCEFATAL		0x00000008ULL

/*
 * Non-terminal errors dispositions that can be returned by cmi_mca_trap
 */
#define	CMI_ERRDISP_IGNORED		0x00010000ULL
#define	CMI_ERRDISP_PCC_CLEARED		0x00020000ULL
#define	CMI_ERRDISP_UC_CLEARED		0x00040000ULL
#define	CMI_ERRDISP_POISONED		0x00080000ULL
#define	CMI_ERRDISP_INCONSISTENT	0x00100000ULL

#ifdef __cplusplus
}
#endif

#endif /* _SYS_CPU_MODULE_IMPL_H */
