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

#ifndef _AUTHAMD_H
#define	_AUTHAMD_H

#include <sys/types.h>
#include <sys/mca_amd.h>
#include <sys/cpu_module_ms_impl.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	AUTHAMD_MAX_NODES		8	/* max number of nodes */
#define	AUTHAMD_DRAM_NCHANNEL		2	/* dram channels per node */
#define	AUTHAMD_DRAM_NCS		8	/* chip-selects per channel */

#define	AUTHAMD_FAMILY_6		0x6
#define	AUTHAMD_FAMILY_F		0xf
#define	AUTHAMD_FAMILY_10		0x10

#define	AUTHAMD_SYNDTYPE_64_8		0x0
#define	AUTHAMD_SYNDTYPE_128_16		0x1

typedef struct authamd_data authamd_data_t;

typedef struct authamd_error_disp {
	const char *aad_subclass;
	const char *aad_leafclass;
	uint64_t aad_ereport_members;
} authamd_error_disp_t;

/*
 * Model-specific logout structure.
 */
#pragma pack(1)
typedef struct authamd_logout {
	uint8_t aal_eccerrcnt[AUTHAMD_DRAM_NCHANNEL][AUTHAMD_DRAM_NCS];
} authamd_logout_t;
#pragma pack()

/*
 * Per node shared state
 */
struct authamd_nodeshared {
	uint_t ans_chipid;
	uint_t ans_procnodeid;
	uint_t ans_family;		/* family number */
	uint32_t ans_rev;		/* revision per cpuid_getchiprev */
	volatile ulong_t ans_cfgonce;	/* Config performed once per chip */
	hrtime_t ans_poll_timestamp;	/* Checks poll owner is alive */
	cmi_hdl_t ans_pollowner;	/* poller of shared resources */
	char *ans_eccsymsz;		/* DRAM ChipKill ECC Symbol Size */
};

enum authamd_cfgonce_bitnum {
	AUTHAMD_CFGONCE_ONLNSPRCFG,
	AUTHAMD_CFGONCE_NBTHRESH,
	AUTHAMD_CFGONCE_NBMCACFG,
	AUTHAMD_CFGONCE_CACHESCRUB,
	AUTHAMD_CFGONCE_NBMCA,
	AUTHAMD_CFGONCE_ECCSYMSZ
};

/*
 * Per-CPU model-specific state
 */
struct authamd_data {
	cmi_hdl_t amd_hdl;			/* cpu we're associated with */
	uint64_t amd_hwcr;
	struct authamd_nodeshared *amd_shared;
};

#ifdef _KERNEL

/*
 * Our cms_ops operations and function prototypes for all non-NULL members.
 */
extern const cms_ops_t _cms_ops;

extern int authamd_init(cmi_hdl_t, void **);
extern size_t authamd_logout_size(cmi_hdl_t);
extern uint64_t authamd_mcgctl_val(cmi_hdl_t, int, uint64_t);
extern boolean_t authamd_bankctl_skipinit(cmi_hdl_t, int);
extern uint64_t authamd_bankctl_val(cmi_hdl_t, int, uint64_t);
extern void authamd_mca_init(cmi_hdl_t, int);
extern void authamd_bank_logout(cmi_hdl_t, int, uint64_t, uint64_t,
    uint64_t, void *);
extern uint32_t authamd_error_action(cmi_hdl_t, int, int, uint64_t,
    uint64_t, uint64_t, void *);
extern cms_cookie_t authamd_disp_match(cmi_hdl_t, int, int, uint64_t, uint64_t,
    uint64_t, void *);
extern void authamd_ereport_class(cmi_hdl_t, cms_cookie_t, const char **,
    const char **);
extern void authamd_ereport_add_logout(cmi_hdl_t, nvlist_t *,
    nv_alloc_t *, int, uint64_t, uint64_t, uint64_t, void *, cms_cookie_t);
extern cms_errno_t authamd_msrinject(cmi_hdl_t, uint_t, uint64_t);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _AUTHAMD_H */
