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

#ifndef	_SYS_NDIFM_H
#define	_SYS_NDIFM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ddifm.h>
#include <sys/ddifm_impl.h>

/* FM handle cache support */
#define	DMA_HANDLE	0
#define	ACC_HANDLE	1
#define	DEFAULT_DMACACHE_SZ	100
#define	DEFAULT_ACCCACHE_SZ	10

extern int default_dmacache_sz;
extern int default_acccache_sz;

/* Forward declarations for FM NDI */

typedef struct i_ddi_fmc ndi_fmc_t;
typedef struct i_ddi_fmc_entry ndi_fmcentry_t;

/* Per-handle NDI error status */
typedef struct i_ndi_err {
	uint64_t err_ena;			/* ENA for this error */
	int err_status;				/* error status */
	int err_expected;			/* was this error expected? */
	void *err_ontrap;			/* ontrap protection, if any */
	struct i_ddi_fmc_entry *err_fep;	/* FM cache link */
	int (*err_cf)();			/* compare function */
} ndi_err_t;

#ifdef	_KERNEL

extern void ndi_fmc_insert(dev_info_t *, int, void *, void *);
extern void ndi_fmc_remove(dev_info_t *, int, const void *);
extern int ndi_fmc_error(dev_info_t *, dev_info_t *, int, uint64_t,
    const void *);
extern int ndi_fmc_entry_error(dev_info_t *, int, ddi_fm_error_t *,
    const void *);
extern int ndi_fmc_entry_error_all(dev_info_t *, int, ddi_fm_error_t *);

extern int ndi_fm_handler_dispatch(dev_info_t *, dev_info_t *,
    const ddi_fm_error_t *);
extern int i_ddi_fm_handler_dispatch(dev_info_t *, const ddi_fm_error_t *);

extern void ndi_fm_acc_err_set(ddi_acc_handle_t, ddi_fm_error_t *);
extern void ndi_fm_dma_err_set(ddi_dma_handle_t, ddi_fm_error_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NDIFM_H */
