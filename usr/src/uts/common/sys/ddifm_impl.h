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

#ifndef	_DDIFM_IMPL_H
#define	_DDIFM_IMPL_H

#include <sys/dditypes.h>
#include <sys/errorq.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct i_ddi_fmkstat {
	kstat_named_t	fek_erpt_dropped;	/* total ereports dropped */
	kstat_named_t	fek_fmc_miss;		/* total fmc misses */
	kstat_named_t	fek_fmc_full;		/* total fmc allocs fail */
	kstat_named_t	fek_acc_err;		/* total access errors */
	kstat_named_t	fek_dma_err;		/* total dma errors */
};

/* Fault management error handler support */

#define	DDI_MAX_ERPT_CLASS	64
#define	DDI_FM_STKDEPTH		20
#define	DDI_FM_SYM_SZ		64

struct i_ddi_errhdl {
	int (*eh_func)();	/* error handler callback */
	void *eh_impl;		/* callback arg */
};

/* Fault management resource cache support */

struct i_ddi_fmc_entry {
	struct i_ddi_fmc_entry *fce_prev;
	struct i_ddi_fmc_entry *fce_next;
	void *fce_resource;		/* acc or DMA handle cached */
	void *fce_bus_specific;		/* Bus-specific handle data */
};

struct i_ddi_fmc {
	kmutex_t fc_lock;			/* cache active access */
	struct i_ddi_fmc_entry *fc_head;	/* active handle list */
	struct i_ddi_fmc_entry *fc_tail;	/* tail of active handle list */
};

/* Error handler targets */
struct i_ddi_fmtgt {
	struct i_ddi_fmtgt *ft_next;	/* next fm child target */
	dev_info_t *ft_dip;		/* fm target error handler dip */
	struct i_ddi_errhdl *ft_errhdl;	/* error handler */
};

struct i_ddi_fmhdl {
	kmutex_t fh_lock;		/* error handler lock */
	kthread_t *fh_lock_owner;
	struct i_ddi_fmc *fh_dma_cache;	/* fm dma handle cache */
	struct i_ddi_fmc *fh_acc_cache;	/* fm access handle cache */
	dev_info_t *fh_dip;
	kstat_t *fh_ksp;		/* pointer to installed kstat */
	int fh_cap;			/* fm level for this instance */
	struct i_ddi_fmkstat fh_kstat;	/* fm kstats for this inst */
	errorq_t *fh_errorq;		/* errorq for this instance */
	nvlist_t *fh_fmri;		/* optional fmri */
	ddi_iblock_cookie_t fh_ibc;	/* ibc for error handling */
	struct i_ddi_fmtgt *fh_tgts;	/* registered fm tgts */
	void *fh_bus_specific;		/* Bus specific FM info */
};

typedef struct pci_fm_err {
	char *err_class;
	uint32_t reg_bit;
	char *terr_class;
	int flags;
} pci_fm_err_t;

extern pci_fm_err_t pci_err_tbl[];

#ifdef _KERNEL
typedef int (*ddi_fmcompare_t)(dev_info_t *, const void *, const void *,
    const void *);

extern void ndi_fm_init(void);

/* driver defect error reporting */
extern void i_ddi_drv_ereport_post(dev_info_t *, const char *, nvlist_t *, int);

/* target error handler add/remove/dispatch */
extern void i_ddi_fm_handler_enter(dev_info_t *);
extern void i_ddi_fm_handler_exit(dev_info_t *);
extern boolean_t i_ddi_fm_handler_owned(dev_info_t *);

/* access and dma handle protection support */
extern void i_ddi_fm_acc_err_set(ddi_acc_handle_t, uint64_t, int, int);
extern void i_ddi_fm_dma_err_set(ddi_dma_handle_t, uint64_t, int, int);
extern ddi_fmcompare_t i_ddi_fm_acc_err_cf_get(ddi_acc_handle_t);
extern ddi_fmcompare_t i_ddi_fm_dma_err_cf_get(ddi_dma_handle_t);

/* fm busop support */
extern void i_ndi_busop_access_enter(dev_info_t *, ddi_acc_handle_t);
extern void i_ndi_busop_access_exit(dev_info_t *, ddi_acc_handle_t);
extern int i_ndi_busop_fm_init(dev_info_t *, int, ddi_iblock_cookie_t *);
extern void i_ndi_busop_fm_fini(dev_info_t *);

/* fm cache support */
void i_ndi_fmc_create(struct i_ddi_fmc **, int, ddi_iblock_cookie_t);
void i_ndi_fmc_destroy(struct i_ddi_fmc *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _DDIFM_IMPL_H */
