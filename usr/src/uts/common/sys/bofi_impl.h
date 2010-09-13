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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_BOFI_IMPL_H
#define	_SYS_BOFI_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

struct bofi_errent {
	struct bofi_errent *next;	/* next on in-use chain */
	struct bofi_errent *cnext;	/* next on clone chain */
	struct bofi_errent *cprev;	/* prev on clone chain */
	struct bofi_errdef errdef;
	struct bofi_errstate errstate;
	caddr_t name;
	struct acc_log_elem *logbase;
	uint_t state;
	kcondvar_t cv;
	ddi_softintr_t softintr_id;
};

/*
 * values for state
 */
#define	BOFI_DEV_ACTIVE 1
#define	BOFI_NEW_MESSAGE 2
#define	BOFI_MESSAGE_WAIT 4
#define	BOFI_DEBUG 8

#define	BOFI_NLINKS 8192

struct bofi_link {
	struct bofi_link *link;	/* next on shadow handle chain */
	struct bofi_errent *errentp;	/* pointer to corresponding errent */
};

struct bofi_shadow {
	union {
		struct dvma_ops dvma_ops;
		ddi_acc_impl_t acc;
		struct {
			uint_t (*int_handler)(caddr_t, caddr_t);
			caddr_t int_handler_arg1;
			caddr_t int_handler_arg2;
		} intr;
	} save;
	struct bofi_shadow *next;	/* next on inuse chain */
	struct bofi_shadow *prev;	/* prev on inuse chain */
	struct bofi_shadow *hnext;	/* next on hhash chain */
	struct bofi_shadow *hprev;	/* prev on hhash chain */
	struct bofi_shadow *dnext;	/* next on dhash chain */
	struct bofi_shadow *dprev;	/* prev on dhash chain */
	struct bofi_link *link;	/* errdef chain */
	uint_t type;
	union {
		ddi_dma_handle_t dma_handle;
		ddi_acc_handle_t acc_handle;
	} hdl;
	uint32_t bofi_inum;
	dev_info_t *dip;
	char name[NAMESIZE];		/* as returned by ddi_get_name() */
	int instance;		/* as returned by ddi_get_instance() */
	int rnumber;
	offset_t offset;
	offset_t len;
	caddr_t addr;
	caddr_t mapaddr;
	caddr_t origaddr;
	caddr_t allocaddr;
	uint_t flags;
	int map_flags;
	page_t *map_pp;
	page_t **map_pplist;
	struct bofi_shadow **hparrayp;
	int hilevel;
	ddi_umem_cookie_t umem_cookie;
};

/*
 * values for type
 */
#define	BOFI_ACC_HDL 1
#define	BOFI_DMA_HDL 2
#define	BOFI_INT_HDL 3
#define	BOFI_NULL    4

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_BOFI_IMPL_H */
