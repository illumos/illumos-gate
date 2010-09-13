/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_1394_ADAPTERS_HCI1394_BUF_H
#define	_SYS_1394_ADAPTERS_HCI1394_BUF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_buf.h
 *   These routines handle IO bound memory.  They include routines to alloc and
 *   free. IO bound memory and a routine to get the adapter's default dma
 *   attributes.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>


/*
 * Input parameters into buf_alloc().
 *    bp_length - size of buffer to alloc and map into IO space.
 *    bp_max_cookies - maximum number of cookies we can handle.
 *    bp_alignment - buffer alignment requirements.
 *
 * bp_max_cookies overwrites the adapter's default dma_attr_sgllen setting.
 * bp_alignment overwrites the adapter's default dma_attr_align setting.
 */
typedef struct hci1394_buf_parms_s {
	size_t		bp_length;
	uint_t		bp_max_cookies;
	uint64_t	bp_alignment;
} hci1394_buf_parms_t;

/*
 * Output from buf_alloc().  This structure contains information
 * about the buffer allocated.
 */
typedef struct hci1394_buf_info_s {
	ddi_dma_cookie_t	bi_cookie; /* ddi_dma_addr_bind_handle */
	uint_t			bi_cookie_count; /* ddi_dma_addr_bind_handle */
	caddr_t			bi_kaddr; /* ddi_dma_mem_alloc */
	size_t			bi_length; /* copy of input parms bp_length */
	size_t			bi_real_length; /* ddi_dma_mem_alloc */
	ddi_acc_handle_t	bi_handle; /* ddi_dma_mem_alloc */
	ddi_dma_handle_t	bi_dma_handle; /* ddi_dma_alloc_handle */
} hci1394_buf_info_t;

/*
 * private structure to track buffer information
 */
typedef struct hci1394_buf_s {
	ddi_acc_handle_t	bu_handle;
	ddi_dma_handle_t	bu_dma_handle;
	hci1394_drvinfo_t 	*bu_drvinfo;
} hci1394_buf_t;

/*
 * handle passed back from alloc() and used for free()
 */
typedef struct hci1394_buf_s	*hci1394_buf_handle_t;


void hci1394_buf_attr_get(ddi_dma_attr_t *dma_attr);
int hci1394_buf_alloc(hci1394_drvinfo_t *drvinfo, hci1394_buf_parms_t *parms,
    hci1394_buf_info_t *info, hci1394_buf_handle_t *handle);
void hci1394_buf_free(hci1394_buf_handle_t *handle);

/* warlock directives */
_NOTE(SCHEME_PROTECTS_DATA("Single user", hci1394_buf_info_s hci1394_buf_s))

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_ADAPTERS_HCI1394_BUF_H */
