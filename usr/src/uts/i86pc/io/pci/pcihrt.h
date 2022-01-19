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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * pcihrt.h -- PCI Hot-Plug Resource Table
 */

#ifndef	_PCIHRT_H
#define	_PCIHRT_H

#ifdef	__cplusplus
extern "C" {
#endif

struct hrt_hdr { /* PCI Hot-Plug Configuration Resource Table header */
	uint32_t hrt_sig;	/* $HRT					*/
	uint16_t hrt_avail_imap; /* Bitmap of unused IRQs		*/
	uint16_t hrt_used_imap;	/* Bitmap of IRQs used by PCI		*/
	uchar_t	hrt_entry_cnt;	/* no. of PCI hot-plug slot entries	*/
	uchar_t	hrt_ver;	/* version no. = 1			*/
	uchar_t	hrt_resv0;	/* reserved				*/
	uchar_t	hrt_resv1;	/* reserved				*/
	uchar_t	hrt_resv2;	/* reserved				*/
	uchar_t	hrt_resv3;	/* reserved				*/
	uchar_t	hrt_resv4;	/* reserved				*/
	uchar_t	hrt_resv5;	/* reserved				*/
};

struct php_entry {	/* PCI hot-plug slot entry */
	uchar_t	php_devno;	/* PCI dev/func no. of the slot		*/
	uchar_t	php_pri_bus;	/* Primary bus of this slot		*/
	uchar_t	php_sec_bus;	/* Secondary bus of this slot		*/
	uchar_t	php_subord_bus;	/* Max Subordinate bus of this slot	*/
	uint16_t php_io_start;	/* allocated I/O space starting addr	*/
	uint16_t php_io_size;	/* allocated I/O space size in bytes	*/
	uint16_t php_mem_start;	/* allocated Memory space start addr	*/
	uint16_t php_mem_size;	/* allocated Memory space size in 64k	*/
	uint16_t php_pfmem_start; /* allocated Prefetchable Memory start */
	uint16_t php_pfmem_size; /* allocated Prefetchable size in 64k	*/
};

#ifdef	__cplusplus
}
#endif

#endif	/* _PCIHRT_H */
