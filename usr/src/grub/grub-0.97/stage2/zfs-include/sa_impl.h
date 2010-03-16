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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SA_IMPL_H
#define	_SYS_SA_IMPL_H

typedef struct sa_hdr_phys {
	uint32_t sa_magic;
	uint16_t sa_layout_info;
	uint16_t sa_lengths[1];
} sa_hdr_phys_t;

#define	SA_HDR_SIZE(hdr)	BF32_GET_SB(hdr->sa_layout_info, 10, 16, 3, 0)
#define	SA_SIZE_OFFSET	0x8

#endif	/* _SYS_SA_IMPL_H */
