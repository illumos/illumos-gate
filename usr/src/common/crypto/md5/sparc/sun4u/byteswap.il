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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * byteswap.il -- definitions for .inline functions for little-endian loads.
 *
 * right now, this file is only used on UltraSPARC architectures,
 * which have a special address space identifier for loading 32 and 16 bit
 * integers in little-endian byte order.
 *
 * note: apparently these files are not preprocessed, so we cannot
 *       use `ASI_PL'.
 *
 * This file and common/crypto/md5/md5_byteswap.h implement the
 * same thing and must be changed together.
 */

	.inline	load_little_32, 4
	lduwa	[%o0]0x88, %o0
	.end

	.inline load_little_16, 4
	lduha	[%o0]0x88, %o0
	.end
