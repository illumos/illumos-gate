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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/asm_linkage.h>
#include <sys/machthread.h>
#include <sys/fsr.h>

/*LINTLIBRARY*/

#define	VIS_BLOCKSIZE	64

	.seg    ".data"
	.align  VIS_BLOCKSIZE
	.type   sync_buf, #object
sync_buf:
	.skip   VIS_BLOCKSIZE
	.size   sync_buf, VIS_BLOCKSIZE

	ENTRY(tomatillo_store_store_order)
	set	sync_buf, %o1

	rd	%fprs, %o2			! %o2 = saved fprs
	or	%o2, FPRS_FEF, %o3
	wr	%g0, %o3, %fprs			! make sure fp is enabled
	stda    %d0, [%o1]ASI_BLK_COMMIT_P
	wr	%o2, 0, %fprs			! restore fprs

	retl
	membar  #Sync
	SET_SIZE(tomatillo_store_store_order)

