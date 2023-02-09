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
 * Copyright (c) 2007 by Sun Microsystems, Inc.
 */

/*
 * General machine architecture & implementation specific
 * assembly language routines.
 */
#include "assym.h"

#include <sys/asm_linkage.h>
#include <sys/eeprom.h>
#include <sys/param.h>
#include <sys/async.h>
#include <sys/intreg.h>
#include <sys/machthread.h>
#include <sys/iocache.h>
#include <sys/privregs.h>
#include <sys/archsystm.h>

	!
	! void	memscrub_read(caddr_t src, u_int blks)
	!

	.seg ".text"
	.align	4

	ENTRY(memscrub_read)
	srl	%o1, 0, %o1			! clear upper word of blk count
        rd	%fprs, %o2			! get the status of fp
	wr	%g0, FPRS_FEF, %fprs		! enable fp

1:
	prefetch [%o0 + 8*64], 0
	ldda	[%o0]ASI_BLK_P, %d0
	add	%o0, 64, %o0
	prefetch [%o0 + 8*64], 0
	ldda	[%o0]ASI_BLK_P, %d16
	add	%o0, 64, %o0
	prefetch [%o0 + 8*64], 0
	ldda	[%o0]ASI_BLK_P, %d32
	add	%o0, 64, %o0
	prefetch [%o0 + 8*64], 0
	ldda	[%o0]ASI_BLK_P, %d48
	dec	%o1
	brnz,a	%o1, 1b
	add	%o0, 64, %o0

	retl
	wr	%o2, 0, %fprs			! restore fprs (disabled)
	SET_SIZE(memscrub_read)

