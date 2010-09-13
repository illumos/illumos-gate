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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * ISO2022 generic escape sequence handler for graphical characters
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* static  char *sccsid = "%Z%%M%	%I%	%E% SMI"; */

/*
 * single control characters
 */
#define SI	0x0F
#define SO	0x0E

#define ESC	0x1B

#define LS0	0x0F		
#define LS1	0x0E
#define LS1R	0x7E	/* need ESC */
#define LS2	0x6E	/* need ESC */
#define LS2R	0x7D	/* need ESC */
#define LS3	0x6F	/* need ESC */
#define LS3R	0x7C	/* need ESC */
#define SS2_7B	0x4E	/* need ESC */
#define SS2_8B	0x8E
#define SS3_7B	0x4F	/* need ESC */
#define SS3_8B	0x8F

#define C_C0	0
#define C_C1	1

#define G0	0
#define G1	1
#define G2	2
#define G3	3

#define CONT	0
#define SING	1
#define MULT	2
/*
 * code info
 */
typedef struct {
	char g0_len; /* 1 or 2 */
	char g1_len; /* 1 or 2 */
	char g2_len; /* 1 or 2 */
	char g3_len; /* 1 or 2 */
	char bit_env;/* 7 or 8 */

} isowidth_t;
