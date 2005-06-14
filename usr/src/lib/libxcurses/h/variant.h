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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 1993 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * $Header: /rd/h/rcs/variant.h 1.2 1994/01/24 23:12:41 mark Exp $
 */

 /*
 * For EBCDIC support:
 *    the variant structure that contains the 13 POSIX.2 portable characters 
 *    that are variant in EBCDIC based code pages.
 */

#ifndef __M_VARIANT_H__
#define	__M_VARIANT_H__

struct variant {
	char	*codeset;
	char	backslash;
	char	right_bracket;
	char	left_bracket;
	char	right_brace;
	char	left_brace;
	char	circumflex;
	char	tilde;
	char	exclamation_mark;
	char	number_sign;
	char	vertical_line;
	char	dollar_sign;
	char	commercial_at;
	char	grave_accent;
};

struct variant *getsyntx(void);

#endif	/* __M_VARIANT_H__ */
