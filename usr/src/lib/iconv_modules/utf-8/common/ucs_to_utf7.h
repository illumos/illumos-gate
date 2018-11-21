/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	UCS_TO_UTF7_H
#define	UCS_TO_UTF7_H


#include "common_defs.h"


/* Modified Base64 alphabet -- see RFC 2045 and 2152. */
static const char *mb64 =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define	ICV_INRANGE_OF_MBASE64_ALPHABET(u) \
		(((u) >= (uint_t)'A' && (u) <= (uint_t)'Z') || \
		 ((u) >= (uint_t)'a' && (u) <= (uint_t)'z') || \
		 ((u) >= (uint_t)'0' && (u) <= (uint_t)'9') || \
		 (u) == (uint_t)'+' || (u) == (uint_t)'/')


#endif	/* UCS_TO_UTF7_H */
