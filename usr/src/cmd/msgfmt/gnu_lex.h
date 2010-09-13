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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_GNU_LEX_H
#define	_GNU_LEX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <limits.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	KW_DOMAIN	"domain"
#define	KW_MSGID	"msgid"
#define	KW_MSGID_PLURAL	"msgid_plural"
#define	KW_MSGSTR	"msgstr"

#define	MAX_KW_LEN	12	/* msgid_plural */

struct ch {
	int	len;
	int	eof;
	unsigned char	buf[MB_LEN_MAX+1];	/* including a null */
};

#ifdef	__cplusplus
}
#endif

#endif /* _GNU_LEX_H */
