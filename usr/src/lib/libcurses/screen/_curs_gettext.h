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
 * Copyright (c) 1990, 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_CURS_GETTEXT_H
#define	_CURS_GETTEXT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Header file for _curs_gettext() macro. */
#if !defined(TEXT_DOMAIN)	/* Should be defined thru -D flag. */
#	define	TEXT_DOMAIN	"SYS_TEST"
#endif

char *_dgettext(const char *, const char *);
#define	_curs_gettext(msg_id)	_dgettext(TEXT_DOMAIN, msg_id)

#ifdef	__cplusplus
}
#endif

#endif	/* _CURS_GETTEXT_H */
