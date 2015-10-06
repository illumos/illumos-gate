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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBC_GETTEXT_H
#define	_LIBC_GETTEXT_H

#include <libintl.h>
#include <locale.h>

extern char *dgettext_l(const char *, const char *, locale_t);

/* Header file for _libc_gettext() macro. */
#if !defined(TEXT_DOMAIN)	/* Should be defined thru -D flag. */
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

#define	_libc_gettext(msg_id)		dgettext(TEXT_DOMAIN, (msg_id))
#define	_libc_gettext_l(msg_id, loc)	dgettext_l(TEXT_DOMAIN, (msg_id), (loc))

#endif	/* _LIBC_GETTEXT_H */
