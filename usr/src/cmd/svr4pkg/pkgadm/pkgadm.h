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
 * Copyright (c) 2017 Peter Tribble.
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PKGADM_H
#define	_PKGADM_H


#ifdef __cplusplus
extern "C" {
#endif

#include "pkglib.h"
#include "libinst.h"

/* version of packaging interface */
#define	SUNW_PKGVERS	"1.0"

/* string comparitor abbreviators */

#define	ci_streq(a, b)		(strcasecmp((a), (b)) == 0)
#define	ci_strneq(a, b, c)	(strncasecmp((a), (b), (c)) == 0)
#define	streq(a, b)		(strcmp((a), (b)) == 0)
#define	strneq(a, b, c)		(strncmp((a), (b), (c)) == 0)

/* max l10n message length we will display */
#define	MSG_MAX			1024

/* main.c */
extern	void		log_msg(LogMsgType, const char *, ...);
extern	void		set_verbose(boolean_t);
extern	boolean_t	get_verbose(void);
/* lock.c */
extern int		admin_lock(int, char **);

#define	PKGADM_DBSTATUS_TEXT	"text"

#ifdef __cplusplus
}
#endif

#endif /* _PKGADM_H */
