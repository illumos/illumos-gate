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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PKGADM_H
#define	_PKGADM_H


/*
 * Module:	patchutil.h
 * Description:	This module contains the interfaces for patchadd
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <pkgerr.h>
#include <keystore.h>
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
extern	void		log_pkgerr(LogMsgType, PKG_ERR *);
extern	void		set_verbose(boolean_t);
extern	boolean_t	get_verbose(void);
/* lock.c */
extern int		admin_lock(int, char **);
/* listcert.c */
extern int		listcert(int, char **);
/* importcert.c */
extern int		addcert(int, char **);
/* removecert.c */
extern int		removecert(int, char **);

/* certs.c */
extern int		load_cert_and_key(PKG_ERR *, FILE *,
    keystore_encoding_format_t, char *, EVP_PKEY **, X509 **);
extern int		load_all_certs(PKG_ERR *, FILE *,
    keystore_encoding_format_t, char *, STACK_OF(X509) **);

#define	PKGADM_DBSTATUS_TEXT	"text"

#ifdef __cplusplus
}
#endif

#endif /* _PKGADM_H */
