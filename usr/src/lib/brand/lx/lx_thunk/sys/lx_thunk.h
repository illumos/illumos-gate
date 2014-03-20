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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LX_THUNK_H
#define	_LX_THUNK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct hostent *lxt_gethostbyaddr_r(const char *addr, int addr_len, int type,
    struct hostent *result, char *buf, int buf_len, int *h_errnop);
struct hostent *lxt_gethostbyname_r(const char *name,
    struct hostent *result, char *buf, int buf_len, int *h_errnop);
struct servent *lxt_getservbyport_r(int port, const char *proto,
    struct servent *result, char *buf, int buf_len);
struct servent *lxt_getservbyname_r(const char *name, const char *proto,
    struct servent *result, char *buf, int buf_len);

void openlog(const char *ident, int logopt, int facility);
void syslog(int priority, const char *message, ...);
void closelog(void);

void lxt_debug(const char *msg, ...);
void lxt_vdebug(const char *msg, va_list va);

#ifdef	__cplusplus
}
#endif

#endif	/* _LX_THUNK_H */
