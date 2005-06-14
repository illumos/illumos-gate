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
 * Copyright (c) 1998,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MY_ALLOC_H
#define	_MY_ALLOC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <netdb.h>
#include <netdir.h>
#include <rpc/nettype.h>

int add_alloc(char *, void *, size_t, const char *, int);
int drop_alloc(const char *, void *, const char *, int);

void *my_malloc(size_t, const char *, int);
void *my_realloc(void *, size_t, const char *, int);
void my_free(void *, const char *, int);
char *my_strdup(const char *, const char *, int);

int  my_sethostent(int, const char *, int);
int  my_endhostent(const char *, int);

void *my_setnetconfig(const char *, int);
int  my_endnetconfig(void *, const char *, int);

void *my_setnetpath(const char *, int);
int  my_endnetpath(void *, const char *, int);

int  my_netdir_getbyname(struct netconfig *, struct nd_hostserv *,
	struct nd_addrlist **, const char *, int);
int  my_netdir_free(void *, int, const char *, int);

struct hostent *my_getipnodebyname(const char *, int, int, int *, char *, int);
void my_freehostent(struct hostent *, char *, int);

struct netconfig *my_getnetconfigent(char *, char *, int);
void  my_freenetconfigent(struct netconfig *, char *, int);

void *my__rpc_setconf(char *, char *, int);
void my__rpc_endconf(void *, char *, int);

void check_leaks(char *);

#define	AUTOFS_DUMP_DEBUG	1000000
#define	free(a)			my_free(a, __FILE__, __LINE__)
#define	malloc(a)		my_malloc(a, __FILE__, __LINE__)
#define	realloc(a, s)		my_realloc(a, s, __FILE__, __LINE__)
#define	strdup(a)		my_strdup(a, __FILE__, __LINE__)

#define	sethostent(s)		my_sethostent(s, __FILE__, __LINE__)
#define	endhostent()		my_endhostent(__FILE__, __LINE__)

#define	setnetconfig()		my_setnetconfig(__FILE__, __LINE__)
#define	endnetconfig(v)		my_endnetconfig(v, __FILE__, __LINE__)

#define	setnetpath()		my_setnetpath(__FILE__, __LINE__)
#define	endnetpath(v)		my_endnetpath(v, __FILE__, __LINE__)

#define	netdir_getbyname(t, s, a)	\
	my_netdir_getbyname(t, s, a, __FILE__, __LINE__)
#define	netdir_free(a, t)	my_netdir_free(a, t, __FILE__, __LINE__)

#define	getipnodebyname(n, a, f, e)	\
	my_getipnodebyname(n, a, f, e, __FILE__, __LINE__)
#define	 freehostent(h)		my_freehostent(h, __FILE__, __LINE__)

#define	getnetconfigent(n)	my_getnetconfigent(n, __FILE__, __LINE__)
#define	freenetconfigent(n)	my_freenetconfigent(n, __FILE__, __LINE__)

#ifdef __cplusplus
}
#endif

#endif	/* _MY_ALLOC_H */
