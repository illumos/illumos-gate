/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Copyright (C) 2005-2008  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: port_before.h.in,v 1.31 2008/02/28 05:36:10 marka Exp $ */

#ifndef port_before_h
#define port_before_h
/* Solaris-specific changes */
#include "sunw_port_before.h"
#include <config.h>

#ifdef NEED_SUN4PROTOS
#define _PARAMS(x) x
#endif

struct group;           /* silence warning */
struct passwd;          /* silence warning */
struct timeval;         /* silence warning */
struct timezone;        /* silence warning */

#ifdef HAVE_SYS_TIMERS_H
#include <sys/timers.h>
#endif
#include <limits.h>

#ifdef ISC_PLATFORM_NEEDTIMESPEC
#include <time.h>		/* For time_t */
struct timespec {
	time_t  tv_sec;         /* seconds */
	long    tv_nsec;        /* nanoseconds */
};
#endif
#ifndef HAVE_MEMMOVE
#define memmove(a,b,c) bcopy(b,a,c)
#endif

#undef WANT_IRS_GR
#undef WANT_IRS_NIS
#undef WANT_IRS_PW

#define BSD_COMP 1
#define USE_POLL 1
#define HAVE_MD5 1
#define SOLARIS2 1

/* DO_PTHREADS is conditionally defined in sunw_port_before.h
 * #define DO_PTHREADS 1 */
#define GETGROUPLIST_ARGS const char *name, gid_t basegid, gid_t *groups, int *ngroups
#define GETNETBYADDR_ADDR_T long
#define SETPWENT_VOID 1
#define SETGRENT_VOID 1

#define NET_R_ARGS char *buf, int buflen
#define NET_R_BAD NULL
#define NET_R_COPY buf, buflen
#define NET_R_COPY_ARGS NET_R_ARGS
#define NET_R_END_RESULT(x) /*empty*/
#define NET_R_END_RETURN void
#undef NET_R_ENT_ARGS /*empty*/
#define NET_R_OK nptr
#define NET_R_RETURN struct netent *
#undef NET_R_SET_RESULT /*empty*/
#undef NET_R_SETANSWER
#define NET_R_SET_RETURN void
#undef NETENT_DATA

#define GROUP_R_RETURN struct group *
#define GROUP_R_SET_RETURN void
#undef GROUP_R_SET_RESULT /*empty*/
#define GROUP_R_END_RETURN void
#define GROUP_R_END_RESULT(x) /*empty*/
#define GROUP_R_ARGS char *buf, int buflen
#define GROUP_R_ENT_ARGS void
#define GROUP_R_OK gptr
#define GROUP_R_BAD NULL

#define HOST_R_ARGS char *buf, int buflen, int *h_errnop
#define HOST_R_BAD NULL
#define HOST_R_COPY buf, buflen
#define HOST_R_COPY_ARGS char *buf, int buflen
#define HOST_R_END_RESULT(x) /*empty*/
#define HOST_R_END_RETURN void
#undef HOST_R_ENT_ARGS /*empty*/
#define HOST_R_ERRNO *h_errnop = h_errno
#define HOST_R_OK hptr
#define HOST_R_RETURN struct hostent *
#undef HOST_R_SETANSWER
#undef HOST_R_SET_RESULT
#define HOST_R_SET_RETURN void
#undef HOSTENT_DATA

#define NGR_R_ARGS char *buf, int buflen
#define NGR_R_BAD (0)
#define NGR_R_COPY buf, buflen
#define NGR_R_COPY_ARGS NGR_R_ARGS
#define NGR_R_CONST
#define NGR_R_END_RESULT(x)  /*empty*/
#define NGR_R_END_RETURN void
#undef NGR_R_END_ARGS /*empty*/
#define NGR_R_OK 1
#define NGR_R_RETURN int
#define NGR_R_SET_CONST const
#undef NGR_R_SET_RESULT /*empty*/
#define NGR_R_SET_RETURN void
#undef NGR_R_SET_ARGS


#if !defined(NGR_R_SET_ARGS) && defined(NGR_R_END_ARGS)
#define NGR_R_SET_ARGS NGR_R_END_ARGS
#endif

#define PROTO_R_ARGS char *buf, int buflen
#define PROTO_R_BAD NULL
#define PROTO_R_COPY buf, buflen
#define PROTO_R_COPY_ARGS PROTO_R_ARGS
#define PROTO_R_END_RESULT(x) /*empty*/
#define PROTO_R_END_RETURN void
#undef PROTO_R_ENT_ARGS /*empty*/
#undef PROTO_R_ENT_UNUSED
#define PROTO_R_OK pptr
#undef PROTO_R_SETANSWER
#define PROTO_R_RETURN struct protoent *
#undef PROTO_R_SET_RESULT
#define PROTO_R_SET_RETURN void
#undef PROTOENT_DATA

#define PASS_R_ARGS char *buf, int buflen
#define PASS_R_BAD NULL
#define PASS_R_COPY buf, buflen
#define PASS_R_COPY_ARGS PASS_R_ARGS
#define PASS_R_END_RESULT(x) /*empty*/
#define PASS_R_END_RETURN void
#undef PASS_R_ENT_ARGS
#define PASS_R_OK pwptr
#define PASS_R_RETURN struct passwd *
#undef PASS_R_SET_RESULT /*empty*/
#define PASS_R_SET_RETURN void

#define SERV_R_ARGS char *buf, int buflen
#define SERV_R_BAD NULL
#define SERV_R_COPY buf, buflen
#define SERV_R_COPY_ARGS SERV_R_ARGS
#define SERV_R_END_RESULT(x) /*empty*/
#define SERV_R_END_RETURN void
#undef SERV_R_ENT_ARGS /*empty*/
#undef SERV_R_ENT_UNUSED /*empty*/
#define SERV_R_OK sptr
#undef SERV_R_SETANSWER
#define SERV_R_RETURN struct servent *
#undef SERV_R_SET_RESULT
#define SERV_R_SET_RETURN void



#define DE_CONST(konst, var) \
	do { \
		union { const void *k; void *v; } _u; \
		_u.k = konst; \
		var = _u.v; \
	} while (0)

#define UNUSED(x) (x) = (x)

#undef NEED_SOLARIS_BITTYPES
#define ISC_SOCKLEN_T int

#ifdef __GNUC__
#define ISC_FORMAT_PRINTF(fmt, args) \
	__attribute__((__format__(__printf__, fmt, args)))
#else
#define ISC_FORMAT_PRINTF(fmt, args)
#endif

/* Pull in host order macros when _XOPEN_SOURCE_EXTENDED is defined. */
#if defined(__hpux) && defined(_XOPEN_SOURCE_EXTENDED)
#include <sys/byteorder.h>
#endif

#endif

/*! \file */
