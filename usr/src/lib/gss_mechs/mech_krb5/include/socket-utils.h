/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Copyright (C) 2001,2005 by the Massachusetts Institute of Technology,
 * Cambridge, MA, USA.  All Rights Reserved.
 *
 * This software is being provided to you, the LICENSEE, by the
 * Massachusetts Institute of Technology (M.I.T.) under the following
 * license.  By obtaining, using and/or copying this software, you agree
 * that you have read, understood, and will comply with these terms and
 * conditions:
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify and distribute
 * this software and its documentation for any purpose and without fee or
 * royalty is hereby granted, provided that you agree to comply with the
 * following copyright notice and statements, including the disclaimer, and
 * that the same appear on ALL copies of the software and documentation,
 * including modifications that you make for internal use or for
 * distribution:
 *
 * THIS SOFTWARE IS PROVIDED "AS IS", AND M.I.T. MAKES NO REPRESENTATIONS
 * OR WARRANTIES, EXPRESS OR IMPLIED.  By way of example, but not
 * limitation, M.I.T. MAKES NO REPRESENTATIONS OR WARRANTIES OF
 * MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF
 * THE LICENSED SOFTWARE OR DOCUMENTATION WILL NOT INFRINGE ANY THIRD PARTY
 * PATENTS, COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS.
 *
 * The name of the Massachusetts Institute of Technology or M.I.T. may NOT
 * be used in advertising or publicity pertaining to distribution of the
 * software.  Title to copyright in this software and any associated
 * documentation shall at all times remain with M.I.T., and USER agrees to
 * preserve same.
 *
 * Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 */

#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

/* Some useful stuff cross-platform for manipulating socket addresses.
   We assume at least ipv4 sockaddr_in support.  The sockaddr_storage
   stuff comes from the ipv6 socket api enhancements; socklen_t is
   provided on some systems; the rest is just convenience for internal
   use in the krb5 tree.

   Do NOT install this file.  */

/* for HAVE_SOCKLEN_T, KRB5_USE_INET6, etc */
#include "autoconf.h"
/* for sockaddr_storage */
#include "port-sockets.h"
/* for "inline" if needed */
#include "k5-platform.h"

#if defined (__GNUC__)
/*
 * There's a lot of confusion between pointers to different sockaddr
 * types, and pointers with different degrees of indirection, as in
 * the locate_kdc type functions.  Use these function to ensure we
 * don't do something silly like cast a "sockaddr **" to a
 * "sockaddr_in *".
 *
 * The casts to (void *) are to get GCC to shut up about alignment
 * increasing.
 */
static __inline__ struct sockaddr_in *sa2sin (struct sockaddr *sa)
{
    return (struct sockaddr_in *) (void *) sa;
}
#ifdef KRB5_USE_INET6
static __inline__ struct sockaddr_in6 *sa2sin6 (struct sockaddr *sa)
{
    return (struct sockaddr_in6 *) (void *) sa;
}
#endif
static __inline__ struct sockaddr *ss2sa (struct sockaddr_storage *ss)
{
    return (struct sockaddr *) ss;
}
static __inline__ struct sockaddr_in *ss2sin (struct sockaddr_storage *ss)
{
    return (struct sockaddr_in *) ss;
}
#ifdef KRB5_USE_INET6
static __inline__ struct sockaddr_in6 *ss2sin6 (struct sockaddr_storage *ss)
{
    return (struct sockaddr_in6 *) ss;
}
#endif
#else
#define sa2sin(S)	((struct sockaddr_in *)(S))
#define sa2sin6(S)	((struct sockaddr_in6 *)(S))
#define ss2sa(S)	((struct sockaddr *)(S))
#define ss2sin(S)	((struct sockaddr_in *)(S))
#define ss2sin6(S)	((struct sockaddr_in6 *)(S))
#endif

#if !defined (socklen)
/* socklen_t socklen (struct sockaddr *) */
#  ifdef HAVE_SA_LEN
#    define socklen(X) ((X)->sa_len)
#  else
#    ifdef KRB5_USE_INET6
#      define socklen(X) ((X)->sa_family == AF_INET6 ? (socklen_t) sizeof (struct sockaddr_in6) : (X)->sa_family == AF_INET ? (socklen_t) sizeof (struct sockaddr_in) : (socklen_t) sizeof (struct sockaddr))
#    else
#      define socklen(X) ((X)->sa_family == AF_INET ? (socklen_t) sizeof (struct sockaddr_in) : (socklen_t) sizeof (struct sockaddr))
#    endif
#  endif
#endif

#endif /* SOCKET_UTILS_H */
