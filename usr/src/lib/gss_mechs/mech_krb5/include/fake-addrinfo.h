#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (C) 2001,2002 by the Massachusetts Institute of Technology,
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

/* Approach overview:

   If a system version is available but buggy, save pointers to it,
   redefine the names to refer to static functions defined here, and
   in those functions, call the system versions and fix up the
   returned data.  Use the native data structures and flag values.

   If no system version exists, use gethostby* and fake it.  Define
   the data structures and flag values locally.


   Note that recent Windows developers' code has an interesting hack:
   When you include the right header files, with the right set of
   macros indicating system versions, you'll get an inline function
   that looks for getaddrinfo (or whatever) in the system library, and
   calls it if it's there.  If it's not there, it fakes it with
   gethostby* calls.

   We're taking a simpler approach: A system provides these routines or
   it does not.

   Someday, we may want to take into account different versions (say,
   different revs of GNU libc) where some are broken in one way, and
   some work or are broken in another way.  Cross that bridge when we
   come to it.  */

/* To do, maybe:

   + For AIX 4.3.3, using the RFC 2133 definition: Implement
     AI_NUMERICHOST.  It's not defined in the header file.

     For certain (old?) versions of GNU libc, AI_NUMERICHOST is
     defined but not implemented.

   + Use gethostbyname2, inet_aton and other IPv6 or thread-safe
     functions if available.  But, see
     http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=135182 for one
     gethostbyname2 problem on Linux.  And besides, if a platform is
     supporting IPv6 at all, they really should be doing getaddrinfo
     by now.

   + inet_ntop, inet_pton

   + Upgrade host requirements to include working implementations of
     these functions, and throw all this away.  Pleeease?  :-)  */

#ifndef FAI_DEFINED
#define FAI_DEFINED
#include "port-sockets.h"
#include "socket-utils.h"

#ifdef S_SPLINT_S
/*@-incondefs@*/
extern int
getaddrinfo (/*@in@*/ /*@null@*/ const char *,
	     /*@in@*/ /*@null@*/ const char *,
	     /*@in@*/ /*@null@*/ const struct addrinfo *,
	     /*@out@*/ struct addrinfo **)
    ;
extern void
freeaddrinfo (/*@only@*/ /*@out@*/ struct addrinfo *)
    ;
extern int
getnameinfo (const struct sockaddr *addr, socklen_t addrsz,
	     /*@out@*/ /*@null@*/ char *h, socklen_t hsz,
	     /*@out@*/ /*@null@*/ char *s, socklen_t ssz,
	     int flags)
    /*@requires (maxSet(h)+1) >= hsz /\ (maxSet(s)+1) >= ssz @*/
    /* too hard: maxRead(addr) >= (addrsz-1) */
    /*@modifies *h, *s@*/;
extern /*@dependent@*/ char *gai_strerror (int code) /*@*/;
/*@=incondefs@*/
#endif


#if defined (__APPLE__) && defined (__MACH__)
#undef HAVE_GETADDRINFO
#endif

#if defined (__linux__) || defined (_AIX)
/* See comments below.  */
#  define WRAP_GETADDRINFO
/* #  define WRAP_GETNAMEINFO */
#endif

#ifdef __linux__
# define COPY_FIRST_CANONNAME
#endif

#ifdef _AIX
# define NUMERIC_SERVICE_BROKEN
# define COPY_FIRST_CANONNAME
#endif


#ifdef COPY_FIRST_CANONNAME
# include <string.h>
#endif

#ifdef NUMERIC_SERVICE_BROKEN
# include <ctype.h>		/* isdigit */
# include <stdlib.h>		/* strtoul */
#endif

#ifdef _WIN32
#define HAVE_GETADDRINFO 1
#define HAVE_GETNAMEINFO 1
#endif


/* Do we actually have *any* systems we care about that don't provide
   either getaddrinfo or one of these two flavors of
   gethostbyname_r?  */
#if !defined(HAVE_GETHOSTBYNAME_R) || defined(THREADSAFE_GETHOSTBYNAME)
#define GET_HOST_BY_NAME(NAME, HP, ERR) \
    { (HP) = gethostbyname (NAME); (ERR) = h_errno; }
#define GET_HOST_BY_ADDR(ADDR, ADDRLEN, FAMILY, HP, ERR) \
    { (HP) = gethostbyaddr ((ADDR), (ADDRLEN), (FAMILY)); (ERR) = h_errno; }
#else
#ifdef _AIX /* XXX should have a feature test! */
#define GET_HOST_BY_NAME(NAME, HP, ERR) \
    {									\
	struct hostent my_h_ent;					\
	struct hostent_data my_h_ent_data;				\
	(HP) = (gethostbyname_r((NAME), &my_h_ent, &my_h_ent_data)	\
		? 0							\
		: &my_h_ent);						\
	(ERR) = h_errno;						\
    }
/*
#define GET_HOST_BY_ADDR(ADDR, ADDRLEN, FAMILY, HP, ERR) \
    {									\
	struct hostent my_h_ent;					\
	struct hostent_data my_h_ent_data;				\
	(HP) = (gethostbyaddr_r((ADDR), (ADDRLEN), (FAMILY), &my_h_ent,	\
				&my_h_ent_data)				\
		? 0							\
		: &my_h_ent);						\
	(ERR) = my_h_err;						\
    }
*/
#else
#ifdef GETHOSTBYNAME_R_RETURNS_INT
#define GET_HOST_BY_NAME(NAME, HP, ERR) \
    {									\
	struct hostent my_h_ent, *my_hp;				\
	int my_h_err;							\
	char my_h_buf[8192];						\
	(HP) = (gethostbyname_r((NAME), &my_h_ent,			\
				my_h_buf, sizeof (my_h_buf), &my_hp,	\
				&my_h_err)				\
		? 0							\
		: &my_h_ent);						\
	(ERR) = my_h_err;						\
    }
#define GET_HOST_BY_ADDR(ADDR, ADDRLEN, FAMILY, HP, ERR) \
    {									\
	struct hostent my_h_ent, *my_hp;				\
	int my_h_err;							\
	char my_h_buf[8192];						\
	(HP) = (gethostbyaddr_r((ADDR), (ADDRLEN), (FAMILY), &my_h_ent,	\
				my_h_buf, sizeof (my_h_buf), &my_hp,	\
				&my_h_err)				\
		? 0							\
		: &my_h_ent);						\
	(ERR) = my_h_err;						\
    }
#else
#define GET_HOST_BY_NAME(NAME, HP, ERR) \
    {									\
	struct hostent my_h_ent;					\
	int my_h_err;							\
	char my_h_buf[8192];						\
	(HP) = gethostbyname_r((NAME), &my_h_ent,			\
			       my_h_buf, sizeof (my_h_buf), &my_h_err);	\
	(ERR) = my_h_err;						\
    }
#define GET_HOST_BY_ADDR(ADDR, ADDRLEN, FAMILY, HP, ERR) \
    {									\
	struct hostent my_h_ent;					\
	int my_h_err;							\
	char my_h_buf[8192];						\
	(HP) = gethostbyaddr_r((ADDR), (ADDRLEN), (FAMILY), &my_h_ent,	\
			       my_h_buf, sizeof (my_h_buf), &my_h_err);	\
	(ERR) = my_h_err;						\
    }
#endif /* returns int? */
#endif /* _AIX */
#endif

/* Now do the same for getservby* functions.  */
#ifndef HAVE_GETSERVBYNAME_R
#define GET_SERV_BY_NAME(NAME, PROTO, SP, ERR) \
    ((SP) = getservbyname (NAME, PROTO), (ERR) = (SP) ? 0 : -1)
#define GET_SERV_BY_PORT(PORT, PROTO, SP, ERR) \
    ((SP) = getservbyport (PORT, PROTO), (ERR) = (SP) ? 0 : -1)
#else
#ifdef GETSERVBYNAME_R_RETURNS_INT
#define GET_SERV_BY_NAME(NAME, PROTO, SP, ERR) \
    {									\
	struct servent my_s_ent, *my_sp;				\
	int my_s_err;							\
	char my_s_buf[8192];						\
	(SP) = (getservbyname_r((NAME), (PROTO), &my_s_ent,		\
				my_s_buf, sizeof (my_s_buf), &my_sp,	\
				&my_s_err)				\
		? 0							\
		: &my_s_ent);						\
	(ERR) = my_s_err;						\
    }
#define GET_SERV_BY_PORT(PORT, PROTO, SP, ERR) \
    {									\
	struct servent my_s_ent, *my_sp;				\
	int my_s_err;							\
	char my_s_buf[8192];						\
	(SP) = (getservbyport_r((PORT), (PROTO), &my_s_ent,		\
				my_s_buf, sizeof (my_s_buf), &my_sp,	\
				&my_s_err)				\
		? 0							\
		: &my_s_ent);						\
	(ERR) = my_s_err;						\
    }
#else
/* returns ptr -- IRIX? */
#define GET_SERV_BY_NAME(NAME, PROTO, SP, ERR) \
    {									\
	struct servent my_s_ent;					\
	int my_s_err;							\
	char my_s_buf[8192];						\
	(SP) = getservbyname_r((NAME), (PROTO), &my_s_ent,		\
			       my_s_buf, sizeof (my_s_buf), &my_s_err);	\
	(ERR) = my_s_err;						\
    }

#define GET_SERV_BY_PORT(PORT, PROTO, SP, ERR) \
    {									\
	struct servent my_s_ent, *my_sp;				\
	char my_s_buf[8192];						\
	my_sp = getservbyport_r((PORT), (PROTO), &my_s_ent,		\
				my_s_buf, sizeof (my_s_buf));		\
	(SP) = my_sp;							\
	(ERR) = my_sp == 0;						\
	(ERR) = (ERR);	/* avoid "unused" warning */			\
    }
#endif
#endif

#ifdef WRAP_GETADDRINFO
static int (*const gaiptr) (const char *, const char *,
			    const struct addrinfo *,
			    struct addrinfo **) = &getaddrinfo;
static void (*const faiptr) (struct addrinfo *) = &freeaddrinfo;
#endif

#ifdef WRAP_GETNAMEINFO
static int (*const gniptr) (const struct sockaddr *, socklen_t,
			    char *, socklen_t, char *, socklen_t,
			    int) = &getnameinfo;
#endif

#if !defined (HAVE_GETADDRINFO) || defined(WRAP_GETADDRINFO)

#undef  getaddrinfo
#define getaddrinfo	my_fake_getaddrinfo
#undef  freeaddrinfo
#define freeaddrinfo	my_fake_freeaddrinfo

#endif

#if !defined (HAVE_GETADDRINFO) || defined(WRAP_GETNAMEINFO)

#undef  getnameinfo
#define getnameinfo	my_fake_getnameinfo

#endif

#if !defined (HAVE_GETADDRINFO)

#undef  gai_strerror
#define gai_strerror	my_fake_gai_strerror
#undef  addrinfo
#define addrinfo	my_fake_addrinfo

struct addrinfo {
    int ai_family;		/* PF_foo */
    int ai_socktype;		/* SOCK_foo */
    int ai_protocol;		/* 0, IPPROTO_foo */
    int ai_flags;		/* AI_PASSIVE etc */
    size_t ai_addrlen;		/* real length of socket address */
    char *ai_canonname;		/* canonical name of host */
    struct sockaddr *ai_addr;	/* pointer to variable-size address */
    struct addrinfo *ai_next;	/* next in linked list */
};

#undef	AI_PASSIVE
#define	AI_PASSIVE	0x01
#undef	AI_CANONNAME
#define	AI_CANONNAME	0x02
#undef	AI_NUMERICHOST
#define	AI_NUMERICHOST	0x04
/* N.B.: AI_V4MAPPED, AI_ADDRCONFIG, AI_ALL, and AI_DEFAULT are part
   of the spec for getipnodeby*, and *not* part of the spec for
   getaddrinfo.  Don't use them!  */
#undef	AI_V4MAPPED
#define	AI_V4MAPPED	eeeevil!
#undef	AI_ADDRCONFIG
#define	AI_ADDRCONFIG	eeeevil!
#undef	AI_ALL
#define	AI_ALL		eeeevil!
#undef	AI_DEFAULT
#define AI_DEFAULT	eeeevil!

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif
#ifndef NI_MAXSERV
#define NI_MAXSERV 32
#endif

#undef	NI_NUMERICHOST
#define NI_NUMERICHOST	0x01
#undef	NI_NUMERICSERV
#define NI_NUMERICSERV	0x02
#undef	NI_NAMEREQD
#define NI_NAMEREQD	0x04
#undef	NI_DGRAM
#define NI_DGRAM	0x08
#undef	NI_NOFQDN
#define NI_NOFQDN	0x10


#undef  EAI_ADDRFAMILY
#define EAI_ADDRFAMILY	1
#undef  EAI_AGAIN
#define EAI_AGAIN	2
#undef  EAI_BADFLAGS
#define EAI_BADFLAGS	3
#undef  EAI_FAIL
#define EAI_FAIL	4
#undef  EAI_FAMILY
#define EAI_FAMILY	5
#undef  EAI_MEMORY
#define EAI_MEMORY	6
#undef  EAI_NODATA
#define EAI_NODATA	7
#undef  EAI_NONAME
#define EAI_NONAME	8
#undef  EAI_SERVICE
#define EAI_SERVICE	9
#undef  EAI_SOCKTYPE
#define EAI_SOCKTYPE	10
#undef  EAI_SYSTEM
#define EAI_SYSTEM	11

#endif /* ! HAVE_GETADDRINFO */

#if (!defined (HAVE_GETADDRINFO) || defined (WRAP_GETADDRINFO)) && defined(DEBUG_ADDRINFO)
/* Some debug routines.  */

static const char *protoname (int p) {
    static char buf[30];

#define X(N) if (p == IPPROTO_ ## N) return #N

    X(TCP);
    X(UDP);
    X(ICMP);
    X(IPV6);
#ifdef IPPROTO_GRE
    X(GRE);
#endif
    X(NONE);
    X(RAW);
#ifdef IPPROTO_COMP
    X(COMP);
#endif

    sprintf(buf, " %-2d", p);
    return buf;
}	

static const char *socktypename (int t) {
    static char buf[30];
    switch (t) {
    case SOCK_DGRAM: return "DGRAM";
    case SOCK_STREAM: return "STREAM";
    case SOCK_RAW: return "RAW";
    case SOCK_RDM: return "RDM";
    case SOCK_SEQPACKET: return "SEQPACKET";
    }
    sprintf(buf, " %-2d", t);
    return buf;
}

static const char *familyname (int f) {
    static char buf[30];
    switch (f) {
    default:
	sprintf(buf, "AF %d", f);
	return buf;
    case AF_INET: return "AF_INET";
    case AF_INET6: return "AF_INET6";
#ifdef AF_UNIX
    case AF_UNIX: return "AF_UNIX";
#endif
    }
}

static void debug_dump_getaddrinfo_args (const char *name, const char *serv,
					 const struct addrinfo *hint)
{
    const char *sep;
    fprintf(stderr,
	    "getaddrinfo(hostname %s, service %s,\n"
	    "            hints { ",
	    name ? name : "(null)", serv ? serv : "(null)");
    if (hint) {
	sep = "";
#define Z(FLAG) if (hint->ai_flags & AI_##FLAG) fprintf(stderr, "%s%s", sep, #FLAG), sep = "|"
	Z(CANONNAME);
	Z(PASSIVE);
#ifdef AI_NUMERICHOST
	Z(NUMERICHOST);
#endif
	if (sep[0] == 0)
	    fprintf(stderr, "no-flags");
	if (hint->ai_family)
	    fprintf(stderr, " %s", familyname(hint->ai_family));
	if (hint->ai_socktype)
	    fprintf(stderr, " SOCK_%s", socktypename(hint->ai_socktype));
	if (hint->ai_protocol)
	    fprintf(stderr, " IPPROTO_%s", protoname(hint->ai_protocol));
    } else
	fprintf(stderr, "(null)");
    fprintf(stderr, " }):\n");
}

static void debug_dump_error (int err)
{
    fprintf(stderr, "error %d: %s\n", err, gai_strerror(err));
}

static void debug_dump_addrinfos (const struct addrinfo *ai)
{
    int count = 0;
    fprintf(stderr, "addrinfos returned:\n");
    while (ai) {
	fprintf(stderr, "%p...", ai);
	fprintf(stderr, " socktype=%s", socktypename(ai->ai_socktype));
	fprintf(stderr, " ai_family=%s", familyname(ai->ai_family));
	if (ai->ai_family != ai->ai_addr->sa_family)
	    fprintf(stderr, " sa_family=%s",
		    familyname(ai->ai_addr->sa_family));
	fprintf(stderr, "\n");
	ai = ai->ai_next;
	count++;
    }
    fprintf(stderr, "end addrinfos returned (%d)\n");
}

#endif

#if !defined (HAVE_GETADDRINFO) || defined (WRAP_GETADDRINFO)

static
int getaddrinfo (const char *name, const char *serv,
		 const struct addrinfo *hint, struct addrinfo **result);

static
void freeaddrinfo (struct addrinfo *ai);

#endif

#if !defined (HAVE_GETADDRINFO) || defined (WRAP_GETNAMEINFO)
static
int getnameinfo (const struct sockaddr *addr, socklen_t len,
		 char *host, socklen_t hostlen,
		 char *service, socklen_t servicelen,
		 int flags);
#endif

#if !defined (HAVE_GETADDRINFO)

#define HAVE_FAKE_GETADDRINFO /* was not originally HAVE_GETADDRINFO */
#define HAVE_GETADDRINFO
#undef  HAVE_GETNAMEINFO
#define HAVE_GETNAMEINFO 1

static
char *gai_strerror (int code);

#endif

/* Fudge things on older gai implementations.  */
/* AIX 4.3.3 is based on RFC 2133; no AI_NUMERICHOST.  */
#ifndef AI_NUMERICHOST
# define AI_NUMERICHOST 0
#endif

#if !defined(inline)
# if !defined(__GNUC__)
#  define inline /* nothing, just static */
# else
#  define inline __inline__
# endif
# define ADDRINFO_UNDEF_INLINE
#endif

#if !defined(_XOPEN_SOURCE_EXTENDED) && !defined(HAVE_MACSOCK_H) && !defined(_WIN32)
/* Hack for HPUX, to get h_errno.  */
# define _XOPEN_SOURCE_EXTENDED 1
# include <netdb.h>
# undef _XOPEN_SOURCE_EXTENDED
#endif

#ifdef HAVE_FAKE_GETADDRINFO
#define NEED_FAKE_GETADDRINFO
#endif

#if defined(NEED_FAKE_GETADDRINFO) || defined(WRAP_GETADDRINFO)
#include <stdlib.h>
#endif

#ifdef NEED_FAKE_GETADDRINFO
#include <string.h> /* for strspn */

static inline int translate_h_errno (int h);

static inline int fai_add_entry (struct addrinfo **result, void *addr,
				 int port, const struct addrinfo *template)
{
    struct addrinfo *n = malloc (sizeof (struct addrinfo));
    struct sockaddr_in *sin4;
    if (n == 0)
	return EAI_MEMORY;
    if (template->ai_family != AF_INET)
	return EAI_FAMILY;
    *n = *template;
    sin4 = malloc (sizeof (struct sockaddr_in));
    if (sin4 == 0)
	return EAI_MEMORY;
    n->ai_addr = (struct sockaddr *) sin4;
    sin4->sin_family = AF_INET;
    sin4->sin_addr = *(struct in_addr *)addr;
    sin4->sin_port = port;
#ifdef HAVE_SA_LEN
    sin4->sin_len = sizeof (struct sockaddr_in);
#endif
    n->ai_next = *result;
    *result = n;
    return 0;
}

static inline int fai_add_hosts_by_name (const char *name, int af,
					 struct addrinfo *template,
					 int portnum, int flags,
					 struct addrinfo **result)
{
    struct hostent *hp;
    int i, r;
    int herr;

    if (af != AF_INET)
	/* For now, real ipv6 support needs real getaddrinfo.  */
	return EAI_FAMILY;
    GET_HOST_BY_NAME (name, hp, herr);
    if (hp == 0)
	return translate_h_errno (herr);
    for (i = 0; hp->h_addr_list[i]; i++) {
	r = fai_add_entry (result, hp->h_addr_list[i], portnum, template);
	if (r)
	    return r;
    }
    if (*result && (flags & AI_CANONNAME))
	(*result)->ai_canonname = strdup (hp->h_name);
    return 0;
}

static inline void
fake_freeaddrinfo (struct addrinfo *ai)
{
    struct addrinfo *next;
    while (ai) {
	next = ai->ai_next;
	if (ai->ai_canonname)
	  free (ai->ai_canonname);
	if (ai->ai_addr)
	  free (ai->ai_addr);
	free (ai);
	ai = next;
    }
}

static inline int
fake_getaddrinfo (const char *name, const char *serv,
		  const struct addrinfo *hint, struct addrinfo **result)
{
    struct addrinfo *res = 0;
    int ret;
    int port = 0, socktype;
    int flags;
    struct addrinfo template;

#ifdef DEBUG_ADDRINFO
    debug_dump_getaddrinfo_args(name, serv, hint);
#endif

    if (hint != 0) {
	if (hint->ai_family != 0 && hint->ai_family != AF_INET)
	    return EAI_NODATA;
	socktype = hint->ai_socktype;
	flags = hint->ai_flags;
    } else {
	socktype = 0;
	flags = 0;
    }

    if (serv) {
	size_t numlen = strspn (serv, "0123456789");
	if (serv[numlen] == '\0') {
	    /* pure numeric */
	    unsigned long p = strtoul (serv, 0, 10);
	    if (p == 0 || p > 65535)
		return EAI_NONAME;
	    port = htons (p);
	} else {
	    struct servent *sp;
	    int try_dgram_too = 0;
	    if (socktype == 0) {
		try_dgram_too = 1;
		socktype = SOCK_STREAM;
	    }
	try_service_lookup:
#ifdef HAVE_GETSERVBYNAME_R
	    {
		char my_s_buf[1024];
		struct servent my_s_ent;
		sp = getservbyname_r(serv,
				     socktype == SOCK_STREAM ? "tcp" : "udp",
				     &my_s_ent, my_s_buf, sizeof(my_s_buf));
	    }
#else
	    sp = getservbyname (serv, socktype == SOCK_STREAM ? "tcp" : "udp");
#endif
	    if (sp == 0) {
		if (try_dgram_too) {
		    socktype = SOCK_DGRAM;
		    goto try_service_lookup;
		}
		return EAI_SERVICE;
	    }
	    port = sp->s_port;
	}
    }

    if (name == 0) {
	name = (flags & AI_PASSIVE) ? "0.0.0.0" : "127.0.0.1";
	flags |= AI_NUMERICHOST;
    }

    template.ai_family = AF_INET;
    template.ai_addrlen = sizeof (struct sockaddr_in);
    template.ai_socktype = socktype;
    template.ai_protocol = 0;
    template.ai_flags = 0;
    template.ai_canonname = 0;
    template.ai_next = 0;
    template.ai_addr = 0;

    /* If NUMERICHOST is set, parse a numeric address.
       If it's not set, don't accept such names.  */
    if (flags & AI_NUMERICHOST) {
	struct in_addr addr4;
#if 0
	ret = inet_aton (name, &addr4);
	if (ret)
	    return EAI_NONAME;
#else
	addr4.s_addr = inet_addr (name);
	if (addr4.s_addr == 0xffffffff || addr4.s_addr == -1)
	    /* 255.255.255.255 or parse error, both bad */
	    return EAI_NONAME;
#endif
	ret = fai_add_entry (&res, &addr4, port, &template);
    } else {
	ret = fai_add_hosts_by_name (name, AF_INET, &template, port, flags,
				     &res);
    }

    if (ret && ret != NO_ADDRESS) {
	fake_freeaddrinfo (res);
	return ret;
    }
    if (res == 0)
	return NO_ADDRESS;
    *result = res;
    return 0;
}

#include <errno.h>
static inline int
fake_getnameinfo (const struct sockaddr *sa, socklen_t len,
		  char *host, socklen_t hostlen,
		  char *service, socklen_t servicelen,
		  int flags)
{
    struct hostent *hp;
    const struct sockaddr_in *sinp;
    struct servent *sp;
    size_t hlen, slen;

    if (sa->sa_family != AF_INET) {
	return EAI_FAMILY;
    }
    sinp = (const struct sockaddr_in *) sa;

    hlen = hostlen;
    if (hostlen < 0 || hlen != hostlen) {
	errno = EINVAL;
	return EAI_SYSTEM;
    }
    slen = servicelen;
    if (servicelen < 0 || slen != servicelen) {
	errno = EINVAL;
	return EAI_SYSTEM;
    }

    if (host) {
	if (flags & NI_NUMERICHOST) {
#if (defined(__GNUC__) && defined(__mips__)) || 1 /* thread safety always */
	    /* The inet_ntoa call, passing a struct, fails on IRIX 6.5
	       using gcc 2.95; we get back "0.0.0.0".  Since this in a
	       configuration still important at Athena, here's the
	       workaround, which also happens to be thread-safe....  */
	    const unsigned char *uc;
	    char tmpbuf[20];
	numeric_host:
	    uc = (const unsigned char *) &sinp->sin_addr;
	    sprintf(tmpbuf, "%d.%d.%d.%d", uc[0], uc[1], uc[2], uc[3]);
	    strncpy(host, tmpbuf, hlen);
#else
	    char *p;
	numeric_host:
	    p = inet_ntoa (sinp->sin_addr);
	    strncpy (host, p, hlen);
#endif
	} else {
	    int herr;
	    GET_HOST_BY_ADDR((const char *) &sinp->sin_addr,
			     sizeof (struct in_addr),
			     sa->sa_family, hp, herr);
	    if (hp == 0) {
		if (herr == NO_ADDRESS && !(flags & NI_NAMEREQD)) /* ??? */
		    goto numeric_host;
		return translate_h_errno (herr);
	    }
	    /* According to the Open Group spec, getnameinfo can
	       silently truncate, but must still return a
	       null-terminated string.  */
	    strncpy (host, hp->h_name, hlen);
	}
	host[hostlen-1] = 0;
    }

    if (service) {
	if (flags & NI_NUMERICSERV) {
	    char numbuf[10];
	    int port;
	numeric_service:
	    port = ntohs (sinp->sin_port);
	    if (port < 0 || port > 65535)
		return EAI_FAIL;
	    sprintf (numbuf, "%d", port);
	    strncpy (service, numbuf, slen);
	} else {
	    int serr;
	    GET_SERV_BY_PORT(sinp->sin_port,
			     (flags & NI_DGRAM) ? "udp" : "tcp",
			     sp, serr);
	    if (sp == 0)
		goto numeric_service;
	    strncpy (service, sp->s_name, slen);
	}
	service[servicelen-1] = 0;
    }

    return 0;
}

#include <errno.h>

static inline
char *gai_strerror (int code)
{
    switch (code) {
    case EAI_ADDRFAMILY: return "address family for nodename not supported";
    case EAI_AGAIN:	return "temporary failure in name resolution";
    case EAI_BADFLAGS:	return "bad flags to getaddrinfo/getnameinfo";
    case EAI_FAIL:	return "non-recoverable failure in name resolution";
    case EAI_FAMILY:	return "ai_family not supported";
    case EAI_MEMORY:	return "out of memory";
    case EAI_NODATA:	return "no address associated with hostname";
    case EAI_NONAME:	return "name does not exist";
    case EAI_SERVICE:	return "service name not supported for specified socket type";
    case EAI_SOCKTYPE:	return "ai_socktype not supported";
    case EAI_SYSTEM:	return strerror (errno);
    default:		return "bogus getaddrinfo error?";
    }
}

static inline int translate_h_errno (int h)
{
    switch (h) {
    case 0:
	return 0;
#ifdef NETDB_INTERNAL
    case NETDB_INTERNAL:
	if (errno == ENOMEM)
	    return EAI_MEMORY;
	return EAI_SYSTEM;
#endif
    case HOST_NOT_FOUND:
	return EAI_NONAME;
    case TRY_AGAIN:
	return EAI_AGAIN;
    case NO_RECOVERY:
	return EAI_FAIL;
    case NO_DATA:
#if NO_DATA != NO_ADDRESS
    case NO_ADDRESS:
#endif
	return EAI_NODATA;
    default:
	return EAI_SYSTEM;
    }
}

#ifdef HAVE_FAKE_GETADDRINFO
static inline
int getaddrinfo (const char *name, const char *serv,
		 const struct addrinfo *hint, struct addrinfo **result)
{
    return fake_getaddrinfo(name, serv, hint, result);
}

static inline
void freeaddrinfo (struct addrinfo *ai)
{
    fake_freeaddrinfo(ai);
}

static inline
int getnameinfo (const struct sockaddr *sa, socklen_t len,
		 char *host, socklen_t hostlen,
		 char *service, socklen_t servicelen,
		 int flags)
{
    return fake_getnameinfo(sa, len, host, hostlen, service, servicelen,
			    flags);
}
#endif /* HAVE_FAKE_GETADDRINFO */
#endif /* NEED_FAKE_GETADDRINFO */


#ifdef WRAP_GETADDRINFO

static inline
int
getaddrinfo (const char *name, const char *serv, const struct addrinfo *hint,
	     struct addrinfo **result)
{
    int aierr;
#if defined(_AIX) || defined(COPY_FIRST_CANONNAME)
    struct addrinfo *ai;
#endif
#ifdef NUMERIC_SERVICE_BROKEN
    int service_is_numeric = 0;
    int service_port = 0;
    int socket_type = 0;
#endif

#ifdef DEBUG_ADDRINFO
    debug_dump_getaddrinfo_args(name, serv, hint);
#endif

#ifdef NUMERIC_SERVICE_BROKEN
    /* AIX 4.3.3 is broken.  (Or perhaps out of date?)

       If a numeric service is provided, and it doesn't correspond to
       a known service name for tcp or udp (as appropriate), an error
       code (for "host not found") is returned.  If the port maps to a
       known service for both udp and tcp, all is well.  */
    if (serv && serv[0] && isdigit(serv[0])) {
	unsigned long lport;
	char *end;
	lport = strtoul(serv, &end, 10);
	if (!*end) {
	    if (lport > 65535)
		return EAI_SOCKTYPE;
	    service_is_numeric = 1;
	    service_port = htons(lport);
	    serv = "discard";	/* defined for both udp and tcp */
	    if (hint)
		socket_type = hint->ai_socktype;
	}
    }
#endif

    aierr = (*gaiptr) (name, serv, hint, result);
    if (aierr || *result == 0) {
#ifdef DEBUG_ADDRINFO
	debug_dump_error(aierr);
#endif
	return aierr;
    }

    /* Linux libc version 6 (libc-2.2.4.so on Debian) is broken.

       RFC 2553 says that when AI_CANONNAME is set, the ai_canonname
       flag of the first returned structure has the canonical name of
       the host.  Instead, GNU libc sets ai_canonname in each returned
       structure to the name that the corresponding address maps to,
       if any, or a printable numeric form.

       RFC 2553 bis and the new Open Group spec say that field will be
       the canonical name if it can be determined, otherwise, the
       provided hostname or a copy of it.

       IMNSHO, "canonical name" means CNAME processing and not PTR
       processing, but I can see arguing it.  Using the numeric form
       when that's not the form provided is just wrong.  So, let's fix
       it.

       The glibc 2.2.5 sources indicate that the canonical name is
       *not* allocated separately, it's just some extra storage tacked
       on the end of the addrinfo structure.  So, let's try this
       approach: If getaddrinfo sets ai_canonname, we'll replace the
       *first* one with allocated storage, and free up that pointer in
       freeaddrinfo if it's set; the other ai_canonname fields will be
       left untouched.  And we'll just pray that the application code
       won't mess around with the list structure; if we start doing
       that, we'll have to start replacing and freeing all of the
       ai_canonname fields.

       Ref: http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=133668 .

       Since it's dependent on the target hostname, it's hard to check
       for at configure time.  Always do it on Linux for now.  When
       they get around to fixing it, add a compile-time or run-time
       check for the glibc version in use.

       Some Windows documentation says that even when AI_CANONNAME is
       set, the returned ai_canonname field can be null.  The NetBSD
       1.5 implementation also does this, if the input hostname is a
       numeric host address string.  That case isn't handled well at
       the moment.  */

#ifdef COPY_FIRST_CANONNAME
    /*
     * This code must *always* return an error, return a null
     * ai_canonname, or return an ai_canonname allocated here using
     * malloc, so that freeaddrinfo can always free a non-null
     * ai_canonname.  Note that it really doesn't matter if the
     * AI_CANONNAME flag was set.
     */
    ai = *result;
    if (ai->ai_canonname) {
	struct hostent *hp;
	const char *name2 = 0;
	int i, herr;

	/*
	 * Current versions of GET_HOST_BY_NAME will fail if the
	 * target hostname has IPv6 addresses only.  Make sure it
	 * fails fairly cleanly.
	 */
	GET_HOST_BY_NAME (name, hp, herr);
	if (hp == 0) {
	    /*
	     * This case probably means it's an IPv6-only name.  If
	     * ai_canonname is a numeric address, get rid of it.
	     */
	    if (ai->ai_canonname && strchr(ai->ai_canonname, ':'))
		ai->ai_canonname = 0;
	    name2 = ai->ai_canonname ? ai->ai_canonname : name;
	} else {
	    /* Sometimes gethostbyname will be directed to /etc/hosts
	       first, and sometimes that file will have entries with
	       the unqualified name first.  So take the first entry
	       that looks like it could be a FQDN.  */
	    for (i = 0; hp->h_aliases[i]; i++) {
		if (strchr(hp->h_aliases[i], '.') != 0) {
		    name2 = hp->h_aliases[i];
		    break;
		}
	    }
	    /* Give up, just use the first name (h_name ==
	       h_aliases[0] on all systems I've seen).  */
	    if (hp->h_aliases[i] == 0)
		name2 = hp->h_name;
	}

	ai->ai_canonname = strdup(name2);
	if (name2 != 0 && ai->ai_canonname == 0) {
	    (*faiptr)(ai);
	    *result = 0;
#ifdef DEBUG_ADDRINFO
	    debug_dump_error(EAI_MEMORY);
#endif
	    return EAI_MEMORY;
	}
	/* Zap the remaining ai_canonname fields glibc fills in, in
	   case the application messes around with the list
	   structure.  */
	while ((ai = ai->ai_next) != NULL)
	    ai->ai_canonname = 0;
    }
#endif

#ifdef NUMERIC_SERVICE_BROKEN
    if (service_port != 0) {
	for (ai = *result; ai; ai = ai->ai_next) {
	    if (socket_type != 0 && ai->ai_socktype == 0)
		/* Is this check actually needed?  */
		ai->ai_socktype = socket_type;
	    switch (ai->ai_family) {
	    case AF_INET:
		((struct sockaddr_in *)ai->ai_addr)->sin_port = service_port;
		break;
	    case AF_INET6:
		((struct sockaddr_in6 *)ai->ai_addr)->sin6_port = service_port;
		break;
	    }
	}
    }
#endif

#ifdef _AIX
    for (ai = *result; ai; ai = ai->ai_next) {
	/* AIX 4.3.3 libc is broken.  It doesn't set the family or len
	   fields of the sockaddr structures.  Usually, sa_family is
	   zero, but I've seen it set to 1 in some cases also (maybe
	   just leftover from previous contents of the memory
	   block?).  So, always override what libc returned.  */
	ai->ai_addr->sa_family = ai->ai_family;
#ifdef HAVE_SA_LEN /* always true on AIX, actually */
	ai->ai_addr->sa_len = ai->ai_addrlen;
#endif
    }
#endif

    /* Not dealt with currently:

       - Some versions of GNU libc can lose some IPv4 addresses in
	 certain cases when multiple IPv4 and IPv6 addresses are
	 available.  */

#ifdef DEBUG_ADDRINFO
    debug_dump_addrinfos(*result);
#endif

    return 0;
}

static inline
void freeaddrinfo (struct addrinfo *ai)
{
#ifdef COPY_FIRST_CANONNAME
    if (ai) {
      free(ai->ai_canonname);
	ai->ai_canonname = 0;
	(*faiptr)(ai);
    }
#else
    (*faiptr)(ai);
#endif
}
#endif /* WRAP_GETADDRINFO */

#ifdef WRAP_GETNAMEINFO
static inline
int getnameinfo (const struct sockaddr *sa, socklen_t len,
		 char *host, socklen_t hostlen,
		 char *service, socklen_t servicelen,
		 int flags)
{
    return (*gniptr)(sa, len, host, hostlen, service, servicelen, flags);
}
#endif /* WRAP_GETNAMEINFO */

#if defined(KRB5_USE_INET6) && defined(NEED_INSIXADDR_ANY) 
/* If compiling with IPv6 support and C library does not define in6addr_any */
static const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
#endif

#ifdef ADDRINFO_UNDEF_INLINE
# undef inline
# undef ADDRINFO_UNDEF_INLINE
#endif

#endif /* FAI_DEFINED */
