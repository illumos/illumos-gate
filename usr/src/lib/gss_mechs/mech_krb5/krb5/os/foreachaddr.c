/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * include/foreachaddr.c
 *
 * Copyright 1990,1991,2000,2001,2002 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Iterate over the protocol addresses supported by this host, invoking
 * a callback function or three supplied by the caller.
 *
 * XNS support is untested, but "should just work".  (Hah!)
 */

/* This is the primary "export" of this file.  It's a static function,
   so this file must be #included in the .c file containing the
   caller.

   This function iterates over all the addresses it can find for the
   local system, in one or two passes.  In each pass, and between the
   two, it can invoke callback functions supplied by the caller.  The
   two passes should operate on the same information, though not
   necessarily in the same order each time.  Duplicate and local
   addresses should be eliminated.  Storage passed to callback
   functions should not be assumed to be valid after foreach_localaddr
   returns.

   The int return value is an errno value (XXX or krb5_error_code
   returned for a socket error) if something internal to
   foreach_localaddr fails.  If one of the callback functions wants to
   indicate an error, it should store something via the 'data' handle.
   If any callback function returns a non-zero value,
   foreach_localaddr will clean up and return immediately.

   Multiple definitions are provided below, dependent on various
   system facilities for extracting the necessary information.  */

/* Solaris Kerberos: changing foreach_localaddr to non-static as it's called in
 * a couple places.
 */

#ifdef TEST
# define Tprintf(X) printf X
# define Tperror(X) perror(X)
#else
# define Tprintf(X) (void) X
# define Tperror(X) (void)(X)
#endif

/*
 * The SIOCGIF* ioctls require a socket.
 * It doesn't matter *what* kind of socket they use, but it has to be
 * a socket.
 *
 * Of course, you can't just ask the kernel for a socket of arbitrary
 * type; you have to ask for one with a valid type.
 *
 */
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#ifndef USE_AF
#define USE_AF AF_INET
#define USE_TYPE SOCK_DGRAM
#define USE_PROTO 0
#endif
#endif

#ifdef KRB5_USE_NS
#include <netns/ns.h>
#ifndef USE_AF
#define USE_AF AF_NS
#define USE_TYPE SOCK_DGRAM
#define USE_PROTO 0		/* guess */
#endif
#endif
/*
 * Add more address families here.
 */

#include <errno.h>
#include <fake-addrinfo.h>
#include <sys/sockio.h>
#include <k5-int.h>

/*
 * Return all the protocol addresses of this host.
 *
 * We could kludge up something to return all addresses, assuming that
 * they're valid kerberos protocol addresses, but we wouldn't know the
 * real size of the sockaddr or know which part of it was actually the
 * host part.
 *
 * This uses the SIOCGIFCONF, SIOCGIFFLAGS, and SIOCGIFADDR ioctl's.
 */

/*
 * BSD 4.4 defines the size of an ifreq to be
 * max(sizeof(ifreq), sizeof(ifreq.ifr_name)+ifreq.ifr_addr.sa_len
 * However, under earlier systems, sa_len isn't present, so the size is 
 * just sizeof(struct ifreq).
 */
#ifdef HAVE_SA_LEN
#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif
#define ifreq_size(i) max(sizeof(struct ifreq),\
     sizeof((i).ifr_name)+(i).ifr_addr.sa_len)
#else
#define ifreq_size(i) sizeof(struct ifreq)
#endif /* HAVE_SA_LEN*/


#ifdef SIOCGLIFCONF /* Solaris */
static int
get_lifconf (int af, int s, size_t *lenp, char *buf)
    /*@modifies *buf,*lenp@*/
{
    int ret;
    struct lifconf lifc;

    lifc.lifc_family = af;
    lifc.lifc_flags = 0;
    lifc.lifc_len = *lenp;
    lifc.lifc_buf = buf;
    memset(buf, 0, *lenp);

    ret = ioctl (s, SIOCGLIFCONF, (char *)&lifc);
    if (ret)
	Tperror ("SIOCGLIFCONF");

    *lenp = lifc.lifc_len;
    return ret;
}
#endif

/* Return value is errno if internal stuff failed, otherwise zero,
   even in the case where a called function terminated the iteration.

   If one of the callback functions wants to pass back an error
   indication, it should do it via some field pointed to by the DATA
   argument.  */

int
foreach_localaddr (void *data,
		   int (*pass1fn) (void *, struct sockaddr *),
		   int (*betweenfn) (void *),
		   int (*pass2fn) (void *, struct sockaddr *))
{
    /* Okay, this is kind of odd.  We have to use each of the address
       families we care about, because with an AF_INET socket, extra
       interfaces like hme0:1 that have only AF_INET6 addresses will
       cause errors.  Similarly, if hme0 has more AF_INET addresses
       than AF_INET6 addresses, we won't be able to retrieve all of
       the AF_INET addresses if we use an AF_INET6 socket.  Since
       neither family is guaranteed to have the greater number of
       addresses, we should use both.

       If it weren't for this little quirk, we could use one socket of
       any type, and ask for addresses of all types.  At least, it
       seems to work that way.  */

    /* Solaris kerberos: avoid using AF_NS if no define */
#if defined (KRB5_USE_INET6) && defined (KRB5_USE_NS)
    static const int afs[] = { AF_INET, AF_NS, AF_INET6 };
#elif defined (KRB5_USE_INET6)
    static const int afs[] = { AF_INET, AF_INET6 };
#else
    static const int afs[] = { AF_INET };
#endif
    
#define N_AFS (sizeof (afs) / sizeof (afs[0]))
    struct {
	int af;
	int sock;
	void *buf;
	size_t buf_size;
	struct lifnum lifnum;
    } afp[N_AFS];
    int code, i, j;
    int retval = 0, afidx;
    krb5_error_code sock_err = 0;
    struct lifreq *lifr, lifreq, *lifr2;

#define FOREACH_AF() for (afidx = 0; afidx < N_AFS; afidx++)
#define P (afp[afidx])

    KRB5_LOG0(KRB5_INFO, "foreach_localaddr() start");
    /* init */
    FOREACH_AF () {
	P.af = afs[afidx];
	P.sock = -1;
	P.buf = 0;
    }

    /* first pass: get raw data, discard uninteresting addresses, callback */
    FOREACH_AF () {
	KRB5_LOG (KRB5_INFO, "foreach_localaddr() trying af %d", P.af);
	P.sock = socket (P.af, USE_TYPE, USE_PROTO);
	if (P.sock < 0) {
	    sock_err = SOCKET_ERROR;
	    Tperror ("socket");
	    continue;
	}

	P.lifnum.lifn_family = P.af;
	P.lifnum.lifn_flags = 0;
	P.lifnum.lifn_count = 0;
	code = ioctl (P.sock, SIOCGLIFNUM, &P.lifnum);
	if (code) {
	    Tperror ("ioctl(SIOCGLIFNUM)");
	    retval = errno;
	    goto punt;
	}

	KRB5_LOG (KRB5_INFO, "foreach_localaddr() lifn_count %d",
		P.lifnum.lifn_count);
	P.buf_size = P.lifnum.lifn_count * sizeof (struct lifreq) * 2;
	P.buf = malloc (P.buf_size);
	if (P.buf == NULL) {
	    retval = errno;
	    goto punt;
	}

	code = get_lifconf (P.af, P.sock, &P.buf_size, P.buf);
	if (code < 0) {
	    retval = errno;
	    goto punt;
	}

	for (i = 0; i < P.buf_size; i+= sizeof (*lifr)) {
	    /*LINTED*/
	    lifr = (struct lifreq *)((caddr_t) P.buf+i);

	    strncpy(lifreq.lifr_name, lifr->lifr_name,
		    sizeof (lifreq.lifr_name));
	    KRB5_LOG (KRB5_INFO, "foreach_localaddr() interface %s",
		    lifreq.lifr_name);
	    /* ioctl unknown to lclint */
	    if (ioctl (P.sock, SIOCGLIFFLAGS, (char *)&lifreq) < 0) {
		Tperror ("ioctl(SIOCGLIFFLAGS)");
	    skip:
		KRB5_LOG (KRB5_INFO, 
			"foreach_localaddr() skipping interface %s",
			lifr->lifr_name);
		/* mark for next pass */
		lifr->lifr_name[0] = '\0';
		continue;
	    }

#ifdef IFF_LOOPBACK
	    /* None of the current callers want loopback addresses.  */
	    if (lifreq.lifr_flags & IFF_LOOPBACK) {
		Tprintf (("  loopback\n"));
		goto skip;
	    }
#endif
	    /* Ignore interfaces that are down.  */
	    if ((lifreq.lifr_flags & IFF_UP) == 0) {
		Tprintf (("  down\n"));
		goto skip;
	    }

	    /* Make sure we didn't process this address already.  */
	    for (j = 0; j < i; j += sizeof (*lifr2)) {
		/*LINTED*/
		lifr2 = (struct lifreq *)((caddr_t) P.buf+j);
		if (lifr2->lifr_name[0] == '\0')
		    continue;
		if (lifr2->lifr_addr.ss_family == lifr->lifr_addr.ss_family
		    /* Compare address info.  If this isn't good enough --
		       i.e., if random padding bytes turn out to differ
		       when the addresses are the same -- then we'll have
		       to do it on a per address family basis.  */
		    && !memcmp (&lifr2->lifr_addr, &lifr->lifr_addr,
				sizeof (*lifr))) {
		    Tprintf (("  duplicate addr\n"));
		    KRB5_LOG0 (KRB5_INFO, "foreach_localaddr() dup addr");
		    goto skip;
		}
	    }

	    if ((*pass1fn) (data, ss2sa (&lifr->lifr_addr)))
		goto punt;
	}
    }

    /* Did we actually get any working sockets?  */
    FOREACH_AF ()
	if (P.sock != -1)
	    goto have_working_socket;
    retval = sock_err;
    goto punt;
have_working_socket:

    if (betweenfn != NULL && (*betweenfn)(data))
	goto punt;

    if (pass2fn)
	FOREACH_AF ()
	    if (P.sock >= 0) {
		for (i = 0; i < P.buf_size; i+= sizeof (*lifr)) {
		    /*LINTED*/
		    lifr = (struct lifreq *)((caddr_t) P.buf+i);

		    if (lifr->lifr_name[0] == '\0')
			/* Marked in first pass to be ignored.  */
			continue;

		    KRB5_LOG (KRB5_INFO,
			    "foreach_localaddr() doing pass2fn i = %d",
			    i);
		    if ((*pass2fn) (data, ss2sa (&lifr->lifr_addr)))
			goto punt;
		}
	    }
punt:
    FOREACH_AF () {
	closesocket(P.sock);
	free (P.buf);
    }

    return retval;
}
