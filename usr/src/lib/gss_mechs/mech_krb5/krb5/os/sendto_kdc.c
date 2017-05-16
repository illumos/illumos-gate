/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * lib/krb5/os/sendto_kdc.c
 *
 * Copyright 1990,1991,2001,2002,2004,2005,2007 by the Massachusetts Institute of Technology.
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
 * Send packet to KDC for realm; wait for response, retransmitting
 * as necessary.
 */

#include "fake-addrinfo.h"
#include "k5-int.h"

/* Solaris Kerberos */
#include <syslog.h>
#include <locale.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#include "os-proto.h"
#ifdef _WIN32
#include <sys/timeb.h>
#endif

#ifdef _AIX
#include <sys/select.h>
#endif

#ifndef _WIN32
/* For FIONBIO.  */
#include <sys/ioctl.h>
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif
#endif

#define MAX_PASS		    3
/* Solaris Kerberos: moved to k5-int.h */
/* #define DEFAULT_UDP_PREF_LIMIT	 1465 */
#define HARD_UDP_LIMIT		32700 /* could probably do 64K-epsilon ? */

#undef DEBUG

#ifdef DEBUG
int krb5int_debug_sendto_kdc = 0;
#define debug krb5int_debug_sendto_kdc

static void default_debug_handler (const void *data, size_t len)
{
#if 0
    FILE *logfile;
    logfile = fopen("/tmp/sendto_kdc.log", "a");
    if (logfile == NULL)
	return;
    fwrite(data, 1, len, logfile);
    fclose(logfile);
#else
    fwrite(data, 1, len, stderr);
    /* stderr is unbuffered */
#endif
}

void (*krb5int_sendtokdc_debug_handler) (const void *, size_t) = default_debug_handler;

/* 
 * Solaris Kerberos: only including the debug stuff if DEBUG defined outside
 * this file.
 */
static char global_err_str[NI_MAXHOST + NI_MAXSERV + 1024];

/* Solaris kerberos: removed put() since it isn't needed. */
#if 0
static void put(const void *ptr, size_t len)
{
    (*krb5int_sendtokdc_debug_handler)(ptr, len);
}
#endif

static void putstr(const char *str)
{
    /* Solaris kerberos: build the string which will be passed to syslog later */
    strlcat(global_err_str, str, sizeof (global_err_str));
}
#else
void (*krb5int_sendtokdc_debug_handler) (const void *, size_t) = 0;
#endif

#define dprint krb5int_debug_fprint
 void
krb5int_debug_fprint (const char *fmt, ...)
{
#ifdef DEBUG
    va_list args;

    /* Temporaries for variable arguments, etc.  */
    krb5_error_code kerr;
    int err;
    fd_set *rfds, *wfds, *xfds;
    int i;
    int maxfd;
    struct timeval *tv;
    struct addrinfo *ai;
    const krb5_data *d;
    char addrbuf[NI_MAXHOST], portbuf[NI_MAXSERV];
    const char *p;
#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif
    char tmpbuf[max(NI_MAXHOST + NI_MAXSERV + 30, 200)];

    /* 
     * Solaris kerberos: modified this function to create a string to pass to
     * syslog()
     */
    global_err_str[0] = NULL;

    va_start(args, fmt);

#define putf(FMT,X)	(sprintf(tmpbuf,FMT,X),putstr(tmpbuf))

    for (; *fmt; fmt++) {
	if (*fmt != '%') {
	    /* Possible optimization: Look for % and print all chars
	       up to it in one call.  */
	    putf("%c", *fmt);
	    continue;
	}
	/* After this, always processing a '%' sequence.  */
	fmt++;
	switch (*fmt) {
	case 0:
	default:
	    abort();
	case 'E':
	    /* %E => krb5_error_code */
	    kerr = va_arg(args, krb5_error_code);
	    sprintf(tmpbuf, "%lu/", (unsigned long) kerr);
	    putstr(tmpbuf);
	    p = error_message(kerr);
	    putstr(p);
	    break;
	case 'm':
	    /* %m => errno value (int) */
	    /* Like syslog's %m except the errno value is passed in
	       rather than the current value.  */
	    err = va_arg(args, int);
	    putf("%d/", err);
	    p = NULL;
#ifdef HAVE_STRERROR_R
	    if (strerror_r(err, tmpbuf, sizeof(tmpbuf)) == 0)
		p = tmpbuf;
#endif
	    if (p == NULL)
		p = strerror(err);
	    putstr(p);
	    break;
	case 'F':
	    /* %F => fd_set *, fd_set *, fd_set *, int */
	    rfds = va_arg(args, fd_set *);
	    wfds = va_arg(args, fd_set *);
	    xfds = va_arg(args, fd_set *);
	    maxfd = va_arg(args, int);

	    for (i = 0; i < maxfd; i++) {
		int r = FD_ISSET(i, rfds);
		int w = wfds && FD_ISSET(i, wfds);
		int x = xfds && FD_ISSET(i, xfds);
		if (r || w || x) {
		    putf(" %d", i);
		    if (r)
			putstr("r");
		    if (w)
			putstr("w");
		    if (x)
			putstr("x");
		}
	    }
	    putstr(" ");
	    break;
	case 's':
	    /* %s => char * */
	    p = va_arg(args, const char *);
	    putstr(p);
	    break;
	case 't':
	    /* %t => struct timeval * */
	    tv = va_arg(args, struct timeval *);
	    if (tv) {
		sprintf(tmpbuf, "%ld.%06ld",
			(long) tv->tv_sec, (long) tv->tv_usec);
		putstr(tmpbuf);
	    } else
		putstr("never");
	    break;
	case 'd':
	    /* %d => int */
	    putf("%d", va_arg(args, int));
	    break;
	case 'p':
	    /* %p => pointer */
	    putf("%p", va_arg(args, void*));
	    break;
	case 'A':
	    /* %A => addrinfo */
	    ai = va_arg(args, struct addrinfo *);
	    if (ai->ai_socktype == SOCK_DGRAM)
		strcpy(tmpbuf, "dgram");
	    else if (ai->ai_socktype == SOCK_STREAM)
		strcpy(tmpbuf, "stream");
	    else
		sprintf(tmpbuf, "socktype%d", ai->ai_socktype);
	    if (0 != getnameinfo (ai->ai_addr, ai->ai_addrlen,
				  addrbuf, sizeof (addrbuf),
				  portbuf, sizeof (portbuf),
				  NI_NUMERICHOST | NI_NUMERICSERV)) {
		if (ai->ai_addr->sa_family == AF_UNSPEC)
		    strcpy(tmpbuf + strlen(tmpbuf), " AF_UNSPEC");
		else
		    sprintf(tmpbuf + strlen(tmpbuf), " af%d", ai->ai_addr->sa_family);
	    } else
		sprintf(tmpbuf + strlen(tmpbuf), " %s.%s", addrbuf, portbuf);
	    putstr(tmpbuf);
	    break;
	case 'D':
	    /* %D => krb5_data * */
	    d = va_arg(args, krb5_data *);
	    /* Solaris Kerberos */
	    p = d->data;
	    putstr("0x");
	    for (i = 0; i < d->length; i++) {
		putf("%.2x", *p++);
	    }
	    break;
	}
    }
    va_end(args);

    /* Solaris kerberos: use syslog() for debug output */
    syslog(LOG_DEBUG, global_err_str);
#endif
}

#define print_addrlist krb5int_print_addrlist
static void
print_addrlist (const struct addrlist *a)
{
    int i;
    dprint("%d{", a->naddrs);
    for (i = 0; i < a->naddrs; i++)
	dprint("%s%p=%A", i ? "," : "", (void*)a->addrs[i].ai, a->addrs[i].ai);
    dprint("}");
}

static int
merge_addrlists (struct addrlist *dest, struct addrlist *src)
{
    /* Wouldn't it be nice if we could filter out duplicates?  The
       alloc/free handling makes that pretty difficult though.  */
    int err, i;

/* Solaris Kerberos */
#ifdef DEBUG
    /*LINTED*/
    dprint("merging addrlists:\n\tlist1: ");
    for (i = 0; i < dest->naddrs; i++)
	/*LINTED*/
	dprint(" %A", dest->addrs[i].ai);
    /*LINTED*/
    dprint("\n\tlist2: ");
    for (i = 0; i < src->naddrs; i++)
	/*LINTED*/
	dprint(" %A", src->addrs[i].ai);
    /*LINTED*/
    dprint("\n");
#endif

    err = krb5int_grow_addrlist (dest, src->naddrs);
    if (err)
	return err;
    for (i = 0; i < src->naddrs; i++) {
	dest->addrs[dest->naddrs + i] = src->addrs[i];
	src->addrs[i].ai = 0;
	src->addrs[i].freefn = 0;
    }
    dest->naddrs += i;
    src->naddrs = 0;

/* Solaris Kerberos */
#ifdef DEBUG
    /*LINTED*/
    dprint("\tout:   ");
    for (i = 0; i < dest->naddrs; i++)
	/*LINTED*/
	dprint(" %A", dest->addrs[i].ai);
    /*LINTED*/
    dprint("\n");
#endif

    return 0;
}

static int
in_addrlist (struct addrinfo *thisaddr, struct addrlist *list)
{
    int i;
    for (i = 0; i < list->naddrs; i++) {
	if (thisaddr->ai_addrlen == list->addrs[i].ai->ai_addrlen
	    && !memcmp(thisaddr->ai_addr, list->addrs[i].ai->ai_addr,
		       thisaddr->ai_addrlen))
	    return 1;
    }
    return 0;
}

static int
check_for_svc_unavailable (krb5_context context,
			   const krb5_data *reply,
			   void *msg_handler_data)
{
    krb5_error_code *retval = (krb5_error_code *)msg_handler_data;

    *retval = 0;

    if (krb5_is_krb_error(reply)) {
	krb5_error *err_reply;

	if (decode_krb5_error(reply, &err_reply) == 0) {
	    *retval = err_reply->error;
	    krb5_free_error(context, err_reply);

	    /* Returning 0 means continue to next KDC */
	    return (*retval != KDC_ERR_SVC_UNAVAILABLE);
	}
    }

    return 1;
}

/*
 * send the formatted request 'message' to a KDC for realm 'realm' and
 * return the response (if any) in 'reply'.
 *
 * If the message is sent and a response is received, 0 is returned,
 * otherwise an error code is returned.
 *
 * The storage for 'reply' is allocated and should be freed by the caller
 * when finished.
 */

krb5_error_code
krb5_sendto_kdc (krb5_context context, const krb5_data *message,
		 const krb5_data *realm, krb5_data *reply,
		 int *use_master, int tcp_only)
{
	return (krb5_sendto_kdc2(context, message, realm, reply, use_master,
				tcp_only, NULL));
}

/*
 * Solaris Kerberos
 * Same as krb5_sendto_kdc plus an extra arg to return the FQDN
 * of the KDC sent the request.
 * Caller (at top of stack) needs to free hostname_used.
 */
krb5_error_code
krb5_sendto_kdc2 (krb5_context context, const krb5_data *message,
		 const krb5_data *realm, krb5_data *reply,
		int *use_master, int tcp_only, char **hostname_used)
{
    krb5_error_code retval, retval2;
    struct addrlist addrs = ADDRLIST_INIT;	/* Solaris Kerberos */
    int socktype1 = 0, socktype2 = 0, addr_used;

    /*
     * find KDC location(s) for realm
     */

    /*
     * BUG: This code won't return "interesting" errors (e.g., out of mem,
     * bad config file) from locate_kdc.  KRB5_REALM_CANT_RESOLVE can be
     * ignored from one query of two, but if only one query is done, or
     * both return that error, it should be returned to the caller.  Also,
     * "interesting" errors (not KRB5_KDC_UNREACH) from sendto_{udp,tcp}
     * should probably be returned as well.
     */

    /*LINTED*/
    dprint("krb5_sendto_kdc(%d@%p, \"%D\", use_master=%d, tcp_only=%d)\n",
    /*LINTED*/
	   message->length, message->data, realm, *use_master, tcp_only);

    if (!tcp_only && context->udp_pref_limit < 0) {
	int tmp;
	retval = profile_get_integer(context->profile,
				     "libdefaults", "udp_preference_limit", 0,
				     DEFAULT_UDP_PREF_LIMIT, &tmp);
	if (retval)
	    return retval;
	if (tmp < 0)
	    tmp = DEFAULT_UDP_PREF_LIMIT;
	else if (tmp > HARD_UDP_LIMIT)
	    /* In the unlikely case that a *really* big value is
	       given, let 'em use as big as we think we can
	       support.  */
	    tmp = HARD_UDP_LIMIT;
	context->udp_pref_limit = tmp;
    }

    retval = (*use_master ? KRB5_KDC_UNREACH : KRB5_REALM_UNKNOWN);

    if (tcp_only)
	socktype1 = SOCK_STREAM, socktype2 = 0;
    else if (message->length <= context->udp_pref_limit)
	socktype1 = SOCK_DGRAM, socktype2 = SOCK_STREAM;
    else
	socktype1 = SOCK_STREAM, socktype2 = SOCK_DGRAM;

    retval = krb5_locate_kdc(context, realm, &addrs, *use_master, socktype1, 0);
    if (socktype2) {
	struct addrlist addrs2;

	retval2 = krb5_locate_kdc(context, realm, &addrs2, *use_master,
				  socktype2, 0);
#if 0
	if (retval2 == 0) {
	    (void) merge_addrlists(&addrs, &addrs2);
	    krb5int_free_addrlist(&addrs2);
	    retval = 0;
	} else if (retval == KRB5_REALM_CANT_RESOLVE) {
	    retval = retval2;
	}
#else
	retval = retval2;
	if (retval == 0) {
	    (void) merge_addrlists(&addrs, &addrs2);
	    krb5int_free_addrlist(&addrs2);
	}
#endif
    }

    if (addrs.naddrs > 0) {
	krb5_error_code err = 0;

        retval = krb5int_sendto (context, message, &addrs, 0, reply, 0, 0,
				 0, 0, &addr_used, check_for_svc_unavailable, &err);
	switch (retval) {
	case 0:
            /*
             * Set use_master to 1 if we ended up talking to a master when
             * we didn't explicitly request to
             */
            if (*use_master == 0) {
                struct addrlist addrs3;
                retval = krb5_locate_kdc(context, realm, &addrs3, 1, 
                                         addrs.addrs[addr_used].ai->ai_socktype,
                                         addrs.addrs[addr_used].ai->ai_family);
                if (retval == 0) {
		    if (in_addrlist(addrs.addrs[addr_used].ai, &addrs3))
			*use_master = 1;
                    krb5int_free_addrlist (&addrs3);
                }
            }

	    if (hostname_used) {
		struct sockaddr *sa;
		char buf[NI_MAXHOST];
		int err;

		*hostname_used = NULL;
		sa = addrs.addrs[addr_used].ai->ai_addr;
		err = getnameinfo (sa, socklen (sa), buf, sizeof (buf), 0, 0,
				AI_CANONNAME);
		if (err)
		    err = getnameinfo (sa, socklen (sa), buf,
				    sizeof (buf), 0, 0,
				    NI_NUMERICHOST);
		if (!err)
		    *hostname_used = strdup(buf);
	            /* don't sweat strdup fail */
	    }
            krb5int_free_addrlist (&addrs);
            return 0;
	default:
	    break;
	    /* Cases here are for constructing useful error messages.  */
	case KRB5_KDC_UNREACH:
	    if (err == KDC_ERR_SVC_UNAVAILABLE) {
		retval = KRB5KDC_ERR_SVC_UNAVAILABLE;
	    } else {
		krb5_set_error_message(context, retval,
				    dgettext(TEXT_DOMAIN,
				    "Cannot contact any KDC for realm '%.*s'"),
				    realm->length, realm->data);
	    }
	    break;
	}
        krb5int_free_addrlist (&addrs);
    }
    return retval;
}

#ifdef DEBUG

#ifdef _WIN32
#define dperror(MSG) \
	 dprint("%s: an error occurred ... "			\
		"\tline=%d errno=%m socketerrno=%m\n",		\
		(MSG), __LINE__, errno, SOCKET_ERRNO)
#else
#define dperror(MSG) dprint("%s: %m\n", MSG, errno)
#endif
#define dfprintf(ARGLIST) (debug ? fprintf ARGLIST : 0)

#else /* ! DEBUG */

#define dperror(MSG) ((void)(MSG))
#define dfprintf(ARGLIST) ((void)0)

#endif

/*
 * Notes:
 *
 * Getting "connection refused" on a connected UDP socket causes
 * select to indicate write capability on UNIX, but only shows up
 * as an exception on Windows.  (I don't think any UNIX system flags
 * the error as an exception.)  So we check for both, or make it
 * system-specific.
 *
 * Always watch for responses from *any* of the servers.  Eventually
 * fix the UDP code to do the same.
 *
 * To do:
 * - TCP NOPUSH/CORK socket options?
 * - error codes that don't suck
 * - getsockopt(SO_ERROR) to check connect status
 * - handle error RESPONSE_TOO_BIG from UDP server and use TCP
 *   connections already in progress
 */

#include "cm.h"

static int getcurtime (struct timeval *tvp)
{
#ifdef _WIN32
    struct _timeb tb;
    _ftime(&tb);
    tvp->tv_sec = tb.time;
    tvp->tv_usec = tb.millitm * 1000;
    /* Can _ftime fail?  */
    return 0;
#else
    if (gettimeofday(tvp, 0)) {
	dperror("gettimeofday");
	return errno;
    }
    return 0;
#endif
}

/*
 * Call select and return results.
 * Input: interesting file descriptors and absolute timeout
 * Output: select return value (-1 or num fds ready) and fd_sets
 * Return: 0 (for i/o available or timeout) or error code.
 */
krb5_error_code
krb5int_cm_call_select (const struct select_state *in,
			struct select_state *out, int *sret)
{
    struct timeval now, *timo;
    krb5_error_code e;

    *out = *in;
    e = getcurtime(&now);
    if (e)
	return e;
    if (out->end_time.tv_sec == 0)
	timo = 0;
    else {
	timo = &out->end_time;
	out->end_time.tv_sec -= now.tv_sec;
	out->end_time.tv_usec -= now.tv_usec;
	if (out->end_time.tv_usec < 0) {
	    out->end_time.tv_usec += 1000000;
	    out->end_time.tv_sec--;
	}
	if (out->end_time.tv_sec < 0) {
	    *sret = 0;
	    return 0;
	}
    }
    /*LINTED*/
    dprint("selecting on max=%d sockets [%F] timeout %t\n",
	    /*LINTED*/
	   out->max,
	   &out->rfds, &out->wfds, &out->xfds, out->max,
	   timo);
    *sret = select(out->max, &out->rfds, &out->wfds, &out->xfds, timo);
    e = SOCKET_ERRNO;

/* Solaris Kerberos */
#ifdef DEBUG
    /*LINTED*/
    dprint("select returns %d", *sret);
    if (*sret < 0)
	/*LINTED*/
	dprint(", error = %E\n", e);
    else if (*sret == 0)
	/*LINTED*/
	dprint(" (timeout)\n");
    else
	/*LINTED*/
	dprint(":%F\n", &out->rfds, &out->wfds, &out->xfds, out->max);
#endif

    if (*sret < 0)
	return e;
    return 0;
}

static int service_tcp_fd (struct conn_state *conn,
			   struct select_state *selstate, int ssflags);
static int service_udp_fd (struct conn_state *conn,
			   struct select_state *selstate, int ssflags);

static void
set_conn_state_msg_length (struct conn_state *state, const krb5_data *message)
{
    if (!message || message->length == 0) 
	return;

    if (!state->is_udp) {

	state->x.out.msg_len_buf[0] = (message->length >> 24) & 0xff;
	state->x.out.msg_len_buf[1] = (message->length >> 16) & 0xff;
	state->x.out.msg_len_buf[2] = (message->length >>  8) & 0xff;
	state->x.out.msg_len_buf[3] =  message->length        & 0xff;

	SG_SET(&state->x.out.sgbuf[0], state->x.out.msg_len_buf, 4);
	SG_SET(&state->x.out.sgbuf[1], message->data, message->length);
   	state->x.out.sg_count = 2;

    } else {

	SG_SET(&state->x.out.sgbuf[0], message->data, message->length);
	SG_SET(&state->x.out.sgbuf[1], 0, 0);
	state->x.out.sg_count = 1;

    }
}



static int
setup_connection (struct conn_state *state, struct addrinfo *ai,
		  const krb5_data *message, char **udpbufp)
{
    state->state = INITIALIZING;
    state->err = 0;
    state->x.out.sgp = state->x.out.sgbuf;
    state->addr = ai;
    state->fd = INVALID_SOCKET;
    SG_SET(&state->x.out.sgbuf[1], 0, 0);
    if (ai->ai_socktype == SOCK_STREAM) {
	/*
	SG_SET(&state->x.out.sgbuf[0], message_len_buf, 4);
	SG_SET(&state->x.out.sgbuf[1], message->data, message->length);
	state->x.out.sg_count = 2;
	*/
	
	state->is_udp = 0;
	state->service = service_tcp_fd;
	set_conn_state_msg_length (state, message);
    } else {
	/*
	SG_SET(&state->x.out.sgbuf[0], message->data, message->length);
	SG_SET(&state->x.out.sgbuf[1], 0, 0);
	state->x.out.sg_count = 1;
	*/

	state->is_udp = 1;
	state->service = service_udp_fd;
	set_conn_state_msg_length (state, message);

	if (*udpbufp == 0) {
	    *udpbufp = malloc(krb5_max_dgram_size);
	    if (*udpbufp == 0) {
		dperror("malloc(krb5_max_dgram_size)");
		(void) closesocket(state->fd);
		state->fd = INVALID_SOCKET;
		state->state = FAILED;
		return 1;
	    }
	}
	state->x.in.buf = *udpbufp;
	state->x.in.bufsize = krb5_max_dgram_size;
    }
    return 0;
}

static int
start_connection (struct conn_state *state, 
		  struct select_state *selstate, 
		  struct sendto_callback_info* callback_info,
                  krb5_data* callback_buffer)
{
    int fd, e;
    struct addrinfo *ai = state->addr;

    /*LINTED*/
    dprint("start_connection(@%p)\ngetting %s socket in family %d...", state,
	   /*LINTED*/
	   ai->ai_socktype == SOCK_STREAM ? "stream" : "dgram", ai->ai_family);
    fd = socket(ai->ai_family, ai->ai_socktype, 0);
    if (fd == INVALID_SOCKET) {
	state->err = SOCKET_ERRNO;
	/*LINTED*/
	dprint("socket: %m creating with af %d\n", state->err, ai->ai_family);
	return -1;		/* try other hosts */
    }
    /* Make it non-blocking.  */
    if (ai->ai_socktype == SOCK_STREAM) {
	static const int one = 1;
	static const struct linger lopt = { 0, 0 };

	if (ioctlsocket(fd, FIONBIO, (const void *) &one))
	    dperror("sendto_kdc: ioctl(FIONBIO)");
	if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &lopt, sizeof(lopt)))
	    dperror("sendto_kdc: setsockopt(SO_LINGER)");
    }

    /* Start connecting to KDC.  */
    /*LINTED*/
    dprint(" fd %d; connecting to %A...\n", fd, ai);
    e = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (e != 0) {
	/*
	 * This is the path that should be followed for non-blocking
	 * connections.
	 */
	if (SOCKET_ERRNO == EINPROGRESS || SOCKET_ERRNO == EWOULDBLOCK) {
	    state->state = CONNECTING;
	    state->fd = fd;
	} else {
	    /*LINTED*/
	    dprint("connect failed: %m\n", SOCKET_ERRNO);
	    (void) closesocket(fd);
	    state->err = SOCKET_ERRNO;
	    state->state = FAILED;
	    return -2;
	}
    } else {
	/*
	 * Connect returned zero even though we tried to make it
	 * non-blocking, which should have caused it to return before
	 * finishing the connection.  Oh well.  Someone's network
	 * stack is broken, but if they gave us a connection, use it.
	 */
	state->state = WRITING;
	state->fd = fd;
    }
    /*LINTED*/
    dprint("new state = %s\n", state_strings[state->state]);


    /*
     * Here's where KPASSWD callback gets the socket information it needs for
     * a kpasswd request
     */
    if (callback_info) {

	e = callback_info->pfn_callback(state, 
					callback_info->context, 
					callback_buffer);
	if (e != 0) {
	    dprint("callback failed: %m\n", e);
	    (void) closesocket(fd);
	    state->err = e;
	    state->fd = INVALID_SOCKET;
	    state->state = FAILED;
	    return -3;
	}

	dprint("callback %p (message=%d@%p)\n", 
	       state,
	       callback_buffer->length, 
	       callback_buffer->data);

	set_conn_state_msg_length( state, callback_buffer );
    }

    if (ai->ai_socktype == SOCK_DGRAM) {
	/* Send it now.  */
	int ret;
	sg_buf *sg = &state->x.out.sgbuf[0];

	/*LINTED*/
	dprint("sending %d bytes on fd %d\n", SG_LEN(sg), state->fd);
	ret = send(state->fd, SG_BUF(sg), SG_LEN(sg), 0);
	if (ret != SG_LEN(sg)) {
	    dperror("sendto");
	    (void) closesocket(state->fd);
	    state->fd = INVALID_SOCKET;
	    state->state = FAILED;
	    return -4;
	} else {
	    state->state = READING;
	}
    }
#ifdef DEBUG
    if (debug) {
	struct sockaddr_storage ss;
	socklen_t sslen = sizeof(ss);
	if (getsockname(state->fd, (struct sockaddr *)&ss, &sslen) == 0) {
	    struct addrinfo hack_ai;
	    memset(&hack_ai, 0, sizeof(hack_ai));
	    hack_ai.ai_addr = (struct sockaddr *) &ss;
	    hack_ai.ai_addrlen = sslen;
	    hack_ai.ai_socktype = SOCK_DGRAM;
	    hack_ai.ai_family = ai->ai_family;
	    dprint("local socket address is %A\n", &hack_ai);
	}
    }
#endif
    FD_SET(state->fd, &selstate->rfds);
    if (state->state == CONNECTING || state->state == WRITING)
	FD_SET(state->fd, &selstate->wfds);
    FD_SET(state->fd, &selstate->xfds);
    if (selstate->max <= state->fd)
	selstate->max = state->fd + 1;
    selstate->nfds++;

    /*LINTED*/
    dprint("new select vectors: %F\n",
	   /*LINTED*/
	   &selstate->rfds, &selstate->wfds, &selstate->xfds, selstate->max);

    return 0;
}

/* Return 0 if we sent something, non-0 otherwise.
   If 0 is returned, the caller should delay waiting for a response.
   Otherwise, the caller should immediately move on to process the
   next connection.  */
static int
maybe_send (struct conn_state *conn, 
	    struct select_state *selstate, 
	    struct sendto_callback_info* callback_info,
	    krb5_data* callback_buffer)
{
    sg_buf *sg;

    /*LINTED*/
    dprint("maybe_send(@%p) state=%s type=%s\n", conn,
	   /*LINTED*/
	   state_strings[conn->state],
	   conn->is_udp ? "udp" : "tcp");
    if (conn->state == INITIALIZING)
	return start_connection(conn, selstate, callback_info, callback_buffer);

    /* Did we already shut down this channel?  */
    if (conn->state == FAILED) {
	dprint("connection already closed\n");
	return -1;
    }

    if (conn->addr->ai_socktype == SOCK_STREAM) {
	dprint("skipping stream socket\n");
	/* The select callback will handle flushing any data we
	   haven't written yet, and we only write it once.  */
	return -1;
    }

    /* UDP - Send message, possibly for the first time, possibly a
       retransmit if a previous attempt timed out.  */
    sg = &conn->x.out.sgbuf[0];
    /*LINTED*/
    dprint("sending %d bytes on fd %d\n", SG_LEN(sg), conn->fd);
    if (send(conn->fd, SG_BUF(sg), SG_LEN(sg), 0) != SG_LEN(sg)) {
	dperror("send");
	/* Keep connection alive, we'll try again next pass.

	   Is this likely to catch any errors we didn't get from the
	   select callbacks?  */
	return -1;
    }
    /* Yay, it worked.  */
    return 0;
}

static void
kill_conn(struct conn_state *conn, struct select_state *selstate, int err)
{
    conn->state = FAILED;
    shutdown(conn->fd, SHUTDOWN_BOTH);
    FD_CLR(conn->fd, &selstate->rfds);
    FD_CLR(conn->fd, &selstate->wfds);
    FD_CLR(conn->fd, &selstate->xfds);
    conn->err = err;
    /*LINTED*/
    dprint("abandoning connection %d: %m\n", conn->fd, err);
    /* Fix up max fd for next select call.  */
    if (selstate->max == 1 + conn->fd) {
	while (selstate->max > 0
	       && ! FD_ISSET(selstate->max-1, &selstate->rfds)
	       && ! FD_ISSET(selstate->max-1, &selstate->wfds)
	       && ! FD_ISSET(selstate->max-1, &selstate->xfds))
	    selstate->max--;
	/*LINTED*/
	dprint("new max_fd + 1 is %d\n", selstate->max);
    }
    selstate->nfds--;
}

/* Check socket for error.  */
static int
get_so_error(int fd)
{
    int e, sockerr;
    socklen_t sockerrlen;

    sockerr = 0;
    sockerrlen = sizeof(sockerr);
    e = getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &sockerrlen);
    if (e != 0) {
	/* What to do now?  */
	e = SOCKET_ERRNO;
	dprint("getsockopt(SO_ERROR) on fd failed: %m\n", e);
	return e;
    }
    return sockerr;
}

/* Return nonzero only if we're finished and the caller should exit
   its loop.  This happens in two cases: We have a complete message,
   or the socket has closed and no others are open.  */

static int
service_tcp_fd (struct conn_state *conn, struct select_state *selstate,
		int ssflags)
{
    krb5_error_code e = 0;
    int nwritten, nread;

    if (!(ssflags & (SSF_READ|SSF_WRITE|SSF_EXCEPTION)))
	abort();
    switch (conn->state) {
	SOCKET_WRITEV_TEMP tmp;

    case CONNECTING:
	if (ssflags & SSF_READ) {
	    /* Bad -- the KDC shouldn't be sending to us first.  */
	    e = EINVAL /* ?? */;
	kill_conn:
	    kill_conn(conn, selstate, e);
	    if (e == EINVAL) {
		closesocket(conn->fd);
		conn->fd = INVALID_SOCKET;
	    }
	    return e == 0;
	}
	if (ssflags & SSF_EXCEPTION) {
	handle_exception:
	    e = get_so_error(conn->fd);
	    if (e)
		dprint("socket error on exception fd: %m", e);
	    else
		dprint("no socket error info available on exception fd");
	    goto kill_conn;
	}

	/*
	 * Connect finished -- but did it succeed or fail?
	 * UNIX sets can_write if failed.
	 * Call getsockopt to see if error pending.
	 *
	 * (For most UNIX systems it works to just try writing the
	 * first time and detect an error.  But Bill Dodd at IBM
	 * reports that some version of AIX, SIGPIPE can result.)
	 */
	e = get_so_error(conn->fd);
	if (e) {
	    dprint("socket error on write fd: %m", e);
	    goto kill_conn;
	}
	conn->state = WRITING;
	goto try_writing;

    case WRITING:
	if (ssflags & SSF_READ) {
	    e = E2BIG;
	    /* Bad -- the KDC shouldn't be sending anything yet.  */
	    goto kill_conn;
	}
	if (ssflags & SSF_EXCEPTION)
	    goto handle_exception;

    try_writing:
	/*LINTED*/
	dprint("trying to writev %d (%d bytes) to fd %d\n",
		/*LINTED*/
	       conn->x.out.sg_count,
	       ((conn->x.out.sg_count == 2 ? SG_LEN(&conn->x.out.sgp[1]) : 0)
		/*LINTED*/
		+ SG_LEN(&conn->x.out.sgp[0])),
	       conn->fd);
	nwritten = SOCKET_WRITEV(conn->fd, conn->x.out.sgp,
				 conn->x.out.sg_count, tmp);
	if (nwritten < 0) {
	    e = SOCKET_ERRNO;
	    /*LINTED*/
	    dprint("failed: %m\n", e);
	    goto kill_conn;
	}
	/*LINTED*/
	dprint("wrote %d bytes\n", nwritten);
	while (nwritten) {
	    sg_buf *sgp = conn->x.out.sgp;
	    if (nwritten < SG_LEN(sgp)) {
		/*LINTED*/
		SG_ADVANCE(sgp, nwritten);
		nwritten = 0;
	    } else {
		nwritten -= SG_LEN(conn->x.out.sgp);
		conn->x.out.sgp++;
		conn->x.out.sg_count--;
		if (conn->x.out.sg_count == 0 && nwritten != 0)
		    /* Wrote more than we wanted to?  */
		    abort();
	    }
	}
	if (conn->x.out.sg_count == 0) {
	    /* Done writing, switch to reading.  */
	    /* Don't call shutdown at this point because
	     * some implementations cannot deal with half-closed connections.*/
	    FD_CLR(conn->fd, &selstate->wfds);
	    /* Q: How do we detect failures to send the remaining data
	       to the remote side, since we're in non-blocking mode?
	       Will we always get errors on the reading side?  */
	    /*LINTED*/
	    dprint("switching fd %d to READING\n", conn->fd);
	    conn->state = READING;
	    conn->x.in.bufsizebytes_read = 0;
	    conn->x.in.bufsize = 0;
	    conn->x.in.buf = 0;
	    conn->x.in.pos = 0;
	    conn->x.in.n_left = 0;
	}
	return 0;

    case READING:
	if (ssflags & SSF_EXCEPTION) {
	    if (conn->x.in.buf) {
		free(conn->x.in.buf);
		conn->x.in.buf = 0;
	    }
	    goto handle_exception;
	}

	if (conn->x.in.bufsizebytes_read == 4) {
	    /* Reading data.  */
	    /*LINTED*/
	    dprint("reading %d bytes of data from fd %d\n",
		   (int) conn->x.in.n_left, conn->fd);
	    nread = SOCKET_READ(conn->fd, conn->x.in.pos, conn->x.in.n_left);
	    if (nread <= 0) {
		e = nread ? SOCKET_ERRNO : ECONNRESET;
		free(conn->x.in.buf);
		conn->x.in.buf = 0;
		goto kill_conn;
	    }
	    conn->x.in.n_left -= nread;
	    conn->x.in.pos += nread;
	    /* Solaris Kerberos */
	    if ((long)conn->x.in.n_left <= 0) {
		/* We win!  */
		return 1;
	    }
	} else {
	    /* Reading length.  */
	    nread = SOCKET_READ(conn->fd,
				conn->x.in.bufsizebytes + conn->x.in.bufsizebytes_read,
				4 - conn->x.in.bufsizebytes_read);
	    if (nread < 0) {
		e = SOCKET_ERRNO;
		goto kill_conn;
	    }
	    conn->x.in.bufsizebytes_read += nread;
	    if (conn->x.in.bufsizebytes_read == 4) {
		unsigned long len;
		len = conn->x.in.bufsizebytes[0];
		len = (len << 8) + conn->x.in.bufsizebytes[1];
		len = (len << 8) + conn->x.in.bufsizebytes[2];
		len = (len << 8) + conn->x.in.bufsizebytes[3];
		/*LINTED*/
		dprint("received length on fd %d is %d\n", conn->fd, (int)len);
		/* Arbitrary 1M cap.  */
		if (len > 1 * 1024 * 1024) {
		    e = E2BIG;
		    goto kill_conn;
		}
		conn->x.in.bufsize = conn->x.in.n_left = len;
		conn->x.in.buf = conn->x.in.pos = malloc(len);
		/*LINTED*/
		dprint("allocated %d byte buffer at %p\n", (int) len,
		       conn->x.in.buf);
		if (conn->x.in.buf == 0) {
		    /* allocation failure */
		    e = errno;
		    goto kill_conn;
		}
	    }
	}
	break;

    default:
	abort();
    }
    return 0;
}

static int
service_udp_fd(struct conn_state *conn, struct select_state *selstate,
	       int ssflags)
{
    int nread;

    if (!(ssflags & (SSF_READ|SSF_EXCEPTION)))
	abort();
    if (conn->state != READING)
	abort();

    nread = recv(conn->fd, conn->x.in.buf, conn->x.in.bufsize, 0);
    if (nread < 0) {
	kill_conn(conn, selstate, SOCKET_ERRNO);
	return 0;
    }
    conn->x.in.pos = conn->x.in.buf + nread;
    return 1;
}

static int
service_fds (krb5_context context,
	     struct select_state *selstate,
	     struct conn_state *conns, size_t n_conns, int *winning_conn,
	     struct select_state *seltemp,
	     int (*msg_handler)(krb5_context, const krb5_data *, void *),
	     void *msg_handler_data)
{
    int e, selret;

    e = 0;
    while (selstate->nfds > 0
	   && (e = krb5int_cm_call_select(selstate, seltemp, &selret)) == 0) {
	int i;

	/*LINTED*/
	dprint("service_fds examining results, selret=%d\n", selret);

	if (selret == 0)
	    /* Timeout, return to caller.  */
	    return 0;

	/* Got something on a socket, process it.  */
	for (i = 0; i <= selstate->max && selret > 0 && i < n_conns; i++) {
	    int ssflags;

	    if (conns[i].fd == INVALID_SOCKET)
		continue;
	    ssflags = 0;
	    if (FD_ISSET(conns[i].fd, &seltemp->rfds))
		ssflags |= SSF_READ, selret--;
	    if (FD_ISSET(conns[i].fd, &seltemp->wfds))
		ssflags |= SSF_WRITE, selret--;
	    if (FD_ISSET(conns[i].fd, &seltemp->xfds))
		ssflags |= SSF_EXCEPTION, selret--;
	    if (!ssflags)
		continue;

	    /*LINTED*/
	    dprint("handling flags '%s%s%s' on fd %d (%A) in state %s\n",
		    /*LINTED*/
		   (ssflags & SSF_READ) ? "r" : "",
		    /*LINTED*/
		   (ssflags & SSF_WRITE) ? "w" : "",
		    /*LINTED*/
		   (ssflags & SSF_EXCEPTION) ? "x" : "",
		    /*LINTED*/
		   conns[i].fd, conns[i].addr,
		   state_strings[(int) conns[i].state]);

	    if (conns[i].service (&conns[i], selstate, ssflags)) {
		int stop = 1;

		if (msg_handler != NULL) {
		    krb5_data reply;

		    reply.data = conns[i].x.in.buf;
		    reply.length = conns[i].x.in.pos - conns[i].x.in.buf;

		    stop = (msg_handler(context, &reply, msg_handler_data) != 0);
		}

		if (stop) {
		    dprint("fd service routine says we're done\n");
		    *winning_conn = i;
		    return 1;
		}
	    }
	}
    }
    if (e != 0) {
	/*LINTED*/
	dprint("select returned %m\n", e);
	*winning_conn = -1;
	return 1;
    }
    return 0;
}

/*
 * Current worst-case timeout behavior:
 *
 * First pass, 1s per udp or tcp server, plus 2s at end.
 * Second pass, 1s per udp server, plus 4s.
 * Third pass, 1s per udp server, plus 8s.
 * Fourth => 16s, etc.
 *
 * Restated:
 * Per UDP server, 1s per pass.
 * Per TCP server, 1s.
 * Backoff delay, 2**(P+1) - 2, where P is total number of passes.
 *
 * Total = 2**(P+1) + U*P + T - 2.
 *
 * If P=3, Total = 3*U + T + 14.
 * If P=4, Total = 4*U + T + 30.
 *
 * Note that if you try to reach two ports (e.g., both 88 and 750) on
 * one server, it counts as two.
 */

krb5_error_code
/*ARGSUSED*/
krb5int_sendto (krb5_context context, const krb5_data *message,
                const struct addrlist *addrs,
		struct sendto_callback_info* callback_info, krb5_data *reply,
		struct sockaddr *localaddr, socklen_t *localaddrlen,
                struct sockaddr *remoteaddr, socklen_t *remoteaddrlen,
		int *addr_used,
		/* return 0 -> keep going, 1 -> quit */
		int (*msg_handler)(krb5_context, const krb5_data *, void *),
		void *msg_handler_data)
{
    int i, pass;
    int delay_this_pass = 2;
    krb5_error_code retval;
    struct conn_state *conns;
    krb5_data *callback_data = 0;
    size_t n_conns, host;
    struct select_state *sel_state;
    struct timeval now;
    int winning_conn = -1, e = 0;
    char *udpbuf = 0;

    if (message)
	dprint("krb5int_sendto(message=%d@%p, addrlist=", message->length, message->data);
    else
	dprint("krb5int_sendto(callback=%p, addrlist=", callback_info);
    print_addrlist(addrs);
    dprint(")\n");

    reply->data = 0;
    reply->length = 0;

    n_conns = addrs->naddrs;
    conns = malloc(n_conns * sizeof(struct conn_state));
    if (conns == NULL) {
	return ENOMEM;
    }

    memset(conns, 0, n_conns * sizeof(struct conn_state));

    if (callback_info) {
	callback_data = malloc(n_conns * sizeof(krb5_data));
	if (callback_data == NULL) {
	    return ENOMEM;
	}

	memset(callback_data, 0, n_conns * sizeof(krb5_data));
    }

    for (i = 0; i < n_conns; i++) {
	conns[i].fd = INVALID_SOCKET;
    }

    /* One for use here, listing all our fds in use, and one for
       temporary use in service_fds, for the fds of interest.  */
    sel_state = malloc(2 * sizeof(*sel_state));
    if (sel_state == NULL) {
	free(conns);
	return ENOMEM;
    }
    sel_state->max = 0;
    sel_state->nfds = 0;
    sel_state->end_time.tv_sec = sel_state->end_time.tv_usec = 0;
    FD_ZERO(&sel_state->rfds);
    FD_ZERO(&sel_state->wfds);
    FD_ZERO(&sel_state->xfds);


    /* Set up connections.  */
    for (host = 0; host < n_conns; host++) {
	retval = setup_connection(&conns[host], 
				  addrs->addrs[host].ai,
				  message, 
				  &udpbuf);
	if (retval)
	    continue;
    }
    for (pass = 0; pass < MAX_PASS; pass++) {
	/* Possible optimization: Make only one pass if TCP only.
	   Stop making passes if all UDP ports are closed down.  */
	/*LINTED*/
	dprint("pass %d delay=%d\n", pass, delay_this_pass);
	for (host = 0; host < n_conns; host++) {
	    /*LINTED*/
	    dprint("host %d\n", host);

	    /* Send to the host, wait for a response, then move on. */
	    if (maybe_send(&conns[host], 
			   sel_state,
			   callback_info,
			   (callback_info ? &callback_data[host] : NULL)))
		continue;

	    retval = getcurtime(&now);
	    if (retval)
		goto egress;
	    sel_state->end_time = now;
	    sel_state->end_time.tv_sec += 1;
	    e = service_fds(context, sel_state, conns, host+1, &winning_conn,
			    sel_state+1, msg_handler, msg_handler_data);
	    if (e)
		break;
	    if (pass > 0 && sel_state->nfds == 0)
		/*
		 * After the first pass, if we close all fds, break
		 * out right away.  During the first pass, it's okay,
		 * we're probably about to open another connection.
		 */
		break;
	}
	if (e)
	    break;
	retval = getcurtime(&now);
	if (retval)
	    goto egress;
	/* Possible optimization: Find a way to integrate this select
	   call with the last one from the above loop, if the loop
	   actually calls select.  */
	sel_state->end_time.tv_sec += delay_this_pass;
	e = service_fds(context, sel_state, conns, host+1, &winning_conn,
		        sel_state+1, msg_handler, msg_handler_data);
	if (e)
	    break;
	if (sel_state->nfds == 0)
	    break;
	delay_this_pass *= 2;
    }

    if (sel_state->nfds == 0) {
	/* No addresses?  */
	retval = KRB5_KDC_UNREACH;
	goto egress;
    }
    if (e == 0 || winning_conn < 0) {
	retval = KRB5_KDC_UNREACH;
	goto egress;
    }
    /* Success!  */
    reply->data = conns[winning_conn].x.in.buf;
    reply->length = (conns[winning_conn].x.in.pos
		     - conns[winning_conn].x.in.buf);
    /*LINTED*/
    dprint("returning %d bytes in buffer %p\n",
	   (int) reply->length, reply->data);
    retval = 0;
    conns[winning_conn].x.in.buf = 0;
    if (addr_used)
        *addr_used = winning_conn;
    if (localaddr != 0 && localaddrlen != 0 && *localaddrlen > 0)
	(void) getsockname(conns[winning_conn].fd, localaddr, localaddrlen);

     if (remoteaddr != 0 && remoteaddrlen != 0 && *remoteaddrlen > 0)
	(void) getpeername(conns[winning_conn].fd, remoteaddr, remoteaddrlen);

egress:
    for (i = 0; i < n_conns; i++) {
	if (conns[i].fd != INVALID_SOCKET)
	    closesocket(conns[i].fd);
	if (conns[i].state == READING
	    && conns[i].x.in.buf != 0
	    && conns[i].x.in.buf != udpbuf)
	    free(conns[i].x.in.buf);
	if (callback_info) {
	    callback_info->pfn_cleanup( callback_info->context, &callback_data[i]);
	}
    }

    if (callback_data) 
	free(callback_data);

    free(conns);
    if (reply->data != udpbuf)
	free(udpbuf);
    free(sel_state);
    return retval;
}
