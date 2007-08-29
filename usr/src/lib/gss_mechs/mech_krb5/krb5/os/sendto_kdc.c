/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/os/sendto_kdc.c
 *
 * Copyright 1990,1991,2001,2002 by the Massachusetts Institute of Technology.
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

#define NEED_SOCKETS
#define NEED_LOWLEVEL_IO
#include <fake-addrinfo.h>
#include <k5-int.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#include "os-proto.h"

#ifdef _AIX
#include <sys/select.h>
#endif

/* For FIONBIO.  */
#include <sys/ioctl.h>
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#define MAX_PASS		    3
/* Solaris Kerberos: moved to k5-int.h */
/* #define DEFAULT_UDP_PREF_LIMIT	 1465 */
#define HARD_UDP_LIMIT		32700 /* could probably do 64K-epsilon ? */

/* Solaris kerberos: leaving this here because other code depends on this. */
static void default_debug_handler (const void *data, size_t len)
{
    fwrite(data, 1, len, stderr);
    /* stderr is unbuffered */
}

void (*krb5int_sendtokdc_debug_handler) (const void *, size_t) = default_debug_handler;

/* 
 * Solaris Kerberos: only including the debug stuff if DEBUG defined outside
 * this file.
 */
#ifdef  DEBUG

static char global_err_str[NI_MAXHOST + NI_MAXSERV + 1024];

/* Solaris kerberos: removed put() since it isn't needed. */

static void putstr(const char *str)
{
    /* Solaris kerberos: build the string which will be passed to syslog later */
    strlcat(global_err_str, str, sizeof (global_err_str));
}

#define dprint krb5int_debug_fprint
#define dperror dprint

#include <com_err.h>

static void
krb5int_debug_fprint (const char *fmt, ...)
{
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
    char tmpbuf[NI_MAXHOST + NI_MAXSERV + 30];

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
	    break;
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
	    if (0 != getnameinfo (ai->ai_addr, ai->ai_addrlen,
				  addrbuf, sizeof (addrbuf),
				  portbuf, sizeof (portbuf),
				  NI_NUMERICHOST | NI_NUMERICSERV))
		/*LINTED*/
		strcpy (addrbuf, "??"), strcpy (portbuf, "??");
	    sprintf(tmpbuf, "%s %s.%s",
		    (ai->ai_socktype == SOCK_DGRAM
		     ? "udp"
		     : ai->ai_socktype == SOCK_STREAM
		     ? "tcp"
		     : "???"),
		    addrbuf, portbuf);
	    putstr(tmpbuf);
	    break;
	case 'D':
	    /* %D => krb5_data * */
	    d = va_arg(args, krb5_data *);
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
}

#else
#define dprint (void)
#define dperror(MSG) ((void)(MSG))
#endif

static int
merge_addrlists (struct addrlist *dest, struct addrlist *src)
{
    int err, i;

#ifdef DEBUG
    /*LINTED*/
    dprint("merging addrlists:\n\tlist1: ");
    for (i = 0; i < dest->naddrs; i++)
	/*LINTED*/
	dprint(" %A", dest->addrs[i]);
    /*LINTED*/
    dprint("\n\tlist2: ");
    for (i = 0; i < src->naddrs; i++)
	/*LINTED*/
	dprint(" %A", src->addrs[i]);
    /*LINTED*/
    dprint("\n");
#endif

    err = krb5int_grow_addrlist (dest, src->naddrs);
    if (err)
	return err;
    for (i = 0; i < src->naddrs; i++) {
	dest->addrs[dest->naddrs + i] = src->addrs[i];
	src->addrs[i] = 0;
    }
    dest->naddrs += i;
    src->naddrs = 0;

#ifdef DEBUG
    /*LINTED*/
    dprint("\tout:   ");
    for (i = 0; i < dest->naddrs; i++)
	/*LINTED*/
	dprint(" %A", dest->addrs[i]);
    /*LINTED*/
    dprint("\n");
#endif

    return 0;
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
    krb5_error_code retval;
    struct addrlist addrs;
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

	retval = krb5_locate_kdc(context, realm, &addrs2, *use_master,
				 socktype2, 0);
	if (retval == 0) {
	    (void) merge_addrlists(&addrs, &addrs2);
	    krb5int_free_addrlist(&addrs2);
	}
    }
    if (addrs.naddrs > 0) {
        retval = krb5int_sendto (context, message, &addrs, reply, 0, 0,
		&addr_used);
	if (retval == 0) { 
            /*
	     * Set use_master to 1 if we ended up talking to a master when 
	     * didn't explicitly request to 
	     */ 

	    if (*use_master == 0) { 
	        struct addrlist addrs3; 
		retval = krb5_locate_kdc(context, realm, &addrs3, 1,  
					addrs.addrs[addr_used]->ai_socktype,
					addrs.addrs[addr_used]->ai_family);
		if (retval == 0) { 
		    int i; 
		    for (i = 0; i < addrs3.naddrs; i++) { 
			if (addrs.addrs[addr_used]->ai_addrlen == 
			    addrs3.addrs[i]->ai_addrlen && 
			    memcmp(addrs.addrs[addr_used]->ai_addr, 
				addrs3.addrs[i]->ai_addr, 
				addrs.addrs[addr_used]->ai_addrlen) == 0) { 
				*use_master = 1;
				break;
			}
		    }
		    krb5int_free_addrlist (&addrs3);
		}
	    }
	    krb5int_free_addrlist (&addrs);
	    return 0;
	}
	krb5int_free_addrlist (&addrs);
    }
    return retval;
}


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

#include <cm.h>

static const char *const state_strings[] = {
    "INITIALIZING", "CONNECTING", "WRITING", "READING", "FAILED"
};
enum conn_states { INITIALIZING, CONNECTING, WRITING, READING, FAILED };
struct incoming_krb5_message {
    size_t bufsizebytes_read;
    size_t bufsize;
    char *buf;
    char *pos;
    unsigned char bufsizebytes[4];
    size_t n_left;
};
struct conn_state {
    SOCKET fd;
    krb5_error_code err;
    enum conn_states state;
    unsigned int is_udp : 1;
    int (*service)(struct conn_state *, struct select_state *, int);
    struct addrinfo *addr;
    struct {
	struct {
	    sg_buf sgbuf[2];
	    sg_buf *sgp;
	    int sg_count;
	} out;
	struct incoming_krb5_message in;
    } x;
};

static int getcurtime (struct timeval *tvp)
{
    if (gettimeofday(tvp, 0)) {
	dperror("gettimeofday");
	return errno;
    }
    return 0;
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
	   out->max, &out->rfds, &out->wfds, &out->xfds, out->max, timo);
    *sret = select(out->max, &out->rfds, &out->wfds, &out->xfds, timo);
    e = SOCKET_ERRNO;

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


static int
setup_connection (struct conn_state *state, struct addrinfo *ai,
		  const krb5_data *message, unsigned char *message_len_buf,
		  char **udpbufp)
{
    state->state = INITIALIZING;
    state->err = 0;
    state->x.out.sgp = state->x.out.sgbuf;
    state->addr = ai;
    state->fd = INVALID_SOCKET;
    SG_SET(&state->x.out.sgbuf[1], 0, 0);
    if (ai->ai_socktype == SOCK_STREAM) {
	SG_SET(&state->x.out.sgbuf[0], message_len_buf, 4);
	SG_SET(&state->x.out.sgbuf[1], message->data, message->length);
	state->x.out.sg_count = 2;
	state->is_udp = 0;
	state->service = service_tcp_fd;
    } else {
	SG_SET(&state->x.out.sgbuf[0], message->data, message->length);
	SG_SET(&state->x.out.sgbuf[1], 0, 0);
	state->x.out.sg_count = 1;
	state->is_udp = 1;
	state->service = service_udp_fd;

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
start_connection (struct conn_state *state, struct select_state *selstate)
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
	} else {
	    /*LINTED*/
	    dprint("connect failed: %m\n", SOCKET_ERRNO);
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
    }
    /*LINTED*/
    dprint("new state = %s\n", state_strings[state->state]);

    state->fd = fd;

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
	    return -3;
	} else {
	    state->state = READING;
	}
    }

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
maybe_send (struct conn_state *conn, struct select_state *selstate)
{
    sg_buf *sg;

    /*LINTED*/
    dprint("maybe_send(@%p) state=%s type=%s\n", conn,
	   /*LINTED*/
	   state_strings[conn->state], conn->is_udp ? "udp" : "tcp");
    if (conn->state == INITIALIZING)
	return start_connection(conn, selstate);

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
	    e = 1;		/* need only be non-zero */
	    goto kill_conn;
	}

	/*
	 * Connect finished -- but did it succeed or fail?
	 * UNIX sets can_write if failed.
	 * Try writing, I guess, and find out.
	 */
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
service_fds (struct select_state *selstate,
	     struct conn_state *conns, size_t n_conns, int *winning_conn)
{
    int e, selret;
    struct select_state sel_results;

    e = 0;
    while (selstate->nfds > 0
	   && (e = krb5int_cm_call_select(selstate, &sel_results, &selret)) == 0) {
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
	    if (FD_ISSET(conns[i].fd, &sel_results.rfds))
		ssflags |= SSF_READ, selret--;
	    if (FD_ISSET(conns[i].fd, &sel_results.wfds))
		ssflags |= SSF_WRITE, selret--;
	    if (FD_ISSET(conns[i].fd, &sel_results.xfds))
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
		dprint("fd service routine says we're done\n");
		*winning_conn = i;
		return 1;
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
		const struct addrlist *addrs, krb5_data *reply,
		struct sockaddr_storage *localaddr, socklen_t *localaddrlen,
		int *addr_used)
{
    int i, pass;
    int delay_this_pass = 2;
    krb5_error_code retval;
    struct conn_state *conns;
    size_t n_conns, host;
    struct select_state select_state;
    struct timeval now;
    int winning_conn = -1, e = 0;
    unsigned char message_len_buf[4];
    char *udpbuf = 0;

    /*LINTED*/
    dprint("krb5int_sendto(message=%d@%p)\n", message->length, message->data);

    reply->data = 0;
    reply->length = 0;

    n_conns = addrs->naddrs;
    conns = malloc(n_conns * sizeof(struct conn_state));
    if (conns == NULL) {
	return ENOMEM;
    }
    memset(conns, 0, n_conns * sizeof(conns[i]));
    for (i = 0; i < n_conns; i++) {
	conns[i].fd = INVALID_SOCKET;
    }

    select_state.max = 0;
    select_state.nfds = 0;
    FD_ZERO(&select_state.rfds);
    FD_ZERO(&select_state.wfds);
    FD_ZERO(&select_state.xfds);

    message_len_buf[0] = (message->length >> 24) & 0xff;
    message_len_buf[1] = (message->length >> 16) & 0xff;
    message_len_buf[2] = (message->length >>  8) & 0xff;
    message_len_buf[3] =  message->length        & 0xff;

    /* Set up connections.  */
    for (host = 0; host < n_conns; host++) {
	retval = setup_connection (&conns[host], addrs->addrs[host],
				   message, message_len_buf, &udpbuf);
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
	    if (maybe_send(&conns[host], &select_state))
		continue;

	    retval = getcurtime(&now);
	    if (retval)
		goto egress;
	    select_state.end_time = now;
	    select_state.end_time.tv_sec += 1;
	    e = service_fds(&select_state, conns, host+1, &winning_conn);
	    if (e)
		break;
	    if (pass > 0 && select_state.nfds == 0)
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
	select_state.end_time.tv_sec += delay_this_pass;
	e = service_fds(&select_state, conns, host+1, &winning_conn);
	if (e)
	    break;
	if (select_state.nfds == 0)
	    break;
	delay_this_pass *= 2;
    }

    if (select_state.nfds == 0) {
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
    dprint("returning %d bytes in buffer %p (winning_conn=%d)\n",
	(int) reply->length, reply->data, winning_conn);
    retval = 0;
    conns[winning_conn].x.in.buf = 0;
    if (addr_used)
	    *addr_used = winning_conn;
    if (localaddr != 0 && localaddrlen != 0 && *localaddrlen > 0)
	(void) getsockname(conns[winning_conn].fd, (struct sockaddr *)localaddr,
			   localaddrlen);
egress:
    for (i = 0; i < n_conns; i++) {
	if (conns[i].fd != INVALID_SOCKET)
	    close(conns[i].fd);
	if (conns[i].state == READING
	    && conns[i].x.in.buf != 0
	    && conns[i].x.in.buf != udpbuf)
	    free(conns[i].x.in.buf);
    }
    free(conns);
    if (reply->data != udpbuf)
	free(udpbuf);
    return retval;
}
