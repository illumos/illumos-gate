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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Shared routines for client and server for
 * secure read(), write(), getc(), and putc().
 * Only one security context, thus only work on one fd at a time!
 */

#include "ftp_var.h"
#include <gssapi/gssapi.h>
#include <arpa/ftp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>

extern struct	sockaddr_in hisaddr;
extern struct	sockaddr_in myaddr;
extern int	dlevel;
extern int	auth_type;
extern uint_t	maxbuf; 	/* maximum output buffer size */
extern uchar_t	*ucbuf;		/* cleartext buffer */
static uint_t	nout;		/* number of chars in ucbuf */
static uint_t	smaxbuf;	/* Internal saved value of maxbuf */
static uint_t	smaxqueue;	/* Maximum allowed to queue before flush */

extern gss_ctx_id_t gcontext;
static int secure_putbuf(int, uchar_t *, uint_t);

static int
looping_write(int fd, const char *buf, int len)
{
	int cc, len2 = 0;

	if (len == 0)
		return (0);

	do {
		cc = write(fd, buf, len);
		if (cc < 0) {
			if (errno == EINTR)
				continue;
			return (cc);
		} else if (cc == 0) {
			return (len2);
		} else {
			buf += cc;
			len2 += cc;
			len -= cc;
		}
	} while (len > 0);
	return (len2);
}

static int
looping_read(int fd, char *buf, int len)
{
	int cc, len2 = 0;

	do {
		cc = read(fd, buf, len);
		if (cc < 0) {
			if (errno == EINTR)
				continue;
			return (cc);	/* errno is already set */
		} else if (cc == 0) {
			return (len2);
		} else {
			buf += cc;
			len2 += cc;
			len -= cc;
		}
	} while (len > 0);
	return (len2);
}

#define	ERR	-2

static void
secure_error(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	putc('\n', stderr);
}

/*
 * Given maxbuf as a buffer size, determine how much can we
 * really transfer given the overhead of different algorithms
 *
 * Sets smaxbuf and smaxqueue
 */

static int
secure_determine_constants(void)
{
	smaxbuf = maxbuf;
	smaxqueue = maxbuf;

	if (auth_type == AUTHTYPE_GSSAPI) {
		OM_uint32 maj_stat, min_stat, mlen;
		OM_uint32 msize = maxbuf;

		maj_stat = gss_wrap_size_limit(&min_stat, gcontext,
			(dlevel == PROT_P),
			GSS_C_QOP_DEFAULT,
			msize, &mlen);
		if (maj_stat != GSS_S_COMPLETE) {
			user_gss_error(maj_stat, min_stat,
				"GSSAPI fudge determination");
			/* Return error how? */
			return (ERR);
		}
		smaxqueue = mlen;
	}

	return (0);
}

static uchar_t
secure_putbyte(int fd, uchar_t c)
{
	int ret;

	if ((smaxbuf == 0) || (smaxqueue == 0) || (smaxbuf != maxbuf)) {
	    ret = secure_determine_constants();
	    if (ret)
		return (ret);
	}
	ucbuf[nout++] = c;
	if (nout == smaxqueue) {
		nout = 0;
		ret = secure_putbuf(fd, ucbuf, smaxqueue);
		return (ret ? ret :c);
	}
	return (c);
}

/*
 * returns:
 *	 0  on success
 *	-1  on error (errno set)
 *	-2  on security error
 */
int
secure_flush(int fd)
{
	int ret;

	if (dlevel == PROT_C)
		return (0);
	if (nout)
		if (ret = secure_putbuf(fd, ucbuf, nout))
			return (ret);
	return (secure_putbuf(fd, (uchar_t *)"", nout = 0));
}

/*
 * returns:
 *	>= 0	on success
 *	-1	on error
 *	-2	on security error
 */
int
secure_putc(int c, FILE *stream)
{
	if (dlevel == PROT_C)
		return (putc(c, stream));
	return (secure_putbyte(fileno(stream), (uchar_t)c));
}

/*
 * returns:
 *	nbyte on success
 *	-1  on error (errno set)
 *	-2  on security error
 */
ssize_t
secure_write(int fd, const void *inbuf, size_t nbyte)
{
	uint_t i;
	int c;
	uchar_t *buf = (uchar_t *)inbuf;

	if (dlevel == PROT_C)
		return (write(fd, buf, nbyte));
	for (i = 0; nbyte > 0; nbyte--)
		if ((c = secure_putbyte(fd, buf[i++])) < 0)
			return (c);
	return (i);
}

/*
 * returns:
 *	 0  on success
 *	-1  on error, errno set
 *	-2  on security error
 */
static int secure_putbuf(int fd, uchar_t *buf, uint_t nbyte)
{
	static char *outbuf;		/* output ciphertext */
	static uint_t bufsize;	/* size of outbuf */
	int length;
	uint_t net_len;

	/* Other auth types go here ... */

	if (auth_type == AUTHTYPE_GSSAPI) {
		gss_buffer_desc in_buf, out_buf;
		OM_uint32 maj_stat, min_stat;
		int conf_state;

		in_buf.value = buf;
		in_buf.length = nbyte;
		maj_stat = gss_seal(&min_stat, gcontext,
				(dlevel == PROT_P), /* confidential */
				GSS_C_QOP_DEFAULT,
				&in_buf, &conf_state,
				&out_buf);
		if (maj_stat != GSS_S_COMPLETE) {
			/*
			 * generally need to deal
			 * ie. should loop, but for now just fail
			 */
			user_gss_error(maj_stat, min_stat, dlevel == PROT_P?
				"GSSAPI seal failed" : "GSSAPI sign failed");
			return (ERR);
		}

		if (bufsize < out_buf.length) {
			outbuf = outbuf ?
				realloc(outbuf, (size_t)out_buf.length) :
				malloc((size_t)out_buf.length);
			if (outbuf)
				bufsize = out_buf.length;
			else {
				bufsize = 0;
				secure_error("%s (in malloc of PROT buffer)",
					strerror(errno));
				return (ERR);
			}
		}

		memcpy(outbuf, out_buf.value, length = out_buf.length);
		gss_release_buffer(&min_stat, &out_buf);
	}
	net_len = htonl((uint32_t)length);
	if (looping_write(fd, (char *)&net_len, 4) == -1)
		return (-1);
	if (looping_write(fd, outbuf, length) != length)
		return (-1);
	return (0);
}

static int
secure_getbyte(int fd)
{
	/* number of chars in ucbuf, pointer into ucbuf */
	static uint_t nin, bufp;
	int kerror;
	uint_t length;

	if (nin == 0) {
		if ((kerror =
			looping_read(fd, (char *)&length, sizeof (length)))
			!= sizeof (length)) {
			secure_error("Couldn't read PROT buffer length: %d/%s",
				kerror, (kerror == -1) ? strerror(errno) :
				"premature EOF");
			return (ERR);
		}
		if ((length = ntohl((uint32_t)length)) > maxbuf) {
			secure_error("Length (%d) of PROT buffer > PBSZ=%u",
				length, maxbuf);
			return (ERR);
		}
		if ((kerror = looping_read(fd, (char *)ucbuf, length))
			!= length) {
			secure_error("Couldn't read %u byte PROT buffer: %s",
					length, kerror == -1 ?
					strerror(errno) : "premature EOF");
			return (ERR);
		}
		/* Other auth types go here ... */

		if (auth_type == AUTHTYPE_GSSAPI) {
			gss_buffer_desc xmit_buf, msg_buf;
			OM_uint32 maj_stat, min_stat;
			int conf_state;

			xmit_buf.value = ucbuf;
			xmit_buf.length = length;
			conf_state = (dlevel == PROT_P);
			/* decrypt/verify the message */
			maj_stat = gss_unseal(&min_stat, gcontext, &xmit_buf,
				&msg_buf, &conf_state, NULL);
			if (maj_stat != GSS_S_COMPLETE) {
				user_gss_error(maj_stat, min_stat,
				    (dlevel == PROT_P)?
				    "failed unsealing ENC message":
				    "failed unsealing MIC message");
				return (ERR);
			}

			memcpy(ucbuf, msg_buf.value,
				nin = bufp = msg_buf.length);
			gss_release_buffer(&min_stat, &msg_buf);
		}
		/* Other auth types go here ... */
	}
	return ((nin == 0) ? EOF : ucbuf[bufp - nin--]);
}

/*
 * returns:
 *	 0	on success
 *	-1	on EOF
 *	-2	on security error
 */
int
secure_getc(FILE *stream)
{
	if (dlevel == PROT_C)
		return (getc(stream));
	return (secure_getbyte(fileno(stream)));
}

/*
 * returns:
 *	> 0	on success (n == # of bytes read)
 *	 0	on EOF
 *	-1	on error, errno set, only for PROT_C
 *	-2	on security error (ERR = -2)
 */
ssize_t
secure_read(int fd, void *inbuf, size_t nbyte)
{
	int c, i;
	char *buf = (char *)inbuf;

	if (dlevel == PROT_C)
		return (read(fd, buf, nbyte));
	if (goteof)
		return (goteof = 0);

	for (i = 0; nbyte > 0; nbyte--)
		switch (c = secure_getbyte(fd)) {
			case ERR:
				return (c);
			case EOF:
				goteof = i ? 1 : 0;
				return (i);
			default:
				buf[i++] = c;
		}
	return (i);
}
