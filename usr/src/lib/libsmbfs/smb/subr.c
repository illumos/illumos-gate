/*
 * Copyright (c) 2000, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: subr.c,v 1.19 2005/02/09 00:23:45 lindak Exp $
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/time.h>

#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <sysexits.h>
#include <libintl.h>

#include <netsmb/netbios.h>
#include <netsmb/smb_lib.h>
#include <netsmb/nb_lib.h>

#include <err.h>

#include "private.h"

static int smblib_initialized;

int
smb_lib_init(void)
{
	int error;

	if (smblib_initialized)
		return (0);
	if ((error = nls_setlocale("")) != 0) {
		fprintf(stdout, dgettext(TEXT_DOMAIN,
		    "%s: can't initialise locale\n"), __progname);
		return (error);
	}
	smblib_initialized++;
	return (0);
}

int
smb_getlocalname(char **namepp)
{
	char buf[SMBIOC_MAX_NAME], *cp;

	if (gethostname(buf, sizeof (buf)) != 0)
		return (errno);
	cp = strchr(buf, '.');
	if (cp)
		*cp = '\0';
	cp = strdup(buf);
	if (cp == NULL)
		return (ENOMEM);
	*namepp = cp;
	return (0);
}

/*
 * Private version of strerror(3C) that
 * knows our special error codes.
 */
char *
smb_strerror(int err)
{
	char *msg;

	switch (err) {
	case EBADRPC:
		msg = dgettext(TEXT_DOMAIN,
		    "remote call failed");
		break;
	case EAUTH:
		msg = dgettext(TEXT_DOMAIN,
		    "authentication failed");
		break;
	default:
		msg = strerror(err);
		break;
	}

	return (msg);
}

/*
 * Print a (descriptive) error message
 * error values:
 *         0 - no specific error code available;
 *  1..32767 - system error
 */
void
smb_error(const char *fmt, int error, ...) {
	va_list ap;
	const char *cp;
	int errtype;

	fprintf(stderr, "%s: ", __progname);
	va_start(ap, error);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (error == -1) {
		error = errno;
		errtype = SMB_SYS_ERROR;
	} else {
		errtype = error & SMB_ERRTYPE_MASK;
		error &= ~SMB_ERRTYPE_MASK;
	}
	switch (errtype) {
	    case SMB_SYS_ERROR:
		if (error)
			fprintf(stderr, ": syserr = %s\n", smb_strerror(error));
		else
			fprintf(stderr, "\n");
		break;
	    case SMB_RAP_ERROR:
		fprintf(stderr, ": raperr = %d (0x%04x)\n", error, error);
		break;
	    case SMB_NB_ERROR:
		cp = nb_strerror(error);
		if (cp == NULL)
			fprintf(stderr, ": nberr = unknown (0x%04x)\n", error);
		else
			fprintf(stderr, ": nberr = %s\n", cp);
		break;
	    default:
		fprintf(stderr, "\n");
	}
}

char *
smb_printb(char *dest, int flags, const struct smb_bitname *bnp) {
	int first = 1;

	strcpy(dest, "<");
	for (; bnp->bn_bit; bnp++) {
		if (flags & bnp->bn_bit) {
			strcat(dest, bnp->bn_name);
			first = 0;
		}
		if (!first && (flags & bnp[1].bn_bit))
			strcat(dest, "|");
	}
	strcat(dest, ">");
	return (dest);
}

void
smb_simplecrypt(char *dst, const char *src)
{
	int ch, pos;

	*dst++ = '$';
	*dst++ = '$';
	*dst++ = '1';
	pos = 27;
	while (*src) {
		ch = *src++;
		if (isascii(ch))
			ch = (isupper(ch) ? ('A' + (ch - 'A' + 13) % 26) :
			    islower(ch) ? ('a' + (ch - 'a' + 13) % 26) : ch);
		ch ^= pos;
		pos += 13;
		sprintf(dst, "%02x", ch);
		dst += 2;
	}
	*dst = 0;
}

int
smb_simpledecrypt(char *dst, const char *src)
{
	char *ep, hexval[3];
	int len, ch, pos;

	if (strncmp(src, "$$1", 3) != 0)
		return (EINVAL);
	src += 3;
	len = strlen(src);
	if (len & 1)
		return (EINVAL);
	len /= 2;
	hexval[2] = 0;
	pos = 27;
	while (len--) {
		hexval[0] = *src++;
		hexval[1] = *src++;
		ch = strtoul(hexval, &ep, 16);
		if (*ep != 0)
			return (EINVAL);
		ch ^= pos;
		pos += 13;
		if (isascii(ch))
			ch = (isupper(ch) ? ('A' + (ch - 'A' + 13) % 26) :
			    islower(ch) ? ('a' + (ch - 'a' + 13) % 26) : ch);
		*dst++ = ch;
	}
	*dst = 0;
	return (0);
}

/*
 * Number of seconds between 1970 and 1601 year
 * (134774 * 24 * 60 * 60)
 */
static const uint64_t DIFF1970TO1601 = 11644473600ULL;

void
smb_time_local2server(struct timeval *tsp, int tzoff, long *seconds)
{
	*seconds = tsp->tv_sec - tzoff * 60;
}

void
smb_time_server2local(ulong_t seconds, int tzoff, struct timeval *tsp)
{
	tsp->tv_sec = seconds + tzoff * 60;
	tsp->tv_usec = 0;
}

/*
 * Time from server comes as UTC, so no need to use tz
 */
/*ARGSUSED*/
void
smb_time_NT2local(uint64_t nsec, int tzoff, struct timeval *tsp)
{
	smb_time_server2local(nsec / 10000000 - DIFF1970TO1601, 0, tsp);
}

/*ARGSUSED*/
void
smb_time_local2NT(struct timeval *tsp, int tzoff, uint64_t *nsec)
{
	long seconds;

	smb_time_local2server(tsp, 0, &seconds);
	*nsec = (((uint64_t)(seconds) & ~1) + DIFF1970TO1601) *
	    (uint64_t)10000000;
}

void
smb_hexdump(const void *buf, int len)
{
	const uchar_t *p = buf;
	int ofs = 0;

	while (len--) {
		if (ofs % 16 == 0)
			fprintf(stderr, "%02X: ", ofs);
		fprintf(stderr, "%02x ", *p++);
		ofs++;
		if (ofs % 16 == 0)
			fprintf(stderr, "\n");
	}
	if (ofs % 16 != 0)
		fprintf(stderr, "\n");
}

void
dprint(const char *fname, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if (smb_debug) {
		fprintf(stderr, "%s: ", fname);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	}
	va_end(ap);
}

#undef __progname

char *__progname = NULL;

char *
smb_getprogname()
{
	char *p;

	if (__progname == NULL) {
		__progname = (char *)getexecname();
		if ((p = strrchr(__progname, '/')) != 0)
			__progname = p + 1;
	}
	return (__progname);
}
