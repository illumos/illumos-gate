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
#include <cflib.h>
#include <err.h>

uid_t real_uid, eff_uid;

static int smblib_initialized;

struct rcfile *smb_rc;

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

extern int home_nsmbrc;

#ifdef DEBUG
#include "queue.h"
#include "rcfile_priv.h"

struct rcsection *rc_findsect(struct rcfile *rcp, const char *sectname);
struct rckey *rc_sect_findkey(struct rcsection *rsp, const char *keyname);

void
dump_props(char *where)
{
	struct rcsection *rsp = NULL;
	struct rckey *rkp = NULL;

	printf("Settings %s\n", where);
	SLIST_FOREACH(rsp, &smb_rc->rf_sect, rs_next) {
		printf("section=%s\n", rsp->rs_name);
		fflush(stdout);

		SLIST_FOREACH(rkp, &rsp->rs_keys, rk_next) {
			printf("  key=%s, value=%s\n",
			    rkp->rk_name, rkp->rk_value);
			fflush(stdout);
		}
	}
}
#endif

/*
 * first read ~/.smbrc, next try to merge SMB_CFG_FILE - if that fails
 * because SMB_CFG_FILE doesn't exist, try to merge OLD_SMB_CFG_FILE
 */
int
smb_open_rcfile(struct smb_ctx *ctx)
{
	char *home, *fn;
	int error, len;

	smb_rc = NULL;
#ifdef DEPRECATED
	fn = SMB_CFG_FILE;
	error = rc_merge(fn, &smb_rc);
	if (error == ENOENT) {
		/*
		 * OK, try to read a config file in the old location.
		 */
		fn = OLD_SMB_CFG_FILE;
		error = rc_merge(fn, &smb_rc);
	}
#endif
	fn = "/usr/sbin/sharectl get smbfs";
	error = rc_merge_pipe(fn, &smb_rc);
	if (error != 0 && error != ENOENT)
		fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "Can't open %s: %s\n"), fn, smb_strerror(errno));
#ifdef DEBUG
	if (smb_debug)
		dump_props("after reading global repository");
#endif

	home = getenv("HOME");
	if (home == NULL && ctx && ctx->ct_home)
		home = ctx->ct_home;
	if (home) {
		len = strlen(home) + 20;
		fn = malloc(len);
		snprintf(fn, len, "%s/.nsmbrc", home);
		home_nsmbrc = 1;
		error = rc_merge(fn, &smb_rc);
		if (error != 0 && error != ENOENT) {
			fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "Can't open %s: %s\n"), fn, smb_strerror(errno));
		}
		free(fn);
	}
	home_nsmbrc = 0;
#ifdef DEBUG
	if (smb_debug)
		dump_props("after reading user settings");
#endif
	if (smb_rc == NULL) {
		return (ENOENT);
	}
	return (0);
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
