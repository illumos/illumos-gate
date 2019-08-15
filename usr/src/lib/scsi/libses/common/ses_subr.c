/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <scsi/libses.h>
#include "ses_impl.h"

__thread ses_errno_t _ses_errno;
__thread char _ses_errmsg[1024];
__thread char _ses_nverr_member[256];

static void ses_vpanic(const char *, va_list) __NORETURN;

static void
ses_vpanic(const char *fmt, va_list ap)
{
	int oserr = errno;
	char msg[BUFSIZ];
	size_t len;

	(void) snprintf(msg, sizeof (msg), "ABORT: ");
	len = strlen(msg);
	(void) vsnprintf(msg + len, sizeof (msg) - len, fmt, ap);

	if (strchr(fmt, '\n') == NULL) {
		len = strlen(msg);
		(void) snprintf(msg + len, sizeof (msg) - len, ": %s\n",
		    strerror(oserr));
	}

	(void) write(STDERR_FILENO, msg, strlen(msg));

	abort();
}

/*PRINTFLIKE1*/
void
ses_panic(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	ses_vpanic(fmt, ap);
	va_end(ap);
}

int
ses_assert(const char *expr, const char *file, int line)
{
	ses_panic("\"%s\", line %d: assertion failed: %s\n", file, line, expr);

	/*NOTREACHED*/
	return (0);
}

int
nvlist_add_fixed_string(nvlist_t *nvl, const char *name,
    const char *buf, size_t len)
{
	char *str = alloca(len + 1);
	bcopy(buf, str, len);
	str[len] = '\0';

	return (nvlist_add_string(nvl, name, str));
}

/*
 * Like fixed_string, but clears any leading or trailing spaces.
 */
int
nvlist_add_fixed_string_trunc(nvlist_t *nvl, const char *name,
    const char *buf, size_t len)
{
	while (buf[0] == ' ' && len > 0) {
		buf++;
		len--;
	}

	while (len > 0 && buf[len - 1] == ' ')
		len--;

	return (nvlist_add_fixed_string(nvl, name, buf, len));
}

ses_errno_t
ses_errno(void)
{
	return (_ses_errno);
}

const char *
ses_errmsg(void)
{
	if (_ses_errmsg[0] == '\0')
		(void) snprintf(_ses_errmsg, sizeof (_ses_errmsg), "%s",
		    ses_strerror(_ses_errno));

	return (_ses_errmsg);
}

const char *
ses_nv_error_member(void)
{
	if (_ses_nverr_member[0] != '\0')
		return (_ses_nverr_member);
	else
		return (NULL);
}

static int
__ses_set_errno(ses_errno_t err, const char *nvm)
{
	if (nvm == NULL) {
		_ses_nverr_member[0] = '\0';
	} else {
		(void) strlcpy(_ses_nverr_member, nvm,
		    sizeof (_ses_nverr_member));
	}
	_ses_errmsg[0] = '\0';
	_ses_errno = err;

	return (-1);
}

int
ses_set_errno(ses_errno_t err)
{
	return (__ses_set_errno(err, NULL));
}

int
ses_set_nverrno(int err, const char *member)
{
	ses_errno_t se = (err == ENOMEM || err == EAGAIN) ?
	    ESES_NOMEM : ESES_NVL;

	/*
	 * If the error is ESES_NVL, then we should always have a member
	 * available.  The only time 'member' is NULL is when nvlist_alloc()
	 * fails, which should only be possible if memory allocation fails.
	 */
	assert(se == ESES_NOMEM || member != NULL);

	return (__ses_set_errno(se, member));
}

static int
ses_verror(ses_errno_t err, const char *fmt, va_list ap)
{
	int syserr = errno;
	size_t n;
	char *errmsg;

	errmsg = alloca(sizeof (_ses_errmsg));
	(void) vsnprintf(errmsg, sizeof (_ses_errmsg), fmt, ap);
	(void) ses_set_errno(err);

	n = strlen(errmsg);

	while (n != 0 && errmsg[n - 1] == '\n')
		errmsg[--n] = '\0';

	bcopy(errmsg, _ses_errmsg, sizeof (_ses_errmsg));
	errno = syserr;

	return (-1);
}

static int
ses_vnverror(int err, const char *member, const char *fmt,
    va_list ap)
{
	int syserr = errno;
	size_t n;
	char *errmsg;

	errmsg = alloca(sizeof (_ses_errmsg));
	(void) vsnprintf(errmsg, sizeof (_ses_errmsg), fmt, ap);
	(void) ses_set_nverrno(err, member);

	n = strlen(errmsg);

	while (n != 0 && errmsg[n - 1] == '\n')
		errmsg[--n] = '\0';

	(void) snprintf(errmsg + n, sizeof (_ses_errmsg) - n, ": %s",
	    strerror(err));

	bcopy(errmsg, _ses_errmsg, sizeof (_ses_errmsg));
	errno = syserr;

	return (-1);
}

int
ses_error(ses_errno_t err, const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = ses_verror(err, fmt, ap);
	va_end(ap);

	return (rv);
}

int
ses_nverror(int err, const char *member, const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = ses_vnverror(err, member, fmt, ap);
	va_end(ap);

	return (rv);
}

int
ses_libscsi_error(libscsi_hdl_t *shp, const char *fmt, ...)
{
	va_list ap;
	char errmsg[LIBSES_ERRMSGLEN];
	libscsi_errno_t se = libscsi_errno(shp);
	ses_errno_t e;

	switch (se) {
	case ESCSI_NONE:
		return (0);
	case ESCSI_NOMEM:
		e = ESES_NOMEM;
		break;
	case ESCSI_NOTSUP:
		e = ESES_NOTSUP;
		break;
	case ESCSI_ZERO_LENGTH:
	case ESCSI_VERSION:
	case ESCSI_BADFLAGS:
	case ESCSI_BOGUSFLAGS:
	case ESCSI_BADLENGTH:
	case ESCSI_NEEDBUF:
		va_start(ap, fmt);
		(void) vsnprintf(errmsg, sizeof (errmsg), fmt, ap);
		va_end(ap);
		ses_panic("%s: unexpected libscsi error %s: %s", errmsg,
		    libscsi_errname(se), libscsi_errmsg(shp));
		break;
	case ESCSI_UNKNOWN:
		e = ESES_UNKNOWN;
		break;
	default:
		e = ESES_LIBSCSI;
		break;
	}

	va_start(ap, fmt);
	(void) vsnprintf(errmsg, sizeof (errmsg), fmt, ap);
	va_end(ap);

	return (ses_error(e, "%s: %s", errmsg, libscsi_errmsg(shp)));
}

int
ses_scsi_error(libscsi_action_t *ap, const char *fmt, ...)
{
	va_list args;
	char errmsg[LIBSES_ERRMSGLEN];
	uint64_t asc = 0, ascq = 0, key = 0;
	const char *code, *keystr;

	va_start(args, fmt);
	(void) vsnprintf(errmsg, sizeof (errmsg), fmt, args);
	va_end(args);

	if (libscsi_action_parse_sense(ap, &key, &asc, &ascq, NULL) != 0)
		return (ses_error(ESES_LIBSCSI,
		    "%s: SCSI status %d (no sense data available)", errmsg,
		    libscsi_action_get_status(ap)));

	code = libscsi_sense_code_name(asc, ascq);
	keystr = libscsi_sense_key_name(key);

	return (ses_error(ESES_LIBSCSI, "%s: SCSI status %d sense key %llu "
	    "(%s) additional sense code 0x%llx/0x%llx (%s)", errmsg,
	    libscsi_action_get_status(ap), key, keystr ? keystr : "<unknown>",
	    asc, ascq, code ? code : "<unknown>"));
}

void *
ses_alloc(size_t sz)
{
	void *p;

	if (sz == 0)
		ses_panic("attempted zero-length allocation");

	if ((p = malloc(sz)) == NULL)
		(void) ses_set_errno(ESES_NOMEM);

	return (p);
}

void *
ses_zalloc(size_t sz)
{
	void *p;

	if ((p = ses_alloc(sz)) != NULL)
		bzero(p, sz);

	return (p);
}

char *
ses_strdup(const char *s)
{
	char *p;
	size_t len;

	if (s == NULL)
		ses_panic("attempted zero-length allocation");

	len = strlen(s) + 1;

	if ((p = ses_alloc(len)) != NULL)
		bcopy(s, p, len);

	return (p);
}

void *
ses_realloc(void *p, size_t sz)
{
	if (sz == 0)
		ses_panic("attempted zero-length allocation");

	if ((p = realloc(p, sz)) == NULL)
		(void) ses_set_errno(ESES_NOMEM);

	return (p);
}

/*ARGSUSED*/
void
ses_free(void *p)
{
	free(p);
}
