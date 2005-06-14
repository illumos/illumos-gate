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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>

#include <fmd_alloc.h>
#include <fmd_subr.h>
#include <fmd_error.h>
#include <fmd_string.h>
#include <fmd_scheme.h>
#include <fmd_fmri.h>
#include <fmd.h>

/*
 * Interfaces to be used by the plugins
 */

void *
fmd_fmri_alloc(size_t size)
{
	return (fmd_alloc(size, FMD_SLEEP));
}

void *
fmd_fmri_zalloc(size_t size)
{
	return (fmd_zalloc(size, FMD_SLEEP));
}

void
fmd_fmri_free(void *data, size_t size)
{
	fmd_free(data, size);
}

int
fmd_fmri_set_errno(int err)
{
	errno = err;
	return (-1);
}

void
fmd_fmri_warn(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fmd_verror(EFMD_FMRI_SCHEME, format, ap);
	va_end(ap);
}

/*
 * Convert an input string to a URI escaped string and return the new string.
 * RFC2396 Section 2.4 says that data must be escaped if it does not have a
 * representation using an unreserved character, where an unreserved character
 * is one that is either alphanumberic or one of the marks defined in S2.3.
 * We've amended the unreserved character list to include commas and colons,
 * as both are needed to make FMRIs readable without escaping.  We also permit
 * "/" to pass through unescaped as any path delimiters used by the event
 * creator are presumably intended to appear in the final path.
 */
char *
fmd_fmri_strescape(const char *s)
{
	static const char rfc2396_mark[] = "-_.!~*'()" ":,";
	static const char hex_digits[] = "0123456789ABCDEF";

	const char *p;
	char c, *q, *s2;
	size_t n = 0;

	if (s == NULL)
		return (NULL);

	for (p = s; (c = *p) != '\0'; p++) {
		if (isalnum(c) || c == '/' || strchr(rfc2396_mark, c) != NULL)
			n++;	/* represent c as itself */
		else
			n += 3; /* represent c as escape */
	}

	s2 = fmd_alloc(n + 1, FMD_SLEEP);

	for (p = s, q = s2; (c = *p) != '\0'; p++) {
		if (isalnum(c) || c == '/' || strchr(rfc2396_mark, c) != NULL) {
			*q++ = c;
		} else {
			*q++ = '%';
			*q++ = hex_digits[((uchar_t)c & 0xf0) >> 4];
			*q++ = hex_digits[(uchar_t)c & 0xf];
		}
	}

	ASSERT(q == s2 + n);
	*q = '\0';
	return (s2);
}

char *
fmd_fmri_strdup(const char *s)
{
	return (fmd_strdup(s, FMD_SLEEP));
}

void
fmd_fmri_strfree(char *s)
{
	fmd_strfree(s);
}

const char *
fmd_fmri_get_rootdir(void)
{
	return (fmd.d_rootdir);
}

const char *
fmd_fmri_get_platform(void)
{
	return (fmd.d_platform);
}

uint64_t
fmd_fmri_get_drgen(void)
{
	uint64_t gen;

	(void) pthread_mutex_lock(&fmd.d_stats_lock);
	gen = fmd.d_stats->ds_dr_gen.fmds_value.ui64;
	(void) pthread_mutex_unlock(&fmd.d_stats_lock);

	return (gen);
}

/*
 * Interfaces for users of the plugins
 */

static fmd_scheme_t *
nvl2scheme(nvlist_t *nvl)
{
	char *name;

	if (nvlist_lookup_string(nvl, FM_FMRI_SCHEME, &name) != 0) {
		(void) fmd_set_errno(EFMD_FMRI_INVAL);
		return (NULL);
	}

	return (fmd_scheme_hash_lookup(fmd.d_schemes, name));
}

ssize_t
fmd_fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	fmd_scheme_t *sp;
	char c;
	ssize_t rv;

	if (buf == NULL && buflen == 0) {
		buf = &c;
		buflen = sizeof (c);
	}

	if ((sp = nvl2scheme(nvl)) == NULL)
		return (-1); /* errno is set for us */

	(void) pthread_mutex_lock(&sp->sch_opslock);
	ASSERT(buf != NULL || buflen == 0);
	rv = sp->sch_ops.sop_nvl2str(nvl, buf, buflen);
	(void) pthread_mutex_unlock(&sp->sch_opslock);

	fmd_scheme_hash_release(fmd.d_schemes, sp);
	return (rv);
}

int
fmd_fmri_expand(nvlist_t *nvl)
{
	fmd_scheme_t *sp;
	int rv;

	if ((sp = nvl2scheme(nvl)) == NULL)
		return (-1); /* errno is set for us */

	(void) pthread_mutex_lock(&sp->sch_opslock);
	rv = sp->sch_ops.sop_expand(nvl);
	(void) pthread_mutex_unlock(&sp->sch_opslock);

	fmd_scheme_hash_release(fmd.d_schemes, sp);
	return (rv);
}

int
fmd_fmri_present(nvlist_t *nvl)
{
	fmd_scheme_t *sp;
	int rv;

	if ((sp = nvl2scheme(nvl)) == NULL)
		return (-1); /* errno is set for us */

	(void) pthread_mutex_lock(&sp->sch_opslock);
	rv = sp->sch_ops.sop_present(nvl);
	(void) pthread_mutex_unlock(&sp->sch_opslock);

	fmd_scheme_hash_release(fmd.d_schemes, sp);
	return (rv);
}

int
fmd_fmri_unusable(nvlist_t *nvl)
{
	fmd_scheme_t *sp;
	int rv;

	if ((sp = nvl2scheme(nvl)) == NULL)
		return (-1); /* errno is set for us */

	(void) pthread_mutex_lock(&sp->sch_opslock);
	rv = sp->sch_ops.sop_unusable(nvl);
	(void) pthread_mutex_unlock(&sp->sch_opslock);

	fmd_scheme_hash_release(fmd.d_schemes, sp);
	return (rv);
}

int
fmd_fmri_contains(nvlist_t *er, nvlist_t *ee)
{
	fmd_scheme_t *sp;
	char *ername, *eename;
	int rv;

	if (nvlist_lookup_string(er, FM_FMRI_SCHEME, &ername) != 0 ||
	    nvlist_lookup_string(ee, FM_FMRI_SCHEME, &eename) != 0 ||
	    strcmp(ername, eename) != 0)
		return (fmd_set_errno(EFMD_FMRI_INVAL));

	if ((sp = fmd_scheme_hash_lookup(fmd.d_schemes, ername)) == NULL)
		return (-1); /* errno is set for us */

	(void) pthread_mutex_lock(&sp->sch_opslock);
	rv = sp->sch_ops.sop_contains(er, ee);
	(void) pthread_mutex_unlock(&sp->sch_opslock);

	fmd_scheme_hash_release(fmd.d_schemes, sp);
	return (rv);
}
