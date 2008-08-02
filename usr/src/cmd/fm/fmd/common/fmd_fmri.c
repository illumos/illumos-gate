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
#include <fmd_topo.h>
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
 * is one that is either alphanumeric or one of the marks defined in S2.3.
 */
static size_t
fmd_fmri_uriescape(const char *s, const char *xmark, char *buf, size_t len)
{
	static const char rfc2396_mark[] = "-_.!~*'()";
	static const char hex_digits[] = "0123456789ABCDEF";
	static const char empty_str[] = "";

	const char *p;
	char c, *q;
	size_t n = 0;

	if (s == NULL)
		s = empty_str;

	if (xmark == NULL)
		xmark = empty_str;

	for (p = s; (c = *p) != '\0'; p++) {
		if (isalnum(c) || strchr(rfc2396_mark, c) || strchr(xmark, c))
			n++;	/* represent c as itself */
		else
			n += 3; /* represent c as escape */
	}

	if (buf == NULL)
		return (n);

	for (p = s, q = buf; (c = *p) != '\0' && q < buf + len; p++) {
		if (isalnum(c) || strchr(rfc2396_mark, c) || strchr(xmark, c)) {
			*q++ = c;
		} else {
			*q++ = '%';
			*q++ = hex_digits[((uchar_t)c & 0xf0) >> 4];
			*q++ = hex_digits[(uchar_t)c & 0xf];
		}
	}

	if (q == buf + len)
		q--; /* len is too small: truncate output string */

	*q = '\0';
	return (n);
}

/*
 * Convert a name-value pair list representing an FMRI authority into the
 * corresponding RFC2396 string representation and return the new string.
 */
char *
fmd_fmri_auth2str(nvlist_t *nvl)
{
	nvpair_t *nvp;
	char *s, *p, *v;
	size_t n = 0;

	for (nvp = nvlist_next_nvpair(nvl, NULL);
	    nvp != NULL; nvp = nvlist_next_nvpair(nvl, nvp)) {

		if (nvpair_type(nvp) != DATA_TYPE_STRING)
			continue; /* do not format non-string elements */

		n += fmd_fmri_uriescape(nvpair_name(nvp), NULL, NULL, 0) + 1;
		(void) nvpair_value_string(nvp, &v);
		n += fmd_fmri_uriescape(v, ":", NULL, 0) + 1;
	}

	p = s = fmd_alloc(n, FMD_SLEEP);

	for (nvp = nvlist_next_nvpair(nvl, NULL);
	    nvp != NULL; nvp = nvlist_next_nvpair(nvl, nvp)) {

		if (nvpair_type(nvp) != DATA_TYPE_STRING)
			continue; /* do not format non-string elements */

		if (p != s)
			*p++ = ',';

		p += fmd_fmri_uriescape(nvpair_name(nvp), NULL, p, n);
		*p++ = '=';
		(void) nvpair_value_string(nvp, &v);
		p += fmd_fmri_uriescape(v, ":", p, n);
	}

	return (s);
}

/*
 * Convert an input string to a URI escaped string and return the new string.
 * We amend the unreserved character list to include commas and colons,
 * as both are needed to make FMRIs readable without escaping.  We also permit
 * "/" to pass through unescaped as any path delimiters used by the event
 * creator are presumably intended to appear in the final path.
 */
char *
fmd_fmri_strescape(const char *s)
{
	char *s2;
	size_t n;

	if (s == NULL)
		return (NULL);

	n = fmd_fmri_uriescape(s, ":,/", NULL, 0);
	s2 = fmd_alloc(n + 1, FMD_SLEEP);
	(void) fmd_fmri_uriescape(s, ":,/", s2, n + 1);

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

struct topo_hdl *
fmd_fmri_topo_hold(int version)
{
	fmd_topo_t *ftp;

	if (version != TOPO_VERSION)
		return (NULL);

	ftp = fmd_topo_hold();

	return (ftp->ft_hdl);
}

void
fmd_fmri_topo_rele(struct topo_hdl *thp)
{
	fmd_topo_rele_hdl(thp);
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
fmd_fmri_replaced(nvlist_t *nvl)
{
	fmd_scheme_t *sp;
	int rv;

	if ((sp = nvl2scheme(nvl)) == NULL)
		return (-1); /* errno is set for us */

	(void) pthread_mutex_lock(&sp->sch_opslock);
	rv = sp->sch_ops.sop_replaced(nvl);
	(void) pthread_mutex_unlock(&sp->sch_opslock);

	fmd_scheme_hash_release(fmd.d_schemes, sp);
	return (rv);
}

int
fmd_fmri_service_state(nvlist_t *nvl)
{
	fmd_scheme_t *sp;
	int rv;

	if ((sp = nvl2scheme(nvl)) == NULL)
		return (-1); /* errno is set for us */

	(void) pthread_mutex_lock(&sp->sch_opslock);
	rv = sp->sch_ops.sop_service_state(nvl);
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

nvlist_t *
fmd_fmri_translate(nvlist_t *fmri, nvlist_t *auth)
{
	fmd_scheme_t *sp;
	nvlist_t *nvl;

	if ((sp = nvl2scheme(fmri)) == NULL)
		return (NULL); /* errno is set for us */

	(void) pthread_mutex_lock(&sp->sch_opslock);
	nvl = sp->sch_ops.sop_translate(fmri, auth);
	(void) pthread_mutex_unlock(&sp->sch_opslock);

	fmd_scheme_hash_release(fmd.d_schemes, sp);
	return (nvl);
}
