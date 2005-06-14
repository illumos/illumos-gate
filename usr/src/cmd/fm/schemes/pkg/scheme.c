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

#include <fm/fmd_fmri.h>

/*
 * buf_append -- Append str to buf (if it's non-NULL).  Place prepend
 * in buf in front of str and append behind it (if they're non-NULL).
 * Continue to update size even if we run out of space to actually
 * stuff characters in the buffer.
 */
static void
buf_append(ssize_t *sz, char *buf, size_t buflen, char *str,
    char *prepend, char *append)
{
	ssize_t left;

	if (str == NULL)
		return;

	if (buflen == 0 || (left = buflen - *sz) < 0)
		left = 0;

	if (buf != NULL && left != 0)
		buf += *sz;

	if (prepend == NULL && append == NULL)
		*sz += snprintf(buf, left, "%s", str);
	else if (append == NULL)
		*sz += snprintf(buf, left, "%s%s", prepend, str);
	else if (prepend == NULL)
		*sz += snprintf(buf, left, "%s%s", str, append);
	else
		*sz += snprintf(buf, left, "%s%s%s", prepend, str, append);
}

ssize_t
fmd_fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	nvlist_t *anvl = NULL;
	uint8_t version;
	ssize_t size = 0;
	char *pkgname = NULL;
	char *achas = NULL;
	char *adom = NULL;
	char *aprod = NULL;
	char *asrvr = NULL;
	char *ahost = NULL;
	int more_auth = 0;
	int err;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_PKG_SCHEME_VERSION)
		return (fmd_fmri_set_errno(EINVAL));

	/* Get authority, if present */
	err = nvlist_lookup_nvlist(nvl, FM_FMRI_AUTHORITY, &anvl);
	if (err != 0 && err != ENOENT)
		return (fmd_fmri_set_errno(err));

	/*
	 *  For brevity, we only include the pkgname and any authority
	 *  info present in the FMRI in our output string.  The FMRI
	 *  also has data on the package directory and version.
	 */
	err = nvlist_lookup_string(nvl, FM_FMRI_PKG_INST, &pkgname);
	if (err != 0 || pkgname == NULL)
		return (fmd_fmri_set_errno(EINVAL));

	if (anvl != NULL) {
		(void) nvlist_lookup_string(anvl,
		    FM_FMRI_AUTH_PRODUCT, &aprod);
		(void) nvlist_lookup_string(anvl,
		    FM_FMRI_AUTH_CHASSIS, &achas);
		(void) nvlist_lookup_string(anvl,
		    FM_FMRI_AUTH_DOMAIN, &adom);
		(void) nvlist_lookup_string(anvl,
		    FM_FMRI_AUTH_SERVER, &asrvr);
		(void) nvlist_lookup_string(anvl,
		    FM_FMRI_AUTH_HOST, &ahost);
		if (aprod != NULL)
			more_auth++;
		if (achas != NULL)
			more_auth++;
		if (adom != NULL)
			more_auth++;
		if (asrvr != NULL)
			more_auth++;
		if (ahost != NULL)
			more_auth++;
	}

	/* pkg:// */
	buf_append(&size, buf, buflen, FM_FMRI_SCHEME_PKG, NULL, "://");

	/* authority, if any */
	if (aprod != NULL)
		buf_append(&size, buf, buflen, aprod, FM_FMRI_AUTH_PRODUCT "=",
		    --more_auth > 0 ? "," : NULL);
	if (achas != NULL)
		buf_append(&size, buf, buflen, achas, FM_FMRI_AUTH_CHASSIS "=",
		    --more_auth > 0 ? "," : NULL);
	if (adom != NULL)
		buf_append(&size, buf, buflen, adom, FM_FMRI_AUTH_DOMAIN "=",
		    --more_auth > 0 ? "," : NULL);
	if (asrvr != NULL)
		buf_append(&size, buf, buflen, asrvr, FM_FMRI_AUTH_SERVER "=",
		    --more_auth > 0 ? "," : NULL);
	if (ahost != NULL)
		buf_append(&size, buf, buflen, ahost, FM_FMRI_AUTH_HOST "=",
		    NULL);

	/* pkg-name part */
	buf_append(&size, buf, buflen, pkgname, "/", NULL);

	return (size);
}

/*
 * fmd_fmri_present() is called by fmadm to determine if a faulty ASRU
 * is still present in the system.  In general we don't expect to get
 * ASRUs in this scheme, so it's unlikely this routine will get called.
 * In case it does, though, we just return true by default, as we have no
 * real way to look up the component in the system configuration.
 */
/*ARGSUSED*/
int
fmd_fmri_present(nvlist_t *nvl)
{
	return (1);
}

/*
 * fmd_fmri_unusable() is called by fmadm to determine if a faulty ASRU
 * is usable.  In general we don't expect to get ASRUs in this scheme,
 * so it's unlikely this routine will get called.  In case it does,
 * though, we just return false by default, as we have no real way to
 * find the component or determine the component's usability.
 */
/*ARGSUSED*/
int
fmd_fmri_unusable(nvlist_t *nvl)
{
	return (0);
}
