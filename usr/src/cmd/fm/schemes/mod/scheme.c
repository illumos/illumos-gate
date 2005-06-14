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

/*
 * Maximum 32 bit integer is 2147483647, which is 10 digits.  A buffer
 * of 11 bytes can therefore contain the null-terminated ascii
 * representation of any integer module id.
 */
#define	MAXINTSTR	11

ssize_t
fmd_fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	nvlist_t *anvl = NULL;
	uint8_t version;
	ssize_t size = 0;
	int32_t modid;
	char *achas = NULL;
	char *adom = NULL;
	char *aprod = NULL;
	char *asrvr = NULL;
	char *ahost = NULL;
	char *modname = NULL;
	char numbuf[MAXINTSTR];
	int more_auth = 0;
	int err;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_MOD_SCHEME_VERSION)
		return (fmd_fmri_set_errno(EINVAL));

	/* Get authority, if present */
	err = nvlist_lookup_nvlist(nvl, FM_FMRI_AUTHORITY, &anvl);
	if (err != 0 && err != ENOENT)
		return (fmd_fmri_set_errno(err));

	/*
	 *  For brevity, we only include the module name and id
	 *  present in the FMRI in our output string.  The FMRI
	 *  also has data on the package containing the module.
	 */

	/* There must be a module name */
	err = nvlist_lookup_string(nvl, FM_FMRI_MOD_NAME, &modname);
	if (err != 0 || modname == NULL)
		return (fmd_fmri_set_errno(EINVAL));

	/* There must be a module id */
	err = nvlist_lookup_int32(nvl, FM_FMRI_MOD_ID, &modid);
	if (err != 0)
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

	/* mod:// */
	buf_append(&size, buf, buflen, FM_FMRI_SCHEME_MOD, NULL, "://");

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

	/* module parts */
	buf_append(&size, buf, buflen, modname, "/" FM_FMRI_MOD_NAME "=", "/");

	(void) snprintf(numbuf, MAXINTSTR, "%d", modid);
	buf_append(&size, buf, buflen, numbuf, FM_FMRI_MOD_ID "=", NULL);

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
