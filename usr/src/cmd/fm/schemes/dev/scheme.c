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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/fmd_fmri.h>
#include <libdevinfo.h>
#include <alloca.h>
#include <string.h>

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
	char *devid = NULL;
	char *devpath = NULL;
	char *achas = NULL;
	char *adom = NULL;
	char *aprod = NULL;
	char *asrvr = NULL;
	char *ahost = NULL;
	int more_auth = 0;
	int err;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_DEV_SCHEME_VERSION)
		return (fmd_fmri_set_errno(EINVAL));

	/* Get authority, if present */
	err = nvlist_lookup_nvlist(nvl, FM_FMRI_AUTHORITY, &anvl);
	if (err != 0 && err != ENOENT)
		return (fmd_fmri_set_errno(err));

	/* Get devid, if present */
	err = nvlist_lookup_string(nvl, FM_FMRI_DEV_ID, &devid);
	if (err != 0 && err != ENOENT)
		return (fmd_fmri_set_errno(err));

	/* There must be a device path present */
	err = nvlist_lookup_string(nvl, FM_FMRI_DEV_PATH, &devpath);
	if (err != 0 || devpath == NULL)
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

	/* dev:// */
	buf_append(&size, buf, buflen, FM_FMRI_SCHEME_DEV, NULL, "://");

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

	/* device-id part */
	buf_append(&size, buf, buflen, devid, "/:" FM_FMRI_DEV_ID "=", NULL);

	/* device-path part */
	buf_append(&size, buf, buflen, devpath, "/", NULL);

	return (size);
}

/*
 * callback routine for di_walk_minor()
 */
struct walkinfo {
	int matched;
	const char *path;
	int len;
};

static int
dev_match(di_node_t node, void *arg)
{
	struct walkinfo *wip = (struct walkinfo *)arg;
	char *path = di_devfs_path(node);

	if (path != NULL && strncmp(path, wip->path, wip->len) == 0) {
		/*
		 * found the match we were looking for, set matched
		 * flag and terminate the walk.
		 */
		wip->matched = 1;
		di_devfs_path_free(path);
		return (DI_WALK_TERMINATE);
	}

	if (path != NULL)
		di_devfs_path_free(path);
	return (DI_WALK_CONTINUE);
}

/*
 * For now we only check for the presence of the device in the device
 * tree.  This is somewhat unsophisticated, because a device may have
 * been inserted into the same slot as the previous ASRU and we don't
 * know how to tell them apart yet.
 */
int
fmd_fmri_present(nvlist_t *nvl)
{
	di_node_t parent;
	uint8_t version;
	char *devpath = NULL;
	char *parentpath;
	char *cp;
	struct walkinfo walkinfo;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_DEV_SCHEME_VERSION ||
	    nvlist_lookup_string(nvl, FM_FMRI_DEV_PATH, &devpath) != 0)
		return (fmd_fmri_set_errno(EINVAL));

	if (devpath == NULL || (walkinfo.len = strlen(devpath)) == 0)
		return (fmd_fmri_set_errno(EINVAL));

	/* strip off last component of path */
	parentpath = alloca(walkinfo.len + 1);
	(void) strcpy(parentpath, devpath);
	if ((cp = strrchr(parentpath, '/')) == NULL)
		parentpath = "/";
	else
		*cp = '\0';

	/* if the result is an empty path, start walk at "/" */
	if (*parentpath == '\0')
		parentpath = "/";

	if ((parent = di_init(parentpath, DINFOSUBTREE)) == DI_NODE_NIL)
		return (errno == ENXIO ? 0 : -1);

	walkinfo.matched = 0;
	walkinfo.path = devpath;
	(void) di_walk_node(parent,
	    DI_WALK_SIBFIRST, (void *)&walkinfo, dev_match);
	di_fini(parent);

	return (walkinfo.matched);
}

/*
 *  We presently don't have a good indication of the usability of an
 *  ASRU in the dev scheme, so we'll assume its usable.
 */
int
fmd_fmri_unusable(nvlist_t *nvl)
{
	uint8_t version;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_DEV_SCHEME_VERSION)
		return (fmd_fmri_set_errno(EINVAL));

	return (0);
}
