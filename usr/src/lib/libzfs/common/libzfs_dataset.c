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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <libdevinfo.h>
#include <libintl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <zone.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/mount.h>

#include <sys/spa.h>
#include <sys/zio.h>
#include <libzfs.h>

#include "zfs_namecheck.h"
#include "zfs_prop.h"
#include "libzfs_impl.h"

/*
 * Given a single type (not a mask of types), return the type in a human
 * readable form.
 */
const char *
zfs_type_to_name(zfs_type_t type)
{
	switch (type) {
	case ZFS_TYPE_FILESYSTEM:
		return (dgettext(TEXT_DOMAIN, "filesystem"));
	case ZFS_TYPE_SNAPSHOT:
		return (dgettext(TEXT_DOMAIN, "snapshot"));
	case ZFS_TYPE_VOLUME:
		return (dgettext(TEXT_DOMAIN, "volume"));
	}

	zfs_baderror(type);
	return (NULL);
}

/*
 * Given a path and mask of ZFS types, return a string describing this dataset.
 * This is used when we fail to open a dataset and we cannot get an exact type.
 * We guess what the type would have been based on the path and the mask of
 * acceptable types.
 */
static const char *
path_to_str(const char *path, int types)
{
	/*
	 * When given a single type, always report the exact type.
	 */
	if (types == ZFS_TYPE_SNAPSHOT)
		return (dgettext(TEXT_DOMAIN, "snapshot"));
	if (types == ZFS_TYPE_FILESYSTEM)
		return (dgettext(TEXT_DOMAIN, "filesystem"));
	if (types == ZFS_TYPE_VOLUME)
		return (dgettext(TEXT_DOMAIN, "volume"));

	/*
	 * The user is requesting more than one type of dataset.  If this is the
	 * case, consult the path itself.  If we're looking for a snapshot, and
	 * a '@' is found, then report it as "snapshot".  Otherwise, remove the
	 * snapshot attribute and try again.
	 */
	if (types & ZFS_TYPE_SNAPSHOT) {
		if (strchr(path, '@') != NULL)
			return (dgettext(TEXT_DOMAIN, "snapshot"));
		return (path_to_str(path, types & ~ZFS_TYPE_SNAPSHOT));
	}


	/*
	 * The user has requested either filesystems or volumes.
	 * We have no way of knowing a priori what type this would be, so always
	 * report it as "filesystem" or "volume", our two primitive types.
	 */
	if (types & ZFS_TYPE_FILESYSTEM)
		return (dgettext(TEXT_DOMAIN, "filesystem"));

	assert(types & ZFS_TYPE_VOLUME);
	return (dgettext(TEXT_DOMAIN, "volume"));
}

/*
 * Validate a ZFS path.  This is used even before trying to open the dataset, to
 * provide a more meaningful error message.  We place a more useful message in
 * 'buf' detailing exactly why the name was not valid.
 */
static int
zfs_validate_name(const char *path, int type, char *buf, size_t buflen)
{
	namecheck_err_t why;
	char what;

	if (dataset_namecheck(path, &why, &what) != 0) {
		if (buf != NULL) {
			switch (why) {
			case NAME_ERR_TOOLONG:
				(void) strlcpy(buf, dgettext(TEXT_DOMAIN,
				    "name is too long"), buflen);
				break;

			case NAME_ERR_LEADING_SLASH:
				(void) strlcpy(buf, dgettext(TEXT_DOMAIN,
				    "leading slash"), buflen);
				break;

			case NAME_ERR_EMPTY_COMPONENT:
				(void) strlcpy(buf, dgettext(TEXT_DOMAIN,
				    "empty component"), buflen);
				break;

			case NAME_ERR_TRAILING_SLASH:
				(void) strlcpy(buf, dgettext(TEXT_DOMAIN,
				    "trailing slash"), buflen);
				break;

			case NAME_ERR_INVALCHAR:
				(void) snprintf(buf, buflen,
				    dgettext(TEXT_DOMAIN, "invalid character "
				    "'%c'"), what);
				break;

			case NAME_ERR_MULTIPLE_AT:
				(void) strlcpy(buf, dgettext(TEXT_DOMAIN,
				    "multiple '@' delimiters"), buflen);
				break;
			}
		}

		return (0);
	}

	if (!(type & ZFS_TYPE_SNAPSHOT) && strchr(path, '@') != NULL) {
		if (buf != NULL)
			(void) strlcpy(buf,
			    dgettext(TEXT_DOMAIN,
			    "snapshot delimiter '@'"), buflen);
		return (0);
	}

	return (1);
}

int
zfs_name_valid(const char *name, zfs_type_t type)
{
	return (zfs_validate_name(name, type, NULL, NULL));
}

/*
 * Utility function to gather stats (objset and zpl) for the given object.
 */
static int
get_stats(zfs_handle_t *zhp)
{
	zfs_cmd_t zc = { 0 };

	(void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));

	zc.zc_config_src = (uint64_t)(uintptr_t)zfs_malloc(1024);
	zc.zc_config_src_size = 1024;

	while (ioctl(zfs_fd, ZFS_IOC_OBJSET_STATS, &zc) != 0) {
		if (errno == ENOMEM) {
			zc.zc_config_src = (uint64_t)(uintptr_t)
			    zfs_malloc(zc.zc_config_src_size);
		} else {
			free((void *)(uintptr_t)zc.zc_config_src);
			return (-1);
		}
	}

	bcopy(&zc.zc_objset_stats, &zhp->zfs_dmustats,
	    sizeof (zc.zc_objset_stats));

	verify(nvlist_unpack((void *)(uintptr_t)zc.zc_config_src,
	    zc.zc_config_src_size, &zhp->zfs_props, 0) == 0);

	zhp->zfs_volsize = zc.zc_volsize;
	zhp->zfs_volblocksize = zc.zc_volblocksize;

	return (0);
}

/*
 * Refresh the properties currently stored in the handle.
 */
void
zfs_refresh_properties(zfs_handle_t *zhp)
{
	(void) get_stats(zhp);
}

/*
 * Makes a handle from the given dataset name.  Used by zfs_open() and
 * zfs_iter_* to create child handles on the fly.
 */
zfs_handle_t *
make_dataset_handle(const char *path)
{
	zfs_handle_t *zhp = zfs_malloc(sizeof (zfs_handle_t));

	(void) strlcpy(zhp->zfs_name, path, sizeof (zhp->zfs_name));

	if (get_stats(zhp) != 0) {
		free(zhp);
		return (NULL);
	}

	/*
	 * We've managed to open the dataset and gather statistics.  Determine
	 * the high-level type.
	 */
	if (zhp->zfs_dmustats.dds_is_snapshot)
		zhp->zfs_type = ZFS_TYPE_SNAPSHOT;
	else if (zhp->zfs_dmustats.dds_type == DMU_OST_ZVOL)
		zhp->zfs_type = ZFS_TYPE_VOLUME;
	else if (zhp->zfs_dmustats.dds_type == DMU_OST_ZFS)
		zhp->zfs_type = ZFS_TYPE_FILESYSTEM;
	else
		/* we should never see any other dataset types */
		zfs_baderror(zhp->zfs_dmustats.dds_type);

	return (zhp);
}

/*
 * Opens the given snapshot, filesystem, or volume.   The 'types'
 * argument is a mask of acceptable types.  The function will print an
 * appropriate error message and return NULL if it can't be opened.
 */
zfs_handle_t *
zfs_open(const char *path, int types)
{
	zfs_handle_t *zhp;

	/*
	 * Validate the name before we even try to open it.  We don't care about
	 * the verbose invalid messages here; just report a generic error.
	 */
	if (!zfs_validate_name(path, types, NULL, 0)) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot open '%s': invalid %s name"), path,
		    path_to_str(path, types));
		return (NULL);
	}

	/*
	 * Try to get stats for the dataset, which will tell us if it exists.
	 */
	errno = 0;
	if ((zhp = make_dataset_handle(path)) == NULL) {
		switch (errno) {
		case ENOENT:
			/*
			 * The dataset doesn't exist.
			 */
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot open '%s': no such %s"), path,
			    path_to_str(path, types));
			break;

		case EBUSY:
			/*
			 * We were able to open the dataset but couldn't
			 * get the stats.
			 */
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot open '%s': %s is busy"), path,
			    path_to_str(path, types));
			break;

		default:
			zfs_baderror(errno);

		}
		return (NULL);
	}

	if (!(types & zhp->zfs_type)) {
		zfs_error(dgettext(TEXT_DOMAIN, "cannot open '%s': operation "
		    "not supported for %ss"), path,
		    zfs_type_to_name(zhp->zfs_type));
		free(zhp);
		return (NULL);
	}

	return (zhp);
}

/*
 * Release a ZFS handle.  Nothing to do but free the associated memory.
 */
void
zfs_close(zfs_handle_t *zhp)
{
	if (zhp->zfs_mntopts)
		free(zhp->zfs_mntopts);
	free(zhp);
}

struct {
	const char *name;
	uint64_t value;
} checksum_table[] = {
	{ "on",		ZIO_CHECKSUM_ON },
	{ "off",	ZIO_CHECKSUM_OFF },
	{ "fletcher2",	ZIO_CHECKSUM_FLETCHER_2 },
	{ "fletcher4",	ZIO_CHECKSUM_FLETCHER_4 },
	{ "sha256",	ZIO_CHECKSUM_SHA256 },
	{ NULL }
};

struct {
	const char *name;
	uint64_t value;
} compress_table[] = {
	{ "on",		ZIO_COMPRESS_ON },
	{ "off",	ZIO_COMPRESS_OFF },
	{ "lzjb",	ZIO_COMPRESS_LZJB },
	{ NULL }
};

struct {
	const char *name;
	uint64_t value;
} snapdir_table[] = {
	{ "hidden",	ZFS_SNAPDIR_HIDDEN },
	{ "visible",	ZFS_SNAPDIR_VISIBLE },
	{ NULL }
};

struct {
	const char *name;
	uint64_t value;
} acl_mode_table[] = {
	{ "discard",	DISCARD },
	{ "groupmask",	GROUPMASK },
	{ "passthrough", PASSTHROUGH },
	{ NULL }
};

struct {
	const char *name;
	uint64_t value;
} acl_inherit_table[] = {
	{ "discard",	DISCARD },
	{ "noallow",	NOALLOW },
	{ "secure",	SECURE },
	{ "passthrough", PASSTHROUGH },
	{ NULL }
};


/*
 * Given a numeric suffix, convert the value into a number of bits that the
 * resulting value must be shifted.
 */
static int
str2shift(const char *buf, char *reason, size_t len)
{
	const char *ends = "BKMGTPEZ";
	int i;

	if (buf[0] == '\0')
		return (0);
	for (i = 0; i < strlen(ends); i++) {
		if (toupper(buf[0]) == ends[i])
			break;
	}
	if (i == strlen(ends)) {
		(void) snprintf(reason, len, dgettext(TEXT_DOMAIN, "invalid "
		    "numeric suffix '%s'"), buf);
		return (-1);
	}

	/*
	 * We want to allow trailing 'b' characters for 'GB' or 'Mb'.  But don't
	 * allow 'BB' - that's just weird.
	 */
	if (buf[1] == '\0' || (toupper(buf[1]) == 'B' && buf[2] == '\0' &&
	    toupper(buf[0]) != 'B')) {
		return (10*i);
	}

	(void) snprintf(reason, len, dgettext(TEXT_DOMAIN, "invalid numeric "
	    "suffix '%s'"), buf);
	return (-1);
}

/*
 * Convert a string of the form '100G' into a real number.  Used when setting
 * properties or creating a volume.  'buf' is used to place an extended error
 * message for the caller to use.
 */
static int
nicestrtonum(const char *value, uint64_t *num, char *buf, size_t buflen)
{
	char *end;
	int shift;

	*num = 0;

	/* Check to see if this looks like a number.  */
	if ((value[0] < '0' || value[0] > '9') && value[0] != '.') {
		(void) strlcpy(buf, dgettext(TEXT_DOMAIN,
		    "must be a numeric value"), buflen);
		return (-1);
	}

	/* Rely on stroll() to process the numeric portion.  */
	errno = 0;
	*num = strtoll(value, &end, 10);

	/*
	 * Check for ERANGE, which indicates that the value is too large to fit
	 * in a 64-bit value.
	 */
	if (errno == ERANGE) {
		(void) strlcpy(buf, dgettext(TEXT_DOMAIN,
		    "value is too large"), buflen);
		return (-1);
	}

	/*
	 * If we have a decimal value, then do the computation with floating
	 * point arithmetic.  Otherwise, use standard arithmetic.
	 */
	if (*end == '.') {
		double fval = strtod(value, &end);

		if ((shift = str2shift(end, buf, buflen)) == -1)
			return (-1);

		fval *= pow(2, shift);

		if (fval > UINT64_MAX) {
			(void) strlcpy(buf, dgettext(TEXT_DOMAIN,
			    "value is too large"), buflen);
			return (-1);
		}

		*num = (uint64_t)fval;
	} else {
		if ((shift = str2shift(end, buf, buflen)) == -1)
			return (-1);

		/* Check for overflow */
		if (shift >= 64 || (*num << shift) >> shift != *num) {
			(void) strlcpy(buf, dgettext(TEXT_DOMAIN,
			    "value is too large"), buflen);
			return (-1);
		}

		*num <<= shift;
	}

	return (0);
}

int
zfs_nicestrtonum(const char *str, uint64_t *val)
{
	char buf[1];

	return (nicestrtonum(str, val, buf, sizeof (buf)));
}

/*
 * Given a property type and value, verify that the value is appropriate.  Used
 * by zfs_prop_set() and some libzfs consumers.
 */
int
zfs_prop_validate(zfs_prop_t prop, const char *value, uint64_t *intval)
{
	const char *propname = zfs_prop_to_name(prop);
	uint64_t number;
	char reason[64];
	int i;

	/*
	 * Check to see if this a read-only property.
	 */
	if (zfs_prop_readonly(prop)) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot set %s property: read-only property"), propname);
		return (-1);
	}

	/* See if the property value is too long */
	if (strlen(value) >= ZFS_MAXPROPLEN) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "bad %s value '%s': value is too long"), propname,
		    value);
		return (-1);
	}

	/* Perform basic checking based on property type */
	switch (zfs_prop_get_type(prop)) {
	case prop_type_boolean:
		if (strcmp(value, "on") == 0) {
			number = 1;
		} else if (strcmp(value, "off") == 0) {
			number = 0;
		} else {
			zfs_error(dgettext(TEXT_DOMAIN,
			    "bad %s value '%s': must be 'on' or 'off'"),
			    propname, value);
			return (-1);
		}
		break;

	case prop_type_number:
		/* treat 'none' as 0 */
		if (strcmp(value, "none") == 0) {
			number = 0;
			break;
		}

		if (nicestrtonum(value, &number, reason,
		    sizeof (reason)) != 0) {
			zfs_error(dgettext(TEXT_DOMAIN,
			    "bad %s value '%s': %s"), propname, value,
			    reason);
			return (-1);
		}

		/* don't allow 0 for quota, use 'none' instead */
		if (prop == ZFS_PROP_QUOTA && number == 0 &&
		    strcmp(value, "none") != 0) {
			zfs_error(dgettext(TEXT_DOMAIN,
			    "bad %s value '%s': use '%s=none' to disable"),
			    propname, value, propname);
			return (-1);
		}

		/* must be power of two within SPA_{MIN,MAX}BLOCKSIZE */
		if (prop == ZFS_PROP_RECORDSIZE ||
		    prop == ZFS_PROP_VOLBLOCKSIZE) {
			if (number < SPA_MINBLOCKSIZE ||
			    number > SPA_MAXBLOCKSIZE || !ISP2(number)) {
				zfs_error(dgettext(TEXT_DOMAIN,
				    "bad %s value '%s': "
				    "must be power of 2 from %u to %uk"),
				    propname, value,
				    (uint_t)SPA_MINBLOCKSIZE,
				    (uint_t)SPA_MAXBLOCKSIZE >> 10);
				return (-1);
			}
		}

		break;

	case prop_type_string:
	case prop_type_index:
		/*
		 * The two writable string values, 'mountpoint' and
		 * 'checksum' need special consideration.  The 'index' types are
		 * specified as strings by the user, but passed to the kernel as
		 * integers.
		 */
		switch (prop) {
		case ZFS_PROP_MOUNTPOINT:
			if (strcmp(value, ZFS_MOUNTPOINT_NONE) == 0 ||
			    strcmp(value, ZFS_MOUNTPOINT_LEGACY) == 0)
				break;

			if (value[0] != '/') {
				zfs_error(dgettext(TEXT_DOMAIN,
				    "bad %s value '%s': must be an absolute "
				    "path, 'none', or 'legacy'"),
				    propname, value);
				return (-1);
			}
			break;

		case ZFS_PROP_CHECKSUM:
			for (i = 0; checksum_table[i].name != NULL; i++) {
				if (strcmp(value, checksum_table[i].name)
				    == 0) {
					number = checksum_table[i].value;
					break;
				}
			}

			if (checksum_table[i].name == NULL) {
				zfs_error(dgettext(TEXT_DOMAIN,
				    "bad %s value '%s': must be 'on', 'off', "
				    "'fletcher2', 'fletcher4', or 'sha256'"),
				    propname, value);
				return (-1);
			}
			break;

		case ZFS_PROP_COMPRESSION:
			for (i = 0; compress_table[i].name != NULL; i++) {
				if (strcmp(value, compress_table[i].name)
				    == 0) {
					number = compress_table[i].value;
					break;
				}
			}

			if (compress_table[i].name == NULL) {
				zfs_error(dgettext(TEXT_DOMAIN,
				    "bad %s value '%s': must be 'on', 'off', "
				    "or 'lzjb'"),
				    propname, value);
				return (-1);
			}
			break;

		case ZFS_PROP_SNAPDIR:
			for (i = 0; snapdir_table[i].name != NULL; i++) {
				if (strcmp(value, snapdir_table[i].name) == 0) {
					number = snapdir_table[i].value;
					break;
				}
			}

			if (snapdir_table[i].name == NULL) {
				zfs_error(dgettext(TEXT_DOMAIN,
				    "bad %s value '%s': must be 'hidden' "
				    "or 'visible'"),
				    propname, value);
				return (-1);
			}
			break;

		case ZFS_PROP_ACLMODE:
			for (i = 0; acl_mode_table[i].name != NULL; i++) {
				if (strcmp(value, acl_mode_table[i].name)
				    == 0) {
					number = acl_mode_table[i].value;
					break;
				}
			}

			if (acl_mode_table[i].name == NULL) {
				zfs_error(dgettext(TEXT_DOMAIN,
				    "bad %s value '%s': must be 'discard', "
				    "'groupmask' or 'passthrough'"),
				    propname, value);
				return (-1);
			}
			break;

		case ZFS_PROP_ACLINHERIT:
			for (i = 0; acl_inherit_table[i].name != NULL; i++) {
				if (strcmp(value, acl_inherit_table[i].name)
				    == 0) {
					number = acl_inherit_table[i].value;
					break;
				}
			}

			if (acl_inherit_table[i].name == NULL) {
				zfs_error(dgettext(TEXT_DOMAIN,
				    "bad %s value '%s': must be 'discard', "
				    "'noallow', 'secure' or 'passthrough'"),
				    propname, value);
				return (-1);
			}
			break;

		case ZFS_PROP_SHARENFS:
			/*
			 * Nothing to do for 'sharenfs', this gets passed on to
			 * share(1M) verbatim.
			 */
			break;
		}
	}

	if (intval != NULL)
		*intval = number;

	return (0);
}

/*
 * Given a property name and value, set the property for the given dataset.
 */
int
zfs_prop_set(zfs_handle_t *zhp, zfs_prop_t prop, const char *propval)
{
	const char *propname = zfs_prop_to_name(prop);
	uint64_t number;
	zfs_cmd_t zc = { 0 };
	int ret;
	prop_changelist_t *cl;

	if (zfs_prop_validate(prop, propval, &number) != 0)
		return (-1);

	/*
	 * Check to see if the value applies to this type
	 */
	if (!zfs_prop_valid_for_type(prop, zhp->zfs_type)) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot set %s for '%s': property does not apply to %ss"),
		    propname, zhp->zfs_name, zfs_type_to_name(zhp->zfs_type));
		return (-1);
	}

	/*
	 * For the mountpoint and sharenfs properties, check if it can be set
	 * in a global/non-global zone based on the zoned property value:
	 *
	 *		global zone	    non-global zone
	 * -----------------------------------------------------
	 * zoned=on	mountpoint (no)	    mountpoint (yes)
	 *		sharenfs (no)	    sharenfs (no)
	 *
	 * zoned=off	mountpoint (yes)	N/A
	 *		sharenfs (yes)
	 */
	if (prop == ZFS_PROP_MOUNTPOINT || prop == ZFS_PROP_SHARENFS) {
		if (zfs_prop_get_int(zhp, ZFS_PROP_ZONED)) {
			if (getzoneid() == GLOBAL_ZONEID) {
				zfs_error(dgettext(TEXT_DOMAIN,
				    "cannot set %s for '%s': "
				    "dataset is used in a non-global zone"),
				    propname, zhp->zfs_name);
				return (-1);
			} else if (prop == ZFS_PROP_SHARENFS) {
				zfs_error(dgettext(TEXT_DOMAIN,
				    "cannot set %s for '%s': filesystems "
				    "cannot be shared in a non-global zone"),
				    propname, zhp->zfs_name);
				return (-1);
			}
		} else if (getzoneid() != GLOBAL_ZONEID) {
			/*
			 * If zoned property is 'off', this must be in
			 * a globle zone. If not, something is wrong.
			 */
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot set %s for '%s': dataset is "
			    "used in a non-global zone, but 'zoned' "
			    "property is not set"),
			    propname, zhp->zfs_name);
			return (-1);
		}
	}

	if ((cl = changelist_gather(zhp, prop, 0)) == NULL)
		return (-1);

	if (prop == ZFS_PROP_MOUNTPOINT && changelist_haszonedchild(cl)) {
		zfs_error(dgettext(TEXT_DOMAIN, "cannot set %s for '%s', "
			"child dataset with inherited mountpoint is used "
			"in a non-global zone"),
			propname, zhp->zfs_name);
		ret = -1;
		goto error;
	}

	if ((ret = changelist_prefix(cl)) != 0)
		goto error;

	/*
	 * Execute the corresponding ioctl() to set this property.
	 */
	(void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));

	switch (prop) {
	case ZFS_PROP_QUOTA:
		zc.zc_cookie = number;
		ret = ioctl(zfs_fd, ZFS_IOC_SET_QUOTA, &zc);
		break;
	case ZFS_PROP_RESERVATION:
		zc.zc_cookie = number;
		ret = ioctl(zfs_fd, ZFS_IOC_SET_RESERVATION, &zc);
		break;
	case ZFS_PROP_MOUNTPOINT:
	case ZFS_PROP_SHARENFS:
		/*
		 * These properties are passed down as real strings.
		 */
		(void) strlcpy(zc.zc_prop_name, propname,
		    sizeof (zc.zc_prop_name));
		(void) strlcpy(zc.zc_prop_value, propval,
		    sizeof (zc.zc_prop_value));
		zc.zc_intsz = 1;
		zc.zc_numints = strlen(propval) + 1;
		ret = ioctl(zfs_fd, ZFS_IOC_SET_PROP, &zc);
		break;
	case ZFS_PROP_VOLSIZE:
		zc.zc_volsize = number;
		ret = ioctl(zfs_fd, ZFS_IOC_SET_VOLSIZE, &zc);
		break;
	case ZFS_PROP_VOLBLOCKSIZE:
		zc.zc_volblocksize = number;
		ret = ioctl(zfs_fd, ZFS_IOC_SET_VOLBLOCKSIZE, &zc);
		break;
	default:
		(void) strlcpy(zc.zc_prop_name, propname,
		    sizeof (zc.zc_prop_name));
		/* LINTED - alignment */
		*(uint64_t *)zc.zc_prop_value = number;
		zc.zc_intsz = 8;
		zc.zc_numints = 1;
		ret = ioctl(zfs_fd, ZFS_IOC_SET_PROP, &zc);
		break;
	}

	if (ret != 0) {
		switch (errno) {

		case EPERM:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot set %s for '%s': permission "
			    "denied"), propname, zhp->zfs_name);
			break;

		case ENOENT:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot open '%s': no such %s"), zhp->zfs_name,
			    zfs_type_to_name(zhp->zfs_type));
			break;

		case ENOSPC:
			/*
			 * For quotas and reservations, ENOSPC indicates
			 * something different; setting a quota or reservation
			 * doesn't use any disk space.
			 */
			switch (prop) {
			case ZFS_PROP_QUOTA:
				zfs_error(dgettext(TEXT_DOMAIN, "cannot set %s "
				    "for '%s': size is less than current "
				    "used or reserved space"), propname,
				    zhp->zfs_name);
				break;

			case ZFS_PROP_RESERVATION:
				zfs_error(dgettext(TEXT_DOMAIN, "cannot set %s "
				    "for '%s': size is greater than available "
				    "space"), propname, zhp->zfs_name);
				break;

			default:
				zfs_error(dgettext(TEXT_DOMAIN,
				    "cannot set %s for '%s': out of space"),
				    propname, zhp->zfs_name);
				break;
			}
			break;

		case EBUSY:
			if (prop == ZFS_PROP_VOLBLOCKSIZE) {
				zfs_error(dgettext(TEXT_DOMAIN,
				    "cannot set %s for '%s': "
				    "volume already contains data"),
				    propname, zhp->zfs_name);
			} else {
				zfs_baderror(errno);
			}
			break;

		case EROFS:
			zfs_error(dgettext(TEXT_DOMAIN, "cannot set %s for "
			    "'%s': read only %s"), propname, zhp->zfs_name,
			    zfs_type_to_name(zhp->zfs_type));
			break;

		case EOVERFLOW:
			/*
			 * This platform can't address a volume this big.
			 */
#ifdef _ILP32
			if (prop == ZFS_PROP_VOLSIZE) {
				zfs_error(dgettext(TEXT_DOMAIN,
				    "cannot set %s for '%s': "
				    "max volume size is 1TB on 32-bit systems"),
				    propname, zhp->zfs_name);
				break;
			}
#endif
			zfs_baderror(errno);
		default:
			zfs_baderror(errno);
		}
	} else {
		/*
		 * Refresh the statistics so the new property value
		 * is reflected.
		 */
		if ((ret = changelist_postfix(cl)) != 0)
			goto error;

		(void) get_stats(zhp);
	}

error:
	changelist_free(cl);
	return (ret);
}

/*
 * Given a property, inherit the value from the parent dataset.
 */
int
zfs_prop_inherit(zfs_handle_t *zhp, zfs_prop_t prop)
{
	const char *propname = zfs_prop_to_name(prop);
	zfs_cmd_t zc = { 0 };
	int ret;
	prop_changelist_t *cl;

	/*
	 * Verify that this property is inheritable.
	 */
	if (zfs_prop_readonly(prop)) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot inherit %s for '%s': property is read-only"),
		    propname, zhp->zfs_name);
		return (-1);
	}

	if (!zfs_prop_inheritable(prop)) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot inherit %s for '%s': property is not inheritable"),
		    propname, zhp->zfs_name);
		return (-1);
	}

	/*
	 * Check to see if the value applies to this type
	 */
	if (!zfs_prop_valid_for_type(prop, zhp->zfs_type)) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot inherit %s for '%s': property does "
		    "not apply to %ss"), propname, zhp->zfs_name,
		    zfs_type_to_name(zhp->zfs_type));
		return (-1);
	}

	(void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));
	(void) strlcpy(zc.zc_prop_name, propname, sizeof (zc.zc_prop_name));

	if (prop == ZFS_PROP_MOUNTPOINT && getzoneid() == GLOBAL_ZONEID &&
	    zfs_prop_get_int(zhp, ZFS_PROP_ZONED)) {
		zfs_error(dgettext(TEXT_DOMAIN, "cannot inherit %s for '%s', "
		    "dataset is used in a non-global zone"), propname,
		    zhp->zfs_name);
		return (-1);
	}

	/*
	 * Determine datasets which will be affected by this change, if any.
	 */
	if ((cl = changelist_gather(zhp, prop, 0)) == NULL)
		return (-1);

	if (prop == ZFS_PROP_MOUNTPOINT && changelist_haszonedchild(cl)) {
		zfs_error(dgettext(TEXT_DOMAIN, "cannot inherit %s for '%s', "
			"child dataset with inherited mountpoint is "
			"used in a non-global zone"),
			propname, zhp->zfs_name);
		ret = -1;
		goto error;
	}

	if ((ret = changelist_prefix(cl)) != 0)
		goto error;

	zc.zc_numints = 0;

	if ((ret = ioctl(zfs_fd, ZFS_IOC_SET_PROP, &zc)) != 0) {
		switch (errno) {
		case EPERM:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot inherit %s for '%s': permission "
			    "denied"), propname, zhp->zfs_name);
			break;
		case ENOENT:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot open '%s': no such %s"), zhp->zfs_name,
			    zfs_type_to_name(zhp->zfs_type));
			break;
		case ENOSPC:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot inherit %s for '%s': "
			    "out of space"), propname, zhp->zfs_name);
			break;
		default:
			zfs_baderror(errno);
		}

	} else {

		if ((ret = changelist_postfix(cl)) != 0)
			goto error;

		/*
		 * Refresh the statistics so the new property is reflected.
		 */
		(void) get_stats(zhp);
	}


error:
	changelist_free(cl);
	return (ret);
}

static void
nicebool(int value, char *buf, size_t buflen)
{
	if (value)
		(void) strlcpy(buf, "on", buflen);
	else
		(void) strlcpy(buf, "off", buflen);
}

/*
 * True DSL properties are stored in an nvlist.  The following two functions
 * extract them appropriately.
 */
static uint64_t
getprop_uint64(zfs_handle_t *zhp, zfs_prop_t prop, char **source)
{
	nvlist_t *nv;
	uint64_t value;

	if (nvlist_lookup_nvlist(zhp->zfs_props,
	    zfs_prop_to_name(prop), &nv) == 0) {
		verify(nvlist_lookup_uint64(nv, ZFS_PROP_VALUE, &value) == 0);
		verify(nvlist_lookup_string(nv, ZFS_PROP_SOURCE, source) == 0);
	} else {
		value = zfs_prop_default_numeric(prop);
		*source = "";
	}

	return (value);
}

static char *
getprop_string(zfs_handle_t *zhp, zfs_prop_t prop, char **source)
{
	nvlist_t *nv;
	char *value;

	if (nvlist_lookup_nvlist(zhp->zfs_props,
	    zfs_prop_to_name(prop), &nv) == 0) {
		verify(nvlist_lookup_string(nv, ZFS_PROP_VALUE, &value) == 0);
		verify(nvlist_lookup_string(nv, ZFS_PROP_SOURCE, source) == 0);
	} else {
		if ((value = (char *)zfs_prop_default_string(prop)) == NULL)
			value = "";
		*source = "";
	}

	return (value);
}

/*
 * Internal function for getting a numeric property.  Both zfs_prop_get() and
 * zfs_prop_get_int() are built using this interface.
 *
 * Certain properties can be overridden using 'mount -o'.  In this case, scan
 * the contents of the /etc/mnttab entry, searching for the appropriate options.
 * If they differ from the on-disk values, report the current values and mark
 * the source "temporary".
 */
static uint64_t
get_numeric_property(zfs_handle_t *zhp, zfs_prop_t prop, zfs_source_t *src,
    char **source)
{
	uint64_t val;
	struct mnttab mnt;

	*source = NULL;

	if (zhp->zfs_mntopts == NULL)
		mnt.mnt_mntopts = "";
	else
		mnt.mnt_mntopts = zhp->zfs_mntopts;

	switch (prop) {
	case ZFS_PROP_ATIME:
		val = getprop_uint64(zhp, prop, source);

		if (hasmntopt(&mnt, MNTOPT_ATIME) && !val) {
			val = TRUE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		} else if (hasmntopt(&mnt, MNTOPT_NOATIME) && val) {
			val = FALSE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		}
		return (val);

	case ZFS_PROP_AVAILABLE:
		return (zhp->zfs_dmustats.dds_available);

	case ZFS_PROP_DEVICES:
		val = getprop_uint64(zhp, prop, source);

		if (hasmntopt(&mnt, MNTOPT_DEVICES) && !val) {
			val = TRUE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		} else if (hasmntopt(&mnt, MNTOPT_NODEVICES) && val) {
			val = FALSE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		}
		return (val);

	case ZFS_PROP_EXEC:
		val = getprop_uint64(zhp, prop, source);

		if (hasmntopt(&mnt, MNTOPT_EXEC) && !val) {
			val = TRUE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		} else if (hasmntopt(&mnt, MNTOPT_NOEXEC) && val) {
			val = FALSE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		}
		return (val);

	case ZFS_PROP_RECORDSIZE:
	case ZFS_PROP_COMPRESSION:
	case ZFS_PROP_ZONED:
		val = getprop_uint64(zhp, prop, source);
		return (val);

	case ZFS_PROP_READONLY:
		val = getprop_uint64(zhp, prop, source);

		if (hasmntopt(&mnt, MNTOPT_RO) && !val) {
			val = TRUE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		} else if (hasmntopt(&mnt, MNTOPT_RW) && val) {
			val = FALSE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		}
		return (val);

	case ZFS_PROP_QUOTA:
		if (zhp->zfs_dmustats.dds_quota == 0)
			*source = "";	/* default */
		else
			*source = zhp->zfs_name;
		return (zhp->zfs_dmustats.dds_quota);

	case ZFS_PROP_RESERVATION:
		if (zhp->zfs_dmustats.dds_reserved == 0)
			*source = "";	/* default */
		else
			*source = zhp->zfs_name;
		return (zhp->zfs_dmustats.dds_reserved);

	case ZFS_PROP_COMPRESSRATIO:
		/*
		 * Using physical space and logical space, calculate the
		 * compression ratio.  We return the number as a multiple of
		 * 100, so '2.5x' would be returned as 250.
		 */
		if (zhp->zfs_dmustats.dds_compressed_bytes == 0)
			return (100ULL);
		else
			return (zhp->zfs_dmustats.dds_uncompressed_bytes * 100 /
			    zhp->zfs_dmustats.dds_compressed_bytes);

	case ZFS_PROP_REFERENCED:
		/*
		 * 'referenced' refers to the amount of physical space
		 * referenced (possibly shared) by this object.
		 */
		return (zhp->zfs_dmustats.dds_space_refd);

	case ZFS_PROP_SETUID:
		val = getprop_uint64(zhp, prop, source);

		if (hasmntopt(&mnt, MNTOPT_SETUID) && !val) {
			val = TRUE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		} else if (hasmntopt(&mnt, MNTOPT_NOSETUID) && val) {
			val = FALSE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		}
		return (val);

	case ZFS_PROP_VOLSIZE:
		return (zhp->zfs_volsize);

	case ZFS_PROP_VOLBLOCKSIZE:
		return (zhp->zfs_volblocksize);

	case ZFS_PROP_USED:
		return (zhp->zfs_dmustats.dds_space_used);

	case ZFS_PROP_CREATETXG:
		return (zhp->zfs_dmustats.dds_creation_txg);

	case ZFS_PROP_MOUNTED:
		/*
		 * Unlike other properties, we defer calculation of 'MOUNTED'
		 * until actually requested.  This is because the getmntany()
		 * call can be extremely expensive on systems with a large
		 * number of filesystems, and the property isn't needed in
		 * normal use cases.
		 */
		if (zhp->zfs_mntopts == NULL) {
			struct mnttab search = { 0 }, entry;

			search.mnt_special = (char *)zhp->zfs_name;
			search.mnt_fstype = MNTTYPE_ZFS;
			rewind(mnttab_file);

			if (getmntany(mnttab_file, &entry, &search) == 0)
				zhp->zfs_mntopts =
				    zfs_strdup(entry.mnt_mntopts);
		}
		return (zhp->zfs_mntopts != NULL);

	default:
		zfs_baderror(EINVAL);
	}

	return (0);
}

/*
 * Calculate the source type, given the raw source string.
 */
static void
get_source(zfs_handle_t *zhp, zfs_source_t *srctype, char *source,
    char *statbuf, size_t statlen)
{
	if (statbuf == NULL || *srctype == ZFS_SRC_TEMPORARY)
		return;

	if (source == NULL) {
		*srctype = ZFS_SRC_NONE;
	} else if (source[0] == '\0') {
		*srctype = ZFS_SRC_DEFAULT;
	} else {
		if (strcmp(source, zhp->zfs_name) == 0) {
			*srctype = ZFS_SRC_LOCAL;
		} else {
			(void) strlcpy(statbuf, source, statlen);
			*srctype = ZFS_SRC_INHERITED;
		}
	}

}

/*
 * Retrieve a property from the given object.  If 'literal' is specified, then
 * numbers are left as exact values.  Otherwise, numbers are converted to a
 * human-readable form.
 *
 * Returns 0 on success, or -1 on error.
 */
int
zfs_prop_get(zfs_handle_t *zhp, zfs_prop_t prop, char *propbuf, size_t proplen,
    zfs_source_t *src, char *statbuf, size_t statlen, int literal)
{
	char *source = NULL;
	uint64_t val;
	char *str;
	int i;
	const char *root;

	/*
	 * Check to see if this property applies to our object
	 */
	if (!zfs_prop_valid_for_type(prop, zhp->zfs_type))
		return (-1);

	if (src)
		*src = ZFS_SRC_NONE;

	switch (prop) {
	case ZFS_PROP_ATIME:
	case ZFS_PROP_READONLY:
	case ZFS_PROP_SETUID:
	case ZFS_PROP_ZONED:
	case ZFS_PROP_DEVICES:
	case ZFS_PROP_EXEC:
		/*
		 * Basic boolean values are built on top of
		 * get_numeric_property().
		 */
		nicebool(get_numeric_property(zhp, prop, src, &source),
		    propbuf, proplen);

		break;

	case ZFS_PROP_AVAILABLE:
	case ZFS_PROP_RECORDSIZE:
	case ZFS_PROP_CREATETXG:
	case ZFS_PROP_REFERENCED:
	case ZFS_PROP_USED:
	case ZFS_PROP_VOLSIZE:
	case ZFS_PROP_VOLBLOCKSIZE:
		/*
		 * Basic numeric values are built on top of
		 * get_numeric_property().
		 */
		val = get_numeric_property(zhp, prop, src, &source);
		if (literal)
			(void) snprintf(propbuf, proplen, "%llu", val);
		else
			zfs_nicenum(val, propbuf, proplen);
		break;

	case ZFS_PROP_COMPRESSION:
		val = getprop_uint64(zhp, prop, &source);
		for (i = 0; compress_table[i].name != NULL; i++) {
			if (compress_table[i].value == val)
				break;
		}
		assert(compress_table[i].name != NULL);
		(void) strlcpy(propbuf, compress_table[i].name, proplen);
		break;

	case ZFS_PROP_CHECKSUM:
		val = getprop_uint64(zhp, prop, &source);
		for (i = 0; checksum_table[i].name != NULL; i++) {
			if (checksum_table[i].value == val)
				break;
		}
		assert(checksum_table[i].name != NULL);
		(void) strlcpy(propbuf, checksum_table[i].name, proplen);
		break;

	case ZFS_PROP_SNAPDIR:
		val = getprop_uint64(zhp, prop, &source);
		for (i = 0; snapdir_table[i].name != NULL; i++) {
			if (snapdir_table[i].value == val)
				break;
		}
		assert(snapdir_table[i].name != NULL);
		(void) strlcpy(propbuf, snapdir_table[i].name, proplen);
		break;

	case ZFS_PROP_ACLMODE:
		val = getprop_uint64(zhp, prop, &source);
		for (i = 0; acl_mode_table[i].name != NULL; i++) {
			if (acl_mode_table[i].value == val)
				break;
		}
		assert(acl_mode_table[i].name != NULL);
		(void) strlcpy(propbuf, acl_mode_table[i].name, proplen);
		break;

	case ZFS_PROP_ACLINHERIT:
		val = getprop_uint64(zhp, prop, &source);
		for (i = 0; acl_inherit_table[i].name != NULL; i++) {
			if (acl_inherit_table[i].value == val)
				break;
		}
		assert(acl_inherit_table[i].name != NULL);
		(void) strlcpy(propbuf, acl_inherit_table[i].name, proplen);
		break;

	case ZFS_PROP_CREATION:
		/*
		 * 'creation' is a time_t stored in the statistics.  We convert
		 * this into a string unless 'literal' is specified.
		 */
		{
			time_t time = (time_t)
			    zhp->zfs_dmustats.dds_creation_time;
			struct tm t;

			if (literal ||
			    localtime_r(&time, &t) == NULL ||
			    strftime(propbuf, proplen, "%a %b %e %k:%M %Y",
			    &t) == 0)
				(void) snprintf(propbuf, proplen, "%llu",
				    zhp->zfs_dmustats.dds_creation_time);
		}
		break;

	case ZFS_PROP_MOUNTPOINT:
		/*
		 * Getting the precise mountpoint can be tricky.
		 *
		 *  - for 'none' or 'legacy', return those values.
		 *  - for default mountpoints, construct it as /zfs/<dataset>
		 *  - for inherited mountpoints, we want to take everything
		 *    after our ancestor and append it to the inherited value.
		 *
		 * If the pool has an alternate root, we want to prepend that
		 * root to any values we return.
		 */
		root = zhp->zfs_dmustats.dds_altroot;
		str = getprop_string(zhp, prop, &source);

		if (str[0] == '\0') {
			(void) snprintf(propbuf, proplen, "%s/zfs/%s",
			    root, zhp->zfs_name);
		} else if (str[0] == '/') {
			const char *relpath = zhp->zfs_name + strlen(source);

			if (relpath[0] == '/')
				relpath++;
			if (str[1] == '\0')
				str++;

			if (relpath[0] == '\0')
				(void) snprintf(propbuf, proplen, "%s%s",
				    root, str);
			else
				(void) snprintf(propbuf, proplen, "%s%s%s%s",
				    root, str, relpath[0] == '@' ? "" : "/",
				    relpath);
		} else {
			/* 'legacy' or 'none' */
			(void) strlcpy(propbuf, str, proplen);
		}

		break;

	case ZFS_PROP_SHARENFS:
		(void) strlcpy(propbuf, getprop_string(zhp, prop, &source),
		    proplen);
		break;

	case ZFS_PROP_ORIGIN:
		(void) strlcpy(propbuf, getprop_string(zhp, prop, &source),
		    proplen);
		/*
		 * If there is no parent at all, return failure to indicate that
		 * it doesn't apply to this dataset.
		 */
		if (propbuf[0] == '\0')
			return (-1);
		break;

	case ZFS_PROP_QUOTA:
	case ZFS_PROP_RESERVATION:
		val = get_numeric_property(zhp, prop, src, &source);

		/*
		 * If quota or reservation is 0, we translate this into 'none'
		 * (unless literal is set), and indicate that it's the default
		 * value.  Otherwise, we print the number nicely and indicate
		 * that its set locally.
		 */
		if (val == 0) {
			if (literal)
				(void) strlcpy(propbuf, "0", proplen);
			else
				(void) strlcpy(propbuf, "none", proplen);
		} else {
			if (literal)
				(void) snprintf(propbuf, proplen, "%llu", val);
			else
				zfs_nicenum(val, propbuf, proplen);
		}
		break;

	case ZFS_PROP_COMPRESSRATIO:
		val = get_numeric_property(zhp, prop, src, &source);
		(void) snprintf(propbuf, proplen, "%lld.%02lldx", val / 100,
		    val % 100);
		break;

	case ZFS_PROP_TYPE:
		switch (zhp->zfs_type) {
		case ZFS_TYPE_FILESYSTEM:
			str = "filesystem";
			break;
		case ZFS_TYPE_VOLUME:
			str = "volume";
			break;
		case ZFS_TYPE_SNAPSHOT:
			str = "snapshot";
			break;
		default:
			zfs_baderror(zhp->zfs_type);
		}
		(void) snprintf(propbuf, proplen, "%s", str);
		break;

	case ZFS_PROP_MOUNTED:
		/*
		 * The 'mounted' property is a pseudo-property that described
		 * whether the filesystem is currently mounted.  Even though
		 * it's a boolean value, the typical values of "on" and "off"
		 * don't make sense, so we translate to "yes" and "no".
		 */
		if (get_numeric_property(zhp, ZFS_PROP_MOUNTED, src, &source))
			(void) strlcpy(propbuf, "yes", proplen);
		else
			(void) strlcpy(propbuf, "no", proplen);
		break;

	case ZFS_PROP_NAME:
		/*
		 * The 'name' property is a pseudo-property derived from the
		 * dataset name.  It is presented as a real property to simplify
		 * consumers.
		 */
		(void) strlcpy(propbuf, zhp->zfs_name, proplen);
		break;

	default:
		zfs_baderror(EINVAL);
	}

	get_source(zhp, src, source, statbuf, statlen);

	return (0);
}

/*
 * Utility function to get the given numeric property.  Does no validation that
 * the given property is the appropriate type; should only be used with
 * hard-coded property types.
 */
uint64_t
zfs_prop_get_int(zfs_handle_t *zhp, zfs_prop_t prop)
{
	char *source;
	zfs_source_t sourcetype = ZFS_SRC_NONE;

	return (get_numeric_property(zhp, prop, &sourcetype, &source));
}

/*
 * Similar to zfs_prop_get(), but returns the value as an integer.
 */
int
zfs_prop_get_numeric(zfs_handle_t *zhp, zfs_prop_t prop, uint64_t *value,
    zfs_source_t *src, char *statbuf, size_t statlen)
{
	char *source;

	/*
	 * Check to see if this property applies to our object
	 */
	if (!zfs_prop_valid_for_type(prop, zhp->zfs_type))
		return (-1);

	if (src)
		*src = ZFS_SRC_NONE;

	*value = get_numeric_property(zhp, prop, src, &source);

	get_source(zhp, src, source, statbuf, statlen);

	return (0);
}

/*
 * Returns the name of the given zfs handle.
 */
const char *
zfs_get_name(const zfs_handle_t *zhp)
{
	return (zhp->zfs_name);
}

/*
 * Returns the type of the given zfs handle.
 */
zfs_type_t
zfs_get_type(const zfs_handle_t *zhp)
{
	return (zhp->zfs_type);
}

/*
 * Iterate over all child filesystems
 */
int
zfs_iter_filesystems(zfs_handle_t *zhp, zfs_iter_f func, void *data)
{
	zfs_cmd_t zc = { 0 };
	zfs_handle_t *nzhp;
	int ret;

	for ((void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));
	    ioctl(zfs_fd, ZFS_IOC_DATASET_LIST_NEXT, &zc) == 0;
	    (void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name))) {
		/*
		 * Ignore private dataset names.
		 */
		if (dataset_name_hidden(zc.zc_name))
			continue;

		/*
		 * Silently ignore errors, as the only plausible explanation is
		 * that the pool has since been removed.
		 */
		if ((nzhp = make_dataset_handle(zc.zc_name)) == NULL)
			continue;

		if ((ret = func(nzhp, data)) != 0)
			return (ret);
	}

	/*
	 * An errno value of ESRCH indicates normal completion.  If ENOENT is
	 * returned, then the underlying dataset has been removed since we
	 * obtained the handle.
	 */
	if (errno != ESRCH && errno != ENOENT)
		zfs_baderror(errno);

	return (0);
}

/*
 * Iterate over all snapshots
 */
int
zfs_iter_snapshots(zfs_handle_t *zhp, zfs_iter_f func, void *data)
{
	zfs_cmd_t zc = { 0 };
	zfs_handle_t *nzhp;
	int ret;

	for ((void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));
	    ioctl(zfs_fd, ZFS_IOC_SNAPSHOT_LIST_NEXT, &zc) == 0;
	    (void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name))) {

		if ((nzhp = make_dataset_handle(zc.zc_name)) == NULL)
			continue;

		if ((ret = func(nzhp, data)) != 0)
			return (ret);
	}

	/*
	 * An errno value of ESRCH indicates normal completion.  If ENOENT is
	 * returned, then the underlying dataset has been removed since we
	 * obtained the handle.  Silently ignore this case, and return success.
	 */
	if (errno != ESRCH && errno != ENOENT)
		zfs_baderror(errno);

	return (0);
}

/*
 * Iterate over all children, snapshots and filesystems
 */
int
zfs_iter_children(zfs_handle_t *zhp, zfs_iter_f func, void *data)
{
	int ret;

	if ((ret = zfs_iter_filesystems(zhp, func, data)) != 0)
		return (ret);

	return (zfs_iter_snapshots(zhp, func, data));
}

/*
 * Given a complete name, return just the portion that refers to the parent.
 * Can return NULL if this is a pool.
 */
static int
parent_name(const char *path, char *buf, size_t buflen)
{
	char *loc;

	if ((loc = strrchr(path, '/')) == NULL)
		return (-1);

	(void) strncpy(buf, path, MIN(buflen, loc - path));
	buf[loc - path] = '\0';

	return (0);
}

/*
 * Checks to make sure that the given path has a parent, and that it exists.
 */
static int
check_parents(const char *path, zfs_type_t type)
{
	zfs_cmd_t zc = { 0 };
	char parent[ZFS_MAXNAMELEN];
	char *slash;
	zfs_handle_t *zhp;

	/* get parent, and check to see if this is just a pool */
	if (parent_name(path, parent, sizeof (parent)) != 0) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot create '%s': missing dataset name"),
		    path, zfs_type_to_name(type));
		zfs_error(dgettext(TEXT_DOMAIN,
		    "use 'zpool create' to create a storage pool"));
		return (-1);
	}

	/* check to see if the pool exists */
	if ((slash = strchr(parent, '/')) == NULL)
		slash = parent + strlen(parent);
	(void) strncpy(zc.zc_name, parent, slash - parent);
	zc.zc_name[slash - parent] = '\0';
	if (ioctl(zfs_fd, ZFS_IOC_OBJSET_STATS, &zc) != 0 &&
	    errno == ENOENT) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot create '%s': no such pool '%s'"), path, zc.zc_name);
		return (-1);
	}

	/* check to see if the parent dataset exists */
	if ((zhp = make_dataset_handle(parent)) == NULL) {
		switch (errno) {
		case ENOENT:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot create '%s': parent does not exist"), path);
			return (-1);

		default:
			zfs_baderror(errno);
		}
	}

	/* we are in a non-global zone, but parent is in the global zone */
	if (getzoneid() != GLOBAL_ZONEID &&
	    !zfs_prop_get_int(zhp, ZFS_PROP_ZONED)) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot create '%s': permission denied"), path);
		zfs_close(zhp);
		return (-1);
	}

	/* make sure parent is a filesystem */
	if (zfs_get_type(zhp) != ZFS_TYPE_FILESYSTEM) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot create '%s': parent is not a filesystem"),
		    path);
		zfs_close(zhp);
		return (-1);
	}

	zfs_close(zhp);
	return (0);
}

/*
 * Create a new filesystem or volume.  'sizestr' and 'blocksizestr' are used
 * only for volumes, and indicate the size and blocksize of the volume.
 */
int
zfs_create(const char *path, zfs_type_t type,
	const char *sizestr, const char *blocksizestr)
{
	char reason[64];
	zfs_cmd_t zc = { 0 };
	int ret;
	uint64_t size = 0;
	uint64_t blocksize = zfs_prop_default_numeric(ZFS_PROP_VOLBLOCKSIZE);

	/* convert sizestr into integer size */
	if (sizestr != NULL && nicestrtonum(sizestr, &size,
	    reason, sizeof (reason)) != 0) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "bad volume size '%s': %s"), sizestr, reason);
		return (-1);
	}

	/* convert blocksizestr into integer blocksize */
	if (blocksizestr != NULL && nicestrtonum(blocksizestr, &blocksize,
	    reason, sizeof (reason)) != 0) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "bad volume blocksize '%s': %s"), blocksizestr, reason);
		return (-1);
	}

	/* validate the path, taking care to note the extended error message */
	if (!zfs_validate_name(path, type, reason, sizeof (reason))) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot create '%s': %s in %s name"), path, reason,
		    zfs_type_to_name(type));
		if (strstr(reason, "snapshot") != NULL)
			zfs_error(dgettext(TEXT_DOMAIN,
			    "use 'zfs snapshot' to create a snapshot"));
		return (-1);
	}

	/* validate parents exist */
	if (check_parents(path, type) != 0)
		return (-1);

	/*
	 * The failure modes when creating a dataset of a different type over
	 * one that already exists is a little strange.  In particular, if you
	 * try to create a dataset on top of an existing dataset, the ioctl()
	 * will return ENOENT, not EEXIST.  To prevent this from happening, we
	 * first try to see if the dataset exists.
	 */
	(void) strlcpy(zc.zc_name, path, sizeof (zc.zc_name));
	if (ioctl(zfs_fd, ZFS_IOC_OBJSET_STATS, &zc) == 0) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot create '%s': dataset exists"), path);
		return (-1);
	}

	if (type == ZFS_TYPE_VOLUME)
		zc.zc_objset_type = DMU_OST_ZVOL;
	else
		zc.zc_objset_type = DMU_OST_ZFS;

	if (type == ZFS_TYPE_VOLUME) {
		/*
		 * If we are creating a volume, the size and block size must
		 * satisfy a few restraints.  First, the blocksize must be a
		 * valid block size between SPA_{MIN,MAX}BLOCKSIZE.  Second, the
		 * volsize must be a multiple of the block size, and cannot be
		 * zero.
		 */
		if (size == 0) {
			zfs_error(dgettext(TEXT_DOMAIN,
			    "bad volume size '%s': cannot be zero"), sizestr);
			return (-1);
		}

		if (blocksize < SPA_MINBLOCKSIZE ||
		    blocksize > SPA_MAXBLOCKSIZE || !ISP2(blocksize)) {
			zfs_error(dgettext(TEXT_DOMAIN,
			    "bad volume block size '%s': "
			    "must be power of 2 from %u to %uk"),
			    blocksizestr,
			    (uint_t)SPA_MINBLOCKSIZE,
			    (uint_t)SPA_MAXBLOCKSIZE >> 10);
			return (-1);
		}

		if (size % blocksize != 0) {
			char buf[64];
			zfs_nicenum(blocksize, buf, sizeof (buf));
			zfs_error(dgettext(TEXT_DOMAIN,
			    "bad volume size '%s': "
			    "must be multiple of volume block size (%s)"),
			    sizestr, buf);
			return (-1);
		}

		zc.zc_volsize = size;
		zc.zc_volblocksize = blocksize;
	}

	/* create the dataset */
	ret = ioctl(zfs_fd, ZFS_IOC_CREATE, &zc);

	if (ret == 0 && type == ZFS_TYPE_VOLUME)
		ret = zvol_create_link(path);

	/* check for failure */
	if (ret != 0) {
		char parent[ZFS_MAXNAMELEN];
		(void) parent_name(path, parent, sizeof (parent));

		switch (errno) {
		case ENOENT:
			/*
			 * The parent dataset has been deleted since our
			 * previous check.
			 */
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot create '%s': no such parent '%s'"),
			    path, parent);
			break;

		case EPERM:
			/*
			 * The user doesn't have permission to create a new
			 * dataset here.
			 */
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot create '%s': permission denied"), path);
			break;

		case EDQUOT:
		case ENOSPC:
			/*
			 * The parent dataset does not have enough free space
			 * to create a new dataset.
			 */
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot create '%s': not enough space in '%s'"),
			    path, parent);
			break;

		case EEXIST:
			/*
			 * The target dataset already exists.  We should have
			 * caught this above, but there may be some unexplained
			 * race condition.
			 */
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot create '%s': dataset exists"), path);
			break;

		case EINVAL:
			/*
			 * The target dataset does not support children.
			 */
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot create '%s': children unsupported in '%s'"),
			    path, parent);
			break;

		case EDOM:
			zfs_error(dgettext(TEXT_DOMAIN, "bad %s value '%s': "
			    "must be power of 2 from %u to %uk"),
			    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE),
			    blocksizestr ? blocksizestr : "<unknown>",
			    (uint_t)SPA_MINBLOCKSIZE,
			    (uint_t)SPA_MAXBLOCKSIZE >> 10);
			break;
#ifdef _ILP32
		case EOVERFLOW:
			/*
			 * This platform can't address a volume this big.
			 */
			if (type == ZFS_TYPE_VOLUME) {
				zfs_error(dgettext(TEXT_DOMAIN,
				    "cannot create '%s': "
				    "max volume size is 1TB on 32-bit systems"),
				    path);
				break;
			}
#endif

		default:
			zfs_baderror(errno);
		}

		return (-1);
	}

	return (0);
}

/*
 * Destroys the given dataset.  The caller must make sure that the filesystem
 * isn't mounted, and that there are no active dependents.
 */
int
zfs_destroy(zfs_handle_t *zhp)
{
	zfs_cmd_t zc = { 0 };
	int ret;

	(void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));

	/*
	 * We use the check for 'zfs_volblocksize' instead of ZFS_TYPE_VOLUME
	 * so that we do the right thing for snapshots of volumes.
	 */
	if (zhp->zfs_volblocksize != 0) {
		if (zvol_remove_link(zhp->zfs_name) != 0)
			return (-1);

		zc.zc_objset_type = DMU_OST_ZVOL;
	} else {
		zc.zc_objset_type = DMU_OST_ZFS;
	}

	ret = ioctl(zfs_fd, ZFS_IOC_DESTROY, &zc);

	if (ret != 0) {
		switch (errno) {

		case EPERM:
			/*
			 * We don't have permission to destroy this dataset.
			 */
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot destroy '%s': permission denied"),
			    zhp->zfs_name);
			break;

		case ENOENT:
			/*
			 * We've hit a race condition where the dataset has been
			 * destroyed since we opened it.
			 */
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot destroy '%s': no such %s"),
			    zhp->zfs_name, zfs_type_to_name(zhp->zfs_type));
			break;

		case EBUSY:
			/*
			 * Even if we destroy all children, there is a chance we
			 * can hit this case if:
			 *
			 * 	- A child dataset has since been created
			 * 	- A filesystem is mounted
			 *
			 * This error message is awful, but hopefully we've
			 * already caught the common cases (and aborted more
			 * appropriately) before calling this function.  There's
			 * nothing else we can do at this point.
			 */
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot destroy '%s': %s is busy"),
			    zhp->zfs_name, zfs_type_to_name(zhp->zfs_type));
			break;

		default:
			zfs_baderror(errno);
		}

		return (-1);
	}

	remove_mountpoint(zhp);

	return (0);
}

/*
 * Clones the given dataset.  The target must be of the same type as the source.
 */
int
zfs_clone(zfs_handle_t *zhp, const char *target)
{
	char reason[64];
	zfs_cmd_t zc = { 0 };
	char parent[ZFS_MAXNAMELEN];
	int ret;

	assert(zhp->zfs_type == ZFS_TYPE_SNAPSHOT);

	/* validate the target name */
	if (!zfs_validate_name(target, ZFS_TYPE_FILESYSTEM, reason,
	    sizeof (reason))) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot create '%s': %s in filesystem name"), target,
		    reason, zfs_type_to_name(ZFS_TYPE_FILESYSTEM));
		return (-1);
	}

	/* validate parents exist */
	if (check_parents(target, zhp->zfs_type) != 0)
		return (-1);

	(void) parent_name(target, parent, sizeof (parent));

	/* do the clone */
	if (zhp->zfs_volblocksize != 0)
		zc.zc_objset_type = DMU_OST_ZVOL;
	else
		zc.zc_objset_type = DMU_OST_ZFS;

	(void) strlcpy(zc.zc_name, target, sizeof (zc.zc_name));
	(void) strlcpy(zc.zc_filename, zhp->zfs_name, sizeof (zc.zc_filename));
	ret = ioctl(zfs_fd, ZFS_IOC_CREATE, &zc);

	if (ret != 0) {
		switch (errno) {
		case EPERM:
			/*
			 * The user doesn't have permission to create the clone.
			 */
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot create '%s': permission denied"),
			    target);
			break;

		case ENOENT:
			/*
			 * The parent doesn't exist.  We should have caught this
			 * above, but there may a race condition that has since
			 * destroyed the parent.
			 *
			 * At this point, we don't know whether it's the source
			 * that doesn't exist anymore, or whether the target
			 * dataset doesn't exist.
			 */
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot create '%s': no such parent '%s'"),
			    target, parent);
			break;

		case EDQUOT:
		case ENOSPC:
			/*
			 * There is not enough space in the target dataset
			 */
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot create '%s': not enough space in '%s'"),
			    target, parent);
			break;

		case EEXIST:
			/*
			 * The target already exists.
			 */
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot create '%s': dataset exists"), target);
			break;

		case EXDEV:
			/*
			 * The source and target pools differ.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot create '%s': "
			    "source and target pools differ"), target);
			break;

		default:
			zfs_baderror(errno);
		}
	} else if (zhp->zfs_volblocksize != 0) {
		ret = zvol_create_link(target);
	}

	return (ret);
}

/*
 * Takes a snapshot of the given dataset
 */
int
zfs_snapshot(const char *path)
{
	char reason[64];
	const char *delim;
	char *parent;
	zfs_handle_t *zhp;
	zfs_cmd_t zc = { 0 };
	int ret;

	/* validate the snapshot name */
	if (!zfs_validate_name(path, ZFS_TYPE_SNAPSHOT, reason,
	    sizeof (reason))) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot snapshot '%s': %s in snapshot name"), path,
		    reason);
		return (-1);
	}

	/* make sure we have a snapshot */
	if ((delim = strchr(path, '@')) == NULL) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot snapshot '%s': missing '@' delim in snapshot "
		    "name"), path);
		zfs_error(dgettext(TEXT_DOMAIN,
		    "use 'zfs create' to create a filesystem"));
		return (-1);
	}

	/* make sure the parent exists and is of the appropriate type */
	parent = zfs_malloc(delim - path + 1);
	(void) strncpy(parent, path, delim - path);
	parent[delim - path] = '\0';

	if ((zhp = zfs_open(parent, ZFS_TYPE_FILESYSTEM |
	    ZFS_TYPE_VOLUME)) == NULL) {
		free(parent);
		return (-1);
	}

	(void) strlcpy(zc.zc_name, path, sizeof (zc.zc_name));

	if (zhp->zfs_type == ZFS_TYPE_VOLUME)
		zc.zc_objset_type = DMU_OST_ZVOL;
	else
		zc.zc_objset_type = DMU_OST_ZFS;

	ret = ioctl(zfs_fd, ZFS_IOC_CREATE, &zc);

	if (ret == 0 && zhp->zfs_type == ZFS_TYPE_VOLUME) {
		ret = zvol_create_link(path);
		if (ret != 0)
			(void) ioctl(zfs_fd, ZFS_IOC_DESTROY, &zc);
	}

	if (ret != 0) {
		switch (errno) {
		case EPERM:
			/*
			 * User doesn't have permission to create a snapshot
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot create '%s': "
			    "permission denied"), path);
			break;

		case EDQUOT:
		case ENOSPC:
			/*
			 * Out of space in parent.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot create '%s': "
			    "not enough space in '%s'"), path, parent);
			break;

		case EEXIST:
			/*
			 * Snapshot already exists.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot create '%s': "
			    "snapshot exists"), path);
			break;

		case ENOENT:
			/*
			 * Shouldn't happen because we verified the parent
			 * above.  But there may be a race condition where it
			 * has since been removed.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot open '%s': "
			    "no such %s"), parent,
			    zfs_type_to_name(zhp->zfs_type));
			break;

		default:
			zfs_baderror(errno);
		}
	}

	free(parent);
	zfs_close(zhp);

	return (ret);
}

/*
 * Dumps a backup of tosnap, incremental from fromsnap if it isn't NULL.
 */
int
zfs_backup(zfs_handle_t *zhp_to, zfs_handle_t *zhp_from)
{
	zfs_cmd_t zc = { 0 };
	int ret;

	/* do the ioctl() */
	(void) strlcpy(zc.zc_name, zhp_to->zfs_name, sizeof (zc.zc_name));
	if (zhp_from) {
		(void) strlcpy(zc.zc_prop_value, zhp_from->zfs_name,
		    sizeof (zc.zc_name));
	} else {
		zc.zc_prop_value[0] = '\0';
	}
	zc.zc_cookie = STDOUT_FILENO;

	ret = ioctl(zfs_fd, ZFS_IOC_SENDBACKUP, &zc);
	if (ret != 0) {
		switch (errno) {
		case EPERM:
			/*
			 * User doesn't have permission to do a backup
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot backup '%s': "
			    "permission denied"), zhp_to->zfs_name);
			break;

		case EXDEV:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot do incremental backup from %s:\n"
			    "it is not an earlier snapshot from the "
			    "same fs as %s"),
			    zhp_from->zfs_name, zhp_to->zfs_name);
			break;

		case ENOENT:
			/*
			 * Shouldn't happen because we verified the parent
			 * above.  But there may be a race condition where it
			 * has since been removed.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot open: "
			    "no such snapshot"));
			break;

		case EDQUOT:
		case EFBIG:
		case EIO:
		case ENOLINK:
		case ENOSPC:
		case ENOSTR:
		case ENXIO:
		case EPIPE:
		case ERANGE:
		case EFAULT:
		case EROFS:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot write backup stream: %s"),
			    strerror(errno));
			break;

		case EINTR:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "backup failed: signal recieved"));
			break;

		default:
			zfs_baderror(errno);
		}
	}

	return (ret);
}

/*
 * Restores a backup of tosnap from stdin.
 */
int
zfs_restore(const char *tosnap, int isprefix, int verbose, int dryrun)
{
	zfs_cmd_t zc = { 0 };
	time_t begin_time;
	int ioctl_err, err, bytes, size;
	char *cp;
	dmu_replay_record_t drr;
	struct drr_begin *drrb = &zc.zc_begin_record;

	begin_time = time(NULL);

	/* trim off snapname, if any */
	(void) strcpy(zc.zc_name, tosnap);
	cp = strchr(zc.zc_name, '@');
	if (cp)
		*cp = '\0';

	/* read in the BEGIN record */
	cp = (char *)&drr;
	bytes = 0;
	do {
		size = read(STDIN_FILENO, cp, sizeof (drr) - bytes);
		cp += size;
		bytes += size;
	} while (size > 0);

	if (size < 0 || bytes != sizeof (drr)) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot restore: invalid backup stream "
		    "(couldn't read first record)"));
		return (-1);
	}

	zc.zc_begin_record = drr.drr_u.drr_begin;

	if (drrb->drr_magic != DMU_BACKUP_MAGIC &&
	    drrb->drr_magic != BSWAP_64(DMU_BACKUP_MAGIC)) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot restore: invalid backup stream "
		    "(invalid magic number)"));
		return (-1);
	}

	if (drrb->drr_version != DMU_BACKUP_VERSION &&
	    drrb->drr_version != BSWAP_64(DMU_BACKUP_VERSION)) {
		if (drrb->drr_magic == BSWAP_64(DMU_BACKUP_MAGIC))
			drrb->drr_version = BSWAP_64(drrb->drr_version);
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot restore: only backup version 0x%llx is supported, "
		    "stream is version %llx."),
		    DMU_BACKUP_VERSION, drrb->drr_version);
		return (-1);
	}

	/*
	 * Determine name of destination snapshot.
	 */
	(void) strcpy(drrb->drr_toname, tosnap);
	if (isprefix) {
		if (strchr(tosnap, '@') != NULL) {
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot restore: "
			    "argument to -d must be a filesystem"));
			return (-1);
		}

		cp = strchr(drr.drr_u.drr_begin.drr_toname, '/');
		if (cp == NULL)
			cp = drr.drr_u.drr_begin.drr_toname;
		else
			cp++;

		(void) strcat(drrb->drr_toname, "/");
		(void) strcat(drrb->drr_toname, cp);
	} else if (strchr(tosnap, '@') == NULL) {
		/*
		 * they specified just a filesystem; tack on the
		 * snapname from the backup.
		 */
		cp = strchr(drr.drr_u.drr_begin.drr_toname, '@');
		if (cp == NULL || strlen(tosnap) + strlen(cp) >= MAXNAMELEN) {
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot restore: invalid backup stream "
			    "(invalid snapshot name)"));
			return (-1);
		}
		(void) strcat(drrb->drr_toname, cp);
	}

	if (drrb->drr_fromguid) {
		zfs_handle_t *h;
		/* incremental backup stream */

		/* do the ioctl to the containing fs */
		(void) strcpy(zc.zc_name, drrb->drr_toname);
		cp = strchr(zc.zc_name, '@');
		*cp = '\0';

		/* make sure destination fs exists */
		h = zfs_open(zc.zc_name, ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME);
		if (h == NULL) {
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot restore incrememtal backup: destination\n"
			    "filesystem %s does not exist"),
			    zc.zc_name);
			return (-1);
		}
		if (!dryrun) {
			/* unmount destination fs or remove device link. */
			if (h->zfs_type == ZFS_TYPE_FILESYSTEM) {
				(void) zfs_unmount(h, NULL, 0);
			} else {
				(void) zvol_remove_link(h->zfs_name);
			}
		}
		zfs_close(h);
	} else {
		/* full backup stream */

		(void) strcpy(zc.zc_name, drrb->drr_toname);

		/* make sure they aren't trying to restore into the root */
		if (strchr(zc.zc_name, '/') == NULL) {
			cp = strchr(zc.zc_name, '@');
			if (cp)
				*cp = '\0';
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot restore: destination fs %s already exists"),
			    zc.zc_name);
			return (-1);
		}

		if (isprefix) {
			zfs_handle_t *h;

			/* make sure prefix exists */
			h = zfs_open(tosnap, ZFS_TYPE_FILESYSTEM |
			    ZFS_TYPE_VOLUME);
			if (h == NULL) {
				zfs_error(dgettext(TEXT_DOMAIN,
				    "cannot restore: "
				    "filesystem %s does not exist"),
				    tosnap);
				return (-1);
			}

			/* create any necessary ancestors up to prefix */
			zc.zc_objset_type = DMU_OST_ZFS;
			/*
			 * zc.zc_name is now the full name of the snap
			 * we're restoring into
			 */
			cp = zc.zc_name + strlen(tosnap) + 1;
			while (cp = strchr(cp, '/')) {
				*cp = '\0';
				err = ioctl(zfs_fd, ZFS_IOC_CREATE, &zc);
				if (err && errno != ENOENT && errno != EEXIST) {
					zfs_error(dgettext(TEXT_DOMAIN,
					    "cannot restore: "
					    "couldn't create ancestor %s"),
					    zc.zc_name);
					return (-1);
				}
				*cp = '/';
				cp++;
			}
		}

		/* Make sure destination fs does not exist */
		cp = strchr(zc.zc_name, '@');
		*cp = '\0';
		if (ioctl(zfs_fd, ZFS_IOC_OBJSET_STATS, &zc) == 0) {
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot restore full backup: "
			    "destination filesystem %s already exists"),
			    zc.zc_name);
			return (-1);
		}

		/* Do the recvbackup ioctl to the fs's parent. */
		cp = strrchr(zc.zc_name, '/');
		*cp = '\0';
	}

	(void) strcpy(zc.zc_prop_value, tosnap);
	zc.zc_cookie = STDIN_FILENO;
	zc.zc_intsz = isprefix;
	if (verbose) {
		(void) printf("%s %s backup of %s into %s\n",
		    dryrun ? "would restore" : "restoring",
		    drrb->drr_fromguid ? "incremental" : "full",
		    drr.drr_u.drr_begin.drr_toname,
		    zc.zc_begin_record.drr_toname);
		(void) fflush(stdout);
	}
	if (dryrun)
		return (0);
	err = ioctl_err = ioctl(zfs_fd, ZFS_IOC_RECVBACKUP, &zc);
	if (ioctl_err != 0) {
		switch (errno) {
		case ENODEV:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot restore: "
			    "most recent snapshot does not "
			    "match incremental backup source"));
			break;
		case ETXTBSY:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot restore: "
			    "destination has been modified since "
			    "most recent snapshot --\n"
			    "use 'zfs rollback' to discard changes"));
			break;
		case EEXIST:
			if (drrb->drr_fromguid == 0) {
				/* it's the containing fs that exists */
				cp = strchr(drrb->drr_toname, '@');
				*cp = '\0';
			}
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot restore to %s: destination already exists"),
			    drrb->drr_toname);
			break;
		case ENOENT:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot restore: destination does not exist"));
			break;
		case EBUSY:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot restore: destination is in use"));
			break;
		case ENOSPC:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot restore: out of space"));
			break;
		case EDQUOT:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot restore: quota exceeded"));
			break;
		case EINTR:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "restore failed: signal recieved"));
			break;
		case EINVAL:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot restore: invalid backup stream"));
			break;
		case EPERM:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot restore: permission denied"));
			break;
		default:
			zfs_baderror(errno);
		}
	}

	/*
	 * Mount or recreate the /dev links for the target filesystem
	 * (if created, or if we tore them down to do an incremental
	 * restore), and the /dev links for the new snapshot (if
	 * created).
	 */
	cp = strchr(drrb->drr_toname, '@');
	if (cp && (ioctl_err == 0 || drrb->drr_fromguid)) {
		zfs_handle_t *h;

		*cp = '\0';
		h = zfs_open(drrb->drr_toname,
		    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME);
		*cp = '@';
		if (h) {
			if (h->zfs_type == ZFS_TYPE_FILESYSTEM) {
				err = zfs_mount(h, NULL, 0);
			} else {
				err = zvol_create_link(h->zfs_name);
				if (err == 0 && ioctl_err == 0) {
					err =
					    zvol_create_link(drrb->drr_toname);
				}
			}
			zfs_close(h);
		}
	}

	if (err || ioctl_err)
		return (-1);

	if (verbose) {
		char buf1[64];
		char buf2[64];
		uint64_t bytes = zc.zc_cookie;
		time_t delta = time(NULL) - begin_time;
		if (delta == 0)
			delta = 1;
		zfs_nicenum(bytes, buf1, sizeof (buf1));
		zfs_nicenum(bytes/delta, buf2, sizeof (buf1));

		(void) printf("restored %sb backup in %lu seconds (%sb/sec)\n",
		    buf1, delta, buf2);
	}
	return (0);
}

/*
 * Destroy any more recent snapshots.  We invoke this callback on any dependents
 * of the snapshot first.  If the 'cb_dependent' member is non-zero, then this
 * is a dependent and we should just destroy it without checking the transaction
 * group.
 */
typedef struct rollback_data {
	const char	*cb_target;		/* the snapshot */
	uint64_t	cb_create;		/* creation time reference */
	prop_changelist_t *cb_clp;		/* changelist pointer */
	int		cb_error;
	int		cb_dependent;
} rollback_data_t;

static int
rollback_destroy(zfs_handle_t *zhp, void *data)
{
	rollback_data_t *cbp = data;

	if (!cbp->cb_dependent) {
		if (strcmp(zhp->zfs_name, cbp->cb_target) != 0 &&
		    zfs_get_type(zhp) == ZFS_TYPE_SNAPSHOT &&
		    zfs_prop_get_int(zhp, ZFS_PROP_CREATETXG) >
		    cbp->cb_create) {

			cbp->cb_dependent = TRUE;
			(void) zfs_iter_dependents(zhp, rollback_destroy, cbp);
			cbp->cb_dependent = FALSE;

			if (zfs_destroy(zhp) != 0)
				cbp->cb_error = 1;
			else
				changelist_remove(zhp, cbp->cb_clp);
		}
	} else {
		if (zfs_destroy(zhp) != 0)
			cbp->cb_error = 1;
		else
			changelist_remove(zhp, cbp->cb_clp);
	}

	zfs_close(zhp);
	return (0);
}

/*
 * Rollback the dataset to its latest snapshot.
 */
static int
do_rollback(zfs_handle_t *zhp)
{
	int ret;
	zfs_cmd_t zc = { 0 };

	assert(zhp->zfs_type == ZFS_TYPE_FILESYSTEM ||
	    zhp->zfs_type == ZFS_TYPE_VOLUME);

	if (zhp->zfs_type == ZFS_TYPE_VOLUME &&
	    zvol_remove_link(zhp->zfs_name) != 0)
		return (-1);

	(void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));

	if (zhp->zfs_volblocksize != 0)
		zc.zc_objset_type = DMU_OST_ZVOL;
	else
		zc.zc_objset_type = DMU_OST_ZFS;

	/*
	 * We rely on the consumer to verify that there are no newer snapshots
	 * for the given dataset.  Given these constraints, we can simply pass
	 * the name on to the ioctl() call.  There is still an unlikely race
	 * condition where the user has taken a snapshot since we verified that
	 * this was the most recent.
	 */
	if ((ret = ioctl(zfs_fd, ZFS_IOC_ROLLBACK, &zc)) != 0) {
		switch (errno) {
		case EPERM:
			/*
			 * The user doesn't have permission to rollback the
			 * given dataset.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot rollback '%s': "
			    "permission denied"), zhp->zfs_name);
			break;

		case EDQUOT:
		case ENOSPC:
			/*
			 * The parent dataset doesn't have enough space to
			 * rollback to the last snapshot.
			 */
			{
				char parent[ZFS_MAXNAMELEN];
				(void) parent_name(zhp->zfs_name, parent,
				    sizeof (parent));
				zfs_error(dgettext(TEXT_DOMAIN, "cannot "
				    "rollback '%s': out of space"), parent);
			}
			break;

		case ENOENT:
			/*
			 * The dataset doesn't exist.  This shouldn't happen
			 * except in race conditions.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot rollback '%s': "
			    "no such %s"), zhp->zfs_name,
			    zfs_type_to_name(zhp->zfs_type));
			break;

		case EBUSY:
			/*
			 * The filesystem is busy.  This should have been caught
			 * by the caller before getting here, but there may be
			 * an unexpected problem.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot rollback '%s': "
			    "%s is busy"), zhp->zfs_name,
			    zfs_type_to_name(zhp->zfs_type));
			break;

		default:
			zfs_baderror(errno);
		}
	} else if (zhp->zfs_type == ZFS_TYPE_VOLUME) {
		ret = zvol_create_link(zhp->zfs_name);
	}

	return (ret);
}

/*
 * Given a dataset, rollback to a specific snapshot, discarding any
 * data changes since then and making it the active dataset.
 *
 * Any snapshots more recent than the target are destroyed, along with
 * their dependents.
 */
int
zfs_rollback(zfs_handle_t *zhp, zfs_handle_t *snap, int flag)
{
	int ret;
	rollback_data_t cb = { 0 };
	prop_changelist_t *clp;

	/*
	 * Unmount all dependendents of the dataset and the dataset itself.
	 * The list we need to gather is the same as for doing rename
	 */
	clp = changelist_gather(zhp, ZFS_PROP_NAME, flag ? MS_FORCE: 0);
	if (clp == NULL)
		return (-1);

	if ((ret = changelist_prefix(clp)) != 0)
		goto out;

	/*
	 * Destroy all recent snapshots and its dependends.
	 */
	cb.cb_target = snap->zfs_name;
	cb.cb_create = zfs_prop_get_int(snap, ZFS_PROP_CREATETXG);
	cb.cb_clp = clp;
	(void) zfs_iter_children(zhp, rollback_destroy, &cb);

	if ((ret = cb.cb_error) != 0) {
		(void) changelist_postfix(clp);
		goto out;
	}

	/*
	 * Now that we have verified that the snapshot is the latest,
	 * rollback to the given snapshot.
	 */
	ret = do_rollback(zhp);

	if (ret != 0) {
		(void) changelist_postfix(clp);
		goto out;
	}

	/*
	 * We only want to re-mount the filesystem if it was mounted in the
	 * first place.
	 */
	ret = changelist_postfix(clp);

out:
	changelist_free(clp);
	return (ret);
}

/*
 * Iterate over all dependents for a given dataset.  This includes both
 * hierarchical dependents (children) and data dependents (snapshots and
 * clones).  The bulk of the processing occurs in get_dependents() in
 * libzfs_graph.c.
 */
int
zfs_iter_dependents(zfs_handle_t *zhp, zfs_iter_f func, void *data)
{
	char **dependents;
	size_t count;
	int i;
	zfs_handle_t *child;
	int ret = 0;

	dependents = get_dependents(zhp->zfs_name, &count);
	for (i = 0; i < count; i++) {
		if ((child = make_dataset_handle(dependents[i])) == NULL)
			continue;

		if ((ret = func(child, data)) != 0)
			break;
	}

	for (i = 0; i < count; i++)
		free(dependents[i]);
	free(dependents);

	return (ret);
}

/*
 * Renames the given dataset.
 */
int
zfs_rename(zfs_handle_t *zhp, const char *target)
{
	int ret;
	zfs_cmd_t zc = { 0 };
	char reason[64];
	char *delim;
	prop_changelist_t *cl;
	char parent[ZFS_MAXNAMELEN];

	(void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));
	(void) strlcpy(zc.zc_prop_value, target, sizeof (zc.zc_prop_value));

	/* if we have the same exact name, just return success */
	if (strcmp(zhp->zfs_name, target) == 0)
		return (0);

	/*
	 * Make sure the target name is valid
	 */
	if (!zfs_validate_name(target, zhp->zfs_type, reason,
	    sizeof (reason))) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot create '%s': %s in %s name"), target, reason,
		    zfs_type_to_name(zhp->zfs_type));
		return (-1);
	}

	if (zhp->zfs_type == ZFS_TYPE_SNAPSHOT) {
		if ((delim = strchr(target, '@')) == NULL) {
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot rename to '%s': not a snapshot"), target);
			return (-1);
		}

		/*
		 * Make sure we're renaming within the same dataset.
		 */
		if (strncmp(zhp->zfs_name, target, delim - target) != 0 ||
		    zhp->zfs_name[delim - target] != '@') {
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot rename to '%s': snapshots must be part "
			    "of same dataset"), target);
			return (-1);
		}

		(void) strncpy(parent, target, delim - target);
		parent[delim - target] = '\0';
	} else {
		/* validate parents */
		if (check_parents(target, zhp->zfs_type) != 0)
			return (-1);

		(void) parent_name(target, parent, sizeof (parent));

		/* make sure we're in the same pool */
		verify((delim = strchr(target, '/')) != NULL);
		if (strncmp(zhp->zfs_name, target, delim - target) != 0 ||
		    zhp->zfs_name[delim - target] != '/') {
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot rename to '%s': "
			    "datasets must be within same pool"), target);
			return (-1);
		}
	}

	if (getzoneid() == GLOBAL_ZONEID &&
	    zfs_prop_get_int(zhp, ZFS_PROP_ZONED)) {
		zfs_error(dgettext(TEXT_DOMAIN, "cannot rename %s, "
		    "dataset is used in a non-global zone"), zhp->zfs_name);
		return (-1);
	}

	if ((cl = changelist_gather(zhp, ZFS_PROP_NAME, 0)) == NULL)
		return (1);

	if (changelist_haszonedchild(cl)) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot rename '%s': child dataset with inherited "
		    "mountpoint is used in a non-global zone"), zhp->zfs_name);
		ret = -1;
		goto error;
	}

	if ((ret = changelist_prefix(cl)) != 0)
		goto error;

	if (zhp->zfs_volblocksize != 0)
		zc.zc_objset_type = DMU_OST_ZVOL;
	else
		zc.zc_objset_type = DMU_OST_ZFS;

	if ((ret = ioctl(zfs_fd, ZFS_IOC_RENAME, &zc)) != 0) {
		switch (errno) {
		case EPERM:
			/*
			 * The user doesn't have permission to rename the
			 * given dataset.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot rename '%s': "
			    "permission denied"), zhp->zfs_name);
			break;

		case EDQUOT:
		case ENOSPC:
			/*
			 * Not enough space in the parent dataset.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot "
			    "rename '%s': not enough space in '%s'"),
			    zhp->zfs_name, parent);
			break;

		case ENOENT:
			/*
			 * The destination doesn't exist.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot rename '%s' "
			    "to '%s': destination doesn't exist"),
			    zhp->zfs_name, target);
			break;

		case EEXIST:
			/*
			 * The destination already exists.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot rename '%s' "
			    "to '%s': destination already exists"),
			    zhp->zfs_name, target);
			break;

		case EBUSY:
			/*
			 * The filesystem is busy.  This should have been caught
			 * by the caller before getting here, but there may be
			 * an unexpected problem.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot rename '%s': "
			    "%s is busy"), zhp->zfs_name,
			    zfs_type_to_name(zhp->zfs_type));
			break;

		default:
			zfs_baderror(errno);
		}

		/*
		 * On failure, we still want to remount any filesystems that
		 * were previously mounted, so we don't alter the system state.
		 */
		(void) changelist_postfix(cl);
	} else {
		changelist_rename(cl, zfs_get_name(zhp), target);

		ret = changelist_postfix(cl);
	}

error:
	changelist_free(cl);
	return (ret);
}

/*
 * Given a zvol dataset, issue the ioctl to create the appropriate minor node,
 * poke devfsadm to create the /dev link, and then wait for the link to appear.
 */
int
zvol_create_link(const char *dataset)
{
	zfs_cmd_t zc = { 0 };
	di_devlink_handle_t hdl;

	(void) strlcpy(zc.zc_name, dataset, sizeof (zc.zc_name));

	/*
	 * Issue the appropriate ioctl.
	 */
	if (ioctl(zfs_fd, ZFS_IOC_CREATE_MINOR, &zc) != 0) {
		switch (errno) {
		case EPERM:
			zfs_error(dgettext(TEXT_DOMAIN, "cannot create "
			    "device links for '%s': permission denied"),
			    dataset);
			break;

		case EEXIST:
			/*
			 * Silently ignore the case where the link already
			 * exists.  This allows 'zfs volinit' to be run multiple
			 * times without errors.
			 */
			return (0);

		default:
			zfs_baderror(errno);
		}

		return (-1);
	}

	/*
	 * Call devfsadm and wait for the links to magically appear.
	 */
	if ((hdl = di_devlink_init(ZFS_DRIVER, DI_MAKE_LINK)) == NULL) {
		zfs_error(dgettext(TEXT_DOMAIN,
		    "cannot create device links for '%s'"), dataset);
		(void) ioctl(zfs_fd, ZFS_IOC_REMOVE_MINOR, &zc);
		return (-1);
	} else {
		(void) di_devlink_fini(&hdl);
	}

	return (0);
}

/*
 * Remove a minor node for the given zvol and the associated /dev links.
 */
int
zvol_remove_link(const char *dataset)
{
	zfs_cmd_t zc = { 0 };

	(void) strlcpy(zc.zc_name, dataset, sizeof (zc.zc_name));

	if (ioctl(zfs_fd, ZFS_IOC_REMOVE_MINOR, &zc) != 0) {
		switch (errno) {
		case EPERM:
			zfs_error(dgettext(TEXT_DOMAIN, "cannot remove "
			    "device links for '%s': permission denied"),
			    dataset);
			break;

		case EBUSY:
			zfs_error(dgettext(TEXT_DOMAIN, "cannot remove "
			    "device links for '%s': volume is in use"),
			    dataset);
			break;

		case ENXIO:
			/*
			 * Silently ignore the case where the link no longer
			 * exists, so that 'zfs volfini' can be run multiple
			 * times without errors.
			 */
			return (0);

		default:
			zfs_baderror(errno);
		}

		return (-1);
	}

	return (0);
}
