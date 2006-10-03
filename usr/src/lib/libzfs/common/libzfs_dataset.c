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
#include <fcntl.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/mount.h>

#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/zap.h>
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
zfs_validate_name(libzfs_handle_t *hdl, const char *path, int type)
{
	namecheck_err_t why;
	char what;

	if (dataset_namecheck(path, &why, &what) != 0) {
		if (hdl != NULL) {
			switch (why) {
			case NAME_ERR_TOOLONG:
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "name is too long"));
				break;

			case NAME_ERR_LEADING_SLASH:
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "leading slash in name"));
				break;

			case NAME_ERR_EMPTY_COMPONENT:
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "empty component in name"));
				break;

			case NAME_ERR_TRAILING_SLASH:
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "trailing slash in name"));
				break;

			case NAME_ERR_INVALCHAR:
				zfs_error_aux(hdl,
				    dgettext(TEXT_DOMAIN, "invalid character "
				    "'%c' in name"), what);
				break;

			case NAME_ERR_MULTIPLE_AT:
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "multiple '@' delimiters in name"));
				break;

			case NAME_ERR_NOLETTER:
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "pool doesn't begin with a letter"));
				break;

			case NAME_ERR_RESERVED:
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "name is reserved"));
				break;

			case NAME_ERR_DISKLIKE:
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "reserved disk name"));
				break;
			}
		}

		return (0);
	}

	if (!(type & ZFS_TYPE_SNAPSHOT) && strchr(path, '@') != NULL) {
		if (hdl != NULL)
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "snapshot delimiter '@' in filesystem name"));
		return (0);
	}

	if (type == ZFS_TYPE_SNAPSHOT && strchr(path, '@') == NULL) {
		if (hdl != NULL)
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "missing '@' delimeter in snapshot name"));
		return (0);
	}

	return (-1);
}

int
zfs_name_valid(const char *name, zfs_type_t type)
{
	return (zfs_validate_name(NULL, name, type));
}

/*
 * This function takes the raw DSL properties, and filters out the user-defined
 * properties into a separate nvlist.
 */
static int
process_user_props(zfs_handle_t *zhp)
{
	libzfs_handle_t *hdl = zhp->zfs_hdl;
	nvpair_t *elem;
	nvlist_t *propval;

	nvlist_free(zhp->zfs_user_props);

	if (nvlist_alloc(&zhp->zfs_user_props, NV_UNIQUE_NAME, 0) != 0)
		return (no_memory(hdl));

	elem = NULL;
	while ((elem = nvlist_next_nvpair(zhp->zfs_props, elem)) != NULL) {
		if (!zfs_prop_user(nvpair_name(elem)))
			continue;

		verify(nvpair_value_nvlist(elem, &propval) == 0);
		if (nvlist_add_nvlist(zhp->zfs_user_props,
		    nvpair_name(elem), propval) != 0)
			return (no_memory(hdl));
	}

	return (0);
}

/*
 * Utility function to gather stats (objset and zpl) for the given object.
 */
static int
get_stats(zfs_handle_t *zhp)
{
	zfs_cmd_t zc = { 0 };
	libzfs_handle_t *hdl = zhp->zfs_hdl;

	(void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));

	if (zcmd_alloc_dst_nvlist(hdl, &zc, 0) != 0)
		return (-1);

	while (ioctl(zhp->zfs_hdl->libzfs_fd, ZFS_IOC_OBJSET_STATS, &zc) != 0) {
		if (errno == ENOMEM) {
			if (zcmd_expand_dst_nvlist(hdl, &zc) != 0) {
				zcmd_free_nvlists(&zc);
				return (-1);
			}
		} else {
			zcmd_free_nvlists(&zc);
			return (-1);
		}
	}

	bcopy(&zc.zc_objset_stats, &zhp->zfs_dmustats,
	    sizeof (zc.zc_objset_stats));

	(void) strlcpy(zhp->zfs_root, zc.zc_value, sizeof (zhp->zfs_root));

	if (zhp->zfs_props) {
		nvlist_free(zhp->zfs_props);
		zhp->zfs_props = NULL;
	}

	if (zcmd_read_dst_nvlist(hdl, &zc, &zhp->zfs_props) != 0) {
		zcmd_free_nvlists(&zc);
		return (-1);
	}

	zcmd_free_nvlists(&zc);

	zhp->zfs_volstats = zc.zc_vol_stats;

	if (process_user_props(zhp) != 0)
		return (-1);

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
make_dataset_handle(libzfs_handle_t *hdl, const char *path)
{
	zfs_handle_t *zhp = calloc(sizeof (zfs_handle_t), 1);

	if (zhp == NULL)
		return (NULL);

	zhp->zfs_hdl = hdl;

top:
	(void) strlcpy(zhp->zfs_name, path, sizeof (zhp->zfs_name));

	if (get_stats(zhp) != 0) {
		free(zhp);
		return (NULL);
	}

	if (zhp->zfs_dmustats.dds_inconsistent) {
		zfs_cmd_t zc = { 0 };

		/*
		 * If it is dds_inconsistent, then we've caught it in
		 * the middle of a 'zfs receive' or 'zfs destroy', and
		 * it is inconsistent from the ZPL's point of view, so
		 * can't be mounted.  However, it could also be that we
		 * have crashed in the middle of one of those
		 * operations, in which case we need to get rid of the
		 * inconsistent state.  We do that by either rolling
		 * back to the previous snapshot (which will fail if
		 * there is none), or destroying the filesystem.  Note
		 * that if we are still in the middle of an active
		 * 'receive' or 'destroy', then the rollback and destroy
		 * will fail with EBUSY and we will drive on as usual.
		 */

		(void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));

		if (zhp->zfs_type == ZFS_TYPE_VOLUME) {
			(void) zvol_remove_link(hdl, zhp->zfs_name);
			zc.zc_objset_type = DMU_OST_ZVOL;
		} else {
			zc.zc_objset_type = DMU_OST_ZFS;
		}

		/* If we can successfully roll it back, reget the stats */
		if (ioctl(hdl->libzfs_fd, ZFS_IOC_ROLLBACK, &zc) == 0)
			goto top;
		/*
		 * If we can sucessfully destroy it, pretend that it
		 * never existed.
		 */
		if (ioctl(hdl->libzfs_fd, ZFS_IOC_DESTROY, &zc) == 0) {
			free(zhp);
			errno = ENOENT;
			return (NULL);
		}
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
		abort();	/* we should never see any other types */

	return (zhp);
}

/*
 * Opens the given snapshot, filesystem, or volume.   The 'types'
 * argument is a mask of acceptable types.  The function will print an
 * appropriate error message and return NULL if it can't be opened.
 */
zfs_handle_t *
zfs_open(libzfs_handle_t *hdl, const char *path, int types)
{
	zfs_handle_t *zhp;
	char errbuf[1024];

	(void) snprintf(errbuf, sizeof (errbuf),
	    dgettext(TEXT_DOMAIN, "cannot open '%s'"), path);

	/*
	 * Validate the name before we even try to open it.
	 */
	if (!zfs_validate_name(hdl, path, ZFS_TYPE_ANY)) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "invalid dataset name"));
		(void) zfs_error(hdl, EZFS_INVALIDNAME, errbuf);
		return (NULL);
	}

	/*
	 * Try to get stats for the dataset, which will tell us if it exists.
	 */
	errno = 0;
	if ((zhp = make_dataset_handle(hdl, path)) == NULL) {
		(void) zfs_standard_error(hdl, errno, errbuf, path);
		return (NULL);
	}

	if (!(types & zhp->zfs_type)) {
		(void) zfs_error(hdl, EZFS_BADTYPE, errbuf);
		zfs_close(zhp);
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
	nvlist_free(zhp->zfs_props);
	nvlist_free(zhp->zfs_user_props);
	free(zhp);
}

/*
 * Given a numeric suffix, convert the value into a number of bits that the
 * resulting value must be shifted.
 */
static int
str2shift(libzfs_handle_t *hdl, const char *buf)
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
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "invalid numeric suffix '%s'"), buf);
		return (-1);
	}

	/*
	 * We want to allow trailing 'b' characters for 'GB' or 'Mb'.  But don't
	 * allow 'BB' - that's just weird.
	 */
	if (buf[1] == '\0' || (toupper(buf[1]) == 'B' && buf[2] == '\0' &&
	    toupper(buf[0]) != 'B'))
		return (10*i);

	zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
	    "invalid numeric suffix '%s'"), buf);
	return (-1);
}

/*
 * Convert a string of the form '100G' into a real number.  Used when setting
 * properties or creating a volume.  'buf' is used to place an extended error
 * message for the caller to use.
 */
static int
nicestrtonum(libzfs_handle_t *hdl, const char *value, uint64_t *num)
{
	char *end;
	int shift;

	*num = 0;

	/* Check to see if this looks like a number.  */
	if ((value[0] < '0' || value[0] > '9') && value[0] != '.') {
		if (hdl)
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "bad numeric value '%s'"), value);
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
		if (hdl)
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "numeric value is too large"));
		return (-1);
	}

	/*
	 * If we have a decimal value, then do the computation with floating
	 * point arithmetic.  Otherwise, use standard arithmetic.
	 */
	if (*end == '.') {
		double fval = strtod(value, &end);

		if ((shift = str2shift(hdl, end)) == -1)
			return (-1);

		fval *= pow(2, shift);

		if (fval > UINT64_MAX) {
			if (hdl)
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "numeric value is too large"));
			return (-1);
		}

		*num = (uint64_t)fval;
	} else {
		if ((shift = str2shift(hdl, end)) == -1)
			return (-1);

		/* Check for overflow */
		if (shift >= 64 || (*num << shift) >> shift != *num) {
			if (hdl)
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "numeric value is too large"));
			return (-1);
		}

		*num <<= shift;
	}

	return (0);
}

int
zfs_nicestrtonum(libzfs_handle_t *hdl, const char *str, uint64_t *val)
{
	return (nicestrtonum(hdl, str, val));
}

/*
 * The prop_parse_*() functions are designed to allow flexibility in callers
 * when setting properties.  At the DSL layer, all properties are either 64-bit
 * numbers or strings.  We want the user to be able to ignore this fact and
 * specify properties as native values (boolean, for example) or as strings (to
 * simplify command line utilities).  This also handles converting index types
 * (compression, checksum, etc) from strings to their on-disk index.
 */

static int
prop_parse_boolean(libzfs_handle_t *hdl, nvpair_t *elem, uint64_t *val)
{
	uint64_t ret;

	switch (nvpair_type(elem)) {
	case DATA_TYPE_STRING:
		{
			char *value;
			VERIFY(nvpair_value_string(elem, &value) == 0);

			if (strcmp(value, "on") == 0) {
				ret = 1;
			} else if (strcmp(value, "off") == 0) {
				ret = 0;
			} else {
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "property '%s' must be 'on' or 'off'"),
				    nvpair_name(elem));
				return (-1);
			}
			break;
		}

	case DATA_TYPE_UINT64:
		{
			VERIFY(nvpair_value_uint64(elem, &ret) == 0);
			if (ret > 1) {
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "'%s' must be a boolean value"),
				    nvpair_name(elem));
				return (-1);
			}
			break;
		}

	case DATA_TYPE_BOOLEAN_VALUE:
		{
			boolean_t value;
			VERIFY(nvpair_value_boolean_value(elem, &value) == 0);
			ret = value;
			break;
		}

	default:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "'%s' must be a boolean value"),
		    nvpair_name(elem));
		return (-1);
	}

	*val = ret;
	return (0);
}

static int
prop_parse_number(libzfs_handle_t *hdl, nvpair_t *elem, zfs_prop_t prop,
    uint64_t *val)
{
	uint64_t ret;
	boolean_t isnone = B_FALSE;

	switch (nvpair_type(elem)) {
	case DATA_TYPE_STRING:
		{
			char *value;
			(void) nvpair_value_string(elem, &value);
			if (strcmp(value, "none") == 0) {
				isnone = B_TRUE;
				ret = 0;
			} else if (nicestrtonum(hdl, value, &ret) != 0) {
				return (-1);
			}
			break;
		}

	case DATA_TYPE_UINT64:
		(void) nvpair_value_uint64(elem, &ret);
		break;

	default:
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "'%s' must be a number"),
		    nvpair_name(elem));
		return (-1);
	}

	/*
	 * Quota special: force 'none' and don't allow 0.
	 */
	if (ret == 0 && !isnone && prop == ZFS_PROP_QUOTA) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "use 'none' to disable quota"));
		return (-1);
	}

	*val = ret;
	return (0);
}

static int
prop_parse_index(libzfs_handle_t *hdl, nvpair_t *elem, zfs_prop_t prop,
    uint64_t *val)
{
	char *propname = nvpair_name(elem);
	char *value;

	if (nvpair_type(elem) != DATA_TYPE_STRING) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "'%s' must be a string"), propname);
		return (-1);
	}

	(void) nvpair_value_string(elem, &value);

	if (zfs_prop_string_to_index(prop, value, val) != 0) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "'%s' must be one of '%s'"), propname,
		    zfs_prop_values(prop));
		return (-1);
	}

	return (0);
}

/*
 * Given an nvlist of properties to set, validates that they are correct, and
 * parses any numeric properties (index, boolean, etc) if they are specified as
 * strings.
 */
static nvlist_t *
zfs_validate_properties(libzfs_handle_t *hdl, zfs_type_t type, nvlist_t *nvl,
    uint64_t zoned, zfs_handle_t *zhp, const char *errbuf)
{
	nvpair_t *elem;
	const char *propname;
	zfs_prop_t prop;
	uint64_t intval;
	char *strval;
	nvlist_t *ret;

	if (nvlist_alloc(&ret, NV_UNIQUE_NAME, 0) != 0) {
		(void) no_memory(hdl);
		return (NULL);
	}

	if (type == ZFS_TYPE_SNAPSHOT) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "snaphot properties cannot be modified"));
		(void) zfs_error(hdl, EZFS_PROPTYPE, errbuf);
		goto error;
	}

	elem = NULL;
	while ((elem = nvlist_next_nvpair(nvl, elem)) != NULL) {
		propname = nvpair_name(elem);

		/*
		 * Make sure this property is valid and applies to this type.
		 */
		if ((prop = zfs_name_to_prop(propname)) == ZFS_PROP_INVAL) {
			if (!zfs_prop_user(propname)) {
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "invalid property '%s'"),
				    propname);
				(void) zfs_error(hdl, EZFS_BADPROP, errbuf);
				goto error;
			} else {
				/*
				 * If this is a user property, make sure it's a
				 * string, and that it's less than
				 * ZAP_MAXNAMELEN.
				 */
				if (nvpair_type(elem) != DATA_TYPE_STRING) {
					zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
					    "'%s' must be a string"),
					    propname);
					(void) zfs_error(hdl, EZFS_BADPROP,
					    errbuf);
					goto error;
				}

				if (strlen(nvpair_name(elem)) >=
				    ZAP_MAXNAMELEN) {
					zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
					    "property name '%s' is too long"),
					    propname);
					(void) zfs_error(hdl, EZFS_BADPROP,
					    errbuf);
					goto error;
				}
			}

			(void) nvpair_value_string(elem, &strval);
			if (nvlist_add_string(ret, propname, strval) != 0) {
				(void) no_memory(hdl);
				goto error;
			}
			continue;
		}

		/*
		 * Normalize the name, to get rid of shorthand abbrevations.
		 */
		propname = zfs_prop_to_name(prop);

		if (!zfs_prop_valid_for_type(prop, type)) {
			zfs_error_aux(hdl,
			    dgettext(TEXT_DOMAIN, "'%s' does not "
			    "apply to datasets of this type"), propname);
			(void) zfs_error(hdl, EZFS_PROPTYPE, errbuf);
			goto error;
		}

		if (zfs_prop_readonly(prop) &&
		    (prop != ZFS_PROP_VOLBLOCKSIZE || zhp != NULL)) {
			zfs_error_aux(hdl,
			    dgettext(TEXT_DOMAIN, "'%s' is readonly"),
			    propname);
			(void) zfs_error(hdl, EZFS_PROPREADONLY, errbuf);
			goto error;
		}

		/*
		 * Convert any properties to the internal DSL value types.
		 */
		strval = NULL;
		switch (zfs_prop_get_type(prop)) {
		case prop_type_boolean:
			if (prop_parse_boolean(hdl, elem, &intval) != 0) {
				(void) zfs_error(hdl, EZFS_BADPROP, errbuf);
				goto error;
			}
			break;

		case prop_type_string:
			if (nvpair_type(elem) != DATA_TYPE_STRING) {
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "'%s' must be a string"),
				    propname);
				(void) zfs_error(hdl, EZFS_BADPROP, errbuf);
				goto error;
			}
			(void) nvpair_value_string(elem, &strval);
			if (strlen(strval) >= ZFS_MAXPROPLEN) {
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "'%s' is too long"), propname);
				(void) zfs_error(hdl, EZFS_BADPROP, errbuf);
				goto error;
			}
			break;

		case prop_type_number:
			if (prop_parse_number(hdl, elem, prop, &intval) != 0) {
				(void) zfs_error(hdl, EZFS_BADPROP, errbuf);
				goto error;
			}
			break;

		case prop_type_index:
			if (prop_parse_index(hdl, elem, prop, &intval) != 0) {
				(void) zfs_error(hdl, EZFS_BADPROP, errbuf);
				goto error;
			}
			break;

		default:
			abort();
		}

		/*
		 * Add the result to our return set of properties.
		 */
		if (strval) {
			if (nvlist_add_string(ret, propname, strval) != 0) {
				(void) no_memory(hdl);
				goto error;
			}
		} else if (nvlist_add_uint64(ret, propname, intval) != 0) {
			(void) no_memory(hdl);
			goto error;
		}

		/*
		 * Perform some additional checks for specific properties.
		 */
		switch (prop) {
		case ZFS_PROP_RECORDSIZE:
		case ZFS_PROP_VOLBLOCKSIZE:
			/* must be power of two within SPA_{MIN,MAX}BLOCKSIZE */
			if (intval < SPA_MINBLOCKSIZE ||
			    intval > SPA_MAXBLOCKSIZE || !ISP2(intval)) {
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "'%s' must be power of 2 from %u "
				    "to %uk"), propname,
				    (uint_t)SPA_MINBLOCKSIZE,
				    (uint_t)SPA_MAXBLOCKSIZE >> 10);
				(void) zfs_error(hdl, EZFS_BADPROP, errbuf);
				goto error;
			}
			break;

		case ZFS_PROP_MOUNTPOINT:
			if (strcmp(strval, ZFS_MOUNTPOINT_NONE) == 0 ||
			    strcmp(strval, ZFS_MOUNTPOINT_LEGACY) == 0)
				break;

			if (strval[0] != '/') {
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "'%s' must be an absolute path, "
				    "'none', or 'legacy'"), propname);
				(void) zfs_error(hdl, EZFS_BADPROP, errbuf);
				goto error;
			}
			break;
		}

		/*
		 * For the mountpoint and sharenfs properties, check if it can
		 * be set in a global/non-global zone based on the zoned
		 * property value:
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
			if (zoned) {
				if (getzoneid() == GLOBAL_ZONEID) {
					zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
					    "'%s' cannot be set on "
					    "dataset in a non-global zone"),
					    propname);
					(void) zfs_error(hdl, EZFS_ZONED,
					    errbuf);
					goto error;
				} else if (prop == ZFS_PROP_SHARENFS) {
					zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
					    "'%s' cannot be set in "
					    "a non-global zone"), propname);
					(void) zfs_error(hdl, EZFS_ZONED,
					    errbuf);
					goto error;
				}
			} else if (getzoneid() != GLOBAL_ZONEID) {
				/*
				 * If zoned property is 'off', this must be in
				 * a globle zone. If not, something is wrong.
				 */
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "'%s' cannot be set while dataset "
				    "'zoned' property is set"), propname);
				(void) zfs_error(hdl, EZFS_ZONED, errbuf);
				goto error;
			}
		}

		/*
		 * For changes to existing volumes, we have some additional
		 * checks to enforce.
		 */
		if (type == ZFS_TYPE_VOLUME && zhp != NULL) {
			uint64_t volsize = zfs_prop_get_int(zhp,
			    ZFS_PROP_VOLSIZE);
			uint64_t blocksize = zfs_prop_get_int(zhp,
			    ZFS_PROP_VOLBLOCKSIZE);
			char buf[64];

			switch (prop) {
			case ZFS_PROP_RESERVATION:
				if (intval > volsize) {
					zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
					    "'%s' is greater than current "
					    "volume size"), propname);
					(void) zfs_error(hdl, EZFS_BADPROP,
					    errbuf);
					goto error;
				}
				break;

			case ZFS_PROP_VOLSIZE:
				if (intval % blocksize != 0) {
					zfs_nicenum(blocksize, buf,
					    sizeof (buf));
					zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
					    "'%s' must be a multiple of "
					    "volume block size (%s)"),
					    propname, buf);
					(void) zfs_error(hdl, EZFS_BADPROP,
					    errbuf);
					goto error;
				}

				if (intval == 0) {
					zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
					    "'%s' cannot be zero"),
					    propname);
					(void) zfs_error(hdl, EZFS_BADPROP,
					    errbuf);
					goto error;
				}
			}
		}
	}

	/*
	 * If this is an existing volume, and someone is setting the volsize,
	 * make sure that it matches the reservation, or add it if necessary.
	 */
	if (zhp != NULL && type == ZFS_TYPE_VOLUME &&
	    nvlist_lookup_uint64(ret, zfs_prop_to_name(ZFS_PROP_VOLSIZE),
	    &intval) == 0) {
		uint64_t old_volsize = zfs_prop_get_int(zhp,
		    ZFS_PROP_VOLSIZE);
		uint64_t old_reservation = zfs_prop_get_int(zhp,
		    ZFS_PROP_RESERVATION);
		uint64_t new_reservation;

		if (old_volsize == old_reservation &&
		    nvlist_lookup_uint64(ret,
		    zfs_prop_to_name(ZFS_PROP_RESERVATION),
		    &new_reservation) != 0) {
			if (nvlist_add_uint64(ret,
			    zfs_prop_to_name(ZFS_PROP_RESERVATION),
			    intval) != 0) {
				(void) no_memory(hdl);
				goto error;
			}
		}
	}

	return (ret);

error:
	nvlist_free(ret);
	return (NULL);
}

/*
 * Given a property name and value, set the property for the given dataset.
 */
int
zfs_prop_set(zfs_handle_t *zhp, const char *propname, const char *propval)
{
	zfs_cmd_t zc = { 0 };
	int ret = -1;
	prop_changelist_t *cl = NULL;
	char errbuf[1024];
	libzfs_handle_t *hdl = zhp->zfs_hdl;
	nvlist_t *nvl = NULL, *realprops;
	zfs_prop_t prop;

	(void) snprintf(errbuf, sizeof (errbuf),
	    dgettext(TEXT_DOMAIN, "cannot set property for '%s'"),
	    zhp->zfs_name);

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_add_string(nvl, propname, propval) != 0) {
		(void) no_memory(hdl);
		goto error;
	}

	if ((realprops = zfs_validate_properties(hdl, zhp->zfs_type, nvl,
	    zfs_prop_get_int(zhp, ZFS_PROP_ZONED), zhp, errbuf)) == NULL)
		goto error;
	nvlist_free(nvl);
	nvl = realprops;

	prop = zfs_name_to_prop(propname);

	if ((cl = changelist_gather(zhp, prop, 0)) == NULL)
		goto error;

	if (prop == ZFS_PROP_MOUNTPOINT && changelist_haszonedchild(cl)) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "child dataset with inherited mountpoint is used "
		    "in a non-global zone"));
		ret = zfs_error(hdl, EZFS_ZONED, errbuf);
		goto error;
	}

	if ((ret = changelist_prefix(cl)) != 0)
		goto error;

	/*
	 * Execute the corresponding ioctl() to set this property.
	 */
	(void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));

	if (zcmd_write_src_nvlist(hdl, &zc, nvl, NULL) != 0)
		goto error;

	ret = ioctl(hdl->libzfs_fd, ZFS_IOC_SET_PROP, &zc);

	if (ret != 0) {
		switch (errno) {

		case ENOSPC:
			/*
			 * For quotas and reservations, ENOSPC indicates
			 * something different; setting a quota or reservation
			 * doesn't use any disk space.
			 */
			switch (prop) {
			case ZFS_PROP_QUOTA:
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "size is less than current used or "
				    "reserved space"));
				(void) zfs_error(hdl, EZFS_PROPSPACE, errbuf);
				break;

			case ZFS_PROP_RESERVATION:
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "size is greater than available space"));
				(void) zfs_error(hdl, EZFS_PROPSPACE, errbuf);
				break;

			default:
				(void) zfs_standard_error(hdl, errno, errbuf);
				break;
			}
			break;

		case EBUSY:
			if (prop == ZFS_PROP_VOLBLOCKSIZE)
				(void) zfs_error(hdl, EZFS_VOLHASDATA, errbuf);
			else
				(void) zfs_standard_error(hdl, EBUSY, errbuf);
			break;

		case EROFS:
			(void) zfs_error(hdl, EZFS_DSREADONLY, errbuf);
			break;

		case EOVERFLOW:
			/*
			 * This platform can't address a volume this big.
			 */
#ifdef _ILP32
			if (prop == ZFS_PROP_VOLSIZE) {
				(void) zfs_error(hdl, EZFS_VOLTOOBIG, errbuf);
				break;
			}
#endif
			/* FALLTHROUGH */
		default:
			(void) zfs_standard_error(hdl, errno, errbuf);
		}
	} else {
		/*
		 * Refresh the statistics so the new property value
		 * is reflected.
		 */
		if ((ret = changelist_postfix(cl)) == 0)
			(void) get_stats(zhp);
	}

error:
	nvlist_free(nvl);
	zcmd_free_nvlists(&zc);
	if (cl)
		changelist_free(cl);
	return (ret);
}

/*
 * Given a property, inherit the value from the parent dataset.
 */
int
zfs_prop_inherit(zfs_handle_t *zhp, const char *propname)
{
	zfs_cmd_t zc = { 0 };
	int ret;
	prop_changelist_t *cl;
	libzfs_handle_t *hdl = zhp->zfs_hdl;
	char errbuf[1024];
	zfs_prop_t prop;

	(void) snprintf(errbuf, sizeof (errbuf), dgettext(TEXT_DOMAIN,
	    "cannot inherit %s for '%s'"), propname, zhp->zfs_name);

	if ((prop = zfs_name_to_prop(propname)) == ZFS_PROP_INVAL) {
		/*
		 * For user properties, the amount of work we have to do is very
		 * small, so just do it here.
		 */
		if (!zfs_prop_user(propname)) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "invalid property"));
			return (zfs_error(hdl, EZFS_BADPROP, errbuf));
		}

		(void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));
		(void) strlcpy(zc.zc_value, propname, sizeof (zc.zc_value));

		if (ioctl(zhp->zfs_hdl->libzfs_fd,
		    ZFS_IOC_SET_PROP, &zc) != 0)
			return (zfs_standard_error(hdl, errno, errbuf));

		return (0);
	}

	/*
	 * Verify that this property is inheritable.
	 */
	if (zfs_prop_readonly(prop))
		return (zfs_error(hdl, EZFS_PROPREADONLY, errbuf));

	if (!zfs_prop_inheritable(prop))
		return (zfs_error(hdl, EZFS_PROPNONINHERIT, errbuf));

	/*
	 * Check to see if the value applies to this type
	 */
	if (!zfs_prop_valid_for_type(prop, zhp->zfs_type))
		return (zfs_error(hdl, EZFS_PROPTYPE, errbuf));

	(void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));
	(void) strlcpy(zc.zc_value, propname, sizeof (zc.zc_value));

	if (prop == ZFS_PROP_MOUNTPOINT && getzoneid() == GLOBAL_ZONEID &&
	    zfs_prop_get_int(zhp, ZFS_PROP_ZONED)) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "dataset is used in a non-global zone"));
		return (zfs_error(hdl, EZFS_ZONED, errbuf));
	}

	/*
	 * Determine datasets which will be affected by this change, if any.
	 */
	if ((cl = changelist_gather(zhp, prop, 0)) == NULL)
		return (-1);

	if (prop == ZFS_PROP_MOUNTPOINT && changelist_haszonedchild(cl)) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "child dataset with inherited mountpoint is used "
		    "in a non-global zone"));
		ret = zfs_error(hdl, EZFS_ZONED, errbuf);
		goto error;
	}

	if ((ret = changelist_prefix(cl)) != 0)
		goto error;

	if ((ret = ioctl(zhp->zfs_hdl->libzfs_fd,
	    ZFS_IOC_SET_PROP, &zc)) != 0) {
		return (zfs_standard_error(hdl, errno, errbuf));
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
static int
get_numeric_property(zfs_handle_t *zhp, zfs_prop_t prop, zfs_source_t *src,
    char **source, uint64_t *val)
{
	struct mnttab mnt;

	*source = NULL;

	/*
	 * Because looking up the mount options is potentially expensive
	 * (iterating over all of /etc/mnttab), we defer its calculation until
	 * we're looking up a property which requires its presence.
	 */
	if (!zhp->zfs_mntcheck &&
	    (prop == ZFS_PROP_ATIME ||
	    prop == ZFS_PROP_DEVICES ||
	    prop == ZFS_PROP_EXEC ||
	    prop == ZFS_PROP_READONLY ||
	    prop == ZFS_PROP_SETUID ||
	    prop == ZFS_PROP_MOUNTED)) {
		struct mnttab search = { 0 }, entry;

		search.mnt_special = (char *)zhp->zfs_name;
		search.mnt_fstype = MNTTYPE_ZFS;
		rewind(zhp->zfs_hdl->libzfs_mnttab);

		if (getmntany(zhp->zfs_hdl->libzfs_mnttab, &entry,
		    &search) == 0 && (zhp->zfs_mntopts =
		    zfs_strdup(zhp->zfs_hdl,
		    entry.mnt_mntopts)) == NULL)
			return (-1);

		zhp->zfs_mntcheck = B_TRUE;
	}

	if (zhp->zfs_mntopts == NULL)
		mnt.mnt_mntopts = "";
	else
		mnt.mnt_mntopts = zhp->zfs_mntopts;

	switch (prop) {
	case ZFS_PROP_ATIME:
		*val = getprop_uint64(zhp, prop, source);

		if (hasmntopt(&mnt, MNTOPT_ATIME) && !*val) {
			*val = B_TRUE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		} else if (hasmntopt(&mnt, MNTOPT_NOATIME) && *val) {
			*val = B_FALSE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		}
		break;

	case ZFS_PROP_AVAILABLE:
		*val = zhp->zfs_dmustats.dds_available;
		break;

	case ZFS_PROP_DEVICES:
		*val = getprop_uint64(zhp, prop, source);

		if (hasmntopt(&mnt, MNTOPT_DEVICES) && !*val) {
			*val = B_TRUE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		} else if (hasmntopt(&mnt, MNTOPT_NODEVICES) && *val) {
			*val = B_FALSE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		}
		break;

	case ZFS_PROP_EXEC:
		*val = getprop_uint64(zhp, prop, source);

		if (hasmntopt(&mnt, MNTOPT_EXEC) && !*val) {
			*val = B_TRUE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		} else if (hasmntopt(&mnt, MNTOPT_NOEXEC) && *val) {
			*val = B_FALSE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		}
		break;

	case ZFS_PROP_RECORDSIZE:
	case ZFS_PROP_COMPRESSION:
	case ZFS_PROP_ZONED:
		*val = getprop_uint64(zhp, prop, source);
		break;

	case ZFS_PROP_READONLY:
		*val = getprop_uint64(zhp, prop, source);

		if (hasmntopt(&mnt, MNTOPT_RO) && !*val) {
			*val = B_TRUE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		} else if (hasmntopt(&mnt, MNTOPT_RW) && *val) {
			*val = B_FALSE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		}
		break;

	case ZFS_PROP_CREATION:
		*val = zhp->zfs_dmustats.dds_creation_time;
		break;

	case ZFS_PROP_QUOTA:
		if (zhp->zfs_dmustats.dds_quota == 0)
			*source = "";	/* default */
		else
			*source = zhp->zfs_name;
		*val = zhp->zfs_dmustats.dds_quota;
		break;

	case ZFS_PROP_RESERVATION:
		if (zhp->zfs_dmustats.dds_reserved == 0)
			*source = "";	/* default */
		else
			*source = zhp->zfs_name;
		*val = zhp->zfs_dmustats.dds_reserved;
		break;

	case ZFS_PROP_COMPRESSRATIO:
		/*
		 * Using physical space and logical space, calculate the
		 * compression ratio.  We return the number as a multiple of
		 * 100, so '2.5x' would be returned as 250.
		 */
		if (zhp->zfs_dmustats.dds_compressed_bytes == 0)
			*val = 100ULL;
		else
			*val =
			    (zhp->zfs_dmustats.dds_uncompressed_bytes * 100 /
			    zhp->zfs_dmustats.dds_compressed_bytes);
		break;

	case ZFS_PROP_REFERENCED:
		/*
		 * 'referenced' refers to the amount of physical space
		 * referenced (possibly shared) by this object.
		 */
		*val = zhp->zfs_dmustats.dds_space_refd;
		break;

	case ZFS_PROP_SETUID:
		*val = getprop_uint64(zhp, prop, source);

		if (hasmntopt(&mnt, MNTOPT_SETUID) && !*val) {
			*val = B_TRUE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		} else if (hasmntopt(&mnt, MNTOPT_NOSETUID) && *val) {
			*val = B_FALSE;
			if (src)
				*src = ZFS_SRC_TEMPORARY;
		}
		break;

	case ZFS_PROP_VOLSIZE:
		*val = zhp->zfs_volstats.zv_volsize;
		break;

	case ZFS_PROP_VOLBLOCKSIZE:
		*val = zhp->zfs_volstats.zv_volblocksize;
		break;

	case ZFS_PROP_USED:
		*val = zhp->zfs_dmustats.dds_space_used;
		break;

	case ZFS_PROP_CREATETXG:
		*val = zhp->zfs_dmustats.dds_creation_txg;
		break;

	case ZFS_PROP_MOUNTED:
		*val = (zhp->zfs_mntopts != NULL);
		break;

	case ZFS_PROP_CANMOUNT:
		*val = getprop_uint64(zhp, prop, source);
		break;

	default:
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "cannot get non-numeric property"));
		return (zfs_error(zhp->zfs_hdl, EZFS_BADPROP,
		    dgettext(TEXT_DOMAIN, "internal error")));
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
    zfs_source_t *src, char *statbuf, size_t statlen, boolean_t literal)
{
	char *source = NULL;
	uint64_t val;
	char *str;
	const char *root;
	const char *strval;

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
	case ZFS_PROP_CANMOUNT:
		/*
		 * Basic boolean values are built on top of
		 * get_numeric_property().
		 */
		if (get_numeric_property(zhp, prop, src, &source, &val) != 0)
			return (-1);
		nicebool(val, propbuf, proplen);

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
		if (get_numeric_property(zhp, prop, src, &source, &val) != 0)
			return (-1);
		if (literal)
			(void) snprintf(propbuf, proplen, "%llu",
			(u_longlong_t)val);
		else
			zfs_nicenum(val, propbuf, proplen);
		break;

	case ZFS_PROP_COMPRESSION:
	case ZFS_PROP_CHECKSUM:
	case ZFS_PROP_SNAPDIR:
	case ZFS_PROP_ACLMODE:
	case ZFS_PROP_ACLINHERIT:
		val = getprop_uint64(zhp, prop, &source);
		verify(zfs_prop_index_to_string(prop, val, &strval) == 0);
		(void) strlcpy(propbuf, strval, proplen);
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
				    (u_longlong_t)
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
		root = zhp->zfs_root;
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
		(void) strlcpy(propbuf, zhp->zfs_dmustats.dds_clone_of,
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
		if (get_numeric_property(zhp, prop, src, &source, &val) != 0)
			return (-1);

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
				(void) snprintf(propbuf, proplen, "%llu",
				(u_longlong_t)val);
			else
				zfs_nicenum(val, propbuf, proplen);
		}
		break;

	case ZFS_PROP_COMPRESSRATIO:
		if (get_numeric_property(zhp, prop, src, &source, &val) != 0)
			return (-1);
		(void) snprintf(propbuf, proplen, "%lld.%02lldx", (longlong_t)
		    val / 100, (longlong_t)val % 100);
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
			abort();
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
		if (get_numeric_property(zhp, ZFS_PROP_MOUNTED,
		    src, &source, &val) != 0)
			return (-1);
		if (val)
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
		abort();
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
	uint64_t val;

	(void) get_numeric_property(zhp, prop, &sourcetype, &source, &val);

	return (val);
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
		return (zfs_error(zhp->zfs_hdl, EZFS_PROPTYPE,
		    dgettext(TEXT_DOMAIN, "cannot get property '%s'"),
		    zfs_prop_to_name(prop)));

	if (src)
		*src = ZFS_SRC_NONE;

	if (get_numeric_property(zhp, prop, src, &source, value) != 0)
		return (-1);

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
	    ioctl(zhp->zfs_hdl->libzfs_fd, ZFS_IOC_DATASET_LIST_NEXT, &zc) == 0;
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
		if ((nzhp = make_dataset_handle(zhp->zfs_hdl,
		    zc.zc_name)) == NULL)
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
		return (zfs_standard_error(zhp->zfs_hdl, errno,
		    dgettext(TEXT_DOMAIN, "cannot iterate filesystems")));

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
	    ioctl(zhp->zfs_hdl->libzfs_fd, ZFS_IOC_SNAPSHOT_LIST_NEXT,
	    &zc) == 0;
	    (void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name))) {

		if ((nzhp = make_dataset_handle(zhp->zfs_hdl,
		    zc.zc_name)) == NULL)
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
		return (zfs_standard_error(zhp->zfs_hdl, errno,
		    dgettext(TEXT_DOMAIN, "cannot iterate filesystems")));

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
 * Checks to make sure that the given path has a parent, and that it exists.  We
 * also fetch the 'zoned' property, which is used to validate property settings
 * when creating new datasets.
 */
static int
check_parents(libzfs_handle_t *hdl, const char *path, uint64_t *zoned)
{
	zfs_cmd_t zc = { 0 };
	char parent[ZFS_MAXNAMELEN];
	char *slash;
	zfs_handle_t *zhp;
	char errbuf[1024];

	(void) snprintf(errbuf, sizeof (errbuf), "cannot create '%s'",
	    path);

	/* get parent, and check to see if this is just a pool */
	if (parent_name(path, parent, sizeof (parent)) != 0) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "missing dataset name"));
		return (zfs_error(hdl, EZFS_INVALIDNAME, errbuf));
	}

	/* check to see if the pool exists */
	if ((slash = strchr(parent, '/')) == NULL)
		slash = parent + strlen(parent);
	(void) strncpy(zc.zc_name, parent, slash - parent);
	zc.zc_name[slash - parent] = '\0';
	if (ioctl(hdl->libzfs_fd, ZFS_IOC_OBJSET_STATS, &zc) != 0 &&
	    errno == ENOENT) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "no such pool '%s'"), zc.zc_name);
		return (zfs_error(hdl, EZFS_NOENT, errbuf));
	}

	/* check to see if the parent dataset exists */
	if ((zhp = make_dataset_handle(hdl, parent)) == NULL) {
		switch (errno) {
		case ENOENT:
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "parent does not exist"));
			return (zfs_error(hdl, EZFS_NOENT, errbuf));

		default:
			return (zfs_standard_error(hdl, errno, errbuf));
		}
	}

	*zoned = zfs_prop_get_int(zhp, ZFS_PROP_ZONED);
	/* we are in a non-global zone, but parent is in the global zone */
	if (getzoneid() != GLOBAL_ZONEID && !(*zoned)) {
		(void) zfs_standard_error(hdl, EPERM, errbuf);
		zfs_close(zhp);
		return (-1);
	}

	/* make sure parent is a filesystem */
	if (zfs_get_type(zhp) != ZFS_TYPE_FILESYSTEM) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "parent is not a filesystem"));
		(void) zfs_error(hdl, EZFS_BADTYPE, errbuf);
		zfs_close(zhp);
		return (-1);
	}

	zfs_close(zhp);
	return (0);
}

/*
 * Create a new filesystem or volume.
 */
int
zfs_create(libzfs_handle_t *hdl, const char *path, zfs_type_t type,
    nvlist_t *props)
{
	zfs_cmd_t zc = { 0 };
	int ret;
	uint64_t size = 0;
	uint64_t blocksize = zfs_prop_default_numeric(ZFS_PROP_VOLBLOCKSIZE);
	char errbuf[1024];
	uint64_t zoned;

	(void) snprintf(errbuf, sizeof (errbuf), dgettext(TEXT_DOMAIN,
	    "cannot create '%s'"), path);

	/* validate the path, taking care to note the extended error message */
	if (!zfs_validate_name(hdl, path, type))
		return (zfs_error(hdl, EZFS_INVALIDNAME, errbuf));

	/* validate parents exist */
	if (check_parents(hdl, path, &zoned) != 0)
		return (-1);

	/*
	 * The failure modes when creating a dataset of a different type over
	 * one that already exists is a little strange.  In particular, if you
	 * try to create a dataset on top of an existing dataset, the ioctl()
	 * will return ENOENT, not EEXIST.  To prevent this from happening, we
	 * first try to see if the dataset exists.
	 */
	(void) strlcpy(zc.zc_name, path, sizeof (zc.zc_name));
	if (ioctl(hdl->libzfs_fd, ZFS_IOC_OBJSET_STATS, &zc) == 0) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "dataset already exists"));
		return (zfs_error(hdl, EZFS_EXISTS, errbuf));
	}

	if (type == ZFS_TYPE_VOLUME)
		zc.zc_objset_type = DMU_OST_ZVOL;
	else
		zc.zc_objset_type = DMU_OST_ZFS;

	if (props && (props = zfs_validate_properties(hdl, type, props, zoned,
	    NULL, errbuf)) == 0)
		return (-1);

	if (type == ZFS_TYPE_VOLUME) {
		/*
		 * If we are creating a volume, the size and block size must
		 * satisfy a few restraints.  First, the blocksize must be a
		 * valid block size between SPA_{MIN,MAX}BLOCKSIZE.  Second, the
		 * volsize must be a multiple of the block size, and cannot be
		 * zero.
		 */
		if (props == NULL || nvlist_lookup_uint64(props,
		    zfs_prop_to_name(ZFS_PROP_VOLSIZE), &size) != 0) {
			nvlist_free(props);
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "missing volume size"));
			return (zfs_error(hdl, EZFS_BADPROP, errbuf));
		}

		if ((ret = nvlist_lookup_uint64(props,
		    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE),
		    &blocksize)) != 0) {
			if (ret == ENOENT) {
				blocksize = zfs_prop_default_numeric(
				    ZFS_PROP_VOLBLOCKSIZE);
			} else {
				nvlist_free(props);
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "missing volume block size"));
				return (zfs_error(hdl, EZFS_BADPROP, errbuf));
			}
		}

		if (size == 0) {
			nvlist_free(props);
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "volume size cannot be zero"));
			return (zfs_error(hdl, EZFS_BADPROP, errbuf));
		}

		if (size % blocksize != 0) {
			nvlist_free(props);
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "volume size must be a multiple of volume block "
			    "size"));
			return (zfs_error(hdl, EZFS_BADPROP, errbuf));
		}
	}

	if (props &&
	    zcmd_write_src_nvlist(hdl, &zc, props, NULL) != 0)
		return (-1);
	nvlist_free(props);

	/* create the dataset */
	ret = ioctl(hdl->libzfs_fd, ZFS_IOC_CREATE, &zc);

	if (ret == 0 && type == ZFS_TYPE_VOLUME)
		ret = zvol_create_link(hdl, path);

	zcmd_free_nvlists(&zc);

	/* check for failure */
	if (ret != 0) {
		char parent[ZFS_MAXNAMELEN];
		(void) parent_name(path, parent, sizeof (parent));

		switch (errno) {
		case ENOENT:
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "no such parent '%s'"), parent);
			return (zfs_error(hdl, EZFS_NOENT, errbuf));

		case EINVAL:
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "parent '%s' is not a filesysem"), parent);
			return (zfs_error(hdl, EZFS_BADTYPE, errbuf));

		case EDOM:
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "volume block size must be power of 2 from "
			    "%u to %uk"),
			    (uint_t)SPA_MINBLOCKSIZE,
			    (uint_t)SPA_MAXBLOCKSIZE >> 10);

			return (zfs_error(hdl, EZFS_BADPROP, errbuf));

#ifdef _ILP32
		case EOVERFLOW:
			/*
			 * This platform can't address a volume this big.
			 */
			if (type == ZFS_TYPE_VOLUME)
				return (zfs_error(hdl, EZFS_VOLTOOBIG,
				    errbuf));
#endif
			/* FALLTHROUGH */
		default:
			return (zfs_standard_error(hdl, errno, errbuf));
		}
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

	if (ZFS_IS_VOLUME(zhp)) {
		if (zvol_remove_link(zhp->zfs_hdl, zhp->zfs_name) != 0)
			return (-1);

		zc.zc_objset_type = DMU_OST_ZVOL;
	} else {
		zc.zc_objset_type = DMU_OST_ZFS;
	}

	ret = ioctl(zhp->zfs_hdl->libzfs_fd, ZFS_IOC_DESTROY, &zc);
	if (ret != 0) {
		return (zfs_standard_error(zhp->zfs_hdl, errno,
		    dgettext(TEXT_DOMAIN, "cannot destroy '%s'"),
		    zhp->zfs_name));
	}

	remove_mountpoint(zhp);

	return (0);
}

struct destroydata {
	char *snapname;
	boolean_t gotone;
};

static int
zfs_remove_link_cb(zfs_handle_t *zhp, void *arg)
{
	struct destroydata *dd = arg;
	zfs_handle_t *szhp;
	char name[ZFS_MAXNAMELEN];

	(void) strlcpy(name, zhp->zfs_name, sizeof (name));
	(void) strlcat(name, "@", sizeof (name));
	(void) strlcat(name, dd->snapname, sizeof (name));

	szhp = make_dataset_handle(zhp->zfs_hdl, name);
	if (szhp) {
		dd->gotone = B_TRUE;
		zfs_close(szhp);
	}

	if (zhp->zfs_type == ZFS_TYPE_VOLUME) {
		(void) zvol_remove_link(zhp->zfs_hdl, name);
		/*
		 * NB: this is simply a best-effort.  We don't want to
		 * return an error, because then we wouldn't visit all
		 * the volumes.
		 */
	}

	return (zfs_iter_filesystems(zhp, zfs_remove_link_cb, arg));
}

/*
 * Destroys all snapshots with the given name in zhp & descendants.
 */
int
zfs_destroy_snaps(zfs_handle_t *zhp, char *snapname)
{
	zfs_cmd_t zc = { 0 };
	int ret;
	struct destroydata dd = { 0 };

	dd.snapname = snapname;
	(void) zfs_remove_link_cb(zhp, &dd);

	if (!dd.gotone) {
		return (zfs_standard_error(zhp->zfs_hdl, ENOENT,
		    dgettext(TEXT_DOMAIN, "cannot destroy '%s@%s'"),
		    zhp->zfs_name, snapname));
	}

	(void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));
	(void) strlcpy(zc.zc_value, snapname, sizeof (zc.zc_value));

	ret = ioctl(zhp->zfs_hdl->libzfs_fd, ZFS_IOC_DESTROY_SNAPS, &zc);
	if (ret != 0) {
		char errbuf[1024];

		(void) snprintf(errbuf, sizeof (errbuf), dgettext(TEXT_DOMAIN,
		    "cannot destroy '%s@%s'"), zc.zc_name, snapname);

		switch (errno) {
		case EEXIST:
			zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
			    "snapshot is cloned"));
			return (zfs_error(zhp->zfs_hdl, EZFS_EXISTS, errbuf));

		default:
			return (zfs_standard_error(zhp->zfs_hdl, errno,
			    errbuf));
		}
	}

	return (0);
}

/*
 * Clones the given dataset.  The target must be of the same type as the source.
 */
int
zfs_clone(zfs_handle_t *zhp, const char *target, nvlist_t *props)
{
	zfs_cmd_t zc = { 0 };
	char parent[ZFS_MAXNAMELEN];
	int ret;
	char errbuf[1024];
	libzfs_handle_t *hdl = zhp->zfs_hdl;
	zfs_type_t type;
	uint64_t zoned;

	assert(zhp->zfs_type == ZFS_TYPE_SNAPSHOT);

	(void) snprintf(errbuf, sizeof (errbuf), dgettext(TEXT_DOMAIN,
	    "cannot create '%s'"), target);

	/* validate the target name */
	if (!zfs_validate_name(hdl, target, ZFS_TYPE_FILESYSTEM))
		return (zfs_error(hdl, EZFS_INVALIDNAME, errbuf));

	/* validate parents exist */
	if (check_parents(hdl, target, &zoned) != 0)
		return (-1);

	(void) parent_name(target, parent, sizeof (parent));

	/* do the clone */
	if (ZFS_IS_VOLUME(zhp)) {
		zc.zc_objset_type = DMU_OST_ZVOL;
		type = ZFS_TYPE_VOLUME;
	} else {
		zc.zc_objset_type = DMU_OST_ZFS;
		type = ZFS_TYPE_FILESYSTEM;
	}

	if (props) {
		if ((props = zfs_validate_properties(hdl, type, props, zoned,
		    zhp, errbuf)) == NULL)
			return (-1);

		if (zcmd_write_src_nvlist(hdl, &zc, props, NULL) != 0) {
			nvlist_free(props);
			return (-1);
		}

		nvlist_free(props);
	}

	(void) strlcpy(zc.zc_name, target, sizeof (zc.zc_name));
	(void) strlcpy(zc.zc_value, zhp->zfs_name, sizeof (zc.zc_value));
	ret = ioctl(zhp->zfs_hdl->libzfs_fd, ZFS_IOC_CREATE, &zc);

	zcmd_free_nvlists(&zc);

	if (ret != 0) {
		switch (errno) {

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
			zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
			    "no such parent '%s'"), parent);
			return (zfs_error(zhp->zfs_hdl, EZFS_NOENT, errbuf));

		case EXDEV:
			zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
			    "source and target pools differ"));
			return (zfs_error(zhp->zfs_hdl, EZFS_CROSSTARGET,
			    errbuf));

		default:
			return (zfs_standard_error(zhp->zfs_hdl, errno,
			    errbuf));
		}
	} else if (ZFS_IS_VOLUME(zhp)) {
		ret = zvol_create_link(zhp->zfs_hdl, target);
	}

	return (ret);
}

typedef struct promote_data {
	char cb_mountpoint[MAXPATHLEN];
	const char *cb_target;
	const char *cb_errbuf;
	uint64_t cb_pivot_txg;
} promote_data_t;

static int
promote_snap_cb(zfs_handle_t *zhp, void *data)
{
	promote_data_t *pd = data;
	zfs_handle_t *szhp;
	char snapname[MAXPATHLEN];

	/* We don't care about snapshots after the pivot point */
	if (zfs_prop_get_int(zhp, ZFS_PROP_CREATETXG) > pd->cb_pivot_txg)
		return (0);

	/* Remove the device link if it's a zvol. */
	if (ZFS_IS_VOLUME(zhp))
		(void) zvol_remove_link(zhp->zfs_hdl, zhp->zfs_name);

	/* Check for conflicting names */
	(void) strlcpy(snapname, pd->cb_target, sizeof (snapname));
	(void) strlcat(snapname, strchr(zhp->zfs_name, '@'), sizeof (snapname));
	szhp = make_dataset_handle(zhp->zfs_hdl, snapname);
	if (szhp != NULL) {
		zfs_close(szhp);
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "snapshot name '%s' from origin \n"
		    "conflicts with '%s' from target"),
		    zhp->zfs_name, snapname);
		return (zfs_error(zhp->zfs_hdl, EZFS_EXISTS, pd->cb_errbuf));
	}
	return (0);
}

static int
promote_snap_done_cb(zfs_handle_t *zhp, void *data)
{
	promote_data_t *pd = data;

	/* We don't care about snapshots after the pivot point */
	if (zfs_prop_get_int(zhp, ZFS_PROP_CREATETXG) > pd->cb_pivot_txg)
		return (0);

	/* Create the device link if it's a zvol. */
	if (ZFS_IS_VOLUME(zhp))
		(void) zvol_create_link(zhp->zfs_hdl, zhp->zfs_name);

	return (0);
}

/*
 * Promotes the given clone fs to be the clone parent.
 */
int
zfs_promote(zfs_handle_t *zhp)
{
	libzfs_handle_t *hdl = zhp->zfs_hdl;
	zfs_cmd_t zc = { 0 };
	char parent[MAXPATHLEN];
	char *cp;
	int ret;
	zfs_handle_t *pzhp;
	promote_data_t pd;
	char errbuf[1024];

	(void) snprintf(errbuf, sizeof (errbuf), dgettext(TEXT_DOMAIN,
	    "cannot promote '%s'"), zhp->zfs_name);

	if (zhp->zfs_type == ZFS_TYPE_SNAPSHOT) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "snapshots can not be promoted"));
		return (zfs_error(hdl, EZFS_BADTYPE, errbuf));
	}

	(void) strlcpy(parent, zhp->zfs_dmustats.dds_clone_of, sizeof (parent));
	if (parent[0] == '\0') {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "not a cloned filesystem"));
		return (zfs_error(hdl, EZFS_BADTYPE, errbuf));
	}
	cp = strchr(parent, '@');
	*cp = '\0';

	/* Walk the snapshots we will be moving */
	pzhp = zfs_open(hdl, zhp->zfs_dmustats.dds_clone_of, ZFS_TYPE_SNAPSHOT);
	if (pzhp == NULL)
		return (-1);
	pd.cb_pivot_txg = zfs_prop_get_int(pzhp, ZFS_PROP_CREATETXG);
	zfs_close(pzhp);
	pd.cb_target = zhp->zfs_name;
	pd.cb_errbuf = errbuf;
	pzhp = zfs_open(hdl, parent, ZFS_TYPE_ANY);
	if (pzhp == NULL)
		return (-1);
	(void) zfs_prop_get(pzhp, ZFS_PROP_MOUNTPOINT, pd.cb_mountpoint,
	    sizeof (pd.cb_mountpoint), NULL, NULL, 0, FALSE);
	ret = zfs_iter_snapshots(pzhp, promote_snap_cb, &pd);
	if (ret != 0) {
		zfs_close(pzhp);
		return (-1);
	}

	/* issue the ioctl */
	(void) strlcpy(zc.zc_value, zhp->zfs_dmustats.dds_clone_of,
	    sizeof (zc.zc_value));
	(void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));
	ret = ioctl(hdl->libzfs_fd, ZFS_IOC_PROMOTE, &zc);

	if (ret != 0) {
		int save_errno = errno;

		(void) zfs_iter_snapshots(pzhp, promote_snap_done_cb, &pd);
		zfs_close(pzhp);

		switch (save_errno) {
		case EEXIST:
			/*
			 * There is a conflicting snapshot name.  We
			 * should have caught this above, but they could
			 * have renamed something in the mean time.
			 */
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "conflicting snapshot name from parent '%s'"),
			    parent);
			return (zfs_error(hdl, EZFS_EXISTS, errbuf));

		default:
			return (zfs_standard_error(hdl, save_errno, errbuf));
		}
	} else {
		(void) zfs_iter_snapshots(zhp, promote_snap_done_cb, &pd);
	}

	zfs_close(pzhp);
	return (ret);
}

static int
zfs_create_link_cb(zfs_handle_t *zhp, void *arg)
{
	char *snapname = arg;
	int ret;

	if (zhp->zfs_type == ZFS_TYPE_VOLUME) {
		char name[MAXPATHLEN];

		(void) strlcpy(name, zhp->zfs_name, sizeof (name));
		(void) strlcat(name, "@", sizeof (name));
		(void) strlcat(name, snapname, sizeof (name));
		(void) zvol_create_link(zhp->zfs_hdl, name);
		/*
		 * NB: this is simply a best-effort.  We don't want to
		 * return an error, because then we wouldn't visit all
		 * the volumes.
		 */
	}

	ret = zfs_iter_filesystems(zhp, zfs_create_link_cb, snapname);

	zfs_close(zhp);

	return (ret);
}

/*
 * Takes a snapshot of the given dataset
 */
int
zfs_snapshot(libzfs_handle_t *hdl, const char *path, boolean_t recursive)
{
	const char *delim;
	char *parent;
	zfs_handle_t *zhp;
	zfs_cmd_t zc = { 0 };
	int ret;
	char errbuf[1024];

	(void) snprintf(errbuf, sizeof (errbuf), dgettext(TEXT_DOMAIN,
	    "cannot snapshot '%s'"), path);

	/* validate the target name */
	if (!zfs_validate_name(hdl, path, ZFS_TYPE_SNAPSHOT))
		return (zfs_error(hdl, EZFS_INVALIDNAME, errbuf));

	/* make sure the parent exists and is of the appropriate type */
	delim = strchr(path, '@');
	if ((parent = zfs_alloc(hdl, delim - path + 1)) == NULL)
		return (-1);
	(void) strncpy(parent, path, delim - path);
	parent[delim - path] = '\0';

	if ((zhp = zfs_open(hdl, parent, ZFS_TYPE_FILESYSTEM |
	    ZFS_TYPE_VOLUME)) == NULL) {
		free(parent);
		return (-1);
	}

	(void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));
	(void) strlcpy(zc.zc_value, delim+1, sizeof (zc.zc_value));
	zc.zc_cookie = recursive;
	ret = ioctl(zhp->zfs_hdl->libzfs_fd, ZFS_IOC_SNAPSHOT, &zc);

	/*
	 * if it was recursive, the one that actually failed will be in
	 * zc.zc_name.
	 */
	(void) snprintf(errbuf, sizeof (errbuf), dgettext(TEXT_DOMAIN,
	    "cannot create snapshot '%s@%s'"), zc.zc_name, zc.zc_value);
	if (ret == 0 && recursive) {
		(void) zfs_iter_filesystems(zhp,
		    zfs_create_link_cb, (char *)delim+1);
	}
	if (ret == 0 && zhp->zfs_type == ZFS_TYPE_VOLUME) {
		ret = zvol_create_link(zhp->zfs_hdl, path);
		if (ret != 0) {
			(void) ioctl(zhp->zfs_hdl->libzfs_fd, ZFS_IOC_DESTROY,
			    &zc);
		}
	}

	if (ret != 0)
		(void) zfs_standard_error(hdl, errno, errbuf);

	free(parent);
	zfs_close(zhp);

	return (ret);
}

/*
 * Dumps a backup of tosnap, incremental from fromsnap if it isn't NULL.
 */
int
zfs_send(zfs_handle_t *zhp_to, zfs_handle_t *zhp_from)
{
	zfs_cmd_t zc = { 0 };
	int ret;
	char errbuf[1024];
	libzfs_handle_t *hdl = zhp_to->zfs_hdl;

	(void) snprintf(errbuf, sizeof (errbuf), dgettext(TEXT_DOMAIN,
	    "cannot send '%s'"), zhp_to->zfs_name);

	/* do the ioctl() */
	(void) strlcpy(zc.zc_name, zhp_to->zfs_name, sizeof (zc.zc_name));
	if (zhp_from) {
		(void) strlcpy(zc.zc_value, zhp_from->zfs_name,
		    sizeof (zc.zc_name));
	} else {
		zc.zc_value[0] = '\0';
	}
	zc.zc_cookie = STDOUT_FILENO;

	ret = ioctl(zhp_to->zfs_hdl->libzfs_fd, ZFS_IOC_SENDBACKUP, &zc);
	if (ret != 0) {
		switch (errno) {

		case EXDEV:
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "not an ealier snapshot from the same fs"));
			return (zfs_error(hdl, EZFS_CROSSTARGET, errbuf));

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
			zfs_error_aux(hdl, strerror(errno));
			return (zfs_error(hdl, EZFS_BADBACKUP, errbuf));

		default:
			return (zfs_standard_error(hdl, errno, errbuf));
		}
	}

	return (ret);
}

/*
 * Restores a backup of tosnap from stdin.
 */
int
zfs_receive(libzfs_handle_t *hdl, const char *tosnap, int isprefix,
    int verbose, int dryrun, boolean_t force)
{
	zfs_cmd_t zc = { 0 };
	time_t begin_time;
	int ioctl_err, err, bytes, size;
	char *cp;
	dmu_replay_record_t drr;
	struct drr_begin *drrb = &zc.zc_begin_record;
	char errbuf[1024];
	prop_changelist_t *clp;

	begin_time = time(NULL);

	(void) snprintf(errbuf, sizeof (errbuf), dgettext(TEXT_DOMAIN,
	    "cannot receive"));

	/* trim off snapname, if any */
	(void) strlcpy(zc.zc_name, tosnap, sizeof (zc.zc_name));
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
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "invalid "
		    "stream (failed to read first record)"));
		return (zfs_error(hdl, EZFS_BADSTREAM, errbuf));
	}

	zc.zc_begin_record = drr.drr_u.drr_begin;

	if (drrb->drr_magic != DMU_BACKUP_MAGIC &&
	    drrb->drr_magic != BSWAP_64(DMU_BACKUP_MAGIC)) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "invalid "
		    "stream (bad magic number)"));
		return (zfs_error(hdl, EZFS_BADSTREAM, errbuf));
	}

	if (drrb->drr_version != DMU_BACKUP_VERSION &&
	    drrb->drr_version != BSWAP_64(DMU_BACKUP_VERSION)) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "only version "
		    "0x%llx is supported (stream is version 0x%llx)"),
		    DMU_BACKUP_VERSION, drrb->drr_version);
		return (zfs_error(hdl, EZFS_BADSTREAM, errbuf));
	}

	/*
	 * Determine name of destination snapshot.
	 */
	(void) strlcpy(zc.zc_value, tosnap, sizeof (zc.zc_value));
	if (isprefix) {
		if (strchr(tosnap, '@') != NULL) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "destination must be a filesystem"));
			return (zfs_error(hdl, EZFS_BADTYPE, errbuf));
		}

		cp = strchr(drr.drr_u.drr_begin.drr_toname, '/');
		if (cp == NULL)
			cp = drr.drr_u.drr_begin.drr_toname;
		else
			cp++;

		(void) strcat(zc.zc_value, "/");
		(void) strcat(zc.zc_value, cp);
	} else if (strchr(tosnap, '@') == NULL) {
		/*
		 * they specified just a filesystem; tack on the
		 * snapname from the backup.
		 */
		cp = strchr(drr.drr_u.drr_begin.drr_toname, '@');
		if (cp == NULL || strlen(tosnap) + strlen(cp) >= MAXNAMELEN)
			return (zfs_error(hdl, EZFS_INVALIDNAME, errbuf));
		(void) strcat(zc.zc_value, cp);
	}

	if (drrb->drr_fromguid) {
		zfs_handle_t *h;
		/* incremental backup stream */

		/* do the ioctl to the containing fs */
		(void) strlcpy(zc.zc_name, zc.zc_value, sizeof (zc.zc_name));
		cp = strchr(zc.zc_name, '@');
		*cp = '\0';

		/* make sure destination fs exists */
		h = zfs_open(hdl, zc.zc_name,
		    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME);
		if (h == NULL)
			return (-1);
		if (!dryrun) {
			/*
			 * We need to unmount all the dependents of the dataset
			 * and the dataset itself. If it's a volume
			 * then remove device link.
			 */
			if (h->zfs_type == ZFS_TYPE_FILESYSTEM) {
				clp = changelist_gather(h, ZFS_PROP_NAME, 0);
				if (clp == NULL)
					return (-1);
				if (changelist_prefix(clp) != 0) {
					changelist_free(clp);
					return (-1);
				}
			} else {
				(void) zvol_remove_link(hdl, h->zfs_name);
			}
		}
		zfs_close(h);
	} else {
		/* full backup stream */

		(void) strlcpy(zc.zc_name, zc.zc_value, sizeof (zc.zc_name));

		/* make sure they aren't trying to receive into the root */
		if (strchr(zc.zc_name, '/') == NULL) {
			cp = strchr(zc.zc_name, '@');
			if (cp)
				*cp = '\0';
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "destination '%s' already exists"), zc.zc_name);
			return (zfs_error(hdl, EZFS_EXISTS, errbuf));
		}

		if (isprefix) {
			zfs_handle_t *h;

			/* make sure prefix exists */
			h = zfs_open(hdl, tosnap, ZFS_TYPE_FILESYSTEM);
			if (h == NULL)
				return (-1);
			zfs_close(h);

			/* create any necessary ancestors up to prefix */
			zc.zc_objset_type = DMU_OST_ZFS;

			/*
			 * zc.zc_name is now the full name of the snap
			 * we're restoring into.  Attempt to create,
			 * mount, and share any ancestor filesystems, up
			 * to the one that was named.
			 */
			for (cp = zc.zc_name + strlen(tosnap) + 1;
			    cp = strchr(cp, '/'); *cp = '/', cp++) {
				const char *opname;
				*cp = '\0';

				opname = dgettext(TEXT_DOMAIN, "create");
				if (zfs_create(hdl, zc.zc_name,
				    ZFS_TYPE_FILESYSTEM, NULL) != 0) {
					if (errno == EEXIST)
						continue;
					goto ancestorerr;
				}

				opname = dgettext(TEXT_DOMAIN, "open");
				h = zfs_open(hdl, zc.zc_name,
				    ZFS_TYPE_FILESYSTEM);
				if (h == NULL)
					goto ancestorerr;

				opname = dgettext(TEXT_DOMAIN, "mount");
				if (zfs_mount(h, NULL, 0) != 0)
					goto ancestorerr;

				opname = dgettext(TEXT_DOMAIN, "share");
				if (zfs_share(h) != 0)
					goto ancestorerr;

				zfs_close(h);

				continue;
ancestorerr:
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "failed to %s ancestor '%s'"), opname,
				    zc.zc_name);
				return (zfs_error(hdl, EZFS_BADRESTORE,
				    errbuf));
			}
		}

		/* Make sure destination fs does not exist */
		cp = strchr(zc.zc_name, '@');
		*cp = '\0';
		if (ioctl(hdl->libzfs_fd, ZFS_IOC_OBJSET_STATS, &zc) == 0) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "destination '%s' exists"), zc.zc_name);
			return (zfs_error(hdl, EZFS_EXISTS, errbuf));
		}

		/* Do the recvbackup ioctl to the fs's parent. */
		cp = strrchr(zc.zc_name, '/');
		*cp = '\0';
	}

	zc.zc_cookie = STDIN_FILENO;
	zc.zc_guid = force;
	if (verbose) {
		(void) printf("%s %s stream of %s into %s\n",
		    dryrun ? "would receive" : "receiving",
		    drrb->drr_fromguid ? "incremental" : "full",
		    drr.drr_u.drr_begin.drr_toname,
		    zc.zc_value);
		(void) fflush(stdout);
	}
	if (dryrun)
		return (0);
	err = ioctl_err = ioctl(hdl->libzfs_fd, ZFS_IOC_RECVBACKUP, &zc);
	if (ioctl_err != 0) {
		switch (errno) {
		case ENODEV:
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "most recent snapshot does not match incremental "
			    "source"));
			(void) zfs_error(hdl, EZFS_BADRESTORE, errbuf);
			break;
		case ETXTBSY:
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "destination has been modified since most recent "
			    "snapshot"));
			(void) zfs_error(hdl, EZFS_BADRESTORE, errbuf);
			break;
		case EEXIST:
			if (drrb->drr_fromguid == 0) {
				/* it's the containing fs that exists */
				cp = strchr(zc.zc_value, '@');
				*cp = '\0';
			}
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "destination already exists"));
			(void) zfs_error(hdl, EZFS_EXISTS, dgettext(TEXT_DOMAIN,
			    "cannot restore to %s"), zc.zc_value);
			break;
		case EINVAL:
			(void) zfs_error(hdl, EZFS_BADSTREAM, errbuf);
			break;
		case ECKSUM:
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "invalid stream (checksum mismatch)"));
			(void) zfs_error(hdl, EZFS_BADSTREAM, errbuf);
			break;
		default:
			(void) zfs_standard_error(hdl, errno, errbuf);
		}
	}

	/*
	 * Mount or recreate the /dev links for the target filesystem
	 * (if created, or if we tore them down to do an incremental
	 * restore), and the /dev links for the new snapshot (if
	 * created). Also mount any children of the target filesystem
	 * if we did an incremental receive.
	 */
	cp = strchr(zc.zc_value, '@');
	if (cp && (ioctl_err == 0 || drrb->drr_fromguid)) {
		zfs_handle_t *h;

		*cp = '\0';
		h = zfs_open(hdl, zc.zc_value,
		    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME);
		*cp = '@';
		if (h) {
			if (h->zfs_type == ZFS_TYPE_VOLUME) {
				err = zvol_create_link(hdl, h->zfs_name);
				if (err == 0 && ioctl_err == 0)
					err = zvol_create_link(hdl,
					    zc.zc_value);
			} else {
				if (drrb->drr_fromguid) {
					err = changelist_postfix(clp);
					changelist_free(clp);
				} else {
					err = zfs_mount(h, NULL, 0);
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

		(void) printf("received %sb stream in %lu seconds (%sb/sec)\n",
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
	boolean_t	cb_dependent;
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

			cbp->cb_dependent = B_TRUE;
			if (zfs_iter_dependents(zhp, B_FALSE, rollback_destroy,
			    cbp) != 0)
				cbp->cb_error = 1;
			cbp->cb_dependent = B_FALSE;

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
	    zvol_remove_link(zhp->zfs_hdl, zhp->zfs_name) != 0)
		return (-1);

	(void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));

	if (ZFS_IS_VOLUME(zhp))
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
	if ((ret = ioctl(zhp->zfs_hdl->libzfs_fd, ZFS_IOC_ROLLBACK,
	    &zc)) != 0) {
		(void) zfs_standard_error(zhp->zfs_hdl, errno,
		    dgettext(TEXT_DOMAIN, "cannot rollback '%s'"),
		    zhp->zfs_name);
	} else if (zhp->zfs_type == ZFS_TYPE_VOLUME) {
		ret = zvol_create_link(zhp->zfs_hdl, zhp->zfs_name);
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
zfs_iter_dependents(zfs_handle_t *zhp, boolean_t allowrecursion,
    zfs_iter_f func, void *data)
{
	char **dependents;
	size_t count;
	int i;
	zfs_handle_t *child;
	int ret = 0;

	if (get_dependents(zhp->zfs_hdl, allowrecursion, zhp->zfs_name,
	    &dependents, &count) != 0)
		return (-1);

	for (i = 0; i < count; i++) {
		if ((child = make_dataset_handle(zhp->zfs_hdl,
		    dependents[i])) == NULL)
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
	char *delim;
	prop_changelist_t *cl;
	char parent[ZFS_MAXNAMELEN];
	libzfs_handle_t *hdl = zhp->zfs_hdl;
	char errbuf[1024];

	/* if we have the same exact name, just return success */
	if (strcmp(zhp->zfs_name, target) == 0)
		return (0);

	(void) snprintf(errbuf, sizeof (errbuf), dgettext(TEXT_DOMAIN,
	    "cannot rename to '%s'"), target);

	/*
	 * Make sure the target name is valid
	 */
	if (zhp->zfs_type == ZFS_TYPE_SNAPSHOT) {
		if ((strchr(target, '@') == NULL) ||
		    *target == '@') {
			/*
			 * Snapshot target name is abbreviated,
			 * reconstruct full dataset name
			 */
			(void) strlcpy(parent, zhp->zfs_name,
			    sizeof (parent));
			delim = strchr(parent, '@');
			if (strchr(target, '@') == NULL)
				*(++delim) = '\0';
			else
				*delim = '\0';
			(void) strlcat(parent, target, sizeof (parent));
			target = parent;
		} else {
			/*
			 * Make sure we're renaming within the same dataset.
			 */
			delim = strchr(target, '@');
			if (strncmp(zhp->zfs_name, target, delim - target)
			    != 0 || zhp->zfs_name[delim - target] != '@') {
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "snapshots must be part of same "
				    "dataset"));
				return (zfs_error(hdl, EZFS_CROSSTARGET,
					    errbuf));
			}
		}
		if (!zfs_validate_name(hdl, target, zhp->zfs_type))
			return (zfs_error(hdl, EZFS_INVALIDNAME, errbuf));
	} else {
		if (!zfs_validate_name(hdl, target, zhp->zfs_type))
			return (zfs_error(hdl, EZFS_INVALIDNAME, errbuf));
		uint64_t unused;

		/* validate parents */
		if (check_parents(hdl, target, &unused) != 0)
			return (-1);

		(void) parent_name(target, parent, sizeof (parent));

		/* make sure we're in the same pool */
		verify((delim = strchr(target, '/')) != NULL);
		if (strncmp(zhp->zfs_name, target, delim - target) != 0 ||
		    zhp->zfs_name[delim - target] != '/') {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "datasets must be within same pool"));
			return (zfs_error(hdl, EZFS_CROSSTARGET, errbuf));
		}

		/* new name cannot be a child of the current dataset name */
		if (strncmp(parent, zhp->zfs_name,
			    strlen(zhp->zfs_name)) == 0) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "New dataset name cannot be a descendent of "
			    "current dataset name"));
			return (zfs_error(hdl, EZFS_INVALIDNAME, errbuf));
		}
	}

	(void) snprintf(errbuf, sizeof (errbuf),
	    dgettext(TEXT_DOMAIN, "cannot rename '%s'"), zhp->zfs_name);

	if (getzoneid() == GLOBAL_ZONEID &&
	    zfs_prop_get_int(zhp, ZFS_PROP_ZONED)) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "dataset is used in a non-global zone"));
		return (zfs_error(hdl, EZFS_ZONED, errbuf));
	}

	if ((cl = changelist_gather(zhp, ZFS_PROP_NAME, 0)) == NULL)
		return (-1);

	if (changelist_haszonedchild(cl)) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "child dataset with inherited mountpoint is used "
		    "in a non-global zone"));
		(void) zfs_error(hdl, EZFS_ZONED, errbuf);
		goto error;
	}

	if ((ret = changelist_prefix(cl)) != 0)
		goto error;

	if (ZFS_IS_VOLUME(zhp))
		zc.zc_objset_type = DMU_OST_ZVOL;
	else
		zc.zc_objset_type = DMU_OST_ZFS;

	(void) strlcpy(zc.zc_name, zhp->zfs_name, sizeof (zc.zc_name));
	(void) strlcpy(zc.zc_value, target, sizeof (zc.zc_value));

	if ((ret = ioctl(zhp->zfs_hdl->libzfs_fd, ZFS_IOC_RENAME, &zc)) != 0) {
		(void) zfs_standard_error(zhp->zfs_hdl, errno, errbuf);

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
zvol_create_link(libzfs_handle_t *hdl, const char *dataset)
{
	zfs_cmd_t zc = { 0 };
	di_devlink_handle_t dhdl;

	(void) strlcpy(zc.zc_name, dataset, sizeof (zc.zc_name));

	/*
	 * Issue the appropriate ioctl.
	 */
	if (ioctl(hdl->libzfs_fd, ZFS_IOC_CREATE_MINOR, &zc) != 0) {
		switch (errno) {
		case EEXIST:
			/*
			 * Silently ignore the case where the link already
			 * exists.  This allows 'zfs volinit' to be run multiple
			 * times without errors.
			 */
			return (0);

		default:
			return (zfs_standard_error(hdl, errno,
			    dgettext(TEXT_DOMAIN, "cannot create device links "
			    "for '%s'"), dataset));
		}
	}

	/*
	 * Call devfsadm and wait for the links to magically appear.
	 */
	if ((dhdl = di_devlink_init(ZFS_DRIVER, DI_MAKE_LINK)) == NULL) {
		zfs_error_aux(hdl, strerror(errno));
		(void) zfs_error(hdl, EZFS_DEVLINKS,
		    dgettext(TEXT_DOMAIN, "cannot create device links "
		    "for '%s'"), dataset);
		(void) ioctl(hdl->libzfs_fd, ZFS_IOC_REMOVE_MINOR, &zc);
		return (-1);
	} else {
		(void) di_devlink_fini(&dhdl);
	}

	return (0);
}

/*
 * Remove a minor node for the given zvol and the associated /dev links.
 */
int
zvol_remove_link(libzfs_handle_t *hdl, const char *dataset)
{
	zfs_cmd_t zc = { 0 };

	(void) strlcpy(zc.zc_name, dataset, sizeof (zc.zc_name));

	if (ioctl(hdl->libzfs_fd, ZFS_IOC_REMOVE_MINOR, &zc) != 0) {
		switch (errno) {
		case ENXIO:
			/*
			 * Silently ignore the case where the link no longer
			 * exists, so that 'zfs volfini' can be run multiple
			 * times without errors.
			 */
			return (0);

		default:
			return (zfs_standard_error(hdl, errno,
			    dgettext(TEXT_DOMAIN, "cannot remove device "
			    "links for '%s'"), dataset));
		}
	}

	return (0);
}

nvlist_t *
zfs_get_user_props(zfs_handle_t *zhp)
{
	return (zhp->zfs_user_props);
}

/*
 * Given a comma-separated list of properties, contruct a property list
 * containing both user-defined and native properties.  This function will
 * return a NULL list if 'all' is specified, which can later be expanded on a
 * per-dataset basis by zfs_expand_proplist().
 */
int
zfs_get_proplist(libzfs_handle_t *hdl, char *fields, zfs_proplist_t **listp)
{
	int i;
	size_t len;
	char *s, *p;
	char c;
	zfs_prop_t prop;
	zfs_proplist_t *entry;
	zfs_proplist_t **last;

	*listp = NULL;
	last = listp;

	/*
	 * If 'all' is specified, return a NULL list.
	 */
	if (strcmp(fields, "all") == 0)
		return (0);

	/*
	 * If no fields were specified, return an error.
	 */
	if (fields[0] == '\0') {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "no properties specified"));
		return (zfs_error(hdl, EZFS_BADPROP, dgettext(TEXT_DOMAIN,
		    "bad property list")));
	}

	/*
	 * It would be nice to use getsubopt() here, but the inclusion of column
	 * aliases makes this more effort than it's worth.
	 */
	s = fields;
	while (*s != '\0') {
		if ((p = strchr(s, ',')) == NULL) {
			len = strlen(s);
			p = s + len;
		} else {
			len = p - s;
		}

		/*
		 * Check for empty options.
		 */
		if (len == 0) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "empty property name"));
			return (zfs_error(hdl, EZFS_BADPROP,
			    dgettext(TEXT_DOMAIN, "bad property list")));
		}

		/*
		 * Check all regular property names.
		 */
		c = s[len];
		s[len] = '\0';
		for (i = 0; i < ZFS_NPROP_ALL; i++) {
			if ((prop = zfs_name_to_prop(s)) != ZFS_PROP_INVAL)
				break;
		}

		/*
		 * If no column is specified, and this isn't a user property,
		 * return failure.
		 */
		if (i == ZFS_NPROP_ALL && !zfs_prop_user(s)) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "invalid property '%s'"), s);
			return (zfs_error(hdl, EZFS_BADPROP,
			    dgettext(TEXT_DOMAIN, "bad property list")));
		}

		if ((entry = zfs_alloc(hdl, sizeof (zfs_proplist_t))) == NULL)
			return (-1);

		entry->pl_prop = prop;
		if (prop == ZFS_PROP_INVAL) {
			if ((entry->pl_user_prop =
			    zfs_strdup(hdl, s)) == NULL) {
				free(entry);
				return (-1);
			}
			entry->pl_width = strlen(s);
		} else {
			entry->pl_width = zfs_prop_width(prop,
			    &entry->pl_fixed);
		}

		*last = entry;
		last = &entry->pl_next;

		s = p;
		if (c == ',')
			s++;
	}

	return (0);
}

void
zfs_free_proplist(zfs_proplist_t *pl)
{
	zfs_proplist_t *next;

	while (pl != NULL) {
		next = pl->pl_next;
		free(pl->pl_user_prop);
		free(pl);
		pl = next;
	}
}

/*
 * This function is used by 'zfs list' to determine the exact set of columns to
 * display, and their maximum widths.  This does two main things:
 *
 * 	- If this is a list of all properties, then expand the list to include
 *	  all native properties, and set a flag so that for each dataset we look
 *	  for new unique user properties and add them to the list.
 *
 * 	- For non fixed-width properties, keep track of the maximum width seen
 *	  so that we can size the column appropriately.
 */
int
zfs_expand_proplist(zfs_handle_t *zhp, zfs_proplist_t **plp)
{
	libzfs_handle_t *hdl = zhp->zfs_hdl;
	zfs_prop_t prop;
	zfs_proplist_t *entry;
	zfs_proplist_t **last, **start;
	nvlist_t *userprops, *propval;
	nvpair_t *elem;
	char *strval;
	char buf[ZFS_MAXPROPLEN];

	if (*plp == NULL) {
		/*
		 * If this is the very first time we've been called for an 'all'
		 * specification, expand the list to include all native
		 * properties.
		 */
		last = plp;
		for (prop = 0; prop < ZFS_NPROP_VISIBLE; prop++) {
			if ((entry = zfs_alloc(hdl,
			    sizeof (zfs_proplist_t))) == NULL)
				return (-1);

			entry->pl_prop = prop;
			entry->pl_width = zfs_prop_width(prop,
			    &entry->pl_fixed);
			entry->pl_all = B_TRUE;

			*last = entry;
			last = &entry->pl_next;
		}

		/*
		 * Add 'name' to the beginning of the list, which is handled
		 * specially.
		 */
		if ((entry = zfs_alloc(hdl,
		    sizeof (zfs_proplist_t))) == NULL)
			return (-1);

		entry->pl_prop = ZFS_PROP_NAME;
		entry->pl_width = zfs_prop_width(ZFS_PROP_NAME,
		    &entry->pl_fixed);
		entry->pl_all = B_TRUE;
		entry->pl_next = *plp;
		*plp = entry;
	}

	userprops = zfs_get_user_props(zhp);

	entry = *plp;
	if (entry->pl_all && nvlist_next_nvpair(userprops, NULL) != NULL) {
		/*
		 * Go through and add any user properties as necessary.  We
		 * start by incrementing our list pointer to the first
		 * non-native property.
		 */
		start = plp;
		while (*start != NULL) {
			if ((*start)->pl_prop == ZFS_PROP_INVAL)
				break;
			start = &(*start)->pl_next;
		}

		elem = NULL;
		while ((elem = nvlist_next_nvpair(userprops, elem)) != NULL) {
			/*
			 * See if we've already found this property in our list.
			 */
			for (last = start; *last != NULL;
			    last = &(*last)->pl_next) {
				if (strcmp((*last)->pl_user_prop,
				    nvpair_name(elem)) == 0)
					break;
			}

			if (*last == NULL) {
				if ((entry = zfs_alloc(hdl,
				    sizeof (zfs_proplist_t))) == NULL ||
				    ((entry->pl_user_prop = zfs_strdup(hdl,
				    nvpair_name(elem)))) == NULL) {
					free(entry);
					return (-1);
				}

				entry->pl_prop = ZFS_PROP_INVAL;
				entry->pl_width = strlen(nvpair_name(elem));
				entry->pl_all = B_TRUE;
				*last = entry;
			}
		}
	}

	/*
	 * Now go through and check the width of any non-fixed columns
	 */
	for (entry = *plp; entry != NULL; entry = entry->pl_next) {
		if (entry->pl_fixed)
			continue;

		if (entry->pl_prop != ZFS_PROP_INVAL) {
			if (zfs_prop_get(zhp, entry->pl_prop,
			    buf, sizeof (buf), NULL, NULL, 0, B_FALSE) == 0) {
				if (strlen(buf) > entry->pl_width)
					entry->pl_width = strlen(buf);
			}
		} else if (nvlist_lookup_nvlist(userprops,
		    entry->pl_user_prop, &propval)  == 0) {
			verify(nvlist_lookup_string(propval,
			    ZFS_PROP_VALUE, &strval) == 0);
			if (strlen(strval) > entry->pl_width)
				entry->pl_width = strlen(strval);
		}
	}

	return (0);
}
