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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Master property table.
 *
 * This table keeps track of all the properties supported by ZFS, and their
 * various attributes.  Not all of these are needed by the kernel, and several
 * are only used by a single libzfs client.  But having them here centralizes
 * all property information in one location.
 *
 * 	name		The human-readable string representing this property
 * 	proptype	Basic type (string, boolean, number)
 * 	default		Default value for the property.  Sadly, C only allows
 * 			you to initialize the first member of a union, so we
 * 			have two default members for each property.
 * 	attr		Attributes (readonly, inheritable) for the property
 * 	types		Valid dataset types to which this applies
 * 	values		String describing acceptable values for the property
 * 	colname		The column header for 'zfs list'
 *	colfmt		The column formatting for 'zfs list'
 *
 * This table must match the order of property types in libzfs.h.
 */

#include <sys/zio.h>
#include <sys/spa.h>
#include <sys/zfs_acl.h>
#include <sys/zfs_ioctl.h>

#include "zfs_prop.h"

#if defined(_KERNEL)
#include <sys/systm.h>
#else
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#endif

typedef enum {
	prop_default,
	prop_readonly,
	prop_inherit
} prop_attr_t;

typedef struct {
	const char	*pd_name;
	zfs_proptype_t	pd_proptype;
	uint64_t	pd_numdefault;
	const char	*pd_strdefault;
	prop_attr_t	pd_attr;
	int		pd_types;
	const char	*pd_values;
	const char	*pd_colname;
	const char	*pd_colfmt;
} prop_desc_t;

static prop_desc_t zfs_prop_table[ZFS_NPROP_ALL] = {
	{ "type",	prop_type_string,	0,	NULL,	prop_readonly,
	    ZFS_TYPE_ANY, "filesystem | volume | snapshot", "TYPE", "%10s" },
	{ "creation",	prop_type_number,	0,	NULL,	prop_readonly,
	    ZFS_TYPE_ANY, "<date>", "CREATION", "%-20s" },
	{ "used",	prop_type_number,	0,	NULL,	prop_readonly,
	    ZFS_TYPE_ANY, "<size>",	"USED", "%5s" },
	{ "available",	prop_type_number,	0,	NULL,	prop_readonly,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME, "<size>", "AVAIL", "%5s" },
	{ "referenced",	prop_type_number,	0,	NULL,	prop_readonly,
	    ZFS_TYPE_SNAPSHOT | ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME,
	    "<size>", "REFER", "%5s" },
	{ "compressratio", prop_type_number,	0,	NULL,	prop_readonly,
	    ZFS_TYPE_ANY, "<1.00x or higher if compressed>", "RATIO", "%5s" },
	{ "mounted",	prop_type_boolean,	0,	NULL,	prop_readonly,
	    ZFS_TYPE_FILESYSTEM, "yes | no | -", "MOUNTED", "%7s" },
	{ "origin",	prop_type_string,	0,	NULL,	prop_readonly,
	    ZFS_TYPE_FILESYSTEM, "<snapshot>", "ORIGIN", "%-20s" },
	{ "quota",	prop_type_number,	0,	NULL,	prop_default,
	    ZFS_TYPE_FILESYSTEM, "<size> | none", "QUOTA", "%5s" },
	{ "reservation", prop_type_number,	0,	NULL,	prop_default,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME,
	    "<size> | none", "RESERV", "%6s" },
	{ "volsize",	prop_type_number,	0,	NULL,	prop_default,
	    ZFS_TYPE_VOLUME, "<size>", "VOLSIZE", "%7s" },
	{ "volblocksize", prop_type_number,	8192,	NULL,	prop_default,
	    ZFS_TYPE_VOLUME, "512 to 128k, power of 2",	"VOLBLOCK", "%8s" },
	{ "recordsize",	prop_type_number,	SPA_MAXBLOCKSIZE,	NULL,
	    prop_inherit,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_SNAPSHOT,
	    "512 to 128k, power of 2", "RECSIZE", "%7s" },
	{ "mountpoint",	prop_type_string,	0,	"/",	prop_inherit,
	    ZFS_TYPE_FILESYSTEM,
	    "<path> | legacy | none", "MOUNTPOINT", "%-20s" },
	{ "sharenfs",	prop_type_string,	0,	"off",	prop_inherit,
	    ZFS_TYPE_FILESYSTEM,
	    "on | off | share(1M) options", "SHARENFS", "%-15s" },
	{ "checksum",	prop_type_index,	ZIO_CHECKSUM_DEFAULT,	NULL,
	    prop_inherit,	ZFS_TYPE_ANY,
	    "on | off | fletcher2 | fletcher4 | sha256", "CHECKSUM", "%10s" },
	{ "compression", prop_type_index,	ZIO_COMPRESS_DEFAULT,	NULL,
	    prop_inherit,	ZFS_TYPE_ANY,
	    "on | off | lzjb", "COMPRESS", "%8s" },
	{ "atime",	prop_type_boolean,	1,	NULL,	prop_inherit,
	    ZFS_TYPE_FILESYSTEM,
	    "on | off", "ATIME", "%5s" },
	{ "devices",	prop_type_boolean,	1,	NULL,	prop_inherit,
	    ZFS_TYPE_FILESYSTEM,
	    "on | off", "DEVICES", "%7s" },
	{ "exec",	prop_type_boolean,	1,	NULL,	prop_inherit,
	    ZFS_TYPE_FILESYSTEM,
	    "on | off", "EXEC", "%4s" },
	{ "setuid",	prop_type_boolean,	1,	NULL,	prop_inherit,
	    ZFS_TYPE_FILESYSTEM, "on | off", "SETUID", "%6s" },
	{ "readonly",	prop_type_boolean,	0,	NULL,	prop_inherit,
	    ZFS_TYPE_ANY, "on | off", "RDONLY", "%6s" },
	{ "zoned",	prop_type_boolean,	0,	NULL,	prop_inherit,
	    ZFS_TYPE_ANY,
	    "on | off", "ZONED", "%5s" },
	{ "snapdir",	prop_type_index,	ZFS_SNAPDIR_VISIBLE,	NULL,
	    prop_inherit,
	    ZFS_TYPE_FILESYSTEM,
	    "hidden | visible", "SNAPDIR", "%7s" },
	{ "aclmode", prop_type_index,	GROUPMASK,	 NULL,	prop_inherit,
	    ZFS_TYPE_FILESYSTEM,
	    "discard | groupmask | passthrough", "ACLMODE", "%11s" },
	{ "aclinherit", prop_type_index,	SECURE,	NULL, 	prop_inherit,
	    ZFS_TYPE_FILESYSTEM,
	    "discard | noallow | secure | passthrough", "ACLINHERIT", "%11s" },
	{ "createtxg",	prop_type_number,	0,	NULL,	prop_readonly,
	    ZFS_TYPE_ANY, NULL, NULL, NULL},
	{ "name",	prop_type_string,	0,	NULL,	prop_readonly,
	    ZFS_TYPE_ANY,
	    NULL, "NAME", "%-20s" },
};

zfs_proptype_t
zfs_prop_get_type(zfs_prop_t prop)
{
	return (zfs_prop_table[prop].pd_proptype);
}

/*
 * Given a property name, returns the corresponding property ID.
 */
zfs_prop_t
zfs_name_to_prop(const char *propname)
{
	int i;

	for (i = 0; i < ZFS_NPROP_ALL; i++) {
		if (strcmp(zfs_prop_table[i].pd_name, propname) == 0)
			return (i);
#ifndef _KERNEL
		if (zfs_prop_table[i].pd_colname != NULL &&
		    strcasecmp(zfs_prop_table[i].pd_colname, propname) == 0)
			return (i);
#endif
	}

	return (ZFS_PROP_INVAL);
}

/*
 * Return the default value for the given property.
 */
void
zfs_prop_default_string(zfs_prop_t prop, char *buf, size_t buflen)
{
	/*
	 * For index types (compression and checksum), we want the numeric value
	 * in the kernel, but the string value in userland.  The kernel will
	 * call zfs_prop_default_numeric() based on the property type.  In
	 * userland, the zfs_prop_is_string() will return TRUE for index types,
	 * and we'll return "on" from this function.
	 */
	if (zfs_prop_table[prop].pd_proptype == prop_type_index)
		(void) strncpy(buf, "on", buflen);
	else
		(void) strncpy(buf, zfs_prop_table[prop].pd_strdefault, buflen);
}

uint64_t
zfs_prop_default_numeric(zfs_prop_t prop)
{
	return (zfs_prop_table[prop].pd_numdefault);
}

/*
 * Returns TRUE if the property is readonly.
 */
int
zfs_prop_readonly(zfs_prop_t prop)
{
	return (zfs_prop_table[prop].pd_attr == prop_readonly);
}

#ifndef _KERNEL
/*
 * Given a property ID, returns the corresponding name.
 */
const char *
zfs_prop_to_name(zfs_prop_t prop)
{
	return (zfs_prop_table[prop].pd_name);
}

/*
 * Returns TRUE if the property is inheritable.
 */
int
zfs_prop_inheritable(zfs_prop_t prop)
{
	return (zfs_prop_table[prop].pd_attr == prop_inherit);
}

/*
 * Returns TRUE if the property applies to the given dataset types.
 */
int
zfs_prop_valid_for_type(zfs_prop_t prop, int types)
{
	return ((zfs_prop_table[prop].pd_types & types) != 0);
}

/*
 * Returns a string describing the set of acceptable values for the given
 * property, or NULL if it cannot be set.
 */
const char *
zfs_prop_values(zfs_prop_t prop)
{
	return (zfs_prop_table[prop].pd_values);
}

/*
 * Returns TRUE if this property is a string type.  Note that index types
 * (compression, checksum) are treated as strings in userland, even though they
 * are stored numerically on disk.
 */
int
zfs_prop_is_string(zfs_prop_t prop)
{
	return (zfs_prop_table[prop].pd_proptype == prop_type_string ||
	    zfs_prop_table[prop].pd_proptype == prop_type_index);
}

/*
 * Returns the column header for the given property.  Used only in
 * 'zfs list -o', but centralized here with the other property information.
 */
const char *
zfs_prop_column_name(zfs_prop_t prop)
{
	return (zfs_prop_table[prop].pd_colname);
}

/*
 * Returns the column formatting for the given property.  Used only in
 * 'zfs list -o', but centralized here with the other property information.
 */
const char *
zfs_prop_column_format(zfs_prop_t prop)
{
	return (zfs_prop_table[prop].pd_colfmt);
}

/*
 * Returns an array of names suitable for passing to getsubopt() to determine
 * the property index.
 */
char **
zfs_prop_column_subopts(void)
{
	char **ret = malloc((ZFS_NPROP_ALL + 1) * sizeof (char *));
	int i;

	for (i = 0; i < ZFS_NPROP_ALL; i++)
		ret[i] = (char *)zfs_prop_table[i].pd_name;

	ret[i] = NULL;

	return (ret);
}

/*
 * Same as above, but using the short (abbreviated) column names as indices.
 */
char **
zfs_prop_column_short_subopts(void)
{
	char **ret = malloc((ZFS_NPROP_ALL + 1) * sizeof (char *) * 2);
	char *cur;
	int i;

	for (i = 0; i < ZFS_NPROP_ALL; i++) {
		if (zfs_prop_table[i].pd_colname == NULL) {
			ret[i] = "";
		} else {
			ret[i] = strdup(zfs_prop_table[i].pd_colname);
			for (cur = ret[i]; *cur != '\0'; cur++)
				*cur = tolower(*cur);
		}
	}


	ret[i] = NULL;

	return (ret);
}

#endif
