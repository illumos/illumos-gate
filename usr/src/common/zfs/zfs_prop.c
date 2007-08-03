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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/zio.h>
#include <sys/spa.h>
#include <sys/zfs_acl.h>
#include <sys/zfs_ioctl.h>
#include <sys/zfs_znode.h>

#include "zfs_prop.h"
#include "zfs_deleg.h"

#if defined(_KERNEL)
#include <sys/systm.h>
#include <util/qsort.h>
#else
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#endif

typedef enum {
	PROP_DEFAULT,
	PROP_READONLY,
	PROP_INHERIT
} prop_attr_t;

typedef struct zfs_index {
	const char *name;
	uint64_t index;
} zfs_index_t;

typedef struct {
	const char *pd_name;		/* human-readable property name */
	zfs_proptype_t pd_proptype;	/* string, boolean, index, number */
	const char *pd_strdefault;	/* default for strings */
	uint64_t pd_numdefault;		/* for boolean / index / number */
	prop_attr_t pd_attr;		/* default, readonly, inherit */
	int pd_types;			/* bitfield of valid dataset types */
					/* fs | vol | snap; or pool */
	const char *pd_values;		/* string telling acceptable values */
	const char *pd_colname;		/* column header for "zfs list" */
	boolean_t pd_rightalign;	/* column alignment for "zfs list" */
	boolean_t pd_visible;		/* do we list this property with the */
					/* "zfs get" help message */
	const zfs_index_t *pd_table;	/* for index properties, a table */
					/* defining the possible values */
} prop_desc_t;

static prop_desc_t zfs_prop_table[ZFS_NUM_PROPS];

static void
register_impl(zfs_prop_t prop, const char *name, zfs_proptype_t type,
    uint64_t numdefault, const char *strdefault, prop_attr_t attr,
    int objset_types, const char *values, const char *colname,
    boolean_t rightalign, boolean_t visible, const zfs_index_t *table)
{
	prop_desc_t *pd = &zfs_prop_table[prop];

	ASSERT(pd->pd_name == NULL || pd->pd_name == name);

	pd->pd_name = name;
	pd->pd_proptype = type;
	pd->pd_numdefault = numdefault;
	pd->pd_strdefault = strdefault;
	pd->pd_attr = attr;
	pd->pd_types = objset_types;
	pd->pd_values = values;
	pd->pd_colname = colname;
	pd->pd_rightalign = rightalign;
	pd->pd_visible = visible;
	pd->pd_table = table;
}

static void
register_string(zfs_prop_t prop, const char *name, const char *def,
    prop_attr_t attr, int objset_types, const char *values,
    const char *colname)
{
	register_impl(prop, name, PROP_TYPE_STRING, 0, def, attr,
	    objset_types, values, colname, B_FALSE, B_TRUE, NULL);

}

static void
register_number(zfs_prop_t prop, const char *name, uint64_t def,
    prop_attr_t attr, int objset_types, const char *values, const char *colname)
{
	register_impl(prop, name, PROP_TYPE_NUMBER, def, NULL, attr,
	    objset_types, values, colname, B_TRUE, B_TRUE, NULL);
}

static void
register_boolean(zfs_prop_t prop, const char *name, uint64_t def,
    prop_attr_t attr, int objset_types, const char *values, const char *colname)
{
	register_impl(prop, name, PROP_TYPE_BOOLEAN, def, NULL, attr,
	    objset_types, values, colname, B_TRUE, B_TRUE, NULL);
}

static void
register_index(zfs_prop_t prop, const char *name, uint64_t def,
    int objset_types, const char *values, const char *colname,
    const zfs_index_t *table)
{
	register_impl(prop, name, PROP_TYPE_INDEX, def, NULL, PROP_INHERIT,
	    objset_types, values, colname, B_TRUE, B_TRUE, table);
}

static void
register_hidden(zfs_prop_t prop, const char *name, zfs_proptype_t type,
    prop_attr_t attr, int objset_types, const char *colname)
{
	register_impl(prop, name, type, 0, NULL, attr,
	    objset_types, NULL, colname, B_FALSE, B_FALSE, NULL);
}

void
zfs_prop_init(void)
{
	static zfs_index_t checksum_table[] = {
		{ "on",		ZIO_CHECKSUM_ON },
		{ "off",	ZIO_CHECKSUM_OFF },
		{ "fletcher2",	ZIO_CHECKSUM_FLETCHER_2 },
		{ "fletcher4",	ZIO_CHECKSUM_FLETCHER_4 },
		{ "sha256",	ZIO_CHECKSUM_SHA256 },
		{ NULL }
	};

	static zfs_index_t compress_table[] = {
		{ "on",		ZIO_COMPRESS_ON },
		{ "off",	ZIO_COMPRESS_OFF },
		{ "lzjb",	ZIO_COMPRESS_LZJB },
		{ "gzip",	ZIO_COMPRESS_GZIP_6 },	/* gzip default */
		{ "gzip-1",	ZIO_COMPRESS_GZIP_1 },
		{ "gzip-2",	ZIO_COMPRESS_GZIP_2 },
		{ "gzip-3",	ZIO_COMPRESS_GZIP_3 },
		{ "gzip-4",	ZIO_COMPRESS_GZIP_4 },
		{ "gzip-5",	ZIO_COMPRESS_GZIP_5 },
		{ "gzip-6",	ZIO_COMPRESS_GZIP_6 },
		{ "gzip-7",	ZIO_COMPRESS_GZIP_7 },
		{ "gzip-8",	ZIO_COMPRESS_GZIP_8 },
		{ "gzip-9",	ZIO_COMPRESS_GZIP_9 },
		{ NULL }
	};

	static zfs_index_t snapdir_table[] = {
		{ "hidden",	ZFS_SNAPDIR_HIDDEN },
		{ "visible",	ZFS_SNAPDIR_VISIBLE },
		{ NULL }
	};

	static zfs_index_t acl_mode_table[] = {
		{ "discard",	ZFS_ACL_DISCARD },
		{ "groupmask",	ZFS_ACL_GROUPMASK },
		{ "passthrough", ZFS_ACL_PASSTHROUGH },
		{ NULL }
	};

	static zfs_index_t acl_inherit_table[] = {
		{ "discard",	ZFS_ACL_DISCARD },
		{ "noallow",	ZFS_ACL_NOALLOW },
		{ "secure",	ZFS_ACL_SECURE },
		{ "passthrough", ZFS_ACL_PASSTHROUGH },
		{ NULL }
	};

	static zfs_index_t copies_table[] = {
		{ "1",		1 },
		{ "2",		2 },
		{ "3",		3 },
		{ NULL }
	};

	static zfs_index_t version_table[] = {
		{ "1",		1 },
		{ "2",		2 },
		{ "current",	ZPL_VERSION },
		{ NULL }
	};

	/* inherit index properties */
	register_index(ZFS_PROP_CHECKSUM, "checksum", ZIO_CHECKSUM_DEFAULT,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME,
	    "on | off | fletcher2 | fletcher4 | sha256", "CHECKSUM",
	    checksum_table);
	register_index(ZFS_PROP_COMPRESSION, "compression",
	    ZIO_COMPRESS_DEFAULT, ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME,
	    "on | off | lzjb | gzip | gzip-[1-9]", "COMPRESS", compress_table);
	register_index(ZFS_PROP_SNAPDIR, "snapdir", ZFS_SNAPDIR_HIDDEN,
	    ZFS_TYPE_FILESYSTEM, "hidden | visible", "SNAPDIR", snapdir_table);
	register_index(ZFS_PROP_ACLMODE, "aclmode", ZFS_ACL_GROUPMASK,
	    ZFS_TYPE_FILESYSTEM, "discard | groupmask | passthrough", "ACLMODE",
	    acl_mode_table);
	register_index(ZFS_PROP_ACLINHERIT, "aclinherit", ZFS_ACL_SECURE,
	    ZFS_TYPE_FILESYSTEM,
	    "discard | noallow | secure | passthrough", "ACLINHERIT",
	    acl_inherit_table);
	register_index(ZFS_PROP_COPIES, "copies", 1,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME,
	    "1 | 2 | 3", "COPIES", copies_table);
	register_index(ZFS_PROP_VERSION, "version", 0,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_SNAPSHOT,
	    "1 | 2 | current", "VERSION", version_table);

	/* string properties */
	register_string(ZFS_PROP_ORIGIN, "origin", NULL, PROP_READONLY,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME, "<snapshot>", "ORIGIN");
	register_string(ZPOOL_PROP_BOOTFS, "bootfs", NULL, PROP_DEFAULT,
	    ZFS_TYPE_POOL, "<filesystem>", "BOOTFS");
	register_string(ZFS_PROP_MOUNTPOINT, "mountpoint", "/", PROP_INHERIT,
	    ZFS_TYPE_FILESYSTEM, "<path> | legacy | none", "MOUNTPOINT");
	register_string(ZFS_PROP_SHARENFS, "sharenfs", "off", PROP_INHERIT,
	    ZFS_TYPE_FILESYSTEM, "on | off | share(1M) options", "SHARENFS");
	register_string(ZFS_PROP_SHAREISCSI, "shareiscsi", "off", PROP_INHERIT,
	    ZFS_TYPE_ANY, "on | off | type=<type>", "SHAREISCSI");
	register_string(ZFS_PROP_TYPE, "type", NULL, PROP_READONLY,
	    ZFS_TYPE_ANY, "filesystem | volume | snapshot", "TYPE");

	/* readonly number properties */
	register_number(ZFS_PROP_USED, "used", 0, PROP_READONLY,
	    ZFS_TYPE_ANY, "<size>", "USED");
	register_number(ZFS_PROP_AVAILABLE, "available", 0, PROP_READONLY,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME,
	    "<size>", "AVAIL");
	register_number(ZFS_PROP_REFERENCED, "referenced", 0, PROP_READONLY,
	    ZFS_TYPE_ANY, "<size>", "REFER");
	register_number(ZFS_PROP_COMPRESSRATIO, "compressratio", 0,
	    PROP_READONLY, ZFS_TYPE_ANY,
	    "<1.00x or higher if compressed>", "RATIO");
	register_number(ZFS_PROP_VOLBLOCKSIZE, "volblocksize", 8192,
	    PROP_READONLY,
	    ZFS_TYPE_VOLUME, "512 to 128k, power of 2",	"VOLBLOCK");

	/* default number properties */
	register_number(ZFS_PROP_QUOTA, "quota", 0, PROP_DEFAULT,
	    ZFS_TYPE_FILESYSTEM, "<size> | none", "QUOTA");
	register_number(ZFS_PROP_RESERVATION, "reservation", 0, PROP_DEFAULT,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME, "<size> | none", "RESERV");
	register_number(ZFS_PROP_VOLSIZE, "volsize", 0, PROP_DEFAULT,
	    ZFS_TYPE_VOLUME, "<size>", "VOLSIZE");

	/* inherit number properties */
	register_number(ZFS_PROP_RECORDSIZE, "recordsize", SPA_MAXBLOCKSIZE,
	    PROP_INHERIT,
	    ZFS_TYPE_FILESYSTEM, "512 to 128k, power of 2", "RECSIZE");

	/* readonly boolean properties */
	register_boolean(ZFS_PROP_MOUNTED, "mounted", 0, PROP_READONLY,
	    ZFS_TYPE_FILESYSTEM, "yes | no | -", "MOUNTED");

	/* default boolean properties */
	register_boolean(ZFS_PROP_CANMOUNT, "canmount", 1, PROP_DEFAULT,
	    ZFS_TYPE_FILESYSTEM, "on | off", "CANMOUNT");
	register_boolean(ZPOOL_PROP_DELEGATION, "delegation", 1, PROP_DEFAULT,
	    ZFS_TYPE_POOL, "on | off", "DELEGATION");
	register_boolean(ZPOOL_PROP_AUTOREPLACE, "autoreplace", 0, PROP_DEFAULT,
	    ZFS_TYPE_POOL, "on | off", "REPLACE");

	/* inherit boolean properties */
	register_boolean(ZFS_PROP_ATIME, "atime", 1, PROP_INHERIT,
	    ZFS_TYPE_FILESYSTEM, "on | off", "ATIME");
	register_boolean(ZFS_PROP_DEVICES, "devices", 1, PROP_INHERIT,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_SNAPSHOT, "on | off", "DEVICES");
	register_boolean(ZFS_PROP_EXEC, "exec", 1, PROP_INHERIT,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_SNAPSHOT, "on | off", "EXEC");
	register_boolean(ZFS_PROP_SETUID, "setuid", 1, PROP_INHERIT,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_SNAPSHOT, "on | off", "SETUID");
	register_boolean(ZFS_PROP_READONLY, "readonly", 0, PROP_INHERIT,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME, "on | off", "RDONLY");
	register_boolean(ZFS_PROP_ZONED, "zoned", 0, PROP_INHERIT,
	    ZFS_TYPE_FILESYSTEM, "on | off", "ZONED");
	register_boolean(ZFS_PROP_XATTR, "xattr", 1, PROP_INHERIT,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_SNAPSHOT, "on | off", "XATTR");

	/* hidden properties */
	register_hidden(ZFS_PROP_CREATETXG, "createtxg", PROP_TYPE_NUMBER,
	    PROP_READONLY, ZFS_TYPE_ANY, NULL);
	register_hidden(ZFS_PROP_NUMCLONES, "numclones", PROP_TYPE_NUMBER,
	    PROP_READONLY, ZFS_TYPE_SNAPSHOT, NULL);
	register_hidden(ZFS_PROP_NAME, "name", PROP_TYPE_STRING,
	    PROP_READONLY, ZFS_TYPE_ANY, "NAME");
	register_hidden(ZFS_PROP_ISCSIOPTIONS, "iscsioptions", PROP_TYPE_STRING,
	    PROP_INHERIT, ZFS_TYPE_VOLUME, "ISCSIOPTIONS");
	register_hidden(ZPOOL_PROP_NAME, "zpoolname", PROP_TYPE_STRING,
	    PROP_READONLY, ZFS_TYPE_POOL, NULL);

	/* oddball properties */
	register_impl(ZFS_PROP_CREATION, "creation", PROP_TYPE_NUMBER, 0, NULL,
	    PROP_READONLY, ZFS_TYPE_ANY,
	    "<date>", "CREATION", B_FALSE, B_TRUE, NULL);
}


/*
 * Returns TRUE if the property applies to any of the given dataset types.
 */
int
zfs_prop_valid_for_type(zfs_prop_t prop, int types)
{
	return ((zfs_prop_table[prop].pd_types & types) != 0);
}

/*
 * Determine if the specified property is visible or not.
 */
boolean_t
zfs_prop_is_visible(zfs_prop_t prop)
{
	if (prop < 0)
		return (B_FALSE);

	return (zfs_prop_table[prop].pd_visible);
}

/*
 * A comparison function we can use to order indexes into the
 * zfs_prop_table[]
 */
static int
zfs_prop_compare(const void *arg1, const void *arg2)
{
	const zfs_prop_t *p1 = arg1;
	const zfs_prop_t *p2 = arg2;
	boolean_t p1ro, p2ro;

	p1ro = (zfs_prop_table[*p1].pd_attr == PROP_READONLY);
	p2ro = (zfs_prop_table[*p2].pd_attr == PROP_READONLY);

	if (p1ro == p2ro) {
		return (strcmp(zfs_prop_table[*p1].pd_name,
		    zfs_prop_table[*p2].pd_name));
	}

	return (p1ro ? -1 : 1);
}

/*
 * Iterate over all properties, calling back into the specified function
 * for each property. We will continue to iterate until we either
 * reach the end or the callback function something other than
 * ZFS_PROP_CONT.
 */
zfs_prop_t
zfs_prop_iter_common(zfs_prop_f func, void *cb, zfs_type_t type,
    boolean_t show_all, boolean_t ordered)
{
	int i;
	zfs_prop_t order[ZFS_NUM_PROPS];

	for (int j = 0; j < ZFS_NUM_PROPS; j++)
		order[j] = j;


	if (ordered) {
		qsort((void *)order, ZFS_NUM_PROPS, sizeof (zfs_prop_t),
		    zfs_prop_compare);
	}

	for (i = 0; i < ZFS_NUM_PROPS; i++) {
		if (zfs_prop_valid_for_type(order[i], type) &&
		    (zfs_prop_is_visible(order[i]) || show_all)) {
			if (func(order[i], cb) != ZFS_PROP_CONT)
				return (order[i]);
		}
	}
	return (ZFS_PROP_CONT);
}

zfs_prop_t
zfs_prop_iter(zfs_prop_f func, void *cb)
{
	return (zfs_prop_iter_common(func, cb, ZFS_TYPE_ANY, B_FALSE, B_FALSE));
}

zfs_prop_t
zfs_prop_iter_ordered(zfs_prop_f func, void *cb)
{
	return (zfs_prop_iter_common(func, cb, ZFS_TYPE_ANY, B_FALSE, B_TRUE));
}

zpool_prop_t
zpool_prop_iter(zpool_prop_f func, void *cb)
{
	return (zfs_prop_iter_common(func, cb, ZFS_TYPE_POOL, B_FALSE,
	    B_FALSE));
}

zfs_proptype_t
zfs_prop_get_type(zfs_prop_t prop)
{
	return (zfs_prop_table[prop].pd_proptype);
}

zfs_proptype_t
zpool_prop_get_type(zfs_prop_t prop)
{
	return (zfs_prop_table[prop].pd_proptype);
}

static boolean_t
propname_match(const char *p, zfs_prop_t prop, size_t len)
{
	const char *propname = zfs_prop_table[prop].pd_name;
#ifndef _KERNEL
	const char *colname = zfs_prop_table[prop].pd_colname;
	int c;

	if (colname == NULL)
		return (B_FALSE);
#endif

	if (len == strlen(propname) &&
	    strncmp(p, propname, len) == 0)
		return (B_TRUE);

#ifndef _KERNEL
	if (len != strlen(colname))
		return (B_FALSE);

	for (c = 0; c < len; c++)
		if (p[c] != tolower(colname[c]))
			break;

	return (colname[c] == '\0');
#else
	return (B_FALSE);
#endif
}

zfs_prop_t
zfs_name_to_prop_cb(zfs_prop_t prop, void *cb_data)
{
	const char *propname = cb_data;

	if (propname_match(propname, prop, strlen(propname)))
		return (prop);

	return (ZFS_PROP_CONT);
}

/*
 * Given a property name and its type, returns the corresponding property ID.
 */
zfs_prop_t
zfs_name_to_prop_common(const char *propname, zfs_type_t type)
{
	zfs_prop_t prop;

	prop = zfs_prop_iter_common(zfs_name_to_prop_cb, (void *)propname,
	    type, B_TRUE, B_FALSE);
	return (prop == ZFS_PROP_CONT ? ZFS_PROP_INVAL : prop);
}

/*
 * Given a zfs dataset property name, returns the corresponding property ID.
 */
zfs_prop_t
zfs_name_to_prop(const char *propname)
{
	return (zfs_name_to_prop_common(propname, ZFS_TYPE_ANY));
}

/*
 * Given a pool property name, returns the corresponding property ID.
 */
zpool_prop_t
zpool_name_to_prop(const char *propname)
{
	return (zfs_name_to_prop_common(propname, ZFS_TYPE_POOL));
}

boolean_t
zfs_prop_delegatable(zfs_prop_t prop)
{
	prop_desc_t *pd = &zfs_prop_table[prop];
	return (pd->pd_attr != PROP_READONLY && pd->pd_types != ZFS_TYPE_POOL);
}

/*
 * For user property names, we allow all lowercase alphanumeric characters, plus
 * a few useful punctuation characters.
 */
static int
valid_char(char c)
{
	return ((c >= 'a' && c <= 'z') ||
	    (c >= '0' && c <= '9') ||
	    c == '-' || c == '_' || c == '.' || c == ':');
}

/*
 * Returns true if this is a valid user-defined property (one with a ':').
 */
boolean_t
zfs_prop_user(const char *name)
{
	int i;
	char c;
	boolean_t foundsep = B_FALSE;

	for (i = 0; i < strlen(name); i++) {
		c = name[i];
		if (!valid_char(c))
			return (B_FALSE);
		if (c == ':')
			foundsep = B_TRUE;
	}

	if (!foundsep)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Return the default value for the given property.
 */
const char *
zfs_prop_default_string(zfs_prop_t prop)
{
	return (zfs_prop_table[prop].pd_strdefault);
}

const char *
zpool_prop_default_string(zpool_prop_t prop)
{
	return (zfs_prop_table[prop].pd_strdefault);
}

uint64_t
zfs_prop_default_numeric(zfs_prop_t prop)
{
	return (zfs_prop_table[prop].pd_numdefault);
}

uint64_t
zpool_prop_default_numeric(zpool_prop_t prop)
{
	return (zfs_prop_table[prop].pd_numdefault);
}

/*
 * Returns TRUE if the property is readonly.
 */
int
zfs_prop_readonly(zfs_prop_t prop)
{
	return (zfs_prop_table[prop].pd_attr == PROP_READONLY);
}

/*
 * Given a dataset property ID, returns the corresponding name.
 * Assuming the zfs dataset property ID is valid.
 */
const char *
zfs_prop_to_name(zfs_prop_t prop)
{
	return (zfs_prop_table[prop].pd_name);
}

/*
 * Given a pool property ID, returns the corresponding name.
 * Assuming the pool property ID is valid.
 */
const char *
zpool_prop_to_name(zpool_prop_t prop)
{
	return (zfs_prop_table[prop].pd_name);
}

/*
 * Returns TRUE if the property is inheritable.
 */
int
zfs_prop_inheritable(zfs_prop_t prop)
{
	return (zfs_prop_table[prop].pd_attr == PROP_INHERIT);
}

/*
 * Tables of index types, plus functions to convert between the user view
 * (strings) and internal representation (uint64_t).
 */
int
zfs_prop_string_to_index(zfs_prop_t prop, const char *string, uint64_t *index)
{
	const zfs_index_t *table;
	int i;

	if ((table = zfs_prop_table[prop].pd_table) == NULL)
		return (-1);

	for (i = 0; table[i].name != NULL; i++) {
		if (strcmp(string, table[i].name) == 0) {
			*index = table[i].index;
			return (0);
		}
	}

	return (-1);
}

int
zfs_prop_index_to_string(zfs_prop_t prop, uint64_t index, const char **string)
{
	const zfs_index_t *table;
	int i;

	if ((table = zfs_prop_table[prop].pd_table) == NULL)
		return (-1);

	for (i = 0; table[i].name != NULL; i++) {
		if (table[i].index == index) {
			*string = table[i].name;
			return (0);
		}
	}

	return (-1);
}

#ifndef _KERNEL

/*
 * Returns a string describing the set of acceptable values for the given
 * zfs property, or NULL if it cannot be set.
 */
const char *
zfs_prop_values(zfs_prop_t prop)
{
	if (zfs_prop_table[prop].pd_types == ZFS_TYPE_POOL)
		return (NULL);

	return (zfs_prop_table[prop].pd_values);
}

/*
 * Returns a string describing the set of acceptable values for the given
 * zpool property, or NULL if it cannot be set.
 */
const char *
zpool_prop_values(zfs_prop_t prop)
{
	if (zfs_prop_table[prop].pd_types != ZFS_TYPE_POOL)
		return (NULL);

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
	return (zfs_prop_table[prop].pd_proptype == PROP_TYPE_STRING ||
	    zfs_prop_table[prop].pd_proptype == PROP_TYPE_INDEX);
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
 * Returns whether the given property should be displayed right-justified for
 * 'zfs list'.
 */
boolean_t
zfs_prop_align_right(zfs_prop_t prop)
{
	return (zfs_prop_table[prop].pd_rightalign);
}

/*
 * Determines the minimum width for the column, and indicates whether it's fixed
 * or not.  Only string columns are non-fixed.
 */
size_t
zfs_prop_width(zfs_prop_t prop, boolean_t *fixed)
{
	prop_desc_t *pd = &zfs_prop_table[prop];
	const zfs_index_t *idx;
	size_t ret;
	int i;

	*fixed = B_TRUE;

	/*
	 * Start with the width of the column name.
	 */
	ret = strlen(pd->pd_colname);

	/*
	 * For fixed-width values, make sure the width is large enough to hold
	 * any possible value.
	 */
	switch (pd->pd_proptype) {
	case PROP_TYPE_NUMBER:
		/*
		 * The maximum length of a human-readable number is 5 characters
		 * ("20.4M", for example).
		 */
		if (ret < 5)
			ret = 5;
		/*
		 * 'creation' is handled specially because it's a number
		 * internally, but displayed as a date string.
		 */
		if (prop == ZFS_PROP_CREATION)
			*fixed = B_FALSE;
		break;
	case PROP_TYPE_BOOLEAN:
		/*
		 * The maximum length of a boolean value is 3 characters, for
		 * "off".
		 */
		if (ret < 3)
			ret = 3;
		break;
	case PROP_TYPE_INDEX:
		idx = zfs_prop_table[prop].pd_table;
		for (i = 0; idx[i].name != NULL; i++) {
			if (strlen(idx[i].name) > ret)
				ret = strlen(idx[i].name);
		}
		break;

	case PROP_TYPE_STRING:
		*fixed = B_FALSE;
		break;
	}

	return (ret);
}

#endif
