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
 * Copyright 1997-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef LINT
static char SCCSID[] = "%Z%%M%	%I%	%E% SMI";
#endif

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <rpcsvc/nis.h>
#include "nis_proc.h"
#include "nis_mt.h"

/*
 * TA_MULTIVAL and TA_SEARCHABLE are mutually exclusive.  The
 * separator character for multivalue searches is stored in the
 * upper byte of tc_flags and is accessed with TA_MULTISEP.
 *
 * XXX these defines should be moved to rpcsvc/nis.h eventually XXX
 */
#define	TA_MULTIVAL (0xff000000)
#define	TA_MULTISEP(x) (((x) & 0xff000000) >> 24)

#ifndef _REENTRANT
#define	strtok_r(a, b, c) strtok((a), (b))
#endif /* _REENTRANT */

/*
 *  If FORCE_GROUP is defined, then the members column of the group
 *  table is considered a multival column, even if TA_MULTIVAL
 *  isn't set on the column.
 */
#define	FORCE_GROUP 1

struct dir_item {
	NIS_HASH_ITEM item;
	NIS_HASH_TABLE tables;
};
typedef struct dir_item dir_item;

struct tab_item {
	NIS_HASH_ITEM item;
	nis_db_list_result *res;
	NIS_HASH_TABLE columns;
	dir_item *dir;
};
typedef struct tab_item tab_item;

struct col_item {
	NIS_HASH_ITEM item;
	int colnum;
	char sep[2];
	int case_insensitive;
	NIS_HASH_TABLE entries;
	tab_item *tab;
};
typedef struct col_item col_item;

struct ent_item {
	NIS_HASH_ITEM item;
	nis_object **obj;
	int nobj;
	col_item *col;
};
typedef struct ent_item ent_item;

static NIS_HASH_TABLE dirs = NIS_HASH_TABLE_MT_INIT;

static tab_item *find_table(nis_object *, int);
static col_item *find_column(nis_object *, char *, int);
static ent_item *find_entry(nis_object *, char *, char *, int);

static tab_item *load_table(nis_object *, int);
static col_item *load_column(tab_item *, table_col *, int, int);
static ent_item *load_entry(col_item *, nis_object *, int);

static void free_table(tab_item *);
static void free_column(col_item *);
static void free_entry(ent_item *);

static void strlower(char *);

#define	RW	-1
#define	NONE	0
#define	RO	1

/*
 * The find_table(), find_column(), and find_entry() functions leave the
 * respective NIS_HASH_TABLE entries locked. The release_*() functions below
 * unlock those tables in the correct order.
 */
static void
release_directory(dir_item *dir) {
	if (dir != 0)
		(void) __nis_release_item(dir, &dirs, __nis_item_access(dir));
}

static void
release_table(tab_item *tab, int release_dir) {

	dir_item	*dir;

	if (tab != 0 && (dir = tab->dir) != 0) {
		(void) __nis_release_item(tab, &dir->tables,
					__nis_item_access(tab));
		if (release_dir)
			release_directory(dir);
	}
}

static void
release_column(col_item *col, int release_tab) {

	tab_item	*tab;

	if (col != 0 && (tab = col->tab) != 0) {
		(void) __nis_release_item(col, &tab->columns,
						__nis_item_access(col));
		if (release_tab)
			release_table(tab, 1);
	}
}

static void
release_entry(ent_item *ent, int release_col) {

	col_item	*col;

	if (ent != 0 && (col = ent->col) != 0) {
		(void) __nis_release_item(ent, &col->entries,
						__nis_item_access(ent));
		if (release_col)
			release_column(col, 1);
	}
}

/*
 *  Check to see if the attribute in 'attr' is a multival
 *  attribute.
 */
int
multival_check(nis_object *tobj, nis_attr *attr, table_col *cols, int ncols)
{
	int i;

#ifdef FORCE_GROUP
	if (strcasecmp(tobj->TA_data.ta_type, "group_tbl") == 0 &&
	    strcasecmp(attr->zattr_ndx, "members") == 0) {
		return (1);
	}
#endif /* FORCE_GROUP */
	for (i = 0; i < ncols; i++) {
		if (strcasecmp(cols[i].tc_name, attr->zattr_ndx) == 0) {
			/* if column is searchable, then it is not multival */
			if (cols[i].tc_flags & TA_SEARCHABLE)
				return (0);
			if ((cols[i].tc_flags & TA_MULTIVAL) != 0)
				return (1);
		}
	}
	return (0);
}

/*
 *  Determine which attributes refer to multival columns.  All of
 *  the regular attributes are moved to the beginning of 'attr'
 *  and the multival attributes are moved to the end.  The
 *  'nattr' and 'nmulti' variables are set to the number of each
 *  type of attributes.
 *
 *  We assume that most tables don't have multival columns, so do
 *  a quick scan and return if this is the case.
 */
nis_error
multival_attr(nis_object *tobj, nis_attr *attr, int *nattr, int *nmulti)
{
	int i;
	int front;
	int back;
	table_col *cols;
	int ncols;
	int *is_multival;
	int tmp;
	nis_attr tmp_attr;

	if (__type_of(tobj) == DIRECTORY_OBJ) {
		*nmulti = 0;
		return (NIS_SUCCESS);
	}

	cols = tobj->TA_data.ta_cols.ta_cols_val;
	ncols = tobj->TA_data.ta_cols.ta_cols_len;
	for (i = 0; i < ncols; i++) {
		if (cols[i].tc_flags & TA_MULTIVAL)
			break;
	}
#ifdef FORCE_GROUP
	if (strcasecmp(tobj->TA_data.ta_type, "group_tbl") == 0) {
		i = 3;	/* members column number */
	}
#endif /* FORCE_GROUP */
	if (i >= ncols) {
		*nmulti = 0;
		return (NIS_SUCCESS);
	}

	/* determine which elements of attr are multival */
	is_multival = (int *)malloc(*nattr * sizeof (is_multival[0]));
	if (is_multival == NULL) {
		return (NIS_NOMEMORY);
	}
	for (i = 0; i < *nattr; i++) {
		is_multival[i] = multival_check(tobj, &attr[i], cols, ncols);
	}

	/* partition sort to put regular attributes first, multival last */
	front = 0;
	back = *nattr - 1;
	while (front <= back) {
		if (!is_multival[front])
			front += 1;
		else if (is_multival[back])
			back -= 1;
		else {
			tmp_attr = attr[front];
			attr[front] = attr[back];
			attr[back] = tmp_attr;
			tmp = is_multival[front];
			is_multival[front] = is_multival[back];
			is_multival[back] = tmp;
			front += 1;
			back -= 1;
		}
	}

	if (front < *nattr) {
		*nmulti = *nattr - front;
		*nattr = front;
	} else {
		*nmulti = 0;
	}

	free((void *)is_multival);
	return (NIS_SUCCESS);
}

/*
 *  Do a multival search on nis_object.  If all of the attributes
 *  in 'm' have matches, then the object should not be filtered out.
 */
int
multival_filter(nis_object *tobj, int nm, nis_attr *m, nis_object *obj)
{
	int i;
	int st;
	int len;
	char *p;
	int vlen;
	char *val;
	char *last;
	col_item *col;

	for (i = 0; i < nm; i++) {
		if ((col = find_column(tobj, m[i].zattr_ndx, RO)) == NULL)
			return (1);
		p = ENTRY_VAL(obj, col->colnum);
		len = ENTRY_LEN(obj, col->colnum);
		if (p == NULL || len == 0 || p[len-1] != '\0') {
			release_column(col, 1);
			return (1);
		}
		/* make copy of value because strtok leaves trail of '\0' */
		p = strdup(p);
		if (p == NULL) {
			release_column(col, 1);
			return (1);
		}

		val = strtok_r(p, col->sep, &last);
		while (val) {
			vlen = strlen(val) + 1;	/* include '\0' */
			if (vlen == m[i].zattr_val.zattr_val_len) {
				if (col->case_insensitive) {
					st = strcasecmp(val,
						m[i].zattr_val.zattr_val_val);
				} else {
					st = strcmp(val,
						m[i].zattr_val.zattr_val_val);
				}
				if (st == 0)
					break;
			}
			val = strtok_r(NULL, col->sep, &last);
		}
		free((void *)p);
		release_column(col, 1);
		if (val == NULL)
			return (1);
	}

	/* found a match for all attributes, don't filter this object */
	return (0);
}

/*
 *  Search the table specified by 'tobj' for all of the objects that
 *  are selected by the attributes in 'm'.  This is basically a
 *  join operation.  For the first attribute, we retrieve a list of
 *  objects.  For subsequent attributes, we do a join and keep only
 *  the objects that occur in both lists.
 */
void
multival_list(nis_object *tobj, int nm, nis_attr *m, nis_db_list_result *res)
{
	int i;
	int j;
	int k;
	int n;
	char *val;
	int len;
	ent_item *ent;
	obj_list *olist;
	int count = 0;
	int nobj = 0;
	nis_object **objs = NULL;

	for (i = 0; i < nm; i++) {
		val = m[i].zattr_val.zattr_val_val;
		len = m[i].zattr_val.zattr_val_len;
		if (val == NULL || len == 0 || val[len-1] != '\0') {
			res->status = NIS_BADATTRIBUTE;
			return;
		}
		ent = find_entry(tobj, m[i].zattr_ndx, val, RO);
		if (!ent) {
			res->status = NIS_NOTFOUND;
			free((void *)objs);
			return;
		}

		if (objs == NULL) {
			objs = (nis_object **)malloc(
					ent->nobj * sizeof (nis_object *));
			if (objs == NULL) {
				release_entry(ent, 1);
				res->status = NIS_NOMEMORY;
				return;
			}
			for (j = 0; j < ent->nobj; j++) {
				objs[j] = ent->obj[j];
			}
			nobj = ent->nobj;
			count = nobj;
		} else {
			for (j = 0; j < nobj; j++) {
				if (objs[j] == NULL)
					continue;
				for (k = 0; k < ent->nobj; k++) {
					if (objs[j] == ent->obj[k])
						break;
				}
				if (k >= ent->nobj) {
					objs[j] = NULL;
					count -= 1;
				}
			}
		}
		release_entry(ent, 1);
	}

	if (count == 0) {
		res->status = NIS_NOTFOUND;
		free((void *)objs);
		return;
	}

	olist = (obj_list *)calloc(count, sizeof (obj_list));

	n = 0;
	for (i = 0; i < nobj; i++) {
		if (objs[i]) {
			olist[n].o = nis_clone_object(objs[i], 0);
			n++;
		}
	}
	free((void *)objs);

	if (n != count)  {
		syslog(LOG_ERR,
			"multival_list: miscounted objects (%d, %d)", n, count);
	}

	res->status = NIS_SUCCESS;
	res->objs = olist;
	res->numo = count;
}

/*
 *  A table has been modified in some way, so we must free up
 *  the entries associated with it.
 */
void
multival_invalidate(nis_object *obj)
{
	dir_item *dir;
	tab_item *tab;

	if (__type_of(obj) != TABLE_OBJ && __type_of(obj) != ENTRY_OBJ)
		return;

	dir = (dir_item *)nis_find_item_rw(obj->zo_domain, &dirs, RO);
	if (dir == NULL)
		return;

	tab = (tab_item *)nis_remove_item(obj->zo_name, &dir->tables);
	release_directory(dir);
	if (tab)
		free_table(tab);
}

static
tab_item *
find_table(nis_object *tobj, int rw)
{
	int i;
	table_col *cols;
	int ncols;
	dir_item *dir;
	tab_item *tab;

	dir = (dir_item *)nis_find_item_rw(tobj->zo_domain, &dirs, RO);
	if (dir == NULL)
		return (NULL);

	tab = (tab_item *)nis_find_item_rw(tobj->zo_name, &dir->tables, rw);
	if (tab != 0)
		tab->dir = dir;
	return (tab);
}

static
col_item *
find_column(nis_object *tobj, char *name, int rw)
{
	tab_item *tab;
	col_item *col;

	tab = find_table(tobj, RO);
	if (tab == NULL) {
		/*
		 * While loading the table, we need write access (at least
		 * to parts of it).
		 */
		tab = load_table(tobj, RW);
		if (tab == NULL) {
			/* remove any partially loaded table information */
			multival_invalidate(tobj);
			return (NULL);
		}
	}
	col = (col_item *)nis_find_item_rw(name, &tab->columns, rw);
	if (col != 0) {
		col->tab = tab;
	} else {
		release_table(tab, 1);
	}
	return (col);
}

static
ent_item *
find_entry(nis_object *tobj, char *key, char *val, int rw)
{
	col_item *col;
	ent_item *ent;

	strlower(key);
	col = find_column(tobj, key, RO);
	if (col == NULL)
		return (NULL);
	if (col->case_insensitive)
		strlower(val);
	ent = (ent_item *)nis_find_item_rw(val, &col->entries, rw);
	if (ent != 0) {
		ent->col = col;
	} else {
		release_column(col, 1);
	}
	return (ent);
}

static
col_item *
load_column(tab_item *tab, table_col *tc, int n, int rw)
{
	col_item *col;

	col = (col_item *)calloc(1, sizeof (col_item));
	if (col == NULL)
		return (NULL);
	col->item.name = strdup(tc->tc_name);
	if (col->item.name == NULL) {
		free((void *)col);
		return (NULL);
	}
	col->colnum = n;
	col->sep[0] = TA_MULTISEP(tc->tc_flags);
	col->sep[1] = '\0';
	if (tc->tc_flags & TA_CASE)
		col->case_insensitive = 1;
	else
		col->case_insensitive = 0;
	col->tab = tab;
	if (!nis_insert_item_rw((NIS_HASH_ITEM *)col, &tab->columns, rw)) {
		free((void *)col->item.name);
		free((void *)col);
		return (NULL);
	}
	return (col);
}

/*
 * load_entry()
 *
 * The col entry val/len should be checked before calling load_entry to make
 * sure it is non-NULL, non-empty, length > 0, and NUL terminated.
 */
static
ent_item *
load_entry(col_item *col, nis_object *obj, int rw)
{
	char *p;
	char *val;
	int len;
	char *last;
	ent_item *ent = 0;

	p = ENTRY_VAL(obj, col->colnum);
	len = ENTRY_LEN(obj, col->colnum);
	if (p == NULL || len == 0 || p[0] == '\0' ||
		(len > 0 && p[len-1] != '\0')) {
		syslog(LOG_ERR,
		    "load_entry: bad entry; empty/NULL or nonNUL terminated");
		return (NULL);
	}

	/* make a copy of p because strtok leaves a trail of '\0' */
	p = strdup(p);
	if (p == NULL)
		return (NULL);

	val = strtok_r(p, col->sep, &last);
	while (val) {
		/*
		 * We're going to modify the entry, so we need RW access.
		 * XXX  We expect the caller to be load_table(), and it
		 * doesn't use the return value other than to check for
		 * success (non-NULL). Thus, we make no attempt to return
		 * the (last created) entry with the requested access.
		 */
		if (ent != 0) {
			/* Release entry from previous lap */
			release_entry(ent, 1);
		}
		ent = (ent_item *)nis_find_item_rw(val, &col->entries, RW);
		if (ent == NULL) {
			ent = (ent_item *)calloc(1, sizeof (ent_item));
			if (ent == NULL) {
				free((void *)p);
				return (NULL);
			}
			ent->item.name = strdup(val);
			if (ent->item.name == NULL) {
				free((void *)p);
				free((void *)ent);
				return (NULL);
			}
			if (col->case_insensitive) {
				strlower(ent->item.name);
			}
			ent->obj = NULL;
			ent->nobj = 0;
			ent->col = col;
			if (!nis_insert_item_rw((NIS_HASH_ITEM *)ent,
						&col->entries, RW)) {
				free((void *)p);
				free((void *)ent->item.name);
				free((void *)ent);
				return (NULL);
			}
		}
		ent->obj = (nis_object **)realloc(ent->obj,
				(ent->nobj + 1) * sizeof (entry_obj *));
		if (ent->obj == NULL) {
			ent->nobj = 0;
			free((void *)p);
			release_entry(ent, 1);
			return (NULL);
		}
		ent->obj[ent->nobj] = obj;
		ent->nobj += 1;

		val = strtok_r(NULL, col->sep, &last);
	}

	free((void *)p);
	return (ent);
}

static
tab_item *
load_table(nis_object *tobj, int rw)
{
	int i;
	int j;
	int multival;
	table_col *cols;
	table_col *col;
	table_col colbuf;
	dir_item *dir;
	tab_item *tab;
	int ncols;
	col_item **collist;
	char name[NIS_MAXNAMELEN];
	char tblbuf[NIS_MAXNAMELEN * 2];
	char *table;
	nis_db_list_result *res;
	obj_list *objs;
	int nobj;
	ent_item *tmpent = 0;

	/*
	 *  Get directory item.  Create it if it doesn't exist.
	 */
	dir = (dir_item *)nis_find_item_rw(tobj->zo_domain, &dirs, RO);
	if (dir == NULL) {
		dir = (dir_item *)calloc(1, sizeof (dir_item));
		if (dir == NULL)
			return (NULL);
		dir->item.name = strdup(tobj->zo_domain);
		if (dir->item.name == NULL) {
			free((void *)dir);
			return (NULL);
		}
		if (!nis_insert_item_rw((NIS_HASH_ITEM *)dir, &dirs, RO)) {
			free((void *)dir->item.name);
			free((void *)dir);
			return (NULL);
		}
	}

	/* create table item and add to directory item */
	tab = (tab_item *)calloc(1, sizeof (tab_item));
	if (tab == NULL) {
		__nis_release_item(dir, &dirs, RO);
		return (NULL);
	}
	tab->item.name = strdup(tobj->zo_name);
	if (tab->item.name == NULL) {
		free((void *)tab);
		__nis_release_item(dir, &dirs, RO);
		return (NULL);
	}
	tab->dir = dir;
	if (!nis_insert_item_rw((NIS_HASH_ITEM *)tab, &dir->tables, rw)) {
		free((void *)tab->item.name);
		free((void *)tab);
		__nis_release_item(dir, &dirs, RO);
		return (NULL);
	}

	cols = tobj->TA_data.ta_cols.ta_cols_val;
	ncols = tobj->TA_data.ta_cols.ta_cols_len;

	/*
	 *  We keep a copy of each of the columns in an array so that
	 *  we can load the entries for each one.  Each element of the
	 *  array is also stored in 'tab'.
	 */
	collist = (col_item **)calloc(ncols, sizeof (col_item *));
	if (collist == NULL) {
		release_table(tab, 1);
		return (NULL);
	}

	for (i = 0; i < ncols; i++) {
		multival = 0;
		if ((cols[i].tc_flags & TA_SEARCHABLE) == 0 &&
		    (cols[i].tc_flags & TA_MULTIVAL) != 0) {
			multival = 1;
			col = &cols[i];
		}
#ifdef FORCE_GROUP
		if (!multival) {
			if (i == 3 &&
			    strcasecmp(tobj->TA_data.ta_type,
					"group_tbl") == 0) {
				multival = 1;
				colbuf = cols[i];
				colbuf.tc_flags |= ((',' << 24) & 0xff000000);
				col = &colbuf;
			}
		}
#endif /* FORCE_GROUP */
		if (multival) {
			collist[i] = load_column(tab, col, i, RO);
			if (collist[i] == NULL) {
				int c;

				for (c = 0; c++; c < i)
					release_column(collist[c], 0);
				release_table(tab, 1);
				free((void *)collist);
				return (NULL);
			}
		}
	}

	sprintf(name, "%s.%s", tobj->zo_name, tobj->zo_domain);
	table = internal_table_name(name, tblbuf);
	if (table == NULL) {
		for (i = 0; i < ncols; i++)
			release_column(collist[i], 0);
		release_table(tab, 1);
		free((void *)collist);
		return (NULL);
	}

	res = db_list_flags(name, 0, NULL, FN_NORAGS);
	if (res == 0 ||
		(res->status != NIS_SUCCESS && res->status != NIS_NOTFOUND)) {
		for (i = 0; i < ncols; i++) {
			release_column(collist[i], 0);
		}
		release_table(tab, 1);
		free((void *)collist);
		if (res != 0)
			free_db_list(res);
		return (NULL);
	}

	tab->res = res;
	objs = tab->res->objs;
	for (i = 0; i < tab->res->numo; i++) {
		for (j = 0; j < ncols; j++) {
			if (collist[j]) {
				char *p;
				int len;

				/*
				 * Make sure we have a valid column string
				 * before calling load_entry.
				 */
				p = ENTRY_VAL(objs[i].o,
					    (collist[j])->colnum);
				len = ENTRY_LEN(objs[i].o,
						(collist[j])->colnum);
				if (p == NULL || len == 0 || p[0] == '\0' ||
				    (len > 0 && p[len-1] != '\0'))
					continue;

				if (!(tmpent = load_entry(collist[j],
							objs[i].o, RO))) {
					int	c;

					for (c = 0; c < ncols; c++)
						release_column(collist[c], 0);
					release_table(tab, 1);
					free((void *)collist);
					return (NULL);
				}
				release_entry(tmpent, 0);
			}
		}
	}

	for (i = 0; i < ncols; i++)
		release_column(collist[i], 0);

	free((void *)collist);

	return (tab);
}

static
void
free_table(tab_item *tab)
{
	col_item *col;

	while ((col = (col_item *)nis_pop_item(&tab->columns)) != NULL) {
		free_column(col);
	}
	free((void *)tab->item.name);
	free_db_list(tab->res);
	free((void *)tab);
}

static
void
free_column(col_item *col)
{
	ent_item *ent;

	while ((ent = (ent_item *)nis_pop_item(&col->entries)) != NULL) {
		free_entry(ent);
	}
	free((void *)col->item.name);
	free((void *)col);
}

static
void
free_entry(ent_item *ent)
{
	free((void *)ent->item.name);
	free((void *)ent->obj);
	free((void *)ent);
}

static
void
strlower(char *s)
{
	while (*s) {
		if (isupper(*s))
			*s = tolower(*s);
		s++;
	}
}
