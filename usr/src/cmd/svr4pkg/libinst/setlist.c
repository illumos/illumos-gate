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

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <locale.h>
#include <libintl.h>
#include <pkglocs.h>
#include <pkglib.h>
#include "libinst.h"

int	cl_NClasses = -1;
static int	cl_handle = -1;	/* list array handle */

struct cl_attr	**cl_Classes = NULL;

static int new_order;
static struct cl_attr	*new_cl_attr(char *cl_name);

static unsigned	s_verify(char *class_name), d_verify(char *class_name);
static unsigned	s_pathtype(char *class_name);

#define	MALSIZ	64
#define	ERR_MEMORY	"memory allocation failure"

static struct cl_attr *
new_cl_attr(char *cl_name)
{
	struct cl_attr *class, **class_ptr;

	if (cl_handle == -1) {
		cl_handle = ar_create(MALSIZ, sizeof (struct cl_attr),
		    "package class");
		if (cl_handle == -1) {
			progerr(gettext(ERR_MEMORY));
			return (NULL);
		}
	}

	class_ptr = (struct cl_attr **)ar_next_avail(cl_handle);

	if (class_ptr == NULL || *class_ptr == NULL) {
		progerr(gettext(ERR_MEMORY));
		return (NULL);
	}

	class = *class_ptr;

	strcpy(class->name, cl_name);
	class->inst_script = NULL;
	class->rem_script = NULL;
	class->src_verify = s_verify(cl_name);
	class->dst_verify = d_verify(cl_name);
	class->relpath_2_CAS = s_pathtype(cl_name);

	return (class);
}

/* Insert a single class into the list. */
void
addlist(struct cl_attr ***listp, char *item)
{
	int	i;

	/* If the list is already there, scan for this item */
	if (*listp) {
		for (i = 0; (*listp)[i]; i++)
			if (strcmp(item, (*listp)[i]->name) == 0)
				return;
	} else {
		i = 0;
	}

	/* Insert the new entry */
	if (new_cl_attr(item) == NULL)
		quit(99);

	/* Point the passed pointer to the head of the list. */
	(*listp) = (struct cl_attr **)ar_get_head(cl_handle);
}

/*
 * Create a list of all classes involved in this installation as well as
 * their attributes.
 */
int
setlist(struct cl_attr ***plist, char *slist)
{
	struct cl_attr	**list, *struct_ptr;
	char	*pt;
	int	n;
	int	i;
	int	sn = -1;

	/* Initialize the environment scanners. */
	(void) s_verify(NULL);
	(void) d_verify(NULL);
	(void) s_pathtype(NULL);

	n = 0;

	/*
	 * This looks like a serious memory leak, however pkgmk depends on
	 * this creating a second list and forgetting any prior ones. The
	 * pkgmk utility does a reasonable job of keeping track of a prior
	 * list constructed from the prototype file using addlist() above.
	 * Perhaps this should be reviewed later, but I do not believe this
	 * to be a problem from what I've seen. - JST
	 */
	cl_handle = -1;		/* forget other lists */

	/* Isolate the first token. */
	pt = strtok(slist, " \t\n");
	while (pt) {
		if (sn == -1 && strcmp(pt, "none") == 0)
			sn = n;

		/* Add new class to list. */
		if ((struct_ptr = new_cl_attr(pt)) == NULL)
			quit(99);

		/* Next token. */
		n++;
		pt = strtok(NULL, " \t\n");
		if (pt && sn != -1)
			if (strcmp(pt, "none") == 0)
				pt = strtok(NULL, " \t\n");
	}
	/*
	 * According to the ABI, if there is a class "none", it will be
	 * the first class to be installed.  This insures that iff there
	 * is a class "none", it will be the first to be installed.
	 * If there is no class "none", nothing happens!
	 */
	new_order = 0;

	/* Get the head of the array. */
	list = (struct cl_attr **)ar_get_head(cl_handle);

	if (sn > 0) {
		struct_ptr = list[sn];
		for (i = sn; i > 0; i--)
			list[i] = list[i - 1];
		list[0] = struct_ptr;
		new_order++;	/* the order is different now */
	}

	/* Point the passed pointer to the head of the list. */
	*plist = list;

	return (n);
}

/* Process the class list from the caller. */
void
cl_sets(char *slist)
{
	char *list_ptr;

	/* If there is a list, process it; else skip it */
	if (slist && *slist) {
		list_ptr = qstrdup(slist);

		if (list_ptr && *list_ptr) {
			cl_NClasses = setlist(&cl_Classes, list_ptr);
			if (new_order)		/* if list order changed ... */
				/* ... tell the environment. */
				cl_putl("CLASSES", cl_Classes);
		}
	}
}

int
cl_getn(void)
{
	return (cl_NClasses);
}

/*
 * Since the order may have changed, this puts the CLASSES list back into
 * the environment in the precise order to be used.
 */
void
cl_putl(char *parm_name, struct cl_attr **list)
{
	int i;
	size_t j;
	char *pt = NULL;

	if (list && *list) {
		j = 1; /* room for ending null */
		for (i = 0; list[i]; i++)
			j += strlen(list[i]->name) + 1;
		pt = calloc(j, sizeof (char));
		(void) strcpy(pt, list[0]->name);
		for (i = 1; list[i]; i++) {
			(void) strcat(pt, " ");
			(void) strcat(pt, list[i]->name);
		}
		if (parm_name && *parm_name)
			putparam(parm_name, pt);
		free(pt);
	}
}


int
cl_idx(char *cl_nam)
{
	int	n;

	for (n = 0; n < cl_NClasses; n++)
		if (strcmp(cl_Classes[n]->name, cl_nam) == 0)
			return (n);
	return (-1);
}

/* Return source verification level for this class */
unsigned
cl_svfy(int idx)
{
	if (cl_Classes && idx >= 0 && idx < cl_NClasses)
		return (cl_Classes[idx]->src_verify);
	return (0);
}

/* Return destination verify level for this class */
unsigned
cl_dvfy(int idx)
{
	if (cl_Classes && idx >= 0 && idx < cl_NClasses)
		return (cl_Classes[idx]->dst_verify);
	return (0);
}

/* Return path argument type for this class. */
unsigned
cl_pthrel(int idx)
{
	if (cl_Classes && idx >= 0 && idx < cl_NClasses)
		return (cl_Classes[idx]->relpath_2_CAS);
	return (0);
}

/* Return the class name associated with this class index */
char *
cl_nam(int idx)
{
	if (cl_Classes && idx >= 0 && idx < cl_NClasses)
		return (cl_Classes[idx]->name);
	return (NULL);
}

void
cl_setl(struct cl_attr **cl_lst)
{
	int	i;
	int	sn = -1;
	struct cl_attr	*pt;

	if (cl_lst) {
		for (cl_NClasses = 0; cl_lst[cl_NClasses]; cl_NClasses++)
			if (strcmp(cl_lst[cl_NClasses]->name, "none") == 0)
				if (sn == -1)
					sn = cl_NClasses;
		if (sn > 0) {
			pt = cl_lst[sn];
			for (i = sn; i > 0; i--)
				cl_lst[i] = cl_lst[i - 1];
			cl_lst[0] = pt;
		}
		i = 1;
		while (i < cl_NClasses) {
			if (strcmp(cl_lst[i]->name, "none") == 0)
				for (sn = i; sn < (cl_NClasses - 1); sn++)
					cl_lst[sn] = cl_lst[sn + 1];
			i++;
		}
		cl_Classes = cl_lst;
	} else {
		cl_Classes = NULL;
		cl_NClasses = -1;
	}
}

/*
 * Scan the given environment variable for an occurrance of the given
 * class name. Return 0 if not found or 1 if found.
 */
static unsigned
is_in_env(char *class_name, char *paramname, char **paramvalue, int *noentry)
{
	unsigned retval = 0;
	char *test_class;

	if (class_name && *class_name) {
		/*
		 * If a prior getenv() has not failed and there is no
		 * environment string then get environment info on
		 * this parameter.
		 */
		if (!(*noentry) && *paramvalue == NULL) {
			*paramvalue = getenv(paramname);
			if (*paramvalue == NULL)
				(*noentry)++;
		}

		/* If there's something there, evaluate it. */
		if (!(*noentry)) {
			int n;

			n = strlen(class_name);	/* end of class name */
			test_class = *paramvalue;	/* environ ptr */

			while (test_class = strstr(test_class, class_name)) {
				/*
				 * At this point we have a pointer to a
				 * substring within param that matches
				 * class_name for its length, but class_name
				 * may be a substring of the test_class, so
				 * we check that next.
				 */
				if (isspace(*(test_class + n)) ||
				    *(test_class + n) == '\0') {
					retval = 1;
					break;
				}
				if (*(++test_class) == '\0')
					break;
			}
		}
	}
	return (retval);
}

/* Assign source path verification level to this class */
static unsigned
s_verify(char *class_name)
{
	static int noentry;
	static char *noverify;

	if (class_name == NULL) {	/* initialize */
		noentry = 0;
		noverify = NULL;
	} else {
		if (is_in_env(class_name, "PKG_SRC_NOVERIFY", &noverify,
		    &noentry))
			return (NOVERIFY);
		else
			return (DEFAULT);
	}
	return (0);
}

/*
 * Set destination verify to default. This is usually called by pkgdbmerg()
 * in order to correct verification conflicts.
 */
void
cl_def_dverify(int idx)
{
	if (cl_Classes && idx >= 0 && idx < cl_NClasses)
		cl_Classes[idx]->dst_verify = DEFAULT;
}

/* Assign destination path verification level to this path. */
static unsigned
d_verify(char *class_name)
{
	static int noentry;
	static char *qkverify;

	if (class_name == NULL) {	/* initialize */
		noentry = 0;
		qkverify = NULL;
	} else {
		if (is_in_env(class_name, "PKG_DST_QKVERIFY", &qkverify,
		    &noentry))
			return (QKVERIFY);
		else
			return (DEFAULT);
	}
	return (0);
}

/* Assign CAS path type to this class */
static unsigned
s_pathtype(char *class_name)
{
	static int noentry;
	static char *type_list;

	if (class_name == NULL) {	/* initialize */
		noentry = 0;
		type_list = NULL;
	} else {
		if (is_in_env(class_name, "PKG_CAS_PASSRELATIVE", &type_list,
		    &noentry))
			return (REL_2_CAS);
		else
			return (DEFAULT);
	}
	return (0);
}
