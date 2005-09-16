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

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include "mio.h"
#include "wish.h"
#include "typetab.h"
#include "partabdefs.h"
#include "message.h"
#include "sizes.h"

extern struct ott_tab *Cur_ott;
static int find_max();

bool
namecheck(path, name, objtype, errstr, is_new)
char *path, *name, *objtype, **errstr;
bool is_new;
{
    int len;
    static char error[MESSIZ];
    char pathbuf[PATHSIZ], oldpath[PATHSIZ];
    char *p;
    char *template = NULL;
    int span;
    int fs_max_fix;
    int maxchar;
    int maxpath;
    int retval;
    struct opt_entry *opt;
    struct ott_entry *ott;
    extern struct one_part Parts[];
    struct opt_entry *obj_to_parts();
    struct ott_entry *dname_to_ott();
    extern  char * part_construct();
    extern  char * path_to_fstype();
    extern char Opwd[];

#ifdef _DEBUG
    _debug(stderr, "in namecheck(%s)\n", name);
#endif

    if (name == NULL || name[0] == '\0') {
	*errstr = "Object name must have at least 1 character";
	return(FALSE);
    }
/* miked k17 */
/*    for (p = name; *p; p++) */    /* convert spaces and tabs to underlines */
/*	if (*p == ' ' || *p == '\t')
	    *p = '_';
*/

    for (p = name; *p; p++)	/* check for spaces and tabs */
	if (*p == ' ' || *p == '\t') {
	    sprintf(error, "Object name cannot contain space or tab characters\n");
	    *errstr = error;
	    return(FALSE);
        }

    if (objtype)
	opt = obj_to_parts(objtype);
    else
	opt = NULL;

/*    if ( path && ! strcmp(path_to_fstype(path),"s5") ) */
/*
 *	this mess sets the maximum object name size depending on the
 *	file system type of the path arguement or, if path is null,
 *	on the value of Opwd, a global containing the pathname of
 *	the last filefolder made current.  The mechanations with
 *	fs_max_fix are because the is a table in Parts that contains
 *	max object lengths that are based on 255.  This table cannot
 *	be changed to reflect s5 .vs. ufs so the kluge is made here.
 */
    if ( ! strcmp(path_to_fstype(path?path:&Opwd[5]),"s5") )
        fs_max_fix = FILE_NAME_SIZ - 1 - 14;
    else
        fs_max_fix = 0;

    if (opt) {
	template = Parts[opt->part_offset].part_template;
	maxchar = find_max(template) - fs_max_fix;
    } else {
	maxchar = FILE_NAME_SIZ - 1 - fs_max_fix;
    }
    /*
     *	changed 12 to 14 here.  miked .. upped 14 to FILE_NAME_SIZ. abs
     */

    if ((len=strlen(name)) > maxchar) {
	sprintf(error, "Object name cannot have more than %d characters\n", maxchar);
	*errstr = error;
	return(FALSE);
    }
    /* check if total pathsize to big */
    if (opt)
	maxpath = len + 4;	/* 4: "/" + prefix(2) + NULL */
    else
	maxpath = FILE_NAME_SIZ + 10; /* name + /.pref + 3 is biggest defined */

    if ((int)(path?strlen(path):0) + maxpath > PATHSIZ) {
	sprintf(error,
		"Can't create object: folder path length exceeds %d characters\n"
		, PATHSIZ - maxpath);
	*errstr = error;
	return(FALSE);
    }

/*	if ((span=strcspn(name, "!@#$^&*(){}[]|\\`~;\"'<>/?")) < len) {
miked */
    if ((span=strcspn(name, "/!&|<>")) < len) {
	sprintf(error,
	"Object name cannot contain the special character '%c'", name[span]);
	*errstr = error;
	return(FALSE);
    }

    for (p = name; *p; p++)	/* test for only printable characters. miked */
	if ( iscntrl( *p ) ) {
	    sprintf(error,
		    "Object name cannot contain the special character ^%c",
		    (*p + '@'));
	    *errstr = error;
	    return(FALSE);
	}

    if ((span=strspn(name, ".")) != 0) {
	sprintf(error, "Object name cannot start with the character '%c'", *name);
	*errstr = error;
	return(FALSE);
    }

    if (!is_new) {
#ifdef _DEBUG
	_debug(stderr, "namecheck returning true\n");
#endif
	return(TRUE);
    }

    if (path) {
	strcat(strcpy(pathbuf, path), "/");
    } else
	pathbuf[0] = '\0';

    if (template)
	strcat(pathbuf, part_construct(name, template));
    else
	strcat(pathbuf, name);
#ifdef _DEBUG
    _debug(stderr, "namecheck: checking existance of %s\n",pathbuf);
#endif

#ifndef WISH
    /* check if the object is in the wastebasket */

    if (Cur_ott && path && strcmp(Cur_ott->path, path) != 0) {
	strcpy(oldpath, Cur_ott->path);
	ott_lock_inc(NULL);
	ott_get(path?path:".", 0L, 0L, 0L, 0L);
    } else
	oldpath[0] = '\0';

    if ((ott = dname_to_ott(name)) != NULL) {
	if (ott->objmask & M_WB)
	    sprintf(error, "object exists in wastebasket");
	else
	    sprintf(error, "An object with that name already exists");
	*errstr = error;
	retval = FALSE;
    } else if (access(pathbuf, 0) != -1) {
	*errstr = "An object with that name already exists";
	retval = FALSE;
    } else
	retval = TRUE;

    if (oldpath[0]) {		/* restore old ott */
	make_current(oldpath);
	ott_unlock_inc(NULL);
    }
#else
    if (access(pathbuf, 0) != -1) {
	static char dbuf[MESSIZ];

	sprintf(dbuf, "An object with that name already exists in %s",
		bsd_path_to_title(path?path:&Opwd[5], MESS_COLS-43));
	*errstr = dbuf;
	retval = FALSE;
    } else
	retval = TRUE;
#endif

#ifdef _DEBUG
    _debug(stderr, "namecheck returning %d\n", retval);
#endif
    return(retval);
}

static int
find_max(template)
char *template;
{
	int max_len;
	register char *p = template;

	while (*p && *p != '%')
		p++;

	if (*p == '\0')
		return(FILE_NAME_SIZ -1);

	p++;

	if (*p != '.')
		return(FILE_NAME_SIZ -1);

	p++;

	if ((max_len = atoi(p)) == 0)
		return(FILE_NAME_SIZ -1);

	return(max_len);
}
