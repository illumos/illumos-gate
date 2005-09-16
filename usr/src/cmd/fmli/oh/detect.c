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
#include <sys/types.h>
#include <sys/stat.h>
/*#include <sys/dir.h>  this is file system dependent. abs */
#include <sys/times.h>
#include <ctype.h>
#include "wish.h"
#include "var_arrays.h"
#include "typetab.h"
#include "detabdefs.h"
#include "partabdefs.h"
#include "optabdefs.h"
#include "parse.h"
#include "sizes.h"

#define ACC_NOTSET	1
#define ACC_OKREAD	0
#define ACC_NOREAD	-1
#define ck_readable(X)	(access(X, 4))
#define NULLSTR		""

/* PGSHFT should be PNUMSHF from <sys/immu.h> see below  abs 9/15/99 */
/* #define PGSHFT	64		 kludge to detect core files */
#define LOOKED_AT_OEH	1
#define LOOKED_AT_BYTES	2

extern struct one_part Parts[MAXPARTS];
extern struct odft_entry Detab[MAXODFT];


static int Seen_non_printable;
static int Seen_eighth_bit;
static int Already_looked;
static struct oeh Oeh;

int Pathlen;

#ifndef WISH
void det_mail_in(), det_mail_out();
#endif
static int look_at_bytes();
static int magic_heuristics();
static int external_heuristics();
static int oeu_heuristics();
struct opt_entry *obj_to_parts();
static bool exist_heuristics();
static bool part_heuristics();

/* The heuristics program drives off of the detection table (defined in
 * detab.c).  It cycles through this table, executing heuristics commands
 * as it goes.  There are basically 4 kinds of heuristics:
 *
 * Heuristics based on object part names
 * Heuristics based on magic numbers
 * Heuristics based on user-defined functions
 * Heuristics based on internal functions
 *
 * The most efficient method is part-names, the least efficient is
 * user-defined functions since they require a fork().
 * For this reason, it is probably best for user-defined functions to come
 * last if possible.
 */

int
heuristics(path, stray)
char *path;
char stray[][FILE_NAME_SIZ];
{				/* begin heuristics */
    struct stat sbuf;
    char buf[2048];		/* xed header size */
    register int i;
    int psize = strlen(path) + 1;
    int size = array_len(stray);
    long docmask = 0L;
    char pathbuf[PATHSIZ];
    bool is_directory, determined;
    int heur;
    int accessible;

    strcpy(pathbuf, path);
    strcat(pathbuf, "/");
    Pathlen = psize;

    for (i = 0; i < size; i++) {
	if (stray[i][0] == '\0')
	    continue;		/* already determined by other heuristics */
	/* below, 3 is for: "/" & prefixes */
	if (psize + (int)strlen(stray[i]) + 3 > PATHSIZ) /* EFT k16 */
	    continue;		/* ignore - path too big */
	strcpy(pathbuf+psize, stray[i]);
	if (stat(pathbuf, &sbuf) == -1) {
#ifdef _DEBUG
	    _debug(stderr, "can't stat %s\n", pathbuf);
#endif
	    continue;
	}

	/* MUST be a directory to be check for exist_heuristics;
	 * Directories will ONLY be checked for exist_heuristics, part_-
	 * heuristics and shell and exec functions. (No magic or internal
	 * (oeu,ascii,core,archive,mailin/out) functions will be run.)
	 */
	if (sbuf.st_mode & 040000)
	    is_directory = TRUE;
	else
	    is_directory = FALSE;

	if ( sbuf.st_mode & 04000 ) /* narrow screen file */
	    docmask = M_NAR;
	else
	    docmask = 0L;

	determined = FALSE;
	accessible = ACC_NOTSET;
	Already_looked = 0;
	for (heur = 0; !determined && Detab[heur].objtype[0]; heur++) {
	    switch (Detab[heur].func_type) {
	    case F_DPARTS:
		if (is_directory == FALSE)
		    continue;
		if (exist_heuristics(path, stray[i], Detab[heur].objtype,
				     Detab[heur].defmask, Detab[heur].defodi, 
				     sbuf.st_mtime))
		    determined = TRUE;
		break;
	    case F_PARTS:
		if (part_heuristics(path, stray, i, Detab[heur].objtype,
				    Detab[heur].defmask, Detab[heur].defodi,
				    sbuf.st_mtime, NULL))
		    determined = TRUE;
		break;
	    case F_MAGIC:
		if (is_directory == TRUE)
		    continue;
		if (accessible == ACC_NOTSET)
		    accessible = ck_readable(pathbuf);
		if (accessible == ACC_NOREAD)
		    break;
		if (magic_heuristics(path, stray[i], Detab[heur].objtype,
				     Detab[heur].defmask, Detab[heur].defodi,
				     sbuf.st_mtime, Detab[heur].magic_offset,
				     Detab[heur].magic_bytes))
		    determined = TRUE;
		break;
	    case F_SHELL:
	    case F_EXEC:
		if (external_heuristics(path, stray[i], Detab[heur].defmask,
					Detab[heur].defodi, sbuf.st_mtime, NULL))
		    determined = TRUE;
		break;
	    case F_INT:
		if (is_directory == TRUE)
		    continue;
		switch (Detab[heur].intern_func) {
		case IDF_ZLASC:	/* zero length ascii */
		    if (sbuf.st_size == 0) {
			/* file pathsize already tested at top of this fcn */
			ott_make_entry(stray[i], stray[i], Detab[heur].objtype,
				       docmask|Detab[heur].defmask, Detab[heur].defodi,
				       sbuf.st_mtime);
			stray[i][0] = '\0';
			determined = TRUE;
		    }
		    break;
		case IDF_ASC:
		    if (accessible == ACC_NOTSET)
			accessible = ck_readable(pathbuf);
		    if (accessible == ACC_NOREAD)
			break;
		    look_at_bytes(path, stray[i]);
		    if (! Seen_non_printable) {
			/* file pathsize already tested at top of this fcn */
			ott_make_entry(stray[i], stray[i], Detab[heur].objtype,
				       docmask|Detab[heur].defmask, Detab[heur].defodi,
				       sbuf.st_mtime);
			stray[i][0] = '\0';
			determined = TRUE;
		    }
		    break;
		case IDF_TRANS:
		    if (accessible == ACC_NOTSET)
			accessible = ck_readable(pathbuf);
		    if (accessible == ACC_NOREAD)
			break;
		    if (oeu_heuristics(path, stray[i], Detab[heur].objtype,
				       Detab[heur].defmask, Detab[heur].defodi, 
				       sbuf.st_mtime)) {
			determined = TRUE;
		    }
		    break;
		case IDF_CORE:
		    /* if a file is named "core" and it is at least 3 pages long
		     * and it is an even multiple of a page size, and it has at
		     * least one byte within the first five hundred with the
		     * eighth bit set, then it is probably a core file.
		     * >> This sounds nice  but  you can't do this with PGSHFT = 64
		     * >> which causes the code below to do nothing more than generate
		     * >> compiler warnings.  you could replace PGSHFT with PNUMSHFT
		     * >> from <sys/immu.h> but this introduces machine dependencies
		     * >> and may still get into trouble when memory management changes.
		     * >> since no one  but the compiler has complained, I commented out
		     * >> the code. abs 9/15/88
		     */
		    if (accessible == ACC_NOTSET)
			accessible = ck_readable(pathbuf);
		    if (accessible == ACC_NOREAD)
			break;
		    look_at_bytes(path, stray[i]);
		    if (strcmp(stray[i], "core") == 0 && Seen_non_printable 
			/* && sbuf.st_size >= (1<<PGSHFT)*3 && ! (sbuf.st_size % (1<<PGSHFT) ) */
			)
		    {
			/* file pathsize already tested at top of this fcn */
			ott_make_entry(stray[i],stray[i],Detab[heur].objtype,
				       Detab[heur].defmask,Detab[heur].defodi,
				       sbuf.st_mtime);
			stray[i][0] = '\0';
			determined = TRUE;
		    }
		    break;
		case IDF_ARCH:
		    if (accessible == ACC_NOTSET)
			accessible = ck_readable(pathbuf);
		    if (accessible == ACC_NOREAD)
			break;
		    look_at_bytes(path, stray[i]);
		    if (Seen_non_printable && has_suffix(stray[i], ".a") &&
			strncmp(buf, "!<arch>", 7) == 0) {
			/* file pathsize already tested at top of this fcn */
			ott_make_entry(stray[i], stray[i], Detab[heur].objtype,
				       Detab[heur].defmask,Detab[heur].defodi,
				       sbuf.st_mtime);
			stray[i][0] = '\0';
			determined = TRUE;
		    }
		    break;
		case IDF_ENCRYPT:
		    if (accessible == ACC_NOTSET)
			accessible = ck_readable(pathbuf);
		    if (accessible == ACC_NOREAD)
			break;
		    if (oeu_heuristics(path, stray[i], NULL,
				       Detab[heur].defmask, Detab[heur].defodi, 
				       sbuf.st_mtime)) {
			determined = TRUE;
		    }
		    break;
		case IDF_UNKNOWN:
		    /* file pathsize already tested at top of this fcn */
		    ott_make_entry(stray[i], stray[i], Detab[heur].objtype,
				   Detab[heur].defmask, Detab[heur].defodi,
				   sbuf.st_mtime);
		    stray[i][0] = '\0';
		    determined = TRUE;
		    break;
#ifndef WISH
		case IDF_MAIL_IN:
		    if (part_heuristics(path, stray, i, Detab[heur].objtype,
					Detab[heur].defmask, Detab[heur].defodi, 
					sbuf.st_mtime, det_mail_in)) {
			determined = TRUE;
		    }
		    break;
		case IDF_MAIL_OUT:
		    if (part_heuristics(path, stray, i, Detab[heur].objtype,
					Detab[heur].defmask, Detab[heur].defodi, 
					sbuf.st_mtime, det_mail_out)) {
			determined = TRUE;
		    }
		    break;
#endif
#ifdef _DEBUG
		default:
		    _debug(stderr, "no such func: %d\n", Detab[heur].intern_func);
#endif
		}
	    }
	}
    }
    return(0);
}

static bool

exist_heuristics(path, name, objtype, mask, odi, mtime)
char *path, *name, *objtype;
long mask;
char *odi;
time_t mtime;			/* EFT abs k16 */
{
    register int i;
    struct opt_entry *partab;
    int part_offset, numparts;
    char *base;
    char *pattern;
    char *part_construct();
    int	found[MAXOBJPARTS];
    char pathbuf[PATHSIZ];
    char *part_match();

    /* get the parts table associated with objtype */

    if ((partab = obj_to_parts(objtype)) == NULL)
	return(FALSE);
    part_offset = partab->part_offset;
    numparts = partab->numparts;

    if ((base = part_match(name, Parts[part_offset].part_template)) == NULL)
	return(FALSE);

    found[0] = 1;
    for (i = 1; i < numparts; i++)
	found[i] = -1;

    for (i = 1; i < numparts; i++) {
	pattern = part_construct(base, Parts[part_offset+i].part_template);
	/* if any part's path is > PATHSIZ, do not display it */
	if ((int)strlen(pattern) + Pathlen + 3 > PATHSIZ) /* EFT k16 */
	    return(FALSE);
	sprintf(pathbuf, "%s/%s", path, pattern);
	if (access(pathbuf, 0) == -1) {	/* exists ? */
	    if (!(Parts[part_offset+i].part_flags & PRT_OPT))
		return(FALSE);
	} else {
	    found[i] = 1;
	}
    }
    /* file pathsize already tested in heuristics() - this uses "name" */
    ott_make_entry(name, base, objtype, mask|partab->int_class, odi, mtime);

    for (i = 1; i < numparts; i++) {
	if (found[i] == 1)
	    /* file pathsize already tested when each part found */
	    ott_make_entry(part_construct(base, 
					  Parts[part_offset+i].part_template), 
			   NULLSTR, NULL, mask|partab->int_class, NULL, mtime);
    }

    return(TRUE);
}

static bool
part_heuristics(path, stray, index, objtype, mask, odi, mtime, info_func)
char *path;
char stray[][FILE_NAME_SIZ];
char *objtype;
int index;
long mask;
char *odi;
time_t mtime;	/* EFT abs k16 */
void (*info_func)();
{
    register int i, j;
    int	found[MAXOBJPARTS];
    struct opt_entry *partab;
    int part_offset, numparts;
    int size = array_len(stray);
    char *p, base[PNAMESIZ];
    char fullpath[PATHSIZ];
    char *dname;
    char *part_match();

    /* get the parts table associated with objtype */

    if ((partab = obj_to_parts(objtype)) == NULL)
	return(FALSE);
    part_offset = partab->part_offset;
    numparts = partab->numparts;

    for (i = 0; i < numparts; i++)
	found[i] = -1;

    /* look for the entry index in the table, in reverse order since
     * the more restrictive names are at the end (for example, the first
     * parts template is often unrestricted).
     */

    for (i = numparts-1; i >= 0; i--)
	if (p = part_match(stray[index], Parts[part_offset+i].part_template)) {
	    found[i] = index;
	    strcpy(base, p);
	    break;
	}

    if (!p)			/* was not found */
	return(FALSE);

    /* if any part's path is > PATHSIZ, do not display it */
    if ((found[i] != -1) &&
	((int)strlen(stray[found[i]]) + Pathlen + 3 > PATHSIZ))	/* EFT k16 */
	return(FALSE);

    /* scan through the rest of the parts, looking in the stray
     * array for each one.  If a required part is ever not found,
     * or if the name is > PATHSIZ,
     * then immediately return FALSE.
     */

    for (i = 0; i < numparts; i++) {
	/* don't look for an already found part */
	if (found[i] != -1)
	    continue;
	for (j = 0; j < size; j++) {
	    if (stray[j][0] == '\0' || j == index)
		continue;
	    if ((p=part_match(stray[j], Parts[part_offset+i].part_template)) &&
		strcmp(p, base) == 0) {
		found[i] = j;
		break;
	    }
	}

	/* if a required part is not found, then return FALSE */

	if (found[i] == -1 && !(Parts[part_offset+i].part_flags & PRT_OPT))
	    return(FALSE);
	/* if any part's path is > PATHSIZ, do not display it */
	if ((found[i] != -1) &&
	    ((int)strlen(stray[found[i]]) + Pathlen + 3 > PATHSIZ)) /*EFT k16*/
	    return(FALSE);
    }

    /* at this point, we should have all the parts, so we will go
     * through the found array and make entries for each part.
     */

    j = 0;
    while (found[j] == -1)
	j++;

    if (info_func != NULL) {
	strcpy(fullpath, path);
	strcat(fullpath, "/");
	strcat(fullpath, stray[found[j]]);
	(*info_func)(fullpath, &dname, &odi, &mask, &mtime);
    } else {
	if (base && *base)
	    dname = base;
	else
	    dname = stray[found[j]];
    }
    /* file pathsize already tested when each part found */
    ott_make_entry(stray[found[j]], dname, objtype, mask|partab->int_class, odi, mtime);
    stray[found[j]][0] = '\0';

    for (i = j+1; i < numparts; i++) {
	if (found[i] != -1) {
	    /* file pathsize already tested when each part found */
	    ott_make_entry(stray[found[i]], NULL, NULL,
			   mask|partab->int_class, NULL, mtime);
	    stray[found[i]][0] = '\0';
	}
    }

    return(TRUE);
}

static int
look_at_bytes(path, file)
char *path, *file;
{
	char buf[PATHSIZ];
	register char	*p;
	register int	numread;
	register int	fd;

	if (Already_looked & LOOKED_AT_BYTES)
		return (0);

	Already_looked |= LOOKED_AT_BYTES;
	Seen_eighth_bit = Seen_non_printable = FALSE;
	sprintf(buf, "%s/%s", path, file);
	if ((fd = open(buf, O_RDONLY)) < 0)
		return (0);
	numread = read(fd, buf, sizeof(buf));
	close(fd);

	for (p = buf; numread > 0; numread--, p++)
		if (!isprint(*p) && !isspace(*p) && *p != '\7' && *p != '\b') {
			Seen_non_printable = TRUE;
			if (!isascii(*p))
				Seen_eighth_bit = TRUE;
		}
	return (0);
}

static int
magic_heuristics(path, name, objtype, mask, odi, mtime, offsets, bytes)
char *path, *name, *objtype;
long mask;
char *odi;
time_t mtime;	/* EFT abs k16 */
long *offsets;
char *bytes;
{
    FILE *fp;
    register int i;
    char buf[PATHSIZ];

    /* file pathsize already tested in heuristics() */
    sprintf(buf, "%s/%s", path, name);
    if ((fp = fopen(buf, "r")) == NULL)
	return(0);

    for (i = 0; offsets[i] != -1; i++) {
	/* if the next offset is equal to the previous plus one, no need
	 * to seek
	 */
	if (i == 0 || offsets[i-1] != offsets[i] - 1) {
	    if (fseek(fp, offsets[i], 0) != 0) {
		fclose(fp);
		return(0);
	    }
	}
	if (getc(fp) != bytes[i]) {
	    fclose(fp);
	    return(0);
	}
    }

    fclose(fp);
    ott_make_entry(name, name, objtype, mask, odi, mtime);
    name[0] = 0;

    return(1);
}


/* currently unimplemented */

static int
external_heuristics()
{
	return(0);
}

static int
oeu_heuristics(path, name, objtype, defmask, defodi, mtime)
char *path, *name, *objtype;
long defmask;
char *defodi;
time_t mtime;	/* EFT abs k16 */
{
    char fullpath_or_odi[PATHSIZ];
	
    /* file pathsize already tested in heuristics() */
    sprintf(fullpath_or_odi, "%s/%s", path, name);
    if (look_at_oeh(fullpath_or_odi) != 0) {
	return(0);
    }

    if (!objtype) {		/* any encrypted object */
	if (Oeh.encrytest)
	    objtype = Oeh.num;
	else
	    return (0);
    }
    /* reuse fullpath_or_odi variable */
    strcpy(fullpath_or_odi, "TYPE=");
    strcat(fullpath_or_odi, Oeh.type);
    ott_make_entry(name, name, objtype,
		   defmask, (defodi&&*defodi)?defodi:fullpath_or_odi, mtime);
    return(1);
}

int
look_at_oeh(path)
char *path;
{
	static int oeh_retcode;

	if (Already_looked & LOOKED_AT_OEH)
		return(oeh_retcode);

#ifdef WISH
	oeh_retcode = oeucheck(path, &Oeh, READ_HEADER);
#else
	oeh_retcode = oeuparse(path, &Oeh, READ_HEADER);
#endif
#ifdef _DEBUG
	_debug(stderr, "oeuparse(%s) returned %d\n", path, oeh_retcode);
#endif
	Already_looked |= LOOKED_AT_OEH;
	return(oeh_retcode);
}
