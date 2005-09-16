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

#include	<pwd.h>
#include	<stdio.h>
#include	<string.h>
#include	<time.h>
#include	<values.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	"wish.h"
#undef	min
#undef	max
#include	"typetab.h"		/* for ott masks ott_tab ott_entry() */
#include	"partabdefs.h"
#include	"var_arrays.h"		/* for array_len() */
#include 	"sizes.h"

#ifndef TEST

#include	"eval.h"

#else  /* TEST */
#define IOSTRUCT	FILE
#define putac		putc
#define putastr		fputs
#define mess_temp	puts
#endif /* TEST */

#define DAY	(24L * 60L * 60L)

extern struct ott_entry	*Cur_entry;
extern struct opt_entry	Partab[];
extern char *Oasys;

static char	any[] = "any";
static char path_buf[PATHSIZ];
static void traverse();
static char *myregcmp(char *s);
static int range(char *s, int origin, int *mindays, int *maxdays);

#ifdef TEST
int
main(argc, argv)
int	argc;
char	*argv[];
{
	wish_init(argc, argv);
	odftread();
	genfind(argc, argv, stdin, stdout);
	return (0);
}
#endif /* TEST */

/*
 * usage: genfind path filename type owner age
 */
int
genfind(argc, argv, instr, outstr, errstr)
int	argc;
char	*argv[];
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
IOSTRUCT *errstr;
{
	FILE	*fp;
	register pid_t	uid;	/* EFT abs k16 */
	int	min_days;
	int	max_days;
	int	do_traverse;
	int	origin;
	int	pathpos;
	int	namepos;
	char	path[PATHSIZ];
	char	buf[BUFSIZ];
	char 	*type;
	char	*dtype;
	char	allpath[PATHSIZ];
	char 	*Allfile="/info/OH/externals/allobjs";
	register int i;
	register char	*pattern;
	register struct	passwd *passwdptr;
	struct	passwd *getpwnam();

	if (argc < 6 && argc > 8) {
		mess_temp("Arguments invalid");
		return FAIL;
	}
	i = 1;
	origin = 0;
	if (strcmp(argv[i], "-1") == 0) {
		origin = 1;
		i++;
	}
	else
		do_traverse = TRUE;
	if (strcmp(argv[i], "-n") == 0) {
		do_traverse = FALSE;
		i++;
	}
	else
		do_traverse = TRUE;
	pathpos = i;
	/* traverse assumes at least 1 extra byte available in path */
	if ((int)strlen(argv[i]) > PATHSIZ - 2) {        /* EFT k16 */
		mess_temp("Path too long");
		return FAIL;
	}
	strncpy(path, argv[i], PATHSIZ);
	path[sizeof(path) - 1] = '\0';
	if ((pattern = myregcmp(argv[++i])) == NULL) {
		mess_temp("Name invalid");
		return FAIL;
	}
	namepos = ++i;
	if (strCcmp(argv[++i], any)) {
		if ((passwdptr = getpwnam(argv[i])) == NULL) {
			mess_temp("Owner invalid");
			return FAIL;
		}
		uid = passwdptr->pw_uid;
	}
	else
		uid = -1;
	if (strCcmp(argv[++i], any)) {
		if (range(argv[i], origin, &min_days, &max_days) < 0) {
			mess_temp("Age invalid");
			return FAIL;
		}
	}
	else
		min_days = -1;

	(void) strcpy(allpath, Oasys);
	(void) strcat(allpath, Allfile);


	if ((fp = fopen(allpath, "r")) == NULL) 
		type=NULL;
	else 
		while(fgets(buf,BUFSIZ,fp)) {
			type=strtok(buf,"\t");
			dtype=strtok(NULL,"\n");
			if (strcmp(argv[namepos],dtype) == 0)
				break;
			type=NULL;
		}
	fclose(fp);

	traverse(path, pattern, uid, strCcmp(argv[namepos], any) ? argv[namepos] : NULL, min_days, max_days, argv[pathpos], do_traverse, outstr, type );
	return SUCCESS;
}

static void
traverse(path, pattern, uid, objtype, min_days, max_days, prefix, do_traverse, outstr, type)
char	*path;
char	*pattern;
int	uid;
char	*objtype;
int	min_days;
int	max_days;
char	*prefix;
int	do_traverse;
IOSTRUCT	*outstr;
char	*type;
{
    register int	i;
    register int	length;
    register int	ott_len;
    register int	numdays;
    char	*basename;
    char	*objname;
    char	*typename;
    char	*intobj;
    long	mask;
    time_t	now;           /* EFT abs k16 */
    struct	stat	filestat;
    struct tm	*t;
    struct ott_tab	*ott;
    struct ott_tab	*ott_get();
    struct ott_entry	*entry;
    char	*bsd_path_to_title();
    char	*regex();
    time_t	time();		/* EFT abs k16 */
    struct tm	*localtime();

    /* check to see if enough space to put file names */
    if ((length = strlen(path)) >= PATHSIZ - 2)
	return;
    if ((ott = ott_get(path, OTT_SALPHA, 0, 0, 0)) == NULL)
	return;
    entry = Cur_entry;
    ott_len = array_len(ott->parents);
    now = time(NULL);
    t = localtime(&now);
    now += (60 - t->tm_sec) + 60 * ((59 - t->tm_min) + 60 * (23 - t->tm_hour));
    for (i = 0; i < ott_len; ++i) {
	/* shorter names */
	basename = entry[ott->parents[i]].name;
	objname = entry[ott->parents[i]].dname;
	typename = entry[ott->parents[i]].display;
	intobj = entry[ott->parents[i]].objtype;
	mask = entry[ott->parents[i]].objmask;
	/* object's name not viewable or marked deleted */
	if (basename[0] == '\0' || (mask & M_WB) || (mask & M_DL))
	    continue;
	/*
	 * these tests are performed in order of increasing
	 * computational cost
	 */
	path[length] = '/';
	strncpy(&path[length + 1], basename, PATHSIZ - length - 2);

	if ((!objtype || !strcmp(objtype, typename) ||
	     !strcmp(intobj, type)) && regex(pattern, objname)) {
	    numdays = (int) ((now - entry[ott->parents[i]].mtime) / DAY);
	    if (min_days < 0 || (numdays >= min_days && numdays <= max_days)) {
		if (uid >= 0 && stat(path, &filestat))
		    continue;
		if (uid < 0 || filestat.st_uid == uid) {
		    putastr(path, outstr);
		    putac(';', outstr);
		    putastr(entry[ott->parents[i]].objtype, outstr);
		    putac(';', outstr);
		    path[length] = '\0';
		    if (do_traverse) {

			strcpy(path_buf,path);
			strcat(path_buf,"/");
			strcat(path_buf,objname);
			putastr(bsd_path_to_title(&path_buf[strlen(prefix)+1],
				COLS - 30), outstr);
		    } else
			putastr(objname, outstr);
		    path[length] = '/';
		    putac(';', outstr);
		    putastr(typename, outstr);
		    putac('\n', outstr);
		}
	    }
	}
	if (mask & CL_DIR) {
	    /* object is a directory and not deleted, search */
	    if (do_traverse)
		traverse(path, pattern, uid, objtype, min_days, max_days,
			 prefix, do_traverse, outstr, type);
	    path[length] = '\0';
	    if ((ott = ott_get(path, OTT_SALPHA, 0, 0, 0)) == NULL)
		return;
	    entry = Cur_entry;
	    ott_len = array_len(ott->parents);
	}
    }				/* end of for loop */
}

static int
range(char *s, int origin, int *mindays, int *maxdays)
{
	char	*s1;
	long	strtol();

	switch (*s) {
	case '<':
		*mindays = 0;
		*maxdays = (int) strtol(s + 1, &s1, 10);
		break;
	case '>':
		*maxdays = MAXINT;
		*mindays = (int) strtol(s + 1, &s1, 10);
		break;
	default:
		*mindays = (int) strtol(s, &s1, 10);
		if (s1 == s)
			return FAIL;
		if (*s1 == '-')
			*maxdays = (int) strtol(s1 + 1, &s1, 10);
		else if (*s1 == '.' && s1[1] == '.')
			*maxdays = (int) strtol(s1 + 2, &s1, 10);
		else
			*maxdays = *mindays;
		break;
	}
	if (origin && *mindays == 1)
		*mindays = 0;
	if (*mindays < 0 || *maxdays < 0)
		return FAIL;
	return (*s1 == '\0') ? SUCCESS : FAIL;
}

static char *
myregcmp(char *s)
{
	register char	*p;
	register char	*q;
	register int	len;
	static char	special[] = "+.${}()";
	char	*regcmp();
	char	*strnsave();
	char	*_backslash();

	len = strlen(s) * 2 + 4;
	p = strnsave("^", len);
	(void) strcat(p, s);
	(void) _backslash(p, len, special, special);
	(void) strcat(p, "$");
	for (q = p; *q; q++)
		switch (*q) {
		case '*':
			memshift(q + 1, q, strlen(q) + 1);
			*q++ = '.';
			break;
		case '?':
			*q = '.';
			break;
		case '\\':
			if (!*++q)
				q--;
			break;
		case '[':
			if (q[1] == '!')
				q[1] = '^';
			break;
		default:
			break;
		}
	q = regcmp(p, NULL);
	free(p);
	return q;
}
