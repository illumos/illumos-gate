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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * diagcode library unit test
 *
 * usually run from "make test" target.  takes a single argument
 * which is the directory where the test dictionaries are found.
 * this test driver scans the dictionaries for comments of the form:
 *	#TEST:<routine>:<errno>:<input>:<output>
 * and executes that test.
 *
 * exit 0 and an "All tests passed" message means no failures.  otherwise
 * error messages are spewed as appropriate and exit value is non-zero.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <alloca.h>
#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdarg.h>

#include <fm/diagcode.h>

#define	MAXLINE	10240
#define	MAXARG 10
#define	MAXKEY 100
#define	MAXCODE 100

static char *Myname;
static char *Dict;
static int Line;
static int Errcount;
static fm_dc_handle_t *Dhp;

/*PRINTFLIKE1*/
static void
err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stderr, "%s: %s:%d ", Myname, Dict, Line);
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, "\n");
	Errcount++;
}

/* parse an expected errno value from test line (numeric or some symbolic) */
static int
geterrno(const char *s)
{
	if (*s == '\0' || isspace(*s))
		return (0);
	else if (isdigit(*s))
		return (atoi(s));
	else if (strcmp(s, "EPERM") == 0)
		return (EPERM);
	else if (strcmp(s, "ENOENT") == 0)
		return (ENOENT);
	else if (strcmp(s, "ESRCH") == 0)
		return (ESRCH);
	else if (strcmp(s, "ENOMEM") == 0)
		return (ENOMEM);
	else if (strcmp(s, "EACCES") == 0)
		return (EACCES);
	else if (strcmp(s, "EINVAL") == 0)
		return (EINVAL);
	else if (strcmp(s, "ERANGE") == 0)
		return (ERANGE);
	else if (strcmp(s, "ENOMSG") == 0)
		return (ENOMSG);
	else if (strcmp(s, "ENOTSUP") == 0)
		return (ENOTSUP);
	else {
		err("geterrno: don't know errno \"%s\"", s);
		Errcount++;
		return (0);
	}
}

/* call fm_dc_opendict() as part of a test */
static void
do_open(const char *dirpath, const char *dictname, char *argv[], int argc)
{
	int reterrno;
	int experrno;

	if (argc != 2) {
		err("argc != 2");
		return;
	}
	experrno = geterrno(argv[1]);

	if ((Dhp = fm_dc_opendict(FM_DC_VERSION, dirpath, dictname)) == NULL)
		reterrno = errno;
	else
		reterrno = 0;

	if (reterrno != experrno)
		err("opendict errno %d, expected %d", reterrno, experrno);
}

/* call fm_dc_closedict() as part of a test */
static void
do_close(const char *dirpath, const char *dictname, char *argv[], int argc)
{
	if (Dhp) {
		fm_dc_closedict(Dhp);
		Dhp = NULL;
	}
}

/* call fm_dc_codelen() as part of a test */
static void
do_codelen(const char *dirpath, const char *dictname, char *argv[], int argc)
{
	int retcodelen;
	int expcodelen;

	if (argc != 3) {
		err("argc != 3");
		return;
	}
	expcodelen = geterrno(argv[2]);

	if (Dhp == NULL) {
		err("codelen NULL handle");
		return;
	}

	retcodelen = fm_dc_codelen(Dhp);

	if (retcodelen != expcodelen)
		err("codelen %d, expected %d", retcodelen, expcodelen);
}

/* call fm_dc_maxkey() as part of a test */
static void
do_maxkey(const char *dirpath, const char *dictname, char *argv[], int argc)
{
	int retmaxkey;
	int expmaxkey;

	if (argc != 3) {
		err("argc != 3");
		return;
	}
	expmaxkey = geterrno(argv[2]);

	if (Dhp == NULL) {
		err("maxkey NULL handle");
		return;
	}

	retmaxkey = fm_dc_maxkey(Dhp);

	if (retmaxkey != expmaxkey)
		err("maxkey %d, expected %d", retmaxkey, expmaxkey);
}

/* call fm_dc_key2code() as part of a test */
static void
do_key2code(const char *dirpath, const char *dictname, char *argv[], int argc)
{
	int reterrno;
	int experrno;
	const char *key[MAXKEY];
	char code[MAXCODE];
	int nel;
	char *beginp;
	char *endp;

	if (argc < 3) {
		err("argc < 3");
		return;
	}
	if (argc > 4) {
		err("argc > 4");
		return;
	}
	experrno = geterrno(argv[1]);

	/* convert key into array */
	nel = 0;
	beginp = argv[2];
	while (nel < MAXKEY - 1) {
		key[nel++] = beginp;
		if ((endp = strchr(beginp, ' ')) != NULL) {
			*endp++ = '\0';
			beginp = endp;
		} else
			break;
	}
	key[nel] = NULL;

	if (Dhp == NULL) {
		err("key2code NULL handle");
		return;
	}

	if (fm_dc_key2code(Dhp, key, code, MAXCODE) < 0)
		reterrno = errno;
	else
		reterrno = 0;

	if (reterrno != experrno) {
		err("key2code errno %d, expected %d", reterrno, experrno);
		return;
	}

	if (reterrno == 0 && argc > 3 && strcmp(code, argv[3]))
		err("code \"%s\", expected \"%s\"", code, argv[3]);
}

/* call fm_dc_code2key() as part of a test */
static void
do_code2key(const char *dirpath, const char *dictname, char *argv[], int argc)
{
	int reterrno;
	int experrno;
	char keystr[MAXLINE];
	char *key[MAXKEY];
	int nel;

	if (argc < 3) {
		err("argc < 3");
		return;
	}
	if (argc > 4) {
		err("argc > 4");
		return;
	}
	experrno = geterrno(argv[1]);

	if (Dhp == NULL) {
		err("code2key NULL handle");
		return;
	}

	if (fm_dc_code2key(Dhp, argv[2], key, fm_dc_maxkey(Dhp)) < 0)
		reterrno = errno;
	else
		reterrno = 0;

	if (reterrno != experrno) {
		err("errno %d, expected %d", reterrno, experrno);
		return;
	}

	if (reterrno)
		return;

	if (argc > 3) {
		/* convert key into string */
		keystr[0] = '\0';
		for (nel = 0; key[nel]; nel++) {
			if (nel)
				(void) strcat(keystr, " ");
			(void) strcat(keystr, key[nel]);
		}

		if (strcmp(keystr, argv[3]))
			err("key \"%s\", expected \"%s\"", keystr, argv[3]);
	}
	for (nel = 0; key[nel]; nel++)
		free(key[nel]);
}

/* call fm_dc_getprop() as part of a test */
static void
do_getprop(const char *dirpath, const char *dictname, char *argv[], int argc)
{
	int reterrno;
	int experrno;
	const char *val;

	if (argc != 4) {
		err("argc != 4");
		return;
	}
	experrno = geterrno(argv[1]);

	if (Dhp == NULL) {
		err("getprop NULL handle");
		return;
	}

	if ((val = fm_dc_getprop(Dhp, argv[2])) == NULL)
		reterrno = errno;
	else
		reterrno = 0;

	if (reterrno != experrno) {
		err("getprop errno %d, expected %d", reterrno, experrno);
		return;
	}

	if (reterrno == 0 && strcmp(val, argv[3]))
		err("val \"%s\", expected \"%s\"", val, argv[3]);
}

/* scan a dictionary, looking for test directives embedded in the comments */
static void
testdict(const char *dirpath, const char *dictname)
{
	char linebuf[MAXLINE];
	char fname[MAXLINE];
	FILE *fp;

	(void) snprintf(fname, MAXLINE, "%s/%s.dict", dirpath, dictname);

	if ((fp = fopen(fname, "r")) == NULL) {
		perror(fname);
		Errcount++;
		return;
	}

	Line = 0;
	Dict = fname;

	while (fgets(linebuf, MAXLINE, fp) != NULL) {
		char *argv[MAXARG];
		int argc;
		char *beginp;
		char *endp;

		Line++;
		if (strncmp(linebuf, "#TEST:", 6))
			continue;

		if ((endp = strchr(linebuf, '\n')) != NULL)
			*endp = '\0';
		argc = 0;
		beginp = &linebuf[6];
		while (argc < MAXARG - 1) {
			argv[argc++] = beginp;
			if ((endp = strchr(beginp, ':')) != NULL) {
				*endp++ = '\0';
				beginp = endp;
			} else
				break;
		}
		argv[argc] = NULL;

		if (strcmp(argv[0], "open") == 0)
			do_open(dirpath, dictname, argv, argc);
		else if (strcmp(argv[0], "close") == 0)
			do_close(dirpath, dictname, argv, argc);
		else if (strcmp(argv[0], "codelen") == 0)
			do_codelen(dirpath, dictname, argv, argc);
		else if (strcmp(argv[0], "maxkey") == 0)
			do_maxkey(dirpath, dictname, argv, argc);
		else if (strcmp(argv[0], "key2code") == 0)
			do_key2code(dirpath, dictname, argv, argc);
		else if (strcmp(argv[0], "code2key") == 0)
			do_code2key(dirpath, dictname, argv, argc);
		else if (strcmp(argv[0], "getprop") == 0)
			do_getprop(dirpath, dictname, argv, argc);
		else {
			err("unknown TEST command: \"%s\"", argv[0]);
			Errcount++;
		}
	}

	(void) fclose(fp);

	if (Dhp) {
		fm_dc_closedict(Dhp);
		Dhp = NULL;
	}
}

/* scan a directory, looking for dictionaries to test against */
int
main(int argc, char *argv[])
{
	DIR *dirp;
	struct dirent *dp;

	if ((Myname = strrchr(argv[0], '/')) == NULL)
		Myname = argv[0];
	else
		Myname++;

	if (argc != 2) {
		(void) fprintf(stderr, "usage: %s test-directory\n", argv[0]);
		exit(1);
	}

	if ((dirp = opendir(argv[1])) == NULL) {
		perror(argv[1]);
		exit(1);
	}

	while ((dp = readdir(dirp)) != NULL) {
		char *ptr;

		if (dp->d_name[0] == '.')
			continue;

		if ((ptr = strrchr(dp->d_name, '.')) == NULL ||
		    strcmp(ptr, ".dict"))
			continue;

		*ptr = '\0';	/* remove the extension */
		testdict(argv[1], dp->d_name);
	}
	(void) closedir(dirp);

	if (Errcount == 0)
		(void) printf("%s: All tests passed.\n", Myname);

	return (Errcount);
}
