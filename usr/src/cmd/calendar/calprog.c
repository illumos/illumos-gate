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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	/usr/lib/calprog produces an egrep -f file
 *	that will select today's and tomorrow's
 *	calendar entries, with special weekend provisions
 *	used by calendar command
 */


#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <time.h>
#include <sys/stat.h>
#include <locale.h>
#include <errno.h>


#define	DAY	(3600*24L)

extern  char	*getenv(), *malloc();

static char	*file;
static int	old_behavior;
static int	linenum = 1;
static time_t	t;
static char	errmsg[128];
static char	*errlst[] = {
/*	0	*/ "error on open of \"%s\", errno = %d",
/*	1	*/ "could not malloc enough memory",
/*	2	*/ "error on stat of \"%s\", errno = %d",
/*	3	*/ "file \"%s\" is not a regular file",
/*	4	*/ "error in reading the file \"%s\"",
/*	5	*/ "\"%s\" file: error on line %d",
/*	6	*/ "\"%s\" file: format descriptions are missing"
};

static
char *month[] = {
	"[Jj]an",
	"[Ff]eb",
	"[Mm]ar",
	"[Aa]pr",
	"[Mm]ay",
	"[Jj]un",
	"[Jj]ul",
	"[Aa]ug",
	"[Ss]ep",
	"[Oo]ct",
	"[Nn]ov",
	"[Dd]ec"
};

static void read_tmpl(void);
static void error(const char *fmt, ...);
static void generate(char *);

static void
tprint(time_t t)
{
	struct tm *tm;
	tm = localtime(&t);
	(void) printf
		("(^|[ \t(,;])((%s[^ ]* *|0*%d/|\\*/)0*%d)([^0123456789]|$)\n",
		month[tm->tm_mon], tm->tm_mon + 1, tm->tm_mday);
}

int
main(int argc, char *argv[])
{

	(void) setlocale(LC_ALL, "");
	(void) time(&t);
	if (((file = getenv("DATEMSK")) == 0) || file[0] == '\0')
		old_behavior = 1;
	if (old_behavior)
		tprint(t);
	else
		read_tmpl();
	switch (localtime(&t)->tm_wday) {
	case 5:
		t += DAY;
		if (old_behavior)
			tprint(t);
		else
			read_tmpl();
	case 6:
		t += DAY;
		if (old_behavior)
			tprint(t);
		else
			read_tmpl();
	default:
		t += DAY;
		if (old_behavior)
			tprint(t);
		else
			read_tmpl();
	}
	return (0);
}


static void
read_tmpl(void)
{
	char	*clean_line();
	FILE  *fp;
	char *bp, *start;
	struct stat sb;
	int	no_empty = 0;

	if ((start = (char *)malloc(512)) == NULL)
		error(errlst[1]);
	if ((fp = fopen(file, "r")) == NULL)
		error(errlst[0], file, errno);
	if (fstat(fileno(fp), &sb) < 0)
		error(errlst[2], file, errno);
	if ((sb.st_mode & S_IFMT) != S_IFREG)
		error(errlst[3], file);
	for (;;) {
		bp = start;
		if (!fgets(bp, 512, fp)) {
			if (!feof(fp)) {
				free(start);
				fclose(fp);
				error(errlst[4], file);
				}
			break;
		}
		if (*(bp+strlen(bp)-1) != '\n')   /* terminating newline? */
			{
			free(start);
			fclose(fp);
			error(errlst[5], file, linenum);
			}
		bp = clean_line(bp);
		if (strlen(bp))  /*  anything left?  */
			{
			no_empty++;
			generate(bp);
			}
	linenum++;
	}
	free(start);
	fclose(fp);
	if (!no_empty)
		error(errlst[6], file);
}


char  *
clean_line(char *s)
{
	char  *ns;

	*(s + strlen(s) -1) = (char)0; /* delete newline */
	if (!strlen(s))
		return (s);
	ns = s + strlen(s) - 1; /* s->start; ns->end */
	while ((ns != s) && (isspace(*ns))) {
		*ns = (char)0;	/* delete terminating spaces */
		--ns;
		}
	while (*s)		/* delete beginning white spaces */
		if (isspace(*s))
			++s;
		else
			break;
	return (s);
}

static void
error(const char *fmt, ...)
{
	va_list	args;

	va_start(args, fmt);
	(void) vsnprintf(errmsg, sizeof (errmsg), fmt, args);
	fprintf(stderr, "%s\n", errmsg);
	va_end(args);
	exit(1);
}

static void
generate(char *fmt)
{
	char	timebuf[1024];
	char	outbuf[2 * 1024];
	char	*tb, *ob;
	int	space = 0;

	strftime(timebuf, sizeof (timebuf), fmt, localtime(&t));
	tb = timebuf;
	ob = outbuf;
	while (*tb)
		if (isspace(*tb)) {
			++tb;
			space++;
		}
		else
			{
			if (space) {
				*ob++ = '[';
				*ob++ = ' ';
				*ob++ = '\t';
				*ob++ = ']';
				*ob++ = '*';
				space = 0;
				continue;
			}
			if (isalpha(*tb)) {
				*ob++ = '[';
				*ob++ = toupper(*tb);
				*ob++ = tolower(*tb++);
				*ob++ = ']';
				continue;
			}
			else
				*ob++ = *tb++;
				if (*(tb - 1) == '0')
					*ob++ = '*';
			}
	*ob = '\0';
	printf("%s\n", outbuf);
}
