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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <locale.h>

#define	MAXLINELEN	4096

/*
 * Usage:
 *	sonconfig -f <file>
 *		Reads input from file. The file is structured as
 *			 <fam> <type> <protocol> <path|module>
 *			 <fam> <type> <protocol>
 *		with the first line registering and the second line
 *		deregistering.
 *
 *	soconfig <fam> <type> <protocol> <path|module>
 *		registers
 *
 *	soconfig <fam> <type> <protocol>
 *		deregisters
 */

static int	parse_file(char *filename);

static int	split_line(char *line, char *argvec[], int maxargvec);

static int	parse_params(char *famstr, char *typestr, char *protostr,
				char *path, int line);

static int	parse_int(char *str);

static void	usage(void);

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int ret;

	argc--; argv++;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc == 2 && strcmp(argv[0], "-f") == 0) {
		ret = parse_file(argv[1]);
		exit(ret);
	}
	if (argc == 3) {
		ret = parse_params(argv[0], argv[1], argv[2], NULL, -1);
		exit(ret);
	}
	if (argc == 4) {
		ret = parse_params(argv[0], argv[1], argv[2], argv[3], -1);
		exit(ret);
	}
	usage();
	exit(1);
	/* NOTREACHED */
}

static void
usage(void)
{
	fprintf(stderr, gettext(
	    "Usage:	soconfig -f <file>\n"
	    "\tsoconfig <fam> <type> <protocol> <path|module>\n"
	    "\tsoconfig <fam> <type> <protocol>\n"));
}

/*
 * Open the specified file and parse each line. Skip comments (everything
 * after a '#'). Return 1 if at least one error was encountered; otherwise 0.
 */
static int
parse_file(char *filename)
{
	char line[MAXLINELEN];
	char pline[MAXLINELEN];
	int argcount;
	char *argvec[20];
	FILE *fp;
	int linecount = 0;
	int numerror = 0;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		perror("soconfig: open");
		fprintf(stderr, "\n");
		usage();
		return (1);
	}

	while (fgets(line, sizeof (line) - 1, fp) != NULL) {
		linecount++;
		strcpy(pline, line);
		argcount = split_line(pline, argvec,
		    sizeof (argvec) / sizeof (argvec[0]));
#ifdef DEBUG
		{
			int i;

			printf("scanned %d args\n", argcount);
			for (i = 0; i < argcount; i++)
				printf("arg[%d]: %s\n", i, argvec[i]);
		}
#endif /* DEBUG */
		switch (argcount) {
		case 0:
			/* Empty line - or comment only line */
			break;
		case 3:
			numerror += parse_params(argvec[0], argvec[1],
			    argvec[2], NULL, linecount);
			break;
		case 4:
			numerror += parse_params(argvec[0], argvec[1],
			    argvec[2], argvec[3], linecount);
			break;
		default:
			numerror++;
			fprintf(stderr,
			    gettext("Malformed line: <%s>\n"), line);
			fprintf(stderr,
			    gettext("\ton line %d\n"), linecount);
			break;
		}
	}
	(void) fclose(fp);

	if (numerror > 0)
		return (1);
	else
		return (0);
}

/*
 * Parse a line splitting it off at whitspace characters.
 * Modifies the content of the string by inserting NULLs.
 */
static int
split_line(char *line, char *argvec[], int maxargvec)
{
	int i = 0;
	char *cp;

	/* Truncate at the beginning of a comment */
	cp = strchr(line, '#');
	if (cp != NULL)
		*cp = NULL;

	/* CONSTCOND */
	while (1) {
		/* Skip any whitespace */
		while (isspace(*line) && *line != NULL)
			line++;

		if (i >= maxargvec)
			return (i);

		argvec[i] = line;
		if (*line == NULL)
			return (i);
		i++;
		/* Skip until next whitespace */
		while (!isspace(*line) && *line != NULL)
			line++;
		if (*line != NULL) {
			/* Break off argument */
			*line++ = NULL;
		}
	}
	/* NOTREACHED */
}

/*
 * Parse the set of parameters and issues the sockconfig syscall.
 * If line is not -1 it is assumed to be the line number in the file.
 */
static int
parse_params(char *famstr, char *typestr, char *protostr, char *path, int line)
{
	int fam, type, protocol;

	fam = parse_int(famstr);
	if (fam == -1) {
		fprintf(stderr, gettext("Bad family number: %s\n"), famstr);
		if (line != -1)
			fprintf(stderr,
			    gettext("\ton line %d\n"), line);
		else {
			fprintf(stderr, "\n");
			usage();
		}
		return (1);
	}

	type = parse_int(typestr);
	if (type == -1) {
		fprintf(stderr,
		    gettext("Bad socket type number: %s\n"), typestr);
		if (line != -1)
			fprintf(stderr,
			    gettext("\ton line %d\n"), line);
		else {
			fprintf(stderr, "\n");
			usage();
		}
		return (1);
	}

	protocol = parse_int(protostr);
	if (protocol == -1) {
		fprintf(stderr,
		    gettext("Bad protocol number: %s\n"), protostr);
		if (line != -1)
			fprintf(stderr,
			    gettext("\ton line %d\n"), line);
		else {
			fprintf(stderr, "\n");
			usage();
		}
		return (1);
	}


	if (path != NULL) {
		struct stat stats;

		if (strncmp(path, "/dev", strlen("/dev")) == 0 &&
		    stat(path, &stats) == -1) {
			perror(path);
			if (line != -1)
				fprintf(stderr,
				    gettext("\ton line %d\n"), line);
			else {
				fprintf(stderr, "\n");
				usage();
			}
			return (1);
		}
	}

#ifdef DEBUG
	printf("not calling sockconfig(%d, %d, %d, %s)\n",
	    fam, type, protocol, path == NULL ? "(null)" : path);
#else
	if (_sockconfig(fam, type, protocol, path) == -1) {
		perror("sockconfig");
		return (1);
	}
#endif
	return (0);
}

static int
parse_int(char *str)
{
	char *end;
	int res;

	res = strtol(str, &end, 0);
	if (end == str)
		return (-1);
	return (res);
}
