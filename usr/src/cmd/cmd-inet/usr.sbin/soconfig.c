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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/stat.h>
#include <unistd.h>

#define	MAXLINELEN	4096

/*
 * Usage:
 *	soconfig -d <dir>
 *		Reads input from files in dir.
 *
 *	soconfig -f <file>
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
 *
 *	soconfig -l
 *		print the in-kernel socket configuration table
 *
 * Filter Operations (Consolidation Private):
 *
 *	soconfig -F <name> <modname> {auto [top | bottom | before:filter |
 *		after:filter] | prog} <fam>:<type>:<proto>,...
 *		configure filter
 *
 *	soconfig -F <name>
 *		unconfigures filter
 */

static int	parse_files_in_dir(const char *dir);

static int	parse_file(char *filename);

static int	split_line(char *line, char *argvec[], int maxargvec);

static int	parse_params(char *famstr, char *typestr, char *protostr,
				char *path, const char *file, int line);

static int	parse_int(char *str);

static void	usage(void);

static int	parse_filter_params(int argc, char **argv);

static int	print_socktable();

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

	if (argc == 1 && strcmp(argv[0], "-l") == 0) {
		ret = print_socktable();
		exit(ret);
	}

	if (argc >= 2 && strcmp(argv[0], "-F") == 0) {
		argc--; argv++;
		ret = parse_filter_params(argc, argv);
		exit(ret);
	}
	if (argc == 2 && strcmp(argv[0], "-d") == 0) {
		ret = parse_files_in_dir(argv[1]);
		exit(ret);
	}
	if (argc == 2 && strcmp(argv[0], "-f") == 0) {
		ret = parse_file(argv[1]);
		exit(ret);
	}
	if (argc == 3) {
		ret = parse_params(argv[0], argv[1], argv[2], NULL, NULL, -1);
		exit(ret);
	}
	if (argc == 4) {
		ret = parse_params(argv[0], argv[1], argv[2], argv[3],
		    NULL, -1);
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
	    "Usage:	soconfig -d <dir>\n"
	    "\tsoconfig -f <file>\n"
	    "\tsoconfig <fam> <type> <protocol> <path|module>\n"
	    "\tsoconfig <fam> <type> <protocol>\n"
	    "\tsoconfig -l\n"));
}

/*
 * Parse all files in the given directory.
 */
static int
parse_files_in_dir(const char *dirname)
{
	DIR		*dp;
	struct dirent 	*dirp;
	struct stat	stats;
	char		buf[MAXPATHLEN];

	if ((dp = opendir(dirname)) == NULL) {
		fprintf(stderr, gettext("failed to open directory '%s': %s\n"),
		    dirname, strerror(errno));
		return (1);
	}

	while ((dirp = readdir(dp)) != NULL) {
		if (dirp->d_name[0] == '.')
			continue;

		if (snprintf(buf, sizeof (buf), "%s/%s", dirname,
		    dirp->d_name) >= sizeof (buf)) {
			fprintf(stderr,
			    gettext("path name is too long: %s/%s\n"),
			    dirname, dirp->d_name);
			continue;
		}
		if (stat(buf, &stats) == -1) {
			fprintf(stderr,
			    gettext("failed to stat '%s': %s\n"), buf,
			    strerror(errno));
			continue;
		}
		if (!S_ISREG(stats.st_mode))
			continue;

		(void) parse_file(buf);
	}

	closedir(dp);

	return (0);
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
			    argvec[2], NULL, filename, linecount);
			break;
		case 4:
			numerror += parse_params(argvec[0], argvec[1],
			    argvec[2], argvec[3], filename, linecount);
			break;
		default:
			numerror++;
			fprintf(stderr,
			    gettext("Malformed line: <%s>\n"), line);
			fprintf(stderr,
			    gettext("\ton line %d in %s\n"), linecount,
			    filename);
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
parse_params(char *famstr, char *typestr, char *protostr, char *path,
    const char *file, int line)
{
	int cmd, fam, type, protocol;

	fam = parse_int(famstr);
	if (fam == -1) {
		fprintf(stderr, gettext("Bad family number: %s\n"), famstr);
		if (line != -1)
			fprintf(stderr,
			    gettext("\ton line %d in %s\n"), line, file);
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
			    gettext("\ton line %d in %s\n"), line, file);
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
			    gettext("\ton line %d in %s\n"), line, file);
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
				    gettext("\ton line %d in %s\n"), line,
				    file);
			else {
				fprintf(stderr, "\n");
				usage();
			}
			return (1);
		}

		cmd = SOCKCONFIG_ADD_SOCK;
	} else {
		cmd = SOCKCONFIG_REMOVE_SOCK;
	}

#ifdef DEBUG
	printf("not calling sockconfig(%d, %d, %d, %d, %s)\n",
	    cmd, fam, type, protocol, path == NULL ? "(null)" : path);
#else
	if (_sockconfig(cmd, fam, type, protocol, path) == -1) {
		char *s;

		switch (errno) {
		case EEXIST:
			s = gettext("Mapping exists");
			break;
		default:
			s = strerror(errno);
			break;
		}

		fprintf(stderr,
		    gettext("warning: socket configuration failed "
		    "for family %d type %d protocol %d: %s\n"),
		    fam, type, protocol, s);
		if (line != -1) {
			fprintf(stderr,
			    gettext("\ton line %d in %s\n"), line, file);
		}
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

/*
 * Add and remove socket filters.
 */
static int
parse_filter_params(int argc, char **argv)
{
	struct sockconfig_filter_props filprop;
	sof_socktuple_t *socktuples;
	size_t tupcnt, nalloc;
	char *hintarg, *socktup, *tupstr;
	int i;

	if (argc == 1) {
		if (_sockconfig(SOCKCONFIG_REMOVE_FILTER, argv[0], 0,
		    0, 0) < 0) {
			switch (errno) {
			case ENXIO:
				fprintf(stderr,
				    gettext("socket filter is not configured "
				    "'%s'\n"), argv[0]);
				break;
			default:
				perror("sockconfig");
				break;
			}
			return (1);
		}
		return (0);
	}

	if (argc < 4 || argc > 5)
		return (1);


	if (strlen(argv[1]) >= MODMAXNAMELEN) {
		fprintf(stderr,
		    gettext("invalid module name '%s': name too long\n"),
		    argv[1]);
		return (1);
	}
	filprop.sfp_modname = argv[1];

	/* Check the attach semantics */
	if (strcmp(argv[2], "auto") == 0) {
		filprop.sfp_autoattach = B_TRUE;
		if (argc == 5) {
			/* placement hint */
			if (strcmp(argv[3], "top") == 0) {
				filprop.sfp_hint = SOF_HINT_TOP;
			} else if (strcmp(argv[3], "bottom") == 0) {
				filprop.sfp_hint = SOF_HINT_BOTTOM;
			} else {
				if (strncmp(argv[3], "before", 6) == 0) {
					filprop.sfp_hint = SOF_HINT_BEFORE;
				} else if (strncmp(argv[3], "after", 5) == 0) {
					filprop.sfp_hint = SOF_HINT_AFTER;
				} else {
					fprintf(stderr,
					    gettext("invalid placement hint "
					    "'%s'\n"), argv[3]);
					return (1);
				}

				hintarg = strchr(argv[3], ':');
				if (hintarg == NULL ||
				    (strlen(++hintarg) == 0) ||
				    (strlen(hintarg) >= FILNAME_MAX)) {
					fprintf(stderr,
					    gettext("invalid placement hint "
					    "argument '%s': name too long\n"),
					    argv[3]);
					return (1);
				}

				filprop.sfp_hintarg = hintarg;
			}
		} else {
			filprop.sfp_hint = SOF_HINT_NONE;
		}
	} else if (strcmp(argv[2], "prog") == 0) {
		filprop.sfp_autoattach = B_FALSE;
		filprop.sfp_hint = SOF_HINT_NONE;
		/* cannot specify placement hint for programmatic filter */
		if (argc == 5) {
			fprintf(stderr,
			    gettext("placement hint specified for programmatic "
			    "filter\n"));
			return (1);
		}
	} else {
		fprintf(stderr, gettext("invalid attach semantic '%s'\n"),
		    argv[2]);
		return (1);
	}

	/* parse the socket tuples */
	nalloc = 4;
	socktuples = calloc(nalloc, sizeof (sof_socktuple_t));
	if (socktuples == NULL) {
		perror("calloc");
		return (1);
	}

	tupcnt = 0;
	tupstr = argv[(argc == 4) ? 3 : 4];
	while ((socktup = strsep(&tupstr, ",")) != NULL) {
		int val;
		char *valstr;

		if (tupcnt == nalloc) {
			sof_socktuple_t *new;

			nalloc *= 2;
			new = realloc(socktuples,
			    nalloc * sizeof (sof_socktuple_t));
			if (new == NULL) {
				perror("realloc");
				free(socktuples);
				return (1);
			}
			socktuples = new;
		}
		i = 0;
		while ((valstr = strsep(&socktup, ":")) != NULL && i < 3) {
			val = parse_int(valstr);
			if (val == -1) {
				fprintf(stderr, gettext("bad socket tuple\n"));
				free(socktuples);
				return (1);
			}
			switch (i) {
			case 0:	socktuples[tupcnt].sofst_family = val; break;
			case 1:	socktuples[tupcnt].sofst_type = val; break;
			case 2:	socktuples[tupcnt].sofst_protocol = val; break;
			}
			i++;
		}
		if (i != 3) {
			fprintf(stderr, gettext("bad socket tuple\n"));
			free(socktuples);
			return (1);
		}
		tupcnt++;
	}
	if (tupcnt == 0) {
		fprintf(stderr, gettext("no socket tuples specified\n"));
		free(socktuples);
		return (1);
	}
	filprop.sfp_socktuple_cnt = tupcnt;
	filprop.sfp_socktuple = socktuples;

	if (_sockconfig(SOCKCONFIG_ADD_FILTER, argv[0], &filprop, 0, 0) < 0) {
		switch (errno) {
		case EINVAL:
			fprintf(stderr,
			    gettext("invalid socket filter configuration\n"));
			break;
		case EEXIST:
			fprintf(stderr,
			    gettext("socket filter is already configured "
			    "'%s'\n"), argv[0]);
			break;
		case ENOSPC:
			fprintf(stderr, gettext("unable to satisfy placement "
			    "constraint\n"));
			break;
		default:
			perror("sockconfig");
			break;
		}
		free(socktuples);
		return (1);
	}
	free(socktuples);
	return (0);
}

/*
 *  Print the in-kernel socket configuration table
 */

static int
print_socktable()
{
	sockconfig_socktable_t sc_table;
	int i;

	(void) memset(&sc_table, 0, sizeof (sockconfig_socktable_t));

	/* get number of entries */
	if (_sockconfig(SOCKCONFIG_GET_SOCKTABLE, &sc_table) == -1) {
		fprintf(stderr,
		    gettext("cannot get in-kernel socket table: %s\n"),
		    strerror(errno));
		return (-1);
	}
	if (sc_table.num_of_entries == 0)
		return (0);

	sc_table.st_entries = calloc(sc_table.num_of_entries,
	    sizeof (sockconfig_socktable_entry_t));
	if (sc_table.st_entries == NULL) {
		fprintf(stderr, gettext("out of memory\n"));
		return (-1);
	}

	/* get socket table entries */
	if (_sockconfig(SOCKCONFIG_GET_SOCKTABLE, &sc_table) == -1) {
		fprintf(stderr,
		    gettext("cannot get in-kernel socket table: %s\n"),
		    strerror(errno));
		return (-1);
	}

	printf("%6s %4s %5s %15s %15s %6s %6s\n",
	    "FAMILY", "TYPE", "PROTO", "STRDEV", "SOCKMOD",
	    "REFS", "FLAGS");
	for (i = 0; i < sc_table.num_of_entries; i++) {
		printf("%6u %4u %5u %15s %15s %6u %#6x\n",
		    sc_table.st_entries[i].se_family,
		    sc_table.st_entries[i].se_type,
		    sc_table.st_entries[i].se_protocol,
		    (strcmp(sc_table.st_entries[i].se_modname,
		    "socktpi") == 0) ?
		    sc_table.st_entries[i].se_strdev : "-",
		    sc_table.st_entries[i].se_modname,
		    sc_table.st_entries[i].se_refcnt,
		    sc_table.st_entries[i].se_flags);
	}
	free(sc_table.st_entries);
	return (0);
}
