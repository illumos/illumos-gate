/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Parse a "Manlink" file and create the symlinks described within under a
 * specified destination directory.
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <libgen.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>

static const char *progname = NULL;

static void
usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr,
	    "Usage: %s [opts] -d <destdir> <input(s)>\n\n"
	    "Options:\n"
	    "\t-n\tdry run\n",
	    progname);
}

typedef struct manlink_iter {
	FILE	*mi_fp;
	size_t	mi_cap;
	char	*mi_line;
	char	*mi_tok_saveptr;
	char	*mi_target;
} manlink_iter_t;

typedef struct manlink_iter_result {
	const char	*mir_name;
	const char	*mir_target;
} manlink_iter_res_t;

static bool
valid_name(const char *name)
{
	for (char c; (c = *name) != '\0'; name++) {
		if (c == '/') {
			/* Link names expected to be in base directory */
			return (false);
		}
		if (c == '#') {
			/* Should not contain comment character */
			return (false);
		}
		if (!isalnum(c) && !ispunct(c)) {
			/* Expect "normal" man page names */
			return (false);
		}
	}
	return (true);
}

static bool
valid_target(const char *target)
{
	for (char c; (c = *target) != '\0'; target++) {
		if (isalnum(c)) {
			continue;
		}
		switch (c) {
		case '.':
		case '_':
		case '-':
		case '/':
			break;
		default:
			return (false);
		}
	}
	return (true);
}

static void
link_iter_init(FILE *ifp, manlink_iter_t *itr)
{
	itr->mi_fp = ifp;
	itr->mi_cap = 0;
	itr->mi_line = NULL;
	itr->mi_target = NULL;
}

static void
link_iter_fini(manlink_iter_t *itr)
{
	(void) fclose(itr->mi_fp);
	free(itr->mi_line);
	free(itr->mi_target);
}

static bool
link_iter_next(manlink_iter_t *itr, const char **namep, const char **targetp)
{
	ssize_t len;

	while ((len = getline(&itr->mi_line, &itr->mi_cap, itr->mi_fp)) >= 1) {
		char *line = itr->mi_line;

		/* Nuke the trailing newline (if any) */
		if (line[len - 1] == '\n') {
			line[len - 1] = '\0';
		}

		if (*line == '\0' || *line == '#') {
			/* Skip empty lines and comments */
			continue;
		} else if (*line == '\t') {
			const char *name = line + 1;

			if (!valid_name(name)) {
				err(EXIT_FAILURE,
				    "Invalid link name: \"%s\"", name);
			} else if (itr->mi_target == NULL) {
				err(EXIT_FAILURE,
				    "Link without preceding target");
			} else {
				*namep = name;
				*targetp = itr->mi_target;
				return (true);
			}
		} else {
			if (!valid_target(line)) {
				errx(EXIT_FAILURE,
				    "Invalid link target \"%s\"", line);
			} else {
				free(itr->mi_target);
				itr->mi_target = strdup(line);
				continue;
			}
		}
	}

	return (false);
}

static void
do_links(const char *dest_dir, const char *input_file, bool dry_run)
{
	int dfd = open(dest_dir, O_DIRECTORY | O_RDONLY, 0);
	if (dfd < 0) {
		err(EXIT_FAILURE, "Could not open destination dir %s",
		    dest_dir);
	}

	FILE *ifp = fopen(input_file, "r");
	if (ifp == NULL) {
		err(EXIT_FAILURE, "Could not open input file %s", input_file);
	}

	manlink_iter_t iter;
	link_iter_init(ifp, &iter);

	const char *name, *target;
	while (link_iter_next(&iter, &name, &target)) {
		struct stat st;

		const int res = fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW);
		if (res == 0) {
			if (S_ISLNK(st.st_mode)) {
				char buf[MAXPATHLEN];

				buf[0] = '\0';
				ssize_t len = readlinkat(dfd, name, buf,
				    sizeof (buf));
				if (len > 0) {
					/* NUL terminate */
					buf[MIN(len, sizeof (buf) - 1)] = '\0';
				}

				if (strncmp(buf, target, sizeof (buf)) == 0) {
					continue;
				}
			}
			(void) printf("unlink %s/%s\n", dest_dir, name);
			if (!dry_run && unlinkat(dfd, name, 0) != 0) {
				err(EXIT_FAILURE,
				    "Could not unlink conflicting file %s/%s",
				    dest_dir, name);
			}
		} else if (errno != ENOENT) {
			err(EXIT_FAILURE, "stat() failure for link %s/%s",
			    dest_dir, name);
		}

		(void) printf("link %s/%s -> %s\n", dest_dir, name, target);
		if (!dry_run && symlinkat(target, dfd, name) != 0) {
			err(EXIT_FAILURE, "failure to create link at %s/%s",
			    dest_dir, name);
		}
	}
	link_iter_fini(&iter);
}

int
main(int argc, char *argv[])
{
	char *dest_dir = NULL;
	bool do_dry_run = false;
	progname = basename(argv[0]);

	int c;
	while ((c = getopt(argc, argv, "nd:")) != -1) {
		switch (c) {
		case 'd':
			dest_dir = optarg;
			break;
		case 'n':
			do_dry_run = true;
			break;
		case '?':
			usage("unknown option: -%c", optopt);
			exit(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		usage("input file(s)");
		exit(EXIT_FAILURE);
	}
	for (uint_t i = 0; i < (uint_t)argc; i++) {
		do_links(dest_dir, argv[i], do_dry_run);
	}

	return (EXIT_SUCCESS);
}
