/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2000 Dan Papasian.  All rights reserved.
 * Copyright 2023 OmniOS Community Edition (OmniOSce) Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/fcntl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <err.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	EXIT_USAGE	2

static void	usage(void) __NORETURN;
static bool	print_matches(char *, const char *const);

static bool	silent = false;
static bool	allpaths = false;

int
main(int argc, char **argv)
{
	char *p, *path;
	size_t pathlen;
	int opt, status;

	status = EXIT_SUCCESS;

	while ((opt = getopt(argc, argv, "as")) != -1) {
		switch (opt) {
		case 'a':
			allpaths = true;
			break;
		case 's':
			silent = true;
			break;
		default:
			usage();
			break;
		}
	}

	argv += optind;
	argc -= optind;

	if (argc == 0)
		exit(EXIT_SUCCESS);

	if ((p = getenv("PATH")) == NULL)
		errx(EXIT_FAILURE, "Could not find PATH in environment");

	pathlen = strlen(p);
	path = strdup(p);

	if (path == NULL)
		err(EXIT_FAILURE, "Failed to duplicate PATH");

	while (argc > 0) {
		memcpy(path, p, pathlen + 1);

		if (strlen(*argv) >= FILENAME_MAX) {
			status = EXIT_FAILURE;

			warnx("operand too long '%s'", *argv);
		} else if (!print_matches(path, *argv)) {
			status = EXIT_FAILURE;

			if (!silent) {
				(void) printf("no %s in", *argv);

				if (pathlen > 0) {
					char *q = path;
					const char *d;

					memcpy(q, p, pathlen + 1);

					while ((d = strsep(&q, ":")) != NULL) {
						(void) printf(" %s",
						    *d == '\0' ? "." : d);
					}
				}

				(void) printf("\n");
			}
		}

		argv++;
		argc--;
	}

	free(path);
	exit(status);
}

static void
usage(void)
{
	(void) fprintf(stderr, "usage: which [-as] program ...\n");
	exit(EXIT_USAGE);
}

static bool
is_there(const char *const candidate)
{
	struct stat fin;

	if (faccessat(AT_FDCWD, candidate, X_OK, AT_EACCESS) == 0 &&
	    stat(candidate, &fin) == 0 &&
	    S_ISREG(fin.st_mode)) {
		if (!silent)
			printf("%s\n", candidate);

		return (true);
	}

	return (false);
}

static bool
print_matches(char *path, const char *const filename)
{
	char candidate[PATH_MAX];
	const char *d;
	bool found = false;

	if (strchr(filename, '/') != NULL)
		return (is_there(filename));

	while ((d = strsep(&path, ":")) != NULL) {
		if (*d == '\0')
			d = ".";
		if (snprintf(candidate, sizeof (candidate), "%s/%s", d,
		    filename) >= (int)sizeof (candidate))
			continue;
		if (is_there(candidate)) {
			found = true;
			if (!allpaths)
				break;
		}
	}

	return (found);
}
