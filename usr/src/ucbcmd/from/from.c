/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <pwd.h>
#include <sys/param.h>
#include <string.h>

static int match(char *, char *);

int
main(int argc, char **argv)
{
	char lbuf[BUFSIZ];
	char lbuf2[BUFSIZ];
	struct passwd *pp;
	int stashed = 0;
	char *name;
	char *sender = NULL;
	char mailbox[MAXPATHLEN];
	char *tmp_mailbox;
	extern char *optarg;
	extern int optind;
	extern int opterr;
	int c;
	int errflg = 0;

	opterr = 0;
	while ((c = getopt(argc, argv, "s:")) != EOF)
		switch (c) {
		case 's':
			sender = optarg;
			for (name = sender; *name; name++)
				if (isupper(*name))
					*name = tolower(*name);
			break;
		case '?':
			errflg++;
			break;
		}
	if (errflg) {
		(void) fprintf(stderr,
			    "Usage: from [-s sender] [user]\n");
		exit(1);
	}

	if (optind < argc) {
		(void) sprintf(mailbox, "/var/mail/%s", argv[optind]);
	} else {
		if (tmp_mailbox = getenv("MAIL")) {
			(void) strcpy(mailbox, tmp_mailbox);
		} else {
			name = getlogin();
			if (name == NULL || strlen(name) == 0) {
				pp = getpwuid(getuid());
				if (pp == NULL) {
					(void) fprintf(stderr,
					    "Who are you?\n");
					exit(1);
				}
				name = pp->pw_name;
			}
			(void) sprintf(mailbox, "/var/mail/%s", name);
		}
	}
	if (freopen(mailbox, "r", stdin) == NULL) {
		(void) fprintf(stderr, "Can't open %s\n", mailbox);
		exit(0);
	}
	while (fgets(lbuf, sizeof (lbuf), stdin) != NULL)
		if (lbuf[0] == '\n' && stashed) {
			stashed = 0;
			(void) printf("%s", lbuf2);
		} else if (strncmp(lbuf, "From ", 5) == 0 &&
		    (sender == NULL || match(&lbuf[4], sender))) {
			(void) strcpy(lbuf2, lbuf);
			stashed = 1;
		}
	if (stashed)
		(void) printf("%s", lbuf2);
	return (0);
}

static int
match(char *line, char *str)
{
	char ch;

	while (*line == ' ' || *line == '\t')
		++line;
	if (*line == '\n')
		return (0);
	while (*str && *line != ' ' && *line != '\t' && *line != '\n') {
		ch = isupper(*line) ? tolower(*line) : *line;
		if (ch != *str++)
			return (0);
		line++;
	}
	return (*str == '\0');
}
