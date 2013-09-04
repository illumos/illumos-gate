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
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2013 DEY Storage Systems, Inc.
 */

/*
 * POSIX localedef.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <stddef.h>
#include <unistd.h>
#include <limits.h>
#include <locale.h>
#include <dirent.h>
#include "localedef.h"
#include "parser.tab.h"

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

int verbose = 0;
int undefok = 0;
int warnok = 0;
static char *locname = NULL;
static char locpath[PATH_MAX];

const char *
category_name(void)
{
	switch (get_category()) {
	case T_CHARMAP:
		return ("CHARMAP");
	case T_WIDTH:
		return ("WIDTH");
	case T_COLLATE:
		return ("LC_COLLATE");
	case T_CTYPE:
		return ("LC_CTYPE");
	case T_MESSAGES:
		return ("LC_MESSAGES");
	case T_MONETARY:
		return ("LC_MONETARY");
	case T_NUMERIC:
		return ("LC_NUMERIC");
	case T_TIME:
		return ("LC_TIME");
	default:
		INTERR;
		return (NULL);
	}
}

static char *
category_file(void)
{
	(void) snprintf(locpath, sizeof (locpath), "%s/%s/LCL_DATA",
	    locname, category_name());
	return (locpath);
}

FILE *
open_category(void)
{
	FILE *file;

	if (verbose) {
		(void) printf(_("Writing category %s: "), category_name());
		(void) fflush(stdout);
	}

	/* make the parent directory */
	(void) mkdirp(dirname(category_file()), 0755);

	/*
	 * note that we have to regenerate the file name, as dirname
	 * clobbered it.
	 */
	file = fopen(category_file(), "w");
	if (file == NULL) {
		errf(strerror(errno));
		return (NULL);
	}
	return (file);
}

void
close_category(FILE *f)
{
	if (fchmod(fileno(f), 0644) < 0) {
		(void) fclose(f);
		(void) unlink(category_file());
		errf(strerror(errno));
	}
	if (fclose(f) < 0) {
		(void) unlink(category_file());
		errf(strerror(errno));
	}
	if (verbose) {
		(void) fprintf(stdout, _("done.\n"));
		(void) fflush(stdout);
	}
}

/*
 * This function is used when copying the category from another
 * locale.  Note that the copy is actually performed using a hard
 * link for efficiency.
 */
void
copy_category(char *src)
{
	char	srcpath[PATH_MAX];
	int	rv;

	(void) snprintf(srcpath, sizeof (srcpath), "%s/%s/LCL_DATA",
	    src, category_name());
	rv = access(srcpath, R_OK);
	if ((rv != 0) && (strchr(srcpath, '/') == NULL)) {
		/* Maybe we should try the system locale */
		(void) snprintf(srcpath, sizeof (srcpath),
		    "/usr/lib/locale/%s/%s/LCL_DATA", src, category_name());
		rv = access(srcpath, R_OK);
	}

	if (rv != 0) {
		errf(_("source locale data unavailable"), src);
		return;
	}

	if (verbose > 1) {
		(void) printf(_("Copying category %s from %s: "),
		    category_name(), src);
		(void) fflush(stdout);
	}

	/* make the parent directory */
	(void) mkdirp(dirname(category_file()), 0755);

	if (link(srcpath, category_file()) != 0) {
		errf(_("unable to copy locale data: %s"), strerror(errno));
		return;
	}
	if (verbose > 1) {
		(void) printf(_("done.\n"));
	}
}

int
putl_category(const char *s, FILE *f)
{
	if (s && fputs(s, f) == EOF) {
		(void) fclose(f);
		(void) unlink(category_file());
		errf(strerror(errno));
		return (EOF);
	}
	if (fputc('\n', f) == EOF) {
		(void) fclose(f);
		(void) unlink(category_file());
		errf(strerror(errno));
		return (EOF);
	}
	return (0);
}

int
wr_category(void *buf, size_t sz, FILE *f)
{
	if (!sz) {
		return (0);
	}
	if (fwrite(buf, sz, 1, f) < 1) {
		(void) fclose(f);
		(void) unlink(category_file());
		errf(strerror(errno));
		return (EOF);
	}
	return (0);
}

int yyparse(void);

static void
usage(void)
{
	(void) fprintf(stderr,
	    _("Usage: localedef [options] localename\n"));
	(void) fprintf(stderr, ("[options] are:\n"));
	(void) fprintf(stderr, ("  -c          : ignore warnings\n"));
	(void) fprintf(stderr, ("  -v          : verbose output\n"));
	(void) fprintf(stderr, ("  -U          : ignore undefined symbols\n"));
	(void) fprintf(stderr, ("  -f charmap  : use given charmap file\n"));
	(void) fprintf(stderr, ("  -u encoding : assume encoding\n"));
	(void) fprintf(stderr, ("  -w widths   : use screen widths file\n"));
	(void) fprintf(stderr, ("  -i locsrc   : source file for locale\n"));
	exit(4);
}

int
main(int argc, char **argv)
{
	int c;
	char *lfname = NULL;
	char *cfname = NULL;
	char *wfname = NULL;
	DIR *dir;

	init_charmap();
	init_collate();
	init_ctype();
	init_messages();
	init_monetary();
	init_numeric();
	init_time();

	yydebug = 0;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "w:i:cf:u:vU")) != -1) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'i':
			lfname = optarg;
			break;
		case 'u':
			set_wide_encoding(optarg);
			break;
		case 'f':
			cfname = optarg;
			break;
		case 'U':
			undefok++;
			break;
		case 'c':
			warnok++;
			break;
		case 'w':
			wfname = optarg;
			break;
		case '?':
			usage();
			break;
		}
	}

	if ((argc - 1) != (optind)) {
		usage();
	}
	locname = argv[argc - 1];
	if (verbose) {
		(void) printf(_("Processing locale %s.\n"), locname);
	}

	if (cfname) {
		if (verbose)
			(void) printf(_("Loading charmap %s.\n"), cfname);
		reset_scanner(cfname);
		(void) yyparse();
	}

	if (wfname) {
		if (verbose)
			(void) printf(_("Loading widths %s.\n"), wfname);
		reset_scanner(wfname);
		(void) yyparse();
	}

	if (verbose) {
		(void) printf(_("Loading POSIX portable characters.\n"));
	}
	add_charmap_posix();

	if (lfname) {
		reset_scanner(lfname);
	} else {
		reset_scanner(NULL);
	}

	/* make the directory for the locale if not already present */
	while ((dir = opendir(locname)) == NULL) {
		if ((errno != ENOENT) ||
		    (mkdir(locname, 0755) <  0)) {
			errf(strerror(errno));
		}
	}
	(void) closedir(dir);

	(void) mkdirp(dirname(category_file()), 0755);

	(void) yyparse();
	if (verbose) {
		(void) printf(_("All done.\n"));
	}
	return (warnings ? 1 : 0);
}
