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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <dirent.h>
#include <locale.h>
#include <libintl.h>
#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/file.h>

#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/libbsm.h>

#include "praudit.h"
#include "toktable.h"

static int	process_options(int *argc, char *argv[], char *names[]);

static int	input_mode;	/* audit file source */
static int	format = PRF_DEFAULTM;	/* output mode */

static char	SEPARATOR[SEP_SIZE] = ",";	/* field separator */


/*
 * ----------------------------------------------------------------------
 * praudit  -  display contents of audit trail file
 *
 * main() - main control
 * input:    - command line input:   praudit -r|s -l -x -ddelim. -c filename(s)
 * ----------------------------------------------------------------------
 */

int
main(int argc, char **argv)
{
	int	i = 0, retstat;
	char	*names[MAXFILENAMES];

	/* Internationalization */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	/*
	 * get audit file names
	 */
	if ((retstat = process_options(&argc, argv, names)) == 0) {
		if (format & PRF_XMLM)
			print_audit_xml_prolog();
		do {
			retstat = 0;
			/*
			 * process each audit file
			 */
			if (input_mode == FILEMODE) {
				if (freopen(names[i], "r", stdin) == NULL) {
					(void) fprintf(stderr,
					    gettext("praudit: Can't assign %s "
					    "to stdin.\n"), names[i]);
					exit(1);
				}
			}

			/*
			 * Call the library routine to format the
			 * audit data from stdin and print to stdout
			 */
			retstat = print_audit(format, SEPARATOR);

		} while ((++i < argc) && retstat >= 0);
	}
	if ((retstat == 0) && (format & PRF_XMLM))
		print_audit_xml_ending();

	if (retstat == -2) {
		(void) printf(gettext("\nusage: praudit [-r/-s] [-l] [-x] "
		    "[-ddel] [-c] filename...\n"));
		exit(1);
	} else if (retstat < 0) {
		exit(1);
	}
	return (0);
}


/*
 * -------------------------------------------------------------------
 * process_options() - get command line flags and file names
 * input:    - praudit [-r]/[-s] [-l] [-x] [-ddel] [-c] {audit file names}
 * output:   - {audit file names}
 * globals set:	format:		RAWM / SHORTM / XML / ONELINE or DEFAULTM
 *			SEPARATOR:  default, ",", set here if
 *				user specified
 * NOTE: no changes required here for new audit record format
 * -------------------------------------------------------------------
 */
int
process_options(int *argc, char **argv, char **names)
{
	int	c, returnstat = 0;

	/*
	 * check for flags
	 */

	while ((c = getopt(*argc, argv, "crslxd:")) != -1) {
		switch (c) {
		case 'c':
			format |= PRF_NOCACHE;	/* turn off cache */
			break;
		case 'r':
			if (format & PRF_SHORTM)
				returnstat = -2;
			else
				format |= PRF_RAWM;
			break;
		case 's':
			if (format & PRF_RAWM)
				returnstat = -2;
			else
				format |= PRF_SHORTM;
			break;
		case 'l':
			format |= PRF_ONELINE;
			break;
		case 'x':
			format |= PRF_XMLM;
			break;
		case 'd':
			if (strlen(optarg) < sizeof (SEPARATOR))
				(void) strlcpy(SEPARATOR, optarg,
				    sizeof (SEPARATOR));
			else {
				(void) fprintf(stderr,
				    gettext("praudit: Delimiter too "
				    "long.  Using default.\n"));
			}
			break;
		default:
			returnstat = -2;
			break;
		}
	}

	argv = &argv[optind - 1];
	*argc -= optind;

	if (*argc > MAXFILENAMES) {
		(void) fprintf(stderr, gettext("praudit: Too many file "
		    "names.\n"));
		return (-1);
	}
	if (*argc > 0) {
		int count = *argc;

		input_mode = FILEMODE;
		/*
		 * copy file names from command line
		 */
		do {
			*names++ = *++argv;
		} while (--count > 0);
	} else
		input_mode = PIPEMODE;

	return (returnstat);
}
