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
 * Copyright 1993 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved   */


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <stdlib.h>
#include <libintl.h>

#include "lp.h"
#include "class.h"
#include "printers.h"
#include "msgs.h"

char **
pick_opts(char * infile_opts, char ** new_opts)
{
	char * flasts = NULL;
	char * old_opt;
	char ** final_opts = NULL;
	int key_len;
	int keyfound = 0;
	char ** head;

	if (infile_opts == NULL || new_opts == NULL) {
	(void) printf("lpadmin error: Cannot process -o options");
		return (NULL);
	}

	head = new_opts;
	for (; *new_opts != NULL; new_opts++) {
		if (strlen(*new_opts) > (strcspn(*new_opts, "=") + 1)) {
			if ((addlist(&final_opts, *new_opts)) != 0) {
				fprintf(stderr,
				    gettext("lpadmin: System Error %d\n"),
				    errno);

				return (NULL);
			}
		}
	}
	/*
	 * For each currently set option, ie, those already in the file,
	 * compare to new list from lpadmin (new_opts).
	 */
	for (old_opt = strtok_r(infile_opts, LP_SEP, &flasts);
		old_opt != NULL; old_opt = strtok_r(NULL, LP_SEP, &flasts)) {

		keyfound = 0;

		for (new_opts = head; *new_opts != NULL; new_opts++) {

			key_len = strcspn(*new_opts, "=");
			/*
			 * if the keys match, and the the key from the
			 * lpadmin -o has a value, take the new value from
			 * lpadmin
			 */
			if ((strncmp(old_opt, *new_opts, key_len + 1)) == 0) {
				keyfound++;
			}
		}
		if (keyfound == 0) {
			if ((addlist(&final_opts, old_opt)) != 0) {
				fprintf(stderr,
				    gettext("lpadmin: System Error %d\n"),
				    errno);

				return (NULL);
			}
		}

	}

	return (final_opts);
}
