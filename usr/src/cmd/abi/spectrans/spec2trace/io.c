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
 * Copyright (c) 1997-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/param.h>
#include "parser.h"
#include "trace.h"
#include "db.h"
#include "util.h"
#include "errlog.h"

/* Types and Globals */
FILE	*Bodyfp = NULL;
FILE	*Headfp = NULL;
FILE	*Mapfp = NULL;

static char headfile_name[MAXLINE]; /* Saved for later. */
static char mapfile_name[MAXLINE]; /* Saved for later. */

/* File globals. */
static int alt_code_file(void);
static void abort_code_file(void);

/*
 * open_code_file - open the code file and the invisible temp file.
 */
int
open_code_file(void)
{
	char	*dir = db_get_target_directory();
	char	*body_file_name;
	int	rc = YES;

	errlog(BEGIN, "open_code_file() {");

	/* Open the Head file, which gets the headers, includes and */
	/* definitions, and eventually gets the body concatenated to it. */
	(void) snprintf(headfile_name, sizeof (headfile_name), "%s.c",
		db_get_output_file());
	if ((Headfp = fopen(headfile_name, "w")) == NULL) {
		errlog(FATAL, "%s: %s", headfile_name, strerror(errno));
	}

	(void) snprintf(mapfile_name, sizeof (mapfile_name), "%s-vers",
	    db_get_output_file());

	if ((Mapfp = fopen(mapfile_name, "w")) == NULL) {
		errlog(FATAL, "%s: %s", mapfile_name, strerror(errno));
	}
	(void) fputs("SUNWabi_1.1 {\n    global:\n", Mapfp);

	/* Now the Body file, which is an ephemeral temp-file. */
	if ((body_file_name = tempnam(dir, NULL)) == NULL) {
		errlog(FATAL, "out of memory creating a temp-file name");
	}

	if ((Bodyfp = fopen(body_file_name, "w+")) == NULL) {
		errlog(FATAL, "%s: %s", body_file_name, strerror(errno));
	}

	if (unlink(body_file_name) != 0) {
		errlog(FATAL, "unlink %s: %s", body_file_name, strerror(errno));
	}

	(void) free(body_file_name);
	errlog(END, "}");
	return (rc);
}

/*
 * abort_code_file -- close and discard files.
 * this function is also called from alt_code_file, so
 * it is not cool to unlink the code file or the mapfile
 */
static void
abort_code_file(void)
{
	errlog(BEGIN, "abort_code_file() {");
	(void) fclose(Bodyfp);
	(void) fclose(Headfp);
	if (unlink(headfile_name) != 0) {
		errlog(FATAL, "unlink %s: %s", headfile_name, strerror(errno));
	}
	errlog(END, "}");
}

int
alt_code_file(void)
{
	char hfn[MAXLINE];
	FILE *hfp;

	abort_code_file();
	(void) snprintf(hfn, sizeof (hfn), "%s.c", db_get_output_file());
	if ((hfp = fopen(hfn, "w")) == NULL) {
		errlog(FATAL, "%s: %s", headfile_name, strerror(errno));
	}

	(void) fputs("static int __abi_place_holder;\n", hfp);
	(void) fclose(hfp);

	return (YES);
}

/*
 * commit_code_file -- close and commit files that have advanced
 *	beyond byte position 0.
 */
int
commit_code_file(void)
{
	char	copy_buffer[BUFSIZ*8];
	size_t	n;

	errlog(BEGIN, "commit_code_file() {");
	/*
	 * We unconditionally want a .pf and a -vers file
	 */
	(void) fputs("    local:\n\t*;\n};\n", Mapfp);
	if (fclose(Mapfp) != 0) {
		errlog(FATAL, "fclose %s: %s", mapfile_name, strerror(errno));
	}
	if (ftell(Bodyfp) == 0) {
		/*
		 * special case, redo C file with place holder
		 * so that makefiles won't break...
		 */
		errlog(END, "}");
		return (alt_code_file());
	} else {
		/* Concatenate body file to head file, close both. */
		rewind(Bodyfp);
		while ((n = fread(copy_buffer, 1,
		    sizeof (copy_buffer), Bodyfp)) != 0) {
			(void) fwrite(copy_buffer, 1, n, Headfp);
		}
		(void) fclose(Bodyfp);
		if (fclose(Headfp) != 0) {
			errlog(FATAL, "fclose <temp file>: %s",
			    strerror(errno));
		}
	}

	errlog(END, "}");
	return (YES);
}
