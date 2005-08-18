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
 *	Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "sbfocus_enter.h"

/*
 * sbfocus_symbol() will write one symbol to a pipe that has the program
 * "sbfocus" at the receiving end. If the program has not been started yet,
 * it is started, and the pipe established. "sbfocus" is started with the
 * function arguments "type" and "name" as its arguments, in that order.
 *
 * sbfocus_symbol() should be called with four arguments:
 *	data	Pointer to a Sbld struct that the caller has allocated in
 *		permanent storage. It must be the same struct for all related
 *		calls to sbfocus_symbol().
 *	name	This is the string name of the library/executable being built.
 *	type	A string, should be one of:
 *                      "-a": Building a archived library
 *			"-s": Building a shared library
 *			"-x": Building an executable
 *			"-r": Concatenating object files
 *	symbol	The string that should be written to "sbfocus". If this
 *		argument is NULL "sbfocus" is started, but no symbol is
 *		written to it.
 */

void
sbfocus_symbol(Sbld data, char *name, char *type, char *symbol)
{
	int	fd[2];

	if (data->failed) {
		return;
	}

	if (data->fd == NULL) {
		data->failed = 0;
		(void) pipe(fd);

		switch (vfork()) {
		case -1:
			(void) fprintf(stderr,
			"vfork() failed. SourceBrowser data will be lost.\n");
			data->failed = 1;
			(void) close(fd[0]);
			(void) close(fd[1]);
			return;

		/*
		 * Child process
		 */
		case 0:
			(void) dup2(fd[0], fileno(stdin));
			(void) close(fd[1]);
			(void) execlp("sbfocus", "sbfocus", type, name, 0);
			data->failed = 1;
			_exit(1);

		/*
		 * Parent process
		 */
		default:
			if (data->failed) {
				(void) fprintf(stderr,
				"`sbfocus' would not start."
				" SourceBrowser data will be lost.\n");
				return;
			}
			(void) close(fd[0]);
			data->fd = fdopen(fd[1], "w");
			break;
		}
	}
	if (symbol != NULL) {
		(void) fputs(symbol, data->fd);
		(void) putc('\n', data->fd);
	}
}

/*
 * sbfocus_close() will close the pipe to "sbfocus", causing it to terminate.
 *
 * sbfocus_close() should be called with one argument, a pointer to the data
 * block used with sbfocus_symbol().
 */
void
sbfocus_close(Sbld data)
{
	if ((data->fd != NULL) && (data->failed == 0)) {
		(void) fclose(data->fd);
	}
	data->fd = NULL;
	data->failed = 0;
}
