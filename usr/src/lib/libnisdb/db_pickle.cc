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
 *	db_pickle.cc
 *
 *	Copyright (c) 1988-2000 by Sun Microsystems, Inc.
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* #include <sys/types.h> */
#include <stdio.h>
/* #include <syslog.h> */
#include <string.h>
#include <unistd.h>
#include "db_headers.h"
#include "db_pickle.h"
#include "nisdb_mt.h"

/* Constructor.  Creates pickle_file with given name and mode. */
pickle_file::pickle_file(char* f, pickle_mode m)
{
	if ((filename = strdup(f)) == NULL) {
		FATAL("pickle_file::pickle_file: cannot allocate space",
			DB_MEMORY_LIMIT);
	}

	INITRW(pickle);

	mode = m;
}

/*
 * Opens pickle_file with mode specified with constructor.
 * Returns TRUE if open was successful; FALSE otherwise.
 */
bool_t
pickle_file::open()
{
	WRITELOCK(this, FALSE, "w pickle_file::open");
	if (mode == PICKLE_READ) {
		file = fopen(filename, "r");
		if (file)
			xdrstdio_create(&(xdr), file, XDR_DECODE);
	} else if (mode == PICKLE_WRITE) {
		file = fopen(filename, "w");
		if (file) {
			setvbuf(file, NULL, _IOFBF, 81920);
			xdrstdio_create(&(xdr), file, XDR_ENCODE);
		}
	} else if (mode == PICKLE_APPEND) {
		file = fopen(filename, "a");
		if (file)
			xdrstdio_create(&(xdr), file, XDR_ENCODE);
	}
	if (file == NULL) {
		WRITEUNLOCK(this, FALSE, "wu pickle_file::open");
		return (FALSE);
	}
	WRITEUNLOCK(this, FALSE, "wu pickle_file::open");
	return (TRUE);
}


/* Closes pickle_file.  Returns 0 if successful; -1 otherwise. */
int
pickle_file::close()
{
	int	ret;

	WRITELOCK(this, EOF, "w pickle_file::close");
	xdr_destroy(&(xdr));
	ret = fclose(file);
	WRITEUNLOCK(this, EOF, "wu pickle_file::close");
	return (ret);
}


/*
 * dump or load data structure to/from 'filename' using function 'f'.
 * dump or load is determined by 'mode' with which pickle_file was created.
 * Returns 0 if successful; 1 if file cannot be opened in mode
 * specified; -1 if transfer failed do to encoding/decoding errors.
*/
int
pickle_file::transfer(pptr p, bool_t (*f) (XDR*, pptr))
{
	WRITELOCK(this, -1, "w pickle_file::transfer");
	if (open()) {
		if ((f)(&xdr, p) == FALSE) {
			close();
			WRITEUNLOCK(this, -1, "wu pickle_file::transfer");
			return (-1);
		} else {
			fsync(fileno(file));
			WRITEUNLOCK(this, -1, "wu pickle_file::transfer");
			return (close());
		}
	}
	WRITEUNLOCK(this, -1, "wu pickle_file::transfer");
	return (1);
}
