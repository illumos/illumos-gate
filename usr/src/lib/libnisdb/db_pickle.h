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
 *	db_pickle.h
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef PICKLE_H
#define	PICKLE_H

#include "nisdb_rw.h"

/*
 * 'pickle' is the package for storing data structures into files.
 * 'pickle_file' is the base class.  Classes that inherit this base
 * class need to instantiate the virtual function 'dump'.
 */

enum pickle_mode {
	PICKLE_READ, PICKLE_WRITE, PICKLE_APPEND
};

typedef enum pickle_mode pickle_mode;

typedef void* pptr;		/* pickle pointer */

class pickle_file {
    protected:
	FILE *file;		/* file handle */
	pickle_mode mode;
	XDR xdr;
	char *filename;
	STRUCTRWLOCK(pickle);
    public:

	/* Constructor.  Creates pickle_file with given name and mode. */
	pickle_file(char *, pickle_mode);

	~pickle_file()  { delete filename; DESTROYRW(pickle); }

	/*
	 * Opens pickle_file with mode specified with constructor.
	 * Returns TRUE if open was successful; FALSE otherwise.
	 */
	bool_t open();

	/* Closes pickle_file.  Returns 0 if successful; -1 otherwise. */
	int close();

	/*
	 * dump or load data structure to/from 'filename' using function 'f'.
	 * dump/load is determined by 'mode' with which pickle_file was created.
	 * Returns 0 if successful; 1 if file cannot be opened in mode
	 * specified; -1 if transfer failed do to encoding/decoding errors.
	 */
	int transfer(pptr, bool_t (*f) (XDR*, pptr));

	/* Exclusive access */
	int acqexcl(void) {
		return (WLOCK(pickle));
	}

	int relexcl(void) {
		return (WULOCK(pickle));
	}
};
#endif /* PICKLE_H */
