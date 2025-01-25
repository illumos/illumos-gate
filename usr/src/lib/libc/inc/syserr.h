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

#ifndef _SYSERR_H
#define	_SYSERR_H

/*
 * Definitions for library-private variables relating to error names and
 * descriptions.
 */

/*
 * The maximum system error number; the size of the _sys_nerrs and
 * _sys_err_names arrays.
 */
extern int _sys_num_nerr;

/*
 * _sys_nerrs and _sys_nindex are used together. _sys_nerrs is one long string
 * that is a concatenation of all of the error descriptions, separated by '\0',
 * and _sys_index is an array of indices into that. A pointer to the
 * description for a particular error can therefore be obtained (after bounds
 * checks) via:
 *     &_sys_nerrs[_sys_nindex[<errnum>]]
 */
extern const char _sys_nerrs[];
extern const int _sys_nindex[];
/*
 * An array mapping an errno to its constant, e.g. ENOENT -> "ENOENT"
 */
extern const char *_sys_err_names[];

#endif /* _SYSERR_H */
