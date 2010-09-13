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
/* BEGIN PROLOGUE */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * kmdb_terminfo_skel.c is the skeleton used to generate
 * kmdb_terminfo.c, which contains the kmdb-specific version
 * of terminfo.
 */

#include <strings.h>
#include <unistd.h>
#include <curses.h>

#include <mdb/mdb_io.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb.h>

typedef enum {
	TIO_ATTR_REQSTR,
	TIO_ATTR_STR,
	TIO_ATTR_BOOL,
	TIO_ATTR_INT
} termio_attr_type_t;

typedef struct {
	const char *ta_name;
	termio_attr_type_t ta_type;
	const void *ta_data;
} termio_attr_t;

typedef struct {
	const char *td_name;
	const termio_attr_t *td_data;
} termio_desc_t;

/* END PROLOGUE */

/*
 * tigen will insert the following definitions here:
 *
 *	<term>_attrs  (one per terminal type passed to tigen)
 *	termio_db
 */

/* BEGIN EPILOGUE */

static const termio_desc_t *tdp;

/*ARGSUSED*/
int
setupterm(char *name, int fd, int *err)
{
	for (tdp = termio_db; tdp->td_name != NULL; tdp++) {
		if (strcmp(tdp->td_name, name) == 0)
			return (OK);
	}

	*err = 0;
	return (ERR);
}

int
restartterm(char *name, int fd, int *err)
{
	const termio_desc_t *otdp = tdp;
	int status;

	if ((status = setupterm(name, fd, err)) != OK)
		tdp = otdp; /* restore old terminal settings */

	return (status);
}

const char *
tigetstr(const char *name)
{
	const termio_attr_t *tap;

	for (tap = tdp->td_data; tap->ta_name != NULL; tap++) {
		if (strcmp(tap->ta_name, name) == 0) {
			if (tap->ta_type == TIO_ATTR_REQSTR ||
			    tap->ta_type == TIO_ATTR_STR)
				return (tap->ta_data);
			else
				return ((char *)-1);
		}
	}

	return (NULL);
}

int
tigetflag(const char *name)
{
	const termio_attr_t *tap;

	for (tap = tdp->td_data; tap->ta_name != NULL; tap++) {
		if (strcmp(tap->ta_name, name) == 0) {
			if (tap->ta_type == TIO_ATTR_BOOL)
				return ((uintptr_t)tap->ta_data);
			else
				return (-1);
		}
	}

	return (0);
}

int
tigetnum(const char *name)
{
	const termio_attr_t *tap;

	for (tap = tdp->td_data; tap->ta_name != NULL; tap++) {
		if (strcmp(tap->ta_name, name) == 0) {
			if (tap->ta_type == TIO_ATTR_INT)
				return ((uintptr_t)tap->ta_data);
			else
				return (-2);
		}
	}

	return (-1);
}

/* END EPILOGUE */
