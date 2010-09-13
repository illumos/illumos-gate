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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * kmdb version of the File Descriptor I/O Backend
 *
 * We don't have any files to open, so this is just a stub.
 */

#include <mdb/mdb_err.h>
#include <mdb/mdb_io.h>
#include <mdb/mdb.h>

#include <unistd.h>
#include <fcntl.h>

/*ARGSUSED*/
mdb_io_t *
mdb_fdio_create_path(const char *path[], const char *fname,
    int flags, mode_t mode)
{
	(void) set_errno(ENOENT);
	return (NULL);
}
