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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "libelf.h"
#include "decl.h"
#include "msg.h"


/*
 * Raw file input/output
 * Read pieces of input files.
 */


char *
_elf_read(int fd, off_t off, size_t fsz)
{
	char		*p;

	if (fsz == 0)
		return (0);

	if (fd == -1) {
		_elf_seterr(EREQ_NOFD, 0);
		return (0);
	}

	if (lseek(fd, off, 0) != off) {
		_elf_seterr(EIO_SEEK, errno);
		return (0);
	}
	if ((p = (char *)malloc(fsz)) == 0) {
		_elf_seterr(EMEM_DATA, errno);
		return (0);
	}

	if (read(fd, p, fsz) != fsz) {
		_elf_seterr(EIO_READ, errno);
		free(p);
		return (0);
	}
	return (p);
}
