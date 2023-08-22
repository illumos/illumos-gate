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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 */

#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libelf.h>
#include <errno.h>
#include "decl.h"
#include "msg.h"

/*
 * File output
 *	These functions write output files.
 *	On SVR4 and newer systems use mmap(2).  On older systems (or on
 *	file systems that don't support mmap), use write(2).
 */


char *
_elf_outmap(int fd, size_t sz, unsigned int *pflag)
{
	char	*p;

	/*
	 * Note: Some NFS implementations do not provide from enlarging a file
	 * via ftruncate(), thus this may fail with ENOSUP.  In this case the
	 * fall through to the calloc() mechanism will occur.
	 */
	if ((!*pflag) && (ftruncate(fd, (off_t)sz) == 0) &&
	    (p = mmap((char *)0, sz, PROT_READ+PROT_WRITE,
	    MAP_SHARED, fd, (off_t)0)) != (char *)-1) {
		*pflag = 1;
		return (p);
	}

	*pflag = 0;

	/*
	 * If mmap fails, try calloc.  Some file systems don't mmap.  Note, we
	 * use calloc rather than malloc, as ld(1) assumes that the backing
	 * storage it is working with is zero filled.
	 */
	if ((p = (char *)calloc(1, sz)) == 0)
		_elf_seterr(EMEM_OUT, errno);
	return (p);
}


size_t
_elf_outsync(int fd, char *p, size_t sz, unsigned int flag)
{
	if (flag != 0) {
		int	rv, err;

		err = ENOTSUP; /* msync should only return 0 or -1 */
		rv = msync(p, sz, MS_ASYNC);
		if (rv == -1)
			err = errno;
		(void) munmap(p, sz);
		if (rv == 0)
			return (sz);
		_elf_seterr(EIO_SYNC, err);
		return (0);
	}
	if ((lseek(fd, 0L, SEEK_SET) == 0) &&
	    (write(fd, p, sz) == sz)) {
		(void) free(p);
		return (sz);
	}
	_elf_seterr(EIO_WRITE, errno);
	return (0);
}
