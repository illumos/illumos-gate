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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "synonyms.h"
#include <sys/types.h>
#include <sys/types32.h>
#include <rpc/types.h>
#include <sys/vfs.h>
#include <strings.h>
#include <sharefs/share.h>
#include <sys/syscall.h>

#include "libc.h"

#define	SMAX(i, j)		\
	if ((j) > (i)) {	\
		(i) = (j);	\
	}

int
_sharefs(enum sharefs_sys_op opcode, struct share *sh)
{
	uint32_t		i, j;

	/*
	 * We need to know the total size of the share
	 * and also the largest element size. This is to
	 * get enough buffer space to transfer from
	 * userland to kernel.
	 */
	i = (sh->sh_path ? strlen(sh->sh_path) : 0);
	sh->sh_size = i;

	j = (sh->sh_res ? strlen(sh->sh_res) : 0);
	sh->sh_size += j;
	SMAX(i, j);

	j = (sh->sh_fstype ? strlen(sh->sh_fstype) : 0);
	sh->sh_size += j;
	SMAX(i, j);

	j = (sh->sh_opts ? strlen(sh->sh_opts) : 0);
	sh->sh_size += j;
	SMAX(i, j);

	j = (sh->sh_descr ? strlen(sh->sh_descr) : 0);
	sh->sh_size += j;
	SMAX(i, j);

	return (syscall(SYS_sharefs, opcode, sh, i));
}
