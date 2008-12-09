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

/*
 * The sharable object /usr/lib/libldstab.so.1 is a link-editor
 * support library that was used to compress the stab table by
 * eliminating duplicate include file entries. The link-editor would
 * load it by default, unless the user explicitly supplied a support
 * library via the ld -S option. We publically documented this in the
 * Solaris Linkers and Libraries Manual (LLM), stating that users
 * who supply their own support libraries should also explicitly
 * add '-S libldstab.so.1' to their link commands in order to retain
 * the functionality it supplied.
 *
 * The original libldstab.so worked by forking a child process running
 * a program named sbfocus. sbfocus was delivered with the Sun
 * compilers, and was expected to be found in the users PATH.
 * As the compilers and the OSnet are delivered on disjoint schedules,
 * this division never worked very well. Modern versions of the
 * compilers supply their own support libraries directly as needed, and
 * no longer deliver a program named sbfocus. The link-editor no longer
 * loads libldstab.so.1 by default, and it is no longer documented in the LLM.
 *
 * The current version of /usr/lib/libldstab.so.1 is a stub that exists
 * solely for backward compatibility. In the case where an existing
 *  Makefile  still follows the old advice in the LLM and supplies
 * '-S libldstab.so.1' to the link-editor command line, this object
 * will be loaded. It specifies a support library version of
 * LD_SUP_VNONE, which indicates to the link-editor that it is
 * not needed and should be quietly unloaded. In this way, we
 * preserve the old documented interface without undue overhead.
 */


#include <stdio.h>
#include <link.h>
#include "libld.h"


/* ARGSUSED */
uint_t
#if	defined(_ELF64)
ld_version64(uint_t version)
#else
ld_version(uint_t version)
#endif
{
	/* LD_SUP_VNONE tells libld.so to ignore this support library */
	return (LD_SUP_VNONE);
}
