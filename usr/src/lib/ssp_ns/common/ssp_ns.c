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
 * Copyright 2020 Oxide Computer Company
 */

#include <sys/ccompile.h>

/*
 * To impement gcc's stack protector library, the compiler emits a function call
 * to a symbol which can be called absolutely. As a result, to make that happen,
 * we mimic what gcc does with libssp and create an archive file that can be
 * used in the specs file to pull this in directly. This is a bit of a pain, but
 * that's the best we can do given the architecture that we have.
 *
 * Warning: This is a static archive. Nothing beyond the call for
 * __stack_chk_fail_local and calls to committed interfaces should be here. As
 * this implementation will be linked into programs, one should exercise care to
 * make sure we don't expose anything else here.
 */

extern void __stack_chk_fail(void);

void __HIDDEN
__stack_chk_fail_local(void)
{
	__stack_chk_fail();
}
