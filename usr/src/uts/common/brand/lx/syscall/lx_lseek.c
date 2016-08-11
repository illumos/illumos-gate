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
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/errno.h>
#include <sys/debug.h>


#if defined(_SYSCALL32_IMPL) || defined(_ILP32)

/* from uts/common/syscalls/lseek.c */
extern offset_t llseek32(int32_t, uint32_t, uint32_t, int);
extern off32_t lseek32(int32_t, off32_t, int32_t);

long
lx_llseek(int fd, uint32_t off_high, uint32_t off_low, void *out, int whence)
{
	offset_t res;

	ASSERT(get_udatamodel() == DATAMODEL_ILP32);
	res = llseek32(fd, off_low, off_high, whence);
	if (ttolwp(curthread)->lwp_errno == 0) {
		if (copyout(&res, out, sizeof (offset_t)) != 0) {
			return (set_errno(EFAULT));
		}
	}
	return (ttolwp(curthread)->lwp_errno);
}


long
lx_lseek32(int fd, off32_t offset, int whence)
{
	offset_t res;

	/*
	 * When returning EOVERFLOW for an offset which is outside the bounds
	 * of an off32_t, Linux will still perform the actual seek before
	 * yielding EOVERFLOW.
	 *
	 * In order to emulate that behavior, an llseek bound to the 64-bit
	 * boundary is used.  The overflow can then be reported after the
	 * successful seek.
	 */
	ASSERT(get_udatamodel() == DATAMODEL_ILP32);
	res = llseek32(fd, 0, (uint32_t)offset, whence);
	if (ttolwp(curthread)->lwp_errno == 0 && res > MAXOFF32_T) {
		return (set_errno(EOVERFLOW));
	}
	return (res);

}
#endif /* defined(_SYSCALL32_IMPL) || defined(_ILP32) */

#if defined(_LP64)

/* from uts/common/syscalls/lseek.c */
extern off_t lseek64(int, off_t, int);

long
lx_lseek64(int fd, off_t offset, int whence)
{
	ASSERT(get_udatamodel() == DATAMODEL_LP64);
	return (lseek64(fd, offset, whence));
}

#endif /* defined(_LP64) */
