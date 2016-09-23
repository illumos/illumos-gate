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

#include <sys/fcntl.h>
#include <sys/lx_misc.h>

/*
 * Based on illumos posix_fadvise which does nothing. The only difference is
 * that on Linux an fd refering to a pipe or FIFO returns EINVAL. The Linux
 * POSIX_FADV_* values are the same as the illumos values. See how the 32-bit
 * glibc calls fadvise64; the offeset is a 64-bit value, but the length is not.
 * fadvise64_64 passes both the offset and length as 64-bit values. The 64-bit
 * fadvise64 caller always passes 64-bit values for the offset and length.
 */

/*
 * This is the fadvise64 function used by 64-bit callers, and by 32-bit callers
 * after they have adjusted their arguments.
 */
/* ARGSUSED */
int
lx_fadvise64(int fd, off64_t offset, off64_t len, int advice)
{
	file_t *fp;
	boolean_t is_fifo;

	switch (advice) {
	case POSIX_FADV_NORMAL:
	case POSIX_FADV_RANDOM:
	case POSIX_FADV_SEQUENTIAL:
	case POSIX_FADV_WILLNEED:
	case POSIX_FADV_DONTNEED:
	case POSIX_FADV_NOREUSE:
		break;
	default:
		return (set_errno(EINVAL));
	}

	if (len < 0)
		return (set_errno(EINVAL));

	if ((fp = getf(fd)) == NULL)
		return (set_errno(EBADF));
	is_fifo = (fp->f_vnode->v_type == VFIFO);
	releasef(fd);

	if (is_fifo)
		return (set_errno(ESPIPE));

	return (0);
}

/*
 * This is the fadvise64 function used by 32-bit callers. Linux passes the
 * 64-bit offset by concatenating consecutive arguments. We must perform the
 * same conversion here.
 */
long
lx_fadvise64_32(int fd, uint32_t off_lo, uint32_t off_hi, int32_t len,
    int advice)
{
	off64_t offset;

	offset = off_hi;
	offset = offset << 32;
	offset |= off_lo;

	return (lx_fadvise64(fd, offset, (off64_t)len, advice));
}

/*
 * This function is only used by 32-bit callers. Linux passes the 64-bit offset
 * and length by concatenating consecutive arguments. We must perform the same
 * conversion here.
 */
long
lx_fadvise64_64(int fd, uint32_t off_lo, uint32_t off_hi, uint32_t len_lo,
    uint32_t len_hi, int advice)
{
	off64_t offset;
	off64_t len;

	offset = off_hi;
	offset = offset << 32;
	offset |= off_lo;
	len = len_hi;
	len = len << 32;
	len |= len_lo;

	return (lx_fadvise64(fd, offset, len, advice));
}
