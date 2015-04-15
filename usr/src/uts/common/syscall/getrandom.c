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
 * Copyright (c) 2015, Joyent, Inc.
 */

/*
 * getrandom system call implementation
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/random.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>

#include <sys/random.h>

/*
 * Impose a maximum upper bound on the number of bytes that we'll read in one
 * go, ala a read of /dev/random. For /dev/urandom, we clamp it based on our
 * return value, because the system call returns an int, we can't handle more
 * than INT_MAX.
 */
#define	MAXRANDBYTES	1024
#define	MAXURANDBYTES	INT_MAX

int
getrandom(void *bufp, size_t buflen, int flags)
{
	int out = 0;
	uint8_t rbytes[128];
	uint8_t *buf = bufp;

	if (flags & ~(GRND_NONBLOCK | GRND_RANDOM))
		return (set_errno(EINVAL));

	if ((flags & GRND_RANDOM) && buflen > MAXRANDBYTES) {
		buflen = MAXRANDBYTES;
	} else if (buflen > MAXURANDBYTES) {
		buflen = MAXURANDBYTES;
	}

	while (out < buflen) {
		int err;
		size_t len = MIN(sizeof (rbytes), buflen - out);

		if (flags & GRND_RANDOM) {
			if (flags & GRND_NONBLOCK)
				err = random_get_bytes(rbytes, len);
			else
				err = random_get_blocking_bytes(rbytes, len);
		} else {
			err = random_get_pseudo_bytes(rbytes, len);
		}

		if (err == 0) {
			if (ddi_copyout(rbytes, buf + out, len, 0) != 0)
				return (set_errno(EFAULT));
			out += len;
		} else if (err == EAGAIN && out > 0) {
			break;
		} else {
			return (set_errno(err));
		}
	}

	return (out);
}
