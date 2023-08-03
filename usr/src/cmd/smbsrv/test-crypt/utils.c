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
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

#include <stdio.h>
#include <strings.h>
#include <sys/cmn_err.h>
#include <sys/varargs.h>

#include "utils.h"

void
hexdump(const uchar_t *buf, int len)
{
	int idx;
	char ascii[24];
	char *pa = ascii;

	bzero(ascii, sizeof (ascii));

	idx = 0;
	while (len--) {
		if ((idx & 15) == 0) {
			printf("%04X: ", idx);
			pa = ascii;
		}
		if (*buf > ' ' && *buf <= '~')
			*pa++ = *buf;
		else
			*pa++ = '.';
		printf("%02x ", *buf++);

		idx++;
		if ((idx & 3) == 0) {
			*pa++ = ' ';
			(void) putchar(' ');
		}
		if ((idx & 15) == 0) {
			*pa = '\0';
			printf("%s\n", ascii);
		}
	}

	if ((idx & 15) != 0) {
		*pa = '\0';
		/* column align the last ascii row */
		while ((idx & 15) != 0) {
			if ((idx & 3) == 0)
				(void) putchar(' ');
			printf("   ");
			idx++;
		}
		printf("%s\n", ascii);
	}
}

/*
 * Provide a real function (one that prints something) to replace
 * the stub in libfakekernel.  This prints cmn_err() messages.
 */
void
fakekernel_putlog(char *msg, size_t len, int flags)
{

	(void) fwrite(msg, 1, len, stdout);
	(void) fflush(stdout);
}

/*
 * Build a UIO for the input or output buffer
 * Arbitrarily splits into 2 segs for testing uio.
 */
void
make_uio(void *buf, size_t buflen, uio_t *uio, iovec_t *iov, int iovmax)
{
	size_t maxseg = 512;
	size_t tlen;
	int i;

	bzero(uio, sizeof (*uio));
	uio->uio_resid = buflen;
	uio->uio_segflg = UIO_SYSSPACE;

	for (i = 0; i < iovmax; i++) {
		if (buflen <= 0)
			break;
		tlen = buflen;
		if (tlen > maxseg)
			tlen = maxseg;
		iov[i].iov_base = buf;
		iov[i].iov_len = tlen;
		buf += tlen;
		buflen -= tlen;
	}

	uio->uio_iov = iov;
	uio->uio_iovcnt = i;
}
