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
 * Copyright 2013 Pluribus Networks Inc.
 */

#include <sys/uio.h>

#include <termios.h>
#include <unistd.h>

/*
 * Make a pre-existing termios structure into "raw" mode: character-at-a-time
 * mode with no characters interpreted, 8-bit data path.
 */
void
cfmakeraw(struct termios *t)
{
	t->c_iflag &= ~(IMAXBEL|IXOFF|INPCK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON|IGNPAR);
	t->c_iflag |= IGNBRK;
	t->c_oflag &= ~OPOST;
	t->c_lflag &= ~(ECHO|ECHOE|ECHOK|ECHONL|ICANON|ISIG|IEXTEN|NOFLSH|TOSTOP |PENDIN);
	t->c_cflag &= ~(CSIZE|PARENB);
	t->c_cflag |= CS8|CREAD;
	t->c_cc[VMIN] = 1;
	t->c_cc[VTIME] = 0;
}

ssize_t
preadv(int d, const struct iovec *iov, int iovcnt, off_t offset)
{
	off_t		old_offset;
	ssize_t		n;

	old_offset = lseek(d, (off_t)0, SEEK_CUR);
	if (old_offset == -1)
		return (-1);

	offset = lseek(d, offset, SEEK_SET);
	if (offset == -1)
		return (-1);

	n = readv(d, iov, iovcnt);
	if (n == -1)
		return (-1);

	offset = lseek(d, old_offset, SEEK_SET);
	if (offset == -1)
		return (-1);

	return (n);
}

ssize_t
pwritev(int d, const struct iovec *iov, int iovcnt, off_t offset)
{
	off_t		old_offset;
	ssize_t		n;

	old_offset = lseek(d, (off_t)0, SEEK_CUR);
	if (old_offset == -1)
		return (-1);

	offset = lseek(d, offset, SEEK_SET);
	if (offset == -1)
		return (-1);

	n = writev(d, iov, iovcnt);
	if (n == -1)
		return (-1);

	offset = lseek(d, old_offset, SEEK_SET);
	if (offset == -1)
		return (-1);

	return (n);
}
