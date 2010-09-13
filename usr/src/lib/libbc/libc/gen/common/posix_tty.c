/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1995 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * wrappers for posix tty manipulation functions
 */

#include <errno.h>
#include <termios.h>
#include <termio.h>
#include <sys/types.h>

/*
 * return the output speed from the struct
 */
speed_t
cfgetospeed(struct termios *termios_p)
{
	return (termios_p->c_cflag & CBAUDEXT ?
			(termios_p->c_cflag & CBAUD) + CBAUD + 1 :
			termios_p->c_cflag & CBAUD);
}

/*
 * set the speed in the struct
 */
int
cfsetospeed(struct termios *termios_p, speed_t speed)
{
	if (speed > (2*CBAUD + 1)) {
		errno = EINVAL;
		return (-1);
	}
	if (speed > CBAUD) {
		termios_p->c_cflag |= CBAUDEXT;
		speed -= (CBAUD + 1);
	} else
		termios_p->c_cflag &= ~CBAUDEXT;

	termios_p->c_cflag =
	    (termios_p->c_cflag & ~CBAUD) | (speed & CBAUD);
	return (0);
}

/*
 * return the input speed from the struct
 */
speed_t
cfgetispeed(struct termios *termios_p)
{
	return (termios_p->c_cflag & CIBAUDEXT ?
	    ((termios_p->c_cflag & CIBAUD) >> IBSHIFT)
		+ (CIBAUD >> IBSHIFT) + 1 :
	    (termios_p->c_cflag & CIBAUD) >> IBSHIFT);
}

/*
 * set the input speed in the struct
 */
int
cfsetispeed(struct termios *termios_p, speed_t speed)
{
	if (speed > (2*CBAUD + 1)) {
		errno = EINVAL;
		return (-1);
	}
	if ((speed << IBSHIFT) > CIBAUD) {
		termios_p->c_cflag |= CIBAUDEXT;
		speed -= ((CIBAUD >> IBSHIFT) + 1);
	} else
		termios_p->c_cflag &= ~CIBAUDEXT;
	termios_p->c_cflag =
	    (termios_p->c_cflag & ~CIBAUD) | ((speed << IBSHIFT) & CIBAUD);
	return (0);
}

/*
 * grab the modes
 */
int
tcgetattr(int fd, struct termios *termios_p)
{
	return (ioctl(fd, TCGETS, termios_p));
}

/*
 * set the modes
 */
int
tcsetattr(int fd, int option, struct termios *termios_p)
{
	struct termios	work_area;

	/* If input speed is zero, set it to the output speed. */
	if ((((termios_p->c_cflag >> IBSHIFT) & CIBAUD) == 0) &&
		((termios_p->c_cflag & CIBAUDEXT) == 0)) {
		work_area = *termios_p;
		work_area.c_cflag |= (work_area.c_cflag & CBAUD) << IBSHIFT;
		if (termios_p->c_cflag & CBAUDEXT)
			work_area.c_cflag |= CIBAUDEXT;
		termios_p = &work_area;
	}
	switch (option) {
	case TCSADRAIN:
		return (ioctl(fd, TCSETSW, termios_p));
	case TCSAFLUSH:
		return (ioctl(fd, TCSETSF, termios_p));
	case TCSANOW:
		return (ioctl(fd, TCSETS, termios_p));
	default:
		errno = EINVAL;
		return (-1);
	}
	/*NOTREACHED*/
}

/*
 * send a break
 * This is kludged for duration != 0; it should do something like crank the
 * baud rate down and then send the break if the duration != 0.
 */
int
tcsendbreak(int fd, int duration)
{
	unsigned d = (unsigned)duration;

	do
		if (ioctl(fd, TCSBRK, 0) == -1)
			return (-1);
	while (d--);
	return (0);
}

/*
 * wait for all output to drain from fd
 */
int
tcdrain(int fd)
{
	return (ioctl(fd, TCSBRK, !0));
}

/*
 * flow control
 */
int
tcflow(int fd, int action)
{
	switch (action) {
	default:
		errno = EINVAL;
		return (-1);
	case TCOOFF:
	case TCOON:
	case TCIOFF:
	case TCION:
		return (ioctl(fd, TCXONC, action));
	}
	/*NOTREACHED*/
}

/*
 * flush read/write/both
 */
int
tcflush(int fd, int queue)
{
	switch (queue) {
	default:
		errno = EINVAL;
		return (-1);
	case TCIFLUSH:
	case TCOFLUSH:
	case TCIOFLUSH:
		return (ioctl(fd, TCFLSH, queue));
	}
	/*NOTREACHED*/
}

/*
 * get the foreground process group id
 */
pid_t
tcgetpgrp(int fd)
{
	int grp_id;

	if (ioctl(fd, TIOCGETPGRP, &grp_id) == -1)
		return ((pid_t)-1);
	else
		return ((pid_t)grp_id);
}

/*
 * set the foreground process group id
 */
int
tcsetpgrp(int fd, int grp_id)
{
	return (ioctl(fd, TIOCSETPGRP, &grp_id));
}
