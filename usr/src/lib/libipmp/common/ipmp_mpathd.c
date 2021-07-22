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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * Low-level interfaces for communicating with in.mpathd(1M).
 *
 * These routines are not intended for use outside of libipmp.
 */

#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/isa_defs.h>

#include "ipmp.h"
#include "ipmp_mpathd.h"

/*
 * Connect to the multipathing daemon.  Returns an IPMP error code; upon
 * success, `fdp' points to the newly opened socket.
 */
int
ipmp_connect(int *fdp)
{
	int	fd;
	int	error;
	int	on = 1;
	int	flags;
	struct sockaddr_in sin;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return (IPMP_FAILURE);

	/*
	 * If we have sufficient privilege, enable TCP_ANONPRIVBIND so the
	 * kernel will choose a privileged source port (since in.mpathd only
	 * accepts requests on loopback, this is sufficient for security).
	 * If not, drive on since MI_QUERY and MI_PING commands are allowed
	 * from non-privileged ports.
	 */
	(void) setsockopt(fd, IPPROTO_TCP, TCP_ANONPRIVBIND, &on, sizeof (on));

	/*
	 * Bind to a port chosen by the kernel.
	 */
	(void) memset(&sin, 0, sizeof (struct sockaddr_in));
	sin.sin_port = htons(0);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(fd, (struct sockaddr *)&sin, sizeof (sin)) == -1)
		goto fail;

	/*
	 * Attempt to connect to in.mpathd.
	 */
	sin.sin_port = htons(MPATHD_PORT);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (connect(fd, (struct sockaddr *)&sin, sizeof (sin)) == -1) {
		if (errno == ECONNREFUSED) {
			(void) close(fd);
			return (IPMP_ENOMPATHD);
		}
		goto fail;
	}

	/*
	 * Kick the socket into nonblocking mode.
	 */
	flags = fcntl(fd, F_GETFL, 0);
	if (flags != -1)
		(void) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	*fdp = fd;
	return (IPMP_SUCCESS);
fail:
	error = errno;
	(void) close(fd);
	errno = error;
	return (IPMP_FAILURE);
}

/*
 * Read the TLV triplet from descriptor `fd' and store its type, length and
 * value in `*typep', `*lenp', and `*valuep' respectively, before the current
 * time becomes `endtp'.  The buffer pointed to by `*valuep' will be
 * dynamically allocated.  Returns an IPMP error code.
 */
int
ipmp_readtlv(int fd, ipmp_infotype_t *typep, size_t *lenp, void **valuep,
    const struct timeval *endtp)
{
	int	retval;
	void	*value;
	uint32_t tlen;

	retval = ipmp_read(fd, typep, sizeof (*typep), endtp);
	if (retval != IPMP_SUCCESS)
		return (retval);

	retval = ipmp_read(fd, &tlen, sizeof (tlen), endtp);
	if (retval != IPMP_SUCCESS)
		return (retval);

	*lenp = tlen;

	value = malloc(*lenp);
	if (value == NULL) {
		/*
		 * Even though we cannot allocate space for the value, we
		 * still slurp it off so the input stream doesn't get left
		 * in a weird place.
		 */
		value = alloca(*lenp);
		(void) ipmp_read(fd, value, *lenp, endtp);
		return (IPMP_ENOMEM);
	}

	retval = ipmp_read(fd, value, *lenp, endtp);
	if (retval != IPMP_SUCCESS) {
		free(value);
		return (retval);
	}

	*valuep = value;
	return (IPMP_SUCCESS);
}

/*
 * Write `buflen' bytes from `buffer' to open file `fd'.  Returns IPMP_SUCCESS
 * if all requested bytes were written, or an error code if not.
 */
int
ipmp_write(int fd, const void *buffer, size_t buflen)
{
	size_t		nwritten;
	ssize_t		nbytes;
	const char	*buf = buffer;

	for (nwritten = 0; nwritten < buflen; nwritten += nbytes) {
		nbytes = write(fd, &buf[nwritten], buflen - nwritten);
		if (nbytes == -1)
			return (IPMP_FAILURE);
		if (nbytes == 0) {
			errno = EIO;
			return (IPMP_FAILURE);
		}
	}

	assert(nwritten == buflen);
	return (IPMP_SUCCESS);
}

/*
 * Write the TLV triplet named by `type', `len' and `value' to file descriptor
 * `fd'.  Returns an IPMP error code.
 */
int
ipmp_writetlv(int fd, ipmp_infotype_t type, size_t len, void *value)
{
	int	retval;
	uint32_t tlen;

#if defined(_LP64)
	if (len > UINT32_MAX)
		return (IPMP_EPROTO);
#endif

	tlen = (uint32_t)len;

	retval = ipmp_write(fd, &type, sizeof (type));
	if (retval != IPMP_SUCCESS)
		return (retval);

	retval = ipmp_write(fd, &tlen, sizeof (uint32_t));
	if (retval != IPMP_SUCCESS)
		return (retval);

	return (ipmp_write(fd, value, tlen));
}

/*
 * Attempt to read `buflen' worth of bytes from `fd' into the buffer pointed
 * to by `buf' before the current time becomes `endtp'; a `endtp' of NULL
 * means forever.  Returns an IPMP error code.
 */
int
ipmp_read(int fd, void *buffer, size_t buflen, const struct timeval *endtp)
{
	int		retval;
	int		timeleft = -1;
	struct timeval	curtime;
	ssize_t		nbytes = 0;	/* total bytes processed */
	ssize_t		prbytes;	/* per-round bytes processed */
	struct pollfd	pfd;

	while (nbytes < buflen) {
		/*
		 * If a timeout was specified, then compute the amount of time
		 * left before timing out.
		 */
		if (endtp != NULL) {
			if (gettimeofday(&curtime, NULL) == -1)
				break;

			timeleft = (endtp->tv_sec - curtime.tv_sec) * MILLISEC;
			timeleft += (endtp->tv_usec - curtime.tv_usec) / 1000;

			/*
			 * If we should've already timed out, then just
			 * have poll() return immediately.
			 */
			if (timeleft < 0)
				timeleft = 0;
		}

		pfd.fd = fd;
		pfd.events = POLLIN;

		/*
		 * Wait for data to come in or for the timeout to fire.
		 */
		retval = poll(&pfd, 1, timeleft);
		if (retval <= 0) {
			if (retval == 0)
				errno = ETIME;
			break;
		}

		/*
		 * Descriptor is ready; have at it.
		 */
		prbytes = read(fd, (caddr_t)buffer + nbytes, buflen - nbytes);
		if (prbytes <= 0) {
			if (prbytes == -1 && errno == EINTR)
				continue;
			break;
		}
		nbytes += prbytes;
	}

	return (nbytes == buflen ? IPMP_SUCCESS : IPMP_FAILURE);
}
