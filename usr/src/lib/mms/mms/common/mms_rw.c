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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * MMS socket or named-pipe string writer and string reader.
 *
 * O_NDELAY and O_NONBLOCK are assumed to be not set for a blocking
 * read and write. Currently, both flags are clear as the default.
 */
#include <sys/types.h>
#include <sys/filio.h>
#include <pthread.h>
#include <stropts.h>
#include <sys/conf.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <mms_dmd.h>
#include "mms_network.h"
#include "mms_sym.h"
#include "mms_sock.h"

static	pthread_mutex_t	mms_read_mutex = PTHREAD_MUTEX_INITIALIZER;
static	pthread_mutex_t	mms_write_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * mms_writer()
 *
 * Parameters:
 *	fd	File descriptor that packet is to be written to
 *	buf	Contains the text that is to be written. Buf must be '\0'
 *		terminated.
 *
 * This routine will write out a mms command from one process to another
 * using the fd as the descriptor to write to. It replaces newline
 * characters in the input buffer with blanks and appends "\r\n" to the end
 * of the input buffer. The newline character is used as the delimiter of a
 * command. O_NDELAY and O_ NONBLOCK are assumed to be clear, thus it will
 * block if it cannot write. This routine should be protected by a mutex if
 * more than one thread or process can write to fd at one time. The reason
 * for this is that if the routine is interrupted while it is writing, it
 * will try to complete the write when control is returned to this routine.
 * Though the odds of this are slim, it should still be done.
 *
 * Return Values:
 *	-1		No data was written and write failed. Check errno
 *			for cause of failure.
 *	< len of buf	If the write was able to write part of the data
 *			but write returned a -1 on suplmental call to write.
 *			Thus one needs to look at errno to determine the
 *			cause of the failure. This will also corrupt the
 *			socket. Recovery should be to close the socket and
 *			reconnect if a application to MM. If no data was
 *			written in then a len of 0 will be returned.
 *	len of buf	If write was successful. This routine also writes the
 *			'\0' byte but does not add this to the length returned.
 *
 */

int
mms_writer(mms_t *conn, char *buf)
{
	struct	iovec	iov[3];
	struct	iovec	*iov_start;
	int		nleft;
	int		i;
	int		rc;
	int		nwritten;
	int		niov;
	char		*terminator = "\n";
	int		termlen = strlen(terminator);
	int		buflen;
	char		hdr[MMS_SOCK_HDR_SIZE + 1];

	buflen = strlen(buf);
	(void) snprintf(hdr, sizeof (hdr), "%8.8s%7.7d\n", MMS_MSG_MAGIC,
	    buflen + termlen);

	iov[0].iov_base = hdr;
	iov[0].iov_len = MMS_SOCK_HDR_SIZE;

	iov[1].iov_base = buf;
	iov[1].iov_len = buflen;

	iov[2].iov_base = terminator;
	iov[2].iov_len = termlen;

	nwritten = 0;
	nleft = 0;
	for (i = 0; i < 3; i++) {
		/* Calculate the number of bytes to write */
		nleft += iov[i].iov_len;
	}
	iov_start = iov;
	niov = 3;
	(void) pthread_mutex_lock(&mms_write_mutex);
	while (nleft > 0) {
		/*
		 * if socket or fifo full, write blocks until room
		 * is made
		 */
		if ((rc = mms_write(conn, iov_start, niov)) < 0) {
			if (mms_write_has_error(conn) == 0)
				continue;
			/* see if any data has been written */
			if (nwritten) {
				rc = nwritten;
			}
			(void) pthread_mutex_unlock(&mms_write_mutex);
			return (rc);
		}
		/* some or all data written */
		nleft -= rc;
		nwritten += rc;

		if (nleft > 0) {		/* not all written */
			/* Have to figure out where to restart */
			for (i = 0; i < niov; i++) {
				if (rc < iov[i].iov_len) {
					break;
				}
				rc -= iov[i].iov_len;
			}
			iov[i].iov_base += rc;
			iov[i].iov_len -= rc;
			iov_start += i;
			niov -= i;
			continue;
		}
	}

	(void) pthread_mutex_unlock(&mms_write_mutex);
	/* buffer written */
	return (buflen);
}

/*
 * mms_reader()
 *
 * Return a complete MMS command in a read buffer, including the newline
 * character that delimits one command from the next.
 *
 * Parameters:
 *	fd	File descriptor that routine is to read from
 *	buf	Ptr to the text that was read in. Actual return value
 *		of the message that was received. If an error occurs
 *		this will be set to NULL.
 *
 * This routine allocates a read buffer and copy bytes from the receive
 * buffer for the file descriptor until a newline character is encountered
 * and copied. Then the read buffer is terminated with '\0'. If an interrupt
 * occurs while reading, the routine will start another read. This routine
 * will read until the necessary amount of data is obtained or it errors out
 * for some some reason. O_NDELAY and O_NONBLOCK are assumed to be clear,
 * thus it will block if it cannot read. This routine should be protected by
 * a mutex if more than one thread or process can read from the fd at one
 * time. The reason for this is that if the routine is interrupted while it
 * is reading, it will try to complete the read when control is returned to
 * this routine. Though the odds of this are slim, it should still be
 * done.
 *
 * Return Values:
 *	-1		No data was read and read failed. Check errno
 *			for cause of failure. If errno was an EINTR the
 *			routine will attempt to read again. All other reasons
 *			for a -1 return value from read will return a -1. User
 *			will need to check the errno to determine reason.
 *	0		If EOF was read, the read will return a 0. This
 *			routine will return a 0 in this case otherwise the
 *			internal loops turn into infinite loops.
 *	len of buf	The length of the message that was read. Even though
 *			this routine reads the header and a trailing '\0'
 *			character this value does not include them.
 *
 */

int
mms_reader(mms_t *conn, char **cmdbuf)
{
	int		rc;
	int		bufsize;
	char		*buf;
	char		hdr[MMS_SOCK_HDR_SIZE + 1];

	*cmdbuf = NULL;
	(void) pthread_mutex_lock(&mms_read_mutex);

	/*
	 * Read header to get message size
	 */
	while ((rc = mms_read(conn, hdr, MMS_SOCK_HDR_SIZE)) < 0) {
		if (mms_read_has_error(conn) == 0) {
			continue;
		}
		(void) pthread_mutex_unlock(&mms_read_mutex);
		return (-1);
	}
	if (rc == 0) {
		/* Hit EOF */
		(void) pthread_mutex_unlock(&mms_read_mutex);
		return (rc);
	}
	hdr[MMS_SOCK_HDR_SIZE] = '\0';

	/*
	 * Check message magic
	 */
	if (strncmp(hdr, MMS_MSG_MAGIC, MMS_MSG_MAGIC_LEN) != 0) {
		/* Incorrect input */
		mms_error(&conn->mms_err, MMS_ERR_READ);
		(void) pthread_mutex_unlock(&mms_read_mutex);
		return (-1);
	}

	(void) sscanf(hdr + MMS_MSG_MAGIC_LEN, "%d", &bufsize);

	buf = malloc(bufsize + 1);
	if (buf == NULL) {
		mms_error(&conn->mms_err, MMS_ERR_NOMEM);
		(void) pthread_mutex_unlock(&mms_read_mutex);
		return (-1);
	}
	while ((rc = mms_read(conn, buf, bufsize)) < 0) {
		if (mms_read_has_error(conn) == 0) {
			continue;
		}
		free(buf);
		(void) pthread_mutex_unlock(&mms_read_mutex);
		return (-1);
	}
	*cmdbuf = buf;				/* return buffer ptr */
	buf[rc] = '\0';			/* terminate what is read */
	(void) pthread_mutex_unlock(&mms_read_mutex);
	return (rc);
}
