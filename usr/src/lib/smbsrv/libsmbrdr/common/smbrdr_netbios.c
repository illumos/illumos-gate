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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * NetBIOS support functions. NetBIOS is documented in the following
 * RFC documents:
 *
 * RFC 1001: Protocol Standard for a NetBIOS Service on a TCP/UDP
 *           Transport: Concepts and Methods
 *
 * RFC 1002: Protocol Standard for a NetBIOS Service on a TCP/UDP
 *           Transport: Detailed Specifications
 *
 */

#define	BSD_BYTE_STRING_PROTOTYPES

#include <string.h>
#include <unistd.h>
#include <synch.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/time.h>

#include <stdio.h>
#include <pthread.h>

#include <smbsrv/cifs.h>

#define	MAX_NETBIOS_NAME_SIZE	16

#define	SESSION_MESSAGE				0x00
#define	SESSION_REQUEST				0x81
#define	POSITIVE_SESSION_RESPONSE		0x82
#define	NEGATIVE_SESSION_RESPONSE		0x83
#define	RETARGET_SESSION_RESPONSE		0x84
#define	SESSION_KEEP_ALIVE			0x85

#define	NB_READ_MSG_ERR_EOF			0
#define	NB_READ_MSG_ERR				-1
#define	NB_READ_MSG_ERR_OVERFLOW		-2
#define	NB_READ_MSG_ERR_UNDERFLOW		-3
#define	NB_RCV_MSG_ERR_INVTYPE			-4

/*
 * Semaphore object used to serialize access through NetBIOS exchange.
 */
static mutex_t nb_mutex;

static int nb_write_msg(int fd, unsigned char *buf, unsigned count, int type);
static int nb_read_msg(int fd, unsigned char *buf, unsigned max_buf,
    int *type, long timeout);
static int nb_read_itter(int fd, unsigned char *buf, unsigned cnt);
static int nb_first_level_name_encode(char *name, char *scope,
    unsigned char *out, int max_out);


/*
 * nb_lock
 *
 * Acquire mutex for doing netbios operations
 */
void
nb_lock()
{
	(void) mutex_lock(&nb_mutex);
}

/*
 * nb_lock
 *
 * Release netbios mutex.
 */
void
nb_unlock()
{
	(void) mutex_unlock(&nb_mutex);
}

void
nb_close(int fd)
{
	(void) mutex_lock(&nb_mutex);
	if (fd > 0) {
		(void) close(fd);
		(void) printf("[%d] socket (%d) closed\n", pthread_self(), fd);
	}
	(void) mutex_unlock(&nb_mutex);
}

/*
 * nb_keep_alive
 *
 * Send the NetBIOS keep alive message only if smbrdr is connected on port 139.
 * No response is expected but we do need to ignore keep-alive messages in
 * nb_exchange. The mutex ensures compatibility/serialization with
 * nb_exchange to allow us to call this function from a separate thread.
 */
int
nb_keep_alive(int fd, short port)
{
	int nothing;
	int rc;

	if (port == SMB_SRVC_TCP_PORT)
		return (0);

	(void) mutex_lock(&nb_mutex);

	rc = nb_write_msg(fd, (unsigned char *)&nothing, 0, SESSION_KEEP_ALIVE);

	(void) mutex_unlock(&nb_mutex);
	return (rc);
}

/*
 * nb_send
 *
 * This is just a wrapper round the nb_write_msg.
 */
int
nb_send(int fd, unsigned char *send_buf, unsigned send_cnt)
{
	int rc;

	rc = nb_write_msg(fd, send_buf, send_cnt, SESSION_MESSAGE);
	return (rc);
}

/*
 * nb_rcv
 *
 * This is a wrapper round the nb_read_msg() so that if a
 * keep-alive message is received, just discard it and go
 * back to look for the real response.
 */
int
nb_rcv(int fd, unsigned char *recv_buf, unsigned recv_max, long timeout)
{
	int rc;
	int type;

	do {
		rc = nb_read_msg(fd, recv_buf, recv_max, &type, timeout);
		if (rc < 0)
			return (rc);
	} while (type == SESSION_KEEP_ALIVE);

	if (type != SESSION_MESSAGE)
		return (NB_RCV_MSG_ERR_INVTYPE);

	return (rc);
}

/*
 * nb_exchange
 *
 * This is the NetBIOS workhorse function where we do the send/receive
 * message exchange. A mutex is used to serialize access because
 * we may get swapped out between the send and receive operations and
 * another thread could enter here and collect our response. If a
 * keep-alive message is received, just discard it and go back to look
 * for the real response.
 *
 * Note: With the addition of support for SMB over TCP, this function
 * may be exchanging NetBIOS-less SMB data.
 */
int
nb_exchange(int fd, unsigned char *send_buf, unsigned send_cnt,
    unsigned char *recv_buf, unsigned recv_max, long timeout)
{
	int rc;

	(void) mutex_lock(&nb_mutex);

	rc = nb_send(fd, send_buf, send_cnt);
	if (rc == send_cnt)
		rc = nb_rcv(fd, recv_buf, recv_max, timeout);

	(void) mutex_unlock(&nb_mutex);
	return (rc);
}

/*
 * nb_session_request
 *
 * We should never see descriptor 0 (stdin) or -1.
 */
int
nb_session_request(int fd, char *called_name, char *called_scope,
    char *calling_name, char *calling_scope)
{
	unsigned char sr_buf[200];
	int len;
	int rc;
	int type;

	if (fd == 0 || fd == -1)
		return (-1);

	rc = nb_first_level_name_encode(called_name, called_scope, sr_buf, 100);
	len = rc;
	rc = nb_first_level_name_encode(calling_name, calling_scope,
	    sr_buf+len, 100);
	len += rc;

	(void) mutex_lock(&nb_mutex);

	rc = nb_write_msg(fd, (unsigned char *)sr_buf, len, SESSION_REQUEST);
	if (rc < 0) {
		(void) mutex_unlock(&nb_mutex);
		return (rc);
	}

	for (;;) {
		rc = nb_read_msg(fd, (unsigned char *)sr_buf,
		    sizeof (sr_buf), &type, 0);
		if (rc < 0) {
			(void) mutex_unlock(&nb_mutex);
			return (rc);
		}

		if ((rc == 0) && (type == -1)) {
			(void) mutex_unlock(&nb_mutex);
			return (-1);		/* EOF */
		}

		if (type == POSITIVE_SESSION_RESPONSE) {
			(void) mutex_unlock(&nb_mutex);
			return (0);
		}

		if (type == NEGATIVE_SESSION_RESPONSE) {
			(void) mutex_unlock(&nb_mutex);
			return (-1);
		}
	}

	/* NOTREACHED */
	(void) mutex_unlock(&nb_mutex);
	return (-1);
}



/*
 * nb_write_msg
 */
static int
nb_write_msg(int fd, unsigned char *buf, unsigned count, int type)
{
	struct iovec iov[2];
	unsigned char header[4];
	int rc;

	if (fd == 0 || fd == -1) {
		/*
		 * We should never see descriptor 0 (stdin).
		 */
		return (-1);
	}

	/*
	 * The NetBIOS message length is limited to 17 bits but
	 * we use this layer for SMB over both NetBIOS and TCP
	 * (NetBIOS-less SMB). When using SMB over TCP the length
	 * is 24 bits but we are ignoring that for now because we
	 * don't expect any messages larger than 64KB.
	 */
	header[0] = type;
	header[1] = (count >> 16) & 1;
	header[2] = count >> 8;
	header[3] = count;

	iov[0].iov_base = (caddr_t)header;
	iov[0].iov_len = 4;
	iov[1].iov_base = (caddr_t)buf;
	iov[1].iov_len = count;

	rc = writev(fd, iov, 2);
	if (rc != 4 + count) {
		return (-3);		/* error */
	}

	return (count);
}


/*
 * nb_read_msg
 *
 * Added select to ensure that we don't block forever waiting for a
 * message.
 */
static int
nb_read_msg(int fd, unsigned char *buf, unsigned max_buf,
    int *type, long timeout)
{
	unsigned char header[4];
	int length;
	int rc;
	fd_set readfds;
	struct timeval tval;

	*type = -1;

	if (fd == 0 || fd == -1) {
		/*
		 * We should never see descriptor 0 (stdin).
		 */
		return (NB_READ_MSG_ERR);
	}

	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);
	tval.tv_sec = (timeout == 0) ? 45 : timeout;
	tval.tv_usec = 0;

	if ((rc = select(fd + 1, &readfds, 0, 0, &tval)) <= 0) {
		return (NB_READ_MSG_ERR);
	}

	if ((rc = nb_read_itter(fd, header, 4)) < 0)
		return (rc);		/* error */

	if (rc != 4)
		return (NB_READ_MSG_ERR_EOF);		/* EOF */

	/*
	 * The NetBIOS message length is limited to 17 bits but
	 * we use this layer for SMB over both NetBIOS and TCP
	 * (NetBIOS-less SMB). When using SMB over TCP the length
	 * is 24 bits but we are ignoring that for now because we
	 * don't expect any messages larger than 64KB.
	 */
	*type = header[0];
	length = ((header[1]&1) << 16) + (header[2]<<8) + header[3];

	if (length > max_buf)
		return (NB_READ_MSG_ERR_OVERFLOW);	/* error overflow */

	if ((rc = nb_read_itter(fd, buf, length)) != length)
		return (NB_READ_MSG_ERR_UNDERFLOW);	/* error underflow */

	return (rc);
}


/*
 * nb_read_itter
 *
 * We should never see descriptor 0 (stdin) or -1.
 */
static int
nb_read_itter(int fd, unsigned char *buf, unsigned cnt)
{
	int ix;
	int rc;

	for (ix = 0; ix < cnt; ix += rc) {
		if (fd == 0 || fd == -1)
			return (-1);

		if ((rc = read(fd, buf+ix, cnt-ix)) < 0)
			return (rc);

		if (rc == 0)
			break;
	}

	return (ix);
}


/*
 * nb_first_level_name_encode
 */
static int
nb_first_level_name_encode(char *name, char *scope,
    unsigned char *out, int max_out)
{
	unsigned char ch, len;
	unsigned char *in;
	unsigned char *lp;
	unsigned char *op = out;
	unsigned char *op_end = op + max_out;

	in = (unsigned char *)name;
	*op++ = 0x20;
	for (len = 0; ((ch = *in) != 0) && len < MAX_NETBIOS_NAME_SIZE;
	    len++, in++) {
		*op++ = 'A' + ((ch >> 4) & 0xF);
		*op++ = 'A' + ((ch) & 0xF);
	}

	for (; len < MAX_NETBIOS_NAME_SIZE; len++) {
		ch = ' ';
		*op++ = 'A' + ((ch >> 4) & 0xF);
		*op++ = 'A' + ((ch) & 0xF);
	}

	in = (unsigned char *)scope;
	len = 0;
	lp = op++;
	for (; op < op_end; in++) {
		ch = *in;
		if (ch == 0) {
			if ((*lp = len) != 0)
				*op++ = 0;
			break;
		}
		if (ch == '.') {
			*lp = (op - lp) - 1;
			lp = op++;
			len = 0;
		} else {
			*op++ = ch;
			len++;
		}
	}

	return ((int)(op - out));
}
