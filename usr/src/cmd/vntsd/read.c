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

/*
 * read thread - Read from tcp client and write to vcc driver. There  are one
 * writer and multiple readers per console. The first client who connects to
 * a console get write access. An error message is returned to readers if they
 * attemp to input commands. Read thread accepts special daemon commands from
 * all clients.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <thread.h>
#include <synch.h>
#include <signal.h>
#include <assert.h>
#include <ctype.h>
#include <syslog.h>
#include <libintl.h>
#include "vntsd.h"
#include "chars.h"

/* write_vcc()  - write to vcc virtual console */
static int
write_vcc(vntsd_client_t *clientp, char c)
{
	int	n;


	assert(clientp);
	assert(clientp->cons);

	n = write(clientp->cons->vcc_fd, &c, 1);

	if (n < 0) {
		/* write error */
		if (errno == EINTR) {
			return (vntsd_cons_chk_intr(clientp));
		}

		return (VNTSD_STATUS_VCC_IO_ERR);
	}

	assert(n != 0);
	return (VNTSD_SUCCESS);

}

/*
 * acquire_writer() the client is going to be writer.
 * insert the client to the head of the console client queue.
 */
static int
acquire_writer(vntsd_client_t *clientp)
{
	vntsd_cons_t	    *consp;
	vntsd_client_t	    *writerp;
	int		    rv;

	D1(stderr, "t@%d:acuire_writer :client@%d\n", thr_self(),
	    clientp->sockfd);

	assert(clientp != NULL);
	consp = clientp->cons;

	assert(consp);

	(void) mutex_lock(&consp->lock);

	assert(consp->clientpq != NULL);
	if (consp->clientpq->handle == clientp) {
		/* clientp is a writer already */
		(void) mutex_unlock(&consp->lock);
		return (VNTSD_SUCCESS);
	}

	/* current writer */
	writerp = (vntsd_client_t *)(consp->clientpq->handle);

	(void) mutex_lock(&writerp->lock);

	rv = vntsd_que_rm(&(consp->clientpq), clientp);
	assert(rv == VNTSD_SUCCESS);

	(void) mutex_lock(&clientp->lock);

	/* move client to be first in the console queue */
	consp->clientpq->handle = clientp;

	/* move previous writer to be the second in the queue */
	rv =  vntsd_que_insert_after(consp->clientpq, clientp, writerp);

	(void) mutex_unlock(&consp->lock);
	(void) mutex_unlock(&writerp->lock);
	(void) mutex_unlock(&clientp->lock);

	if (rv != VNTSD_SUCCESS) {
		return (rv);
	}

	/* write warning message to the writer */

	if ((rv = vntsd_write_line(writerp,
	    gettext("Warning: Console connection forced into read-only mode")))
	    != VNTSD_SUCCESS) {
		return (rv);
	}

	return (VNTSD_SUCCESS);
}

/* interrupt handler */
int
vntsd_cons_chk_intr(vntsd_client_t *clientp)
{

	if (clientp->status & VNTSD_CLIENT_TIMEOUT) {
		return (VNTSD_STATUS_CLIENT_QUIT);
	}
	if (clientp->status & VNTSD_CLIENT_CONS_DELETED) {
		return (VNTSD_STATUS_RESELECT_CONS);
	}

	if (clientp->status & VNTSD_CLIENT_IO_ERR) {
		return (VNTSD_STATUS_CLIENT_QUIT);
	}
	return (VNTSD_STATUS_CONTINUE);
}

/* read from client */
static int
read_char(vntsd_client_t *clientp, char *c)
{
	int	    rv;

	for (; ; ) {

		rv = vntsd_read_data(clientp, c);

		switch (rv) {

		case VNTSD_STATUS_ACQUIRE_WRITER:
			clientp->prev_char = 0;
			rv = acquire_writer(clientp);
			if (rv != VNTSD_SUCCESS) {
				return (rv);
			}
			break;

		case VNTSD_SUCCESS:
			/*
			 * Based on telnet protocol, when an <eol> is entered,
			 * vntsd receives <0x0d,0x00>. However, console expects
			 * <0xd> only. We need to filter out <0x00>.
			 */
			if (clientp->prev_char == 0xd && *c == 0) {
				clientp->prev_char = *c;
				break;
			}

			clientp->prev_char = *c;
			return (rv);

		default:
			assert(rv != VNTSD_STATUS_CONTINUE);
			clientp->prev_char = 0;
			return (rv);

		}
	}
}

/* vntsd_read worker */
int
vntsd_read(vntsd_client_t *clientp)
{
	char		c;
	int		rv;


	assert(clientp);
	D3(stderr, "t@%d vntsd_read@%d\n", thr_self(), clientp->sockfd);

	for (; ; ) {

		/* client input */
		rv = read_char(clientp, &c);

		if (rv == VNTSD_STATUS_INTR) {
			rv = vntsd_cons_chk_intr(clientp);
		}

		if (rv != VNTSD_SUCCESS) {
			return (rv);
		}

		assert(clientp->cons);

		/*
		 * Only keyboard inputs from first connection to a
		 * guest console should be accepted.  Check to see if
		 * this client is the first connection in console
		 * queue
		 */
		if (clientp->cons->clientpq->handle != clientp) {
			/*
			 * Since this console connection is not the first
			 * connection in the console queue,
			 * it is operating in 'reader'
			 * mode, print warning and ignore the input.
			 */
			rv = vntsd_write_line(clientp,
			    gettext(VNTSD_NO_WRITE_ACCESS_MSG));

			/* check errors and interrupts */
			if (rv == VNTSD_STATUS_INTR) {
				rv = vntsd_cons_chk_intr(clientp);
			}

			if (rv != VNTSD_SUCCESS) {
				return (rv);
			}

			continue;
		}

		rv = vntsd_ctrl_cmd(clientp, c);

		switch (rv) {
		case VNTSD_STATUS_CONTINUE:
			continue;
			break;
		case VNTSD_STATUS_INTR:
			rv = vntsd_cons_chk_intr(clientp);
			if (rv != VNTSD_SUCCESS) {
				return (rv);
			}
			break;
		case VNTSD_SUCCESS:
			break;
		default:
			return (rv);
		}

		/* write to vcc */
		rv = write_vcc(clientp, c);
		if (rv == VNTSD_STATUS_INTR) {
			rv = vntsd_cons_chk_intr(clientp);
		}
		if (rv != VNTSD_SUCCESS) {
			return (rv);
		}

	}

	/*NOTREACHED*/
	return (0);
}
