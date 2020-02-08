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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * write thread - read from vcc console and  write to tcp client. There are one
 * writer and multiple readers per console. The first client who connects to
 * a console get write access.
 * Writer thread writes vcc data to all tcp clients that connected to
 * the console.
 */

#include <stdio.h>
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
#include <poll.h>
#include <syslog.h>
#include <libintl.h>
#include "vntsd.h"
#include "chars.h"

/* handle for writing all clients  */
typedef	struct write_buf {
	uint_t	sz;	    /* data size */
	char	*buf;
} write_buf_t;

/*
 * check the state of write thread. exit if no more client connects to the
 * console.
 */
static void
write_chk_status(vntsd_cons_t *consp, int status)
{

	if ((consp->status & VNTSD_CONS_DELETED) || (consp->clientpq == NULL)) {
		thr_exit(0);
	}

	switch (status) {
	case VNTSD_STATUS_VCC_IO_ERR:
		assert(consp->group != NULL);
		if (vntsd_vcc_err(consp) != VNTSD_STATUS_CONTINUE) {
			thr_exit(0);
		}
		break;
	case VNTSD_STATUS_INTR:
		thr_exit(0);
	default:
		break;

	}
}

/*
 * skip_terminal_null()
 * scan terminal null character sequence (0x5e 0x40)
 * return number of characters in the buf after skipping terminal null
 * sequence. buf size must be at least sz+1.
 */
static int
skip_terminal_null(char *buf, int sz)
{
	int	    i, j;
	static int  term_null_seq = 0;

	assert(sz >= 0);

	if (term_null_seq) {
		/* skip 0x5e previously */
		term_null_seq = 0;

		if (buf[0] != 0x40) {
			/* not terminal null sequence put 0x5e back */
			for (i = sz; i > 0; i--) {
				buf[i] = buf[i-1];
			}

			buf[0] = 0x5e;

			sz++;
		} else {
			/* skip terminal null sequence */
			sz--;

			if (sz == 0) {
				return (sz);
			}

			for (i = 0; i < sz; i++) {
				buf[i] = buf[i+1];
			}
		}
	}

	for (; ; ) {
		for (i = 0; i < sz; i++) {
			if (buf[i]  == '\0') {
				return (i);
			}

			if (buf[i] == 0x5e) {
				/* possible terminal null sequence */
				if (i == sz -1) {
					/* last character in buffer */
					term_null_seq = 1;
					sz--;
					buf[i] = 0;
					return (sz);
				}

				if (buf[i+1] == 0x40) {
					/* found terminal null sequence */
					sz -= 2;
					for (j = i; j < sz -i; j++) {
						buf[j] = buf[j+2];
					}
					break;
				}

				if (buf[i+1] == '\0') {
					buf[i] = 0;
					term_null_seq = 1;
					return (i);
				}

			}
		}

		if (i == sz) {
			/* end of scan */
			return (sz);
		}
	}
}

/* read data from vcc */
static int
read_vcc(vntsd_cons_t *consp, char *buf, ssize_t *sz)
{
	/* read from vcc */
	*sz = read(consp->vcc_fd, buf, VNTSD_MAX_BUF_SIZE);

	if (errno == EINTR) {
		return (VNTSD_STATUS_INTR);
	}

	if ((*sz > 0)) {
		return (VNTSD_SUCCESS);
	}
	return (VNTSD_STATUS_VCC_IO_ERR);
}

/*
 * write to a client
 * this function is passed as a parameter to vntsd_que_find.
 * for each client that connected to the console, vntsd_que_find
 * applies this function.
 */
static boolean_t
write_one_client(vntsd_client_t *clientp, write_buf_t *write_buf)
{
	int rv;

	rv = vntsd_write_client(clientp, write_buf->buf, write_buf->sz);
	if (rv != VNTSD_SUCCESS) {
		(void) mutex_lock(&clientp->lock);
		clientp->status |= VNTSD_CLIENT_IO_ERR;
		assert(clientp->cons);
		(void) thr_kill(clientp->cons_tid, 0);
		(void) mutex_unlock(&clientp->lock);
	}
	return (B_FALSE);

}

/* vntsd_write_thread() */
void*
vntsd_write_thread(vntsd_cons_t *consp)
{
	char		buf[VNTSD_MAX_BUF_SIZE+1];
	int		sz;
	int		rv;
	write_buf_t	write_buf;

	D1(stderr, "t@%d vntsd_write@%d\n", thr_self(), consp->vcc_fd);

	assert(consp);
	write_chk_status(consp, VNTSD_SUCCESS);

	for (; ; ) {
		bzero(buf,  VNTSD_MAX_BUF_SIZE +1);

		/* read data */
		rv = read_vcc(consp, buf, &sz);

		write_chk_status(consp, rv);

		if (sz <= 0) {
			continue;
		}

		/* has data */
		if ((sz = skip_terminal_null(buf, sz)) == 0) {
			/* terminal null sequence */
			continue;
		}

		write_buf.sz = sz;
		write_buf.buf = buf;

		/*
		 * output data to all clients connected
		 * to this console
		 */

		(void) mutex_lock(&consp->lock);
		(void) vntsd_que_find(consp->clientpq,
		    (compare_func_t)write_one_client, &write_buf);
		(void) mutex_unlock(&consp->lock);

		write_chk_status(consp, VNTSD_SUCCESS);

	}

	/*NOTREACHED*/
	return (NULL);
}
