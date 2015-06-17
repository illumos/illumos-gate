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
 * Copyright 2015 Joyent, Inc.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <port.h>
#include <poll.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/debug.h>
#include <sys/list.h>

#include "pipe_stream.h"

struct pipe_stream {
	pipe_stream_loop_t *pis_loop;

	boolean_t pis_finished;
	boolean_t pis_associated;

	void *pis_arg0;
	void *pis_arg1;

	int pis_fd_write;
	int pis_fd_read;
	list_node_t pis_linkage;
};

struct pipe_stream_loop {
	int psl_port;

	uint8_t *psl_buf;
	size_t psl_buf_cap;
	size_t psl_buf_occ;

	list_t psl_pipes;

	pipe_stream_data_cb *psl_cb_data;
	pipe_stream_eof_cb *psl_cb_eof;
	pipe_stream_error_cb *psl_cb_error;
};


int
pipe_stream_loop_fini(pipe_stream_loop_t *psl)
{
	if (psl == NULL) {
		return (0);
	}

	VERIFY0(close(psl->psl_port));

	while (!list_is_empty(&psl->psl_pipes)) {
		pipe_stream_fini(list_head(&psl->psl_pipes));
	}

	list_destroy(&psl->psl_pipes);
	free(psl);

	return (0);
}

int
pipe_stream_loop_init(pipe_stream_loop_t **pslp, size_t bufsize,
    pipe_stream_data_cb *data_cb, pipe_stream_eof_cb *eof_cb,
    pipe_stream_error_cb *error_cb)
{
	pipe_stream_loop_t *psl;

	if ((psl = calloc(1, sizeof (*psl))) == NULL) {
		return (-1);
	}

	psl->psl_buf_cap = bufsize;
	psl->psl_buf_occ = 0;
	if ((psl->psl_buf = calloc(1, bufsize)) == NULL) {
		free(psl);
		return (-1);
	}

	if ((psl->psl_port = port_create()) == -1) {
		free(psl->psl_buf);
		free(psl);
		return (-1);
	}

	psl->psl_cb_data = data_cb;
	psl->psl_cb_eof = eof_cb;
	psl->psl_cb_error = error_cb;

	list_create(&psl->psl_pipes, sizeof (pipe_stream_t),
	    offsetof(pipe_stream_t, pis_linkage));

	*pslp = psl;
	return (0);
}

boolean_t
pipe_stream_loop_should_run(pipe_stream_loop_t *psl)
{
	pipe_stream_t *pis;

	for (pis = list_head(&psl->psl_pipes); pis != NULL;
	    pis = list_next(&psl->psl_pipes, pis)) {
		if (!pis->pis_finished) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

int
pipe_stream_loop_run(pipe_stream_loop_t *psl)
{
	pipe_stream_t *pis;
	port_event_t pev;
	ssize_t sz;

	for (pis = list_head(&psl->psl_pipes); pis != NULL;
	    pis = list_next(&psl->psl_pipes, pis)) {
		if (pis->pis_finished || pis->pis_associated) {
			/*
			 * Skip streams that are already finished, as well as
			 * those that have already been associated with the
			 * port.
			 */
			continue;
		}

		if (port_associate(psl->psl_port, PORT_SOURCE_FD,
		    pis->pis_fd_read, POLLIN, pis) != 0) {
			return (-1);
		}
	}

again:
	if (port_get(psl->psl_port, &pev, NULL) != 0) {
		switch (errno) {
		case ETIME:
			/*
			 * Timeout expired; return to caller.
			 */
			return (0);

		case EINTR:
			/*
			 * Interrupted by signal.  Try again.
			 */
			goto again;

		default:
			return (-1);
		}
	}

	VERIFY(pev.portev_source == PORT_SOURCE_FD);
	pis = (pipe_stream_t *)pev.portev_user;
	VERIFY((int)pev.portev_object == pis->pis_fd_read);
	pis->pis_associated = B_FALSE;

read_again:
	if ((sz = read(pis->pis_fd_read, psl->psl_buf,
	    psl->psl_buf_cap)) == -1) {
		if (errno == EINTR) {
			goto read_again;
		}

		if (psl->psl_cb_error != NULL) {
			psl->psl_cb_error(errno, pis->pis_arg0, pis->pis_arg1);
		}

		VERIFY0(close(pis->pis_fd_read));
		pis->pis_fd_read = -1;
		pis->pis_finished = B_TRUE;
	}
	psl->psl_buf_occ = sz;

	if (sz == 0) {
		/*
		 * Stream EOF.
		 */
		pis->pis_finished = B_TRUE;
		VERIFY0(close(pis->pis_fd_read));
		pis->pis_fd_read = -1;
		if (psl->psl_cb_eof != NULL) {
			psl->psl_cb_eof(pis->pis_arg0, pis->pis_arg1);
		}
		return (0);
	}

	if (psl->psl_cb_data != NULL) {
		int cbr = psl->psl_cb_data(psl->psl_buf, psl->psl_buf_occ,
		    pis->pis_arg0, pis->pis_arg1);

		if (cbr != 0) {
			/*
			 * Callback failure: close file descriptor.
			 */
			pis->pis_finished = B_TRUE;
			VERIFY0(close(pis->pis_fd_read));
			pis->pis_fd_read = -1;
			if (psl->psl_cb_eof != NULL) {
				psl->psl_cb_eof(pis->pis_arg0, pis->pis_arg1);
			}
		}

		return (0);
	}

	return (0);
}

int
pipe_stream_init(pipe_stream_loop_t *psl, pipe_stream_t **pisp, void *arg0,
    void *arg1)
{
	int e = 0;
	pipe_stream_t *pis;
	int fds[2] = { -1, -1 };

	if ((pis = calloc(1, sizeof (*pis))) == NULL) {
		return (-1);
	}

	if (pipe(fds) != 0) {
		e = errno;
		goto fail;
	}

	pis->pis_fd_read = fds[0];
	pis->pis_fd_write = fds[1];

	pis->pis_arg0 = arg0;
	pis->pis_arg1 = arg1;

	pis->pis_finished = B_FALSE;
	pis->pis_associated = B_FALSE;

	pis->pis_loop = psl;
	list_insert_tail(&psl->psl_pipes, pis);

	*pisp = pis;
	return (0);

fail:
	if (fds[0] != -1) {
		VERIFY0(close(fds[0]));
	}
	if (fds[1] != -1) {
		VERIFY0(close(fds[1]));
	}
	free(pis);
	errno = e;
	return (-1);
}

int
pipe_stream_fini(pipe_stream_t *pis)
{
	if (pis == NULL) {
		return (0);
	}

	if (pis->pis_fd_read != -1) {
		VERIFY0(close(pis->pis_fd_read));
	}
	if (pis->pis_fd_write != -1) {
		VERIFY0(close(pis->pis_fd_write));
	}

	list_remove(&pis->pis_loop->psl_pipes, pis);

	free(pis);
	return (0);
}

/*
 * Called in the parent, after forking, to close the "write" end of the pipe.
 */
void
pipe_stream_parent_afterfork(pipe_stream_t *pis)
{
	if (pis->pis_fd_write != -1) {
		(void) close(pis->pis_fd_write);
		pis->pis_fd_write = -1;
	}
}

/*
 * Called in the child, after forking, to close the "read" end of the
 * pipe, and to dup the file descriptor into the right place.
 */
int
pipe_stream_child_afterfork(pipe_stream_t *pis, int dup_to)
{
	int e = 0;

	if (dup_to != -1) {
		if (dup2(pis->pis_fd_write, dup_to) == -1) {
			e = errno;
		}
		VERIFY0(close(pis->pis_fd_write));
		pis->pis_fd_write = dup_to;
	}

	(void) close(pis->pis_fd_read);
	pis->pis_fd_read = -1;

	errno = e;
	return (e == 0 ? 0 : -1);
}
