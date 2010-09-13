/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <synch.h>
#include <tlm_buffers.h>
#include <tlm.h>
#include "tlm_proto.h"


/*
 * tlm_allocate_buffers
 *
 * build a set of buffers
 */
tlm_buffers_t *
tlm_allocate_buffers(boolean_t write, long xfer_size)
{
	tlm_buffers_t *buffers = ndmp_malloc(sizeof (tlm_buffers_t));
	int	buf;

	if (buffers == 0)
		return (0);

	for (buf = 0; buf < TLM_TAPE_BUFFERS; buf++) {
		buffers->tbs_buffer[buf].tb_buffer_data =
		    ndmp_malloc(xfer_size);
		if (buffers->tbs_buffer[buf].tb_buffer_data == 0) {
			int	i;

			/* Memory allocation failed. Give everything back */
			for (i = 0; i < buf; i++)
				free(buffers->tbs_buffer[i].tb_buffer_data);

			free(buffers);
			return (0);
		} else {
			buffers->tbs_buffer[buf].tb_buffer_size = (write)
			    ? xfer_size : 0;
			buffers->tbs_buffer[buf].tb_full = FALSE;
			buffers->tbs_buffer[buf].tb_eof = FALSE;
			buffers->tbs_buffer[buf].tb_eot = FALSE;
			buffers->tbs_buffer[buf].tb_errno = 0;
			buffers->tbs_buffer[buf].tb_buffer_spot = 0;
		}

	}

	(void) mutex_init(&buffers->tbs_mtx, 0, NULL);
	(void) cond_init(&buffers->tbs_in_cv, 0, NULL);
	(void) cond_init(&buffers->tbs_out_cv, 0, NULL);

	buffers->tbs_data_transfer_size = xfer_size;
	buffers->tbs_ref = 1;
	return (buffers);
}

/*
 * tlm_release_buffers
 *
 * give all memory back to the OS
 */
void
tlm_release_buffers(tlm_buffers_t *buffers)
{
	int i;

	if (buffers != NULL) {
		tlm_buffer_release_in_buf(buffers);
		tlm_buffer_release_out_buf(buffers);

		(void) mutex_lock(&buffers->tbs_mtx);

		if (--buffers->tbs_ref <= 0) {
			for (i = 0; i < TLM_TAPE_BUFFERS; i++)
				free(buffers->tbs_buffer[i].tb_buffer_data);

		}

		(void) cond_destroy(&buffers->tbs_in_cv);
		(void) cond_destroy(&buffers->tbs_out_cv);
		(void) mutex_unlock(&buffers->tbs_mtx);
		(void) mutex_destroy(&buffers->tbs_mtx);
		free(buffers);
	}
}

/*
 * tlm_buffer_mark_empty
 *
 * Mark a buffer empty and clear its flags. No lock is take here:
 * the buffer should be marked empty before it is released for use
 * by another thread.
 */
void
tlm_buffer_mark_empty(tlm_buffer_t *buf)
{
	if (buf == NULL)
		return;

	buf->tb_full = buf->tb_eof = buf->tb_eot = FALSE;
	buf->tb_errno = 0;
}


/*
 * tlm_buffer_advance_in_idx
 *
 * Advance the input index of the buffers(round-robin) and return pointer
 * to the next buffer in the buffer pool.
 */
tlm_buffer_t *
tlm_buffer_advance_in_idx(tlm_buffers_t *bufs)
{
	if (bufs == NULL)
		return (NULL);

	(void) mutex_lock(&bufs->tbs_mtx);
	if (++bufs->tbs_buffer_in >= TLM_TAPE_BUFFERS)
		bufs->tbs_buffer_in = 0;

	(void) mutex_unlock(&bufs->tbs_mtx);
	return (&bufs->tbs_buffer[bufs->tbs_buffer_in]);
}


/*
 * tlm_buffer_advance_out_idx
 *
 * Advance the output index of the buffers(round-robin) and return pointer
 * to the next buffer in the buffer pool.
 */
tlm_buffer_t *
tlm_buffer_advance_out_idx(tlm_buffers_t *bufs)
{
	if (bufs == NULL)
		return (NULL);

	(void) mutex_lock(&bufs->tbs_mtx);
	if (++bufs->tbs_buffer_out >= TLM_TAPE_BUFFERS)
		bufs->tbs_buffer_out = 0;

	(void) mutex_unlock(&bufs->tbs_mtx);
	return (&bufs->tbs_buffer[bufs->tbs_buffer_out]);
}


/*
 * tlm_buffer_in_buf
 *
 * Return pointer to the next buffer in the buffer pool.
 */
tlm_buffer_t *
tlm_buffer_in_buf(tlm_buffers_t *bufs, int *idx)
{
	tlm_buffer_t *ret;

	if (bufs == NULL)
		return (NULL);

	(void) mutex_lock(&bufs->tbs_mtx);
	ret = &bufs->tbs_buffer[bufs->tbs_buffer_in];
	if (idx)
		*idx = bufs->tbs_buffer_in;
	(void) mutex_unlock(&bufs->tbs_mtx);
	return (ret);
}


/*
 * tlm_buffer_out_buf
 *
 * Return pointer to the next buffer in the buffer pool.
 */
tlm_buffer_t *
tlm_buffer_out_buf(tlm_buffers_t *bufs, int *idx)
{
	tlm_buffer_t *ret;

	if (bufs == NULL)
		return (NULL);

	(void) mutex_lock(&bufs->tbs_mtx);
	ret = &bufs->tbs_buffer[bufs->tbs_buffer_out];
	if (idx)
		*idx = bufs->tbs_buffer_out;
	(void) mutex_unlock(&bufs->tbs_mtx);
	return (ret);
}


/*
 * tlm_buffer_release_in_buf
 *
 * Another buffer is filled. Wake up the consumer if it's waiting for it.
 */
void
tlm_buffer_release_in_buf(tlm_buffers_t *bufs)
{
	(void) mutex_lock(&bufs->tbs_mtx);
	bufs->tbs_flags |= TLM_BUF_IN_READY;
	(void) cond_signal(&bufs->tbs_in_cv);
	(void) mutex_unlock(&bufs->tbs_mtx);
}


/*
 * tlm_buffer_release_out_buf
 *
 * A buffer is used. Wake up the producer to re-fill a buffer if it's waiting
 * for the buffer to be used.
 */
void
tlm_buffer_release_out_buf(tlm_buffers_t *bufs)
{
	(void) mutex_lock(&bufs->tbs_mtx);
	bufs->tbs_flags |= TLM_BUF_OUT_READY;
	(void) cond_signal(&bufs->tbs_out_cv);
	(void) mutex_unlock(&bufs->tbs_mtx);
}

/*
 * tlm_buffer_in_buf_wait
 *
 * Wait for the input buffer to get available.
 */
void
tlm_buffer_in_buf_wait(tlm_buffers_t *bufs)

{
	(void) mutex_lock(&bufs->tbs_mtx);

	while ((bufs->tbs_flags & TLM_BUF_IN_READY) == 0)
		(void) cond_wait(&bufs->tbs_in_cv, &bufs->tbs_mtx);

	bufs->tbs_flags &= ~TLM_BUF_IN_READY;

	(void) mutex_unlock(&bufs->tbs_mtx);
}

/*
 * tlm_buffer_setup_timer
 *
 * Set up the time out value.
 */
static inline void
tlm_buffer_setup_timer(timestruc_t *timo, unsigned milli_timo)
{
	if (milli_timo == 0)
		milli_timo = 1;

	if (milli_timo / 1000)
		timo->tv_sec = (milli_timo / 1000);
	else
		timo->tv_sec = 0;
	timo->tv_nsec = (milli_timo % 1000) * 1000000L;
}


/*
 * tlm_buffer_in_buf_timed_wait
 *
 * Wait for the input buffer to get ready with a time out.
 */
void
tlm_buffer_in_buf_timed_wait(tlm_buffers_t *bufs, unsigned int milli_timo)

{
	timestruc_t timo;

	tlm_buffer_setup_timer(&timo, milli_timo);

	(void) mutex_lock(&bufs->tbs_mtx);

	(void) cond_reltimedwait(&bufs->tbs_in_cv, &bufs->tbs_mtx, &timo);

	/*
	 * TLM_BUF_IN_READY doesn't matter for timedwait but clear
	 * it here so that cond_wait doesn't get the wrong result.
	 */
	bufs->tbs_flags &= ~TLM_BUF_IN_READY;

	(void) mutex_unlock(&bufs->tbs_mtx);
}


/*
 * tlm_buffer_out_buf_timed_wait
 *
 * Wait for the output buffer to get ready with a time out.
 */
void
tlm_buffer_out_buf_timed_wait(tlm_buffers_t *bufs, unsigned int milli_timo)
{
	timestruc_t timo;

	tlm_buffer_setup_timer(&timo, milli_timo);

	(void) mutex_lock(&bufs->tbs_mtx);

	(void) cond_reltimedwait(&bufs->tbs_out_cv, &bufs->tbs_mtx, &timo);

	/*
	 * TLM_BUF_OUT_READY doesn't matter for timedwait but clear
	 * it here so that cond_wait doesn't get the wrong result.
	 */
	bufs->tbs_flags &= ~TLM_BUF_OUT_READY;

	(void) mutex_unlock(&bufs->tbs_mtx);
}


/*
 * tlm_cmd_wait
 *
 * TLM command synchronization typically use by command
 * parent threads to wait for launched threads to initialize.
 */
void
tlm_cmd_wait(tlm_cmd_t *cmd, uint32_t event_type)
{
	(void) mutex_lock(&cmd->tc_mtx);

	while ((cmd->tc_flags & event_type) == 0)
		(void) cond_wait(&cmd->tc_cv, &cmd->tc_mtx);

	cmd->tc_flags &= ~event_type;
	(void) mutex_unlock(&cmd->tc_mtx);
}


/*
 * tlm_cmd_signal
 *
 * TLM command synchronization typically use by launched threads
 * to unleash the parent thread.
 */
void
tlm_cmd_signal(tlm_cmd_t *cmd, uint32_t event_type)
{
	(void) mutex_lock(&cmd->tc_mtx);

	cmd->tc_flags |= event_type;
	(void) cond_signal(&cmd->tc_cv);

	(void) mutex_unlock(&cmd->tc_mtx);
}
