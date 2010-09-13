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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <thread.h>
#include <synch.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>

#include "device.h"
#include "bstream.h"
#include "trackio.h"
#include "util.h"
#include "mmc.h"
#include "transport.h"
#include "misc_scsi.h"
#include "main.h"

/*
 * tio data
 */
static struct iobuf	tio_iobs[NIOBS];
static uchar_t		tio_synch_initialized, tio_abort, tio_done;
static int		tio_errno;
static mutex_t		tio_mutex;
static cond_t		tio_cond;
static int		tio_fd, tio_trackno;
static int		tio_got_ctrl_c;

/*
 * Progress call back data.
 */
static mutex_t	pcb_mutex;
static cond_t	pcb_cond;
static uchar_t	pcb_user_abort, pcb_done, pcb_synch_initialized;
static int64_t	pcb_completed_io_size;
static int	(*pcb_cb)(int64_t, int64_t);
static int64_t	pcb_arg;

static void
fini_tio_data(void)
{
	int i;
	for (i = 0; i < NIOBS; i++) {
		if (tio_iobs[i].iob_buf) {
			free(tio_iobs[i].iob_buf);
			tio_iobs[i].iob_buf = NULL;
		}
	}
	if (tio_synch_initialized == 1) {
		(void) mutex_destroy(&tio_mutex);
		(void) cond_destroy(&tio_cond);
		tio_synch_initialized = 0;
	}
	tio_abort = tio_done = 0;
}

static void
init_tio_data(int bsize)
{
	int i;

	(void) memset(tio_iobs, 0, sizeof (tio_iobs));
	for (i = 0; i < NIOBS; i++) {
		tio_iobs[i].iob_buf = (uchar_t *)my_zalloc(bsize);
		tio_iobs[i].iob_total_size = bsize;
		tio_iobs[i].iob_state = IOBS_EMPTY;
	}
	(void) mutex_init(&tio_mutex, USYNC_THREAD, 0);
	(void) cond_init(&tio_cond, USYNC_THREAD, 0);
	tio_synch_initialized = 1;
	tio_abort = tio_done = 0;
	tio_got_ctrl_c = 0;
}

static void
init_pcb_data(void)
{
	(void) mutex_init(&pcb_mutex, USYNC_THREAD, 0);
	(void) cond_init(&pcb_cond, USYNC_THREAD, 0);
	pcb_user_abort = pcb_done = 0;
	pcb_completed_io_size = 0;
	pcb_synch_initialized = 1;
}

static void
fini_pcb_data(void)
{
	if (pcb_synch_initialized == 1) {
		(void) mutex_destroy(&pcb_mutex);
		(void) cond_destroy(&pcb_cond);
		pcb_synch_initialized = 0;
	}
	pcb_user_abort = pcb_done = 0;
	pcb_completed_io_size = 0;
}

/* ARGSUSED */
static void *
write_to_cd(void *arg)
{
	int i;

	i = 0;
#ifndef lint
	while (1) {
#endif
		(void) mutex_lock(&tio_mutex);
		while ((tio_iobs[i].iob_state != IOBS_READY) &&
		    (tio_abort == 0)) {
			/* Wait for buffer to become ready */
			(void) cond_wait(&tio_cond, &tio_mutex);
		}
		if (tio_abort == 1) {
			/* Do a flush cache before aborting */
			(void) flush_cache(tio_fd);
			(void) mutex_unlock(&tio_mutex);
			thr_exit((void *)1);
		}
		tio_iobs[i].iob_state = IOBS_UNDER_DEVICE_IO;

		/* If no more data, then close the track */
		if (tio_iobs[i].iob_data_size == 0) {
			int retry = 20;

			/* Some drives misbehave if flush_cache is not done */
			(void) flush_cache(tio_fd);

			if (write_mode == TAO_MODE) {
				/* Its important to try hard to close track */
				if (simulation)
					retry = 5;

				for (; retry > 0; retry--) {

					/* OK to hold mutex when close_track */
					if (close_track(tio_fd,
					    tio_trackno, 0, 0))
						break;

					(void) sleep(1);
				}
			}

			/* Some drives don't allow close track in test write */
			if ((retry == 0) && (simulation == 0)) {
				if (errno)
					tio_errno = errno;
				else
					tio_errno = -1;
			}

			tio_done = 1;
			(void) cond_broadcast(&tio_cond);
			(void) mutex_unlock(&tio_mutex);
			thr_exit((void *)0);
		}

		(void) mutex_unlock(&tio_mutex);

		if (!write10(tio_fd, tio_iobs[i].iob_start_blk,
		    tio_iobs[i].iob_nblks, tio_iobs[i].iob_buf,
		    tio_iobs[i].iob_data_size)) {

			int err = errno;
			(void) mutex_lock(&tio_mutex);
			if (err)
				tio_errno = err;
			else
				tio_errno = -1;
			(void) cond_broadcast(&tio_cond);
			(void) mutex_unlock(&tio_mutex);
			thr_exit((void *)2);
		}

		(void) mutex_lock(&tio_mutex);
		tio_iobs[i].iob_state = IOBS_EMPTY;
		(void) cond_broadcast(&tio_cond);
		(void) mutex_unlock(&tio_mutex);
		i++;
		if (i == NIOBS)
			i = 0;
#ifndef lint
	}
#endif
	return (NULL);
}

/* ARGSUSED */
static void *
progress_callback(void *arg)
{
	int ret;

pc_again:
	(void) mutex_lock(&pcb_mutex);
	if (!pcb_done) {
		(void) cond_wait(&pcb_cond, &pcb_mutex);
	}
	if (pcb_done) {
		(void) mutex_unlock(&pcb_mutex);
		if (tio_got_ctrl_c) {
			pcb_cb(pcb_arg, 0xFFFFFFFF);
		}
		thr_exit((void *)0);
	}
	(void) mutex_unlock(&pcb_mutex);
	ret = pcb_cb(pcb_arg, pcb_completed_io_size);
	if (ret != 0) {
		(void) mutex_lock(&pcb_mutex);
		pcb_user_abort = (uchar_t)ret;
		(void) mutex_unlock(&pcb_mutex);
		thr_exit((void *)0);
	}
#ifdef lint
	return (NULL);
#else
	goto pc_again;
#endif
}

/* ARGSUSED */
static void
trackio_sig_handler(int i)
{
	/* Dont need mutex as it is only modified here */
	tio_got_ctrl_c = 1;
	(void) signal(SIGINT, trackio_sig_handler);
}

int
write_track(cd_device *dev, struct track_info *ti, bstreamhandle h,
	int (*cb)(int64_t, int64_t), int64_t arg, struct trackio_error *te)
{
	int			blksize, i, sz_read, rem;
	uint32_t		start_b;
	thread_t		tio_thread, pc_thread;
	int			write_cd_thr_created;
	int			progress_callback_thr_created;
	int			signal_handler_installed;
	int			retval;
	void			(*ohandler)(int);

	write_cd_thr_created = progress_callback_thr_created = 0;
	signal_handler_installed = retval = 0;

	if (ti->ti_track_mode & 4)
		blksize = DATA_TRACK_BLKSIZE;
	else
		blksize = AUDIO_TRACK_BLKSIZE;

	/* Initialize buffers */
	init_tio_data(NBLKS_PER_BUF*blksize);

	/* Fill in all buffers before starting */
	start_b = ti->ti_start_address;

	/*
	 * Start filling initial buffer to ensure that there is plenty of
	 * data when writing begins.
	 */
	for (i = 0; i < NIOBS; i++) {
		sz_read = h->bstr_read(h, tio_iobs[i].iob_buf,
		    tio_iobs[i].iob_total_size);


		/*
		 * We need to read the source file into the buffer and make
		 * sure that the data in the buffer is a multiple of the
		 * blocksize (data or audio blocksize). iob_total_size is a
		 * multiple of the blocksize so this case should only be
		 * encountered at EOF or from piped input.
		 */
		while ((rem = (sz_read % blksize)) != 0) {
			int ret;

			/*
			 * rem contains the amount of data past the previous
			 * block boundry. we need to subtract it from the
			 * blocksize to get the amount needed to reach the
			 * next block boundry.
			 */

			if ((sz_read + (blksize - rem)) >
			    tio_iobs[i].iob_total_size) {

			/*
			 * This should not occur, but we are trying to
			 * write past the end of the buffer. return
			 * with an error.
			 */
				sz_read = -1;
				break;
			}

			/*
			 * Try to continue reading in case the data is being
			 * piped in.
			 */
			ret = h->bstr_read(h, &tio_iobs[i].iob_buf[sz_read],
			    (blksize - rem));

			if (ret < 0) {
				sz_read = ret;
				break;
			}

			/*
			 * No more data. We need to make sure that we are
			 * aligned with the blocksize. so pad the rest of
			 * the buffer with 0s
			 */

			if (ret == 0) {
				ret = blksize - rem;
				(void) memset(&tio_iobs[i].iob_buf[sz_read],
				    0, ret);
			}
			sz_read += ret;
		}

		if (sz_read < 0) {

			/* reading the source failed, clean up and return */
			te->err_type = TRACKIO_ERR_SYSTEM;
			te->te_errno = errno;
			goto write_track_failed;
		}

		tio_iobs[i].iob_start_blk = start_b;
		tio_iobs[i].iob_nblks = (sz_read/blksize);
		start_b += tio_iobs[i].iob_nblks;
		tio_iobs[i].iob_data_size = sz_read;
		tio_iobs[i].iob_state = IOBS_READY;
		if (sz_read == 0)
			break;
	}

	tio_fd = dev->d_fd;
	tio_trackno = ti->ti_track_no;

	/* Install signal handler for CTRL-C */
	ohandler = signal(SIGINT, trackio_sig_handler);
	if (ohandler) {
		signal_handler_installed = 1;
	}

	/* Create thread which will issue commands to write to device */
	if (thr_create(0, 0, write_to_cd, NULL,
	    THR_BOUND | THR_NEW_LWP, &tio_thread) != 0) {
		te->err_type = TRACKIO_ERR_SYSTEM;
		te->te_errno = errno;
		goto write_track_failed;
	}
	write_cd_thr_created = 1;

	/* If caller specified a callback, create a thread to do callbacks */
	if (cb != NULL) {
		init_pcb_data();
		pcb_cb = cb;
		pcb_arg = arg;
		if (thr_create(0, 0, progress_callback, NULL,
		    THR_BOUND | THR_NEW_LWP, &pc_thread) != 0) {
			te->err_type = TRACKIO_ERR_SYSTEM;
			te->te_errno = errno;
			goto write_track_failed;
		}
		progress_callback_thr_created = 1;
	}

	i = 0;
	while (sz_read != 0) {
		(void) mutex_lock(&tio_mutex);
		while ((tio_iobs[i].iob_state != IOBS_EMPTY) &&
		    (tio_errno == 0) && (pcb_user_abort == 0)) {

			/* Do callbacks only if there is nothing else to do */
			if (cb != NULL) {
				(void) mutex_lock(&pcb_mutex);
				(void) cond_broadcast(&pcb_cond);
				(void) mutex_unlock(&pcb_mutex);
			}

			/* If user requested abort, bail out */
			if (pcb_user_abort || tio_got_ctrl_c) {
				break;
			}
			(void) cond_wait(&tio_cond, &tio_mutex);
		}
		if (pcb_user_abort || tio_got_ctrl_c) {
			(void) mutex_unlock(&tio_mutex);
			te->err_type = TRACKIO_ERR_USER_ABORT;
			goto write_track_failed;
		}
		/*
		 * We've got a transport error, stop writing, save all
		 * of the error information and clean up the threads.
		 */
		if (tio_errno != 0) {
			(void) mutex_unlock(&tio_mutex);
			te->err_type = TRACKIO_ERR_TRANSPORT;
			te->te_errno = tio_errno;
			te->status = uscsi_status;
			if (uscsi_status == 2) {
				te->key = SENSE_KEY(rqbuf) & 0xf;
				te->asc = ASC(rqbuf);
				te->ascq = ASCQ(rqbuf);
			}
			goto write_track_failed;
		}
		pcb_completed_io_size += tio_iobs[i].iob_data_size;
		tio_iobs[i].iob_state = IOBS_UNDER_FILE_IO;
		(void) mutex_unlock(&tio_mutex);

		sz_read = h->bstr_read(h, tio_iobs[i].iob_buf,
		    tio_iobs[i].iob_total_size);

		/*
		 * We need to read the source file into the buffer and make
		 * sure that the data in the buffer is a multiple of the
		 * blocksize (data or audio blocksize). this case should only
		 * be encountered at EOF or from piped input.
		 */

		while ((rem = (sz_read % blksize)) != 0) {
			int ret;


			/*
			 * This should not occur, we are trying to write
			 * past the end of the buffer, return error.
			 */

			if ((sz_read + (blksize - rem)) >
			    tio_iobs[i].iob_total_size) {

				sz_read = -1;
				break;
			}

			/*
			 * Try to continue reading in case the data is being
			 * piped in.
			 */

			ret = h->bstr_read(h, &tio_iobs[i].iob_buf[sz_read],
			    (blksize - rem));

			if (ret < 0) {
				sz_read = ret;
				break;
			}

			/*
			 * No more data. We need to make sure that we are
			 * aligned with the blocksize. so pad the rest of
			 * the buffer with 0s
			 */

			if (ret == 0) {
				/*
				 * rem contains the amount of data past the
				 * previous block boundry. we need to subtract
				 * it from the blocksize to get the amount
				 * needed to reach the next block boundry.
				 */
				ret = blksize - rem;
				(void) memset(&tio_iobs[i].iob_buf[sz_read],
				    0, ret);
			}
			sz_read += ret;
		}
		if (sz_read < 0) {
			te->err_type = TRACKIO_ERR_SYSTEM;
			te->te_errno = errno;
			goto write_track_failed;
		}
		(void) mutex_lock(&tio_mutex);
		tio_iobs[i].iob_start_blk = start_b;
		tio_iobs[i].iob_nblks = (sz_read/blksize);
		start_b += tio_iobs[i].iob_nblks;
		tio_iobs[i].iob_data_size = sz_read;
		tio_iobs[i].iob_state = IOBS_READY;
		(void) cond_broadcast(&tio_cond);
		(void) mutex_unlock(&tio_mutex);
		i++;
		if (i == NIOBS)
			i = 0;
	}
	(void) mutex_lock(&tio_mutex);
	while ((tio_errno == 0) && (tio_done == 0)) {

		/* Wait for track IO to complete */
		(void) cond_wait(&tio_cond, &tio_mutex);
		if (tio_errno != 0) {
			te->err_type = TRACKIO_ERR_TRANSPORT;
			te->te_errno = tio_errno;
			te->status = uscsi_status;
			if (uscsi_status == 2) {
				te->key = SENSE_KEY(rqbuf) & 0xf;
				te->asc = ASC(rqbuf);
				te->ascq = ASCQ(rqbuf);
			}
			(void) mutex_unlock(&tio_mutex);
			goto write_track_failed;
		}
		if (cb != NULL) {
			while (tio_iobs[i].iob_state == IOBS_EMPTY) {
				(void) mutex_lock(&pcb_mutex);
				pcb_completed_io_size +=
				    tio_iobs[i].iob_data_size;
				(void) cond_broadcast(&pcb_cond);
				(void) mutex_unlock(&pcb_mutex);
				i++;
				if (i == NIOBS)
					i = 0;
			}
		}
	}
	(void) mutex_unlock(&tio_mutex);
	retval = 1;
write_track_failed:
	if (progress_callback_thr_created) {
		if (thr_kill(pc_thread, 0) == 0) {
			(void) mutex_lock(&pcb_mutex);

			pcb_done = 1;
			(void) cond_broadcast(&pcb_cond);
			(void) mutex_unlock(&pcb_mutex);
			(void) thr_join(pc_thread, NULL, NULL);
		}
	}
	if (write_cd_thr_created) {
		if (thr_kill(tio_thread, 0) == 0) {
			(void) mutex_lock(&tio_mutex);
			tio_abort = 1;
			(void) cond_broadcast(&tio_cond);
			(void) mutex_unlock(&tio_mutex);
			(void) thr_join(tio_thread, NULL, NULL);
		}
	}

	if (signal_handler_installed) {
		(void) signal(SIGINT, ohandler);
	}

	fini_tio_data();
	fini_pcb_data();
	return (retval);
}
