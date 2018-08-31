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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/scsi/generic/mode.h>
#include <sys/disp.h>
#include <sys/byteorder.h>
#include <sys/atomic.h>
#include <sys/sdt.h>
#include <sys/dkio.h>
#include <sys/dkioc_free_util.h>

#include <sys/stmf.h>
#include <sys/lpif.h>
#include <sys/portif.h>
#include <sys/stmf_ioctl.h>
#include <sys/stmf_sbd_ioctl.h>

#include "stmf_sbd.h"
#include "sbd_impl.h"

#define	SCSI2_CONFLICT_FREE_CMDS(cdb)	( \
	/* ----------------------- */                                      \
	/* Refer Both		   */                                      \
	/* SPC-2 (rev 20) Table 10 */                                      \
	/* SPC-3 (rev 23) Table 31 */                                      \
	/* ----------------------- */                                      \
	((cdb[0]) == SCMD_INQUIRY)					|| \
	((cdb[0]) == SCMD_LOG_SENSE_G1)					|| \
	((cdb[0]) == SCMD_RELEASE)					|| \
	((cdb[0]) == SCMD_RELEASE_G1)					|| \
	((cdb[0]) == SCMD_REPORT_LUNS)					|| \
	((cdb[0]) == SCMD_REQUEST_SENSE)				|| \
	/* PREVENT ALLOW MEDIUM REMOVAL with prevent == 0 */               \
	((((cdb[0]) == SCMD_DOORLOCK) && (((cdb[4]) & 0x3) == 0)))	|| \
	/* SERVICE ACTION IN with READ MEDIA SERIAL NUMBER (0x01) */       \
	(((cdb[0]) == SCMD_SVC_ACTION_IN_G5) && (                          \
	    ((cdb[1]) & 0x1F) == 0x01))					|| \
	/* MAINTENANCE IN with service actions REPORT ALIASES (0x0Bh) */   \
	/* REPORT DEVICE IDENTIFIER (0x05)  REPORT PRIORITY (0x0Eh) */     \
	/* REPORT TARGET PORT GROUPS (0x0A) REPORT TIMESTAMP (0x0F) */     \
	(((cdb[0]) == SCMD_MAINTENANCE_IN) && (                            \
	    (((cdb[1]) & 0x1F) == 0x0B) ||                                 \
	    (((cdb[1]) & 0x1F) == 0x05) ||                                 \
	    (((cdb[1]) & 0x1F) == 0x0E) ||                                 \
	    (((cdb[1]) & 0x1F) == 0x0A) ||                                 \
	    (((cdb[1]) & 0x1F) == 0x0F)))				|| \
	/* ----------------------- */                                      \
	/* SBC-3 (rev 17) Table 3  */                                      \
	/* ----------------------- */                                      \
	/* READ CAPACITY(10) */                                            \
	((cdb[0]) == SCMD_READ_CAPACITY)				|| \
	/* READ CAPACITY(16) */                                            \
	(((cdb[0]) == SCMD_SVC_ACTION_IN_G4) && (                          \
	    ((cdb[1]) & 0x1F) == 0x10))					|| \
	/* START STOP UNIT with START bit 0 and POWER CONDITION 0  */      \
	(((cdb[0]) == SCMD_START_STOP) && (                                \
	    (((cdb[4]) & 0xF0) == 0) && (((cdb[4]) & 0x01) == 0))))
/* End of SCSI2_CONFLICT_FREE_CMDS */

stmf_status_t sbd_lu_reset_state(stmf_lu_t *lu);
static void sbd_handle_sync_cache(struct scsi_task *task,
    struct stmf_data_buf *initial_dbuf);
void sbd_handle_read_xfer_completion(struct scsi_task *task,
    sbd_cmd_t *scmd, struct stmf_data_buf *dbuf);
void sbd_handle_short_write_xfer_completion(scsi_task_t *task,
    stmf_data_buf_t *dbuf);
void sbd_handle_short_write_transfers(scsi_task_t *task,
    stmf_data_buf_t *dbuf, uint32_t cdb_xfer_size);
void sbd_handle_mode_select_xfer(scsi_task_t *task, uint8_t *buf,
    uint32_t buflen);
void sbd_handle_mode_select(scsi_task_t *task, stmf_data_buf_t *dbuf);
void sbd_handle_identifying_info(scsi_task_t *task, stmf_data_buf_t *dbuf);

static void sbd_handle_unmap_xfer(scsi_task_t *task, uint8_t *buf,
    uint32_t buflen);
static void sbd_handle_unmap(scsi_task_t *task, stmf_data_buf_t *dbuf);

extern void sbd_pgr_initialize_it(scsi_task_t *, sbd_it_data_t *);
extern int sbd_pgr_reservation_conflict(scsi_task_t *);
extern void sbd_pgr_reset(sbd_lu_t *);
extern void sbd_pgr_remove_it_handle(sbd_lu_t *, sbd_it_data_t *);
extern void sbd_handle_pgr_in_cmd(scsi_task_t *, stmf_data_buf_t *);
extern void sbd_handle_pgr_out_cmd(scsi_task_t *, stmf_data_buf_t *);
extern void sbd_handle_pgr_out_data(scsi_task_t *, stmf_data_buf_t *);
void sbd_do_sgl_write_xfer(struct scsi_task *task, sbd_cmd_t *scmd,
    int first_xfer);
static void sbd_handle_write_same(scsi_task_t *task,
    struct stmf_data_buf *initial_dbuf);
static void sbd_do_write_same_xfer(struct scsi_task *task, sbd_cmd_t *scmd,
    struct stmf_data_buf *dbuf, uint8_t dbuf_reusable);
static void sbd_handle_write_same_xfer_completion(struct scsi_task *task,
    sbd_cmd_t *scmd, struct stmf_data_buf *dbuf, uint8_t dbuf_reusable);
/*
 * IMPORTANT NOTE:
 * =================
 * The whole world here is based on the assumption that everything within
 * a scsi task executes in a single threaded manner, even the aborts.
 * Dont ever change that. There wont be any performance gain but there
 * will be tons of race conditions.
 */

void
sbd_do_read_xfer(struct scsi_task *task, sbd_cmd_t *scmd,
    struct stmf_data_buf *dbuf)
{
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	uint64_t laddr;
	uint32_t len, buflen, iolen;
	int ndx;
	int bufs_to_take;

	/* Lets try not to hog all the buffers the port has. */
	bufs_to_take = ((task->task_max_nbufs > 2) &&
	    (task->task_cmd_xfer_length < (32 * 1024))) ? 2 :
	    task->task_max_nbufs;

	len = scmd->len > dbuf->db_buf_size ? dbuf->db_buf_size : scmd->len;
	laddr = scmd->addr + scmd->current_ro;

	for (buflen = 0, ndx = 0; (buflen < len) &&
	    (ndx < dbuf->db_sglist_length); ndx++) {
		iolen = min(len - buflen, dbuf->db_sglist[ndx].seg_length);
		if (iolen == 0)
			break;
		if (sbd_data_read(sl, task, laddr, (uint64_t)iolen,
		    dbuf->db_sglist[ndx].seg_addr) != STMF_SUCCESS) {
			scmd->flags |= SBD_SCSI_CMD_XFER_FAIL;
			/* Do not need to do xfer anymore, just complete it */
			dbuf->db_data_size = 0;
			dbuf->db_xfer_status = STMF_SUCCESS;
			sbd_handle_read_xfer_completion(task, scmd, dbuf);
			return;
		}
		buflen += iolen;
		laddr += (uint64_t)iolen;
	}
	dbuf->db_relative_offset = scmd->current_ro;
	dbuf->db_data_size = buflen;
	dbuf->db_flags = DB_DIRECTION_TO_RPORT;
	(void) stmf_xfer_data(task, dbuf, 0);
	scmd->len -= buflen;
	scmd->current_ro += buflen;
	if (scmd->len && (scmd->nbufs < bufs_to_take)) {
		uint32_t maxsize, minsize, old_minsize;

		maxsize = (scmd->len > (128*1024)) ? 128*1024 : scmd->len;
		minsize = maxsize >> 2;
		do {
			/*
			 * A bad port implementation can keep on failing the
			 * the request but keep on sending us a false
			 * minsize.
			 */
			old_minsize = minsize;
			dbuf = stmf_alloc_dbuf(task, maxsize, &minsize, 0);
		} while ((dbuf == NULL) && (old_minsize > minsize) &&
		    (minsize >= 512));
		if (dbuf == NULL) {
			return;
		}
		scmd->nbufs++;
		sbd_do_read_xfer(task, scmd, dbuf);
	}
}

/*
 * sbd_zcopy: Bail-out switch for reduced copy path.
 *
 * 0 - read & write off
 * 1 - read & write on
 * 2 - only read on
 * 4 - only write on
 */
int sbd_zcopy = 1;	/* enable zcopy read & write path */
uint32_t sbd_max_xfer_len = 0;		/* Valid if non-zero */
uint32_t sbd_1st_xfer_len = 0;		/* Valid if non-zero */
uint32_t sbd_copy_threshold = 0;		/* Valid if non-zero */

static void
sbd_do_sgl_read_xfer(struct scsi_task *task, sbd_cmd_t *scmd, int first_xfer)
{
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	sbd_zvol_io_t *zvio;
	int ret, final_xfer;
	uint64_t offset;
	uint32_t xfer_len, max_len, first_len;
	stmf_status_t xstat;
	stmf_data_buf_t *dbuf;
	uint_t nblks;
	uint64_t blksize = sl->sl_blksize;
	size_t db_private_sz;
	uintptr_t pad;

	ASSERT(rw_read_held(&sl->sl_access_state_lock));
	ASSERT((sl->sl_flags & SL_MEDIA_LOADED) != 0);

	/*
	 * Calculate the limits on xfer_len to the minimum of :
	 *    - task limit
	 *    - lun limit
	 *    - sbd global limit if set
	 *    - first xfer limit if set
	 *
	 * First, protect against silly over-ride value
	 */
	if (sbd_max_xfer_len && ((sbd_max_xfer_len % DEV_BSIZE) != 0)) {
		cmn_err(CE_WARN, "sbd_max_xfer_len invalid %d, resetting\n",
		    sbd_max_xfer_len);
		sbd_max_xfer_len = 0;
	}
	if (sbd_1st_xfer_len && ((sbd_1st_xfer_len % DEV_BSIZE) != 0)) {
		cmn_err(CE_WARN, "sbd_1st_xfer_len invalid %d, resetting\n",
		    sbd_1st_xfer_len);
		sbd_1st_xfer_len = 0;
	}

	max_len = MIN(task->task_max_xfer_len, sl->sl_max_xfer_len);
	if (sbd_max_xfer_len)
		max_len = MIN(max_len, sbd_max_xfer_len);
	/*
	 * Special case the first xfer if hints are set.
	 */
	if (first_xfer && (sbd_1st_xfer_len || task->task_1st_xfer_len)) {
		/* global over-ride has precedence */
		if (sbd_1st_xfer_len)
			first_len = sbd_1st_xfer_len;
		else
			first_len = task->task_1st_xfer_len;
	} else {
		first_len = 0;
	}

	while (scmd->len && scmd->nbufs < task->task_max_nbufs) {

		xfer_len = MIN(max_len, scmd->len);
		if (first_len) {
			xfer_len = MIN(xfer_len, first_len);
			first_len = 0;
		}
		if (scmd->len == xfer_len) {
			final_xfer = 1;
		} else {
			/*
			 * Attempt to end xfer on a block boundary.
			 * The only way this does not happen is if the
			 * xfer_len is small enough to stay contained
			 * within the same block.
			 */
			uint64_t xfer_offset, xfer_aligned_end;

			final_xfer = 0;
			xfer_offset = scmd->addr + scmd->current_ro;
			xfer_aligned_end =
			    P2ALIGN(xfer_offset+xfer_len, blksize);
			if (xfer_aligned_end > xfer_offset)
				xfer_len = xfer_aligned_end - xfer_offset;
		}
		/*
		 * Allocate object to track the read and reserve
		 * enough space for scatter/gather list.
		 */
		offset = scmd->addr + scmd->current_ro;
		nblks = sbd_zvol_numsegs(sl, offset, xfer_len);

		db_private_sz = sizeof (*zvio) + sizeof (uintptr_t) /* PAD */ +
		    (nblks * sizeof (stmf_sglist_ent_t));
		dbuf = stmf_alloc(STMF_STRUCT_DATA_BUF, db_private_sz,
		    AF_DONTZERO);
		/*
		 * Setup the dbuf
		 *
		 * XXX Framework does not handle variable length sglists
		 * properly, so setup db_lu_private and db_port_private
		 * fields here. db_stmf_private is properly set for
		 * calls to stmf_free.
		 */
		if (dbuf->db_port_private == NULL) {
			/*
			 * XXX Framework assigns space to PP after db_sglist[0]
			 */
			cmn_err(CE_PANIC, "db_port_private == NULL");
		}
		pad = (uintptr_t)&dbuf->db_sglist[nblks];
		dbuf->db_lu_private = (void *)P2ROUNDUP(pad, sizeof (pad));
		dbuf->db_port_private = NULL;
		dbuf->db_buf_size = xfer_len;
		dbuf->db_data_size = xfer_len;
		dbuf->db_relative_offset = scmd->current_ro;
		dbuf->db_sglist_length = (uint16_t)nblks;
		dbuf->db_xfer_status = 0;
		dbuf->db_handle = 0;

		dbuf->db_flags = (DB_DONT_CACHE | DB_DONT_REUSE |
		    DB_DIRECTION_TO_RPORT | DB_LU_DATA_BUF);
		if (final_xfer)
			dbuf->db_flags |= DB_SEND_STATUS_GOOD;

		zvio = dbuf->db_lu_private;
		/* Need absolute offset for zvol access */
		zvio->zvio_offset = offset;
		zvio->zvio_flags = ZVIO_SYNC;

		/*
		 * Accounting for start of read.
		 * Note there is no buffer address for the probe yet.
		 */
		DTRACE_PROBE5(backing__store__read__start, sbd_lu_t *, sl,
		    uint8_t *, NULL, uint64_t, xfer_len,
		    uint64_t, offset, scsi_task_t *, task);

		ret = sbd_zvol_alloc_read_bufs(sl, dbuf);

		DTRACE_PROBE6(backing__store__read__end, sbd_lu_t *, sl,
		    uint8_t *, NULL, uint64_t, xfer_len,
		    uint64_t, offset, int, ret, scsi_task_t *, task);

		if (ret != 0) {
			/*
			 * Read failure from the backend.
			 */
			stmf_free(dbuf);
			if (scmd->nbufs == 0) {
				/* nothing queued, just finish */
				scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_READ_ERROR);
				rw_exit(&sl->sl_access_state_lock);
			} else {
				/* process failure when other dbufs finish */
				scmd->flags |= SBD_SCSI_CMD_XFER_FAIL;
			}
			return;
		}


		/*
		 * Allow PP to do setup
		 */
		xstat = stmf_setup_dbuf(task, dbuf, 0);
		if (xstat != STMF_SUCCESS) {
			/*
			 * This could happen if the driver cannot get the
			 * DDI resources it needs for this request.
			 * If other dbufs are queued, try again when the next
			 * one completes, otherwise give up.
			 */
			sbd_zvol_rele_read_bufs(sl, dbuf);
			stmf_free(dbuf);
			if (scmd->nbufs > 0) {
				/* completion of previous dbuf will retry */
				return;
			}
			/*
			 * Done with this command.
			 */
			scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
			if (first_xfer)
				stmf_scsilib_send_status(task, STATUS_QFULL, 0);
			else
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_READ_ERROR);
			rw_exit(&sl->sl_access_state_lock);
			return;
		}
		/*
		 * dbuf is now queued on task
		 */
		scmd->nbufs++;

		/* XXX leave this in for FW? */
		DTRACE_PROBE4(sbd__xfer, struct scsi_task *, task,
		    struct stmf_data_buf *, dbuf, uint64_t, offset,
		    uint32_t, xfer_len);
		/*
		 * Do not pass STMF_IOF_LU_DONE so that the zvol
		 * state can be released in the completion callback.
		 */
		xstat = stmf_xfer_data(task, dbuf, 0);
		switch (xstat) {
		case STMF_SUCCESS:
			break;
		case STMF_BUSY:
			/*
			 * The dbuf is queued on the task, but unknown
			 * to the PP, thus no completion will occur.
			 */
			sbd_zvol_rele_read_bufs(sl, dbuf);
			stmf_teardown_dbuf(task, dbuf);
			stmf_free(dbuf);
			scmd->nbufs--;
			if (scmd->nbufs > 0) {
				/* completion of previous dbuf will retry */
				return;
			}
			/*
			 * Done with this command.
			 */
			rw_exit(&sl->sl_access_state_lock);
			scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
			if (first_xfer)
				stmf_scsilib_send_status(task, STATUS_QFULL, 0);
			else
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_READ_ERROR);
			return;
		case STMF_ABORTED:
			/*
			 * Completion from task_done will cleanup
			 */
			scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
			return;
		}
		/*
		 * Update the xfer progress.
		 */
		ASSERT(scmd->len >= xfer_len);
		scmd->len -= xfer_len;
		scmd->current_ro += xfer_len;
	}
}

void
sbd_handle_read_xfer_completion(struct scsi_task *task, sbd_cmd_t *scmd,
    struct stmf_data_buf *dbuf)
{
	if (dbuf->db_xfer_status != STMF_SUCCESS) {
		stmf_abort(STMF_QUEUE_TASK_ABORT, task,
		    dbuf->db_xfer_status, NULL);
		return;
	}
	task->task_nbytes_transferred += dbuf->db_data_size;
	if (scmd->len == 0 || scmd->flags & SBD_SCSI_CMD_XFER_FAIL) {
		stmf_free_dbuf(task, dbuf);
		scmd->nbufs--;
		if (scmd->nbufs)
			return;	/* wait for all buffers to complete */
		scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
		if (scmd->flags & SBD_SCSI_CMD_XFER_FAIL)
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_READ_ERROR);
		else
			stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}
	if (dbuf->db_flags & DB_DONT_REUSE) {
		/* allocate new dbuf */
		uint32_t maxsize, minsize, old_minsize;
		stmf_free_dbuf(task, dbuf);

		maxsize = (scmd->len > (128*1024)) ? 128*1024 : scmd->len;
		minsize = maxsize >> 2;
		do {
			old_minsize = minsize;
			dbuf = stmf_alloc_dbuf(task, maxsize, &minsize, 0);
		} while ((dbuf == NULL) && (old_minsize > minsize) &&
		    (minsize >= 512));
		if (dbuf == NULL) {
			scmd->nbufs --;
			if (scmd->nbufs == 0) {
				stmf_abort(STMF_QUEUE_TASK_ABORT, task,
				    STMF_ALLOC_FAILURE, NULL);
			}
			return;
		}
	}
	sbd_do_read_xfer(task, scmd, dbuf);
}

/*
 * This routine must release the DMU resources and free the dbuf
 * in all cases.  If this is the final dbuf of the task, then drop
 * the reader lock on the LU state. If there are no errors and more
 * work to do, then queue more xfer operations.
 */
void
sbd_handle_sgl_read_xfer_completion(struct scsi_task *task, sbd_cmd_t *scmd,
    struct stmf_data_buf *dbuf)
{
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	stmf_status_t xfer_status;
	uint32_t data_size;
	int scmd_err;

	ASSERT(dbuf->db_lu_private);
	ASSERT(scmd->cmd_type == SBD_CMD_SCSI_READ);

	scmd->nbufs--;	/* account for this dbuf */
	/*
	 * Release the DMU resources.
	 */
	sbd_zvol_rele_read_bufs(sl, dbuf);
	/*
	 * Release the dbuf after retrieving needed fields.
	 */
	xfer_status = dbuf->db_xfer_status;
	data_size = dbuf->db_data_size;
	stmf_teardown_dbuf(task, dbuf);
	stmf_free(dbuf);
	/*
	 * Release the state lock if this is the last completion.
	 * If this is the last dbuf on task and all data has been
	 * transferred or an error encountered, then no more dbufs
	 * will be queued.
	 */
	scmd_err = (((scmd->flags & SBD_SCSI_CMD_ACTIVE) == 0) ||
	    (scmd->flags & SBD_SCSI_CMD_XFER_FAIL) ||
	    (xfer_status != STMF_SUCCESS));
	if (scmd->nbufs == 0 && (scmd->len == 0 || scmd_err)) {
		/* all DMU state has been released */
		rw_exit(&sl->sl_access_state_lock);
	}

	/*
	 * If there have been no errors, either complete the task
	 * or issue more data xfer operations.
	 */
	if (!scmd_err) {
		/*
		 * This chunk completed successfully
		 */
		task->task_nbytes_transferred += data_size;
		if (scmd->nbufs == 0 && scmd->len == 0) {
			/*
			 * This command completed successfully
			 *
			 * Status was sent along with data, so no status
			 * completion will occur. Tell stmf we are done.
			 */
			scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
			stmf_task_lu_done(task);
			return;
		}
		/*
		 * Start more xfers
		 */
		sbd_do_sgl_read_xfer(task, scmd, 0);
		return;
	}
	/*
	 * Sort out the failure
	 */
	if (scmd->flags & SBD_SCSI_CMD_ACTIVE) {
		/*
		 * If a previous error occurred, leave the command active
		 * and wait for the last completion to send the status check.
		 */
		if (scmd->flags & SBD_SCSI_CMD_XFER_FAIL) {
			if (scmd->nbufs == 0) {
				scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_READ_ERROR);
			}
			return;
		}
		/*
		 * Must have been a failure on current dbuf
		 */
		ASSERT(xfer_status != STMF_SUCCESS);
		scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
		stmf_abort(STMF_QUEUE_TASK_ABORT, task, xfer_status, NULL);
	}
}

void
sbd_handle_sgl_write_xfer_completion(struct scsi_task *task, sbd_cmd_t *scmd,
    struct stmf_data_buf *dbuf)
{
	sbd_zvol_io_t *zvio = dbuf->db_lu_private;
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	int ret;
	int scmd_err, scmd_xfer_done;
	stmf_status_t xfer_status = dbuf->db_xfer_status;
	uint32_t data_size = dbuf->db_data_size;

	ASSERT(zvio);

	/*
	 * Allow PP to free up resources before releasing the write bufs
	 * as writing to the backend could take some time.
	 */
	stmf_teardown_dbuf(task, dbuf);

	scmd->nbufs--;	/* account for this dbuf */
	/*
	 * All data was queued and this is the last completion,
	 * but there could still be an error.
	 */
	scmd_xfer_done = (scmd->len == 0 && scmd->nbufs == 0);
	scmd_err = (((scmd->flags & SBD_SCSI_CMD_ACTIVE) == 0) ||
	    (scmd->flags & SBD_SCSI_CMD_XFER_FAIL) ||
	    (xfer_status != STMF_SUCCESS));

	DTRACE_PROBE5(backing__store__write__start, sbd_lu_t *, sl,
	    uint8_t *, NULL, uint64_t, data_size,
	    uint64_t, zvio->zvio_offset, scsi_task_t *, task);

	if (scmd_err) {
		/* just return the write buffers */
		sbd_zvol_rele_write_bufs_abort(sl, dbuf);
		ret = 0;
	} else {
		if (scmd_xfer_done)
			zvio->zvio_flags = ZVIO_COMMIT;
		else
			zvio->zvio_flags = 0;
		/* write the data */
		ret = sbd_zvol_rele_write_bufs(sl, dbuf);
	}

	DTRACE_PROBE6(backing__store__write__end, sbd_lu_t *, sl,
	    uint8_t *, NULL, uint64_t, data_size,
	    uint64_t, zvio->zvio_offset, int, ret,  scsi_task_t *, task);

	if (ret != 0) {
		/* update the error flag */
		scmd->flags |= SBD_SCSI_CMD_XFER_FAIL;
		scmd_err = 1;
	}

	/* Release the dbuf */
	stmf_free(dbuf);

	/*
	 * Release the state lock if this is the last completion.
	 * If this is the last dbuf on task and all data has been
	 * transferred or an error encountered, then no more dbufs
	 * will be queued.
	 */
	if (scmd->nbufs == 0 && (scmd->len == 0 || scmd_err)) {
		/* all DMU state has been released */
		rw_exit(&sl->sl_access_state_lock);
	}
	/*
	 * If there have been no errors, either complete the task
	 * or issue more data xfer operations.
	 */
	if (!scmd_err) {
		/* This chunk completed successfully */
		task->task_nbytes_transferred += data_size;
		if (scmd_xfer_done) {
			/* This command completed successfully */
			scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
			if ((scmd->flags & SBD_SCSI_CMD_SYNC_WRITE) &&
			    (sbd_flush_data_cache(sl, 0) != SBD_SUCCESS)) {
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_WRITE_ERROR);
			} else {
				stmf_scsilib_send_status(task, STATUS_GOOD, 0);
			}
			return;
		}
		/*
		 * Start more xfers
		 */
		sbd_do_sgl_write_xfer(task, scmd, 0);
		return;
	}
	/*
	 * Sort out the failure
	 */
	if (scmd->flags & SBD_SCSI_CMD_ACTIVE) {
		if (scmd->flags & SBD_SCSI_CMD_XFER_FAIL) {
			if (scmd->nbufs == 0) {
				scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_WRITE_ERROR);
			}
			/*
			 * Leave the command active until last dbuf completes.
			 */
			return;
		}
		scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
		ASSERT(xfer_status != STMF_SUCCESS);
		stmf_abort(STMF_QUEUE_TASK_ABORT, task, xfer_status, NULL);
	}
}

/*
 * Handle a copy operation using the zvol interface.
 *
 * Similar to the sbd_data_read/write path, except it goes directly through
 * the zvol interfaces. It can pass a port provider sglist in the
 * form of uio which is lost through the vn_rdwr path.
 *
 * Returns:
 *	STMF_SUCCESS - request handled
 *	STMF_FAILURE - request not handled, caller must deal with error
 */
static stmf_status_t
sbd_copy_rdwr(scsi_task_t *task, uint64_t laddr, stmf_data_buf_t *dbuf,
    int cmd, int commit)
{
	sbd_lu_t		*sl = task->task_lu->lu_provider_private;
	struct uio		uio;
	struct iovec		*iov, *tiov, iov1[8];
	uint32_t		len, resid;
	int			ret, i, iovcnt, flags;
	boolean_t		is_read;

	ASSERT(cmd == SBD_CMD_SCSI_READ || cmd == SBD_CMD_SCSI_WRITE);

	is_read = (cmd == SBD_CMD_SCSI_READ) ? B_TRUE : B_FALSE;
	iovcnt = dbuf->db_sglist_length;
	/* use the stack for small iovecs */
	if (iovcnt > 8) {
		iov = kmem_alloc(iovcnt * sizeof (*iov), KM_SLEEP);
	} else {
		iov = &iov1[0];
	}

	/* Convert dbuf sglist to iovec format */
	len = dbuf->db_data_size;
	resid = len;
	tiov = iov;
	for (i = 0; i < iovcnt; i++) {
		tiov->iov_base = (caddr_t)dbuf->db_sglist[i].seg_addr;
		tiov->iov_len = MIN(resid, dbuf->db_sglist[i].seg_length);
		resid -= tiov->iov_len;
		tiov++;
	}
	if (resid != 0) {
		cmn_err(CE_WARN, "inconsistant sglist rem %d", resid);
		if (iov != &iov1[0])
			kmem_free(iov, iovcnt * sizeof (*iov));
		return (STMF_FAILURE);
	}
	/* Setup the uio struct */
	uio.uio_iov = iov;
	uio.uio_iovcnt = iovcnt;
	uio.uio_loffset = laddr;
	uio.uio_segflg = (short)UIO_SYSSPACE;
	uio.uio_resid = (uint64_t)len;
	uio.uio_llimit = RLIM64_INFINITY;

	if (is_read == B_TRUE) {
		uio.uio_fmode = FREAD;
		uio.uio_extflg = UIO_COPY_CACHED;
		DTRACE_PROBE5(backing__store__read__start, sbd_lu_t *, sl,
		    uint8_t *, NULL, uint64_t, len, uint64_t, laddr,
		    scsi_task_t *, task);

		/* Fetch the data */
		ret = sbd_zvol_copy_read(sl, &uio);

		DTRACE_PROBE6(backing__store__read__end, sbd_lu_t *, sl,
		    uint8_t *, NULL, uint64_t, len, uint64_t, laddr, int, ret,
		    scsi_task_t *, task);
	} else {
		uio.uio_fmode = FWRITE;
		uio.uio_extflg = UIO_COPY_DEFAULT;
		DTRACE_PROBE5(backing__store__write__start, sbd_lu_t *, sl,
		    uint8_t *, NULL, uint64_t, len, uint64_t, laddr,
		    scsi_task_t *, task);

		flags = (commit) ? ZVIO_COMMIT : 0;
		/* Write the data */
		ret = sbd_zvol_copy_write(sl, &uio, flags);

		DTRACE_PROBE6(backing__store__write__end, sbd_lu_t *, sl,
		    uint8_t *, NULL, uint64_t, len, uint64_t, laddr, int, ret,
		    scsi_task_t *, task);
	}

	if (iov != &iov1[0])
		kmem_free(iov, iovcnt * sizeof (*iov));
	if (ret != 0) {
		/* Backend I/O error */
		return (STMF_FAILURE);
	}
	return (STMF_SUCCESS);
}

void
sbd_handle_read(struct scsi_task *task, struct stmf_data_buf *initial_dbuf)
{
	uint64_t lba, laddr;
	uint32_t len;
	uint8_t op = task->task_cdb[0];
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	sbd_cmd_t *scmd;
	stmf_data_buf_t *dbuf;
	int fast_path;

	if (op == SCMD_READ) {
		lba = READ_SCSI21(&task->task_cdb[1], uint64_t);
		len = (uint32_t)task->task_cdb[4];

		if (len == 0) {
			len = 256;
		}
	} else if (op == SCMD_READ_G1) {
		lba = READ_SCSI32(&task->task_cdb[2], uint64_t);
		len = READ_SCSI16(&task->task_cdb[7], uint32_t);
	} else if (op == SCMD_READ_G5) {
		lba = READ_SCSI32(&task->task_cdb[2], uint64_t);
		len = READ_SCSI32(&task->task_cdb[6], uint32_t);
	} else if (op == SCMD_READ_G4) {
		lba = READ_SCSI64(&task->task_cdb[2], uint64_t);
		len = READ_SCSI32(&task->task_cdb[10], uint32_t);
	} else {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_OPCODE);
		return;
	}

	laddr = lba << sl->sl_data_blocksize_shift;
	len <<= sl->sl_data_blocksize_shift;

	if ((laddr + (uint64_t)len) > sl->sl_lu_size) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_LBA_OUT_OF_RANGE);
		return;
	}

	task->task_cmd_xfer_length = len;
	if (task->task_additional_flags & TASK_AF_NO_EXPECTED_XFER_LENGTH) {
		task->task_expected_xfer_length = len;
	}

	if (len != task->task_expected_xfer_length) {
		fast_path = 0;
		len = (len > task->task_expected_xfer_length) ?
		    task->task_expected_xfer_length : len;
	} else {
		fast_path = 1;
	}

	if (len == 0) {
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}

	/*
	 * Determine if this read can directly use DMU buffers.
	 */
	if (sbd_zcopy & (2|1) &&		/* Debug switch */
	    initial_dbuf == NULL &&		/* No PP buffer passed in */
	    sl->sl_flags & SL_CALL_ZVOL &&	/* zvol backing store */
	    (task->task_additional_flags &
	    TASK_AF_ACCEPT_LU_DBUF))		/* PP allows it */
	{
		/*
		 * Reduced copy path
		 */
		uint32_t copy_threshold, minsize;
		int ret;

		/*
		 * The sl_access_state_lock will be held shared
		 * for the entire request and released when all
		 * dbufs have completed.
		 */
		rw_enter(&sl->sl_access_state_lock, RW_READER);
		if ((sl->sl_flags & SL_MEDIA_LOADED) == 0) {
			rw_exit(&sl->sl_access_state_lock);
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_READ_ERROR);
			return;
		}

		/*
		 * Check if setup is more expensive than copying the data.
		 *
		 * Use the global over-ride sbd_zcopy_threshold if set.
		 */
		copy_threshold = (sbd_copy_threshold > 0) ?
		    sbd_copy_threshold : task->task_copy_threshold;
		minsize = len;
		if (len < copy_threshold &&
		    (dbuf = stmf_alloc_dbuf(task, len, &minsize, 0)) != 0) {

			ret = sbd_copy_rdwr(task, laddr, dbuf,
			    SBD_CMD_SCSI_READ, 0);
			/* done with the backend */
			rw_exit(&sl->sl_access_state_lock);
			if (ret != 0) {
				/* backend error */
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_READ_ERROR);
			} else {
				/* send along good data */
				dbuf->db_relative_offset = 0;
				dbuf->db_data_size = len;
				dbuf->db_flags = DB_SEND_STATUS_GOOD |
				    DB_DIRECTION_TO_RPORT;
				/* XXX keep for FW? */
				DTRACE_PROBE4(sbd__xfer,
				    struct scsi_task *, task,
				    struct stmf_data_buf *, dbuf,
				    uint64_t, laddr, uint32_t, len);
				(void) stmf_xfer_data(task, dbuf,
				    STMF_IOF_LU_DONE);
			}
			return;
		}

		/* committed to reduced copy */
		if (task->task_lu_private) {
			scmd = (sbd_cmd_t *)task->task_lu_private;
		} else {
			scmd = (sbd_cmd_t *)kmem_alloc(sizeof (sbd_cmd_t),
			    KM_SLEEP);
			task->task_lu_private = scmd;
		}
		/*
		 * Setup scmd to track read progress.
		 */
		scmd->flags = SBD_SCSI_CMD_ACTIVE;
		scmd->cmd_type = SBD_CMD_SCSI_READ;
		scmd->nbufs = 0;
		scmd->addr = laddr;
		scmd->len = len;
		scmd->current_ro = 0;

		/*
		 * Kick-off the read.
		 */
		sbd_do_sgl_read_xfer(task, scmd, 1);
		return;
	}

	if (initial_dbuf == NULL) {
		uint32_t maxsize, minsize, old_minsize;

		maxsize = (len > (128*1024)) ? 128*1024 : len;
		minsize = maxsize >> 2;
		do {
			old_minsize = minsize;
			initial_dbuf = stmf_alloc_dbuf(task, maxsize,
			    &minsize, 0);
		} while ((initial_dbuf == NULL) && (old_minsize > minsize) &&
		    (minsize >= 512));
		if (initial_dbuf == NULL) {
			stmf_scsilib_send_status(task, STATUS_QFULL, 0);
			return;
		}
	}
	dbuf = initial_dbuf;

	if ((dbuf->db_buf_size >= len) && fast_path &&
	    (dbuf->db_sglist_length == 1)) {
		if (sbd_data_read(sl, task, laddr, (uint64_t)len,
		    dbuf->db_sglist[0].seg_addr) == STMF_SUCCESS) {
			dbuf->db_relative_offset = 0;
			dbuf->db_data_size = len;
			dbuf->db_flags = DB_SEND_STATUS_GOOD |
			    DB_DIRECTION_TO_RPORT;
			/* XXX keep for FW? */
			DTRACE_PROBE4(sbd__xfer, struct scsi_task *, task,
			    struct stmf_data_buf *, dbuf,
			    uint64_t, laddr, uint32_t, len);
			(void) stmf_xfer_data(task, dbuf, STMF_IOF_LU_DONE);
		} else {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_READ_ERROR);
		}
		return;
	}

	if (task->task_lu_private) {
		scmd = (sbd_cmd_t *)task->task_lu_private;
	} else {
		scmd = (sbd_cmd_t *)kmem_alloc(sizeof (sbd_cmd_t), KM_SLEEP);
		task->task_lu_private = scmd;
	}
	scmd->flags = SBD_SCSI_CMD_ACTIVE;
	scmd->cmd_type = SBD_CMD_SCSI_READ;
	scmd->nbufs = 1;
	scmd->addr = laddr;
	scmd->len = len;
	scmd->current_ro = 0;

	sbd_do_read_xfer(task, scmd, dbuf);
}

void
sbd_do_write_xfer(struct scsi_task *task, sbd_cmd_t *scmd,
    struct stmf_data_buf *dbuf, uint8_t dbuf_reusable)
{
	uint32_t len;
	int bufs_to_take;

	if (scmd->len == 0) {
		goto DO_WRITE_XFER_DONE;
	}

	/* Lets try not to hog all the buffers the port has. */
	bufs_to_take = ((task->task_max_nbufs > 2) &&
	    (task->task_cmd_xfer_length < (32 * 1024))) ? 2 :
	    task->task_max_nbufs;

	if ((dbuf != NULL) &&
	    ((dbuf->db_flags & DB_DONT_REUSE) || (dbuf_reusable == 0))) {
		/* free current dbuf and allocate a new one */
		stmf_free_dbuf(task, dbuf);
		dbuf = NULL;
	}
	if (scmd->nbufs >= bufs_to_take) {
		goto DO_WRITE_XFER_DONE;
	}
	if (dbuf == NULL) {
		uint32_t maxsize, minsize, old_minsize;

		maxsize = (scmd->len > (128*1024)) ? 128*1024 :
		    scmd->len;
		minsize = maxsize >> 2;
		do {
			old_minsize = minsize;
			dbuf = stmf_alloc_dbuf(task, maxsize, &minsize, 0);
		} while ((dbuf == NULL) && (old_minsize > minsize) &&
		    (minsize >= 512));
		if (dbuf == NULL) {
			if (scmd->nbufs == 0) {
				stmf_abort(STMF_QUEUE_TASK_ABORT, task,
				    STMF_ALLOC_FAILURE, NULL);
			}
			return;
		}
	}

	len = scmd->len > dbuf->db_buf_size ? dbuf->db_buf_size :
	    scmd->len;

	dbuf->db_relative_offset = scmd->current_ro;
	dbuf->db_data_size = len;
	dbuf->db_flags = DB_DIRECTION_FROM_RPORT;
	(void) stmf_xfer_data(task, dbuf, 0);
	scmd->nbufs++; /* outstanding port xfers and bufs used */
	scmd->len -= len;
	scmd->current_ro += len;

	if ((scmd->len != 0) && (scmd->nbufs < bufs_to_take)) {
		sbd_do_write_xfer(task, scmd, NULL, 0);
	}
	return;

DO_WRITE_XFER_DONE:
	if (dbuf != NULL) {
		stmf_free_dbuf(task, dbuf);
	}
}

void
sbd_do_sgl_write_xfer(struct scsi_task *task, sbd_cmd_t *scmd, int first_xfer)
{
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	sbd_zvol_io_t *zvio;
	int ret;
	uint32_t xfer_len, max_len, first_len;
	stmf_status_t xstat;
	stmf_data_buf_t *dbuf;
	uint_t nblks;
	uint64_t blksize = sl->sl_blksize;
	uint64_t offset;
	size_t db_private_sz;
	uintptr_t pad;

	ASSERT(rw_read_held(&sl->sl_access_state_lock));
	ASSERT((sl->sl_flags & SL_MEDIA_LOADED) != 0);

	/*
	 * Calculate the limits on xfer_len to the minimum of :
	 *    - task limit
	 *    - lun limit
	 *    - sbd global limit if set
	 *    - first xfer limit if set
	 *
	 * First, protect against silly over-ride value
	 */
	if (sbd_max_xfer_len && ((sbd_max_xfer_len % DEV_BSIZE) != 0)) {
		cmn_err(CE_WARN, "sbd_max_xfer_len invalid %d, resetting\n",
		    sbd_max_xfer_len);
		sbd_max_xfer_len = 0;
	}
	if (sbd_1st_xfer_len && ((sbd_1st_xfer_len % DEV_BSIZE) != 0)) {
		cmn_err(CE_WARN, "sbd_1st_xfer_len invalid %d, resetting\n",
		    sbd_1st_xfer_len);
		sbd_1st_xfer_len = 0;
	}

	max_len = MIN(task->task_max_xfer_len, sl->sl_max_xfer_len);
	if (sbd_max_xfer_len)
		max_len = MIN(max_len, sbd_max_xfer_len);
	/*
	 * Special case the first xfer if hints are set.
	 */
	if (first_xfer && (sbd_1st_xfer_len || task->task_1st_xfer_len)) {
		/* global over-ride has precedence */
		if (sbd_1st_xfer_len)
			first_len = sbd_1st_xfer_len;
		else
			first_len = task->task_1st_xfer_len;
	} else {
		first_len = 0;
	}


	while (scmd->len && scmd->nbufs < task->task_max_nbufs) {

		xfer_len = MIN(max_len, scmd->len);
		if (first_len) {
			xfer_len = MIN(xfer_len, first_len);
			first_len = 0;
		}
		if (xfer_len < scmd->len) {
			/*
			 * Attempt to end xfer on a block boundary.
			 * The only way this does not happen is if the
			 * xfer_len is small enough to stay contained
			 * within the same block.
			 */
			uint64_t xfer_offset, xfer_aligned_end;

			xfer_offset = scmd->addr + scmd->current_ro;
			xfer_aligned_end =
			    P2ALIGN(xfer_offset+xfer_len, blksize);
			if (xfer_aligned_end > xfer_offset)
				xfer_len = xfer_aligned_end - xfer_offset;
		}
		/*
		 * Allocate object to track the write and reserve
		 * enough space for scatter/gather list.
		 */
		offset = scmd->addr + scmd->current_ro;
		nblks = sbd_zvol_numsegs(sl, offset, xfer_len);
		db_private_sz = sizeof (*zvio) + sizeof (uintptr_t) /* PAD */ +
		    (nblks * sizeof (stmf_sglist_ent_t));
		dbuf = stmf_alloc(STMF_STRUCT_DATA_BUF, db_private_sz,
		    AF_DONTZERO);

		/*
		 * Setup the dbuf
		 *
		 * XXX Framework does not handle variable length sglists
		 * properly, so setup db_lu_private and db_port_private
		 * fields here. db_stmf_private is properly set for
		 * calls to stmf_free.
		 */
		if (dbuf->db_port_private == NULL) {
			/*
			 * XXX Framework assigns space to PP after db_sglist[0]
			 */
			cmn_err(CE_PANIC, "db_port_private == NULL");
		}
		pad = (uintptr_t)&dbuf->db_sglist[nblks];
		dbuf->db_lu_private = (void *)P2ROUNDUP(pad, sizeof (pad));
		dbuf->db_port_private = NULL;
		dbuf->db_buf_size = xfer_len;
		dbuf->db_data_size = xfer_len;
		dbuf->db_relative_offset = scmd->current_ro;
		dbuf->db_sglist_length = (uint16_t)nblks;
		dbuf->db_xfer_status = 0;
		dbuf->db_handle = 0;
		dbuf->db_flags = (DB_DONT_CACHE | DB_DONT_REUSE |
		    DB_DIRECTION_FROM_RPORT | DB_LU_DATA_BUF);

		zvio = dbuf->db_lu_private;
		zvio->zvio_offset = offset;

		/* get the buffers */
		ret = sbd_zvol_alloc_write_bufs(sl, dbuf);
		if (ret != 0) {
			/*
			 * Could not allocate buffers from the backend;
			 * treat it like an IO error.
			 */
			stmf_free(dbuf);
			scmd->flags |= SBD_SCSI_CMD_XFER_FAIL;
			if (scmd->nbufs == 0) {
				/*
				 * Nothing queued, so no completions coming
				 */
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_WRITE_ERROR);
				rw_exit(&sl->sl_access_state_lock);
			}
			/*
			 * Completions of previous buffers will cleanup.
			 */
			return;
		}

		/*
		 * Allow PP to do setup
		 */
		xstat = stmf_setup_dbuf(task, dbuf, 0);
		if (xstat != STMF_SUCCESS) {
			/*
			 * This could happen if the driver cannot get the
			 * DDI resources it needs for this request.
			 * If other dbufs are queued, try again when the next
			 * one completes, otherwise give up.
			 */
			sbd_zvol_rele_write_bufs_abort(sl, dbuf);
			stmf_free(dbuf);
			if (scmd->nbufs > 0) {
				/* completion of previous dbuf will retry */
				return;
			}
			/*
			 * Done with this command.
			 */
			scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
			if (first_xfer)
				stmf_scsilib_send_status(task, STATUS_QFULL, 0);
			else
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_WRITE_ERROR);
			rw_exit(&sl->sl_access_state_lock);
			return;
		}

		/*
		 * dbuf is now queued on task
		 */
		scmd->nbufs++;

		xstat = stmf_xfer_data(task, dbuf, 0);
		switch (xstat) {
		case STMF_SUCCESS:
			break;
		case STMF_BUSY:
			/*
			 * The dbuf is queued on the task, but unknown
			 * to the PP, thus no completion will occur.
			 */
			sbd_zvol_rele_write_bufs_abort(sl, dbuf);
			stmf_teardown_dbuf(task, dbuf);
			stmf_free(dbuf);
			scmd->nbufs--;
			if (scmd->nbufs > 0) {
				/* completion of previous dbuf will retry */
				return;
			}
			/*
			 * Done with this command.
			 */
			scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
			if (first_xfer)
				stmf_scsilib_send_status(task, STATUS_QFULL, 0);
			else
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_WRITE_ERROR);
			rw_exit(&sl->sl_access_state_lock);
			return;
		case STMF_ABORTED:
			/*
			 * Completion code will cleanup.
			 */
			scmd->flags |= SBD_SCSI_CMD_XFER_FAIL;
			return;
		}
		/*
		 * Update the xfer progress.
		 */
		scmd->len -= xfer_len;
		scmd->current_ro += xfer_len;
	}
}

void
sbd_handle_write_xfer_completion(struct scsi_task *task, sbd_cmd_t *scmd,
    struct stmf_data_buf *dbuf, uint8_t dbuf_reusable)
{
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	uint64_t laddr;
	uint32_t buflen, iolen;
	int ndx;

	if (scmd->nbufs > 0) {
		/*
		 * Decrement the count to indicate the port xfer
		 * into the dbuf has completed even though the buf is
		 * still in use here in the LU provider.
		 */
		scmd->nbufs--;
	}

	if (dbuf->db_xfer_status != STMF_SUCCESS) {
		stmf_abort(STMF_QUEUE_TASK_ABORT, task,
		    dbuf->db_xfer_status, NULL);
		return;
	}

	if (scmd->flags & SBD_SCSI_CMD_XFER_FAIL) {
		goto WRITE_XFER_DONE;
	}

	if (scmd->len != 0) {
		/*
		 * Initiate the next port xfer to occur in parallel
		 * with writing this buf.
		 */
		sbd_do_write_xfer(task, scmd, NULL, 0);
	}

	laddr = scmd->addr + dbuf->db_relative_offset;

	/*
	 * If this is going to a zvol, use the direct call to
	 * sbd_zvol_copy_{read,write}. The direct call interface is
	 * restricted to PPs that accept sglists, but that is not required.
	 */
	if (sl->sl_flags & SL_CALL_ZVOL &&
	    (task->task_additional_flags & TASK_AF_ACCEPT_LU_DBUF) &&
	    (sbd_zcopy & (4|1))) {
		int commit;

		commit = (scmd->len == 0 && scmd->nbufs == 0);
		if (sbd_copy_rdwr(task, laddr, dbuf, SBD_CMD_SCSI_WRITE,
		    commit) != STMF_SUCCESS)
			scmd->flags |= SBD_SCSI_CMD_XFER_FAIL;
		buflen = dbuf->db_data_size;
	} else {
		for (buflen = 0, ndx = 0; (buflen < dbuf->db_data_size) &&
		    (ndx < dbuf->db_sglist_length); ndx++) {
			iolen = min(dbuf->db_data_size - buflen,
			    dbuf->db_sglist[ndx].seg_length);
			if (iolen == 0)
				break;
			if (sbd_data_write(sl, task, laddr, (uint64_t)iolen,
			    dbuf->db_sglist[ndx].seg_addr) != STMF_SUCCESS) {
				scmd->flags |= SBD_SCSI_CMD_XFER_FAIL;
				break;
			}
			buflen += iolen;
			laddr += (uint64_t)iolen;
		}
	}
	task->task_nbytes_transferred += buflen;
WRITE_XFER_DONE:
	if (scmd->len == 0 || scmd->flags & SBD_SCSI_CMD_XFER_FAIL) {
		stmf_free_dbuf(task, dbuf);
		if (scmd->nbufs)
			return;	/* wait for all buffers to complete */
		scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
		if (scmd->flags & SBD_SCSI_CMD_XFER_FAIL) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_WRITE_ERROR);
		} else {
			/*
			 * If SYNC_WRITE flag is on then we need to flush
			 * cache before sending status.
			 * Note: this may be a no-op because of how
			 * SL_WRITEBACK_CACHE_DISABLE and
			 * SL_FLUSH_ON_DISABLED_WRITECACHE are set, but not
			 * worth code complexity of checking those in this code
			 * path, SBD_SCSI_CMD_SYNC_WRITE is rarely set.
			 */
			if ((scmd->flags & SBD_SCSI_CMD_SYNC_WRITE) &&
			    (sbd_flush_data_cache(sl, 0) != SBD_SUCCESS)) {
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_WRITE_ERROR);
			} else {
				stmf_scsilib_send_status(task, STATUS_GOOD, 0);
			}
		}
		return;
	}
	sbd_do_write_xfer(task, scmd, dbuf, dbuf_reusable);
}

/*
 * Return true if copy avoidance is beneficial.
 */
static int
sbd_zcopy_write_useful(scsi_task_t *task, uint64_t laddr, uint32_t len,
    uint64_t blksize)
{
	/*
	 * If there is a global copy threshold over-ride, use it.
	 * Otherwise use the PP value with the caveat that at least
	 * 1/2 the data must avoid being copied to be useful.
	 */
	if (sbd_copy_threshold > 0) {
		return (len >= sbd_copy_threshold);
	} else {
		uint64_t no_copy_span;

		/* sub-blocksize writes always copy */
		if (len < task->task_copy_threshold || len < blksize)
			return (0);
		/*
		 * Calculate amount of data that will avoid the copy path.
		 * The calculation is only valid if len >= blksize.
		 */
		no_copy_span = P2ALIGN(laddr+len, blksize) -
		    P2ROUNDUP(laddr, blksize);
		return (no_copy_span >= len/2);
	}
}

void
sbd_handle_write(struct scsi_task *task, struct stmf_data_buf *initial_dbuf)
{
	uint64_t lba, laddr;
	uint32_t len;
	uint8_t op = task->task_cdb[0], do_immediate_data = 0;
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	sbd_cmd_t *scmd;
	stmf_data_buf_t *dbuf;
	uint8_t	sync_wr_flag = 0;

	if (sl->sl_flags & SL_WRITE_PROTECTED) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_WRITE_PROTECTED);
		return;
	}
	if (op == SCMD_WRITE) {
		lba = READ_SCSI21(&task->task_cdb[1], uint64_t);
		len = (uint32_t)task->task_cdb[4];

		if (len == 0) {
			len = 256;
		}
	} else if (op == SCMD_WRITE_G1) {
		lba = READ_SCSI32(&task->task_cdb[2], uint64_t);
		len = READ_SCSI16(&task->task_cdb[7], uint32_t);
	} else if (op == SCMD_WRITE_G5) {
		lba = READ_SCSI32(&task->task_cdb[2], uint64_t);
		len = READ_SCSI32(&task->task_cdb[6], uint32_t);
	} else if (op == SCMD_WRITE_G4) {
		lba = READ_SCSI64(&task->task_cdb[2], uint64_t);
		len = READ_SCSI32(&task->task_cdb[10], uint32_t);
	} else if (op == SCMD_WRITE_VERIFY) {
		lba = READ_SCSI32(&task->task_cdb[2], uint64_t);
		len = READ_SCSI16(&task->task_cdb[7], uint32_t);
		sync_wr_flag = SBD_SCSI_CMD_SYNC_WRITE;
	} else if (op == SCMD_WRITE_VERIFY_G5) {
		lba = READ_SCSI32(&task->task_cdb[2], uint64_t);
		len = READ_SCSI32(&task->task_cdb[6], uint32_t);
		sync_wr_flag = SBD_SCSI_CMD_SYNC_WRITE;
	} else if (op == SCMD_WRITE_VERIFY_G4) {
		lba = READ_SCSI64(&task->task_cdb[2], uint64_t);
		len = READ_SCSI32(&task->task_cdb[10], uint32_t);
		sync_wr_flag = SBD_SCSI_CMD_SYNC_WRITE;
	} else {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_OPCODE);
		return;
	}

	laddr = lba << sl->sl_data_blocksize_shift;
	len <<= sl->sl_data_blocksize_shift;

	if ((laddr + (uint64_t)len) > sl->sl_lu_size) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_LBA_OUT_OF_RANGE);
		return;
	}

	task->task_cmd_xfer_length = len;
	if (task->task_additional_flags & TASK_AF_NO_EXPECTED_XFER_LENGTH) {
		task->task_expected_xfer_length = len;
	}

	len = (len > task->task_expected_xfer_length) ?
	    task->task_expected_xfer_length : len;

	if (len == 0) {
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}

	if (sbd_zcopy & (4|1) &&		/* Debug switch */
	    initial_dbuf == NULL &&		/* No PP buf passed in */
	    sl->sl_flags & SL_CALL_ZVOL &&	/* zvol backing store */
	    (task->task_additional_flags &
	    TASK_AF_ACCEPT_LU_DBUF) &&		/* PP allows it */
	    sbd_zcopy_write_useful(task, laddr, len, sl->sl_blksize)) {

		/*
		 * XXX Note that disallowing initial_dbuf will eliminate
		 * iSCSI from participating. For small writes, that is
		 * probably ok. For large writes, it may be best to just
		 * copy the data from the initial dbuf and use zcopy for
		 * the rest.
		 */
		rw_enter(&sl->sl_access_state_lock, RW_READER);
		if ((sl->sl_flags & SL_MEDIA_LOADED) == 0) {
			rw_exit(&sl->sl_access_state_lock);
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_READ_ERROR);
			return;
		}
		/*
		 * Setup scmd to track the write progress.
		 */
		if (task->task_lu_private) {
			scmd = (sbd_cmd_t *)task->task_lu_private;
		} else {
			scmd = (sbd_cmd_t *)kmem_alloc(sizeof (sbd_cmd_t),
			    KM_SLEEP);
			task->task_lu_private = scmd;
		}
		scmd->flags = SBD_SCSI_CMD_ACTIVE | sync_wr_flag;
		scmd->cmd_type = SBD_CMD_SCSI_WRITE;
		scmd->nbufs = 0;
		scmd->addr = laddr;
		scmd->len = len;
		scmd->current_ro = 0;
		sbd_do_sgl_write_xfer(task, scmd, 1);
		return;
	}

	if ((initial_dbuf != NULL) && (task->task_flags & TF_INITIAL_BURST)) {
		if (initial_dbuf->db_data_size > len) {
			if (initial_dbuf->db_data_size >
			    task->task_expected_xfer_length) {
				/* protocol error */
				stmf_abort(STMF_QUEUE_TASK_ABORT, task,
				    STMF_INVALID_ARG, NULL);
				return;
			}
			initial_dbuf->db_data_size = len;
		}
		do_immediate_data = 1;
	}
	dbuf = initial_dbuf;

	if (task->task_lu_private) {
		scmd = (sbd_cmd_t *)task->task_lu_private;
	} else {
		scmd = (sbd_cmd_t *)kmem_alloc(sizeof (sbd_cmd_t), KM_SLEEP);
		task->task_lu_private = scmd;
	}
	scmd->flags = SBD_SCSI_CMD_ACTIVE | sync_wr_flag;
	scmd->cmd_type = SBD_CMD_SCSI_WRITE;
	scmd->nbufs = 0;
	scmd->addr = laddr;
	scmd->len = len;
	scmd->current_ro = 0;

	if (do_immediate_data) {
		/*
		 * Account for data passed in this write command
		 */
		(void) stmf_xfer_data(task, dbuf, STMF_IOF_STATS_ONLY);
		scmd->len -= dbuf->db_data_size;
		scmd->current_ro += dbuf->db_data_size;
		dbuf->db_xfer_status = STMF_SUCCESS;
		sbd_handle_write_xfer_completion(task, scmd, dbuf, 0);
	} else {
		sbd_do_write_xfer(task, scmd, dbuf, 0);
	}
}

/*
 * Utility routine to handle small non performance data transfers to the
 * initiators. dbuf is an initial data buf (if any), 'p' points to a data
 * buffer which is source of data for transfer, cdb_xfer_size is the
 * transfer size based on CDB, cmd_xfer_size is the actual amount of data
 * which this command would transfer (the size of data pointed to by 'p').
 */
void
sbd_handle_short_read_transfers(scsi_task_t *task, stmf_data_buf_t *dbuf,
    uint8_t *p, uint32_t cdb_xfer_size, uint32_t cmd_xfer_size)
{
	uint32_t bufsize, ndx;
	sbd_cmd_t *scmd;

	cmd_xfer_size = min(cmd_xfer_size, cdb_xfer_size);

	task->task_cmd_xfer_length = cmd_xfer_size;
	if (task->task_additional_flags & TASK_AF_NO_EXPECTED_XFER_LENGTH) {
		task->task_expected_xfer_length = cmd_xfer_size;
	} else {
		cmd_xfer_size = min(cmd_xfer_size,
		    task->task_expected_xfer_length);
	}

	if (cmd_xfer_size == 0) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}
	if (dbuf == NULL) {
		uint32_t minsize = cmd_xfer_size;

		dbuf = stmf_alloc_dbuf(task, cmd_xfer_size, &minsize, 0);
	}
	if (dbuf == NULL) {
		stmf_scsilib_send_status(task, STATUS_QFULL, 0);
		return;
	}

	for (bufsize = 0, ndx = 0; bufsize < cmd_xfer_size; ndx++) {
		uint8_t *d;
		uint32_t s;

		d = dbuf->db_sglist[ndx].seg_addr;
		s = min((cmd_xfer_size - bufsize),
		    dbuf->db_sglist[ndx].seg_length);
		bcopy(p+bufsize, d, s);
		bufsize += s;
	}
	dbuf->db_relative_offset = 0;
	dbuf->db_data_size = cmd_xfer_size;
	dbuf->db_flags = DB_DIRECTION_TO_RPORT;

	if (task->task_lu_private == NULL) {
		task->task_lu_private =
		    kmem_alloc(sizeof (sbd_cmd_t), KM_SLEEP);
	}
	scmd = (sbd_cmd_t *)task->task_lu_private;

	scmd->cmd_type = SBD_CMD_SMALL_READ;
	scmd->flags = SBD_SCSI_CMD_ACTIVE;
	(void) stmf_xfer_data(task, dbuf, 0);
}

void
sbd_handle_short_read_xfer_completion(struct scsi_task *task, sbd_cmd_t *scmd,
    struct stmf_data_buf *dbuf)
{
	if (dbuf->db_xfer_status != STMF_SUCCESS) {
		stmf_abort(STMF_QUEUE_TASK_ABORT, task,
		    dbuf->db_xfer_status, NULL);
		return;
	}
	task->task_nbytes_transferred = dbuf->db_data_size;
	scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
	stmf_scsilib_send_status(task, STATUS_GOOD, 0);
}

void
sbd_handle_short_write_transfers(scsi_task_t *task,
    stmf_data_buf_t *dbuf, uint32_t cdb_xfer_size)
{
	sbd_cmd_t *scmd;

	task->task_cmd_xfer_length = cdb_xfer_size;
	if (task->task_additional_flags & TASK_AF_NO_EXPECTED_XFER_LENGTH) {
		task->task_expected_xfer_length = cdb_xfer_size;
	} else {
		cdb_xfer_size = min(cdb_xfer_size,
		    task->task_expected_xfer_length);
	}

	if (cdb_xfer_size == 0) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}
	if (task->task_lu_private == NULL) {
		task->task_lu_private = kmem_zalloc(sizeof (sbd_cmd_t),
		    KM_SLEEP);
	} else {
		bzero(task->task_lu_private, sizeof (sbd_cmd_t));
	}
	scmd = (sbd_cmd_t *)task->task_lu_private;
	scmd->cmd_type = SBD_CMD_SMALL_WRITE;
	scmd->flags = SBD_SCSI_CMD_ACTIVE;
	scmd->len = cdb_xfer_size;
	if (dbuf == NULL) {
		uint32_t minsize = cdb_xfer_size;

		dbuf = stmf_alloc_dbuf(task, cdb_xfer_size, &minsize, 0);
		if (dbuf == NULL) {
			stmf_abort(STMF_QUEUE_TASK_ABORT, task,
			    STMF_ALLOC_FAILURE, NULL);
			return;
		}
		dbuf->db_data_size = cdb_xfer_size;
		dbuf->db_relative_offset = 0;
		dbuf->db_flags = DB_DIRECTION_FROM_RPORT;
		(void) stmf_xfer_data(task, dbuf, 0);
	} else {
		if (dbuf->db_data_size < cdb_xfer_size) {
			stmf_abort(STMF_QUEUE_TASK_ABORT, task,
			    STMF_ABORTED, NULL);
			return;
		}
		dbuf->db_data_size = cdb_xfer_size;
		sbd_handle_short_write_xfer_completion(task, dbuf);
	}
}

void
sbd_handle_short_write_xfer_completion(scsi_task_t *task,
    stmf_data_buf_t *dbuf)
{
	sbd_cmd_t *scmd;
	stmf_status_t st_ret;
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;

	/*
	 * For now lets assume we will get only one sglist element
	 * for short writes. If that ever changes, we should allocate
	 * a local buffer and copy all the sg elements to one linear space.
	 */
	if ((dbuf->db_xfer_status != STMF_SUCCESS) ||
	    (dbuf->db_sglist_length > 1)) {
		stmf_abort(STMF_QUEUE_TASK_ABORT, task,
		    dbuf->db_xfer_status, NULL);
		return;
	}

	task->task_nbytes_transferred = dbuf->db_data_size;
	scmd = (sbd_cmd_t *)task->task_lu_private;
	scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;

	/* Lets find out who to call */
	switch (task->task_cdb[0]) {
	case SCMD_MODE_SELECT:
	case SCMD_MODE_SELECT_G1:
		if (sl->sl_access_state == SBD_LU_STANDBY) {
			st_ret = stmf_proxy_scsi_cmd(task, dbuf);
			if (st_ret != STMF_SUCCESS) {
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_LU_NO_ACCESS_UNAVAIL);
			}
		} else {
			sbd_handle_mode_select_xfer(task,
			    dbuf->db_sglist[0].seg_addr, dbuf->db_data_size);
		}
		break;
	case SCMD_UNMAP:
		sbd_handle_unmap_xfer(task,
		    dbuf->db_sglist[0].seg_addr, dbuf->db_data_size);
		break;
	case SCMD_PERSISTENT_RESERVE_OUT:
		if (sl->sl_access_state == SBD_LU_STANDBY) {
			st_ret = stmf_proxy_scsi_cmd(task, dbuf);
			if (st_ret != STMF_SUCCESS) {
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_LU_NO_ACCESS_UNAVAIL);
			}
		} else {
			sbd_handle_pgr_out_data(task, dbuf);
		}
		break;
	default:
		/* This should never happen */
		stmf_abort(STMF_QUEUE_TASK_ABORT, task,
		    STMF_ABORTED, NULL);
	}
}

void
sbd_handle_read_capacity(struct scsi_task *task,
    struct stmf_data_buf *initial_dbuf)
{
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	uint32_t cdb_len;
	uint8_t p[32];
	uint64_t s;
	uint16_t blksize;

	s = sl->sl_lu_size >> sl->sl_data_blocksize_shift;
	s--;
	blksize = ((uint16_t)1) << sl->sl_data_blocksize_shift;

	switch (task->task_cdb[0]) {
	case SCMD_READ_CAPACITY:
		if (s & 0xffffffff00000000ull) {
			p[0] = p[1] = p[2] = p[3] = 0xFF;
		} else {
			p[0] = (s >> 24) & 0xff;
			p[1] = (s >> 16) & 0xff;
			p[2] = (s >> 8) & 0xff;
			p[3] = s & 0xff;
		}
		p[4] = 0; p[5] = 0;
		p[6] = (blksize >> 8) & 0xff;
		p[7] = blksize & 0xff;
		sbd_handle_short_read_transfers(task, initial_dbuf, p, 8, 8);
		break;

	case SCMD_SVC_ACTION_IN_G4:
		cdb_len = READ_SCSI32(&task->task_cdb[10], uint32_t);
		bzero(p, 32);
		p[0] = (s >> 56) & 0xff;
		p[1] = (s >> 48) & 0xff;
		p[2] = (s >> 40) & 0xff;
		p[3] = (s >> 32) & 0xff;
		p[4] = (s >> 24) & 0xff;
		p[5] = (s >> 16) & 0xff;
		p[6] = (s >> 8) & 0xff;
		p[7] = s & 0xff;
		p[10] = (blksize >> 8) & 0xff;
		p[11] = blksize & 0xff;
		if (sl->sl_flags & SL_UNMAP_ENABLED) {
			p[14] = 0x80;
		}
		sbd_handle_short_read_transfers(task, initial_dbuf, p,
		    cdb_len, 32);
		break;
	}
}

void
sbd_calc_geometry(uint64_t s, uint16_t blksize, uint8_t *nsectors,
    uint8_t *nheads, uint32_t *ncyl)
{
	if (s < (4ull * 1024ull * 1024ull * 1024ull)) {
		*nsectors = 32;
		*nheads = 8;
	} else {
		*nsectors = 254;
		*nheads = 254;
	}
	*ncyl = s / ((uint64_t)blksize * (uint64_t)(*nsectors) *
	    (uint64_t)(*nheads));
}

void
sbd_handle_mode_sense(struct scsi_task *task,
    struct stmf_data_buf *initial_dbuf, uint8_t *buf)
{
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	uint32_t cmd_size, n;
	uint8_t *cdb;
	uint32_t ncyl;
	uint8_t nsectors, nheads;
	uint8_t page, ctrl, header_size, pc_valid;
	uint16_t nbytes;
	uint8_t *p;
	uint64_t s = sl->sl_lu_size;
	uint32_t dev_spec_param_offset;

	p = buf;	/* buf is assumed to be zeroed out and large enough */
	n = 0;
	cdb = &task->task_cdb[0];
	page = cdb[2] & 0x3F;
	ctrl = (cdb[2] >> 6) & 3;
	cmd_size = (cdb[0] == SCMD_MODE_SENSE) ? cdb[4] :
	    READ_SCSI16(&cdb[7], uint32_t);

	if (cdb[0] == SCMD_MODE_SENSE) {
		header_size = 4;
		dev_spec_param_offset = 2;
	} else {
		header_size = 8;
		dev_spec_param_offset = 3;
	}

	/* Now validate the command */
	if ((cdb[2] == 0) || (page == MODEPAGE_ALLPAGES) || (page == 0x08) ||
	    (page == 0x0A) || (page == 0x03) || (page == 0x04)) {
		pc_valid = 1;
	} else {
		pc_valid = 0;
	}
	if ((cmd_size < header_size) || (pc_valid == 0)) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}

	/* We will update the length in the mode header at the end */

	/* Block dev device specific param in mode param header has wp bit */
	if (sl->sl_flags & SL_WRITE_PROTECTED) {
		p[n + dev_spec_param_offset] = BIT_7;
	}
	n += header_size;
	/* We are not going to return any block descriptor */

	nbytes = ((uint16_t)1) << sl->sl_data_blocksize_shift;
	sbd_calc_geometry(s, nbytes, &nsectors, &nheads, &ncyl);

	if ((page == 0x03) || (page == MODEPAGE_ALLPAGES)) {
		p[n] = 0x03;
		p[n+1] = 0x16;
		if (ctrl != 1) {
			p[n + 11] = nsectors;
			p[n + 12] = nbytes >> 8;
			p[n + 13] = nbytes & 0xff;
			p[n + 20] = 0x80;
		}
		n += 24;
	}
	if ((page == 0x04) || (page == MODEPAGE_ALLPAGES)) {
		p[n] = 0x04;
		p[n + 1] = 0x16;
		if (ctrl != 1) {
			p[n + 2] = ncyl >> 16;
			p[n + 3] = ncyl >> 8;
			p[n + 4] = ncyl & 0xff;
			p[n + 5] = nheads;
			p[n + 20] = 0x15;
			p[n + 21] = 0x18;
		}
		n += 24;
	}
	if ((page == MODEPAGE_CACHING) || (page == MODEPAGE_ALLPAGES)) {
		struct mode_caching *mode_caching_page;

		mode_caching_page = (struct mode_caching *)&p[n];

		mode_caching_page->mode_page.code = MODEPAGE_CACHING;
		mode_caching_page->mode_page.ps = 1; /* A saveable page */
		mode_caching_page->mode_page.length = 0x12;

		switch (ctrl) {
		case (0):
			/* Current */
			if ((sl->sl_flags & SL_WRITEBACK_CACHE_DISABLE) == 0) {
				mode_caching_page->wce = 1;
			}
			break;

		case (1):
			/* Changeable */
			if ((sl->sl_flags &
			    SL_WRITEBACK_CACHE_SET_UNSUPPORTED) == 0) {
				mode_caching_page->wce = 1;
			}
			break;

		default:
			if ((sl->sl_flags &
			    SL_SAVED_WRITE_CACHE_DISABLE) == 0) {
				mode_caching_page->wce = 1;
			}
			break;
		}
		n += (sizeof (struct mode_page) +
		    mode_caching_page->mode_page.length);
	}
	if ((page == MODEPAGE_CTRL_MODE) || (page == MODEPAGE_ALLPAGES)) {
		struct mode_control_scsi3 *mode_control_page;

		mode_control_page = (struct mode_control_scsi3 *)&p[n];

		mode_control_page->mode_page.code = MODEPAGE_CTRL_MODE;
		mode_control_page->mode_page.length =
		    PAGELENGTH_MODE_CONTROL_SCSI3;
		if (ctrl != 1) {
			/* If not looking for changeable values, report this. */
			mode_control_page->que_mod = CTRL_QMOD_UNRESTRICT;
		}
		n += (sizeof (struct mode_page) +
		    mode_control_page->mode_page.length);
	}

	if (cdb[0] == SCMD_MODE_SENSE) {
		if (n > 255) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			return;
		}
		/*
		 * Mode parameter header length doesn't include the number
		 * of bytes in the length field, so adjust the count.
		 * Byte count minus header length field size.
		 */
		buf[0] = (n - 1) & 0xff;
	} else {
		/* Byte count minus header length field size. */
		buf[1] = (n - 2) & 0xff;
		buf[0] = ((n - 2) >> 8) & 0xff;
	}

	sbd_handle_short_read_transfers(task, initial_dbuf, buf,
	    cmd_size, n);
}

void
sbd_handle_mode_select(scsi_task_t *task, stmf_data_buf_t *dbuf)
{
	uint32_t cmd_xfer_len;

	if (task->task_cdb[0] == SCMD_MODE_SELECT) {
		cmd_xfer_len = (uint32_t)task->task_cdb[4];
	} else {
		cmd_xfer_len = READ_SCSI16(&task->task_cdb[7], uint32_t);
	}

	if ((task->task_cdb[1] & 0xFE) != 0x10) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}

	if (cmd_xfer_len == 0) {
		/* zero byte mode selects are allowed */
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}

	sbd_handle_short_write_transfers(task, dbuf, cmd_xfer_len);
}

void
sbd_handle_mode_select_xfer(scsi_task_t *task, uint8_t *buf, uint32_t buflen)
{
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	sbd_it_data_t *it;
	int hdr_len, bd_len;
	sbd_status_t sret;
	int i;

	if (task->task_cdb[0] == SCMD_MODE_SELECT) {
		hdr_len = 4;
	} else {
		hdr_len = 8;
	}

	if (buflen < hdr_len)
		goto mode_sel_param_len_err;

	bd_len = hdr_len == 4 ? buf[3] : READ_SCSI16(&buf[6], int);

	if (buflen < (hdr_len + bd_len + 2))
		goto mode_sel_param_len_err;

	buf += hdr_len + bd_len;
	buflen -= hdr_len + bd_len;

	if ((buf[0] != 8) || (buflen != ((uint32_t)buf[1] + 2))) {
		goto mode_sel_param_len_err;
	}

	if (buf[2] & 0xFB) {
		goto mode_sel_param_field_err;
	}

	for (i = 3; i < (buf[1] + 2); i++) {
		if (buf[i]) {
			goto mode_sel_param_field_err;
		}
	}

	sret = SBD_SUCCESS;

	/* All good. Lets handle the write cache change, if any */
	if (buf[2] & BIT_2) {
		sret = sbd_wcd_set(0, sl);
	} else {
		sret = sbd_wcd_set(1, sl);
	}

	if (sret != SBD_SUCCESS) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_WRITE_ERROR);
		return;
	}

	/* set on the device passed, now set the flags */
	mutex_enter(&sl->sl_lock);
	if (buf[2] & BIT_2) {
		sl->sl_flags &= ~SL_WRITEBACK_CACHE_DISABLE;
	} else {
		sl->sl_flags |= SL_WRITEBACK_CACHE_DISABLE;
	}

	for (it = sl->sl_it_list; it != NULL; it = it->sbd_it_next) {
		if (it == task->task_lu_itl_handle)
			continue;
		it->sbd_it_ua_conditions |= SBD_UA_MODE_PARAMETERS_CHANGED;
	}

	if (task->task_cdb[1] & 1) {
		if (buf[2] & BIT_2) {
			sl->sl_flags &= ~SL_SAVED_WRITE_CACHE_DISABLE;
		} else {
			sl->sl_flags |= SL_SAVED_WRITE_CACHE_DISABLE;
		}
		mutex_exit(&sl->sl_lock);
		sret = sbd_write_lu_info(sl);
	} else {
		mutex_exit(&sl->sl_lock);
	}
	if (sret == SBD_SUCCESS) {
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
	} else {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_WRITE_ERROR);
	}
	return;

mode_sel_param_len_err:
	stmf_scsilib_send_status(task, STATUS_CHECK,
	    STMF_SAA_PARAM_LIST_LENGTH_ERROR);
	return;
mode_sel_param_field_err:
	stmf_scsilib_send_status(task, STATUS_CHECK,
	    STMF_SAA_INVALID_FIELD_IN_PARAM_LIST);
}

/*
 * Command support added from SPC-4 r24
 * Supports info type 0, 2, 127
 */
void
sbd_handle_identifying_info(struct scsi_task *task,
    stmf_data_buf_t *initial_dbuf)
{
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	uint8_t *cdb;
	uint32_t cmd_size;
	uint32_t param_len;
	uint32_t xfer_size;
	uint8_t info_type;
	uint8_t *buf, *p;

	cdb = &task->task_cdb[0];
	cmd_size = READ_SCSI32(&cdb[6], uint32_t);
	info_type = cdb[10]>>1;

	/* Validate the command */
	if (cmd_size < 4) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}

	p = buf = kmem_zalloc(260, KM_SLEEP);

	switch (info_type) {
		case 0:
			/*
			 * No value is supplied but this info type
			 * is mandatory.
			 */
			xfer_size = 4;
			break;
		case 2:
			mutex_enter(&sl->sl_lock);
			param_len = strlcpy((char *)(p+4), sl->sl_alias, 256);
			mutex_exit(&sl->sl_lock);
			/* text info must be null terminated */
			if (++param_len > 256)
				param_len = 256;
			SCSI_WRITE16(p+2, param_len);
			xfer_size = param_len + 4;
			break;
		case 127:
			/* 0 and 2 descriptor supported */
			SCSI_WRITE16(p+2, 8); /* set param length */
			p += 8;
			*p = 4; /* set type to 2 (7 hi bits) */
			p += 2;
			SCSI_WRITE16(p, 256); /* 256 max length */
			xfer_size = 12;
			break;
		default:
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			kmem_free(buf, 260);
			return;
	}
	sbd_handle_short_read_transfers(task, initial_dbuf, buf,
	    cmd_size, xfer_size);
	kmem_free(buf, 260);
}

/*
 * This function parse through a string, passed to it as a pointer to a string,
 * by adjusting the pointer to the first non-space character and returns
 * the count/length of the first bunch of non-space characters. Multiple
 * Management URLs are stored as a space delimited string in sl_mgmt_url
 * field of sbd_lu_t. This function is used to retrieve one url at a time.
 *
 * i/p : pointer to pointer to a url string
 * o/p : Adjust the pointer to the url to the first non white character
 *       and returns the length of the URL
 */
uint16_t
sbd_parse_mgmt_url(char **url_addr)
{
	uint16_t url_length = 0;
	char *url;
	url = *url_addr;

	while (*url != '\0') {
		if (*url == ' ' || *url == '\t' || *url == '\n') {
			(*url_addr)++;
			url = *url_addr;
		} else {
			break;
		}
	}

	while (*url != '\0') {
		if (*url == ' ' || *url == '\t' ||
		    *url == '\n' || *url == '\0') {
			break;
		}
		url++;
		url_length++;
	}
	return (url_length);
}

/* Try to make this the size of a kmem allocation cache. */
static uint_t sbd_write_same_optimal_chunk = 128 * 1024;

static sbd_status_t
sbd_write_same_data(struct scsi_task *task, sbd_cmd_t *scmd)
{
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	uint64_t addr, len, sz_done;
	uint32_t big_buf_size, xfer_size, off;
	uint8_t *big_buf;
	sbd_status_t ret;

	if (task->task_cdb[0] == SCMD_WRITE_SAME_G1) {
		addr = READ_SCSI32(&task->task_cdb[2], uint64_t);
		len = READ_SCSI16(&task->task_cdb[7], uint64_t);
	} else {
		addr = READ_SCSI64(&task->task_cdb[2], uint64_t);
		len = READ_SCSI32(&task->task_cdb[10], uint64_t);
	}
	addr <<= sl->sl_data_blocksize_shift;
	len <<= sl->sl_data_blocksize_shift;

	/*
	 * Reminders:
	 *    "len" is total size of what we wish to "write same".
	 *
	 *    xfer_size will be scmd->trans_data_len, which is the length
	 *    of the pattern we wish to replicate over "len".  We replicate
	 *    "xfer_size" of pattern over "len".
	 *
	 *    big_buf_size is set to an ideal actual-write size for an output
	 *    operation.  It may be the same as "len".  If it's not, it should
	 *    be an exact multiple of "xfer_size" so we don't get pattern
	 *    breakage until the very end of "len".
	 */
	big_buf_size = len > sbd_write_same_optimal_chunk ?
	    sbd_write_same_optimal_chunk : (uint32_t)len;
	xfer_size = scmd->trans_data_len;

	/*
	 * All transfers should be an integral multiple of the sector size.
	 */
	ASSERT((big_buf_size % xfer_size) == 0);

	/*
	 * Don't sleep for the allocation, and don't make the system
	 * reclaim memory.  Trade higher I/Os if in a low-memory situation.
	 */
	big_buf = kmem_alloc(big_buf_size, KM_NOSLEEP | KM_NORMALPRI);

	if (big_buf == NULL) {
		/*
		 * Just send it in terms of of the transmitted data.  This
		 * will be very slow.
		 */
		DTRACE_PROBE1(write__same__low__memory, uint64_t, big_buf_size);
		big_buf = scmd->trans_data;
		big_buf_size = scmd->trans_data_len;
	} else {
		/*
		 * We already ASSERT()ed big_buf_size is an integral multiple
		 * of xfer_size.
		 */
		for (off = 0; off < big_buf_size; off += xfer_size)
			bcopy(scmd->trans_data, big_buf + off, xfer_size);
	}

	/* Do the actual I/O.  Recycle xfer_size now to be write size. */
	DTRACE_PROBE1(write__same__io__begin, uint64_t, len);
	for (sz_done = 0; sz_done < len; sz_done += (uint64_t)xfer_size) {
		xfer_size = ((big_buf_size + sz_done) <= len) ? big_buf_size :
		    len - sz_done;
		ret = sbd_data_write(sl, task, addr + sz_done,
		    (uint64_t)xfer_size, big_buf);
		if (ret != SBD_SUCCESS)
			break;
	}
	DTRACE_PROBE2(write__same__io__end, uint64_t, len, uint64_t, sz_done);

	if (big_buf != scmd->trans_data)
		kmem_free(big_buf, big_buf_size);

	return (ret);
}

static void
sbd_handle_write_same_xfer_completion(struct scsi_task *task, sbd_cmd_t *scmd,
    struct stmf_data_buf *dbuf, uint8_t dbuf_reusable)
{
	uint64_t laddr;
	uint32_t buflen, iolen;
	int ndx, ret;

	if (dbuf->db_xfer_status != STMF_SUCCESS) {
		stmf_abort(STMF_QUEUE_TASK_ABORT, task,
		    dbuf->db_xfer_status, NULL);
		return;
	}

	if (scmd->flags & SBD_SCSI_CMD_XFER_FAIL) {
		goto write_same_xfer_done;
	}

	if (scmd->len != 0) {
		/*
		 * Initiate the next port xfer to occur in parallel
		 * with writing this buf.
		 */
		sbd_do_write_same_xfer(task, scmd, NULL, 0);
	}

	laddr = dbuf->db_relative_offset;

	for (buflen = 0, ndx = 0; (buflen < dbuf->db_data_size) &&
	    (ndx < dbuf->db_sglist_length); ndx++) {
		iolen = min(dbuf->db_data_size - buflen,
		    dbuf->db_sglist[ndx].seg_length);
		if (iolen == 0)
			break;
		bcopy(dbuf->db_sglist[ndx].seg_addr, &scmd->trans_data[laddr],
		    iolen);
		buflen += iolen;
		laddr += (uint64_t)iolen;
	}
	task->task_nbytes_transferred += buflen;

write_same_xfer_done:
	if (scmd->len == 0 || scmd->flags & SBD_SCSI_CMD_XFER_FAIL) {
		stmf_free_dbuf(task, dbuf);
		scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
		if (scmd->flags & SBD_SCSI_CMD_XFER_FAIL) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_WRITE_ERROR);
		} else {
			ret = sbd_write_same_data(task, scmd);
			if (ret != SBD_SUCCESS) {
				stmf_scsilib_send_status(task, STATUS_CHECK,
				    STMF_SAA_WRITE_ERROR);
			} else {
				stmf_scsilib_send_status(task, STATUS_GOOD, 0);
			}
		}
		/*
		 * Only way we should get here is via handle_write_same(),
		 * and that should make the following assertion always pass.
		 */
		ASSERT((scmd->flags & SBD_SCSI_CMD_TRANS_DATA) &&
		    scmd->trans_data != NULL);
		kmem_free(scmd->trans_data, scmd->trans_data_len);
		scmd->flags &= ~SBD_SCSI_CMD_TRANS_DATA;
		return;
	}
	sbd_do_write_same_xfer(task, scmd, dbuf, dbuf_reusable);
}

static void
sbd_do_write_same_xfer(struct scsi_task *task, sbd_cmd_t *scmd,
    struct stmf_data_buf *dbuf, uint8_t dbuf_reusable)
{
	uint32_t len;

	if (scmd->len == 0) {
		if (dbuf != NULL)
			stmf_free_dbuf(task, dbuf);
		return;
	}

	if ((dbuf != NULL) &&
	    ((dbuf->db_flags & DB_DONT_REUSE) || (dbuf_reusable == 0))) {
		/* free current dbuf and allocate a new one */
		stmf_free_dbuf(task, dbuf);
		dbuf = NULL;
	}
	if (dbuf == NULL) {
		uint32_t maxsize, minsize, old_minsize;

		maxsize = (scmd->len > (128*1024)) ? 128*1024 :
		    scmd->len;
		minsize = maxsize >> 2;
		do {
			old_minsize = minsize;
			dbuf = stmf_alloc_dbuf(task, maxsize, &minsize, 0);
		} while ((dbuf == NULL) && (old_minsize > minsize) &&
		    (minsize >= 512));
		if (dbuf == NULL) {
			if (scmd->nbufs == 0) {
				stmf_abort(STMF_QUEUE_TASK_ABORT, task,
				    STMF_ALLOC_FAILURE, NULL);
			}
			return;
		}
	}

	len = scmd->len > dbuf->db_buf_size ? dbuf->db_buf_size :
	    scmd->len;

	dbuf->db_relative_offset = scmd->current_ro;
	dbuf->db_data_size = len;
	dbuf->db_flags = DB_DIRECTION_FROM_RPORT;
	(void) stmf_xfer_data(task, dbuf, 0);
	scmd->nbufs++; /* outstanding port xfers and bufs used */
	scmd->len -= len;
	scmd->current_ro += len;
}

static void
sbd_handle_write_same(scsi_task_t *task, struct stmf_data_buf *initial_dbuf)
{
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	uint64_t addr, len;
	sbd_cmd_t *scmd;
	stmf_data_buf_t *dbuf;
	uint8_t unmap;
	uint8_t do_immediate_data = 0;

	task->task_cmd_xfer_length = 0;
	if (task->task_additional_flags &
	    TASK_AF_NO_EXPECTED_XFER_LENGTH) {
		task->task_expected_xfer_length = 0;
	}
	if (sl->sl_flags & SL_WRITE_PROTECTED) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_WRITE_PROTECTED);
		return;
	}
	if (task->task_cdb[1] & 0xF7) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}
	unmap = task->task_cdb[1] & 0x08;
	if (unmap && ((sl->sl_flags & SL_UNMAP_ENABLED) == 0)) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}
	if (task->task_cdb[0] == SCMD_WRITE_SAME_G1) {
		addr = READ_SCSI32(&task->task_cdb[2], uint64_t);
		len = READ_SCSI16(&task->task_cdb[7], uint64_t);
	} else {
		addr = READ_SCSI64(&task->task_cdb[2], uint64_t);
		len = READ_SCSI32(&task->task_cdb[10], uint64_t);
	}
	if (len == 0) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}
	addr <<= sl->sl_data_blocksize_shift;
	len <<= sl->sl_data_blocksize_shift;

	/* Check if the command is for the unmap function */
	if (unmap) {
		dkioc_free_list_t *dfl = kmem_zalloc(DFL_SZ(1), KM_SLEEP);

		dfl->dfl_num_exts = 1;
		dfl->dfl_exts[0].dfle_start = addr;
		dfl->dfl_exts[0].dfle_length = len;
		if (sbd_unmap(sl, dfl) != 0) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_LBA_OUT_OF_RANGE);
		} else {
			stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		}
		dfl_free(dfl);
		return;
	}

	/* Write same function */

	task->task_cmd_xfer_length = 1 << sl->sl_data_blocksize_shift;
	if (task->task_additional_flags &
	    TASK_AF_NO_EXPECTED_XFER_LENGTH) {
		task->task_expected_xfer_length = task->task_cmd_xfer_length;
	}
	if ((addr + len) > sl->sl_lu_size) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_LBA_OUT_OF_RANGE);
		return;
	}

	/* For rest of this I/O the transfer length is 1 block */
	len = ((uint64_t)1) << sl->sl_data_blocksize_shift;

	/* Some basic checks */
	if ((len == 0) || (len != task->task_expected_xfer_length)) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}


	if ((initial_dbuf != NULL) && (task->task_flags & TF_INITIAL_BURST)) {
		if (initial_dbuf->db_data_size > len) {
			if (initial_dbuf->db_data_size >
			    task->task_expected_xfer_length) {
				/* protocol error */
				stmf_abort(STMF_QUEUE_TASK_ABORT, task,
				    STMF_INVALID_ARG, NULL);
				return;
			}
			initial_dbuf->db_data_size = (uint32_t)len;
		}
		do_immediate_data = 1;
	}
	dbuf = initial_dbuf;

	if (task->task_lu_private) {
		scmd = (sbd_cmd_t *)task->task_lu_private;
	} else {
		scmd = (sbd_cmd_t *)kmem_alloc(sizeof (sbd_cmd_t), KM_SLEEP);
		task->task_lu_private = scmd;
	}
	scmd->flags = SBD_SCSI_CMD_ACTIVE | SBD_SCSI_CMD_TRANS_DATA;
	scmd->cmd_type = SBD_CMD_SCSI_WRITE;
	scmd->nbufs = 0;
	scmd->len = (uint32_t)len;
	scmd->trans_data_len = (uint32_t)len;
	scmd->trans_data = kmem_alloc((size_t)len, KM_SLEEP);
	scmd->current_ro = 0;

	if (do_immediate_data) {
		/*
		 * Account for data passed in this write command
		 */
		(void) stmf_xfer_data(task, dbuf, STMF_IOF_STATS_ONLY);
		scmd->len -= dbuf->db_data_size;
		scmd->current_ro += dbuf->db_data_size;
		dbuf->db_xfer_status = STMF_SUCCESS;
		sbd_handle_write_same_xfer_completion(task, scmd, dbuf, 0);
	} else {
		sbd_do_write_same_xfer(task, scmd, dbuf, 0);
	}
}

static void
sbd_handle_unmap(scsi_task_t *task, stmf_data_buf_t *dbuf)
{
	uint32_t cmd_xfer_len;

	cmd_xfer_len = READ_SCSI16(&task->task_cdb[7], uint32_t);

	if (task->task_cdb[1] & 1) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}

	if (cmd_xfer_len == 0) {
		task->task_cmd_xfer_length = 0;
		if (task->task_additional_flags &
		    TASK_AF_NO_EXPECTED_XFER_LENGTH) {
			task->task_expected_xfer_length = 0;
		}
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}

	sbd_handle_short_write_transfers(task, dbuf, cmd_xfer_len);
}

static void
sbd_handle_unmap_xfer(scsi_task_t *task, uint8_t *buf, uint32_t buflen)
{
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	uint32_t ulen, dlen, num_desc;
	uint64_t addr, len;
	uint8_t *p;
	dkioc_free_list_t *dfl;
	int ret;
	int i;

	if (buflen < 24) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}
	ulen = READ_SCSI16(buf, uint32_t);
	dlen = READ_SCSI16(buf + 2, uint32_t);
	num_desc = dlen >> 4;
	if (((ulen + 2) != buflen) || ((dlen + 8) != buflen) || (dlen & 0xf) ||
	    (num_desc == 0)) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}

	dfl = kmem_zalloc(DFL_SZ(num_desc), KM_SLEEP);
	dfl->dfl_num_exts = num_desc;
	for (p = buf + 8, i = 0; num_desc; num_desc--, p += 16, i++) {
		addr = READ_SCSI64(p, uint64_t);
		addr <<= sl->sl_data_blocksize_shift;
		len = READ_SCSI32(p+8, uint64_t);
		len <<= sl->sl_data_blocksize_shift;
		/* Prepare a list of extents to unmap */
		dfl->dfl_exts[i].dfle_start = addr;
		dfl->dfl_exts[i].dfle_length = len;
	}
	ASSERT(i == dfl->dfl_num_exts);

	/* Finally execute the unmap operations in a single step */
	ret = sbd_unmap(sl, dfl);
	dfl_free(dfl);
	if (ret != 0) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_LBA_OUT_OF_RANGE);
		return;
	}

	stmf_scsilib_send_status(task, STATUS_GOOD, 0);
}

void
sbd_handle_inquiry(struct scsi_task *task, struct stmf_data_buf *initial_dbuf)
{
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	uint8_t *cdbp = (uint8_t *)&task->task_cdb[0];
	uint8_t *p;
	uint8_t byte0;
	uint8_t page_length;
	uint16_t bsize = 512;
	uint16_t cmd_size;
	uint32_t xfer_size = 4;
	uint32_t mgmt_url_size = 0;
	uint8_t exp;
	uint64_t s;
	char *mgmt_url = NULL;


	byte0 = DTYPE_DIRECT;
	/*
	 * Basic protocol checks.
	 */

	if ((((cdbp[1] & 1) == 0) && cdbp[2]) || cdbp[5]) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}

	/*
	 * Zero byte allocation length is not an error.  Just
	 * return success.
	 */

	cmd_size = (((uint16_t)cdbp[3]) << 8) | cdbp[4];

	if (cmd_size == 0) {
		task->task_cmd_xfer_length = 0;
		if (task->task_additional_flags &
		    TASK_AF_NO_EXPECTED_XFER_LENGTH) {
			task->task_expected_xfer_length = 0;
		}
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}

	/*
	 * Standard inquiry
	 */

	if ((cdbp[1] & 1) == 0) {
		int	i;
		struct scsi_inquiry *inq;

		p = (uint8_t *)kmem_zalloc(bsize, KM_SLEEP);
		inq = (struct scsi_inquiry *)p;

		page_length = 69;
		xfer_size = page_length + 5;

		inq->inq_dtype = DTYPE_DIRECT;
		inq->inq_ansi = 5;	/* SPC-3 */
		inq->inq_hisup = 1;
		inq->inq_rdf = 2;	/* Response data format for SPC-3 */
		inq->inq_len = page_length;

		inq->inq_tpgs = TPGS_FAILOVER_IMPLICIT;
		inq->inq_cmdque = 1;

		if (sl->sl_flags & SL_VID_VALID) {
			bcopy(sl->sl_vendor_id, inq->inq_vid, 8);
		} else {
			bcopy(sbd_vendor_id, inq->inq_vid, 8);
		}

		if (sl->sl_flags & SL_PID_VALID) {
			bcopy(sl->sl_product_id, inq->inq_pid, 16);
		} else {
			bcopy(sbd_product_id, inq->inq_pid, 16);
		}

		if (sl->sl_flags & SL_REV_VALID) {
			bcopy(sl->sl_revision, inq->inq_revision, 4);
		} else {
			bcopy(sbd_revision, inq->inq_revision, 4);
		}

		/* Adding Version Descriptors */
		i = 0;
		/* SAM-3 no version */
		inq->inq_vd[i].inq_vd_msb = 0x00;
		inq->inq_vd[i].inq_vd_lsb = 0x60;
		i++;

		/* transport */
		switch (task->task_lport->lport_id->protocol_id) {
		case PROTOCOL_FIBRE_CHANNEL:
			inq->inq_vd[i].inq_vd_msb = 0x09;
			inq->inq_vd[i].inq_vd_lsb = 0x00;
			i++;
			break;

		case PROTOCOL_PARALLEL_SCSI:
		case PROTOCOL_SSA:
		case PROTOCOL_IEEE_1394:
			/* Currently no claims of conformance */
			break;

		case PROTOCOL_SRP:
			inq->inq_vd[i].inq_vd_msb = 0x09;
			inq->inq_vd[i].inq_vd_lsb = 0x40;
			i++;
			break;

		case PROTOCOL_iSCSI:
			inq->inq_vd[i].inq_vd_msb = 0x09;
			inq->inq_vd[i].inq_vd_lsb = 0x60;
			i++;
			break;

		case PROTOCOL_SAS:
		case PROTOCOL_ADT:
		case PROTOCOL_ATAPI:
		default:
			/* Currently no claims of conformance */
			break;
		}

		/* SPC-3 no version */
		inq->inq_vd[i].inq_vd_msb = 0x03;
		inq->inq_vd[i].inq_vd_lsb = 0x00;
		i++;

		/* SBC-2 no version */
		inq->inq_vd[i].inq_vd_msb = 0x03;
		inq->inq_vd[i].inq_vd_lsb = 0x20;

		sbd_handle_short_read_transfers(task, initial_dbuf, p, cmd_size,
		    min(cmd_size, xfer_size));
		kmem_free(p, bsize);

		return;
	}

	rw_enter(&sbd_global_prop_lock, RW_READER);
	if (sl->sl_mgmt_url) {
		mgmt_url_size = strlen(sl->sl_mgmt_url);
		mgmt_url = sl->sl_mgmt_url;
	} else if (sbd_mgmt_url) {
		mgmt_url_size = strlen(sbd_mgmt_url);
		mgmt_url = sbd_mgmt_url;
	}

	/*
	 * EVPD handling
	 */

	/* Default 512 bytes may not be enough, increase bsize if necessary */
	if (cdbp[2] == 0x83 || cdbp[2] == 0x85) {
		if (bsize <  cmd_size)
			bsize = cmd_size;
	}
	p = (uint8_t *)kmem_zalloc(bsize, KM_SLEEP);

	switch (cdbp[2]) {
	case 0x00:
		page_length = 4 + (mgmt_url_size ? 1 : 0);
		if (sl->sl_flags & SL_UNMAP_ENABLED)
			page_length += 2;

		p[0] = byte0;
		p[3] = page_length;
		/* Supported VPD pages in ascending order */
		{
			uint8_t i = 5;

			p[i++] = 0x80;
			p[i++] = 0x83;
			if (mgmt_url_size != 0)
				p[i++] = 0x85;
			p[i++] = 0x86;
			if (sl->sl_flags & SL_UNMAP_ENABLED) {
				p[i++] = 0xb0;
				p[i++] = 0xb2;
			}
		}
		xfer_size = page_length + 4;
		break;

	case 0x80:
		if (sl->sl_serial_no_size) {
			page_length = sl->sl_serial_no_size;
			bcopy(sl->sl_serial_no, p + 4, sl->sl_serial_no_size);
		} else {
			/* if no serial num is specified set 4 spaces */
			page_length = 4;
			bcopy("    ", p + 4, 4);
		}
		p[0] = byte0;
		p[1] = 0x80;
		p[3] = page_length;
		xfer_size = page_length + 4;
		break;

	case 0x83:
		xfer_size = stmf_scsilib_prepare_vpd_page83(task, p,
		    bsize, byte0, STMF_VPD_LU_ID|STMF_VPD_TARGET_ID|
		    STMF_VPD_TP_GROUP|STMF_VPD_RELATIVE_TP_ID);
		break;

	case 0x85:
		if (mgmt_url_size == 0) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			goto err_done;
		}
		{
			uint16_t idx, newidx, sz, url_size;
			char *url;

			p[0] = byte0;
			p[1] = 0x85;

			idx = 4;
			url = mgmt_url;
			url_size = sbd_parse_mgmt_url(&url);
			/* Creating Network Service Descriptors */
			while (url_size != 0) {
				/* Null terminated and 4 Byte aligned */
				sz = url_size + 1;
				sz += (sz % 4) ? 4 - (sz % 4) : 0;
				newidx = idx + sz + 4;

				if (newidx < bsize) {
					/*
					 * SPC-3r23 : Table 320  (Sec 7.6.5)
					 * (Network service descriptor format
					 *
					 * Note: Hard coding service type as
					 * "Storage Configuration Service".
					 */
					p[idx] = 1;
					SCSI_WRITE16(p + idx + 2, sz);
					bcopy(url, p + idx + 4, url_size);
					xfer_size = newidx + 4;
				}
				idx = newidx;

				/* skip to next mgmt url if any */
				url += url_size;
				url_size = sbd_parse_mgmt_url(&url);
			}

			/* Total descriptor length */
			SCSI_WRITE16(p + 2, idx - 4);
			break;
		}

	case 0x86:
		page_length = 0x3c;

		p[0] = byte0;
		p[1] = 0x86;		/* Page 86 response */
		p[3] = page_length;

		/*
		 * Bits 0, 1, and 2 will need to be updated
		 * to reflect the queue tag handling if/when
		 * that is implemented.  For now, we're going
		 * to claim support only for Simple TA.
		 */
		p[5] = 1;
		xfer_size = page_length + 4;
		break;

	case 0xb0:
		if ((sl->sl_flags & SL_UNMAP_ENABLED) == 0) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			goto err_done;
		}
		page_length = 0x3c;
		p[0] = byte0;
		p[1] = 0xb0;
		p[3] = page_length;
		p[20] = p[21] = p[22] = p[23] = 0xFF;
		p[24] = p[25] = p[26] = p[27] = 0xFF;
		xfer_size = page_length + 4;
		break;

	case 0xb2:
		if ((sl->sl_flags & SL_UNMAP_ENABLED) == 0) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			goto err_done;
		}
		page_length = 4;
		p[0] = byte0;
		p[1] = 0xb2;
		p[3] = page_length;

		exp = (uint8_t)sl->sl_data_blocksize_shift;
		s = sl->sl_lu_size >> sl->sl_data_blocksize_shift;
		while (s & ((uint64_t)0xFFFFFFFF80000000ull)) {
			s >>= 1;
			exp++;
		}
		p[4] = exp;
		p[5] = 0xc0;
		xfer_size = page_length + 4;
		break;

	default:
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		goto err_done;
	}

	sbd_handle_short_read_transfers(task, initial_dbuf, p, cmd_size,
	    min(cmd_size, xfer_size));
err_done:
	kmem_free(p, bsize);
	rw_exit(&sbd_global_prop_lock);
}

stmf_status_t
sbd_task_alloc(struct scsi_task *task)
{
	if ((task->task_lu_private =
	    kmem_alloc(sizeof (sbd_cmd_t), KM_NOSLEEP)) != NULL) {
		sbd_cmd_t *scmd = (sbd_cmd_t *)task->task_lu_private;
		scmd->flags = 0;
		return (STMF_SUCCESS);
	}
	return (STMF_ALLOC_FAILURE);
}

void
sbd_remove_it_handle(sbd_lu_t *sl, sbd_it_data_t *it)
{
	sbd_it_data_t **ppit;

	sbd_pgr_remove_it_handle(sl, it);
	mutex_enter(&sl->sl_lock);
	for (ppit = &sl->sl_it_list; *ppit != NULL;
	    ppit = &((*ppit)->sbd_it_next)) {
		if ((*ppit) == it) {
			*ppit = it->sbd_it_next;
			break;
		}
	}
	mutex_exit(&sl->sl_lock);

	DTRACE_PROBE2(itl__nexus__end, stmf_lu_t *, sl->sl_lu,
	    sbd_it_data_t *, it);

	kmem_free(it, sizeof (*it));
}

void
sbd_check_and_clear_scsi2_reservation(sbd_lu_t *sl, sbd_it_data_t *it)
{
	mutex_enter(&sl->sl_lock);
	if ((sl->sl_flags & SL_LU_HAS_SCSI2_RESERVATION) == 0) {
		/* If we dont have any reservations, just get out. */
		mutex_exit(&sl->sl_lock);
		return;
	}

	if (it == NULL) {
		/* Find the I_T nexus which is holding the reservation. */
		for (it = sl->sl_it_list; it != NULL; it = it->sbd_it_next) {
			if (it->sbd_it_flags & SBD_IT_HAS_SCSI2_RESERVATION) {
				ASSERT(it->sbd_it_session_id ==
				    sl->sl_rs_owner_session_id);
				break;
			}
		}
		ASSERT(it != NULL);
	} else {
		/*
		 * We were passed an I_T nexus. If this nexus does not hold
		 * the reservation, do nothing. This is why this function is
		 * called "check_and_clear".
		 */
		if ((it->sbd_it_flags & SBD_IT_HAS_SCSI2_RESERVATION) == 0) {
			mutex_exit(&sl->sl_lock);
			return;
		}
	}
	it->sbd_it_flags &= ~SBD_IT_HAS_SCSI2_RESERVATION;
	sl->sl_flags &= ~SL_LU_HAS_SCSI2_RESERVATION;
	mutex_exit(&sl->sl_lock);
}



void
sbd_new_task(struct scsi_task *task, struct stmf_data_buf *initial_dbuf)
{
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	sbd_it_data_t *it;
	uint8_t cdb0, cdb1;
	stmf_status_t st_ret;

	if ((it = task->task_lu_itl_handle) == NULL) {
		mutex_enter(&sl->sl_lock);
		for (it = sl->sl_it_list; it != NULL; it = it->sbd_it_next) {
			if (it->sbd_it_session_id ==
			    task->task_session->ss_session_id) {
				mutex_exit(&sl->sl_lock);
				stmf_scsilib_send_status(task, STATUS_BUSY, 0);
				return;
			}
		}
		it = (sbd_it_data_t *)kmem_zalloc(sizeof (*it), KM_NOSLEEP);
		if (it == NULL) {
			mutex_exit(&sl->sl_lock);
			stmf_scsilib_send_status(task, STATUS_BUSY, 0);
			return;
		}
		it->sbd_it_session_id = task->task_session->ss_session_id;
		bcopy(task->task_lun_no, it->sbd_it_lun, 8);
		it->sbd_it_next = sl->sl_it_list;
		sl->sl_it_list = it;
		mutex_exit(&sl->sl_lock);

		DTRACE_PROBE1(itl__nexus__start, scsi_task *, task);

		sbd_pgr_initialize_it(task, it);
		if (stmf_register_itl_handle(task->task_lu, task->task_lun_no,
		    task->task_session, it->sbd_it_session_id, it)
		    != STMF_SUCCESS) {
			sbd_remove_it_handle(sl, it);
			stmf_scsilib_send_status(task, STATUS_BUSY, 0);
			return;
		}
		task->task_lu_itl_handle = it;
		if (sl->sl_access_state != SBD_LU_STANDBY) {
			it->sbd_it_ua_conditions = SBD_UA_POR;
		}
	} else if (it->sbd_it_flags & SBD_IT_PGR_CHECK_FLAG) {
		mutex_enter(&sl->sl_lock);
		it->sbd_it_flags &= ~SBD_IT_PGR_CHECK_FLAG;
		mutex_exit(&sl->sl_lock);
		sbd_pgr_initialize_it(task, it);
	}

	if (task->task_mgmt_function) {
		stmf_scsilib_handle_task_mgmt(task);
		return;
	}

	/*
	 * if we're transitioning between access
	 * states, return NOT READY
	 */
	if (sl->sl_access_state == SBD_LU_TRANSITION_TO_STANDBY ||
	    sl->sl_access_state == SBD_LU_TRANSITION_TO_ACTIVE) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_LU_NO_ACCESS_UNAVAIL);
		return;
	}

	/* Checking ua conditions as per SAM3R14 5.3.2 specified order */
	if ((it->sbd_it_ua_conditions) && (task->task_cdb[0] != SCMD_INQUIRY)) {
		uint32_t saa = 0;

		mutex_enter(&sl->sl_lock);
		if (it->sbd_it_ua_conditions & SBD_UA_POR) {
			it->sbd_it_ua_conditions &= ~SBD_UA_POR;
			saa = STMF_SAA_POR;
		}
		mutex_exit(&sl->sl_lock);
		if (saa) {
			stmf_scsilib_send_status(task, STATUS_CHECK, saa);
			return;
		}
	}

	/* Reservation conflict checks */
	if (sl->sl_access_state == SBD_LU_ACTIVE) {
		if (SBD_PGR_RSVD(sl->sl_pgr)) {
			if (sbd_pgr_reservation_conflict(task)) {
				stmf_scsilib_send_status(task,
				    STATUS_RESERVATION_CONFLICT, 0);
				return;
			}
		} else if ((sl->sl_flags & SL_LU_HAS_SCSI2_RESERVATION) &&
		    ((it->sbd_it_flags & SBD_IT_HAS_SCSI2_RESERVATION) == 0)) {
			if (!(SCSI2_CONFLICT_FREE_CMDS(task->task_cdb))) {
				stmf_scsilib_send_status(task,
				    STATUS_RESERVATION_CONFLICT, 0);
				return;
			}
		}
	}

	/* Rest of the ua conndition checks */
	if ((it->sbd_it_ua_conditions) && (task->task_cdb[0] != SCMD_INQUIRY)) {
		uint32_t saa = 0;

		mutex_enter(&sl->sl_lock);
		if (it->sbd_it_ua_conditions & SBD_UA_CAPACITY_CHANGED) {
			it->sbd_it_ua_conditions &= ~SBD_UA_CAPACITY_CHANGED;
			if ((task->task_cdb[0] == SCMD_READ_CAPACITY) ||
			    ((task->task_cdb[0] == SCMD_SVC_ACTION_IN_G4) &&
			    (task->task_cdb[1] ==
			    SSVC_ACTION_READ_CAPACITY_G4))) {
				saa = 0;
			} else {
				saa = STMF_SAA_CAPACITY_DATA_HAS_CHANGED;
			}
		} else if (it->sbd_it_ua_conditions &
		    SBD_UA_MODE_PARAMETERS_CHANGED) {
			it->sbd_it_ua_conditions &=
			    ~SBD_UA_MODE_PARAMETERS_CHANGED;
			saa = STMF_SAA_MODE_PARAMETERS_CHANGED;
		} else if (it->sbd_it_ua_conditions &
		    SBD_UA_ASYMMETRIC_ACCESS_CHANGED) {
			it->sbd_it_ua_conditions &=
			    ~SBD_UA_ASYMMETRIC_ACCESS_CHANGED;
			saa = STMF_SAA_ASYMMETRIC_ACCESS_CHANGED;
		} else if (it->sbd_it_ua_conditions &
		    SBD_UA_ACCESS_STATE_TRANSITION) {
			it->sbd_it_ua_conditions &=
			    ~SBD_UA_ACCESS_STATE_TRANSITION;
			saa = STMF_SAA_LU_NO_ACCESS_TRANSITION;
		} else {
			it->sbd_it_ua_conditions = 0;
			saa = 0;
		}
		mutex_exit(&sl->sl_lock);
		if (saa) {
			stmf_scsilib_send_status(task, STATUS_CHECK, saa);
			return;
		}
	}

	cdb0 = task->task_cdb[0];
	cdb1 = task->task_cdb[1];

	if (sl->sl_access_state == SBD_LU_STANDBY) {
		if (cdb0 != SCMD_INQUIRY &&
		    cdb0 != SCMD_MODE_SENSE &&
		    cdb0 != SCMD_MODE_SENSE_G1 &&
		    cdb0 != SCMD_MODE_SELECT &&
		    cdb0 != SCMD_MODE_SELECT_G1 &&
		    cdb0 != SCMD_RESERVE &&
		    cdb0 != SCMD_RELEASE &&
		    cdb0 != SCMD_PERSISTENT_RESERVE_OUT &&
		    cdb0 != SCMD_PERSISTENT_RESERVE_IN &&
		    cdb0 != SCMD_REQUEST_SENSE &&
		    cdb0 != SCMD_READ_CAPACITY &&
		    cdb0 != SCMD_TEST_UNIT_READY &&
		    cdb0 != SCMD_START_STOP &&
		    cdb0 != SCMD_READ &&
		    cdb0 != SCMD_READ_G1 &&
		    cdb0 != SCMD_READ_G4 &&
		    cdb0 != SCMD_READ_G5 &&
		    !(cdb0 == SCMD_SVC_ACTION_IN_G4 &&
		    cdb1 == SSVC_ACTION_READ_CAPACITY_G4) &&
		    !(cdb0 == SCMD_MAINTENANCE_IN &&
		    (cdb1 & 0x1F) == 0x05) &&
		    !(cdb0 == SCMD_MAINTENANCE_IN &&
		    (cdb1 & 0x1F) == 0x0A)) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_LU_NO_ACCESS_STANDBY);
			return;
		}

		/*
		 * is this a short write?
		 * if so, we'll need to wait until we have the buffer
		 * before proxying the command
		 */
		switch (cdb0) {
			case SCMD_MODE_SELECT:
			case SCMD_MODE_SELECT_G1:
			case SCMD_PERSISTENT_RESERVE_OUT:
				break;
			default:
				st_ret = stmf_proxy_scsi_cmd(task,
				    initial_dbuf);
				if (st_ret != STMF_SUCCESS) {
					stmf_scsilib_send_status(task,
					    STATUS_CHECK,
					    STMF_SAA_LU_NO_ACCESS_UNAVAIL);
				}
				return;
		}
	}

	cdb0 = task->task_cdb[0] & 0x1F;

	if ((cdb0 == SCMD_READ) || (cdb0 == SCMD_WRITE)) {
		if (task->task_additional_flags & TASK_AF_PORT_LOAD_HIGH) {
			stmf_scsilib_send_status(task, STATUS_QFULL, 0);
			return;
		}
		if (cdb0 == SCMD_READ) {
			sbd_handle_read(task, initial_dbuf);
			return;
		}
		sbd_handle_write(task, initial_dbuf);
		return;
	}

	cdb0 = task->task_cdb[0];
	cdb1 = task->task_cdb[1];

	if (cdb0 == SCMD_INQUIRY) {		/* Inquiry */
		sbd_handle_inquiry(task, initial_dbuf);
		return;
	}

	if (cdb0  == SCMD_PERSISTENT_RESERVE_OUT) {
		sbd_handle_pgr_out_cmd(task, initial_dbuf);
		return;
	}

	if (cdb0  == SCMD_PERSISTENT_RESERVE_IN) {
		sbd_handle_pgr_in_cmd(task, initial_dbuf);
		return;
	}

	if (cdb0 == SCMD_RELEASE) {
		if (cdb1) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			return;
		}

		mutex_enter(&sl->sl_lock);
		if (sl->sl_flags & SL_LU_HAS_SCSI2_RESERVATION) {
			/* If not owner don't release it, just return good */
			if (it->sbd_it_session_id !=
			    sl->sl_rs_owner_session_id) {
				mutex_exit(&sl->sl_lock);
				stmf_scsilib_send_status(task, STATUS_GOOD, 0);
				return;
			}
		}
		sl->sl_flags &= ~SL_LU_HAS_SCSI2_RESERVATION;
		it->sbd_it_flags &= ~SBD_IT_HAS_SCSI2_RESERVATION;
		mutex_exit(&sl->sl_lock);
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}

	if (cdb0 == SCMD_RESERVE) {
		if (cdb1) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			return;
		}

		mutex_enter(&sl->sl_lock);
		if (sl->sl_flags & SL_LU_HAS_SCSI2_RESERVATION) {
			/* If not owner, return conflict status */
			if (it->sbd_it_session_id !=
			    sl->sl_rs_owner_session_id) {
				mutex_exit(&sl->sl_lock);
				stmf_scsilib_send_status(task,
				    STATUS_RESERVATION_CONFLICT, 0);
				return;
			}
		}
		sl->sl_flags |= SL_LU_HAS_SCSI2_RESERVATION;
		it->sbd_it_flags |= SBD_IT_HAS_SCSI2_RESERVATION;
		sl->sl_rs_owner_session_id = it->sbd_it_session_id;
		mutex_exit(&sl->sl_lock);
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}

	if (cdb0 == SCMD_REQUEST_SENSE) {
		/*
		 * LU provider needs to store unretrieved sense data
		 * (e.g. after power-on/reset).  For now, we'll just
		 * return good status with no sense.
		 */

		if ((cdb1 & ~1) || task->task_cdb[2] || task->task_cdb[3] ||
		    task->task_cdb[5]) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
		} else {
			stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		}

		return;
	}

	/* Report Target Port Groups */
	if ((cdb0 == SCMD_MAINTENANCE_IN) &&
	    ((cdb1 & 0x1F) == 0x0A)) {
		stmf_scsilib_handle_report_tpgs(task, initial_dbuf);
		return;
	}

	/* Report Identifying Information */
	if ((cdb0 == SCMD_MAINTENANCE_IN) &&
	    ((cdb1 & 0x1F) == 0x05)) {
		sbd_handle_identifying_info(task, initial_dbuf);
		return;
	}

	if (cdb0 == SCMD_START_STOP) {			/* Start stop */
		task->task_cmd_xfer_length = 0;
		if (task->task_cdb[4] & 0xFC) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			return;
		}
		if (task->task_cdb[4] & 2) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
		} else {
			stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		}
		return;

	}

	if ((cdb0 == SCMD_MODE_SENSE) || (cdb0 == SCMD_MODE_SENSE_G1)) {
		uint8_t *p;
		p = kmem_zalloc(512, KM_SLEEP);
		sbd_handle_mode_sense(task, initial_dbuf, p);
		kmem_free(p, 512);
		return;
	}

	if ((cdb0 == SCMD_MODE_SELECT) || (cdb0 == SCMD_MODE_SELECT_G1)) {
		sbd_handle_mode_select(task, initial_dbuf);
		return;
	}

	if ((cdb0 == SCMD_UNMAP) && (sl->sl_flags & SL_UNMAP_ENABLED)) {
		sbd_handle_unmap(task, initial_dbuf);
		return;
	}

	if ((cdb0 == SCMD_WRITE_SAME_G4) || (cdb0 == SCMD_WRITE_SAME_G1)) {
		sbd_handle_write_same(task, initial_dbuf);
		return;
	}

	if (cdb0 == SCMD_TEST_UNIT_READY) {	/* Test unit ready */
		task->task_cmd_xfer_length = 0;
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}

	if (cdb0 == SCMD_READ_CAPACITY) {		/* Read Capacity */
		sbd_handle_read_capacity(task, initial_dbuf);
		return;
	}

	if (cdb0 == SCMD_SVC_ACTION_IN_G4) { /* Read Capacity or read long */
		if (cdb1 == SSVC_ACTION_READ_CAPACITY_G4) {
			sbd_handle_read_capacity(task, initial_dbuf);
			return;
		/*
		 * } else if (cdb1 == SSVC_ACTION_READ_LONG_G4) {
		 * 	sbd_handle_read(task, initial_dbuf);
		 * 	return;
		 */
		}
	}

	/*
	 * if (cdb0 == SCMD_SVC_ACTION_OUT_G4) {
	 *	if (cdb1 == SSVC_ACTION_WRITE_LONG_G4) {
	 *		 sbd_handle_write(task, initial_dbuf);
	 * 		return;
	 *	}
	 * }
	 */

	if (cdb0 == SCMD_VERIFY) {
		/*
		 * Something more likely needs to be done here.
		 */
		task->task_cmd_xfer_length = 0;
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}

	if (cdb0 == SCMD_SYNCHRONIZE_CACHE ||
	    cdb0 == SCMD_SYNCHRONIZE_CACHE_G4) {
		sbd_handle_sync_cache(task, initial_dbuf);
		return;
	}

	/*
	 * Write and Verify use the same path as write, but don't clutter the
	 * performance path above with checking for write_verify opcodes.  We
	 * rely on zfs's integrity checks for the "Verify" part of Write &
	 * Verify.  (Even if we did a read to "verify" we'd merely be reading
	 * cache, not actual media.)
	 * Therefore we
	 *   a) only support this if sbd_is_zvol, and
	 *   b) run the IO through the normal write path with a forced
	 *	sbd_flush_data_cache at the end.
	 */

	if ((sl->sl_flags & SL_ZFS_META) && (
	    cdb0 == SCMD_WRITE_VERIFY ||
	    cdb0 == SCMD_WRITE_VERIFY_G4 ||
	    cdb0 == SCMD_WRITE_VERIFY_G5)) {
		sbd_handle_write(task, initial_dbuf);
		return;
	}

	stmf_scsilib_send_status(task, STATUS_CHECK, STMF_SAA_INVALID_OPCODE);
}

void
sbd_dbuf_xfer_done(struct scsi_task *task, struct stmf_data_buf *dbuf)
{
	sbd_cmd_t *scmd = (sbd_cmd_t *)task->task_lu_private;

	if (dbuf->db_flags & DB_LU_DATA_BUF) {
		/*
		 * Buffers passed in from the LU always complete
		 * even if the task is no longer active.
		 */
		ASSERT(task->task_additional_flags & TASK_AF_ACCEPT_LU_DBUF);
		ASSERT(scmd);
		switch (scmd->cmd_type) {
		case (SBD_CMD_SCSI_READ):
			sbd_handle_sgl_read_xfer_completion(task, scmd, dbuf);
			break;
		case (SBD_CMD_SCSI_WRITE):
			sbd_handle_sgl_write_xfer_completion(task, scmd, dbuf);
			break;
		default:
			cmn_err(CE_PANIC, "Unknown cmd type, task = %p",
			    (void *)task);
			break;
		}
		return;
	}

	if ((scmd == NULL) || ((scmd->flags & SBD_SCSI_CMD_ACTIVE) == 0))
		return;

	switch (scmd->cmd_type) {
	case (SBD_CMD_SCSI_READ):
		sbd_handle_read_xfer_completion(task, scmd, dbuf);
		break;

	case (SBD_CMD_SCSI_WRITE):
		if ((task->task_cdb[0] == SCMD_WRITE_SAME_G1) ||
		    (task->task_cdb[0] == SCMD_WRITE_SAME_G4)) {
			sbd_handle_write_same_xfer_completion(task, scmd, dbuf,
			    1);
		} else {
			sbd_handle_write_xfer_completion(task, scmd, dbuf, 1);
		}
		break;

	case (SBD_CMD_SMALL_READ):
		sbd_handle_short_read_xfer_completion(task, scmd, dbuf);
		break;

	case (SBD_CMD_SMALL_WRITE):
		sbd_handle_short_write_xfer_completion(task, dbuf);
		break;

	default:
		cmn_err(CE_PANIC, "Unknown cmd type, task = %p", (void *)task);
		break;
	}
}

/* ARGSUSED */
void
sbd_send_status_done(struct scsi_task *task)
{
	cmn_err(CE_PANIC,
	    "sbd_send_status_done: this should not have been called");
}

void
sbd_task_free(struct scsi_task *task)
{
	if (task->task_lu_private) {
		sbd_cmd_t *scmd = (sbd_cmd_t *)task->task_lu_private;
		if (scmd->flags & SBD_SCSI_CMD_ACTIVE) {
			cmn_err(CE_PANIC, "cmd is active, task = %p",
			    (void *)task);
		}
		kmem_free(scmd, sizeof (sbd_cmd_t));
	}
}

/*
 * Aborts are synchronus w.r.t. I/O AND
 * All the I/O which SBD does is synchronous AND
 * Everything within a task is single threaded.
 *   IT MEANS
 * If this function is called, we are doing nothing with this task
 * inside of sbd module.
 */
/* ARGSUSED */
stmf_status_t
sbd_abort(struct stmf_lu *lu, int abort_cmd, void *arg, uint32_t flags)
{
	sbd_lu_t *sl = (sbd_lu_t *)lu->lu_provider_private;
	scsi_task_t *task;

	if (abort_cmd == STMF_LU_RESET_STATE) {
		return (sbd_lu_reset_state(lu));
	}

	if (abort_cmd == STMF_LU_ITL_HANDLE_REMOVED) {
		sbd_check_and_clear_scsi2_reservation(sl, (sbd_it_data_t *)arg);
		sbd_remove_it_handle(sl, (sbd_it_data_t *)arg);
		return (STMF_SUCCESS);
	}

	ASSERT(abort_cmd == STMF_LU_ABORT_TASK);
	task = (scsi_task_t *)arg;
	if (task->task_lu_private) {
		sbd_cmd_t *scmd = (sbd_cmd_t *)task->task_lu_private;

		if (scmd->flags & SBD_SCSI_CMD_ACTIVE) {
			if (scmd->flags & SBD_SCSI_CMD_TRANS_DATA) {
				kmem_free(scmd->trans_data,
				    scmd->trans_data_len);
				scmd->flags &= ~SBD_SCSI_CMD_TRANS_DATA;
			}
			scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
			return (STMF_ABORT_SUCCESS);
		}
	}

	return (STMF_NOT_FOUND);
}

/*
 * This function is called during task clean-up if the
 * DB_LU_FLAG is set on the dbuf. This should only be called for
 * abort processing after sbd_abort has been called for the task.
 */
void
sbd_dbuf_free(struct scsi_task *task, struct stmf_data_buf *dbuf)
{
	sbd_cmd_t *scmd = (sbd_cmd_t *)task->task_lu_private;
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;

	ASSERT(dbuf->db_lu_private);
	ASSERT(scmd && scmd->nbufs > 0);
	ASSERT((scmd->flags & SBD_SCSI_CMD_ACTIVE) == 0);
	ASSERT(dbuf->db_flags & DB_LU_DATA_BUF);
	ASSERT(task->task_additional_flags & TASK_AF_ACCEPT_LU_DBUF);
	ASSERT((curthread->t_flag & T_INTR_THREAD) == 0);

	if (scmd->cmd_type == SBD_CMD_SCSI_READ) {
		sbd_zvol_rele_read_bufs(sl, dbuf);
	} else if (scmd->cmd_type == SBD_CMD_SCSI_WRITE) {
		sbd_zvol_rele_write_bufs_abort(sl, dbuf);
	} else {
		cmn_err(CE_PANIC, "Unknown cmd type %d, task = %p",
		    scmd->cmd_type, (void *)task);
	}
	if (--scmd->nbufs == 0)
		rw_exit(&sl->sl_access_state_lock);
	stmf_teardown_dbuf(task, dbuf);
	stmf_free(dbuf);
}

/* ARGSUSED */
void
sbd_ctl(struct stmf_lu *lu, int cmd, void *arg)
{
	sbd_lu_t *sl = (sbd_lu_t *)lu->lu_provider_private;
	stmf_change_status_t st;

	ASSERT((cmd == STMF_CMD_LU_ONLINE) ||
	    (cmd == STMF_CMD_LU_OFFLINE) ||
	    (cmd == STMF_ACK_LU_ONLINE_COMPLETE) ||
	    (cmd == STMF_ACK_LU_OFFLINE_COMPLETE));

	st.st_completion_status = STMF_SUCCESS;
	st.st_additional_info = NULL;

	switch (cmd) {
	case STMF_CMD_LU_ONLINE:
		if (sl->sl_state == STMF_STATE_ONLINE)
			st.st_completion_status = STMF_ALREADY;
		else if (sl->sl_state != STMF_STATE_OFFLINE)
			st.st_completion_status = STMF_FAILURE;
		if (st.st_completion_status == STMF_SUCCESS) {
			sl->sl_state = STMF_STATE_ONLINE;
			sl->sl_state_not_acked = 1;
		}
		(void) stmf_ctl(STMF_CMD_LU_ONLINE_COMPLETE, lu, &st);
		break;

	case STMF_CMD_LU_OFFLINE:
		if (sl->sl_state == STMF_STATE_OFFLINE)
			st.st_completion_status = STMF_ALREADY;
		else if (sl->sl_state != STMF_STATE_ONLINE)
			st.st_completion_status = STMF_FAILURE;
		if (st.st_completion_status == STMF_SUCCESS) {
			sl->sl_flags &= ~(SL_MEDIUM_REMOVAL_PREVENTED |
			    SL_LU_HAS_SCSI2_RESERVATION);
			sl->sl_state = STMF_STATE_OFFLINE;
			sl->sl_state_not_acked = 1;
			sbd_pgr_reset(sl);
		}
		(void) stmf_ctl(STMF_CMD_LU_OFFLINE_COMPLETE, lu, &st);
		break;

	case STMF_ACK_LU_ONLINE_COMPLETE:
		/* Fallthrough */
	case STMF_ACK_LU_OFFLINE_COMPLETE:
		sl->sl_state_not_acked = 0;
		break;

	}
}

/* ARGSUSED */
stmf_status_t
sbd_info(uint32_t cmd, stmf_lu_t *lu, void *arg, uint8_t *buf,
    uint32_t *bufsizep)
{
	return (STMF_NOT_SUPPORTED);
}

stmf_status_t
sbd_lu_reset_state(stmf_lu_t *lu)
{
	sbd_lu_t *sl = (sbd_lu_t *)lu->lu_provider_private;

	mutex_enter(&sl->sl_lock);
	if (sl->sl_flags & SL_SAVED_WRITE_CACHE_DISABLE) {
		sl->sl_flags |= SL_WRITEBACK_CACHE_DISABLE;
		mutex_exit(&sl->sl_lock);
		if (sl->sl_access_state == SBD_LU_ACTIVE) {
			(void) sbd_wcd_set(1, sl);
		}
	} else {
		sl->sl_flags &= ~SL_WRITEBACK_CACHE_DISABLE;
		mutex_exit(&sl->sl_lock);
		if (sl->sl_access_state == SBD_LU_ACTIVE) {
			(void) sbd_wcd_set(0, sl);
		}
	}
	sbd_pgr_reset(sl);
	sbd_check_and_clear_scsi2_reservation(sl, NULL);
	if (stmf_deregister_all_lu_itl_handles(lu) != STMF_SUCCESS) {
		return (STMF_FAILURE);
	}
	return (STMF_SUCCESS);
}

sbd_status_t
sbd_flush_data_cache(sbd_lu_t *sl, int fsync_done)
{
	int r = 0;
	int ret;

	if (fsync_done)
		goto over_fsync;
	if ((sl->sl_data_vtype == VREG) || (sl->sl_data_vtype == VBLK)) {
		if (VOP_FSYNC(sl->sl_data_vp, FSYNC, kcred, NULL))
			return (SBD_FAILURE);
	}
over_fsync:
	if (((sl->sl_data_vtype == VCHR) || (sl->sl_data_vtype == VBLK)) &&
	    ((sl->sl_flags & SL_NO_DATA_DKIOFLUSH) == 0)) {
		ret = VOP_IOCTL(sl->sl_data_vp, DKIOCFLUSHWRITECACHE, NULL,
		    FKIOCTL, kcred, &r, NULL);
		if ((ret == ENOTTY) || (ret == ENOTSUP)) {
			mutex_enter(&sl->sl_lock);
			sl->sl_flags |= SL_NO_DATA_DKIOFLUSH;
			mutex_exit(&sl->sl_lock);
		} else if (ret != 0) {
			return (SBD_FAILURE);
		}
	}

	return (SBD_SUCCESS);
}

/* ARGSUSED */
static void
sbd_handle_sync_cache(struct scsi_task *task,
    struct stmf_data_buf *initial_dbuf)
{
	sbd_lu_t *sl = (sbd_lu_t *)task->task_lu->lu_provider_private;
	uint64_t	lba, laddr;
	sbd_status_t	sret;
	uint32_t	len;
	int		is_g4 = 0;
	int		immed;

	task->task_cmd_xfer_length = 0;
	/*
	 * Determine if this is a 10 or 16 byte CDB
	 */

	if (task->task_cdb[0] == SCMD_SYNCHRONIZE_CACHE_G4)
		is_g4 = 1;

	/*
	 * Determine other requested parameters
	 *
	 * We don't have a non-volatile cache, so don't care about SYNC_NV.
	 * Do not support the IMMED bit.
	 */

	immed = (task->task_cdb[1] & 0x02);

	if (immed) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}

	/*
	 * Check to be sure we're not being asked to sync an LBA
	 * that is out of range.  While checking, verify reserved fields.
	 */

	if (is_g4) {
		if ((task->task_cdb[1] & 0xf9) || task->task_cdb[14] ||
		    task->task_cdb[15]) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			return;
		}

		lba = READ_SCSI64(&task->task_cdb[2], uint64_t);
		len = READ_SCSI32(&task->task_cdb[10], uint32_t);
	} else {
		if ((task->task_cdb[1] & 0xf9) || task->task_cdb[6] ||
		    task->task_cdb[9]) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_INVALID_FIELD_IN_CDB);
			return;
		}

		lba = READ_SCSI32(&task->task_cdb[2], uint64_t);
		len = READ_SCSI16(&task->task_cdb[7], uint32_t);
	}

	laddr = lba << sl->sl_data_blocksize_shift;
	len <<= sl->sl_data_blocksize_shift;

	if ((laddr + (uint64_t)len) > sl->sl_lu_size) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_LBA_OUT_OF_RANGE);
		return;
	}

	sret = sbd_flush_data_cache(sl, 0);
	if (sret != SBD_SUCCESS) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_WRITE_ERROR);
		return;
	}

	stmf_scsilib_send_status(task, STATUS_GOOD, 0);
}
