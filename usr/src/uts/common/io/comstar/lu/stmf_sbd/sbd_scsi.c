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

#include <stmf.h>
#include <lpif.h>
#include <portif.h>
#include <stmf_ioctl.h>
#include <stmf_sbd.h>
#include <sbd_impl.h>

stmf_status_t sbd_lu_reset_state(stmf_lu_t *lu);
static void sbd_handle_sync_cache(struct scsi_task *task,
    struct stmf_data_buf *initial_dbuf);
void sbd_handle_read_xfer_completion(struct scsi_task *task,
    sbd_cmd_t *scmd, struct stmf_data_buf *dbuf);

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
	sbd_store_t *sst = (sbd_store_t *)task->task_lu->lu_provider_private;
	sbd_lu_t *slu = (sbd_lu_t *)sst->sst_sbd_private;
	uint64_t laddr;
	uint32_t len, buflen, iolen;
	int ndx;
	int bufs_to_take;

	/* Lets try not to hog all the buffers the port has. */
	bufs_to_take = ((task->task_max_nbufs > 2) &&
	    (task->task_cmd_xfer_length < (32 * 1024))) ? 2 :
	    task->task_max_nbufs;

	len = scmd->len > dbuf->db_buf_size ? dbuf->db_buf_size : scmd->len;
	laddr = scmd->addr + scmd->current_ro + slu->sl_sli->sli_lu_data_offset;

	for (buflen = 0, ndx = 0; (buflen < len) &&
	    (ndx < dbuf->db_sglist_length); ndx++) {
		iolen = min(len - buflen, dbuf->db_sglist[ndx].seg_length);
		if (iolen == 0)
			break;
		if (sst->sst_data_read(sst, laddr, (uint64_t)iolen,
		    dbuf->db_sglist[0].seg_addr) != STMF_SUCCESS) {
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
	sbd_do_read_xfer(task, scmd, dbuf);
}

void
sbd_handle_read(struct scsi_task *task, struct stmf_data_buf *initial_dbuf)
{
	uint64_t lba, laddr;
	uint32_t len;
	uint8_t op = task->task_cdb[0];
	sbd_store_t *sst = (sbd_store_t *)task->task_lu->lu_provider_private;
	sbd_lu_t *slu = (sbd_lu_t *)sst->sst_sbd_private;
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

	laddr = lba << slu->sl_shift_count;
	len <<= slu->sl_shift_count;

	if ((laddr + (uint64_t)len) > slu->sl_sli->sli_lu_data_size) {
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
			stmf_abort(STMF_QUEUE_TASK_ABORT, task,
			    STMF_ALLOC_FAILURE, NULL);
			return;
		}
	}
	dbuf = initial_dbuf;

	if ((dbuf->db_buf_size >= len) && fast_path &&
	    (dbuf->db_sglist_length == 1)) {
		if (sst->sst_data_read(sst,
		    laddr + slu->sl_sli->sli_lu_data_offset, (uint64_t)len,
		    dbuf->db_sglist[0].seg_addr) == STMF_SUCCESS) {
			dbuf->db_relative_offset = 0;
			dbuf->db_data_size = len;
			dbuf->db_flags = DB_SEND_STATUS_GOOD |
			    DB_DIRECTION_TO_RPORT;
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
					struct stmf_data_buf *dbuf)
{
	uint32_t len;
	int bufs_to_take;

	/* Lets try not to hog all the buffers the port has. */
	bufs_to_take = ((task->task_max_nbufs > 2) &&
	    (task->task_cmd_xfer_length < (32 * 1024))) ? 2 :
	    task->task_max_nbufs;

	len = scmd->len > dbuf->db_buf_size ? dbuf->db_buf_size : scmd->len;

	dbuf->db_relative_offset = scmd->current_ro;
	dbuf->db_data_size = len;
	dbuf->db_flags = DB_DIRECTION_FROM_RPORT;
	(void) stmf_xfer_data(task, dbuf, 0);
	scmd->len -= len;
	scmd->current_ro += len;
	if (scmd->len && (scmd->nbufs < bufs_to_take)) {
		uint32_t maxsize, minsize, old_minsize;

		maxsize = (scmd->len > (128*1024)) ? 128*1024 : scmd->len;
		minsize = maxsize >> 2;
		do {
			old_minsize = minsize;
			dbuf = stmf_alloc_dbuf(task, maxsize, &minsize, 0);
		} while ((dbuf == NULL) && (old_minsize > minsize) &&
		    (minsize >= 512));
		if (dbuf == NULL) {
			return;
		}
		scmd->nbufs++;
		sbd_do_write_xfer(task, scmd, dbuf);
	}
}

void
sbd_handle_write_xfer_completion(struct scsi_task *task, sbd_cmd_t *scmd,
    struct stmf_data_buf *dbuf, uint8_t dbuf_reusable)
{
	sbd_store_t *sst = (sbd_store_t *)task->task_lu->lu_provider_private;
	sbd_lu_t *slu = (sbd_lu_t *)sst->sst_sbd_private;
	uint64_t laddr;
	uint32_t buflen, iolen;
	int ndx;

	if (dbuf->db_xfer_status != STMF_SUCCESS) {
		stmf_abort(STMF_QUEUE_TASK_ABORT, task,
		    dbuf->db_xfer_status, NULL);
		return;
	}

	if (scmd->flags & SBD_SCSI_CMD_XFER_FAIL) {
		goto WRITE_XFER_DONE;
	}

	laddr = scmd->addr + dbuf->db_relative_offset +
				slu->sl_sli->sli_lu_data_offset;

	for (buflen = 0, ndx = 0; (buflen < dbuf->db_data_size) &&
	    (ndx < dbuf->db_sglist_length); ndx++) {
		iolen = min(dbuf->db_data_size - buflen,
					dbuf->db_sglist[ndx].seg_length);
		if (iolen == 0)
			break;
		if (sst->sst_data_write(sst, laddr, (uint64_t)iolen,
		    dbuf->db_sglist[0].seg_addr) != STMF_SUCCESS) {
			scmd->flags |= SBD_SCSI_CMD_XFER_FAIL;
			break;
		}
		buflen += iolen;
		laddr += (uint64_t)iolen;
	}
	task->task_nbytes_transferred += buflen;
WRITE_XFER_DONE:
	if (scmd->len == 0 || scmd->flags & SBD_SCSI_CMD_XFER_FAIL) {
		stmf_free_dbuf(task, dbuf);
		scmd->nbufs--;
		if (scmd->nbufs)
			return;	/* wait for all buffers to complete */
		scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
		if (scmd->flags & SBD_SCSI_CMD_XFER_FAIL)
			stmf_scsilib_send_status(task, STATUS_CHECK,
			    STMF_SAA_WRITE_ERROR);
		else
			stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}
	if (dbuf_reusable == 0) {
		uint32_t maxsize, minsize, old_minsize;
		/* free current dbuf and allocate a new one */
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
	sbd_do_write_xfer(task, scmd, dbuf);
}

void
sbd_handle_write(struct scsi_task *task, struct stmf_data_buf *initial_dbuf)
{
	uint64_t lba, laddr;
	uint32_t len;
	uint8_t op = task->task_cdb[0], do_immediate_data = 0;
	sbd_store_t *sst = (sbd_store_t *)task->task_lu->lu_provider_private;
	sbd_lu_t *slu = (sbd_lu_t *)sst->sst_sbd_private;
	sbd_cmd_t *scmd;
	stmf_data_buf_t *dbuf;

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
	} else {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_OPCODE);
		return;
	}

	laddr = lba << slu->sl_shift_count;
	len <<= slu->sl_shift_count;

	if ((laddr + (uint64_t)len) > slu->sl_sli->sli_lu_data_size) {
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
			stmf_abort(STMF_QUEUE_TASK_ABORT, task,
			    STMF_ALLOC_FAILURE, NULL);
			return;
		}
	} else if (task->task_flags & TF_INITIAL_BURST) {
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
	scmd->flags = SBD_SCSI_CMD_ACTIVE;
	scmd->cmd_type = SBD_CMD_SCSI_WRITE;
	scmd->nbufs = 1;
	scmd->addr = laddr;
	scmd->len = len;
	scmd->current_ro = 0;

	if (do_immediate_data) {
		scmd->len -= dbuf->db_data_size;
		scmd->current_ro += dbuf->db_data_size;
		dbuf->db_xfer_status = STMF_SUCCESS;
		sbd_handle_write_xfer_completion(task, scmd, dbuf, 0);
	} else {
		sbd_do_write_xfer(task, scmd, dbuf);
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
		stmf_abort(STMF_QUEUE_TASK_ABORT, task,
		    STMF_ALLOC_FAILURE, NULL);
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
sbd_handle_read_capacity(struct scsi_task *task,
    struct stmf_data_buf *initial_dbuf)
{
	sbd_store_t *sst = (sbd_store_t *)task->task_lu->lu_provider_private;
	sbd_lu_t *slu = (sbd_lu_t *)sst->sst_sbd_private;
	sbd_lu_info_t *sli = slu->sl_sli;
	uint32_t cdb_len;
	uint8_t p[32];
	uint64_t s;

	s = sli->sli_lu_data_size >> slu->sl_shift_count;
	s--;
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
		p[6] = (sli->sli_blocksize >> 8) & 0xff;
		p[7] = sli->sli_blocksize & 0xff;
		sbd_handle_short_read_transfers(task, initial_dbuf, p, 8, 8);
		return;

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
		p[10] = (sli->sli_blocksize >> 8) & 0xff;
		p[11] = sli->sli_blocksize & 0xff;
		sbd_handle_short_read_transfers(task, initial_dbuf, p,
		    cdb_len, 32);
		return;
	}
}

static uint8_t sbd_p3[] =
	{3, 0x16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 2, 0, 0, 0,
	    0, 0, 0, 0, 0x80, 0, 0, 0};
static uint8_t sbd_p4[] =
	{4, 0x16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	    0, 0, 0, 0, 0x15, 0x18, 0, 0};
static uint8_t sbd_pa[] = {0xa, 0xa, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0};
static uint8_t sbd_bd[] = {0, 0, 0, 0, 0, 0, 0x02, 0};

void
sbd_handle_mode_sense(struct scsi_task *task,
    struct stmf_data_buf *initial_dbuf)
{
	sbd_store_t *sst = (sbd_store_t *)task->task_lu->lu_provider_private;
	sbd_lu_t *slu = (sbd_lu_t *)sst->sst_sbd_private;
	sbd_lu_info_t *sli = slu->sl_sli;
	uint32_t cmd_size, hdrsize, xfer_size, ncyl;
	uint8_t payload_buf[8 + 8 + 24 + 24 + 12];
	uint8_t *payload, *p;
	uint8_t ctrl, page;
	uint16_t ps;
	uint64_t s = sli->sli_lu_data_size;
	uint8_t dbd;

	p = &task->task_cdb[0];
	page = p[2] & 0x3F;
	ctrl = (p[2] >> 6) & 3;
	dbd = p[1] & 0x08;

	hdrsize = (p[0] == SCMD_MODE_SENSE) ? 4 : 8;

	cmd_size = (p[0] == SCMD_MODE_SENSE) ? p[4] :
	    READ_SCSI16(&p[7], uint32_t);

	switch (page) {
	case 0x03:
		ps = hdrsize + sizeof (sbd_p3);
		break;
	case 0x04:
		ps = hdrsize + sizeof (sbd_p4);
		break;
	case 0x0A:
		ps = hdrsize + sizeof (sbd_pa);
		break;
	case MODEPAGE_ALLPAGES:
		ps = hdrsize + sizeof (sbd_p3) + sizeof (sbd_p4)
		    + sizeof (sbd_pa);

		/*
		 * If the buffer is big enough, include the block
		 * descriptor; otherwise, leave it out.
		 */
		if (cmd_size < ps) {
			dbd = 1;
		}

		if (dbd == 0) {
			ps += 8;
		}

		break;
	default:
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}

	xfer_size = min(cmd_size, ps);

	if ((xfer_size < hdrsize) || (ctrl == 1) ||
	    (((task->task_additional_flags &
	    TASK_AF_NO_EXPECTED_XFER_LENGTH) == 0) &&
	    (xfer_size > task->task_expected_xfer_length))) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}

	bzero(payload_buf, xfer_size);

	if (p[0] == SCMD_MODE_SENSE) {
		payload_buf[0] = ps - 1;
	} else {
		ps -= 2;
		*((uint16_t *)payload_buf) = BE_16(ps);
	}

	payload = payload_buf + hdrsize;

	switch (page) {
	case 0x03:
		bcopy(sbd_p3, payload, sizeof (sbd_p3));
		break;

	case 0x0A:
		bcopy(sbd_pa, payload, sizeof (sbd_pa));
		break;

	case MODEPAGE_ALLPAGES:
		if (dbd == 0) {
			payload_buf[3] = sizeof (sbd_bd);
			bcopy(sbd_bd, payload, sizeof (sbd_bd));
			payload += sizeof (sbd_bd);
		}

		bcopy(sbd_p3, payload, sizeof (sbd_p3));
		payload += sizeof (sbd_p3);
		bcopy(sbd_pa, payload, sizeof (sbd_pa));
		payload += sizeof (sbd_pa);
		/* FALLTHROUGH */

	case 0x04:
		bcopy(sbd_p4, payload, sizeof (sbd_p4));

		if (s > 1024 * 1024 * 1024) {
			payload[5] = 16;
		} else {
			payload[5] = 2;
		}
		ncyl = (uint32_t)((s/(((uint64_t)payload[5]) * 32 * 512)) + 1);
		payload[4] = (uchar_t)ncyl;
		payload[3] = (uchar_t)(ncyl >> 8);
		payload[2] = (uchar_t)(ncyl >> 16);
		break;

	}

	sbd_handle_short_read_transfers(task, initial_dbuf, payload_buf,
	    cmd_size, xfer_size);
}


void
sbd_handle_inquiry(struct scsi_task *task, struct stmf_data_buf *initial_dbuf,
			uint8_t *p, int bsize)
{
	uint8_t *cdbp = (uint8_t *)&task->task_cdb[0];
	uint32_t cmd_size;
	uint8_t page_length;

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

	cmd_size = (((uint32_t)cdbp[3]) << 8) | cdbp[4];

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
		struct scsi_inquiry *inq = (struct scsi_inquiry *)p;

		page_length = 31;
		bzero(inq, page_length + 5);

		inq->inq_dtype = 0;
		inq->inq_ansi = 5;	/* SPC-3 */
		inq->inq_hisup = 1;
		inq->inq_rdf = 2;	/* Response data format for SPC-3 */
		inq->inq_len = page_length;

		inq->inq_tpgs = 1;

		inq->inq_cmdque = 1;

		(void) strncpy((char *)inq->inq_vid, "SUN     ", 8);
		(void) strncpy((char *)inq->inq_pid, "COMSTAR         ", 16);
		(void) strncpy((char *)inq->inq_revision, "1.0 ", 4);

		sbd_handle_short_read_transfers(task, initial_dbuf, p, cmd_size,
		    min(cmd_size, page_length + 5));

		return;
	}

	/*
	 * EVPD handling
	 */

	switch (cdbp[2]) {
	case 0x00:
		page_length = 3;

		bzero(p, page_length + 4);

		p[0] = 0;
		p[3] = page_length;	/* we support 3 pages, 0, 0x83, 0x86 */
		p[5] = 0x83;
		p[6] = 0x86;

		break;

	case 0x83:

		page_length = stmf_scsilib_prepare_vpd_page83(task, p,
		    bsize, 0, STMF_VPD_LU_ID|STMF_VPD_TARGET_ID|
		    STMF_VPD_TP_GROUP|STMF_VPD_RELATIVE_TP_ID) - 4;
		break;

	case 0x86:
		page_length = 0x3c;

		bzero(p, page_length + 4);

		p[0] = 0;
		p[1] = 0x86;		/* Page 86 response */
		p[3] = page_length;

		/*
		 * Bits 0, 1, and 2 will need to be updated
		 * to reflect the queue tag handling if/when
		 * that is implemented.  For now, we're going
		 * to claim support only for Simple TA.
		 */
		p[5] = 1;

		break;

	default:
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_INVALID_FIELD_IN_CDB);
		return;
	}

	sbd_handle_short_read_transfers(task, initial_dbuf, p, cmd_size,
	    min(cmd_size, page_length + 4));
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
sbd_remove_it_handle(sbd_lu_t *slu, sbd_it_data_t *it)
{
	sbd_it_data_t **ppit;

	mutex_enter(&slu->sl_it_list_lock);
	for (ppit = &slu->sl_it_list; *ppit != NULL;
					ppit = &((*ppit)->sbd_it_next)) {
		if ((*ppit) == it) {
			*ppit = it->sbd_it_next;
			break;
		}
	}
	mutex_exit(&slu->sl_it_list_lock);
	kmem_free(it, sizeof (*it));
}

void
sbd_check_and_clear_scsi2_reservation(sbd_lu_t *slu, sbd_it_data_t *it)
{
	mutex_enter(&slu->sl_it_list_lock);
	if ((slu->sl_flags & SBD_LU_HAS_SCSI2_RESERVATION) == 0) {
		/* If we dont have any reservations, just get out. */
		mutex_exit(&slu->sl_it_list_lock);
		return;
	}

	if (it == NULL) {
		/* Find the I_T nexus which is holding the reservation. */
		for (it = slu->sl_it_list; it != NULL; it = it->sbd_it_next) {
			if (it->sbd_it_flags & SBD_IT_HAS_SCSI2_RESERVATION) {
				ASSERT(it->sbd_it_session_id ==
					slu->sl_rs_owner_session_id);
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
			mutex_exit(&slu->sl_it_list_lock);
			return;
		}
	}
	it->sbd_it_flags &= ~SBD_IT_HAS_SCSI2_RESERVATION;
	slu->sl_flags &= ~SBD_IT_HAS_SCSI2_RESERVATION;
	mutex_exit(&slu->sl_it_list_lock);
}

/*
 * returns non-zero, if this command can be allowed to run even if the
 * lu has been reserved by another initiator.
 */
int
sbd_reserve_allow(scsi_task_t *task)
{
	uint8_t cdb0 = task->task_cdb[0];
	uint8_t cdb1 = task->task_cdb[1];

	if ((cdb0 == SCMD_INQUIRY) || (cdb0 == SCMD_READ_CAPACITY) ||
	    ((cdb0 == SCMD_SVC_ACTION_IN_G4) &&
	    (cdb1 == SSVC_ACTION_READ_CAPACITY_G4))) {
		return (1);
	}
	return (0);
}

void
sbd_new_task(struct scsi_task *task, struct stmf_data_buf *initial_dbuf)
{
	sbd_store_t *sst = (sbd_store_t *)task->task_lu->lu_provider_private;
	sbd_lu_t *slu = (sbd_lu_t *)sst->sst_sbd_private;
	sbd_it_data_t *it;
	uint8_t cdb0, cdb1;

	if ((it = task->task_lu_itl_handle) == NULL) {
		mutex_enter(&slu->sl_it_list_lock);
		for (it = slu->sl_it_list; it != NULL; it = it->sbd_it_next) {
			if (it->sbd_it_session_id ==
			    task->task_session->ss_session_id) {
				mutex_exit(&slu->sl_it_list_lock);
				stmf_scsilib_send_status(task, STATUS_BUSY, 0);
				return;
			}
		}
		it = (sbd_it_data_t *)kmem_zalloc(sizeof (*it), KM_NOSLEEP);
		if (it == NULL) {
			mutex_exit(&slu->sl_it_list_lock);
			stmf_scsilib_send_status(task, STATUS_BUSY, 0);
			return;
		}
		it->sbd_it_session_id = task->task_session->ss_session_id;
		bcopy(task->task_lun_no, it->sbd_it_lun, 8);
		it->sbd_it_next = slu->sl_it_list;
		slu->sl_it_list = it;
		mutex_exit(&slu->sl_it_list_lock);
		if (stmf_register_itl_handle(task->task_lu, task->task_lun_no,
		    task->task_session, it->sbd_it_session_id, it)
		    != STMF_SUCCESS) {
			sbd_remove_it_handle(slu, it);
			stmf_scsilib_send_status(task, STATUS_BUSY, 0);
			return;
		}
		task->task_lu_itl_handle = it;
		it->sbd_it_ua_conditions = SBD_UA_POR;
	}

	if (task->task_mgmt_function) {
		stmf_scsilib_handle_task_mgmt(task);
		return;
	}

	if ((slu->sl_flags & SBD_LU_HAS_SCSI2_RESERVATION) &&
	    ((it->sbd_it_flags & SBD_IT_HAS_SCSI2_RESERVATION) == 0)) {
		if (!sbd_reserve_allow(task)) {
			stmf_scsilib_send_status(task,
			    STATUS_RESERVATION_CONFLICT, 0);
			return;
		}
	}

	if ((it->sbd_it_ua_conditions) && (task->task_cdb[0] != SCMD_INQUIRY)) {
		uint32_t saa = 0;

		mutex_enter(&slu->sl_it_list_lock);
		if (it->sbd_it_ua_conditions & SBD_UA_POR) {
			it->sbd_it_ua_conditions &= ~SBD_UA_POR;
			saa = STMF_SAA_POR;
		} else if (it->sbd_it_ua_conditions & SBD_UA_CAPACITY_CHANGED) {
			it->sbd_it_ua_conditions &= ~SBD_UA_CAPACITY_CHANGED;
			if ((task->task_cdb[0] == SCMD_READ_CAPACITY) ||
			    ((task->task_cdb[0] == SCMD_SVC_ACTION_IN_G4) &&
			    (task->task_cdb[1] ==
			    SSVC_ACTION_READ_CAPACITY_G4))) {
				saa = 0;
			} else {
				saa = STMF_SAA_CAPACITY_DATA_HAS_CHANGED;
			}
		} else {
			it->sbd_it_ua_conditions = 0;
			saa = 0;
		}
		mutex_exit(&slu->sl_it_list_lock);
		if (saa) {
			stmf_scsilib_send_status(task, STATUS_CHECK, saa);
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

	if (cdb0 == SCMD_TEST_UNIT_READY) {	/* Test unit ready */
		task->task_cmd_xfer_length = 0;
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}

	if (cdb0 == SCMD_READ_CAPACITY) {		/* Read Capacity */
		sbd_handle_read_capacity(task, initial_dbuf);
		return;
	}

	if (cdb0 == SCMD_INQUIRY) {		/* Inquiry */
		uint8_t *p;

		p = (uint8_t *)kmem_zalloc(512, KM_SLEEP);
		sbd_handle_inquiry(task, initial_dbuf, p, 512);
		kmem_free(p, 512);
		return;
	}

	if (cdb0 == SCMD_SVC_ACTION_IN_G4) { 	/* Read Capacity or read long */
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

	if (cdb0 == SCMD_START_STOP) {			/* Start stop */
		/* XXX Implement power management */
		task->task_cmd_xfer_length = 0;
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}
#if 0
	/* XXX Remove #if 0 above */
	if ((cdb0 == SCMD_MODE_SELECT) || (cdb0 == SCMD_MODE_SELECT_G1)) {
		sbd_handle_mode_select(task, initial_dbuf);
		return;
	}
#endif
	if ((cdb0 == SCMD_MODE_SENSE) || (cdb0 == SCMD_MODE_SENSE_G1)) {
		sbd_handle_mode_sense(task, initial_dbuf);
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

	if (cdb0 == SCMD_VERIFY) {
		/*
		 * Something more likely needs to be done here.
		 */
		task->task_cmd_xfer_length = 0;
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}

	if ((cdb0 == SCMD_RESERVE) || (cdb0 == SCMD_RELEASE)) {
		if (cdb1) {
			stmf_scsilib_send_status(task, STATUS_CHECK,
				STMF_SAA_INVALID_FIELD_IN_CDB);
			return;
		}
		mutex_enter(&slu->sl_it_list_lock);
		if (slu->sl_flags & SBD_LU_HAS_SCSI2_RESERVATION) {
			if (it->sbd_it_session_id !=
			    slu->sl_rs_owner_session_id) {
				/*
				 * This can only happen if things were in
				 * flux.
				 */
				mutex_exit(&slu->sl_it_list_lock);
				stmf_scsilib_send_status(task,
						STATUS_RESERVATION_CONFLICT, 0);
				return;
			}
		}
	}

	if (cdb0 == SCMD_RELEASE) {
		slu->sl_flags &= ~SBD_LU_HAS_SCSI2_RESERVATION;
		it->sbd_it_flags &= ~SBD_IT_HAS_SCSI2_RESERVATION;
		mutex_exit(&slu->sl_it_list_lock);
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}
	if (cdb0 == SCMD_RESERVE) {
		slu->sl_flags |= SBD_LU_HAS_SCSI2_RESERVATION;
		it->sbd_it_flags |= SBD_IT_HAS_SCSI2_RESERVATION;
		slu->sl_rs_owner_session_id = it->sbd_it_session_id;
		mutex_exit(&slu->sl_it_list_lock);
		stmf_scsilib_send_status(task, STATUS_GOOD, 0);
		return;
	}

	if (cdb0 == SCMD_SYNCHRONIZE_CACHE ||
	    cdb0 == SCMD_SYNCHRONIZE_CACHE_G4) {
		sbd_handle_sync_cache(task, initial_dbuf);
		return;
	}

	/* Report Target Port Groups */
	if ((cdb0 == SCMD_MAINTENANCE_IN) &&
	    ((cdb1 & 0x1F) == 0x0A)) {
		stmf_scsilib_handle_report_tpgs(task, initial_dbuf);
		return;
	}

	stmf_scsilib_send_status(task, STATUS_CHECK, STMF_SAA_INVALID_OPCODE);
}

void
sbd_dbuf_xfer_done(struct scsi_task *task, struct stmf_data_buf *dbuf)
{
	sbd_cmd_t *scmd = NULL;

	scmd = (sbd_cmd_t *)task->task_lu_private;
	if ((scmd == NULL) || ((scmd->flags & SBD_SCSI_CMD_ACTIVE) == 0))
		return;

	if (scmd->cmd_type == SBD_CMD_SCSI_READ) {
		sbd_handle_read_xfer_completion(task, scmd, dbuf);
	} else if (scmd->cmd_type == SBD_CMD_SCSI_WRITE) {
		sbd_handle_write_xfer_completion(task, scmd, dbuf, 1);
	} else if (scmd->cmd_type == SBD_CMD_SMALL_READ) {
		sbd_handle_short_read_xfer_completion(task, scmd, dbuf);
	} else {
		cmn_err(CE_PANIC, "Unknown cmd type, task = %p", (void *)task);
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
	sbd_store_t *sst = (sbd_store_t *)lu->lu_provider_private;
	sbd_lu_t *slu = (sbd_lu_t *)sst->sst_sbd_private;
	scsi_task_t *task;

	if (abort_cmd == STMF_LU_RESET_STATE) {
		return (sbd_lu_reset_state(lu));
	}

	if (abort_cmd == STMF_LU_ITL_HANDLE_REMOVED) {
		sbd_check_and_clear_scsi2_reservation(slu,
					(sbd_it_data_t *)arg);
		sbd_remove_it_handle(slu, (sbd_it_data_t *)arg);
		return (STMF_SUCCESS);
	}

	ASSERT(abort_cmd == STMF_LU_ABORT_TASK);
	task = (scsi_task_t *)arg;
	if (task->task_lu_private) {
		sbd_cmd_t *scmd = (sbd_cmd_t *)task->task_lu_private;

		if (scmd->flags & SBD_SCSI_CMD_ACTIVE) {
			scmd->flags &= ~SBD_SCSI_CMD_ACTIVE;
			return (STMF_ABORT_SUCCESS);
		}
	}

	return (STMF_NOT_FOUND);
}

/* ARGSUSED */
void
sbd_ctl(struct stmf_lu *lu, int cmd, void *arg)
{
	sbd_store_t *sst = (sbd_store_t *)lu->lu_provider_private;
	sbd_lu_t *slu = (sbd_lu_t *)sst->sst_sbd_private;
	stmf_change_status_t st;

	ASSERT((cmd == STMF_CMD_LU_ONLINE) ||
		(cmd == STMF_CMD_LU_OFFLINE) ||
		(cmd == STMF_ACK_LU_ONLINE_COMPLETE) ||
		(cmd == STMF_ACK_LU_OFFLINE_COMPLETE));

	st.st_completion_status = STMF_SUCCESS;
	st.st_additional_info = NULL;

	switch (cmd) {
	case STMF_CMD_LU_ONLINE:
		if (slu->sl_state == STMF_STATE_ONLINE)
			st.st_completion_status = STMF_ALREADY;
		else if (slu->sl_state != STMF_STATE_OFFLINE)
			st.st_completion_status = STMF_FAILURE;
		if (st.st_completion_status == STMF_SUCCESS) {
			slu->sl_state = STMF_STATE_ONLINING;
			slu->sl_state_not_acked = 1;
			st.st_completion_status = sst->sst_online(sst);
			if (st.st_completion_status != STMF_SUCCESS) {
				slu->sl_state = STMF_STATE_OFFLINE;
				slu->sl_state_not_acked = 0;
			} else {
				slu->sl_state = STMF_STATE_ONLINE;
			}
		}
		(void) stmf_ctl(STMF_CMD_LU_ONLINE_COMPLETE, lu, &st);
		break;

	case STMF_CMD_LU_OFFLINE:
		if (slu->sl_state == STMF_STATE_OFFLINE)
			st.st_completion_status = STMF_ALREADY;
		else if (slu->sl_state != STMF_STATE_ONLINE)
			st.st_completion_status = STMF_FAILURE;
		if (st.st_completion_status == STMF_SUCCESS) {
			slu->sl_state = STMF_STATE_OFFLINING;
			slu->sl_state_not_acked = 1;
			st.st_completion_status = sst->sst_offline(sst);
			if (st.st_completion_status != STMF_SUCCESS) {
				slu->sl_state = STMF_STATE_ONLINE;
				slu->sl_state_not_acked = 0;
			} else {
				slu->sl_state = STMF_STATE_OFFLINE;
			}
		}
		(void) stmf_ctl(STMF_CMD_LU_OFFLINE_COMPLETE, lu, &st);
		break;

	case STMF_ACK_LU_ONLINE_COMPLETE:
		/* Fallthrough */
	case STMF_ACK_LU_OFFLINE_COMPLETE:
		slu->sl_state_not_acked = 0;
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
	sbd_store_t *sst = (sbd_store_t *)lu->lu_provider_private;
	sbd_lu_t *slu = (sbd_lu_t *)sst->sst_sbd_private;

	sbd_check_and_clear_scsi2_reservation(slu, NULL);
	if (stmf_deregister_all_lu_itl_handles(lu) != STMF_SUCCESS) {
		return (STMF_FAILURE);
	}
	return (STMF_SUCCESS);
}

/* ARGSUSED */
static void
sbd_handle_sync_cache(struct scsi_task *task,
    struct stmf_data_buf *initial_dbuf)
{
	sbd_store_t	*sst =
	    (sbd_store_t *)task->task_lu->lu_provider_private;
	sbd_lu_t	*slu = (sbd_lu_t *)sst->sst_sbd_private;
	uint64_t	lba, laddr;
	uint32_t	len;
	int		is_g4 = 0;
	int		immed;

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

	laddr = lba << slu->sl_shift_count;
	len <<= slu->sl_shift_count;

	if ((laddr + (uint64_t)len) > slu->sl_sli->sli_lu_data_size) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_LBA_OUT_OF_RANGE);
		return;
	}

	if (sst->sst_data_flush(sst) != STMF_SUCCESS) {
		stmf_scsilib_send_status(task, STATUS_CHECK,
		    STMF_SAA_WRITE_ERROR);
		return;
	}

	stmf_scsilib_send_status(task, STATUS_GOOD, 0);
}
