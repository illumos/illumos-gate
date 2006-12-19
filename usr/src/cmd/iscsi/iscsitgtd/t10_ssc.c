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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Implementation of SSC-2 emulation
 */

#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <aio.h>
#include <sys/asynch.h>
#include <sys/scsi/generic/sense.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/targets/stdef.h>
#include <netinet/in.h>

#include "target.h"
#include "utility.h"
#include "t10.h"
#include "t10_spc.h"
#include "t10_ssc.h"

/*
 * []----
 * | Forward declarations
 * []----
 */
static scsi_cmd_table_t ssc_table[];
static void ssc_cmd(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len);
static void ssc_data(t10_cmd_t *cmd, emul_handle_t id, size_t offset,
    char *data, size_t data_len);
static void ssc_free(emul_handle_t e);
static void ssc_write_cmplt(emul_handle_t e);
static void ssc_read_cmplt(emul_handle_t id);
static void ssc_setup_tape(ssc_params_t *s, t10_lu_common_t *lu);
static uint32_t find_last_obj_id(char *file_mark, off_t eod);
static char *sense_dev_config(ssc_params_t *s, char *data);
static char *sense_compression(ssc_params_t *s, char *data);

static long ssc_page_size;

/*
 * []----
 * | ssc_init_common -- initialize common information that all ITLs will use
 * []----
 */
Boolean_t
ssc_common_init(t10_lu_common_t *lu)
{
	ssc_params_t	*s;
	ssc_obj_mark_t	mark;

	ssc_page_size = sysconf(_SC_PAGESIZE);

	if (lu->l_mmap == MAP_FAILED)
		return (False);

	if ((s = (ssc_params_t *)calloc(1, sizeof (*s))) == NULL)
		return (False);

	s->s_size		= lu->l_size;
	s->s_fast_write_ack = lu->l_fast_write_ack;

	bcopy(lu->l_mmap, &mark, sizeof (mark));
	if (mark.som_sig != SSC_OBJ_SIG) {
		ssc_setup_tape(s, lu);
	}
	s->s_cur_fm	= 0;
	s->s_cur_rec	= sizeof (ssc_obj_mark_t);
	s->s_prev_rec	= s->s_cur_rec;
	s->s_state	= lu->l_state;

	lu->l_dtype_params = (void *)s;
	return (True);
}

/*
 * []----
 * | ssc_fini_common -- free any resources
 * []----
 */
void
ssc_common_fini(t10_lu_common_t *lu)
{
	free(lu->l_dtype_params);
}

void
ssc_task_mgmt(t10_lu_common_t *lu, TaskOp_t op)
{
	ssc_params_t	*s = (ssc_params_t *)lu->l_dtype_params;

	switch (op) {
	case CapacityChange:
		s->s_size = lu->l_size;
		break;

	case DeviceOnline:
		s->s_state = lu->l_state;
	}
}

/*
 * []----
 * | ssc_init_per -- initialize per ITL information
 * []----
 */
void
ssc_per_init(t10_lu_impl_t *itl)
{
	ssc_params_t	*s = (ssc_params_t *)itl->l_common->l_dtype_params;

	if (s->s_state == lu_online)
		itl->l_cmd	= ssc_cmd;
	else
		itl->l_cmd	= spc_cmd_offline;
	itl->l_data		= ssc_data;
	itl->l_cmd_table	= ssc_table;
}

/*
 * []----
 * | ssc_fini_per -- release or free any ITL resources
 * []----
 */
/*ARGSUSED*/
void
ssc_per_fini(t10_lu_impl_t *itl)
{
}

/*
 * []----
 * | ssc_cmd -- start a SCSI command
 * |
 * | This routine is called from within the SAM-3 Task router.
 * []----
 */
static void
ssc_cmd(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	scsi_cmd_table_t	*e;

	e = &cmd->c_lu->l_cmd_table[cdb[0]];
#ifdef FULL_DEBUG
	queue_prt(mgmtq, Q_STE_IO, "SSC%x  LUN%d Cmd %s\n",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num,
	    e->cmd_name == NULL ? "(no name)" : e->cmd_name);
#endif
	(*e->cmd_start)(cmd, cdb, cdb_len);
}

/*
 * []----
 * | ssc_data -- Data phase for command.
 * |
 * | Normally this is only called for the WRITE command. Other commands
 * | that have a data in phase will probably be short circuited when
 * | we call trans_rqst_dataout() and the data is already available.
 * | At least this is true for iSCSI. FC however will need a DataIn phase
 * | for commands like MODE SELECT and PGROUT.
 * []----
 */
static void
ssc_data(t10_cmd_t *cmd, emul_handle_t id, size_t offset, char *data,
    size_t data_len)
{
	scsi_cmd_table_t	*e;

	e = &cmd->c_lu->l_cmd_table[cmd->c_cdb[0]];
#ifdef FULL_DEBUG
	queue_prt(mgmtq, Q_STE_IO, "SSC%x  LUN%d Data %s\n",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num,
	    e->cmd_name);
#endif
	(*e->cmd_data)(cmd, id, offset, data, data_len);
}

/*
 * []------------------------------------------------------------------[]
 * | SCSI Streaming Commands - 3					|
 * | T10/1611-D Revision 01c						|
 * | The following functions implement the emulation of SSC-3 type	|
 * | commands.								|
 * []------------------------------------------------------------------[]
 */

/*ARGSUSED*/
static void
ssc_read(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	ssc_io_t	*io;
	ssc_params_t	*s		= (ssc_params_t *)T10_PARAMS_AREA(cmd);
	ssc_obj_mark_t	fm,
			rm;
	int		fixed,
			sili;
	off_t		offset		= 0;
	size_t		xfer,
			req_len;
	void		*mmap		= cmd->c_lu->l_common->l_mmap;
	t10_cmd_t	*c;

	fixed	= cdb[1] & 0x01;
	sili	= cdb[1] & 0x02;

	if (s == NULL)
		return;

	/*
	 * Standard error checking.
	 */
	if ((sili && fixed) || (cdb[1] & 0xfc) ||
	    SAM_CONTROL_BYTE_RESERVED(cdb[5])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	req_len	= (cdb[2] << 16) | (cdb[3] << 8) | cdb[4];
	req_len	*= fixed ? 512 : 1;

	if (req_len == 0) {
		trans_send_complete(cmd, STATUS_GOOD);
		return;
	}

#ifdef FULL_DEBUG
	queue_prt(mgmtq, Q_STE_IO,
	    "SSC%x  LUN%d read 0x%x bytes",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num, req_len);
#endif

	bcopy((char *)mmap + s->s_cur_fm, &fm, sizeof (fm));
	bcopy((char *)mmap + s->s_cur_fm + s->s_cur_rec, &rm, sizeof (rm));

	if (rm.som_sig != SSC_OBJ_SIG) {
		queue_prt(mgmtq, Q_STE_ERRS,
		    "SSC%x  LUN%d bad RECORD-MARK",
		    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num);
		spc_sense_create(cmd, KEY_MEDIUM_ERROR, 0);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	} else if (rm.som_type != SSC_OBJ_TYPE_RM) {
		s->s_cur_fm	+= fm.o_fm.size;
		s->s_cur_rec	= sizeof (ssc_obj_mark_t);
		s->s_prev_rec	= s->s_cur_rec;

		spc_sense_create(cmd, KEY_NO_SENSE, 0);
		spc_sense_ascq(cmd, SPC_ASC_FM_DETECTED, SPC_ASCQ_FM_DETECTED);
		spc_sense_info(cmd, req_len);
		spc_sense_flags(cmd, SPC_SENSE_FM);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	} else if ((sili == 0) &&
	    ((rm.o_rm.size - sizeof (ssc_obj_mark_t)) != req_len)) {
		queue_prt(mgmtq, Q_STE_ERRS,
		    "SSC%x  LUN%d Wrong size read",
		    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num);

		s->s_prev_rec	= s->s_cur_rec;
		s->s_cur_rec	+= rm.o_rm.size;

		spc_sense_create(cmd, KEY_NO_SENSE, 0);
		spc_sense_flags(cmd, SPC_SENSE_ILI);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	do {
		xfer = MIN((req_len - offset), T10_MAX_OUT(cmd));
		if ((offset + xfer) < req_len)
			c = trans_cmd_dup(cmd);
		else
			c = cmd;
		if ((io = (ssc_io_t *)calloc(1, sizeof (*io))) == NULL) {
			trans_send_complete(c, STATUS_BUSY);
			return;
		}

		io->sio_cmd		= c;
		io->sio_offset		= offset;
		io->sio_total		= req_len;
		io->sio_data_len	= xfer;
		io->sio_data		= (char *)mmap + s->s_cur_fm +
		    s->s_cur_rec + sizeof (ssc_obj_mark_t) + offset;
		io->sio_aio.a_aio.aio_return = xfer;

		ssc_read_cmplt((emul_handle_t)io);
		offset += xfer;
	} while (offset < req_len);

	s->s_prev_rec = s->s_cur_rec;
	s->s_cur_rec += req_len + sizeof (ssc_obj_mark_t);
}

static void
ssc_read_cmplt(emul_handle_t id)
{
	ssc_io_t	*io	= (ssc_io_t *)id;
	t10_cmd_t	*cmd	= io->sio_cmd;

	if (io->sio_aio.a_aio.aio_return != io->sio_data_len) {
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	if ((io->sio_offset + io->sio_data_len) < io->sio_total) {
		if (trans_send_datain(cmd, io->sio_data, io->sio_data_len,
		    io->sio_offset, ssc_free, False, io) == False) {
			trans_send_complete(cmd, STATUS_BUSY);
		}
	} else {
		if (trans_send_datain(cmd, io->sio_data, io->sio_data_len,
		    io->sio_offset, ssc_free, True, io) == False) {
			trans_send_complete(cmd, STATUS_BUSY);
		}
	}
}

/*ARGSUSED*/
static void
ssc_write(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	ssc_obj_mark_t	mark;
	size_t		request_len,
			max_xfer;
	int		fixed,
			prev_id;
	ssc_io_t	*io;
	ssc_params_t	*s		= (ssc_params_t *)T10_PARAMS_AREA(cmd);

	if (s == NULL)
		return;

	if ((cdb[1] & 0xfe) || SAM_CONTROL_BYTE_RESERVED(cdb[5])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}
	fixed		= cdb[1];
	request_len	= (cdb[2] << 16) | (cdb[3] << 8) | cdb[4];
	request_len	*= fixed ? 512 : 1;

#ifdef FULL_DEBUG
	queue_prt(mgmtq, Q_STE_IO,
	    "SSC%x  LUN%d write %d, fixed %d",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num,
	    request_len, fixed);
#endif
	io = cmd->c_emul_id;
	if (io == NULL) {
		if ((io = calloc(1, sizeof (*io))) == NULL) {
			trans_send_complete(cmd, STATUS_BUSY);
			return;
		}
		io->sio_total	= request_len;
		io->sio_cmd	= cmd;
		io->sio_offset	= 0;

		/*
		 * Writing looses all information after the current
		 * file-mark. So, check to see if the current file-mark
		 * size doesn't reflect the end-of-media. If not, update
		 * it.
		 */
		bcopy((char *)cmd->c_lu->l_common->l_mmap + s->s_cur_fm,
		    &mark, sizeof (mark));
		if (mark.o_fm.size !=
		    (s->s_size - sizeof (ssc_obj_mark_t) - s->s_cur_fm)) {
			mark.o_fm.size = s->s_size - sizeof (ssc_obj_mark_t) -
			    s->s_cur_fm;
			bcopy(&mark, (char *)cmd->c_lu->l_common->l_mmap +
			    s->s_cur_fm, sizeof (mark));
		}

		/*
		 * End-of-Partition detection
		 */
		if ((s->s_cur_rec + request_len) > (mark.o_fm.size)) {
			spc_sense_create(cmd, KEY_VOLUME_OVERFLOW, 0);
			spc_sense_ascq(cmd, SPC_ASC_EOP, SPC_ASCQ_EOP);
			spc_sense_flags(cmd, SPC_SENSE_EOM);
			trans_send_complete(cmd, STATUS_CHECK);
			return;
		}

		if ((s->s_cur_fm == 0) &&
		    (s->s_cur_rec == sizeof (ssc_obj_mark_t))) {

			/*
			 * The current position is a BOM. By setting
			 * the prev_id value to -1 the code below will
			 * create the first ID with a value of zero
			 * Which is what the specification requires.
			 */
			prev_id = -1;

		} else if (s->s_cur_rec == sizeof (ssc_obj_mark_t)) {

			/*
			 * If the current position is at the beginning of
			 * this file-mark use the object ID found in
			 * the file-mark header. It will have been updated
			 * from the last object ID in the previous file-mark.
			 *
			 * NOTE: We're counting on 'mark' still referring
			 * to the current file mark here.
			 */
			prev_id = mark.o_fm.last_obj_id;
		} else {
			bcopy((char *)cmd->c_lu->l_common->l_mmap +
			    s->s_cur_fm + s->s_prev_rec, &mark, sizeof (mark));
			prev_id	= mark.o_rm.obj_id;
		}

		bzero(&mark, sizeof (mark));
		mark.som_sig		= SSC_OBJ_SIG;
		mark.som_type		= SSC_OBJ_TYPE_RM;
		mark.o_rm.size		= request_len +
		    sizeof (ssc_obj_mark_t);
		mark.o_rm.obj_id	= prev_id + 1;
		bcopy(&mark, (char *)cmd->c_lu->l_common->l_mmap +
		    s->s_cur_fm + s->s_cur_rec, sizeof (mark));
	}

	max_xfer = min(io->sio_total - io->sio_offset,
	    cmd->c_lu->l_targ->s_maxout);
	io->sio_aio.a_aio.aio_return = max_xfer;
	io->sio_data_len = max_xfer;
	io->sio_data = (char *)cmd->c_lu->l_common->l_mmap +
	    s->s_cur_fm +  s->s_cur_rec + sizeof (mark) + io->sio_offset;

	if (trans_rqst_dataout(cmd, io->sio_data, io->sio_data_len,
	    io->sio_offset, io, ssc_free) == False) {
		trans_send_complete(cmd, STATUS_BUSY);
	}
}

/*ARGSUSED*/
static void
ssc_write_data(t10_cmd_t *cmd, emul_handle_t id, size_t offset, char *data,
    size_t data_len)
{
	ssc_io_t	*io	= (ssc_io_t *)id;
	ssc_params_t	*s	= (ssc_params_t *)T10_PARAMS_AREA(cmd);

	if (s == NULL)
		return;

	if (s->s_fast_write_ack == False) {
		uint64_t	sa;
		size_t		len;

		/*
		 * msync requires the address to be page aligned.
		 * That means we need to account for any alignment
		 * loss in the len field and access the full page.
		 */
		sa = (uint64_t)(intptr_t)data & ~(ssc_page_size - 1);
		len = (((size_t)data & (ssc_page_size - 1)) +
		    data_len + ssc_page_size - 1) &
		    ~(ssc_page_size -1);

		/*
		 * We only need to worry about sync'ing the blocks
		 * in the mmap case because if the fast cache isn't
		 * enabled for AIO the file will be opened with F_SYNC
		 * which performs the correct action.
		 */
		if (msync((char *)(intptr_t)sa, len, MS_SYNC) == -1) {
			perror("msync");
			spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
			trans_send_complete(cmd, STATUS_CHECK);
			return;
		}
	}
	ssc_write_cmplt((emul_handle_t)io);
}

static void
ssc_write_cmplt(emul_handle_t e)
{
	ssc_io_t	*io	= (ssc_io_t *)e;
	t10_cmd_t	*cmd	= io->sio_cmd;
	ssc_params_t	*s	= (ssc_params_t *)T10_PARAMS_AREA(cmd);

	if (s == NULL)
		return;

	if ((io->sio_offset + io->sio_data_len) < io->sio_total) {
		io->sio_offset	+= io->sio_data_len;
		ssc_write(cmd, cmd->c_cdb, cmd->c_cdb_len);
		return;
	}

	s->s_prev_rec	= s->s_cur_rec;
	s->s_cur_rec	+= io->sio_total + sizeof (ssc_obj_mark_t);
	free(io);
	trans_send_complete(cmd, STATUS_GOOD);
}

/*ARGSUSED*/
static void
ssc_rewind(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	ssc_params_t	*s = (ssc_params_t *)T10_PARAMS_AREA(cmd);

	if (s == NULL)
		return;

	if ((cdb[1] & ~SSC_REWIND_IMMED) || cdb[2] || cdb[3] || cdb[4] ||
	    SAM_CONTROL_BYTE_RESERVED(cdb[5])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	s->s_cur_fm	= 0;
	s->s_cur_rec	= sizeof (ssc_obj_mark_t);
	trans_send_complete(cmd, STATUS_GOOD);
}

/*ARGSUSED*/
static void
ssc_read_limits(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	struct read_blklim	*rb;
	int			min_size	= 512;

	if (cdb[1] || cdb[2] || cdb[3] || cdb[4] ||
	    SAM_CONTROL_BYTE_RESERVED(cdb[5])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	if ((rb = (struct read_blklim *)calloc(1, sizeof (*rb))) == NULL) {
		trans_send_complete(cmd, STATUS_BUSY);
		return;
	}

	/*
	 * maximum block size is set to zero to indicate no maximum block
	 * limit is specified.
	 */
	rb->granularity = 9;	/* 512 block sizes */
	rb->min_hi	= hibyte(min_size);
	rb->min_lo	= lobyte(min_size);

	if (trans_send_datain(cmd, (char *)rb, sizeof (*rb), 0, ssc_free,
	    True, (emul_handle_t)rb) == False) {
		trans_send_complete(cmd, STATUS_BUSY);
	}
}

/*ARGSUSED*/
static void
ssc_space(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	int		code,
			count;
	ssc_params_t	*s		= T10_PARAMS_AREA(cmd);
	ssc_obj_mark_t	mark;
	t10_lu_common_t	*lu		= cmd->c_lu->l_common;

	if (s == NULL)
		return;

	if ((cdb[1] & 0xf0) || SAM_CONTROL_BYTE_RESERVED(cdb[5])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	code = cdb[1] & 0x0f;
	count = (cdb[2] << 16) | (cdb[3] << 8) | cdb[4];

	if ((count == 0) && (code != SSC_SPACE_CODE_END_OF_DATA)) {
		trans_send_complete(cmd, STATUS_GOOD);
		return;
	}

	switch (code) {
	case SSC_SPACE_CODE_BLOCKS:
		if (count < 0) {
			bcopy((char *)lu->l_mmap + s->s_cur_fm + s->s_cur_rec,
			    &mark, sizeof (mark));
			if ((mark.som_sig == SSC_OBJ_SIG) &&
			    (mark.som_type == SSC_OBJ_TYPE_RM)) {
				count = mark.o_rm.obj_id + count;

				/*
				 * If the count is still negative it means
				 * the request is still attempting to go
				 * beyond the beginning of the file mark.
				 */
				if (count < 0) {
					count *= -1;
					spc_sense_create(cmd, KEY_NO_SENSE, 0);
					spc_sense_ascq(cmd,
					    SPC_ASC_FM_DETECTED,
					    SPC_ASCQ_FM_DETECTED);
					spc_sense_info(cmd, count);
					trans_send_complete(cmd, STATUS_CHECK);
					return;
				}
				s->s_cur_rec = s->s_cur_fm + sizeof (mark);
			} else {
				/*
				 * Something is not right. We'll let the
				 * processing below determine exactly what
				 * is wrong. So don't update the record
				 * mark and sent the count to 1.
				 */
				count = 1;
			}
		}

		while (count) {
			bcopy((char *)lu->l_mmap + s->s_cur_fm + s->s_cur_rec,
			    &mark, sizeof (mark));

			/*
			 * Something internally bad has happened with
			 * the marks in the file.
			 */
			if (mark.som_sig != SSC_OBJ_SIG) {
				queue_prt(mgmtq, Q_STE_ERRS,
				    "SSC%x  LUN%d, bad sig mark: "
				    "expected=0x%x, got=0x%x",
				    cmd->c_lu->l_targ->s_targ_num,
				    cmd->c_lu->l_common->l_num,
				    SSC_OBJ_SIG, mark.som_sig);
				spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
				trans_send_complete(cmd, STATUS_CHECK);
				return;
			}

			/*
			 * Hit a filemark. Update the current record if
			 * we're not at the End-Of-Medium.
			 */
			if (mark.som_type == SSC_OBJ_TYPE_FM) {
				if (mark.o_fm.eom == True) {
					spc_sense_create(cmd, KEY_MEDIUM_ERROR,
					    0);
					spc_sense_ascq(cmd, SPC_ASC_EOP,
					    SPC_ASCQ_EOP);
					spc_sense_info(cmd, count);
					spc_sense_flags(cmd, SPC_SENSE_EOM);
					trans_send_complete(cmd, STATUS_CHECK);
					return;
				}
				s->s_cur_fm += s->s_cur_rec;
				s->s_cur_rec += sizeof (mark);
				spc_sense_create(cmd, KEY_NO_SENSE, 0);
				spc_sense_ascq(cmd, SPC_ASC_FM_DETECTED,
				    SPC_ASCQ_FM_DETECTED);
				spc_sense_info(cmd, count);
				trans_send_complete(cmd, STATUS_CHECK);
				return;
			}
			s->s_cur_rec += mark.o_rm.size;
			count--;
		}
		trans_send_complete(cmd, STATUS_CHECK);
		break;

	case SSC_SPACE_CODE_FILEMARKS:
		if (count < 0) {
			bcopy((char *)lu->l_mmap + s->s_cur_fm, &mark,
			    sizeof (mark));
			if ((mark.som_sig == SSC_OBJ_SIG) &&
			    (mark.som_type == SSC_OBJ_TYPE_FM)) {
				count = mark.o_fm.num + count;

				/*
				 * If the count is still negative it means
				 * the request is still attempting to go
				 * beyond the beginning of the file mark.
				 */
				if (count < 0) {
					count *= -1;
					spc_sense_create(cmd, KEY_NO_SENSE, 0);
					spc_sense_ascq(cmd,
					    SPC_ASC_FM_DETECTED,
					    SPC_ASCQ_FM_DETECTED);
					spc_sense_info(cmd, count);
					trans_send_complete(cmd, STATUS_CHECK);
					return;
				}
				s->s_cur_fm = 0;
				s->s_cur_rec = sizeof (ssc_obj_mark_t);
			} else {
				/*
				 * Something is not right. We'll let the
				 * processing below determine exactly what
				 * is wrong. So don't update the record
				 * mark and sent the count to 1.
				 */
				count = 1;
			}
		}

		while (count--) {
			bcopy((char *)lu->l_mmap + s->s_cur_fm, &mark,
			    sizeof (mark));
			if (mark.som_sig != SSC_OBJ_SIG) {
				queue_prt(mgmtq, Q_STE_ERRS,
				    "SSC%x  LUN%d, bad sig mark: "
				    "expected=0x%x, got=0x%x",
				    cmd->c_lu->l_targ->s_targ_num,
				    cmd->c_lu->l_common->l_num,
				    SSC_OBJ_SIG, mark.som_sig);
				spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
				trans_send_complete(cmd, STATUS_CHECK);
				return;
			}
			if (mark.som_type != SSC_OBJ_TYPE_FM) {
				queue_prt(mgmtq, Q_STE_ERRS,
				    "SSC%x  LUN%d, bad mark type: "
				    "expected=0x%x, got=0x%x",
				    cmd->c_lu->l_targ->s_targ_num,
				    cmd->c_lu->l_common->l_num,
				    SSC_OBJ_TYPE_FM, mark.som_type);
				spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
				trans_send_complete(cmd, STATUS_CHECK);
				return;
			}
			if (mark.o_fm.eom == True) {
				spc_sense_create(cmd, KEY_MEDIUM_ERROR, 0);
				spc_sense_ascq(cmd, SPC_ASC_EOP, SPC_ASCQ_EOP);
				spc_sense_info(cmd, count);
				spc_sense_flags(cmd, SPC_SENSE_EOM);
				trans_send_complete(cmd, STATUS_CHECK);
				return;
			}
			s->s_cur_fm += mark.o_fm.size;
		}
		trans_send_complete(cmd, STATUS_GOOD);
		break;

	default:
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}
}

/*
 * []----
 * | ssc_msense -- MODE SENSE command
 * |
 * | This command is part of the SPC set, but is device specific enough
 * | that it must be emulated in each device type.
 * []----
 */
/*ARGSUSED*/
static void
ssc_msense(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	ssc_params_t		*s		= T10_PARAMS_AREA(cmd);
	struct mode_header	*mode_hdr;
	int			request_len,
				alloc_len;
	char			*data,
				*np;

	/*
	 * SPC-3 Revision 21c section 6.8
	 * Reserve bit checks
	 */
	if ((cdb[1] & ~8) || SAM_CONTROL_BYTE_RESERVED(cdb[5])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	/*
	 * Zero length causes a simple ack to occur.
	 */
	if (cdb[4] == 0) {
		trans_send_complete(cmd, STATUS_GOOD);
		return;
	} else {
		request_len = cdb[4];
		alloc_len = max(request_len,
		    sizeof (*mode_hdr) + MODE_BLK_DESC_LENGTH +
		    sizeof (ssc_data_compression_t) + sizeof (*mode_hdr) +
		    MODE_BLK_DESC_LENGTH + sizeof (ssc_device_config_t));
	}

	queue_prt(mgmtq, Q_STE_NONIO, "SSC%x  LUN%d: MODE_SENSE(0x%x)",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num, cdb[2]);

	if ((data = memalign(sizeof (void *), alloc_len)) == NULL) {
		trans_send_complete(cmd, STATUS_BUSY);
		return;
	}

	mode_hdr = (struct mode_header *)data;

	switch (cdb[2]) {
	case MODE_SENSE_COMPRESSION:
		mode_hdr->length	= sizeof (ssc_data_compression_t);
		mode_hdr->bdesc_length	= MODE_BLK_DESC_LENGTH;
		(void) sense_compression(s, data + sizeof (*mode_hdr) +
		    mode_hdr->bdesc_length);
		break;

	case MODE_SENSE_DEV_CONFIG:
		mode_hdr->length	= sizeof (ssc_device_config_t);
		mode_hdr->bdesc_length	= MODE_BLK_DESC_LENGTH;
		(void) sense_dev_config(s, data + sizeof (*mode_hdr) +
		    mode_hdr->bdesc_length);
		break;

	case MODE_SENSE_SEND_ALL:
		np = sense_compression(s, data);
		(void) sense_dev_config(s, np);
		break;

	case 0x00:
		bzero(data, alloc_len);
		break;

	default:
		queue_prt(mgmtq, Q_STE_ERRS,
		    "SSC%x  LUN%d: MODE SENSE(0x%x) not handled",
		    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num,
		    cdb[2]);
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	if (trans_send_datain(cmd, (char *)data, request_len, 0, ssc_free,
	    True, data) == False) {
		trans_send_complete(cmd, STATUS_BUSY);
	}
}

/*ARGSUSED*/
static void
ssc_read_pos(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	int			service_action,
				request_len,
				alloc_len;
	pos_short_form_t	*sf;
	void			*data;
	ssc_params_t		*s = (ssc_params_t *)T10_PARAMS_AREA(cmd);
	ssc_obj_mark_t		mark;

	if (s == NULL)
		return;

	/*
	 * Standard reserve bit check
	 */
	if ((cdb[1] & 0xc0) || cdb[2] || cdb[3] || cdb[4] || cdb[5] ||
	    cdb[6] || SAM_CONTROL_BYTE_RESERVED(cdb[9])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	service_action	= cdb[1] & 0x1f;
	request_len	= (cdb[7] << 8) | cdb[8];
	switch (service_action) {
	case SSC_READ_POS_SHORT_FORM:
		alloc_len = max(request_len, sizeof (*sf));
		if ((data = memalign(sizeof (void *), alloc_len)) == NULL) {
			trans_send_complete(cmd, STATUS_BUSY);
			return;
		}
		sf = (pos_short_form_t *)data;
		bcopy((char *)cmd->c_lu->l_common->l_mmap + s->s_cur_fm,
		    &mark, sizeof (mark));
		if ((mark.o_fm.bom == True) &&
		    (s->s_cur_rec == sizeof (ssc_obj_mark_t)))
			sf->bop = 1;
		bcopy((char *)cmd->c_lu->l_common->l_mmap + s->s_cur_fm +
		    s->s_cur_rec, &mark, sizeof (mark));
		sf->first_obj[0] = hibyte(hiword(mark.o_rm.obj_id));
		sf->first_obj[1] = lobyte(hiword(mark.o_rm.obj_id));
		sf->first_obj[2] = hibyte(loword(mark.o_rm.obj_id));
		sf->first_obj[3] = lobyte(loword(mark.o_rm.obj_id));

		/*
		 * We mark the last object to be the same as the first
		 * object which indicates that nothing is currently
		 * buffered.
		 */
		sf->last_obj[0] = sf->first_obj[0];
		sf->last_obj[1] = sf->first_obj[1];
		sf->last_obj[2] = sf->first_obj[2];
		sf->last_obj[3] = sf->first_obj[3];

		break;

	case SSC_READ_POS_LONG_FORM:
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;

	default:
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	if (trans_send_datain(cmd, (char *)data, request_len, 0, ssc_free,
	    True, data) == False) {
		trans_send_complete(cmd, STATUS_BUSY);
	}
}

/*ARGSUSED*/
static void
ssc_rpt_density(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	ssc_density_t		*d;
	ssc_density_media_t	*dm;
	ssc_params_t		*s	= (ssc_params_t *)T10_PARAMS_AREA(cmd);
	size_t			cap	= s->s_size / (1024 * 1024);
	int			medium_type,
				request_len,
				alloc_len;
	void			*data;

	if (s == NULL)
		return;

	if ((cdb[1] & 0xfc) || cdb[2] || cdb[3] || cdb[4] || cdb[5] ||
	    cdb[6] || SAM_CONTROL_BYTE_RESERVED(cdb[9])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	medium_type = cdb[1] & 0x2;
	request_len = (cdb[7] << 8) | cdb[8];
	alloc_len = max(request_len, max(sizeof (*d), sizeof (*dm)));
	if ((data = memalign(sizeof (void *), alloc_len)) == NULL) {
		trans_send_complete(cmd, STATUS_BUSY);
		return;
	}
	if (medium_type == 0) {
		d		= (ssc_density_t *)data;
		d->d_hdr.len	= htons(sizeof (*d) -
		    sizeof (ssc_density_header_t));
		d->d_prim_code	= 1;
		d->d_wrtok	= 1;
		d->d_deflt	= 1;
		d->d_tracks[1]	= 1;
		d->d_capacity[0]	= hibyte(hiword(cap));
		d->d_capacity[1]	= lobyte(hiword(cap));
		d->d_capacity[2]	= hibyte(loword(cap));
		d->d_capacity[3]	= lobyte(loword(cap));
		bcopy(cmd->c_lu->l_common->l_vid, d->d_organization,
		    min(sizeof (d->d_organization),
		    strlen(cmd->c_lu->l_common->l_vid)));
		bcopy(cmd->c_lu->l_common->l_pid, d->d_description,
		    min(sizeof (d->d_description),
		    strlen(cmd->c_lu->l_common->l_pid)));
	} else {
		dm		= (ssc_density_media_t *)data;
		dm->d_hdr.len	= htons(sizeof (*d) -
		    sizeof (ssc_density_header_t));
		bcopy(cmd->c_lu->l_common->l_vid, d->d_organization,
		    min(sizeof (d->d_organization),
		    strlen(cmd->c_lu->l_common->l_vid)));
		bcopy(cmd->c_lu->l_common->l_pid, dm->d_description,
		    min(sizeof (dm->d_description),
		    strlen(cmd->c_lu->l_common->l_pid)));
	}

	if (trans_send_datain(cmd, (char *)data, request_len, 0, ssc_free,
	    True, (emul_handle_t)data) == False) {
		trans_send_complete(cmd, STATUS_BUSY);
	}
}

/*ARGSUSED*/
static void
ssc_write_fm(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	int		marks_requested;
	off_t		next_size;
	ssc_params_t	*s		= (ssc_params_t *)T10_PARAMS_AREA(cmd);
	ssc_obj_mark_t	mark_fm;

	if (s == NULL)
		return;

	if ((cdb[1] & 0xfc) || SAM_CONTROL_BYTE_RESERVED(cdb[5])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	marks_requested = (cdb[2] << 16) | (cdb[3] << 8) | cdb[4];
	while (marks_requested--) {
		/*
		 * Get the last file-mark and update it's size.
		 */
		bcopy((char *)cmd->c_lu->l_common->l_mmap + s->s_cur_fm,
		    &mark_fm, sizeof (mark_fm));
		if (mark_fm.som_sig != SSC_OBJ_SIG) {
			spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
			trans_send_complete(cmd, STATUS_CHECK);
			return;
		}
		next_size		= mark_fm.o_fm.size - s->s_cur_rec;
		mark_fm.o_fm.size	= s->s_cur_rec;
		bcopy(&mark_fm, (char *)cmd->c_lu->l_common->l_mmap +
		    s->s_cur_fm, sizeof (mark_fm));

		/*
		 * Write new mark and update internal location of mark.
		 */
		mark_fm.o_fm.last_obj_id =
		    find_last_obj_id((char *)cmd->c_lu->l_common->l_mmap +
		    s->s_cur_fm, s->s_cur_rec);
		mark_fm.o_fm.bom	= False;
		mark_fm.o_fm.size	= next_size;
		s->s_cur_fm		+= s->s_cur_rec;
		s->s_cur_rec		= sizeof (ssc_obj_mark_t);
		s->s_prev_rec		= s->s_cur_rec;
		bcopy(&mark_fm, (char *)cmd->c_lu->l_common->l_mmap +
		    s->s_cur_fm, sizeof (mark_fm));
		mark_fm.o_fm.size	= 0;
		bcopy(&mark_fm, (char *)cmd->c_lu->l_common->l_mmap +
		    s->s_cur_fm + s->s_cur_rec, sizeof (mark_fm));
	}
	trans_send_complete(cmd, STATUS_GOOD);
}

/*ARGSUSED*/
static void
ssc_locate(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
}

/*ARGSUSED*/
static void
ssc_erase(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	ssc_obj_mark_t	mark;
	ssc_params_t	*s	= (ssc_params_t *)T10_PARAMS_AREA(cmd);

	if (s == NULL)
		return;

	bzero(&mark, sizeof (mark));
	mark.som_sig	= SSC_OBJ_SIG;
	mark.som_type	= SSC_OBJ_TYPE_FM;
	mark.o_fm.bom	= True;
	mark.o_fm.eom	= False;
	mark.o_fm.size	= s->s_size - sizeof (mark);

	bcopy(&mark, (char *)cmd->c_lu->l_common->l_mmap, sizeof (mark));
}

/*ARGSUSED*/
static void
ssc_load(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	ssc_params_t	*s	= T10_PARAMS_AREA(cmd);
	t10_lu_common_t	*lu	= cmd->c_lu->l_common;
	ssc_obj_mark_t	mark;

	/*
	 * SSC-3, revision 02, section 7.2 LOAD/UNLOAD command
	 * Check for various reserve bits.
	 */
	if ((cdb[1] & ~SSC_LOAD_CMD_IMMED) || cdb[2] || cdb[3] ||
	    (cdb[4] & ~(SSC_LOAD_CMD_LOAD | SSC_LOAD_CMD_RETEN |
	    SSC_LOAD_CMD_EOT | SSC_LOAD_CMD_HOLD)) ||
	    SAM_CONTROL_BYTE_RESERVED(cdb[5])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	queue_prt(mgmtq, Q_STE_NONIO, "SSC%x  LUN%d load bits 0x%x",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num, cdb[4]);

	/*
	 * There are four possible actions based on the LOAD and HOLD
	 * bits.
	 */
	switch (cdb[4] & (SSC_LOAD_CMD_LOAD|SSC_LOAD_CMD_HOLD)) {
	case SSC_LOAD_CMD_LOAD|SSC_LOAD_CMD_HOLD:
		/*
		 * Load the media into the system if not already done
		 * so, but do not position tape. The EOT and RETEN should
		 * be zero. Since this emulation currently is always available
		 * we're good to go.
		 */
		break;

	case SSC_LOAD_CMD_LOAD:
		/*
		 * Without the HOLD bit the tape should be positioned at
		 * the beginning of partition 0.
		 */
		s->s_cur_fm	= 0;
		s->s_cur_rec	= sizeof (ssc_obj_mark_t);
		break;

	case SSC_LOAD_CMD_HOLD:
		/*
		 * Without the LOAD bit we leave the tape online, but look
		 * at the RETEN and EOT bits. The RETEN doesn't mean anything
		 * for this virtual tape, but we can reposition to EOT.
		 */
		if (cdb[4] & SSC_LOAD_CMD_EOT) {
			/*CONSTANTCONDITION*/
			while (1) {
				bcopy((char *)lu->l_mmap + s->s_cur_fm, &mark,
				    sizeof (mark));
				if (mark.som_sig != SSC_OBJ_SIG) {
					queue_prt(mgmtq, Q_STE_ERRS,
					    "SSC%x  LUN%d, bad sig mark: "
					    "expected=0x%x, got=0x%x",
					    cmd->c_lu->l_targ->s_targ_num,
					    cmd->c_lu->l_common->l_num,
					    SSC_OBJ_SIG, mark.som_sig);
					spc_sense_create(cmd,
					    KEY_MEDIUM_ERROR, 0);
					trans_send_complete(cmd, STATUS_CHECK);
					return;
				}
				if (mark.som_type != SSC_OBJ_TYPE_FM) {
					queue_prt(mgmtq, Q_STE_ERRS,
					    "SSC%x  LUN%d, bad mark type: "
					    "expected=0x%x, got=0x%x",
					    cmd->c_lu->l_targ->s_targ_num,
					    cmd->c_lu->l_common->l_num,
					    SSC_OBJ_TYPE_FM, mark.som_type);
					spc_sense_create(cmd,
					    KEY_MEDIUM_ERROR, 0);
					trans_send_complete(cmd, STATUS_CHECK);
					return;
				}
				if (mark.o_fm.eom == True)
					break;
				s->s_cur_fm += mark.o_fm.size;
			}
		}
		break;

	case 0:
		/*
		 * Unload the current tape.
		 */

		break;
	}
	trans_send_complete(cmd, STATUS_GOOD);
}

/*ARGSUSED*/
static void
ssc_logsense(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	spc_log_supported_pages_t	p;
	void				*v;

	/*
	 * Reserve bit checks
	 */
	if ((cdb[1] & ~(SSC_LOG_SP|SSC_LOG_PPC)) || cdb[3] || cdb[4] ||
	    SAM_CONTROL_BYTE_RESERVED(cdb[9])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	queue_prt(mgmtq, Q_STE_ERRS, "SSC%x  LUN%d page code 0x%x",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num, cdb[2]);

	switch (cdb[2] & SPC_LOG_PAGE_MASK) {
	case 0:
		if ((v = malloc(sizeof (p))) == NULL) {
			trans_send_complete(cmd, STATUS_BUSY);
			return;
		}
		bzero(&p, sizeof (p));
		p.length[0] = 1;
		bcopy(&p, v, sizeof (p));
		if (trans_send_datain(cmd, (char *)v, sizeof (p), 0, free,
		    True, (emul_handle_t)v) == False) {
			trans_send_complete(cmd, STATUS_BUSY);
		}
		break;

	default:
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0);
		trans_send_complete(cmd, STATUS_CHECK);
		break;
	}
}

/*
 * []------------------------------------------------------------------[]
 * | Support functions for the SSC command set				|
 * []------------------------------------------------------------------[]
 */
static uint32_t
find_last_obj_id(char *file_mark, off_t eod)
{
	ssc_obj_mark_t	rm;
	off_t		offset	= sizeof (ssc_obj_mark_t);
	uint32_t	obj_id	= 0xffffffff;

	bcopy(file_mark + offset, &rm, sizeof (rm));
	while (rm.som_type == SSC_OBJ_TYPE_RM) {
		obj_id = rm.o_rm.obj_id;
		offset += rm.o_rm.size;
		if (offset >= eod)
			break;
		bcopy(file_mark + offset, &rm, sizeof (rm));
	}
	return (obj_id);
}

static void
ssc_setup_tape(ssc_params_t *s, t10_lu_common_t *lu)
{
	ssc_obj_mark_t	mark;

	/*
	 * Add Begin-of-Partition marker
	 */
	bzero(&mark, sizeof (mark));
	mark.som_sig	= SSC_OBJ_SIG;
	mark.som_type	= SSC_OBJ_TYPE_FM;
	mark.o_fm.bom	= True;
	mark.o_fm.eom	= False;
	mark.o_fm.size	= s->s_size - sizeof (mark);
	bcopy(&mark, lu->l_mmap, sizeof (mark));

	/*
	 * Add first file-record with a zero size.
	 */
	bzero(&mark, sizeof (mark));
	mark.som_sig		= SSC_OBJ_SIG;
	mark.som_type		= SSC_OBJ_TYPE_RM;
	mark.o_rm.size		= 0;
	mark.o_rm.obj_id	= 0xffffffff;
	bcopy(&mark, (char *)lu->l_mmap + sizeof (ssc_obj_mark_t),
	    sizeof (mark));

	/*
	 * Add End-of-Partiton marker
	 */
	bzero(&mark, sizeof (mark));
	mark.som_sig	= SSC_OBJ_SIG;
	mark.som_type	= SSC_OBJ_TYPE_FM;
	mark.o_fm.bom	= False;
	mark.o_fm.eom	= True;
	mark.o_fm.size	= 0;
	bcopy(&mark, (char *)lu->l_mmap + s->s_size - sizeof (mark),
	    sizeof (mark));
}

static char *
sense_compression(ssc_params_t *s, char *data)
{
	ssc_data_compression_t	d;

	bzero(&d, sizeof (d));
	d.mode_page.code	= MODE_SENSE_COMPRESSION;
	d.mode_page.length	= sizeof (d) - sizeof (struct mode_page);
	bcopy(&d, data, sizeof (d));

	return (data + sizeof (d));
}

static char *
sense_dev_config(ssc_params_t *s, char *data)
{
	ssc_device_config_t	d;

	bzero(&d, sizeof (d));
	d.mode_page.code	= MODE_SENSE_DEV_CONFIG;
	d.mode_page.length	= sizeof (d) - sizeof (struct mode_page);
	d.lois			= 1;
	d.socf			= 1;
	d.rewind_on_reset	= 1;
	bcopy(&d, data, sizeof (d));

	return (data + sizeof (d));
}

static void
ssc_free(emul_handle_t e)
{
	free(e);
}

/*
 * []----
 * | Command table for SSC emulation. This is at the end of the file because
 * | it's big and ugly. ;-) To make for fast translation to the appropriate
 * | emulation routine we just have a big command table with all 256 possible
 * | entries. Most will report STATUS_CHECK, unsupport operation. By doing
 * | this we can avoid error checking for command range.
 * []----
 */
static scsi_cmd_table_t ssc_table[] = {
	/* 0x00 -- 0x0f */
	{ spc_tur,		NULL,	NULL,		"TEST_UNIT_READY" },
	{ ssc_rewind,	NULL,	NULL,			"REWIND"},
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_request_sense,	NULL,	NULL,		"REQUEST_SENSE" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ ssc_read_limits,	NULL,	NULL,		"READ BLOCK LIMITS"},
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ ssc_read, NULL, ssc_read_cmplt,		"READ(6)" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ ssc_write, ssc_write_data, ssc_write_cmplt,	"WRITE(6)" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0x10 -- 0x1f */
	{ ssc_write_fm,	NULL,	NULL,			"WRITE_FILEMARKS(6)"},
	{ ssc_space,	NULL,	NULL,			"SPACE(6)"},
	{ spc_inquiry, NULL, NULL,			"INQUIRY" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_mselect, spc_mselect_data, NULL,		"MODE_SELECT(6)" },
	{ spc_request_sense,		NULL,	NULL,	"RESERVE" },
	{ spc_request_sense,		NULL,	NULL,	"RELEASE" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ ssc_erase,	NULL,	NULL,			"ERASE(6)"},
	{ ssc_msense,		NULL,	NULL,		"MODE_SENSE(6)" },
	{ ssc_load,	NULL,	NULL,		"LOAD_UNLOAD" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_send_diag,	NULL,	NULL,		"SEND_DIAG" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0x20 -- 0x2f */
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,		NULL,	NULL,	"READ_CAPACITY" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ ssc_read, NULL, ssc_read_cmplt,		"READ_G1" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ ssc_write, ssc_write_data, ssc_write_cmplt,	"WRITE_G1" },
	{ ssc_locate,	NULL,	NULL,			"LOCATE(10)"},
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0x30 -- 0x3f */
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ ssc_read_pos,	NULL,	NULL,			"READ POSITION"},
	{ spc_unsupported,	NULL,	NULL,		"SYNC_CACHE" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0x40 -- 0x4f */
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ ssc_rpt_density,	NULL,	NULL,	"REPORT DENSITY SUPPORT"},
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ ssc_logsense,		NULL,	NULL,		"LOG SENSE" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0x50 -- 0x5f */
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0x60 -- 0x6f */
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0x70 -- 0x7f */
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0x80 -- 0x8f */
	{ ssc_write_fm,	NULL,	NULL,			"WRITE_FILEMARKS(16)"},
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ ssc_read, NULL, ssc_read_cmplt,		"READ_G4" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ ssc_write, ssc_write_data, ssc_write_cmplt,	"WRITE_G4" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0x90 -- 0x9f */
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ ssc_locate,	NULL,	NULL,			"LOCATE(16)"},
	{ ssc_erase,	NULL,	NULL,			"ERASE" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,		"SVC_ACTION_G4" },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0xa0 - 0xaf */
	{ spc_report_luns,	NULL,	NULL,		"REPORT_LUNS" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_report_tpgs,	NULL,	NULL,		"REPORT_TPGS" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0xb0 -- 0xbf */
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0xc0 -- 0xcf */
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0xd0 -- 0xdf */
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0xe0 -- 0xef */
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0xf0 -- 0xff */
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
};
