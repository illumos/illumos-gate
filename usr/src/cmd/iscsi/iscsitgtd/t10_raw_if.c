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
 * []------------------------------------------------------------------[]
 * | Implementation of SBC-2 emulation					|
 * []------------------------------------------------------------------[]
 */
#include <sys/types.h>
#include <sys/asynch.h>
#include <sys/mman.h>
#include <stddef.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <sys/sysmacros.h>

#include <sys/scsi/generic/sense.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/generic/inquiry.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/generic/mode.h>
#include <sys/scsi/generic/dad_mode.h>
#include <sys/scsi/impl/uscsi.h>

#include "t10.h"
#include "t10_spc.h"
#include "utility.h"
#include "target.h"

typedef struct raw_io {
	t10_aio_t	r_aio;
	t10_cmd_t	*r_cmd;

	uint8_t		*r_cdb;
	char		*r_data;
	size_t		r_cdb_len,
			r_data_len;
	uint64_t	r_offset,
			r_lba;
	size_t		r_lba_cnt;
	uint32_t	r_status;
} raw_io_t;

typedef struct raw_params {
	uint64_t	r_size;
	int		r_dtype;
} raw_params_t;

typedef enum { RawDataToDevice, RawDataFromDevice, NoData } raw_direction_t;

/*
 * Forward declarations
 */
static scsi_cmd_table_t raw_table[];
static void raw_cmd(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len);
static void raw_data(t10_cmd_t *cmd, emul_handle_t id, size_t offset,
    char *data, size_t data_len);
static void raw_free_io(emul_handle_t id);
static void do_dataout(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len,
    size_t opt_data_len);
static raw_io_t *do_datain(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len,
    size_t data_len);
static int do_uscsi(t10_cmd_t *cmd, raw_io_t *io, raw_direction_t dir);
static void raw_read_cmplt(emul_handle_t id);
static void raw_write_cmplt(emul_handle_t e);

/*
 * []----
 * | raw_init_common -- Initialize LU data which is common to all I_T_Ls
 * []----
 */
Boolean_t
raw_common_init(t10_lu_common_t *lu)
{
	tgt_node_t	*node	= lu->l_root;
	char		*str;
	raw_params_t	*r;

	if ((r = (raw_params_t *)calloc(1, sizeof (*r))) == NULL)
		return (False);

	if (tgt_find_value_str(node, XML_ELEMENT_SIZE, &str) == True) {
		r->r_size = strtoll(str, NULL, 0);
		free(str);
	}
	lu->l_dtype_params = (void *)r;
	return (True);
}

void
raw_common_fini(t10_lu_common_t *lu)
{
	free(lu->l_dtype_params);
}

/*
 * []----
 * | raw_init_per -- Initialize per I_T_L information
 * []----
 */
void
raw_per_init(t10_lu_impl_t *itl)
{
	itl->l_cmd	= raw_cmd;
	itl->l_data	= raw_data;
	itl->l_cmd_table = raw_table;

	/*
	 * The first time an I_T nexus connects to a LU it is supposed
	 * to receive an unit attention upon the first command sent.
	 */
	itl->l_status	= KEY_UNIT_ATTENTION;
	itl->l_asc	= 0x29;
	itl->l_ascq	= 0x01;
}

/*ARGSUSED*/
void
raw_per_fini(t10_lu_impl_t *itl)
{
}

/*ARGSUSED*/
void
raw_task_mgmt(t10_lu_common_t *t, TaskOp_t op)
{
}

/*
 * []----
 * | raw_cmd -- start a SCSI command
 * |
 * | This routine is called from within the SAM-3 Task router.
 * []----
 */
static void
raw_cmd(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	scsi_cmd_table_t	*e;
#ifdef FULL_DEBUG
	char			debug[80];
#endif

	e = &cmd->c_lu->l_cmd_table[cdb[0]];
#ifdef FULL_DEBUG
	(void) snprintf(debug, sizeof (debug), "RAW%d  Cmd %s\n",
	    cmd->c_lu->l_common->l_num,
	    e->cmd_name == NULL ? "(no name)" : e->cmd_name);
	queue_str(mgmtq, Q_STE_IO, msg_log, debug);
#endif
	(*e->cmd_start)(cmd, cdb, cdb_len);
}

/*
 * []----
 * | raw_data -- Data phase for command.
 * |
 * | Normally this is only called for the WRITE command. Other commands
 * | that have a data in phase will probably be short circuited when
 * | we call trans_rqst_dataout() and the data is already available.
 * | At least this is true for iSCSI. FC however will need a DataIn phase
 * | for commands like MODE SELECT and PGROUT.
 * []----
 */
static void
raw_data(t10_cmd_t *cmd, emul_handle_t id, size_t offset, char *data,
    size_t data_len)
{
	scsi_cmd_table_t	*e;
#ifdef FULL_DEBUG
	char			debug[80];
#endif

	e = &cmd->c_lu->l_cmd_table[cmd->c_cdb[0]];
#ifdef FULL_DEBUG
	(void) snprintf(debug, sizeof (debug), "RAW%d  Data %s\n",
	    cmd->c_lu->l_common->l_num, e->cmd_name);
	queue_str(mgmtq, Q_STE_IO, msg_log, debug);
#endif
	(*e->cmd_data)(cmd, id, offset, data, data_len);
}

/*
 * []------------------------------------------------------------------[]
 * | The following methods handle special case requirements for the	|
 * | raw devices.							|
 * []------------------------------------------------------------------[]
 */

/*
 * []----
 * | raw_read_tape -- handle SCSI reads from raw tape
 * |
 * | Need to handle reads from SCSI tape differently than LBA devices
 * | for two reasons.
 * |    (1) The command block for tape reads is different than for
 * |	    LBA devices. There's only a count field.
 * |    (2) Since tapes have records it's not possible to break up
 * |	    the read operations in the same manner as LBA devices.
 * |	    All of the data must first be read in from the device
 * |	    and then broken up to fit the transport. This is a slower
 * |	    approach, but nobody expects tapes to be quick. If speed
 * |	    is needed a better approach would be to create a virtual
 * |	    tape device and then stage out the data to the device later.
 * []----
 */
/*ARGSUSED*/
static void
raw_read_tape(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	size_t		req_len;
	size_t		xfer;
	off_t		offset		= 0;
	raw_io_t	*io;
	Boolean_t	last;
	t10_cmd_t	*c;

	req_len = (cdb[2] << 16) | (cdb[3] << 8) | cdb[4];
	if (cdb[1] & 0x1)
		req_len *= 512;

	if (((io = do_datain(cmd, cdb, CDB_GROUP0, req_len)) == NULL) ||
	    (io->r_status != STATUS_GOOD)) {
		if (io != NULL)
			raw_free_io(io);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	while (offset < io->r_data_len) {
		xfer = min(T10_MAX_OUT(cmd), io->r_data_len - offset);
		last = ((offset + xfer) >= io->r_data_len) ? True : False;
		if (last == True)
			c = cmd;
		else
			c = trans_cmd_dup(cmd);

		if (trans_send_datain(c, io->r_data + offset,
		    xfer, offset, raw_free_io, last, io) == False) {
			raw_free_io(io);
			spc_sense_create(c, KEY_HARDWARE_ERROR, 0);
			trans_send_complete(c, STATUS_CHECK);
			return;
		}
		offset += xfer;
	}
}

/*
 * []----
 * | raw_read -- emulation of SCSI READ command
 * []----
 */
/*ARGSUSED*/
static void
raw_read(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	/*LINTED*/
	union scsi_cdb	*u		= (union scsi_cdb *)cdb;
	diskaddr_t	addr;
	off_t		offset		= 0;
	uint32_t	cnt;
	uint32_t	min;
	raw_io_t	*io;
	uint64_t	err_blkno;
	int		sense_len;
	char		debug[80];
	raw_params_t	*r;
	uchar_t		addl_sense_len;
	t10_cmd_t	*c;

	if ((r = (raw_params_t *)T10_PARAMS_AREA(cmd)) == NULL)
		return;

	if (r->r_dtype == DTYPE_SEQUENTIAL) {
		raw_read_tape(cmd, cdb, cdb_len);
		return;
	}

	switch (u->scc_cmd) {
	case SCMD_READ:
		/*
		 * SBC-2 Revision 16, section 5.5
		 * Reserve bit checks
		 */
		if ((cdb[1] & 0xe0) || (cdb[5] & 0x38)) {
			spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
			spc_sense_ascq(cmd, 0x24, 0x00);
			trans_send_complete(cmd, STATUS_CHECK);
			return;
		}

		addr = (diskaddr_t)(uint32_t)GETG0ADDR(u);
		cnt = GETG0COUNT(u);

		/*
		 * SBC-2 Revision 16
		 * Section: 5.5 READ(6) command
		 *	A TRANSFER LENGTH field set to zero specifies
		 *	that 256 logical blocks shall be read.
		 */
		if (cnt == 0)
			cnt = 256;
		break;

	case SCMD_READ_G1:
		/*
		 * SBC-2 Revision 16, section 5.6
		 * Reserve bit checks.
		 */
		if ((cdb[1] & 6) || cdb[6] || (cdb[9] & 0x38)) {
			spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
			spc_sense_ascq(cmd, 0x24, 0x00);
			trans_send_complete(cmd, STATUS_CHECK);
			return;
		}

		addr = (diskaddr_t)(uint32_t)GETG1ADDR(u);
		cnt = GETG1COUNT(u);
		break;

	case SCMD_READ_G4:
		/*
		 * SBC-2 Revision 16, section 5.8
		 * Reserve bit checks
		 */
		if ((cdb[1] & 0x6) || (cdb[10] & 6) || cdb[14] ||
		    (cdb[15] & 0x38)) {
			spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
			spc_sense_ascq(cmd, 0x24, 0x00);
			trans_send_complete(cmd, STATUS_CHECK);
			return;
		}

		addr = GETG4LONGADDR(u);
		cnt = GETG4COUNT(u);
		break;

	default:
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	if ((addr + cnt) > r->r_size) {

		/*
		 * request exceed the capacity of disk
		 * set error block number to capacity + 1
		 */
		err_blkno = r->r_size + 1;

		/*
		 * XXX: What's SBC-2 say about ASC/ASCQ here. Solaris
		 * doesn't care about these values when key is set
		 * to KEY_ILLEGAL_REQUEST.
		 */
		if (err_blkno > FIXED_SENSE_ADDL_INFO_LEN)
			addl_sense_len = INFORMATION_SENSE_DESCR;
		else
			addl_sense_len = 0;

		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, addl_sense_len);
		spc_sense_info(cmd, err_blkno);
		spc_sense_ascq(cmd, 0x21, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);

		(void) snprintf(debug, sizeof (debug),
		    "RAW%d  READ Illegal sector (0x%llx + 0x%x) > 0x%llx",
		    cmd->c_lu->l_common->l_num, addr, cnt, r->r_size);
		queue_str(mgmtq, Q_STE_ERRS, msg_log, debug);
		return;
	}

	cmd->c_lu->l_cmds_read++;
	cmd->c_lu->l_sects_read += cnt;

	if (cnt == 0) {
		trans_send_complete(cmd, STATUS_GOOD);
		return;
	}

	do {
		min = MIN((cnt * 512) - offset, T10_MAX_OUT(cmd));
		if ((offset + min) < (cnt * 512LL))
			c = trans_cmd_dup(cmd);
		else
			c = cmd;
		if ((io = (raw_io_t *)calloc(1, sizeof (*io))) == NULL) {

			/*
			 * We're pretty much dead in the water. If we can't
			 * allocate memory. It's unlikey we'll be able to
			 * allocate a sense buffer or queue the command
			 * up to be sent back to the transport for delivery.
			 */
			spc_sense_create(c, KEY_HARDWARE_ERROR, 0);
			trans_send_complete(c, STATUS_CHECK);
			return;
		}

		io->r_cmd		= c;
		io->r_lba		= addr;
		io->r_lba_cnt		= cnt;
		io->r_offset		= offset;
		io->r_data_len		= min;
		io->r_aio.a_aio_cmplt	= raw_read_cmplt;
		io->r_aio.a_id		= io;

#ifdef FULL_DEBUG
		(void) snprintf(debug, sizeof (debug),
		    "RAW%d  blk 0x%llx, cnt %d, offset 0x%llx, size %d",
		    c->c_lu->l_common->l_num, addr, cnt, io->r_offset, min);
		queue_str(mgmtq, Q_STE_IO, msg_log, debug);
#endif
		if ((io->r_data = (char *)malloc(min)) == NULL) {
			err_blkno = addr + ((offset + 511) / 512);
			if (err_blkno > FIXED_SENSE_ADDL_INFO_LEN)
				sense_len = INFORMATION_SENSE_DESCR;
			else
				sense_len = 0;
			spc_sense_create(c, KEY_HARDWARE_ERROR,
			    sense_len);
			spc_sense_info(c, err_blkno);
			trans_send_complete(c, STATUS_CHECK);
			return;
		}
		trans_aioread(c, io->r_data, min, (addr * 512LL) +
		    (off_t)io->r_offset, &io->r_aio);
		offset += min;
	} while (offset < (off_t)(cnt * 512));
}

/*
 * []----
 * | raw_read_cmplt -- Once we have the data, need to send it along.
 * []----
 */
static void
raw_read_cmplt(emul_handle_t id)
{
	raw_io_t	*io		= (raw_io_t *)id;
	int		sense_len;
	uint64_t	err_blkno;
	t10_cmd_t	*cmd		= io->r_cmd;
	Boolean_t	last;

	if (io->r_aio.a_aio.aio_return != io->r_data_len) {
		err_blkno = io->r_lba + ((io->r_offset + 511) / 512);
		cmd->c_resid = (io->r_lba_cnt * 512) - io->r_offset;
		if (err_blkno > FIXED_SENSE_ADDL_INFO_LEN)
			sense_len = INFORMATION_SENSE_DESCR;
		else
			sense_len = 0;
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, sense_len);
		spc_sense_info(cmd, err_blkno);
		trans_send_complete(cmd, STATUS_CHECK);
		raw_free_io(io);
		return;
	}

	last = ((io->r_offset + io->r_data_len) < (io->r_lba_cnt * 512LL)) ?
	    False : True;
	if (trans_send_datain(cmd, io->r_data, io->r_data_len,
	    io->r_offset, raw_free_io, last, io) == False) {
		raw_free_io(io);
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		trans_send_complete(cmd, STATUS_CHECK);
	}
}

/*ARGSUSED*/
static void
raw_write_tape(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	size_t		request_len;
	size_t		xfer;
	raw_io_t	*io;

	request_len	= (cdb[2] << 16) | (cdb[3] << 8) | cdb[4];
	request_len	*= (cdb[1] & 0x1) ? 512 : 1;

	if ((io = calloc(1, sizeof (*io))) == NULL) {
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}
	if ((io->r_data = malloc(request_len)) == NULL) {
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		trans_send_complete(cmd, STATUS_CHECK);
	}
	io->r_data_len		= request_len;
	io->r_cmd		= cmd;

	xfer = min(T10_MAX_OUT(cmd), request_len);
	(void) trans_rqst_dataout(cmd, io->r_data, xfer, io->r_offset, io,
	    raw_free_io);
}

/*ARGSUSED*/
void
raw_write_tape_data(t10_cmd_t *cmd, emul_handle_t id, size_t offset, char *data,
    size_t data_len)
{
	raw_io_t	*io = (raw_io_t *)id;
	size_t		xfer;

	if ((io->r_offset + data_len) < io->r_data_len) {
		io->r_offset += data_len;
		xfer = min(T10_MAX_OUT(cmd), io->r_data_len - io->r_offset);
		(void) trans_rqst_dataout(cmd, io->r_data + io->r_offset, xfer,
		    io->r_offset, io, raw_free_io);
		return;
	} else {
		trans_send_complete(cmd, do_uscsi(cmd, io, RawDataToDevice));
	}
}

/*
 * []----
 * | raw_write -- implement a SCSI write command.
 * []----
 */
/*ARGSUSED*/
static void
raw_write(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	/*LINTED*/
	union scsi_cdb	*cdbp		= (union scsi_cdb *)cdb;
	off_t		addr;
	uint64_t	err_blkno;
	uint32_t	cnt;
	uchar_t		addl_sense_len;
	char		debug[80]; /* debug */
	raw_params_t	*r;
	raw_io_t	*io;
	size_t		max_out;

	if ((r = (raw_params_t *)T10_PARAMS_AREA(cmd)) == NULL)
		return;

	if (r->r_dtype == DTYPE_SEQUENTIAL) {
		raw_write_tape(cmd, cdb, cdb_len);
		return;
	}

	switch (cdb[0]) {
	case SCMD_WRITE:
		/*
		 * SBC-2 revision 16, section 5.24
		 * Reserve bit checks.
		 */
		if ((cdb[1] & 0xe0) || (cdb[5] & 0x38)) {
			spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
			spc_sense_ascq(cmd, 0x24, 0x00);
			trans_send_complete(cmd, STATUS_CHECK);
			return;
		}
		addr = (off_t)cdbp->g0_addr2 << 16 |
		    (off_t)cdbp->g0_addr1 << 8 | (off_t)cdbp->g0_addr0;
		cnt = cdbp->g0_count0;
		/*
		 * SBC-2 Revision 16/Section 5.24 WRITE(6)
		 * A TRANSFER LENGHT of 0 indicates that 256 logical blocks
		 * shall be written.
		 */
		if (cnt == 0)
			cnt = 256;
		break;

	case SCMD_WRITE_G1:
		/*
		 * SBC-2 revision 16, section 5.25
		 * Reserve bit checks.
		 */
		if ((cdb[1] & 0x6) || cdb[6] || (cdb[9] & 0x38)) {
			spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
			spc_sense_ascq(cmd, 0x24, 0x00);
			trans_send_complete(cmd, STATUS_CHECK);
			return;
		}
		addr = (off_t)cdbp->g1_addr3 << 24 |
		    (off_t)cdbp->g1_addr2 << 16 |
		    (off_t)cdbp->g1_addr1 << 8 |
		    (off_t)cdbp->g1_addr0;
		cnt = cdbp->g1_count1 << 8 | cdbp->g1_count0;
		break;

	case SCMD_WRITE_G4:
		/*
		 * SBC-2 revision 16, section 5.27
		 * Reserve bit checks.
		 */
		if ((cdb[1] & 0x6) || cdb[14] || (cdb[15] & 0x38)) {
			spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
			spc_sense_ascq(cmd, 0x24, 0x00);
			trans_send_complete(cmd, STATUS_CHECK);
			return;
		}
		addr = (off_t)(cdbp->g4_addr3 & 0xff) << 56 |
		    (off_t)(cdbp->g4_addr2 & 0xff) << 48 |
		    (off_t)(cdbp->g4_addr1 & 0xff) << 40 |
		    (off_t)(cdbp->g4_addr0 & 0xff) << 32 |
		    (off_t)(cdbp->g4_addtl_cdb_data3 & 0xff) << 24 |
		    (off_t)(cdbp->g4_addtl_cdb_data2 & 0xff) << 16 |
		    (off_t)(cdbp->g4_addtl_cdb_data1 & 0xff) << 8 |
		    (off_t)(cdbp->g4_addtl_cdb_data0 & 0xff);
		cnt = cdbp->g4_count3 << 24 | cdbp->g4_count2 << 16 |
		    cdbp->g4_count1 << 8 | cdbp->g4_count0;
		break;

	default:
		queue_str(mgmtq, Q_STE_ERRS, msg_log,
		    "Unprocessed WRITE type");
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, 0x24, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;

	}

	if ((addr < 0) || ((addr + cnt) > r->r_size)) {

		/*
		 * request exceed the capacity of disk
		 * set error block number to capacity + 1
		 */
		err_blkno = r->r_size + 1;

		/*
		 * XXX: What's SBC-2 say about ASC/ASCQ here. Solaris
		 * doesn't care about these values when key is set
		 * to KEY_ILLEGAL_REQUEST.
		 */
		if (err_blkno > FIXED_SENSE_ADDL_INFO_LEN)
			addl_sense_len = INFORMATION_SENSE_DESCR;
		else
			addl_sense_len = 0;

		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, addl_sense_len);
		spc_sense_info(cmd, err_blkno);
		spc_sense_ascq(cmd, 0x21, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);

		(void) snprintf(debug, sizeof (debug),
		    "RAW%d  WRITE Illegal sector (0x%llx + 0x%x) > 0x%llx",
		    cmd->c_lu->l_common->l_num, addr, cnt, r->r_size);
		queue_str(mgmtq, Q_STE_ERRS, msg_log, debug);
		return;
	}

	if (cnt == 0) {
		trans_send_complete(cmd, STATUS_GOOD);
		return;
	}

	io = (raw_io_t *)cmd->c_emul_id;
	if (io == NULL) {
		if ((io = (raw_io_t *)calloc(1, sizeof (*io))) == NULL) {
			spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
			trans_send_complete(cmd, STATUS_CHECK);
			return;
		}
		io->r_lba		= addr;
		io->r_lba_cnt		= cnt;
		io->r_cmd		= cmd;
		io->r_aio.a_aio_cmplt	= raw_write_cmplt;
		io->r_aio.a_id		= io;

		/*
		 * Only update the statistics the first time through
		 * for this particular command. If the requested transfer
		 * is larger than the transport can handle this routine
		 * will be called many times.
		 */
		cmd->c_lu->l_cmds_write++;
		cmd->c_lu->l_sects_write += cnt;
	}

	/*
	 * If a transport sets the maximum output value to zero we'll
	 * just request the entire amount. Otherwise, transfer no more
	 * than the maximum output or the reminder, whichever is less.
	 */
	max_out = cmd->c_lu->l_targ->s_maxout;
	io->r_data_len = max_out ? MIN(max_out,
	    (cnt * 512) - io->r_offset) : (cnt * 512);

#ifdef FULL_DEBUG
	(void) snprintf(debug, sizeof (debug),
	    "RAW%d  blk 0x%llx, cnt %d, offset 0x%llx, size %d",
	    cmd->c_lu->l_common->l_num, addr, cnt, io->r_offset,
	    io->r_data_len);
	queue_str(mgmtq, Q_STE_IO, msg_log, debug);
#endif

	if ((io->r_data = (char *)malloc(io->r_data_len)) == NULL) {

		/*
		 * NOTE: May need a different ASC code
		 */
		err_blkno = addr + ((io->r_offset + 511) / 512);
		if (err_blkno > FIXED_SENSE_ADDL_INFO_LEN)
			addl_sense_len = INFORMATION_SENSE_DESCR;
		else
			addl_sense_len = 0;

		spc_sense_create(cmd, KEY_HARDWARE_ERROR, addl_sense_len);
		spc_sense_info(cmd, err_blkno);
		trans_send_complete(cmd, STATUS_CHECK);
		return;

	}
	if (trans_rqst_dataout(cmd, io->r_data, io->r_data_len, io->r_offset,
	    io, raw_free_io) == False) {
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		trans_send_complete(cmd, STATUS_CHECK);
	}
}

/*
 * []----
 * | raw_write_data -- store a chunk of data from the transport
 * []----
 */
/*ARGSUSED*/
void
raw_write_data(t10_cmd_t *cmd, emul_handle_t id, size_t offset, char *data,
    size_t data_len)
{
	raw_io_t	*io	= (raw_io_t *)id;
	raw_params_t	*r	= T10_PARAMS_AREA(cmd);

	if (r == NULL)
		return;

	if (r->r_dtype == DTYPE_SEQUENTIAL) {
		raw_write_tape_data(cmd, id, offset, data, data_len);
		return;
	}

	trans_aiowrite(cmd, data, data_len, (io->r_lba * 512) +
	    (off_t)io->r_offset, &io->r_aio);
}

/*
 * []----
 * | raw_write_cmplt -- deal with end game of write
 * |
 * | See if all of the data for this write operation has been dealt
 * | with. If so, send a final acknowledgement back to the transport.
 * | If not, update the offset, calculate the next transfer size, and
 * | start the process again.
 * []---
 */
static void
raw_write_cmplt(emul_handle_t e)
{
	raw_io_t	*io	= (raw_io_t *)e;
	t10_cmd_t	*cmd	= io->r_cmd;

	if ((io->r_offset + io->r_data_len) < (io->r_lba_cnt * 512)) {
		free(io->r_data);

		io->r_offset	+= io->r_data_len;
		io->r_data_len	= MIN(cmd->c_lu->l_targ->s_maxout,
		    (io->r_lba_cnt * 512) - io->r_offset);
		raw_write(cmd, cmd->c_cdb, cmd->c_cdb_len);
		return;
	}
	trans_send_complete(cmd, STATUS_GOOD);
}

static void
raw_reserve(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	raw_io_t	*io;

	if ((io = do_datain(cmd, cdb, CDB_GROUP0, 0)) == NULL) {
		trans_send_complete(cmd, STATUS_CHECK);
	} else {
		trans_send_complete(cmd, io->r_status);
		raw_free_io(io);
	}
}

static void
raw_release(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	raw_io_t	*io;

	if ((io = do_datain(cmd, cdb, CDB_GROUP0, 0)) == NULL) {
		trans_send_complete(cmd, STATUS_CHECK);
	} else {
		trans_send_complete(cmd, io->r_status);
		raw_free_io(io);
	}
}

static void
raw_persist_in(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	raw_io_t	*io;
	uint32_t	len;

	len = (cdb[7] << 8) | cdb[8];
	if ((io = do_datain(cmd, cdb, CDB_GROUP1, len)) == NULL) {
		trans_send_complete(cmd, STATUS_CHECK);
	} else {
		if (trans_send_datain(cmd, io->r_data, io->r_data_len, 0,
		    raw_free_io, True, io) == False) {
			spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
			trans_send_complete(cmd, STATUS_CHECK);
		}
	}
}

static void
raw_persist_out(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	size_t		len;

	len = (cdb[5] << 24) | (cdb[6] << 16) | (cdb[7] << 8) | cdb[8];
	do_dataout(cmd, cdb, cdb_len, len);
}

/*ARGSUSED*/
static void
raw_persist_data(t10_cmd_t *cmd, emul_handle_t id, size_t offset, char *data,
    size_t data_len)
{
	raw_io_t	*io = (raw_io_t *)id;
	trans_send_complete(cmd, do_uscsi(cmd, io, RawDataToDevice));
}

static void
raw_msense(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	raw_io_t	*io;
	int		len;

	switch (cdb[0]) {
	case SCMD_MODE_SENSE:
		len = cdb[4];
		break;

	case SCMD_MODE_SENSE_G1:
		len = (cdb[7] << 8) | cdb[8];
		break;
	}

	if (((io = do_datain(cmd, cdb, CDB_GROUP0, len)) == NULL) ||
	    (io->r_status != STATUS_GOOD)) {
		if (io != NULL)
			raw_free_io(io);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}
	if (trans_send_datain(cmd, io->r_data, io->r_data_len, 0,
	    raw_free_io, True, io) == False) {
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		trans_send_complete(cmd, STATUS_CHECK);
	}
}

static void
raw_tur(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	raw_io_t	*io;

	if ((io = do_datain(cmd, cdb, CDB_GROUP0, 0)) == NULL) {
		trans_send_complete(cmd, STATUS_CHECK);
	} else {
		trans_send_complete(cmd, io->r_status);
		raw_free_io(io);
	}
}

static void
raw_request_sense(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	raw_io_t	*io;

	if (((io = do_datain(cmd, cdb, CDB_GROUP0, cdb[4])) == NULL) ||
	    (io->r_status != STATUS_GOOD)) {
		if (io != NULL)
			raw_free_io(io);
		trans_send_complete(cmd, STATUS_CHECK);
	} else {
		if (trans_send_datain(cmd, io->r_data, io->r_data_len, 0,
		    raw_free_io, True, io) == False) {
			spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
			trans_send_complete(cmd, STATUS_CHECK);
		}
	}
}

static void
raw_inquiry(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	raw_io_t		*io;
	uint32_t		len;
	struct scsi_inquiry	inq;
	raw_params_t		*r;

	if ((r = (raw_params_t *)T10_PARAMS_AREA(cmd)) == NULL)
		return;

	len = (cdb[3] << 8) | cdb[4];
	if (((io = do_datain(cmd, cdb, CDB_GROUP0, len)) == NULL) ||
	    (io->r_status != STATUS_GOOD)) {
		if (io != NULL)
			raw_free_io(io);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	if ((cdb[1] & 1) == 0) {
		bcopy(io->r_data, &inq, sizeof (inq));
		r->r_dtype = inq.inq_dtype;
	}
	if (trans_send_datain(cmd, io->r_data, io->r_data_len, 0,
	    raw_free_io, True, io) == False) {
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		trans_send_complete(cmd, STATUS_CHECK);
	}
}

static void
raw_mselect(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	int len;

	switch (cdb[0]) {
	case SCMD_MODE_SELECT:
		len	= cdb[4];
		cdb_len	= CDB_GROUP0;
		break;

	case SCMD_MODE_SELECT_G1:
		len	= (cdb[7] << 8) | cdb[8];
		cdb_len	= CDB_GROUP1;
		break;
	}
	do_dataout(cmd, cdb, cdb_len, len);
}

/*ARGSUSED*/
static void
raw_mselect_data(t10_cmd_t *cmd, emul_handle_t id, size_t offset, char *data,
    size_t data_len)
{
	raw_io_t	*io = (raw_io_t *)id;
	trans_send_complete(cmd, do_uscsi(cmd, io, RawDataToDevice));
}

static void
raw_startstop(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	raw_io_t	*io;

	if ((io = do_datain(cmd, cdb, CDB_GROUP0, 0)) == NULL) {
		trans_send_complete(cmd, STATUS_CHECK);
	} else {
		trans_send_complete(cmd, io->r_status);
		raw_free_io(io);
	}
}

static void
raw_rewind(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	raw_io_t	*io;

	if ((io = do_datain(cmd, cdb, CDB_GROUP0, 0)) == NULL) {
		trans_send_complete(cmd, STATUS_CHECK);
	} else {
		trans_send_complete(cmd, io->r_status);
		raw_free_io(io);
	}
}

static void
raw_send_diag(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	int len;

	len = (cdb[3] << 8) | cdb[4];
	do_dataout(cmd, cdb, CDB_GROUP0, len);
}

/*ARGSUSED*/
static void
raw_send_diag_data(t10_cmd_t *cmd, emul_handle_t id, size_t offset,
    char *data, size_t data_len)
{
	raw_io_t	*io = (raw_io_t *)id;
	trans_send_complete(cmd, do_uscsi(cmd, io, RawDataToDevice));
}

static void
raw_recap(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	struct scsi_capacity	cap;
	raw_io_t		*io;
	raw_params_t		*r;

	if ((r = (raw_params_t *)T10_PARAMS_AREA(cmd)) == NULL)
		return;

	if (((io = do_datain(cmd, cdb, CDB_GROUP1, sizeof (cap))) == NULL) ||
	    (io->r_status != STATUS_GOOD)) {
		if (io != NULL)
			raw_free_io(io);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	bcopy(io->r_data, &cap, sizeof (cap));
	/*
	 * Currently there's a bug in ZFS which doesn't report a capacity
	 * for any of the volumes. This means that when using ZFS the
	 * administrator must supply the device size.
	 */
	if (cap.capacity != 0)
		r->r_size = cap.capacity;
	if (trans_send_datain(cmd, io->r_data, io->r_data_len, 0,
	    raw_free_io, True, io) == False) {
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		trans_send_complete(cmd, STATUS_CHECK);
	}
}

static void
raw_service_actiong4(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	raw_io_t	*io;
	uint32_t	len;
	struct scsi_capacity_16	cap16;
	raw_params_t		*r;

	if ((r = (raw_params_t *)T10_PARAMS_AREA(cmd)) == NULL)
		return;

	len = (cdb[10] << 24) | (cdb[11] << 16) | (cdb[12] << 8) | cdb[13];
	if (((io = do_datain(cmd, cdb, CDB_GROUP4, len)) == NULL) ||
	    (io->r_status != STATUS_GOOD)) {
		if (io != NULL)
			raw_free_io(io);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	bcopy(io->r_data, &cap16, sizeof (cap16));
	/*
	 * Currently there's a bug in ZFS which doesn't report a capacity
	 * for any of the volumes. This means that when using ZFS the
	 * administrator must supply the device size.
	 */
	if (cap16.sc_capacity != 0)
		r->r_size = cap16.sc_capacity;
	if (trans_send_datain(cmd, io->r_data, io->r_data_len, 0,
	    raw_free_io, True, io) == False) {
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		trans_send_complete(cmd, STATUS_CHECK);
	}
}

static void
raw_synccache(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	raw_io_t	*io;

	if ((io = do_datain(cmd, cdb, CDB_GROUP1, 0)) == NULL) {
		trans_send_complete(cmd, STATUS_CHECK);
	} else {
		trans_send_complete(cmd, io->r_status);
		raw_free_io(io);
	}
}

static void
raw_write_fm(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	raw_io_t	*io;

	if ((io = do_datain(cmd, cdb, CDB_GROUP0, 0)) == NULL) {
		trans_send_complete(cmd, STATUS_CHECK);
	} else {
		trans_send_complete(cmd, io->r_status);
		raw_free_io(io);
	}
}

static void
raw_report_tpgs(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	raw_io_t	*io;
	uint32_t	len;

	len = (cdb[6] << 24) | (cdb[7] << 16) | (cdb[8] << 8) | cdb[9];
	if (((io = do_datain(cmd, cdb, CDB_GROUP5, len)) == NULL) ||
	    (io->r_status != STATUS_GOOD)) {
		if (io != NULL)
			raw_free_io(io);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}
	if (trans_send_datain(cmd, io->r_data, io->r_data_len, 0,
	    raw_free_io, True, io) == False) {
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		trans_send_complete(cmd, STATUS_CHECK);
	}
}

static void
raw_read_limits(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	raw_io_t	*io;

	/*
	 * spec defines this command to return 6 bytes of data
	 */
	if (((io = do_datain(cmd, cdb, CDB_GROUP0, 6)) == NULL) ||
	    (io->r_status != STATUS_GOOD)) {
		if (io != NULL)
			raw_free_io(io);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}
	if (trans_send_datain(cmd, io->r_data, io->r_data_len, 0,
	    raw_free_io, True, io) == False) {
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		trans_send_complete(cmd, STATUS_CHECK);
	}
}

/*
 * []------------------------------------------------------------------[]
 * | Support related functions for raw devices				|
 * []------------------------------------------------------------------[]
 */

static void
do_dataout(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len, size_t opt_data_len)
{
	char		*opt_data	= NULL;
	raw_io_t	*io;

	if ((io = calloc(1, sizeof (*io))) == NULL) {
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}
	if ((opt_data_len != 0) &&
	    ((opt_data = malloc(opt_data_len)) == NULL)) {
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}
	io->r_cdb	= cdb;
	io->r_cdb_len	= cdb_len;
	io->r_data	= opt_data;
	io->r_data_len	= opt_data_len;
	if (trans_rqst_dataout(cmd, opt_data, opt_data_len, 0, io,
	    raw_free_io) == False) {
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		trans_send_complete(cmd, STATUS_CHECK);
	}
}

static raw_io_t *
do_datain(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len, size_t data_len)
{
	raw_io_t	*io;

	if ((io = calloc(1, sizeof (*io))) == NULL) {
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		return (NULL);
	}

	io->r_cdb	= cdb;
	io->r_cdb_len	= cdb_len;
	io->r_data_len	= data_len;
	if ((data_len != 0) && ((io->r_data = malloc(data_len)) == NULL)) {
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		free(io);
		return (NULL);
	}
	(void) do_uscsi(cmd, io, data_len == 0 ? NoData : RawDataFromDevice);
	return (io);
}

static int
do_uscsi(t10_cmd_t *cmd, raw_io_t *io, raw_direction_t dir)
{
	struct uscsi_cmd	u;
	uchar_t			sense_buf[128];

	bzero(&u, sizeof (u));
	u.uscsi_cdb	= (caddr_t)io->r_cdb;
	u.uscsi_cdblen	= io->r_cdb_len;
	u.uscsi_bufaddr	= io->r_data;
	u.uscsi_buflen	= io->r_data_len;
	u.uscsi_flags	= ((dir == RawDataToDevice) ? USCSI_WRITE :
	    (dir == RawDataFromDevice) ? USCSI_READ : 0) | USCSI_RQENABLE;
	u.uscsi_rqbuf	= (char *)sense_buf;
	u.uscsi_rqlen	= sizeof (sense_buf);

	if ((ioctl(cmd->c_lu->l_common->l_fd, USCSICMD, &u) == 0) &&
	    (u.uscsi_status == 0)) {
		io->r_status = 0;
		return (0);
	}
	queue_prt(mgmtq, Q_STE_ERRS,
	    "RAW%d  LUN%d USCSICMD errno %d, cmd_status %d, rqstatus %d, "
	    "rqresid %d",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num, errno,
	    u.uscsi_status, u.uscsi_rqstatus, u.uscsi_rqresid);

	if ((u.uscsi_rqlen - u.uscsi_rqresid) <
	    sizeof (struct scsi_extended_sense)) {
		queue_prt(mgmtq, Q_STE_ERRS,
		    "RAW%x  LUN%d -- No sense data, got=%d, needed=%d",
		    cmd->c_lu->l_targ->s_targ_num,
		    cmd->c_lu->l_common->l_num,
		    u.uscsi_rqlen - u.uscsi_rqresid,
		    sizeof (struct scsi_extended_sense));
		spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
		io->r_status = STATUS_CHECK;
		return (STATUS_CHECK);
	} else {
		spc_sense_raw(cmd, sense_buf, u.uscsi_rqlen - u.uscsi_rqresid);
		io->r_status = u.uscsi_status;
		return (u.uscsi_status);
	}
}

static void
raw_free_io(emul_handle_t id)
{
	raw_io_t	*io = (raw_io_t *)id;

	if (io->r_data_len)
		free(io->r_data);
	free(io);
}

/*
 * []----
 * | Command table for LBA emulation. This is at the end of the file because
 * | it's big and ugly. ;-) To make for fast translation to the appropriate
 * | emulation routine we just have a big command table with all 256 possible
 * | entries. Most will report STATUS_CHECK, unsupport operation. By doing
 * | this we can avoid error checking for command range.
 * []----
 */
static scsi_cmd_table_t raw_table[] = {
	/* 0x00 -- 0x0f */
	{ raw_tur,		NULL,	NULL,		"TEST_UNIT_READY" },
	{ raw_rewind,	NULL,	NULL,			"REWIND" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_request_sense,	NULL,	NULL,		"REQUEST_SENSE" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_read_limits,	NULL,	NULL,		"READ_LIMITS" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_read, NULL, NULL,		"READ" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_write, raw_write_data, NULL,	"WRITE" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0x10 -- 0x1f */
	{ raw_write_fm,	NULL,	NULL,			"WRITE_FILEMARKS" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_inquiry, NULL, NULL,			"INQUIRY" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_mselect, raw_mselect_data, NULL,		"MODE_SELECT" },
	{ raw_reserve,		NULL,	NULL,		"RESERVE" },
	{ raw_release,		NULL,	NULL,		"RELEASE" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_msense,		NULL,	NULL,		"MODE_SENSE" },
	{ raw_startstop,	NULL,	NULL,		"START_STOP" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_send_diag,	raw_send_diag_data,	NULL,	"SEND_DIAG" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0x20 -- 0x2f */
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_recap,		NULL,	NULL,		"READ_CAPACITY" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_read, NULL, NULL,		"READ_G1" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_write, raw_write_data, NULL,	"WRITE_G1" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0x30 -- 0x3f */
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_synccache,	NULL,	NULL,		"SYNC_CACHE" },
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

	/* 0x50 -- 0x5f */
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_mselect,	raw_mselect_data,	NULL,	"MODE_SELECT" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_msense,	NULL,	NULL,	"MODE_SENSE" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_persist_in,	NULL,	NULL,	"PERSISTENT_RESERVE_IN" },
	{ raw_persist_out, raw_persist_data, NULL, "PERSISTENT_RESERVE_OUT" },

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
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_read, NULL, NULL,		"READ_G4" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_write, raw_write_data, NULL,	"WRITE_G4" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0x90 -- 0x9f */
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
	{ raw_service_actiong4,	NULL,	NULL,		"SVC_ACTION_G4" },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0xa0 - 0xaf */
	{ spc_report_luns,	NULL,	NULL,		"REPORT_LUNS" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ raw_report_tpgs,	NULL,	NULL,		"REPORT_TPGS" },
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
