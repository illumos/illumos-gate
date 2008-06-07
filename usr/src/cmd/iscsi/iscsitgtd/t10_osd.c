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
 * | Implementation of OSD emulation					|
 * |									|
 * | NOTE: At this point in time this file is nothing more than a	|
 * | place holder for the implementation. As the project evolves we'll	|
 * | add more and more functionality.					|
 * []------------------------------------------------------------------[]
 */
#include <sys/types.h>
#include <aio.h>
#include <sys/asynch.h>
#include <sys/mman.h>
#include <stddef.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>

#include <sys/scsi/generic/sense.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/generic/inquiry.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/generic/mode.h>
#include <sys/scsi/generic/dad_mode.h>

#include "t10.h"
#include "t10_spc.h"
#include "t10_osd.h"
#include "utility.h"

/*
 * Forward declarations
 */
static void osd_cmd(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len);
static void osd_data(t10_cmd_t *cmd, emul_handle_t e, size_t offset,
    char *data, size_t data_len);
static scsi_cmd_table_t osd_table[];
static void osd_list(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len);

/*
 * []----
 * | osd_init_common -- Initialize LU data which is common to all I_T_Ls
 * []----
 */
/*ARGSUSED*/
Boolean_t
osd_common_init(t10_lu_common_t *lu)
{
	osd_params_t	*o;
	char		*str;
	tgt_node_t	*node	= lu->l_root;

	if ((o = (osd_params_t *)calloc(1, sizeof (*o))) == NULL)
		return (False);

	if (tgt_find_value_str(node, XML_ELEMENT_SIZE, &str) == True) {
		o->o_size = strtoll(str, NULL, 0);
		free(str);
	} else {
		free(o);
		return (False);
	}

	lu->l_dtype_params = (void *)o;
	return (True);
}

/*ARGSUSED*/
void
osd_common_fini(t10_lu_common_t *lu)
{
	free(lu->l_dtype_params);
}

/*
 * []----
 * | osd_init_per -- Initialize per I_T_L information
 * []----
 */
/*ARGSUSED*/
void
osd_per_init(t10_lu_impl_t *itl)
{
	itl->l_cmd	= osd_cmd;
	itl->l_data	= osd_data;
	itl->l_cmd_table = osd_table;

	/*
	 * The first time an I_T nexus connects to a LU it is supposed
	 * to receive an unit attention upon the first command sent.
	 */
	itl->l_status	= KEY_UNIT_ATTENTION;
	itl->l_asc	= SPC_ASC_PWR_ON;
	itl->l_ascq	= SPC_ASCQ_PWR_ON;
}

/*ARGSUSED*/
void
osd_per_fini(t10_lu_impl_t *itl)
{
}

/*ARGSUSED*/
void
osd_task_mgmt(t10_lu_common_t *lu, TaskOp_t op)
{
}

/*
 * []----
 * | osd_cmd -- start a SCSI command
 * |
 * | This routine is called from within the SAM-3 Task router.
 * []----
 */
static void
osd_cmd(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	scsi_cmd_table_t	*e;

	e = &cmd->c_lu->l_cmd_table[cdb[0]];
#ifdef FULL_DEBUG
	queue_prt(mgmtq, Q_STE_IO, "SBC%x  LUN%d Cmd %s\n",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num,
	    e->cmd_name == NULL ? "(no name)" : e->cmd_name);
#endif
	(*e->cmd_start)(cmd, cdb, cdb_len);
}

/*
 * []----
 * | osd_data -- Data phase for command.
 * |
 * | Normally this is only called for the WRITE command. Other commands
 * | that have a data in phase will probably be short circuited when
 * | we call trans_rqst_dataout() and the data is already available.
 * | At least this is true for iSCSI. FC however will need a DataIn phase
 * | for commands like MODE SELECT and PGROUT.
 * []----
 */
static void
osd_data(t10_cmd_t *cmd, emul_handle_t id, size_t offset, char *data,
    size_t data_len)
{
	scsi_cmd_table_t	*e;

	e = &cmd->c_lu->l_cmd_table[cmd->c_cdb[0]];
#ifdef FULL_DEBUG
	queue_prt(mgmtq, Q_STE_IO, "SBC%x  LUN%d Data %s\n",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num,
	    e->cmd_name);
#endif
	(*e->cmd_data)(cmd, id, offset, data, data_len);
}

/*
 * []------------------------------------------------------------------[]
 * | SCSI Object-Based Storage Device Commands				|
 * | T10/1355-D								|
 * | The following functions implement the emulation of OSD type	|
 * | commands.								|
 * []------------------------------------------------------------------[]
 */
static void
osd_service_action(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	osd_generic_cdb_t	*o;
	uint16_t		service_action;

	/*
	 * debug only -- no need to drop core if someone doesn't play right.
	 */
	assert(cdb_len == sizeof (*o));
	if (cdb_len != sizeof (*o)) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, SPC_ASCQ_INVALID_CDB);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}
	o = (osd_generic_cdb_t *)cdb;
	service_action = o->ocdb_basic.b_service_action[0] << 8 |
	    o->ocdb_basic.b_service_action[1];

	queue_prt(mgmtq, Q_STE_NONIO,
	    "OSD%x  LUN%d service=0x%x, options=0x%x, specific_opts=0x%x,"
	    " fmt=0x%x", cmd->c_lu->l_targ->s_targ_num,
	    cmd->c_lu->l_common->l_num, service_action, o->ocdb_options,
	    o->ocdb_specific_opts, o->ocdb_fmt);

	switch (service_action) {
	case OSD_APPEND:
	case OSD_CREATE:
	case OSD_CREATE_AND_WRITE:
	case OSD_CREATE_COLLECTION:
	case OSD_CREATE_PARTITION:
	case OSD_FLUSH:
	case OSD_FLUSH_COLLECTION:
	case OSD_FLUSH_OSD:
	case OSD_FLUSH_PARTITION:
	case OSD_FORMAT_OSD:
	case OSD_GET_ATTR:
	case OSD_LIST:
		osd_list(cmd, cdb, cdb_len);
		break;

	case OSD_LIST_COLLECTION:
	case OSD_PERFORM_SCSI:
	case OSD_TASK_MGMT:
	default:
		spc_unsupported(cmd, cdb, cdb_len);
		break;
	}
}

/*
 * []----
 * | osd_list -- return a list of objects
 * []----
 */
static void
osd_list(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	osd_cmd_list_t		*o	= (osd_cmd_list_t *)cdb;
	osd_obj_id_t		part;
	osd_list_param_t	*data;
	uint64_t		len, alloc_len;

	part = (uint64_t)o->ocdb_partition_id[0] << 56 |
	    (uint64_t)o->ocdb_partition_id[1] << 48 |
	    (uint64_t)o->ocdb_partition_id[2] << 40 |
	    (uint64_t)o->ocdb_partition_id[3] << 32 |
	    (uint64_t)o->ocdb_partition_id[4] << 24 |
	    (uint64_t)o->ocdb_partition_id[5] << 16 |
	    (uint64_t)o->ocdb_partition_id[6] << 8 |
	    (uint64_t)o->ocdb_partition_id[7];
	len = (uint64_t)o->ocdb_length[0] << 56 |
	    (uint64_t)o->ocdb_length[1] << 48 |
	    (uint64_t)o->ocdb_length[2] << 40 |
	    (uint64_t)o->ocdb_length[3] << 32 |
	    (uint64_t)o->ocdb_length[4] << 24 |
	    (uint64_t)o->ocdb_length[5] << 16 |
	    (uint64_t)o->ocdb_length[6] << 8 |
	    (uint64_t)o->ocdb_length[7];

	if (len == 0) {
		trans_send_complete(cmd, STATUS_GOOD);
		return;
	}

	queue_prt(mgmtq, Q_STE_NONIO, "part=0x%llx, len=0x%llx", part, len);
	alloc_len = MAX(sizeof (*data), len);
	if ((data = calloc(1, alloc_len)) == NULL) {
		trans_send_complete(cmd, STATUS_BUSY);
		return;
	}
	data->op_length[7] = sizeof (*data) - 8;
	if (part == OSD_PARTITION_ROOT)
		data->op_root = 1;

	(void) trans_send_datain(cmd, (char *)data, sizeof (*data), 0, free,
	    True, (emul_handle_t)data);
}

/*
 * []------------------------------------------------------------------[]
 * | Support related functions for OSD					|
 * []------------------------------------------------------------------[]
 */

/*
 * []----
 * | Command table for OSD emulation. This is at the end of the file because
 * | it's big and ugly. ;-) To make for fast translation to the appropriate
 * | emulation routine we just have a big command table with all 256 possible
 * | entries. Most will report STATUS_CHECK, unsupport operation. By doing
 * | this we can avoid error checking for command range or the use of a switch
 * | statement.
 * []----
 */
static scsi_cmd_table_t osd_table[] = {
	/* 0x00 -- 0x0f */
	{ spc_tur,		NULL,	NULL,		"TEST_UNIT_READY" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_request_sense,	NULL,	NULL,		"REQUEST_SENSE" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,		"READ" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,		"WRITE" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },

	/* 0x10 -- 0x1f */
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_inquiry, NULL, NULL,			"INQUIRY" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_mselect, spc_mselect_data, NULL,		"MODE_SELECT" },
	{ spc_unsupported,		NULL,	NULL,	"RESERVE" },
	{ spc_unsupported,		NULL,	NULL,	"RELEASE" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,		NULL,	NULL,	"MODE_SENSE" },
	{ spc_unsupported,	NULL,	NULL,		"START_STOP" },
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
	{ spc_unsupported,	NULL,	NULL,		"READ_G1" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,		"WRITE_G1" },
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
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	"LOG_SENSE" },
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
	{ spc_unsupported,	NULL,	NULL,	"PERSISTENT_IN" },
	{ spc_unsupported,	NULL,	NULL,	"PERSISTENT_OUT" },

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
	{ osd_service_action,	NULL,	NULL,		"SERVICE_ACTION" },

	/* 0x80 -- 0x8f */
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,		"READ_G4" },
	{ spc_unsupported,	NULL,	NULL,	NULL },
	{ spc_unsupported,	NULL,	NULL,		"WRITE_G4" },
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
