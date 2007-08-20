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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * []------------------------------------------------------------------[]
 * | Implementation of SPC-3 Persistent Reserve emulation		|
 * []------------------------------------------------------------------[]
 */
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/asynch.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#include <sys/scsi/generic/sense.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/generic/inquiry.h>
#include <sys/scsi/generic/mode.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/generic/persist.h>

#include "t10.h"
#include "t10_spc.h"
#include "t10_spc_pr.h"
#include "t10_sbc.h"
#include "target.h"

/*
 * External declarations
 */
void spc_free(emul_handle_t id);
void sbc_cmd(t10_cmd_t *, uint8_t *, size_t);
void sbc_cmd_reserved(t10_cmd_t *, uint8_t *, size_t);

extern target_queue_t *mgmtq;

/*
 * Forward declarations
 */
static
    spc_pr_rsrv_t *spc_pr_rsrv_find(scsi3_pgr_t *, uint64_t, uint64_t, char *);
static
    spc_pr_rsrv_t *spc_pr_rsrv_alloc(scsi3_pgr_t *, uint64_t, uint64_t, char *,
    uint8_t, uint8_t);
static
    spc_pr_key_t *spc_pr_key_find(scsi3_pgr_t *, uint64_t, uint64_t, char *);
static
    spc_pr_key_t *spc_pr_key_alloc(scsi3_pgr_t *, uint64_t, uint64_t, char *);

static void spc_pr_rsrv_release(t10_cmd_t *, scsi3_pgr_t *, spc_pr_rsrv_t *);
static void spc_pr_key_free(scsi3_pgr_t *, spc_pr_key_t *);
static void spc_pr_rsrv_free(scsi3_pgr_t *, spc_pr_rsrv_t *);
static void spc_pr_erase(scsi3_pgr_t *);
static void spc_pr_key_rsrv_init(scsi3_pgr_t *);

static int spc_pr_register(t10_cmd_t *, void *, size_t);
static int spc_pr_reserve(t10_cmd_t *, void *, size_t);
static int spc_pr_release(t10_cmd_t *, void *, size_t);
static int spc_pr_clear(t10_cmd_t *, void *, size_t);
static int spc_pr_preempt(t10_cmd_t *, void *, size_t);
static int spc_pr_register_and_move(t10_cmd_t *, void *, size_t);

static int spc_pr_in_readkeys(char *, scsi3_pgr_t *, void *, uint16_t);
static int spc_pr_in_readrsrv(char *, scsi3_pgr_t *, void *, uint16_t);
static int spc_pr_in_repcap(char *, scsi3_pgr_t *, void *, uint16_t);
static int spc_pr_in_fullstat(char *, scsi3_pgr_t *, void *, uint16_t);

static int spc_pgr_isconflict(uint8_t *, uint_t);
Boolean_t spc_pr_write(t10_cmd_t *);

/*
 * []----
 * | spc_pgr_check --  PERSISTENT_RESERVE {IN|OUT} check of I_T_L
 * |	Refer to SPC-3, Section ?.?, Tables ?? and ??
 * []----
 */
Boolean_t
spc_pgr_check(t10_cmd_t *cmd, uint8_t *cdb)
{
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	scsi3_pgr_t		*pgr = &res->res_scsi_3_pgr;
	spc_pr_rsrv_t		*rsrv;
	Boolean_t		conflict = False;

	/*
	 * Check reservation commands.
	 */
	switch (cdb[0]) {
		/*
		 * Always dis-allow these commands.
		 */
		case SCMD_RESERVE:
		case SCMD_RESERVE_G1:
		case SCMD_RELEASE:
		case SCMD_RELEASE_G1:
			conflict = True;
			goto done;

		/*
		 * Always allow these commands.
		 */
		case SCMD_PERSISTENT_RESERVE_IN:
		case SCMD_PERSISTENT_RESERVE_OUT:
			conflict = False;
			goto done;
	}

	/*
	 * If no reservations exist, allow all remaining command types.
	 */
	assert(res->res_type == RT_PGR);
	if (pgr->pgr_numrsrv == 0) {
		conflict = False;
		goto done;
	}

	/*
	 * At this point we know there is at least one reservation.
	 * If there is no reservation set on this service delivery
	 * port then conflict all remaining command types.
	 */
	if (!(rsrv = spc_pr_rsrv_find(pgr, 0, 0, T10_PGR_TID(cmd)))) {
		queue_prt(mgmtq, Q_PR_IO, "PGR Reserved on other port\n",
		    "\t%016x:%s\n", T10_PGR_ISID(cmd), T10_PGR_TID(cmd));
		conflict = True;
		goto done;
	}

	/*
	 * Check the command against the reservation type for this port.
	 */
	switch (rsrv->r_type) {
		case PGR_TYPE_WR_EX:
		case PGR_TYPE_EX_AC:
			if (T10_PGR_ISID(cmd) == rsrv->r_isid)
				conflict = False;
			else
				conflict = spc_pgr_isconflict(cdb,
				    rsrv->r_type);
			break;
		case PGR_TYPE_WR_EX_RO:
		case PGR_TYPE_EX_AC_RO:
			if (spc_pr_key_find(
			    pgr, 0, T10_PGR_ISID(cmd), T10_PGR_TID(cmd)))
				conflict = False;
			else
				conflict = spc_pgr_isconflict(cdb,
				    rsrv->r_type);
			break;
		case PGR_TYPE_WR_EX_AR:
		case PGR_TYPE_EX_AC_AR:
			if (spc_pr_key_find(pgr, 0, 0, T10_PGR_TID(cmd)))
				conflict = False;
			else
				conflict = spc_pgr_isconflict(cdb,
				    rsrv->r_type);
			break;
		default:
			conflict = True;
			break;
	}

done:
	queue_prt(mgmtq, Q_PR_IO, "PGR%d LUN%d CDB:%s - spc_pgr_check(%s)\n",
	    cmd->c_lu->l_targ->s_targ_num,
	    cmd->c_lu->l_common->l_num,
	    cmd->c_lu->l_cmd_table[cmd->c_cdb[0]].cmd_name == NULL
	    ? "(no name)"
	    : cmd->c_lu->l_cmd_table[cmd->c_cdb[0]].cmd_name,
	    (conflict) ? "Conflict" : "Allowed");

	return (conflict);
}

/*
 * []----
 * | spc_pgr_isconflict
 * |	PGR reservation conflict checking.
 * |	SPC-3, Revision 23, Table 31
 * []----
 */
static int
spc_pgr_isconflict(uint8_t *cdb, uint_t type)
{
	Boolean_t		conflict = False;

	switch (cdb[0]) {
		case SCMD_FORMAT:
		case SCMD_EXTENDED_COPY:
		case SCMD_LOG_SELECT_G1:
		case SCMD_MODE_SELECT:
		case SCMD_MODE_SELECT_G1:
		case SCMD_MODE_SENSE:
		case SCMD_MODE_SENSE_G1:
		case SCMD_READ_ATTRIBUTE:
		case SCMD_READ_BUFFER:
		case SCMD_GDIAG:	/* SCMD_RECEIVE_DIAGNOSTIC_RESULTS */
		case SCMD_SDIAG:	/* SCMD_SEND_DIAGNOSTIC_RESULTS */
		case SCMD_WRITE_ATTRIBUTE:
		case SCMD_WRITE_BUFFER:
			conflict = True;
			break;

		case SCMD_DOORLOCK:	/* SCMD_PREVENT_ALLOW_MEDIA_REMOVAL */
			/*
			 * As per SPC-3, Revision 23, Table 31
			 * (prevent <> 0)
			 */
			conflict = (cdb[4] & 0x1) ? True: False;
			break;

		case SCMD_REPORT_TARGET_PORT_GROUPS:	/* SCMD_REPORT_ */
			/*
			 * As pee SPC-3, Revision 23, Section 6.23
			 */
			switch ((cdb[1] & 0x03)) {
				/* SCMD_REPORT_SUPPORTED_OPERATION_CODES */
				case 0x0c:
				/* SCMD_REPORT_SUPPORTED_MANAGEMENT_FUNCTIONS */
				case 0x0d:

					conflict = True;
					break;
			}
			break;

		case SCMD_SET_DEVICE:
			/*
			 * SPC-3, Revision 23, Section 6.29
			 */
			switch ((cdb[1] & 0x1F)) {
				case SCMD_SET_DEVICE_IDENTIFIER:
				case SCMD_SET_PRIORITY:
				case SCMD_SET_TARGET_PORT_GROUPS:
				case SCMD_SET_TIMESTAMP:
				conflict = True;
				break;
			}
			break;

		case SCMD_READ:
		case SCMD_READ_G1:
		case SCMD_READ_G4:
			if (type == PGR_TYPE_EX_AC || type == PGR_TYPE_EX_AC_RO)
				conflict = True;
			break;
	}

	return (conflict);
}


/*
 * []----
 * | spc_cmd_pr_in --  PERSISTENT_RESERVE IN
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
/*ARGSUSED*/
void
spc_cmd_pr_in(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	scsi_cdb_prin_t		*p_prin = (scsi_cdb_prin_t *)cdb;
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	scsi3_pgr_t		*pgr = &res->res_scsi_3_pgr;
	uint16_t		alen;
	size_t			len;
	void			*buf;
	Boolean_t		status;

	/*
	 * Information obtained from:
	 *	SPC-3, Revision 23
	 *	Section 6.11 PERSISTENCE RESERVE IN
	 * Need to generate a CHECK CONDITION with ILLEGAL REQUEST
	 * and INVALID FIELD IN CDB (0x24/0x00) if any of the following is
	 * true.
	 *	(1) The SERVICE ACTION field is 004h - 01fh,
	 *	(2) The reserved area in byte 1 is set,
	 *	(3) The reserved area in bytes 2 thru 6 are set,
	 *	(4) If any of the reserved bits in the CONTROL byte are set.
	 */
	if ((p_prin->action >= 0x4) || p_prin->resbits || p_prin->resbytes[0] ||
	    p_prin->resbytes[1] || p_prin->resbytes[2] || p_prin->resbytes[3] ||
	    p_prin->resbytes[4] || p_prin->control) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	/*
	 * Information obtained from:
	 *	SPC-3, Revision 23
	 *	Section 6.11 PERSISTENCE RESERVE IN
	 * Acquire ALLOCATION LENGTH from bytes 7, 8
	 * A zero(0) length allocation is not an error and we should just
	 * acknowledge the operation.
	 */
	if ((alen = SCSI_READ16(p_prin->alloc_len)) == 0) {
		queue_prt(mgmtq, Q_PR_IO,
		    "PGR:%d LUN:%d CDB:%s - spc_cmd_pr_in, len = 0\n",
		    cmd->c_lu->l_targ->s_targ_num,
		    cmd->c_lu->l_common->l_num,
		    cmd->c_lu->l_cmd_table[cmd->c_cdb[0]].cmd_name == NULL
		    ? "(no name)"
		    : cmd->c_lu->l_cmd_table[cmd->c_cdb[0]].cmd_name);

		trans_send_complete(cmd, STATUS_GOOD);
		return;
	}

	/*
	 * Allocate space with an alignment that will work for any casting.
	 */
	if ((buf = memalign(sizeof (void *), alen)) == NULL) {
		/*
		 * Lack of memory is not fatal, just too busy
		 */
		trans_send_complete(cmd, STATUS_BUSY);
		return;
	} else {
		bzero(buf, alen);
	}

	/*
	 * Start processing, lock reservation
	 */
	pthread_rwlock_rdlock(&res->res_rwlock);

	/*
	 * Per SPC-3, Revision 23, Table 102, validate ranget of service actions
	 */
	switch (p_prin->action) {
		case PR_IN_READ_KEYS:
			len = spc_pr_in_readkeys(
			    T10_PGR_TID(cmd), pgr, buf, alen);
			break;
		case PR_IN_READ_RESERVATION:
			len = spc_pr_in_readrsrv(
			    T10_PGR_TID(cmd), pgr, buf, alen);
			break;
		case PR_IN_REPORT_CAPABILITIES:
			len = spc_pr_in_repcap(
			    T10_PGR_TID(cmd), pgr, buf, alen);
			break;
		case PR_IN_READ_FULL_STATUS:
			len = spc_pr_in_fullstat(
			    T10_PGR_TID(cmd), pgr, buf, alen);
			break;
		default:
			pthread_rwlock_unlock(&res->res_rwlock);
			spc_free(buf);

			/*
			 * Fail command
			 */
			spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
			spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
			trans_send_complete(cmd, STATUS_CHECK);
			return;
	}

	/*
	 * Complete processing, unlock reservation
	 */
	pthread_rwlock_unlock(&res->res_rwlock);

	/*
	 * Now send the selected Persistent Reservation response back
	 */
	if (trans_send_datain(cmd, buf, alen, 0, spc_free, True, buf) == False)
		trans_send_complete(cmd, STATUS_BUSY);
}

/*
 * []----
 * |   spc_pr_in_readkey -
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
static int
spc_pr_in_readkeys(char *transportID, scsi3_pgr_t *pgr, void *bp,
    uint16_t alloc_len)
{
	int			i = 0, max_buf_keys, hsize;
	scsi_prin_readrsrv_t	*buf = (scsi_prin_readrsrv_t *)bp;
	spc_pr_key_t		*key;

	hsize = sizeof (buf->PRgeneration) + sizeof (buf->add_len);
	max_buf_keys = ((int)alloc_len - hsize) / sizeof (key->k_key);

	queue_prt(mgmtq, Q_PR_IO,
	    "PGRIN readkeys - transportID=%s\n", transportID);

	if (pgr->pgr_numkeys)
	for (key  = (spc_pr_key_t *)pgr->pgr_keylist.lnk_fwd;
	    key != (spc_pr_key_t *)&pgr->pgr_keylist;
	    key  = (spc_pr_key_t *)key->k_link.lnk_fwd) {

		if (strcmp(key->k_transportID, transportID))
			continue;

		if (i < max_buf_keys)
			SCSI_WRITE64(buf->res_key_list[i].reservation_key,
			    key->k_key);

		queue_prt(mgmtq, Q_PR_IO,
		    "PGRIN readkeys - key:%016x, isid:%016x\n",
		    key->k_key, key->k_isid);

		i++;
	}

	SCSI_WRITE32(buf->add_len, i * sizeof (key->k_key));
	SCSI_WRITE32(buf->PRgeneration, pgr->pgr_generation);

	return (hsize + min(SCSI_READ32(buf->add_len),
	    (int)(max_buf_keys * sizeof (key->k_key))));
}

/*
 * []----
 * |   spc_pr_in_readresv -
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
static int
spc_pr_in_readrsrv(
    char *transportID, scsi3_pgr_t *pgr, void *bp, uint16_t alloc_len)
{
	int			i = 0, max_buf_rsrv, hsize;
	spc_pr_rsrv_t		*rsrv;
	scsi_prin_readrsrv_t	*buf = (scsi_prin_readrsrv_t *)bp;

	hsize = sizeof (buf->PRgeneration) + sizeof (buf->add_len);
	max_buf_rsrv = ((int)alloc_len - hsize) / sizeof (scsi_prin_rsrvdesc_t);

	queue_prt(mgmtq, Q_PR_IO,
	    "PGRIN readrsrv - transportID=%s\n", transportID);

	if (pgr->pgr_numrsrv)
	for (rsrv  = (spc_pr_rsrv_t *)pgr->pgr_rsrvlist.lnk_fwd;
	    rsrv != (spc_pr_rsrv_t *)&pgr->pgr_rsrvlist;
	    rsrv  = (spc_pr_rsrv_t *)rsrv->r_link.lnk_fwd) {

		if (strcmp(rsrv->r_transportID, transportID))
			continue;

		if (i < max_buf_rsrv) {
			SCSI_WRITE64(buf->res_key_list[i].reservation_key,
			    rsrv->r_key);
			buf->res_key_list[i].scope = rsrv->r_scope;
			buf->res_key_list[i].type = rsrv->r_type;
		}

		queue_prt(mgmtq, Q_PR_IO,
		    "PGRIN readrsrv - "
		    "key:%016x isid:%016x scope:%d type:%d \n",
		    rsrv->r_key, rsrv->r_isid, rsrv->r_scope, rsrv->r_type);

		i++;
	}

	SCSI_WRITE32(buf->add_len, i * sizeof (scsi_prin_rsrvdesc_t));
	SCSI_WRITE32(buf->PRgeneration, pgr->pgr_generation);

	return (hsize + min(SCSI_READ32(buf->add_len),
	    (int)(max_buf_rsrv * sizeof (scsi_prin_rsrvdesc_t))));
}

/*
 * []----
 * |   spc_pr_in_repcap -
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
/*
 */
static int
spc_pr_in_repcap(
    char *transportID, scsi3_pgr_t *pgr, void *bp, uint16_t alloc_len)
{
	scsi_prin_rpt_cap_t	*buf = (scsi_prin_rpt_cap_t *)bp;

	buf->crh = 0;			/* Supports Reserve / Release */
	buf->sip_c = 1;			/* Specify Initiator Ports Capable */
	buf->atp_c = 1;			/* All Target Ports Capable */
	buf->ptpl_c = 1;		/* Persist Through Power Loss C */
	buf->tmv = 1;			/* Type Mask Valid */
	buf->ptpl_a = pgr_persist;	/* Persist Though Power Loss Active */
	buf->pr_type.wr_ex = 1;		/* Write Exclusve */
	buf->pr_type.ex_ac = 1;		/* Exclusive Access */
	buf->pr_type.wr_ex_ro = 1;	/* Write Exclusive Registrants Only */
	buf->pr_type.ex_ac_ro = 1;	/* Exclusive Access Registrants Only */
	buf->pr_type.wr_ex_ar = 1;	/* Write Exclusive All Registrants */
	buf->pr_type.ex_ac_ar = 1;	/* Exclusive Access All Registrants */

	SCSI_WRITE16(buf->length, sizeof (scsi_prin_rpt_cap_t));

	return (sizeof (scsi_prin_rpt_cap_t));
}

/*
 * []----
 * |   spc_pr_in_fullstat -
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
/*
 */
static int
spc_pr_in_fullstat(
    char *transportID, scsi3_pgr_t *pgr, void *bp, uint16_t alloc_len)
{
	int			i = 0, max_buf_rsrv, hsize;
	spc_pr_rsrv_t		*rsrv;
	scsi_prin_full_status_t	*buf = (scsi_prin_full_status_t *)bp;

	hsize = sizeof (buf->PRgeneration) + sizeof (buf->add_len);
	max_buf_rsrv = ((int)alloc_len - hsize) /
	    sizeof (scsi_prin_full_status_t);

	if (pgr->pgr_numrsrv)
	for (i = 0, rsrv  = (spc_pr_rsrv_t *)pgr->pgr_rsrvlist.lnk_fwd;
	    rsrv != (spc_pr_rsrv_t *)&pgr->pgr_rsrvlist;
	    rsrv  = (spc_pr_rsrv_t *)rsrv->r_link.lnk_fwd) {

		if (i < max_buf_rsrv) {
			SCSI_WRITE64(buf->full_desc[i].reservation_key,
			    rsrv->r_key);
			buf->full_desc[i].all_tg_pt = 1;
			buf->full_desc[i].r_holder =
			    strcmp(rsrv->r_transportID, transportID) ? 0 : 1;
			buf->full_desc[i].scope = rsrv->r_scope;
			buf->full_desc[i].type = rsrv->r_type;
			SCSI_WRITE16(buf->full_desc[i].rel_tgt_port_id, 0);
			SCSI_WRITE32(buf->full_desc[i].add_len,
			    sizeof (scsi_transport_id_t));
			buf->full_desc[i].trans_id.protocol_id =
			    iSCSI_PROTOCOL_ID;
			buf->full_desc[i].trans_id.format_code =
			    WW_UID_DEVICE_NAME;
			SCSI_WRITE16(buf->full_desc[i].trans_id.add_len, 0);
			sprintf(buf->full_desc[i].trans_id.iscsi_name, "");
		}

		i++;
	}

	SCSI_WRITE32(buf->add_len, i * sizeof (scsi_prin_rsrvdesc_t));
	SCSI_WRITE32(buf->PRgeneration, pgr->pgr_generation);

	return (hsize + min(SCSI_READ32(buf->add_len),
	    (int)(max_buf_rsrv * sizeof (scsi_prin_rsrvdesc_t))));

}

/*
 * []----
 * | spc_cmd_pr_out --  PERSISTENT_RESERVE OUT
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
/*ARGSUSED*/
void
spc_cmd_pr_out(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	scsi_cdb_prout_t	*p_prout = (scsi_cdb_prout_t *)cdb;
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	size_t			len;
	void			*buf;

	/*
	 * Information obtained from:
	 *	SPC-3, Revision 23
	 *	Section 6.12 PERSISTENCE RESERVE OUT
	 * Need to generate a CHECK CONDITION with ILLEGAL REQUEST
	 * and INVALID FIELD IN CDB (0x24/0x00) if any of the following is
	 * true.
	 *	(1) The SERVICE ACTION field is 008h - 01fh,
	 *	(2) The reserved area in byte 1 is set,
	 *	(3) The TYPE and SCOPE fields are invalid,
	 *	(4) The reserved area in bytes 3 and 4 are set,
	 *	(5) If any of the reserved bits in the CONTROL byte are set.
	 */
	if ((p_prout->action >= 0x8) || p_prout->resbits ||
	    (p_prout->type >= 0x9) ||
	    (p_prout->scope >= 0x3) || p_prout->control) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	/*
	 * Information obtained from:
	 *	SPC-3, Revision 23
	 *	Section 6.12 PERSISTENCE RESERVE OUT
	 * Acquire ALLOCATION LENGTH from bytes 5 thru 8
	 */
	len = SCSI_READ32(p_prout->param_len);

	/*
	 * Parameter list length shall contain 24 (0x18),
	 * the SPEC_I_PIT is zero (it is because we don't support SIP_C))
	 * the service action is not REGISTER AND MOVE
	 */
	if ((p_prout->action != PR_OUT_REGISTER_MOVE) && (len != 24)) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_PARAM_LIST_LEN, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	/*
	 * Information obtained from:
	 *	SPC-3, Revision 23
	 *	Section 6.11.3.3 Persistent Reservation Scope
	 * SCOPE field shall be set to LU_SCOPE
	 */
	if (p_prout->scope != PR_LU_SCOPE) {
		pthread_rwlock_unlock(&res->res_rwlock);
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	/*
	 * Allocate space with an alignment that will work for any casting.
	 */
	if ((buf = memalign(sizeof (void *), len)) == NULL) {
		/*
		 * Lack of memory is not fatal, just too busy
		 */
		trans_send_complete(cmd, STATUS_BUSY);
		return;
	}

	/*
	 * Now request the Persistent Reserve OUT parameter list
	 */
	if (trans_rqst_dataout(cmd, buf, len, 0, buf, spc_free) == False)
		trans_send_complete(cmd, STATUS_BUSY);
}

/*
 * []----
 * | spc_cmd_pr_out_data -- DataIn phase of PERSISTENT_RESERVE OUT command
 * []----
 */
/*ARGSUSED*/
void
spc_cmd_pr_out_data(t10_cmd_t *cmd, emul_handle_t id, size_t offset, char *data,
    size_t data_len)
{
	scsi_cdb_prout_t	*p_prout = (scsi_cdb_prout_t *)cmd->c_cdb;
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	scsi_prout_plist_t	*plist = (scsi_prout_plist_t *)data;
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	scsi3_pgr_t		*pgr = &res->res_scsi_3_pgr;
	t10_lu_impl_t		*lu;
	int			status;

	/*
	 * If this is the first time using the persistance data,
	 * initialize the reservation and resource key queues
	 */
	pthread_rwlock_wrlock(&res->res_rwlock);
	if (pgr->pgr_rsrvlist.lnk_fwd == NULL) {
		spc_pr_key_rsrv_init(pgr);
	}

	/*
	 * Now process the action.
	 */
	switch (p_prout->action) {
	case PR_OUT_REGISTER_AND_IGNORE_EXISTING_KEY:
	case PR_OUT_REGISTER:
		/*
		 * PR_OUT_REGISTER_IGNORE differs from PR_OUT_REGISTER
		 * in that the reservation_key is ignored.
		 */
		status = spc_pr_register(cmd, data, data_len);
		break;

	case PR_OUT_RESERVE:
		status = spc_pr_reserve(cmd, data, data_len);
		break;

	case PR_OUT_RELEASE:
		status = spc_pr_release(cmd, data, data_len);
		break;

	case PR_OUT_CLEAR:
		status = spc_pr_clear(cmd, data, data_len);
		break;

	case PR_OUT_PREEMPT_ABORT:
	case PR_OUT_PREEMPT:
		/*
		 * PR_OUT_PREEMPT_ABORT differs from PR_OUT_PREEMPT
		 * in that all current acitivy for the preempted
		 * Initiators will be terminated.
		 */
		status = spc_pr_preempt(cmd, data, data_len);
		break;

	case PR_OUT_REGISTER_MOVE:
		/*
		 * PR_OUT_REGISTER_MOVE registers a key for another I_T
		 */
		status = spc_pr_register_and_move(cmd, data, data_len);
		break;
	}

	/*
	 * Check status of action performed.
	 */
	if (status == STATUS_CHECK) {
		/*
		 * Check condition required.
		 */
		pthread_rwlock_unlock(&res->res_rwlock);
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, cmd->c_lu->l_asc, cmd->c_lu->l_ascq);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	/*
	 * Handle Failed processing status
	 */
	if (status != STATUS_GOOD) {
		pthread_rwlock_unlock(&res->res_rwlock);
		trans_send_complete(cmd, status);
		return;
	}

	/*
	 * Successful, bump the PRgeneration value
	 */
	if (p_prout->action != PR_OUT_RESERVE &&
	    p_prout->action != PR_OUT_RELEASE)
		pgr->pgr_generation++;

	/*
	 * If Activate Persist Through Power Loss (APTPL) is set, persist
	 * this PGR data on disk
	 */
	if (plist->aptpl || pgr->pgr_aptpl)
		spc_pr_write(cmd);

	/*
	 * When the last registration is removed, PGR is no longer
	 * active and we must reset the reservation type.
	 */
	if (pgr->pgr_numkeys == 0 && pgr->pgr_numrsrv == 0) {
		res->res_type = RT_NONE;
		pgr->pgr_aptpl = 0;
	} else {
		res->res_type = RT_PGR;
	}

	/*
	 * Set the command dispatcher according to the reservation type
	 */
	lu = avl_first(&cmd->c_lu->l_common->l_all_open);
	do {
		lu->l_cmd = (res->res_type == RT_NONE)
		    ? sbc_cmd
		    : sbc_cmd_reserved;
		lu = AVL_NEXT(&cmd->c_lu->l_common->l_all_open, lu);
	} while (lu != NULL);

	queue_prt(mgmtq, Q_PR_IO, "PGROUT:%d LUN:%d action:%s\n",
	    cmd->c_lu->l_targ->s_targ_num,
	    cmd->c_lu->l_common->l_num,
	    (p_prout->action == PR_OUT_REGISTER_AND_IGNORE_EXISTING_KEY)
	    ? "Register & ignore existing key"
	    : (p_prout->action == PR_OUT_REGISTER)
	    ? "Register"
	    : (p_prout->action == PR_OUT_RESERVE)
	    ? "Reserve"
	    : (p_prout->action == PR_OUT_RELEASE)
	    ? "Release"
	    : (p_prout->action == PR_OUT_CLEAR)
	    ? "Clear"
	    : (p_prout->action == PR_OUT_PREEMPT_ABORT)
	    ? "Preempt & abort"
	    : (p_prout->action == PR_OUT_PREEMPT)
	    ? "Preempt"
	    : (p_prout->action == PR_OUT_REGISTER_MOVE)
	    ? "Register & move"
	    : "Uknown");

	/*
	 * Processing is complete, release mutex
	 */
	pthread_rwlock_unlock(&res->res_rwlock);

	/*
	 * Send back a succesful response
	 */
	trans_send_complete(cmd, STATUS_GOOD);
}

/*
 * []----
 * | spc_pr_register
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
static int
spc_pr_register(t10_cmd_t *cmd, void *data, size_t data_len)
{
	scsi_cdb_prout_t	*p_prout = (scsi_cdb_prout_t *)cmd->c_cdb;
	scsi_prout_plist_t	*plist = (scsi_prout_plist_t *)data;
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	scsi3_pgr_t		*pgr = &res->res_scsi_3_pgr;
	spc_pr_rsrv_t		*rsrv;
	spc_pr_key_t		*key;
	uint64_t		reservation_key;
	uint64_t		service_key;
	t10_lu_impl_t		*lu;
	t10_targ_impl_t		*ti;

	/*
	 * Validate Persistent Reserver Out parameter list
	 */
	if (plist->obsolete1[0] || plist->obsolete1[1] ||
	    plist->obsolete1[2] || plist->obsolete1[3] ||
	    plist->resbits1 || plist->resbits2 || plist->resbytes1 ||
	    plist->obsolete2[0] || plist->obsolete2[1]) {
		cmd->c_lu->l_status = KEY_ILLEGAL_REQUEST;
		cmd->c_lu->l_asc = SPC_ASC_INVALID_CDB;
		cmd->c_lu->l_ascq = 0;
		return (STATUS_CHECK);
	}

	/*
	 * Determine if Activate Persist Trhough Power Loss (APTPL)
	 * is valid for this device server.
	 */
	if (plist->aptpl && (pgr_persist == 0)) {
		/* pgr - define SCSI-3 error codes */
		cmd->c_lu->l_status = KEY_ILLEGAL_REQUEST;
		cmd->c_lu->l_asc = SPC_ASC_INVALID_FIELD_IN_PARAMETER_LIST;
		cmd->c_lu->l_ascq = 0;
		return (STATUS_CHECK);
	}

	/*
	 * Get reservation values
	 */
	reservation_key = SCSI_READ64(plist->reservation_key);
	service_key = SCSI_READ64(plist->service_key);

	queue_prt(mgmtq, Q_PR_IO,
	    "PGROUT: register reservation:%016x, key:%016x\n",
	    reservation_key, service_key);

	/*
	 * We may need register all initiators, depending on ALL_TG_TP
	 */
	lu = avl_first(&cmd->c_lu->l_common->l_all_open);
	do {
		/*
		 * Find specified key
		 */
		ti = lu->l_targ;
		key = spc_pr_key_find(pgr, 0, ti->s_isid, ti->s_transportID);
		if (key) {
			/*
			 * What about ALL_TG_TP?
			 */
			if (plist->all_tg_pt ||
			    (key->k_isid == T10_PGR_ISID(cmd))) {

				if (p_prout->action == PR_OUT_REGISTER &&
				    key->k_key != reservation_key) {
					/*
					 * The Initiator did not specify the
					 * existing key. Reservation conflict.
					 */
					return (STATUS_RESERVATION_CONFLICT);
				}
				/*
				 * Change existing key ?
				 */
				if (service_key) {
					queue_prt(mgmtq, Q_PR_IO,
					    "PGROUT: change "
					    "old:%016x = new:%016x\n",
					    key->k_key, service_key);

					/*
					 * Overwrite (change) key
					 */
					key->k_key = service_key;

				} else {
					/*
					 * Remove existing key
					 * NOTE: If we own the reservation then
					 * we must release it.
					 */
					queue_prt(mgmtq, Q_PR_IO,
					    "PGROUT: delete "
					    "old:%016x = new:%016x\n",
					    key->k_key, service_key);

					rsrv = spc_pr_rsrv_find(pgr, 0,
					    ti->s_isid, ti->s_transportID);
					if (rsrv) {
						spc_pr_rsrv_release(
						    cmd, pgr, rsrv);
						spc_pr_key_free(pgr, key);
					}
				}
			}
		} else {
			/*
			 * What about ALL_TG_TP?
			 */
			if (plist->all_tg_pt ||
			    (ti->s_isid == T10_PGR_ISID(cmd))) {
				/*
				 * Process request from un-registered Initiator.
				 */
				if ((p_prout->action == PR_OUT_REGISTER) &&
				    (reservation_key || service_key == 0)) {
					/*
					 * Unregistered initiator is attempting
					 * to modify a key.
					 */
					return (STATUS_RESERVATION_CONFLICT);
				}

				/*
				 * Allocate new key.
				 */
				queue_prt(mgmtq, Q_PR_IO,
				    "PGROUT: new:%016x\n", service_key);

				key = spc_pr_key_alloc(pgr, service_key,
				    ti->s_isid, ti->s_transportID);
				if (key == NULL) {
					/* pgr - define SCSI-3 error codes */
					cmd->c_lu->l_status =
					    KEY_ABORTED_COMMAND;
					cmd->c_lu->l_asc =
					    SPC_ASC_MEMORY_OUT_OF;
					cmd->c_lu->l_ascq =
					    SPC_ASCQ_RESERVATION_FAIL;
					return (STATUS_CHECK);
				}
			}
		}
		lu = AVL_NEXT(&cmd->c_lu->l_common->l_all_open, lu);
	} while (lu != NULL);

	/*
	 * Apply the last valid APTPL bit
	 *	SPC-3, Revision 23
	 *	Section 5.6.4.1 Preserving persistent reservervations and
	 *	registrations through power loss
	 */
	pgr->pgr_aptpl = plist->aptpl;

	return (STATUS_GOOD);
}

/*
 * []----
 * | spc_pr_reserve
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
/* ARGSUSED */
static int
spc_pr_reserve(t10_cmd_t *cmd, void *data, size_t data_len)
{
	scsi_cdb_prout_t	*p_prout = (scsi_cdb_prout_t *)cmd->c_cdb;
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	scsi3_pgr_t		*pgr = &res->res_scsi_3_pgr;
	spc_pr_rsrv_t		*rsrv;
	scsi_prout_plist_t	*plist = (scsi_prout_plist_t *)data;
	uint64_t		reservation_key;
	int			status;

	/*
	 * Do not allow an unregistered initiator to
	 * make a reservation.
	 */
	reservation_key = SCSI_READ64(plist->reservation_key);
	if (!spc_pr_key_find(
	    pgr, reservation_key, T10_PGR_ISID(cmd), T10_PGR_TID(cmd))) {

		queue_prt(mgmtq, Q_PR_IO,
		    "PGROUT: reserve reservation:%016x not found\n",
		    reservation_key);

		return (STATUS_RESERVATION_CONFLICT);
	} else {

		queue_prt(mgmtq, Q_PR_IO,
		    "PGROUT: reserve reservation:%016x\n", reservation_key);

	}

	/*
	 * See if there is a reservation on this port by
	 * another Initiator.  There can be only one LU_SCOPE
	 * reservation per ITL.  We do not support extents.
	 */
	if (rsrv = spc_pr_rsrv_find(pgr, 0, 0, T10_PGR_TID(cmd))) {
		if (rsrv->r_isid != T10_PGR_ISID(cmd)) {

			queue_prt(mgmtq, Q_PR_IO,
			    "PGROUT: reserve %016x != %016x:%s\n",
			    rsrv->r_isid, T10_PGR_ISID(cmd),
			    T10_PGR_TID(cmd));

			return (STATUS_RESERVATION_CONFLICT);
		}
	}

	/*
	 * At this point there is either no reservation or the
	 * reservation is held by this Initiator.
	 */
	if (rsrv != NULL) {

		queue_prt(mgmtq, Q_PR_IO,
		    "PGROUT reserve(+) - transportID=%s\n"
		    "\tkey:%016x isid:%016x scope:%d type:%d \n",
		    rsrv->r_transportID, rsrv->r_key, rsrv->r_isid,
		    rsrv->r_scope, rsrv->r_type);

		/*
		 * An Initiator cannot re-reserve.  It must first
		 * release.  But if its' type and scope match then
		 * return STATUS_GOOD.
		 */
		if (rsrv->r_type == p_prout->type &&
		    rsrv->r_scope == p_prout->scope) {
			status = STATUS_GOOD;
		} else {
			status = STATUS_RESERVATION_CONFLICT;
		}
	} else {
		/*
		 * No reservation exists.  Establish a new one.
		 */
		queue_prt(mgmtq, Q_PR_IO,
		    "PGROUT reserve - transportID=%s\n"
		    "\tkey:%016x isid:%016x scope:%d type:%d \n",
		    T10_PGR_TID(cmd), reservation_key, T10_PGR_ISID(cmd),
		    p_prout->scope, p_prout->type);

		rsrv = spc_pr_rsrv_alloc(pgr, reservation_key,
		    T10_PGR_ISID(cmd), T10_PGR_TID(cmd),
		    p_prout->scope, p_prout->type);
		if (rsrv == NULL) {
			cmd->c_lu->l_status = KEY_ABORTED_COMMAND;
			cmd->c_lu->l_asc = SPC_ASC_MEMORY_OUT_OF;
			cmd->c_lu->l_ascq = SPC_ASCQ_RESERVATION_FAIL;
			status = STATUS_CHECK;
		} else {
			status = STATUS_GOOD;
		}
	}

	return (status);
}

/*
 * []----
 * | spc_pr_release
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
static int
spc_pr_release(t10_cmd_t *cmd, void *data, size_t data_len)
{
	scsi_cdb_prout_t	*p_prout = (scsi_cdb_prout_t *)cmd->c_cdb;
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	scsi3_pgr_t		*pgr = &res->res_scsi_3_pgr;
	spc_pr_rsrv_t		*rsrv;
	scsi_prout_plist_t	*plist = (scsi_prout_plist_t *)data;
	uint64_t		reservation_key;
	int			status;

	/*
	 * Do not allow an unregistered initiator to attempting to
	 * release a reservation.
	 */
	reservation_key = SCSI_READ64(plist->reservation_key);
	if (!spc_pr_key_find(
	    pgr, reservation_key, T10_PGR_ISID(cmd), T10_PGR_TID(cmd))) {

		queue_prt(mgmtq, Q_PR_IO,
		    "PGROUT: release reservation:%016x not found\n",
		    reservation_key);

		return (STATUS_RESERVATION_CONFLICT);
	} else {

		queue_prt(mgmtq, Q_PR_IO,
		    "PGROUT: release reservation:%016x\n", reservation_key);
	}

	if (!(rsrv = spc_pr_rsrv_find(
	    pgr, 0, T10_PGR_ISID(cmd), T10_PGR_TID(cmd)))) {
		/*
		 * Releasing a non-existent reservation is allowed.
		 */
		status = STATUS_GOOD;

	} else if (p_prout->scope != rsrv->r_scope ||
	    p_prout->type != rsrv->r_type ||
	    reservation_key != rsrv->r_key) {
		queue_prt(mgmtq, Q_PR_IO,
		    "PGROUT release failed - transportID=%s\n"
		    "\tkey:%016x isid:%016x scope:%d type:%d \n",
		    T10_PGR_TID(cmd), reservation_key, T10_PGR_ISID(cmd),
		    p_prout->scope, p_prout->type);

		/*
		 * Scope and key must match to release.
		 */
		cmd->c_lu->l_status = KEY_ILLEGAL_REQUEST;
		cmd->c_lu->l_asc = SPC_ASC_PARAMETERS_CHANGED;
		cmd->c_lu->l_ascq = SPC_ASCQ_RES_RELEASED;
		status = STATUS_CHECK;
	} else {
		/*
		 * Now release the reservation.
		 */
		queue_prt(mgmtq, Q_PR_IO,
		    "PGROUT release - transportID=%s\n"
		    "\tkey:%016x isid:%016x scope:%d type:%d \n",
		    rsrv->r_transportID, rsrv->r_key, rsrv->r_isid,
		    rsrv->r_scope, rsrv->r_type);

		spc_pr_rsrv_release(cmd, pgr, rsrv);
		status = STATUS_GOOD;
	}

	return (status);
}

/*
 * []----
 * | spc_pr_preempt
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
/* ARGSUSED */
static int
spc_pr_preempt(t10_cmd_t *cmd, void *data, size_t data_len)
{
	scsi_cdb_prout_t	*p_prout = (scsi_cdb_prout_t *)cmd->c_cdb;
	t10_lu_impl_t		*lu;
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	scsi3_pgr_t		*pgr = &res->res_scsi_3_pgr;
	scsi_prout_plist_t	*plist = (scsi_prout_plist_t *)data;
	uint64_t		reservation_key;
	uint64_t		service_key;
	spc_pr_key_t		*key;
	spc_pr_rsrv_t		*rsrv;
	int			status = STATUS_GOOD;

	/*
	 * Get reservation values
	 */
	reservation_key = SCSI_READ64(plist->reservation_key);
	service_key = SCSI_READ64(plist->service_key);


	/*
	 * Initiator must be registered and service key (preempt key)
	 * must exist.
	 */
	if ((!(key = spc_pr_key_find(pgr, service_key, 0, ""))) ||
	    (!(rsrv = spc_pr_rsrv_find(pgr, reservation_key,
	    T10_PGR_ISID(cmd), "")))) {

		queue_prt(mgmtq, Q_PR_IO,
		    "PGROUT: preempt failed reservation:%016x, key:%016x\n",
		    reservation_key, service_key);

		return (STATUS_RESERVATION_CONFLICT);
	} else {

		queue_prt(mgmtq, Q_PR_IO,
		    "PGROUT: preempt reservation:%016x, key:%016x\n",
		    reservation_key, service_key);
	}

	/*
	 * Preempt all keys matching service action key and free
	 * the associated structures.  Do not set UNIT_ATTN for
	 * the Initiator which requested the action.
	 *
	 * Unlike the other Persistent Reservation commands, the preempt,
	 * preempt_and_abort and clear actions are service delivery port
	 * independent.  So we remove matching keys across ports.
	 */
	for (key = (spc_pr_key_t *)pgr->pgr_keylist.lnk_fwd;
	    key != (spc_pr_key_t *)&pgr->pgr_keylist;
	    key = (spc_pr_key_t *)key->k_link.lnk_fwd) {

		/* Skip non-matching keys */
		if (key->k_key != service_key)
			continue;

		/* Remove the registration key. */
		spc_pr_key_free(pgr, key);

		/* Do not set UNIT ATTN for calling Initiator */
		if (key->k_isid == T10_PGR_ISID(cmd))
			continue;

		/*
		 * Find associated I_T Nexuses
		 */
		lu = avl_first(&cmd->c_lu->l_common->l_all_open);
		do {
			lu->l_cmd	= sbc_cmd;
			lu->l_status	= KEY_UNIT_ATTENTION;
			lu->l_asc	= SPC_ASC_PARAMETERS_CHANGED;
			lu->l_ascq	= SPC_ASCQ_RES_PREEMPTED;
			lu = AVL_NEXT(&cmd->c_lu->l_common->l_all_open, lu);
		} while (lu != NULL);

		/*
		 * Is this the preempt and abort?
		 */
		if (p_prout->action == PR_OUT_PREEMPT_ABORT) {
			queue_message_set(
			    cmd->c_lu->l_common->l_from_transports,
			    Q_HIGH, msg_reset_lu, (void *)cmd->c_lu);
		}
	}

	/*
	 * Re-establish our registration key if we preempted it.
	 */
	if (!(key = spc_pr_key_find(
	    pgr, reservation_key, T10_PGR_ISID(cmd), T10_PGR_TID(cmd)))) {

		queue_prt(mgmtq, Q_PR_IO,
		    "PGROUT: preempt - register:%016x, isid:%016x:%s\n",
		    reservation_key, T10_PGR_ISID(cmd), T10_PGR_TID(cmd));

		key = spc_pr_key_alloc(pgr, reservation_key,
		    T10_PGR_ISID(cmd), T10_PGR_TID(cmd));
	}

	/*
	 * Now look for a matching reservation to preempt.
	 */
	for (rsrv = (spc_pr_rsrv_t *)pgr->pgr_rsrvlist.lnk_fwd;
	    rsrv != (spc_pr_rsrv_t *)&pgr->pgr_rsrvlist;
	    rsrv = (spc_pr_rsrv_t *)rsrv->r_link.lnk_fwd) {

		/* Skip non-matching keys */
		if (rsrv->r_key != service_key)
			continue;

		/*
		 * Remove matching reservations on other ports
		 * and establish a new reservation on this port only.
		 * To change the fuctionality to preempt rather than
		 * delete the reservations on other ports just remove
		 * the following block of code.
		 */
		if (strcmp(rsrv->r_transportID, T10_PGR_TID(cmd))) {
			spc_pr_rsrv_free(pgr, rsrv);
			continue;
		}

		rsrv->r_key = reservation_key;
		rsrv->r_isid = T10_PGR_ISID(cmd);
		rsrv->r_scope = p_prout->scope;
		rsrv->r_type = p_prout->type;

		queue_prt(mgmtq, Q_PR_IO,
		    "PGROUT preempt - transportID=%s\n"
		    "\tkey:%016x isid:%016x scope:%d type:%d \n",
		    rsrv->r_transportID, rsrv->r_key, rsrv->r_isid,
		    rsrv->r_scope, rsrv->r_type);
	}

	return (status);
}

/*
 * []----
 * | spc_pr_clear
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
/* ARGSUSED */
static int
spc_pr_clear(t10_cmd_t *cmd, void *data, size_t data_len)
{
	scsi_cdb_prout_t	*p_prout = (scsi_cdb_prout_t *)cmd->c_cdb;
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	scsi3_pgr_t		*pgr = &res->res_scsi_3_pgr;
	scsi_prout_plist_t	*plist = (scsi_prout_plist_t *)data;
	uint64_t		reservation_key;
	spc_pr_key_t		*key;
	t10_targ_impl_t		*tp;
	t10_lu_impl_t		*lu;

	/*
	 * Do not allow an unregistered initiator to attempting to
	 * clear the PGR.
	 */
	reservation_key = SCSI_READ64(plist->reservation_key);
	if (!spc_pr_key_find(pgr, reservation_key, T10_PGR_ISID(cmd), "")) {

		queue_prt(mgmtq, Q_PR_IO,
		    "PGROUT: clear pgr:%016x not found\n", reservation_key);

		return (STATUS_RESERVATION_CONFLICT);
	} else {
		queue_prt(mgmtq, Q_PR_IO,
		    "PGROUT: clear pgr:%016x\n", reservation_key);
	}

	/*
	 * We need to set UNIT ATTENTION for all registered initiators.
	 */
	for (key = (spc_pr_key_t *)pgr->pgr_keylist.lnk_fwd;
	    key != (spc_pr_key_t *)&pgr->pgr_keylist;
	    key = (spc_pr_key_t *)key->k_link.lnk_fwd) {

		/* Do not set UNIT ATTN for calling Initiator */
		if (key->k_isid == T10_PGR_ISID(cmd))
			continue;
		/*
		 * At this point the only way to get in here is to be the owner
		 * of the reservation.
		 */
		lu = avl_first(&cmd->c_lu->l_common->l_all_open);
		do {
			lu->l_status = KEY_UNIT_ATTENTION;
			lu->l_asc = SPC_ASC_PARAMETERS_CHANGED;
			lu->l_ascq = SPC_ASCQ_RES_PREEMPTED;
			lu = AVL_NEXT(&cmd->c_lu->l_common->l_all_open, lu);
		} while (lu != NULL);
	}

	/*
	 * Now erase the reservation and registration info.
	 */
	spc_pr_erase(pgr);

	return (STATUS_GOOD);
}

/*
 * []----
 * | spc_pr_register_and_move
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
static int
spc_pr_register_and_move(t10_cmd_t *cmd, void *data, size_t data_len)
{
	return (STATUS_RESERVATION_CONFLICT);
}

/*
 * []----
 * | spc_pr_key_alloc -
 * | 	Allocate a new registration key and add it to the key list.
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
static spc_pr_key_t *
spc_pr_key_alloc(scsi3_pgr_t *pgr, uint64_t service_key, uint64_t isid,
    char *transportID)
{
	spc_pr_key_t	*key = (spc_pr_key_t *)
	    memalign(sizeof (void *), sizeof (spc_pr_key_t));

	if (key != NULL) {
		key->k_key = service_key;
		key->k_isid = isid;
		key->k_transportID = strdup(transportID);

		insque(&key->k_link, pgr->pgr_keylist.lnk_bwd);

		pgr->pgr_numkeys++;
		assert(pgr->pgr_numkeys > 0);
	}

	return (key);
}

/*
 * []----
 * | spc_pr_key_rsrv_init -
 * |	Initialize registration & reservervation queues
 * []----
 */
static void
spc_pr_key_rsrv_init(scsi3_pgr_t *pgr)
{
	assert(pgr->pgr_numrsrv == 0);
	assert(pgr->pgr_numkeys == 0);
	pgr->pgr_rsrvlist.lnk_fwd = (key_link_t *)&pgr->pgr_rsrvlist.lnk_fwd;

	assert(pgr->pgr_rsrvlist.lnk_bwd == NULL);
	pgr->pgr_rsrvlist.lnk_bwd = (key_link_t *)&pgr->pgr_rsrvlist.lnk_fwd;

	assert(pgr->pgr_keylist.lnk_fwd == NULL);
	pgr->pgr_keylist.lnk_fwd = (key_link_t *)&pgr->pgr_keylist.lnk_fwd;

	assert(pgr->pgr_keylist.lnk_bwd == NULL);
	pgr->pgr_keylist.lnk_bwd = (key_link_t *)&pgr->pgr_keylist.lnk_fwd;
}

/*
 * []----
 * | spc_pr_key_free -
 * |	Free a registration key
 * []----
 */
static void
spc_pr_key_free(scsi3_pgr_t *pgr, spc_pr_key_t *key)
{
	remque(&key->k_link);
	free(key->k_transportID);
	free(key);

	pgr->pgr_numkeys--;
	assert(pgr->pgr_numkeys >= 0);
}

/*
 * []----
 * | spc_pr_key_find -
 * |	Find a registration key based on the key, owner id and port id.
 * []----
 */
static spc_pr_key_t *
spc_pr_key_find(scsi3_pgr_t *pgr, uint64_t key, uint64_t isid,
    char *transportID)
{
	spc_pr_key_t	*kp;
	spc_pr_key_t	*rval = NULL;


	for (kp = (spc_pr_key_t *)pgr->pgr_keylist.lnk_fwd;
	    kp != (spc_pr_key_t *)&pgr->pgr_keylist;
	    kp = (spc_pr_key_t *)kp->k_link.lnk_fwd) {
		if ((key == 0 || kp->k_key == key) &&
		    (isid == 0 || kp->k_isid == isid) &&
		    (strlen(transportID) == 0 ||
		    (strcmp(kp->k_transportID, transportID) == 0))) {
			rval = kp;
			break;
		}
	}

	return (rval);
}


/*
 * []----
 * | spc_pr_rsrv_alloc -
 * |	Allocate a new reservation and add it to the rsrv list.
 * []----
 */
static spc_pr_rsrv_t *
spc_pr_rsrv_alloc(scsi3_pgr_t *pgr, uint64_t service_key, uint64_t isid,
    char *transportID, uint8_t scope, uint8_t type)
{
	spc_pr_rsrv_t	*rsrv = (spc_pr_rsrv_t *)
	    memalign(sizeof (void *), sizeof (spc_pr_rsrv_t));

	if (rsrv != NULL) {
		rsrv->r_key = service_key;
		rsrv->r_isid = isid;
		rsrv->r_transportID = strdup(transportID);
		rsrv->r_scope = scope;
		rsrv->r_type = type;

		insque(&rsrv->r_link, pgr->pgr_rsrvlist.lnk_bwd);

		pgr->pgr_numrsrv++;
		assert(pgr->pgr_numrsrv > 0);
	}

	return (rsrv);
}


/*
 * []----
 * | spc_pr_rsrv_free -
 * |	Free a reservation.
 * []----
 */
static void
spc_pr_rsrv_free(scsi3_pgr_t *pgr, spc_pr_rsrv_t *rsrv)
{
	remque(&rsrv->r_link);
	free(rsrv->r_transportID);
	free(rsrv);

	pgr->pgr_numrsrv--;
	assert(pgr->pgr_numrsrv >= 0);
}

/*
 * []----
 * | spc_pr_rsrv_find -
 * |	Find a reservation based on the key, owner id and port id.
 * []----
 */
static spc_pr_rsrv_t *
spc_pr_rsrv_find(scsi3_pgr_t *pgr, uint64_t key, uint64_t isid,
    char *transportID)
{
	spc_pr_rsrv_t	*rp, *rval = NULL;

	for (rp = (spc_pr_rsrv_t *)pgr->pgr_rsrvlist.lnk_fwd;
	    rp != (spc_pr_rsrv_t *)&pgr->pgr_rsrvlist;
	    rp = (spc_pr_rsrv_t *)rp->r_link.lnk_fwd) {
		if ((key == 0 || rp->r_key == key) &&
		    (isid == 0 || rp->r_isid == isid) &&
		    (strlen(transportID) == 0 ||
		    (strcmp(rp->r_transportID, transportID) == 0))) {
			rval = rp;
			break;
		}
	}

	return (rval);
}

/*
 * []----
 * | spc_pr_erase -
 * |	Find specified key / reservation and erease it
 * []----
 */
/*
 */
static void
spc_pr_erase(scsi3_pgr_t *pgr)
{
	spc_pr_key_t		*key;
	spc_pr_rsrv_t		*rsrv;

	while ((key = (spc_pr_key_t *)pgr->pgr_keylist.lnk_fwd) !=
	    (spc_pr_key_t *)&pgr->pgr_keylist) {
		spc_pr_key_free(pgr, key);
	}

	assert(pgr->pgr_numkeys == 0);

	while ((rsrv = (spc_pr_rsrv_t *)pgr->pgr_rsrvlist.lnk_fwd) !=
	    (spc_pr_rsrv_t *)&pgr->pgr_rsrvlist) {
		spc_pr_rsrv_free(pgr, rsrv);
	}

	assert(pgr->pgr_numrsrv == 0);

	pgr->pgr_generation = 0;
	pgr->pgr_aptpl = 0;
}

/*
 * []----
 * | spc_pr_rsrv_release -
 * |	Release the reservation the perform any other required clearing actions.
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
static void
spc_pr_rsrv_release(t10_cmd_t *cmd, scsi3_pgr_t *pgr, spc_pr_rsrv_t *rsrv)
{
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	t10_lu_impl_t		*lu;
	spc_pr_key_t		*key;

	/*
	 * For Registrants-Only mode set UNIT ATTN.
	 */
	if (rsrv->r_type == PGR_TYPE_WR_EX_RO ||
	    rsrv->r_type == PGR_TYPE_EX_AC_RO) {

		for (key = (spc_pr_key_t *)pgr->pgr_keylist.lnk_fwd;
		    key != (spc_pr_key_t *)&pgr->pgr_keylist;
		    key = (spc_pr_key_t *)key->k_link.lnk_fwd) {

			/*
			 * No UNIT ATTN for the requesting Initiator.
			 */
			if (key->k_isid == T10_PGR_ISID(cmd))
				continue;

			/*
			 * Find associated I_T Nexuses
			 */
			lu = avl_first(&cmd->c_lu->l_common->l_all_open);
			do {
				lu->l_cmd	= sbc_cmd;
				lu->l_status	= KEY_UNIT_ATTENTION;
				lu->l_asc	= SPC_ASC_PARAMETERS_CHANGED;
				lu->l_ascq	= SPC_ASCQ_RES_RELEASED;
				lu = AVL_NEXT(&cmd->c_lu->l_common->l_all_open,
				    lu);
			} while (lu != NULL);
		}
	}

	/*
	 * Remove the reservation.
	 */
	spc_pr_rsrv_free(pgr, rsrv);
}

/*
 * []----
 * | spc_pr_read -
 * |	Read in pgr keys and reservations for this device from backend storage.
 * |	At least the local pgr write lock must be held.
 * []----
 */
Boolean_t
spc_pr_read(t10_cmd_t *cmd)
{
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	scsi3_pgr_t		*pgr = &res->res_scsi_3_pgr;
	spc_pr_key_t		*key;
	spc_pr_rsrv_t		*rsrv;
	spc_pr_diskkey_t	*klist;
	spc_pr_diskrsrv_t	*rlist;
	spc_pr_persist_disk_t	*buf = NULL;
	t10_lu_impl_t		*lu;
	int			i, pfd;
	Boolean_t		status = False;
	char			path[MAXPATHLEN];

	/*
	 * If the pre-processor supported "#if .. sizeof", these would
	 * not be required here
	 */
	assert(sizeof (spc_pr_diskkey_t) == 256);
	assert(sizeof (spc_pr_diskrsrv_t) == 256);
	assert(sizeof (spc_pr_persist_disk_t) == 512);

	/*
	 * Open/create the PERSISTANCE file specification
	 */
	(void) snprintf(path, MAXPATHLEN, "%s/%s/%s%d",
	    target_basedir, cmd->c_lu->l_targ->s_targ_base,
	    PERSISTANCEBASE, cmd->c_lu->l_common->l_num);
	if ((pfd = open(path, O_RDONLY)) >= 0) {
		struct stat pstat;
		if ((fstat(pfd, &pstat)) == 0)
			if (pstat.st_size > 0)
				if (buf  = malloc(pstat.st_size))
					if (read(pfd, buf, pstat.st_size) ==
					    pstat.st_size)
						status = True;
	}

	/*
	 * Clean up on no persistence file found
	 */
	if (status == False) {
		if (pfd >= 0)
			close(pfd);
		if (buf)
			free(buf);
		return (status);
	}

	/*
	 * If this is the first time using the persistance data,
	 * initialize the reservation and resource key queues
	 */
	if (pgr->pgr_rsrvlist.lnk_fwd == NULL) {
		spc_pr_key_rsrv_init(pgr);
	}

	/*
	 * Perform some vailidation
	 */
	if ((buf->magic != PGRMAGIC) ||
	    (buf->revision != SPC_PGR_PERSIST_DATA_REVISION)) {
		status = False;
		goto done;
	}

	/*
	 * Get the registration keys.
	 */
	klist = buf->keylist;
	for (i = 0; i < buf->numkeys; i++) {
		if (klist[i].rectype != PGRDISKKEY) {
			status = False;
			goto done;
		}
		key = spc_pr_key_alloc(pgr, klist[i].key, klist[i].isid,
		    klist[i].transportID);
		if (key == NULL) {
			status = False;
			goto done;
		}
	}

	/*
	 * Get the reservations.
	 */
	rlist = (spc_pr_diskrsrv_t *)&buf->keylist[buf->numkeys];
	for (i = 0; i < buf->numrsrv; i++) {
		if (rlist[i].rectype != PGRDISKRSRV) {
			status = False;
			goto done;
		}
		rsrv = spc_pr_rsrv_alloc(pgr, rlist[i].key, rlist[i].isid,
		    rlist[i].transportID, rlist[i].scope, rlist[i].type);
		if (rsrv == NULL) {
			status = False;
			goto done;
		}
	}

	/*
	 * If there was data then set the reservation type.
	 */
	if (pgr->pgr_numkeys > 0 || pgr->pgr_numrsrv > 0) {
		res->res_type = RT_PGR;
		pgr->pgr_generation = buf->generation;

		/*
		 * Set the command dispatcher according to the reservation type
		 */
		lu = avl_first(&cmd->c_lu->l_common->l_all_open);
		do {
			lu->l_cmd = sbc_cmd_reserved;
			lu = AVL_NEXT(&cmd->c_lu->l_common->l_all_open, lu);
		} while (lu != NULL);
	}

done:	pthread_rwlock_unlock(&res->res_rwlock);
	free(buf);
	return (status);
}

/*
 * []----
 * | spc_pr_write -
 * |	Write PGR keys and reservations for this device to backend storage.
 * |	At least the local pgr write lock must be held.
 * []----
 */
Boolean_t
spc_pr_write(t10_cmd_t *cmd)
{
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	scsi3_pgr_t		*pgr = &res->res_scsi_3_pgr;
	spc_pr_key_t		*key;
	spc_pr_rsrv_t		*rsrv;
	spc_pr_diskkey_t	*klist;
	spc_pr_diskrsrv_t	*rlist;
	spc_pr_persist_disk_t	*buf;
	ssize_t			length, bufsize;
	int			i, pfd = -1;
	char			path[MAXPATHLEN];
	Boolean_t		status = True;

	/*
	 * If the pre-processor supported "#if .. sizeof", these would
	 * not be required here
	 */
	assert(sizeof (spc_pr_diskkey_t) == 256);
	assert(sizeof (spc_pr_diskrsrv_t) == 256);
	assert(sizeof (spc_pr_persist_disk_t) == 512);

	/*
	 * Verify space requirements and allocate buffer memory.
	 * Space needed is header + keylist + rsrvlist.
	 * Subtract 1 from numkeys since header already defines
	 * the first element of the keylist.
	 * Round up the bufsize to the next FBA boundary.
	 */
	bufsize = sizeof (spc_pr_persist_disk_t) +
	    (pgr->pgr_numkeys - 1) * sizeof (spc_pr_diskkey_t) +
	    pgr->pgr_numrsrv * sizeof (spc_pr_diskrsrv_t);
	bufsize = roundup(bufsize, 512);
	if ((buf = memalign(sizeof (void *), bufsize)) == NULL)
		return (False);
	else
		bzero(buf, bufsize);

	/*
	 * Build header.
	 */
	buf->magic = PGRMAGIC;
	buf->revision = SPC_PGR_PERSIST_DATA_REVISION;
	buf->generation = pgr->pgr_generation;
	buf->numkeys = pgr->pgr_numkeys;
	buf->numrsrv = pgr->pgr_numrsrv;

	/*
	 * Copy the keys.
	 */
	klist = buf->keylist;
	for (i = 0, key = (spc_pr_key_t *)pgr->pgr_keylist.lnk_fwd;
	    key != (spc_pr_key_t *)&pgr->pgr_keylist && i < pgr->pgr_numkeys;
	    key = (spc_pr_key_t *)key->k_link.lnk_fwd, i++) {

		klist[i].rectype = PGRDISKKEY;
		klist[i].reserved = 0;
		klist[i].key = key->k_key;
		klist[i].isid = key->k_isid;
		strncpy(klist[i].transportID, key->k_transportID,
		    sizeof (klist[i].transportID));
	}

	/*
	 * Copy the reservations.
	 */
	rlist = (spc_pr_diskrsrv_t *)&buf->keylist[pgr->pgr_numkeys];
	for (i = 0, rsrv = (spc_pr_rsrv_t *)pgr->pgr_rsrvlist.lnk_fwd;
	    rsrv != (spc_pr_rsrv_t *)&pgr->pgr_rsrvlist &&
	    i < pgr->pgr_numrsrv;
	    rsrv = (spc_pr_rsrv_t *)rsrv->r_link.lnk_fwd, i++) {

		rlist[i].rectype = PGRDISKRSRV;
		rlist[i].reserved = 0;
		rlist[i].scope = rsrv->r_scope;
		rlist[i].type = rsrv->r_type;
		rlist[i].key = rsrv->r_key;
		rlist[i].isid = rsrv->r_isid;
		strncpy(rlist[i].transportID, rsrv->r_transportID,
		    sizeof (rlist[i].transportID));
	}

	/*
	 * Open/create the PERSISTANCE file specification
	 */
	(void) snprintf(path, MAXPATHLEN, "%s/%s/%s%d",
	    target_basedir, cmd->c_lu->l_targ->s_targ_base,
	    PERSISTANCEBASE, cmd->c_lu->l_common->l_num);
	if ((pfd = open(path, O_WRONLY|O_CREAT)) >= 0) {
		length = write(pfd, buf, bufsize);
		close(pfd);
	} else {
		if ((pfd < 0) || (length != bufsize))
			status = False;
	}

	/*
	 * Free allocated buffer
	 */
	free(buf);
	return (status);
}
