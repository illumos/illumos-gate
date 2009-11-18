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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
extern target_queue_t *mgmtq;
void spc_free(emul_handle_t id);
void sbc_cmd(t10_cmd_t *, uint8_t *, size_t);
void sbc_cmd_reserved(t10_cmd_t *, uint8_t *, size_t);

/*
 * Forward declarations
 */
static spc_pr_key_t *spc_pr_key_find(scsi3_pgr_t *, uint64_t, char *, char *);
static spc_pr_key_t *spc_pr_key_alloc(scsi3_pgr_t *, uint64_t, char *, char *);
static spc_pr_rsrv_t *spc_pr_rsrv_find(scsi3_pgr_t *, uint64_t, char *, char *);
static spc_pr_rsrv_t *spc_pr_rsrv_alloc(scsi3_pgr_t *, uint64_t, char *, char *,
    uint8_t, uint8_t);

static void spc_pr_key_free(scsi3_pgr_t *, spc_pr_key_t *);
static void spc_pr_rsrv_free(scsi3_pgr_t *, spc_pr_rsrv_t *);
static void spc_pr_rsrv_release(t10_cmd_t *, scsi3_pgr_t *, spc_pr_rsrv_t *);

static int spc_pr_out_register(t10_cmd_t *, void *, size_t);
static int spc_pr_out_reserve(t10_cmd_t *, void *, size_t);
static int spc_pr_out_release(t10_cmd_t *, void *, size_t);
static int spc_pr_out_clear(t10_cmd_t *, void *, size_t);
static int spc_pr_out_preempt(t10_cmd_t *, void *, size_t);
static int spc_pr_out_register_and_move(t10_cmd_t *, void *, size_t);

static int spc_pr_in_readkeys(char *, scsi3_pgr_t *, void *, uint16_t);
static int spc_pr_in_readrsrv(char *, scsi3_pgr_t *, void *, uint16_t);
static int spc_pr_in_repcap(char *, scsi3_pgr_t *, void *, uint16_t);
static int spc_pr_in_fullstat(char *, scsi3_pgr_t *, void *, uint16_t);

Boolean_t spc_pr_write(t10_cmd_t *);
static void spc_pr_erase(scsi3_pgr_t *);
static void spc_pr_initialize(scsi3_pgr_t *);

/*
 * []----
 * | spc_pgr_is_conflicting
 * |	PGR reservation conflict checking.
 * |	SPC-3, Revision 23, Table 31
 * []----
 */
static int
spc_pgr_is_conflicting(uint8_t *cdb, uint_t type)
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

		case SCMD_MAINTENANCE_IN:	/* SCMD_REPORT_ */
			/*
			 * As per SPC-3, Revision 23, Section 6.23
			 */
			switch ((cdb[1] & 0x1f)) {
				case SSVC_ACTION_GET_SUPPORTED_OPERATIONS:
				case SSVC_SCTION_GET_SUPPORTED_MANAGEMENT:

					conflict = True;
					break;
			}
			break;

		case SCMD_MAINTENANCE_OUT:
			/*
			 * SPC-3, Revision 23, Section 6.29
			 */
			switch ((cdb[1] & 0x1F)) {
				case SSVC_ACTION_SET_DEVICE_IDENTIFIER:
				case SSVC_ACTION_SET_PRIORITY:
				case SSVC_ACTION_SET_TARGET_PORT_GROUPS:
				case SSVC_ACTION_SET_TIMESTAMP:
				conflict = True;
				break;
			}
			break;

		case SCMD_READ:
		case SCMD_READ_G1:
		case SCMD_READ_G4:
			/*
			 * Exclusive Access, and EA Registrants Only
			 */
			if (type == PGR_TYPE_EX_AC || type == PGR_TYPE_EX_AC_RO)
				conflict = True;
			break;
	}

	return (conflict);
}

/*
 * []----
 * | spc_npr_check --  NON-PERSISTENT RESERVE check of I_T_L
 * |	Refer to SPC-2, Section 5.5.1, Tables 10
 * []----
 */
Boolean_t
spc_npr_check(t10_cmd_t *cmd, uint8_t *cdb)
{
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	Boolean_t		conflict = False;

	/*
	 * If a logical unit has been reserved by any RESERVE command and
	 * is still reserved by any initiator, all PERSISTENT RESERVE IN
	 * and all PRESISTENT RESERVE OUT commands shall conflict regardless
	 * of initiator or service action and shall terminate with a
	 * RESERVATION CONLICT status. SPC-2 section 5.5.1.
	 */
	if ((cdb[0] == SCMD_PERSISTENT_RESERVE_IN) ||
	    (cdb[0] == SCMD_PERSISTENT_RESERVE_OUT) ||
	    (res->res_owner != cmd->c_lu)) {
		conflict = True;
	}

	queue_prt(mgmtq, Q_PR_IO,
	    "NPR%x LUN%d CDB:%s - spc_npr_check(Reservation:%s)\n",
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
 * | spc_pgr_check --  PERSISTENT_RESERVE {IN|OUT} check of I_T_L
 * |	Refer to SPC-3, Section 5.6.1, Tables 31
 * []----
 */
Boolean_t
spc_pgr_check(t10_cmd_t *cmd, uint8_t *cdb)
{
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	scsi3_pgr_t		*pgr = &res->res_scsi_3_pgr;
	spc_pr_rsrv_t		*rsrv = NULL;
	Boolean_t		conflict = False;

	/*
	 * If no reservations exist, allow all remaining command types.
	 */
	assert(res->res_type == RT_PGR);
	if ((cdb[0] == SCMD_PERSISTENT_RESERVE_IN) ||
	    (cdb[0] == SCMD_TEST_UNIT_READY) ||
	    (pgr->pgr_numrsrv == 0)) {
		conflict = False;
		goto done;
	}

	/*
	 * If a logical unit has executed a PERSISTENT RESERVE OUT command
	 * with the REGISTER or REGISTER AND IGNORE EXISTING KEY service
	 * action and is still registered by any initiator, all RESERVE
	 * commands and all RELEASE commands regardless of initiator shall
	 * conflict and shall terminate with a RESERVATION CONFLICT status.
	 * SPC-2 section 5.5.1.
	 *
	 * CRH bit 0, no support for exception defined in
	 * SPC-3 section 5.6.3.
	 */
	if ((cdb[0] == SCMD_RESERVE) ||
	    (cdb[0] == SCMD_RELEASE)) {
		conflict = True;
		goto done;
	}

	/*
	 * At this point we know there is at least one reservation.
	 * If there is no reservation set on this service delivery
	 * port then conflict all remaining command types.
	 */
	if (!(rsrv = spc_pr_rsrv_find(pgr, 0, "", T10_PGR_TNAME(cmd)))) {
		queue_prt(mgmtq, Q_PR_ERRS, "PGR%x Reserved on other port\n",
		    "\t%s:%s\n", cmd->c_lu->l_targ->s_targ_num,
		    T10_PGR_INAME(cmd), T10_PGR_TNAME(cmd));
		conflict = True;
		goto done;
	}

	/*
	 * Check the command against the reservation type for this port.
	 */
	switch (rsrv->r_type) {
		case PGR_TYPE_WR_EX:	/* Write Exclusive */
		case PGR_TYPE_EX_AC:	/* Exclusive Access */
			if (strcmp(T10_PGR_INAME(cmd), rsrv->r_i_name) == 0)
				conflict = False;
			else
				conflict = spc_pgr_is_conflicting(cdb,
				    rsrv->r_type);
			break;
		case PGR_TYPE_WR_EX_RO:	/* Write Exclusive, Registrants Only */
		case PGR_TYPE_EX_AC_RO:	/* Exclusive Access, Registrants Only */
			if (spc_pr_key_find(
			    pgr, 0, T10_PGR_INAME(cmd), T10_PGR_TNAME(cmd)))
				conflict = False;
			else
				conflict = spc_pgr_is_conflicting(cdb,
				    rsrv->r_type);
			break;
		case PGR_TYPE_WR_EX_AR:	/* Write Exclusive, All Registrants */
		case PGR_TYPE_EX_AC_AR:	/* Exclusive Access, All Registrants */
			if (spc_pr_key_find(pgr, 0, "", T10_PGR_TNAME(cmd)))
				conflict = False;
			else
				conflict = spc_pgr_is_conflicting(cdb,
				    rsrv->r_type);
			break;
		default:
			conflict = True;
			break;
	}

done:
	queue_prt(mgmtq, Q_PR_IO, "PGR%x LUN%d CDB:%s - spc_pgr_check(%s:%s)\n",
	    cmd->c_lu->l_targ->s_targ_num,
	    cmd->c_lu->l_common->l_num,
	    cmd->c_lu->l_cmd_table[cmd->c_cdb[0]].cmd_name == NULL
	    ? "(no name)"
	    : cmd->c_lu->l_cmd_table[cmd->c_cdb[0]].cmd_name,
	    (rsrv == NULL)
	    ? "<none>"
	    : (rsrv->r_type == PGR_TYPE_WR_EX)
	    ? "Write Exclusive"
	    : (rsrv->r_type == PGR_TYPE_EX_AC)
	    ? "Exclusive Access"
	    : (rsrv->r_type == PGR_TYPE_WR_EX_RO)
	    ? "Write Exclusive, Registrants Only"
	    : (rsrv->r_type == PGR_TYPE_EX_AC_RO)
	    ? "Exclusive Access, Registrants Only"
	    : (rsrv->r_type == PGR_TYPE_WR_EX_AR)
	    ? "Write Exclusive, All Registrants"
	    : (rsrv->r_type == PGR_TYPE_EX_AC_AR)
	    ? "Exclusive Access, All Registrants"
	    : "Uknown reservation type",
	    (conflict) ? "Conflict" : "Allowed");

	return (conflict);
}

/*
 * []----
 * | spc_cmd_reserve6 -- RESERVE(6) command
 * []----
 */
/*ARGSUSED*/
void
spc_cmd_reserve6(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	disk_params_t	*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t	*res = &p->d_sbc_reserve;
	t10_lu_impl_t	*lu;

	if (cdb[1] & 0xe0 || SAM_CONTROL_BYTE_RESERVED(cdb[5])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	(void) pthread_rwlock_wrlock(&res->res_rwlock);
	/*
	 * The ways to get in here are,
	 * 1) to be the owner of the reservation (SPC-2 section 7.21.2)
	 * 2) reservation not applied, nobody is the owner.
	 */
	if (res->res_owner != cmd->c_lu) {
		lu = avl_first(&cmd->c_lu->l_common->l_all_open);
		do {
			if (lu != cmd->c_lu)
				lu->l_cmd = sbc_cmd_reserved;
			lu = AVL_NEXT(&cmd->c_lu->l_common->l_all_open, lu);
		} while (lu != NULL);
		res->res_owner = cmd->c_lu;
	}
	res->res_type = RT_NPR;
	(void) pthread_rwlock_unlock(&res->res_rwlock);

	trans_send_complete(cmd, STATUS_GOOD);
}

/*
 * []----
 * | spc_cmd_release6 -- RELEASE(6) command
 * []----
 */
/*ARGSUSED*/
void
spc_cmd_release6(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	disk_params_t	*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t	*res = &p->d_sbc_reserve;
	t10_lu_impl_t	*lu;

	if (cdb[1] & 0xe0 || cdb[3] || cdb[4] ||
	    SAM_CONTROL_BYTE_RESERVED(cdb[5])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	(void) pthread_rwlock_wrlock(&res->res_rwlock);
	/*
	 * The ways to get in here are,
	 * 1) to be the owner of the reservation
	 * 2) reservation not applied, nobody is the owner.
	 */
	if (res->res_owner != NULL) {
		lu = avl_first(&cmd->c_lu->l_common->l_all_open);
		do {
			lu->l_cmd = sbc_cmd;
			lu = AVL_NEXT(&cmd->c_lu->l_common->l_all_open, lu);
		} while (lu != NULL);
		res->res_owner = NULL;
		res->res_type = RT_NONE;
	}
	(void) pthread_rwlock_unlock(&res->res_rwlock);

	trans_send_complete(cmd, STATUS_GOOD);
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
	size_t			len = 0;
	void			*buf;

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
		queue_prt(mgmtq, Q_PR_ERRS,
		    "PGR%x LUN%d CDB:%s - spc_cmd_pr_in, len = 0\n",
		    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num,
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
	(void) pthread_rwlock_rdlock(&res->res_rwlock);

	queue_prt(mgmtq, Q_PR_NONIO, "PGR%x LUN%d action:%s\n",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num,
	    (p_prin->action == PR_IN_READ_KEYS)
	    ? "Read keys"
	    : (p_prin->action == PR_IN_READ_RESERVATION)
	    ? "Read reservation"
	    : (p_prin->action == PR_IN_REPORT_CAPABILITIES)
	    ? "Report capabilties"
	    : (p_prin->action == PR_IN_READ_FULL_STATUS)
	    ? "Read full status"
	    : "Uknown");

	/*
	 * Per SPC-3, Revision 23, Table 102, validate ranget of service actions
	 */
	switch (p_prin->action) {
		case PR_IN_READ_KEYS:
			len = spc_pr_in_readkeys(
			    T10_PGR_TNAME(cmd), pgr, buf, alen);
			break;
		case PR_IN_READ_RESERVATION:
			len = spc_pr_in_readrsrv(
			    T10_PGR_TNAME(cmd), pgr, buf, alen);
			break;
		case PR_IN_REPORT_CAPABILITIES:
			len = spc_pr_in_repcap(
			    T10_PGR_TNAME(cmd), pgr, buf, alen);
			break;
		case PR_IN_READ_FULL_STATUS:
			len = spc_pr_in_fullstat(
			    T10_PGR_TNAME(cmd), pgr, buf, alen);
			break;
	}

	/*
	 * Complete processing, unlock reservation
	 */
	(void) pthread_rwlock_unlock(&res->res_rwlock);

	/*
	 * Now send the selected Persistent Reservation response back
	 */
	if (trans_send_datain(cmd, buf, len, 0, spc_free, True, buf) == False)
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

	queue_prt(mgmtq, Q_PR_NONIO,
	    "PGRIN readkeys - transportID=%s\n", transportID);

	if (pgr->pgr_numkeys)
	for (key  = (spc_pr_key_t *)pgr->pgr_keylist.lnk_fwd;
	    key != (spc_pr_key_t *)&pgr->pgr_keylist;
	    key  = (spc_pr_key_t *)key->k_link.lnk_fwd) {

		if (strcmp(key->k_transportID, transportID))
			continue;

		if (i < max_buf_keys) {
			SCSI_WRITE64(&buf->key_list.service_key[i], key->k_key);
			queue_prt(mgmtq, Q_PR_NONIO,
			    "PGRIN readkeys - key:%016lx, i_name:%s\n",
			    key->k_key, key->k_i_name);
			i++;
		}
		else
			break;		/* No room left, leave now */
	}

	SCSI_WRITE32(buf->PRgeneration, pgr->pgr_generation);
	SCSI_WRITE32(buf->add_len, pgr->pgr_numkeys * sizeof (key->k_key));

	return (hsize + min(i, max_buf_keys) * sizeof (key->k_key));
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
	scsi_prin_readrsrv_t	*buf = (scsi_prin_readrsrv_t *)bp;
	scsi_prin_rsrvdesc_t	*desc;
	spc_pr_rsrv_t		*rsrv;

	hsize = sizeof (buf->PRgeneration) + sizeof (buf->add_len);
	max_buf_rsrv = ((int)alloc_len - hsize) / sizeof (scsi_prin_rsrvdesc_t);

	queue_prt(mgmtq, Q_PR_NONIO,
	    "PGRIN readrsrv - transportID=%s\n", transportID);

	if (pgr->pgr_numrsrv)
	for (rsrv  = (spc_pr_rsrv_t *)pgr->pgr_rsrvlist.lnk_fwd;
	    rsrv != (spc_pr_rsrv_t *)&pgr->pgr_rsrvlist;
	    rsrv  = (spc_pr_rsrv_t *)rsrv->r_link.lnk_fwd) {

		if (strcmp(rsrv->r_transportID, transportID))
			continue;

		if (i < max_buf_rsrv) {
			desc = &buf->key_list.res_key_list[i];
			SCSI_WRITE64(desc->reservation_key, rsrv->r_key);
			desc->scope = rsrv->r_scope;
			desc->type = rsrv->r_type;

			queue_prt(mgmtq, Q_PR_NONIO,
			    "PGRIN readrsrv - "
			    "key:%016lx i_name:%s scope:%d type:%d \n",
			    rsrv->r_key, rsrv->r_i_name,
			    rsrv->r_scope, rsrv->r_type);

			i++;
		}
		else
			break;		/* No room left, leave now */
	}

	SCSI_WRITE32(buf->PRgeneration, pgr->pgr_generation);
	SCSI_WRITE32(buf->add_len,
	    pgr->pgr_numrsrv * sizeof (scsi_prin_rsrvdesc_t));

	return (hsize + min(i, max_buf_rsrv)* sizeof (scsi_prin_rsrvdesc_t));
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

	buf->crh = 1;			/* Support Reserve/Release Exceptions */
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
	iscsi_transport_id_t	*tptid;

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
			    sizeof (iscsi_transport_id_t));
			buf->full_desc[i].trans_id.protocol_id =
			    iSCSI_PROTOCOL_ID;
			buf->full_desc[i].trans_id.format_code =
			    WW_UID_DEVICE_NAME;
			tptid = (iscsi_transport_id_t *)
			    &(buf->full_desc[i].trans_id);
			SCSI_WRITE16(tptid->add_len, 0);
			(void) sprintf(tptid->iscsi_name, "");
			i++;
		}
		else
			break;		/* No room left, leave now */

	}

	SCSI_WRITE32(buf->PRgeneration, pgr->pgr_generation);
	SCSI_WRITE32(buf->add_len, i * sizeof (scsi_prin_rsrvdesc_t));

	return (hsize + min(i, max_buf_rsrv) * sizeof (scsi_prin_rsrvdesc_t));

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
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	scsi3_pgr_t		*pgr = &res->res_scsi_3_pgr;
	scsi_prout_plist_t	*plist = (scsi_prout_plist_t *)data;
	t10_lu_impl_t		*lu;
	int			status;

	/*
	 * If this is the first time using the persistence data,
	 * initialize the reservation and resource key queues
	 */
	(void) pthread_rwlock_wrlock(&res->res_rwlock);
	if (pgr->pgr_rsrvlist.lnk_fwd == NULL) {
		spc_pr_initialize(pgr);
	}

	queue_prt(mgmtq, Q_PR_NONIO, "PGR%x LUN%d action:%s\n",
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
	 * Now process the action.
	 */
	switch (p_prout->action) {
	case PR_OUT_REGISTER_AND_IGNORE_EXISTING_KEY:
	case PR_OUT_REGISTER:
		/*
		 * PR_OUT_REGISTER_IGNORE differs from PR_OUT_REGISTER
		 * in that the reservation_key is ignored.
		 */
		status = spc_pr_out_register(cmd, data, data_len);
		break;

	case PR_OUT_RESERVE:
		status = spc_pr_out_reserve(cmd, data, data_len);
		break;

	case PR_OUT_RELEASE:
		status = spc_pr_out_release(cmd, data, data_len);
		break;

	case PR_OUT_CLEAR:
		status = spc_pr_out_clear(cmd, data, data_len);
		break;

	case PR_OUT_PREEMPT_ABORT:
	case PR_OUT_PREEMPT:
		/*
		 * PR_OUT_PREEMPT_ABORT differs from PR_OUT_PREEMPT
		 * in that all current acitivy for the preempted
		 * Initiators will be terminated.
		 */
		status = spc_pr_out_preempt(cmd, data, data_len);
		break;

	case PR_OUT_REGISTER_MOVE:
		/*
		 * PR_OUT_REGISTER_MOVE registers a key for another I_T
		 */
		status = spc_pr_out_register_and_move(cmd, data, data_len);
		break;
	}

	/*
	 * Check status of action performed.
	 */
	if (status == STATUS_CHECK) {
		/*
		 * Check condition required.
		 */
		(void) pthread_rwlock_unlock(&res->res_rwlock);
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, cmd->c_lu->l_asc, cmd->c_lu->l_ascq);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	/*
	 * Handle Failed processing status
	 */
	if (status != STATUS_GOOD) {
		(void) pthread_rwlock_unlock(&res->res_rwlock);
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
		(void) spc_pr_write(cmd);

	/*
	 * When the last registration is removed, PGR is no longer
	 * active and we must reset the reservation type.
	 */
	if ((pgr->pgr_numkeys == 0) && (pgr->pgr_numrsrv == 0)) {
		res->res_type = RT_NONE;
		pgr->pgr_aptpl = 0;
	} else {
		res->res_type = RT_PGR;
	}

	/*
	 * Set the command dispatcher according to the reservation type
	 */
	(void) pthread_mutex_lock(&cmd->c_lu->l_common->l_common_mutex);
	lu = avl_first(&cmd->c_lu->l_common->l_all_open);
	do {
		lu->l_cmd = (res->res_type == RT_NONE)
		    ? sbc_cmd : sbc_cmd_reserved;
		lu = AVL_NEXT(&cmd->c_lu->l_common->l_all_open, lu);
	} while (lu != NULL);
	(void) pthread_mutex_unlock(&cmd->c_lu->l_common->l_common_mutex);

	/*
	 * Processing is complete, release mutex
	 */
	(void) pthread_rwlock_unlock(&res->res_rwlock);

	/*
	 * Send back a succesful response
	 */
	trans_send_complete(cmd, STATUS_GOOD);
}

/*
 * []----
 * | spc_pr_out_register
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
static int
spc_pr_out_register(t10_cmd_t *cmd, void *data, size_t data_len)
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

	queue_prt(mgmtq, Q_PR_NONIO,
	    "PGR%x LUN%d register reservation:%016lx, key:%016lx\n",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num,
	    reservation_key, service_key);

	/*
	 * We may need register all initiators, depending on ALL_TG_TP
	 */
	(void) pthread_mutex_lock(&cmd->c_lu->l_common->l_common_mutex);
	lu = avl_first(&cmd->c_lu->l_common->l_all_open);
	do {
		/*
		 * Find specified key
		 */
		ti = lu->l_targ;
		key = spc_pr_key_find(pgr, 0, ti->s_i_name, ti->s_targ_base);
		if (key) {
			/*
			 * What about ALL_TG_TP?
			 */
			if (plist->all_tg_pt ||
			    (strcmp(key->k_i_name, T10_PGR_INAME(cmd)) == 0)) {

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
					queue_prt(mgmtq, Q_PR_NONIO,
					    "PGROUT: change "
					    "old:%016lx = new:%016lx\n",
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
					queue_prt(mgmtq, Q_PR_NONIO,
					    "PGROUT: delete "
					    "old:%016lx = new:%016lx\n",
					    key->k_key, service_key);

					rsrv = spc_pr_rsrv_find(pgr, 0,
					    ti->s_i_name, ti->s_targ_base);
					if (rsrv) {
						spc_pr_rsrv_release(
						    cmd, pgr, rsrv);
					}
					spc_pr_key_free(pgr, key);
				}
			}
		} else {
			/*
			 * What about ALL_TG_TP?
			 */
			if (plist->all_tg_pt ||
			    (strcmp(ti->s_i_name, T10_PGR_INAME(cmd)) == 0)) {
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

				key = spc_pr_key_alloc(pgr, service_key,
				    ti->s_i_name, ti->s_targ_base);
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
	(void) pthread_mutex_unlock(&cmd->c_lu->l_common->l_common_mutex);

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
 * | spc_pr_out_reserve
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
/* ARGSUSED */
static int
spc_pr_out_reserve(t10_cmd_t *cmd, void *data, size_t data_len)
{
	scsi_cdb_prout_t	*p_prout = (scsi_cdb_prout_t *)cmd->c_cdb;
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	scsi3_pgr_t		*pgr = &res->res_scsi_3_pgr;
	spc_pr_rsrv_t		*rsrv;
	scsi_prout_plist_t	*plist = (scsi_prout_plist_t *)data;
	uint64_t		reservation_key;
	uint64_t		service_key;
	int			status;

	/*
	 * Do not allow an unregistered initiator to
	 * make a reservation.
	 */
	reservation_key = SCSI_READ64(plist->reservation_key);
	service_key = SCSI_READ64(plist->service_key);

	queue_prt(mgmtq, Q_PR_NONIO,
	    "PGR%x LUN%d reserve reservation:%016lx, key:%016lx\n",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num,
	    reservation_key, service_key);

	if (!spc_pr_key_find(
	    pgr, reservation_key, T10_PGR_INAME(cmd), T10_PGR_TNAME(cmd))) {

		queue_prt(mgmtq, Q_PR_ERRS,
		    "PGROUT: reserve service:%016lx not found\n",
		    reservation_key);

		return (STATUS_RESERVATION_CONFLICT);
	}

	/*
	 * See if there is a reservation on this port by
	 * another Initiator.  There can be only one LU_SCOPE
	 * reservation per ITL.  We do not support extents.
	 */
	if (rsrv = spc_pr_rsrv_find(pgr, 0, "", T10_PGR_TNAME(cmd))) {
		if (strcmp(rsrv->r_i_name, T10_PGR_INAME(cmd)) != 0) {

			queue_prt(mgmtq, Q_PR_ERRS,
			    "PGROUT: reserve %s != %s:%s\n", rsrv->r_i_name,
			    T10_PGR_INAME(cmd), T10_PGR_TNAME(cmd));

			return (STATUS_RESERVATION_CONFLICT);
		}
	}

	/*
	 * At this point there is either no reservation or the
	 * reservation is held by this Initiator.
	 */
	if (rsrv != NULL) {

		/*
		 * An Initiator cannot re-reserve.  It must first
		 * release.  But if its' type and scope match then
		 * return STATUS_GOOD.
		 */
		if (rsrv->r_type == p_prout->type &&
		    rsrv->r_scope == p_prout->scope) {
			queue_prt(mgmtq, Q_PR_NONIO,
			    "PGROUT reserve - transportID=%s\n"
			    "\tkey:%016lx i_name:%s scope:%d type:%d \n",
			    rsrv->r_transportID, rsrv->r_key, rsrv->r_i_name,
			    rsrv->r_scope, rsrv->r_type);
			status = STATUS_GOOD;
		} else {
			queue_prt(mgmtq, Q_PR_ERRS,
			    "PGROUT reserve failed - transportID=%s\n"
			    "\tkey:%016lx i_name:%s scope:%d type:%d \n",
			    rsrv->r_transportID, rsrv->r_key, rsrv->r_i_name,
			    rsrv->r_scope, rsrv->r_type);
			status = STATUS_RESERVATION_CONFLICT;
		}
	} else {
		/*
		 * No reservation exists.  Establish a new one.
		 */
		queue_prt(mgmtq, Q_PR_NONIO,
		    "PGROUT reserve - transportID=%s\n"
		    "\tkey:%016lx i_name:%s scope:%d type:%d \n",
		    T10_PGR_TNAME(cmd), reservation_key, T10_PGR_INAME(cmd),
		    p_prout->scope, p_prout->type);

		rsrv = spc_pr_rsrv_alloc(pgr, reservation_key,
		    T10_PGR_INAME(cmd), T10_PGR_TNAME(cmd),
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
 * | spc_pr_out_release
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
static int
spc_pr_out_release(t10_cmd_t *cmd, void *data, size_t data_len)
{
	scsi_cdb_prout_t	*p_prout = (scsi_cdb_prout_t *)cmd->c_cdb;
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	scsi3_pgr_t		*pgr = &res->res_scsi_3_pgr;
	spc_pr_rsrv_t		*rsrv;
	scsi_prout_plist_t	*plist = (scsi_prout_plist_t *)data;
	uint64_t		reservation_key;
	uint64_t		service_key;
	int			status;

	/*
	 * Do not allow an unregistered initiator to
	 * make a reservation.
	 */
	reservation_key = SCSI_READ64(plist->reservation_key);
	service_key = SCSI_READ64(plist->service_key);

	queue_prt(mgmtq, Q_PR_NONIO,
	    "PGR%x LUN%d release reservation:%016lx, key:%016lx\n",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num,
	    reservation_key, service_key);

	if (!spc_pr_key_find(
	    pgr, reservation_key, T10_PGR_INAME(cmd), T10_PGR_TNAME(cmd))) {

		queue_prt(mgmtq, Q_PR_ERRS,
		    "PGROUT: release service:%016lx not found\n",
		    reservation_key);

		return (STATUS_RESERVATION_CONFLICT);
	} else {

		queue_prt(mgmtq, Q_PR_NONIO,
		    "PGROUT: release service:%016lx\n", service_key);
	}

	/*
	 * Releasing a non-existent reservation is allowed.
	 */
	if (!(rsrv = spc_pr_rsrv_find(
	    pgr, 0, T10_PGR_INAME(cmd), T10_PGR_TNAME(cmd)))) {

		status = STATUS_GOOD;

	} else if (p_prout->scope != rsrv->r_scope ||
	    p_prout->type != rsrv->r_type ||
	    reservation_key != rsrv->r_key) {
		queue_prt(mgmtq, Q_PR_ERRS,
		    "PGROUT release failed - transportID=%s\n"
		    "\tkey:%016lx i_name:%s scope:%d type:%d \n",
		    T10_PGR_TNAME(cmd), reservation_key, T10_PGR_INAME(cmd),
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
		queue_prt(mgmtq, Q_PR_NONIO,
		    "PGROUT release - transportID=%s\n"
		    "\tkey:%016lx i_name:s scope:%d type:%d \n",
		    rsrv->r_transportID, rsrv->r_key, rsrv->r_i_name,
		    rsrv->r_scope, rsrv->r_type);

		spc_pr_rsrv_release(cmd, pgr, rsrv);
		status = STATUS_GOOD;
	}

	return (status);
}

/*
 * []----
 * | spc_pr_out_preempt
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
/* ARGSUSED */
static int
spc_pr_out_preempt(t10_cmd_t *cmd, void *data, size_t data_len)
{
	scsi_cdb_prout_t	*p_prout = (scsi_cdb_prout_t *)cmd->c_cdb;
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	scsi3_pgr_t		*pgr = &res->res_scsi_3_pgr;
	scsi_prout_plist_t	*plist = (scsi_prout_plist_t *)data;
	uint64_t		reservation_key;
	uint64_t		service_key;
	spc_pr_key_t		*key, *key_next;
	spc_pr_rsrv_t		*rsrv, *rsrv_next;
	t10_lu_impl_t		*lu;
	int			status = STATUS_GOOD;

	/*
	 * Get reservation values
	 */
	reservation_key = SCSI_READ64(plist->reservation_key);
	service_key = SCSI_READ64(plist->service_key);

	queue_prt(mgmtq, Q_PR_NONIO,
	    "PGR%x LUN%d preempt reservation:%016lx, key:%016lx\n",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num,
	    reservation_key, service_key);

	/*
	 * Service key (preempt key) must exist, and
	 * Initiator must be registered
	 */
	if (spc_pr_key_find(pgr, service_key, "", "") == NULL ||
	    spc_pr_key_find(pgr, reservation_key, T10_PGR_INAME(cmd), "") ==
	    NULL) {

		queue_prt(mgmtq, Q_PR_ERRS,
		    "PGROUT: preempt failed reservation:%016lx, key:%016lx\n",
		    reservation_key, service_key);

		return (STATUS_RESERVATION_CONFLICT);
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
	    key = (spc_pr_key_t *)key_next) {

		Boolean_t	unit_attn;

		/*
		 * Get next pointer in case the key gets deallocated
		 */
		key_next = (spc_pr_key_t *)key->k_link.lnk_fwd;

		/* Skip non-matching keys */
		if (key->k_key != service_key) {
			queue_prt(mgmtq, Q_PR_NONIO,
			    "PGROUT preempt key:%016lx != key:%016lx "
			    "i_name:%s transportID:%s\n", service_key,
			    key->k_key, key->k_i_name, key->k_transportID);
			continue;
		}

		/*
		 * Determine if UNIT ATTN needed
		 */
		unit_attn = strcmp(key->k_i_name, T10_PGR_INAME(cmd));

		/*
		 * Remove the registration key
		 */
		queue_prt(mgmtq, Q_PR_NONIO,
		    "PGROUT preempt delete key:%016lx "
		    "i_name:%s transportID:%s\n",
		    key->k_key, key->k_i_name, key->k_transportID);
		spc_pr_key_free(pgr, key);

		/*
		 * UNIT ATTN needed ?
		 * Do not set UNIT ATTN for calling Initiator
		 */
		if (unit_attn == False)
			continue;

		/*
		 * Is this the preempt and abort?
		 */
		if (p_prout->action == PR_OUT_PREEMPT_ABORT) {
			queue_message_set(
			    cmd->c_lu->l_common->l_from_transports,
			    Q_HIGH, msg_reset_lu, (void *)cmd->c_lu);
		}

		/*
		 * Find associated I_T Nexuses
		 */
		(void) pthread_mutex_lock(&cmd->c_lu->l_common->l_common_mutex);
		lu = avl_first(&cmd->c_lu->l_common->l_all_open);
		do {
			lu->l_status	= KEY_UNIT_ATTENTION;
			lu->l_asc	= SPC_ASC_PARAMETERS_CHANGED;
			lu->l_ascq	= SPC_ASCQ_RES_PREEMPTED;
			lu = AVL_NEXT(&cmd->c_lu->l_common->l_all_open, lu);
		} while (lu != NULL);
		(void) pthread_mutex_unlock(
		    &cmd->c_lu->l_common->l_common_mutex);
	}

	/*
	 * Re-establish our service key if we preempted it.
	 */
	if (!(key = spc_pr_key_find(
	    pgr, reservation_key, T10_PGR_INAME(cmd), T10_PGR_TNAME(cmd)))) {

		queue_prt(mgmtq, Q_PR_NONIO,
		    "PGROUT: preempt - register:%016lx, i_name:%s:%s\n",
		    reservation_key, T10_PGR_INAME(cmd), T10_PGR_TNAME(cmd));

		key = spc_pr_key_alloc(pgr, reservation_key,
		    T10_PGR_INAME(cmd), T10_PGR_TNAME(cmd));
		if (key == NULL) {
			cmd->c_lu->l_status = KEY_ABORTED_COMMAND;
			cmd->c_lu->l_asc = SPC_ASC_MEMORY_OUT_OF;
			cmd->c_lu->l_ascq = SPC_ASCQ_RESERVATION_FAIL;
			return (STATUS_CHECK);
		}
	}

	/*
	 * Now look for a matching reservation to preempt.
	 */
	for (rsrv = (spc_pr_rsrv_t *)pgr->pgr_rsrvlist.lnk_fwd;
	    rsrv != (spc_pr_rsrv_t *)&pgr->pgr_rsrvlist;
	    rsrv = (spc_pr_rsrv_t *)rsrv_next) {

		/*
		 * Get next pointer in case the reservation gets deallocated
		 */
		rsrv_next = (spc_pr_rsrv_t *)rsrv->r_link.lnk_fwd;

		/* Skip non-matching keys */
		if (rsrv->r_key != service_key) {
			queue_prt(mgmtq, Q_PR_NONIO,
			    "PGROUT preempt rsrv:%016lx != rsrv:%016lx"
			    "i_name:%s scope:%d type:%d \n", service_key,
			    rsrv->r_key, rsrv->r_i_name,
			    rsrv->r_scope, rsrv->r_type);
			continue;
		}

		/*
		 * Remove matching reservations on other ports
		 * and establish a new reservation on this port only.
		 * To change the fuctionality to preempt rather than
		 * delete the reservations on other ports just remove
		 * the following block of code.
		 */
		if (strcmp(rsrv->r_transportID, T10_PGR_TNAME(cmd))) {
			queue_prt(mgmtq, Q_PR_NONIO,
			    "PGROUT preempt(-) rsrv:%016lx "
			    "i_name:%s scope:%d type:%d \n",
			    rsrv->r_key, rsrv->r_i_name,
			    rsrv->r_scope, rsrv->r_type);

			spc_pr_rsrv_free(pgr, rsrv);
			continue;
		} else {
			/*
			 * We have a matching reservation so preempt it.
			 */
			rsrv->r_key = reservation_key;
			rsrv->r_i_name = strdup(T10_PGR_INAME(cmd));
			rsrv->r_scope = p_prout->scope;
			rsrv->r_type = p_prout->type;

			queue_prt(mgmtq, Q_PR_NONIO,
			    "PGROUT preempt(+) rsrv:%016lx "
			    "i_name:%s scope:%d type:%d \n",
			    rsrv->r_key, rsrv->r_i_name,
			    rsrv->r_scope, rsrv->r_type);
		}
	}

	return (status);
}

/*
 * []----
 * | spc_pr_out_clear
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
/* ARGSUSED */
static int
spc_pr_out_clear(t10_cmd_t *cmd, void *data, size_t data_len)
{
	disk_params_t		*p = (disk_params_t *)T10_PARAMS_AREA(cmd);
	sbc_reserve_t		*res = &p->d_sbc_reserve;
	scsi3_pgr_t		*pgr = &res->res_scsi_3_pgr;
	scsi_prout_plist_t	*plist = (scsi_prout_plist_t *)data;
	uint64_t		reservation_key;
	uint64_t		service_key;
	spc_pr_key_t		*key;
	t10_lu_impl_t		*lu;

	/*
	 * Do not allow an unregistered initiator to attempting to
	 * clear the PGR.
	 */
	reservation_key = SCSI_READ64(plist->reservation_key);
	service_key = SCSI_READ64(plist->service_key);

	queue_prt(mgmtq, Q_PR_NONIO,
	    "PGR%x LUN%d clear reservation:%016lx, key:%016lx\n",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num,
	    reservation_key, service_key);

	if (!spc_pr_key_find(pgr, reservation_key, T10_PGR_INAME(cmd), "")) {

		queue_prt(mgmtq, Q_PR_ERRS,
		    "PGROUT: clear service:%016lx not found\n",
		    reservation_key);

		return (STATUS_RESERVATION_CONFLICT);
	}

	/*
	 * We need to set UNIT ATTENTION for all registered initiators.
	 */
	for (key = (spc_pr_key_t *)pgr->pgr_keylist.lnk_fwd;
	    key != (spc_pr_key_t *)&pgr->pgr_keylist;
	    key = (spc_pr_key_t *)key->k_link.lnk_fwd) {

		/* Do not set UNIT ATTN for calling Initiator */
		if (!(strcmp(key->k_i_name, T10_PGR_INAME(cmd))))
			continue;
		/*
		 * At this point the only way to get in here is to be the owner
		 * of the reservation.
		 */
		(void) pthread_mutex_lock(&cmd->c_lu->l_common->l_common_mutex);
		lu = avl_first(&cmd->c_lu->l_common->l_all_open);
		do {
			lu->l_status = KEY_UNIT_ATTENTION;
			lu->l_asc = SPC_ASC_PARAMETERS_CHANGED;
			lu->l_ascq = SPC_ASCQ_RES_PREEMPTED;
			lu = AVL_NEXT(&cmd->c_lu->l_common->l_all_open, lu);
		} while (lu != NULL);
		(void) pthread_mutex_unlock(
		    &cmd->c_lu->l_common->l_common_mutex);
	}

	/*
	 * Now erase the reservation and registration info.
	 */
	spc_pr_erase(pgr);

	return (STATUS_GOOD);
}

/*
 * []----
 * | spc_pr_out_register_and_move
 * |	Refer to SPC-3, Section 6.1, Tables ?? and ??
 * []----
 */
static int
spc_pr_out_register_and_move(t10_cmd_t *cmd, void *data, size_t data_len)
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
spc_pr_key_alloc(scsi3_pgr_t *pgr, uint64_t service_key, char *i_name,
    char *transportID)
{
	spc_pr_key_t	*key = (spc_pr_key_t *)
	    memalign(sizeof (void *), sizeof (spc_pr_key_t));

	if (key != NULL) {
		key->k_key = service_key;
		key->k_i_name = strdup(i_name);
		key->k_transportID = strdup(transportID);

		insque(&key->k_link, pgr->pgr_keylist.lnk_bwd);

		pgr->pgr_numkeys++;
		assert(pgr->pgr_numkeys > 0);
	}

	return (key);
}

/*
 * []----
 * | spc_pr_initialize -
 * |	Initialize registration & reservervation queues
 * []----
 */
static void
spc_pr_initialize(scsi3_pgr_t *pgr)
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
	free(key->k_i_name);
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
spc_pr_key_find(scsi3_pgr_t *pgr, uint64_t key, char *i_name, char *transportID)
{
	spc_pr_key_t	*kp;
	spc_pr_key_t	*rval = NULL;

	for (kp = (spc_pr_key_t *)pgr->pgr_keylist.lnk_fwd;
	    kp != (spc_pr_key_t *)&pgr->pgr_keylist;
	    kp = (spc_pr_key_t *)kp->k_link.lnk_fwd) {
		if ((key == 0 || kp->k_key == key) &&
		    (strlen(i_name) == 0 ||
		    (strcmp(kp->k_i_name, i_name) == 0)) &&
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
spc_pr_rsrv_alloc(scsi3_pgr_t *pgr, uint64_t service_key, char *i_name,
    char *transportID, uint8_t scope, uint8_t type)
{
	spc_pr_rsrv_t	*rsrv = (spc_pr_rsrv_t *)
	    memalign(sizeof (void *), sizeof (spc_pr_rsrv_t));

	if (rsrv != NULL) {
		rsrv->r_key = service_key;
		rsrv->r_i_name = strdup(i_name);
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
	free(rsrv->r_i_name);
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
spc_pr_rsrv_find(scsi3_pgr_t *pgr, uint64_t key, char *i_name,
    char *transportID)
{
	spc_pr_rsrv_t	*rp, *rval = NULL;

	for (rp = (spc_pr_rsrv_t *)pgr->pgr_rsrvlist.lnk_fwd;
	    rp != (spc_pr_rsrv_t *)&pgr->pgr_rsrvlist;
	    rp = (spc_pr_rsrv_t *)rp->r_link.lnk_fwd) {
		if ((key == 0 || rp->r_key == key) &&
		    (strlen(i_name) == 0 ||
		    (strcmp(rp->r_i_name, i_name) == 0)) &&
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
			if (!(strcmp(key->k_i_name, T10_PGR_INAME(cmd))))
				continue;

			/*
			 * Find associated I_T Nexuses
			 */
			(void) pthread_mutex_lock(
			    &cmd->c_lu->l_common->l_common_mutex);
			lu = avl_first(&cmd->c_lu->l_common->l_all_open);
			do {
				lu->l_status	= KEY_UNIT_ATTENTION;
				lu->l_asc	= SPC_ASC_PARAMETERS_CHANGED;
				lu->l_ascq	= SPC_ASCQ_RES_RELEASED;
				lu = AVL_NEXT(&cmd->c_lu->l_common->l_all_open,
				    lu);
			} while (lu != NULL);
			(void) pthread_mutex_unlock(
			    &cmd->c_lu->l_common->l_common_mutex);
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
void
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
	char			*c, path[MAXPATHLEN] = {0};

	/*
	 * Open the PERSISTENCE file specification if one exists
	 * taking into account the alternate location if a ZVOL
	 */
	if (tgt_find_value_str(cmd->c_lu->l_common->l_root, XML_ELEMENT_BACK,
	    &c) == True) {
		if (((pgr_basedir != NULL) && (strlen(pgr_basedir) != 0)) &&
		    (strncmp(ZVOL_PATH, c, sizeof (ZVOL_PATH) - 1) == 0)) {
			(void) snprintf(path, MAXPATHLEN, "%s/%s-%s%d",
			    pgr_basedir, &c[sizeof (ZVOL_PATH) - 1],
			    PERSISTENCEBASE, cmd->c_lu->l_common->l_num);
		} else {
			(void) snprintf(path, MAXPATHLEN, "%s/%s/%s%d",
			    target_basedir, cmd->c_lu->l_targ->s_targ_base,
			    PERSISTENCEBASE, cmd->c_lu->l_common->l_num);
		}
		free(c);
	}
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
			(void) close(pfd);
		if (buf)
			free(buf);
		return;
	}

	/*
	 * If this is the first time using the persistence data,
	 * initialize the reservation and resource key queues
	 */
	if (pgr->pgr_rsrvlist.lnk_fwd == NULL) {
		(void) spc_pr_initialize(pgr);
	}

	/*
	 * Perform some vailidation on what we are looking at
	 */
	assert(buf->magic == PGRMAGIC);
	assert(buf->revision == SPC_PGR_PERSIST_DATA_REVISION);

	/*
	 * Get the PGR keys
	 */
	klist = (spc_pr_diskkey_t *)&buf->keylist[0];
	for (i = 0; i < buf->numkeys; i++) {
		assert(klist[i].rectype == PGRDISKKEY);

		/*
		 * Was the key previously read, if not restore it
		 */
		key = spc_pr_key_find(pgr, 0, T10_PGR_INAME(cmd),
		    T10_PGR_TNAME(cmd));
		if (key == NULL)
			key = spc_pr_key_alloc(pgr, klist[i].key,
			    klist[i].i_name, klist[i].transportID);
		assert(key);
	}

	/*
	 * Get the PGR reservations
	 */
	rlist = (spc_pr_diskrsrv_t *)&buf->keylist[buf->numkeys];
	for (i = 0; i < buf->numrsrv; i++) {
		assert(rlist[i].rectype == PGRDISKRSRV);

		/*
		 * Was the reservation previously read, if not restore it
		 */
		rsrv = spc_pr_rsrv_find(pgr, 0, T10_PGR_INAME(cmd),
		    T10_PGR_TNAME(cmd));
		if (rsrv == NULL)
			rsrv = spc_pr_rsrv_alloc(pgr, rlist[i].key,
			    rlist[i].i_name, rlist[i].transportID,
			    rlist[i].scope, rlist[i].type);
		assert(rsrv);
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
		(void) pthread_mutex_lock(&cmd->c_lu->l_common->l_common_mutex);
		lu = avl_first(&cmd->c_lu->l_common->l_all_open);
		do {
			lu->l_cmd = sbc_cmd_reserved;
			lu = AVL_NEXT(&cmd->c_lu->l_common->l_all_open, lu);
		} while (lu != NULL);
		(void) pthread_mutex_unlock(
		    &cmd->c_lu->l_common->l_common_mutex);
	}

	free(buf);
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
	char			*c, path[MAXPATHLEN] = {0};
	Boolean_t		status = True;

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
		klist[i].key = key->k_key;
		(void) strncpy(klist[i].i_name, key->k_i_name,
		    sizeof (klist[i].i_name));
		(void) strncpy(klist[i].transportID, key->k_transportID,
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
		rlist[i].key = rsrv->r_key;
		rlist[i].scope = rsrv->r_scope;
		rlist[i].type = rsrv->r_type;
		(void) strncpy(rlist[i].i_name, rsrv->r_i_name,
		    sizeof (rlist[i].i_name));
		(void) strncpy(rlist[i].transportID, rsrv->r_transportID,
		    sizeof (rlist[i].transportID));
	}

	/*
	 * Open the PERSISTENCE file specification if one exists
	 * taking into account the alternate location if a ZVOL
	 */
	if (tgt_find_value_str(cmd->c_lu->l_common->l_root, XML_ELEMENT_BACK,
	    &c) == True) {
		if (((pgr_basedir != NULL) && (strlen(pgr_basedir) != 0)) &&
		    (strncmp(ZVOL_PATH, c, sizeof (ZVOL_PATH) - 1) == 0)) {
			(void) snprintf(path, MAXPATHLEN, "%s/%s-%s%d",
			    pgr_basedir, &c[sizeof (ZVOL_PATH) - 1],
			    PERSISTENCEBASE, cmd->c_lu->l_common->l_num);
		} else {
			(void) snprintf(path, MAXPATHLEN, "%s/%s/%s%d",
			    target_basedir, cmd->c_lu->l_targ->s_targ_base,
			    PERSISTENCEBASE, cmd->c_lu->l_common->l_num);
		}
		free(c);
	}
	if ((pfd = open(path, O_WRONLY|O_CREAT, 0600)) >= 0) {
		length = write(pfd, buf, bufsize);
		(void) close(pfd);
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
