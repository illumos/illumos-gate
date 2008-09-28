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

/*
 * []------------------------------------------------------------------[]
 * | SPC-3 Support Functions						|
 * | These routines are not directly called by the SAM-3 layer. Those	|
 * | who write device emulation modules are free to call these routine	|
 * | to carry out housekeeping chores.					|
 * []------------------------------------------------------------------[]
 */

#include <sys/types.h>
#include <sys/asynch.h>
#include <sys/param.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>

#include <sys/scsi/generic/sense.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/generic/inquiry.h>
#include <sys/scsi/generic/mode.h>
#include <sys/scsi/generic/commands.h>

#include "t10.h"
#include "t10_spc.h"
#include "target.h"

void spc_free(emul_handle_t id);

/*
 * []----
 * | spc_unsupported -- generic routine to indicate we don't support this cmd
 * []----
 */
/*ARGSUSED*/
void
spc_unsupported(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	char	debug[80];

	(void) snprintf(debug, sizeof (debug),
	    "SAM%d  LUN%d Command 0x%x (%s) unsupported\n",
	    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num,
	    cdb[0], cmd->c_lu->l_cmd_table[cdb[0]].cmd_name != NULL ?
	    cmd->c_lu->l_cmd_table[cdb[0]].cmd_name : "No description");
	queue_str(mgmtq, Q_STE_ERRS, msg_log, debug);

	spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
	spc_sense_ascq(cmd, 0x20, 0x00);
	trans_send_complete(cmd, STATUS_CHECK);
}

/*
 * []----
 * | spc_tur -- test unit ready
 * []----
 */
/*ARGSUSED*/
void
spc_tur(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	/*
	 * SPC-3 Revision 21c, section 6.31
	 * Reserve bit checks
	 */
	if (cdb[1] || cdb[2] || cdb[3] || cdb[4] ||
	    SAM_CONTROL_BYTE_RESERVED(cdb[5])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
	} else
		trans_send_complete(cmd, STATUS_GOOD);
}

/*
 * []----
 * | spc_request_sense --
 * []----
 */
/*ARGSUSED*/
void
spc_request_sense(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	/* ---- Check for reserved bit conditions ---- */
	if ((cdb[1] & 0xfe) || cdb[2] || cdb[3] ||
	    SAM_CONTROL_BYTE_RESERVED(cdb[5])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
	} else {
		/*
		 * Since we always run with autosense enabled there's
		 * no sense data to return. That may change in the future
		 * if we decide to add such support, but for now return
		 * success always.
		 */
		spc_sense_create(cmd, 0, 0);
		trans_send_complete(cmd, STATUS_GOOD);
	}
}

/*
 * []----
 * | spc_inquiry -- Standard INQUIRY command
 * []----
 */
/*ARGSUSED*/
void
spc_inquiry(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	uint8_t			*rsp_buf;
	uint8_t			*rbp;		/* temporary var */
	uint8_t			evpd;
	struct scsi_inquiry	*inq;
	uint32_t		len;
	uint32_t		page83_len;
	uint32_t		rqst_len;
	uint32_t		rtn_len;
	struct vpd_hdr		*vhp;
	struct vpd_desc		vd;
	size_t			scsi_len;
	t10_lu_common_t		*lu = cmd->c_lu->l_common;
	void			*v;
	uint16_t		*vdv;
	extended_inq_data_t	*eid;

	/*
	 * Information obtained from:
	 *	SPC-3 Revision 21c
	 *	Section 6.4.1 INQUIRY command
	 * Need to generate a CHECK CONDITION with ILLEGAL REQUEST
	 * and INVALID FIELD IN CDB (0x24/0x00) if any of the following is
	 * true.
	 *    (1) If the EVPD bit is not set, then the page code must be zero.
	 *    (2) If any bit other than EVPD is set.
	 *    (3) If any of the reserved bits in the CONTROL byte are set.
	 */
	/*
	 * SPC-3,4 keyword reserved:
	 * ...Receipts are not required to check reserved bits, bytes, words
	 * or fields for zero values.
	 *
	 * Ignore the check for reserved fields in the CDB byte 1.
	 */
	evpd = cdb[1] & 1;
	if ((evpd == 0 && (cdb[2] != 0)) || SAM_CONTROL_BYTE_RESERVED(cdb[5])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	rqst_len = cdb[3] << 8 | cdb[4];
	/*
	 * Zero length is not an error and we should just acknowledge
	 * the operation.
	 */
	if (rqst_len == 0) {
		trans_send_complete(cmd, STATUS_GOOD);
		return;
	}

	/*
	 * We send back a total of six Vital Product Data descriptors
	 * plus associated data. Three are EUI values, two are for AULA
	 * support being simple 4 byte values, and one is the IQN string.
	 * NOTE: The IQN string is just an artifact of when the target
	 * was created. Once FC support is added, the t_name would be
	 * either a "naa." or "eui." string.
	 */
	scsi_len = ((strlen(cmd->c_lu->l_targ->s_targ_base) + 1) + 3) & ~3;
	page83_len = (sizeof (struct vpd_desc) * 6) + scsi_len +
	    (lu->l_guid_len * 3) + (sizeof (uint32_t) * 2);

	/*
	 * We always allocate enough space so that the code can create
	 * either the full inquiry data or page 0x83 data.
	 */
	len = sizeof (struct vpd_hdr) + page83_len;
	len = max(rqst_len, max(sizeof (*inq), len));
	len = max(len, sizeof (*eid));

	/*
	 * Allocate space with an alignment that will work for any casting.
	 */
	if ((v = memalign(sizeof (void *), len)) == NULL) {
		trans_send_complete(cmd, STATUS_BUSY);
		return;
	}
	bzero(v, len);
	rsp_buf = (uint8_t *)v;

	/*
	 * EVPD not set returns the standard inquiry data.
	 */
	if (evpd == 0) {
		/*
		 * Return whatever is the smallest amount between the
		 * INQUIRY data or the amount requested.
		 * Version descriptor details also should be included
		 * with the inquiry response. So, rtn_len should consider
		 * version descriptor details in standard inquiry format
		 * as per SPC-3 Revision 23, Section 6.4.2 Table 81
		 */

		rtn_len = min(rqst_len, max(sizeof (*inq),
		    (SPC_INQ_VD_IDX + SPC_INQ_VD_LEN)));

		inq = (struct scsi_inquiry *)rsp_buf;
		/*
		 * SPC-3 Revision 21c, Section 6.4.2 .. Table 82 -- Version
		 * This target will comply with T10/1416-D
		 */
		inq->inq_ansi		= SPC_INQ_VERS_SPC_3;

		inq->inq_len		= sizeof (*inq) - 4;
		inq->inq_dtype		= lu->l_dtype;
		inq->inq_normaca	= 0;
		inq->inq_rdf		= SPC_INQ_RDF;
		inq->inq_cmdque		= 1;
		inq->inq_linked		= 0;

		/*
		 * JIST Requires that we show support for hierarchical
		 * support (HiSup).
		 */
		inq->inq_hisup		= 1;

		/*
		 * SPC-4, revision 1a, section 6.4.2
		 * Stand INQUIRY Data
		 * To support MPxIO we enable ALUA support and identify
		 * all paths to this device as being active/optimized
		 * we defaults to symmertrical devices.
		 */
		inq->inq_tpgs		= 1;

		(void) snprintf(inq->inq_vid,
		    sizeof (inq->inq_vid) + sizeof (inq->inq_pid) +
		    sizeof (inq->inq_revision), "%-8s%-16s%-4s",
		    lu->l_vid, lu->l_pid,
		    DEFAULT_REVISION);

		/*
		 * SPC-3 Revision 21c, section 6.4.2
		 * Table 85 -- Version Descriptor values
		 * Starting at byte 58 there are up to 8 version
		 * descriptors which are 16bits in size.
		 *
		 * NOTE: The ordering of these values is according
		 * to the standard. First comes the architectural
		 * version and then followed by: physical transport,
		 * SCSI transport, primary command set version, and
		 * finally the device type command set.
		 */
		vdv = &((uint16_t *)v)[29];

		/* SAM-3 T10/1561-D rev 14 */
		*vdv++ = htons(SPC_INQ_VD_SAM3);

		/* physical transport code unknown */
		*vdv++ = htons(0x0000);

		*vdv++ = htons(cmd->c_lu->l_targ->s_trans_vers);

		/* SPC ANSI X3.301:1997 */
		*vdv++ = htons(SPC_INQ_VD_SPC3);

		if (lu->l_dtype == DTYPE_DIRECT) {
			/* SBC-2 T10/1417-D rev 5a */
			*vdv++ = htons(SPC_INQ_VD_SBC2);
		} else if (lu->l_dtype == DTYPE_SEQUENTIAL) {
			/* SSC-2 (no version) */
			*vdv++ = htons(SPC_INQ_VD_SSC3);
		} else if (lu->l_dtype == DTYPE_OSD) {
			/* OSD T10/1355-D revision 10 */
			*vdv++ = htons(SPC_INQ_VD_OSD);
		}

	} else {

		/* ---- Common information returned with all page types ---- */
		rsp_buf[0] = lu->l_dtype;
		rsp_buf[1] = cdb[2];

		queue_prt(mgmtq, Q_STE_NONIO, "SPC%d  INQUIRY Page%x request\n",
		    lu->l_num, cdb[2]);
		switch (cdb[2]) {
		default:
			spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
			spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
			trans_send_complete(cmd, STATUS_CHECK);
			return;

		case SPC_INQ_PAGE0:
			/*
			 * SPC-3 Revision 21c Section 7.6.10
			 * EVPD page 0 returns information about which pages
			 * are supported. We support page 0x00 and 0x83.
			 * NOTE: The value found in byte[3] is the returned
			 * page length as defined by (n - 3) where 'n' is
			 * the last valid byte. In this case 5.
			 */
			rsp_buf[3]	= 4;
			rsp_buf[4]	= SPC_INQ_PAGE0;
			rsp_buf[5]	= SPC_INQ_PAGE80;
			rsp_buf[6]	= SPC_INQ_PAGE83;
			rsp_buf[7]	= SPC_INQ_PAGE86;

			/*
			 * Return the smallest amount of data between the
			 * requested amount and the size of the Page83 data.
			 */
			rtn_len = min(rqst_len, sizeof (struct vpd_hdr) +
			    rsp_buf[3]);
			break;

		case SPC_INQ_PAGE80:
			/*
			 * Return the smallest amount of data between the
			 * requested amount and the size of the Page80 data.
			 */
			rtn_len = min(rqst_len, sizeof (struct vpd_hdr) + 4);
			rsp_buf[3]	= 4;
			rsp_buf[4]	= 0x20;
			rsp_buf[5]	= 0x20;
			rsp_buf[6]	= 0x20;
			rsp_buf[7]	= 0x20;
			break;

		case SPC_INQ_PAGE83:
			/*
			 * Return the smallest amount of data between the
			 * requested amount and the size of the Page83 data.
			 */
			rtn_len = min(rqst_len, sizeof (struct vpd_hdr) +
			    page83_len);

			/*
			 * Information obtained from:
			 *    SPC-3 Revision 21c
			 *    Section 7.6.4.1
			 */

			/* ---- VPD header ---- */
			vhp = (struct vpd_hdr *)v;
			vhp->device_type	= lu->l_dtype;
			vhp->periph_qual	= SPC_INQUIRY_PERIPH_CONN;
			vhp->page_code		= cdb[2];
			vhp->page_len[0]	= hibyte(loword(page83_len));
			vhp->page_len[1]	= lobyte(loword(page83_len));
			rbp			= (uint8_t *)v + sizeof (*vhp);

			/* ---- VPD descriptor ---- */
			/*
			 * SPC-4 revision 1a, section 7.6.3.8
			 * Target port group designator format
			 */
			/* initialize descriptor */
			bzero(&vd, sizeof (vd));
			vd.code_set	= SPC_INQUIRY_CODE_SET_BINARY;
			vd.id_type	= SPC_INQUIRY_ID_TYPE_TARG_PORT;
			vd.proto_id	= SPC_INQUIRY_PROTOCOL_ISCSI;
			vd.association	= SPC_INQUIRY_ASSOC_TARGPORT;
			vd.piv		= 1;
			vd.len		= 4;
			bcopy(&vd, rbp, sizeof (vd));
			rbp		+= sizeof (vd);

			len		= SPC_DEFAULT_TPG;
			rbp[2]		= hibyte(loword(len));
			rbp[3]		= lobyte(loword(len));
			rbp		+= vd.len;

			/* ---- VPD descriptor ---- */
			/*
			 * SPC-4, revision 1a, section 7.6.3.7
			 * Relative target port designator format
			 */
			vd.code_set	= SPC_INQUIRY_CODE_SET_BINARY;
			vd.id_type	= SPC_INQUIRY_ID_TYPE_RELATIVE;
			vd.proto_id	= SPC_INQUIRY_PROTOCOL_ISCSI;
			vd.association	= SPC_INQUIRY_ASSOC_TARGPORT;
			vd.piv		= 1;
			vd.len		= 4;
			bcopy(&vd, rbp, sizeof (vd));
			rbp		+= sizeof (vd);

			rbp[2]	= hibyte(loword(cmd->c_lu->l_targ->s_tpgt));
			rbp[3]	= lobyte(loword(cmd->c_lu->l_targ->s_tpgt));
			rbp	+= vd.len;

			assert(lu->l_guid != NULL);
			/* ---- VPD descriptor ---- */
			vd.code_set	= SPC_INQUIRY_CODE_SET_BINARY;
			vd.id_type	= SUN_INQUIRY_ID_TYPE(lu->l_guid);
			vd.proto_id	= SPC_INQUIRY_PROTOCOL_ISCSI;
			vd.association	= SPC_INQUIRY_ASSOC_LUN;
			/*
			 * If the ASSOCIATION field contains a value other
			 * than 01b or 10b, then the PIV bit contents are
			 * reserved. SPC-4 revision 11 section 7.6.3.1.
			 */
			vd.piv		= 0;
			vd.len		= lu->l_guid_len;
			bcopy(&vd, rbp, sizeof (vd));
			rbp		+= sizeof (vd);

			bcopy(lu->l_guid, &rbp[0], lu->l_guid_len);
			rbp		+= lu->l_guid_len;

			/* ---- VPD descriptor ---- */
			vd.code_set	= SPC_INQUIRY_CODE_SET_UTF8;
			vd.id_type	= SPC_INQUIRY_ID_TYPE_SCSI;
			vd.proto_id	= SPC_INQUIRY_PROTOCOL_ISCSI;
			vd.association	= SPC_INQUIRY_ASSOC_TARG;
			vd.piv		= 1;
			vd.len		= scsi_len;
			bcopy(&vd, rbp, sizeof (vd));
			rbp		+= sizeof (vd);

			/*
			 * SPC-3 revision 23, section 7.6.3.11
			 * Use the string length and not the scsi_len because
			 * we've rounded up the length to a multiple of four
			 * as required by the specification.
			 */
			bcopy(cmd->c_lu->l_targ->s_targ_base, &rbp[0],
			    strlen(cmd->c_lu->l_targ->s_targ_base));
			rbp		+= vd.len;

			/* ---- VPD descriptor ---- */
			vd.code_set	= SPC_INQUIRY_CODE_SET_BINARY;
			vd.id_type	= SUN_INQUIRY_ID_TYPE(lu->l_guid);
			vd.proto_id	= SPC_INQUIRY_PROTOCOL_ISCSI;
			vd.association	= SPC_INQUIRY_ASSOC_TARG;
			vd.piv		= 1;
			vd.len		= lu->l_guid_len;
			bcopy(&vd, rbp, sizeof (vd));
			rbp		+= sizeof (vd);

			/*
			 * XXX Is this right XXX
			 * Should we be using some other name.
			 */
			bcopy(lu->l_guid, &rbp[0], lu->l_guid_len);
			rbp		+= lu->l_guid_len;

			/* ---- VPD descriptor ---- */
			vd.code_set	= SPC_INQUIRY_CODE_SET_BINARY;
			vd.id_type	= SUN_INQUIRY_ID_TYPE(lu->l_guid);
			vd.proto_id	= SPC_INQUIRY_PROTOCOL_ISCSI;
			vd.association	= SPC_INQUIRY_ASSOC_TARGPORT;
			vd.piv		= 1;
			vd.len		= lu->l_guid_len;
			bcopy(&vd, rbp, sizeof (vd));
			rbp		+= sizeof (vd);

			/*
			 * XXX Is this right XXX
			 * Should we be using some other name.
			 */
			bcopy(lu->l_guid, &rbp[0], lu->l_guid_len);

			/*
			 * rbp is updated here even though nobody will
			 * currently use it. Currently is the optertive word
			 * here. If for some reason we add another VDP
			 * then the pointer will be correct.
			 */
			rbp		+= lu->l_guid_len;

			break;

		case SPC_INQ_PAGE86:
			/*
			 * Return the smallest amount of data between the
			 * requested amount and the size of the Page86 data.
			 */
			rtn_len = min(rqst_len, sizeof (*eid));
			eid = (extended_inq_data_t *)v;
			eid->ei_hdr.device_type = lu->l_dtype;
			eid->ei_hdr.page_code = cdb[2];
			eid->ei_hdr.page_len[1] = 60; /* defined by spec */

			/*
			 * At this point in time we don't support any of the
			 * extended data attributes. We should support
			 * the task management bits though.
			 */
			break;
		}
	}

	if (trans_send_datain(cmd, (char *)rsp_buf, rtn_len, 0, spc_free,
	    True, rsp_buf) == False) {
		trans_send_complete(cmd, STATUS_BUSY);
	}
}

/*
 * []----
 * | spc_mselect -- Generic MODE SELECT command
 * []----
 */
/*ARGSUSED*/
void
spc_mselect(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	char	*buf;

	/*
	 * SPC-3 revision 21c, section 6.7
	 * Reserve bit checks
	 */
	if ((cdb[1] & 0xee) || cdb[2] || cdb[3] ||
	    SAM_CONTROL_BYTE_RESERVED(cdb[5])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	if (cdb[4] == 0) {
		trans_send_complete(cmd, STATUS_GOOD);
		return;
	}

	if (((buf = (char *)calloc(1, cdb[4])) == NULL) ||
	    (trans_rqst_dataout(cmd, buf, cdb[4], 0, buf,
	    spc_free) == False)) {
		trans_send_complete(cmd, STATUS_BUSY);
	}
}

/*
 * []----
 * | spc_mselect_data -- DataIn phase of MODE SELECT command
 * []----
 */
/*ARGSUSED*/
void
spc_mselect_data(t10_cmd_t *cmd, emul_handle_t id, size_t offset, char *data,
    size_t data_len)
{
	struct mode_control_scsi3	mode_ctl_page;
	struct mode_header		hdr;

	bcopy(data, &hdr, sizeof (hdr));
	bcopy(data + sizeof (hdr) + hdr.bdesc_length, &mode_ctl_page,
	    sizeof (mode_ctl_page));

	switch (mode_ctl_page.mode_page.code) {
	case MODE_SENSE_CONTROL:
		/*
		 * SPC-3 revision 21c, section 7.4.6
		 * Table 239 describes the fields. We're only interested
		 * in the descriptor sense bit.
		 */
		if (mode_ctl_page.d_sense == 1) {
			cmd->c_lu->l_dsense_enabled = True;
		} else {
			cmd->c_lu->l_dsense_enabled = False;
		}
		break;

	default:
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}
	trans_send_complete(cmd, STATUS_GOOD);
}

/*
 * []----
 * | spc_report_luns --
 * []----
 */
/*ARGSUSED*/
void
spc_report_luns(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	int		expected_data;
	uint8_t		*buf			= NULL;
	int		entries			= 0;
	int		len;
	int		len_network;
	int		select;
	int		lun_idx;
	int		lun_val;
	char		*str;
	tgt_node_t	*targ;
	tgt_node_t	*lun_list;
	tgt_node_t	*lun;

	/*
	 * SPC-3 Revision 21c section 6.21
	 * Error checking.
	 */
	if (cdb[1] || cdb[3] || cdb[4] ||
	    (cdb[2] & ~SPC_RPT_LUNS_SELECT_MASK) || cdb[5] || cdb[10] ||
	    SAM_CONTROL_BYTE_RESERVED(cdb[11])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	expected_data = cdb[6] << 24 | cdb[7] << 16 | cdb[8] << 8 | cdb[9];
	if (expected_data < 16) {
		/*
		 * The allocation length should be at least 16 according
		 * to SPC-3.
		 */
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}
	select = cdb[2];

	targ = NULL;
	(void) pthread_rwlock_rdlock(&targ_config_mutex);
	while ((targ = tgt_node_next_child(targets_config, XML_ELEMENT_TARG,
	    targ)) != NULL) {
		if (tgt_find_value_str(targ, XML_ELEMENT_INAME, &str) ==
		    False) {
			goto error;
		}
		if (strcmp(str, cmd->c_lu->l_targ->s_targ_base) == 0) {
			free(str);
			break;
		} else
			free(str);
	}
	if (!targ)
		goto error;
	if ((lun_list = tgt_node_next(targ, XML_ELEMENT_LUNLIST, NULL)) == NULL)
		goto error;

	lun = NULL;
	while ((lun = tgt_node_next(lun_list, XML_ELEMENT_LUN, lun)) != NULL)
		entries++;


	len = entries * SCSI_REPORTLUNS_ADDRESS_SIZE;
	if ((buf = (uint8_t *)calloc(1, MAX(expected_data, len))) == NULL) {
		trans_send_complete(cmd, STATUS_BUSY);
		(void) pthread_rwlock_unlock(&targ_config_mutex);
		return;
	}

	len_network = htonl(len);
	bcopy(&len_network, buf, sizeof (len_network));

	if (expected_data >= (len + SCSI_REPORTLUNS_ADDRESS_SIZE)) {

		lun_idx = SCSI_REPORTLUNS_ADDRESS_SIZE;
		lun	= NULL;
		while ((lun = tgt_node_next(lun_list, XML_ELEMENT_LUN, lun)) !=
		    NULL) {
			if (tgt_find_value_int(lun, XML_ELEMENT_LUN,
			    &lun_val) == False)
				goto error;
			if (spc_encode_lu_addr(&buf[lun_idx], select,
			    lun_val) == False)
				continue;
			lun_idx += SCSI_REPORTLUNS_ADDRESS_SIZE;
		}
		if (trans_send_datain(cmd, (char *)buf,
		    len + SCSI_REPORTLUNS_ADDRESS_SIZE, 0, spc_free, True,
		    buf) == False) {
			trans_send_complete(cmd, STATUS_BUSY);
		}
	} else {
		/*
		 * This will return the size needed to complete this request
		 * and a implicit LUN zero.
		 */
		if (trans_send_datain(cmd, (char *)buf, 16, 0, spc_free, True,
		    buf) == False) {
			trans_send_complete(cmd, STATUS_BUSY);
		}
	}
	(void) pthread_rwlock_unlock(&targ_config_mutex);
	return;

error:
	(void) pthread_rwlock_unlock(&targ_config_mutex);
	if (buf)
		free(buf);
	spc_sense_create(cmd, KEY_HARDWARE_ERROR, 0);
	trans_send_complete(cmd, STATUS_CHECK);
}

/*ARGSUSED*/
void
spc_report_tpgs(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	rtpg_hdr_t		*r;
	rtpg_desc_t		*dp;
	rtpg_targ_desc_t	*tp;
	int			rqst_len;
	int			alloc_len;
	int			i;
	t10_lu_common_t		*lu	= cmd->c_lu->l_common;
	t10_lu_impl_t		*lu_per;

	if (disable_tpgs == True) {
		spc_unsupported(cmd, cdb, cdb_len);
		return;
	}

	/*
	 * Reserve bit checks
	 */
	if ((cdb[1] & 0xe0) || (cdb[1] & ~SPC_MI_SVC_MASK) ||
	    ((cdb[1] & SPC_MI_SVC_MASK) != SPC_MI_SVC_RTPG) ||
	    cdb[2] || cdb[3] || cdb[4] || cdb[5] ||
	    cdb[10] || SAM_CONTROL_BYTE_RESERVED(cdb[11])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	/*
	 * We only have one target port group which it's size is
	 * accounted for in rtpg_hdr_t. Take the number of tgts
	 * and subtract one since the first is accounted for in
	 * rtpg_targ_desc_t
	 */
	(void) pthread_mutex_lock(&lu->l_common_mutex);
	alloc_len = ((avl_numnodes(&lu->l_all_open) - 1) *
	    sizeof (rtpg_targ_desc_t)) + sizeof (rtpg_hdr_t);
	(void) pthread_mutex_unlock(&lu->l_common_mutex);

	/*
	 * Make sure that we have enough room to store everything
	 * that we want to, but only returned the requested about
	 * of data which is why d->d_len is set to the request amount.
	 * A client could issue a REPORT_TPGS with a length of 4 bytes
	 * which would be just enough to see how much space is actually
	 * used.
	 */
	rqst_len = cdb[6] << 24 | cdb[7] << 16 |
	    cdb[8] << 8 | cdb[9];

	if (rqst_len == 0) {
		trans_send_complete(cmd, STATUS_GOOD);
		return;
	}

	if ((r = (rtpg_hdr_t *)calloc(1, alloc_len)) == NULL) {
		trans_send_complete(cmd, STATUS_BUSY);
		return;
	}

	i		= alloc_len - sizeof (r->len);
	r->len[0]	= hibyte(hiword(i));
	r->len[1]	= lobyte(hiword(i));
	r->len[2]	= hibyte(loword(i));
	r->len[3]	= lobyte(loword(i));
	dp		= &r->desc_list[0];
	(void) pthread_mutex_lock(&lu->l_common_mutex);
	dp->tpg_cnt	= avl_numnodes(&lu->l_all_open);
	(void) pthread_mutex_unlock(&lu->l_common_mutex);
	dp->status_code	= 0;
	dp->access_state	= 0; /* Active/optimized */
	dp->pref	= 1;
	dp->t_sup	= 1;
	dp->u_sup	= 1;
	dp->s_sup	= 1;
	dp->an_sup	= 0;
	dp->ao_sup	= 1;
	i		= SPC_DEFAULT_TPG;
	dp->tpg[0]	= hibyte(loword(i));
	dp->tpg[1]	= lobyte(loword(i));

	tp		= &dp->targ_list[0];
	(void) pthread_mutex_lock(&lu->l_common_mutex);
	lu_per		= avl_first(&lu->l_all_open);
	do {
		tp->rel_tpi[0] = hibyte(loword(lu_per->l_targ->s_tpgt));
		tp->rel_tpi[1] = lobyte(loword(lu_per->l_targ->s_tpgt));
		lu_per = AVL_NEXT(&lu->l_all_open, lu_per);
		tp++;
	} while (lu_per != NULL);
	(void) pthread_mutex_unlock(&lu->l_common_mutex);

	if (trans_send_datain(cmd, (char *)r, MIN(rqst_len, alloc_len), 0,
	    spc_free, True, (char *)r) == False) {
		trans_send_complete(cmd, STATUS_BUSY);
	}
}

/*ARGSUSED*/
void
spc_send_diag(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	/*
	 * SPC-3 Revision 21c, section 6.27
	 * Reserve bit checks
	 */
	if ((cdb[1] & ~SPC_SEND_DIAG_SELFTEST) || cdb[2] || cdb[3] || cdb[4] ||
	    SAM_CONTROL_BYTE_RESERVED(cdb[5])) {
		spc_sense_create(cmd, KEY_ILLEGAL_REQUEST, 0);
		spc_sense_ascq(cmd, SPC_ASC_INVALID_CDB, 0x00);
		trans_send_complete(cmd, STATUS_CHECK);
		return;
	}

	/*
	 * There's no diagnostics to be run at this time. So, always
	 * return success. If, at some point in the future, it's determined
	 * that something can be done which is meaningful then place the
	 * code here.
	 */
	trans_send_complete(cmd, STATUS_GOOD);
}

void
spc_free(emul_handle_t id)
{
	free(id);
}

/*
 * []----
 * | spc_cmd_offline -- return IN_PROGRESS for media related commands
 * |
 * | During LU initialization the device is in an offline state. When
 * | offlined only non-media related commands are allowed to proceed.
 * | TEST_UNIT_READY is considered a media command since it must return
 * | a CHECK_CONDITION if a media command would do so.
 * []----
 */
void
spc_cmd_offline(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len)
{
	scsi_cmd_table_t	*e;
	int			old_dtype;

	e = &cmd->c_lu->l_cmd_table[cdb[0]];

	switch (cdb[0]) {
	case SCMD_TEST_UNIT_READY:
	case SCMD_START_STOP:
	case SCMD_READ:
	case SCMD_READ_G1:
	case SCMD_READ_G4:
	case SCMD_WRITE:
	case SCMD_WRITE_G1:
	case SCMD_WRITE_G4:
#ifdef FULL_DEBUG
		queue_prt(mgmtq, Q_STE_IO, "SPC%x  LUN%d Cmd %s\n",
		    cmd->c_lu->l_targ->s_targ_num, cmd->c_lu->l_common->l_num,
		    e->cmd_name == NULL ? "(no name)" : e->cmd_name);
#endif
		spc_sense_create(cmd, KEY_NOT_READY, 0);
		spc_sense_ascq(cmd, SPC_ASC_IN_PROG, SPC_ASCQ_IN_PROG);
		trans_send_complete(cmd, STATUS_CHECK);
		break;

	case SCMD_INQUIRY:
		/*
		 * While the device is being initialized any inquiry commands
		 * will return an unknown device type. This will cause the
		 * transport to hold off further plumbing until the
		 * initialization is complete and we send the inventory change
		 * notice.
		 */
		old_dtype = cmd->c_lu->l_common->l_dtype;
		cmd->c_lu->l_common->l_dtype	= 0x1f;
		(*e->cmd_start)(cmd, cdb, cdb_len);
		cmd->c_lu->l_common->l_dtype	= old_dtype;
		break;

	default:
		(*e->cmd_start)(cmd, cdb, cdb_len);
		break;
	}
}

/*
 * []----
 * | spc_sense_create -- allocate sense structure
 * |
 * | If additional header sense length is requested and the I_T_Q has
 * | enabled descriptor sense data allocate the space.
 * []----
 */
void
spc_sense_create(t10_cmd_t *cmd, int sense_key, int addl_sense_len)
{
	char	*buf;
	int	size;

	/*
	 * It's possible under certain conditions -- namely a malloc error
	 * when setting up a command -- that the pointer to the ITL structure
	 * isn't valid. If that's the case don't attempt to dereference it
	 * to look at the dsense_enabled flag.
	 */
	if ((cmd->c_lu != NULL) && (cmd->c_lu->l_dsense_enabled == True)) {
		struct scsi_descr_sense_hdr d;

		if ((buf = (char *)calloc(1,
		    sizeof (d) + 2 + addl_sense_len)) == NULL)
			return;

		size = sizeof (d) + addl_sense_len;
		bzero(&d, sizeof (d));
		d.ds_class		= CLASS_EXTENDED_SENSE;
		d.ds_code		= CODE_FMT_DESCR_CURRENT;
		d.ds_key		= sense_key;
		d.ds_addl_sense_length	= addl_sense_len;
		bcopy(&d, &buf[2], sizeof (d));

	} else {
		struct scsi_extended_sense	e;

		if ((buf = (char *)calloc(1, sizeof (e) + 2)) == NULL)
			return;
		size = sizeof (e);
		bzero(&e, sizeof (e));
		e.es_class	= CLASS_EXTENDED_SENSE;
		e.es_code	= CODE_FMT_FIXED_CURRENT;
		e.es_key	= sense_key;
		bcopy(&e, &buf[2], size);

	}

	/* ---- First two bytes of the sense store the length ---- */
	buf[0]	= hibyte(loword(size));
	buf[1]	= lobyte(loword(size));

	cmd->c_cmd_sense	= buf;
	cmd->c_cmd_sense_len	= size + 2;
}

/*
 * []----
 * | spc_sense_raw -- copy an existing sense buffer for return.
 * |
 * | If an emulation module already has a sense buffer there's no need
 * | to decode the sense data and call the various spc_sense_ routines
 * | to reencode the information.
 * []----
 */
void
spc_sense_raw(t10_cmd_t *cmd, uchar_t *sense_buf, size_t sense_len)
{
	ushort_t	s = (ushort_t)sense_len;
	if ((cmd->c_cmd_sense = malloc(sense_len + 2)) == NULL)
		return;
	bcopy(sense_buf, &cmd->c_cmd_sense[2], sense_len);
	cmd->c_cmd_sense[0]	= hibyte(s);
	cmd->c_cmd_sense[1]	= lobyte(s);
	cmd->c_cmd_sense_len	= s + 2;
}

void
spc_sense_ascq(t10_cmd_t *cmd, int asc, int ascq)
{
	struct scsi_extended_sense	s;
	struct scsi_descr_sense_hdr	d;

	bcopy(&cmd->c_cmd_sense[2], &s, sizeof (s));

	switch (s.es_code) {
	case CODE_FMT_DESCR_CURRENT:
	case CODE_FMT_DESCR_DEFERRED:
		bcopy(&cmd->c_cmd_sense[2], &d, sizeof (d));
		d.ds_add_code	= asc;
		d.ds_qual_code	= ascq;
		bcopy(&d, &cmd->c_cmd_sense[2], sizeof (d));
		break;

	default:
		s.es_add_code	= asc;
		s.es_qual_code	= ascq;
		bcopy(&s, &cmd->c_cmd_sense[2], sizeof (s));
		break;
	}
}

void
spc_sense_info(t10_cmd_t *cmd, uint64_t info)
{
	struct scsi_information_sense_descr	isd;
	struct scsi_extended_sense		s;
	char					*p;
	uint32_t				fixed_info = (uint32_t)info;

	switch (cmd->c_cmd_sense[2] & 0x0f) {
	case CODE_FMT_DESCR_CURRENT:
	case CODE_FMT_DESCR_DEFERRED:
		isd.isd_descr_type	= DESCR_INFORMATION;
		isd.isd_addl_length	= 0x0a;
		isd.isd_valid		= 1;
		isd.isd_information[0]	= (info >> 56) & 0xff;
		isd.isd_information[1]	= (info >> 48) & 0xff;
		isd.isd_information[2]	= (info >> 40) & 0xff;
		isd.isd_information[3]	= (info >> 32) & 0xff;
		isd.isd_information[4]	= (info >> 24) & 0xff;
		isd.isd_information[5]	= (info >> 16) & 0xff;
		isd.isd_information[6]	= (info >> 8) & 0xff;
		isd.isd_information[7]	= info & 0xff;
		p = &cmd->c_cmd_sense[2] + sizeof (struct scsi_descr_sense_hdr);
		bcopy(&isd, p, sizeof (isd));
		break;

	case CODE_FMT_VENDOR_SPECIFIC:
	case CODE_FMT_FIXED_CURRENT:
	case CODE_FMT_FIXED_DEFERRED:
	default:
		bcopy(&cmd->c_cmd_sense[2], &s, sizeof (s));

		s.es_valid	= 1;
		if (info > FIXED_SENSE_ADDL_INFO_LEN) {
			s.es_info_1 = 0xff;
			s.es_info_2 = 0xff;
			s.es_info_3 = 0xff;
			s.es_info_4 = 0xff;
		} else {
			s.es_info_1 = hibyte(hiword(fixed_info));
			s.es_info_2 = lobyte(hiword(fixed_info));
			s.es_info_3 = hibyte(loword(fixed_info));
			s.es_info_4 = lobyte(loword(fixed_info));
		}
		bcopy(&s, &cmd->c_cmd_sense[2], sizeof (s));
		break;
	}
}

void
spc_sense_flags(t10_cmd_t *cmd, int flags)
{
	struct scsi_extended_sense	s;

	bcopy(&cmd->c_cmd_sense[2], &s, sizeof (s));
	if (flags & SPC_SENSE_EOM)
		s.es_eom = 1;
	if (flags & SPC_SENSE_FM)
		s.es_filmk = 1;
	if (flags & SPC_SENSE_ILI)
		s.es_ili = 1;
	bcopy(&s, &cmd->c_cmd_sense[2], sizeof (s));
}

/*
 * []----
 * | spc_decode_lu_addr -- Decodes LU addressing as specified in SAM-3
 * []----
 */
Boolean_t
spc_decode_lu_addr(uint8_t *buf, int len, uint32_t *val)
{
	uint32_t	lun;

	if (len < 2)
		return (False);

	switch (buf[0] & SCSI_REPORTLUNS_ADDRESS_MASK) {
	case SCSI_REPORTLUNS_ADDRESS_PERIPHERAL:
	case SCSI_REPORTLUNS_ADDRESS_FLAT_SPACE:
		lun = ((buf[0] & 0x3f) << 8) | (buf[1] & 0xff);
		break;

	/*
	 * Since we never encode a LUN using this method, we
	 * shouldn't receive it back.
	 */
	case SCSI_REPORTLUNS_ADDRESS_LOGICAL_UNIT:
		return (False);

	case SCSI_REPORTLUNS_ADDRESS_EXTENDED_UNIT:
		switch (buf[0] & SCSI_REPORTLUNS_ADDRESS_EXTENDED_MASK) {
		case SCSI_REPORTLUNS_ADDRESS_EXTENDED_2B:
			lun = buf[1] & 0xff;
			break;

		case SCSI_REPORTLUNS_ADDRESS_EXTENDED_4B:
			if (len < 4)
				return (False);
			lun = buf[1] << 16 | buf[2] << 8 | (buf[3] & 0xff);
			break;

		case SCSI_REPORTLUNS_ADDRESS_EXTENDED_6B:
			if (len < 6)
				return (False);
			/*
			 * This should be able to handle a 40-bit LUN,
			 * but since our LUNs are only 32-bit we don't
			 * bother to decode buf[1]. This is okay since
			 * we generate the LUN in the first place.
			 */
			lun = buf[2] << 24 | buf[3] << 16 |
			    buf[4] << 8 | (buf[5] & 0xff);
			break;

		case SCSI_REPORTLUNS_ADDRESS_EXTENDED_8B:
			/*
			 * Since we current don't support larger than
			 * 32-bit LUNs we'll never create an extended
			 * address using this format. So, if we are to
			 * get this format in, just return an error.
			 */
			return (False);

		break;
		}
	}
	*val = lun;
	return (True);
}

/*
 * []----
 * | spc_encode_lu_addr -- encode, based on SAM-3/SPC-3 specs, a LUN
 * |
 * | NOTE: This routine only deals with 32-bit logical unit numbers.
 * | If this program ever switches to using larger values we need to
 * | simply deal with those formats.
 * []----
 */
Boolean_t
spc_encode_lu_addr(uint8_t *buf, int select_field, uint32_t lun)
{
	if (lun < 256) {

		/*
		 * SAM-3 revision 14, Section 4.9.6.
		 * No bus identifier for our luns.
		 */
		buf[0] = SCSI_REPORTLUNS_ADDRESS_PERIPHERAL;
		buf[1] = lun;

	} else if (lun <= T10_MAX_LUNS) {

		/*
		 * SAM-3 revision 14, Section 4.9.7.
		 * 14-bit flat address space.
		 */
		buf[0] = SCSI_REPORTLUNS_ADDRESS_FLAT_SPACE | (lun >> 8 & 0x3f);
		buf[1] = lun & 0xff;

	} else if (select_field == SCSI_REPORTLUNS_SELECT_ALL) {

		buf[0] = SCSI_REPORTLUNS_ADDRESS_EXTENDED_UNIT |
		    SCSI_REPORTLUNS_ADDRESS_EXTENDED_6B;
		/*
		 * 32-bit limitation. This format should be able to
		 * handle a 40-bit LUN.
		 */
		buf[1] = 0;
		buf[2] = lun >> 24 & 0xff;
		buf[3] = lun >> 16 & 0xff;
		buf[4] = lun >> 8 & 0xff;
		buf[5] = lun & 0xff;
	} else
		/*
		 * Either the user hasn't requested extended unit addressing
		 * or the LU is greater than 32bits. Since internally we
		 * only have 32bit numbers it's more likely that the initiator
		 * hasn't selected a correct report format.
		 */
		return (False);
	return (True);
}
