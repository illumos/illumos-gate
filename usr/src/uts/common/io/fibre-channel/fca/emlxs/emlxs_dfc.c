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
 * Copyright 2010 Emulex.  All rights reserved.
 * Use is subject to license terms.
 */


#include <emlxs.h>

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_DFC_C);

static int32_t		emlxs_dfc_get_rev(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_get_hbainfo(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_get_hbastats(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_get_drvstats(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_set_diag(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_send_mbox(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_read_pci(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_write_pci(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_get_cfg(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_set_cfg(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_send_menlo(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_send_ct(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_send_ct_rsp(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_write_flash(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_read_flash(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_send_els(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_loopback_test(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_get_dump_region(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_loopback_mode(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_get_ioinfo(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_get_linkinfo(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_read_mem(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_write_mem(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_write_ctlreg(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_read_ctlreg(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_get_event(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_set_event(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_get_eventinfo(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_get_nodeinfo(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);

#ifdef SFCT_SUPPORT
static int32_t		emlxs_dfc_get_fctstat(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
#endif /* SFCT_SUPPORT */

static int32_t		emlxs_dfc_create_vport(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_destroy_vport(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_get_vportinfo(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_npiv_resource(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_npiv_test(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static emlxs_port_t	*emlxs_vport_find_wwpn(emlxs_hba_t *hba, uint8_t *wwpn);

#ifdef DHCHAP_SUPPORT
static int32_t		emlxs_dfc_init_auth(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_get_auth_cfg(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_set_auth_cfg(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_get_auth_pwd(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_set_auth_pwd(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_get_auth_status(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_get_auth_cfg_table(emlxs_hba_t *hba,
				dfc_t *dfc, int32_t mode);
static int32_t		emlxs_dfc_get_auth_key_table(emlxs_hba_t *hba,
				dfc_t *dfc, int32_t mode);
#endif	/* DHCHAP_SUPPORT */

#ifdef SAN_DIAG_SUPPORT
static int32_t		emlxs_dfc_sd_set_bucket(dfc_t *dfc, int32_t mode);
static int32_t		emlxs_dfc_sd_destroy_bucket(dfc_t *dfc);
static int32_t		emlxs_dfc_sd_get_bucket(dfc_t *dfc, int32_t mode);
static int32_t		emlxs_dfc_sd_start_collection(emlxs_hba_t *hba,
				dfc_t *dfc, int32_t mode);
static int32_t		emlxs_dfc_sd_stop_collection(emlxs_hba_t *hba,
				dfc_t *dfc, int32_t mode);
static int32_t		emlxs_dfc_sd_reset_collection(emlxs_hba_t *hba,
				dfc_t *dfc, int32_t mode);
static int32_t		emlxs_dfc_sd_get_data(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_sd_set_event(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_sd_get_event(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
#endif	/* SAN_DIAG_SUPPORT */

static int32_t		emlxs_dfc_send_scsi_fcp(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
#ifdef FCIO_SUPPORT
static int32_t		emlxs_fcio_manage(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
#endif	/* FCIO_SUPPORT */

static int32_t		emlxs_dfc_get_persist_linkdown(emlxs_hba_t *hba,
				dfc_t *dfc, int32_t mode);
static int32_t		emlxs_dfc_set_persist_linkdown(emlxs_hba_t *hba,
				dfc_t *dfc, int32_t mode);

/* SLI-4 ioctls */
static int32_t		emlxs_dfc_get_fcflist(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int32_t		emlxs_dfc_send_mbox4(emlxs_hba_t *hba, dfc_t *dfc,
				int32_t mode);
static int		emlxs_dfc_rd_be_fcf(emlxs_hba_t *hba, dfc_t *dfc,
			    int32_t mode);
static int		emlxs_dfc_set_be_dcbx(emlxs_hba_t *hba, dfc_t *dfc,
			    int32_t mode);
static int		emlxs_dfc_get_be_dcbx(emlxs_hba_t *hba, dfc_t *dfc,
			    int32_t mode);
static int		emlxs_dfc_get_qos(emlxs_hba_t *hba, dfc_t *dfc,
			    int32_t mode);


uint32_t	emlxs_loopback_tmo = 60;

emlxs_table_t emlxs_dfc_table[] = {
	{EMLXS_GET_HBAINFO, "GET_HBAINFO"},
	{EMLXS_GET_REV, "GET_REV"},
	{EMLXS_SET_DIAG, "SET_DIAG"},
	{EMLXS_SEND_MBOX, "SEND_MBOX"},
	{EMLXS_READ_PCI, "READ_PCI"},
	{EMLXS_WRITE_PCI, "WRITE_PCI"},
	{EMLXS_GET_CFG, "GET_CFG"},
	{EMLXS_SET_CFG, "SET_CFG"},
	{EMLXS_SEND_CT, "SEND_CT"},
	{EMLXS_SEND_CT_RSP, "SEND_CT_RSP"},
	{EMLXS_SEND_MENLO, "SEND_MENLO"},
	{EMLXS_WRITE_FLASH, "WRITE_FLASH"},
	{EMLXS_READ_FLASH, "READ_FLASH"},
	{EMLXS_SEND_ELS, "SEND_ELS"},
	{EMLXS_LOOPBACK_TEST, "LOOPBACK_TEST"},
	{EMLXS_GET_DUMPREGION, "GET_DUMPREGION"},
	{EMLXS_LOOPBACK_MODE, "LOOPBACK_MODE"},
	{EMLXS_GET_IOINFO, "GET_IOINFO"},
	{EMLXS_GET_LINKINFO, "GET_LINKINFO"},
	{EMLXS_GET_NODEINFO, "GET_NODEINFO"},
	{EMLXS_READ_MEM, "READ_MEM"},
	{EMLXS_WRITE_MEM, "WRITE_MEM"},
	{EMLXS_WRITE_CTLREG, "WRITE_CTLREG"},
	{EMLXS_READ_CTLREG, "READ_CTLREG"},
	{EMLXS_SEND_SCSI, "SEND_SCSI"},
	{EMLXS_GET_EVENT, "GET_EVENT"},
	{EMLXS_SET_EVENT, "SET_EVENT"},
	{EMLXS_GET_EVENTINFO, "GET_EVENTINFO"},
	{EMLXS_GET_HBASTATS, "GET_HBASTATS"},
	{EMLXS_GET_DRVSTATS, "GET_DRVSTATS"},
	{EMLXS_CREATE_VPORT, "CREATE_VPORT"},
	{EMLXS_DESTROY_VPORT, "DESTROY_VPORT"},
	{EMLXS_GET_VPORTINFO, "GET_VPORTINFO"},
	{EMLXS_NPIV_RESOURCE, "NPIV_RESOURCE"},
	{EMLXS_NPIV_TEST, "NPIV_TEST"},
	{EMLXS_INIT_AUTH, "INIT_AUTH"},
	{EMLXS_GET_AUTH_CFG, "GET_AUTH_CFG"},
	{EMLXS_SET_AUTH_CFG, "SET_AUTH_CFG"},
	{EMLXS_GET_AUTH_PASSWORD, "GET_AUTH_PASSWORD"},
	{EMLXS_SET_AUTH_PASSWORD, "SET_AUTH_PASSWORD"},
	{EMLXS_GET_AUTH_STATUS, "GET_AUTH_STATUS"},
	{EMLXS_GET_AUTH_CFG_TABLE, "GET_AUTH_CFG_TABLE"},
	{EMLXS_GET_AUTH_KEY_TABLE, "GET_AUTH_KEY_TABLE"},
	{EMLXS_FCIO_CMD, "FCIO_CMD"},
	{EMLXS_GET_FCTSTAT, "GET_FCTSTAT"},
	{EMLXS_GET_PERSIST_LINKDOWN, "GET_PERSIST_LINKDOWN"},
	{EMLXS_SET_PERSIST_LINKDOWN, "SET_PERSIST_LINKDOWN"},
	{EMLXS_GET_FCOE_FCFLIST, "GET_FCOE_FCFLIST"},
	{EMLXS_SEND_MBOX4, "SEND_MBOX4"},
	{EMLXS_RD_BE_FCF, "RD_BE_FCF"},
	{EMLXS_SET_BE_DCBX, "SET_BE_DCBX"},
	{EMLXS_GET_BE_DCBX, "GET_BE_DCBX"},
	{EMLXS_GET_QOS, "GET_QOS"},

};	/* emlxs_dfc_table */


emlxs_table_t emlxs_dfc_event_table[] = {
	{FC_REG_LINK_EVENT,		"LINK_EVENT"},
	{FC_REG_RSCN_EVENT,		"RSCN_EVENT"},
	{FC_REG_CT_EVENT,		"CT_EVENT"},
	{FC_REG_DUMP_EVENT,		"DUMP_EVENT"},
	{FC_REG_TEMP_EVENT,		"TEMP_EVENT"},
	{FC_REG_VPORTRSCN_EVENT,	"VPORTRSCN_EVENT"},
	{FC_REG_FCOE_EVENT,		"FCOE_EVENT"},

};	/* emlxs_dfc_event_table */


#ifdef SAN_DIAG_SUPPORT
kmutex_t		sd_bucket_mutex;
sd_bucket_info_t	sd_bucket;
#endif	/* SAN_DIAG_SUPPORT */

extern char    *
emlxs_dfc_xlate(uint16_t cmd)
{
	static char	buffer[32];
	uint32_t	i;
	uint32_t	count;

	count = sizeof (emlxs_dfc_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (cmd == emlxs_dfc_table[i].code) {
			return (emlxs_dfc_table[i].string);
		}
	}

	(void) sprintf(buffer, "Cmd=0x%x", cmd);
	return (buffer);

} /* emlxs_dfc_xlate() */


extern char    *
emlxs_dfc_event_xlate(uint32_t event)
{
	static char	buffer[32];
	uint32_t	i;
	uint32_t	count;

	count = sizeof (emlxs_dfc_event_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (event == emlxs_dfc_event_table[i].code) {
			return (emlxs_dfc_event_table[i].string);
		}
	}

	(void) sprintf(buffer, "Event=0x%x", event);
	return (buffer);

} /* emlxs_dfc_event_xlate() */



extern int32_t
emlxs_dfc_manage(emlxs_hba_t *hba, void *arg, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	int		rval = 0;
	dfc_t		*dfc;

	dfc = (dfc_t *)kmem_zalloc(sizeof (dfc_t), KM_SLEEP);

#ifdef	_MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32:
		{
			dfc32_t		dfc32;

			if (ddi_copyin((void *)arg, (void *)&dfc32,
			    sizeof (dfc32_t), mode)) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
				    "%s: ddi_copyin failed.",
				    emlxs_dfc_xlate(dfc->cmd));

				rval = DFC_COPYIN_ERROR;
				break;
			}

			dfc->cmd = dfc32.cmd;
			dfc->flag = dfc32.flag;
			dfc->buf1 = (void *)((uintptr_t)dfc32.buf1);
			dfc->buf1_size = dfc32.buf1_size;
			dfc->data1 = dfc32.data1;
			dfc->buf2 = (void *)((uintptr_t)dfc32.buf2);
			dfc->buf2_size = dfc32.buf2_size;
			dfc->data2 = dfc32.data2;
			dfc->buf3 = (void *)((uintptr_t)dfc32.buf3);
			dfc->buf3_size = dfc32.buf3_size;
			dfc->data3 = dfc32.data3;
			dfc->buf4 = (void *)((uintptr_t)dfc32.buf4);
			dfc->buf4_size = dfc32.buf4_size;
			dfc->data4 = dfc32.data4;

			break;
		}

	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)arg, (void *)dfc, sizeof (dfc_t),
		    mode)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: ddi_copyin failed.",
			    emlxs_dfc_xlate(dfc->cmd));

			rval = DFC_COPYIN_ERROR;
		}
		break;
	}
#else	/* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, (void *)dfc, sizeof (dfc_t), mode)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYIN_ERROR;
	}
#endif	/* _MULTI_DATAMODEL */


	switch (dfc->cmd) {
	case EMLXS_GET_HBAINFO:
		{

			rval = emlxs_dfc_get_hbainfo(hba, dfc, mode);

			break;
		}

	case EMLXS_GET_HBASTATS:
		{

			rval = emlxs_dfc_get_hbastats(hba, dfc, mode);

			break;
		}

	case EMLXS_GET_DRVSTATS:
		{

			rval = emlxs_dfc_get_drvstats(hba, dfc, mode);

			break;
		}

	case EMLXS_GET_NODEINFO:
		{

			rval = emlxs_dfc_get_nodeinfo(hba, dfc, mode);

			break;
		}

	case EMLXS_SET_DIAG:
		{
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
		    "%s requested.", emlxs_dfc_xlate(dfc->cmd));

			rval = emlxs_dfc_set_diag(hba, dfc, mode);

			break;
		}

	case EMLXS_SEND_MBOX:
		{
			rval = emlxs_dfc_send_mbox(hba, dfc, mode);

			break;
		}

	case EMLXS_READ_PCI:
		{
			rval = emlxs_dfc_read_pci(hba, dfc, mode);

			break;
		}

	case EMLXS_WRITE_PCI:
		{
			rval = emlxs_dfc_write_pci(hba, dfc, mode);

			break;
		}

	case EMLXS_GET_CFG:
		{
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
		    "%s requested.", emlxs_dfc_xlate(dfc->cmd));

			rval = emlxs_dfc_get_cfg(hba, dfc, mode);

			break;
		}

	case EMLXS_SET_CFG:
		{
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
		    "%s requested.", emlxs_dfc_xlate(dfc->cmd));

			rval = emlxs_dfc_set_cfg(hba, dfc, mode);

			break;
		}

	case EMLXS_SEND_CT:
		{
			rval = emlxs_dfc_send_ct(hba, dfc, mode);

			break;
		}

	case EMLXS_SEND_CT_RSP:
		{
			rval = emlxs_dfc_send_ct_rsp(hba, dfc, mode);

			break;
		}

#ifdef MENLO_SUPPORT
	case EMLXS_SEND_MENLO:
		{
			rval = emlxs_dfc_send_menlo(hba, dfc, mode);

			break;
		}
#endif /* MENLO_SUPPORT */

	case EMLXS_WRITE_FLASH:
		{
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
		    "%s requested.", emlxs_dfc_xlate(dfc->cmd));

			rval = emlxs_dfc_write_flash(hba, dfc, mode);

			break;
		}

	case EMLXS_READ_FLASH:
		{
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
		    "%s requested.", emlxs_dfc_xlate(dfc->cmd));

			rval = emlxs_dfc_read_flash(hba, dfc, mode);

			break;
		}

	case EMLXS_SEND_ELS:
		{
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
		    "%s requested.", emlxs_dfc_xlate(dfc->cmd));

			rval = emlxs_dfc_send_els(hba, dfc, mode);

			break;
		}

	case EMLXS_LOOPBACK_TEST:
		{
			rval = emlxs_dfc_loopback_test(hba, dfc, mode);

			break;
		}

	case EMLXS_GET_DUMPREGION:
		{

			rval = emlxs_dfc_get_dump_region(hba, dfc, mode);

			break;
		}

	case EMLXS_LOOPBACK_MODE:
		{
			rval = emlxs_dfc_loopback_mode(hba, dfc, mode);

			break;
		}

	case EMLXS_GET_IOINFO:
		{
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
		    "%s requested.", emlxs_dfc_xlate(dfc->cmd));

			rval = emlxs_dfc_get_ioinfo(hba, dfc, mode);

			break;
		}

	case EMLXS_GET_LINKINFO:
		{
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
		    "%s requested.", emlxs_dfc_xlate(dfc->cmd));

			rval = emlxs_dfc_get_linkinfo(hba, dfc, mode);

			break;
		}

#ifdef SFCT_SUPPORT
	case EMLXS_GET_FCTSTAT:
		{
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
		    "%s requested.", emlxs_dfc_xlate(dfc->cmd));

			rval = emlxs_dfc_get_fctstat(hba, dfc, mode);

			break;
		}
#endif /* SFCT_SUPPORT */

	case EMLXS_READ_MEM:
		{
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
		    "%s requested.", emlxs_dfc_xlate(dfc->cmd));

			rval = emlxs_dfc_read_mem(hba, dfc, mode);

			break;
		}

	case EMLXS_WRITE_MEM:
		{
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
		    "%s requested.", emlxs_dfc_xlate(dfc->cmd));

			rval = emlxs_dfc_write_mem(hba, dfc, mode);

			break;
		}

	case EMLXS_WRITE_CTLREG:
		{
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
		    "%s requested.", emlxs_dfc_xlate(dfc->cmd));

			rval = emlxs_dfc_write_ctlreg(hba, dfc, mode);

			break;
		}

	case EMLXS_READ_CTLREG:
		{
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
		    "%s requested.", emlxs_dfc_xlate(dfc->cmd));

			rval = emlxs_dfc_read_ctlreg(hba, dfc, mode);

			break;
		}


	case EMLXS_GET_EVENTINFO:
		{
			rval = emlxs_dfc_get_eventinfo(hba, dfc, mode);

			break;
		}

	case EMLXS_GET_EVENT:
		{
			rval = emlxs_dfc_get_event(hba, dfc, mode);

			break;
		}

	case EMLXS_SET_EVENT:
		{
			rval = emlxs_dfc_set_event(hba, dfc, mode);

			break;
		}

	case EMLXS_GET_REV:
		{
			rval = emlxs_dfc_get_rev(hba, dfc, mode);

			break;
		}

	case EMLXS_SEND_SCSI:
		{
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
		    "%s requested.", emlxs_dfc_xlate(dfc->cmd));
			rval = emlxs_dfc_send_scsi_fcp(hba, dfc, mode);
			break;
		}

	case EMLXS_CREATE_VPORT:
		{

			rval = emlxs_dfc_create_vport(hba, dfc, mode);

			break;
		}

	case EMLXS_DESTROY_VPORT:
		{

			rval = emlxs_dfc_destroy_vport(hba, dfc, mode);

			break;
		}

	case EMLXS_GET_VPORTINFO:
		{

			rval = emlxs_dfc_get_vportinfo(hba, dfc, mode);

			break;
		}

	case EMLXS_NPIV_RESOURCE:
		{
			rval = emlxs_dfc_npiv_resource(hba, dfc, mode);

			break;
		}

	case EMLXS_NPIV_TEST:
		{
			rval = emlxs_dfc_npiv_test(hba, dfc, mode);

			break;
		}

#ifdef DHCHAP_SUPPORT
	case EMLXS_INIT_AUTH:
		{
			rval = emlxs_dfc_init_auth(hba, dfc, mode);

			break;
		}

	case EMLXS_GET_AUTH_CFG:
		{
			rval = emlxs_dfc_get_auth_cfg(hba, dfc, mode);

			break;
		}

	case EMLXS_SET_AUTH_CFG:
		{
			rval = emlxs_dfc_set_auth_cfg(hba, dfc, mode);

			break;
		}

	case EMLXS_GET_AUTH_PASSWORD:
		{
			rval = emlxs_dfc_get_auth_pwd(hba, dfc, mode);

			break;
		}

	case EMLXS_SET_AUTH_PASSWORD:
		{
			rval = emlxs_dfc_set_auth_pwd(hba, dfc, mode);

			break;
		}

	case EMLXS_GET_AUTH_STATUS:
		{
			rval = emlxs_dfc_get_auth_status(hba, dfc, mode);

			break;
		}

	case EMLXS_GET_AUTH_CFG_TABLE:
		{
			rval = emlxs_dfc_get_auth_cfg_table(hba, dfc, mode);
			break;
		}

	case EMLXS_GET_AUTH_KEY_TABLE:
		{
			rval = emlxs_dfc_get_auth_key_table(hba, dfc, mode);
			break;
		}

#endif	/* DHCHAP_SUPPORT */

#ifdef FCIO_SUPPORT
	case EMLXS_FCIO_CMD:
		rval = emlxs_fcio_manage(hba, dfc, mode);
		break;
#endif /* FCIO_SUPPORT */

#ifdef SAN_DIAG_SUPPORT
	case EMLXS_SD_SET_BUCKET:
		rval = emlxs_dfc_sd_set_bucket(dfc, mode);
		break;

	case EMLXS_SD_DESTROY_BUCKET:
		rval = emlxs_dfc_sd_destroy_bucket(dfc);
		break;

	case EMLXS_SD_GET_BUCKET:
		rval = emlxs_dfc_sd_get_bucket(dfc, mode);
		break;

	case EMLXS_SD_START_DATA_COLLECTION:
		rval = emlxs_dfc_sd_start_collection(hba, dfc, mode);
		break;

	case EMLXS_SD_STOP_DATA_COLLECTION:
		rval = emlxs_dfc_sd_stop_collection(hba, dfc, mode);
		break;

	case EMLXS_SD_RESET_DATA_COLLECTION:
		rval = emlxs_dfc_sd_reset_collection(hba, dfc, mode);
		break;

	case EMLXS_SD_GET_DATA:
		rval = emlxs_dfc_sd_get_data(hba, dfc, mode);
		break;

	case EMLXS_SD_SET_EVENT:
		rval = emlxs_dfc_sd_set_event(hba, dfc, mode);
		break;

	case EMLXS_SD_GET_EVENT:
		rval = emlxs_dfc_sd_get_event(hba, dfc, mode);
		break;
#endif	/* SAN_DIAG_SUPPORT */

	case EMLXS_GET_PERSIST_LINKDOWN:
		rval = emlxs_dfc_get_persist_linkdown(hba, dfc, mode);
		break;

	case EMLXS_SET_PERSIST_LINKDOWN:
		rval = emlxs_dfc_set_persist_linkdown(hba, dfc, mode);
		break;

	case EMLXS_GET_FCOE_FCFLIST:
		rval = emlxs_dfc_get_fcflist(hba, dfc, mode);
		break;

	case EMLXS_SEND_MBOX4:
		rval = emlxs_dfc_send_mbox4(hba, dfc, mode);
		break;

	case EMLXS_RD_BE_FCF:
		rval = emlxs_dfc_rd_be_fcf(hba, dfc, mode);
		break;

	case EMLXS_SET_BE_DCBX:
		rval = emlxs_dfc_set_be_dcbx(hba, dfc, mode);
		break;

	case EMLXS_GET_BE_DCBX:
		rval = emlxs_dfc_get_be_dcbx(hba, dfc, mode);
		break;

	case EMLXS_GET_QOS:
		rval = emlxs_dfc_get_qos(hba, dfc, mode);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
		    "Unknown command received. (0x%x)", dfc->cmd);
		rval = DFC_ARG_INVALID;

	}	/* switch() */

	kmem_free(dfc, sizeof (dfc_t));
	return (rval);

} /* emlxs_dfc_manage() */


#ifdef FCIO_SUPPORT

emlxs_table_t emlxs_fcio_table[] = {
	{FCIO_GET_NUM_DEVS, "GET_NUM_DEVS"},
	{FCIO_GET_DEV_LIST, "GET_DEV_LIST"},
	{FCIO_GET_SYM_PNAME, "GET_SYM_PNAME"},
	{FCIO_GET_SYM_NNAME, "GET_SYM_NNAME"},
	{FCIO_SET_SYM_PNAME, "SET_SYM_PNAME"},
	{FCIO_SET_SYM_NNAME, "SET_SYM_NNAME"},
	{FCIO_GET_LOGI_PARAMS, "GET_LOGI_PARAMS"},
	{FCIO_DEV_LOGIN, "DEV_LOGIN"},
	{FCIO_DEV_LOGOUT, "DEV_LOGOUT"},
	{FCIO_GET_STATE, "GET_STATE"},
	{FCIO_DEV_REMOVE, "DEV_REMOVE"},
	{FCIO_GET_FCODE_REV, "GET_FCODE_REV"},
	{FCIO_GET_FW_REV, "GET_FW_REV"},
	{FCIO_GET_DUMP_SIZE, "GET_DUMP_SIZE"},
	{FCIO_FORCE_DUMP, "FORCE_DUMP"},
	{FCIO_GET_DUMP, "GET_DUMP"},
	{FCIO_GET_TOPOLOGY, "GET_TOPOLOGY"},
	{FCIO_RESET_LINK, "RESET_LINK"},
	{FCIO_RESET_HARD, "RESET_HARD"},
	{FCIO_RESET_HARD_CORE, "RESET_HARD_CORE"},
	{FCIO_DIAG, "DIAG"},
	{FCIO_NS, "NS"},
	{FCIO_DOWNLOAD_FW, "DOWNLOAD_FW"},
	{FCIO_GET_HOST_PARAMS, "GET_HOST_PARAMS"},
	{FCIO_LINK_STATUS, "LINK_STATUS"},
	{FCIO_DOWNLOAD_FCODE, "DOWNLOAD_FCODE"},
	{FCIO_GET_NODE_ID, "GET_NODE_ID"},
	{FCIO_SET_NODE_ID, "SET_NODE_ID"},
	{FCIO_SEND_NODE_ID, "SEND_NODE_ID"},
	/* {FCIO_GET_P2P_INFO, "GET_P2P_INFO"}, */
	{FCIO_GET_ADAPTER_ATTRIBUTES, "GET_ADAPTER_ATTRIBUTES"},
	{FCIO_GET_OTHER_ADAPTER_PORTS, "GET_OTHER_ADAPTER_PORTS"},
	{FCIO_GET_ADAPTER_PORT_ATTRIBUTES, "GET_ADAPTER_PORT_ATTRIBUTES"},
	{FCIO_GET_DISCOVERED_PORT_ATTRIBUTES, "GET_DISCOVERED_PORT_ATTRIBUTES"},
	{FCIO_GET_PORT_ATTRIBUTES, "GET_PORT_ATTRIBUTES"},
	{FCIO_GET_ADAPTER_PORT_STATS, "GET_ADAPTER_PORT_STATS"},
};	/* emlxs_fcio_table */


extern char    *
emlxs_fcio_xlate(uint16_t cmd)
{
	static char	buffer[32];
	uint32_t	i;
	uint32_t	count;

	count = sizeof (emlxs_fcio_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (cmd == emlxs_fcio_table[i].code) {
			return (emlxs_fcio_table[i].string);
		}
	}

	(void) sprintf(buffer, "Cmd=0x%x", cmd);
	return (buffer);

} /* emlxs_fcio_xlate() */


static int32_t
emlxs_fcio_manage(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t			*port = &PPORT;
	emlxs_config_t			*cfg  = &CFG;
	int				rval = 0;
	fcio_t				local_fcio;
	fcio_t				*fcio = &local_fcio;
	emlxs_vpd_t			*vpd = &VPD;
	fc_hba_port_attributes_t	*port_attrs;
	emlxs_node_t			*ndlp;
	uint8_t				*wwpn;
	uint32_t			use32 = 0;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s: %s: requested.",
	    emlxs_dfc_xlate(dfc->cmd), emlxs_fcio_xlate(dfc->data1));

	if (!dfc->buf4 || !dfc->buf4_size) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg, "%s: %s: Null buffer4 found.",
		    emlxs_dfc_xlate(dfc->cmd), emlxs_fcio_xlate(dfc->data1));

		return (EFAULT);
	}

	if (dfc->buf4_size < sizeof (uint32_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg,
		    "%s: %s: Buffer4 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), emlxs_fcio_xlate(dfc->data1),
		    dfc->buf4_size);

		return (EFAULT);
	}

	/* Map DFC to FCIO */
	bzero(fcio, sizeof (fcio_t));
	fcio->fcio_flags	= dfc->flag;
	fcio->fcio_cmd		= dfc->data1;
	fcio->fcio_cmd_flags	= dfc->data2;
	fcio->fcio_xfer		= dfc->data3;
	fcio->fcio_errno	= 0; /* dfc->buf4 on return */

	if (dfc->buf1_size && dfc->buf1) {
		fcio->fcio_ilen = dfc->buf1_size;
		fcio->fcio_ibuf = kmem_zalloc(dfc->buf1_size, KM_SLEEP);

		if (ddi_copyin(dfc->buf1, fcio->fcio_ibuf, fcio->fcio_ilen,
		    mode)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: %s: ddi_copyin failed. (size=%d)",
			    emlxs_dfc_xlate(dfc->cmd),
			    emlxs_fcio_xlate(dfc->data1), fcio->fcio_ilen);

			rval = EFAULT;
			goto done;
		}
	}

	if (dfc->buf2_size && dfc->buf2) {
		fcio->fcio_olen = dfc->buf2_size;
		fcio->fcio_obuf = kmem_zalloc(dfc->buf2_size, KM_SLEEP);

		if (ddi_copyin(dfc->buf2, fcio->fcio_obuf, fcio->fcio_olen,
		    mode)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: %s: ddi_copyin failed. (size=%d)",
			    emlxs_dfc_xlate(dfc->cmd),
			    emlxs_fcio_xlate(dfc->data1), fcio->fcio_olen);

			rval = EFAULT;
			goto done;
		}
	}

	if (dfc->buf3_size && dfc->buf3) {
		fcio->fcio_alen = dfc->buf3_size;
		fcio->fcio_abuf = kmem_zalloc(dfc->buf3_size, KM_SLEEP);

		if (ddi_copyin(dfc->buf3, fcio->fcio_abuf, fcio->fcio_alen,
		    mode)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: %s: ddi_copyin failed. (size=%d)",
			    emlxs_dfc_xlate(dfc->cmd),
			    emlxs_fcio_xlate(dfc->data1), fcio->fcio_alen);

			rval = EFAULT;
			goto done;
		}
	}

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		use32 = 1;
	}
#endif	/* _MULTI_DATAMODEL */

	/* FCIO command */
	switch (fcio->fcio_cmd) {
	case FCIO_DIAG:
	{
		fc_fca_pm_t pm;

		bzero((caddr_t)&pm, sizeof (fc_fca_pm_t));

		pm.pm_cmd_len   = fcio->fcio_ilen;
		pm.pm_cmd_buf   = fcio->fcio_ibuf;
		pm.pm_data_len  = fcio->fcio_alen;
		pm.pm_data_buf  = fcio->fcio_abuf;
		pm.pm_stat_len  = fcio->fcio_olen;
		pm.pm_stat_buf  = fcio->fcio_obuf;
		pm.pm_cmd_code  = FC_PORT_DIAG;
		pm.pm_cmd_flags = fcio->fcio_cmd_flags;

		rval = emlxs_fca_port_manage(port, &pm);

		if (rval != FC_SUCCESS) {
			fcio->fcio_errno = rval;

			if (rval == FC_INVALID_REQUEST) {
				rval = ENOTTY;
			} else {
				rval = EIO;
			}
		}
		if (fcio->fcio_olen > pm.pm_stat_len) {
			fcio->fcio_olen = pm.pm_stat_len;
		}

		break;
	}

	case FCIO_GET_HOST_PARAMS:
	{
		if (use32) {
			fc_port_dev32_t *port_dev;
			uint32_t i;

			if (fcio->fcio_xfer != FCIO_XFER_READ ||
			    fcio->fcio_olen != sizeof (fc_port_dev32_t)) {
				rval = EINVAL;
				break;
			}

			port_dev = (fc_port_dev32_t *)fcio->fcio_obuf;
			port_dev->dev_did.port_id = port->did;
			port_dev->dev_hard_addr.hard_addr =
			    cfg[CFG_ASSIGN_ALPA].current;
			port_dev->dev_state = port->ulp_statec;
			bcopy((caddr_t)&port->wwpn,
			    (caddr_t)&port_dev->dev_pwwn, 8);
			bcopy((caddr_t)&port->wwnn,
			    (caddr_t)&port_dev->dev_nwwn, 8);

			if (hba->topology == TOPOLOGY_LOOP) {
				for (i = 0; i < port->alpa_map[0]; i++) {
			if (port->alpa_map[i + 1] == port->did) {
				port_dev->dev_did.priv_lilp_posit =
				    (uint8_t)(i & 0xff);
				break;
			}
				}
			}

			port_dev->dev_type[0] = LE_SWAP32(0x00000120);
			port_dev->dev_type[1] = LE_SWAP32(0x00000001);

		} else {

			fc_port_dev_t *port_dev;
			uint32_t i;

			if (fcio->fcio_xfer != FCIO_XFER_READ ||
			    fcio->fcio_olen != sizeof (fc_port_dev_t)) {
				rval = EINVAL;
				break;
			}

			port_dev = (fc_port_dev_t *)fcio->fcio_obuf;
			port_dev->dev_did.port_id = port->did;
			port_dev->dev_hard_addr.hard_addr =
			    cfg[CFG_ASSIGN_ALPA].current;
			port_dev->dev_state = port->ulp_statec;
			bcopy((caddr_t)&port->wwpn,
			    (caddr_t)&port_dev->dev_pwwn, 8);
			bcopy((caddr_t)&port->wwnn,
			    (caddr_t)&port_dev->dev_nwwn, 8);

			if (hba->topology == TOPOLOGY_LOOP) {
				for (i = 0; i < port->alpa_map[0]; i++) {
			if (port->alpa_map[i + 1] == port->did) {
				port_dev->dev_did.priv_lilp_posit =
				    (uint8_t)(i & 0xff);
				break;
			}
				}
			}

			port_dev->dev_type[0] = LE_SWAP32(0x00000120);
			port_dev->dev_type[1] = LE_SWAP32(0x00000001);
		}

		break;
	}

	case FCIO_RESET_LINK:
	{
		uint8_t null_wwn[8];

		if (fcio->fcio_xfer != FCIO_XFER_WRITE ||
		    fcio->fcio_ilen != 8) {
			rval = EINVAL;
			break;
		}

		bzero(null_wwn, 8);

		if (bcmp((uint8_t *)fcio->fcio_ibuf, null_wwn, 8) == 0) {
			rval = emlxs_fca_reset(port, FC_FCA_LINK_RESET);

			if (rval != FC_SUCCESS) {
				fcio->fcio_errno = rval;
				rval = EIO;
			}
		} else {
			rval = ENOTSUP;
		}
		break;
	}

	case FCIO_RESET_HARD:
	case FCIO_RESET_HARD_CORE:
	{
		rval = emlxs_fca_reset(port, FC_FCA_RESET);

		if (rval != FC_SUCCESS) {
			fcio->fcio_errno = rval;
			rval = EIO;
		}
		break;
	}

	case FCIO_DOWNLOAD_FW:
	{
		fc_fca_pm_t	pm;

		if (fcio->fcio_xfer != FCIO_XFER_WRITE ||
		    fcio->fcio_ilen == 0) {
			rval = EINVAL;
			break;
		}

		bzero((caddr_t)&pm, sizeof (pm));

		pm.pm_cmd_flags = FC_FCA_PM_WRITE;
		pm.pm_cmd_code  = FC_PORT_DOWNLOAD_FW;
		pm.pm_data_len  = fcio->fcio_ilen;
		pm.pm_data_buf  = fcio->fcio_ibuf;

		rval = emlxs_fca_port_manage(port, &pm);

		if (rval != FC_SUCCESS) {
			fcio->fcio_errno = rval;
			rval = EIO;
		}
		break;
	}

	case FCIO_GET_FW_REV:
	{
		fc_fca_pm_t	pm;

		if (fcio->fcio_xfer != FCIO_XFER_READ ||
		    fcio->fcio_olen < FC_FW_REV_SIZE) {
			rval = EINVAL;
			break;
		}

		bzero((caddr_t)&pm, sizeof (pm));

		pm.pm_cmd_flags = FC_FCA_PM_READ;
		pm.pm_cmd_code  = FC_PORT_GET_FW_REV;
		pm.pm_data_len  = fcio->fcio_olen;
		pm.pm_data_buf  = fcio->fcio_obuf;

		rval = emlxs_fca_port_manage(port, &pm);

		if (rval != FC_SUCCESS) {
			fcio->fcio_errno = rval;
			rval = EIO;
		}
		break;
	}

	case FCIO_GET_FCODE_REV:
	{
		fc_fca_pm_t	pm;

		if (fcio->fcio_xfer != FCIO_XFER_READ ||
		    fcio->fcio_olen < FC_FCODE_REV_SIZE) {
			rval = EINVAL;
			break;
		}

		bzero((caddr_t)&pm, sizeof (pm));

		pm.pm_cmd_flags = FC_FCA_PM_READ;
		pm.pm_cmd_code  = FC_PORT_GET_FCODE_REV;
		pm.pm_data_len  = fcio->fcio_olen;
		pm.pm_data_buf  = fcio->fcio_obuf;

		rval = emlxs_fca_port_manage(port, &pm);

		if (rval != FC_SUCCESS) {
			fcio->fcio_errno = rval;
			rval = EIO;
		}
		break;
	}

	case FCIO_DOWNLOAD_FCODE:
	{
		fc_fca_pm_t	pm;

		if (fcio->fcio_xfer != FCIO_XFER_WRITE ||
		    fcio->fcio_ilen == 0) {
			rval = EINVAL;
			break;
		}

		bzero((caddr_t)&pm, sizeof (pm));

		pm.pm_cmd_flags = FC_FCA_PM_WRITE;
		pm.pm_cmd_code  = FC_PORT_DOWNLOAD_FCODE;
		pm.pm_data_len  = fcio->fcio_ilen;
		pm.pm_data_buf  = fcio->fcio_ibuf;

		rval = emlxs_fca_port_manage(port, &pm);

		if (rval != FC_SUCCESS) {
			fcio->fcio_errno = rval;
			rval = EIO;
		}
		break;
	}

	case FCIO_GET_ADAPTER_ATTRIBUTES:
	{
		if (use32) {
			fc_hba_adapter_attributes32_t	*hba_attrs;

			if (fcio->fcio_xfer != FCIO_XFER_READ ||
			    fcio->fcio_olen <
			    sizeof (fc_hba_adapter_attributes32_t)) {
				rval = EINVAL;
				break;
			}

			hba_attrs =
			    (fc_hba_adapter_attributes32_t *)fcio->fcio_obuf;

			hba_attrs->version = FC_HBA_ADAPTER_ATTRIBUTES_VERSION;
			(void) strncpy(hba_attrs->Manufacturer, "Emulex",
			    sizeof (hba_attrs->Manufacturer));
			(void) strncpy(hba_attrs->SerialNumber, vpd->serial_num,
			    sizeof (hba_attrs->SerialNumber));
			(void) strncpy(hba_attrs->Model, hba->model_info.model,
			    sizeof (hba_attrs->Model));
			(void) strncpy(hba_attrs->ModelDescription,
			    hba->model_info.model_desc,
			    sizeof (hba_attrs->ModelDescription));
			bcopy((caddr_t)&port->wwnn,
			    (caddr_t)&hba_attrs->NodeWWN, 8);
			(void) strncpy((caddr_t)hba_attrs->NodeSymbolicName,
			    (caddr_t)port->snn,
			    sizeof (hba_attrs->NodeSymbolicName));
			(void) sprintf(hba_attrs->HardwareVersion, "%x",
			    vpd->biuRev);
			(void) sprintf(hba_attrs->DriverVersion, "%s (%s)",
			    emlxs_version, emlxs_revision);
			(void) strncpy(hba_attrs->OptionROMVersion,
			    vpd->fcode_version,
			    sizeof (hba_attrs->OptionROMVersion));
			(void) sprintf(hba_attrs->FirmwareVersion, "%s (%s)",
			    vpd->fw_version, vpd->fw_label);
			(void) strncpy(hba_attrs->DriverName, DRIVER_NAME,
			    sizeof (hba_attrs->DriverName));
			hba_attrs->VendorSpecificID =
			    ((hba->model_info.device_id << 16) |
			    PCI_VENDOR_ID_EMULEX);
			hba_attrs->NumberOfPorts = hba->num_of_ports;
		} else {
			fc_hba_adapter_attributes_t	*hba_attrs;

			if (fcio->fcio_xfer != FCIO_XFER_READ ||
			    fcio->fcio_olen <
			    sizeof (fc_hba_adapter_attributes_t)) {
				rval = EINVAL;
				break;
			}

			hba_attrs =
			    (fc_hba_adapter_attributes_t *)fcio->fcio_obuf;

			hba_attrs->version = FC_HBA_ADAPTER_ATTRIBUTES_VERSION;
			(void) strncpy(hba_attrs->Manufacturer, "Emulex",
			    sizeof (hba_attrs->Manufacturer));
			(void) strncpy(hba_attrs->SerialNumber, vpd->serial_num,
			    sizeof (hba_attrs->SerialNumber));
			(void) strncpy(hba_attrs->Model, hba->model_info.model,
			    sizeof (hba_attrs->Model));
			(void) strncpy(hba_attrs->ModelDescription,
			    hba->model_info.model_desc,
			    sizeof (hba_attrs->ModelDescription));
			bcopy((caddr_t)&port->wwnn,
			    (caddr_t)&hba_attrs->NodeWWN, 8);
			(void) strncpy((caddr_t)hba_attrs->NodeSymbolicName,
			    (caddr_t)port->snn,
			    sizeof (hba_attrs->NodeSymbolicName));
			(void) sprintf(hba_attrs->HardwareVersion, "%x",
			    vpd->biuRev);
			(void) sprintf(hba_attrs->DriverVersion, "%s (%s)",
			    emlxs_version, emlxs_revision);
			(void) strncpy(hba_attrs->OptionROMVersion,
			    vpd->fcode_version,
			    sizeof (hba_attrs->OptionROMVersion));
			(void) sprintf(hba_attrs->FirmwareVersion, "%s (%s)",
			    vpd->fw_version, vpd->fw_label);
			(void) strncpy(hba_attrs->DriverName, DRIVER_NAME,
			    sizeof (hba_attrs->DriverName));
			hba_attrs->VendorSpecificID =
			    ((hba->model_info.device_id << 16) |
			    PCI_VENDOR_ID_EMULEX);
			hba_attrs->NumberOfPorts = hba->num_of_ports;
		}
		break;
	}

	case FCIO_GET_ADAPTER_PORT_ATTRIBUTES:
	{
		if (use32) {
			fc_hba_port_attributes32_t  *port_attrs;
			uint32_t value1;
			uint32_t value2;

			if (fcio->fcio_xfer != FCIO_XFER_READ ||
			    fcio->fcio_olen <
			    sizeof (fc_hba_port_attributes32_t)) {
				rval = EINVAL;
				break;
			}

			port_attrs =
			    (fc_hba_port_attributes32_t *)fcio->fcio_obuf;

			port_attrs->version    = FC_HBA_PORT_ATTRIBUTES_VERSION;
			port_attrs->lastChange = 0;
			port_attrs->fp_minor   = 0;
			bcopy((caddr_t)&port->wwnn,
			    (caddr_t)&port_attrs->NodeWWN, 8);
			bcopy((caddr_t)&port->wwpn,
			    (caddr_t)&port_attrs->PortWWN, 8);

			if (hba->state <= FC_LINK_DOWN) {
				/* port_attrs->PortFcId   */
				/* port_attrs->PortType   */
				/* port_attrs->PortSpeed  */
				/* port_attrs->FabricName */
				port_attrs->PortState =
				    FC_HBA_PORTSTATE_OFFLINE;
			} else {
				port_attrs->PortFcId  = port->did;
				port_attrs->PortState = FC_HBA_PORTSTATE_ONLINE;

				if (hba->topology == TOPOLOGY_LOOP) {
					port_attrs->PortType =
					    FC_HBA_PORTTYPE_LPORT;
				} else {
					port_attrs->PortType =
					    FC_HBA_PORTTYPE_NPORT;
				}

				ndlp = emlxs_node_find_did(port, FABRIC_DID);

				if (ndlp) {
					bcopy(&ndlp->nlp_portname,
					    (caddr_t)&port_attrs->FabricName,
					    sizeof (port_attrs->FabricName));
				}

				switch (hba->linkspeed) {
				case 0:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_1GBIT;
					break;
				case LA_1GHZ_LINK:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_1GBIT;
					break;
				case LA_2GHZ_LINK:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_2GBIT;
					break;
				case LA_4GHZ_LINK:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_4GBIT;
					break;
				case LA_8GHZ_LINK:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_8GBIT;
					break;
				case LA_10GHZ_LINK:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_10GBIT;
					break;
				default:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_UNKNOWN;
				}
			}

			port_attrs->PortSupportedClassofService =
			    LE_SWAP32(FC_NS_CLASS3);
			(void) strncpy((caddr_t)port_attrs->PortSymbolicName,
			    (caddr_t)port->spn,
			    sizeof (port_attrs->PortSymbolicName));

			/* Set the hba speed limit */
			if (vpd->link_speed & LMT_10GB_CAPABLE) {
				port_attrs->PortSupportedSpeed |=
				    FC_HBA_PORTSPEED_10GBIT;
			}
			if (vpd->link_speed & LMT_8GB_CAPABLE) {
				port_attrs->PortSupportedSpeed |=
				    FC_HBA_PORTSPEED_8GBIT;
			}
			if (vpd->link_speed & LMT_4GB_CAPABLE) {
				port_attrs->PortSupportedSpeed |=
				    FC_HBA_PORTSPEED_4GBIT;
			}
			if (vpd->link_speed & LMT_2GB_CAPABLE) {
				port_attrs->PortSupportedSpeed |=
				    FC_HBA_PORTSPEED_2GBIT;
			}
			if (vpd->link_speed & LMT_1GB_CAPABLE) {
				port_attrs->PortSupportedSpeed |=
				    FC_HBA_PORTSPEED_1GBIT;
			}

			value1 = 0x00000120;
			value2 = 0x00000001;

			bcopy((caddr_t)&value1,
			    (caddr_t)&port_attrs->PortSupportedFc4Types[0], 4);
			bcopy((caddr_t)&value2,
			    (caddr_t)&port_attrs->PortSupportedFc4Types[4], 4);

			bcopy((caddr_t)&value1,
			    (caddr_t)&port_attrs->PortActiveFc4Types[0], 4);
			bcopy((caddr_t)&value2,
			    (caddr_t)&port_attrs->PortActiveFc4Types[4], 4);

			port_attrs->PortMaxFrameSize = FF_FRAME_SIZE;
			port_attrs->NumberofDiscoveredPorts =
			    emlxs_nport_count(port);

		} else {

			fc_hba_port_attributes_t  *port_attrs;
			uint32_t value1;
			uint32_t value2;

			if (fcio->fcio_xfer != FCIO_XFER_READ ||
			    fcio->fcio_olen <
			    sizeof (fc_hba_port_attributes_t)) {
				rval = EINVAL;
				break;
			}

			port_attrs =
			    (fc_hba_port_attributes_t *)fcio->fcio_obuf;

			port_attrs->version    = FC_HBA_PORT_ATTRIBUTES_VERSION;
			port_attrs->lastChange = 0;
			port_attrs->fp_minor   = 0;
			bcopy((caddr_t)&port->wwnn,
			    (caddr_t)&port_attrs->NodeWWN, 8);
			bcopy((caddr_t)&port->wwpn,
			    (caddr_t)&port_attrs->PortWWN, 8);

			if (hba->state <= FC_LINK_DOWN) {
				/* port_attrs->PortFcId   */
				/* port_attrs->PortType   */
				/* port_attrs->PortSpeed  */
				/* port_attrs->FabricName */
				port_attrs->PortState =
				    FC_HBA_PORTSTATE_OFFLINE;
			} else {
				port_attrs->PortFcId  = port->did;
				port_attrs->PortState = FC_HBA_PORTSTATE_ONLINE;

				if (hba->topology == TOPOLOGY_LOOP) {
					port_attrs->PortType =
					    FC_HBA_PORTTYPE_LPORT;
				} else {
					port_attrs->PortType =
					    FC_HBA_PORTTYPE_NPORT;
				}

				ndlp = emlxs_node_find_did(port, FABRIC_DID);

				if (ndlp) {
					bcopy(&ndlp->nlp_portname,
					    (caddr_t)&port_attrs->FabricName,
					    sizeof (port_attrs->FabricName));
				}

				switch (hba->linkspeed) {
				case 0:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_1GBIT;
					break;
				case LA_1GHZ_LINK:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_1GBIT;
					break;
				case LA_2GHZ_LINK:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_2GBIT;
					break;
				case LA_4GHZ_LINK:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_4GBIT;
					break;
				case LA_8GHZ_LINK:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_8GBIT;
					break;
				case LA_10GHZ_LINK:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_10GBIT;
					break;
				default:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_UNKNOWN;
				}
			}

			port_attrs->PortSupportedClassofService =
			    LE_SWAP32(FC_NS_CLASS3);
			(void) strncpy((caddr_t)port_attrs->PortSymbolicName,
			    (caddr_t)port->spn,
			    sizeof (port_attrs->PortSymbolicName));

			/* Set the hba speed limit */
			if (vpd->link_speed & LMT_10GB_CAPABLE) {
				port_attrs->PortSupportedSpeed |=
				    FC_HBA_PORTSPEED_10GBIT;
			}
			if (vpd->link_speed & LMT_8GB_CAPABLE) {
				port_attrs->PortSupportedSpeed |=
				    FC_HBA_PORTSPEED_8GBIT;
			}
			if (vpd->link_speed & LMT_4GB_CAPABLE) {
				port_attrs->PortSupportedSpeed |=
				    FC_HBA_PORTSPEED_4GBIT;
			}
			if (vpd->link_speed & LMT_2GB_CAPABLE) {
				port_attrs->PortSupportedSpeed |=
				    FC_HBA_PORTSPEED_2GBIT;
			}
			if (vpd->link_speed & LMT_1GB_CAPABLE) {
				port_attrs->PortSupportedSpeed |=
				    FC_HBA_PORTSPEED_1GBIT;
			}

			value1 = 0x00000120;
			value2 = 0x00000001;

			bcopy((caddr_t)&value1,
			    (caddr_t)&port_attrs->PortSupportedFc4Types[0], 4);
			bcopy((caddr_t)&value2,
			    (caddr_t)&port_attrs->PortSupportedFc4Types[4], 4);

			bcopy((caddr_t)&value1,
			    (caddr_t)&port_attrs->PortActiveFc4Types[0], 4);
			bcopy((caddr_t)&value2,
			    (caddr_t)&port_attrs->PortActiveFc4Types[4], 4);

			port_attrs->PortMaxFrameSize = FF_FRAME_SIZE;
			port_attrs->NumberofDiscoveredPorts =
			    emlxs_nport_count(port);
		}

		break;
	}

	case FCIO_GET_NODE_ID:
	{
		fc_fca_pm_t	pm;

		if (fcio->fcio_xfer != FCIO_XFER_READ ||
		    fcio->fcio_olen < sizeof (fc_rnid_t)) {
			rval = EINVAL;
			break;
		}

		bzero((caddr_t)&pm, sizeof (pm));

		pm.pm_cmd_flags = FC_FCA_PM_READ;
		pm.pm_cmd_code  = FC_PORT_GET_NODE_ID;
		pm.pm_data_len  = fcio->fcio_olen;
		pm.pm_data_buf  = fcio->fcio_obuf;

		rval = emlxs_fca_port_manage(port, &pm);

		if (rval != FC_SUCCESS) {
			fcio->fcio_errno = rval;
			rval = EIO;
		}
		break;
	}

	case FCIO_SET_NODE_ID:
	{
		fc_fca_pm_t	pm;

		if (fcio->fcio_xfer != FCIO_XFER_WRITE ||
		    fcio->fcio_ilen < sizeof (fc_rnid_t)) {
			rval = EINVAL;
			break;
		}

		bzero((caddr_t)&pm, sizeof (pm));

		pm.pm_cmd_flags = FC_FCA_PM_READ;
		pm.pm_cmd_code  = FC_PORT_SET_NODE_ID;
		pm.pm_data_len  = fcio->fcio_ilen;
		pm.pm_data_buf  = fcio->fcio_ibuf;

		rval = emlxs_fca_port_manage(port, &pm);

		if (rval != FC_SUCCESS) {
			fcio->fcio_errno = rval;
			rval = EIO;
		}
		break;
	}


	case FCIO_GET_NUM_DEVS:
	{
		if (fcio->fcio_xfer != FCIO_XFER_READ ||
		    fcio->fcio_olen < sizeof (uint32_t)) {
			rval = EINVAL;
			break;
		}

		*(uint32_t *)fcio->fcio_obuf = emlxs_nport_count(port);

		break;
	}

	case FCIO_GET_DEV_LIST:
	{
		if (use32) {
			fc_port_dev32_t *port_dev;
			uint32_t max_count;
			uint32_t i;
			uint32_t j;
			emlxs_node_t *nlp;
			uint32_t nport_count;

			if (fcio->fcio_xfer != FCIO_XFER_READ ||
			    fcio->fcio_alen < sizeof (uint32_t)) {
				rval = EINVAL;
				break;
			}

			port_dev = (fc_port_dev32_t *)fcio->fcio_obuf;
			max_count = fcio->fcio_olen / sizeof (fc_port_dev32_t);

			rw_enter(&port->node_rwlock, RW_READER);

			nport_count = emlxs_nport_count(port);
			*(uint32_t *)fcio->fcio_abuf = nport_count;

			if (nport_count == 0) {
				rw_exit(&port->node_rwlock);

				fcio->fcio_errno = FC_NO_MAP;
				rval = EIO;
				break;
			}

			if (nport_count > max_count) {
				rw_exit(&port->node_rwlock);

				fcio->fcio_errno = FC_TOOMANY;
				rval = EIO;
				break;
			}

			for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
				nlp = port->node_table[i];
				while (nlp != NULL) {
				if ((nlp->nlp_DID & 0xFFF000) != 0xFFF000) {
					port_dev->dev_dtype = 0;
					port_dev->dev_type[0] =
					    BE_SWAP32(0x00000100);
					port_dev->dev_state =
					    PORT_DEVICE_LOGGED_IN;
					port_dev->dev_did.port_id =
					    nlp->nlp_DID;
					port_dev->dev_did.priv_lilp_posit = 0;
					port_dev->dev_hard_addr.hard_addr = 0;

	if (hba->topology == TOPOLOGY_LOOP) {
		for (j = 1; j < port->alpa_map[0]; j++) {
			if (nlp->nlp_DID == port->alpa_map[j]) {
				port_dev->dev_did.priv_lilp_posit = j-1;
				break;
			}
		}
		port_dev->dev_hard_addr.hard_addr = nlp->nlp_DID;
	}

					bcopy((caddr_t)&nlp->nlp_portname,
					    (caddr_t)&port_dev->dev_pwwn, 8);
					bcopy((caddr_t)&nlp->nlp_nodename,
					    (caddr_t)&port_dev->dev_nwwn, 8);
					port_dev++;
				}

				nlp = (NODELIST *) nlp->nlp_list_next;
				}
			}
			rw_exit(&port->node_rwlock);

		} else {

			fc_port_dev_t *port_dev;
			uint32_t max_count;
			uint32_t i;
			uint32_t j;
			emlxs_node_t *nlp;
			uint32_t nport_count;

			if (fcio->fcio_xfer != FCIO_XFER_READ ||
			    fcio->fcio_alen < sizeof (uint32_t)) {
				rval = EINVAL;
				break;
			}

			port_dev = (fc_port_dev_t *)fcio->fcio_obuf;
			max_count = fcio->fcio_olen / sizeof (fc_port_dev_t);

			rw_enter(&port->node_rwlock, RW_READER);

			nport_count = emlxs_nport_count(port);
			*(uint32_t *)fcio->fcio_abuf = nport_count;

			if (nport_count == 0) {
				rw_exit(&port->node_rwlock);

				fcio->fcio_errno = FC_NO_MAP;
				rval = EIO;
				break;
			}

			if (nport_count > max_count) {
				rw_exit(&port->node_rwlock);

				fcio->fcio_errno = FC_TOOMANY;
				rval = EIO;
				break;
			}

			for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
				nlp = port->node_table[i];
				while (nlp != NULL) {
				if ((nlp->nlp_DID & 0xFFF000) != 0xFFF000) {
					port_dev->dev_dtype = 0;
					port_dev->dev_type[0] =
					    BE_SWAP32(0x00000100);
					port_dev->dev_state =
					    PORT_DEVICE_LOGGED_IN;
					port_dev->dev_did.port_id =
					    nlp->nlp_DID;
					port_dev->dev_did.priv_lilp_posit = 0;
					port_dev->dev_hard_addr.hard_addr = 0;

	if (hba->topology == TOPOLOGY_LOOP) {
		for (j = 1; j < port->alpa_map[0]; j++) {
			if (nlp->nlp_DID == port->alpa_map[j]) {
				port_dev->dev_did.priv_lilp_posit = j-1;
				break;
			}
		}
		port_dev->dev_hard_addr.hard_addr = nlp->nlp_DID;
	}

					bcopy((caddr_t)&nlp->nlp_portname,
					    (caddr_t)&port_dev->dev_pwwn, 8);
					bcopy((caddr_t)&nlp->nlp_nodename,
					    (caddr_t)&port_dev->dev_nwwn, 8);
					port_dev++;
				}

				nlp = (NODELIST *) nlp->nlp_list_next;
				}
			}
			rw_exit(&port->node_rwlock);
		}

		break;
	}

	case FCIO_GET_LOGI_PARAMS:
	{
		uint8_t null_wwn[8];

		if (fcio->fcio_ilen != sizeof (la_wwn_t) ||
		    (fcio->fcio_xfer & FCIO_XFER_READ) == 0 ||
		    (fcio->fcio_xfer & FCIO_XFER_WRITE) == 0) {
			rval = EINVAL;
			break;
		}

		bzero(null_wwn, 8);
		wwpn = (uint8_t *)fcio->fcio_ibuf;

		if ((bcmp((caddr_t)wwpn, (caddr_t)null_wwn, 8) == 0) ||
		    (bcmp((caddr_t)wwpn, (caddr_t)&port->wwpn, 8) == 0)) {
			bcopy((caddr_t)&port->sparam,
			    (caddr_t)fcio->fcio_obuf, fcio->fcio_olen);
		} else {
			ndlp = emlxs_node_find_wwpn(port, wwpn);

			if (ndlp) {
				bcopy((caddr_t)&ndlp->sparm,
				    (caddr_t)fcio->fcio_obuf,
				    fcio->fcio_olen);
			} else {
				rval = ENXIO;
			}
		}

		break;
	}

	case FCIO_GET_STATE:
	{
		uint8_t null_wwn[8];
		uint32_t *statep;

		if (fcio->fcio_ilen != 8 ||
		    fcio->fcio_olen != 4 ||
		    (fcio->fcio_xfer & FCIO_XFER_WRITE) == 0 ||
		    (fcio->fcio_xfer & FCIO_XFER_READ) == 0) {
			rval = EINVAL;
			break;
		}

		bzero(null_wwn, 8);
		wwpn   = (uint8_t *)fcio->fcio_ibuf;
		statep = (uint32_t *)fcio->fcio_obuf;

		if ((bcmp((caddr_t)wwpn, (caddr_t)null_wwn, 8) == 0) ||
		    (bcmp((caddr_t)wwpn, (caddr_t)&port->wwpn, 8) == 0)) {
			*statep = PORT_DEVICE_VALID;
		} else {
			ndlp = emlxs_node_find_wwpn(port, wwpn);

			if (ndlp) {
				*statep = PORT_DEVICE_VALID;
			} else {
				*statep = PORT_DEVICE_INVALID;
			}
		}

		break;
	}

	case FCIO_GET_TOPOLOGY:
	{
		uint32_t *tp;

		if (fcio->fcio_olen != 4 ||
		    (fcio->fcio_xfer & FCIO_XFER_READ) == 0) {
			rval = EINVAL;
			break;
		}

		tp = (uint32_t *)fcio->fcio_obuf;

		if (hba->state <= FC_LINK_DOWN) {
			*tp = FC_TOP_UNKNOWN;
		} else {
			ndlp = emlxs_node_find_did(port, FABRIC_DID);

			if (hba->topology == TOPOLOGY_LOOP) {
				if (ndlp) {
					*tp = FC_TOP_PUBLIC_LOOP;
				} else {
					*tp = FC_TOP_PRIVATE_LOOP;
				}
			} else {
				if (ndlp) {
					*tp = FC_TOP_FABRIC;
				} else {
					*tp = FC_TOP_PT_PT;
				}
			}
		}

		break;
	}

	case FCIO_LINK_STATUS:
	{
		fc_portid_t	*portid;
		fc_rls_acc_t	*rls;
		fc_fca_pm_t	pm;

		if (fcio->fcio_ilen != sizeof (fc_portid_t) ||
		    fcio->fcio_olen != sizeof (fc_rls_acc_t) ||
		    fcio->fcio_xfer != FCIO_XFER_RW) {
			rval = EINVAL;
			break;
		}

		if ((fcio->fcio_cmd_flags != FCIO_CFLAGS_RLS_DEST_FPORT) &&
		    (fcio->fcio_cmd_flags != FCIO_CFLAGS_RLS_DEST_NPORT)) {
			rval = EINVAL;
			break;
		}

		portid = (fc_portid_t *)fcio->fcio_ibuf;
		rls    = (fc_rls_acc_t *)fcio->fcio_obuf;

		if (portid->port_id == 0 || portid->port_id == port->did) {
			bzero((caddr_t)&pm, sizeof (pm));

			pm.pm_cmd_flags = FC_FCA_PM_READ;
			pm.pm_cmd_code  = FC_PORT_RLS;
			pm.pm_data_len  = sizeof (fc_rls_acc_t);
			pm.pm_data_buf  = (caddr_t)rls;

			rval = emlxs_fca_port_manage(port, &pm);

			if (rval != FC_SUCCESS) {
				fcio->fcio_errno = rval;
				rval = EIO;
			}
		} else {
			rval = ENOTSUP;
		}
		break;
	}

	case FCIO_GET_OTHER_ADAPTER_PORTS:
	{
		uint32_t	index;
		char		*path;

		if (fcio->fcio_olen < MAXPATHLEN ||
		    fcio->fcio_ilen != sizeof (uint32_t)) {
			rval = EINVAL;
			break;
		}

		index = *(uint32_t *)fcio->fcio_ibuf;
		path  = (char *)fcio->fcio_obuf;

		if (index > hba->vpi_max) {
			fcio->fcio_errno = FC_BADPORT;
			rval = EFAULT;
			break;
		}

		(void) ddi_pathname(hba->dip, path);

		break;
	}

	case FCIO_GET_DISCOVERED_PORT_ATTRIBUTES:
	{
		uint32_t index;

		if (fcio->fcio_xfer != FCIO_XFER_READ ||
		    fcio->fcio_ilen < sizeof (uint32_t) ||
		    fcio->fcio_olen < sizeof (fc_hba_port_attributes_t)) {
			rval = EINVAL;
			break;
		}

		index = *(uint32_t *)fcio->fcio_ibuf;
		ndlp  = emlxs_node_find_index(port, index, 1);

		if (!ndlp) {
			fcio->fcio_errno = FC_OUTOFBOUNDS;
			rval = EINVAL;
			break;
		}

		goto get_node_attrs;
	}

	/* Same as FCIO_GET_DISCOVERED_PORT_ATTRIBUTES */
	/* except WWPN is used instead of index */
	case FCIO_GET_PORT_ATTRIBUTES:
	{
		emlxs_node_t *ndlp2;

		if ((fcio->fcio_xfer != FCIO_XFER_READ) ||
		    (fcio->fcio_ilen < 8) ||
		    (fcio->fcio_olen < sizeof (fc_hba_port_attributes_t))) {
			rval = EINVAL;
			break;
		}

		wwpn  = (uint8_t *)fcio->fcio_ibuf;
		ndlp  = emlxs_node_find_wwpn(port, wwpn);

		if (!ndlp) {
			fcio->fcio_errno = FC_NOMAP;
			rval = EINVAL;
			break;
		}

		/* Filter fabric ports */
		if ((ndlp->nlp_DID & 0xFFF000) == 0xFFF000) {
			fcio->fcio_errno = FC_NOMAP;
			rval = EINVAL;
			break;
		}

get_node_attrs:

		port_attrs = (fc_hba_port_attributes_t *)fcio->fcio_obuf;

		port_attrs->version    = FC_HBA_PORT_ATTRIBUTES_VERSION;
		/* port_attrs->lastChange */
		/* port_attrs->fp_minor   */
		bcopy((caddr_t)&ndlp->nlp_nodename,
		    (caddr_t)&port_attrs->NodeWWN, 8);
		bcopy((caddr_t)&ndlp->nlp_portname,
		    (caddr_t)&port_attrs->PortWWN, 8);

		port_attrs->PortSpeed = HBA_PORTSPEED_UNKNOWN;
		port_attrs->PortType  = FC_HBA_PORTTYPE_UNKNOWN;
		port_attrs->PortState = FC_HBA_PORTSTATE_OFFLINE;

		if (hba->state > FC_LINK_UP) {
			ndlp2 = emlxs_node_find_did(port, FABRIC_DID);

			port_attrs->PortFcId  = ndlp->nlp_DID;
			port_attrs->PortState = FC_HBA_PORTSTATE_ONLINE;

			/* no switch */
			if (!ndlp2) {
				if (hba->topology == TOPOLOGY_LOOP) {
					port_attrs->PortType =
					    FC_HBA_PORTTYPE_LPORT;
				} else {
					port_attrs->PortType =
					    FC_HBA_PORTTYPE_PTP;
				}

				/* We share a common speed */
				switch (hba->linkspeed) {
				case 0:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_1GBIT;
					break;
				case LA_1GHZ_LINK:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_1GBIT;
					break;
				case LA_2GHZ_LINK:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_2GBIT;
					break;
				case LA_4GHZ_LINK:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_4GBIT;
					break;
				case LA_8GHZ_LINK:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_8GBIT;
					break;
				case LA_10GHZ_LINK:
					port_attrs->PortSpeed =
					    HBA_PORTSPEED_10GBIT;
					break;
				}
			}
			/* public loop */
			else if (hba->topology == TOPOLOGY_LOOP) {
				/* Check for common area and domain */
				if ((ndlp->nlp_DID & 0xFFFF00) ==
				    (port->did & 0xFFFF00)) {
					port_attrs->PortType =
					    FC_HBA_PORTTYPE_NLPORT;

					/* We share a common speed */
					switch (hba->linkspeed) {
					case 0:
						port_attrs->PortSpeed =
						    HBA_PORTSPEED_1GBIT;
						break;
					case LA_1GHZ_LINK:
						port_attrs->PortSpeed =
						    HBA_PORTSPEED_1GBIT;
						break;
					case LA_2GHZ_LINK:
						port_attrs->PortSpeed =
						    HBA_PORTSPEED_2GBIT;
						break;
					case LA_4GHZ_LINK:
						port_attrs->PortSpeed =
						    HBA_PORTSPEED_4GBIT;
						break;
					case LA_8GHZ_LINK:
						port_attrs->PortSpeed =
						    HBA_PORTSPEED_8GBIT;
						break;
					case LA_10GHZ_LINK:
						port_attrs->PortSpeed =
						    HBA_PORTSPEED_10GBIT;
						break;
					}
				}
			}
		}

		port_attrs->PortSupportedClassofService =
		    LE_SWAP32(FC_NS_CLASS3);
		/* port_attrs->PortSymbolicName		*/
		/* port_attrs->PortSupportedSpeed	*/
		/* port_attrs->PortSupportedFc4Types	*/
		/* port_attrs->PortActiveFc4Types	*/
		/* port_attrs->PortMaxFrameSize		*/
		/* port_attrs->NumberofDiscoveredPorts	*/

		break;
	}

	case FCIO_GET_SYM_PNAME:
	{
		if (fcio->fcio_olen < (strlen(port->spn)+1) ||
		    (fcio->fcio_xfer & FCIO_XFER_READ) == 0) {
			rval = EINVAL;
			break;
		}

		(void) strcpy((caddr_t)fcio->fcio_obuf, (caddr_t)port->spn);

		break;
	}

	case FCIO_GET_SYM_NNAME:
	{
		if (fcio->fcio_olen < (strlen(port->snn)+1) ||
		    (fcio->fcio_xfer & FCIO_XFER_READ) == 0) {
			rval = EINVAL;
			break;
		}

		(void) strcpy((caddr_t)fcio->fcio_obuf, (caddr_t)port->snn);

		break;
	}

	case FCIO_FORCE_DUMP:
	{
		rval = emlxs_fca_reset(port, FC_FCA_CORE);

		if (rval != FC_SUCCESS) {
			fcio->fcio_errno = rval;
			rval = EIO;
			break;
		}

		break;
	}

	case FCIO_GET_DUMP_SIZE:
	{
		fc_fca_pm_t pm;

		if (fcio->fcio_olen != sizeof (uint32_t) ||
		    fcio->fcio_xfer != FCIO_XFER_READ) {
			rval = EINVAL;
			break;
		}

		bzero((caddr_t)&pm, sizeof (fc_fca_pm_t));

		pm.pm_data_len  = fcio->fcio_olen;
		pm.pm_data_buf  = fcio->fcio_obuf;
		pm.pm_cmd_code  = FC_PORT_GET_DUMP_SIZE;
		pm.pm_cmd_flags = FC_FCA_PM_READ;

		rval = emlxs_fca_port_manage(port, &pm);

		if (rval != FC_SUCCESS) {
			fcio->fcio_errno = rval;

			if (rval == FC_INVALID_REQUEST) {
				rval = ENOTTY;
			} else {
				rval = EIO;
			}
		}

		break;
	}

	case FCIO_GET_DUMP:
	{
		fc_fca_pm_t pm;
		uint32_t dump_size;

		if (fcio->fcio_xfer != FCIO_XFER_READ) {
			rval = EINVAL;
			break;
		}

		bzero((caddr_t)&pm, sizeof (fc_fca_pm_t));

		pm.pm_data_len  = sizeof (uint32_t);
		pm.pm_data_buf  = (caddr_t)&dump_size;
		pm.pm_cmd_code  = FC_PORT_GET_DUMP_SIZE;
		pm.pm_cmd_flags = FC_FCA_PM_READ;

		rval = emlxs_fca_port_manage(port, &pm);

		if (rval != FC_SUCCESS) {
			fcio->fcio_errno = rval;

			if (rval == FC_INVALID_REQUEST) {
				rval = ENOTTY;
			} else {
				rval = EIO;
			}
			break;
		}

		if (fcio->fcio_olen != dump_size) {
			fcio->fcio_errno = FC_NOMEM;
			rval = EINVAL;
			break;
		}

		bzero((caddr_t)&pm, sizeof (fc_fca_pm_t));

		pm.pm_data_len  = fcio->fcio_olen;
		pm.pm_data_buf  = fcio->fcio_obuf;
		pm.pm_cmd_code  = FC_PORT_GET_DUMP;
		pm.pm_cmd_flags = FC_FCA_PM_READ;

		rval = emlxs_fca_port_manage(port, &pm);

		if (rval != FC_SUCCESS) {
			fcio->fcio_errno = rval;

			if (rval == FC_INVALID_REQUEST) {
				rval = ENOTTY;
			} else {
				rval = EIO;
			}
		}

		break;
	}

	case FCIO_SET_SYM_PNAME:
	case FCIO_SET_SYM_NNAME:
	case FCIO_DEV_LOGIN:
	case FCIO_DEV_LOGOUT:
	case FCIO_DEV_REMOVE:
	case FCIO_NS:
	case FCIO_SEND_NODE_ID:
	case FCIO_GET_ADAPTER_PORT_STATS:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
		    "%s: Unsupported FCIO command.",
		    emlxs_fcio_xlate(fcio->fcio_cmd));
		rval = ENOTSUP;
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
		    "Unknown FCIO command. (0x%x)", fcio->fcio_cmd);
		rval = EFAULT;

	}	/* switch() */

done:

	if (rval != 0 && fcio->fcio_errno == 0) {
		fcio->fcio_errno = FC_FAILURE;
	}

	if (fcio->fcio_ibuf) {
		if (ddi_copyout(fcio->fcio_ibuf, dfc->buf1, fcio->fcio_ilen,
		    mode)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: %s: ddi_copyout failed. (size=%d)",
			    emlxs_dfc_xlate(dfc->cmd),
			    emlxs_fcio_xlate(dfc->data1), fcio->fcio_ilen);

			rval = EFAULT;
		}

		kmem_free(fcio->fcio_ibuf, fcio->fcio_ilen);
	}

	if (fcio->fcio_obuf) {
		if (ddi_copyout(fcio->fcio_obuf, dfc->buf2, fcio->fcio_olen,
		    mode)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: %s: ddi_copyout failed. (size=%d)",
			    emlxs_dfc_xlate(dfc->cmd),
			    emlxs_fcio_xlate(dfc->data1), fcio->fcio_olen);

			rval = EFAULT;
		}

		kmem_free(fcio->fcio_obuf, fcio->fcio_olen);
	}

	if (fcio->fcio_abuf) {
		if (ddi_copyout(fcio->fcio_abuf, dfc->buf3, fcio->fcio_alen,
		    mode)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: %s: ddi_copyout failed. (size=%d)",
			    emlxs_dfc_xlate(dfc->cmd),
			    emlxs_fcio_xlate(dfc->data1), fcio->fcio_alen);

			rval = EFAULT;
		}

		kmem_free(fcio->fcio_abuf, fcio->fcio_alen);
	}

	if (ddi_copyout((void *)&fcio->fcio_errno, (void *)dfc->buf4,
	    dfc->buf4_size, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: %s: ddi_copyout failed. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), emlxs_fcio_xlate(dfc->data1),
		    dfc->buf4_size);

			rval = EFAULT;
	}

	return (rval);

} /* emlxs_fcio_manage() */

#endif /* FCIO_SUPPORT */


static int32_t
emlxs_dfc_create_vport(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	emlxs_config_t	*cfg = &CFG;
	emlxs_port_t	*vport;
	emlxs_port_t	*tport;
	dfc_vportinfo_t	dfc_vport;
	uint32_t	vpi;
	uint32_t	options;
	char		name[256];
	uint8_t		wwn[8];

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s requested.",
	    emlxs_dfc_xlate(dfc->cmd));

	options = dfc->data1;

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < sizeof (dfc_vportinfo_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	/* Read the dfc_vport object */
	if (ddi_copyin((void *)dfc->buf1, (void *)&dfc_vport,
	    sizeof (dfc_vportinfo_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYIN_ERROR);
	}

	if (!(options & VPORT_OPT_AUTORETRY)) {
		if (!(hba->flag & FC_NPIV_ENABLED)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: NPIV currently not enabled.",
			    emlxs_dfc_xlate(dfc->cmd));

			return (DFC_NPIV_DISABLED);
		}

		if (!(hba->flag & FC_NPIV_SUPPORTED)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: NPIV currently not supported.",
			    emlxs_dfc_xlate(dfc->cmd));

			return (DFC_NPIV_UNSUPPORTED);
		}
	}

	/*
	 * Only the same WWNN and WWPN can be re-created
	 */
	bzero(wwn, 8);
	if (bcmp(wwn, dfc_vport.wwpn, 8) || bcmp(wwn, dfc_vport.wwnn, 0)) {
		for (vpi = 1; vpi <= hba->vpi_max; vpi++) {
			vport = &VPORT(vpi);

			if ((bcmp((caddr_t)&vport->wwnn,
			    (caddr_t)dfc_vport.wwnn, 8) == 0) &&
			    (bcmp((caddr_t)&vport->wwpn,
			    (caddr_t)dfc_vport.wwpn, 8) == 0)) {
				if (!(vport->flag & EMLXS_PORT_CONFIG) &&
				    (vport->flag & EMLXS_PORT_BOUND)) {
					dfc_vport.vpi = vpi;
					break;
				} else {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_dfc_error_msg,
					    "%s: VPI already in use.",
					    emlxs_dfc_xlate(dfc->cmd));

					return (DFC_ARG_INVALID);
				}
			}
		}
	}

	/* else auto assign */
	/* Acquire a VPI */
	if (dfc_vport.vpi == 0) {
		/* Auto Assign VPI */
		for (vpi = 1; vpi <= hba->vpi_max; vpi++) {
			vport = &VPORT(vpi);

			if (!(vport->flag & EMLXS_PORT_CONFIG)) {
				break;
			}
		}

		if (vpi > hba->vpi_max) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Out of resources.",
			    emlxs_dfc_xlate(dfc->cmd));

			return (DFC_DRVRES_ERROR);
		}

		dfc_vport.vpi = vpi;
	}

	/* Establish a WWPN */
	bzero(wwn, 8);
	if (!(bcmp(wwn, dfc_vport.wwpn, 8))) {
		/* Generate new WWPN */
		bcopy((caddr_t)&hba->wwpn, (caddr_t)dfc_vport.wwpn, 8);
		dfc_vport.wwpn[0] = 0x20;
		dfc_vport.wwpn[1] = (uint8_t)vpi;
	} else {	/* use one provided */

		/* Make sure WWPN is unique */
		if (tport = emlxs_vport_find_wwpn(hba, dfc_vport.wwpn)) {
			if ((tport->flag & EMLXS_PORT_CONFIG) &&
			    (tport->flag & EMLXS_PORT_BOUND)) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
				    "%s: WWPN already exists. vpi=%d",
				    emlxs_dfc_xlate(dfc->cmd), vpi);
				return (DFC_ARG_INVALID);
			}
		}
	}

	/* Establish a WWNN */
	bzero(wwn, 8);
	if (!(bcmp(wwn, dfc_vport.wwnn, 8))) {
		/* Generate new WWNN */
		bcopy((caddr_t)&hba->wwnn, (caddr_t)dfc_vport.wwnn, 8);
		dfc_vport.wwnn[0] = 0x28;
		dfc_vport.wwnn[1] = (uint8_t)vpi;
	}
	/* else use WWNN provided */

	/* Generate the symbolic node name */
	if (dfc_vport.snn[0]) {
		(void) strcpy(name, dfc_vport.snn);
		(void) sprintf(dfc_vport.snn, "%s %s", hba->snn, name);
	} else {
		(void) strcpy(dfc_vport.snn, hba->snn);
	}

	/* Generate the symbolic port name */
	if (dfc_vport.spn[0]) {
		(void) strcpy(name, dfc_vport.spn);
		(void) sprintf(dfc_vport.spn, "%s VPort-%d VName-%s", hba->spn,
		    vpi, name);
	} else {
		(void) sprintf(dfc_vport.spn, "%s VPort-%d", hba->spn, vpi);
	}

	dfc_vport.port_id = 0;
	dfc_vport.ulp_statec = FC_STATE_OFFLINE;
	dfc_vport.flags = VPORT_CONFIG;

	/* Set the highest configured vpi */
	if (dfc_vport.vpi >= hba->vpi_high) {
		hba->vpi_high = dfc_vport.vpi;
	}

	/* Configure the port object */
	bcopy((caddr_t)dfc_vport.wwnn, (caddr_t)&vport->wwnn, 8);
	bcopy((caddr_t)dfc_vport.wwpn, (caddr_t)&vport->wwpn, 8);
	(void) strncpy((caddr_t)vport->snn, (caddr_t)dfc_vport.snn, 256);
	(void) strncpy((caddr_t)vport->spn, (caddr_t)dfc_vport.spn, 256);
	vport->flag |= (EMLXS_PORT_CONFIG | EMLXS_PORT_ENABLE);

	/* Adjust restricted flags */
	vport->options &= ~EMLXS_OPT_RESTRICT_MASK;
	vport->flag &= ~EMLXS_PORT_RESTRICTED;
	if (options & VPORT_OPT_RESTRICT) {
		vport->options |= EMLXS_OPT_RESTRICT;
		vport->flag |= EMLXS_PORT_RESTRICTED;
		dfc_vport.flags |= VPORT_RESTRICTED;
	} else if (options & VPORT_OPT_UNRESTRICT) {
		vport->options |= EMLXS_OPT_UNRESTRICT;
	} else if (cfg[CFG_VPORT_RESTRICTED].current) {
		vport->flag |= EMLXS_PORT_RESTRICTED;
		dfc_vport.flags |= VPORT_RESTRICTED;
	}
#ifdef SFCT_SUPPORT
	if (vport->tgt_mode) {
		emlxs_fct_bind_port(vport);
	}
#endif /* SFCT_SUPPORT */

	if (ddi_copyout((void *)&dfc_vport, (void *)dfc->buf1,
	    sizeof (dfc_vportinfo_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYOUT_ERROR);
	}

	if (vport->flag & EMLXS_PORT_BOUND) {
		/*
		 * The same WWNN, WWPN and VPI has been re-created.
		 * Bring up the vport now!
		 */
		emlxs_port_online(vport);
	}

	return (0);

} /* emlxs_dfc_create_vport() */


static int32_t
emlxs_dfc_destroy_vport(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	emlxs_port_t	*vport;
	uint8_t		wwpn[8];
	fc_packet_t	*pkt = NULL;
	uint32_t	rval = 0;
	ELS_PKT		*els;
	char		buffer[256];

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s requested.",
	    emlxs_dfc_xlate(dfc->cmd));

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	if (dfc->buf1_size < 8) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		rval = DFC_ARG_TOOSMALL;
		goto done;
	}

	/* Read the wwn object */
	if (ddi_copyin((void *)dfc->buf1, (void *)wwpn, 8, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYIN_ERROR;
		goto done;
	}

	/* Make sure WWPN is unique */
	vport = emlxs_vport_find_wwpn(hba, wwpn);

	/* Physical does not have EMLXS_PORT_CONFIG set */
	if (!vport || !(vport->flag & EMLXS_PORT_CONFIG)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: WWPN does not exists. %s", emlxs_dfc_xlate(dfc->cmd),
		    emlxs_wwn_xlate(buffer, wwpn));

		rval = DFC_ARG_INVALID;
		goto done;
	}

	if (vport->did) {
		/* Fabric Logout */
		if (!(pkt = emlxs_pkt_alloc(vport,
		    sizeof (uint32_t) + sizeof (LOGO),
		    sizeof (FCP_RSP), 0, KM_NOSLEEP))) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Unable to allocate packet.",
			    emlxs_dfc_xlate(dfc->cmd));

			rval = DFC_SYSRES_ERROR;
			goto done;
		}

		/* Make this a polled IO */
		pkt->pkt_tran_flags &= ~FC_TRAN_INTR;
		pkt->pkt_tran_flags |= FC_TRAN_NO_INTR;
		pkt->pkt_comp = NULL;

		pkt->pkt_tran_type = FC_PKT_EXCHANGE;
		pkt->pkt_timeout = 60;

		/* Build the fc header */
		pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(FABRIC_DID);
		pkt->pkt_cmd_fhdr.r_ctl = R_CTL_ELS_REQ;
		pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(vport->did);
		pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
		pkt->pkt_cmd_fhdr.f_ctl =
		    F_CTL_FIRST_SEQ | F_CTL_END_SEQ | F_CTL_SEQ_INITIATIVE;
		pkt->pkt_cmd_fhdr.seq_id = 0;
		pkt->pkt_cmd_fhdr.df_ctl = 0;
		pkt->pkt_cmd_fhdr.seq_cnt = 0;
		pkt->pkt_cmd_fhdr.ox_id = 0xFFFF;
		pkt->pkt_cmd_fhdr.rx_id = 0xFFFF;
		pkt->pkt_cmd_fhdr.ro = 0;

		/* Build the command */
		els = (ELS_PKT *) pkt->pkt_cmd;
		els->elsCode = 0x05;	/* LOGO */
		els->un.logo.un.nPortId32 = LE_SWAP32(vport->did);
		bcopy(&vport->wwpn, &els->un.logo.portName, 8);

		/*
		 * Just send LOGO. Don't worry about result.
		 * This is just a courtesy anyway.
		 */
		(void) emlxs_pkt_send(pkt, 1);


		/* Take the port offline */
		(void) emlxs_port_offline(vport, 0xffffffff);
	}

	vport->flag &= ~(EMLXS_PORT_CONFIG | EMLXS_PORT_ENABLE);

	rval = 0;

done:

	if (pkt) {
		emlxs_pkt_free(pkt);
	}

	return (rval);

} /* emlxs_dfc_destroy_vport() */


static int32_t
emlxs_dfc_get_vportinfo(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	emlxs_port_t	*vport;
	dfc_vportinfo_t	*dfc_vport;
	dfc_vportinfo_t	*dfc_vport_list = NULL;
	uint32_t	i;
	uint32_t	size;
	uint32_t	max_count;
	uint32_t	rval = DFC_SUCCESS;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s requested.",
	    emlxs_dfc_xlate(dfc->cmd));

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	size = (sizeof (dfc_vportinfo_t) * MAX_VPORTS);

	if (!(dfc_vport_list =
	    (dfc_vportinfo_t *)kmem_zalloc(size, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to allocate memory.",
		    emlxs_dfc_xlate(dfc->cmd));

		return (DFC_SYSRES_ERROR);
	}

	max_count = 0;
	for (i = 0; i <= hba->vpi_max; i++) {
		vport = &VPORT(i);
		dfc_vport = &dfc_vport_list[i];

		if (!(vport->flag & EMLXS_PORT_CONFIG)) {
			continue;
		}

		bcopy(vport->snn, dfc_vport->snn, 256);
		bcopy(vport->spn, dfc_vport->spn, 256);
		bcopy(&vport->wwpn, dfc_vport->wwpn, 8);
		bcopy(&vport->wwnn, dfc_vport->wwnn, 8);
		dfc_vport->port_id = vport->did;
		dfc_vport->vpi = vport->vpi;
		dfc_vport->ulp_statec = vport->ulp_statec;
		dfc_vport->flags = VPORT_CONFIG;

		if (vport->flag & EMLXS_PORT_ENABLE) {
			dfc_vport->flags |= VPORT_ENABLED;
		}

		if (vport->flag & EMLXS_PORT_BOUND) {
			dfc_vport->flags |= VPORT_BOUND;
		}

		if (vport->flag & EMLXS_PORT_IP_UP) {
			dfc_vport->flags |= VPORT_IP;
		}

		if (vport->flag & EMLXS_PORT_RESTRICTED) {
			dfc_vport->flags |= VPORT_RESTRICTED;
		}

		max_count++;
	}

	max_count *= sizeof (dfc_vportinfo_t);

	if (max_count > dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (%d > %d)",
		    emlxs_dfc_xlate(dfc->cmd), max_count, dfc->buf1_size);

		rval = DFC_ARG_TOOSMALL;
		goto done;
	}

	if (ddi_copyout((void *)dfc_vport_list, (void *)dfc->buf1,
	    dfc->buf1_size, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYOUT_ERROR;
		goto done;
	}

done:

	if (dfc_vport_list) {
		kmem_free(dfc_vport_list, size);
	}

	return (rval);

} /* emlxs_dfc_get_vportinfo() */


static emlxs_port_t *
emlxs_vport_find_wwpn(emlxs_hba_t *hba, uint8_t *wwpn)
{
	emlxs_port_t	*port;
	NODELIST	*nlp;
	int		i, j;

	for (i = 0; i <= hba->vpi_max; i++) {
		port = &VPORT(i);

		/* Check Local N-port, including physical port */
		if (bcmp(&port->wwpn, wwpn, 8) == 0) {
			return (port);
		}

		/* Check Remote N-port */
		rw_enter(&port->node_rwlock, RW_READER);
		for (j = 0; j < EMLXS_NUM_HASH_QUES; j++) {
			nlp = port->node_table[j];
			while (nlp != NULL) {
				/* Check Local N-port */
				if (bcmp(&nlp->nlp_portname, wwpn, 8) == 0) {
					rw_exit(&port->node_rwlock);
					return (port);
				}
				nlp = nlp->nlp_list_next;
			}
		}

		rw_exit(&port->node_rwlock);
	}

	return (0);

} /* emlxs_vport_find_wwpn() */


static int32_t
emlxs_dfc_npiv_resource(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t		*port = &PPORT;
	dfc_vport_resource_t	vres;
	MAILBOXQ		*mbq = NULL;
	MAILBOX			*mb;
	uint32_t		rval = DFC_SUCCESS;

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < sizeof (dfc_vport_resource_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	bzero(&vres, sizeof (dfc_vport_resource_t));

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		int i;
		int total_rpi;
		emlxs_port_t *vport;

		total_rpi = 0;
		for (i = 0; i < hba->sli.sli4.VPICount; i++) {
			vport = &VPORT(i);
			total_rpi += vport->VPIobj.rpi_online;
		}

		vres.vpi_max = hba->sli.sli4.VPICount - 1;
		vres.vpi_inuse = (port->VPIobj.vfip == NULL) ? 0 :
		    (port->VPIobj.vfip->vpi_online - 1);
		vres.rpi_max = hba->sli.sli4.RPICount;
		vres.rpi_inuse = total_rpi;

		if (ddi_copyout((void *)&vres, (void *)dfc->buf1,
		    sizeof (dfc_vport_resource_t), mode) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: ddi_copyout failed.",
			    emlxs_dfc_xlate(dfc->cmd));

			rval = DFC_COPYOUT_ERROR;
		}
		return (rval);
	}

	mbq =
	    (MAILBOXQ *)kmem_zalloc(sizeof (MAILBOXQ), KM_SLEEP);

	mb = (MAILBOX *) mbq;

	emlxs_mb_read_config(hba, mbq);

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0);

	if (rval == MBX_TIMEOUT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Mailbox timed out. cmd=%x",
		    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

		rval = DFC_TIMEOUT;
		goto done;
	}

	if (rval) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: %s failed. status=%x", emlxs_dfc_xlate(dfc->cmd),
		    emlxs_mb_cmd_xlate(mb->mbxCommand), rval);

		rval = DFC_IO_ERROR;
		goto done;
	}

	vres.vpi_max = mb->un.varRdConfig.max_vpi;
	vres.vpi_inuse =
	    (mb->un.varRdConfig.max_vpi <=
	    mb->un.varRdConfig.avail_vpi) ? 0 : mb->un.varRdConfig.max_vpi -
	    mb->un.varRdConfig.avail_vpi;

	vres.rpi_max = mb->un.varRdConfig.max_rpi;
	vres.rpi_inuse =
	    (mb->un.varRdConfig.max_rpi <=
	    mb->un.varRdConfig.avail_rpi) ? 0 : mb->un.varRdConfig.max_rpi -
	    mb->un.varRdConfig.avail_rpi;

	if (ddi_copyout((void *)&vres, (void *)dfc->buf1,
	    sizeof (dfc_vport_resource_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYOUT_ERROR;
	}

done:

	/* Free allocated mbox memory */
	if (mbq) {
		kmem_free(mbq, sizeof (MAILBOXQ));
	}

	return (rval);

} /* emlxs_dfc_npiv_resource() */


static int32_t
emlxs_dfc_npiv_test(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	emlxs_port_t	*vport = &VPORT(hba->vpi_max);
	emlxs_config_t	*cfg = &CFG;
	fc_packet_t	*pkt = NULL;
	fc_packet_t	*pkt1 = NULL;
	ELS_PKT		*els;
	LS_RJT		*lsrjt;
	uint32_t	checklist = 0;
	uint32_t	mask = 0;
	uint32_t	rval = DFC_SUCCESS;
	uint8_t		wwn[8];
	emlxs_vpd_t	*vpd = &VPD;
	int		i;

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < sizeof (uint32_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	if (cfg[CFG_NPIV_ENABLE].current) {
		checklist |= CL_NPIV_PARM_ENABLE;
	}

	if (hba->sli_mode >= 3) {
		checklist |= CL_SLI3_ENABLE;
	}


	if ((vpd->feaLevelHigh >= 0x09) || (hba->sli_mode >= 4)) {
		checklist |= CL_HBA_SUPPORT_NPIV;
	}


	if (hba->num_of_ports <= hba->vpi_max) {
		checklist |= CL_HBA_HAS_RESOURCES;
	}

	if (hba->state < FC_LINK_UP) {
		goto done;
	}

	checklist |= CL_HBA_LINKUP;

	if (hba->topology == TOPOLOGY_LOOP) {
		goto done;
	}

	if (!(hba->flag & FC_FABRIC_ATTACHED)) {
		goto done;
	}

	checklist |= CL_P2P_TOPOLOGY;

	if (!(hba->flag & FC_NPIV_SUPPORTED)) {
		goto done;
	}

	checklist |= CL_FABRIC_SUPPORTS_NPIV;

	mask =
	    (CL_NPIV_PARM_ENABLE | CL_SLI3_ENABLE | CL_HBA_SUPPORT_NPIV |
	    CL_HBA_HAS_RESOURCES);

	/*
	 * Check if those four conditions are met
	 */
	if ((checklist & mask) != mask) {
		/*
		 * One or more conditions are not met
		 */
		goto done;
	}

		/* Now check if fabric have resources */
	for (i = 1; i <= hba->vpi_max; i++) {
			vport = &VPORT(i);
		if (vport->did) {
				checklist |= CL_FABRIC_HAS_RESOURCES;
				goto done;
			}
		}

	vport->vpi = hba->vpi_max;
	vport->hba = hba;

	if (!(pkt = emlxs_pkt_alloc(vport,
	    sizeof (uint32_t) + sizeof (SERV_PARM), sizeof (FCP_RSP),
	    0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "Unable to allocate packet.");
		goto done;
	}

	/* Build (FDISC) the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(FABRIC_DID);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_EXTENDED_SVC | R_CTL_UNSOL_CONTROL;
	pkt->pkt_cmd_fhdr.s_id = 0;
	pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
	pkt->pkt_cmd_fhdr.f_ctl = F_CTL_FIRST_SEQ | F_CTL_SEQ_INITIATIVE;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xffff;
	pkt->pkt_cmd_fhdr.rx_id = 0xffff;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* Build the command (FDISC) */
	els = (ELS_PKT *) pkt->pkt_cmd;
	els->elsCode = 0x04;	/* FLOGI - This will be changed automatically */
				/* by the drive (See emlxs_send_els()) */

	/* Copy latest service parameters to payload */
	bcopy((void *)&port->sparam,
	    (void *)&els->un.logi, sizeof (SERV_PARM));

	bcopy((caddr_t)&hba->wwnn, (caddr_t)wwn, 8);
	wwn[0] = 0x28;
	wwn[1] = hba->vpi_max;
	bcopy((caddr_t)wwn, (caddr_t)&els->un.logi.nodeName, 8);
	bcopy((caddr_t)wwn, (caddr_t)&vport->wwnn, 8);

	bcopy((caddr_t)&hba->wwpn, (caddr_t)wwn, 8);
	wwn[0] = 0x20;
	wwn[1] = hba->vpi_max;
	bcopy((caddr_t)wwn, (caddr_t)&els->un.logi.portName, 8);
	bcopy((caddr_t)wwn, (caddr_t)&vport->wwpn, 8);

	bcopy((void *)&els->un.logi, (void *)&vport->sparam,
	    sizeof (SERV_PARM));



	/* Make this a polled IO */
	pkt->pkt_tran_flags &= ~FC_TRAN_INTR;
	pkt->pkt_tran_flags |= FC_TRAN_NO_INTR;
	pkt->pkt_comp = NULL;

	pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	pkt->pkt_timeout = 60;

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to send packet.", emlxs_dfc_xlate(dfc->cmd));

		goto done;
	}

	if (pkt->pkt_state == FC_PKT_SUCCESS) {
		if (!(pkt1 = emlxs_pkt_alloc(vport,
		    sizeof (uint32_t) + sizeof (LOGO), sizeof (FCP_RSP),
		    0, KM_NOSLEEP))) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "Unable to allocate LOGO packet.");
			goto free_resc;
		}

		/* Make this a polled IO */
		pkt1->pkt_tran_flags &= ~FC_TRAN_INTR;
		pkt1->pkt_tran_flags |= FC_TRAN_NO_INTR;
		pkt1->pkt_comp = NULL;

		pkt1->pkt_tran_type = FC_PKT_EXCHANGE;
		pkt1->pkt_timeout = 60;

		/* Build (LOGO) the fc header */
		pkt1->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(FABRIC_DID);
		pkt1->pkt_cmd_fhdr.r_ctl = R_CTL_ELS_REQ;
		pkt1->pkt_cmd_fhdr.s_id =
		    LE_SWAP24_LO(pkt->pkt_resp_fhdr.d_id);
		pkt1->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
		pkt1->pkt_cmd_fhdr.f_ctl =
		    F_CTL_FIRST_SEQ | F_CTL_END_SEQ | F_CTL_SEQ_INITIATIVE;
		pkt1->pkt_cmd_fhdr.seq_id = 0;
		pkt1->pkt_cmd_fhdr.df_ctl = 0;
		pkt1->pkt_cmd_fhdr.seq_cnt = 0;
		pkt1->pkt_cmd_fhdr.ox_id = 0xFFFF;
		pkt1->pkt_cmd_fhdr.rx_id = 0xFFFF;
		pkt1->pkt_cmd_fhdr.ro = 0;

		/* Build the command (LOGO) */
		els = (ELS_PKT *) pkt1->pkt_cmd;
		els->elsCode = 0x05;	/* LOGO */
		els->un.logo.un.nPortId32 =
		    LE_SWAP32(pkt->pkt_resp_fhdr.d_id);
		bcopy((caddr_t)&hba->wwpn, (caddr_t)wwn, 8);
		wwn[0] = 0x20;
		wwn[1] = hba->vpi_max;
		bcopy(wwn, &els->un.logo.portName, 8);

		if (emlxs_pkt_send(pkt1, 1) != FC_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Unable to send packet.",
			    emlxs_dfc_xlate(dfc->cmd));

			goto free_resc;
		}

		if (pkt1->pkt_state != FC_PKT_SUCCESS) {
			if (pkt1->pkt_state == FC_PKT_TIMEOUT) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_dfc_error_msg,
				    "%s: Pkt Transport error. Pkt Timeout.",
				    emlxs_dfc_xlate(dfc->cmd));
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_dfc_error_msg,
				    "%s: Pkt Transport error. state=%x",
				    emlxs_dfc_xlate(dfc->cmd),
				    pkt1->pkt_state);
			}
			goto free_resc;
		}

		checklist |= CL_FABRIC_HAS_RESOURCES;
	} else if (pkt->pkt_state == FC_PKT_LS_RJT) {
		lsrjt = (LS_RJT *) pkt->pkt_resp;
		if (lsrjt->un.b.lsRjtRsnCodeExp != LSEXP_OUT_OF_RESOURCE) {
			checklist |= CL_FABRIC_HAS_RESOURCES;
		}
	}

	/*
	 * Free up default RPIs and VPI
	 */
free_resc:

	/* Unregister all nodes */
	(void) emlxs_mb_unreg_node(vport, 0, 0, 0, 0);

	(void) emlxs_mb_unreg_vpi(vport);

done:
	if (ddi_copyout((void *)&checklist, (void *)dfc->buf1,
	    sizeof (uint32_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));
		rval = DFC_COPYOUT_ERROR;
	}

	if (pkt) {
		/* Free the pkt */
		emlxs_pkt_free(pkt);
	}

	if (pkt1) {
		/* Free the pkt */
		emlxs_pkt_free(pkt1);
	}

	return (rval);

} /* emlxs_dfc_npiv_test() */


static int32_t
emlxs_dfc_get_rev(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	rev;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s requested.",
	    emlxs_dfc_xlate(dfc->cmd));

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < sizeof (uint32_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	rev = DFC_REV;

	if (ddi_copyout((void *)&rev, (void *)dfc->buf1, sizeof (uint32_t),
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYOUT_ERROR);
	}

	return (0);

} /* emlxs_dfc_get_rev() */


static int32_t
emlxs_dfc_get_hbainfo(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	emlxs_vpd_t	*vpd = &VPD;
	emlxs_config_t	*cfg = &CFG;
	dfc_hbainfo_t	hbainfo;
	NODELIST	*ndlp;
	char		pathname[256];

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s requested.",
	    emlxs_dfc_xlate(dfc->cmd));

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < sizeof (dfc_hbainfo_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	bzero((void *) &hbainfo, sizeof (dfc_hbainfo_t));

	(void) strncpy(hbainfo.vpd_serial_num, vpd->serial_num,
	    sizeof (hbainfo.vpd_serial_num));
	(void) strncpy(hbainfo.vpd_part_num, vpd->part_num,
	    sizeof (hbainfo.vpd_part_num));
	(void) strncpy(hbainfo.vpd_port_num, vpd->port_num,
	    sizeof (hbainfo.vpd_port_num));
	(void) strncpy(hbainfo.vpd_eng_change, vpd->eng_change,
	    sizeof (hbainfo.vpd_eng_change));
	(void) strncpy(hbainfo.vpd_manufacturer, vpd->manufacturer,
	    sizeof (hbainfo.vpd_manufacturer));
	(void) strncpy(hbainfo.vpd_model, vpd->model,
	    sizeof (hbainfo.vpd_model));
	(void) strncpy(hbainfo.vpd_model_desc, vpd->model_desc,
	    sizeof (hbainfo.vpd_model_desc));
	(void) strncpy(hbainfo.vpd_prog_types, vpd->prog_types,
	    sizeof (hbainfo.vpd_prog_types));
	(void) strncpy(hbainfo.vpd_id, vpd->id, sizeof (hbainfo.vpd_id));

	hbainfo.device_id = hba->model_info.device_id;
	hbainfo.vendor_id =
	    ddi_get32(hba->pci_acc_handle,
	    (uint32_t *)(hba->pci_addr + PCI_VENDOR_ID_REGISTER)) & 0xffff;

	hbainfo.ports = hba->num_of_ports;
	hbainfo.port_index = vpd->port_index;

	bcopy(&hba->wwnn, hbainfo.wwnn, sizeof (hbainfo.wwnn));
	(void) strncpy(hbainfo.snn, port->snn, sizeof (hbainfo.snn));

	bcopy(&hba->wwpn, hbainfo.wwpn, sizeof (hbainfo.wwpn));
	(void) strncpy(hbainfo.spn, port->spn, sizeof (hbainfo.spn));

	hbainfo.biuRev = vpd->biuRev;
	hbainfo.smRev = vpd->smRev;
	hbainfo.smFwRev = vpd->smFwRev;
	hbainfo.endecRev = vpd->endecRev;
	hbainfo.rBit = vpd->rBit;
	hbainfo.fcphHigh = vpd->fcphHigh;
	hbainfo.fcphLow = vpd->fcphLow;
	hbainfo.feaLevelHigh = vpd->feaLevelHigh;
	hbainfo.feaLevelLow = vpd->feaLevelLow;

	hbainfo.kern_rev = vpd->postKernRev;
	(void) strncpy(hbainfo.kern_name, vpd->postKernName,
	    sizeof (hbainfo.kern_name));

	hbainfo.stub_rev = vpd->opFwRev;
	(void) strncpy(hbainfo.stub_name, vpd->opFwName,
	    sizeof (hbainfo.stub_name));

	hbainfo.sli1_rev = vpd->sli1FwRev;
	(void) strncpy(hbainfo.sli1_name, vpd->sli1FwName,
	    sizeof (hbainfo.sli1_name));

	hbainfo.sli2_rev = vpd->sli2FwRev;
	(void) strncpy(hbainfo.sli2_name, vpd->sli2FwName,
	    sizeof (hbainfo.sli2_name));

	hbainfo.sli3_rev = vpd->sli3FwRev;
	(void) strncpy(hbainfo.sli3_name, vpd->sli3FwName,
	    sizeof (hbainfo.sli3_name));

	hbainfo.sli4_rev = vpd->sli4FwRev;
	(void) strncpy(hbainfo.sli4_name, vpd->sli4FwName,
	    sizeof (hbainfo.sli4_name));

	hbainfo.sli_mode = hba->sli_mode;
	hbainfo.vpi_max  = hba->vpi_max;
	hbainfo.vpi_high = hba->vpi_high;
	hbainfo.flags = 0;

	/* Set support flags */
	hbainfo.flags  = HBA_FLAG_DYN_WWN;
	hbainfo.flags |= HBA_FLAG_NPIV;

#ifdef DHCHAP_SUPPORT
	hbainfo.flags |= HBA_FLAG_DHCHAP;

	if (cfg[CFG_AUTH_E2E].current) {
		hbainfo.flags |= HBA_FLAG_E2E_AUTH;
	}
#endif	/* DHCHAP_SUPPORT */

#ifdef SAN_DIAG_SUPPORT
	hbainfo.flags |= HBA_FLAG_SAN_DIAG;
#endif	/* SAN_DIAG_SUPPORT */

#ifdef SFCT_SUPPORT
	hbainfo.flags |= HBA_FLAG_TARGET_MODE;
	if (hba->tgt_mode) {
		hbainfo.flags |= HBA_FLAG_TARGET_MODE_ENA;
	}
#endif /* SFCT_SUPPORT */

	hbainfo.flags |= HBA_FLAG_FCOE;

	if (! (hba->model_info.flags & EMLXS_FCOE_SUPPORTED)) {
		hbainfo.flags |= HBA_FLAG_PERSISTLINK;
	}

	(void) strncpy(hbainfo.fcode_version, vpd->fcode_version,
	    sizeof (hbainfo.fcode_version));
	(void) strncpy(hbainfo.boot_version, vpd->boot_version,
	    sizeof (hbainfo.boot_version));
	(void) strncpy(hbainfo.fw_version, vpd->fw_version,
	    sizeof (hbainfo.fw_version));
	(void) strncpy(hbainfo.drv_label, emlxs_label,
	    sizeof (hbainfo.drv_label));
	(void) strncpy(hbainfo.drv_module, emlxs_name,
	    sizeof (hbainfo.drv_module));
	(void) strncpy(hbainfo.drv_name, DRIVER_NAME,
	    sizeof (hbainfo.drv_name));
	(void) strncpy(hbainfo.drv_version, emlxs_version,
	    sizeof (hbainfo.drv_version));
	(void) strncpy(hbainfo.drv_revision, emlxs_revision,
	    sizeof (hbainfo.drv_revision));
	(void) strncpy(hbainfo.hostname, (char *)utsname.nodename,
	    sizeof (hbainfo.hostname));

	(void) ddi_pathname(hba->dip, pathname);
	(void) sprintf(hbainfo.os_devname, "/devices%s", pathname);

	if (hba->flag & (FC_OFFLINE_MODE | FC_OFFLINING_MODE)) {
		hbainfo.flags |= HBA_FLAG_OFFLINE;
	}

	hbainfo.drv_instance = hba->ddiinst;
	hbainfo.port_id = port->did;
	hbainfo.port_type = HBA_PORTTYPE_UNKNOWN;

#ifdef MENLO_SUPPORT
	if (hba->flag & FC_MENLO_MODE) {
		hbainfo.topology  = LNK_MENLO_MAINTENANCE;
	} else
#endif /* MENLO_SUPPORT */

	if (hba->state >= FC_LINK_UP) {
		ndlp = emlxs_node_find_did(port, FABRIC_DID);

		if (hba->topology == TOPOLOGY_LOOP) {
			if (ndlp) {
				hbainfo.port_type = HBA_PORTTYPE_NLPORT;
				hbainfo.topology = LNK_PUBLIC_LOOP;
			} else {
				hbainfo.port_type = HBA_PORTTYPE_LPORT;
				hbainfo.topology = LNK_LOOP;
			}

			hbainfo.alpa_count = port->alpa_map[0];
			bcopy((void *)&port->alpa_map[1], hbainfo.alpa_map,
			    hbainfo.alpa_count);
		} else {
			if (ndlp) {
				hbainfo.port_type = HBA_PORTTYPE_NPORT;
				hbainfo.topology = LNK_FABRIC;
			} else {
				hbainfo.port_type = HBA_PORTTYPE_PTP;
				hbainfo.topology = LNK_PT2PT;
			}
		}

		if (ndlp) {
			bcopy(&ndlp->nlp_nodename, hbainfo.fabric_wwnn,
			    sizeof (hbainfo.fabric_wwnn));
			bcopy(&ndlp->nlp_portname, hbainfo.fabric_wwpn,
			    sizeof (hbainfo.fabric_wwpn));
		}

		if (hba->linkspeed == LA_2GHZ_LINK) {
			hbainfo.port_speed = HBA_PORTSPEED_2GBIT;
		} else if (hba->linkspeed == LA_4GHZ_LINK) {
			hbainfo.port_speed = HBA_PORTSPEED_4GBIT;
		} else if (hba->linkspeed == LA_8GHZ_LINK) {
			hbainfo.port_speed = HBA_PORTSPEED_8GBIT;
		} else if (hba->linkspeed == LA_10GHZ_LINK) {
			hbainfo.port_speed = HBA_PORTSPEED_10GBIT;
		} else {
			hbainfo.port_speed = HBA_PORTSPEED_1GBIT;
		}

		hbainfo.node_count = port->node_count;
	}

	hbainfo.hard_alpa = cfg[CFG_ASSIGN_ALPA].current;
	hbainfo.supported_cos = LE_SWAP32((FC_NS_CLASS3 | FC_NS_CLASS2));

	hbainfo.supported_types[0] = LE_SWAP32(0x00000120);
	hbainfo.supported_types[1] = LE_SWAP32(0x00000001);

	hbainfo.active_types[0] = LE_SWAP32(0x00000120);
	hbainfo.active_types[1] = LE_SWAP32(0x00000001);

	if (!cfg[CFG_NETWORK_ON].current) {
		hbainfo.active_types[0] &= ~(LE_SWAP32(0x00000020));
	}

	if (vpd->link_speed & LMT_10GB_CAPABLE) {
		hbainfo.supported_speeds |= FC_HBA_PORTSPEED_10GBIT;
	}
	if (vpd->link_speed & LMT_8GB_CAPABLE) {
		hbainfo.supported_speeds |= FC_HBA_PORTSPEED_8GBIT;
	}
	if (vpd->link_speed & LMT_4GB_CAPABLE) {
		hbainfo.supported_speeds |= FC_HBA_PORTSPEED_4GBIT;
	}
	if (vpd->link_speed & LMT_2GB_CAPABLE) {
		hbainfo.supported_speeds |= FC_HBA_PORTSPEED_2GBIT;
	}
	if (vpd->link_speed & LMT_1GB_CAPABLE) {
		hbainfo.supported_speeds |= FC_HBA_PORTSPEED_1GBIT;
	}

	hbainfo.max_frame_size = FF_FRAME_SIZE;

	if (hba->bus_type == SBUS_FC) {
		hbainfo.flags |= HBA_FLAG_SBUS;
	}

	if (hba->flag & (FC_ONLINING_MODE | FC_OFFLINING_MODE)) {
		hbainfo.flags |= HBA_FLAG_OFFLINE;
		hbainfo.port_state = HBA_PORTSTATE_UNKNOWN;
	} else if (hba->flag & FC_ONLINE_MODE) {
		if (hba->flag & FC_LOOPBACK_MODE) {
			hbainfo.port_state = HBA_PORTSTATE_LOOPBACK;
		} else if (hba->state <= FC_LINK_DOWN) {
			hbainfo.port_state = HBA_PORTSTATE_LINKDOWN;
		}
#ifdef MENLO_SUPPORT
		else if (hba->flag & FC_MENLO_MODE) {
			hbainfo.port_state = HBA_PORTSTATE_LINKDOWN;
		}
#endif /* MENLO_SUPPORT */
		else {
			hbainfo.port_state = HBA_PORTSTATE_ONLINE;
		}
	} else {
		hbainfo.flags |= HBA_FLAG_OFFLINE;

		if (hba->state == FC_ERROR) {
			hbainfo.port_state = HBA_PORTSTATE_ERROR;
		} else {
			hbainfo.port_state = HBA_PORTSTATE_OFFLINE;
		}
	}

	hbainfo.pci_function_number = hba->pci_function_number;
	hbainfo.pci_device_number = hba->pci_device_number;
	hbainfo.pci_bus_number = hba->pci_bus_number;

	if (ddi_copyout((void *)&hbainfo, (void *)dfc->buf1,
	    sizeof (dfc_hbainfo_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYOUT_ERROR);
	}

#ifdef FMA_SUPPORT
	/* Access handle validation */
	if (emlxs_fm_check_acc_handle(hba, hba->pci_acc_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_access_handle_msg, NULL);
		return (DFC_DRV_ERROR);
	}
#endif  /* FMA_SUPPORT */

	return (0);

} /* emlxs_dfc_get_hbainfo() */



static int32_t
emlxs_dfc_get_hbastats(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	dfc_hbastats_t	stats;
	MAILBOX		*mb = NULL;
	MAILBOXQ	*mbq = NULL;
	uint32_t	rval = 0;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s requested.",
	    emlxs_dfc_xlate(dfc->cmd));

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < sizeof (dfc_hbastats_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	mbq =
	    (MAILBOXQ *)kmem_zalloc(sizeof (MAILBOXQ), KM_SLEEP);

	mb = (MAILBOX *)mbq;

	emlxs_mb_read_status(hba, mbq);

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0);

	if (rval == MBX_TIMEOUT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Mailbox timed out. cmd=%x",
		    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

		rval = DFC_TIMEOUT;
		goto done;
	}

	if (rval) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: %s failed. status=%x", emlxs_dfc_xlate(dfc->cmd),
		    emlxs_mb_cmd_xlate(mb->mbxCommand), rval);

		rval = DFC_IO_ERROR;
		goto done;
	}

	bzero((void *) &stats, sizeof (dfc_hbastats_t));

	stats.tx_frame_cnt = mb->un.varRdStatus.xmitFrameCnt;
	stats.rx_frame_cnt = mb->un.varRdStatus.rcvFrameCnt;
	stats.tx_kbyte_cnt = mb->un.varRdStatus.xmitByteCnt;
	stats.rx_kbyte_cnt = mb->un.varRdStatus.rcvByteCnt;
	stats.tx_seq_cnt = mb->un.varRdStatus.xmitSeqCnt;
	stats.rx_seq_cnt = mb->un.varRdStatus.rcvSeqCnt;
	stats.orig_exch_cnt = mb->un.varRdStatus.totalOrigExchanges;
	stats.resp_exch_cnt = mb->un.varRdStatus.totalRespExchanges;
	stats.pbsy_cnt = mb->un.varRdStatus.rcvPbsyCnt;
	stats.fbsy_cnt = mb->un.varRdStatus.rcvFbsyCnt;

	emlxs_mb_read_lnk_stat(hba, mbq);

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0);

	if (rval == MBX_TIMEOUT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Mailbox timed out. cmd=%x",
		    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

		rval = DFC_TIMEOUT;
		goto done;
	}

	if (rval) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: %s failed. status=%x", emlxs_dfc_xlate(dfc->cmd),
		    emlxs_mb_cmd_xlate(mb->mbxCommand), rval);

		rval = DFC_IO_ERROR;
		goto done;
	}

	stats.link_failure_cnt = mb->un.varRdLnk.linkFailureCnt;
	stats.loss_sync_cnt = mb->un.varRdLnk.lossSyncCnt;
	stats.loss_signal_cnt = mb->un.varRdLnk.lossSignalCnt;
	stats.seq_error_cnt = mb->un.varRdLnk.primSeqErrCnt;
	stats.inval_tx_word_cnt = mb->un.varRdLnk.invalidXmitWord;
	stats.crc_error_cnt = mb->un.varRdLnk.crcCnt;
	stats.seq_timeout_cnt = mb->un.varRdLnk.primSeqTimeout;
	stats.elastic_overrun_cnt = mb->un.varRdLnk.elasticOverrun;
	stats.arb_timeout_cnt = mb->un.varRdLnk.arbTimeout;
	stats.rx_buf_credit = mb->un.varRdLnk.rxBufCredit;
	stats.rx_buf_cnt = mb->un.varRdLnk.rxBufCreditCur;
	stats.tx_buf_credit = mb->un.varRdLnk.txBufCredit;
	stats.tx_buf_cnt = mb->un.varRdLnk.txBufCreditCur;
	stats.EOFa_cnt = mb->un.varRdLnk.EOFaCnt;
	stats.EOFdti_cnt = mb->un.varRdLnk.EOFdtiCnt;
	stats.EOFni_cnt = mb->un.varRdLnk.EOFniCnt;
	stats.SOFf_cnt = mb->un.varRdLnk.SOFfCnt;
	stats.link_event_tag = hba->link_event_tag;
	stats.last_reset_time = hba->timer_tics - hba->stats.ResetTime;
	stats.port_type = HBA_PORTTYPE_UNKNOWN;

#ifdef MENLO_SUPPORT
	if (hba->flag & FC_MENLO_MODE) {
		stats.topology = LNK_MENLO_MAINTENANCE;
	} else
#endif /* MENLO_SUPPORT */

	if (hba->state >= FC_LINK_UP) {
		if (hba->topology == TOPOLOGY_LOOP) {
			if (hba->flag & FC_FABRIC_ATTACHED) {
				stats.port_type = HBA_PORTTYPE_NLPORT;
				stats.topology = LNK_PUBLIC_LOOP;
			} else {
				stats.port_type = HBA_PORTTYPE_LPORT;
				stats.topology = LNK_LOOP;
			}
		} else {
			if (hba->flag & FC_FABRIC_ATTACHED) {
				stats.port_type = HBA_PORTTYPE_NPORT;
				stats.topology = LNK_FABRIC;
			} else {
				stats.port_type = HBA_PORTTYPE_PTP;
				stats.topology = LNK_PT2PT;
			}
		}

		if (hba->linkspeed == LA_2GHZ_LINK) {
			stats.link_speed = HBA_PORTSPEED_2GBIT;
		} else if (hba->linkspeed == LA_4GHZ_LINK) {
			stats.link_speed = HBA_PORTSPEED_4GBIT;
		} else if (hba->linkspeed == LA_8GHZ_LINK) {
			stats.link_speed = HBA_PORTSPEED_8GBIT;
		} else if (hba->linkspeed == LA_10GHZ_LINK) {
			stats.link_speed = HBA_PORTSPEED_10GBIT;
		} else {
			stats.link_speed = HBA_PORTSPEED_1GBIT;
		}
	}

	if (ddi_copyout((void *)&stats, (void *)dfc->buf1,
	    sizeof (dfc_hbastats_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYOUT_ERROR);
	}

done:

	/* Free allocated mbox memory */
	if (mbq) {
		kmem_free(mbq, sizeof (MAILBOXQ));
	}

	return (rval);

} /* emlxs_dfc_get_hbastats() */



static int32_t
emlxs_dfc_get_drvstats(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	dfc_drvstats_t	stats;
	uint32_t	rval = 0;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s requested.",
	    emlxs_dfc_xlate(dfc->cmd));

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	bzero((void *) &stats, sizeof (dfc_drvstats_t));

	stats.LinkUp = hba->stats.LinkUp;
	stats.LinkDown = hba->stats.LinkDown;
	stats.LinkEvent = hba->stats.LinkEvent;
	stats.LinkMultiEvent = hba->stats.LinkMultiEvent;

	stats.MboxIssued = hba->stats.MboxIssued;
	stats.MboxCompleted = hba->stats.MboxCompleted;
	stats.MboxGood = hba->stats.MboxGood;
	stats.MboxError = hba->stats.MboxError;
	stats.MboxBusy = hba->stats.MboxBusy;
	stats.MboxInvalid = hba->stats.MboxInvalid;

	stats.IocbIssued[0] = hba->stats.IocbIssued[0];
	stats.IocbIssued[1] = hba->stats.IocbIssued[1];
	stats.IocbIssued[2] = hba->stats.IocbIssued[2];
	stats.IocbIssued[3] = hba->stats.IocbIssued[3];
	stats.IocbReceived[0] = hba->stats.IocbReceived[0];
	stats.IocbReceived[1] = hba->stats.IocbReceived[1];
	stats.IocbReceived[2] = hba->stats.IocbReceived[2];
	stats.IocbReceived[3] = hba->stats.IocbReceived[3];
	stats.IocbTxPut[0] = hba->stats.IocbTxPut[0];
	stats.IocbTxPut[1] = hba->stats.IocbTxPut[1];
	stats.IocbTxPut[2] = hba->stats.IocbTxPut[2];
	stats.IocbTxPut[3] = hba->stats.IocbTxPut[3];
	stats.IocbTxGet[0] = hba->stats.IocbTxGet[0];
	stats.IocbTxGet[1] = hba->stats.IocbTxGet[1];
	stats.IocbTxGet[2] = hba->stats.IocbTxGet[2];
	stats.IocbTxGet[3] = hba->stats.IocbTxGet[3];
	stats.IocbRingFull[0] = hba->stats.IocbRingFull[0];
	stats.IocbRingFull[1] = hba->stats.IocbRingFull[1];
	stats.IocbRingFull[2] = hba->stats.IocbRingFull[2];
	stats.IocbRingFull[3] = hba->stats.IocbRingFull[3];

	stats.IntrEvent[0] = hba->stats.IntrEvent[0];
	stats.IntrEvent[1] = hba->stats.IntrEvent[1];
	stats.IntrEvent[2] = hba->stats.IntrEvent[2];
	stats.IntrEvent[3] = hba->stats.IntrEvent[3];
	stats.IntrEvent[4] = hba->stats.IntrEvent[4];
	stats.IntrEvent[5] = hba->stats.IntrEvent[5];
	stats.IntrEvent[6] = hba->stats.IntrEvent[6];
	stats.IntrEvent[7] = hba->stats.IntrEvent[7];

	stats.FcpIssued = hba->stats.FcpIssued;
	stats.FcpCompleted = hba->stats.FcpCompleted;
	stats.FcpGood = hba->stats.FcpGood;
	stats.FcpError = hba->stats.FcpError;

	stats.FcpEvent = hba->stats.FcpEvent;
	stats.FcpStray = hba->stats.FcpStray;

	stats.ElsEvent = hba->stats.ElsEvent;
	stats.ElsStray = hba->stats.ElsStray;

	stats.ElsCmdIssued = hba->stats.ElsCmdIssued;
	stats.ElsCmdCompleted = hba->stats.ElsCmdCompleted;
	stats.ElsCmdGood = hba->stats.ElsCmdGood;
	stats.ElsCmdError = hba->stats.ElsCmdError;

	stats.ElsRspIssued = hba->stats.ElsRspIssued;
	stats.ElsRspCompleted = hba->stats.ElsRspCompleted;

	stats.ElsRcvEvent = hba->stats.ElsRcvEvent;
	stats.ElsRcvError = hba->stats.ElsRcvError;
	stats.ElsRcvDropped = hba->stats.ElsRcvDropped;
	stats.ElsCmdReceived = hba->stats.ElsCmdReceived;
	stats.ElsRscnReceived = hba->stats.ElsRscnReceived;
	stats.ElsPlogiReceived = hba->stats.ElsPlogiReceived;
	stats.ElsPrliReceived = hba->stats.ElsPrliReceived;
	stats.ElsPrloReceived = hba->stats.ElsPrloReceived;
	stats.ElsLogoReceived = hba->stats.ElsLogoReceived;
	stats.ElsAdiscReceived = hba->stats.ElsAdiscReceived;
	stats.ElsGenReceived = hba->stats.ElsGenReceived;

	stats.CtEvent = hba->stats.CtEvent;
	stats.CtStray = hba->stats.CtStray;

	stats.CtCmdIssued = hba->stats.CtCmdIssued;
	stats.CtCmdCompleted = hba->stats.CtCmdCompleted;
	stats.CtCmdGood = hba->stats.CtCmdGood;
	stats.CtCmdError = hba->stats.CtCmdError;

	stats.CtRspIssued = hba->stats.CtRspIssued;
	stats.CtRspCompleted = hba->stats.CtRspCompleted;

	stats.CtRcvEvent = hba->stats.CtRcvEvent;
	stats.CtRcvError = hba->stats.CtRcvError;
	stats.CtRcvDropped = hba->stats.CtRcvDropped;
	stats.CtCmdReceived = hba->stats.CtCmdReceived;

	stats.IpEvent = hba->stats.IpEvent;
	stats.IpStray = hba->stats.IpStray;

	stats.IpSeqIssued = hba->stats.IpSeqIssued;
	stats.IpSeqCompleted = hba->stats.IpSeqCompleted;
	stats.IpSeqGood = hba->stats.IpSeqGood;
	stats.IpSeqError = hba->stats.IpSeqError;

	stats.IpBcastIssued = hba->stats.IpBcastIssued;
	stats.IpBcastCompleted = hba->stats.IpBcastCompleted;
	stats.IpBcastGood = hba->stats.IpBcastGood;
	stats.IpBcastError = hba->stats.IpBcastError;

	stats.IpRcvEvent = hba->stats.IpRcvEvent;
	stats.IpDropped = hba->stats.IpDropped;
	stats.IpSeqReceived = hba->stats.IpSeqReceived;
	stats.IpBcastReceived = hba->stats.IpBcastReceived;

	stats.IpUbPosted = hba->stats.IpUbPosted;
	stats.ElsUbPosted = hba->stats.ElsUbPosted;
	stats.CtUbPosted = hba->stats.CtUbPosted;

#if (DFC_REV >= 2)
	stats.IocbThrottled   = hba->stats.IocbThrottled;
	stats.ElsAuthReceived = hba->stats.ElsAuthReceived;
#endif

	if (ddi_copyout((void *)&stats, (void *)dfc->buf1, dfc->buf1_size,
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYOUT_ERROR);
	}

	return (rval);

} /* emlxs_dfc_get_drvstats() */


extern uint32_t
emlxs_set_hba_mode(emlxs_hba_t *hba, uint32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	i;

	mutex_enter(&EMLXS_PORT_LOCK);

	/* Wait if adapter is in transition */
	i = 0;
	while ((hba->flag & (FC_ONLINING_MODE | FC_OFFLINING_MODE))) {
		if (i++ > 30) {
			break;
		}

		mutex_exit(&EMLXS_PORT_LOCK);
		delay(drv_usectohz(1000000));
		mutex_enter(&EMLXS_PORT_LOCK);
	}

	switch (mode) {
	case DDI_SHOW:
		break;

	case DDI_ONDI:
		if (hba->flag & FC_OFFLINE_MODE) {
			mutex_exit(&EMLXS_PORT_LOCK);
			(void) emlxs_online(hba);
			mutex_enter(&EMLXS_PORT_LOCK);
		}
		break;


		/* Killed + Restart state */
	case DDI_OFFDI:
		if (hba->flag & FC_ONLINE_MODE) {
			mutex_exit(&EMLXS_PORT_LOCK);

			(void) emlxs_offline(hba);

			/* Reset with restart */
			EMLXS_SLI_HBA_RESET(hba, 1, 1, 0);

			mutex_enter(&EMLXS_PORT_LOCK);
		} else if (hba->state < FC_INIT_START) {
			mutex_exit(&EMLXS_PORT_LOCK);

			/* Reset with restart */
			EMLXS_SLI_HBA_RESET(hba, 1, 1, 0);

			mutex_enter(&EMLXS_PORT_LOCK);
		}

		break;

		/* Killed + Reset state */
	case DDI_WARMDI:
		if (hba->flag & FC_ONLINE_MODE) {
			mutex_exit(&EMLXS_PORT_LOCK);

			(void) emlxs_offline(hba);

			/* Reset with no restart */
			EMLXS_SLI_HBA_RESET(hba, 0, 0, 0);

			mutex_enter(&EMLXS_PORT_LOCK);
		} else if (hba->state != FC_WARM_START) {
			mutex_exit(&EMLXS_PORT_LOCK);

			/* Reset with no restart */
			EMLXS_SLI_HBA_RESET(hba, 0, 0, 0);

			mutex_enter(&EMLXS_PORT_LOCK);
		}

		break;

		/* Killed */
	case DDI_DIAGDI:
		if (hba->flag & FC_ONLINE_MODE) {
			mutex_exit(&EMLXS_PORT_LOCK);

			(void) emlxs_offline(hba);

			mutex_enter(&EMLXS_PORT_LOCK);
		} else if (hba->state != FC_KILLED) {
			mutex_exit(&EMLXS_PORT_LOCK);

			EMLXS_SLI_HBA_KILL(hba);

			mutex_enter(&EMLXS_PORT_LOCK);
		}

		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "emlxs_set_hba_mode: Invalid mode. mode%x", mode);
	}

	/* Wait if adapter is in transition */
	i = 0;
	while ((hba->flag & (FC_ONLINING_MODE | FC_OFFLINING_MODE))) {
		if (i++ > 30) {
			break;
		}

		mutex_exit(&EMLXS_PORT_LOCK);
		delay(drv_usectohz(1000000));
		mutex_enter(&EMLXS_PORT_LOCK);
	}

	/* Return current state */
	if (hba->flag & FC_ONLINE_MODE) {
		mode = DDI_ONDI;
	} else if (hba->state == FC_KILLED) {
		mode = DDI_DIAGDI;
	} else if (hba->state == FC_WARM_START) {
		mode = DDI_WARMDI;
	} else {
		mode = DDI_OFFDI;
	}

	mutex_exit(&EMLXS_PORT_LOCK);

	return (mode);

} /* emlxs_set_hba_mode() */


static int32_t
emlxs_dfc_set_diag(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	int32_t		rval = 0;
	int32_t		flag;

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < sizeof (uint32_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	flag = emlxs_set_hba_mode(hba, dfc->flag);

	if (ddi_copyout((void *)&flag, (void *)dfc->buf1, sizeof (uint32_t),
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYOUT_ERROR);
	}

	return (rval);

} /* emlxs_dfc_set_diag() */



static int32_t
emlxs_dfc_send_mbox(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port  = &PPORT;
	MAILBOX		*mb    = NULL;
	MAILBOXQ	*mbq   = NULL;
	uint32_t	size  = 0;
	MATCHMAP	*rx_mp = NULL;
	MATCHMAP	*tx_mp = NULL;
	uintptr_t	lptr;
	int32_t		rval  = 0;
	int32_t		mbxstatus = 0;
	NODELIST	*ndlp;
	uint32_t	did;
	uint32_t	extsize = 0;
	uint8_t		*extbuf  = NULL;

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (!dfc->buf2 || !dfc->buf2_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer2 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size > MAILBOX_CMD_BSIZE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too large. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOBIG);
	}
#ifdef MBOX_EXT_SUPPORT
	if (dfc->buf3_size || dfc->buf4_size) {
		if (dfc->buf3_size && !dfc->buf3) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Null buffer3 found.",
			    emlxs_dfc_xlate(dfc->cmd));

			return (DFC_ARG_NULL);
		}

		if (dfc->buf3_size > MBOX_EXTENSION_SIZE) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: buffer3 too large. (size=%d)",
			    emlxs_dfc_xlate(dfc->cmd), dfc->buf3_size);

			return (DFC_ARG_TOOBIG);
		}

		if (dfc->buf4_size && !dfc->buf4) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Null buffer4 found.",
			    emlxs_dfc_xlate(dfc->cmd));

			return (DFC_ARG_NULL);
		}

		if (dfc->buf4_size > MBOX_EXTENSION_SIZE) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: buffer4 too large. (size=%d)",
			    emlxs_dfc_xlate(dfc->cmd), dfc->buf3_size);

			return (DFC_ARG_TOOBIG);
		}

		extsize =
		    (dfc->buf3_size >
		    dfc->buf4_size) ? dfc->buf3_size : dfc->buf4_size;
		extbuf =
		    (uint8_t *)kmem_zalloc(extsize, KM_SLEEP);

		if (dfc->buf3_size) {
			if (ddi_copyin((void *)dfc->buf3, (void *)extbuf,
			    dfc->buf3_size, mode) != 0) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_dfc_error_msg,
				    "%s: ddi_copyin mbox extension data "
				    "failed.", emlxs_dfc_xlate(dfc->cmd));

				rval = DFC_COPYIN_ERROR;
				goto done;
			}
		}
	}
#endif /* MBOX_EXT_SUPPORT */

	mbq =
	    (MAILBOXQ *)kmem_zalloc(sizeof (MAILBOXQ), KM_SLEEP);

	mb = (MAILBOX *) mbq;

	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	if (ddi_copyin((void *)dfc->buf1, (void *)mb, dfc->buf1_size,
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYIN_ERROR;
		goto done;
	}
#ifdef _LP64
	if ((mb->mbxCommand == MBX_READ_SPARM) ||
	    (mb->mbxCommand == MBX_READ_RPI) ||
	    (mb->mbxCommand == MBX_REG_LOGIN) ||
	    (mb->mbxCommand == MBX_READ_LA) ||
	    (mb->mbxCommand == MBX_RUN_BIU_DIAG)) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Invalid mailbox command. Must use 64bit version. "
		    "cmd=%x", emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

		/* Must use 64 bit versions of these mbox cmds */
		rval = DFC_ARG_INVALID;
		goto done;
	}
#endif

	lptr = 0;
	size = 0;
	switch (mb->mbxCommand) {
	/* Offline only */
	case MBX_CONFIG_LINK:	/* 0x07 */
	case MBX_PART_SLIM:	    /* 0x08 */
	case MBX_CONFIG_RING:	/* 0x09 */
	case MBX_DUMP_CONTEXT:	/* 0x18 */
	case MBX_RUN_DIAGS:	    /* 0x19 */
	case MBX_RESTART:	    /* 0x1A */
	case MBX_SET_MASK:	    /* 0x20 */
	case MBX_FLASH_WR_ULA:	/* 0x98 */
		if (!(hba->flag & FC_OFFLINE_MODE)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Adapter not offline. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_ONLINE_ERROR;
			goto done;
		}
		break;

	/* Online / Offline */
	case MBX_UNREG_LOGIN:	/* 0x14 */
		ndlp = emlxs_node_find_rpi(port, mb->un.varUnregLogin.rpi);

		if (ndlp) {
			did = ndlp->nlp_DID;

			/* remove it */
			emlxs_node_rm(port, ndlp);

			/*
			 * If we just unregistered the host node then
			 * clear the host DID
			 */
			if (did == port->did) {
				port->did = 0;
			}
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Node not found. cmd=%x rpi=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand,
			    mb->un.varUnregLogin.rpi);

			/* Node does not exist */
			rval = DFC_ARG_INVALID;
			goto done;
		}

		/* Send it */
		break;

	case MBX_UNREG_D_ID:	/* 0x23 */

		did = mb->un.varRegLogin.did;

		if (did == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Node not found. cmd=%x did=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand, did);

			rval = DFC_ARG_INVALID;
			goto done;
		}

		if (did == 0xffffffff) {
			emlxs_node_destroy_all(port);
			break;
		}

		/* Check for base node */
		if (did == BCAST_DID) {
			/* just flush base node */
			(void) emlxs_tx_node_flush(port, &port->node_base,
			    0, 0, 0);
			(void) emlxs_chipq_node_flush(port, 0, &port->node_base,
			    0);

			/* Return now */
			rval = 0;
			goto done;
		}

		/* Make sure the node does already exist */
		ndlp = emlxs_node_find_did(port, did);

		if (ndlp) {
			/* remove it */
			emlxs_node_rm(port, ndlp);

			/*
			 * If we just unregistered the host node then
			 * clear the host DID
			 */
			if (did == port->did) {
				port->did = 0;
			}
		} else {

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Node not found. cmd=%x did=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand, did);

			/* Node does not exist */
			rval = DFC_ARG_INVALID;
			goto done;
		}

		/* Send it */
		break;

	/* Online / Offline - with DMA */
	case MBX_READ_EVENT_LOG:	/* 0x38 */
		lptr =
		    (uintptr_t)PADDR(mb->un.varRdEvtLog.un.sp64.addrHigh,
		    mb->un.varRdEvtLog.un.sp64.addrLow);
		size = (int)mb->un.varRdEvtLog.un.sp64.tus.f.bdeSize;

		if (!lptr || !size || (size > MEM_BUF_SIZE)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Invalid BDE. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_ARG_INVALID;
			goto done;
		}

		/* Allocate receive buffer */
		if ((rx_mp = emlxs_mem_buf_alloc(hba, MEM_BUF_SIZE)) == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Unable to allocate receive buffer. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_DRVRES_ERROR;
			goto done;
		}

		mb->un.varRdEvtLog.un.sp64.addrHigh = PADDR_HI(rx_mp->phys);
		mb->un.varRdEvtLog.un.sp64.addrLow = PADDR_LO(rx_mp->phys);
		mb->un.varRdEvtLog.un.sp64.tus.f.bdeFlags = 0;

		break;

	case MBX_READ_SPARM:	/* 0x0D */
	case MBX_READ_SPARM64:	/* 0x8D */
		lptr =
		    (uintptr_t)PADDR(mb->un.varRdSparm.un.sp64.addrHigh,
		    mb->un.varRdSparm.un.sp64.addrLow);
		size = (int)mb->un.varRdSparm.un.sp64.tus.f.bdeSize;

		if (!lptr || !size || (size > MEM_BUF_SIZE)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Invalid BDE. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_ARG_INVALID;
			goto done;
		}

		/* Allocate receive buffer */
		if ((rx_mp = emlxs_mem_buf_alloc(hba, MEM_BUF_SIZE)) == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Unable to allocate receive buffer. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_DRVRES_ERROR;
			goto done;
		}

		mb->un.varRdSparm.un.sp64.addrHigh = PADDR_HI(rx_mp->phys);
		mb->un.varRdSparm.un.sp64.addrLow = PADDR_LO(rx_mp->phys);
		mb->un.varRdSparm.un.sp64.tus.f.bdeFlags = 0;

		break;

	case MBX_READ_RPI:	/* 0x0F */
	case MBX_READ_RPI64:	/* 0x8F */
		lptr =
		    (uintptr_t)PADDR(mb->un.varRdRPI.un.sp64.addrHigh,
		    mb->un.varRdRPI.un.sp64.addrLow);
		size = (int)mb->un.varRdRPI.un.sp64.tus.f.bdeSize;

		if (!lptr || !size || (size > MEM_BUF_SIZE)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Invalid BDE. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_ARG_INVALID;
			goto done;
		}

		/* Allocate receive buffer */
		if ((rx_mp = emlxs_mem_buf_alloc(hba, MEM_BUF_SIZE)) == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Unable to allocate receive buffer. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_DRVRES_ERROR;
			goto done;
		}

		mb->un.varRdRPI.un.sp64.addrHigh = PADDR_HI(rx_mp->phys);
		mb->un.varRdRPI.un.sp64.addrLow = PADDR_LO(rx_mp->phys);
		mb->un.varRdRPI.un.sp64.tus.f.bdeFlags = 0;

		break;

	case MBX_RUN_BIU_DIAG:	 /* 0x04 */
	case MBX_RUN_BIU_DIAG64: /* 0x84 */
		lptr =
		    (uintptr_t)PADDR(mb->un.varBIUdiag.un.s2.xmit_bde64.
		    addrHigh, mb->un.varBIUdiag.un.s2.xmit_bde64.addrLow);
		size = (int)mb->un.varBIUdiag.un.s2.xmit_bde64.tus.f.bdeSize;

		if (!lptr || !size || (size > MEM_BUF_SIZE)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Invalid xmit BDE. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_ARG_INVALID;
			goto done;
		}

		/* Allocate xmit buffer */
		if ((tx_mp = emlxs_mem_buf_alloc(hba, MEM_BUF_SIZE)) == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Unable to allocate xmit buffer. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_DRVRES_ERROR;
			goto done;
		}

		/* Initialize the xmit buffer */
		if (ddi_copyin((void *)lptr, (void *)tx_mp->virt, size,
		    mode) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: ddi_copyin failed. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_COPYIN_ERROR;
			goto done;
		}
		EMLXS_MPDATA_SYNC(tx_mp->dma_handle, 0, size,
		    DDI_DMA_SYNC_FORDEV);

		mb->un.varBIUdiag.un.s2.xmit_bde64.addrHigh =
		    PADDR_HI(tx_mp->phys);
		mb->un.varBIUdiag.un.s2.xmit_bde64.addrLow =
		    PADDR_LO(tx_mp->phys);
		mb->un.varBIUdiag.un.s2.xmit_bde64.tus.f.bdeFlags = 0;

		/* Initialize the receive buffer */
		lptr =
		    (uintptr_t)PADDR(mb->un.varBIUdiag.un.s2.rcv_bde64.
		    addrHigh, mb->un.varBIUdiag.un.s2.rcv_bde64.addrLow);
		size = (int)mb->un.varBIUdiag.un.s2.rcv_bde64.tus.f.bdeSize;

		if (!lptr || !size || (size > MEM_BUF_SIZE)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Invalid rcv BDE. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_ARG_INVALID;
			goto done;
		}

		/* Allocate receive buffer */
		if ((rx_mp = emlxs_mem_buf_alloc(hba, MEM_BUF_SIZE)) == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Unable to allocate receive buffer. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_DRVRES_ERROR;
			goto done;
		}

		mb->un.varBIUdiag.un.s2.rcv_bde64.addrHigh =
		    PADDR_HI(rx_mp->phys);
		mb->un.varBIUdiag.un.s2.rcv_bde64.addrLow =
		    PADDR_LO(rx_mp->phys);
		mb->un.varBIUdiag.un.s2.rcv_bde64.tus.f.bdeFlags = 0;

		break;

	case MBX_REG_LOGIN:	/* 0x13 */
	case MBX_REG_LOGIN64:	/* 0x93 */

		did = mb->un.varRegLogin.did;

		/* Check for invalid node ids to register */
		if (did == 0 || (did & 0xff000000)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Invalid node id. cmd=%x did=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand, did);

			rval = DFC_ARG_INVALID;
			goto done;
		}

		/* Check if the node limit has been reached */
		if (port->node_count >= hba->max_nodes) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Too many nodes. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_HBARES_ERROR;
			goto done;
		}

		lptr =
		    (uintptr_t)PADDR(mb->un.varRegLogin.un.sp64.addrHigh,
		    mb->un.varRegLogin.un.sp64.addrLow);
		size = (int)mb->un.varRegLogin.un.sp64.tus.f.bdeSize;

		if (!lptr || (size > MEM_BUF_SIZE)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Invalid BDE. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_ARG_INVALID;
			goto done;
		}

		/* Allocate xmit buffer */
		if ((tx_mp = emlxs_mem_buf_alloc(hba, MEM_BUF_SIZE)) == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Unable to allocate xmit buffer. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_DRVRES_ERROR;
			goto done;
		}

		/* Initialize the xmit buffer */
		if (ddi_copyin((void *)lptr, (void *)tx_mp->virt, size,
		    mode) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Unable to allocate xmit buffer. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_COPYIN_ERROR;
			goto done;
		}
		EMLXS_MPDATA_SYNC(tx_mp->dma_handle, 0, size,
		    DDI_DMA_SYNC_FORDEV);

		mb->un.varRegLogin.un.sp64.addrHigh = PADDR_HI(tx_mp->phys);
		mb->un.varRegLogin.un.sp64.addrLow = PADDR_LO(tx_mp->phys);
		mb->un.varRegLogin.un.sp64.tus.f.bdeFlags = 0;

		break;

	case MBX_READ_LA:	/* 0x15 */
	case MBX_READ_LA64:	/* 0x95 */
		lptr =
		    (uintptr_t)PADDR(mb->un.varReadLA.un.lilpBde64.
		    addrHigh, mb->un.varReadLA.un.lilpBde64.addrLow);
		size = (int)mb->un.varReadLA.un.lilpBde64.tus.f.bdeSize;

		if (!lptr || !size || (size > MEM_BUF_SIZE)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Invalid BDE. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_ARG_INVALID;
			goto done;
		}

		/* Allocate receive buffer */
		if ((rx_mp = emlxs_mem_buf_alloc(hba, MEM_BUF_SIZE)) == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Unable to allocate receive buffer. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_DRVRES_ERROR;
			goto done;
		}

		mb->un.varReadLA.un.lilpBde64.addrHigh =
		    PADDR_HI(rx_mp->phys);
		mb->un.varReadLA.un.lilpBde64.addrLow =
		    PADDR_LO(rx_mp->phys);
		mb->un.varReadLA.un.lilpBde64.tus.f.bdeFlags = 0;

		break;


		/* Do not allow these commands */
	case MBX_CONFIG_PORT:	/* 0x88 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Command not allowed. cmd=%x",
		    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

		rval = DFC_ARG_INVALID;
		goto done;


	/* Online / Offline */
	default:
		break;

	}	/* switch() */

	mb->mbxOwner = OWN_HOST;

	/* Set or don't set the PASSTHRU bit. */
	/* Setting will prevent the driver from processing it as its own */
	switch (mb->mbxCommand) {
	case MBX_REG_LOGIN:	/* 0x13 */
	case MBX_REG_LOGIN64:	/* 0x93 */
		break;

	default:
		mbq->flag |= MBQ_PASSTHRU;
	}

#ifdef MBOX_EXT_SUPPORT
	if (extbuf) {
		mbq->extbuf  = extbuf;
		mbq->extsize = extsize;
	}
#endif /* MBOX_EXT_SUPPORT */

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "%s: %s sent.  (%x %x %x %x)", emlxs_dfc_xlate(dfc->cmd),
	    emlxs_mb_cmd_xlate(mb->mbxCommand), mb->un.varWords[0],
	    mb->un.varWords[1], mb->un.varWords[2], mb->un.varWords[3]);

	/* issue the mbox cmd to the sli */
	mbxstatus = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0);

	if (mbxstatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: %s failed. mbxstatus=0x%x",
		    emlxs_dfc_xlate(dfc->cmd),
		    emlxs_mb_cmd_xlate(mb->mbxCommand), mbxstatus);

	}

	if (ddi_copyout((void *)mb, (void *)dfc->buf2, dfc->buf2_size,
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed. cmd=%x",
		    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

		rval = DFC_COPYOUT_ERROR;
		goto done;
	}

	if (rx_mp) {
		EMLXS_MPDATA_SYNC(rx_mp->dma_handle, 0, size,
		    DDI_DMA_SYNC_FORKERNEL);

		if (ddi_copyout((void *)rx_mp->virt, (void *)lptr, size,
		    mode) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: ddi_copyout failed for receive buffer. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

			rval = DFC_COPYOUT_ERROR;
			goto done;
		}
	}
#ifdef MBOX_EXT_SUPPORT
	/*  Any data needs to copy to mbox extension area */
	if (dfc->buf4_size) {
		if (ddi_copyout((void *)extbuf, (void *)dfc->buf4,
		    dfc->buf4_size, mode) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: ddi_copyout failed for mbox extension data.",
			    emlxs_dfc_xlate(dfc->cmd));

			rval = DFC_COPYIN_ERROR;
			goto done;
		}
	}
#endif /* MBOX_EXT_SUPPORT */

	rval = 0;

done:

	/* Free allocated mbox memory */
	if (extbuf) {
		kmem_free(extbuf, extsize);
	}

	/* Free allocated mbox memory */
	if (mbq) {
		kmem_free(mbq, sizeof (MAILBOXQ));
	}

	/* Free allocated mbuf memory */
	if (rx_mp) {
#ifdef FMA_SUPPORT
		if (!rval) {
			if (emlxs_fm_check_dma_handle(hba, rx_mp->dma_handle)
			    != DDI_FM_OK) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_invalid_dma_handle_msg,
				    "emlxs_dfc_send_mbox: hdl=%p",
				    rx_mp->dma_handle);
				rval = DFC_IO_ERROR;
			}
		}
#endif  /* FMA_SUPPORT */
		emlxs_mem_buf_free(hba, rx_mp);
	}

	if (tx_mp) {
#ifdef FMA_SUPPORT
		if (!rval) {
			if (emlxs_fm_check_dma_handle(hba, tx_mp->dma_handle)
			    != DDI_FM_OK) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_invalid_dma_handle_msg,
				    "emlxs_dfc_send_mbox: hdl=%p",
				    tx_mp->dma_handle);
				rval = DFC_IO_ERROR;
			}
		}
#endif  /* FMA_SUPPORT */
		emlxs_mem_buf_free(hba, tx_mp);
	}

	return (rval);

} /* emlxs_dfc_send_mbox() */


static int32_t
emlxs_dfc_read_pci(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	offset;
	uint32_t	cnt;
	uint32_t	outsz;
	uint32_t	i;
	uint32_t	*buffer;
	uint32_t	*bptr;
	uint32_t	value;
	uint32_t	size;
	uint32_t	max = 4096;

	offset = dfc->data1;
	cnt = dfc->data2;
	outsz = dfc->buf1_size;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "%s: offset=%x count=%d", emlxs_dfc_xlate(dfc->cmd), offset, cnt);

	if (!dfc->buf1_size || !dfc->buf1) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (offset & 0x3) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Offset misaligned. (offset=%d)",
		    emlxs_dfc_xlate(dfc->cmd), offset);

		return (DFC_ARG_MISALIGNED);
	}

	if (cnt & 0x3) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Count misaligned. (count=%d)",
		    emlxs_dfc_xlate(dfc->cmd), cnt);

		return (DFC_ARG_MISALIGNED);
	}

	if (outsz & 0x3) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Output size misaligned. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), outsz);

		return (DFC_ARG_MISALIGNED);
	}

	/* Get max PCI config range */
	if (hba->model_info.chip <= EMLXS_HELIOS_CHIP) {
		max = 256;
	} else {
		max = 4096;
	}

	if ((cnt + offset) > max) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Offset+Count too large. (offset=%d count=%d max=%d)",
		    emlxs_dfc_xlate(dfc->cmd), offset, cnt, max);

		return (DFC_ARG_TOOBIG);
	}

	if (outsz > max) {
		outsz = max;
	}

	if (cnt > outsz) {
		cnt = outsz;
	}

	size = cnt;

	if (!(buffer = (uint32_t *)kmem_zalloc(size, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to allocate buffer.",
		    emlxs_dfc_xlate(dfc->cmd));

		return (DFC_SYSRES_ERROR);
	}

	bptr = buffer;
	for (i = offset; i < (offset + cnt); i += 4) {
		value =
		    ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + i));
		*bptr++ = BE_SWAP32(value);
	}

	if (ddi_copyout((void *)buffer, (void *)dfc->buf1, outsz, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		kmem_free(buffer, size);
		return (DFC_COPYOUT_ERROR);
	}

	kmem_free(buffer, size);

#ifdef FMA_SUPPORT
	/* Access handle validation */
	if (emlxs_fm_check_acc_handle(hba, hba->pci_acc_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_access_handle_msg, NULL);
		return (DFC_DRV_ERROR);
	}
#endif  /* FMA_SUPPORT */

	return (0);

} /* emlxs_dfc_read_pci() */


static int32_t
emlxs_dfc_write_pci(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	offset;
	uint32_t	cnt;
	uint32_t	value;
	uint32_t	i;
	uint32_t	max;
	uint8_t		buffer[256];
	uint32_t	*bptr;
	uint16_t	word0;
	uint16_t	word1;

	offset = dfc->data1;
	cnt = dfc->data2;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "%s: offset=%x count=%d", emlxs_dfc_xlate(dfc->cmd), offset, cnt);

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (offset & 0x3) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Offset misaligned. (offset=%d)",
		    emlxs_dfc_xlate(dfc->cmd), offset);

		return (DFC_ARG_MISALIGNED);
	}

	if (cnt > dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Count too large. (count=%d)",
		    emlxs_dfc_xlate(dfc->cmd), cnt);

		return (DFC_ARG_TOOBIG);
	}

	if (cnt & 0x3) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Count misaligned. (count=%d)",
		    emlxs_dfc_xlate(dfc->cmd), cnt);

		return (DFC_ARG_MISALIGNED);
	}

	/* Get max PCI config range */
	if (hba->model_info.chip <= EMLXS_HELIOS_CHIP) {
		max = 256;
	} else {
		max = 4096;
	}

	if ((cnt + offset) > max) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Count+Offset too large. (offset=%d count=%d max=%d)",
		    emlxs_dfc_xlate(dfc->cmd), offset, cnt, max);

		return (DFC_ARG_TOOBIG);
	}

	bzero(buffer, sizeof (buffer));

	if (ddi_copyin((void *)dfc->buf1, (void *)buffer, cnt, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYIN_ERROR);
	}

	bptr = (uint32_t *)buffer;
	for (i = offset; i < (offset + cnt); i += 4) {
		value = *bptr++;
		value = BE_SWAP32(value);

		word0 = value & 0xFFFF;
		word1 = value >> 16;

		/*
		 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_debug_msg,
		 * "%s: Writing. offset=%x cnt=%d value=%08x %04x %04x",
		 * emlxs_dfc_xlate(dfc->cmd), i, value, word0, word1);
		 */

		/* word0 = PCIMEM_SHORT(word0); */
		ddi_put16(hba->pci_acc_handle,
		    (uint16_t *)(hba->pci_addr + i), (uint16_t)word0);

		/* word1 = PCIMEM_SHORT(word1); */
		ddi_put16(hba->pci_acc_handle,
		    (uint16_t *)(hba->pci_addr + i + 2), (uint16_t)word1);
	}

#ifdef FMA_SUPPORT
	/* Access handle validation */
	if (emlxs_fm_check_acc_handle(hba, hba->pci_acc_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_access_handle_msg, NULL);
		return (DFC_DRV_ERROR);
	}
#endif  /* FMA_SUPPORT */

	return (0);

} /* emlxs_dfc_write_pci() */


static int32_t
emlxs_dfc_get_cfg(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	dfc_cfgparam_t	*cfgparam;
	uint32_t	size;
	uint32_t	count;
	uint32_t	i;
	int32_t		rval = 0;
	emlxs_config_t	*cfg;

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	count = dfc->buf1_size / sizeof (dfc_cfgparam_t);

	if (count > MAX_CFG_PARAM) {
		count = MAX_CFG_PARAM;
	}

	if (count > NUM_CFG_PARAM) {
		count = NUM_CFG_PARAM;
	}

	size = count * sizeof (dfc_cfgparam_t);

	if (!(cfgparam = (dfc_cfgparam_t *)kmem_zalloc(size, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to allocate cfgparm buffer.",
		    emlxs_dfc_xlate(dfc->cmd));

		return (DFC_SYSRES_ERROR);
	}

	cfg = &CFG;
	for (i = 0; i < count; i++) {
		(void) strncpy(cfgparam[i].a_string, cfg[i].string,
		    sizeof (cfgparam[i].a_string));
		cfgparam[i].a_low = cfg[i].low;
		cfgparam[i].a_hi = cfg[i].hi;
		cfgparam[i].a_default = cfg[i].def;
		cfgparam[i].a_current = cfg[i].current;

		if (!(cfg[i].flags & PARM_HIDDEN)) {
			cfgparam[i].a_flag |= CFG_EXPORT;
		}
		cfgparam[i].a_flag |= CFG_COMMON;

		/* Adjust a_flag based on the hba model */
		switch (i) {
			case CFG_NETWORK_ON:
			case CFG_TOPOLOGY:
			case CFG_LINK_SPEED:
			case CFG_CR_DELAY:
			case CFG_CR_COUNT:
#ifdef SFCT_SUPPORT
			case CFG_TARGET_MODE:
#endif /* SFCT_SUPPORT */
			if (!(hba->model_info.flags & EMLXS_FCOE_SUPPORTED)) {
				cfgparam[i].a_flag |= CFG_APPLICABLE;
			}
			break;

			case CFG_NUM_WQ:
			if (hba->model_info.flags & EMLXS_FCOE_SUPPORTED) {
				cfgparam[i].a_flag |= CFG_APPLICABLE;
			}
			break;

			case CFG_PERSIST_LINKDOWN:
			cfgparam[i].a_flag &= ~CFG_EXPORT;
			break;

			default:
			cfgparam[i].a_flag |= CFG_APPLICABLE;
			break;
		}

		if ((cfg[i].flags & PARM_DYNAMIC)) {
			if ((cfg[i].flags & PARM_DYNAMIC_RESET) ==
			    PARM_DYNAMIC_RESET) {
				cfgparam[i].a_changestate = CFG_RESTART;
			} else if ((cfg[i].flags & PARM_DYNAMIC_LINK) ==
			    PARM_DYNAMIC_LINK) {
				cfgparam[i].a_changestate = CFG_LINKRESET;
			} else {
				cfgparam[i].a_changestate = CFG_DYMANIC;
			}
		} else {
			cfgparam[i].a_changestate = CFG_REBOOT;
		}

		(void) strncpy(cfgparam[i].a_help, cfg[i].help,
		    sizeof (cfgparam[i].a_help));
	}

	if (ddi_copyout((void *)cfgparam, (void *)dfc->buf1, size, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYOUT_ERROR;
	}

	rval = 0;

	kmem_free(cfgparam, size);

	return (rval);

} /* emlxs_dfc_get_cfg() */


/* ARGSUSED */
static int32_t
emlxs_dfc_set_cfg(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	index;
	uint32_t	new_value;
	uint32_t	rc;

	index = dfc->data1;
	new_value = dfc->data2;

	rc = emlxs_set_parm(hba, index, new_value);

	if (rc) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to set parameter. code=%d",
		    emlxs_dfc_xlate(dfc->cmd), rc);

		switch (rc) {
		case 2:
			return (DFC_NPIV_ACTIVE);

		default:
			return (DFC_ARG_INVALID);
		}
	}

	return (0);

} /* emlxs_dfc_set_cfg() */


static int32_t
emlxs_dfc_send_ct(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint8_t		*rsp_buf;
	uint8_t		*cmd_buf;
	uint32_t	did;
	uint32_t	rsp_size;
	uint32_t	cmd_size;
	uint32_t	timeout;
	fc_packet_t	*pkt = NULL;
	uint32_t	rval = 0;
	dfc_destid_t	destid;
	NODELIST	*nlp;
	char		buffer[128];

	cmd_buf = dfc->buf1;
	cmd_size = dfc->buf1_size;
	rsp_buf = dfc->buf2;
	rsp_size = dfc->buf2_size;
	timeout = dfc->data1;

	if (timeout < (2 * hba->fc_ratov)) {
		timeout = 2 * hba->fc_ratov;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "%s: csize=%d rsize=%d", emlxs_dfc_xlate(dfc->cmd), cmd_size,
	    rsp_size);


	if (!cmd_size || !cmd_buf) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	if (!rsp_size || !rsp_buf) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer2 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	if (!dfc->buf3 || !dfc->buf3_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer3 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	if (!dfc->buf4 || !dfc->buf4_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer4 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	if (rsp_size > MAX_CT_PAYLOAD) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer2 too large. size=%d",
		    emlxs_dfc_xlate(dfc->cmd), rsp_size);

		rval = DFC_ARG_TOOBIG;
		goto done;
	}

	if (cmd_size > MAX_CT_PAYLOAD) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too large. size=%d",
		    emlxs_dfc_xlate(dfc->cmd), cmd_size);

		rval = DFC_ARG_TOOBIG;
		goto done;
	}

	if (dfc->buf3_size < sizeof (dfc_destid_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer3 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf3_size);

		rval = DFC_ARG_TOOSMALL;
		goto done;
	}

	if (dfc->buf4_size < sizeof (uint32_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer4 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf4_size);

		rval = DFC_ARG_TOOSMALL;
		goto done;
	}

	if (ddi_copyin((void *)dfc->buf3, (void *)&destid,
	    sizeof (dfc_destid_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to read destination id.",
		    emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYIN_ERROR;
		goto done;
	}

	if (destid.idType == 0) {
		if ((nlp = emlxs_node_find_wwpn(port, destid.wwpn)) == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: WWPN does not exists. %s",
			    emlxs_dfc_xlate(dfc->cmd), emlxs_wwn_xlate(buffer,
			    destid.wwpn));

			rval = DFC_ARG_INVALID;
			goto done;
		}
		did = nlp->nlp_DID;
	} else {
		if (emlxs_node_find_did(port, destid.d_id) == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: DID does not exist. did=%x",
			    emlxs_dfc_xlate(dfc->cmd), destid.d_id);

			rval = DFC_ARG_INVALID;
			goto done;
		}
		did = destid.d_id;
	}

	if (did == 0) {
		did = port->did;
	}

	if (!(pkt = emlxs_pkt_alloc(port, cmd_size, rsp_size, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to allocate packet.",
		    emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_SYSRES_ERROR;
		goto done;
	}

	/* Make this a polled IO */
	pkt->pkt_tran_flags &= ~FC_TRAN_INTR;
	pkt->pkt_tran_flags |= FC_TRAN_NO_INTR;
	pkt->pkt_comp = NULL;

	pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	pkt->pkt_timeout = (timeout) ? timeout : 30;

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(did);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_UNSOL_CONTROL;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(port->did);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_FC_SERVICES;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_FIRST_SEQ | F_CTL_END_SEQ | F_CTL_SEQ_INITIATIVE;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.rx_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* Copy in the command buffer */
	if (ddi_copyin((void *)cmd_buf, (void *)pkt->pkt_cmd, cmd_size,
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to read command buffer.",
		    emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYIN_ERROR;
		goto done;
	}

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to send packet.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_IO_ERROR;
		goto done;
	}

	if ((pkt->pkt_state != FC_PKT_SUCCESS) &&
	    (pkt->pkt_state != FC_PKT_FS_RJT)) {
		if (pkt->pkt_state == FC_PKT_TIMEOUT) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "Pkt Transport error. Pkt Timeout.");
			rval = DFC_TIMEOUT;
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "Pkt Transport error. state=%x", pkt->pkt_state);
			rval = DFC_IO_ERROR;
		}
		goto done;
	}

	if (ddi_copyout((void *)pkt->pkt_resp, (void *)rsp_buf, rsp_size,
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to read response.",
		    emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYOUT_ERROR;
		goto done;
	}

	rsp_size -= pkt->pkt_resp_resid;
	if (ddi_copyout((void *)&rsp_size, (void *)dfc->buf4, dfc->buf4_size,
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to write response.",
		    emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYOUT_ERROR;
		goto done;
	}

	rval = 0;

done:

	if (pkt) {
		emlxs_pkt_free(pkt);
	}

	return (rval);

} /* emlxs_dfc_send_ct() */


static int32_t
emlxs_dfc_send_ct_rsp(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint8_t		*cmd_buf;
	uint32_t	rx_id;
	uint32_t	cmd_size;
	uint32_t	timeout;
	fc_packet_t	*pkt = NULL;
	uint32_t	rval = 0;

	cmd_buf = dfc->buf1;
	cmd_size = dfc->buf1_size;
	rx_id = dfc->flag;
	timeout = 2 * hba->fc_ratov;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s: csize=%d",
	    emlxs_dfc_xlate(dfc->cmd), cmd_size);

	if (!cmd_size || !cmd_buf) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	if (!(pkt = emlxs_pkt_alloc(port, cmd_size, 0, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to allocate packet.",
		    emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_SYSRES_ERROR;
		goto done;
	}

	/* Make this a polled IO */
	pkt->pkt_tran_flags &= ~FC_TRAN_INTR;
	pkt->pkt_tran_flags |= FC_TRAN_NO_INTR;
	pkt->pkt_comp = NULL;

	pkt->pkt_tran_type = FC_PKT_OUTBOUND;
	pkt->pkt_timeout = (timeout) ? timeout : 30;

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(0);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_SOLICITED_CONTROL;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(port->did);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_FC_SERVICES;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_LAST_SEQ | F_CTL_END_SEQ | F_CTL_XCHG_CONTEXT;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xffff;
	pkt->pkt_cmd_fhdr.rx_id = rx_id;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* Copy in the command buffer */
	if (ddi_copyin((void *)cmd_buf, (void *)pkt->pkt_cmd, cmd_size,
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to read command buffer.",
		    emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYIN_ERROR;
		goto done;
	}

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to send packet.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_IO_ERROR;
		goto done;
	}

	if (pkt->pkt_state != FC_PKT_SUCCESS) {
		if (pkt->pkt_state == FC_PKT_TIMEOUT) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "Pkt Transport error. Pkt Timeout.");
			rval = DFC_TIMEOUT;
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "Pkt Transport error. state=%x", pkt->pkt_state);
			rval = DFC_IO_ERROR;
		}
		goto done;
	}

	rval = 0;

done:

	if (pkt) {
		emlxs_pkt_free(pkt);
	}

	return (rval);

} /* emlxs_dfc_send_ct_rsp() */


#ifdef MENLO_SUPPORT

static int32_t
emlxs_dfc_send_menlo(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint8_t		*rsp_buf = NULL;
	uint8_t		*cmd_buf = NULL;
	uint32_t	rsp_size = 0;
	uint32_t	cmd_size = 0;
	uint32_t	rval = 0;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "%s: csize=%d rsize=%d", emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size,
	    dfc->buf2_size);

	if (hba->model_info.device_id != PCI_DEVICE_ID_LP21000_M) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Menlo device not present. device=%x,%x",
		    emlxs_dfc_xlate(dfc->cmd), hba->model_info.device_id,
		    hba->model_info.ssdid);

		rval = DFC_INVALID_ADAPTER;
		goto done;
	}

	if (!dfc->buf1_size || !dfc->buf1) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	if (!dfc->buf2_size || !dfc->buf2) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer2 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	if (!dfc->buf3 || !dfc->buf3_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer3 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	if (dfc->buf3_size < sizeof (uint32_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer3 too small. %d < %d",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf3_size,
		    sizeof (uint32_t));

		rval = DFC_ARG_TOOSMALL;
		goto done;
	}

	cmd_size  = dfc->buf1_size;
	cmd_buf = (uint8_t *)kmem_zalloc(cmd_size,
	    KM_SLEEP);

	rsp_size  = dfc->buf2_size;
	rsp_buf = (uint8_t *)kmem_zalloc(rsp_size,
	    KM_SLEEP);

	/* Read the command buffer */
	if (ddi_copyin((void *)dfc->buf1, (void *)cmd_buf,
	    cmd_size, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg,
		    "%s: Unable to read command buffer.",
		    emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYIN_ERROR;
		goto done;
	}

	/* Send the command */
	rval = emlxs_send_menlo_cmd(hba, cmd_buf, cmd_size,
	    rsp_buf, &rsp_size);

	if (rval == 0) {
		/* Return the response */
		if (ddi_copyout((void *)rsp_buf, (void *)dfc->buf2,
		    rsp_size, mode) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Unable to write response.",
			    emlxs_dfc_xlate(dfc->cmd));

			rval = DFC_COPYOUT_ERROR;
			goto done;
		}

		/* Return the response size */
		if (ddi_copyout((void *)&rsp_size, (void *)dfc->buf3,
		    dfc->buf3_size, mode) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Unable to write response size.",
			    emlxs_dfc_xlate(dfc->cmd));

			rval = DFC_COPYOUT_ERROR;
			goto done;
		}
	}

done:

	if (cmd_buf) {
		kmem_free(cmd_buf, dfc->buf1_size);
	}

	if (rsp_buf) {
		kmem_free(rsp_buf, dfc->buf2_size);
	}

	return (rval);

} /* emlxs_dfc_send_menlo() */


extern int32_t
emlxs_send_menlo_cmd(emlxs_hba_t *hba, uint8_t *cmd_buf, uint32_t cmd_size,
    uint8_t *rsp_buf, uint32_t *rsp_size)
{
	emlxs_port_t		*port = &PPORT;
	uint8_t			*data_buf = NULL;
	uint32_t		data_size = 0;
	fc_packet_t		*pkt = NULL;
	int32_t			rval = 0;
	menlo_set_cmd_t		set_cmd;
	menlo_reset_cmd_t	reset_cmd;
	uint32_t		rsp_code;
	uint32_t		mm_mode = 0;
	uint32_t		cmd_code;
	clock_t			timeout;
	MAILBOXQ		*mbq = NULL;
	MAILBOX			*mb;
	uint32_t		addr;
	uint32_t		value;
	uint32_t		mbxstatus;

	cmd_code = *(uint32_t *)cmd_buf;
	cmd_code = BE_SWAP32(cmd_code);

	/* Look for Zephyr specific commands */
	if (cmd_code & 0x80000000) {
		bzero((uint8_t *)&reset_cmd, sizeof (menlo_reset_cmd_t));
		bzero((uint8_t *)&set_cmd, sizeof (menlo_set_cmd_t));
		bzero((uint8_t *)&rsp_code, sizeof (uint32_t));

		/* Validate response buffer */
		if (*rsp_size < sizeof (uint32_t)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "emlxs_send_menlo_cmd: Response overrun.");
			rval = DFC_RSP_BUF_OVERRUN;
			goto done;
		}

		/* All of these responses will be 4 bytes only */
		*rsp_size = sizeof (uint32_t);
		rsp_code = 0;

		/* Validate command buffer */
		switch (cmd_code) {
		case MENLO_CMD_RESET:
			if (cmd_size < sizeof (menlo_reset_cmd_t)) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_dfc_error_msg,
				    "emlxs_send_menlo_cmd: "
				    "Invalid command size. %d < %d",
				    cmd_size,
				    sizeof (menlo_reset_cmd_t));
				rval = DFC_ARG_INVALID;
				goto done;
			}
			cmd_size = sizeof (menlo_reset_cmd_t);

			/* Read the command buffer */
			bcopy((void *)cmd_buf, (void *)&reset_cmd, cmd_size);

			if (reset_cmd.firmware) {
				/* MENLO_FW_GOLDEN */
				value = 1;

				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_dfc_detail_msg,
				    "emlxs_send_menlo_cmd: Reset with Golden "
				    "firmware requested.");

			} else {
				/* MENLO_FW_OPERATIONAL */
				value = 0;

				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_dfc_detail_msg,
				    "emlxs_send_menlo_cmd: Reset with "
				    "Operational firmware requested.");
			}

			addr  = 0x103007;

			break;

		case MENLO_CMD_SET_MODE:
			if (cmd_size < sizeof (menlo_set_cmd_t)) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_dfc_error_msg,
				    "emlxs_send_menlo_cmd: "
				    "Invalid command size. %d < %d",
				    cmd_size,
				    sizeof (menlo_set_cmd_t));
				rval = DFC_ARG_INVALID;
				goto done;
			}
			cmd_size = sizeof (menlo_set_cmd_t);

			/* Read the command buffer */
			bcopy((void *)cmd_buf, (void *)&set_cmd, cmd_size);

			if (set_cmd.value1) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_dfc_detail_msg,
				    "emlxs_send_menlo_cmd: "
				    "Maintenance mode enable requested.");

				/* Make sure the mode flag is cleared */
				if (hba->flag & FC_MENLO_MODE) {
					mutex_enter(&EMLXS_PORT_LOCK);
					hba->flag &= ~FC_MENLO_MODE;
					mutex_exit(&EMLXS_PORT_LOCK);
				}

				mm_mode = 1;
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_dfc_detail_msg,
				    "emlxs_send_menlo_cmd: "
				    "Maintenance mode disable requested.");
			}

			addr  = 0x103107;
			value = mm_mode;

			break;

		default:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "emlxs_send_menlo_cmd: "
			    "Invalid command. cmd=%x", cmd_code);
			rval = DFC_ARG_INVALID;
			goto done;
		}

		mbq = (MAILBOXQ *)kmem_zalloc(sizeof (MAILBOXQ),
		    KM_SLEEP);

		mb = (MAILBOX *) mbq;

		/* Create the set_variable mailbox request */
		emlxs_mb_set_var(hba, mbq, addr, value);

		mbq->flag |= MBQ_PASSTHRU;

		/* issue the mbox cmd to the sli */
		mbxstatus = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0);

		if (mbxstatus) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "emlxs_send_menlo_cmd: %s failed. mbxstatus=0x%x",
			    emlxs_mb_cmd_xlate(mb->mbxCommand), mbxstatus);

			if (mbxstatus == MBX_TIMEOUT) {
				rval = DFC_TIMEOUT;
			} else {
				rval = DFC_IO_ERROR;
			}
			goto done;
		}

		bcopy((void *)&rsp_code, (void *)rsp_buf, *rsp_size);

		/* Check if we need to wait for maintenance mode */
		if (mm_mode && !(hba->flag & FC_MENLO_MODE)) {
			/* Wait for link to come up in maintenance mode */
			mutex_enter(&EMLXS_LINKUP_LOCK);

			timeout = emlxs_timeout(hba, 30);

			rval = 0;
			while ((rval != -1) && !(hba->flag & FC_MENLO_MODE)) {
				rval =
				    cv_timedwait(&EMLXS_LINKUP_CV,
				    &EMLXS_LINKUP_LOCK, timeout);
			}

			mutex_exit(&EMLXS_LINKUP_LOCK);

			if (rval == -1) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_dfc_error_msg,
				    "emlxs_send_menlo_cmd: "
				    "Menlo maintenance mode error. Timeout.");

				rval = DFC_TIMEOUT;
				goto done;
			}
		}
	} else {	/* Standard commands */

		if (hba->state <= FC_LINK_DOWN) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "emlxs_send_menlo_cmd: Adapter link down.");

			rval = DFC_LINKDOWN_ERROR;
			goto done;
		}

		if (cmd_code == MENLO_CMD_FW_DOWNLOAD) {
			/* Check cmd size */
			/* Must be at least 12 bytes of command */
			/* plus 4 bytes of data */
			if (cmd_size < (12 + 4)) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_dfc_error_msg,
				    "emlxs_send_menlo_cmd: "
				    "Invalid command size. %d < %d",
				    cmd_size,
				    (12 + 4));

				rval = DFC_ARG_INVALID;
				goto done;
			}

			/* Extract data buffer from command buffer */
			data_buf    = cmd_buf  + 12;
			data_size   = cmd_size - 12;
			cmd_size    = 12;
		}

		if (!(pkt = emlxs_pkt_alloc(port, cmd_size, *rsp_size, 0,
		    KM_NOSLEEP))) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "emlxs_send_menlo_cmd: Unable to allocate packet.");

			rval = DFC_SYSRES_ERROR;
			goto done;
		}

		/* Make this a polled IO */
		pkt->pkt_tran_flags &= ~FC_TRAN_INTR;
		pkt->pkt_tran_flags |= FC_TRAN_NO_INTR;
		pkt->pkt_comp = NULL;
		pkt->pkt_tran_type = FC_PKT_EXCHANGE;
		pkt->pkt_timeout = 30;

		/* Build the fc header */
		pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(EMLXS_MENLO_DID);
		pkt->pkt_cmd_fhdr.r_ctl = R_CTL_COMMAND;
		pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(port->did);
		pkt->pkt_cmd_fhdr.type = EMLXS_MENLO_TYPE;
		pkt->pkt_cmd_fhdr.f_ctl =
		    F_CTL_FIRST_SEQ | F_CTL_END_SEQ | F_CTL_SEQ_INITIATIVE;
		pkt->pkt_cmd_fhdr.seq_id = 0;
		pkt->pkt_cmd_fhdr.df_ctl = 0;
		pkt->pkt_cmd_fhdr.seq_cnt = 0;
		pkt->pkt_cmd_fhdr.ox_id = 0xFFFF;
		pkt->pkt_cmd_fhdr.rx_id = 0xFFFF;
		pkt->pkt_cmd_fhdr.ro = 0;

		/* Copy in the command buffer */
		bcopy((void *)cmd_buf, (void *)pkt->pkt_cmd, cmd_size);

		if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "emlxs_send_menlo_cmd: Unable to send packet.");

			rval = DFC_IO_ERROR;
			goto done;
		}

		if (pkt->pkt_state != FC_PKT_SUCCESS) {
			if (pkt->pkt_state == FC_PKT_TIMEOUT) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_dfc_error_msg,
				    "emlxs_send_menlo_cmd: "
				    "Pkt Transport error. Pkt Timeout.");
				rval = DFC_TIMEOUT;
			} else if ((pkt->pkt_state == FC_PKT_LOCAL_RJT) &&
			    (pkt->pkt_reason == FC_REASON_OVERRUN)) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_dfc_error_msg,
				    "emlxs_send_menlo_cmd: "
				    "Pkt Transport error. Response overrun.");
				rval = DFC_RSP_BUF_OVERRUN;
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_dfc_error_msg,
				    "emlxs_send_menlo_cmd: "
				    "Pkt Transport error. state=%x",
				    pkt->pkt_state);
				rval = DFC_IO_ERROR;
			}
			goto done;
		}

		if (cmd_code == MENLO_CMD_FW_DOWNLOAD) {
			uint32_t *rsp;

			/* Check response code */
			rsp = (uint32_t *)pkt->pkt_resp;
			rsp_code = *rsp;
			rsp_code = BE_SWAP32(rsp_code);

			if (rsp_code == MENLO_RSP_SUCCESS) {
				/* Now transmit the data phase */

				/* Save last rx_id */
				uint32_t rx_id = pkt->pkt_cmd_fhdr.rx_id;

				/* Free old pkt */
				emlxs_pkt_free(pkt);

				/* Allocate data pkt */
				if (!(pkt = emlxs_pkt_alloc(port, data_size,
				    *rsp_size, 0, KM_NOSLEEP))) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_dfc_error_msg,
					    "emlxs_send_menlo_cmd: "
					    "Unable to allocate data "
					    "packet.");

					rval = DFC_SYSRES_ERROR;
					goto done;
				}

				/* Make this a polled IO */
				pkt->pkt_tran_flags &= ~FC_TRAN_INTR;
				pkt->pkt_tran_flags |= FC_TRAN_NO_INTR;
				pkt->pkt_comp = NULL;
				pkt->pkt_tran_type = FC_PKT_OUTBOUND;
				pkt->pkt_timeout = 30;

				/* Build the fc header */
				pkt->pkt_cmd_fhdr.d_id =
				    LE_SWAP24_LO(EMLXS_MENLO_DID);
				pkt->pkt_cmd_fhdr.r_ctl = R_CTL_COMMAND;
				pkt->pkt_cmd_fhdr.s_id =
				    LE_SWAP24_LO(port->did);
				pkt->pkt_cmd_fhdr.type = EMLXS_MENLO_TYPE;
				pkt->pkt_cmd_fhdr.f_ctl =
				    F_CTL_FIRST_SEQ | F_CTL_END_SEQ |
				    F_CTL_SEQ_INITIATIVE;
				pkt->pkt_cmd_fhdr.seq_id = 0;
				pkt->pkt_cmd_fhdr.df_ctl = 0;
				pkt->pkt_cmd_fhdr.seq_cnt = 0;
				pkt->pkt_cmd_fhdr.ox_id = 0xFFFF;
				pkt->pkt_cmd_fhdr.rx_id = rx_id;
				pkt->pkt_cmd_fhdr.ro = 0;

				/* Copy in the data buffer */
				bcopy((void *)data_buf, (void *)pkt->pkt_cmd,
				    data_size);

				if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_dfc_error_msg,
					    "emlxs_send_menlo_cmd: "
					    "Unable to send data packet.");

					rval = DFC_IO_ERROR;
					goto done;
				}

				if (pkt->pkt_state != FC_PKT_SUCCESS) {
					if (pkt->pkt_state == FC_PKT_TIMEOUT) {
						EMLXS_MSGF(EMLXS_CONTEXT,
						    &emlxs_dfc_error_msg,
						    "emlxs_send_menlo_cmd: "
						    "Data Pkt Transport "
						    "error. Pkt Timeout.");
						rval = DFC_TIMEOUT;
					} else if ((pkt->pkt_state ==
					    FC_PKT_LOCAL_RJT) &&
					    (pkt->pkt_reason ==
					    FC_REASON_OVERRUN)) {
						EMLXS_MSGF(EMLXS_CONTEXT,
						    &emlxs_dfc_error_msg,
						    "emlxs_send_menlo_cmd: "
						    "Data Pkt Transport "
						    "error. Response overrun.");
						rval = DFC_RSP_BUF_OVERRUN;
					} else {
						EMLXS_MSGF(EMLXS_CONTEXT,
						    &emlxs_dfc_error_msg,
						    "emlxs_send_menlo_cmd: "
						    "Data Pkt Transport "
						    "error. state=%x",
						    pkt->pkt_state);
						rval = DFC_IO_ERROR;
					}
					goto done;
				}
			}
		}

		bcopy((void *)pkt->pkt_resp, (void *)rsp_buf, *rsp_size);
		*rsp_size = *rsp_size - pkt->pkt_resp_resid;
	}

	rval = 0;

done:

	if (pkt) {
		emlxs_pkt_free(pkt);
	}

	if (mbq) {
		kmem_free(mbq, sizeof (MAILBOXQ));
	}

	return (rval);

} /* emlxs_send_menlo_cmd() */


/* ARGSUSED */
extern void
emlxs_fcoe_attention_thread(emlxs_hba_t *hba,
    void *arg1, void *arg2)
{
	emlxs_port_t		*port = &PPORT;
	menlo_init_rsp_t	*rsp;
	menlo_get_cmd_t		*cmd;
	fc_packet_t		*pkt = NULL;

	if (!(pkt = emlxs_pkt_alloc(port, sizeof (menlo_get_cmd_t),
	    sizeof (menlo_init_rsp_t), 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "FCoE attention: Unable to allocate packet.");

		return;
	}

	/* Make this a polled IO */
	pkt->pkt_tran_flags &= ~FC_TRAN_INTR;
	pkt->pkt_tran_flags |= FC_TRAN_NO_INTR;
	pkt->pkt_comp = NULL;
	pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	pkt->pkt_timeout = 30;

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(EMLXS_MENLO_DID);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_COMMAND;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(port->did);
	pkt->pkt_cmd_fhdr.type = EMLXS_MENLO_TYPE;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_FIRST_SEQ | F_CTL_END_SEQ | F_CTL_SEQ_INITIATIVE;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.rx_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.ro = 0;

	cmd = (menlo_get_cmd_t *)pkt->pkt_cmd;
	cmd->code = MENLO_CMD_GET_INIT;
	cmd->context = 0;
	cmd->length = sizeof (menlo_init_rsp_t);

	/* Little Endian Swap */
	cmd->code = BE_SWAP32(cmd->code);
	cmd->length = BE_SWAP32(cmd->length);

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "FCoE attention: Unable to send packet.");

		goto done;
	}

	if (pkt->pkt_state != FC_PKT_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "FCoE attention: Pkt Transport error. state=%x",
		    pkt->pkt_state);

		goto done;
	}

	/* Check response code */
	rsp = (menlo_init_rsp_t *)pkt->pkt_resp;
	rsp->code = BE_SWAP32(rsp->code);

	if (rsp->code != MENLO_RSP_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "FCoE attention: FCOE Response error =%x", rsp->code);

		goto done;
	}

	/* Little Endian Swap */
	rsp->bb_credit = BE_SWAP32(rsp->bb_credit);
	rsp->frame_size = BE_SWAP32(rsp->frame_size);
	rsp->fw_version = BE_SWAP32(rsp->fw_version);
	rsp->reset_status = BE_SWAP32(rsp->reset_status);
	rsp->maint_status = BE_SWAP32(rsp->maint_status);
	rsp->fw_type = BE_SWAP32(rsp->fw_type);
	rsp->fru_data_valid = BE_SWAP32(rsp->fru_data_valid);

	/* Log the event */
	emlxs_log_fcoe_event(port, rsp);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "MENLO_INIT: bb_credit      = 0x%x", rsp->bb_credit);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "MENLO_INIT: frame_size     = 0x%x", rsp->frame_size);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "MENLO_INIT: fw_version     = 0x%x", rsp->fw_version);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "MENLO_INIT: reset_status   = 0x%x", rsp->reset_status);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "MENLO_INIT: maint_status   = 0x%x", rsp->maint_status);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "MENLO_INIT: fw_type        = 0x%x", rsp->fw_type);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "MENLO_INIT: fru_data_valid = 0x%x", rsp->fru_data_valid);

	/* Perform attention checks */
	if (rsp->fru_data_valid == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_adapter_error_msg,
		    "Invalid FRU data found on adapter. "
		    "Return adapter to Emulex for repair.");
	}

	switch (rsp->fw_type) {
	case MENLO_FW_TYPE_GOLDEN:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_adapter_warning_msg,
		    "FCoE chip is running Golden firmware. "
		    "Update FCoE firmware immediately.");
		break;

	case MENLO_FW_TYPE_DIAG:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_adapter_notice_msg,
		    "FCoE chip is running Diagnostic firmware. "
		    "Operational use of the adapter is suspended.");
		break;
	}

done:

	if (pkt) {
		emlxs_pkt_free(pkt);
	}

	return;

} /* emlxs_fcoe_attention_thread() */

#endif /* MENLO_SUPPORT */


static int32_t
emlxs_dfc_write_flash(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	offset;
	uint32_t	cnt;
	uint8_t		*buffer;
	uint8_t		*bptr;
	uint32_t	i;

	if (hba->bus_type != SBUS_FC) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Invalid bus_type. (bus_type=%x)",
		    emlxs_dfc_xlate(dfc->cmd), hba->bus_type);

		return (DFC_ARG_INVALID);
	}

	if (!(hba->flag & FC_OFFLINE_MODE)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Adapter not offline.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ONLINE_ERROR);
	}

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	offset = dfc->data1;
	cnt = dfc->data2;

	if (offset > (64 * 1024)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Offset too large. (offset=%d)",
		    emlxs_dfc_xlate(dfc->cmd), offset);

		return (DFC_ARG_TOOBIG);
	}

	if (cnt > dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Count too large. (count=%d)",
		    emlxs_dfc_xlate(dfc->cmd), cnt);

		return (DFC_ARG_TOOBIG);
	}

	if ((cnt + offset) > (64 * 1024)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Count+Offset too large. (count=%d offset=%d)",
		    emlxs_dfc_xlate(dfc->cmd), cnt, offset);

		return (DFC_ARG_TOOBIG);
	}

	if (cnt == 0) {
		return (0);
	}

	if ((buffer = (uint8_t *)kmem_zalloc(cnt, KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to allocate buffer.",
		    emlxs_dfc_xlate(dfc->cmd));

		return (DFC_SYSRES_ERROR);
	}

	if (ddi_copyin((void *)dfc->buf1, (void *)buffer, cnt, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		kmem_free(buffer, cnt);
		return (DFC_COPYIN_ERROR);
	}

	bptr = buffer;
	for (i = 0; i < cnt; i++) {
		SBUS_WRITE_FLASH_COPY(hba, offset, *bptr);
		offset++;
		bptr++;
	}

	kmem_free(buffer, cnt);

#ifdef FMA_SUPPORT
	/* Access handle validation */
	if (emlxs_fm_check_acc_handle(hba, hba->sli.sli3.sbus_flash_acc_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_access_handle_msg, NULL);
		return (DFC_DRV_ERROR);
	}
#endif  /* FMA_SUPPORT */

	return (0);

} /* emlxs_dfc_write_flash() */


static int32_t
emlxs_dfc_read_flash(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	offset;
	uint32_t	count;
	uint32_t	outsz;
	uint8_t		*buffer;
	uint8_t		*bptr;
	uint32_t	i;

	if (hba->bus_type != SBUS_FC) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Invalid bus_type. (bus_type=%x)",
		    emlxs_dfc_xlate(dfc->cmd), hba->bus_type);

		return (DFC_ARG_INVALID);
	}

	if (!(hba->flag & FC_OFFLINE_MODE)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Adapter not offline.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ONLINE_ERROR);
	}

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	offset = dfc->data1;
	count = dfc->data2;
	outsz = dfc->buf1_size;

	if (offset > (64 * 1024)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Offset too large. (offset=%d)",
		    emlxs_dfc_xlate(dfc->cmd), offset);

		return (DFC_ARG_TOOBIG);
	}

	if ((count + offset) > (64 * 1024)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Count+Offset too large. (count=%d offset=%d)",
		    emlxs_dfc_xlate(dfc->cmd), count, offset);

		return (DFC_ARG_TOOBIG);
	}

	if (count < outsz) {
		outsz = count;
	}

	if ((buffer = (uint8_t *)kmem_zalloc(outsz, KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to allocate buffer.",
		    emlxs_dfc_xlate(dfc->cmd));

		return (DFC_SYSRES_ERROR);
	}

	bptr = buffer;
	for (i = 0; i < outsz; i++) {
		*bptr++ = SBUS_READ_FLASH_COPY(hba, offset++);
	}

	if (ddi_copyout((void *)buffer, (void *)dfc->buf1, outsz, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		kmem_free(buffer, outsz);
		return (DFC_COPYOUT_ERROR);
	}

	kmem_free(buffer, outsz);

#ifdef FMA_SUPPORT
	/* Access handle validation */
	if (emlxs_fm_check_acc_handle(hba, hba->sli.sli3.sbus_flash_acc_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_access_handle_msg, NULL);
		return (DFC_DRV_ERROR);
	}
#endif  /* FMA_SUPPORT */

	return (0);

} /* emlxs_dfc_read_flash() */


static int32_t
emlxs_dfc_send_els(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint8_t		*rsp_buf;
	uint8_t		*cmd_buf;
	dfc_destid_t	destid;
	uint32_t	rsp_size;
	uint32_t	cmd_size;
	uint32_t	timeout;
	fc_packet_t	*pkt = NULL;
	NODELIST	*ndlp;
	uint32_t	did;
	uint32_t	rval = 0;
	char		buffer[128];

	cmd_buf = dfc->buf1;
	cmd_size = dfc->buf1_size;
	rsp_buf = dfc->buf2;
	rsp_size = dfc->buf2_size;

	timeout = 2 * hba->fc_ratov;

	if (!cmd_size || !cmd_buf) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	if (!rsp_buf || !rsp_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer2 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	if (!dfc->buf3 || !dfc->buf3_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer3 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	if (dfc->buf3_size < sizeof (dfc_destid_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer3 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf3_size);

		rval = DFC_ARG_TOOSMALL;
		goto done;
	}

	if (!dfc->buf4 || !dfc->buf4_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer4 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	if (dfc->buf4_size < sizeof (uint32_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer4 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf4_size);

		rval = DFC_ARG_TOOSMALL;
		goto done;
	}

	if (ddi_copyin((void *)dfc->buf3, (void *)&destid,
	    sizeof (dfc_destid_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYIN_ERROR;
		goto done;
	}

	if (destid.idType == 0) {
		if ((ndlp = emlxs_node_find_wwpn(port, destid.wwpn)) == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: WWPN does not exists. %s",
			    emlxs_dfc_xlate(dfc->cmd), emlxs_wwn_xlate(buffer,
			    destid.wwpn));

			rval = DFC_ARG_INVALID;
			goto done;
		}
		did = ndlp->nlp_DID;
	} else {
		if (emlxs_node_find_did(port, destid.d_id) == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: DID does not exist. did=%x",
			    emlxs_dfc_xlate(dfc->cmd), destid.d_id);

			rval = DFC_ARG_INVALID;
			goto done;
		}
		did = destid.d_id;
	}

	if (did == 0) {
		did = port->did;
	}

	if (!(pkt = emlxs_pkt_alloc(port, cmd_size, rsp_size, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to allocate packet.",
		    emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_SYSRES_ERROR;
		goto done;
	}

	/* Make this a polled IO */
	pkt->pkt_tran_flags &= ~FC_TRAN_INTR;
	pkt->pkt_tran_flags |= FC_TRAN_NO_INTR;
	pkt->pkt_comp = NULL;

	pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	pkt->pkt_timeout = (timeout) ? timeout : 30;

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(did);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_ELS_REQ;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(port->did);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_FIRST_SEQ | F_CTL_END_SEQ | F_CTL_SEQ_INITIATIVE;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.rx_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* Copy in the command buffer */
	if (ddi_copyin((void *)cmd_buf, (void *)pkt->pkt_cmd, cmd_size,
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYIN_ERROR;
		goto done;
	}

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		rval = DFC_IO_ERROR;
		goto done;
	}

	if (pkt->pkt_state != FC_PKT_SUCCESS) {
		if (pkt->pkt_state == FC_PKT_TIMEOUT) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "Pkt Transport error. Pkt Timeout.");
			rval = DFC_TIMEOUT;
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "Pkt Transport error. state=%x", pkt->pkt_state);
			rval = DFC_IO_ERROR;
		}
		goto done;
	}

	rsp_size -= pkt->pkt_resp_resid;
	if (ddi_copyout((void *)pkt->pkt_resp, (void *)rsp_buf, rsp_size,
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: rsp_buf ddi_copyout failed.",
		    emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYOUT_ERROR;
		goto done;
	}

	if (ddi_copyout((void *)&rsp_size, (void *)dfc->buf4,
	    sizeof (uint32_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: rsp_size ddi_copyout failed.",
		    emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYOUT_ERROR;
		goto done;
	}

	rval = 0;

done:
	if (pkt) {
		emlxs_pkt_free(pkt);
	}

	return (rval);

} /* emlxs_dfc_send_els() */


static int32_t
emlxs_dfc_get_ioinfo(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	dfc_ioinfo_t	ioinfo;
	uint32_t	i;

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < sizeof (dfc_ioinfo_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	bzero(&ioinfo, sizeof (dfc_ioinfo_t));

	ioinfo.a_mboxCmd = HBASTATS.MboxIssued;
	ioinfo.a_mboxCmpl = HBASTATS.MboxCompleted;
	ioinfo.a_mboxErr = HBASTATS.MboxError;

	for (i = 0; i < hba->chan_count; i++) {
		ioinfo.a_iocbCmd += HBASTATS.IocbIssued[i];
		ioinfo.a_iocbRsp += HBASTATS.IocbReceived[i];
	}

	ioinfo.a_adapterIntr = HBASTATS.IntrEvent[0] + HBASTATS.IntrEvent[1] +
	    HBASTATS.IntrEvent[2] + HBASTATS.IntrEvent[3] +
	    HBASTATS.IntrEvent[4] + HBASTATS.IntrEvent[5] +
	    HBASTATS.IntrEvent[6] + HBASTATS.IntrEvent[7];

	ioinfo.a_fcpCmd = HBASTATS.FcpIssued;
	ioinfo.a_fcpCmpl = HBASTATS.FcpCompleted;
	ioinfo.a_fcpErr = HBASTATS.FcpCompleted - HBASTATS.FcpGood;

	ioinfo.a_seqXmit = HBASTATS.IpSeqIssued;
	ioinfo.a_seqRcv = HBASTATS.IpSeqReceived;
	ioinfo.a_seqXmitErr = HBASTATS.IpSeqCompleted - HBASTATS.IpSeqGood;

	ioinfo.a_bcastXmit = HBASTATS.IpBcastIssued;
	ioinfo.a_bcastRcv = HBASTATS.IpBcastReceived;

	ioinfo.a_elsXmit = HBASTATS.ElsCmdIssued;
	ioinfo.a_elsRcv = HBASTATS.ElsCmdReceived;
	ioinfo.a_elsXmitErr = HBASTATS.ElsCmdCompleted - HBASTATS.ElsCmdGood;

	ioinfo.a_RSCNRcv = HBASTATS.ElsRscnReceived;

	ioinfo.a_elsBufPost = HBASTATS.ElsUbPosted;
	ioinfo.a_ipBufPost = HBASTATS.IpUbPosted;

	ioinfo.a_cnt1 = 0;
	ioinfo.a_cnt2 = 0;
	ioinfo.a_cnt3 = 0;
	ioinfo.a_cnt4 = 0;

	if (ddi_copyout((void *)&ioinfo, (void *)dfc->buf1,
	    sizeof (dfc_ioinfo_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYOUT_ERROR);
	}

	return (0);

} /* emlxs_dfc_get_ioinfo() */


static int32_t
emlxs_dfc_get_linkinfo(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	dfc_linkinfo_t	linkinfo;

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < sizeof (dfc_linkinfo_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	bzero(&linkinfo, sizeof (dfc_linkinfo_t));

	linkinfo.a_linkEventTag = hba->link_event_tag;
	linkinfo.a_linkUp = HBASTATS.LinkUp;
	linkinfo.a_linkDown = HBASTATS.LinkDown;
	linkinfo.a_linkMulti = HBASTATS.LinkMultiEvent;
	linkinfo.a_DID = port->did;
	linkinfo.a_topology = 0;

	if (hba->state <= FC_LINK_DOWN) {
		linkinfo.a_linkState = LNK_DOWN;
	}
#ifdef MENLO_SUPPORT
	else if (hba->flag & FC_MENLO_MODE) {
		linkinfo.a_linkState = LNK_DOWN;
		linkinfo.a_topology  = LNK_MENLO_MAINTENANCE;

	}
#endif /* MENLO_SUPPORT */
	else if (hba->state == FC_LINK_DOWN_PERSIST) {
		linkinfo.a_linkState = LNK_DOWN_PERSIST;
	} else if (hba->state < FC_READY) {
		linkinfo.a_linkState = LNK_DISCOVERY;
	} else {
		linkinfo.a_linkState = LNK_READY;
	}

	if (linkinfo.a_linkState != LNK_DOWN) {
		if (hba->topology == TOPOLOGY_LOOP) {
			if (hba->flag & FC_FABRIC_ATTACHED) {
				linkinfo.a_topology = LNK_PUBLIC_LOOP;
			} else {
				linkinfo.a_topology = LNK_LOOP;
			}

			linkinfo.a_alpa = port->did & 0xff;
			linkinfo.a_alpaCnt = port->alpa_map[0];

			if (linkinfo.a_alpaCnt > 127) {
				linkinfo.a_alpaCnt = 127;
			}

			bcopy((void *)&port->alpa_map[0], linkinfo.a_alpaMap,
			    linkinfo.a_alpaCnt+1);
		} else {
			if (hba->flag & FC_FABRIC_ATTACHED) {
				linkinfo.a_topology = LNK_FABRIC;
			} else {
				linkinfo.a_topology = LNK_PT2PT;
			}
		}
	}

	bcopy(&hba->wwpn, linkinfo.a_wwpName, 8);
	bcopy(&hba->wwnn, linkinfo.a_wwnName, 8);

	if (ddi_copyout((void *)&linkinfo, (void *)dfc->buf1,
	    sizeof (dfc_linkinfo_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYOUT_ERROR);
	}

	return (0);

} /* emlxs_dfc_get_linkinfo() */

#ifdef SFCT_SUPPORT
static int32_t
emlxs_dfc_get_fctstat(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t		*port = &PPORT;
	emlxs_tgtport_stat_t	*statp = &TGTPORTSTAT;
	dfc_tgtport_stat_t	dfcstat;

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < sizeof (emlxs_tgtport_stat_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	bzero(&dfcstat, sizeof (dfcstat));

	dfcstat.Version = DFC_TGTPORT_STAT_VERSION;

	dfcstat.FctRcvDropped = statp->FctRcvDropped;
	dfcstat.FctOverQDepth = statp->FctOverQDepth;
	dfcstat.FctOutstandingIO = statp->FctOutstandingIO;
	dfcstat.FctFailedPortRegister = statp->FctFailedPortRegister;
	dfcstat.FctPortRegister = statp->FctPortRegister;
	dfcstat.FctPortDeregister = statp->FctPortDeregister;

	dfcstat.FctAbortSent = statp->FctAbortSent;
	dfcstat.FctNoBuffer = statp->FctNoBuffer;
	dfcstat.FctScsiStatusErr = statp->FctScsiStatusErr;
	dfcstat.FctScsiQfullErr = statp->FctScsiQfullErr;
	dfcstat.FctScsiResidOver = statp->FctScsiResidOver;
	dfcstat.FctScsiResidUnder = statp->FctScsiResidUnder;
	dfcstat.FctScsiSenseErr = statp->FctScsiSenseErr;

	dfcstat.FctEvent = statp->FctEvent;
	dfcstat.FctCompleted = statp->FctCompleted;
	dfcstat.FctCmplGood = statp->FctCmplGood;
	dfcstat.FctCmplError = statp->FctCmplError;
	dfcstat.FctStray = statp->FctStray;

	bcopy(&statp->FctP2IOWcnt[0], &dfcstat.FctP2IOWcnt[0],
	    (sizeof (uint64_t) * MAX_TGTPORT_IOCNT));
	bcopy(&statp->FctP2IORcnt[0], &dfcstat.FctP2IORcnt[0],
	    (sizeof (uint64_t) * MAX_TGTPORT_IOCNT));
	dfcstat.FctIOCmdCnt = statp->FctIOCmdCnt;
	dfcstat.FctReadBytes = statp->FctReadBytes;
	dfcstat.FctWriteBytes = statp->FctWriteBytes;
	dfcstat.FctCmdReceived = statp->FctCmdReceived;

	if (dfc->flag) {	/* Clear counters after read */
		bzero(&statp->FctP2IOWcnt[0],
		    (sizeof (uint64_t) * MAX_TGTPORT_IOCNT));
		bzero(&statp->FctP2IORcnt[0],
		    (sizeof (uint64_t) * MAX_TGTPORT_IOCNT));
		statp->FctIOCmdCnt = 0;
		statp->FctReadBytes = 0;
		statp->FctWriteBytes = 0;
		statp->FctCmdReceived = 0;
	}
	if (hba->state <= FC_LINK_DOWN) {
		dfcstat.FctLinkState = LNK_DOWN;
	}
#ifdef MENLO_SUPPORT
	else if (hba->flag & FC_MENLO_MODE) {
		dfcstat.FctLinkState = LNK_DOWN;
	}
#endif /* MENLO_SUPPORT */
	else if (hba->state < FC_READY) {
		dfcstat.FctLinkState = LNK_DISCOVERY;
	} else {
		dfcstat.FctLinkState = LNK_READY;
	}

	if (ddi_copyout((void *)&dfcstat, (void *)dfc->buf1,
	    sizeof (dfc_tgtport_stat_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYOUT_ERROR);
	}

	return (0);

} /* emlxs_dfc_get_fctstat() */
#endif /* SFCT_SUPPORT */

static int32_t
emlxs_dfc_get_nodeinfo(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port;
	emlxs_config_t	*cfg = &CFG;
	dfc_node_t	*dfc_node;
	dfc_node_t	*dnp;
	uint32_t	node_count;
	NODELIST	*nlp;
	uint32_t	size;
	uint32_t	i;

	port = &VPORT(dfc->data1);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s requested.",
	    emlxs_dfc_xlate(dfc->cmd));

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: NULL buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < (sizeof (dfc_node_t) * MAX_NODES)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	if (!dfc->buf2 || !dfc->buf2_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: NULL buffer2 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf2_size < sizeof (uint32_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer2 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf2_size);

		return (DFC_ARG_TOOSMALL);
	}

	node_count = port->node_count;

	if (node_count == 0) {
		return (0);
	}

	if (node_count > MAX_NODES) {
		node_count = MAX_NODES;
	}

	size = node_count * sizeof (dfc_node_t);

	if (!(dfc_node = (dfc_node_t *)kmem_zalloc(size, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to allocate dfc_node.",
		    emlxs_dfc_xlate(dfc->cmd));

		return (DFC_SYSRES_ERROR);
	}

	dnp = dfc_node;

	rw_enter(&port->node_rwlock, RW_READER);
	for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
		nlp = port->node_table[i];
		while (nlp != NULL) {
			dnp->port_id = nlp->nlp_DID;
			dnp->rpi = nlp->nlp_Rpi;
			dnp->xri = nlp->nlp_Xri;

			bcopy((char *)&nlp->sparm, (char *)&dnp->sparm,
			    sizeof (dnp->sparm));

			if (nlp->nlp_fcp_info & NLP_FCP_TGT_DEVICE) {
				dnp->flags |= PORT_FLAG_FCP_TARGET;
			}
			if (nlp->nlp_fcp_info & NLP_FCP_INI_DEVICE) {
				dnp->flags |= PORT_FLAG_FCP_INI;

			}
			if (nlp->nlp_fcp_info & NLP_FCP_2_DEVICE) {
				dnp->flags |= PORT_FLAG_FCP2;
			}
			if (cfg[CFG_NETWORK_ON].current && nlp->nlp_Xri) {
				dnp->flags |= PORT_FLAG_IP;
			}
			if (nlp->nlp_fcp_info & NLP_EMLX_VPORT) {
				dnp->flags |= PORT_FLAG_VPORT;
			}

			dnp++;
			nlp = (NODELIST *) nlp->nlp_list_next;
		}
	}
	rw_exit(&port->node_rwlock);

	if (ddi_copyout((void *)dfc_node, (void *)dfc->buf1, size, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		kmem_free(dfc_node, size);
		return (DFC_COPYOUT_ERROR);
	}

	if (ddi_copyout((void *)&node_count, (void *)dfc->buf2,
	    sizeof (uint32_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		kmem_free(dfc_node, size);
		return (DFC_COPYOUT_ERROR);
	}

	kmem_free(dfc_node, size);

	return (0);

} /* emlxs_dfc_get_nodeinfo() */


static int32_t
emlxs_dfc_read_mem(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	offset;
	uint32_t	size;
	uint32_t	max_size;
	uint8_t		*buffer;
	uint8_t		*slim;

	offset = dfc->data1;
	size = dfc->data2;

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (size > dfc->buf1_size) {
		size = dfc->buf1_size;
	}

	if (offset % 4) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Offset misaligned. (offset=%d)",
		    emlxs_dfc_xlate(dfc->cmd), offset);

		return (DFC_ARG_MISALIGNED);
	}

	if (size % 4) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Size misaligned. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), size);

		return (DFC_ARG_MISALIGNED);
	}

	if (hba->flag & FC_SLIM2_MODE) {
		max_size = SLI2_SLIM2_SIZE;
	} else {
		max_size = 4096;
	}

	if (offset >= max_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Offset too large. (offset=%d)",
		    emlxs_dfc_xlate(dfc->cmd), offset);

		return (DFC_ARG_TOOBIG);
	}

	if ((size + offset) > max_size) {
		size = (max_size - offset);
	}

	if (!(buffer = (uint8_t *)kmem_zalloc(size, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to allocate buffer.",
		    emlxs_dfc_xlate(dfc->cmd));

		return (DFC_SYSRES_ERROR);
	}

	if (hba->flag & FC_SLIM2_MODE) {
		slim = (uint8_t *)hba->sli.sli3.slim2.virt + offset;
		BE_SWAP32_BCOPY((uint8_t *)slim, (uint8_t *)buffer, size);
	} else {
		slim = (uint8_t *)hba->sli.sli3.slim_addr + offset;
		READ_SLIM_COPY(hba, (uint32_t *)buffer, (uint32_t *)slim,
		    (size / 4));
	}

	if (ddi_copyout((void *)buffer, (void *)dfc->buf1, size, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		kmem_free(buffer, size);
		return (DFC_COPYOUT_ERROR);
	}

	kmem_free(buffer, size);

#ifdef FMA_SUPPORT
	/* Access handle validation */
	if (emlxs_fm_check_acc_handle(hba, hba->sli.sli3.slim_acc_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_access_handle_msg, NULL);
		return (DFC_DRV_ERROR);
	}
#endif  /* FMA_SUPPORT */

	return (0);

} /* emlxs_dfc_read_mem() */


static int32_t
emlxs_dfc_write_mem(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	offset;
	uint32_t	size;
	uint32_t	max_size;
	uint8_t		*buffer;
	uint8_t		*slim;

	offset = dfc->data1;
	size = dfc->data2;

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (size > dfc->buf1_size) {
		size = dfc->buf1_size;
	}

	if (offset % 4) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Offset misaligned. (offset=%d)",
		    emlxs_dfc_xlate(dfc->cmd), offset);

		return (DFC_ARG_MISALIGNED);
	}

	if (size % 4) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Size misaligned. (szie=%d)",
		    emlxs_dfc_xlate(dfc->cmd), size);

		return (DFC_ARG_MISALIGNED);
	}

	if (hba->flag & FC_SLIM2_MODE) {
		max_size = SLI2_SLIM2_SIZE;
	} else {
		max_size = 4096;
	}

	if (offset >= max_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Offset too large. (offset=%d)",
		    emlxs_dfc_xlate(dfc->cmd), offset);

		return (DFC_ARG_TOOBIG);
	}

	if ((size + offset) > max_size) {
		size = (max_size - offset);
	}

	if (!(buffer = (uint8_t *)kmem_zalloc(size, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to allocate buffer.",
		    emlxs_dfc_xlate(dfc->cmd));

		return (DFC_SYSRES_ERROR);
	}

	if (ddi_copyin((void *)dfc->buf1, (void *)buffer, size, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		kmem_free(buffer, size);
		return (DFC_COPYIN_ERROR);
	}

	if (hba->flag & FC_SLIM2_MODE) {
		slim = (uint8_t *)hba->sli.sli3.slim2.virt + offset;
		BE_SWAP32_BCOPY((uint8_t *)buffer, (uint8_t *)slim, size);
	} else {
		slim = (uint8_t *)hba->sli.sli3.slim_addr + offset;
		WRITE_SLIM_COPY(hba, (uint32_t *)buffer, (uint32_t *)slim,
		    (size / 4));
	}

	kmem_free(buffer, size);

#ifdef FMA_SUPPORT
	/* Access handle validation */
	if (emlxs_fm_check_acc_handle(hba, hba->sli.sli3.slim_acc_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_access_handle_msg, NULL);
		return (DFC_DRV_ERROR);
	}
#endif  /* FMA_SUPPORT */

	return (0);

} /* emlxs_dfc_write_mem() */


/* ARGSUSED */
static int32_t
emlxs_dfc_write_ctlreg(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	offset;
	uint32_t	value;

	offset = dfc->data1;
	value = dfc->data2;

	if (hba->model_info.flags & EMLXS_FCOE_SUPPORTED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: FCoE not  supported.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_FCOE_NOTSUPPORTED);
	}

	if (!(hba->flag & FC_OFFLINE_MODE)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Adapter not offline.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ONLINE_ERROR);
	}

	if (offset % 4) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Offset misaligned. (offset=%d)",
		    emlxs_dfc_xlate(dfc->cmd), offset);

		return (DFC_ARG_MISALIGNED);
	}

	if (offset > 255) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Offset too large. (offset=%d)",
		    emlxs_dfc_xlate(dfc->cmd), offset);

		return (DFC_ARG_TOOBIG);
	}

	WRITE_CSR_REG(hba, (hba->sli.sli3.csr_addr + offset), value);

#ifdef FMA_SUPPORT
	/* Access handle validation */
	if (emlxs_fm_check_acc_handle(hba, hba->sli.sli3.csr_acc_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_access_handle_msg, NULL);
		return (DFC_DRV_ERROR);
	}
#endif  /* FMA_SUPPORT */

	return (0);

} /* emlxs_dfc_write_ctlreg() */


static int32_t
emlxs_dfc_read_ctlreg(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	offset;
	uint32_t	value;

	offset = dfc->data1;

	if (hba->model_info.flags & EMLXS_FCOE_SUPPORTED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: FCoE not  supported.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_FCOE_NOTSUPPORTED);
	}

	if (offset % 4) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Offset misaligned. (offset=%d)",
		    emlxs_dfc_xlate(dfc->cmd), offset);

		return (DFC_ARG_MISALIGNED);
	}

	if (offset > 255) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Offset too large. (offset=%d)",
		    emlxs_dfc_xlate(dfc->cmd), offset);

		return (DFC_ARG_TOOBIG);
	}

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < sizeof (uint32_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	value = READ_CSR_REG(hba, (hba->sli.sli3.csr_addr + offset));

	if (ddi_copyout((void *)&value, (void *)dfc->buf1, sizeof (uint32_t),
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYOUT_ERROR);
	}

#ifdef FMA_SUPPORT
	/* Access handle validation */
	if (emlxs_fm_check_acc_handle(hba, hba->sli.sli3.csr_acc_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_access_handle_msg, NULL);
		return (DFC_DRV_ERROR);
	}
#endif  /* FMA_SUPPORT */

	return (0);

} /* emlxs_dfc_read_ctlreg() */


static int32_t
emlxs_dfc_set_event(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t		*port = &PPORT;
	uint32_t		event;
	uint32_t		enable;
	uint32_t		pid;
	uint32_t		count;
	uint32_t		i;
	emlxs_dfc_event_t	*dfc_event;

	event = dfc->data1;
	pid = dfc->data2;
	enable = dfc->flag;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "%s: %s. pid=%d enable=%d", emlxs_dfc_xlate(dfc->cmd),
	    emlxs_dfc_event_xlate(event), pid, enable);

	switch (event) {
	case FC_REG_LINK_EVENT:
	case FC_REG_RSCN_EVENT:
	case FC_REG_CT_EVENT:
	case FC_REG_DUMP_EVENT:
	case FC_REG_TEMP_EVENT:
	case FC_REG_VPORTRSCN_EVENT:
	case FC_REG_FCOE_EVENT:
		break;

	case FC_REG_MULTIPULSE_EVENT:
	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: %s. Invalid event. pid=%d enable=%d",
		    emlxs_dfc_xlate(dfc->cmd), emlxs_dfc_event_xlate(event),
		    pid, enable);

		return (DFC_ARG_INVALID);
	}

	if (enable) {
		if (dfc->buf1_size < sizeof (uint32_t)) {
			dfc->buf1 = NULL;
		} else if (!dfc->buf1) {
			dfc->buf1_size = 0;
		}

		/* Make sure this pid/event is not already registered */
		dfc_event = NULL;
		for (i = 0; i < MAX_DFC_EVENTS; i++) {
			dfc_event = &hba->dfc_event[i];

			if (dfc_event->pid == pid &&
			    dfc_event->event == event) {
				break;
			}
		}

		if (i == MAX_DFC_EVENTS) {
			/* Find next available event object */
			for (i = 0; i < MAX_DFC_EVENTS; i++) {
				dfc_event = &hba->dfc_event[i];

				if (!dfc_event->pid && !dfc_event->event) {
					break;
				}
			}

			/* Return if all event objects are busy */
			if (i == MAX_DFC_EVENTS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_dfc_error_msg,
				    "%s: %s. Too many events registered. "
				    "pid=%d enable=%d",
				    emlxs_dfc_xlate(dfc->cmd),
				    emlxs_dfc_event_xlate(event), pid,
				    enable);

				return (DFC_DRVRES_ERROR);
			}
		}

		/* Initialize */
		dfc_event->pid = pid;
		dfc_event->event = event;
		dfc_event->last_id = (uint32_t)-1;
		dfc_event->dataout = NULL;
		dfc_event->size = 0;
		dfc_event->mode = 0;

		(void) emlxs_get_dfc_event(port, dfc_event, 0);

		if (dfc->buf1) {
			if (ddi_copyout((void *)&dfc_event->last_id,
			    dfc->buf1, sizeof (uint32_t), mode) != 0) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_dfc_error_msg,
				    "%s: ddi_copyout failed.",
				    emlxs_dfc_xlate(dfc->cmd));

				return (DFC_COPYOUT_ERROR);
			}
		}

		/*
		 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_debug_msg,
		 * "%s: %s. Enabled. pid=%d id=%d", emlxs_dfc_xlate(dfc->cmd),
		 * emlxs_dfc_event_xlate(event), pid, dfc_event->last_id);
		 */

		hba->event_mask |= event;

	} else {	/* Disable */

		/* Find the event entry */
		dfc_event = NULL;
		for (i = 0; i < MAX_DFC_EVENTS; i++) {
			dfc_event = &hba->dfc_event[i];

			if (dfc_event->pid == pid &&
			    dfc_event->event == event) {
				break;
			}
		}

		if (i == MAX_DFC_EVENTS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: %s. Event not registered. pid=%d enable=%d",
			    emlxs_dfc_xlate(dfc->cmd),
			    emlxs_dfc_event_xlate(event), pid, enable);

			return (DFC_ARG_INVALID);
		}

		/* Kill the event thread if it is sleeping */
		(void) emlxs_kill_dfc_event(port, dfc_event);

		/* Count the number of pids still registered for this event */
		count = 0;
		for (i = 0; i < MAX_DFC_EVENTS; i++) {
			dfc_event = &hba->dfc_event[i];

			if (dfc_event->event == event) {
				count++;
			}
		}

		/* If no more pids need this event, */
		/* then disable logging for this event */
		if (count == 0) {
			hba->event_mask &= ~event;
		}
	}

	return (0);

} /* emlxs_dfc_set_event() */


static int32_t
emlxs_dfc_get_eventinfo(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	size;
	int32_t		rval = 0;
	HBA_EVENTINFO 	*event_buffer = NULL;
	uint32_t	event_count = 0;
	uint32_t	missed = 0;

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 buffer.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	event_count = dfc->buf1_size / sizeof (HBA_EVENTINFO);

	if (!event_count) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	if (!dfc->buf2 || !dfc->buf2_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer2 buffer.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf2_size < sizeof (uint32_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer2 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf2_size);

		return (DFC_ARG_TOOSMALL);
	}

	if (!dfc->buf3 || !dfc->buf3_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer3 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf3_size < sizeof (uint32_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer3 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf3_size);

		return (DFC_ARG_TOOSMALL);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s called. max=%d",
	    emlxs_dfc_xlate(dfc->cmd), event_count);

	size = (event_count * sizeof (HBA_EVENTINFO));
	event_buffer = (HBA_EVENTINFO *)kmem_zalloc(size, KM_SLEEP);

	if (emlxs_get_dfc_eventinfo(port, event_buffer, &event_count,
	    &missed) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: emlxs_get_dfc_eventinfo failed.",
		    emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_DRV_ERROR;
		goto done;
	}

	if (event_count) {
		if (ddi_copyout((void *)event_buffer, dfc->buf1,
		    (event_count * sizeof (HBA_EVENTINFO)), mode) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: ddi_copyout failed.",
			    emlxs_dfc_xlate(dfc->cmd));

			rval = DFC_COPYOUT_ERROR;
			goto done;
		}
	}

	if (ddi_copyout((void *)&event_count, dfc->buf2, sizeof (uint32_t),
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYOUT_ERROR;
		goto done;
	}

	if (ddi_copyout((void *)&missed, dfc->buf3, sizeof (uint32_t),
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYOUT_ERROR;
		goto done;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "%s: events=%d missed=%d new=%d last_id=%d",
	    emlxs_dfc_xlate(dfc->cmd), event_count, hba->hba_event.missed,
	    hba->hba_event.new, hba->hba_event.last_id);

done:

	if (event_buffer) {
		kmem_free(event_buffer, size);
	}

	return (rval);

} /* emlxs_dfc_get_eventinfo() */


static int32_t
emlxs_dfc_get_event(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t		*port = &PPORT;
	uint32_t		event;
	uint32_t		pid;
	uint32_t		sleep;
	uint32_t		i;
	int32_t			rval = DFC_SUCCESS;
	emlxs_dfc_event_t	*dfc_event;

	event = dfc->data1;
	pid = dfc->data2;

	if (!dfc->buf1_size) {
		dfc->buf1 = NULL;
	} else if (!dfc->buf1) {
		dfc->buf1_size = 0;
	}

	if (dfc->buf2_size < sizeof (uint32_t)) {
		dfc->buf2 = NULL;
	} else if (!dfc->buf2) {
		dfc->buf2_size = 0;
	}

	if (dfc->buf3_size < sizeof (uint32_t)) {
		dfc->buf3 = NULL;
	} else if (!dfc->buf3) {
		dfc->buf3_size = 0;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "%s: %s. pid=%d size=%d,%p rcv_size=%d,%p id=%d",
	    emlxs_dfc_xlate(dfc->cmd), emlxs_dfc_event_xlate(event), pid,
	    dfc->buf1_size, dfc->buf1, dfc->buf2_size, dfc->buf2, dfc->data3);

	/* Find the event entry */
	dfc_event = NULL;
	for (i = 0; i < MAX_DFC_EVENTS; i++) {
		dfc_event = &hba->dfc_event[i];

		if (dfc_event->pid == pid && dfc_event->event == event) {
			break;
		}
	}

	if (i == MAX_DFC_EVENTS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: %s. Event not registered. pid=%d",
		    emlxs_dfc_xlate(dfc->cmd), emlxs_dfc_event_xlate(event),
		    pid);

		return (DFC_ARG_INVALID);
	}

	if (!(hba->event_mask & dfc_event->event)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: %s. Event not registered. pid=%d",
		    emlxs_dfc_xlate(dfc->cmd), emlxs_dfc_event_xlate(event),
		    pid);

		return (DFC_ARG_INVALID);
	}

	/* Initialize event buffer pointers */
	dfc_event->dataout = dfc->buf1;
	dfc_event->size = dfc->buf1_size;
	dfc_event->last_id = dfc->data3;
	dfc_event->mode = mode;

	sleep = (dfc->flag & 0x01) ? 1 : 0;

	if ((rval = emlxs_get_dfc_event(port, dfc_event, sleep))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_debug_msg,
		    "%s: %s. Exiting. pid=%d rsize=%d id=%d rval=%d",
		    emlxs_dfc_xlate(dfc->cmd), emlxs_dfc_event_xlate(event),
		    pid, dfc_event->size, dfc_event->last_id, rval);

		return (rval);
	}

	if (dfc->buf2) {
		if (ddi_copyout((void *)&dfc_event->size, dfc->buf2,
		    sizeof (uint32_t), mode) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: ddi_copyout failed.",
			    emlxs_dfc_xlate(dfc->cmd));

			return (DFC_COPYOUT_ERROR);
		}
	}

	if (dfc->buf3) {
		if (ddi_copyout((void *)&dfc_event->last_id, dfc->buf3,
		    sizeof (uint32_t), mode) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: ddi_copyout failed.",
			    emlxs_dfc_xlate(dfc->cmd));

			return (DFC_COPYOUT_ERROR);
		}
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_debug_msg,
	    "%s: %s. Completed. pid=%d rsize=%d id=%d",
	    emlxs_dfc_xlate(dfc->cmd), emlxs_dfc_event_xlate(event), pid,
	    dfc_event->size, dfc_event->last_id);

	return (rval);

} /* emlxs_dfc_get_event() */


extern uint32_t
emlxs_get_dump_region(emlxs_hba_t *hba, uint32_t region,
    uint8_t *buffer, uint32_t *psize)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	size;
	uint32_t	size_only;
	uint32_t	rval = 0;
	uint8_t		*memptr;
	uint32_t	*wptr;

	if (!buffer || !(*psize)) {
		size_only = 1;
		size = 0xffffffff;
	} else {
		size_only = 0;
		size = *psize;
	}

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		if (region != 7) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "emlxs_get_dump_region: Invalid sli4 region. "
			    "(id=%d)", region);

			rval = DFC_ARG_INVALID;
			goto done;
		}
	}

	switch (region) {
	case 0:	/* SLI Registers */

		if (size < (4 * sizeof (uint32_t))) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "emlxs_get_dump_region: Buffer too small. "
			    "(SLI Registers: size=%d)", size);

			rval = DFC_ARG_TOOSMALL;
			goto done;
		}

		size = (4 * sizeof (uint32_t));

		if (size_only) {
			break;
		}

		wptr = (uint32_t *)buffer;
		wptr[0] = READ_CSR_REG(hba, FC_HA_REG(hba));
		wptr[1] = READ_CSR_REG(hba, FC_CA_REG(hba));
		wptr[2] = READ_CSR_REG(hba, FC_HS_REG(hba));
		wptr[3] = READ_CSR_REG(hba, FC_HC_REG(hba));

#ifdef FMA_SUPPORT
		/* Access handle validation */
		if (emlxs_fm_check_acc_handle(hba, hba->sli.sli3.csr_acc_handle)
		    != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_access_handle_msg, NULL);
			rval = DFC_DRV_ERROR;
		}
#endif  /* FMA_SUPPORT */

		break;

	case 1:	/* SLIM */

		if (hba->flag & FC_SLIM2_MODE) {
			size = MIN(SLI2_SLIM2_SIZE, size);
		} else {
			size = MIN(4096, size);
		}

		if (size_only) {
			break;
		}

		if (hba->flag & FC_SLIM2_MODE) {
			memptr = (uint8_t *)hba->sli.sli3.slim2.virt;
			BE_SWAP32_BCOPY((uint8_t *)memptr, (uint8_t *)buffer,
			    size);
		} else {
			memptr = (uint8_t *)hba->sli.sli3.slim_addr;
			READ_SLIM_COPY(hba, (uint32_t *)buffer,
			    (uint32_t *)memptr, (size / 4));
#ifdef FMA_SUPPORT
			/* Access handle validation */
			if (emlxs_fm_check_acc_handle(hba,
			    hba->sli.sli3.slim_acc_handle) != DDI_FM_OK) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_invalid_access_handle_msg, NULL);
				rval = DFC_DRV_ERROR;
			}
#endif  /* FMA_SUPPORT */
		}

		break;

	case 2:	/* Port Control Block */

		if (size < sizeof (PCB)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "emlxs_get_dump_region: Buffer too small. "
			    "(PCB: size=%d)", size);

			rval = DFC_ARG_TOOSMALL;
			goto done;
		}

		size = sizeof (PCB);

		if (size_only) {
			break;
		}

		memptr = (uint8_t *)&(((SLIM2 *)hba->sli.sli3.slim2.virt)->pcb);
		BE_SWAP32_BCOPY((uint8_t *)memptr, (uint8_t *)buffer, size);
		break;

	case 3:	/* MailBox */

		if (size < MAILBOX_CMD_BSIZE) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "emlxs_get_dump_region: Buffer too small. "
			    "(Mailbox: size=%d)", size);

			rval = DFC_ARG_TOOSMALL;
			goto done;
		}

		size = MAILBOX_CMD_BSIZE;

		if (size_only) {
			break;
		}

		if (hba->flag & FC_SLIM2_MODE) {
			memptr = (uint8_t *)hba->sli.sli3.slim2.virt;
			BE_SWAP32_BCOPY((uint8_t *)memptr, (uint8_t *)buffer,
			    size);
		} else {
			memptr = (uint8_t *)hba->sli.sli3.slim_addr;
			READ_SLIM_COPY(hba, (uint32_t *)buffer,
			    (uint32_t *)memptr, (size / 4));
#ifdef FMA_SUPPORT
			/* Access handle validation */
			if (emlxs_fm_check_acc_handle(hba,
			    hba->sli.sli3.slim_acc_handle) != DDI_FM_OK) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_invalid_access_handle_msg, NULL);
				rval = DFC_DRV_ERROR;
			}
#endif  /* FMA_SUPPORT */
		}

		break;

	case 4:	/* Host Put/Get pointer array */

		if (size < MAX_RINGS * sizeof (HGP)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "emlxs_get_dump_region: Buffer too small. "
			    "(HGP: size=%d)", size);

			rval = DFC_ARG_TOOSMALL;
			goto done;
		}

		size = MAX_RINGS * sizeof (HGP);

		if (size_only) {
			break;
		}

		{
			memptr = (uint8_t *)hba->sli.sli3.slim_addr +
			    hba->sli.sli3.hgp_ring_offset;

			READ_SLIM_COPY(hba, (uint32_t *)buffer,
			    (uint32_t *)memptr, (size / 4));
#ifdef FMA_SUPPORT
			/* Access handle validation */
			if (emlxs_fm_check_acc_handle(hba,
			    hba->sli.sli3.slim_acc_handle) != DDI_FM_OK) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_invalid_access_handle_msg, NULL);
				rval = DFC_DRV_ERROR;
			}
#endif  /* FMA_SUPPORT */
		}

		break;

	case 5:	/* Port  Get/Put pointer array */

		if (size < MAX_RINGS * sizeof (PGP)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "emlxs_get_dump_region: Buffer too small. "
			    "(PGP: size=%d)", size);

			rval = DFC_ARG_TOOSMALL;
			goto done;
		}

		size = MAX_RINGS * sizeof (PGP);

		if (size_only) {
			break;
		}

		memptr = (uint8_t *)
		    ((SLIM2 *)hba->sli.sli3.slim2.virt)->mbx.us.s2.port;
		BE_SWAP32_BCOPY((uint8_t *)memptr, (uint8_t *)buffer, size);
		break;

	case 6:	/* Command/Response Ring */

		if (size < SLI_IOCB_MAX_SIZE) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "emlxs_get_dump_region: Buffer too small. "
			    "(Rings: size=%d)", size);

			rval = DFC_ARG_TOOSMALL;
			goto done;
		}

		size = SLI_IOCB_MAX_SIZE;

		if (size_only) {
			break;
		}

		memptr = (uint8_t *)((SLIM2 *)hba->sli.sli3.slim2.virt)->IOCBs;
		BE_SWAP32_BCOPY((uint8_t *)memptr, (uint8_t *)buffer, size);
		break;

	case 7:	/* All driver specific structures */

		if (size < sizeof (emlxs_hba_t)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "emlxs_get_dump_region: Buffer too small. "
			    "(Driver: size=%d)", size);

			rval = DFC_ARG_TOOSMALL;
			goto done;
		}

		size = sizeof (emlxs_hba_t);

		if (size_only) {
			break;
		}

		memptr = (uint8_t *)hba;
		bcopy((void *)memptr, (void *)buffer, size);

		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "emlxs_get_dump_region: Invalid region. (id=%d)", region);

		rval = DFC_ARG_INVALID;
	}

done:

	*psize = size;

	return (rval);

} /* emlxs_get_dump_region() */



static int32_t
emlxs_dfc_get_dump_region(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	size;
	uint32_t	size_only = 0;
	uint32_t	rval = 0;
	uint8_t		*buffer = NULL;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "%s: region=%d size=%d",
	    emlxs_dfc_xlate(dfc->cmd), dfc->data1, dfc->buf1_size);

	if (!dfc->buf1 || !dfc->buf1_size) {
		size_only = 1;
	}

	if (!dfc->buf2 || !dfc->buf2_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer2 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf2_size < sizeof (uint32_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer2 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf2_size);

		return (DFC_ARG_TOOSMALL);
	}

	/* First get region size only */
	size = 0;
	rval = emlxs_get_dump_region(hba, dfc->data1, NULL, &size);

	if (rval != 0) {
		goto done;
	}

	if (!size_only) {
		if (dfc->buf1_size < size) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Buffer1 too small. (size: %d < %d)",
			    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size, size);

			rval = DFC_ARG_TOOSMALL;
			goto done;
		}

		buffer = (uint8_t *)kmem_zalloc(size, KM_SLEEP);

		/* Get the region data */
		rval = emlxs_get_dump_region(hba, dfc->data1, buffer, &size);

		if (rval != 0) {
			goto done;
		}

		/* Return the region data */
		if (ddi_copyout((void *)buffer, (void *) dfc->buf1,
		    size, mode) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: ddi_copyout failed.",
			    emlxs_dfc_xlate(dfc->cmd));

			rval = DFC_COPYOUT_ERROR;
			goto done;
		}
	}

	/* Return the region size */
	if (ddi_copyout((void *) &size, (void *) dfc->buf2,
	    sizeof (uint32_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYOUT_ERROR;
		goto done;
	}

done:

	if (buffer) {
		kmem_free(buffer, size);
	}

	return (rval);

} /* emlxs_dfc_get_dump_region() */



#ifdef MENLO_SUPPORT
static int32_t
emlxs_dfc_menlo_port_offset(emlxs_hba_t *hba)
{
	uint32_t	cnt;
	char		pathname[256];

	(void) ddi_pathname(hba->dip, pathname);
	cnt = strlen(pathname);
	if ((cnt < 4) || (strcmp(&pathname[cnt-3], "0,1") != 0))
		return (0);
	return (1);
}

static int32_t
emlxs_dfc_set_menlo_loopback(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	MAILBOXQ *mbq = NULL;
	MAILBOX *mb = NULL;
	fc_packet_t *pkt = NULL;
	uint32_t mbxstatus;
	uint32_t i;
	uint32_t offset;
	uint32_t rval = 0;
	menlo_cmd_t *cmd;

	mbq = (MAILBOXQ *)kmem_zalloc(sizeof (MAILBOXQ),
	    KM_SLEEP);

	mb = (MAILBOX *)mbq;

	/* SET MENLO maint mode */
	/* Create the set_variable mailbox request */
	emlxs_mb_set_var(hba, mbq, 0x103107, 1);

	mbq->flag |= MBQ_PASSTHRU;

	/* issue the mbox cmd to the sli */
	mbxstatus = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0);

	if (mbxstatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: %s failed. mbxstatus=0x%x",
		    emlxs_dfc_xlate(EMLXS_LOOPBACK_MODE),
		    emlxs_mb_cmd_xlate(mb->mbxCommand), mbxstatus);

		rval = DFC_IO_ERROR;
		if (mbxstatus == MBX_TIMEOUT)
			rval = DFC_TIMEOUT;
		goto done;
	}


	/* Wait 30 sec for maint mode */
	i = 0;
	do {
		if (i++ > 300) {
			break;
		}

		delay(drv_usectohz(100000));

	} while (!(hba->flag & FC_MENLO_MODE));

	if (!(hba->flag & FC_MENLO_MODE)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to enter maint mode.",
		    emlxs_dfc_xlate(EMLXS_LOOPBACK_MODE));

		rval = DFC_DRV_ERROR;
		goto done;
	}

	offset = emlxs_dfc_menlo_port_offset(hba);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
	    "%s: Entered maint mode. Port offset: %d",
	    emlxs_dfc_xlate(EMLXS_LOOPBACK_MODE), offset);


	/* Issue Menlo loopback command */
	if (!(pkt = emlxs_pkt_alloc(port, sizeof (menlo_cmd_t),
	    sizeof (uint32_t), 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to allocate packet.",
		    emlxs_dfc_xlate(EMLXS_LOOPBACK_MODE));

		rval = DFC_SYSRES_ERROR;
		goto done;
	}

	/* Make this a polled IO */
	pkt->pkt_tran_flags &= ~FC_TRAN_INTR;
	pkt->pkt_tran_flags |= FC_TRAN_NO_INTR;
	pkt->pkt_comp = NULL;
	pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	pkt->pkt_timeout = 30;

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(EMLXS_MENLO_DID);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_COMMAND;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(port->did);
	pkt->pkt_cmd_fhdr.type = EMLXS_MENLO_TYPE;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_FIRST_SEQ | F_CTL_END_SEQ | F_CTL_SEQ_INITIATIVE;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.rx_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.ro = 0;

	cmd = (menlo_cmd_t *)pkt->pkt_cmd;
	cmd->code = BE_SWAP32(MENLO_CMD_LOOPBACK);
	cmd->lb.context = BE_SWAP32(offset);
	cmd->lb.type = BE_SWAP32(MENLO_LOOPBACK_ENABLE);

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to send packet.",
		    emlxs_dfc_xlate(EMLXS_LOOPBACK_MODE));

		rval = DFC_IO_ERROR;
		goto done;
	}

	if (pkt->pkt_state != FC_PKT_SUCCESS) {
		if (pkt->pkt_state == FC_PKT_TIMEOUT) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_dfc_error_msg,
			    "%s: Pkt Transport error. Pkt Timeout.",
			    emlxs_dfc_xlate(EMLXS_LOOPBACK_MODE));
			rval = DFC_TIMEOUT;
		} else if ((pkt->pkt_state == FC_PKT_LOCAL_RJT) &&
		    (pkt->pkt_reason == FC_REASON_OVERRUN)) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_dfc_error_msg,
			    "%s: Pkt Transport error. Rsp overrun.",
			    emlxs_dfc_xlate(EMLXS_LOOPBACK_MODE));
			rval = DFC_RSP_BUF_OVERRUN;
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_dfc_error_msg,
			    "%s: Pkt Transport error. state=%x",
			    emlxs_dfc_xlate(EMLXS_LOOPBACK_MODE),
			    pkt->pkt_state);
			rval = DFC_IO_ERROR;
		}
		goto done;
	}


	/* CLEAR MENLO maint mode */
	/* Create the set_variable mailbox request */
	emlxs_mb_set_var(hba, mbq, 0x103107, 0);

	mbq->flag |= MBQ_PASSTHRU;

	/* issue the mbox cmd to the sli */
	mbxstatus = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0);

	if (mbxstatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: %s failed. mbxstatus=0x%x",
		    emlxs_dfc_xlate(EMLXS_LOOPBACK_MODE),
		    emlxs_mb_cmd_xlate(mb->mbxCommand), mbxstatus);

		rval = DFC_IO_ERROR;
		if (mbxstatus == MBX_TIMEOUT)
			rval = DFC_TIMEOUT;
	}

	delay(drv_usectohz(1000000));
	i = 0;
	while ((hba->state < FC_LINK_UP) && (hba->state != FC_ERROR)) {
		delay(drv_usectohz(100000));
		i++;

		if (i == 300) {
			rval = DFC_TIMEOUT;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Linkup timeout.",
			    emlxs_dfc_xlate(EMLXS_LOOPBACK_MODE));

			goto done;
		}
	}

done:
	/* Free allocated mbox memory */
	if (mbq) {
		kmem_free(mbq, sizeof (MAILBOXQ));
	}
	if (pkt) {
		emlxs_pkt_free(pkt);
	}
	return (rval);
}

static int32_t
emlxs_dfc_set_menlo_fte(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	fc_packet_t *pkt = NULL;
	uint32_t rval = 0;
	menlo_cmd_t *cmd;


	/* Issue Menlo loopback command */
	if (!(pkt = emlxs_pkt_alloc(port, sizeof (menlo_cmd_t),
	    sizeof (uint32_t), 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to allocate packet.",
		    emlxs_dfc_xlate(EMLXS_LOOPBACK_MODE));

		rval = DFC_SYSRES_ERROR;
		goto done;
	}

	/* Make this a polled IO */
	pkt->pkt_tran_flags &= ~FC_TRAN_INTR;
	pkt->pkt_tran_flags |= FC_TRAN_NO_INTR;
	pkt->pkt_comp = NULL;
	pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	pkt->pkt_timeout = 30;

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(EMLXS_MENLO_DID);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_COMMAND;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(port->did);
	pkt->pkt_cmd_fhdr.type = EMLXS_MENLO_TYPE;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_FIRST_SEQ | F_CTL_END_SEQ | F_CTL_SEQ_INITIATIVE;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.rx_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.ro = 0;

	cmd = (menlo_cmd_t *)pkt->pkt_cmd;
	cmd->code = BE_SWAP32(MENLO_CMD_FTE_INSERT);
	cmd->fte_insert.fcid = BE_SWAP32(0);
	bcopy((caddr_t)&port->wwpn, (caddr_t)cmd->fte_insert.wwpn, 8);

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to send packet.",
		    emlxs_dfc_xlate(EMLXS_LOOPBACK_MODE));

		rval = DFC_IO_ERROR;
		goto done;
	}

	if (pkt->pkt_state != FC_PKT_SUCCESS) {
		if (pkt->pkt_state == FC_PKT_TIMEOUT) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_dfc_error_msg,
			    "%s: Pkt Transport error. Pkt Timeout.",
			    emlxs_dfc_xlate(EMLXS_LOOPBACK_MODE));
			rval = DFC_TIMEOUT;
		} else if ((pkt->pkt_state == FC_PKT_LOCAL_RJT) &&
		    (pkt->pkt_reason == FC_REASON_OVERRUN)) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_dfc_error_msg,
			    "%s: Pkt Transport error. Rsp overrun.",
			    emlxs_dfc_xlate(EMLXS_LOOPBACK_MODE));
			rval = DFC_RSP_BUF_OVERRUN;
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_dfc_error_msg,
			    "%s: Pkt Transport error. state=%x",
			    emlxs_dfc_xlate(EMLXS_LOOPBACK_MODE),
			    pkt->pkt_state);
			rval = DFC_IO_ERROR;
		}
		goto done;
	}


done:
	if (pkt) {
		emlxs_pkt_free(pkt);
	}
	return (rval);
}

static int32_t
emlxs_dfc_reset_menlo(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	MAILBOXQ *mbq = NULL;
	MAILBOX *mb = NULL;
	uint32_t mbxstatus;
	uint32_t rval = 0;

	mbq = (MAILBOXQ *)kmem_zalloc(sizeof (MAILBOXQ),
	    KM_SLEEP);

	mb = (MAILBOX *)mbq;

	/* RESET MENLO */
	/* Create the set_variable mailbox request */
	emlxs_mb_set_var(hba, mbq, 0x103007, 0);

	mbq->flag |= MBQ_PASSTHRU;

	/* issue the mbox cmd to the sli */
	mbxstatus = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0);

	if (mbxstatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: %s failed. mbxstatus=0x%x",
		    emlxs_dfc_xlate(EMLXS_LOOPBACK_MODE),
		    emlxs_mb_cmd_xlate(mb->mbxCommand), mbxstatus);

		rval = DFC_IO_ERROR;
		if (mbxstatus == MBX_TIMEOUT)
			rval = DFC_TIMEOUT;
		goto done;
	}
done:
	/* Free allocated mbox memory */
	if (mbq) {
		kmem_free(mbq, sizeof (MAILBOXQ));
	}
	return (rval);
}

#endif /* MENLO_SUPPORT */

/* ARGSUSED */
static int32_t
emlxs_dfc_loopback_mode(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	emlxs_config_t	*cfg = &CFG;
	MAILBOXQ	*mbq = NULL;
	MAILBOX		*mb = NULL;
	uint32_t	rval = DFC_SUCCESS;
	uint32_t	i;
	uint32_t	timeout;
	uint32_t	topology;
	uint32_t	speed;
	uint32_t	new_mode;
	NODELIST	*ndlp;

	if (hba->model_info.flags & EMLXS_FCOE_SUPPORTED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: FCoE not supported.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_FCOE_NOTSUPPORTED);
	}

	/* Reinitialize the link */
	switch (dfc->flag) {
	case 0:	/* Disable */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_debug_msg,
		    "%s: Disabling Loopback.", emlxs_dfc_xlate(dfc->cmd));

		if (!(hba->flag & FC_LOOPBACK_MODE)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_debug_msg,
			    "%s: Loopback already disabled.",
			    emlxs_dfc_xlate(dfc->cmd));

			return (rval);
		}
		goto resetdone;

	case 1:	/* Internal loopback */
		new_mode = FC_ILB_MODE;
		topology = FLAGS_LOCAL_LB;
		speed = 0;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_debug_msg,
		    "%s: Enabling ILB.", emlxs_dfc_xlate(dfc->cmd));

		/* Check if mode already set */
		if ((hba->flag & FC_ILB_MODE)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_debug_msg,
			    "%s: ILB mode already enabled.",
			    emlxs_dfc_xlate(dfc->cmd));

			return (rval);
		}

		break;

	case 2:	/* External loopback */
		new_mode = FC_ELB_MODE;
		topology = FLAGS_TOPOLOGY_MODE_LOOP;
		speed = cfg[CFG_LINK_SPEED].current;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_debug_msg,
		    "%s: Enabling ELB.", emlxs_dfc_xlate(dfc->cmd));

		/* Check if mode already set */
		if ((hba->flag & FC_ELB_MODE)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_debug_msg,
			    "%s: ELB mode already enabled.",
			    emlxs_dfc_xlate(dfc->cmd));

			return (rval);
		}

		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Invalid loopback mode. (mode=%x)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->flag);

		return (DFC_ARG_INVALID);
	}

	/* Make sure adapter is online */
	if (emlxs_online(hba)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to bring adapter online.",
		    emlxs_dfc_xlate(dfc->cmd));

		return (DFC_OFFLINE_ERROR);
	}

#ifdef MENLO_SUPPORT
	if (hba->model_info.device_id == PCI_DEVICE_ID_LP21000_M) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Menlo support detected: mode:x%x",
		    emlxs_dfc_xlate(dfc->cmd), new_mode);

		if (new_mode == FC_ILB_MODE) {
			rval = emlxs_dfc_set_menlo_loopback(hba);
			if (rval)
				goto done;
		}
	}
#endif /* MENLO_SUPPORT */

	mbq = (MAILBOXQ *)kmem_zalloc(sizeof (MAILBOXQ),
	    KM_SLEEP);

	mb = (MAILBOX *) mbq;

	/* Take the link down */
	emlxs_mb_down_link(hba, mbq);

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0);

	if (rval == MBX_TIMEOUT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Mailbox timed out. cmd=%x",
		    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

		rval = DFC_TIMEOUT;
		goto done;
	}

	if (rval) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: %s failed. status=%x", emlxs_dfc_xlate(dfc->cmd),
		    emlxs_mb_cmd_xlate(mb->mbxCommand), rval);

		rval = DFC_IO_ERROR;
		goto done;
	}

	/* Reinitialize the link */
	emlxs_mb_init_link(hba, mbq, topology, speed);

	/* Set the loopback mode and timer */
	mutex_enter(&EMLXS_PORT_LOCK);
	hba->flag |= new_mode;
	hba->loopback_tics = hba->timer_tics + emlxs_loopback_tmo;
	mutex_exit(&EMLXS_PORT_LOCK);

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0);

	if (rval == MBX_TIMEOUT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Mailbox timed out. cmd=%x",
		    emlxs_dfc_xlate(dfc->cmd), mb->mbxCommand);

		rval = DFC_TIMEOUT;
		goto done;
	}

	if (rval) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: %s failed. status=%x", emlxs_dfc_xlate(dfc->cmd),
		    emlxs_mb_cmd_xlate(mb->mbxCommand), rval);

		rval = DFC_IO_ERROR;
		goto done;
	}

	/*
	 * Wait for adapter to come online.
	 * Need *2 since we wait 1/2 sec in while loop.
	 */
	timeout = dfc->data1;
	if (!timeout) {
		timeout = 60 * 2;
	} else {
		timeout = timeout * 2;
	}

	i = 0;
	while ((hba->state < FC_LINK_UP) && (hba->state != FC_ERROR)) {
		delay(drv_usectohz(500000));
		i++;

		if (i == timeout) {
			rval = DFC_TIMEOUT;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Linkup timeout.", emlxs_dfc_xlate(dfc->cmd));

			goto done;
		}
	}

	/* Create host node */
	if (emlxs_mb_reg_did(port, port->did, (SERV_PARM *)&hba->sparam,
	    NULL, NULL, NULL)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to register host node.",
		    emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_DRV_ERROR;
		goto done;
	}

	i = 0;
	do {
		if (i++ > 300) {
			break;
		}

		delay(drv_usectohz(100000));

	} while (!(ndlp = emlxs_node_find_did(port, port->did)));

	if (!ndlp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to create host node.",
		    emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_DRV_ERROR;
		goto done;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_debug_msg,
	    "%s: Node created. node=%p", emlxs_dfc_xlate(dfc->cmd), ndlp);

#ifdef MENLO_SUPPORT
	if (hba->model_info.device_id == PCI_DEVICE_ID_LP21000_M) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Menlo support detected: mode:x%x",
		    emlxs_dfc_xlate(dfc->cmd), new_mode);

		rval = emlxs_dfc_set_menlo_fte(hba);
		if (rval)
			goto done;
	}
#endif /* MENLO_SUPPORT */

	/* Create host XRI */
	(void) emlxs_create_xri(port, &hba->chan[hba->channel_ct], ndlp);

	i = 0;
	do {
		if (i++ > 300) {
			break;
		}

		delay(drv_usectohz(100000));

	} while (!ndlp->nlp_Xri);

	if (!ndlp->nlp_Xri) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to create XRI.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_DRV_ERROR;
		goto done;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_debug_msg,
	    "%s: XRI created. xri=%x", emlxs_dfc_xlate(dfc->cmd),
	    ndlp->nlp_Xri);
done:
	/* Free allocated mbox memory */
	if (mbq) {
		kmem_free(mbq, sizeof (MAILBOXQ));
	}

	if (rval) {
resetdone:
		/* Reset the adapter */
#ifdef MENLO_SUPPORT
		if (hba->model_info.device_id == PCI_DEVICE_ID_LP21000_M) {

			rval = emlxs_dfc_reset_menlo(hba);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_debug_msg,
			    "%s: Menlo reset: rval:x%x",
			    emlxs_dfc_xlate(dfc->cmd), rval);
	}
#endif /* MENLO_SUPPORT */

		/* Reset link whether we are bound to ULP or not */
		(void) emlxs_reset_link(hba, 1, 1);
	}

	return (rval);
} /* emlxs_dfc_loopback_mode() */


static int32_t
emlxs_dfc_loopback_test(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	int32_t		rval = 0;
	NODELIST	*ndlp;
	clock_t		timeout;
	fc_packet_t	*pkt = NULL;
	SLI_CT_REQUEST	*CtCmd;
	uint16_t	CtRsp;

	if (hba->model_info.flags & EMLXS_FCOE_SUPPORTED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: FCoE not  supported.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_FCOE_NOTSUPPORTED);
	}

	mutex_enter(&EMLXS_PORT_LOCK);
	if (!(hba->flag & FC_LOOPBACK_MODE)) {
		mutex_exit(&EMLXS_PORT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Adapter not in loopback mode.",
		    emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_DRV_ERROR;
		goto done;
	}
	hba->loopback_tics = hba->timer_tics + emlxs_loopback_tmo;
	mutex_exit(&EMLXS_PORT_LOCK);

	if (!(hba->flag & FC_ONLINE_MODE)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Adapter offline.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_OFFLINE_ERROR;
		goto done;
	}

	if (hba->state < FC_LINK_UP) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Link not up.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_OFFLINE_ERROR;
		goto done;
	}

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: NULL buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	if (!dfc->buf2 || !dfc->buf2_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: NULL buffer2 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	if (dfc->buf1_size > MAX_CT_PAYLOAD) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too large. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		rval = DFC_ARG_TOOBIG;
		goto done;
	}

	/* Check if we have a node for ourselves */
	ndlp = emlxs_node_find_did(port, port->did);

	if (!ndlp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Host node not found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_INVALID;
		goto done;
	}

	if (!ndlp->nlp_Xri) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Host XRI not found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_DRV_ERROR;
		goto done;
	}

	pkt = emlxs_pkt_alloc(port, dfc->buf1_size + 16,
	    dfc->buf2_size + 16, 0, KM_SLEEP);

	if (pkt == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to allocate pkt.", emlxs_dfc_xlate(dfc->cmd));
		rval = DFC_SYSRES_ERROR;
		goto done;
	}

	CtCmd = (SLI_CT_REQUEST*)pkt->pkt_cmd;
	CtRsp = SLI_CT_LOOPBACK;
	CtCmd->CommandResponse.bits.CmdRsp = LE_SWAP16(CtRsp);

	if (ddi_copyin((void *)dfc->buf1, (void *)&CtCmd->un.data,
	    dfc->buf1_size, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYIN_ERROR;
		goto done;
	}

	pkt->pkt_tran_type = FC_PKT_OUTBOUND;
	pkt->pkt_timeout = 2 * hba->fc_ratov;
	pkt->pkt_tran_flags |= FC_TRAN_NO_INTR;
	pkt->pkt_comp = NULL;

	pkt->pkt_cmd_fhdr.d_id = port->did;
	pkt->pkt_cmd_fhdr.r_ctl = FC_SOL_CTL;
	pkt->pkt_cmd_fhdr.s_id = port->did;
	pkt->pkt_cmd_fhdr.type = FC_CT_TYPE;
	pkt->pkt_cmd_fhdr.f_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xffff;
	pkt->pkt_cmd_fhdr.rx_id = ndlp->nlp_Xri;
	pkt->pkt_cmd_fhdr.ro = 0;

	mutex_enter(&EMLXS_PKT_LOCK);
	timeout = emlxs_timeout(hba, (pkt->pkt_timeout + 15));

	if (hba->loopback_pkt) {
		rval = 0;
		while ((rval != -1) && hba->loopback_pkt) {
			rval =
			    cv_timedwait(&EMLXS_PKT_CV, &EMLXS_PKT_LOCK,
			    timeout);
		}

		if (rval == -1) {
			mutex_exit(&EMLXS_PKT_LOCK);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "Loopback busy timeout.");
			rval = DFC_TIMEOUT;
			goto done;
		}
	}
	hba->loopback_pkt = (void *) pkt;
	mutex_exit(&EMLXS_PKT_LOCK);

	/* Send polled command */
	if ((rval = emlxs_pkt_send(pkt, 1)) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "Pkt Transport error. ret=%x state=%x", rval,
		    pkt->pkt_state);

		rval = DFC_IO_ERROR;
		goto done;
	}

	if (pkt->pkt_state != FC_PKT_SUCCESS) {
		if (pkt->pkt_state == FC_PKT_TIMEOUT) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "Pkt Transport error. Pkt Timeout.");
			rval = DFC_TIMEOUT;
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "Pkt Transport error. state=%x", pkt->pkt_state);
			rval = DFC_IO_ERROR;
		}
		goto done;
	}

	/* Wait for sequence completion */
	mutex_enter(&EMLXS_PKT_LOCK);
	rval = 0;
	while ((rval != -1) && !(pkt->pkt_tran_flags & FC_TRAN_COMPLETED)) {
		rval = cv_timedwait(&EMLXS_PKT_CV, &EMLXS_PKT_LOCK, timeout);
	}
	mutex_exit(&EMLXS_PKT_LOCK);

	if (rval == -1) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "Loopback sequence timeout.");

		rval = DFC_TIMEOUT;
		goto done;
	}

	CtCmd = (SLI_CT_REQUEST*)pkt->pkt_resp;

	if (ddi_copyout((void *)&CtCmd->un.data, (void *)dfc->buf2,
	    dfc->buf2_size, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYOUT_ERROR;
		goto done;
	}

	rval = 0;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_debug_msg, "%s: Test completed.",
	    emlxs_dfc_xlate(dfc->cmd));

done:

	if (rval) {
		mutex_enter(&EMLXS_PKT_LOCK);
		if (pkt && (hba->loopback_pkt == pkt)) {
			hba->loopback_pkt = NULL;
		}
		mutex_exit(&EMLXS_PKT_LOCK);

		/* Reset the adapter */
		(void) emlxs_fca_reset(port, FC_FCA_LINK_RESET);
	}

	if (pkt) {
		emlxs_pkt_free(pkt);
	}

	return (rval);

} /* emlxs_dfc_loopback_test() */


extern int32_t
emlxs_dfc_handle_event(emlxs_hba_t *hba, CHANNEL *cp, IOCBQ *iocbq)
{
	emlxs_port_t	*port = &PPORT;
	IOCB		*cmd;
	emlxs_buf_t	*sbp;

	cmd = &iocbq->iocb;

	HBASTATS.CtEvent++;

	sbp = (emlxs_buf_t *)iocbq->sbp;

	if (!sbp) {
		HBASTATS.CtStray++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "Stray interrupt. cmd=0x%x iotag=0x%x status=0x%x "
		    "perr=0x%x", (uint32_t)cmd->ULPCOMMAND,
		    (uint32_t)cmd->ULPIOTAG, cmd->ULPSTATUS,
		    cmd->un.ulpWord[4]);

		return (DFC_ARG_INVALID);
	}

	if (cp->channelno != hba->channel_ct) {
		HBASTATS.CtStray++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "CT Event: Invalid IO Channel:%d iocbq=%p", cp->channelno,
		    iocbq);

		return (DFC_ARG_INVALID);
	}

	switch (cmd->ULPCOMMAND) {
	case CMD_XMIT_SEQUENCE_CR:
	case CMD_XMIT_SEQUENCE64_CR:
	case CMD_XMIT_SEQUENCE_CX:
	case CMD_XMIT_SEQUENCE64_CX:

		HBASTATS.CtCmdCompleted++;

		if (cmd->ULPSTATUS == 0) {
			HBASTATS.CtCmdGood++;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
			    "XMIT_SEQUENCE comp: status=0x%x",
			    cmd->ULPSTATUS);
		} else {
			HBASTATS.CtCmdError++;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "XMIT_SEQUENCE comp: status=0x%x [%08x,%08x]",
			    cmd->ULPSTATUS, cmd->un.ulpWord[4],
			    cmd->un.ulpWord[5]);
		}

		emlxs_pkt_complete(sbp, cmd->ULPSTATUS,
		    cmd->un.grsp.perr.statLocalError, 1);

		break;

	default:

		HBASTATS.CtStray++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "Invalid iocb: cmd=0x%x", cmd->ULPCOMMAND);

		emlxs_pkt_complete(sbp, cmd->ULPSTATUS,
		    cmd->un.grsp.perr.statLocalError, 1);

		break;

	}	/* switch(cmd->ULPCOMMAND) */

	return (0);

} /* emlxs_dfc_handle_event() */


/* ARGSUSED */
extern int
emlxs_dfc_handle_unsol_req(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	emlxs_hba_t	*hba = HBA;
	IOCB		*iocb;
	uint8_t		*bp;
	fc_packet_t	*pkt;

	iocb = &iocbq->iocb;
	bp = (uint8_t *)mp->virt;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "CT Receive: cmd=%x status=0x%x ",
	    iocb->ULPCOMMAND, iocb->ULPSTATUS);

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_debug_msg,
	 * "CT Receive: payload=%p size=%d [%02x,%02x, %02x, %02x]", bp,
	 * size, bp[0], bp[1], bp[2],bp[3]);
	 */

	/* Return payload */
	mutex_enter(&EMLXS_PKT_LOCK);
	if (hba->loopback_pkt) {
		pkt = (fc_packet_t *)hba->loopback_pkt;
		hba->loopback_pkt = NULL;

		size = MIN(size, pkt->pkt_rsplen);
		bcopy(bp, pkt->pkt_resp, size);
		pkt->pkt_tran_flags |= FC_TRAN_COMPLETED;

		cv_broadcast(&EMLXS_PKT_CV);
	}
	mutex_exit(&EMLXS_PKT_LOCK);

	return (0);

} /* emlxs_dfc_handle_unsol_req() */


#ifdef DHCHAP_SUPPORT

static int32_t
emlxs_dfc_init_auth(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint8_t		lwwpn[8];
	uint8_t		rwwpn[8];
	int32_t		rval = 0;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s requested.",
	    emlxs_dfc_xlate(dfc->cmd));

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < 8) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	if (!dfc->buf2 || !dfc->buf2_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer2 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf2_size < 8) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer2 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	/* Read the lwwpn */
	if (ddi_copyin((void *)dfc->buf1, (void *)&lwwpn, 8, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYIN_ERROR);
	}

	/* Read the rwwpn */
	if (ddi_copyin((void *)dfc->buf2, (void *)&rwwpn, 8, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYIN_ERROR);
	}

	/* Initiate authentication here */
	rval = emlxs_dhc_init_auth(hba, lwwpn, rwwpn);

	return (rval);

} /* emlxs_dfc_init_auth() */


static int32_t
emlxs_dfc_get_auth_cfg(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t		*port = &PPORT;
	dfc_fcsp_config_t	fcsp_config;
	uint32_t		rval = DFC_SUCCESS;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s requested.",
	    emlxs_dfc_xlate(dfc->cmd));

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < sizeof (dfc_fcsp_config_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	/* Read the fcsp_config */
	if (ddi_copyin((void *)dfc->buf1, (void *)&fcsp_config,
	    sizeof (dfc_fcsp_config_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYIN_ERROR);
	}

	if ((rval = emlxs_dhc_get_auth_cfg(hba, &fcsp_config)) != 0) {
		return (rval);
	}

	if (ddi_copyout((void *)&fcsp_config, (void *)dfc->buf1,
	    sizeof (dfc_fcsp_config_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYOUT_ERROR);
	}

	return (0);

} /* emlxs_dfc_get_auth_cfg() */



static int32_t
emlxs_dfc_set_auth_cfg(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t		*port = &PPORT;
	dfc_fcsp_config_t	fcsp_config;
	dfc_password_t		dfc_pwd;
	uint32_t		rval = DFC_SUCCESS;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s requested.",
	    emlxs_dfc_xlate(dfc->cmd));

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < sizeof (dfc_fcsp_config_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	if (!dfc->buf2 || !dfc->buf2_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer2 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf2_size < sizeof (dfc_password_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer2 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	/* Read the fcsp_config */
	if (ddi_copyin((void *)dfc->buf1, (void *)&fcsp_config,
	    sizeof (dfc_fcsp_config_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYIN_ERROR);
	}

	/* Read the password */
	if (ddi_copyin((void *)dfc->buf2, (void *)&dfc_pwd,
	    sizeof (dfc_password_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYIN_ERROR);
	}

	switch (dfc->flag) {
	case EMLXS_AUTH_CFG_ADD:
		rval = emlxs_dhc_add_auth_cfg(hba, &fcsp_config, &dfc_pwd);
		break;

	case EMLXS_AUTH_CFG_DELETE:
		rval = emlxs_dhc_delete_auth_cfg(hba, &fcsp_config, &dfc_pwd);
		break;
	}

	if (rval) {
		return (rval);
	}

	if (ddi_copyout((void *)&fcsp_config, (void *)dfc->buf1,
	    sizeof (dfc_fcsp_config_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYOUT_ERROR);
	}

	return (0);

} /* emlxs_dfc_set_auth_cfg() */



static int32_t
emlxs_dfc_get_auth_pwd(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t		*port = &PPORT;
	dfc_auth_password_t	dfc_pwd;
	uint32_t		rval = DFC_SUCCESS;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s requested.",
	    emlxs_dfc_xlate(dfc->cmd));

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < sizeof (dfc_auth_password_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}


	/* Read the auth password */
	if (ddi_copyin((void *)dfc->buf1, (void *)&dfc_pwd,
	    sizeof (dfc_auth_password_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYIN_ERROR);
	}

	if ((rval = emlxs_dhc_get_auth_key(hba, &dfc_pwd)) != 0) {
		return (rval);
	}

	if (ddi_copyout((void *)&dfc_pwd, (void *)dfc->buf1,
	    sizeof (dfc_auth_password_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYOUT_ERROR);
	}

	return (0);

} /* emlxs_dfc_get_auth_pwd() */


static int32_t
emlxs_dfc_set_auth_pwd(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t		*port = &PPORT;
	dfc_auth_password_t	dfc_pwd;
	uint32_t		rval = DFC_SUCCESS;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s requested.",
	    emlxs_dfc_xlate(dfc->cmd));

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < sizeof (dfc_auth_password_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	/* Read the auth password */
	if (ddi_copyin((void *)dfc->buf1, (void *)&dfc_pwd,
	    sizeof (dfc_auth_password_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYIN_ERROR);
	}

	if ((rval = emlxs_dhc_set_auth_key(hba, &dfc_pwd))) {
		return (rval);
	}

	if (ddi_copyout((void *)&dfc_pwd, (void *)dfc->buf1,
	    sizeof (dfc_auth_password_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYOUT_ERROR);
	}

	return (0);

} /* emlxs_dfc_set_auth_pwd() */


static int32_t
emlxs_dfc_get_auth_status(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t		*port = &PPORT;
	dfc_auth_status_t	fcsp_status;
	uint32_t		rval = DFC_SUCCESS;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s requested.",
	    emlxs_dfc_xlate(dfc->cmd));

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg, "%s: Null buffer1 found.",
		    emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < sizeof (dfc_auth_status_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg, "%s: Buffer too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	/* Read the fcsp_config */
	if (ddi_copyin((void *) dfc->buf1, (void *) &fcsp_status,
	    sizeof (dfc_auth_status_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYIN_ERROR);
	}

	if ((rval = emlxs_dhc_get_auth_status(hba, &fcsp_status)) != 0) {
		return (rval);
	}

	if (ddi_copyout((void *) &fcsp_status, (void *) dfc->buf1,
	    sizeof (dfc_auth_status_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg, "%s: ddi_copyout failed.",
		    emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYOUT_ERROR);
	}

	return (0);

} /* emlxs_dfc_get_auth_status() */


static int32_t
emlxs_dfc_get_auth_cfg_table(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t		*port = &PPORT;
	dfc_fcsp_config_t	*fcsp_cfg;
	uint32_t		count;
	uint32_t		size;
	uint32_t		rval = DFC_SUCCESS;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s requested.",
	    emlxs_dfc_xlate(dfc->cmd));

	/* Lock cfg table while we do this */
	/* This prevents the table from changing while we get a copy */
	mutex_enter(&hba->auth_lock);

	if (!dfc->buf2 || !dfc->buf2_size) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg, "%s: Null buffer2 found.",
		    emlxs_dfc_xlate(dfc->cmd));

		mutex_exit(&hba->auth_lock);
		return (DFC_ARG_NULL);
	}

	if (dfc->buf2_size < sizeof (uint32_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg, "%s: Buffer2 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf2_size);

		mutex_exit(&hba->auth_lock);
		return (DFC_ARG_TOOSMALL);
	}

	if (ddi_copyout((void *)&hba->auth_cfg_count, (void *)dfc->buf2,
	    sizeof (uint32_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed for table count. count=%d",
		    emlxs_dfc_xlate(dfc->cmd), hba->auth_cfg_count);

		mutex_exit(&hba->auth_lock);
		return (DFC_COPYOUT_ERROR);
	}

	if (!dfc->buf1 || !dfc->buf1_size) {
		mutex_exit(&hba->auth_lock);
		return (DFC_SUCCESS);
	}

	/* Check table size */
	count = dfc->buf1_size / sizeof (dfc_fcsp_config_t);
	if (count < hba->auth_cfg_count) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg, "%s: Buffer1 too small. (%d < %d)",
		    emlxs_dfc_xlate(dfc->cmd), count, hba->auth_cfg_count);

		mutex_exit(&hba->auth_lock);
		return (DFC_ARG_TOOSMALL);
	}

	size = hba->auth_cfg_count * sizeof (dfc_fcsp_config_t);

	mutex_exit(&hba->auth_lock);

	fcsp_cfg = (dfc_fcsp_config_t *)kmem_zalloc(size, KM_SLEEP);

	mutex_enter(&hba->auth_lock);

	if ((rval = emlxs_dhc_get_auth_cfg_table(hba, fcsp_cfg)) != 0) {
		mutex_exit(&hba->auth_lock);
		kmem_free(fcsp_cfg, size);
		return (rval);
	}

	mutex_exit(&hba->auth_lock);

	if (ddi_copyout((void *)fcsp_cfg, (void *)dfc->buf1, size, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg, "%s: ddi_copyout failed.",
		    emlxs_dfc_xlate(dfc->cmd));

		kmem_free(fcsp_cfg, size);
		return (DFC_COPYOUT_ERROR);
	}

	kmem_free(fcsp_cfg, size);
	return (0);

} /* emlxs_dfc_get_auth_cfg_table() */


static int32_t
emlxs_dfc_get_auth_key_table(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t		*port = &PPORT;
	dfc_auth_password_t	*auth_pwd;
	uint32_t		count;
	uint32_t		size;
	uint32_t		rval = DFC_SUCCESS;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg, "%s requested.",
	    emlxs_dfc_xlate(dfc->cmd));

	/* Lock cfg table while we do this */
	/* This prevents the table from changing while we get a copy */
	mutex_enter(&hba->auth_lock);

	if (!dfc->buf2 || !dfc->buf2_size) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg, "%s: Null buffer2 found.",
		    emlxs_dfc_xlate(dfc->cmd));

		mutex_exit(&hba->auth_lock);
		return (DFC_ARG_NULL);
	}

	if (dfc->buf2_size < sizeof (uint32_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg, "%s: Buffer2 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf2_size);

		mutex_exit(&hba->auth_lock);
		return (DFC_ARG_TOOSMALL);
	}

	if (ddi_copyout((void *)&hba->auth_key_count, (void *)dfc->buf2,
	    sizeof (uint32_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed for table count. count=%d",
		    emlxs_dfc_xlate(dfc->cmd), hba->auth_key_count);

		mutex_exit(&hba->auth_lock);
		return (DFC_COPYOUT_ERROR);
	}

	if (!dfc->buf1 || !dfc->buf1_size) {
		mutex_exit(&hba->auth_lock);
		return (DFC_SUCCESS);
	}

	/* Check table size */
	count = dfc->buf1_size / sizeof (dfc_auth_password_t);
	if (count < hba->auth_key_count) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg, "%s: Buffer1 too small. (%d < %d)",
		    emlxs_dfc_xlate(dfc->cmd), count, hba->auth_key_count);

		mutex_exit(&hba->auth_lock);
		return (DFC_ARG_TOOSMALL);
	}

	size = hba->auth_key_count * sizeof (dfc_auth_password_t);

	mutex_exit(&hba->auth_lock);

	auth_pwd = (dfc_auth_password_t *)kmem_zalloc(size, KM_SLEEP);

	mutex_enter(&hba->auth_lock);

	if ((rval = emlxs_dhc_get_auth_key_table(hba, auth_pwd)) != 0) {
		mutex_exit(&hba->auth_lock);
		kmem_free(auth_pwd, size);
		return (rval);
	}

	mutex_exit(&hba->auth_lock);

	if (ddi_copyout((void *)auth_pwd, (void *)dfc->buf1, size, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg, "%s: ddi_copyout failed.",
		    emlxs_dfc_xlate(dfc->cmd));

		kmem_free(auth_pwd, size);
		return (DFC_COPYOUT_ERROR);
	}

	kmem_free(auth_pwd, size);
	return (0);

} /* emlxs_dfc_get_auth_key_table() */



#endif	/* DHCHAP_SUPPORT */

#ifdef SAN_DIAG_SUPPORT
static int32_t
emlxs_dfc_sd_set_bucket(dfc_t *dfc, int32_t mode)
{
	uint32_t	type, search_type;
	uint16_t	state;
	int32_t		rval = DFC_SD_OK;

	type = dfc->data1;
	search_type = dfc->data2;

	mutex_enter(&sd_bucket_mutex);
	state = sd_bucket.state;
	mutex_exit(&sd_bucket_mutex);

	if (state == SD_COLLECTING)
		rval = DFC_SD_ERROR_DATA_COLLECTION_ACTIVE;
	else if ((search_type < SD_SEARCH_LINEAR) ||
	    (search_type > SD_SEARCH_POWER_2))
		rval = DFC_SD_ERROR_INVALID_ARG;
	else if (type != SD_SCSI_IO_LATENCY_TYPE)
		rval = DFC_SD_ERROR_NOT_SUPPORTED;
	else {
		(void) ddi_copyin(dfc->buf3, (void *) &sd_bucket,
		    sizeof (sd_bucket_info_t), mode);
		mutex_enter(&sd_bucket_mutex);
		sd_bucket.state = SD_STOPPED;
		mutex_exit(&sd_bucket_mutex);
	}

set_bucket_exit:
	return (rval);
}


static int32_t
emlxs_dfc_sd_destroy_bucket(dfc_t *dfc)
{
	uint32_t	type;
	int32_t 	rval = DFC_SD_OK;

	type = dfc->data1;

	mutex_enter(&sd_bucket_mutex);

	if (sd_bucket.search_type == 0)
		rval = DFC_SD_ERROR_BUCKET_NOT_SET;
	else if (sd_bucket.state == SD_COLLECTING)
		rval = DFC_SD_ERROR_DATA_COLLECTION_ACTIVE;
	else if (type != SD_SCSI_IO_LATENCY_TYPE)
		rval = DFC_SD_ERROR_NOT_SUPPORTED;
	else
		bzero((uint8_t *)&sd_bucket, sizeof (sd_bucket_info_t));

destroy_bucket_exit:
	mutex_exit(&sd_bucket_mutex);
	return (rval);
}


static int32_t
emlxs_dfc_sd_get_bucket(dfc_t *dfc, int32_t mode)
{
	uint32_t	type;
	int32_t		rval = DFC_SD_OK;

	type = dfc->data1;

	if (sd_bucket.search_type == 0)
		rval = DFC_SD_ERROR_BUCKET_NOT_SET;
	else if (type != SD_SCSI_IO_LATENCY_TYPE)
		rval = DFC_SD_ERROR_NOT_SUPPORTED;
	else
		(void) ddi_copyout(&sd_bucket, dfc->buf3,
		    sizeof (sd_bucket_info_t), mode);

	return (rval);
}


static int32_t
emlxs_dfc_sd_start_collection(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*vport;
	NODELIST	*nlp;
	uint8_t		wwpn[8];
	int32_t		rval = DFC_SD_OK;
	int		i;

	if (dfc->data1 != SD_SCSI_IO_LATENCY_TYPE) {
		rval = DFC_SD_ERROR_NOT_SUPPORTED;
		goto start_collect_exit;
	}

	if (sd_bucket.search_type == 0) {
		rval = DFC_SD_ERROR_BUCKET_NOT_SET;
		goto start_collect_exit;
	}

	/* Read the wwn object */
	(void) ddi_copyin((void *)dfc->buf3, (void *)wwpn, 8, mode);

	/* Make sure WWPN is unique */
	vport = emlxs_vport_find_wwpn(hba, wwpn);

	if (!vport) {
		rval = DFC_SD_ERROR_INVALID_PORT;
		goto start_collect_exit;
	}

	/* traverse list of nodes for this vport and reset counter */
	rw_enter(&vport->node_rwlock, RW_READER);
	if (vport->sd_io_latency_state == SD_COLLECTING) {
		rval = DFC_SD_ERROR_DATA_COLLECTION_ACTIVE;
		rw_exit(&vport->node_rwlock);
		goto start_collect_exit;
	}

	for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
		nlp = vport->node_table[i];
		while (nlp != NULL) {
			bzero((void *)&nlp->sd_dev_bucket[0],
			    sizeof (struct SD_time_stats_v0) *
			    SD_IO_LATENCY_MAX_BUCKETS);

			nlp = nlp->nlp_list_next;
		}
	}

	vport->sd_io_latency_state = SD_COLLECTING;
	rw_exit(&vport->node_rwlock);

	mutex_enter(&sd_bucket_mutex);
	sd_bucket.state = SD_COLLECTING;
	mutex_exit(&sd_bucket_mutex);

start_collect_exit:
	return (rval);
}


static int32_t
emlxs_dfc_sd_stop_collection(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*vport;
	emlxs_hba_t	*temp_hba;
	uint8_t		wwpn[8];
	int32_t		rval = DFC_SD_OK;
	int		i, j;

	if (dfc->data1 != SD_SCSI_IO_LATENCY_TYPE) {
		rval = DFC_SD_ERROR_NOT_SUPPORTED;
		goto stop_collect_exit;
	}

	if (sd_bucket.search_type == 0) {
		rval = DFC_SD_ERROR_BUCKET_NOT_SET;
		goto stop_collect_exit;
	}

	/* Read the wwn object */
	(void) ddi_copyin((void *)dfc->buf3, (void *)wwpn, 8, mode);

	/* Make sure WWPN is unique */
	vport = emlxs_vport_find_wwpn(hba, wwpn);

	if (!vport) {
		rval = DFC_SD_ERROR_INVALID_PORT;
		goto stop_collect_exit;
	}

	rw_enter(&vport->node_rwlock, RW_READER);
	if (vport->sd_io_latency_state != SD_COLLECTING) {
		rval = DFC_SD_ERROR_DATA_COLLECTION_NOT_ACTIVE;
		rw_exit(&vport->node_rwlock);
		goto stop_collect_exit;
	}
	vport->sd_io_latency_state = SD_STOPPED;
	rw_exit(&vport->node_rwlock);

	/* see if any other port is collecting io latency */
	for (i = 0; i < emlxs_device.hba_count; i++) {
		temp_hba = emlxs_device.hba[i];
		for (j = 0; j < temp_hba->num_of_ports; j++) {
			vport = &temp_hba->port[j];
			if (vport->sd_io_latency_state == SD_COLLECTING)
				goto stop_collect_exit;
		}
	}

	/*
	 * if we get here, that means no one else is collecting
	 * io latency data.
	 */
	mutex_enter(&sd_bucket_mutex);
	sd_bucket.state = SD_STOPPED;
	mutex_exit(&sd_bucket_mutex);

stop_collect_exit:
	return (rval);
}


static int32_t
emlxs_dfc_sd_reset_collection(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t   *vport;
	NODELIST	*nlp;
	uint8_t		wwpn[8];
	int32_t 	rval = DFC_SD_OK;
	int		i;

	if (dfc->data1 != SD_SCSI_IO_LATENCY_TYPE) {
		rval = DFC_SD_ERROR_NOT_SUPPORTED;
		goto reset_collect_exit;
	}

	if (sd_bucket.search_type == 0) {
		rval = DFC_SD_ERROR_BUCKET_NOT_SET;
		goto reset_collect_exit;
	}

	/* Read the wwn object */
	(void) ddi_copyin((void *)dfc->buf3, (void *)wwpn, 8, mode);

	/* Make sure WWPN is unique */
	vport = emlxs_vport_find_wwpn(hba, wwpn);

	if (!vport) {
		rval = DFC_SD_ERROR_INVALID_PORT;
		goto reset_collect_exit;
	}

	/* traverse list of nodes for this vport and reset counter */
	rw_enter(&vport->node_rwlock, RW_READER);
	for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
		nlp = vport->node_table[i];
		while (nlp != NULL) {
			bzero((void *)&nlp->sd_dev_bucket[0],
			    sizeof (struct SD_time_stats_v0) *
			    SD_IO_LATENCY_MAX_BUCKETS);

			nlp = nlp->nlp_list_next;
		}
	}
	rw_exit(&vport->node_rwlock);

reset_collect_exit:
	return (rval);
}


static int32_t
emlxs_dfc_sd_get_data(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t   *vport;
	uint8_t		wwpn[8];
	int		i, skip_bytes;
	uint16_t	count;
	uint32_t	bufsize, size_needed;
	NODELIST	*nlp;
	int32_t 	rval = DFC_SD_OK;

	if (dfc->data1 != SD_SCSI_IO_LATENCY_TYPE) {
		rval = DFC_SD_ERROR_NOT_SUPPORTED;
		goto get_data_exit;
	}

	if (sd_bucket.search_type == 0) {
		rval = DFC_SD_ERROR_BUCKET_NOT_SET;
		goto get_data_exit;
	}

	/* Read the wwn object */
	(void) ddi_copyin((void *)dfc->buf3, (void *)wwpn, 8, mode);

	/* Make sure WWPN is unique */
	vport = emlxs_vport_find_wwpn(hba, wwpn);

	if (!vport) {
		rval = DFC_SD_ERROR_INVALID_PORT;
		goto get_data_exit;
	}

	bufsize = dfc->buf4_size;

	/*
	 * count # of targets to see if buffer is big enough
	 */
	count = 0;
	rw_enter(&vport->node_rwlock, RW_READER);
	for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
		nlp = vport->node_table[i];
		while (nlp != NULL) {
			count++;
			nlp = nlp->nlp_list_next;
		}
	}
	rw_exit(&vport->node_rwlock);

	size_needed = count * (sizeof (HBA_WWN) +
	    sizeof (struct SD_time_stats_v0) * SD_IO_LATENCY_MAX_BUCKETS);

	if (bufsize < size_needed) {
		rval = DFC_SD_ERROR_MORE_DATA_AVAIL;
		goto update_count;	/* not enough space, return */
	}

	/*
	 * return data collected, reset counter.
	 */
	count = 0;
	skip_bytes = 0;
	rw_enter(&vport->node_rwlock, RW_READER);
	for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
		nlp = vport->node_table[i];
		while (nlp != NULL) {
			/* copy port name */
			(void) ddi_copyout((void *)&nlp->nlp_portname,
			    (void *)((char *)dfc->buf4 + skip_bytes),
			    sizeof (HBA_WWN), mode);
			skip_bytes += sizeof (HBA_WWN);

			/* copy bucket data */
			(void) ddi_copyout((void *)&nlp->sd_dev_bucket[0],
			    (void *)((char *)dfc->buf4 + skip_bytes),
			    sizeof (struct SD_time_stats_v0) *
			    SD_IO_LATENCY_MAX_BUCKETS, mode);
			skip_bytes += sizeof (struct SD_time_stats_v0) *
			    SD_IO_LATENCY_MAX_BUCKETS;

			bzero((void *)&nlp->sd_dev_bucket[0],
			    sizeof (struct SD_time_stats_v0) *
			    SD_IO_LATENCY_MAX_BUCKETS);

			count++;
			bufsize -= sizeof (struct SD_IO_Latency_Response);

			nlp = nlp->nlp_list_next;
		}
	}
	rw_exit(&vport->node_rwlock);

update_count:
	(void) ddi_copyout((void *)&count, (void *)dfc->buf2,
	    sizeof (uint16_t), mode);

get_data_exit:
	return (rval);
}


static int32_t
emlxs_dfc_sd_set_event(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t		*vport;
	uint8_t			wwpn[8];
	uint32_t		event, pid, enable;
	int32_t 		rval = DFC_SD_OK;
	int			i, count;
	emlxs_dfc_event_t	*dfc_event;

	/*
	 * The value of "event" has been shifted left based on
	 * the category that the application gave to libdfc.
	 *
	 * This is so the old Event handling code won't mistakenly
	 * grab an SD Event.
	 */
	event = dfc->data1;
	pid = dfc->data3;
	enable = dfc->flag;

	/* Read the wwn object */
	(void) ddi_copyin((void *)dfc->buf3, (void *)wwpn, 8, mode);

	/* Make sure WWPN is unique */
	vport = emlxs_vport_find_wwpn(hba, wwpn);

	if (!vport) {
		rval = DFC_SD_ERROR_INVALID_PORT;
		goto set_sd_event_exit;
	}

	if (enable) {
		/* Find next available event object */
		for (i = 0; i < MAX_DFC_EVENTS; i++) {
			dfc_event = &vport->sd_events[i];

			if (!dfc_event->pid && !dfc_event->event)
				break;
		}

		/* Return if all event objects are busy */
		if (i == MAX_DFC_EVENTS) {
			rval = DFC_SD_ERROR_OUT_OF_HANDLES;
			goto set_sd_event_exit;
		}

		/* Initialize */
		/* TODO: Should we add SUBCAT in dfc_event ??? */
		dfc_event->pid = pid;
		dfc_event->event = event;
		dfc_event->last_id = (uint32_t)-1;
		dfc_event->dataout = NULL;
		dfc_event->size = 0;
		dfc_event->mode = 0;

		(void) emlxs_get_sd_event(vport, dfc_event, 0);

		if (dfc->buf1)
			(void) ddi_copyout((void *) &dfc_event->last_id,
			    dfc->buf1, sizeof (uint32_t), mode);

		vport->sd_event_mask |= event;
	} else { /* Disable */
		/* find event entry */
		for (i = 0; i < MAX_DFC_EVENTS; i++) {
			dfc_event = &vport->sd_events[i];

			if (dfc_event->pid  == pid && dfc_event->event == event)
				break;
		}

		/* Return if not found */
		if (i == MAX_DFC_EVENTS) {
			rval = DFC_SD_ERROR_INVALID_ARG;
			goto set_sd_event_exit;
		}

		/* Kill the event thread if it is sleeping */
		(void) emlxs_kill_dfc_event(vport, dfc_event);

		/* Count the number of pids still registered for this event */
		count = 0;
		for (i = 0; i < MAX_DFC_EVENTS; i++) {
			dfc_event = &vport->sd_events[i];

			if (dfc_event->event == event)
				count++;
		}

		/*
		 * If no more pids need this event,
		 * then disable logging for this event
		 */
		if (count == 0)
			vport->sd_event_mask &= ~event;
	}

set_sd_event_exit:
	return (rval);
} /* emlxs_dfc_sd_set_event */


static int32_t
emlxs_dfc_sd_get_event(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t   *vport;
	uint8_t		wwpn[8];
	uint32_t	event, pid, sleep, i;
	int32_t		rval = DFC_SD_OK;
	emlxs_dfc_event_t *dfc_event;

	event = dfc->data1;
	pid = dfc->data2;

	/* Read the wwn object */
	(void) ddi_copyin((void *)dfc->buf4, (void *)wwpn, 8, mode);

	/* Make sure WWPN is unique */
	vport = emlxs_vport_find_wwpn(hba, wwpn);

	if (!vport) {
		rval = DFC_SD_ERROR_INVALID_PORT;
		goto get_sd_event_exit;
	}

	/* Find the event entry */
	dfc_event = NULL;
	for (i = 0; i < MAX_DFC_EVENTS; i++) {
		dfc_event = &vport->sd_events[i];

		if (dfc_event->pid == pid && dfc_event->event == event)
			break;
	}

	if (i == MAX_DFC_EVENTS) {
		rval = DFC_SD_ERROR_GENERIC;
		goto get_sd_event_exit;
	}

	if (!(vport->sd_event_mask & dfc_event->event)) {
		rval = DFC_SD_ERROR_GENERIC;
		goto get_sd_event_exit;
	}

	/* Initialize event buffer pointers */
	dfc_event->dataout = dfc->buf1;
	dfc_event->size = dfc->buf1_size;
	dfc_event->last_id = dfc->data3;
	dfc_event->mode = mode;

	sleep = (dfc->flag & 0x01) ? 1 : 0;

	if (emlxs_get_sd_event(vport, dfc_event, sleep))
		return (DFC_SD_ERROR_GENERIC);

	/*
	 * update rcv_size.
	 */
	if (dfc->buf2)
		(void) ddi_copyout((void *) &dfc_event->size, dfc->buf2,
		    sizeof (uint32_t), mode);

	/*
	 * update index
	 */
	if (dfc->buf3)
		(void) ddi_copyout((void *) &dfc_event->last_id, dfc->buf3,
		    sizeof (uint32_t), mode);

get_sd_event_exit:
	return (rval);
} /* emlxs_dfc_sd_get_event */
#endif

static int32_t
emlxs_dfc_send_scsi_fcp(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t			*port = &PPORT;
	fc_packet_t			*pkt = NULL;
	NODELIST			*ndlp;
	FCP_CMND			*fcp_cmd;
	FCP_RSP				*fcp_rsp;
	void				*ptr;
	char				buffer[64];
	dfc_send_scsi_fcp_cmd_info_t	cmdinfo;
	uint32_t			rval = 0;

	/* cmd info */
	if (!dfc->buf1 ||
	    (dfc->buf1_size != sizeof (dfc_send_scsi_fcp_cmd_info_t))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	/* reqBuffer info */
	if (!dfc->buf2 || (dfc->buf2_size != sizeof (FCP_CMND))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer2 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	/* rspBuffer info, could be 0 for SCSI commands like TUR */
	if (!dfc->buf3 && dfc->buf3_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer3 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	/* senseBuffer info */
	if (!dfc->buf4 || !dfc->buf4_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer4 found.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_ARG_NULL;
		goto done;
	}

	if (ddi_copyin((void *) dfc->buf1, (void *) &cmdinfo,
	    sizeof (dfc_send_scsi_fcp_cmd_info_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYIN_ERROR;
		goto done;
	}

	if (cmdinfo.ver == DFC_SEND_SCSI_FCP_V2) {
		port =
		    emlxs_vport_find_wwpn(hba, (uint8_t *)&cmdinfo.src_wwn);
		if (port == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: WWPN does not exists. %s",
			    emlxs_dfc_xlate(dfc->cmd), emlxs_wwn_xlate(buffer,
			    (uint8_t *)&cmdinfo.src_wwn));

			rval = DFC_ARG_INVALID;
			goto done;
		}
	}

	if ((ndlp = emlxs_node_find_wwpn(port,
	    (uint8_t *)&cmdinfo.dst_wwn)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: WWPN does not exists. %s", emlxs_dfc_xlate(dfc->cmd),
		    emlxs_wwn_xlate(buffer, (uint8_t *)&cmdinfo.dst_wwn));

		rval = DFC_ARG_INVALID;
		goto done;
	}

	if (!(pkt = emlxs_pkt_alloc(port, sizeof (FCP_CMND), sizeof (FCP_RSP),
	    dfc->buf3_size, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Unable to allocate packet.",
		    emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_SYSRES_ERROR;
		goto done;
	}
	fcp_cmd = (FCP_CMND *) pkt->pkt_cmd;
	/* Copy in the command buffer */
	if (ddi_copyin((void *)dfc->buf2, (void *)fcp_cmd, sizeof (FCP_CMND),
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYIN_ERROR;
		goto done;
	}

	/* Make this a polled IO */
	pkt->pkt_tran_flags &= ~FC_TRAN_INTR;
	pkt->pkt_tran_flags |= FC_TRAN_NO_INTR;
	pkt->pkt_comp = NULL;

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(ndlp->nlp_DID);
	pkt->pkt_cmd_fhdr.r_ctl = FC_FCP_CMND;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(port->did);
	pkt->pkt_cmd_fhdr.type = FC_FCP_DATA;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.rx_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.ro = 0;

	pkt->pkt_timeout = 30;

	if ((fcp_cmd->fcpCntl3 == WRITE_DATA) && dfc->buf3_size) {
		pkt->pkt_tran_type = FC_PKT_FCP_WRITE;
		if (ddi_copyin((void *)dfc->buf3, (void *)pkt->pkt_data,
		    dfc->buf3_size, mode) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: ddi_copyin failed.",
			    emlxs_dfc_xlate(dfc->cmd));

			rval = DFC_COPYIN_ERROR;
			goto done;
		}
	} else {
		pkt->pkt_tran_type = FC_PKT_FCP_READ;
	}

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		rval = DFC_IO_ERROR;
		goto done;
	}

	if (pkt->pkt_state != FC_PKT_SUCCESS) {
		if (pkt->pkt_state == FC_PKT_TIMEOUT) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "Pkt Transport error. Pkt Timeout.");
			rval = DFC_TIMEOUT;
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "Pkt Transport error. state=%x", pkt->pkt_state);
			rval = DFC_IO_ERROR;
		}
		goto done;
	}

	if (pkt->pkt_data_resid) {
		if (pkt->pkt_data_resid < dfc->buf3_size)
			dfc->buf3_size -= pkt->pkt_data_resid;
		else
			dfc->buf3_size = 0;
	}

	SCSI_RSP_CNT(cmdinfo) = dfc->buf3_size;

	fcp_rsp = (FCP_RSP *) pkt->pkt_resp;
	/*
	 * This is sense count for flag = 0.
	 * It is fcp response size for flag = 1.
	 */
	if (dfc->flag) {
		SCSI_SNS_CNT(cmdinfo) = 24 + LE_SWAP32(fcp_rsp->rspSnsLen) +
		    LE_SWAP32(fcp_rsp->rspRspLen);
		ptr = (void *)fcp_rsp;
	} else {
		SCSI_SNS_CNT(cmdinfo) = LE_SWAP32(fcp_rsp->rspSnsLen);
		ptr = (void *)&fcp_rsp->rspSnsInfo[0];
	}

	if (ddi_copyout((void *) &cmdinfo, (void *) dfc->buf1,
	    sizeof (dfc_send_scsi_fcp_cmd_info_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: rsp_buf ddi_copyout failed.",
		    emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYOUT_ERROR;
		goto done;
	}

	if (SCSI_SNS_CNT(cmdinfo)) {
		if (ddi_copyout(ptr, (void *)dfc->buf4, SCSI_SNS_CNT(cmdinfo),
		    mode) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: rsp_size ddi_copyout failed.",
			    emlxs_dfc_xlate(dfc->cmd));

			rval = DFC_COPYOUT_ERROR;
			goto done;
		}
	}

	if (SCSI_RSP_CNT(cmdinfo)) {
		if (ddi_copyout((void *)pkt->pkt_data, (void *)dfc->buf3,
		    SCSI_RSP_CNT(cmdinfo), mode) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: rsp_size ddi_copyout failed.",
			    emlxs_dfc_xlate(dfc->cmd));

			rval = DFC_COPYOUT_ERROR;
			goto done;
		}
	}


	rval = 0;

done:
	if (pkt) {
		emlxs_pkt_free(pkt);
	}

	return (rval);

} /* emlxs_dfc_send_scsi_fcp() */


static int32_t
emlxs_dfc_get_persist_linkdown(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t		*port = &PPORT;
	emlxs_config_t		*cfg = &CFG;
	uint16_t		linkdown = 0;
	uint32_t		rval = 0;

	if (hba->model_info.flags & EMLXS_FCOE_SUPPORTED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: FCoE not  supported.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_FCOE_NOTSUPPORTED);
	}

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	linkdown = (uint16_t)cfg[CFG_PERSIST_LINKDOWN].current;
	if (ddi_copyout((void *)&linkdown, dfc->buf1, dfc->buf1_size,
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_COPYOUT_ERROR);
	}

	return (rval);

} /* emlxs_dfc_get_persist_linkdown() */


/*ARGSUSED*/
static int32_t
emlxs_dfc_set_persist_linkdown(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t		*port = &PPORT;
	emlxs_config_t		*cfg = &CFG;
	uint32_t		rval = 0;

	if (hba->model_info.flags & EMLXS_FCOE_SUPPORTED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: FCoE not  supported.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_FCOE_NOTSUPPORTED);
	}

	if (dfc->data1) {
		cfg[CFG_PERSIST_LINKDOWN].current = 1;
	} else {
		cfg[CFG_PERSIST_LINKDOWN].current = 0;
	}

	return (rval);

} /* emlxs_dfc_set_persist_linkdown() */


static int32_t
emlxs_dfc_get_fcflist(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t		*port = &PPORT;
	DFC_FCoEFCFInfo_t	*fcflistentry;
	DFC_FCoEFCFList_t	*fcflist;
	FCFIobj_t		*fcfp;
	uint32_t		size;
	uint32_t		i;
	uint32_t		count = 0;
	uint32_t		rval = 0;

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (dfc->buf1_size < sizeof (DFC_FCoEFCFList_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Buffer1 too small. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_TOOSMALL);
	}

	if (! (hba->model_info.flags & EMLXS_FCOE_SUPPORTED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: FCoE not  supported.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_FCOE_NOTSUPPORTED);
	}

	if (hba->state != FC_READY) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: HBA not ready.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_DRV_ERROR);
	}

	size = sizeof (DFC_FCoEFCFList_t) +
	    hba->sli.sli4.fcftab.table_count * sizeof (DFC_FCoEFCFInfo_t);
	fcflist = (DFC_FCoEFCFList_t *)kmem_zalloc(size, KM_SLEEP);

	if (ddi_copyin(dfc->buf1, (void *)fcflist,
	    sizeof (DFC_FCoEFCFList_t), mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYIN_ERROR;
		goto done;
	}

	fcflistentry = fcflist->entries;
	mutex_enter(&EMLXS_FCF_LOCK);
	fcfp = hba->sli.sli4.fcftab.table;
	for (i = 0; i < hba->sli.sli4.fcftab.table_count; i++, fcfp++) {
		if ((fcfp->state != FCFI_STATE_FREE) &&
		    (fcfp->fcf_rec.fcf_valid)) {
			fcflistentry->Priority = fcfp->fcf_rec.fip_priority;
			if (fcfp->fcf_rec.fcf_available) {
				fcflistentry->State = FCF_AVAILABLE_STATE;
			}
			fcflistentry->LKA_Period = fcfp->fcf_rec.fka_adv_period;

			bcopy((void *)fcfp->fcf_rec.vlan_bitmap,
			    (void *)fcflistentry->VLanBitMap, 512);
			bcopy((void *)fcfp->fcf_rec.fc_map,
			    (void *)fcflistentry->FC_Map, 3);
			bcopy((void *)fcfp->fcf_rec.fabric_name_identifier,
			    (void *)fcflistentry->FabricName, 8);
			bcopy((void *)fcfp->fcf_rec.switch_name_identifier,
			    (void *)fcflistentry->SwitchName, 8);
			bcopy((void *)&fcfp->fcf_rec.fcf_mac_address_hi,
			    (void *)fcflistentry->Mac, 6);

			count++;
			fcflistentry++;
		}
	}
	mutex_exit(&EMLXS_FCF_LOCK);

	fcflist->nActiveFCFs = hba->sli.sli4.fcftab.fcfi_count;

	if (count > fcflist->numberOfEntries) {
		rval = DFC_ARG_TOOSMALL;
	}

	i = sizeof (DFC_FCoEFCFList_t) +
	    (fcflist->numberOfEntries - 1) * sizeof (DFC_FCoEFCFInfo_t);
	fcflist->numberOfEntries = (uint16_t)count;

	if (ddi_copyout((void *) fcflist, dfc->buf1,
	    i, mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYOUT_ERROR;
		goto done;
	}

done:
	kmem_free(fcflist, size);
	return (rval);

} /* emlxs_dfc_get_fcflist() */


static int32_t
emlxs_dfc_send_mbox4(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	MAILBOX4	*mb4 = NULL;
	MAILBOXQ	*mbq = NULL;
	MBUF_INFO	bufinfo;
	uint32_t	offset;
	int32_t		mbxstatus = 0;
	uint32_t	rval = 0;

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if (!dfc->buf2 || !dfc->buf2_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer2 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	if ((dfc->buf1_size != sizeof (MAILBOX4)) &&
	    (dfc->buf2_size != sizeof (MAILBOX4))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Invalid buffer size. (size=%d)",
		    emlxs_dfc_xlate(dfc->cmd), dfc->buf1_size);

		return (DFC_ARG_INVALID);
	}

	if (dfc->buf3_size && !dfc->buf3) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: NULL buffer3 found.",
		    emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_INVALID);
	}

	if (! (hba->model_info.flags & EMLXS_FCOE_SUPPORTED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: FCoE not  supported.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_FCOE_NOTSUPPORTED);
	}

	bzero(&bufinfo, sizeof (MBUF_INFO));
	if (dfc->buf3_size) {
		bufinfo.size = dfc->buf3_size;
		bufinfo.flags = FC_MBUF_DMA | FC_MBUF_SNGLSG | FC_MBUF_DMA32;
		bufinfo.align = ddi_ptob(hba->dip, 1L);
		(void) emlxs_mem_alloc(hba, &bufinfo);

		if (bufinfo.virt == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: Unable to allocate buffer.",
			    emlxs_dfc_xlate(dfc->cmd));

			rval = DFC_SYSRES_ERROR;
			goto done;
		}

		if (ddi_copyin((void *)dfc->buf3, (void *)bufinfo.virt,
		    dfc->buf3_size, mode) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: ddi_copyin failed", emlxs_dfc_xlate(dfc->cmd));

			rval = DFC_COPYIN_ERROR;
			goto done;
		}
	}

	mbq =
	    (MAILBOXQ *)kmem_zalloc(sizeof (MAILBOXQ), KM_SLEEP);

	mb4 = (MAILBOX4 *) mbq;

	bzero((void *)mb4, sizeof (MAILBOX4));

	if (ddi_copyin((void *)dfc->buf1, (void *)mb4, dfc->buf1_size,
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyin failed.", emlxs_dfc_xlate(dfc->cmd));

		rval = DFC_COPYIN_ERROR;
		goto done;
	}

	if (dfc->buf3_size) {
		offset = dfc->data3;
		mb4->un.varWords[offset-1] = PADDR_LO(bufinfo.phys);
		mb4->un.varWords[offset] = PADDR_HI(bufinfo.phys);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "%s: %s sent.  (%x %x %x %x)", emlxs_dfc_xlate(dfc->cmd),
	    emlxs_mb_cmd_xlate(mb4->mbxCommand), mb4->un.varWords[0],
	    mb4->un.varWords[1], mb4->un.varWords[2], mb4->un.varWords[3]);

	/* issue the mbox cmd to the sli */
	mbxstatus = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0);

	if (mbxstatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: %s failed. mbxstatus=0x%x",
		    emlxs_dfc_xlate(dfc->cmd),
		    emlxs_mb_cmd_xlate(mb4->mbxCommand), mbxstatus);
	}

	if (ddi_copyout((void *)mb4, (void *)dfc->buf2, dfc->buf2_size,
	    mode) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: ddi_copyout failed. cmd=%x",
		    emlxs_dfc_xlate(dfc->cmd), mb4->mbxCommand);

		rval = DFC_COPYOUT_ERROR;
		goto done;
	}

	if (dfc->buf3_size) {
		if (ddi_copyout((void *)bufinfo.virt, (void *)dfc->buf3,
		    dfc->buf3_size, mode) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: ddi_copyout failed. cmd=%x",
			    emlxs_dfc_xlate(dfc->cmd), mb4->mbxCommand);

			rval = DFC_COPYOUT_ERROR;
			goto done;
		}
	}
done:
	/* Free allocated memory */
	if (bufinfo.virt) {
		emlxs_mem_free(hba, &bufinfo);
	}

	if (mbq) {
		kmem_free(mbq, sizeof (MAILBOXQ));
	}

	return (rval);
} /* emlxs_dfc_send_mbox4() */


static int
emlxs_dfc_rd_be_fcf(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t			*port = &PPORT;
	MATCHMAP			*mp;
	MAILBOX4			*mb  = NULL;
	MAILBOXQ			*mbq = NULL;
	IOCTL_FCOE_READ_FCF_TABLE	*fcf;
	mbox_req_hdr_t			*hdr_req;
	mbox_rsp_hdr_t			*hdr_rsp;
	FCF_RECORD_t			*fcfrec;
	uint32_t			rc = 0;
	uint32_t			rval = 0;
	uint16_t			index;

	if (!dfc->buf1 || !dfc->buf1_size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: Null buffer1 found.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_ARG_NULL);
	}

	mbq =
	    (MAILBOXQ *)kmem_zalloc(sizeof (MAILBOXQ), KM_SLEEP);

	index = dfc->data1;
	mb = (MAILBOX4 *)mbq;

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF, 1)) == 0) {
		rval = DFC_SYSRES_ERROR;
		goto done;
	}
	bzero(mp->virt, mp->size);

	/*
	 * Signifies a non-embedded command
	 */
	mb->un.varSLIConfig.be.embedded = 0;
	mbq->nonembed = (void *)mp;
	mbq->mbox_cmpl = NULL;

	mb->mbxCommand = MBX_SLI_CONFIG;
	mb->mbxOwner = OWN_HOST;

	hdr_req = (mbox_req_hdr_t *)mp->virt;
	hdr_rsp = (mbox_rsp_hdr_t *)mp->virt;

	hdr_req->subsystem = IOCTL_SUBSYSTEM_FCOE;
	hdr_req->opcode = FCOE_OPCODE_READ_FCF_TABLE;
	hdr_req->timeout = 0;
	hdr_req->req_length = sizeof (IOCTL_FCOE_READ_FCF_TABLE);
	fcf = (IOCTL_FCOE_READ_FCF_TABLE *)(hdr_req + 1);
	fcf->params.request.fcf_index = index;

	rc =  EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0);
	if (rc == MBX_SUCCESS) {
		fcfrec = &fcf->params.response.fcf_entry[0];
		if (ddi_copyout((void *)fcfrec, (void *)dfc->buf1,
		    dfc->buf1_size, mode) != 0) {
			rval = DFC_COPYOUT_ERROR;
		}
		if (ddi_copyout(
		    (void *)&fcf->params.response.next_valid_fcf_index,
		    (void *)dfc->buf2, dfc->buf2_size, mode) != 0) {
			rval = DFC_COPYOUT_ERROR;
		}
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: %s failed. mbxstatus=0x%x", emlxs_dfc_xlate(dfc->cmd),
		    emlxs_mb_cmd_xlate(mb->mbxCommand), rc);

		if ((rc == MBX_NONEMBED_ERROR) &&
		    (hdr_rsp->status == MBX_RSP_STATUS_NO_FCF)) {
			rval = DFC_FCOE_NO_DATA;
		} else {
			rval = DFC_IO_ERROR;
		}
	}
done:
	if (mp)
		emlxs_mem_put(hba, MEM_BUF, (void *)mp);
	if (mbq)
		kmem_free(mbq, sizeof (MAILBOXQ));

	return (rval);
}


/*ARGSUSED*/
static int
emlxs_dfc_set_be_dcbx(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t				*port = &PPORT;
	MAILBOXQ				*mbq = NULL;
	MAILBOX4				*mb;
	IOCTL_DCBX_SET_DCBX_MODE		*dcbx_mode;
	uint32_t				port_num = 0;
	uint32_t				rval = 0;

	mbq =
	    (MAILBOXQ *)kmem_zalloc(sizeof (MAILBOXQ), KM_SLEEP);

	mb = (MAILBOX4 *)mbq;

	/*
	 * Signifies an embedded command
	 */
	mb->un.varSLIConfig.be.embedded = 1;
	mbq->mbox_cmpl = NULL;

	mb->mbxCommand = MBX_SLI_CONFIG;
	mb->mbxOwner = OWN_HOST;
	mb->un.varSLIConfig.be.payload_length = IOCTL_HEADER_SZ;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
	    IOCTL_SUBSYSTEM_DCBX;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.opcode =
	    DCBX_OPCODE_SET_DCBX_MODE;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
	    sizeof (IOCTL_DCBX_SET_DCBX_MODE);
	dcbx_mode = (IOCTL_DCBX_SET_DCBX_MODE *)&mb->un.varSLIConfig.payload;
	dcbx_mode->params.request.port_num = (uint8_t)port_num;
	dcbx_mode->params.request.dcbx_mode = dfc->data1;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "%s requested on port %d.", emlxs_dfc_xlate(dfc->cmd), port_num);
	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0);
	if (rval != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: %s failed. mbxstatus=0x%x", emlxs_dfc_xlate(dfc->cmd),
		    emlxs_mb_cmd_xlate(mb->mbxCommand), rval);

		rval = DFC_DRV_ERROR;
	}

done:
	if (mbq)
		kmem_free(mbq, sizeof (MAILBOXQ));

	return (rval);
}


static int
emlxs_dfc_get_be_dcbx(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t				*port = &PPORT;
	MAILBOXQ				*mbq = NULL;
	MAILBOX4				*mb;
	IOCTL_DCBX_GET_DCBX_MODE		*dcbx_mode;
	uint32_t				port_num = 0;
	uint32_t				rval = 0;

	mbq =
	    (MAILBOXQ *)kmem_zalloc(sizeof (MAILBOXQ), KM_SLEEP);

	mb = (MAILBOX4 *)mbq;

	/*
	 * Signifies an embedded command
	 */
	mb->un.varSLIConfig.be.embedded = 1;
	mbq->mbox_cmpl = NULL;

	mb->mbxCommand = MBX_SLI_CONFIG;
	mb->mbxOwner = OWN_HOST;
	mb->un.varSLIConfig.be.payload_length = IOCTL_HEADER_SZ;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
	    IOCTL_SUBSYSTEM_DCBX;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.opcode =
	    DCBX_OPCODE_GET_DCBX_MODE;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
	    sizeof (IOCTL_DCBX_SET_DCBX_MODE);
	dcbx_mode = (IOCTL_DCBX_GET_DCBX_MODE *)&mb->un.varSLIConfig.payload;
	dcbx_mode->params.request.port_num = (uint8_t)port_num;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_detail_msg,
	    "%s requested on port %d.", emlxs_dfc_xlate(dfc->cmd), port_num);
	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0);
	if (rval != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: %s failed. mbxstatus=0x%x", emlxs_dfc_xlate(dfc->cmd),
		    emlxs_mb_cmd_xlate(mb->mbxCommand), rval);

		rval = DFC_DRV_ERROR;
		goto done;
	}

	if (ddi_copyout((void *)&dcbx_mode->params.response.dcbx_mode,
	    (void *)dfc->buf1, dfc->buf1_size, mode) != 0) {
		rval = DFC_COPYOUT_ERROR;
	}

done:
	if (mbq)
		kmem_free(mbq, sizeof (MAILBOXQ));

	return (rval);
}


static int
emlxs_dfc_get_qos(emlxs_hba_t *hba, dfc_t *dfc, int32_t mode)
{
	emlxs_port_t	*port = &PPORT;
	uint32_t	rval = 0;

	if (! (hba->model_info.flags & EMLXS_FCOE_SUPPORTED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "%s: FCoE not  supported.", emlxs_dfc_xlate(dfc->cmd));

		return (DFC_FCOE_NOTSUPPORTED);
	}

	if (dfc->buf1_size) {
		if (ddi_copyout((void *)&hba->qos_linkspeed, (void *)dfc->buf1,
		    dfc->buf1_size, mode) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
			    "%s: ddi_copyout failed.",
			    emlxs_dfc_xlate(dfc->cmd));

			rval = DFC_COPYOUT_ERROR;
			return (rval);
		}
	}

	return (rval);

} /* emlxs_dfc_get_qos() */
