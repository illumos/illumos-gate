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

/* Copyright 2015 QLogic Corporation */

/*
 * Copyright (c) 2008, 2011, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * ISP2xxx Solaris Fibre Channel Adapter (FCA) driver source file.
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2015 QLOGIC CORPORATION		**
 * *			ALL RIGHTS RESERVED				**
 * *									**
 * ***********************************************************************
 *
 */

#include <ql_apps.h>
#include <ql_api.h>
#include <ql_debug.h>
#include <ql_init.h>
#include <ql_iocb.h>
#include <ql_ioctl.h>
#include <ql_mbx.h>
#include <ql_nx.h>
#include <ql_xioctl.h>

/*
 * Local data
 */

/*
 * Local prototypes
 */
static int ql_sdm_ioctl(ql_adapter_state_t *, int, void *, int);
static int ql_sdm_setup(ql_adapter_state_t *, EXT_IOCTL **, void *, int,
    boolean_t (*)(EXT_IOCTL *));
static boolean_t ql_validate_signature(EXT_IOCTL *);
static int ql_sdm_return(ql_adapter_state_t *, EXT_IOCTL *, void *, int);
static void ql_query(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_qry_hba_node(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_qry_hba_port(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_qry_disc_port(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_qry_disc_tgt(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_qry_fw(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_qry_chip(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_qry_driver(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_fcct(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_aen_reg(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_aen_get(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_scsi_passthru(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_wwpn_to_scsiaddr(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_host_idx(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_host_drvname(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_read_nvram(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_write_nvram(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_read_flash(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_write_flash(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_write_vpd(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_read_vpd(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_diagnostic_loopback(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_send_els_rnid(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_set_host_data(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_get_host_data(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_qry_cna_port(ql_adapter_state_t *, EXT_IOCTL *, int);

static int ql_lun_count(ql_adapter_state_t *, ql_tgt_t *);
static int ql_report_lun(ql_adapter_state_t *, ql_tgt_t *);
static int ql_inq_scan(ql_adapter_state_t *, ql_tgt_t *, int);
static int ql_inq(ql_adapter_state_t *, ql_tgt_t *, int, ql_mbx_iocb_t *,
    uint32_t);
static uint32_t	ql_get_buffer_data(caddr_t, caddr_t, uint32_t, int);
static uint32_t ql_send_buffer_data(caddr_t, caddr_t, uint32_t, int);
static int ql_24xx_flash_desc(ql_adapter_state_t *);
static int ql_setup_flash(ql_adapter_state_t *);
static ql_tgt_t *ql_find_port(ql_adapter_state_t *, uint8_t *, uint16_t);
static int ql_flash_fcode_load(ql_adapter_state_t *, void *, uint32_t, int);
static int ql_flash_fcode_dump(ql_adapter_state_t *, void *, uint32_t,
    uint32_t, int);
static int ql_program_flash_address(ql_adapter_state_t *, uint32_t,
    uint8_t);
static void ql_set_rnid_parameters(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_get_rnid_parameters(ql_adapter_state_t *, EXT_IOCTL *, int);
static int ql_reset_statistics(ql_adapter_state_t *, EXT_IOCTL *);
static void ql_get_statistics(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_get_statistics_fc(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_get_statistics_fc4(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_set_led_state(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_get_led_state(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_drive_led(ql_adapter_state_t *, uint32_t);
static int ql_setup_led(ql_adapter_state_t *);
static int ql_wrapup_led(ql_adapter_state_t *);
static void ql_get_port_summary(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_get_target_id(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_get_sfp(ql_adapter_state_t *, EXT_IOCTL *, int);
static int ql_dump_sfp(ql_adapter_state_t *, void *, int);
static ql_fcache_t *ql_setup_fnode(ql_adapter_state_t *);
static void ql_get_fcache(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_get_fcache_ex(ql_adapter_state_t *, EXT_IOCTL *, int);
void ql_update_fcache(ql_adapter_state_t *, uint8_t *, uint32_t);
static int ql_check_pci(ql_adapter_state_t *, ql_fcache_t *, uint32_t *);
static void ql_flash_layout_table(ql_adapter_state_t *, uint32_t);
static void ql_process_flt(ql_adapter_state_t *, uint32_t);
static void ql_flash_nvram_defaults(ql_adapter_state_t *);
static void ql_port_param(ql_adapter_state_t *, EXT_IOCTL *, int);
static int ql_check_pci(ql_adapter_state_t *, ql_fcache_t *, uint32_t *);
static void ql_get_pci_data(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_get_fwfcetrace(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_get_fwexttrace(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_menlo_reset(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_menlo_get_fw_version(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_menlo_update_fw(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_menlo_manage_info(ql_adapter_state_t *, EXT_IOCTL *, int);
static int ql_suspend_hba(ql_adapter_state_t *, uint32_t);
static void ql_restart_hba(ql_adapter_state_t *);
static void ql_get_vp_cnt_id(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_vp_ioctl(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_qry_vport(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_access_flash(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_reset_cmd(ql_adapter_state_t *, EXT_IOCTL *);
static void ql_update_flash_caches(ql_adapter_state_t *);
static void ql_get_dcbx_parameters(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_get_xgmac_statistics(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_get_fcf_list(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_get_resource_counts(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_qry_adapter_versions(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_get_temperature(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_dump_cmd(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_serdes_reg(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_serdes_reg_ex(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_els_passthru(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_flash_update_caps(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_get_bbcr_data(ql_adapter_state_t *, EXT_IOCTL *, int);
static void ql_get_priv_stats(ql_adapter_state_t *, EXT_IOCTL *, int);

/* ******************************************************************** */
/*			External IOCTL support.				*/
/* ******************************************************************** */

/*
 * ql_alloc_xioctl_resource
 *	Allocates resources needed by module code.
 *
 * Input:
 *	ha:		adapter state pointer.
 *
 * Returns:
 *	SYS_ERRNO
 *
 * Context:
 *	Kernel context.
 */
int
ql_alloc_xioctl_resource(ql_adapter_state_t *ha)
{
	ql_xioctl_t	*xp;

	QL_PRINT_9(ha, "started\n");

	if (ha->xioctl != NULL) {
		QL_PRINT_9(ha, "already allocated done\n",
		    ha->instance);
		return (0);
	}

	xp = kmem_zalloc(sizeof (ql_xioctl_t), KM_SLEEP);
	if (xp == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		return (ENOMEM);
	}
	ha->xioctl = xp;

	/* Allocate AEN tracking buffer */
	xp->aen_tracking_queue = kmem_zalloc(EXT_DEF_MAX_AEN_QUEUE *
	    sizeof (EXT_ASYNC_EVENT), KM_SLEEP);
	if (xp->aen_tracking_queue == NULL) {
		EL(ha, "failed, kmem_zalloc-2\n");
		ql_free_xioctl_resource(ha);
		return (ENOMEM);
	}

	QL_PRINT_9(ha, "done\n");

	return (0);
}

/*
 * ql_free_xioctl_resource
 *	Frees resources used by module code.
 *
 * Input:
 *	ha:		adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
void
ql_free_xioctl_resource(ql_adapter_state_t *ha)
{
	ql_xioctl_t	*xp = ha->xioctl;

	QL_PRINT_9(ha, "started\n");

	if (xp == NULL) {
		QL_PRINT_9(ha, "already freed\n");
		return;
	}

	if (xp->aen_tracking_queue != NULL) {
		kmem_free(xp->aen_tracking_queue, EXT_DEF_MAX_AEN_QUEUE *
		    sizeof (EXT_ASYNC_EVENT));
		xp->aen_tracking_queue = NULL;
	}

	kmem_free(xp, sizeof (ql_xioctl_t));
	ha->xioctl = NULL;

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_xioctl
 *	External IOCTL processing.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	function to perform
 *	arg:	data type varies with request
 *	mode:	flags
 *	cred_p:	credentials pointer
 *	rval_p:	pointer to result value
 *
 * Returns:
 *	0:		success
 *	ENXIO:		No such device or address
 *	ENOPROTOOPT:	Protocol not available
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
int
ql_xioctl(ql_adapter_state_t *ha, int cmd, intptr_t arg, int mode,
    cred_t *cred_p, int *rval_p)
{
	int	rval;

	QL_PRINT_9(ha, "started, cmd=%d\n", cmd);

	if (ha->xioctl == NULL) {
		QL_PRINT_9(ha, "no context\n");
		return (ENXIO);
	}

	switch (cmd) {
	case EXT_CC_QUERY:
	case EXT_CC_SEND_FCCT_PASSTHRU:
	case EXT_CC_REG_AEN:
	case EXT_CC_GET_AEN:
	case EXT_CC_SEND_SCSI_PASSTHRU:
	case EXT_CC_WWPN_TO_SCSIADDR:
	case EXT_CC_SEND_ELS_RNID:
	case EXT_CC_SET_DATA:
	case EXT_CC_GET_DATA:
	case EXT_CC_HOST_IDX:
	case EXT_CC_READ_NVRAM:
	case EXT_CC_UPDATE_NVRAM:
	case EXT_CC_READ_OPTION_ROM:
	case EXT_CC_READ_OPTION_ROM_EX:
	case EXT_CC_UPDATE_OPTION_ROM:
	case EXT_CC_UPDATE_OPTION_ROM_EX:
	case EXT_CC_GET_VPD:
	case EXT_CC_SET_VPD:
	case EXT_CC_LOOPBACK:
	case EXT_CC_GET_FCACHE:
	case EXT_CC_GET_FCACHE_EX:
	case EXT_CC_HOST_DRVNAME:
	case EXT_CC_GET_SFP_DATA:
	case EXT_CC_PORT_PARAM:
	case EXT_CC_GET_PCI_DATA:
	case EXT_CC_GET_FWEXTTRACE:
	case EXT_CC_GET_FWFCETRACE:
	case EXT_CC_GET_VP_CNT_ID:
	case EXT_CC_VPORT_CMD:
	case EXT_CC_ACCESS_FLASH:
	case EXT_CC_RESET_FW:
	case EXT_CC_MENLO_MANAGE_INFO:
	case EXT_CC_I2C_DATA:
	case EXT_CC_DUMP:
	case EXT_CC_SERDES_REG_OP:
	case EXT_CC_VF_STATE:
	case EXT_CC_SERDES_REG_OP_EX:
	case EXT_CC_ELS_PASSTHRU_OS:
	case EXT_CC_FLASH_UPDATE_CAPS_OS:
	case EXT_CC_GET_BBCR_DATA_OS:
		rval = ql_sdm_ioctl(ha, cmd, (void *)arg, mode);
		break;
	default:
		/* function not supported. */
		EL(ha, "function=%d not supported\n", cmd);
		rval = ENOPROTOOPT;
	}

	QL_PRINT_9(ha, "done\n");

	return (rval);
}

/*
 * ql_sdm_ioctl
 *	Provides ioctl functions for SAN/Device Management functions
 *	AKA External Ioctl functions.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	ioctl_code:	ioctl function to perform
 *	arg:		Pointer to EXT_IOCTL cmd data in application land.
 *	mode:		flags
 *
 * Returns:
 *	0:	success
 *	ENOMEM:	Alloc of local EXT_IOCTL struct failed.
 *	EFAULT:	Copyin of caller's EXT_IOCTL struct failed or
 *		copyout of EXT_IOCTL status info failed.
 *	EINVAL:	Signature or version of caller's EXT_IOCTL invalid.
 *	EBUSY:	Device busy
 *
 * Context:
 *	Kernel context.
 */
static int
ql_sdm_ioctl(ql_adapter_state_t *ha, int ioctl_code, void *arg, int mode)
{
	EXT_IOCTL		*cmd;
	int			rval;
	ql_adapter_state_t	*vha;

	QL_PRINT_9(ha, "started\n");

	/* Copy argument structure (EXT_IOCTL) from application land. */
	if ((rval = ql_sdm_setup(ha, &cmd, arg, mode,
	    ql_validate_signature)) != 0) {
		/*
		 * a non-zero value at this time means a problem getting
		 * the requested information from application land, just
		 * return the error code and hope for the best.
		 */
		EL(ha, "failed, sdm_setup\n");
		return (rval);
	}

	/*
	 * Map the physical ha ptr (which the ioctl is called with)
	 * to the virtual ha that the caller is addressing.
	 */
	if (ha->flags & VP_ENABLED) {
		/* Check that it is within range. */
		if (cmd->HbaSelect > ha->max_vports) {
			EL(ha, "Invalid HbaSelect vp index: %xh\n",
			    cmd->HbaSelect);
			cmd->Status = EXT_STATUS_INVALID_VPINDEX;
			cmd->ResponseLen = 0;
			return (EFAULT);
		}
		/*
		 * Special case: HbaSelect == 0 is physical ha
		 */
		if (cmd->HbaSelect != 0) {
			vha = ha->vp_next;
			while (vha != NULL) {
				if (vha->vp_index == cmd->HbaSelect) {
					ha = vha;
					break;
				}
				vha = vha->vp_next;
			}
			/*
			 * The specified vp index may be valid(within range)
			 * but it's not in the list. Currently this is all
			 * we can say.
			 */
			if (vha == NULL || !(vha->flags & VP_ENABLED)) {
				cmd->Status = EXT_STATUS_INVALID_VPINDEX;
				cmd->ResponseLen = 0;
				return (EFAULT);
			}
		}
	}

	/*
	 * If driver is suspended, stalled, or powered down rtn BUSY
	 */
	if (ha->flags & ADAPTER_SUSPENDED ||
	    (ha->task_daemon_flags & (DRIVER_STALL | ISP_ABORT_NEEDED |
	    ABORT_ISP_ACTIVE | LOOP_RESYNC_NEEDED | LOOP_RESYNC_ACTIVE)) ||
	    ha->power_level != PM_LEVEL_D0) {
		EL(ha, " %s\n", ha->flags & ADAPTER_SUSPENDED ?
		    "driver suspended" :
		    (ha->task_daemon_flags & (DRIVER_STALL | ISP_ABORT_NEEDED |
		    ABORT_ISP_ACTIVE | LOOP_RESYNC_NEEDED |
		    LOOP_RESYNC_ACTIVE) ? "driver stalled" :
		    "FCA powered down"));
		cmd->Status = EXT_STATUS_BUSY;
		cmd->ResponseLen = 0;
		rval = EBUSY;

		/* Return results to caller */
		if ((ql_sdm_return(ha, cmd, arg, mode)) == -1) {
			EL(ha, "failed, sdm_return\n");
			rval = EFAULT;
		}
		return (rval);
	}

	switch (ioctl_code) {
	case EXT_CC_QUERY_OS:
		ql_query(ha, cmd, mode);
		break;
	case EXT_CC_SEND_FCCT_PASSTHRU_OS:
		ql_fcct(ha, cmd, mode);
		break;
	case EXT_CC_REG_AEN_OS:
		ql_aen_reg(ha, cmd, mode);
		break;
	case EXT_CC_GET_AEN_OS:
		ql_aen_get(ha, cmd, mode);
		break;
	case EXT_CC_GET_DATA_OS:
		ql_get_host_data(ha, cmd, mode);
		break;
	case EXT_CC_SET_DATA_OS:
		ql_set_host_data(ha, cmd, mode);
		break;
	case EXT_CC_SEND_ELS_RNID_OS:
		ql_send_els_rnid(ha, cmd, mode);
		break;
	case EXT_CC_SCSI_PASSTHRU_OS:
		ql_scsi_passthru(ha, cmd, mode);
		break;
	case EXT_CC_WWPN_TO_SCSIADDR_OS:
		ql_wwpn_to_scsiaddr(ha, cmd, mode);
		break;
	case EXT_CC_HOST_IDX_OS:
		ql_host_idx(ha, cmd, mode);
		break;
	case EXT_CC_HOST_DRVNAME_OS:
		ql_host_drvname(ha, cmd, mode);
		break;
	case EXT_CC_READ_NVRAM_OS:
		ql_read_nvram(ha, cmd, mode);
		break;
	case EXT_CC_UPDATE_NVRAM_OS:
		ql_write_nvram(ha, cmd, mode);
		break;
	case EXT_CC_READ_OPTION_ROM_OS:
	case EXT_CC_READ_OPTION_ROM_EX_OS:
		ql_read_flash(ha, cmd, mode);
		break;
	case EXT_CC_UPDATE_OPTION_ROM_OS:
	case EXT_CC_UPDATE_OPTION_ROM_EX_OS:
		ql_write_flash(ha, cmd, mode);
		break;
	case EXT_CC_LOOPBACK_OS:
		ql_diagnostic_loopback(ha, cmd, mode);
		break;
	case EXT_CC_GET_VPD_OS:
		ql_read_vpd(ha, cmd, mode);
		break;
	case EXT_CC_SET_VPD_OS:
		ql_write_vpd(ha, cmd, mode);
		break;
	case EXT_CC_GET_FCACHE_OS:
		ql_get_fcache(ha, cmd, mode);
		break;
	case EXT_CC_GET_FCACHE_EX_OS:
		ql_get_fcache_ex(ha, cmd, mode);
		break;
	case EXT_CC_GET_SFP_DATA_OS:
		ql_get_sfp(ha, cmd, mode);
		break;
	case EXT_CC_PORT_PARAM_OS:
		ql_port_param(ha, cmd, mode);
		break;
	case EXT_CC_GET_PCI_DATA_OS:
		ql_get_pci_data(ha, cmd, mode);
		break;
	case EXT_CC_GET_FWEXTTRACE_OS:
		ql_get_fwexttrace(ha, cmd, mode);
		break;
	case EXT_CC_GET_FWFCETRACE_OS:
		ql_get_fwfcetrace(ha, cmd, mode);
		break;
	case EXT_CC_MENLO_RESET:
		ql_menlo_reset(ha, cmd, mode);
		break;
	case EXT_CC_MENLO_GET_FW_VERSION:
		ql_menlo_get_fw_version(ha, cmd, mode);
		break;
	case EXT_CC_MENLO_UPDATE_FW:
		ql_menlo_update_fw(ha, cmd, mode);
		break;
	case EXT_CC_MENLO_MANAGE_INFO:
		ql_menlo_manage_info(ha, cmd, mode);
		break;
	case EXT_CC_GET_VP_CNT_ID_OS:
		ql_get_vp_cnt_id(ha, cmd, mode);
		break;
	case EXT_CC_VPORT_CMD_OS:
		ql_vp_ioctl(ha, cmd, mode);
		break;
	case EXT_CC_ACCESS_FLASH_OS:
		ql_access_flash(ha, cmd, mode);
		break;
	case EXT_CC_RESET_FW_OS:
		ql_reset_cmd(ha, cmd);
		break;
	case EXT_CC_I2C_DATA:
		ql_get_temperature(ha, cmd, mode);
		break;
	case EXT_CC_DUMP_OS:
		ql_dump_cmd(ha, cmd, mode);
		break;
	case EXT_CC_SERDES_REG_OP:
		ql_serdes_reg(ha, cmd, mode);
		break;
	case EXT_CC_SERDES_REG_OP_EX:
		ql_serdes_reg_ex(ha, cmd, mode);
		break;
	case EXT_CC_ELS_PASSTHRU_OS:
		ql_els_passthru(ha, cmd, mode);
		break;
	case EXT_CC_FLASH_UPDATE_CAPS_OS:
		ql_flash_update_caps(ha, cmd, mode);
		break;
	case EXT_CC_GET_BBCR_DATA_OS:
		ql_get_bbcr_data(ha, cmd, mode);
		break;
	default:
		/* function not supported. */
		EL(ha, "failed, function not supported=%d\n", ioctl_code);

		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		cmd->ResponseLen = 0;
		break;
	}

	/* Return results to caller */
	if (ql_sdm_return(ha, cmd, arg, mode) == -1) {
		EL(ha, "failed, sdm_return\n");
		return (EFAULT);
	}

	QL_PRINT_9(ha, "done\n");

	return (0);
}

/*
 * ql_sdm_setup
 *	Make a local copy of the EXT_IOCTL struct and validate it.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	cmd_struct:	Pointer to location to store local adrs of EXT_IOCTL.
 *	arg:		Address of application EXT_IOCTL cmd data
 *	mode:		flags
 *	val_sig:	Pointer to a function to validate the ioctl signature.
 *
 * Returns:
 *	0:		success
 *	EFAULT:		Copy in error of application EXT_IOCTL struct.
 *	EINVAL:		Invalid version, signature.
 *	ENOMEM:		Local allocation of EXT_IOCTL failed.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_sdm_setup(ql_adapter_state_t *ha, EXT_IOCTL **cmd_struct, void *arg,
    int mode, boolean_t (*val_sig)(EXT_IOCTL *))
{
	int		rval;
	EXT_IOCTL	*cmd;

	QL_PRINT_9(ha, "started\n");

	/* Allocate local memory for EXT_IOCTL. */
	*cmd_struct = NULL;
	cmd = (EXT_IOCTL *)kmem_zalloc(sizeof (EXT_IOCTL), KM_SLEEP);
	if (cmd == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		return (ENOMEM);
	}
	/* Get argument structure. */
	rval = ddi_copyin(arg, (void *)cmd, sizeof (EXT_IOCTL), mode);
	if (rval != 0) {
		EL(ha, "failed, ddi_copyin\n");
		rval = EFAULT;
	} else {
		/*
		 * Check signature and the version.
		 * If either are not valid then neither is the
		 * structure so don't attempt to return any error status
		 * because we can't trust what caller's arg points to.
		 * Just return the errno.
		 */
		if (val_sig(cmd) == 0) {
			EL(ha, "failed, signature\n");
			rval = EINVAL;
		} else if (cmd->Version > EXT_VERSION) {
			EL(ha, "failed, version\n");
			rval = EINVAL;
		}
	}

	if (rval == 0) {
		QL_PRINT_9(ha, "done\n");
		*cmd_struct = cmd;
		cmd->Status = EXT_STATUS_OK;
		cmd->DetailStatus = 0;
	} else {
		kmem_free((void *)cmd, sizeof (EXT_IOCTL));
	}

	return (rval);
}

/*
 * ql_validate_signature
 *	Validate the signature string for an external ioctl call.
 *
 * Input:
 *	sg:	Pointer to EXT_IOCTL signature to validate.
 *
 * Returns:
 *	B_TRUE:		Signature is valid.
 *	B_FALSE:	Signature is NOT valid.
 *
 * Context:
 *	Kernel context.
 */
static boolean_t
ql_validate_signature(EXT_IOCTL *cmd_struct)
{
	/*
	 * Check signature.
	 *
	 * If signature is not valid then neither is the rest of
	 * the structure (e.g., can't trust it), so don't attempt
	 * to return any error status other than the errno.
	 */
	if (bcmp(&cmd_struct->Signature, "QLOGIC", 6) != 0) {
		QL_PRINT_2(NULL, "failed,\n");
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * ql_sdm_return
 *	Copies return data/status to application land for
 *	ioctl call using the SAN/Device Management EXT_IOCTL call interface.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	cmd:		Pointer to kernel copy of requestor's EXT_IOCTL struct.
 *	ioctl_code:	ioctl function to perform
 *	arg:		EXT_IOCTL cmd data in application land.
 *	mode:		flags
 *
 * Returns:
 *	0:	success
 *	EFAULT:	Copy out error.
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
static int
ql_sdm_return(ql_adapter_state_t *ha, EXT_IOCTL *cmd, void *arg, int mode)
{
	int	rval = 0;

	QL_PRINT_9(ha, "started\n");

	rval |= ddi_copyout((void *)&cmd->ResponseLen,
	    (void *)&(((EXT_IOCTL*)arg)->ResponseLen), sizeof (uint32_t),
	    mode);

	rval |= ddi_copyout((void *)&cmd->Status,
	    (void *)&(((EXT_IOCTL*)arg)->Status),
	    sizeof (cmd->Status), mode);
	rval |= ddi_copyout((void *)&cmd->DetailStatus,
	    (void *)&(((EXT_IOCTL*)arg)->DetailStatus),
	    sizeof (cmd->DetailStatus), mode);

	kmem_free((void *)cmd, sizeof (EXT_IOCTL));

	if (rval != 0) {
		/* Some copyout operation failed */
		EL(ha, "failed, ddi_copyout\n");
		return (EFAULT);
	}

	QL_PRINT_9(ha, "done\n");

	return (0);
}

/*
 * ql_query
 *	Performs all EXT_CC_QUERY functions.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_query(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	QL_PRINT_9(ha, "started, cmd=%d\n",
	    cmd->SubCode);

	/* case off on command subcode */
	switch (cmd->SubCode) {
	case EXT_SC_QUERY_HBA_NODE:
		ql_qry_hba_node(ha, cmd, mode);
		break;
	case EXT_SC_QUERY_HBA_PORT:
		ql_qry_hba_port(ha, cmd, mode);
		break;
	case EXT_SC_QUERY_DISC_PORT:
		ql_qry_disc_port(ha, cmd, mode);
		break;
	case EXT_SC_QUERY_DISC_TGT:
		ql_qry_disc_tgt(ha, cmd, mode);
		break;
	case EXT_SC_QUERY_DRIVER:
		ql_qry_driver(ha, cmd, mode);
		break;
	case EXT_SC_QUERY_FW:
		ql_qry_fw(ha, cmd, mode);
		break;
	case EXT_SC_QUERY_CHIP:
		ql_qry_chip(ha, cmd, mode);
		break;
	case EXT_SC_QUERY_CNA_PORT:
		ql_qry_cna_port(ha, cmd, mode);
		break;
	case EXT_SC_QUERY_ADAPTER_VERSIONS:
		ql_qry_adapter_versions(ha, cmd, mode);
		break;
	case EXT_SC_QUERY_DISC_LUN:
	default:
		/* function not supported. */
		cmd->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		EL(ha, "failed, Unsupported Subcode=%xh\n",
		    cmd->SubCode);
		break;
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_qry_hba_node
 *	Performs EXT_SC_QUERY_HBA_NODE subfunction.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_qry_hba_node(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_HBA_NODE	tmp_node = {0};
	uint_t		len;
	caddr_t		bufp;

	QL_PRINT_9(ha, "started\n");

	if (cmd->ResponseLen < sizeof (EXT_HBA_NODE)) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = sizeof (EXT_HBA_NODE);
		EL(ha, "failed, ResponseLen < EXT_HBA_NODE, "
		    "Len=%xh\n", cmd->ResponseLen);
		cmd->ResponseLen = 0;
		return;
	}

	/* fill in the values */

	bcopy(ha->loginparams.node_ww_name.raw_wwn, tmp_node.WWNN,
	    EXT_DEF_WWN_NAME_SIZE);

	(void) sprintf((char *)(tmp_node.Manufacturer), "QLogic Corporation");

	(void) sprintf((char *)(tmp_node.Model), "%x", ha->device_id);

	bcopy(&tmp_node.WWNN[5], tmp_node.SerialNum, 3);

	(void) sprintf((char *)(tmp_node.DriverVersion), QL_VERSION);

	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		size_t		verlen;
		uint16_t	w;
		char		*tmpptr;

		verlen = strlen((char *)(tmp_node.DriverVersion));
		if (verlen + 5 > EXT_DEF_MAX_STR_SIZE) {
			EL(ha, "failed, No room for fpga version string\n");
		} else {
			w = (uint16_t)ddi_get16(ha->sbus_fpga_dev_handle,
			    (uint16_t *)
			    (ha->sbus_fpga_iobase + FPGA_REVISION));

			tmpptr = (char *)&(tmp_node.DriverVersion[verlen + 1]);
			if (tmpptr == NULL) {
				EL(ha, "Unable to insert fpga version str\n");
			} else {
				(void) sprintf(tmpptr, "%d.%d",
				    ((w & 0xf0) >> 4), (w & 0x0f));
				tmp_node.DriverAttr |= EXT_CC_HBA_NODE_SBUS;
			}
		}
	}

	(void) sprintf((char *)(tmp_node.FWVersion), "%01d.%02d.%02d",
	    ha->fw_major_version, ha->fw_minor_version,
	    ha->fw_subminor_version);

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_1)) {
		switch (ha->fw_attributes) {
		case FWATTRIB_EF:
			(void) strcat((char *)(tmp_node.FWVersion), " EF");
			break;
		case FWATTRIB_TP:
			(void) strcat((char *)(tmp_node.FWVersion), " TP");
			break;
		case FWATTRIB_IP:
			(void) strcat((char *)(tmp_node.FWVersion), " IP");
			break;
		case FWATTRIB_IPX:
			(void) strcat((char *)(tmp_node.FWVersion), " IPX");
			break;
		case FWATTRIB_FL:
			(void) strcat((char *)(tmp_node.FWVersion), " FL");
			break;
		case FWATTRIB_FPX:
			(void) strcat((char *)(tmp_node.FWVersion), " FLX");
			break;
		default:
			break;
		}
	}

	/* FCode version. */
	/*LINTED [Solaris DDI_DEV_T_ANY Lint error]*/
	if (ddi_getlongprop(DDI_DEV_T_ANY, ha->dip, PROP_LEN_AND_VAL_ALLOC |
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, "version", (caddr_t)&bufp,
	    (int *)&len) == DDI_PROP_SUCCESS) {
		if (len < EXT_DEF_MAX_STR_SIZE) {
			bcopy(bufp, tmp_node.OptRomVersion, len);
		} else {
			bcopy(bufp, tmp_node.OptRomVersion,
			    EXT_DEF_MAX_STR_SIZE - 1);
			tmp_node.OptRomVersion[EXT_DEF_MAX_STR_SIZE - 1] =
			    '\0';
		}
		kmem_free(bufp, len);
	} else {
		(void) sprintf((char *)tmp_node.OptRomVersion, "0");
	}
	tmp_node.PortCount = 1;
	tmp_node.InterfaceType = EXT_DEF_FC_INTF_TYPE;

	tmp_node.MpiVersion[0] = ha->mpi_fw_major_version;
	tmp_node.MpiVersion[1] = ha->mpi_fw_minor_version;
	tmp_node.MpiVersion[2] = ha->mpi_fw_subminor_version;
	tmp_node.PepFwVersion[0] = ha->phy_fw_major_version;
	tmp_node.PepFwVersion[1] = ha->phy_fw_minor_version;
	tmp_node.PepFwVersion[2] = ha->phy_fw_subminor_version;
	if (ddi_copyout((void *)&tmp_node,
	    (void *)(uintptr_t)(cmd->ResponseAdr),
	    sizeof (EXT_HBA_NODE), mode) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, ddi_copyout\n");
	} else {
		cmd->ResponseLen = sizeof (EXT_HBA_NODE);
		QL_PRINT_9(ha, "done\n");
	}
}

/*
 * ql_qry_hba_port
 *	Performs EXT_SC_QUERY_HBA_PORT subfunction.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_qry_hba_port(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	ql_link_t	*link;
	ql_tgt_t	*tq;
	ql_mbx_data_t	mr = {0};
	EXT_HBA_PORT	tmp_port = {0};
	int		rval;
	uint16_t	port_cnt, tgt_cnt, index;

	QL_PRINT_9(ha, "started\n");

	if (cmd->ResponseLen < sizeof (EXT_HBA_PORT)) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = sizeof (EXT_HBA_PORT);
		EL(ha, "failed, ResponseLen < EXT_HBA_NODE, Len=%xh\n",
		    cmd->ResponseLen);
		cmd->ResponseLen = 0;
		return;
	}

	/* fill in the values */

	bcopy(ha->loginparams.nport_ww_name.raw_wwn, tmp_port.WWPN,
	    EXT_DEF_WWN_NAME_SIZE);
	tmp_port.Id[0] = 0;
	tmp_port.Id[1] = ha->d_id.b.domain;
	tmp_port.Id[2] = ha->d_id.b.area;
	tmp_port.Id[3] = ha->d_id.b.al_pa;

	/* For now we are initiator only driver */
	tmp_port.Type = EXT_DEF_INITIATOR_DEV;

	if (ha->task_daemon_flags & LOOP_DOWN) {
		tmp_port.State = EXT_DEF_HBA_LOOP_DOWN;
	} else if (DRIVER_SUSPENDED(ha)) {
		tmp_port.State = EXT_DEF_HBA_SUSPENDED;
	} else {
		tmp_port.State = EXT_DEF_HBA_OK;
	}

	if (ha->flags & POINT_TO_POINT) {
		tmp_port.Mode = EXT_DEF_P2P_MODE;
	} else {
		tmp_port.Mode = EXT_DEF_LOOP_MODE;
	}
	/*
	 * fill in the portspeed values.
	 *
	 * default to not yet negotiated state
	 */
	tmp_port.PortSpeed = EXT_PORTSPEED_NOT_NEGOTIATED;

	if (tmp_port.State == EXT_DEF_HBA_OK) {
		switch (ha->iidma_rate) {
		case IIDMA_RATE_1GB:
			tmp_port.PortSpeed = EXT_DEF_PORTSPEED_1GBIT;
			break;
		case IIDMA_RATE_2GB:
			tmp_port.PortSpeed = EXT_DEF_PORTSPEED_2GBIT;
			break;
		case IIDMA_RATE_4GB:
			tmp_port.PortSpeed = EXT_DEF_PORTSPEED_4GBIT;
			break;
		case IIDMA_RATE_8GB:
			tmp_port.PortSpeed = EXT_DEF_PORTSPEED_8GBIT;
			break;
		case IIDMA_RATE_10GB:
			tmp_port.PortSpeed = EXT_DEF_PORTSPEED_10GBIT;
			break;
		case IIDMA_RATE_16GB:
			tmp_port.PortSpeed = EXT_DEF_PORTSPEED_16GBIT;
			break;
		case IIDMA_RATE_32GB:
			tmp_port.PortSpeed = EXT_DEF_PORTSPEED_32GBIT;
			break;
		default:
			tmp_port.PortSpeed = EXT_DEF_PORTSPEED_UNKNOWN;
			EL(ha, "failed, data rate=%xh\n", mr.mb[1]);
			break;
		}
	}

	/* Report all supported port speeds */
	if (CFG_IST(ha, CFG_CTRL_25XX)) {
		tmp_port.PortSupportedSpeed = (EXT_DEF_PORTSPEED_8GBIT |
		    EXT_DEF_PORTSPEED_4GBIT | EXT_DEF_PORTSPEED_2GBIT |
		    EXT_DEF_PORTSPEED_1GBIT);
		/*
		 * Correct supported speeds based on type of
		 * sfp that is present
		 */
		switch (ha->sfp_stat) {
		case 1:
			/* no sfp detected */
			break;
		case 2:
		case 4:
			/* 4GB sfp */
			tmp_port.PortSupportedSpeed &=
			    ~EXT_DEF_PORTSPEED_8GBIT;
			break;
		case 3:
		case 5:
			/* 8GB sfp */
			tmp_port.PortSupportedSpeed &=
			    ~EXT_DEF_PORTSPEED_1GBIT;
			break;
		default:
			EL(ha, "sfp_stat: %xh\n", ha->sfp_stat);
			break;

		}
	} else if (CFG_IST(ha, CFG_FCOE_SUPPORT)) {
		tmp_port.PortSupportedSpeed = EXT_DEF_PORTSPEED_10GBIT;
	} else if (CFG_IST(ha, CFG_CTRL_24XX)) {
		tmp_port.PortSupportedSpeed = (EXT_DEF_PORTSPEED_4GBIT |
		    EXT_DEF_PORTSPEED_2GBIT | EXT_DEF_PORTSPEED_1GBIT);
	} else if (CFG_IST(ha, CFG_CTRL_23XX)) {
		tmp_port.PortSupportedSpeed = (EXT_DEF_PORTSPEED_2GBIT |
		    EXT_DEF_PORTSPEED_1GBIT);
	} else if (CFG_IST(ha, CFG_CTRL_63XX)) {
		tmp_port.PortSupportedSpeed = EXT_DEF_PORTSPEED_2GBIT;
	} else if (CFG_IST(ha, CFG_CTRL_22XX)) {
		tmp_port.PortSupportedSpeed = EXT_DEF_PORTSPEED_1GBIT;
	} else if (CFG_IST(ha, CFG_CTRL_83XX)) {
		tmp_port.PortSupportedSpeed = EXT_DEF_PORTSPEED_4GBIT |
		    EXT_DEF_PORTSPEED_8GBIT | EXT_DEF_PORTSPEED_16GBIT;
	} else if (CFG_IST(ha, CFG_CTRL_27XX)) {
		tmp_port.PortSupportedSpeed = EXT_DEF_PORTSPEED_4GBIT |
		    EXT_DEF_PORTSPEED_8GBIT | EXT_DEF_PORTSPEED_16GBIT |
		    EXT_DEF_PORTSPEED_32GBIT;
	} else {
		tmp_port.PortSupportedSpeed = EXT_DEF_PORTSPEED_UNKNOWN;
		EL(ha, "unknown HBA type: %xh\n", ha->device_id);
	}

	if (ha->task_daemon_flags & LOOP_DOWN) {
		(void) ql_get_firmware_state(ha, NULL);
	}

	tmp_port.LinkState1 = ha->fw_state[1];
	tmp_port.LinkState2 = LSB(ha->sfp_stat);
	tmp_port.LinkState3 = ha->fw_state[3];
	tmp_port.LinkState6 = ha->fw_state[6];

	port_cnt = 0;
	tgt_cnt = 0;

	for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
		for (link = ha->dev[index].first; link != NULL;
		    link = link->next) {
			tq = link->base_address;

			if (!VALID_TARGET_ID(ha, tq->loop_id) ||
			    tq->d_id.b24 == FS_MANAGEMENT_SERVER) {
				continue;
			}

			if (tq->flags & (TQF_RSCN_RCVD | TQF_IIDMA_NEEDED |
			    TQF_NEED_AUTHENTICATION | TQF_PLOGI_PROGRS)) {
				continue;
			}

			port_cnt++;
			if ((tq->flags & TQF_INITIATOR_DEVICE) == 0) {
				tgt_cnt++;
			}
		}
	}

	tmp_port.DiscPortCount = port_cnt;
	tmp_port.DiscTargetCount = tgt_cnt;

	tmp_port.DiscPortNameType = EXT_DEF_USE_NODE_NAME;

	rval = ddi_copyout((void *)&tmp_port,
	    (void *)(uintptr_t)(cmd->ResponseAdr),
	    sizeof (EXT_HBA_PORT), mode);
	if (rval != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, ddi_copyout\n");
	} else {
		cmd->ResponseLen = sizeof (EXT_HBA_PORT);
		QL_PRINT_9(ha, "done, ports=%d, targets=%d\n",
		    ha->instance, port_cnt, tgt_cnt);
	}
}

/*
 * ql_qry_disc_port
 *	Performs EXT_SC_QUERY_DISC_PORT subfunction.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 *	cmd->Instance = Port instance in fcport chain.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_qry_disc_port(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_DISC_PORT	tmp_port = {0};
	ql_link_t	*link;
	ql_tgt_t	*tq;
	uint16_t	index;
	uint16_t	inst = 0;

	QL_PRINT_9(ha, "started\n");

	if (cmd->ResponseLen < sizeof (EXT_DISC_PORT)) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = sizeof (EXT_DISC_PORT);
		EL(ha, "failed, ResponseLen < EXT_DISC_PORT, Len=%xh\n",
		    cmd->ResponseLen);
		cmd->ResponseLen = 0;
		return;
	}

	for (link = NULL, index = 0;
	    index < DEVICE_HEAD_LIST_SIZE && link == NULL; index++) {
		for (link = ha->dev[index].first; link != NULL;
		    link = link->next) {
			tq = link->base_address;

			if (!VALID_TARGET_ID(ha, tq->loop_id) ||
			    tq->d_id.b24 == FS_MANAGEMENT_SERVER) {
				continue;
			}

			if (tq->flags & (TQF_RSCN_RCVD | TQF_IIDMA_NEEDED |
			    TQF_NEED_AUTHENTICATION | TQF_PLOGI_PROGRS)) {
				continue;
			}

			if (inst != cmd->Instance) {
				inst++;
				continue;
			}

			/* fill in the values */
			bcopy(tq->node_name, tmp_port.WWNN,
			    EXT_DEF_WWN_NAME_SIZE);
			bcopy(tq->port_name, tmp_port.WWPN,
			    EXT_DEF_WWN_NAME_SIZE);

			break;
		}
	}

	if (link == NULL) {
		/* no matching device */
		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		EL(ha, "failed, port not found port=%d\n", cmd->Instance);
		cmd->ResponseLen = 0;
		return;
	}

	tmp_port.Id[0] = 0;
	tmp_port.Id[1] = tq->d_id.b.domain;
	tmp_port.Id[2] = tq->d_id.b.area;
	tmp_port.Id[3] = tq->d_id.b.al_pa;

	tmp_port.Type = 0;
	if (tq->flags & TQF_INITIATOR_DEVICE) {
		tmp_port.Type = (uint16_t)(tmp_port.Type |
		    EXT_DEF_INITIATOR_DEV);
	} else if ((tq->flags & TQF_TAPE_DEVICE) == 0) {
		(void) ql_inq_scan(ha, tq, 1);
	} else if (tq->flags & TQF_TAPE_DEVICE) {
		tmp_port.Type = (uint16_t)(tmp_port.Type | EXT_DEF_TAPE_DEV);
	}

	if (tq->flags & TQF_FABRIC_DEVICE) {
		tmp_port.Type = (uint16_t)(tmp_port.Type | EXT_DEF_FABRIC_DEV);
	} else {
		tmp_port.Type = (uint16_t)(tmp_port.Type | EXT_DEF_TARGET_DEV);
	}

	tmp_port.Status = 0;
	tmp_port.Bus = 0;  /* Hard-coded for Solaris */

	bcopy(tq->port_name, &tmp_port.TargetId, 8);

	if (ddi_copyout((void *)&tmp_port,
	    (void *)(uintptr_t)(cmd->ResponseAdr),
	    sizeof (EXT_DISC_PORT), mode) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, ddi_copyout\n");
	} else {
		cmd->ResponseLen = sizeof (EXT_DISC_PORT);
		QL_PRINT_9(ha, "done\n");
	}
}

/*
 * ql_qry_disc_tgt
 *	Performs EXT_SC_QUERY_DISC_TGT subfunction.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	cmd:		EXT_IOCTL cmd struct pointer.
 *	mode:		flags.
 *
 *	cmd->Instance = Port instance in fcport chain.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_qry_disc_tgt(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_DISC_TARGET	tmp_tgt = {0};
	ql_link_t	*link;
	ql_tgt_t	*tq;
	uint16_t	index;
	uint16_t	inst = 0;

	QL_PRINT_9(ha, "started, target=%d\n",
	    cmd->Instance);

	if (cmd->ResponseLen < sizeof (EXT_DISC_TARGET)) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = sizeof (EXT_DISC_TARGET);
		EL(ha, "failed, ResponseLen < EXT_DISC_TARGET, Len=%xh\n",
		    cmd->ResponseLen);
		cmd->ResponseLen = 0;
		return;
	}

	/* Scan port list for requested target and fill in the values */
	for (link = NULL, index = 0;
	    index < DEVICE_HEAD_LIST_SIZE && link == NULL; index++) {
		for (link = ha->dev[index].first; link != NULL;
		    link = link->next) {
			tq = link->base_address;

			if (!VALID_TARGET_ID(ha, tq->loop_id) ||
			    tq->flags & TQF_INITIATOR_DEVICE ||
			    tq->d_id.b24 == FS_MANAGEMENT_SERVER) {
				continue;
			}
			if (inst != cmd->Instance) {
				inst++;
				continue;
			}

			/* fill in the values */
			bcopy(tq->node_name, tmp_tgt.WWNN,
			    EXT_DEF_WWN_NAME_SIZE);
			bcopy(tq->port_name, tmp_tgt.WWPN,
			    EXT_DEF_WWN_NAME_SIZE);

			break;
		}
	}

	if (link == NULL) {
		/* no matching device */
		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		cmd->DetailStatus = EXT_DSTATUS_TARGET;
		EL(ha, "failed, not found target=%d\n", cmd->Instance);
		cmd->ResponseLen = 0;
		return;
	}
	tmp_tgt.Id[0] = 0;
	tmp_tgt.Id[1] = tq->d_id.b.domain;
	tmp_tgt.Id[2] = tq->d_id.b.area;
	tmp_tgt.Id[3] = tq->d_id.b.al_pa;

	tmp_tgt.LunCount = (uint16_t)ql_lun_count(ha, tq);

	if ((tq->flags & TQF_TAPE_DEVICE) == 0) {
		(void) ql_inq_scan(ha, tq, 1);
	}

	tmp_tgt.Type = 0;
	if (tq->flags & TQF_TAPE_DEVICE) {
		tmp_tgt.Type = (uint16_t)(tmp_tgt.Type | EXT_DEF_TAPE_DEV);
	}

	if (tq->flags & TQF_FABRIC_DEVICE) {
		tmp_tgt.Type = (uint16_t)(tmp_tgt.Type | EXT_DEF_FABRIC_DEV);
	} else {
		tmp_tgt.Type = (uint16_t)(tmp_tgt.Type | EXT_DEF_TARGET_DEV);
	}

	tmp_tgt.Status = 0;

	tmp_tgt.Bus = 0;  /* Hard-coded for Solaris. */

	bcopy(tq->port_name, &tmp_tgt.TargetId, 8);

	if (ddi_copyout((void *)&tmp_tgt,
	    (void *)(uintptr_t)(cmd->ResponseAdr),
	    sizeof (EXT_DISC_TARGET), mode) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, ddi_copyout\n");
	} else {
		cmd->ResponseLen = sizeof (EXT_DISC_TARGET);
		QL_PRINT_9(ha, "done\n");
	}
}

/*
 * ql_qry_fw
 *	Performs EXT_SC_QUERY_FW subfunction.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_qry_fw(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_FW		fw_info = {0};

	QL_PRINT_9(ha, "started\n");

	if (cmd->ResponseLen < sizeof (EXT_FW)) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = sizeof (EXT_FW);
		EL(ha, "failed, ResponseLen < EXT_FW, Len=%xh\n",
		    cmd->ResponseLen);
		cmd->ResponseLen = 0;
		return;
	}

	(void) sprintf((char *)(fw_info.Version), "%d.%02d.%02d",
	    ha->fw_major_version, ha->fw_minor_version,
	    ha->fw_subminor_version);

	fw_info.Attrib = ha->fw_attributes;

	if (ddi_copyout((void *)&fw_info,
	    (void *)(uintptr_t)(cmd->ResponseAdr),
	    sizeof (EXT_FW), mode) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, ddi_copyout\n");
		return;
	} else {
		cmd->ResponseLen = sizeof (EXT_FW);
		QL_PRINT_9(ha, "done\n");
	}
}

/*
 * ql_qry_chip
 *	Performs EXT_SC_QUERY_CHIP subfunction.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_qry_chip(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_CHIP	chip = {0};
	uint16_t	PciDevNumber;

	QL_PRINT_9(ha, "started\n");

	if (cmd->ResponseLen < sizeof (EXT_CHIP)) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = sizeof (EXT_CHIP);
		EL(ha, "failed, ResponseLen < EXT_CHIP, Len=%xh\n",
		    cmd->ResponseLen);
		cmd->ResponseLen = 0;
		return;
	}

	chip.VendorId = ha->ven_id;
	chip.DeviceId = ha->device_id;
	chip.SubVendorId = ha->subven_id;
	chip.SubSystemId = ha->subsys_id;
	chip.IoAddr = ql_pci_config_get32(ha, PCI_CONF_BASE0);
	chip.IoAddrLen = 0x100;
	chip.MemAddr = ql_pci_config_get32(ha, PCI_CONF_BASE1);
	chip.MemAddrLen = 0x100;
	chip.ChipRevID = ha->rev_id;
	chip.FuncNo = ha->pci_function_number;
	chip.PciBusNumber = (uint16_t)
	    ((ha->pci_bus_addr & PCI_REG_BUS_M) >> PCI_REG_BUS_SHIFT);

	PciDevNumber = (uint16_t)
	    ((ha->pci_bus_addr & PCI_REG_DEV_M) >> PCI_REG_DEV_SHIFT);
	chip.PciSlotNumber = (uint16_t)(((PciDevNumber << 3) & 0xF8) |
	    (chip.FuncNo & 0x7));

	if (ddi_copyout((void *)&chip,
	    (void *)(uintptr_t)(cmd->ResponseAdr),
	    sizeof (EXT_CHIP), mode) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, ddi_copyout\n");
	} else {
		cmd->ResponseLen = sizeof (EXT_CHIP);
		QL_PRINT_9(ha, "done\n");
	}
}

/*
 * ql_qry_driver
 *	Performs EXT_SC_QUERY_DRIVER subfunction.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_qry_driver(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_DRIVER	qd = {0};

	QL_PRINT_9(ha, "started\n");

	if (cmd->ResponseLen < sizeof (EXT_DRIVER)) {
		cmd->Status = EXT_STATUS_DATA_OVERRUN;
		cmd->DetailStatus = sizeof (EXT_DRIVER);
		EL(ha, "failed, ResponseLen < EXT_DRIVER, Len=%xh\n",
		    cmd->ResponseLen);
		cmd->ResponseLen = 0;
		return;
	}

	(void) strcpy((void *)&qd.Version[0], QL_VERSION);
	qd.NumOfBus = 1;	/* Fixed for Solaris */
	qd.TargetsPerBus = (uint16_t)
	    (CFG_IST(ha, (CFG_ISP_FW_TYPE_2 | CFG_EXT_FW_INTERFACE)) ?
	    MAX_24_FIBRE_DEVICES : MAX_22_FIBRE_DEVICES);
	qd.LunsPerTarget = 2030;
	qd.MaxTransferLen = QL_DMA_MAX_XFER_SIZE;
	qd.MaxDataSegments = QL_DMA_SG_LIST_LENGTH;

	if (ddi_copyout((void *)&qd, (void *)(uintptr_t)cmd->ResponseAdr,
	    sizeof (EXT_DRIVER), mode) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, ddi_copyout\n");
	} else {
		cmd->ResponseLen = sizeof (EXT_DRIVER);
		QL_PRINT_9(ha, "done\n");
	}
}

/*
 * ql_fcct
 *	IOCTL management server FC-CT passthrough.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	User space CT arguments pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_fcct(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	ql_mbx_iocb_t		*pkt;
	ql_mbx_data_t		mr;
	dma_mem_t		*dma_mem;
	caddr_t			pld;
	uint32_t		pkt_size, pld_byte_cnt, *long_ptr;
	int			rval;
	ql_ct_iu_preamble_t	*ct;
	ql_xioctl_t		*xp = ha->xioctl;
	ql_tgt_t		tq;
	uint16_t		comp_status, loop_id;

	QL_PRINT_9(ha, "started\n");

	/* Get CT argument structure. */
	if ((ha->topology & QL_FABRIC_CONNECTION) == 0) {
		EL(ha, "failed, No switch\n");
		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		cmd->ResponseLen = 0;
		return;
	}

	if (DRIVER_SUSPENDED(ha)) {
		EL(ha, "failed, LOOP_NOT_READY\n");
		cmd->Status = EXT_STATUS_BUSY;
		cmd->ResponseLen = 0;
		return;
	}

	/* Login management server device. */
	if ((xp->flags & QL_MGMT_SERVER_LOGIN) == 0) {
		tq.d_id.b.al_pa = 0xfa;
		tq.d_id.b.area = 0xff;
		tq.d_id.b.domain = 0xff;
		tq.loop_id = (uint16_t)(CFG_IST(ha, CFG_ISP_FW_TYPE_2) ?
		    MANAGEMENT_SERVER_24XX_LOOP_ID :
		    MANAGEMENT_SERVER_LOOP_ID);
		rval = ql_login_fport(ha, &tq, tq.loop_id, LFF_NO_PRLI, &mr);
		if (rval != QL_SUCCESS) {
			EL(ha, "failed, server login\n");
			cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
			cmd->ResponseLen = 0;
			return;
		} else {
			xp->flags |= QL_MGMT_SERVER_LOGIN;
		}
	}

	QL_PRINT_9(ha, "cmd\n");
	QL_DUMP_9(cmd, 8, sizeof (EXT_IOCTL));

	/* Allocate a DMA Memory Descriptor */
	dma_mem = (dma_mem_t *)kmem_zalloc(sizeof (dma_mem_t), KM_SLEEP);
	if (dma_mem == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}
	/* Determine maximum buffer size. */
	if (cmd->RequestLen < cmd->ResponseLen) {
		pld_byte_cnt = cmd->ResponseLen;
	} else {
		pld_byte_cnt = cmd->RequestLen;
	}

	/* Allocate command block. */
	pkt_size = (uint32_t)(sizeof (ql_mbx_iocb_t) + pld_byte_cnt);
	pkt = kmem_zalloc(pkt_size, KM_SLEEP);
	if (pkt == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}
	pld = (caddr_t)pkt + sizeof (ql_mbx_iocb_t);

	/* Get command payload data. */
	if (ql_get_buffer_data((caddr_t)(uintptr_t)cmd->RequestAdr, pld,
	    cmd->RequestLen, mode) != cmd->RequestLen) {
		EL(ha, "failed, get_buffer_data\n");
		kmem_free(pkt, pkt_size);
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	/* Get DMA memory for the IOCB */
	if (ql_get_dma_mem(ha, dma_mem, pkt_size, LITTLE_ENDIAN_DMA,
	    QL_DMA_RING_ALIGN) != QL_SUCCESS) {
		cmn_err(CE_WARN, "%sDMA memory "
		    "alloc failed", QL_NAME);
		kmem_free(pkt, pkt_size);
		kmem_free(dma_mem, sizeof (dma_mem_t));
		cmd->Status = EXT_STATUS_MS_NO_RESPONSE;
		cmd->ResponseLen = 0;
		return;
	}

	/* Copy out going payload data to IOCB DMA buffer. */
	ddi_rep_put8(dma_mem->acc_handle, (uint8_t *)pld,
	    (uint8_t *)dma_mem->bp, pld_byte_cnt, DDI_DEV_AUTOINCR);

	/* Sync IOCB DMA buffer. */
	(void) ddi_dma_sync(dma_mem->dma_handle, 0, pld_byte_cnt,
	    DDI_DMA_SYNC_FORDEV);

	/*
	 * Setup IOCB
	 */
	ct = (ql_ct_iu_preamble_t *)pld;
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		pkt->ms24.entry_type = CT_PASSTHRU_TYPE;
		pkt->ms24.entry_count = 1;

		pkt->ms24.vp_index = ha->vp_index;

		/* Set loop ID */
		pkt->ms24.n_port_hdl = (uint16_t)
		    (ct->gs_type == GS_TYPE_DIR_SERVER ?
		    LE_16(SNS_24XX_HDL) :
		    LE_16(MANAGEMENT_SERVER_24XX_LOOP_ID));

		/* Set ISP command timeout. */
		pkt->ms24.timeout = LE_16(120);

		/* Set cmd/response data segment counts. */
		pkt->ms24.cmd_dseg_count = LE_16(1);
		pkt->ms24.resp_dseg_count = LE_16(1);

		/* Load ct cmd byte count. */
		pkt->ms24.cmd_byte_count = LE_32(cmd->RequestLen);

		/* Load ct rsp byte count. */
		pkt->ms24.resp_byte_count = LE_32(cmd->ResponseLen);

		long_ptr = (uint32_t *)&pkt->ms24.dseg;

		/* Load MS command entry data segments. */
		*long_ptr++ = (uint32_t)
		    LE_32(LSD(dma_mem->cookie.dmac_laddress));
		*long_ptr++ = (uint32_t)
		    LE_32(MSD(dma_mem->cookie.dmac_laddress));
		*long_ptr++ = (uint32_t)(LE_32(cmd->RequestLen));

		/* Load MS response entry data segments. */
		*long_ptr++ = (uint32_t)
		    LE_32(LSD(dma_mem->cookie.dmac_laddress));
		*long_ptr++ = (uint32_t)
		    LE_32(MSD(dma_mem->cookie.dmac_laddress));
		*long_ptr = (uint32_t)LE_32(cmd->ResponseLen);

		rval = ql_issue_mbx_iocb(ha, (caddr_t)pkt,
		    sizeof (ql_mbx_iocb_t));

		comp_status = (uint16_t)LE_16(pkt->sts24.comp_status);
		if (comp_status == CS_DATA_UNDERRUN) {
			if ((BE_16(ct->max_residual_size)) == 0) {
				comp_status = CS_COMPLETE;
			}
		}

		if (rval != QL_SUCCESS || (pkt->sts24.entry_status & 0x3c) !=
		    0) {
			EL(ha, "failed, I/O timeout or "
			    "es=%xh, ss_l=%xh, rval=%xh\n",
			    pkt->sts24.entry_status,
			    pkt->sts24.scsi_status_l, rval);
			kmem_free(pkt, pkt_size);
			ql_free_dma_resource(ha, dma_mem);
			kmem_free(dma_mem, sizeof (dma_mem_t));
			cmd->Status = EXT_STATUS_MS_NO_RESPONSE;
			cmd->ResponseLen = 0;
			return;
		}
	} else {
		pkt->ms.entry_type = MS_TYPE;
		pkt->ms.entry_count = 1;

		/* Set loop ID */
		loop_id = (uint16_t)(ct->gs_type == GS_TYPE_DIR_SERVER ?
		    SIMPLE_NAME_SERVER_LOOP_ID : MANAGEMENT_SERVER_LOOP_ID);
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			pkt->ms.loop_id_l = LSB(loop_id);
			pkt->ms.loop_id_h = MSB(loop_id);
		} else {
			pkt->ms.loop_id_h = LSB(loop_id);
		}

		/* Set ISP command timeout. */
		pkt->ms.timeout = LE_16(120);

		/* Set data segment counts. */
		pkt->ms.cmd_dseg_count_l = 1;
		pkt->ms.total_dseg_count = LE_16(2);

		/* Response total byte count. */
		pkt->ms.resp_byte_count = LE_32(cmd->ResponseLen);
		pkt->ms.dseg[1].length = LE_32(cmd->ResponseLen);

		/* Command total byte count. */
		pkt->ms.cmd_byte_count = LE_32(cmd->RequestLen);
		pkt->ms.dseg[0].length = LE_32(cmd->RequestLen);

		/* Load command/response data segments. */
		pkt->ms.dseg[0].address[0] = (uint32_t)
		    LE_32(LSD(dma_mem->cookie.dmac_laddress));
		pkt->ms.dseg[0].address[1] = (uint32_t)
		    LE_32(MSD(dma_mem->cookie.dmac_laddress));
		pkt->ms.dseg[1].address[0] = (uint32_t)
		    LE_32(LSD(dma_mem->cookie.dmac_laddress));
		pkt->ms.dseg[1].address[1] = (uint32_t)
		    LE_32(MSD(dma_mem->cookie.dmac_laddress));

		rval = ql_issue_mbx_iocb(ha, (caddr_t)pkt,
		    sizeof (ql_mbx_iocb_t));

		comp_status = (uint16_t)LE_16(pkt->sts.comp_status);
		if (comp_status == CS_DATA_UNDERRUN) {
			if ((BE_16(ct->max_residual_size)) == 0) {
				comp_status = CS_COMPLETE;
			}
		}
		if (rval != QL_SUCCESS || (pkt->sts.entry_status & 0x7e) != 0) {
			EL(ha, "failed, I/O timeout or "
			    "es=%xh, rval=%xh\n", pkt->sts.entry_status, rval);
			kmem_free(pkt, pkt_size);
			ql_free_dma_resource(ha, dma_mem);
			kmem_free(dma_mem, sizeof (dma_mem_t));
			cmd->Status = EXT_STATUS_MS_NO_RESPONSE;
			cmd->ResponseLen = 0;
			return;
		}
	}

	/* Sync in coming DMA buffer. */
	(void) ddi_dma_sync(dma_mem->dma_handle, 0,
	    pld_byte_cnt, DDI_DMA_SYNC_FORKERNEL);
	/* Copy in coming DMA data. */
	ddi_rep_get8(dma_mem->acc_handle, (uint8_t *)pld,
	    (uint8_t *)dma_mem->bp, pld_byte_cnt,
	    DDI_DEV_AUTOINCR);

	/* Copy response payload from DMA buffer to application. */
	if (cmd->ResponseLen != 0) {
		QL_PRINT_9(ha, "ResponseLen=%d\n",
		    cmd->ResponseLen);
		QL_DUMP_9(pld, 8, cmd->ResponseLen);

		/* Send response payload. */
		if (ql_send_buffer_data(pld,
		    (caddr_t)(uintptr_t)cmd->ResponseAdr,
		    cmd->ResponseLen, mode) != cmd->ResponseLen) {
			EL(ha, "failed, send_buffer_data\n");
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->ResponseLen = 0;
		}
	}

	kmem_free(pkt, pkt_size);
	ql_free_dma_resource(ha, dma_mem);
	kmem_free(dma_mem, sizeof (dma_mem_t));

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_aen_reg
 *	IOCTL management server Asynchronous Event Tracking Enable/Disable.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_aen_reg(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_REG_AEN	reg_struct;
	int		rval = 0;
	ql_xioctl_t	*xp = ha->xioctl;

	QL_PRINT_9(ha, "started\n");

	rval = ddi_copyin((void*)(uintptr_t)cmd->RequestAdr, &reg_struct,
	    cmd->RequestLen, mode);

	if (rval == 0) {
		if (reg_struct.Enable) {
			xp->flags |= QL_AEN_TRACKING_ENABLE;
		} else {
			xp->flags &= ~QL_AEN_TRACKING_ENABLE;
			/* Empty the queue. */
			INTR_LOCK(ha);
			xp->aen_q_head = 0;
			xp->aen_q_tail = 0;
			INTR_UNLOCK(ha);
		}
		QL_PRINT_9(ha, "done\n");
	} else {
		cmd->Status = EXT_STATUS_COPY_ERR;
		EL(ha, "failed, ddi_copyin\n");
	}
}

/*
 * ql_aen_get
 *	IOCTL management server Asynchronous Event Record Transfer.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_aen_get(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	uint32_t	out_size;
	EXT_ASYNC_EVENT	*tmp_q;
	EXT_ASYNC_EVENT	aen[EXT_DEF_MAX_AEN_QUEUE];
	uint8_t		i;
	uint8_t		queue_cnt;
	uint8_t		request_cnt;
	ql_xioctl_t	*xp = ha->xioctl;

	QL_PRINT_9(ha, "started\n");

	/* Compute the number of events that can be returned */
	request_cnt = (uint8_t)(cmd->ResponseLen / sizeof (EXT_ASYNC_EVENT));

	if (request_cnt < EXT_DEF_MAX_AEN_QUEUE) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = EXT_DEF_MAX_AEN_QUEUE;
		EL(ha, "failed, request_cnt < EXT_DEF_MAX_AEN_QUEUE, "
		    "Len=%xh\n", request_cnt);
		cmd->ResponseLen = 0;
		return;
	}

	/* 1st: Make a local copy of the entire queue content. */
	tmp_q = (EXT_ASYNC_EVENT *)xp->aen_tracking_queue;
	queue_cnt = 0;

	INTR_LOCK(ha);
	i = xp->aen_q_head;

	for (; queue_cnt < EXT_DEF_MAX_AEN_QUEUE; ) {
		if (tmp_q[i].AsyncEventCode != 0) {
			bcopy(&tmp_q[i], &aen[queue_cnt],
			    sizeof (EXT_ASYNC_EVENT));
			queue_cnt++;
			tmp_q[i].AsyncEventCode = 0; /* empty out the slot */
		}
		if (i == xp->aen_q_tail) {
			/* done. */
			break;
		}
		i++;
		if (i == EXT_DEF_MAX_AEN_QUEUE) {
			i = 0;
		}
	}

	/* Empty the queue. */
	xp->aen_q_head = 0;
	xp->aen_q_tail = 0;

	INTR_UNLOCK(ha);

	/* 2nd: Now transfer the queue content to user buffer */
	/* Copy the entire queue to user's buffer. */
	out_size = (uint32_t)(queue_cnt * sizeof (EXT_ASYNC_EVENT));
	if (queue_cnt == 0) {
		cmd->ResponseLen = 0;
	} else if (ddi_copyout((void *)&aen[0],
	    (void *)(uintptr_t)(cmd->ResponseAdr),
	    out_size, mode) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, ddi_copyout\n");
	} else {
		cmd->ResponseLen = out_size;
		QL_PRINT_9(ha, "done\n");
	}
}

/*
 * ql_enqueue_aen
 *
 * Input:
 *	ha:		adapter state pointer.
 *	event_code:	async event code of the event to add to queue.
 *	payload:	event payload for the queue.
 *	INTR_LOCK must be already obtained.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_enqueue_aen(ql_adapter_state_t *ha, uint16_t event_code, void *payload)
{
	uint8_t			new_entry;	/* index to current entry */
	uint16_t		*mbx;
	EXT_ASYNC_EVENT		*aen_queue;
	ql_xioctl_t		*xp = ha->xioctl;

	QL_PRINT_9(ha, "started, event_code=%d\n",
	    event_code);

	if (xp == NULL) {
		QL_PRINT_9(ha, "no context\n");
		return;
	}
	aen_queue = (EXT_ASYNC_EVENT *)xp->aen_tracking_queue;

	if (aen_queue[xp->aen_q_tail].AsyncEventCode != 0) {
		/* Need to change queue pointers to make room. */

		/* Increment tail for adding new entry. */
		xp->aen_q_tail++;
		if (xp->aen_q_tail == EXT_DEF_MAX_AEN_QUEUE) {
			xp->aen_q_tail = 0;
		}
		if (xp->aen_q_head == xp->aen_q_tail) {
			/*
			 * We're overwriting the oldest entry, so need to
			 * update the head pointer.
			 */
			xp->aen_q_head++;
			if (xp->aen_q_head == EXT_DEF_MAX_AEN_QUEUE) {
				xp->aen_q_head = 0;
			}
		}
	}

	new_entry = xp->aen_q_tail;
	aen_queue[new_entry].AsyncEventCode = event_code;

	/* Update payload */
	if (payload != NULL) {
		switch (event_code) {
		case MBA_LIP_OCCURRED:
		case MBA_LOOP_UP:
		case MBA_LOOP_DOWN:
		case MBA_LIP_F8:
		case MBA_LIP_RESET:
		case MBA_PORT_UPDATE:
			break;
		case MBA_RSCN_UPDATE:
			mbx = (uint16_t *)payload;
			/* al_pa */
			aen_queue[new_entry].Payload.RSCN.RSCNInfo[0] =
			    LSB(mbx[2]);
			/* area */
			aen_queue[new_entry].Payload.RSCN.RSCNInfo[1] =
			    MSB(mbx[2]);
			/* domain */
			aen_queue[new_entry].Payload.RSCN.RSCNInfo[2] =
			    LSB(mbx[1]);
			/* save in big endian */
			BIG_ENDIAN_24(&aen_queue[new_entry].
			    Payload.RSCN.RSCNInfo[0]);

			aen_queue[new_entry].Payload.RSCN.AddrFormat =
			    MSB(mbx[1]);

			break;
		default:
			/* Not supported */
			EL(ha, "failed, event code not supported=%xh\n",
			    event_code);
			aen_queue[new_entry].AsyncEventCode = 0;
			break;
		}
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_scsi_passthru
 *	IOCTL SCSI passthrough.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	User space SCSI command pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_scsi_passthru(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	ql_mbx_iocb_t		*pkt;
	ql_mbx_data_t		mr;
	dma_mem_t		*dma_mem;
	caddr_t			pld;
	uint32_t		pkt_size, pld_size;
	uint16_t		qlnt, retries, cnt, cnt2;
	uint8_t			*name;
	EXT_FC_SCSI_PASSTHRU	*ufc_req;
	EXT_SCSI_PASSTHRU	*usp_req;
	int			rval;
	union _passthru {
		EXT_SCSI_PASSTHRU	sp_cmd;
		EXT_FC_SCSI_PASSTHRU	fc_cmd;
	} pt_req;		/* Passthru request */
	uint32_t		status, sense_sz = 0;
	ql_tgt_t		*tq = NULL;
	EXT_SCSI_PASSTHRU	*sp_req = &pt_req.sp_cmd;
	EXT_FC_SCSI_PASSTHRU	*fc_req = &pt_req.fc_cmd;

	/* SCSI request struct for SCSI passthrough IOs. */
	struct {
		uint16_t	lun;
		uint16_t	sense_length;	/* Sense buffer size */
		size_t		resid;		/* Residual */
		uint8_t		*cdbp;		/* Requestor's CDB */
		uint8_t		*u_sense;	/* Requestor's sense buffer */
		uint8_t		cdb_len;	/* Requestor's CDB length */
		uint8_t		direction;
	} scsi_req;

	struct {
		uint8_t		*rsp_info;
		uint8_t		*req_sense_data;
		uint32_t	residual_length;
		uint32_t	rsp_info_length;
		uint32_t	req_sense_length;
		uint16_t	comp_status;
		uint8_t		state_flags_l;
		uint8_t		state_flags_h;
		uint8_t		scsi_status_l;
		uint8_t		scsi_status_h;
	} sts;

	QL_PRINT_9(ha, "started\n");

	/* Verify Sub Code and set cnt to needed request size. */
	if (cmd->SubCode == EXT_SC_SEND_SCSI_PASSTHRU) {
		pld_size = sizeof (EXT_SCSI_PASSTHRU);
	} else if (cmd->SubCode == EXT_SC_SEND_FC_SCSI_PASSTHRU) {
		pld_size = sizeof (EXT_FC_SCSI_PASSTHRU);
	} else {
		EL(ha, "failed, invalid SubCode=%xh\n", cmd->SubCode);
		cmd->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		cmd->ResponseLen = 0;
		return;
	}

	dma_mem = (dma_mem_t *)kmem_zalloc(sizeof (dma_mem_t), KM_SLEEP);
	if (dma_mem == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}
	/*  Verify the size of and copy in the passthru request structure. */
	if (cmd->RequestLen != pld_size) {
		/* Return error */
		EL(ha, "failed, RequestLen != cnt, is=%xh, expected=%xh\n",
		    cmd->RequestLen, pld_size);
		cmd->Status = EXT_STATUS_INVALID_PARAM;
		cmd->DetailStatus = EXT_DSTATUS_REQUEST_LEN;
		cmd->ResponseLen = 0;
		return;
	}

	if (ddi_copyin((void *)(uintptr_t)cmd->RequestAdr, &pt_req,
	    pld_size, mode) != 0) {
		EL(ha, "failed, ddi_copyin\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	/*
	 * Find fc_port from SCSI PASSTHRU structure fill in the scsi_req
	 * request data structure.
	 */
	if (cmd->SubCode == EXT_SC_SEND_SCSI_PASSTHRU) {
		scsi_req.lun = sp_req->TargetAddr.Lun;
		scsi_req.sense_length = sizeof (sp_req->SenseData);
		scsi_req.cdbp = &sp_req->Cdb[0];
		scsi_req.cdb_len = sp_req->CdbLength;
		scsi_req.direction = sp_req->Direction;
		usp_req = (EXT_SCSI_PASSTHRU *)(uintptr_t)cmd->RequestAdr;
		scsi_req.u_sense = &usp_req->SenseData[0];
		cmd->DetailStatus = EXT_DSTATUS_TARGET;

		qlnt = QLNT_PORT;
		name = (uint8_t *)&sp_req->TargetAddr.Target;
		QL_PRINT_9(ha, "SubCode=%xh, Target=%lld\n",
		    ha->instance, cmd->SubCode, sp_req->TargetAddr.Target);
		tq = ql_find_port(ha, name, qlnt);
	} else {
		/*
		 * Must be FC PASSTHRU, verified above.
		 */
		if (fc_req->FCScsiAddr.DestType == EXT_DEF_DESTTYPE_WWPN) {
			qlnt = QLNT_PORT;
			name = &fc_req->FCScsiAddr.DestAddr.WWPN[0];
			QL_PRINT_9(ha, "SubCode=%xh, "
			    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x\n",
			    ha->instance, cmd->SubCode, name[0], name[1],
			    name[2], name[3], name[4], name[5], name[6],
			    name[7]);
			tq = ql_find_port(ha, name, qlnt);
		} else if (fc_req->FCScsiAddr.DestType ==
		    EXT_DEF_DESTTYPE_WWNN) {
			qlnt = QLNT_NODE;
			name = &fc_req->FCScsiAddr.DestAddr.WWNN[0];
			QL_PRINT_9(ha, "SubCode=%xh, "
			    "wwnn=%02x%02x%02x%02x%02x%02x%02x%02x\n",
			    ha->instance, cmd->SubCode, name[0], name[1],
			    name[2], name[3], name[4], name[5], name[6],
			    name[7]);
			tq = ql_find_port(ha, name, qlnt);
		} else if (fc_req->FCScsiAddr.DestType ==
		    EXT_DEF_DESTTYPE_PORTID) {
			qlnt = QLNT_PID;
			name = &fc_req->FCScsiAddr.DestAddr.Id[0];
			QL_PRINT_9(ha, "SubCode=%xh, PID="
			    "%02x%02x%02x\n", cmd->SubCode,
			    name[0], name[1], name[2]);
			tq = ql_find_port(ha, name, qlnt);
		} else {
			EL(ha, "failed, SubCode=%xh invalid DestType=%xh\n",
			    cmd->SubCode, fc_req->FCScsiAddr.DestType);
			cmd->Status = EXT_STATUS_INVALID_PARAM;
			cmd->ResponseLen = 0;
			return;
		}
		scsi_req.lun = fc_req->FCScsiAddr.Lun;
		scsi_req.sense_length = sizeof (fc_req->SenseData);
		scsi_req.cdbp = &sp_req->Cdb[0];
		scsi_req.cdb_len = sp_req->CdbLength;
		ufc_req = (EXT_FC_SCSI_PASSTHRU *)(uintptr_t)cmd->RequestAdr;
		scsi_req.u_sense = &ufc_req->SenseData[0];
		scsi_req.direction = fc_req->Direction;
	}

	if (tq == NULL || !VALID_TARGET_ID(ha, tq->loop_id)) {
		EL(ha, "failed, fc_port not found\n");
		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		cmd->ResponseLen = 0;
		return;
	}

	if (tq->flags & TQF_NEED_AUTHENTICATION) {
		EL(ha, "target not available; loopid=%xh\n", tq->loop_id);
		cmd->Status = EXT_STATUS_DEVICE_OFFLINE;
		cmd->ResponseLen = 0;
		return;
	}

	/* Allocate command block. */
	if ((scsi_req.direction == EXT_DEF_SCSI_PASSTHRU_DATA_IN ||
	    scsi_req.direction == EXT_DEF_SCSI_PASSTHRU_DATA_OUT) &&
	    cmd->ResponseLen) {
		pld_size = cmd->ResponseLen;
		pkt_size = (uint32_t)(sizeof (ql_mbx_iocb_t) + pld_size);
		pkt = kmem_zalloc(pkt_size, KM_SLEEP);
		if (pkt == NULL) {
			EL(ha, "failed, kmem_zalloc\n");
			cmd->Status = EXT_STATUS_NO_MEMORY;
			cmd->ResponseLen = 0;
			return;
		}
		pld = (caddr_t)pkt + sizeof (ql_mbx_iocb_t);

		/* Get DMA memory for the IOCB */
		if (ql_get_dma_mem(ha, dma_mem, pld_size, LITTLE_ENDIAN_DMA,
		    QL_DMA_DATA_ALIGN) != QL_SUCCESS) {
			cmn_err(CE_WARN, "%srequest queue DMA memory "
			    "alloc failed", QL_NAME);
			kmem_free(pkt, pkt_size);
			cmd->Status = EXT_STATUS_MS_NO_RESPONSE;
			cmd->ResponseLen = 0;
			return;
		}

		if (scsi_req.direction == EXT_DEF_SCSI_PASSTHRU_DATA_IN) {
			scsi_req.direction = (uint8_t)
			    (CFG_IST(ha, CFG_ISP_FW_TYPE_2) ?
			    CF_RD : CF_DATA_IN | CF_STAG);
		} else {
			scsi_req.direction = (uint8_t)
			    (CFG_IST(ha, CFG_ISP_FW_TYPE_2) ?
			    CF_WR : CF_DATA_OUT | CF_STAG);
			cmd->ResponseLen = 0;

			/* Get command payload. */
			if (ql_get_buffer_data(
			    (caddr_t)(uintptr_t)cmd->ResponseAdr,
			    pld, pld_size, mode) != pld_size) {
				EL(ha, "failed, get_buffer_data\n");
				cmd->Status = EXT_STATUS_COPY_ERR;

				kmem_free(pkt, pkt_size);
				ql_free_dma_resource(ha, dma_mem);
				kmem_free(dma_mem, sizeof (dma_mem_t));
				return;
			}

			/* Copy out going data to DMA buffer. */
			ddi_rep_put8(dma_mem->acc_handle, (uint8_t *)pld,
			    (uint8_t *)dma_mem->bp, pld_size,
			    DDI_DEV_AUTOINCR);

			/* Sync DMA buffer. */
			(void) ddi_dma_sync(dma_mem->dma_handle, 0,
			    dma_mem->size, DDI_DMA_SYNC_FORDEV);
		}
	} else {
		scsi_req.direction = (uint8_t)
		    (CFG_IST(ha, CFG_ISP_FW_TYPE_2) ? 0 : CF_STAG);
		cmd->ResponseLen = 0;

		pkt_size = sizeof (ql_mbx_iocb_t);
		pkt = kmem_zalloc(pkt_size, KM_SLEEP);
		if (pkt == NULL) {
			EL(ha, "failed, kmem_zalloc-2\n");
			cmd->Status = EXT_STATUS_NO_MEMORY;
			return;
		}
		pld = NULL;
		pld_size = 0;
	}

	/* retries = ha->port_down_retry_count; */
	retries = 1;
	cmd->Status = EXT_STATUS_OK;
	cmd->DetailStatus = EXT_DSTATUS_NOADNL_INFO;

	QL_PRINT_9(ha, "SCSI cdb\n");
	QL_DUMP_9(scsi_req.cdbp, 8, scsi_req.cdb_len);

	do {
		if (DRIVER_SUSPENDED(ha)) {
			sts.comp_status = CS_LOOP_DOWN_ABORT;
			break;
		}

		if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
			uint64_t		lun_addr = 0;
			fcp_ent_addr_t		*fcp_ent_addr = 0;

			pkt->cmd24.entry_type = IOCB_CMD_TYPE_7;
			pkt->cmd24.entry_count = 1;

			/* Set LUN number and address method */
			lun_addr = ql_get_lun_addr(tq, scsi_req.lun);
			fcp_ent_addr = (fcp_ent_addr_t *)&lun_addr;

			pkt->cmd24.fcp_lun[2] =
			    lobyte(fcp_ent_addr->ent_addr_0);
			pkt->cmd24.fcp_lun[3] =
			    hibyte(fcp_ent_addr->ent_addr_0);
			pkt->cmd24.fcp_lun[0] =
			    lobyte(fcp_ent_addr->ent_addr_1);
			pkt->cmd24.fcp_lun[1] =
			    hibyte(fcp_ent_addr->ent_addr_1);
			pkt->cmd24.fcp_lun[6] =
			    lobyte(fcp_ent_addr->ent_addr_2);
			pkt->cmd24.fcp_lun[7] =
			    hibyte(fcp_ent_addr->ent_addr_2);
			pkt->cmd24.fcp_lun[4] =
			    lobyte(fcp_ent_addr->ent_addr_3);
			pkt->cmd24.fcp_lun[5] =
			    hibyte(fcp_ent_addr->ent_addr_3);

			/* Set N_port handle */
			pkt->cmd24.n_port_hdl = (uint16_t)LE_16(tq->loop_id);

			/* Set VP Index */
			pkt->cmd24.vp_index = ha->vp_index;

			/* Set target ID */
			pkt->cmd24.target_id[0] = tq->d_id.b.al_pa;
			pkt->cmd24.target_id[1] = tq->d_id.b.area;
			pkt->cmd24.target_id[2] = tq->d_id.b.domain;

			/* Set ISP command timeout. */
			pkt->cmd24.timeout = (uint16_t)LE_16(15);

			/* Load SCSI CDB */
			ddi_rep_put8(ha->req_q[0]->req_ring.acc_handle,
			    scsi_req.cdbp, pkt->cmd24.scsi_cdb,
			    scsi_req.cdb_len, DDI_DEV_AUTOINCR);
			for (cnt = 0; cnt < MAX_CMDSZ;
			    cnt = (uint16_t)(cnt + 4)) {
				ql_chg_endian((uint8_t *)&pkt->cmd24.scsi_cdb
				    + cnt, 4);
			}

			/* Set tag queue control flags */
			pkt->cmd24.task = TA_STAG;

			if (pld_size) {
				/* Set transfer direction. */
				pkt->cmd24.control_flags = scsi_req.direction;

				/* Set data segment count. */
				pkt->cmd24.dseg_count = LE_16(1);

				/* Load total byte count. */
				pkt->cmd24.total_byte_count = LE_32(pld_size);

				/* Load data descriptor. */
				pkt->cmd24.dseg.address[0] = (uint32_t)
				    LE_32(LSD(dma_mem->cookie.dmac_laddress));
				pkt->cmd24.dseg.address[1] = (uint32_t)
				    LE_32(MSD(dma_mem->cookie.dmac_laddress));
				pkt->cmd24.dseg.length = LE_32(pld_size);
			}
		} else if (CFG_IST(ha, CFG_ENABLE_64BIT_ADDRESSING)) {
			pkt->cmd3.entry_type = IOCB_CMD_TYPE_3;
			pkt->cmd3.entry_count = 1;
			if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
				pkt->cmd3.target_l = LSB(tq->loop_id);
				pkt->cmd3.target_h = MSB(tq->loop_id);
			} else {
				pkt->cmd3.target_h = LSB(tq->loop_id);
			}
			pkt->cmd3.lun_l = LSB(scsi_req.lun);
			pkt->cmd3.lun_h = MSB(scsi_req.lun);
			pkt->cmd3.control_flags_l = scsi_req.direction;
			pkt->cmd3.timeout = LE_16(15);
			for (cnt = 0; cnt < scsi_req.cdb_len; cnt++) {
				pkt->cmd3.scsi_cdb[cnt] = scsi_req.cdbp[cnt];
			}
			if (pld_size) {
				pkt->cmd3.dseg_count = LE_16(1);
				pkt->cmd3.byte_count = LE_32(pld_size);
				pkt->cmd3.dseg[0].address[0] = (uint32_t)
				    LE_32(LSD(dma_mem->cookie.dmac_laddress));
				pkt->cmd3.dseg[0].address[1] = (uint32_t)
				    LE_32(MSD(dma_mem->cookie.dmac_laddress));
				pkt->cmd3.dseg[0].length = LE_32(pld_size);
			}
		} else {
			pkt->cmd.entry_type = IOCB_CMD_TYPE_2;
			pkt->cmd.entry_count = 1;
			if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
				pkt->cmd.target_l = LSB(tq->loop_id);
				pkt->cmd.target_h = MSB(tq->loop_id);
			} else {
				pkt->cmd.target_h = LSB(tq->loop_id);
			}
			pkt->cmd.lun_l = LSB(scsi_req.lun);
			pkt->cmd.lun_h = MSB(scsi_req.lun);
			pkt->cmd.control_flags_l = scsi_req.direction;
			pkt->cmd.timeout = LE_16(15);
			for (cnt = 0; cnt < scsi_req.cdb_len; cnt++) {
				pkt->cmd.scsi_cdb[cnt] = scsi_req.cdbp[cnt];
			}
			if (pld_size) {
				pkt->cmd.dseg_count = LE_16(1);
				pkt->cmd.byte_count = LE_32(pld_size);
				pkt->cmd.dseg[0].address = (uint32_t)
				    LE_32(LSD(dma_mem->cookie.dmac_laddress));
				pkt->cmd.dseg[0].length = LE_32(pld_size);
			}
		}
		/* Go issue command and wait for completion. */
		QL_PRINT_9(ha, "request pkt\n");
		QL_DUMP_9(pkt, 8, pkt_size);

		status = ql_issue_mbx_iocb(ha, (caddr_t)pkt, pkt_size);

		if (pld_size) {
			/* Sync in coming DMA buffer. */
			(void) ddi_dma_sync(dma_mem->dma_handle, 0,
			    dma_mem->size, DDI_DMA_SYNC_FORKERNEL);
			/* Copy in coming DMA data. */
			ddi_rep_get8(dma_mem->acc_handle, (uint8_t *)pld,
			    (uint8_t *)dma_mem->bp, pld_size,
			    DDI_DEV_AUTOINCR);
		}

		if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
			pkt->sts24.entry_status = (uint8_t)
			    (pkt->sts24.entry_status & 0x3c);
		} else {
			pkt->sts.entry_status = (uint8_t)
			    (pkt->sts.entry_status & 0x7e);
		}

		if (status == QL_SUCCESS && pkt->sts.entry_status != 0) {
			EL(ha, "failed, entry_status=%xh, d_id=%xh\n",
			    pkt->sts.entry_status, tq->d_id.b24);
			status = QL_FUNCTION_PARAMETER_ERROR;
		}

		sts.comp_status = (uint16_t)
		    (CFG_IST(ha, CFG_ISP_FW_TYPE_2) ?
		    LE_16(pkt->sts24.comp_status) :
		    LE_16(pkt->sts.comp_status));

		/*
		 * We have verified about all the request that can be so far.
		 * Now we need to start verification of our ability to
		 * actually issue the CDB.
		 */
		if (DRIVER_SUSPENDED(ha)) {
			sts.comp_status = CS_LOOP_DOWN_ABORT;
			break;
		} else if (status == QL_SUCCESS &&
		    (sts.comp_status == CS_PORT_LOGGED_OUT ||
		    sts.comp_status == CS_PORT_UNAVAILABLE)) {
			EL(ha, "login retry d_id=%xh\n", tq->d_id.b24);
			if (tq->flags & TQF_FABRIC_DEVICE) {
				rval = ql_login_fport(ha, tq, tq->loop_id,
				    LFF_NO_PLOGI, &mr);
				if (rval != QL_SUCCESS) {
					EL(ha, "failed, login_fport=%xh, "
					    "d_id=%xh\n", rval, tq->d_id.b24);
				}
			} else {
				rval = ql_login_lport(ha, tq, tq->loop_id,
				    LLF_NONE);
				if (rval != QL_SUCCESS) {
					EL(ha, "failed, login_lport=%xh, "
					    "d_id=%xh\n", rval, tq->d_id.b24);
				}
			}
		} else {
			break;
		}

		bzero((caddr_t)pkt, sizeof (ql_mbx_iocb_t));

	} while (retries--);

	if (sts.comp_status == CS_LOOP_DOWN_ABORT) {
		/* Cannot issue command now, maybe later */
		EL(ha, "failed, suspended\n");
		kmem_free(pkt, pkt_size);
		ql_free_dma_resource(ha, dma_mem);
		kmem_free(dma_mem, sizeof (dma_mem_t));
		cmd->Status = EXT_STATUS_SUSPENDED;
		cmd->ResponseLen = 0;
		return;
	}

	if (status != QL_SUCCESS) {
		/* Command error */
		EL(ha, "failed, I/O\n");
		kmem_free(pkt, pkt_size);
		ql_free_dma_resource(ha, dma_mem);
		kmem_free(dma_mem, sizeof (dma_mem_t));
		cmd->Status = EXT_STATUS_ERR;
		cmd->DetailStatus = status;
		cmd->ResponseLen = 0;
		return;
	}

	/* Setup status. */
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		sts.scsi_status_l = pkt->sts24.scsi_status_l;
		sts.scsi_status_h = pkt->sts24.scsi_status_h;

		/* Setup residuals. */
		sts.residual_length = LE_32(pkt->sts24.residual_length);

		/* Setup state flags. */
		sts.state_flags_l = pkt->sts24.state_flags_l;
		sts.state_flags_h = pkt->sts24.state_flags_h;
		if (pld_size && sts.comp_status != CS_DATA_UNDERRUN) {
			sts.state_flags_h = (uint8_t)(sts.state_flags_h |
			    SF_GOT_BUS | SF_GOT_TARGET | SF_SENT_CMD |
			    SF_XFERRED_DATA | SF_GOT_STATUS);
		} else {
			sts.state_flags_h = (uint8_t)(sts.state_flags_h |
			    SF_GOT_BUS | SF_GOT_TARGET | SF_SENT_CMD |
			    SF_GOT_STATUS);
		}
		if (scsi_req.direction & CF_WR) {
			sts.state_flags_l = (uint8_t)(sts.state_flags_l |
			    SF_DATA_OUT);
		} else if (scsi_req.direction & CF_RD) {
			sts.state_flags_l = (uint8_t)(sts.state_flags_l |
			    SF_DATA_IN);
		}
		sts.state_flags_l = (uint8_t)(sts.state_flags_l | SF_SIMPLE_Q);

		/* Setup FCP response info. */
		sts.rsp_info_length = sts.scsi_status_h & FCP_RSP_LEN_VALID ?
		    LE_32(pkt->sts24.fcp_rsp_data_length) : 0;
		sts.rsp_info = &pkt->sts24.rsp_sense_data[0];
		for (cnt = 0; cnt < sts.rsp_info_length;
		    cnt = (uint16_t)(cnt + 4)) {
			ql_chg_endian(sts.rsp_info + cnt, 4);
		}

		/* Setup sense data. */
		if (sts.scsi_status_h & FCP_SNS_LEN_VALID) {
			sts.req_sense_length =
			    LE_32(pkt->sts24.fcp_sense_length);
			sts.state_flags_h = (uint8_t)(sts.state_flags_h |
			    SF_ARQ_DONE);
		} else {
			sts.req_sense_length = 0;
		}
		sts.req_sense_data =
		    &pkt->sts24.rsp_sense_data[sts.rsp_info_length];
		cnt2 = (uint16_t)(((uintptr_t)pkt + sizeof (sts_24xx_entry_t)) -
		    (uintptr_t)sts.req_sense_data);
		for (cnt = 0; cnt < cnt2; cnt = (uint16_t)(cnt + 4)) {
			ql_chg_endian(sts.req_sense_data + cnt, 4);
		}
	} else {
		sts.scsi_status_l = pkt->sts.scsi_status_l;
		sts.scsi_status_h = pkt->sts.scsi_status_h;

		/* Setup residuals. */
		sts.residual_length = LE_32(pkt->sts.residual_length);

		/* Setup state flags. */
		sts.state_flags_l = pkt->sts.state_flags_l;
		sts.state_flags_h = pkt->sts.state_flags_h;

		/* Setup FCP response info. */
		sts.rsp_info_length = sts.scsi_status_h & FCP_RSP_LEN_VALID ?
		    LE_16(pkt->sts.rsp_info_length) : 0;
		sts.rsp_info = &pkt->sts.rsp_info[0];

		/* Setup sense data. */
		sts.req_sense_length = sts.scsi_status_h & FCP_SNS_LEN_VALID ?
		    LE_16(pkt->sts.req_sense_length) : 0;
		sts.req_sense_data = &pkt->sts.req_sense_data[0];
	}

	QL_PRINT_9(ha, "response pkt\n");
	QL_DUMP_9(&pkt->sts, 8, sizeof (sts_entry_t));

	switch (sts.comp_status) {
	case CS_INCOMPLETE:
	case CS_ABORTED:
	case CS_DEVICE_UNAVAILABLE:
	case CS_PORT_UNAVAILABLE:
	case CS_PORT_LOGGED_OUT:
	case CS_PORT_CONFIG_CHG:
	case CS_PORT_BUSY:
	case CS_LOOP_DOWN_ABORT:
		cmd->Status = EXT_STATUS_BUSY;
		break;
	case CS_RESET:
	case CS_QUEUE_FULL:
		cmd->Status = EXT_STATUS_ERR;
		break;
	case CS_TIMEOUT:
		cmd->Status = EXT_STATUS_ERR;
		break;
	case CS_DATA_OVERRUN:
		cmd->Status = EXT_STATUS_DATA_OVERRUN;
		break;
	case CS_DATA_UNDERRUN:
		cmd->Status = EXT_STATUS_DATA_UNDERRUN;
		break;
	}

	/*
	 * If non data transfer commands fix tranfer counts.
	 */
	if (scsi_req.cdbp[0] == SCMD_TEST_UNIT_READY ||
	    scsi_req.cdbp[0] == SCMD_REZERO_UNIT ||
	    scsi_req.cdbp[0] == SCMD_SEEK ||
	    scsi_req.cdbp[0] == SCMD_SEEK_G1 ||
	    scsi_req.cdbp[0] == SCMD_RESERVE ||
	    scsi_req.cdbp[0] == SCMD_RELEASE ||
	    scsi_req.cdbp[0] == SCMD_START_STOP ||
	    scsi_req.cdbp[0] == SCMD_DOORLOCK ||
	    scsi_req.cdbp[0] == SCMD_VERIFY ||
	    scsi_req.cdbp[0] == SCMD_WRITE_FILE_MARK ||
	    scsi_req.cdbp[0] == SCMD_VERIFY_G0 ||
	    scsi_req.cdbp[0] == SCMD_SPACE ||
	    scsi_req.cdbp[0] == SCMD_ERASE ||
	    (scsi_req.cdbp[0] == SCMD_FORMAT &&
	    (scsi_req.cdbp[1] & FPB_DATA) == 0)) {
		/*
		 * Non data transfer command, clear sts_entry residual
		 * length.
		 */
		sts.residual_length = 0;
		cmd->ResponseLen = 0;
		if (sts.comp_status == CS_DATA_UNDERRUN) {
			sts.comp_status = CS_COMPLETE;
			cmd->Status = EXT_STATUS_OK;
		}
	} else {
		cmd->ResponseLen = pld_size;
	}

	/* Correct ISP completion status */
	if (sts.comp_status == CS_COMPLETE && sts.scsi_status_l == 0 &&
	    (sts.scsi_status_h & FCP_RSP_MASK) == 0) {
		QL_PRINT_9(ha, "Correct completion\n",
		    ha->instance);
		scsi_req.resid = 0;
	} else if (sts.comp_status == CS_DATA_UNDERRUN) {
		QL_PRINT_9(ha, "Correct UNDERRUN\n",
		    ha->instance);
		scsi_req.resid = sts.residual_length;
		if (sts.scsi_status_h & FCP_RESID_UNDER) {
			cmd->Status = (uint32_t)EXT_STATUS_OK;

			cmd->ResponseLen = (uint32_t)
			    (pld_size - scsi_req.resid);
		} else {
			EL(ha, "failed, Transfer ERROR\n");
			cmd->Status = EXT_STATUS_ERR;
			cmd->ResponseLen = 0;
		}
	} else {
		QL_PRINT_9(ha, "error d_id=%xh, comp_status=%xh, "
		    "scsi_status_h=%xh, scsi_status_l=%xh\n",
		    tq->d_id.b24, sts.comp_status, sts.scsi_status_h,
		    sts.scsi_status_l);

		scsi_req.resid = pld_size;
		/*
		 * Handle residual count on SCSI check
		 * condition.
		 *
		 * - If Residual Under / Over is set, use the
		 *   Residual Transfer Length field in IOCB.
		 * - If Residual Under / Over is not set, and
		 *   Transferred Data bit is set in State Flags
		 *   field of IOCB, report residual value of 0
		 *   (you may want to do this for tape
		 *   Write-type commands only). This takes care
		 *   of logical end of tape problem and does
		 *   not break Unit Attention.
		 * - If Residual Under / Over is not set, and
		 *   Transferred Data bit is not set in State
		 *   Flags, report residual value equal to
		 *   original data transfer length.
		 */
		if (sts.scsi_status_l & STATUS_CHECK) {
			cmd->Status = EXT_STATUS_SCSI_STATUS;
			cmd->DetailStatus = sts.scsi_status_l;
			if (sts.scsi_status_h &
			    (FCP_RESID_OVER | FCP_RESID_UNDER)) {
				scsi_req.resid = sts.residual_length;
			} else if (sts.state_flags_h &
			    STATE_XFERRED_DATA) {
				scsi_req.resid = 0;
			}
		}
	}

	if (sts.scsi_status_l & STATUS_CHECK &&
	    sts.scsi_status_h & FCP_SNS_LEN_VALID &&
	    sts.req_sense_length) {
		/*
		 * Check condition with vaild sense data flag set and sense
		 * length != 0
		 */
		if (sts.req_sense_length > scsi_req.sense_length) {
			sense_sz = scsi_req.sense_length;
		} else {
			sense_sz = sts.req_sense_length;
		}

		EL(ha, "failed, Check Condition Status, d_id=%xh\n",
		    tq->d_id.b24);
		QL_DUMP_2(sts.req_sense_data, 8, sts.req_sense_length);

		if (ddi_copyout(sts.req_sense_data, scsi_req.u_sense,
		    (size_t)sense_sz, mode) != 0) {
			EL(ha, "failed, request sense ddi_copyout\n");
		}

		cmd->Status = EXT_STATUS_SCSI_STATUS;
		cmd->DetailStatus = sts.scsi_status_l;
	}

	/* Copy response payload from DMA buffer to application. */
	if (scsi_req.direction & (CF_RD | CF_DATA_IN) &&
	    cmd->ResponseLen != 0) {
		QL_PRINT_9(ha, "Data Return resid=%lu, "
		    "byte_count=%u, ResponseLen=%xh\n",
		    scsi_req.resid, pld_size, cmd->ResponseLen);
		QL_DUMP_9(pld, 8, cmd->ResponseLen);

		/* Send response payload. */
		if (ql_send_buffer_data(pld,
		    (caddr_t)(uintptr_t)cmd->ResponseAdr,
		    cmd->ResponseLen, mode) != cmd->ResponseLen) {
			EL(ha, "failed, send_buffer_data\n");
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->ResponseLen = 0;
		}
	}

	if (cmd->Status != EXT_STATUS_OK) {
		EL(ha, "failed, cmd->Status=%xh, comp_status=%xh, "
		    "d_id=%xh\n", cmd->Status, sts.comp_status, tq->d_id.b24);
	} else {
		/*EMPTY*/
		QL_PRINT_9(ha, "done, ResponseLen=%d\n",
		    ha->instance, cmd->ResponseLen);
	}

	kmem_free(pkt, pkt_size);
	ql_free_dma_resource(ha, dma_mem);
	kmem_free(dma_mem, sizeof (dma_mem_t));
}

/*
 * ql_wwpn_to_scsiaddr
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_wwpn_to_scsiaddr(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	int		status;
	uint8_t		wwpn[EXT_DEF_WWN_NAME_SIZE];
	EXT_SCSI_ADDR	*tmp_addr;
	ql_tgt_t	*tq;

	QL_PRINT_9(ha, "started\n");

	if (cmd->RequestLen != EXT_DEF_WWN_NAME_SIZE) {
		/* Return error */
		EL(ha, "incorrect RequestLen\n");
		cmd->Status = EXT_STATUS_INVALID_PARAM;
		cmd->DetailStatus = EXT_DSTATUS_REQUEST_LEN;
		return;
	}

	status = ddi_copyin((void*)(uintptr_t)cmd->RequestAdr, wwpn,
	    cmd->RequestLen, mode);

	if (status != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		EL(ha, "failed, ddi_copyin\n");
		return;
	}

	tq = ql_find_port(ha, wwpn, QLNT_PORT);

	if (tq == NULL || tq->flags & TQF_INITIATOR_DEVICE) {
		/* no matching device */
		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		EL(ha, "failed, device not found\n");
		return;
	}

	/* Copy out the IDs found.  For now we can only return target ID. */
	tmp_addr = (EXT_SCSI_ADDR *)(uintptr_t)cmd->ResponseAdr;

	status = ddi_copyout((void *)wwpn, (void *)&tmp_addr->Target, 8, mode);

	if (status != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		EL(ha, "failed, ddi_copyout\n");
	} else {
		cmd->Status = EXT_STATUS_OK;
		QL_PRINT_9(ha, "done\n");
	}
}

/*
 * ql_host_idx
 *	Gets host order index.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_host_idx(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	uint16_t	idx;

	QL_PRINT_9(ha, "started\n");

	if (cmd->ResponseLen < sizeof (uint16_t)) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = sizeof (uint16_t);
		EL(ha, "failed, ResponseLen < Len=%xh\n", cmd->ResponseLen);
		cmd->ResponseLen = 0;
		return;
	}

	idx = (uint16_t)ha->instance;

	if (ddi_copyout((void *)&idx, (void *)(uintptr_t)(cmd->ResponseAdr),
	    sizeof (uint16_t), mode) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, ddi_copyout\n");
	} else {
		cmd->ResponseLen = sizeof (uint16_t);
		QL_PRINT_9(ha, "done\n");
	}
}

/*
 * ql_host_drvname
 *	Gets host driver name
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_host_drvname(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{

	char		drvname[] = QL_NAME;
	uint32_t	qlnamelen;

	QL_PRINT_9(ha, "started\n");

	qlnamelen = (uint32_t)(strlen(QL_NAME) + 1);

	if (cmd->ResponseLen < qlnamelen) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = qlnamelen;
		EL(ha, "failed, ResponseLen: %xh, needed: %xh\n",
		    cmd->ResponseLen, qlnamelen);
		cmd->ResponseLen = 0;
		return;
	}

	if (ddi_copyout((void *)&drvname,
	    (void *)(uintptr_t)(cmd->ResponseAdr),
	    qlnamelen, mode) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, ddi_copyout\n");
	} else {
		cmd->ResponseLen = qlnamelen - 1;
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_read_nvram
 *	Get NVRAM contents.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_read_nvram(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{

	QL_PRINT_9(ha, "started\n");

	if (cmd->ResponseLen < ha->nvram_cache->size) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = ha->nvram_cache->size;
		EL(ha, "failed, ResponseLen != NVRAM, Len=%xh\n",
		    cmd->ResponseLen);
		cmd->ResponseLen = 0;
		return;
	}

	/* Get NVRAM data. */
	if (ql_nv_util_dump(ha, (void *)(uintptr_t)(cmd->ResponseAdr),
	    mode) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, copy error\n");
	} else {
		cmd->ResponseLen = ha->nvram_cache->size;
		QL_PRINT_9(ha, "done\n");
	}
}

/*
 * ql_write_nvram
 *	Loads NVRAM contents.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_write_nvram(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{

	QL_PRINT_9(ha, "started\n");

	if (cmd->RequestLen < ha->nvram_cache->size) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = ha->nvram_cache->size;
		EL(ha, "failed, RequestLen != NVRAM, Len=%xh\n",
		    cmd->RequestLen);
		return;
	}

	/* Load NVRAM data. */
	if (ql_nv_util_load(ha, (void *)(uintptr_t)(cmd->RequestAdr),
	    mode) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		EL(ha, "failed, copy error\n");
	} else {
		/*EMPTY*/
		QL_PRINT_9(ha, "done\n");
	}
}

/*
 * ql_write_vpd
 *	Loads VPD contents.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_write_vpd(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	QL_PRINT_9(ha, "started\n");

	int32_t		rval = 0;

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_1)) {
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		EL(ha, "failed, invalid request for HBA\n");
		return;
	}

	if (cmd->RequestLen < QL_24XX_VPD_SIZE) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = QL_24XX_VPD_SIZE;
		EL(ha, "failed, RequestLen != VPD len, len passed=%xh\n",
		    cmd->RequestLen);
		return;
	}

	/* Load VPD data. */
	if ((rval = ql_vpd_load(ha, (void *)(uintptr_t)(cmd->RequestAdr),
	    mode)) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->DetailStatus = rval;
		EL(ha, "failed, errno=%x\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_9(ha, "done\n");
	}
}

/*
 * ql_read_vpd
 *	Dumps VPD contents.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_read_vpd(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	QL_PRINT_9(ha, "started\n");

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_1)) {
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		EL(ha, "failed, invalid request for HBA\n");
		return;
	}

	if (cmd->ResponseLen < QL_24XX_VPD_SIZE) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = QL_24XX_VPD_SIZE;
		EL(ha, "failed, ResponseLen < VPD len, len passed=%xh\n",
		    cmd->ResponseLen);
		return;
	}

	/* Dump VPD data. */
	if ((ql_vpd_dump(ha, (void *)(uintptr_t)(cmd->ResponseAdr),
	    mode)) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		EL(ha, "failed,\n");
	} else {
		/*EMPTY*/
		QL_PRINT_9(ha, "done\n");
	}
}

/*
 * ql_get_fcache
 *	Dumps flash cache contents.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_get_fcache(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	uint32_t	bsize, boff, types, cpsize, hsize;
	ql_fcache_t	*fptr;

	QL_PRINT_9(ha, "started\n");

	if (ha->fcache == NULL) {
		cmd->Status = EXT_STATUS_ERR;
		EL(ha, "failed, adapter fcache not setup\n");
		return;
	}

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_1)) {
		bsize = 100;
	} else {
		bsize = 400;
	}

	if (cmd->ResponseLen < bsize) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = bsize;
		EL(ha, "failed, ResponseLen < %d, len passed=%xh\n",
		    bsize, cmd->ResponseLen);
		return;
	}

	boff = 0;
	bsize = 0;
	fptr = ha->fcache;

	/*
	 * For backwards compatibility, get one of each image type
	 */
	types = (FTYPE_BIOS | FTYPE_FCODE | FTYPE_EFI);
	while ((fptr != NULL) && (fptr->buf != NULL) && (types != 0)) {
		/* Get the next image */
		if ((fptr = ql_get_fbuf(ha->fcache, types)) != NULL) {

			cpsize = (fptr->buflen < 100 ? fptr->buflen : 100);

			if (ddi_copyout(fptr->buf,
			    (void *)(uintptr_t)(cmd->ResponseAdr + boff),
			    cpsize, mode) != 0) {
				EL(ha, "ddicopy failed, done\n");
				cmd->Status = EXT_STATUS_COPY_ERR;
				cmd->DetailStatus = 0;
				return;
			}
			boff += 100;
			bsize += cpsize;
			types &= ~(fptr->type);
		}
	}

	/*
	 * Get the firmware image -- it needs to be last in the
	 * buffer at offset 300 for backwards compatibility. Also for
	 * backwards compatibility, the pci header is stripped off.
	 */
	if ((fptr = ql_get_fbuf(ha->fcache, FTYPE_FW)) != NULL) {

		hsize = sizeof (pci_header_t) + sizeof (pci_data_t);
		if (hsize > fptr->buflen) {
			EL(ha, "header size (%xh) exceeds buflen (%xh)\n",
			    hsize, fptr->buflen);
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->DetailStatus = 0;
			return;
		}

		cpsize = ((fptr->buflen - hsize) < 100 ?
		    fptr->buflen - hsize : 100);

		if (ddi_copyout(fptr->buf + hsize,
		    (void *)(uintptr_t)(cmd->ResponseAdr + 300),
		    cpsize, mode) != 0) {
			EL(ha, "fw ddicopy failed, done\n");
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->DetailStatus = 0;
			return;
		}
		bsize += 100;
	}

	cmd->Status = EXT_STATUS_OK;
	cmd->DetailStatus = bsize;

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_get_fcache_ex
 *	Dumps flash cache contents.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_get_fcache_ex(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	uint32_t	bsize = 0;
	uint32_t	boff = 0;
	ql_fcache_t	*fptr;

	QL_PRINT_9(ha, "started\n");

	if (ha->fcache == NULL) {
		cmd->Status = EXT_STATUS_ERR;
		EL(ha, "failed, adapter fcache not setup\n");
		return;
	}

	/* Make sure user passed enough buffer space */
	for (fptr = ha->fcache; fptr != NULL; fptr = fptr->next) {
		bsize += FBUFSIZE;
	}

	if (cmd->ResponseLen < bsize) {
		if (cmd->ResponseLen != 0) {
			EL(ha, "failed, ResponseLen < %d, len passed=%xh\n",
			    bsize, cmd->ResponseLen);
		}
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = bsize;
		return;
	}

	boff = 0;
	fptr = ha->fcache;
	while ((fptr != NULL) && (fptr->buf != NULL)) {
		/* Get the next image */
		if (ddi_copyout(fptr->buf,
		    (void *)(uintptr_t)(cmd->ResponseAdr + boff),
		    (fptr->buflen < FBUFSIZE ? fptr->buflen : FBUFSIZE),
		    mode) != 0) {
			EL(ha, "failed, ddicopy at %xh, done\n", boff);
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->DetailStatus = 0;
			return;
		}
		boff += FBUFSIZE;
		fptr = fptr->next;
	}

	cmd->Status = EXT_STATUS_OK;
	cmd->DetailStatus = bsize;

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_read_flash
 *	Get flash contents.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_read_flash(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	ql_xioctl_t	*xp = ha->xioctl;

	QL_PRINT_9(ha, "started\n");

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_1) &&
	    ql_stall_driver(ha, 0) != QL_SUCCESS) {
		EL(ha, "ql_stall_driver failed\n");
		ql_restart_driver(ha);
		cmd->Status = EXT_STATUS_BUSY;
		cmd->DetailStatus = xp->fdesc.flash_size;
		cmd->ResponseLen = 0;
		return;
	}

	if (ql_setup_fcache(ha) != QL_SUCCESS) {
		cmd->Status = EXT_STATUS_ERR;
		cmd->DetailStatus = xp->fdesc.flash_size;
		EL(ha, "failed, ResponseLen=%xh, flash size=%xh\n",
		    cmd->ResponseLen, xp->fdesc.flash_size);
		cmd->ResponseLen = 0;
	} else {
		/* adjust read size to flash size */
		if (cmd->ResponseLen > xp->fdesc.flash_size) {
			EL(ha, "adjusting req=%xh, max=%xh\n",
			    cmd->ResponseLen, xp->fdesc.flash_size);
			cmd->ResponseLen = xp->fdesc.flash_size;
		}

		/* Get flash data. */
		if (ql_flash_fcode_dump(ha,
		    (void *)(uintptr_t)(cmd->ResponseAdr),
		    (size_t)(cmd->ResponseLen), 0, mode) != 0) {
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->ResponseLen = 0;
			EL(ha, "failed,\n");
		}
	}

	/* Resume I/O */
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_1)) {
		EL(ha, "isp_abort_needed for restart\n");
		ql_awaken_task_daemon(ha, NULL, ISP_ABORT_NEEDED,
		    DRIVER_STALL);
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_write_flash
 *	Loads flash contents.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_write_flash(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	ql_xioctl_t	*xp = ha->xioctl;

	QL_PRINT_9(ha, "started\n");

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_1) &&
	    ql_stall_driver(ha, 0) != QL_SUCCESS) {
		EL(ha, "ql_stall_driver failed\n");
		ql_restart_driver(ha);
		cmd->Status = EXT_STATUS_BUSY;
		cmd->DetailStatus = xp->fdesc.flash_size;
		cmd->ResponseLen = 0;
		return;
	}

	if (ql_setup_fcache(ha) != QL_SUCCESS) {
		cmd->Status = EXT_STATUS_ERR;
		cmd->DetailStatus = xp->fdesc.flash_size;
		EL(ha, "failed, RequestLen=%xh, size=%xh\n",
		    cmd->RequestLen, xp->fdesc.flash_size);
		cmd->ResponseLen = 0;
	} else {
		/* Load flash data. */
		if (cmd->RequestLen > xp->fdesc.flash_size) {
			cmd->Status = EXT_STATUS_ERR;
			cmd->DetailStatus = xp->fdesc.flash_size;
			EL(ha, "failed, RequestLen=%xh, flash size=%xh\n",
			    cmd->RequestLen, xp->fdesc.flash_size);
		} else if (ql_flash_fcode_load(ha,
		    (void *)(uintptr_t)(cmd->RequestAdr),
		    (size_t)(cmd->RequestLen), mode) != 0) {
			cmd->Status = EXT_STATUS_COPY_ERR;
			EL(ha, "failed,\n");
		}
	}

	/* Resume I/O */
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_1)) {
		EL(ha, "isp_abort_needed for restart\n");
		ql_awaken_task_daemon(ha, NULL, ISP_ABORT_NEEDED,
		    DRIVER_STALL);
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_diagnostic_loopback
 *	Performs EXT_CC_LOOPBACK Command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_diagnostic_loopback(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_LOOPBACK_REQ	plbreq;
	EXT_LOOPBACK_RSP	plbrsp;
	ql_mbx_data_t		mr;
	uint32_t		rval, timer, bpsize;
	caddr_t			bp, pld;
	uint16_t		opt;
	boolean_t		loop_up;

	QL_PRINT_9(ha, "started\n");

	/* Get loop back request. */
	if (ddi_copyin((void *)(uintptr_t)cmd->RequestAdr,
	    (void *)&plbreq, sizeof (EXT_LOOPBACK_REQ), mode) != 0) {
		EL(ha, "failed, ddi_copyin\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	/* Check transfer length fits in buffer. */
	if (plbreq.BufferLength < plbreq.TransferCount) {
		EL(ha, "failed, BufferLength=%d, xfercnt=%d\n",

		    plbreq.BufferLength, plbreq.TransferCount);
		cmd->Status = EXT_STATUS_INVALID_PARAM;
		cmd->ResponseLen = 0;
		return;
	}

	/* Allocate command memory. */
	bpsize = plbreq.TransferCount + 4; /* Include opcode size */
	bp = kmem_zalloc(bpsize, KM_SLEEP);
	if (bp == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}
	pld = bp + 4;
	*bp = 0x10;	/* opcode */

	/* Get loopback data. */
	if (ql_get_buffer_data((caddr_t)(uintptr_t)plbreq.BufferAddress,
	    pld, plbreq.TransferCount, mode) != plbreq.TransferCount) {
		EL(ha, "failed, ddi_copyin-2\n");
		kmem_free(bp, bpsize);
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	if (LOOP_RECONFIGURE(ha) ||
	    ql_stall_driver(ha, 0) != QL_SUCCESS) {
		EL(ha, "failed, LOOP_NOT_READY\n");
		ql_restart_driver(ha);
		kmem_free(bp, bpsize);
		cmd->Status = EXT_STATUS_BUSY;
		cmd->ResponseLen = 0;
		return;
	}
	loop_up = ha->task_daemon_flags & LOOP_DOWN ? B_FALSE : B_TRUE;

	/* Shutdown IP. */
	if (ha->flags & IP_INITIALIZED) {
		(void) ql_shutdown_ip(ha);
	}

	/* determine topology so we can send the loopback or the echo */
	/* Echo is supported on 2300's only and above */

	ADAPTER_STATE_LOCK(ha);
	ha->flags |= LOOPBACK_ACTIVE;
	ADAPTER_STATE_UNLOCK(ha);

	opt = plbreq.Options;

	if (CFG_IST(ha, CFG_FCOE_SUPPORT)) {
		opt = (uint16_t)(plbreq.Options & MBC_LOOPBACK_POINT_MASK);
		if (loop_up && opt == MBC_LOOPBACK_POINT_EXTERNAL) {
			if (plbreq.TransferCount > 252) {
				EL(ha, "transfer count (%d) > 252\n",
				    plbreq.TransferCount);
				ql_restart_driver(ha);
				kmem_free(bp, bpsize);
				cmd->Status = EXT_STATUS_INVALID_PARAM;
				cmd->ResponseLen = 0;
				return;
			}
			plbrsp.CommandSent = INT_DEF_LB_ECHO_CMD;
			rval = ql_diag_echo(ha, pld, plbreq.TransferCount,
			    MBC_ECHO_ELS, &mr);
		} else {
			if (CFG_IST(ha, CFG_LOOP_POINT_SUPPORT)) {
				(void) ql_set_loop_point(ha, opt);
			}
			plbrsp.CommandSent = INT_DEF_LB_LOOPBACK_CMD;
			rval = ql_diag_loopback(ha, pld, plbreq.TransferCount,
			    opt, plbreq.IterationCount, &mr);
			if (mr.mb[0] == 0x4005 && mr.mb[1] == 0x17) {
				(void) ql_abort_isp(ha);
			}
			if (CFG_IST(ha, CFG_LOOP_POINT_SUPPORT)) {
				(void) ql_set_loop_point(ha, 0);
			}
		}
	} else {
		if (loop_up && (ha->topology & QL_F_PORT) &&
		    CFG_IST(ha, CFG_LB_ECHO_SUPPORT)) {
			QL_PRINT_9(ha, "F_PORT topology -- using "
			    "echo\n");
			plbrsp.CommandSent = INT_DEF_LB_ECHO_CMD;
			if ((rval = ql_diag_echo(ha, bp, bpsize,
			    (uint16_t)(CFG_IST(ha, CFG_ISP_FW_TYPE_1) ?
			    MBC_ECHO_64BIT : MBC_ECHO_ELS), &mr)) !=
			    QL_SUCCESS) {
				rval = ql_diag_echo(ha, pld,
				    plbreq.TransferCount,
				    (uint16_t)(CFG_IST(ha, CFG_ISP_FW_TYPE_1) ?
				    MBC_ECHO_64BIT : 0), &mr);
			}
		} else {
			plbrsp.CommandSent = INT_DEF_LB_LOOPBACK_CMD;
			if (CFG_IST(ha, CFG_ISP_FW_TYPE_1)) {
				opt = (uint16_t)(opt | MBC_LOOPBACK_64BIT);
			}
			rval = ql_diag_loopback(ha, pld, plbreq.TransferCount,
			    opt, plbreq.IterationCount, &mr);
		}
	}
	ADAPTER_STATE_LOCK(ha);
	ha->flags &= ~LOOPBACK_ACTIVE;
	ADAPTER_STATE_UNLOCK(ha);

	ql_restart_driver(ha);
	if (loop_up && opt == MBC_LOOPBACK_POINT_INTERNAL) {
		timer = 30;
		do {
			delay(100);
		} while (timer-- && LOOP_NOT_READY(ha));
	}

	/* Restart IP if it was shutdown. */
	if (ha->flags & IP_ENABLED && !(ha->flags & IP_INITIALIZED)) {
		(void) ql_initialize_ip(ha);
		ql_isp_rcvbuf(ha);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, diagnostic_loopback_mbx=%xh\n", rval);
		kmem_free(bp, bpsize);
		cmd->Status = EXT_STATUS_MAILBOX;
		cmd->DetailStatus = rval;
		cmd->ResponseLen = 0;
		return;
	}

	/* Return loopback data. */
	if (ql_send_buffer_data(pld, (caddr_t)(uintptr_t)plbreq.BufferAddress,
	    plbreq.TransferCount, mode) != plbreq.TransferCount) {
		EL(ha, "failed, ddi_copyout\n");
		kmem_free(bp, bpsize);
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}
	kmem_free(bp, bpsize);

	/* Return loopback results. */
	plbrsp.BufferAddress = plbreq.BufferAddress;
	plbrsp.BufferLength = plbreq.TransferCount;
	plbrsp.CompletionStatus = mr.mb[0];

	if (plbrsp.CommandSent == INT_DEF_LB_ECHO_CMD) {
		plbrsp.CrcErrorCount = 0;
		plbrsp.DisparityErrorCount = 0;
		plbrsp.FrameLengthErrorCount = 0;
		plbrsp.IterationCountLastError = 0;
	} else {
		plbrsp.CrcErrorCount = mr.mb[1];
		plbrsp.DisparityErrorCount = mr.mb[2];
		plbrsp.FrameLengthErrorCount = mr.mb[3];
		plbrsp.IterationCountLastError =
		    SHORT_TO_LONG(mr.mb[18], mr.mb[19]);
	}

	rval = ddi_copyout((void *)&plbrsp,
	    (void *)(uintptr_t)cmd->ResponseAdr,
	    sizeof (EXT_LOOPBACK_RSP), mode);
	if (rval != 0) {
		EL(ha, "failed, ddi_copyout-2\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}
	cmd->ResponseLen = sizeof (EXT_LOOPBACK_RSP);

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_set_loop_point
 *	Setup loop point for port configuration.
 *
 * Input:
 *	ha:	adapter state structure.
 *	opt:	loop point option.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_set_loop_point(ql_adapter_state_t *ha, uint16_t opt)
{
	ql_mbx_data_t	mr;
	int		rval;
	uint32_t	timer;

	QL_PRINT_9(ha, "started\n");

	/*
	 * We get the current port config, modify the loopback field and
	 * write it back out.
	 */
	if ((rval = ql_get_port_config(ha, &mr)) != QL_SUCCESS) {
		EL(ha, "get_port_config status=%xh\n", rval);
		return (rval);
	}
	/*
	 * Set the loopback mode field while maintaining the others.
	 */
	mr.mb[1] = (uint16_t)(mr.mb[1] & ~LOOPBACK_MODE_FIELD_MASK);
	if (opt == MBC_LOOPBACK_POINT_INTERNAL) {
		mr.mb[1] = (uint16_t)(mr.mb[1] | LOOPBACK_MODE_INTERNAL);
	} else if (CFG_IST(ha, CFG_CTRL_80XX) &&
	    opt == MBC_LOOPBACK_POINT_EXTERNAL) {
		mr.mb[1] = (uint16_t)(mr.mb[1] | LOOPBACK_MODE_EXTERNAL);
	}
	/*
	 * Changing the port configuration will cause the port state to cycle
	 * down and back up. The indication that this has happened is that
	 * the point to point flag gets set.
	 */
	ADAPTER_STATE_LOCK(ha);
	ha->flags &= ~POINT_TO_POINT;
	ADAPTER_STATE_UNLOCK(ha);
	if ((rval = ql_set_port_config(ha, &mr)) != QL_SUCCESS) {
		EL(ha, "set_port_config status=%xh\n", rval);
	}

	/* wait for a while */
	for (timer = opt ? 10 : 0; timer; timer--) {
		if (ha->flags & POINT_TO_POINT) {
			break;
		}
		/* Delay for 1000000 usec (1 second). */
		ql_delay(ha, 1000000);
	}

	QL_PRINT_9(ha, "done\n");

	return (rval);
}

/*
 * ql_send_els_rnid
 *	IOCTL for extended link service RNID command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	User space CT arguments pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_send_els_rnid(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_RNID_REQ	tmp_rnid;
	port_id_t	tmp_fcid;
	caddr_t		tmp_buf, bptr;
	uint32_t	copy_len;
	ql_tgt_t	*tq = NULL;
	EXT_RNID_DATA	rnid_data;
	uint32_t	loop_ready_wait = 10 * 60 * 10;
	int		rval = 0;
	uint32_t	local_hba = 0;

	QL_PRINT_9(ha, "started\n");

	if (DRIVER_SUSPENDED(ha)) {
		EL(ha, "failed, LOOP_NOT_READY\n");
		cmd->Status = EXT_STATUS_BUSY;
		cmd->ResponseLen = 0;
		return;
	}

	if (cmd->RequestLen != sizeof (EXT_RNID_REQ)) {
		/* parameter error */
		EL(ha, "failed, RequestLen < EXT_RNID_REQ, Len=%xh\n",
		    cmd->RequestLen);
		cmd->Status = EXT_STATUS_INVALID_PARAM;
		cmd->DetailStatus = EXT_DSTATUS_REQUEST_LEN;
		cmd->ResponseLen = 0;
		return;
	}

	if (ddi_copyin((void*)(uintptr_t)cmd->RequestAdr,
	    &tmp_rnid, cmd->RequestLen, mode) != 0) {
		EL(ha, "failed, ddi_copyin\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	/* Find loop ID of the device */
	if (tmp_rnid.Addr.Type == EXT_DEF_TYPE_WWNN) {
		bptr = (caddr_t)ha->loginparams.node_ww_name.raw_wwn;
		if (bcmp((void *)bptr, (void *)tmp_rnid.Addr.FcAddr.WWNN,
		    EXT_DEF_WWN_NAME_SIZE) == 0) {
			local_hba = 1;
		} else {
			tq = ql_find_port(ha,
			    (uint8_t *)tmp_rnid.Addr.FcAddr.WWNN, QLNT_NODE);
		}
	} else if (tmp_rnid.Addr.Type == EXT_DEF_TYPE_WWPN) {
		bptr = (caddr_t)ha->loginparams.nport_ww_name.raw_wwn;
		if (bcmp((void *)bptr, (void *)tmp_rnid.Addr.FcAddr.WWPN,
		    EXT_DEF_WWN_NAME_SIZE) == 0) {
			local_hba = 1;
		} else {
			tq = ql_find_port(ha,
			    (uint8_t *)tmp_rnid.Addr.FcAddr.WWPN, QLNT_PORT);
		}
	} else if (tmp_rnid.Addr.Type == EXT_DEF_TYPE_PORTID) {
		/*
		 * Copy caller's d_id to tmp space.
		 */
		bcopy(&tmp_rnid.Addr.FcAddr.Id[1], tmp_fcid.r.d_id,
		    EXT_DEF_PORTID_SIZE_ACTUAL);
		BIG_ENDIAN_24(&tmp_fcid.r.d_id[0]);

		if (bcmp((void *)&ha->d_id, (void *)tmp_fcid.r.d_id,
		    EXT_DEF_PORTID_SIZE_ACTUAL) == 0) {
			local_hba = 1;
		} else {
			tq = ql_find_port(ha, (uint8_t *)tmp_fcid.r.d_id,
			    QLNT_PID);
		}
	}

	/* Allocate memory for command. */
	tmp_buf = kmem_zalloc(SEND_RNID_RSP_SIZE, KM_SLEEP);
	if (tmp_buf == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}

	if (local_hba) {
		rval = ql_get_rnid_params(ha, SEND_RNID_RSP_SIZE, tmp_buf);
		if (rval != QL_SUCCESS) {
			EL(ha, "failed, get_rnid_params_mbx=%xh\n", rval);
			kmem_free(tmp_buf, SEND_RNID_RSP_SIZE);
			cmd->Status = EXT_STATUS_ERR;
			cmd->ResponseLen = 0;
			return;
		}

		/* Save gotten RNID data. */
		bcopy(tmp_buf, &rnid_data, sizeof (EXT_RNID_DATA));

		/* Now build the Send RNID response */
		tmp_buf[0] = (char)(EXT_DEF_RNID_DFORMAT_TOPO_DISC);
		tmp_buf[1] = (2 * EXT_DEF_WWN_NAME_SIZE);
		tmp_buf[2] = 0;
		tmp_buf[3] = sizeof (EXT_RNID_DATA);
		bcopy(ha->loginparams.nport_ww_name.raw_wwn, &tmp_buf[4],
		    EXT_DEF_WWN_NAME_SIZE);
		bcopy(ha->loginparams.node_ww_name.raw_wwn,
		    &tmp_buf[4 + EXT_DEF_WWN_NAME_SIZE],
		    EXT_DEF_WWN_NAME_SIZE);
		bcopy((uint8_t *)&rnid_data,
		    &tmp_buf[4 + 2 * EXT_DEF_WWN_NAME_SIZE],
		    sizeof (EXT_RNID_DATA));
	} else {
		if (tq == NULL) {
			/* no matching device */
			EL(ha, "failed, device not found\n");
			kmem_free(tmp_buf, SEND_RNID_RSP_SIZE);
			cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
			cmd->DetailStatus = EXT_DSTATUS_TARGET;
			cmd->ResponseLen = 0;
			return;
		}

		/* Send command */
		rval = ql_send_rnid_els(ha, tq->loop_id,
		    (uint8_t)tmp_rnid.DataFormat, SEND_RNID_RSP_SIZE, tmp_buf);
		if (rval != QL_SUCCESS) {
			EL(ha, "failed, send_rnid_mbx=%xh, id=%xh\n",
			    rval, tq->loop_id);
			while (LOOP_NOT_READY(ha)) {
				ql_delay(ha, 100000);
				if (loop_ready_wait-- == 0) {
					EL(ha, "failed, loop not ready\n");
					cmd->Status = EXT_STATUS_ERR;
					cmd->ResponseLen = 0;
				}
			}
			rval = ql_send_rnid_els(ha, tq->loop_id,
			    (uint8_t)tmp_rnid.DataFormat, SEND_RNID_RSP_SIZE,
			    tmp_buf);
			if (rval != QL_SUCCESS) {
				/* error */
				EL(ha, "failed, send_rnid_mbx=%xh, id=%xh\n",
				    rval, tq->loop_id);
				kmem_free(tmp_buf, SEND_RNID_RSP_SIZE);
				cmd->Status = EXT_STATUS_ERR;
				cmd->ResponseLen = 0;
				return;
			}
		}
	}

	/* Copy the response */
	copy_len = (cmd->ResponseLen > SEND_RNID_RSP_SIZE) ?
	    SEND_RNID_RSP_SIZE : cmd->ResponseLen;

	if (ql_send_buffer_data(tmp_buf, (caddr_t)(uintptr_t)cmd->ResponseAdr,
	    copy_len, mode) != copy_len) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		EL(ha, "failed, ddi_copyout\n");
	} else {
		cmd->ResponseLen = copy_len;
		if (copy_len < SEND_RNID_RSP_SIZE) {
			cmd->Status = EXT_STATUS_DATA_OVERRUN;
			EL(ha, "failed, EXT_STATUS_DATA_OVERRUN\n");

		} else if (cmd->ResponseLen > SEND_RNID_RSP_SIZE) {
			cmd->Status = EXT_STATUS_DATA_UNDERRUN;
			EL(ha, "failed, EXT_STATUS_DATA_UNDERRUN\n");
		} else {
			cmd->Status = EXT_STATUS_OK;
			QL_PRINT_9(ha, "done\n",
			    ha->instance);
		}
	}

	kmem_free(tmp_buf, SEND_RNID_RSP_SIZE);
}

/*
 * ql_set_host_data
 *	Process IOCTL subcommand to set host/adapter related data.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	User space CT arguments pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_set_host_data(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	QL_PRINT_9(ha, "started, SubCode=%d\n",
	    cmd->SubCode);

	/*
	 * case off on command subcode
	 */
	switch (cmd->SubCode) {
	case EXT_SC_SET_RNID:
		ql_set_rnid_parameters(ha, cmd, mode);
		break;
	case EXT_SC_RST_STATISTICS:
		(void) ql_reset_statistics(ha, cmd);
		break;
	case EXT_SC_SET_BEACON_STATE:
		ql_set_led_state(ha, cmd, mode);
		break;
	case EXT_SC_SET_PARMS:
	case EXT_SC_SET_BUS_MODE:
	case EXT_SC_SET_DR_DUMP_BUF:
	case EXT_SC_SET_RISC_CODE:
	case EXT_SC_SET_FLASH_RAM:
	case EXT_SC_SET_LUN_BITMASK:
	case EXT_SC_SET_RETRY_CNT:
	case EXT_SC_SET_RTIN:
	case EXT_SC_SET_FC_LUN_BITMASK:
	case EXT_SC_ADD_TARGET_DEVICE:
	case EXT_SC_SWAP_TARGET_DEVICE:
	case EXT_SC_SET_SEL_TIMEOUT:
	default:
		/* function not supported. */
		EL(ha, "failed, function not supported=%d\n", cmd->SubCode);
		cmd->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		break;
	}

	if (cmd->Status != EXT_STATUS_OK) {
		EL(ha, "failed, Status=%d\n", cmd->Status);
	} else {
		/*EMPTY*/
		QL_PRINT_9(ha, "done\n");
	}
}

/*
 * ql_get_host_data
 *	Performs EXT_CC_GET_DATA subcommands.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_get_host_data(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	int	out_size = 0;

	QL_PRINT_9(ha, "started, SubCode=%d\n",
	    cmd->SubCode);

	/* case off on command subcode */
	switch (cmd->SubCode) {
	case EXT_SC_GET_STATISTICS:
		out_size = sizeof (EXT_HBA_PORT_STAT);
		break;
	case EXT_SC_GET_FC_STATISTICS:
		out_size = sizeof (EXT_HBA_PORT_STAT);
		break;
	case EXT_SC_GET_PORT_SUMMARY:
		out_size = sizeof (EXT_DEVICEDATA);
		break;
	case EXT_SC_GET_RNID:
		out_size = sizeof (EXT_RNID_DATA);
		break;
	case EXT_SC_GET_TARGET_ID:
		out_size = sizeof (EXT_DEST_ADDR);
		break;
	case EXT_SC_GET_BEACON_STATE:
		out_size = sizeof (EXT_BEACON_CONTROL);
		break;
	case EXT_SC_GET_FC4_STATISTICS:
		out_size = sizeof (EXT_HBA_FC4STATISTICS);
		break;
	case EXT_SC_GET_DCBX_PARAM:
		out_size = EXT_DEF_DCBX_PARAM_BUF_SIZE;
		break;
	case EXT_SC_GET_RESOURCE_CNTS:
		out_size = sizeof (EXT_RESOURCE_CNTS);
		break;
	case EXT_SC_GET_FCF_LIST:
		out_size = sizeof (EXT_FCF_LIST);
		break;
	case EXT_SC_GET_PRIV_STATS:
		out_size = cmd->ResponseLen;
		break;
	case EXT_SC_GET_SCSI_ADDR:
	case EXT_SC_GET_ERR_DETECTIONS:
	case EXT_SC_GET_BUS_MODE:
	case EXT_SC_GET_DR_DUMP_BUF:
	case EXT_SC_GET_RISC_CODE:
	case EXT_SC_GET_FLASH_RAM:
	case EXT_SC_GET_LINK_STATUS:
	case EXT_SC_GET_LOOP_ID:
	case EXT_SC_GET_LUN_BITMASK:
	case EXT_SC_GET_PORT_DATABASE:
	case EXT_SC_GET_PORT_DATABASE_MEM:
	case EXT_SC_GET_POSITION_MAP:
	case EXT_SC_GET_RETRY_CNT:
	case EXT_SC_GET_RTIN:
	case EXT_SC_GET_FC_LUN_BITMASK:
	case EXT_SC_GET_SEL_TIMEOUT:
	default:
		/* function not supported. */
		EL(ha, "failed, function not supported=%d\n", cmd->SubCode);
		cmd->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		cmd->ResponseLen = 0;
		return;
	}

	if (cmd->ResponseLen < out_size) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = out_size;
		EL(ha, "failed, ResponseLen=%xh, size=%xh\n",
		    cmd->ResponseLen, out_size);
		cmd->ResponseLen = 0;
		return;
	}

	switch (cmd->SubCode) {
	case EXT_SC_GET_RNID:
		ql_get_rnid_parameters(ha, cmd, mode);
		break;
	case EXT_SC_GET_STATISTICS:
		ql_get_statistics(ha, cmd, mode);
		break;
	case EXT_SC_GET_FC_STATISTICS:
		ql_get_statistics_fc(ha, cmd, mode);
		break;
	case EXT_SC_GET_FC4_STATISTICS:
		ql_get_statistics_fc4(ha, cmd, mode);
		break;
	case EXT_SC_GET_PORT_SUMMARY:
		ql_get_port_summary(ha, cmd, mode);
		break;
	case EXT_SC_GET_TARGET_ID:
		ql_get_target_id(ha, cmd, mode);
		break;
	case EXT_SC_GET_BEACON_STATE:
		ql_get_led_state(ha, cmd, mode);
		break;
	case EXT_SC_GET_DCBX_PARAM:
		ql_get_dcbx_parameters(ha, cmd, mode);
		break;
	case EXT_SC_GET_FCF_LIST:
		ql_get_fcf_list(ha, cmd, mode);
		break;
	case EXT_SC_GET_RESOURCE_CNTS:
		ql_get_resource_counts(ha, cmd, mode);
		break;
	case EXT_SC_GET_PRIV_STATS:
		ql_get_priv_stats(ha, cmd, mode);
		break;
	}

	if (cmd->Status != EXT_STATUS_OK) {
		EL(ha, "failed, Status=%d\n", cmd->Status);
	} else {
		/*EMPTY*/
		QL_PRINT_9(ha, "done\n");
	}
}

/* ******************************************************************** */
/*			Helper Functions				*/
/* ******************************************************************** */

/*
 * ql_lun_count
 *	Get numbers of LUNS on target.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	q:	device queue pointer.
 *
 * Returns:
 *	Number of LUNs.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_lun_count(ql_adapter_state_t *ha, ql_tgt_t *tq)
{
	int	cnt;

	QL_PRINT_9(ha, "started\n");

	/* Bypass LUNs that failed. */
	cnt = ql_report_lun(ha, tq);
	if (cnt == 0) {
		cnt = ql_inq_scan(ha, tq, ha->maximum_luns_per_target);
	}

	QL_PRINT_9(ha, "done\n");

	return (cnt);
}

/*
 * ql_report_lun
 *	Get numbers of LUNS using report LUN command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	q:	target queue pointer.
 *
 * Returns:
 *	Number of LUNs.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_report_lun(ql_adapter_state_t *ha, ql_tgt_t *tq)
{
	int			rval;
	uint8_t			retries;
	ql_mbx_iocb_t		*pkt;
	ql_rpt_lun_lst_t	*rpt;
	dma_mem_t		dma_mem;
	uint32_t		pkt_size, cnt;
	uint16_t		comp_status;
	uint8_t			scsi_status_h, scsi_status_l, *reqs;

	QL_PRINT_9(ha, "started\n");

	if (DRIVER_SUSPENDED(ha)) {
		EL(ha, "failed, LOOP_NOT_READY\n");
		return (0);
	}

	pkt_size = sizeof (ql_mbx_iocb_t) + sizeof (ql_rpt_lun_lst_t);
	pkt = kmem_zalloc(pkt_size, KM_SLEEP);
	if (pkt == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		return (0);
	}
	rpt = (ql_rpt_lun_lst_t *)((caddr_t)pkt + sizeof (ql_mbx_iocb_t));

	/* Get DMA memory for the IOCB */
	if (ql_get_dma_mem(ha, &dma_mem, sizeof (ql_rpt_lun_lst_t),
	    LITTLE_ENDIAN_DMA, QL_DMA_RING_ALIGN) != QL_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d) DMA memory "
		    "alloc failed", QL_NAME, ha->instance);
		kmem_free(pkt, pkt_size);
		return (0);
	}

	for (retries = 0; retries < 4; retries++) {
		if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
			pkt->cmd24.entry_type = IOCB_CMD_TYPE_7;
			pkt->cmd24.entry_count = 1;

			/* Set N_port handle */
			pkt->cmd24.n_port_hdl = (uint16_t)LE_16(tq->loop_id);

			/* Set target ID */
			pkt->cmd24.target_id[0] = tq->d_id.b.al_pa;
			pkt->cmd24.target_id[1] = tq->d_id.b.area;
			pkt->cmd24.target_id[2] = tq->d_id.b.domain;

			/* Set Virtual Port ID */
			pkt->cmd24.vp_index = ha->vp_index;

			/* Set ISP command timeout. */
			pkt->cmd24.timeout = LE_16(15);

			/* Load SCSI CDB */
			pkt->cmd24.scsi_cdb[0] = SCMD_REPORT_LUNS;
			pkt->cmd24.scsi_cdb[6] =
			    MSB(MSW(sizeof (ql_rpt_lun_lst_t)));
			pkt->cmd24.scsi_cdb[7] =
			    LSB(MSW(sizeof (ql_rpt_lun_lst_t)));
			pkt->cmd24.scsi_cdb[8] =
			    MSB(LSW(sizeof (ql_rpt_lun_lst_t)));
			pkt->cmd24.scsi_cdb[9] =
			    LSB(LSW(sizeof (ql_rpt_lun_lst_t)));
			for (cnt = 0; cnt < MAX_CMDSZ; cnt += 4) {
				ql_chg_endian((uint8_t *)&pkt->cmd24.scsi_cdb
				    + cnt, 4);
			}

			/* Set tag queue control flags */
			pkt->cmd24.task = TA_STAG;

			/* Set transfer direction. */
			pkt->cmd24.control_flags = CF_RD;

			/* Set data segment count. */
			pkt->cmd24.dseg_count = LE_16(1);

			/* Load total byte count. */
			/* Load data descriptor. */
			pkt->cmd24.dseg.address[0] = (uint32_t)
			    LE_32(LSD(dma_mem.cookie.dmac_laddress));
			pkt->cmd24.dseg.address[1] = (uint32_t)
			    LE_32(MSD(dma_mem.cookie.dmac_laddress));
			pkt->cmd24.total_byte_count =
			    LE_32(sizeof (ql_rpt_lun_lst_t));
			pkt->cmd24.dseg.length =
			    LE_32(sizeof (ql_rpt_lun_lst_t));
		} else if (CFG_IST(ha, CFG_ENABLE_64BIT_ADDRESSING)) {
			pkt->cmd3.entry_type = IOCB_CMD_TYPE_3;
			pkt->cmd3.entry_count = 1;
			if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
				pkt->cmd3.target_l = LSB(tq->loop_id);
				pkt->cmd3.target_h = MSB(tq->loop_id);
			} else {
				pkt->cmd3.target_h = LSB(tq->loop_id);
			}
			pkt->cmd3.control_flags_l = CF_DATA_IN | CF_STAG;
			pkt->cmd3.timeout = LE_16(15);
			pkt->cmd3.dseg_count = LE_16(1);
			pkt->cmd3.scsi_cdb[0] = SCMD_REPORT_LUNS;
			pkt->cmd3.scsi_cdb[6] =
			    MSB(MSW(sizeof (ql_rpt_lun_lst_t)));
			pkt->cmd3.scsi_cdb[7] =
			    LSB(MSW(sizeof (ql_rpt_lun_lst_t)));
			pkt->cmd3.scsi_cdb[8] =
			    MSB(LSW(sizeof (ql_rpt_lun_lst_t)));
			pkt->cmd3.scsi_cdb[9] =
			    LSB(LSW(sizeof (ql_rpt_lun_lst_t)));
			pkt->cmd3.byte_count =
			    LE_32(sizeof (ql_rpt_lun_lst_t));
			pkt->cmd3.dseg[0].address[0] = (uint32_t)
			    LE_32(LSD(dma_mem.cookie.dmac_laddress));
			pkt->cmd3.dseg[0].address[1] = (uint32_t)
			    LE_32(MSD(dma_mem.cookie.dmac_laddress));
			pkt->cmd3.dseg[0].length =
			    LE_32(sizeof (ql_rpt_lun_lst_t));
		} else {
			pkt->cmd.entry_type = IOCB_CMD_TYPE_2;
			pkt->cmd.entry_count = 1;
			if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
				pkt->cmd.target_l = LSB(tq->loop_id);
				pkt->cmd.target_h = MSB(tq->loop_id);
			} else {
				pkt->cmd.target_h = LSB(tq->loop_id);
			}
			pkt->cmd.control_flags_l = CF_DATA_IN | CF_STAG;
			pkt->cmd.timeout = LE_16(15);
			pkt->cmd.dseg_count = LE_16(1);
			pkt->cmd.scsi_cdb[0] = SCMD_REPORT_LUNS;
			pkt->cmd.scsi_cdb[6] =
			    MSB(MSW(sizeof (ql_rpt_lun_lst_t)));
			pkt->cmd.scsi_cdb[7] =
			    LSB(MSW(sizeof (ql_rpt_lun_lst_t)));
			pkt->cmd.scsi_cdb[8] =
			    MSB(LSW(sizeof (ql_rpt_lun_lst_t)));
			pkt->cmd.scsi_cdb[9] =
			    LSB(LSW(sizeof (ql_rpt_lun_lst_t)));
			pkt->cmd.byte_count =
			    LE_32(sizeof (ql_rpt_lun_lst_t));
			pkt->cmd.dseg[0].address = (uint32_t)
			    LE_32(LSD(dma_mem.cookie.dmac_laddress));
			pkt->cmd.dseg[0].length =
			    LE_32(sizeof (ql_rpt_lun_lst_t));
		}

		rval = ql_issue_mbx_iocb(ha, (caddr_t)pkt,
		    sizeof (ql_mbx_iocb_t));

		/* Sync in coming DMA buffer. */
		(void) ddi_dma_sync(dma_mem.dma_handle, 0, dma_mem.size,
		    DDI_DMA_SYNC_FORKERNEL);
		/* Copy in coming DMA data. */
		ddi_rep_get8(dma_mem.acc_handle, (uint8_t *)rpt,
		    (uint8_t *)dma_mem.bp, dma_mem.size, DDI_DEV_AUTOINCR);

		if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
			pkt->sts24.entry_status = (uint8_t)
			    (pkt->sts24.entry_status & 0x3c);
			comp_status = (uint16_t)LE_16(pkt->sts24.comp_status);
			scsi_status_h = pkt->sts24.scsi_status_h;
			scsi_status_l = pkt->sts24.scsi_status_l;
			cnt = scsi_status_h & FCP_RSP_LEN_VALID ?
			    LE_32(pkt->sts24.fcp_rsp_data_length) : 0;
			reqs = &pkt->sts24.rsp_sense_data[cnt];
		} else {
			pkt->sts.entry_status = (uint8_t)
			    (pkt->sts.entry_status & 0x7e);
			comp_status = (uint16_t)LE_16(pkt->sts.comp_status);
			scsi_status_h = pkt->sts.scsi_status_h;
			scsi_status_l = pkt->sts.scsi_status_l;
			reqs = &pkt->sts.req_sense_data[0];
		}
		if (rval == QL_SUCCESS && pkt->sts.entry_status != 0) {
			EL(ha, "failed, entry_status=%xh, d_id=%xh\n",
			    pkt->sts.entry_status, tq->d_id.b24);
			rval = QL_FUNCTION_PARAMETER_ERROR;
		}

		if (rval != QL_SUCCESS || comp_status != CS_COMPLETE ||
		    scsi_status_l & STATUS_CHECK) {
			/* Device underrun, treat as OK. */
			if (rval == QL_SUCCESS &&
			    comp_status == CS_DATA_UNDERRUN &&
			    scsi_status_h & FCP_RESID_UNDER) {
				break;
			}

			EL(ha, "failed, issue_iocb=%xh, d_id=%xh, cs=%xh, "
			    "ss_h=%xh, ss_l=%xh\n", rval, tq->d_id.b24,
			    comp_status, scsi_status_h, scsi_status_l);

			if (rval == QL_SUCCESS) {
				if ((comp_status == CS_TIMEOUT) ||
				    (comp_status == CS_PORT_UNAVAILABLE) ||
				    (comp_status == CS_PORT_LOGGED_OUT)) {
					rval = QL_FUNCTION_TIMEOUT;
					break;
				}
				rval = QL_FUNCTION_FAILED;
			} else if (rval == QL_ABORTED) {
				break;
			}

			if (scsi_status_l & STATUS_CHECK) {
				EL(ha, "STATUS_CHECK Sense Data\n%2xh%3xh"
				    "%3xh%3xh%3xh%3xh%3xh%3xh%3xh%3xh%3xh"
				    "%3xh%3xh%3xh%3xh%3xh%3xh%3xh\n", reqs[0],
				    reqs[1], reqs[2], reqs[3], reqs[4],
				    reqs[5], reqs[6], reqs[7], reqs[8],
				    reqs[9], reqs[10], reqs[11], reqs[12],
				    reqs[13], reqs[14], reqs[15], reqs[16],
				    reqs[17]);
			}
		} else {
			break;
		}
		bzero((caddr_t)pkt, pkt_size);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
		rval = 0;
	} else {
		QL_PRINT_9(ha, "LUN list\n");
		QL_DUMP_9(rpt, 8, rpt->hdr.len + 8);
		rval = (int)(BE_32(rpt->hdr.len) / 8);
	}

	kmem_free(pkt, pkt_size);
	ql_free_dma_resource(ha, &dma_mem);

	QL_PRINT_9(ha, "done\n");

	return (rval);
}

/*
 * ql_inq_scan
 *	Get numbers of LUNS using inquiry command.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	tq:		target queue pointer.
 *	count:		scan for the number of existing LUNs.
 *
 * Returns:
 *	Number of LUNs.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_inq_scan(ql_adapter_state_t *ha, ql_tgt_t *tq, int count)
{
	int		lun, cnt, rval;
	ql_mbx_iocb_t	*pkt;
	uint8_t		*inq;
	uint32_t	pkt_size;

	QL_PRINT_9(ha, "started\n");

	pkt_size = sizeof (ql_mbx_iocb_t) + INQ_DATA_SIZE;
	pkt = kmem_zalloc(pkt_size, KM_SLEEP);
	if (pkt == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		return (0);
	}
	inq = (uint8_t *)((caddr_t)pkt + sizeof (ql_mbx_iocb_t));

	cnt = 0;
	for (lun = 0; lun < MAX_LUNS; lun++) {

		if (DRIVER_SUSPENDED(ha)) {
			rval = QL_LOOP_DOWN;
			cnt = 0;
			break;
		}

		rval = ql_inq(ha, tq, lun, pkt, INQ_DATA_SIZE);
		if (rval == QL_SUCCESS) {
			switch (*inq) {
			case DTYPE_DIRECT:
			case DTYPE_PROCESSOR:	/* Appliance. */
			case DTYPE_WORM:
			case DTYPE_RODIRECT:
			case DTYPE_SCANNER:
			case DTYPE_OPTICAL:
			case DTYPE_CHANGER:
			case DTYPE_ESI:
				cnt++;
				break;
			case DTYPE_SEQUENTIAL:
				cnt++;
				tq->flags |= TQF_TAPE_DEVICE;
				break;
			default:
				QL_PRINT_9(ha, "failed, "
				    "unsupported device id=%xh, lun=%d, "
				    "type=%xh\n", tq->loop_id,
				    lun, *inq);
				break;
			}

			if (*inq == DTYPE_ESI || cnt >= count) {
				break;
			}
		} else if (rval == QL_ABORTED || rval == QL_FUNCTION_TIMEOUT) {
			cnt = 0;
			break;
		}
	}

	kmem_free(pkt, pkt_size);

	QL_PRINT_9(ha, "done\n");

	return (cnt);
}

/*
 * ql_inq
 *	Issue inquiry command.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	tq:		target queue pointer.
 *	lun:		LUN number.
 *	pkt:		command and buffer pointer.
 *	inq_len:	amount of inquiry data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_inq(ql_adapter_state_t *ha, ql_tgt_t *tq, int lun, ql_mbx_iocb_t *pkt,
    uint32_t inq_len)
{
	dma_mem_t	dma_mem;
	int		rval, retries;
	uint32_t	pkt_size, cnt;
	uint16_t	comp_status;
	uint8_t		scsi_status_h, scsi_status_l, *reqs;
	caddr_t		inq_data;
	uint64_t	lun_addr;
	fcp_ent_addr_t	*fcp_ent_addr = (fcp_ent_addr_t *)&lun_addr;

	QL_PRINT_9(ha, "started\n");

	if (DRIVER_SUSPENDED(ha)) {
		EL(ha, "failed, loop down\n");
		return (QL_FUNCTION_TIMEOUT);
	}

	pkt_size = (uint32_t)(sizeof (ql_mbx_iocb_t) + inq_len);
	bzero((caddr_t)pkt, pkt_size);

	inq_data = (caddr_t)pkt + sizeof (ql_mbx_iocb_t);

	/* Get DMA memory for the IOCB */
	if (ql_get_dma_mem(ha, &dma_mem, inq_len,
	    LITTLE_ENDIAN_DMA, QL_DMA_RING_ALIGN) != QL_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d) DMA memory "
		    "alloc failed", QL_NAME, ha->instance);
		return (0);
	}

	for (retries = 0; retries < 4; retries++) {
		if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
			pkt->cmd24.entry_type = IOCB_CMD_TYPE_7;
			pkt->cmd24.entry_count = 1;

			/* Set LUN number */
			lun_addr = ql_get_lun_addr(tq, lun);
			fcp_ent_addr = (fcp_ent_addr_t *)&lun_addr;
			pkt->cmd24.fcp_lun[2] =
			    lobyte(fcp_ent_addr->ent_addr_0);
			pkt->cmd24.fcp_lun[3] =
			    hibyte(fcp_ent_addr->ent_addr_0);
			pkt->cmd24.fcp_lun[0] =
			    lobyte(fcp_ent_addr->ent_addr_1);
			pkt->cmd24.fcp_lun[1] =
			    hibyte(fcp_ent_addr->ent_addr_1);
			pkt->cmd24.fcp_lun[6] =
			    lobyte(fcp_ent_addr->ent_addr_2);
			pkt->cmd24.fcp_lun[7] =
			    hibyte(fcp_ent_addr->ent_addr_2);
			pkt->cmd24.fcp_lun[4] =
			    lobyte(fcp_ent_addr->ent_addr_3);
			pkt->cmd24.fcp_lun[5] =
			    hibyte(fcp_ent_addr->ent_addr_3);

			/* Set N_port handle */
			pkt->cmd24.n_port_hdl = (uint16_t)LE_16(tq->loop_id);

			/* Set target ID */
			pkt->cmd24.target_id[0] = tq->d_id.b.al_pa;
			pkt->cmd24.target_id[1] = tq->d_id.b.area;
			pkt->cmd24.target_id[2] = tq->d_id.b.domain;

			/* Set Virtual Port ID */
			pkt->cmd24.vp_index = ha->vp_index;

			/* Set ISP command timeout. */
			pkt->cmd24.timeout = LE_16(15);

			/* Load SCSI CDB */
			pkt->cmd24.scsi_cdb[0] = SCMD_INQUIRY;
			pkt->cmd24.scsi_cdb[4] = LSB(LSW(inq_len));
			for (cnt = 0; cnt < MAX_CMDSZ; cnt += 4) {
				ql_chg_endian((uint8_t *)&pkt->cmd24.scsi_cdb
				    + cnt, 4);
			}

			/* Set tag queue control flags */
			pkt->cmd24.task = TA_STAG;

			/* Set transfer direction. */
			pkt->cmd24.control_flags = CF_RD;

			/* Set data segment count. */
			pkt->cmd24.dseg_count = LE_16(1);

			/* Load total byte count. */
			pkt->cmd24.total_byte_count = LE_32(inq_len);

			/* Load data descriptor. */
			pkt->cmd24.dseg.address[0] = (uint32_t)
			    LE_32(LSD(dma_mem.cookie.dmac_laddress));
			pkt->cmd24.dseg.address[1] = (uint32_t)
			    LE_32(MSD(dma_mem.cookie.dmac_laddress));
			pkt->cmd24.dseg.length = LE_32(inq_len);
		} else if (CFG_IST(ha, CFG_ENABLE_64BIT_ADDRESSING)) {
			pkt->cmd3.entry_type = IOCB_CMD_TYPE_3;
			cnt = CMD_TYPE_3_DATA_SEGMENTS;

			pkt->cmd3.entry_count = 1;
			if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
				pkt->cmd3.target_l = LSB(tq->loop_id);
				pkt->cmd3.target_h = MSB(tq->loop_id);
			} else {
				pkt->cmd3.target_h = LSB(tq->loop_id);
			}
			pkt->cmd3.lun_l = LSB(lun);
			pkt->cmd3.lun_h = MSB(lun);
			pkt->cmd3.control_flags_l = CF_DATA_IN | CF_STAG;
			pkt->cmd3.timeout = LE_16(15);
			pkt->cmd3.scsi_cdb[0] = SCMD_INQUIRY;
			pkt->cmd3.scsi_cdb[4] = LSB(LSW(inq_len));
			pkt->cmd3.dseg_count = LE_16(1);
			pkt->cmd3.byte_count = LE_32(inq_len);
			pkt->cmd3.dseg[0].address[0] = (uint32_t)
			    LE_32(LSD(dma_mem.cookie.dmac_laddress));
			pkt->cmd3.dseg[0].address[1] = (uint32_t)
			    LE_32(MSD(dma_mem.cookie.dmac_laddress));
			pkt->cmd3.dseg[0].length = LE_32(inq_len);
		} else {
			pkt->cmd.entry_type = IOCB_CMD_TYPE_2;
			cnt = CMD_TYPE_2_DATA_SEGMENTS;

			pkt->cmd.entry_count = 1;
			if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
				pkt->cmd.target_l = LSB(tq->loop_id);
				pkt->cmd.target_h = MSB(tq->loop_id);
			} else {
				pkt->cmd.target_h = LSB(tq->loop_id);
			}
			pkt->cmd.lun_l = LSB(lun);
			pkt->cmd.lun_h = MSB(lun);
			pkt->cmd.control_flags_l = CF_DATA_IN | CF_STAG;
			pkt->cmd.timeout = LE_16(15);
			pkt->cmd.scsi_cdb[0] = SCMD_INQUIRY;
			pkt->cmd.scsi_cdb[4] = LSB(LSW(inq_len));
			pkt->cmd.dseg_count = LE_16(1);
			pkt->cmd.byte_count = LE_32(inq_len);
			pkt->cmd.dseg[0].address = (uint32_t)
			    LE_32(LSD(dma_mem.cookie.dmac_laddress));
			pkt->cmd.dseg[0].length = LE_32(inq_len);
		}

/*		rval = ql_issue_mbx_iocb(ha, (caddr_t)pkt, pkt_size); */
		rval = ql_issue_mbx_iocb(ha, (caddr_t)pkt,
		    sizeof (ql_mbx_iocb_t));

		/* Sync in coming IOCB DMA buffer. */
		(void) ddi_dma_sync(dma_mem.dma_handle, 0, dma_mem.size,
		    DDI_DMA_SYNC_FORKERNEL);
		/* Copy in coming DMA data. */
		ddi_rep_get8(dma_mem.acc_handle, (uint8_t *)inq_data,
		    (uint8_t *)dma_mem.bp, dma_mem.size, DDI_DEV_AUTOINCR);

		if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
			pkt->sts24.entry_status = (uint8_t)
			    (pkt->sts24.entry_status & 0x3c);
			comp_status = (uint16_t)LE_16(pkt->sts24.comp_status);
			scsi_status_h = pkt->sts24.scsi_status_h;
			scsi_status_l = pkt->sts24.scsi_status_l;
			cnt = scsi_status_h & FCP_RSP_LEN_VALID ?
			    LE_32(pkt->sts24.fcp_rsp_data_length) : 0;
			reqs = &pkt->sts24.rsp_sense_data[cnt];
		} else {
			pkt->sts.entry_status = (uint8_t)
			    (pkt->sts.entry_status & 0x7e);
			comp_status = (uint16_t)LE_16(pkt->sts.comp_status);
			scsi_status_h = pkt->sts.scsi_status_h;
			scsi_status_l = pkt->sts.scsi_status_l;
			reqs = &pkt->sts.req_sense_data[0];
		}
		if (rval == QL_SUCCESS && pkt->sts.entry_status != 0) {
			EL(ha, "failed, entry_status=%xh, d_id=%xh\n",
			    pkt->sts.entry_status, tq->d_id.b24);
			rval = QL_FUNCTION_PARAMETER_ERROR;
		}

		if (rval != QL_SUCCESS || comp_status != CS_COMPLETE ||
		    scsi_status_l & STATUS_CHECK) {
			EL(ha, "failed, issue_iocb=%xh, d_id=%xh, cs=%xh, "
			    "ss_h=%xh, ss_l=%xh\n", rval, tq->d_id.b24,
			    comp_status, scsi_status_h, scsi_status_l);

			if (rval == QL_SUCCESS) {
				if ((comp_status == CS_TIMEOUT) ||
				    (comp_status == CS_PORT_UNAVAILABLE) ||
				    (comp_status == CS_PORT_LOGGED_OUT)) {
					rval = QL_FUNCTION_TIMEOUT;
					break;
				}
				rval = QL_FUNCTION_FAILED;
			}

			if (scsi_status_l & STATUS_CHECK) {
				EL(ha, "STATUS_CHECK Sense Data\n%2xh%3xh"
				    "%3xh%3xh%3xh%3xh%3xh%3xh%3xh%3xh%3xh"
				    "%3xh%3xh%3xh%3xh%3xh%3xh%3xh\n", reqs[0],
				    reqs[1], reqs[2], reqs[3], reqs[4],
				    reqs[5], reqs[6], reqs[7], reqs[8],
				    reqs[9], reqs[10], reqs[11], reqs[12],
				    reqs[13], reqs[14], reqs[15], reqs[16],
				    reqs[17]);
			}
		} else {
			break;
		}
	}
	ql_free_dma_resource(ha, &dma_mem);

	QL_PRINT_9(ha, "done\n");

	return (rval);
}

/*
 * ql_get_buffer_data
 *	Copies data from user space to kernal buffer.
 *
 * Input:
 *	src:	User source buffer address.
 *	dst:	Kernal destination buffer address.
 *	size:	Amount of data.
 *	mode:	flags.
 *
 * Returns:
 *	Returns number of bytes transferred.
 *
 * Context:
 *	Kernel context.
 */
static uint32_t
ql_get_buffer_data(caddr_t src, caddr_t dst, uint32_t size, int mode)
{
	uint32_t	cnt;

	for (cnt = 0; cnt < size; cnt++) {
		if (ddi_copyin(src++, dst++, 1, mode) != 0) {
			QL_PRINT_2(NULL, "failed, ddi_copyin\n");
			break;
		}
	}

	return (cnt);
}

/*
 * ql_send_buffer_data
 *	Copies data from kernal buffer to user space.
 *
 * Input:
 *	src:	Kernal source buffer address.
 *	dst:	User destination buffer address.
 *	size:	Amount of data.
 *	mode:	flags.
 *
 * Returns:
 *	Returns number of bytes transferred.
 *
 * Context:
 *	Kernel context.
 */
static uint32_t
ql_send_buffer_data(caddr_t src, caddr_t dst, uint32_t size, int mode)
{
	uint32_t	cnt;

	for (cnt = 0; cnt < size; cnt++) {
		if (ddi_copyout(src++, dst++, 1, mode) != 0) {
			QL_PRINT_2(NULL, "failed, ddi_copyin\n");
			break;
		}
	}

	return (cnt);
}

/*
 * ql_find_port
 *	Locates device queue.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	name:	device port name.
 *
 * Returns:
 *	Returns target queue pointer.
 *
 * Context:
 *	Kernel context.
 */
static ql_tgt_t *
ql_find_port(ql_adapter_state_t *ha, uint8_t *name, uint16_t type)
{
	ql_link_t	*link;
	ql_tgt_t	*tq;
	uint16_t	index;

	/* Scan port list for requested target */
	for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
		for (link = ha->dev[index].first; link != NULL;
		    link = link->next) {
			tq = link->base_address;

			switch (type) {
			case QLNT_LOOP_ID:
				if (bcmp(name, &tq->loop_id,
				    sizeof (uint16_t)) == 0) {
					return (tq);
				}
				break;
			case QLNT_PORT:
				if (bcmp(name, tq->port_name, 8) == 0) {
					return (tq);
				}
				break;
			case QLNT_NODE:
				if (bcmp(name, tq->node_name, 8) == 0) {
					return (tq);
				}
				break;
			case QLNT_PID:
				if (bcmp(name, tq->d_id.r.d_id,
				    sizeof (tq->d_id.r.d_id)) == 0) {
					return (tq);
				}
				break;
			default:
				EL(ha, "failed, invalid type=%d\n", type);
				return (NULL);
			}
		}
	}

	return (NULL);
}

/*
 * ql_24xx_flash_desc
 *	Get flash descriptor table.
 *
 * Input:
 *	ha:		adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_24xx_flash_desc(ql_adapter_state_t *ha)
{
	uint32_t	cnt;
	uint16_t	chksum, *bp, data;
	int		rval;
	flash_desc_t	*fdesc;
	ql_xioctl_t	*xp = ha->xioctl;

	QL_PRINT_9(ha, "started\n");

	if (ha->flash_desc_addr == 0) {
		QL_PRINT_9(ha, "desc ptr=0\n");
		return (QL_FUNCTION_FAILED);
	}

	if ((fdesc = kmem_zalloc(sizeof (flash_desc_t), KM_SLEEP)) == NULL) {
		EL(ha, "kmem_zalloc=null\n");
		return (QL_MEMORY_ALLOC_FAILED);
	}
	rval = ql_dump_fcode(ha, (uint8_t *)fdesc, sizeof (flash_desc_t),
	    ha->flash_desc_addr << 2);
	if (rval != QL_SUCCESS) {
		EL(ha, "read status=%xh\n", rval);
		kmem_free(fdesc, sizeof (flash_desc_t));
		return (rval);
	}

	chksum = 0;
	bp = (uint16_t *)fdesc;
	for (cnt = 0; cnt < (sizeof (flash_desc_t)) / 2; cnt++) {
		data = *bp++;
		LITTLE_ENDIAN_16(&data);
		chksum += data;
	}

	LITTLE_ENDIAN_32(&fdesc->flash_valid);
	LITTLE_ENDIAN_16(&fdesc->flash_version);
	LITTLE_ENDIAN_16(&fdesc->flash_len);
	LITTLE_ENDIAN_16(&fdesc->flash_checksum);
	LITTLE_ENDIAN_16(&fdesc->flash_manuf);
	LITTLE_ENDIAN_16(&fdesc->flash_id);
	LITTLE_ENDIAN_32(&fdesc->block_size);
	LITTLE_ENDIAN_32(&fdesc->alt_block_size);
	LITTLE_ENDIAN_32(&fdesc->flash_size);
	LITTLE_ENDIAN_32(&fdesc->write_enable_data);
	LITTLE_ENDIAN_32(&fdesc->read_timeout);

	/* flash size in desc table is in 1024 bytes */
	fdesc->flash_size = fdesc->flash_size * 0x400;

	if (chksum != 0 || fdesc->flash_valid != FLASH_DESC_VAILD ||
	    fdesc->flash_version != FLASH_DESC_VERSION) {
		EL(ha, "invalid descriptor table\n");
		kmem_free(fdesc, sizeof (flash_desc_t));
		return (QL_FUNCTION_FAILED);
	}

	bcopy(fdesc, &xp->fdesc, sizeof (flash_desc_t));
	kmem_free(fdesc, sizeof (flash_desc_t));

	QL_PRINT_9(ha, "done\n");

	return (QL_SUCCESS);
}

/*
 * ql_setup_flash
 *	Gets the manufacturer and id number of the flash chip, and
 *	sets up the size parameter.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	int:	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_setup_flash(ql_adapter_state_t *ha)
{
	ql_xioctl_t	*xp = ha->xioctl;
	int		rval = QL_SUCCESS;

	if (xp->fdesc.flash_size != 0) {
		return (rval);
	}

	if (CFG_IST(ha, CFG_CTRL_22XX) && !ha->subven_id) {
		return (QL_FUNCTION_FAILED);
	}

	if (CFG_IST(ha, CFG_CTRL_252780818283)) {
		/*
		 * Temporarily set the ha->xioctl->fdesc.flash_size to
		 * 25xx flash size to avoid failing of ql_dump_focde.
		 */
		if (CFG_IST(ha, CFG_CTRL_278083)) {
			ha->xioctl->fdesc.flash_size = 0x1000000;
		} else if (CFG_IST(ha, CFG_CTRL_82XX)) {
			ha->xioctl->fdesc.flash_size = 0x800000;
		} else if (CFG_IST(ha, CFG_CTRL_25XX)) {
			ha->xioctl->fdesc.flash_size = 0x200000;
		} else {
			ha->xioctl->fdesc.flash_size = 0x400000;
		}

		if (ql_24xx_flash_desc(ha) == QL_SUCCESS) {
			EL(ha, "flash desc table ok, exit\n");
			return (rval);
		}
		if (CFG_IST(ha, CFG_CTRL_82XX)) {
			xp->fdesc.flash_manuf = MXIC_FLASH;
			xp->fdesc.flash_id = MXIC_FLASHID_25LXX;
			xp->fdesc.flash_len = 0x17;
		} else {
			(void) ql_24xx_flash_id(ha);
		}

	} else if (CFG_IST(ha, CFG_CTRL_24XX)) {
		(void) ql_24xx_flash_id(ha);
	} else {
		ql_flash_enable(ha);

		ql_write_flash_byte(ha, 0x5555, 0xaa);
		ql_write_flash_byte(ha, 0x2aaa, 0x55);
		ql_write_flash_byte(ha, 0x5555, 0x90);
		xp->fdesc.flash_manuf = (uint8_t)ql_read_flash_byte(ha, 0x0000);

		if (CFG_IST(ha, CFG_SBUS_CARD)) {
			ql_write_flash_byte(ha, 0xaaaa, 0xaa);
			ql_write_flash_byte(ha, 0x5555, 0x55);
			ql_write_flash_byte(ha, 0xaaaa, 0x90);
			xp->fdesc.flash_id = (uint16_t)
			    ql_read_flash_byte(ha, 0x0002);
		} else {
			ql_write_flash_byte(ha, 0x5555, 0xaa);
			ql_write_flash_byte(ha, 0x2aaa, 0x55);
			ql_write_flash_byte(ha, 0x5555, 0x90);
			xp->fdesc.flash_id = (uint16_t)
			    ql_read_flash_byte(ha, 0x0001);
		}

		ql_write_flash_byte(ha, 0x5555, 0xaa);
		ql_write_flash_byte(ha, 0x2aaa, 0x55);
		ql_write_flash_byte(ha, 0x5555, 0xf0);

		ql_flash_disable(ha);
	}

	/* Default flash descriptor table. */
	xp->fdesc.write_statusreg_cmd = 1;
	xp->fdesc.write_enable_bits = 0;
	xp->fdesc.unprotect_sector_cmd = 0;
	xp->fdesc.protect_sector_cmd = 0;
	xp->fdesc.write_disable_bits = 0xbc;
	xp->fdesc.block_size = 0x10000;
	xp->fdesc.erase_cmd = 0xd8;

	switch (xp->fdesc.flash_manuf) {
	case AMD_FLASH:
		switch (xp->fdesc.flash_id) {
		case SPAN_FLASHID_16384K:
			if (xp->fdesc.flash_len == 0x18) {
				xp->fdesc.flash_size = 0x1000000;
			} else {
				rval = QL_FUNCTION_FAILED;
			}
			break;
		case SPAN_FLASHID_2048K:
			xp->fdesc.flash_size = 0x200000;
			break;
		case AMD_FLASHID_1024K:
			xp->fdesc.flash_size = 0x100000;
			break;
		case AMD_FLASHID_512K:
		case AMD_FLASHID_512Kt:
		case AMD_FLASHID_512Kb:
			if (CFG_IST(ha, CFG_SBUS_CARD)) {
				xp->fdesc.flash_size = QL_SBUS_FCODE_SIZE;
			} else {
				xp->fdesc.flash_size = 0x80000;
			}
			break;
		case AMD_FLASHID_128K:
			xp->fdesc.flash_size = 0x20000;
			break;
		default:
			rval = QL_FUNCTION_FAILED;
			break;
		}
		break;
	case ST_FLASH:
		switch (xp->fdesc.flash_id) {
		case ST_FLASHID_128K:
			xp->fdesc.flash_size = 0x20000;
			break;
		case ST_FLASHID_512K:
			xp->fdesc.flash_size = 0x80000;
			break;
		case ST_FLASHID_M25PXX:
			if (xp->fdesc.flash_len == 0x14) {
				xp->fdesc.flash_size = 0x100000;
			} else if (xp->fdesc.flash_len == 0x15) {
				xp->fdesc.flash_size = 0x200000;
			} else {
				rval = QL_FUNCTION_FAILED;
			}
			break;
		case ST_FLASHID_N25QXXX:
			if (xp->fdesc.flash_len == 0x18) {
				xp->fdesc.flash_size = 0x1000000;
			} else {
				rval = QL_FUNCTION_FAILED;
			}
			break;
		default:
			rval = QL_FUNCTION_FAILED;
			break;
		}
		break;
	case SST_FLASH:
		switch (xp->fdesc.flash_id) {
		case SST_FLASHID_128K:
			xp->fdesc.flash_size = 0x20000;
			break;
		case SST_FLASHID_1024K_A:
			xp->fdesc.flash_size = 0x100000;
			xp->fdesc.block_size = 0x8000;
			xp->fdesc.erase_cmd = 0x52;
			break;
		case SST_FLASHID_1024K:
		case SST_FLASHID_1024K_B:
			xp->fdesc.flash_size = 0x100000;
			break;
		case SST_FLASHID_2048K:
			xp->fdesc.flash_size = 0x200000;
			break;
		default:
			rval = QL_FUNCTION_FAILED;
			break;
		}
		break;
	case MXIC_FLASH:
		switch (xp->fdesc.flash_id) {
		case MXIC_FLASHID_512K:
			xp->fdesc.flash_size = 0x80000;
			break;
		case MXIC_FLASHID_1024K:
			xp->fdesc.flash_size = 0x100000;
			break;
		case MXIC_FLASHID_25LXX:
			xp->fdesc.write_disable_bits = 0xbc;
			if (xp->fdesc.flash_len == 0x14) {
				xp->fdesc.flash_size = 0x100000;
			} else if (xp->fdesc.flash_len == 0x15) {
				xp->fdesc.flash_size = 0x200000;
			} else if (xp->fdesc.flash_len == 0x16) {
				xp->fdesc.flash_size = 0x400000;
			} else if (xp->fdesc.flash_len == 0x17) {
				xp->fdesc.flash_size = 0x800000;
			} else if (xp->fdesc.flash_len == 0x18) {
				xp->fdesc.flash_size = 0x1000000;
			} else {
				rval = QL_FUNCTION_FAILED;
			}
			break;
		default:
			rval = QL_FUNCTION_FAILED;
			break;
		}
		break;
	case ATMEL_FLASH:
		switch (xp->fdesc.flash_id) {
		case ATMEL_FLASHID_1024K:
			xp->fdesc.flash_size = 0x100000;
			xp->fdesc.write_disable_bits = 0xbc;
			xp->fdesc.unprotect_sector_cmd = 0x39;
			xp->fdesc.protect_sector_cmd = 0x36;
			break;
		default:
			rval = QL_FUNCTION_FAILED;
			break;
		}
		break;
	case WINBOND_FLASH:
		switch (xp->fdesc.flash_id) {
		case WINBOND_FLASHID:
			if (xp->fdesc.flash_len == 0x15) {
				xp->fdesc.flash_size = 0x200000;
			} else if (xp->fdesc.flash_len == 0x16) {
				xp->fdesc.flash_size = 0x400000;
			} else if (xp->fdesc.flash_len == 0x17) {
				xp->fdesc.flash_size = 0x800000;
			} else if (xp->fdesc.flash_len == 0x18) {
				xp->fdesc.flash_size = 0x1000000;
			} else {
				rval = QL_FUNCTION_FAILED;
			}
			break;
		default:
			rval = QL_FUNCTION_FAILED;
			break;
		}
		break;
	case INTEL_FLASH:
		switch (xp->fdesc.flash_id) {
		case INTEL_FLASHID:
			if (xp->fdesc.flash_len == 0x11) {
				xp->fdesc.flash_size = 0x200000;
			} else if (xp->fdesc.flash_len == 0x12) {
				xp->fdesc.flash_size = 0x400000;
			} else if (xp->fdesc.flash_len == 0x13) {
				xp->fdesc.flash_size = 0x800000;
			} else {
				rval = QL_FUNCTION_FAILED;
			}
			break;
		default:
			rval = QL_FUNCTION_FAILED;
			break;
		}
		break;
	case EON_FLASH:
		switch (xp->fdesc.flash_id) {
		case EON_FLASHID_EN25QXXX:
			if (xp->fdesc.flash_len == 0x18) {
				xp->fdesc.flash_size = 0x1000000;
			} else {
				rval = QL_FUNCTION_FAILED;
			}
			break;
		default:
			rval = QL_FUNCTION_FAILED;
			break;
		}
		break;
	default:
		rval = QL_FUNCTION_FAILED;
		break;
	}

	/* Try flash table later. */
	if (rval != QL_SUCCESS && CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		EL(ha, "no default id\n");
		return (QL_SUCCESS);
	}

	/*
	 * hack for non std 2312/2322 and 6312/6322 boards. hardware people
	 * need to use either the 128k flash chip (original), or something
	 * larger. For driver purposes, we'll treat it as a 128k flash chip.
	 */
	if ((ha->device_id == 0x2312 || ha->device_id == 0x6312 ||
	    ha->device_id == 0x2322 || ha->device_id == 0x6322) &&
	    (xp->fdesc.flash_size > 0x20000) &&
	    (CFG_IST(ha, CFG_SBUS_CARD) == 0)) {
		EL(ha, "chip exceeds max size: %xh, using 128k\n",
		    xp->fdesc.flash_size);
		xp->fdesc.flash_size = 0x20000;
	}

	if (rval == QL_SUCCESS) {
		EL(ha, "man_id=%xh, flash_id=%xh, size=%xh\n",
		    xp->fdesc.flash_manuf, xp->fdesc.flash_id,
		    xp->fdesc.flash_size);
	} else {
		EL(ha, "unsupported mfr / type: man_id=%xh, flash_id=%xh\n",
		    xp->fdesc.flash_manuf, xp->fdesc.flash_id);
	}

	return (rval);
}

/*
 * ql_flash_fcode_load
 *	Loads fcode data into flash from application.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	bp:	user buffer address.
 *	size:	user buffer size.
 *	mode:	flags
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_flash_fcode_load(ql_adapter_state_t *ha, void *bp, uint32_t bsize,
    int mode)
{
	uint8_t		*bfp;
	ql_xioctl_t	*xp = ha->xioctl;
	int		rval = 0;

	QL_PRINT_9(ha, "started\n");

	if (bsize > xp->fdesc.flash_size) {
		EL(ha, "failed, bufsize: %xh, flash size: %xh\n", bsize,
		    xp->fdesc.flash_size);
		return (ENOMEM);
	}

	if ((bfp = (uint8_t *)kmem_zalloc(bsize, KM_SLEEP)) == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		rval = ENOMEM;
	} else {
		if (ddi_copyin(bp, bfp, bsize, mode) != 0) {
			EL(ha, "failed, ddi_copyin\n");
			rval = EFAULT;
		} else if (ql_load_fcode(ha, bfp, bsize, 0) != QL_SUCCESS) {
			EL(ha, "failed, load_fcode\n");
			rval = EFAULT;
		} else {
			/* Reset caches on all adapter instances. */
			ql_update_flash_caches(ha);
			rval = 0;
		}
		kmem_free(bfp, bsize);
	}

	QL_PRINT_9(ha, "done\n");

	return (rval);
}

/*
 * ql_load_fcode
 *	Loads fcode in to flash.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	dp:	data pointer.
 *	size:	data length.
 *	addr:	flash byte address.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_load_fcode(ql_adapter_state_t *ha, uint8_t *dp, uint32_t size, uint32_t addr)
{
	uint32_t	cnt;
	int		rval;

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		return (ql_24xx_load_flash(ha, dp, size, addr));
	}

	QL_PRINT_9(ha, "started\n");

	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		/*
		 * sbus has an additional check to make
		 * sure they don't brick the HBA.
		 */
		if (dp[0] != 0xf1) {
			EL(ha, "failed, incorrect fcode for sbus\n");
			return (QL_FUNCTION_PARAMETER_ERROR);
		}
	}

	GLOBAL_HW_LOCK();

	/* Enable Flash Read/Write. */
	ql_flash_enable(ha);

	/* Erase flash prior to write. */
	rval = ql_erase_flash(ha, 0);

	if (rval == QL_SUCCESS) {
		/* Write fcode data to flash. */
		for (cnt = 0; cnt < (uint32_t)size; cnt++) {
			/* Allow other system activity. */
			if (cnt % 0x1000 == 0) {
				drv_usecwait(1);
			}
			rval = ql_program_flash_address(ha, addr++, *dp++);
			if (rval != QL_SUCCESS)
				break;
		}
	}

	ql_flash_disable(ha);

	GLOBAL_HW_UNLOCK();

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_9(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_flash_fcode_dump
 *	Dumps FLASH to application.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	bp:	user buffer address.
 *	bsize:	user buffer size
 *	faddr:	flash byte address
 *	mode:	flags
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_flash_fcode_dump(ql_adapter_state_t *ha, void *bp, uint32_t bsize,
    uint32_t faddr, int mode)
{
	uint8_t		*bfp;
	int		rval;
	ql_xioctl_t	*xp = ha->xioctl;

	QL_PRINT_9(ha, "started\n");

	/* adjust max read size to flash size */
	if (bsize > xp->fdesc.flash_size) {
		EL(ha, "adjusting req=%xh, max=%xh\n", bsize,
		    xp->fdesc.flash_size);
		bsize = xp->fdesc.flash_size;
	}

	if ((bfp = (uint8_t *)kmem_zalloc(bsize, KM_SLEEP)) == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		rval = ENOMEM;
	} else {
		/* Dump Flash fcode. */
		rval = ql_dump_fcode(ha, bfp, bsize, faddr);

		if (rval != QL_SUCCESS) {
			EL(ha, "failed, dump_fcode = %x\n", rval);
			rval = EFAULT;
		} else if (ddi_copyout(bfp, bp, bsize, mode) != 0) {
			EL(ha, "failed, ddi_copyout\n");
			rval = EFAULT;
		} else {
			rval = 0;
		}
		kmem_free(bfp, bsize);
	}

	QL_PRINT_9(ha, "done\n");

	return (rval);
}

/*
 * ql_dump_fcode
 *	Dumps fcode from flash.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	dp:		data pointer.
 *	size:		data length in bytes.
 *	startpos:	starting position in flash (byte address).
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 *
 */
int
ql_dump_fcode(ql_adapter_state_t *ha, uint8_t *dp, uint32_t size,
    uint32_t startpos)
{
	uint32_t	cnt, data, addr;
	uint8_t		bp[4], *src;
	int		fp_rval, rval = QL_SUCCESS;
	dma_mem_t	mem;

	QL_PRINT_9(ha, "started\n");

	/* make sure startpos+size doesn't exceed flash */
	if (size + startpos > ha->xioctl->fdesc.flash_size) {
		EL(ha, "exceeded flash range, sz=%xh, stp=%xh, flsz=%xh\n",
		    size, startpos, ha->xioctl->fdesc.flash_size);
		return (QL_FUNCTION_PARAMETER_ERROR);
	}

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		/* check start addr is 32 bit aligned for 24xx */
		if ((startpos & 0x3) != 0) {
			rval = ql_24xx_read_flash(ha,
			    ha->flash_data_addr | startpos >> 2, &data);
			if (rval != QL_SUCCESS) {
				EL(ha, "failed2, rval = %xh\n", rval);
				return (rval);
			}
			bp[0] = LSB(LSW(data));
			bp[1] = MSB(LSW(data));
			bp[2] = LSB(MSW(data));
			bp[3] = MSB(MSW(data));
			while (size && startpos & 0x3) {
				*dp++ = bp[startpos & 0x3];
				startpos++;
				size--;
			}
			if (size == 0) {
				QL_PRINT_9(ha, "done2\n",
				    ha->instance);
				return (rval);
			}
		}

		/* adjust 24xx start addr for 32 bit words */
		addr = startpos / 4 | ha->flash_data_addr;
	}

	bzero(&mem, sizeof (dma_mem_t));
	/* Check for Fast page is supported */
	if ((ha->pha->task_daemon_flags & FIRMWARE_UP) &&
	    (CFG_IST(ha, CFG_FLASH_DMA_SUPPORT))) {
		fp_rval = QL_SUCCESS;
		/* Setup DMA buffer. */
		rval = ql_get_dma_mem(ha, &mem, size,
		    LITTLE_ENDIAN_DMA, QL_DMA_DATA_ALIGN);
		if (rval != QL_SUCCESS) {
			EL(ha, "failed, ql_get_dma_mem=%xh\n",
			    rval);
			return (ENOMEM);
		}
	} else {
		fp_rval = QL_NOT_SUPPORTED;
	}

	GLOBAL_HW_LOCK();

	/* Enable Flash Read/Write. */
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_1)) {
		ql_flash_enable(ha);
	}

	/* Read fcode data from flash. */
	while (size) {
		/* Allow other system activity. */
		if (size % 0x1000 == 0) {
			ql_delay(ha, 10000);
		}
		if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
			if (fp_rval == QL_SUCCESS && (addr & 0x3f) == 0) {
				cnt = (size + 3) >> 2;
				fp_rval = ql_rd_risc_ram(ha, addr,
				    mem.cookie.dmac_laddress, cnt);
				if (fp_rval == QL_SUCCESS) {
					for (src = mem.bp; size; size--) {
						*dp++ = *src++;
					}
					addr += cnt;
					continue;
				}
			}
			rval = ql_24xx_read_flash(ha, addr++,
			    &data);
			if (rval != QL_SUCCESS) {
				break;
			}
			bp[0] = LSB(LSW(data));
			bp[1] = MSB(LSW(data));
			bp[2] = LSB(MSW(data));
			bp[3] = MSB(MSW(data));
			for (cnt = 0; size && cnt < 4; size--) {
				*dp++ = bp[cnt++];
			}
		} else {
			*dp++ = (uint8_t)ql_read_flash_byte(ha, startpos++);
			size--;
		}
	}

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_1)) {
		ql_flash_disable(ha);
	}

	GLOBAL_HW_UNLOCK();

	if (mem.dma_handle != NULL) {
		ql_free_dma_resource(ha, &mem);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_9(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_program_flash_address
 *	Program flash address.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	addr:	flash byte address.
 *	data:	data to be written to flash.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_program_flash_address(ql_adapter_state_t *ha, uint32_t addr,
    uint8_t data)
{
	int	rval;

	/* Write Program Command Sequence */
	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		ql_write_flash_byte(ha, 0x5555, 0xa0);
		ql_write_flash_byte(ha, addr, data);
	} else {
		ql_write_flash_byte(ha, 0x5555, 0xaa);
		ql_write_flash_byte(ha, 0x2aaa, 0x55);
		ql_write_flash_byte(ha, 0x5555, 0xa0);
		ql_write_flash_byte(ha, addr, data);
	}

	/* Wait for write to complete. */
	rval = ql_poll_flash(ha, addr, data);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval=%xh\n", rval);
	}
	return (rval);
}

/*
 * ql_set_rnid_parameters
 *	Set RNID parameters.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	User space CT arguments pointer.
 *	mode:	flags.
 */
static void
ql_set_rnid_parameters(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_SET_RNID_REQ	tmp_set;
	EXT_RNID_DATA		*tmp_buf;
	int			rval = 0;

	QL_PRINT_9(ha, "started\n");

	if (DRIVER_SUSPENDED(ha)) {
		EL(ha, "failed, LOOP_NOT_READY\n");
		cmd->Status = EXT_STATUS_BUSY;
		cmd->ResponseLen = 0;
		return;
	}

	cmd->ResponseLen = 0; /* NO response to caller. */
	if (cmd->RequestLen != sizeof (EXT_SET_RNID_REQ)) {
		/* parameter error */
		EL(ha, "failed, RequestLen < EXT_SET_RNID_REQ, Len=%xh\n",
		    cmd->RequestLen);
		cmd->Status = EXT_STATUS_INVALID_PARAM;
		cmd->DetailStatus = EXT_DSTATUS_REQUEST_LEN;
		cmd->ResponseLen = 0;
		return;
	}

	rval = ddi_copyin((void*)(uintptr_t)cmd->RequestAdr, &tmp_set,
	    cmd->RequestLen, mode);
	if (rval != 0) {
		EL(ha, "failed, ddi_copyin\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	/* Allocate memory for command. */
	tmp_buf = kmem_zalloc(sizeof (EXT_RNID_DATA), KM_SLEEP);
	if (tmp_buf == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}

	rval = ql_get_rnid_params(ha, sizeof (EXT_RNID_DATA),
	    (caddr_t)tmp_buf);
	if (rval != QL_SUCCESS) {
		/* error */
		EL(ha, "failed, get_rnid_params_mbx=%xh\n", rval);
		kmem_free(tmp_buf, sizeof (EXT_RNID_DATA));
		cmd->Status = EXT_STATUS_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	/* Now set the requested params. */
	bcopy(tmp_set.IPVersion, tmp_buf->IPVersion, 2);
	bcopy(tmp_set.UDPPortNumber, tmp_buf->UDPPortNumber, 2);
	bcopy(tmp_set.IPAddress, tmp_buf->IPAddress, 16);

	rval = ql_set_rnid_params(ha, sizeof (EXT_RNID_DATA),
	    (caddr_t)tmp_buf);
	if (rval != QL_SUCCESS) {
		/* error */
		EL(ha, "failed, set_rnid_params_mbx=%xh\n", rval);
		cmd->Status = EXT_STATUS_ERR;
		cmd->ResponseLen = 0;
	}

	kmem_free(tmp_buf, sizeof (EXT_RNID_DATA));

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_get_rnid_parameters
 *	Get RNID parameters.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	User space CT arguments pointer.
 *	mode:	flags.
 */
static void
ql_get_rnid_parameters(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_RNID_DATA	*tmp_buf;
	uint32_t	rval;

	QL_PRINT_9(ha, "started\n");

	if (DRIVER_SUSPENDED(ha)) {
		EL(ha, "failed, LOOP_NOT_READY\n");
		cmd->Status = EXT_STATUS_BUSY;
		cmd->ResponseLen = 0;
		return;
	}

	/* Allocate memory for command. */
	tmp_buf = kmem_zalloc(sizeof (EXT_RNID_DATA), KM_SLEEP);
	if (tmp_buf == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}

	/* Send command */
	rval = ql_get_rnid_params(ha, sizeof (EXT_RNID_DATA),
	    (caddr_t)tmp_buf);
	if (rval != QL_SUCCESS) {
		/* error */
		EL(ha, "failed, get_rnid_params_mbx=%xh\n", rval);
		kmem_free(tmp_buf, sizeof (EXT_RNID_DATA));
		cmd->Status = EXT_STATUS_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	/* Copy the response */
	if (ql_send_buffer_data((caddr_t)tmp_buf,
	    (caddr_t)(uintptr_t)cmd->ResponseAdr,
	    sizeof (EXT_RNID_DATA), mode) != sizeof (EXT_RNID_DATA)) {
		EL(ha, "failed, ddi_copyout\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
	} else {
		QL_PRINT_9(ha, "done\n");
		cmd->ResponseLen = sizeof (EXT_RNID_DATA);
	}

	kmem_free(tmp_buf, sizeof (EXT_RNID_DATA));
}

/*
 * ql_reset_statistics
 *	Performs EXT_SC_RST_STATISTICS subcommand. of EXT_CC_SET_DATA.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_reset_statistics(ql_adapter_state_t *ha, EXT_IOCTL *cmd)
{
	ql_xioctl_t		*xp = ha->xioctl;
	int			rval = 0;

	QL_PRINT_9(ha, "started\n");

	if (DRIVER_SUSPENDED(ha)) {
		EL(ha, "failed, LOOP_NOT_READY\n");
		cmd->Status = EXT_STATUS_BUSY;
		cmd->ResponseLen = 0;
		return (QL_FUNCTION_SUSPENDED);
	}

	rval = ql_reset_link_status(ha);
	if (rval != QL_SUCCESS) {
		EL(ha, "failed, reset_link_status_mbx=%xh\n", rval);
		cmd->Status = EXT_STATUS_MAILBOX;
		cmd->DetailStatus = rval;
		cmd->ResponseLen = 0;
	}

	TASK_DAEMON_LOCK(ha);
	xp->IosRequested = 0;
	xp->BytesRequested = 0;
	xp->IOInputRequests = 0;
	xp->IOOutputRequests = 0;
	xp->IOControlRequests = 0;
	xp->IOInputMByteCnt = 0;
	xp->IOOutputMByteCnt = 0;
	xp->IOOutputByteCnt = 0;
	xp->IOInputByteCnt = 0;
	TASK_DAEMON_UNLOCK(ha);

	INTR_LOCK(ha);
	xp->ControllerErrorCount = 0;
	xp->DeviceErrorCount = 0;
	xp->TotalLipResets = 0;
	xp->TotalInterrupts = 0;
	INTR_UNLOCK(ha);

	QL_PRINT_9(ha, "done\n");

	return (rval);
}

/*
 * ql_get_statistics
 *	Performs EXT_SC_GET_STATISTICS subcommand. of EXT_CC_GET_DATA.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_get_statistics(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_HBA_PORT_STAT	ps = {0};
	ql_link_stats_t		*ls;
	int			rval;
	ql_xioctl_t		*xp = ha->xioctl;
	int			retry = 10;

	QL_PRINT_9(ha, "started\n");

	while (ha->task_daemon_flags &
	    (ABORT_ISP_ACTIVE | LOOP_RESYNC_ACTIVE | DRIVER_STALL)) {
		ql_delay(ha, 10000000);	/* 10 second delay */

		retry--;

		if (retry == 0) { /* effectively 100 seconds */
			EL(ha, "failed, LOOP_NOT_READY\n");
			cmd->Status = EXT_STATUS_BUSY;
			cmd->ResponseLen = 0;
			return;
		}
	}

	/* Allocate memory for command. */
	ls = kmem_zalloc(sizeof (ql_link_stats_t), KM_SLEEP);
	if (ls == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}

	/*
	 * I think these are supposed to be port statistics
	 * the loop ID or port ID should be in cmd->Instance.
	 */
	rval = ql_get_status_counts(ha, (uint16_t)
	    (ha->task_daemon_flags & LOOP_DOWN ? 0xFF : ha->loop_id),
	    sizeof (ql_link_stats_t), (caddr_t)ls, 0);
	if (rval != QL_SUCCESS) {
		EL(ha, "failed, get_link_status=%xh, id=%xh\n", rval,
		    ha->loop_id);
		cmd->Status = EXT_STATUS_MAILBOX;
		cmd->DetailStatus = rval;
		cmd->ResponseLen = 0;
	} else {
		ps.ControllerErrorCount = xp->ControllerErrorCount;
		ps.DeviceErrorCount = xp->DeviceErrorCount;
		ps.IoCount = (uint32_t)(xp->IOInputRequests +
		    xp->IOOutputRequests + xp->IOControlRequests);
		ps.MBytesCount = (uint32_t)(xp->IOInputMByteCnt +
		    xp->IOOutputMByteCnt);
		ps.LipResetCount = xp->TotalLipResets;
		ps.InterruptCount = xp->TotalInterrupts;
		ps.LinkFailureCount = LE_32(ls->link_fail_cnt);
		ps.LossOfSyncCount = LE_32(ls->sync_loss_cnt);
		ps.LossOfSignalsCount = LE_32(ls->signal_loss_cnt);
		ps.PrimitiveSeqProtocolErrorCount = LE_32(ls->prot_err_cnt);
		ps.InvalidTransmissionWordCount = LE_32(ls->inv_xmit_cnt);
		ps.InvalidCRCCount = LE_32(ls->inv_crc_cnt);

		rval = ddi_copyout((void *)&ps,
		    (void *)(uintptr_t)cmd->ResponseAdr,
		    sizeof (EXT_HBA_PORT_STAT), mode);
		if (rval != 0) {
			EL(ha, "failed, ddi_copyout\n");
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->ResponseLen = 0;
		} else {
			cmd->ResponseLen = sizeof (EXT_HBA_PORT_STAT);
		}
	}

	kmem_free(ls, sizeof (ql_link_stats_t));

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_get_statistics_fc
 *	Performs EXT_SC_GET_FC_STATISTICS subcommand. of EXT_CC_GET_DATA.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_get_statistics_fc(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_HBA_PORT_STAT	ps = {0};
	ql_link_stats_t		*ls;
	int			rval;
	uint16_t		qlnt;
	EXT_DEST_ADDR		pextdestaddr;
	uint8_t			*name;
	ql_tgt_t		*tq = NULL;
	int			retry = 10;

	QL_PRINT_9(ha, "started\n");

	if (ddi_copyin((void *)(uintptr_t)cmd->RequestAdr,
	    (void *)&pextdestaddr, sizeof (EXT_DEST_ADDR), mode) != 0) {
		EL(ha, "failed, ddi_copyin\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	qlnt = QLNT_PORT;
	name = pextdestaddr.DestAddr.WWPN;

	QL_PRINT_9(ha, "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x\n",
	    ha->instance, name[0], name[1], name[2], name[3], name[4],
	    name[5], name[6], name[7]);

	tq = ql_find_port(ha, name, qlnt);

	if (tq == NULL || !VALID_TARGET_ID(ha, tq->loop_id)) {
		EL(ha, "failed, fc_port not found\n");
		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		cmd->ResponseLen = 0;
		return;
	}

	while (ha->task_daemon_flags &
	    (ABORT_ISP_ACTIVE | LOOP_RESYNC_ACTIVE | DRIVER_STALL)) {
		ql_delay(ha, 10000000);	/* 10 second delay */

		retry--;

		if (retry == 0) { /* effectively 100 seconds */
			EL(ha, "failed, LOOP_NOT_READY\n");
			cmd->Status = EXT_STATUS_BUSY;
			cmd->ResponseLen = 0;
			return;
		}
	}

	/* Allocate memory for command. */
	ls = kmem_zalloc(sizeof (ql_link_stats_t), KM_SLEEP);
	if (ls == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}

	rval = ql_get_link_status(ha, tq->loop_id, sizeof (ql_link_stats_t),
	    (caddr_t)ls, 0);
	if (rval != QL_SUCCESS) {
		EL(ha, "failed, get_link_status=%xh, d_id=%xh\n", rval,
		    tq->d_id.b24);
		cmd->Status = EXT_STATUS_MAILBOX;
		cmd->DetailStatus = rval;
		cmd->ResponseLen = 0;
	} else {
		ps.LinkFailureCount = LE_32(ls->link_fail_cnt);
		ps.LossOfSyncCount = LE_32(ls->sync_loss_cnt);
		ps.LossOfSignalsCount = LE_32(ls->signal_loss_cnt);
		ps.PrimitiveSeqProtocolErrorCount = LE_32(ls->prot_err_cnt);
		ps.InvalidTransmissionWordCount = LE_32(ls->inv_xmit_cnt);
		ps.InvalidCRCCount = LE_32(ls->inv_crc_cnt);

		rval = ddi_copyout((void *)&ps,
		    (void *)(uintptr_t)cmd->ResponseAdr,
		    sizeof (EXT_HBA_PORT_STAT), mode);

		if (rval != 0) {
			EL(ha, "failed, ddi_copyout\n");
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->ResponseLen = 0;
		} else {
			cmd->ResponseLen = sizeof (EXT_HBA_PORT_STAT);
		}
	}

	kmem_free(ls, sizeof (ql_link_stats_t));

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_get_statistics_fc4
 *	Performs EXT_SC_GET_FC_STATISTICS subcommand. of EXT_CC_GET_DATA.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_get_statistics_fc4(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	uint32_t		rval;
	EXT_HBA_FC4STATISTICS	fc4stats = {0};
	ql_xioctl_t		*xp = ha->xioctl;

	QL_PRINT_9(ha, "started\n");

	fc4stats.InputRequests = xp->IOInputRequests;
	fc4stats.OutputRequests = xp->IOOutputRequests;
	fc4stats.ControlRequests = xp->IOControlRequests;
	fc4stats.InputMegabytes = xp->IOInputMByteCnt;
	fc4stats.OutputMegabytes = xp->IOOutputMByteCnt;

	rval = ddi_copyout((void *)&fc4stats,
	    (void *)(uintptr_t)cmd->ResponseAdr,
	    sizeof (EXT_HBA_FC4STATISTICS), mode);

	if (rval != 0) {
		EL(ha, "failed, ddi_copyout\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
	} else {
		cmd->ResponseLen = sizeof (EXT_HBA_FC4STATISTICS);
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_set_led_state
 *	Performs EXT_SET_BEACON_STATE subcommand of EXT_CC_SET_DATA.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_set_led_state(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_BEACON_CONTROL	bstate;
	int			rval;
	ql_mbx_data_t		mr;

	QL_PRINT_9(ha, "started\n");

	if (cmd->RequestLen < sizeof (EXT_BEACON_CONTROL)) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = sizeof (EXT_BEACON_CONTROL);
		EL(ha, "done - failed, RequestLen < EXT_BEACON_CONTROL,"
		    " Len=%xh\n", cmd->RequestLen);
		cmd->ResponseLen = 0;
		return;
	}

	if (!CFG_IST(ha, CFG_SET_LEDS_SUPPORT)) {
		cmd->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		cmd->DetailStatus = 0;
		EL(ha, "done - failed, Invalid function for HBA model\n");
		cmd->ResponseLen = 0;
		return;
	}

	rval = ddi_copyin((void*)(uintptr_t)cmd->RequestAdr, &bstate,
	    cmd->RequestLen, mode);

	if (rval != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		EL(ha, "done -  failed, ddi_copyin\n");
		return;
	}

	switch (bstate.State) {
	case EXT_DEF_GRN_BLINK_OFF:	/* turn beacon off */
		if (ha->ledstate.BeaconState == BEACON_OFF) {
			/* not quite an error -- LED state is already off */
			cmd->Status = EXT_STATUS_OK;
			EL(ha, "LED off request -- LED is already off\n");
			break;
		}

		if (CFG_IST(ha, CFG_CTRL_82XX)) {
			rval = ql_diag_beacon(ha, QL_BEACON_DISABLE,
			    &mr);

			if (rval == QL_SUCCESS) {
				ha->ledstate.BeaconState = BEACON_OFF;
				ha->ledstate.LEDflags = LED_ALL_OFF;
				cmd->Status = EXT_STATUS_OK;
			} else {
				cmd->Status = EXT_STATUS_ERR;
				EL(ha, "failed, disable beacon request %xh\n",
				    bstate.State);
			}
			break;
		}

		ha->ledstate.BeaconState = BEACON_OFF;
		ha->ledstate.LEDflags = LED_ALL_OFF;

		if ((rval = ql_wrapup_led(ha)) != QL_SUCCESS) {
			cmd->Status = EXT_STATUS_MAILBOX;
		} else {
			cmd->Status = EXT_STATUS_OK;
		}
		break;

	case EXT_DEF_GRN_BLINK_ON:	/* turn beacon on */
		if (ha->ledstate.BeaconState == BEACON_ON) {
			/* not quite an error -- LED state is already on */
			cmd->Status = EXT_STATUS_OK;
			EL(ha, "LED on request  - LED is already on\n");
			break;
		}

		if (CFG_IST(ha, CFG_CTRL_82XX)) {
			rval = ql_diag_beacon(ha, QL_BEACON_ENABLE,
			    &mr);

			if (rval == QL_SUCCESS) {
				ha->ledstate.BeaconState = BEACON_ON;
				ha->ledstate.LEDflags = LED_GREEN;
				cmd->Status = EXT_STATUS_OK;
			} else {
				cmd->Status = EXT_STATUS_ERR;
				EL(ha, "failed, enable beacon request %xh\n",
				    bstate.State);
			}
			break;
		}

		if ((rval = ql_setup_led(ha)) != QL_SUCCESS) {
			cmd->Status = EXT_STATUS_MAILBOX;
			break;
		}

		if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
			ha->ledstate.LEDflags = LED_YELLOW_24 | LED_AMBER_24;
		} else {
			ha->ledstate.LEDflags = LED_GREEN;
		}
		ha->ledstate.BeaconState = BEACON_ON;

		cmd->Status = EXT_STATUS_OK;
		break;
	default:
		cmd->Status = EXT_STATUS_ERR;
		EL(ha, "failed, unknown state request %xh\n", bstate.State);
		break;
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_get_led_state
 *	Performs EXT_GET_BEACON_STATE subcommand of EXT_CC_GET_DATA.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_get_led_state(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_BEACON_CONTROL	bstate = {0};
	uint32_t		rval;

	QL_PRINT_9(ha, "started\n");

	if (cmd->ResponseLen < sizeof (EXT_BEACON_CONTROL)) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = sizeof (EXT_BEACON_CONTROL);
		EL(ha, "done - failed, ResponseLen < EXT_BEACON_CONTROL,"
		    "Len=%xh\n", cmd->ResponseLen);
		cmd->ResponseLen = 0;
		return;
	}

	if (!CFG_IST(ha, CFG_SET_LEDS_SUPPORT)) {
		cmd->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		cmd->DetailStatus = 0;
		EL(ha, "done - failed, Invalid function for HBA model\n");
		cmd->ResponseLen = 0;
		return;
	}

	if (ha->task_daemon_flags & ABORT_ISP_ACTIVE) {
		cmd->Status = EXT_STATUS_BUSY;
		EL(ha, "done -  failed, isp abort active\n");
		cmd->ResponseLen = 0;
		return;
	}

	/* inform the user of the current beacon state (off or on) */
	bstate.State = ha->ledstate.BeaconState;

	rval = ddi_copyout((void *)&bstate,
	    (void *)(uintptr_t)cmd->ResponseAdr,
	    sizeof (EXT_BEACON_CONTROL), mode);

	if (rval != 0) {
		EL(ha, "failed, ddi_copyout\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
	} else {
		cmd->Status = EXT_STATUS_OK;
		cmd->ResponseLen = sizeof (EXT_BEACON_CONTROL);
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_blink_led
 *	Determine the next state of the LED and drive it
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Context:
 *	Interrupt context.
 */
void
ql_blink_led(ql_adapter_state_t *ha)
{
	uint32_t	nextstate;
	ql_mbx_data_t	mr;

	QL_PRINT_9(ha, "started\n");

	if (ha->ledstate.BeaconState == BEACON_ON) {
		if (CFG_IST(ha, CFG_CTRL_2363 | CFG_CTRL_2425)) {
			/* determine the next led state */
			if (CFG_IST(ha, CFG_CTRL_2425)) {
				nextstate = (ha->ledstate.LEDflags) &
				    (~(RD32_IO_REG(ha, gpiod)));
			} else {
				nextstate = (ha->ledstate.LEDflags) &
				    (~(RD16_IO_REG(ha, gpiod)));
			}

			/* turn the led on or off */
			ql_drive_led(ha, nextstate);
		} else if (CFG_IST(ha, CFG_CTRL_81XX)) {
			if (ha->ledstate.flags & LED_ACTIVE) {
				mr.mb[1] = 0x2000;
				mr.mb[2] = 0x4000;
				ha->ledstate.flags &= ~LED_ACTIVE;
			} else {
				mr.mb[1] = 0x4000;
				mr.mb[2] = 0x2000;
				ha->ledstate.flags |= LED_ACTIVE;
			}
			(void) ql_set_led_config(ha, &mr);
		} else if (CFG_IST(ha, CFG_CTRL_80XX)) {
			if (ha->ledstate.flags & LED_ACTIVE) {
				mr.mb[1] = 0x4000;
				mr.mb[2] = 0x2000;
				mr.mb[3] = 0x4000;
				mr.mb[4] = 0x4000;
				mr.mb[5] = 0;
				mr.mb[6] = 0x2000;
				(void) ql_set_led_config(ha, &mr);
				ha->ledstate.flags &= ~LED_ACTIVE;
			} else {
				mr.mb[1] = 0x4000;
				mr.mb[2] = 0x4000;
				mr.mb[3] = 0x4000;
				mr.mb[4] = 0x2000;
				mr.mb[5] = 0;
				mr.mb[6] = 0x2000;
				(void) ql_set_led_config(ha, &mr);
				ha->ledstate.flags |= LED_ACTIVE;
			}
		} else if (CFG_IST(ha, CFG_CTRL_83XX)) {
			if (ha->ledstate.flags & LED_ACTIVE) {
				(void) ql_write_remote_reg(ha,
				    ha->ledstate.select,
				    0x40004000);
				(void) ql_write_remote_reg(ha,
				    ha->ledstate.select + 4,
				    0x40004000);
				ha->ledstate.flags &= ~LED_ACTIVE;
			} else {
				(void) ql_write_remote_reg(ha,
				    ha->ledstate.select,
				    0x40002000);
				(void) ql_write_remote_reg(ha,
				    ha->ledstate.select + 4,
				    0x40002000);
				ha->ledstate.flags |= LED_ACTIVE;
			}
		} else if (!CFG_IST(ha, CFG_CTRL_27XX)) {
			EL(ha, "unsupported HBA: %xh\n", ha->device_id);
		}
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_drive_led
 *	drive the led's as determined by LEDflags
 *
 * Input:
 *	ha:		adapter state pointer.
 *	LEDflags:	LED flags
 *
 * Context:
 *	Kernel/Interrupt context.
 */
static void
ql_drive_led(ql_adapter_state_t *ha, uint32_t LEDflags)
{
	QL_PRINT_9(ha, "started\n");

	if (CFG_IST(ha, CFG_CTRL_2363)) {

		uint16_t	gpio_enable, gpio_data;

		/* setup to send new data */
		gpio_enable = (uint16_t)RD16_IO_REG(ha, gpioe);
		gpio_enable = (uint16_t)(gpio_enable | LED_MASK);
		WRT16_IO_REG(ha, gpioe, gpio_enable);

		/* read current data and clear out old led data */
		gpio_data = (uint16_t)RD16_IO_REG(ha, gpiod);
		gpio_data = (uint16_t)(gpio_data & ~LED_MASK);

		/* set in the new led data. */
		gpio_data = (uint16_t)(gpio_data | LEDflags);

		/* write out the new led data */
		WRT16_IO_REG(ha, gpiod, gpio_data);

	} else if (CFG_IST(ha, CFG_CTRL_2425)) {
		uint32_t	gpio_data;

		/* setup to send new data */
		gpio_data = RD32_IO_REG(ha, gpiod);
		gpio_data |= LED_MASK_UPDATE_24;
		WRT32_IO_REG(ha, gpiod, gpio_data);

		/* read current data and clear out old led data */
		gpio_data = RD32_IO_REG(ha, gpiod);
		gpio_data &= ~LED_MASK_COLORS_24;

		/* set in the new led data */
		gpio_data |= LEDflags;

		/* write out the new led data */
		WRT32_IO_REG(ha, gpiod, gpio_data);

	} else {
		EL(ha, "unsupported HBA: %xh\n", ha->device_id);
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_setup_led
 *	Setup LED for driver control
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Context:
 *	Kernel/Interrupt context.
 */
static int
ql_setup_led(ql_adapter_state_t *ha)
{
	int		rval = QL_SUCCESS;
	ql_mbx_data_t	mr;

	QL_PRINT_9(ha, "started\n");

	if (CFG_IST(ha, CFG_CTRL_2363 | CFG_CTRL_2425)) {
		/* decouple the LED control from the fw */
		rval = ql_get_firmware_option(ha, &mr);
		if (rval != QL_SUCCESS) {
			EL(ha, "failed, get_firmware_option=%xh\n", rval);
			return (rval);
		}

		/* set the appropriate options */
		mr.mb[1] = (uint16_t)(mr.mb[1] | FO1_DISABLE_GPIO);

		/* send it back to the firmware */
		rval = ql_set_firmware_option(ha, &mr);
		if (rval != QL_SUCCESS) {
			EL(ha, "failed, set_firmware_option=%xh\n", rval);
			return (rval);
		}

		/* initally, turn the LED's off */
		ql_drive_led(ha, LED_ALL_OFF);

	} else if (CFG_IST(ha, CFG_CTRL_81XX)) {
		(void) ql_get_led_config(ha, &ha->ledstate.cfg);
		mr.mb[1] = 0x2000;
		mr.mb[2] = 0x2000;
		rval = ql_set_led_config(ha, &mr);

	} else if (CFG_IST(ha, CFG_CTRL_80XX)) {
		/* Save initial value */
		rval = ql_get_led_config(ha, &ha->ledstate.cfg);
		if (rval != QL_SUCCESS) {
			EL(ha, "failed, get_led_config=%xh\n", rval);
			return (rval);
		}
		mr.mb[1] = 0x4000;
		mr.mb[2] = 0x4000;
		mr.mb[3] = 0x4000;
		mr.mb[4] = 0x2000;
		mr.mb[5] = 0;
		mr.mb[6] = 0x2000;
		rval = ql_set_led_config(ha, &mr);

	} else if (CFG_IST(ha, CFG_CTRL_83XX)) {
		rval = ql_get_firmware_option(ha, &mr);
		if (rval != QL_SUCCESS) {
			EL(ha, "failed, get_firmware_option=%xh\n", rval);
			return (rval);
		}

		mr.mb[1] = (uint16_t)(mr.mb[1] | FO1_DISABLE_LEDS);

		rval = ql_set_firmware_option(ha, &mr);
		if (rval != QL_SUCCESS) {
			EL(ha, "failed, set_firmware_option=%xh\n", rval);
			return (rval);
		}

		(void) ql_write_remote_reg(ha, ha->ledstate.select,
		    0x40002000);
		(void) ql_write_remote_reg(ha, ha->ledstate.select + 4,
		    0x40002000);

	} else if (CFG_IST(ha, CFG_CTRL_27XX)) {
		/* take control of LED */
		rval = ql_get_firmware_option(ha, &mr);
		if (rval != QL_SUCCESS) {
			EL(ha, "failed, get_firmware_option=%xh\n", rval);
			return (rval);
		}

		mr.mb[1] = (uint16_t)(mr.mb[1] | FO1_DISABLE_LEDS);

		rval = ql_set_firmware_option(ha, &mr);
		if (rval != QL_SUCCESS) {
			EL(ha, "failed, set_firmware_option=%xh\n", rval);
			return (rval);
		}

		mr.mb[1] = 0xf;
		mr.mb[2] = 0x230;
		mr.mb[3] = 0x230;
		mr.mb[4] = 0x4000;
		rval = ql_led_config(ha, &mr);
		if (rval != QL_SUCCESS) {
			EL(ha, "failed, led_config=%xh\n", rval);
			return (rval);
		}
	} else {
		EL(ha, "unsupported HBA: %xh\n", ha->device_id);
	}
	ha->ledstate.flags |= LED_ACTIVE;

	QL_PRINT_9(ha, "done\n");

	return (rval);
}

/*
 * ql_wrapup_led
 *	Return LED control to the firmware
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Context:
 *	Kernel/Interrupt context.
 */
static int
ql_wrapup_led(ql_adapter_state_t *ha)
{
	int		rval = QL_SUCCESS;
	ql_mbx_data_t	mr;

	QL_PRINT_9(ha, "started\n");


	if (CFG_IST(ha, CFG_CTRL_2363 | CFG_CTRL_2425)) {
		uint32_t	gpio_data;

		/* Turn all LED's off */
		ql_drive_led(ha, LED_ALL_OFF);

		if (CFG_IST(ha, CFG_CTRL_2425)) {
			/* disable the LED update mask */
			gpio_data = RD32_IO_REG(ha, gpiod);
			gpio_data &= ~LED_MASK_UPDATE_24;

			/* write out the data */
			WRT32_IO_REG(ha, gpiod, gpio_data);
			/* give LED control back to the f/w */
		}
		rval = ql_get_firmware_option(ha, &mr);
		if (rval != QL_SUCCESS) {
			EL(ha, "failed, get_firmware_option=%xh\n", rval);
			return (rval);
		}

		mr.mb[1] = (uint16_t)(mr.mb[1] & ~FO1_DISABLE_GPIO);

		rval = ql_set_firmware_option(ha, &mr);
		if (rval != QL_SUCCESS) {
			EL(ha, "failed, set_firmware_option=%xh\n", rval);
			return (rval);
		}
	} else if (CFG_IST(ha, CFG_CTRL_8081)) {
		rval = ql_set_led_config(ha, &ha->ledstate.cfg);

	} else if (CFG_IST(ha, CFG_CTRL_2783)) {
		/* give LED control back to the f/w */
		rval = ql_get_firmware_option(ha, &mr);
		if (rval != QL_SUCCESS) {
			EL(ha, "failed, get_firmware_option=%xh\n", rval);
			return (rval);
		}

		mr.mb[1] = (uint16_t)(mr.mb[1] & ~FO1_DISABLE_LEDS);

		rval = ql_set_firmware_option(ha, &mr);
		if (rval != QL_SUCCESS) {
			EL(ha, "failed, set_firmware_option=%xh\n", rval);
			return (rval);
		}

	} else {
		EL(ha, "unsupported HBA: %xh\n", ha->device_id);
	}

	QL_PRINT_9(ha, "done\n");

	return (rval);
}

/*
 * ql_get_port_summary
 *	Performs EXT_SC_GET_PORT_SUMMARY subcommand. of EXT_CC_GET_DATA.
 *
 *	The EXT_IOCTL->RequestAdr points to a single
 *	UINT32 which identifies the device type.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_get_port_summary(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_DEVICEDATA		dd = {0};
	EXT_DEVICEDATA		*uddp;
	ql_link_t		*link;
	ql_tgt_t		*tq;
	uint32_t		rlen, dev_type, index;
	int			rval = 0;
	EXT_DEVICEDATAENTRY	*uddep, *ddep;

	QL_PRINT_9(ha, "started\n");

	ddep = &dd.EntryList[0];

	/*
	 * Get the type of device the requestor is looking for.
	 *
	 * We ignore this for now.
	 */
	rval = ddi_copyin((void *)(uintptr_t)cmd->RequestAdr,
	    (void *)&dev_type, sizeof (dev_type), mode);
	if (rval != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, ddi_copyin\n");
		return;
	}
	/*
	 * Count the number of entries to be returned. Count devices
	 * that are offlline, but have been persistently bound.
	 */
	for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
		for (link = ha->dev[index].first; link != NULL;
		    link = link->next) {
			tq = link->base_address;
			if (tq->flags & TQF_INITIATOR_DEVICE ||
			    !VALID_TARGET_ID(ha, tq->loop_id)) {
				continue;	/* Skip this one */
			}
			dd.TotalDevices++;
		}
	}
	/*
	 * Compute the number of entries that can be returned
	 * based upon the size of caller's response buffer.
	 */
	dd.ReturnListEntryCount = 0;
	if (dd.TotalDevices == 0) {
		rlen = sizeof (EXT_DEVICEDATA) - sizeof (EXT_DEVICEDATAENTRY);
	} else {
		rlen = (uint32_t)(sizeof (EXT_DEVICEDATA) +
		    (sizeof (EXT_DEVICEDATAENTRY) * (dd.TotalDevices - 1)));
	}
	if (rlen > cmd->ResponseLen) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = rlen;
		EL(ha, "failed, rlen > ResponseLen, rlen=%d, Len=%d\n",
		    rlen, cmd->ResponseLen);
		cmd->ResponseLen = 0;
		return;
	}
	cmd->ResponseLen = 0;
	uddp = (EXT_DEVICEDATA *)(uintptr_t)cmd->ResponseAdr;
	uddep = &uddp->EntryList[0];
	for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
		for (link = ha->dev[index].first; link != NULL;
		    link = link->next) {
			tq = link->base_address;
			if (tq->flags & TQF_INITIATOR_DEVICE ||
			    !VALID_TARGET_ID(ha, tq->loop_id) ||
			    tq->d_id.b24 == FS_MANAGEMENT_SERVER) {
				continue;	/* Skip this one */
			}

			bzero((void *)ddep, sizeof (EXT_DEVICEDATAENTRY));

			bcopy(tq->node_name, ddep->NodeWWN, 8);
			bcopy(tq->port_name, ddep->PortWWN, 8);

			ddep->PortID[0] = tq->d_id.b.domain;
			ddep->PortID[1] = tq->d_id.b.area;
			ddep->PortID[2] = tq->d_id.b.al_pa;

			bcopy(tq->port_name,
			    (caddr_t)&ddep->TargetAddress.Target, 8);

			ddep->DeviceFlags = tq->flags;
			ddep->LoopID = tq->loop_id;
			QL_PRINT_9(ha, "Tgt=%lld, loop=%xh, "
			    "wwnn=%02x%02x%02x%02x%02x%02x%02x%02x, "
			    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x\n",
			    ha->instance, ddep->TargetAddress.Target,
			    ddep->LoopID, ddep->NodeWWN[0], ddep->NodeWWN[1],
			    ddep->NodeWWN[2], ddep->NodeWWN[3],
			    ddep->NodeWWN[4], ddep->NodeWWN[5],
			    ddep->NodeWWN[6], ddep->NodeWWN[7],
			    ddep->PortWWN[0], ddep->PortWWN[1],
			    ddep->PortWWN[2], ddep->PortWWN[3],
			    ddep->PortWWN[4], ddep->PortWWN[5],
			    ddep->PortWWN[6], ddep->PortWWN[7]);
			rval = ddi_copyout((void *)ddep, (void *)uddep,
			    sizeof (EXT_DEVICEDATAENTRY), mode);

			if (rval != 0) {
				cmd->Status = EXT_STATUS_COPY_ERR;
				cmd->ResponseLen = 0;
				EL(ha, "failed, ddi_copyout\n");
				break;
			}
			dd.ReturnListEntryCount++;
			uddep++;
			cmd->ResponseLen += (uint32_t)
			    sizeof (EXT_DEVICEDATAENTRY);
		}
	}
	rval = ddi_copyout((void *)&dd, (void *)uddp,
	    sizeof (EXT_DEVICEDATA) - sizeof (EXT_DEVICEDATAENTRY), mode);

	if (rval != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, ddi_copyout-2\n");
	} else {
		cmd->ResponseLen += (uint32_t)sizeof (EXT_DEVICEDATAENTRY);
		QL_PRINT_9(ha, "done\n");
	}
}

/*
 * ql_get_target_id
 *	Performs EXT_SC_GET_TARGET_ID subcommand. of EXT_CC_GET_DATA.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_get_target_id(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	uint32_t		rval;
	uint16_t		qlnt;
	EXT_DEST_ADDR		extdestaddr = {0};
	uint8_t			*name;
	uint8_t			wwpn[EXT_DEF_WWN_NAME_SIZE];
	ql_tgt_t		*tq;

	QL_PRINT_9(ha, "started\n");

	if (ddi_copyin((void *)(uintptr_t)cmd->RequestAdr,
	    (void*)wwpn, sizeof (EXT_DEST_ADDR), mode) != 0) {
		EL(ha, "failed, ddi_copyin\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	qlnt = QLNT_PORT;
	name = wwpn;
	QL_PRINT_9(ha, "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x\n",
	    ha->instance, name[0], name[1], name[2], name[3], name[4],
	    name[5], name[6], name[7]);

	tq = ql_find_port(ha, name, qlnt);
	if (tq == NULL || !VALID_TARGET_ID(ha, tq->loop_id)) {
		EL(ha, "failed, fc_port not found\n");
		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		cmd->ResponseLen = 0;
		return;
	}

	bcopy(tq->port_name, (caddr_t)&extdestaddr.DestAddr.ScsiAddr.Target, 8);

	rval = ddi_copyout((void *)&extdestaddr,
	    (void *)(uintptr_t)cmd->ResponseAdr, sizeof (EXT_DEST_ADDR), mode);
	if (rval != 0) {
		EL(ha, "failed, ddi_copyout\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_setup_fcache
 *	Populates selected flash sections into the cache
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 *
 * Note:
 *	Driver must be in stalled state prior to entering or
 *	add code to this function prior to calling ql_setup_flash()
 */
int
ql_setup_fcache(ql_adapter_state_t *ha)
{
	int		rval;
	uint32_t	freadpos = 0;
	uint32_t	fw_done = 0;
	ql_fcache_t	*head = NULL;
	ql_fcache_t	*tail = NULL;
	ql_fcache_t	*ftmp;

	QL_PRINT_10(ha, "started cfg=0x%llx\n", ha->cfg_flags);

	/* If we already have populated it, rtn */
	if (ha->fcache != NULL) {
		EL(ha, "buffer already populated\n");
		return (QL_SUCCESS);
	}

	ql_flash_nvram_defaults(ha);

	if ((rval = ql_setup_flash(ha)) != QL_SUCCESS) {
		EL(ha, "unable to setup flash; rval=%xh\n", rval);
		return (rval);
	}

	while (freadpos != 0xffffffff) {
		/* Allocate & populate this node */
		if ((ftmp = ql_setup_fnode(ha)) == NULL) {
			EL(ha, "node alloc failed\n");
			rval = QL_FUNCTION_FAILED;
			break;
		}

		/* link in the new node */
		if (head == NULL) {
			head = tail = ftmp;
		} else {
			tail->next = ftmp;
			tail = ftmp;
		}

		/* Do the firmware node first for 24xx/25xx's */
		if (fw_done == 0) {
			if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
				freadpos = ha->flash_fw_addr << 2;
			}
			fw_done = 1;
		}

		if ((rval = ql_dump_fcode(ha, ftmp->buf, FBUFSIZE,
		    freadpos)) != QL_SUCCESS) {
			EL(ha, "failed, 24xx dump_fcode"
			    " pos=%xh rval=%xh\n", freadpos, rval);
			rval = QL_FUNCTION_FAILED;
			break;
		}

		/* checkout the pci data / format */
		if (ql_check_pci(ha, ftmp, &freadpos)) {
			EL(ha, "flash header incorrect\n");
			rval = QL_FUNCTION_FAILED;
			break;
		}
	}

	if (rval != QL_SUCCESS) {
		/* release all resources we have */
		ftmp = head;
		while (ftmp != NULL) {
			tail = ftmp->next;
			kmem_free(ftmp->buf, FBUFSIZE);
			kmem_free(ftmp, sizeof (ql_fcache_t));
			ftmp = tail;
		}

		EL(ha, "failed, done\n");
	} else {
		ha->fcache = head;
		QL_PRINT_10(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_update_fcache
 *	re-populates updated flash into the fcache. If
 *	fcache does not exist (e.g., flash was empty/invalid on
 *	boot), this routine will create and the populate it.
 *
 * Input:
 *	ha	= adapter state pointer.
 *	*bpf	= Pointer to flash buffer.
 *	bsize	= Size of flash buffer.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
void
ql_update_fcache(ql_adapter_state_t *ha, uint8_t *bfp, uint32_t bsize)
{
	int		rval = QL_SUCCESS;
	uint32_t	freadpos = 0;
	uint32_t	fw_done = 0;
	ql_fcache_t	*head = NULL;
	ql_fcache_t	*tail = NULL;
	ql_fcache_t	*ftmp;

	QL_PRINT_3(ha, "started\n");

	while (freadpos != 0xffffffff) {

		/* Allocate & populate this node */

		if ((ftmp = ql_setup_fnode(ha)) == NULL) {
			EL(ha, "node alloc failed\n");
			rval = QL_FUNCTION_FAILED;
			break;
		}

		/* link in the new node */
		if (head == NULL) {
			head = tail = ftmp;
		} else {
			tail->next = ftmp;
			tail = ftmp;
		}

		/* Do the firmware node first for 24xx's */
		if (fw_done == 0) {
			if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
				freadpos = ha->flash_fw_addr << 2;
			}
			fw_done = 1;
		}

		/* read in first FBUFSIZE bytes of this flash section */
		if (freadpos + FBUFSIZE > bsize) {
			EL(ha, "passed buffer too small; fr=%xh, bsize=%xh\n",
			    freadpos, bsize);
			rval = QL_FUNCTION_FAILED;
			break;
		}
		bcopy(bfp + freadpos, ftmp->buf, FBUFSIZE);

		/* checkout the pci data / format */
		if (ql_check_pci(ha, ftmp, &freadpos)) {
			EL(ha, "flash header incorrect\n");
			rval = QL_FUNCTION_FAILED;
			break;
		}
	}

	if (rval != QL_SUCCESS) {
		/*
		 * release all resources we have
		 */
		ql_fcache_rel(head);
		EL(ha, "failed, done\n");
	} else {
		/*
		 * Release previous fcache resources and update with new
		 */
		ql_fcache_rel(ha->fcache);
		ha->fcache = head;

		QL_PRINT_3(ha, "done\n");
	}
}

/*
 * ql_setup_fnode
 *	Allocates fcache node
 *
 * Input:
 *	ha = adapter state pointer.
 *	node = point to allocated fcache node (NULL = failed)
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 *
 * Note:
 *	Driver must be in stalled state prior to entering or
 *	add code to this function prior to calling ql_setup_flash()
 */
static ql_fcache_t *
ql_setup_fnode(ql_adapter_state_t *ha)
{
	ql_fcache_t	*fnode = NULL;

	if ((fnode = (ql_fcache_t *)(kmem_zalloc(sizeof (ql_fcache_t),
	    KM_SLEEP))) == NULL) {
		EL(ha, "fnode alloc failed\n");
		fnode = NULL;
	} else if ((fnode->buf = (uint8_t *)(kmem_zalloc(FBUFSIZE,
	    KM_SLEEP))) == NULL) {
		EL(ha, "buf alloc failed\n");
		kmem_free(fnode, sizeof (ql_fcache_t));
		fnode = NULL;
	} else {
		fnode->buflen = FBUFSIZE;
	}

	return (fnode);
}

/*
 * ql_fcache_rel
 *	Releases the fcache resources
 *
 * Input:
 *	ha	= adapter state pointer.
 *	head	= Pointer to fcache linked list
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 *
 */
void
ql_fcache_rel(ql_fcache_t *head)
{
	ql_fcache_t	*ftmp = head;
	ql_fcache_t	*tail;

	/* release all resources we have */
	while (ftmp != NULL) {
		tail = ftmp->next;
		kmem_free(ftmp->buf, FBUFSIZE);
		kmem_free(ftmp, sizeof (ql_fcache_t));
		ftmp = tail;
	}
}

/*
 * ql_update_flash_caches
 *	Updates driver flash caches
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_update_flash_caches(ql_adapter_state_t *ha)
{
	uint32_t		len;
	ql_link_t		*link;
	ql_adapter_state_t	*ha2;

	QL_PRINT_3(ha, "started\n");

	/* Get base path length. */
	for (len = (uint32_t)strlen(ha->devpath); len; len--) {
		if (ha->devpath[len] == ',' ||
		    ha->devpath[len] == '@') {
			break;
		}
	}

	/* Reset fcache on all adapter instances. */
	for (link = ql_hba.first; link != NULL; link = link->next) {
		ha2 = link->base_address;

		if (strncmp(ha->devpath, ha2->devpath, len) != 0) {
			continue;
		}

		ql_fcache_rel(ha2->fcache);
		ha2->fcache = NULL;

		if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
			if (ha2->vcache != NULL) {
				kmem_free(ha2->vcache, QL_24XX_VPD_SIZE);
				ha2->vcache = NULL;
			}
		}

		(void) ql_setup_fcache(ha2);
	}

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_get_fbuf
 *	Search the fcache list for the type specified
 *
 * Input:
 *	fptr	= Pointer to fcache linked list
 *	ftype	= Type of image to be returned.
 *
 * Returns:
 *	Pointer to ql_fcache_t.
 *	NULL means not found.
 *
 * Context:
 *	Kernel context.
 *
 *
 */
ql_fcache_t *
ql_get_fbuf(ql_fcache_t *fptr, uint32_t ftype)
{
	while (fptr != NULL) {
		/* does this image meet criteria? */
		if (ftype & fptr->type) {
			break;
		}
		fptr = fptr->next;
	}
	return (fptr);
}

/*
 * ql_check_pci
 *
 *	checks the passed buffer for a valid pci signature and
 *	expected (and in range) pci length values.
 *
 *	For firmware type, a pci header is added since the image in
 *	the flash does not have one (!!!).
 *
 *	On successful pci check, nextpos adjusted to next pci header.
 *
 * Returns:
 *	-1 --> last pci image
 *	0 --> pci header valid
 *	1 --> pci header invalid.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_check_pci(ql_adapter_state_t *ha, ql_fcache_t *fcache, uint32_t *nextpos)
{
	pci_header_t	*pcih;
	pci_data_t	*pcid;
	uint32_t	doff;
	uint8_t		*pciinfo;

	QL_PRINT_3(ha, "started\n");

	if (fcache != NULL) {
		pciinfo = fcache->buf;
	} else {
		EL(ha, "failed, null fcache ptr passed\n");
		return (1);
	}

	if (pciinfo == NULL) {
		EL(ha, "failed, null pciinfo ptr passed\n");
		return (1);
	}

	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		caddr_t	bufp;
		uint_t	len;

		if (pciinfo[0] != SBUS_CODE_FCODE) {
			EL(ha, "failed, unable to detect sbus fcode\n");
			return (1);
		}
		fcache->type = FTYPE_FCODE;

		/*LINTED [Solaris DDI_DEV_T_ANY Lint error]*/
		if (ddi_getlongprop(DDI_DEV_T_ANY, ha->dip,
		    PROP_LEN_AND_VAL_ALLOC | DDI_PROP_DONTPASS |
		    DDI_PROP_CANSLEEP, "version", (caddr_t)&bufp,
		    (int *)&len) == DDI_PROP_SUCCESS) {

			(void) snprintf(fcache->verstr,
			    FCHBA_OPTION_ROM_VERSION_LEN, "%s", bufp);
			kmem_free(bufp, len);
		}

		*nextpos = 0xffffffff;

		QL_PRINT_3(ha, "CFG_SBUS_CARD, done\n");

		return (0);
	}

	if (*nextpos == ha->flash_fw_addr << 2) {

		pci_header_t	fwh = {0};
		pci_data_t	fwd = {0};
		uint8_t		*buf, *bufp;

		/*
		 * Build a pci header for the firmware module
		 */
		if ((buf = (uint8_t *)(kmem_zalloc(FBUFSIZE, KM_SLEEP))) ==
		    NULL) {
			EL(ha, "failed, unable to allocate buffer\n");
			return (1);
		}

		fwh.signature[0] = PCI_HEADER0;
		fwh.signature[1] = PCI_HEADER1;
		fwh.dataoffset[0] = LSB(sizeof (pci_header_t));
		fwh.dataoffset[1] = MSB(sizeof (pci_header_t));

		fwd.signature[0] = 'P';
		fwd.signature[1] = 'C';
		fwd.signature[2] = 'I';
		fwd.signature[3] = 'R';
		fwd.codetype = PCI_CODE_FW;
		fwd.pcidatalen[0] = LSB(sizeof (pci_data_t));
		fwd.pcidatalen[1] = MSB(sizeof (pci_data_t));

		bufp = buf;
		bcopy(&fwh, bufp, sizeof (pci_header_t));
		bufp += sizeof (pci_header_t);
		bcopy(&fwd, bufp, sizeof (pci_data_t));
		bufp += sizeof (pci_data_t);

		bcopy(fcache->buf, bufp, (FBUFSIZE - sizeof (pci_header_t) -
		    sizeof (pci_data_t)));
		bcopy(buf, fcache->buf, FBUFSIZE);

		fcache->type = FTYPE_FW;

		(void) snprintf(fcache->verstr, FCHBA_OPTION_ROM_VERSION_LEN,
		    "%d.%02d.%02d", fcache->buf[19], fcache->buf[23],
		    fcache->buf[27]);

		*nextpos = ha->boot_code_addr << 2;
		kmem_free(buf, FBUFSIZE);

		QL_PRINT_3(ha, "FTYPE_FW, done\n");

		return (0);
	}

	/* get to the pci header image length */
	pcih = (pci_header_t *)pciinfo;

	doff = pcih->dataoffset[0] | (pcih->dataoffset[1] << 8);

	/* some header section sanity check */
	if (pcih->signature[0] != PCI_HEADER0 ||
	    pcih->signature[1] != PCI_HEADER1 || doff > 50) {
		EL(ha, "buffer format error: s0=%xh, s1=%xh, off=%xh\n",
		    pcih->signature[0], pcih->signature[1], doff);
		return (1);
	}

	pcid = (pci_data_t *)(pciinfo + doff);

	/* a slight sanity data section check */
	if (pcid->signature[0] != 'P' || pcid->signature[1] != 'C' ||
	    pcid->signature[2] != 'I' || pcid->signature[3] != 'R') {
		EL(ha, "failed, data sig mismatch!\n");
		return (1);
	}

	if (pcid->indicator == PCI_IND_LAST_IMAGE) {
		QL_PRINT_3(ha, "last image\n");
		if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
			ql_flash_layout_table(ha, *nextpos +
			    (pcid->imagelength[0] | (pcid->imagelength[1] <<
			    8)) * PCI_SECTOR_SIZE);
			(void) ql_24xx_flash_desc(ha);
		}
		*nextpos = 0xffffffff;
	} else {
		/* adjust the next flash read start position */
		*nextpos += (pcid->imagelength[0] |
		    (pcid->imagelength[1] << 8)) * PCI_SECTOR_SIZE;
	}

	switch (pcid->codetype) {
	case PCI_CODE_X86PC:
		fcache->type = FTYPE_BIOS;
		break;
	case PCI_CODE_FCODE:
		fcache->type = FTYPE_FCODE;
		break;
	case PCI_CODE_EFI:
		fcache->type = FTYPE_EFI;
		break;
	case PCI_CODE_HPPA:
		fcache->type = FTYPE_HPPA;
		break;
	default:
		fcache->type = FTYPE_UNKNOWN;
		break;
	}

	(void) snprintf(fcache->verstr, FCHBA_OPTION_ROM_VERSION_LEN,
	    "%d.%02d", pcid->revisionlevel[1], pcid->revisionlevel[0]);

	QL_PRINT_3(ha, "done\n");

	return (0);
}

/*
 * ql_flash_layout_table
 *	Obtains flash addresses from table
 *
 * Input:
 *	ha:		adapter state pointer.
 *	flt_paddr:	flash layout pointer address.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_flash_layout_table(ql_adapter_state_t *ha, uint32_t flt_paddr)
{
	ql_flt_ptr_t	*fptr;
	uint8_t		*bp;
	int		rval;
	uint32_t	len, faddr, cnt;
	uint16_t	chksum, w16;

	QL_PRINT_9(ha, "started\n");

	/* Process flash layout table header */
	len = sizeof (ql_flt_ptr_t);
	if ((bp = kmem_zalloc(len, KM_SLEEP)) == NULL) {
		EL(ha, "kmem_zalloc=null\n");
		return;
	}

	/* Process pointer to flash layout table */
	if ((rval = ql_dump_fcode(ha, bp, len, flt_paddr)) != QL_SUCCESS) {
		EL(ha, "fptr dump_flash pos=%xh, status=%xh\n", flt_paddr,
		    rval);
		kmem_free(bp, len);
		return;
	}
	fptr = (ql_flt_ptr_t *)bp;

	/* Verify pointer to flash layout table. */
	for (chksum = 0, cnt = 0; cnt < len; cnt += 2) {
		w16 = (uint16_t)CHAR_TO_SHORT(bp[cnt], bp[cnt + 1]);
		chksum += w16;
	}
	if (chksum != 0 || fptr->sig[0] != 'Q' || fptr->sig[1] != 'F' ||
	    fptr->sig[2] != 'L' || fptr->sig[3] != 'T') {
		EL(ha, "ptr chksum=%xh, sig=%c%c%c%c \n",
		    chksum, fptr->sig[0],
		    fptr->sig[1], fptr->sig[2], fptr->sig[3]);
		kmem_free(bp, len);
		return;
	}
	faddr = CHAR_TO_LONG(fptr->addr[0], fptr->addr[1], fptr->addr[2],
	    fptr->addr[3]);

	kmem_free(bp, len);

	ql_process_flt(ha, faddr);

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_process_flt
 *	Obtains flash addresses from flash layout table
 *
 * Input:
 *	ha:	adapter state pointer.
 *	faddr:	flash layout table byte address.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_process_flt(ql_adapter_state_t *ha, uint32_t faddr)
{
	ql_flt_hdr_t	*fhdr;
	ql_flt_region_t	*frgn;
	uint8_t		*bp, *eaddr, nv_rg, vpd_rg;
	int		rval;
	uint32_t	len, cnt, fe_addr;
	uint16_t	chksum, w16;

	QL_PRINT_9(ha, "started faddr=%xh\n", faddr);

	/* Process flash layout table header */
	if ((bp = kmem_zalloc(FLASH_LAYOUT_TABLE_SIZE, KM_SLEEP)) == NULL) {
		EL(ha, "kmem_zalloc=null\n");
		return;
	}
	fhdr = (ql_flt_hdr_t *)bp;

	/* Process flash layout table. */
	if ((rval = ql_dump_fcode(ha, bp, FLASH_LAYOUT_TABLE_SIZE, faddr)) !=
	    QL_SUCCESS) {
		EL(ha, "fhdr dump_flash pos=%xh, status=%xh\n", faddr, rval);
		kmem_free(bp, FLASH_LAYOUT_TABLE_SIZE);
		return;
	}

	/* Verify flash layout table. */
	len = (uint32_t)(CHAR_TO_SHORT(fhdr->len[0], fhdr->len[1]) +
	    sizeof (ql_flt_hdr_t) + sizeof (ql_flt_region_t));
	if (len > FLASH_LAYOUT_TABLE_SIZE) {
		chksum = 0xffff;
	} else {
		for (chksum = 0, cnt = 0; cnt < len; cnt += 2) {
			w16 = (uint16_t)CHAR_TO_SHORT(bp[cnt], bp[cnt + 1]);
			chksum += w16;
		}
	}
	w16 = CHAR_TO_SHORT(fhdr->version[0], fhdr->version[1]);
	if (chksum != 0 || w16 != 1) {
		EL(ha, "table chksum=%xh, version=%d\n", chksum, w16);
		kmem_free(bp, FLASH_LAYOUT_TABLE_SIZE);
		return;
	}
	eaddr = bp + len;

	/* Process Function/Port Configuration Map. */
	nv_rg = vpd_rg = 0;
	if (CFG_IST(ha, CFG_CTRL_82XX)) {
		uint16_t	i;
		uint8_t		*mbp = eaddr;
		ql_fp_cfg_map_t	*cmp = (ql_fp_cfg_map_t *)mbp;

		len = (uint32_t)(CHAR_TO_SHORT(cmp->hdr.len[0],
		    cmp->hdr.len[1]));
		if (len > FLASH_LAYOUT_TABLE_SIZE) {
			chksum = 0xffff;
		} else {
			for (chksum = 0, cnt = 0; cnt < len; cnt += 2) {
				w16 = (uint16_t)CHAR_TO_SHORT(mbp[cnt],
				    mbp[cnt + 1]);
				chksum += w16;
			}
		}
		w16 = CHAR_TO_SHORT(cmp->hdr.version[0], cmp->hdr.version[1]);
		if (chksum != 0 || w16 != 1 ||
		    cmp->hdr.Signature[0] != 'F' ||
		    cmp->hdr.Signature[1] != 'P' ||
		    cmp->hdr.Signature[2] != 'C' ||
		    cmp->hdr.Signature[3] != 'M') {
			EL(ha, "cfg_map chksum=%xh, version=%d, "
			    "sig=%c%c%c%c \n", chksum, w16,
			    cmp->hdr.Signature[0], cmp->hdr.Signature[1],
			    cmp->hdr.Signature[2], cmp->hdr.Signature[3]);
		} else {
			cnt = (uint16_t)
			    (CHAR_TO_SHORT(cmp->hdr.NumberEntries[0],
			    cmp->hdr.NumberEntries[1]));
			/* Locate entry for function. */
			for (i = 0; i < cnt; i++) {
				if (cmp->cfg[i].FunctionType == FT_FC &&
				    cmp->cfg[i].FunctionNumber[0] ==
				    ha->pci_function_number &&
				    cmp->cfg[i].FunctionNumber[1] == 0) {
					nv_rg = cmp->cfg[i].ConfigRegion;
					vpd_rg = cmp->cfg[i].VpdRegion;
					break;
				}
			}

			if (nv_rg == 0 || vpd_rg == 0) {
				EL(ha, "cfg_map nv_rg=%d, vpd_rg=%d\n", nv_rg,
				    vpd_rg);
				nv_rg = vpd_rg = 0;
			}
		}
	}

	/* Process flash layout table regions */
	for (frgn = (ql_flt_region_t *)(bp + sizeof (ql_flt_hdr_t));
	    (uint8_t *)frgn < eaddr; frgn++) {
		faddr = CHAR_TO_LONG(frgn->beg_addr[0], frgn->beg_addr[1],
		    frgn->beg_addr[2], frgn->beg_addr[3]);
		faddr >>= 2;
		fe_addr = CHAR_TO_LONG(frgn->end_addr[0], frgn->end_addr[1],
		    frgn->end_addr[2], frgn->end_addr[3]);
		fe_addr >>= 2;

		switch (frgn->region) {
		case FLASH_8021_BOOTLOADER_REGION:
			ha->bootloader_addr = faddr;
			ha->bootloader_size = (fe_addr - faddr) + 1;
			QL_PRINT_9(ha, "bootloader_addr=%xh, "
			    "size=%xh\n", faddr,
			    ha->bootloader_size);
			break;
		case FLASH_FW_REGION:
		case FLASH_8021_FW_REGION:
			ha->flash_fw_addr = faddr;
			ha->flash_fw_size = (fe_addr - faddr) + 1;
			QL_PRINT_9(ha, "flash_fw_addr=%xh, "
			    "size=%xh\n", faddr,
			    ha->flash_fw_size);
			break;
		case FLASH_GOLDEN_FW_REGION:
		case FLASH_8021_GOLDEN_FW_REGION:
			ha->flash_golden_fw_addr = faddr;
			QL_PRINT_9(ha, "flash_golden_fw_addr=%xh\n",
			    ha->instance, faddr);
			break;
		case FLASH_8021_VPD_REGION:
			if (!vpd_rg || vpd_rg == FLASH_8021_VPD_REGION) {
				ha->flash_vpd_addr = faddr;
				QL_PRINT_9(ha, "8021_flash_vpd_"
				    "addr=%xh\n", faddr);
			}
			break;
		case FLASH_VPD_0_REGION:
			if (vpd_rg) {
				if (vpd_rg == FLASH_VPD_0_REGION) {
					ha->flash_vpd_addr = faddr;
					QL_PRINT_9(ha, "vpd_rg  "
					    "flash_vpd_addr=%xh\n",
					    ha->instance, faddr);
				}
			} else if (ha->function_number == 0 &&
			    !(CFG_IST(ha, CFG_CTRL_82XX))) {
				ha->flash_vpd_addr = faddr;
				QL_PRINT_9(ha, "flash_vpd_addr=%xh"
				    "\n", faddr);
			}
			break;
		case FLASH_NVRAM_0_REGION:
			if (nv_rg) {
				if (nv_rg == FLASH_NVRAM_0_REGION) {
					ADAPTER_STATE_LOCK(ha);
					ha->function_number = 0;
					ADAPTER_STATE_UNLOCK(ha);
					ha->flash_nvram_addr = faddr;
					QL_PRINT_9(ha, "nv_rg "
					    "flash_nvram_addr=%xh\n",
					    ha->instance, faddr);
				}
			} else if (ha->function_number == 0) {
				ha->flash_nvram_addr = faddr;
				QL_PRINT_9(ha, "flash_nvram_addr="
				    "%xh\n", faddr);
			}
			break;
		case FLASH_VPD_1_REGION:
			if (vpd_rg) {
				if (vpd_rg == FLASH_VPD_1_REGION) {
					ha->flash_vpd_addr = faddr;
					QL_PRINT_9(ha, "vpd_rg "
					    "flash_vpd_addr=%xh\n",
					    ha->instance, faddr);
				}
			} else if (ha->function_number &&
			    !(CFG_IST(ha, CFG_CTRL_82XX))) {
				ha->flash_vpd_addr = faddr;
				QL_PRINT_9(ha, "flash_vpd_addr=%xh"
				    "\n", faddr);
			}
			break;
		case FLASH_NVRAM_1_REGION:
			if (nv_rg) {
				if (nv_rg == FLASH_NVRAM_1_REGION) {
					ADAPTER_STATE_LOCK(ha);
					ha->function_number = 1;
					ADAPTER_STATE_UNLOCK(ha);
					ha->flash_nvram_addr = faddr;
					QL_PRINT_9(ha, "nv_rg "
					    "flash_nvram_addr=%xh\n",
					    ha->instance, faddr);
				}
			} else if (ha->function_number) {
				ha->flash_nvram_addr = faddr;
				QL_PRINT_9(ha, "flash_nvram_addr="
				    "%xh\n", faddr);
			}
			break;
		case FLASH_DESC_TABLE_REGION:
			if (!(CFG_IST(ha, CFG_CTRL_82XX))) {
				ha->flash_desc_addr = faddr;
				QL_PRINT_9(ha, "flash_desc_addr="
				    "%xh\n", faddr);
			}
			break;
		case FLASH_ERROR_LOG_0_REGION:
			if (ha->function_number == 0) {
				ha->flash_errlog_start = faddr;
				QL_PRINT_9(ha, "flash_errlog_addr="
				    "%xh\n", faddr);
			}
			break;
		case FLASH_ERROR_LOG_1_REGION:
			if (ha->function_number) {
				ha->flash_errlog_start = faddr;
				QL_PRINT_9(ha, "flash_errlog_addr="
				    "%xh\n", faddr);
			}
			break;
		default:
			break;
		}
	}
	kmem_free(bp, FLASH_LAYOUT_TABLE_SIZE);

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_flash_nvram_defaults
 *	Flash default addresses.
 *
 * Input:
 *	ha:		adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_flash_nvram_defaults(ql_adapter_state_t *ha)
{
	QL_PRINT_10(ha, "started\n");

	if (ha->function_number == 3) {
		if (CFG_IST(ha, CFG_CTRL_27XX)) {
			ha->flash_nvram_addr = NVRAM_2700_FUNC3_ADDR;
			ha->flash_vpd_addr = VPD_2700_FUNC3_ADDR;
			ha->ledstate.select = BEACON_2700_FUNC3_ADDR;
			ha->flash_data_addr = FLASH_2700_DATA_ADDR;
			ha->flash_desc_addr = FLASH_2700_DESCRIPTOR_TABLE;
			ha->flash_fw_addr = FLASH_2700_FIRMWARE_ADDR;
			ha->flash_fw_size = FLASH_2700_FIRMWARE_SIZE;
			ha->boot_code_addr = FLASH_2700_BOOT_CODE_ADDR;
		} else {
			EL(ha, "unassigned flash fn%d addr: %x\n",
			    ha->function_number, ha->device_id);
		}
	} else if (ha->function_number == 2) {
		if (CFG_IST(ha, CFG_CTRL_27XX)) {
			ha->flash_nvram_addr = NVRAM_2700_FUNC2_ADDR;
			ha->flash_vpd_addr = VPD_2700_FUNC2_ADDR;
			ha->ledstate.select = BEACON_2700_FUNC2_ADDR;
			ha->flash_data_addr = FLASH_2700_DATA_ADDR;
			ha->flash_desc_addr = FLASH_2700_DESCRIPTOR_TABLE;
			ha->flash_fw_addr = FLASH_2700_FIRMWARE_ADDR;
			ha->flash_fw_size = FLASH_2700_FIRMWARE_SIZE;
			ha->boot_code_addr = FLASH_2700_BOOT_CODE_ADDR;
		} else {
			EL(ha, "unassigned flash fn%d addr: %x\n",
			    ha->function_number, ha->device_id);
		}
	} else if (ha->function_number == 1) {
		if (CFG_IST(ha, CFG_CTRL_23XX) ||
		    (CFG_IST(ha, CFG_CTRL_63XX))) {
			ha->flash_nvram_addr = NVRAM_2300_FUNC1_ADDR;
			ha->flash_fw_addr = FLASH_2300_FIRMWARE_ADDR;
			ha->boot_code_addr = FLASH_2300_BOOT_CODE_ADDR;
		} else if (CFG_IST(ha, CFG_CTRL_24XX)) {
			ha->flash_data_addr = FLASH_24_25_DATA_ADDR;
			ha->flash_nvram_addr = NVRAM_2400_FUNC1_ADDR;
			ha->flash_vpd_addr = VPD_2400_FUNC1_ADDR;
			ha->flash_errlog_start = FLASH_2400_ERRLOG_START_ADDR_1;
			ha->flash_desc_addr = FLASH_2400_DESCRIPTOR_TABLE;
			ha->flash_fw_addr = FLASH_2400_FIRMWARE_ADDR;
			ha->boot_code_addr = FLASH_2400_BOOT_CODE_ADDR;
		} else if (CFG_IST(ha, CFG_CTRL_25XX)) {
			ha->flash_data_addr = FLASH_24_25_DATA_ADDR;
			ha->flash_nvram_addr = NVRAM_2500_FUNC1_ADDR;
			ha->flash_vpd_addr = VPD_2500_FUNC1_ADDR;
			ha->flash_errlog_start = FLASH_2500_ERRLOG_START_ADDR_1;
			ha->flash_desc_addr = FLASH_2500_DESCRIPTOR_TABLE;
			ha->flash_fw_addr = FLASH_2500_FIRMWARE_ADDR;
			ha->boot_code_addr = FLASH_2500_BOOT_CODE_ADDR;
		} else if (CFG_IST(ha, CFG_CTRL_81XX)) {
			ha->flash_data_addr = FLASH_8100_DATA_ADDR;
			ha->flash_nvram_addr = NVRAM_8100_FUNC1_ADDR;
			ha->flash_vpd_addr = VPD_8100_FUNC1_ADDR;
			ha->flash_errlog_start = FLASH_8100_ERRLOG_START_ADDR_1;
			ha->flash_desc_addr = FLASH_8100_DESCRIPTOR_TABLE;
			ha->flash_fw_addr = FLASH_8100_FIRMWARE_ADDR;
			ha->boot_code_addr = FLASH_8100_BOOT_CODE_ADDR;
		} else if (CFG_IST(ha, CFG_CTRL_82XX)) {
			ha->flash_data_addr = 0;
			ha->flash_nvram_addr = NVRAM_8021_FUNC1_ADDR;
			ha->flash_vpd_addr = VPD_8021_FUNC1_ADDR;
			ha->flash_errlog_start = 0;
			ha->flash_desc_addr = FLASH_8021_DESCRIPTOR_TABLE;
			ha->flash_fw_addr = FLASH_8021_FIRMWARE_ADDR;
			ha->flash_fw_size = FLASH_8021_FIRMWARE_SIZE;
			ha->bootloader_addr = FLASH_8021_BOOTLOADER_ADDR;
			ha->bootloader_size = FLASH_8021_BOOTLOADER_SIZE;
			ha->boot_code_addr = FLASH_8021_BOOT_CODE_ADDR;
		} else if (CFG_IST(ha, CFG_CTRL_83XX)) {
			ha->flash_nvram_addr = NVRAM_8300_FC_FUNC1_ADDR;
			ha->flash_vpd_addr = VPD_8300_FC_FUNC1_ADDR;
			ha->ledstate.select = BEACON_8300_FC_FUNC1_ADDR;
			ha->flash_errlog_start = FLASH_8300_ERRLOG_START_ADDR_1;
			ha->flash_data_addr = FLASH_8300_DATA_ADDR;
			ha->flash_desc_addr = FLASH_8300_DESCRIPTOR_TABLE;
			ha->flash_fw_addr = FLASH_8300_FC_FIRMWARE_ADDR;
			ha->flash_fw_size = FLASH_8300_FIRMWARE_SIZE;
			ha->bootloader_addr = FLASH_8300_BOOTLOADER_ADDR;
			ha->bootloader_size = FLASH_8300_BOOTLOADER_SIZE;
			ha->boot_code_addr = FLASH_8300_BOOT_CODE_ADDR;
		} else if (CFG_IST(ha, CFG_CTRL_27XX)) {
			ha->flash_nvram_addr = NVRAM_2700_FUNC1_ADDR;
			ha->flash_vpd_addr = VPD_2700_FUNC1_ADDR;
			ha->ledstate.select = BEACON_2700_FUNC1_ADDR;
			ha->flash_data_addr = FLASH_2700_DATA_ADDR;
			ha->flash_desc_addr = FLASH_2700_DESCRIPTOR_TABLE;
			ha->flash_fw_addr = FLASH_2700_FIRMWARE_ADDR;
			ha->flash_fw_size = FLASH_2700_FIRMWARE_SIZE;
			ha->boot_code_addr = FLASH_2700_BOOT_CODE_ADDR;
		} else {
			EL(ha, "unassigned flash fn%d addr: %x\n",
			    ha->function_number, ha->device_id);
		}
	} else if (ha->function_number == 0) {
		if (CFG_IST(ha, CFG_CTRL_22XX)) {
			ha->flash_nvram_addr = NVRAM_2200_FUNC0_ADDR;
			ha->flash_fw_addr = FLASH_2200_FIRMWARE_ADDR;
			ha->boot_code_addr = FLASH_2200_BOOT_CODE_ADDR;
		} else if (CFG_IST(ha, CFG_CTRL_23XX) ||
		    (CFG_IST(ha, CFG_CTRL_63XX))) {
			ha->flash_nvram_addr = NVRAM_2300_FUNC0_ADDR;
			ha->flash_fw_addr = FLASH_2300_FIRMWARE_ADDR;
			ha->boot_code_addr = FLASH_2300_BOOT_CODE_ADDR;
		} else if (CFG_IST(ha, CFG_CTRL_24XX)) {
			ha->flash_data_addr = FLASH_24_25_DATA_ADDR;
			ha->flash_nvram_addr = NVRAM_2400_FUNC0_ADDR;
			ha->flash_vpd_addr = VPD_2400_FUNC0_ADDR;
			ha->flash_errlog_start = FLASH_2400_ERRLOG_START_ADDR_0;
			ha->flash_desc_addr = FLASH_2400_DESCRIPTOR_TABLE;
			ha->flash_fw_addr = FLASH_2400_FIRMWARE_ADDR;
			ha->boot_code_addr = FLASH_2400_BOOT_CODE_ADDR;
		} else if (CFG_IST(ha, CFG_CTRL_25XX)) {
			ha->flash_data_addr = FLASH_24_25_DATA_ADDR;
			ha->flash_nvram_addr = NVRAM_2500_FUNC0_ADDR;
			ha->flash_vpd_addr = VPD_2500_FUNC0_ADDR;
			ha->flash_errlog_start = FLASH_2500_ERRLOG_START_ADDR_0;
			ha->flash_desc_addr = FLASH_2500_DESCRIPTOR_TABLE;
			ha->flash_fw_addr = FLASH_2500_FIRMWARE_ADDR;
			ha->boot_code_addr = FLASH_2500_BOOT_CODE_ADDR;
		} else if (CFG_IST(ha, CFG_CTRL_81XX)) {
			ha->flash_data_addr = FLASH_8100_DATA_ADDR;
			ha->flash_nvram_addr = NVRAM_8100_FUNC0_ADDR;
			ha->flash_vpd_addr = VPD_8100_FUNC0_ADDR;
			ha->flash_errlog_start = FLASH_8100_ERRLOG_START_ADDR_0;
			ha->flash_desc_addr = FLASH_8100_DESCRIPTOR_TABLE;
			ha->flash_fw_addr = FLASH_8100_FIRMWARE_ADDR;
			ha->boot_code_addr = FLASH_8100_BOOT_CODE_ADDR;
		} else if (CFG_IST(ha, CFG_CTRL_82XX)) {
			ha->flash_data_addr = 0;
			ha->flash_nvram_addr = NVRAM_8021_FUNC0_ADDR;
			ha->flash_vpd_addr = VPD_8021_FUNC0_ADDR;
			ha->flash_errlog_start = 0;
			ha->flash_desc_addr = FLASH_8021_DESCRIPTOR_TABLE;
			ha->flash_fw_addr = FLASH_8021_FIRMWARE_ADDR;
			ha->flash_fw_size = FLASH_8021_FIRMWARE_SIZE;
			ha->bootloader_addr = FLASH_8021_BOOTLOADER_ADDR;
			ha->bootloader_size = FLASH_8021_BOOTLOADER_SIZE;
			ha->boot_code_addr = FLASH_8021_BOOT_CODE_ADDR;
		} else if (CFG_IST(ha, CFG_CTRL_83XX)) {
			ha->flash_nvram_addr = NVRAM_8300_FC_FUNC0_ADDR;
			ha->flash_vpd_addr = VPD_8300_FC_FUNC0_ADDR;
			ha->ledstate.select = BEACON_8300_FCOE_FUNC0_ADDR;
			ha->flash_errlog_start = FLASH_8300_ERRLOG_START_ADDR_0;
			ha->flash_data_addr = FLASH_8300_DATA_ADDR;
			ha->flash_desc_addr = FLASH_8300_DESCRIPTOR_TABLE;
			ha->flash_fw_addr = FLASH_8300_FC_FIRMWARE_ADDR;
			ha->flash_fw_size = FLASH_8300_FIRMWARE_SIZE;
			ha->bootloader_addr = FLASH_8300_BOOTLOADER_ADDR;
			ha->bootloader_size = FLASH_8300_BOOTLOADER_SIZE;
			ha->boot_code_addr = FLASH_8300_BOOT_CODE_ADDR;
		} else if (CFG_IST(ha, CFG_CTRL_27XX)) {
			ha->flash_nvram_addr = NVRAM_2700_FUNC0_ADDR;
			ha->flash_vpd_addr = VPD_2700_FUNC0_ADDR;
			ha->ledstate.select = BEACON_2700_FUNC0_ADDR;
			ha->flash_data_addr = FLASH_2700_DATA_ADDR;
			ha->flash_desc_addr = FLASH_2700_DESCRIPTOR_TABLE;
			ha->flash_fw_addr = FLASH_2700_FIRMWARE_ADDR;
			ha->flash_fw_size = FLASH_2700_FIRMWARE_SIZE;
			ha->boot_code_addr = FLASH_2700_BOOT_CODE_ADDR;
		} else {
			EL(ha, "unassigned flash fn%d addr: %x\n",
			    ha->function_number, ha->device_id);
		}
	} else {
		EL(ha, "known function=%d, device_id=%x\n",
		    ha->function_number, ha->device_id);
	}
	QL_PRINT_10(ha, "done\n");
}

/*
 * ql_get_sfp
 *	Returns sfp data to sdmapi caller
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_get_sfp(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	QL_PRINT_9(ha, "started\n");

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_1)) {
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		EL(ha, "failed, invalid request for HBA\n");
		return;
	}

	if (cmd->ResponseLen < QL_24XX_SFP_SIZE) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = QL_24XX_SFP_SIZE;
		EL(ha, "failed, ResponseLen < SFP len, len passed=%xh\n",
		    cmd->ResponseLen);
		return;
	}

	/* Dump SFP data in user buffer */
	if ((ql_dump_sfp(ha, (void *)(uintptr_t)(cmd->ResponseAdr),
	    mode)) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		EL(ha, "failed, copy error\n");
	} else {
		cmd->Status = EXT_STATUS_OK;
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_dump_sfp
 *	Dumps SFP.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	bp:	buffer address.
 *	mode:	flags
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_dump_sfp(ql_adapter_state_t *ha, void *bp, int mode)
{
	dma_mem_t	mem;
	uint32_t	cnt;
	int		rval2, rval = 0;
	uint32_t	dxfer;

	QL_PRINT_9(ha, "started\n");

	/* Get memory for SFP. */

	if ((rval2 = ql_get_dma_mem(ha, &mem, 64, LITTLE_ENDIAN_DMA,
	    QL_DMA_DATA_ALIGN)) != QL_SUCCESS) {
		EL(ha, "failed, ql_get_dma_mem=%xh\n", rval2);
		return (ENOMEM);
	}

	for (cnt = 0; cnt < QL_24XX_SFP_SIZE; cnt += mem.size) {
		rval2 = ql_read_sfp(ha, &mem,
		    (uint16_t)(cnt < 256 ? 0xA0 : 0xA2),
		    (uint16_t)(cnt & 0xff));
		if (rval2 != QL_SUCCESS) {
			EL(ha, "failed, read_sfp=%xh\n", rval2);
			rval = EFAULT;
			break;
		}

		/* copy the data back */
		if ((dxfer = ql_send_buffer_data(mem.bp, bp, mem.size,
		    mode)) != mem.size) {
			/* ddi copy error */
			EL(ha, "failed, ddi copy; byte cnt = %xh", dxfer);
			rval = EFAULT;
			break;
		}

		/* adjust the buffer pointer */
		bp = (caddr_t)bp + mem.size;
	}

	ql_free_phys(ha, &mem);

	QL_PRINT_9(ha, "done\n");

	return (rval);
}

/*
 * ql_port_param
 *	Retrieves or sets the firmware port speed settings
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 *
 */
static void
ql_port_param(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	uint8_t			*name;
	ql_tgt_t		*tq;
	EXT_PORT_PARAM		port_param = {0};
	uint32_t		rval = QL_SUCCESS;
	uint32_t		idma_rate;

	QL_PRINT_9(ha, "started\n");

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_1)) {
		EL(ha, "invalid request for this HBA\n");
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		cmd->ResponseLen = 0;
		return;
	}

	if (LOOP_NOT_READY(ha)) {
		EL(ha, "failed, loop not ready\n");
		cmd->Status = EXT_STATUS_DEVICE_OFFLINE;
		cmd->ResponseLen = 0;
		return;
	}

	if (ddi_copyin((void *)(uintptr_t)cmd->RequestAdr,
	    (void*)&port_param, sizeof (EXT_PORT_PARAM), mode) != 0) {
		EL(ha, "failed, ddi_copyin\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	if (port_param.FCScsiAddr.DestType != EXT_DEF_DESTTYPE_WWPN) {
		EL(ha, "Unsupported dest lookup type: %xh\n",
		    port_param.FCScsiAddr.DestType);
		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		cmd->ResponseLen = 0;
		return;
	}

	name = port_param.FCScsiAddr.DestAddr.WWPN;

	QL_PRINT_9(ha, "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x\n",
	    ha->instance, name[0], name[1], name[2], name[3], name[4],
	    name[5], name[6], name[7]);

	tq = ql_find_port(ha, name, (uint16_t)QLNT_PORT);
	if (tq == NULL || !VALID_TARGET_ID(ha, tq->loop_id) ||
	    tq->d_id.b24 == FS_MANAGEMENT_SERVER) {
		EL(ha, "failed, fc_port not found\n");
		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		cmd->ResponseLen = 0;
		return;
	}

	cmd->Status = EXT_STATUS_OK;
	cmd->DetailStatus = EXT_STATUS_OK;

	switch (port_param.Mode) {
	case EXT_IIDMA_MODE_GET:
		/*
		 * Report the firmware's port rate for the wwpn
		 */
		rval = ql_iidma_rate(ha, tq->loop_id, &idma_rate,
		    port_param.Mode);

		if (rval != QL_SUCCESS) {
			EL(ha, "iidma get failed: %xh\n", rval);
			cmd->Status = EXT_STATUS_MAILBOX;
			cmd->DetailStatus = rval;
			cmd->ResponseLen = 0;
		} else {
			switch (idma_rate) {
			case IIDMA_RATE_1GB:
				port_param.Speed =
				    EXT_DEF_PORTSPEED_1GBIT;
				break;
			case IIDMA_RATE_2GB:
				port_param.Speed =
				    EXT_DEF_PORTSPEED_2GBIT;
				break;
			case IIDMA_RATE_4GB:
				port_param.Speed =
				    EXT_DEF_PORTSPEED_4GBIT;
				break;
			case IIDMA_RATE_8GB:
				port_param.Speed =
				    EXT_DEF_PORTSPEED_8GBIT;
				break;
			case IIDMA_RATE_10GB:
				port_param.Speed =
				    EXT_DEF_PORTSPEED_10GBIT;
				break;
			case IIDMA_RATE_16GB:
				port_param.Speed =
				    EXT_DEF_PORTSPEED_16GBIT;
				break;
			case IIDMA_RATE_32GB:
				port_param.Speed =
				    EXT_DEF_PORTSPEED_32GBIT;
				break;
			default:
				port_param.Speed =
				    EXT_DEF_PORTSPEED_UNKNOWN;
				EL(ha, "failed, Port speed rate=%xh\n",
				    idma_rate);
				break;
			}

			/* Copy back the data */
			rval = ddi_copyout((void *)&port_param,
			    (void *)(uintptr_t)cmd->ResponseAdr,
			    sizeof (EXT_PORT_PARAM), mode);

			if (rval != 0) {
				cmd->Status = EXT_STATUS_COPY_ERR;
				cmd->ResponseLen = 0;
				EL(ha, "failed, ddi_copyout\n");
			} else {
				cmd->ResponseLen = (uint32_t)
				    sizeof (EXT_PORT_PARAM);
			}
		}
		break;

	case EXT_IIDMA_MODE_SET:
		/*
		 * Set the firmware's port rate for the wwpn
		 */
		switch (port_param.Speed) {
		case EXT_DEF_PORTSPEED_1GBIT:
			idma_rate = IIDMA_RATE_1GB;
			break;
		case EXT_DEF_PORTSPEED_2GBIT:
			idma_rate = IIDMA_RATE_2GB;
			break;
		case EXT_DEF_PORTSPEED_4GBIT:
			idma_rate = IIDMA_RATE_4GB;
			break;
		case EXT_DEF_PORTSPEED_8GBIT:
			idma_rate = IIDMA_RATE_8GB;
			break;
		case EXT_DEF_PORTSPEED_10GBIT:
			idma_rate = IIDMA_RATE_10GB;
			break;
		case EXT_DEF_PORTSPEED_16GBIT:
			idma_rate = IIDMA_RATE_16GB;
			break;
		case EXT_DEF_PORTSPEED_32GBIT:
			idma_rate = IIDMA_RATE_32GB;
			break;
		default:
			EL(ha, "invalid set iidma rate: %x\n",
			    port_param.Speed);
			cmd->Status = EXT_STATUS_INVALID_PARAM;
			cmd->ResponseLen = 0;
			rval = QL_PARAMETER_ERROR;
			break;
		}

		if (rval == QL_SUCCESS) {
			rval = ql_iidma_rate(ha, tq->loop_id, &idma_rate,
			    port_param.Mode);
			if (rval != QL_SUCCESS) {
				EL(ha, "iidma set failed: %xh\n", rval);
				cmd->Status = EXT_STATUS_MAILBOX;
				cmd->DetailStatus = rval;
				cmd->ResponseLen = 0;
			}
		}
		break;
	default:
		EL(ha, "invalid mode specified: %x\n", port_param.Mode);
		cmd->Status = EXT_STATUS_INVALID_PARAM;
		cmd->ResponseLen = 0;
		cmd->DetailStatus = 0;
		break;
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_get_fwexttrace
 *	Dumps f/w extended trace buffer
 *
 * Input:
 *	ha:	adapter state pointer.
 *	bp:	buffer address.
 *	mode:	flags
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
static void
ql_get_fwexttrace(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	int	rval;
	caddr_t	payload;

	QL_PRINT_9(ha, "started\n");

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_1)) {
		EL(ha, "invalid request for this HBA\n");
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		cmd->ResponseLen = 0;
		return;
	}

	if ((CFG_IST(ha, CFG_ENABLE_FWEXTTRACE) == 0) ||
	    (ha->fwexttracebuf.bp == NULL)) {
		EL(ha, "f/w extended trace is not enabled\n");
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		cmd->ResponseLen = 0;
		return;
	}

	if (cmd->ResponseLen < FWEXTSIZE) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = FWEXTSIZE;
		EL(ha, "failed, ResponseLen (%xh) < %xh (FWEXTSIZE)\n",
		    cmd->ResponseLen, FWEXTSIZE);
		cmd->ResponseLen = 0;
		return;
	}

	/* Time Stamp */
	rval = ql_fw_etrace(ha, &ha->fwexttracebuf, FTO_INSERT_TIME_STAMP,
	    NULL);
	if (rval != QL_SUCCESS) {
		EL(ha, "f/w extended trace insert"
		    "time stamp failed: %xh\n", rval);
		cmd->Status = EXT_STATUS_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	/* Disable Tracing */
	rval = ql_fw_etrace(ha, &ha->fwexttracebuf, FTO_EXT_TRACE_DISABLE,
	    NULL);
	if (rval != QL_SUCCESS) {
		EL(ha, "f/w extended trace disable failed: %xh\n", rval);
		cmd->Status = EXT_STATUS_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	/* Allocate payload buffer */
	payload = kmem_zalloc(FWEXTSIZE, KM_SLEEP);
	if (payload == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}

	/* Sync DMA buffer. */
	(void) ddi_dma_sync(ha->fwexttracebuf.dma_handle, 0,
	    FWEXTSIZE, DDI_DMA_SYNC_FORKERNEL);

	/* Copy trace buffer data. */
	ddi_rep_get8(ha->fwexttracebuf.acc_handle, (uint8_t *)payload,
	    (uint8_t *)ha->fwexttracebuf.bp, FWEXTSIZE,
	    DDI_DEV_AUTOINCR);

	/* Send payload to application. */
	if (ql_send_buffer_data(payload, (caddr_t)(uintptr_t)cmd->ResponseAdr,
	    cmd->ResponseLen, mode) != cmd->ResponseLen) {
		EL(ha, "failed, send_buffer_data\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
	} else {
		cmd->Status = EXT_STATUS_OK;
	}

	kmem_free(payload, FWEXTSIZE);

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_get_fwfcetrace
 *	Dumps f/w fibre channel event trace buffer
 *
 * Input:
 *	ha:	adapter state pointer.
 *	bp:	buffer address.
 *	mode:	flags
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
static void
ql_get_fwfcetrace(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	int			rval;
	caddr_t			fce_trace_p;
	ql_mbx_data_t		mr;
	EXT_FW_FCE_TRACE	*fce_trace;
	size_t			cnt;
	uint32_t		*bp;

	QL_PRINT_9(ha, "started\n");

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_1)) {
		EL(ha, "invalid request for this HBA\n");
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		cmd->ResponseLen = 0;
		return;
	}

	if ((CFG_IST(ha, CFG_ENABLE_FWFCETRACE) == 0) ||
	    (ha->fwfcetracebuf.bp == NULL)) {
		EL(ha, "f/w FCE trace is not enabled\n");
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		cmd->ResponseLen = 0;
		return;
	}

	if (cmd->ResponseLen < FWFCESIZE) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = FWFCESIZE;
		EL(ha, "failed, ResponseLen (%xh) < %xh (FWFCESIZE)\n",
		    cmd->ResponseLen, FWFCESIZE);
		cmd->ResponseLen = 0;
		return;
	}

	/* Disable Tracing */
	rval = ql_fw_etrace(ha, &ha->fwfcetracebuf, FTO_FCE_TRACE_DISABLE, &mr);
	if (rval != QL_SUCCESS) {
		EL(ha, "f/w FCE trace disable failed: %xh\n", rval);
		cmd->Status = EXT_STATUS_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	/* Allocate payload buffer */
	fce_trace = kmem_zalloc(FWFCESIZE, KM_SLEEP);
	if (fce_trace == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}
	fce_trace_p = (caddr_t)&fce_trace->TraceData[0];

	/* Copy In Ponter and Base Pointer values */
	fce_trace->Registers[0] = mr.mb[2];
	fce_trace->Registers[1] = mr.mb[3];
	fce_trace->Registers[2] = mr.mb[4];
	fce_trace->Registers[3] = mr.mb[5];

	fce_trace->Registers[4] = LSW(ha->fwexttracebuf.cookies->dmac_address);
	fce_trace->Registers[5] = MSW(ha->fwexttracebuf.cookies->dmac_address);
	fce_trace->Registers[6] = LSW(ha->fwexttracebuf.cookies->dmac_notused);
	fce_trace->Registers[7] = MSW(ha->fwexttracebuf.cookies->dmac_notused);

	/* Copy FCE Trace Enable Registers */
	fce_trace->Registers[8] = ha->fw_fce_trace_enable.mb[0];
	fce_trace->Registers[9] = ha->fw_fce_trace_enable.mb[2];
	fce_trace->Registers[10] = ha->fw_fce_trace_enable.mb[3];
	fce_trace->Registers[11] = ha->fw_fce_trace_enable.mb[4];
	fce_trace->Registers[12] = ha->fw_fce_trace_enable.mb[5];
	fce_trace->Registers[13] = ha->fw_fce_trace_enable.mb[6];

	/* Sync DMA buffer. */
	(void) ddi_dma_sync(ha->fwfcetracebuf.dma_handle, 0,
	    FWFCESIZE, DDI_DMA_SYNC_FORKERNEL);

	/* Copy trace buffer data. */
	ddi_rep_get8(ha->fwfcetracebuf.acc_handle, (uint8_t *)fce_trace_p,
	    (uint8_t *)ha->fwfcetracebuf.bp, FWFCESIZE,
	    DDI_DEV_AUTOINCR);

	/* Swap bytes in buffer in case of Big Endian */
	bp = (uint32_t *)&fce_trace->TraceData[0];
	for (cnt = 0; cnt < (FWFCESIZE / sizeof (uint32_t)); cnt++) {
		LITTLE_ENDIAN_32(bp);
		bp++;
	}

	/* Send payload to application. */
	if (ql_send_buffer_data((caddr_t)fce_trace,
	    (caddr_t)(uintptr_t)cmd->ResponseAdr,
	    cmd->ResponseLen, mode) != cmd->ResponseLen) {
		EL(ha, "failed, send_buffer_data\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
	} else {
		cmd->Status = EXT_STATUS_OK;
	}

	/* Re-enable Tracing */
	bzero(ha->fwfcetracebuf.bp, ha->fwfcetracebuf.size);
	if ((rval = ql_fw_etrace(ha, &ha->fwfcetracebuf,
	    FTO_FCE_TRACE_ENABLE, &mr)) != QL_SUCCESS) {
		EL(ha, "fcetrace enable failed: %xh\n", rval);
	} else {
		ha->fw_fce_trace_enable = mr;
		EL(ha, "FCE Trace Re-Enabled\n");
	}

	kmem_free(fce_trace, FWFCESIZE);

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_get_pci_data
 *	Retrieves pci config space data
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 *
 */
static void
ql_get_pci_data(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	uint8_t		cap_ptr;
	uint8_t		cap_id;
	uint32_t	buf_size = 256;

	QL_PRINT_9(ha, "started\n");

	/*
	 * First check the "Capabilities List" bit of the status register.
	 */
	if (ql_pci_config_get16(ha, PCI_CONF_STAT) & PCI_STAT_CAP) {
		/*
		 * Now get the capability pointer
		 */
		cap_ptr = (uint8_t)ql_pci_config_get8(ha, PCI_CONF_CAP_PTR);
		while (cap_ptr != PCI_CAP_NEXT_PTR_NULL) {
			/*
			 * Check for the pcie capability.
			 */
			cap_id = (uint8_t)ql_pci_config_get8(ha, cap_ptr);
			if (cap_id == PCI_CAP_ID_PCI_E) {
				buf_size = 4096;
				break;
			}
			cap_ptr = (uint8_t)ql_pci_config_get8(ha,
			    (cap_ptr + PCI_CAP_NEXT_PTR));
		}
	}

	if (cmd->ResponseLen < buf_size) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = buf_size;
		EL(ha, "failed ResponseLen < buf_size, len passed=%xh\n",
		    cmd->ResponseLen);
		return;
	}

	/* Dump PCI config data. */
	if ((ql_pci_dump(ha, (void *)(uintptr_t)(cmd->ResponseAdr),
	    buf_size, mode)) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->DetailStatus = 0;
		EL(ha, "failed, copy err pci_dump\n");
	} else {
		cmd->Status = EXT_STATUS_OK;
		cmd->DetailStatus = buf_size;
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_pci_dump
 *	Dumps PCI config data to application buffer.
 *
 * Input:
 *	ha = adapter state pointer.
 *	bp = user buffer address.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
int
ql_pci_dump(ql_adapter_state_t *ha, uint32_t *bp, uint32_t pci_size, int mode)
{
	uint32_t	pci_os;
	uint32_t	*ptr32, *org_ptr32;

	QL_PRINT_9(ha, "started\n");

	ptr32 = kmem_zalloc(pci_size, KM_SLEEP);
	if (ptr32 == NULL) {
		EL(ha, "failed kmem_zalloc\n");
		return (ENOMEM);
	}

	/* store the initial value of ptr32 */
	org_ptr32 = ptr32;
	for (pci_os = 0; pci_os < pci_size; pci_os += 4) {
		*ptr32 = (uint32_t)ql_pci_config_get32(ha, pci_os);
		LITTLE_ENDIAN_32(ptr32);
		ptr32++;
	}

	if (ddi_copyout((void *)org_ptr32, (void *)bp, pci_size, mode) !=
	    0) {
		EL(ha, "failed ddi_copyout\n");
		kmem_free(org_ptr32, pci_size);
		return (EFAULT);
	}

	QL_DUMP_9(org_ptr32, 8, pci_size);

	kmem_free(org_ptr32, pci_size);

	QL_PRINT_9(ha, "done\n");

	return (0);
}

/*
 * ql_menlo_reset
 *	Reset Menlo
 *
 * Input:
 *	ha:	adapter state pointer.
 *	bp:	buffer address.
 *	mode:	flags
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static void
ql_menlo_reset(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_MENLO_RESET	rst;
	ql_mbx_data_t	mr;
	int		rval;

	QL_PRINT_9(ha, "started\n");

	if ((CFG_IST(ha, CFG_CTRL_MENLO)) == 0) {
		EL(ha, "failed, invalid request for HBA\n");
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		cmd->ResponseLen = 0;
		return;
	}

	/*
	 * TODO: only vp_index 0 can do this (?)
	 */

	/*  Verify the size of request structure. */
	if (cmd->RequestLen < sizeof (EXT_MENLO_RESET)) {
		/* Return error */
		EL(ha, "RequestLen=%d < %d\n", cmd->RequestLen,
		    sizeof (EXT_MENLO_RESET));
		cmd->Status = EXT_STATUS_INVALID_PARAM;
		cmd->DetailStatus = EXT_DSTATUS_REQUEST_LEN;
		cmd->ResponseLen = 0;
		return;
	}

	/* Get reset request. */
	if (ddi_copyin((void *)(uintptr_t)cmd->RequestAdr,
	    (void *)&rst, sizeof (EXT_MENLO_RESET), mode) != 0) {
		EL(ha, "failed, ddi_copyin\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	/* Wait for I/O to stop and daemon to stall. */
	if (ql_suspend_hba(ha, 0) != QL_SUCCESS) {
		EL(ha, "ql_stall_driver failed\n");
		ql_restart_hba(ha);
		cmd->Status = EXT_STATUS_BUSY;
		cmd->ResponseLen = 0;
		return;
	}

	rval = ql_reset_menlo(ha, &mr, rst.Flags);
	if (rval != QL_SUCCESS) {
		EL(ha, "failed, status=%xh\n", rval);
		cmd->Status = EXT_STATUS_MAILBOX;
		cmd->DetailStatus = rval;
		cmd->ResponseLen = 0;
	} else if (mr.mb[1] != 0) {
		EL(ha, "failed, substatus=%d\n", mr.mb[1]);
		cmd->Status = EXT_STATUS_ERR;
		cmd->DetailStatus = mr.mb[1];
		cmd->ResponseLen = 0;
	}

	ql_restart_hba(ha);

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_menlo_get_fw_version
 *	Get Menlo firmware version.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	bp:	buffer address.
 *	mode:	flags
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static void
ql_menlo_get_fw_version(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	int				rval;
	ql_mbx_iocb_t			*pkt;
	EXT_MENLO_GET_FW_VERSION	ver = {0};

	QL_PRINT_9(ha, "started\n");

	if ((CFG_IST(ha, CFG_CTRL_MENLO)) == 0) {
		EL(ha, "failed, invalid request for HBA\n");
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		cmd->ResponseLen = 0;
		return;
	}

	if (cmd->ResponseLen < sizeof (EXT_MENLO_GET_FW_VERSION)) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = sizeof (EXT_MENLO_GET_FW_VERSION);
		EL(ha, "ResponseLen=%d < %d\n", cmd->ResponseLen,
		    sizeof (EXT_MENLO_GET_FW_VERSION));
		cmd->ResponseLen = 0;
		return;
	}

	/* Allocate packet. */
	pkt = kmem_zalloc(sizeof (ql_mbx_iocb_t), KM_SLEEP);
	if (pkt == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}

	pkt->mvfy.entry_type = VERIFY_MENLO_TYPE;
	pkt->mvfy.entry_count = 1;
	pkt->mvfy.options_status = LE_16(VMF_DO_NOT_UPDATE_FW);

	rval = ql_issue_mbx_iocb(ha, (caddr_t)pkt, sizeof (ql_mbx_iocb_t));
	LITTLE_ENDIAN_16(&pkt->mvfy.options_status);
	LITTLE_ENDIAN_16(&pkt->mvfy.failure_code);
	ver.FwVersion = LE_32(pkt->mvfy.fw_version);

	if (rval != QL_SUCCESS || (pkt->mvfy.entry_status & 0x3c) != 0 ||
	    pkt->mvfy.options_status != CS_COMPLETE) {
		/* Command error */
		EL(ha, "failed, status=%xh, es=%xh, cs=%xh, fc=%xh\n", rval,
		    pkt->mvfy.entry_status & 0x3c, pkt->mvfy.options_status,
		    pkt->mvfy.failure_code);
		cmd->Status = EXT_STATUS_ERR;
		cmd->DetailStatus = rval != QL_SUCCESS ? rval :
		    QL_FUNCTION_FAILED;
		cmd->ResponseLen = 0;
	} else if (ddi_copyout((void *)&ver,
	    (void *)(uintptr_t)cmd->ResponseAdr,
	    sizeof (EXT_MENLO_GET_FW_VERSION), mode) != 0) {
		EL(ha, "failed, ddi_copyout\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
	} else {
		cmd->ResponseLen = sizeof (EXT_MENLO_GET_FW_VERSION);
	}

	kmem_free(pkt, sizeof (ql_mbx_iocb_t));

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_menlo_update_fw
 *	Get Menlo update firmware.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	bp:	buffer address.
 *	mode:	flags
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static void
ql_menlo_update_fw(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	ql_mbx_iocb_t		*pkt;
	dma_mem_t		*dma_mem;
	EXT_MENLO_UPDATE_FW	fw;
	uint32_t		*ptr32;
	int			rval;

	QL_PRINT_9(ha, "started\n");

	if ((CFG_IST(ha, CFG_CTRL_MENLO)) == 0) {
		EL(ha, "failed, invalid request for HBA\n");
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		cmd->ResponseLen = 0;
		return;
	}

	/*
	 * TODO: only vp_index 0 can do this (?)
	 */

	/*  Verify the size of request structure. */
	if (cmd->RequestLen < sizeof (EXT_MENLO_UPDATE_FW)) {
		/* Return error */
		EL(ha, "RequestLen=%d < %d\n", cmd->RequestLen,
		    sizeof (EXT_MENLO_UPDATE_FW));
		cmd->Status = EXT_STATUS_INVALID_PARAM;
		cmd->DetailStatus = EXT_DSTATUS_REQUEST_LEN;
		cmd->ResponseLen = 0;
		return;
	}

	/* Get update fw request. */
	if (ddi_copyin((caddr_t)(uintptr_t)cmd->RequestAdr, (caddr_t)&fw,
	    sizeof (EXT_MENLO_UPDATE_FW), mode) != 0) {
		EL(ha, "failed, ddi_copyin\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	/* Wait for I/O to stop and daemon to stall. */
	if (ql_suspend_hba(ha, 0) != QL_SUCCESS) {
		EL(ha, "ql_stall_driver failed\n");
		ql_restart_hba(ha);
		cmd->Status = EXT_STATUS_BUSY;
		cmd->ResponseLen = 0;
		return;
	}

	/* Allocate packet. */
	dma_mem = (dma_mem_t *)kmem_zalloc(sizeof (dma_mem_t), KM_SLEEP);
	if (dma_mem == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}
	pkt = kmem_zalloc(sizeof (ql_mbx_iocb_t), KM_SLEEP);
	if (pkt == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		kmem_free(dma_mem, sizeof (dma_mem_t));
		ql_restart_hba(ha);
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}

	/* Get DMA memory for the IOCB */
	if (ql_get_dma_mem(ha, dma_mem, fw.TotalByteCount, LITTLE_ENDIAN_DMA,
	    QL_DMA_DATA_ALIGN) != QL_SUCCESS) {
		cmn_err(CE_WARN, "%srequest queue DMA memory "
		    "alloc failed", QL_NAME);
		kmem_free(pkt, sizeof (ql_mbx_iocb_t));
		kmem_free(dma_mem, sizeof (dma_mem_t));
		ql_restart_hba(ha);
		cmd->Status = EXT_STATUS_MS_NO_RESPONSE;
		cmd->ResponseLen = 0;
		return;
	}

	/* Get firmware data. */
	if (ql_get_buffer_data((caddr_t)(uintptr_t)fw.pFwDataBytes, dma_mem->bp,
	    fw.TotalByteCount, mode) != fw.TotalByteCount) {
		EL(ha, "failed, get_buffer_data\n");
		ql_free_dma_resource(ha, dma_mem);
		kmem_free(pkt, sizeof (ql_mbx_iocb_t));
		kmem_free(dma_mem, sizeof (dma_mem_t));
		ql_restart_hba(ha);
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	/* Sync DMA buffer. */
	(void) ddi_dma_sync(dma_mem->dma_handle, 0, dma_mem->size,
	    DDI_DMA_SYNC_FORDEV);

	pkt->mvfy.entry_type = VERIFY_MENLO_TYPE;
	pkt->mvfy.entry_count = 1;
	pkt->mvfy.options_status = (uint16_t)LE_16(fw.Flags);
	ptr32 = dma_mem->bp;
	pkt->mvfy.fw_version = LE_32(ptr32[2]);
	pkt->mvfy.fw_size = LE_32(fw.TotalByteCount);
	pkt->mvfy.fw_sequence_size = LE_32(fw.TotalByteCount);
	pkt->mvfy.dseg_count = LE_16(1);
	pkt->mvfy.dseg.address[0] = (uint32_t)
	    LE_32(LSD(dma_mem->cookie.dmac_laddress));
	pkt->mvfy.dseg.address[1] = (uint32_t)
	    LE_32(MSD(dma_mem->cookie.dmac_laddress));
	pkt->mvfy.dseg.length = LE_32(fw.TotalByteCount);

	rval = ql_issue_mbx_iocb(ha, (caddr_t)pkt, sizeof (ql_mbx_iocb_t));
	LITTLE_ENDIAN_16(&pkt->mvfy.options_status);
	LITTLE_ENDIAN_16(&pkt->mvfy.failure_code);

	if (rval != QL_SUCCESS || (pkt->mvfy.entry_status & 0x3c) != 0 ||
	    pkt->mvfy.options_status != CS_COMPLETE) {
		/* Command error */
		EL(ha, "failed, status=%xh, es=%xh, cs=%xh, fc=%xh\n", rval,
		    pkt->mvfy.entry_status & 0x3c, pkt->mvfy.options_status,
		    pkt->mvfy.failure_code);
		cmd->Status = EXT_STATUS_ERR;
		cmd->DetailStatus = rval != QL_SUCCESS ? rval :
		    QL_FUNCTION_FAILED;
		cmd->ResponseLen = 0;
	}

	ql_free_dma_resource(ha, dma_mem);
	kmem_free(pkt, sizeof (ql_mbx_iocb_t));
	kmem_free(dma_mem, sizeof (dma_mem_t));
	ql_restart_hba(ha);

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_menlo_manage_info
 *	Get Menlo manage info.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	bp:	buffer address.
 *	mode:	flags
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static void
ql_menlo_manage_info(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	ql_mbx_iocb_t		*pkt;
	dma_mem_t		*dma_mem = NULL;
	EXT_MENLO_MANAGE_INFO	info;
	int			rval;

	QL_PRINT_9(ha, "started\n");


	/* The call is only supported for Schultz right now */
	if (CFG_IST(ha, CFG_FCOE_SUPPORT)) {
		ql_get_xgmac_statistics(ha, cmd, mode);
		QL_PRINT_9(ha, "CFG_FCOE_SUPPORT done\n");
		return;
	}

	if (!CFG_IST(ha, CFG_CTRL_MENLO)) {
		EL(ha, "failed, invalid request for HBA\n");
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		cmd->ResponseLen = 0;
		return;
	}

	/*  Verify the size of request structure. */
	if (cmd->RequestLen < sizeof (EXT_MENLO_MANAGE_INFO)) {
		/* Return error */
		EL(ha, "RequestLen=%d < %d\n", cmd->RequestLen,
		    sizeof (EXT_MENLO_MANAGE_INFO));
		cmd->Status = EXT_STATUS_INVALID_PARAM;
		cmd->DetailStatus = EXT_DSTATUS_REQUEST_LEN;
		cmd->ResponseLen = 0;
		return;
	}

	/* Get manage info request. */
	if (ddi_copyin((caddr_t)(uintptr_t)cmd->RequestAdr,
	    (caddr_t)&info, sizeof (EXT_MENLO_MANAGE_INFO), mode) != 0) {
		EL(ha, "failed, ddi_copyin\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	/* Allocate packet. */
	pkt = kmem_zalloc(sizeof (ql_mbx_iocb_t), KM_SLEEP);
	if (pkt == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		ql_restart_driver(ha);
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}

	pkt->mdata.entry_type = MENLO_DATA_TYPE;
	pkt->mdata.entry_count = 1;
	pkt->mdata.options_status = (uint16_t)LE_16(info.Operation);

	/* Get DMA memory for the IOCB */
	if (info.Operation == MENLO_OP_READ_MEM ||
	    info.Operation == MENLO_OP_WRITE_MEM) {
		pkt->mdata.total_byte_count = LE_32(info.TotalByteCount);
		pkt->mdata.parameter_1 =
		    LE_32(info.Parameters.ap.MenloMemory.StartingAddr);
		dma_mem = (dma_mem_t *)kmem_zalloc(sizeof (dma_mem_t),
		    KM_SLEEP);
		if (dma_mem == NULL) {
			EL(ha, "failed, kmem_zalloc\n");
			kmem_free(pkt, sizeof (ql_mbx_iocb_t));
			cmd->Status = EXT_STATUS_NO_MEMORY;
			cmd->ResponseLen = 0;
			return;
		}
		if (ql_get_dma_mem(ha, dma_mem, info.TotalByteCount,
		    LITTLE_ENDIAN_DMA, QL_DMA_DATA_ALIGN) != QL_SUCCESS) {
			cmn_err(CE_WARN, "%srequest queue DMA memory "
			    "alloc failed", QL_NAME);
			kmem_free(dma_mem, sizeof (dma_mem_t));
			kmem_free(pkt, sizeof (ql_mbx_iocb_t));
			cmd->Status = EXT_STATUS_MS_NO_RESPONSE;
			cmd->ResponseLen = 0;
			return;
		}
		if (info.Operation == MENLO_OP_WRITE_MEM) {
			/* Get data. */
			if (ql_get_buffer_data(
			    (caddr_t)(uintptr_t)info.pDataBytes,
			    dma_mem->bp, info.TotalByteCount, mode) !=
			    info.TotalByteCount) {
				EL(ha, "failed, get_buffer_data\n");
				ql_free_dma_resource(ha, dma_mem);
				kmem_free(dma_mem, sizeof (dma_mem_t));
				kmem_free(pkt, sizeof (ql_mbx_iocb_t));
				cmd->Status = EXT_STATUS_COPY_ERR;
				cmd->ResponseLen = 0;
				return;
			}
			(void) ddi_dma_sync(dma_mem->dma_handle, 0,
			    dma_mem->size, DDI_DMA_SYNC_FORDEV);
		}
		pkt->mdata.dseg_count = LE_16(1);
		pkt->mdata.dseg.address[0] = (uint32_t)
		    LE_32(LSD(dma_mem->cookie.dmac_laddress));
		pkt->mdata.dseg.address[1] = (uint32_t)
		    LE_32(MSD(dma_mem->cookie.dmac_laddress));
		pkt->mdata.dseg.length = LE_32(info.TotalByteCount);
	} else if (info.Operation & MENLO_OP_CHANGE_CONFIG) {
		pkt->mdata.parameter_1 =
		    LE_32(info.Parameters.ap.MenloConfig.ConfigParamID);
		pkt->mdata.parameter_2 =
		    LE_32(info.Parameters.ap.MenloConfig.ConfigParamData0);
		pkt->mdata.parameter_3 =
		    LE_32(info.Parameters.ap.MenloConfig.ConfigParamData1);
	} else if (info.Operation & MENLO_OP_GET_INFO) {
		pkt->mdata.parameter_1 =
		    LE_32(info.Parameters.ap.MenloInfo.InfoDataType);
		pkt->mdata.parameter_2 =
		    LE_32(info.Parameters.ap.MenloInfo.InfoContext);
	}

	rval = ql_issue_mbx_iocb(ha, (caddr_t)pkt, sizeof (ql_mbx_iocb_t));
	LITTLE_ENDIAN_16(&pkt->mdata.options_status);
	LITTLE_ENDIAN_16(&pkt->mdata.failure_code);

	if (rval != QL_SUCCESS || (pkt->mdata.entry_status & 0x3c) != 0 ||
	    pkt->mdata.options_status != CS_COMPLETE) {
		/* Command error */
		EL(ha, "failed, status=%xh, es=%xh, cs=%xh, fc=%xh\n", rval,
		    pkt->mdata.entry_status & 0x3c, pkt->mdata.options_status,
		    pkt->mdata.failure_code);
		cmd->Status = EXT_STATUS_ERR;
		cmd->DetailStatus = rval != QL_SUCCESS ? rval :
		    QL_FUNCTION_FAILED;
		cmd->ResponseLen = 0;
	} else if (info.Operation == MENLO_OP_READ_MEM) {
		(void) ddi_dma_sync(dma_mem->dma_handle, 0, dma_mem->size,
		    DDI_DMA_SYNC_FORKERNEL);
		if (ql_send_buffer_data((caddr_t)(uintptr_t)info.pDataBytes,
		    dma_mem->bp, info.TotalByteCount, mode) !=
		    info.TotalByteCount) {
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->ResponseLen = 0;
		}
	}

	ql_free_dma_resource(ha, dma_mem);
	kmem_free(dma_mem, sizeof (dma_mem_t));
	kmem_free(pkt, sizeof (ql_mbx_iocb_t));

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_suspend_hba
 *	Suspends all adapter ports.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	options:	BIT_0 --> leave driver stalled on exit if
 *				  failed.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_suspend_hba(ql_adapter_state_t *ha, uint32_t opt)
{
	ql_adapter_state_t	*ha2;
	ql_link_t		*link;
	int			rval = QL_SUCCESS;

	/* Quiesce I/O on all adapter ports */
	for (link = ql_hba.first; link != NULL; link = link->next) {
		ha2 = link->base_address;

		if (ha2->fru_hba_index != ha->fru_hba_index) {
			continue;
		}

		if ((rval = ql_stall_driver(ha2, opt)) != QL_SUCCESS) {
			EL(ha, "ql_stall_driver status=%xh\n", rval);
			break;
		}
	}

	return (rval);
}

/*
 * ql_restart_hba
 *	Restarts adapter.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_restart_hba(ql_adapter_state_t *ha)
{
	ql_adapter_state_t	*ha2;
	ql_link_t		*link;

	/* Resume I/O on all adapter ports */
	for (link = ql_hba.first; link != NULL; link = link->next) {
		ha2 = link->base_address;

		if (ha2->fru_hba_index != ha->fru_hba_index) {
			continue;
		}

		ql_restart_driver(ha2);
	}
}

/*
 * ql_get_vp_cnt_id
 *	Retrieves pci config space data
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 *
 */
static void
ql_get_vp_cnt_id(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	ql_adapter_state_t	*vha;
	PEXT_VPORT_ID_CNT	ptmp_vp;
	int			id = 0;
	int			rval;
	char			name[MAXPATHLEN];

	QL_PRINT_9(ha, "started\n");

	/*
	 * To be backward compatible with older API
	 * check for the size of old EXT_VPORT_ID_CNT
	 */
	if (cmd->ResponseLen < sizeof (EXT_VPORT_ID_CNT) &&
	    (cmd->ResponseLen != EXT_OLD_VPORT_ID_CNT_SIZE)) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = sizeof (EXT_VPORT_ID_CNT);
		EL(ha, "failed, ResponseLen < EXT_VPORT_ID_CNT, Len=%xh\n",
		    cmd->ResponseLen);
		cmd->ResponseLen = 0;
		return;
	}

	ptmp_vp = (EXT_VPORT_ID_CNT *)
	    kmem_zalloc(sizeof (EXT_VPORT_ID_CNT), KM_SLEEP);
	if (ptmp_vp == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->ResponseLen = 0;
		return;
	}
	vha = ha->vp_next;
	while (vha != NULL) {
		ptmp_vp->VpCnt++;
		ptmp_vp->VpId[id] = vha->vp_index;
		(void) ddi_pathname(vha->dip, name);
		(void) strncpy((char *)ptmp_vp->vp_path[id], name,
		    (sizeof (ptmp_vp->vp_path[id]) -1));
		ptmp_vp->VpDrvInst[id] = (int32_t)vha->instance;
		id++;
		vha = vha->vp_next;
	}
	rval = ddi_copyout((void *)ptmp_vp,
	    (void *)(uintptr_t)(cmd->ResponseAdr),
	    cmd->ResponseLen, mode);
	if (rval != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, ddi_copyout\n");
	} else {
		cmd->ResponseLen = sizeof (EXT_VPORT_ID_CNT);
		QL_PRINT_9(ha, "done, vport_cnt=%d\n",
		    ha->instance, ptmp_vp->VpCnt);
	}
	kmem_free(ptmp_vp, sizeof (EXT_VPORT_ID_CNT));
}

/*
 * ql_vp_ioctl
 *	Performs all EXT_CC_VPORT_CMD functions.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_vp_ioctl(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	QL_PRINT_9(ha, "started, cmd=%d\n",
	    cmd->SubCode);

	/* case off on command subcode */
	switch (cmd->SubCode) {
	case EXT_VF_SC_VPORT_GETINFO:
		ql_qry_vport(ha, cmd, mode);
		break;
	default:
		/* function not supported. */
		cmd->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		EL(ha, "failed, Unsupported Subcode=%xh\n",
		    cmd->SubCode);
		break;
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_qry_vport
 *	Performs EXT_VF_SC_VPORT_GETINFO subfunction.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_qry_vport(ql_adapter_state_t *vha, EXT_IOCTL *cmd, int mode)
{
	ql_adapter_state_t	*tmp_vha;
	EXT_VPORT_INFO		tmp_vport = {0};

	QL_PRINT_9(vha, "started\n", vha->instance);

	if (cmd->ResponseLen < sizeof (EXT_VPORT_INFO)) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = sizeof (EXT_VPORT_INFO);
		EL(vha, "failed, ResponseLen < EXT_VPORT_INFO, Len=%xh\n",
		    cmd->ResponseLen);
		cmd->ResponseLen = 0;
		return;
	}

	/* Fill in the vport information. */
	bcopy(vha->loginparams.node_ww_name.raw_wwn, tmp_vport.wwnn,
	    EXT_DEF_WWN_NAME_SIZE);
	bcopy(vha->loginparams.nport_ww_name.raw_wwn, tmp_vport.wwpn,
	    EXT_DEF_WWN_NAME_SIZE);
	tmp_vport.state = vha->state;
	tmp_vport.id = vha->vp_index;

	tmp_vha = vha->pha->vp_next;
	while (tmp_vha != NULL) {
		tmp_vport.used++;
		tmp_vha = tmp_vha->vp_next;
	}

	if (vha->max_vports > tmp_vport.used) {
		tmp_vport.free = vha->max_vports - tmp_vport.used;
	}

	if (ddi_copyout((void *)&tmp_vport,
	    (void *)(uintptr_t)(cmd->ResponseAdr),
	    sizeof (EXT_VPORT_INFO), mode) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(vha, "failed, ddi_copyout\n");
	} else {
		cmd->ResponseLen = sizeof (EXT_VPORT_INFO);
		QL_PRINT_9(vha, "done\n", vha->instance);
	}
}

/*
 * ql_access_flash
 *	Performs all EXT_CC_ACCESS_FLASH_OS functions.
 *
 * Input:
 *	pi:	port info pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_access_flash(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	int	rval;

	QL_PRINT_9(ha, "started\n");

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_1) &&
	    ql_stall_driver(ha, 0) != QL_SUCCESS) {
		EL(ha, "ql_stall_driver failed\n");
		ql_restart_driver(ha);
		cmd->Status = EXT_STATUS_BUSY;
		cmd->ResponseLen = 0;
		return;
	}

	switch (cmd->SubCode) {
	case EXT_SC_FLASH_READ:
		if ((rval = ql_flash_fcode_dump(ha,
		    (void *)(uintptr_t)(cmd->ResponseAdr),
		    (size_t)(cmd->ResponseLen), cmd->Reserved1, mode)) != 0) {
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->ResponseLen = 0;
			EL(ha, "flash_fcode_dump status=%xh\n", rval);
		}
		break;
	case EXT_SC_FLASH_WRITE:
		if ((rval = ql_r_m_w_flash(ha,
		    (void *)(uintptr_t)(cmd->RequestAdr),
		    (size_t)(cmd->RequestLen), cmd->Reserved1, mode)) !=
		    QL_SUCCESS) {
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->ResponseLen = 0;
			EL(ha, "r_m_w_flash status=%xh\n", rval);
		} else {
			/* Reset caches on all adapter instances. */
			ql_update_flash_caches(ha);
		}
		break;
	default:
		EL(ha, "unknown subcode=%xh\n", cmd->SubCode);
		cmd->Status = EXT_STATUS_ERR;
		cmd->ResponseLen = 0;
		break;
	}

	/* Resume I/O */
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_1)) {
		EL(ha, "isp_abort_needed for restart\n");
		ql_awaken_task_daemon(ha, NULL, ISP_ABORT_NEEDED,
		    DRIVER_STALL);
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_reset_cmd
 *	Performs all EXT_CC_RESET_FW_OS functions.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_reset_cmd(ql_adapter_state_t *ha, EXT_IOCTL *cmd)
{
	uint8_t	timer;

	QL_PRINT_9(ha, "started\n");

	switch (cmd->SubCode) {
	case EXT_SC_RESET_FC_FW:
		if (CFG_IST(ha, CFG_CTRL_82XX)) {
			(void) ql_8021_reset_fw(ha);
		} else {
			EL(ha, "isp_abort_needed\n");
			ql_awaken_task_daemon(ha, NULL, ISP_ABORT_NEEDED, 0);
		}
		for (timer = 180; timer; timer--) {
			ql_awaken_task_daemon(ha, NULL, 0, 0);
			/* Delay for 1 second. */
			delay(100);
			if (!(ha->task_daemon_flags & (ISP_ABORT_NEEDED |
			    ABORT_ISP_ACTIVE | LOOP_RESYNC_NEEDED |
			    LOOP_RESYNC_ACTIVE))) {
				break;
			}
		}
		break;
	case EXT_SC_RESET_MPI_FW:
		if (!(CFG_IST(ha, CFG_CTRL_8081))) {
			EL(ha, "invalid request for HBA\n");
			cmd->Status = EXT_STATUS_INVALID_REQUEST;
			cmd->ResponseLen = 0;
		} else {
			ADAPTER_STATE_LOCK(ha);
			ha->flags |= DISABLE_NIC_FW_DMP;
			ADAPTER_STATE_UNLOCK(ha);

			/* Wait for I/O to stop and daemon to stall. */
			if (ql_suspend_hba(ha, 0) != QL_SUCCESS) {
				EL(ha, "ql_suspend_hba failed\n");
				cmd->Status = EXT_STATUS_BUSY;
				cmd->ResponseLen = 0;
			} else if (ql_restart_mpi(ha) != QL_SUCCESS) {
				cmd->Status = EXT_STATUS_ERR;
				cmd->ResponseLen = 0;
			} else {
				/*
				 * While the restart_mpi mailbox cmd may be
				 * done the MPI is not. Wait at least 6 sec. or
				 * exit if the loop comes up.
				 */
				for (timer = 6; timer; timer--) {
					if (!(ha->task_daemon_flags &
					    LOOP_DOWN)) {
						break;
					}
					/* Delay for 1 second. */
					ql_delay(ha, 1000000);
				}
			}
			ql_restart_hba(ha);

			ADAPTER_STATE_LOCK(ha);
			ha->flags &= ~DISABLE_NIC_FW_DMP;
			ADAPTER_STATE_UNLOCK(ha);
		}
		break;
	default:
		EL(ha, "unknown subcode=%xh\n", cmd->SubCode);
		cmd->Status = EXT_STATUS_ERR;
		cmd->ResponseLen = 0;
		break;
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_get_dcbx_parameters
 *	Get DCBX parameters.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	User space CT arguments pointer.
 *	mode:	flags.
 */
static void
ql_get_dcbx_parameters(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	uint8_t		*tmp_buf;
	int		rval;

	QL_PRINT_9(ha, "started\n");

	if (!(CFG_IST(ha, CFG_FCOE_SUPPORT))) {
		EL(ha, "invalid request for HBA\n");
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		cmd->ResponseLen = 0;
		return;
	}

	/* Allocate memory for command. */
	tmp_buf = kmem_zalloc(EXT_DEF_DCBX_PARAM_BUF_SIZE, KM_SLEEP);
	if (tmp_buf == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}
	/* Send command */
	rval = ql_get_dcbx_params(ha, EXT_DEF_DCBX_PARAM_BUF_SIZE,
	    (caddr_t)tmp_buf);
	if (rval != QL_SUCCESS) {
		/* error */
		EL(ha, "failed, get_dcbx_params_mbx=%xh\n", rval);
		kmem_free(tmp_buf, EXT_DEF_DCBX_PARAM_BUF_SIZE);
		cmd->Status = EXT_STATUS_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	/* Copy the response */
	if (ql_send_buffer_data((caddr_t)tmp_buf,
	    (caddr_t)(uintptr_t)cmd->ResponseAdr,
	    EXT_DEF_DCBX_PARAM_BUF_SIZE, mode) != EXT_DEF_DCBX_PARAM_BUF_SIZE) {
		EL(ha, "failed, ddi_copyout\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
	} else {
		cmd->ResponseLen = EXT_DEF_DCBX_PARAM_BUF_SIZE;
		QL_PRINT_9(ha, "done\n");
	}
	kmem_free(tmp_buf, EXT_DEF_DCBX_PARAM_BUF_SIZE);

}

/*
 * ql_qry_cna_port
 *	Performs EXT_SC_QUERY_CNA_PORT subfunction.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_qry_cna_port(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	EXT_CNA_PORT	cna_port = {0};

	QL_PRINT_9(ha, "started\n");

	if (!(CFG_IST(ha, CFG_FCOE_SUPPORT))) {
		EL(ha, "invalid request for HBA\n");
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		cmd->ResponseLen = 0;
		return;
	}

	if (cmd->ResponseLen < sizeof (EXT_CNA_PORT)) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = sizeof (EXT_CNA_PORT);
		EL(ha, "failed, ResponseLen < EXT_CNA_PORT, Len=%xh\n",
		    cmd->ResponseLen);
		cmd->ResponseLen = 0;
		return;
	}

	cna_port.VLanId = ha->fcoe_vlan_id;
	cna_port.FabricParam = ha->fabric_params;
	bcopy(ha->fcoe_vnport_mac, cna_port.VNPortMACAddress,
	    EXT_DEF_MAC_ADDRESS_SIZE);

	if (ddi_copyout((void *)&cna_port,
	    (void *)(uintptr_t)(cmd->ResponseAdr),
	    sizeof (EXT_CNA_PORT), mode) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, ddi_copyout\n");
	} else {
		cmd->ResponseLen = sizeof (EXT_CNA_PORT);
		QL_PRINT_9(ha, "done\n");
	}
}

/*
 * ql_qry_adapter_versions
 *	Performs EXT_SC_QUERY_ADAPTER_VERSIONS subfunction.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_qry_adapter_versions(ql_adapter_state_t *ha, EXT_IOCTL *cmd,
    int mode)
{
	uint8_t				is_8142, mpi_cap;
	uint32_t			ver_len, transfer_size;
	PEXT_ADAPTERREGIONVERSION	padapter_ver = NULL;

	QL_PRINT_9(ha, "started\n");

	/* 8142s do not have a EDC PHY firmware. */
	mpi_cap = (uint8_t)(ha->mpi_capability_list >> 8);

	is_8142 = 0;
	/* Sizeof (Length + Reserved) = 8 Bytes */
	if (mpi_cap == 0x02 || mpi_cap == 0x04) {
		ver_len = (sizeof (EXT_REGIONVERSION) * (NO_OF_VERSIONS - 1))
		    + 8;
		is_8142 = 1;
	} else {
		ver_len = (sizeof (EXT_REGIONVERSION) * NO_OF_VERSIONS) + 8;
	}

	/* Allocate local memory for EXT_ADAPTERREGIONVERSION */
	padapter_ver = (EXT_ADAPTERREGIONVERSION *)kmem_zalloc(ver_len,
	    KM_SLEEP);

	if (padapter_ver == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}

	padapter_ver->Length = 1;
	/* Copy MPI version */
	padapter_ver->RegionVersion[0].Region =
	    EXT_OPT_ROM_REGION_MPI_RISC_FW;
	padapter_ver->RegionVersion[0].Version[0] =
	    ha->mpi_fw_major_version;
	padapter_ver->RegionVersion[0].Version[1] =
	    ha->mpi_fw_minor_version;
	padapter_ver->RegionVersion[0].Version[2] =
	    ha->mpi_fw_subminor_version;
	padapter_ver->RegionVersion[0].VersionLength = 3;
	padapter_ver->RegionVersion[0].Location = RUNNING_VERSION;

	if (!is_8142) {
		padapter_ver->RegionVersion[1].Region =
		    EXT_OPT_ROM_REGION_EDC_PHY_FW;
		padapter_ver->RegionVersion[1].Version[0] =
		    ha->phy_fw_major_version;
		padapter_ver->RegionVersion[1].Version[1] =
		    ha->phy_fw_minor_version;
		padapter_ver->RegionVersion[1].Version[2] =
		    ha->phy_fw_subminor_version;
		padapter_ver->RegionVersion[1].VersionLength = 3;
		padapter_ver->RegionVersion[1].Location = RUNNING_VERSION;
		padapter_ver->Length = NO_OF_VERSIONS;
	}

	if (cmd->ResponseLen < ver_len) {
		EL(ha, "failed, ResponseLen < ver_len, ",
		    "RespLen=%xh ver_len=%xh\n", cmd->ResponseLen, ver_len);
		/* Calculate the No. of valid versions being returned. */
		padapter_ver->Length = (uint32_t)
		    ((cmd->ResponseLen - 8) / sizeof (EXT_REGIONVERSION));
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = ver_len;
		transfer_size = cmd->ResponseLen;
	} else {
		transfer_size = ver_len;
	}

	if (ddi_copyout((void *)padapter_ver,
	    (void *)(uintptr_t)(cmd->ResponseAdr),
	    transfer_size, mode) != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, ddi_copyout\n");
	} else {
		cmd->ResponseLen = ver_len;
		QL_PRINT_9(ha, "done\n");
	}

	kmem_free(padapter_ver, ver_len);
}

/*
 * ql_get_xgmac_statistics
 *	Get XgMac information
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_get_xgmac_statistics(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	int			rval;
	uint32_t		size;
	int8_t			*tmp_buf;
	EXT_MENLO_MANAGE_INFO	info;

	QL_PRINT_9(ha, "started\n");

	/*  Verify the size of request structure. */
	if (cmd->RequestLen < sizeof (EXT_MENLO_MANAGE_INFO)) {
		/* Return error */
		EL(ha, "RequestLen=%d < %d\n", cmd->RequestLen,
		    sizeof (EXT_MENLO_MANAGE_INFO));
		cmd->Status = EXT_STATUS_INVALID_PARAM;
		cmd->DetailStatus = EXT_DSTATUS_REQUEST_LEN;
		cmd->ResponseLen = 0;
		return;
	}

	/* Get manage info request. */
	if (ddi_copyin((caddr_t)(uintptr_t)cmd->RequestAdr,
	    (caddr_t)&info, sizeof (EXT_MENLO_MANAGE_INFO), mode) != 0) {
		EL(ha, "failed, ddi_copyin\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	size = info.TotalByteCount;
	if (!size) {
		/* parameter error */
		cmd->Status = EXT_STATUS_INVALID_PARAM;
		cmd->DetailStatus = 0;
		EL(ha, "failed, size=%xh\n", size);
		cmd->ResponseLen = 0;
		return;
	}

	/* Allocate memory for command. */
	tmp_buf = kmem_zalloc(size, KM_SLEEP);
	if (tmp_buf == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}

	if (!(info.Operation & MENLO_OP_GET_INFO)) {
		EL(ha, "Invalid request for 81XX\n");
		kmem_free(tmp_buf, size);
		cmd->Status = EXT_STATUS_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	rval = ql_get_xgmac_stats(ha, size, (caddr_t)tmp_buf);

	if (rval != QL_SUCCESS) {
		/* error */
		EL(ha, "failed, get_xgmac_stats =%xh\n", rval);
		kmem_free(tmp_buf, size);
		cmd->Status = EXT_STATUS_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	if (ql_send_buffer_data(tmp_buf, (caddr_t)(uintptr_t)info.pDataBytes,
	    size, mode) != size) {
		EL(ha, "failed, ddi_copyout\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
	} else {
		cmd->ResponseLen = info.TotalByteCount;
		QL_PRINT_9(ha, "done\n");
	}
	kmem_free(tmp_buf, size);
	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_get_fcf_list
 *	Get FCF list.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	User space CT arguments pointer.
 *	mode:	flags.
 */
static void
ql_get_fcf_list(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	uint8_t			*tmp_buf;
	int			rval;
	EXT_FCF_LIST		fcf_list = {0};
	ql_fcf_list_desc_t	mb_fcf_list = {0};

	QL_PRINT_9(ha, "started\n");

	if (!(CFG_IST(ha, CFG_FCOE_SUPPORT))) {
		EL(ha, "invalid request for HBA\n");
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		cmd->ResponseLen = 0;
		return;
	}
	/* Get manage info request. */
	if (ddi_copyin((caddr_t)(uintptr_t)cmd->RequestAdr,
	    (caddr_t)&fcf_list, sizeof (EXT_FCF_LIST), mode) != 0) {
		EL(ha, "failed, ddi_copyin\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	if (!(fcf_list.BufSize)) {
		/* Return error */
		EL(ha, "failed, fcf_list BufSize is=%xh\n",
		    fcf_list.BufSize);
		cmd->Status = EXT_STATUS_INVALID_PARAM;
		cmd->ResponseLen = 0;
		return;
	}
	/* Allocate memory for command. */
	tmp_buf = kmem_zalloc(fcf_list.BufSize, KM_SLEEP);
	if (tmp_buf == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}
	/* build the descriptor */
	if (fcf_list.Options) {
		mb_fcf_list.options = FCF_LIST_RETURN_ONE;
	} else {
		mb_fcf_list.options = FCF_LIST_RETURN_ALL;
	}
	mb_fcf_list.fcf_index = (uint16_t)fcf_list.FcfIndex;
	mb_fcf_list.buffer_size = fcf_list.BufSize;

	/* Send command */
	rval = ql_get_fcf_list_mbx(ha, &mb_fcf_list, (caddr_t)tmp_buf);
	if (rval != QL_SUCCESS) {
		/* error */
		EL(ha, "failed, get_fcf_list_mbx=%xh\n", rval);
		kmem_free(tmp_buf, fcf_list.BufSize);
		cmd->Status = EXT_STATUS_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	/* Copy the response */
	if (ql_send_buffer_data((caddr_t)tmp_buf,
	    (caddr_t)(uintptr_t)cmd->ResponseAdr,
	    fcf_list.BufSize, mode) != fcf_list.BufSize) {
		EL(ha, "failed, ddi_copyout\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
	} else {
		cmd->ResponseLen = mb_fcf_list.buffer_size;
		QL_PRINT_9(ha, "done\n");
	}

	kmem_free(tmp_buf, fcf_list.BufSize);
}

/*
 * ql_get_resource_counts
 *	Get Resource counts:
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	User space CT arguments pointer.
 *	mode:	flags.
 */
static void
ql_get_resource_counts(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	int			rval;
	ql_mbx_data_t		mr;
	EXT_RESOURCE_CNTS	tmp_rc_cnt = {0};

	QL_PRINT_9(ha, "started\n");

	if (cmd->ResponseLen < sizeof (EXT_RESOURCE_CNTS)) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = sizeof (EXT_RESOURCE_CNTS);
		EL(ha, "failed, ResponseLen < EXT_RESOURCE_CNTS, "
		    "Len=%xh\n", cmd->ResponseLen);
		cmd->ResponseLen = 0;
		return;
	}

	rval = ql_get_resource_cnts(ha, &mr);
	if (rval != QL_SUCCESS) {
		EL(ha, "resource cnt mbx failed\n");
		cmd->Status = EXT_STATUS_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	tmp_rc_cnt.OrgTgtXchgCtrlCnt = (uint32_t)mr.mb[1];
	tmp_rc_cnt.CurTgtXchgCtrlCnt = (uint32_t)mr.mb[2];
	tmp_rc_cnt.CurXchgCtrlCnt = (uint32_t)mr.mb[3];
	tmp_rc_cnt.OrgXchgCtrlCnt = (uint32_t)mr.mb[6];
	tmp_rc_cnt.CurIocbBufCnt = (uint32_t)mr.mb[7];
	tmp_rc_cnt.OrgIocbBufCnt = (uint32_t)mr.mb[10];
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		tmp_rc_cnt.NoOfSupVPs = (uint32_t)mr.mb[11];
	}
	if (CFG_IST(ha, CFG_FCOE_SUPPORT)) {
		tmp_rc_cnt.NoOfSupFCFs = (uint32_t)mr.mb[12];
	}

	rval = ddi_copyout((void *)&tmp_rc_cnt,
	    (void *)(uintptr_t)(cmd->ResponseAdr),
	    sizeof (EXT_RESOURCE_CNTS), mode);
	if (rval != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, ddi_copyout\n");
	} else {
		cmd->ResponseLen = sizeof (EXT_RESOURCE_CNTS);
		QL_PRINT_9(ha, "done\n");
	}
}

/*
 * ql_get_temperature
 *	Get ASIC temperature data
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_get_temperature(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	ql_mbx_data_t	mr;
	int		rval = 0;
	EXT_BOARD_TEMP	board_temp = {0};

	QL_PRINT_9(ha, "started\n");

	if (!(ha->fw_ext_attributes & TEMP_SUPPORT_ISP)) {
		EL(ha, "invalid request for HBA\n");
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		cmd->ResponseLen = 0;
		return;
	}

	if (cmd->ResponseLen < sizeof (EXT_BOARD_TEMP)) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = sizeof (EXT_BOARD_TEMP);
		EL(ha, "failed, ResponseLen < EXT_BOARD_TEMP, "
		    "Len=%xh \n", cmd->ResponseLen);
		cmd->ResponseLen = 0;
		return;
	}

	switch (cmd->SubCode) {
	case EXT_SC_GET_BOARD_TEMP:
		rval = ql_get_temp(ha, &mr);
		if (rval != QL_SUCCESS) {
			/* error */
			EL(ha, "failed, get_temperature_mbx=%xh\n", rval);
			cmd->Status = EXT_STATUS_ERR;
			cmd->ResponseLen = 0;
			break;
		}
		board_temp.IntTemp = mr.mb[1];

		rval = ddi_copyout((void *)&board_temp,
		    (void *)(uintptr_t)(cmd->ResponseAdr),
		    sizeof (EXT_BOARD_TEMP), mode);
		if (rval != 0) {
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->ResponseLen = 0;
			EL(ha, "failed, ddi_copyout\n");
		} else {
			cmd->ResponseLen = sizeof (EXT_BOARD_TEMP);
		}
		break;
	default:
		EL(ha, "unknown subcode=%xh\n", cmd->SubCode);
		cmd->Status = EXT_STATUS_ERR;
		cmd->ResponseLen = 0;
		break;
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_dump_cmd
 *	Performs all EXT_CC_DUMP_OS functions.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_dump_cmd(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	caddr_t		dump;
	uint32_t	sdm_valid_dump = 0;
	int		rval = 0;

	QL_PRINT_9(ha, "started\n");

	if (ha->ql_dump_state & QL_DUMP_VALID &&
	    !(ha->ql_dump_state & QL_DUMP_UPLOADED) &&
	    ha->ql_dump_state != 0) {
		sdm_valid_dump = 1;
	} else {
		EL(ha, "dump does not exist for instance %d (%x, %p)\n",
		    ha->instance, ha->ql_dump_state, ha->ql_dump_ptr);
	}

	cmd->Status = EXT_STATUS_OK;
	cmd->DetailStatus = 0;

	switch (cmd->SubCode) {
	case EXT_SC_DUMP_SIZE:
		cmd->ResponseLen = 0;
		if (sdm_valid_dump) {
			cmd->DetailStatus = ha->risc_dump_size;
		}
		break;
	case EXT_SC_DUMP_READ:
		if (!sdm_valid_dump) {
			cmd->Status = EXT_STATUS_INVALID_REQUEST;
			cmd->ResponseLen = 0;
			break;
		}

		if (cmd->ResponseLen < ha->risc_dump_size) {
			cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
			cmd->DetailStatus = ha->risc_dump_size;
			EL(ha, "failed, ResponseLen < %x, "
			    "Len=%xh\n", ha->risc_dump_size,
			    cmd->ResponseLen);
			break;
		}

		ADAPTER_STATE_LOCK(ha);
		ha->flags |= DISABLE_NIC_FW_DMP;
		ADAPTER_STATE_UNLOCK(ha);

		QL_DUMP_LOCK(ha);

		dump = kmem_zalloc(ha->risc_dump_size, KM_SLEEP);
		cmd->ResponseLen = (uint32_t)ql_ascii_fw_dump(ha, dump);

		if ((rval = ddi_copyout((void *)dump,
		    (void *)(uintptr_t)(cmd->ResponseAdr), cmd->ResponseLen,
		    mode)) != 0) {
			ha->ql_dump_state &= ~QL_DUMP_UPLOADED;
			EL(ha, "failed, ddi_copyout\n");
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->ResponseLen = 0;
		} else {
			ha->ql_dump_state |= QL_DUMP_UPLOADED;
		}

		kmem_free(dump, ha->risc_dump_size);

		QL_DUMP_UNLOCK(ha);

		ADAPTER_STATE_LOCK(ha);
		ha->flags &= ~DISABLE_NIC_FW_DMP;
		ADAPTER_STATE_UNLOCK(ha);
		break;
	case EXT_SC_DUMP_TRIGGER:
		cmd->ResponseLen = 0;

		ADAPTER_STATE_LOCK(ha);
		ha->flags |= DISABLE_NIC_FW_DMP;
		ADAPTER_STATE_UNLOCK(ha);

		if (sdm_valid_dump) {
			cmd->Status = EXT_STATUS_INVALID_REQUEST;
			EL(ha, "Existing dump file needs to be retrieved.\n");
		} else {
			rval = ql_dump_firmware(ha);

			if (rval != QL_SUCCESS && rval != QL_DATA_EXISTS) {
				cmd->Status = EXT_STATUS_ERR;
			}
		}

		ADAPTER_STATE_LOCK(ha);
		ha->flags &= ~DISABLE_NIC_FW_DMP;
		ADAPTER_STATE_UNLOCK(ha);
		break;
	default:
		EL(ha, "unknown subcode=%xh\n", cmd->SubCode);
		cmd->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		cmd->ResponseLen = 0;
		break;
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_serdes_reg
 *	Performs all EXT_CC_SERDES_REG_OP functions.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_serdes_reg(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	ql_mbx_data_t	mr = {0};
	int		rval = 0;
	EXT_SERDES_REG	serdes_reg = {0};

	QL_PRINT_9(ha, "started\n");

	/* Check if request valid for HBA */
	if (!(CFG_IST(ha, CFG_SERDES_SUPPORT))) {
		EL(ha, "invalid request for HBA\n");
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		cmd->ResponseLen = 0;
		return;
	}

	/* Copy in the request structure. */
	if (ddi_copyin((void *)(uintptr_t)cmd->RequestAdr,
	    (void *)&serdes_reg, sizeof (EXT_SERDES_REG), mode) != 0) {
		EL(ha, "failed, ddi_copyin\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	switch (cmd->SubCode) {
	case EXT_SC_WRITE_SERDES_REG:
		mr.mb[1] = serdes_reg.addr;
		mr.mb[2] = LSB(serdes_reg.val);
		mr.mb[3] = 0;
		mr.mb[4] = MSB(serdes_reg.val);
		if ((rval = ql_write_serdes(ha, &mr)) != QL_SUCCESS) {
			/* error */
			EL(ha, "failed, write_serdes_mbx=%xh\n", rval);
			cmd->Status = EXT_STATUS_ERR;
			cmd->ResponseLen = 0;
			break;
		} else {
			cmd->Status = EXT_STATUS_OK;
		}
		break;
	case EXT_SC_READ_SERDES_REG:
		/* Verify the size of response structure. */
		if (cmd->ResponseLen < sizeof (EXT_SERDES_REG)) {
			cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
			cmd->DetailStatus = sizeof (EXT_SERDES_REG);
			EL(ha, "failed, ResponseLen < EXT_SERDES_REG, "
			    "Len=%xh \n", cmd->ResponseLen);
			cmd->ResponseLen = 0;
			break;
		}
		mr.mb[1] = serdes_reg.addr;
		if ((rval = ql_read_serdes(ha, &mr)) != QL_SUCCESS) {
			/* error */
			EL(ha, "failed, read_serdes_mbx=%xh\n", rval);
			cmd->Status = EXT_STATUS_ERR;
			cmd->ResponseLen = 0;
			break;
		}
		serdes_reg.val = CHAR_TO_SHORT(LSB(mr.mb[1]), LSB(mr.mb[2]));
		/* Copy back the response data */
		if (ddi_copyout((void *)&serdes_reg,
		    (void *)(uintptr_t)(cmd->ResponseAdr),
		    sizeof (EXT_SERDES_REG), mode) != 0) {
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->ResponseLen = 0;
			EL(ha, "failed, ddi_copyout\n");
		} else {
			cmd->Status = EXT_STATUS_OK;
			cmd->ResponseLen = sizeof (EXT_SERDES_REG);
		}
		break;
	default:
		/* Subcode not supported. */
		EL(ha, "unknown subcode=%xh\n", cmd->SubCode);
		cmd->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		cmd->ResponseLen = 0;
		break;
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_serdes_reg_ex
 *	Performs all EXT_CC_SERDES_REG_OP_EX functions.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	EXT_IOCTL cmd struct pointer.
 *	mode:	flags
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_serdes_reg_ex(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	ql_mbx_data_t		mr = {0};
	int			rval = 0;
	EXT_SERDES_REG_EX	serdes_reg_ex = {0};

	QL_PRINT_9(ha, "started\n");

	/* Check if request valid for HBA */
	if (!(CFG_IST(ha, CFG_SERDES_SUPPORT))) {
		EL(ha, "invalid request for HBA\n");
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		cmd->ResponseLen = 0;
		return;
	}

	/* Copy in the request structure. */
	if (ddi_copyin((void *)(uintptr_t)cmd->RequestAdr,
	    (void *)&serdes_reg_ex, sizeof (EXT_SERDES_REG_EX), mode) != 0) {
		EL(ha, "failed, ddi_copyin\n");
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	switch (cmd->SubCode) {
	case EXT_SC_WRITE_SERDES_REG:
		mr.mb[3] = LSW(serdes_reg_ex.addr);
		mr.mb[4] = MSW(serdes_reg_ex.addr);
		mr.mb[5] = LSW(serdes_reg_ex.val);
		mr.mb[6] = MSW(serdes_reg_ex.val);
		if ((rval = ql_write_serdes(ha, &mr)) != QL_SUCCESS) {
			/* error */
			EL(ha, "failed, write_serdes_mbx=%xh\n", rval);
			cmd->Status = EXT_STATUS_ERR;
			cmd->ResponseLen = 0;
			break;
		} else {
			cmd->Status = EXT_STATUS_OK;
		}
		break;
	case EXT_SC_READ_SERDES_REG:
		/* Verify the size of response structure. */
		if (cmd->ResponseLen < sizeof (EXT_SERDES_REG_EX)) {
			cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
			cmd->DetailStatus = sizeof (EXT_SERDES_REG_EX);
			EL(ha, "failed, ResponseLen < EXT_SERDES_REG_EX, "
			    "Len=%xh\n", cmd->ResponseLen);
			cmd->ResponseLen = 0;
			break;
		}
		mr.mb[3] = LSW(serdes_reg_ex.addr);
		mr.mb[4] = MSW(serdes_reg_ex.addr);
		if ((rval = ql_read_serdes(ha, &mr)) != QL_SUCCESS) {
			/* error */
			EL(ha, "failed, read_serdes_mbx=%xh\n", rval);
			cmd->Status = EXT_STATUS_ERR;
			cmd->ResponseLen = 0;
			break;
		}
		serdes_reg_ex.val = SHORT_TO_LONG(mr.mb[1], mr.mb[2]);
		/* Copy back the response data */
		if (ddi_copyout((void *)&serdes_reg_ex,
		    (void *)(uintptr_t)(cmd->ResponseAdr),
		    sizeof (EXT_SERDES_REG_EX), mode) != 0) {
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->ResponseLen = 0;
			EL(ha, "failed, ddi_copyout\n");
		} else {
			cmd->Status = EXT_STATUS_OK;
			cmd->ResponseLen = sizeof (EXT_SERDES_REG_EX);
		}
		break;
	default:
		/* Subcode not supported. */
		EL(ha, "unknown subcode=%xh\n", cmd->SubCode);
		cmd->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		cmd->ResponseLen = 0;
		break;
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_els_passthru
 *	IOCTL for extended link service passthru command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	User space CT arguments pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_els_passthru(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	ql_mbx_iocb_t		*pkt;
	dma_mem_t		*dma_mem;
	caddr_t			bp, pld;
	uint32_t		pkt_size, pld_byte_cnt, cmd_size, *long_ptr;
	EXT_ELS_PT_REQ		*pt_req;
	boolean_t		local_hba = B_FALSE;
	ql_tgt_t		*tq = NULL;
	port_id_t		tmp_fcid;
	int			rval;
	uint16_t		comp_status;

	QL_PRINT_9(ha, "started\n");

	if (DRIVER_SUSPENDED(ha)) {
		EL(ha, "failed, LOOP_NOT_READY\n");
		cmd->Status = EXT_STATUS_BUSY;
		cmd->ResponseLen = 0;
		return;
	}

	if (cmd->RequestLen < sizeof (EXT_ELS_PT_REQ)) {
		/* parameter error */
		EL(ha, "failed, RequestLen < EXT_ELS_PT_REQ, Len=%xh\n",
		    cmd->RequestLen);
		cmd->Status = EXT_STATUS_INVALID_PARAM;
		cmd->DetailStatus = EXT_DSTATUS_REQUEST_LEN;
		cmd->ResponseLen = 0;
		return;
	}

	/* Allocate memory for command. */
	bp = kmem_zalloc(cmd->RequestLen, KM_SLEEP);

	if (ddi_copyin((void*)(uintptr_t)cmd->RequestAdr,
	    bp, cmd->RequestLen, mode) != 0) {
		EL(ha, "failed, ddi_copyin\n");
		kmem_free(bp, cmd->RequestLen);
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		return;
	}
	pt_req = (EXT_ELS_PT_REQ *)bp;

	QL_PRINT_9(ha, "EXT_ELS_PT_REQ\n");
	QL_DUMP_9((uint8_t *)pt_req, 8, sizeof (EXT_ELS_PT_REQ));

	/* Find loop ID of the device */
	if (pt_req->ValidMask & EXT_DEF_WWPN_VALID) {
		if (bcmp(ha->loginparams.nport_ww_name.raw_wwn, pt_req->WWPN,
		    EXT_DEF_WWN_NAME_SIZE) == 0) {
			local_hba = B_TRUE;
		} else {
			tq = ql_find_port(ha, pt_req->WWPN, QLNT_PORT);
		}
	} else if (pt_req->ValidMask & EXT_DEF_PID_VALID) {
		/*
		 * Copy caller's d_id to tmp space.
		 */
		bcopy(&pt_req->Id[1], tmp_fcid.r.d_id,
		    EXT_DEF_PORTID_SIZE_ACTUAL);
		BIG_ENDIAN_24(&tmp_fcid.r.d_id[0]);

		if (bcmp((void *)&ha->d_id, (void *)tmp_fcid.r.d_id,
		    EXT_DEF_PORTID_SIZE_ACTUAL) == 0) {
			local_hba = B_TRUE;
		} else {
			tq = ql_find_port(ha, (uint8_t *)tmp_fcid.r.d_id,
			    QLNT_PID);
		}
	} else if (pt_req->ValidMask & EXT_DEF_WWNN_VALID) {
		if (bcmp(ha->loginparams.node_ww_name.raw_wwn, pt_req->WWNN,
		    EXT_DEF_WWN_NAME_SIZE) == 0) {
			local_hba = B_TRUE;
		} else {
			tq = ql_find_port(ha, pt_req->WWNN, QLNT_NODE);
		}
	}

	if (local_hba == B_TRUE) {
		EL(ha, "failed, els to adapter\n");
		kmem_free(bp, cmd->RequestLen);
		cmd->Status = EXT_STATUS_ERR;
		cmd->ResponseLen = 0;
		return;
	}

	if (tq == NULL) {
		/* no matching device */
		EL(ha, "failed, device not found\n");
		kmem_free(bp, cmd->RequestLen);
		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		cmd->DetailStatus = EXT_DSTATUS_TARGET;
		cmd->ResponseLen = 0;
		return;
	}

	/* Allocate a DMA Memory Descriptor */
	dma_mem = (dma_mem_t *)kmem_zalloc(sizeof (dma_mem_t), KM_SLEEP);
	if (dma_mem == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		kmem_free(bp, cmd->RequestLen);
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}
	/* Determine maximum buffer size. */
	cmd_size = cmd->RequestLen - sizeof (EXT_ELS_PT_REQ);
	pld_byte_cnt = cmd_size < cmd->ResponseLen ? cmd->ResponseLen :
	    cmd_size;
	pld = (caddr_t)(bp + sizeof (EXT_ELS_PT_REQ));

	/* Allocate command block. */
	pkt_size = (uint32_t)(sizeof (ql_mbx_iocb_t));
	pkt = kmem_zalloc(pkt_size, KM_SLEEP);
	if (pkt == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		kmem_free(dma_mem, sizeof (dma_mem_t));
		kmem_free(bp, cmd->RequestLen);
		cmd->Status = EXT_STATUS_NO_MEMORY;
		cmd->ResponseLen = 0;
		return;
	}

	/* Get DMA memory for the payload */
	if (ql_get_dma_mem(ha, dma_mem, pld_byte_cnt, LITTLE_ENDIAN_DMA,
	    QL_DMA_RING_ALIGN) != QL_SUCCESS) {
		cmn_err(CE_WARN, "%sDMA memory alloc failed", QL_NAME);
		kmem_free(pkt, pkt_size);
		kmem_free(dma_mem, sizeof (dma_mem_t));
		kmem_free(bp, cmd->RequestLen);
		cmd->Status = EXT_STATUS_MS_NO_RESPONSE;
		cmd->ResponseLen = 0;
		return;
	}

	/* Copy out going payload data to IOCB DMA buffer. */
	ddi_rep_put8(dma_mem->acc_handle, (uint8_t *)pld,
	    (uint8_t *)dma_mem->bp, cmd_size, DDI_DEV_AUTOINCR);

	/* Sync IOCB DMA buffer. */
	(void) ddi_dma_sync(dma_mem->dma_handle, 0, cmd_size,
	    DDI_DMA_SYNC_FORDEV);

	/*
	 * Setup IOCB
	 */
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		pkt->els.entry_type = ELS_PASSTHRU_TYPE;
		pkt->els.entry_count = 1;

		/* Set loop ID */
		pkt->els.n_port_hdl = tq->loop_id;

		/* Set cmd/response data segment counts. */
		pkt->els.xmt_dseg_count = LE_16(1);
		pkt->els.vp_index = ha->vp_index;
		pkt->els.rcv_dseg_count = LE_16(1);

		pkt->els.els_cmd_opcode = pld[0];

		pkt->els.d_id_7_0 = tq->d_id.b.al_pa;
		pkt->els.d_id_15_8 = tq->d_id.b.area;
		pkt->els.d_id_23_16 = tq->d_id.b.domain;

		pkt->els.s_id_7_0 = ha->d_id.b.al_pa;
		pkt->els.s_id_15_8 = ha->d_id.b.area;
		pkt->els.s_id_23_16 = ha->d_id.b.domain;

		/* Load rsp byte count. */
		pkt->els.rcv_payld_data_bcnt = LE_32(cmd->ResponseLen);

		/* Load cmd byte count. */
		pkt->els.xmt_payld_data_bcnt = LE_32(cmd_size);

		long_ptr = (uint32_t *)&pkt->els.dseg;

		/* Load MS command entry data segments. */
		*long_ptr++ = (uint32_t)
		    LE_32(LSD(dma_mem->cookie.dmac_laddress));
		*long_ptr++ = (uint32_t)
		    LE_32(MSD(dma_mem->cookie.dmac_laddress));
		*long_ptr++ = LE_32(cmd_size);

		/* Load MS response entry data segments. */
		*long_ptr++ = (uint32_t)
		    LE_32(LSD(dma_mem->cookie.dmac_laddress));
		*long_ptr++ = (uint32_t)
		    LE_32(MSD(dma_mem->cookie.dmac_laddress));
		*long_ptr = LE_32(cmd->ResponseLen);

		rval = ql_issue_mbx_iocb(ha, (caddr_t)pkt,
		    sizeof (ql_mbx_iocb_t));

		comp_status = (uint16_t)LE_16(pkt->sts24.comp_status);
		if (rval == QL_SUCCESS && comp_status == CS_DATA_UNDERRUN) {
			comp_status = CS_COMPLETE;
		}
		if (rval != QL_SUCCESS ||
		    (pkt->sts24.entry_status & 0x3c) != 0 ||
		    comp_status != CS_COMPLETE) {
			EL(ha, "failed, I/O timeout, cs=%xh, es=%xh, "
			    "rval=%xh\n",
			    comp_status, pkt->sts24.entry_status, rval);
			ql_free_dma_resource(ha, dma_mem);
			kmem_free(pkt, pkt_size);
			kmem_free(dma_mem, sizeof (dma_mem_t));
			kmem_free(bp, cmd->RequestLen);
			cmd->Status = EXT_STATUS_ERR;
			cmd->ResponseLen = 0;
			return;
		}
	} else {
		pkt->ms.entry_type = MS_TYPE;
		pkt->ms.entry_count = 1;

		/* Set loop ID */
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			pkt->ms.loop_id_l = LSB(tq->loop_id);
			pkt->ms.loop_id_h = MSB(tq->loop_id);
		} else {
			pkt->ms.loop_id_h = LSB(tq->loop_id);
		}

		pkt->ms.control_flags_h = CF_ELS_PASSTHROUGH;

		/* Set ISP command timeout. */
		pkt->ms.timeout = LE_16(120);

		/* Set data segment counts. */
		pkt->ms.cmd_dseg_count_l = 1;
		pkt->ms.total_dseg_count = LE_16(2);

		/* Response total byte count. */
		pkt->ms.resp_byte_count = LE_32(cmd->ResponseLen);
		pkt->ms.dseg[1].length = LE_32(cmd->ResponseLen);

		/* Command total byte count. */
		pkt->ms.cmd_byte_count = LE_32(cmd_size);
		pkt->ms.dseg[0].length = LE_32(cmd_size);

		/* Load command/response data segments. */
		pkt->ms.dseg[0].address[0] = (uint32_t)
		    LE_32(LSD(dma_mem->cookie.dmac_laddress));
		pkt->ms.dseg[0].address[1] = (uint32_t)
		    LE_32(MSD(dma_mem->cookie.dmac_laddress));
		pkt->ms.dseg[1].address[0] = (uint32_t)
		    LE_32(LSD(dma_mem->cookie.dmac_laddress));
		pkt->ms.dseg[1].address[1] = (uint32_t)
		    LE_32(MSD(dma_mem->cookie.dmac_laddress));

		rval = ql_issue_mbx_iocb(ha, (caddr_t)pkt,
		    sizeof (ql_mbx_iocb_t));

		comp_status = (uint16_t)LE_16(pkt->sts.comp_status);
		if (rval == QL_SUCCESS && comp_status == CS_DATA_UNDERRUN) {
			comp_status = CS_COMPLETE;
		}
		if (rval != QL_SUCCESS ||
		    (pkt->sts.entry_status & 0x7e) != 0 ||
		    comp_status != CS_COMPLETE) {
			EL(ha, "failed, I/O timeout, cs=%xh, es=%xh, "
			    "rval=%xh\n",
			    comp_status, pkt->sts.entry_status, rval);
			ql_free_dma_resource(ha, dma_mem);
			kmem_free(pkt, pkt_size);
			kmem_free(dma_mem, sizeof (dma_mem_t));
			kmem_free(bp, cmd->RequestLen);
			cmd->Status = EXT_STATUS_ERR;
			cmd->ResponseLen = 0;
			return;
		}
	}

	/* Sync payload DMA buffer. */
	(void) ddi_dma_sync(dma_mem->dma_handle, 0, cmd->ResponseLen,
	    DDI_DMA_SYNC_FORKERNEL);

	if (ql_send_buffer_data(dma_mem->bp,
	    (caddr_t)(uintptr_t)cmd->ResponseAdr,
	    cmd->ResponseLen, mode) != cmd->ResponseLen) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		EL(ha, "failed, ddi_copyout\n");
	} else {
		QL_PRINT_9(ha, "els_rsp\n");
		QL_DUMP_9(pld, 8, cmd->ResponseLen);
		cmd->Status = EXT_STATUS_OK;
		QL_PRINT_9(ha, "done\n");
	}

	ql_free_dma_resource(ha, dma_mem);
	kmem_free(pkt, pkt_size);
	kmem_free(dma_mem, sizeof (dma_mem_t));
	kmem_free(bp, cmd->RequestLen);
}

/*
 * ql_flash_update_caps
 *	IOCTL for flash update capabilities command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	User space CT arguments pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_flash_update_caps(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	int			rval;
	uint64_t		cb;
	EXT_FLASH_UPDATE_CAPS	caps = {0};

	QL_PRINT_9(ha, "started\n");

	cb = LONG_TO_LLONG(ha->fw_attributes, ha->fw_ext_attributes);

	switch (cmd->SubCode) {
	case EXT_SC_GET_FLASH_UPDATE_CAPS:
		if (cmd->ResponseLen < sizeof (EXT_FLASH_UPDATE_CAPS)) {
			cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
			cmd->DetailStatus = sizeof (EXT_FLASH_UPDATE_CAPS);
			EL(ha, "failed, ResponseLen < 0x%x, Len=0x%x\n",
			    sizeof (EXT_FLASH_UPDATE_CAPS), cmd->ResponseLen);
			cmd->ResponseLen = 0;
			return;
		}
		caps.Capabilities = cb;
		caps.OutageDuration = 300;	/* seconds */

		rval = ddi_copyout((void *)&caps,
		    (void *)(uintptr_t)(cmd->ResponseAdr),
		    sizeof (EXT_FLASH_UPDATE_CAPS), mode);
		if (rval != 0) {
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->ResponseLen = 0;
			EL(ha, "failed, ddi_copyout\n");
		} else {
			cmd->ResponseLen = sizeof (EXT_FLASH_UPDATE_CAPS);
		}
		break;
	case EXT_SC_SET_FLASH_UPDATE_CAPS:
		if (cmd->RequestLen < sizeof (EXT_FLASH_UPDATE_CAPS)) {
			/* parameter error */
			EL(ha, "failed, RequestLen < EXT_FLASH_UPDATE_CAPS, "
			    "Len=%xh\n", cmd->RequestLen);
			cmd->Status = EXT_STATUS_INVALID_PARAM;
			cmd->DetailStatus = EXT_DSTATUS_REQUEST_LEN;
			cmd->ResponseLen = 0;
			return;
		}

		/* Copy in the request structure. */
		if (ddi_copyin((void *)(uintptr_t)cmd->RequestAdr,
		    (void *)&caps, sizeof (EXT_FLASH_UPDATE_CAPS), mode) != 0) {
			EL(ha, "failed, ddi_copyin\n");
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->ResponseLen = 0;
			return;
		}

		if (cb != caps.Capabilities || caps.OutageDuration < 300) {
			cmd->Status = EXT_STATUS_ERR;
			cmd->ResponseLen = 0;
		}
		break;
	default:
		/* Subcode not supported. */
		EL(ha, "unknown subcode=%xh\n", cmd->SubCode);
		cmd->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		cmd->ResponseLen = 0;
		break;
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_get_bbcr_data
 *	IOCTL for get buffer to buffer credits command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	User space CT arguments pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_get_bbcr_data(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	int		rval;
	ql_mbx_data_t	mr;
	EXT_BBCR_DATA	bb = {0};

	QL_PRINT_9(ha, "started\n");

	if (cmd->ResponseLen < sizeof (EXT_BBCR_DATA)) {
		cmd->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		cmd->DetailStatus = sizeof (EXT_BBCR_DATA);
		EL(ha, "failed, ResponseLen < 0x%x, Len=0x%x\n",
		    sizeof (EXT_BBCR_DATA), cmd->ResponseLen);
		cmd->ResponseLen = 0;
		return;
	}

	if (!(CFG_IST(ha, CFG_BBCR_SUPPORT))) {
		EL(ha, "invalid request for HBA\n");
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		cmd->ResponseLen = 0;
		return;
	}
	if (ha->task_daemon_flags & LOOP_DOWN) {
		rval = ql_get_adapter_id(ha, &mr);
		ha->bbcr_initial = LSB(mr.mb[15]);
		ha->bbcr_runtime = MSB(mr.mb[15]);
		bb.ConfiguredBBSCN = ha->bbcr_initial & BBCR_INITIAL_MASK;
		bb.NegotiatedBBSCN = ha->bbcr_runtime & BBCR_RUNTIME_MASK;
		bb.Status = EXT_DEF_BBCR_STATUS_UNKNOWN;
		bb.State = EXT_DEF_BBCR_STATE_OFFLINE;
		if (rval == 0x4005) {
			bb.mbx1 = mr.mb[1];
		}
	} else {
		bb.ConfiguredBBSCN = ha->bbcr_initial & BBCR_INITIAL_MASK;
		bb.NegotiatedBBSCN = ha->bbcr_runtime & BBCR_RUNTIME_MASK;

		if (bb.ConfiguredBBSCN) {
			bb.Status = EXT_DEF_BBCR_STATUS_ENABLED;
			if (bb.NegotiatedBBSCN &&
			    !(ha->bbcr_runtime & BBCR_RUNTIME_REJECT)) {
				bb.State = EXT_DEF_BBCR_STATE_ONLINE;
			} else {
				bb.State = EXT_DEF_BBCR_STATE_OFFLINE;
				if (ha->bbcr_runtime & BBCR_RUNTIME_REJECT) {
					bb.OfflineReasonCode =
					    EXT_DEF_BBCR_REASON_LOGIN_REJECT;
				} else {
					bb.OfflineReasonCode =
					    EXT_DEF_BBCR_REASON_SWITCH;
				}
			}
		} else {
			bb.Status = EXT_DEF_BBCR_STATUS_DISABLED;
		}
	}

	rval = ddi_copyout((void *)&bb, (void *)(uintptr_t)(cmd->ResponseAdr),
	    sizeof (EXT_BBCR_DATA), mode);
	if (rval != 0) {
		cmd->Status = EXT_STATUS_COPY_ERR;
		cmd->ResponseLen = 0;
		EL(ha, "failed, ddi_copyout\n");
	} else {
		cmd->ResponseLen = sizeof (EXT_BBCR_DATA);
	}

	QL_PRINT_9(ha, "done\n");
}

/*
 * ql_get_priv_stats
 *	Performs EXT_SC_GET_PRIV_STATS subcommand. of EXT_CC_GET_DATA.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	Local EXT_IOCTL cmd struct pointer.
 *	mode:	flags.
 *
 * Returns:
 *	None, request status indicated in cmd->Status.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_get_priv_stats(ql_adapter_state_t *ha, EXT_IOCTL *cmd, int mode)
{
	uint8_t	*ls;
	int	rval;
	int	retry = 10;

	QL_PRINT_9(ha, "started\n");

	while (ha->task_daemon_flags & (DRIVER_STALL | ABORT_ISP_ACTIVE |
	    LOOP_RESYNC_ACTIVE)) {
		ql_delay(ha, 10000000);	/* 10 second delay */

		retry--;

		if (retry == 0) { /* effectively 100 seconds */
			EL(ha, "failed, LOOP_NOT_READY\n");
			cmd->Status = EXT_STATUS_BUSY;
			cmd->ResponseLen = 0;
			return;
		}
	}

	/* Allocate memory for command. */
	ls = kmem_zalloc(cmd->ResponseLen, KM_SLEEP);

	/*
	 * I think these are supposed to be port statistics
	 * the loop ID or port ID should be in cmd->Instance.
	 */
	rval = ql_get_status_counts(ha,
	    ha->task_daemon_flags & LOOP_DOWN ? 0xFF : ha->loop_id,
	    cmd->ResponseLen, (caddr_t)ls, 0);
	if (rval != QL_SUCCESS) {
		EL(ha, "failed, get_link_status=%xh, id=%xh\n", rval,
		    ha->loop_id);
		cmd->Status = EXT_STATUS_MAILBOX;
		cmd->DetailStatus = rval;
		cmd->ResponseLen = 0;
	} else {
		rval = ddi_copyout((void *)&ls,
		    (void *)(uintptr_t)cmd->ResponseAdr, cmd->ResponseLen,
		    mode);
		if (rval != 0) {
			EL(ha, "failed, ddi_copyout\n");
			cmd->Status = EXT_STATUS_COPY_ERR;
			cmd->ResponseLen = 0;
		}
	}

	kmem_free(ls, cmd->ResponseLen);

	QL_PRINT_9(ha, "done\n");
}
