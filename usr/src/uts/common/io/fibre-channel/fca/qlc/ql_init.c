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
#include <ql_isr.h>
#include <ql_mbx.h>
#include <ql_nx.h>
#include <ql_xioctl.h>

/*
 * Local data
 */

/*
 * Local prototypes
 */
static uint16_t ql_nvram_request(ql_adapter_state_t *, uint32_t);
static int ql_nvram_24xx_config(ql_adapter_state_t *);
static void ql_23_properties(ql_adapter_state_t *, ql_init_cb_t *);
static void ql_24xx_properties(ql_adapter_state_t *, ql_init_24xx_cb_t *);
static int ql_check_isp_firmware(ql_adapter_state_t *);
static int ql_load_flash_fw(ql_adapter_state_t *);
static int ql_configure_loop(ql_adapter_state_t *);
static int ql_configure_hba(ql_adapter_state_t *);
static int ql_configure_fabric(ql_adapter_state_t *);
static int ql_configure_device_d_id(ql_adapter_state_t *);
static void ql_update_dev(ql_adapter_state_t *, uint32_t);
static void ql_set_max_read_req(ql_adapter_state_t *);
static void ql_configure_n_port_info(ql_adapter_state_t *);
static void ql_reset_24xx_chip(ql_adapter_state_t *);
static void ql_mps_reset(ql_adapter_state_t *);

/*
 * ql_initialize_adapter
 *	Initialize board.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_initialize_adapter(ql_adapter_state_t *ha)
{
	int			rval;
	class_svc_param_t	*class3_param;
	caddr_t			msg;
	la_els_logi_t		*els = &ha->loginparams;
	int			retries = 5;

	QL_PRINT_10(ha, "started cfg=0x%llx\n", ha->cfg_flags);

	do {
		/* Clear adapter flags. */
		TASK_DAEMON_LOCK(ha);
		ha->task_daemon_flags &= TASK_DAEMON_STOP_FLG |
		    TASK_DAEMON_SLEEPING_FLG | TASK_DAEMON_ALIVE_FLG |
		    TASK_DAEMON_IDLE_CHK_FLG;
		ha->task_daemon_flags |= LOOP_DOWN;
		TASK_DAEMON_UNLOCK(ha);

		ha->loop_down_timer = LOOP_DOWN_TIMER_OFF;
		ADAPTER_STATE_LOCK(ha);
		ha->flags |= ABORT_CMDS_LOOP_DOWN_TMO;
		ha->flags &= ~ONLINE;
		ADAPTER_STATE_UNLOCK(ha);

		ha->state = FC_STATE_OFFLINE;
		msg = "Loop OFFLINE";

		rval = ql_pci_sbus_config(ha);
		if (rval != QL_SUCCESS) {
			TASK_DAEMON_LOCK(ha);
			if (!(ha->task_daemon_flags & ABORT_ISP_ACTIVE)) {
				EL(ha, "ql_pci_sbus_cfg, isp_abort_needed\n");
				ha->task_daemon_flags |= ISP_ABORT_NEEDED;
			}
			TASK_DAEMON_UNLOCK(ha);
			continue;
		}

		(void) ql_setup_fcache(ha);

		/* Reset ISP chip. */
		ql_reset_chip(ha);

		/* Get NVRAM configuration if needed. */
		if (ha->init_ctrl_blk.cb.version == 0) {
			(void) ql_nvram_config(ha);
		}

		/* Determine which RISC code to use. */
		if ((rval = ql_check_isp_firmware(ha)) != QL_SUCCESS) {
			if (ha->dev_state != NX_DEV_READY) {
				EL(ha, "dev_state not ready, isp_abort_needed_2"
				    "\n");
				TASK_DAEMON_LOCK(ha);
				ha->task_daemon_flags |= ISP_ABORT_NEEDED;
				TASK_DAEMON_UNLOCK(ha);
				break;
			}
			if ((rval = ql_mbx_wrap_test(ha, NULL)) == QL_SUCCESS) {
				rval = ql_load_isp_firmware(ha);
			}
		}

		if (rval == QL_SUCCESS && (rval = ql_set_cache_line(ha)) ==
		    QL_SUCCESS && (rval = ql_init_rings(ha)) == QL_SUCCESS) {

			ql_enable_intr(ha);
			(void) ql_fw_ready(ha, ha->fwwait);

			if (!DRIVER_SUSPENDED(ha) &&
			    ha->loop_down_timer == LOOP_DOWN_TIMER_OFF) {
				if (ha->topology & QL_LOOP_CONNECTION) {
					ha->state = ha->state | FC_STATE_LOOP;
					msg = "Loop ONLINE";
					TASK_DAEMON_LOCK(ha);
					ha->task_daemon_flags |= STATE_ONLINE;
					TASK_DAEMON_UNLOCK(ha);
				} else if (ha->topology & QL_P2P_CONNECTION) {
					ha->state = ha->state |
					    FC_STATE_ONLINE;
					msg = "Link ONLINE";
					TASK_DAEMON_LOCK(ha);
					ha->task_daemon_flags |= STATE_ONLINE;
					TASK_DAEMON_UNLOCK(ha);
				} else {
					msg = "Unknown Link state";
				}
			}
		} else {
			TASK_DAEMON_LOCK(ha);
			if (!(ha->task_daemon_flags & ABORT_ISP_ACTIVE)) {
				EL(ha, "failed, isp_abort_needed\n");
				ha->task_daemon_flags |= ISP_ABORT_NEEDED |
				    LOOP_DOWN;
			}
			TASK_DAEMON_UNLOCK(ha);
		}

	} while (retries-- != 0 && ha->task_daemon_flags & ISP_ABORT_NEEDED);

	cmn_err(CE_NOTE, "!Qlogic %s(%d): %s", QL_NAME, ha->instance, msg);

	/* Enable ISP interrupts if not already enabled. */
	if (!(ha->flags & INTERRUPTS_ENABLED)) {
		ql_enable_intr(ha);
	}

	ADAPTER_STATE_LOCK(ha);
	ha->flags |= ONLINE;
	ADAPTER_STATE_UNLOCK(ha);

	/*
	 * Set flash write-protection.
	 */
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2) &&
	    ha->dev_state == NX_DEV_READY) {
		ql_24xx_protect_flash(ha);
	}

	TASK_DAEMON_LOCK(ha);
	ha->task_daemon_flags &= ~(FC_STATE_CHANGE | MARKER_NEEDED |
	    COMMAND_WAIT_NEEDED);
	TASK_DAEMON_UNLOCK(ha);

	/*
	 * Setup login parameters.
	 */
	bcopy(QL_VERSION, ha->adapter_stats->revlvl.qlddv, strlen(QL_VERSION));

	els->common_service.fcph_version = 0x2006;
	els->common_service.btob_credit = 3;
	els->common_service.cmn_features =
	    ha->topology & QL_N_PORT ? 0x8000 : 0x8800;
	els->common_service.conc_sequences = 0xff;
	els->common_service.relative_offset = 3;
	els->common_service.e_d_tov = 0x07d0;

	class3_param = (class_svc_param_t *)&els->class_3;
	class3_param->class_valid_svc_opt = 0x8800;
	class3_param->rcv_data_size = els->common_service.rx_bufsize;
	class3_param->conc_sequences = 0xff;
	class3_param->open_sequences_per_exch = 1;

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_10(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_pci_sbus_config
 *	Setup device PCI/SBUS configuration registers.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_pci_sbus_config(ql_adapter_state_t *ha)
{
	uint32_t	timer;
	uint16_t	cmd, w16;

	QL_PRINT_10(ha, "started\n");

	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		w16 = (uint16_t)ddi_get16(ha->sbus_fpga_dev_handle,
		    (uint16_t *)(ha->sbus_fpga_iobase + FPGA_REVISION));
		EL(ha, "FPGA rev is %d.%d", (w16 & 0xf0) >> 4,
		    w16 & 0xf);
	} else {
		/*
		 * we want to respect framework's setting of PCI
		 * configuration space command register and also
		 * want to make sure that all bits of interest to us
		 * are properly set in command register.
		 */
		cmd = (uint16_t)ql_pci_config_get16(ha, PCI_CONF_COMM);
		cmd = (uint16_t)(cmd | PCI_COMM_IO | PCI_COMM_MAE |
		    PCI_COMM_ME | PCI_COMM_PARITY_DETECT |
		    PCI_COMM_SERR_ENABLE);
		if (ql_get_cap_ofst(ha, PCI_CAP_ID_PCIX)) {
			cmd = (uint16_t)(cmd | PCI_COMM_MEMWR_INVAL);
		}

		/*
		 * If this is a 2300 card and not 2312, reset the
		 * MEMWR_INVAL due to a bug in the 2300. Unfortunately, the
		 * 2310 also reports itself as a 2300 so we need to get the
		 * fb revision level -- a 6 indicates it really is a 2300 and
		 * not a 2310.
		 */

		if (ha->device_id == 0x2300) {
			/* Pause RISC. */
			WRT16_IO_REG(ha, hccr, HC_PAUSE_RISC);
			for (timer = 0; timer < 30000; timer++) {
				if ((RD16_IO_REG(ha, hccr) & HC_RISC_PAUSE) !=
				    0) {
					break;
				} else {
					drv_usecwait(MILLISEC);
				}
			}

			/* Select FPM registers. */
			WRT16_IO_REG(ha, ctrl_status, 0x20);

			/* Get the fb rev level */
			if (RD16_IO_REG(ha, fb_cmd) == 6) {
				cmd = (uint16_t)(cmd & ~PCI_COMM_MEMWR_INVAL);
			}

			/* Deselect FPM registers. */
			WRT16_IO_REG(ha, ctrl_status, 0x0);

			/* Release RISC module. */
			WRT16_IO_REG(ha, hccr, HC_RELEASE_RISC);
			for (timer = 0; timer < 30000; timer++) {
				if ((RD16_IO_REG(ha, hccr) & HC_RISC_PAUSE) ==
				    0) {
					break;
				} else {
					drv_usecwait(MILLISEC);
				}
			}
		} else if (ha->device_id == 0x2312) {
			/*
			 * cPCI ISP2312 specific code to service function 1
			 * hot-swap registers.
			 */
			if ((RD16_IO_REG(ha, ctrl_status) & ISP_FUNC_NUM_MASK)
			    != 0) {
				ql_pci_config_put8(ha, 0x66, 0xc2);
			}
		}

		if (!(CFG_IST(ha, CFG_CTRL_82XX)) &&
		    ha->pci_max_read_req != 0) {
			ql_set_max_read_req(ha);
		}

		ql_pci_config_put16(ha, PCI_CONF_COMM, cmd);

		/* Set cache line register. */
		ql_pci_config_put8(ha, PCI_CONF_CACHE_LINESZ, 0x10);

		/* Set latency register. */
		ql_pci_config_put8(ha, PCI_CONF_LATENCY_TIMER, 0x40);

		/* Reset expansion ROM address decode enable. */
		if (!CFG_IST(ha, CFG_CTRL_278083)) {
			w16 = (uint16_t)ql_pci_config_get16(ha, PCI_CONF_ROM);
			w16 = (uint16_t)(w16 & ~BIT_0);
			ql_pci_config_put16(ha, PCI_CONF_ROM, w16);
		}
	}

	QL_PRINT_10(ha, "done\n");

	return (QL_SUCCESS);
}

/*
 * Set the PCI max read request value.
 *
 * Input:
 *	ha:		adapter state pointer.
 *
 * Output:
 *	none.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */

static void
ql_set_max_read_req(ql_adapter_state_t *ha)
{
	int		ofst;
	uint16_t	read_req, w16;
	uint16_t	tmp = ha->pci_max_read_req;

	QL_PRINT_3(ha, "started\n");

	if ((ofst = ql_get_cap_ofst(ha, PCI_CAP_ID_PCIX))) {
		ofst += PCI_PCIX_COMMAND;
		QL_PRINT_10(ha, "PCI-X Command Reg = %xh\n", ofst);
		/* check for vaild override value */
		if (tmp == 512 || tmp == 1024 || tmp == 2048 ||
		    tmp == 4096) {
			/* shift away the don't cares */
			tmp = (uint16_t)(tmp >> 10);
			/* convert bit pos to request value */
			for (read_req = 0; tmp != 0; read_req++) {
				tmp = (uint16_t)(tmp >> 1);
			}
			w16 = (uint16_t)ql_pci_config_get16(ha, ofst);
			w16 = (uint16_t)(w16 & ~(BIT_3 & BIT_2));
			w16 = (uint16_t)(w16 | (read_req << 2));
			ql_pci_config_put16(ha, ofst, w16);
		} else {
			EL(ha, "invalid parameter value for "
			    "'pci-max-read-request': %d; using system "
			    "default\n", tmp);
		}
	} else if ((ofst = ql_get_cap_ofst(ha, PCI_CAP_ID_PCI_E))) {
		ofst += PCI_PCIE_DEVICE_CONTROL;
		QL_PRINT_10(ha, "PCI-E Device Control Reg = %xh\n", ofst);
		if (tmp == 128 || tmp == 256 || tmp == 512 ||
		    tmp == 1024 || tmp == 2048 || tmp == 4096) {
			/* shift away the don't cares */
			tmp = (uint16_t)(tmp >> 8);
			/* convert bit pos to request value */
			for (read_req = 0; tmp != 0; read_req++) {
				tmp = (uint16_t)(tmp >> 1);
			}
			w16 = (uint16_t)ql_pci_config_get16(ha, ofst);
			w16 = (uint16_t)(w16 & ~(BIT_14 | BIT_13 |
			    BIT_12));
			w16 = (uint16_t)(w16 | (read_req << 12));
			ql_pci_config_put16(ha, ofst, w16);
		} else {
			EL(ha, "invalid parameter value for "
			    "'pci-max-read-request': %d; using system "
			    "default\n", tmp);
		}
	}
	QL_PRINT_3(ha, "done\n");
}

/*
 * NVRAM configuration.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	ha->req_q[0]:	request ring
 *
 * Output:
 *	ha->init_ctrl_blk = initialization control block
 *	host adapters parameters in host adapter block
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_nvram_config(ql_adapter_state_t *ha)
{
	uint32_t	cnt;
	caddr_t		dptr1, dptr2;
	ql_init_cb_t	*icb = &ha->init_ctrl_blk.cb;
	ql_ip_init_cb_t	*ip_icb = &ha->ip_init_ctrl_blk.cb;
	nvram_t		*nv = (nvram_t *)ha->req_q[0]->req_ring.bp;
	uint16_t	*wptr = (uint16_t *)ha->req_q[0]->req_ring.bp;
	uint8_t		chksum = 0;
	int		rval;
	int		idpromlen;
	char		idprombuf[32];
	uint32_t	start_addr;
	la_els_logi_t	*els = &ha->loginparams;

	QL_PRINT_10(ha, "started\n");

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		return (ql_nvram_24xx_config(ha));
	}

	start_addr = 0;
	if ((rval = ql_lock_nvram(ha, &start_addr, LNF_NVRAM_DATA)) ==
	    QL_SUCCESS) {
		/* Verify valid NVRAM checksum. */
		for (cnt = 0; cnt < sizeof (nvram_t) / 2; cnt++) {
			*wptr = (uint16_t)ql_get_nvram_word(ha,
			    (uint32_t)(cnt + start_addr));
			chksum = (uint8_t)(chksum + (uint8_t)*wptr);
			chksum = (uint8_t)(chksum + (uint8_t)(*wptr >> 8));
			wptr++;
		}
		ql_release_nvram(ha);
	}

	/* Bad NVRAM data, set defaults parameters. */
	if (rval != QL_SUCCESS || chksum || nv->id[0] != 'I' ||
	    nv->id[1] != 'S' || nv->id[2] != 'P' || nv->id[3] != ' ' ||
	    nv->nvram_version < 1) {

		EL(ha, "failed, rval=%xh, checksum=%xh, "
		    "id=%02x%02x%02x%02xh, flsz=%xh, pciconfvid=%xh, "
		    "nvram_version=%x\n", rval, chksum, nv->id[0], nv->id[1],
		    nv->id[2], nv->id[3], ha->xioctl->fdesc.flash_size,
		    ha->subven_id, nv->nvram_version);

		/* Don't print nvram message if it's an on-board 2200 */
		if (!((CFG_IST(ha, CFG_CTRL_22XX)) &&
		    (ha->xioctl->fdesc.flash_size == 0))) {
			cmn_err(CE_WARN, "%s(%d): NVRAM configuration failed,"
			    " using driver defaults.", QL_NAME, ha->instance);
		}

		/* Reset NVRAM data. */
		bzero((void *)nv, sizeof (nvram_t));

		/*
		 * Set default initialization control block.
		 */
		nv->parameter_block_version = ICB_VERSION;
		nv->firmware_options[0] = BIT_4 | BIT_3 | BIT_2 | BIT_1;
		nv->firmware_options[1] = BIT_7 | BIT_5 | BIT_2;

		nv->max_frame_length[1] = 4;

		/*
		 * Allow 2048 byte frames for 2300
		 */
		if (CFG_IST(ha, CFG_CTRL_2363)) {
			nv->max_frame_length[1] = 8;
		}
		nv->max_iocb_allocation[1] = 1;
		nv->execution_throttle[0] = 16;
		nv->login_retry_count = 8;

		idpromlen = 32;

		/*LINTED [Solaris DDI_DEV_T_ANY Lint warning]*/
		if (ddi_getlongprop_buf(DDI_DEV_T_ANY, ha->dip,
		    DDI_PROP_CANSLEEP, "idprom", (caddr_t)idprombuf,
		    &idpromlen) != DDI_PROP_SUCCESS) {

			QL_PRINT_10(ha, "Unable to read idprom "
			    "property\n");
			cmn_err(CE_WARN, "%s(%d) : Unable to read idprom "
			    "property", QL_NAME, ha->instance);

			nv->port_name[2] = 33;
			nv->port_name[3] = 224;
			nv->port_name[4] = 139;
			nv->port_name[7] = (uint8_t)
			    (NAA_ID_IEEE_EXTENDED << 4 | ha->instance);
		} else {

			nv->port_name[2] = idprombuf[2];
			nv->port_name[3] = idprombuf[3];
			nv->port_name[4] = idprombuf[4];
			nv->port_name[5] = idprombuf[5];
			nv->port_name[6] = idprombuf[6];
			nv->port_name[7] = idprombuf[7];
			nv->port_name[0] = (uint8_t)
			    (NAA_ID_IEEE_EXTENDED << 4 | ha->instance);
		}

		/* Don't print nvram message if it's an on-board 2200 */
		if (!(CFG_IST(ha, CFG_CTRL_22XX)) &&
		    (ha->xioctl->fdesc.flash_size == 0)) {
			cmn_err(CE_WARN, "%s(%d): Unreliable HBA NVRAM, using"
			    " default HBA parameters and temporary WWPN:"
			    " %02x%02x%02x%02x%02x%02x%02x%02x", QL_NAME,
			    ha->instance, nv->port_name[0], nv->port_name[1],
			    nv->port_name[2], nv->port_name[3],
			    nv->port_name[4], nv->port_name[5],
			    nv->port_name[6], nv->port_name[7]);
		}

		nv->login_timeout = 4;

		/* Set default connection options for the 23xx to 2 */
		if (!(CFG_IST(ha, CFG_CTRL_22XX))) {
			nv->add_fw_opt[0] = (uint8_t)(nv->add_fw_opt[0] |
			    BIT_5);
		}

		/*
		 * Set default host adapter parameters
		 */
		nv->host_p[0] = BIT_1;
		nv->host_p[1] = BIT_2;
		nv->reset_delay = 5;
		nv->port_down_retry_count = 8;
		nv->maximum_luns_per_target[0] = 8;

		rval = QL_FUNCTION_FAILED;
	}

	/* Reset initialization control blocks. */
	bzero((void *)icb, sizeof (ql_init_cb_t));
	bzero((void *)ip_icb, sizeof (ql_ip_init_cb_t));

	/*
	 * Copy over NVRAM RISC parameter block
	 * to initialization control block.
	 */
	dptr1 = (caddr_t)icb;
	dptr2 = (caddr_t)&nv->parameter_block_version;
	cnt = (uint32_t)((uintptr_t)&icb->request_q_outpointer[0] -
	    (uintptr_t)&icb->version);
	while (cnt-- != 0) {
		*dptr1++ = *dptr2++;
	}

	/* Copy 2nd half. */
	dptr1 = (caddr_t)&icb->add_fw_opt[0];
	cnt = (uint32_t)((uintptr_t)&icb->reserved_3[0] -
	    (uintptr_t)&icb->add_fw_opt[0]);
	while (cnt-- != 0) {
		*dptr1++ = *dptr2++;
	}

	ha->execution_throttle = CHAR_TO_SHORT(nv->execution_throttle[0],
	    nv->execution_throttle[1]);
	ha->loop_reset_delay = nv->reset_delay;
	ha->port_down_retry_count = nv->port_down_retry_count;
	ha->maximum_luns_per_target = CHAR_TO_SHORT(
	    nv->maximum_luns_per_target[0], nv->maximum_luns_per_target[1]);
	if (ha->maximum_luns_per_target == 0) {
		ha->maximum_luns_per_target++;
	}
	ha->adapter_features = CHAR_TO_SHORT(nv->adapter_features[0],
	    nv->adapter_features[1]);

	/* Check for adapter node name (big endian). */
	for (cnt = 0; cnt < 8; cnt++) {
		if (icb->node_name[cnt] != 0) {
			break;
		}
	}

	/* Copy port name if no node name (big endian). */
	if (cnt == 8) {
		for (cnt = 0; cnt < 8; cnt++) {
			icb->node_name[cnt] = icb->port_name[cnt];
		}
		icb->node_name[0] = (uint8_t)(icb->node_name[0] & ~BIT_0);
		icb->port_name[0] = (uint8_t)(icb->node_name[0] | BIT_0);
	}

	ADAPTER_STATE_LOCK(ha);
	ha->cfg_flags &= ~(CFG_ENABLE_FULL_LIP_LOGIN | CFG_ENABLE_TARGET_RESET |
	    CFG_ENABLE_LIP_RESET | CFG_LOAD_FLASH_FW | CFG_FAST_TIMEOUT |
	    CFG_DISABLE_RISC_CODE_LOAD | CFG_ENABLE_FWEXTTRACE |
	    CFG_ENABLE_FWFCETRACE | CFG_SET_CACHE_LINE_SIZE_1 | CFG_LR_SUPPORT);
	if (nv->host_p[0] & BIT_4) {
		ha->cfg_flags |= CFG_DISABLE_RISC_CODE_LOAD;
	}
	if (nv->host_p[0] & BIT_5) {
		ha->cfg_flags |= CFG_SET_CACHE_LINE_SIZE_1;
	}
	if (nv->host_p[1] & BIT_2) {
		ha->cfg_flags |= CFG_ENABLE_FULL_LIP_LOGIN;
	}
	if (nv->host_p[1] & BIT_3) {
		ha->cfg_flags |= CFG_ENABLE_TARGET_RESET;
	}
	nv->adapter_features[0] & BIT_3 ?
	    (ha->flags |= MULTI_CHIP_ADAPTER) :
	    (ha->flags &= ~MULTI_CHIP_ADAPTER);
	ADAPTER_STATE_UNLOCK(ha);

	/* Get driver properties. */
	ql_23_properties(ha, icb);

	/*
	 * Setup driver firmware options.
	 */
	icb->firmware_options[0] = (uint8_t)
	    (icb->firmware_options[0] | BIT_6 | BIT_1);

	/*
	 * There is no use enabling fast post for SBUS or 2300
	 * Always enable 64bit addressing, except SBUS cards.
	 */
	ha->cfg_flags |= CFG_ENABLE_64BIT_ADDRESSING;
	if (CFG_IST(ha, CFG_SBUS_CARD | CFG_CTRL_2363)) {
		icb->firmware_options[0] = (uint8_t)
		    (icb->firmware_options[0] & ~BIT_3);
		if (CFG_IST(ha, CFG_SBUS_CARD)) {
			icb->special_options[0] = (uint8_t)
			    (icb->special_options[0] | BIT_5);
			ha->cfg_flags &= ~CFG_ENABLE_64BIT_ADDRESSING;
		}
	} else {
		icb->firmware_options[0] = (uint8_t)
		    (icb->firmware_options[0] | BIT_3);
	}
	/* RIO and ZIO not supported. */
	icb->add_fw_opt[0] = (uint8_t)(icb->add_fw_opt[0] &
	    ~(BIT_3 | BIT_2 | BIT_1 | BIT_0));

	icb->firmware_options[1] = (uint8_t)(icb->firmware_options[1] |
	    BIT_7 | BIT_6 | BIT_5 | BIT_2 | BIT_0);
	icb->firmware_options[0] = (uint8_t)
	    (icb->firmware_options[0] & ~(BIT_5 | BIT_4));
	icb->firmware_options[1] = (uint8_t)
	    (icb->firmware_options[1] & ~BIT_4);
	if (CFG_IST(ha, CFG_ENABLE_FCP_2_SUPPORT)) {
		icb->firmware_options[1] = (uint8_t)
		    (icb->firmware_options[1] | BIT_7 | BIT_6);
		icb->add_fw_opt[1] = (uint8_t)
		    (icb->add_fw_opt[1] | BIT_5 | BIT_4);
	}
	icb->add_fw_opt[1] = (uint8_t)(icb->add_fw_opt[1] & ~(BIT_5 | BIT_4));
	icb->special_options[0] = (uint8_t)(icb->special_options[0] | BIT_1);

	if (CFG_IST(ha, CFG_CTRL_2363)) {
		if ((icb->special_options[1] & 0x20) == 0) {
			EL(ha, "50 ohm is not set\n");
		}
	}

	/*
	 * Set host adapter parameters
	 */
	/* Get adapter id string for Sun branded 23xx only */
	if (CFG_IST(ha, CFG_CTRL_23XX) && nv->adapInfo[0] != 0) {
		(void) snprintf((int8_t *)ha->adapInfo, 16, "%s",
		    nv->adapInfo);
	}

	ha->r_a_tov = (uint16_t)(icb->login_timeout < R_A_TOV_DEFAULT ?
	    R_A_TOV_DEFAULT : icb->login_timeout);

	els->common_service.rx_bufsize = CHAR_TO_SHORT(
	    icb->max_frame_length[0], icb->max_frame_length[1]);
	bcopy((void *)icb->port_name, (void *)els->nport_ww_name.raw_wwn, 8);
	bcopy((void *)icb->node_name, (void *)els->node_ww_name.raw_wwn, 8);

	cmn_err(CE_CONT, "!Qlogic %s(%d) WWPN=%02x%02x%02x%02x"
	    "%02x%02x%02x%02x : WWNN=%02x%02x%02x%02x%02x%02x%02x%02x\n",
	    QL_NAME, ha->instance,
	    els->nport_ww_name.raw_wwn[0], els->nport_ww_name.raw_wwn[1],
	    els->nport_ww_name.raw_wwn[2], els->nport_ww_name.raw_wwn[3],
	    els->nport_ww_name.raw_wwn[4], els->nport_ww_name.raw_wwn[5],
	    els->nport_ww_name.raw_wwn[6], els->nport_ww_name.raw_wwn[7],
	    els->node_ww_name.raw_wwn[0], els->node_ww_name.raw_wwn[1],
	    els->node_ww_name.raw_wwn[2], els->node_ww_name.raw_wwn[3],
	    els->node_ww_name.raw_wwn[4], els->node_ww_name.raw_wwn[5],
	    els->node_ww_name.raw_wwn[6], els->node_ww_name.raw_wwn[7]);
	/*
	 * Setup ring parameters in initialization control block
	 */
	cnt = ha->req_q[0]->req_entry_cnt;
	icb->request_q_length[0] = LSB(cnt);
	icb->request_q_length[1] = MSB(cnt);
	cnt = ha->rsp_queues[0]->rsp_entry_cnt;
	icb->response_q_length[0] = LSB(cnt);
	icb->response_q_length[1] = MSB(cnt);

	start_addr = ha->req_q[0]->req_ring.cookie.dmac_address;
	icb->request_q_address[0] = LSB(LSW(start_addr));
	icb->request_q_address[1] = MSB(LSW(start_addr));
	icb->request_q_address[2] = LSB(MSW(start_addr));
	icb->request_q_address[3] = MSB(MSW(start_addr));

	start_addr = ha->req_q[0]->req_ring.cookie.dmac_notused;
	icb->request_q_address[4] = LSB(LSW(start_addr));
	icb->request_q_address[5] = MSB(LSW(start_addr));
	icb->request_q_address[6] = LSB(MSW(start_addr));
	icb->request_q_address[7] = MSB(MSW(start_addr));

	start_addr = ha->rsp_queues[0]->rsp_ring.cookie.dmac_address;
	icb->response_q_address[0] = LSB(LSW(start_addr));
	icb->response_q_address[1] = MSB(LSW(start_addr));
	icb->response_q_address[2] = LSB(MSW(start_addr));
	icb->response_q_address[3] = MSB(MSW(start_addr));

	start_addr = ha->rsp_queues[0]->rsp_ring.cookie.dmac_notused;
	icb->response_q_address[4] = LSB(LSW(start_addr));
	icb->response_q_address[5] = MSB(LSW(start_addr));
	icb->response_q_address[6] = LSB(MSW(start_addr));
	icb->response_q_address[7] = MSB(MSW(start_addr));

	/*
	 * Setup IP initialization control block
	 */
	ip_icb->version = IP_ICB_VERSION;

	if (CFG_IST(ha, CFG_ENABLE_64BIT_ADDRESSING)) {
		ip_icb->ip_firmware_options[0] = (uint8_t)
		    (ip_icb->ip_firmware_options[0] | BIT_2 | BIT_0);
	} else {
		ip_icb->ip_firmware_options[0] = (uint8_t)
		    (ip_icb->ip_firmware_options[0] | BIT_2);
	}

	cnt = RCVBUF_CONTAINER_CNT;
	ip_icb->queue_size[0] = LSB(cnt);
	ip_icb->queue_size[1] = MSB(cnt);

	start_addr = ha->rcv_ring.cookie.dmac_address;
	ip_icb->queue_address[0] = LSB(LSW(start_addr));
	ip_icb->queue_address[1] = MSB(LSW(start_addr));
	ip_icb->queue_address[2] = LSB(MSW(start_addr));
	ip_icb->queue_address[3] = MSB(MSW(start_addr));

	start_addr = ha->rcv_ring.cookie.dmac_notused;
	ip_icb->queue_address[4] = LSB(LSW(start_addr));
	ip_icb->queue_address[5] = MSB(LSW(start_addr));
	ip_icb->queue_address[6] = LSB(MSW(start_addr));
	ip_icb->queue_address[7] = MSB(MSW(start_addr));

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_10(ha, "done\n");
	}
	return (rval);
}

/*
 * Get NVRAM data word
 *	Calculates word position in NVRAM and calls request routine to
 *	get the word from NVRAM.
 *
 * Input:
 *	ha = adapter state pointer.
 *	address = NVRAM word address.
 *
 * Returns:
 *	data word.
 *
 * Context:
 *	Kernel context.
 */
uint16_t
ql_get_nvram_word(ql_adapter_state_t *ha, uint32_t address)
{
	uint32_t	nv_cmd;
	uint16_t	rval;

	QL_PRINT_4(ha, "started\n");

	nv_cmd = address << 16;
	nv_cmd = nv_cmd | NV_READ_OP;

	rval = (uint16_t)ql_nvram_request(ha, nv_cmd);

	QL_PRINT_4(ha, "NVRAM data = %xh\n", rval);

	return (rval);
}

/*
 * NVRAM request
 *	Sends read command to NVRAM and gets data from NVRAM.
 *
 * Input:
 *	ha = adapter state pointer.
 *	nv_cmd = Bit 26= start bit
 *	Bit 25, 24 = opcode
 *	Bit 23-16 = address
 *	Bit 15-0 = write data
 *
 * Returns:
 *	data word.
 *
 * Context:
 *	Kernel context.
 */
static uint16_t
ql_nvram_request(ql_adapter_state_t *ha, uint32_t nv_cmd)
{
	uint8_t		cnt;
	uint16_t	reg_data;
	uint16_t	data = 0;

	/* Send command to NVRAM. */

	nv_cmd <<= 5;
	for (cnt = 0; cnt < 11; cnt++) {
		if (nv_cmd & BIT_31) {
			ql_nv_write(ha, NV_DATA_OUT);
		} else {
			ql_nv_write(ha, 0);
		}
		nv_cmd <<= 1;
	}

	/* Read data from NVRAM. */

	for (cnt = 0; cnt < 16; cnt++) {
		WRT16_IO_REG(ha, nvram, NV_SELECT + NV_CLOCK);
		ql_nv_delay();
		data <<= 1;
		reg_data = RD16_IO_REG(ha, nvram);
		if (reg_data & NV_DATA_IN) {
			data = (uint16_t)(data | BIT_0);
		}
		WRT16_IO_REG(ha, nvram, NV_SELECT);
		ql_nv_delay();
	}

	/* Deselect chip. */

	WRT16_IO_REG(ha, nvram, NV_DESELECT);
	ql_nv_delay();

	return (data);
}

void
ql_nv_write(ql_adapter_state_t *ha, uint16_t data)
{
	WRT16_IO_REG(ha, nvram, (uint16_t)(data | NV_SELECT));
	ql_nv_delay();
	WRT16_IO_REG(ha, nvram, (uint16_t)(data | NV_SELECT | NV_CLOCK));
	ql_nv_delay();
	WRT16_IO_REG(ha, nvram, (uint16_t)(data | NV_SELECT));
	ql_nv_delay();
}

void
ql_nv_delay(void)
{
	drv_usecwait(NV_DELAY_COUNT);
}

/*
 * ql_nvram_24xx_config
 *	ISP2400 nvram.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	ha->req_q[0]:	request ring
 *
 * Output:
 *	ha->init_ctrl_blk = initialization control block
 *	host adapters parameters in host adapter block
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_nvram_24xx_config(ql_adapter_state_t *ha)
{
	uint32_t		index, addr;
	uint32_t		chksum = 0, saved_chksum = 0;
	uint32_t		*longptr;
	nvram_24xx_t		nvram;
	int			idpromlen;
	char			idprombuf[32];
	caddr_t			src, dst;
	uint16_t		w1;
	int			rval;
	nvram_24xx_t		*nv = (nvram_24xx_t *)&nvram;
	ql_init_24xx_cb_t	*icb =
	    (ql_init_24xx_cb_t *)&ha->init_ctrl_blk.cb24;
	ql_ip_init_24xx_cb_t	*ip_icb = &ha->ip_init_ctrl_blk.cb24;
	la_els_logi_t		*els = &ha->loginparams;

	QL_PRINT_10(ha, "started\n");

	if ((rval = ql_lock_nvram(ha, &addr, LNF_NVRAM_DATA)) == QL_SUCCESS) {

		/* Get NVRAM data and calculate checksum. */
		longptr = (uint32_t *)nv;
		chksum = saved_chksum = 0;
		for (index = 0; index < sizeof (nvram_24xx_t) / 4; index++) {
			rval = ql_24xx_read_flash(ha, addr++, longptr);
			if (rval != QL_SUCCESS) {
				EL(ha, "24xx_read_flash failed=%xh\n", rval);
				break;
			}
			saved_chksum = chksum;
			chksum += *longptr;
			LITTLE_ENDIAN_32(longptr);
			longptr++;
		}

		ql_release_nvram(ha);
	}

	/* Bad NVRAM data, set defaults parameters. */
	if (rval != QL_SUCCESS || chksum || nv->id[0] != 'I' ||
	    nv->id[1] != 'S' || nv->id[2] != 'P' || nv->id[3] != ' ' ||
	    (nv->nvram_version[0] | nv->nvram_version[1]) == 0) {

		cmn_err(CE_WARN, "%s(%d): NVRAM configuration failed, using "
		    "driver defaults.", QL_NAME, ha->instance);
		EL(ha, "failed, rval=%xh, checksum=%xh, id=%c%c%c%c, "
		    "nvram_version=%x\n", rval, chksum, nv->id[0], nv->id[1],
		    nv->id[2], nv->id[3], CHAR_TO_SHORT(nv->nvram_version[0],
		    nv->nvram_version[1]));

		saved_chksum = ~saved_chksum + 1;

		(void) ql_flash_errlog(ha, FLASH_ERRLOG_NVRAM_CHKSUM_ERR, 0,
		    MSW(saved_chksum), LSW(saved_chksum));

		/* Reset NVRAM data. */
		bzero((void *)nv, sizeof (nvram_24xx_t));

		/*
		 * Set default initialization control block.
		 */
		nv->nvram_version[0] = LSB(ICB_24XX_VERSION);
		nv->nvram_version[1] = MSB(ICB_24XX_VERSION);

		nv->version[0] = 1;
		nv->max_frame_length[1] = 8;
		nv->execution_throttle[0] = 16;
		nv->exchange_count[0] = 128;
		nv->max_luns_per_target[0] = 8;

		idpromlen = 32;

		/*LINTED [Solaris DDI_DEV_T_ANY Lint warning]*/
		if (rval = ddi_getlongprop_buf(DDI_DEV_T_ANY, ha->dip,
		    DDI_PROP_CANSLEEP, "idprom", (caddr_t)idprombuf,
		    &idpromlen) != DDI_PROP_SUCCESS) {

			cmn_err(CE_WARN, "%s(%d) : Unable to read idprom "
			    "property, rval=%x", QL_NAME, ha->instance, rval);

			nv->port_name[0] = 33;
			nv->port_name[3] = 224;
			nv->port_name[4] = 139;
			nv->port_name[7] = (uint8_t)
			    (NAA_ID_IEEE_EXTENDED << 4 | ha->instance);
		} else {
			nv->port_name[2] = idprombuf[2];
			nv->port_name[3] = idprombuf[3];
			nv->port_name[4] = idprombuf[4];
			nv->port_name[5] = idprombuf[5];
			nv->port_name[6] = idprombuf[6];
			nv->port_name[7] = idprombuf[7];
			nv->port_name[0] = (uint8_t)
			    (NAA_ID_IEEE_EXTENDED << 4 | ha->instance);
		}

		cmn_err(CE_WARN, "%s(%d): Unreliable HBA NVRAM, using default "
		    "HBA parameters and temporary "
		    "WWPN: %02x%02x%02x%02x%02x%02x%02x%02x", QL_NAME,
		    ha->instance, nv->port_name[0], nv->port_name[1],
		    nv->port_name[2], nv->port_name[3], nv->port_name[4],
		    nv->port_name[5], nv->port_name[6], nv->port_name[7]);

		nv->login_retry_count[0] = 8;

		nv->firmware_options_1[0] = BIT_2 | BIT_1;
		nv->firmware_options_1[1] = BIT_5;
		nv->firmware_options_2[0] = BIT_5;
		nv->firmware_options_2[1] = BIT_4;
		nv->firmware_options_3[1] = BIT_6;

		/*
		 * Set default host adapter parameters
		 */
		nv->host_p[0] = BIT_4 | BIT_1;
		nv->host_p[1] = BIT_3 | BIT_2;
		nv->reset_delay = 5;
		nv->max_luns_per_target[0] = 128;
		nv->port_down_retry_count[0] = 30;
		nv->link_down_timeout[0] = 30;

		if (CFG_IST(ha, CFG_FCOE_SUPPORT)) {
			nv->firmware_options_3[2] = BIT_4;
			nv->feature_mask_l[0] = 9;
			nv->ext_blk.version[0] = 1;
			nv->ext_blk.fcf_vlan_match = 1;
			nv->ext_blk.fcf_vlan_id[0] = LSB(1002);
			nv->ext_blk.fcf_vlan_id[1] = MSB(1002);
			nv->fw.isp8001.e_node_mac_addr[1] = 2;
			nv->fw.isp8001.e_node_mac_addr[2] = 3;
			nv->fw.isp8001.e_node_mac_addr[3] = 4;
			nv->fw.isp8001.e_node_mac_addr[4] = MSB(ha->instance);
			nv->fw.isp8001.e_node_mac_addr[5] = LSB(ha->instance);
		}

		rval = QL_FUNCTION_FAILED;
	}

	/* Reset initialization control blocks. */
	bzero((void *)icb, sizeof (ql_init_24xx_cb_t));

	/*
	 * Copy over NVRAM Firmware Initialization Control Block.
	 */
	dst = (caddr_t)icb;
	src = (caddr_t)&nv->version;
	index = (uint32_t)((uintptr_t)&icb->response_q_inpointer[0] -
	    (uintptr_t)icb);
	while (index--) {
		*dst++ = *src++;
	}
	icb->login_retry_count[0] = nv->login_retry_count[0];
	icb->login_retry_count[1] = nv->login_retry_count[1];
	icb->link_down_on_nos[0] = nv->link_down_on_nos[0];
	icb->link_down_on_nos[1] = nv->link_down_on_nos[1];

	/* Copy 2nd half. */
	dst = (caddr_t)&icb->interrupt_delay_timer;
	src = (caddr_t)&nv->interrupt_delay_timer;
	index = (uint32_t)((uintptr_t)&icb->qos -
	    (uintptr_t)&icb->interrupt_delay_timer);
	while (index--) {
		*dst++ = *src++;
	}

	ha->execution_throttle = 16;
	ha->loop_reset_delay = nv->reset_delay;
	ha->port_down_retry_count = CHAR_TO_SHORT(nv->port_down_retry_count[0],
	    nv->port_down_retry_count[1]);
	ha->maximum_luns_per_target = CHAR_TO_SHORT(
	    nv->max_luns_per_target[0], nv->max_luns_per_target[1]);
	if (ha->maximum_luns_per_target == 0) {
		ha->maximum_luns_per_target++;
	}
	if (CFG_IST(ha, CFG_FCOE_SUPPORT)) {
		dst = (caddr_t)icb->enode_mac_addr;
		src = (caddr_t)nv->fw.isp8001.e_node_mac_addr;
		index = sizeof (nv->fw.isp8001.e_node_mac_addr);
		while (index--) {
			*dst++ = *src++;
		}
		dst = (caddr_t)&icb->ext_blk;
		src = (caddr_t)&nv->ext_blk;
		index = sizeof (ql_ext_icb_8100_t);
		while (index--) {
			*dst++ = *src++;
		}
		EL(ha, "e_node_mac_addr=%02x-%02x-%02x-%02x-%02x-%02x\n",
		    icb->enode_mac_addr[0], icb->enode_mac_addr[1],
		    icb->enode_mac_addr[2], icb->enode_mac_addr[3],
		    icb->enode_mac_addr[4], icb->enode_mac_addr[5]);
	}

	/* Check for adapter node name (big endian). */
	for (index = 0; index < 8; index++) {
		if (icb->node_name[index] != 0) {
			break;
		}
	}

	/* Copy port name if no node name (big endian). */
	if (index == 8) {
		for (index = 0; index < 8; index++) {
			icb->node_name[index] = icb->port_name[index];
		}
		icb->node_name[0] = (uint8_t)(icb->node_name[0] & ~BIT_0);
		icb->port_name[0] = (uint8_t)(icb->node_name[0] | BIT_0);
	}

	ADAPTER_STATE_LOCK(ha);
	ha->cfg_flags &= ~(CFG_ENABLE_FULL_LIP_LOGIN | CFG_ENABLE_TARGET_RESET |
	    CFG_ENABLE_LIP_RESET | CFG_LOAD_FLASH_FW | CFG_FAST_TIMEOUT |
	    CFG_DISABLE_RISC_CODE_LOAD | CFG_ENABLE_FWEXTTRACE |
	    CFG_ENABLE_FWFCETRACE | CFG_SET_CACHE_LINE_SIZE_1 | CFG_LR_SUPPORT);
	if (nv->host_p[1] & BIT_2) {
		ha->cfg_flags |= CFG_ENABLE_FULL_LIP_LOGIN;
	}
	if (nv->host_p[1] & BIT_3) {
		ha->cfg_flags |= CFG_ENABLE_TARGET_RESET;
	}
	ha->flags &= ~MULTI_CHIP_ADAPTER;
	ADAPTER_STATE_UNLOCK(ha);

	/* Get driver properties. */
	ql_24xx_properties(ha, icb);

	/*
	 * Setup driver firmware options.
	 */
	if (!CFG_IST(ha, CFG_FCOE_SUPPORT)) {
		icb->firmware_options_1[0] = (uint8_t)
		    (icb->firmware_options_1[0] | BIT_1);
		icb->firmware_options_1[1] = (uint8_t)
		    (icb->firmware_options_1[1] | BIT_5 | BIT_2);
		icb->firmware_options_3[0] = (uint8_t)
		    (icb->firmware_options_3[0] | BIT_1);
	}
	icb->firmware_options_1[0] = (uint8_t)(icb->firmware_options_1[0] &
	    ~(BIT_5 | BIT_4));
	icb->firmware_options_1[1] = (uint8_t)(icb->firmware_options_1[1] |
	    BIT_6);
	icb->firmware_options_2[0] = (uint8_t)(icb->firmware_options_2[0] &
	    ~(BIT_3 | BIT_2 | BIT_1 | BIT_0));
	if (CFG_IST(ha, CFG_ENABLE_FCP_2_SUPPORT)) {
		icb->firmware_options_2[1] = (uint8_t)
		    (icb->firmware_options_2[1] | BIT_4);
	} else {
		icb->firmware_options_2[1] = (uint8_t)
		    (icb->firmware_options_2[1] & ~BIT_4);
	}
	icb->firmware_options_3[0] = (uint8_t)(icb->firmware_options_3[0] &
	    ~BIT_7);

	/*
	 * Set host adapter parameters
	 */
	w1 = CHAR_TO_SHORT(icb->login_timeout[0], icb->login_timeout[1]);
	ha->r_a_tov = (uint16_t)(w1 < R_A_TOV_DEFAULT ? R_A_TOV_DEFAULT : w1);

	ADAPTER_STATE_LOCK(ha);
	ha->cfg_flags |= CFG_ENABLE_64BIT_ADDRESSING;
	if (CFG_IST(ha, CFG_CTRL_81XX) && nv->enhanced_features[0] & BIT_0) {
		ha->cfg_flags |= CFG_LR_SUPPORT;
	}
	ADAPTER_STATE_UNLOCK(ha);

	/* Queue shadowing */
	if (ha->flags & QUEUE_SHADOW_PTRS) {
		icb->firmware_options_2[3] = (uint8_t)
		    (icb->firmware_options_2[3] | BIT_6 | BIT_5);
	} else {
		icb->firmware_options_2[3] = (uint8_t)
		    (icb->firmware_options_2[3] | ~(BIT_6 | BIT_5));
	}

	/* ISP2422 Serial Link Control */
	if (CFG_IST(ha, CFG_CTRL_24XX)) {
		ha->serdes_param[0] = CHAR_TO_SHORT(nv->fw.isp2400.swing_opt[0],
		    nv->fw.isp2400.swing_opt[1]);
		ha->serdes_param[1] = CHAR_TO_SHORT(nv->fw.isp2400.swing_1g[0],
		    nv->fw.isp2400.swing_1g[1]);
		ha->serdes_param[2] = CHAR_TO_SHORT(nv->fw.isp2400.swing_2g[0],
		    nv->fw.isp2400.swing_2g[1]);
		ha->serdes_param[3] = CHAR_TO_SHORT(nv->fw.isp2400.swing_4g[0],
		    nv->fw.isp2400.swing_4g[1]);
	}

	els->common_service.rx_bufsize = CHAR_TO_SHORT(
	    icb->max_frame_length[0], icb->max_frame_length[1]);
	bcopy((void *)icb->port_name, (void *)els->nport_ww_name.raw_wwn, 8);
	bcopy((void *)icb->node_name, (void *)els->node_ww_name.raw_wwn, 8);

	cmn_err(CE_CONT, "!Qlogic %s(%d) WWPN=%02x%02x%02x%02x"
	    "%02x%02x%02x%02x : WWNN=%02x%02x%02x%02x%02x%02x%02x%02x\n",
	    QL_NAME, ha->instance,
	    els->nport_ww_name.raw_wwn[0], els->nport_ww_name.raw_wwn[1],
	    els->nport_ww_name.raw_wwn[2], els->nport_ww_name.raw_wwn[3],
	    els->nport_ww_name.raw_wwn[4], els->nport_ww_name.raw_wwn[5],
	    els->nport_ww_name.raw_wwn[6], els->nport_ww_name.raw_wwn[7],
	    els->node_ww_name.raw_wwn[0], els->node_ww_name.raw_wwn[1],
	    els->node_ww_name.raw_wwn[2], els->node_ww_name.raw_wwn[3],
	    els->node_ww_name.raw_wwn[4], els->node_ww_name.raw_wwn[5],
	    els->node_ww_name.raw_wwn[6], els->node_ww_name.raw_wwn[7]);
	/*
	 * Setup ring parameters in initialization control block
	 */
	w1 = ha->req_q[0]->req_entry_cnt;
	icb->request_q_length[0] = LSB(w1);
	icb->request_q_length[1] = MSB(w1);
	w1 = ha->rsp_queues[0]->rsp_entry_cnt;
	icb->response_q_length[0] = LSB(w1);
	icb->response_q_length[1] = MSB(w1);

	addr = ha->req_q[0]->req_ring.cookie.dmac_address;
	icb->request_q_address[0] = LSB(LSW(addr));
	icb->request_q_address[1] = MSB(LSW(addr));
	icb->request_q_address[2] = LSB(MSW(addr));
	icb->request_q_address[3] = MSB(MSW(addr));

	addr = ha->req_q[0]->req_ring.cookie.dmac_notused;
	icb->request_q_address[4] = LSB(LSW(addr));
	icb->request_q_address[5] = MSB(LSW(addr));
	icb->request_q_address[6] = LSB(MSW(addr));
	icb->request_q_address[7] = MSB(MSW(addr));

	addr = ha->rsp_queues[0]->rsp_ring.cookie.dmac_address;
	icb->response_q_address[0] = LSB(LSW(addr));
	icb->response_q_address[1] = MSB(LSW(addr));
	icb->response_q_address[2] = LSB(MSW(addr));
	icb->response_q_address[3] = MSB(MSW(addr));

	addr = ha->rsp_queues[0]->rsp_ring.cookie.dmac_notused;
	icb->response_q_address[4] = LSB(LSW(addr));
	icb->response_q_address[5] = MSB(LSW(addr));
	icb->response_q_address[6] = LSB(MSW(addr));
	icb->response_q_address[7] = MSB(MSW(addr));

	/*
	 * Setup IP initialization control block
	 */
	ip_icb->version = IP_ICB_24XX_VERSION;

	ip_icb->ip_firmware_options[0] = (uint8_t)
	    (ip_icb->ip_firmware_options[0] | BIT_2);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_10(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_lock_nvram
 *	Locks NVRAM access and returns starting address of NVRAM.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	addr:	pointer for start address.
 *	flags:	Are mutually exclusive:
 *		LNF_NVRAM_DATA --> get nvram
 *		LNF_VPD_DATA --> get vpd data (24/25xx only).
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_lock_nvram(ql_adapter_state_t *ha, uint32_t *addr, uint32_t flags)
{
	int	i;

	QL_PRINT_3(ha, "started\n");

	if ((flags & LNF_NVRAM_DATA) && (flags & LNF_VPD_DATA)) {
		EL(ha, "invalid options for function");
		return (QL_FUNCTION_FAILED);
	}

	if (ha->device_id == 0x2312 || ha->device_id == 0x2322) {
		if ((flags & LNF_NVRAM_DATA) == 0) {
			EL(ha, "invalid 2312/2322 option for HBA");
			return (QL_FUNCTION_FAILED);
		}

		/* if function number is non-zero, then adjust offset */
		*addr = ha->flash_nvram_addr;

		/* Try to get resource lock. Wait for 10 seconds max */
		for (i = 0; i < 10000; i++) {
			/* if nvram busy bit is reset, acquire sema */
			if ((RD16_IO_REG(ha, nvram) & 0x8000) == 0) {
				WRT16_IO_REG(ha, host_to_host_sema, 1);
				drv_usecwait(MILLISEC);
				if (RD16_IO_REG(ha, host_to_host_sema) & 1) {
					break;
				}
			}
			drv_usecwait(MILLISEC);
		}
		if ((RD16_IO_REG(ha, host_to_host_sema) & 1) == 0) {
			cmn_err(CE_WARN, "%s(%d): unable to get NVRAM lock",
			    QL_NAME, ha->instance);
			return (QL_FUNCTION_FAILED);
		}
	} else if (CFG_IST(ha, CFG_CTRL_24XX)) {
		if (flags & LNF_VPD_DATA) {
			*addr = NVRAM_DATA_ADDR | ha->flash_vpd_addr;
		} else if (flags & LNF_NVRAM_DATA) {
			*addr = NVRAM_DATA_ADDR | ha->flash_nvram_addr;
		} else {
			EL(ha, "invalid 2422 option for HBA");
			return (QL_FUNCTION_FAILED);
		}

		GLOBAL_HW_LOCK();
	} else if (CFG_IST(ha, CFG_CTRL_252780818283)) {
		if (flags & LNF_VPD_DATA) {
			*addr = ha->flash_data_addr | ha->flash_vpd_addr;
		} else if (flags & LNF_NVRAM_DATA) {
			*addr = ha->flash_data_addr | ha->flash_nvram_addr;
		} else {
			EL(ha, "invalid 2581 option for HBA");
			return (QL_FUNCTION_FAILED);
		}

		GLOBAL_HW_LOCK();
	} else {
		if ((flags & LNF_NVRAM_DATA) == 0) {
			EL(ha, "invalid option for HBA");
			return (QL_FUNCTION_FAILED);
		}
		*addr = 0;
		GLOBAL_HW_LOCK();
	}

	QL_PRINT_3(ha, "done\n");

	return (QL_SUCCESS);
}

/*
 * ql_release_nvram
 *	Releases NVRAM access.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
void
ql_release_nvram(ql_adapter_state_t *ha)
{
	QL_PRINT_3(ha, "started\n");

	if (ha->device_id == 0x2312 || ha->device_id == 0x2322) {
		/* Release resource lock */
		WRT16_IO_REG(ha, host_to_host_sema, 0);
	} else {
		GLOBAL_HW_UNLOCK();
	}

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_23_properties
 *	Copies driver properties to NVRAM or adapter structure.
 *
 *	Driver properties are by design global variables and hidden
 *	completely from administrators. Knowledgeable folks can
 *	override the default values using driver.conf
 *
 * Input:
 *	ha:	adapter state pointer.
 *	icb:	Init control block structure pointer.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_23_properties(ql_adapter_state_t *ha, ql_init_cb_t *icb)
{
	uint32_t	data, cnt;

	QL_PRINT_3(ha, "started\n");

	/* Get frame payload size. */
	if ((data = ql_get_prop(ha, "max-frame-length")) == 0xffffffff) {
		data = 2048;
	}
	if (data == 512 || data == 1024 || data == 2048) {
		icb->max_frame_length[0] = LSB(data);
		icb->max_frame_length[1] = MSB(data);
	} else {
		EL(ha, "invalid parameter value for 'max-frame-length': "
		    "%d; using nvram default of %d\n", data, CHAR_TO_SHORT(
		    icb->max_frame_length[0], icb->max_frame_length[1]));
	}

	/* Get max IOCB allocation. */
	icb->max_iocb_allocation[0] = 0;
	icb->max_iocb_allocation[1] = 1;

	/* Get execution throttle. */
	if ((data = ql_get_prop(ha, "execution-throttle")) == 0xffffffff) {
		data = 32;
	}
	if (data != 0 && data < 65536) {
		icb->execution_throttle[0] = LSB(data);
		icb->execution_throttle[1] = MSB(data);
	} else {
		EL(ha, "invalid parameter value for 'execution-throttle': "
		    "%d; using nvram default of %d\n", data, CHAR_TO_SHORT(
		    icb->execution_throttle[0], icb->execution_throttle[1]));
	}

	/* Get Login timeout. */
	if ((data = ql_get_prop(ha, "login-timeout")) == 0xffffffff) {
		data = 3;
	}
	if (data < 256) {
		icb->login_timeout = (uint8_t)data;
	} else {
		EL(ha, "invalid parameter value for 'login-timeout': "
		    "%d; using nvram value of %d\n", data, icb->login_timeout);
	}

	/* Get retry count. */
	if ((data = ql_get_prop(ha, "login-retry-count")) == 0xffffffff) {
		data = 4;
	}
	if (data < 256) {
		icb->login_retry_count = (uint8_t)data;
	} else {
		EL(ha, "invalid parameter value for 'login-retry-count': "
		    "%d; using nvram value of %d\n", data,
		    icb->login_retry_count);
	}

	/* Get adapter hard loop ID enable. */
	data = ql_get_prop(ha, "enable-adapter-hard-loop-ID");
	if (data == 0) {
		icb->firmware_options[0] =
		    (uint8_t)(icb->firmware_options[0] & ~BIT_0);
	} else if (data == 1) {
		icb->firmware_options[0] =
		    (uint8_t)(icb->firmware_options[0] | BIT_0);
	} else if (data != 0xffffffff) {
		EL(ha, "invalid parameter value for "
		    "'enable-adapter-hard-loop-ID': %d; using nvram value "
		    "of %d\n", data, icb->firmware_options[0] & BIT_0 ? 1 : 0);
	}

	/* Get adapter hard loop ID. */
	data = ql_get_prop(ha, "adapter-hard-loop-ID");
	if (data < 126) {
		icb->hard_address[0] = (uint8_t)data;
	} else if (data != 0xffffffff) {
		EL(ha, "invalid parameter value for 'adapter-hard-loop-ID': "
		    "%d; using nvram value of %d\n",
		    data, icb->hard_address[0]);
	}

	/* Get LIP reset. */
	if ((data = ql_get_prop(ha, "enable-LIP-reset-on-bus-reset")) ==
	    0xffffffff) {
		data = 0;
	}
	if (data == 0) {
		ha->cfg_flags &= ~CFG_ENABLE_LIP_RESET;
	} else if (data == 1) {
		ha->cfg_flags |= CFG_ENABLE_LIP_RESET;
	} else {
		EL(ha, "invalid parameter value for "
		    "'enable-LIP-reset-on-bus-reset': %d; using nvram value "
		    "of %d\n", data,
		    CFG_IST(ha, CFG_ENABLE_LIP_RESET) ? 1 : 0);
	}

	/* Get LIP full login. */
	if ((data = ql_get_prop(ha, "enable-LIP-full-login-on-bus-reset")) ==
	    0xffffffff) {
		data = 1;
	}
	if (data == 0) {
		ha->cfg_flags &= ~CFG_ENABLE_FULL_LIP_LOGIN;
	} else if (data == 1) {
		ha->cfg_flags |= CFG_ENABLE_FULL_LIP_LOGIN;
	} else {
		EL(ha, "invalid parameter value for "
		    "'enable-LIP-full-login-on-bus-reset': %d; using nvram "
		    "value of %d\n", data,
		    CFG_IST(ha, CFG_ENABLE_FULL_LIP_LOGIN) ? 1 : 0);
	}

	/* Get target reset. */
	if ((data = ql_get_prop(ha, "enable-target-reset-on-bus-reset")) ==
	    0xffffffff) {
		data = 0;
	}
	if (data == 0) {
		ha->cfg_flags &= ~CFG_ENABLE_TARGET_RESET;
	} else if (data == 1) {
		ha->cfg_flags |= CFG_ENABLE_TARGET_RESET;
	} else {
		EL(ha, "invalid parameter value for "
		    "'enable-target-reset-on-bus-reset': %d; using nvram "
		    "value of %d", data,
		    CFG_IST(ha, CFG_ENABLE_TARGET_RESET) ? 1 : 0);
	}

	/* Get reset delay. */
	if ((data = ql_get_prop(ha, "reset-delay")) == 0xffffffff) {
		data = 5;
	}
	if (data != 0 && data < 256) {
		ha->loop_reset_delay = (uint8_t)data;
	} else {
		EL(ha, "invalid parameter value for 'reset-delay': %d; "
		    "using nvram value of %d", data, ha->loop_reset_delay);
	}

	/* Get port down retry count. */
	if ((data = ql_get_prop(ha, "port-down-retry-count")) == 0xffffffff) {
		data = 8;
	}
	if (data < 256) {
		ha->port_down_retry_count = (uint8_t)data;
	} else {
		EL(ha, "invalid parameter value for 'port-down-retry-count':"
		    " %d; using nvram value of %d\n", data,
		    ha->port_down_retry_count);
	}

	/* Get connection mode setting. */
	if ((data = ql_get_prop(ha, "connection-options")) == 0xffffffff) {
		data = 2;
	}
	cnt = CFG_IST(ha, CFG_CTRL_22XX) ? 3 : 2;
	if (data <= cnt) {
		icb->add_fw_opt[0] = (uint8_t)(icb->add_fw_opt[0] &
		    ~(BIT_6 | BIT_5 | BIT_4));
		icb->add_fw_opt[0] = (uint8_t)(icb->add_fw_opt[0] |
		    (uint8_t)(data << 4));
	} else {
		EL(ha, "invalid parameter value for 'connection-options': "
		    "%d; using nvram value of %d\n", data,
		    (icb->add_fw_opt[0] >> 4) & 0x3);
	}

	/* Get data rate setting. */
	if ((CFG_IST(ha, CFG_CTRL_22XX)) == 0) {
		if ((data = ql_get_prop(ha, "fc-data-rate")) == 0xffffffff) {
			data = 2;
		}
		if (data < 3) {
			icb->special_options[1] = (uint8_t)
			    (icb->special_options[1] & 0x3f);
			icb->special_options[1] = (uint8_t)
			    (icb->special_options[1] | (uint8_t)(data << 6));
		} else {
			EL(ha, "invalid parameter value for 'fc-data-rate': "
			    "%d; using nvram value of %d\n", data,
			    (icb->special_options[1] >> 6) & 0x3);
		}
	}

	/* Get IP FW container count. */
	ha->ip_init_ctrl_blk.cb.cc[0] = LSB(ql_ip_buffer_count);
	ha->ip_init_ctrl_blk.cb.cc[1] = MSB(ql_ip_buffer_count);

	/* Get IP low water mark. */
	ha->ip_init_ctrl_blk.cb.low_water_mark[0] = LSB(ql_ip_low_water);
	ha->ip_init_ctrl_blk.cb.low_water_mark[1] = MSB(ql_ip_low_water);

	/* Get IP fast register post count. */
	ha->ip_init_ctrl_blk.cb.fast_post_reg_count[0] =
	    ql_ip_fast_post_count;

	ADAPTER_STATE_LOCK(ha);

	ql_common_properties(ha);

	ADAPTER_STATE_UNLOCK(ha);

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_common_properties
 *	Driver properties adapter structure.
 *
 *	Driver properties are by design global variables and hidden
 *	completely from administrators. Knowledgeable folks can
 *	override the default values using driver.conf
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
void
ql_common_properties(ql_adapter_state_t *ha)
{
	uint32_t	data;

	QL_PRINT_10(ha, "started\n");

	/* Get extended logging enable. */
	if ((data = ql_get_prop(ha, "extended-logging")) == 0xffffffff ||
	    data == 0) {
		ha->cfg_flags &= ~CFG_ENABLE_EXTENDED_LOGGING;
	} else if (data == 1) {
		ha->cfg_flags |= CFG_ENABLE_EXTENDED_LOGGING;
	} else {
		EL(ha, "invalid parameter value for 'extended-logging': %d;"
		    " using default value of 0\n", data);
		ha->cfg_flags &= ~CFG_ENABLE_EXTENDED_LOGGING;
	}

	/* Get FCP 2 Error Recovery. */
	if ((data = ql_get_prop(ha, "enable-FCP-2-error-recovery")) ==
	    0xffffffff || data == 1) {
		ha->cfg_flags |= CFG_ENABLE_FCP_2_SUPPORT;
	} else if (data == 0) {
		ha->cfg_flags &= ~CFG_ENABLE_FCP_2_SUPPORT;
	} else {
		EL(ha, "invalid parameter value for "
		    "'enable-FCP-2-error-recovery': %d; using nvram value of "
		    "1\n", data);
		ha->cfg_flags |= CFG_ENABLE_FCP_2_SUPPORT;
	}

#ifdef QL_DEBUG_LEVEL_2
	ha->cfg_flags |= CFG_ENABLE_EXTENDED_LOGGING;
#endif

	/* Get port down retry delay. */
	if ((data = ql_get_prop(ha, "port-down-retry-delay")) == 0xffffffff) {
		ha->port_down_retry_delay = PORT_RETRY_TIME;
	} else if (data < 256) {
		ha->port_down_retry_delay = (uint8_t)data;
	} else {
		EL(ha, "invalid parameter value for 'port-down-retry-delay':"
		    " %d; using default value of %d", data, PORT_RETRY_TIME);
		ha->port_down_retry_delay = PORT_RETRY_TIME;
	}

	/* Get queue full retry count. */
	if ((data = ql_get_prop(ha, "queue-full-retry-count")) == 0xffffffff) {
		ha->qfull_retry_count = 16;
	} else if (data < 256) {
		ha->qfull_retry_count = (uint8_t)data;
	} else {
		EL(ha, "invalid parameter value for 'queue-full-retry-count':"
		    " %d; using default value of 16", data);
		ha->qfull_retry_count = 16;
	}

	/* Get queue full retry delay. */
	if ((data = ql_get_prop(ha, "queue-full-retry-delay")) == 0xffffffff) {
		ha->qfull_retry_delay = PORT_RETRY_TIME;
	} else if (data < 256) {
		ha->qfull_retry_delay = (uint8_t)data;
	} else {
		EL(ha, "invalid parameter value for 'queue-full-retry-delay':"
		    " %d; using default value of %d", data, PORT_RETRY_TIME);
		ha->qfull_retry_delay = PORT_RETRY_TIME;
	}

	/* Get loop down timeout. */
	if ((data = ql_get_prop(ha, "link-down-timeout")) == 0xffffffff) {
		data = 0;
	} else if (data > 255) {
		EL(ha, "invalid parameter value for 'link-down-timeout': %d;"
		    " using nvram value of 0\n", data);
		data = 0;
	}
	ha->loop_down_abort_time = (uint8_t)(LOOP_DOWN_TIMER_START - data);
	if (ha->loop_down_abort_time == LOOP_DOWN_TIMER_START) {
		ha->loop_down_abort_time--;
	} else if (ha->loop_down_abort_time <= LOOP_DOWN_TIMER_END) {
		ha->loop_down_abort_time = LOOP_DOWN_TIMER_END + 1;
	}

	/* Get link down error enable. */
	if ((data = ql_get_prop(ha, "enable-link-down-error")) == 0xffffffff ||
	    data == 1) {
		ha->cfg_flags |= CFG_ENABLE_LINK_DOWN_REPORTING;
	} else if (data == 0) {
		ha->cfg_flags &= ~CFG_ENABLE_LINK_DOWN_REPORTING;
	} else {
		EL(ha, "invalid parameter value for 'link-down-error': %d;"
		    " using default value of 1\n", data);
	}

	/*
	 * Get firmware dump flags.
	 *	TAKE_FW_DUMP_ON_MAILBOX_TIMEOUT		BIT_0
	 *	TAKE_FW_DUMP_ON_ISP_SYSTEM_ERROR	BIT_1
	 *	TAKE_FW_DUMP_ON_DRIVER_COMMAND_TIMEOUT	BIT_2
	 *	TAKE_FW_DUMP_ON_LOOP_OFFLINE_TIMEOUT	BIT_3
	 */
	ha->cfg_flags &= ~(CFG_DUMP_MAILBOX_TIMEOUT |
	    CFG_DUMP_ISP_SYSTEM_ERROR | CFG_DUMP_DRIVER_COMMAND_TIMEOUT |
	    CFG_DUMP_LOOP_OFFLINE_TIMEOUT);
	if ((data = ql_get_prop(ha, "firmware-dump-flags")) != 0xffffffff) {
		if (data & BIT_0) {
			ha->cfg_flags |= CFG_DUMP_MAILBOX_TIMEOUT;
		}
		if (data & BIT_1) {
			ha->cfg_flags |= CFG_DUMP_ISP_SYSTEM_ERROR;
		}
		if (data & BIT_2) {
			ha->cfg_flags |= CFG_DUMP_DRIVER_COMMAND_TIMEOUT;
		}
		if (data & BIT_3) {
			ha->cfg_flags |= CFG_DUMP_LOOP_OFFLINE_TIMEOUT;
		}
	}

	/* Get the PCI max read request size override. */
	ha->pci_max_read_req = 0;
	if ((data = ql_get_prop(ha, "pci-max-read-request")) != 0xffffffff &&
	    data != 0) {
		ha->pci_max_read_req = (uint16_t)(data);
	}

	/* Get the plogi retry params overrides. */
	if ((data = ql_get_prop(ha, "plogi_params_retry_count")) !=
	    0xffffffff && data != 0) {
		ha->plogi_params->retry_cnt = (uint32_t)(data);
	}
	if ((data = ql_get_prop(ha, "plogi_params_retry_delay")) !=
	    0xffffffff && data != 0) {
		ha->plogi_params->retry_dly_usec = (uint32_t)(data);
	}

	/*
	 * Set default fw wait, adjusted for slow FCF's.
	 * Revisit when FCF's as fast as FC switches.
	 */
	ha->fwwait = (uint8_t)(CFG_IST(ha, CFG_FCOE_SUPPORT) ? 45 : 10);
	/* Get the attach fw_ready override value. */
	if ((data = ql_get_prop(ha, "init-loop-sync-wait")) != 0xffffffff) {
		if (data > 0 && data <= 240) {
			ha->fwwait = (uint8_t)data;
		} else {
			EL(ha, "invalid parameter value for "
			    "'init-loop-sync-wait': %d; using default "
			    "value of %d\n", data, ha->fwwait);
		}
	}

	/* Get fm-capable property */
	ha->fm_capabilities = DDI_FM_NOT_CAPABLE;
	if ((data = ql_get_prop(ha, "fm-capable")) != 0xffffffff) {
		if (data == 0) {
			ha->fm_capabilities = DDI_FM_NOT_CAPABLE;
		} else if (data > 0xf) {
			ha->fm_capabilities = 0xf;

		} else {
			ha->fm_capabilities = (int)(data);
		}
	} else {
		ha->fm_capabilities = (int)(DDI_FM_EREPORT_CAPABLE
		    | DDI_FM_ERRCB_CAPABLE);
	}

	if ((data = ql_get_prop(ha, "msix-vectors")) == 0xffffffff) {
		ha->mq_msix_vectors = 0;
	} else if (data < 256) {
		ha->mq_msix_vectors = (uint8_t)data;
	} else {
		EL(ha, "invalid parameter value for 'msix-vectors': "
		    "%d; using value of %d\n", data, 0);
		ha->mq_msix_vectors = 0;
	}

	/* Get number of completion threads. */
	if ((data = ql_get_prop(ha, "completion-threads")) == 0xffffffff) {
		ha->completion_thds = 4;
	} else if (data < 256 && data >= 1) {
		ha->completion_thds = (uint8_t)data;
	} else {
		EL(ha, "invalid parameter value for 'completion-threads':"
		    " %d; using default value of %d", data, 4);
		ha->completion_thds = 4;
	}

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_24xx_properties
 *	Copies driver properties to NVRAM or adapter structure.
 *
 *	Driver properties are by design global variables and hidden
 *	completely from administrators. Knowledgeable folks can
 *	override the default values using /etc/system.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	icb:	Init control block structure pointer.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_24xx_properties(ql_adapter_state_t *ha, ql_init_24xx_cb_t *icb)
{
	uint32_t	data;

	QL_PRINT_10(ha, "started\n");

	/* Get frame size */
	if ((data = ql_get_prop(ha, "max-frame-length")) == 0xffffffff) {
		data = 2048;
	}
	if (data == 512 || data == 1024 || data == 2048 || data == 2112) {
		icb->max_frame_length[0] = LSB(data);
		icb->max_frame_length[1] = MSB(data);
	} else {
		EL(ha, "invalid parameter value for 'max-frame-length': %d;"
		    " using nvram default of %d\n", data, CHAR_TO_SHORT(
		    icb->max_frame_length[0], icb->max_frame_length[1]));
	}

	/* Get execution throttle. */
	if ((data = ql_get_prop(ha, "execution-throttle")) == 0xffffffff) {
		data = 32;
	}
	if (data != 0 && data < 65536) {
		icb->execution_throttle[0] = LSB(data);
		icb->execution_throttle[1] = MSB(data);
	} else {
		EL(ha, "invalid parameter value for 'execution-throttle':"
		    " %d; using nvram default of %d\n", data, CHAR_TO_SHORT(
		    icb->execution_throttle[0], icb->execution_throttle[1]));
	}

	/* Get Login timeout. */
	if ((data = ql_get_prop(ha, "login-timeout")) == 0xffffffff) {
		data = 3;
	}
	if (data < 65536) {
		icb->login_timeout[0] = LSB(data);
		icb->login_timeout[1] = MSB(data);
	} else {
		EL(ha, "invalid parameter value for 'login-timeout': %d; "
		    "using nvram value of %d\n", data, CHAR_TO_SHORT(
		    icb->login_timeout[0], icb->login_timeout[1]));
	}

	/* Get retry count. */
	if ((data = ql_get_prop(ha, "login-retry-count")) == 0xffffffff) {
		data = 4;
	}
	if (data < 65536) {
		icb->login_retry_count[0] = LSB(data);
		icb->login_retry_count[1] = MSB(data);
	} else {
		EL(ha, "invalid parameter value for 'login-retry-count': "
		    "%d; using nvram value of %d\n", data, CHAR_TO_SHORT(
		    icb->login_retry_count[0], icb->login_retry_count[1]));
	}

	/* Get adapter hard loop ID enable. */
	data = ql_get_prop(ha, "enable-adapter-hard-loop-ID");
	if (data == 0) {
		icb->firmware_options_1[0] =
		    (uint8_t)(icb->firmware_options_1[0] & ~BIT_0);
	} else if (data == 1) {
		icb->firmware_options_1[0] =
		    (uint8_t)(icb->firmware_options_1[0] | BIT_0);
	} else if (data != 0xffffffff) {
		EL(ha, "invalid parameter value for "
		    "'enable-adapter-hard-loop-ID': %d; using nvram value "
		    "of %d\n", data,
		    icb->firmware_options_1[0] & BIT_0 ? 1 : 0);
	}

	/* Get adapter hard loop ID. */
	data = ql_get_prop(ha, "adapter-hard-loop-ID");
	if (data < 126) {
		icb->hard_address[0] = LSB(data);
		icb->hard_address[1] = MSB(data);
	} else if (data != 0xffffffff) {
		EL(ha, "invalid parameter value for 'adapter-hard-loop-ID':"
		    " %d; using nvram value of %d\n", data, CHAR_TO_SHORT(
		    icb->hard_address[0], icb->hard_address[1]));
	}

	/* Get LIP reset. */
	if ((data = ql_get_prop(ha, "enable-LIP-reset-on-bus-reset")) ==
	    0xffffffff) {
		data = 0;
	}
	if (data == 0) {
		ha->cfg_flags &= ~CFG_ENABLE_LIP_RESET;
	} else if (data == 1) {
		ha->cfg_flags |= CFG_ENABLE_LIP_RESET;
	} else {
		EL(ha, "invalid parameter value for "
		    "'enable-LIP-reset-on-bus-reset': %d; using value of 0\n",
		    data);
	}

	/* Get LIP full login. */
	if ((data = ql_get_prop(ha, "enable-LIP-full-login-on-bus-reset")) ==
	    0xffffffff) {
		data = 1;
	}
	if (data == 0) {
		ha->cfg_flags &= ~CFG_ENABLE_FULL_LIP_LOGIN;
	} else if (data == 1) {
		ha->cfg_flags |= CFG_ENABLE_FULL_LIP_LOGIN;
	} else {
		EL(ha, "invalid parameter value for "
		    "'enable-LIP-full-login-on-bus-reset': %d; using nvram "
		    "value of %d\n", data,
		    ha->cfg_flags & CFG_ENABLE_FULL_LIP_LOGIN ? 1 : 0);
	}

	/* Get target reset. */
	if ((data = ql_get_prop(ha, "enable-target-reset-on-bus-reset")) ==
	    0xffffffff) {
		data = 0;
	}
	if (data == 0) {
		ha->cfg_flags &= ~CFG_ENABLE_TARGET_RESET;
	} else if (data == 1) {
		ha->cfg_flags |= CFG_ENABLE_TARGET_RESET;
	} else {
		EL(ha, "invalid parameter value for "
		    "'enable-target-reset-on-bus-reset': %d; using nvram "
		    "value of %d", data,
		    ha->cfg_flags & CFG_ENABLE_TARGET_RESET ? 1 : 0);
	}

	/* Get reset delay. */
	if ((data = ql_get_prop(ha, "reset-delay")) == 0xffffffff) {
		data = 5;
	}
	if (data != 0 && data < 256) {
		ha->loop_reset_delay = (uint8_t)data;
	} else {
		EL(ha, "invalid parameter value for 'reset-delay': %d; "
		    "using nvram value of %d", data, ha->loop_reset_delay);
	}

	/* Get port down retry count. */
	if ((data = ql_get_prop(ha, "port-down-retry-count")) == 0xffffffff) {
		data = 8;
	}
	if (data < 256) {
		ha->port_down_retry_count = (uint16_t)data;
	} else {
		EL(ha, "invalid parameter value for 'port-down-retry-count':"
		    " %d; using nvram value of %d\n", data,
		    ha->port_down_retry_count);
	}

	if (!(CFG_IST(ha, CFG_FCOE_SUPPORT))) {
		uint32_t	conn;

		/* Get connection mode setting. */
		if ((conn = ql_get_prop(ha, "connection-options")) ==
		    0xffffffff) {
			conn = 2;
		}
		if (conn <= 2) {
			icb->firmware_options_2[0] = (uint8_t)
			    (icb->firmware_options_2[0] &
			    ~(BIT_6 | BIT_5 | BIT_4));
			icb->firmware_options_2[0] = (uint8_t)
			    (icb->firmware_options_2[0] | (uint8_t)(conn << 4));
		} else {
			EL(ha, "invalid parameter value for 'connection-"
			    "options': %d; using nvram value of %d\n", conn,
			    (icb->firmware_options_2[0] >> 4) & 0x3);
		}
		conn = icb->firmware_options_2[0] >> 4 & 0x3;
		if (conn == 0 && ha->max_vports > 125) {
			ha->max_vports = 125;
		}

		/* Get data rate setting. */
		if ((data = ql_get_prop(ha, "fc-data-rate")) == 0xffffffff) {
			data = 2;
		}
		if ((CFG_IST(ha, CFG_CTRL_24XX) && data < 4) ||
		    (CFG_IST(ha, CFG_CTRL_25XX) && data < 5) ||
		    (CFG_IST(ha, CFG_CTRL_2783) && data < 6)) {
			if (CFG_IST(ha, CFG_CTRL_2783) && data == 5 &&
			    conn == 0) {
				EL(ha, "invalid parameter value for 'fc-data-"
				    "rate': %d; using nvram value of %d\n",
				    data, 2);
				data = 2;
			}
			icb->firmware_options_3[1] = (uint8_t)
			    (icb->firmware_options_3[1] & 0x1f);
			icb->firmware_options_3[1] = (uint8_t)
			    (icb->firmware_options_3[1] | (uint8_t)(data << 5));
		} else {
			EL(ha, "invalid parameter value for 'fc-data-rate': "
			    "%d; using nvram value of %d\n", data,
			    (icb->firmware_options_3[1] >> 5) & 0x7);
		}
	}

	/* Get IP FW container count. */
	ha->ip_init_ctrl_blk.cb24.cc[0] = LSB(ql_ip_buffer_count);
	ha->ip_init_ctrl_blk.cb24.cc[1] = MSB(ql_ip_buffer_count);

	/* Get IP low water mark. */
	ha->ip_init_ctrl_blk.cb24.low_water_mark[0] = LSB(ql_ip_low_water);
	ha->ip_init_ctrl_blk.cb24.low_water_mark[1] = MSB(ql_ip_low_water);

	ADAPTER_STATE_LOCK(ha);

	/* Get enable flash load. */
	if ((data = ql_get_prop(ha, "enable-flash-load")) == 0xffffffff ||
	    data == 0) {
		ha->cfg_flags &= ~CFG_LOAD_FLASH_FW;
	} else if (data == 1) {
		ha->cfg_flags |= CFG_LOAD_FLASH_FW;
	} else {
		EL(ha, "invalid parameter value for 'enable-flash-load': "
		    "%d; using default value of 0\n", data);
	}

	/* Enable firmware extended tracing */
	if ((data = ql_get_prop(ha, "enable-fwexttrace")) != 0xffffffff) {
		if (data != 0) {
			ha->cfg_flags |= CFG_ENABLE_FWEXTTRACE;
		}
	}

	/* Enable firmware fc tracing */
	if ((data = ql_get_prop(ha, "enable-fwfcetrace")) != 0xffffffff) {
		ha->cfg_flags |= CFG_ENABLE_FWFCETRACE;
		ha->fwfcetraceopt = data;
	}

	/* Enable fast timeout */
	if ((data = ql_get_prop(ha, "enable-fasttimeout")) != 0xffffffff) {
		if (data != 0) {
			ha->cfg_flags |= CFG_FAST_TIMEOUT;
		}
	}

	ql_common_properties(ha);

	ADAPTER_STATE_UNLOCK(ha);

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_get_prop
 *	Get property value from configuration file.
 *
 * Input:
 *	ha= adapter state pointer.
 *	string = property string pointer.
 *
 * Returns:
 *	0xFFFFFFFF = no property else property value.
 *
 * Context:
 *	Kernel context.
 */
uint32_t
ql_get_prop(ql_adapter_state_t *ha, char *string)
{
	char		buf[256];
	uint32_t	data = 0xffffffff;

	/*
	 * Look for a adapter instance NPIV (virtual port) specific parameter
	 */
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		(void) sprintf(buf, "hba%d-vp%d-%s", ha->instance,
		    ha->vp_index, string);
		/*LINTED [Solaris DDI_DEV_T_ANY Lint warning]*/
		data = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY, ha->dip, 0,
		    buf, (int)0xffffffff);
	}

	/*
	 * Get adapter instance parameter if a vp specific one isn't found.
	 */
	if (data == 0xffffffff) {
		(void) sprintf(buf, "hba%d-%s", ha->instance, string);
		/*LINTED [Solaris DDI_DEV_T_ANY Lint warning]*/
		data = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY, ha->dip,
		    0, buf, (int)0xffffffff);
	}

	/* Adapter instance parameter found? */
	if (data == 0xffffffff) {
		/* No, get default parameter. */
		/*LINTED [Solaris DDI_DEV_T_ANY Lint warning]*/
		data = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY, ha->dip, 0,
		    string, (int)0xffffffff);
	}

	return (data);
}

/*
 * ql_check_isp_firmware
 *	Checks if using already loaded RISC code or drivers copy.
 *	If using already loaded code, save a copy of it.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_check_isp_firmware(ql_adapter_state_t *ha)
{
	int		rval;
	uint16_t	word_count;
	uint32_t	byte_count;
	uint32_t	fw_size, *lptr;
	caddr_t		bufp;
	uint16_t	risc_address = (uint16_t)ha->risc_fw[0].addr;

	QL_PRINT_10(ha, "started\n");

	/* Test for firmware running. */
	if (CFG_IST(ha, CFG_CTRL_82XX)) {
		if ((rval = ql_8021_fw_chk(ha)) == QL_SUCCESS) {
			rval = ql_start_firmware(ha);
		}
	} else if (CFG_IST(ha, CFG_CTRL_278083)) {
		ha->dev_state = NX_DEV_READY;
		if (ha->rom_status == MBS_ROM_FW_RUNNING) {
			EL(ha, "ISP ROM Status = MBS_ROM_FW_RUNNING\n");
			rval = QL_SUCCESS;
		} else if (ha->rom_status == MBS_ROM_IDLE) {
			EL(ha, "ISP ROM Status = MBS_ROM_IDLE\n");
			rval = QL_FUNCTION_FAILED;
		} else {
			EL(ha, "ISP ROM Status, mbx0=%xh\n", ha->rom_status);
			rval = QL_FUNCTION_FAILED;
		}
	} else if (CFG_IST(ha, CFG_DISABLE_RISC_CODE_LOAD)) {
		ha->dev_state = NX_DEV_READY;
		if (ha->risc_code != NULL) {
			kmem_free(ha->risc_code, ha->risc_code_size);
			ha->risc_code = NULL;
			ha->risc_code_size = 0;
		}

		/* Get RISC code length. */
		rval = ql_rd_risc_ram(ha, risc_address + 3,
		    ha->req_q[0]->req_ring.cookie.dmac_laddress, 1);
		if (rval == QL_SUCCESS) {
			lptr = (uint32_t *)ha->req_q[0]->req_ring.bp;
			fw_size = *lptr << 1;

			if ((bufp = kmem_alloc(fw_size, KM_SLEEP)) != NULL) {
				ha->risc_code_size = fw_size;
				ha->risc_code = bufp;
				ha->fw_transfer_size = 128;

				/* Dump RISC code. */
				do {
					if (fw_size > ha->fw_transfer_size) {
						byte_count =
						    ha->fw_transfer_size;
					} else {
						byte_count = fw_size;
					}

					word_count =
					    (uint16_t)(byte_count >> 1);

					rval = ql_rd_risc_ram(ha, risc_address,
					    ha->req_q[0]->req_ring.cookie.
					    dmac_laddress, word_count);
					if (rval != QL_SUCCESS) {
						kmem_free(ha->risc_code,
						    ha->risc_code_size);
						ha->risc_code = NULL;
						ha->risc_code_size = 0;
						break;
					}

					(void) ddi_dma_sync(
					    ha->req_q[0]->req_ring.dma_handle,
					    0, byte_count,
					    DDI_DMA_SYNC_FORKERNEL);
					ddi_rep_get16(
					    ha->req_q[0]->req_ring.acc_handle,
					    (uint16_t *)bufp, (uint16_t *)
					    ha->req_q[0]->req_ring.bp,
					    word_count, DDI_DEV_AUTOINCR);

					risc_address += word_count;
					fw_size -= byte_count;
					bufp	+= byte_count;
				} while (fw_size != 0);
			}
			rval = QL_FUNCTION_FAILED;
		}
	} else {
		ha->dev_state = NX_DEV_READY;
		rval = QL_FUNCTION_FAILED;
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "Load RISC code\n");
	} else {
		/*EMPTY*/
		QL_PRINT_10(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_load_isp_firmware
 *	Load and start RISC firmware.
 *	Uses request ring for DMA buffer.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_load_isp_firmware(ql_adapter_state_t *vha)
{
	caddr_t			risc_code_address;
	uint32_t		risc_address, risc_code_size;
	int			rval = QL_FUNCTION_FAILED;
	uint32_t		word_count, cnt;
	size_t			byte_count;
	ql_adapter_state_t	*ha = vha->pha;

	QL_PRINT_10(ha, "started\n");

	if (CFG_IST(ha, CFG_CTRL_82XX)) {
		rval = ql_8021_reset_fw(ha) == NX_DEV_READY ?
		    QL_SUCCESS : QL_FUNCTION_FAILED;
	} else {
		if (CFG_IST(ha, CFG_CTRL_81XX)) {
			ql_mps_reset(ha);
		}

		if (CFG_IST(ha, CFG_LOAD_FLASH_FW)) {
			QL_PRINT_10(ha, "CFG_LOAD_FLASH_FW exit\n");
			return (ql_load_flash_fw(ha));
		}

		if (CFG_IST(ha, CFG_CTRL_27XX)) {
			(void) ql_2700_get_module_dmp_template(ha);
		}

		/* Load firmware segments */
		for (cnt = 0; cnt < MAX_RISC_CODE_SEGMENTS &&
		    ha->risc_fw[cnt].code != NULL; cnt++) {

			risc_code_address = ha->risc_fw[cnt].code;
			risc_address = ha->risc_fw[cnt].addr;
			if ((risc_address = ha->risc_fw[cnt].addr) == 0) {
				continue;
			}
			risc_code_size = ha->risc_fw[cnt].length;

			while (risc_code_size) {
				if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
					word_count = ha->fw_transfer_size >> 2;
					if (word_count > risc_code_size) {
						word_count = risc_code_size;
					}
					byte_count = word_count << 2;

					ddi_rep_put32(
					    ha->req_q[0]->req_ring.acc_handle,
					    (uint32_t *)risc_code_address,
					    (uint32_t *)
					    ha->req_q[0]->req_ring.bp,
					    word_count, DDI_DEV_AUTOINCR);
				} else {
					word_count = ha->fw_transfer_size >> 1;
					if (word_count > risc_code_size) {
						word_count = risc_code_size;
					}
					byte_count = word_count << 1;

					ddi_rep_put16(
					    ha->req_q[0]->req_ring.acc_handle,
					    (uint16_t *)risc_code_address,
					    (uint16_t *)
					    ha->req_q[0]->req_ring.bp,
					    word_count, DDI_DEV_AUTOINCR);
				}

				(void) ddi_dma_sync(
				    ha->req_q[0]->req_ring.dma_handle,
				    0, byte_count, DDI_DMA_SYNC_FORDEV);

				rval = ql_wrt_risc_ram(ha, risc_address,
				    ha->req_q[0]->req_ring.cookie.dmac_laddress,
				    word_count);
				if (rval != QL_SUCCESS) {
					EL(ha, "failed, load=%xh\n", rval);
					cnt = MAX_RISC_CODE_SEGMENTS;
					break;
				}

				risc_address += word_count;
				risc_code_size -= word_count;
				risc_code_address += byte_count;
			}
		}
	}
	bzero(ha->req_q[0]->req_ring.bp, ha->fw_transfer_size);

	/* Start firmware. */
	if (rval == QL_SUCCESS) {
		rval = ql_start_firmware(ha);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_10(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_load_flash_fw
 *	Gets ISP24xx firmware from flash and loads ISP.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 */
static int
ql_load_flash_fw(ql_adapter_state_t *ha)
{
	int		rval;
	uint8_t		seg_cnt;
	uint32_t	risc_address, xfer_size, count,	*bp, faddr;
	uint32_t	risc_code_size = 0;

	QL_PRINT_10(ha, "started\n");

	if (CFG_IST(ha, CFG_CTRL_278083)) {
		if ((rval = ql_load_flash_image(ha)) != QL_SUCCESS) {
			EL(ha, "load_flash_image status=%xh\n", rval);
		} else if (CFG_IST(ha, CFG_CTRL_27XX) &&
		    (rval = ql_2700_get_flash_dmp_template(ha)) !=
		    QL_SUCCESS) {
			EL(ha, "get_flash_dmp_template status=%xh\n", rval);
		}
	} else {
		faddr = ha->flash_data_addr | ha->flash_fw_addr;

		for (seg_cnt = 0; seg_cnt < 2; seg_cnt++) {
			xfer_size = ha->fw_transfer_size >> 2;
			do {
				GLOBAL_HW_LOCK();

				/* Read data from flash. */
				bp = (uint32_t *)ha->req_q[0]->req_ring.bp;
				for (count = 0; count < xfer_size; count++) {
					rval = ql_24xx_read_flash(ha, faddr++,
					    bp);
					if (rval != QL_SUCCESS) {
						break;
					}
					ql_chg_endian((uint8_t *)bp++, 4);
				}

				GLOBAL_HW_UNLOCK();

				if (rval != QL_SUCCESS) {
					EL(ha, "24xx_read_flash failed=%xh\n",
					    rval);
					break;
				}

				if (risc_code_size == 0) {
					bp = (uint32_t *)
					    ha->req_q[0]->req_ring.bp;
					risc_address = bp[2];
					risc_code_size = bp[3];
					ha->risc_fw[seg_cnt].addr =
					    risc_address;
				}

				if (risc_code_size < xfer_size) {
					faddr -= xfer_size - risc_code_size;
					xfer_size = risc_code_size;
				}

				(void) ddi_dma_sync(
				    ha->req_q[0]->req_ring.dma_handle,
				    0, xfer_size << 2, DDI_DMA_SYNC_FORDEV);

				rval = ql_wrt_risc_ram(ha, risc_address,
				    ha->req_q[0]->req_ring.cookie.dmac_laddress,
				    xfer_size);
				if (rval != QL_SUCCESS) {
					EL(ha, "ql_wrt_risc_ram failed=%xh\n",
					    rval);
					break;
				}

				risc_address += xfer_size;
				risc_code_size -= xfer_size;
			} while (risc_code_size);

			if (rval != QL_SUCCESS) {
				break;
			}
		}
	}

	/* Start firmware. */
	if (rval == QL_SUCCESS) {
		rval = ql_start_firmware(ha);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_10(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_start_firmware
 *	Starts RISC code.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_start_firmware(ql_adapter_state_t *vha)
{
	int			rval, rval2;
	uint32_t		data;
	ql_mbx_data_t		mr = {0};
	ql_adapter_state_t	*ha = vha->pha;
	ql_init_24xx_cb_t	*icb =
	    (ql_init_24xx_cb_t *)&ha->init_ctrl_blk.cb24;

	QL_PRINT_10(ha, "started\n");

	if (CFG_IST(ha, CFG_CTRL_82XX)) {
		/* Save firmware version. */
		rval = ql_get_fw_version(ha, &mr, MAILBOX_TOV);
		ha->fw_major_version = mr.mb[1];
		ha->fw_minor_version = mr.mb[2];
		ha->fw_subminor_version = mr.mb[3];
		ha->fw_attributes = mr.mb[6];
	} else if ((rval = ql_verify_checksum(ha)) == QL_SUCCESS) {
		/* Verify checksum of loaded RISC code. */
		/* Start firmware execution. */
		(void) ql_execute_fw(ha);

		/* Save firmware version. */
		(void) ql_get_fw_version(ha, &mr, MAILBOX_TOV);
		ha->fw_major_version = mr.mb[1];
		ha->fw_minor_version = mr.mb[2];
		ha->fw_subminor_version = mr.mb[3];
		ha->fw_ext_memory_end = SHORT_TO_LONG(mr.mb[4], mr.mb[5]);
		ha->fw_ext_memory_size = ((ha->fw_ext_memory_end -
		    0x100000) + 1) * 4;
		if (CFG_IST(ha, CFG_CTRL_278083)) {
			ha->fw_attributes = SHORT_TO_LONG(mr.mb[6], mr.mb[15]);
			ha->phy_fw_major_version = LSB(mr.mb[13]);
			ha->phy_fw_minor_version = MSB(mr.mb[14]);
			ha->phy_fw_subminor_version = LSB(mr.mb[14]);
			ha->fw_ext_attributes = SHORT_TO_LONG(mr.mb[16],
			    mr.mb[17]);
		} else {
			ha->fw_attributes = mr.mb[6];
			ha->phy_fw_major_version = LSB(mr.mb[8]);
			ha->phy_fw_minor_version = MSB(mr.mb[9]);
			ha->phy_fw_subminor_version = LSB(mr.mb[9]);
			ha->mpi_capability_list =
			    SHORT_TO_LONG(mr.mb[13], mr.mb[12]);
		}
		ha->mpi_fw_major_version = LSB(mr.mb[10]);
		ha->mpi_fw_minor_version = MSB(mr.mb[11]);
		ha->mpi_fw_subminor_version = LSB(mr.mb[11]);
		if (CFG_IST(ha, CFG_CTRL_27XX)) {
			ha->fw_shared_ram_start =
			    SHORT_TO_LONG(mr.mb[18], mr.mb[19]);
			ha->fw_shared_ram_end =
			    SHORT_TO_LONG(mr.mb[20], mr.mb[21]);
			ha->fw_ddr_ram_start =
			    SHORT_TO_LONG(mr.mb[22], mr.mb[23]);
			ha->fw_ddr_ram_end =
			    SHORT_TO_LONG(mr.mb[24], mr.mb[25]);
		}
		if (CFG_IST(ha, CFG_FLASH_ACC_SUPPORT)) {
			if ((rval2 = ql_flash_access(ha, FAC_GET_SECTOR_SIZE,
			    0, 0, &data)) == QL_SUCCESS) {
				ha->xioctl->fdesc.block_size = data << 2;
				QL_PRINT_10(ha, "fdesc.block_size="
				    "%xh\n",
				    ha->xioctl->fdesc.block_size);
			} else {
				EL(ha, "flash_access status=%xh\n", rval2);
			}
		}

		/* Set Serdes Transmit Parameters. */
		if (CFG_IST(ha, CFG_CTRL_24XX) && ha->serdes_param[0] & BIT_0) {
			mr.mb[1] = ha->serdes_param[0];
			mr.mb[2] = ha->serdes_param[1];
			mr.mb[3] = ha->serdes_param[2];
			mr.mb[4] = ha->serdes_param[3];
			(void) ql_serdes_param(ha, &mr);
		}
	}
	/* ETS workaround */
	if (CFG_IST(ha, CFG_CTRL_81XX) && ql_enable_ets) {
		if (ql_get_firmware_option(ha, &mr) == QL_SUCCESS) {
			mr.mb[2] = (uint16_t)
			    (mr.mb[2] | FO2_FCOE_512_MAX_MEM_WR_BURST);
			(void) ql_set_firmware_option(ha, &mr);
		}
	}

	if (ha->flags & MULTI_QUEUE) {
		QL_PRINT_10(ha, "MULTI_QUEUE\n");
		icb->msi_x_vector[0] = LSB(ha->rsp_queues[0]->msi_x_vector);
		icb->msi_x_vector[1] = MSB(ha->rsp_queues[0]->msi_x_vector);
		if (ha->iflags & IFLG_INTR_MSIX &&
		    CFG_IST(ha, CFG_NO_INTR_HSHAKE_SUP)) {
			QL_PRINT_10(ha, "NO_INTR_HANDSHAKE\n");
			ADAPTER_STATE_LOCK(ha);
			ha->flags |= NO_INTR_HANDSHAKE;
			ADAPTER_STATE_UNLOCK(ha);
			icb->firmware_options_2[2] = (uint8_t)
			    (icb->firmware_options_2[2] & ~(BIT_6 | BIT_5));
			icb->firmware_options_2[2] = (uint8_t)
			    (icb->firmware_options_2[2] | BIT_7);
		} else {
			icb->firmware_options_2[2] = (uint8_t)
			    (icb->firmware_options_2[2] & ~BIT_5);
			icb->firmware_options_2[2] = (uint8_t)
			    (icb->firmware_options_2[2] | BIT_7 | BIT_6);
		}
	} else {
		icb->firmware_options_2[2] = (uint8_t)
		    (icb->firmware_options_2[2] & ~(BIT_7 | BIT_5));
		icb->firmware_options_2[2] = (uint8_t)
		    (icb->firmware_options_2[2] | BIT_6);
	}
	icb->firmware_options_2[3] = (uint8_t)
	    (icb->firmware_options_2[3] & ~(BIT_1 | BIT_0));

	/* Set fw execution throttle. */
	if (CFG_IST(ha, CFG_CTRL_22XX) ||
	    ql_get_resource_cnts(ha, &mr) != QL_SUCCESS) {
		icb->execution_throttle[0] = 0xff;
		icb->execution_throttle[1] = 0xff;
	} else {
		icb->execution_throttle[0] = LSB(mr.mb[6]);
		icb->execution_throttle[1] = MSB(mr.mb[6]);
	}
	EL(ha, "icb->execution_throttle %d\n",
	    CHAR_TO_SHORT(icb->execution_throttle[0],
	    icb->execution_throttle[1]));

	if (rval != QL_SUCCESS) {
		ha->task_daemon_flags &= ~FIRMWARE_LOADED;
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		ha->task_daemon_flags |= FIRMWARE_LOADED;
		QL_PRINT_10(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_set_cache_line
 *	Sets PCI cache line parameter.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_set_cache_line(ql_adapter_state_t *ha)
{
	QL_PRINT_3(ha, "started\n");

	/* Set the cache line. */
	if (CFG_IST(ha->pha, CFG_SET_CACHE_LINE_SIZE_1)) {
		/* Set cache line register. */
		ql_pci_config_put8(ha->pha, PCI_CONF_CACHE_LINESZ, 1);
	}

	QL_PRINT_3(ha, "done\n");

	return (QL_SUCCESS);
}

/*
 * ql_init_rings
 *	Initializes firmware and ring pointers.
 *
 *	Beginning of response ring has initialization control block
 *	already built by nvram config routine.
 *
 * Input:
 *	ha =			adapter state pointer.
 *	ha->req_q =		request rings
 *	ha->rsp_queues =	response rings
 *	ha->init_ctrl_blk =	initialization control block
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_init_rings(ql_adapter_state_t *vha2)
{
	int			rval, rval2;
	uint16_t		index;
	ql_mbx_data_t		mr;
	ql_adapter_state_t	*ha = vha2->pha;

	QL_PRINT_3(ha, "started\n");

	/* Clear outstanding commands array. */
	for (index = 0; index < ha->osc_max_cnt; index++) {
		ha->outstanding_cmds[index] = NULL;
	}
	ha->osc_index = 1;

	ha->pending_cmds.first = NULL;
	ha->pending_cmds.last = NULL;

	/* Initialize firmware. */
	ha->req_q[0]->req_ring_ptr = ha->req_q[0]->req_ring.bp;
	ha->req_q[0]->req_ring_index = 0;
	ha->req_q[0]->req_q_cnt = REQUEST_ENTRY_CNT - 1;
	ha->rsp_queues[0]->rsp_ring_ptr = ha->rsp_queues[0]->rsp_ring.bp;
	ha->rsp_queues[0]->rsp_ring_index = 0;

	if (ha->flags & VP_ENABLED) {
		ql_adapter_state_t	*vha;
		ql_init_24xx_cb_t	*icb = &ha->init_ctrl_blk.cb24;

		bzero(icb->vp_count,
		    ((uintptr_t)icb + sizeof (ql_init_24xx_cb_t)) -
		    (uintptr_t)icb->vp_count);
		icb->vp_count[0] = ha->max_vports - 1;

		/* Allow connection option 2. */
		icb->global_vp_option[0] = BIT_1;

		/* Setup default options for all ports. */
		for (index = 0; index < ha->max_vports; index++) {
			icb->vpc[index].options = VPO_TARGET_MODE_DISABLED |
			    VPO_INITIATOR_MODE_ENABLED;
		}
		/* Setup enabled ports. */
		for (vha = ha->vp_next; vha != NULL; vha = vha->vp_next) {
			if (vha->vp_index == 0 ||
			    vha->vp_index >= ha->max_vports) {
				continue;
			}

			index = (uint8_t)(vha->vp_index - 1);
			bcopy(vha->loginparams.node_ww_name.raw_wwn,
			    icb->vpc[index].node_name, 8);
			bcopy(vha->loginparams.nport_ww_name.raw_wwn,
			    icb->vpc[index].port_name, 8);

			if (vha->flags & VP_ENABLED) {
				icb->vpc[index].options = (uint8_t)
				    (icb->vpc[index].options | VPO_ENABLED);
			}
		}
	}

	for (index = 0; index < 2; index++) {
		rval = ql_init_firmware(ha);
		if (rval == QL_COMMAND_ERROR) {
			EL(ha, "stopping firmware\n");
			(void) ql_stop_firmware(ha);
		} else {
			break;
		}
	}

	if (rval == QL_SUCCESS && CFG_IST(ha, CFG_ISP_FW_TYPE_1)) {
		/* Tell firmware to enable MBA_PORT_BYPASS_CHANGED event */
		rval = ql_get_firmware_option(ha, &mr);
		if (rval == QL_SUCCESS) {
			mr.mb[1] = (uint16_t)(mr.mb[1] | BIT_9);
			mr.mb[2] = 0;
			mr.mb[3] = BIT_10;
			rval = ql_set_firmware_option(ha, &mr);
		}
	}

	if ((rval == QL_SUCCESS) && (CFG_IST(ha, CFG_ENABLE_FWFCETRACE))) {
		/* Firmware Fibre Channel Event Trace Buffer */
		if ((rval2 = ql_get_dma_mem(ha, &ha->fwfcetracebuf, FWFCESIZE,
		    LITTLE_ENDIAN_DMA, QL_DMA_RING_ALIGN)) != QL_SUCCESS) {
			EL(ha, "fcetrace buffer alloc failed: %xh\n", rval2);
		} else {
			if ((rval2 = ql_fw_etrace(ha, &ha->fwfcetracebuf,
			    FTO_FCE_TRACE_ENABLE, NULL)) != QL_SUCCESS) {
				EL(ha, "fcetrace enable failed: %xh\n", rval2);
				ql_free_phys(ha, &ha->fwfcetracebuf);
			}
		}
	}

	if ((rval == QL_SUCCESS) && (CFG_IST(ha, CFG_ENABLE_FWEXTTRACE))) {
		/* Firmware Extended Trace Buffer */
		if ((rval2 = ql_get_dma_mem(ha, &ha->fwexttracebuf, FWEXTSIZE,
		    LITTLE_ENDIAN_DMA, QL_DMA_RING_ALIGN)) != QL_SUCCESS) {
			EL(ha, "exttrace buffer alloc failed: %xh\n", rval2);
		} else {
			if ((rval2 = ql_fw_etrace(ha, &ha->fwexttracebuf,
			    FTO_EXT_TRACE_ENABLE, NULL)) != QL_SUCCESS) {
				EL(ha, "exttrace enable failed: %xh\n", rval2);
				ql_free_phys(ha, &ha->fwexttracebuf);
			}
		}
	}

	if (rval == QL_SUCCESS && CFG_IST(ha, CFG_CTRL_MENLO)) {
		ql_mbx_iocb_t	*pkt;
		clock_t		timer;

		/* Wait for firmware login of menlo. */
		for (timer = 3000; timer; timer--) {
			if (ha->flags & MENLO_LOGIN_OPERATIONAL) {
				break;
			}

			if (!(ha->flags & INTERRUPTS_ENABLED) ||
			    ddi_in_panic()) {
				if (INTERRUPT_PENDING(ha)) {
					(void) ql_isr((caddr_t)ha);
					INTR_LOCK(ha);
					ha->intr_claimed = B_TRUE;
					INTR_UNLOCK(ha);
				}
			}

			/* Delay for 1 tick (10 milliseconds). */
			ql_delay(ha, 10000);
		}

		if (timer == 0) {
			rval = QL_FUNCTION_TIMEOUT;
		} else {
			pkt = kmem_zalloc(sizeof (ql_mbx_iocb_t), KM_SLEEP);
			if (pkt == NULL) {
				EL(ha, "failed, kmem_zalloc\n");
				rval = QL_MEMORY_ALLOC_FAILED;
			} else {
				pkt->mvfy.entry_type = VERIFY_MENLO_TYPE;
				pkt->mvfy.entry_count = 1;
				pkt->mvfy.options_status =
				    LE_16(VMF_DO_NOT_UPDATE_FW);

				rval = ql_issue_mbx_iocb(ha, (caddr_t)pkt,
				    sizeof (ql_mbx_iocb_t));
				LITTLE_ENDIAN_16(&pkt->mvfy.options_status);
				LITTLE_ENDIAN_16(&pkt->mvfy.failure_code);

				if (rval != QL_SUCCESS ||
				    (pkt->mvfy.entry_status & 0x3c) != 0 ||
				    pkt->mvfy.options_status != CS_COMPLETE) {
					EL(ha, "failed, status=%xh, es=%xh, "
					    "cs=%xh, fc=%xh\n", rval,
					    pkt->mvfy.entry_status & 0x3c,
					    pkt->mvfy.options_status,
					    pkt->mvfy.failure_code);
					if (rval == QL_SUCCESS) {
						rval = QL_FUNCTION_FAILED;
					}
				}

				kmem_free(pkt, sizeof (ql_mbx_iocb_t));
			}
		}
	}

	if (rval != QL_SUCCESS) {
		TASK_DAEMON_LOCK(ha);
		ha->task_daemon_flags &= ~FIRMWARE_UP;
		TASK_DAEMON_UNLOCK(ha);
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		TASK_DAEMON_LOCK(ha);
		ha->task_daemon_flags |= FIRMWARE_UP;
		TASK_DAEMON_UNLOCK(ha);
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_fw_ready
 *	Waits for firmware ready. If firmware becomes ready
 *	device queues and RISC code are synchronized.
 *
 * Input:
 *	ha = adapter state pointer.
 *	secs = max wait time, in seconds (0-255).
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_fw_ready(ql_adapter_state_t *ha, uint8_t secs)
{
	ql_mbx_data_t	mr;
	clock_t		timer, login_wait, wait;
	clock_t		dly = 250000;
	clock_t		sec_delay = MICROSEC / dly;
	int		rval = QL_FUNCTION_FAILED;
	uint16_t	state[6] = {0};

	QL_PRINT_3(ha, "started\n");

	login_wait = ha->r_a_tov * 2 * sec_delay;
	timer = wait = secs * sec_delay;
	state[0] = 0xffff;

	/* Wait for ISP to finish LIP */
	while (login_wait != 0 && wait != 0 &&
	    !(ha->task_daemon_flags & ISP_ABORT_NEEDED) &&
	    !(ha->flags & MPI_RESET_NEEDED)) {

		rval = ql_get_firmware_state(ha, &mr);
		if (rval == QL_SUCCESS) {
			if (mr.mb[1] != FSTATE_READY) {
				if (mr.mb[1] == FSTATE_LOSS_SYNC &&
				    mr.mb[4] == FSTATE_MPI_NIC_ERROR &&
				    CFG_IST(ha, CFG_FCOE_SUPPORT)) {
					EL(ha, "mpi_nic_error, "
					    "isp_abort_needed\n");
					ADAPTER_STATE_LOCK(ha);
					ha->flags |= MPI_RESET_NEEDED;
					ADAPTER_STATE_UNLOCK(ha);
					if (!(ha->task_daemon_flags &
					    ABORT_ISP_ACTIVE)) {
						TASK_DAEMON_LOCK(ha);
						ha->task_daemon_flags |=
						    ISP_ABORT_NEEDED;
						TASK_DAEMON_UNLOCK(ha);
					}
				}
				if (mr.mb[1] != FSTATE_WAIT_LOGIN) {
					timer = --wait;
				} else {
					timer = --login_wait;
				}
				rval = QL_FUNCTION_FAILED;
			} else {
				/* Firmware is ready. Get 2 * R_A_TOV. */
				rval = ql_get_timeout_parameters(ha,
				    &ha->r_a_tov);
				if (rval != QL_SUCCESS) {
					EL(ha, "failed, get_timeout_param"
					    "=%xh\n", rval);
				}

				/* Configure loop. */
				rval = ql_configure_loop(ha);
				(void) ql_marker(ha, 0, 0, MK_SYNC_ALL);

				if (ha->task_daemon_flags &
				    LOOP_RESYNC_NEEDED) {
					wait--;
					EL(ha, "loop trans; tdf=%xh\n",
					    ha->task_daemon_flags);
				} else {
					break;
				}
			}
		} else {
			break;
		}

		if (state[0] != mr.mb[1] || state[1] != mr.mb[2] ||
		    state[2] != mr.mb[3] || state[3] != mr.mb[4] ||
		    state[4] != mr.mb[5] || state[5] != mr.mb[6]) {
			EL(ha, "mbx1=%xh, mbx2=%xh, mbx3=%xh, mbx4=%xh, "
			    "mbx5=%xh, mbx6=%xh\n", mr.mb[1], mr.mb[2],
			    mr.mb[3], mr.mb[4], mr.mb[5], mr.mb[6]);
			state[0] = mr.mb[1];
			state[1] = mr.mb[2];
			state[2] = mr.mb[3];
			state[3] = mr.mb[4];
			state[4] = mr.mb[5];
			state[5] = mr.mb[6];
		}

		/* Delay for a tick if waiting. */
		if (timer != 0) {
			if (timer % 4 == 0) {
				delay(drv_usectohz(dly));
			} else {
				drv_usecwait(dly);
			}
		} else {
			rval = QL_FUNCTION_TIMEOUT;
		}
	}

	if (rval != QL_SUCCESS) {
		if ((ha->task_daemon_flags & ISP_ABORT_NEEDED ||
		    ha->flags & MPI_RESET_NEEDED) &&
		    ha->task_daemon_flags & LOOP_RESYNC_NEEDED) {
			TASK_DAEMON_LOCK(ha);
			ha->task_daemon_flags &= ~LOOP_RESYNC_NEEDED;
			TASK_DAEMON_UNLOCK(ha);
		}
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_configure_loop
 *	Setup configurations based on loop.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_configure_loop(ql_adapter_state_t *ha)
{
	int			rval = QL_SUCCESS;
	ql_adapter_state_t	*vha;

	QL_PRINT_10(ha, "started\n");

	for (vha = ha; vha != NULL; vha = vha->vp_next) {
		TASK_DAEMON_LOCK(ha);
		if (!(vha->task_daemon_flags & LOOP_RESYNC_NEEDED) &&
		    vha->vp_index != 0 &&
		    (!(vha->flags & VP_ENABLED) ||
		    vha->flags & VP_ID_NOT_ACQUIRED)) {
			TASK_DAEMON_UNLOCK(ha);
			continue;
		}
		vha->task_daemon_flags &= ~LOOP_RESYNC_NEEDED;
		TASK_DAEMON_UNLOCK(ha);

		rval = ql_configure_hba(vha);
		if (rval == QL_SUCCESS && !(ha->task_daemon_flags &
		    (LOOP_RESYNC_NEEDED | LOOP_DOWN))) {
			rval = ql_configure_device_d_id(vha);
			if (rval == QL_SUCCESS && !(ha->task_daemon_flags &
			    (LOOP_RESYNC_NEEDED | LOOP_DOWN))) {
				(void) ql_configure_fabric(vha);
			}
		}
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_10(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_configure_n_port_info
 *	Setup configurations based on N port 2 N port topology.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 *	ADAPTER_STATE_LOCK must be already obtained
 */
static void
ql_configure_n_port_info(ql_adapter_state_t *ha)
{
	ql_tgt_t		tmp_tq;
	ql_tgt_t		*tq;
	uint8_t			*cb_port_name;
	ql_link_t		*link;
	int			index, rval;
	uint16_t		loop_id = 0;
	uint32_t		found = 0;
	ql_dev_id_list_t	*list;
	uint32_t		list_size;
	ql_mbx_data_t		mr;
	port_id_t		d_id = {0, 0, 0, 0};

	QL_PRINT_10(ha, "started\n");

	/* Free existing target queues. */
	for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
		link = ha->dev[index].first;
		while (link != NULL) {
			tq = link->base_address;
			link = link->next;

			/* workaround FW issue, do implicit logout */
			/* Never logo to the reused loopid!! */
			if ((tq->loop_id != 0x7ff) &&
			    (tq->loop_id != 0x7fe)) {
				if (found == 0) {
					rval = ql_get_port_database(ha,
					    tq, PDF_NONE);
					if ((rval == QL_SUCCESS) &&
					    (tq->master_state ==
					    PD_STATE_PORT_LOGGED_IN)) {
						EL(ha, "nport id (%xh) "
						    "loop_id=%xh "
						    "reappeared\n",
						    tq->d_id.b24,
						    tq->loop_id);
						bcopy((void *)&tq->port_name[0],
						    (void *)&ha->n_port->
						    port_name[0],
						    8);
						bcopy((void *)&tq->node_name[0],
						    (void *)&ha->n_port->
						    node_name[0],
						    8);
						ha->n_port->d_id.b24 =
						    tq->d_id.b24;
						found = 1;
						continue;
					}
				}
				(void) ql_logout_fabric_port(ha, tq);
			}

			tq->loop_id = PORT_NO_LOOP_ID;
		}
	}

	if (found == 1) {
		QL_PRINT_10(ha, "done found\n");
		return;
	}

	tq = &tmp_tq;

	/*
	 * If the N_Port's WWPN is larger than our's then it has the
	 * N_Port login initiative.  It will have determined that and
	 * logged in with the firmware.  This results in a device
	 * database entry.  In this situation we will later send up a PLOGI
	 * by proxy for the N_Port to get things going.
	 *
	 * If the N_Ports WWPN is smaller then the firmware has the
	 * N_Port login initiative and does a FLOGI in order to obtain the
	 * N_Ports WWNN and WWPN.  These names are required later
	 * during Leadvilles FLOGI.  No PLOGI is done by the firmware in
	 * anticipation of a PLOGI via the driver from the upper layers.
	 * Upon reciept of said PLOGI the driver issues an ELS PLOGI
	 * pass-through command and the firmware assumes the s_id
	 * and the N_Port assumes the d_id and Bob's your uncle.
	 */

	/*
	 * In N port 2 N port topology the FW provides a port database entry at
	 * loop_id 0x7fe which allows us to acquire the Ports WWPN.
	 */
	tq->d_id.b.al_pa = 0;
	tq->d_id.b.area = 0;
	tq->d_id.b.domain = 0;
	tq->loop_id = 0x7fe;

	rval = ql_get_port_database(ha, tq, PDF_NONE);

	/*
	 * Only collect the P2P remote port information in the case of
	 * QL_SUCCESS. FW should have always logged in (flogi) to remote
	 * port at this point.
	 */
	if (rval == QL_SUCCESS) {
		cb_port_name = &ha->loginparams.nport_ww_name.raw_wwn[0];

		if ((ql_wwn_cmp(ha, (la_wwn_t *)&tq->port_name[0],
		    (la_wwn_t *)cb_port_name) == 1)) {
			EL(ha, "target port has N_Port login initiative\n");
		} else {
			EL(ha, "host port has N_Port login initiative\n");
		}

		/* Capture the N Ports WWPN */

		bcopy((void *)&tq->port_name[0],
		    (void *)&ha->n_port->port_name[0], 8);
		bcopy((void *)&tq->node_name[0],
		    (void *)&ha->n_port->node_name[0], 8);

		/* Resolve an n_port_handle */
		ha->n_port->n_port_handle = 0x7fe;

	}

	list_size = sizeof (ql_dev_id_list_t) * DEVICE_LIST_ENTRIES;
	list = (ql_dev_id_list_t *)kmem_zalloc(list_size, KM_SLEEP);

	if (ql_get_id_list(ha, (caddr_t)list, list_size, &mr) ==
	    QL_SUCCESS) {
			/* For the p2p mr.mb[1] must be 1 */
			if (mr.mb[1] == 1) {
				index = 0;
				ql_dev_list(ha, list, index,
				    &d_id, &loop_id);
				ha->n_port->n_port_handle = loop_id;

				tq->loop_id = loop_id;
				tq->d_id.b24 = d_id.b24;
				ha->n_port->d_id.b24 = d_id.b24;
			} else {
				for (index = 0; index <= LAST_LOCAL_LOOP_ID;
				    index++) {
					/* resuse tq */
					tq->loop_id = (uint16_t)index;
					rval = ql_get_port_database(ha, tq,
					    PDF_NONE);
					if (rval == QL_NOT_LOGGED_IN) {
						if (tq->master_state ==
						    PD_STATE_PLOGI_PENDING) {
							ha->n_port->
							    n_port_handle =
							    tq->loop_id;
							ha->n_port->d_id.b24 =
							    tq->hard_addr.b24;
							break;
						}
					} else if (rval == QL_SUCCESS) {
						ha->n_port->n_port_handle =
						    tq->loop_id;
						ha->n_port->d_id.b24 =
						    tq->hard_addr.b24;

						break;
					}
				}
				if (index > LAST_LOCAL_LOOP_ID) {
					EL(ha, "P2P:exceeded last id, "
					    "n_port_handle = %xh\n",
					    ha->n_port->n_port_handle);

					ha->n_port->n_port_handle = 0;
					tq->loop_id = 0;
				}
			}
		} else {
			kmem_free(list, list_size);
			EL(ha, "ql_get_dev_list unsuccessful\n");
			return;
		}

		/* with the tq->loop_id to get the port database */

		rval = ql_get_port_database(ha, tq, PDF_NONE);

		if (rval == QL_NOT_LOGGED_IN) {
			if (tq->master_state == PD_STATE_PLOGI_PENDING) {
				bcopy((void *)&tq->port_name[0],
				    (void *)&ha->n_port->port_name[0], 8);
				bcopy((void *)&tq->node_name[0],
				    (void *)&ha->n_port->node_name[0], 8);
				bcopy((void *)&tq->hard_addr,
				    (void *)&ha->n_port->d_id,
				    sizeof (port_id_t));
				ha->n_port->d_id.b24 = d_id.b24;
			}
		} else if (rval == QL_SUCCESS) {
			bcopy((void *)&tq->port_name[0],
			    (void *)&ha->n_port->port_name[0], 8);
			bcopy((void *)&tq->node_name[0],
			    (void *)&ha->n_port->node_name[0], 8);
			bcopy((void *)&tq->hard_addr,
			    (void *)&ha->n_port->d_id, sizeof (port_id_t));
			ha->n_port->d_id.b24 = d_id.b24;

		}

		kmem_free(list, list_size);

		EL(ha, "d_id = %xh, nport_handle = %xh, tq->loop_id = %xh",
		    tq->d_id.b24, ha->n_port->n_port_handle, tq->loop_id);
}


/*
 * ql_configure_hba
 *	Setup adapter context.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_configure_hba(ql_adapter_state_t *ha)
{
	uint8_t		*bp;
	int		rval;
	uint32_t	state;
	ql_mbx_data_t	mr;

	QL_PRINT_10(ha, "started\n");

	/* Get host addresses. */
	rval = ql_get_adapter_id(ha, &mr);
	if (rval == QL_SUCCESS) {
		ha->topology = (uint8_t)(ha->topology &
		    ~(QL_N_PORT | QL_NL_PORT | QL_F_PORT | QL_FL_PORT));

		/* Save Host d_id, alpa, loop ID. */
		ha->loop_id = mr.mb[1];
		ha->d_id.b.al_pa = LSB(mr.mb[2]);
		ha->d_id.b.area = MSB(mr.mb[2]);
		ha->d_id.b.domain = LSB(mr.mb[3]);
		ha->bbcr_initial = LSB(mr.mb[15]);
		ha->bbcr_runtime = MSB(mr.mb[15]);

		ADAPTER_STATE_LOCK(ha);
		ha->flags &= ~FDISC_ENABLED;
		ADAPTER_STATE_UNLOCK(ha);

		/* Get loop topology. */
		switch (mr.mb[6]) {
		case GID_TOP_NL_PORT:
			ha->topology = (uint8_t)(ha->topology | QL_NL_PORT);
			ha->loop_id = mr.mb[1];
			break;
		case GID_TOP_FL_PORT:
			ha->topology = (uint8_t)(ha->topology | QL_FL_PORT);
			ha->loop_id = mr.mb[1];
			break;
		case GID_TOP_N_PORT:
		case GID_TOP_N_PORT_NO_TGT:
			ha->flags |= POINT_TO_POINT;
			ha->topology = (uint8_t)(ha->topology | QL_N_PORT);
			ha->loop_id = 0xffff;
			if (CFG_IST(ha, CFG_N2N_SUPPORT)) {
				ql_configure_n_port_info(ha);
			}
			break;
		case GID_TOP_F_PORT:
			ha->flags |= POINT_TO_POINT;
			ha->topology = (uint8_t)(ha->topology | QL_F_PORT);
			ha->loop_id = 0xffff;

			/* Get supported option. */
			if (CFG_IST(ha, CFG_ISP_FW_TYPE_2) &&
			    mr.mb[7] & GID_FP_NPIV_SUPPORT) {
				ADAPTER_STATE_LOCK(ha);
				ha->flags |= FDISC_ENABLED;
				ADAPTER_STATE_UNLOCK(ha);
			}
			/* Get VLAN ID, mac address */
			if (CFG_IST(ha, CFG_FCOE_SUPPORT)) {
				ha->flags |= FDISC_ENABLED;
				ha->fabric_params = mr.mb[7];
				ha->fcoe_vlan_id = (uint16_t)(mr.mb[9] & 0xfff);
				ha->fcoe_fcf_idx = mr.mb[10];
				ha->fcoe_vnport_mac[5] = MSB(mr.mb[11]);
				ha->fcoe_vnport_mac[4] = LSB(mr.mb[11]);
				ha->fcoe_vnport_mac[3] = MSB(mr.mb[12]);
				ha->fcoe_vnport_mac[2] = LSB(mr.mb[12]);
				ha->fcoe_vnport_mac[1] = MSB(mr.mb[13]);
				ha->fcoe_vnport_mac[0] = LSB(mr.mb[13]);
			}
			break;
		default:
			QL_PRINT_2(ha, "UNKNOWN topology=%xh, d_id=%xh\n",
			    mr.mb[6], ha->d_id.b24);
			rval = QL_FUNCTION_FAILED;
			break;
		}

		if (CFG_IST(ha, CFG_CTRL_2363 | CFG_ISP_FW_TYPE_2)) {
			mr.mb[1] = 0;
			mr.mb[2] = 0;
			rval = ql_data_rate(ha, &mr);
			if (rval != QL_SUCCESS) {
				EL(ha, "data_rate status=%xh\n", rval);
				state = FC_STATE_FULL_SPEED;
			} else {
				ha->iidma_rate = mr.mb[1];
				if (mr.mb[1] == IIDMA_RATE_1GB) {
					state = FC_STATE_1GBIT_SPEED;
				} else if (mr.mb[1] == IIDMA_RATE_2GB) {
					state = FC_STATE_2GBIT_SPEED;
				} else if (mr.mb[1] == IIDMA_RATE_4GB) {
					state = FC_STATE_4GBIT_SPEED;
				} else if (mr.mb[1] == IIDMA_RATE_8GB) {
					state = FC_STATE_8GBIT_SPEED;
				} else if (mr.mb[1] == IIDMA_RATE_10GB) {
					state = FC_STATE_10GBIT_SPEED;
				} else if (mr.mb[1] == IIDMA_RATE_16GB) {
					state = FC_STATE_16GBIT_SPEED;
				} else if (mr.mb[1] == IIDMA_RATE_32GB) {
					state = FC_STATE_32GBIT_SPEED;
				} else {
					state = 0;
				}
			}
		} else {
			ha->iidma_rate = IIDMA_RATE_1GB;
			state = FC_STATE_FULL_SPEED;
		}
		ha->state = FC_PORT_STATE_MASK(ha->state) | state;
	} else if (rval == MBS_COMMAND_ERROR) {
		EL(ha, "mbox cmd error, rval = %xh, mr.mb[1]=%hx\n",
		    rval, mr.mb[1]);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		bp = ha->loginparams.nport_ww_name.raw_wwn;
		EL(ha, "topology=%xh, hba port id=%xh, "
		    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02xh\n",
		    ha->topology, ha->d_id.b24, bp[0], bp[1],
		    bp[2], bp[3], bp[4], bp[5], bp[6], bp[7]);
	}
	return (rval);
}

/*
 * ql_configure_device_d_id
 *	Updates device loop ID.
 *	Also adds to device queue any new devices found on private loop.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_configure_device_d_id(ql_adapter_state_t *ha)
{
	port_id_t		d_id;
	ql_link_t		*link;
	int			rval;
	int			loop;
	ql_tgt_t		*tq;
	ql_dev_id_list_t	*list;
	uint32_t		list_size;
	uint16_t		index, loop_id;
	ql_mbx_data_t		mr;
	uint8_t			retries = MAX_DEVICE_LOST_RETRY;

	QL_PRINT_10(ha, "started\n");

	list_size = sizeof (ql_dev_id_list_t) * DEVICE_LIST_ENTRIES;
	list = kmem_zalloc(list_size, KM_SLEEP);
	if (list == NULL) {
		rval = QL_MEMORY_ALLOC_FAILED;
		EL(ha, "failed, rval = %xh\n", rval);
		return (rval);
	}

	do {
		/*
		 * Get data from RISC code d_id list to init each device queue.
		 */
		rval = ql_get_id_list(ha, (caddr_t)list, list_size, &mr);
		if (rval != QL_SUCCESS) {
			kmem_free(list, list_size);
			EL(ha, "failed, rval = %xh\n", rval);
			return (rval);
		}

		/*
		 * Mark queues as unusable selectively.
		 * If the current topology is AL, only fabric tgt queues
		 * are marked as unusable and eventually removed.
		 * If the current topology is P2P, all fabric tgt queues
		 * are processed in ql_configure_n_port_info().
		 * If the current topology is Fabric, all previous created
		 * non-fabric device should be marked as lost and eventually
		 * should be removed.
		 */
		for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
			for (link = ha->dev[index].first; link != NULL;
			    link = link->next) {
				tq = link->base_address;

				if (VALID_DEVICE_ID(ha, tq->loop_id)) {
					DEVICE_QUEUE_LOCK(tq);
					if (!(tq->flags & TQF_PLOGI_PROGRS) &&
					    !(ha->topology & QL_N_PORT)) {
						tq->loop_id = (uint16_t)
						    (tq->loop_id |
						    PORT_LOST_ID);
					}
					if ((ha->topology & QL_NL_PORT) &&
					    (tq->flags & TQF_FABRIC_DEVICE)) {
						tq->loop_id = (uint16_t)
						    (tq->loop_id |
						    PORT_LOST_ID);
					}
					DEVICE_QUEUE_UNLOCK(tq);
				}
			}
		}

		/* If device not in queues add new queue. */
		for (index = 0; index < mr.mb[1]; index++) {
			ql_dev_list(ha, list, index, &d_id, &loop_id);

			if (VALID_DEVICE_ID(ha, loop_id)) {
				ADAPTER_STATE_LOCK(ha);
				tq = ql_dev_init(ha, d_id, loop_id);
				ADAPTER_STATE_UNLOCK(ha);
				if (tq != NULL) {
					tq->loop_id = loop_id;

					/* Test for fabric device. */
					if (ha->topology & QL_F_PORT ||
					    d_id.b.domain !=
					    ha->d_id.b.domain ||
					    d_id.b.area != ha->d_id.b.area) {
						tq->flags |= TQF_FABRIC_DEVICE;
					}

					if (ql_get_port_database(ha, tq,
					    PDF_NONE) == QL_SUCCESS) {
						tq->loop_id = (uint16_t)
						    (tq->loop_id &
						    ~PORT_LOST_ID);
					}
				}
			}
		}

		/* 24xx does not report switch devices in ID list. */
		if (CFG_IST(ha, CFG_ISP_FW_TYPE_2) &&
		    ha->topology & QL_FABRIC_CONNECTION) {
			d_id.b24 = FS_FABRIC_F_PORT;
			ADAPTER_STATE_LOCK(ha);
			tq = ql_dev_init(ha, d_id, FL_PORT_24XX_HDL);
			ADAPTER_STATE_UNLOCK(ha);
			if (tq != NULL) {
				tq->flags |= TQF_FABRIC_DEVICE;
				(void) ql_get_port_database(ha, tq, PDF_NONE);
			}

			d_id.b24 = FS_NAME_SERVER;
			ADAPTER_STATE_LOCK(ha);
			tq = ql_dev_init(ha, d_id, SNS_24XX_HDL);
			ADAPTER_STATE_UNLOCK(ha);
			if (tq != NULL) {
				tq->flags |= TQF_FABRIC_DEVICE;
				if (ha->vp_index != 0) {
					(void) ql_login_fport(ha, tq,
					    SNS_24XX_HDL, LFF_NONE, NULL);
				}
				(void) ql_get_port_database(ha, tq, PDF_NONE);
			}
		}

		/* Allocate queue for broadcast. */
		d_id.b24 = FS_BROADCAST;
		ADAPTER_STATE_LOCK(ha);
		(void) ql_dev_init(ha, d_id, (uint16_t)
		    (CFG_IST(ha, CFG_ISP_FW_TYPE_2) ? BROADCAST_24XX_HDL :
		    IP_BROADCAST_LOOP_ID));
		ADAPTER_STATE_UNLOCK(ha);

		/*
		 * Topology change (fabric<->p2p),(fabric<->al)
		 * (al<->p2p) have to be taken care of.
		 */
		loop = FALSE;
		for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
			ql_update_dev(ha, index);
		}

		if ((ha->topology & QL_NL_PORT) && (mr.mb[1] != 0)) {
			loop = FALSE;
		} else if (mr.mb[1] == 0 && !(ha->topology & QL_F_PORT)) {
			loop = TRUE;
		}

		/* Give devices time to recover. */
		if (loop == TRUE) {
			drv_usecwait(1000000);
		}
	} while (retries-- && loop == TRUE &&
	    !(ha->pha->task_daemon_flags & LOOP_RESYNC_NEEDED));

	kmem_free(list, list_size);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_10(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_dev_list
 *	Gets device d_id and loop ID from firmware device list.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	list	device list pointer.
 *	index:	list index of device data.
 *	d_id:	pointer for d_id data.
 *	id:	pointer for loop ID.
 *
 * Context:
 *	Kernel context.
 */
void
ql_dev_list(ql_adapter_state_t *ha, union ql_dev_id_list *list,
    uint32_t index, port_id_t *d_id, uint16_t *id)
{
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		struct ql_24_dev_id	*list24 = (struct ql_24_dev_id *)list;

		d_id->b.al_pa = list24[index].al_pa;
		d_id->b.area = list24[index].area;
		d_id->b.domain = list24[index].domain;
		*id = CHAR_TO_SHORT(list24[index].n_port_hdl_l,
		    list24[index].n_port_hdl_h);

	} else if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
		struct ql_ex_dev_id	*list23 = (struct ql_ex_dev_id *)list;

		d_id->b.al_pa = list23[index].al_pa;
		d_id->b.area = list23[index].area;
		d_id->b.domain = list23[index].domain;
		*id = CHAR_TO_SHORT(list23[index].loop_id_l,
		    list23[index].loop_id_h);

	} else {
		struct ql_dev_id	*list22 = (struct ql_dev_id *)list;

		d_id->b.al_pa = list22[index].al_pa;
		d_id->b.area = list22[index].area;
		d_id->b.domain = list22[index].domain;
		*id = (uint16_t)list22[index].loop_id;
	}
}

/*
 * ql_configure_fabric
 *	Setup fabric context.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_configure_fabric(ql_adapter_state_t *ha)
{
	port_id_t	d_id;
	ql_tgt_t	*tq;
	int		rval = QL_FUNCTION_FAILED;

	QL_PRINT_10(ha, "started\n");

	if (ha->topology & QL_FABRIC_CONNECTION) {
		/* Test switch fabric controller present. */
		d_id.b24 = FS_FABRIC_F_PORT;
		tq = ql_d_id_to_queue(ha, d_id);
		if (tq != NULL) {
			/* Get port/node names of F_Port. */
			(void) ql_get_port_database(ha, tq, PDF_NONE);

			d_id.b24 = FS_NAME_SERVER;
			tq = ql_d_id_to_queue(ha, d_id);
			if (tq != NULL) {
				(void) ql_get_port_database(ha, tq, PDF_NONE);
				rval = QL_SUCCESS;
			}
		}
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_10(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_reset_chip
 *	Reset ISP chip.
 *
 * Input:
 *	ha = adapter block pointer.
 *	All activity on chip must be already stopped.
 *	ADAPTER_STATE_LOCK must be released.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_reset_chip(ql_adapter_state_t *vha)
{
	uint32_t		cnt;
	uint16_t		cmd;
	ql_adapter_state_t	*ha = vha->pha;

	QL_PRINT_10(ha, "started\n");

	/*
	 * accessing pci space while not powered can cause panic's
	 * on some platforms (i.e. Sunblade 1000's)
	 */
	if (ha->power_level == PM_LEVEL_D3) {
		QL_PRINT_2(ha, "Low Power exit\n");
		return;
	}

	/* Disable ISP interrupts. */
	ql_disable_intr(ha);

	/* Reset all outbound mailbox registers */
	for (cnt = 0; cnt < ha->reg_off->mbox_cnt; cnt++) {
		WRT16_IO_REG(ha, mailbox_in[cnt], (uint16_t)0);
	}

	if (CFG_IST(ha, CFG_CTRL_82XX)) {
		ha->timeout_cnt = 0;
		ql_8021_reset_chip(ha);
		QL_PRINT_10(ha, "8021 exit\n");
		return;
	}

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		ql_reset_24xx_chip(ha);
		QL_PRINT_10(ha, "24xx exit\n");
		return;
	}
	QL_PRINT_10(ha, "CFG_ISP_FW_TYPE_1 reset\n");

	/*
	 * We are going to reset the chip in case of 2300. That might cause
	 * a PBM ERR if a DMA transaction is in progress. One way of
	 * avoiding it is to disable Bus Master operation before we start
	 * the reset activity.
	 */
	cmd = (uint16_t)ql_pci_config_get16(ha, PCI_CONF_COMM);
	cmd = (uint16_t)(cmd & ~PCI_COMM_ME);
	ql_pci_config_put16(ha, PCI_CONF_COMM, cmd);

	/* Pause RISC. */
	WRT16_IO_REG(ha, hccr, HC_PAUSE_RISC);
	for (cnt = 0; cnt < 30000; cnt++) {
		if ((RD16_IO_REG(ha, hccr) & HC_RISC_PAUSE) != 0) {
			break;
		}
		drv_usecwait(MILLISEC);
	}

	/*
	 * A call to ql_isr() can still happen through
	 * ql_mailbox_command(). So Mark that we are/(will-be)
	 * running from rom code now.
	 */
	TASK_DAEMON_LOCK(ha);
	ha->task_daemon_flags &= ~(FIRMWARE_UP | FIRMWARE_LOADED);
	TASK_DAEMON_UNLOCK(ha);

	/* Select FPM registers. */
	WRT16_IO_REG(ha, ctrl_status, 0x20);

	/* FPM Soft Reset. */
	WRT16_IO_REG(ha, fpm_diag_config, 0x100);

	/* Toggle FPM reset for 2300 */
	if (CFG_IST(ha, CFG_CTRL_2363)) {
		WRT16_IO_REG(ha, fpm_diag_config, 0);
	}

	/* Select frame buffer registers. */
	WRT16_IO_REG(ha, ctrl_status, 0x10);

	/* Reset frame buffer FIFOs. */
	if (CFG_IST(ha, CFG_CTRL_2363)) {
		WRT16_IO_REG(ha, fb_cmd, 0x00fc);
		/* read back fb_cmd until zero or 3 seconds max */
		for (cnt = 0; cnt < 300000; cnt++) {
			if ((RD16_IO_REG(ha, fb_cmd) & 0xff) == 0) {
				break;
			}
			drv_usecwait(10);
		}
	} else {
		WRT16_IO_REG(ha, fb_cmd, 0xa000);
	}

	/* Select RISC module registers. */
	WRT16_IO_REG(ha, ctrl_status, 0);

	/* Reset RISC module. */
	WRT16_IO_REG(ha, hccr, HC_RESET_RISC);

	/* Reset ISP semaphore. */
	WRT16_IO_REG(ha, semaphore, 0);

	/* Release RISC module. */
	WRT16_IO_REG(ha, hccr, HC_RELEASE_RISC);

	/* Insure mailbox registers are free. */
	WRT16_IO_REG(ha, hccr, HC_CLR_RISC_INT);
	WRT16_IO_REG(ha, hccr, HC_CLR_HOST_INT);

	/* clear the mailbox command pointer. */
	INTR_LOCK(ha);
	ha->mcp = NULL;
	INTR_UNLOCK(ha);

	MBX_REGISTER_LOCK(ha);
	ha->mailbox_flags = (uint8_t)(ha->mailbox_flags &
	    ~(MBX_BUSY_FLG | MBX_WANT_FLG | MBX_ABORT | MBX_INTERRUPT));
	MBX_REGISTER_UNLOCK(ha);

	/* Bus Master is disabled so chip reset is safe. */
	if (CFG_IST(ha, CFG_CTRL_2363)) {
		WRT16_IO_REG(ha, ctrl_status, ISP_RESET);
		drv_usecwait(MILLISEC);

		/* Wait for reset to finish. */
		for (cnt = 0; cnt < 30000; cnt++) {
			if ((RD16_IO_REG(ha, ctrl_status) & ISP_RESET) == 0) {
				break;
			}
			drv_usecwait(MILLISEC);
		}
	}

	/* Wait for RISC to recover from reset. */
	for (cnt = 0; cnt < 30000; cnt++) {
		if (RD16_IO_REG(ha, mailbox_out[0]) != MBS_ROM_BUSY) {
			break;
		}
		drv_usecwait(MILLISEC);
	}

	/* restore bus master */
	cmd = (uint16_t)ql_pci_config_get16(ha, PCI_CONF_COMM);
	cmd = (uint16_t)(cmd | PCI_COMM_ME);
	ql_pci_config_put16(ha, PCI_CONF_COMM, cmd);

	/* Disable RISC pause on FPM parity error. */
	WRT16_IO_REG(ha, hccr, HC_DISABLE_PARITY_PAUSE);

	if (CFG_IST(ha, CFG_CTRL_22XX) &&
	    RD16_IO_REG(ha, mailbox_out[7]) == 4) {
		ha->fw_transfer_size = 128;
	}

	/* Initialize probe registers */
	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		/* Pause RISC. */
		WRT16_IO_REG(ha, hccr, HC_PAUSE_RISC);
		for (cnt = 0; cnt < 30000; cnt++) {
			if ((RD16_IO_REG(ha, hccr) & HC_RISC_PAUSE) != 0) {
				break;
			} else {
				drv_usecwait(MILLISEC);
			}
		}

		/* Select FPM registers. */
		WRT16_IO_REG(ha, ctrl_status, 0x30);

		/* Set probe register */
		WRT16_IO_REG(ha, mailbox_in[23], 0x204c);

		/* Select RISC module registers. */
		WRT16_IO_REG(ha, ctrl_status, 0);

		/* Release RISC module. */
		WRT16_IO_REG(ha, hccr, HC_RELEASE_RISC);
	}

	QL_PRINT_10(ha, "done\n");
}

/*
 * ql_reset_24xx_chip
 *	Reset ISP24xx chip.
 *
 * Input:
 *	ha = adapter block pointer.
 *	All activity on chip must be already stopped.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static void
ql_reset_24xx_chip(ql_adapter_state_t *ha)
{
	uint32_t	timer, stat;

	QL_PRINT_10(ha, "started\n");

	/* Shutdown DMA. */
	if (CFG_IST(ha, CFG_MWB_4096_SUPPORT)) {
		WRT32_IO_REG(ha, ctrl_status, DMA_SHUTDOWN | MWB_4096_BYTES);
	} else {
		WRT32_IO_REG(ha, ctrl_status, DMA_SHUTDOWN);
	}

	/* Wait for DMA to stop. */
	for (timer = 0; timer < 30000; timer++) {
		if ((RD32_IO_REG(ha, ctrl_status) & DMA_ACTIVE) == 0) {
			break;
		}
		drv_usecwait(100);
	}

	/* Stop the firmware. */
	WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT);
	WRT16_IO_REG(ha, mailbox_in[0], MBC_STOP_FIRMWARE);
	WRT16_IO_REG(ha, mailbox_in[1], 0);
	WRT16_IO_REG(ha, mailbox_in[2], 0);
	WRT16_IO_REG(ha, mailbox_in[3], 0);
	WRT16_IO_REG(ha, mailbox_in[4], 0);
	WRT16_IO_REG(ha, mailbox_in[5], 0);
	WRT16_IO_REG(ha, mailbox_in[6], 0);
	WRT16_IO_REG(ha, mailbox_in[7], 0);
	WRT16_IO_REG(ha, mailbox_in[8], 0);
	WRT32_IO_REG(ha, hccr, HC24_SET_HOST_INT);
	for (timer = 0; timer < 30000; timer++) {
		stat = RD32_IO_REG(ha, risc2host);
		if (stat & BIT_15) {
			if ((stat & 0xff) < 0x12) {
				WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT);
				break;
			}
			WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT);
		}
		drv_usecwait(100);
	}

	/* Reset the chip. */
	WRT32_IO_REG(ha, ctrl_status, ISP_RESET);
	drv_usecwait(100);

	/* Wait for RISC to recover from reset. */
	for (timer = 30000; timer; timer--) {
		ha->rom_status = RD16_IO_REG(ha, mailbox_out[0]);
		if (CFG_IST(ha, CFG_CTRL_278083)) {
			/* Wait for RISC to recover from reset. */
			if ((ha->rom_status & MBS_ROM_STATUS_MASK) !=
			    MBS_ROM_BUSY) {
				break;
			}
		} else {
			/* Wait for idle status from ROM firmware. */
			if (ha->rom_status == MBS_ROM_IDLE) {
				break;
			}
		}
		drv_usecwait(100);
	}

	/* Wait for reset to finish. */
	for (timer = 0; timer < 30000; timer++) {
		if ((RD32_IO_REG(ha, ctrl_status) & ISP_RESET) == 0) {
			break;
		}
		drv_usecwait(100);
	}

	ha->adapter_stats->revlvl.isp2200 = RD16_IO_REG(ha, mailbox_out[4]);
	ha->adapter_stats->revlvl.risc = RD16_IO_REG(ha, mailbox_out[5]);
	ha->adapter_stats->revlvl.frmbfr = RD16_IO_REG(ha, mailbox_out[6]);
	ha->adapter_stats->revlvl.riscrom = RD16_IO_REG(ha, mailbox_out[8]);

	/* Insure mailbox registers are free. */
	WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT);
	WRT32_IO_REG(ha, hccr, HC24_CLR_HOST_INT);

	/* clear the mailbox command pointer. */
	INTR_LOCK(ha);
	ha->mcp = NULL;
	INTR_UNLOCK(ha);

	/* Insure mailbox registers are free. */
	MBX_REGISTER_LOCK(ha);
	ha->mailbox_flags = (uint8_t)(ha->mailbox_flags &
	    ~(MBX_BUSY_FLG | MBX_WANT_FLG | MBX_ABORT | MBX_INTERRUPT));
	MBX_REGISTER_UNLOCK(ha);

	if (ha->flags & MPI_RESET_NEEDED) {
		WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT);
		WRT16_IO_REG(ha, mailbox_in[0], MBC_RESTART_MPI);
		WRT32_IO_REG(ha, hccr, HC24_SET_HOST_INT);
		for (timer = 0; timer < 30000; timer++) {
			stat = RD32_IO_REG(ha, risc2host);
			if (stat & BIT_15) {
				if ((stat & 0xff) < 0x12) {
					WRT32_IO_REG(ha, hccr,
					    HC24_CLR_RISC_INT);
					break;
				}
				WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT);
			}
			drv_usecwait(100);
		}
		ADAPTER_STATE_LOCK(ha);
		ha->flags &= ~MPI_RESET_NEEDED;
		ADAPTER_STATE_UNLOCK(ha);
	}

	QL_PRINT_10(ha, "done\n");
}

/*
 * ql_abort_isp
 *	Resets ISP and aborts all outstanding commands.
 *
 * Input:
 *	ha = adapter state pointer.
 *	DEVICE_QUEUE_LOCK must be released.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_abort_isp(ql_adapter_state_t *vha)
{
	ql_link_t		*link, *link2;
	uint16_t		index;
	ql_tgt_t		*tq;
	ql_lun_t		*lq;
	int			rval = QL_SUCCESS;
	ql_adapter_state_t	*ha = vha->pha;
	boolean_t		abort_loop_down = B_FALSE;

	QL_PRINT_2(ha, "started\n");

	TASK_DAEMON_LOCK(ha);
	ha->task_daemon_flags &= ~ISP_ABORT_NEEDED;
	if (ha->task_daemon_flags & ABORT_ISP_ACTIVE ||
	    (ha->flags & ONLINE) == 0 || ha->flags & ADAPTER_SUSPENDED) {
		TASK_DAEMON_UNLOCK(ha);
		QL_PRINT_2(ha, "already active or suspended tdf=0x%llx, "
		    "flgs=0x%llx\n", ha->task_daemon_flags, ha->flags);
		return (rval);
	}

	ha->task_daemon_flags |= ABORT_ISP_ACTIVE;
	ha->task_daemon_flags &= ~(MARKER_NEEDED | FIRMWARE_UP |
	    FIRMWARE_LOADED);
	for (vha = ha; vha != NULL; vha = vha->vp_next) {
		vha->task_daemon_flags &= ~(COMMAND_WAIT_NEEDED |
		    LOOP_RESYNC_NEEDED);
		vha->task_daemon_flags |= LOOP_DOWN;
		if (vha->loop_down_timer == LOOP_DOWN_TIMER_OFF) {
			abort_loop_down = B_TRUE;
			vha->loop_down_timer = LOOP_DOWN_TIMER_START;
		}
	}

	TASK_DAEMON_UNLOCK(ha);

	ql_port_state(ha, FC_STATE_OFFLINE, FC_STATE_CHANGE);

	if (ha->mailbox_flags & MBX_BUSY_FLG) {
		/* Acquire mailbox register lock. */
		MBX_REGISTER_LOCK(ha);

		/* Wake up mailbox box routine. */
		ha->mailbox_flags = (uint8_t)(ha->mailbox_flags | MBX_ABORT);
		cv_broadcast(&ha->cv_mbx_intr);

		/* Release mailbox register lock. */
		MBX_REGISTER_UNLOCK(ha);

		/* Wait for mailbox. */
		for (index = 100; index &&
		    ha->mailbox_flags & MBX_ABORT; index--) {
			delay(1);
		}
	}

	/* Wait for commands to end gracefully if not in panic. */
	if (ha->flags & PARITY_ERROR) {
		ADAPTER_STATE_LOCK(ha);
		ha->flags &= ~PARITY_ERROR;
		ADAPTER_STATE_UNLOCK(ha);
	} else if (ddi_in_panic() == 0) {
		ql_cmd_wait(ha);
	}

	rval = QL_ABORTED;
	if (ha->flags & FW_DUMP_NEEDED) {
		rval = ql_binary_fw_dump(ha, TRUE);
	}

	/* Shutdown IP. */
	if (ha->flags & IP_INITIALIZED) {
		(void) ql_shutdown_ip(ha);
	}

	if (ha->task_daemon_flags & ISP_ABORT_NEEDED) {
		TASK_DAEMON_LOCK(ha);
		ha->task_daemon_flags &= ~ISP_ABORT_NEEDED;
		TASK_DAEMON_UNLOCK(ha);
	}

	/* Reset the chip. */
	if (rval != QL_SUCCESS) {
		rval = QL_SUCCESS;
		ql_reset_chip(ha);
	}

	/*
	 * Even though we have waited for outstanding commands to complete,
	 * except for ones marked SRB_COMMAND_TIMEOUT, and reset the ISP,
	 * there could still be an interrupt thread active.  The interrupt
	 * lock will prevent us from getting an sp from the outstanding
	 * cmds array that the ISR may be using.
	 */

	/* Place all commands in outstanding cmd list on device queue. */
	ql_requeue_all_cmds(ha);

	/*
	 * Clear per LUN active count, because there should not be
	 * any IO outstanding at this time.
	 */
	for (vha = ha; vha != NULL; vha = vha->vp_next) {
		for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
			link = vha->dev[index].first;
			while (link != NULL) {
				tq = link->base_address;
				link = link->next;
				DEVICE_QUEUE_LOCK(tq);
				tq->outcnt = 0;
				tq->flags &= ~TQF_QUEUE_SUSPENDED;
				for (link2 = tq->lun_queues.first;
				    link2 != NULL; link2 = link2->next) {
					lq = link2->base_address;
					lq->lun_outcnt = 0;
					lq->flags &= ~LQF_UNTAGGED_PENDING;
				}
				DEVICE_QUEUE_UNLOCK(tq);
			}
		}
	}

	if ((rval = ql_check_isp_firmware(ha)) != QL_SUCCESS) {
		if (ha->dev_state != NX_DEV_READY) {
			EL(ha, "dev_state not ready\n");
		} else if ((rval = ql_mbx_wrap_test(ha, NULL)) == QL_SUCCESS) {
			rval = ql_load_isp_firmware(ha);
		}
	}

	if (rval == QL_SUCCESS && (rval = ql_set_cache_line(ha)) ==
	    QL_SUCCESS && (rval = ql_init_rings(ha)) == QL_SUCCESS &&
	    (rval = ql_fw_ready(ha, 10)) == QL_SUCCESS) {

		/* Enable ISP interrupts. */
		if (!(ha->flags & INTERRUPTS_ENABLED)) {
			ql_enable_intr(ha);
		}

		/* If reset abort needed that may have been set. */
		TASK_DAEMON_LOCK(ha);
		ha->task_daemon_flags &= ~(ISP_ABORT_NEEDED |
		    ABORT_ISP_ACTIVE);
		TASK_DAEMON_UNLOCK(ha);

		/* Set loop online, if it really is. */
		ql_loop_online(ha);
	} else {
		/* Enable ISP interrupts. */
		if (!(ha->flags & INTERRUPTS_ENABLED)) {
			ql_enable_intr(ha);
		}

		TASK_DAEMON_LOCK(ha);
		for (vha = ha; vha != NULL; vha = vha->vp_next) {
			vha->task_daemon_flags |= LOOP_DOWN;
		}
		ha->task_daemon_flags &= ~ISP_ABORT_NEEDED;
		TASK_DAEMON_UNLOCK(ha);

		ql_port_state(ha, FC_STATE_OFFLINE, FC_STATE_CHANGE);

		ql_abort_queues(ha);

		TASK_DAEMON_LOCK(ha);
		ha->task_daemon_flags &= ~ABORT_ISP_ACTIVE;
		TASK_DAEMON_UNLOCK(ha);
	}

	for (vha = ha; vha != NULL; vha = vha->vp_next) {
		if (!(vha->task_daemon_flags & LOOP_DOWN) &&
		    abort_loop_down == B_TRUE) {
			vha->loop_down_timer = LOOP_DOWN_TIMER_OFF;
		}
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_2(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_requeue_all_cmds
 *	Requeue all commands.
 *
 * Input:
 *	ha = virtual adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
void
ql_requeue_all_cmds(ql_adapter_state_t *ha)
{
	ql_link_t	*link;
	ql_tgt_t	*tq;
	ql_lun_t	*lq;
	ql_srb_t	*sp;
	uint16_t	index;

	/* Place all commands in outstanding cmd list on device queue. */
	for (index = 1; index < ha->osc_max_cnt; index++) {
		INTR_LOCK(ha);
		REQUEST_RING_LOCK(ha);
		if ((link = ha->pending_cmds.first) != NULL) {
			sp = link->base_address;
			ql_remove_link(&ha->pending_cmds, &sp->cmd);

			REQUEST_RING_UNLOCK(ha);
			index = 0;
		} else {
			REQUEST_RING_UNLOCK(ha);
			if ((sp = ha->outstanding_cmds[index]) == NULL ||
			    sp == QL_ABORTED_SRB(ha)) {
				INTR_UNLOCK(ha);
				continue;
			}
		}

		/*
		 * It's not obvious but the index for commands pulled from
		 * pending will be zero and that entry in the outstanding array
		 * is not used so nulling it is "no harm, no foul".
		 */

		ha->outstanding_cmds[index] = NULL;
		sp->handle = 0;
		sp->flags &= ~SRB_IN_TOKEN_ARRAY;

		INTR_UNLOCK(ha);

		/* If command timeout. */
		if (sp->flags & SRB_COMMAND_TIMEOUT) {
			sp->pkt->pkt_reason = CS_TIMEOUT;
			sp->flags &= ~SRB_RETRY;
			sp->flags |= SRB_ISP_COMPLETED;

			/* Call done routine to handle completion. */
			ql_done(&sp->cmd, B_FALSE);
			continue;
		}

		/* Acquire target queue lock. */
		lq = sp->lun_queue;
		tq = lq->target_queue;

		/* return any tape IO as exchange dropped due to chip reset */
		if (tq->flags & TQF_TAPE_DEVICE) {
			sp->pkt->pkt_reason = CS_TRANSPORT;
			sp->flags &= ~SRB_RETRY;
			sp->flags |= SRB_ISP_COMPLETED;

			EL(ha, "rtn seq IO, sp=%ph", sp);

			/* Call done routine to handle completion. */
			ql_done(&sp->cmd, B_FALSE);
			continue;
		}

		DEVICE_QUEUE_LOCK(tq);

		/* Reset watchdog time. */
		sp->wdg_q_time = sp->init_wdg_q_time;

		/* Place request back on top of device queue. */
		sp->flags &= ~(SRB_ISP_STARTED | SRB_ISP_COMPLETED |
		    SRB_RETRY);

		ql_add_link_t(&lq->cmd, &sp->cmd);
		sp->flags |= SRB_IN_DEVICE_QUEUE;

		/* Release target queue lock. */
		DEVICE_QUEUE_UNLOCK(tq);
	}
}

/*
 * ql_vport_control
 *	Issue Virtual Port Control command.
 *
 * Input:
 *	ha = virtual adapter state pointer.
 *	cmd = control command.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_vport_control(ql_adapter_state_t *ha, uint8_t cmd)
{
	ql_mbx_iocb_t	*pkt;
	uint8_t		bit;
	int		rval;
	uint32_t	pkt_size;

	QL_PRINT_10(ha, "started\n");

	if (ha->vp_index != 0) {
		pkt_size = sizeof (ql_mbx_iocb_t);
		pkt = kmem_zalloc(pkt_size, KM_SLEEP);
		if (pkt == NULL) {
			EL(ha, "failed, kmem_zalloc\n");
			return (QL_MEMORY_ALLOC_FAILED);
		}

		pkt->vpc.entry_type = VP_CONTROL_TYPE;
		pkt->vpc.entry_count = 1;
		pkt->vpc.command = cmd;
		pkt->vpc.vp_count = 1;
		pkt->vpc.fcf_index = ha->fcoe_fcf_idx;
		bit = (uint8_t)(ha->vp_index - 1);
		pkt->vpc.vp_index[bit / 8] = (uint8_t)
		    (pkt->vpc.vp_index[bit / 8] | BIT_0 << bit % 8);

		rval = ql_issue_mbx_iocb(ha, (caddr_t)pkt, pkt_size);
		if (rval == QL_SUCCESS && pkt->vpc.status != 0) {
			rval = QL_COMMAND_ERROR;
		}

		kmem_free(pkt, pkt_size);
	} else {
		rval = QL_SUCCESS;
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_10(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_vport_modify
 *	Issue of Modify Virtual Port command.
 *
 * Input:
 *	ha = virtual adapter state pointer.
 *	cmd = command.
 *	opt = option.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
int
ql_vport_modify(ql_adapter_state_t *ha, uint8_t cmd, uint8_t opt)
{
	ql_mbx_iocb_t	*pkt;
	int		rval;
	uint32_t	pkt_size;

	QL_PRINT_10(ha, "started\n");

	if (ha->pha->task_daemon_flags & LOOP_DOWN) {
		QL_PRINT_10(ha, "loop_down\n");
		return (QL_FUNCTION_FAILED);
	}

	pkt_size = sizeof (ql_mbx_iocb_t);
	pkt = kmem_zalloc(pkt_size, KM_SLEEP);
	if (pkt == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		return (QL_MEMORY_ALLOC_FAILED);
	}

	pkt->vpm.entry_type = VP_MODIFY_TYPE;
	pkt->vpm.entry_count = 1;
	pkt->vpm.command = cmd;
	pkt->vpm.vp_count = 1;
	pkt->vpm.first_vp_index = ha->vp_index;
	pkt->vpm.first_options = opt;
	pkt->vpm.fcf_index = ha->fcoe_fcf_idx;
	bcopy(ha->loginparams.nport_ww_name.raw_wwn, pkt->vpm.first_port_name,
	    8);
	bcopy(ha->loginparams.node_ww_name.raw_wwn, pkt->vpm.first_node_name,
	    8);

	rval = ql_issue_mbx_iocb(ha, (caddr_t)pkt, pkt_size);
	if (rval == QL_SUCCESS && pkt->vpm.status != 0) {
		EL(ha, "failed, ql_issue_mbx_iocb=%xh, status=%xh\n", rval,
		    pkt->vpm.status);
		rval = QL_COMMAND_ERROR;
	}

	kmem_free(pkt, pkt_size);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_10(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_vport_enable
 *	Enable virtual port.
 *
 * Input:
 *	ha = virtual adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
int
ql_vport_enable(ql_adapter_state_t *ha)
{
	int	timer;

	QL_PRINT_10(ha, "started\n");

	ha->state = FC_PORT_SPEED_MASK(ha->state) | FC_STATE_OFFLINE;
	TASK_DAEMON_LOCK(ha);
	ha->task_daemon_flags |= LOOP_DOWN;
	ha->task_daemon_flags &= ~(FC_STATE_CHANGE | STATE_ONLINE);
	TASK_DAEMON_UNLOCK(ha);

	ADAPTER_STATE_LOCK(ha);
	ha->flags |= VP_ENABLED;
	ha->flags &= ~VP_ID_NOT_ACQUIRED;
	ADAPTER_STATE_UNLOCK(ha);
	ha->fcoe_fcf_idx = 0;

	if (ql_vport_modify(ha, VPM_MODIFY_ENABLE, VPO_TARGET_MODE_DISABLED |
	    VPO_INITIATOR_MODE_ENABLED | VPO_ENABLED) != QL_SUCCESS) {
		QL_PRINT_2(ha, "failed to enable virtual port\n");
		return (QL_FUNCTION_FAILED);
	}
	if (!(ha->pha->task_daemon_flags & LOOP_DOWN)) {
		/* Wait for loop to come up. */
		for (timer = 0; timer < 3000 &&
		    !(ha->task_daemon_flags & STATE_ONLINE);
		    timer++) {
			if (ha->flags & VP_ID_NOT_ACQUIRED) {
				break;
			}
			delay(1);
		}
	}

	QL_PRINT_10(ha, "done\n");

	return (QL_SUCCESS);
}

/*
 * ql_vport_create
 *	Create virtual port context.
 *
 * Input:
 *	ha:	parent adapter state pointer.
 *	index:	virtual port index number.
 *
 * Context:
 *	Kernel context.
 */
ql_adapter_state_t *
ql_vport_create(ql_adapter_state_t *ha, uint8_t index)
{
	ql_adapter_state_t	*vha;

	QL_PRINT_10(ha, "started\n");

	/* Inherit the parents data. */
	vha = kmem_alloc(sizeof (ql_adapter_state_t), KM_SLEEP);

	ADAPTER_STATE_LOCK(ha);
	bcopy(ha, vha, sizeof (ql_adapter_state_t));
	vha->pi_attrs = NULL;
	vha->ub_outcnt = 0;
	vha->ub_allocated = 0;
	vha->flags = 0;
	vha->task_daemon_flags = 0;
	ha->vp_next = vha;
	vha->pha = ha;
	vha->vp_index = index;
	ADAPTER_STATE_UNLOCK(ha);

	vha->hba.next = NULL;
	vha->hba.prev = NULL;
	vha->hba.base_address = vha;
	vha->state = FC_PORT_SPEED_MASK(ha->state) | FC_STATE_OFFLINE;
	vha->dev = kmem_zalloc(sizeof (*vha->dev) * DEVICE_HEAD_LIST_SIZE,
	    KM_SLEEP);
	vha->ub_array = kmem_zalloc(sizeof (*vha->ub_array) * QL_UB_LIMIT,
	    KM_SLEEP);

	QL_PRINT_10(ha, "done\n");

	return (vha);
}

/*
 * ql_vport_destroy
 *	Destroys virtual port context.
 *
 * Input:
 *	ha = virtual adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
void
ql_vport_destroy(ql_adapter_state_t *ha)
{
	ql_adapter_state_t	*vha;

	QL_PRINT_10(ha, "started\n");

	/* Remove port from list. */
	ADAPTER_STATE_LOCK(ha);
	for (vha = ha->pha; vha != NULL; vha = vha->vp_next) {
		if (vha->vp_next == ha) {
			vha->vp_next = ha->vp_next;
			break;
		}
	}
	ADAPTER_STATE_UNLOCK(ha);

	if (ha->ub_array != NULL) {
		kmem_free(ha->ub_array, sizeof (*ha->ub_array) * QL_UB_LIMIT);
	}
	if (ha->dev != NULL) {
		kmem_free(ha->dev, sizeof (*vha->dev) * DEVICE_HEAD_LIST_SIZE);
	}
	kmem_free(ha, sizeof (ql_adapter_state_t));

	QL_PRINT_10(ha, "done\n");
}

/*
 * ql_mps_reset
 *	Reset MPS for FCoE functions.
 *
 * Input:
 *	ha = virtual adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_mps_reset(ql_adapter_state_t *ha)
{
	uint32_t	data, dctl = 1000;

	do {
		if (dctl-- == 0 || ql_wrt_risc_ram_word(ha, 0x7c00, 1) !=
		    QL_SUCCESS) {
			return;
		}
		if (ql_rd_risc_ram_word(ha, 0x7c00, &data) != QL_SUCCESS) {
			(void) ql_wrt_risc_ram_word(ha, 0x7c00, 0);
			return;
		}
	} while (!(data & BIT_0));

	if (ql_rd_risc_ram_word(ha, 0x7A15, &data) == QL_SUCCESS) {
		dctl = (uint16_t)ql_pci_config_get16(ha, 0x54);
		if ((data & 0xe0) < (dctl & 0xe0)) {
			data &= 0xff1f;
			data |= dctl & 0xe0;
			(void) ql_wrt_risc_ram_word(ha, 0x7A15, data);
		} else if ((data & 0xe0) != (dctl & 0xe0)) {
			data &= 0xff1f;
			data |= dctl & 0xe0;
			(void) ql_wrt_risc_ram_word(ha, 0x7A15, data);
		}
	}
	(void) ql_wrt_risc_ram_word(ha, 0x7c00, 0);
}

/*
 * ql_update_dev
 *	Updates device status on loop reconfigure.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	index:	list index of device data.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_update_dev(ql_adapter_state_t *ha, uint32_t index)
{
	ql_link_t	*link;
	ql_tgt_t	*tq;
	int		rval;

	QL_PRINT_3(ha, "started\n");

	link = ha->dev[index].first;
	while (link != NULL) {
		tq = link->base_address;
		link = link->next;

		if (tq->loop_id & PORT_LOST_ID &&
		    !(tq->flags & (TQF_INITIATOR_DEVICE | TQF_FABRIC_DEVICE))) {

			tq->loop_id &= ~PORT_LOST_ID;

			if (VALID_DEVICE_ID(ha, tq->loop_id)) {
				/* implicit logo due to fw issue */
				rval = ql_get_port_database(ha, tq, PDF_NONE);

				if (rval == QL_NOT_LOGGED_IN) {
					if (tq->master_state ==
					    PD_STATE_PORT_UNAVAILABLE) {
						(void) ql_logout_fabric_port(
						    ha, tq);
						tq->loop_id = PORT_NO_LOOP_ID;
					}
				} else if (rval == QL_SUCCESS) {
					tq->loop_id = PORT_NO_LOOP_ID;
				}
			}
		} else if (ha->topology & QL_NL_PORT &&
		    tq->flags & TQF_FABRIC_DEVICE) {

			tq->loop_id &= ~PORT_LOST_ID;

			if (VALID_DEVICE_ID(ha, tq->loop_id)) {
				/* implicit logo due to fw issue */
				rval = ql_get_port_database(ha, tq, PDF_NONE);

				if (rval == QL_NOT_LOGGED_IN) {
					if (tq->master_state ==
					    PD_STATE_PORT_UNAVAILABLE) {
						(void) ql_logout_fabric_port(
						    ha, tq);
						/*
						 * fabric to AL topo change
						 */
						tq->loop_id = PORT_NO_LOOP_ID;
					}
				} else if (rval == QL_SUCCESS) {
					/*
					 * Normally this is 7fe,
					 * Don't issue logo, it causes
					 * logo in single tgt AL.
					 */
					tq->loop_id = PORT_NO_LOOP_ID;
				}
			}
		}
	}

	QL_PRINT_3(ha, "done\n");
}
