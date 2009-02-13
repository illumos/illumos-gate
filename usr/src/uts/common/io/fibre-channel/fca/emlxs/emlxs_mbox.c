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
 * Copyright 2009 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */

#include <emlxs.h>

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_MBOX_C);

static void	emlxs_mb_part_slim(emlxs_hba_t *hba, MAILBOX *mb,
			uint32_t hbainit);
static void	emlxs_mb_set_mask(emlxs_hba_t *hba, MAILBOX *mb, uint32_t mask,
			uint32_t ringno);
static void	emlxs_mb_set_debug(emlxs_hba_t *hba, MAILBOX *mb,
			uint32_t word0, uint32_t word1, uint32_t word2);
static int32_t	emlxs_mb_handle_cmd(emlxs_hba_t *hba, MAILBOX *mb);
static void	emlxs_mb_write_nv(emlxs_hba_t *hba, MAILBOX *mb);


emlxs_table_t emlxs_mb_cmd_table[] = {
	{MBX_SHUTDOWN, "SHUTDOWN"},
	{MBX_LOAD_SM, "LOAD_SM"},
	{MBX_READ_NV, "READ_NV"},
	{MBX_WRITE_NV, "WRITE_NV"},
	{MBX_RUN_BIU_DIAG, "RUN_BIU_DIAG"},
	{MBX_INIT_LINK, "INIT_LINK"},
	{MBX_DOWN_LINK, "DOWN_LINK"},
	{MBX_CONFIG_LINK, "CONFIG_LINK"},
	{MBX_PART_SLIM, "PART_SLIM"},
	{MBX_CONFIG_RING, "CONFIG_RING"},
	{MBX_RESET_RING, "RESET_RING"},
	{MBX_READ_CONFIG, "READ_CONFIG"},
	{MBX_READ_RCONFIG, "READ_RCONFIG"},
	{MBX_READ_SPARM, "READ_SPARM"},
	{MBX_READ_STATUS, "READ_STATUS"},
	{MBX_READ_RPI, "READ_RPI"},
	{MBX_READ_XRI, "READ_XRI"},
	{MBX_READ_REV, "READ_REV"},
	{MBX_READ_LNK_STAT, "READ_LNK_STAT"},
	{MBX_REG_LOGIN, "REG_LOGIN"},
	{MBX_UNREG_LOGIN, "UNREG_LOGIN"},
	{MBX_READ_LA, "READ_LA"},
	{MBX_CLEAR_LA, "CLEAR_LA"},
	{MBX_DUMP_MEMORY, "DUMP_MEMORY"},
	{MBX_DUMP_CONTEXT, "DUMP_CONTEXT"},
	{MBX_RUN_DIAGS, "RUN_DIAGS"},
	{MBX_RESTART, "RESTART"},
	{MBX_UPDATE_CFG, "UPDATE_CFG"},
	{MBX_DOWN_LOAD, "DOWN_LOAD"},
	{MBX_DEL_LD_ENTRY, "DEL_LD_ENTRY"},
	{MBX_RUN_PROGRAM, "RUN_PROGRAM"},
	{MBX_SET_MASK, "SET_MASK"},
	{MBX_SET_VARIABLE, "SET_VARIABLE"},
	{MBX_UNREG_D_ID, "UNREG_D_ID"},
	{MBX_KILL_BOARD, "KILL_BOARD"},
	{MBX_CONFIG_FARP, "CONFIG_FARP"},
	{MBX_LOAD_AREA, "LOAD_AREA"},
	{MBX_RUN_BIU_DIAG64, "RUN_BIU_DIAG64"},
	{MBX_CONFIG_PORT, "CONFIG_PORT"},
	{MBX_READ_SPARM64, "READ_SPARM64"},
	{MBX_READ_RPI64, "READ_RPI64"},
	{MBX_CONFIG_MSI, "CONFIG_MSI"},
	{MBX_CONFIG_MSIX, "CONFIG_MSIX"},
	{MBX_REG_LOGIN64, "REG_LOGIN64"},
	{MBX_READ_LA64, "READ_LA64"},
	{MBX_FLASH_WR_ULA, "FLASH_WR_ULA"},
	{MBX_SET_DEBUG, "SET_DEBUG"},
	{MBX_GET_DEBUG, "GET_DEBUG"},
	{MBX_LOAD_EXP_ROM, "LOAD_EXP_ROM"},
	{MBX_BEACON, "BEACON"},
	{MBX_CONFIG_HBQ, "CONFIG_HBQ"},	/* SLI3 */
	{MBX_REG_VPI, "REG_VPI"},	/* NPIV */
	{MBX_ASYNC_EVENT, "ASYNC_EVENT"},
	{MBX_HEARTBEAT, "HEARTBEAT"},
	{MBX_READ_EVENT_LOG_STATUS, "READ_EVENT_LOG_STATUS"},
	{MBX_READ_EVENT_LOG, "READ_EVENT_LOG"},
	{MBX_WRITE_EVENT_LOG, "WRITE_EVENT_LOG"},
	{MBX_NV_LOG, "NV_LOG"},
	{MBX_PORT_CAPABILITIES, "PORT_CAPABILITIES"},
	{MBX_IOV_CONTROL, "IOV_CONTROL"},
	{MBX_IOV_MBX, "IOV_MBX"}
};	/* emlxs_mb_cmd_table */


/*ARGSUSED*/
extern void
emlxs_mb_async_event(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_ASYNC_EVENT;
	mb->mbxOwner = OWN_HOST;
	mb->un.varWords[0] = FC_ELS_RING;

	return;

} /* emlxs_mb_async_event() */


/*ARGSUSED*/
extern void
emlxs_mb_heartbeat(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_HEARTBEAT;
	mb->mbxOwner = OWN_HOST;

	return;

} /* emlxs_mb_heartbeat() */


#ifdef MSI_SUPPORT

/*ARGSUSED*/
extern void
emlxs_mb_config_msi(emlxs_hba_t *hba, MAILBOX *mb, uint32_t *intr_map,
    uint32_t intr_count)
{
	uint32_t i;
	uint32_t mask;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_CONFIG_MSI;

	/* Set the default message id to zero */
	mb->un.varCfgMSI.defaultPresent = 1;
	mb->un.varCfgMSI.defaultMessageNumber = 0;

	for (i = 1; i < intr_count; i++) {
		mask = intr_map[i];

		mb->un.varCfgMSI.attConditions |= mask;

#ifdef EMLXS_BIG_ENDIAN
		if (mask & HA_R0ATT) {
			mb->un.varCfgMSI.messageNumberByHA[3] = i;
		}
		if (mask & HA_R1ATT) {
			mb->un.varCfgMSI.messageNumberByHA[7] = i;
		}
		if (mask & HA_R2ATT) {
			mb->un.varCfgMSI.messageNumberByHA[11] = i;
		}
		if (mask & HA_R3ATT) {
			mb->un.varCfgMSI.messageNumberByHA[15] = i;
		}
		if (mask & HA_LATT) {
			mb->un.varCfgMSI.messageNumberByHA[29] = i;
		}
		if (mask & HA_MBATT) {
			mb->un.varCfgMSI.messageNumberByHA[30] = i;
		}
		if (mask & HA_ERATT) {
			mb->un.varCfgMSI.messageNumberByHA[31] = i;
		}
#endif	/* EMLXS_BIG_ENDIAN */

#ifdef EMLXS_LITTLE_ENDIAN
		/* Accounts for half word swap of LE architecture */
		if (mask & HA_R0ATT) {
			mb->un.varCfgMSI.messageNumberByHA[2] = i;
		}
		if (mask & HA_R1ATT) {
			mb->un.varCfgMSI.messageNumberByHA[6] = i;
		}
		if (mask & HA_R2ATT) {
			mb->un.varCfgMSI.messageNumberByHA[10] = i;
		}
		if (mask & HA_R3ATT) {
			mb->un.varCfgMSI.messageNumberByHA[14] = i;
		}
		if (mask & HA_LATT) {
			mb->un.varCfgMSI.messageNumberByHA[28] = i;
		}
		if (mask & HA_MBATT) {
			mb->un.varCfgMSI.messageNumberByHA[31] = i;
		}
		if (mask & HA_ERATT) {
			mb->un.varCfgMSI.messageNumberByHA[30] = i;
		}
#endif	/* EMLXS_LITTLE_ENDIAN */
	}

	mb->mbxOwner = OWN_HOST;

	return;

} /* emlxs_mb_config_msi() */


/*ARGSUSED*/
extern void
emlxs_mb_config_msix(emlxs_hba_t *hba, MAILBOX *mb, uint32_t *intr_map,
    uint32_t intr_count)
{
	uint32_t i;
	uint32_t mask;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_CONFIG_MSIX;

	/* Set the default message id to zero */
	mb->un.varCfgMSIX.defaultPresent = 1;
	mb->un.varCfgMSIX.defaultMessageNumber = 0;

	for (i = 1; i < intr_count; i++) {
		mask = intr_map[i];

		mb->un.varCfgMSIX.attConditions1 |= mask;

#ifdef EMLXS_BIG_ENDIAN
		if (mask & HA_R0ATT) {
			mb->un.varCfgMSIX.messageNumberByHA[3] = i;
		}
		if (mask & HA_R1ATT) {
			mb->un.varCfgMSIX.messageNumberByHA[7] = i;
		}
		if (mask & HA_R2ATT) {
			mb->un.varCfgMSIX.messageNumberByHA[11] = i;
		}
		if (mask & HA_R3ATT) {
			mb->un.varCfgMSIX.messageNumberByHA[15] = i;
		}
		if (mask & HA_LATT) {
			mb->un.varCfgMSIX.messageNumberByHA[29] = i;
		}
		if (mask & HA_MBATT) {
			mb->un.varCfgMSIX.messageNumberByHA[30] = i;
		}
		if (mask & HA_ERATT) {
			mb->un.varCfgMSIX.messageNumberByHA[31] = i;
		}
#endif	/* EMLXS_BIG_ENDIAN */

#ifdef EMLXS_LITTLE_ENDIAN
		/* Accounts for word swap of LE architecture */
		if (mask & HA_R0ATT) {
			mb->un.varCfgMSIX.messageNumberByHA[0] = i;
		}
		if (mask & HA_R1ATT) {
			mb->un.varCfgMSIX.messageNumberByHA[4] = i;
		}
		if (mask & HA_R2ATT) {
			mb->un.varCfgMSIX.messageNumberByHA[8] = i;
		}
		if (mask & HA_R3ATT) {
			mb->un.varCfgMSIX.messageNumberByHA[12] = i;
		}
		if (mask & HA_LATT) {
			mb->un.varCfgMSIX.messageNumberByHA[30] = i;
		}
		if (mask & HA_MBATT) {
			mb->un.varCfgMSIX.messageNumberByHA[29] = i;
		}
		if (mask & HA_ERATT) {
			mb->un.varCfgMSIX.messageNumberByHA[28] = i;
		}
#endif	/* EMLXS_LITTLE_ENDIAN */
	}

	mb->mbxOwner = OWN_HOST;

	return;

} /* emlxs_mb_config_msix() */


#endif	/* MSI_SUPPORT */


/*ARGSUSED*/
extern void
emlxs_mb_reset_ring(emlxs_hba_t *hba, MAILBOX *mb, uint32_t ringno)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_RESET_RING;
	mb->un.varRstRing.ring_no = ringno;
	mb->mbxOwner = OWN_HOST;

	return;

} /* emlxs_mb_reset_ring() */



/*
 * emlxs_mb_dump_vpd  Issue a DUMP MEMORY mailbox command
 */
/*ARGSUSED*/
extern void
emlxs_mb_dump_vpd(emlxs_hba_t *hba, MAILBOX *mb, uint32_t offset)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	/*
	 * Setup to dump VPD region
	 */
	mb->mbxCommand = MBX_DUMP_MEMORY;
	mb->un.varDmp.cv = 1;
	mb->un.varDmp.type = DMP_NV_PARAMS;
	mb->un.varDmp.entry_index = offset;
	mb->un.varDmp.region_id = DMP_VPD_REGION;

	/* limited by mailbox size */
	mb->un.varDmp.word_cnt = DMP_VPD_DUMP_WCOUNT;

	mb->un.varDmp.co = 0;
	mb->un.varDmp.resp_offset = 0;
	mb->mbxOwner = OWN_HOST;

} /* emlxs_mb_dump_vpd() */


/*ARGSUSED*/
extern void
emlxs_mb_dump(emlxs_hba_t *hba, MAILBOX *mb, uint32_t offset, uint32_t words)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_DUMP_MEMORY;
	mb->un.varDmp.type = DMP_MEM_REG;
	mb->un.varDmp.word_cnt = words;
	mb->un.varDmp.base_adr = offset;

	mb->un.varDmp.co = 0;
	mb->un.varDmp.resp_offset = 0;
	mb->mbxOwner = OWN_HOST;

	return;

} /* emlxs_mb_dump() */



/*
 *  emlxs_mb_read_nv  Issue a READ NVPARAM mailbox command
 */
/*ARGSUSED*/
extern void
emlxs_mb_read_nv(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_READ_NV;
	mb->mbxOwner = OWN_HOST;
} /* End emlxs_mb_read_nv */


/*
 * emlxs_mb_read_rev  Issue a READ REV mailbox command
 */
/*ARGSUSED*/
extern void
emlxs_mb_read_rev(emlxs_hba_t *hba, MAILBOX *mb, uint32_t v3)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->un.varRdRev.cv = 1;

	if (v3) {
		mb->un.varRdRev.cv3 = 1;
	}

	mb->mbxCommand = MBX_READ_REV;
	mb->mbxOwner = OWN_HOST;
} /* End emlxs_mb_read_rev */


/*
 * emlxs_mb_run_biu_diag  Issue a RUN_BIU_DIAG mailbox command
 */
/*ARGSUSED*/
extern uint32_t
emlxs_mb_run_biu_diag(emlxs_hba_t *hba, MAILBOX *mb, uint64_t out,
    uint64_t in)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_RUN_BIU_DIAG64;
	mb->un.varBIUdiag.un.s2.xmit_bde64.tus.f.bdeSize = MEM_ELSBUF_SIZE;
	mb->un.varBIUdiag.un.s2.xmit_bde64.addrHigh = putPaddrHigh(out);
	mb->un.varBIUdiag.un.s2.xmit_bde64.addrLow = putPaddrLow(out);
	mb->un.varBIUdiag.un.s2.rcv_bde64.tus.f.bdeSize = MEM_ELSBUF_SIZE;
	mb->un.varBIUdiag.un.s2.rcv_bde64.addrHigh = putPaddrHigh(in);
	mb->un.varBIUdiag.un.s2.rcv_bde64.addrLow = putPaddrLow(in);
	mb->mbxOwner = OWN_HOST;

	return (0);
} /* End emlxs_mb_run_biu_diag */


/*
 *  emlxs_mb_read_la  Issue a READ LA mailbox command
 */
extern uint32_t
emlxs_mb_read_la(emlxs_hba_t *hba, MAILBOX *mb)
{
	MATCHMAP *mp;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF)) == 0) {
		mb->mbxCommand = MBX_READ_LA64;

		return (1);
	}

	mb->mbxCommand = MBX_READ_LA64;
	mb->un.varReadLA.un.lilpBde64.tus.f.bdeSize = 128;
	mb->un.varReadLA.un.lilpBde64.addrHigh = putPaddrHigh(mp->phys);
	mb->un.varReadLA.un.lilpBde64.addrLow = putPaddrLow(mp->phys);
	mb->mbxOwner = OWN_HOST;

	/*
	 * save address for completion
	 */
	((MAILBOXQ *)mb)->bp = (uint8_t *)mp;

	return (0);

} /* emlxs_mb_read_la() */


/*
 *  emlxs_mb_clear_la  Issue a CLEAR LA mailbox command
 */
extern void
emlxs_mb_clear_la(emlxs_hba_t *hba, MAILBOX *mb)
{
#ifdef FC_RPI_CHECK
	emlxs_rpi_check(hba);
#endif	/* FC_RPI_CHECK */

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->un.varClearLA.eventTag = hba->link_event_tag;
	mb->mbxCommand = MBX_CLEAR_LA;
	mb->mbxOwner = OWN_HOST;

	return;

} /* End emlxs_mb_clear_la */


/*
 * emlxs_mb_read_status  Issue a READ STATUS mailbox command
 */
/*ARGSUSED*/
extern void
emlxs_mb_read_status(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_READ_STATUS;
	mb->mbxOwner = OWN_HOST;
} /* End fc_read_status */

/*
 * emlxs_mb_read_lnk_stat  Issue a LINK STATUS mailbox command
 */
/*ARGSUSED*/
extern void
emlxs_mb_read_lnk_stat(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_READ_LNK_STAT;
	mb->mbxOwner = OWN_HOST;
} /* End emlxs_mb_read_lnk_stat */


/*
 * emlxs_mb_write_nv  Issue a WRITE NVPARAM mailbox command
 */
static void
emlxs_emb_mb_write_nv(emlxs_hba_t *hba, MAILBOX *mb)
{
	int32_t		i;
	emlxs_config_t	*cfg = &CFG;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	bcopy((void *)&hba->wwnn,
	    (void *)mb->un.varWTnvp.nodename, sizeof (NAME_TYPE));

	bcopy((void *)&hba->wwpn,
	    (void *)mb->un.varWTnvp.portname, sizeof (NAME_TYPE));

	mb->un.varWTnvp.pref_DID = 0;
	mb->un.varWTnvp.hardAL_PA = (uint8_t)cfg[CFG_ASSIGN_ALPA].current;
	mb->un.varWTnvp.rsvd1[0] = 0xffffffff;
	mb->un.varWTnvp.rsvd1[1] = 0xffffffff;
	mb->un.varWTnvp.rsvd1[2] = 0xffffffff;
	for (i = 0; i < 21; i++) {
		mb->un.varWTnvp.rsvd3[i] = 0xffffffff;
	}

	mb->mbxCommand = MBX_WRITE_NV;
	mb->mbxOwner = OWN_HOST;
} /* End emlxs_mb_write_nv */


/*
 * emlxs_mb_part_slim  Issue a PARTITION SLIM mailbox command
 */
static void
emlxs_mb_part_slim(emlxs_hba_t *hba, MAILBOX *mb, uint32_t hbainit)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);


	mb->un.varSlim.numRing = hba->ring_count;
	mb->un.varSlim.hbainit = hbainit;
	mb->mbxCommand = MBX_PART_SLIM;
	mb->mbxOwner = OWN_HOST;
} /* End emlxs_mb_part_slim */


/*
 * emlxs_mb_config_ring  Issue a CONFIG RING mailbox command
 */
extern void
emlxs_mb_config_ring(emlxs_hba_t *hba, int32_t ring, MAILBOX *mb)
{
	int32_t i;
	int32_t j;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	j = 0;
	for (i = 0; i < ring; i++) {
		j += hba->ring_masks[i];
	}

	for (i = 0; i < hba->ring_masks[ring]; i++) {
		if ((j + i) >= 6) {
			break;
		}

		mb->un.varCfgRing.rrRegs[i].rval  = hba->ring_rval[j + i];
		mb->un.varCfgRing.rrRegs[i].rmask = hba->ring_rmask[j + i];

		mb->un.varCfgRing.rrRegs[i].tval  = hba->ring_tval[j + i];
		mb->un.varCfgRing.rrRegs[i].tmask = hba->ring_tmask[j + i];
	}

	mb->un.varCfgRing.ring = ring;
	mb->un.varCfgRing.profile = 0;
	mb->un.varCfgRing.maxOrigXchg = 0;
	mb->un.varCfgRing.maxRespXchg = 0;
	mb->un.varCfgRing.recvNotify = 1;
	mb->un.varCfgRing.numMask = hba->ring_masks[ring];
	mb->mbxCommand = MBX_CONFIG_RING;
	mb->mbxOwner = OWN_HOST;

	return;

} /* End emlxs_mb_config_ring */


/*
 *  emlxs_mb_config_link  Issue a CONFIG LINK mailbox command
 */
extern void
emlxs_mb_config_link(emlxs_hba_t *hba, MAILBOX *mb)
{
	emlxs_port_t   *port = &PPORT;
	emlxs_config_t *cfg = &CFG;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	/*
	 * NEW_FEATURE SLI-2, Coalescing Response Feature.
	 */
	if (cfg[CFG_CR_DELAY].current) {
		mb->un.varCfgLnk.cr = 1;
		mb->un.varCfgLnk.ci = 1;
		mb->un.varCfgLnk.cr_delay = cfg[CFG_CR_DELAY].current;
		mb->un.varCfgLnk.cr_count = cfg[CFG_CR_COUNT].current;
	}

	if (cfg[CFG_ACK0].current)
		mb->un.varCfgLnk.ack0_enable = 1;

	mb->un.varCfgLnk.myId = port->did;
	mb->un.varCfgLnk.edtov = hba->fc_edtov;
	mb->un.varCfgLnk.arbtov = hba->fc_arbtov;
	mb->un.varCfgLnk.ratov = hba->fc_ratov;
	mb->un.varCfgLnk.rttov = hba->fc_rttov;
	mb->un.varCfgLnk.altov = hba->fc_altov;
	mb->un.varCfgLnk.crtov = hba->fc_crtov;
	mb->un.varCfgLnk.citov = hba->fc_citov;
	mb->mbxCommand = MBX_CONFIG_LINK;
	mb->mbxOwner = OWN_HOST;

	return;

} /* emlxs_mb_config_link() */


/*
 *  emlxs_mb_init_link  Issue an INIT LINK mailbox command
 */
extern void
emlxs_mb_init_link(emlxs_hba_t *hba, MAILBOX *mb, uint32_t topology,
    uint32_t linkspeed)
{
	emlxs_vpd_t	*vpd = &VPD;
	emlxs_config_t	*cfg = &CFG;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	switch (topology) {
	case FLAGS_LOCAL_LB:
		mb->un.varInitLnk.link_flags = FLAGS_TOPOLOGY_MODE_LOOP;
		mb->un.varInitLnk.link_flags |= FLAGS_LOCAL_LB;
		break;
	case FLAGS_TOPOLOGY_MODE_LOOP_PT:
		mb->un.varInitLnk.link_flags = FLAGS_TOPOLOGY_MODE_LOOP;
		mb->un.varInitLnk.link_flags |= FLAGS_TOPOLOGY_FAILOVER;
		break;
	case FLAGS_TOPOLOGY_MODE_PT_PT:
		mb->un.varInitLnk.link_flags = FLAGS_TOPOLOGY_MODE_PT_PT;
		break;
	case FLAGS_TOPOLOGY_MODE_LOOP:
		mb->un.varInitLnk.link_flags = FLAGS_TOPOLOGY_MODE_LOOP;
		break;
	case FLAGS_TOPOLOGY_MODE_PT_LOOP:
		mb->un.varInitLnk.link_flags = FLAGS_TOPOLOGY_MODE_PT_PT;
		mb->un.varInitLnk.link_flags |= FLAGS_TOPOLOGY_FAILOVER;
		break;
	}

	if (cfg[CFG_LILP_ENABLE].current == 0) {
		/* Disable LIRP/LILP support */
		mb->un.varInitLnk.link_flags |= FLAGS_LIRP_LILP;
	}

	/*
	 * Setting up the link speed
	 */
	switch (linkspeed) {
	case 0:
		break;

	case 1:
		if (!(vpd->link_speed & LMT_1GB_CAPABLE)) {
			linkspeed = 0;
		}
		break;

	case 2:
		if (!(vpd->link_speed & LMT_2GB_CAPABLE)) {
			linkspeed = 0;
		}
		break;

	case 4:
		if (!(vpd->link_speed & LMT_4GB_CAPABLE)) {
			linkspeed = 0;
		}
		break;

	case 8:
		if (!(vpd->link_speed & LMT_8GB_CAPABLE)) {
			linkspeed = 0;
		}
		break;

	case 10:
		if (!(vpd->link_speed & LMT_10GB_CAPABLE)) {
			linkspeed = 0;
		}
		break;

	default:
		linkspeed = 0;
		break;

	}

	if ((linkspeed > 0) && (vpd->feaLevelHigh >= 0x02)) {
		mb->un.varInitLnk.link_flags |= FLAGS_LINK_SPEED;
		mb->un.varInitLnk.link_speed = linkspeed;
	}

	mb->un.varInitLnk.link_flags |= FLAGS_PREABORT_RETURN;

	mb->un.varInitLnk.fabric_AL_PA =
	    (uint8_t)cfg[CFG_ASSIGN_ALPA].current;
	mb->mbxCommand = (volatile uint8_t) MBX_INIT_LINK;
	mb->mbxOwner = OWN_HOST;


	return;

} /* emlxs_mb_init_link() */


/*
 *  emlxs_mb_down_link  Issue a DOWN LINK mailbox command
 */
/*ARGSUSED*/
extern void
emlxs_mb_down_link(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_DOWN_LINK;
	mb->mbxOwner = OWN_HOST;

	return;

} /* emlxs_mb_down_link() */


/*
 * emlxs_mb_read_sparam  Issue a READ SPARAM mailbox command
 */
extern uint32_t
emlxs_mb_read_sparam(emlxs_hba_t *hba, MAILBOX *mb)
{
	MATCHMAP *mp;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF)) == 0) {
		mb->mbxCommand = MBX_READ_SPARM64;

		return (1);
	}

	mb->un.varRdSparm.un.sp64.tus.f.bdeSize = sizeof (SERV_PARM);
	mb->un.varRdSparm.un.sp64.addrHigh = putPaddrHigh(mp->phys);
	mb->un.varRdSparm.un.sp64.addrLow = putPaddrLow(mp->phys);
	mb->mbxCommand = MBX_READ_SPARM64;
	mb->mbxOwner = OWN_HOST;

	/*
	 * save address for completion
	 */
	((MAILBOXQ *)mb)->bp = (uint8_t *)mp;

	return (0);

} /* emlxs_mb_read_sparam() */


/*
 * emlxs_mb_read_rpi    Issue a READ RPI mailbox command
 */
/*ARGSUSED*/
extern uint32_t
emlxs_mb_read_rpi(emlxs_hba_t *hba, uint32_t rpi, MAILBOX *mb,
    uint32_t flag)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	/*
	 * Set flag to issue action on cmpl
	 */
	mb->un.varWords[30] = flag;
	mb->un.varRdRPI.reqRpi = (volatile uint16_t) rpi;
	mb->mbxCommand = MBX_READ_RPI64;
	mb->mbxOwner = OWN_HOST;

	return (0);
} /* End emlxs_mb_read_rpi */


/*
 * emlxs_mb_read_xri    Issue a READ XRI mailbox command
 */
/*ARGSUSED*/
extern uint32_t
emlxs_mb_read_xri(emlxs_hba_t *hba, uint32_t xri, MAILBOX *mb,
    uint32_t flag)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	/*
	 * Set flag to issue action on cmpl
	 */
	mb->un.varWords[30] = flag;
	mb->un.varRdXRI.reqXri = (volatile uint16_t)xri;
	mb->mbxCommand = MBX_READ_XRI;
	mb->mbxOwner = OWN_HOST;

	return (0);
} /* End emlxs_mb_read_xri */


/*ARGSUSED*/
extern int32_t
emlxs_mb_check_sparm(emlxs_hba_t *hba, SERV_PARM *nsp)
{
	uint32_t nsp_value;
	uint32_t *iptr;

	if (nsp->cmn.fPort) {
		return (0);
	}

	/* Validate the service parameters */
	iptr = (uint32_t *)&nsp->portName;
	if (iptr[0] == 0 && iptr[1] == 0) {
		return (1);
	}

	iptr = (uint32_t *)&nsp->nodeName;
	if (iptr[0] == 0 && iptr[1] == 0) {
		return (2);
	}

	if (nsp->cls2.classValid) {
		nsp_value =
		    ((nsp->cls2.rcvDataSizeMsb & 0x0f) << 8) | nsp->cls2.
		    rcvDataSizeLsb;

		/* If the receive data length is zero then set it to */
		/* the CSP value */
		if (!nsp_value) {
			nsp->cls2.rcvDataSizeMsb = nsp->cmn.bbRcvSizeMsb;
			nsp->cls2.rcvDataSizeLsb = nsp->cmn.bbRcvSizeLsb;
			return (0);
		}
	}

	if (nsp->cls3.classValid) {
		nsp_value =
		    ((nsp->cls3.rcvDataSizeMsb & 0x0f) << 8) | nsp->cls3.
		    rcvDataSizeLsb;

		/* If the receive data length is zero then set it to */
		/* the CSP value */
		if (!nsp_value) {
			nsp->cls3.rcvDataSizeMsb = nsp->cmn.bbRcvSizeMsb;
			nsp->cls3.rcvDataSizeLsb = nsp->cmn.bbRcvSizeLsb;
			return (0);
		}
	}

	return (0);

} /* emlxs_mb_check_sparm() */


/*
 * emlxs_mb_reg_did  Issue a REG_LOGIN mailbox command
 */
extern uint32_t
emlxs_mb_reg_did(emlxs_port_t *port, uint32_t did, SERV_PARM *param,
    emlxs_buf_t *sbp, fc_unsol_buf_t *ubp, IOCBQ *iocbq)
{
	emlxs_hba_t	*hba = HBA;
	MATCHMAP	*mp;
	MAILBOXQ	*mbq;
	MAILBOX		*mb;
	uint32_t	rval;

	/* Check for invalid node ids to register */
	if ((did == 0) && (!(hba->flag & FC_LOOPBACK_MODE))) {
		return (1);
	}

	if (did & 0xff000000) {
		return (1);
	}

	if ((rval = emlxs_mb_check_sparm(hba, param))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_create_failed_msg,
		    "Invalid service parameters. did=%06x rval=%d", did,
		    rval);

		return (1);
	}

	/* Check if the node limit has been reached */
	if (port->node_count >= hba->max_nodes) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_create_failed_msg,
		    "Limit reached. did=%06x count=%d", did,
		    port->node_count);

		return (1);
	}

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX | MEM_PRI))) {
		return (1);
	}

	/* Build login request */
	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF | MEM_PRI)) == 0) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
		return (1);
	}

	bcopy((void *)param, (void *)mp->virt, sizeof (SERV_PARM));

	mb = (MAILBOX *)mbq->mbox;
	mb->un.varRegLogin.un.sp64.tus.f.bdeSize = sizeof (SERV_PARM);
	mb->un.varRegLogin.un.sp64.addrHigh = putPaddrHigh(mp->phys);
	mb->un.varRegLogin.un.sp64.addrLow = putPaddrLow(mp->phys);
	mb->un.varRegLogin.rpi = 0;
	mb->un.varRegLogin.did = did;
	mb->un.varWords[30] = 0;	/* flags */
	mb->mbxCommand = MBX_REG_LOGIN64;
	mb->mbxOwner = OWN_HOST;

#ifdef SLI3_SUPPORT
	mb->un.varRegLogin.vpi = port->vpi;
#endif	/* SLI3_SUPPORT */

	mbq->sbp = (uint8_t *)sbp;
	mbq->ubp = (uint8_t *)ubp;
	mbq->iocbq = (uint8_t *)iocbq;
	mbq->bp = (uint8_t *)mp;

	if (emlxs_sli_issue_mbox_cmd(hba, mb, MBX_NOWAIT, 0) != MBX_BUSY) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}

	return (0);

} /* emlxs_mb_reg_did() */

/*
 * emlxs_mb_unreg_rpi  Issue a UNREG_LOGIN mailbox command
 */
extern uint32_t
emlxs_mb_unreg_rpi(emlxs_port_t *port, uint32_t rpi, emlxs_buf_t *sbp,
    fc_unsol_buf_t *ubp, IOCBQ *iocbq)
{
	emlxs_hba_t	*hba = HBA;
	MAILBOXQ	*mbq;
	MAILBOX		*mb;
	NODELIST	*ndlp;

	if (rpi != 0xffff) {
		/* Make sure the node does already exist */
		ndlp = emlxs_node_find_rpi(port, rpi);


		if (ndlp) {
			/*
			 * If we just unregistered the host node then
			 * clear the host DID
			 */
			if (ndlp->nlp_DID == port->did) {
				port->did = 0;
			}

			/* remove it */
			emlxs_node_rm(port, ndlp);

		} else {
			return (1);
		}
	} else {	/* Unreg all */

		emlxs_node_destroy_all(port);
	}

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX | MEM_PRI))) {
		return (1);
	}

	mb = (MAILBOX *)mbq->mbox;
	mb->un.varUnregLogin.rpi = (uint16_t)rpi;

#ifdef SLI3_SUPPORT
	mb->un.varUnregLogin.vpi = port->vpi;
#endif  /* SLI3_SUPPORT */

	mb->mbxCommand = MBX_UNREG_LOGIN;
	mb->mbxOwner = OWN_HOST;
	mbq->sbp = (uint8_t *)sbp;
	mbq->ubp = (uint8_t *)ubp;
	mbq->iocbq = (uint8_t *)iocbq;

	if (emlxs_sli_issue_mbox_cmd(hba, mb, MBX_NOWAIT, 0) != MBX_BUSY) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}

	return (0);
} /* emlxs_mb_unreg_rpi() */

/*
 * emlxs_mb_unreg_did  Issue a UNREG_DID mailbox command
 */
extern uint32_t
emlxs_mb_unreg_did(emlxs_port_t *port, uint32_t did, emlxs_buf_t *sbp,
    fc_unsol_buf_t *ubp, IOCBQ *iocbq)
{
	emlxs_hba_t	*hba = HBA;
	NODELIST	*ndlp;
	MAILBOXQ	*mbq;
	MAILBOX		*mb;

	/*
	 * Unregister all default RPIs if did == 0xffffffff
	 */
	if (did != 0xffffffff) {
		/* Check for base node */
		if (did == Bcast_DID) {
			/* just flush base node */
			(void) emlxs_tx_node_flush(port, &port->node_base,
			    0, 0, 0);
			(void) emlxs_chipq_node_flush(port, 0,
			    &port->node_base, 0);

			/* Return now */
			return (1);
		}


		/*
		 * A zero DID means that we are trying to unreg the host node
		 * after a link bounce
		 */

		/*
		 * If the prev_did == 0 then the adapter has been reset and
		 * there is no need in unregistering
		 */

		/*
		 * If the prev_did != 0 then we can look for the hosts
		 * last known DID node
		 */

		if (did == 0) {
			if (port->prev_did == 0) {
				return (1);
			}

			did = port->prev_did;
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
			return (1);
		}
	}

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX | MEM_PRI))) {
		return (1);
	}

	mb = (MAILBOX *)mbq->mbox;
	mb->un.varUnregDID.did = did;

#ifdef SLI3_SUPPORT
	mb->un.varUnregDID.vpi = port->vpi;
#endif	/* SLI3_SUPPORT */

	mb->mbxCommand = MBX_UNREG_D_ID;
	mb->mbxOwner = OWN_HOST;
	mbq->sbp = (uint8_t *)sbp;
	mbq->ubp = (uint8_t *)ubp;
	mbq->iocbq = (uint8_t *)iocbq;

	if (emlxs_sli_issue_mbox_cmd(hba, mb, MBX_NOWAIT, 0) != MBX_BUSY) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}

	return (0);

} /* End emlxs_mb_unreg_did */


/*
 * emlxs_mb_set_mask   Issue a SET MASK mailbox command
 */
/*ARGSUSED*/
static void
emlxs_mb_set_mask(emlxs_hba_t *hba, MAILBOX *mb, uint32_t mask,
    uint32_t ringno)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->un.varWords[0] = 0x11223344;	/* set passwd */
	mb->un.varWords[1] = mask;	/* set mask */
	mb->un.varWords[2] = ringno;	/* set ringno */
	mb->mbxCommand = MBX_SET_MASK;
	mb->mbxOwner = OWN_HOST;
} /* End emlxs_mb_set_mask */


/*
 * emlxs_mb_set_debug  Issue a special debug mailbox command
 */
/*ARGSUSED*/
static void
emlxs_mb_set_debug(emlxs_hba_t *hba, MAILBOX *mb, uint32_t word0,
    uint32_t word1, uint32_t word2)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->un.varWords[0] = word0;
	mb->un.varWords[1] = word1;
	mb->un.varWords[2] = word2;
	mb->mbxCommand = MBX_SET_DEBUG;
	mb->mbxOwner = OWN_HOST;
} /* End emlxs_mb_set_debug */


/*
 * emlxs_mb_set_var   Issue a special debug mbox command to write slim
 */
/*ARGSUSED*/
extern void
emlxs_mb_set_var(emlxs_hba_t *hba, MAILBOX *mb, uint32_t addr,
    uint32_t value)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	/* addr = 0x090597 is AUTO ABTS disable for ELS commands */
	/* addr = 0x052198 is DELAYED ABTS enable for ELS commands */
	/* addr = 0x100506 is for setting PCI MAX READ value */

	/*
	 * Always turn on DELAYED ABTS for ELS timeouts
	 */
	if ((addr == 0x052198) && (value == 0)) {
		value = 1;
	}

	mb->un.varWords[0] = addr;
	mb->un.varWords[1] = value;
	mb->mbxCommand = MBX_SET_VARIABLE;
	mb->mbxOwner = OWN_HOST;
} /* End emlxs_mb_set_var */


/*
 * Disable Traffic Cop
 */
/*ARGSUSED*/
extern void
emlxs_disable_tc(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->un.varWords[0] = 0x50797;
	mb->un.varWords[1] = 0;
	mb->un.varWords[2] = 0xfffffffe;
	mb->mbxCommand = MBX_SET_VARIABLE;
	mb->mbxOwner = OWN_HOST;

} /* End emlxs_disable_tc */



#ifdef SLI3_SUPPORT
extern void
emlxs_mb_config_hbq(emlxs_hba_t *hba, MAILBOX *mb, int hbq_id)
{
	HBQ_INIT_t	*hbq;
	int		i;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	hbq = &hba->hbq_table[hbq_id];

	mb->un.varCfgHbq.hbqId = hbq_id;
	mb->un.varCfgHbq.numEntries = hbq->HBQ_numEntries;
	mb->un.varCfgHbq.recvNotify = hbq->HBQ_recvNotify;
	mb->un.varCfgHbq.numMask = hbq->HBQ_num_mask;
	mb->un.varCfgHbq.profile = hbq->HBQ_profile;
	mb->un.varCfgHbq.ringMask = hbq->HBQ_ringMask;
	mb->un.varCfgHbq.headerLen = hbq->HBQ_headerLen;
	mb->un.varCfgHbq.logEntry = hbq->HBQ_logEntry;
	mb->un.varCfgHbq.hbqaddrLow = putPaddrLow(hbq->HBQ_host_buf.phys);
	mb->un.varCfgHbq.hbqaddrHigh = putPaddrHigh(hbq->HBQ_host_buf.phys);
	mb->mbxCommand = MBX_CONFIG_HBQ;
	mb->mbxOwner = OWN_HOST;

	/* Copy info for profiles 2,3,5. Other profiles this area is reserved */
	if ((hbq->HBQ_profile == 2) || (hbq->HBQ_profile == 3) ||
	    (hbq->HBQ_profile == 5)) {
		bcopy(&hbq->profiles.allprofiles,
		    &mb->un.varCfgHbq.profiles.allprofiles,
		    sizeof (hbq->profiles));
	}

	/* Return if no rctl / type masks for this HBQ */
	if (!hbq->HBQ_num_mask) {
		return;
	}

	/* Otherwise we setup specific rctl / type masks for this HBQ */
	for (i = 0; i < hbq->HBQ_num_mask; i++) {
		mb->un.varCfgHbq.hbqMasks[i].tmatch =
		    hbq->HBQ_Masks[i].tmatch;
		mb->un.varCfgHbq.hbqMasks[i].tmask = hbq->HBQ_Masks[i].tmask;
		mb->un.varCfgHbq.hbqMasks[i].rctlmatch =
		    hbq->HBQ_Masks[i].rctlmatch;
		mb->un.varCfgHbq.hbqMasks[i].rctlmask =
		    hbq->HBQ_Masks[i].rctlmask;
	}

	return;

} /* emlxs_mb_config_hbq() */

#endif	/* SLI3_SUPPORT */


extern uint32_t
emlxs_mb_reg_vpi(emlxs_port_t *port)
{
	emlxs_hba_t	*hba = HBA;
	MAILBOXQ	*mbq;
	MAILBOX		*mb;

	if (!(hba->flag & FC_NPIV_ENABLED)) {
		return (0);
	}

	mutex_enter(&EMLXS_PORT_LOCK);

	/* Can't reg vpi until ClearLA is sent */
	if (hba->state != FC_READY) {
		mutex_exit(&EMLXS_PORT_LOCK);

		return (1);
	}

	/* Must have port id */
	if (!port->did) {
		mutex_exit(&EMLXS_PORT_LOCK);

		return (1);
	}

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX | MEM_PRI))) {
		mutex_exit(&EMLXS_PORT_LOCK);

		return (1);
	}

	port->flag |= EMLXS_PORT_REGISTERED;

	mutex_exit(&EMLXS_PORT_LOCK);

	mb = (MAILBOX *)mbq->mbox;
	bzero((void *)mb, MAILBOX_CMD_BSIZE);
	mb->un.varRegVpi.vpi = port->vpi;
	mb->un.varRegVpi.sid = port->did;
	mb->mbxCommand = MBX_REG_VPI;
	mb->mbxOwner = OWN_HOST;

	if (emlxs_sli_issue_mbox_cmd(hba, mb, MBX_NOWAIT, 0) != MBX_BUSY) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}

	return (0);

} /* emlxs_mb_reg_vpi() */


extern uint32_t
emlxs_mb_unreg_vpi(emlxs_port_t *port)
{
	emlxs_hba_t	*hba = HBA;
	MAILBOXQ	*mbq;
	MAILBOX		*mb;

	mutex_enter(&EMLXS_PORT_LOCK);

	if (!(port->flag & EMLXS_PORT_REGISTERED)) {
		mutex_exit(&EMLXS_PORT_LOCK);

		return (0);
	}

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX | MEM_PRI))) {
		mutex_exit(&EMLXS_PORT_LOCK);

		return (1);
	}

	port->flag &= ~EMLXS_PORT_REGISTERED;

	mutex_exit(&EMLXS_PORT_LOCK);

	mb = (MAILBOX *)mbq->mbox;
	bzero((void *)mb, MAILBOX_CMD_BSIZE);
	mb->un.varUnregVpi.vpi = port->vpi;
	mb->mbxCommand = MBX_UNREG_VPI;
	mb->mbxOwner = OWN_HOST;

	if (emlxs_sli_issue_mbox_cmd(hba, mb, MBX_NOWAIT, 0) != MBX_BUSY) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}

	return (0);

} /* emlxs_mb_unreg_vpi() */


/*
 * emlxs_mb_config_farp  Issue a CONFIG FARP mailbox command
 */
extern void
emlxs_mb_config_farp(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	bcopy((uint8_t *)&hba->wwpn,
	    (uint8_t *)&mb->un.varCfgFarp.portname, sizeof (NAME_TYPE));

	bcopy((uint8_t *)&hba->wwpn,
	    (uint8_t *)&mb->un.varCfgFarp.nodename, sizeof (NAME_TYPE));

	mb->un.varCfgFarp.filterEnable = 1;
	mb->un.varCfgFarp.portName = 1;
	mb->un.varCfgFarp.nodeName = 1;
	mb->mbxCommand = MBX_CONFIG_FARP;
	mb->mbxOwner = OWN_HOST;
} /* emlxs_mb_config_farp() */


/*
 * emlxs_mb_read_nv  Issue a READ CONFIG mailbox command
 */
/*ARGSUSED*/
extern void
emlxs_mb_read_config(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_READ_CONFIG;
	mb->mbxOwner = OWN_HOST;
} /* emlxs_mb_read_config() */



/*
 * NAME:     emlxs_mb_put
 *
 * FUNCTION: put mailbox cmd onto the mailbox queue.
 *
 * EXECUTION ENVIRONMENT: process and interrupt level.
 *
 * NOTES:
 *
 * CALLED FROM: emlxs_sli_issue_mbox_cmd
 *
 * INPUT: hba           - pointer to the device info area
 *      mbp             - pointer to mailbox queue entry of mailbox cmd
 *
 * RETURNS: NULL - command queued
 */
extern void
emlxs_mb_put(emlxs_hba_t *hba, MAILBOXQ *mbq)
{

	mutex_enter(&EMLXS_MBOX_LOCK);

	if (hba->mbox_queue.q_first) {

		/*
		 * queue command to end of list
		 */
		((MAILBOXQ *)hba->mbox_queue.q_last)->next = mbq;
		hba->mbox_queue.q_last = (uint8_t *)mbq;
		hba->mbox_queue.q_cnt++;
	} else {

		/*
		 * add command to empty list
		 */
		hba->mbox_queue.q_first = (uint8_t *)mbq;
		hba->mbox_queue.q_last = (uint8_t *)mbq;
		hba->mbox_queue.q_cnt = 1;
	}

	mbq->next = NULL;

	mutex_exit(&EMLXS_MBOX_LOCK);
} /* emlxs_mb_put() */


/*
 * NAME:     emlxs_mb_get
 *
 * FUNCTION: get a mailbox command from mailbox command queue
 *
 * EXECUTION ENVIRONMENT: interrupt level.
 *
 * NOTES:
 *
 * CALLED FROM: emlxs_handle_mb_event
 *
 * INPUT: hba       - pointer to the device info area
 *
 * RETURNS: NULL - no match found mb pointer - pointer to a mailbox command
 */
extern MAILBOXQ *
emlxs_mb_get(emlxs_hba_t *hba)
{
	MAILBOXQ	*p_first = NULL;

	mutex_enter(&EMLXS_MBOX_LOCK);

	if (hba->mbox_queue.q_first) {
		p_first = (MAILBOXQ *)hba->mbox_queue.q_first;
		hba->mbox_queue.q_first = (uint8_t *)p_first->next;

		if (hba->mbox_queue.q_first == NULL) {
			hba->mbox_queue.q_last = NULL;
			hba->mbox_queue.q_cnt = 0;
		} else {
			hba->mbox_queue.q_cnt--;
		}

		p_first->next = NULL;
	}

	mutex_exit(&EMLXS_MBOX_LOCK);

	return (p_first);

} /* emlxs_mb_get() */



/* EMLXS_PORT_LOCK must be held when calling this */
void
emlxs_mb_init(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t flag, uint32_t tmo)
{
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif	/* FMA_SUPPORT */
	MATCHMAP	*mp;

	HBASTATS.MboxIssued++;
	hba->mbox_queue_flag = flag;

	/* Set the Mailbox timer */
	hba->mbox_timer = hba->timer_tics + tmo;

	/* Initialize mailbox */
	mbq->flag &= MBQ_INIT_MASK;
	hba->mbox_mbqflag = mbq->flag;

	mbq->next = 0;

	mutex_enter(&EMLXS_MBOX_LOCK);
	if (flag == MBX_NOWAIT) {
		hba->mbox_mbq = 0;
	} else {
		hba->mbox_mbq = (uint8_t *)mbq;
	}
	mutex_exit(&EMLXS_MBOX_LOCK);

	if (mbq->bp) {
		mp = (MATCHMAP *) mbq->bp;
		emlxs_mpdata_sync(mp->dma_handle, 0, mp->size,
		    DDI_DMA_SYNC_FORDEV);

		hba->mbox_bp = mbq->bp;
		mbq->bp = 0;
	}

	if (mbq->sbp) {
		hba->mbox_sbp = mbq->sbp;
		mbq->sbp = 0;
	}

	if (mbq->ubp) {
		hba->mbox_ubp = mbq->ubp;
		mbq->ubp = 0;
	}

	if (mbq->iocbq) {
		hba->mbox_iocbq = mbq->iocbq;
		mbq->iocbq = 0;
	}
#ifdef MBOX_EXT_SUPPORT
	if (mbq->extbuf && mbq->extsize) {
		hba->mbox_ext = mbq->extbuf;
		hba->mbox_ext_size = mbq->extsize;
	}
#endif /* MBOX_EXT_SUPPORT */

	return;

} /* emlxs_mb_init() */


extern void
emlxs_mb_fini(emlxs_hba_t *hba, MAILBOX *mb, uint32_t mbxStatus)
{
	emlxs_port_t	*port = &PPORT;
	MATCHMAP	*mbox_bp;
	emlxs_buf_t	*mbox_sbp;
	fc_unsol_buf_t	*mbox_ubp;
	IOCBQ		*mbox_iocbq;
	MAILBOXQ	*mbox_mbq;
	MAILBOX		*mbox;
	uint32_t	mbox_queue_flag;
	emlxs_ub_priv_t	*ub_priv;

	mutex_enter(&EMLXS_PORT_LOCK);

	if (hba->mbox_queue_flag) {
		HBASTATS.MboxCompleted++;

		if (mbxStatus != MBX_SUCCESS) {
			HBASTATS.MboxError++;
		} else {
			HBASTATS.MboxGood++;
		}
	}

	mbox_bp = (MATCHMAP *)hba->mbox_bp;
	mbox_sbp = (emlxs_buf_t *)hba->mbox_sbp;
	mbox_ubp = (fc_unsol_buf_t *)hba->mbox_ubp;
	mbox_iocbq = (IOCBQ *)hba->mbox_iocbq;
	mbox_mbq = (MAILBOXQ *)hba->mbox_mbq;
	mbox_queue_flag = hba->mbox_queue_flag;

#ifdef MBOX_EXT_SUPPORT
	hba->mbox_ext = 0;
	hba->mbox_ext_size = 0;
#endif /* MBOX_EXT_SUPPORT */

	hba->mbox_bp = 0;
	hba->mbox_sbp = 0;
	hba->mbox_ubp = 0;
	hba->mbox_iocbq = 0;
	hba->mbox_mbqflag = 0;
	hba->mbox_mbq = 0;
	hba->mbox_timer = 0;
	hba->mbox_queue_flag = 0;

	mutex_exit(&EMLXS_PORT_LOCK);

	if (mbox_mbq) {
		if (mb) {
			/* Copy the local mailbox provided back into */
			/* the original mailbox */
			bcopy((uint32_t *)mb, (uint32_t *)mbox_mbq,
			    MAILBOX_CMD_BSIZE);
		}

		mbox = (MAILBOX *)mbox_mbq;
		mbox->mbxStatus = mbxStatus;

		/* Mark mailbox complete */
		mbox_mbq->flag |= MBQ_COMPLETED;

		/* Wake up the sleeping thread */
		if (mbox_queue_flag == MBX_SLEEP) {
			mutex_enter(&EMLXS_MBOX_LOCK);
			cv_broadcast(&EMLXS_MBOX_CV);
			mutex_exit(&EMLXS_MBOX_LOCK);
		}
	}

	/* Check for deferred MBUF cleanup */
	if (mbox_bp && (mbox_queue_flag == MBX_NOWAIT)) {
		(void) emlxs_mem_put(hba, MEM_BUF, (uint8_t *)mbox_bp);
	}
#ifdef SFCT_SUPPORT
	if (mbox_sbp && mbox_sbp->fct_cmd) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "FCT mailbox: %s: status=%x",
		    emlxs_mb_cmd_xlate(mb->mbxCommand),
		    (uint32_t)mb->mbxStatus);
	}
#endif /* SFCT_SUPPORT */

	/* Check for deferred pkt completion */
	if (mbox_sbp) {
		if (mbxStatus != MBX_SUCCESS) {
			/* Set error status */
			mbox_sbp->pkt_flags &= ~PACKET_STATE_VALID;
			emlxs_set_pkt_state(mbox_sbp, IOSTAT_LOCAL_REJECT,
			    IOERR_NO_RESOURCES, 1);
		}

		emlxs_pkt_complete(mbox_sbp, -1, 0, 1);
	}

	/* Check for deferred ub completion */
	if (mbox_ubp) {
		ub_priv = mbox_ubp->ub_fca_private;
		port = ub_priv->port;

		emlxs_ub_callback(port, mbox_ubp);
	}

	/* Check for deferred iocb tx */
	if (mbox_iocbq) {
		emlxs_sli_issue_iocb_cmd(hba, mbox_iocbq->ring, mbox_iocbq);
	}

	return;

} /* emlxs_mb_fini() */



/* This should only be called with active MBX_NOWAIT mailboxes */
void
emlxs_mb_retry(emlxs_hba_t *hba, MAILBOX *mb)
{
	MAILBOXQ	*mbq;

	mutex_enter(&EMLXS_PORT_LOCK);

	HBASTATS.MboxCompleted++;

	if (mb->mbxStatus != 0) {
		HBASTATS.MboxError++;
	} else {
		HBASTATS.MboxGood++;
	}

	mbq = (MAILBOXQ *)mb;
	mbq->bp = (uint8_t *)hba->mbox_bp;
	mbq->sbp = (uint8_t *)hba->mbox_sbp;
	mbq->ubp = (uint8_t *)hba->mbox_ubp;
	mbq->iocbq = (uint8_t *)hba->mbox_iocbq;

	hba->mbox_bp = 0;
	hba->mbox_sbp = 0;
	hba->mbox_ubp = 0;
	hba->mbox_iocbq = 0;
	hba->mbox_mbq = 0;
	hba->mbox_mbqflag = 0;
	hba->mbox_queue_flag = 0;

	mutex_exit(&EMLXS_PORT_LOCK);

	return;

} /* emlxs_mb_retry() */


extern char *
emlxs_mb_cmd_xlate(uint8_t cmd)
{
	static char	buffer[32];
	uint32_t	i;
	uint32_t	count;

	count = sizeof (emlxs_mb_cmd_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (cmd == emlxs_mb_cmd_table[i].code) {
			return (emlxs_mb_cmd_table[i].string);
		}
	}

	(void) sprintf(buffer, "Cmd=0x%x", cmd);
	return (buffer);

} /* emlxs_mb_cmd_xlate() */
