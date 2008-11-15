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
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */


#include "emlxs.h"

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_MBOX_C);

static void emlxs_mb_part_slim(emlxs_hba_t *hba, MAILBOX *mb,
    uint32_t hbainit);
static void emlxs_mb_set_mask(emlxs_hba_t *hba, MAILBOX *mb, uint32_t mask,
    uint32_t ringno);
static void emlxs_mb_set_debug(emlxs_hba_t *hba, MAILBOX *mb, uint32_t word0,
    uint32_t word1, uint32_t word2);
static int32_t emlxs_mb_handle_cmd(emlxs_hba_t *hba, MAILBOX *mb);
static void emlxs_mb_write_nv(emlxs_hba_t *hba, MAILBOX *mb);

static void emlxs_mb_init(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t flag,
    uint32_t tmo);
static void emlxs_mb_retry(emlxs_hba_t *hba, MAILBOX *mb);


emlxs_table_t emlxs_mb_cmd_table[] =
{
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
	{MBX_NV_LOG, "NV_LOG"}

};	/* emlxs_mb_cmd_table */


/* ARGSUSED */
extern void
emlxs_mb_async_event(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_ASYNC_EVENT;
	mb->mbxOwner = OWN_HOST;
	mb->un.varWords[0] = FC_ELS_RING;

	return;

} /* emlxs_mb_async_event() */


/* ARGSUSED */
extern void
emlxs_mb_heartbeat(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_HEARTBEAT;
	mb->mbxOwner = OWN_HOST;

	return;

} /* emlxs_mb_heartbeat() */


#ifdef MSI_SUPPORT

/* ARGSUSED */
extern void
emlxs_mb_config_msi(emlxs_hba_t *hba, MAILBOX *mb, uint32_t *intr_map,
    uint32_t intr_count)
{
	uint32_t i;
	uint32_t mask;

	bzero((void *) mb, MAILBOX_CMD_BSIZE);

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


/* ARGSUSED */
extern void
emlxs_mb_config_msix(emlxs_hba_t *hba, MAILBOX *mb, uint32_t *intr_map,
    uint32_t intr_count)
{
	uint32_t i;
	uint32_t mask;

	bzero((void *) mb, MAILBOX_CMD_BSIZE);

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

/* ARGSUSED */
extern void
emlxs_mb_reset_ring(emlxs_hba_t *hba, MAILBOX *mb, uint32_t ringno)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_RESET_RING;
	mb->un.varRstRing.ring_no = ringno;
	mb->mbxOwner = OWN_HOST;

	return;

} /* emlxs_mb_reset_ring() */



/*
 *  emlxs_mb_dump_vpd  Issue a DUMP MEMORY
 *                     mailbox command
 */
/* ARGSUSED */
extern void
emlxs_mb_dump_vpd(emlxs_hba_t *hba, MAILBOX *mb, uint32_t offset)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	/*
	 * Setup to dump VPD region
	 */
	mb->mbxCommand = MBX_DUMP_MEMORY;
	mb->un.varDmp.cv = 1;
	mb->un.varDmp.type = DMP_NV_PARAMS;
	mb->un.varDmp.entry_index = offset;
	mb->un.varDmp.region_id = DMP_VPD_REGION;
	mb->un.varDmp.word_cnt = DMP_VPD_DUMP_WCOUNT;	/* limited by */
							/*   mailbox size */

	mb->un.varDmp.co = 0;
	mb->un.varDmp.resp_offset = 0;
	mb->mbxOwner = OWN_HOST;
} /* emlxs_mb_dump_vpd() */


/*
 *  emlxs_mb_read_nv  Issue a READ NVPARAM
 *                  mailbox command
 */
/* ARGSUSED */
extern void
emlxs_mb_read_nv(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_READ_NV;
	mb->mbxOwner = OWN_HOST;

} /* End emlxs_mb_read_nv */


/*
 *  emlxs_mb_read_rev  Issue a READ REV
 *                   mailbox command
 */
/* ARGSUSED */
extern void
emlxs_mb_read_rev(emlxs_hba_t *hba, MAILBOX *mb, uint32_t v3)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mb->un.varRdRev.cv = 1;

	if (v3) {
		mb->un.varRdRev.cv3 = 1;
	}

	mb->mbxCommand = MBX_READ_REV;
	mb->mbxOwner = OWN_HOST;

} /* End emlxs_mb_read_rev */


/*
 *  emlxs_mb_run_biu_diag  Issue a RUN_BIU_DIAG
 *                     mailbox command
 */
/* ARGSUSED */
extern uint32_t
emlxs_mb_run_biu_diag(emlxs_hba_t *hba, MAILBOX *mb, uint64_t out,
    uint64_t in)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_RUN_BIU_DIAG64;
	mb->un.varBIUdiag.un.s2.xmit_bde64.tus.f.bdeSize = MEM_ELSBUF_SIZE;
	mb->un.varBIUdiag.un.s2.xmit_bde64.addrHigh =
	    (uint32_t)putPaddrHigh(out);
	mb->un.varBIUdiag.un.s2.xmit_bde64.addrLow =
	    (uint32_t)putPaddrLow(out);
	mb->un.varBIUdiag.un.s2.rcv_bde64.tus.f.bdeSize = MEM_ELSBUF_SIZE;
	mb->un.varBIUdiag.un.s2.rcv_bde64.addrHigh =
	    (uint32_t)putPaddrHigh(in);
	mb->un.varBIUdiag.un.s2.rcv_bde64.addrLow = (uint32_t)putPaddrLow(in);
	mb->mbxOwner = OWN_HOST;

	return (0);

} /* End emlxs_mb_run_biu_diag */


/*
 *  emlxs_mb_read_la  Issue a READ LA
 *                  mailbox command
 */
extern uint32_t
emlxs_mb_read_la(emlxs_hba_t *hba, MAILBOX *mb)
{
	MATCHMAP *mp;

	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	if ((mp = (MATCHMAP *) emlxs_mem_get(hba, MEM_BUF)) == 0) {
		mb->mbxCommand = MBX_READ_LA64;

		return (1);
	}
	mb->mbxCommand = MBX_READ_LA64;
	mb->un.varReadLA.un.lilpBde64.tus.f.bdeSize = 128;
	mb->un.varReadLA.un.lilpBde64.addrHigh =
	    (uint32_t)putPaddrHigh(mp->phys);
	mb->un.varReadLA.un.lilpBde64.addrLow =
	    (uint32_t)putPaddrLow(mp->phys);
	mb->mbxOwner = OWN_HOST;

	/*
	 * save address for completion
	 */
	((MAILBOXQ *)mb)->bp = (uint8_t *)mp;

	return (0);

} /* emlxs_mb_read_la() */


/*
 *  emlxs_mb_clear_la  Issue a CLEAR LA
 *                   mailbox command
 */
extern void
emlxs_mb_clear_la(emlxs_hba_t *hba, MAILBOX *mb)
{
#ifdef FC_RPI_CHECK
	emlxs_rpi_check(hba);
#endif	/* FC_RPI_CHECK */

	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mb->un.varClearLA.eventTag = hba->link_event_tag;
	mb->mbxCommand = MBX_CLEAR_LA;
	mb->mbxOwner = OWN_HOST;

	return;

} /* End emlxs_mb_clear_la */


/*
 *  emlxs_mb_read_status  Issue a READ STATUS
 *                      mailbox command
 */
/* ARGSUSED */
extern void
emlxs_mb_read_status(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_READ_STATUS;
	mb->mbxOwner = OWN_HOST;

} /* End fc_read_status */


/*
 *  emlxs_mb_read_lnk_stat  Issue a LINK STATUS
 *                        mailbox command
 */
/* ARGSUSED */
extern void
emlxs_mb_read_lnk_stat(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_READ_LNK_STAT;
	mb->mbxOwner = OWN_HOST;

} /* End emlxs_mb_read_lnk_stat */


/*
 *  emlxs_mb_write_nv  Issue a WRITE NVPARAM
 *                   mailbox command
 */
static void
emlxs_emb_mb_write_nv(emlxs_hba_t *hba, MAILBOX *mb)
{
	int32_t i;
	emlxs_config_t *cfg = &CFG;

	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	bcopy((void *) &hba->wwnn,
	    (void *) mb->un.varWTnvp.nodename,
	    sizeof (NAME_TYPE));

	bcopy((void *) &hba->wwpn,
	    (void *) mb->un.varWTnvp.portname,
	    sizeof (NAME_TYPE));

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
 *  emlxs_mb_part_slim  Issue a PARTITION SLIM
 *                    mailbox command
 */
static void
emlxs_mb_part_slim(emlxs_hba_t *hba, MAILBOX *mb, uint32_t hbainit)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);


	mb->un.varSlim.numRing = hba->ring_count;
	mb->un.varSlim.hbainit = hbainit;
	mb->mbxCommand = MBX_PART_SLIM;
	mb->mbxOwner = OWN_HOST;

} /* End emlxs_mb_part_slim */


/*
 *  emlxs_mb_config_ring  Issue a CONFIG RING
 *                      mailbox command
 */
extern void
emlxs_mb_config_ring(emlxs_hba_t *hba, int32_t ring, MAILBOX *mb)
{
	int32_t i;
	int32_t j;

	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	j = 0;
	for (i = 0; i < ring; i++) {
		j += hba->ring_masks[i];
	}

	for (i = 0; i < hba->ring_masks[ring]; i++) {
		if ((j + i) >= 6) {
			break;
		}
		mb->un.varCfgRing.rrRegs[i].rval = hba->ring_rval[j + i];
		mb->un.varCfgRing.rrRegs[i].rmask = hba->ring_rmask[j + i];

		mb->un.varCfgRing.rrRegs[i].tval = hba->ring_tval[j + i];
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
 *  emlxs_mb_config_link  Issue a CONFIG LINK
 *                      mailbox command
 */
extern void
emlxs_mb_config_link(emlxs_hba_t *hba, MAILBOX *mb)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;

	bzero((void *) mb, MAILBOX_CMD_BSIZE);

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
 *  emlxs_mb_init_link  Issue an INIT LINK
 *                    mailbox command
 */
extern void
emlxs_mb_init_link(emlxs_hba_t *hba, MAILBOX *mb, uint32_t topology,
    uint32_t linkspeed)
{
	emlxs_vpd_t *vpd = &VPD;
	emlxs_config_t *cfg = &CFG;

	bzero((void *) mb, MAILBOX_CMD_BSIZE);

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

	mb->un.varInitLnk.fabric_AL_PA = (uint8_t)cfg[CFG_ASSIGN_ALPA].current;
	mb->mbxCommand = (volatile uint8_t) MBX_INIT_LINK;
	mb->mbxOwner = OWN_HOST;


	return;

} /* emlxs_mb_init_link() */


/*
 *  emlxs_mb_down_link  Issue a DOWN LINK
 *                    mailbox command
 */
/* ARGSUSED */
extern void
emlxs_mb_down_link(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_DOWN_LINK;
	mb->mbxOwner = OWN_HOST;

	return;

} /* emlxs_mb_down_link() */


/*
 *  emlxs_mb_read_sparam  Issue a READ SPARAM
 *                      mailbox command
 */
extern uint32_t
emlxs_mb_read_sparam(emlxs_hba_t *hba, MAILBOX *mb)
{
	MATCHMAP *mp;

	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	if ((mp = (MATCHMAP *) emlxs_mem_get(hba, MEM_BUF)) == 0) {
		mb->mbxCommand = MBX_READ_SPARM64;

		return (1);
	}
	mb->un.varRdSparm.un.sp64.tus.f.bdeSize = sizeof (SERV_PARM);
	mb->un.varRdSparm.un.sp64.addrHigh = (uint32_t)putPaddrHigh(mp->phys);
	mb->un.varRdSparm.un.sp64.addrLow = (uint32_t)putPaddrLow(mp->phys);
	mb->mbxCommand = MBX_READ_SPARM64;
	mb->mbxOwner = OWN_HOST;

	/*
	 * save address for completion
	 */
	((MAILBOXQ *)mb)->bp = (uint8_t *)mp;

	return (0);

} /* emlxs_mb_read_sparam() */


/*
 *  emlxs_mb_read_rpi    Issue a READ RPI
 *                     mailbox command
 */
/* ARGSUSED */
extern uint32_t
emlxs_mb_read_rpi(emlxs_hba_t *hba, uint32_t rpi, MAILBOX *mb, uint32_t flag)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

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
 *  emlxs_mb_read_xri    Issue a READ XRI
 *                     mailbox command
 */
/* ARGSUSED */
extern uint32_t
emlxs_mb_read_xri(emlxs_hba_t *hba, uint32_t xri, MAILBOX *mb, uint32_t flag)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	/*
	 * Set flag to issue action on cmpl
	 */
	mb->un.varWords[30] = flag;
	mb->un.varRdXRI.reqXri = (volatile uint16_t) xri;
	mb->mbxCommand = MBX_READ_XRI;
	mb->mbxOwner = OWN_HOST;

	return (0);

} /* End emlxs_mb_read_xri */


/* ARGSUSED */
extern int32_t
emlxs_mb_check_sparm(emlxs_hba_t *hba, SERV_PARM *nsp)
{
	uint32_t nsp_value;
	uint32_t *iptr;

	if (nsp->cmn.fPort) {
		return (0);
	}
	/* Validate the service parameters */
	iptr = (uint32_t *)& nsp->portName;
	if (iptr[0] == 0 && iptr[1] == 0) {
		return (1);
	}
	iptr = (uint32_t *)& nsp->nodeName;
	if (iptr[0] == 0 && iptr[1] == 0) {
		return (2);
	}
	if (nsp->cls2.classValid) {
		nsp_value = ((nsp->cls2.rcvDataSizeMsb & 0x0f) << 8) |
		    nsp->cls2.rcvDataSizeLsb;

		/*
		 * If the receive data length is zero then set it to the CSP
		 * value
		 */
		if (!nsp_value) {
			nsp->cls2.rcvDataSizeMsb = nsp->cmn.bbRcvSizeMsb;
			nsp->cls2.rcvDataSizeLsb = nsp->cmn.bbRcvSizeLsb;
			return (0);
		}
	}
	if (nsp->cls3.classValid) {
		nsp_value = ((nsp->cls3.rcvDataSizeMsb & 0x0f) << 8) |
		    nsp->cls3.rcvDataSizeLsb;

		/*
		 * If the receive data length is zero then set it to the CSP
		 * value
		 */
		/* This prevents a Emulex adapter bug from occurring */
		if (!nsp_value) {
			nsp->cls3.rcvDataSizeMsb = nsp->cmn.bbRcvSizeMsb;
			nsp->cls3.rcvDataSizeLsb = nsp->cmn.bbRcvSizeLsb;
			return (0);
		}
	}
	return (0);

} /* emlxs_mb_check_sparm() */


/*
 *  emlxs_mb_reg_did  Issue a REG_LOGIN
 *                    mailbox command
 */
extern uint32_t
emlxs_mb_reg_did(emlxs_port_t *port, uint32_t did, SERV_PARM *param,
    emlxs_buf_t *sbp, fc_unsol_buf_t *ubp, IOCBQ *iocbq)
{
	emlxs_hba_t *hba = HBA;
	MATCHMAP *mp;
	MAILBOXQ *mbq;
	MAILBOX *mb;
	uint32_t rval;

	/* Check for invalid node ids to register */
	if (did == 0 || (did & 0xff000000)) {
		return (1);
	}
	if ((rval = emlxs_mb_check_sparm(hba, param))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_create_failed_msg,
		    "Invalid service parameters. did=%06x rval=%d", did, rval);

		return (1);
	}
	/* Check if the node limit has been reached */
	if (port->node_count >= hba->max_nodes) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_create_failed_msg,
		    "Limit reached. did=%06x count=%d", did, port->node_count);

		return (1);
	}
	if (!(mbq = (MAILBOXQ *) emlxs_mem_get(hba, MEM_MBOX | MEM_PRI))) {
		return (1);
	}
	/* Build login request */
	if ((mp = (MATCHMAP *) emlxs_mem_get(hba, MEM_BUF | MEM_PRI)) == 0) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
		return (1);
	}
	bcopy((void *) param, (void *) mp->virt, sizeof (SERV_PARM));

	mb = (MAILBOX *) mbq->mbox;
	mb->un.varRegLogin.un.sp64.tus.f.bdeSize = sizeof (SERV_PARM);
	mb->un.varRegLogin.un.sp64.addrHigh = (uint32_t)putPaddrHigh(mp->phys);
	mb->un.varRegLogin.un.sp64.addrLow = (uint32_t)putPaddrLow(mp->phys);
	mb->un.varRegLogin.rpi = 0;
	mb->un.varRegLogin.did = did;
	mb->un.varWords[30] = 0;	/* flags */
	mb->mbxCommand = MBX_REG_LOGIN64;
	mb->mbxOwner = OWN_HOST;

#ifdef SLI3_SUPPORT
	mb->un.varRegLogin.vpi =
	    port->vpi;
#endif	/* SLI3_SUPPORT */

	mbq->sbp = (uint8_t *)sbp;
	mbq->ubp = (uint8_t *)ubp;
	mbq->iocbq = (uint8_t *)iocbq;
	mbq->bp = (uint8_t *)mp;

	if (emlxs_mb_issue_cmd(hba, mb, MBX_NOWAIT, 0) != MBX_BUSY) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}
	return (0);

} /* emlxs_mb_reg_did() */

/*
 *  emlxs_mb_unreg_rpi  Issue a UNREG_LOGIN
 *                      mailbox command
 */
extern uint32_t
emlxs_mb_unreg_rpi(emlxs_port_t *port, uint32_t rpi, emlxs_buf_t *sbp,
    fc_unsol_buf_t *ubp, IOCBQ *iocbq)
{
	emlxs_hba_t *hba = HBA;
	MAILBOXQ *mbq;
	MAILBOX *mb;
	NODELIST *ndlp;

	if (rpi != 0xffff) {
		/* Make sure the node does already exist */
		ndlp = emlxs_node_find_rpi(port, rpi);


		if (ndlp) {
			/*
			 * If we just unregistered the host node then clear
			 * the host DID
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

	if (!(mbq = (MAILBOXQ *) emlxs_mem_get(hba, MEM_MBOX | MEM_PRI))) {
		return (1);
	}
	mb = (MAILBOX *) mbq->mbox;
	mb->un.varUnregLogin.rpi = (uint16_t)rpi;

#ifdef SLI3_SUPPORT
	mb->un.varUnregLogin.vpi = port->vpi;
#endif	/* SLI3_SUPPORT */

	mb->mbxCommand = MBX_UNREG_LOGIN;
	mb->mbxOwner = OWN_HOST;
	mbq->sbp = (uint8_t *)sbp;
	mbq->ubp = (uint8_t *)ubp;
	mbq->iocbq = (uint8_t *)iocbq;

	if (emlxs_mb_issue_cmd(hba, mb, MBX_NOWAIT, 0) != MBX_BUSY) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}
	return (0);
} /* emlxs_mb_unreg_rpi() */

/*
 *  emlxs_mb_unreg_did  Issue a UNREG_DID
 *                      mailbox command
 */
extern uint32_t
emlxs_mb_unreg_did(emlxs_port_t *port, uint32_t did, emlxs_buf_t *sbp,
    fc_unsol_buf_t *ubp, IOCBQ *iocbq)
{
	emlxs_hba_t *hba = HBA;
	NODELIST *ndlp;
	MAILBOXQ *mbq;
	MAILBOX *mb;

	/*
	 * Unregister all default RPIs if did == 0xffffffff
	 */
	if (did != 0xffffffff) {
		/* Check for base node */
		if (did == Bcast_DID) {
			/* just flush base node */
			(void) emlxs_tx_node_flush(port, &port->node_base,
			    0, 0, 0);
			(void) emlxs_chipq_node_flush(port, 0, &port->node_base,
			    0);

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
		 * If the prev_did != 0 then we can look for the hosts last
		 * known DID node
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
			 * If we just unregistered the host node then clear
			 * the host DID
			 */
			if (did == port->did) {
				port->did = 0;
			}
		} else {
			return (1);
		}
	}
	if (!(mbq = (MAILBOXQ *) emlxs_mem_get(hba, MEM_MBOX | MEM_PRI))) {
		return (1);
	}
	mb = (MAILBOX *) mbq->mbox;
	mb->un.varUnregDID.did = did;

#ifdef SLI3_SUPPORT
	mb->un.varUnregDID.vpi = port->vpi;
#endif	/* SLI3_SUPPORT */

	mb->mbxCommand = MBX_UNREG_D_ID;
	mb->mbxOwner = OWN_HOST;
	mbq->sbp = (uint8_t *)sbp;
	mbq->ubp = (uint8_t *)ubp;
	mbq->iocbq = (uint8_t *)iocbq;

	if (emlxs_mb_issue_cmd(hba, mb, MBX_NOWAIT, 0) != MBX_BUSY) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}
	return (0);

} /* End emlxs_mb_unreg_did */


/*
 *  emlxs_mb_set_mask   Issue a SET MASK
 *                    mailbox command
 */
/* ARGSUSED */
static void
emlxs_mb_set_mask(emlxs_hba_t *hba, MAILBOX *mb, uint32_t mask,
    uint32_t ringno)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mb->un.varWords[0] = 0x11223344;	/* set passwd */
	mb->un.varWords[1] = mask;	/* set mask */
	mb->un.varWords[2] = ringno;	/* set ringno */
	mb->mbxCommand = MBX_SET_MASK;
	mb->mbxOwner = OWN_HOST;

} /* End emlxs_mb_set_mask */


/*
 *  emlxs_mb_set_debug  Issue a special debug
 *                    mailbox command
 */
/* ARGSUSED */
static void
emlxs_mb_set_debug(emlxs_hba_t *hba, MAILBOX *mb, uint32_t word0,
    uint32_t word1, uint32_t word2)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mb->un.varWords[0] = word0;
	mb->un.varWords[1] = word1;
	mb->un.varWords[2] = word2;
	mb->mbxCommand = MBX_SET_DEBUG;
	mb->mbxOwner = OWN_HOST;

} /* End emlxs_mb_set_debug */


/*
 *  emlxs_mb_set_var   Issue a special debug mbox
 *                    command to write slim
 */
/* ARGSUSED */
extern void
emlxs_mb_set_var(emlxs_hba_t *hba, MAILBOX *mb, uint32_t addr, uint32_t value)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

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
/* ARGSUSED */
extern void
emlxs_disable_tc(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mb->un.varWords[0] = 0x50797;
	mb->un.varWords[1] = 0;
	mb->un.varWords[2] = 0xfffffffe;
	mb->mbxCommand = MBX_SET_VARIABLE;
	mb->mbxOwner = OWN_HOST;

} /* End emlxs_disable_tc */


/*
 *  emlxs_mb_config_port  Issue a CONFIG_PORT
 *                      mailbox command
 */
extern uint32_t
emlxs_mb_config_port(emlxs_hba_t *hba, MAILBOX *mb, uint32_t sli_mode,
    uint32_t hbainit)
{
	emlxs_vpd_t *vpd = &VPD;
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg;
	RING *rp;
	uint64_t pcb;
	uint64_t mbx;
	uint64_t hgp;
	uint64_t pgp;
	uint64_t rgp;
	MAILBOX *mbox;
	SLIM2 *slim;
	SLI2_RDSC *rdsc;
	uint64_t offset;
	uint32_t Laddr;
	uint32_t i;

	cfg = &CFG;
	bzero((void *) mb, MAILBOX_CMD_BSIZE);
	mbox = NULL;
	slim = NULL;

	mb->mbxCommand = MBX_CONFIG_PORT;
	mb->mbxOwner = OWN_HOST;

	mb->un.varCfgPort.pcbLen = sizeof (PCB);

#ifdef SLI3_SUPPORT
	mb->un.varCfgPort.hbainit[0] = hbainit;
#else	/* SLI3_SUPPORT */
	mb->un.varCfgPort.hbainit = hbainit;
#endif	/* SLI3_SUPPORT */

	pcb = hba->slim2.phys + (uint64_t)(unsigned long)& (slim->pcb);
	mb->un.varCfgPort.pcbLow = (uint32_t)putPaddrLow(pcb);
	mb->un.varCfgPort.pcbHigh = (uint32_t)putPaddrHigh(pcb);

	/* Set Host pointers in SLIM flag */
	mb->un.varCfgPort.hps = 1;

	/* Initialize hba structure for assumed default SLI2 mode */
	/* If config port succeeds, then we will update it then   */
	hba->sli_mode = 2;
	hba->vpi_max = 1;
	hba->flag &= ~FC_NPIV_ENABLED;

#ifdef SLI3_SUPPORT
	if (sli_mode >= 3) {
		mb->un.varCfgPort.sli_mode = 3;
		mb->un.varCfgPort.cerbm = 1;
		mb->un.varCfgPort.max_hbq = EMLXS_NUM_HBQ;

#ifdef NPIV_SUPPORT
		if (cfg[CFG_NPIV_ENABLE].current) {
			if (vpd->feaLevelHigh >= 0x09) {
				if (hba->model_info.chip >= EMLXS_SATURN_CHIP) {
					mb->un.varCfgPort.vpi_max =
					    MAX_VPORTS - 1;
				} else {
					mb->un.varCfgPort.vpi_max =
					    MAX_VPORTS_LIMITED - 1;
				}

				mb->un.varCfgPort.cmv = 1;
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
				    "CFGPORT: Firmware does not support NPIV. "
				    "level=%d", vpd->feaLevelHigh);
			}

		}
#endif	/* NPIV_SUPPORT */
	}
#endif	/* SLI3_SUPPORT */

	/*
	 * Now setup pcb
	 */
	((SLIM2 *) hba->slim2.virt)->pcb.type = TYPE_NATIVE_SLI2;
	((SLIM2 *) hba->slim2.virt)->pcb.feature = FEATURE_INITIAL_SLI2;
	((SLIM2 *) hba->slim2.virt)->pcb.maxRing = (hba->ring_count - 1);
	((SLIM2 *) hba->slim2.virt)->pcb.mailBoxSize = sizeof (MAILBOX) +
	    MBOX_EXTENSION_SIZE;

	mbx = hba->slim2.phys + (uint64_t)(unsigned long)& (slim->mbx);
	((SLIM2 *)hba->slim2.virt)->pcb.mbAddrHigh =
	    (uint32_t)putPaddrHigh(mbx);
	((SLIM2 *)hba->slim2.virt)->pcb.mbAddrLow = (uint32_t)putPaddrLow(mbx);


	/*
	 * Set up HGP - Port Memory
	 *
	 * CR0Put    - SLI2(no HBQs) = 0xc0, With HBQs = 0x80
	 * RR0Get 0xc4 0x84
	 * CR1Put 0xc8 0x88
	 * RR1Get 0xcc 0x8c
	 * CR2Put 0xd0 0x90
	 * RR2Get 0xd4 0x94
	 * CR3Put 0xd8 0x98
	 * RR3Get 0xdc 0x9c
	 *
	 * Reserved 0xa0-0xbf
	 *
	 * If HBQs configured:
	 * HBQ 0 Put ptr  0xc0
	 * HBQ 1 Put ptr  0xc4
	 * HBQ 2 Put ptr  0xc8
	 * ......
	 * HBQ(M-1)Put Pointer 0xc0+(M-1)*4
	 */

#ifdef SLI3_SUPPORT
	if (sli_mode >= 3) {
		/* ERBM is enabled */
		hba->hgp_ring_offset = 0x80;
		hba->hgp_hbq_offset = 0xC0;

		hba->iocb_cmd_size = SLI3_IOCB_CMD_SIZE;
		hba->iocb_rsp_size = SLI3_IOCB_RSP_SIZE;

	} else	/* SLI2 */
#endif	/* SLI3_SUPPORT */
	{
		/* ERBM is disabled */
		hba->hgp_ring_offset = 0xC0;
		hba->hgp_hbq_offset = 0;

		hba->iocb_cmd_size = SLI2_IOCB_CMD_SIZE;
		hba->iocb_rsp_size = SLI2_IOCB_RSP_SIZE;
	}

	/* The Sbus card uses Host Memory. The PCI card uses SLIM POINTER */
	if (hba->bus_type == SBUS_FC) {
		hgp = hba->slim2.phys +
		    (uint64_t)(unsigned long)& (mbox->us.s2.host);
		((SLIM2 *)hba->slim2.virt)->pcb.hgpAddrHigh =
		    (uint32_t)putPaddrHigh(hgp);
		((SLIM2 *)hba->slim2.virt)->pcb.hgpAddrLow =
		    (uint32_t)putPaddrLow(hgp);
	} else {
		((SLIM2 *)hba->slim2.virt)->pcb.hgpAddrHigh =
		    (uint32_t)ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + PCI_BAR_1_REGISTER));

		Laddr = ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + PCI_BAR_0_REGISTER));
		Laddr &= ~0x4;
		((SLIM2 *)hba->slim2.virt)->pcb.hgpAddrLow =
		    (uint32_t)(Laddr + hba->hgp_ring_offset);

	}

	pgp = hba->slim2.phys + (uint64_t)(unsigned long)& (mbox->us.s2.port);
	((SLIM2 *)hba->slim2.virt)->pcb.pgpAddrHigh =
	    (uint32_t)putPaddrHigh(pgp);
	((SLIM2 *)hba->slim2.virt)->pcb.pgpAddrLow = (uint32_t)putPaddrLow(pgp);

	offset = 0;
	for (i = 0; i < 4; i++) {
		rp = &hba->ring[i];
		rdsc = &((SLIM2 *) hba->slim2.virt)->pcb.rdsc[i];

		/* Setup command ring */
		rgp = hba->slim2.phys +
		    (uint64_t)(unsigned long)& (slim->IOCBs[offset]);
		rdsc->cmdAddrHigh = (uint32_t)putPaddrHigh(rgp);
		rdsc->cmdAddrLow = (uint32_t)putPaddrLow(rgp);
		rdsc->cmdEntries = rp->fc_numCiocb;

		rp->fc_cmdringaddr = (void *) &((SLIM2 *) hba->slim2.virt)->
		    IOCBs[offset];
		offset += rdsc->cmdEntries * hba->iocb_cmd_size;

		/* Setup response ring */
		rgp = hba->slim2.phys +
		    (uint64_t)(unsigned long)& (slim->IOCBs[offset]);
		rdsc->rspAddrHigh = (uint32_t)putPaddrHigh(rgp);
		rdsc->rspAddrLow = (uint32_t)putPaddrLow(rgp);
		rdsc->rspEntries = rp->fc_numRiocb;

		rp->fc_rspringaddr = (void *) &((SLIM2 *) hba->slim2.virt)->
		    IOCBs[offset];
		offset += rdsc->rspEntries * hba->iocb_rsp_size;
	}

	emlxs_pcimem_bcopy((uint32_t *)(&((SLIM2 *) hba->slim2.virt)->pcb),
	    (uint32_t *)(&((SLIM2 *) hba->slim2.virt)->pcb), sizeof (PCB));

	offset =
	    ((uint64_t)(unsigned long)& (((SLIM2 *) hba->slim2.virt)->pcb) -
	    (uint64_t)(unsigned long)hba->slim2.virt);
	emlxs_mpdata_sync(hba->slim2.dma_handle, (off_t)offset, sizeof (PCB),
	    DDI_DMA_SYNC_FORDEV);

	return (0);

} /* emlxs_mb_config_port() */


#ifdef SLI3_SUPPORT
extern void
emlxs_mb_config_hbq(emlxs_hba_t *hba, MAILBOX *mb, int hbq_id)
{
	HBQ_INIT_t *hbq;
	int i;

	bzero((void *) mb, MAILBOX_CMD_BSIZE);

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
		mb->un.varCfgHbq.hbqMasks[i].tmatch = hbq->HBQ_Masks[i].tmatch;
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
	emlxs_hba_t *hba = HBA;
	MAILBOXQ *mbq;
	MAILBOX *mb;

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
	if (!(mbq = (MAILBOXQ *) emlxs_mem_get(hba, MEM_MBOX | MEM_PRI))) {
		mutex_exit(&EMLXS_PORT_LOCK);

		return (1);
	}
	port->flag |= EMLXS_PORT_REGISTERED;

	mutex_exit(&EMLXS_PORT_LOCK);

	mb = (MAILBOX *) mbq->mbox;
	bzero((void *) mb, MAILBOX_CMD_BSIZE);
	mb->un.varRegVpi.vpi = port->vpi;
	mb->un.varRegVpi.sid = port->did;
	mb->mbxCommand = MBX_REG_VPI;
	mb->mbxOwner = OWN_HOST;

	if (emlxs_mb_issue_cmd(hba, mb, MBX_NOWAIT, 0) != MBX_BUSY) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}
	return (0);

} /* emlxs_mb_reg_vpi() */


extern uint32_t
emlxs_mb_unreg_vpi(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	MAILBOXQ *mbq;
	MAILBOX *mb;

	mutex_enter(&EMLXS_PORT_LOCK);

	if (!(port->flag & EMLXS_PORT_REGISTERED)) {
		mutex_exit(&EMLXS_PORT_LOCK);

		return (0);
	}
	if (!(mbq = (MAILBOXQ *) emlxs_mem_get(hba, MEM_MBOX | MEM_PRI))) {
		mutex_exit(&EMLXS_PORT_LOCK);

		return (1);
	}
	port->flag &= ~EMLXS_PORT_REGISTERED;

	mutex_exit(&EMLXS_PORT_LOCK);

	mb = (MAILBOX *) mbq->mbox;
	bzero((void *) mb, MAILBOX_CMD_BSIZE);
	mb->un.varUnregVpi.vpi = port->vpi;
	mb->mbxCommand = MBX_UNREG_VPI;
	mb->mbxOwner = OWN_HOST;

	if (emlxs_mb_issue_cmd(hba, mb, MBX_NOWAIT, 0) != MBX_BUSY) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}
	return (0);

} /* emlxs_mb_unreg_vpi() */


/*
 *  emlxs_mb_config_farp  Issue a CONFIG FARP
 *                      mailbox command
 */
extern void
emlxs_mb_config_farp(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	bcopy((uint8_t *)& hba->wwpn,
	    (uint8_t *)& mb->un.varCfgFarp.portname,
	    sizeof (NAME_TYPE));

	bcopy((uint8_t *)& hba->wwpn,
	    (uint8_t *)& mb->un.varCfgFarp.nodename,
	    sizeof (NAME_TYPE));

	mb->un.varCfgFarp.filterEnable = 1;
	mb->un.varCfgFarp.portName = 1;
	mb->un.varCfgFarp.nodeName = 1;
	mb->mbxCommand = MBX_CONFIG_FARP;
	mb->mbxOwner = OWN_HOST;
} /* emlxs_mb_config_farp() */


/*
 *  emlxs_mb_read_nv  Issue a READ CONFIG
 *                  mailbox command
 */
/* ARGSUSED */
extern void
emlxs_mb_read_config(emlxs_hba_t *hba, MAILBOX *mb)
{
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

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
 * CALLED FROM: emlxs_mb_issue_cmd
 *
 * INPUT: hba           - pointer to the device info area mbp
 *                      - pointer to mailbox queue entry of mailbox cmd
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
		((MAILBOXQ *) hba->mbox_queue.q_last)->next = mbq;
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
	MAILBOXQ *p_first = NULL;

	mutex_enter(&EMLXS_MBOX_LOCK);

	if (hba->mbox_queue.q_first) {
		p_first = (MAILBOXQ *) hba->mbox_queue.q_first;
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
static void
emlxs_mb_init(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t flag, uint32_t tmo)
{
	MATCHMAP *mp;

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
#endif	/* MBOX_EXT_SUPPORT */

	return;

} /* emlxs_mb_init() */


extern void
emlxs_mb_fini(emlxs_hba_t *hba, MAILBOX *mb, uint32_t mbxStatus)
{
	emlxs_port_t *port = &PPORT;
	MATCHMAP *mbox_bp;
	emlxs_buf_t *mbox_sbp;
	fc_unsol_buf_t *mbox_ubp;
	IOCBQ *mbox_iocbq;
	MAILBOXQ *mbox_mbq;
	MAILBOX *mbox;
	uint32_t mbox_queue_flag;
	emlxs_ub_priv_t *ub_priv;

	mutex_enter(&EMLXS_PORT_LOCK);

	if (hba->mbox_queue_flag) {
		HBASTATS.MboxCompleted++;

		if (mbxStatus != MBX_SUCCESS) {
			HBASTATS.MboxError++;
		} else {
			HBASTATS.MboxGood++;
		}
	}
	mbox_bp = (MATCHMAP *) hba->mbox_bp;
	mbox_sbp = (emlxs_buf_t *)hba->mbox_sbp;
	mbox_ubp = (fc_unsol_buf_t *)hba->mbox_ubp;
	mbox_iocbq = (IOCBQ *) hba->mbox_iocbq;
	mbox_mbq = (MAILBOXQ *) hba->mbox_mbq;
	mbox_queue_flag = hba->mbox_queue_flag;

#ifdef MBOX_EXT_SUPPORT
	hba->mbox_ext = 0;
	hba->mbox_ext_size = 0;
#endif	/* MBOX_EXT_SUPPORT */

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
			/*
			 * Copy the local mailbox provided back into the
			 * original mailbox
			 */
			bcopy((uint32_t *)mb, (uint32_t *)mbox_mbq,
			    MAILBOX_CMD_BSIZE);
		}
		mbox = (MAILBOX *) mbox_mbq;
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
#endif	/* SFCT_SUPPORT */

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
		emlxs_issue_iocb_cmd(hba, mbox_iocbq->ring, mbox_iocbq);
	}
	return;

} /* emlxs_mb_fini() */



/* This should only be called with active MBX_NOWAIT mailboxes */
static void
emlxs_mb_retry(emlxs_hba_t *hba, MAILBOX *mb)
{
	MAILBOXQ *mbq;

	mutex_enter(&EMLXS_PORT_LOCK);

	HBASTATS.MboxCompleted++;

	if (mb->mbxStatus != 0) {
		HBASTATS.MboxError++;
	} else {
		HBASTATS.MboxGood++;
	}

	mbq = (MAILBOXQ *) mb;
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



/*
 *  emlxs_handle_mb_event
 *
 *  Description: Process a Mailbox Attention.
 *  Called from host_interrupt to process MBATT
 *
 *    Returns:
 *
 */
extern uint32_t
emlxs_handle_mb_event(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	MAILBOX *mb;
	MAILBOX *swpmb;
	MAILBOX *mbox;
	MAILBOXQ *mbq;
	emlxs_config_t *cfg;
	uint32_t control;
	volatile uint32_t word0;
	MATCHMAP *mbox_bp;
	uint32_t la_enable;
	off_t offset;
	uint32_t i;
	MAILBOXQ mailbox;

	cfg = &CFG;
	swpmb = (MAILBOX *) & word0;
	mb = (MAILBOX *) & mailbox;

	switch (hba->mbox_queue_flag) {
	case 0:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_stray_mbox_intr_msg,
		    "No mailbox active.");
		return (0);

	case MBX_POLL:

		/*
		 * Mark mailbox complete, this should wake up any polling
		 * threads
		 */
		/*
		 * This can happen if interrupts are enabled while a polled
		 * mailbox command is outstanding
		 */
		/*
		 * If we don't set MBQ_COMPLETED here, the polling thread may
		 * wait until timeout error occurs
		 */

		mutex_enter(&EMLXS_MBOX_LOCK);
		mbq = (MAILBOXQ *) hba->mbox_mbq;
		if (mbq) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Mailbox event. Completing Polled command.");
			mbq->flag |= MBQ_COMPLETED;
		}
		mutex_exit(&EMLXS_MBOX_LOCK);

		return (0);

	case MBX_SLEEP:
	case MBX_NOWAIT:
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_completion_error_msg,
		    "Invalid Mailbox flag (%x).");
		return (0);
	}

	/* Get first word of mailbox */
	if (hba->flag & FC_SLIM2_MODE) {
		mbox = FC_SLIM2_MAILBOX(hba);
		offset = (off_t)((uint64_t)(unsigned long)mbox -
		    (uint64_t)(unsigned long)hba->slim2.virt);

		emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
		    sizeof (uint32_t), DDI_DMA_SYNC_FORKERNEL);
		word0 = *((volatile uint32_t *) mbox);
		word0 = PCIMEM_LONG(word0);
	} else {
		mbox = FC_SLIM1_MAILBOX(hba);
		word0 = READ_SLIM_ADDR(hba, ((volatile uint32_t *) mbox));
	}

	i = 0;
	while (swpmb->mbxOwner == OWN_CHIP) {
		if (i++ > 10000) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_stray_mbox_intr_msg,
			    "OWN_CHIP: %s: status=%x",
			    emlxs_mb_cmd_xlate(swpmb->mbxCommand),
			    swpmb->mbxStatus);

			return (1);
		}
		/* Get first word of mailbox */
		if (hba->flag & FC_SLIM2_MODE) {
			emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
			    sizeof (uint32_t), DDI_DMA_SYNC_FORKERNEL);
			word0 = *((volatile uint32_t *) mbox);
			word0 = PCIMEM_LONG(word0);
		} else {
			word0 = READ_SLIM_ADDR(hba,
			    ((volatile uint32_t *) mbox));
		}
	}

	/* Now that we are the owner, DMA Sync entire mailbox if needed */
	if (hba->flag & FC_SLIM2_MODE) {
		emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
		    MAILBOX_CMD_BSIZE, DDI_DMA_SYNC_FORKERNEL);
		emlxs_pcimem_bcopy((uint32_t *)mbox, (uint32_t *)mb,
		    MAILBOX_CMD_BSIZE);
	} else {
		READ_SLIM_COPY(hba, (uint32_t *)mb, (uint32_t *)mbox,
		    MAILBOX_CMD_WSIZE);
	}

#ifdef MBOX_EXT_SUPPORT
	if (hba->mbox_ext) {
		uint32_t *mbox_ext = (uint32_t *)((uint8_t *)mbox +
		    MBOX_EXTENSION_OFFSET);
		off_t offset_ext = offset + MBOX_EXTENSION_OFFSET;

		if (hba->flag & FC_SLIM2_MODE) {
			emlxs_mpdata_sync(hba->slim2.dma_handle, offset_ext,
			    hba->mbox_ext_size, DDI_DMA_SYNC_FORKERNEL);
			emlxs_pcimem_bcopy(mbox_ext, (uint32_t *)hba->mbox_ext,
			    hba->mbox_ext_size);
		} else {
			READ_SLIM_COPY(hba, (uint32_t *)hba->mbox_ext, mbox_ext,
			    (hba->mbox_ext_size / 4));
		}
	}
#endif	/* MBOX_EXT_SUPPORT */

	/* Now sync the memory buffer if one was used */
	if (hba->mbox_bp) {
		mbox_bp = (MATCHMAP *) hba->mbox_bp;
		emlxs_mpdata_sync(mbox_bp->dma_handle, 0, mbox_bp->size,
		    DDI_DMA_SYNC_FORKERNEL);
	}
	/* Mailbox has been completely received at this point */

	if (mb->mbxCommand == MBX_HEARTBEAT) {
		hba->heartbeat_active = 0;
		goto done;
	}
	if (hba->mbox_queue_flag == MBX_SLEEP) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
		    "Received.  %s: status=%x Sleep.",
		    emlxs_mb_cmd_xlate(swpmb->mbxCommand), swpmb->mbxStatus);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
		    "Completed. %s: status=%x",
		    emlxs_mb_cmd_xlate(swpmb->mbxCommand), swpmb->mbxStatus);
	}

	/* Filter out passthru mailbox */
	if (hba->mbox_mbqflag & MBQ_PASSTHRU) {
		goto done;
	}
	/* If succesful, process the result */
	if (mb->mbxStatus == 0) {
		(void) emlxs_mb_handle_cmd(hba, mb);
		goto done;
	}
	/* ERROR RETURNED */

	/* Check for no resources */
	if ((mb->mbxStatus == MBXERR_NO_RESOURCES) &&
	    (hba->mbox_queue_flag == MBX_NOWAIT)) {
		/* Retry only MBX_NOWAIT requests */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_event_msg,
		    "Retrying.  %s: status=%x",
		    emlxs_mb_cmd_xlate(mb->mbxCommand),
		    (uint32_t)mb->mbxStatus);

		if ((mbox = (MAILBOX *) emlxs_mem_get(hba, MEM_MBOX))) {
			bcopy((uint8_t *)mb, (uint8_t *)mbox,
			    MAILBOX_CMD_BSIZE);

			switch (mbox->mbxCommand) {
			case MBX_READ_SPARM:
				control = mbox->un.varRdSparm.un.sp.bdeSize;
				if (control == 0) {
					(void) emlxs_mb_read_sparam(hba, mbox);
				}
				break;

			case MBX_READ_SPARM64:
				control = mbox->un.varRdSparm.un.sp64.tus.f.
				    bdeSize;
				if (control == 0) {
					(void) emlxs_mb_read_sparam(hba, mbox);
				}
				break;

			case MBX_REG_LOGIN:
				control = mbox->un.varRegLogin.un.sp.bdeSize;
				if (control == 0) {
#ifdef NPIV_SUPPORT
					/* Special handle for vport PLOGI */
					if (hba->mbox_iocbq == (uint8_t *)1) {
						hba->mbox_iocbq = NULL;
					}
#endif /* NPIV_SUPPORT */
					goto done;
				}
				break;

			case MBX_REG_LOGIN64:
				control = mbox->un.varRegLogin.un.sp64.tus.f.
				    bdeSize;
				if (control == 0) {
#ifdef NPIV_SUPPORT
					/* Special handle for vport PLOGI */
					if (hba->mbox_iocbq == (uint8_t *)1) {
						hba->mbox_iocbq = NULL;
					}
#endif /* NPIV_SUPPORT */
					goto done;
				}
				break;

			case MBX_READ_LA:
				control = mbox->un.varReadLA.un.lilpBde.bdeSize;
				if (control == 0) {
					(void) emlxs_mb_read_la(hba, mbox);
				}
				break;

			case MBX_READ_LA64:
				control = mbox->un.varReadLA.un.lilpBde64.tus.f.
				    bdeSize;
				if (control == 0) {
					(void) emlxs_mb_read_la(hba, mbox);
				}
				break;
			}

			mbox->mbxOwner = OWN_HOST;
			mbox->mbxStatus = 0;

			/* Refresh the mailbox area */
			emlxs_mb_retry(hba, mbox);

			if (emlxs_mb_issue_cmd(hba, mbox, MBX_NOWAIT, 0) !=
			    MBX_BUSY) {
				(void) emlxs_mem_put(hba, MEM_MBOX,
				    (uint8_t *)mbox);
			}
			return (0);
		}
	}
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_completion_error_msg,
	    "%s: status=0x%x", emlxs_mb_cmd_xlate(mb->mbxCommand),
	    (uint32_t)mb->mbxStatus);

	/*
	 * ERROR: process mailbox command error
	 */
	switch (mb->mbxCommand) {
	case MBX_REG_LOGIN:
	case MBX_REG_LOGIN64:

		if (mb->mbxStatus == MBXERR_RPI_FULL) {
#ifdef SLI3_SUPPORT
			port = &VPORT(mb->un.varRegLogin.vpi);
#endif	/* SLI3_SUPPORT */

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_create_failed_msg,
			    "Limit reached. count=%d", port->node_count);
		}
#ifdef NPIV_SUPPORT
		/* Special handle for vport PLOGI */
		if (hba->mbox_iocbq == (uint8_t *)1) {
			hba->mbox_iocbq = NULL;
		}
#endif /* NPIV_SUPPORT */
		break;

	case MBX_READ_LA:
	case MBX_READ_LA64:

		/* Enable Link Attention interrupts */
		mutex_enter(&EMLXS_PORT_LOCK);

		if (!(hba->hc_copy & HC_LAINT_ENA)) {
			/*
			 * hba->hc_copy  = READ_CSR_REG(hba, FC_HC_REG(hba,
			 * hba->csr_addr));
			 */
			hba->hc_copy |= HC_LAINT_ENA;
			WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr),
			    hba->hc_copy);
		}
		mutex_exit(&EMLXS_PORT_LOCK);

		break;


	case MBX_CLEAR_LA:

		la_enable = 1;

		if (mb->mbxStatus == 0x1601) {
			/*
			 * Get a buffer which will be used for mailbox
			 * commands
			 */
			if ((mbox = (MAILBOX *) emlxs_mem_get(hba, MEM_MBOX |
			    MEM_PRI))) {
				/* Get link attention message */
				if (emlxs_mb_read_la(hba, mbox) == 0) {
					if (emlxs_mb_issue_cmd(hba, mbox,
					    MBX_NOWAIT, 0) != MBX_BUSY) {
						(void) emlxs_mem_put(hba,
						    MEM_MBOX, (uint8_t *)mbox);
					}
					la_enable = 0;
				} else {
					(void) emlxs_mem_put(hba, MEM_MBOX,
					    (uint8_t *)mbox);
				}
			}
		}
		mutex_enter(&EMLXS_PORT_LOCK);
		if (la_enable) {
			if (!(hba->hc_copy & HC_LAINT_ENA)) {
				/* Enable Link Attention interrupts */
				/*
				 * hba->hc_copy  = READ_CSR_REG(hba,
				 * FC_HC_REG(hba, hba->csr_addr));
				 */
				hba->hc_copy |= HC_LAINT_ENA;
				WRITE_CSR_REG(hba,
				    FC_HC_REG(hba, hba->csr_addr),
				    hba->hc_copy);
			}
		} else {
			if (hba->hc_copy & HC_LAINT_ENA) {
				/* Disable Link Attention interrupts */
				/*
				 * hba->hc_copy  = READ_CSR_REG(hba,
				 * FC_HC_REG(hba, hba->csr_addr));
				 */
				hba->hc_copy &= ~HC_LAINT_ENA;
				WRITE_CSR_REG(hba,
				    FC_HC_REG(hba, hba->csr_addr),
				    hba->hc_copy);
			}
		}
		mutex_exit(&EMLXS_PORT_LOCK);

		break;

	case MBX_INIT_LINK:
		if ((hba->flag & FC_SLIM2_MODE) &&
		    (hba->mbox_queue_flag == MBX_NOWAIT)) {
			/* Retry only MBX_NOWAIT requests */

			if ((cfg[CFG_LINK_SPEED].current > 0) &&
			    ((mb->mbxStatus == 0x0011) ||
			    (mb->mbxStatus == 0x0500))) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_event_msg,
				    "Retrying.  %s: status=%x. Auto-speed set.",
				    emlxs_mb_cmd_xlate(mb->mbxCommand),
				    (uint32_t)mb->mbxStatus);

				if ((mbox = (MAILBOX *) emlxs_mem_get(hba,
				    MEM_MBOX))) {
					bcopy((uint8_t *)mb, (uint8_t *)mbox,
					    MAILBOX_CMD_BSIZE);

					mbox->un.varInitLnk.link_flags &=
					    ~FLAGS_LINK_SPEED;
					mbox->un.varInitLnk.link_speed = 0;
					mbox->mbxOwner = OWN_HOST;
					mbox->mbxStatus = 0;

					/* Refresh the mailbox area */
					emlxs_mb_retry(hba, mbox);

					if (emlxs_mb_issue_cmd(hba, mbox,
					    MBX_NOWAIT, 0) != MBX_BUSY) {
						(void) emlxs_mem_put(hba,
						    MEM_MBOX, (uint8_t *)mbox);
					}
					return (0);
				}
			}
		}
		break;
	}

done:

	/* Clean up the mailbox area */
	emlxs_mb_fini(hba, mb, mb->mbxStatus);

	/* Attempt to send pending mailboxes */
	if ((mbox = (MAILBOX *) emlxs_mb_get(hba))) {
		if (emlxs_mb_issue_cmd(hba, mbox, MBX_NOWAIT, 0) != MBX_BUSY) {
			(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbox);
		}
	}
	return (0);

} /* emlxs_handle_mb_event() */



/*
 *  emlxs_mb_handle_cmd
 *
 *  Description: Process a Mailbox Command.
 *  Called from host_interrupt to process MBATT
 *
 *    Returns:
 *
 */
static int
emlxs_mb_handle_cmd(emlxs_hba_t *hba, MAILBOX *mb)
{
	emlxs_port_t *port = &PPORT;
	emlxs_port_t *vport;
	MAILBOXQ *mbox;
	NODELIST *ndlp;
	volatile SERV_PARM *sp;
	int32_t i;
	uint32_t ldata;
	uint32_t ldid;
	uint16_t lrpi;
	uint16_t lvpi;
	MATCHMAP *mp;
	uint8_t *wwn;
	READ_LA_VAR la;

	if (mb->mbxStatus != 0) {
		return (1);
	}
	mp = (MATCHMAP *) hba->mbox_bp;

	/*
	 * Mailbox command completed successfully, process completion
	 */
	switch (mb->mbxCommand) {
	case MBX_SHUTDOWN:
	case MBX_LOAD_SM:
	case MBX_READ_NV:
	case MBX_WRITE_NV:
	case MBX_RUN_BIU_DIAG:
	case MBX_RUN_BIU_DIAG64:
	case MBX_INIT_LINK:
	case MBX_DOWN_LINK:
	case MBX_CONFIG_LINK:
	case MBX_PART_SLIM:
	case MBX_CONFIG_RING:
	case MBX_RESET_RING:
	case MBX_READ_CONFIG:
	case MBX_READ_RCONFIG:
	case MBX_READ_STATUS:
	case MBX_READ_XRI:
	case MBX_READ_REV:
	case MBX_READ_LNK_STAT:
	case MBX_UNREG_LOGIN:
	case MBX_DUMP_MEMORY:
	case MBX_DUMP_CONTEXT:
	case MBX_RUN_DIAGS:
	case MBX_RESTART:
	case MBX_UPDATE_CFG:
	case MBX_DOWN_LOAD:
	case MBX_DEL_LD_ENTRY:
	case MBX_RUN_PROGRAM:
	case MBX_SET_MASK:
	case MBX_SET_VARIABLE:
	case MBX_UNREG_D_ID:
	case MBX_KILL_BOARD:
	case MBX_CONFIG_FARP:
	case MBX_LOAD_AREA:
	case MBX_CONFIG_PORT:
	case MBX_CONFIG_MSI:
	case MBX_FLASH_WR_ULA:
	case MBX_SET_DEBUG:
	case MBX_GET_DEBUG:
	case MBX_LOAD_EXP_ROM:
	case MBX_BEACON:
	case MBX_READ_RPI:
	case MBX_READ_RPI64:
	case MBX_REG_VPI:
	case MBX_UNREG_VPI:
	case MBX_CONFIG_HBQ:
	case MBX_ASYNC_EVENT:
	case MBX_HEARTBEAT:
		break;

	case MBX_CONFIG_MSIX:
		break;

	case MBX_READ_SPARM:	/* a READ SPARAM command completed */
	case MBX_READ_SPARM64:	/* a READ SPARAM command completed */
		{
			if (mp) {
				bcopy((caddr_t)mp->virt, (caddr_t)& hba->sparam,
				    sizeof (SERV_PARM));

				bcopy((caddr_t)& hba->sparam.nodeName,
				    (caddr_t)& hba->wwnn,
				    sizeof (NAME_TYPE));

				bcopy((caddr_t)& hba->sparam.portName,
				    (caddr_t)& hba->wwpn,
				    sizeof (NAME_TYPE));

				/* Initialize the physical port */
				bcopy((caddr_t)& hba->sparam,
				    (caddr_t)& port->sparam,
				    sizeof (SERV_PARM));
				bcopy((caddr_t)& hba->wwpn,
				    (caddr_t)& port->wwpn, sizeof (NAME_TYPE));
				bcopy((caddr_t)& hba->wwnn,
				    (caddr_t)& port->wwnn, sizeof (NAME_TYPE));

				/* Initialize the virtual ports */
				for (i = 1; i < MAX_VPORTS; i++) {
					vport = &VPORT(i);
					if (vport->flag & EMLXS_PORT_BOUND) {
						continue;
					}
					bcopy((caddr_t)& hba->sparam,
					    (caddr_t)& vport->sparam,
					    sizeof (SERV_PARM));

					bcopy((caddr_t)& vport->wwnn,
					    (caddr_t)& vport->sparam.nodeName,
					    sizeof (NAME_TYPE));

					bcopy((caddr_t)& vport->wwpn,
					    (caddr_t)& vport->sparam.portName,
					    sizeof (NAME_TYPE));
				}

			}
			break;
		}


	case MBX_REG_LOGIN:
	case MBX_REG_LOGIN64:

		if (!mp) {
			break;
		}
#ifdef SLI3_SUPPORT
		ldata = mb->un.varWords[5];
		lvpi = ldata & 0xffff;
		port = &VPORT(lvpi);
#endif	/* SLI3_SUPPORT */

		/* First copy command data */
		ldata = mb->un.varWords[0];	/* get rpi */
		lrpi = ldata & 0xffff;

		ldata = mb->un.varWords[1];	/* get did */
		ldid = ldata & Mask_DID;

		sp = (volatile SERV_PARM *) mp->virt;
		ndlp = emlxs_node_find_did(port, ldid);

		if (!ndlp) {
			/* Attempt to create a node */
			if ((ndlp = (NODELIST *) emlxs_mem_get(hba, MEM_NLP))) {
				ndlp->nlp_Rpi = lrpi;
				ndlp->nlp_DID = ldid;

				bcopy((uint8_t *)sp,
				    (uint8_t *)& ndlp->sparm,
				    sizeof (SERV_PARM));

				bcopy((uint8_t *)& sp->nodeName,
				    (uint8_t *)& ndlp->nlp_nodename,
				    sizeof (NAME_TYPE));

				bcopy((uint8_t *)& sp->portName,
				    (uint8_t *)& ndlp->nlp_portname,
				    sizeof (NAME_TYPE));

				ndlp->nlp_active = 1;
				ndlp->nlp_flag[FC_CT_RING] |= NLP_CLOSED;
				ndlp->nlp_flag[FC_ELS_RING] |= NLP_CLOSED;
				ndlp->nlp_flag[FC_FCP_RING] |= NLP_CLOSED;
				ndlp->nlp_flag[FC_IP_RING] |= NLP_CLOSED;

				/* Add the node */
				emlxs_node_add(port, ndlp);

				/* Open the node */
				emlxs_node_open(port, ndlp, FC_CT_RING);
				emlxs_node_open(port, ndlp, FC_ELS_RING);
				emlxs_node_open(port, ndlp, FC_IP_RING);
				emlxs_node_open(port, ndlp, FC_FCP_RING);
			} else {
				wwn = (uint8_t *)& sp->portName;
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_node_create_failed_msg,
				    "Unable to allocate node. did=%06x rpi=%x "
				    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x",
				    ldid, lrpi, wwn[0], wwn[1], wwn[2], wwn[3],
				    wwn[4], wwn[5], wwn[6], wwn[7]);

				break;
			}
		} else {
			mutex_enter(&EMLXS_PORT_LOCK);

			ndlp->nlp_Rpi = lrpi;
			ndlp->nlp_DID = ldid;

			bcopy((uint8_t *)sp,
			    (uint8_t *)& ndlp->sparm,
			    sizeof (SERV_PARM));

			bcopy((uint8_t *)& sp->nodeName,
			    (uint8_t *)& ndlp->nlp_nodename,
			    sizeof (NAME_TYPE));

			bcopy((uint8_t *)& sp->portName,
			    (uint8_t *)& ndlp->nlp_portname,
			    sizeof (NAME_TYPE));

			wwn = (uint8_t *)& ndlp->nlp_portname;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_update_msg,
			    "node=%p did=%06x rpi=%x wwpn="
			    "%02x%02x%02x%02x%02x%02x%02x%02x",
			    ndlp, ndlp->nlp_DID, ndlp->nlp_Rpi, wwn[0], wwn[1],
			    wwn[2], wwn[3], wwn[4], wwn[5], wwn[6], wwn[7]);

			mutex_exit(&EMLXS_PORT_LOCK);

			/* Open the node */
			emlxs_node_open(port, ndlp, FC_CT_RING);
			emlxs_node_open(port, ndlp, FC_ELS_RING);
			emlxs_node_open(port, ndlp, FC_IP_RING);
			emlxs_node_open(port, ndlp, FC_FCP_RING);
		}

		/* If this was a fabric login */
		if (ndlp->nlp_DID == Fabric_DID) {
			/*
			 * If CLEAR_LA has been sent, then attempt to
			 * register the vpi now
			 */
			if (hba->state == FC_READY) {
				(void) emlxs_mb_reg_vpi(port);
			}
#ifdef SLI3_SUPPORT
			/*
			 * If NPIV Fabric support has just been established
			 * on the physical port, then notify the vports of
			 * the link up
			 */
			if ((lvpi == 0) &&
			    (hba->flag & FC_NPIV_ENABLED) &&
			    (hba->flag & FC_NPIV_SUPPORTED)) {
				/* Skip the physical port */
				for (i = 1; i < MAX_VPORTS; i++) {
					vport = &VPORT(i);

					if (!(vport->flag & EMLXS_PORT_BOUND) ||
					    !(vport->flag &
					    EMLXS_PORT_ENABLE)) {
						continue;
					}
					emlxs_port_online(vport);
				}
			}
#endif	/* SLI3_SUPPORT */

		}
#ifdef NPIV_SUPPORT
		if (hba->mbox_iocbq == (uint8_t *)1) {
			hba->mbox_iocbq = NULL;
			(void) emlxs_mb_unreg_did(port, ldid, NULL, NULL, NULL);
		}
#endif	/* NPIV_SUPPORT */

#ifdef DHCHAP_SUPPORT
		if (hba->mbox_sbp || hba->mbox_ubp) {
			if (emlxs_dhc_auth_start(port, ndlp, hba->mbox_sbp,
			    hba->mbox_ubp) == 0) {
				/*
				 * Auth started - auth completion will handle
				 * sbp and ubp now
				 */
				hba->mbox_sbp = NULL;
				hba->mbox_ubp = NULL;
			}
		}
#endif	/* DHCHAP_SUPPORT */

#ifdef SFCT_SUPPORT
		if (hba->mbox_sbp && ((emlxs_buf_t *)hba->mbox_sbp)->fct_cmd) {
			emlxs_buf_t *cmd_sbp = (emlxs_buf_t *)hba->mbox_sbp;

			if (cmd_sbp->fct_state == EMLXS_FCT_REG_PENDING) {
				hba->mbox_sbp = NULL;

				mutex_enter(&EMLXS_PKT_LOCK);
				cmd_sbp->node = ndlp;
				cmd_sbp->fct_state = EMLXS_FCT_REG_COMPLETE;
				cv_broadcast(&EMLXS_PKT_CV);
				mutex_exit(&EMLXS_PKT_LOCK);
			}
		}
#endif	/* SFCT_SUPPORT */

		break;

	case MBX_READ_LA:
	case MBX_READ_LA64:
		bcopy((uint32_t *)((char *)mb + sizeof (uint32_t)),
		    (uint32_t *)& la, sizeof (READ_LA_VAR));

		if (mp) {
			bcopy((caddr_t)mp->virt,
			    (caddr_t)port->alpa_map, 128);
		} else {
			bzero((caddr_t)port->alpa_map, 128);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_atten_msg,
		    "type=%s tag=%d -> %d  ALPA=%x",
		    ((la.attType == AT_LINK_UP) ?
		    "LinkUp" : "LinkDown"),
		    (uint32_t)hba->link_event_tag,
		    (uint32_t)la.eventTag, (uint32_t)la.granted_AL_PA);

		if (la.pb) {
			hba->flag |= FC_BYPASSED_MODE;
		} else {
			hba->flag &= ~FC_BYPASSED_MODE;
		}

		if (hba->link_event_tag == la.eventTag) {
			HBASTATS.LinkMultiEvent++;
		} else if (hba->link_event_tag + 1 < la.eventTag) {
			HBASTATS.LinkMultiEvent++;

			if (hba->state > FC_LINK_DOWN) {
				/* Declare link down here */
				emlxs_linkdown(hba);
			}
		}
		hba->link_event_tag = la.eventTag;
		port->lip_type = 0;

		/* If link not already up then declare it up now */
		if ((la.attType == AT_LINK_UP) &&
		    (hba->state < FC_LINK_UP)) {

			/* Save the linkspeed */
			hba->linkspeed = la.UlnkSpeed;

			/*
			 * Check for old model adapters that only
			 * supported 1Gb
			 */
			if ((hba->linkspeed == 0) &&
			    (hba->model_info.chip &
			    EMLXS_DRAGONFLY_CHIP)) {
				hba->linkspeed = LA_1GHZ_LINK;
			}
			if ((hba->topology = la.topology) ==
			    TOPOLOGY_LOOP) {
				port->did = la.granted_AL_PA;
				port->lip_type = la.lipType;

				if (hba->flag & FC_SLIM2_MODE) {
					i = la.un.lilpBde64.tus.f.
					    bdeSize;
				} else {
					i = la.un.lilpBde.bdeSize;
				}

				if (i == 0) {
					port->alpa_map[0] = 0;
				} else {
					uint8_t *alpa_map;
					uint32_t j;

					/*
					 * Check number of devices in
					 * map
					 */
					if (port->alpa_map[0] > 127) {
						port->alpa_map[0] = 127;
					}
					alpa_map = (uint8_t *)port->alpa_map;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_link_atten_msg,
					    "alpa_map: %d device(s):  %02x "
					    "%02x %02x %02x %02x %02x %02x",
					    alpa_map[0], alpa_map[1],
					    alpa_map[2], alpa_map[3],
					    alpa_map[4], alpa_map[5],
					    alpa_map[6], alpa_map[7]);

					for (j = 8; j <= alpa_map[0]; j += 8) {
						EMLXS_MSGF(EMLXS_CONTEXT,
						    &emlxs_link_atten_msg,
						    "alpa_map: %02x %02x %02x "
						    "%02x %02x %02x %02x %02x",
						    alpa_map[j],
						    alpa_map[j + 1],
						    alpa_map[j + 2],
						    alpa_map[j + 3],
						    alpa_map[j + 4],
						    alpa_map[j + 5],
						    alpa_map[j + 6],
						    alpa_map[j + 7]);
					}
				}
			}
#ifdef MENLO_SUPPORT
			/* Check if Menlo maintenance mode is enabled */
			if (hba->model_info.device_id ==
			    PCI_DEVICE_ID_LP21000_M) {
				if (la.mm == 1) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_link_atten_msg,
					    "Maintenance Mode enabled.");

					mutex_enter(&EMLXS_PORT_LOCK);
					hba->flag |= FC_MENLO_MODE;
					mutex_exit(&EMLXS_PORT_LOCK);

					mutex_enter(&EMLXS_LINKUP_LOCK);
					cv_broadcast(&EMLXS_LINKUP_CV);
					mutex_exit(&EMLXS_LINKUP_LOCK);
				} else {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_link_atten_msg,
					    "Maintenance Mode disabled.");
				}

				/* Check FCoE attention bit */
				if (la.fa == 1) {
					(void) thread_create(NULL, 0,
					    emlxs_fcoe_attention_thread,
					    (char *)hba, 0,
					    &p0, TS_RUN,
					    v.v_maxsyspri - 2);
				}
			}
#endif	/* MENLO_SUPPORT */

			if ((mbox = (MAILBOXQ *) emlxs_mem_get(hba,
			    MEM_MBOX | MEM_PRI))) {
				/*
				 * This should turn on DELAYED ABTS
				 * for ELS timeouts
				 */
				emlxs_mb_set_var(hba, (MAILBOX *) mbox,
				    0x00052198, 0x1);

				emlxs_mb_put(hba, mbox);
			}
			if ((mbox = (MAILBOXQ *) emlxs_mem_get(hba,
			    MEM_MBOX | MEM_PRI))) {
				/*
				 * If link not already down then
				 * declare it down now
				 */
				if (emlxs_mb_read_sparam(hba,
				    (MAILBOX *) mbox) == 0) {
					emlxs_mb_put(hba, mbox);
				} else {
					(void) emlxs_mem_put(hba, MEM_MBOX,
					    (uint8_t *)mbox);
				}
			}
			if ((mbox = (MAILBOXQ *) emlxs_mem_get(hba,
			    MEM_MBOX | MEM_PRI))) {
				emlxs_mb_config_link(hba,
				    (MAILBOX *) mbox);

				emlxs_mb_put(hba, mbox);
			}
			/* Declare the linkup here */
			emlxs_linkup(hba);
		}
		/* If link not already down then declare it down now */
		else if ((la.attType == AT_LINK_DOWN) &&
		    (hba->state > FC_LINK_DOWN)) {
			/* Declare link down here */
			emlxs_linkdown(hba);
		}
		/* Enable Link attention interrupt */
		mutex_enter(&EMLXS_PORT_LOCK);

		if (!(hba->hc_copy & HC_LAINT_ENA)) {
			/*
			 * hba->hc_copy  = READ_CSR_REG(hba,
			 * FC_HC_REG(hba, hba->csr_addr));
			 */
			hba->hc_copy |= HC_LAINT_ENA;
			WRITE_CSR_REG(hba, FC_HC_REG(hba,
			    hba->csr_addr), hba->hc_copy);
		}
		mutex_exit(&EMLXS_PORT_LOCK);

		/* Log the link event */
		emlxs_log_link_event(port);

		break;

	case MBX_CLEAR_LA:
		/* Enable on Link Attention interrupts */
		mutex_enter(&EMLXS_PORT_LOCK);

		if (!(hba->hc_copy & HC_LAINT_ENA)) {
			/*
			 * hba->hc_copy  = READ_CSR_REG(hba, FC_HC_REG(hba,
			 * hba->csr_addr));
			 */
			hba->hc_copy |= HC_LAINT_ENA;
			WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr),
			    hba->hc_copy);
		}
		if (hba->state >= FC_LINK_UP) {
			emlxs_ffstate_change_locked(hba, FC_READY);
		}
		mutex_exit(&EMLXS_PORT_LOCK);

		/* Adapter is now ready for FCP traffic */
		if (hba->state == FC_READY) {
			/* Register vpi's for all ports that have did's */
			for (i = 0; i < MAX_VPORTS; i++) {
				vport = &VPORT(i);

				if (!(vport->flag & EMLXS_PORT_BOUND) ||
				    !(vport->did)) {
					continue;
				}
				(void) emlxs_mb_reg_vpi(vport);
			}

			/* Attempt to send any pending IO */
			emlxs_issue_iocb_cmd(hba, &hba->ring[FC_FCP_RING], 0);
		}
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_completion_error_msg,
		    "Unknown mailbox cmd: 0x%x", mb->mbxCommand);
		HBASTATS.MboxInvalid++;
		break;
	}

	return (0);

} /* emlxs_mb_handle_cmd() */


/* MBX_NOWAIT - returns MBX_BUSY or MBX_SUCCESS or MBX_HARDWARE_ERROR */
/* MBX_WAIT   - returns MBX_TIMEOUT or mailbox_status */
/* MBX_SLEEP  - returns MBX_TIMEOUT or mailbox_status */
/* MBX_POLL   - returns MBX_TIMEOUT or mailbox_status */

extern uint32_t
emlxs_mb_issue_cmd(emlxs_hba_t *hba, MAILBOX *mb, int32_t flag, uint32_t tmo)
{
	emlxs_port_t *port = &PPORT;
	MAILBOX *mbox;
	MAILBOXQ *mbq;
	volatile uint32_t word0;
	volatile uint32_t ldata;
	uint32_t ha_copy;
	off_t offset;
	MATCHMAP *mbox_bp;
	uint32_t tmo_local;
	MAILBOX *swpmb;

	mbq = (MAILBOXQ *) mb;
	swpmb = (MAILBOX *) & word0;

	mb->mbxStatus = MBX_SUCCESS;

	/* Check for minimum timeouts */
	switch (mb->mbxCommand) {
		/* Mailbox commands that erase/write flash */
	case MBX_DOWN_LOAD:
	case MBX_UPDATE_CFG:
	case MBX_LOAD_AREA:
	case MBX_LOAD_EXP_ROM:
	case MBX_WRITE_NV:
	case MBX_FLASH_WR_ULA:
	case MBX_DEL_LD_ENTRY:
	case MBX_LOAD_SM:
		if (tmo < 300) {
			tmo = 300;
		}
		break;

	default:
		if (tmo < 30) {
			tmo = 30;
		}
		break;
	}

	/* Adjust wait flag */
	if (flag != MBX_NOWAIT) {
		/* If interrupt is enabled, use sleep, otherwise poll */
		if (hba->hc_copy & HC_MBINT_ENA) {
			flag = MBX_SLEEP;
		} else {
			flag = MBX_POLL;
		}
	}
	mutex_enter(&EMLXS_PORT_LOCK);

	/* Check for hardware error */
	if (hba->flag & FC_HARDWARE_ERROR) {
		mb->mbxStatus = (hba->flag & FC_OVERTEMP_EVENT) ?
		    MBX_OVERTEMP_ERROR : MBX_HARDWARE_ERROR;

		mutex_exit(&EMLXS_PORT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
		    "Hardware error reported. %s failed. status=%x mb=%p",
		    emlxs_mb_cmd_xlate(mb->mbxCommand), mb->mbxStatus, mb);

		return (MBX_HARDWARE_ERROR);
	}
	if (hba->mbox_queue_flag) {
		/* If we are not polling, then queue it for later */
		if (flag == MBX_NOWAIT) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Busy.      %s: mb=%p NoWait.",
			    emlxs_mb_cmd_xlate(mb->mbxCommand), mb);

			emlxs_mb_put(hba, mbq);

			HBASTATS.MboxBusy++;

			mutex_exit(&EMLXS_PORT_LOCK);

			return (MBX_BUSY);
		}
		tmo_local = tmo * 20;	/* Convert tmo seconds to 50 */
					/*   millisecond tics */
		while (hba->mbox_queue_flag) {
			mutex_exit(&EMLXS_PORT_LOCK);

			if (tmo_local-- == 0) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_event_msg,
				    "Timeout.   %s: mb=%p tmo=%d Waiting.",
				    emlxs_mb_cmd_xlate(mb->mbxCommand), mb,
				    tmo);

				/* Non-lethalStatus mailbox timeout */
				/* Does not indicate a hardware error */
				mb->mbxStatus = MBX_TIMEOUT;
				return (MBX_TIMEOUT);
			}
			DELAYMS(50);
			mutex_enter(&EMLXS_PORT_LOCK);
		}
	}
	/* Initialize mailbox area */
	emlxs_mb_init(hba, mbq, flag, tmo);

	switch (flag) {
	case MBX_NOWAIT:

		if (mb->mbxCommand != MBX_HEARTBEAT) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Sending.   %s: mb=%p NoWait.",
			    emlxs_mb_cmd_xlate(mb->mbxCommand), mb);
		}
		break;

	case MBX_SLEEP:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
		    "Sending.   %s: mb=%p Sleep.",
		    emlxs_mb_cmd_xlate(mb->mbxCommand), mb);

		break;

	case MBX_POLL:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
		    "Sending.   %s: mb=%p Polled.",
		    emlxs_mb_cmd_xlate(mb->mbxCommand), mb);
		break;
	}

	mb->mbxOwner = OWN_CHIP;

	/* Clear the attention bit */
	WRITE_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr), HA_MBATT);

	if (hba->flag & FC_SLIM2_MODE) {
		/* First copy command data */
		mbox = FC_SLIM2_MAILBOX(hba);
		offset = (off_t)((uint64_t)(unsigned long)mbox -
		    (uint64_t)(unsigned long)hba->slim2.virt);

#ifdef MBOX_EXT_SUPPORT
		if (hba->mbox_ext) {
			uint32_t *mbox_ext = (uint32_t *)((uint8_t *)mbox +
			    MBOX_EXTENSION_OFFSET);
			off_t offset_ext = offset + MBOX_EXTENSION_OFFSET;

			emlxs_pcimem_bcopy((uint32_t *)hba->mbox_ext, mbox_ext,
			    hba->mbox_ext_size);
			emlxs_mpdata_sync(hba->slim2.dma_handle, offset_ext,
			    hba->mbox_ext_size, DDI_DMA_SYNC_FORDEV);
		}
#endif	/* MBOX_EXT_SUPPORT */

		emlxs_pcimem_bcopy((uint32_t *)mb, (uint32_t *)mbox,
		    MAILBOX_CMD_BSIZE);
		emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
		    MAILBOX_CMD_BSIZE, DDI_DMA_SYNC_FORDEV);
	}
	/* Check for config port command */
	else if (mb->mbxCommand == MBX_CONFIG_PORT) {
		/* copy command data into host mbox for cmpl */
		mbox = FC_SLIM2_MAILBOX(hba);
		offset = (off_t)((uint64_t)(unsigned long)mbox -
		    (uint64_t)(unsigned long)hba->slim2.virt);

		emlxs_pcimem_bcopy((uint32_t *)mb, (uint32_t *)mbox,
		    MAILBOX_CMD_BSIZE);
		emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
		    MAILBOX_CMD_BSIZE, DDI_DMA_SYNC_FORDEV);

		/* First copy command data */
		mbox = FC_SLIM1_MAILBOX(hba);
		WRITE_SLIM_COPY(hba, &mb->un.varWords, &mbox->un.varWords,
		    (MAILBOX_CMD_WSIZE - 1));

		/* copy over last word, with mbxOwner set */
		ldata = *((volatile uint32_t *) mb);
		WRITE_SLIM_ADDR(hba, ((volatile uint32_t *) mbox), ldata);

		/* switch over to host mailbox */
		/*
		 * hba->mbox_queueaddr = (uint32_t *)&((SLIM2 *)
		 * hba->slim2.virt)->mbx;
		 */
		hba->flag |= FC_SLIM2_MODE;
	} else {	/* SLIM 1 */
		mbox = FC_SLIM1_MAILBOX(hba);

#ifdef MBOX_EXT_SUPPORT
		if (hba->mbox_ext) {
			uint32_t *mbox_ext = (uint32_t *)((uint8_t *)mbox +
			    MBOX_EXTENSION_OFFSET);
			WRITE_SLIM_COPY(hba, (uint32_t *)hba->mbox_ext,
			    mbox_ext, (hba->mbox_ext_size / 4));
		}
#endif	/* MBOX_EXT_SUPPORT */

		/* First copy command data */
		WRITE_SLIM_COPY(hba, &mb->un.varWords, &mbox->un.varWords,
		    (MAILBOX_CMD_WSIZE - 1));

		/* copy over last word, with mbxOwner set */
		ldata = *((volatile uint32_t *) mb);
		WRITE_SLIM_ADDR(hba, ((volatile uint32_t *) mbox), ldata);
	}

	/* Interrupt board to do it right away */
	WRITE_CSR_REG(hba, FC_CA_REG(hba, hba->csr_addr), CA_MBATT);

	mutex_exit(&EMLXS_PORT_LOCK);

	switch (flag) {
	case MBX_NOWAIT:
		return (MBX_SUCCESS);

	case MBX_SLEEP:

		/* Wait for completion */
		/* The driver clock is timing the mailbox. */
		/* emlxs_mb_fini() will be called externally. */

		mutex_enter(&EMLXS_MBOX_LOCK);
		while (!(mbq->flag & MBQ_COMPLETED)) {
			cv_wait(&EMLXS_MBOX_CV, &EMLXS_MBOX_LOCK);
		}
		mutex_exit(&EMLXS_MBOX_LOCK);

		if (mb->mbxStatus == MBX_TIMEOUT) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_event_msg,
			    "Timeout.   %s: mb=%p tmo=%d. Sleep.",
			    emlxs_mb_cmd_xlate(mb->mbxCommand), mb, tmo);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Completed. %s: mb=%p status=%x Sleep.",
			    emlxs_mb_cmd_xlate(mb->mbxCommand), mb,
			    mb->mbxStatus);
		}

		break;

	case MBX_POLL:

		tmo_local = tmo * 2000;	/* Convert tmo seconds to 500 usec */
					/*   tics */

		if (hba->state >= FC_INIT_START) {
			ha_copy = READ_CSR_REG(hba, FC_HA_REG(hba,
			    hba->csr_addr));

			/* Wait for command to complete */
			while (!(ha_copy & HA_MBATT) &&
			    !(mbq->flag & MBQ_COMPLETED)) {
				if (!hba->timer_id && (tmo_local-- == 0)) {
					/* self time */
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_hardware_error_msg,
					    "Mailbox Timeout: %s: mb=%p Polled",
					    emlxs_mb_cmd_xlate(mb->mbxCommand),
					    mb);

					hba->flag |= FC_MBOX_TIMEOUT;
					emlxs_ffstate_change(hba, FC_ERROR);
					emlxs_mb_fini(hba, NULL, MBX_TIMEOUT);

					break;
				}
				DELAYUS(500);
				ha_copy = READ_CSR_REG(hba,
				    FC_HA_REG(hba, hba->csr_addr));
			}

			if (mb->mbxStatus == MBX_TIMEOUT) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_event_msg,
				    "Timeout.   %s: mb=%p tmo=%d. Polled.",
				    emlxs_mb_cmd_xlate(mb->mbxCommand), mb,
				    tmo);

				break;
			}
		}
		/* Get first word of mailbox */
		if (hba->flag & FC_SLIM2_MODE) {
			mbox = FC_SLIM2_MAILBOX(hba);
			offset = (off_t)((uint64_t)(unsigned long)mbox -
			    (uint64_t)(unsigned long)hba->slim2.virt);

			emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
			    sizeof (uint32_t), DDI_DMA_SYNC_FORKERNEL);
			word0 = *((volatile uint32_t *) mbox);
			word0 = PCIMEM_LONG(word0);
		} else {
			mbox = FC_SLIM1_MAILBOX(hba);
			word0 = READ_SLIM_ADDR(hba,
			    ((volatile uint32_t *) mbox));
		}

		/* Wait for command to complete */
		while ((swpmb->mbxOwner == OWN_CHIP) &&
		    !(mbq->flag & MBQ_COMPLETED)) {
			if (!hba->timer_id && (tmo_local-- == 0)) {
				/* self time */
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_hardware_error_msg,
				    "Mailbox Timeout: %s: mb=%p Polled.",
				    emlxs_mb_cmd_xlate(mb->mbxCommand), mb);

				hba->flag |= FC_MBOX_TIMEOUT;
				emlxs_ffstate_change(hba, FC_ERROR);
				emlxs_mb_fini(hba, NULL, MBX_TIMEOUT);

				break;
			}
			DELAYUS(500);

			/* Get first word of mailbox */
			if (hba->flag & FC_SLIM2_MODE) {
				emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
				    sizeof (uint32_t), DDI_DMA_SYNC_FORKERNEL);
				word0 = *((volatile uint32_t *) mbox);
				word0 = PCIMEM_LONG(word0);
			} else {
				word0 = READ_SLIM_ADDR(hba,
				    ((volatile uint32_t *) mbox));
			}

		}	/* while */

		if (mb->mbxStatus == MBX_TIMEOUT) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_event_msg,
			    "Timeout.   %s: mb=%p tmo=%d. Polled.",
			    emlxs_mb_cmd_xlate(mb->mbxCommand), mb, tmo);

			break;
		}
		/* copy results back to user */
		if (hba->flag & FC_SLIM2_MODE) {
			emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
			    MAILBOX_CMD_BSIZE, DDI_DMA_SYNC_FORKERNEL);
			emlxs_pcimem_bcopy((uint32_t *)mbox, (uint32_t *)mb,
			    MAILBOX_CMD_BSIZE);
		} else {
			READ_SLIM_COPY(hba, (uint32_t *)mb, (uint32_t *)mbox,
			    MAILBOX_CMD_WSIZE);
		}

#ifdef MBOX_EXT_SUPPORT
		if (hba->mbox_ext) {
			uint32_t *mbox_ext = (uint32_t *)((uint8_t *)mbox +
			    MBOX_EXTENSION_OFFSET);
			off_t offset_ext = offset + MBOX_EXTENSION_OFFSET;

			if (hba->flag & FC_SLIM2_MODE) {
				emlxs_mpdata_sync(hba->slim2.dma_handle,
				    offset_ext, hba->mbox_ext_size,
				    DDI_DMA_SYNC_FORKERNEL);
				emlxs_pcimem_bcopy(mbox_ext,
				    (uint32_t *)hba->mbox_ext,
				    hba->mbox_ext_size);
			} else {
				READ_SLIM_COPY(hba, (uint32_t *)hba->mbox_ext,
				    mbox_ext, (hba->mbox_ext_size / 4));
			}
		}
#endif	/* MBOX_EXT_SUPPORT */

		/* Sync the memory buffer */
		if (hba->mbox_bp) {
			mbox_bp = (MATCHMAP *) hba->mbox_bp;
			emlxs_mpdata_sync(mbox_bp->dma_handle, 0, mbox_bp->size,
			    DDI_DMA_SYNC_FORKERNEL);
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
		    "Completed. %s: mb=%p status=%x Polled.",
		    emlxs_mb_cmd_xlate(mb->mbxCommand), mb, mb->mbxStatus);

		/* Process the result */
		if (!(mbq->flag & MBQ_PASSTHRU)) {
			(void) emlxs_mb_handle_cmd(hba, mb);
		}
		/* Clear the attention bit */
		WRITE_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr), HA_MBATT);

		/* Clean up the mailbox area */
		emlxs_mb_fini(hba, NULL, mb->mbxStatus);

		break;

	}	/* switch (flag) */

	return (mb->mbxStatus);

} /* emlxs_mb_issue_cmd() */



extern char *
emlxs_mb_cmd_xlate(uint8_t cmd)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_mb_cmd_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (cmd == emlxs_mb_cmd_table[i].code) {
			return (emlxs_mb_cmd_table[i].string);
		}
	}

	(void) sprintf(buffer, "Cmd=0x%x", cmd);
	return (buffer);

} /* emlxs_mb_cmd_xlate() */
