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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2000 to 2010, LSI Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms of all code within
 * this file that is exclusively owned by LSI, with or without
 * modification, is permitted provided that, in addition to the CDDL 1.0
 * License requirements, the following conditions are met:
 *
 *    Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * mptsas_raid - This file contains all the RAID related functions for the
 * MPT interface.
 */

#if defined(lint) || defined(DEBUG)
#define	MPTSAS_DEBUG
#endif

#define	MPI_RAID_VOL_PAGE_0_PHYSDISK_MAX	2

/*
 * standard header files
 */
#include <sys/note.h>
#include <sys/scsi/scsi.h>
#include <sys/byteorder.h>
#include <sys/raidioctl.h>

#pragma pack(1)

#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_type.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_cnfg.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_init.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_ioc.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_raid.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_tool.h>

#pragma pack()

/*
 * private header files.
 */
#include <sys/scsi/adapters/mpt_sas/mptsas_var.h>

static int mptsas_get_raid_wwid(mptsas_t *mpt, mptsas_raidvol_t *raidvol);

extern int mptsas_check_dma_handle(ddi_dma_handle_t handle);
extern int mptsas_check_acc_handle(ddi_acc_handle_t handle);
extern mptsas_target_t *mptsas_tgt_alloc(mptsas_t *, uint16_t,
    uint64_t, uint32_t, mptsas_phymask_t, uint8_t);

static int
mptsas_raidconf_page_0_cb(mptsas_t *mpt, caddr_t page_memp,
    ddi_acc_handle_t accessp, uint16_t iocstatus, uint32_t iocloginfo,
    va_list ap)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(ap))
#endif
	pMpi2RaidConfigurationPage0_t	raidconfig_page0;
	pMpi2RaidConfig0ConfigElement_t	element;
	uint32_t *confignum;
	int rval = DDI_SUCCESS, i;
	uint8_t numelements, vol, disk;
	uint16_t elementtype, voldevhandle;
	uint16_t etype_vol, etype_pd, etype_hs;
	uint16_t etype_oce;
	m_raidconfig_t *raidconfig;
	uint64_t raidwwn;
	uint32_t native;
	mptsas_target_t	*ptgt;
	uint32_t configindex;

	if (iocstatus == MPI2_IOCSTATUS_CONFIG_INVALID_PAGE) {
		return (DDI_FAILURE);
	}

	if (iocstatus != MPI2_IOCSTATUS_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "mptsas_get_raid_conf_page0 "
		    "config: IOCStatus=0x%x, IOCLogInfo=0x%x",
		    iocstatus, iocloginfo);
		rval = DDI_FAILURE;
		return (rval);
	}
	confignum = va_arg(ap,  uint32_t *);
	configindex = va_arg(ap, uint32_t);
	raidconfig_page0 = (pMpi2RaidConfigurationPage0_t)page_memp;
	/*
	 * Get all RAID configurations.
	 */
	etype_vol = MPI2_RAIDCONFIG0_EFLAGS_VOLUME_ELEMENT;
	etype_pd = MPI2_RAIDCONFIG0_EFLAGS_VOL_PHYS_DISK_ELEMENT;
	etype_hs = MPI2_RAIDCONFIG0_EFLAGS_HOT_SPARE_ELEMENT;
	etype_oce = MPI2_RAIDCONFIG0_EFLAGS_OCE_ELEMENT;
	/*
	 * Set up page address for next time through.
	 */
	*confignum =  ddi_get8(accessp,
	    &raidconfig_page0->ConfigNum);

	/*
	 * Point to the right config in the structure.
	 * Increment the number of valid RAID configs.
	 */
	raidconfig = &mpt->m_raidconfig[configindex];
	mpt->m_num_raid_configs++;

	/*
	 * Set the native flag if this is not a foreign
	 * configuration.
	 */
	native = ddi_get32(accessp, &raidconfig_page0->Flags);
	if (native & MPI2_RAIDCONFIG0_FLAG_FOREIGN_CONFIG) {
		native = FALSE;
	} else {
		native = TRUE;
	}
	raidconfig->m_native = (uint8_t)native;

	/*
	 * Get volume information for the volumes in the
	 * config.
	 */
	numelements = ddi_get8(accessp, &raidconfig_page0->NumElements);
	vol = 0;
	disk = 0;
	element = (pMpi2RaidConfig0ConfigElement_t)
	    &raidconfig_page0->ConfigElement;

	for (i = 0; ((i < numelements) && native); i++, element++) {
		/*
		 * Get the element type.  Could be Volume,
		 * PhysDisk, Hot Spare, or Online Capacity
		 * Expansion PhysDisk.
		 */
		elementtype = ddi_get16(accessp, &element->ElementFlags);
		elementtype &= MPI2_RAIDCONFIG0_EFLAGS_MASK_ELEMENT_TYPE;

		/*
		 * For volumes, get the RAID settings and the
		 * WWID.
		 */
		if (elementtype == etype_vol) {
			voldevhandle = ddi_get16(accessp,
			    &element->VolDevHandle);
			raidconfig->m_raidvol[vol].m_israid = 1;
			raidconfig->m_raidvol[vol].
			    m_raidhandle = voldevhandle;
			/*
			 * Get the settings for the raid
			 * volume.  This includes the
			 * DevHandles for the disks making up
			 * the raid volume.
			 */
			if (mptsas_get_raid_settings(mpt,
			    &raidconfig->m_raidvol[vol]))
				continue;

			/*
			 * Get the WWID of the RAID volume for
			 * SAS HBA
			 */
			if (mptsas_get_raid_wwid(mpt,
			    &raidconfig->m_raidvol[vol]))
				continue;

			raidwwn = raidconfig->m_raidvol[vol].
			    m_raidwwid;

			/*
			 * RAID uses phymask of 0.
			 */
			ptgt = mptsas_tgt_alloc(mpt,
			    voldevhandle, raidwwn, 0, 0, 0);

			raidconfig->m_raidvol[vol].m_raidtgt =
			    ptgt;

			/*
			 * Increment volume index within this
			 * raid config.
			 */
			vol++;
		} else if ((elementtype == etype_pd) ||
		    (elementtype == etype_hs) ||
		    (elementtype == etype_oce)) {
			/*
			 * For all other element types, put
			 * their DevHandles in the phys disk
			 * list of the config.  These are all
			 * some variation of a Phys Disk and
			 * this list is used to keep these
			 * disks from going online.
			 */
			raidconfig->m_physdisk_devhdl[disk] = ddi_get16(accessp,
			    &element->PhysDiskDevHandle);

			/*
			 * Increment disk index within this
			 * raid config.
			 */
			disk++;
		}
	}

	return (rval);
}

int
mptsas_get_raid_info(mptsas_t *mpt)
{
	int rval = DDI_SUCCESS;
	uint32_t confignum, pageaddress;
	uint8_t configindex;

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Clear all RAID info before starting.
	 */
	bzero(mpt->m_raidconfig, sizeof (mpt->m_raidconfig));
	mpt->m_num_raid_configs = 0;

	configindex = 0;
	confignum = 0xff;
	pageaddress = MPI2_RAID_PGAD_FORM_GET_NEXT_CONFIGNUM | confignum;
	while (rval == DDI_SUCCESS) {
		/*
		 * Get the header and config page.  reply contains the reply
		 * frame, which holds status info for the request.
		 */
		rval = mptsas_access_config_page(mpt,
		    MPI2_CONFIG_ACTION_PAGE_READ_CURRENT,
		    MPI2_CONFIG_EXTPAGETYPE_RAID_CONFIG, 0, pageaddress,
		    mptsas_raidconf_page_0_cb, &confignum, configindex);
		configindex++;
		pageaddress = MPI2_RAID_PGAD_FORM_GET_NEXT_CONFIGNUM |
		    confignum;
	}

	return (rval);
}

static int
mptsas_raidvol_page_0_cb(mptsas_t *mpt, caddr_t page_memp,
    ddi_acc_handle_t accessp, uint16_t iocstatus, uint32_t iocloginfo,
    va_list ap)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(ap))
#endif
	pMpi2RaidVolPage0_t raidpage;
	int rval = DDI_SUCCESS, i;
	mptsas_raidvol_t *raidvol;
	uint8_t	numdisks, volstate, voltype, physdisknum;
	uint32_t volsetting;
	uint32_t statusflags, resync_flag;

	if (iocstatus == MPI2_IOCSTATUS_CONFIG_INVALID_PAGE)
		return (DDI_FAILURE);

	if (iocstatus != MPI2_IOCSTATUS_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "mptsas_raidvol_page0_cb "
		    "config: IOCStatus=0x%x, IOCLogInfo=0x%x",
		    iocstatus, iocloginfo);
		rval = DDI_FAILURE;
		return (rval);
	}

	raidvol = va_arg(ap,  mptsas_raidvol_t *);

	raidpage = (pMpi2RaidVolPage0_t)page_memp;
	volstate = ddi_get8(accessp, &raidpage->VolumeState);
	volsetting = ddi_get32(accessp,
	    (uint32_t *)(void *)&raidpage->VolumeSettings);
	statusflags = ddi_get32(accessp, &raidpage->VolumeStatusFlags);
	voltype = ddi_get8(accessp, &raidpage->VolumeType);

	raidvol->m_state = volstate;
	raidvol->m_statusflags = statusflags;
	/*
	 * Volume size is not used right now. Set to 0.
	 */
	raidvol->m_raidsize = 0;
	raidvol->m_settings = volsetting;
	raidvol->m_raidlevel = voltype;

	if (statusflags & MPI2_RAIDVOL0_STATUS_FLAG_QUIESCED) {
		mptsas_log(mpt, CE_NOTE, "?Volume %d is quiesced\n",
		    raidvol->m_raidhandle);
	}

	if (statusflags &
	    MPI2_RAIDVOL0_STATUS_FLAG_RESYNC_IN_PROGRESS) {
		mptsas_log(mpt, CE_NOTE, "?Volume %d is resyncing\n",
		    raidvol->m_raidhandle);
	}

	resync_flag = MPI2_RAIDVOL0_STATUS_FLAG_RESYNC_IN_PROGRESS;
	switch (volstate) {
	case MPI2_RAID_VOL_STATE_OPTIMAL:
		mptsas_log(mpt, CE_NOTE, "?Volume %d is "
		    "optimal\n", raidvol->m_raidhandle);
		break;
	case MPI2_RAID_VOL_STATE_DEGRADED:
		if ((statusflags & resync_flag) == 0) {
			mptsas_log(mpt, CE_WARN, "Volume %d "
			    "is degraded\n",
			    raidvol->m_raidhandle);
		}
		break;
	case MPI2_RAID_VOL_STATE_FAILED:
		mptsas_log(mpt, CE_WARN, "Volume %d is "
		    "failed\n", raidvol->m_raidhandle);
		break;
	case MPI2_RAID_VOL_STATE_MISSING:
		mptsas_log(mpt, CE_WARN, "Volume %d is "
		    "missing\n", raidvol->m_raidhandle);
		break;
	default:
		break;
	}
	numdisks = raidpage->NumPhysDisks;
	raidvol->m_ndisks = numdisks;
	for (i = 0; i < numdisks; i++) {
		physdisknum = raidpage->PhysDisk[i].PhysDiskNum;
		raidvol->m_disknum[i] = physdisknum;
		if (mptsas_get_physdisk_settings(mpt, raidvol,
		    physdisknum))
			break;
	}
	return (rval);
}

int
mptsas_get_raid_settings(mptsas_t *mpt, mptsas_raidvol_t *raidvol)
{
	int rval = DDI_SUCCESS;
	uint32_t page_address;

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Get the header and config page.  reply contains the reply frame,
	 * which holds status info for the request.
	 */
	page_address = (MPI2_RAID_VOLUME_PGAD_FORM_MASK &
	    MPI2_RAID_VOLUME_PGAD_FORM_HANDLE) | raidvol->m_raidhandle;
	rval = mptsas_access_config_page(mpt,
	    MPI2_CONFIG_ACTION_PAGE_READ_CURRENT,
	    MPI2_CONFIG_PAGETYPE_RAID_VOLUME, 0, page_address,
	    mptsas_raidvol_page_0_cb, raidvol);

	return (rval);
}

static int
mptsas_raidvol_page_1_cb(mptsas_t *mpt, caddr_t page_memp,
    ddi_acc_handle_t accessp, uint16_t iocstatus, uint32_t iocloginfo,
    va_list ap)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(ap))
#endif
	pMpi2RaidVolPage1_t	raidpage;
	int			rval = DDI_SUCCESS, i;
	uint8_t			*sas_addr = NULL;
	uint8_t			tmp_sas_wwn[SAS_WWN_BYTE_SIZE];
	uint64_t		*sas_wwn;

	if (iocstatus != MPI2_IOCSTATUS_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "mptsas_raidvol_page_1_cb "
		    "config: IOCStatus=0x%x, IOCLogInfo=0x%x",
		    iocstatus, iocloginfo);
		rval = DDI_FAILURE;
		return (rval);
	}
	sas_wwn = va_arg(ap, uint64_t *);

	raidpage = (pMpi2RaidVolPage1_t)page_memp;
	sas_addr = (uint8_t *)(&raidpage->WWID);
	for (i = 0; i < SAS_WWN_BYTE_SIZE; i++) {
		tmp_sas_wwn[i] = ddi_get8(accessp, sas_addr + i);
	}
	bcopy(tmp_sas_wwn, sas_wwn, SAS_WWN_BYTE_SIZE);
	*sas_wwn = LE_64(*sas_wwn);
	return (rval);
}

static int
mptsas_get_raid_wwid(mptsas_t *mpt, mptsas_raidvol_t *raidvol)
{
	int rval = DDI_SUCCESS;
	uint32_t page_address;
	uint64_t sas_wwn;

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Get the header and config page.  reply contains the reply frame,
	 * which holds status info for the request.
	 */
	page_address = (MPI2_RAID_VOLUME_PGAD_FORM_MASK &
	    MPI2_RAID_VOLUME_PGAD_FORM_HANDLE) | raidvol->m_raidhandle;
	rval = mptsas_access_config_page(mpt,
	    MPI2_CONFIG_ACTION_PAGE_READ_CURRENT,
	    MPI2_CONFIG_PAGETYPE_RAID_VOLUME, 1, page_address,
	    mptsas_raidvol_page_1_cb, &sas_wwn);

	/*
	 * Get the required information from the page.
	 */
	if (rval == DDI_SUCCESS) {

		/*
		 * replace top nibble of WWID of RAID to '3' for OBP
		 */
		sas_wwn = MPTSAS_RAID_WWID(sas_wwn);
		raidvol->m_raidwwid = sas_wwn;
	}

done:
	return (rval);
}

static int
mptsas_raidphydsk_page_0_cb(mptsas_t *mpt, caddr_t page_memp,
    ddi_acc_handle_t accessp, uint16_t iocstatus, uint32_t iocloginfo,
    va_list ap)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(ap))
#endif
	pMpi2RaidPhysDiskPage0_t	diskpage;
	int			rval = DDI_SUCCESS;
	uint16_t		*devhdl;
	uint8_t			*state;

	if (iocstatus == MPI2_IOCSTATUS_CONFIG_INVALID_PAGE)
		return (DDI_FAILURE);

	if (iocstatus != MPI2_IOCSTATUS_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "mptsas_raidphydsk_page0_cb "
		    "config: IOCStatus=0x%x, IOCLogInfo=0x%x",
		    iocstatus, iocloginfo);
		rval = DDI_FAILURE;
		return (rval);
	}
	devhdl = va_arg(ap, uint16_t *);
	state = va_arg(ap, uint8_t *);
	diskpage = (pMpi2RaidPhysDiskPage0_t)page_memp;
	*devhdl = ddi_get16(accessp, &diskpage->DevHandle);
	*state = ddi_get8(accessp, &diskpage->PhysDiskState);
	return (rval);
}

int
mptsas_get_physdisk_settings(mptsas_t *mpt, mptsas_raidvol_t *raidvol,
    uint8_t physdisknum)
{
	int			rval = DDI_SUCCESS, i;
	uint8_t			state;
	uint16_t		devhdl;
	uint32_t		page_address;

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Get the header and config page.  reply contains the reply frame,
	 * which holds status info for the request.
	 */
	page_address = (MPI2_PHYSDISK_PGAD_FORM_MASK &
	    MPI2_PHYSDISK_PGAD_FORM_PHYSDISKNUM) | physdisknum;
	rval = mptsas_access_config_page(mpt,
	    MPI2_CONFIG_ACTION_PAGE_READ_CURRENT,
	    MPI2_CONFIG_PAGETYPE_RAID_PHYSDISK, 0, page_address,
	    mptsas_raidphydsk_page_0_cb, &devhdl, &state);

	/*
	 * Get the required information from the page.
	 */
	if (rval == DDI_SUCCESS) {
		for (i = 0; i < MPTSAS_MAX_DISKS_IN_VOL; i++) {
			/* find the correct position in the arrays */
			if (raidvol->m_disknum[i] == physdisknum)
				break;
		}
		raidvol->m_devhdl[i] = devhdl;

		switch (state) {
			case MPI2_RAID_PD_STATE_OFFLINE:
				raidvol->m_diskstatus[i] =
				    RAID_DISKSTATUS_FAILED;
				break;

			case MPI2_RAID_PD_STATE_HOT_SPARE:
			case MPI2_RAID_PD_STATE_NOT_CONFIGURED:
			case MPI2_RAID_PD_STATE_NOT_COMPATIBLE:
				break;

			case MPI2_RAID_PD_STATE_DEGRADED:
			case MPI2_RAID_PD_STATE_OPTIMAL:
			case MPI2_RAID_PD_STATE_REBUILDING:
			case MPI2_RAID_PD_STATE_ONLINE:
			default:
				raidvol->m_diskstatus[i] =
				    RAID_DISKSTATUS_GOOD;
				break;
		}
	}

	return (rval);
}

/*
 * RAID Action for System Shutdown. This request uses the dedicated TM slot to
 * avoid a call to mptsas_save_cmd.  Since Solaris requires that the mutex is
 * not held during the mptsas_quiesce function, this RAID action must not use
 * the normal code path of requests and replies.
 */
void
mptsas_raid_action_system_shutdown(mptsas_t *mpt)
{
	pMpi2RaidActionRequest_t	action;
	uint8_t				ir_active = FALSE, reply_type;
	uint8_t				function, found_reply = FALSE;
	uint16_t			SMID, action_type;
	mptsas_slots_t			*slots = mpt->m_active;
	int				config, vol;
	mptsas_cmd_t			*cmd;
	uint32_t			request_desc_low, reply_addr;
	int				cnt;
	pMpi2ReplyDescriptorsUnion_t	reply_desc_union;
	pMPI2DefaultReply_t		reply;
	pMpi2AddressReplyDescriptor_t	address_reply;

	/*
	 * Before doing the system shutdown RAID Action, make sure that the IOC
	 * supports IR and make sure there is a valid volume for the request.
	 */
	if (mpt->m_ir_capable) {
		for (config = 0; (config < mpt->m_num_raid_configs) &&
		    (!ir_active); config++) {
			for (vol = 0; vol < MPTSAS_MAX_RAIDVOLS; vol++) {
				if (mpt->m_raidconfig[config].m_raidvol[vol].
				    m_israid) {
					ir_active = TRUE;
					break;
				}
			}
		}
	}
	if (!ir_active) {
		return;
	}

	/*
	 * If TM slot is already being used (highly unlikely), show message and
	 * don't issue the RAID action.
	 */
	if (slots->m_slot[MPTSAS_TM_SLOT(mpt)] != NULL) {
		mptsas_log(mpt, CE_WARN, "RAID Action slot in use.  Cancelling"
		    " System Shutdown RAID Action.\n");
		return;
	}

	/*
	 * Create the cmd and put it in the dedicated TM slot.
	 */
	cmd = &(mpt->m_event_task_mgmt.m_event_cmd);
	bzero((caddr_t)cmd, sizeof (*cmd));
	cmd->cmd_pkt = NULL;
	cmd->cmd_slot = MPTSAS_TM_SLOT(mpt);
	slots->m_slot[MPTSAS_TM_SLOT(mpt)] = cmd;

	/*
	 * Form message for raid action.
	 */
	action = (pMpi2RaidActionRequest_t)(mpt->m_req_frame +
	    (mpt->m_req_frame_size * cmd->cmd_slot));
	bzero(action, mpt->m_req_frame_size);
	action->Function = MPI2_FUNCTION_RAID_ACTION;
	action->Action = MPI2_RAID_ACTION_SYSTEM_SHUTDOWN_INITIATED;

	/*
	 * Send RAID Action.
	 */
	(void) ddi_dma_sync(mpt->m_dma_req_frame_hdl, 0, 0,
	    DDI_DMA_SYNC_FORDEV);
	request_desc_low = (cmd->cmd_slot << 16) +
	    MPI2_REQ_DESCRIPT_FLAGS_DEFAULT_TYPE;
	MPTSAS_START_CMD(mpt, request_desc_low, 0);

	/*
	 * Even though reply does not matter because the system is shutting
	 * down, wait no more than 5 seconds here to get the reply just because
	 * we don't want to leave it hanging if it's coming.  Poll because
	 * interrupts are disabled when this function is called.
	 */
	for (cnt = 0; cnt < 5000; cnt++) {
		/*
		 * Check for a reply.
		 */
		(void) ddi_dma_sync(mpt->m_dma_post_queue_hdl, 0, 0,
		    DDI_DMA_SYNC_FORCPU);

		reply_desc_union = (pMpi2ReplyDescriptorsUnion_t)
		    MPTSAS_GET_NEXT_REPLY(mpt, mpt->m_post_index);

		if (ddi_get32(mpt->m_acc_post_queue_hdl,
		    &reply_desc_union->Words.Low) == 0xFFFFFFFF ||
		    ddi_get32(mpt->m_acc_post_queue_hdl,
		    &reply_desc_union->Words.High) == 0xFFFFFFFF) {
			drv_usecwait(1000);
			continue;
		}

		/*
		 * There is a reply.  If it's not an address reply, ignore it.
		 */
		reply_type = ddi_get8(mpt->m_acc_post_queue_hdl,
		    &reply_desc_union->Default.ReplyFlags);
		reply_type &= MPI2_RPY_DESCRIPT_FLAGS_TYPE_MASK;
		if (reply_type != MPI2_RPY_DESCRIPT_FLAGS_ADDRESS_REPLY) {
			goto clear_and_continue;
		}

		/*
		 * SMID must be the TM slot since that's what we're using for
		 * this RAID action.  If not, ignore this reply.
		 */
		address_reply =
		    (pMpi2AddressReplyDescriptor_t)reply_desc_union;
		SMID = ddi_get16(mpt->m_acc_post_queue_hdl,
		    &address_reply->SMID);
		if (SMID != MPTSAS_TM_SLOT(mpt)) {
			goto clear_and_continue;
		}

		/*
		 * If reply frame is not in the proper range ignore it.
		 */
		reply_addr = ddi_get32(mpt->m_acc_post_queue_hdl,
		    &address_reply->ReplyFrameAddress);
		if ((reply_addr < mpt->m_reply_frame_dma_addr) ||
		    (reply_addr >= (mpt->m_reply_frame_dma_addr +
		    (mpt->m_reply_frame_size * mpt->m_free_queue_depth))) ||
		    ((reply_addr - mpt->m_reply_frame_dma_addr) %
		    mpt->m_reply_frame_size != 0)) {
			goto clear_and_continue;
		}

		/*
		 * If not a RAID action reply ignore it.
		 */
		(void) ddi_dma_sync(mpt->m_dma_reply_frame_hdl, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
		reply = (pMPI2DefaultReply_t)(mpt->m_reply_frame +
		    (reply_addr - mpt->m_reply_frame_dma_addr));
		function = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &reply->Function);
		if (function != MPI2_FUNCTION_RAID_ACTION) {
			goto clear_and_continue;
		}

		/*
		 * Finally, make sure this is the System Shutdown RAID action.
		 * If not, ignore reply.
		 */
		action_type = ddi_get16(mpt->m_acc_reply_frame_hdl,
		    &reply->FunctionDependent1);
		if (action_type !=
		    MPI2_RAID_ACTION_SYSTEM_SHUTDOWN_INITIATED) {
			goto clear_and_continue;
		}
		found_reply = TRUE;

clear_and_continue:
		/*
		 * Clear the reply descriptor for re-use and increment index.
		 */
		ddi_put64(mpt->m_acc_post_queue_hdl,
		    &((uint64_t *)(void *)mpt->m_post_queue)[mpt->m_post_index],
		    0xFFFFFFFFFFFFFFFF);
		(void) ddi_dma_sync(mpt->m_dma_post_queue_hdl, 0, 0,
		    DDI_DMA_SYNC_FORDEV);

		/*
		 * Update the global reply index and keep looking for the
		 * reply if not found yet.
		 */
		if (++mpt->m_post_index == mpt->m_post_queue_depth) {
			mpt->m_post_index = 0;
		}
		ddi_put32(mpt->m_datap, &mpt->m_reg->ReplyPostHostIndex,
		    mpt->m_post_index);
		if (!found_reply) {
			continue;
		}

		break;
	}

	/*
	 * clear the used slot as the last step.
	 */
	slots->m_slot[MPTSAS_TM_SLOT(mpt)] = NULL;
}

int
mptsas_delete_volume(mptsas_t *mpt, uint16_t volid)
{
	int		config, i = 0, vol = (-1);

	for (config = 0; (config < mpt->m_num_raid_configs) && (vol != i);
	    config++) {
		for (i = 0; i < MPTSAS_MAX_RAIDVOLS; i++) {
			if (mpt->m_raidconfig[config].m_raidvol[i].
			    m_raidhandle == volid) {
				vol = i;
				break;
			}
		}
	}

	if (vol < 0) {
		mptsas_log(mpt, CE_WARN, "raid doesn't exist at specified "
		    "target.");
		return (-1);
	}

	mpt->m_raidconfig[config].m_raidvol[vol].m_israid = 0;
	mpt->m_raidconfig[config].m_raidvol[vol].m_ndisks = 0;
	for (i = 0; i < MPTSAS_MAX_DISKS_IN_VOL; i++) {
		mpt->m_raidconfig[config].m_raidvol[vol].m_disknum[i] = 0;
		mpt->m_raidconfig[config].m_raidvol[vol].m_devhdl[i] = 0;
	}

	return (0);
}
