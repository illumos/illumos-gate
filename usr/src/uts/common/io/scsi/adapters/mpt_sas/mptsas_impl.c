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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2014 OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright (c) 2014, Tegile Systems Inc. All rights reserved.
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
 * mptsas_impl - This file contains all the basic functions for communicating
 * to MPT based hardware.
 */

#if defined(lint) || defined(DEBUG)
#define	MPTSAS_DEBUG
#endif

/*
 * standard header files
 */
#include <sys/note.h>
#include <sys/scsi/scsi.h>
#include <sys/pci.h>

#pragma pack(1)
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_type.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_cnfg.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_init.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_ioc.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_sas.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_tool.h>
#pragma pack()

/*
 * private header files.
 */
#include <sys/scsi/adapters/mpt_sas/mptsas_var.h>
#include <sys/scsi/adapters/mpt_sas/mptsas_smhba.h>

/*
 * FMA header files.
 */
#include <sys/fm/io/ddi.h>

/*
 *  prototypes
 */
static void mptsas_ioc_event_cmdq_add(mptsas_t *mpt, m_event_struct_t *cmd);
static void mptsas_ioc_event_cmdq_delete(mptsas_t *mpt, m_event_struct_t *cmd);
static m_event_struct_t *mptsas_ioc_event_find_by_cmd(mptsas_t *mpt,
    struct mptsas_cmd *cmd);

/*
 * add ioc evnet cmd into the queue
 */
static void
mptsas_ioc_event_cmdq_add(mptsas_t *mpt, m_event_struct_t *cmd)
{
	if ((cmd->m_event_linkp = mpt->m_ioc_event_cmdq) == NULL) {
		mpt->m_ioc_event_cmdtail = &cmd->m_event_linkp;
		mpt->m_ioc_event_cmdq = cmd;
	} else {
		cmd->m_event_linkp = NULL;
		*(mpt->m_ioc_event_cmdtail) = cmd;
		mpt->m_ioc_event_cmdtail = &cmd->m_event_linkp;
	}
}

/*
 * remove specified cmd from the ioc event queue
 */
static void
mptsas_ioc_event_cmdq_delete(mptsas_t *mpt, m_event_struct_t *cmd)
{
	m_event_struct_t	*prev = mpt->m_ioc_event_cmdq;
	if (prev == cmd) {
		if ((mpt->m_ioc_event_cmdq = cmd->m_event_linkp) == NULL) {
			mpt->m_ioc_event_cmdtail = &mpt->m_ioc_event_cmdq;
		}
		cmd->m_event_linkp = NULL;
		return;
	}
	while (prev != NULL) {
		if (prev->m_event_linkp == cmd) {
			prev->m_event_linkp = cmd->m_event_linkp;
			if (cmd->m_event_linkp == NULL) {
				mpt->m_ioc_event_cmdtail = &prev->m_event_linkp;
			}

			cmd->m_event_linkp = NULL;
			return;
		}
		prev = prev->m_event_linkp;
	}
}

static m_event_struct_t *
mptsas_ioc_event_find_by_cmd(mptsas_t *mpt, struct mptsas_cmd *cmd)
{
	m_event_struct_t	*ioc_cmd = NULL;

	ioc_cmd = mpt->m_ioc_event_cmdq;
	while (ioc_cmd != NULL) {
		if (&(ioc_cmd->m_event_cmd) == cmd) {
			return (ioc_cmd);
		}
		ioc_cmd = ioc_cmd->m_event_linkp;
	}
	ioc_cmd = NULL;
	return (ioc_cmd);
}

void
mptsas_destroy_ioc_event_cmd(mptsas_t *mpt)
{
	m_event_struct_t	*ioc_cmd = NULL;
	m_event_struct_t	*ioc_cmd_tmp = NULL;
	ioc_cmd = mpt->m_ioc_event_cmdq;

	/*
	 * because the IOC event queue is resource of per instance for driver,
	 * it's not only ACK event commands used it, but also some others used
	 * it. We need destroy all ACK event commands when IOC reset, but can't
	 * disturb others.So we use filter to clear the ACK event cmd in ioc
	 * event queue, and other requests should be reserved, and they would
	 * be free by its owner.
	 */
	while (ioc_cmd != NULL) {
		if (ioc_cmd->m_event_cmd.cmd_flags & CFLAG_CMDACK) {
			NDBG20(("destroy!! remove Ack Flag ioc_cmd\n"));
			if ((mpt->m_ioc_event_cmdq =
			    ioc_cmd->m_event_linkp) == NULL)
				mpt->m_ioc_event_cmdtail =
				    &mpt->m_ioc_event_cmdq;
			ioc_cmd_tmp = ioc_cmd;
			ioc_cmd = ioc_cmd->m_event_linkp;
			kmem_free(ioc_cmd_tmp, M_EVENT_STRUCT_SIZE);
		} else {
			/*
			 * it's not ack cmd, so continue to check next one
			 */

			NDBG20(("destroy!! it's not Ack Flag, continue\n"));
			ioc_cmd = ioc_cmd->m_event_linkp;
		}

	}
}

void
mptsas_start_config_page_access(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	pMpi2ConfigRequest_t	request;
	pMpi2SGESimple64_t	sge;
	struct scsi_pkt		*pkt = cmd->cmd_pkt;
	mptsas_config_request_t	*config = pkt->pkt_ha_private;
	uint8_t			direction;
	uint32_t		length, flagslength;
	uint64_t		request_desc;

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Point to the correct message and clear it as well as the global
	 * config page memory.
	 */
	request = (pMpi2ConfigRequest_t)(mpt->m_req_frame +
	    (mpt->m_req_frame_size * cmd->cmd_slot));
	bzero(request, mpt->m_req_frame_size);

	/*
	 * Form the request message.
	 */
	ddi_put8(mpt->m_acc_req_frame_hdl, &request->Function,
	    MPI2_FUNCTION_CONFIG);
	ddi_put8(mpt->m_acc_req_frame_hdl, &request->Action, config->action);
	direction = MPI2_SGE_FLAGS_IOC_TO_HOST;
	length = 0;
	sge = (pMpi2SGESimple64_t)&request->PageBufferSGE;
	if (config->action == MPI2_CONFIG_ACTION_PAGE_HEADER) {
		if (config->page_type > MPI2_CONFIG_PAGETYPE_MASK) {
			ddi_put8(mpt->m_acc_req_frame_hdl,
			    &request->Header.PageType,
			    MPI2_CONFIG_PAGETYPE_EXTENDED);
			ddi_put8(mpt->m_acc_req_frame_hdl,
			    &request->ExtPageType, config->page_type);
		} else {
			ddi_put8(mpt->m_acc_req_frame_hdl,
			    &request->Header.PageType, config->page_type);
		}
	} else {
		ddi_put8(mpt->m_acc_req_frame_hdl, &request->ExtPageType,
		    config->ext_page_type);
		ddi_put16(mpt->m_acc_req_frame_hdl, &request->ExtPageLength,
		    config->ext_page_length);
		ddi_put8(mpt->m_acc_req_frame_hdl, &request->Header.PageType,
		    config->page_type);
		ddi_put8(mpt->m_acc_req_frame_hdl, &request->Header.PageLength,
		    config->page_length);
		ddi_put8(mpt->m_acc_req_frame_hdl,
		    &request->Header.PageVersion, config->page_version);
		if ((config->page_type & MPI2_CONFIG_PAGETYPE_MASK) ==
		    MPI2_CONFIG_PAGETYPE_EXTENDED) {
			length = config->ext_page_length * 4;
		} else {
			length = config->page_length * 4;
		}

		if (config->action == MPI2_CONFIG_ACTION_PAGE_WRITE_NVRAM) {
			direction = MPI2_SGE_FLAGS_HOST_TO_IOC;
		}
		ddi_put32(mpt->m_acc_req_frame_hdl, &sge->Address.Low,
		    (uint32_t)cmd->cmd_dma_addr);
		ddi_put32(mpt->m_acc_req_frame_hdl, &sge->Address.High,
		    (uint32_t)(cmd->cmd_dma_addr >> 32));
	}
	ddi_put8(mpt->m_acc_req_frame_hdl, &request->Header.PageNumber,
	    config->page_number);
	ddi_put32(mpt->m_acc_req_frame_hdl, &request->PageAddress,
	    config->page_address);
	flagslength = ((uint32_t)(MPI2_SGE_FLAGS_LAST_ELEMENT |
	    MPI2_SGE_FLAGS_END_OF_BUFFER |
	    MPI2_SGE_FLAGS_SIMPLE_ELEMENT |
	    MPI2_SGE_FLAGS_SYSTEM_ADDRESS |
	    MPI2_SGE_FLAGS_64_BIT_ADDRESSING |
	    direction |
	    MPI2_SGE_FLAGS_END_OF_LIST) << MPI2_SGE_FLAGS_SHIFT);
	flagslength |= length;
	ddi_put32(mpt->m_acc_req_frame_hdl, &sge->FlagsLength, flagslength);

	(void) ddi_dma_sync(mpt->m_dma_req_frame_hdl, 0, 0,
	    DDI_DMA_SYNC_FORDEV);
	request_desc = (cmd->cmd_slot << 16) +
	    MPI2_REQ_DESCRIPT_FLAGS_DEFAULT_TYPE;
	cmd->cmd_rfm = NULL;
	MPTSAS_START_CMD(mpt, request_desc);
	if ((mptsas_check_dma_handle(mpt->m_dma_req_frame_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_acc_req_frame_hdl) !=
	    DDI_SUCCESS)) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
	}
}

int
mptsas_access_config_page(mptsas_t *mpt, uint8_t action, uint8_t page_type,
    uint8_t page_number, uint32_t page_address, int (*callback) (mptsas_t *,
    caddr_t, ddi_acc_handle_t, uint16_t, uint32_t, va_list), ...)
{
	va_list			ap;
	ddi_dma_attr_t		attrs;
	ddi_dma_cookie_t	cookie;
	ddi_acc_handle_t	accessp;
	size_t			len = 0;
	mptsas_config_request_t	config;
	int			rval = DDI_SUCCESS, config_flags = 0;
	mptsas_cmd_t		*cmd;
	struct scsi_pkt		*pkt;
	pMpi2ConfigReply_t	reply;
	uint16_t		iocstatus = 0;
	uint32_t		iocloginfo;
	caddr_t			page_memp;
	boolean_t		free_dma = B_FALSE;

	va_start(ap, callback);
	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Get a command from the pool.
	 */
	if ((rval = (mptsas_request_from_pool(mpt, &cmd, &pkt))) == -1) {
		mptsas_log(mpt, CE_NOTE, "command pool is full for config "
		    "page request");
		rval = DDI_FAILURE;
		goto page_done;
	}
	config_flags |= MPTSAS_REQUEST_POOL_CMD;

	bzero((caddr_t)cmd, sizeof (*cmd));
	bzero((caddr_t)pkt, scsi_pkt_size());
	bzero((caddr_t)&config, sizeof (config));

	/*
	 * Save the data for this request to be used in the call to start the
	 * config header request.
	 */
	config.action = MPI2_CONFIG_ACTION_PAGE_HEADER;
	config.page_type = page_type;
	config.page_number = page_number;
	config.page_address = page_address;

	/*
	 * Form a blank cmd/pkt to store the acknowledgement message
	 */
	pkt->pkt_ha_private	= (opaque_t)&config;
	pkt->pkt_flags		= FLAG_HEAD;
	pkt->pkt_time		= 60;
	cmd->cmd_pkt		= pkt;
	cmd->cmd_flags		= CFLAG_CMDIOC | CFLAG_CONFIG;

	/*
	 * Save the config header request message in a slot.
	 */
	if (mptsas_save_cmd(mpt, cmd) == TRUE) {
		cmd->cmd_flags |= CFLAG_PREPARED;
		mptsas_start_config_page_access(mpt, cmd);
	} else {
		mptsas_waitq_add(mpt, cmd);
	}

	/*
	 * If this is a request for a RAID info page, or any page called during
	 * the RAID info page request, poll because these config page requests
	 * are nested.  Poll to avoid data corruption due to one page's data
	 * overwriting the outer page request's data.  This can happen when
	 * the mutex is released in cv_wait.
	 */
	if ((page_type == MPI2_CONFIG_EXTPAGETYPE_RAID_CONFIG) ||
	    (page_type == MPI2_CONFIG_PAGETYPE_RAID_VOLUME) ||
	    (page_type == MPI2_CONFIG_PAGETYPE_RAID_PHYSDISK)) {
		(void) mptsas_poll(mpt, cmd, pkt->pkt_time * 1000);
	} else {
		while ((cmd->cmd_flags & CFLAG_FINISHED) == 0) {
			cv_wait(&mpt->m_config_cv, &mpt->m_mutex);
		}
	}

	/*
	 * Check if the header request completed without timing out
	 */
	if (cmd->cmd_flags & CFLAG_TIMEOUT) {
		mptsas_log(mpt, CE_WARN, "config header request timeout");
		rval = DDI_FAILURE;
		goto page_done;
	}

	/*
	 * cmd_rfm points to the reply message if a reply was given.  Check the
	 * IOCStatus to make sure everything went OK with the header request.
	 */
	if (cmd->cmd_rfm) {
		config_flags |= MPTSAS_ADDRESS_REPLY;
		(void) ddi_dma_sync(mpt->m_dma_reply_frame_hdl, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
		reply = (pMpi2ConfigReply_t)(mpt->m_reply_frame + (cmd->cmd_rfm
		    - (mpt->m_reply_frame_dma_addr & 0xffffffffu)));
		config.page_type = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &reply->Header.PageType);
		config.page_number = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &reply->Header.PageNumber);
		config.page_length = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &reply->Header.PageLength);
		config.page_version = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &reply->Header.PageVersion);
		config.ext_page_type = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &reply->ExtPageType);
		config.ext_page_length = ddi_get16(mpt->m_acc_reply_frame_hdl,
		    &reply->ExtPageLength);

		iocstatus = ddi_get16(mpt->m_acc_reply_frame_hdl,
		    &reply->IOCStatus);
		iocloginfo = ddi_get32(mpt->m_acc_reply_frame_hdl,
		    &reply->IOCLogInfo);

		if (iocstatus) {
			NDBG13(("mptsas_access_config_page header: "
			    "IOCStatus=0x%x, IOCLogInfo=0x%x", iocstatus,
			    iocloginfo));
			rval = DDI_FAILURE;
			goto page_done;
		}

		if ((config.page_type & MPI2_CONFIG_PAGETYPE_MASK) ==
		    MPI2_CONFIG_PAGETYPE_EXTENDED)
			len = (config.ext_page_length * 4);
		else
			len = (config.page_length * 4);

	}

	if (pkt->pkt_reason == CMD_RESET) {
		mptsas_log(mpt, CE_WARN, "ioc reset abort config header "
		    "request");
		rval = DDI_FAILURE;
		goto page_done;
	}

	/*
	 * Put the reply frame back on the free queue, increment the free
	 * index, and write the new index to the free index register.  But only
	 * if this reply is an ADDRESS reply.
	 */
	if (config_flags & MPTSAS_ADDRESS_REPLY) {
		ddi_put32(mpt->m_acc_free_queue_hdl,
		    &((uint32_t *)(void *)mpt->m_free_queue)[mpt->m_free_index],
		    cmd->cmd_rfm);
		(void) ddi_dma_sync(mpt->m_dma_free_queue_hdl, 0, 0,
		    DDI_DMA_SYNC_FORDEV);
		if (++mpt->m_free_index == mpt->m_free_queue_depth) {
			mpt->m_free_index = 0;
		}
		ddi_put32(mpt->m_datap, &mpt->m_reg->ReplyFreeHostIndex,
		    mpt->m_free_index);
		config_flags &= (~MPTSAS_ADDRESS_REPLY);
	}

	/*
	 * Allocate DMA buffer here.  Store the info regarding this buffer in
	 * the cmd struct so that it can be used for this specific command and
	 * de-allocated after the command completes.  The size of the reply
	 * will not be larger than the reply frame size.
	 */
	attrs = mpt->m_msg_dma_attr;
	attrs.dma_attr_sgllen = 1;
	attrs.dma_attr_granular = (uint32_t)len;

	if (mptsas_dma_addr_create(mpt, attrs,
	    &cmd->cmd_dmahandle, &accessp, &page_memp,
	    len, &cookie) == FALSE) {
		rval = DDI_FAILURE;
		mptsas_log(mpt, CE_WARN,
		    "mptsas_dma_addr_create(len=0x%x) failed", (int)len);
		goto page_done;
	}
	/* NOW we can safely call mptsas_dma_addr_destroy(). */
	free_dma = B_TRUE;

	cmd->cmd_dma_addr = cookie.dmac_laddress;
	bzero(page_memp, len);

	/*
	 * Save the data for this request to be used in the call to start the
	 * config page read
	 */
	config.action = action;
	config.page_address = page_address;

	/*
	 * Re-use the cmd that was used to get the header.  Reset some of the
	 * values.
	 */
	bzero((caddr_t)pkt, scsi_pkt_size());
	pkt->pkt_ha_private	= (opaque_t)&config;
	pkt->pkt_flags		= FLAG_HEAD;
	pkt->pkt_time		= 60;
	cmd->cmd_flags		= CFLAG_PREPARED | CFLAG_CMDIOC | CFLAG_CONFIG;

	/*
	 * Send the config page request.  cmd is re-used from header request.
	 */
	mptsas_start_config_page_access(mpt, cmd);

	/*
	 * If this is a request for a RAID info page, or any page called during
	 * the RAID info page request, poll because these config page requests
	 * are nested.  Poll to avoid data corruption due to one page's data
	 * overwriting the outer page request's data.  This can happen when
	 * the mutex is released in cv_wait.
	 */
	if ((page_type == MPI2_CONFIG_EXTPAGETYPE_RAID_CONFIG) ||
	    (page_type == MPI2_CONFIG_PAGETYPE_RAID_VOLUME) ||
	    (page_type == MPI2_CONFIG_PAGETYPE_RAID_PHYSDISK)) {
		(void) mptsas_poll(mpt, cmd, pkt->pkt_time * 1000);
	} else {
		while ((cmd->cmd_flags & CFLAG_FINISHED) == 0) {
			cv_wait(&mpt->m_config_cv, &mpt->m_mutex);
		}
	}

	/*
	 * Check if the request completed without timing out
	 */
	if (cmd->cmd_flags & CFLAG_TIMEOUT) {
		mptsas_log(mpt, CE_WARN, "config page request timeout");
		rval = DDI_FAILURE;
		goto page_done;
	}

	/*
	 * cmd_rfm points to the reply message if a reply was given.  The reply
	 * frame and the config page are returned from this function in the
	 * param list.
	 */
	if (cmd->cmd_rfm) {
		config_flags |= MPTSAS_ADDRESS_REPLY;
		(void) ddi_dma_sync(mpt->m_dma_reply_frame_hdl, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
		(void) ddi_dma_sync(cmd->cmd_dmahandle, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
		reply = (pMpi2ConfigReply_t)(mpt->m_reply_frame + (cmd->cmd_rfm
		    - (mpt->m_reply_frame_dma_addr & 0xffffffffu)));
		iocstatus = ddi_get16(mpt->m_acc_reply_frame_hdl,
		    &reply->IOCStatus);
		iocstatus = MPTSAS_IOCSTATUS(iocstatus);
		iocloginfo = ddi_get32(mpt->m_acc_reply_frame_hdl,
		    &reply->IOCLogInfo);
	}

	if (callback(mpt, page_memp, accessp, iocstatus, iocloginfo, ap)) {
		rval = DDI_FAILURE;
		goto page_done;
	}

	mptsas_fma_check(mpt, cmd);
	/*
	 * Check the DMA/ACC handles and then free the DMA buffer.
	 */
	if ((mptsas_check_dma_handle(cmd->cmd_dmahandle) != DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(accessp) != DDI_SUCCESS)) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		rval = DDI_FAILURE;
	}

	if (pkt->pkt_reason == CMD_TRAN_ERR) {
		mptsas_log(mpt, CE_WARN, "config fma error");
		rval = DDI_FAILURE;
		goto page_done;
	}
	if (pkt->pkt_reason == CMD_RESET) {
		mptsas_log(mpt, CE_WARN, "ioc reset abort config request");
		rval = DDI_FAILURE;
		goto page_done;
	}

page_done:
	va_end(ap);
	/*
	 * Put the reply frame back on the free queue, increment the free
	 * index, and write the new index to the free index register.  But only
	 * if this reply is an ADDRESS reply.
	 */
	if (config_flags & MPTSAS_ADDRESS_REPLY) {
		ddi_put32(mpt->m_acc_free_queue_hdl,
		    &((uint32_t *)(void *)mpt->m_free_queue)[mpt->m_free_index],
		    cmd->cmd_rfm);
		(void) ddi_dma_sync(mpt->m_dma_free_queue_hdl, 0, 0,
		    DDI_DMA_SYNC_FORDEV);
		if (++mpt->m_free_index == mpt->m_free_queue_depth) {
			mpt->m_free_index = 0;
		}
		ddi_put32(mpt->m_datap, &mpt->m_reg->ReplyFreeHostIndex,
		    mpt->m_free_index);
	}

	if (free_dma)
		mptsas_dma_addr_destroy(&cmd->cmd_dmahandle, &accessp);

	if (cmd && (cmd->cmd_flags & CFLAG_PREPARED)) {
		mptsas_remove_cmd(mpt, cmd);
		config_flags &= (~MPTSAS_REQUEST_POOL_CMD);
	}
	if (config_flags & MPTSAS_REQUEST_POOL_CMD)
		mptsas_return_to_pool(mpt, cmd);

	if (config_flags & MPTSAS_CMD_TIMEOUT) {
		mpt->m_softstate &= ~MPTSAS_SS_MSG_UNIT_RESET;
		if ((mptsas_restart_ioc(mpt)) == DDI_FAILURE) {
			mptsas_log(mpt, CE_WARN, "mptsas_restart_ioc failed");
		}
	}

	return (rval);
}

int
mptsas_send_config_request_msg(mptsas_t *mpt, uint8_t action, uint8_t pagetype,
	uint32_t pageaddress, uint8_t pagenumber, uint8_t pageversion,
	uint8_t pagelength, uint32_t SGEflagslength, uint64_t SGEaddress)
{
	pMpi2ConfigRequest_t	config;
	int			send_numbytes;

	bzero(mpt->m_hshk_memp, sizeof (MPI2_CONFIG_REQUEST));
	config = (pMpi2ConfigRequest_t)mpt->m_hshk_memp;
	ddi_put8(mpt->m_hshk_acc_hdl, &config->Function, MPI2_FUNCTION_CONFIG);
	ddi_put8(mpt->m_hshk_acc_hdl, &config->Action, action);
	ddi_put8(mpt->m_hshk_acc_hdl, &config->Header.PageNumber, pagenumber);
	ddi_put8(mpt->m_hshk_acc_hdl, &config->Header.PageType, pagetype);
	ddi_put32(mpt->m_hshk_acc_hdl, &config->PageAddress, pageaddress);
	ddi_put8(mpt->m_hshk_acc_hdl, &config->Header.PageVersion, pageversion);
	ddi_put8(mpt->m_hshk_acc_hdl, &config->Header.PageLength, pagelength);
	ddi_put32(mpt->m_hshk_acc_hdl,
	    &config->PageBufferSGE.MpiSimple.FlagsLength, SGEflagslength);
	ddi_put32(mpt->m_hshk_acc_hdl,
	    &config->PageBufferSGE.MpiSimple.u.Address64.Low, SGEaddress);
	ddi_put32(mpt->m_hshk_acc_hdl,
	    &config->PageBufferSGE.MpiSimple.u.Address64.High,
	    SGEaddress >> 32);
	send_numbytes = sizeof (MPI2_CONFIG_REQUEST);

	/*
	 * Post message via handshake
	 */
	if (mptsas_send_handshake_msg(mpt, (caddr_t)config, send_numbytes,
	    mpt->m_hshk_acc_hdl)) {
		return (-1);
	}
	return (0);
}

int
mptsas_send_extended_config_request_msg(mptsas_t *mpt, uint8_t action,
	uint8_t extpagetype, uint32_t pageaddress, uint8_t pagenumber,
	uint8_t pageversion, uint16_t extpagelength,
	uint32_t SGEflagslength, uint64_t SGEaddress)
{
	pMpi2ConfigRequest_t	config;
	int			send_numbytes;

	bzero(mpt->m_hshk_memp, sizeof (MPI2_CONFIG_REQUEST));
	config = (pMpi2ConfigRequest_t)mpt->m_hshk_memp;
	ddi_put8(mpt->m_hshk_acc_hdl, &config->Function, MPI2_FUNCTION_CONFIG);
	ddi_put8(mpt->m_hshk_acc_hdl, &config->Action, action);
	ddi_put8(mpt->m_hshk_acc_hdl, &config->Header.PageNumber, pagenumber);
	ddi_put8(mpt->m_hshk_acc_hdl, &config->Header.PageType,
	    MPI2_CONFIG_PAGETYPE_EXTENDED);
	ddi_put8(mpt->m_hshk_acc_hdl, &config->ExtPageType, extpagetype);
	ddi_put32(mpt->m_hshk_acc_hdl, &config->PageAddress, pageaddress);
	ddi_put8(mpt->m_hshk_acc_hdl, &config->Header.PageVersion, pageversion);
	ddi_put16(mpt->m_hshk_acc_hdl, &config->ExtPageLength, extpagelength);
	ddi_put32(mpt->m_hshk_acc_hdl,
	    &config->PageBufferSGE.MpiSimple.FlagsLength, SGEflagslength);
	ddi_put32(mpt->m_hshk_acc_hdl,
	    &config->PageBufferSGE.MpiSimple.u.Address64.Low, SGEaddress);
	ddi_put32(mpt->m_hshk_acc_hdl,
	    &config->PageBufferSGE.MpiSimple.u.Address64.High,
	    SGEaddress >> 32);
	send_numbytes = sizeof (MPI2_CONFIG_REQUEST);

	/*
	 * Post message via handshake
	 */
	if (mptsas_send_handshake_msg(mpt, (caddr_t)config, send_numbytes,
	    mpt->m_hshk_acc_hdl)) {
		return (-1);
	}
	return (0);
}

int
mptsas_ioc_wait_for_response(mptsas_t *mpt)
{
	int	polls = 0;

	while ((ddi_get32(mpt->m_datap,
	    &mpt->m_reg->HostInterruptStatus) & MPI2_HIS_IOP_DOORBELL_STATUS)) {
		drv_usecwait(1000);
		if (polls++ > 60000) {
			return (-1);
		}
	}
	return (0);
}

int
mptsas_ioc_wait_for_doorbell(mptsas_t *mpt)
{
	int	polls = 0;

	while ((ddi_get32(mpt->m_datap,
	    &mpt->m_reg->HostInterruptStatus) & MPI2_HIM_DIM) == 0) {
		drv_usecwait(1000);
		if (polls++ > 300000) {
			return (-1);
		}
	}
	return (0);
}

int
mptsas_send_handshake_msg(mptsas_t *mpt, caddr_t memp, int numbytes,
	ddi_acc_handle_t accessp)
{
	int	i;

	/*
	 * clean pending doorbells
	 */
	ddi_put32(mpt->m_datap, &mpt->m_reg->HostInterruptStatus, 0);
	ddi_put32(mpt->m_datap, &mpt->m_reg->Doorbell,
	    ((MPI2_FUNCTION_HANDSHAKE << MPI2_DOORBELL_FUNCTION_SHIFT) |
	    ((numbytes / 4) << MPI2_DOORBELL_ADD_DWORDS_SHIFT)));

	if (mptsas_ioc_wait_for_doorbell(mpt)) {
		NDBG19(("mptsas_send_handshake failed.  Doorbell not ready\n"));
		return (-1);
	}

	/*
	 * clean pending doorbells again
	 */
	ddi_put32(mpt->m_datap, &mpt->m_reg->HostInterruptStatus, 0);

	if (mptsas_ioc_wait_for_response(mpt)) {
		NDBG19(("mptsas_send_handshake failed.  Doorbell not "
		    "cleared\n"));
		return (-1);
	}

	/*
	 * post handshake message
	 */
	for (i = 0; (i < numbytes / 4); i++, memp += 4) {
		ddi_put32(mpt->m_datap, &mpt->m_reg->Doorbell,
		    ddi_get32(accessp, (uint32_t *)((void *)(memp))));
		if (mptsas_ioc_wait_for_response(mpt)) {
			NDBG19(("mptsas_send_handshake failed posting "
			    "message\n"));
			return (-1);
		}
	}

	if (mptsas_check_acc_handle(mpt->m_datap) != DDI_SUCCESS) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		ddi_fm_acc_err_clear(mpt->m_datap, DDI_FME_VER0);
		return (-1);
	}

	return (0);
}

int
mptsas_get_handshake_msg(mptsas_t *mpt, caddr_t memp, int numbytes,
	ddi_acc_handle_t accessp)
{
	int		i, totalbytes, bytesleft;
	uint16_t	val;

	/*
	 * wait for doorbell
	 */
	if (mptsas_ioc_wait_for_doorbell(mpt)) {
		NDBG19(("mptsas_get_handshake failed.  Doorbell not ready\n"));
		return (-1);
	}

	/*
	 * get first 2 bytes of handshake message to determine how much
	 * data we will be getting
	 */
	for (i = 0; i < 2; i++, memp += 2) {
		val = (ddi_get32(mpt->m_datap,
		    &mpt->m_reg->Doorbell) & MPI2_DOORBELL_DATA_MASK);
		ddi_put32(mpt->m_datap, &mpt->m_reg->HostInterruptStatus, 0);
		if (mptsas_ioc_wait_for_doorbell(mpt)) {
			NDBG19(("mptsas_get_handshake failure getting initial"
			    " data\n"));
			return (-1);
		}
		ddi_put16(accessp, (uint16_t *)((void *)(memp)), val);
		if (i == 1) {
			totalbytes = (val & 0xFF) * 2;
		}
	}

	/*
	 * If we are expecting less bytes than the message wants to send
	 * we simply save as much as we expected and then throw out the rest
	 * later
	 */
	if (totalbytes > (numbytes / 2)) {
		bytesleft = ((numbytes / 2) - 2);
	} else {
		bytesleft = (totalbytes - 2);
	}

	/*
	 * Get the rest of the data
	 */
	for (i = 0; i < bytesleft; i++, memp += 2) {
		val = (ddi_get32(mpt->m_datap,
		    &mpt->m_reg->Doorbell) & MPI2_DOORBELL_DATA_MASK);
		ddi_put32(mpt->m_datap, &mpt->m_reg->HostInterruptStatus, 0);
		if (mptsas_ioc_wait_for_doorbell(mpt)) {
			NDBG19(("mptsas_get_handshake failure getting"
			    " main data\n"));
			return (-1);
		}
		ddi_put16(accessp, (uint16_t *)((void *)(memp)), val);
	}

	/*
	 * Sometimes the device will send more data than is expected
	 * This data is not used by us but needs to be cleared from
	 * ioc doorbell.  So we just read the values and throw
	 * them out.
	 */
	if (totalbytes > (numbytes / 2)) {
		for (i = (numbytes / 2); i < totalbytes; i++) {
			val = (ddi_get32(mpt->m_datap,
			    &mpt->m_reg->Doorbell) &
			    MPI2_DOORBELL_DATA_MASK);
			ddi_put32(mpt->m_datap,
			    &mpt->m_reg->HostInterruptStatus, 0);
			if (mptsas_ioc_wait_for_doorbell(mpt)) {
				NDBG19(("mptsas_get_handshake failure getting "
				    "extra garbage data\n"));
				return (-1);
			}
		}
	}

	ddi_put32(mpt->m_datap, &mpt->m_reg->HostInterruptStatus, 0);

	if (mptsas_check_acc_handle(mpt->m_datap) != DDI_SUCCESS) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		ddi_fm_acc_err_clear(mpt->m_datap, DDI_FME_VER0);
		return (-1);
	}

	return (0);
}

int
mptsas_kick_start(mptsas_t *mpt)
{
	int		polls = 0;
	uint32_t	diag_reg, ioc_state, saved_HCB_size;

	/*
	 * Start a hard reset.  Write magic number and wait 500 mSeconds.
	 */
	MPTSAS_ENABLE_DRWE(mpt);
	drv_usecwait(500000);

	/*
	 * Read the current Diag Reg and save the Host Controlled Boot size.
	 */
	diag_reg = ddi_get32(mpt->m_datap, &mpt->m_reg->HostDiagnostic);
	saved_HCB_size = ddi_get32(mpt->m_datap, &mpt->m_reg->HCBSize);

	/*
	 * Set Reset Adapter bit and wait 50 mSeconds.
	 */
	diag_reg |= MPI2_DIAG_RESET_ADAPTER;
	ddi_put32(mpt->m_datap, &mpt->m_reg->HostDiagnostic, diag_reg);
	drv_usecwait(50000);

	/*
	 * Poll, waiting for Reset Adapter bit to clear.  300 Seconds max
	 * (600000 * 500 = 300,000,000 uSeconds, 300 seconds).
	 * If no more adapter (all FF's), just return failure.
	 */
	for (polls = 0; polls < 600000; polls++) {
		diag_reg = ddi_get32(mpt->m_datap,
		    &mpt->m_reg->HostDiagnostic);
		if (diag_reg == 0xFFFFFFFF) {
			mptsas_fm_ereport(mpt, DDI_FM_DEVICE_NO_RESPONSE);
			ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_LOST);
			return (DDI_FAILURE);
		}
		if (!(diag_reg & MPI2_DIAG_RESET_ADAPTER)) {
			break;
		}
		drv_usecwait(500);
	}
	if (polls == 600000) {
		mptsas_fm_ereport(mpt, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_LOST);
		return (DDI_FAILURE);
	}

	/*
	 * Check if adapter is in Host Boot Mode.  If so, restart adapter
	 * assuming the HCB points to good FW.
	 * Set BootDeviceSel to HCDW (Host Code and Data Window).
	 */
	if (diag_reg & MPI2_DIAG_HCB_MODE) {
		diag_reg &= ~MPI2_DIAG_BOOT_DEVICE_SELECT_MASK;
		diag_reg |= MPI2_DIAG_BOOT_DEVICE_SELECT_HCDW;
		ddi_put32(mpt->m_datap, &mpt->m_reg->HostDiagnostic, diag_reg);

		/*
		 * Re-enable the HCDW.
		 */
		ddi_put32(mpt->m_datap, &mpt->m_reg->HCBSize,
		    (saved_HCB_size | MPI2_HCB_SIZE_HCB_ENABLE));
	}

	/*
	 * Restart the adapter.
	 */
	diag_reg &= ~MPI2_DIAG_HOLD_IOC_RESET;
	ddi_put32(mpt->m_datap, &mpt->m_reg->HostDiagnostic, diag_reg);

	/*
	 * Disable writes to the Host Diag register.
	 */
	ddi_put32(mpt->m_datap, &mpt->m_reg->WriteSequence,
	    MPI2_WRSEQ_FLUSH_KEY_VALUE);

	/*
	 * Wait 60 seconds max for FW to come to ready state.
	 */
	for (polls = 0; polls < 60000; polls++) {
		ioc_state = ddi_get32(mpt->m_datap, &mpt->m_reg->Doorbell);
		if (ioc_state == 0xFFFFFFFF) {
			mptsas_fm_ereport(mpt, DDI_FM_DEVICE_NO_RESPONSE);
			ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_LOST);
			return (DDI_FAILURE);
		}
		if ((ioc_state & MPI2_IOC_STATE_MASK) ==
		    MPI2_IOC_STATE_READY) {
			break;
		}
		drv_usecwait(1000);
	}
	if (polls == 60000) {
		mptsas_fm_ereport(mpt, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_LOST);
		return (DDI_FAILURE);
	}

	/*
	 * Clear the ioc ack events queue.
	 */
	mptsas_destroy_ioc_event_cmd(mpt);

	return (DDI_SUCCESS);
}

int
mptsas_ioc_reset(mptsas_t *mpt, int first_time)
{
	int		polls = 0;
	uint32_t	reset_msg;
	uint32_t	ioc_state;

	ioc_state = ddi_get32(mpt->m_datap, &mpt->m_reg->Doorbell);
	/*
	 * If chip is already in ready state then there is nothing to do.
	 */
	if (ioc_state == MPI2_IOC_STATE_READY) {
		return (MPTSAS_NO_RESET);
	}
	/*
	 * If the chip is already operational, we just need to send
	 * it a message unit reset to put it back in the ready state
	 */
	if (ioc_state & MPI2_IOC_STATE_OPERATIONAL) {
		/*
		 * If the first time, try MUR anyway, because we haven't even
		 * queried the card for m_event_replay and other capabilities.
		 * Other platforms do it this way, we can still do a hard
		 * reset if we need to, MUR takes less time than a full
		 * adapter reset, and there are reports that some HW
		 * combinations will lock up when receiving a hard reset.
		 */
		if ((first_time || mpt->m_event_replay) &&
		    (mpt->m_softstate & MPTSAS_SS_MSG_UNIT_RESET)) {
			mpt->m_softstate &= ~MPTSAS_SS_MSG_UNIT_RESET;
			reset_msg = MPI2_FUNCTION_IOC_MESSAGE_UNIT_RESET;
			ddi_put32(mpt->m_datap, &mpt->m_reg->Doorbell,
			    (reset_msg << MPI2_DOORBELL_FUNCTION_SHIFT));
			if (mptsas_ioc_wait_for_response(mpt)) {
				NDBG19(("mptsas_ioc_reset failure sending "
				    "message_unit_reset\n"));
				goto hard_reset;
			}

			/*
			 * Wait no more than 60 seconds for chip to become
			 * ready.
			 */
			while ((ddi_get32(mpt->m_datap, &mpt->m_reg->Doorbell) &
			    MPI2_IOC_STATE_READY) == 0x0) {
				drv_usecwait(1000);
				if (polls++ > 60000) {
					goto hard_reset;
				}
			}

			/*
			 * Save the last reset mode done on IOC which will be
			 * helpful while resuming from suspension.
			 */
			mpt->m_softstate |= MPTSAS_DID_MSG_UNIT_RESET;

			/*
			 * the message unit reset would do reset operations
			 * clear reply and request queue, so we should clear
			 * ACK event cmd.
			 */
			mptsas_destroy_ioc_event_cmd(mpt);
			return (MPTSAS_SUCCESS_MUR);
		}
	}
hard_reset:
	mpt->m_softstate &= ~MPTSAS_DID_MSG_UNIT_RESET;
	if (mptsas_kick_start(mpt) == DDI_FAILURE) {
		mptsas_fm_ereport(mpt, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_LOST);
		return (MPTSAS_RESET_FAIL);
	}
	return (MPTSAS_SUCCESS_HARDRESET);
}


int
mptsas_request_from_pool(mptsas_t *mpt, mptsas_cmd_t **cmd,
    struct scsi_pkt **pkt)
{
	m_event_struct_t	*ioc_cmd = NULL;

	ioc_cmd = kmem_zalloc(M_EVENT_STRUCT_SIZE, KM_SLEEP);
	if (ioc_cmd == NULL) {
		return (DDI_FAILURE);
	}
	ioc_cmd->m_event_linkp = NULL;
	mptsas_ioc_event_cmdq_add(mpt, ioc_cmd);
	*cmd = &(ioc_cmd->m_event_cmd);
	*pkt = &(ioc_cmd->m_event_pkt);

	return (DDI_SUCCESS);
}

void
mptsas_return_to_pool(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	m_event_struct_t	*ioc_cmd = NULL;

	ioc_cmd = mptsas_ioc_event_find_by_cmd(mpt, cmd);
	if (ioc_cmd == NULL) {
		return;
	}

	mptsas_ioc_event_cmdq_delete(mpt, ioc_cmd);
	kmem_free(ioc_cmd, M_EVENT_STRUCT_SIZE);
	ioc_cmd = NULL;
}

/*
 * NOTE: We should be able to queue TM requests in the controller to make this
 * a lot faster.  If resetting all targets, for example, we can load the hi
 * priority queue with its limit and the controller will reply as they are
 * completed.  This way, we don't have to poll for one reply at a time.
 * Think about enhancing this later.
 */
int
mptsas_ioc_task_management(mptsas_t *mpt, int task_type, uint16_t dev_handle,
	int lun, uint8_t *reply, uint32_t reply_size, int mode)
{
	/*
	 * In order to avoid allocating variables on the stack,
	 * we make use of the pre-existing mptsas_cmd_t and
	 * scsi_pkt which are included in the mptsas_t which
	 * is passed to this routine.
	 */

	pMpi2SCSITaskManagementRequest_t	task;
	int					rval = FALSE;
	mptsas_cmd_t				*cmd;
	struct scsi_pkt				*pkt;
	mptsas_slots_t				*slots = mpt->m_active;
	uint64_t				request_desc, i;
	pMPI2DefaultReply_t			reply_msg;

	/*
	 * Can't start another task management routine.
	 */
	if (slots->m_slot[MPTSAS_TM_SLOT(mpt)] != NULL) {
		mptsas_log(mpt, CE_WARN, "Can only start 1 task management"
		    " command at a time\n");
		return (FALSE);
	}

	cmd = &(mpt->m_event_task_mgmt.m_event_cmd);
	pkt = &(mpt->m_event_task_mgmt.m_event_pkt);

	bzero((caddr_t)cmd, sizeof (*cmd));
	bzero((caddr_t)pkt, scsi_pkt_size());

	pkt->pkt_cdbp		= (opaque_t)&cmd->cmd_cdb[0];
	pkt->pkt_scbp		= (opaque_t)&cmd->cmd_scb;
	pkt->pkt_ha_private	= (opaque_t)cmd;
	pkt->pkt_flags		= (FLAG_NOINTR | FLAG_HEAD);
	pkt->pkt_time		= 60;
	pkt->pkt_address.a_target = dev_handle;
	pkt->pkt_address.a_lun = (uchar_t)lun;
	cmd->cmd_pkt		= pkt;
	cmd->cmd_scblen		= 1;
	cmd->cmd_flags		= CFLAG_TM_CMD;
	cmd->cmd_slot		= MPTSAS_TM_SLOT(mpt);

	slots->m_slot[MPTSAS_TM_SLOT(mpt)] = cmd;

	/*
	 * Store the TM message in memory location corresponding to the TM slot
	 * number.
	 */
	task = (pMpi2SCSITaskManagementRequest_t)(mpt->m_req_frame +
	    (mpt->m_req_frame_size * cmd->cmd_slot));
	bzero(task, mpt->m_req_frame_size);

	/*
	 * form message for requested task
	 */
	mptsas_init_std_hdr(mpt->m_acc_req_frame_hdl, task, dev_handle, lun, 0,
	    MPI2_FUNCTION_SCSI_TASK_MGMT);

	/*
	 * Set the task type
	 */
	ddi_put8(mpt->m_acc_req_frame_hdl, &task->TaskType, task_type);

	/*
	 * Send TM request using High Priority Queue.
	 */
	(void) ddi_dma_sync(mpt->m_dma_req_frame_hdl, 0, 0,
	    DDI_DMA_SYNC_FORDEV);
	request_desc = (cmd->cmd_slot << 16) +
	    MPI2_REQ_DESCRIPT_FLAGS_HIGH_PRIORITY;
	MPTSAS_START_CMD(mpt, request_desc);
	rval = mptsas_poll(mpt, cmd, MPTSAS_POLL_TIME);

	if (pkt->pkt_reason == CMD_INCOMPLETE)
		rval = FALSE;

	/*
	 * If a reply frame was used and there is a reply buffer to copy the
	 * reply data into, copy it.  If this fails, log a message, but don't
	 * fail the TM request.
	 */
	if (cmd->cmd_rfm && reply) {
		(void) ddi_dma_sync(mpt->m_dma_reply_frame_hdl, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
		reply_msg = (pMPI2DefaultReply_t)
		    (mpt->m_reply_frame + (cmd->cmd_rfm -
		    (mpt->m_reply_frame_dma_addr & 0xffffffffu)));
		if (reply_size > sizeof (MPI2_SCSI_TASK_MANAGE_REPLY)) {
			reply_size = sizeof (MPI2_SCSI_TASK_MANAGE_REPLY);
		}
		mutex_exit(&mpt->m_mutex);
		for (i = 0; i < reply_size; i++) {
			if (ddi_copyout((uint8_t *)reply_msg + i, reply + i, 1,
			    mode)) {
				mptsas_log(mpt, CE_WARN, "failed to copy out "
				    "reply data for TM request");
				break;
			}
		}
		mutex_enter(&mpt->m_mutex);
	}

	/*
	 * clear the TM slot before returning
	 */
	slots->m_slot[MPTSAS_TM_SLOT(mpt)] = NULL;

	/*
	 * If we lost our task management command
	 * we need to reset the ioc
	 */
	if (rval == FALSE) {
		mptsas_log(mpt, CE_WARN, "mptsas_ioc_task_management failed "
		    "try to reset ioc to recovery!");
		mpt->m_softstate &= ~MPTSAS_SS_MSG_UNIT_RESET;
		if (mptsas_restart_ioc(mpt)) {
			mptsas_log(mpt, CE_WARN, "mptsas_restart_ioc failed");
			rval = FAILED;
		}
	}

	return (rval);
}

/*
 * Complete firmware download frame for v2.0 cards.
 */
static void
mptsas_uflash2(pMpi2FWDownloadRequest fwdownload,
    ddi_acc_handle_t acc_hdl, uint32_t size, uint8_t type,
    ddi_dma_cookie_t flsh_cookie)
{
	pMpi2FWDownloadTCSGE_t	tcsge;
	pMpi2SGESimple64_t	sge;
	uint32_t		flagslength;

	ddi_put8(acc_hdl, &fwdownload->Function,
	    MPI2_FUNCTION_FW_DOWNLOAD);
	ddi_put8(acc_hdl, &fwdownload->ImageType, type);
	ddi_put8(acc_hdl, &fwdownload->MsgFlags,
	    MPI2_FW_DOWNLOAD_MSGFLGS_LAST_SEGMENT);
	ddi_put32(acc_hdl, &fwdownload->TotalImageSize, size);

	tcsge = (pMpi2FWDownloadTCSGE_t)&fwdownload->SGL;
	ddi_put8(acc_hdl, &tcsge->ContextSize, 0);
	ddi_put8(acc_hdl, &tcsge->DetailsLength, 12);
	ddi_put8(acc_hdl, &tcsge->Flags, 0);
	ddi_put32(acc_hdl, &tcsge->ImageOffset, 0);
	ddi_put32(acc_hdl, &tcsge->ImageSize, size);

	sge = (pMpi2SGESimple64_t)(tcsge + 1);
	flagslength = size;
	flagslength |= ((uint32_t)(MPI2_SGE_FLAGS_LAST_ELEMENT |
	    MPI2_SGE_FLAGS_END_OF_BUFFER |
	    MPI2_SGE_FLAGS_SIMPLE_ELEMENT |
	    MPI2_SGE_FLAGS_SYSTEM_ADDRESS |
	    MPI2_SGE_FLAGS_64_BIT_ADDRESSING |
	    MPI2_SGE_FLAGS_HOST_TO_IOC |
	    MPI2_SGE_FLAGS_END_OF_LIST) << MPI2_SGE_FLAGS_SHIFT);
	ddi_put32(acc_hdl, &sge->FlagsLength, flagslength);
	ddi_put32(acc_hdl, &sge->Address.Low,
	    flsh_cookie.dmac_address);
	ddi_put32(acc_hdl, &sge->Address.High,
	    (uint32_t)(flsh_cookie.dmac_laddress >> 32));
}

/*
 * Complete firmware download frame for v2.5 cards.
 */
static void
mptsas_uflash25(pMpi25FWDownloadRequest fwdownload,
    ddi_acc_handle_t acc_hdl, uint32_t size, uint8_t type,
    ddi_dma_cookie_t flsh_cookie)
{
	pMpi2IeeeSgeSimple64_t	sge;
	uint8_t			flags;

	ddi_put8(acc_hdl, &fwdownload->Function,
	    MPI2_FUNCTION_FW_DOWNLOAD);
	ddi_put8(acc_hdl, &fwdownload->ImageType, type);
	ddi_put8(acc_hdl, &fwdownload->MsgFlags,
	    MPI2_FW_DOWNLOAD_MSGFLGS_LAST_SEGMENT);
	ddi_put32(acc_hdl, &fwdownload->TotalImageSize, size);

	ddi_put32(acc_hdl, &fwdownload->ImageOffset, 0);
	ddi_put32(acc_hdl, &fwdownload->ImageSize, size);

	sge = (pMpi2IeeeSgeSimple64_t)&fwdownload->SGL;
	flags = MPI2_IEEE_SGE_FLAGS_SIMPLE_ELEMENT |
	    MPI2_IEEE_SGE_FLAGS_SYSTEM_ADDR |
	    MPI25_IEEE_SGE_FLAGS_END_OF_LIST;
	ddi_put8(acc_hdl, &sge->Flags, flags);
	ddi_put32(acc_hdl, &sge->Length, size);
	ddi_put32(acc_hdl, &sge->Address.Low,
	    flsh_cookie.dmac_address);
	ddi_put32(acc_hdl, &sge->Address.High,
	    (uint32_t)(flsh_cookie.dmac_laddress >> 32));
}

static int mptsas_enable_mpi25_flashupdate = 0;

int
mptsas_update_flash(mptsas_t *mpt, caddr_t ptrbuffer, uint32_t size,
    uint8_t type, int mode)
{

	/*
	 * In order to avoid allocating variables on the stack,
	 * we make use of the pre-existing mptsas_cmd_t and
	 * scsi_pkt which are included in the mptsas_t which
	 * is passed to this routine.
	 */

	ddi_dma_attr_t		flsh_dma_attrs;
	ddi_dma_cookie_t	flsh_cookie;
	ddi_dma_handle_t	flsh_dma_handle;
	ddi_acc_handle_t	flsh_accessp;
	caddr_t			memp, flsh_memp;
	mptsas_cmd_t		*cmd;
	struct scsi_pkt		*pkt;
	int			i;
	int			rvalue = 0;
	uint64_t		request_desc;

	if (mpt->m_MPI25 && !mptsas_enable_mpi25_flashupdate) {
		/*
		 * The code is there but not tested yet.
		 * User has to know there are risks here.
		 */
		mptsas_log(mpt, CE_WARN, "mptsas_update_flash(): "
		    "Updating firmware through MPI 2.5 has not been "
		    "tested yet!\n"
		    "To enable set mptsas_enable_mpi25_flashupdate to 1\n");
		return (-1);
	} /* Otherwise, you pay your money and you take your chances. */

	if ((rvalue = (mptsas_request_from_pool(mpt, &cmd, &pkt))) == -1) {
		mptsas_log(mpt, CE_WARN, "mptsas_update_flash(): allocation "
		    "failed. event ack command pool is full\n");
		return (rvalue);
	}

	bzero((caddr_t)cmd, sizeof (*cmd));
	bzero((caddr_t)pkt, scsi_pkt_size());
	cmd->ioc_cmd_slot = (uint32_t)rvalue;

	/*
	 * dynamically create a customized dma attribute structure
	 * that describes the flash file.
	 */
	flsh_dma_attrs = mpt->m_msg_dma_attr;
	flsh_dma_attrs.dma_attr_sgllen = 1;

	if (mptsas_dma_addr_create(mpt, flsh_dma_attrs, &flsh_dma_handle,
	    &flsh_accessp, &flsh_memp, size, &flsh_cookie) == FALSE) {
		mptsas_log(mpt, CE_WARN,
		    "(unable to allocate dma resource.");
		mptsas_return_to_pool(mpt, cmd);
		return (-1);
	}

	bzero(flsh_memp, size);

	for (i = 0; i < size; i++) {
		(void) ddi_copyin(ptrbuffer + i, flsh_memp + i, 1, mode);
	}
	(void) ddi_dma_sync(flsh_dma_handle, 0, 0, DDI_DMA_SYNC_FORDEV);

	/*
	 * form a cmd/pkt to store the fw download message
	 */
	pkt->pkt_cdbp		= (opaque_t)&cmd->cmd_cdb[0];
	pkt->pkt_scbp		= (opaque_t)&cmd->cmd_scb;
	pkt->pkt_ha_private	= (opaque_t)cmd;
	pkt->pkt_flags		= FLAG_HEAD;
	pkt->pkt_time		= 60;
	cmd->cmd_pkt		= pkt;
	cmd->cmd_scblen		= 1;
	cmd->cmd_flags		= CFLAG_CMDIOC | CFLAG_FW_CMD;

	/*
	 * Save the command in a slot
	 */
	if (mptsas_save_cmd(mpt, cmd) == FALSE) {
		mptsas_dma_addr_destroy(&flsh_dma_handle, &flsh_accessp);
		mptsas_return_to_pool(mpt, cmd);
		return (-1);
	}

	/*
	 * Fill in fw download message
	 */
	ASSERT(cmd->cmd_slot != 0);
	memp = mpt->m_req_frame + (mpt->m_req_frame_size * cmd->cmd_slot);
	bzero(memp, mpt->m_req_frame_size);

	if (mpt->m_MPI25)
		mptsas_uflash25((pMpi25FWDownloadRequest)memp,
		    mpt->m_acc_req_frame_hdl, size, type, flsh_cookie);
	else
		mptsas_uflash2((pMpi2FWDownloadRequest)memp,
		    mpt->m_acc_req_frame_hdl, size, type, flsh_cookie);

	/*
	 * Start command
	 */
	(void) ddi_dma_sync(mpt->m_dma_req_frame_hdl, 0, 0,
	    DDI_DMA_SYNC_FORDEV);
	request_desc = (cmd->cmd_slot << 16) +
	    MPI2_REQ_DESCRIPT_FLAGS_DEFAULT_TYPE;
	cmd->cmd_rfm = NULL;
	MPTSAS_START_CMD(mpt, request_desc);

	rvalue = 0;
	(void) cv_reltimedwait(&mpt->m_fw_cv, &mpt->m_mutex,
	    drv_usectohz(60 * MICROSEC), TR_CLOCK_TICK);
	if (!(cmd->cmd_flags & CFLAG_FINISHED)) {
		mpt->m_softstate &= ~MPTSAS_SS_MSG_UNIT_RESET;
		if ((mptsas_restart_ioc(mpt)) == DDI_FAILURE) {
			mptsas_log(mpt, CE_WARN, "mptsas_restart_ioc failed");
		}
		rvalue = -1;
	}
	mptsas_remove_cmd(mpt, cmd);
	mptsas_dma_addr_destroy(&flsh_dma_handle, &flsh_accessp);

	return (rvalue);
}

static int
mptsas_sasdevpage_0_cb(mptsas_t *mpt, caddr_t page_memp,
    ddi_acc_handle_t accessp, uint16_t iocstatus, uint32_t iocloginfo,
    va_list ap)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(ap))
#endif
	pMpi2SasDevicePage0_t	sasdevpage;
	int			rval = DDI_SUCCESS, i;
	uint8_t			*sas_addr = NULL;
	uint8_t			tmp_sas_wwn[SAS_WWN_BYTE_SIZE];
	uint16_t		*devhdl, *bay_num, *enclosure;
	uint64_t		*sas_wwn;
	uint32_t		*dev_info;
	uint8_t			*physport, *phynum;
	uint16_t		*pdevhdl, *io_flags;
	uint32_t		page_address;

	if ((iocstatus != MPI2_IOCSTATUS_SUCCESS) &&
	    (iocstatus != MPI2_IOCSTATUS_CONFIG_INVALID_PAGE)) {
		mptsas_log(mpt, CE_WARN, "mptsas_get_sas_device_page0 "
		    "header: IOCStatus=0x%x, IOCLogInfo=0x%x",
		    iocstatus, iocloginfo);
		rval = DDI_FAILURE;
		return (rval);
	}
	page_address = va_arg(ap, uint32_t);
	/*
	 * The INVALID_PAGE status is normal if using GET_NEXT_HANDLE and there
	 * are no more pages.  If everything is OK up to this point but the
	 * status is INVALID_PAGE, change rval to FAILURE and quit.  Also,
	 * signal that device traversal is complete.
	 */
	if (iocstatus == MPI2_IOCSTATUS_CONFIG_INVALID_PAGE) {
		if ((page_address & MPI2_SAS_DEVICE_PGAD_FORM_MASK) ==
		    MPI2_SAS_DEVICE_PGAD_FORM_GET_NEXT_HANDLE) {
			mpt->m_done_traverse_dev = 1;
		}
		rval = DDI_FAILURE;
		return (rval);
	}
	devhdl = va_arg(ap, uint16_t *);
	sas_wwn = va_arg(ap, uint64_t *);
	dev_info = va_arg(ap, uint32_t *);
	physport = va_arg(ap, uint8_t *);
	phynum = va_arg(ap, uint8_t *);
	pdevhdl = va_arg(ap, uint16_t *);
	bay_num = va_arg(ap, uint16_t *);
	enclosure = va_arg(ap, uint16_t *);
	io_flags = va_arg(ap, uint16_t *);

	sasdevpage = (pMpi2SasDevicePage0_t)page_memp;

	*dev_info = ddi_get32(accessp, &sasdevpage->DeviceInfo);
	*devhdl = ddi_get16(accessp, &sasdevpage->DevHandle);
	sas_addr = (uint8_t *)(&sasdevpage->SASAddress);
	for (i = 0; i < SAS_WWN_BYTE_SIZE; i++) {
		tmp_sas_wwn[i] = ddi_get8(accessp, sas_addr + i);
	}
	bcopy(tmp_sas_wwn, sas_wwn, SAS_WWN_BYTE_SIZE);
	*sas_wwn = LE_64(*sas_wwn);
	*physport = ddi_get8(accessp, &sasdevpage->PhysicalPort);
	*phynum = ddi_get8(accessp, &sasdevpage->PhyNum);
	*pdevhdl = ddi_get16(accessp, &sasdevpage->ParentDevHandle);
	*bay_num = ddi_get16(accessp, &sasdevpage->Slot);
	*enclosure = ddi_get16(accessp, &sasdevpage->EnclosureHandle);
	*io_flags = ddi_get16(accessp, &sasdevpage->Flags);

	if (*io_flags & MPI25_SAS_DEVICE0_FLAGS_FAST_PATH_CAPABLE) {
		/*
		 * Leave a messages about FP cabability in the log.
		 */
		mptsas_log(mpt, CE_CONT,
		    "!w%016"PRIx64" FastPath Capable%s", *sas_wwn,
		    (*io_flags &
		    MPI25_SAS_DEVICE0_FLAGS_ENABLED_FAST_PATH)?
		    " and Enabled":" but Disabled");
	}

	return (rval);
}

/*
 * Request MPI configuration page SAS device page 0 to get DevHandle, device
 * info and SAS address.
 */
int
mptsas_get_sas_device_page0(mptsas_t *mpt, uint32_t page_address,
    uint16_t *dev_handle, uint64_t *sas_wwn, uint32_t *dev_info,
    uint8_t *physport, uint8_t *phynum, uint16_t *pdev_handle,
    uint16_t *bay_num, uint16_t *enclosure, uint16_t *io_flags)
{
	int rval = DDI_SUCCESS;

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Get the header and config page.  reply contains the reply frame,
	 * which holds status info for the request.
	 */
	rval = mptsas_access_config_page(mpt,
	    MPI2_CONFIG_ACTION_PAGE_READ_CURRENT,
	    MPI2_CONFIG_EXTPAGETYPE_SAS_DEVICE, 0, page_address,
	    mptsas_sasdevpage_0_cb, page_address, dev_handle, sas_wwn,
	    dev_info, physport, phynum, pdev_handle,
	    bay_num, enclosure, io_flags);

	return (rval);
}

static int
mptsas_sasexpdpage_0_cb(mptsas_t *mpt, caddr_t page_memp,
    ddi_acc_handle_t accessp, uint16_t iocstatus, uint32_t iocloginfo,
    va_list ap)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(ap))
#endif
	pMpi2ExpanderPage0_t	expddevpage;
	int			rval = DDI_SUCCESS, i;
	uint8_t			*sas_addr = NULL;
	uint8_t			tmp_sas_wwn[SAS_WWN_BYTE_SIZE];
	uint16_t		*devhdl;
	uint64_t		*sas_wwn;
	uint8_t			physport;
	mptsas_phymask_t	*phymask;
	uint16_t		*pdevhdl;
	uint32_t		page_address;

	if ((iocstatus != MPI2_IOCSTATUS_SUCCESS) &&
	    (iocstatus != MPI2_IOCSTATUS_CONFIG_INVALID_PAGE)) {
		mptsas_log(mpt, CE_WARN, "mptsas_get_sas_expander_page0 "
		    "config: IOCStatus=0x%x, IOCLogInfo=0x%x",
		    iocstatus, iocloginfo);
		rval = DDI_FAILURE;
		return (rval);
	}
	page_address = va_arg(ap, uint32_t);
	/*
	 * The INVALID_PAGE status is normal if using GET_NEXT_HANDLE and there
	 * are no more pages.  If everything is OK up to this point but the
	 * status is INVALID_PAGE, change rval to FAILURE and quit.  Also,
	 * signal that device traversal is complete.
	 */
	if (iocstatus == MPI2_IOCSTATUS_CONFIG_INVALID_PAGE) {
		if ((page_address & MPI2_SAS_EXPAND_PGAD_FORM_MASK) ==
		    MPI2_SAS_EXPAND_PGAD_FORM_GET_NEXT_HNDL) {
			mpt->m_done_traverse_smp = 1;
		}
		rval = DDI_FAILURE;
		return (rval);
	}
	devhdl = va_arg(ap, uint16_t *);
	sas_wwn = va_arg(ap, uint64_t *);
	phymask = va_arg(ap, mptsas_phymask_t *);
	pdevhdl = va_arg(ap, uint16_t *);

	expddevpage = (pMpi2ExpanderPage0_t)page_memp;

	*devhdl = ddi_get16(accessp, &expddevpage->DevHandle);
	physport = ddi_get8(accessp, &expddevpage->PhysicalPort);
	*phymask = mptsas_physport_to_phymask(mpt, physport);
	*pdevhdl = ddi_get16(accessp, &expddevpage->ParentDevHandle);
	sas_addr = (uint8_t *)(&expddevpage->SASAddress);
	for (i = 0; i < SAS_WWN_BYTE_SIZE; i++) {
		tmp_sas_wwn[i] = ddi_get8(accessp, sas_addr + i);
	}
	bcopy(tmp_sas_wwn, sas_wwn, SAS_WWN_BYTE_SIZE);
	*sas_wwn = LE_64(*sas_wwn);

	return (rval);
}

/*
 * Request MPI configuration page SAS device page 0 to get DevHandle, phymask
 * and SAS address.
 */
int
mptsas_get_sas_expander_page0(mptsas_t *mpt, uint32_t page_address,
    mptsas_smp_t *info)
{
	int			rval = DDI_SUCCESS;

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Get the header and config page.  reply contains the reply frame,
	 * which holds status info for the request.
	 */
	rval = mptsas_access_config_page(mpt,
	    MPI2_CONFIG_ACTION_PAGE_READ_CURRENT,
	    MPI2_CONFIG_EXTPAGETYPE_SAS_EXPANDER, 0, page_address,
	    mptsas_sasexpdpage_0_cb, page_address, &info->m_devhdl,
	    &info->m_addr.mta_wwn, &info->m_addr.mta_phymask, &info->m_pdevhdl);

	return (rval);
}

static int
mptsas_sasportpage_0_cb(mptsas_t *mpt, caddr_t page_memp,
    ddi_acc_handle_t accessp, uint16_t iocstatus, uint32_t iocloginfo,
    va_list ap)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(ap))
#endif
	int	rval = DDI_SUCCESS, i;
	uint8_t	*sas_addr = NULL;
	uint64_t *sas_wwn;
	uint8_t	tmp_sas_wwn[SAS_WWN_BYTE_SIZE];
	uint8_t *portwidth;
	pMpi2SasPortPage0_t sasportpage;

	if (iocstatus != MPI2_IOCSTATUS_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "mptsas_get_sas_port_page0 "
		    "config: IOCStatus=0x%x, IOCLogInfo=0x%x",
		    iocstatus, iocloginfo);
		rval = DDI_FAILURE;
		return (rval);
	}
	sas_wwn = va_arg(ap, uint64_t *);
	portwidth = va_arg(ap, uint8_t *);

	sasportpage = (pMpi2SasPortPage0_t)page_memp;
	sas_addr = (uint8_t *)(&sasportpage->SASAddress);
	for (i = 0; i < SAS_WWN_BYTE_SIZE; i++) {
		tmp_sas_wwn[i] = ddi_get8(accessp, sas_addr + i);
	}
	bcopy(tmp_sas_wwn, sas_wwn, SAS_WWN_BYTE_SIZE);
	*sas_wwn = LE_64(*sas_wwn);
	*portwidth = ddi_get8(accessp, &sasportpage->PortWidth);
	return (rval);
}

/*
 * Request MPI configuration page SAS port page 0 to get initiator SAS address
 * and port width.
 */
int
mptsas_get_sas_port_page0(mptsas_t *mpt, uint32_t page_address,
    uint64_t *sas_wwn, uint8_t *portwidth)
{
	int rval = DDI_SUCCESS;

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Get the header and config page.  reply contains the reply frame,
	 * which holds status info for the request.
	 */
	rval = mptsas_access_config_page(mpt,
	    MPI2_CONFIG_ACTION_PAGE_READ_CURRENT,
	    MPI2_CONFIG_EXTPAGETYPE_SAS_PORT, 0, page_address,
	    mptsas_sasportpage_0_cb, sas_wwn, portwidth);

	return (rval);
}

static int
mptsas_sasiou_page_0_cb(mptsas_t *mpt, caddr_t page_memp,
    ddi_acc_handle_t accessp, uint16_t iocstatus, uint32_t iocloginfo,
    va_list ap)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(ap))
#endif
	int rval = DDI_SUCCESS;
	pMpi2SasIOUnitPage0_t sasioupage0;
	int i, num_phys;
	uint32_t cpdi[MPTSAS_MAX_PHYS], *retrypage0, *readpage1;
	uint8_t port_flags;

	if (iocstatus != MPI2_IOCSTATUS_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "mptsas_get_sas_io_unit_page0 "
		    "config: IOCStatus=0x%x, IOCLogInfo=0x%x",
		    iocstatus, iocloginfo);
		rval = DDI_FAILURE;
		return (rval);
	}
	readpage1 = va_arg(ap, uint32_t *);
	retrypage0 = va_arg(ap, uint32_t *);

	sasioupage0 = (pMpi2SasIOUnitPage0_t)page_memp;

	num_phys = ddi_get8(accessp, &sasioupage0->NumPhys);
	/*
	 * ASSERT that the num_phys value in SAS IO Unit Page 0 is the same as
	 * was initially set.  This should never change throughout the life of
	 * the driver.
	 */
	ASSERT(num_phys == mpt->m_num_phys);
	for (i = 0; i < num_phys; i++) {
		cpdi[i] = ddi_get32(accessp,
		    &sasioupage0->PhyData[i].
		    ControllerPhyDeviceInfo);
		port_flags = ddi_get8(accessp,
		    &sasioupage0->PhyData[i].PortFlags);
		mpt->m_phy_info[i].port_num =
		    ddi_get8(accessp,
		    &sasioupage0->PhyData[i].Port);
		mpt->m_phy_info[i].ctrl_devhdl =
		    ddi_get16(accessp, &sasioupage0->
		    PhyData[i].ControllerDevHandle);
		mpt->m_phy_info[i].attached_devhdl =
		    ddi_get16(accessp, &sasioupage0->
		    PhyData[i].AttachedDevHandle);
		mpt->m_phy_info[i].phy_device_type = cpdi[i];
		mpt->m_phy_info[i].port_flags = port_flags;

		if (port_flags & DISCOVERY_IN_PROGRESS) {
			*retrypage0 = *retrypage0 + 1;
			break;
		} else {
			*retrypage0 = 0;
		}
		if (!(port_flags & AUTO_PORT_CONFIGURATION)) {
			/*
			 * some PHY configuration described in
			 * SAS IO Unit Page1
			 */
			*readpage1 = 1;
		}
	}

	return (rval);
}

static int
mptsas_sasiou_page_1_cb(mptsas_t *mpt, caddr_t page_memp,
    ddi_acc_handle_t accessp, uint16_t iocstatus, uint32_t iocloginfo,
    va_list ap)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(ap))
#endif
	int rval = DDI_SUCCESS;
	pMpi2SasIOUnitPage1_t sasioupage1;
	int i, num_phys;
	uint32_t cpdi[MPTSAS_MAX_PHYS];
	uint8_t port_flags;

	if (iocstatus != MPI2_IOCSTATUS_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "mptsas_get_sas_io_unit_page1 "
		    "config: IOCStatus=0x%x, IOCLogInfo=0x%x",
		    iocstatus, iocloginfo);
		rval = DDI_FAILURE;
		return (rval);
	}

	sasioupage1 = (pMpi2SasIOUnitPage1_t)page_memp;
	num_phys = ddi_get8(accessp, &sasioupage1->NumPhys);
	/*
	 * ASSERT that the num_phys value in SAS IO Unit Page 1 is the same as
	 * was initially set.  This should never change throughout the life of
	 * the driver.
	 */
	ASSERT(num_phys == mpt->m_num_phys);
	for (i = 0; i < num_phys; i++) {
		cpdi[i] = ddi_get32(accessp, &sasioupage1->PhyData[i].
		    ControllerPhyDeviceInfo);
		port_flags = ddi_get8(accessp,
		    &sasioupage1->PhyData[i].PortFlags);
		mpt->m_phy_info[i].port_num =
		    ddi_get8(accessp,
		    &sasioupage1->PhyData[i].Port);
		mpt->m_phy_info[i].port_flags = port_flags;
		mpt->m_phy_info[i].phy_device_type = cpdi[i];
	}
	return (rval);
}

/*
 * Read IO unit page 0 to get information for each PHY. If needed, Read IO Unit
 * page1 to update the PHY information.  This is the message passing method of
 * this function which should be called except during initialization.
 */
int
mptsas_get_sas_io_unit_page(mptsas_t *mpt)
{
	int rval = DDI_SUCCESS, state;
	uint32_t readpage1 = 0, retrypage0 = 0;

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Now we cycle through the state machine.  Here's what happens:
	 * 1. Read IO unit page 0 and set phy information
	 * 2. See if Read IO unit page1 is needed because of port configuration
	 * 3. Read IO unit page 1 and update phy information.
	 */
	state = IOUC_READ_PAGE0;
	while (state != IOUC_DONE) {
		if (state == IOUC_READ_PAGE0) {
			rval = mptsas_access_config_page(mpt,
			    MPI2_CONFIG_ACTION_PAGE_READ_CURRENT,
			    MPI2_CONFIG_EXTPAGETYPE_SAS_IO_UNIT, 0, 0,
			    mptsas_sasiou_page_0_cb, &readpage1,
			    &retrypage0);
		} else if (state == IOUC_READ_PAGE1) {
			rval = mptsas_access_config_page(mpt,
			    MPI2_CONFIG_ACTION_PAGE_READ_CURRENT,
			    MPI2_CONFIG_EXTPAGETYPE_SAS_IO_UNIT, 1, 0,
			    mptsas_sasiou_page_1_cb);
		}

		if (rval == DDI_SUCCESS) {
			switch (state) {
			case IOUC_READ_PAGE0:
				/*
				 * retry 30 times if discovery is in process
				 */
				if (retrypage0 && (retrypage0 < 30)) {
					drv_usecwait(1000 * 100);
					state = IOUC_READ_PAGE0;
					break;
				} else if (retrypage0 == 30) {
					mptsas_log(mpt, CE_WARN,
					    "!Discovery in progress, can't "
					    "verify IO unit config, then "
					    "after 30 times retry, give "
					    "up!");
					state = IOUC_DONE;
					rval = DDI_FAILURE;
					break;
				}

				if (readpage1 == 0) {
					state = IOUC_DONE;
					rval = DDI_SUCCESS;
					break;
				}

				state = IOUC_READ_PAGE1;
				break;

			case IOUC_READ_PAGE1:
				state = IOUC_DONE;
				rval = DDI_SUCCESS;
				break;
			}
		} else {
			return (rval);
		}
	}

	return (rval);
}

static int
mptsas_biospage_3_cb(mptsas_t *mpt, caddr_t page_memp,
    ddi_acc_handle_t accessp, uint16_t iocstatus, uint32_t iocloginfo,
    va_list ap)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(ap))
#endif
	pMpi2BiosPage3_t	sasbiospage;
	int			rval = DDI_SUCCESS;
	uint32_t		*bios_version;

	if ((iocstatus != MPI2_IOCSTATUS_SUCCESS) &&
	    (iocstatus != MPI2_IOCSTATUS_CONFIG_INVALID_PAGE)) {
		mptsas_log(mpt, CE_WARN, "mptsas_get_bios_page3 header: "
		    "IOCStatus=0x%x, IOCLogInfo=0x%x", iocstatus, iocloginfo);
		rval = DDI_FAILURE;
		return (rval);
	}
	bios_version = va_arg(ap, uint32_t *);
	sasbiospage = (pMpi2BiosPage3_t)page_memp;
	*bios_version = ddi_get32(accessp, &sasbiospage->BiosVersion);

	return (rval);
}

/*
 * Request MPI configuration page BIOS page 3 to get BIOS version.  Since all
 * other information in this page is not needed, just ignore it.
 */
int
mptsas_get_bios_page3(mptsas_t *mpt, uint32_t *bios_version)
{
	int rval = DDI_SUCCESS;

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Get the header and config page.  reply contains the reply frame,
	 * which holds status info for the request.
	 */
	rval = mptsas_access_config_page(mpt,
	    MPI2_CONFIG_ACTION_PAGE_READ_CURRENT, MPI2_CONFIG_PAGETYPE_BIOS, 3,
	    0, mptsas_biospage_3_cb, bios_version);

	return (rval);
}

/*
 * Read IO unit page 0 to get information for each PHY. If needed, Read IO Unit
 * page1 to update the PHY information.  This is the handshaking version of
 * this function, which should be called during initialization only.
 */
int
mptsas_get_sas_io_unit_page_hndshk(mptsas_t *mpt)
{
	ddi_dma_attr_t		recv_dma_attrs, page_dma_attrs;
	ddi_dma_cookie_t	page_cookie;
	ddi_dma_handle_t	recv_dma_handle, page_dma_handle;
	ddi_acc_handle_t	recv_accessp, page_accessp;
	pMpi2ConfigReply_t	configreply;
	pMpi2SasIOUnitPage0_t	sasioupage0;
	pMpi2SasIOUnitPage1_t	sasioupage1;
	int			recv_numbytes;
	caddr_t			recv_memp, page_memp;
	int			i, num_phys, start_phy = 0;
	int			page0_size =
	    sizeof (MPI2_CONFIG_PAGE_SASIOUNIT_0) +
	    (sizeof (MPI2_SAS_IO_UNIT0_PHY_DATA) * (MPTSAS_MAX_PHYS - 1));
	int			page1_size =
	    sizeof (MPI2_CONFIG_PAGE_SASIOUNIT_1) +
	    (sizeof (MPI2_SAS_IO_UNIT1_PHY_DATA) * (MPTSAS_MAX_PHYS - 1));
	uint32_t		flags_length;
	uint32_t		cpdi[MPTSAS_MAX_PHYS];
	uint32_t		readpage1 = 0, retrypage0 = 0;
	uint16_t		iocstatus;
	uint8_t			port_flags, page_number, action;
	uint32_t		reply_size = 256; /* Big enough for any page */
	uint_t			state;
	int			rval = DDI_FAILURE;
	boolean_t		free_recv = B_FALSE, free_page = B_FALSE;

	/*
	 * Initialize our "state machine".  This is a bit convoluted,
	 * but it keeps us from having to do the ddi allocations numerous
	 * times.
	 */

	NDBG20(("mptsas_get_sas_io_unit_page_hndshk enter"));
	ASSERT(mutex_owned(&mpt->m_mutex));
	state = IOUC_READ_PAGE0;

	/*
	 * dynamically create a customized dma attribute structure
	 * that describes mpt's config reply page request structure.
	 */
	recv_dma_attrs = mpt->m_msg_dma_attr;
	recv_dma_attrs.dma_attr_sgllen = 1;
	recv_dma_attrs.dma_attr_granular = (sizeof (MPI2_CONFIG_REPLY));

	if (mptsas_dma_addr_create(mpt, recv_dma_attrs,
	    &recv_dma_handle, &recv_accessp, &recv_memp,
	    (sizeof (MPI2_CONFIG_REPLY)), NULL) == FALSE) {
		mptsas_log(mpt, CE_WARN,
		    "mptsas_get_sas_io_unit_page_hndshk: recv dma failed");
		goto cleanup;
	}
	/* Now safe to call mptsas_dma_addr_destroy(recv_dma_handle). */
	free_recv = B_TRUE;

	page_dma_attrs = mpt->m_msg_dma_attr;
	page_dma_attrs.dma_attr_sgllen = 1;
	page_dma_attrs.dma_attr_granular = reply_size;

	if (mptsas_dma_addr_create(mpt, page_dma_attrs,
	    &page_dma_handle, &page_accessp, &page_memp,
	    reply_size, &page_cookie) == FALSE) {
		mptsas_log(mpt, CE_WARN,
		    "mptsas_get_sas_io_unit_page_hndshk: page dma failed");
		goto cleanup;
	}
	/* Now safe to call mptsas_dma_addr_destroy(page_dma_handle). */
	free_page = B_TRUE;

	/*
	 * Now we cycle through the state machine.  Here's what happens:
	 * 1. Read IO unit page 0 and set phy information
	 * 2. See if Read IO unit page1 is needed because of port configuration
	 * 3. Read IO unit page 1 and update phy information.
	 */

	sasioupage0 = (pMpi2SasIOUnitPage0_t)page_memp;
	sasioupage1 = (pMpi2SasIOUnitPage1_t)page_memp;

	while (state != IOUC_DONE) {
		switch (state) {
		case IOUC_READ_PAGE0:
			page_number = 0;
			action = MPI2_CONFIG_ACTION_PAGE_READ_CURRENT;
			flags_length = (uint32_t)page0_size;
			flags_length |= ((uint32_t)(
			    MPI2_SGE_FLAGS_LAST_ELEMENT |
			    MPI2_SGE_FLAGS_END_OF_BUFFER |
			    MPI2_SGE_FLAGS_SIMPLE_ELEMENT |
			    MPI2_SGE_FLAGS_SYSTEM_ADDRESS |
			    MPI2_SGE_FLAGS_64_BIT_ADDRESSING |
			    MPI2_SGE_FLAGS_IOC_TO_HOST |
			    MPI2_SGE_FLAGS_END_OF_LIST) <<
			    MPI2_SGE_FLAGS_SHIFT);

			break;

		case IOUC_READ_PAGE1:
			page_number = 1;
			action = MPI2_CONFIG_ACTION_PAGE_READ_CURRENT;
			flags_length = (uint32_t)page1_size;
			flags_length |= ((uint32_t)(
			    MPI2_SGE_FLAGS_LAST_ELEMENT |
			    MPI2_SGE_FLAGS_END_OF_BUFFER |
			    MPI2_SGE_FLAGS_SIMPLE_ELEMENT |
			    MPI2_SGE_FLAGS_SYSTEM_ADDRESS |
			    MPI2_SGE_FLAGS_64_BIT_ADDRESSING |
			    MPI2_SGE_FLAGS_IOC_TO_HOST |
			    MPI2_SGE_FLAGS_END_OF_LIST) <<
			    MPI2_SGE_FLAGS_SHIFT);

			break;
		default:
			break;
		}

		bzero(recv_memp, sizeof (MPI2_CONFIG_REPLY));
		configreply = (pMpi2ConfigReply_t)recv_memp;
		recv_numbytes = sizeof (MPI2_CONFIG_REPLY);

		if (mptsas_send_extended_config_request_msg(mpt,
		    MPI2_CONFIG_ACTION_PAGE_HEADER,
		    MPI2_CONFIG_EXTPAGETYPE_SAS_IO_UNIT,
		    0, page_number, 0, 0, 0, 0)) {
			goto cleanup;
		}

		if (mptsas_get_handshake_msg(mpt, recv_memp, recv_numbytes,
		    recv_accessp)) {
			goto cleanup;
		}

		iocstatus = ddi_get16(recv_accessp, &configreply->IOCStatus);
		iocstatus = MPTSAS_IOCSTATUS(iocstatus);

		if (iocstatus != MPI2_IOCSTATUS_SUCCESS) {
			mptsas_log(mpt, CE_WARN,
			    "mptsas_get_sas_io_unit_page_hndshk: read page "
			    "header iocstatus = 0x%x", iocstatus);
			goto cleanup;
		}

		if (action != MPI2_CONFIG_ACTION_PAGE_WRITE_NVRAM) {
			bzero(page_memp, reply_size);
		}

		if (mptsas_send_extended_config_request_msg(mpt, action,
		    MPI2_CONFIG_EXTPAGETYPE_SAS_IO_UNIT, 0, page_number,
		    ddi_get8(recv_accessp, &configreply->Header.PageVersion),
		    ddi_get16(recv_accessp, &configreply->ExtPageLength),
		    flags_length, page_cookie.dmac_laddress)) {
			goto cleanup;
		}

		if (mptsas_get_handshake_msg(mpt, recv_memp, recv_numbytes,
		    recv_accessp)) {
			goto cleanup;
		}

		iocstatus = ddi_get16(recv_accessp, &configreply->IOCStatus);
		iocstatus = MPTSAS_IOCSTATUS(iocstatus);

		if (iocstatus != MPI2_IOCSTATUS_SUCCESS) {
			mptsas_log(mpt, CE_WARN,
			    "mptsas_get_sas_io_unit_page_hndshk: IO unit "
			    "config failed for action %d, iocstatus = 0x%x",
			    action, iocstatus);
			goto cleanup;
		}

		switch (state) {
		case IOUC_READ_PAGE0:
			if ((ddi_dma_sync(page_dma_handle, 0, 0,
			    DDI_DMA_SYNC_FORCPU)) != DDI_SUCCESS) {
				goto cleanup;
			}

			num_phys = ddi_get8(page_accessp,
			    &sasioupage0->NumPhys);
			ASSERT(num_phys == mpt->m_num_phys);
			if (num_phys > MPTSAS_MAX_PHYS) {
				mptsas_log(mpt, CE_WARN, "Number of phys "
				    "supported by HBA (%d) is more than max "
				    "supported by driver (%d).  Driver will "
				    "not attach.", num_phys,
				    MPTSAS_MAX_PHYS);
				rval = DDI_FAILURE;
				goto cleanup;
			}
			for (i = start_phy; i < num_phys; i++, start_phy = i) {
				cpdi[i] = ddi_get32(page_accessp,
				    &sasioupage0->PhyData[i].
				    ControllerPhyDeviceInfo);
				port_flags = ddi_get8(page_accessp,
				    &sasioupage0->PhyData[i].PortFlags);

				mpt->m_phy_info[i].port_num =
				    ddi_get8(page_accessp,
				    &sasioupage0->PhyData[i].Port);
				mpt->m_phy_info[i].ctrl_devhdl =
				    ddi_get16(page_accessp, &sasioupage0->
				    PhyData[i].ControllerDevHandle);
				mpt->m_phy_info[i].attached_devhdl =
				    ddi_get16(page_accessp, &sasioupage0->
				    PhyData[i].AttachedDevHandle);
				mpt->m_phy_info[i].phy_device_type = cpdi[i];
				mpt->m_phy_info[i].port_flags = port_flags;

				if (port_flags & DISCOVERY_IN_PROGRESS) {
					retrypage0++;
					NDBG20(("Discovery in progress, can't "
					    "verify IO unit config, then NO.%d"
					    " times retry", retrypage0));
					break;
				} else {
					retrypage0 = 0;
				}
				if (!(port_flags & AUTO_PORT_CONFIGURATION)) {
					/*
					 * some PHY configuration described in
					 * SAS IO Unit Page1
					 */
					readpage1 = 1;
				}
			}

			/*
			 * retry 30 times if discovery is in process
			 */
			if (retrypage0 && (retrypage0 < 30)) {
				drv_usecwait(1000 * 100);
				state = IOUC_READ_PAGE0;
				break;
			} else if (retrypage0 == 30) {
				mptsas_log(mpt, CE_WARN,
				    "!Discovery in progress, can't "
				    "verify IO unit config, then after"
				    " 30 times retry, give up!");
				state = IOUC_DONE;
				rval = DDI_FAILURE;
				break;
			}

			if (readpage1 == 0) {
				state = IOUC_DONE;
				rval = DDI_SUCCESS;
				break;
			}

			state = IOUC_READ_PAGE1;
			break;

		case IOUC_READ_PAGE1:
			if ((ddi_dma_sync(page_dma_handle, 0, 0,
			    DDI_DMA_SYNC_FORCPU)) != DDI_SUCCESS) {
				goto cleanup;
			}

			num_phys = ddi_get8(page_accessp,
			    &sasioupage1->NumPhys);
			ASSERT(num_phys == mpt->m_num_phys);
			if (num_phys > MPTSAS_MAX_PHYS) {
				mptsas_log(mpt, CE_WARN, "Number of phys "
				    "supported by HBA (%d) is more than max "
				    "supported by driver (%d).  Driver will "
				    "not attach.", num_phys,
				    MPTSAS_MAX_PHYS);
				rval = DDI_FAILURE;
				goto cleanup;
			}
			for (i = 0; i < num_phys; i++) {
				cpdi[i] = ddi_get32(page_accessp,
				    &sasioupage1->PhyData[i].
				    ControllerPhyDeviceInfo);
				port_flags = ddi_get8(page_accessp,
				    &sasioupage1->PhyData[i].PortFlags);
				mpt->m_phy_info[i].port_num =
				    ddi_get8(page_accessp,
				    &sasioupage1->PhyData[i].Port);
				mpt->m_phy_info[i].port_flags = port_flags;
				mpt->m_phy_info[i].phy_device_type = cpdi[i];

			}

			state = IOUC_DONE;
			rval = DDI_SUCCESS;
			break;
		}
	}
	if ((mptsas_check_dma_handle(recv_dma_handle) != DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(page_dma_handle) != DDI_SUCCESS)) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		rval = DDI_FAILURE;
		goto cleanup;
	}
	if ((mptsas_check_acc_handle(recv_accessp) != DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(page_accessp) != DDI_SUCCESS)) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		rval = DDI_FAILURE;
		goto cleanup;
	}

cleanup:
	if (free_recv)
		mptsas_dma_addr_destroy(&recv_dma_handle, &recv_accessp);
	if (free_page)
		mptsas_dma_addr_destroy(&page_dma_handle, &page_accessp);
	if (rval != DDI_SUCCESS) {
		mptsas_fm_ereport(mpt, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_LOST);
	}
	return (rval);
}

/*
 * mptsas_get_manufacture_page5
 *
 * This function will retrieve the base WWID from the adapter.  Since this
 * function is only called during the initialization process, use handshaking.
 */
int
mptsas_get_manufacture_page5(mptsas_t *mpt)
{
	ddi_dma_attr_t			recv_dma_attrs, page_dma_attrs;
	ddi_dma_cookie_t		page_cookie;
	ddi_dma_handle_t		recv_dma_handle, page_dma_handle;
	ddi_acc_handle_t		recv_accessp, page_accessp;
	pMpi2ConfigReply_t		configreply;
	caddr_t				recv_memp, page_memp;
	int				recv_numbytes;
	pMpi2ManufacturingPage5_t	m5;
	uint32_t			flagslength;
	int				rval = DDI_SUCCESS;
	uint_t				iocstatus;
	boolean_t		free_recv = B_FALSE, free_page = B_FALSE;

	MPTSAS_DISABLE_INTR(mpt);

	if (mptsas_send_config_request_msg(mpt, MPI2_CONFIG_ACTION_PAGE_HEADER,
	    MPI2_CONFIG_PAGETYPE_MANUFACTURING, 0, 5, 0, 0, 0, 0)) {
		rval = DDI_FAILURE;
		goto done;
	}

	/*
	 * dynamically create a customized dma attribute structure
	 * that describes the MPT's config reply page request structure.
	 */
	recv_dma_attrs = mpt->m_msg_dma_attr;
	recv_dma_attrs.dma_attr_sgllen = 1;
	recv_dma_attrs.dma_attr_granular = (sizeof (MPI2_CONFIG_REPLY));

	if (mptsas_dma_addr_create(mpt, recv_dma_attrs,
	    &recv_dma_handle, &recv_accessp, &recv_memp,
	    (sizeof (MPI2_CONFIG_REPLY)), NULL) == FALSE) {
		rval = DDI_FAILURE;
		goto done;
	}
	/* Now safe to call mptsas_dma_addr_destroy(recv_dma_handle). */
	free_recv = B_TRUE;

	bzero(recv_memp, sizeof (MPI2_CONFIG_REPLY));
	configreply = (pMpi2ConfigReply_t)recv_memp;
	recv_numbytes = sizeof (MPI2_CONFIG_REPLY);

	/*
	 * get config reply message
	 */
	if (mptsas_get_handshake_msg(mpt, recv_memp, recv_numbytes,
	    recv_accessp)) {
		rval = DDI_FAILURE;
		goto done;
	}

	if (iocstatus = ddi_get16(recv_accessp, &configreply->IOCStatus)) {
		mptsas_log(mpt, CE_WARN, "mptsas_get_manufacture_page5 update: "
		    "IOCStatus=0x%x, IOCLogInfo=0x%x", iocstatus,
		    ddi_get32(recv_accessp, &configreply->IOCLogInfo));
		goto done;
	}

	/*
	 * dynamically create a customized dma attribute structure
	 * that describes the MPT's config page structure.
	 */
	page_dma_attrs = mpt->m_msg_dma_attr;
	page_dma_attrs.dma_attr_sgllen = 1;
	page_dma_attrs.dma_attr_granular = (sizeof (MPI2_CONFIG_PAGE_MAN_5));

	if (mptsas_dma_addr_create(mpt, page_dma_attrs, &page_dma_handle,
	    &page_accessp, &page_memp, (sizeof (MPI2_CONFIG_PAGE_MAN_5)),
	    &page_cookie) == FALSE) {
		rval = DDI_FAILURE;
		goto done;
	}
	/* Now safe to call mptsas_dma_addr_destroy(page_dma_handle). */
	free_page = B_TRUE;

	bzero(page_memp, sizeof (MPI2_CONFIG_PAGE_MAN_5));
	m5 = (pMpi2ManufacturingPage5_t)page_memp;
	NDBG20(("mptsas_get_manufacture_page5: paddr 0x%p",
	    (void *)(uintptr_t)page_cookie.dmac_laddress));

	/*
	 * Give reply address to IOC to store config page in and send
	 * config request out.
	 */

	flagslength = sizeof (MPI2_CONFIG_PAGE_MAN_5);
	flagslength |= ((uint32_t)(MPI2_SGE_FLAGS_LAST_ELEMENT |
	    MPI2_SGE_FLAGS_END_OF_BUFFER | MPI2_SGE_FLAGS_SIMPLE_ELEMENT |
	    MPI2_SGE_FLAGS_SYSTEM_ADDRESS | MPI2_SGE_FLAGS_64_BIT_ADDRESSING |
	    MPI2_SGE_FLAGS_IOC_TO_HOST |
	    MPI2_SGE_FLAGS_END_OF_LIST) << MPI2_SGE_FLAGS_SHIFT);

	if (mptsas_send_config_request_msg(mpt,
	    MPI2_CONFIG_ACTION_PAGE_READ_CURRENT,
	    MPI2_CONFIG_PAGETYPE_MANUFACTURING, 0, 5,
	    ddi_get8(recv_accessp, &configreply->Header.PageVersion),
	    ddi_get8(recv_accessp, &configreply->Header.PageLength),
	    flagslength, page_cookie.dmac_laddress)) {
		rval = DDI_FAILURE;
		goto done;
	}

	/*
	 * get reply view handshake
	 */
	if (mptsas_get_handshake_msg(mpt, recv_memp, recv_numbytes,
	    recv_accessp)) {
		rval = DDI_FAILURE;
		goto done;
	}

	if (iocstatus = ddi_get16(recv_accessp, &configreply->IOCStatus)) {
		mptsas_log(mpt, CE_WARN, "mptsas_get_manufacture_page5 config: "
		    "IOCStatus=0x%x, IOCLogInfo=0x%x", iocstatus,
		    ddi_get32(recv_accessp, &configreply->IOCLogInfo));
		goto done;
	}

	(void) ddi_dma_sync(page_dma_handle, 0, 0, DDI_DMA_SYNC_FORCPU);

	/*
	 * Fusion-MPT stores fields in little-endian format.  This is
	 * why the low-order 32 bits are stored first.
	 */
	mpt->un.sasaddr.m_base_wwid_lo =
	    ddi_get32(page_accessp, (uint32_t *)(void *)&m5->Phy[0].WWID);
	mpt->un.sasaddr.m_base_wwid_hi =
	    ddi_get32(page_accessp, (uint32_t *)(void *)&m5->Phy[0].WWID + 1);

	if (ddi_prop_update_int64(DDI_DEV_T_NONE, mpt->m_dip,
	    "base-wwid", mpt->un.m_base_wwid) != DDI_PROP_SUCCESS) {
		NDBG2(("%s%d: failed to create base-wwid property",
		    ddi_driver_name(mpt->m_dip), ddi_get_instance(mpt->m_dip)));
	}

	/*
	 * Set the number of PHYs present.
	 */
	mpt->m_num_phys = ddi_get8(page_accessp, (uint8_t *)&m5->NumPhys);

	if (ddi_prop_update_int(DDI_DEV_T_NONE, mpt->m_dip,
	    "num-phys", mpt->m_num_phys) != DDI_PROP_SUCCESS) {
		NDBG2(("%s%d: failed to create num-phys property",
		    ddi_driver_name(mpt->m_dip), ddi_get_instance(mpt->m_dip)));
	}

	mptsas_log(mpt, CE_NOTE, "!mpt%d: Initiator WWNs: 0x%016llx-0x%016llx",
	    mpt->m_instance, (unsigned long long)mpt->un.m_base_wwid,
	    (unsigned long long)mpt->un.m_base_wwid + mpt->m_num_phys - 1);

	if ((mptsas_check_dma_handle(recv_dma_handle) != DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(page_dma_handle) != DDI_SUCCESS)) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		rval = DDI_FAILURE;
		goto done;
	}
	if ((mptsas_check_acc_handle(recv_accessp) != DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(page_accessp) != DDI_SUCCESS)) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		rval = DDI_FAILURE;
	}
done:
	/*
	 * free up memory
	 */
	if (free_recv)
		mptsas_dma_addr_destroy(&recv_dma_handle, &recv_accessp);
	if (free_page)
		mptsas_dma_addr_destroy(&page_dma_handle, &page_accessp);
	MPTSAS_ENABLE_INTR(mpt);

	return (rval);
}

static int
mptsas_sasphypage_0_cb(mptsas_t *mpt, caddr_t page_memp,
    ddi_acc_handle_t accessp, uint16_t iocstatus, uint32_t iocloginfo,
    va_list ap)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(ap))
#endif
	pMpi2SasPhyPage0_t	sasphypage;
	int			rval = DDI_SUCCESS;
	uint16_t		*owner_devhdl, *attached_devhdl;
	uint8_t			*attached_phy_identify;
	uint32_t		*attached_phy_info;
	uint8_t			*programmed_link_rate;
	uint8_t			*hw_link_rate;
	uint8_t			*change_count;
	uint32_t		*phy_info;
	uint8_t			*negotiated_link_rate;
	uint32_t		page_address;

	if ((iocstatus != MPI2_IOCSTATUS_SUCCESS) &&
	    (iocstatus != MPI2_IOCSTATUS_CONFIG_INVALID_PAGE)) {
		mptsas_log(mpt, CE_WARN, "mptsas_get_sas_expander_page0 "
		    "config: IOCStatus=0x%x, IOCLogInfo=0x%x",
		    iocstatus, iocloginfo);
		rval = DDI_FAILURE;
		return (rval);
	}
	page_address = va_arg(ap, uint32_t);
	/*
	 * The INVALID_PAGE status is normal if using GET_NEXT_HANDLE and there
	 * are no more pages.  If everything is OK up to this point but the
	 * status is INVALID_PAGE, change rval to FAILURE and quit.  Also,
	 * signal that device traversal is complete.
	 */
	if (iocstatus == MPI2_IOCSTATUS_CONFIG_INVALID_PAGE) {
		if ((page_address & MPI2_SAS_EXPAND_PGAD_FORM_MASK) ==
		    MPI2_SAS_EXPAND_PGAD_FORM_GET_NEXT_HNDL) {
			mpt->m_done_traverse_smp = 1;
		}
		rval = DDI_FAILURE;
		return (rval);
	}
	owner_devhdl = va_arg(ap, uint16_t *);
	attached_devhdl = va_arg(ap, uint16_t *);
	attached_phy_identify = va_arg(ap, uint8_t *);
	attached_phy_info = va_arg(ap, uint32_t *);
	programmed_link_rate = va_arg(ap, uint8_t *);
	hw_link_rate = va_arg(ap, uint8_t *);
	change_count = va_arg(ap, uint8_t *);
	phy_info = va_arg(ap, uint32_t *);
	negotiated_link_rate = va_arg(ap, uint8_t *);

	sasphypage = (pMpi2SasPhyPage0_t)page_memp;

	*owner_devhdl =
	    ddi_get16(accessp, &sasphypage->OwnerDevHandle);
	*attached_devhdl =
	    ddi_get16(accessp, &sasphypage->AttachedDevHandle);
	*attached_phy_identify =
	    ddi_get8(accessp, &sasphypage->AttachedPhyIdentifier);
	*attached_phy_info =
	    ddi_get32(accessp, &sasphypage->AttachedPhyInfo);
	*programmed_link_rate =
	    ddi_get8(accessp, &sasphypage->ProgrammedLinkRate);
	*hw_link_rate =
	    ddi_get8(accessp, &sasphypage->HwLinkRate);
	*change_count =
	    ddi_get8(accessp, &sasphypage->ChangeCount);
	*phy_info =
	    ddi_get32(accessp, &sasphypage->PhyInfo);
	*negotiated_link_rate =
	    ddi_get8(accessp, &sasphypage->NegotiatedLinkRate);

	return (rval);
}

/*
 * Request MPI configuration page SAS phy page 0 to get DevHandle, phymask
 * and SAS address.
 */
int
mptsas_get_sas_phy_page0(mptsas_t *mpt, uint32_t page_address,
    smhba_info_t *info)
{
	int			rval = DDI_SUCCESS;

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Get the header and config page.  reply contains the reply frame,
	 * which holds status info for the request.
	 */
	rval = mptsas_access_config_page(mpt,
	    MPI2_CONFIG_ACTION_PAGE_READ_CURRENT,
	    MPI2_CONFIG_EXTPAGETYPE_SAS_PHY, 0, page_address,
	    mptsas_sasphypage_0_cb, page_address, &info->owner_devhdl,
	    &info->attached_devhdl, &info->attached_phy_identify,
	    &info->attached_phy_info, &info->programmed_link_rate,
	    &info->hw_link_rate, &info->change_count,
	    &info->phy_info, &info->negotiated_link_rate);

	return (rval);
}

static int
mptsas_sasphypage_1_cb(mptsas_t *mpt, caddr_t page_memp,
    ddi_acc_handle_t accessp, uint16_t iocstatus, uint32_t iocloginfo,
    va_list ap)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(ap))
#endif
	pMpi2SasPhyPage1_t	sasphypage;
	int			rval = DDI_SUCCESS;

	uint32_t		*invalid_dword_count;
	uint32_t		*running_disparity_error_count;
	uint32_t		*loss_of_dword_sync_count;
	uint32_t		*phy_reset_problem_count;
	uint32_t		page_address;

	if ((iocstatus != MPI2_IOCSTATUS_SUCCESS) &&
	    (iocstatus != MPI2_IOCSTATUS_CONFIG_INVALID_PAGE)) {
		mptsas_log(mpt, CE_WARN, "mptsas_get_sas_expander_page1 "
		    "config: IOCStatus=0x%x, IOCLogInfo=0x%x",
		    iocstatus, iocloginfo);
		rval = DDI_FAILURE;
		return (rval);
	}
	page_address = va_arg(ap, uint32_t);
	/*
	 * The INVALID_PAGE status is normal if using GET_NEXT_HANDLE and there
	 * are no more pages.  If everything is OK up to this point but the
	 * status is INVALID_PAGE, change rval to FAILURE and quit.  Also,
	 * signal that device traversal is complete.
	 */
	if (iocstatus == MPI2_IOCSTATUS_CONFIG_INVALID_PAGE) {
		if ((page_address & MPI2_SAS_EXPAND_PGAD_FORM_MASK) ==
		    MPI2_SAS_EXPAND_PGAD_FORM_GET_NEXT_HNDL) {
			mpt->m_done_traverse_smp = 1;
		}
		rval = DDI_FAILURE;
		return (rval);
	}

	invalid_dword_count = va_arg(ap, uint32_t *);
	running_disparity_error_count = va_arg(ap, uint32_t *);
	loss_of_dword_sync_count = va_arg(ap, uint32_t *);
	phy_reset_problem_count = va_arg(ap, uint32_t *);

	sasphypage = (pMpi2SasPhyPage1_t)page_memp;

	*invalid_dword_count =
	    ddi_get32(accessp, &sasphypage->InvalidDwordCount);
	*running_disparity_error_count =
	    ddi_get32(accessp, &sasphypage->RunningDisparityErrorCount);
	*loss_of_dword_sync_count =
	    ddi_get32(accessp, &sasphypage->LossDwordSynchCount);
	*phy_reset_problem_count =
	    ddi_get32(accessp, &sasphypage->PhyResetProblemCount);

	return (rval);
}

/*
 * Request MPI configuration page SAS phy page 0 to get DevHandle, phymask
 * and SAS address.
 */
int
mptsas_get_sas_phy_page1(mptsas_t *mpt, uint32_t page_address,
    smhba_info_t *info)
{
	int			rval = DDI_SUCCESS;

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Get the header and config page.  reply contains the reply frame,
	 * which holds status info for the request.
	 */
	rval = mptsas_access_config_page(mpt,
	    MPI2_CONFIG_ACTION_PAGE_READ_CURRENT,
	    MPI2_CONFIG_EXTPAGETYPE_SAS_PHY, 1, page_address,
	    mptsas_sasphypage_1_cb, page_address,
	    &info->invalid_dword_count,
	    &info->running_disparity_error_count,
	    &info->loss_of_dword_sync_count,
	    &info->phy_reset_problem_count);

	return (rval);
}
/*
 * mptsas_get_manufacture_page0
 *
 * This function will retrieve the base
 * Chip name, Board Name,Board Trace number from the adapter.
 * Since this function is only called during the
 * initialization process, use handshaking.
 */
int
mptsas_get_manufacture_page0(mptsas_t *mpt)
{
	ddi_dma_attr_t			recv_dma_attrs, page_dma_attrs;
	ddi_dma_cookie_t		page_cookie;
	ddi_dma_handle_t		recv_dma_handle, page_dma_handle;
	ddi_acc_handle_t		recv_accessp, page_accessp;
	pMpi2ConfigReply_t		configreply;
	caddr_t				recv_memp, page_memp;
	int				recv_numbytes;
	pMpi2ManufacturingPage0_t	m0;
	uint32_t			flagslength;
	int				rval = DDI_SUCCESS;
	uint_t				iocstatus;
	uint8_t				i = 0;
	boolean_t		free_recv = B_FALSE, free_page = B_FALSE;

	MPTSAS_DISABLE_INTR(mpt);

	if (mptsas_send_config_request_msg(mpt, MPI2_CONFIG_ACTION_PAGE_HEADER,
	    MPI2_CONFIG_PAGETYPE_MANUFACTURING, 0, 0, 0, 0, 0, 0)) {
		rval = DDI_FAILURE;
		goto done;
	}

	/*
	 * dynamically create a customized dma attribute structure
	 * that describes the MPT's config reply page request structure.
	 */
	recv_dma_attrs = mpt->m_msg_dma_attr;
	recv_dma_attrs.dma_attr_sgllen = 1;
	recv_dma_attrs.dma_attr_granular = (sizeof (MPI2_CONFIG_REPLY));

	if (mptsas_dma_addr_create(mpt, recv_dma_attrs, &recv_dma_handle,
	    &recv_accessp, &recv_memp, (sizeof (MPI2_CONFIG_REPLY)),
	    NULL) == FALSE) {
		rval = DDI_FAILURE;
		goto done;
	}
	/* Now safe to call mptsas_dma_addr_destroy(recv_dma_handle). */
	free_recv = B_TRUE;

	bzero(recv_memp, sizeof (MPI2_CONFIG_REPLY));
	configreply = (pMpi2ConfigReply_t)recv_memp;
	recv_numbytes = sizeof (MPI2_CONFIG_REPLY);

	/*
	 * get config reply message
	 */
	if (mptsas_get_handshake_msg(mpt, recv_memp, recv_numbytes,
	    recv_accessp)) {
		rval = DDI_FAILURE;
		goto done;
	}

	if (iocstatus = ddi_get16(recv_accessp, &configreply->IOCStatus)) {
		mptsas_log(mpt, CE_WARN, "mptsas_get_manufacture_page5 update: "
		    "IOCStatus=0x%x, IOCLogInfo=0x%x", iocstatus,
		    ddi_get32(recv_accessp, &configreply->IOCLogInfo));
		goto done;
	}

	/*
	 * dynamically create a customized dma attribute structure
	 * that describes the MPT's config page structure.
	 */
	page_dma_attrs = mpt->m_msg_dma_attr;
	page_dma_attrs.dma_attr_sgllen = 1;
	page_dma_attrs.dma_attr_granular = (sizeof (MPI2_CONFIG_PAGE_MAN_0));

	if (mptsas_dma_addr_create(mpt, page_dma_attrs, &page_dma_handle,
	    &page_accessp, &page_memp, (sizeof (MPI2_CONFIG_PAGE_MAN_0)),
	    &page_cookie) == FALSE) {
		rval = DDI_FAILURE;
		goto done;
	}
	/* Now safe to call mptsas_dma_addr_destroy(page_dma_handle). */
	free_page = B_TRUE;

	bzero(page_memp, sizeof (MPI2_CONFIG_PAGE_MAN_0));
	m0 = (pMpi2ManufacturingPage0_t)page_memp;

	/*
	 * Give reply address to IOC to store config page in and send
	 * config request out.
	 */

	flagslength = sizeof (MPI2_CONFIG_PAGE_MAN_0);
	flagslength |= ((uint32_t)(MPI2_SGE_FLAGS_LAST_ELEMENT |
	    MPI2_SGE_FLAGS_END_OF_BUFFER | MPI2_SGE_FLAGS_SIMPLE_ELEMENT |
	    MPI2_SGE_FLAGS_SYSTEM_ADDRESS | MPI2_SGE_FLAGS_64_BIT_ADDRESSING |
	    MPI2_SGE_FLAGS_IOC_TO_HOST |
	    MPI2_SGE_FLAGS_END_OF_LIST) << MPI2_SGE_FLAGS_SHIFT);

	if (mptsas_send_config_request_msg(mpt,
	    MPI2_CONFIG_ACTION_PAGE_READ_CURRENT,
	    MPI2_CONFIG_PAGETYPE_MANUFACTURING, 0, 0,
	    ddi_get8(recv_accessp, &configreply->Header.PageVersion),
	    ddi_get8(recv_accessp, &configreply->Header.PageLength),
	    flagslength, page_cookie.dmac_laddress)) {
		rval = DDI_FAILURE;
		goto done;
	}

	/*
	 * get reply view handshake
	 */
	if (mptsas_get_handshake_msg(mpt, recv_memp, recv_numbytes,
	    recv_accessp)) {
		rval = DDI_FAILURE;
		goto done;
	}

	if (iocstatus = ddi_get16(recv_accessp, &configreply->IOCStatus)) {
		mptsas_log(mpt, CE_WARN, "mptsas_get_manufacture_page0 config: "
		    "IOCStatus=0x%x, IOCLogInfo=0x%x", iocstatus,
		    ddi_get32(recv_accessp, &configreply->IOCLogInfo));
		goto done;
	}

	(void) ddi_dma_sync(page_dma_handle, 0, 0, DDI_DMA_SYNC_FORCPU);

	/*
	 * Fusion-MPT stores fields in little-endian format.  This is
	 * why the low-order 32 bits are stored first.
	 */

	for (i = 0; i < 16; i++) {
		mpt->m_MANU_page0.ChipName[i] =
		    ddi_get8(page_accessp,
		    (uint8_t *)(void *)&m0->ChipName[i]);
	}

	for (i = 0; i < 8; i++) {
		mpt->m_MANU_page0.ChipRevision[i] =
		    ddi_get8(page_accessp,
		    (uint8_t *)(void *)&m0->ChipRevision[i]);
	}

	for (i = 0; i < 16; i++) {
		mpt->m_MANU_page0.BoardName[i] =
		    ddi_get8(page_accessp,
		    (uint8_t *)(void *)&m0->BoardName[i]);
	}

	for (i = 0; i < 16; i++) {
		mpt->m_MANU_page0.BoardAssembly[i] =
		    ddi_get8(page_accessp,
		    (uint8_t *)(void *)&m0->BoardAssembly[i]);
	}

	for (i = 0; i < 16; i++) {
		mpt->m_MANU_page0.BoardTracerNumber[i] =
		    ddi_get8(page_accessp,
		    (uint8_t *)(void *)&m0->BoardTracerNumber[i]);
	}

	if ((mptsas_check_dma_handle(recv_dma_handle) != DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(page_dma_handle) != DDI_SUCCESS)) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		rval = DDI_FAILURE;
		goto done;
	}
	if ((mptsas_check_acc_handle(recv_accessp) != DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(page_accessp) != DDI_SUCCESS)) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		rval = DDI_FAILURE;
	}
done:
	/*
	 * free up memory
	 */
	if (free_recv)
		mptsas_dma_addr_destroy(&recv_dma_handle, &recv_accessp);
	if (free_page)
		mptsas_dma_addr_destroy(&page_dma_handle, &page_accessp);
	MPTSAS_ENABLE_INTR(mpt);

	return (rval);
}
