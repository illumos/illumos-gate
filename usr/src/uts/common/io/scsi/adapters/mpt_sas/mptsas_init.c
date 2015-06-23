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
 * Copyright (c) 2014, Tegile Systems Inc. All rights reserved.
 */

/*
 * Copyright (c) 2000 to 2009, LSI Corporation.
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
 * mptsas_init - This file contains all the functions used to initialize
 * MPT2.0 based hardware.
 */

#if defined(lint) || defined(DEBUG)
#define	MPTSAS_DEBUG
#endif

/*
 * standard header files
 */
#include <sys/note.h>
#include <sys/scsi/scsi.h>

#pragma pack(1)
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_type.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_cnfg.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_init.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_ioc.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_tool.h>
#pragma pack()
/*
 * private header files.
 */
#include <sys/scsi/adapters/mpt_sas/mptsas_var.h>

static int mptsas_ioc_do_get_facts(mptsas_t *mpt, caddr_t memp, int var,
	ddi_acc_handle_t accessp);
static int mptsas_ioc_do_get_facts_reply(mptsas_t *mpt, caddr_t memp, int var,
	ddi_acc_handle_t accessp);
static int mptsas_ioc_do_get_port_facts(mptsas_t *mpt, caddr_t memp, int var,
	ddi_acc_handle_t accessp);
static int mptsas_ioc_do_get_port_facts_reply(mptsas_t *mpt, caddr_t memp,
    int var, ddi_acc_handle_t accessp);
static int mptsas_ioc_do_enable_port(mptsas_t *mpt, caddr_t memp, int var,
	ddi_acc_handle_t accessp);
static int mptsas_ioc_do_enable_port_reply(mptsas_t *mpt, caddr_t memp, int var,
	ddi_acc_handle_t accessp);
static int mptsas_ioc_do_enable_event_notification(mptsas_t *mpt, caddr_t memp,
	int var, ddi_acc_handle_t accessp);
static int mptsas_ioc_do_enable_event_notification_reply(mptsas_t *mpt,
    caddr_t memp, int var, ddi_acc_handle_t accessp);
static int mptsas_do_ioc_init(mptsas_t *mpt, caddr_t memp, int var,
	ddi_acc_handle_t accessp);
static int mptsas_do_ioc_init_reply(mptsas_t *mpt, caddr_t memp, int var,
	ddi_acc_handle_t accessp);

static const char *
mptsas_devid_type_string(mptsas_t *mpt)
{
	switch (mpt->m_devid) {
	case MPI2_MFGPAGE_DEVID_SAS2008:
		return ("SAS2008");
	case MPI2_MFGPAGE_DEVID_SAS2004:
		return ("SAS2004");
	case MPI2_MFGPAGE_DEVID_SAS2108_1:
	case MPI2_MFGPAGE_DEVID_SAS2108_2:
	case MPI2_MFGPAGE_DEVID_SAS2108_3:
		return ("SAS2108");
	case MPI2_MFGPAGE_DEVID_SAS2116_1:
	case MPI2_MFGPAGE_DEVID_SAS2116_2:
		return ("SAS2116");
	case MPI2_MFGPAGE_DEVID_SAS2208_1:
	case MPI2_MFGPAGE_DEVID_SAS2208_2:
	case MPI2_MFGPAGE_DEVID_SAS2208_3:
	case MPI2_MFGPAGE_DEVID_SAS2208_4:
	case MPI2_MFGPAGE_DEVID_SAS2208_5:
	case MPI2_MFGPAGE_DEVID_SAS2208_6:
		return ("SAS2208");
	case MPI2_MFGPAGE_DEVID_SAS2308_1:
	case MPI2_MFGPAGE_DEVID_SAS2308_2:
	case MPI2_MFGPAGE_DEVID_SAS2308_3:
		return ("SAS2308");
	case MPI25_MFGPAGE_DEVID_SAS3004:
		return ("SAS3004");
	case MPI25_MFGPAGE_DEVID_SAS3008:
		return ("SAS3008");
	case MPI25_MFGPAGE_DEVID_SAS3108_1:
	case MPI25_MFGPAGE_DEVID_SAS3108_2:
	case MPI25_MFGPAGE_DEVID_SAS3108_5:
	case MPI25_MFGPAGE_DEVID_SAS3108_6:
		return ("SAS3108");
	default:
		return ("?");
	}
}

int
mptsas_ioc_get_facts(mptsas_t *mpt)
{
	/*
	 * Send get facts messages
	 */
	if (mptsas_do_dma(mpt, sizeof (MPI2_IOC_FACTS_REQUEST), NULL,
	    mptsas_ioc_do_get_facts)) {
		return (DDI_FAILURE);
	}

	/*
	 * Get facts reply messages
	 */
	if (mptsas_do_dma(mpt, sizeof (MPI2_IOC_FACTS_REPLY), NULL,
	    mptsas_ioc_do_get_facts_reply)) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
mptsas_ioc_do_get_facts(mptsas_t *mpt, caddr_t memp, int var,
		ddi_acc_handle_t accessp)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(var))
#endif
	pMpi2IOCFactsRequest_t	facts;
	int			numbytes;

	bzero(memp, sizeof (*facts));
	facts = (void *)memp;
	ddi_put8(accessp, &facts->Function, MPI2_FUNCTION_IOC_FACTS);
	numbytes = sizeof (*facts);

	/*
	 * Post message via handshake
	 */
	if (mptsas_send_handshake_msg(mpt, memp, numbytes, accessp)) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
mptsas_ioc_do_get_facts_reply(mptsas_t *mpt, caddr_t memp, int var,
		ddi_acc_handle_t accessp)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(var))
#endif

	pMpi2IOCFactsReply_t	factsreply;
	int			numbytes;
	uint_t			iocstatus;
	char			buf[32];
	uint16_t		numReplyFrames;
	uint16_t		queueSize, queueDiff;
	int			simple_sge_main;
	int			simple_sge_next;
	uint32_t		capabilities;
	uint16_t		msgversion;

	bzero(memp, sizeof (*factsreply));
	factsreply = (void *)memp;
	numbytes = sizeof (*factsreply);

	/*
	 * get ioc facts reply message
	 */
	if (mptsas_get_handshake_msg(mpt, memp, numbytes, accessp)) {
		return (DDI_FAILURE);
	}

	if (iocstatus = ddi_get16(accessp, &factsreply->IOCStatus)) {
		mptsas_log(mpt, CE_WARN, "mptsas_ioc_do_get_facts_reply: "
		    "IOCStatus=0x%x, IOCLogInfo=0x%x", iocstatus,
		    ddi_get32(accessp, &factsreply->IOCLogInfo));
		return (DDI_FAILURE);
	}

	/*
	 * store key values from reply to mpt structure
	 */
	mpt->m_fwversion = ddi_get32(accessp, &factsreply->FWVersion.Word);
	mpt->m_productid = ddi_get16(accessp, &factsreply->ProductID);


	(void) sprintf(buf, "%u.%u.%u.%u",
	    ddi_get8(accessp, &factsreply->FWVersion.Struct.Major),
	    ddi_get8(accessp, &factsreply->FWVersion.Struct.Minor),
	    ddi_get8(accessp, &factsreply->FWVersion.Struct.Unit),
	    ddi_get8(accessp, &factsreply->FWVersion.Struct.Dev));
	mptsas_log(mpt, CE_NOTE, "?MPT Firmware version v%s (%s)\n",
	    buf, mptsas_devid_type_string(mpt));
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, mpt->m_dip,
	    "firmware-version", buf);

	/*
	 * Set up request info.
	 */
	mpt->m_max_requests = ddi_get16(accessp,
	    &factsreply->RequestCredit) - 1;
	mpt->m_req_frame_size = ddi_get16(accessp,
	    &factsreply->IOCRequestFrameSize) * 4;

	/*
	 * Size of reply free queue should be the number of requests
	 * plus some additional for events (32).  Make sure number of
	 * reply frames is not a multiple of 16 so that the queue sizes
	 * are calculated correctly later to be a multiple of 16.
	 */
	mpt->m_reply_frame_size = ddi_get8(accessp,
	    &factsreply->ReplyFrameSize) * 4;
	numReplyFrames = mpt->m_max_requests + 32;
	if (!(numReplyFrames % 16)) {
		numReplyFrames--;
	}
	mpt->m_max_replies = numReplyFrames;
	queueSize = numReplyFrames;
	queueSize += 16 - (queueSize % 16);
	mpt->m_free_queue_depth = queueSize;

	/*
	 * Size of reply descriptor post queue should be the number of
	 * request frames + the number of reply frames + 1 and needs to
	 * be a multiple of 16.  This size can be no larger than
	 * MaxReplyDescriptorPostQueueDepth from IOCFacts.  If the
	 * calculated queue size is larger than allowed, subtract a
	 * multiple of 16 from m_max_requests, m_max_replies, and
	 * m_reply_free_depth.
	 */
	queueSize = mpt->m_max_requests + numReplyFrames + 1;
	if (queueSize % 16) {
		queueSize += 16 - (queueSize % 16);
	}
	mpt->m_post_queue_depth = ddi_get16(accessp,
	    &factsreply->MaxReplyDescriptorPostQueueDepth);
	if (queueSize > mpt->m_post_queue_depth) {
		queueDiff = queueSize - mpt->m_post_queue_depth;
		if (queueDiff % 16) {
			queueDiff += 16 - (queueDiff % 16);
		}
		mpt->m_max_requests -= queueDiff;
		mpt->m_max_replies -= queueDiff;
		mpt->m_free_queue_depth -= queueDiff;
		queueSize -= queueDiff;
	}
	mpt->m_post_queue_depth = queueSize;

	/*
	 * Set up max chain depth.
	 */
	mpt->m_max_chain_depth = ddi_get8(accessp,
	    &factsreply->MaxChainDepth);
	mpt->m_ioc_capabilities = ddi_get32(accessp,
	    &factsreply->IOCCapabilities);

	/*
	 * Set flag to check for SAS3 support.
	 */
	msgversion = ddi_get16(accessp, &factsreply->MsgVersion);
	if (msgversion == MPI2_VERSION_02_05) {
		mptsas_log(mpt, CE_NOTE, "?mpt_sas%d SAS 3 Supported\n",
		    mpt->m_instance);
		mpt->m_MPI25 = TRUE;
	} else {
		mptsas_log(mpt, CE_NOTE, "?mpt_sas%d MPI Version 0x%x\n",
		    mpt->m_instance, msgversion);
	}

	/*
	 * Calculate max frames per request based on DMA S/G length.
	 */
	simple_sge_main = MPTSAS_MAX_FRAME_SGES64(mpt) - 1;
	simple_sge_next = mpt->m_req_frame_size / MPTSAS_SGE_SIZE(mpt) - 1;

	mpt->m_max_request_frames = (MPTSAS_MAX_DMA_SEGS -
	    simple_sge_main) / simple_sge_next + 1;
	if (((MPTSAS_MAX_DMA_SEGS - simple_sge_main) %
	    simple_sge_next) > 1) {
		mpt->m_max_request_frames++;
	}

	/*
	 * Check if controller supports FW diag buffers and set flag to enable
	 * each type.
	 */
	capabilities = ddi_get32(accessp, &factsreply->IOCCapabilities);
	if (capabilities & MPI2_IOCFACTS_CAPABILITY_DIAG_TRACE_BUFFER) {
		mpt->m_fw_diag_buffer_list[MPI2_DIAG_BUF_TYPE_TRACE].enabled =
		    TRUE;
	}
	if (capabilities & MPI2_IOCFACTS_CAPABILITY_SNAPSHOT_BUFFER) {
		mpt->m_fw_diag_buffer_list[MPI2_DIAG_BUF_TYPE_SNAPSHOT].
		    enabled = TRUE;
	}
	if (capabilities & MPI2_IOCFACTS_CAPABILITY_EXTENDED_BUFFER) {
		mpt->m_fw_diag_buffer_list[MPI2_DIAG_BUF_TYPE_EXTENDED].
		    enabled = TRUE;
	}

	/*
	 * Check if controller supports replaying events when issuing Message
	 * Unit Reset and set flag to enable MUR.
	 */
	if (capabilities & MPI2_IOCFACTS_CAPABILITY_EVENT_REPLAY) {
		mpt->m_event_replay = TRUE;
	}

	/*
	 * Check if controller supports IR.
	 */
	if (capabilities & MPI2_IOCFACTS_CAPABILITY_INTEGRATED_RAID) {
		mpt->m_ir_capable = TRUE;
	}

	return (DDI_SUCCESS);
}

int
mptsas_ioc_get_port_facts(mptsas_t *mpt, int port)
{
	/*
	 * Send get port facts message
	 */
	if (mptsas_do_dma(mpt, sizeof (MPI2_PORT_FACTS_REQUEST), port,
	    mptsas_ioc_do_get_port_facts)) {
		return (DDI_FAILURE);
	}

	/*
	 * Get port facts reply message
	 */
	if (mptsas_do_dma(mpt, sizeof (MPI2_PORT_FACTS_REPLY), port,
	    mptsas_ioc_do_get_port_facts_reply)) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
mptsas_ioc_do_get_port_facts(mptsas_t *mpt, caddr_t memp, int var,
			ddi_acc_handle_t accessp)
{
	pMpi2PortFactsRequest_t	facts;
	int			numbytes;

	bzero(memp, sizeof (*facts));
	facts = (void *)memp;
	ddi_put8(accessp, &facts->Function, MPI2_FUNCTION_PORT_FACTS);
	ddi_put8(accessp, &facts->PortNumber, var);
	numbytes = sizeof (*facts);

	/*
	 * Send port facts message via handshake
	 */
	if (mptsas_send_handshake_msg(mpt, memp, numbytes, accessp)) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
mptsas_ioc_do_get_port_facts_reply(mptsas_t *mpt, caddr_t memp, int var,
				ddi_acc_handle_t accessp)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(var))
#endif
	pMpi2PortFactsReply_t	factsreply;
	int			numbytes;
	uint_t			iocstatus;

	bzero(memp, sizeof (*factsreply));
	factsreply = (void *)memp;
	numbytes = sizeof (*factsreply);

	/*
	 * Get port facts reply message via handshake
	 */
	if (mptsas_get_handshake_msg(mpt, memp, numbytes, accessp)) {
		return (DDI_FAILURE);
	}

	if (iocstatus = ddi_get16(accessp, &factsreply->IOCStatus)) {
		mptsas_log(mpt, CE_WARN, "mptsas_ioc_do_get_port_facts_reply: "
		    "IOCStatus=0x%x, IOCLogInfo=0x%x", iocstatus,
		    ddi_get32(accessp, &factsreply->IOCLogInfo));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

int
mptsas_ioc_enable_port(mptsas_t *mpt)
{
	/*
	 * Send enable port message
	 */
	if (mptsas_do_dma(mpt, sizeof (MPI2_PORT_ENABLE_REQUEST), 0,
	    mptsas_ioc_do_enable_port)) {
		return (DDI_FAILURE);
	}

	/*
	 * Get enable port reply message
	 */
	if (mptsas_do_dma(mpt, sizeof (MPI2_PORT_ENABLE_REPLY), 0,
	    mptsas_ioc_do_enable_port_reply)) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
mptsas_ioc_do_enable_port(mptsas_t *mpt, caddr_t memp, int var,
	ddi_acc_handle_t accessp)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(var))
#endif
	pMpi2PortEnableRequest_t	enable;
	int				numbytes;

	bzero(memp, sizeof (*enable));
	enable = (void *)memp;
	ddi_put8(accessp, &enable->Function, MPI2_FUNCTION_PORT_ENABLE);
	numbytes = sizeof (*enable);

	/*
	 * Send message via handshake
	 */
	if (mptsas_send_handshake_msg(mpt, memp, numbytes, accessp)) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
mptsas_ioc_do_enable_port_reply(mptsas_t *mpt, caddr_t memp, int var,
	ddi_acc_handle_t accessp)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(var))
#endif

	int			numbytes;
	uint_t			iocstatus;
	pMpi2PortEnableReply_t	portreply;

	numbytes = sizeof (MPI2_PORT_ENABLE_REPLY);
	bzero(memp, numbytes);
	portreply = (void *)memp;

	/*
	 * Get message via handshake
	 */
	if (mptsas_get_handshake_msg(mpt, memp, numbytes, accessp)) {
		return (DDI_FAILURE);
	}

	if (iocstatus = ddi_get16(accessp, &portreply->IOCStatus)) {
		mptsas_log(mpt, CE_WARN, "mptsas_ioc_do_enable_port_reply: "
		    "IOCStatus=0x%x, IOCLogInfo=0x%x", iocstatus,
		    ddi_get32(accessp, &portreply->IOCLogInfo));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

int
mptsas_ioc_enable_event_notification(mptsas_t *mpt)
{
	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Send enable event notification message
	 */
	if (mptsas_do_dma(mpt, sizeof (MPI2_EVENT_NOTIFICATION_REQUEST), NULL,
	    mptsas_ioc_do_enable_event_notification)) {
		return (DDI_FAILURE);
	}

	/*
	 * Get enable event reply message
	 */
	if (mptsas_do_dma(mpt, sizeof (MPI2_EVENT_NOTIFICATION_REPLY), NULL,
	    mptsas_ioc_do_enable_event_notification_reply)) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
mptsas_ioc_do_enable_event_notification(mptsas_t *mpt, caddr_t memp, int var,
	ddi_acc_handle_t accessp)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(var))
#endif

	pMpi2EventNotificationRequest_t	event;
	int				numbytes;

	bzero(memp, sizeof (*event));
	event = (void *)memp;
	ddi_put8(accessp, &event->Function, MPI2_FUNCTION_EVENT_NOTIFICATION);
	numbytes = sizeof (*event);

	/*
	 * Send message via handshake
	 */
	if (mptsas_send_handshake_msg(mpt, memp, numbytes, accessp)) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
mptsas_ioc_do_enable_event_notification_reply(mptsas_t *mpt, caddr_t memp,
    int var, ddi_acc_handle_t accessp)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(var))
#endif
	int				numbytes;
	uint_t				iocstatus;
	pMpi2EventNotificationReply_t	eventsreply;

	numbytes = sizeof (MPI2_EVENT_NOTIFICATION_REPLY);
	bzero(memp, numbytes);
	eventsreply = (void *)memp;

	/*
	 * Get message via handshake
	 */
	if (mptsas_get_handshake_msg(mpt, memp, numbytes, accessp)) {
		return (DDI_FAILURE);
	}

	if (iocstatus = ddi_get16(accessp, &eventsreply->IOCStatus)) {
		mptsas_log(mpt, CE_WARN,
		    "mptsas_ioc_do_enable_event_notification_reply: "
		    "IOCStatus=0x%x, IOCLogInfo=0x%x", iocstatus,
		    ddi_get32(accessp, &eventsreply->IOCLogInfo));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

int
mptsas_ioc_init(mptsas_t *mpt)
{
	/*
	 * Send ioc init message
	 */
	if (mptsas_do_dma(mpt, sizeof (MPI2_IOC_INIT_REQUEST), NULL,
	    mptsas_do_ioc_init)) {
		return (DDI_FAILURE);
	}

	/*
	 * Get ioc init reply message
	 */
	if (mptsas_do_dma(mpt, sizeof (MPI2_IOC_INIT_REPLY), NULL,
	    mptsas_do_ioc_init_reply)) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
mptsas_do_ioc_init(mptsas_t *mpt, caddr_t memp, int var,
    ddi_acc_handle_t accessp)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(var))
#endif

	pMpi2IOCInitRequest_t	init;
	int			numbytes;
	timespec_t		time;
	uint64_t		mSec;

	bzero(memp, sizeof (*init));
	init = (void *)memp;
	ddi_put8(accessp, &init->Function, MPI2_FUNCTION_IOC_INIT);
	ddi_put8(accessp, &init->WhoInit, MPI2_WHOINIT_HOST_DRIVER);
	ddi_put16(accessp, &init->MsgVersion, MPI2_VERSION);
	ddi_put16(accessp, &init->HeaderVersion, MPI2_HEADER_VERSION);
	ddi_put16(accessp, &init->SystemRequestFrameSize,
	    mpt->m_req_frame_size / 4);
	ddi_put16(accessp, &init->ReplyDescriptorPostQueueDepth,
	    mpt->m_post_queue_depth);
	ddi_put16(accessp, &init->ReplyFreeQueueDepth,
	    mpt->m_free_queue_depth);

	/*
	 * These addresses are set using the DMA cookie addresses from when the
	 * memory was allocated.  Sense buffer hi address should be 0.
	 */
	ddi_put32(accessp, &init->SenseBufferAddressHigh,
	    (uint32_t)(mpt->m_req_sense_dma_addr >> 32));
	ddi_put32(accessp, &init->SystemReplyAddressHigh,
	    (uint32_t)(mpt->m_reply_frame_dma_addr >> 32));
	ddi_put32(accessp, &init->SystemRequestFrameBaseAddress.High,
	    (uint32_t)(mpt->m_req_frame_dma_addr >> 32));
	ddi_put32(accessp, &init->SystemRequestFrameBaseAddress.Low,
	    (uint32_t)mpt->m_req_frame_dma_addr);
	ddi_put32(accessp, &init->ReplyDescriptorPostQueueAddress.High,
	    (uint32_t)(mpt->m_post_queue_dma_addr >> 32));
	ddi_put32(accessp, &init->ReplyDescriptorPostQueueAddress.Low,
	    (uint32_t)mpt->m_post_queue_dma_addr);
	ddi_put32(accessp, &init->ReplyFreeQueueAddress.High,
	    (uint32_t)(mpt->m_free_queue_dma_addr >> 32));
	ddi_put32(accessp, &init->ReplyFreeQueueAddress.Low,
	    (uint32_t)mpt->m_free_queue_dma_addr);

	/*
	 * Fill in the timestamp with the number of milliseconds since midnight
	 * of January 1, 1970 UT (Greenwich Mean Time).  Time is returned in
	 * seconds and nanoseconds.  Translate both to milliseconds and add
	 * them together to get total milliseconds.
	 */
	gethrestime(&time);
	mSec = time.tv_sec * MILLISEC;
	mSec += (time.tv_nsec / MICROSEC);
	ddi_put32(accessp, &init->TimeStamp.High, (uint32_t)(mSec >> 32));
	ddi_put32(accessp, &init->TimeStamp.Low, (uint32_t)mSec);

	numbytes = sizeof (*init);

	/*
	 * Post message via handshake
	 */
	if (mptsas_send_handshake_msg(mpt, memp, numbytes, accessp)) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
mptsas_do_ioc_init_reply(mptsas_t *mpt, caddr_t memp, int var,
		ddi_acc_handle_t accessp)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(var))
#endif

	pMpi2IOCInitReply_t	initreply;
	int			numbytes;
	uint_t			iocstatus;

	numbytes = sizeof (MPI2_IOC_INIT_REPLY);
	bzero(memp, numbytes);
	initreply = (void *)memp;

	/*
	 * Get reply message via handshake
	 */
	if (mptsas_get_handshake_msg(mpt, memp, numbytes, accessp)) {
		return (DDI_FAILURE);
	}

	if (iocstatus = ddi_get16(accessp, &initreply->IOCStatus)) {
		mptsas_log(mpt, CE_WARN, "mptsas_do_ioc_init_reply: "
		    "IOCStatus=0x%x, IOCLogInfo=0x%x", iocstatus,
		    ddi_get32(accessp, &initreply->IOCLogInfo));
		return (DDI_FAILURE);
	}

	if ((ddi_get32(mpt->m_datap, &mpt->m_reg->Doorbell)) &
	    MPI2_IOC_STATE_OPERATIONAL) {
		mptsas_log(mpt, CE_NOTE,
		    "?mpt%d: IOC Operational.\n", mpt->m_instance);
	} else {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}
