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
 * The following notice accompanied the original version of this file:
 *
 * BSD LICENSE
 *
 * Copyright(c) 2007 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef	_FCOE_H_
#define	_FCOE_H_

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

extern int			 fcoe_use_ext_log;
extern struct fcoe_soft_state	*fcoe_global_ss;

/*
 * Caution: 1) LOG will be available in debug/non-debug mode
 *	    2) Anything which can potentially flood the log should be under
 *	       extended logging, and use FCOE_EXT_LOG.
 *	    3) Don't use FCOE_EXT_LOG in performance-critical code path, such
 *	       as normal SCSI I/O code path. It could hurt system performance.
 *	    4) Use kmdb to change foce_use_ext_log in the fly to adjust
 *	       tracing
 */
#define	FCOE_EXT_LOG(log_ident, ...)	\
	do {	\
		if (fcoe_use_ext_log) {	\
			fcoe_trace(log_ident, __VA_ARGS__);	\
		}	\
	} while (0)

#define	FCOE_LOG(log_ident, ...)	\
	fcoe_trace(log_ident, __VA_ARGS__)

/*
 * There will be only one fcoe instance
 */
typedef struct fcoe_soft_state {
	dev_info_t	*ss_dip;
	uint32_t	 ss_flags;
	list_t		 ss_mac_list;
	uint32_t	 ss_ioctl_flags;
	kmutex_t	 ss_ioctl_mutex;

	/*
	 * watchdog stuff
	 */
	ddi_taskq_t	*ss_watchdog_taskq;
	kcondvar_t	 ss_watch_cv;
	kmutex_t	 ss_watch_mutex;
	list_t		 ss_pfrm_list;	/* Pending frame */
} fcoe_soft_state_t;

#define	SS_FLAG_TERMINATE_WATCHDOG	0x0020
#define	SS_FLAG_WATCHDOG_RUNNING	0x0040
#define	SS_FLAG_DOG_WAITING		0x0080

/*
 *  Driver name
 */
#define	FCOEI_DRIVER_NAME	"fcoei"
#define	FCOET_DRIVER_NAME	"fcoet"

/*
 * One for each ethernet port
 */
typedef struct fcoe_mac
{
	list_node_t		fm_ss_node;
	datalink_id_t		fm_linkid;
	uint32_t		fm_flags;

	fcoe_soft_state_t	*fm_ss;
	fcoe_port_t		fm_eport;
	fcoe_client_t		fm_client;
	dev_info_t		*fm_client_dev;

	mac_handle_t		fm_handle;
	mac_client_handle_t	fm_cli_handle;
	mac_promisc_handle_t	fm_promisc_handle;
	mac_notify_handle_t	fm_notify_handle;
	mac_unicast_handle_t	fm_unicst_handle;
	uint8_t			fm_primary_addr[ETHERADDRL];
	uint8_t			fm_current_addr[ETHERADDRL];
	uint32_t		fm_running:1,
				fm_force_promisc:1,
				fm_rsvd:18,
				fm_state:4,
				fm_link_state:8;
	uint32_t		fm_frm_cnt;
	kcondvar_t		fm_tx_cv;
	kmutex_t		fm_mutex;
} fcoe_mac_t;

#define	FCOE_MAC_STATE_OFFLINE		0x0
#define	FCOE_MAC_STATE_ONLINE		0x1

#define	FCOE_MAC_LINK_STATE_DOWN	0x00
#define	FCOE_MAC_LINK_STATE_UP		0x01

#define	FCOE_MAC_FLAG_ENABLED		0x01
#define	FCOE_MAC_FLAG_BOUND		0x02
#define	FCOE_MAC_FLAG_USER_DEL		0x04

typedef struct fcoe_frame_header {
	uint8_t		 ffh_ver[1];	/* version field - upper 4 bits */
	uint8_t		 ffh_resvd[12];
	uint8_t		 ffh_sof[1];	/* start of frame per RFC 3643 */
} fcoe_frame_header_t;

typedef struct fcoe_frame_tailer {
	uint8_t		 fft_crc[4];	/* FC packet CRC */
	uint8_t		 fft_eof[1];
	uint8_t		 fft_resvd[3];
} fcoe_frame_tailer_t;

/*
 * RAW frame structure
 * It is used to describe the content of every mblk
 */
typedef struct fcoe_i_frame {
	list_node_t		 fmi_pending_node;

	fcoe_frame_t		*fmi_frame;	/* to common struct */
	fcoe_mac_t		*fmi_mac;	/* to/from where */

	/*
	 * FRAME structure
	 */
	struct ether_header	*fmi_efh;	/* 14 bytes eth header */
	fcoe_frame_header_t	*fmi_ffh;	/* 14 bytes FCOE hader */
	uint8_t			*fmi_fc_frame;
	fcoe_frame_tailer_t	*fmi_fft;	/* 8 bytes FCOE tailer */
} fcoe_i_frame_t;

typedef struct fcoe_worker {
	list_t		worker_frm_list;
	kmutex_t	worker_lock;
	kcondvar_t	worker_cv;
	uint32_t	worker_flags;
	uint32_t	worker_ntasks;
} fcoe_worker_t;

#define	FCOE_WORKER_TERMINATE	0x01
#define	FCOE_WORKER_STARTED	0x02
#define	FCOE_WORKER_ACTIVE	0x04

/*
 * IOCTL supporting stuff
 */
#define	FCOE_IOCTL_FLAG_MASK		0xFF
#define	FCOE_IOCTL_FLAG_IDLE		0x00
#define	FCOE_IOCTL_FLAG_OPEN		0x01
#define	FCOE_IOCTL_FLAG_EXCL		0x02
#define	FCOE_IOCTL_FLAG_EXCL_BUSY	0x04

/*
 * define common-used macros to simplify coding
 */
#define	FCOE_FIP_TYPE		0x8914
#define	FCOE_802_1Q_TAG		0x8100

#define	PADDING_HEADER_SIZE	(sizeof (struct ether_header) + \
	sizeof (fcoe_frame_header_t))
#define	PADDING_SIZE	(PADDING_HEADER_SIZE + sizeof (fcoe_frame_tailer_t))

#define	EPORT2MAC(x_eport)	((fcoe_mac_t *)(x_eport)->eport_fcoe_private)

#define	FRM2MAC(x_frm)		(EPORT2MAC((x_frm)->frm_eport))
#define	FRM2FMI(x_frm)		((fcoe_i_frame_t *)(x_frm)->frm_fcoe_private)
#define	FRM2MBLK(x_frm)		((mblk_t *)(x_frm)->frm_netb)

#define	FCOE_VER			0
#define	FCOE_DECAPS_VER(x_ffh)		((x_ffh)->ffh_ver[0] >> 4)
#define	FCOE_ENCAPS_VER(x_ffh, x_v)			\
	{						\
		(x_ffh)->ffh_ver[0] = ((x_v) << 4);	\
	}

/*
 * fcoe driver common functions
 */
extern fcoe_mac_t *fcoe_lookup_mac_by_id(datalink_id_t);
extern void fcoe_destroy_mac(fcoe_mac_t *);
extern mblk_t *fcoe_get_mblk(fcoe_mac_t *, uint32_t);
extern void fcoe_post_frame(fcoe_frame_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _FCOE_H_ */
