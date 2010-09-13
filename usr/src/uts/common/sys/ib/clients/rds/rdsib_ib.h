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
 * Copyright (c) 2005 SilverStorm Technologies, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
/*
 * Sun elects to include this software in Sun product
 * under the OpenIB BSD license.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _RDSIB_IB_H
#define	_RDSIB_IB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ib/ibtl/ibti.h>
#include "rdsib_debug.h"
#include "rdsib_protocol.h"

/*
 * Global Configuration Variables
 * As defined in RDS proposal
 */
extern uint_t		MaxNodes;
extern uint_t		UserBufferSize;
extern uint_t		RdsPktSize;
extern uint_t		NDataRX;
extern uint_t		MaxDataSendBuffers;
extern uint_t		MaxDataRecvBuffers;
extern uint_t		MaxCtrlSendBuffers;
extern uint_t		MaxCtrlRecvBuffers;
extern uint_t		DataRecvBufferLWM;
extern uint_t		CtrlRecvBufferLWM;
extern uint_t		PendingRxPktsHWM;
extern uint_t		MinRnrRetry;
extern uint8_t		IBPathRetryCount;
extern uint8_t		IBPktLifeTime;

#ifdef DEBUG
extern uint32_t		rdsdbglvl;
#else
extern uint32_t		rdsdbglvl;
#endif

/* performance tunables */
extern uint_t		rds_no_interrupts;
extern uint_t		rds_poll_percent_full;
extern uint_t		rds_wc_signal;
extern uint_t		rds_waittime_ms;

/* loopback port map */
#define			RDS_PORT_MAP_SIZE	8192
extern krwlock_t	rds_loopback_portmap_lock;
extern uint8_t		rds_loopback_portmap[RDS_PORT_MAP_SIZE];

extern ddi_taskq_t	*rds_taskq;
extern uint_t		rds_rx_pkts_pending_hwm; /* readonly */

/* Number of WCs to poll in a single call */
#define	RDS_NUM_DATA_SEND_WCS	10
#define	RDS_RDMAW_WRID	0xdabadaba
#define	RDS_NUM_ACKS	4 /* only 1 is used */

typedef enum rds_hca_state_s {
	RDS_HCA_STATE_ADDED		= 0,
	RDS_HCA_STATE_OPEN		= 1,
	RDS_HCA_STATE_MEM_REGISTERED	= 2,
	RDS_HCA_STATE_STOPPING		= 3,
	RDS_HCA_STATE_REMOVED		= 4
} rds_hca_state_t;

/*
 * There is one of this structure for each HCA in the system.
 * This holds all the information about the HCA.
 *
 * hca_nextp - Points to the next hca in the system.
 * hca_state - State of the hca (only modified on HCA attach/detach)
 * hca_guid - HCA Guid
 * hca_nports - Number of ports on the HCA
 * hca_hdl - HCA hdl obtained after opening the HCA
 * hca_pdhdl - PD hdl
 * hca_lkey - LKey for the registered global receive buffer pool memory
 * hca_rkey - Rkey for the registered global receive buffer pool memory
 * hca_attrp - HCA attributes
 * hca_pinfop - ptr to portinfo data, allocated by ibtf
 * hca_pinfo_sz - Sizeof of portinfo data
 */
typedef struct rds_hca_s {
	struct rds_hca_s	*hca_nextp;
	rds_hca_state_t		hca_state;
	ib_guid_t		hca_guid;
	uint_t			hca_nports;
	ibt_hca_hdl_t		hca_hdl;
	ibt_pd_hdl_t		hca_pdhdl;
	ibt_mr_hdl_t		hca_mrhdl;
	ibt_lkey_t		hca_lkey;
	ibt_rkey_t		hca_rkey;
	ibt_sbind_hdl_t		hca_bindhdl[4];
	ibt_hca_attr_t		hca_attr;
	ibt_hca_portinfo_t	*hca_pinfop;
	uint_t			hca_pinfo_sz;
} rds_hca_t;

/*
 * RDS Soft State
 * NOTE: Only one soft state per driver and NOT per instance.
 *
 * sessionlock - protects the rds_session_t:session_nextp, this lock has
 *      to be taken for read/write acess of the sessions list.
 * nsessions - Number of sessions in sessionlist
 * sessionlistp - Pointer to the first session.
 * ibhdl - Clnt handle acquired after registering with IBTF
 * nhcas - Number of HCAs initialized. This is also the number of rds_hca_t
 * 	structures in the rds_hcalistp.
 * hcalistp - list of rds_hca_t.
 * srvhdl - RDS service handle
 */
typedef struct rds_state_s {
	krwlock_t		rds_sessionlock;
	uint_t			rds_nsessions;
	struct rds_session_s	*rds_sessionlistp;
	ibt_clnt_hdl_t		rds_ibhdl;
	krwlock_t		rds_hca_lock;
	uint_t			rds_nhcas;
	rds_hca_t		*rds_hcalistp;
	ibt_srv_hdl_t		rds_srvhdl;
	ib_svc_id_t		rds_service_id;
} rds_state_t;

extern rds_state_t	*rdsib_statep; /* global */

/* defined in rds_cm.c */
ibt_srv_hdl_t rds_register_service(ibt_clnt_hdl_t rds_ibhdl);
int rds_bind_service(struct rds_state_s *statep);

/* defined in rds_ib.c */
void rds_recvcq_handler(ibt_cq_hdl_t cq, void *);
rds_hca_t *rds_gid_to_hcap(rds_state_t *statep, ib_gid_t gid);
rds_hca_t *rds_get_hcap(rds_state_t *statep, ib_guid_t guid);
int rdsib_initialize_ib();
void rdsib_deinitialize_ib();

/* defined in rds_debug.c */
void rds_logging_initialization();
void rds_logging_destroy();

#ifdef __cplusplus
}
#endif

#endif	/* _RDSIB_IB_H */
