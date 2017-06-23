/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#ifndef __ECORE_PTP_H__
#define __ECORE_PTP_H__

enum _ecore_status_t ecore_ptp_hwtstamp_tx_on(struct ecore_hwfn *p_hwfn,
					      struct ecore_ptt *p_ptt);

enum _ecore_status_t ecore_ptp_cfg_rx_filters(struct ecore_hwfn *p_hwfn,
					      struct ecore_ptt *p_ptt,
					      enum ecore_ptp_filter_type type);

enum _ecore_status_t ecore_ptp_read_rx_ts(struct ecore_hwfn *p_hwfn,
					  struct ecore_ptt *p_ptt, u64 *ts);

enum _ecore_status_t ecore_ptp_read_tx_ts(struct ecore_hwfn *p_hwfn,
					  struct ecore_ptt *p_ptt, u64 *ts);

enum _ecore_status_t ecore_ptp_read_cc(struct ecore_hwfn *p_hwfn,
				       struct ecore_ptt *p_ptt, u64 *cycles);

enum _ecore_status_t ecore_ptp_adjfreq(struct ecore_hwfn *p_hwfn,
				       struct ecore_ptt *p_ptt, s32 ppb);

enum _ecore_status_t ecore_ptp_disable(struct ecore_hwfn *p_hwfn,
				       struct ecore_ptt *p_ptt);

enum _ecore_status_t ecore_ptp_enable(struct ecore_hwfn *p_hwfn,
				      struct ecore_ptt *p_ptt);

#endif /* __ECORE_PTP_H__ */
