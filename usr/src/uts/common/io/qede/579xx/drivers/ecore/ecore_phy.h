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

#ifndef __ECORE_PHY_H__
#define __ECORE_PHY_H__

#include "ecore_phy_api.h"

int ecore_phy_read(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
		   u32 port, u32 lane, u32 addr, u32 cmd, u8 *buf);
int ecore_phy_write(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
		    u32 port, u32 lane, u32 addr, u32 data_lo,
		    u32 data_hi, u32 cmd);

#endif /* __ECORE_PHY_H__ */
