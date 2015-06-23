/****************************************************************************
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
 *
 * Copyright 2014 QLogic Corporation
 * The contents of this file are subject to the terms of the
 * QLogic End User License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://www.qlogic.com/Resources/Documents/DriverDownloadHelp/
 * QLogic_End_User_Software_License.txt
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 *
 * Name: mac_stx.h
 *
 * Description: Host collected MAC statistics
 *
 * Author: Yitchak Gertner
 *
 * $Date: 2014/01/02 $       $Revision: #20 $
 ****************************************************************************/

#ifndef MAC_STX_H
#define MAC_STX_H


#include "mac_stats.h"
#include "mac_drv_info.h"


#define MAC_STX_NA                          0xffffffff


typedef struct emac_stats      emac_stats_t;
typedef struct bmac1_stats     bmac1_stats_t;
typedef struct bmac2_stats     bmac2_stats_t;
typedef union  mac_stats       mac_stats_t;
typedef struct mac_stx         mac_stx_t;
typedef struct host_port_stats host_port_stats_t;
typedef struct host_func_stats host_func_stats_t;


typedef struct fcoe_capabilities   fcoe_capabilities_t;
typedef struct port_info           port_info_t;
typedef struct eth_stats_info      eth_stats_info_t;
typedef struct fcoe_stats_info     fcoe_stats_info_t;
typedef struct fcoe_stats_enhanced fcoe_stats_enhanced_t;
typedef struct iscsi_stats_info    iscsi_stats_info_t;

#endif /* MAC_STX_H */

