/*******************************************************************************
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
 * Module Description:
 *
 *
 * History:
 *    02/05/07 Alon Elhanani    Inception. 
 ******************************************************************************/
#ifndef _DMAE_H
#define _DMAE_H

// DMAE commands allocations:

#define DMAE_CMD_DRV_0   0
#define DMAE_CMD_DRV_1   1
#define DMAE_CMD_DRV_2   2
#define DMAE_CMD_DRV_3   3
#define DMAE_CMD_DRV_4   4
#define DMAE_CMD_DRV_5   5
#define DMAE_CMD_DRV_6   6
#define DMAE_CMD_DRV_7   7
#define DMAE_CMD_DRV_8   8
#define DMAE_CMD_DRV_9   9
#define DMAE_CMD_DRV_10  10
#define DMAE_CMD_DRV_11  11
#define DMAE_CMD_DRV_12  12
#define DMAE_CMD_DRV_13  13
#define DMAE_CMD_MFW_0   14
#define DMAE_CMD_MFW_1   15

/* continue with other DAME clietns:
e.g.:
.
.
.
.
#define DMAE_CMD_XXX_1  15
*/

#endif // _DMAE_H
