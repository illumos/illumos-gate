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
 *
 ******************************************************************************/


/* The dest MAC address of GVRP is 01-80-C2-00-00-21 */
#define IS_GVRP_ADDR(_addr) \
    (((_addr)[0] == 0x01) && ((_addr)[1] == 0x80) && ((_addr)[2] == 0xC2) && ((_addr)[3] == 0x00) && ((_addr)[4] == 0x00) && ((_addr)[5] == 0x21))


/* The dest MAC address of LACP is 01-80-C2-00-00-02 */
#define IS_LACP_ADDR(_addr) \
    (((_addr)[0] == 0x01) && ((_addr)[1] == 0x80) && ((_addr)[2] == 0xC2) && ((_addr)[3] == 0x00) && ((_addr)[4] == 0x00) && ((_addr)[5] == 0x02))


