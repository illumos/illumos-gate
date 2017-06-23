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

#ifndef GTT_REG_ADDR_H
#define GTT_REG_ADDR_H

/* Win 2 */
#define GTT_BAR0_MAP_REG_IGU_CMD                                                                             0x00f000UL //Access:RW   DataWidth:0x20   // 

/* Win 3 */
#define GTT_BAR0_MAP_REG_TSDM_RAM                                                                            0x010000UL //Access:RW   DataWidth:0x20   // 

/* Win 4 */
#define GTT_BAR0_MAP_REG_MSDM_RAM                                                                            0x011000UL //Access:RW   DataWidth:0x20   // 

/* Win 5 */
#define GTT_BAR0_MAP_REG_MSDM_RAM_1024                                                                       0x012000UL //Access:RW   DataWidth:0x20   // 

/* Win 6 */
#define GTT_BAR0_MAP_REG_USDM_RAM                                                                            0x013000UL //Access:RW   DataWidth:0x20   // 

/* Win 7 */
#define GTT_BAR0_MAP_REG_USDM_RAM_1024                                                                       0x014000UL //Access:RW   DataWidth:0x20   // 

/* Win 8 */
#define GTT_BAR0_MAP_REG_USDM_RAM_2048                                                                       0x015000UL //Access:RW   DataWidth:0x20   // 

/* Win 9 */
#define GTT_BAR0_MAP_REG_XSDM_RAM                                                                            0x016000UL //Access:RW   DataWidth:0x20   // 

/* Win 10 */
#define GTT_BAR0_MAP_REG_YSDM_RAM                                                                            0x017000UL //Access:RW   DataWidth:0x20   // 

/* Win 11 */
#define GTT_BAR0_MAP_REG_PSDM_RAM                                                                            0x018000UL //Access:RW   DataWidth:0x20   // 

#endif
