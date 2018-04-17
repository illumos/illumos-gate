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

#ifndef _ECORE_IGU_DEF_H_
#define _ECORE_IGU_DEF_H_

/* Fields of IGU PF CONFIGRATION REGISTER */
#define IGU_PF_CONF_FUNC_EN       (0x1<<0)  /* function enable        */
#define IGU_PF_CONF_MSI_MSIX_EN   (0x1<<1)  /* MSI/MSIX enable        */
#define IGU_PF_CONF_INT_LINE_EN   (0x1<<2)  /* INT enable             */
#define IGU_PF_CONF_ATTN_BIT_EN   (0x1<<3)  /* attention enable       */
#define IGU_PF_CONF_SINGLE_ISR_EN (0x1<<4)  /* single ISR mode enable */
#define IGU_PF_CONF_SIMD_MODE     (0x1<<5)  /* simd all ones mode     */

/* Fields of IGU VF CONFIGRATION REGISTER */
#define IGU_VF_CONF_FUNC_EN        (0x1<<0)  /* function enable        */
#define IGU_VF_CONF_MSI_MSIX_EN    (0x1<<1)  /* MSI/MSIX enable        */
#define IGU_VF_CONF_SINGLE_ISR_EN  (0x1<<4)  /* single ISR mode enable */
#define IGU_VF_CONF_PARENT_MASK    (0xF)     /* Parent PF              */
#define IGU_VF_CONF_PARENT_SHIFT   5         /* Parent PF              */

/* Igu control commands
 */
enum igu_ctrl_cmd
{
	IGU_CTRL_CMD_TYPE_RD,
	IGU_CTRL_CMD_TYPE_WR,
	MAX_IGU_CTRL_CMD
};

/* Control register for the IGU command register
 */
struct igu_ctrl_reg
{
	u32 ctrl_data;
#define IGU_CTRL_REG_FID_MASK		0xFFFF /* Opaque_FID	 */
#define IGU_CTRL_REG_FID_SHIFT		0
#define IGU_CTRL_REG_PXP_ADDR_MASK	0xFFF /* Command address */
#define IGU_CTRL_REG_PXP_ADDR_SHIFT	16
#define IGU_CTRL_REG_RESERVED_MASK	0x1
#define IGU_CTRL_REG_RESERVED_SHIFT	28
#define IGU_CTRL_REG_TYPE_MASK		0x1 /* use enum igu_ctrl_cmd */
#define IGU_CTRL_REG_TYPE_SHIFT		31
};

#endif
