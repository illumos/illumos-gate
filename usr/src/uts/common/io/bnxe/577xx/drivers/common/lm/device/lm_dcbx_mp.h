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
 *    28/06/11 ShayH    Inception.
 ******************************************************************************/
#ifndef _LM_DCBX_MP_H
#define _LM_DCBX_MP_H

/*******************************************************************************
 * Constants.
 ******************************************************************************/
#define MAX_NUM_OF_ETH_CONS_PER_COS                 (MAX_RSS_CHAINS)
#define ETH_MP_MAX_COS_SUPPORTED                    (3)

/*******************************************************************************
 * Defines.
 ******************************************************************************/

#define MAX_ETH_TX_ONLY_CONS                        ((ETH_MP_MAX_COS_SUPPORTED - 1)*(MAX_NUM_OF_ETH_CONS_PER_COS))
#define MAX_ETH_TX_ONLY_CHAINS                      ((ETH_MP_MAX_COS_SUPPORTED - 1)*(MAX_HW_CHAINS))


typedef enum
{
    lm_chain_type_cos_reg       = 0,
    lm_chain_type_cos_tx_only   = 1,
    lm_chain_type_not_cos       = 2
}lm_chain_type_t;

/**
 * @description
 * Get COS number based on chain. 
 * If the chain doesn't belong to a specific COS (e.g. ISCSI L2 
 * chain) 
 * @param pdev 
 * @param chain 
 * 
 * @return u8_t 
 */
u8_t 
lm_mp_cos_from_chain(IN struct _lm_device_t *pdev, 
                     IN const u32_t         chain);

/**
 * @description
 * Get max cos chain used.
 * @param pdev 
 * @param chain 
 * @param cos 
 * 
 * @return u32_t 
 */
u8_t
lm_mp_max_cos_chain_used(
    IN struct _lm_device_t  *pdev);

#endif// _LM_DCBX_MP_H
