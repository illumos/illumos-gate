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
 *    28/06/11 Shay Haroush    Inception.
 ******************************************************************************/

#include "lm5710.h"
#include "lm_dcbx_mp.h"

/*******************************************************************************
 * Constants.
 ******************************************************************************/
#define MAX_NUM_OF_ACTIVE_ETH_CONS_PER_COS(_pdev)	LM_SB_CNT(_pdev)
#define ETH_CHAIN_COS0_START_OFFSET(_pdev)              (0)
#define ETH_CHAIN_COS1_START_OFFSET(_pdev)              (ETH_CHAIN_COS0_START_OFFSET(_pdev) + LM_SB_CNT(_pdev) + MAX_NON_RSS_CHAINS)
#define ETH_CHAIN_COS2_START_OFFSET(_pdev)              (ETH_CHAIN_COS1_START_OFFSET(_pdev) + LM_SB_CNT(_pdev))

/*******************************************************************************
 * Defines.
 ******************************************************************************/
#define ETH_IS_CHAIN_IN_COS0_RANGE(_pdev, _chain)   ( lm_mp_eth_is_chain_in_cosx_range(_pdev, _chain, ETH_CHAIN_COS0_START_OFFSET(_pdev)))
#define ETH_IS_CHAIN_IN_COS1_RANGE(_pdev, _chain)   ( lm_mp_eth_is_chain_in_cosx_range(_pdev, _chain, ETH_CHAIN_COS1_START_OFFSET(_pdev)))
#define ETH_IS_CHAIN_IN_COS2_RANGE(_pdev, _chain)   ( lm_mp_eth_is_chain_in_cosx_range(_pdev, _chain, ETH_CHAIN_COS2_START_OFFSET(_pdev)))
#define ETH_CID_COSX_END_OFFSET(_pdev, _val)        (_val + MAX_NUM_OF_ACTIVE_ETH_CONS_PER_COS(pdev))

/**
 * @description
 * Check if chain is in COS range based on COS start offset. 
 * @param chain 
 * @param cos_start_offset 
 * 
 * @return u8_t 
 */
STATIC u8_t 
lm_mp_eth_is_chain_in_cosx_range(
    IN lm_device_t  *pdev,
    IN const u32_t  chain, 
    IN const u32_t  cos_start_offset)
{
    if((cos_start_offset <= chain) &&
      (chain < ETH_CID_COSX_END_OFFSET(pdev, cos_start_offset)))
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}
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
                     IN const u32_t         chain)
{
    // Cos 0 is the default
    u8_t cos = ETH_MP_MAX_COS_SUPPORTED;

    if (ETH_IS_CHAIN_IN_COS0_RANGE(pdev, chain) )
    {
        cos = 0;
    }
    else if (ETH_IS_CHAIN_IN_COS1_RANGE(pdev, chain) )
    {
        cos = 1;
    }
    else if (ETH_IS_CHAIN_IN_COS2_RANGE(pdev, chain) )
    {
        cos = 2;
    }
    else
    {
        DbgMessage(pdev, INFORMi|INFORMl2sp, " lm_mp_cos_from_chain:  ");
    }
    return cos;
}
/**
 * @description
 * Return chain type.
 * @param pdev 
 * @param chain 
 * 
 * @return lm_chain_type_t 
 */
lm_chain_type_t
lm_mp_get_chain_type(IN struct _lm_device_t   *pdev, 
                     IN const u32_t           chain)
{
    const u8_t cos = lm_mp_cos_from_chain(pdev, chain);

    if (0 == cos)
    {
        return lm_chain_type_cos_reg;
    }
    else if (cos < ETH_MP_MAX_COS_SUPPORTED)
    {
        return lm_chain_type_cos_tx_only;
    }
    else
    {
        return lm_chain_type_not_cos;
    }
}
/**
 * @description
 * GET L2 chain COS start offset.
 * @param pdev 
 * @param cos 
 * 
 * @return u8_t 
 */
STATIC u8_t
lm_mp_get_eth_chain_cosx_start_offset(IN struct _lm_device_t    *pdev, 
                                      IN const u8_t             cos)
{
    u8_t cosx_start_offset = 0;

    switch(cos)
    {
    case 0:
        cosx_start_offset = ETH_CHAIN_COS0_START_OFFSET(pdev);
        break;
    case 1:
        cosx_start_offset = ETH_CHAIN_COS1_START_OFFSET(pdev);
        break;
    case 2:
        cosx_start_offset = ETH_CHAIN_COS2_START_OFFSET(pdev);
        break;
    default:
        DbgBreakMsg("invalid cos");
        cosx_start_offset = ETH_CHAIN_COS0_START_OFFSET(pdev);
    }

    return cosx_start_offset;
}
/**
 * @description
 * Get regular chain from chain. 
 * If chain isn't a COS chain(e.g. ISCSI L2) than return 
 * original value. 
 * @param pdev 
 * @param chain 
 * 
 * @return u32_t 
 */
u32_t 
lm_mp_get_reg_chain_from_chain(IN struct _lm_device_t   *pdev, 
                               IN u32_t                 chain)
{
    const u8_t cos          = lm_mp_cos_from_chain(pdev, chain);
    u8_t cosx_start_offset  = 0;

    if( cos >= ETH_MP_MAX_COS_SUPPORTED)
    {
        return chain;
    }

    cosx_start_offset = 
        lm_mp_get_eth_chain_cosx_start_offset(pdev,cos);

    chain -= cosx_start_offset;

    return chain;
}
/**
 * @description
 * Get COS chain from regular chain.
 * @param pdev 
 * @param chain 
 * @param cos 
 * 
 * @return u32_t 
 */
u8_t
lm_mp_get_cos_chain_from_reg_chain(
    IN struct _lm_device_t  *pdev, 
    INOUT u8_t              chain,
    INOUT const u8_t        cos)
{
    u8_t cosx_start_offset = 0;

    if( cos >= ETH_MP_MAX_COS_SUPPORTED)
    {
        return chain;
    }

    cosx_start_offset = 
        lm_mp_get_eth_chain_cosx_start_offset(pdev,cos);

    chain += cosx_start_offset;

    return chain;
}
/**
 * @description
 * Get max cos chain used.
 * @param pdev 
 * 
 * @return u32_t 
 */
u8_t
lm_mp_max_cos_chain_used(
    IN struct _lm_device_t  *pdev)
{
    const u8_t max_num_cos = lm_dcbx_cos_max_num(pdev);
    const u8_t cosx_start_offset = 
        lm_mp_get_eth_chain_cosx_start_offset(pdev, max_num_cos -1);
    const u8_t max_chain_used = ETH_CID_COSX_END_OFFSET(pdev, cosx_start_offset);

    DbgBreakIf(FALSE == MM_DCB_MP_L2_IS_ENABLE(pdev));
    DbgBreakIf(1 == max_num_cos);

    return max_chain_used;
}
