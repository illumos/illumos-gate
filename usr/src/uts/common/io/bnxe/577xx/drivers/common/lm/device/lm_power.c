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
 *      This file contains functions that handle power management and WOL
 *      functionality
 *
 ******************************************************************************/

#include "lm5710.h"

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
u32_t
init_nwuf_57710(
    lm_device_t *pdev,
    lm_nwuf_list_t *nwuf_list)
{
    lm_nwuf_t* nwuf       = NULL ;
    u32_t      nwuf_cnt   = 0 ;
    u32_t      offset     = 0 ;
    u8_t       mask       = 0 ;
    u32_t      val        = 0 ;
    u64_t      val_64     = 0 ;
    u32_t      val_32[2]  = {0} ;
    u32_t      mod        = 0 ;
    u32_t      idx        = 0 ;
    u32_t      bit        = 0 ;
    u32_t      reg_len    = 0 ;
    u32_t      reg_crc    = 0 ;
    u32_t      reg_be     = 0 ;
    u32_t      reg_offset = 0 ;
    if CHK_NULL(pdev)
    {
        return 0 ;
    }
    ASSERT_STATIC(LM_NWUF_PATTERN_SIZE <= 128 );
    // Write the size + crc32 of the patterns
    for(idx = 0; idx < LM_MAX_NWUF_CNT; idx++)
    {
        nwuf = &nwuf_list->nwuf_arr[idx];
        // find NIG registers names
#define LM_NIG_ACPI_PAT_LEN_IDX(_func,_idx) NIG_REG_LLH##_func##_ACPI_PAT_##_idx##_LEN
#define LM_NIG_ACPI_PAT_CRC_IDX(_func,_idx) NIG_REG_LLH##_func##_ACPI_PAT_##_idx##_CRC
        switch( idx )
        { /* TBD - E1H: currenlty assuming split registers in NIG */
        case 0:
            reg_len = (0 == PORT_ID(pdev)) ? LM_NIG_ACPI_PAT_LEN_IDX(0,0) : LM_NIG_ACPI_PAT_LEN_IDX(1,0) ;
            reg_crc = (0 == PORT_ID(pdev)) ? LM_NIG_ACPI_PAT_CRC_IDX(0,0) : LM_NIG_ACPI_PAT_CRC_IDX(1,0) ;
            break;
        case 1:
            reg_len = (0 == PORT_ID(pdev)) ? LM_NIG_ACPI_PAT_LEN_IDX(0,1) : LM_NIG_ACPI_PAT_LEN_IDX(1,1) ;
            reg_crc = (0 == PORT_ID(pdev)) ? LM_NIG_ACPI_PAT_CRC_IDX(0,1) : LM_NIG_ACPI_PAT_CRC_IDX(1,1) ;
            break;
        case 2:
            reg_len = (0 == PORT_ID(pdev)) ? LM_NIG_ACPI_PAT_LEN_IDX(0,2) : LM_NIG_ACPI_PAT_LEN_IDX(1,2) ;
            reg_crc = (0 == PORT_ID(pdev)) ? LM_NIG_ACPI_PAT_CRC_IDX(0,2) : LM_NIG_ACPI_PAT_CRC_IDX(1,2) ;
            break;
        case 3:
            reg_len = (0 == PORT_ID(pdev)) ? LM_NIG_ACPI_PAT_LEN_IDX(0,3) : LM_NIG_ACPI_PAT_LEN_IDX(1,3) ;
            reg_crc = (0 == PORT_ID(pdev)) ? LM_NIG_ACPI_PAT_CRC_IDX(0,3) : LM_NIG_ACPI_PAT_CRC_IDX(1,3) ;
            break;
        case 4:
            reg_len = (0 == PORT_ID(pdev)) ? LM_NIG_ACPI_PAT_LEN_IDX(0,4) : LM_NIG_ACPI_PAT_LEN_IDX(1,4) ;
            reg_crc = (0 == PORT_ID(pdev)) ? LM_NIG_ACPI_PAT_CRC_IDX(0,4) : LM_NIG_ACPI_PAT_CRC_IDX(1,4) ;
            break;
        case 5:
            reg_len = (0 == PORT_ID(pdev)) ? LM_NIG_ACPI_PAT_LEN_IDX(0,5) : LM_NIG_ACPI_PAT_LEN_IDX(1,5) ;
            reg_crc = (0 == PORT_ID(pdev)) ? LM_NIG_ACPI_PAT_CRC_IDX(0,5) : LM_NIG_ACPI_PAT_CRC_IDX(1,5) ;
            break;
        case 6:
            reg_len = (0 == PORT_ID(pdev)) ? LM_NIG_ACPI_PAT_LEN_IDX(0,6) : LM_NIG_ACPI_PAT_LEN_IDX(1,6) ;
            reg_crc = (0 == PORT_ID(pdev)) ? LM_NIG_ACPI_PAT_CRC_IDX(0,6) : LM_NIG_ACPI_PAT_CRC_IDX(1,6) ;
            break;
        case 7:
            reg_len = (0 == PORT_ID(pdev)) ? LM_NIG_ACPI_PAT_LEN_IDX(0,7) : LM_NIG_ACPI_PAT_LEN_IDX(1,7) ;
            reg_crc = (0 == PORT_ID(pdev)) ? LM_NIG_ACPI_PAT_CRC_IDX(0,7) : LM_NIG_ACPI_PAT_CRC_IDX(1,7) ;
            break;
        default:
            DbgBreakMsg("Invalid index\n") ;
            return 0 ;
        } // switch idx
        // write pattern length
        val = nwuf->pattern_size;
        DbgMessage(pdev, VERBOSE, "init_nwuf_57710: idx[%d] crc_mask=0x%08x size=%d\n", idx, nwuf->crc32, val  );
        // Init NIG registers
#if !(defined(DOS) || defined(__LINUX))
        if (0)
        {
            val = min( nwuf->size * 8, 64 ) ;
            if( val != nwuf->size * 8 )
            {
                DbgMessage(pdev, WARN, "init_nwuf_57710: idx[%d] Updated size=%03d-->%03d\n", idx, nwuf->size * 8, val ) ;
            }
        }
#endif
        REG_WR( pdev,  reg_len, val ) ;
        // write crc value
        val = nwuf->crc32 ;
        REG_WR( pdev,  reg_crc, val ) ;
     } // LM_MAX_NWUF_CNT loop
    // byte enable mask
    reg_be = (0 == PORT_ID(pdev)) ? NIG_REG_LLH0_ACPI_BE_MEM_DATA : NIG_REG_LLH1_ACPI_BE_MEM_DATA ;
// create a matrix following LLH_vlsi_spec_rev4.doc document:
//
//        63                                                     56      7                                                        0
//        +------------------------------------------------------------------------------------------------------------------------+
//word 0  |Pattern 7 bit 0 | Pattern 6 bit 0 |....|Pattern 0 bit 0|..... |Pattern 7 bit 7 | Pattern 6 bit 7 |....|Pattern 0 bit 7  |
//        +------------------------------------------------------------------------------------------------------------------------+
//word 1  |Pattern 7 bit 8 | Pattern 6 bit 8 |....|Pattern 0 bit 8|..... |Pattern 7 bit 15| Pattern 6 bit 15|....|Pattern 0 bit 15 |
//        +------------------------------------------------------------------------------------------------------------------------+
//        |                                                      ..........                                                        |
//        +------------------------------------------------------------------------------------------------------------------------+
//        |                                                      ..........                                                        |
//        +------------------------------------------------------------------------------------------------------------------------+
//        |                                                                                                                        |
//        +------------------------------------------------------------------------------------------------------------------------+
//        |                                                      ..........                                                        |
//        +------------------------------------------------------------------------------------------------------------------------+
//word 15 |Pattern 7bit 120| Pattern6 bit120 |....|Pattern0 bit120|..... |Pattern7 bit 127| Pattern6 bit 127|....|Pattern0 bit 127 |
//        +------------------------------------------------------------------------------------------------------------------------+

    for(offset = 0; offset <= LM_NWUF_PATTERN_SIZE; offset++)
    {
        mod = offset%8 ;
        if ( ( 0 == mod ) && ( offset!= 0 ) )
        {
            // write to the registers, WB (write using DMAE)
            reg_offset  = ( offset / 8 ) - 1  ; // 0 - 15
            val = (reg_offset*sizeof(u64_t)) ;
            // For yet to be explained reasons, using WR_DMAE write it to the opposite port.
            // We'll always use indirect writes
            if( 0 )//pdev->vars.b_is_dmae_ready )
            {
                REG_WR_DMAE( pdev,  reg_be+val, &val_64 ) ;
            }
            else
            {
                val_32[0] = U64_LO(val_64);
                val_32[1] = U64_HI(val_64);
                REG_WR_IND( pdev,  reg_be+val,   val_32[0] ) ;
                REG_WR_IND( pdev,  reg_be+val+4, val_32[1] ) ;
            }
            // reset for next 8 iterations
            val_64 = 0 ;
        }
        // after write - nothing to do!
        if( LM_NWUF_PATTERN_SIZE == offset )
        {
            break ;
        }
        for(idx = 0; idx < LM_MAX_NWUF_CNT; idx++)
        {
            nwuf = &nwuf_list->nwuf_arr[idx];
            if(nwuf->size == 0 || offset > nwuf->size * 8)
            {
                continue;
            }
            mask = nwuf->mask[(offset/8)]; // 0-15
            bit = mod ;
            if( mask & (1 << bit) )
            {
                val_64  |= 0x1ULL << idx;
            }
        } // LM_MAX_NWUF_CNT
        if( mod != 7 )
        {
            val_64  = val_64 << 8 ;
        }
    } // LM_NWUF_PATTERN_SIZE
    nwuf_cnt = 0;
    // count total items
    for(idx = 0; idx < LM_MAX_NWUF_CNT; idx++)
    {
        nwuf = &nwuf_list->nwuf_arr[idx];
        if(nwuf->size == 0)
        {
            continue;
        }
        nwuf_cnt++ ;
    }
    return nwuf_cnt;
} /* init_nwuf_57510 */

/*******************************************************************************
 * Description:
 *         Configures nwuf packets.
 *         (for wide bus)
 * Return:
 ******************************************************************************/
void lm_set_d3_nwuf(       lm_device_t*      pdev,
                     const lm_wake_up_mode_t wake_up_mode )
{
    const u8_t port_id     = PORT_ID(pdev);
    u8_t  abs_func_id      = ABS_FUNC_ID(pdev); // for debugging only
    u8_t  nwuf_reg_value   = 0 ;
    u32_t cnt              = 0 ;
    u32_t offset           = 0;

    UNREFERENCED_PARAMETER_( abs_func_id );

    /* Set up interesting packet detection. */
    if ( 0 != GET_FLAGS(wake_up_mode, LM_WAKE_UP_MODE_NWUF) )
    {
        // This comment - from TETON
        /* Also need to be documented in the prm - to prevent a false
         * detection, we need to disable ACP_EN if there is no pattern
         * programmed.  There is no way of preventing false detection
         * by intializing the pattern buffer a certain way. */
        if( (cnt = init_nwuf_57710(pdev, &pdev->nwuf_list)) )
        {
            DbgMessage(pdev, WARN, "LM_WAKE_UP_MODE_NWUF is ON cnt=%d\n", cnt );
            nwuf_reg_value = 1 ;
        }
        else
        {
            DbgMessage(pdev, WARN , "LM_WAKE_UP_MODE_NWUF is ON cnt=0\n" );
            nwuf_reg_value = 0 ;
        }

        // Enable ACPI register (split)
        offset = (0 == port_id) ? NIG_REG_LLH0_ACPI_ENABLE :NIG_REG_LLH1_ACPI_ENABLE;
        REG_WR( pdev, offset, nwuf_reg_value ) ;

        if( !CHIP_IS_E1(pdev) )
        {
            // mark function for enablement in nig
            lm_set_func_en(pdev, TRUE);

            // for E2 and above, we need to set also NIG_REG_PX_ACPI_MF_GLOBAL_EN to 1
            // This register is global per port.
            // The "algorithm" will be - if ANY of the vnic is enabled - we enable ACPI for the port (logic OR)
            // The patterns themselves should prevent a "false positive" wake up for a function
            // All the above is relevant for MF SI mode!
            if ( !CHIP_IS_E1x(pdev)   &&
                 nwuf_reg_value       &&
                 ( IS_MF_SI_MODE(pdev) ) )
            {
                // TODO - NIV (T7.0) should be different behaviour!
                DbgBreakIf( CHIP_IS_E1(pdev) ); // if someone will take this if block out of "if( !IS_E1(pdev)"
                DbgBreakIf( !nwuf_reg_value );

                offset = (0 == port_id) ? NIG_REG_P0_ACPI_MF_GLOBAL_EN :NIG_REG_P1_ACPI_MF_GLOBAL_EN;

                REG_WR( pdev, offset, nwuf_reg_value ) ;
            }
        }
        DbgMessage(pdev, WARN, "ACPI_ENABLE=%d\n", nwuf_reg_value );
    }
    else
    {
        DbgMessage(pdev, WARN , "LM_WAKE_UP_MODE_NWUF is OFF\n" );
    }
} /* lm_set_d3_nwuf */
/*******************************************************************************
 * Description:
 *         Configures magic packets.
 * Return:
 ******************************************************************************/
void lm_set_d3_mpkt( lm_device_t*            pdev,
                     const lm_wake_up_mode_t wake_up_mode )
{
    u32_t       emac_base     = 0 ;
    u32_t       val           = 0 ;
    u32_t       offset        = 0 ;
    u8_t  const b_enable_mpkt = ( 0 != GET_FLAGS(wake_up_mode, LM_WAKE_UP_MODE_MAGIC_PACKET) );
    u8_t*       mac_addr      = &pdev->params.mac_addr[0]; //&pdev->hw_info.mac_addr[0];

    if CHK_NULL(pdev)
    {
        DbgBreakIf(!pdev) ;
        return;
    }
    /* Set up magic packet detection. */
    if( b_enable_mpkt )
    {
        DbgMessage(pdev, WARN , "LM_WAKE_UP_MODE_MAGIC_PACKET is ON\n" );
    }
    else
    {
        DbgMessage(pdev, WARN , "LM_WAKE_UP_MODE_MAGIC_PACKET is OFF\n" );
    }
    emac_base = ( 0 == PORT_ID(pdev) ) ? GRCBASE_EMAC0 : GRCBASE_EMAC1 ;

    /* The mac address is written to entries 1-5 to
       preserve entry 0 which is used by the PMF */
    val = (mac_addr[0] << 8) | mac_addr[1];
    offset = EMAC_REG_EMAC_MAC_MATCH + (VNIC_ID(pdev)+ 1)*8 ;
    REG_WR(pdev, emac_base+ offset , b_enable_mpkt ? val:0);

    val = (mac_addr[2] << 24) | (mac_addr[3] << 16) |
          (mac_addr[4] << 8)  |  mac_addr[5];
    offset+= 4;
    REG_WR(pdev, emac_base+ offset, b_enable_mpkt ? val:0);
}

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
set_d0_power_state(
    lm_device_t *pdev,
    u8_t set_pci_pm)
{
    u32_t idx = 0;
    UNREFERENCED_PARAMETER_(set_pci_pm);
    DbgMessage(pdev, INFORM, "### set_d0_power_state\n");
#if 0
    u32_t val;
    /* This step should be done by the OS or the caller.  Windows is
     * already doing this. */
    if(set_pci_pm)
    {
        /* Set the device to D0 state.  If a device is already in D3 state,
         * we will not be able to read the PCICFG_PM_CSR register using the
         * PCI memory command, we need to use config access here. */
        mm_read_pci(
            pdev,
            OFFSETOF(reg_space_t, pci_config.pcicfg_pm_csr),
            &val);
        /* Set the device to D0 state.  This may be already done by the OS. */
        val &= ~PCICFG_PM_CSR_STATE;
        val |= PCICFG_PM_CSR_STATE_D0 | PCICFG_PM_CSR_PME_STATUS;
        mm_write_pci(
            pdev,
            OFFSETOF(reg_space_t, pci_config.pcicfg_pm_csr),
            val);
    }
#endif
    /* With 5706_A1, the chip gets a reset coming out of D3.  Wait
     * for the boot to code finish running before we continue.  Without
     * this wait, we could run into lockup or the PHY may not work. */
    if(CHIP_ID(pdev) == CHIP_ID_5706_A1)
    {
        for(idx = 0; idx < 1000; idx++)
        {
            mm_wait(pdev, 15);
        }
    }
#if 0 // PWR_TODO - WOL wait for spec
    /* Clear the ACPI_RCVD and MPKT_RCVD bits and disable magic packet. */
    val = REG_RD(pdev, emac.emac_mode);
    val |= EMAC_MODE_MPKT_RCVD | EMAC_MODE_ACPI_RCVD;
    val &= ~EMAC_MODE_MPKT;
    REG_WR(pdev, emac.emac_mode, val);
    /* Disable interesting packet detection. */
    val = REG_RD(pdev, rpm.rpm_config);
    val &= ~RPM_CONFIG_ACPI_ENA;
    REG_WR(pdev, rpm.rpm_config, val);
#endif // if 0
} /* set_d0_power_state */


/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_set_power_state(
    lm_device_t*      pdev,
    lm_power_state_t  power_state,
    lm_wake_up_mode_t wake_up_mode,     /* Valid when power_state is D3. */
    u8_t              set_pci_pm )
{
    UNREFERENCED_PARAMETER_(wake_up_mode);
    switch( power_state )
    {
    case LM_POWER_STATE_D0:
        set_d0_power_state(pdev, set_pci_pm);
        break;
    default:
        //set_d3_power_state(pdev, wake_up_mode, set_pci_pm);
        break;
    }
} /* lm_set_power_state */

void lm_set_func_en(struct _lm_device_t *pdev, const u8_t b_enable)
{
    const u8_t bus_num = INST_ID_TO_BUS_NUM(PFDEV(pdev)->vars.inst_id) ;

    if (pdev->params.pfunc_abs < ARRSIZE(g_lm_chip_global[0].func_en))
    {
        g_lm_chip_global[bus_num].func_en[pdev->params.pfunc_abs] = b_enable;
    }
}

u8_t lm_get_func_en(struct _lm_device_t *pdev, const u8_t pfunc_abs)
{
    const u8_t bus_num = INST_ID_TO_BUS_NUM(PFDEV(pdev)->vars.inst_id) ;

    if (pfunc_abs < ARRSIZE(g_lm_chip_global[0].func_en))
    {
        return g_lm_chip_global[bus_num].func_en[pfunc_abs];
    }
    
    return 0;
}

#define DEFINITIVE_PF_FOR_MPS 0 //PF0 defines the MPS value for all PFs when the device is in ARI mode. 

void lm_pcie_state_save_for_d3(struct _lm_device_t *pdev)
{
    static const u32_t pcicfg_device_control_offset     = PCICFG_OFFSET + PCICFG_DEVICE_CONTROL;
    static const u32_t PCICFG_DEVICE_CONTROL_MPS_MASK   = 0x000000E0;
    const u8_t abs_func_id                              = ABS_FUNC_ID(pdev);

    u32_t pf0_pcie_status_control = 0;

    //save PF0's PCIE_REG_PCIER_DEVICE_STATUS_CONTROL, since Windows does not restore the MPS value properly when resuming from 
    //D3. See CQ57271.
    if (DEFINITIVE_PF_FOR_MPS != abs_func_id)
    {
        lm_pretend_func(pdev, DEFINITIVE_PF_FOR_MPS);
        pf0_pcie_status_control = REG_RD(pdev, pcicfg_device_control_offset);
        pdev->hw_info.saved_pf0_pcie_mps = GET_FLAGS(pf0_pcie_status_control, PCICFG_DEVICE_CONTROL_MPS_MASK);
        lm_pretend_func(pdev, abs_func_id);
    }
}

void lm_pcie_state_restore_for_d0(struct _lm_device_t *pdev)
{
    static const u32_t pcicfg_device_control_offset     = PCICFG_OFFSET + PCICFG_DEVICE_CONTROL;
    static const u32_t PCICFG_DEVICE_CONTROL_MPS_MASK   = 0x000000E0;
    const u8_t abs_func_id                              = ABS_FUNC_ID(pdev);

    u32_t pf0_pcie_status_control = 0;
    u32_t pf0_mps = 0;
    u32_t own_pcie_status_control = REG_RD(pdev, pcicfg_device_control_offset);
    u32_t own_mps = GET_FLAGS(own_pcie_status_control, PCICFG_DEVICE_CONTROL_MPS_MASK);

    //restore PF0's PCIE_REG_PCIER_DEVICE_STATUS_CONTROL, since Windows does not restore the MPS value properly when resuming from 
    //D3. See CQ57271. 
    if((DEFINITIVE_PF_FOR_MPS != ABS_FUNC_ID(pdev)) && // if we're not PF0 ourselves,
       (INVALID_MPS != pdev->hw_info.saved_pf0_pcie_mps)) //and if there was a previous value saved
    {
        lm_pretend_func(pdev, DEFINITIVE_PF_FOR_MPS);

        //read current MPS value of PF0
        pf0_pcie_status_control = REG_RD(pdev, pcicfg_device_control_offset);
        pf0_mps = GET_FLAGS(pf0_pcie_status_control, PCICFG_DEVICE_CONTROL_MPS_MASK);

        //if it's different than the value we saved when going down to D3, and it's different then 
        //current PF's MPS - restore it
        if ( ( pf0_mps != pdev->hw_info.saved_pf0_pcie_mps) && 
             ( pf0_mps != own_mps) )
        {
            RESET_FLAGS(pf0_pcie_status_control, PCICFG_DEVICE_CONTROL_MPS_MASK);
            SET_FLAGS(pf0_pcie_status_control, pdev->hw_info.saved_pf0_pcie_mps);

            REG_WR(pdev, pcicfg_device_control_offset, pf0_pcie_status_control);
			
			++pdev->debug_info.pf0_mps_overwrite;
        }

        lm_pretend_func(pdev, abs_func_id);
    }
}

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
static lm_nwuf_t * find_nwuf( lm_nwuf_list_t* nwuf_list,
                              u32_t           mask_size,
                              u8_t*           byte_mask,
                              u8_t*           pattern )
{
    lm_nwuf_t *nwuf;
    u8_t found;
    u32_t idx;
    u32_t j;
    u32_t k;
    ASSERT_STATIC(LM_MAX_NWUF_CNT==8);
    for(idx = 0; idx < LM_MAX_NWUF_CNT; idx++)
    {
        nwuf = &nwuf_list->nwuf_arr[idx];
        if(nwuf->size != mask_size)
        {
            continue;
        }
        found = TRUE;
        for(j = 0; j < mask_size && found == TRUE; j++)
        {
            if(nwuf->mask[j] != byte_mask[j])
            {
                found = FALSE;
                break;
            }
            for(k = 0; k < 8; k++)
            {
                if((byte_mask[j] & (1 << k)) &&
                    (nwuf->pattern[j*8 + k] != pattern[j*8 + k]))
                {
                    found = FALSE;
                    break;
                }
            }
        }
        if(found)
        {
            return nwuf;
        }
    }
    return NULL;
} /* find_nwuf */
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t lm_add_nwuf( lm_device_t* pdev,
                         u32_t        mask_size,
                         u8_t*        byte_mask,
                         u8_t*        pattern )
{
    lm_nwuf_t* nwuf        = NULL ;
    u32_t      idx         = 0 ;
    u32_t      j           = 0 ;
    u32_t      k           = 0 ;
    u32_t      zero_serial = 0 ;
    if( ERR_IF(0 == mask_size) || ERR_IF( mask_size > LM_NWUF_PATTERN_MASK_SIZE ) )
    {
        DbgBreakMsg("Invalid byte mask size\n");
        return LM_STATUS_FAILURE;
    }
    /* If this is a duplicate entry, we are done. */
    nwuf = find_nwuf(&pdev->nwuf_list, mask_size, byte_mask, pattern);
    // according to DTM test (WHQL) we should fail duplicate adding
    if( NULL != nwuf )
    {
        DbgMessage(pdev, WARN, "Duplicated nwuf entry.\n");
        return LM_STATUS_EXISTING_OBJECT;
    }
    /* Find an empty slot. */
    nwuf = NULL;
    for(idx = 0; idx < LM_MAX_NWUF_CNT; idx++)
    {
        if(pdev->nwuf_list.nwuf_arr[idx].size == 0)
        {
            nwuf = &pdev->nwuf_list.nwuf_arr[idx] ;
            break;
        }
    }
    if( NULL == nwuf )
    {
        DbgMessage(pdev, WARN, "Cannot add Nwuf, exceeded maximum.\n");
        return LM_STATUS_RESOURCE;
    }
    pdev->nwuf_list.cnt++;
    /* Save nwuf data. */
    nwuf->size         = mask_size;
    // apply the mask on the pattern
    for(j = 0; j < mask_size; j++)
    {
        nwuf->mask[j] = byte_mask[j];
        for(k = 0; k < 8; k++)
        {
            if(byte_mask[j] & (1 << k))
            {
                nwuf->pattern[j*8 + k] = pattern[j*8 + k];
                zero_serial = 0;
            }
            else
            {
                nwuf->pattern[j*8 + k] = 0;
                ++zero_serial;
            }
        }
    }
    // Decrement from pattern size last bits that are not enabled (revresed)
    // TODO: When pattern size will be added to the interface, this calculation (zero_serial) is not needed, and
    //       pattern size would be the original pattern size as recieved from OS
    nwuf->pattern_size = mask_size*8 - zero_serial ;
    j = nwuf->pattern_size/8 ;
    if( nwuf->pattern_size % 8 )
    {
        j++;
    }
    j*= 8;
    // TODO: when patter size will be added to the interface, j should be: mask_size*8
    // calc the CRC using the same NIG algorithem and save it
    nwuf->crc32 = calc_crc32( nwuf->pattern, j, 0xffffffff /*seed*/, 1 /*complement*/ ) ;
#define WOL_DBG_PRINT 0
#if (WOL_DBG_PRINT) // this is to debug wolpattern WHQL test
    {
        printk("lm_add_nwuf: pattern[%u] mask_size=%03u pattern_size=%03u (%03u) crc calc size=%03u\n",
                 idx,
                 nwuf->size,
                 nwuf->pattern_size,
                 nwuf->size*8,
                 j );
        printk("pattern[%u] CRC=0x%08x\n",idx, nwuf->crc32 ) ;
        //printk("Pattern (original) size=%03u\n", nwuf->pattern_size ) ;

        for( idx = 0 ; idx < nwuf->size*8 ; idx++ )
        {
            printk("%02X", pattern[idx] ) ;
            if( idx != nwuf->size*8-1 )
            {
                printk("-") ;
            }
            if( ( 0!= idx ) && 0 == ( idx % 32 ) )
            {
                printk("\n") ;
            }
        }
        printk("\nPattern (masked):\n");
        for( idx = 0 ; idx < nwuf->size*8 ; idx++ )
        {
            printk("%02X", nwuf->pattern[idx] ) ;
            if( idx != nwuf->size*8-1 )
            {
                printk("-") ;
            }
            if( ( 0!= idx ) && 0 == ( idx % 32 ) )
            {
                printk("\n") ;
            }
        }
        printk("\nmask (size=%03u)\n", nwuf->size) ;
        for( idx = 0 ; idx < nwuf->size ; idx++ )
        {
            printk("%02X", byte_mask[idx] ) ;
            if( idx != nwuf->size-1 )
            {
                printk("-") ;
            }
        }
        printk("\n") ;
    }
#endif // WOL_DBG_PRINT
    if ERR_IF( 0xffffffff == nwuf->crc32 )
    {
        DbgBreakMsg("Invalid crc32\n") ;
    }
    return LM_STATUS_SUCCESS;
} /* lm_add_nwuf */

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t lm_del_nwuf( lm_device_t* pdev,
                         u32_t        mask_size,
                         u8_t*        byte_mask,
                         u8_t *       pattern )
{
    lm_nwuf_t *nwuf;
    u32_t k;
    if(mask_size == 0 || mask_size > LM_NWUF_PATTERN_MASK_SIZE)
    {
        DbgBreakMsg("Invalid byte mask size\n");
        return LM_STATUS_FAILURE;
    }
    /* Look for a matching pattern. */
    nwuf = find_nwuf(&pdev->nwuf_list, mask_size, byte_mask, pattern);
    if(nwuf)
    {
        /*
        printk("lm_del_nwuf: pattern[?] mask_size=%03u(%03u) cnt=%u crc32=0x%08x %02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X....\n",
                 nwuf->size, nwuf->size*8, pdev->nwuf_list.cnt-1, nwuf->crc32,
                 nwuf->pattern[0],  nwuf->pattern[1], nwuf->pattern[2], nwuf->pattern[3],
                 nwuf->pattern[4],  nwuf->pattern[5], nwuf->pattern[6], nwuf->pattern[7],
                 nwuf->pattern[8],  nwuf->pattern[9], nwuf->pattern[10], nwuf->pattern[11],
                 nwuf->pattern[12], nwuf->pattern[13], nwuf->pattern[14], nwuf->pattern[15] ) ;
        */
        nwuf->size = 0;
        nwuf->crc32 = 0 ;
        for(k = 0; k < LM_NWUF_PATTERN_MASK_SIZE; k++)
        {
            nwuf->mask[k] = 0;
        }
        for(k = 0; k < LM_NWUF_PATTERN_SIZE; k++)
        {
            nwuf->pattern[k] = 0xff;
        }
        pdev->nwuf_list.cnt--;
    }
    else
    {
        // according to DTM test (WHQL) we should fail non exists delete
        DbgMessage(pdev, WARN, "not exists nwuf entry. mask_size=%03d\n", mask_size );
        return LM_STATUS_OBJECT_NOT_FOUND;
    }
    return LM_STATUS_SUCCESS;
} /* lm_del_nwuf */

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_clear_nwuf(
    lm_device_t *pdev)
{
    u32_t j;
    u32_t k;
    for(j = 0; j < LM_MAX_NWUF_CNT; j++)
    {
        pdev->nwuf_list.nwuf_arr[j].size = 0;
        for(k = 0; k < LM_NWUF_PATTERN_MASK_SIZE; k++)
        {
            pdev->nwuf_list.nwuf_arr[j].mask[k] = 0;
        }
        for(k = 0; k < LM_NWUF_PATTERN_SIZE; k++)
        {
            pdev->nwuf_list.nwuf_arr[j].pattern[k] = 0xff;
        }
    }
    pdev->nwuf_list.cnt = 0;
} /* lm_clear_nwuf */


