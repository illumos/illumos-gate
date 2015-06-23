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
 *      This file contains functions that handle direct HW access
 *
 ******************************************************************************/

#include "lm5710.h"
#include "hw_dump.h"
#include "577xx_int_offsets.h"

/* not in hsi */
void ecore_init_cmng(const struct cmng_init_input *input_data,
                              struct cmng_init *ram_data);

void ecore_init_max_per_vn(u16_t vnic_max_rate,
                             struct rate_shaping_vars_per_vn *ram_data);

/*The NIG mirror is only used in VMChimney in MF/SI mode.
  In this mode, we assume that the driver in the host OS loads
  first, and allocates offset 0 in the NIG for it's own MAC address,
  so we don't use it. Also, iSCSI has a reserved entry in the NIG, so
  we don't use that either.
  */
#define IS_VALID_NIG_IDX(_idx) ((_idx != ECORE_LLH_CAM_ETH_LINE) && (_idx != ECORE_LLH_CAM_ISCSI_ETH_LINE))
#define INVALID_NIG_OFFSET ((u8_t)-1)

// initialize congestion managmet params
void lm_cmng_init(struct _lm_device_t *pdev, u32_t port_rate)
{
    u8_t                   vnic                       = 0;
    u32_t                  i                          = 0;
    u32_t*                 buf                        = NULL;
    u8_t                   all_zero                   = 0;
    u8_t                   num_vnics                  = pdev->params.vnics_per_port;
    const u8_t             b_afex_and_non_pmf         = IS_MF_AFEX_MODE(pdev) && (!IS_PMF(pdev));
    const u8_t             port_id                    = PORT_ID(pdev); // TBD: E1H - cmng params are currently per port, may change to be per function
    const u8_t             vnic_id                    = VNIC_ID(pdev);
    static const u8_t      DEF_MIN_RATE               = 1      ; /* default MIN rate in case VNIC min rate is configured to zero- 100Mbps */
    struct cmng_init_input input_data                 = {0};
    struct cmng_init       ram_data                   = {{{0}}};

    if(IS_MULTI_VNIC(pdev) && pdev->params.cmng_enable)
    {
        SET_FLAGS(input_data.flags.cmng_enables, CMNG_FLAGS_PER_PORT_RATE_SHAPING_VN);
        input_data.port_rate = port_rate;

        all_zero = TRUE;
        for (vnic = 0 ; vnic < num_vnics ; vnic++)
        {
            input_data.vnic_max_rate[vnic] = lm_get_max_bw(pdev,
                                                           port_rate,
                                                           vnic);

            if (!GET_FLAGS(pdev->hw_info.mf_info.func_mf_cfg , FUNC_MF_CFG_FUNC_HIDE))
            {
                if (pdev->hw_info.mf_info.min_bw[vnic] == 0)
                {
                    input_data.vnic_min_rate[vnic] = DEF_MIN_RATE;
                }
                else
                {
                    input_data.vnic_min_rate[vnic] = pdev->hw_info.mf_info.min_bw[vnic];
                    all_zero = FALSE;
                }
            }
        }

        // IS_DCB_ENABLED isn't updated when this function is called from lm_init_intmem_port
        // but it is called each time the link is up.
        if (!(all_zero || LM_DCBX_ETS_IS_ENABLED(pdev)))
        {
            SET_FLAGS(input_data.flags.cmng_enables,CMNG_FLAGS_PER_PORT_FAIRNESS_VN);
        }

        if( b_afex_and_non_pmf )
        {
            ecore_init_max_per_vn( input_data.vnic_max_rate[vnic_id], &ram_data.vnic.vnic_max_rate[vnic_id] );
        }
        else
        {
            ecore_init_cmng(&input_data,&ram_data);
        }
    }

    // store per vnic struct to internal memory rs. we store data for all 4 vnics even if there are only 2 vnics, just to
    // make sure there are known values.
    for (vnic = 0; vnic < ARRSIZE(ram_data.vnic.vnic_max_rate); vnic++)
    {
        buf = (u32_t *)&ram_data.vnic.vnic_max_rate[vnic];
        ASSERT_STATIC(0 == sizeof(ram_data.vnic.vnic_max_rate[vnic]) % 4);

        if( b_afex_and_non_pmf && (vnic != vnic_id) )
        {
            // If AFEX && non pmf we want to write only for the current VNIC
            continue;
        }

        for (i = 0; i < sizeof(ram_data.vnic.vnic_max_rate[vnic])/4; i++)
        {
            LM_INTMEM_WRITE32(pdev,XSTORM_RATE_SHAPING_PER_VN_VARS_OFFSET((port_id+2*vnic))+i*4,
                              buf[i], BAR_XSTRORM_INTMEM);
        }
    }

    if( b_afex_and_non_pmf )
    {
        // If AFEX && non pmf we want to write only for the current VNIC
        // All other writes below are for PMF so we exit in this case.
        return;
    }

    // Store per port struct to internal memory
    buf = (u32_t *)&ram_data.port.rs_vars;
    ASSERT_STATIC(0 == (sizeof(ram_data.port.rs_vars) % 4)) ;
    for (i = 0; i < sizeof(ram_data.port.rs_vars)/4; i++)
    {
       LM_INTMEM_WRITE32(pdev,(XSTORM_CMNG_PER_PORT_VARS_OFFSET(port_id) + OFFSETOF(struct cmng_struct_per_port, rs_vars) + i*4),
                          buf[i], BAR_XSTRORM_INTMEM);
    }

    buf = (u32_t *)&ram_data.port.fair_vars;
    ASSERT_STATIC(0 == (sizeof(ram_data.port.fair_vars) % 4)) ;
    for (i = 0; i < sizeof(ram_data.port.fair_vars)/4; i++)
    {
       LM_INTMEM_WRITE32(pdev,(XSTORM_CMNG_PER_PORT_VARS_OFFSET(port_id) + OFFSETOF(struct cmng_struct_per_port, fair_vars) + i*4),
                          buf[i], BAR_XSTRORM_INTMEM);
    }

    buf = (u32_t *)&ram_data.port.flags;
    ASSERT_STATIC(0 == (sizeof(ram_data.port.flags) % 4));
    for (i = 0; i < sizeof(ram_data.port.flags)/4; i++)
    {
       LM_INTMEM_WRITE32(pdev,(XSTORM_CMNG_PER_PORT_VARS_OFFSET(port_id) + OFFSETOF(struct cmng_struct_per_port, flags) + i*4),
                          buf[i], BAR_XSTRORM_INTMEM);
    }

    // store per vnic struct to internal memory fair. we store data for all 4 vnics even if there are only 2 vnics, just to
    //make sure there are known values.
    for (vnic = 0; vnic < ARRSIZE(ram_data.vnic.vnic_min_rate); vnic++)
    {
        buf = (u32_t *)&ram_data.vnic.vnic_min_rate[vnic];
        ASSERT_STATIC(0 == sizeof(ram_data.vnic.vnic_min_rate[vnic]) % 4);
        for (i = 0; i < sizeof(ram_data.vnic.vnic_min_rate[vnic])/4; i++)
        {
            LM_INTMEM_WRITE32(pdev,XSTORM_FAIRNESS_PER_VN_VARS_OFFSET((port_id+2*vnic))+i*4,
                              buf[i], BAR_XSTRORM_INTMEM);
        }
    }

} /* lm_cmng_init */

/**initialize_nig_entry
 * Initialize a NIG mirror entry to a given MAC address. Note -
 * the entrie's reference count remains 0.
 *
 * @param pdev
 * @param offset the index of the NIG entry
 * @param addr the MAC address to use
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         failure code on failure.
 */
static lm_status_t lm_initialize_nig_entry(
    lm_device_t *pdev,
    u8_t         offset,
    u8_t        *addr)
{
    lm_nig_mirror_entry_t* entry = &pdev->vars.nig_mirror.entries[offset];
    DbgBreakIf(entry->refcnt != 0);
    mm_memcpy(entry->addr, addr, ARRSIZE(entry->addr));
    return LM_STATUS_SUCCESS;
}

/**get_available_nig_entry
 * Find a NIG entry that's not in use. Entry 0 and 15 are never
 * considered available, since they are used by iSCSI and by the
 * L2 client.
 *
 * @param pdev
 *
 * @return an index to a usable NIG entry, or INVALID_NIG_OFFSET
 *         if there aren't any available entries.
 */
static u8_t lm_get_available_nig_entry(lm_device_t *pdev)
{
    u8_t i;
    lm_nig_mirror_t *nig_mirror = &pdev->vars.nig_mirror;

    for (i=0; i<ARRSIZE(nig_mirror->entries); ++i)
    {
        if (IS_VALID_NIG_IDX(i) &&
            (nig_mirror->entries[i].refcnt == 0))
        {
            return i;
        }
    }
    return INVALID_NIG_OFFSET;
}

/**find_nig_entry_for_addr
 * Find the entry for a given MAC address in the nig.
 *
 * @param pdev
 * @param addr the MAC address to look for
 *
 * @return u8_t the index of the NIG entry that contains the
 *         given MAC address, or INVALID_NIG_OFFSET if no such
 *         entry exists.
 */
static u8_t lm_find_nig_entry_for_addr(
    lm_device_t *pdev,
    u8_t        *addr)
{
    u8_t i;
    lm_nig_mirror_t *nig_mirror = &pdev->vars.nig_mirror;
    lm_nig_mirror_entry_t* cur_entry = NULL;

    for (i=0; i<ARRSIZE(nig_mirror->entries); ++i)
    {
        cur_entry = &nig_mirror->entries[i];
        if ( (cur_entry->refcnt > 0) &&
             (mm_memcmp(cur_entry->addr, addr, ARRSIZE(cur_entry->addr))) )
        {
            return i;
        }
    }
    return INVALID_NIG_OFFSET;
}

lm_status_t lm_insert_nig_entry(
    lm_device_t *pdev,
    u8_t        *addr)
{
    u8_t offset = 0;
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    offset = lm_find_nig_entry_for_addr(pdev, addr);

    if (offset == INVALID_NIG_OFFSET)
    {
        /*If there was no entry for this MAC, insert it to an available slot and call lm_set_mac_in_nig.*/
        offset = lm_get_available_nig_entry(pdev);
        if (offset == INVALID_NIG_OFFSET)
        {
            return LM_STATUS_RESOURCE; //no available NIG entry.
        }

        lm_status = lm_initialize_nig_entry(pdev, offset, addr);
        DbgBreakIf (lm_status != LM_STATUS_SUCCESS);

        lm_status = lm_set_mac_in_nig(pdev, addr, LM_CLI_IDX_NDIS, offset);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
    }

    NIG_ENTRY_INC_REFCNT(&pdev->vars.nig_mirror.entries[offset]);

    return lm_status;
}

/**remove_nig_entry
 * Dereference the entry for a given MAC address. If this was
 * the last reference the MAC address is removed from the NIG.
 *
 * @param pdev
 * @param addr the MAC address
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success,
 *         LM_STATUS_FAILURE if the given MAC is not in the NIG,
 *         other failure codes on other errors.
 */
lm_status_t lm_remove_nig_entry(
    lm_device_t *pdev,
    u8_t        *addr)
{
    u8_t offset = 0;
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    lm_nig_mirror_entry_t* entry = NULL;

    offset = lm_find_nig_entry_for_addr(pdev, addr);
    if (offset == INVALID_NIG_OFFSET)
    {
        DbgBreakIf(offset == INVALID_NIG_OFFSET); //trying to remove an address that isn't in the NIG.
        return LM_STATUS_FAILURE;
    }

    entry = &pdev->vars.nig_mirror.entries[offset];

    NIG_ENTRY_DEC_REFCNT(entry);

    if (entry->refcnt == 0)
    {
        lm_status = lm_set_mac_in_nig(pdev, NULL, LM_CLI_IDX_NDIS, offset);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
        mm_mem_zero(entry->addr, sizeof(entry->addr));
    }

    return lm_status;
}

void lm_setup_fan_failure_detection(struct _lm_device_t *pdev)
{
    u32_t             val = 0;
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u8_t             port = 0;
    u8_t      is_required = FALSE;
    u32            offset = 0;

    offset = OFFSETOF(shmem_region_t, dev_info.shared_hw_config.config2) ;

    LM_SHMEM_READ(pdev, offset, &val);

    val &= SHARED_HW_CFG_FAN_FAILURE_MASK;

    switch(val)
    {
    case SHARED_HW_CFG_FAN_FAILURE_PHY_TYPE:
        {
            /*
             * The fan failure mechanism is usually related to the PHY type since
             * the power consumption of the board is effected by the PHY. Currently,
             * fan is required for most designs with SFX7101, BCM8727 and BCM8481.
             */
            for (port = PORT_0; port < PORT_MAX; port++)
            {
                is_required |= elink_fan_failure_det_req(pdev, pdev->hw_info.shmem_base, pdev->hw_info.shmem_base2, port);
            }
        }
        break;

    case SHARED_HW_CFG_FAN_FAILURE_ENABLED:
        is_required = TRUE;
        break;

    case SHARED_HW_CFG_FAN_FAILURE_DISABLED:
    default:
        break;
    }

    DbgMessage(pdev, WARN, "lm_setup_fan_failure_detection: cfg=0x%x is_required=%d\n", val, is_required );

    if (!is_required)
    {
        return;
    }

    // read spio5 in order to make it input collaterally - we don't care of the returned value
    // MCP does the same
    lm_status = lm_spio_read( pdev, 5, &val ) ;
    if( LM_STATUS_SUCCESS != lm_status )
    {
        DbgBreakIf(1) ;
    }

    // We write here since value changes from 1 to 0
    val = REG_RD(pdev,MISC_REG_SPIO_INT) ;
    val |= (1<<(16+5)) ;
    REG_WR(pdev,MISC_REG_SPIO_INT, val ) ;

    // enable the SPIO_INT 5 to signal the IGU
    val = REG_RD(pdev,MISC_REG_SPIO_EVENT_EN) ;
    val |= (1<<5) ;
    REG_WR(pdev,MISC_REG_SPIO_EVENT_EN, val ) ;
}

/*
 *------------------------------------------------------------------------
 * lm_gpio_read -
 *
 * Read the value of the requested GPIO pin (with pin_num)
 *
 *------------------------------------------------------------------------
 */
lm_status_t lm_gpio_read(struct _lm_device_t *pdev, u32_t pin_num, u32_t* value_ptr, u8_t port)
{
    u32_t reg_val       = 0;
    u32_t gpio_port     = 0;
    u32_t mask          = 0;
    u32_t swap_val      = 0;
    u32_t swap_override = 0;

    if ( CHK_NULL(pdev) || CHK_NULL(value_ptr) )
    {
        DbgBreakIf(!pdev);
        DbgBreakIf(!value_ptr);
        return LM_STATUS_INVALID_PARAMETER ;
    }

    if (pin_num > MISC_REGISTERS_GPIO_3)
    {
        DbgMessage(pdev, FATAL , "Invalid pin_num GPIO %d\n", pin_num);
        return LM_STATUS_INVALID_PARAMETER;
    }

    /* The GPIO should be swapped if the swap register is set and active */
    swap_val      = REG_RD(pdev,  NIG_REG_PORT_SWAP);
    swap_override = REG_RD(pdev,  NIG_REG_STRAP_OVERRIDE);


    // define port upon swap
    gpio_port = (swap_val && swap_override) ^ port;

    // Get the current port number (0 or 1)
    if (gpio_port > 1)
    {
        return LM_STATUS_FAILURE;
    }

    // Calculate the value with relevent OE set to 1 (for input).
    // Calulate the mask for the read value.
    if (gpio_port == 0)
    {
        switch (pin_num)
        {
            case 0:
                mask = GRC_MISC_REGISTERS_GPIO_PORT0_VAL0;
                break;
            case 1:
                mask = GRC_MISC_REGISTERS_GPIO_PORT0_VAL1;
                break;
            case 2:
                mask = GRC_MISC_REGISTERS_GPIO_PORT0_VAL2;
                break;
            case 3:
                mask = GRC_MISC_REGISTERS_GPIO_PORT0_VAL3;
                break;
            default:
                break;
        }
    }
    // Calculate the value with relevent OE set to 1 (for input).
    // Calulate the mask for the read value.
    if (gpio_port == 1)
    {
        switch (pin_num)
        {
            case 0:
                mask = GRC_MISC_REGISTERS_GPIO_PORT1_VAL0;
                break;
            case 1:
                mask = GRC_MISC_REGISTERS_GPIO_PORT1_VAL1;
                break;
            case 2:
                mask = GRC_MISC_REGISTERS_GPIO_PORT1_VAL2;
                break;
            case 3:
                mask = GRC_MISC_REGISTERS_GPIO_PORT1_VAL3;
                break;
            default:
                break;
        }
    }

    // Read from MISC block the GPIO register
    reg_val = REG_RD(pdev, MISC_REG_GPIO);
    DbgMessage(NULL, INFORM, "lm_gpio_read: MISC_REG_GPIO value 0x%x mask 0x%x\n", reg_val, mask);

    // Get the requested pin value by masking the val with mask
    if ((reg_val & mask) == mask)
    {
        *value_ptr = 1;
    }
    else
    {
        *value_ptr = 0;
    }
    DbgMessage(NULL, INFORM, "lm_gpio_read: pin %d value is %x\n", pin_num, *value_ptr);

    return LM_STATUS_SUCCESS;
}

/*
 *------------------------------------------------------------------------
 * lm_gpio_write -
 *
 * Write a value to the requested GPIO pin (with pin_num)
 *
 *------------------------------------------------------------------------
 */
lm_status_t lm_gpio_write(struct _lm_device_t *pdev, u32_t pin_num, u32_t mode, u8_t port)
{
    u32_t gpio_port     = 0;
    u32_t gpio_shift    = 0;
    u32_t gpio_mask     = 0;
    u32_t gpio_reg      = 0;
    u32_t swap_val      = 0;
    u32_t swap_override = 0;

    if( CHK_NULL(pdev) )
    {
        DbgBreakIf(!pdev);
        return LM_STATUS_INVALID_PARAMETER ;
    }
    if (pin_num > MISC_REGISTERS_GPIO_3)
    {
    DbgMessage(pdev, FATAL , "lm_gpio_write: Invalid pin_num GPIO %d\n", pin_num);
    return LM_STATUS_INVALID_PARAMETER;
    }

    /* The GPIO should be swapped if the swap register is set and active */
    swap_val      = REG_RD(pdev,  NIG_REG_PORT_SWAP);
    swap_override = REG_RD(pdev,  NIG_REG_STRAP_OVERRIDE);

    // define port upon swap
    gpio_port = (swap_val && swap_override) ^ port;

    // Get the current port number (0 or 1)
    if (gpio_port > 1) {
    return LM_STATUS_FAILURE;
    }

    gpio_shift = pin_num +
            (gpio_port ? MISC_REGISTERS_GPIO_PORT_SHIFT : 0);

    gpio_mask = (1 << gpio_shift);

    // lock before read
    lm_hw_lock(pdev, HW_LOCK_RESOURCE_GPIO, TRUE);

    /* read GPIO and mask except the float bits */
    gpio_reg = (REG_RD(pdev, MISC_REG_GPIO) & MISC_REGISTERS_GPIO_FLOAT);

    switch (mode) {
    case MISC_REGISTERS_GPIO_OUTPUT_LOW:
        DbgMessage(NULL, WARN, "Set GPIO %d (shift %d) -> output low\n", pin_num, gpio_shift);
        /* clear FLOAT and set CLR */
        gpio_reg &= ~(gpio_mask << MISC_REGISTERS_GPIO_FLOAT_POS);
        gpio_reg |=  (gpio_mask << MISC_REGISTERS_GPIO_CLR_POS);
        break;

    case MISC_REGISTERS_GPIO_OUTPUT_HIGH:
        DbgMessage(NULL, WARN, "Set GPIO %d (shift %d) -> output high\n", pin_num, gpio_shift);
        /* clear FLOAT and set SET */
        gpio_reg &= ~(gpio_mask << MISC_REGISTERS_GPIO_FLOAT_POS);
        gpio_reg |=  (gpio_mask << MISC_REGISTERS_GPIO_SET_POS);
        break;

    case MISC_REGISTERS_GPIO_INPUT_HI_Z:
        DbgMessage(NULL, WARN, "Set GPIO %d (shift %d) -> input\n", pin_num, gpio_shift);
        /* set FLOAT */
        gpio_reg |= (gpio_mask << MISC_REGISTERS_GPIO_FLOAT_POS);
        break;

    default:
        break;
    }

    REG_WR(pdev, MISC_REG_GPIO, gpio_reg);
    lm_hw_unlock(pdev, HW_LOCK_RESOURCE_GPIO);

    return LM_STATUS_SUCCESS;


}

/*
 *------------------------------------------------------------------------
 * lm_gpio_mult_write -
 *
 * Write a value to the requested GPIO pins (bits defined)
 * User is expected to handle any port swapping and know exactly
 * which pin(s) to drive.
 *
 *------------------------------------------------------------------------
 */
lm_status_t lm_gpio_mult_write(struct _lm_device_t *pdev, u8_t pins, u32_t mode)
{
    u32_t gpio_reg      = 0;
    lm_status_t rc      = LM_STATUS_SUCCESS;

    if( CHK_NULL(pdev) )
    {
        DbgBreakIf(!pdev);
        return LM_STATUS_INVALID_PARAMETER ;
    }
    // lock before read
    lm_hw_lock(pdev, HW_LOCK_RESOURCE_GPIO, TRUE);

    /* read GPIO and mask except the float bits */
    gpio_reg = REG_RD(pdev, MISC_REG_GPIO);
    gpio_reg &= ~(pins << MISC_REGISTERS_GPIO_FLOAT_POS);
    gpio_reg &= ~(pins << MISC_REGISTERS_GPIO_CLR_POS);
    gpio_reg &= ~(pins << MISC_REGISTERS_GPIO_SET_POS);

    switch (mode) {
    case MISC_REGISTERS_GPIO_OUTPUT_LOW:
        DbgMessage(NULL, WARN, "Set GPIO 0x%x -> output low\n", pins);
        /* clear FLOAT and set CLR */
        gpio_reg |=  (pins << MISC_REGISTERS_GPIO_CLR_POS);
        break;

    case MISC_REGISTERS_GPIO_OUTPUT_HIGH:
        DbgMessage(NULL, WARN, "Set GPIO 0x%x -> output high\n", pins);
        /* clear FLOAT and set SET */
        gpio_reg |=  (pins << MISC_REGISTERS_GPIO_SET_POS);
        break;

    case MISC_REGISTERS_GPIO_INPUT_HI_Z:
        DbgMessage(NULL, WARN, "Set GPIO 0x%x -> input\n", pins);
        /* set FLOAT */
        gpio_reg |= (pins << MISC_REGISTERS_GPIO_FLOAT_POS);
        break;

    default:
    DbgMessage(pdev, FATAL , "lm_gpio_mult_write: Invalid GPIO mode %d\n", mode);
    rc = LM_STATUS_INVALID_PARAMETER;
        break;
    }

    if (rc == LM_STATUS_SUCCESS)
    {
        REG_WR(pdev, MISC_REG_GPIO, gpio_reg);
    }

    lm_hw_unlock(pdev, HW_LOCK_RESOURCE_GPIO);

    return rc;
}

/*
 *------------------------------------------------------------------------
 * lm_gpio_int_write -
 *
 * Set or clear the requested GPIO pin (with pin_num)
 *
 *------------------------------------------------------------------------
 */

lm_status_t lm_gpio_int_write(struct _lm_device_t *pdev, u32_t pin_num, u32_t mode, u8_t port)
{
    /* The GPIO should be swapped if swap register is set and active */
    u32_t gpio_port;
    u32_t gpio_shift ;
    u32_t gpio_mask;
    u32_t gpio_reg;
    u32_t swap_val      = 0;
    u32_t swap_override = 0;

    swap_val      = REG_RD(pdev,  NIG_REG_PORT_SWAP);
    swap_override = REG_RD(pdev,  NIG_REG_STRAP_OVERRIDE);
    gpio_port     = (swap_val && swap_override ) ^ port;
    gpio_shift    = pin_num + (gpio_port ? MISC_REGISTERS_GPIO_PORT_SHIFT : 0);
    gpio_mask     = (1 << gpio_shift);

    if (pin_num > MISC_REGISTERS_GPIO_3)
    {
        DbgMessage(pdev, FATAL , "lm_gpio_write: Invalid pin_num GPIO %d\n", pin_num);
        return LM_STATUS_INVALID_PARAMETER;
    }

    // lock before read
    lm_hw_lock(pdev, HW_LOCK_RESOURCE_GPIO, TRUE);

    /* read GPIO int */
    gpio_reg = REG_RD(pdev, MISC_REG_GPIO_INT);

    switch (mode)
    {
    case MISC_REGISTERS_GPIO_INT_OUTPUT_CLR:
        DbgMessage(pdev, INFORM, "Clear GPIO INT %d (shift %d) -> output low\n",
           pin_num, gpio_shift);
        // clear SET and set CLR
        gpio_reg &= ~(gpio_mask << MISC_REGISTERS_GPIO_INT_SET_POS);
        gpio_reg |=  (gpio_mask << MISC_REGISTERS_GPIO_INT_CLR_POS);
        break;

    case MISC_REGISTERS_GPIO_INT_OUTPUT_SET:
        DbgMessage(pdev, INFORM, "Set GPIO INT %d (shift %d) -> output high\n",
           pin_num, gpio_shift);
        // clear CLR and set SET
        gpio_reg &= ~(gpio_mask << MISC_REGISTERS_GPIO_INT_CLR_POS);
        gpio_reg |=  (gpio_mask << MISC_REGISTERS_GPIO_INT_SET_POS);
        break;

    default:
        break;
    }

    REG_WR(pdev, MISC_REG_GPIO_INT, gpio_reg);
    // unlock after write
    DbgMessage(pdev, INFORM, "lm_gpio_int_write: pin %d value is %x\n",
       pin_num, gpio_reg);
    lm_hw_unlock(pdev, HW_LOCK_RESOURCE_GPIO);

    return 0;
}

/*
 *------------------------------------------------------------------------
 * lm_spio_read -
 *
 * Read the value of the requested SPIO pin (with pin_num)
 *
 *------------------------------------------------------------------------
 */
lm_status_t lm_spio_read(struct _lm_device_t *pdev, u32_t pin_num, u32_t* value_ptr)
{
    u32_t reg_val = 0, mask = 0;

    // Read from MISC block the SPIO register
    reg_val = REG_RD(pdev, MISC_REG_SPIO);

    DbgMessage(pdev, INFORM, "lm_spio_read: MISC_REG_SPIO value is 0x%x\n", reg_val);

    // Calculate the value with relevent OE set to 1 (for input).
    // Calulate the mask for the read value.
    switch (pin_num) {
        case 0:        // SPIO pins 0-2 do not have OE pins
            mask = MISC_SPIO_EN_VAUX_L;
            break;
        case 1:
            mask = MISC_SPIO_DIS_VAUX_L;
            break;
        case 2:
            mask = MISC_SPIO_SEL_VAUX_L;
            break;
        case 3:         // SPIO pin 3 is not connected
            return LM_STATUS_FAILURE;
        case 4:        // SPIO pins 4-7 have OE pins
            reg_val |= (MISC_SPIO_SPIO4 << MISC_SPIO_FLOAT_POS);
            mask = MISC_SPIO_SPIO4;
            break;
        case 5:
            reg_val |= (MISC_SPIO_SPIO5 << MISC_SPIO_FLOAT_POS);
            mask = MISC_SPIO_SPIO5;
            break;
        case 6:
            reg_val |= (MISC_SPIO_UMP_ADDR0 << MISC_SPIO_FLOAT_POS);
            mask = MISC_SPIO_UMP_ADDR0;
            break;
        case 7:
            reg_val |= (MISC_SPIO_UMP_ADDR1 << MISC_SPIO_FLOAT_POS);
            mask = MISC_SPIO_UMP_ADDR1;
            break;
        default:
            return LM_STATUS_FAILURE;
    }

    // Write to SPIO register the value with the relevant OE set to 1
    REG_WR(pdev, MISC_REG_SPIO, reg_val);
    DbgMessage(NULL, INFORM, "lm_spio_read: writing MISC_REG_SPIO 0x%x\n", reg_val);

    // Read from MISC block the SPIO register
    reg_val = REG_RD(pdev, MISC_REG_SPIO);
    DbgMessage(NULL, INFORM, "lm_spio_read: MISC_REG_SPIO value 0x%x\n", reg_val);

    // Get the requested pin value by masking the val with mask
    if ((reg_val & mask) == mask)
    {
        *value_ptr = 1;
    }
    else
    {
        *value_ptr = 0;
    }
    DbgMessage(NULL, INFORM, "lm_spio_read: pin %d value is 0x%x\n", pin_num, *value_ptr);

    return LM_STATUS_SUCCESS;
}

/*
 *------------------------------------------------------------------------
 * lm_spio_write -
 *
 * Write a value to the requested SPIO pin (with pin_num)
 *
 *------------------------------------------------------------------------
 */
lm_status_t lm_spio_write(struct _lm_device_t *pdev, u32_t pin_num, u32_t value)
{
    u32_t       reg_val   = 0;
    lm_status_t lm_status = LM_STATUS_SUCCESS ;

    if CHK_NULL(pdev)
    {
        DbgBreakIf(!pdev);
        return LM_STATUS_INVALID_PARAMETER ;
    }

    // lock before read
    lm_hw_lock(pdev, HW_LOCK_RESOURCE_GPIO, TRUE); // The GPIO lock is used for SPIO as well!

    // Read from MISC block the SPIO register
    reg_val = REG_RD(pdev, MISC_REG_SPIO);
    DbgMessage(NULL, INFORM, "lm_gpio_write: MISC_REG_SPIO value is 0x%x\n", reg_val);

    // Turn the requested SPIO pin to output by setting its OE bit to 0 and
    // If value is 1 set the relevant SET bit to 1, otherwise set the CLR bit to 1.
    if (pin_num >= 8 || pin_num == 3) {
        // SPIO pin 3 is not connected
        lm_status = LM_STATUS_FAILURE;
    } else {
        u32 pin = 1 << pin_num;
        // Set pin as OUTPUT
        reg_val &= ~(pin << MISC_SPIO_FLOAT_POS);
        // Clear the pins CLR and SET bits
        reg_val &= ~(pin << MISC_SPIO_SET_POS) & ~(pin << MISC_SPIO_CLR_POS);
        // If value is 1 set the SET bit of this pin, otherwise set the CLR bit.
        reg_val |= (value == 1) ? (pin << MISC_SPIO_SET_POS) : (pin << MISC_SPIO_CLR_POS);
    }

    if( LM_STATUS_SUCCESS == lm_status )
    {
        // Write to SPIO register the value with the relevant OE set to 1 and
        // If value is 1, set the relevant SET bit to 1, otherwise set the CLR bit to 1.
        REG_WR(pdev, MISC_REG_SPIO, reg_val);
        DbgMessage(NULL, INFORM, "lm_spio_write: writing MISC_REG_SPIO 0x%x\n", reg_val);
    }

    // unlock
    lm_hw_unlock(pdev, HW_LOCK_RESOURCE_GPIO);

    return lm_status ;
}


/*
 *------------------------------------------------------------------------
 * lm_set_led_mode -
 *
 * Set the led mode of the requested port
 *
 *------------------------------------------------------------------------
 */
lm_status_t lm_set_led_mode(struct _lm_device_t *pdev, u32_t port_idx, u32_t mode_idx)
{

    DbgBreakIf(!pdev);

    // Write to relevant NIG register LED_MODE (P0 or P1) the mode index (0-15)
    switch (port_idx) {
        case 0:
            REG_WR(pdev,  NIG_REG_LED_MODE_P0, mode_idx);
            break;
        case 1:
            REG_WR(pdev,  NIG_REG_LED_MODE_P1, mode_idx);
            break;
        default:
            DbgMessage(NULL, FATAL, "lm_set_led_mode() unknown port index %d\n", port_idx);
            return LM_STATUS_FAILURE;
    }

    DbgMessage(NULL, INFORM, "lm_set_led_mode() wrote to NIG_REG_LED_MODE (port %d) 0x%x\n", port_idx, mode_idx);
    return LM_STATUS_SUCCESS;
}

/*
 *------------------------------------------------------------------------
 * lm_get_led_mode -
 *
 * Get the led mode of the requested port
 *
 *------------------------------------------------------------------------
 */
lm_status_t lm_get_led_mode(struct _lm_device_t *pdev, u32_t port_idx, u32_t* mode_idx_ptr)
{

    DbgBreakIf(!pdev);

    // Read from the relevant NIG register LED_MODE (P0 or P1) the mode index (0-15)
    switch (port_idx) {
        case 0:
            *mode_idx_ptr = REG_RD(pdev,  NIG_REG_LED_MODE_P0);
            break;
        case 1:
            *mode_idx_ptr = REG_RD(pdev,  NIG_REG_LED_MODE_P1);
            break;
        default:
            DbgMessage(NULL, FATAL, "lm_get_led_mode() unknown port index %d\n", port_idx);
            return LM_STATUS_FAILURE;
    }

    DbgMessage(NULL, INFORM, "lm_get_led_mode() read from NIG_REG_LED_MODE (port %d) 0x%x\n", port_idx, *mode_idx_ptr);

    return LM_STATUS_SUCCESS;
}

/*
 *------------------------------------------------------------------------
 * lm_override_led_value -
 *
 * Override the led value of the requsted led
 *
 *------------------------------------------------------------------------
 */
lm_status_t lm_override_led_value(struct _lm_device_t *pdev, u32_t port_idx, u32_t led_idx, u32_t value)
{
    u32_t reg_val   = 0;

    // If port 0 then use EMAC0, else use EMAC1
    u32_t emac_base = (port_idx) ? GRCBASE_EMAC1 : GRCBASE_EMAC0;

    DbgBreakIf(!pdev);

    DbgMessage(NULL, INFORM, "lm_override_led_value() port %d led_idx %d value %d\n", port_idx, led_idx, value);

    switch (led_idx) {
        case 0: //10MB led
            // Read the current value of the LED register in the EMAC block
            reg_val = REG_RD(pdev, emac_base + EMAC_REG_EMAC_LED);
            // Set the OVERRIDE bit to 1
            reg_val |= EMAC_LED_OVERRIDE;
            // If value is 1, set the 10M_OVERRIDE bit, otherwise reset it.
            reg_val = (value==1) ? (reg_val | EMAC_LED_10MB_OVERRIDE) : (reg_val & ~EMAC_LED_10MB_OVERRIDE);
            REG_WR(pdev, emac_base+ EMAC_REG_EMAC_LED, reg_val);
            break;
        case 1: //100MB led
            // Read the current value of the LED register in the EMAC block
            reg_val = REG_RD(pdev, emac_base + EMAC_REG_EMAC_LED);
            // Set the OVERRIDE bit to 1
            reg_val |= EMAC_LED_OVERRIDE;
            // If value is 1, set the 100M_OVERRIDE bit, otherwise reset it.
            reg_val = (value==1) ? (reg_val | EMAC_LED_100MB_OVERRIDE) : (reg_val & ~EMAC_LED_100MB_OVERRIDE);
            REG_WR(pdev, emac_base+ EMAC_REG_EMAC_LED, reg_val);
            break;
        case 2: //1000MB led
            // Read the current value of the LED register in the EMAC block
            reg_val = REG_RD(pdev, emac_base + EMAC_REG_EMAC_LED);
            // Set the OVERRIDE bit to 1
            reg_val |= EMAC_LED_OVERRIDE;
            // If value is 1, set the 1000M_OVERRIDE bit, otherwise reset it.
            reg_val = (value==1) ? (reg_val | EMAC_LED_1000MB_OVERRIDE) : (reg_val & ~EMAC_LED_1000MB_OVERRIDE);
            REG_WR(pdev, emac_base+ EMAC_REG_EMAC_LED, reg_val);
            break;
        case 3: //2500MB led
            // Read the current value of the LED register in the EMAC block
            reg_val = REG_RD(pdev, emac_base + EMAC_REG_EMAC_LED);
            // Set the OVERRIDE bit to 1
            reg_val |= EMAC_LED_OVERRIDE;
            // If value is 1, set the 2500M_OVERRIDE bit, otherwise reset it.
            reg_val = (value==1) ? (reg_val | EMAC_LED_2500MB_OVERRIDE) : (reg_val & ~EMAC_LED_2500MB_OVERRIDE);
            REG_WR(pdev, emac_base+ EMAC_REG_EMAC_LED, reg_val);
            break;
        case 4: //10G led
            if (port_idx == 0) {
                REG_WR(pdev,  NIG_REG_LED_10G_P0, value);
            } else {
                REG_WR(pdev,  NIG_REG_LED_10G_P1, value);
            }
            break;
        case 5: //TRAFFIC led

            // Find if the traffic control is via BMAC or EMAC
            if (port_idx == 0) {
                reg_val = REG_RD(pdev,  NIG_REG_NIG_EMAC0_EN);
            } else {
                reg_val = REG_RD(pdev,  NIG_REG_NIG_EMAC1_EN);
            }

            // Override the traffic led in the EMAC:
            if (reg_val == 1) {
                // Read the current value of the LED register in the EMAC block
                reg_val = REG_RD(pdev, emac_base + EMAC_REG_EMAC_LED);
                // Set the TRAFFIC_OVERRIDE bit to 1
                reg_val |= EMAC_LED_OVERRIDE;
                // If value is 1, set the TRAFFIC bit, otherwise reset it.
                reg_val = (value==1) ? (reg_val | EMAC_LED_TRAFFIC) : (reg_val & ~EMAC_LED_TRAFFIC);
                REG_WR(pdev, emac_base+ EMAC_REG_EMAC_LED, reg_val);
            } else {    // Override the traffic led in the BMAC:
                if (port_idx == 0) {
                    REG_WR(pdev,  NIG_REG_LED_CONTROL_OVERRIDE_TRAFFIC_P0, 1);
                    REG_WR(pdev,  NIG_REG_LED_CONTROL_TRAFFIC_P0, value);
                } else {
                    REG_WR(pdev,  NIG_REG_LED_CONTROL_OVERRIDE_TRAFFIC_P1, 1);
                    REG_WR(pdev,  NIG_REG_LED_CONTROL_TRAFFIC_P1, value);
                }
            }
            break;
        default:
            DbgMessage(NULL, FATAL, "lm_override_led_value() unknown led index %d (should be 0-5)\n", led_idx);
            return LM_STATUS_FAILURE;
    }

    return LM_STATUS_SUCCESS;
}

/*
 *------------------------------------------------------------------------
 * lm_blink_traffic_led -
 *
 * Blink the traffic led with the requsted rate
 *
 *------------------------------------------------------------------------
 */
lm_status_t lm_blink_traffic_led(struct _lm_device_t *pdev, u32_t port_idx, u32_t rate)
{
    u32_t reg_val   = 0;
    // If port 0 then use EMAC0, else use EMAC1
    u32_t emac_base = (port_idx) ? GRCBASE_EMAC1 : GRCBASE_EMAC0;

    DbgBreakIf(!pdev);

    // Find if the traffic control is via BMAC or EMAC
    if (port_idx == 0) {
        reg_val = REG_RD(pdev,  NIG_REG_NIG_EMAC0_EN);
    } else {
        reg_val = REG_RD(pdev,  NIG_REG_NIG_EMAC1_EN);
    }

    // Blink the traffic led using EMAC control:
    if (reg_val == 1) {
        // Read the current value of the LED register in the EMAC block
        reg_val = REG_RD(pdev, emac_base + EMAC_REG_EMAC_LED);

        // Set the TRAFFIC_OVERRIDE, TRAFFIC and BLNK_TRAFFIC to 1
        reg_val |= EMAC_LED_OVERRIDE;
        reg_val |= EMAC_LED_TRAFFIC;
        reg_val |= EMAC_LED_BLNK_TRAFFIC;

        // If rate field was entered then set the BLNK_RATE_ENA bit and the BLNK_RATE field,
        // Otherwise the blink rate will be about 16Hz
        if (rate != 0) {
            reg_val |= EMAC_LED_BLNK_RATE_ENA;
            reg_val |= (rate << EMAC_LED_BLNK_RATE_BITSHIFT);
        }
        REG_WR(pdev, emac_base+ EMAC_REG_EMAC_LED, reg_val);
        DbgMessage(NULL, INFORM, "lm_blink_traffic_led() port %d write to EMAC_REG_EMAC_LED the value 0x%x\n", port_idx, reg_val);

    } else { // Blink the traffic led in the BMAC:
        // Set the CONTROL_OVERRIDE_TRAFFIC and the CONTROL_BLINK_TRAFFIC to 1.
        if (port_idx == 0) {
            REG_WR(pdev,  NIG_REG_LED_CONTROL_OVERRIDE_TRAFFIC_P0, 1);
            REG_WR(pdev,  NIG_REG_LED_CONTROL_TRAFFIC_P0, 1);
            REG_WR(pdev,  NIG_REG_LED_CONTROL_BLINK_TRAFFIC_P0, 1);
            DbgMessage(NULL, INFORM, "lm_blink_traffic_led() set BLINK_TRAFFIC_P0 to 1\n");
            // If the rate field was entered, update the BLINK_RATE register accordingly
            if (rate != 0) {
                REG_WR(pdev,  NIG_REG_LED_CONTROL_BLINK_RATE_ENA_P0, 1);
                REG_WR(pdev,  NIG_REG_LED_CONTROL_BLINK_RATE_P0, rate);
                DbgMessage(NULL, INFORM, "lm_blink_traffic_led() port %d write to NIG_REG_LED_CONTROL_BLINK_RATE_P0 %x\n", port_idx, rate);
            }
        } else {
            REG_WR(pdev,  NIG_REG_LED_CONTROL_OVERRIDE_TRAFFIC_P1, 1);
            REG_WR(pdev,  NIG_REG_LED_CONTROL_TRAFFIC_P1, 1);
            REG_WR(pdev,  NIG_REG_LED_CONTROL_BLINK_TRAFFIC_P1, 1);
            DbgMessage(NULL, INFORM, "lm_blink_traffic_led() set BLINK_TRAFFIC_P1 to 1\n");
            // If the rate field was entered, update the BLINK_RATE register accordingly
            if (rate != 0) {
                REG_WR(pdev,  NIG_REG_LED_CONTROL_BLINK_RATE_ENA_P1, 1);
                REG_WR(pdev,  NIG_REG_LED_CONTROL_BLINK_RATE_P1, rate);
                DbgMessage(NULL, INFORM, "lm_blink_traffic_led() port %d write to NIG_REG_LED_CONTROL_BLINK_RATE_P1 0x%x\n", port_idx, rate);
            }
        }
    }
    return LM_STATUS_SUCCESS;
}

/*
 *------------------------------------------------------------------------
 * lm_get_led_status -
 *
 * Get the led status of the requsted led, on the requested port
 *
 *------------------------------------------------------------------------
 */
lm_status_t lm_get_led_status(struct _lm_device_t *pdev, u32_t port_idx, u32_t led_idx, u32_t* value_ptr)
{
    u32_t reg_val   = 0;

    // If port 0 then use EMAC0, else use EMAC1
    u32_t emac_base = (port_idx) ? GRCBASE_EMAC1 : GRCBASE_EMAC0;

    DbgBreakIf(!pdev);

    switch (led_idx) {
        case 0: //10MB LED
            // Read the current value of the LED register in the EMAC block
            reg_val = REG_RD(pdev, emac_base + EMAC_REG_EMAC_LED);
            // Check the 10MB bit status
            *value_ptr = ((reg_val & EMAC_LED_10MB) == EMAC_LED_10MB) ? 1 : 0;
            break;
        case 1: //100MB LED
            // Read the current value of the LED register in the EMAC block
            reg_val = REG_RD(pdev, emac_base + EMAC_REG_EMAC_LED);
            // Check the 100MB bit status
            *value_ptr = ((reg_val & EMAC_LED_100MB) == EMAC_LED_100MB) ? 1 : 0;
            break;
        case 2: //1000MB LED
            // Read the current value of the LED register in the EMAC block
            reg_val = REG_RD(pdev, emac_base + EMAC_REG_EMAC_LED);
            // Check the 1000MB bit status
            *value_ptr = ((reg_val & EMAC_LED_1000MB) == EMAC_LED_1000MB) ? 1 : 0;
            break;
        case 3: //2500MB LED
            // Read the current value of the LED register in the EMAC block
            reg_val = REG_RD(pdev, emac_base + EMAC_REG_EMAC_LED);
            // Check the 2500MB bit status
            *value_ptr = ((reg_val & EMAC_LED_2500MB) == EMAC_LED_2500MB) ? 1 : 0;
            break;
        case 4: //10G LED
            if (port_idx == 0) {
                *value_ptr = REG_RD(pdev,  NIG_REG_LED_10G_P0);
            } else {
                *value_ptr = REG_RD(pdev,  NIG_REG_LED_10G_P1);
            }
            break;
        case 5: //TRAFFIC LED
            // Read the traffic led from the EMAC block
            reg_val = REG_RD(pdev, emac_base + EMAC_REG_EMAC_LED);
            // Check the TRAFFIC_STAT bit status
            *value_ptr = ((reg_val & EMAC_LED_TRAFFIC_STAT) == EMAC_LED_TRAFFIC_STAT) ? 1 : 0;

            // Read the traffic led from the BMAC block
            if (port_idx == 0) {
                *value_ptr = REG_RD(pdev,  NIG_REG_LED_STATUS_ACTIVE_P0);
            } else {
                *value_ptr = REG_RD(pdev,  NIG_REG_LED_STATUS_ACTIVE_P1);
            }
            break;
        default:
            DbgMessage(NULL, FATAL, "lm_get_led_status() unknown led index %d (should be 0-5)\n", led_idx);
            return LM_STATUS_FAILURE;
    }

    DbgMessage(NULL, INFORM, "lm_get_led_status() port %d led_idx %d value %d\n", port_idx, led_idx, *value_ptr);

    return LM_STATUS_SUCCESS;

}

/*
*------------------------------------------------------------------------
* lm_reset_led -
*
* Sets the LEDs to operational mode after establishing link
*
*------------------------------------------------------------------------
*/
void
lm_reset_led(struct _lm_device_t *pdev)
{
    //u32_t val;
    u8_t port = 0;

    if (CHK_NULL(pdev)){
        DbgBreakIf(!pdev);
        return;
    }
    port = PORT_ID(pdev);

    REG_WR(pdev,  NIG_REG_LED_10G_P0 + port*4, 0);
    REG_WR(pdev,  NIG_REG_LED_MODE_P0 + port*4,SHARED_HW_CFG_LED_MAC1);
}

static u8_t lm_is_57710A0_dbg_intr( struct _lm_device_t * pdev )
{
    u32_t val = 0;

    /* if during MSI/MSI-X mode then take no action (different problem) */
    if(pdev->params.interrupt_mode != LM_INT_MODE_INTA)
    {
        DbgMessage(pdev, WARN, "MSI/MSI-X enabled - debugging INTA/B failed\n");
        return 0;
    }

    /* read status from PCIE core */
    val = REG_RD(pdev, 0x2004);

    /* if interrupt line value from PCIE core is not asserted then take no action (different problem) */
    #define PCIE_CORE_INT_PENDING_BIT 0X00080000 /* when this bit is set, interrupt is asserted (pending) */
    if(!GET_FLAGS(val, PCIE_CORE_INT_PENDING_BIT))
    {
        DbgMessage(pdev, WARN, "PCIE core int line not asserted - debugging INTA/B failed\n");
        return 0;
    }

    /* if interrupt line from PCIE core is not enabled then take no action (different problem) */
    #define PCIE_CORE_INT_DISABLE_BIT 0X00000400 /* when this bit is set, interrupt is disabled */
    if(GET_FLAGS(val, PCIE_CORE_INT_DISABLE_BIT))
    {
        DbgMessage(pdev, WARN, "PCIE core int line not enabled - debugging INTA/B failed\n");
        return 0;
    }

    /* read interrupt mask from IGU */
    val = REG_RD(pdev,  HC_REG_INT_MASK + 4*PORT_ID(pdev) );

    /* if not 1FFFF then write warning to log (suspected as different problem) and continue to following step */
    if(val != 0x0001ffff)
    {
        DbgMessage(pdev, WARN, "IGU int mask != 0x1ffff - might not be related to debugging INTA/B issue\n");
    }

    /* verify that int_line_en_0/1 is 1. If bit is clear then no action  write warning to log and return. */
    // We skip this check.

    return 1;
}

/** lm_57710A0_dbg_intr
 *
 * Description:
 * 1. some sanity checks that the case we have is indeed the
 * interrupt debugging mode.
 * 2. Apply special handling, that is to disable and enable
 * INTA/B in IGU
 */
void lm_57710A0_dbg_intr( struct _lm_device_t * pdev )
{
    if(IS_CHIP_REV_A0(pdev) && lm_is_57710A0_dbg_intr(pdev))
    {
        lm_disable_int(pdev);
        lm_enable_int(pdev);
    }
}

/*******************************************************************************
 * Description: turn led on/off/operational mode
 *              Must be called under PHY_LOCK
 * Return:
 ******************************************************************************/
lm_status_t
lm_set_led_wrapper(struct _lm_device_t*     pdev,
                   const   u8_t             led_mode )
{
    u8_t        elink_res = ELINK_STATUS_OK;
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    PHY_HW_LOCK(pdev);
    elink_res = elink_set_led( &pdev->params.link, &pdev->vars.link, led_mode, pdev->vars.link.line_speed );
    PHY_HW_UNLOCK(pdev);

    switch(elink_res)
    {
    case ELINK_STATUS_OK:
        lm_status = LM_STATUS_SUCCESS;
        break;

    case ELINK_STATUS_ERROR:
    default:
        lm_status = LM_STATUS_FAILURE;
        break;
    }// switch elink_res

    return lm_status;
} /* lm_set_led */

/*******************************************************************************
 * Description: Reads the parametrs using elink interface
 *              Must be called under PHY_LOCK
 * Return:
 ******************************************************************************/
lm_status_t
lm_get_transceiver_data(struct _lm_device_t*     pdev,
                        b10_transceiver_data_t*  b10_transceiver_data )
{
    u16_t eeprom_data[][2] = { { ELINK_SFP_EEPROM_VENDOR_NAME_ADDR, ELINK_SFP_EEPROM_VENDOR_NAME_SIZE},
                               { ELINK_SFP_EEPROM_PART_NO_ADDR,     ELINK_SFP_EEPROM_PART_NO_SIZE},
                               { ELINK_SFP_EEPROM_SERIAL_ADDR,      ELINK_SFP_EEPROM_SERIAL_SIZE},
                               { ELINK_SFP_EEPROM_REVISION_ADDR,    ELINK_SFP_EEPROM_REVISION_SIZE},
                               { ELINK_SFP_EEPROM_DATE_ADDR,        ELINK_SFP_EEPROM_DATE_SIZE} } ;

    u8_t        vendor_name  [ELINK_SFP_EEPROM_VENDOR_NAME_SIZE] = {0};
    u8_t        model_num    [ELINK_SFP_EEPROM_PART_NO_SIZE]     = {0};
    u8_t        serial_num   [ELINK_SFP_EEPROM_SERIAL_SIZE]      = {0};
    u8_t        revision_num [ELINK_SFP_EEPROM_REVISION_SIZE]    = {0};
    u8_t        mfg_date     [ELINK_SFP_EEPROM_DATE_SIZE]        = {0};
    u8_t*       ptr_arr[ARRSIZE(eeprom_data)]                    = {0}; // for convinence of coding
    u8_t        idx                                              = 0;
    u8_t        elink_res                                        = ELINK_STATUS_ERROR;
    u8_t        ext_phy_type                                     = 0;
    lm_status_t lm_status                                        = LM_STATUS_SUCCESS;

    // we use local variables (vendor_name, model_num etc...) to protect flows in IA64
    // that upper layer might send us non-aligned to u16_t pointer, in this case a BSOD might occur.
    // using local variables and than memcpy prevent such situation.

    if CHK_NULL( b10_transceiver_data )
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    ASSERT_STATIC( sizeof(b10_transceiver_data->vendor_name)  == sizeof(vendor_name) ) ;
    ASSERT_STATIC( sizeof(b10_transceiver_data->model_num)    == sizeof(model_num) ) ;
    ASSERT_STATIC( sizeof(b10_transceiver_data->serial_num)   == sizeof(serial_num) ) ;
    ASSERT_STATIC( sizeof(b10_transceiver_data->revision_num) == sizeof(revision_num) ) ;
    ASSERT_STATIC( sizeof(b10_transceiver_data->mfg_date)     == sizeof(mfg_date) ) ;

    mm_mem_zero( b10_transceiver_data, sizeof( b10_transceiver_data_t ) ) ;

    ptr_arr[0] = &vendor_name[0];
    ptr_arr[1] = &model_num[0];
    ptr_arr[2] = &serial_num[0];
    ptr_arr[3] = &revision_num[0];
    ptr_arr[4] = &mfg_date[0];

    if( pdev->params.link.num_phys > ELINK_MAX_PHYS )
    {
        DbgBreakIf(1);
        return LM_STATUS_FAILURE;
    }

    // query from elink all ext_phy types (currently 1 and 2)
    for( ext_phy_type = ELINK_EXT_PHY1; ext_phy_type < pdev->params.link.num_phys; ext_phy_type++ )
    {
        if( ELINK_ETH_PHY_SFPP_10G_FIBER == pdev->params.link.phy[ext_phy_type].media_type ||
       ELINK_ETH_PHY_SFP_1G_FIBER == pdev->params.link.phy[ext_phy_type].media_type ||
        ELINK_ETH_PHY_DA_TWINAX == pdev->params.link.phy[ext_phy_type].media_type)
        {
            // only in case not SFP+ - the elink query is supported
            for( idx = 0; idx < ARRSIZE(eeprom_data) ; idx++ )
            {
                PHY_HW_LOCK(pdev);
                elink_res = elink_read_sfp_module_eeprom( &pdev->params.link.phy[ext_phy_type], // ELINK_INT_PHY, ELINK_EXT_PHY1, ELINK_EXT_PHY2
                                                          &pdev->params.link,
							  ELINK_I2C_DEV_ADDR_A0,
                                                          eeprom_data[idx][0],
                                                          (u8_t)eeprom_data[idx][1],
                                                          ptr_arr[idx] ) ;
                PHY_HW_UNLOCK(pdev);
                if( ELINK_STATUS_OK != elink_res )
                {
                    // We assume that if one of the queries failed - there is an error so we break this loop
                    break;
                }

            } // for "eeprom_data" size

            // only one sfp+ module is expected on board so we exit the ext_phy_type loop
            break;

        } // ELINK_ETH_PHY_SFP_FIBER == media_type

    } // for "ext_phy_type"

    switch(elink_res)
    {
    case ELINK_STATUS_OK:
        {
            b10_transceiver_data->ver_num = TRANSCEIVER_DATA_VER_NUM;

            mm_memcpy( b10_transceiver_data->vendor_name,  &vendor_name[0],  sizeof(vendor_name) );
            mm_memcpy( b10_transceiver_data->model_num,    &model_num[0],    sizeof(model_num) );
            mm_memcpy( b10_transceiver_data->serial_num,   &serial_num[0],   sizeof(serial_num) );
            mm_memcpy( b10_transceiver_data->revision_num, &revision_num[0], sizeof(revision_num) );
            mm_memcpy( b10_transceiver_data->mfg_date,     &mfg_date[0],     sizeof(mfg_date) );
        }
        lm_status = LM_STATUS_SUCCESS;
        break;

    case ELINK_STATUS_TIMEOUT:
        lm_status = LM_STATUS_TIMEOUT;
        break;

    case ELINK_STATUS_ERROR:
    default:
        lm_status = LM_STATUS_FAILURE;
        break;
    }// switch elink_res

    return lm_status;

} /* lm_get_transceiver_data */

lm_status_t lm_set_mac_in_nig(lm_device_t * pdev, u8_t * mac_addr, lm_cli_idx_t lm_cli_idx, u8_t offset)
{
    u32_t reg_offset = 0;
    u32_t wb_data[2] = {0};
    u8_t  enable_mac = 0;

    #define MAX_OFFSET_IN_MEM_1   8

    if (lm_cli_idx == LM_CLI_IDX_ISCSI)
    {
        offset = ECORE_LLH_CAM_ISCSI_ETH_LINE;
    }
    else if (offset == ECORE_LLH_CAM_ISCSI_ETH_LINE)
    {
        offset = MAX_MAC_OFFSET_IN_NIG; /* Invalidate offset if not iscsi and its in iscsi place */
    }

    /* We set the macs in the nig llh only for E2 SI/NIV mode and for NDIS only (first 16 entries) */
    if (CHIP_IS_E1x(pdev) || !IS_MULTI_VNIC(pdev) || IS_MF_SD_MODE(pdev) || offset >= MAX_MAC_OFFSET_IN_NIG)
    {
        return LM_STATUS_SUCCESS;
    }

    /* in switch-independt mode we need to configure the NIG LLH with the appropriate mac addresses, we use the
     * cam mapping 1--1 for all indices smaller than 16 */
    if (mac_addr)
    {
        DbgMessage(pdev, WARN, "Setting mac in nig to offset: %d mac_addr[%02x]:[%02x]:[%02x]:[%02x]:[%02x]:[%02x]\n", offset,
                   mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
        DbgMessage(pdev, WARN, "[%x]:[%x]\n",  mac_addr[6], mac_addr[7]);

        if (offset < MAX_OFFSET_IN_MEM_1)
        {
            reg_offset = (PORT_ID(pdev)? NIG_REG_LLH1_FUNC_MEM: NIG_REG_LLH0_FUNC_MEM) + 8*offset;
        }
        else
        {
            reg_offset = (PORT_ID(pdev)? NIG_REG_P1_LLH_FUNC_MEM2: NIG_REG_P0_LLH_FUNC_MEM2) + 8*(offset - MAX_OFFSET_IN_MEM_1);
        }

        wb_data[0] = ((mac_addr[2] << 24) | (mac_addr[3] << 16) | (mac_addr[4] << 8) | mac_addr[5]);
        wb_data[1] = ((mac_addr[0] << 8)  | mac_addr[1]);

        REG_WR_DMAE_LEN(pdev, reg_offset, wb_data, ARRSIZE(wb_data));

        enable_mac = 1;
    }

    DbgMessage(pdev, WARN, "Enable_mac: %d\n", enable_mac);

    if (offset < MAX_OFFSET_IN_MEM_1)
    {
        reg_offset = (PORT_ID(pdev)? NIG_REG_LLH1_FUNC_MEM_ENABLE : NIG_REG_LLH0_FUNC_MEM_ENABLE) + 4*offset;
    }
    else
    {
        reg_offset = (PORT_ID(pdev)? NIG_REG_P1_LLH_FUNC_MEM2_ENABLE : NIG_REG_P0_LLH_FUNC_MEM2_ENABLE) + 4*(offset - MAX_OFFSET_IN_MEM_1);
    }
    REG_WR(pdev, reg_offset, enable_mac);

    return LM_STATUS_SUCCESS;
}

/**
 * Table to lookup appropriate lock register for function.
 *
 * Indexed with func ID (0-7).
 *
 * Note registers are *not* consecutive, thus table.
 */

static const u32_t lm_hw_lock_table[8] = {
        MISC_REG_DRIVER_CONTROL_1, /* 0 */
        MISC_REG_DRIVER_CONTROL_2, /* 1 */
        MISC_REG_DRIVER_CONTROL_3, /* 2 */
        MISC_REG_DRIVER_CONTROL_4, /* 3 */
        MISC_REG_DRIVER_CONTROL_5, /* 4 */
        MISC_REG_DRIVER_CONTROL_6, /* 5 */
        MISC_REG_DRIVER_CONTROL_7, /* 6 */
        MISC_REG_DRIVER_CONTROL_8, /* 7 */
};

/*******************************************************************************
 * Description:
 *         Acquiring the HW lock for a specific resource.
 *         The assumption is that only 1 bit is set in the resource parameter
 *         There is a HW attention in case the same function attempts to
 *         acquire the same lock more than once
 *
 * Params:
 *         resource: the HW LOCK Register name
 *         b_block: Try to get lock until succesful, or backout immediately on failure.
 * Return:
 *          Success - got the lock
 *          Fail - Invalid parameter or could not obtain the lock for our 1 sec in block mode
 *          or couldn't obtain lock one-shot in non block mode
 ******************************************************************************/
lm_status_t lm_hw_lock(      lm_device_t* pdev,
                       const u32_t        resource,
                       const u8_t         b_block)
{
    u32_t cnt                = 0;
    u32_t lock_status        = 0;
    u32_t const resource_bit = (1 << resource);
    u8_t  const func         = FUNC_ID(pdev);
    u32_t hw_lock_cntr_reg   = 0;

    // Validating the resource in within range
    if (resource > HW_LOCK_MAX_RESOURCE_VALUE)
    {
        DbgMessage(pdev, FATAL, "lm_hw_lock: LM_STATUS_INVALID_PARAMETER resource=0x%x\n", resource);
        DbgBreakMsg("lm_hw_lock: LM_STATUS_INVALID_PARAMETER\n");
        return LM_STATUS_INVALID_PARAMETER;
    }

    DbgBreakIf(func >= ARRSIZE(lm_hw_lock_table));
    hw_lock_cntr_reg = lm_hw_lock_table[func];

    // Validating that the resource is not already taken
    lock_status = REG_RD(pdev, hw_lock_cntr_reg);
    if (lock_status & resource_bit)
    {
        DbgMessage(pdev, FATAL , "lm_hw_lock: LM_STATUS_EXISTING_OBJECT lock_status=0x%x resource_bit=0x%x\n", lock_status, resource_bit);
        DbgBreakMsg("lm_hw_lock: LM_STATUS_EXISTING_OBJECT\n");
        return LM_STATUS_EXISTING_OBJECT;
    }
    // Try for 16 second every 50us
    for (cnt = 0; cnt < 320000; cnt++)
    {
        // Try to acquire the lock
        REG_WR(pdev, hw_lock_cntr_reg + 4, resource_bit);
        lock_status= REG_RD(pdev, hw_lock_cntr_reg);
        if (lock_status & resource_bit)
        {
            return LM_STATUS_SUCCESS;
        }
        if (!b_block)
        {
            return LM_STATUS_FAILURE;
        }
        mm_wait(pdev, 50);
    }
    DbgMessage(pdev, FATAL , "lm_hw_lock: LM_STATUS_TIMEOUT\n" );
    DbgBreakMsg("lm_hw_lock: FAILED LM_STATUS_TIMEOUT\n");
    return LM_STATUS_TIMEOUT;
}
/*******************************************************************************
 * Description:
 *         Releasing the HW lock for a specific resource.
 *         There is a HW attention in case the a function attempts to release
 *         a lock that it did not acquire (if b_verify_locked is TRUE, default)
 * Return:
 *          Success - if the parameter is valid, the assumption is that it
 *                    will succeed
 *          Fail - Invalid parameter
 ******************************************************************************/
lm_status_t lm_hw_unlock_ex(lm_device_t*  pdev,
                            const u32_t   resource,
                            const u8_t    b_verify_locked )
{
    u32_t lock_status        = 0;
    u32_t const resource_bit = (1 << resource);
    u8_t  const func         = FUNC_ID(pdev);
    u32_t hw_lock_cntr_reg   = 0;

    // Validating the resource in within range
    if (resource > HW_LOCK_MAX_RESOURCE_VALUE)
    {
        DbgMessage(pdev, FATAL, "lm_hw_unlock: LM_STATUS_INVALID_PARAMETER resource=0x%x\n", resource);
        DbgBreakMsg("lm_hw_unlock: LM_STATUS_INVALID_PARAMETER\n");
        return LM_STATUS_INVALID_PARAMETER;
    }

    DbgBreakIf(func >= ARRSIZE(lm_hw_lock_table));
    hw_lock_cntr_reg = lm_hw_lock_table[func];

    // Validating that the resource is currently taken
    lock_status = REG_RD(pdev, hw_lock_cntr_reg);
    if (!(lock_status & resource_bit))
    {
        // This comment is explicitly outside the IF since we still want to be aware it happened.
        DbgMessage(pdev, FATAL, "lm_hw_unlock: LM_STATUS_OBJECT_NOT_FOUND lock_status=0x%x resource_bit=0x%x\n", lock_status, resource_bit);

        if( b_verify_locked )
        {
           DbgBreakMsg("lm_hw_unlock: LM_STATUS_OBJECT_NOT_FOUND\n");
           return LM_STATUS_OBJECT_NOT_FOUND;
        }
    }
    REG_WR(pdev, hw_lock_cntr_reg, resource_bit);

    return LM_STATUS_SUCCESS;
}

/*******************************************************************************
 * Description:
 *         Releasing the HW lock for a specific resource.
 *         There is a HW attention in case the a function attempts to release
 *         a lock that it did not acquire
           THIS function is a wrapper function now for lm_hw_unlock_ex.
 * Return:
 *          Success - if the parameter is valid, the assumption is that it
 *                    will succeed
 *          Fail - Invalid parameter
 ******************************************************************************/
lm_status_t lm_hw_unlock(lm_device_t*      pdev,
                         const u32_t       resource)
{
    return lm_hw_unlock_ex( pdev, resource, TRUE);
}

/**
 * @Desription
 *      This function is used to recover from a state where the
 *      locks stayed in "taken" state during a reboot. We want
 *      to clear all the locks before proceeding.
 *
 * @param pdev
 */
void lm_hw_clear_all_locks(lm_device_t *pdev)
{
    u32_t lock_status        = 0;
    u32_t hw_lock_cntr_reg   = 0;
    u8_t  func               = 0;

    /* We clear locks due to error recover possible failure leaving locking traces...
     * we do this only for E2 and above */
    if (CHIP_IS_E1x(pdev))
    {
        return;
    }

    for (func = 0; func < MAX_FUNC_NUM; func++)
    {
        DbgBreakIf(func >= ARRSIZE(lm_hw_lock_table));
        hw_lock_cntr_reg = lm_hw_lock_table[func];

        lock_status = REG_RD(pdev, hw_lock_cntr_reg);
        if (lock_status != 0)
        {
            REG_WR(pdev, hw_lock_cntr_reg, lock_status);
        }
    }
}

u32_t reg_wait_verify_val(struct _lm_device_t * pdev, u32_t reg_offset, u32_t excpected_val, u32_t total_wait_time_ms )
{
    u32_t val            = 0 ;
    u32_t wait_cnt       = 0 ;
    u32_t wait_cnt_limit = total_wait_time_ms/DEFAULT_WAIT_INTERVAL_MICSEC ;
    if( wait_cnt_limit == 0 )
    {
        wait_cnt_limit = 1;
    }
    val=REG_RD(pdev,reg_offset);
    while( (val != excpected_val) && (wait_cnt++ != wait_cnt_limit) )
    {
        mm_wait(pdev, DEFAULT_WAIT_INTERVAL_MICSEC) ;
        val=REG_RD(pdev,reg_offset);
    }
    if (val != excpected_val) {
        DbgMessage(pdev, WARN, "val = 0x%x, expected val = 0x%x\n", val, excpected_val );
    DbgBreakIf(val != excpected_val);
    }
    return wait_cnt;
}

/*******************************************************************************
 * Description:
 *     stop any dma transactions to/from chip
 *     after this function is called, no write to chip is availalbe anymore.
 * Return:
 *     void
 ******************************************************************************/
void lm_disable_pci_dma(struct _lm_device_t *pdev, u8_t b_wait_for_done)
{
    u32_t       val   = 0;
    u32_t       idx   = 0;
    const u32_t flags = (PCICFG_DEVICE_STATUS_NO_PEND << 16) ;

    if (IS_PFDEV(pdev))
    {
        if (CHIP_IS_E1x(pdev))
        {
            /* Disable bus_master. */
            val=REG_RD(pdev,GRCBASE_PCICONFIG+PCICFG_COMMAND_OFFSET);
            RESET_FLAGS( val, PCICFG_COMMAND_BUS_MASTER );
            REG_WR(pdev,GRCBASE_PCICONFIG+PCICFG_COMMAND_OFFSET,val);
        }
        else
        {
            /* In E2, there is a cleaner way to disable pci-dma, no need for a pci-configuration
             * transaction */
            REG_WR(pdev, PGLUE_B_REG_INTERNAL_PFID_ENABLE_MASTER, 0);
        }

        /* wait until there is no pending transaction. */
        if (b_wait_for_done)
        {
            for(idx = 0; idx < 1000; idx++)
            {
                val=REG_RD(pdev,GRCBASE_PCICONFIG+PCICFG_DEVICE_CONTROL);
                if( (val & flags) == 0)
                {
                    break;
                }
                mm_wait(pdev, 5);
            }
        }
    }
}
/*******************************************************************************
 * Description:
 *     enable Bus Master Enable
 * Return:
 *     void
 ******************************************************************************/
void lm_enable_pci_dma(struct _lm_device_t *pdev)
{
    u32_t       val   = 0;
    if (IS_PFDEV(pdev))
    {
        if (CHIP_IS_E1x(pdev))
        {
            /* Enable bus_master. */
            val=REG_RD(pdev,GRCBASE_PCICONFIG+PCICFG_COMMAND_OFFSET);
            if( 0 == GET_FLAGS( val, PCICFG_COMMAND_BUS_MASTER ) )
            {
                SET_FLAGS( val, PCICFG_COMMAND_BUS_MASTER );
                REG_WR(pdev,GRCBASE_PCICONFIG+PCICFG_COMMAND_OFFSET,val);
            }
        }
        else
        {
            /* In E2, there is a cleaner way to disable pci-dma, no need for a pci-configuration
             * transaction */
            REG_WR(pdev, PGLUE_B_REG_INTERNAL_PFID_ENABLE_MASTER, 1);
        }
    }
}
/*******************************************************************************
 * Description:
 *     disable non fatal error pcie reporting
 * Return:
 *     void
 ******************************************************************************/
void lm_set_pcie_nfe_report(lm_device_t *pdev)
{
    if(IS_PFDEV(pdev) && pdev->params.disable_pcie_nfr)
    {
        u32_t pci_devctl = 0 ;
        pci_devctl = REG_RD(pdev,GRCBASE_PCICONFIG + PCICFG_DEVICE_CONTROL);
        RESET_FLAGS( pci_devctl, PCICFG_DEVICE_STATUS_NON_FATAL_ERR_DET );
        REG_WR(pdev,GRCBASE_PCICONFIG + PCICFG_DEVICE_CONTROL,pci_devctl);
    }
}

// These lm_reg_xx_ind_imp() are for blk reading when lock is acquired only once (for the whole block reading)
void
lm_reg_rd_ind_imp(
    lm_device_t *pdev,
    u32_t offset,
    u32_t *ret)
{
    DbgBreakIf(offset & 0x3);
    mm_write_pci(pdev,PCICFG_GRC_ADDRESS,offset);
    mm_read_pci(pdev,PCICFG_GRC_DATA,ret);
} /* lm_reg_rd_ind_imp */
void
lm_reg_wr_ind_imp(
    lm_device_t *pdev,
    u32_t offset,
    u32_t val)
{
    u32_t dummy;
    DbgBreakIf(offset & 0x3);
    mm_write_pci(pdev,PCICFG_GRC_ADDRESS,offset);
    mm_write_pci(pdev,PCICFG_GRC_DATA,val);
    lm_reg_rd_ind_imp(pdev,PCICFG_VENDOR_ID_OFFSET,&dummy);
} /* lm_reg_wr_ind_imp */
/*******************************************************************************
 * Description:
 *
 * Return:
 *    None.
 *
 * Note:
 *    The caller is responsible for synchronizing calls to lm_reg_rd_ind and
 *    lm_reg_wr_ind.
 ******************************************************************************/
void
lm_reg_rd_ind(
    lm_device_t *pdev,
    u32_t offset,
    u32_t *ret)
{
    MM_ACQUIRE_IND_REG_LOCK(pdev);
    lm_reg_rd_ind_imp(pdev,offset,ret);
    MM_RELEASE_IND_REG_LOCK(pdev);
} /* lm_reg_rd_ind */
/*******************************************************************************
 * Description:
 *
 * Return:
 *    None.
 *
 * Note:
 *    The caller is responsible for synchronizing calls to lm_reg_rd_ind and
 *    lm_reg_wr_ind.
 ******************************************************************************/
void
lm_reg_wr_ind(
    lm_device_t *pdev,
    u32_t offset,
    u32_t val)
{
    MM_ACQUIRE_IND_REG_LOCK(pdev);
    lm_reg_wr_ind_imp(pdev,offset,val);
    MM_RELEASE_IND_REG_LOCK(pdev);
} /* lm_reg_wr_ind */
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_reg_rd_blk(
    lm_device_t *pdev,
    u32_t reg_offset,
    u32_t *buf_ptr,
    u32_t u32t_cnt)
{
    u32_t current_offset = 0;
    DbgBreakIf(reg_offset & 0x3);
    while(u32t_cnt)
    {
        *buf_ptr = REG_RD(pdev, reg_offset + current_offset);
        buf_ptr++;
        u32t_cnt--;
        current_offset += 4;
    }
} /* lm_reg_rd_blk */
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_reg_rd_blk_ind(
    lm_device_t *pdev,
    u32_t reg_offset,
    u32_t *buf_ptr,
    u32_t u32t_cnt,
    u8_t acquire_lock_flag)
{
    u32_t current_offset = 0;
    if(acquire_lock_flag)
    {
        MM_ACQUIRE_IND_REG_LOCK(pdev);
    }
    while(u32t_cnt)
    {
        lm_reg_rd_ind_imp(pdev, reg_offset + current_offset, buf_ptr);
        buf_ptr++;
        u32t_cnt--;
        current_offset += 4;
    }
    if(acquire_lock_flag)
    {
        MM_RELEASE_IND_REG_LOCK(pdev);
    }
} /* lm_reg_rd_blk_ind */

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_reg_wr_blk(
    lm_device_t *pdev,
    u32_t reg_offset,
    u32_t *data_ptr,
    u32_t u32t_cnt)
{
    u32_t current_offset = 0;
    DbgBreakIf(reg_offset & 0x3);
    while(u32t_cnt)
    {
        REG_WR(pdev, reg_offset + current_offset, *data_ptr);
        data_ptr++;
        u32t_cnt--;
        current_offset += 4;
    }
} /* lm_reg_wr_blk */

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_reg_wr_blk_ind(
    lm_device_t *pdev,
    u32_t reg_offset,
    u32_t *data_ptr,
    u32_t u32t_cnt)
{
    u32_t current_offset = 0;

    MM_ACQUIRE_IND_REG_LOCK(pdev);
    while(u32t_cnt)
    {
        lm_reg_wr_ind_imp(pdev, reg_offset + current_offset, *data_ptr);
        data_ptr++;
        u32t_cnt--;
        current_offset += 4;
    }
    MM_RELEASE_IND_REG_LOCK(pdev);
} /* lm_reg_wr_blk_ind */

void lm_set_waitp(lm_device_t *pdev)
{
    REG_WR(pdev,DRV_DUMP_TSTORM_WAITP_ADDRESS,1);
    REG_WR(pdev,DRV_DUMP_XSTORM_WAITP_ADDRESS,1);
    REG_WR(pdev,DRV_DUMP_CSTORM_WAITP_ADDRESS,1);
    REG_WR(pdev,DRV_DUMP_USTORM_WAITP_ADDRESS,1);
}

void lm_collect_idle_storms_dorrbell_asserts( struct _lm_device_t *pdev,
                                              const  u8_t          b_idle_chk,
                                              const  u8_t          b_storms_asserts,
                                              const  u8_t          b_dorrbell_info )
{
#if !(defined(UEFI) || defined(DOS) || defined(__LINUX))
    if( b_idle_chk )
    {
        lm_idle_chk(pdev);
    }

    if( b_dorrbell_info )
    {
        lm_get_doorbell_info(pdev);
    }

    if( b_storms_asserts )
    {
        lm_get_storms_assert(pdev);
    }
#endif
}
