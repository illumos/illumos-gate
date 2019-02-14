/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lm5706.h"


/*******************************************************************************
 * Constants.
 ******************************************************************************/

/* Buffered flash (Atmel: AT45DB011B) specific information */
#define SEEPROM_SHIFT_BITS                      2
#define SEEPROM_PHY_PAGE_SIZE                   (1 << SEEPROM_SHIFT_BITS)
#define SEEPROM_BYTE_ADDR_MASK                  (SEEPROM_PHY_PAGE_SIZE-1)
#define SEEPROM_PAGE_SIZE                       4
#define SEEPROM_TOTAL_SIZE                      65536

#define BUFFERED_FLASH_SHIFT_BITS               9
#define BUFFERED_FLASH_PHY_PAGE_SIZE            (1 << BUFFERED_FLASH_SHIFT_BITS)
#define BUFFERED_FLASH_BYTE_ADDR_MASK           (BUFFERED_FLASH_PHY_PAGE_SIZE-1)
#define BUFFERED_FLASH_PAGE_SIZE                264
#define BUFFERED_FLASH_TOTAL_SIZE               0x21000

#define SAIFUN_FLASH_SHIFT_BITS                 8
#define SAIFUN_FLASH_PHY_PAGE_SIZE              (1 << SAIFUN_FLASH_SHIFT_BITS)
#define SAIFUN_FLASH_BYTE_ADDR_MASK             (SAIFUN_FLASH_PHY_PAGE_SIZE-1)
#define SAIFUN_FLASH_PAGE_SIZE                  256
#define SAIFUN_FLASH_BASE_TOTAL_SIZE            65536

#define ST_MICRO_FLASH_SHIFT_BITS               8
#define ST_MICRO_FLASH_PHY_PAGE_SIZE            (1 << ST_MICRO_FLASH_SHIFT_BITS)
#define ST_MICRO_FLASH_BYTE_ADDR_MASK           (ST_MICRO_FLASH_PHY_PAGE_SIZE-1)
#define ST_MICRO_FLASH_PAGE_SIZE                256
#define ST_MICRO_FLASH_BASE_TOTAL_SIZE          65536
#define ST_MICRO_FLASH_1MBIT                    0x20000

/* NVRAM flags for nvram_write_dword and nvram_read_dword. */
#define NVRAM_FLAG_NONE                         0x00
#define NVRAM_FLAG_SET_FIRST_CMD_BIT            0x01
#define NVRAM_FLAG_SET_LAST_CMD_BIT             0x02
#define NVRAM_FLAG_BUFFERED_FLASH               0x04

#define NVRAM_TIMEOUT_COUNT                     30000


#define FLASH_STRAP_MASK                        (NVM_CFG1_FLASH_MODE   | \
                                                 NVM_CFG1_BUFFER_MODE  | \
                                                 NVM_CFG1_PROTECT_MODE | \
                                                 NVM_CFG1_FLASH_SIZE)
#define FLASH_BACKUP_STRAP_MASK                 (0xf << 26)


typedef struct _new_nvm_cfg_t
{
    /* Strapping to indicate the flash type (original | backup) */
    u32_t strapping;
    /* New configuration values */
    u32_t config1;
    u32_t config2;
    u32_t config3;
    u32_t write1;
    u32_t buffered;
    u32_t shift_bits;
    u32_t page_size;
    u32_t addr_mask;
    u32_t total_size;
    char *name;
} new_nvm_cfg_t;

/* This table is indexed by the strap values */
static const new_nvm_cfg_t cfg_table[] =
{
    /* Slow EEPROM */
    {0x00000000, 0x40830380, 0x009f0081, 0xa184a053, 0xaf000400,
     1, SEEPROM_SHIFT_BITS, SEEPROM_PAGE_SIZE,
     SEEPROM_BYTE_ADDR_MASK, SEEPROM_TOTAL_SIZE,
     "EEPROM - slow"},
    /* Expansion entry 0001 */
    {0x08000002, 0x4b808201, 0x00050081, 0x03840253, 0xaf020406,
     0, SAIFUN_FLASH_SHIFT_BITS, SAIFUN_FLASH_PAGE_SIZE,
     SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
     "Entry 0001"},
    /* Saifun SA25F010 (non-buffered flash) */
    {0x04000001, 0x47808201, 0x00050081, 0x03840253, 0xaf020406,  /* strap, cfg1, & write1 need updates */
     0, SAIFUN_FLASH_SHIFT_BITS, SAIFUN_FLASH_PAGE_SIZE,
     SAIFUN_FLASH_BYTE_ADDR_MASK, SAIFUN_FLASH_BASE_TOTAL_SIZE*2,
     "Non-buffered flash (128kB)"},
    /* Saifun SA25F020 (non-buffered flash) */
    {0x0c000003, 0x4f808201, 0x00050081, 0x03840253, 0xaf020406,  /* strap, cfg1, & write1 need updates */
     0, SAIFUN_FLASH_SHIFT_BITS, SAIFUN_FLASH_PAGE_SIZE,
     SAIFUN_FLASH_BYTE_ADDR_MASK, SAIFUN_FLASH_BASE_TOTAL_SIZE*4,
     "Non-buffered flash (256kB)"},
    /* Expansion entry 0100 */
    {0x11000000, 0x53808201, 0x00050081, 0x03840253, 0xaf020406,
     0, SAIFUN_FLASH_SHIFT_BITS, SAIFUN_FLASH_PAGE_SIZE,
     SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
     "Entry 0100"},
    /* Entry 0101: ST M45PE10 (non-buffered flash, TetonII B0) */
    {0x19000002, 0x5b808201, 0x000500db, 0x03840253, 0xaf020406,
     0, ST_MICRO_FLASH_SHIFT_BITS, ST_MICRO_FLASH_PAGE_SIZE,
     ST_MICRO_FLASH_BYTE_ADDR_MASK, ST_MICRO_FLASH_BASE_TOTAL_SIZE*2,
     "Entry 0101: ST M45PE10 (128kB non-bufferred)"},
    /* Entry 0110: ST M45PE20 (non-buffered flash)*/
    {0x15000001, 0x57808201, 0x000500db, 0x03840253, 0xaf020406,
     0, ST_MICRO_FLASH_SHIFT_BITS, ST_MICRO_FLASH_PAGE_SIZE,
     ST_MICRO_FLASH_BYTE_ADDR_MASK, ST_MICRO_FLASH_BASE_TOTAL_SIZE*4,
     "Entry 0110: ST M45PE20 (256kB non-bufferred)"},
    /* Saifun SA25F005 (non-buffered flash) */
    {0x1d000003, 0x5f808201, 0x00050081, 0x03840253, 0xaf020406,  /* strap, cfg1, & write1 need updates */
     0, SAIFUN_FLASH_SHIFT_BITS, SAIFUN_FLASH_PAGE_SIZE,
     SAIFUN_FLASH_BYTE_ADDR_MASK, SAIFUN_FLASH_BASE_TOTAL_SIZE,
     "Non-buffered flash (64kB)"},
    /* Fast EEPROM */
    {0x22000000, 0x62808380, 0x009f0081, 0xa184a053, 0xaf000400,
     1, SEEPROM_SHIFT_BITS, SEEPROM_PAGE_SIZE,
     SEEPROM_BYTE_ADDR_MASK, SEEPROM_TOTAL_SIZE,
     "EEPROM - fast"},
    /* Expansion entry 1001 */
    {0x2a000002, 0x6b808201, 0x00050081, 0x03840253, 0xaf020406,
     0, SAIFUN_FLASH_SHIFT_BITS, SAIFUN_FLASH_PAGE_SIZE,
     SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
     "Entry 1001"},
    /* Expansion entry 1010 */
    {0x26000001, 0x67808201, 0x00050081, 0x03840253, 0xaf020406,
     0, SAIFUN_FLASH_SHIFT_BITS, SAIFUN_FLASH_PAGE_SIZE,
     SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
     "Entry 1010"},
    /* ATMEL AT45DB011B (buffered flash) */
    {0x2e000003, 0x6e808273, 0x00570081, 0x68848353, 0xaf000400,
     1, BUFFERED_FLASH_SHIFT_BITS, BUFFERED_FLASH_PAGE_SIZE,
     BUFFERED_FLASH_BYTE_ADDR_MASK, BUFFERED_FLASH_TOTAL_SIZE,
     "Buffered flash (128kB)"},
    /* Expansion entry 1100 */
    {0x33000000, 0x73808201, 0x00050081, 0x03840253, 0xaf020406,
     0, SAIFUN_FLASH_SHIFT_BITS, SAIFUN_FLASH_PAGE_SIZE,
     SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
     "Entry 1100"},
    /* Expansion entry 1101 */
    {0x3b000002, 0x7b808201, 0x00050081, 0x03840253, 0xaf020406,
     0, SAIFUN_FLASH_SHIFT_BITS, SAIFUN_FLASH_PAGE_SIZE,
     SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
     "Entry 1101"},
    /* Ateml Expansion entry 1110 */
    {0x37000001, 0x76808273, 0x00570081, 0x68848353, 0xaf000400,
     1, BUFFERED_FLASH_SHIFT_BITS, BUFFERED_FLASH_PAGE_SIZE,
     BUFFERED_FLASH_BYTE_ADDR_MASK, 0,
     "Entry 1110 (Atmel)"},
    /* ATMEL AT45DB021B (buffered flash) */
    {0x3f000003, 0x7e808273, 0x00570081, 0x68848353, 0xaf000400,
     1, BUFFERED_FLASH_SHIFT_BITS, BUFFERED_FLASH_PAGE_SIZE,
     BUFFERED_FLASH_BYTE_ADDR_MASK, BUFFERED_FLASH_TOTAL_SIZE*2,
     "Buffered flash (256kB)"},
};

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
acquire_nvram_lock(
    lm_device_t *pdev)
{
    lm_status_t lm_status;
    u32_t j, cnt;
    u32_t val;

    /* Adjust timeout for emulation/FPGA */
    cnt = NVRAM_TIMEOUT_COUNT;
    if (CHIP_REV(pdev) == CHIP_REV_FPGA) cnt *= 10;
    else if (CHIP_REV(pdev) == CHIP_REV_IKOS) cnt *= 100;

    val = 0;

    /* Request access to the flash interface. */
    REG_WR(pdev, nvm.nvm_sw_arb, NVM_SW_ARB_ARB_REQ_SET2);

    for(j = 0; j < cnt*10; j++)
    {
        REG_RD(pdev, nvm.nvm_sw_arb, &val);
        if(val & NVM_SW_ARB_ARB_ARB2)
        {
            break;
        }
        mm_wait(pdev, 5);
    }

    if(val & NVM_SW_ARB_ARB_ARB2)
    {
        lm_status = LM_STATUS_SUCCESS;
    }
    else
    {
        DbgBreakMsg("Cannot get access to nvram interface.\n");

        lm_status = LM_STATUS_BUSY;
    }
    return lm_status;
} /* acquire_nvram_lock */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
release_nvram_lock(
    lm_device_t *pdev)
{
    u32_t j, cnt;
    u32_t val;

    /* Relinquish nvram interface. */
    REG_WR(pdev, nvm.nvm_sw_arb, NVM_SW_ARB_ARB_REQ_CLR2);

    /* Adjust timeout for emulation/FPGA */
    cnt = NVRAM_TIMEOUT_COUNT;
    if (CHIP_REV(pdev) == CHIP_REV_FPGA) cnt *= 10;
    else if (CHIP_REV(pdev) == CHIP_REV_IKOS) cnt *= 100;

    val = 0;

    for(j = 0; j < cnt; j++)
    {
        REG_RD(pdev, nvm.nvm_sw_arb, &val);
        if(!(val & NVM_SW_ARB_ARB_ARB2))
        {
            break;
        }

        mm_wait(pdev, 5);
    }

    DbgBreakIf(val & NVM_SW_ARB_ARB_ARB2);
} /* release_nvram_lock */



/*******************************************************************************
 * Description:
 *
 * Return:
 *
 ******************************************************************************/
STATIC lm_status_t
enable_nvram_write(
    lm_device_t *pdev)
{
    u32_t val, j, cnt;
    lm_status_t lm_status;

    REG_RD(pdev, misc.misc_cfg, &val);
    REG_WR(pdev, misc.misc_cfg, val | MISC_CFG_NVM_WR_EN_PCI);

    lm_status = LM_STATUS_SUCCESS;

    if (!pdev->hw_info.flash_spec.buffered)
    {
        REG_WR(pdev, nvm.nvm_command, NVM_COMMAND_DONE);
        REG_WR(pdev, nvm.nvm_command, NVM_COMMAND_WREN  |
                                      NVM_COMMAND_DOIT);

        /* Adjust timeout for emulation/FPGA */
        cnt = NVRAM_TIMEOUT_COUNT;
        if (CHIP_REV(pdev) == CHIP_REV_FPGA) cnt *= 10;
        else if (CHIP_REV(pdev) == CHIP_REV_IKOS) cnt *= 100;

        lm_status = LM_STATUS_BUSY;

        for(j = 0; j < cnt; j++)
        {
            mm_wait(pdev, 5);

            REG_RD(pdev, nvm.nvm_command, &val);
            if(val & NVM_COMMAND_DONE)
            {
                lm_status = LM_STATUS_SUCCESS;
                break;
            }
        }
    }

    return lm_status;
} /* enable_nvram_write */



/*******************************************************************************
 * Description:
 *
 * Return:
 *
 ******************************************************************************/
STATIC lm_status_t
disable_nvram_write(
    lm_device_t *pdev)
{
    lm_status_t lm_status;
    u32_t val;

    REG_RD(pdev, misc.misc_cfg, &val);
    REG_WR(pdev, misc.misc_cfg, val & ~MISC_CFG_NVM_WR_EN);
    lm_status = LM_STATUS_SUCCESS;

#if 0 /* On Saifun and ST parts, WP kicks in at the end of the write.
         So, no need to have this. */
    if (!pdev->hw_info.flash_spec.buffered)
    {
        /* Restoring protection causes the next read at a wrong location;
         * leave this out for now. */
        REG_WR(pdev, nvm.nvm_command, NVM_COMMAND_DONE);
        REG_WR(pdev, nvm.nvm_command, NVM_COMMAND_WRDI  |
                                      NVM_COMMAND_DOIT);

        /* Adjust timeout for emulation/FPGA */
        cnt = NVRAM_TIMEOUT_COUNT;
        if (CHIP_REV(pdev) == CHIP_REV_FPGA) cnt *= 10;
        else if (CHIP_REV(pdev) == CHIP_REV_IKOS) cnt *= 100;

        lm_status = LM_STATUS_BUSY;
        for(j = 0; j < cnt; j++)
        {
            mm_wait(pdev, 5);

            REG_RD(pdev, nvm.nvm_command, &val);
            if(val & NVM_COMMAND_DONE)
            {
                lm_status = LM_STATUS_SUCCESS;
                break;
            }
        }
    }
#endif

    return lm_status;
} /* disable_nvram_write */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
enable_nvram_access(
    lm_device_t *pdev)
{
    u32_t val;

    REG_RD(pdev, nvm.nvm_access_enable, &val);

    /* Enable both bits, even on read. */
    REG_WR(
        pdev,
        nvm.nvm_access_enable,
       val | NVM_ACCESS_ENABLE_EN | NVM_ACCESS_ENABLE_WR_EN);

    return LM_STATUS_SUCCESS;
} /* enable_nvram_access */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
disable_nvram_access(
    lm_device_t *pdev)
{
    u32_t val;

    REG_RD(pdev, nvm.nvm_access_enable, &val);

    /* Disable both bits, even after read. */
    REG_WR(
        pdev,
        nvm.nvm_access_enable,
        val & ~(NVM_ACCESS_ENABLE_EN | NVM_ACCESS_ENABLE_WR_EN));

    return LM_STATUS_SUCCESS;
} /* disable_nvram_access */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
nvram_erase_page(
    lm_device_t *pdev,
    u32_t offset)
{
    lm_status_t lm_status;
    u32_t cmd_flags;
    u32_t val;
    u32_t j, cnt;

    if (pdev->hw_info.flash_spec.buffered)
    {
        /* Buffered flash, no erase needed */
        return LM_STATUS_SUCCESS;
    }

    /* Build an erase command */
    cmd_flags = NVM_COMMAND_ERASE | NVM_COMMAND_WR | NVM_COMMAND_DOIT;

    /* Need to clear DONE bit separately. */
    REG_WR(pdev, nvm.nvm_command, NVM_COMMAND_DONE);

    /* Address of the NVRAM to read from. */
    REG_WR(pdev, nvm.nvm_addr, offset & NVM_ADDR_NVM_ADDR_VALUE);

    /* Issue an erase command. */
    REG_WR(pdev, nvm.nvm_command, cmd_flags);

    /* Adjust timeout for emulation/FPGA */
    cnt = NVRAM_TIMEOUT_COUNT;
    if (CHIP_REV(pdev) == CHIP_REV_FPGA) cnt *= 10;
    else if (CHIP_REV(pdev) == CHIP_REV_IKOS) cnt *= 100;

    /* Wait for completion. */
    lm_status = LM_STATUS_BUSY;
    for(j = 0; j < cnt; j++)
    {
        mm_wait(pdev, 5);

        REG_RD(pdev, nvm.nvm_command, &val);
        if(val & NVM_COMMAND_DONE)
        {
            lm_status = LM_STATUS_SUCCESS;
            break;
        }
    }

    return lm_status;

} /* nvram_erase_page */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
nvram_read_dword(
    lm_device_t *pdev,
    u32_t offset,
    u32_t *ret_val,
    u32_t nvram_flags)
{
    lm_status_t lm_status;
    u32_t cmd_flags;
    u32_t val;
    u32_t j, cnt;

    /* Build the command word. */
    cmd_flags = NVM_COMMAND_DOIT;
    if(nvram_flags & NVRAM_FLAG_SET_FIRST_CMD_BIT)
    {
        cmd_flags |= NVM_COMMAND_FIRST;
    }

    if(nvram_flags & NVRAM_FLAG_SET_LAST_CMD_BIT)
    {
        cmd_flags |= NVM_COMMAND_LAST;
    }

    if ((CHIP_NUM(pdev) == CHIP_NUM_5706) || (CHIP_NUM(pdev) == CHIP_NUM_5708))
    {
        /* Calculate an offset of a buffered flash. */
        if(nvram_flags & NVRAM_FLAG_BUFFERED_FLASH)
        {
            offset = ((offset / pdev->hw_info.flash_spec.page_size) <<
                       pdev->hw_info.flash_spec.shift_bits) +
                     (offset % pdev->hw_info.flash_spec.page_size);
        }

        /* Need to clear DONE bit separately. */
        REG_WR(pdev, nvm.nvm_command, NVM_COMMAND_DONE);
    }

    /* Address of the NVRAM to read from. */
    if (cmd_flags & NVM_COMMAND_FIRST) {
        REG_WR(pdev, nvm.nvm_addr, offset & NVM_ADDR_NVM_ADDR_VALUE);
    }

    /* Issue a read command. */
    REG_WR(pdev, nvm.nvm_command, cmd_flags);

    /* Adjust timeout for emulation/FPGA */
    cnt = NVRAM_TIMEOUT_COUNT;
    if (CHIP_REV(pdev) == CHIP_REV_FPGA) cnt *= 10;
    else if (CHIP_REV(pdev) == CHIP_REV_IKOS) cnt *= 100;

    /* Wait for completion. */
    lm_status = LM_STATUS_BUSY;
    for(j = 0; j < cnt; j++)
    {
        mm_wait(pdev, 5);

        REG_RD(pdev, nvm.nvm_command, &val);
        if(val & NVM_COMMAND_DONE)
        {
            REG_RD(pdev, nvm.nvm_read, &val);

            /* Change to little endian. */
            #if defined(LITTLE_ENDIAN)
            val = ((val & 0xff) << 24) | ((val & 0xff00) << 8) |
                ((val & 0xff0000) >> 8) | ((val >> 24) & 0xff);
            #endif

            *ret_val = val;

            lm_status = LM_STATUS_SUCCESS;

            break;
        }
    }

    return lm_status;
} /* nvram_read_dword */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
nvram_write_dword(
    lm_device_t *pdev,
    u32_t offset,
    u32_t val,
    u32_t nvram_flags)
{
    lm_status_t lm_status;
    u32_t cmd_flags;
    u32_t j, cnt;

    /* Build the command word. */
    cmd_flags = NVM_COMMAND_DOIT | NVM_COMMAND_WR;
    if(nvram_flags & NVRAM_FLAG_SET_FIRST_CMD_BIT)
    {
        cmd_flags |= NVM_COMMAND_FIRST;
    }

    if(nvram_flags & NVRAM_FLAG_SET_LAST_CMD_BIT)
    {
        cmd_flags |= NVM_COMMAND_LAST;
    }
    if ((CHIP_NUM(pdev) == CHIP_NUM_5706) || (CHIP_NUM(pdev) == CHIP_NUM_5708))
    {
        /* Calculate an offset of a buffered flash. */
        if(nvram_flags & NVRAM_FLAG_BUFFERED_FLASH)
        {
            offset = ((offset / pdev->hw_info.flash_spec.page_size) <<
                      pdev->hw_info.flash_spec.shift_bits) +
                     (offset % pdev->hw_info.flash_spec.page_size);
        }

        /* Need to clear DONE bit separately. */
        REG_WR(pdev, nvm.nvm_command, NVM_COMMAND_DONE);
    }

    /* Change to little endian. */
    #if defined(LITTLE_ENDIAN)
    val = ((val & 0xff) << 24) | ((val & 0xff00) << 8) |
        ((val & 0xff0000) >> 8) | ((val >> 24) & 0xff);
    #endif

    /* Write the data. */
    REG_WR(pdev, nvm.nvm_write, val);

    /* Address of the NVRAM to write to. */
    if (cmd_flags & NVM_COMMAND_FIRST) {
        REG_WR(pdev, nvm.nvm_addr, offset & NVM_ADDR_NVM_ADDR_VALUE);
    }

    /* Issue the write command. */
    REG_WR(pdev, nvm.nvm_command, cmd_flags);

    /* Adjust timeout for emulation/FPGA */
    cnt = NVRAM_TIMEOUT_COUNT;
    if (CHIP_REV(pdev) == CHIP_REV_FPGA) cnt *= 10;
    else if (CHIP_REV(pdev) == CHIP_REV_IKOS) cnt *= 100;

    /* Wait for completion. */
    lm_status = LM_STATUS_BUSY;
    for(j = 0; j < cnt; j++)
    {
        mm_wait(pdev, 5);

        REG_RD(pdev, nvm.nvm_command, &val);
        if(val & NVM_COMMAND_DONE)
        {
            lm_status = LM_STATUS_SUCCESS;
            break;
        }
    }

    return lm_status;
} /* nvram_write_dword */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC u32_t
find_atmel_size(
    lm_device_t *pdev)
{
    u32_t orig, val, done=0, size=BUFFERED_FLASH_TOTAL_SIZE;

    if (CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        REG_RD(pdev, nvm.nvm_cfg4, &val);
        val &= 0x07;
        return (1 << val) ;
    }

    /* It is assumed that the flash is enabled and locked for exclusive access */
    REG_RD(pdev, nvm.nvm_cfg3, &orig);
    REG_WR(pdev, nvm.nvm_cfg3, 0x57848353);
    REG_WR(pdev, nvm.nvm_read, 0);
    REG_WR(pdev, nvm.nvm_command, NVM_COMMAND_DONE);
    REG_WR(pdev, nvm.nvm_command, NVM_COMMAND_DOIT |
                                  NVM_COMMAND_FIRST |
                                  NVM_COMMAND_LAST);
    while (!done)
    {
        REG_RD(pdev, nvm.nvm_command, &val);
        if (val & NVM_COMMAND_DONE)
        {
            done = 1;
        }
    }
    REG_RD(pdev, nvm.nvm_read, &val);
    REG_WR(pdev, nvm.nvm_cfg3, orig);
    val &= 0x3c;
    switch (val)
    {
        case 0x24:
            size *= 8;
            break;
        case 0x1c:
            size *= 4;
            break;
        case 0x14:
            size *= 2;
            break;
        case 0x0c:
            size *= 1;
            break;
        default:
            size *= 0;
            break;
    }
    return size;
}


/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC u32_t
find_stm_size(
    lm_device_t *pdev)
{
    u32_t idx, val, result, bit;

    if (CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        REG_RD(pdev, nvm.nvm_cfg4, &val);
        val &= 0x07;
        return (1 << val) ;
    }

    /* It is assumed that the flash is enabled and locked for exclusive access */
    /* Set CS, SO, SCLK as output, SI as input */
    REG_WR(pdev, nvm.nvm_addr, NVM_ADDR_NVM_ADDR_VALUE_EECLK_TE |
                               NVM_ADDR_NVM_ADDR_VALUE_EEDATA_TE |
                               NVM_ADDR_NVM_ADDR_VALUE_SI_TE
                               );
    /* Set initial data CS=1, SO=0, SCLK=0, SI=n/a */
    REG_WR(pdev, nvm.nvm_write, NVM_WRITE_NVM_WRITE_VALUE_EECLK_TE |
                                NVM_WRITE_NVM_WRITE_VALUE_EEDATA_TE |
                                NVM_WRITE_NVM_WRITE_VALUE_CS_B_TE
                                );
    /* Enable bit-bang mode */
    REG_RD(pdev, nvm.nvm_cfg1, &val);
    REG_WR(pdev, nvm.nvm_cfg1, val | NVM_CFG1_BITBANG_MODE);
    mm_wait(pdev, 1);

    /* Bit-bang the command */

    val = 0xf9;

    REG_WR(pdev, nvm.nvm_write, 0);
    mm_wait(pdev, 1);
    for (idx=0; idx < 8; idx++)
    {
        bit = ((val >> idx) & 0x1) << 4;
        REG_WR(pdev, nvm.nvm_write, bit);
        mm_wait(pdev, 1);
        REG_WR(pdev, nvm.nvm_write, NVM_WRITE_NVM_WRITE_VALUE_SCLK_TE | bit);
        mm_wait(pdev, 1);
    }
    REG_WR(pdev, nvm.nvm_write, 0);
    mm_wait(pdev, 1);

    /* Bit-bang to read ID, 1st byte: manuf ID;
     * 2nd byte: memory type; 3rd byte: memory capacity */
    result = 0;
    for (idx = 0; idx < 24; idx++)
    {
        REG_RD(pdev, nvm.nvm_read, &val);
        bit = (val & NVM_WRITE_NVM_WRITE_VALUE_SI_TE) >> 5;
        result = (result << 1) | bit;

        REG_WR(pdev, nvm.nvm_write, NVM_WRITE_NVM_WRITE_VALUE_SCLK_TE);
        mm_wait(pdev, 1);
        REG_WR(pdev, nvm.nvm_write, 0);
        mm_wait(pdev, 1);
    }
    REG_WR(pdev, nvm.nvm_write, NVM_WRITE_NVM_WRITE_VALUE_CS_B_TE);
    mm_wait(pdev, 1);

    val = ST_MICRO_FLASH_1MBIT;
    switch (result)
    {
        case 0x00204014:
            val *= 8;
            break;
        case 0x00204013:
            val *= 4;
            break;
        case 0x00204012:
            val *= 2;
            break;
        case 0x00204011:
            val *= 1;
            break;
        default:
            val *= 0;
            break;
    }

    /* Get out of bit-bang mode */
    REG_RD(pdev, nvm.nvm_cfg1, &idx);
    REG_WR(pdev, nvm.nvm_cfg1, idx & ~NVM_CFG1_BITBANG_MODE);
    mm_wait(pdev, 1);

    return val;
}


/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC u32_t
find_nvram_size(
    lm_device_t *pdev,
    u32_t table_idx)
{
    lm_status_t lm_status;
    u32_t size, val;

    if (CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        REG_RD(pdev, nvm.nvm_cfg4, &val);
        val &= 0x07;
        return ((1 << val) * 1024 * 1024 / 8);
    }

    /* Request access to the flash interface. */
    lm_status = acquire_nvram_lock(pdev);
    if(lm_status != LM_STATUS_SUCCESS) return 0;

    /* Enable access to flash interface */
    lm_status = enable_nvram_access(pdev);
    if(lm_status != LM_STATUS_SUCCESS) return 0;

    switch (table_idx)
    {
        case 11:
        case 14:
        case 15:
            /* ATMEL */
            size = find_atmel_size(pdev);
            break;
        case 5:
        case 6:
            size = find_stm_size(pdev);
            break;
        case 2:
        case 3:
        case 7:
            /* This one is static */
            size = cfg_table[table_idx].total_size;
            break;
        default:
            size = 0;
            break;
    }
    /* Disable access to flash interface */
    (void) disable_nvram_access(pdev);
    release_nvram_lock(pdev);
    return size;
}


/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_nvram_init(
    lm_device_t *pdev,
    u8_t reset_flash_block)
{
    u32_t idx, val;
    lm_status_t lm_status;

    DbgMessage(pdev, INFORM, "### lm_nvram_init\n");

    if (CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        REG_RD(pdev, nvm.nvm_cfg4, &val);

        pdev->hw_info.flash_spec.buffered   = 0;
        pdev->hw_info.flash_spec.shift_bits = 0;
        pdev->hw_info.flash_spec.page_size  = SAIFUN_FLASH_PAGE_SIZE;
        pdev->hw_info.flash_spec.addr_mask  = 0;
        pdev->hw_info.flash_spec.total_size = (1 << (val & 0x07)) * 1024 * 1024 / 8;
        return;
    }

    idx = lm_nvram_query(pdev, reset_flash_block, FALSE);

    if (idx == (u32_t)-1)
    {
        /* Not necessarily an error, it could mean that the flash block has
         * been reconfigured.
         */
        return;
    }

    DbgMessage(pdev, INFORM, cfg_table[idx].name);
    DbgMessage(pdev, INFORM, " reconfiguring.\n");

    /* Request access to the flash interface. */
    lm_status = acquire_nvram_lock(pdev);
    if(lm_status != LM_STATUS_SUCCESS) return;

    /* Enable access to flash interface */
    lm_status = enable_nvram_access(pdev);
    if(lm_status != LM_STATUS_SUCCESS) return;

    /* Reconfigure the flash interface */
    /*     Program the SPI and SEE clocks faster if FPGA or IKOS */
    val = cfg_table[idx].config1;

    if(CHIP_REV(pdev) == CHIP_REV_FPGA)
    {
        val &= ~(NVM_CFG1_SPI_CLK_DIV | NVM_CFG1_SEE_CLK_DIV);
        val |= (0x0<<7) | (0x6<<11);
    }
    else if(CHIP_REV(pdev) == CHIP_REV_IKOS)
    {
        val &= ~(NVM_CFG1_SPI_CLK_DIV | NVM_CFG1_SEE_CLK_DIV);
        val |= (0x0<<7) | (0x0<<11);
    }
    else
    {
          /* No change, leave it */
    }

    REG_WR(pdev, nvm.nvm_cfg1, val);
    REG_WR(pdev, nvm.nvm_cfg2, cfg_table[idx].config2);
    REG_WR(pdev, nvm.nvm_cfg3, cfg_table[idx].config3);
    REG_WR(pdev, nvm.nvm_write1, cfg_table[idx].write1);

    /* Disable access to flash interface */
    (void) disable_nvram_access(pdev);
    release_nvram_lock(pdev);

} /* lm_nvram_init */


/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
u32_t
lm_nvram_query(
    lm_device_t *pdev,
    u8_t reset_flash_block,
    u8_t no_hw_mod)
{
    u32_t val;
    u32_t j;
    u32_t cnt, idx, ret_val = (u32_t)-1;
    u8_t reconfigured = FALSE;
    u32_t entry_count, mask;


    DbgMessage(pdev, INFORM, "### lm_nvram_query\n");

    if (CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        REG_RD(pdev, nvm.nvm_cfg4, &val);

        pdev->hw_info.flash_spec.buffered   = 0;
        pdev->hw_info.flash_spec.shift_bits = 0;
        pdev->hw_info.flash_spec.page_size  = SAIFUN_FLASH_PAGE_SIZE;
        pdev->hw_info.flash_spec.addr_mask  = 0;
        pdev->hw_info.flash_spec.total_size = (1 << (val & 0x07)) * 1024 * 1024 / 8;
        return (u32_t)-1;
    }

    /* Adjust timeout for emulation/FPGA */
    cnt = NVRAM_TIMEOUT_COUNT;
    if(CHIP_REV(pdev) == CHIP_REV_FPGA) cnt *= 10;
    else if(CHIP_REV(pdev) == CHIP_REV_IKOS) cnt *= 100;

    /* Reset the NVRAM interface block. */
    if(reset_flash_block)
    {
        val = 0;

        /* Get access to write flash block register */
        (void) enable_nvram_access(pdev);

        REG_WR(pdev, nvm.nvm_command, NVM_COMMAND_RST);
        for(j = 0; j < cnt; j++)
        {
            mm_wait(pdev, 5);

            REG_RD(pdev, nvm.nvm_command, &val);
            if(!(val & NVM_COMMAND_RST))
            {
                break;
            }
        }

        DbgBreakIf(val & NVM_COMMAND_RST);
    }

    /* Determine the selected interface. */
    REG_RD(pdev, nvm.nvm_cfg1, &val);

    entry_count = sizeof(cfg_table)/sizeof(new_nvm_cfg_t);

    if (val & (1<<30))
    {
        /* Flash interface has been reconfigured */
        mask = FLASH_BACKUP_STRAP_MASK;
        for (idx=0; idx<entry_count; idx++)
        {
            if ((val & mask) == (cfg_table[idx].strapping & mask))
            {
                DbgMessage(pdev, INFORM, "Reconfigured ");
                DbgMessage(pdev, INFORM, cfg_table[idx].name);
                DbgMessage(pdev, INFORM, " detected.\n");

                reconfigured = TRUE;
                ret_val = idx;
                break;
            }
        }
    }
    else
    {
        /* Not yet been reconfigured */

        /* A new bit to indicate where to look for strapping (backup vs. original) */
        mask = (val & (1<<23)) ? FLASH_BACKUP_STRAP_MASK : FLASH_STRAP_MASK;

        for (idx=0; idx<entry_count; idx++)
        {

            if ((val & mask) == (cfg_table[idx].strapping & mask))
            {
                DbgMessage(pdev, INFORM, cfg_table[idx].name);
                DbgMessage(pdev, INFORM, " detected.\n");

                ret_val = idx;
                break;
            }
        }
    } /* if (val & (1<<30)) */

    /* Check for exceptions: entries that are supported by TetonII B0,
     * but not earlier chips
     */
    if ((ret_val == 5) && (CHIP_ID(pdev) < CHIP_ID_5708_B0))
    {
        pdev->hw_info.flash_spec.total_size = 0;

        DbgBreakMsg("Unsupported type.\n");
    }
    else if (ret_val != (u32_t)-1)
    {
        /* Track what's been configured */
        pdev->hw_info.flash_spec.buffered   = cfg_table[ret_val].buffered;
        pdev->hw_info.flash_spec.shift_bits = cfg_table[ret_val].shift_bits;
        pdev->hw_info.flash_spec.page_size  = cfg_table[ret_val].page_size;
        pdev->hw_info.flash_spec.addr_mask  = cfg_table[ret_val].addr_mask;
        /* Determine the size before reconfiguring, dynamically */
        if (no_hw_mod)
        {
            pdev->hw_info.flash_spec.total_size = cfg_table[ret_val].total_size;
        }
        else
        {
            pdev->hw_info.flash_spec.total_size = find_nvram_size(pdev, idx);
        }
    }
    else
    {
        pdev->hw_info.flash_spec.total_size = 0;

        DbgBreakMsg("Unknown flash/EEPROM type.\n");
    }

    return (reconfigured) ? (u32_t)-1 : ret_val;

} /* lm_nvram_query */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_nvram_read(
    lm_device_t *pdev,
    u32_t offset,
    u32_t *ret_buf,
    u32_t buf_size)
{
    lm_status_t lm_status;
    u32_t cmd_flags;

    DbgMessage(pdev, VERBOSE, "### lm_nvram_read\n");

    if((buf_size & 0x03) || (offset & 0x03))
    {
        DbgBreakMsg("Invalid paramter.\n");

        return LM_STATUS_FAILURE;
    }
    if(offset + buf_size > pdev->hw_info.flash_spec.total_size)
    {
        DbgBreakMsg("Invalid paramter.\n");

        return LM_STATUS_FAILURE;
    }

    if (pdev->hw_info.flash_spec.buffered)
    {
        cmd_flags = NVRAM_FLAG_BUFFERED_FLASH;
    }
    else
    {
        cmd_flags = NVRAM_FLAG_NONE;
    }

    /* Request access to the flash interface. */
    lm_status = acquire_nvram_lock(pdev);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    /* Enable access to flash interface */
    lm_status = enable_nvram_access(pdev);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    if(buf_size <= sizeof(u32_t))
    {
        /* Address of the NVRAM to read from. */
        cmd_flags |= NVRAM_FLAG_SET_FIRST_CMD_BIT |
            NVRAM_FLAG_SET_LAST_CMD_BIT;
        lm_status = nvram_read_dword(pdev, offset, ret_buf, cmd_flags);
    }
    else
    {
        /* Read the first word. */
        cmd_flags |= NVRAM_FLAG_SET_FIRST_CMD_BIT;
        lm_status = nvram_read_dword(pdev, offset, ret_buf, cmd_flags);
        cmd_flags &= ~NVRAM_FLAG_SET_FIRST_CMD_BIT;
        if(lm_status == LM_STATUS_SUCCESS)
        {
            /* Advance to the next dword. */
            offset += sizeof(u32_t);
            ret_buf++;
            buf_size -= sizeof(u32_t);

            while(buf_size > sizeof(u32_t) && lm_status == LM_STATUS_SUCCESS)
            {
                lm_status = nvram_read_dword(pdev, offset, ret_buf, cmd_flags);

                /* Advance to the next dword. */
                offset += sizeof(u32_t);
                ret_buf++;
                buf_size -= sizeof(u32_t);
            }

            if(lm_status == LM_STATUS_SUCCESS)
            {
                cmd_flags |= NVRAM_FLAG_SET_LAST_CMD_BIT;
                lm_status = nvram_read_dword(pdev, offset, ret_buf, cmd_flags);
            }
        }
    }

    /* Disable access to flash interface */
    (void) disable_nvram_access(pdev);

    release_nvram_lock(pdev);

    return lm_status;
} /* lm_nvram_read */

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_nvram_write(
    lm_device_t *pdev,
    u32_t offset,
    u32_t *data_buf,
    u32_t buf_size)
{
    lm_status_t lm_status;
    u32_t cmd_flags;
    u32_t written_so_far, page_start, page_end, data_start, data_end;
    u32_t idx, *ptr32, addr, base_flags;
    static u32_t flash_buffer[66];

    DbgMessage(pdev, VERBOSE, "### lm_nvram_write\n");

    if(offset & 0x03)
    {
        DbgBreakMsg("Invalid paramter.\n");

        return LM_STATUS_FAILURE;
    }

    if(offset + buf_size > pdev->hw_info.flash_spec.total_size)
    {
        DbgBreakMsg("Invalid paramter.\n");
        return LM_STATUS_FAILURE;
    }

    lm_status = LM_STATUS_SUCCESS;

    written_so_far = 0;
    ptr32 = data_buf;

    if ((CHIP_NUM(pdev) == CHIP_NUM_5706) || (CHIP_NUM(pdev) == CHIP_NUM_5708))
    {
        base_flags = (pdev->hw_info.flash_spec.buffered) ?
                     NVRAM_FLAG_BUFFERED_FLASH : NVRAM_FLAG_NONE;
        while (written_so_far < buf_size)
        {
            /* Find the page_start addr */
            page_start = offset + written_so_far;
            page_start -= (page_start % pdev->hw_info.flash_spec.page_size);
            /* Find the page_end addr */
            page_end = page_start + pdev->hw_info.flash_spec.page_size;
            /* Find the data_start addr */
            data_start = (written_so_far==0) ?  offset : page_start;
            /* Find the data_end addr */
            data_end = (page_end > offset + buf_size) ?
                       (offset+buf_size) : page_end;

            /* Request access to the flash interface. */
            lm_status = acquire_nvram_lock(pdev);
            if(lm_status != LM_STATUS_SUCCESS) return lm_status;

            /* Enable access to flash interface */
            lm_status = enable_nvram_access(pdev);
            if(lm_status != LM_STATUS_SUCCESS) return lm_status;

            if (pdev->hw_info.flash_spec.buffered == 0)
            {
                /* Read the whole page into the buffer (non-buffer flash only) */
                for (idx=0; idx<pdev->hw_info.flash_spec.page_size; idx+=4)
                {
                    cmd_flags = base_flags;
                    if (idx==0)
                    {
                        cmd_flags |= NVRAM_FLAG_SET_FIRST_CMD_BIT;
                    }
                    if (idx==pdev->hw_info.flash_spec.page_size-4)
                    {
                        cmd_flags |= NVRAM_FLAG_SET_LAST_CMD_BIT;
                    }
                    lm_status |= nvram_read_dword(pdev, page_start+idx,
                                                  &flash_buffer[idx/4],
                                                  cmd_flags);
                }
                if(lm_status != LM_STATUS_SUCCESS) return lm_status;
            }

            /* Enable writes to flash interface (unlock write-protect) */
            lm_status = enable_nvram_write(pdev);
            if(lm_status != LM_STATUS_SUCCESS) return lm_status;

            /* Erase the page */
            lm_status = nvram_erase_page(pdev, page_start);
            if(lm_status != LM_STATUS_SUCCESS) return lm_status;

            /* Re-enable the write again for the actual write */
            lm_status = enable_nvram_write(pdev);
            if(lm_status != LM_STATUS_SUCCESS) return lm_status;

            /* Loop to write back the buffer data from page_start to data_start */
            cmd_flags = NVRAM_FLAG_SET_FIRST_CMD_BIT | base_flags;
            idx = 0;
            for (addr=page_start; addr<data_start; addr+=4, idx++)
            {
                if (pdev->hw_info.flash_spec.buffered == 0)
                {
                    /* Write back only for non-buffered flash */
                    (void) nvram_write_dword(pdev, addr, flash_buffer[idx], cmd_flags);
                    cmd_flags = base_flags;
                }
            }

            /* Loop to write the new data from data_start to data_end */
            for (addr=data_start; addr<data_end; addr+=4, idx++)
            {
                if ((addr==page_end-4) ||
                    ((pdev->hw_info.flash_spec.buffered) && (addr>=data_end-4)))
                {
                    /* End of a page (page_end==data_end)
                     * OR end of new data (in buffered flash case) */
                    cmd_flags |= NVRAM_FLAG_SET_LAST_CMD_BIT;
                }
                (void) nvram_write_dword(pdev, addr, *ptr32, cmd_flags);
                cmd_flags = base_flags;
                ptr32++;
            }

            /* Loop to write back the buffer data from data_end to page_end */
            for (addr=data_end; addr<page_end; addr+=4, idx++)
            {
                if (pdev->hw_info.flash_spec.buffered == 0)
                {
                    /* Write back only for non-buffered flash */
                    if (addr == page_end-4)
                    {
                        cmd_flags = NVRAM_FLAG_SET_LAST_CMD_BIT | base_flags;
                    }
                    (void) nvram_write_dword(pdev, addr, flash_buffer[idx], cmd_flags);
                    cmd_flags = base_flags;
                }
            }

            /* Disable writes to flash interface (lock write-protect) */
            (void) disable_nvram_write(pdev);

            /* Disable access to flash interface */
            (void) disable_nvram_access(pdev);
            release_nvram_lock(pdev);

            /* Increment written_so_far */
            written_so_far += data_end - data_start;
        } // while
    }
    else if (CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        /* Request access to the flash interface. */
        lm_status = acquire_nvram_lock(pdev);
        if(lm_status != LM_STATUS_SUCCESS) return lm_status;

        /* Enable access to flash interface */
        lm_status = enable_nvram_access(pdev);
        if(lm_status != LM_STATUS_SUCCESS) return lm_status;

        cmd_flags = NVRAM_FLAG_SET_FIRST_CMD_BIT;
        addr = offset;
        while (written_so_far < buf_size)
        {
            if (written_so_far == (buf_size - 4))
                cmd_flags |= NVRAM_FLAG_SET_LAST_CMD_BIT;
            else if (((addr & 0xff) + 4) == 256)
                cmd_flags |= NVRAM_FLAG_SET_LAST_CMD_BIT;
            if ((addr & 0xff) == 0)
                cmd_flags |= NVRAM_FLAG_SET_FIRST_CMD_BIT;
            (void) nvram_write_dword(pdev, addr, *ptr32, cmd_flags);
            ptr32++;
            addr += 4;
            written_so_far += 4;
            cmd_flags = 0;
        }
        /* Disable access to flash interface */
        (void) disable_nvram_access(pdev);
        release_nvram_lock(pdev);
    }

    return lm_status;

} /* lm_nvram_write */
