 /******************************************************************************
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
 *    03/21/03 Hav Khauv        Inception.
 ******************************************************************************/

#include "lm5710.h"

#define NVRAM_TIMEOUT_COUNT                     100000


/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
static lm_status_t
acquire_nvram_lock(
    lm_device_t *pdev)
{
    lm_status_t lm_status;
    u32_t j, cnt;
    u32_t val;
    u8_t port_num = PORT_ID(pdev); /* TBD - E1H: nvram lock – DOES NOT scale to 8 functions! (only 4 clients)
                                    * 1. Can we assume no concurrent access by control applications?
                                    * 2. If not, the MISC lock is our backup */

    DbgMessage(pdev, VERBOSEnv, "### acquire_nvram_lock\n");
    /* Adjust timeout for emulation/FPGA */
    cnt = NVRAM_TIMEOUT_COUNT;
    if (CHIP_REV_IS_EMUL(pdev)) cnt *= 100;

    val = 0;

    /* Request access to the flash interface. */
    REG_WR(pdev, MCP_REG_MCPR_NVM_SW_ARB, (MCPR_NVM_SW_ARB_ARB_REQ_SET1 << port_num ));
    for(j = 0; j < cnt*10; j++)
    {
        val=REG_RD(pdev, MCP_REG_MCPR_NVM_SW_ARB);
        if(val & (MCPR_NVM_SW_ARB_ARB_ARB1 << port_num))
        {
            break;
        }

        mm_wait(pdev, 5);
    }

    if(val & (MCPR_NVM_SW_ARB_ARB_ARB1 << port_num))
    {
        lm_status = LM_STATUS_SUCCESS;
    }
    else
    {
        DbgMessage(NULL, FATAL, "Value of MCP_REG_MCPR_NVM_SW_ARB is 0x%x\n", val);
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
static void
release_nvram_lock(
    lm_device_t *pdev)
{
    u32_t j, cnt;
    u32_t val;
    u8_t port_num = PORT_ID(pdev);

    DbgMessage(pdev, VERBOSEnv, "### release_nvram_lock\n");
    /* Adjust timeout for emulation/FPGA */
    cnt = NVRAM_TIMEOUT_COUNT;
    if (CHIP_REV_IS_EMUL(pdev)) cnt *= 100;

    /* Relinquish nvram interface. */
    REG_WR(pdev,  MCP_REG_MCPR_NVM_SW_ARB, (MCPR_NVM_SW_ARB_ARB_REQ_CLR1 << port_num));

    val = 0;

    for(j = 0; j < cnt; j++)
    {
        val=REG_RD(pdev, MCP_REG_MCPR_NVM_SW_ARB);
        if(!(val & (MCPR_NVM_SW_ARB_ARB_ARB1 << port_num)))
        {
            break;
        }

        mm_wait(pdev, 5);
    }

    DbgBreakIf(val & (MCPR_NVM_SW_ARB_ARB_ARB1 << port_num));
} /* release_nvram_lock */


#if 0
/*******************************************************************************
* Description:
*
* Return:
*
******************************************************************************/
static lm_status_t
enable_nvram_write(
   lm_device_t *pdev)
{
    u32_t val, j, cnt;
    lm_status_t lm_status;

    lm_status = LM_STATUS_SUCCESS;

    DbgMessage(pdev, INFORMnv, "### enable_nvram_write\n");

    /* Need to clear DONE bit separately. */
    REG_WR(pdev, MCP_REG_MCPR_NVM_COMMAND, MCPR_NVM_COMMAND_DONE);

    /* Issue a write enable command. */
    REG_WR(pdev, MCP_REG_MCPR_NVM_COMMAND, MCPR_NVM_COMMAND_DOIT | MCPR_NVM_COMMAND_WREN);

    /* Adjust timeout for emulation/FPGA */
    cnt = NVRAM_TIMEOUT_COUNT;
    if (CHIP_REV(pdev) == CHIP_REV_EMUL) cnt *= 100;

    lm_status = LM_STATUS_BUSY;

    for(j = 0; j < cnt; j++)
    {
        mm_wait(pdev, 5);

        val=REG_RD(pdev,  MCP_REG_MCPR_NVM_COMMAND);
        if(val & MCPR_NVM_COMMAND_DONE)
        {
            lm_status = LM_STATUS_SUCCESS;
            break;
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
static lm_status_t
disable_nvram_write(
                    lm_device_t *pdev)
{
    lm_status_t lm_status;
    u32_t cnt,j,val;

    DbgMessage(pdev, INFORMnv, "### disable_nvram_write\n");
    /* Need to clear DONE bit separately. */
    REG_WR(pdev, MCP_REG_MCPR_NVM_COMMAND, MCPR_NVM_COMMAND_DONE);

        /* Issue a write disable command. */
    REG_WR(pdev, MCP_REG_MCPR_NVM_COMMAND, MCPR_NVM_COMMAND_DOIT | MCPR_NVM_COMMAND_WRDI);

    /* Adjust timeout for emulation/FPGA */
    cnt = NVRAM_TIMEOUT_COUNT;
    if (CHIP_REV(pdev) == CHIP_REV_EMUL) cnt *= 100;

    lm_status = LM_STATUS_BUSY;
    for(j = 0; j < cnt; j++)
    {
        mm_wait(pdev, 5);

        val=REG_RD(pdev,  MCP_REG_MCPR_NVM_COMMAND);
        if(val & MCPR_NVM_COMMAND_DONE)
        {
            lm_status = LM_STATUS_SUCCESS;
            break;
        }
    }

    return lm_status;
} /* disable_nvram_write */

#endif /* 0 */

/*******************************************************************************
* Description:
*
* Return:
******************************************************************************/
static lm_status_t
enable_nvram_access(
    lm_device_t *pdev)
{
    u32_t val;

    DbgMessage(pdev, VERBOSEnv, "### enable_nvram_access\n");
    val=REG_RD(pdev,  MCP_REG_MCPR_NVM_ACCESS_ENABLE);

    /* Enable both bits, even on read. */
    REG_WR(pdev,  MCP_REG_MCPR_NVM_ACCESS_ENABLE, val | MCPR_NVM_ACCESS_ENABLE_EN | MCPR_NVM_ACCESS_ENABLE_WR_EN);

    return LM_STATUS_SUCCESS;
} /* enable_nvram_access */



/*******************************************************************************
* Description:
*
* Return:
******************************************************************************/
static lm_status_t
disable_nvram_access(
    lm_device_t *pdev)
{
    u32_t val;

    DbgMessage(pdev, VERBOSEnv, "### disable_nvram_access\n");
    val=REG_RD(pdev,  MCP_REG_MCPR_NVM_ACCESS_ENABLE);

    /* Disable both bits, even after read. */
    REG_WR(pdev,  MCP_REG_MCPR_NVM_ACCESS_ENABLE, val & ~(MCPR_NVM_ACCESS_ENABLE_EN | MCPR_NVM_ACCESS_ENABLE_WR_EN));

    return LM_STATUS_SUCCESS;
} /* disable_nvram_access */




/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
static lm_status_t
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

    DbgMessage(pdev, VERBOSEnv, "### nvram_read_dword\n");
    DbgMessage(pdev, VERBOSEnv, "offset %d flags %d\n",offset,nvram_flags);

    /* Build the command word. */
    cmd_flags = nvram_flags | MCPR_NVM_COMMAND_DOIT;

    /* Need to clear DONE bit separately. */
    REG_WR(pdev,  MCP_REG_MCPR_NVM_COMMAND, MCPR_NVM_COMMAND_DONE);

    /* Address of the NVRAM to read from. */
    REG_WR(pdev,  MCP_REG_MCPR_NVM_ADDR, offset & MCPR_NVM_ADDR_NVM_ADDR_VALUE);

    /* Issue a read command. */
    REG_WR(pdev,  MCP_REG_MCPR_NVM_COMMAND, cmd_flags);

    /* Adjust timeout for emulation/FPGA */
    cnt = NVRAM_TIMEOUT_COUNT;
    if (CHIP_REV_IS_EMUL(pdev)) cnt *= 100;

    /* Wait for completion. */
    lm_status = LM_STATUS_BUSY;
    for(j = 0; j < cnt; j++)
    {
        mm_wait(pdev, 5);
        val=REG_RD(pdev,  MCP_REG_MCPR_NVM_COMMAND);
        if(val & MCPR_NVM_COMMAND_DONE)
        {
            val=REG_RD(pdev,  MCP_REG_MCPR_NVM_READ);

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
static lm_status_t
nvram_write_dword(
    lm_device_t *pdev,
    u32_t offset,
    u32_t val,
    u32_t nvram_flags)
{
    lm_status_t lm_status;
    u32_t cmd_flags;
    u32_t j, cnt;

    DbgMessage(pdev, VERBOSEnv, "### nvram_write_dword\n");
    /* Build the command word. */
    cmd_flags = nvram_flags | MCPR_NVM_COMMAND_DOIT | MCPR_NVM_COMMAND_WR;

    /* Change to little endian. */
    #if defined(LITTLE_ENDIAN)
    val = ((val & 0xff) << 24) | ((val & 0xff00) << 8) |
        ((val & 0xff0000) >> 8) | ((val >> 24) & 0xff);
    #endif

    /* Need to clear DONE bit separately. */
    REG_WR(pdev,  MCP_REG_MCPR_NVM_COMMAND, MCPR_NVM_COMMAND_DONE);

    /* Write the data. */
    REG_WR(pdev,  MCP_REG_MCPR_NVM_WRITE, val);

    /* Address of the NVRAM to write to. */
    REG_WR(pdev,  MCP_REG_MCPR_NVM_ADDR, offset & MCPR_NVM_ADDR_NVM_ADDR_VALUE);

    /* Issue the write command. */
    REG_WR(pdev,  MCP_REG_MCPR_NVM_COMMAND, cmd_flags);

    /* Adjust timeout for emulation/FPGA */

    cnt = NVRAM_TIMEOUT_COUNT;
    if (CHIP_REV_IS_EMUL(pdev)) cnt *= 100;

    /* Wait for completion. */
    lm_status = LM_STATUS_BUSY;
    for(j = 0; j < cnt; j++)
    {
        mm_wait(pdev, 5);

        val=REG_RD(pdev,  MCP_REG_MCPR_NVM_COMMAND);
        if(val & MCPR_NVM_COMMAND_DONE)
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
lm_status_t
lm_nvram_read(
    lm_device_t *pdev,
    u32_t offset,
    u32_t *ret_buf,
    u32_t buf_size)
{
    lm_status_t lm_status;
    u32_t cmd_flags;


    DbgMessage(pdev, VERBOSEnv, "### lm_nvram_read\n");
    DbgMessage(pdev, VERBOSEnv, "offset %d size %d\n",offset,buf_size);

    if((buf_size & 0x03) || (offset & 0x03))
    {
        DbgBreakMsg("Invalid paramter.\n");

        return LM_STATUS_FAILURE;
    }

    // TODO what is the nvram total size
    if(offset + buf_size > pdev->hw_info.flash_spec.total_size)
    {
        DbgBreakMsg("Invalid paramter.\n");

        return LM_STATUS_FAILURE;
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
        release_nvram_lock(pdev);
        return lm_status;
    }

    /* Read the first word. */
    cmd_flags = MCPR_NVM_COMMAND_FIRST;
    while(buf_size > sizeof(u32_t) && lm_status == LM_STATUS_SUCCESS)
    {
        lm_status = nvram_read_dword(pdev, offset, ret_buf, cmd_flags);

        /* Advance to the next dword. */
        offset += sizeof(u32_t);
        ret_buf++;
        buf_size -= sizeof(u32_t);
        cmd_flags = 0;
    }

    if(lm_status == LM_STATUS_SUCCESS)
    {
        cmd_flags |= MCPR_NVM_COMMAND_LAST;
        lm_status = nvram_read_dword(pdev, offset, ret_buf, cmd_flags);
    }

    /* Disable access to flash interface */
    disable_nvram_access(pdev);

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
    u32_t written_so_far;
    u32_t cmd_flags;
    u32_t *ptr32, addr;

    DbgMessage(pdev, VERBOSEnv, "### lm_nvram_write\n");

    if(offset & 0x03)
    {
        DbgBreakMsg("Invalid paramter.\n");

        return LM_STATUS_FAILURE;
    }
    // TODO what is the nvram total size
    if(offset + buf_size > pdev->hw_info.flash_spec.total_size)
    {		
	DbgMessage(pdev, FATAL, "lm_nvram_write failed ! buf_size %d larger than NVM total_size %d\n", buf_size, pdev->hw_info.flash_spec.total_size);
        DbgBreakMsg("Failed to write to NVM! Attemp to write to offset larger than NVM total size !\n");

        return LM_STATUS_FAILURE;
    }

    lm_status = LM_STATUS_SUCCESS;

    /* Request access to the flash interface. */
    lm_status = acquire_nvram_lock(pdev);
    if(lm_status != LM_STATUS_SUCCESS)
        return lm_status;

    /* Enable access to flash interface */
    lm_status = enable_nvram_access(pdev);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        release_nvram_lock(pdev);
        return lm_status;
    }

    written_so_far = 0;
    cmd_flags = MCPR_NVM_COMMAND_FIRST;
    addr = offset;
    ptr32 = data_buf;
    while (written_so_far < buf_size)
    {
        if (written_so_far == (buf_size - 4))
            cmd_flags |= MCPR_NVM_COMMAND_LAST;
        else if (((addr & 0xff) + 4) == NVRAM_PAGE_SIZE)        // else if (((addr + 4) % NVRAM_PAGE_SIZE) == 0)
            cmd_flags |= MCPR_NVM_COMMAND_LAST;
        else if ((addr & 0xff) == 0)                            // else if ((addr % NVRAM_PAGE_SIZE) == 0)
            cmd_flags |= MCPR_NVM_COMMAND_FIRST;
        nvram_write_dword(pdev, addr, *ptr32, cmd_flags);
        ptr32++;
        addr += 4;
        written_so_far += 4;
        cmd_flags = 0;
    }
    /* Disable access to flash interface */
    disable_nvram_access(pdev);
    release_nvram_lock(pdev);


    return lm_status;

} /* lm_nvram_write */
