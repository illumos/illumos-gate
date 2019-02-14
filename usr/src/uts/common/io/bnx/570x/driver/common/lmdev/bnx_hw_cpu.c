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
#include "rxpfw.h"
#include "txpfw.h"
#include "tpatfw.h"
#include "comfw.h"
#include "cpfw.h"
#include "rv2p_p1.h"
#include "rv2p_p2.h"
#include "xi_rv2p_p1.h"
#include "xi_rv2p_p2.h"
#include "xi90_rv2p_p1.h"
#include "xi90_rv2p_p2.h"
#include "xinanfw.h"



/*******************************************************************************
 * CPU register info.
 ******************************************************************************/

typedef struct _cpu_reg_t
{
    u32_t mode;
    u32_t mode_value_halt;
    u32_t mode_value_sstep;

    u32_t state;
    u32_t state_value_clear;

    u32_t gpr0;
    u32_t evmask;
    u32_t pc;
    u32_t inst;
    u32_t bp;

    u32_t spad_base;

    u32_t mips_view_base;
} cpu_reg_t;



/*******************************************************************************
 * Firmware info. 
 ******************************************************************************/

typedef struct _fw_info_t
{
    u32_t ver_major;
    u32_t ver_minor;
    u32_t ver_fix;

    u32_t start_addr;

    /* Text section. */
    u32_t text_addr;
    u32_t text_len;
    u32_t text_index;
    u32_t *text;

    /* Data section. */
    u32_t data_addr;
    u32_t data_len;
    u32_t data_index;
    u32_t *data;

    /* SBSS section. */
    u32_t sbss_addr;
    u32_t sbss_len;
    u32_t sbss_index;
    u32_t *sbss;

    /* BSS section. */
    u32_t bss_addr;
    u32_t bss_len;
    u32_t bss_index;
    u32_t *bss;

    /* Read-only section. */
    u32_t rodata_addr;
    u32_t rodata_len;
    u32_t rodata_index;
    u32_t *rodata;
} fw_info_t;



#define RV2P_PROC1                              0
#define RV2P_PROC2                              1
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
load_rv2p_fw(
    lm_device_t *pdev,
    u32_t *rv2p_code,
    u32_t rv2p_code_len,
    u32_t rv2p_proc)
{
    u32_t idx;
    u32_t val;

    DbgBreakIf(rv2p_proc != RV2P_PROC1 && rv2p_proc != RV2P_PROC2);

    for(idx = 0; idx < rv2p_code_len; idx += 8)
    {
        REG_WR(pdev, rv2p.rv2p_instr_high, *rv2p_code);
        rv2p_code++;
        REG_WR(pdev, rv2p.rv2p_instr_low, *rv2p_code);
        rv2p_code++;

        if(rv2p_proc == RV2P_PROC1)
        {
            val = (idx/8) | RV2P_PROC1_ADDR_CMD_RDWR;
            REG_WR(pdev, rv2p.rv2p_proc1_addr_cmd, val);
        }
        else
        {
            val = (idx/8) | RV2P_PROC2_ADDR_CMD_RDWR;
            REG_WR(pdev, rv2p.rv2p_proc2_addr_cmd, val);
        }
    }

    /* Reset the processor, un-stall is done later. */
    if(rv2p_proc == RV2P_PROC1)
    {
        REG_WR(pdev, rv2p.rv2p_command, RV2P_COMMAND_PROC1_RESET);
    }
    else
    {
        REG_WR(pdev, rv2p.rv2p_command, RV2P_COMMAND_PROC2_RESET);
    }
} /* load_rv2p_fw */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
load_cpu_fw(
    lm_device_t *pdev,
    cpu_reg_t *cpu_reg,
    fw_info_t *fw)
{
    u32_t val;

    /* Halt the CPU. */
    REG_RD_IND(pdev, cpu_reg->mode, &val);
    val |= cpu_reg->mode_value_halt;
    REG_WR_IND(pdev, cpu_reg->mode, val);
    REG_WR_IND(pdev, cpu_reg->state, cpu_reg->state_value_clear);

    /* Load the Text area. */
    if(fw->text)
    {
        lm_reg_wr_blk(
            pdev,
            cpu_reg->spad_base + (fw->text_addr - cpu_reg->mips_view_base),
            fw->text,
            fw->text_len/4);
    }

    /* Load the Data area. */
    if(fw->data)
    {
        lm_reg_wr_blk(
            pdev,
            cpu_reg->spad_base + (fw->data_addr - cpu_reg->mips_view_base),
            fw->data,
            fw->data_len/4);
    }

    /* Load the SBSS area. */
    if(fw->sbss)
    {
        lm_reg_wr_blk(
            pdev,
            cpu_reg->spad_base + (fw->sbss_addr - cpu_reg->mips_view_base),
            fw->sbss,
            fw->sbss_len/4);
    }

    /* Load the BSS area. */
    if(fw->bss)
    {
        lm_reg_wr_blk(
            pdev,
            cpu_reg->spad_base + (fw->bss_addr - cpu_reg->mips_view_base),
            fw->bss,
            fw->bss_len/4);
    }

    /* Load the Read-Only area. */
    if(fw->rodata)
    {
        lm_reg_wr_blk(
            pdev,
            cpu_reg->spad_base + (fw->rodata_addr - cpu_reg->mips_view_base),
            fw->rodata,
            fw->rodata_len/4);
    }

    /* Clear the pre-fetch instruction. */
    REG_WR_IND(pdev, cpu_reg->inst, 0);
    REG_WR_IND(pdev, cpu_reg->pc, fw->start_addr);

    /* Start the CPU. */
    REG_RD_IND(pdev, cpu_reg->mode, &val);
    val &= ~cpu_reg->mode_value_halt;
    REG_WR_IND(pdev, cpu_reg->state, cpu_reg->state_value_clear);
    REG_WR_IND(pdev, cpu_reg->mode, val);
} /* load_cpu_fw */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
init_5706_cpus(
    lm_device_t *pdev,
    u32_t cpu_mask)
{
    cpu_reg_t cpu_reg;
    fw_info_t fw;

    DbgBreakIf(
        CHIP_NUM(pdev) != CHIP_NUM_5706 &&
        CHIP_NUM(pdev) != CHIP_NUM_5708);

    if(cpu_mask & CPU_RXP)
    {
        cpu_reg.mode = OFFSETOF(reg_space_t, rxp.rxp_cpu_mode);
        cpu_reg.mode_value_halt = RXP_CPU_MODE_SOFT_HALT;
        cpu_reg.mode_value_sstep = RXP_CPU_MODE_STEP_ENA;
        cpu_reg.state = OFFSETOF(reg_space_t, rxp.rxp_cpu_state);
        cpu_reg.state_value_clear = 0xffffff;
        cpu_reg.gpr0 = OFFSETOF(reg_space_t, rxp.rxp_cpu_reg_file[0]);
        cpu_reg.evmask = OFFSETOF(reg_space_t, rxp.rxp_cpu_event_mask);
        cpu_reg.pc = OFFSETOF(reg_space_t, rxp.rxp_cpu_program_counter);
        cpu_reg.inst = OFFSETOF(reg_space_t, rxp.rxp_cpu_instruction);
        cpu_reg.bp = OFFSETOF(reg_space_t, rxp.rxp_cpu_hw_breakpoint);
        cpu_reg.spad_base = OFFSETOF(reg_space_t, rxp.rxp_scratch[0]);
        cpu_reg.mips_view_base = 0x8000000;
        
        fw.ver_major = RXP_b06FwReleaseMajor;
        fw.ver_minor = RXP_b06FwReleaseMinor;
        fw.ver_fix = RXP_b06FwReleaseFix;
        fw.start_addr = RXP_b06FwStartAddr;

        fw.text_addr = RXP_b06FwTextAddr;
        fw.text_len = RXP_b06FwTextLen;
        fw.text_index = 0;
        fw.text = RXP_b06FwText;

        fw.data_addr = RXP_b06FwDataAddr;
        fw.data_len = RXP_b06FwDataLen;
        fw.data_index = 0;
        fw.data = RXP_b06FwData;

        fw.sbss_addr = RXP_b06FwSbssAddr;
        fw.sbss_len = RXP_b06FwSbssLen;
        fw.sbss_index = 0;
        fw.sbss = RXP_b06FwSbss;

        fw.bss_addr = RXP_b06FwBssAddr;
        fw.bss_len = RXP_b06FwBssLen;
        fw.bss_index = 0;
        fw.bss = RXP_b06FwBss;

        fw.rodata_addr = RXP_b06FwRodataAddr;
        fw.rodata_len = RXP_b06FwRodataLen;
        fw.rodata_index = 0;
        fw.rodata = RXP_b06FwRodata;

        load_cpu_fw(pdev, &cpu_reg, &fw);
    }

    if(cpu_mask & CPU_TXP)
    {
        cpu_reg.mode = OFFSETOF(reg_space_t, txp.txp_cpu_mode);
        cpu_reg.mode_value_halt = TXP_CPU_MODE_SOFT_HALT;
        cpu_reg.mode_value_sstep = TXP_CPU_MODE_STEP_ENA;
        cpu_reg.state = OFFSETOF(reg_space_t, txp.txp_cpu_state);
        cpu_reg.state_value_clear = 0xffffff;
        cpu_reg.gpr0 = OFFSETOF(reg_space_t, txp.txp_cpu_reg_file[0]);
        cpu_reg.evmask = OFFSETOF(reg_space_t, txp.txp_cpu_event_mask);
        cpu_reg.pc = OFFSETOF(reg_space_t, txp.txp_cpu_program_counter);
        cpu_reg.inst = OFFSETOF(reg_space_t, txp.txp_cpu_instruction);
        cpu_reg.bp = OFFSETOF(reg_space_t, txp.txp_cpu_hw_breakpoint);
        cpu_reg.spad_base = OFFSETOF(reg_space_t, txp.txp_scratch[0]);
        cpu_reg.mips_view_base = 0x8000000;
        
        fw.ver_major = TXP_b06FwReleaseMajor;
        fw.ver_minor = TXP_b06FwReleaseMinor;
        fw.ver_fix = TXP_b06FwReleaseFix;
        fw.start_addr = TXP_b06FwStartAddr;

        fw.text_addr = TXP_b06FwTextAddr;
        fw.text_len = TXP_b06FwTextLen;
        fw.text_index = 0;
        fw.text = TXP_b06FwText;

        fw.data_addr = TXP_b06FwDataAddr;
        fw.data_len = TXP_b06FwDataLen;
        fw.data_index = 0;
        fw.data = TXP_b06FwData;

        fw.sbss_addr = TXP_b06FwSbssAddr;
        fw.sbss_len = TXP_b06FwSbssLen;
        fw.sbss_index = 0;
        fw.sbss = TXP_b06FwSbss;

        fw.bss_addr = TXP_b06FwBssAddr;
        fw.bss_len = TXP_b06FwBssLen;
        fw.bss_index = 0;
        fw.bss = TXP_b06FwBss;

        fw.rodata_addr = TXP_b06FwRodataAddr;
        fw.rodata_len = TXP_b06FwRodataLen;
        fw.rodata_index = 0;
        fw.rodata = TXP_b06FwRodata;

        load_cpu_fw(pdev, &cpu_reg, &fw);
    }

    if(cpu_mask & CPU_TPAT)
    {
        cpu_reg.mode = OFFSETOF(reg_space_t, tpat.tpat_cpu_mode);
        cpu_reg.mode_value_halt = TPAT_CPU_MODE_SOFT_HALT;
        cpu_reg.mode_value_sstep = TPAT_CPU_MODE_STEP_ENA;
        cpu_reg.state = OFFSETOF(reg_space_t, tpat.tpat_cpu_state);
        cpu_reg.state_value_clear = 0xffffff;
        cpu_reg.gpr0 = OFFSETOF(reg_space_t, tpat.tpat_cpu_reg_file[0]);
        cpu_reg.evmask = OFFSETOF(reg_space_t, tpat.tpat_cpu_event_mask);
        cpu_reg.pc = OFFSETOF(reg_space_t, tpat.tpat_cpu_program_counter);
        cpu_reg.inst = OFFSETOF(reg_space_t, tpat.tpat_cpu_instruction);
        cpu_reg.bp = OFFSETOF(reg_space_t, tpat.tpat_cpu_hw_breakpoint);
        cpu_reg.spad_base = OFFSETOF(reg_space_t, tpat.tpat_scratch[0]);
        cpu_reg.mips_view_base = 0x8000000;
        
        fw.ver_major = TPAT_b06FwReleaseMajor;
        fw.ver_minor = TPAT_b06FwReleaseMinor;
        fw.ver_fix = TPAT_b06FwReleaseFix;
        fw.start_addr = TPAT_b06FwStartAddr;

        fw.text_addr = TPAT_b06FwTextAddr;
        fw.text_len = TPAT_b06FwTextLen;
        fw.text_index = 0;
        fw.text = TPAT_b06FwText;

        fw.data_addr = TPAT_b06FwDataAddr;
        fw.data_len = TPAT_b06FwDataLen;
        fw.data_index = 0;
        fw.data = TPAT_b06FwData;

        fw.sbss_addr = TPAT_b06FwSbssAddr;
        fw.sbss_len = TPAT_b06FwSbssLen;
        fw.sbss_index = 0;
        fw.sbss = TPAT_b06FwSbss;

        fw.bss_addr = TPAT_b06FwBssAddr;
        fw.bss_len = TPAT_b06FwBssLen;
        fw.bss_index = 0;
        fw.bss = TPAT_b06FwBss;

        fw.rodata_addr = TPAT_b06FwRodataAddr;
        fw.rodata_len = TPAT_b06FwRodataLen;
        fw.rodata_index = 0;
        fw.rodata = TPAT_b06FwRodata;

        load_cpu_fw(pdev, &cpu_reg, &fw);
    }

    if(cpu_mask & CPU_COM)
    {
        cpu_reg.mode = OFFSETOF(reg_space_t, com.com_cpu_mode);
        cpu_reg.mode_value_halt = COM_CPU_MODE_SOFT_HALT;
        cpu_reg.mode_value_sstep = COM_CPU_MODE_STEP_ENA;
        cpu_reg.state = OFFSETOF(reg_space_t, com.com_cpu_state);
        cpu_reg.state_value_clear = 0xffffff;
        cpu_reg.gpr0 = OFFSETOF(reg_space_t, com.com_cpu_reg_file[0]);
        cpu_reg.evmask = OFFSETOF(reg_space_t, com.com_cpu_event_mask);
        cpu_reg.pc = OFFSETOF(reg_space_t, com.com_cpu_program_counter);
        cpu_reg.inst = OFFSETOF(reg_space_t, com.com_cpu_instruction);
        cpu_reg.bp = OFFSETOF(reg_space_t, com.com_cpu_hw_breakpoint);
        cpu_reg.spad_base = OFFSETOF(reg_space_t, com.com_scratch[0]);
        cpu_reg.mips_view_base = 0x8000000;
        
        fw.ver_major = COM_b06FwReleaseMajor;
        fw.ver_minor = COM_b06FwReleaseMinor;
        fw.ver_fix = COM_b06FwReleaseFix;
        fw.start_addr = COM_b06FwStartAddr;

        fw.text_addr = COM_b06FwTextAddr;
        fw.text_len = COM_b06FwTextLen;
        fw.text_index = 0;
        fw.text = COM_b06FwText;

        fw.data_addr = COM_b06FwDataAddr;
        fw.data_len = COM_b06FwDataLen;
        fw.data_index = 0;
        fw.data = COM_b06FwData;

        fw.sbss_addr = COM_b06FwSbssAddr;
        fw.sbss_len = COM_b06FwSbssLen;
        fw.sbss_index = 0;
        fw.sbss = COM_b06FwSbss;

        fw.bss_addr = COM_b06FwBssAddr;
        fw.bss_len = COM_b06FwBssLen;
        fw.bss_index = 0;
        fw.bss = COM_b06FwBss;

        fw.rodata_addr = COM_b06FwRodataAddr;
        fw.rodata_len = COM_b06FwRodataLen;
        fw.rodata_index = 0;
        fw.rodata = COM_b06FwRodata;

        load_cpu_fw(pdev, &cpu_reg, &fw);
    }

    if(cpu_mask & CPU_CP)
    {
        cpu_reg.mode = OFFSETOF(reg_space_t, cp.cp_cpu_mode);
        cpu_reg.mode_value_halt = CP_CPU_MODE_SOFT_HALT;
        cpu_reg.mode_value_sstep = CP_CPU_MODE_STEP_ENA;
        cpu_reg.state = OFFSETOF(reg_space_t, cp.cp_cpu_state);
        cpu_reg.state_value_clear = 0xffffff;
        cpu_reg.gpr0 = OFFSETOF(reg_space_t, cp.cp_cpu_reg_file[0]);
        cpu_reg.evmask = OFFSETOF(reg_space_t, cp.cp_cpu_event_mask);
        cpu_reg.pc = OFFSETOF(reg_space_t, cp.cp_cpu_program_counter);
        cpu_reg.inst = OFFSETOF(reg_space_t, cp.cp_cpu_instruction);
        cpu_reg.bp = OFFSETOF(reg_space_t, cp.cp_cpu_hw_breakpoint);
        cpu_reg.spad_base = OFFSETOF(reg_space_t, cp.cp_scratch[0]);
        cpu_reg.mips_view_base = 0x8000000;
        
        fw.ver_major = CP_b06FwReleaseMajor;
        fw.ver_minor = CP_b06FwReleaseMinor;
        fw.ver_fix = CP_b06FwReleaseFix;
        fw.start_addr = CP_b06FwStartAddr;

        fw.text_addr = CP_b06FwTextAddr;
        fw.text_len = CP_b06FwTextLen;
        fw.text_index = 0;
        fw.text = CP_b06FwText;

        fw.data_addr = CP_b06FwDataAddr;
        fw.data_len = CP_b06FwDataLen;
        fw.data_index = 0;
        fw.data = CP_b06FwData;

        fw.sbss_addr = CP_b06FwSbssAddr;
        fw.sbss_len = CP_b06FwSbssLen;
        fw.sbss_index = 0;
        fw.sbss = CP_b06FwSbss;

        fw.bss_addr = CP_b06FwBssAddr;
        fw.bss_len = CP_b06FwBssLen;
        fw.bss_index = 0;
        fw.bss = CP_b06FwBss;

        fw.rodata_addr = CP_b06FwRodataAddr;
        fw.rodata_len = CP_b06FwRodataLen;
        fw.rodata_index = 0;
        fw.rodata = CP_b06FwRodata;

        load_cpu_fw(pdev, &cpu_reg, &fw);
    }
} /* init_5706_cpus */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
init_5709_cpus(
    lm_device_t *pdev,
    u32_t cpu_mask)
{
    cpu_reg_t cpu_reg;
    fw_info_t fw;

    DbgBreakIf(CHIP_NUM(pdev) != CHIP_NUM_5709);

    if(cpu_mask & CPU_RXP)
    {
        cpu_reg.mode = OFFSETOF(reg_space_t, rxp.rxp_cpu_mode);
        cpu_reg.mode_value_halt = RXP_CPU_MODE_SOFT_HALT;
        cpu_reg.mode_value_sstep = RXP_CPU_MODE_STEP_ENA;
        cpu_reg.state = OFFSETOF(reg_space_t, rxp.rxp_cpu_state);
        cpu_reg.state_value_clear = 0xffffff;
        cpu_reg.gpr0 = OFFSETOF(reg_space_t, rxp.rxp_cpu_reg_file[0]);
        cpu_reg.evmask = OFFSETOF(reg_space_t, rxp.rxp_cpu_event_mask);
        cpu_reg.pc = OFFSETOF(reg_space_t, rxp.rxp_cpu_program_counter);
        cpu_reg.inst = OFFSETOF(reg_space_t, rxp.rxp_cpu_instruction);
        cpu_reg.bp = OFFSETOF(reg_space_t, rxp.rxp_cpu_hw_breakpoint);
        cpu_reg.spad_base = OFFSETOF(reg_space_t, rxp.rxp_scratch[0]);
        cpu_reg.mips_view_base = 0x8000000;
        
        fw.ver_major = RXP_b09FwReleaseMajor;
        fw.ver_minor = RXP_b09FwReleaseMinor;
        fw.ver_fix = RXP_b09FwReleaseFix;
        fw.start_addr = RXP_b09FwStartAddr;

        fw.text_addr = RXP_b09FwTextAddr;
        fw.text_len = RXP_b09FwTextLen;
        fw.text_index = 0;
        fw.text = RXP_b09FwText;

        fw.data_addr = RXP_b09FwDataAddr;
        fw.data_len = RXP_b09FwDataLen;
        fw.data_index = 0;
        fw.data = RXP_b09FwData;

        fw.sbss_addr = RXP_b09FwSbssAddr;
        fw.sbss_len = RXP_b09FwSbssLen;
        fw.sbss_index = 0;
        fw.sbss = RXP_b09FwSbss;

        fw.bss_addr = RXP_b09FwBssAddr;
        fw.bss_len = RXP_b09FwBssLen;
        fw.bss_index = 0;
        fw.bss = RXP_b09FwBss;

        fw.rodata_addr = RXP_b09FwRodataAddr;
        fw.rodata_len = RXP_b09FwRodataLen;
        fw.rodata_index = 0;
        fw.rodata = RXP_b09FwRodata;

        load_cpu_fw(pdev, &cpu_reg, &fw);
    }

    if(cpu_mask & CPU_TXP)
    {
        cpu_reg.mode = OFFSETOF(reg_space_t, txp.txp_cpu_mode);
        cpu_reg.mode_value_halt = TXP_CPU_MODE_SOFT_HALT;
        cpu_reg.mode_value_sstep = TXP_CPU_MODE_STEP_ENA;
        cpu_reg.state = OFFSETOF(reg_space_t, txp.txp_cpu_state);
        cpu_reg.state_value_clear = 0xffffff;
        cpu_reg.gpr0 = OFFSETOF(reg_space_t, txp.txp_cpu_reg_file[0]);
        cpu_reg.evmask = OFFSETOF(reg_space_t, txp.txp_cpu_event_mask);
        cpu_reg.pc = OFFSETOF(reg_space_t, txp.txp_cpu_program_counter);
        cpu_reg.inst = OFFSETOF(reg_space_t, txp.txp_cpu_instruction);
        cpu_reg.bp = OFFSETOF(reg_space_t, txp.txp_cpu_hw_breakpoint);
        cpu_reg.spad_base = OFFSETOF(reg_space_t, txp.txp_scratch[0]);
        cpu_reg.mips_view_base = 0x8000000;
        
        fw.ver_major = TXP_b09FwReleaseMajor;
        fw.ver_minor = TXP_b09FwReleaseMinor;
        fw.ver_fix = TXP_b09FwReleaseFix;
        fw.start_addr = TXP_b09FwStartAddr;

        fw.text_addr = TXP_b09FwTextAddr;
        fw.text_len = TXP_b09FwTextLen;
        fw.text_index = 0;
        fw.text = TXP_b09FwText;

        fw.data_addr = TXP_b09FwDataAddr;
        fw.data_len = TXP_b09FwDataLen;
        fw.data_index = 0;
        fw.data = TXP_b09FwData;

        fw.sbss_addr = TXP_b09FwSbssAddr;
        fw.sbss_len = TXP_b09FwSbssLen;
        fw.sbss_index = 0;
        fw.sbss = TXP_b09FwSbss;

        fw.bss_addr = TXP_b09FwBssAddr;
        fw.bss_len = TXP_b09FwBssLen;
        fw.bss_index = 0;
        fw.bss = TXP_b09FwBss;

        fw.rodata_addr = TXP_b09FwRodataAddr;
        fw.rodata_len = TXP_b09FwRodataLen;
        fw.rodata_index = 0;
        fw.rodata = TXP_b09FwRodata;

        load_cpu_fw(pdev, &cpu_reg, &fw);
    }

    if(cpu_mask & CPU_TPAT)
    {
        cpu_reg.mode = OFFSETOF(reg_space_t, tpat.tpat_cpu_mode);
        cpu_reg.mode_value_halt = TPAT_CPU_MODE_SOFT_HALT;
        cpu_reg.mode_value_sstep = TPAT_CPU_MODE_STEP_ENA;
        cpu_reg.state = OFFSETOF(reg_space_t, tpat.tpat_cpu_state);
        cpu_reg.state_value_clear = 0xffffff;
        cpu_reg.gpr0 = OFFSETOF(reg_space_t, tpat.tpat_cpu_reg_file[0]);
        cpu_reg.evmask = OFFSETOF(reg_space_t, tpat.tpat_cpu_event_mask);
        cpu_reg.pc = OFFSETOF(reg_space_t, tpat.tpat_cpu_program_counter);
        cpu_reg.inst = OFFSETOF(reg_space_t, tpat.tpat_cpu_instruction);
        cpu_reg.bp = OFFSETOF(reg_space_t, tpat.tpat_cpu_hw_breakpoint);
        cpu_reg.spad_base = OFFSETOF(reg_space_t, tpat.tpat_scratch[0]);
        cpu_reg.mips_view_base = 0x8000000;
        
        fw.ver_major = TPAT_b09FwReleaseMajor;
        fw.ver_minor = TPAT_b09FwReleaseMinor;
        fw.ver_fix = TPAT_b09FwReleaseFix;
        fw.start_addr = TPAT_b09FwStartAddr;

        fw.text_addr = TPAT_b09FwTextAddr;
        fw.text_len = TPAT_b09FwTextLen;
        fw.text_index = 0;
        fw.text = TPAT_b09FwText;

        fw.data_addr = TPAT_b09FwDataAddr;
        fw.data_len = TPAT_b09FwDataLen;
        fw.data_index = 0;
        fw.data = TPAT_b09FwData;

        fw.sbss_addr = TPAT_b09FwSbssAddr;
        fw.sbss_len = TPAT_b09FwSbssLen;
        fw.sbss_index = 0;
        fw.sbss = TPAT_b09FwSbss;

        fw.bss_addr = TPAT_b09FwBssAddr;
        fw.bss_len = TPAT_b09FwBssLen;
        fw.bss_index = 0;
        fw.bss = TPAT_b09FwBss;

        fw.rodata_addr = TPAT_b09FwRodataAddr;
        fw.rodata_len = TPAT_b09FwRodataLen;
        fw.rodata_index = 0;
        fw.rodata = TPAT_b09FwRodata;

        load_cpu_fw(pdev, &cpu_reg, &fw);
    }

    if(cpu_mask & CPU_COM)
    {
        cpu_reg.mode = OFFSETOF(reg_space_t, com.com_cpu_mode);
        cpu_reg.mode_value_halt = COM_CPU_MODE_SOFT_HALT;
        cpu_reg.mode_value_sstep = COM_CPU_MODE_STEP_ENA;
        cpu_reg.state = OFFSETOF(reg_space_t, com.com_cpu_state);
        cpu_reg.state_value_clear = 0xffffff;
        cpu_reg.gpr0 = OFFSETOF(reg_space_t, com.com_cpu_reg_file[0]);
        cpu_reg.evmask = OFFSETOF(reg_space_t, com.com_cpu_event_mask);
        cpu_reg.pc = OFFSETOF(reg_space_t, com.com_cpu_program_counter);
        cpu_reg.inst = OFFSETOF(reg_space_t, com.com_cpu_instruction);
        cpu_reg.bp = OFFSETOF(reg_space_t, com.com_cpu_hw_breakpoint);
        cpu_reg.spad_base = OFFSETOF(reg_space_t, com.com_scratch[0]);
        cpu_reg.mips_view_base = 0x8000000;
        
        fw.ver_major = COM_b09FwReleaseMajor;
        fw.ver_minor = COM_b09FwReleaseMinor;
        fw.ver_fix = COM_b09FwReleaseFix;
        fw.start_addr = COM_b09FwStartAddr;

        fw.text_addr = COM_b09FwTextAddr;
        fw.text_len = COM_b09FwTextLen;
        fw.text_index = 0;
        fw.text = COM_b09FwText;

        fw.data_addr = COM_b09FwDataAddr;
        fw.data_len = COM_b09FwDataLen;
        fw.data_index = 0;
        fw.data = COM_b09FwData;

        fw.sbss_addr = COM_b09FwSbssAddr;
        fw.sbss_len = COM_b09FwSbssLen;
        fw.sbss_index = 0;
        fw.sbss = COM_b09FwSbss;

        fw.bss_addr = COM_b09FwBssAddr;
        fw.bss_len = COM_b09FwBssLen;
        fw.bss_index = 0;
        fw.bss = COM_b09FwBss;

        fw.rodata_addr = COM_b09FwRodataAddr;
        fw.rodata_len = COM_b09FwRodataLen;
        fw.rodata_index = 0;
        fw.rodata = COM_b09FwRodata;

        load_cpu_fw(pdev, &cpu_reg, &fw);
    }

    if(cpu_mask & CPU_CP)
    {
        cpu_reg.mode = OFFSETOF(reg_space_t, cp.cp_cpu_mode);
        cpu_reg.mode_value_halt = CP_CPU_MODE_SOFT_HALT;
        cpu_reg.mode_value_sstep = CP_CPU_MODE_STEP_ENA;
        cpu_reg.state = OFFSETOF(reg_space_t, cp.cp_cpu_state);
        cpu_reg.state_value_clear = 0xffffff;
        cpu_reg.gpr0 = OFFSETOF(reg_space_t, cp.cp_cpu_reg_file[0]);
        cpu_reg.evmask = OFFSETOF(reg_space_t, cp.cp_cpu_event_mask);
        cpu_reg.pc = OFFSETOF(reg_space_t, cp.cp_cpu_program_counter);
        cpu_reg.inst = OFFSETOF(reg_space_t, cp.cp_cpu_instruction);
        cpu_reg.bp = OFFSETOF(reg_space_t, cp.cp_cpu_hw_breakpoint);
        cpu_reg.spad_base = OFFSETOF(reg_space_t, cp.cp_scratch[0]);
        cpu_reg.mips_view_base = 0x8000000;
        
        fw.ver_major = CP_b09FwReleaseMajor;
        fw.ver_minor = CP_b09FwReleaseMinor;
        fw.ver_fix = CP_b09FwReleaseFix;
        fw.start_addr = CP_b09FwStartAddr;

        fw.text_addr = CP_b09FwTextAddr;
        fw.text_len = CP_b09FwTextLen;
        fw.text_index = 0;
        fw.text = CP_b09FwText;

        fw.data_addr = CP_b09FwDataAddr;
        fw.data_len = CP_b09FwDataLen;
        fw.data_index = 0;
        fw.data = CP_b09FwData;

        fw.sbss_addr = CP_b09FwSbssAddr;
        fw.sbss_len = CP_b09FwSbssLen;
        fw.sbss_index = 0;
        fw.sbss = CP_b09FwSbss;

        fw.bss_addr = CP_b09FwBssAddr;
        fw.bss_len = CP_b09FwBssLen;
        fw.bss_index = 0;
        fw.bss = CP_b09FwBss;

        fw.rodata_addr = CP_b09FwRodataAddr;
        fw.rodata_len = CP_b09FwRodataLen;
        fw.rodata_index = 0;
        fw.rodata = CP_b09FwRodata;

        load_cpu_fw(pdev, &cpu_reg, &fw);
    }
} /* init_5709_cpus */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_init_cpus(
    lm_device_t *pdev,
    u32_t cpu_mask)
{
    DbgBreakIf(
            CHIP_NUM(pdev) != CHIP_NUM_5706 &&
            CHIP_NUM(pdev) != CHIP_NUM_5708 &&
            CHIP_NUM(pdev) != CHIP_NUM_5709);

    if(CHIP_NUM(pdev) == CHIP_NUM_5706 || CHIP_NUM(pdev) == CHIP_NUM_5708)
    {
        if(cpu_mask & CPU_RV2P_1)
        {
            // Calling this macro prior to loading will change value of POST_WAIT_TIMEOUT 
            // This parameter dictates how long to wait before dropping L2 packet
            // due to insufficient posted buffers
            // 0 mean no waiting before dropping, 0xFFFF means maximum wait
            if (pdev->params.fw_flow_control)
            {
                RV2P_PROC1_CHG_POST_WAIT_TIMEOUT(pdev->params.fw_flow_control_wait);
            }
            else
            {   
                // No waiting if fw_flow_control is not enabled
                RV2P_PROC1_CHG_POST_WAIT_TIMEOUT(0);
            }
            load_rv2p_fw(pdev, rv2p_proc1, sizeof(rv2p_proc1), RV2P_PROC1);
        }

        if(cpu_mask & CPU_RV2P_2)
        {
            load_rv2p_fw(pdev, rv2p_proc2, sizeof(rv2p_proc2), RV2P_PROC2);
        }

        init_5706_cpus(pdev, cpu_mask);
    }
    else if(CHIP_ID(pdev) == CHIP_ID_5709_A0 || CHIP_ID(pdev) == CHIP_ID_5709_A1)
    {
        if(cpu_mask & CPU_RV2P_1)
        {
            // Calling this macro prior to loading will change value of POST_WAIT_TIMEOUT 
            // This parameter dictates how long to wait before dropping L2 packet
            // due to insufficient posted buffers
            // 0 mean no waiting before dropping, 0xFFFF means maximum wait
            if (pdev->params.fw_flow_control)
            {
                XI90_RV2P_PROC1_CHG_POST_WAIT_TIMEOUT(pdev->params.fw_flow_control_wait);
            }
            else
            {   
                // No waiting if fw_flow_control is not enabled
                XI90_RV2P_PROC1_CHG_POST_WAIT_TIMEOUT(0);
            }
            load_rv2p_fw(
                pdev,
                xi90_rv2p_proc1,
                sizeof(xi90_rv2p_proc1),
                RV2P_PROC1);
        }

        if(cpu_mask & CPU_RV2P_2)
        {
            load_rv2p_fw(
                pdev,
                xi90_rv2p_proc2,
                sizeof(xi90_rv2p_proc2),
                RV2P_PROC2);
        }

        init_5709_cpus(pdev, cpu_mask);
    }
    else
    {
        if(cpu_mask & CPU_RV2P_1)
        {
            // Calling this macro prior to loading will change value of POST_WAIT_TIMEOUT 
            // This parameter dictates how long to wait before dropping L2 packet
            // due to insufficient posted buffers
            // 0 mean no waiting before dropping, 0xFFFF means maximum wait
            if (pdev->params.fw_flow_control)
            {
                XI_RV2P_PROC1_CHG_POST_WAIT_TIMEOUT(pdev->params.fw_flow_control_wait);
            }
            else
            {
                // No waiting if fw_flow_control is not enabled
                XI_RV2P_PROC1_CHG_POST_WAIT_TIMEOUT(0);
            }
            load_rv2p_fw(pdev,xi_rv2p_proc1,sizeof(xi_rv2p_proc1),RV2P_PROC1);
        }

        if(cpu_mask & CPU_RV2P_2)
        {
            load_rv2p_fw(pdev,xi_rv2p_proc2,sizeof(xi_rv2p_proc2),RV2P_PROC2);
        }

        init_5709_cpus(pdev, cpu_mask);
    }
} /* lm_init_cpus */

