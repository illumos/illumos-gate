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

/*
 *  mcp_fio definition
 *  offset: 0x80000000
 */
#ifndef MCP_FIO_H
#define MCP_FIO_H

typedef struct mcp_fio
{
    u32_t mcpf_events_bits;
        #define MCPF_EVENTS_BITS_BMB_WRITE_DONE             (1L<<0)
        #define MCPF_EVENTS_BITS_BMB_READ_RDY               (1L<<1)
        #define MCPF_EVENTS_BITS_P2M_ATTN                   (1L<<2)
        #define MCPF_EVENTS_BITS_SMBUS_EVENT                (1L<<3)
        #define MCPF_EVENTS_BITS_FLASH_EVENT                (1L<<4)
        #define MCPF_EVENTS_BITS_RESERVED0                  (1L<<5)
        #define MCPF_EVENTS_BITS_MAIN_TEMPERATURE_RESET     (1L<<6)
        #define MCPF_EVENTS_BITS_MGMT_TEMPERATURE_RESET     (1L<<7)
        #define MCPF_EVENTS_BITS_EXP_ROM                    (1L<<8)
        #define MCPF_EVENTS_BITS_VPD                        (1L<<9)
        #define MCPF_EVENTS_BITS_FLASH                      (1L<<10)
        #define MCPF_EVENTS_BITS_SMB0                       (1L<<11)
        #define MCPF_EVENTS_BITS_CNIG                       (1L<<12)
        #define MCPF_EVENTS_BITS_PGLUE_MISC_MCTP_ATTN       (1L<<13)
        #define MCPF_EVENTS_BITS_RESERVED1                  (1L<<14)
        #define MCPF_EVENTS_BITS_GPIO0                      (1L<<15)
        #define MCPF_EVENTS_BITS_GPIO1                      (1L<<16)
        #define MCPF_EVENTS_BITS_GPIO2                      (1L<<17)
        #define MCPF_EVENTS_BITS_GPIO3                      (1L<<18)
        #define MCPF_EVENTS_BITS_GPIO4                      (1L<<19)
        #define MCPF_EVENTS_BITS_GPIO5                      (1L<<20)
        #define MCPF_EVENTS_BITS_GPIO6                      (1L<<21)
        #define MCPF_EVENTS_BITS_GPIO7                      (1L<<22)
        #define MCPF_EVENTS_BITS_SW_TMR_1                   (1L<<23)
        #define MCPF_EVENTS_BITS_SW_TMR_2                   (1L<<24)
        #define MCPF_EVENTS_BITS_SW_TMR_3                   (1L<<25)
        #define MCPF_EVENTS_BITS_SW_TMR_4                   (1L<<26)
        #define MCPF_EVENTS_BITS_PERST_N_ASSERT             (1L<<27)
        #define MCPF_EVENTS_BITS_PERST_N_DEASSERT           (1L<<28)
        #define MCPF_EVENTS_BITS_GP_EVENT                   (1L<<29)
        #define MCPF_EVENTS_BITS_NOT_ENABLED                (1L<<30)
        #define MCPF_EVENTS_BITS_ATTENTIONS_VALID           (1L<<31)

    u32_t mcpf_attentions_bits;
	/* Added by Yaniv on 18/5/15. Can add additional interrupts by setting AEU to MCP output 0..7.
	 * When adding new field, here, need to add also define to INUM_ATTENTION_XXX, and add new function to
	 * mcp_attention_handler array in the INUM_ATTENTION_XXX location.
	 */
	#define MCPF_ATTENTIONS_BITS_PARITY_ERROR           (1L<<0) 
        #define MCPF_ATTENTIONS_BITS_ATTN                   (0xffL<<0)

    u32_t mcpf_event_enable;
    u32_t mcpf_attention_enable;
    u32_t mcpf_fio_status;
        #define MCPF_FIO_STATUS_ENABLED                     (1L<<0)
        #define MCPF_FIO_STATUS_FORCE_ENA                   (1L<<1)

    u32_t mcpf_interrupt_status;
        #define MCPF_INTERRUPT_STATUS_EVENT0_E0             (1L<<0)
        #define MCPF_INTERRUPT_STATUS_ATTN0_E0              (1L<<1)
        #define MCPF_INTERRUPT_STATUS_EVENT1_E0             (1L<<2)
        #define MCPF_INTERRUPT_STATUS_ATTN1_E0              (1L<<3)
        #define MCPF_INTERRUPT_STATUS_EVENT0_E1             (1L<<4)
        #define MCPF_INTERRUPT_STATUS_ATTN0_E1              (1L<<5)
        #define MCPF_INTERRUPT_STATUS_EVENT1_E1             (1L<<6)
        #define MCPF_INTERRUPT_STATUS_ATTN1_E1              (1L<<7)
        #define MCPF_INTERRUPT_STATUS_EVENT2_E0             (1L<<8)
        #define MCPF_INTERRUPT_STATUS_ATTN2_E0              (1L<<9)
        #define MCPF_INTERRUPT_STATUS_EVENT3_E0             (1L<<10)
        #define MCPF_INTERRUPT_STATUS_ATTN3_E0              (1L<<11)
        #define MCPF_INTERRUPT_STATUS_SOFT_INTERRUPT        (1L<<31)

    u32_t mcpf_unused_a[2];
    u32_t mcpf_unused_b[16];
    u32_t mcpf_unused_c[4];
    u32_t mcpf_free_counter_value;
    u32_t mcpf_timesync_clock_e0_0;
    u32_t mcpf_timesync_clock_e0_1;
    u32_t mcpf_timesync_clock_e1_0;
    u32_t mcpf_timesync_clock_e1_1;
    u32_t mcpf_soft_interrupt;
        #define MCPF_SOFT_INTERRUPT_INTERRUPT               (1L<<31)

    u32_t mcpf_program_counter;
        #define MCPF_PROGRAM_COUNTER_INTERRUPT              (0xffffffffL<<0)

    u32_t mcpf_mcp_doorbell_status;
        #define MCPF_MCP_DOORBELL_STATUS_STATUS             (0xffffL<<0)

    u32_t mcpf_dbg_mux_message;
        #define MCPF_DBG_MUX_MESSAGE_DATA                   (0xffffffffL<<0)

    u32_t mcpf_unused_d[10];
    u32_t mcpf_mcp_vfid;
        #define MCPF_MCP_VFID_VFID                          (0xffL<<0)
        #define MCPF_MCP_VFID_VFID_VALID                    (1L<<16)
        #define MCPF_MCP_VFID_PATHID                        (1L<<20)
        #define MCPF_MCP_VFID_FIO_REG_EN                    (1L<<30)
        #define MCPF_MCP_VFID_PATH_FORCE                    (1L<<31)

    u32_t mcpf_unused_e[80];
    u32_t mcpf_mult_status;
        #define MCPF_MULT_STATUS_MULTIPLY_DONE              (1L<<0)

    u32_t mcpf_mult_result;
    u32_t mcpf_mult_a;
        #define MCPF_MULT_A_VALUE                           (0xffffL<<0)

    u32_t mcpf_mult_b;
        #define MCPF_MULT_B_VALUE                           (0xffffL<<0)

    u32_t mcpf_unused_f[39036];
    u32_t mcpf_nvm_command;
        #define MCPF_NVM_COMMAND_RST                        (1L<<0)
        #define MCPF_NVM_COMMAND_DONE                       (1L<<3)
        #define MCPF_NVM_COMMAND_DOIT                       (1L<<4)
        #define MCPF_NVM_COMMAND_WR                         (1L<<5)
        #define MCPF_NVM_COMMAND_ERASE                      (1L<<6)
        #define MCPF_NVM_COMMAND_FIRST                      (1L<<7)
        #define MCPF_NVM_COMMAND_LAST                       (1L<<8)
        #define MCPF_NVM_COMMAND_ADDR_INCR                  (1L<<9)
        #define MCPF_NVM_COMMAND_WREN                       (1L<<16)
        #define MCPF_NVM_COMMAND_WRDI                       (1L<<17)
        #define MCPF_NVM_COMMAND_ERASE_ALL                  (1L<<18)
        #define MCPF_NVM_COMMAND_RD_ID                      (1L<<20)
        #define MCPF_NVM_COMMAND_RD_STATUS                  (1L<<21)
        #define MCPF_NVM_COMMAND_MODE_256                   (1L<<22)

    u32_t mcpf_nvm_status;
        #define MCPF_NVM_STATUS_SPI_FSM_STATE               (0x1fL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_IDLE  (0L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_CMD0  (1L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_CMD1  (2L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_CMD_FINISH0  (3L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_CMD_FINISH1  (4L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_ADDR0  (5L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_WRITE_DATA0  (6L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_WRITE_DATA1  (7L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_WRITE_DATA2  (8L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_WRITE_DATA3  (9L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_DATA0  (10L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_DATA1  (11L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_DATA2  (12L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID0  (13L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID1  (14L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID2  (15L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID3  (16L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID4  (17L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_CHECK_BUSY  (18L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_FIRST_WR  (19L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_ERASE  (20L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_WAIT  (21L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_WAIT1  (22L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_LOAD_BUFFER  (23L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_RDATA_2_BUFFER0  (24L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_RDATA_2_BUFFER1  (25L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_RDATA_2_BUFFER2  (26L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_RDATA_2_BUFFER3  (27L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_STORE_BUFFER0  (28L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_STORE_BUFFER1  (29L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_WDATA_2_BUFFER0  (30L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_WDATA_2_BUFFER1  (31L<<0)

    u32_t mcpf_nvm_write;
        #define MCPF_NVM_WRITE_NVM_WRITE_VALUE              (0xffffffffL<<0)
            #define MCPF_NVM_WRITE_NVM_WRITE_VALUE_BIT_BANG  (0L<<0)
            #define MCPF_NVM_WRITE_NVM_WRITE_VALUE_SI       (1L<<0)
            #define MCPF_NVM_WRITE_NVM_WRITE_VALUE_SO       (2L<<0)
            #define MCPF_NVM_WRITE_NVM_WRITE_VALUE_CS_B     (4L<<0)
            #define MCPF_NVM_WRITE_NVM_WRITE_VALUE_SCLK     (8L<<0)

    u32_t mcpf_nvm_addr;
        #define MCPF_NVM_ADDR_NVM_ADDR_VALUE                (0xffffffL<<0)
            #define MCPF_NVM_ADDR_NVM_ADDR_VALUE_BIT_BANG   (0L<<0)
            #define MCPF_NVM_ADDR_NVM_ADDR_VALUE_SI         (1L<<0)
            #define MCPF_NVM_ADDR_NVM_ADDR_VALUE_SO         (2L<<0)
            #define MCPF_NVM_ADDR_NVM_ADDR_VALUE_CS_B       (4L<<0)
            #define MCPF_NVM_ADDR_NVM_ADDR_VALUE_SCLK       (8L<<0)

    u32_t mcpf_nvm_read;
        #define MCPF_NVM_READ_NVM_READ_VALUE                (0xffffffffL<<0)
            #define MCPF_NVM_READ_NVM_READ_VALUE_BIT_BANG   (0L<<0)
            #define MCPF_NVM_READ_NVM_READ_VALUE_SI         (1L<<0)
            #define MCPF_NVM_READ_NVM_READ_VALUE_SO         (2L<<0)
            #define MCPF_NVM_READ_NVM_READ_VALUE_CS_B       (4L<<0)
            #define MCPF_NVM_READ_NVM_READ_VALUE_SCLK       (8L<<0)

    u32_t mcpf_nvm_cfg1;
        #define MCPF_NVM_CFG1_FLASH_MODE                    (1L<<0)
        #define MCPF_NVM_CFG1_BUFFER_MODE                   (1L<<1)
        #define MCPF_NVM_CFG1_PASS_MODE                     (1L<<2)
        #define MCPF_NVM_CFG1_BITBANG_MODE                  (1L<<3)
        #define MCPF_NVM_CFG1_STATUS_BIT                    (0x7L<<4)
        #define MCPF_NVM_CFG1_SPI_CLK_DIV                   (0xfL<<7)
        #define MCPF_NVM_CFG1_SEE_CLK_DIV                   (0x7ffL<<11)
        #define MCPF_NVM_CFG1_STRAP_CONTROL_0               (1L<<23)
        #define MCPF_NVM_CFG1_PROTECT_MODE                  (1L<<24)
        #define MCPF_NVM_CFG1_FLASH_SIZE                    (1L<<25)
        #define MCPF_NVM_CFG1_FW_USTRAP_1                   (1L<<26)
        #define MCPF_NVM_CFG1_FW_USTRAP_0                   (1L<<27)
        #define MCPF_NVM_CFG1_FW_USTRAP_2                   (1L<<28)
        #define MCPF_NVM_CFG1_FW_USTRAP_3                   (1L<<29)
        #define MCPF_NVM_CFG1_FW_FLASH_TYPE_EN              (1L<<30)
        #define MCPF_NVM_CFG1_COMPAT_BYPASSS                (1L<<31)

    u32_t mcpf_nvm_cfg2;
        #define MCPF_NVM_CFG2_ERASE_CMD                     (0xffL<<0)
        #define MCPF_NVM_CFG2_CSB_W                         (0xffL<<8)
        #define MCPF_NVM_CFG2_STATUS_CMD                    (0xffL<<16)
        #define MCPF_NVM_CFG2_READ_ID_CMD                   (0xffL<<24)

    u32_t mcpf_nvm_cfg3;
        #define MCPF_NVM_CFG3_BUFFER_RD_CMD                 (0xffL<<0)
        #define MCPF_NVM_CFG3_WRITE_CMD                     (0xffL<<8)
        #define MCPF_NVM_CFG3_FAST_READ_CMD                 (0xffL<<16)
        #define MCPF_NVM_CFG3_READ_CMD                      (0xffL<<24)

    u32_t mcpf_nvm_sw_arb;
        #define MCPF_NVM_SW_ARB_ARB_REQ_SET0                (1L<<0)
        #define MCPF_NVM_SW_ARB_ARB_REQ_SET1                (1L<<1)
        #define MCPF_NVM_SW_ARB_ARB_REQ_SET2                (1L<<2)
        #define MCPF_NVM_SW_ARB_ARB_REQ_SET3                (1L<<3)
        #define MCPF_NVM_SW_ARB_ARB_REQ_CLR0                (1L<<4)
        #define MCPF_NVM_SW_ARB_ARB_REQ_CLR1                (1L<<5)
        #define MCPF_NVM_SW_ARB_ARB_REQ_CLR2                (1L<<6)
        #define MCPF_NVM_SW_ARB_ARB_REQ_CLR3                (1L<<7)
        #define MCPF_NVM_SW_ARB_ARB_ARB0                    (1L<<8)
        #define MCPF_NVM_SW_ARB_ARB_ARB1                    (1L<<9)
        #define MCPF_NVM_SW_ARB_ARB_ARB2                    (1L<<10)
        #define MCPF_NVM_SW_ARB_ARB_ARB3                    (1L<<11)
        #define MCPF_NVM_SW_ARB_REQ0                        (1L<<12)
        #define MCPF_NVM_SW_ARB_REQ1                        (1L<<13)
        #define MCPF_NVM_SW_ARB_REQ2                        (1L<<14)
        #define MCPF_NVM_SW_ARB_REQ3                        (1L<<15)

    u32_t mcpf_nvm_jedec_id;
        #define MCPF_NVM_JEDEC_ID_EXTENDED_DEVICE_INFO_LENGTH  (0xffL<<0)
        #define MCPF_NVM_JEDEC_ID_DEVICE_ID                 (0xffffL<<8)
        #define MCPF_NVM_JEDEC_ID_MANUFACTURE_ID            (0xffL<<24)

    u32_t mcpf_nvm_cfg5;
        #define MCPF_NVM_CFG5_WREN_CMD                      (0xffL<<0)
        #define MCPF_NVM_CFG5_WRDI_CMD                      (0xffL<<8)
        #define MCPF_NVM_CFG5_ERASE_ALL_CMD                 (0xffL<<16)
        #define MCPF_NVM_CFG5_USE_BUFFER                    (1L<<30)
        #define MCPF_NVM_CFG5_USE_LEGACY_SPI_FSM            (1L<<31)

    u32_t mcpf_nvm_cfg4;
        #define MCPF_NVM_CFG4_FLASH_SIZE                    (0x7L<<0)
            #define MCPF_NVM_CFG4_FLASH_SIZE_1MBIT          (0L<<0)
            #define MCPF_NVM_CFG4_FLASH_SIZE_2MBIT          (1L<<0)
            #define MCPF_NVM_CFG4_FLASH_SIZE_4MBIT          (2L<<0)
            #define MCPF_NVM_CFG4_FLASH_SIZE_8MBIT          (3L<<0)
            #define MCPF_NVM_CFG4_FLASH_SIZE_16MBIT         (4L<<0)
            #define MCPF_NVM_CFG4_FLASH_SIZE_32MBIT         (5L<<0)
            #define MCPF_NVM_CFG4_FLASH_SIZE_64MBIT         (6L<<0)
            #define MCPF_NVM_CFG4_FLASH_SIZE_128MBIT        (7L<<0)
        #define MCPF_NVM_CFG4_FLASH_VENDOR                  (1L<<3)
            #define MCPF_NVM_CFG4_FLASH_VENDOR_ST           (0L<<3)
            #define MCPF_NVM_CFG4_FLASH_VENDOR_ATMEL        (1L<<3)
        #define MCPF_NVM_CFG4_MODE_256_EMPTY_BIT_LOC        (0x3L<<4)
            #define MCPF_NVM_CFG4_MODE_256_EMPTY_BIT_LOC_BIT8  (0L<<4)
            #define MCPF_NVM_CFG4_MODE_256_EMPTY_BIT_LOC_BIT9  (1L<<4)
            #define MCPF_NVM_CFG4_MODE_256_EMPTY_BIT_LOC_BIT10  (2L<<4)
            #define MCPF_NVM_CFG4_MODE_256_EMPTY_BIT_LOC_BIT11  (3L<<4)
        #define MCPF_NVM_CFG4_STATUS_BIT_POLARITY           (1L<<6)
        #define MCPF_NVM_CFG4_FAST                          (1L<<7)
        #define MCPF_NVM_CFG4_SI_INPUT_RELAXED_TIMING       (1L<<8)
        #define MCPF_NVM_CFG4_PASS_MODE_RELAXED_TIMING      (1L<<9)
        #define MCPF_NVM_CFG4_SR_TURNAROUND                 (1L<<10)
        #define MCPF_NVM_CFG4_READ_DUMMY_CYCLES             (0xfL<<11)
        #define MCPF_NVM_CFG4_FAST_READ_DUMMY_CYCLES        (0xfL<<15)
        #define MCPF_NVM_CFG4_SPI_SLOW_CLK_DIV              (0xfL<<19)
        #define MCPF_NVM_CFG4_SLOW_CLK_4_BUFFER_RD          (1L<<23)
        #define MCPF_NVM_CFG4_SLOW_CLK_4_ERASE              (1L<<24)
        #define MCPF_NVM_CFG4_SLOW_CLK_4_FAST_READ          (1L<<25)
        #define MCPF_NVM_CFG4_SLOW_CLK_4_READ               (1L<<26)
        #define MCPF_NVM_CFG4_SLOW_CLK_4_READ_ID            (1L<<27)
        #define MCPF_NVM_CFG4_SLOW_CLK_4_STATUS             (1L<<28)
        #define MCPF_NVM_CFG4_SLOW_CLK_4_WRDI               (1L<<29)
        #define MCPF_NVM_CFG4_SLOW_CLK_4_WREN               (1L<<30)
        #define MCPF_NVM_CFG4_SLOW_CLK_4_WRITE              (1L<<31)

    u32_t mcpf_nvm_reconfig;
        #define MCPF_NVM_RECONFIG_ORIG_STRAP_VALUE          (0xfL<<0)
            #define MCPF_NVM_RECONFIG_ORIG_STRAP_VALUE_ST   (0L<<0)
            #define MCPF_NVM_RECONFIG_ORIG_STRAP_VALUE_ATMEL  (1L<<0)
        #define MCPF_NVM_RECONFIG_RECONFIG_STRAP_VALUE      (0xfL<<4)
        #define MCPF_NVM_RECONFIG_RESERVED                  (0x7fffffL<<8)
        #define MCPF_NVM_RECONFIG_RECONFIG_DONE             (1L<<31)

    u32_t mcpf_nvm_nvm_unused[242];
    u32_t mcpf_nvm_nvm_reg_end;
    u32_t mcpf_unused_g[1536];
    u32_t mcpf_smbus_config;
        #define MCPF_SMBUS_CONFIG_HW_ARP_ASSIGN_ADDR        (1L<<7)
        #define MCPF_SMBUS_CONFIG_ARP_EN0                   (1L<<8)
        #define MCPF_SMBUS_CONFIG_ARP_EN1                   (1L<<9)
        #define MCPF_SMBUS_CONFIG_MASTER_RTRY_CNT           (0xfL<<16)
        #define MCPF_SMBUS_CONFIG_TIMESTAMP_CNT_EN          (1L<<26)
        #define MCPF_SMBUS_CONFIG_PROMISCOUS_MODE           (1L<<27)
        #define MCPF_SMBUS_CONFIG_EN_NIC_SMB_ADDR_0         (1L<<28)
        #define MCPF_SMBUS_CONFIG_BIT_BANG_EN               (1L<<29)
        #define MCPF_SMBUS_CONFIG_SMB_EN                    (1L<<30)
        #define MCPF_SMBUS_CONFIG_RESET                     (1L<<31)

    u32_t mcpf_smbus_timing_config;
        #define MCPF_SMBUS_TIMING_CONFIG_SMBUS_IDLE_TIME    (0xffL<<8)
        #define MCPF_SMBUS_TIMING_CONFIG_PERIODIC_SLAVE_STRETCH  (0xffL<<16)
        #define MCPF_SMBUS_TIMING_CONFIG_RANDOM_SLAVE_STRETCH  (0x7fL<<24)
        #define MCPF_SMBUS_TIMING_CONFIG_MODE_400           (1L<<31)

    u32_t mcpf_smbus_address;
        #define MCPF_SMBUS_ADDRESS_NIC_SMB_ADDR0            (0x7fL<<0)
        #define MCPF_SMBUS_ADDRESS_EN_NIC_SMB_ADDR0         (1L<<7)
        #define MCPF_SMBUS_ADDRESS_NIC_SMB_ADDR1            (0x7fL<<8)
        #define MCPF_SMBUS_ADDRESS_EN_NIC_SMB_ADDR1         (1L<<15)
        #define MCPF_SMBUS_ADDRESS_NIC_SMB_ADDR2            (0x7fL<<16)
        #define MCPF_SMBUS_ADDRESS_EN_NIC_SMB_ADDR2         (1L<<23)
        #define MCPF_SMBUS_ADDRESS_NIC_SMB_ADDR3            (0x7fL<<24)
        #define MCPF_SMBUS_ADDRESS_EN_NIC_SMB_ADDR3         (1L<<31)

    u32_t mcpf_smbus_master_fifo_control;
        #define MCPF_SMBUS_MASTER_FIFO_CONTROL_MASTER_RX_FIFO_THRESHOLD  (0x7fL<<8)
        #define MCPF_SMBUS_MASTER_FIFO_CONTROL_MASTER_RX_PKT_COUNT  (0x7fL<<16)
        #define MCPF_SMBUS_MASTER_FIFO_CONTROL_MASTER_TX_FIFO_FLUSH  (1L<<30)
        #define MCPF_SMBUS_MASTER_FIFO_CONTROL_MASTER_RX_FIFO_FLUSH  (1L<<31)

    u32_t mcpf_smbus_slave_fifo_control;
        #define MCPF_SMBUS_SLAVE_FIFO_CONTROL_SLAVE_RX_FIFO_THRESHOLD  (0x7fL<<8)
        #define MCPF_SMBUS_SLAVE_FIFO_CONTROL_SLAVE_RX_PKT_COUNT  (0x7fL<<16)
        #define MCPF_SMBUS_SLAVE_FIFO_CONTROL_SLAVE_TX_FIFO_FLUSH  (1L<<30)
        #define MCPF_SMBUS_SLAVE_FIFO_CONTROL_SLAVE_RX_FIFO_FLUSH  (1L<<31)

    u32_t mcpf_smbus_bit_bang_control;
        #define MCPF_SMBUS_BIT_BANG_CONTROL_SMBDAT_OUT_EN   (1L<<28)
        #define MCPF_SMBUS_BIT_BANG_CONTROL_SMBDAT_IN       (1L<<29)
        #define MCPF_SMBUS_BIT_BANG_CONTROL_SMBCLK_OUT_EN   (1L<<30)
        #define MCPF_SMBUS_BIT_BANG_CONTROL_SMBCLK_IN       (1L<<31)

    u32_t mcpf_smbus_watchdog;
        #define MCPF_SMBUS_WATCHDOG_WATCHDOG                (0xffffL<<0)

    u32_t mcpf_smbus_heartbeat;
        #define MCPF_SMBUS_HEARTBEAT_HEARTBEAT              (0xffffL<<0)

    u32_t mcpf_smbus_poll_asf;
        #define MCPF_SMBUS_POLL_ASF_POLL_ASF                (0xffffL<<0)

    u32_t mcpf_smbus_poll_legacy;
        #define MCPF_SMBUS_POLL_LEGACY_POLL_LEGACY          (0xffffL<<0)

    u32_t mcpf_smbus_retran;
        #define MCPF_SMBUS_RETRAN_RETRAN                    (0xffL<<0)

    u32_t mcpf_smbus_timestamp;
        #define MCPF_SMBUS_TIMESTAMP_TIMESTAMP              (0xffffffffL<<0)

    u32_t mcpf_smbus_master_command;
        #define MCPF_SMBUS_MASTER_COMMAND_RD_BYTE_COUNT     (0xffL<<0)
        #define MCPF_SMBUS_MASTER_COMMAND_PEC               (1L<<8)
        #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL    (0xfL<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0000  (0L<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0001  (1L<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0010  (2L<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0011  (3L<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0100  (4L<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0101  (5L<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0110  (6L<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0111  (7L<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_1000  (8L<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_1001  (9L<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_1010  (10L<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_1011  (11L<<9)
        #define MCPF_SMBUS_MASTER_COMMAND_STATUS            (0x7L<<25)
            #define MCPF_SMBUS_MASTER_COMMAND_STATUS_000    (0L<<25)
            #define MCPF_SMBUS_MASTER_COMMAND_STATUS_001    (1L<<25)
            #define MCPF_SMBUS_MASTER_COMMAND_STATUS_010    (2L<<25)
            #define MCPF_SMBUS_MASTER_COMMAND_STATUS_011    (3L<<25)
            #define MCPF_SMBUS_MASTER_COMMAND_STATUS_100    (4L<<25)
            #define MCPF_SMBUS_MASTER_COMMAND_STATUS_101    (5L<<25)
            #define MCPF_SMBUS_MASTER_COMMAND_STATUS_110    (6L<<25)
            #define MCPF_SMBUS_MASTER_COMMAND_STATUS_111    (7L<<25)
        #define MCPF_SMBUS_MASTER_COMMAND_ABORT             (1L<<30)
        #define MCPF_SMBUS_MASTER_COMMAND_START_BUSY        (1L<<31)

    u32_t mcpf_smbus_slave_command;
        #define MCPF_SMBUS_SLAVE_COMMAND_PEC                (1L<<8)
        #define MCPF_SMBUS_SLAVE_COMMAND_STATUS             (0x7L<<23)
            #define MCPF_SMBUS_SLAVE_COMMAND_STATUS_000     (0L<<23)
            #define MCPF_SMBUS_SLAVE_COMMAND_STATUS_101     (5L<<23)
            #define MCPF_SMBUS_SLAVE_COMMAND_STATUS_111     (7L<<23)
        #define MCPF_SMBUS_SLAVE_COMMAND_ABORT              (1L<<30)
        #define MCPF_SMBUS_SLAVE_COMMAND_START              (1L<<31)

    u32_t mcpf_smbus_event_enable;
        #define MCPF_SMBUS_EVENT_ENABLE_WATCHDOG_TO_EN      (1L<<0)
        #define MCPF_SMBUS_EVENT_ENABLE_HEARTBEAT_TO_EN     (1L<<1)
        #define MCPF_SMBUS_EVENT_ENABLE_POLL_ASF_TO_EN      (1L<<2)
        #define MCPF_SMBUS_EVENT_ENABLE_POLL_LEGACY_TO_EN   (1L<<3)
        #define MCPF_SMBUS_EVENT_ENABLE_RETRANSMIT_TO_EN    (1L<<4)
        #define MCPF_SMBUS_EVENT_ENABLE_SLAVE_ARP_EVENT_EN  (1L<<20)
        #define MCPF_SMBUS_EVENT_ENABLE_SLAVE_RD_EVENT_EN   (1L<<21)
        #define MCPF_SMBUS_EVENT_ENABLE_SLAVE_TX_UNDERRUN_EN  (1L<<22)
        #define MCPF_SMBUS_EVENT_ENABLE_SLAVE_START_BUSY_EN  (1L<<23)
        #define MCPF_SMBUS_EVENT_ENABLE_SLAVE_RX_EVENT_EN   (1L<<24)
        #define MCPF_SMBUS_EVENT_ENABLE_SLAVE_RX_THRESHOLD_HIT_EN  (1L<<25)
        #define MCPF_SMBUS_EVENT_ENABLE_SLAVE_RX_FIFO_FULL_EN  (1L<<26)
        #define MCPF_SMBUS_EVENT_ENABLE_MASTER_TX_UNDERRUN_EN  (1L<<27)
        #define MCPF_SMBUS_EVENT_ENABLE_MASTER_START_BUSY_EN  (1L<<28)
        #define MCPF_SMBUS_EVENT_ENABLE_MASTER_RX_EVENT_EN  (1L<<29)
        #define MCPF_SMBUS_EVENT_ENABLE_MASTER_RX_THRESHOLD_HIT_EN  (1L<<30)
        #define MCPF_SMBUS_EVENT_ENABLE_MASTER_RX_FIFO_FULL_EN  (1L<<31)

    u32_t mcpf_smbus_event_status;
        #define MCPF_SMBUS_EVENT_STATUS_WATCHDOG_TO         (1L<<0)
        #define MCPF_SMBUS_EVENT_STATUS_HEARTBEAT_TO        (1L<<1)
        #define MCPF_SMBUS_EVENT_STATUS_POLL_ASF_TO         (1L<<2)
        #define MCPF_SMBUS_EVENT_STATUS_POLL_LEGACY_TO      (1L<<3)
        #define MCPF_SMBUS_EVENT_STATUS_RETRANSMIT_TO       (1L<<4)
        #define MCPF_SMBUS_EVENT_STATUS_SLAVE_ARP_EVENT     (1L<<20)
        #define MCPF_SMBUS_EVENT_STATUS_SLAVE_RD_EVENT      (1L<<21)
        #define MCPF_SMBUS_EVENT_STATUS_SLAVE_TX_UNDERRUN   (1L<<22)
        #define MCPF_SMBUS_EVENT_STATUS_SLAVE_START_BUSY    (1L<<23)
        #define MCPF_SMBUS_EVENT_STATUS_SLAVE_RX_EVENT      (1L<<24)
        #define MCPF_SMBUS_EVENT_STATUS_SLAVE_RX_THRESHOLD_HIT  (1L<<25)
        #define MCPF_SMBUS_EVENT_STATUS_SLAVE_RX_FIFO_FULL  (1L<<26)
        #define MCPF_SMBUS_EVENT_STATUS_MASTER_TX_UNDERRUN  (1L<<27)
        #define MCPF_SMBUS_EVENT_STATUS_MASTER_START_BUSY   (1L<<28)
        #define MCPF_SMBUS_EVENT_STATUS_MASTER_RX_EVENT     (1L<<29)
        #define MCPF_SMBUS_EVENT_STATUS_MASTER_RX_THRESHOLD_HIT  (1L<<30)
        #define MCPF_SMBUS_EVENT_STATUS_MASTER_RX_FIFO_FULL  (1L<<31)

    u32_t mcpf_smbus_master_data_write;
        #define MCPF_SMBUS_MASTER_DATA_WRITE_MASTER_SMBUS_WR_DATA  (0xffL<<0)
        #define MCPF_SMBUS_MASTER_DATA_WRITE_WR_STATUS      (1L<<31)

    u32_t mcpf_smbus_master_data_read;
        #define MCPF_SMBUS_MASTER_DATA_READ_MASTER_SMBUS_RD_DATA  (0xffL<<0)
        #define MCPF_SMBUS_MASTER_DATA_READ_PEC_ERR         (1L<<29)
        #define MCPF_SMBUS_MASTER_DATA_READ_RD_STATUS       (0x3L<<30)
            #define MCPF_SMBUS_MASTER_DATA_READ_RD_STATUS_00  (0L<<30)
            #define MCPF_SMBUS_MASTER_DATA_READ_RD_STATUS_01  (1L<<30)
            #define MCPF_SMBUS_MASTER_DATA_READ_RD_STATUS_10  (2L<<30)
            #define MCPF_SMBUS_MASTER_DATA_READ_RD_STATUS_11  (3L<<30)

    u32_t mcpf_smbus_slave_data_write;
        #define MCPF_SMBUS_SLAVE_DATA_WRITE_SLAVE_SMBUS_WR_DATA  (0xffL<<0)
        #define MCPF_SMBUS_SLAVE_DATA_WRITE_WR_STATUS       (1L<<31)
            #define MCPF_SMBUS_SLAVE_DATA_WRITE_WR_STATUS_0  (0L<<31)
            #define MCPF_SMBUS_SLAVE_DATA_WRITE_WR_STATUS_1  (1L<<31)

    u32_t mcpf_smbus_slave_data_read;
        #define MCPF_SMBUS_SLAVE_DATA_READ_SLAVE_SMBUS_RD_DATA  (0xffL<<0)
        #define MCPF_SMBUS_SLAVE_DATA_READ_ERR_STATUS       (0x3L<<28)
            #define MCPF_SMBUS_SLAVE_DATA_READ_ERR_STATUS_00  (0L<<28)
            #define MCPF_SMBUS_SLAVE_DATA_READ_ERR_STATUS_01  (1L<<28)
            #define MCPF_SMBUS_SLAVE_DATA_READ_ERR_STATUS_10  (2L<<28)
            #define MCPF_SMBUS_SLAVE_DATA_READ_ERR_STATUS_11  (3L<<28)
        #define MCPF_SMBUS_SLAVE_DATA_READ_RD_STATUS        (0x3L<<30)
            #define MCPF_SMBUS_SLAVE_DATA_READ_RD_STATUS_00  (0L<<30)
            #define MCPF_SMBUS_SLAVE_DATA_READ_RD_STATUS_01  (1L<<30)
            #define MCPF_SMBUS_SLAVE_DATA_READ_RD_STATUS_10  (2L<<30)
            #define MCPF_SMBUS_SLAVE_DATA_READ_RD_STATUS_11  (3L<<30)

    u32_t mcpf_smbus_smb_unused_1[12];
    u32_t mcpf_smbus_arp_state;
        #define MCPF_SMBUS_ARP_STATE_AV_FLAG0               (1L<<0)
        #define MCPF_SMBUS_ARP_STATE_AR_FLAG0               (1L<<1)
        #define MCPF_SMBUS_ARP_STATE_AV_FLAG1               (1L<<4)
        #define MCPF_SMBUS_ARP_STATE_AR_FLAG1               (1L<<5)

    u32_t mcpf_smbus_smb_unused_2[3];
    u32_t mcpf_smbus_udid0_3;
        #define MCPF_SMBUS_UDID0_3_BYTE_12                  (0xffL<<0)
        #define MCPF_SMBUS_UDID0_3_BYTE_13                  (0xffL<<8)
        #define MCPF_SMBUS_UDID0_3_BYTE_14                  (0xffL<<16)
        #define MCPF_SMBUS_UDID0_3_BYTE_15                  (0xffL<<24)

    u32_t mcpf_smbus_udid0_2;
        #define MCPF_SMBUS_UDID0_2_BYTE_8                   (0xffL<<0)
        #define MCPF_SMBUS_UDID0_2_BYTE_9                   (0xffL<<8)
        #define MCPF_SMBUS_UDID0_2_BYTE_10                  (0xffL<<16)
        #define MCPF_SMBUS_UDID0_2_BYTE_11                  (0xffL<<24)

    u32_t mcpf_smbus_udid0_1;
        #define MCPF_SMBUS_UDID0_1_BYTE_4                   (0xffL<<0)
        #define MCPF_SMBUS_UDID0_1_BYTE_5                   (0xffL<<8)
        #define MCPF_SMBUS_UDID0_1_BYTE_6                   (0xffL<<16)
        #define MCPF_SMBUS_UDID0_1_BYTE_7                   (0xffL<<24)

    u32_t mcpf_smbus_udid0_0;
        #define MCPF_SMBUS_UDID0_0_BYTE_0                   (0xffL<<0)
        #define MCPF_SMBUS_UDID0_0_BYTE_1                   (0xffL<<8)
        #define MCPF_SMBUS_UDID0_0_BYTE_2                   (0xffL<<16)
        #define MCPF_SMBUS_UDID0_0_BYTE_3                   (0xffL<<24)

    u32_t mcpf_smbus_udid1_3;
        #define MCPF_SMBUS_UDID1_3_BYTE_12                  (0xffL<<0)
        #define MCPF_SMBUS_UDID1_3_BYTE_13                  (0xffL<<8)
        #define MCPF_SMBUS_UDID1_3_BYTE_14                  (0xffL<<16)
        #define MCPF_SMBUS_UDID1_3_BYTE_15                  (0xffL<<24)

    u32_t mcpf_smbus_udid1_2;
        #define MCPF_SMBUS_UDID1_2_BYTE_8                   (0xffL<<0)
        #define MCPF_SMBUS_UDID1_2_BYTE_9                   (0xffL<<8)
        #define MCPF_SMBUS_UDID1_2_BYTE_10                  (0xffL<<16)
        #define MCPF_SMBUS_UDID1_2_BYTE_11                  (0xffL<<24)

    u32_t mcpf_smbus_udid1_1;
        #define MCPF_SMBUS_UDID1_1_BYTE_4                   (0xffL<<0)
        #define MCPF_SMBUS_UDID1_1_BYTE_5                   (0xffL<<8)
        #define MCPF_SMBUS_UDID1_1_BYTE_6                   (0xffL<<16)
        #define MCPF_SMBUS_UDID1_1_BYTE_7                   (0xffL<<24)

    u32_t mcpf_smbus_udid1_0;
        #define MCPF_SMBUS_UDID1_0_BYTE_0                   (0xffL<<0)
        #define MCPF_SMBUS_UDID1_0_BYTE_1                   (0xffL<<8)
        #define MCPF_SMBUS_UDID1_0_BYTE_2                   (0xffL<<16)
        #define MCPF_SMBUS_UDID1_0_BYTE_3                   (0xffL<<24)

    u32_t mcpf_smbus_smb_unused_3[211];
    u32_t mcpf_smbus_smb_reg_end;
    u32_t mcpf_unused_h[512];
    u32_t mcpf_m2p_status;
        #define MCPF_M2P_STATUS_M2P_BUSY                    (1L<<0)
        #define MCPF_M2P_STATUS_M2P_PKT_INUSE_ERROR         (1L<<1)
        #define MCPF_M2P_STATUS_M2P_PKT_OVERFLOW_ERROR      (1L<<2)
        #define MCPF_M2P_STATUS_M2P_PKT_UNDERFLOW_ERROR     (1L<<3)
        #define MCPF_M2P_STATUS_M2P_ZERO_LENGTH_ERROR       (1L<<4)
        #define MCPF_M2P_STATUS_M2P_DATA_SM                 (0x3L<<8)
        #define MCPF_M2P_STATUS_M2P_PKT_FIFO_STATUS         (0x3fL<<16)

    u32_t mcpf_m2p_command;
        #define MCPF_M2P_COMMAND_SEND_PKT_TO_PXP            (1L<<0)

    u32_t mcpf_m2p_vdm_length;
        #define MCPF_M2P_VDM_LENGTH_VDM_LENGTH              (0x7fL<<0)

    u32_t mcpf_m2p_pci_id;
        #define MCPF_M2P_PCI_ID_PCI_ID                      (0xffffL<<0)

    u32_t mcpf_m2p_vendor_id;
        #define MCPF_M2P_VENDOR_ID_VENDOR_ID                (0xffffL<<0)

    u32_t mcpf_m2p_vq_id;
        #define MCPF_M2P_VQ_ID_VQR_ID                       (0x1fL<<0)

    u32_t mcpf_m2p_src_fid;
        #define MCPF_M2P_SRC_FID_SRC_FID                    (0xffffL<<0)

    u32_t mcpf_m2p_route_type;
        #define MCPF_M2P_ROUTE_TYPE_ROUTE_TYPE              (0x7L<<0)

    u32_t mcpf_m2p_tag;
        #define MCPF_M2P_TAG_TAG                            (0xffL<<0)

    u32_t mcpf_m2p_vendor_dword;
        #define MCPF_M2P_VENDOR_DWORD_VENDOR_DWORD          (0xffffffffL<<0)

    u32_t mcpf_m2p_path_id;
        #define MCPF_M2P_PATH_ID_PATH_ID                    (1L<<0)

    u32_t mcpf_m2p_tx_data_fifo;
        #define MCPF_M2P_TX_DATA_FIFO_FIFO_DATA             (0xffffffffL<<0)

    u32_t mcpf_m2p_unused[51];
    u32_t mcpf_m2p_reg_end;
    u32_t mcpf_p2m_status;
        #define MCPF_P2M_STATUS_PKT_HDR_CNT                 (0x7fL<<0)
        #define MCPF_P2M_STATUS_RESERVED1                   (0x1ffL<<7)
        #define MCPF_P2M_STATUS_PKT_DATA_CNT                (0x1ffL<<16)
        #define MCPF_P2M_STATUS_RESERVED2                   (0x3fL<<25)
        #define MCPF_P2M_STATUS_P2M_ATTN_BIT                (1L<<31)

    u32_t mcpf_p2m_config;
        #define MCPF_P2M_CONFIG_BACKPRESSURE_MODE           (1L<<0)
        #define MCPF_P2M_CONFIG_DRAIN_MODE                  (1L<<1)
        #define MCPF_P2M_CONFIG_VID_FILTER_DISCARD          (1L<<2)
        #define MCPF_P2M_CONFIG_RESERVED                    (0x1fffffffL<<3)

    u32_t mcpf_p2m_vid_filt_config_0;
        #define MCPF_P2M_VID_FILT_CONFIG_0_VID_FILT_VENDORID  (0xffffL<<0)
        #define MCPF_P2M_VID_FILT_CONFIG_0_VID_FILT_DISCARD  (1L<<16)
        #define MCPF_P2M_VID_FILT_CONFIG_0_VID_FILT_ENABLE  (1L<<17)

    u32_t mcpf_p2m_vid_filt_config_1;
        #define MCPF_P2M_VID_FILT_CONFIG_1_VID_FILT_VENDORID  (0xffffL<<0)
        #define MCPF_P2M_VID_FILT_CONFIG_1_VID_FILT_DISCARD  (1L<<16)
        #define MCPF_P2M_VID_FILT_CONFIG_1_VID_FILT_ENABLE  (1L<<17)

    u32_t mcpf_p2m_tag_filt_config;
        #define MCPF_P2M_TAG_FILT_CONFIG_TAG_FILT_VALUE     (0xffL<<0)
        #define MCPF_P2M_TAG_FILT_CONFIG_TAG_FILT_MASK      (0xffL<<8)
        #define MCPF_P2M_TAG_FILT_CONFIG_TAG_FILT_DISCARD   (1L<<16)

    u32_t mcpf_p2m_length_filt_config;
        #define MCPF_P2M_LENGTH_FILT_CONFIG_LENGTH_MIN_VALUE  (0x7fL<<0)
        #define MCPF_P2M_LENGTH_FILT_CONFIG_TAG_FILT_MASK   (0x7fL<<8)

    u32_t mcpf_p2m_discard_stat_vendorid;
        #define MCPF_P2M_DISCARD_STAT_VENDORID_DISCARD_STAT_VENDORID  (0xffffffffL<<0)

    u32_t mcpf_p2m_discard_stat_tag;
        #define MCPF_P2M_DISCARD_STAT_TAG_DISCARD_STAT_TAG  (0xffffffffL<<0)

    u32_t mcpf_p2m_discard_stat_length;
        #define MCPF_P2M_DISCARD_STAT_LENGTH_DISCARD_STAT_LENGTH  (0xffffffffL<<0)

    u32_t mcpf_p2m_drop_stat;
        #define MCPF_P2M_DROP_STAT_DROP_STAT                (0xffffffffL<<0)

    u32_t mcpf_p2m_rcvd_stat;
        #define MCPF_P2M_RCVD_STAT_RCVD_STAT                (0xffffffffL<<0)

    u32_t mcpf_p2m_hdr_single_reg;
        #define MCPF_P2M_HDR_SINGLE_REG_HEADER_SINGLE_REG_MODE  (0xffffffffL<<0)

    u32_t mcpf_p2m_hdr_fifo_0;
        #define MCPF_P2M_HDR_FIFO_0_HEADER_0                (0xffffffffL<<0)

    u32_t mcpf_p2m_hdr_fifo_1;
        #define MCPF_P2M_HDR_FIFO_1_HEADER_1                (0xffffffffL<<0)

    u32_t mcpf_p2m_hdr_fifo_2;
        #define MCPF_P2M_HDR_FIFO_2_HEADER_2                (0xffffffffL<<0)

    u32_t mcpf_p2m_hdr_fifo_3;
        #define MCPF_P2M_HDR_FIFO_3_HEADER_3                (0x7L<<0)
        #define MCPF_P2M_HDR_FIFO_3_RESERVED                (0x1fffffffL<<3)

    u32_t mcpf_p2m_data_fifo;
        #define MCPF_P2M_DATA_FIFO_DATA                     (0xffffffffL<<0)

    u32_t mcpf_p2m_vdm_length;
        #define MCPF_P2M_VDM_LENGTH_VDM_LENGTH              (0x7fL<<0)

    u32_t mcpf_p2m_pci_req_id;
        #define MCPF_P2M_PCI_REQ_ID_PCI_REQ_ID              (0xffffL<<0)

    u32_t mcpf_p2m_vendor_id;
        #define MCPF_P2M_VENDOR_ID_VENDOR_ID                (0xffffL<<0)

    u32_t mcpf_p2m_fid;
        #define MCPF_P2M_FID_FID                            (0xffffL<<0)

    u32_t mcpf_p2m_vendor_dword;
        #define MCPF_P2M_VENDOR_DWORD_VENDOR_DWORD          (0xffffffffL<<0)

    u32_t mcpf_p2m_other_hdr_fields;
        #define MCPF_P2M_OTHER_HDR_FIELDS_PATH_ID           (1L<<0)
        #define MCPF_P2M_OTHER_HDR_FIELDS_ROUTING_FIELD     (0x7L<<4)
        #define MCPF_P2M_OTHER_HDR_FIELDS_TAG               (0xffL<<16)

    u32_t mcpf_p2m_unused[40];
    u32_t mcpf_p2m_reg_end;
    u32_t mcpf_cache_pim_nvram_base;
    u32_t mcpf_cache_paging_enable;
        #define MCPF_CACHE_PAGING_ENABLE_ENABLE             (1L<<0)

    u32_t mcpf_cache_fetch_completion;
    u32_t mcpf_cache_cache_ctrl_status_0;
        #define MCPF_CACHE_CACHE_CTRL_STATUS_0_LOCK         (1L<<0)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_0_ACTIVE       (1L<<1)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_0_VALID        (1L<<2)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_0_NVRAM_PAGE_OFFSET  (0x1ffL<<3)

    u32_t mcpf_cache_cache_ctrl_status_1;
        #define MCPF_CACHE_CACHE_CTRL_STATUS_1_LOCK         (1L<<0)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_1_ACTIVE       (1L<<1)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_1_VALID        (1L<<2)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_1_NVRAM_PAGE_OFFSET  (0x1ffL<<3)

    u32_t mcpf_cache_cache_ctrl_status_2;
        #define MCPF_CACHE_CACHE_CTRL_STATUS_2_LOCK         (1L<<0)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_2_ACTIVE       (1L<<1)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_2_VALID        (1L<<2)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_2_NVRAM_PAGE_OFFSET  (0x1ffL<<3)

    u32_t mcpf_cache_cache_ctrl_status_3;
        #define MCPF_CACHE_CACHE_CTRL_STATUS_3_LOCK         (1L<<0)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_3_ACTIVE       (1L<<1)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_3_VALID        (1L<<2)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_3_NVRAM_PAGE_OFFSET  (0x1ffL<<3)

    u32_t mcpf_cache_cache_ctrl_status_4;
        #define MCPF_CACHE_CACHE_CTRL_STATUS_4_LOCK         (1L<<0)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_4_ACTIVE       (1L<<1)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_4_VALID        (1L<<2)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_4_NVRAM_PAGE_OFFSET  (0x1ffL<<3)

    u32_t mcpf_cache_cache_ctrl_status_5;
        #define MCPF_CACHE_CACHE_CTRL_STATUS_5_LOCK         (1L<<0)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_5_ACTIVE       (1L<<1)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_5_VALID        (1L<<2)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_5_NVRAM_PAGE_OFFSET  (0x1ffL<<3)

    u32_t mcpf_cache_cache_ctrl_status_6;
        #define MCPF_CACHE_CACHE_CTRL_STATUS_6_LOCK         (1L<<0)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_6_ACTIVE       (1L<<1)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_6_VALID        (1L<<2)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_6_NVRAM_PAGE_OFFSET  (0x1ffL<<3)

    u32_t mcpf_cache_cache_ctrl_status_7;
        #define MCPF_CACHE_CACHE_CTRL_STATUS_7_LOCK         (1L<<0)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_7_ACTIVE       (1L<<1)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_7_VALID        (1L<<2)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_7_NVRAM_PAGE_OFFSET  (0x1ffL<<3)

    u32_t mcpf_cache_cache_ctrl_status_8;
        #define MCPF_CACHE_CACHE_CTRL_STATUS_8_LOCK         (1L<<0)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_8_ACTIVE       (1L<<1)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_8_VALID        (1L<<2)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_8_NVRAM_PAGE_OFFSET  (0x1ffL<<3)

    u32_t mcpf_cache_cache_ctrl_status_9;
        #define MCPF_CACHE_CACHE_CTRL_STATUS_9_LOCK         (1L<<0)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_9_ACTIVE       (1L<<1)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_9_VALID        (1L<<2)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_9_NVRAM_PAGE_OFFSET  (0x1ffL<<3)

    u32_t mcpf_cache_cache_ctrl_status_10;
        #define MCPF_CACHE_CACHE_CTRL_STATUS_10_LOCK        (1L<<0)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_10_ACTIVE      (1L<<1)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_10_VALID       (1L<<2)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_10_NVRAM_PAGE_OFFSET  (0x1ffL<<3)

    u32_t mcpf_cache_cache_ctrl_status_11;
        #define MCPF_CACHE_CACHE_CTRL_STATUS_11_LOCK        (1L<<0)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_11_ACTIVE      (1L<<1)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_11_VALID       (1L<<2)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_11_NVRAM_PAGE_OFFSET  (0x1ffL<<3)

    u32_t mcpf_cache_cache_ctrl_status_12;
        #define MCPF_CACHE_CACHE_CTRL_STATUS_12_LOCK        (1L<<0)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_12_ACTIVE      (1L<<1)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_12_VALID       (1L<<2)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_12_NVRAM_PAGE_OFFSET  (0x1ffL<<3)

    u32_t mcpf_cache_cache_ctrl_status_13;
        #define MCPF_CACHE_CACHE_CTRL_STATUS_13_LOCK        (1L<<0)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_13_ACTIVE      (1L<<1)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_13_VALID       (1L<<2)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_13_NVRAM_PAGE_OFFSET  (0x1ffL<<3)

    u32_t mcpf_cache_cache_ctrl_status_14;
        #define MCPF_CACHE_CACHE_CTRL_STATUS_14_LOCK        (1L<<0)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_14_ACTIVE      (1L<<1)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_14_VALID       (1L<<2)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_14_NVRAM_PAGE_OFFSET  (0x1ffL<<3)

    u32_t mcpf_cache_cache_ctrl_status_15;
        #define MCPF_CACHE_CACHE_CTRL_STATUS_15_LOCK        (1L<<0)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_15_ACTIVE      (1L<<1)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_15_VALID       (1L<<2)
        #define MCPF_CACHE_CACHE_CTRL_STATUS_15_NVRAM_PAGE_OFFSET  (0x1ffL<<3)

    u32_t mcpf_cache_img_loader_baddr;
        #define MCPF_CACHE_IMG_LOADER_BADDR_VALUE           (0x7fffffL<<2)

    u32_t mcpf_cache_img_loader_gaddr;
        #define MCPF_CACHE_IMG_LOADER_GADDR_VALUE           (0x7fffffL<<2)

    u32_t mcpf_cache_img_loader_caddr;
        #define MCPF_CACHE_IMG_LOADER_CADDR_VALUE           (0x7fffffL<<2)

    u32_t mcpf_cache_img_loader_cdata;
        #define MCPF_CACHE_IMG_LOADER_CDATA_VALUE           (0x7fffffL<<2)

    u32_t mcpf_cache_img_loader_cfg;
        #define MCPF_CACHE_IMG_LOADER_CFG_VALUE             (0x7fffffL<<2)

    u32_t mcpf_cache_stat_hit_counter;
    u32_t mcpf_cache_stat_miss_counter;
    u32_t mcpf_cache_last_page_0;
        #define MCPF_CACHE_LAST_PAGE_0_VALID                (1L<<0)
        #define MCPF_CACHE_LAST_PAGE_0_IS_LAST              (1L<<1)
        #define MCPF_CACHE_LAST_PAGE_0_PAGE_INDEX           (0xfL<<2)
        #define MCPF_CACHE_LAST_PAGE_0_PAGE_OFFSET          (0x1ffL<<6)

    u32_t mcpf_cache_last_page_1;
        #define MCPF_CACHE_LAST_PAGE_1_VALID                (1L<<0)
        #define MCPF_CACHE_LAST_PAGE_1_IS_LAST              (1L<<1)
        #define MCPF_CACHE_LAST_PAGE_1_PAGE_INDEX           (0xfL<<2)
        #define MCPF_CACHE_LAST_PAGE_1_PAGE_OFFSET          (0x1ffL<<6)

    u32_t mcpf_cache_page_fetch_state;
    u32_t mcpf_cache_cache_error_status;
        #define MCPF_CACHE_CACHE_ERROR_STATUS_OUT_OF_BOUNDS_READ  (1L<<0)
        #define MCPF_CACHE_CACHE_ERROR_STATUS_ILLEGAL_FETCH  (1L<<1)

    u32_t mcpf_cache_cache_unused[33];
    u32_t mcpf_cache_reg_end;
    u32_t mcpf_unused_i[1088];
    u32_t mcpf_to_bmb_fifo_command;
        #define MCPF_TO_BMB_FIFO_COMMAND_FLUSH              (1L<<0)
        #define MCPF_TO_BMB_FIFO_COMMAND_ERROR              (1L<<1)
        #define MCPF_TO_BMB_FIFO_COMMAND_PKT_TC             (0xfL<<4)
        #define MCPF_TO_BMB_FIFO_COMMAND_PKT_LEN            (0xffffL<<16)

    u32_t mcpf_to_bmb_fifo_status;
        #define MCPF_TO_BMB_FIFO_STATUS_WRITE_DONE          (1L<<0)

    u32_t mcpf_to_bmb_fifo_wr_data;
    u32_t mcpf_bmb_unused_1;
    u32_t mcpf_to_bmb_fifo_sop_dscr0;
    u32_t mcpf_to_bmb_fifo_sop_dscr1;
    u32_t mcpf_to_bmb_fifo_sop_dscr2;
    u32_t mcpf_to_bmb_fifo_sop_dscr3;
    u32_t mcpf_frm_bmb_fifo_command;
        #define MCPF_FRM_BMB_FIFO_COMMAND_READ_DONE         (1L<<0)
        #define MCPF_FRM_BMB_FIFO_COMMAND_FLUSH             (1L<<4)
        #define MCPF_FRM_BMB_FIFO_COMMAND_CLR_PKT_COUNTERS  (1L<<5)

    u32_t mcpf_frm_bmb_fifo_status;
        #define MCPF_FRM_BMB_FIFO_STATUS_BUSY               (1L<<0)
        #define MCPF_FRM_BMB_FIFO_STATUS_PKT_TC0            (0x3L<<2)
        #define MCPF_FRM_BMB_FIFO_STATUS_DATA_VALID         (1L<<4)
        #define MCPF_FRM_BMB_FIFO_STATUS_SOP                (1L<<5)
        #define MCPF_FRM_BMB_FIFO_STATUS_EOP                (1L<<6)
        #define MCPF_FRM_BMB_FIFO_STATUS_ERR                (1L<<7)
        #define MCPF_FRM_BMB_FIFO_STATUS_BYTE_VALID         (0x3L<<8)
            #define MCPF_FRM_BMB_FIFO_STATUS_BYTE_VALID_0   (0L<<8)
            #define MCPF_FRM_BMB_FIFO_STATUS_BYTE_VALID_1   (1L<<8)
            #define MCPF_FRM_BMB_FIFO_STATUS_BYTE_VALID_2   (2L<<8)
            #define MCPF_FRM_BMB_FIFO_STATUS_BYTE_VALID_3   (3L<<8)
        #define MCPF_FRM_BMB_FIFO_STATUS_PKT_TC1            (0x3L<<10)
        #define MCPF_FRM_BMB_FIFO_STATUS_PKT_PORT           (0xfL<<12)
        #define MCPF_FRM_BMB_FIFO_STATUS_PKT_LEN            (0xffffL<<16)

    u32_t mcpf_bmb_unused_2;
    u32_t mcpf_frm_bmb_fifo_rd_data;
    u32_t mcpf_frm_bmb_fifo_sop_dscr0;
    u32_t mcpf_frm_bmb_fifo_sop_dscr1;
    u32_t mcpf_frm_bmb_fifo_sop_dscr2;
    u32_t mcpf_frm_bmb_fifo_sop_dscr3;
    u32_t mcpf_bmb_unused_3[239];
    u32_t mcpf_bmb_reg_end;
    u32_t mcpf_unused_j[87808];
} mcp_fio_t;

#endif /* MCP_FIO_H */
