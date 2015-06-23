
/*
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
 * Generated On Date:  02/17/2011 13:14
 *
 */
#ifndef MCP_FIO_H
#define MCP_FIO_H

/*
 *  mcp_fio definition
 *  offset: 0x80000000
 */
typedef struct mcp_fio
{
    u32_t mcpf_events_bits;
        #define MCPF_EVENTS_BITS_FTQ0_VALID                 (1L<<0)
        #define MCPF_EVENTS_BITS_FTQ1_VALID                 (1L<<1)
        #define MCPF_EVENTS_BITS_UMP_EVENT                  (1L<<2)
        #define MCPF_EVENTS_BITS_SMBUS_EVENT                (1L<<3)
        #define MCPF_EVENTS_BITS_FLASH_EVENT                (1L<<4)
        #define MCPF_EVENTS_BITS_MCP_DOORBELL               (1L<<5)
        #define MCPF_EVENTS_BITS_HFTQ0_VALID                (1L<<6)
        #define MCPF_EVENTS_BITS_HFTQ1_VALID                (1L<<7)
        #define MCPF_EVENTS_BITS_EXP_ROM                    (1L<<8)
        #define MCPF_EVENTS_BITS_VPD                        (1L<<9)
        #define MCPF_EVENTS_BITS_FLASH                      (1L<<10)
        #define MCPF_EVENTS_BITS_SMB0                       (1L<<11)
        #define MCPF_EVENTS_BITS_NIG                        (1L<<12)
        #define MCPF_EVENTS_BITS_RESERVED0                  (1L<<13)
        #define MCPF_EVENTS_BITS_RESERVED1                  (1L<<14)
        #define MCPF_EVENTS_BITS_GPIO0                      (1L<<15)
        #define MCPF_EVENTS_BITS_GPIO1                      (1L<<16)
        #define MCPF_EVENTS_BITS_GPIO2                      (1L<<17)
        #define MCPF_EVENTS_BITS_GPIO3                      (1L<<18)
        #define MCPF_EVENTS_BITS_SW_TMR_1                   (1L<<19)
        #define MCPF_EVENTS_BITS_SW_TMR_2                   (1L<<20)
        #define MCPF_EVENTS_BITS_SW_TMR_3                   (1L<<21)
        #define MCPF_EVENTS_BITS_SW_TMR_4                   (1L<<22)
        #define MCPF_EVENTS_BITS_MSI                        (1L<<23)
        #define MCPF_EVENTS_BITS_RESERVED2                  (1L<<24)
        #define MCPF_EVENTS_BITS_RESERVED3                  (1L<<25)
        #define MCPF_EVENTS_BITS_RESERVED4                  (1L<<26)
        #define MCPF_EVENTS_BITS_MAIN_PWR_INT               (1L<<27)
        #define MCPF_EVENTS_BITS_NOT_ENABLED                (1L<<30)
        #define MCPF_EVENTS_BITS_ATTENTIONS_VALID           (1L<<31)

    u32_t mcpf_attentions_bits;
        #define MCPF_ATTENTIONS_BITS_GRC_TIMEOUT            (1L<<0)
        #define MCPF_ATTENTIONS_BITS_PERST_ASSERTION        (1L<<1)
        #define MCPF_ATTENTIONS_BITS_SPAD_PARITY_ERR        (1L<<2)
        #define MCPF_ATTENTIONS_BITS_SPIO5                  (1L<<3)
        #define MCPF_ATTENTIONS_BITS_RSV_ACCESS             (1L<<4)
        #define MCPF_ATTENTIONS_BITS_PFC_PORT_0             (1L<<5)
        #define MCPF_ATTENTIONS_BITS_PFC_PORT_1             (1L<<6)

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

    u32_t mcpf_unused_a[2];
    u32_t mcpf_unused_b[8];
    u32_t mcpf_mcp_hc_inc_stat[8];
    u32_t mcpf_unused_c[4];
    u32_t mcpf_free_counter_value;
    u32_t mcpf_unused_d[18];
    u32_t mcpf_mcp_vfid;
        #define MCPF_MCP_VFID_VFID                          (0x3fL<<0)
        #define MCPF_MCP_VFID_VFID_VALID                    (1L<<16)
        #define MCPF_MCP_VFID_PATHID                        (1L<<20)
        #define MCPF_MCP_VFID_FIO_REG_EN                    (1L<<30)
        #define MCPF_MCP_VFID_PATH_FORCE                    (1L<<31)

    u32_t mcpf_unused1[16];
    u32_t mcpf_mcpq_bits_status1;
        #define MCPF_MCPQ_BITS_STATUS1_BRCST                (1L<<0)
        #define MCPF_MCPQ_BITS_STATUS1_MLCST                (1L<<1)
        #define MCPF_MCPQ_BITS_STATUS1_UNCST                (1L<<2)
        #define MCPF_MCPQ_BITS_STATUS1_MAC0                 (1L<<3)
        #define MCPF_MCPQ_BITS_STATUS1_MAC1                 (1L<<4)
        #define MCPF_MCPQ_BITS_STATUS1_MAC2                 (1L<<5)
        #define MCPF_MCPQ_BITS_STATUS1_ARP                  (1L<<6)
        #define MCPF_MCPQ_BITS_STATUS1_IP0                  (1L<<7)
        #define MCPF_MCPQ_BITS_STATUS1_IP1                  (1L<<8)
        #define MCPF_MCPQ_BITS_STATUS1_IP2                  (1L<<9)
        #define MCPF_MCPQ_BITS_STATUS1_NTBS_U_SRC           (1L<<10)
        #define MCPF_MCPQ_BITS_STATUS1_NTBS_T_SRC           (1L<<11)
        #define MCPF_MCPQ_BITS_STATUS1_RMCP                 (1L<<12)
        #define MCPF_MCPQ_BITS_STATUS1_DHCP                 (1L<<13)
        #define MCPF_MCPQ_BITS_STATUS1_NTBS_U_DST           (1L<<14)
        #define MCPF_MCPQ_BITS_STATUS1_UDP0                 (1L<<15)
        #define MCPF_MCPQ_BITS_STATUS1_UDP1                 (1L<<16)
        #define MCPF_MCPQ_BITS_STATUS1_UDP2                 (1L<<17)
        #define MCPF_MCPQ_BITS_STATUS1_NTBS_T_DST           (1L<<18)
        #define MCPF_MCPQ_BITS_STATUS1_TCP0                 (1L<<19)
        #define MCPF_MCPQ_BITS_STATUS1_TCP1                 (1L<<20)
        #define MCPF_MCPQ_BITS_STATUS1_TCP2                 (1L<<21)
        #define MCPF_MCPQ_BITS_STATUS1_VLAN_ID0             (1L<<22)
        #define MCPF_MCPQ_BITS_STATUS1_VLAN_ID1             (1L<<23)
        #define MCPF_MCPQ_BITS_STATUS1_VLAN_ID2             (1L<<24)
        #define MCPF_MCPQ_BITS_STATUS1_VLAN                 (1L<<25)
        #define MCPF_MCPQ_BITS_STATUS1_NO_VLAN              (1L<<26)
        #define MCPF_MCPQ_BITS_STATUS1_L2_CRC               (1L<<27)

    u16_t mcpf_mcpq_pkt_len;
        #define MCPF_MCPQ_PKT_LEN_MASK                      (0x3fff<<0)

    u16_t mcpf_mcpq_vlan_tag;
    u32_t mcpf_mcpq_bits_status2;
        #define MCPF_MCPQ_BITS_STATUS2_CLUSTER_MASK         (0x3L<<0)
        #define MCPF_MCPQ_BITS_STATUS2_MF_OUTER_VLAN        (1L<<2)
        #define MCPF_MCPQ_BITS_STATUS2_MF_NO_OUTER_VLAN     (1L<<3)
        #define MCPF_MCPQ_BITS_STATUS2_MF_OUTER_VLAN_ID     (1L<<4)
        #define MCPF_MCPQ_BITS_STATUS2_MF_MAC3              (1L<<5)
        #define MCPF_MCPQ_BITS_STATUS2_MF_IPV6_MLCST        (1L<<6)
        #define MCPF_MCPQ_BITS_STATUS2_OUTER_VLAN_MASK      (0xffffL<<7)
        #define MCPF_MCPQ_BITS_STATUS2_MAC4                 (1L<<23)
        #define MCPF_MCPQ_BITS_STATUS2_MAC5                 (1L<<24)

    u32_t mcpf_mcpq_bits_status3;
        #define MCPF_MCPQ_BITS_STATUS3_ETYPE0               (1L<<1)
        #define MCPF_MCPQ_BITS_STATUS3_ETYPE1               (1L<<2)
        #define MCPF_MCPQ_BITS_STATUS3_ALL_MLCST            (1L<<3)
        #define MCPF_MCPQ_BITS_STATUS3_ARP                  (1L<<7)
        #define MCPF_MCPQ_BITS_STATUS3_ICMPV4               (1L<<8)
        #define MCPF_MCPQ_BITS_STATUS3_ICMPV6               (1L<<9)
        #define MCPF_MCPQ_BITS_STATUS3_LLDP                 (1L<<11)
        #define MCPF_MCPQ_BITS_STATUS3_VNTAG0               (1L<<12)
        #define MCPF_MCPQ_BITS_STATUS3_VNTAG1               (1L<<13)
        #define MCPF_MCPQ_BITS_STATUS3_PF0_VLAN             (1L<<16)
        #define MCPF_MCPQ_BITS_STATUS3_PF1_VLAN             (1L<<18)

    u32_t mcpf_unused_h[10];
    u32_t mcpf_mcpq_cmd;
        #define MCPF_MCPQ_CMD_MCPQ_CMD_POP                  (1L<<30)

    u32_t mcpf_unused_hh[1];
    u32_t mcpf_hmcpq_bits_status1;
        #define MCPF_HMCPQ_BITS_STATUS1_BRCST               (1L<<0)
        #define MCPF_HMCPQ_BITS_STATUS1_MLCST               (1L<<1)
        #define MCPF_HMCPQ_BITS_STATUS1_UNCST               (1L<<2)
        #define MCPF_HMCPQ_BITS_STATUS1_MAC0                (1L<<3)
        #define MCPF_HMCPQ_BITS_STATUS1_MAC1                (1L<<4)
        #define MCPF_HMCPQ_BITS_STATUS1_MAC2                (1L<<5)
        #define MCPF_HMCPQ_BITS_STATUS1_ARP                 (1L<<6)
        #define MCPF_HMCPQ_BITS_STATUS1_IP0                 (1L<<7)
        #define MCPF_HMCPQ_BITS_STATUS1_IP1                 (1L<<8)
        #define MCPF_HMCPQ_BITS_STATUS1_IP2                 (1L<<9)
        #define MCPF_HMCPQ_BITS_STATUS1_NTBS_U_SRC          (1L<<10)
        #define MCPF_HMCPQ_BITS_STATUS1_NTBS_T_SRC          (1L<<11)
        #define MCPF_HMCPQ_BITS_STATUS1_RMCP                (1L<<12)
        #define MCPF_HMCPQ_BITS_STATUS1_DHCP                (1L<<13)
        #define MCPF_HMCPQ_BITS_STATUS1_NTBS_U_DST          (1L<<14)
        #define MCPF_HMCPQ_BITS_STATUS1_UDP0                (1L<<15)
        #define MCPF_HMCPQ_BITS_STATUS1_UDP1                (1L<<16)
        #define MCPF_HMCPQ_BITS_STATUS1_UDP2                (1L<<17)
        #define MCPF_HMCPQ_BITS_STATUS1_NTBS_T_DST          (1L<<18)
        #define MCPF_HMCPQ_BITS_STATUS1_TCP0                (1L<<19)
        #define MCPF_HMCPQ_BITS_STATUS1_TCP1                (1L<<20)
        #define MCPF_HMCPQ_BITS_STATUS1_TCP2                (1L<<21)
        #define MCPF_HMCPQ_BITS_STATUS1_VLAN_ID0            (1L<<22)
        #define MCPF_HMCPQ_BITS_STATUS1_VLAN_ID1            (1L<<23)
        #define MCPF_HMCPQ_BITS_STATUS1_VLAN_ID2            (1L<<24)
        #define MCPF_HMCPQ_BITS_STATUS1_VLAN                (1L<<25)
        #define MCPF_HMCPQ_BITS_STATUS1_NO_VLAN             (1L<<26)
        #define MCPF_HMCPQ_BITS_STATUS1_L2_CRC              (1L<<27)

    u16_t mcpf_hmcpq_pkt_len;
        #define MCPF_HMCPQ_PKT_LEN_MASK                     (0x3fff<<0)

    u16_t mcpf_hmcpq_vlan_tag;
    u32_t mcpf_hmcpq_bits_status2;
        #define MCPF_HMCPQ_BITS_STATUS2_CLUSTER_MASK        (0x3L<<0)
        #define MCPF_HMCPQ_BITS_STATUS2_MF_OUTER_VLAN       (1L<<2)
        #define MCPF_HMCPQ_BITS_STATUS2_MF_NO_OUTER_VLAN    (1L<<3)
        #define MCPF_HMCPQ_BITS_STATUS2_MF_OUTER_VLAN_ID    (1L<<4)
        #define MCPF_HMCPQ_BITS_STATUS2_MF_MAC3             (1L<<5)
        #define MCPF_HMCPQ_BITS_STATUS2_MF_IPV6_MLCST       (1L<<6)
        #define MCPF_HMCPQ_BITS_STATUS2_OUTER_VLAN_MASK     (0xffffL<<7)
        #define MCPF_HMCPQ_BITS_STATUS2_MAC4                (1L<<23)
        #define MCPF_HMCPQ_BITS_STATUS2_MAC5                (1L<<24)

    u32_t mcpf_hmcpq_bits_status3;
        #define MCPF_HMCPQ_BITS_STATUS3_ETYPE0              (1L<<1)
        #define MCPF_HMCPQ_BITS_STATUS3_ETYPE1              (1L<<2)
        #define MCPF_HMCPQ_BITS_STATUS3_ALL_MLCST           (1L<<3)
        #define MCPF_HMCPQ_BITS_STATUS3_ARP                 (1L<<7)
        #define MCPF_HMCPQ_BITS_STATUS3_ICMPV4              (1L<<8)
        #define MCPF_HMCPQ_BITS_STATUS3_ICMPV6              (1L<<9)
        #define MCPF_HMCPQ_BITS_STATUS3_LLDP                (1L<<11)
        #define MCPF_HMCPQ_BITS_STATUS3_VNTAG0              (1L<<12)
        #define MCPF_HMCPQ_BITS_STATUS3_VNTAG1              (1L<<13)
        #define MCPF_HMCPQ_BITS_STATUS3_PF0_VLAN            (1L<<16)
        #define MCPF_HMCPQ_BITS_STATUS3_PF1_VLAN            (1L<<18)

    u32_t mcpf_unused_hj[10];
    u32_t mcpf_hmcpq_cmd;
        #define MCPF_HMCPQ_CMD_HMCPQ_CMD_POP                (1L<<30)

    u32_t mcpf_unused_i[39073];
    u32_t mcpf_nvm_command;
        #define MCPF_NVM_COMMAND_RST                        (1L<<0)
        #define MCPF_NVM_COMMAND_DONE                       (1L<<3)
        #define MCPF_NVM_COMMAND_DOIT                       (1L<<4)
        #define MCPF_NVM_COMMAND_WR                         (1L<<5)
        #define MCPF_NVM_COMMAND_ERASE                      (1L<<6)
        #define MCPF_NVM_COMMAND_FIRST                      (1L<<7)
        #define MCPF_NVM_COMMAND_LAST                       (1L<<8)
        #define MCPF_NVM_COMMAND_WREN                       (1L<<16)
        #define MCPF_NVM_COMMAND_WRDI                       (1L<<17)
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
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_DATA0  (9L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_DATA1  (10L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_DATA2  (11L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID0  (12L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID1  (13L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID2  (14L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID3  (15L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID4  (16L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_CHECK_BUSY0  (17L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_ST_WREN  (18L<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_WAIT  (19L<<0)

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
        #define MCPF_NVM_CFG2_READ_ID                       (0xffL<<24)

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

    u32_t mcpf_nvm_access_enable;
        #define MCPF_NVM_ACCESS_ENABLE_EN                   (1L<<0)
        #define MCPF_NVM_ACCESS_ENABLE_WR_EN                (1L<<1)

    u32_t mcpf_nvm_write1;
        #define MCPF_NVM_WRITE1_WREN_CMD                    (0xffL<<0)
        #define MCPF_NVM_WRITE1_WRDI_CMD                    (0xffL<<8)

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
        #define MCPF_NVM_CFG4_RESERVED                      (0x1fffffL<<11)

    u32_t mcpf_nvm_reconfig;
        #define MCPF_NVM_RECONFIG_ORIG_STRAP_VALUE          (0xfL<<0)
            #define MCPF_NVM_RECONFIG_ORIG_STRAP_VALUE_ST   (0L<<0)
            #define MCPF_NVM_RECONFIG_ORIG_STRAP_VALUE_ATMEL  (1L<<0)
        #define MCPF_NVM_RECONFIG_RECONFIG_STRAP_VALUE      (0xfL<<4)
        #define MCPF_NVM_RECONFIG_RESERVED                  (0x7fffffL<<8)
        #define MCPF_NVM_RECONFIG_RECONFIG_DONE             (1L<<31)

    u32_t mcpf_unused2[243];
    u32_t mcpf_unused_j[1536];
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

    u32_t mcpf_unused3[12];
    u32_t mcpf_smbus_arp_state;
        #define MCPF_SMBUS_ARP_STATE_AV_FLAG0               (1L<<0)
        #define MCPF_SMBUS_ARP_STATE_AR_FLAG0               (1L<<1)
        #define MCPF_SMBUS_ARP_STATE_AV_FLAG1               (1L<<4)
        #define MCPF_SMBUS_ARP_STATE_AR_FLAG1               (1L<<5)

    u32_t mcpf_unused4[3];
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

    u32_t mcpf_unused5[212];
    u32_t mcpf_unused6[256];
    u32_t mcpf_legacy_unused_legacy_smb[9];
    u32_t mcpf_unused7[247];
    u32_t mcpf_unused_k[15616];
    u32_t mcpf_ump_cmd;
        #define MCPF_UMP_CMD_EGRESS_FIFO_ENABLED            (1L<<0)
        #define MCPF_UMP_CMD_INGRESS_FIFO_ENABLED           (1L<<1)
        #define MCPF_UMP_CMD_FC_EN                          (1L<<2)
        #define MCPF_UMP_CMD_MAC_LOOPBACK                   (1L<<3)
        #define MCPF_UMP_CMD_EGRESS_MAC_DISABLE             (1L<<5)
        #define MCPF_UMP_CMD_INGRESS_MAC_DISABLE            (1L<<6)
        #define MCPF_UMP_CMD_INGRESS_DRIVE                  (1L<<8)
        #define MCPF_UMP_CMD_SW_PAUSE                       (1L<<9)
        #define MCPF_UMP_CMD_AUTO_DRIVE                     (1L<<13)
        #define MCPF_UMP_CMD_INGRESS_RESET                  (1L<<14)
        #define MCPF_UMP_CMD_NO_PLUS_TWO                    (1L<<15)
        #define MCPF_UMP_CMD_EGRESS_PKT_FLUSH               (1L<<16)
        #define MCPF_UMP_CMD_CMD_IPG                        (0x1fL<<17)
        #define MCPF_UMP_CMD_EGRESS_FIO_RESET               (1L<<28)
        #define MCPF_UMP_CMD_INGRESS_FIO_RESET              (1L<<29)
        #define MCPF_UMP_CMD_EGRESS_MAC_RESET               (1L<<30)
        #define MCPF_UMP_CMD_INGRESS_MAC_RESET              (1L<<31)

    u32_t mcpf_ump_config;
        #define MCPF_UMP_CONFIG_RMII_MODE                   (1L<<4)
        #define MCPF_UMP_CONFIG_RVMII_MODE                  (1L<<6)
        #define MCPF_UMP_CONFIG_INGRESS_MODE                (1L<<7)
        #define MCPF_UMP_CONFIG_INGRESS_WORD_ACCM           (0xffL<<8)
        #define MCPF_UMP_CONFIG_OLD_BCNT_RDY                (1L<<24)

    u32_t mcpf_ump_fc_trip;
        #define MCPF_UMP_FC_TRIP_XON_TRIP                   (0x1ffL<<0)
        #define MCPF_UMP_FC_TRIP_XOFF_TRIP                  (0x1ffL<<16)

    u32_t mcpf_unused_e[33];
    u32_t mcpf_ump_egress_frm_rd_status;
        #define MCPF_UMP_EGRESS_FRM_RD_STATUS_NEW_FRM       (1L<<0)
        #define MCPF_UMP_EGRESS_FRM_RD_STATUS_FRM_IN_PRO    (1L<<1)
        #define MCPF_UMP_EGRESS_FRM_RD_STATUS_FIFO_EMPTY    (1L<<2)
        #define MCPF_UMP_EGRESS_FRM_RD_STATUS_BCNT          (0x7ffL<<3)
        #define MCPF_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE  (0x1fL<<27)
            #define MCPF_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE_IDLE  (0L<<27)
            #define MCPF_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE_READY  (1L<<27)
            #define MCPF_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE_BUSY  (2L<<27)
            #define MCPF_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE_EXTRA_RD  (3L<<27)
            #define MCPF_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE_LATCH_IP_HDR  (4L<<27)

    u32_t mcpf_ump_egress_frm_rd_data;
    u32_t mcpf_ump_ingress_frm_wr_ctl;
        #define MCPF_UMP_INGRESS_FRM_WR_CTL_NEW_FRM         (1L<<0)
        #define MCPF_UMP_INGRESS_FRM_WR_CTL_FIFO_RDY        (1L<<1)
        #define MCPF_UMP_INGRESS_FRM_WR_CTL_BCNT_RDY        (1L<<2)
        #define MCPF_UMP_INGRESS_FRM_WR_CTL_BCNT            (0x7ffL<<3)
        #define MCPF_UMP_INGRESS_FRM_WR_CTL_INGRESS_FIFO_STATE  (0x3L<<30)
            #define MCPF_UMP_INGRESS_FRM_WR_CTL_INGRESS_FIFO_STATE_IDLE  (0L<<30)
            #define MCPF_UMP_INGRESS_FRM_WR_CTL_INGRESS_FIFO_STATE_WAIT  (1L<<30)
            #define MCPF_UMP_INGRESS_FRM_WR_CTL_INGRESS_FIFO_STATE_BUSY  (2L<<30)
            #define MCPF_UMP_INGRESS_FRM_WR_CTL_INGRESS_FIFO_STATE_EXTRA_WR  (3L<<30)

    u32_t mcpf_ump_ingress_frm_wr_data;
    u32_t mcpf_ump_egress_frame_type;
    u32_t mcpf_ump_fifo_remaining_words;
        #define MCPF_UMP_FIFO_REMAINING_WORDS_EGRESS_FIFO_DEPTH  (0x7ffL<<0)
        #define MCPF_UMP_FIFO_REMAINING_WORDS_EGRESS_FIFO_UNDERFLOW  (1L<<14)
        #define MCPF_UMP_FIFO_REMAINING_WORDS_EGRESS_FIFO_OVERFLOW  (1L<<15)
        #define MCPF_UMP_FIFO_REMAINING_WORDS_INGRESS_FIFO_DEPTH  (0x3ffL<<16)
        #define MCPF_UMP_FIFO_REMAINING_WORDS_INGRESS_FIFO_UNDERFLOW  (1L<<30)
        #define MCPF_UMP_FIFO_REMAINING_WORDS_INGRESS_FIFO_OVERFLOW  (1L<<31)

    u32_t mcpf_ump_egress_fifo_ptrs;
        #define MCPF_UMP_EGRESS_FIFO_PTRS_EGRESS_FIFO_RD_PTR  (0xfffL<<0)
        #define MCPF_UMP_EGRESS_FIFO_PTRS_UPDATE_RDPTR      (1L<<15)
        #define MCPF_UMP_EGRESS_FIFO_PTRS_EGRESS_FIFO_WR_PTR  (0xfffL<<16)
        #define MCPF_UMP_EGRESS_FIFO_PTRS_UPDATE_WRPTR      (1L<<31)

    u32_t mcpf_ump_ingress_fifo_ptrs;
        #define MCPF_UMP_INGRESS_FIFO_PTRS_INGRESS_FIFO_RD_PTR  (0x7ffL<<0)
        #define MCPF_UMP_INGRESS_FIFO_PTRS_UPDATE_RDPTR     (1L<<15)
        #define MCPF_UMP_INGRESS_FIFO_PTRS_INGRESS_FIFO_WR_PTR  (0x7ffL<<16)
        #define MCPF_UMP_INGRESS_FIFO_PTRS_UPDATE_WRPTR     (1L<<31)

    u32_t mcpf_unused_z[1];
    u32_t mcpf_ump_egress_packet_sa_0;
        #define MCPF_UMP_EGRESS_PACKET_SA_0_EGRESS_SA       (0xffffL<<0)

    u32_t mcpf_ump_egress_packet_sa_1;
        #define MCPF_UMP_EGRESS_PACKET_SA_1_EGRESS_SA       (0xffffffffL<<0)

    u32_t mcpf_ump_ingress_burst_command;
        #define MCPF_UMP_INGRESS_BURST_COMMAND_INGRESS_DMA_START  (1L<<0)
        #define MCPF_UMP_INGRESS_BURST_COMMAND_INGRESS_PORT  (1L<<1)
        #define MCPF_UMP_INGRESS_BURST_COMMAND_DMA_LENGTH   (0x7ffL<<2)
        #define MCPF_UMP_INGRESS_BURST_COMMAND_INGRESS_PORT_EXT  (0x3L<<13)
        #define MCPF_UMP_INGRESS_BURST_COMMAND_RBUF_OFFSET  (0x3fffL<<16)

    u32_t mcpf_ump_ingress_rbuf_cluster;
        #define MCPF_UMP_INGRESS_RBUF_CLUSTER_RBUF_CLUSTER  (0x1ffffffL<<0)

    u32_t mcpf_ump_ingress_vlan;
        #define MCPF_UMP_INGRESS_VLAN_INGRESS_VLAN_TAG      (0xffffL<<0)
        #define MCPF_UMP_INGRESS_VLAN_VLAN_INS              (1L<<16)
        #define MCPF_UMP_INGRESS_VLAN_VLAN_DEL              (1L<<17)

    u32_t mcpf_ump_ingress_burst_status;
        #define MCPF_UMP_INGRESS_BURST_STATUS_RESULT        (0x3L<<0)
            #define MCPF_UMP_INGRESS_BURST_STATUS_RESULT_BUSY  (0L<<0)
            #define MCPF_UMP_INGRESS_BURST_STATUS_RESULT_DONE  (1L<<0)
            #define MCPF_UMP_INGRESS_BURST_STATUS_RESULT_ERR  (2L<<0)
            #define MCPF_UMP_INGRESS_BURST_STATUS_RESULT_ERR1  (3L<<0)

    u32_t mcpf_ump_egress_burst_command;
        #define MCPF_UMP_EGRESS_BURST_COMMAND_EGRESS_DMA_START  (1L<<0)
        #define MCPF_UMP_EGRESS_BURST_COMMAND_EGRESS_PORT   (1L<<1)
        #define MCPF_UMP_EGRESS_BURST_COMMAND_DMA_LENGTH    (0x7ffL<<2)
        #define MCPF_UMP_EGRESS_BURST_COMMAND_EGRESS_PORT_EXT  (1L<<13)
        #define MCPF_UMP_EGRESS_BURST_COMMAND_TPBUF_OFFSET  (0x1fffL<<16)

    u32_t mcpf_ump_egress_vlan;
        #define MCPF_UMP_EGRESS_VLAN_EGRESS_VLAN_TAG        (0xffffL<<0)
        #define MCPF_UMP_EGRESS_VLAN_VLAN_INS               (1L<<16)
        #define MCPF_UMP_EGRESS_VLAN_VLAN_DEL               (1L<<17)

    u32_t mcpf_ump_egress_burst_status;
        #define MCPF_UMP_EGRESS_BURST_STATUS_RESULT         (0x3L<<0)
            #define MCPF_UMP_EGRESS_BURST_STATUS_RESULT_BUSY  (0L<<0)
            #define MCPF_UMP_EGRESS_BURST_STATUS_RESULT_DONE  (1L<<0)
            #define MCPF_UMP_EGRESS_BURST_STATUS_RESULT_ERR0  (2L<<0)
            #define MCPF_UMP_EGRESS_BURST_STATUS_RESULT_RSVD  (3L<<0)

    u32_t mcpf_ump_egress_statistic;
        #define MCPF_UMP_EGRESS_STATISTIC_EGRESS_GOOD_CNT   (0xffffL<<0)
        #define MCPF_UMP_EGRESS_STATISTIC_EGRESS_ERROR_CNT  (0xffL<<16)
        #define MCPF_UMP_EGRESS_STATISTIC_EGRESS_DROP_CNT   (0xffL<<24)

    u32_t mcpf_ump_ingress_statistic;
        #define MCPF_UMP_INGRESS_STATISTIC_INGRESS_PKT_CNT  (0xffffL<<0)

    u32_t mcpf_ump_arb_cmd;
        #define MCPF_UMP_ARB_CMD_UMP_ID                     (0x7L<<0)
        #define MCPF_UMP_ARB_CMD_UMP_ARB_DISABLE            (1L<<4)
        #define MCPF_UMP_ARB_CMD_UMP_ARB_START              (1L<<5)
        #define MCPF_UMP_ARB_CMD_UMP_ARB_BYPASS             (1L<<6)
        #define MCPF_UMP_ARB_CMD_UMP_ARB_AUTOBYPASS         (1L<<7)
        #define MCPF_UMP_ARB_CMD_UMP_ARB_TOKEN_IPG          (0x1fL<<8)
        #define MCPF_UMP_ARB_CMD_UMP_ARB_TOKEN_VALID        (1L<<13)
        #define MCPF_UMP_ARB_CMD_UMP_ARB_FC_DISABLE         (1L<<15)
        #define MCPF_UMP_ARB_CMD_UMP_ARB_TIMEOUT            (0xffffL<<16)

    u32_t mcpf_unused_f[2];
    u32_t mcpf_ump_frame_count;
        #define MCPF_UMP_FRAME_COUNT_EGRESS_FRAME_COUNT     (0x7fL<<0)
        #define MCPF_UMP_FRAME_COUNT_INRESS_FRAME_COUNT     (0x1fL<<16)

    u32_t mcpf_ump_egress_statistic_ac;
        #define MCPF_UMP_EGRESS_STATISTIC_AC_EGRESS_GOOD_CNT  (0xffffL<<0)
        #define MCPF_UMP_EGRESS_STATISTIC_AC_EGRESS_ERROR_CNT  (0xffL<<16)
        #define MCPF_UMP_EGRESS_STATISTIC_AC_EGRESS_DROP_CNT  (0xffL<<24)

    u32_t mcpf_ump_ingress_statistic_ac;
        #define MCPF_UMP_INGRESS_STATISTIC_AC_INGRESS_PKT_CNT  (0xffffL<<0)

    u32_t mcpf_ump_event;
        #define MCPF_UMP_EVENT_INGRESS_RDY_EVENT            (1L<<0)
        #define MCPF_UMP_EVENT_EGRESS_RDY_EVENT             (1L<<1)
        #define MCPF_UMP_EVENT_INGRESSBURST_DONE_EVENT      (1L<<2)
        #define MCPF_UMP_EVENT_EGRESSBURST_DONE_EVENT       (1L<<3)
        #define MCPF_UMP_EVENT_EGRESS_FRAME_DROP_EVENT      (1L<<4)
        #define MCPF_UMP_EVENT_INGRESS_RDY_EVENT_EN         (1L<<16)
        #define MCPF_UMP_EVENT_EGRESS_RDY_EVENT_EN          (1L<<17)
        #define MCPF_UMP_EVENT_INGRESSBURST_DONE_EVENT_EN   (1L<<18)
        #define MCPF_UMP_EVENT_EGRESSBURST_DONE_EVENT_EN    (1L<<19)
        #define MCPF_UMP_EVENT_EGRESS_FRAME_DROP_EVENT_EN   (1L<<20)

    u32_t mcpf_unused8[4033];
    u32_t mcpf_ump_egress_fifo_flat_space[1920];
    u32_t mcpf_unused9[128];
    u32_t mcpf_ump_ingress_fifo_flat_space[768];
    u32_t mcpf_unused10[1280];
    u32_t mcpf_unused11[65536];
} mcp_fio_t;

#endif /* MCP_FIO_H */
