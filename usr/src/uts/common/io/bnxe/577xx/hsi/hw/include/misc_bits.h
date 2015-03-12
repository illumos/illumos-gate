/* reset_reg_1 */
#define MISC_REGISTERS_RESET_REG_1_SET                                  0x584  // MISC_REGISTERS_RESET_REG_1+4
#define MISC_REGISTERS_RESET_REG_1_CLEAR                                0x588  // MISC_REGISTERS_RESET_REG_1+8
#define MISC_REGISTERS_RESET_REG_1_RST_BRB1                             (0x1<<0)
#define MISC_REGISTERS_RESET_REG_1_RST_PRS                              (0x1<<1)
#define MISC_REGISTERS_RESET_REG_1_RST_SRC                              (0x1<<2)
#define MISC_REGISTERS_RESET_REG_1_RST_TSDM                             (0x1<<3)
#define MISC_REGISTERS_RESET_REG_1_RST_TSEM                             (0x1<<4)
#define MISC_REGISTERS_RESET_REG_1_RST_TCM                              (0x1<<5)
#define MISC_REGISTERS_RESET_REG_1_RST_RBCR                             (0x1<<6)
#define MISC_REGISTERS_RESET_REG_1_RST_NIG                              (0x1<<7)
#define MISC_REGISTERS_RESET_REG_1_RST_USDM                             (0x1<<8)
#define MISC_REGISTERS_RESET_REG_1_RST_UCM                              (0x1<<9)
#define MISC_REGISTERS_RESET_REG_1_RST_USEM                             (0x1<<10)
#define MISC_REGISTERS_RESET_REG_1_RST_UPB                              (0x1<<11)
#define MISC_REGISTERS_RESET_REG_1_RST_CCM                              (0x1<<12)
#define MISC_REGISTERS_RESET_REG_1_RST_CSEM                             (0x1<<13)
#define MISC_REGISTERS_RESET_REG_1_RST_CSDM                             (0x1<<14)
#define MISC_REGISTERS_RESET_REG_1_RST_RBCU                             (0x1<<15)
#define MISC_REGISTERS_RESET_REG_1_RST_PBF                              (0x1<<16)
#define MISC_REGISTERS_RESET_REG_1_RST_QM                               (0x1<<17)
#define MISC_REGISTERS_RESET_REG_1_RST_TM                               (0x1<<18)
#define MISC_REGISTERS_RESET_REG_1_RST_DORQ                             (0x1<<19)
#define MISC_REGISTERS_RESET_REG_1_RST_XCM                              (0x1<<20)
#define MISC_REGISTERS_RESET_REG_1_RST_XSDM                             (0x1<<21)
#define MISC_REGISTERS_RESET_REG_1_RST_XSEM                             (0x1<<22)
#define MISC_REGISTERS_RESET_REG_1_RST_RBCT                             (0x1<<23)
#define MISC_REGISTERS_RESET_REG_1_RST_CDU                              (0x1<<24)
#define MISC_REGISTERS_RESET_REG_1_RST_CFC                              (0x1<<25)
#define MISC_REGISTERS_RESET_REG_1_RST_PXP                              (0x1<<26)
#define MISC_REGISTERS_RESET_REG_1_RST_PXPV                             (0x1<<27)
#define MISC_REGISTERS_RESET_REG_1_RST_RBCP                             (0x1<<28)
#define MISC_REGISTERS_RESET_REG_1_RST_HC                               (0x1<<29)
#define MISC_REGISTERS_RESET_REG_1_RST_DMAE                             (0x1<<30)
#define MISC_REGISTERS_RESET_REG_1_RST_SEMI_RTC                         (0x1<<31)
/* reset_reg_2 */
#define MISC_REGISTERS_RESET_REG_2_SET                                  0x594  // MISC_REGISTERS_RESET_REG_2+4
#define MISC_REGISTERS_RESET_REG_2_CLEAR                                0x598  // MISC_REGISTERS_RESET_REG_2+8
#define MISC_REGISTERS_RESET_REG_2_RST_BMAC0                            (0x1<<0)
#define MISC_REGISTERS_RESET_REG_2_RST_BMAC1                            (0x1<<1)
#define MISC_REGISTERS_RESET_REG_2_RST_EMAC0                            (0x1<<2)
#define MISC_REGISTERS_RESET_REG_2_RST_EMAC1                            (0x1<<3)
#define MISC_REGISTERS_RESET_REG_2_RST_GRC                              (0x1<<4) //Global register
#define MISC_REGISTERS_RESET_REG_2_RST_MCP_N_RESET_REG_HARD_CORE        (0x1<<5) //Global register
#define MISC_REGISTERS_RESET_REG_2_RST_MCP_N_HARD_CORE_RST_B            (0x1<<6) //Global register
#define MISC_REGISTERS_RESET_REG_2_RST_MCP_N_RESET_CMN_CPU              (0x1<<7) //Global register
#define MISC_REGISTERS_RESET_REG_2_RST_MCP_N_RESET_CMN_CORE             (0x1<<8) //Global register
#define MISC_REGISTERS_RESET_REG_2_RST_RBCN                             (0x1<<9)
#define MISC_REGISTERS_RESET_REG_2_RST_DBG                              (0x1<<10)
#define MISC_REGISTERS_RESET_REG_2_RST_MISC_CORE                        (0x1<<11) //Global register
#define MISC_REGISTERS_RESET_REG_2_RST_DBUE                             (0x1<<12) //Global register
#define MISC_REGISTERS_RESET_REG_2_RST_PCI_MDIO                         (0x1<<13) //Global register
#define MISC_REGISTERS_RESET_REG_2_RST_EMAC0_HARD_CORE                  (0x1<<14)
#define MISC_REGISTERS_RESET_REG_2_RST_EMAC1_HARD_CORE                  (0x1<<15)
#define MISC_REGISTERS_RESET_REG_2_RST_PXP_RQ_RD_WR                     (0x1<<16)
#define MISC_REGISTERS_RESET_REG_2_RST_ATC                              (0x1<<17)
#define MISC_REGISTERS_RESET_REG_2_CNIG                                 (0x1<<18)
#define MISC_REGISTERS_RESET_REG_2_PGLC                                 (0x1<<19) //Global register
#define MISC_REGISTERS_RESET_REG_2_UMAC0                                (0x1<<20)
#define MISC_REGISTERS_RESET_REG_2_UMAC1                                (0x1<<21)
#define MISC_REGISTERS_RESET_REG_2_XMAC                                 (0x1<<22)
#define MISC_REGISTERS_RESET_REG_2_XMAC_SOFT                            (0x1<<23)
#define MISC_REGISTERS_RESET_REG_2_MSTAT0                               (0x1<<24)
#define MISC_REGISTERS_RESET_REG_2_MSTAT1                               (0x1<<25)

/* reset_reg_3 */
#define MISC_REGISTERS_RESET_REG_3_SET                                  0x5a4  // MISC_REGISTERS_RESET_REG_3+4
#define MISC_REGISTERS_RESET_REG_3_CLEAR                                0x5a8  // MISC_REGISTERS_RESET_REG_3+8
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_SERDES0_RSTB_HW         (0x1<<0)    //(NIG - Reset Controls to SERDES0)
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_SERDES0_IDDQ            (0x1<<1)    //(NIG - Reset Controls to SERDES0)
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_SERDES0_PWRDWN          (0x1<<2)    //(NIG - Reset Controls to SERDES0)
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_SERDES0_PWRDWN_SD       (0x1<<3)    //(NIG - Reset Controls to SERDES0)
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_XGXS0_RSTB_HW           (0x1<<4)    //(NIG - Reset Controls to XGXS 0)
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_XGXS0_IDDQ              (0x1<<5)    //(NIG - Reset Controls to XGXS 0)
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_XGXS0_PWRDWN            (0x1<<6)    //(NIG - Reset Controls to XGXS 0)
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_XGXS0_PWRDWN_SD         (0x1<<7)    //(NIG - Reset Controls to XGXS 0)
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_XGXS0_TXD_FIFO_RSTB     (0x1<<8)    //(NIG - Reset Controls to XGXS 0)
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_SERDES1_RSTB_HW         (0x1<<16)   //(NIG - Reset Controls to SERDES1)
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_SERDES1_IDDQ            (0x1<<17)   //(NIG - Reset Controls to SERDES1)
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_SERDES1_PWRDWN          (0x1<<18)   //(NIG - Reset Controls to SERDES1)
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_SERDES1_PWRDWN_SD       (0x1<<19)   //(NIG - Reset Controls to SERDES1)
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_XGXS1_RSTB_HW           (0x1<<20)   //(NIG - Reset Controls to XGXS 1)
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_XGXS1_IDDQ              (0x1<<21)   //(NIG - Reset Controls to XGXS 1)
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_XGXS1_PWRDWN            (0x1<<22)   //(NIG - Reset Controls to XGXS 1)
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_XGXS1_PWRDWN_SD         (0x1<<23)   //(NIG - Reset Controls to XGXS 1)
#define MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_XGXS1_TXD_FIFO_RSTB     (0x1<<24)   //(NIG - Reset Controls to XGXS 1)
/*reset_config*/
#define MISC_REGISTERS_RESET_CONFIG_VREGPNP_BG_2A_EN                                   (0x1<<0)
#define MISC_REGISTERS_RESET_CONFIG_VREGPNP_BG_8A_VMAIN_EN                             (0x1<<1)
#define MISC_REGISTERS_RESET_CONFIG_VREGPNP_BG_8A_VAUX_EN                              (0x1<<2)
#define MISC_REGISTERS_RESET_CONFIG_RST_PXP_AUTO_MODE                                  (0x1<<3)
#define MISC_REGISTERS_RESET_CONFIG_RST_PGL_AUTO_MODE                                  (0x1<<4)
#define MISC_REGISTERS_RESET_CONFIG_RST_RBCP_AUTO_MODE                                 (0x1<<5)
#define MISC_REGISTERS_RESET_CONFIG_RST_GRC                                            (0x1<<6)
#define MISC_REGISTERS_RESET_CONFIG_RST_MCP_N_RESET_REG_HARD_CORE_AUTO_MODE            (0x1<<7)
#define MISC_REGISTERS_RESET_CONFIG_RST_MCP_N_HARD_CORE_RST_B_AUTO_MODE                (0x1<<8)
#define MISC_REGISTERS_RESET_CONFIG_RST_MCP_N_RESET_CMN_CPU_AUTO_MODE                  (0x1<<9)
#define MISC_REGISTERS_RESET_CONFIG_RST_MCP_N_RESET_CMN_CORE_AUTO_MODE                 (0x1<<10)
#define MISC_REGISTERS_RESET_CONFIG_IDDQ_MCP                                           (0x1<<11)
#define MISC_REGISTERS_RESET_CONFIG_RST_RBCN_AUTO_MODE                                 (0x1<<12)
#define MISC_REGISTERS_RESET_CONFIG_RST_DBG_AUTO_MODE                                  (0x1<<13)
#define MISC_REGISTERS_RESET_CONFIG_RST_MISC_CORE_AUTO_MODE                            (0x1<<14)
#define MISC_REGISTERS_RESET_CONFIG_RST_DBUE_AUTO_MODE                                 (0x1<<15)
#define MISC_REGISTERS_RESET_CONFIG_GRC_RESET_ASSERT_ON_CORE_RST                       (0x1<<16)
#define MISC_REGISTERS_RESET_CONFIG_RST_MCP_N_RESET_CMN_CPU_ASSERT_ON_CORE_RST         (0x1<<17)
#define MISC_REGISTERS_RESET_CONFIG_RST_MCP_N_RESET_CMN_CORE_ASSERT_ON_CORE_RST        (0x1<<18)
#define MISC_REGISTERS_RESET_CONFIG_RST_RBCN_ASSERT_ON_CORE_RST                        (0x1<<19)
#define MISC_REGISTERS_RESET_CONFIG_RST_DBG_ASSERT_ON_CORE_RST                         (0x1<<20)
#define MISC_REGISTERS_RESET_CONFIG_RST_MISC_CORE_ASSERT_ON_CORE_RST                   (0x1<<21)
#define MISC_REGISTERS_RESET_CONFIG_RST_DBUE_ASSERT_ON_CORE_RST                        (0x1<<22)
#define MISC_REGISTERS_RESET_CONFIG_WRAPPERS_IDDQ_AND_RST_SIGNALS _ASSERT_ON_CORE_RST  (0x1<<23)

/* voltage_register */
#define MISC_REGISTERS_VOLTAGE_REG_MDIO_VOLTAGE_SEL_MASK   (1L<<0)
#define MISC_REGISTERS_VOLTAGE_REG_MDIO_VOLTAGE_SEL_1_2V   (0L<<0)
#define MISC_REGISTERS_VOLTAGE_REG_MDIO_VOLTAGE_SEL_2_5V   (1L<<0)

// Definitions for GPIO
#define MISC_REGISTERS_GPIO_PORT_SHIFT           4
#define MISC_REGISTERS_GPIO_0                    0
#define MISC_REGISTERS_GPIO_1                    1
#define MISC_REGISTERS_GPIO_2                    2
#define MISC_REGISTERS_GPIO_3                    3

#define MISC_REGISTERS_GPIO_OUTPUT_LOW           0
#define MISC_REGISTERS_GPIO_OUTPUT_HIGH          1
#define MISC_REGISTERS_GPIO_INPUT_HI_Z           2

#define MISC_REGISTERS_GPIO_VALUE                (0xffL<<0)
#define MISC_REGISTERS_GPIO_VALUE_POS            0
#define MISC_REGISTERS_GPIO_SET                  (0xffL<<8)
#define MISC_REGISTERS_GPIO_SET_POS              8
#define MISC_REGISTERS_GPIO_CLR                  (0xffL<<16)
#define MISC_REGISTERS_GPIO_CLR_POS              16
#define MISC_REGISTERS_GPIO_FLOAT                (0xffL<<24)
#define MISC_REGISTERS_GPIO_FLOAT_POS            24

// Port 1 float pins are in bits 31-28
#define GRC_MISC_REGISTERS_GPIO_PORT1_FLOAT3     0x80000000
#define GRC_MISC_REGISTERS_GPIO_PORT1_FLOAT2     0x40000000
#define GRC_MISC_REGISTERS_GPIO_PORT1_FLOAT1     0x20000000
#define GRC_MISC_REGISTERS_GPIO_PORT1_FLOAT0     0x10000000
// Port 0 float pins are in bits 27-24
#define GRC_MISC_REGISTERS_GPIO_PORT0_FLOAT3     0x08000000
#define GRC_MISC_REGISTERS_GPIO_PORT0_FLOAT2     0x04000000
#define GRC_MISC_REGISTERS_GPIO_PORT0_FLOAT1     0x02000000
#define GRC_MISC_REGISTERS_GPIO_PORT0_FLOAT0     0x01000000

#define MISC_REGISTERS_GPIO_OUTPUT               1
#define MISC_REGISTERS_GPIO_INTPUT               0
#define MISC_REGISTERS_GPIO_HIGH                 1
#define MISC_REGISTERS_GPIO_LOW                  0
// Port 1 output enable pins are in bits 31-28
#define GRC_MISC_REGISTERS_GPIO_PORT1_OE3        0x80000000
#define GRC_MISC_REGISTERS_GPIO_PORT1_OE2        0x40000000
#define GRC_MISC_REGISTERS_GPIO_PORT1_OE1        0x20000000
#define GRC_MISC_REGISTERS_GPIO_PORT1_OE0        0x10000000
// Port 0 output enable pins are in bits 27-24
#define GRC_MISC_REGISTERS_GPIO_PORT0_OE3        0x08000000
#define GRC_MISC_REGISTERS_GPIO_PORT0_OE2        0x04000000
#define GRC_MISC_REGISTERS_GPIO_PORT0_OE1        0x02000000
#define GRC_MISC_REGISTERS_GPIO_PORT0_OE0        0x01000000
// Port 1 CLR pins are in bits 23-20
#define GRC_MISC_REGISTERS_GPIO_PORT1_CLR3       0x00800000
#define GRC_MISC_REGISTERS_GPIO_PORT1_CLR2       0x00400000
#define GRC_MISC_REGISTERS_GPIO_PORT1_CLR1       0x00200000
#define GRC_MISC_REGISTERS_GPIO_PORT1_CLR0       0x00100000
// Port 0 CLR pins are in bits 19-16
#define GRC_MISC_REGISTERS_GPIO_PORT0_CLR3       0x00080000
#define GRC_MISC_REGISTERS_GPIO_PORT0_CLR2       0x00040000
#define GRC_MISC_REGISTERS_GPIO_PORT0_CLR1       0x00020000
#define GRC_MISC_REGISTERS_GPIO_PORT0_CLR0       0x00010000
// Port 1 SET pins are in bits 15-12
#define GRC_MISC_REGISTERS_GPIO_PORT1_SET3       0x00008000
#define GRC_MISC_REGISTERS_GPIO_PORT1_SET2       0x00004000
#define GRC_MISC_REGISTERS_GPIO_PORT1_SET1       0x00002000
#define GRC_MISC_REGISTERS_GPIO_PORT1_SET0       0x00001000
// Port 0 SET pins are in bits 11-8
#define GRC_MISC_REGISTERS_GPIO_PORT0_SET3       0x00000800
#define GRC_MISC_REGISTERS_GPIO_PORT0_SET2       0x00000400
#define GRC_MISC_REGISTERS_GPIO_PORT0_SET1       0x00000200
#define GRC_MISC_REGISTERS_GPIO_PORT0_SET0       0x00000100
// Port 1 pin values are in bits 7-4
#define GRC_MISC_REGISTERS_GPIO_PORT1_VAL3       0x00000080
#define GRC_MISC_REGISTERS_GPIO_PORT1_VAL2       0x00000040
#define GRC_MISC_REGISTERS_GPIO_PORT1_VAL1       0x00000020
#define GRC_MISC_REGISTERS_GPIO_PORT1_VAL0       0x00000010
// Port 0 pin values are in bits 3-0
#define GRC_MISC_REGISTERS_GPIO_PORT0_VAL3       0x00000008
#define GRC_MISC_REGISTERS_GPIO_PORT0_VAL2       0x00000004
#define GRC_MISC_REGISTERS_GPIO_PORT0_VAL1       0x00000002
#define GRC_MISC_REGISTERS_GPIO_PORT0_VAL0       0x00000001

// Definitions for SPIO
#define MISC_SPIO_OUTPUT_LOW           0
#define MISC_SPIO_OUTPUT_HIGH          1
#define MISC_SPIO_INPUT_HI_Z           2

#define MISC_SPIO_VALUE                (0xffL<<0)
#define MISC_SPIO_VALUE_POS            0
#define MISC_SPIO_SET                  (0xffL<<8)
#define MISC_SPIO_SET_POS              8
#define MISC_SPIO_CLR                  (0xffL<<16)
#define MISC_SPIO_CLR_POS              16
#define MISC_SPIO_FLOAT                (0xffL<<24)
#define MISC_SPIO_FLOAT_POS            24

#define MISC_SPIO_INT_INT_STATE_POS    0
#define MISC_SPIO_INT_OLD_VALUE_POS    8
#define MISC_SPIO_INT_OLD_SET_POS      16
#define MISC_SPIO_INT_OLD_CLR_POS      24

// SPIO pin assignment
#define MISC_SPIO_EN_VAUX_L            0x01   // SPIO 0
#define MISC_SPIO_DIS_VAUX_L           0x02   // SPIO 1
#define MISC_SPIO_SEL_VAUX_L           0x04   // SPIO 2 Control to power switching logic
#define MISC_SPIO_PORT_SWAP            0x08   // SPIO 3
#define MISC_SPIO_SPIO4                0x10   // SPIO 4 (MFW_SELECT)
#define MISC_SPIO_SPIO5                0x20   // SPIO 5 ==> Output (SMALERT)
#define MISC_SPIO_UMP_ADDR0            0x40   // SPIO 6 <== Input Bit 0 of UMP device ID select
#define MISC_SPIO_UMP_ADDR1            0x80   // SPIO 7 <== Input Bit 1 of UMP device ID select

// Gpio int
#define MISC_REGISTERS_GPIO_INT_OUTPUT_CLR       0
#define MISC_REGISTERS_GPIO_INT_OUTPUT_SET       1

#define MISC_REGISTERS_GPIO_INT_INT_STATUS_MASK  (0xffL<<0)
#define MISC_REGISTERS_GPIO_INT_INT_STATUS_POS   0
#define MISC_REGISTERS_GPIO_INT_OLD_VAL_MASK     (0xffL<<8)
#define MISC_REGISTERS_GPIO_INT_OLD_VAL_POS      8
#define MISC_REGISTERS_GPIO_INT_SET_MASK         (0xffL<<16)
#define MISC_REGISTERS_GPIO_INT_SET_POS          16
#define MISC_REGISTERS_GPIO_INT_CLR_MASK         (0xffL<<24)
#define MISC_REGISTERS_GPIO_INT_CLR_POS          24

// [31-28] OLD_CLR port1, [27-24] OLD_CLR port0: Writing a '1' to
// these bits clears the corresponding bit in the OLD_VALUE
// register. This will acknowledge an interrupt on the falling edge of
// corresponding GPIO input (reset value 0).
// [31-28] OLD_CLR port1
#define GRC_MISC_REGISTERS_GPIO_INT_PORT1_CLR3        0x80000000
#define GRC_MISC_REGISTERS_GPIO_INT_PORT1_CLR2        0x40000000
#define GRC_MISC_REGISTERS_GPIO_INT_PORT1_CLR1        0x20000000
#define GRC_MISC_REGISTERS_GPIO_INT_PORT1_CLR0        0x10000000
// [27-24] OLD_CLR port0
#define GRC_MISC_REGISTERS_GPIO_INT_PORT0_CLR3        0x08000000
#define GRC_MISC_REGISTERS_GPIO_INT_PORT0_CLR2        0x04000000
#define GRC_MISC_REGISTERS_GPIO_INT_PORT0_CLR1        0x02000000
#define GRC_MISC_REGISTERS_GPIO_INT_PORT0_CLR0        0x01000000

//[23-20] OLD_SET port1, [19-16] OLD_SET port0: Writing a '1' to
//these bit sets the corresponding bit in the OLD_VALUE register.
//This will acknowledge an interrupt on the rising edge of
//corresponding GPIO input (reset value 0).
// [23-20] OLD_SET port1
#define GRC_MISC_REGISTERS_GPIO_INT_PORT1_SET3        0x00800000
#define GRC_MISC_REGISTERS_GPIO_INT_PORT1_SET2        0x00400000
#define GRC_MISC_REGISTERS_GPIO_INT_PORT1_SET1        0x00200000
#define GRC_MISC_REGISTERS_GPIO_INT_PORT1_SET0        0x00100000
// [19-16] OLD_SET port0
#define GRC_MISC_REGISTERS_GPIO_INT_PORT0_SET3        0x00080000
#define GRC_MISC_REGISTERS_GPIO_INT_PORT0_SET2        0x00040000
#define GRC_MISC_REGISTERS_GPIO_INT_PORT0_SET1        0x00020000
#define GRC_MISC_REGISTERS_GPIO_INT_PORT0_SET0        0x00010000

//[15-12] OLD_VALUE port1, [11-8] OLD_VALUE port0 (RO field):
//These bits indicate the old value of the GPIO input value. When the
//INT_STATE bit is set; this bit indicates the OLD value of the pin
//such that if INT_STATE is set and this bit is '0'; then the interrupt is
//due to a low to high edge. If INT_STATE is set and this bit is '1';
//then the interrupt is due to a high to low edge (reset value 0xX).

// [15-12] OLD_VALUE port1
#define GRC_MISC_REGISTERS_GPIO_INT_PORT1_OLD_VAL3    0x00008000
#define GRC_MISC_REGISTERS_GPIO_INT_PORT1_OLD_VAL2    0x00004000
#define GRC_MISC_REGISTERS_GPIO_INT_PORT1_OLD_VAL1    0x00002000
#define GRC_MISC_REGISTERS_GPIO_INT_PORT1_OLD_VAL0    0x00001000
// [11-8] OLD_VALUE port0
#define GRC_MISC_REGISTERS_GPIO_INT_PORT0_OLD_VAL3    0x00000800
#define GRC_MISC_REGISTERS_GPIO_INT_PORT0_OLD_VAL2    0x00000400
#define GRC_MISC_REGISTERS_GPIO_INT_PORT0_OLD_VAL1    0x00000200
#define GRC_MISC_REGISTERS_GPIO_INT_PORT0_OLD_VAL0    0x00000100

//[7-4] INT_STATE port1, [3-0] INT_STATE port0 (RO field): These
//bits indicate the current GPIO interrupt state for each GPIO pin.
//This bit is cleared when the appropriate OLD_SET or OLD_CLR
//command bit is written. This bit is set when the GPIO input does
//not match the current value in OLD_VALUE (reset value 0xX).
// [7-4] INT_STATE port1
#define GRC_MISC_REGISTERS_GPIO_INT_PORT1_INT_STATE3  0x00000080
#define GRC_MISC_REGISTERS_GPIO_INT_PORT1_INT_STATE2  0x00000040
#define GRC_MISC_REGISTERS_GPIO_INT_PORT1_INT_STATE1  0x00000020
#define GRC_MISC_REGISTERS_GPIO_INT_PORT1_INT_STATE0  0x00000010
// [3-0] INT_STATE port0
#define GRC_MISC_REGISTERS_GPIO_INT_PORT0_INT_STATE3  0x00000008
#define GRC_MISC_REGISTERS_GPIO_INT_PORT0_INT_STATE2  0x00000004
#define GRC_MISC_REGISTERS_GPIO_INT_PORT0_INT_STATE1  0x00000002
#define GRC_MISC_REGISTERS_GPIO_INT_PORT0_INT_STATE0  0x00000001

// EPIO
// E3 Pins      Type    SFP+ I/F Pins   Notes
// P0_SIG_DET   I       P0_RX_LOS       Port 0 receiver loss detection
// EPIO_16      I       P0_MOD_ABS      Port 0 module absent
// EPIO_17      I       P0_TX_FAULT     Port 0 transmission fault
// EPIO_18      O       P0_TX_DIS       Port 0 transmitter laser disable
// P1_SIG_DET   I       P1_RX_LOS       Port 1 receiver loss detection
// EPIO_19      I       P1_MOD_ABS      Port 1 module absent
// EPIO_20      I       P1_TX_FAULT     Port 1 transmission fault
// EPIO_21      O       P1_TX_DIS       Port 1 transmitter laser disable
// P2_SIG_DET   I       P2_RX_LOS       Port 2 receiver loss detection
// EPIO_22      I       P2_MOD_ABS      Port 2 module absent
// EPIO_23      I       P2_TX_FAULT     Port 2 transmission fault
// EPIO_24      O       P2_TX_DIS       Port 2 transmitter laser disable
// P3_SIG_DET   I       P3_RX_LOS       Port 3 receiver loss detection
// EPIO_25      I       P3_MOD_ABS      Port 3 module absent
// EPIO_26      I       P3_TX_FAULT     Port 3 transmission fault
// EPIO_27      O       P3_TX_DIS       Port 3 transmitter laser disable
// EPIO_28      O       BSC_SEL_0       BSC port select 0
// EPIO_29      O       BSC_SEL_1       BSC port select 1
// BSC_SCL      I/O     BSC_SCL BSC     clock
// BSC_SDA      I/O     BSC_SDA BSC     data

/////////////////////////
// HW Lock Definitions //
/////////////////////////

// Masters
#define HW_LOCK_MASTER_FUNC_0                    0
#define HW_LOCK_MASTER_FUNC_1                    1
#define HW_LOCK_MASTER_FUNC_2                    2
#define HW_LOCK_MASTER_FUNC_3                    3
#define HW_LOCK_MASTER_FUNC_4                    4
#define HW_LOCK_MASTER_FUNC_5                    5
#define HW_LOCK_MASTER_FUNC_6                    6
#define HW_LOCK_MASTER_FUNC_7                    7
#define HW_LOCK_MASTER_RESERVED_8                8
#define HW_LOCK_MASTER_RESERVED_9                9
#define HW_LOCK_MASTER_RESERVED_10               10
#define HW_LOCK_MASTER_RESERVED_11               11
#define HW_LOCK_MASTER_RESERVED_12               12
#define HW_LOCK_MASTER_HOST_SCRIPTS              13
#define HW_LOCK_MASTER_MCP_RESET                 14
#define HW_LOCK_MASTER_MCP                       15

// Resources
#define HW_LOCK_RESOURCE_MDIO                    0
#define HW_LOCK_RESOURCE_GPIO                    1
#define HW_LOCK_RESOURCE_SPIO                    2
#define HW_LOCK_RESOURCE_PORT0_ATT_MASK          3
#define HW_LOCK_RESOURCE_PORT1_ATT_MASK          4
#define HW_LOCK_RESOURCE_RESET                   5
#define HW_LOCK_RESOURCE_PORT0_DMAE_COPY_CMD     6
#define HW_LOCK_RESOURCE_PORT1_DMAE_COPY_CMD     7
#define HW_LOCK_RESOURCE_RECOVERY_LEADER_0       8
#define HW_LOCK_RESOURCE_RECOVERY_LEADER_1       9
#define HW_LOCK_RESOURCE_DRV_FLAGS               10
#define HW_LOCK_RESOURCE_RECOVERY_REG            11
#define HW_LOCK_RESOURCE_NVRAM                   12
#define HW_LOCK_RESOURCE_DCBX_ADMIN_MIB          13
#define HW_LOCK_RESOURCE_SMBUS                   14
#define HW_LOCK_RESOURCE_RESERVED_15             15
#define HW_LOCK_RESOURCE_RESERVED_16             16
#define HW_LOCK_RESOURCE_RESERVED_17             17
#define HW_LOCK_RESOURCE_RESERVED_18             18
#define HW_LOCK_RESOURCE_RESERVED_19             19
#define HW_LOCK_RESOURCE_RESERVED_20             20
#define HW_LOCK_RESOURCE_RESERVED_21             21
#define HW_LOCK_RESOURCE_RESERVED_22             22
#define HW_LOCK_RESOURCE_RESERVED_23             23
#define HW_LOCK_RESOURCE_RESERVED_24             24
#define HW_LOCK_RESOURCE_RESERVED_25             25
#define HW_LOCK_RESOURCE_RESERVED_26             26
#define HW_LOCK_RESOURCE_OEM_0                   27
#define HW_LOCK_RESOURCE_OEM_1                   28
#define HW_LOCK_RESOURCE_OEM_2                   29
#define HW_LOCK_RESOURCE_OEM_3                   30
#define HW_LOCK_RESOURCE_OEM_4                   31
#define HW_LOCK_MAX_RESOURCE_VALUE               31
