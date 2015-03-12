
/* offset of configuration space in the pci core register */
#define PCICFG_OFFSET					0x2000
#define PCICFG_VENDOR_ID_OFFSET				0x00
#define PCICFG_DEVICE_ID_OFFSET				0x02
#define PCICFG_COMMAND_OFFSET				0x04
#define PCICFG_COMMAND_IO_SPACE			(1<<0)
#define PCICFG_COMMAND_MEM_SPACE		(1<<1)
#define PCICFG_COMMAND_BUS_MASTER		(1<<2)
#define PCICFG_COMMAND_SPECIAL_CYCLES		(1<<3)
#define PCICFG_COMMAND_MWI_CYCLES		(1<<4)
#define PCICFG_COMMAND_VGA_SNOOP		(1<<5)
#define PCICFG_COMMAND_PERR_ENA			(1<<6)
#define PCICFG_COMMAND_STEPPING			(1<<7)
#define PCICFG_COMMAND_SERR_ENA			(1<<8)
#define PCICFG_COMMAND_FAST_B2B			(1<<9)
#define PCICFG_COMMAND_INT_DISABLE		(1<<10)
#define PCICFG_COMMAND_RESERVED			(0x1f<<11)
#define PCICFG_STATUS_OFFSET				0x06
#define PCICFG_REVISION_ID_OFFSET			0x08
#define PCICFG_REVESION_ID_MASK			0xff
#define PCICFG_REVESION_ID_ERROR_VAL		0xff
#define PCICFG_CACHE_LINE_SIZE				0x0c
#define PCICFG_LATENCY_TIMER				0x0d
#define PCICFG_HEADER_TYPE  				0x0e
#define PCICFG_HEADER_TYPE_NORMAL          0
#define PCICFG_HEADER_TYPE_BRIDGE          1
#define PCICFG_HEADER_TYPE_CARDBUS         2
#define PCICFG_BAR_1_LOW				0x10
#define PCICFG_BAR_1_HIGH				0x14
#define PCICFG_BAR_2_LOW				0x18
#define PCICFG_BAR_2_HIGH				0x1c
#define PCICFG_BAR_3_LOW				0x20
#define PCICFG_BAR_3_HIGH				0x24
#define PCICFG_SUBSYSTEM_VENDOR_ID_OFFSET		0x2c
#define PCICFG_SUBSYSTEM_ID_OFFSET			0x2e
#define PCICFG_INT_LINE					0x3c
#define PCICFG_INT_PIN					0x3d
#define PCICFG_PM_CAPABILITY				0x48
#define PCICFG_PM_CAPABILITY_VERSION		(0x3<<16)
#define PCICFG_PM_CAPABILITY_CLOCK		(1<<19)
#define PCICFG_PM_CAPABILITY_RESERVED		(1<<20)
#define PCICFG_PM_CAPABILITY_DSI		(1<<21)
#define PCICFG_PM_CAPABILITY_AUX_CURRENT	(0x7<<22)
#define PCICFG_PM_CAPABILITY_D1_SUPPORT		(1<<25)
#define PCICFG_PM_CAPABILITY_D2_SUPPORT		(1<<26)
#define PCICFG_PM_CAPABILITY_PME_IN_D0		(1<<27)
#define PCICFG_PM_CAPABILITY_PME_IN_D1		(1<<28)
#define PCICFG_PM_CAPABILITY_PME_IN_D2		(1<<29)
#define PCICFG_PM_CAPABILITY_PME_IN_D3_HOT	(1<<30)
#define PCICFG_PM_CAPABILITY_PME_IN_D3_COLD	(1<<31)
#define PCICFG_PM_CSR_OFFSET				0x4c
#define PCICFG_PM_CSR_STATE			(0x3<<0)
#define PCICFG_PM_CSR_PME_ENABLE		(1<<8)
#define PCICFG_PM_CSR_PME_STATUS		(1<<15)
#define PCICFG_VPD_FLAG_ADDR_OFFSET			0x50
#define PCICFG_VPD_DATA_OFFSET				0x54
#define PCICFG_MSI_CAP_ID_OFFSET			0x58
#define PCICFG_MSI_CONTROL_ENABLE		(0x1<<16)
#define PCICFG_MSI_CONTROL_MCAP			(0x7<<17)
#define PCICFG_MSI_CONTROL_MENA			(0x7<<20)
#define PCICFG_MSI_CONTROL_64_BIT_ADDR_CAP	(0x1<<23)
#define PCICFG_MSI_CONTROL_MSI_PVMASK_CAPABLE	(0x1<<24)
#define PCICFG_MSI_ADDR_LOW_OFFSET			0x5c
#define PCICFG_MSI_ADDR_HIGH_OFFSET			0x60
#define PCICFG_MSI_DATA_OFFSET				0x64
#define PCICFG_GRC_ADDRESS				0x78
#define PCICFG_GRC_DATA					0x80
#define PCICFG_ME_REGISTER                  0x98
#define PCICFG_MSIX_CAP_ID_OFFSET			0xa0
#define PCICFG_MSIX_CONTROL_TABLE_SIZE		(0x7ff<<16)
#define PCICFG_MSIX_CONTROL_RESERVED		(0x7<<27)
#define PCICFG_MSIX_CONTROL_FUNC_MASK		(0x1<<30)
#define PCICFG_MSIX_CONTROL_MSIX_ENABLE		(0x1<<31)

#define PCICFG_DEVICE_CONTROL				0xb4
#define PCICFG_DEVICE_CONTROL_NP_TRANSACTION_PEND   (1<<21)
#define PCICFG_DEVICE_STATUS				0xb6
#define PCICFG_DEVICE_STATUS_CORR_ERR_DET	(1<<0)
#define PCICFG_DEVICE_STATUS_NON_FATAL_ERR_DET	(1<<1)
#define PCICFG_DEVICE_STATUS_FATAL_ERR_DET	(1<<2)
#define PCICFG_DEVICE_STATUS_UNSUP_REQ_DET	(1<<3)
#define PCICFG_DEVICE_STATUS_AUX_PWR_DET	(1<<4)
#define PCICFG_DEVICE_STATUS_NO_PEND		(1<<5)
#define PCICFG_LINK_CONTROL				0xbc


/* config_2 offset */
#define GRC_CONFIG_2_SIZE_REG				0x408
#define PCI_CONFIG_2_BAR1_SIZE			(0xfL<<0)
#define PCI_CONFIG_2_BAR1_SIZE_DISABLED		(0L<<0)
#define PCI_CONFIG_2_BAR1_SIZE_64K		(1L<<0)
#define PCI_CONFIG_2_BAR1_SIZE_128K		(2L<<0)
#define PCI_CONFIG_2_BAR1_SIZE_256K		(3L<<0)
#define PCI_CONFIG_2_BAR1_SIZE_512K		(4L<<0)
#define PCI_CONFIG_2_BAR1_SIZE_1M		(5L<<0)
#define PCI_CONFIG_2_BAR1_SIZE_2M		(6L<<0)
#define PCI_CONFIG_2_BAR1_SIZE_4M		(7L<<0)
#define PCI_CONFIG_2_BAR1_SIZE_8M		(8L<<0)
#define PCI_CONFIG_2_BAR1_SIZE_16M		(9L<<0)
#define PCI_CONFIG_2_BAR1_SIZE_32M		(10L<<0)
#define PCI_CONFIG_2_BAR1_SIZE_64M		(11L<<0)
#define PCI_CONFIG_2_BAR1_SIZE_128M		(12L<<0)
#define PCI_CONFIG_2_BAR1_SIZE_256M		(13L<<0)
#define PCI_CONFIG_2_BAR1_SIZE_512M		(14L<<0)
#define PCI_CONFIG_2_BAR1_SIZE_1G		(15L<<0)
#define PCI_CONFIG_2_BAR1_64ENA			(1L<<4)
#define PCI_CONFIG_2_EXP_ROM_RETRY		(1L<<5)
#define PCI_CONFIG_2_CFG_CYCLE_RETRY		(1L<<6)
#define PCI_CONFIG_2_FIRST_CFG_DONE		(1L<<7)
#define PCI_CONFIG_2_EXP_ROM_SIZE		(0xffL<<8)
#define PCI_CONFIG_2_EXP_ROM_SIZE_DISABLED	(0L<<8)
#define PCI_CONFIG_2_EXP_ROM_SIZE_2K		(1L<<8)
#define PCI_CONFIG_2_EXP_ROM_SIZE_4K		(2L<<8)
#define PCI_CONFIG_2_EXP_ROM_SIZE_8K		(3L<<8)
#define PCI_CONFIG_2_EXP_ROM_SIZE_16K		(4L<<8)
#define PCI_CONFIG_2_EXP_ROM_SIZE_32K		(5L<<8)
#define PCI_CONFIG_2_EXP_ROM_SIZE_64K		(6L<<8)
#define PCI_CONFIG_2_EXP_ROM_SIZE_128K		(7L<<8)
#define PCI_CONFIG_2_EXP_ROM_SIZE_256K		(8L<<8)
#define PCI_CONFIG_2_EXP_ROM_SIZE_512K		(9L<<8)
#define PCI_CONFIG_2_EXP_ROM_SIZE_1M		(10L<<8)
#define PCI_CONFIG_2_EXP_ROM_SIZE_2M		(11L<<8)
#define PCI_CONFIG_2_EXP_ROM_SIZE_4M		(12L<<8)
#define PCI_CONFIG_2_EXP_ROM_SIZE_8M		(13L<<8)
#define PCI_CONFIG_2_EXP_ROM_SIZE_16M		(14L<<8)
#define PCI_CONFIG_2_EXP_ROM_SIZE_32M		(15L<<8)
#define PCI_CONFIG_2_BAR_PREFETCH		(1L<<16)
#define PCI_CONFIG_2_RESERVED0			(0x7fffL<<17)

/* config_3 offset */
#define GRC_CONFIG_3_SIZE_REG				0x40c
#define PCI_CONFIG_3_STICKY_BYTE			(0xffL<<0)
#define PCI_CONFIG_3_FORCE_PME			(1L<<24)
#define PCI_CONFIG_3_PME_STATUS			(1L<<25)
#define PCI_CONFIG_3_PME_ENABLE			(1L<<26)
#define PCI_CONFIG_3_PM_STATE			(0x3L<<27)
#define PCI_CONFIG_3_VAUX_PRESET			(1L<<30)
#define PCI_CONFIG_3_PCI_POWER			(1L<<31)

#define GRC_REG_DEVICE_CONTROL              0x4d8
#define PCIE_SRIOV_DISABLE_IN_PROGRESS      (1 << 29) /*When VF Enable is cleared(after it was previously set),
                                                        this register will read a value of 1, indicating that all the
                                                        VFs that belong to this PF should be flushed.
                                                        Software should clear this bit within 1 second of VF Enable
                                                        being set by writing a 1 to it, so that VFs are visible to the system again.
                                                        WC */
#define PCIE_FLR_IN_PROGRESS                (1 << 27) /*When FLR is initiated, this register will read a value of 1 indicating that the
                                                        Function is in FLR state. Func can be brought out of FLR state either by
                                                        writing 1 to this register (at least 50 ms after FLR was initiated),
                                                        or it can also be cleared automatically after 55 ms if auto_clear bit
                                                        in private reg space is set. This bit also exists in VF register space
                                                        WC */

#define GRC_BAR2_CONFIG					0x4e0
#define PCI_CONFIG_2_BAR2_SIZE			(0xfL<<0)
#define PCI_CONFIG_2_BAR2_SIZE_DISABLED		(0L<<0)
#define PCI_CONFIG_2_BAR2_SIZE_64K		(1L<<0)
#define PCI_CONFIG_2_BAR2_SIZE_128K		(2L<<0)
#define PCI_CONFIG_2_BAR2_SIZE_256K		(3L<<0)
#define PCI_CONFIG_2_BAR2_SIZE_512K		(4L<<0)
#define PCI_CONFIG_2_BAR2_SIZE_1M		(5L<<0)
#define PCI_CONFIG_2_BAR2_SIZE_2M		(6L<<0)
#define PCI_CONFIG_2_BAR2_SIZE_4M		(7L<<0)
#define PCI_CONFIG_2_BAR2_SIZE_8M		(8L<<0)
#define PCI_CONFIG_2_BAR2_SIZE_16M		(9L<<0)
#define PCI_CONFIG_2_BAR2_SIZE_32M		(10L<<0)
#define PCI_CONFIG_2_BAR2_SIZE_64M		(11L<<0)
#define PCI_CONFIG_2_BAR2_SIZE_128M		(12L<<0)
#define PCI_CONFIG_2_BAR2_SIZE_256M		(13L<<0)
#define PCI_CONFIG_2_BAR2_SIZE_512M		(14L<<0)
#define PCI_CONFIG_2_BAR2_SIZE_1G		(15L<<0)
#define PCI_CONFIG_2_BAR2_64ENA			(1L<<4)

#define GRC_BAR3_CONFIG					0x4f4
#define PCI_CONFIG_2_BAR3_SIZE			(0xfL<<0)
#define PCI_CONFIG_2_BAR3_SIZE_DISABLED		(0L<<0)
#define PCI_CONFIG_2_BAR3_SIZE_64K		(1L<<0)
#define PCI_CONFIG_2_BAR3_SIZE_128K		(2L<<0)
#define PCI_CONFIG_2_BAR3_SIZE_256K		(3L<<0)
#define PCI_CONFIG_2_BAR3_SIZE_512K		(4L<<0)
#define PCI_CONFIG_2_BAR3_SIZE_1M		(5L<<0)
#define PCI_CONFIG_2_BAR3_SIZE_2M		(6L<<0)
#define PCI_CONFIG_2_BAR3_SIZE_4M		(7L<<0)
#define PCI_CONFIG_2_BAR3_SIZE_8M		(8L<<0)
#define PCI_CONFIG_2_BAR3_SIZE_16M		(9L<<0)
#define PCI_CONFIG_2_BAR3_SIZE_32M		(10L<<0)
#define PCI_CONFIG_2_BAR3_SIZE_64M		(11L<<0)
#define PCI_CONFIG_2_BAR3_SIZE_128M		(12L<<0)
#define PCI_CONFIG_2_BAR3_SIZE_256M		(13L<<0)
#define PCI_CONFIG_2_BAR3_SIZE_512M		(14L<<0)
#define PCI_CONFIG_2_BAR3_SIZE_1G		(15L<<0)
#define PCI_CONFIG_2_BAR3_64ENA			(1L<<4)

#define PCI_PM_DATA_A					0x410
#define PCI_PM_DATA_B					0x414
#define PCI_ID_VAL1					0x434
#define PCI_ID_VAL2					0x438
#define PCI_ID_VAL3					0x43c
#define PCI_ID_VAL3_REVISION_ID_ERROR             (0xffL<<24)


#define GRC_CONFIG_REG_VF_BAR_REG_1             0x608
#define GRC_CONFIG_REG_VF_BAR_REG_BAR0_SIZE     0xf

#define GRC_CONFIG_REG_VF_MSIX_CONTROL              0x61C
#define GRC_CR_VF_MSIX_CTRL_VF_MSIX_TBL_SIZE_MASK   0x3F  /*This field resides in VF only and does not exist in PF.
                                                            This register controls the read value of the MSIX_CONTROL[10:0] register
                                                            in the VF configuration space. A value of "00000000011" indicates
                                                            a table size of 4. The value is controlled by IOV_MSIX_TBL_SIZ
                                                            define in version.v */

#define GRC_CONFIG_REG_PF_INIT_VF               0x624
#define GRC_CR_PF_INIT_VF_PF_FIRST_VF_NUM_MASK  0xf /*First VF_NUM for PF is encoded in this register.
                                                    The number of VFs assigned to a PF is assumed to be a multiple of 8.
                                                    Software should program these bits based on Total Number of VFs programmed for each PF.
                                                    Since registers from 0x000-0x7ff are spilt across functions, each PF will have
                                                    the same location for the same 4 bits*/

#define PXPCS_TL_CONTROL_5                      0x814
#define PXPCS_TL_CONTROL_5_UNKNOWNTYPE_ERR_ATTN    (1 << 29) /*WC*/
#define PXPCS_TL_CONTROL_5_BOUNDARY4K_ERR_ATTN     (1 << 28)   /*WC*/
#define PXPCS_TL_CONTROL_5_MRRS_ERR_ATTN   (1 << 27)   /*WC*/
#define PXPCS_TL_CONTROL_5_MPS_ERR_ATTN    (1 << 26)   /*WC*/
#define PXPCS_TL_CONTROL_5_TTX_BRIDGE_FORWARD_ERR  (1 << 25)   /*WC*/
#define PXPCS_TL_CONTROL_5_TTX_TXINTF_OVERFLOW     (1 << 24)   /*WC*/
#define PXPCS_TL_CONTROL_5_PHY_ERR_ATTN    (1 << 23)   /*RO*/
#define PXPCS_TL_CONTROL_5_DL_ERR_ATTN     (1 << 22)   /*RO*/
#define PXPCS_TL_CONTROL_5_TTX_ERR_NP_TAG_IN_USE   (1 << 21)   /*WC*/
#define PXPCS_TL_CONTROL_5_TRX_ERR_UNEXP_RTAG  (1 << 20)   /*WC*/
#define PXPCS_TL_CONTROL_5_PRI_SIG_TARGET_ABORT1   (1 << 19)   /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_UNSPPORT1   (1 << 18)   /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_ECRC1   (1 << 17)   /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_MALF_TLP1   (1 << 16)   /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_RX_OFLOW1   (1 << 15)   /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_UNEXP_CPL1  (1 << 14)   /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_MASTER_ABRT1    (1 << 13)   /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_CPL_TIMEOUT1    (1 << 12)   /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_FC_PRTL1    (1 << 11)   /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_PSND_TLP1   (1 << 10)   /*WC*/
#define PXPCS_TL_CONTROL_5_PRI_SIG_TARGET_ABORT    (1 << 9)    /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_UNSPPORT    (1 << 8)    /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_ECRC    (1 << 7)    /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_MALF_TLP    (1 << 6)    /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_RX_OFLOW    (1 << 5)    /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_UNEXP_CPL   (1 << 4)    /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_MASTER_ABRT     (1 << 3)    /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_CPL_TIMEOUT     (1 << 2)    /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_FC_PRTL     (1 << 1)    /*WC*/
#define PXPCS_TL_CONTROL_5_ERR_PSND_TLP    (1 << 0)    /*WC*/





#define PXPCS_TL_FUNC345_STAT      0x854
#define PXPCS_TL_FUNC345_STAT_PRI_SIG_TARGET_ABORT4    (1 << 29)   /* WC */
#define PXPCS_TL_FUNC345_STAT_ERR_UNSPPORT4    (1 << 28)   /* Unsupported Request Error Status in function4, if set, generate pcie_err_attn output when this error is seen.  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_ECRC4    (1 << 27)   /* ECRC Error TLP Status Status in function 4, if set, generate pcie_err_attn output when this error is seen..  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_MALF_TLP4    (1 << 26)   /* Malformed TLP Status Status in function 4, if set, generate pcie_err_attn output when this error is seen..  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_RX_OFLOW4    (1 << 25)   /* Receiver Overflow Status Status in function 4, if set, generate pcie_err_attn output when this error is seen..  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_UNEXP_CPL4   (1 << 24)   /* Unexpected Completion Status Status in function 4, if set, generate pcie_err_attn output when this error is seen.  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_MASTER_ABRT4     (1 << 23)   /* Receive UR Statusin function 4. If set, generate pcie_err_attn output when this error is seen.  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_CPL_TIMEOUT4     (1 << 22)   /* Completer Timeout Status Status in function 4, if set, generate pcie_err_attn output when this error is seen.  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_FC_PRTL4     (1 << 21)   /* Flow Control Protocol Error Status Status in function 4, if set, generate pcie_err_attn output when this error is seen.  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_PSND_TLP4    (1 << 20)   /* Poisoned Error Status Status in function 4, if set, generate pcie_err_attn output when this error is seen..  WC */
#define PXPCS_TL_FUNC345_STAT_PRI_SIG_TARGET_ABORT3    (1 << 19)   /* WC */
#define PXPCS_TL_FUNC345_STAT_ERR_UNSPPORT3    (1 << 18)   /* Unsupported Request Error Status in function3, if set, generate pcie_err_attn output when this error is seen.  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_ECRC3    (1 << 17)   /* ECRC Error TLP Status Status in function 3, if set, generate pcie_err_attn output when this error is seen..  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_MALF_TLP3    (1 << 16)   /* Malformed TLP Status Status in function 3, if set, generate pcie_err_attn output when this error is seen..  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_RX_OFLOW3    (1 << 15)   /* Receiver Overflow Status Status in function 3, if set, generate pcie_err_attn output when this error is seen..  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_UNEXP_CPL3   (1 << 14)   /* Unexpected Completion Status Status in function 3, if set, generate pcie_err_attn output when this error is seen.  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_MASTER_ABRT3     (1 << 13)   /* Receive UR Statusin function 3. If set, generate pcie_err_attn output when this error is seen.  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_CPL_TIMEOUT3     (1 << 12)   /* Completer Timeout Status Status in function 3, if set, generate pcie_err_attn output when this error is seen.  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_FC_PRTL3     (1 << 11)   /* Flow Control Protocol Error Status Status in function 3, if set, generate pcie_err_attn output when this error is seen.  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_PSND_TLP3    (1 << 10)   /* Poisoned Error Status Status in function 3, if set, generate pcie_err_attn output when this error is seen..  WC */
#define PXPCS_TL_FUNC345_STAT_PRI_SIG_TARGET_ABORT2    (1 << 9)    /* WC */
#define PXPCS_TL_FUNC345_STAT_ERR_UNSPPORT2    (1 << 8)    /* Unsupported Request Error Status for Function 2, if set, generate pcie_err_attn output when this error is seen.  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_ECRC2    (1 << 7)    /* ECRC Error TLP Status Status for Function 2, if set, generate pcie_err_attn output when this error is seen..  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_MALF_TLP2    (1 << 6)    /* Malformed TLP Status Status for Function 2, if set, generate pcie_err_attn output when this error is seen..  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_RX_OFLOW2    (1 << 5)    /* Receiver Overflow Status Status for Function 2, if set, generate pcie_err_attn output when this error is seen..  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_UNEXP_CPL2   (1 << 4)    /* Unexpected Completion Status Status for Function 2, if set, generate pcie_err_attn output when this error is seen.  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_MASTER_ABRT2     (1 << 3)    /* Receive UR Statusfor Function 2. If set, generate pcie_err_attn output when this error is seen.  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_CPL_TIMEOUT2     (1 << 2)    /* Completer Timeout Status Status for Function 2, if set, generate pcie_err_attn output when this error is seen.  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_FC_PRTL2     (1 << 1)    /* Flow Control Protocol Error Status Status for Function 2, if set, generate pcie_err_attn output when this error is seen.  WC */
#define PXPCS_TL_FUNC345_STAT_ERR_PSND_TLP2    (1 << 0)    /* Poisoned Error Status Status for Function 2, if set, generate pcie_err_attn output when this error is seen..  WC */




#define PXPCS_TL_FUNC678_STAT  0x85C
#define PXPCS_TL_FUNC678_STAT_PRI_SIG_TARGET_ABORT7    (1 << 29)   /*    WC */
#define PXPCS_TL_FUNC678_STAT_ERR_UNSPPORT7    (1 << 28)   /* Unsupported Request Error Status in function7, if set, generate pcie_err_attn output when this error is seen. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_ECRC7    (1 << 27)   /* ECRC Error TLP Status Status in function 7, if set, generate pcie_err_attn output when this error is seen.. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_MALF_TLP7    (1 << 26)   /* Malformed TLP Status Status in function 7, if set, generate pcie_err_attn output when this error is seen.. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_RX_OFLOW7    (1 << 25)   /* Receiver Overflow Status Status in function 7, if set, generate pcie_err_attn output when this error is seen.. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_UNEXP_CPL7   (1 << 24)   /* Unexpected Completion Status Status in function 7, if set, generate pcie_err_attn output when this error is seen. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_MASTER_ABRT7     (1 << 23)   /* Receive UR Statusin function 7. If set, generate pcie_err_attn output when this error is seen. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_CPL_TIMEOUT7     (1 << 22)   /* Completer Timeout Status Status in function 7, if set, generate pcie_err_attn output when this error is seen. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_FC_PRTL7     (1 << 21)   /* Flow Control Protocol Error Status Status in function 7, if set, generate pcie_err_attn output when this error is seen. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_PSND_TLP7    (1 << 20)   /* Poisoned Error Status Status in function 7, if set, generate pcie_err_attn output when this error is seen.. WC */
#define PXPCS_TL_FUNC678_STAT_PRI_SIG_TARGET_ABORT6    (1 << 19)    /*    WC */
#define PXPCS_TL_FUNC678_STAT_ERR_UNSPPORT6    (1 << 18)   /* Unsupported Request Error Status in function6, if set, generate pcie_err_attn output when this error is seen. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_ECRC6    (1 << 17)   /* ECRC Error TLP Status Status in function 6, if set, generate pcie_err_attn output when this error is seen.. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_MALF_TLP6    (1 << 16)   /* Malformed TLP Status Status in function 6, if set, generate pcie_err_attn output when this error is seen.. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_RX_OFLOW6    (1 << 15)   /* Receiver Overflow Status Status in function 6, if set, generate pcie_err_attn output when this error is seen.. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_UNEXP_CPL6   (1 << 14)   /* Unexpected Completion Status Status in function 6, if set, generate pcie_err_attn output when this error is seen. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_MASTER_ABRT6     (1 << 13)   /* Receive UR Statusin function 6. If set, generate pcie_err_attn output when this error is seen. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_CPL_TIMEOUT6     (1 << 12)   /* Completer Timeout Status Status in function 6, if set, generate pcie_err_attn output when this error is seen. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_FC_PRTL6     (1 << 11)   /* Flow Control Protocol Error Status Status in function 6, if set, generate pcie_err_attn output when this error is seen. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_PSND_TLP6    (1 << 10)   /* Poisoned Error Status Status in function 6, if set, generate pcie_err_attn output when this error is seen.. WC */
#define PXPCS_TL_FUNC678_STAT_PRI_SIG_TARGET_ABORT5    (1 << 9) /*    WC */
#define PXPCS_TL_FUNC678_STAT_ERR_UNSPPORT5    (1 << 8)    /* Unsupported Request Error Status for Function 5, if set, generate pcie_err_attn output when this error is seen. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_ECRC5    (1 << 7)    /* ECRC Error TLP Status Status for Function 5, if set, generate pcie_err_attn output when this error is seen.. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_MALF_TLP5    (1 << 6)    /* Malformed TLP Status Status for Function 5, if set, generate pcie_err_attn output when this error is seen.. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_RX_OFLOW5    (1 << 5)    /* Receiver Overflow Status Status for Function 5, if set, generate pcie_err_attn output when this error is seen.. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_UNEXP_CPL5   (1 << 4)    /* Unexpected Completion Status Status for Function 5, if set, generate pcie_err_attn output when this error is seen. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_MASTER_ABRT5     (1 << 3)    /* Receive UR Statusfor Function 5. If set, generate pcie_err_attn output when this error is seen. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_CPL_TIMEOUT5     (1 << 2)    /* Completer Timeout Status Status for Function 5, if set, generate pcie_err_attn output when this error is seen. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_FC_PRTL5     (1 << 1)    /* Flow Control Protocol Error Status Status for Function 5, if set, generate pcie_err_attn output when this error is seen. WC */
#define PXPCS_TL_FUNC678_STAT_ERR_PSND_TLP5    (1 << 0)    /* Poisoned Error Status Status for Function 5, if set, generate pcie_err_attn output when this error is seen.. WC */



#define BAR_USTRORM_INTMEM				0x400000
#define BAR_CSTRORM_INTMEM				0x410000
#define BAR_XSTRORM_INTMEM				0x420000
#define BAR_TSTRORM_INTMEM				0x430000

/* for accessing the IGU in case of status block ACK */
#define BAR_IGU_INTMEM  				0x440000

#define BAR_DOORBELL_OFFSET     			0x800000

#define BAR_ME_REGISTER 				0x450000
#define ME_REG_PF_NUM_SHIFT             0
#define ME_REG_PF_NUM                   (7L<<ME_REG_PF_NUM_SHIFT) /* Relative PF Num */
#define ME_REG_VF_VALID                 (1<<8)
#define ME_REG_VF_NUM_SHIFT             9
#define ME_REG_VF_NUM_MASK              (0x3f<<ME_REG_VF_NUM_SHIFT)
#define ME_REG_VF_ERR			(0x1<<3)
#define ME_REG_ABS_PF_NUM_SHIFT         16
#define ME_REG_ABS_PF_NUM               (7L<<ME_REG_ABS_PF_NUM_SHIFT) /* Absolute PF Num */


// Everest Address Space Mapping - For Virtual Functions - Bar 0

#define PXP_VF_ADRR_NUM_QUEUES		136
#define PXP_ADDR_QUEUE_SIZE			32
#define PXP_ADDR_REG_SIZE			512


#define PXP_VF_ADDR_IGU_START		0
#define PXP_VF_ADDR_IGU_SIZE		(0x3000)
#define PXP_VF_ADDR_IGU_END			((PXP_VF_ADDR_IGU_START) + (PXP_VF_ADDR_IGU_SIZE) - 1)

#define PXP_VF_ADDR_USDM_QUEUES_START		0x3000
#define PXP_VF_ADDR_USDM_QUEUES_SIZE		(PXP_VF_ADRR_NUM_QUEUES * PXP_ADDR_QUEUE_SIZE)
#define PXP_VF_ADDR_USDM_QUEUES_END			((PXP_VF_ADDR_USDM_QUEUES_START) + (PXP_VF_ADDR_USDM_QUEUES_SIZE) - 1)

#define PXP_VF_ADDR_CSDM_QUEUES_START		0x4100
#define PXP_VF_ADDR_CSDM_QUEUES_SIZE		(PXP_VF_ADRR_NUM_QUEUES * PXP_ADDR_QUEUE_SIZE)
#define PXP_VF_ADDR_CSDM_QUEUES_END			((PXP_VF_ADDR_CSDM_QUEUES_START) + (PXP_VF_ADDR_CSDM_QUEUES_SIZE) - 1)

#define PXP_VF_ADDR_XSDM_QUEUES_START		0x5200
#define PXP_VF_ADDR_XSDM_QUEUES_SIZE		(PXP_VF_ADRR_NUM_QUEUES * PXP_ADDR_QUEUE_SIZE)
#define PXP_VF_ADDR_XSDM_QUEUES_END			((PXP_VF_ADDR_XSDM_QUEUES_START) + (PXP_VF_ADDR_XSDM_QUEUES_SIZE) - 1)

#define PXP_VF_ADDR_TSDM_QUEUES_START		0x6300
#define PXP_VF_ADDR_TSDM_QUEUES_SIZE		(PXP_VF_ADRR_NUM_QUEUES * PXP_ADDR_QUEUE_SIZE)
#define PXP_VF_ADDR_TSDM_QUEUES_END			((PXP_VF_ADDR_TSDM_QUEUES_START) + (PXP_VF_ADDR_TSDM_QUEUES_SIZE) - 1)

#define PXP_VF_ADDR_USDM_GLOBAL_START		0x7400
#define PXP_VF_ADDR_USDM_GLOBAL_SIZE		(PXP_ADDR_REG_SIZE)
#define PXP_VF_ADDR_USDM_GLOBAL_END			((PXP_VF_ADDR_USDM_GLOBAL_START) + (PXP_VF_ADDR_USDM_GLOBAL_SIZE) - 1)

#define PXP_VF_ADDR_CSDM_GLOBAL_START		0x7600
#define PXP_VF_ADDR_CSDM_GLOBAL_SIZE		(PXP_ADDR_REG_SIZE)
#define PXP_VF_ADDR_CSDM_GLOBAL_END			((PXP_VF_ADDR_CSDM_GLOBAL_START) + (PXP_VF_ADDR_CSDM_GLOBAL_SIZE) - 1)

#define PXP_VF_ADDR_XSDM_GLOBAL_START		0x7800
#define PXP_VF_ADDR_XSDM_GLOBAL_SIZE		(PXP_ADDR_REG_SIZE)
#define PXP_VF_ADDR_XSDM_GLOBAL_END			((PXP_VF_ADDR_XSDM_GLOBAL_START) + (PXP_VF_ADDR_XSDM_GLOBAL_SIZE) - 1)

#define PXP_VF_ADDR_TSDM_GLOBAL_START		0x7a00
#define PXP_VF_ADDR_TSDM_GLOBAL_SIZE		(PXP_ADDR_REG_SIZE)
#define PXP_VF_ADDR_TSDM_GLOBAL_END			((PXP_VF_ADDR_TSDM_GLOBAL_START) + (PXP_VF_ADDR_TSDM_GLOBAL_SIZE) - 1)

// DB in BAR1
#define PXP_VF_ADDR_DB_START				0x7c00
#define PXP_VF_ADDR_DB_SIZE					(0x200)
#define PXP_VF_ADDR_DB_END					((PXP_VF_ADDR_DB_START) + (PXP_VF_ADDR_DB_SIZE) - 1)

#define PXP_VF_ADDR_GRC_START				0x7e00
#define PXP_VF_ADDR_GRC_SIZE				(0x200)
#define PXP_VF_ADDR_GRC_END					((PXP_VF_ADDR_GRC_START) + (PXP_VF_ADDR_GRC_SIZE) - 1)

// DB in BAR2
#define PXP_VF_ADDR_DORQ_START				(0x0)
#define PXP_VF_ADDR_DORQ_SIZE				(0xffffffff)
#define PXP_VF_ADDR_DORQ_END				(0xffffffff)

// function numbers
#define PXP_BAR_GRC		0
#define PXP_BAR_TSDM	0
#define PXP_BAR_USDM	0
#define PXP_BAR_XSDM	0
#define PXP_BAR_CSDM	0
#define PXP_BAR_IGU		0
#define PXP_BAR_DQ		1

#define PXP_VF_BAR_IGU	0
#define PXP_VF_BAR_USDM_QUEUES	0
#define PXP_VF_BAR_TSDM_QUEUES	0
#define PXP_VF_BAR_XSDM_QUEUES	0
#define PXP_VF_BAR_CSDM_QUEUES	0
#define PXP_VF_BAR_USDM_GLOBAL	0
#define PXP_VF_BAR_TSDM_GLOBAL	0
#define PXP_VF_BAR_XSDM_GLOBAL	0
#define PXP_VF_BAR_CSDM_GLOBAL	0
#define PXP_VF_BAR_DB	0
#define PXP_VF_BAR_GRC	0
#define PXP_VF_BAR_DORQ	1

/* PCI CAPABILITIES*/

#define PCI_CAP_PCIE                            0x10    /*PCIe capability ID*/

#define PCIE_DEV_CAPS                           0x04
#ifndef PCIE_DEV_CAPS_FLR_CAPABILITY
    #define PCIE_DEV_CAPS_FLR_CAPABILITY        (1 << 28)
#endif

#define PCIE_DEV_CTRL                           0x08
#define PCIE_DEV_CTRL_FLR                               0x8000; 

#define PCIE_DEV_STATUS                         0x0A
#ifndef PCIE_DEV_STATUS_PENDING_TRANSACTION
    #define PCIE_DEV_STATUS_PENDING_TRANSACTION     (1 << 5)
#endif

#define PCI_CAP_MSIX                            0x11    /*MSI-X capability ID*/
#define PCI_MSIX_CONTROL_SHIFT                  16
#define PCI_MSIX_TABLE_SIZE_MASK                0x07FF
#define PCI_MSIX_TABLE_ENABLE_MASK              0x8000

#ifndef PCI_CAPABILITY_LIST
    #define PCI_CAPABILITY_LIST                     0x34    /* Ofset of first capability list entry*/
#endif
#ifndef PCI_CB_CAPABILITY_LIST
    #define PCI_CB_CAPABILITY_LIST                  0x14
#endif

#if (defined(__LINUX)) || (defined(PCI_CAP_LIST_ID))
#define PCI_CAP_LIST_ID_DEF
#endif
#if (defined(__LINUX)) || (defined(PCI_CAP_LIST_NEXT))
#define PCI_CAP_LIST_NEXT_DEF
#endif
#if (defined(__LINUX)) || (defined(PCI_STATUS))
#define PCI_STATUS_DEF
#endif
#if (defined(__LINUX)) || (defined(PCI_STATUS_CAP_LIST))
#define PCI_STATUS_CAP_LIST_DEF
#endif

#ifndef PCI_CAP_LIST_ID_DEF
    #define PCI_CAP_LIST_ID                         0x0     /* Capability ID */
#endif
#ifndef PCI_CAP_LIST_NEXT_DEF
    #define PCI_CAP_LIST_NEXT                       0x1     /* Next capability in the list */
#endif
#ifndef PCI_STATUS_DEF
    #define PCI_STATUS                              0x6     /* 16 bits */
#endif
#ifndef PCI_STATUS_CAP_LIST_DEF
    #define PCI_STATUS_CAP_LIST                     0x10    /* Support Capability List */
#endif
