#ifndef __devinfo_h__
#define __devinfo_h__

#include "mac_drv_info.h"

/****************************************************************************
 * Shared HW configuration                                                  *
 ****************************************************************************/
#define PIN_CFG_NA                          0x00000000
#define PIN_CFG_GPIO0_P0                    0x00000001
#define PIN_CFG_GPIO1_P0                    0x00000002
#define PIN_CFG_GPIO2_P0                    0x00000003
#define PIN_CFG_GPIO3_P0                    0x00000004
#define PIN_CFG_GPIO0_P1                    0x00000005
#define PIN_CFG_GPIO1_P1                    0x00000006
#define PIN_CFG_GPIO2_P1                    0x00000007
#define PIN_CFG_GPIO3_P1                    0x00000008
#define PIN_CFG_EPIO0                       0x00000009
#define PIN_CFG_EPIO1                       0x0000000a
#define PIN_CFG_EPIO2                       0x0000000b
#define PIN_CFG_EPIO3                       0x0000000c
#define PIN_CFG_EPIO4                       0x0000000d
#define PIN_CFG_EPIO5                       0x0000000e
#define PIN_CFG_EPIO6                       0x0000000f
#define PIN_CFG_EPIO7                       0x00000010
#define PIN_CFG_EPIO8                       0x00000011
#define PIN_CFG_EPIO9                       0x00000012
#define PIN_CFG_EPIO10                      0x00000013
#define PIN_CFG_EPIO11                      0x00000014
#define PIN_CFG_EPIO12                      0x00000015
#define PIN_CFG_EPIO13                      0x00000016
#define PIN_CFG_EPIO14                      0x00000017
#define PIN_CFG_EPIO15                      0x00000018
#define PIN_CFG_EPIO16                      0x00000019
#define PIN_CFG_EPIO17                      0x0000001a
#define PIN_CFG_EPIO18                      0x0000001b
#define PIN_CFG_EPIO19                      0x0000001c
#define PIN_CFG_EPIO20                      0x0000001d
#define PIN_CFG_EPIO21                      0x0000001e
#define PIN_CFG_EPIO22                      0x0000001f
#define PIN_CFG_EPIO23                      0x00000020
#define PIN_CFG_EPIO24                      0x00000021
#define PIN_CFG_EPIO25                      0x00000022
#define PIN_CFG_EPIO26                      0x00000023
#define PIN_CFG_EPIO27                      0x00000024
#define PIN_CFG_EPIO28                      0x00000025
#define PIN_CFG_EPIO29                      0x00000026
#define PIN_CFG_EPIO30                      0x00000027
#define PIN_CFG_EPIO31                      0x00000028

/* EPIO definition */
#define EPIO_CFG_NA                         0x00000000
#define EPIO_CFG_EPIO0                      0x00000001
#define EPIO_CFG_EPIO1                      0x00000002
#define EPIO_CFG_EPIO2                      0x00000003
#define EPIO_CFG_EPIO3                      0x00000004
#define EPIO_CFG_EPIO4                      0x00000005
#define EPIO_CFG_EPIO5                      0x00000006
#define EPIO_CFG_EPIO6                      0x00000007
#define EPIO_CFG_EPIO7                      0x00000008
#define EPIO_CFG_EPIO8                      0x00000009
#define EPIO_CFG_EPIO9                      0x0000000a
#define EPIO_CFG_EPIO10                     0x0000000b
#define EPIO_CFG_EPIO11                     0x0000000c
#define EPIO_CFG_EPIO12                     0x0000000d
#define EPIO_CFG_EPIO13                     0x0000000e
#define EPIO_CFG_EPIO14                     0x0000000f
#define EPIO_CFG_EPIO15                     0x00000010
#define EPIO_CFG_EPIO16                     0x00000011
#define EPIO_CFG_EPIO17                     0x00000012
#define EPIO_CFG_EPIO18                     0x00000013
#define EPIO_CFG_EPIO19                     0x00000014
#define EPIO_CFG_EPIO20                     0x00000015
#define EPIO_CFG_EPIO21                     0x00000016
#define EPIO_CFG_EPIO22                     0x00000017
#define EPIO_CFG_EPIO23                     0x00000018
#define EPIO_CFG_EPIO24                     0x00000019
#define EPIO_CFG_EPIO25                     0x0000001a
#define EPIO_CFG_EPIO26                     0x0000001b
#define EPIO_CFG_EPIO27                     0x0000001c
#define EPIO_CFG_EPIO28                     0x0000001d
#define EPIO_CFG_EPIO29                     0x0000001e
#define EPIO_CFG_EPIO30                     0x0000001f
#define EPIO_CFG_EPIO31                     0x00000020

struct mac_addr {
	u32 upper;
	u32 lower;
};



struct shared_hw_cfg {			 /* NVRAM Offset */
	/* Up to 16 bytes of NULL-terminated string */
	u8  part_num[16];		    /* 0x104 */

	u32 config;			/* 0x114 */
	#define SHARED_HW_CFG_MDIO_VOLTAGE_MASK             0x00000001
		#define SHARED_HW_CFG_MDIO_VOLTAGE_SHIFT             0
		#define SHARED_HW_CFG_MDIO_VOLTAGE_1_2V              0x00000000
		#define SHARED_HW_CFG_MDIO_VOLTAGE_2_5V              0x00000001

	#define SHARED_HW_CFG_PORT_SWAP                     0x00000004

	    #define SHARED_HW_CFG_BEACON_WOL_EN                  0x00000008

	    #define SHARED_HW_CFG_PCIE_GEN3_DISABLED            0x00000000
	    #define SHARED_HW_CFG_PCIE_GEN3_ENABLED             0x00000010

	#define SHARED_HW_CFG_MFW_SELECT_MASK               0x00000700
		#define SHARED_HW_CFG_MFW_SELECT_SHIFT               8
	/* Whatever MFW found in NVM
	   (if multiple found, priority order is: NC-SI, UMP, IPMI) */
		#define SHARED_HW_CFG_MFW_SELECT_DEFAULT             0x00000000
		#define SHARED_HW_CFG_MFW_SELECT_NC_SI               0x00000100
		#define SHARED_HW_CFG_MFW_SELECT_UMP                 0x00000200
		#define SHARED_HW_CFG_MFW_SELECT_IPMI                0x00000300
	/* Use SPIO4 as an arbiter between: 0-NC_SI, 1-IPMI
	  (can only be used when an add-in board, not BMC, pulls-down SPIO4) */
		#define SHARED_HW_CFG_MFW_SELECT_SPIO4_NC_SI_IPMI    0x00000400
	/* Use SPIO4 as an arbiter between: 0-UMP, 1-IPMI
	  (can only be used when an add-in board, not BMC, pulls-down SPIO4) */
		#define SHARED_HW_CFG_MFW_SELECT_SPIO4_UMP_IPMI      0x00000500
	/* Use SPIO4 as an arbiter between: 0-NC-SI, 1-UMP
	  (can only be used when an add-in board, not BMC, pulls-down SPIO4) */
		#define SHARED_HW_CFG_MFW_SELECT_SPIO4_NC_SI_UMP     0x00000600

	/* Adjust the PCIe G2 Tx amplitude driver for all Tx lanes. For
	   backwards compatibility, value of 0 is disabling this feature.
	    That means that though 0 is a valid value, it cannot be
	    configured. */
	#define SHARED_HW_CFG_G2_TX_DRIVE_MASK                        0x0000F000
	#define SHARED_HW_CFG_G2_TX_DRIVE_SHIFT                       12

	#define SHARED_HW_CFG_LED_MODE_MASK                 0x000F0000
		#define SHARED_HW_CFG_LED_MODE_SHIFT                 16
		#define SHARED_HW_CFG_LED_MAC1                       0x00000000
		#define SHARED_HW_CFG_LED_PHY1                       0x00010000
		#define SHARED_HW_CFG_LED_PHY2                       0x00020000
		#define SHARED_HW_CFG_LED_PHY3                       0x00030000
		#define SHARED_HW_CFG_LED_MAC2                       0x00040000
		#define SHARED_HW_CFG_LED_PHY4                       0x00050000
		#define SHARED_HW_CFG_LED_PHY5                       0x00060000
		#define SHARED_HW_CFG_LED_PHY6                       0x00070000
		#define SHARED_HW_CFG_LED_MAC3                       0x00080000
		#define SHARED_HW_CFG_LED_PHY7                       0x00090000
		#define SHARED_HW_CFG_LED_PHY9                       0x000a0000
		#define SHARED_HW_CFG_LED_PHY11                      0x000b0000
		#define SHARED_HW_CFG_LED_MAC4                       0x000c0000
		#define SHARED_HW_CFG_LED_PHY8                       0x000d0000
		#define SHARED_HW_CFG_LED_EXTPHY1                    0x000e0000
		#define SHARED_HW_CFG_LED_EXTPHY2                    0x000f0000

    #define SHARED_HW_CFG_SRIOV_MASK                    0x40000000
		#define SHARED_HW_CFG_SRIOV_DISABLED                 0x00000000
		#define SHARED_HW_CFG_SRIOV_ENABLED                  0x40000000

	#define SHARED_HW_CFG_ATC_MASK                      0x80000000
		#define SHARED_HW_CFG_ATC_DISABLED                   0x00000000
		#define SHARED_HW_CFG_ATC_ENABLED                    0x80000000

	u32 config2;			    /* 0x118 */

	#define SHARED_HW_CFG_PCIE_GEN2_MASK                0x00000100
	    #define SHARED_HW_CFG_PCIE_GEN2_SHIFT                8
	    #define SHARED_HW_CFG_PCIE_GEN2_DISABLED             0x00000000
	#define SHARED_HW_CFG_PCIE_GEN2_ENABLED              0x00000100

	#define SHARED_HW_CFG_SMBUS_TIMING_MASK             0x00001000
		#define SHARED_HW_CFG_SMBUS_TIMING_100KHZ            0x00000000
		#define SHARED_HW_CFG_SMBUS_TIMING_400KHZ            0x00001000

	#define SHARED_HW_CFG_HIDE_PORT1                    0x00002000



		/* Output low when PERST is asserted */
	#define SHARED_HW_CFG_SPIO4_FOLLOW_PERST_MASK       0x00008000
		#define SHARED_HW_CFG_SPIO4_FOLLOW_PERST_DISABLED    0x00000000
		#define SHARED_HW_CFG_SPIO4_FOLLOW_PERST_ENABLED     0x00008000

	#define SHARED_HW_CFG_PCIE_GEN2_PREEMPHASIS_MASK    0x00070000
		#define SHARED_HW_CFG_PCIE_GEN2_PREEMPHASIS_SHIFT    16
		#define SHARED_HW_CFG_PCIE_GEN2_PREEMPHASIS_HW       0x00000000
		#define SHARED_HW_CFG_PCIE_GEN2_PREEMPHASIS_0DB      0x00010000
		#define SHARED_HW_CFG_PCIE_GEN2_PREEMPHASIS_3_5DB    0x00020000
		#define SHARED_HW_CFG_PCIE_GEN2_PREEMPHASIS_6_0DB    0x00030000

	/*  The fan failure mechanism is usually related to the PHY type
	      since the power consumption of the board is determined by the PHY.
	      Currently, fan is required for most designs with SFX7101, BCM8727
	      and BCM8481. If a fan is not required for a board which uses one
	      of those PHYs, this field should be set to "Disabled". If a fan is
	      required for a different PHY type, this option should be set to
	      "Enabled". The fan failure indication is expected on SPIO5 */
	#define SHARED_HW_CFG_FAN_FAILURE_MASK              0x00180000
		#define SHARED_HW_CFG_FAN_FAILURE_SHIFT              19
		#define SHARED_HW_CFG_FAN_FAILURE_PHY_TYPE           0x00000000
		#define SHARED_HW_CFG_FAN_FAILURE_DISABLED           0x00080000
		#define SHARED_HW_CFG_FAN_FAILURE_ENABLED            0x00100000

		/* ASPM Power Management support */
	#define SHARED_HW_CFG_ASPM_SUPPORT_MASK             0x00600000
		#define SHARED_HW_CFG_ASPM_SUPPORT_SHIFT             21
		#define SHARED_HW_CFG_ASPM_SUPPORT_L0S_L1_ENABLED    0x00000000
		#define SHARED_HW_CFG_ASPM_SUPPORT_L0S_DISABLED      0x00200000
		#define SHARED_HW_CFG_ASPM_SUPPORT_L1_DISABLED       0x00400000
		#define SHARED_HW_CFG_ASPM_SUPPORT_L0S_L1_DISABLED   0x00600000

	/* The value of PM_TL_IGNORE_REQS (bit0) in PCI register
	   tl_control_0 (register 0x2800) */
	#define SHARED_HW_CFG_PREVENT_L1_ENTRY_MASK         0x00800000
		#define SHARED_HW_CFG_PREVENT_L1_ENTRY_DISABLED      0x00000000
		#define SHARED_HW_CFG_PREVENT_L1_ENTRY_ENABLED       0x00800000


	/*  Set the MDC/MDIO access for the first external phy */
	#define SHARED_HW_CFG_MDC_MDIO_ACCESS1_MASK         0x1C000000
		#define SHARED_HW_CFG_MDC_MDIO_ACCESS1_SHIFT         26
		#define SHARED_HW_CFG_MDC_MDIO_ACCESS1_PHY_TYPE      0x00000000
		#define SHARED_HW_CFG_MDC_MDIO_ACCESS1_EMAC0         0x04000000
		#define SHARED_HW_CFG_MDC_MDIO_ACCESS1_EMAC1         0x08000000
		#define SHARED_HW_CFG_MDC_MDIO_ACCESS1_BOTH          0x0c000000
		#define SHARED_HW_CFG_MDC_MDIO_ACCESS1_SWAPPED       0x10000000

	/*  Set the MDC/MDIO access for the second external phy */
	#define SHARED_HW_CFG_MDC_MDIO_ACCESS2_MASK         0xE0000000
		#define SHARED_HW_CFG_MDC_MDIO_ACCESS2_SHIFT         29
		#define SHARED_HW_CFG_MDC_MDIO_ACCESS2_PHY_TYPE      0x00000000
		#define SHARED_HW_CFG_MDC_MDIO_ACCESS2_EMAC0         0x20000000
		#define SHARED_HW_CFG_MDC_MDIO_ACCESS2_EMAC1         0x40000000
		#define SHARED_HW_CFG_MDC_MDIO_ACCESS2_BOTH          0x60000000
		#define SHARED_HW_CFG_MDC_MDIO_ACCESS2_SWAPPED       0x80000000

	/*  Max number of PF MSIX vectors */
	u32 config_3;                                       /* 0x11C */
	#define SHARED_HW_CFG_PF_MSIX_MAX_NUM_MASK                    0x0000007F
	#define SHARED_HW_CFG_PF_MSIX_MAX_NUM_SHIFT                   0

	/*  This field extends the mf mode chosen in nvm cfg #73 (as we ran
          out of bits) */
	#define SHARED_HW_CFG_EXTENDED_MF_MODE_MASK         0x00000F00
		#define SHARED_HW_CFG_EXTENDED_MF_MODE_SHIFT              8
		#define SHARED_HW_CFG_EXTENDED_MF_MODE_NPAR1_DOT_5        0x00000000
		#define SHARED_HW_CFG_EXTENDED_MF_MODE_NPAR2_DOT_0        0x00000100

	u32 ump_nc_si_config;			/* 0x120 */
	#define SHARED_HW_CFG_UMP_NC_SI_MII_MODE_MASK       0x00000003
		#define SHARED_HW_CFG_UMP_NC_SI_MII_MODE_SHIFT       0
		#define SHARED_HW_CFG_UMP_NC_SI_MII_MODE_MAC         0x00000000
		#define SHARED_HW_CFG_UMP_NC_SI_MII_MODE_PHY         0x00000001
		#define SHARED_HW_CFG_UMP_NC_SI_MII_MODE_MII         0x00000000
		#define SHARED_HW_CFG_UMP_NC_SI_MII_MODE_RMII        0x00000002

	/* Reserved bits: 226-230 */

	/*  The output pin template BSC_SEL which selects the I2C for this
	port in the I2C Mux */
	u32 board;			/* 0x124 */
	#define SHARED_HW_CFG_E3_I2C_MUX0_MASK              0x0000003F
	    #define SHARED_HW_CFG_E3_I2C_MUX0_SHIFT              0

	#define SHARED_HW_CFG_E3_I2C_MUX1_MASK              0x00000FC0
	#define SHARED_HW_CFG_E3_I2C_MUX1_SHIFT                      6
	/* Use the PIN_CFG_XXX defines on top */
	#define SHARED_HW_CFG_BOARD_REV_MASK                0x00FF0000
	#define SHARED_HW_CFG_BOARD_REV_SHIFT                        16

	#define SHARED_HW_CFG_BOARD_MAJOR_VER_MASK          0x0F000000
	#define SHARED_HW_CFG_BOARD_MAJOR_VER_SHIFT                  24

	#define SHARED_HW_CFG_BOARD_MINOR_VER_MASK          0xF0000000
	#define SHARED_HW_CFG_BOARD_MINOR_VER_SHIFT                  28

	u32 wc_lane_config;				    /* 0x128 */
	#define SHARED_HW_CFG_LANE_SWAP_CFG_MASK            0x0000FFFF
		#define SHARED_HW_CFG_LANE_SWAP_CFG_SHIFT            0
		#define SHARED_HW_CFG_LANE_SWAP_CFG_32103210         0x00001b1b
		#define SHARED_HW_CFG_LANE_SWAP_CFG_32100123         0x00001be4
		#define SHARED_HW_CFG_LANE_SWAP_CFG_31200213         0x000027d8
		#define SHARED_HW_CFG_LANE_SWAP_CFG_02133120         0x0000d827
		#define SHARED_HW_CFG_LANE_SWAP_CFG_01233210         0x0000e41b
		#define SHARED_HW_CFG_LANE_SWAP_CFG_01230123         0x0000e4e4
	#define SHARED_HW_CFG_LANE_SWAP_CFG_TX_MASK         0x000000FF
	#define SHARED_HW_CFG_LANE_SWAP_CFG_TX_SHIFT                 0
	#define SHARED_HW_CFG_LANE_SWAP_CFG_RX_MASK         0x0000FF00
	#define SHARED_HW_CFG_LANE_SWAP_CFG_RX_SHIFT                 8

	/* TX lane Polarity swap */
	#define SHARED_HW_CFG_TX_LANE0_POL_FLIP_ENABLED     0x00010000
	#define SHARED_HW_CFG_TX_LANE1_POL_FLIP_ENABLED     0x00020000
	#define SHARED_HW_CFG_TX_LANE2_POL_FLIP_ENABLED     0x00040000
	#define SHARED_HW_CFG_TX_LANE3_POL_FLIP_ENABLED     0x00080000
	/* TX lane Polarity swap */
	#define SHARED_HW_CFG_RX_LANE0_POL_FLIP_ENABLED     0x00100000
	#define SHARED_HW_CFG_RX_LANE1_POL_FLIP_ENABLED     0x00200000
	#define SHARED_HW_CFG_RX_LANE2_POL_FLIP_ENABLED     0x00400000
	#define SHARED_HW_CFG_RX_LANE3_POL_FLIP_ENABLED     0x00800000

	/*  Selects the port layout of the board */
	#define SHARED_HW_CFG_E3_PORT_LAYOUT_MASK           0x0F000000
		#define SHARED_HW_CFG_E3_PORT_LAYOUT_SHIFT           24
		#define SHARED_HW_CFG_E3_PORT_LAYOUT_2P_01           0x00000000
		#define SHARED_HW_CFG_E3_PORT_LAYOUT_2P_10           0x01000000
		#define SHARED_HW_CFG_E3_PORT_LAYOUT_4P_0123         0x02000000
		#define SHARED_HW_CFG_E3_PORT_LAYOUT_4P_1032         0x03000000
		#define SHARED_HW_CFG_E3_PORT_LAYOUT_4P_2301         0x04000000
		#define SHARED_HW_CFG_E3_PORT_LAYOUT_4P_3210         0x05000000
};


/****************************************************************************
 * Port HW configuration                                                    *
 ****************************************************************************/
struct port_hw_cfg {		    /* port 0: 0x12c  port 1: 0x2bc */

	u32 pci_id;
	#define PORT_HW_CFG_PCI_DEVICE_ID_MASK              0x0000FFFF
	#define PORT_HW_CFG_PCI_DEVICE_ID_SHIFT             0

	#define PORT_HW_CFG_PCI_VENDOR_ID_MASK              0xFFFF0000
	#define PORT_HW_CFG_PCI_VENDOR_ID_SHIFT             16

	u32 pci_sub_id;
	#define PORT_HW_CFG_PCI_SUBSYS_VENDOR_ID_MASK       0x0000FFFF
	#define PORT_HW_CFG_PCI_SUBSYS_VENDOR_ID_SHIFT      0

	#define PORT_HW_CFG_PCI_SUBSYS_DEVICE_ID_MASK       0xFFFF0000
	#define PORT_HW_CFG_PCI_SUBSYS_DEVICE_ID_SHIFT      16

	u32 power_dissipated;
	#define PORT_HW_CFG_POWER_DIS_D0_MASK               0x000000FF
	#define PORT_HW_CFG_POWER_DIS_D0_SHIFT                       0
	#define PORT_HW_CFG_POWER_DIS_D1_MASK               0x0000FF00
	#define PORT_HW_CFG_POWER_DIS_D1_SHIFT                       8
	#define PORT_HW_CFG_POWER_DIS_D2_MASK               0x00FF0000
	#define PORT_HW_CFG_POWER_DIS_D2_SHIFT                       16
	#define PORT_HW_CFG_POWER_DIS_D3_MASK               0xFF000000
	#define PORT_HW_CFG_POWER_DIS_D3_SHIFT                       24

	u32 power_consumed;
	#define PORT_HW_CFG_POWER_CONS_D0_MASK              0x000000FF
	#define PORT_HW_CFG_POWER_CONS_D0_SHIFT                      0
	#define PORT_HW_CFG_POWER_CONS_D1_MASK              0x0000FF00
	#define PORT_HW_CFG_POWER_CONS_D1_SHIFT                      8
	#define PORT_HW_CFG_POWER_CONS_D2_MASK              0x00FF0000
	#define PORT_HW_CFG_POWER_CONS_D2_SHIFT                      16
	#define PORT_HW_CFG_POWER_CONS_D3_MASK              0xFF000000
	#define PORT_HW_CFG_POWER_CONS_D3_SHIFT                      24

	u32 mac_upper;
	u32 mac_lower;                                      /* 0x140 */
	#define PORT_HW_CFG_UPPERMAC_MASK                   0x0000FFFF
	#define PORT_HW_CFG_UPPERMAC_SHIFT                           0


	u32 iscsi_mac_upper;  /* Upper 16 bits are always zeroes */
	u32 iscsi_mac_lower;

	u32 rdma_mac_upper;   /* Upper 16 bits are always zeroes */
	u32 rdma_mac_lower;

	u32 serdes_config;
	#define PORT_HW_CFG_SERDES_TX_DRV_PRE_EMPHASIS_MASK 0x0000FFFF
	#define PORT_HW_CFG_SERDES_TX_DRV_PRE_EMPHASIS_SHIFT         0

	#define PORT_HW_CFG_SERDES_RX_DRV_EQUALIZER_MASK    0xFFFF0000
	#define PORT_HW_CFG_SERDES_RX_DRV_EQUALIZER_SHIFT            16


	/*  Default values: 2P-64, 4P-32 */
	u32 reserved;

	u32 vf_config;					    /* 0x15C */
	#define PORT_HW_CFG_VF_PCI_DEVICE_ID_MASK           0xFFFF0000
	#define PORT_HW_CFG_VF_PCI_DEVICE_ID_SHIFT                   16

	u32 mf_pci_id;					    /* 0x160 */
	#define PORT_HW_CFG_MF_PCI_DEVICE_ID_MASK           0x0000FFFF
	#define PORT_HW_CFG_MF_PCI_DEVICE_ID_SHIFT                   0

	/*  Controls the TX laser of the SFP+ module */
	u32 sfp_ctrl;					    /* 0x164 */
	#define PORT_HW_CFG_TX_LASER_MASK                   0x000000FF
		#define PORT_HW_CFG_TX_LASER_SHIFT                   0
		#define PORT_HW_CFG_TX_LASER_MDIO                    0x00000000
		#define PORT_HW_CFG_TX_LASER_GPIO0                   0x00000001
		#define PORT_HW_CFG_TX_LASER_GPIO1                   0x00000002
		#define PORT_HW_CFG_TX_LASER_GPIO2                   0x00000003
		#define PORT_HW_CFG_TX_LASER_GPIO3                   0x00000004

	/*  Controls the fault module LED of the SFP+ */
	#define PORT_HW_CFG_FAULT_MODULE_LED_MASK           0x0000FF00
		#define PORT_HW_CFG_FAULT_MODULE_LED_SHIFT           8
		#define PORT_HW_CFG_FAULT_MODULE_LED_GPIO0           0x00000000
		#define PORT_HW_CFG_FAULT_MODULE_LED_GPIO1           0x00000100
		#define PORT_HW_CFG_FAULT_MODULE_LED_GPIO2           0x00000200
		#define PORT_HW_CFG_FAULT_MODULE_LED_GPIO3           0x00000300
		#define PORT_HW_CFG_FAULT_MODULE_LED_DISABLED        0x00000400

	/*  The output pin TX_DIS that controls the TX laser of the SFP+
	  module. Use the PIN_CFG_XXX defines on top */
	u32 e3_sfp_ctrl;				    /* 0x168 */
	#define PORT_HW_CFG_E3_TX_LASER_MASK                0x000000FF
	#define PORT_HW_CFG_E3_TX_LASER_SHIFT                        0

	/*  The output pin for SFPP_TYPE which turns on the Fault module LED */
	#define PORT_HW_CFG_E3_FAULT_MDL_LED_MASK           0x0000FF00
	#define PORT_HW_CFG_E3_FAULT_MDL_LED_SHIFT                   8

	/*  The input pin MOD_ABS that indicates whether SFP+ module is
	  present or not. Use the PIN_CFG_XXX defines on top */
	#define PORT_HW_CFG_E3_MOD_ABS_MASK                 0x00FF0000
	#define PORT_HW_CFG_E3_MOD_ABS_SHIFT                         16

	/*  The output pin PWRDIS_SFP_X which disable the power of the SFP+
	  module. Use the PIN_CFG_XXX defines on top */
	#define PORT_HW_CFG_E3_PWR_DIS_MASK                 0xFF000000
	#define PORT_HW_CFG_E3_PWR_DIS_SHIFT                         24

	/*
	 * The input pin which signals module transmit fault. Use the
	 * PIN_CFG_XXX defines on top
	 */
	u32 e3_cmn_pin_cfg;				    /* 0x16C */
	#define PORT_HW_CFG_E3_TX_FAULT_MASK                0x000000FF
	#define PORT_HW_CFG_E3_TX_FAULT_SHIFT                        0

	/*  The output pin which reset the PHY. Use the PIN_CFG_XXX defines on
	 top */
	#define PORT_HW_CFG_E3_PHY_RESET_MASK               0x0000FF00
	#define PORT_HW_CFG_E3_PHY_RESET_SHIFT                       8

	/*
	 * The output pin which powers down the PHY. Use the PIN_CFG_XXX
	 * defines on top
	 */
	#define PORT_HW_CFG_E3_PWR_DOWN_MASK                0x00FF0000
	#define PORT_HW_CFG_E3_PWR_DOWN_SHIFT                        16

	/*  The output pin values BSC_SEL which selects the I2C for this port
	  in the I2C Mux */
	#define PORT_HW_CFG_E3_I2C_MUX0_MASK                0x01000000
	#define PORT_HW_CFG_E3_I2C_MUX1_MASK                0x02000000


	/*
	 * The input pin I_FAULT which indicate over-current has occurred.
	 * Use the PIN_CFG_XXX defines on top
	 */
	u32 e3_cmn_pin_cfg1;				    /* 0x170 */
	#define PORT_HW_CFG_E3_OVER_CURRENT_MASK            0x000000FF
	#define PORT_HW_CFG_E3_OVER_CURRENT_SHIFT                    0

	/*  pause on host ring */
	u32 generic_features;                               /* 0x174 */
	#define PORT_HW_CFG_PAUSE_ON_HOST_RING_MASK                   0x00000001
	#define PORT_HW_CFG_PAUSE_ON_HOST_RING_SHIFT                  0
	#define PORT_HW_CFG_PAUSE_ON_HOST_RING_DISABLED               0x00000000
	#define PORT_HW_CFG_PAUSE_ON_HOST_RING_ENABLED                0x00000001

	/* SFP+ Tx Equalization: NIC recommended and tested value is 0xBEB2
	 * LOM recommended and tested value is 0xBEB2. Using a different
	 * value means using a value not tested by BRCM
	 */
	u32 sfi_tap_values;                                 /* 0x178 */
	#define PORT_HW_CFG_TX_EQUALIZATION_MASK                      0x0000FFFF
	#define PORT_HW_CFG_TX_EQUALIZATION_SHIFT                     0

	/* SFP+ Tx driver broadcast IDRIVER: NIC recommended and tested
	 * value is 0x2. LOM recommended and tested value is 0x2. Using a
	 * different value means using a value not tested by BRCM
	 */
	#define PORT_HW_CFG_TX_DRV_BROADCAST_MASK                     0x000F0000
	#define PORT_HW_CFG_TX_DRV_BROADCAST_SHIFT                    16

	u32 reserved0[5];				    /* 0x17c */

	u32 aeu_int_mask;				    /* 0x190 */

	u32 media_type;					    /* 0x194 */
	#define PORT_HW_CFG_MEDIA_TYPE_PHY0_MASK            0x000000FF
	#define PORT_HW_CFG_MEDIA_TYPE_PHY0_SHIFT                    0

	#define PORT_HW_CFG_MEDIA_TYPE_PHY1_MASK            0x0000FF00
	#define PORT_HW_CFG_MEDIA_TYPE_PHY1_SHIFT                    8

	#define PORT_HW_CFG_MEDIA_TYPE_PHY2_MASK            0x00FF0000
	#define PORT_HW_CFG_MEDIA_TYPE_PHY2_SHIFT                    16

	/*  4 times 16 bits for all 4 lanes. In case external PHY is present
	      (not direct mode), those values will not take effect on the 4 XGXS
	      lanes. For some external PHYs (such as 8706 and 8726) the values
	      will be used to configure the external PHY  in those cases, not
	      all 4 values are needed. */
	u16 xgxs_config_rx[4];			/* 0x198 */
	u16 xgxs_config_tx[4];			/* 0x1A0 */


	/* For storing FCOE mac on shared memory */
	u32 fcoe_fip_mac_upper;
	#define PORT_HW_CFG_FCOE_UPPERMAC_MASK              0x0000ffff
	#define PORT_HW_CFG_FCOE_UPPERMAC_SHIFT                      0
	u32 fcoe_fip_mac_lower;

	u32 fcoe_wwn_port_name_upper;
	u32 fcoe_wwn_port_name_lower;

	u32 fcoe_wwn_node_name_upper;
	u32 fcoe_wwn_node_name_lower;

	/*  wwpn for npiv enabled */
	u32 wwpn_for_npiv_config;                           /* 0x1C0 */
	#define PORT_HW_CFG_WWPN_FOR_NPIV_ENABLED_MASK                0x00000001
	#define PORT_HW_CFG_WWPN_FOR_NPIV_ENABLED_SHIFT               0
	#define PORT_HW_CFG_WWPN_FOR_NPIV_ENABLED_DISABLED            0x00000000
	#define PORT_HW_CFG_WWPN_FOR_NPIV_ENABLED_ENABLED             0x00000001

	/*  wwpn for npiv valid addresses */
	u32 wwpn_for_npiv_valid_addresses;                  /* 0x1C4 */
	#define PORT_HW_CFG_WWPN_FOR_NPIV_ADDRESS_BITMAP_MASK         0x0000FFFF
	#define PORT_HW_CFG_WWPN_FOR_NPIV_ADDRESS_BITMAP_SHIFT        0

	struct mac_addr wwpn_for_niv_macs[16];

	/* Reserved bits: 2272-2336 For storing FCOE mac on shared memory */
	u32 Reserved1[14];

	u32 pf_allocation;                                  /* 0x280 */
	/* number of vfs per PF, if 0 - sriov disabled */
	#define PORT_HW_CFG_NUMBER_OF_VFS_MASK                        0x000000FF
	#define PORT_HW_CFG_NUMBER_OF_VFS_SHIFT                       0

	/*  Enable RJ45 magjack pair swapping on 10GBase-T PHY (0=default),
	      84833 only */
	u32 xgbt_phy_cfg;				    /* 0x284 */
	#define PORT_HW_CFG_RJ45_PAIR_SWAP_MASK             0x000000FF
	#define PORT_HW_CFG_RJ45_PAIR_SWAP_SHIFT                     0

		u32 default_cfg;			    /* 0x288 */
	#define PORT_HW_CFG_GPIO0_CONFIG_MASK               0x00000003
		#define PORT_HW_CFG_GPIO0_CONFIG_SHIFT               0
		#define PORT_HW_CFG_GPIO0_CONFIG_NA                  0x00000000
		#define PORT_HW_CFG_GPIO0_CONFIG_LOW                 0x00000001
		#define PORT_HW_CFG_GPIO0_CONFIG_HIGH                0x00000002
		#define PORT_HW_CFG_GPIO0_CONFIG_INPUT               0x00000003

	#define PORT_HW_CFG_GPIO1_CONFIG_MASK               0x0000000C
		#define PORT_HW_CFG_GPIO1_CONFIG_SHIFT               2
		#define PORT_HW_CFG_GPIO1_CONFIG_NA                  0x00000000
		#define PORT_HW_CFG_GPIO1_CONFIG_LOW                 0x00000004
		#define PORT_HW_CFG_GPIO1_CONFIG_HIGH                0x00000008
		#define PORT_HW_CFG_GPIO1_CONFIG_INPUT               0x0000000c

	#define PORT_HW_CFG_GPIO2_CONFIG_MASK               0x00000030
		#define PORT_HW_CFG_GPIO2_CONFIG_SHIFT               4
		#define PORT_HW_CFG_GPIO2_CONFIG_NA                  0x00000000
		#define PORT_HW_CFG_GPIO2_CONFIG_LOW                 0x00000010
		#define PORT_HW_CFG_GPIO2_CONFIG_HIGH                0x00000020
		#define PORT_HW_CFG_GPIO2_CONFIG_INPUT               0x00000030

	#define PORT_HW_CFG_GPIO3_CONFIG_MASK               0x000000C0
		#define PORT_HW_CFG_GPIO3_CONFIG_SHIFT               6
		#define PORT_HW_CFG_GPIO3_CONFIG_NA                  0x00000000
		#define PORT_HW_CFG_GPIO3_CONFIG_LOW                 0x00000040
		#define PORT_HW_CFG_GPIO3_CONFIG_HIGH                0x00000080
		#define PORT_HW_CFG_GPIO3_CONFIG_INPUT               0x000000c0

	/*  When KR link is required to be set to force which is not
	      KR-compliant, this parameter determine what is the trigger for it.
	      When GPIO is selected, low input will force the speed. Currently
	      default speed is 1G. In the future, it may be widen to select the
	      forced speed in with another parameter. Note when force-1G is
	      enabled, it override option 56: Link Speed option. */
	#define PORT_HW_CFG_FORCE_KR_ENABLER_MASK           0x00000F00
		#define PORT_HW_CFG_FORCE_KR_ENABLER_SHIFT           8
		#define PORT_HW_CFG_FORCE_KR_ENABLER_NOT_FORCED      0x00000000
		#define PORT_HW_CFG_FORCE_KR_ENABLER_GPIO0_P0        0x00000100
		#define PORT_HW_CFG_FORCE_KR_ENABLER_GPIO1_P0        0x00000200
		#define PORT_HW_CFG_FORCE_KR_ENABLER_GPIO2_P0        0x00000300
		#define PORT_HW_CFG_FORCE_KR_ENABLER_GPIO3_P0        0x00000400
		#define PORT_HW_CFG_FORCE_KR_ENABLER_GPIO0_P1        0x00000500
		#define PORT_HW_CFG_FORCE_KR_ENABLER_GPIO1_P1        0x00000600
		#define PORT_HW_CFG_FORCE_KR_ENABLER_GPIO2_P1        0x00000700
		#define PORT_HW_CFG_FORCE_KR_ENABLER_GPIO3_P1        0x00000800
		#define PORT_HW_CFG_FORCE_KR_ENABLER_FORCED          0x00000900
	/*  Enable to determine with which GPIO to reset the external phy */
	#define PORT_HW_CFG_EXT_PHY_GPIO_RST_MASK           0x000F0000
		#define PORT_HW_CFG_EXT_PHY_GPIO_RST_SHIFT           16
		#define PORT_HW_CFG_EXT_PHY_GPIO_RST_PHY_TYPE        0x00000000
		#define PORT_HW_CFG_EXT_PHY_GPIO_RST_GPIO0_P0        0x00010000
		#define PORT_HW_CFG_EXT_PHY_GPIO_RST_GPIO1_P0        0x00020000
		#define PORT_HW_CFG_EXT_PHY_GPIO_RST_GPIO2_P0        0x00030000
		#define PORT_HW_CFG_EXT_PHY_GPIO_RST_GPIO3_P0        0x00040000
		#define PORT_HW_CFG_EXT_PHY_GPIO_RST_GPIO0_P1        0x00050000
		#define PORT_HW_CFG_EXT_PHY_GPIO_RST_GPIO1_P1        0x00060000
		#define PORT_HW_CFG_EXT_PHY_GPIO_RST_GPIO2_P1        0x00070000
		#define PORT_HW_CFG_EXT_PHY_GPIO_RST_GPIO3_P1        0x00080000

	/*  Enable BAM on KR */
	#define PORT_HW_CFG_ENABLE_BAM_ON_KR_MASK           0x00100000
	#define PORT_HW_CFG_ENABLE_BAM_ON_KR_SHIFT                   20
	#define PORT_HW_CFG_ENABLE_BAM_ON_KR_DISABLED                0x00000000
	#define PORT_HW_CFG_ENABLE_BAM_ON_KR_ENABLED                 0x00100000

	/*  Enable Common Mode Sense */
	#define PORT_HW_CFG_ENABLE_CMS_MASK                 0x00200000
	#define PORT_HW_CFG_ENABLE_CMS_SHIFT                         21
	#define PORT_HW_CFG_ENABLE_CMS_DISABLED                      0x00000000
	#define PORT_HW_CFG_ENABLE_CMS_ENABLED                       0x00200000

	/*  Determine the Serdes electrical interface   */
	#define PORT_HW_CFG_NET_SERDES_IF_MASK              0x0F000000
	#define PORT_HW_CFG_NET_SERDES_IF_SHIFT                      24
	#define PORT_HW_CFG_NET_SERDES_IF_SGMII                      0x00000000
	#define PORT_HW_CFG_NET_SERDES_IF_XFI                        0x01000000
	#define PORT_HW_CFG_NET_SERDES_IF_SFI                        0x02000000
	#define PORT_HW_CFG_NET_SERDES_IF_KR                         0x03000000
	#define PORT_HW_CFG_NET_SERDES_IF_DXGXS                      0x04000000
	#define PORT_HW_CFG_NET_SERDES_IF_KR2                        0x05000000

	/*  SFP+ main TAP and post TAP volumes */
	#define PORT_HW_CFG_TAP_LEVELS_MASK                           0x70000000
	#define PORT_HW_CFG_TAP_LEVELS_SHIFT                          28
	#define PORT_HW_CFG_TAP_LEVELS_POST_15_MAIN_43                0x00000000
	#define PORT_HW_CFG_TAP_LEVELS_POST_14_MAIN_44                0x10000000
	#define PORT_HW_CFG_TAP_LEVELS_POST_13_MAIN_45                0x20000000
	#define PORT_HW_CFG_TAP_LEVELS_POST_12_MAIN_46                0x30000000
	#define PORT_HW_CFG_TAP_LEVELS_POST_11_MAIN_47                0x40000000
	#define PORT_HW_CFG_TAP_LEVELS_POST_10_MAIN_48                0x50000000

	u32 speed_capability_mask2;			    /* 0x28C */
	#define PORT_HW_CFG_SPEED_CAPABILITY2_D3_MASK       0x0000FFFF
		#define PORT_HW_CFG_SPEED_CAPABILITY2_D3_SHIFT       0
		#define PORT_HW_CFG_SPEED_CAPABILITY2_D3_10M_FULL    0x00000001
		#define PORT_HW_CFG_SPEED_CAPABILITY2_D3_10M_HALF    0x00000002
		#define PORT_HW_CFG_SPEED_CAPABILITY2_D3_100M_HALF   0x00000004
		#define PORT_HW_CFG_SPEED_CAPABILITY2_D3_100M_FULL   0x00000008
		#define PORT_HW_CFG_SPEED_CAPABILITY2_D3_1G          0x00000010
		#define PORT_HW_CFG_SPEED_CAPABILITY2_D3_2_5G        0x00000020
		#define PORT_HW_CFG_SPEED_CAPABILITY2_D3_10G         0x00000040
		#define PORT_HW_CFG_SPEED_CAPABILITY2_D3_20G         0x00000080

	#define PORT_HW_CFG_SPEED_CAPABILITY2_D0_MASK       0xFFFF0000
		#define PORT_HW_CFG_SPEED_CAPABILITY2_D0_SHIFT       16
		#define PORT_HW_CFG_SPEED_CAPABILITY2_D0_10M_FULL    0x00010000
		#define PORT_HW_CFG_SPEED_CAPABILITY2_D0_10M_HALF    0x00020000
	    #define PORT_HW_CFG_SPEED_CAPABILITY2_D0_100M_HALF   0x00040000
		#define PORT_HW_CFG_SPEED_CAPABILITY2_D0_100M_FULL   0x00080000
		#define PORT_HW_CFG_SPEED_CAPABILITY2_D0_1G          0x00100000
		#define PORT_HW_CFG_SPEED_CAPABILITY2_D0_2_5G        0x00200000
		#define PORT_HW_CFG_SPEED_CAPABILITY2_D0_10G         0x00400000
		#define PORT_HW_CFG_SPEED_CAPABILITY2_D0_20G         0x00800000


	/*  In the case where two media types (e.g. copper and fiber) are
	      present and electrically active at the same time, PHY Selection
	      will determine which of the two PHYs will be designated as the
	      Active PHY and used for a connection to the network.  */
	u32 multi_phy_config;				    /* 0x290 */
	#define PORT_HW_CFG_PHY_SELECTION_MASK              0x00000007
		#define PORT_HW_CFG_PHY_SELECTION_SHIFT              0
		#define PORT_HW_CFG_PHY_SELECTION_HARDWARE_DEFAULT   0x00000000
		#define PORT_HW_CFG_PHY_SELECTION_FIRST_PHY          0x00000001
		#define PORT_HW_CFG_PHY_SELECTION_SECOND_PHY         0x00000002
		#define PORT_HW_CFG_PHY_SELECTION_FIRST_PHY_PRIORITY 0x00000003
		#define PORT_HW_CFG_PHY_SELECTION_SECOND_PHY_PRIORITY 0x00000004

	/*  When enabled, all second phy nvram parameters will be swapped
	      with the first phy parameters */
	#define PORT_HW_CFG_PHY_SWAPPED_MASK                0x00000008
		#define PORT_HW_CFG_PHY_SWAPPED_SHIFT                3
		#define PORT_HW_CFG_PHY_SWAPPED_DISABLED             0x00000000
		#define PORT_HW_CFG_PHY_SWAPPED_ENABLED              0x00000008


	/*  Address of the second external phy */
	u32 external_phy_config2;			    /* 0x294 */
	#define PORT_HW_CFG_XGXS_EXT_PHY2_ADDR_MASK         0x000000FF
	#define PORT_HW_CFG_XGXS_EXT_PHY2_ADDR_SHIFT                 0

	/*  The second XGXS external PHY type */
	#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_MASK         0x0000FF00
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_SHIFT         8
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_DIRECT        0x00000000
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BCM8071       0x00000100
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BCM8072       0x00000200
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BCM8073       0x00000300
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BCM8705       0x00000400
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BCM8706       0x00000500
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BCM8726       0x00000600
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BCM8481       0x00000700
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_SFX7101       0x00000800
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BCM8727       0x00000900
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BCM8727_NOC   0x00000a00
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BCM84823      0x00000b00
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BCM54640      0x00000c00
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BCM84833      0x00000d00
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BCM54618SE    0x00000e00
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BCM8722       0x00000f00
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BCM54616      0x00001000
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BCM84834      0x00001100
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_FAILURE       0x0000fd00
		#define PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_NOT_CONN      0x0000ff00


	/*  4 times 16 bits for all 4 lanes. For some external PHYs (such as
	      8706, 8726 and 8727) not all 4 values are needed. */
	u16 xgxs_config2_rx[4];				    /* 0x296 */
	u16 xgxs_config2_tx[4];				    /* 0x2A0 */

	u32 lane_config;
	#define PORT_HW_CFG_LANE_SWAP_CFG_MASK              0x0000FFFF
		#define PORT_HW_CFG_LANE_SWAP_CFG_SHIFT              0
		/* AN and forced */
		#define PORT_HW_CFG_LANE_SWAP_CFG_01230123           0x00001b1b
		/* forced only */
		#define PORT_HW_CFG_LANE_SWAP_CFG_01233210           0x00001be4
		/* forced only */
		#define PORT_HW_CFG_LANE_SWAP_CFG_31203120           0x0000d8d8
		/* forced only */
		#define PORT_HW_CFG_LANE_SWAP_CFG_32103210           0x0000e4e4
	#define PORT_HW_CFG_LANE_SWAP_CFG_TX_MASK           0x000000FF
	#define PORT_HW_CFG_LANE_SWAP_CFG_TX_SHIFT                   0
	#define PORT_HW_CFG_LANE_SWAP_CFG_RX_MASK           0x0000FF00
	#define PORT_HW_CFG_LANE_SWAP_CFG_RX_SHIFT                   8
	#define PORT_HW_CFG_LANE_SWAP_CFG_MASTER_MASK       0x0000C000
	#define PORT_HW_CFG_LANE_SWAP_CFG_MASTER_SHIFT               14

	/*  Indicate whether to swap the external phy polarity */
	#define PORT_HW_CFG_SWAP_PHY_POLARITY_MASK          0x00010000
		#define PORT_HW_CFG_SWAP_PHY_POLARITY_DISABLED       0x00000000
		#define PORT_HW_CFG_SWAP_PHY_POLARITY_ENABLED        0x00010000


	u32 external_phy_config;
	#define PORT_HW_CFG_XGXS_EXT_PHY_ADDR_MASK          0x000000FF
	#define PORT_HW_CFG_XGXS_EXT_PHY_ADDR_SHIFT                  0

	#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_MASK          0x0000FF00
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_SHIFT          8
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_DIRECT         0x00000000
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BCM8071        0x00000100
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BCM8072        0x00000200
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BCM8073        0x00000300
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BCM8705        0x00000400
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BCM8706        0x00000500
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BCM8726        0x00000600
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BCM8481        0x00000700
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_SFX7101        0x00000800
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BCM8727        0x00000900
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BCM8727_NOC    0x00000a00
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BCM84823       0x00000b00
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BCM54640       0x00000c00
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BCM84833       0x00000d00
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BCM54618SE     0x00000e00
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BCM8722        0x00000f00
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BCM54616       0x00001000
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BCM84834       0x00001100
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_DIRECT_WC      0x0000fc00
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_FAILURE        0x0000fd00
		#define PORT_HW_CFG_XGXS_EXT_PHY_TYPE_NOT_CONN       0x0000ff00

	#define PORT_HW_CFG_SERDES_EXT_PHY_ADDR_MASK        0x00FF0000
	#define PORT_HW_CFG_SERDES_EXT_PHY_ADDR_SHIFT                16

	#define PORT_HW_CFG_SERDES_EXT_PHY_TYPE_MASK        0xFF000000
		#define PORT_HW_CFG_SERDES_EXT_PHY_TYPE_SHIFT        24
		#define PORT_HW_CFG_SERDES_EXT_PHY_TYPE_DIRECT       0x00000000
		#define PORT_HW_CFG_SERDES_EXT_PHY_TYPE_BCM5482      0x01000000
		#define PORT_HW_CFG_SERDES_EXT_PHY_TYPE_DIRECT_SD    0x02000000
		#define PORT_HW_CFG_SERDES_EXT_PHY_TYPE_NOT_CONN     0xff000000

	u32 speed_capability_mask;
	#define PORT_HW_CFG_SPEED_CAPABILITY_D3_MASK        0x0000FFFF
		#define PORT_HW_CFG_SPEED_CAPABILITY_D3_SHIFT        0
		#define PORT_HW_CFG_SPEED_CAPABILITY_D3_10M_FULL     0x00000001
		#define PORT_HW_CFG_SPEED_CAPABILITY_D3_10M_HALF     0x00000002
		#define PORT_HW_CFG_SPEED_CAPABILITY_D3_100M_HALF    0x00000004
		#define PORT_HW_CFG_SPEED_CAPABILITY_D3_100M_FULL    0x00000008
		#define PORT_HW_CFG_SPEED_CAPABILITY_D3_1G           0x00000010
		#define PORT_HW_CFG_SPEED_CAPABILITY_D3_2_5G         0x00000020
		#define PORT_HW_CFG_SPEED_CAPABILITY_D3_10G          0x00000040
		#define PORT_HW_CFG_SPEED_CAPABILITY_D3_20G          0x00000080
		#define PORT_HW_CFG_SPEED_CAPABILITY_D3_RESERVED     0x0000f000

	#define PORT_HW_CFG_SPEED_CAPABILITY_D0_MASK        0xFFFF0000
		#define PORT_HW_CFG_SPEED_CAPABILITY_D0_SHIFT        16
		#define PORT_HW_CFG_SPEED_CAPABILITY_D0_10M_FULL     0x00010000
		#define PORT_HW_CFG_SPEED_CAPABILITY_D0_10M_HALF     0x00020000
		#define PORT_HW_CFG_SPEED_CAPABILITY_D0_100M_HALF    0x00040000
		#define PORT_HW_CFG_SPEED_CAPABILITY_D0_100M_FULL    0x00080000
		#define PORT_HW_CFG_SPEED_CAPABILITY_D0_1G           0x00100000
		#define PORT_HW_CFG_SPEED_CAPABILITY_D0_2_5G         0x00200000
		#define PORT_HW_CFG_SPEED_CAPABILITY_D0_10G          0x00400000
		#define PORT_HW_CFG_SPEED_CAPABILITY_D0_20G          0x00800000
		#define PORT_HW_CFG_SPEED_CAPABILITY_D0_RESERVED     0xf0000000

	/*  A place to hold the original MAC address as a backup */
	u32 backup_mac_upper;			/* 0x2B4 */
	u32 backup_mac_lower;			/* 0x2B8 */

};


/****************************************************************************
 * Shared Feature configuration                                             *
 ****************************************************************************/
struct shared_feat_cfg {		 /* NVRAM Offset */

	u32 config;			/* 0x450 */
	#define SHARED_FEATURE_BMC_ECHO_MODE_EN             0x00000001

	/* Use NVRAM values instead of HW default values */
	#define SHARED_FEAT_CFG_OVERRIDE_PREEMPHASIS_CFG_MASK \
							    0x00000002
		#define SHARED_FEAT_CFG_OVERRIDE_PREEMPHASIS_CFG_DISABLED \
								     0x00000000
		#define SHARED_FEAT_CFG_OVERRIDE_PREEMPHASIS_CFG_ENABLED \
								     0x00000002

	#define SHARED_FEAT_CFG_NCSI_ID_METHOD_MASK         0x00000008
		#define SHARED_FEAT_CFG_NCSI_ID_METHOD_SPIO          0x00000000
		#define SHARED_FEAT_CFG_NCSI_ID_METHOD_NVRAM         0x00000008

	#define SHARED_FEAT_CFG_NCSI_ID_MASK                0x00000030
	#define SHARED_FEAT_CFG_NCSI_ID_SHIFT                        4

	/*  Override the OTP back to single function mode. When using GPIO,
	      high means only SF, 0 is according to CLP configuration */
	#define SHARED_FEAT_CFG_FORCE_SF_MODE_MASK          0x00000700
		#define SHARED_FEAT_CFG_FORCE_SF_MODE_SHIFT          8
		#define SHARED_FEAT_CFG_FORCE_SF_MODE_MF_ALLOWED     0x00000000
		#define SHARED_FEAT_CFG_FORCE_SF_MODE_FORCED_SF      0x00000100
		#define SHARED_FEAT_CFG_FORCE_SF_MODE_SPIO4          0x00000200
		#define SHARED_FEAT_CFG_FORCE_SF_MODE_SWITCH_INDEPT  0x00000300
		#define SHARED_FEAT_CFG_FORCE_SF_MODE_AFEX_MODE      0x00000400
		#define SHARED_FEAT_CFG_FORCE_SF_MODE_BD_MODE        0x00000500
		#define SHARED_FEAT_CFG_FORCE_SF_MODE_UFP_MODE       0x00000600
		#define SHARED_FEAT_CFG_FORCE_SF_MODE_EXTENDED_MODE  0x00000700

	/*  Act as if the FCoE license is invalid */
	#define SHARED_FEAT_CFG_PREVENT_FCOE                0x00001000

    /*  Force FLR capability to all ports */
	#define SHARED_FEAT_CFG_FORCE_FLR_CAPABILITY        0x00002000

	/*  Act as if the iSCSI license is invalid */
	#define SHARED_FEAT_CFG_PREVENT_ISCSI_MASK                    0x00004000
	#define SHARED_FEAT_CFG_PREVENT_ISCSI_SHIFT                   14
	#define SHARED_FEAT_CFG_PREVENT_ISCSI_DISABLED                0x00000000
	#define SHARED_FEAT_CFG_PREVENT_ISCSI_ENABLED                 0x00004000

	/* The interval in seconds between sending LLDP packets. Set to zero
	   to disable the feature */
	#define SHARED_FEAT_CFG_LLDP_XMIT_INTERVAL_MASK     0x00FF0000
	#define SHARED_FEAT_CFG_LLDP_XMIT_INTERVAL_SHIFT             16

	/* The assigned device type ID for LLDP usage */
	#define SHARED_FEAT_CFG_LLDP_DEVICE_TYPE_ID_MASK    0xFF000000
	#define SHARED_FEAT_CFG_LLDP_DEVICE_TYPE_ID_SHIFT            24

};


/****************************************************************************
 * Port Feature configuration                                               *
 ****************************************************************************/
struct port_feat_cfg {		    /* port 0: 0x454  port 1: 0x4c8 */

	u32 config;
	#define PORT_FEAT_CFG_BAR1_SIZE_MASK                 0x0000000F
		#define PORT_FEAT_CFG_BAR1_SIZE_SHIFT                 0
		#define PORT_FEAT_CFG_BAR1_SIZE_DISABLED              0x00000000
		#define PORT_FEAT_CFG_BAR1_SIZE_64K                   0x00000001
		#define PORT_FEAT_CFG_BAR1_SIZE_128K                  0x00000002
		#define PORT_FEAT_CFG_BAR1_SIZE_256K                  0x00000003
		#define PORT_FEAT_CFG_BAR1_SIZE_512K                  0x00000004
		#define PORT_FEAT_CFG_BAR1_SIZE_1M                    0x00000005
		#define PORT_FEAT_CFG_BAR1_SIZE_2M                    0x00000006
		#define PORT_FEAT_CFG_BAR1_SIZE_4M                    0x00000007
		#define PORT_FEAT_CFG_BAR1_SIZE_8M                    0x00000008
		#define PORT_FEAT_CFG_BAR1_SIZE_16M                   0x00000009
		#define PORT_FEAT_CFG_BAR1_SIZE_32M                   0x0000000a
		#define PORT_FEAT_CFG_BAR1_SIZE_64M                   0x0000000b
		#define PORT_FEAT_CFG_BAR1_SIZE_128M                  0x0000000c
		#define PORT_FEAT_CFG_BAR1_SIZE_256M                  0x0000000d
		#define PORT_FEAT_CFG_BAR1_SIZE_512M                  0x0000000e
		#define PORT_FEAT_CFG_BAR1_SIZE_1G                    0x0000000f
	#define PORT_FEAT_CFG_BAR2_SIZE_MASK                 0x000000F0
		#define PORT_FEAT_CFG_BAR2_SIZE_SHIFT                 4
		#define PORT_FEAT_CFG_BAR2_SIZE_DISABLED              0x00000000
		#define PORT_FEAT_CFG_BAR2_SIZE_64K                   0x00000010
		#define PORT_FEAT_CFG_BAR2_SIZE_128K                  0x00000020
		#define PORT_FEAT_CFG_BAR2_SIZE_256K                  0x00000030
		#define PORT_FEAT_CFG_BAR2_SIZE_512K                  0x00000040
		#define PORT_FEAT_CFG_BAR2_SIZE_1M                    0x00000050
		#define PORT_FEAT_CFG_BAR2_SIZE_2M                    0x00000060
		#define PORT_FEAT_CFG_BAR2_SIZE_4M                    0x00000070
		#define PORT_FEAT_CFG_BAR2_SIZE_8M                    0x00000080
		#define PORT_FEAT_CFG_BAR2_SIZE_16M                   0x00000090
		#define PORT_FEAT_CFG_BAR2_SIZE_32M                   0x000000a0
		#define PORT_FEAT_CFG_BAR2_SIZE_64M                   0x000000b0
		#define PORT_FEAT_CFG_BAR2_SIZE_128M                  0x000000c0
		#define PORT_FEAT_CFG_BAR2_SIZE_256M                  0x000000d0
		#define PORT_FEAT_CFG_BAR2_SIZE_512M                  0x000000e0
		#define PORT_FEAT_CFG_BAR2_SIZE_1G                    0x000000f0

	#define PORT_FEAT_CFG_DCBX_MASK                     0x00000100
		#define PORT_FEAT_CFG_DCBX_DISABLED                  0x00000000
		#define PORT_FEAT_CFG_DCBX_ENABLED                   0x00000100

    #define PORT_FEAT_CFG_AUTOGREEEN_MASK               0x00000200
	    #define PORT_FEAT_CFG_AUTOGREEEN_SHIFT               9
	    #define PORT_FEAT_CFG_AUTOGREEEN_DISABLED            0x00000000
	    #define PORT_FEAT_CFG_AUTOGREEEN_ENABLED             0x00000200

	#define PORT_FEAT_CFG_STORAGE_PERSONALITY_MASK                0x00000C00
	#define PORT_FEAT_CFG_STORAGE_PERSONALITY_SHIFT               10
	#define PORT_FEAT_CFG_STORAGE_PERSONALITY_DEFAULT             0x00000000
	#define PORT_FEAT_CFG_STORAGE_PERSONALITY_FCOE                0x00000400
	#define PORT_FEAT_CFG_STORAGE_PERSONALITY_ISCSI               0x00000800
	#define PORT_FEAT_CFG_STORAGE_PERSONALITY_BOTH                0x00000c00

	#define PORT_FEATURE_EN_SIZE_MASK                   0x0f000000
	#define PORT_FEATURE_EN_SIZE_SHIFT                       24
	#define PORT_FEATURE_WOL_ENABLED                         0x01000000
	#define PORT_FEATURE_MBA_ENABLED                         0x02000000
	#define PORT_FEATURE_MFW_ENABLED                         0x04000000

	/* Advertise expansion ROM even if MBA is disabled */
	#define PORT_FEAT_CFG_FORCE_EXP_ROM_ADV_MASK        0x08000000
		#define PORT_FEAT_CFG_FORCE_EXP_ROM_ADV_DISABLED     0x00000000
		#define PORT_FEAT_CFG_FORCE_EXP_ROM_ADV_ENABLED      0x08000000

	/* Check the optic vendor via i2c against a list of approved modules
	   in a separate nvram image */
	#define PORT_FEAT_CFG_OPT_MDL_ENFRCMNT_MASK         0xE0000000
		#define PORT_FEAT_CFG_OPT_MDL_ENFRCMNT_SHIFT         29
		#define PORT_FEAT_CFG_OPT_MDL_ENFRCMNT_NO_ENFORCEMENT \
								     0x00000000
		#define PORT_FEAT_CFG_OPT_MDL_ENFRCMNT_DISABLE_TX_LASER \
								     0x20000000
		#define PORT_FEAT_CFG_OPT_MDL_ENFRCMNT_WARNING_MSG   0x40000000
		#define PORT_FEAT_CFG_OPT_MDL_ENFRCMNT_POWER_DOWN    0x60000000

	u32 wol_config;
	/* Default is used when driver sets to "auto" mode */
	#define PORT_FEATURE_WOL_ACPI_UPON_MGMT             0x00000010

	u32 mba_config;
	#define PORT_FEATURE_MBA_BOOT_AGENT_TYPE_MASK       0x00000007
		#define PORT_FEATURE_MBA_BOOT_AGENT_TYPE_SHIFT       0
		#define PORT_FEATURE_MBA_BOOT_AGENT_TYPE_PXE         0x00000000
		#define PORT_FEATURE_MBA_BOOT_AGENT_TYPE_RPL         0x00000001
		#define PORT_FEATURE_MBA_BOOT_AGENT_TYPE_BOOTP       0x00000002
		#define PORT_FEATURE_MBA_BOOT_AGENT_TYPE_ISCSIB      0x00000003
		#define PORT_FEATURE_MBA_BOOT_AGENT_TYPE_FCOE_BOOT   0x00000004
		#define PORT_FEATURE_MBA_BOOT_AGENT_TYPE_NONE        0x00000007

	#define PORT_FEATURE_MBA_BOOT_RETRY_MASK            0x00000038
	#define PORT_FEATURE_MBA_BOOT_RETRY_SHIFT                    3

    #define PORT_FEATURE_MBA_SETUP_PROMPT_ENABLE        0x00000400
	#define PORT_FEATURE_MBA_HOTKEY_MASK                0x00000800
		#define PORT_FEATURE_MBA_HOTKEY_CTRL_S               0x00000000
		#define PORT_FEATURE_MBA_HOTKEY_CTRL_B               0x00000800

	#define PORT_FEATURE_MBA_EXP_ROM_SIZE_MASK          0x000FF000
		#define PORT_FEATURE_MBA_EXP_ROM_SIZE_SHIFT          12
		#define PORT_FEATURE_MBA_EXP_ROM_SIZE_DISABLED       0x00000000
		#define PORT_FEATURE_MBA_EXP_ROM_SIZE_2K             0x00001000
		#define PORT_FEATURE_MBA_EXP_ROM_SIZE_4K             0x00002000
		#define PORT_FEATURE_MBA_EXP_ROM_SIZE_8K             0x00003000
		#define PORT_FEATURE_MBA_EXP_ROM_SIZE_16K            0x00004000
		#define PORT_FEATURE_MBA_EXP_ROM_SIZE_32K            0x00005000
		#define PORT_FEATURE_MBA_EXP_ROM_SIZE_64K            0x00006000
		#define PORT_FEATURE_MBA_EXP_ROM_SIZE_128K           0x00007000
		#define PORT_FEATURE_MBA_EXP_ROM_SIZE_256K           0x00008000
		#define PORT_FEATURE_MBA_EXP_ROM_SIZE_512K           0x00009000
		#define PORT_FEATURE_MBA_EXP_ROM_SIZE_1M             0x0000a000
		#define PORT_FEATURE_MBA_EXP_ROM_SIZE_2M             0x0000b000
		#define PORT_FEATURE_MBA_EXP_ROM_SIZE_4M             0x0000c000
		#define PORT_FEATURE_MBA_EXP_ROM_SIZE_8M             0x0000d000
		#define PORT_FEATURE_MBA_EXP_ROM_SIZE_16M            0x0000e000
		#define PORT_FEATURE_MBA_EXP_ROM_SIZE_32M            0x0000f000
	#define PORT_FEATURE_MBA_MSG_TIMEOUT_MASK           0x00F00000
	#define PORT_FEATURE_MBA_MSG_TIMEOUT_SHIFT                   20
	#define PORT_FEATURE_MBA_BIOS_BOOTSTRAP_MASK        0x03000000
		#define PORT_FEATURE_MBA_BIOS_BOOTSTRAP_SHIFT        24
		#define PORT_FEATURE_MBA_BIOS_BOOTSTRAP_AUTO         0x00000000
		#define PORT_FEATURE_MBA_BIOS_BOOTSTRAP_BBS          0x01000000
		#define PORT_FEATURE_MBA_BIOS_BOOTSTRAP_INT18H       0x02000000
		#define PORT_FEATURE_MBA_BIOS_BOOTSTRAP_INT19H       0x03000000
	#define PORT_FEATURE_MBA_LINK_SPEED_MASK            0x3C000000
		#define PORT_FEATURE_MBA_LINK_SPEED_SHIFT            26
		#define PORT_FEATURE_MBA_LINK_SPEED_AUTO             0x00000000
		#define PORT_FEATURE_MBA_LINK_SPEED_10M_HALF         0x04000000
		#define PORT_FEATURE_MBA_LINK_SPEED_10M_FULL         0x08000000
		#define PORT_FEATURE_MBA_LINK_SPEED_100M_HALF        0x0c000000
		#define PORT_FEATURE_MBA_LINK_SPEED_100M_FULL        0x10000000
		#define PORT_FEATURE_MBA_LINK_SPEED_1G               0x14000000
		#define PORT_FEATURE_MBA_LINK_SPEED_2_5G             0x18000000
		#define PORT_FEATURE_MBA_LINK_SPEED_10G              0x1c000000
		#define PORT_FEATURE_MBA_LINK_SPEED_20G              0x20000000

	u32 Reserved0;                                      /* 0x460 */

	u32 mba_vlan_cfg;
	#define PORT_FEATURE_MBA_VLAN_TAG_MASK              0x0000FFFF
	#define PORT_FEATURE_MBA_VLAN_TAG_SHIFT                      0
	#define PORT_FEATURE_MBA_VLAN_EN                    0x00010000
	#define PORT_FEATUTE_BOFM_CFGD_EN                   0x00020000
	#define PORT_FEATURE_BOFM_CFGD_FTGT                 0x00040000
	#define PORT_FEATURE_BOFM_CFGD_VEN                  0x00080000

	u32 Reserved1;
	u32 smbus_config;
	#define PORT_FEATURE_SMBUS_ADDR_MASK                0x000000fe
	#define PORT_FEATURE_SMBUS_ADDR_SHIFT                        1

	u32 vf_config;
	#define PORT_FEAT_CFG_VF_BAR2_SIZE_MASK             0x0000000F
		#define PORT_FEAT_CFG_VF_BAR2_SIZE_SHIFT             0
		#define PORT_FEAT_CFG_VF_BAR2_SIZE_DISABLED          0x00000000
		#define PORT_FEAT_CFG_VF_BAR2_SIZE_4K                0x00000001
		#define PORT_FEAT_CFG_VF_BAR2_SIZE_8K                0x00000002
		#define PORT_FEAT_CFG_VF_BAR2_SIZE_16K               0x00000003
		#define PORT_FEAT_CFG_VF_BAR2_SIZE_32K               0x00000004
		#define PORT_FEAT_CFG_VF_BAR2_SIZE_64K               0x00000005
		#define PORT_FEAT_CFG_VF_BAR2_SIZE_128K              0x00000006
		#define PORT_FEAT_CFG_VF_BAR2_SIZE_256K              0x00000007
		#define PORT_FEAT_CFG_VF_BAR2_SIZE_512K              0x00000008
		#define PORT_FEAT_CFG_VF_BAR2_SIZE_1M                0x00000009
		#define PORT_FEAT_CFG_VF_BAR2_SIZE_2M                0x0000000a
		#define PORT_FEAT_CFG_VF_BAR2_SIZE_4M                0x0000000b
		#define PORT_FEAT_CFG_VF_BAR2_SIZE_8M                0x0000000c
		#define PORT_FEAT_CFG_VF_BAR2_SIZE_16M               0x0000000d
		#define PORT_FEAT_CFG_VF_BAR2_SIZE_32M               0x0000000e
		#define PORT_FEAT_CFG_VF_BAR2_SIZE_64M               0x0000000f

	u32 link_config;    /* Used as HW defaults for the driver */

    #define PORT_FEATURE_FLOW_CONTROL_MASK              0x00000700
		#define PORT_FEATURE_FLOW_CONTROL_SHIFT              8
		#define PORT_FEATURE_FLOW_CONTROL_AUTO               0x00000000
		#define PORT_FEATURE_FLOW_CONTROL_TX                 0x00000100
		#define PORT_FEATURE_FLOW_CONTROL_RX                 0x00000200
		#define PORT_FEATURE_FLOW_CONTROL_BOTH               0x00000300
		#define PORT_FEATURE_FLOW_CONTROL_NONE               0x00000400
		#define PORT_FEATURE_FLOW_CONTROL_SAFC_RX            0x00000500
		#define PORT_FEATURE_FLOW_CONTROL_SAFC_TX            0x00000600
		#define PORT_FEATURE_FLOW_CONTROL_SAFC_BOTH          0x00000700

    #define PORT_FEATURE_LINK_SPEED_MASK                0x000F0000
		#define PORT_FEATURE_LINK_SPEED_SHIFT                16
		#define PORT_FEATURE_LINK_SPEED_AUTO                 0x00000000
		#define PORT_FEATURE_LINK_SPEED_10M_HALF             0x00010000
		#define PORT_FEATURE_LINK_SPEED_10M_FULL             0x00020000
		#define PORT_FEATURE_LINK_SPEED_100M_HALF            0x00030000
		#define PORT_FEATURE_LINK_SPEED_100M_FULL            0x00040000
		#define PORT_FEATURE_LINK_SPEED_1G                   0x00050000
		#define PORT_FEATURE_LINK_SPEED_2_5G                 0x00060000
		#define PORT_FEATURE_LINK_SPEED_10G_CX4              0x00070000
		#define PORT_FEATURE_LINK_SPEED_20G                  0x00080000

	#define PORT_FEATURE_CONNECTED_SWITCH_MASK          0x03000000
		#define PORT_FEATURE_CONNECTED_SWITCH_SHIFT          24
		/* (forced) low speed switch (< 10G) */
		#define PORT_FEATURE_CON_SWITCH_1G_SWITCH            0x00000000
		/* (forced) high speed switch (>= 10G) */
		#define PORT_FEATURE_CON_SWITCH_10G_SWITCH           0x01000000
		#define PORT_FEATURE_CON_SWITCH_AUTO_DETECT          0x02000000
		#define PORT_FEATURE_CON_SWITCH_ONE_TIME_DETECT      0x03000000




	/* The default for MCP link configuration,
	   uses the same defines as link_config */
	u32 mfw_wol_link_cfg;

	/* The default for the driver of the second external phy,
	   uses the same defines as link_config */
	u32 link_config2;				    /* 0x47C */

	/* The default for MCP of the second external phy,
	   uses the same defines as link_config */
	u32 mfw_wol_link_cfg2;				    /* 0x480 */




	/*  EEE power saving mode */
	u32 eee_power_mode;                                 /* 0x484 */
	#define PORT_FEAT_CFG_EEE_POWER_MODE_MASK                     0x000000FF
	#define PORT_FEAT_CFG_EEE_POWER_MODE_SHIFT                    0
	#define PORT_FEAT_CFG_EEE_POWER_MODE_DISABLED                 0x00000000
	#define PORT_FEAT_CFG_EEE_POWER_MODE_BALANCED                 0x00000001
	#define PORT_FEAT_CFG_EEE_POWER_MODE_AGGRESSIVE               0x00000002
	#define PORT_FEAT_CFG_EEE_POWER_MODE_LOW_LATENCY              0x00000003


	u32 Reserved2[16];                                  /* 0x488 */
};

/****************************************************************************
 * Device Information                                                       *
 ****************************************************************************/
struct shm_dev_info {				/* size */

	u32    bc_rev; /* 8 bits each: major, minor, build */	       /* 4 */

	struct shared_hw_cfg     shared_hw_config;	      /* 40 */

	struct port_hw_cfg       port_hw_config[PORT_MAX];     /* 400*2=800 */

	struct shared_feat_cfg   shared_feature_config;		   /* 4 */

	struct port_feat_cfg     port_feature_config[PORT_MAX];/* 116*2=232 */

};

struct extended_dev_info_shared_cfg {             /* NVRAM OFFSET */

	/*  Threshold in celcius to start using the fan */
	u32 temperature_monitor1;                           /* 0x4000 */
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_THRESH_MASK     0x0000007F
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_THRESH_SHIFT    0

	/*  Threshold in celcius to shut down the board */
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_THRESH_MASK    0x00007F00
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_THRESH_SHIFT   8

	/*  EPIO of fan temperature status */
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_MASK       0x00FF0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_SHIFT      16
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_NA         0x00000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO0      0x00010000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO1      0x00020000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO2      0x00030000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO3      0x00040000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO4      0x00050000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO5      0x00060000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO6      0x00070000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO7      0x00080000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO8      0x00090000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO9      0x000a0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO10     0x000b0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO11     0x000c0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO12     0x000d0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO13     0x000e0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO14     0x000f0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO15     0x00100000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO16     0x00110000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO17     0x00120000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO18     0x00130000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO19     0x00140000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO20     0x00150000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO21     0x00160000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO22     0x00170000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO23     0x00180000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO24     0x00190000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO25     0x001a0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO26     0x001b0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO27     0x001c0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO28     0x001d0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO29     0x001e0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO30     0x001f0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_FAN_EPIO_EPIO31     0x00200000

	/*  EPIO of shut down temperature status */
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_MASK      0xFF000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_SHIFT     24
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_NA        0x00000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO0     0x01000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO1     0x02000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO2     0x03000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO3     0x04000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO4     0x05000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO5     0x06000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO6     0x07000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO7     0x08000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO8     0x09000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO9     0x0a000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO10    0x0b000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO11    0x0c000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO12    0x0d000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO13    0x0e000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO14    0x0f000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO15    0x10000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO16    0x11000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO17    0x12000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO18    0x13000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO19    0x14000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO20    0x15000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO21    0x16000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO22    0x17000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO23    0x18000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO24    0x19000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO25    0x1a000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO26    0x1b000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO27    0x1c000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO28    0x1d000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO29    0x1e000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO30    0x1f000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SHUT_EPIO_EPIO31    0x20000000


	/*  EPIO of shut down temperature status */
	u32 temperature_monitor2;                           /* 0x4004 */
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_PERIOD_MASK         0x0000FFFF
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_PERIOD_SHIFT        0


	/*  MFW flavor to be used */
	u32 mfw_cfg;                                        /* 0x4008 */
	#define EXTENDED_DEV_INFO_SHARED_CFG_MFW_FLAVOR_MASK          0x000000FF
	#define EXTENDED_DEV_INFO_SHARED_CFG_MFW_FLAVOR_SHIFT         0
	#define EXTENDED_DEV_INFO_SHARED_CFG_MFW_FLAVOR_NA            0x00000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_MFW_FLAVOR_A             0x00000001

	/*  Should NIC data query remain enabled upon last drv unload */
	#define EXTENDED_DEV_INFO_SHARED_CFG_OCBB_EN_LAST_DRV_MASK     0x00000100
	#define EXTENDED_DEV_INFO_SHARED_CFG_OCBB_EN_LAST_DRV_SHIFT    8
	#define EXTENDED_DEV_INFO_SHARED_CFG_OCBB_EN_LAST_DRV_DISABLED 0x00000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_OCBB_EN_LAST_DRV_ENABLED  0x00000100

	/*  Hide DCBX feature in CCM/BACS menus */
	#define EXTENDED_DEV_INFO_SHARED_CFG_HIDE_DCBX_FEAT_MASK      0x00010000
	#define EXTENDED_DEV_INFO_SHARED_CFG_HIDE_DCBX_FEAT_SHIFT     16
	#define EXTENDED_DEV_INFO_SHARED_CFG_HIDE_DCBX_FEAT_DISABLED  0x00000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_HIDE_DCBX_FEAT_ENABLED   0x00010000

	u32 smbus_config;                                   /* 0x400C */
	#define EXTENDED_DEV_INFO_SHARED_CFG_SMBUS_ADDR_MASK          0x000000FF
	#define EXTENDED_DEV_INFO_SHARED_CFG_SMBUS_ADDR_SHIFT         0

	/*  Switching regulator loop gain */
	u32 board_cfg;                                      /* 0x4010 */
	#define EXTENDED_DEV_INFO_SHARED_CFG_LOOP_GAIN_MASK           0x0000000F
	#define EXTENDED_DEV_INFO_SHARED_CFG_LOOP_GAIN_SHIFT          0
	#define EXTENDED_DEV_INFO_SHARED_CFG_LOOP_GAIN_HW_DEFAULT     0x00000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_LOOP_GAIN_X2             0x00000008
	#define EXTENDED_DEV_INFO_SHARED_CFG_LOOP_GAIN_X4             0x00000009
	#define EXTENDED_DEV_INFO_SHARED_CFG_LOOP_GAIN_X8             0x0000000a
	#define EXTENDED_DEV_INFO_SHARED_CFG_LOOP_GAIN_X16            0x0000000b
	#define EXTENDED_DEV_INFO_SHARED_CFG_LOOP_GAIN_DIV8           0x0000000c
	#define EXTENDED_DEV_INFO_SHARED_CFG_LOOP_GAIN_DIV4           0x0000000d
	#define EXTENDED_DEV_INFO_SHARED_CFG_LOOP_GAIN_DIV2           0x0000000e
	#define EXTENDED_DEV_INFO_SHARED_CFG_LOOP_GAIN_X1             0x0000000f

	/*  whether shadow swim feature is supported */
	#define EXTENDED_DEV_INFO_SHARED_CFG_SHADOW_SWIM_MASK         0x00000100
	#define EXTENDED_DEV_INFO_SHARED_CFG_SHADOW_SWIM_SHIFT        8
	#define EXTENDED_DEV_INFO_SHARED_CFG_SHADOW_SWIM_DISABLED     0x00000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_SHADOW_SWIM_ENABLED      0x00000100

    /*  whether to show/hide SRIOV menu in CCM */
	#define EXTENDED_DEV_INFO_SHARED_CFG_SRIOV_SHOW_MENU_MASK     0x00000200
	#define EXTENDED_DEV_INFO_SHARED_CFG_SRIOV_SHOW_MENU_SHIFT    9
	#define EXTENDED_DEV_INFO_SHARED_CFG_SRIOV_SHOW_MENU          0x00000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_SRIOV_HIDE_MENU          0x00000200

	/*  Overide PCIE revision ID when enabled the,
	    revision ID will set to B1=='0x11' */
	#define EXTENDED_DEV_INFO_SHARED_CFG_OVR_REV_ID_MASK          0x00000400
	#define EXTENDED_DEV_INFO_SHARED_CFG_OVR_REV_ID_SHIFT         10
	#define EXTENDED_DEV_INFO_SHARED_CFG_OVR_REV_ID_DISABLED      0x00000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_OVR_REV_ID_ENABLED       0x00000400

	/*  Bypass slicer offset tuning */
	#define EXTENDED_DEV_INFO_SHARED_CFG_BYPASS_SLICER_MASK       0x00000800
	#define EXTENDED_DEV_INFO_SHARED_CFG_BYPASS_SLICER_SHIFT      11
	#define EXTENDED_DEV_INFO_SHARED_CFG_BYPASS_SLICER_DISABLED   0x00000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_BYPASS_SLICER_ENABLED    0x00000800
	/*  Control Revision ID */
	#define EXTENDED_DEV_INFO_SHARED_CFG_REV_ID_CTRL_MASK         0x00003000
	#define EXTENDED_DEV_INFO_SHARED_CFG_REV_ID_CTRL_SHIFT        12
	#define EXTENDED_DEV_INFO_SHARED_CFG_REV_ID_CTRL_PRESERVE     0x00000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_REV_ID_CTRL_ACTUAL       0x00001000
	#define EXTENDED_DEV_INFO_SHARED_CFG_REV_ID_CTRL_FORCE_B0     0x00002000
	#define EXTENDED_DEV_INFO_SHARED_CFG_REV_ID_CTRL_FORCE_B1     0x00003000
	/*  Threshold in celcius for max continuous operation */
	u32 temperature_report;                             /* 0x4014 */
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_MCOT_MASK           0x0000007F
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_MCOT_SHIFT          0

	/*  Threshold in celcius for sensor caution */
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SCT_MASK            0x00007F00
	#define EXTENDED_DEV_INFO_SHARED_CFG_TEMP_SCT_SHIFT           8

	/*  wwn node prefix to be used (unless value is 0) */
	u32 wwn_prefix;                                     /* 0x4018 */
	#define EXTENDED_DEV_INFO_SHARED_CFG_WWN_NODE_PREFIX0_MASK    0x000000FF
	#define EXTENDED_DEV_INFO_SHARED_CFG_WWN_NODE_PREFIX0_SHIFT   0

	#define EXTENDED_DEV_INFO_SHARED_CFG_WWN_NODE_PREFIX1_MASK    0x0000FF00
	#define EXTENDED_DEV_INFO_SHARED_CFG_WWN_NODE_PREFIX1_SHIFT   8

	/*  wwn port prefix to be used (unless value is 0) */
	#define EXTENDED_DEV_INFO_SHARED_CFG_WWN_PORT_PREFIX0_MASK    0x00FF0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_WWN_PORT_PREFIX0_SHIFT   16

	/*  wwn port prefix to be used (unless value is 0) */
	#define EXTENDED_DEV_INFO_SHARED_CFG_WWN_PORT_PREFIX1_MASK    0xFF000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_WWN_PORT_PREFIX1_SHIFT   24

	/*  General debug nvm cfg */
	u32 dbg_cfg_flags;                                  /* 0x401C */
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_MASK                 0x000FFFFF
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_SHIFT                0
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_ENABLE               0x00000001
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_EN_SIGDET_FILTER     0x00000002
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_SET_LP_TX_PRESET7    0x00000004
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_SET_TX_ANA_DEFAULT   0x00000008
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_SET_PLL_ANA_DEFAULT  0x00000010
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_FORCE_G1PLL_RETUNE   0x00000020
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_SET_RX_ANA_DEFAULT   0x00000040
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_FORCE_SERDES_RX_CLK  0x00000080
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_DIS_RX_LP_EIEOS      0x00000100
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_FINALIZE_UCODE       0x00000200
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_HOLDOFF_REQ          0x00000400
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_RX_SIGDET_OVERRIDE   0x00000800
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_GP_PORG_UC_RESET     0x00001000
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_SUPPRESS_COMPEN_EVT  0x00002000
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_ADJ_TXEQ_P0_P1       0x00004000
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_G3_PLL_RETUNE        0x00008000
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_SET_MAC_PHY_CTL8     0x00010000
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_DIS_MAC_G3_FRM_ERR   0x00020000
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_INFERRED_EI          0x00040000
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_GEN3_COMPLI_ENA      0x00080000

	/*  Debug signet rx threshold */
	u32 dbg_rx_sigdet_threshold;                        /* 0x4020 */
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_RX_SIGDET_MASK       0x00000007
	#define EXTENDED_DEV_INFO_SHARED_CFG_DBG_RX_SIGDET_SHIFT      0

    /*  Enable IFFE feature */
	u32 iffe_features;                                  /* 0x4024 */
	#define EXTENDED_DEV_INFO_SHARED_CFG_ENABLE_IFFE_MASK         0x00000001
	#define EXTENDED_DEV_INFO_SHARED_CFG_ENABLE_IFFE_SHIFT        0
	#define EXTENDED_DEV_INFO_SHARED_CFG_ENABLE_IFFE_DISABLED     0x00000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_ENABLE_IFFE_ENABLED      0x00000001

	/*  Allowable port enablement (bitmask for ports 3-1) */
	#define EXTENDED_DEV_INFO_SHARED_CFG_OVERRIDE_PORT_MASK       0x0000000E
	#define EXTENDED_DEV_INFO_SHARED_CFG_OVERRIDE_PORT_SHIFT      1

	/*  Allow iSCSI offload override */
	#define EXTENDED_DEV_INFO_SHARED_CFG_OVERRIDE_ISCSI_MASK      0x00000010
	#define EXTENDED_DEV_INFO_SHARED_CFG_OVERRIDE_ISCSI_SHIFT     4
	#define EXTENDED_DEV_INFO_SHARED_CFG_OVERRIDE_ISCSI_DISABLED  0x00000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_OVERRIDE_ISCSI_ENABLED   0x00000010

	/*  Allow FCoE offload override */
	#define EXTENDED_DEV_INFO_SHARED_CFG_OVERRIDE_FCOE_MASK       0x00000020
	#define EXTENDED_DEV_INFO_SHARED_CFG_OVERRIDE_FCOE_SHIFT      5
	#define EXTENDED_DEV_INFO_SHARED_CFG_OVERRIDE_FCOE_DISABLED   0x00000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_OVERRIDE_FCOE_ENABLED    0x00000020

	/*  Tie to adaptor */
	#define EXTENDED_DEV_INFO_SHARED_CFG_TIE_ADAPTOR_MASK         0x00008000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TIE_ADAPTOR_SHIFT        15
	#define EXTENDED_DEV_INFO_SHARED_CFG_TIE_ADAPTOR_DISABLED     0x00000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TIE_ADAPTOR_ENABLED      0x00008000

	/*  Currently enabled port(s) (bitmask for ports 3-1) */
	u32 current_iffe_mask;                              /* 0x4028 */
	#define EXTENDED_DEV_INFO_SHARED_CFG_CURRENT_CFG_MASK         0x0000000E
	#define EXTENDED_DEV_INFO_SHARED_CFG_CURRENT_CFG_SHIFT        1

	/*  Current iSCSI offload  */
	#define EXTENDED_DEV_INFO_SHARED_CFG_CURRENT_ISCSI_MASK       0x00000010
	#define EXTENDED_DEV_INFO_SHARED_CFG_CURRENT_ISCSI_SHIFT      4
	#define EXTENDED_DEV_INFO_SHARED_CFG_CURRENT_ISCSI_DISABLED   0x00000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_CURRENT_ISCSI_ENABLED    0x00000010

	/*  Current FCoE offload  */
	#define EXTENDED_DEV_INFO_SHARED_CFG_CURRENT_FCOE_MASK        0x00000020
	#define EXTENDED_DEV_INFO_SHARED_CFG_CURRENT_FCOE_SHIFT       5
	#define EXTENDED_DEV_INFO_SHARED_CFG_CURRENT_FCOE_DISABLED    0x00000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_CURRENT_FCOE_ENABLED     0x00000020

	/* FW set this pin to "0" (assert) these signal if either of its MAC
	 * or PHY specific threshold values is exceeded.
	 * Values are standard GPIO/EPIO pins.
	 */
	u32 threshold_pin;                                  /* 0x402C */
	#define EXTENDED_DEV_INFO_SHARED_CFG_TCONTROL_PIN_MASK        0x000000FF
	#define EXTENDED_DEV_INFO_SHARED_CFG_TCONTROL_PIN_SHIFT       0
	#define EXTENDED_DEV_INFO_SHARED_CFG_TWARNING_PIN_MASK        0x0000FF00
	#define EXTENDED_DEV_INFO_SHARED_CFG_TWARNING_PIN_SHIFT       8
	#define EXTENDED_DEV_INFO_SHARED_CFG_TCRITICAL_PIN_MASK       0x00FF0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_TCRITICAL_PIN_SHIFT      16

	/* MAC die temperature threshold in Celsius. */
	u32 mac_threshold_val;                              /* 0x4030 */
	#define EXTENDED_DEV_INFO_SHARED_CFG_CONTROL_MAC_THRESH_MASK  0x000000FF
	#define EXTENDED_DEV_INFO_SHARED_CFG_CONTROL_MAC_THRESH_SHIFT 0
	#define EXTENDED_DEV_INFO_SHARED_CFG_WARNING_MAC_THRESH_MASK  0x0000FF00
	#define EXTENDED_DEV_INFO_SHARED_CFG_WARNING_MAC_THRESH_SHIFT 8
	#define EXTENDED_DEV_INFO_SHARED_CFG_CRITICAL_MAC_THRESH_MASK 0x00FF0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_CRITICAL_MAC_THRESH_SHIFT 16

	/*  PHY die temperature threshold in Celsius. */
	u32 phy_threshold_val;                              /* 0x4034 */
	#define EXTENDED_DEV_INFO_SHARED_CFG_CONTROL_PHY_THRESH_MASK  0x000000FF
	#define EXTENDED_DEV_INFO_SHARED_CFG_CONTROL_PHY_THRESH_SHIFT 0
	#define EXTENDED_DEV_INFO_SHARED_CFG_WARNING_PHY_THRESH_MASK  0x0000FF00
	#define EXTENDED_DEV_INFO_SHARED_CFG_WARNING_PHY_THRESH_SHIFT 8
	#define EXTENDED_DEV_INFO_SHARED_CFG_CRITICAL_PHY_THRESH_MASK 0x00FF0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_CRITICAL_PHY_THRESH_SHIFT 16

	/* External pins to communicate with host.
	 * Values are standard GPIO/EPIO pins.
	 */
	u32 host_pin;                                       /* 0x4038 */
	#define EXTENDED_DEV_INFO_SHARED_CFG_I2C_ISOLATE_MASK         0x000000FF
	#define EXTENDED_DEV_INFO_SHARED_CFG_I2C_ISOLATE_SHIFT        0
	#define EXTENDED_DEV_INFO_SHARED_CFG_MEZZ_FAULT_MASK          0x0000FF00
	#define EXTENDED_DEV_INFO_SHARED_CFG_MEZZ_FAULT_SHIFT         8
	#define EXTENDED_DEV_INFO_SHARED_CFG_MEZZ_VPD_UPDATE_MASK     0x00FF0000
	#define EXTENDED_DEV_INFO_SHARED_CFG_MEZZ_VPD_UPDATE_SHIFT    16
	#define EXTENDED_DEV_INFO_SHARED_CFG_VPD_CACHE_COMP_MASK      0xFF000000
	#define EXTENDED_DEV_INFO_SHARED_CFG_VPD_CACHE_COMP_SHIFT     24
};

#endif
