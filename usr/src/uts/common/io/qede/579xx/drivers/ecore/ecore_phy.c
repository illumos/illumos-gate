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

#include "bcm_osal.h"
#include "ecore.h"
#include "reg_addr.h"
#include "ecore_hw.h"
#include "ecore_hsi_common.h"
#include "ecore_mcp.h"
#include "nvm_cfg.h"
#include "ecore_phy_api.h"

#define SERDESID 0x900e


enum _ecore_status_t ecore_phy_read(struct ecore_hwfn *p_hwfn,
				    struct ecore_ptt *p_ptt, u32 port, u32 lane,
				    u32 addr, u32 cmd, u8 *buf)
{
	return ecore_mcp_phy_read(p_hwfn->p_dev, cmd,
			addr | (lane << 16) | (1<<29) | (port << 30), buf, 8);
}

enum _ecore_status_t ecore_phy_write(struct ecore_hwfn *p_hwfn,
				     struct ecore_ptt *p_ptt, u32 port,
				     u32 lane, u32 addr, u32 data_lo,
				     u32 data_hi, u32 cmd)
{
	u8 buf64[8] = {0};

	OSAL_MEMCPY(buf64, &data_lo, 4);
	OSAL_MEMCPY(buf64 + 4, &data_hi, 4);

	return ecore_mcp_phy_write(p_hwfn->p_dev, cmd,
			addr | (lane << 16) | (1<<29) | (port << 30),
				 buf64, 8);
}

/* phy core write */
int ecore_phy_core_write(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			  u32 port, u32 addr, u32 data_lo, u32 data_hi,
			  char *p_phy_result_buf)
{
	enum _ecore_status_t rc = ECORE_INVAL;

	if (port > 3) {
		OSAL_SPRINTF(p_phy_result_buf,
			     "ERROR! Port must be in range of 0..3\n");
		return rc;
	}

	/* write to address */
	rc = ecore_phy_write(p_hwfn, p_ptt, port, 0 /* lane */, addr, data_lo,
			     data_hi, ECORE_PHY_CORE_WRITE);
	if (rc == ECORE_SUCCESS)
		OSAL_SPRINTF(p_phy_result_buf, "0\n");
	else
		OSAL_SPRINTF(p_phy_result_buf,
			     "Failed placing phy_core command\n");

	return rc;
}

/* phy core read */
int ecore_phy_core_read(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			 u32 port, u32 addr, char *p_phy_result_buf)
{
	enum _ecore_status_t rc = ECORE_INVAL;
	u8 buf64[8] = {0};
	u8 data_hi[4];
	u8 data_lo[4];

	if (port > 3) {
		OSAL_SPRINTF(p_phy_result_buf,
			     "ERROR! Port must be in range of 0..3\n");
		return rc;
	}

	/* read from address */
	rc = ecore_phy_read(p_hwfn, p_ptt, port, 0 /* lane */ , addr,
			    ECORE_PHY_CORE_READ, buf64);
	if (rc == ECORE_SUCCESS) {
		OSAL_MEMCPY(data_lo, buf64, 4);
		OSAL_MEMCPY(data_hi, (buf64 + 4), 4);
		OSAL_SPRINTF(p_phy_result_buf, "0x%08x%08x\n",
			     *(u32 *)data_hi, *(u32 *)data_lo);
	}
	else
		OSAL_SPRINTF(p_phy_result_buf, "Failed placing phy_core command\n");

	return rc;
}

/* phy raw write */
int ecore_phy_raw_write(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			 u32 port, u32 lane, u32 addr, u32 data_lo,
			 u32 data_hi, char *p_phy_result_buf)
{
	enum _ecore_status_t rc = ECORE_INVAL;

	/* check if the enterd port is in the range */
	if (port > 3) {
		OSAL_SPRINTF(p_phy_result_buf,
			     "Port must be in range of 0..3\n");
		return rc;
	}

	/* check if the enterd lane is in the range */
	if (lane > 6) {
		OSAL_SPRINTF(p_phy_result_buf,
			     "Lane must be in range of 0..6\n");
		return rc;
	}

	/* write to address*/
	rc = ecore_phy_write(p_hwfn,p_ptt, port, lane, addr, data_lo,
			     data_hi, ECORE_PHY_RAW_WRITE);
	if (rc == ECORE_SUCCESS)
		OSAL_SPRINTF(p_phy_result_buf, "0\n");
	else
		OSAL_SPRINTF(p_phy_result_buf,
			     "Failed placing phy_core command\n");

	return rc;
}

/* phy raw read */
int ecore_phy_raw_read(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			u32 port, u32 lane, u32 addr, char *p_phy_result_buf)
{
	enum _ecore_status_t rc = ECORE_INVAL;
	u8 buf64[8] = {0};
	u8 data_hi[4];
	u8 data_lo[4];

	/* check if the enterd port is in the range */
	if (port > 3) {
		OSAL_SPRINTF(p_phy_result_buf,
			     "Port must be in range of 0..3\n");
		return rc;
	}

	/* check if the enterd lane is in the range */
	if (lane > 6) {
		OSAL_SPRINTF(p_phy_result_buf,
			     "Lane must be in range of 0..6\n");
		return rc;
	}

	/* read from address */
	rc = ecore_phy_read(p_hwfn,p_ptt, port, lane, addr, ECORE_PHY_RAW_READ,
			    buf64);
	if (rc == ECORE_SUCCESS) {
		OSAL_MEMCPY(data_lo, buf64, 4);
		OSAL_MEMCPY(data_hi, (buf64 + 4), 4);
		OSAL_SPRINTF(p_phy_result_buf, "0x%08x%08x\n",
			     *(u32 *)data_hi, *(u32 *)data_lo);
	} else {
		OSAL_SPRINTF(p_phy_result_buf,
			     "Failed placing phy_core command\n");
	}

	return rc;
}

static u32 ecore_phy_get_nvm_cfg1_addr(struct ecore_hwfn *p_hwfn,
				       struct ecore_ptt *p_ptt)
{
	u32 nvm_cfg_addr, nvm_cfg1_offset;

	nvm_cfg_addr = ecore_rd(p_hwfn, p_ptt, MISC_REG_GEN_PURP_CR0);
	nvm_cfg1_offset = ecore_rd(p_hwfn, p_ptt, nvm_cfg_addr +
				   offsetof(struct nvm_cfg,
					    sections_offset[NVM_CFG_SECTION_NVM_CFG1]));
	return MCP_REG_SCRATCH + nvm_cfg1_offset;
}

/* get phy info */
int ecore_phy_info(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
		    char *p_phy_result_buf)
{
	u32 nvm_cfg1_addr = ecore_phy_get_nvm_cfg1_addr(p_hwfn, p_ptt);
	u32 port_mode, port, max_ports, core_cfg, length = 0;
	enum _ecore_status_t rc = ECORE_INVAL;
	u8 buf64[8] = {0};
	u8 data_hi[4];
	u8 data_lo[4];

	u8 is_bb = ((ecore_rd(p_hwfn, p_ptt, MISCS_REG_CHIP_NUM) & 0x8070)
		    != 0x8070);

	if (is_bb)
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "Device: BB ");
	else
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "Device: AH ");

	core_cfg = ecore_rd(p_hwfn, p_ptt, nvm_cfg1_addr +
			    offsetof(struct nvm_cfg1, glob.core_cfg));
	port_mode = (core_cfg & NVM_CFG1_GLOB_NETWORK_PORT_MODE_MASK) >>
		NVM_CFG1_GLOB_NETWORK_PORT_MODE_OFFSET;
	switch (port_mode) {
	case NVM_CFG1_GLOB_NETWORK_PORT_MODE_BB_1X100G:
		length += OSAL_SPRINTF(&p_phy_result_buf[length], "1x100G\n");
		max_ports = 1;
		break;
	case NVM_CFG1_GLOB_NETWORK_PORT_MODE_1X40G:
		length += OSAL_SPRINTF(&p_phy_result_buf[length], "1x40G\n");
		max_ports = 1;
		break;
	case NVM_CFG1_GLOB_NETWORK_PORT_MODE_1X25G:
		length += OSAL_SPRINTF(&p_phy_result_buf[length], "1x25G\n");
		max_ports = 1;
		break;
	case NVM_CFG1_GLOB_NETWORK_PORT_MODE_BB_2X40G:
		length += OSAL_SPRINTF(&p_phy_result_buf[length], "2x40G\n");
		max_ports = 2;
		break;
	case NVM_CFG1_GLOB_NETWORK_PORT_MODE_2X50G:
		length += OSAL_SPRINTF(&p_phy_result_buf[length], "2x50G\n");
		max_ports = 2;
		break;
	case NVM_CFG1_GLOB_NETWORK_PORT_MODE_2X25G:
		length += OSAL_SPRINTF(&p_phy_result_buf[length], "2x25G\n");
		max_ports = 2;
		break;
	case NVM_CFG1_GLOB_NETWORK_PORT_MODE_2X10G:
		length += OSAL_SPRINTF(&p_phy_result_buf[length], "2x10G\n");
		max_ports = 2;
		break;
	case NVM_CFG1_GLOB_NETWORK_PORT_MODE_4X10G_F:
		length += OSAL_SPRINTF(&p_phy_result_buf[length], "4x10G\n");
		max_ports = 4;
		break;
	case NVM_CFG1_GLOB_NETWORK_PORT_MODE_BB_4X10G_E:
		length += OSAL_SPRINTF(&p_phy_result_buf[length], "4x10G\n");
		max_ports = 4;
		break;
	case NVM_CFG1_GLOB_NETWORK_PORT_MODE_BB_4X20G:
		length += OSAL_SPRINTF(&p_phy_result_buf[length], "4x20G\n");
		max_ports = 4;
		break;
	case NVM_CFG1_GLOB_NETWORK_PORT_MODE_4X25G:
		length += OSAL_SPRINTF(&p_phy_result_buf[length], "4x25G\n");
		max_ports = 4;
		break;
	default:
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				      "Wrong port mode\n");
		return rc;
	}

	if (is_bb) {
		for (port = 0; port < max_ports; port++) {
			rc = ecore_phy_read(p_hwfn, p_ptt, port, 0, SERDESID,
					    DRV_MSG_CODE_PHY_RAW_READ, buf64);
			if (rc == ECORE_SUCCESS) {
				length += OSAL_SPRINTF(
					&p_phy_result_buf[length],
					"Port %d is in ", port);
				OSAL_MEMCPY(data_lo, buf64, 4);
				OSAL_MEMCPY(data_hi, (buf64 + 4), 4);
				if ((data_lo[0] & 0x3f) == 0x14)
					length += OSAL_SPRINTF(
						&p_phy_result_buf[length],
						"Falcon\n");
				else
					length += OSAL_SPRINTF(
						&p_phy_result_buf[length],
						"Eagle\n");
			}
		}
	} else {
		/* @@@TMP until ecore_phy_read() on AH is supported */
		for (port = 0; port < max_ports; port++)
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "Port %d is in MPS25\n", port);
		rc = ECORE_SUCCESS;
	}

	return rc;
}

struct tsc_stat {
	u32 reg;
	char *name;
	char *desc;
};

static struct tsc_stat ah_stat_regs[] = {
	{0x000100, "ETHERSTATSOCTETS               ", "total, good and bad"},
/*	{0x000104, "ETHERSTATSOCTETS_H             ", "total, good and bad"},*/
	{0x000108, "OCTETSOK                       ", "total, good"},
/*	{0x00010c, "OCTETSOK_H                     ", "total, good"}, */
	{0x000110, "AALIGNMENTERRORS               ", "Wrong SFD detected"},
/*	{0x000114, "AALIGNMENTERRORS_H             ", "Wrong SFD detected"}, */
	{0x000118, "APAUSEMACCTRLFRAMES            ", "Good Pause frames received"},
/*	{0x00011c, "APAUSEMACCTRLFRAMES_H          ", "Good Pause frames received"}, */
	{0x000120, "FRAMESOK                       ", "Good frames received"},
/*	{0x000124, "FRAMESOK_H                     ", "Good frames received"}, */
	{0x000128, "CRCERRORS                      ", "wrong CRC and good length received"},
/*	{0x00012c, "CRCERRORS_H                    ", "wrong CRC and good length received"}, */
	{0x000130, "VLANOK                         ", "Good Frames with VLAN tag received"},
/*	{0x000134, "VLANOK_H                       ", "Good Frames with VLAN tag received"}, */
	{0x000138, "IFINERRORS                     ", "Errored frames received"},
/*	{0x00013c, "IFINERRORS_H                   ", "Errored frames received"}, */
	{0x000140, "IFINUCASTPKTS                  ", "Good Unicast received"},
/*	{0x000144, "IFINUCASTPKTS_H                ", "Good Unicast received"}, */
	{0x000148, "IFINMCASTPKTS                  ", "Good Multicast received"},
/*	{0x00014c, "IFINMCASTPKTS_H                ", "Good Multicast received"}, */
	{0x000150, "IFINBCASTPKTS                  ", "Good Broadcast received"},
/*	{0x000154, "IFINBCASTPKTS_H                ", "Good Broadcast received"}, */
	{0x000158, "ETHERSTATSDROPEVENTS           ", "Dropped frames"},
/*	{0x00015c, "ETHERSTATSDROPEVENTS_H         ", "Dropped frames"}, */
	{0x000160, "ETHERSTATSPKTS                 ", "Frames received, good and bad"},
/*	{0x000164, "ETHERSTATSPKTS_H               ", "Frames received, good and bad"}, */
	{0x000168, "ETHERSTATSUNDERSIZEPKTS        ", "Frames received less 64 with good crc"},
/*	{0x00016c, "ETHERSTATSUNDERSIZEPKTS_H      ", "Frames received less 64 with good crc"}, */
	{0x000170, "ETHERSTATSPKTS64               ", "Frames of 64 octets received"},
/*	{0x000174, "ETHERSTATSPKTS64_H             ", "Frames of 64 octets received"}, */
	{0x000178, "ETHERSTATSPKTS65TO127          ", "Frames of 65 to 127 octets received"},
/*       {0x00017c, "ETHERSTATSPKTS65TO127_H        ", "Frames of 65 to 127 octets received"}, */
	{0x000180, "ETHERSTATSPKTS128TO255         ", "Frames of 128 to 255 octets received"},
/*	{0x000184, "ETHERSTATSPKTS128TO255_H       ", "Frames of 128 to 255 octets received"}, */
	{0x000188, "ETHERSTATSPKTS256TO511         ", "Frames of 256 to 511 octets received"},
/*	{0x00018c, "ETHERSTATSPKTS256TO511_H       ", "Frames of 256 to 511 octets received"},*/
	{0x000190, "ETHERSTATSPKTS512TO1023        ", "Frames of 512 to 1023 octets received"},
/*	{0x000194, "ETHERSTATSPKTS512TO1023_H      ", "Frames of 512 to 1023 octets received"},*/
	{0x000198, "ETHERSTATSPKTS1024TO1518       ", "Frames of 1024 to 1518 octets received"},
/*	{0x00019c, "ETHERSTATSPKTS1024TO1518_H     ", "Frames of 1024 to 1518 octets received"},*/
	{0x0001a0, "ETHERSTATSPKTS1519TOMAX        ", "Frames of 1519 to FRM_LENGTH octets received"},
/*	{0x0001a4, "ETHERSTATSPKTS1519TOMAX_H      ", "Frames of 1519 to FRM_LENGTH octets received"},*/
	{0x0001a8, "ETHERSTATSPKTSOVERSIZE         ", "Frames greater FRM_LENGTH and good CRC received"},
/*	{0x0001ac, "ETHERSTATSPKTSOVERSIZE_H       ", "Frames greater FRM_LENGTH and good CRC received"},*/
	{0x0001b0, "ETHERSTATSJABBERS              ", "Frames greater FRM_LENGTH and bad CRC received"},
/*	{0x0001b4, "ETHERSTATSJABBERS_H            ", "Frames greater FRM_LENGTH and bad CRC received"},*/
	{0x0001b8, "ETHERSTATSFRAGMENTS            ", "Frames less 64 and bad CRC received"},
/*	{0x0001bc, "ETHERSTATSFRAGMENTS_H          ", "Frames less 64 and bad CRC received"},*/
	{0x0001c0, "AMACCONTROLFRAMES              ", "Good frames received of type 0x8808 but not Pause"},
/*	{0x0001c4, "AMACCONTROLFRAMES_H            ", "Good frames received of type 0x8808 but not Pause"},*/
	{0x0001c8, "AFRAMETOOLONG                  ", "Good and bad frames exceeding FRM_LENGTH received"},
/*	{0x0001cc, "AFRAMETOOLONG_H                ", "Good and bad frames exceeding FRM_LENGTH received"},*/
	{0x0001d0, "AINRANGELENGTHERROR            ", "Good frames with invalid length field (not supported)"},
/*	{0x0001d4, "AINRANGELENGTHERROR_H          ", "Good frames with invalid length field (not supported)"},*/
	{0x000200, "TXETHERSTATSOCTETS             ", "total, good and bad"},
/*	{0x000204, "TXETHERSTATSOCTETS_H           ", "total, good and bad"},*/
	{0x000208, "TXOCTETSOK                     ", "total, good"},
/*	{0x00020c, "TXOCTETSOK_H                   ", "total, good"},*/
	{0x000218, "TXAPAUSEMACCTRLFRAMES          ", "Good Pause frames transmitted"},
/*	{0x00021c, "TXAPAUSEMACCTRLFRAMES_H        ", "Good Pause frames transmitted"},*/
	{0x000220, "TXFRAMESOK                     ", "Good frames transmitted"},
/*	{0x000224, "TXFRAMESOK_H                   ", "Good frames transmitted"},*/
	{0x000228, "TXCRCERRORS                    ", "wrong CRC transmitted"},
/*	{0x00022c, "TXCRCERRORS_H                  ", "wrong CRC transmitted"},*/
	{0x000230, "TXVLANOK                       ", "Good Frames with VLAN tag transmitted"},
/*	{0x000234, "TXVLANOK_H                     ", "Good Frames with VLAN tag transmitted"},*/
	{0x000238, "IFOUTERRORS                    ", "Errored frames transmitted"},
/*	{0x00023c, "IFOUTERRORS_H                  ", "Errored frames transmitted"},*/
	{0x000240, "IFOUTUCASTPKTS                 ", "Good Unicast transmitted"},
/*	{0x000244, "IFOUTUCASTPKTS_H               ", "Good Unicast transmitted"},*/
	{0x000248, "IFOUTMCASTPKTS                 ", "Good Multicast transmitted"},
/*	{0x00024c, "IFOUTMCASTPKTS_H               ", "Good Multicast transmitted"},*/
	{0x000250, "IFOUTBCASTPKTS                 ", "Good Broadcast transmitted"},
/*	{0x000254, "IFOUTBCASTPKTS_H               ", "Good Broadcast transmitted"},*/
	{0x000258, "TXETHERSTATSDROPEVENTS         ", "Dropped frames (unused, reserved)"},
/*	{0x00025c, "TXETHERSTATSDROPEVENTS_H       ", "Dropped frames (unused, reserved)"},*/
	{0x000260, "TXETHERSTATSPKTS               ", "Frames transmitted, good and bad"},
/*	{0x000264, "TXETHERSTATSPKTS_H             ", "Frames transmitted, good and bad"},*/
	{0x000268, "TXETHERSTATSUNDERSIZEPKTS      ", "Frames transmitted less 64"},
/*	{0x00026c, "TXETHERSTATSUNDERSIZEPKTS_H    ", "Frames transmitted less 64"},*/
	{0x000270, "TXETHERSTATSPKTS64             ", "Frames of 64 octets transmitted"},
/*	{0x000274, "TXETHERSTATSPKTS64_H           ", "Frames of 64 octets transmitted"},*/
	{0x000278, "TXETHERSTATSPKTS65TO127        ", "Frames of 65 to 127 octets transmitted"},
/*	{0x00027c, "TXETHERSTATSPKTS65TO127_H      ", "Frames of 65 to 127 octets transmitted"},*/
	{0x000280, "TXETHERSTATSPKTS128TO255       ", "Frames of 128 to 255 octets transmitted"},
/*	{0x000284, "TXETHERSTATSPKTS128TO255_H     ", "Frames of 128 to 255 octets transmitted"},*/
	{0x000288, "TXETHERSTATSPKTS256TO511       ", "Frames of 256 to 511 octets transmitted"},
/*	{0x00028c, "TXETHERSTATSPKTS256TO511_H     ", "Frames of 256 to 511 octets transmitted"},*/
	{0x000290, "TXETHERSTATSPKTS512TO1023      ", "Frames of 512 to 1023 octets transmitted"},
/*	{0x000294, "TXETHERSTATSPKTS512TO1023_H    ", "Frames of 512 to 1023 octets transmitted"},*/
	{0x000298, "TXETHERSTATSPKTS1024TO1518     ", "Frames of 1024 to 1518 octets transmitted"},
/*	{0x00029c, "TXETHERSTATSPKTS1024TO1518_H   ", "Frames of 1024 to 1518 octets transmitted"},*/
	{0x0002a0, "TXETHERSTATSPKTS1519TOTX_MTU   ", "Frames of 1519 to FRM_LENGTH.TX_MTU octets transmitted"},
/*	{0x0002a4, "TXETHERSTATSPKTS1519TOTX_MTU_H ", "Frames of 1519 to FRM_LENGTH.TX_MTU octets transmitted"},*/
	{0x0002c0, "TXAMACCONTROLFRAMES            ", "Good frames transmitted of type 0x8808 but not Pause"},
/*	{0x0002c4, "TXAMACCONTROLFRAMES_H          ", "Good frames transmitted of type 0x8808 but not Pause"},*/
	{0x000380, "ACBFCPAUSEFRAMESRECEIVED_0     ", "Set of 8 objects recording the number of CBFC (Class Based Flow Control) pause frames received for each class."},
/*	{0x000384, "ACBFCPAUSEFRAMESRECEIVED_0_H   ", "Upper 32bit of 64bit counter."},*/
	{0x000388, "ACBFCPAUSEFRAMESRECEIVED_1     ", "Set of 8 objects recording the number of CBFC (Class Based Flow Control) pause frames received for each class."},
/*	{0x00038c, "ACBFCPAUSEFRAMESRECEIVED_1_H   ", "Upper 32bit of 64bit counter."},*/
	{0x000390, "ACBFCPAUSEFRAMESRECEIVED_2     ", "Set of 8 objects recording the number of CBFC (Class Based Flow Control) pause frames received for each class."},
/*	{0x000394, "ACBFCPAUSEFRAMESRECEIVED_2_H   ", "Upper 32bit of 64bit counter."},*/
	{0x000398, "ACBFCPAUSEFRAMESRECEIVED_3     ", "Set of 8 objects recording the number of CBFC (Class Based Flow Control) pause frames received for each class."},
/*	{0x00039c, "ACBFCPAUSEFRAMESRECEIVED_3_H   ", "Upper 32bit of 64bit counter."},*/
	{0x0003a0, "ACBFCPAUSEFRAMESRECEIVED_4     ", "Set of 8 objects recording the number of CBFC (Class Based Flow Control) pause frames received for each class."},
/*	{0x0003a4, "ACBFCPAUSEFRAMESRECEIVED_4_H   ", "Upper 32bit of 64bit counter."},*/
	{0x0003a8, "ACBFCPAUSEFRAMESRECEIVED_5     ", "Set of 8 objects recording the number of CBFC (Class Based Flow Control) pause frames received for each class."},
/*	{0x0003ac, "ACBFCPAUSEFRAMESRECEIVED_5_H   ", "Upper 32bit of 64bit counter."},*/
	{0x0003b0, "ACBFCPAUSEFRAMESRECEIVED_6     ", "Set of 8 objects recording the number of CBFC (Class Based Flow Control) pause frames received for each class."},
/*	{0x0003b4, "ACBFCPAUSEFRAMESRECEIVED_6_H   ", "Upper 32bit of 64bit counter."},*/
	{0x0003b8, "ACBFCPAUSEFRAMESRECEIVED_7     ", "Set of 8 objects recording the number of CBFC (Class Based Flow Control) pause frames received for each class."},
/*	{0x0003bc, "ACBFCPAUSEFRAMESRECEIVED_7_H   ", "Upper 32bit of 64bit counter."},*/
	{0x0003c0, "ACBFCPAUSEFRAMESTRANSMITTED_0  ", "Set of 8 objects recording the number of CBFC (Class Based Flow Control) pause frames transmitted for each class."},
/*	{0x0003c4, "ACBFCPAUSEFRAMESTRANSMITTED_0_H", "Upper 32bit of 64bit counter."},*/
	{0x0003c8, "ACBFCPAUSEFRAMESTRANSMITTED_1  ", "Set of 8 objects recording the number of CBFC (Class Based Flow Control) pause frames transmitted for each class."},
/*	{0x0003cc, "ACBFCPAUSEFRAMESTRANSMITTED_1_H", "Upper 32bit of 64bit counter."},*/
	{0x0003d0, "ACBFCPAUSEFRAMESTRANSMITTED_2  ", "Set of 8 objects recording the number of CBFC (Class Based Flow Control) pause frames transmitted for each class."},
/*	{0x0003d4, "ACBFCPAUSEFRAMESTRANSMITTED_2_H", "Upper 32bit of 64bit counter."},*/
	{0x0003d8, "ACBFCPAUSEFRAMESTRANSMITTED_3  ", "Set of 8 objects recording the number of CBFC (Class Based Flow Control) pause frames transmitted for each class."},
/*	{0x0003dc, "ACBFCPAUSEFRAMESTRANSMITTED_3_H", "Upper 32bit of 64bit counter."},*/
	{0x0003e0, "ACBFCPAUSEFRAMESTRANSMITTED_4  ", "Set of 8 objects recording the number of CBFC (Class Based Flow Control) pause frames transmitted for each class."},
/*	{0x0003e4, "ACBFCPAUSEFRAMESTRANSMITTED_4_H", "Upper 32bit of 64bit counter."},*/
	{0x0003e8, "ACBFCPAUSEFRAMESTRANSMITTED_5  ", "Set of 8 objects recording the number of CBFC (Class Based Flow Control) pause frames transmitted for each class."},
/*	{0x0003ec, "ACBFCPAUSEFRAMESTRANSMITTED_5_H", "Upper 32bit of 64bit counter."},*/
	{0x0003f0, "ACBFCPAUSEFRAMESTRANSMITTED_6  ", "Set of 8 objects recording the number of CBFC (Class Based Flow Control) pause frames transmitted for each class."},
/*	{0x0003f4, "ACBFCPAUSEFRAMESTRANSMITTED_6_H", "Upper 32bit of 64bit counter."},*/
	{0x0003f8, "ACBFCPAUSEFRAMESTRANSMITTED_7  ", "Set of 8 objects recording the number of CBFC (Class Based Flow Control) pause frames transmitted for each class."},
/*	{0x0003fc, "ACBFCPAUSEFRAMESTRANSMITTED_7_H", "Upper 32bit of 64bit counter."}*/
};
static struct tsc_stat bb_stat_regs[] = {
    {0x00000000, "GRX64","RX 64-byte frame counter" },
    {0x00000001, "GRX127","RX 65 to 127 byte frame counter" },
    {0x00000002, "GRX255","RX 128 to 255 byte frame counter" },
    {0x00000003, "GRX511","RX 256 to 511 byte frame counter" },
    {0x00000004, "GRX1023","RX 512 to 1023 byte frame counter" },
    {0x00000005, "GRX1518","RX 1024 to 1518 byte frame counter" },
    {0x00000006, "GRX1522","RX 1519 to 1522 byte VLAN-tagged frame counter" },
    {0x00000007, "GRX2047","RX 1519 to 2047 byte frame counter" },
    {0x00000008, "GRX4095","RX 2048 to 4095 byte frame counter" },
    {0x00000009, "GRX9216","RX 4096 to 9216 byte frame counter" },
    {0x0000000a, "GRX16383","RX 9217 to 16383 byte frame counter" },
    {0x0000000b, "GRXPKT","RX frame counter (all packets)" },
    {0x0000000c, "GRXUCA","RX UC frame counter" },
    {0x0000000d, "GRXMCA","RX MC frame counter" },
    {0x0000000e, "GRXBCA","RX BC frame counter" },
    {0x0000000f, "GRXFCS","RX FCS error frame counter" },
    {0x00000010, "GRXCF","RX control frame counter" },
    {0x00000011, "GRXPF","RX pause frame counter" },
    {0x00000012, "GRXPP","RX PFC frame counter" },
    {0x00000013, "GRXUO","RX unsupported opcode frame counter" },
    {0x00000014, "GRXUDA","RX unsupported DA for pause/PFC frame counter" },
    {0x00000015, "GRXWSA","RX incorrect SA counter" },
    {0x00000016, "GRXALN","RX alignment error counter" },
    {0x00000017, "GRXFLR","RX out-of-range length frame counter" },
    {0x00000018, "GRXFRERR","RX code error frame counter" },
    {0x00000019, "GRXFCR","RX false carrier counter" },
    {0x0000001a, "GRXOVR","RX oversized frame counter" },
    {0x0000001b, "GRXJBR","RX jabber frame counter" },
    {0x0000001c, "GRXMTUE","RX MTU check error frame counter" },
    {0x0000001d, "GRXMCRC",
	    "RX packet with 4-Byte CRC matching MACSEC_PROG_TX_CRC." },
    {0x0000001e, "GRXPRM","RX promiscuous packet counter" },
    {0x0000001f, "GRXVLN","RX single and double VLAN tagged frame counter" },
    {0x00000020, "GRXDVLN","RX double VLANG tagged frame counter" },
    {0x00000021, "GRXTRFU","RX truncated frame (due to RX FIFO full) counter" },
    {0x00000022, "GRXPOK","RX good frame (good CRC, not oversized, no ERROR)" },
    {0x00000023, "GRXPFCOFF0",
	    "RX PFC frame transition XON to XOFF for Priority0" },
    {0x00000024, "GRXPFCOFF1",
	    "RX PFC frame transition XON to XOFF for Priority1" },
    {0x00000025, "GRXPFCOFF2",
	    "RX PFC frame transition XON to XOFF for Priority2" },
    {0x00000026, "GRXPFCOFF3",
	    "RX PFC frame transition XON to XOFF for Priority3" },
    {0x00000027, "GRXPFCOFF4",
	    "RX PFC frame transition XON to XOFF for Priority4" },
    {0x00000028, "GRXPFCOFF5",
	    "RX PFC frame transition XON to XOFF for Priority5" },
    {0x00000029, "GRXPFCOFF6",
	    "RX PFC frame transition XON to XOFF for Priority6" },
    {0x0000002a, "GRXPFCOFF7",
	    "RX PFC frame transition XON to XOFF for Priority7" },
    {0x0000002b, "GRXPFCP0","RX PFC frame with enable bit set for Priority0" },
    {0x0000002c, "GRXPFCP1","RX PFC frame with enable bit set for Priority1" },
    {0x0000002d, "GRXPFCP2","RX PFC frame with enable bit set for Priority2" },
    {0x0000002e, "GRXPFCP3","RX PFC frame with enable bit set for Priority3" },
    {0x0000002f, "GRXPFCP4","RX PFC frame with enable bit set for Priority4" },
    {0x00000030, "GRXPFCP5","RX PFC frame with enable bit set for Priority5" },
    {0x00000031, "GRXPFCP6","RX PFC frame with enable bit set for Priority6" },
    {0x00000032, "GRXPFCP7","RX PFC frame with enable bit set for Priority7" },
    {0x00000033, "GRXSCHCRC","RX frame with SCH CRC error. For LH mode only" },
    {0x00000034, "GRXUND","RX undersized frame counter" },
    {0x00000035, "GRXFRG","RX fragment counter" },
    {0x00000036, "RXEEELPI", "RX EEE LPI counter"},
    {0x00000037, "RXEEELPIDU", "RX EEE LPI duration counter"},
    {0x00000038, "RXLLFCPHY", "RX LLFC PHY COUNTER"},
    {0x00000039, "RXLLFCLOG", "RX LLFC LOG COUNTER"},
    {0x0000003a, "RXLLFCCRC", "RX LLFC CRC COUNTER"},
    {0x0000003b, "RXHCFC", "RX HCFC COUNTER"},
    {0x0000003c, "RXHCFCCRC", "RX HCFC CRC COUNTER"},
    {0x0000003d, "GRXBYT", "RX byte counter"},
    {0x0000003e, "GRXRBYT", "RX runt byte counter"},
    {0x0000003f, "GRXRPKT", "RX packet counter"},
    {0x00000040, "GTX64", "TX 64-byte frame counter"},
    {0x00000041, "GTX127", "TX 65 to 127 byte frame counter"},
    {0x00000042, "GTX255", "TX 128 to 255 byte frame counter"},
    {0x00000043, "GTX511", "TX 256 to 511 byte frame counter"},
    {0x00000044, "GTX1023", "TX 512 to 1023 byte frame counter"},
    {0x00000045, "GTX1518", "TX 1024 to 1518 byte frame counter"},
    {0x00000046, "GTX1522", "TX 1519 to 1522 byte VLAN-tagged frame counter"},
    {0x00000047, "GTX2047", "TX 1519 to 2047 byte frame counter"},
    {0x00000048, "GTX4095", "TX 2048 to 4095 byte frame counte"},
    {0x00000049, "GTX9216", "TX 4096 to 9216 byte frame counter"},
    {0x0000004a, "GTX16383", "TX 9217 to 16383 byte frame counter"},
    {0x0000004b, "GTXPOK", "TX good frame counter"},
    {0x0000004c, "GTXPKT", "TX frame counter (all packets"},
    {0x0000004d, "GTXUCA", "TX UC frame counter"},
    {0x0000004e, "GTXMCA", "TX MC frame counter"},
    {0x0000004f, "GTXBCA", "TX BC frame counter"},
    {0x00000050, "GTXPF", "TX pause frame counter"},
    {0x00000051, "GTXPP", "TX PFC frame counter"},
    {0x00000052, "GTXJBR", "TX jabber counter"},
    {0x00000053, "GTXFCS", "TX FCS error counter"},
    {0x00000054, "GTXCF", "TX control frame counter"},
    {0x00000055, "GTXOVR", "TX oversize packet counter"},
    {0x00000056, "GTXDFR", "TX Single Deferral Frame Counter"},
    {0x00000057, "GTXEDF", "TX Multiple Deferral Frame Counter"},
    {0x00000058, "GTXSCL", "TX Single Collision Frame Counter"},
    {0x00000059, "GTXMCL", "TX Multiple Collision Frame Counter"},
    {0x0000005a, "GTXLCL", "TX Late Collision Frame Counter"},
    {0x0000005b, "GTXXCL", "TX Excessive Collision Frame Counter"},
    {0x0000005c, "GTXFRG", "TX fragment counter"},
    {0x0000005d, "GTXERR", "TX error (set by system) frame counter"},
    {0x0000005e, "GTXVLN", "TX VLAN Tag Frame Counter"},
    {0x0000005f, "GTXDVLN", "TX Double VLAN Tag Frame Counter"},
    {0x00000060, "GTXRPKT", "TX RUNT Frame Counter"},
    {0x00000061, "GTXUFL", "TX FIFO Underrun Counter"},
    {0x00000062, "GTXPFCP0", "TX PFC frame with enable bit set for Priority0"},
    {0x00000063, "GTXPFCP1", "TX PFC frame with enable bit set for Priority1"},
    {0x00000064, "GTXPFCP2", "TX PFC frame with enable bit set for Priority2"},
    {0x00000065, "GTXPFCP3", "TX PFC frame with enable bit set for Priority3"},
    {0x00000066, "GTXPFCP4", "TX PFC frame with enable bit set for Priority4"},
    {0x00000067, "GTXPFCP5", "TX PFC frame with enable bit set for Priority5"},
    {0x00000068, "GTXPFCP6", "TX PFC frame with enable bit set for Priority6"},
    {0x00000069, "GTXPFCP7", "TX PFC frame with enable bit set for Priority7"},
    {0x0000006a, "TXEEELPI", "TX EEE LPI Event Counter"},
    {0x0000006b, "TXEEELPIDU", "TX EEE LPI Duration Counter"},
    {0x0000006c, "TXLLFCLOG", "Transmit Logical Type LLFC message counter"},
    {0x0000006d, "TXHCFC", "Transmit Logical Type LLFC message counter"},
    {0x0000006e, "GTXNCL", "Transmit Total Collision Counter"},
    {0x0000006f, "GTXBYT", "TX byte counter"}
};

/* get mac status */
static int ecore_bb_phy_mac_stat(struct ecore_hwfn *p_hwfn,
				 struct ecore_ptt *p_ptt,
				 u32 port, char *p_phy_result_buf)
{
	u8 buf64[8] = {0}, data_hi[4], data_lo[4];
	bool b_false_alarm = false;
	u32 length, reg_id, addr;
	enum _ecore_status_t rc = ECORE_INVAL;

	length = OSAL_SPRINTF(p_phy_result_buf,
			       "MAC stats for port %d (only non-zero)\n", port);

	for (reg_id = 0; reg_id < OSAL_ARRAY_SIZE(bb_stat_regs); reg_id++) {
		addr = bb_stat_regs[reg_id].reg;
		rc = ecore_phy_read(p_hwfn, p_ptt, port, 0 /*lane*/, addr,
				    ECORE_PHY_CORE_READ, buf64);

		OSAL_MEMCPY(data_lo, buf64, 4);
		OSAL_MEMCPY(data_hi, (buf64 + 4), 4);

		if (rc == ECORE_SUCCESS) {
			if (*(u32 *)data_lo != 0) {  /* Only non-zero */
				length += OSAL_SPRINTF(&p_phy_result_buf[length],
						       "%-10s: 0x%08x (%s)\n",
						       bb_stat_regs[reg_id].name,
						       *(u32 *)data_lo,
						       bb_stat_regs[reg_id].desc); 
				if ((bb_stat_regs[reg_id].reg == 0x0000000f) ||
				    (bb_stat_regs[reg_id].reg == 0x00000018) ||
				    (bb_stat_regs[reg_id].reg == 0x00000035))
					b_false_alarm = true;
			}
		} else {
			OSAL_SPRINTF(p_phy_result_buf, "Failed reading stat 0x%x\n\n",
				     addr); 
		}
	}

	if (b_false_alarm)
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "Note: GRXFCS/GRXFRERR/GRXFRG may "
				       "increment when the port shuts down\n");

	return rc;
}

/* get mac status */
static int ecore_ah_e5_phy_mac_stat(struct ecore_hwfn *p_hwfn,
				    struct ecore_ptt *p_ptt, u32 port,
				    char *p_phy_result_buf)
{
	u32 length, reg_id, addr, data_hi, data_lo;

	length = OSAL_SPRINTF(p_phy_result_buf,
			       "MAC stats for port %d (only non-zero)\n", port);

	for (reg_id = 0; reg_id < OSAL_ARRAY_SIZE(ah_stat_regs); reg_id++) {
		addr = ah_stat_regs[reg_id].reg;
		data_lo = ecore_rd(p_hwfn, p_ptt,
				   NWM_REG_MAC0_K2_E5 +
				   NWM_REG_MAC0_SIZE * 4 * port +
				   addr);
		data_hi = ecore_rd(p_hwfn, p_ptt,
				   NWM_REG_MAC0_K2_E5 +
				   NWM_REG_MAC0_SIZE * 4 * port +
				   addr + 4);

		if (data_lo) {  /* Only non-zero */
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "%-10s: 0x%08x (%s)\n",
					       ah_stat_regs[reg_id].name,
					       data_lo,
					       ah_stat_regs[reg_id].desc);
		}
	}

	return ECORE_SUCCESS;
}

int ecore_phy_mac_stat(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			u32 port, char *p_phy_result_buf)
{
	int num_ports = ecore_device_num_ports(p_hwfn->p_dev);

	if (port >= (u32)num_ports) {
		OSAL_SPRINTF(p_phy_result_buf,
			     "Port must be in range of 0..%d\n", num_ports);
		return ECORE_INVAL;
	}

	if (ECORE_IS_BB(p_hwfn->p_dev))
		return ecore_bb_phy_mac_stat(p_hwfn, p_ptt, port,
					     p_phy_result_buf);
	else
		return ecore_ah_e5_phy_mac_stat(p_hwfn, p_ptt, port,
						p_phy_result_buf);
}

#define SFP_RX_LOS_OFFSET 110
#define SFP_TX_DISABLE_OFFSET 110
#define SFP_TX_FAULT_OFFSET 110

#define QSFP_RX_LOS_OFFSET 3
#define QSFP_TX_DISABLE_OFFSET 86
#define QSFP_TX_FAULT_OFFSET 4

/* Set SFP error string */
static int ecore_sfp_set_error(enum _ecore_status_t rc, u32 offset,
			       char *p_phy_result_buf, char *p_err_str)
{
	if (rc != ECORE_SUCCESS) {
		if (rc == ECORE_NODEV)
			OSAL_SPRINTF((char *)&p_phy_result_buf[offset],
				     "Transceiver is unplugged.\n");
		else
			OSAL_SPRINTF((char *)&p_phy_result_buf[offset], "%s",
				     p_err_str);

		return ECORE_UNKNOWN_ERROR;
	}

	return rc;
}

/* Validate SFP port */
static int ecore_validate_sfp_port(struct ecore_hwfn *p_hwfn,
				   struct ecore_ptt *p_ptt,
				   u32 port, char *p_phy_result_buf)
{
	/* Verify <port> field is between 0 and number of ports */
	u32 num_ports = ecore_device_num_ports(p_hwfn->p_dev);

	if (port >= num_ports) {
		if (num_ports == 1)
			OSAL_SPRINTF(p_phy_result_buf,
				     "Bad port number, must be 0.\n");
		else
			OSAL_SPRINTF(p_phy_result_buf,
				     "Bad port number, must be between 0 and %d.\n",
				     num_ports-1);

		return ECORE_INVAL;
	}

	return ECORE_SUCCESS;
}

/* Validate SFP parameters */
static int ecore_validate_sfp_parameters(struct ecore_hwfn *p_hwfn,
					 struct ecore_ptt *p_ptt,
					 u32 port, u32 addr, u32 offset,
					 u32 size, char *p_phy_result_buf)
{
	enum _ecore_status_t rc;

	/* Verify <port> field is between 0 and number of ports */
	rc = ecore_validate_sfp_port(p_hwfn, p_ptt, port, p_phy_result_buf);
	if (rc != ECORE_SUCCESS)
		return rc;

	/* Verify <I2C> field is 0xA0 or 0xA2 */
	if ((addr != 0xA0) && (addr != 0xA2)) {
		OSAL_SPRINTF(p_phy_result_buf,
			     "Bad I2C address, must be 0xA0 or 0xA2.\n");
		return ECORE_INVAL;
	}

	/* Verify <size> field is 1 - MAX_I2C_TRANSCEIVER_PAGE_SIZE */
	if ((size == 0) || (size > MAX_I2C_TRANSCEIVER_PAGE_SIZE)) {
		OSAL_SPRINTF(p_phy_result_buf,
			     "Bad size, must be between 1 and %d.\n",
			     MAX_I2C_TRANSCEIVER_PAGE_SIZE);
		return ECORE_INVAL;
	}

	/* Verify <offset> + <size> <= MAX_I2C_TRANSCEIVER_PAGE_SIZE */
	if (offset + size > MAX_I2C_TRANSCEIVER_PAGE_SIZE) {
		OSAL_SPRINTF(p_phy_result_buf,
			     "Bad offset and size, must not exceed %d.\n",
			     MAX_I2C_TRANSCEIVER_PAGE_SIZE);
		return ECORE_INVAL;
	}

	return rc;
}

/* Write to SFP */
int ecore_phy_sfp_write(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			u32 port, u32 addr, u32 offset, u32 size,
			u32 val, char *p_phy_result_buf)
{
	enum _ecore_status_t rc;

	rc = ecore_validate_sfp_parameters(p_hwfn, p_ptt, port, addr,
					   offset, size, p_phy_result_buf);
	if (rc == ECORE_SUCCESS)
	{
		rc = ecore_mcp_phy_sfp_write(p_hwfn, p_ptt, port, addr,
					     offset, size, (u8 *)&val);

		if (rc != ECORE_SUCCESS)
			return ecore_sfp_set_error(rc, 0, p_phy_result_buf,
						   "Error writing to transceiver.\n");

		OSAL_SPRINTF(p_phy_result_buf,
			     "Written successfully to transceiver.\n");
	}

	return rc;
}

/* Read from SFP */
int ecore_phy_sfp_read(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
		       u32 port, u32 addr, u32 offset,
		       u32 size, char *p_phy_result_buf)
{
	enum _ecore_status_t rc;
	u32 i;

	rc = ecore_validate_sfp_parameters(p_hwfn, p_ptt, port, addr,
					   offset, size, p_phy_result_buf);
	if (rc == ECORE_SUCCESS)
	{
		int length = 0;
		u8 buf[MAX_I2C_TRANSCEIVER_PAGE_SIZE];

		rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, addr,
					    offset, size, buf);
		if (rc != ECORE_SUCCESS)
			return ecore_sfp_set_error(rc, 0, p_phy_result_buf,
						   "Error reading from transceiver.\n");
		for (i = 0; i < size; i++)
			length += OSAL_SPRINTF(
				(char *)&p_phy_result_buf[length],
				"%02x ", buf[i]);
	}

	return rc;
}

static enum _ecore_status_t ecore_decode_sfp_info(struct ecore_hwfn *p_hwfn,
						  struct ecore_ptt *p_ptt,
						  u32 port, u32 length,
						  char *p_phy_result_buf)
{
	/* SFP EEPROM contents are described in SFF-8024 and SFF-8472 */
	/***********************************************/
	/* SFP DATA and locations                      */
	/* get specification complianace bytes 3-10    */
	/* get signal rate byte 12                     */
	/* get extended compliance code byte 36        */
	/* get vendor length bytes 14-19               */
	/* get vendor name bytes bytes 20-35           */
	/* get vendor OUI bytes 37-39                  */
	/* get vendor PN  bytes 40-55                  */
	/* get vendor REV bytes 56-59                  */
	/* validated                                   */
	/***********************************************/
	enum _ecore_status_t rc;
	u8 buf[32];

	/* Read byte 12 - signal rate, and if nothing matches */
	/* check byte 8 for 10G copper                        */
	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    12, 1, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, length, p_phy_result_buf,
					   "Error reading specification compliance field.\n");

	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "BYTE 12 signal rate: %d\n", buf[0]);

	if (buf[0] >= 250) {
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "25G signal rate: %d\n", buf[0]);
		/* 25G - This should be copper - could double check */
		/* Read byte 3 - optics, and if nothing matches     */
		/* check byte 8 for 10G copper                      */
		rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port,
					    I2C_TRANSCEIVER_ADDR, 3, 1, buf);
		if (rc != ECORE_SUCCESS)
			return ecore_sfp_set_error(rc, length,
						   p_phy_result_buf,
						   "Error reading optics field.\n");

		switch (buf[0]) {
		case 1:
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "25G Passive copper detected\n");
			break;
		case 2:
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "25G Active copper detected\n");
			break;
		default:
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "UNKNOWN 25G cable detected: %x\n",
					       buf[0]);
			break;
		}

	} else if (buf[3] >= 100) {
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "10G signal rate: %d\n", buf[0]);
		/* 10G - Read byte 3 for optics and byte 8 for copper, and */
		/* byte 2 for AOC                                          */
		/* Read byte 3 - optics, and if nothing matches check byte */
		/* 8 for 10G copper                                        */
		rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port,
					I2C_TRANSCEIVER_ADDR, 3, 1, buf);
		if (rc != ECORE_SUCCESS)
			return ecore_sfp_set_error(rc, length,
						   p_phy_result_buf,
						   "Error reading optics field.\n");

		switch (buf[0]) {
		case 0x10:
			/* 10G SR */
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "10G SR detected\n");
			break;
		case 0x20:
			/* 10G LR */
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "10G LR detected\n");
			break;
		case 0x40:
			/* 10G LRM */
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "10G LRM detected\n");
			break;
		case 0x80:
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "10G ER detected\n");
			break;
		default:
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "SFP/SFP+/SFP-28 transceiver type 0x%x not known...  Check for 10G copper.\n",
					       buf[0]);
			/* Read 3, check 8 too */
			rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port,
						    I2C_TRANSCEIVER_ADDR,
						    8, 1, buf);
			if (rc != ECORE_SUCCESS)
				return ecore_sfp_set_error(rc, length,
							   p_phy_result_buf,
							   "Error reading 10G copper field.\n");

			switch (buf[0]) {
			case 0x04:
			case 0x84:
				length += OSAL_SPRINTF(
					&p_phy_result_buf[length],
					"10G Passive copper detected\n");
				break;
			case 0x08:
			case 0x88:
				length += OSAL_SPRINTF(
					&p_phy_result_buf[length],
					"10G Active copper detected\n");
				break;
			default:
				length += OSAL_SPRINTF(
					&p_phy_result_buf[length],
					"Unexpected SFP/SFP+/SFP-28 transceiver type 0x%x\n",
					buf[3]);
				break;
			} /* switch byte 8 */

		} /* switch byte 3 */

	} else if (buf[0] >= 10) {
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "1G signal rate: %d\n", buf[3]);
		/* 1G -  Read byte 6 for optics and byte 8 for copper */
		rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port,
					    I2C_TRANSCEIVER_ADDR, 6, 1, buf);
		if (rc != ECORE_SUCCESS)
			return ecore_sfp_set_error(rc, length,
						   p_phy_result_buf,
						   "Error reading optics field.\n");

		switch (buf[0]) {
		case 1:
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "1G SX detected\n");
			break;
		case 2:
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "1G LX detected\n");
			break;
		default:
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "Assume 1G Passive copper detected\n");
			break;
		}
	}

	/* get vendor length bytes 14-19 */
	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    14, 6, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, length, p_phy_result_buf,
					   "Error reading vendor length bytes.\n");

	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Length (SMF, km) 0x%x\n", buf[0]);
	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Length (SMF) 0x%x\n", buf[1]);
	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Length (50 um) 0x%x\n", buf[2]);
	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Length (62.5 um) 0x%x\n", buf[3]);
	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Length (OM4 or copper cable) 0x%x\n", buf[4]);
	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Length (OM3) 0x%x\n", buf[5]);

	/* get vendor name bytes bytes 20-35 */
	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    20, 16, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, length, p_phy_result_buf,
					   "Error reading vendor name.\n");

	buf[16] = 0;
	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Vendor name: %s\n", buf);

	/* get vendor OUI bytes 37-39 */
	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    37, 3, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, length, p_phy_result_buf,
					   "Error reading vendor OUI.\n");

	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Vendor OUI: %02x%02x%02x\n",
			       buf[0], buf[1], buf[2]);

	/* get vendor PN  bytes 40-55 */
	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    40, 16, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, length, p_phy_result_buf,
					   "Error reading vendor PN.\n");

	buf[16] = 0;
	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Vendor PN: %s\n", buf);

	/* get vendor REV bytes 56-59 */
	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    56, 4, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, length, p_phy_result_buf,
					   "Error reading vendor rev.\n");

	buf[4] = 0;
	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Vendor rev: %s\n", buf);

	return rc;
}

static enum _ecore_status_t ecore_decode_qsfp_info(struct ecore_hwfn *p_hwfn,
						   struct ecore_ptt *p_ptt,
						   u32 port, u32 length,
						   char *p_phy_result_buf)
{
	/* QSFP EEPROM contents are described in SFF-8024 and SFF-8636 */
	/***********************************************/
	/* QSFP DATA and locations                     */
	/* get specification complianace bytes 131-138 */
	/* get extended rate select bytes 141          */
	/* get vendor length bytes 142-146             */
	/* get device technology byte 147              */
	/* get vendor name bytes bytes 148-163         */
	/* get vendor OUI bytes 165-167                */
	/* get vendor PN  bytes 168-183                */
	/* get vendor REV bytes 184-185                */
	/* validated                                   */
	/***********************************************/
	enum _ecore_status_t rc;
	u8 buf[32];

	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    131, 1, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, length, p_phy_result_buf,
					   "Error reading transceiver compliance code.\n");

	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Transceiver compliance code 0x%x\n", buf[0]);

	switch (buf[0]) {
	case 0x1:
		/* 40G Active (XLPPI) */
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "40G Active (XLPPI) detected.\n");
		break;
	case 0x2:
		/* 40G LR-4 */
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "40G LR-4 detected.\n");
		break;
	case 0x4:
		/* 40G SR-4 */
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "40G SR-4 detected.\n");
		break;
	case 0x8:
		/* 40G CR-4 */
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "40G CR-4 detected.\n");
		break;
	case 0x10:
		/* 10G SR */
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "10G SR detected.\n");
		break;
	case 0x20:
		/* 10G LR */
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "10G LR detected.\n");
		break;
	case 0x40:
		/* 10G LRM */
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "10G LRM detected.\n");
		break;
	case 0x88: /* Could be 40G/100G CR4 cable, check 192 for 100G CR4 */
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "Multi-rate transceiver: 40G CR-4 detected...\n");
		break;
	case 0x80:
		/* Use extended technology field */
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "Use extended technology field\n");
		/* Byte 93 & 129 is supposed to have power info. During    */
		/* testing all reads 0.  Ignore for now                    */
		/* 0-127 is in the first page  this in high region -       */
		/* see what page it is.                                    */
		/*  buf[3] = 0;                                            */
		/*  ret_val = read_transceiver_data(g_port, i2c_addr, 129, */
		/*  buf, 1);                                               */
		/*  length += OSAL_SPRINTF(&p_phy_result_buf[length],      */
		/*  "Read transceiver power data.  Value read: 0x%hx\n\n", */
		/*  buf[3]);                                               */

		rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port,
					    I2C_TRANSCEIVER_ADDR, 192, 1, buf);
		if (rc != ECORE_SUCCESS)
			return ecore_sfp_set_error(rc, length, p_phy_result_buf,
						   "Error reading technology compliance field.\n");

		switch (buf[0]) {
		case 0:
			/* Unspecified */
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "Unspecified detected.\n");
			break;
		case 0x1:
			/* 100G AOC (active optical cable) */
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "100G AOC (active optical cable) detected\n");
			break;
		case 0x2:
			/* 100G SR-4 */
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "100G SR-4 detected\n");
			break;
		case 0x3:
			/* 100G LR-4 */
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "100G LR-4 detected\n");
			break;
		case 0x4:
			/* 100G ER-4 */
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "100G ER-4 detected\n");
			break;
		case 0x8:
			/* 100G ACC (active copper cable) */
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "100G ACC (active copper cable detected\n");
			break;
		case 0xb:
			/* 100G CR-4 */
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "100G CR-4 detected\n");
			break;
		case 0x11:
			/* 4x10G SR */
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "4x10G SR detected\n");
			break;
		default:
			length += OSAL_SPRINTF(&p_phy_result_buf[length],
					       "Unexpected technology. NEW COMPLIANCE CODE TO SUPPORT 0x%x\n",
					       buf[0]);
			break;
		}
		break;
	default:
		/* Unexpected technology compliance field */
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "WARNING: Unexpected technology compliance field detected 0x%x\n",
				       buf[0]);
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "Assume SR-4 detected\n");
		break;
	}

	/* get extended rate select bytes 141 */
	/* get vendor length bytes 142-146 */
	/* get device technology byte 147 */
	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    141, 7, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, length, p_phy_result_buf,
					   "Error reading extended rate select bytes.\n");

	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Extended rate select bytes 0x%x\n", buf[0]);
	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Length (SMF) 0x%x\n", buf[1]);
	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Length (OM3 50 um) 0x%x\n", buf[2]);
	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Length (OM2 50 um) 0x%x\n", buf[3]);
	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Length (OM1 62.5 um) 0x%x\n", buf[4]);
	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Length (Passive or active) 0x%x\n", buf[5]);
	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Device technology byte 0x%x\n", buf[6]);

	/* get vendor name bytes bytes 148-163 */
	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    148, 16, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, length, p_phy_result_buf,
					   "Error reading vendor name.\n");

	buf[16] = 0;
	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Vendor name: %s\n", buf);

	/* get vendor OUI bytes 165-167 */
	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    165, 3, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, length, p_phy_result_buf,
					   "Error reading vendor OUI.\n");

	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Vendor OUI: %02x%02x%02x\n",
			       buf[0], buf[1], buf[2]);

	/* get vendor PN  bytes 168-183 */
	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    168, 16, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, length, p_phy_result_buf,
					   "Error reading vendor PN.\n");

	buf[16] = 0;
	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Vendor PN: %s\n", buf);

	/* get vendor REV bytes 184-185 */
	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    184, 2, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, length, p_phy_result_buf,
					   "Error reading vendor rev.\n");

	buf[2] = 0;
	length += OSAL_SPRINTF(&p_phy_result_buf[length],
			       "Vendor rev: %s\n", buf);

	return rc;
}

/* Decode SFP information */
int ecore_phy_sfp_decode(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			 u32 port, char *p_phy_result_buf)
{
	enum _ecore_status_t rc;
	u32 length = 0;
	u8 buf[4];

	/* Verify <port> field is between 0 and number of ports */
	rc = ecore_validate_sfp_port(p_hwfn, p_ptt, port, p_phy_result_buf);
	if (rc != ECORE_SUCCESS)
		return rc;

	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    0, 1, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, length, p_phy_result_buf,
					   "Error reading transceiver identification field.\n");

	switch (buf[0]) {
	case 0x3: /* SFP, SFP+, SFP-28 */
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "SFP, SFP+ or SFP-28 inserted.\n");
		rc = ecore_decode_sfp_info(p_hwfn, p_ptt, port,
					   length, p_phy_result_buf);
		break;
	case 0xc: /* QSFP */
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "QSFP inserted.\n");
		rc = ecore_decode_qsfp_info(p_hwfn, p_ptt, port,
					    length, p_phy_result_buf);
		break;
	case 0xd: /* QSFP+ */
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "QSFP+ inserted.\n");
		rc = ecore_decode_qsfp_info(p_hwfn, p_ptt, port,
					    length, p_phy_result_buf);
		break;
	case 0x11: /* QSFP-28 */
		length += OSAL_SPRINTF(&p_phy_result_buf[length],
				       "QSFP-28 inserted.\n");
		rc = ecore_decode_qsfp_info(p_hwfn, p_ptt, port,
					    length, p_phy_result_buf);
		break;
	case 0x12: /* CXP2 (CXP-28) */
		OSAL_SPRINTF(p_phy_result_buf,
			     "CXP2 (CXP-28) inserted.\n");
		rc = ECORE_UNKNOWN_ERROR;
		break;
	default:
		OSAL_SPRINTF(p_phy_result_buf,
			     "Unknown transceiver type inserted.\n");
		rc = ECORE_UNKNOWN_ERROR;
		break;
	}

	return rc;
}

/* Get SFP inserted status */
int ecore_phy_sfp_get_inserted(struct ecore_hwfn *p_hwfn,
			       struct ecore_ptt *p_ptt,
			       u32 port, char *p_phy_result_buf)
{
	u32 transceiver_state;
	u32 addr = SECTION_OFFSIZE_ADDR(p_hwfn->mcp_info->public_base,
					PUBLIC_PORT);
	u32 mfw_mb_offsize = ecore_rd(p_hwfn, p_ptt, addr);
	u32 port_addr = SECTION_ADDR(mfw_mb_offsize, port);

	transceiver_state = ecore_rd(p_hwfn, p_ptt,
				     port_addr +
				     OFFSETOF(struct public_port,
					      transceiver_data));

	transceiver_state = GET_FIELD(transceiver_state, ETH_TRANSCEIVER_STATE);

	OSAL_SPRINTF(p_phy_result_buf, "%d",
		     (transceiver_state == ETH_TRANSCEIVER_STATE_PRESENT));

	return ECORE_SUCCESS;
}

/* Get SFP TX disable status */
int ecore_phy_sfp_get_txdisable(struct ecore_hwfn *p_hwfn,
				struct ecore_ptt *p_ptt,
				u32 port, char *p_phy_result_buf)
{
	enum _ecore_status_t rc;
	u32 length = 0;
	u8 buf[4];

	/* Verify <port> field is between 0 and number of ports */
	rc = ecore_validate_sfp_port(p_hwfn, p_ptt, port, p_phy_result_buf);
	if (rc != ECORE_SUCCESS)
		return rc;

	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    0, 1, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, length, p_phy_result_buf,
					   "Error reading transceiver identification field.\n");

	switch (buf[0]) {
	case 0x3: /* SFP, SFP+, SFP-28 */
		rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port,
					    I2C_TRANSCEIVER_ADDR, 110, 1, buf);
		if (rc != ECORE_SUCCESS)
			return ecore_sfp_set_error(rc, length, p_phy_result_buf,
						   "Error reading transceiver tx disable status field.\n");
		OSAL_SPRINTF(p_phy_result_buf, "%d",
			     ((buf[0] & 0xC0) ? 1 : 0));
		break;
	case 0xc: /* QSFP */
	case 0xd: /* QSFP+ */
	case 0x11: /* QSFP-28 */
		rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port,
					    I2C_TRANSCEIVER_ADDR, 86, 1, buf);
		if (rc != ECORE_SUCCESS)
			return ecore_sfp_set_error(rc, length, p_phy_result_buf,
						   "Error reading transceiver tx disable status field.\n");
		OSAL_SPRINTF(p_phy_result_buf, "%d",
			     ((buf[0] & ((1 << port))) ? 1 : 0));
		break;
	default:
		OSAL_SPRINTF(p_phy_result_buf,
			     "Unknown transceiver type inserted.\n");
		rc = ECORE_UNKNOWN_ERROR;
		break;
	}

	return rc;
}

/* Set SFP TX disable */
int ecore_phy_sfp_set_txdisable(struct ecore_hwfn *p_hwfn,
				struct ecore_ptt *p_ptt,
				u32 port, u8 txdisable,
				char *p_phy_result_buf)
{
	enum _ecore_status_t rc;
	u32 length = 0;
	u8 buf[4];

	/* Verify <txdisable> field is between 0 and 1 */
	if (txdisable > 1) {
		OSAL_SPRINTF(p_phy_result_buf,
			     "Bad tx disable value, must be 0 or 1.\n");
		return ECORE_INVAL;
	}

	/* Verify <port> field is between 0 and number of ports */
	rc = ecore_validate_sfp_port(p_hwfn, p_ptt, port,
				     p_phy_result_buf);
	if (rc != ECORE_SUCCESS)
		return rc;

	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    0, 1, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, length, p_phy_result_buf,
					   "Error reading transceiver identification field.\n");

	switch (buf[0]) {
	case 0x3: /* SFP, SFP+, SFP-28 */
		rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port,
					    I2C_TRANSCEIVER_ADDR,
					    SFP_TX_DISABLE_OFFSET, 1, buf);
		if (rc != ECORE_SUCCESS)
			return ecore_sfp_set_error(rc, length, p_phy_result_buf,
						   "Error reading transceiver tx disable status field.\n");

		if (((buf[0] & 0x40) >> 6) != txdisable) {
			buf[0] ^= 0x40;
			rc = ecore_mcp_phy_sfp_write(p_hwfn, p_ptt, port,
						     I2C_TRANSCEIVER_ADDR,
						     SFP_TX_DISABLE_OFFSET,
						     1, buf);
			if (rc != ECORE_SUCCESS)
				OSAL_SPRINTF(&p_phy_result_buf[length],
					     "Error setting transceiver tx disable status field.\n");
		}

		if (((buf[0] & 0x80) >> 7) != txdisable) {
			u32 nvm_cfg_addr, nvm_cfg1_offset, port_cfg_addr;
			u16 gpio;

			nvm_cfg_addr = ecore_rd(p_hwfn, p_ptt,
						MISC_REG_GEN_PURP_CR0);
			nvm_cfg1_offset = ecore_rd(p_hwfn, p_ptt,
						   nvm_cfg_addr + 4);
			port_cfg_addr = MCP_REG_SCRATCH + nvm_cfg1_offset +
					OFFSETOF(struct nvm_cfg1, port[port]);
			gpio = (u16)ecore_rd(p_hwfn, p_ptt,
					     port_cfg_addr +
					     OFFSETOF(struct nvm_cfg1_port,
						      transceiver_00));
			gpio &= NVM_CFG1_PORT_TRANS_MODULE_ABS_MASK;
			rc = ecore_phy_gpio_write(p_hwfn, p_ptt, gpio,
						  txdisable,
						  p_phy_result_buf);
			if (rc != ECORE_SUCCESS)
				OSAL_SPRINTF(&p_phy_result_buf[length],
					     "Error setting transceiver tx disable status field.\n");
		}
		break;
	case 0xc: /* QSFP */
	case 0xd: /* QSFP+ */
	case 0x11: /* QSFP-28 */
		rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port,
					    I2C_TRANSCEIVER_ADDR,
					    QSFP_TX_DISABLE_OFFSET, 1, buf);
		if (rc != ECORE_SUCCESS)
			return ecore_sfp_set_error(rc, length,
						   p_phy_result_buf,
						   "Error reading transceiver tx disable status field.\n");
		if (((buf[0] & (1 << port)) >> port) != txdisable) {
			buf[0] ^= (1 << port);
			rc = ecore_mcp_phy_sfp_write(p_hwfn, p_ptt, port,
						     I2C_TRANSCEIVER_ADDR,
						     QSFP_TX_DISABLE_OFFSET,
						     1, buf);
			if (rc != ECORE_SUCCESS)
				OSAL_SPRINTF(&p_phy_result_buf[length],
					     "Error setting transceiver tx disable status field.\n");
		}
		break;
	default:
		OSAL_SPRINTF(p_phy_result_buf,
			     "Unknown transceiver type inserted.\n");
		rc = ECORE_UNKNOWN_ERROR;
		break;
	}

	return rc;
}

/* Get SFP TX fault status */
int ecore_phy_sfp_get_txreset(struct ecore_hwfn *p_hwfn,
			      struct ecore_ptt *p_ptt,
			      u32 port, char *p_phy_result_buf)
{
	enum _ecore_status_t rc;
	u32 length = 0;
	u8 buf[4];

	/* Verify <port> field is between 0 and number of ports */
	rc = ecore_validate_sfp_port(p_hwfn, p_ptt, port, p_phy_result_buf);
	if (rc != ECORE_SUCCESS)
		return rc;

	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    0, 1, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, length, p_phy_result_buf,
					   "Error reading transceiver identification field.\n");

	switch (buf[0]) {
	case 0x3: /* SFP, SFP+, SFP-28 */
		rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port,
					    I2C_TRANSCEIVER_ADDR,
					    SFP_TX_FAULT_OFFSET, 1, buf);
		if (rc != ECORE_SUCCESS)
			return ecore_sfp_set_error(rc, length, p_phy_result_buf,
						   "Error reading transceiver tx fault status field.\n");
		OSAL_SPRINTF(p_phy_result_buf, "%d",
			     ((buf[0] & 0x02) ? 1 : 0));
		break;
	case 0xc: /* QSFP */
	case 0xd: /* QSFP+ */
	case 0x11: /* QSFP-28 */
		rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port,
					    I2C_TRANSCEIVER_ADDR,
					    QSFP_TX_FAULT_OFFSET, 1, buf);
		if (rc != ECORE_SUCCESS)
			return ecore_sfp_set_error(rc, length, p_phy_result_buf,
						   "Error reading transceiver tx fault status field.\n");
		OSAL_SPRINTF(p_phy_result_buf, "%d",
			     ((buf[0] & (1 << port)) ? 1 : 0));
		break;
	default:
		OSAL_SPRINTF(p_phy_result_buf,
			     "Unknown transceiver type inserted.\n");
		rc = ECORE_UNKNOWN_ERROR;
		break;
	}

	return rc;
}

/* Get SFP RX los status */
int ecore_phy_sfp_get_rxlos(struct ecore_hwfn *p_hwfn,
			    struct ecore_ptt *p_ptt,
			    u32 port, char *p_phy_result_buf)
{
	enum _ecore_status_t rc;
	u32 length = 0;
	u8 buf[4];

	/* Verify <port> field is between 0 and number of ports */
	rc = ecore_validate_sfp_port(p_hwfn, p_ptt, port, p_phy_result_buf);
	if (rc != ECORE_SUCCESS)
		return rc;

	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    0, 1, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, length, p_phy_result_buf,
					   "Error reading transceiver identification field.\n");

	switch (buf[0]) {
	case 0x3: /* SFP, SFP+, SFP-28 */
		rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port,
					    I2C_TRANSCEIVER_ADDR,
					    SFP_RX_LOS_OFFSET, 1, buf);
		if (rc != ECORE_SUCCESS)
			return ecore_sfp_set_error(rc, length, p_phy_result_buf,
						   "Error reading transceiver rx los status field.\n");
		OSAL_SPRINTF(p_phy_result_buf, "%d",
			     ((buf[0] & 0x01) ? 1 : 0));
		break;
	case 0xc: /* QSFP */
	case 0xd: /* QSFP+ */
	case 0x11: /* QSFP-28 */
		rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port,
					    I2C_TRANSCEIVER_ADDR,
					    QSFP_RX_LOS_OFFSET, 1, buf);
		if (rc != ECORE_SUCCESS)
			return ecore_sfp_set_error(rc, length, p_phy_result_buf,
						   "Error reading transceiver rx los status field.\n");
		OSAL_SPRINTF(p_phy_result_buf, "%d",
			     ((buf[0] & (1 << port)) ? 1 : 0));
		break;
	default:
		OSAL_SPRINTF(p_phy_result_buf,
			     "Unknown transceiver type inserted.\n");
		rc = ECORE_UNKNOWN_ERROR;
		break;
	}

	return rc;
}

/* Get SFP EEPROM memory dump */
int ecore_phy_sfp_get_eeprom(struct ecore_hwfn *p_hwfn,
			     struct ecore_ptt *p_ptt,
			     u32 port, char *p_phy_result_buf)
{
	enum _ecore_status_t rc;
	u8 buf[4];

	/* Verify <port> field is between 0 and number of ports */
	rc = ecore_validate_sfp_port(p_hwfn, p_ptt, port, p_phy_result_buf);
	if (rc != ECORE_SUCCESS)
		return rc;

	rc = ecore_mcp_phy_sfp_read(p_hwfn, p_ptt, port, I2C_TRANSCEIVER_ADDR,
				    0, 1, buf);
	if (rc != ECORE_SUCCESS)
		return ecore_sfp_set_error(rc, 0, p_phy_result_buf,
					   "Error reading transceiver identification field.\n");

	switch (buf[0]) {
	case 0x3: /* SFP, SFP+, SFP-28 */
	case 0xc: /* QSFP */
	case 0xd: /* QSFP+ */
	case 0x11: /* QSFP-28 */
		rc = ecore_phy_sfp_read(p_hwfn, p_ptt, port,
					I2C_TRANSCEIVER_ADDR, 0,
					MAX_I2C_TRANSCEIVER_PAGE_SIZE,
					p_phy_result_buf);
		break;
	default:
		OSAL_SPRINTF(p_phy_result_buf,
			     "Unknown transceiver type inserted.\n");
		rc = ECORE_UNKNOWN_ERROR;
		break;
	}

	return rc;
}

/* Write to gpio */
int ecore_phy_gpio_write(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			 u16 gpio, u16 gpio_val, char *p_phy_result_buf)
{
	enum _ecore_status_t rc;

	rc = ecore_mcp_gpio_write(p_hwfn, p_ptt, gpio, gpio_val);

	if (rc == ECORE_SUCCESS)
		OSAL_SPRINTF(p_phy_result_buf,
			     "Written successfully to gpio number %d.\n",
			     gpio);
	else
		OSAL_SPRINTF(p_phy_result_buf,
			     "Can't write to gpio %d\n", gpio);

	return rc;
}

/* Read from gpio */
int ecore_phy_gpio_read(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			u16 gpio, char *p_phy_result_buf)
{
	enum _ecore_status_t rc;
	u32 param;

	rc = ecore_mcp_gpio_read(p_hwfn, p_ptt, gpio, &param);

	if (rc == ECORE_SUCCESS)
		OSAL_SPRINTF(p_phy_result_buf, "%x", param);
	else
		OSAL_SPRINTF(p_phy_result_buf,
			     "Can't read from gpio %d\n", gpio);

	return rc;
}

/* Get information from gpio */
int ecore_phy_gpio_info(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			u16 gpio, char *p_phy_result_buf)
{
	u32 direction, ctrl, length = 0;
	enum _ecore_status_t rc;

	rc = ecore_mcp_gpio_info(p_hwfn, p_ptt, gpio, &direction, &ctrl);

	if (rc != ECORE_SUCCESS) {
		OSAL_SPRINTF(p_phy_result_buf,
			     "Can't get information for gpio %d\n", gpio);
		return rc;
	}

	length = OSAL_SPRINTF(p_phy_result_buf, "Gpio %d is %s - ",
			      gpio,
			      ((direction == 0) ? "output" : "input"));
	switch (ctrl) {
	case 0:
		OSAL_SPRINTF(&p_phy_result_buf[length],
			     "control is uninitialized\n");
		break;
	case 1:
		OSAL_SPRINTF(&p_phy_result_buf[length],
			     "control is path 0\n");
		break;
	case 2:
		OSAL_SPRINTF(&p_phy_result_buf[length],
			     "control is path 1\n");
		break;
	case 3:
		OSAL_SPRINTF(&p_phy_result_buf[length],
			     "control is shared\n");
		break;
	default:
		OSAL_SPRINTF(&p_phy_result_buf[length],
			     "\nError - control is invalid\n");
		break;
	}

	return ECORE_SUCCESS;
}

/* Get information from gpio */
int ecore_phy_extphy_read(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			  u16 port, u16 devad, u16 reg, char *p_phy_result_buf)
{
	enum _ecore_status_t rc;
	u32 resp_cmd;
	u32 val;

	rc = ecore_mcp_cmd(p_hwfn, p_ptt, DRV_MSG_CODE_EXT_PHY_READ,
			   ((port << DRV_MB_PARAM_PORT_SHIFT) |
			    (devad << DRV_MB_PARAM_DEVAD_SHIFT) |
			    (reg << DRV_MB_PARAM_ADDR_SHIFT)),
			   &resp_cmd,
			   &val);

	if ((rc != ECORE_SUCCESS) || (resp_cmd != FW_MSG_CODE_PHY_OK)) {
		OSAL_SPRINTF(p_phy_result_buf,
			     "Failed reading external PHY\n");
		return rc;
	}
	OSAL_SPRINTF(p_phy_result_buf, "0x%04x\n", val);
	return ECORE_SUCCESS;
}

/* Get information from gpio */
int ecore_phy_extphy_write(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			   u16 port, u16 devad, u16 reg, u16 val,
			   char *p_phy_result_buf)
{
	enum _ecore_status_t rc;
	u32 resp_cmd;
	u32 fw_param;

	rc = ecore_mcp_nvm_wr_cmd(p_hwfn, p_ptt, DRV_MSG_CODE_EXT_PHY_WRITE,
				  ((port << DRV_MB_PARAM_PORT_SHIFT) |
				   (devad << DRV_MB_PARAM_DEVAD_SHIFT) |
				   (reg << DRV_MB_PARAM_ADDR_SHIFT)),
				  &resp_cmd,
				  &fw_param,
				  sizeof(u32),
				  (u32 *)&val);

	if ((rc != ECORE_SUCCESS) || (resp_cmd != FW_MSG_CODE_PHY_OK)) {
		OSAL_SPRINTF(p_phy_result_buf,
			     "Failed writing external PHY\n");
		return rc;
	}
	OSAL_SPRINTF(p_phy_result_buf, "0\n");
	return ECORE_SUCCESS;
}
