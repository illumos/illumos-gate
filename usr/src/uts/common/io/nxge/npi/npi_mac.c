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
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <npi_mac.h>

#define	MIF_DELAY	500

#define	MAX_FRAME_SZ1	0x5EE
#define	MAX_FRAME_SZ2	0x5F6
#define	MAX_FRAME_SZ3	0x7D6
#define	MAX_FRAME_SZ4	0x232E
#define	MAX_FRAME_SZ5	0x2406

#define	XMAC_WAIT_REG(handle, portn, reg, val) {\
	uint32_t cnt = MAX_PIO_RETRIES;\
	do {\
		NXGE_DELAY(MAC_RESET_WAIT);\
		XMAC_REG_RD(handle, portn, reg, &val);\
		cnt--;\
	} while (((val & 0x3) != 0) && (cnt > 0));\
}

#define	BMAC_WAIT_REG(handle, portn, reg, val) {\
	uint32_t cnt = MAX_PIO_RETRIES;\
	do {\
		NXGE_DELAY(MAC_RESET_WAIT);\
		BMAC_REG_RD(handle, portn, reg, &val);\
		cnt--;\
	} while (((val & 0x3) != 0) && (cnt > 0));\
}

#define	MIF_WAIT_REG(handle, m_frame, t_delay, interval, max_delay) {	  \
	do {								  \
		NXGE_DELAY(interval);					  \
		MIF_REG_RD(handle, MIF_OUTPUT_FRAME_REG, &m_frame.value); \
		t_delay++;						  \
	} while ((m_frame.bits.w0.ta_lsb == 0) && t_delay < max_delay);	  \
}

uint64_t xmac_offset[] = {
	XTXMAC_SW_RST_REG,
	XRXMAC_SW_RST_REG,
	XTXMAC_STATUS_REG,
	XRXMAC_STATUS_REG,
	XMAC_CTRL_STAT_REG,
	XTXMAC_STAT_MSK_REG,
	XRXMAC_STAT_MSK_REG,
	XMAC_C_S_MSK_REG,
	XMAC_CONFIG_REG,
	XMAC_IPG_REG,
	XMAC_MIN_REG,
	XMAC_MAX_REG,
	XMAC_ADDR0_REG,
	XMAC_ADDR1_REG,
	XMAC_ADDR2_REG,
	XRXMAC_BT_CNT_REG,
	XRXMAC_BC_FRM_CNT_REG,
	XRXMAC_MC_FRM_CNT_REG,
	XRXMAC_FRAG_CNT_REG,
	XRXMAC_HIST_CNT1_REG,
	XRXMAC_HIST_CNT2_REG,
	XRXMAC_HIST_CNT3_REG,
	XRXMAC_HIST_CNT4_REG,
	XRXMAC_HIST_CNT5_REG,
	XRXMAC_HIST_CNT6_REG,
	XRXMAC_MPSZER_CNT_REG,
	XRXMAC_CRC_ER_CNT_REG,
	XRXMAC_CD_VIO_CNT_REG,
	XRXMAC_AL_ER_CNT_REG,
	XTXMAC_FRM_CNT_REG,
	XTXMAC_BYTE_CNT_REG,
	XMAC_LINK_FLT_CNT_REG,
	XRXMAC_HIST_CNT7_REG,
	XMAC_SM_REG,
	XMAC_INTERN1_REG,
	XMAC_INTERN2_REG,
	XMAC_ADDR_CMPEN_REG,
	XMAC_ADDR3_REG,
	XMAC_ADDR4_REG,
	XMAC_ADDR5_REG,
	XMAC_ADDR6_REG,
	XMAC_ADDR7_REG,
	XMAC_ADDR8_REG,
	XMAC_ADDR9_REG,
	XMAC_ADDR10_REG,
	XMAC_ADDR11_REG,
	XMAC_ADDR12_REG,
	XMAC_ADDR13_REG,
	XMAC_ADDR14_REG,
	XMAC_ADDR15_REG,
	XMAC_ADDR16_REG,
	XMAC_ADDR17_REG,
	XMAC_ADDR18_REG,
	XMAC_ADDR19_REG,
	XMAC_ADDR20_REG,
	XMAC_ADDR21_REG,
	XMAC_ADDR22_REG,
	XMAC_ADDR23_REG,
	XMAC_ADDR24_REG,
	XMAC_ADDR25_REG,
	XMAC_ADDR26_REG,
	XMAC_ADDR27_REG,
	XMAC_ADDR28_REG,
	XMAC_ADDR29_REG,
	XMAC_ADDR30_REG,
	XMAC_ADDR31_REG,
	XMAC_ADDR32_REG,
	XMAC_ADDR33_REG,
	XMAC_ADDR34_REG,
	XMAC_ADDR35_REG,
	XMAC_ADDR36_REG,
	XMAC_ADDR37_REG,
	XMAC_ADDR38_REG,
	XMAC_ADDR39_REG,
	XMAC_ADDR40_REG,
	XMAC_ADDR41_REG,
	XMAC_ADDR42_REG,
	XMAC_ADDR43_REG,
	XMAC_ADDR44_REG,
	XMAC_ADDR45_REG,
	XMAC_ADDR46_REG,
	XMAC_ADDR47_REG,
	XMAC_ADDR48_REG,
	XMAC_ADDR49_REG,
	XMAC_ADDR50_REG,
	XMAC_ADDR_FILT0_REG,
	XMAC_ADDR_FILT1_REG,
	XMAC_ADDR_FILT2_REG,
	XMAC_ADDR_FILT12_MASK_REG,
	XMAC_ADDR_FILT0_MASK_REG,
	XMAC_HASH_TBL0_REG,
	XMAC_HASH_TBL1_REG,
	XMAC_HASH_TBL2_REG,
	XMAC_HASH_TBL3_REG,
	XMAC_HASH_TBL4_REG,
	XMAC_HASH_TBL5_REG,
	XMAC_HASH_TBL6_REG,
	XMAC_HASH_TBL7_REG,
	XMAC_HASH_TBL8_REG,
	XMAC_HASH_TBL9_REG,
	XMAC_HASH_TBL10_REG,
	XMAC_HASH_TBL11_REG,
	XMAC_HASH_TBL12_REG,
	XMAC_HASH_TBL13_REG,
	XMAC_HASH_TBL14_REG,
	XMAC_HASH_TBL15_REG,
	XMAC_HOST_INF0_REG,
	XMAC_HOST_INF1_REG,
	XMAC_HOST_INF2_REG,
	XMAC_HOST_INF3_REG,
	XMAC_HOST_INF4_REG,
	XMAC_HOST_INF5_REG,
	XMAC_HOST_INF6_REG,
	XMAC_HOST_INF7_REG,
	XMAC_HOST_INF8_REG,
	XMAC_HOST_INF9_REG,
	XMAC_HOST_INF10_REG,
	XMAC_HOST_INF11_REG,
	XMAC_HOST_INF12_REG,
	XMAC_HOST_INF13_REG,
	XMAC_HOST_INF14_REG,
	XMAC_HOST_INF15_REG,
	XMAC_HOST_INF16_REG,
	XMAC_HOST_INF17_REG,
	XMAC_HOST_INF18_REG,
	XMAC_HOST_INF19_REG,
	XMAC_PA_DATA0_REG,
	XMAC_PA_DATA1_REG,
	XMAC_DEBUG_SEL_REG,
	XMAC_TRAINING_VECT_REG,
};

const char *xmac_name[] = {
	"XTXMAC_SW_RST_REG",
	"XRXMAC_SW_RST_REG",
	"XTXMAC_STATUS_REG",
	"XRXMAC_STATUS_REG",
	"XMAC_CTRL_STAT_REG",
	"XTXMAC_STAT_MSK_REG",
	"XRXMAC_STAT_MSK_REG",
	"XMAC_C_S_MSK_REG",
	"XMAC_CONFIG_REG",
	"XMAC_IPG_REG",
	"XMAC_MIN_REG",
	"XMAC_MAX_REG",
	"XMAC_ADDR0_REG",
	"XMAC_ADDR1_REG",
	"XMAC_ADDR2_REG",
	"XRXMAC_BT_CNT_REG",
	"XRXMAC_BC_FRM_CNT_REG",
	"XRXMAC_MC_FRM_CNT_REG",
	"XRXMAC_FRAG_CNT_REG",
	"XRXMAC_HIST_CNT1_REG",
	"XRXMAC_HIST_CNT2_REG",
	"XRXMAC_HIST_CNT3_REG",
	"XRXMAC_HIST_CNT4_REG",
	"XRXMAC_HIST_CNT5_REG",
	"XRXMAC_HIST_CNT6_REG",
	"XRXMAC_MPSZER_CNT_REG",
	"XRXMAC_CRC_ER_CNT_REG",
	"XRXMAC_CD_VIO_CNT_REG",
	"XRXMAC_AL_ER_CNT_REG",
	"XTXMAC_FRM_CNT_REG",
	"XTXMAC_BYTE_CNT_REG",
	"XMAC_LINK_FLT_CNT_REG",
	"XRXMAC_HIST_CNT7_REG",
	"XMAC_SM_REG",
	"XMAC_INTERN1_REG",
	"XMAC_INTERN2_REG",
	"XMAC_ADDR_CMPEN_REG",
	"XMAC_ADDR3_REG",
	"XMAC_ADDR4_REG",
	"XMAC_ADDR5_REG",
	"XMAC_ADDR6_REG",
	"XMAC_ADDR7_REG",
	"XMAC_ADDR8_REG",
	"XMAC_ADDR9_REG",
	"XMAC_ADDR10_REG",
	"XMAC_ADDR11_REG",
	"XMAC_ADDR12_REG",
	"XMAC_ADDR13_REG",
	"XMAC_ADDR14_REG",
	"XMAC_ADDR15_REG",
	"XMAC_ADDR16_REG",
	"XMAC_ADDR17_REG",
	"XMAC_ADDR18_REG",
	"XMAC_ADDR19_REG",
	"XMAC_ADDR20_REG",
	"XMAC_ADDR21_REG",
	"XMAC_ADDR22_REG",
	"XMAC_ADDR23_REG",
	"XMAC_ADDR24_REG",
	"XMAC_ADDR25_REG",
	"XMAC_ADDR26_REG",
	"XMAC_ADDR27_REG",
	"XMAC_ADDR28_REG",
	"XMAC_ADDR29_REG",
	"XMAC_ADDR30_REG",
	"XMAC_ADDR31_REG",
	"XMAC_ADDR32_REG",
	"XMAC_ADDR33_REG",
	"XMAC_ADDR34_REG",
	"XMAC_ADDR35_REG",
	"XMAC_ADDR36_REG",
	"XMAC_ADDR37_REG",
	"XMAC_ADDR38_REG",
	"XMAC_ADDR39_REG",
	"XMAC_ADDR40_REG",
	"XMAC_ADDR41_REG",
	"XMAC_ADDR42_REG",
	"XMAC_ADDR43_REG",
	"XMAC_ADDR44_REG",
	"XMAC_ADDR45_REG",
	"XMAC_ADDR46_REG",
	"XMAC_ADDR47_REG",
	"XMAC_ADDR48_REG",
	"XMAC_ADDR49_REG",
	"XMAC_ADDR50_RE",
	"XMAC_ADDR_FILT0_REG",
	"XMAC_ADDR_FILT1_REG",
	"XMAC_ADDR_FILT2_REG",
	"XMAC_ADDR_FILT12_MASK_REG",
	"XMAC_ADDR_FILT0_MASK_REG",
	"XMAC_HASH_TBL0_REG",
	"XMAC_HASH_TBL1_REG",
	"XMAC_HASH_TBL2_REG",
	"XMAC_HASH_TBL3_REG",
	"XMAC_HASH_TBL4_REG",
	"XMAC_HASH_TBL5_REG",
	"XMAC_HASH_TBL6_REG",
	"XMAC_HASH_TBL7_REG",
	"XMAC_HASH_TBL8_REG",
	"XMAC_HASH_TBL9_REG",
	"XMAC_HASH_TBL10_REG",
	"XMAC_HASH_TBL11_REG",
	"XMAC_HASH_TBL12_REG",
	"XMAC_HASH_TBL13_REG",
	"XMAC_HASH_TBL14_REG",
	"XMAC_HASH_TBL15_REG",
	"XMAC_HOST_INF0_REG",
	"XMAC_HOST_INF1_REG",
	"XMAC_HOST_INF2_REG",
	"XMAC_HOST_INF3_REG",
	"XMAC_HOST_INF4_REG",
	"XMAC_HOST_INF5_REG",
	"XMAC_HOST_INF6_REG",
	"XMAC_HOST_INF7_REG",
	"XMAC_HOST_INF8_REG",
	"XMAC_HOST_INF9_REG",
	"XMAC_HOST_INF10_REG",
	"XMAC_HOST_INF11_REG",
	"XMAC_HOST_INF12_REG",
	"XMAC_HOST_INF13_REG",
	"XMAC_HOST_INF14_REG",
	"XMAC_HOST_INF15_REG",
	"XMAC_HOST_INF16_REG",
	"XMAC_HOST_INF17_REG",
	"XMAC_HOST_INF18_REG",
	"XMAC_HOST_INF19_REG",
	"XMAC_PA_DATA0_REG",
	"XMAC_PA_DATA1_REG",
	"XMAC_DEBUG_SEL_REG",
	"XMAC_TRAINING_VECT_REG",
};

uint64_t bmac_offset[] = {
	BTXMAC_SW_RST_REG,
	BRXMAC_SW_RST_REG,
	MAC_SEND_PAUSE_REG,
	BTXMAC_STATUS_REG,
	BRXMAC_STATUS_REG,
	BMAC_CTRL_STAT_REG,
	BTXMAC_STAT_MSK_REG,
	BRXMAC_STAT_MSK_REG,
	BMAC_C_S_MSK_REG,
	TXMAC_CONFIG_REG,
	RXMAC_CONFIG_REG,
	MAC_CTRL_CONFIG_REG,
	MAC_XIF_CONFIG_REG,
	BMAC_MIN_REG,
	BMAC_MAX_REG,
	MAC_PA_SIZE_REG,
	MAC_CTRL_TYPE_REG,
	BMAC_ADDR0_REG,
	BMAC_ADDR1_REG,
	BMAC_ADDR2_REG,
	BMAC_ADDR3_REG,
	BMAC_ADDR4_REG,
	BMAC_ADDR5_REG,
	BMAC_ADDR6_REG,
	BMAC_ADDR7_REG,
	BMAC_ADDR8_REG,
	BMAC_ADDR9_REG,
	BMAC_ADDR10_REG,
	BMAC_ADDR11_REG,
	BMAC_ADDR12_REG,
	BMAC_ADDR13_REG,
	BMAC_ADDR14_REG,
	BMAC_ADDR15_REG,
	BMAC_ADDR16_REG,
	BMAC_ADDR17_REG,
	BMAC_ADDR18_REG,
	BMAC_ADDR19_REG,
	BMAC_ADDR20_REG,
	BMAC_ADDR21_REG,
	BMAC_ADDR22_REG,
	BMAC_ADDR23_REG,
	MAC_FC_ADDR0_REG,
	MAC_FC_ADDR1_REG,
	MAC_FC_ADDR2_REG,
	MAC_ADDR_FILT0_REG,
	MAC_ADDR_FILT1_REG,
	MAC_ADDR_FILT2_REG,
	MAC_ADDR_FILT12_MASK_REG,
	MAC_ADDR_FILT00_MASK_REG,
	MAC_HASH_TBL0_REG,
	MAC_HASH_TBL1_REG,
	MAC_HASH_TBL2_REG,
	MAC_HASH_TBL3_REG,
	MAC_HASH_TBL4_REG,
	MAC_HASH_TBL5_REG,
	MAC_HASH_TBL6_REG,
	MAC_HASH_TBL7_REG,
	MAC_HASH_TBL8_REG,
	MAC_HASH_TBL9_REG,
	MAC_HASH_TBL10_REG,
	MAC_HASH_TBL11_REG,
	MAC_HASH_TBL12_REG,
	MAC_HASH_TBL13_REG,
	MAC_HASH_TBL14_REG,
	MAC_HASH_TBL15_REG,
	RXMAC_FRM_CNT_REG,
	MAC_LEN_ER_CNT_REG,
	BMAC_AL_ER_CNT_REG,
	BMAC_CRC_ER_CNT_REG,
	BMAC_CD_VIO_CNT_REG,
	BMAC_SM_REG,
	BMAC_ALTAD_CMPEN_REG,
	BMAC_HOST_INF0_REG,
	BMAC_HOST_INF1_REG,
	BMAC_HOST_INF2_REG,
	BMAC_HOST_INF3_REG,
	BMAC_HOST_INF4_REG,
	BMAC_HOST_INF5_REG,
	BMAC_HOST_INF6_REG,
	BMAC_HOST_INF7_REG,
	BMAC_HOST_INF8_REG,
	BTXMAC_BYTE_CNT_REG,
	BTXMAC_FRM_CNT_REG,
	BRXMAC_BYTE_CNT_REG,
};

const char *bmac_name[] = {
	"BTXMAC_SW_RST_REG",
	"BRXMAC_SW_RST_REG",
	"MAC_SEND_PAUSE_REG",
	"BTXMAC_STATUS_REG",
	"BRXMAC_STATUS_REG",
	"BMAC_CTRL_STAT_REG",
	"BTXMAC_STAT_MSK_REG",
	"BRXMAC_STAT_MSK_REG",
	"BMAC_C_S_MSK_REG",
	"TXMAC_CONFIG_REG",
	"RXMAC_CONFIG_REG",
	"MAC_CTRL_CONFIG_REG",
	"MAC_XIF_CONFIG_REG",
	"BMAC_MIN_REG",
	"BMAC_MAX_REG",
	"MAC_PA_SIZE_REG",
	"MAC_CTRL_TYPE_REG",
	"BMAC_ADDR0_REG",
	"BMAC_ADDR1_REG",
	"BMAC_ADDR2_REG",
	"BMAC_ADDR3_REG",
	"BMAC_ADDR4_REG",
	"BMAC_ADDR5_REG",
	"BMAC_ADDR6_REG",
	"BMAC_ADDR7_REG",
	"BMAC_ADDR8_REG",
	"BMAC_ADDR9_REG",
	"BMAC_ADDR10_REG",
	"BMAC_ADDR11_REG",
	"BMAC_ADDR12_REG",
	"BMAC_ADDR13_REG",
	"BMAC_ADDR14_REG",
	"BMAC_ADDR15_REG",
	"BMAC_ADDR16_REG",
	"BMAC_ADDR17_REG",
	"BMAC_ADDR18_REG",
	"BMAC_ADDR19_REG",
	"BMAC_ADDR20_REG",
	"BMAC_ADDR21_REG",
	"BMAC_ADDR22_REG",
	"BMAC_ADDR23_REG",
	"MAC_FC_ADDR0_REG",
	"MAC_FC_ADDR1_REG",
	"MAC_FC_ADDR2_REG",
	"MAC_ADDR_FILT0_REG",
	"MAC_ADDR_FILT1_REG",
	"MAC_ADDR_FILT2_REG",
	"MAC_ADDR_FILT12_MASK_REG",
	"MAC_ADDR_FILT00_MASK_REG",
	"MAC_HASH_TBL0_REG",
	"MAC_HASH_TBL1_REG",
	"MAC_HASH_TBL2_REG",
	"MAC_HASH_TBL3_REG",
	"MAC_HASH_TBL4_REG",
	"MAC_HASH_TBL5_REG",
	"MAC_HASH_TBL6_REG",
	"MAC_HASH_TBL7_REG",
	"MAC_HASH_TBL8_REG",
	"MAC_HASH_TBL9_REG",
	"MAC_HASH_TBL10_REG",
	"MAC_HASH_TBL11_REG",
	"MAC_HASH_TBL12_REG",
	"MAC_HASH_TBL13_REG",
	"MAC_HASH_TBL14_REG",
	"MAC_HASH_TBL15_REG",
	"RXMAC_FRM_CNT_REG",
	"MAC_LEN_ER_CNT_REG",
	"BMAC_AL_ER_CNT_REG",
	"BMAC_CRC_ER_CNT_REG",
	"BMAC_CD_VIO_CNT_REG",
	"BMAC_SM_REG",
	"BMAC_ALTAD_CMPEN_REG",
	"BMAC_HOST_INF0_REG",
	"BMAC_HOST_INF1_REG",
	"BMAC_HOST_INF2_REG",
	"BMAC_HOST_INF3_REG",
	"BMAC_HOST_INF4_REG",
	"BMAC_HOST_INF5_REG",
	"BMAC_HOST_INF6_REG",
	"BMAC_HOST_INF7_REG",
	"BMAC_HOST_INF8_REG",
	"BTXMAC_BYTE_CNT_REG",
	"BTXMAC_FRM_CNT_REG",
	"BRXMAC_BYTE_CNT_REG",
};

npi_status_t
npi_mac_dump_regs(npi_handle_t handle, uint8_t port)
{

	uint64_t value;
	int num_regs, i;

	ASSERT(IS_PORT_NUM_VALID(port));

	switch (port) {
	case 0:
	case 1:
		num_regs = sizeof (xmac_offset) / sizeof (uint64_t);
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
		    "\nXMAC Register Dump for port %d\n",
		    port));
		for (i = 0; i < num_regs; i++) {
#if defined(__i386)
			XMAC_REG_RD(handle, port, (uint32_t)xmac_offset[i],
			    &value);
#else
			XMAC_REG_RD(handle, port, xmac_offset[i], &value);
#endif
			NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
			    "%08llx %s\t %08llx \n",
			    (XMAC_REG_ADDR((port), (xmac_offset[i]))),
			    xmac_name[i], value));
		}

		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
		    "\n XMAC Register Dump for port %d done\n",
		    port));
		break;

	case 2:
	case 3:
		num_regs = sizeof (bmac_offset) / sizeof (uint64_t);
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
		    "\nBMAC Register Dump for port %d\n",
		    port));
		for (i = 0; i < num_regs; i++) {
#if defined(__i386)
			BMAC_REG_RD(handle, port, (uint32_t)bmac_offset[i],
			    &value);
#else
			BMAC_REG_RD(handle, port, bmac_offset[i], &value);
#endif
			NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
			    "%08llx %s\t %08llx \n",
			    (BMAC_REG_ADDR((port), (bmac_offset[i]))),
			    bmac_name[i], value));
		}

		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
		    "\n BMAC Register Dump for port %d done\n",
		    port));
		break;
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_pcs_link_intr_enable(npi_handle_t handle, uint8_t portn)
{
	pcs_cfg_t pcs_cfg;

	ASSERT(IS_PORT_NUM_VALID(portn));

	PCS_REG_RD(handle, portn, PCS_CONFIG_REG, &pcs_cfg.value);
	pcs_cfg.bits.w0.mask = 0;
	PCS_REG_WR(handle, portn, PCS_CONFIG_REG, pcs_cfg.value);

	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_pcs_link_intr_disable(npi_handle_t handle, uint8_t portn)
{
	pcs_cfg_t pcs_cfg;

	ASSERT(IS_PORT_NUM_VALID(portn));

	PCS_REG_RD(handle, portn, PCS_CONFIG_REG, &pcs_cfg.val.lsw);
	pcs_cfg.bits.w0.mask = 1;
	PCS_REG_WR(handle, portn, PCS_CONFIG_REG, pcs_cfg.val.lsw);

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_xpcs_link_intr_enable(npi_handle_t handle, uint8_t portn)
{
	xpcs_stat1_t xpcs_mask1;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	XPCS_REG_RD(handle, portn, XPCS_MASK_1_REG, &xpcs_mask1.val.lsw);
	xpcs_mask1.bits.w0.csr_rx_link_stat = 1;
	XPCS_REG_WR(handle, portn, XPCS_MASK_1_REG, xpcs_mask1.val.lsw);

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_xpcs_link_intr_disable(npi_handle_t handle, uint8_t portn)
{
	xpcs_stat1_t xpcs_mask1;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	XPCS_REG_RD(handle, portn, XPCS_MASK_1_REG, &xpcs_mask1.val.lsw);
	xpcs_mask1.bits.w0.csr_rx_link_stat = 0;
	XPCS_REG_WR(handle, portn, XPCS_MASK_1_REG, xpcs_mask1.val.lsw);

	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_mif_link_intr_disable(npi_handle_t handle, uint8_t portn)
{
	mif_cfg_t mif_cfg;

	ASSERT(IS_PORT_NUM_VALID(portn));

	MIF_REG_RD(handle, MIF_CONFIG_REG, &mif_cfg.val.lsw);

	mif_cfg.bits.w0.phy_addr = portn;
	mif_cfg.bits.w0.poll_en = 0;

	MIF_REG_WR(handle, MIF_CONFIG_REG, mif_cfg.val.lsw);

	NXGE_DELAY(20);

	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_hashtab_entry(npi_handle_t handle, io_op_t op, uint8_t portn,
			uint8_t entryn, uint16_t *data)
{
	uint64_t val;

	ASSERT((op == OP_GET) || (op == OP_SET));
	ASSERT(IS_PORT_NUM_VALID(portn));

	ASSERT(entryn < MAC_MAX_HASH_ENTRY);
	if (entryn >= MAC_MAX_HASH_ENTRY) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_mac_hashtab_entry"
		    " Invalid Input: entryn <0x%x>",
		    entryn));
		return (NPI_FAILURE | NPI_MAC_HASHTAB_ENTRY_INVALID(portn));
	}

	if (op == OP_SET) {
		val = *data;
		if ((portn == XMAC_PORT_0) || (portn == XMAC_PORT_1)) {
			XMAC_REG_WR(handle, portn,
			    XMAC_HASH_TBLN_REG_ADDR(entryn), val);
		} else {
			BMAC_REG_WR(handle, portn,
			    BMAC_HASH_TBLN_REG_ADDR(entryn), val);
		}
	} else {
		if ((portn == XMAC_PORT_0) || (portn == XMAC_PORT_1)) {
			XMAC_REG_RD(handle, portn,
			    XMAC_HASH_TBLN_REG_ADDR(entryn), &val);
		} else {
			BMAC_REG_RD(handle, portn,
			    BMAC_HASH_TBLN_REG_ADDR(entryn), &val);
		}
		*data = val & 0xFFFF;
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_hostinfo_entry(npi_handle_t handle, io_op_t op, uint8_t portn,
				uint8_t entryn, hostinfo_t *hostinfo)
{
	ASSERT((op == OP_GET) || (op == OP_SET));
	ASSERT(IS_PORT_NUM_VALID(portn));

	if ((portn == XMAC_PORT_0) || (portn == XMAC_PORT_1)) {
		ASSERT(entryn < XMAC_MAX_HOST_INFO_ENTRY);
		if (entryn >= XMAC_MAX_HOST_INFO_ENTRY) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_mac_hostinfo_entry"
			    " Invalid Input: entryn <0x%x>",
			    entryn));
			return (NPI_FAILURE |
			    NPI_MAC_HOSTINFO_ENTRY_INVALID(portn));
		}
	} else {
		ASSERT(entryn < BMAC_MAX_HOST_INFO_ENTRY);
		if (entryn >= BMAC_MAX_HOST_INFO_ENTRY) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_mac_hostinfo_entry"
			    " Invalid Input: entryn <0x%x>",
			    entryn));
			return (NPI_FAILURE |
			    NPI_MAC_HOSTINFO_ENTRY_INVALID(portn));
		}
	}

	if (op == OP_SET) {
		if ((portn == XMAC_PORT_0) || (portn == XMAC_PORT_1)) {
			XMAC_REG_WR(handle, portn,
			    XMAC_HOST_INFN_REG_ADDR(entryn),
			    hostinfo->value);
		} else {
			BMAC_REG_WR(handle, portn,
			    BMAC_HOST_INFN_REG_ADDR(entryn),
			    hostinfo->value);
		}
	} else {
		if ((portn == XMAC_PORT_0) || (portn == XMAC_PORT_1)) {
			XMAC_REG_RD(handle, portn,
			    XMAC_HOST_INFN_REG_ADDR(entryn),
			    &hostinfo->value);
		} else {
			BMAC_REG_RD(handle, portn,
			    BMAC_HOST_INFN_REG_ADDR(entryn),
			    &hostinfo->value);
		}
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_altaddr_enable(npi_handle_t handle, uint8_t portn, uint8_t addrn)
{
	uint64_t val;

	ASSERT(IS_PORT_NUM_VALID(portn));

	if ((portn == XMAC_PORT_0) || (portn == XMAC_PORT_1)) {
		ASSERT(addrn <= XMAC_MAX_ALT_ADDR_ENTRY);
		if (addrn > XMAC_MAX_ALT_ADDR_ENTRY) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_mac_altaddr_enable"
			    " Invalid Input: addrn <0x%x>",
			    addrn));
			return (NPI_FAILURE |
			    NPI_MAC_ALT_ADDR_ENTRY_INVALID(portn));
		}
		XMAC_REG_RD(handle, portn, XMAC_ADDR_CMPEN_REG, &val);
		val |= (1 << addrn);
		XMAC_REG_WR(handle, portn, XMAC_ADDR_CMPEN_REG, val);
	} else {
		ASSERT(addrn <= BMAC_MAX_ALT_ADDR_ENTRY);
		if (addrn > BMAC_MAX_ALT_ADDR_ENTRY) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_mac_altaddr_enable"
			    " Invalid Input: addrn <0x%x>",
			    addrn));
			return (NPI_FAILURE |
			    NPI_MAC_ALT_ADDR_ENTRY_INVALID(portn));
		}
		BMAC_REG_RD(handle, portn, BMAC_ALTAD_CMPEN_REG, &val);
		val |= (1 << addrn);
		BMAC_REG_WR(handle, portn, BMAC_ALTAD_CMPEN_REG, val);
	}

	return (NPI_SUCCESS);
}

/*
 * While all bits of XMAC_ADDR_CMPEN_REG are for alternate MAC addresses,
 * bit0 of BMAC_ALTAD_CMPEN_REG is for unique MAC address.
 */
npi_status_t
npi_mac_altaddr_disable(npi_handle_t handle, uint8_t portn, uint8_t addrn)
{
	uint64_t val;

	ASSERT(IS_PORT_NUM_VALID(portn));

	if ((portn == XMAC_PORT_0) || (portn == XMAC_PORT_1)) {
		ASSERT(addrn <= XMAC_MAX_ALT_ADDR_ENTRY);
		if (addrn > XMAC_MAX_ALT_ADDR_ENTRY) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_mac_altaddr_disable"
			    " Invalid Input: addrn <0x%x>",
			    addrn));
			return (NPI_FAILURE |
			    NPI_MAC_ALT_ADDR_ENTRY_INVALID(portn));
		}
		XMAC_REG_RD(handle, portn, XMAC_ADDR_CMPEN_REG, &val);
		val &= ~(1 << addrn);
		XMAC_REG_WR(handle, portn, XMAC_ADDR_CMPEN_REG, val);
	} else {
		ASSERT(addrn <= BMAC_MAX_ALT_ADDR_ENTRY);
		if (addrn > BMAC_MAX_ALT_ADDR_ENTRY) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_mac_altaddr_disable"
			    " Invalid Input: addrn <0x%x>",
			    addrn));
			return (NPI_FAILURE |
			    NPI_MAC_ALT_ADDR_ENTRY_INVALID(portn));
		}
		BMAC_REG_RD(handle, portn, BMAC_ALTAD_CMPEN_REG, &val);
		val &= ~(1 << addrn);
		BMAC_REG_WR(handle, portn, BMAC_ALTAD_CMPEN_REG, val);
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_altaddr_entry(npi_handle_t handle, io_op_t op, uint8_t portn,
			uint8_t entryn, npi_mac_addr_t *data)
{
	uint64_t val0, val1, val2;

	ASSERT(IS_PORT_NUM_VALID(portn));
	ASSERT((op == OP_GET) || (op == OP_SET));

	if ((portn == XMAC_PORT_0) || (portn == XMAC_PORT_1)) {
		ASSERT(entryn <= XMAC_MAX_ALT_ADDR_ENTRY);
		if (entryn > XMAC_MAX_ALT_ADDR_ENTRY) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_mac_altaddr_entry"
			    " Invalid Input: entryn <0x%x>",
			    entryn));
			return (NPI_FAILURE |
			    NPI_MAC_ALT_ADDR_ENTRY_INVALID(portn));
		}
		if (op == OP_SET) {
			val0 = data->w0;
			val1 = data->w1;
			val2 = data->w2;
			XMAC_REG_WR(handle, portn,
			    XMAC_ALT_ADDR0N_REG_ADDR(entryn), val0);
			XMAC_REG_WR(handle, portn,
			    XMAC_ALT_ADDR1N_REG_ADDR(entryn), val1);
			XMAC_REG_WR(handle, portn,
			    XMAC_ALT_ADDR2N_REG_ADDR(entryn), val2);
		} else {
			XMAC_REG_RD(handle, portn,
			    XMAC_ALT_ADDR0N_REG_ADDR(entryn), &val0);
			XMAC_REG_RD(handle, portn,
			    XMAC_ALT_ADDR1N_REG_ADDR(entryn), &val1);
			XMAC_REG_RD(handle, portn,
			    XMAC_ALT_ADDR2N_REG_ADDR(entryn), &val2);
			data->w0 = val0 & 0xFFFF;
			data->w1 = val1 & 0xFFFF;
			data->w2 = val2 & 0xFFFF;
		}
	} else {
		ASSERT(entryn <= BMAC_MAX_ALT_ADDR_ENTRY);
		if (entryn > BMAC_MAX_ALT_ADDR_ENTRY) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_mac_altaddr_entry"
			    " Invalid Input: entryn <0x%x>",
			    entryn));
			return (NPI_FAILURE |
			    NPI_MAC_ALT_ADDR_ENTRY_INVALID(portn));
		}
		if (op == OP_SET) {
			val0 = data->w0;
			val1 = data->w1;
			val2 = data->w2;
			BMAC_REG_WR(handle, portn,
			    BMAC_ALT_ADDR0N_REG_ADDR(entryn), val0);
			BMAC_REG_WR(handle, portn,
			    BMAC_ALT_ADDR1N_REG_ADDR(entryn), val1);
			BMAC_REG_WR(handle, portn,
			    BMAC_ALT_ADDR2N_REG_ADDR(entryn), val2);
		} else {
			BMAC_REG_RD(handle, portn,
			    BMAC_ALT_ADDR0N_REG_ADDR(entryn), &val0);
			BMAC_REG_RD(handle, portn,
			    BMAC_ALT_ADDR1N_REG_ADDR(entryn), &val1);
			BMAC_REG_RD(handle, portn,
			    BMAC_ALT_ADDR2N_REG_ADDR(entryn), &val2);
			data->w0 = val0 & 0xFFFF;
			data->w1 = val1 & 0xFFFF;
			data->w2 = val2 & 0xFFFF;
		}
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_port_attr(npi_handle_t handle, io_op_t op, uint8_t portn,
			npi_attr_t *attrp)
{
	uint64_t val = 0;
	uint32_t attr;

	ASSERT(IS_PORT_NUM_VALID(portn));
	ASSERT((op == OP_GET) || (op == OP_SET));

	switch (attrp->type) {
	case MAC_PORT_MODE:
		switch (portn) {
		case XMAC_PORT_0:
		case XMAC_PORT_1:
			if (op == OP_SET) {
				attr = attrp->idata[0];
				ASSERT((attr == MAC_MII_MODE) ||	\
				    (attr == MAC_GMII_MODE) ||	\
				    (attr == MAC_XGMII_MODE));
				if ((attr != MAC_MII_MODE) &&
				    (attr != MAC_GMII_MODE) &&
				    (attr != MAC_XGMII_MODE)) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " Invalid Input:"
					    " MAC_PORT_MODE <0x%x>",
					    attr));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				XMAC_REG_RD(handle, portn, XMAC_CONFIG_REG,
				    &val);
				val &= ~XMAC_XIF_MII_MODE_MASK;
				switch (attr) {
				case MAC_MII_MODE:
					val |= (XMAC_XIF_MII_MODE <<
					    XMAC_XIF_MII_MODE_SHIFT);
					break;
				case MAC_GMII_MODE:
					val |= (XMAC_XIF_GMII_MODE <<
					    XMAC_XIF_MII_MODE_SHIFT);
					break;
				case MAC_XGMII_MODE:
					val |= (XMAC_XIF_XGMII_MODE <<
					    XMAC_XIF_MII_MODE_SHIFT);
					break;
				default:
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				XMAC_REG_WR(handle, portn, XMAC_CONFIG_REG,
				    val);
			} else {
				XMAC_REG_RD(handle, portn, XMAC_CONFIG_REG,
				    &val);
				val &= XMAC_XIF_MII_MODE_MASK;
				attr = val >> XMAC_XIF_MII_MODE_SHIFT;
				attrp->odata[0] = attr;
			}
			break;
		case BMAC_PORT_0:
		case BMAC_PORT_1:
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_mac_port_attr"
			    " Invalid Input:"
			    " MAC_PORT_MODE <0x%x>",
			    attrp->type));
			return (NPI_FAILURE |
			    NPI_MAC_PORT_ATTR_INVALID(portn));
		default:
			return (NPI_FAILURE | NPI_MAC_PORT_INVALID(portn));
		}
		break;

	case MAC_PORT_FRAME_SIZE: {
		uint32_t min_fsize;
		uint32_t max_fsize;

		switch (portn) {
		case XMAC_PORT_0:
		case XMAC_PORT_1:
			if (op == OP_SET) {
				min_fsize = attrp->idata[0];
				max_fsize = attrp->idata[1];
				ASSERT((min_fsize &	\
				    ~XMAC_MIN_TX_FRM_SZ_MASK) == 0);
				if ((min_fsize & ~XMAC_MIN_TX_FRM_SZ_MASK)
				    != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_PORT_FRAME_SIZE:"
					    " Invalid Input:"
					    " xmac_min_fsize <0x%x>",
					    min_fsize));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				ASSERT((max_fsize &	\
				    ~XMAC_MAX_FRM_SZ_MASK) == 0);
				if ((max_fsize & ~XMAC_MAX_FRM_SZ_MASK)
				    != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_PORT_FRAME_SIZE:"
					    " Invalid Input:"
					    " xmac_max_fsize <0x%x>",
					    max_fsize));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				XMAC_REG_RD(handle, portn, XMAC_MIN_REG, &val);
				val &= ~(XMAC_MIN_TX_FRM_SZ_MASK |
				    XMAC_MIN_RX_FRM_SZ_MASK);
				val |= (min_fsize << XMAC_MIN_TX_FRM_SZ_SHIFT);
				val |= (min_fsize << XMAC_MIN_RX_FRM_SZ_SHIFT);
				XMAC_REG_WR(handle, portn, XMAC_MIN_REG, val);
				XMAC_REG_WR(handle, portn, XMAC_MAX_REG,
				    max_fsize);
			} else {
				XMAC_REG_RD(handle, portn, XMAC_MIN_REG, &val);
				min_fsize = (val & XMAC_MIN_TX_FRM_SZ_MASK)
				    >> XMAC_MIN_TX_FRM_SZ_SHIFT;
				XMAC_REG_RD(handle, portn, XMAC_MAX_REG, &val);
				attrp->odata[0] = min_fsize;
				attrp->odata[1] = max_fsize;
			}
			break;
		case BMAC_PORT_0:
		case BMAC_PORT_1:
			if (op == OP_SET) {
				min_fsize = attrp->idata[0];
				max_fsize = attrp->idata[1];
				ASSERT((min_fsize & ~BMAC_MIN_FRAME_MASK) == 0);
				if ((min_fsize & ~BMAC_MIN_FRAME_MASK)
				    != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_FRAME_SIZE:"
					    " Invalid Input:"
					    " bmac_min_fsize <0x%x>",
					    min_fsize));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				ASSERT((max_fsize & ~BMAC_MAX_FRAME_MASK) == 0);
				if ((max_fsize & ~BMAC_MAX_FRAME_MASK)
				    != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_FRAME_SIZE:"
					    " Invalid Input:"
					    " bmac_max_fsize <0x%x>",
					    max_fsize));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				BMAC_REG_RD(handle, portn, BMAC_MAX_REG, &val);
				val &= ~BMAC_MAX_FRAME_MASK;
				if (max_fsize <= MAX_FRAME_SZ1)
					val |= MAX_FRAME_SZ1;
				else if ((max_fsize > MAX_FRAME_SZ1) &&
				    (max_fsize <= MAX_FRAME_SZ2))
					val |= MAX_FRAME_SZ2;
				else if ((max_fsize > MAX_FRAME_SZ2) &&
				    (max_fsize <= MAX_FRAME_SZ3))
					val |= MAX_FRAME_SZ3;
				else if ((max_fsize > MAX_FRAME_SZ3) &&
				    (max_fsize <= MAX_FRAME_SZ4))
					val |= MAX_FRAME_SZ4;
				else if ((max_fsize > MAX_FRAME_SZ4) &&
				    (max_fsize <= MAX_FRAME_SZ5))
					val |= MAX_FRAME_SZ5;
				BMAC_REG_WR(handle, portn, BMAC_MAX_REG, val);
				BMAC_REG_WR(handle, portn, BMAC_MIN_REG,
				    min_fsize);
			} else {
				BMAC_REG_RD(handle, portn, BMAC_MIN_REG, &val);
				min_fsize = val & BMAC_MIN_FRAME_MASK;
				BMAC_REG_RD(handle, portn, BMAC_MAX_REG, &val);
				max_fsize = val & BMAC_MAX_FRAME_MASK;
				attrp->odata[0] = min_fsize;
				attrp->odata[1] = max_fsize;
			}
			break;
		default:
			return (NPI_FAILURE | NPI_MAC_PORT_INVALID(portn));
		}
		break;
	}

	case BMAC_PORT_MAX_BURST_SIZE: {
		uint32_t burst_size;
		switch (portn) {
		case XMAC_PORT_0:
		case XMAC_PORT_1:
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_mac_port_attr"
			    " BMAC_PORT_MAX_BURST_SIZE:"
			    " Invalid Input: portn <%d>",
			    portn));
			return (NPI_FAILURE | NPI_MAC_PORT_ATTR_INVALID(portn));
		case BMAC_PORT_0:
		case BMAC_PORT_1:
			/* NOTE: Not used in Full duplex mode */
			if (op == OP_SET) {
				burst_size = attrp->idata[0];
				ASSERT((burst_size & ~0x7FFF) == 0);
				if ((burst_size & ~0x7FFF) != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " BMAC_MAX_BURST_SIZE:"
					    " Invalid Input:"
					    " burst_size <0x%x>",
					    burst_size));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				BMAC_REG_RD(handle, portn, BMAC_MAX_REG, &val);
				val &= ~BMAC_MAX_BURST_MASK;
				val |= (burst_size << BMAC_MAX_BURST_SHIFT);
				BMAC_REG_WR(handle, portn, BMAC_MAX_REG, val);
			} else {
				BMAC_REG_RD(handle, portn, BMAC_MAX_REG, &val);
				burst_size = (val & BMAC_MAX_BURST_MASK)
				    >> BMAC_MAX_BURST_SHIFT;
				attrp->odata[0] = burst_size;
			}
			break;
		default:
			return (NPI_FAILURE | NPI_MAC_PORT_INVALID(portn));
		}
		break;
	}

	case BMAC_PORT_PA_SIZE: {
		uint32_t pa_size;
		switch (portn) {
		case XMAC_PORT_0:
		case XMAC_PORT_1:
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_mac_port_attr"
			    " BMAC_PORT_PA_SIZE:"
			    " Invalid Input: portn <%d>",
			    portn));
			return (NPI_FAILURE | NPI_MAC_PORT_ATTR_INVALID(portn));
		case BMAC_PORT_0:
		case BMAC_PORT_1:
			if (op == OP_SET) {
				pa_size = attrp->idata[0];
				ASSERT((pa_size & ~0x3FF) == 0);
				if ((pa_size & ~0x3FF) != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " BMAC_PORT_PA_SIZE:"
					    " Invalid Input: pa_size <0x%x>",
					    pa_size));

					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				BMAC_REG_RD(handle, portn, MAC_PA_SIZE_REG,
				    &val);
				val &= ~BMAC_PA_SIZE_MASK;
				val |= (pa_size << 0);
				BMAC_REG_WR(handle, portn, MAC_PA_SIZE_REG,
				    val);
			} else {
				BMAC_REG_RD(handle, portn, MAC_PA_SIZE_REG,
				    &val);
				pa_size = (val & BMAC_PA_SIZE_MASK) >> 0;
				attrp->odata[0] = pa_size;
			}
			break;
		default:
			return (NPI_FAILURE | NPI_MAC_PORT_INVALID(portn));
		}
		break;
	}

	case BMAC_PORT_CTRL_TYPE: {
		uint32_t ctrl_type;
		switch (portn) {
		case XMAC_PORT_0:
		case XMAC_PORT_1:
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_mac_port_attr"
			    " BMAC_PORT_CTRL_TYPE:"
			    " Invalid Input: portn <%d>",
			    portn));
			return (NPI_FAILURE | NPI_MAC_PORT_ATTR_INVALID(portn));
		case BMAC_PORT_0:
		case BMAC_PORT_1:
			if (op == OP_SET) {
				ctrl_type = attrp->idata[0];
				ASSERT((ctrl_type & ~0xFFFF) == 0);
				if ((ctrl_type & ~0xFFFF) != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " BMAC_PORT_CTRL_TYPE:"
					    " Invalid Input:"
					    " ctrl_type <0x%x>",
					    ctrl_type));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				BMAC_REG_WR(handle, portn, MAC_CTRL_TYPE_REG,
				    val);
			} else {
				BMAC_REG_RD(handle, portn, MAC_CTRL_TYPE_REG,
				    &val);
				ctrl_type = (val & 0xFFFF);
				attrp->odata[0] = ctrl_type;
			}
			break;
		default:
			return (NPI_FAILURE | NPI_MAC_PORT_INVALID(portn));
		}
		break;
	}

	case XMAC_10G_PORT_IPG:
		{
		uint32_t	ipg0;

		switch (portn) {
		case XMAC_PORT_0:
		case XMAC_PORT_1:
			if (op == OP_SET) {
				ipg0 = attrp->idata[0];
				ASSERT((ipg0 == XGMII_IPG_12_15) ||	\
				    (ipg0 == XGMII_IPG_16_19) ||	\
				    (ipg0 == XGMII_IPG_20_23));
				if ((ipg0 != XGMII_IPG_12_15) &&
				    (ipg0 != XGMII_IPG_16_19) &&
				    (ipg0 != XGMII_IPG_20_23)) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_10G_PORT_IPG:"
					    " Invalid Input:"
					    " xgmii_ipg <0x%x>",
					    ipg0));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}

				XMAC_REG_RD(handle, portn, XMAC_IPG_REG, &val);
				val &= ~(XMAC_IPG_VALUE_MASK |
				    XMAC_IPG_VALUE1_MASK);

				switch (ipg0) {
				case XGMII_IPG_12_15:
					val |= (IPG_12_15_BYTE <<
					    XMAC_IPG_VALUE_SHIFT);
					break;
				case XGMII_IPG_16_19:
					val |= (IPG_16_19_BYTE <<
					    XMAC_IPG_VALUE_SHIFT);
					break;
				case XGMII_IPG_20_23:
					val |= (IPG_20_23_BYTE <<
					    XMAC_IPG_VALUE_SHIFT);
					break;
				default:
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				XMAC_REG_WR(handle, portn, XMAC_IPG_REG, val);
			} else {
				XMAC_REG_RD(handle, portn, XMAC_IPG_REG, &val);
				ipg0 = (val & XMAC_IPG_VALUE_MASK) >>
				    XMAC_IPG_VALUE_SHIFT;
				switch (ipg0) {
				case IPG_12_15_BYTE:
					attrp->odata[0] = XGMII_IPG_12_15;
					break;
				case IPG_16_19_BYTE:
					attrp->odata[0] = XGMII_IPG_16_19;
					break;
				case IPG_20_23_BYTE:
					attrp->odata[0] = XGMII_IPG_20_23;
					break;
				default:
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
			}
			break;
		case BMAC_PORT_0:
		case BMAC_PORT_1:
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_mac_port_attr" "MAC_PORT_IPG:"
			    "  Invalid Input: portn <%d>",
			    portn));
			/* FALLTHROUGH */
		default:
			return (NPI_FAILURE | NPI_MAC_PORT_INVALID(portn));
		}
		break;
	}

	case XMAC_PORT_IPG:
		{
		uint32_t	ipg1;
		switch (portn) {
		case XMAC_PORT_0:
		case XMAC_PORT_1:
			if (op == OP_SET) {
				ipg1 = attrp->idata[0];
				ASSERT((ipg1 == MII_GMII_IPG_12) ||	\
				    (ipg1 == MII_GMII_IPG_13) ||	\
				    (ipg1 == MII_GMII_IPG_14) ||	\
				    (ipg1 == MII_GMII_IPG_15) ||	\
				    (ipg1 == MII_GMII_IPG_16));
				if ((ipg1 != MII_GMII_IPG_12) &&
				    (ipg1 != MII_GMII_IPG_13) &&
				    (ipg1 != MII_GMII_IPG_14) &&
				    (ipg1 != MII_GMII_IPG_15) &&
				    (ipg1 != MII_GMII_IPG_16)) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " XMAC_PORT_IPG:"
					    " Invalid Input:"
					    " mii_gmii_ipg <0x%x>",
					    ipg1));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}

				XMAC_REG_RD(handle, portn, XMAC_IPG_REG, &val);
				val &= ~(XMAC_IPG_VALUE_MASK |
				    XMAC_IPG_VALUE1_MASK);

				switch (ipg1) {
				case MII_GMII_IPG_12:
					val |= (IPG1_12_BYTES <<
					    XMAC_IPG_VALUE1_SHIFT);
					break;
				case MII_GMII_IPG_13:
					val |= (IPG1_13_BYTES <<
					    XMAC_IPG_VALUE1_SHIFT);
					break;
				case MII_GMII_IPG_14:
					val |= (IPG1_14_BYTES <<
					    XMAC_IPG_VALUE1_SHIFT);
					break;
				case MII_GMII_IPG_15:
					val |= (IPG1_15_BYTES <<
					    XMAC_IPG_VALUE1_SHIFT);
					break;
				case MII_GMII_IPG_16:
					val |= (IPG1_16_BYTES <<
					    XMAC_IPG_VALUE1_SHIFT);
					break;
				default:
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				XMAC_REG_WR(handle, portn, XMAC_IPG_REG, val);
			} else {
				XMAC_REG_RD(handle, portn, XMAC_IPG_REG, &val);
				ipg1 = (val & XMAC_IPG_VALUE1_MASK) >>
				    XMAC_IPG_VALUE1_SHIFT;
				switch (ipg1) {
				case IPG1_12_BYTES:
					attrp->odata[1] = MII_GMII_IPG_12;
					break;
				case IPG1_13_BYTES:
					attrp->odata[1] = MII_GMII_IPG_13;
					break;
				case IPG1_14_BYTES:
					attrp->odata[1] = MII_GMII_IPG_14;
					break;
				case IPG1_15_BYTES:
					attrp->odata[1] = MII_GMII_IPG_15;
					break;
				case IPG1_16_BYTES:
					attrp->odata[1] = MII_GMII_IPG_16;
					break;
				default:
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
			}
			break;
		case BMAC_PORT_0:
		case BMAC_PORT_1:
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_mac_port_attr"
			    " MAC_PORT_IPG:"
			    " Invalid Input: portn <%d>",
			    portn));
			/* FALLTHROUGH */
		default:
			return (NPI_FAILURE | NPI_MAC_PORT_INVALID(portn));
		}
		break;
	}

	case MAC_PORT_ADDR: {
		uint32_t addr0;
		uint32_t addr1;
		uint32_t addr2;

		switch (portn) {
		case XMAC_PORT_0:
		case XMAC_PORT_1:
			if (op == OP_SET) {
				addr0 = attrp->idata[0];
				addr1 = attrp->idata[1];
				addr2 = attrp->idata[2];
				ASSERT((addr0 & ~0xFFFF) == 0);
				if ((addr0 & ~0xFFFF) != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_PORT_ADDR:"
					    " Invalid Input:"
					    " addr0 <0x%x>", addr0));

					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				ASSERT((addr1 & ~0xFFFF) == 0);
				if ((addr1 & ~0xFFFF) != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_PORT_ADDR:"
					    " Invalid Input:"
					    " addr1 <0x%x>", addr1));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				ASSERT((addr2 & ~0xFFFF) == 0);
				if ((addr2 & ~0xFFFF) != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_PORT_ADDR:"
					    " Invalid Input:"
					    " addr2 <0x%x.",
					    addr2));

					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				XMAC_REG_WR(handle, portn, XMAC_ADDR0_REG,
				    addr0);
				XMAC_REG_WR(handle, portn, XMAC_ADDR1_REG,
				    addr1);
				XMAC_REG_WR(handle, portn, XMAC_ADDR2_REG,
				    addr2);
			} else {
				XMAC_REG_RD(handle, portn, XMAC_ADDR0_REG,
				    &addr0);
				XMAC_REG_RD(handle, portn, XMAC_ADDR1_REG,
				    &addr1);
				XMAC_REG_RD(handle, portn, XMAC_ADDR2_REG,
				    &addr2);
				attrp->odata[0] = addr0 & MAC_ADDR_REG_MASK;
				attrp->odata[1] = addr1 & MAC_ADDR_REG_MASK;
				attrp->odata[2] = addr2 & MAC_ADDR_REG_MASK;
			}
			break;
		case BMAC_PORT_0:
		case BMAC_PORT_1:
			if (op == OP_SET) {
				addr0 = attrp->idata[0];
				addr1 = attrp->idata[1];
				addr2 = attrp->idata[2];
				ASSERT((addr0 & ~0xFFFF) == 0);
				if ((addr0 & ~0xFFFF) != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_PORT_ADDR:"
					    " Invalid Input:"
					    " addr0 <0x%x>",
					    addr0));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				ASSERT((addr1 & ~0xFFFF) == 0);
				if ((addr1 & ~0xFFFF) != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_PORT_ADDR:"
					    " Invalid Input:"
					    " addr1 <0x%x>",
					    addr1));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				ASSERT((addr2 & ~0xFFFF) == 0);
				if ((addr2 & ~0xFFFF) != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_PORT_ADDR:"
					    " Invalid Input:"
					    " addr2 <0x%x>",
					    addr2));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				BMAC_REG_WR(handle, portn, BMAC_ADDR0_REG,
				    addr0);
				BMAC_REG_WR(handle, portn, BMAC_ADDR1_REG,
				    addr1);
				BMAC_REG_WR(handle, portn, BMAC_ADDR2_REG,
				    addr2);
			} else {
				BMAC_REG_RD(handle, portn, BMAC_ADDR0_REG,
				    &addr0);
				BMAC_REG_RD(handle, portn, BMAC_ADDR1_REG,
				    &addr1);
				BMAC_REG_RD(handle, portn, BMAC_ADDR2_REG,
				    &addr2);
				attrp->odata[0] = addr0 & MAC_ADDR_REG_MASK;
				attrp->odata[1] = addr1 & MAC_ADDR_REG_MASK;
				attrp->odata[2] = addr2 & MAC_ADDR_REG_MASK;
			}
			break;
		default:
			return (NPI_FAILURE | NPI_MAC_PORT_INVALID(portn));
		}
		break;
	}

	case MAC_PORT_ADDR_FILTER: {
		uint32_t addr0;
		uint32_t addr1;
		uint32_t addr2;

		switch (portn) {
		case XMAC_PORT_0:
		case XMAC_PORT_1:
			if (op == OP_SET) {
				addr0 = attrp->idata[0];
				addr1 = attrp->idata[1];
				addr2 = attrp->idata[2];
				ASSERT((addr0 & ~0xFFFF) == 0);
				if ((addr0 & ~0xFFFF) != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_PORT_ADDR_FILTER:"
					    " Invalid Input:"
					    " addr0 <0x%x>",
					    addr0));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				ASSERT((addr1 & ~0xFFFF) == 0);
				if ((addr1 & ~0xFFFF) != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_PORT_ADDR_FILTER:"
					    " Invalid Input:"
					    " addr1 <0x%x>",
					    addr1));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				ASSERT((addr2 & ~0xFFFF) == 0);
				if ((addr2 & ~0xFFFF) != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_PORT_ADDR_FILTER:"
					    " Invalid Input:"
					    " addr2 <0x%x>",
					    addr2));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				XMAC_REG_WR(handle, portn,
				    XMAC_ADDR_FILT0_REG, addr0);
				XMAC_REG_WR(handle, portn,
				    XMAC_ADDR_FILT1_REG, addr1);
				XMAC_REG_WR(handle, portn,
				    XMAC_ADDR_FILT2_REG, addr2);
			} else {
				XMAC_REG_RD(handle, portn,
				    XMAC_ADDR_FILT0_REG, &addr0);
				XMAC_REG_RD(handle, portn,
				    XMAC_ADDR_FILT1_REG, &addr1);
				XMAC_REG_RD(handle, portn,
				    XMAC_ADDR_FILT2_REG, &addr2);
				attrp->odata[0] = addr0 & MAC_ADDR_REG_MASK;
				attrp->odata[1] = addr1 & MAC_ADDR_REG_MASK;
				attrp->odata[2] = addr2 & MAC_ADDR_REG_MASK;
			}
			break;
		case BMAC_PORT_0:
		case BMAC_PORT_1:
			if (op == OP_SET) {
				addr0 = attrp->idata[0];
				addr1 = attrp->idata[1];
				addr2 = attrp->idata[2];
				ASSERT((addr0 & ~0xFFFF) == 0);
				if ((addr0 & ~0xFFFF) != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_PORT_ADDR_FILTER:"
					    " addr0",
					    addr0));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				ASSERT((addr1 & ~0xFFFF) == 0);
				if ((addr1 & ~0xFFFF) != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_PORT_ADDR_FILTER:"
					    " Invalid Input:"
					    " addr1 <0x%x>",
					    addr1));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				ASSERT((addr2 & ~0xFFFF) == 0);
				if ((addr2 & ~0xFFFF) != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_PORT_ADDR_FILTER:"
					    " Invalid Input:"
					    " addr2 <0x%x>",
					    addr2));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				BMAC_REG_WR(handle, portn, MAC_ADDR_FILT0_REG,
				    addr0);
				BMAC_REG_WR(handle, portn, MAC_ADDR_FILT1_REG,
				    addr1);
				BMAC_REG_WR(handle, portn, MAC_ADDR_FILT2_REG,
				    addr2);
			} else {
				BMAC_REG_RD(handle, portn, MAC_ADDR_FILT0_REG,
				    &addr0);
				BMAC_REG_RD(handle, portn, MAC_ADDR_FILT1_REG,
				    &addr1);
				BMAC_REG_RD(handle, portn, MAC_ADDR_FILT2_REG,
				    &addr2);
				attrp->odata[0] = addr0 & MAC_ADDR_REG_MASK;
				attrp->odata[1] = addr1 & MAC_ADDR_REG_MASK;
				attrp->odata[2] = addr2 & MAC_ADDR_REG_MASK;
			}
			break;
		default:
			return (NPI_FAILURE | NPI_MAC_PORT_INVALID(portn));
		}
		break;
	}

	case MAC_PORT_ADDR_FILTER_MASK: {
		uint32_t mask_1_2;
		uint32_t mask_0;

		switch (portn) {
		case XMAC_PORT_0:
		case XMAC_PORT_1:
			if (op == OP_SET) {
				mask_0 = attrp->idata[0];
				mask_1_2 = attrp->idata[1];
				ASSERT((mask_0 & ~0xFFFF) == 0);
				if ((mask_0 & ~0xFFFF) != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_ADDR_FILTER_MASK:"
					    " Invalid Input:"
					    " mask_0 <0x%x>",
					    mask_0));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				ASSERT((mask_1_2 & ~0xFF) == 0);
				if ((mask_1_2 & ~0xFF) != 0) {
					NPI_ERROR_MSG((handle.function,
					    NPI_ERR_CTL,
					    " npi_mac_port_attr"
					    " MAC_ADDR_FILTER_MASK:"
					    " Invalid Input:"
					    " mask_1_2 <0x%x>",
					    mask_1_2));
					return (NPI_FAILURE |
					    NPI_MAC_PORT_ATTR_INVALID(portn));
				}
				XMAC_REG_WR(handle, portn,
				    XMAC_ADDR_FILT0_MASK_REG, mask_0);
				XMAC_REG_WR(handle, portn,
				    XMAC_ADDR_FILT12_MASK_REG, mask_1_2);
			} else {
				XMAC_REG_RD(handle, portn,
				    XMAC_ADDR_FILT0_MASK_REG, &mask_0);
				XMAC_REG_RD(handle, portn,
				    XMAC_ADDR_FILT12_MASK_REG, &mask_1_2);
				attrp->odata[0] = mask_0 & 0xFFFF;
				attrp->odata[1] = mask_1_2 & 0xFF;
			}
			break;
		case BMAC_PORT_0:
		case BMAC_PORT_1:
			if (op == OP_SET) {
				mask_0 = attrp->idata[0];
				mask_1_2 = attrp->idata[1];
				BMAC_REG_WR(handle, portn,
				    MAC_ADDR_FILT00_MASK_REG, mask_0);
				BMAC_REG_WR(handle, portn,
				    MAC_ADDR_FILT12_MASK_REG, mask_1_2);
			} else {
				BMAC_REG_RD(handle, portn,
				    MAC_ADDR_FILT00_MASK_REG, &mask_0);
				BMAC_REG_RD(handle, portn,
				    MAC_ADDR_FILT12_MASK_REG, &mask_1_2);
				attrp->odata[0] = mask_0;
				attrp->odata[1] = mask_1_2;
			}
			break;
		default:
			return (NPI_FAILURE | NPI_MAC_PORT_INVALID(portn));
		}
		break;
	}

	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_mac_port_attr"
		    " Invalid Input:"
		    " attr <0x%x>", attrp->type));
		return (NPI_FAILURE | NPI_MAC_PORT_ATTR_INVALID(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_reset(npi_handle_t handle, uint8_t portn, npi_mac_reset_t mode)
{
	uint64_t val;
	boolean_t txmac = B_FALSE;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	switch (mode) {
	case XTX_MAC_REG_RESET:
		XMAC_REG_WR(handle, portn, XTXMAC_SW_RST_REG, XTXMAC_REG_RST);
		XMAC_WAIT_REG(handle, portn, XTXMAC_SW_RST_REG, val);
		txmac = B_TRUE;
		break;
	case XRX_MAC_REG_RESET:
		XMAC_REG_WR(handle, portn, XRXMAC_SW_RST_REG, XRXMAC_REG_RST);
		XMAC_WAIT_REG(handle, portn, XRXMAC_SW_RST_REG, val);
		break;
	case XTX_MAC_LOGIC_RESET:
		XMAC_REG_WR(handle, portn, XTXMAC_SW_RST_REG, XTXMAC_SOFT_RST);
		XMAC_WAIT_REG(handle, portn, XTXMAC_SW_RST_REG, val);
		txmac = B_TRUE;
		break;
	case XRX_MAC_LOGIC_RESET:
		XMAC_REG_WR(handle, portn, XRXMAC_SW_RST_REG, XRXMAC_SOFT_RST);
		XMAC_WAIT_REG(handle, portn, XRXMAC_SW_RST_REG, val);
		break;
	case XTX_MAC_RESET_ALL:
		XMAC_REG_WR(handle, portn, XTXMAC_SW_RST_REG,
		    XTXMAC_SOFT_RST | XTXMAC_REG_RST);
		XMAC_WAIT_REG(handle, portn, XTXMAC_SW_RST_REG, val);
		txmac = B_TRUE;
		break;
	case XRX_MAC_RESET_ALL:
		XMAC_REG_WR(handle, portn, XRXMAC_SW_RST_REG,
		    XRXMAC_SOFT_RST | XRXMAC_REG_RST);
		XMAC_WAIT_REG(handle, portn, XRXMAC_SW_RST_REG, val);
		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_mac_reset"
		    " Invalid Input: mode <0x%x>",
		    mode));
		return (NPI_FAILURE | NPI_MAC_RESET_MODE_INVALID(portn));
	}

	if (val != 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_xmac_reset"
		    " HW ERROR: MAC_RESET  failed <0x%x>",
		    val));

		if (txmac)
			return (NPI_FAILURE | NPI_TXMAC_RESET_FAILED(portn));
		else
			return (NPI_FAILURE | NPI_RXMAC_RESET_FAILED(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_xif_config(npi_handle_t handle, config_op_t op, uint8_t portn,
			xmac_xif_config_t config)
{
	uint64_t val = 0;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	switch (op) {
	case ENABLE:
	case DISABLE:
		ASSERT((config != 0) && ((config & ~CFG_XMAC_XIF_ALL) == 0));
		if ((config == 0) || (config & ~CFG_XMAC_XIF_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_xmac_xif_config"
			    " Invalid Input:"
			    " config <0x%x>", config));
			return (NPI_FAILURE | NPI_MAC_OPCODE_INVALID(portn));
		}
		if (op == ENABLE) {
			XMAC_REG_RD(handle, portn, XMAC_CONFIG_REG, &val);
			if (config & CFG_XMAC_XIF_LED_FORCE)
				val |= XMAC_XIF_FORCE_LED_ON;
			if (config & CFG_XMAC_XIF_LED_POLARITY)
				val |= XMAC_XIF_LED_POLARITY;
			if (config & CFG_XMAC_XIF_SEL_POR_CLK_SRC)
				val |= XMAC_XIF_SEL_POR_CLK_SRC;
			if (config & CFG_XMAC_XIF_TX_OUTPUT)
				val |= XMAC_XIF_TX_OUTPUT_EN;

			if (config & CFG_XMAC_XIF_LOOPBACK) {
				val &= ~XMAC_XIF_SEL_POR_CLK_SRC;
				val |= XMAC_XIF_LOOPBACK;
			}

			if (config & CFG_XMAC_XIF_LFS)
				val &= ~XMAC_XIF_LFS_DISABLE;
			if (config & CFG_XMAC_XIF_XPCS_BYPASS)
				val |= XMAC_XIF_XPCS_BYPASS;
			if (config & CFG_XMAC_XIF_1G_PCS_BYPASS)
				val |= XMAC_XIF_1G_PCS_BYPASS;
			if (config & CFG_XMAC_XIF_SEL_CLK_25MHZ)
				val |= XMAC_XIF_SEL_CLK_25MHZ;
			XMAC_REG_WR(handle, portn, XMAC_CONFIG_REG, val);

		} else {
			XMAC_REG_RD(handle, portn, XMAC_CONFIG_REG, &val);
			if (config & CFG_XMAC_XIF_LED_FORCE)
				val &= ~XMAC_XIF_FORCE_LED_ON;
			if (config & CFG_XMAC_XIF_LED_POLARITY)
				val &= ~XMAC_XIF_LED_POLARITY;
			if (config & CFG_XMAC_XIF_SEL_POR_CLK_SRC)
				val &= ~XMAC_XIF_SEL_POR_CLK_SRC;
			if (config & CFG_XMAC_XIF_TX_OUTPUT)
				val &= ~XMAC_XIF_TX_OUTPUT_EN;
			if (config & CFG_XMAC_XIF_LOOPBACK)
				val &= ~XMAC_XIF_LOOPBACK;
			if (config & CFG_XMAC_XIF_LFS)
				val |= XMAC_XIF_LFS_DISABLE;
			if (config & CFG_XMAC_XIF_XPCS_BYPASS)
				val &= ~XMAC_XIF_XPCS_BYPASS;
			if (config & CFG_XMAC_XIF_1G_PCS_BYPASS)
				val &= ~XMAC_XIF_1G_PCS_BYPASS;
			if (config & CFG_XMAC_XIF_SEL_CLK_25MHZ)
				val &= ~XMAC_XIF_SEL_CLK_25MHZ;
			XMAC_REG_WR(handle, portn, XMAC_CONFIG_REG, val);
		}
		break;
	case INIT:
		ASSERT((config & ~CFG_XMAC_XIF_ALL) == 0);
		if ((config & ~CFG_XMAC_XIF_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_xmac_xif_config"
			    " Invalid Input: config <0x%x>",
			    config));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		XMAC_REG_RD(handle, portn, XMAC_CONFIG_REG, &val);

		if (config & CFG_XMAC_XIF_LED_FORCE)
			val |= XMAC_XIF_FORCE_LED_ON;
		else
			val &= ~XMAC_XIF_FORCE_LED_ON;
		if (config & CFG_XMAC_XIF_LED_POLARITY)
			val |= XMAC_XIF_LED_POLARITY;
		else
			val &= ~XMAC_XIF_LED_POLARITY;
		if (config & CFG_XMAC_XIF_SEL_POR_CLK_SRC)
			val |= XMAC_XIF_SEL_POR_CLK_SRC;
		else
			val &= ~XMAC_XIF_SEL_POR_CLK_SRC;
		if (config & CFG_XMAC_XIF_TX_OUTPUT)
			val |= XMAC_XIF_TX_OUTPUT_EN;
		else
			val &= ~XMAC_XIF_TX_OUTPUT_EN;

		if (config & CFG_XMAC_XIF_LOOPBACK) {
			val &= ~XMAC_XIF_SEL_POR_CLK_SRC;
			val |= XMAC_XIF_LOOPBACK;
#ifdef	AXIS_DEBUG_LB
			val |= XMAC_RX_MAC2IPP_PKT_CNT_EN;
#endif
		} else {
			val &= ~XMAC_XIF_LOOPBACK;
		}

		if (config & CFG_XMAC_XIF_LFS)
			val &= ~XMAC_XIF_LFS_DISABLE;
		else
			val |= XMAC_XIF_LFS_DISABLE;
		if (config & CFG_XMAC_XIF_XPCS_BYPASS)
			val |= XMAC_XIF_XPCS_BYPASS;
		else
			val &= ~XMAC_XIF_XPCS_BYPASS;
		if (config & CFG_XMAC_XIF_1G_PCS_BYPASS)
			val |= XMAC_XIF_1G_PCS_BYPASS;
		else
			val &= ~XMAC_XIF_1G_PCS_BYPASS;
		if (config & CFG_XMAC_XIF_SEL_CLK_25MHZ)
			val |= XMAC_XIF_SEL_CLK_25MHZ;
		else
			val &= ~XMAC_XIF_SEL_CLK_25MHZ;
		XMAC_REG_WR(handle, portn, XMAC_CONFIG_REG, val);

		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_xmac_xif_config"
		    " Invalid Input: op <0x%x>", op));
		return (NPI_FAILURE | NPI_MAC_OPCODE_INVALID(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_tx_config(npi_handle_t handle, config_op_t op, uint8_t portn,
			xmac_tx_config_t config)
{
	uint64_t val = 0;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	switch (op) {
	case ENABLE:
	case DISABLE:
		ASSERT((config != 0) && ((config & ~CFG_XMAC_TX_ALL) == 0));
		if ((config == 0) || (config & ~CFG_XMAC_TX_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_xmac_tx_config"
			    " Invalid Input: config <0x%x>",
			    config));
			return (NPI_FAILURE | NPI_MAC_OPCODE_INVALID(portn));
		}
		if (op == ENABLE) {
			XMAC_REG_RD(handle, portn, XMAC_CONFIG_REG, &val);
			if (config & CFG_XMAC_TX)
				val |= XMAC_TX_CFG_TX_ENABLE;
			if (config & CFG_XMAC_TX_STRETCH_MODE)
				val |= XMAC_TX_CFG_STRETCH_MD;
			if (config & CFG_XMAC_VAR_IPG)
				val |= XMAC_TX_CFG_VAR_MIN_IPG_EN;
			if (config & CFG_XMAC_TX_CRC)
				val &= ~XMAC_TX_CFG_ALWAYS_NO_CRC;
			XMAC_REG_WR(handle, portn, XMAC_CONFIG_REG, val);
		} else {
			XMAC_REG_RD(handle, portn, XMAC_CONFIG_REG, &val);
			if (config & CFG_XMAC_TX)
				val &= ~XMAC_TX_CFG_TX_ENABLE;
			if (config & CFG_XMAC_TX_STRETCH_MODE)
				val &= ~XMAC_TX_CFG_STRETCH_MD;
			if (config & CFG_XMAC_VAR_IPG)
				val &= ~XMAC_TX_CFG_VAR_MIN_IPG_EN;
			if (config & CFG_XMAC_TX_CRC)
				val |= XMAC_TX_CFG_ALWAYS_NO_CRC;
			XMAC_REG_WR(handle, portn, XMAC_CONFIG_REG, val);
		}
		break;
	case INIT:
		ASSERT((config & ~CFG_XMAC_TX_ALL) == 0);
		if ((config & ~CFG_XMAC_TX_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_xmac_tx_config"
			    " Invalid Input: config <0x%x>",
			    config));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		XMAC_REG_RD(handle, portn, XMAC_CONFIG_REG, &val);
		if (config & CFG_XMAC_TX)
			val |= XMAC_TX_CFG_TX_ENABLE;
		else
			val &= ~XMAC_TX_CFG_TX_ENABLE;
		if (config & CFG_XMAC_TX_STRETCH_MODE)
			val |= XMAC_TX_CFG_STRETCH_MD;
		else
			val &= ~XMAC_TX_CFG_STRETCH_MD;
		if (config & CFG_XMAC_VAR_IPG)
			val |= XMAC_TX_CFG_VAR_MIN_IPG_EN;
		else
			val &= ~XMAC_TX_CFG_VAR_MIN_IPG_EN;
		if (config & CFG_XMAC_TX_CRC)
			val &= ~XMAC_TX_CFG_ALWAYS_NO_CRC;
		else
			val |= XMAC_TX_CFG_ALWAYS_NO_CRC;

		XMAC_REG_WR(handle, portn, XMAC_CONFIG_REG, val);
		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_xmac_tx_config"
		    " Invalid Input: op <0x%x>",
		    op));
		return (NPI_FAILURE | NPI_MAC_OPCODE_INVALID(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_rx_config(npi_handle_t handle, config_op_t op, uint8_t portn,
			xmac_rx_config_t config)
{
	uint64_t val = 0;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	switch (op) {
	case ENABLE:
	case DISABLE:
		ASSERT((config != 0) && ((config & ~CFG_XMAC_RX_ALL) == 0));
		if ((config == 0) || (config & ~CFG_XMAC_RX_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_xmac_rx_config"
			    " Invalid Input: config <0x%x>",
			    config));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		if (op == ENABLE) {
			XMAC_REG_RD(handle, portn, XMAC_CONFIG_REG, &val);
			if (config & CFG_XMAC_RX)
				val |= XMAC_RX_CFG_RX_ENABLE;
			if (config & CFG_XMAC_RX_PROMISCUOUS)
				val |= XMAC_RX_CFG_PROMISC;
			if (config & CFG_XMAC_RX_PROMISCUOUSGROUP)
				val |= XMAC_RX_CFG_PROMISC_GROUP;
			if (config & CFG_XMAC_RX_ERRCHK)
				val &= ~XMAC_RX_CFG_ERR_CHK_DISABLE;
			if (config & CFG_XMAC_RX_CRC_CHK)
				val &= ~XMAC_RX_CFG_CRC_CHK_DISABLE;
			if (config & CFG_XMAC_RX_RESV_MULTICAST)
				val |= XMAC_RX_CFG_RESERVED_MCAST;
			if (config & CFG_XMAC_RX_CODE_VIO_CHK)
				val &= ~XMAC_RX_CFG_CD_VIO_CHK;
			if (config & CFG_XMAC_RX_HASH_FILTER)
				val |= XMAC_RX_CFG_HASH_FILTER_EN;
			if (config & CFG_XMAC_RX_ADDR_FILTER)
				val |= XMAC_RX_CFG_ADDR_FILTER_EN;
			if (config & CFG_XMAC_RX_STRIP_CRC)
				val |= XMAC_RX_CFG_STRIP_CRC;
			if (config & CFG_XMAC_RX_PAUSE)
				val |= XMAC_RX_CFG_RX_PAUSE_EN;
			if (config & CFG_XMAC_RX_PASS_FC_FRAME)
				val |= XMAC_RX_CFG_PASS_FLOW_CTRL;
			XMAC_REG_WR(handle, portn, XMAC_CONFIG_REG, val);
		} else {
			XMAC_REG_RD(handle, portn, XMAC_CONFIG_REG, &val);
			if (config & CFG_XMAC_RX)
				val &= ~XMAC_RX_CFG_RX_ENABLE;
			if (config & CFG_XMAC_RX_PROMISCUOUS)
				val &= ~XMAC_RX_CFG_PROMISC;
			if (config & CFG_XMAC_RX_PROMISCUOUSGROUP)
				val &= ~XMAC_RX_CFG_PROMISC_GROUP;
			if (config & CFG_XMAC_RX_ERRCHK)
				val |= XMAC_RX_CFG_ERR_CHK_DISABLE;
			if (config & CFG_XMAC_RX_CRC_CHK)
				val |= XMAC_RX_CFG_CRC_CHK_DISABLE;
			if (config & CFG_XMAC_RX_RESV_MULTICAST)
				val &= ~XMAC_RX_CFG_RESERVED_MCAST;
			if (config & CFG_XMAC_RX_CODE_VIO_CHK)
				val |= XMAC_RX_CFG_CD_VIO_CHK;
			if (config & CFG_XMAC_RX_HASH_FILTER)
				val &= ~XMAC_RX_CFG_HASH_FILTER_EN;
			if (config & CFG_XMAC_RX_ADDR_FILTER)
				val &= ~XMAC_RX_CFG_ADDR_FILTER_EN;
			if (config & CFG_XMAC_RX_STRIP_CRC)
				val &= ~XMAC_RX_CFG_STRIP_CRC;
			if (config & CFG_XMAC_RX_PAUSE)
				val &= ~XMAC_RX_CFG_RX_PAUSE_EN;
			if (config & CFG_XMAC_RX_PASS_FC_FRAME)
				val &= ~XMAC_RX_CFG_PASS_FLOW_CTRL;
			XMAC_REG_WR(handle, portn, XMAC_CONFIG_REG, val);
		}
		break;
	case INIT:
		ASSERT((config & ~CFG_XMAC_RX_ALL) == 0);
		if ((config & ~CFG_XMAC_RX_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_xmac_rx_config"
			    " Invalid Input: config <0x%x>",
			    config));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		XMAC_REG_RD(handle, portn, XMAC_CONFIG_REG, &val);
		if (config & CFG_XMAC_RX)
			val |= XMAC_RX_CFG_RX_ENABLE;
		else
			val &= ~XMAC_RX_CFG_RX_ENABLE;
		if (config & CFG_XMAC_RX_PROMISCUOUS)
			val |= XMAC_RX_CFG_PROMISC;
		else
			val &= ~XMAC_RX_CFG_PROMISC;
		if (config & CFG_XMAC_RX_PROMISCUOUSGROUP)
			val |= XMAC_RX_CFG_PROMISC_GROUP;
		else
			val &= ~XMAC_RX_CFG_PROMISC_GROUP;
		if (config & CFG_XMAC_RX_ERRCHK)
			val &= ~XMAC_RX_CFG_ERR_CHK_DISABLE;
		else
			val |= XMAC_RX_CFG_ERR_CHK_DISABLE;
		if (config & CFG_XMAC_RX_CRC_CHK)
			val &= ~XMAC_RX_CFG_CRC_CHK_DISABLE;
		else
			val |= XMAC_RX_CFG_CRC_CHK_DISABLE;
		if (config & CFG_XMAC_RX_RESV_MULTICAST)
			val |= XMAC_RX_CFG_RESERVED_MCAST;
		else
			val &= ~XMAC_RX_CFG_RESERVED_MCAST;
		if (config & CFG_XMAC_RX_CODE_VIO_CHK)
			val &= ~XMAC_RX_CFG_CD_VIO_CHK;
		else
			val |= XMAC_RX_CFG_CD_VIO_CHK;
		if (config & CFG_XMAC_RX_HASH_FILTER)
			val |= XMAC_RX_CFG_HASH_FILTER_EN;
		else
			val &= ~XMAC_RX_CFG_HASH_FILTER_EN;
		if (config & CFG_XMAC_RX_ADDR_FILTER)
			val |= XMAC_RX_CFG_ADDR_FILTER_EN;
		else
			val &= ~XMAC_RX_CFG_ADDR_FILTER_EN;
		if (config & CFG_XMAC_RX_PAUSE)
			val |= XMAC_RX_CFG_RX_PAUSE_EN;
		else
			val &= ~XMAC_RX_CFG_RX_PAUSE_EN;
		if (config & CFG_XMAC_RX_STRIP_CRC)
			val |= XMAC_RX_CFG_STRIP_CRC;
		else
			val &= ~XMAC_RX_CFG_STRIP_CRC;
		if (config & CFG_XMAC_RX_PASS_FC_FRAME)
			val |= XMAC_RX_CFG_PASS_FLOW_CTRL;
		else
			val &= ~XMAC_RX_CFG_PASS_FLOW_CTRL;

		XMAC_REG_WR(handle, portn, XMAC_CONFIG_REG, val);
		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_xmac_rx_config"
		    " Invalid Input: op <0x%x>", op));
		return (NPI_FAILURE | NPI_MAC_OPCODE_INVALID(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_tx_iconfig(npi_handle_t handle, config_op_t op, uint8_t portn,
		    xmac_tx_iconfig_t iconfig)
{
	uint64_t val = 0;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	switch (op) {
	case ENABLE:
	case DISABLE:
		ASSERT((iconfig != 0) && ((iconfig & ~ICFG_XMAC_TX_ALL) == 0));
		if ((iconfig == 0) || (iconfig & ~ICFG_XMAC_TX_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_xmac_tx_iconfig"
			    " Invalid Input: iconfig <0x%x>",
			    iconfig));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		XMAC_REG_RD(handle, portn, XTXMAC_STAT_MSK_REG, &val);
		if (op == ENABLE)
			val &= ~iconfig;
		else
			val |= iconfig;
		XMAC_REG_WR(handle, portn, XTXMAC_STAT_MSK_REG, val);

		break;
	case INIT:
		ASSERT((iconfig & ~ICFG_XMAC_TX_ALL) == 0);
		if ((iconfig & ~ICFG_XMAC_TX_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_xmac_tx_iconfig"
			    " Invalid Input: iconfig <0x%x>",
			    iconfig));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		XMAC_REG_WR(handle, portn, XTXMAC_STAT_MSK_REG, ~iconfig);

		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_xmac_tx_iconfig"
		    " Invalid Input: iconfig <0x%x>",
		    iconfig));
		return (NPI_FAILURE | NPI_MAC_OPCODE_INVALID(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_rx_iconfig(npi_handle_t handle, config_op_t op, uint8_t portn,
		    xmac_rx_iconfig_t iconfig)
{
	uint64_t val = 0;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	switch (op) {
	case ENABLE:
	case DISABLE:
		ASSERT((iconfig != 0) && ((iconfig & ~ICFG_XMAC_RX_ALL) == 0));
		if ((iconfig == 0) || (iconfig & ~ICFG_XMAC_RX_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_xmac_rx_iconfig"
			    " Invalid Input: iconfig <0x%x>",
			    iconfig));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		XMAC_REG_RD(handle, portn, XRXMAC_STAT_MSK_REG, &val);
		if (op == ENABLE)
			val &= ~iconfig;
		else
			val |= iconfig;
		XMAC_REG_WR(handle, portn, XRXMAC_STAT_MSK_REG, val);

		break;
	case INIT:
		ASSERT((iconfig & ~ICFG_XMAC_RX_ALL) == 0);
		if ((iconfig & ~ICFG_XMAC_RX_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_xmac_rx_iconfig"
			    " Invalid Input: iconfig <0x%x>",
			    iconfig));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		XMAC_REG_WR(handle, portn, XRXMAC_STAT_MSK_REG, ~iconfig);

		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_xmac_rx_iconfig"
		    " Invalid Input: iconfig <0x%x>",
		    iconfig));
		return (NPI_FAILURE | NPI_MAC_OPCODE_INVALID(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_ctl_iconfig(npi_handle_t handle, config_op_t op, uint8_t portn,
			xmac_ctl_iconfig_t iconfig)
{
	uint64_t val = 0;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	switch (op) {
	case ENABLE:
	case DISABLE:
		ASSERT((iconfig != 0) &&	\
		    ((iconfig & ~ICFG_XMAC_CTRL_ALL) == 0));
		if ((iconfig == 0) || (iconfig & ~ICFG_XMAC_CTRL_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_xmac_ctl_iconfig"
			    " Invalid Input: iconfig <0x%x>",
			    iconfig));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		XMAC_REG_RD(handle, portn, XMAC_C_S_MSK_REG, &val);
		if (op == ENABLE)
			val &= ~iconfig;
		else
			val |= iconfig;
		XMAC_REG_WR(handle, portn, XMAC_C_S_MSK_REG, val);

		break;
	case INIT:
		ASSERT((iconfig & ~ICFG_XMAC_CTRL_ALL) == 0);
		if ((iconfig & ~ICFG_XMAC_CTRL_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_xmac_ctl_iconfig"
			    " Invalid Input: iconfig <0x%x>",
			    iconfig));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		XMAC_REG_WR(handle, portn, XMAC_C_S_MSK_REG, ~iconfig);

		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_xmac_ctl_iconfig"
		    " Invalid Input: iconfig <0x%x>",
		    iconfig));
		return (NPI_FAILURE | NPI_MAC_OPCODE_INVALID(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_tx_get_istatus(npi_handle_t handle, uint8_t portn,
			xmac_tx_iconfig_t *istatus)
{
	uint64_t val;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	XMAC_REG_RD(handle, portn, XTXMAC_STATUS_REG, &val);
	*istatus = (uint32_t)val;

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_rx_get_istatus(npi_handle_t handle, uint8_t portn,
			xmac_rx_iconfig_t *istatus)
{
	uint64_t val;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	XMAC_REG_RD(handle, portn, XRXMAC_STATUS_REG, &val);
	*istatus = (uint32_t)val;

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_ctl_get_istatus(npi_handle_t handle, uint8_t portn,
			xmac_ctl_iconfig_t *istatus)
{
	uint64_t val;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	XMAC_REG_RD(handle, portn, XMAC_CTRL_STAT_REG, &val);
	*istatus = (uint32_t)val;

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_xpcs_reset(npi_handle_t handle, uint8_t portn)
{
	uint64_t val;
	int delay = 100;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	XPCS_REG_RD(handle, portn, XPCS_CTRL_1_REG, &val);
	val |= XPCS_CTRL1_RST;
	XPCS_REG_WR(handle, portn, XPCS_CTRL_1_REG, val);

	while ((--delay) && (val & XPCS_CTRL1_RST)) {
		NXGE_DELAY(10);
		XPCS_REG_RD(handle, portn, XPCS_CTRL_1_REG, &val);
	}

	if (delay == 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_xmac_xpcs_reset portn <%d> failed", portn));
		return (NPI_FAILURE);
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_xpcs_enable(npi_handle_t handle, uint8_t portn)
{
	uint64_t val;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	XPCS_REG_RD(handle, portn, XPCS_CFG_VENDOR_1_REG, &val);
	val |= XPCS_CFG_XPCS_ENABLE;
	XPCS_REG_WR(handle, portn, XPCS_CFG_VENDOR_1_REG, val);

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_xpcs_disable(npi_handle_t handle, uint8_t portn)
{
	uint64_t val;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	XPCS_REG_RD(handle, portn, XPCS_CFG_VENDOR_1_REG, &val);
	val &= ~XPCS_CFG_XPCS_ENABLE;
	XPCS_REG_WR(handle, portn, XPCS_CFG_VENDOR_1_REG, val);

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_xpcs_read(npi_handle_t handle, uint8_t portn, uint8_t xpcs_reg,
			uint32_t *value)
{
	uint32_t reg;
	uint64_t val;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	switch (xpcs_reg) {
	case XPCS_REG_CONTROL1:
		reg = XPCS_CTRL_1_REG;
		break;
	case XPCS_REG_STATUS1:
		reg = XPCS_STATUS_1_REG;
		break;
	case XPCS_REG_DEVICE_ID:
		reg = XPCS_DEV_ID_REG;
		break;
	case XPCS_REG_SPEED_ABILITY:
		reg = XPCS_SPEED_ABILITY_REG;
		break;
	case XPCS_REG_DEVICE_IN_PKG:
		reg = XPCS_DEV_IN_PKG_REG;
		break;
	case XPCS_REG_CONTROL2:
		reg = XPCS_CTRL_2_REG;
		break;
	case XPCS_REG_STATUS2:
		reg = XPCS_STATUS_2_REG;
		break;
	case XPCS_REG_PKG_ID:
		reg = XPCS_PKG_ID_REG;
		break;
	case XPCS_REG_STATUS:
		reg = XPCS_STATUS_REG;
		break;
	case XPCS_REG_TEST_CONTROL:
		reg = XPCS_TEST_CTRL_REG;
		break;
	case XPCS_REG_CONFIG_VENDOR1:
		reg = XPCS_CFG_VENDOR_1_REG;
		break;
	case XPCS_REG_DIAG_VENDOR2:
		reg = XPCS_DIAG_VENDOR_2_REG;
		break;
	case XPCS_REG_MASK1:
		reg = XPCS_MASK_1_REG;
		break;
	case XPCS_REG_PACKET_COUNTER:
		reg = XPCS_PKT_CNTR_REG;
		break;
	case XPCS_REG_TX_STATEMACHINE:
		reg = XPCS_TX_STATE_MC_REG;
		break;
	case XPCS_REG_DESCWERR_COUNTER:
		reg = XPCS_DESKEW_ERR_CNTR_REG;
		break;
	case XPCS_REG_SYMBOL_ERR_L0_1_COUNTER:
		reg = XPCS_SYM_ERR_CNTR_L0_L1_REG;
		break;
	case XPCS_REG_SYMBOL_ERR_L2_3_COUNTER:
		reg = XPCS_SYM_ERR_CNTR_L2_L3_REG;
		break;
	case XPCS_REG_TRAINING_VECTOR:
		reg = XPCS_TRAINING_VECTOR_REG;
		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_xmac_xpcs_read"
		    " Invalid Input: xpcs_reg <0x%x>",
		    xpcs_reg));
		return (NPI_FAILURE | NPI_MAC_REG_INVALID(portn));
	}
	XPCS_REG_RD(handle, portn, reg, &val);
	*value = val & 0xFFFFFFFF;

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_xpcs_write(npi_handle_t handle, uint8_t portn, uint8_t xpcs_reg,
			uint32_t value)
{
	uint32_t reg;
	uint64_t val;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	switch (xpcs_reg) {
	case XPCS_REG_CONTROL1:
		reg = XPCS_CTRL_1_REG;
		break;
	case XPCS_REG_TEST_CONTROL:
		reg = XPCS_TEST_CTRL_REG;
		break;
	case XPCS_REG_CONFIG_VENDOR1:
		reg = XPCS_CFG_VENDOR_1_REG;
		break;
	case XPCS_REG_DIAG_VENDOR2:
		reg = XPCS_DIAG_VENDOR_2_REG;
		break;
	case XPCS_REG_MASK1:
		reg = XPCS_MASK_1_REG;
		break;
	case XPCS_REG_PACKET_COUNTER:
		reg = XPCS_PKT_CNTR_REG;
		break;
	case XPCS_REG_DESCWERR_COUNTER:
		reg = XPCS_DESKEW_ERR_CNTR_REG;
		break;
	case XPCS_REG_TRAINING_VECTOR:
		reg = XPCS_TRAINING_VECTOR_REG;
		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_xmac_xpcs_write"
		    " Invalid Input: xpcs_reg <0x%x>",
		    xpcs_reg));
		return (NPI_FAILURE | NPI_MAC_PCS_REG_INVALID(portn));
	}
	val = value;

	XPCS_REG_WR(handle, portn, reg, val);

	return (NPI_SUCCESS);
}

npi_status_t
npi_bmac_reset(npi_handle_t handle, uint8_t portn, npi_mac_reset_t mode)
{
	uint64_t val = 0;
	boolean_t txmac = B_FALSE;

	ASSERT(IS_BMAC_PORT_NUM_VALID(portn));

	switch (mode) {
	case TX_MAC_RESET:
		BMAC_REG_WR(handle, portn, BTXMAC_SW_RST_REG, 0x1);
		BMAC_WAIT_REG(handle, portn, BTXMAC_SW_RST_REG, val);
		txmac = B_TRUE;
		break;
	case RX_MAC_RESET:
		BMAC_REG_WR(handle, portn, BRXMAC_SW_RST_REG, 0x1);
		BMAC_WAIT_REG(handle, portn, BRXMAC_SW_RST_REG, val);
		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_bmac_reset"
		    " Invalid Input: mode <0x%x>",
		    mode));
		return (NPI_FAILURE | NPI_MAC_RESET_MODE_INVALID(portn));
	}

	if (val != 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_bmac_reset"
		    " BMAC_RESET HW Error: ret <0x%x>",
		    val));
		if (txmac)
			return (NPI_FAILURE | NPI_TXMAC_RESET_FAILED(portn));
		else
			return (NPI_FAILURE | NPI_RXMAC_RESET_FAILED(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_pcs_reset(npi_handle_t handle, uint8_t portn)
{
	/* what to do here ? */
	uint64_t val = 0;
	int delay = 100;

	ASSERT(IS_PORT_NUM_VALID(portn));

	PCS_REG_RD(handle, portn, PCS_MII_CTRL_REG, &val);
	val |= PCS_MII_RESET;
	PCS_REG_WR(handle, portn, PCS_MII_CTRL_REG, val);
	while ((delay) && (val & PCS_MII_RESET)) {
		NXGE_DELAY(10);
		PCS_REG_RD(handle, portn, PCS_MII_CTRL_REG, &val);
		delay--;
	}
	if (delay == 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_bmac_pcs_reset portn <%d> failed", portn));
		return (NPI_FAILURE);
	}
	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_get_link_status(npi_handle_t handle, uint8_t portn,
			boolean_t *link_up)
{
	uint64_t val;

	ASSERT(IS_PORT_NUM_VALID(portn));

	PCS_REG_RD(handle, portn, PCS_MII_STATUS_REG, &val);

	if (val & PCS_MII_STATUS_LINK_STATUS) {
		*link_up = B_TRUE;
	} else {
		*link_up = B_FALSE;
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_bmac_tx_config(npi_handle_t handle, config_op_t op, uint8_t portn,
			bmac_tx_config_t config)
{
	uint64_t val = 0;

	ASSERT(IS_BMAC_PORT_NUM_VALID(portn));

	switch (op) {
	case ENABLE:
	case DISABLE:
		ASSERT((config != 0) && ((config & ~CFG_BMAC_TX_ALL) == 0));
		if ((config == 0) || (config & ~CFG_BMAC_TX_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_bmac_tx_config"
			    " Invalid Input: config <0x%x>",
			    config));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		if (op == ENABLE) {
			BMAC_REG_RD(handle, portn, TXMAC_CONFIG_REG, &val);
			if (config & CFG_BMAC_TX)
				val |= MAC_TX_CFG_TXMAC_ENABLE;
			if (config & CFG_BMAC_TX_CRC)
				val &= ~MAC_TX_CFG_NO_FCS;
			BMAC_REG_WR(handle, portn, TXMAC_CONFIG_REG, val);
		} else {
			BMAC_REG_RD(handle, portn, TXMAC_CONFIG_REG, &val);
			if (config & CFG_BMAC_TX)
				val &= ~MAC_TX_CFG_TXMAC_ENABLE;
			if (config & CFG_BMAC_TX_CRC)
				val |= MAC_TX_CFG_NO_FCS;
			BMAC_REG_WR(handle, portn, TXMAC_CONFIG_REG, val);
		}
		break;
	case INIT:
		ASSERT((config & ~CFG_BMAC_TX_ALL) == 0);
		if ((config & ~CFG_BMAC_TX_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_bmac_tx_config"
			    " Invalid Input: config <0x%x>",
			    config));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		BMAC_REG_RD(handle, portn, TXMAC_CONFIG_REG, &val);
		if (config & CFG_BMAC_TX)
			val |= MAC_TX_CFG_TXMAC_ENABLE;
		else
			val &= ~MAC_TX_CFG_TXMAC_ENABLE;
		if (config & CFG_BMAC_TX_CRC)
			val &= ~MAC_TX_CFG_NO_FCS;
		else
			val |= MAC_TX_CFG_NO_FCS;
		BMAC_REG_WR(handle, portn, TXMAC_CONFIG_REG, val);
		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_bmac_tx_config"
		    " Invalid Input: op <0x%x>",
		    op));
		return (NPI_FAILURE | NPI_MAC_OPCODE_INVALID(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_bmac_rx_config(npi_handle_t handle, config_op_t op, uint8_t portn,
			bmac_rx_config_t config)
{
	uint64_t val = 0;

	ASSERT(IS_BMAC_PORT_NUM_VALID(portn));

	switch (op) {
	case ENABLE:
	case DISABLE:
		ASSERT((config != 0) && ((config & ~CFG_BMAC_RX_ALL) == 0));
		if ((config == 0) || (config & ~CFG_BMAC_RX_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_bmac_rx_config"
			    " Invalid Input: config <0x%x>",
			    config));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		if (op == ENABLE) {
			BMAC_REG_RD(handle, portn, RXMAC_CONFIG_REG, &val);
			if (config & CFG_BMAC_RX)
				val |= MAC_RX_CFG_RXMAC_ENABLE;
			if (config & CFG_BMAC_RX_STRIP_PAD)
				val |= MAC_RX_CFG_STRIP_PAD;
			if (config & CFG_BMAC_RX_STRIP_CRC)
				val |= MAC_RX_CFG_STRIP_FCS;
			if (config & CFG_BMAC_RX_PROMISCUOUS)
				val |= MAC_RX_CFG_PROMISC;
			if (config & CFG_BMAC_RX_PROMISCUOUSGROUP)
				val |= MAC_RX_CFG_PROMISC_GROUP;
			if (config & CFG_BMAC_RX_HASH_FILTER)
				val |= MAC_RX_CFG_HASH_FILTER_EN;
			if (config & CFG_BMAC_RX_ADDR_FILTER)
				val |= MAC_RX_CFG_ADDR_FILTER_EN;
			if (config & CFG_BMAC_RX_DISCARD_ON_ERR)
				val &= ~MAC_RX_CFG_DISABLE_DISCARD;
			BMAC_REG_WR(handle, portn, RXMAC_CONFIG_REG, val);
		} else {
			BMAC_REG_RD(handle, portn, RXMAC_CONFIG_REG, &val);
			if (config & CFG_BMAC_RX)
				val &= ~MAC_RX_CFG_RXMAC_ENABLE;
			if (config & CFG_BMAC_RX_STRIP_PAD)
				val &= ~MAC_RX_CFG_STRIP_PAD;
			if (config & CFG_BMAC_RX_STRIP_CRC)
				val &= ~MAC_RX_CFG_STRIP_FCS;
			if (config & CFG_BMAC_RX_PROMISCUOUS)
				val &= ~MAC_RX_CFG_PROMISC;
			if (config & CFG_BMAC_RX_PROMISCUOUSGROUP)
				val &= ~MAC_RX_CFG_PROMISC_GROUP;
			if (config & CFG_BMAC_RX_HASH_FILTER)
				val &= ~MAC_RX_CFG_HASH_FILTER_EN;
			if (config & CFG_BMAC_RX_ADDR_FILTER)
				val &= ~MAC_RX_CFG_ADDR_FILTER_EN;
			if (config & CFG_BMAC_RX_DISCARD_ON_ERR)
				val |= MAC_RX_CFG_DISABLE_DISCARD;
			BMAC_REG_WR(handle, portn, RXMAC_CONFIG_REG, val);
		}
		break;
	case INIT:
		ASSERT((config & ~CFG_BMAC_RX_ALL) == 0);
		if ((config & ~CFG_BMAC_RX_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_bmac_rx_config"
			    " Invalid Input: config <0x%x>",
			    config));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		BMAC_REG_RD(handle, portn, RXMAC_CONFIG_REG, &val);
		if (config & CFG_BMAC_RX)
			val |= MAC_RX_CFG_RXMAC_ENABLE;
		else
			val &= ~MAC_RX_CFG_RXMAC_ENABLE;
		if (config & CFG_BMAC_RX_STRIP_PAD)
			val |= MAC_RX_CFG_STRIP_PAD;
		else
			val &= ~MAC_RX_CFG_STRIP_PAD;
		if (config & CFG_BMAC_RX_STRIP_CRC)
			val |= MAC_RX_CFG_STRIP_FCS;
		else
			val &= ~MAC_RX_CFG_STRIP_FCS;
		if (config & CFG_BMAC_RX_PROMISCUOUS)
			val |= MAC_RX_CFG_PROMISC;
		else
			val &= ~MAC_RX_CFG_PROMISC;
		if (config & CFG_BMAC_RX_PROMISCUOUSGROUP)
			val |= MAC_RX_CFG_PROMISC_GROUP;
		else
			val &= ~MAC_RX_CFG_PROMISC_GROUP;
		if (config & CFG_BMAC_RX_HASH_FILTER)
			val |= MAC_RX_CFG_HASH_FILTER_EN;
		else
			val &= ~MAC_RX_CFG_HASH_FILTER_EN;
		if (config & CFG_BMAC_RX_ADDR_FILTER)
			val |= MAC_RX_CFG_ADDR_FILTER_EN;
		else
			val &= ~MAC_RX_CFG_ADDR_FILTER_EN;
		if (config & CFG_BMAC_RX_DISCARD_ON_ERR)
			val &= ~MAC_RX_CFG_DISABLE_DISCARD;
		else
			val |= MAC_RX_CFG_DISABLE_DISCARD;

		BMAC_REG_WR(handle, portn, RXMAC_CONFIG_REG, val);
		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_bmac_rx_config"
		    " Invalid Input: op <0x%x>", op));
		return (NPI_FAILURE | NPI_MAC_OPCODE_INVALID(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_bmac_rx_iconfig(npi_handle_t handle, config_op_t op, uint8_t portn,
		    bmac_rx_iconfig_t iconfig)
{
	uint64_t val = 0;

	ASSERT(IS_BMAC_PORT_NUM_VALID(portn));

	switch (op) {
	case ENABLE:
	case DISABLE:
		ASSERT((iconfig != 0) && ((iconfig & ~ICFG_BMAC_RX_ALL) == 0));
		if ((iconfig == 0) || (iconfig & ~ICFG_BMAC_RX_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_bmac_rx_iconfig"
			    " Invalid Input: iconfig <0x%x>",
			    iconfig));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		BMAC_REG_RD(handle, portn, BRXMAC_STAT_MSK_REG, &val);
		if (op == ENABLE)
			val &= ~iconfig;
		else
			val |= iconfig;
		BMAC_REG_WR(handle, portn, BRXMAC_STAT_MSK_REG, val);

		break;
	case INIT:
		ASSERT((iconfig & ~ICFG_BMAC_RX_ALL) == 0);
		if ((iconfig & ~ICFG_BMAC_RX_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_bmac_rx_iconfig"
			    " Invalid Input: iconfig <0x%x>",
			    iconfig));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		BMAC_REG_WR(handle, portn, BRXMAC_STAT_MSK_REG, ~iconfig);

		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_bmac_rx_iconfig"
		    " Invalid Input: iconfig <0x%x>",
		    iconfig));
		return (NPI_FAILURE | NPI_MAC_OPCODE_INVALID(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_bmac_xif_config(npi_handle_t handle, config_op_t op, uint8_t portn,
		    bmac_xif_config_t config)
{
	uint64_t val = 0;

	ASSERT(IS_BMAC_PORT_NUM_VALID(portn));

	switch (op) {
	case ENABLE:
	case DISABLE:
		ASSERT((config != 0) && ((config & ~CFG_BMAC_XIF_ALL) == 0));
		if ((config == 0) || (config & ~CFG_BMAC_XIF_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_bmac_xif_config"
			    " Invalid Input: config <0x%x>",
			    config));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		if (op == ENABLE) {
			BMAC_REG_RD(handle, portn, MAC_XIF_CONFIG_REG, &val);
			if (config & CFG_BMAC_XIF_TX_OUTPUT)
				val |= MAC_XIF_TX_OUTPUT_EN;
			if (config & CFG_BMAC_XIF_LOOPBACK)
				val |= MAC_XIF_MII_INT_LOOPBACK;
			if (config & CFG_BMAC_XIF_GMII_MODE)
				val |= MAC_XIF_GMII_MODE;
			if (config & CFG_BMAC_XIF_LINKLED)
				val |= MAC_XIF_LINK_LED;
			if (config & CFG_BMAC_XIF_LED_POLARITY)
				val |= MAC_XIF_LED_POLARITY;
			if (config & CFG_BMAC_XIF_SEL_CLK_25MHZ)
				val |= MAC_XIF_SEL_CLK_25MHZ;
			BMAC_REG_WR(handle, portn, MAC_XIF_CONFIG_REG, val);
		} else {
			BMAC_REG_RD(handle, portn, MAC_XIF_CONFIG_REG, &val);
			if (config & CFG_BMAC_XIF_TX_OUTPUT)
				val &= ~MAC_XIF_TX_OUTPUT_EN;
			if (config & CFG_BMAC_XIF_LOOPBACK)
				val &= ~MAC_XIF_MII_INT_LOOPBACK;
			if (config & CFG_BMAC_XIF_GMII_MODE)
				val &= ~MAC_XIF_GMII_MODE;
			if (config & CFG_BMAC_XIF_LINKLED)
				val &= ~MAC_XIF_LINK_LED;
			if (config & CFG_BMAC_XIF_LED_POLARITY)
				val &= ~MAC_XIF_LED_POLARITY;
			if (config & CFG_BMAC_XIF_SEL_CLK_25MHZ)
				val &= ~MAC_XIF_SEL_CLK_25MHZ;
			BMAC_REG_WR(handle, portn, MAC_XIF_CONFIG_REG, val);
		}
		break;
	case INIT:
		ASSERT((config & ~CFG_BMAC_XIF_ALL) == 0);
		if ((config & ~CFG_BMAC_XIF_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_bmac_xif_config"
			    " Invalid Input: config <0x%x>",
			    config));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		BMAC_REG_RD(handle, portn, MAC_XIF_CONFIG_REG, &val);
		if (config & CFG_BMAC_XIF_TX_OUTPUT)
			val |= MAC_XIF_TX_OUTPUT_EN;
		else
			val &= ~MAC_XIF_TX_OUTPUT_EN;
		if (config & CFG_BMAC_XIF_LOOPBACK)
			val |= MAC_XIF_MII_INT_LOOPBACK;
		else
			val &= ~MAC_XIF_MII_INT_LOOPBACK;
		if (config & CFG_BMAC_XIF_GMII_MODE)
			val |= MAC_XIF_GMII_MODE;
		else
			val &= ~MAC_XIF_GMII_MODE;
		if (config & CFG_BMAC_XIF_LINKLED)
			val |= MAC_XIF_LINK_LED;
		else
			val &= ~MAC_XIF_LINK_LED;
		if (config & CFG_BMAC_XIF_LED_POLARITY)
			val |= MAC_XIF_LED_POLARITY;
		else
			val &= ~MAC_XIF_LED_POLARITY;
		if (config & CFG_BMAC_XIF_SEL_CLK_25MHZ)
			val |= MAC_XIF_SEL_CLK_25MHZ;
		else
			val &= ~MAC_XIF_SEL_CLK_25MHZ;
		BMAC_REG_WR(handle, portn, MAC_XIF_CONFIG_REG, val);
		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_bmac_xif_config"
		    " Invalid Input: op <0x%x>",
		    op));
		return (NPI_FAILURE | NPI_MAC_OPCODE_INVALID(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_bmac_tx_iconfig(npi_handle_t handle, config_op_t op, uint8_t portn,
		    bmac_tx_iconfig_t iconfig)
{
	uint64_t val = 0;

	ASSERT(IS_BMAC_PORT_NUM_VALID(portn));

	switch (op) {
	case ENABLE:
	case DISABLE:
		ASSERT((iconfig != 0) && ((iconfig & ~ICFG_XMAC_TX_ALL) == 0));
		if ((iconfig == 0) || (iconfig & ~ICFG_XMAC_TX_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_bmac_tx_iconfig"
			    " Invalid Input: iconfig <0x%x>",
			    iconfig));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		BMAC_REG_RD(handle, portn, BTXMAC_STAT_MSK_REG, &val);
		if (op == ENABLE)
			val &= ~iconfig;
		else
			val |= iconfig;
		BMAC_REG_WR(handle, portn, BTXMAC_STAT_MSK_REG, val);

		break;
	case INIT:
		ASSERT((iconfig & ~ICFG_XMAC_TX_ALL) == 0);
		if ((iconfig & ~ICFG_XMAC_TX_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_bmac_tx_iconfig"
			    " Invalid Input: iconfig <0x%x>",
			    iconfig));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		BMAC_REG_WR(handle, portn, BTXMAC_STAT_MSK_REG, ~iconfig);

		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_bmac_tx_iconfig"
		    " Invalid Input: iconfig <0x%x>",
		    iconfig));
		return (NPI_FAILURE | NPI_MAC_OPCODE_INVALID(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_bmac_ctl_iconfig(npi_handle_t handle, config_op_t op, uint8_t portn,
			bmac_ctl_iconfig_t iconfig)
{
	uint64_t val = 0;

	ASSERT(IS_BMAC_PORT_NUM_VALID(portn));

	switch (op) {
	case ENABLE:
	case DISABLE:
		ASSERT((iconfig != 0) && ((iconfig & ~ICFG_BMAC_CTL_ALL) == 0));
		if ((iconfig == 0) || (iconfig & ~ICFG_BMAC_CTL_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_bmac_ctl_iconfig"
			    " Invalid Input: iconfig <0x%x>",
			    iconfig));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		BMAC_REG_RD(handle, portn, BMAC_C_S_MSK_REG, &val);
		if (op == ENABLE)
			val &= ~iconfig;
		else
			val |= iconfig;
		BMAC_REG_WR(handle, portn, BMAC_C_S_MSK_REG, val);

		break;
	case INIT:
		ASSERT((iconfig & ~ICFG_BMAC_RX_ALL) == 0);
		if ((iconfig & ~ICFG_BMAC_RX_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_bmac_ctl_iconfig"
			    " Invalid Input: iconfig <0x%x>",
			    iconfig));
			return (NPI_FAILURE | NPI_MAC_CONFIG_INVALID(portn));
		}
		BMAC_REG_WR(handle, portn, BMAC_C_S_MSK_REG, ~iconfig);

		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_bmac_ctl_iconfig"
		    " Invalid Input: iconfig <0x%x>",
		    iconfig));
		return (NPI_FAILURE | NPI_MAC_OPCODE_INVALID(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_bmac_tx_get_istatus(npi_handle_t handle, uint8_t portn,
			bmac_tx_iconfig_t *istatus)
{
	uint64_t val = 0;

	ASSERT(IS_BMAC_PORT_NUM_VALID(portn));

	BMAC_REG_RD(handle, portn, BTXMAC_STATUS_REG, &val);
	*istatus = (uint32_t)val;

	return (NPI_SUCCESS);
}

npi_status_t
npi_bmac_rx_get_istatus(npi_handle_t handle, uint8_t portn,
			bmac_rx_iconfig_t *istatus)
{
	uint64_t val = 0;

	ASSERT(IS_BMAC_PORT_NUM_VALID(portn));

	BMAC_REG_RD(handle, portn, BRXMAC_STATUS_REG, &val);
	*istatus = (uint32_t)val;

	return (NPI_SUCCESS);
}

npi_status_t
npi_bmac_ctl_get_istatus(npi_handle_t handle, uint8_t portn,
				bmac_ctl_iconfig_t *istatus)
{
	uint64_t val = 0;

	ASSERT(IS_BMAC_PORT_NUM_VALID(portn));

	BMAC_REG_RD(handle, portn, BMAC_CTRL_STAT_REG, &val);
	*istatus = (uint32_t)val;

	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_mif_mdio_read(npi_handle_t handle, uint8_t portn, uint8_t device,
			uint16_t xcvr_reg, uint16_t *value)
{
	mif_frame_t frame;
	uint_t delay;

	frame.value = 0;
	frame.bits.w0.st = FRAME45_ST;		/* Clause 45	*/
	frame.bits.w0.op = FRAME45_OP_ADDR;	/* Select address	*/
	frame.bits.w0.phyad = portn;		/* Port number	*/
	frame.bits.w0.regad = device;		/* Device number	*/
	frame.bits.w0.ta_msb = 1;
	frame.bits.w0.ta_lsb = 0;
	frame.bits.w0.data = xcvr_reg;	/* register address */

	NPI_DEBUG_MSG((handle.function, MIF_CTL,
	    "mdio read port %d addr val=0x%x\n", portn, frame.value));

	MIF_REG_WR(handle, MIF_OUTPUT_FRAME_REG, frame.value);

	delay = 0;
	MIF_WAIT_REG(handle, frame, delay, MIF_DELAY, MIF_DELAY);

	NPI_DEBUG_MSG((handle.function, MIF_CTL,
	    "mdio read port %d addr poll=0x%x\n", portn, frame.value));

	if (delay == MIF_DELAY) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "mdio read no response1\n"));
	}

	frame.bits.w0.st = FRAME45_ST; /* Clause 45 */
	frame.bits.w0.op = FRAME45_OP_READ; /* Read */
	frame.bits.w0.phyad = portn; /* Port Number */
	frame.bits.w0.regad = device; /* Device Number */
	frame.bits.w0.ta_msb = 1;
	frame.bits.w0.ta_lsb = 0;

	NPI_DEBUG_MSG((handle.function, MIF_CTL,
	    "mdio read port %d data frame=0x%x\n", portn, frame.value));

	MIF_REG_WR(handle, MIF_OUTPUT_FRAME_REG, frame.value);

	delay = 0;
	MIF_WAIT_REG(handle, frame, delay, MIF_DELAY, MIF_DELAY);

	NPI_DEBUG_MSG((handle.function, MIF_CTL,
	    "mdio read port %d data poll=0x%x\n", portn, frame.value));

	*value = frame.bits.w0.data;
	NPI_DEBUG_MSG((handle.function, MIF_CTL,
	    "mdio read port=%d val=0x%x\n", portn, *value));

	if (delay == MIF_DELAY) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "mdio read no response2\n"));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_mif_mii_read(npi_handle_t handle, uint8_t portn, uint8_t xcvr_reg,
			uint16_t *value)
{
	mif_frame_t frame;
	uint_t delay;

	frame.bits.w0.st = 0x1; /* Clause 22 */
	frame.bits.w0.op = 0x2;
	frame.bits.w0.phyad = portn;
	frame.bits.w0.regad = xcvr_reg;
	frame.bits.w0.ta_msb = 1;
	frame.bits.w0.ta_lsb = 0;
	MIF_REG_WR(handle, MIF_OUTPUT_FRAME_REG, frame.value);

	delay = 0;
	MIF_WAIT_REG(handle, frame, delay, MIF_DELAY, MAX_PIO_RETRIES);

	if (delay == MAX_PIO_RETRIES)
		return (NPI_FAILURE | NPI_MAC_MII_READ_FAILED(portn));

	*value = frame.bits.w0.data;
	NPI_DEBUG_MSG((handle.function, MIF_CTL,
	    "mif mii read port %d reg=0x%x frame=0x%x\n", portn,
	    xcvr_reg, frame.bits.w0.data));

	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_mif_mdio_write(npi_handle_t handle, uint8_t portn, uint8_t device,
			uint16_t xcvr_reg, uint16_t value)
{
	mif_frame_t frame;
	uint_t delay;

	frame.value = 0;
	frame.bits.w0.st = FRAME45_ST; /* Clause 45 */
	frame.bits.w0.op = FRAME45_OP_ADDR; /* Select Address */
	frame.bits.w0.phyad = portn; /* Port Number */
	frame.bits.w0.regad = device; /* Device Number */
	frame.bits.w0.ta_msb = 1;
	frame.bits.w0.ta_lsb = 0;
	frame.bits.w0.data = xcvr_reg;	/* register address */

	MIF_REG_WR(handle, MIF_OUTPUT_FRAME_REG, frame.value);

	NPI_DEBUG_MSG((handle.function, MIF_CTL,
	    "mdio write port %d addr val=0x%x\n", portn, frame.value));

	delay = 0;
	MIF_WAIT_REG(handle, frame, delay, MIF_DELAY, MIF_DELAY);

	NPI_DEBUG_MSG((handle.function, MIF_CTL,
	    "mdio write port %d addr poll=0x%x\n", portn, frame.value));

	if (delay == MIF_DELAY) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "mdio write no response1\n"));
	}

	frame.bits.w0.st = FRAME45_ST; /* Clause 45 */
	frame.bits.w0.op = FRAME45_OP_WRITE; /* Write */
	frame.bits.w0.phyad = portn; /* Port number   */
	frame.bits.w0.regad = device; /* Device number */
	frame.bits.w0.ta_msb = 1;
	frame.bits.w0.ta_lsb = 0;
	frame.bits.w0.data = value;
	MIF_REG_WR(handle, MIF_OUTPUT_FRAME_REG, frame.value);

	NPI_DEBUG_MSG((handle.function, MIF_CTL,
	    "mdio write port %d data val=0x%x\n", portn, frame.value));

	delay = 0;
	MIF_WAIT_REG(handle, frame, delay, MIF_DELAY, MIF_DELAY);

	NPI_DEBUG_MSG((handle.function, MIF_CTL,
	    "mdio write port %d data poll=0x%x\n", portn, frame.value));

	if (delay == MIF_DELAY) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "mdio write no response2\n"));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_mif_mii_write(npi_handle_t handle, uint8_t portn, uint8_t xcvr_reg,
			uint16_t value)
{
	mif_frame_t frame;
	uint_t delay;

	frame.bits.w0.st = 0x1; /* Clause 22 */
	frame.bits.w0.op = 0x1;
	frame.bits.w0.phyad = portn;
	frame.bits.w0.regad = xcvr_reg;
	frame.bits.w0.ta_msb = 1;
	frame.bits.w0.ta_lsb = 0;
	frame.bits.w0.data = value;
	MIF_REG_WR(handle, MIF_OUTPUT_FRAME_REG, frame.value);

	delay = 0;
	MIF_WAIT_REG(handle, frame, delay, MIF_DELAY, MAX_PIO_RETRIES);

	NPI_DEBUG_MSG((handle.function, MIF_CTL,
	    "mif mii write port %d reg=0x%x frame=0x%x\n", portn,
	    xcvr_reg, frame.value));

	if (delay == MAX_PIO_RETRIES)
		return (NPI_FAILURE | NPI_MAC_MII_WRITE_FAILED(portn));

	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_pcs_mii_read(npi_handle_t handle, uint8_t portn, uint8_t xcvr_reg,
			uint16_t *value)
{
	pcs_anar_t pcs_anar;
	pcs_anar_t pcs_anlpar;
	pcs_stat_t pcs_stat;
	pcs_stat_mc_t pcs_stat_mc;
	mii_anar_t anar;
	mii_anar_t anlpar;
	mii_aner_t aner;
	mii_esr_t esr;
	mii_gsr_t gsr;
	uint64_t val = 0;

	ASSERT(IS_PORT_NUM_VALID(portn));

	switch (xcvr_reg) {
	case MII_CONTROL:
		PCS_REG_RD(handle, portn, PCS_MII_CTRL_REG, &val);
		*value = (uint16_t)val;
		break;
	case MII_STATUS:
		PCS_REG_RD(handle, portn, PCS_MII_STATUS_REG, &val);
		pcs_stat.value = val;
		PCS_REG_RD(handle, portn, PCS_STATE_MACHINE_REG, &val);
		pcs_stat_mc.value = val;
		if ((pcs_stat_mc.bits.w0.link_cfg_stat == 0xB) &&
		    (pcs_stat_mc.bits.w0.word_sync != 0)) {
			pcs_stat.bits.w0.link_stat = 1;
		} else if (pcs_stat_mc.bits.w0.link_cfg_stat != 0xB) {
			pcs_stat.bits.w0.link_stat = 0;
		}
		*value = (uint16_t)pcs_stat.value;
		break;
	case NXGE_MII_ESR:
		PCS_REG_RD(handle, portn, PCS_MII_ADVERT_REG, &val);
		pcs_anar.value = (uint16_t)val;
		esr.value = 0;
		esr.bits.link_1000fdx = pcs_anar.bits.w0.full_duplex;
		esr.bits.link_1000hdx = pcs_anar.bits.w0.half_duplex;
		*value = esr.value;
		break;
	case MII_AN_ADVERT:
		PCS_REG_RD(handle, portn, PCS_MII_ADVERT_REG, &val);
		pcs_anar.value = (uint16_t)val;
		anar.value = 0;
		anar.bits.cap_pause = pcs_anar.bits.w0.pause;
		anar.bits.cap_asmpause = pcs_anar.bits.w0.asm_pause;
		*value = anar.value;
		break;
	case MII_AN_LPABLE:
		PCS_REG_RD(handle, portn, PCS_MII_LPA_REG, &val);
		pcs_anlpar.value = (uint16_t)val;
		anlpar.bits.cap_pause = pcs_anlpar.bits.w0.pause;
		anlpar.bits.cap_asmpause = pcs_anlpar.bits.w0.asm_pause;
		*value = anlpar.value;
		break;
	case MII_AN_EXPANSION:
		PCS_REG_RD(handle, portn, PCS_MII_ADVERT_REG, &val);
		pcs_anar.value = (uint16_t)val;
		aner.value = 0;
		aner.bits.lp_an_able = pcs_anar.bits.w0.full_duplex |
		    pcs_anar.bits.w0.half_duplex;
		*value = aner.value;
		break;
	case NXGE_MII_GSR:
		PCS_REG_RD(handle, portn, PCS_MII_LPA_REG, &val);
		pcs_anar.value = (uint16_t)val;
		gsr.value = 0;
		gsr.bits.link_1000fdx = pcs_anar.bits.w0.full_duplex;
		gsr.bits.link_1000hdx = pcs_anar.bits.w0.half_duplex;
		*value = gsr.value;
		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_mac_pcs_mii_read"
		    " Invalid Input: xcvr_reg <0x%x>",
		    xcvr_reg));
		return (NPI_FAILURE | NPI_MAC_REG_INVALID(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_pcs_mii_write(npi_handle_t handle, uint8_t portn, uint8_t xcvr_reg,
			uint16_t value)
{
	pcs_anar_t pcs_anar;
	mii_anar_t anar;
	mii_gcr_t gcr;
	uint64_t val;

	ASSERT(IS_PORT_NUM_VALID(portn));

	switch (xcvr_reg) {
	case MII_CONTROL:
		val = (uint16_t)value;
		PCS_REG_WR(handle, portn, PCS_MII_CTRL_REG, val);
		break;
	case MII_AN_ADVERT:
		PCS_REG_RD(handle, portn, PCS_MII_ADVERT_REG, &val);
		pcs_anar.value = (uint16_t)val;
		anar.value = value;
		pcs_anar.bits.w0.asm_pause = anar.bits.cap_asmpause;
		pcs_anar.bits.w0.pause = anar.bits.cap_pause;
		val = pcs_anar.value;
		PCS_REG_WR(handle, portn, PCS_MII_ADVERT_REG, val);
		break;
	case NXGE_MII_GCR:
		PCS_REG_RD(handle, portn, PCS_MII_ADVERT_REG, &val);
		pcs_anar.value = (uint16_t)val;
		gcr.value = value;
		pcs_anar.bits.w0.full_duplex = gcr.bits.link_1000fdx;
		pcs_anar.bits.w0.half_duplex = gcr.bits.link_1000hdx;
		val = pcs_anar.value;
		PCS_REG_WR(handle, portn, PCS_MII_ADVERT_REG, val);
		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_mac_pcs_mii_write"
		    " Invalid Input: xcvr_reg <0x%x>",
		    xcvr_reg));
		return (NPI_FAILURE | NPI_MAC_REG_INVALID(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_mif_link_intr_enable(npi_handle_t handle, uint8_t portn,
				uint8_t xcvr_reg, uint16_t mask)
{
	mif_cfg_t mif_cfg;

	ASSERT(IS_PORT_NUM_VALID(portn));

	ASSERT(xcvr_reg <= NXGE_MAX_MII_REGS);
	if (xcvr_reg > NXGE_MAX_MII_REGS) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_mac_mif_link_intr_enable"
		    " Invalid Input: xcvr_reg <0x%x>",
		    xcvr_reg));
		return (NPI_FAILURE | NPI_MAC_REG_INVALID(portn));
	}

	MIF_REG_RD(handle, MIF_CONFIG_REG, &mif_cfg.value);

	mif_cfg.bits.w0.phy_addr = portn;		/* Port number */
	mif_cfg.bits.w0.reg_addr = xcvr_reg;		/* Register address */
	mif_cfg.bits.w0.indirect_md = 0; 		/* Clause 22 */
	mif_cfg.bits.w0.poll_en = 1;

	MIF_REG_WR(handle, MIF_MASK_REG, ~mask);
	MIF_REG_WR(handle, MIF_CONFIG_REG, mif_cfg.value);

	NXGE_DELAY(20);

	return (NPI_SUCCESS);
}

npi_status_t
npi_mac_mif_mdio_link_intr_enable(npi_handle_t handle, uint8_t portn,
			uint8_t device, uint16_t xcvr_reg, uint16_t mask)
{
	mif_cfg_t mif_cfg;
	mif_frame_t frame;
	uint_t delay;

	ASSERT(IS_PORT_NUM_VALID(portn));

	frame.bits.w0.st = 0;		/* Clause 45 */
	frame.bits.w0.op = 0;		/* Select address */
	frame.bits.w0.phyad = portn;	/* Port number */
	frame.bits.w0.regad = device;	/* Device number */
	frame.bits.w0.ta_msb = 1;
	frame.bits.w0.ta_lsb = 0;
	frame.bits.w0.data = xcvr_reg;	/* register address */

	MIF_REG_WR(handle, MIF_OUTPUT_FRAME_REG, frame.value);

	delay = 0;
	MIF_WAIT_REG(handle, frame, delay, MIF_DELAY, MAX_PIO_RETRIES);
	if (delay == MAX_PIO_RETRIES)
		return (NPI_FAILURE);

	MIF_REG_RD(handle, MIF_CONFIG_REG, &mif_cfg.value);

	mif_cfg.bits.w0.phy_addr = portn;		/* Port number */
	mif_cfg.bits.w0.reg_addr = device;		/* Register address */
	mif_cfg.bits.w0.indirect_md = 1; 		/* Clause 45 */
	mif_cfg.bits.w0.poll_en = 1;

	MIF_REG_WR(handle, MIF_MASK_REG, ~mask);
	MIF_REG_WR(handle, MIF_CONFIG_REG, mif_cfg.value);

	NXGE_DELAY(20);

	return (NPI_SUCCESS);
}

void
npi_mac_mif_set_indirect_mode(npi_handle_t handle, boolean_t on_off)
{
	mif_cfg_t mif_cfg;

	MIF_REG_RD(handle, MIF_CONFIG_REG, &mif_cfg.value);
	mif_cfg.bits.w0.indirect_md = on_off;
	MIF_REG_WR(handle, MIF_CONFIG_REG, mif_cfg.value);
}

void
npi_mac_mif_set_atca_mode(npi_handle_t handle, boolean_t on_off)
{
	mif_cfg_t mif_cfg;

	MIF_REG_RD(handle, MIF_CONFIG_REG, &mif_cfg.value);
	mif_cfg.bits.w0.atca_ge = on_off;
	MIF_REG_WR(handle, MIF_CONFIG_REG, mif_cfg.value);
}

npi_status_t
npi_bmac_send_pause(npi_handle_t handle, uint8_t portn, uint16_t pause_time)
{
	uint64_t val;

	ASSERT(IS_BMAC_PORT_NUM_VALID(portn));

	val = MAC_SEND_PAUSE_SEND | pause_time;
	BMAC_REG_WR(handle, portn, MAC_SEND_PAUSE_REG, val);

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_xif_led(npi_handle_t handle, uint8_t portn, boolean_t on_off)
{
	uint64_t val = 0;

	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	XMAC_REG_RD(handle, portn, XMAC_CONFIG_REG, &val);

	if (on_off) {
		val |= XMAC_XIF_LED_POLARITY;
		val &= ~XMAC_XIF_FORCE_LED_ON;
	} else {
		val &= ~XMAC_XIF_LED_POLARITY;
		val |= XMAC_XIF_FORCE_LED_ON;
	}

	XMAC_REG_WR(handle, portn, XMAC_CONFIG_REG, val);

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_zap_tx_counters(npi_handle_t handle, uint8_t portn)
{
	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	XMAC_REG_WR(handle, portn, XTXMAC_FRM_CNT_REG, 0);
	XMAC_REG_WR(handle, portn, XTXMAC_BYTE_CNT_REG, 0);

	return (NPI_SUCCESS);
}

npi_status_t
npi_xmac_zap_rx_counters(npi_handle_t handle, uint8_t portn)
{
	ASSERT(IS_XMAC_PORT_NUM_VALID(portn));

	XMAC_REG_WR(handle, portn, XRXMAC_BT_CNT_REG, 0);
	XMAC_REG_WR(handle, portn, XRXMAC_BC_FRM_CNT_REG, 0);
	XMAC_REG_WR(handle, portn, XRXMAC_MC_FRM_CNT_REG, 0);
	XMAC_REG_WR(handle, portn, XRXMAC_FRAG_CNT_REG, 0);
	XMAC_REG_WR(handle, portn, XRXMAC_HIST_CNT1_REG, 0);
	XMAC_REG_WR(handle, portn, XRXMAC_HIST_CNT2_REG, 0);
	XMAC_REG_WR(handle, portn, XRXMAC_HIST_CNT3_REG, 0);
	XMAC_REG_WR(handle, portn, XRXMAC_HIST_CNT4_REG, 0);
	XMAC_REG_WR(handle, portn, XRXMAC_HIST_CNT5_REG, 0);
	XMAC_REG_WR(handle, portn, XRXMAC_HIST_CNT6_REG, 0);
	XMAC_REG_WR(handle, portn, XRXMAC_MPSZER_CNT_REG, 0);
	XMAC_REG_WR(handle, portn, XRXMAC_CRC_ER_CNT_REG, 0);
	XMAC_REG_WR(handle, portn, XRXMAC_CD_VIO_CNT_REG, 0);
	XMAC_REG_WR(handle, portn, XRXMAC_AL_ER_CNT_REG, 0);
	XMAC_REG_WR(handle, portn, XMAC_LINK_FLT_CNT_REG, 0);

	return (NPI_SUCCESS);
}
