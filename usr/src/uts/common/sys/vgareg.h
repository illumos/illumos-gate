/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_VGAREG_H
#define	_SYS_VGAREG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * VGA frame buffer hardware definitions.
 */

#define	VGA8_DEPTH		8
#define	VGA8_CMAP_ENTRIES	256
#define	VGA_TEXT_CMAP_ENTRIES	64

/*
 * General VGA registers
 * These are relative to their register set, which
 * the 3c0-3df set.
 */
#define	VGA_ATR_AD	0x00
#define	VGA_ATR_DATA	0x01
#define	VGA_MISC_W	0x02
#define	VGA_SEQ_ADR	0x04
#define	VGA_SEQ_DATA	0x05
#define	VGA_DAC_BASE	0x06
#define	VGA_DAC_AD_MK	0x06
#define	VGA_DAC_RD_AD	0x07
#define	VGA_DAC_STS	0x07
#define	VGA_DAC_WR_AD	0x08
#define	VGA_DAC_DATA	0x09
#define	VGA_MISC_R	0x0c
#define	VGA_GRC_ADR	0x0e
#define	VGA_GRC_DATA	0x0f
#define	VGA_CRTC_ADR	0x14
#define	VGA_CRTC_DATA	0x15
#define	CGA_STAT	0x1a

/*
 * Attribute controller index bits
 */
#define	VGA_ATR_ENB_PLT	0x20

/*
 * Miscellaneous output bits
 */
#define	VGA_MISC_IOA_SEL	0x01
#define	VGA_MISC_ENB_RAM	0x02
#define	VGA_MISC_VCLK		0x0c
#define		VGA_MISC_VCLK0		0x00
#define		VGA_MISC_VCLK1		0x04
#define		VGA_MISC_VCLK2		0x08
#define		VGA_MISC_VCLK3		0x0c
#define	VGA_MISC_PGSL		0x20
#define	VGA_MISC_HSP		0x40
#define	VGA_MISC_VSP		0x80

/*
 * CRT Controller registers
 */
#define	VGA_CRTC_H_TOTAL	0x00
#define	VGA_CRTC_H_D_END	0x01
#define	VGA_CRTC_S_H_BLNK	0x02
#define	VGA_CRTC_E_H_BLNK	0x03
#define		VGA_CRTC_E_H_BLNK_PUT_EHB(n) \
			((n)&0x1f)
#define	VGA_CRTC_S_H_SY_P	0x04
#define	VGA_CRTC_E_H_SY_P	0x05
#define		VGA_CRTC_E_H_SY_P_HOR_SKW_SHIFT	5
#define		VGA_CRTC_E_H_SY_P_HOR_SKW	0x60
#define		VGA_CRTC_E_H_SY_P_EHB5		7
#define		VGA_CRTC_E_H_SY_P_PUT_HOR_SKW(skew) \
			((skew)<<VGA_CRTC_E_H_SY_P_HOR_SKW_SHIFT)
#define		VGA_CRTC_E_H_SY_P_PUT_EHB(n) \
			((((n)>>5)&1)<<VGA_CRTC_E_H_SY_P_EHB5)
#define		VGA_CRTC_E_H_SY_P_PUT_EHS(n) \
			((n)&0x1f)
#define	VGA_CRTC_V_TOTAL	0x06
#define	VGA_CRTC_OVFL_REG	0x07
#define		VGA_CRTC_OVFL_REG_VT8	0
#define		VGA_CRTC_OVFL_REG_VDE8	1
#define		VGA_CRTC_OVFL_REG_VRS8	2
#define		VGA_CRTC_OVFL_REG_SVB8	3
#define		VGA_CRTC_OVFL_REG_LCM8	4
#define		VGA_CRTC_OVFL_REG_VT9	5
#define		VGA_CRTC_OVFL_REG_VDE9	6
#define		VGA_CRTC_OVFL_REG_VRS9	7
#define		VGA_CRTC_OVFL_REG_PUT_VT(n)	\
			((((n)>>8)&1)<<VGA_CRTC_OVFL_REG_VT8) \
			| ((((n)>>9)&1)<<VGA_CRTC_OVFL_REG_VT9)
#define		VGA_CRTC_OVFL_REG_PUT_VDE(n)	\
			((((n)>>8)&1)<<VGA_CRTC_OVFL_REG_VDE8) \
			| ((((n)>>9)&1)<<VGA_CRTC_OVFL_REG_VDE9)
#define		VGA_CRTC_OVFL_REG_PUT_VRS(n)	\
			((((n)>>8)&1)<<VGA_CRTC_OVFL_REG_VRS8) \
			| ((((n)>>9)&1)<<VGA_CRTC_OVFL_REG_VRS9)
#define		VGA_CRTC_OVFL_REG_PUT_LCM(n)	\
			((((n)>>8)&1)<<VGA_CRTC_OVFL_REG_LCM8)
#define		VGA_CRTC_OVFL_REG_PUT_SVB(n)	\
			((((n)>>8)&1)<<VGA_CRTC_OVFL_REG_SVB8)
#define	VGA_CRTC_P_R_SCAN	0x08
#define	VGA_CRTC_MAX_S_LN	0x09
#define		VGA_CRTC_MAX_S_LN_SVB9	5
#define		VGA_CRTC_MAX_S_LN_LCM9	6
#define		VGA_CRTC_MAX_S_LN_PUT_SVB(n)	\
			((((n)>>9)&1)<<VGA_CRTC_MAX_S_LN_SVB9)
#define		VGA_CRTC_MAX_S_LN_PUT_LCM(n)	\
			((((n)>>9)&1)<<VGA_CRTC_MAX_S_LN_LCM9)
#define	VGA_CRTC_CSSL		0x0a
#define	VGA_CRTC_CESL		0x0b
#define	VGA_CRTC_STAH		0x0c
#define	VGA_CRTC_STAL		0x0d
#define	VGA_CRTC_CLAH		0x0e
#define	VGA_CRTC_CLAL		0x0f
#define	VGA_CRTC_VRS		0x10
#define	VGA_CRTC_VRE		0x11
#define		VGA_CRTC_VRE_LOCK	0x80
#define		VGA_CRTC_VRE_DIS_VINT	0x20
#define		VGA_CRTC_VRE_PUT_VRE(n) \
			((n)&0x0f)
#define	VGA_CRTC_VDE		0x12
#define	VGA_CRTC_SCREEN_OFFSET	0x13
#define	VGA_CRTC_ULL		0x14
#define	VGA_CRTC_SVB		0x15
#define	VGA_CRTC_EVB		0x16
#define	VGA_CRTC_CRT_MD		0x17
#define		VGA_CRTC_CRT_MD_2BK_CGA		0x01
#define		VGA_CRTC_CRT_MD_4BK_HGC		0x02
#define		VGA_CRTC_CRT_MD_VT_X2		0x04
#define		VGA_CRTC_CRT_MD_WRD_MODE	0x08
#define		VGA_CRTC_CRT_MD_ADW_16K		0x20
#define		VGA_CRTC_CRT_MD_BYTE_MODE	0x40
#define		VGA_CRTC_CRT_MD_NO_RESET	0x80
#define	VGA_CRTC_LCM		0x18

/*
 * Sequencer registers
 */
#define	VGA_SEQ_RST_SYN		0x00
#define		VGA_SEQ_RST_SYN_ASYNC_RESET	0x00
#define		VGA_SEQ_RST_SYN_NO_ASYNC_RESET	0x01
#define		VGA_SEQ_RST_SYN_SYNC_RESET	0x00
#define		VGA_SEQ_RST_SYN_NO_SYNC_RESET	0x02
#define	VGA_SEQ_CLK_MODE	0x01
#define		VGA_SEQ_CLK_MODE_8DC		0x01
#define	VGA_SEQ_EN_WT_PL	0x02
#define		VGA_SEQ_EN_WT_PL_ALL		0x0f
#define	VGA_SEQ_MEM_MODE	0x04
#define		VGA_SEQ_MEM_MODE_EXT_MEM	0x02
#define		VGA_SEQ_MEM_MODE_SEQ_MODE	0x04
#define		VGA_SEQ_MEM_MODE_CHN_4M		0x08

/*
 * Graphics Controller
 */
#define	VGA_GRC_SET_RST_DT	0x00
#define	VGA_GRC_EN_S_R_DT	0x01
#define	VGA_GRC_COLOR_CMP	0x02
#define	VGA_GRC_WT_ROP_RTC	0x03
#define	VGA_GRC_RD_PL_SL	0x04
#define	VGA_GRC_GRP_MODE	0x05
#define		VGA_GRC_GRP_MODE_SHF_MODE_256	0x40
#define	VGA_GRC_MISC_GM		0x06
#define		VGA_GRC_MISC_GM_GRAPH		0x01
#define		VGA_GRC_MISC_GM_MEM_MAP_1	0x04
#define	VGA_GRC_CMP_DNTC	0x07
#define		VGA_GRC_CMP_DNTC_ALL		0x0f
#define	VGA_GRC_BIT_MASK	0x08

/*
 * Attribute controller registers
 */
#define	VGA_ATR_PLT_REG		0x00
#define	VGA_ATR_NUM_PLT		0x10
#define	VGA_ATR_MODE		0x10
#define		VGA_ATR_MODE_GRAPH	0x01
#define		VGA_ATR_MODE_9WIDE	0x04
#define		VGA_ATR_MODE_BLINK	0x08
#define		VGA_ATR_MODE_256CLR	0x40
#define	VGA_ATR_BDR_CLR		0x11
#define	VGA_ATR_DISP_PLN	0x12
#define		VGA_ATR_DISP_PLN_ALL	0x0f
#define	VGA_ATR_H_PX_PAN	0x13
#define	VGA_ATR_PX_PADD		0x14

/*
 * Low-memory frame buffer definitions.  These are relative to the
 * A0000 register set.
 */
#define	VGA_MONO_BASE		0x10000	/* Base of monochrome text */
#define	VGA_COLOR_BASE		0x18000	/* Base of color text */
#define	VGA_TEXT_SIZE		0x8000	/* Size of text frame buffer */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_VGAREG_H */
