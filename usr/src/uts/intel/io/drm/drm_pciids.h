/*
 * This file is auto-generated from the drm_pciids.txt in the DRM CVS
 * Please contact dri-devel@lists.sf.net to add new cards to this list
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DRM_PCIIDS_H_
#define	_DRM_PCIIDS_H_

#ifdef	__cplusplus
extern "C" {
#endif

#define	radeon_PCI_IDS\
	{0x1002, 0x4136, CHIP_RS100|RADEON_IS_IGP, \
	    "ATI Radeon RS100 IGP 320M"}, \
	{0x1002, 0x4137, CHIP_RS200|RADEON_IS_IGP, "ATI Radeon RS200 IGP"}, \
	{0x1002, 0x4144, CHIP_R300, "ATI Radeon AD 9500 Pro"}, \
	{0x1002, 0x4145, CHIP_R300, "ATI Radeon AE 9700 Pro"}, \
	{0x1002, 0x4146, CHIP_R300, "ATI Radeon AF 9700 Pro"}, \
	{0x1002, 0x4147, CHIP_R300, "ATI FireGL AG Z1/X1"}, \
	{0x1002, 0x4150, CHIP_RV350, "ATI Radeon AP 9600"}, \
	{0x1002, 0x4151, CHIP_RV350, "ATI Radeon AQ 9600"}, \
	{0x1002, 0x4152, CHIP_RV350, "ATI Radeon AR 9600"}, \
	{0x1002, 0x4153, CHIP_RV350, "ATI Radeon AS 9600 AS"}, \
	{0x1002, 0x4154, CHIP_RV350, "ATI FireGL AT T2"}, \
	{0x1002, 0x4156, CHIP_RV350, "ATI FireGL AV T2"}, \
	{0x1002, 0x4237, CHIP_RS200|RADEON_IS_IGP, "ATI Radeon RS250 IGP"}, \
	{0x1002, 0x4242, CHIP_R200, "ATI Radeon BB R200 AIW 8500DV"}, \
	{0x1002, 0x4243, CHIP_R200, "ATI Radeon BC R200"}, \
	{0x1002, 0x4336, CHIP_RS100|RADEON_IS_IGP|RADEON_IS_MOBILITY, \
		"ATI Radeon RS100 Mobility U1"}, \
	{0x1002, 0x4337, CHIP_RS200|RADEON_IS_IGP|RADEON_IS_MOBILITY, \
		"ATI Radeon RS200 Mobility IGP 340M"}, \
	{0x1002, 0x4437, CHIP_RS200|RADEON_IS_IGP|RADEON_IS_MOBILITY, \
		"ATI Radeon RS250 Mobility IGP"}, \
	{0x1002, 0x4966, CHIP_RV250, "ATI Radeon If R250 9000"}, \
	{0x1002, 0x4967, CHIP_RV250, "ATI Radeon Ig R250 9000"}, \
	{0x1002, 0x4A49, CHIP_R420, "ATI Radeon JI R420 X800PRO"}, \
	{0x1002, 0x4A4B, CHIP_R420, "ATI Radeon JK R420 X800 XT"}, \
	{0x1002, 0x4C57, CHIP_RV200|RADEON_IS_MOBILITY, \
		"ATI Radeon LW RV200 Mobility 7500 M7"}, \
	{0x1002, 0x4C58, CHIP_RV200|RADEON_IS_MOBILITY, \
		"ATI Radeon LX RV200 Mobility FireGL 7800 M7"}, \
	{0x1002, 0x4C59, CHIP_RV100|RADEON_IS_MOBILITY, \
		"ATI Radeon LY RV100 Mobility M6"}, \
	{0x1002, 0x4C5A, CHIP_RV100|RADEON_IS_MOBILITY, \
		"ATI Radeon LZ RV100 Mobility M6"}, \
	{0x1002, 0x4C64, CHIP_RV250|RADEON_IS_MOBILITY, \
		"ATI Radeon Ld RV250 Mobility 9000 M9"}, \
	{0x1002, 0x4C66, CHIP_RV250|RADEON_IS_MOBILITY, \
		"ATI Radeon Lf R250 Mobility 9000 M9"}, \
	{0x1002, 0x4C67, CHIP_RV250|RADEON_IS_MOBILITY, \
		"ATI Radeon Lg R250 Mobility 9000 M9"}, \
	{0x1002, 0x4E44, CHIP_R300, "ATI Radeon ND R300 9700 Pro"}, \
	{0x1002, 0x4E45, CHIP_R300, "ATI Radeon NE R300 9500 Pro"}, \
	{0x1002, 0x4E46, CHIP_RV350, "ATI Radeon NF RV350 9600"}, \
	{0x1002, 0x4E47, CHIP_R300, "ATI Radeon NG R300 FireGL X1"}, \
	{0x1002, 0x4E48, CHIP_R350, "ATI Radeon NH R350 9800 Pro"}, \
	{0x1002, 0x4E49, CHIP_R350, "ATI Radeon NI R350 9800"}, \
	{0x1002, 0x4E4A, CHIP_RV350, "ATI Radeon NJ RV350 9800 XT"}, \
	{0x1002, 0x4E4B, CHIP_R350, "ATI Radeon NK R350 FireGL X2"}, \
	{0x1002, 0x4E50, CHIP_RV350|RADEON_IS_MOBILITY, \
		"ATI Radeon RV300 Mobility 9600 M10"}, \
	{0x1002, 0x4E51, CHIP_RV350|RADEON_IS_MOBILITY, \
		"ATI Radeon RV350 Mobility 9600 M10 NQ"}, \
	{0x1002, 0x4E54, CHIP_RV350|RADEON_IS_MOBILITY, \
		"ATI Radeon FireGL T2 128"}, \
	{0x1002, 0x4E56, CHIP_RV350|RADEON_IS_MOBILITY, \
		"ATI Radeon FireGL Mobility T2e"}, \
	{0x1002, 0x5144, CHIP_R100|RADEON_SINGLE_CRTC, "ATI Radeon QD R100"}, \
	{0x1002, 0x5145, CHIP_R100|RADEON_SINGLE_CRTC, "ATI Radeon QE R100"}, \
	{0x1002, 0x5146, CHIP_R100|RADEON_SINGLE_CRTC, "ATI Radeon QF R100"}, \
	{0x1002, 0x5147, CHIP_R100|RADEON_SINGLE_CRTC, "ATI Radeon QG R100"}, \
	{0x1002, 0x5148, CHIP_R200, "ATI Radeon QH R200 8500"}, \
	{0x1002, 0x5149, CHIP_R200, "ATI Radeon QI R200"}, \
	{0x1002, 0x514A, CHIP_R200, "ATI Radeon QJ R200"}, \
	{0x1002, 0x514B, CHIP_R200, "ATI Radeon QK R200"}, \
	{0x1002, 0x514C, CHIP_R200, "ATI Radeon QL R200 8500 LE"}, \
	{0x1002, 0x514D, CHIP_R200, "ATI Radeon QM R200 9100"}, \
	{0x1002, 0x514E, CHIP_R200, "ATI Radeon QN R200 8500 LE"}, \
	{0x1002, 0x514F, CHIP_R200, "ATI Radeon QO R200 8500 LE"}, \
	{0x1002, 0x5157, CHIP_RV200, "ATI Radeon QW RV200 7500"}, \
	{0x1002, 0x5158, CHIP_RV200, "ATI Radeon QX RV200 7500"}, \
	{0x1002, 0x5159, CHIP_RV100, "ATI Radeon QY RV100 7000/VE"}, \
	{0x1002, 0x515A, CHIP_RV100, "ATI Radeon QZ RV100 7000/VE"}, \
	{0x1002, 0x515E, CHIP_RV100, "ATI ES1000 RN50"}, \
	{0x1002, 0x5168, CHIP_R200, "ATI Radeon Qh R200"}, \
	{0x1002, 0x5169, CHIP_R200, "ATI Radeon Qi R200"}, \
	{0x1002, 0x516A, CHIP_R200, "ATI Radeon Qj R200"}, \
	{0x1002, 0x516B, CHIP_R200, "ATI Radeon Qk R200"}, \
	{0x1002, 0x516C, CHIP_R200, "ATI Radeon Ql R200"}, \
	{0x1002, 0x5460, CHIP_RV350, "ATI Radeon X300"}, \
	{0x1002, 0x554F, CHIP_R350, "ATI Radeon X800"}, \
	{0x1002, 0x5653, CHIP_RV410|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP, \
		"ATI Radeon Mobility X700 M26"}, \
	{0x1002, 0x5834, CHIP_RS300|RADEON_IS_IGP, "ATI Radeon RS300 IGP"}, \
	{0x1002, 0x5835, CHIP_RS300|RADEON_IS_IGP|RADEON_IS_MOBILITY, \
		"ATI Radeon RS300 Mobility IGP"}, \
	{0x1002, 0x5836, CHIP_RS300|RADEON_IS_IGP, "ATI Radeon RS300 IGP"}, \
	{0x1002, 0x5837, CHIP_RS300|RADEON_IS_IGP, "ATI Radeon RS300 IGP"}, \
	{0x1002, 0x5960, CHIP_RV280, "ATI Radeon RV280 9200"}, \
	{0x1002, 0x5961, CHIP_RV280, "ATI Radeon RV280 9200 SE"}, \
	{0x1002, 0x5962, CHIP_RV280, "ATI Radeon RV280 9200"}, \
	{0x1002, 0x5963, CHIP_RV280, "ATI Radeon RV280 9200"}, \
	{0x1002, 0x5964, CHIP_RV280, "ATI Radeon RV280 9200 SE"}, \
	{0x1002, 0x5968, CHIP_RV280, "ATI Radeon RV280 9200"}, \
	{0x1002, 0x5969, CHIP_RV100, "ATI ES1000 RN50"}, \
	{0x1002, 0x596A, CHIP_RV280, "ATI Radeon RV280 9200"}, \
	{0x1002, 0x596B, CHIP_RV280, "ATI Radeon RV280 9200"}, \
	{0x1002, 0x5b60, CHIP_RV350, "ATI Radeon RV370 X300SE"}, \
	{0x1002, 0x5c61, CHIP_RV280|RADEON_IS_MOBILITY, \
		"ATI Radeon RV280 Mobility"}, \
	{0x1002, 0x5c62, CHIP_RV280, "ATI Radeon RV280"}, \
	{0x1002, 0x5c63, CHIP_RV280|RADEON_IS_MOBILITY, \
		"ATI Radeon RV280 Mobility"}, \
	{0x1002, 0x5c64, CHIP_RV280, "ATI Radeon RV280"}, \
	{0x1002, 0x5d4d, CHIP_R350, "ATI Radeon R480"}, \
	{0, 0, 0, NULL}

#define	r128_PCI_IDS\
	{0x1002, 0x4c45, 0, "ATI Rage 128 Mobility LE (PCI)"}, \
	{0x1002, 0x4c46, 0, "ATI Rage 128 Mobility LF (AGP)"}, \
	{0x1002, 0x4d46, 0, "ATI Rage 128 Mobility MF (AGP)"}, \
	{0x1002, 0x4d4c, 0, "ATI Rage 128 Mobility ML (AGP)"}, \
	{0x1002, 0x5041, 0, "ATI Rage 128 Pro PA (PCI)"}, \
	{0x1002, 0x5042, 0, "ATI Rage 128 Pro PB (AGP)"}, \
	{0x1002, 0x5043, 0, "ATI Rage 128 Pro PC (AGP)"}, \
	{0x1002, 0x5044, 0, "ATI Rage 128 Pro PD (PCI)"}, \
	{0x1002, 0x5045, 0, "ATI Rage 128 Pro PE (AGP)"}, \
	{0x1002, 0x5046, 0, "ATI Rage 128 Pro PF (AGP)"}, \
	{0x1002, 0x5047, 0, "ATI Rage 128 Pro PG (PCI)"}, \
	{0x1002, 0x5048, 0, "ATI Rage 128 Pro PH (AGP)"}, \
	{0x1002, 0x5049, 0, "ATI Rage 128 Pro PI (AGP)"}, \
	{0x1002, 0x504A, 0, "ATI Rage 128 Pro PJ (PCI)"}, \
	{0x1002, 0x504B, 0, "ATI Rage 128 Pro PK (AGP)"}, \
	{0x1002, 0x504C, 0, "ATI Rage 128 Pro PL (AGP)"}, \
	{0x1002, 0x504D, 0, "ATI Rage 128 Pro PM (PCI)"}, \
	{0x1002, 0x504E, 0, "ATI Rage 128 Pro PN (AGP)"}, \
	{0x1002, 0x504F, 0, "ATI Rage 128 Pro PO (AGP)"}, \
	{0x1002, 0x5050, 0, "ATI Rage 128 Pro PP (PCI)"}, \
	{0x1002, 0x5051, 0, "ATI Rage 128 Pro PQ (AGP)"}, \
	{0x1002, 0x5052, 0, "ATI Rage 128 Pro PR (PCI)"}, \
	{0x1002, 0x5053, 0, "ATI Rage 128 Pro PS (PCI)"}, \
	{0x1002, 0x5054, 0, "ATI Rage 128 Pro PT (AGP)"}, \
	{0x1002, 0x5055, 0, "ATI Rage 128 Pro PU (AGP)"}, \
	{0x1002, 0x5056, 0, "ATI Rage 128 Pro PV (PCI)"}, \
	{0x1002, 0x5057, 0, "ATI Rage 128 Pro PW (AGP)"}, \
	{0x1002, 0x5058, 0, "ATI Rage 128 Pro PX (AGP)"}, \
	{0x1002, 0x5245, 0, "ATI Rage 128 RE (PCI)"}, \
	{0x1002, 0x5246, 0, "ATI Rage 128 RF (AGP)"}, \
	{0x1002, 0x5247, 0, "ATI Rage 128 RG (AGP)"}, \
	{0x1002, 0x524b, 0, "ATI Rage 128 RK (PCI)"}, \
	{0x1002, 0x524c, 0, "ATI Rage 128 RL (AGP)"}, \
	{0x1002, 0x534d, 0, "ATI Rage 128 SM (AGP)"}, \
	{0x1002, 0x5446, 0, "ATI Rage 128 Pro Ultra TF (AGP)"}, \
	{0x1002, 0x544C, 0, "ATI Rage 128 Pro Ultra TL (AGP)"}, \
	{0x1002, 0x5452, 0, "ATI Rage 128 Pro Ultra TR (AGP)"}, \
	{0, 0, 0, NULL}

#define	mach64_PCI_IDS\
	{0x1002, 0x4749, 0, "3D Rage Pro"}, \
	{0x1002, 0x4750, 0, "3D Rage Pro 215GP"}, \
	{0x1002, 0x4751, 0, "3D Rage Pro 215GQ"}, \
	{0x1002, 0x4742, 0, "3D Rage Pro AGP 1X/2X"}, \
	{0x1002, 0x4744, 0, "3D Rage Pro AGP 1X"}, \
	{0x1002, 0x4c49, 0, "3D Rage LT Pro"}, \
	{0x1002, 0x4c50, 0, "3D Rage LT Pro"}, \
	{0x1002, 0x4c51, 0, "3D Rage LT Pro"}, \
	{0x1002, 0x4c42, 0, "3D Rage LT Pro AGP-133"}, \
	{0x1002, 0x4c44, 0, "3D Rage LT Pro AGP-66"}, \
	{0x1002, 0x474c, 0, "Rage XC"}, \
	{0x1002, 0x474f, 0, "Rage XL"}, \
	{0x1002, 0x4752, 0, "Rage XL"}, \
	{0x1002, 0x4753, 0, "Rage XC"}, \
	{0x1002, 0x474d, 0, "Rage XL AGP 2X"}, \
	{0x1002, 0x474e, 0, "Rage XC AGP"}, \
	{0x1002, 0x4c52, 0, "Rage Mobility P/M"}, \
	{0x1002, 0x4c53, 0, "Rage Mobility L"}, \
	{0x1002, 0x4c4d, 0, "Rage Mobility P/M AGP 2X"}, \
	{0x1002, 0x4c4e, 0, "Rage Mobility L AGP 2X"}, \
	{0, 0, 0, NULL}

#define	i915_PCI_IDS\
	{0x8086, 0x2562, CHIP_I8XX, "Intel i845G GMCH"}, \
	{0x8086, 0x3582, CHIP_I8XX, "Intel i852GM/i855GM GMCH"}, \
	{0x8086, 0x2572, CHIP_I8XX, "Intel i865G GMCH"}, \
	{0x8086, 0x2582, CHIP_I9XX|CHIP_I915, "Intel i915G"}, \
	{0x8086, 0x2592, CHIP_I9XX|CHIP_I915, "Intel i915GM"}, \
	{0x8086, 0x2772, CHIP_I9XX|CHIP_I915, "Intel i945G"}, \
	{0x8086, 0x27A2, CHIP_I9XX|CHIP_I915, "Intel i945GM"}, \
	{0x8086, 0x2972, CHIP_I9XX|CHIP_I965, "Intel i946GZ"}, \
	{0x8086, 0x2982, CHIP_I9XX|CHIP_I965, "Intel i965G"}, \
	{0x8086, 0x2992, CHIP_I9XX|CHIP_I965, "Intel i965Q"}, \
	{0x8086, 0x29A2, CHIP_I9XX|CHIP_I965, "Intel i965G"}, \
	{0x8086, 0x2A02, CHIP_I9XX|CHIP_I965, "Intel i965GM"}, \
	{0x8086, 0x2A12, CHIP_I9XX|CHIP_I965, "Intel i965GME/GLE"}, \
	{0x8086, 0x29C2, CHIP_I9XX|CHIP_I915, "Intel G33"}, \
	{0x8086, 0x29B2, CHIP_I9XX|CHIP_I915, "Intel Q35"}, \
	{0x8086, 0x29D2, CHIP_I9XX|CHIP_I915, "Intel Q33"}, \
	{0x8086, 0x2A42, CHIP_I9XX|CHIP_I965, "Intel GM45"}, \
	{0x8086, 0x2E02, CHIP_I9XX|CHIP_I965, "Intel EL"}, \
	{0x8086, 0x2E12, CHIP_I9XX|CHIP_I965, "Intel Q45"}, \
	{0x8086, 0x2E22, CHIP_I9XX|CHIP_I965, "Intel G45"}, \
	{0, 0, 0, NULL}

#ifdef	__cplusplus
}
#endif

#endif	/* _DRM_PCIIDS_H_ */
