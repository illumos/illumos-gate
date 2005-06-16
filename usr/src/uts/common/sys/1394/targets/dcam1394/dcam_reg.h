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

#ifndef	_SYS_1394_TARGETS_DCAM1394_REG_H
#define	_SYS_1394_TARGETS_DCAM1394_REG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/1394/targets/dcam1394/dcam.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * dcam spec: Sec 1.1 Camera Initialize Register
 */
#define	DCAM1394_REG_OFFS_INITIALIZE		0x0
#define	DCAM1394_REG_VAL_INITIALIZE_ASSERT	0x80000000

/*
 * dcam spec: Sec 1.2.1.1 Inquiry Register for Video Mode
 */
#define	DCAM1394_REG_OFFS_VID_MODE_INQ		0x180

/*
 * dcam spec: Sec 1.2.2 Inquiry Register for Video Frame Rate
 */
#define	DCAM1394_REG_OFFS_FRAME_RATE_INQ_BASE	0x200

/*
 * dcam spec: basic function inquiry registers, sec 1.3
 */
#define	DCAM1394_REG_OFFS_BASIC_FUNC_INQ	0x400

#define	DCAM1394_MASK_CAM_POWER_CTRL		0x8000
#define	DCAM1394_SHIFT_CAM_POWER_CTRL		15


/*
 * dcam spec: Sec 1.5 Inquiry Register for Feature Elements
 */
#define	DCAM1394_REG_OFFS_FEATURE_ELM_INQ_BASE  0x500

#define	DCAM1394_REG_OFFS_BRIGHTNESS_INQ	0x0
#define	DCAM1394_REG_OFFS_EXPOSURE_INQ		0x4
#define	DCAM1394_REG_OFFS_SHARPNESS_INQ		0x8
#define	DCAM1394_REG_OFFS_WHITE_BALANCE_INQ	0xC
#define	DCAM1394_REG_OFFS_HUE_INQ		0x10
#define	DCAM1394_REG_OFFS_SATURATION_INQ	0x14
#define	DCAM1394_REG_OFFS_GAMMA_INQ		0x18
#define	DCAM1394_REG_OFFS_SHUTTER_INQ		0x1C
#define	DCAM1394_REG_OFFS_GAIN_INQ		0x20
#define	DCAM1394_REG_OFFS_IRIS_INQ		0x24
#define	DCAM1394_REG_OFFS_FOCUS_INQ		0x28
#define	DCAM1394_REG_OFFS_ZOOM_INQ		0x80
#define	DCAM1394_REG_OFFS_PAN_INQ		0x84
#define	DCAM1394_REG_OFFS_TILT_INQ		0x88

/*
 * "presence of feature" bit is located in Feature Presence Inquiry
 * Register(Sec 1.4) Feature Element Inquiry Register(Sec 1.5) and Feature
 * Status and Control Register(Sec 1.7); driver will use later.
 */
#define	DCAM1394_MASK_READOUT_INQ	0x8000000
#define	DCAM1394_SHIFT_READOUT_INQ	27

#define	DCAM1394_MASK_ON_OFF_INQ	0x4000000
#define	DCAM1394_SHIFT_ON_OFF_INQ	26

#define	DCAM1394_MASK_AUTO_INQ		0x2000000
#define	DCAM1394_SHIFT_AUTO_INQ		25

#define	DCAM1394_MASK_MANUAL_INQ	0x1000000
#define	DCAM1394_SHIFT_MANUAL_INQ	24

#define	DCAM1394_MASK_MIN_VAL		0xFFF000
#define	DCAM1394_SHIFT_MIN_VAL		12

#define	DCAM1394_MASK_MAX_VAL		0xFFF
#define	DCAM1394_SHIFT_MAX_VAL		0


/*
 * dcam spec: Sec 1.6
 */
#define	DCAM1394_REG_OFFS_CUR_V_FRM_RATE	0x600
#define	DCAM1394_SHIFT_CUR_V_FRM_RATE		29

#define	DCAM1394_REG_OFFS_CUR_V_MODE		0x604
#define	DCAM1394_SHIFT_CUR_V_MODE		29

#define	DCAM1394_REG_OFFS_CUR_V_FORMAT		0x608
#define	DCAM1394_REG_OFFS_CUR_ISO_CHANNEL	0x60C

#define	DCAM1394_REG_OFFS_CAMERA_POWER		0x610
#define	  DCAM1394_SHIFT_CAMERA_POWER		31

#define	DCAM1394_REG_OFFS_ISO_EN		0x614
#define	DCAM1394_REG_OFFS_MEMORY_SAVE		0x618
#define	DCAM1394_REG_OFFS_ONE_SHOT		0x61C
#define	DCAM1394_REG_OFFS_MEM_SAVE_CH		0x620
#define	DCAM1394_REG_OFFS_CUR_MEM_CH		0x624


#define	DCAM1394_REG_OFFS_FEATURE_CSR_BASE	0x800

#define	DCAM1394_REG_OFFS_BRIGHTNESS_CSR	0x0
#define	DCAM1394_REG_OFFS_EXPOSURE_CSR		0x4
#define	DCAM1394_REG_OFFS_SHARPNESS_CSR		0x8
#define	DCAM1394_REG_OFFS_WHITE_BALANCE_CSR	0xC
#define	DCAM1394_REG_OFFS_HUE_CSR		0x10
#define	DCAM1394_REG_OFFS_SATURATION_CSR	0x14
#define	DCAM1394_REG_OFFS_GAMMA_CSR		0x18
#define	DCAM1394_REG_OFFS_SHUTTER_CSR		0x1C
#define	DCAM1394_REG_OFFS_GAIN_CSR		0x20
#define	DCAM1394_REG_OFFS_IRIS_CSR		0x24
#define	DCAM1394_REG_OFFS_FOCUS_CSR		0x28
#define	DCAM1394_REG_OFFS_ZOOM_CSR		0x80
#define	DCAM1394_REG_OFFS_PAN_CSR		0x84
#define	DCAM1394_REG_OFFS_TILT_CSR		0x88

#define	DCAM1394_MASK_PRESENCE_INQ		0x80000000
#define	DCAM1394_SHIFT_PRESENCE_INQ		31

#define	DCAM1394_MASK_ON_OFF			0x2000000
#define	DCAM1394_SHIFT_ON_OFF			25

#define	DCAM1394_MASK_A_M_MODE			0x1000000
#define	DCAM1394_SHIFT_A_M_MODE			24

#define	DCAM1394_MASK_VALUE			0xFFF  /* XXX: chk vals */
#define	DCAM1394_SHIFT_VALUE			0

/*
 * white balance feature's u and v values
 */
#define	DCAM1394_MASK_U_VALUE			0xFFF000
#define	DCAM1394_SHIFT_U_VALUE			12

#define	DCAM1394_MASK_V_VALUE			0xFFF
#define	DCAM1394_SHIFT_V_VALUE			0

int	dcam_reg_read(dcam_state_t *soft_state, dcam1394_reg_io_t *arg);
int	dcam_reg_write(dcam_state_t *soft_state, dcam1394_reg_io_t *arg);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_1394_TARGETS_DCAM1394_REG_H */
