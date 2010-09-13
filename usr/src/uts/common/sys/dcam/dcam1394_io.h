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

#ifndef _SYS_DCAM_DCAM1394_IO_H
#define	_SYS_DCAM_DCAM1394_IO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* macros for manipulating dcam1394_param_list_t structure */
#define	PARAM_LIST_INIT(list)			bzero(list, sizeof (list))
#define	PARAM_LIST_ADD(list, param, subparam)	list[param][subparam].flag = 1
#define	PARAM_LIST_REMOVE(list, param, subparam)  list[param][subparam].flag = 0
#define	PARAM_LIST_IS_ENTRY(list, param, subparam) list[param][subparam].flag
#define	PARAM_VAL(list, param, subparam)	list[param][subparam].val
#define	PARAM_ERR(list, param, subparam)	list[param][subparam].err

#define	DCAM1394_NUM_PARAM	30
#define	DCAM1394_NUM_SUBPARAM	24

/* parameters */
#define	DCAM1394_PARAM_CAP_POWER_CTRL			0x0
#define	DCAM1394_PARAM_CAP_VID_MODE			0x1
#define	DCAM1394_PARAM_CAP_FRAME_RATE_VID_MODE_0	0x2
#define	DCAM1394_PARAM_CAP_FRAME_RATE_VID_MODE_1	0x3
#define	DCAM1394_PARAM_CAP_FRAME_RATE_VID_MODE_2	0x4
#define	DCAM1394_PARAM_CAP_FRAME_RATE_VID_MODE_3	0x5
#define	DCAM1394_PARAM_CAP_FRAME_RATE_VID_MODE_4	0x6
#define	DCAM1394_PARAM_CAP_FRAME_RATE_VID_MODE_5	0x7
#define	DCAM1394_PARAM_POWER				0x8
#define	DCAM1394_PARAM_VID_MODE				0x9
#define	DCAM1394_PARAM_FRAME_RATE			0xA
#define	DCAM1394_PARAM_RING_BUFF_CAPACITY		0xB
#define	DCAM1394_PARAM_RING_BUFF_NUM_FRAMES_READY	0xC
#define	DCAM1394_PARAM_RING_BUFF_READ_PTR_INCR		0xD
#define	DCAM1394_PARAM_FRAME_NUM_BYTES			0xE
#define	DCAM1394_PARAM_STATUS				0xF
#define	DCAM1394_PARAM_BRIGHTNESS			0x10
#define	DCAM1394_PARAM_EXPOSURE				0x11
#define	DCAM1394_PARAM_SHARPNESS			0x12
#define	DCAM1394_PARAM_WHITE_BALANCE			0x13
#define	DCAM1394_PARAM_HUE				0x14
#define	DCAM1394_PARAM_SATURATION			0x15
#define	DCAM1394_PARAM_GAMMA				0x16
#define	DCAM1394_PARAM_SHUTTER				0x17
#define	DCAM1394_PARAM_GAIN				0x18
#define	DCAM1394_PARAM_IRIS				0x19
#define	DCAM1394_PARAM_FOCUS				0x1A
#define	DCAM1394_PARAM_ZOOM				0x1B
#define	DCAM1394_PARAM_PAN				0x1C
#define	DCAM1394_PARAM_TILT				0x1D

/* subparameters */

/* for DCAM1394_PARAM_CAP_VID_MODE */
#define	DCAM1394_SUBPARAM_VID_MODE_0			0x0
#define	DCAM1394_SUBPARAM_VID_MODE_YUV_444_160_120	0x0
#define	DCAM1394_SUBPARAM_VID_MODE_1			0x1
#define	DCAM1394_SUBPARAM_VID_MODE_YUV_422_320_240	0x1
#define	DCAM1394_SUBPARAM_VID_MODE_2			0x2
#define	DCAM1394_SUBPARAM_VID_MODE_YUV_411_640_480	0x2
#define	DCAM1394_SUBPARAM_VID_MODE_3			0x3
#define	DCAM1394_SUBPARAM_VID_MODE_YUV_422_640_480	0x3
#define	DCAM1394_SUBPARAM_VID_MODE_4			0x4
#define	DCAM1394_SUBPARAM_VID_MODE_RGB_640_480		0x4
#define	DCAM1394_SUBPARAM_VID_MODE_5			0x5
#define	DCAM1394_SUBPARAM_VID_MODE_Y_640_480		0x5

/* for DCAM1394_PARAM_CAP_FRAME_RATE_VID_MODE_0 */
#define	DCAM1394_SUBPARAM_FRAME_RATE_0			0x6
#define	DCAM1394_SUBPARAM_FRAME_RATE_3_75_FPS		0x6
#define	DCAM1394_SUBPARAM_FRAME_RATE_1			0x7
#define	DCAM1394_SUBPARAM_FRAME_RATE_7_5_FPS		0x7
#define	DCAM1394_SUBPARAM_FRAME_RATE_2			0x8
#define	DCAM1394_SUBPARAM_FRAME_RATE_15_FPS		0x8
#define	DCAM1394_SUBPARAM_FRAME_RATE_3			0x9
#define	DCAM1394_SUBPARAM_FRAME_RATE_30_FPS		0x9
#define	DCAM1394_SUBPARAM_FRAME_RATE_4			0xA
#define	DCAM1394_SUBPARAM_FRAME_RATE_60_FPS		0xA

/* for features */
#define	DCAM1394_SUBPARAM_PRESENCE			0xB
#define	DCAM1394_SUBPARAM_CAP_READ			0xC
#define	DCAM1394_SUBPARAM_CAP_ON_OFF			0xD
#define	DCAM1394_SUBPARAM_CAP_CTRL_AUTO			0xE
#define	DCAM1394_SUBPARAM_CAP_CTRL_MANUAL		0xF
#define	DCAM1394_SUBPARAM_MIN_VAL			0x10
#define	DCAM1394_SUBPARAM_MAX_VAL			0x11
#define	DCAM1394_SUBPARAM_ON_OFF			0x12
#define	DCAM1394_SUBPARAM_CTRL_MODE			0x13
#define	DCAM1394_SUBPARAM_VALUE				0x14

/* for white balance feature */
#define	DCAM1394_SUBPARAM_U_VALUE			0x15
#define	DCAM1394_SUBPARAM_V_VALUE			0x16

#define	DCAM1394_SUBPARAM_NONE				0x17

/* parameter values */

/* for video mode param */

#define	DCAM1394_VID_MODE_0			0x0
#define	DCAM1394_VID_MODE_YUV_444_160_120	0x0

#define	DCAM1394_VID_MODE_1			0x1
#define	DCAM1394_VID_MODE_YUV_422_320_240	0x1

#define	DCAM1394_VID_MODE_2			0x2
#define	DCAM1394_VID_MODE_YUV_411_640_480	0x2

#define	DCAM1394_VID_MODE_3			0x3
#define	DCAM1394_VID_MODE_YUV_422_640_480	0x3

#define	DCAM1394_VID_MODE_4			0x4
#define	DCAM1394_VID_MODE_RGB_640_480		0x4

#define	DCAM1394_VID_MODE_5			0x5
#define	DCAM1394_VID_MODE_Y_640_480		0x5

/* for frame rate param */

#define	DCAM1394_FRAME_RATE_0			0x6
#define	DCAM1394_3_75_FPS			0x6

#define	DCAM1394_FRAME_RATE_1			0x7
#define	DCAM1394_7_5_FPS			0x7

#define	DCAM1394_FRAME_RATE_2			0x8
#define	DCAM1394_15_FPS				0x8

#define	DCAM1394_FRAME_RATE_3			0x9
#define	DCAM1394_30_FPS				0x9

#define	DCAM1394_FRAME_RATE_4			0xA
#define	DCAM1394_60_FPS				0xA

/* for feature control mode subparam */

#define	DCAM1394_CTRL_AUTO			0x1
#define	DCAM1394_CTRL_MANUAL			0x0

/* for power control subparam */

#define	DCAM1394_POWER_OFF			0x0
#define	DCAM1394_POWER_ON			0x1

/* ioctl() commands */

#define	DCAM1394_IOC				('d' << 8)

#define	DCAM1394_CMD_REG_READ			(DCAM1394_IOC | 0)
#define	DCAM1394_CMD_REG_WRITE			(DCAM1394_IOC | 1)

#define	DCAM1394_CMD_CAM_RESET			(DCAM1394_IOC | 2)
#define	DCAM1394_CMD_PARAM_GET			(DCAM1394_IOC | 3)
#define	DCAM1394_CMD_PARAM_SET			(DCAM1394_IOC | 4)
#define	DCAM1394_CMD_FRAME_RCV_START		(DCAM1394_IOC | 5)
#define	DCAM1394_CMD_FRAME_RCV_STOP		(DCAM1394_IOC | 6)
#define	DCAM1394_CMD_RING_BUFF_FLUSH		(DCAM1394_IOC | 7)
#define	DCAM1394_CMD_FRAME_SEQ_NUM_COUNT_RESET	(DCAM1394_IOC | 8)

#define	DCAM1394_RING_BUFF_OFFS		0x1

/* for DCAM1394_PARAM_STATUS */

#define	DCAM1394_STATUS_FRAME_RCV_DONE			0x1
#define	DCAM1394_STATUS_RING_BUFF_LOST_FRAME		0x2
#define	DCAM1394_STATUS_PARAM_CHANGE			0x4
#define	DCAM1394_STATUS_FRAME_SEQ_NUM_COUNT_OVERFLOW	0x8
#define	DCAM1394_STATUS_CAM_UNPLUG			0x10

typedef struct dcam1394_param_list_entry_s {
	int 		flag;
	int 		err;
	unsigned int 	val;

} dcam1394_param_list_entry_t;

typedef dcam1394_param_list_entry_t
	dcam1394_param_list_t[DCAM1394_NUM_PARAM][DCAM1394_NUM_SUBPARAM];

typedef dcam1394_param_list_entry_t
	(*dcam1394_param_list_p_t)[DCAM1394_NUM_PARAM][DCAM1394_NUM_SUBPARAM];

typedef struct dcam1394_frame_s {
	unsigned int	 vid_mode;
	unsigned int	 seq_num;
	hrtime_t	 timestamp;
	unsigned char	*buff;
} dcam1394_frame_t;

typedef struct dcam1394_reg_io_s {
	unsigned int	offs;
	unsigned int 	val;

} dcam1394_reg_io_t;

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_DCAM_DCAM1394_IO_H */
