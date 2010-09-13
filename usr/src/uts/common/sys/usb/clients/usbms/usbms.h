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

#ifndef _SYS_USB_USBMS_H
#define	_SYS_USB_USBMS_H



#ifdef __cplusplus
extern "C" {
#endif


struct usbmouseinfo {
	int	mi_x;		/* current X coordinate */
	int	mi_y;		/* current Y coordinate */
	int	mi_z;		/* current wheel */
	int	mi_buttons;	/* current button status */
	struct timeval32 mi_time; /* timestamp */
};

struct usbmousebuf {
	ushort_t mb_size;	/* size (in usbmouseinfo units) of buf */
	ushort_t mb_off;	/* current offset in buffer */
	struct usbmouseinfo *mb_info; /* current usbmouseinfo */
};

typedef struct usbms_input {
	uint_t		xpos;	/* X position in the sample info */
	uint_t		xlen;	/* length of X coordinate */
	uint_t		xattr;	/* attribute of X coordinate */
	uint_t		ypos;	/* Y position in the sample info */
	uint_t		ylen;	/* length of Y coordinate */
	uint_t		yattr;	/* attribute of Y coordinate */
	uint_t		zpos;	/* wheel data position in the sample info */
	uint_t		zlen;	/* length of wheel data */
	uint_t		zattr;	/* attribute of wheel data */
	uint_t		bpos;	/* button data position in the sample info */
	uint_t		tlen;	/* length of the sample info */
} usbms_idf;

typedef struct usbms_state {
	queue_t			*usbms_rq_ptr;   /* pointer to read queue */
	queue_t			*usbms_wq_ptr;   /* pointer to write queue */

	/* Flag for mouse open/qwait status */

	int			usbms_flags;

	/*
	 * Is an ioctl fails because an mblk wasn't
	 * available, the mlbk is saved here.
	 */

	mblk_t			*usbms_iocpending;

	/* mouse software structure from msreg.h */

	struct ms_softc		usbms_softc;

	/* Previous button byte */

	char			usbms_oldbutt;


	/* Report descriptor handle received from hid */

	hidparser_handle_t	usbms_report_descr_handle;

	/*
	 * Max pixel delta of jitter controlled. As this number increases
	 * the jumpiness of the msd increases, i.e., the coarser the motion
	 * for mediumm speeds.
	 * jitter_thresh is the maximum number of jitters suppressed. Thus,
	 * hz/jitter_thresh is the maximum interval of jitters suppressed. As
	 * jitter_thresh increases, a wider range of jitter is suppressed.
	 * However, the more inertia the mouse seems to have, i.e., the slower
	 * the mouse is to react.
	 */

	int			usbms_jitter_thresh;

	/* Timeout used when mstimeout in effect */

	clock_t			usbms_jittertimeout;

	/*
	 * Measure how many (speed_count) msd deltas exceed threshold
	 * (speedlimit). If speedlaw then throw away deltas over speedlimit.
	 * This is to keep really bad mice that jump around from getting
	 * too far.
	 */

	/* Threshold above which deltas are thrown out */

	int		usbms_speedlimit;

	int		usbms_speedlaw;	/* Whether to throw away deltas */

	/*  No. of deltas exceeding spd. limit */

	int		usbms_speed_count;

	int		usbms_iocid;	/* ID of "ioctl" being waited for */
	short		usbms_state;	/* button state at last sample */
	short		usbms_jitter;	/* state counter for input routine */
	timeout_id_t	usbms_timeout_id;	/* id returned by timeout() */
	bufcall_id_t	usbms_reioctl_id;	/* id returned by bufcall() */
	bufcall_id_t	usbms_resched_id;	/* id returned by bufcall() */
	int32_t		usbms_num_buttons;	/* No. of buttons */
	int32_t		usbms_num_wheels;	/* No. of wheels */
	uchar_t		usbms_protoerr;		/* Error set proto */
	ushort_t	usbms_wheel_state_bf;	/* Wheel state bit field */
	ushort_t	usbms_wheel_orient_bf;	/* Wheel orientation	*/
	int32_t		usbms_rptid;		/* Report id of mouse app */
	int32_t		usbms_logical_Xmax;	/* X logical maximum */
	int32_t		usbms_logical_Ymax;	/* Y logical maximum */

	/* Screen resolution for absolute mouse */

	Ms_screen_resolution	usbms_resolution;

	/* report the abs mouse event to upper level once */

	boolean_t	usbms_rpt_abs;

	usbms_idf	usbms_idf;
	struct		usbmousebuf *usbms_buf;
} usbms_state_t;


#define	USBMS_OPEN    0x00000001 /* mouse is open for business */
#define	USBMS_QWAIT   0x00000002 /* mouse is waiting for a response */

/* Macro to find absolute value */

#define	USB_ABS(x)		((x) < 0 ? -(x) : (x))

/*
 * Macro to restrict the value of x to lie between 127 & -127 :
 * if x > 127 return 127
 * else if x < -127 return -127
 * else return x
 */

#define	USB_BYTECLIP(x)	(char)((x) > 127 ? 127 : ((x) < -127 ? -127 : (x)))

/*
 * Default and MAX (supported) number of buttons
 */

#define	USB_MS_DEFAULT_BUTTON_NO	3
#define	USB_MS_MAX_BUTTON_NO		8


/*
 * Input routine states. See usbms_input().
 */
#define	USBMS_WAIT_BUTN		0	/* Button byte */
#define	USBMS_WAIT_X		1	/* Delta X byte */
#define	USBMS_WAIT_Y    	2	/* Delta Y byte */
#define	USBMS_WAIT_WHEEL	3	/* Wheel Byte	*/


/*
 * default resolution, 1024x768.
 */
#define	USBMS_DEFAULT_RES_HEIGHT	768
#define	USBMS_DEFAULT_RES_WIDTH		1024
/*
 * USB buttons:
 *		How the device sends it:
 *		0x01 - Left   button position
 *		0x02 - Right  button position
 *		0x04 - Middle button position
 */


#define	USBMS_BUT(i)	1 << (i - 1)

/*
 * These defines are for converting USB button information to the
 * format that Type 5 mouse sends upstream, which is what the xserver
 * expects.
 */

#define	USB_NO_BUT_PRESSED	0xFF
#define	USB_LEFT_BUT_PRESSED	0xFB
#define	USB_RIGHT_BUT_PRESSED	0xFE
#define	USB_MIDDLE_BUT_PRESSED	0xFD

#define	USB_BUT_PRESSED(i)	~(1 << (i - 1))

/*
 * State structure used for transparent ioctls
 */

typedef struct usbms_iocstate {
		int ioc_state;
		caddr_t u_addr;
} usbms_iocstate_t;

/*
 * Transparent ioctl states
 */

#define	USBMS_GETSTRUCT 1
#define	USBMS_GETRESULT	2

/*
 * Private data are initialized to these values
 */
#define	USBMS_JITTER_THRESH	0	/* Max no. of jitters suppressed */
#define	USBMS_SPEEDLIMIT	48	/* Threshold for msd deltas */
#define	USBMS_SPEEDLAW		0	/* Whether to throw away deltas */
#define	USBMS_SPEED_COUNT	0	/* No. of deltas exceeding spd. limit */
#define	USBMS_BUF_BYTES		4096	/* Mouse buffer size */
#define	USBMS_USAGE_PAGE_BUTTON	0x9	/* Usage Page data value : Button */

#define	JITTERRATE		12	/* No of jitters before timeout */

/* Jitter Timeout while initialization */
#define	JITTER_TIMEOUT		(hz/JITTERRATE)

/*
 * Masks for debug printing
 */
#define	PRINT_MASK_ATTA		0x00000001
#define	PRINT_MASK_OPEN 	0x00000002
#define	PRINT_MASK_CLOSE	0x00000004
#define	PRINT_MASK_SERV		0x00000008
#define	PRINT_MASK_IOCTL	0x00000010
#define	PRINT_MASK_INPUT_INCR	0x00000020
#define	PRINT_MASK_ALL		0xFFFFFFFF

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_USBMS_H */
