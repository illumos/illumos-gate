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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_USB_USBVC_VAR_H
#define	_SYS_USB_USBVC_VAR_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/list.h>
#include <sys/sysmacros.h>
#include <sys/usb/usba/usbai_private.h>
#include <sys/videodev2.h>
#include <sys/usb/clients/video/usbvc/usbvc.h>

typedef struct usbvc_state usbvc_state_t;

/*
 * Power Management support
 */
typedef struct usbvc_power  {

	void		*usbvc_state;	/* points back to usbvc_state */
	uint8_t		usbvc_pwr_states; /* bit mask of device pwr states */
	int		usbvc_pm_busy;

	/* Wakeup and power transistion capabilites of an interface */
	uint8_t		usbvc_pm_capabilities;

	/* flag to indicate if driver is about to raise power level */
	boolean_t	usbvc_raise_power;

	uint8_t		usbvc_current_power;
	uint8_t		usbvc_wakeup_enabled;
} usbvc_power_t;

/* Raw data buf from the USB cam */
typedef struct usbvc_buf
{
	uchar_t *data;
	uint_t len;	/* the length of the allocated memory of data */
	uint_t filled;	/* number of bytes filled */
	uint_t len_read; /* bytes read */
	uchar_t status; /* empty, filling done, read done */

	/* cookie used for memory mapping */
	ddi_umem_cookie_t	umem_cookie;
	struct			v4l2_buffer v4l2_buf;
	list_node_t		buf_node;	/* list */
} usbvc_buf_t;

/* Group data buf related lists and other elements */
typedef struct usbvc_buf_grp
{
    list_t		uv_buf_free;
	list_t		uv_buf_done;
	usbvc_buf_t	*buf_filling;
	uint_t		buf_cnt;
	usbvc_buf_t	*buf_head;
} usbvc_buf_grp_t;

/*
 * UVC Spec: one format descriptor may be followed by sererval frame
 * descriptors, one still image descriptor and one color matching descriptor.
 * It is called a format group. There might be several format groups follow
 * one input/output header.
 */
typedef struct usbvc_format_group {
	usbvc_format_descr_t	*format;
	usbvc_frames_t		*frames;
	uint8_t			frame_cnt;

	/* bytes per pix, used to calculate bytesperline */
	uint8_t			v4l2_bpp;

	uint8_t			v4l2_color;
	uint32_t		v4l2_pixelformat;	/* fcc, pixelformat */
	usbvc_still_image_frame_t	*still;
	usbvc_color_matching_descr_t	*color;
	usbvc_frames_t			*cur_frame;
} usbvc_format_group_t;

/* A stream interface may have several format groups */
typedef struct usbvc_stream_if {

	/* The actual format groups we parsed for the stream interface */
	uint8_t			fmtgrp_cnt;

	usb_if_data_t		*if_descr;
	usbvc_input_header_t	*input_header;
	usbvc_output_header_t	*output_header;
	usbvc_format_group_t	*format_group;
	usbvc_format_group_t	*cur_format_group;
	usbvc_vs_probe_commit_t	ctrl_pc;
	usb_ep_descr_t		*curr_ep;	/* current isoc ep descr */
	usb_pipe_handle_t	datain_ph;	/* current isoc pipe handle */
	uint_t			curr_alt;	/* current alternate  */

	/* The max payload that the isoc data EPs can support */
	uint32_t	max_isoc_payload;

	uchar_t		start_polling;	/* indicate if isoc polling started */

	/*
	 * To flag if VIDIOC_STREAMON is executed, only used by STREAM mode
	 * for suspend/resume. If it's non-zero, we'll have to resume the
	 * device's isoc polling operation after resume.
	 */
	uint8_t		stream_on;

	uchar_t		fid;		/* the MJPEG FID bit */
	usbvc_buf_grp_t	buf_read;	/* buf used for read I/O */
	uint8_t			buf_read_num; /* desired buf num for read I/O */
	usbvc_buf_grp_t	buf_map;	/* buf used for mmap I/O */
	list_node_t	stream_if_node;
} usbvc_stream_if_t;

/* video interface collection */
typedef struct usbvc_vic {

	/* bFirstInterface, the video control infterface num of this VIC */
	uint8_t	vctrl_if_num;

	/*
	 * bInterfaceCount -1, the total number of stream interfaces
	 * belong to this VIC
	 */
	uint8_t	vstrm_if_cnt;
} usbvc_vic_t;

/* Macros */
#define	USBVC_OPEN		0x00000001

/* For serialization. */
#define	USBVC_SER_NOSIG	B_FALSE
#define	USBVC_SER_SIG		B_TRUE

/*
 * Masks for debug printing
 */
#define	PRINT_MASK_ATTA		0x00000001
#define	PRINT_MASK_OPEN 	0x00000002
#define	PRINT_MASK_CLOSE	0x00000004
#define	PRINT_MASK_READ		0x00000008
#define	PRINT_MASK_IOCTL	0x00000010
#define	PRINT_MASK_PM	0x00000020
#define	PRINT_MASK_CB	0x00000040
#define	PRINT_MASK_HOTPLUG	0x00000080
#define	PRINT_MASK_DEVCTRL	0x00000100
#define	PRINT_MASK_DEVMAP	0x00000200
#define	PRINT_MASK_ALL		0xFFFFFFFF

#define	USBVC_MAX_PKTS 40

#define	USBVC_DEFAULT_READ_BUF_NUM 3
#define	USBVC_MAX_READ_BUF_NUM 40
#define	USBVC_MAX_MAP_BUF_NUM 40

/* According to UVC specs, the frame interval is in 100ns unit */
#define	USBVC_FRAME_INTERVAL_DENOMINATOR	10000000

/* Only D3...D0 are writable, Table 4-6, UVC Spec */
#define	USBVC_POWER_MODE_MASK	0xf0;

enum usbvc_buf_status {
	USBVC_BUF_INIT		= 0,  /* Allocated, to be queued */
	    USBVC_BUF_MAPPED	= 1,  /* For map I/O only. Memory is mapped. */
	    USBVC_BUF_EMPTY		= 2, /* not initialized, to be filled */

	/*
	 * buf is filled with a full frame without any errors,
	 * it will be moved to full list.
	 */
	    USBVC_BUF_DONE		= 4,

	/*
	 * buf is filled to full but no EOF bit is found at the end
	 * of video data
	 */
	    USBVC_BUF_ERR		= 8
};

/*
 * This structure is used to map v4l2 controls to uvc controls. The structure
 * array is addressed by (V4L2_CID_BASE - V4L2_CID_*)
 */
typedef struct usbvc_v4l2_ctrl_map {
	char	name[32];
	uint8_t	selector; /* Control Selector */
	uint8_t	len;	/* wLength, defined in uvc spec chp 4 for each ctrl */

	/* The xth bit in bmControls bitmap of processing unit descriptor */
	uint8_t	bit;

	enum	v4l2_ctrl_type type;
} usbvc_v4l2_ctrl_map_t;

typedef struct usbvc_v4l2_ctrl {
	uint8_t			entity_id;
	usbvc_v4l2_ctrl_map_t	*ctrl_map;
} usbvc_v4l2_ctrl_t;


/*
 * State structure
 */
struct usbvc_state {
	dev_info_t		*usbvc_dip;	/* per-device info handle */
	usb_client_dev_data_t	*usbvc_reg;	/* registration data */
	int			usbvc_dev_state; /* USB device states. */
	int			usbvc_drv_state; /* driver states. */
	kmutex_t		usbvc_mutex;
	kcondvar_t		usbvc_serial_cv;
	boolean_t		usbvc_serial_inuse;
	boolean_t		usbvc_locks_initialized;

	usbvc_power_t		*usbvc_pm;

	usb_log_handle_t	usbvc_log_handle;	/* log handle */
	usb_pipe_handle_t	usbvc_default_ph; /* default pipe */

	/* Video ctrl interface header descriptor */
	usbvc_vc_header_t	*usbvc_vc_header;
	list_t			usbvc_term_list;
	list_t			usbvc_unit_list;

	list_t			usbvc_stream_list;
	usbvc_stream_if_t	*usbvc_curr_strm;
	kcondvar_t		usbvc_read_cv;	/* wait for read buf done */
	kcondvar_t		usbvc_mapio_cv;	/* wait for mmap I/O buf done */

	/* current I/O type: read or mmap. */
	uchar_t			usbvc_io_type;
};


/*
 * Used in ioctl entry to copy an argument from kernel space (arg_name)
 * to USER space (arg)
 */
#define	USBVC_COPYOUT(arg_name) \
if (ddi_copyout(&arg_name, (caddr_t)arg, sizeof (arg_name), mode)) { \
    rv = EFAULT; \
    break;	\
}

/*
 * Used in ioctl entry to copy an argument from USER space (arg) to
 * KERNEL space (arg_name)
 */
#define	USBVC_COPYIN(arg_name) \
if (ddi_copyin((caddr_t)arg, &arg_name, sizeof (arg_name), mode)) { \
	rv = EFAULT; \
	break;	\
}

/* Turn a little endian byte array to a uint32_t */
#define	LE_TO_UINT32(src, off, des)	{ \
				uint32_t tmp; \
				des = src[off + 3]; \
				des = des << 24; \
				tmp = src[off + 2]; \
				des |= tmp << 16; \
				tmp = src[off + 1]; \
				des |= tmp << 8; \
				des |= src[off]; \
				}

/* Turn a uint32_t to a little endian byte array */
#define	UINT32_TO_LE(src, off, des)	{ \
				des[off + 0] = 0xff & src; \
				des[off + 1] = 0xff & (src >> 8); \
				des[off + 2] = 0xff & (src >> 16); \
				des[off + 3] = 0xff & (src >> 24); \
				}

/* Turn a little endian byte array to a uint16_t */
#define	LE_TO_UINT16(src, off, des)	 \
				des = src[off + 1]; \
				des = des << 8; \
				des |= src[off];

/* Turn a uint16_t to alittle endian byte array */
#define	UINT16_TO_LE(src, off, des)	{ \
				des[off + 0] = 0xff & src; \
				des[off + 1] = 0xff & (src >> 8); \
				}

#define	NELEM(a)	(sizeof (a) / sizeof (*(a)))

/* Minimum length of class specific descriptors */
#define	USBVC_C_HEAD_LEN_MIN	12	/* ctrl header */
#define	USBVC_I_TERM_LEN_MIN	8	/* input term */
#define	USBVC_O_TERM_LEN_MIN	9	/* output term */
#define	USBVC_P_UNIT_LEN_MIN	8	/* processing unit */
#define	USBVC_S_UNIT_LEN_MIN	5	/* selector unit */
#define	USBVC_E_UNIT_LEN_MIN	22	/* extension unit */
#define	USBVC_FRAME_LEN_MIN	26	/* Frame descriptor */

/* Length of the Frame descriptor which has continuous frame intervals */
#define	USBVC_FRAME_LEN_CON	38


/*
 * According to usb2.0 spec (table 9-13), for all ep, bits 10..0 specify the
 * max pkt size; for high speed ep, bits 12..11 specify the number of
 * additional transaction opportunities per microframe.
 */
#define	HS_PKT_SIZE(pktsize) (pktsize & 0x07ff) * (1 + ((pktsize >> 11) & 3))

/*
 * warlock directives
 * _NOTE is an advice for locklint.  Locklint checks lock use for deadlocks.
 */
_NOTE(MUTEX_PROTECTS_DATA(usbvc_state_t::usbvc_mutex, usbvc_state_t))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usbvc_state_t::{
	usbvc_dip
	usbvc_pm
	usbvc_log_handle
	usbvc_reg
	usbvc_default_ph
	usbvc_vc_header
	usbvc_term_list
	usbvc_unit_list
	usbvc_stream_list
}))

_NOTE(SCHEME_PROTECTS_DATA("stable data", usb_pipe_policy))
_NOTE(SCHEME_PROTECTS_DATA("USBA", usbvc_stream_if::datain_ph))
_NOTE(SCHEME_PROTECTS_DATA("USBA", usbvc_stream_if::curr_alt))
_NOTE(SCHEME_PROTECTS_DATA("USBA", usbvc_stream_if::curr_ep))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", usbvc_buf::umem_cookie))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", usbvc_buf::data))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", usbvc_v4l2_ctrl))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", usbvc_v4l2_ctrl_map))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", mblk_t))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", buf))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", usb_isoc_req))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", v4l2_queryctrl))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", v4l2_format))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", v4l2_control))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", v4l2_streamparm))

int	usbvc_open_isoc_pipe(usbvc_state_t *, usbvc_stream_if_t *);
int	usbvc_start_isoc_polling(usbvc_state_t *, usbvc_stream_if_t *, uchar_t);
int	usbvc_vc_set_ctrl(usbvc_state_t *, uint8_t,  uint8_t,
		uint16_t, uint16_t, mblk_t *);
int	usbvc_vc_get_ctrl(usbvc_state_t *, uint8_t,  uint8_t,
		uint16_t, uint16_t, mblk_t *);
int	usbvc_vs_set_probe_commit(usbvc_state_t *, usbvc_stream_if_t *,
	usbvc_vs_probe_commit_t *, uchar_t);
void	usbvc_free_map_bufs(usbvc_state_t *, usbvc_stream_if_t *);
int	usbvc_alloc_map_bufs(usbvc_state_t *, usbvc_stream_if_t *, int, int);
int	usbvc_vs_get_probe(usbvc_state_t *, usbvc_stream_if_t *,
		usbvc_vs_probe_commit_t *, uchar_t);

/* Functions specific for V4L2 API */
uint8_t		usbvc_v4l2_colorspace(uint8_t);
uint32_t	usbvc_v4l2_guid2fcc(uint8_t *);
int		usbvc_v4l2_ioctl(usbvc_state_t *, int, intptr_t, int);


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_USBVC_VAR_H */
