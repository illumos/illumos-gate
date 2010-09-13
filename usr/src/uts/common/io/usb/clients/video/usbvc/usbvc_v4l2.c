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


/*
 * USB video class driver: V4L2 interface implementation.
 */

#include <sys/usb/usba.h>
#include <sys/fcntl.h>
#include <sys/cmn_err.h>

#include <sys/usb/clients/video/usbvc/usbvc_var.h>
#include <sys/usb/clients/video/usbvc/usbvc.h>
#include <sys/videodev2.h>

static int usbvc_v4l2_set_format(usbvc_state_t *, struct v4l2_format *);
static int usbvc_v4l2_get_format(usbvc_state_t *, struct v4l2_format *);
static void usbvc_v4l2_query_buf(usbvc_state_t *, usbvc_buf_t *,
				struct v4l2_buffer *);
static int usbvc_v4l2_enqueue_buf(usbvc_state_t *, usbvc_buf_t *,
				struct v4l2_buffer *);
static int usbvc_v4l2_dequeue_buffer(usbvc_state_t *,
				struct v4l2_buffer *, int);
static int usbvc_v4l2_query_ctrl(usbvc_state_t *, struct v4l2_queryctrl *);
static int usbvc_v4l2_get_ctrl(usbvc_state_t *, struct v4l2_control *);
static int usbvc_v4l2_set_ctrl(usbvc_state_t *, struct v4l2_control *);
static int usbvc_v4l2_set_parm(usbvc_state_t *, struct v4l2_streamparm *);
static int usbvc_v4l2_get_parm(usbvc_state_t *, struct v4l2_streamparm *);
/* Video controls that supported by usbvc driver */
static usbvc_v4l2_ctrl_map_t usbvc_v4l2_ctrls[] = {
	{
		"Brightness",
		PU_BRIGHTNESS_CONTROL,
		2,
		0,
		V4L2_CTRL_TYPE_INTEGER
	},
	{
		"Contrast",
		PU_CONTRAST_CONTROL,
		2,
		1,
		V4L2_CTRL_TYPE_INTEGER
	},
	{
		"Saturation",
		PU_SATURATION_CONTROL,
		2,
		3,
		V4L2_CTRL_TYPE_INTEGER
	},
	{
		"Hue",
		PU_HUE_CONTROL,
		2,
		2,
		V4L2_CTRL_TYPE_INTEGER
	},
	{
		"Gamma",
		PU_GAMMA_CONTROL,
		2,
		5,
		V4L2_CTRL_TYPE_INTEGER
	}
};


/*
 * V4L2 colorspaces.
 */
static const uint8_t color_primaries[] = {
		0,
		V4L2_COLORSPACE_SRGB,
		V4L2_COLORSPACE_470_SYSTEM_M,
		V4L2_COLORSPACE_470_SYSTEM_BG,
		V4L2_COLORSPACE_SMPTE170M,
		V4L2_COLORSPACE_SMPTE240M,
};

/* V4L2 ioctls */
int
usbvc_v4l2_ioctl(usbvc_state_t *usbvcp, int cmd, intptr_t arg, int mode)
{
	int	rv = 0;

	switch (cmd) {
	case VIDIOC_QUERYCAP:	/* Query capabilities */
	{
		struct v4l2_capability caps;

		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: VIDIOC_QUERYCAP");
		bzero(&caps, sizeof (caps));
		(void) strncpy((char *)&caps.driver, "usbvc",
		    sizeof (caps.driver));
		if (usbvcp->usbvc_reg->dev_product) {
			(void) strncpy((char *)&caps.card,
			    usbvcp->usbvc_reg->dev_product, sizeof (caps.card));
		} else {
			(void) strncpy((char *)&caps.card, "Generic USB video"
			    "class device", sizeof (caps.card));
		}
		(void) strncpy((char *)&caps.bus_info, "usb",
		    sizeof (caps.bus_info));
		caps.version = 1;
		caps.capabilities = V4L2_CAP_VIDEO_CAPTURE
		    | V4L2_CAP_STREAMING | V4L2_CAP_READWRITE;
		USBVC_COPYOUT(caps);

		break;
	}
	case VIDIOC_ENUM_FMT:
	{
		struct v4l2_fmtdesc	fmtdesc;
		usbvc_format_group_t	*fmtgrp;
		usbvc_stream_if_t	*strm_if;

		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: VIDIOC_ENUM_FMT");
		USBVC_COPYIN(fmtdesc);
		mutex_enter(&usbvcp->usbvc_mutex);
		strm_if = usbvcp->usbvc_curr_strm;
		if (fmtdesc.type != V4L2_BUF_TYPE_VIDEO_CAPTURE ||
		    fmtdesc.index >= strm_if->fmtgrp_cnt) {
			rv = EINVAL;
			mutex_exit(&usbvcp->usbvc_mutex);

			break;
		}
		fmtgrp = &strm_if->format_group[fmtdesc.index];
		fmtdesc.pixelformat = fmtgrp->v4l2_pixelformat;
		USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: VIDIOC_ENUM_FMT, idx=%d, grpcnt=%d",
		    fmtdesc.index, strm_if->fmtgrp_cnt);

		switch (fmtgrp->format->bDescriptorSubType) {
		case VS_FORMAT_MJPEG:
			fmtdesc.flags = V4L2_FMT_FLAG_COMPRESSED;
			(void) strncpy(fmtdesc.description, "MJPEG",
			    sizeof (fmtdesc.description));

			break;
		case VS_FORMAT_UNCOMPRESSED:
			fmtdesc.flags = 0;
			if (fmtdesc.pixelformat == V4L2_PIX_FMT_YUYV) {
				(void) strncpy(fmtdesc.description, "YUYV",
				    sizeof (fmtdesc.description));
			} else if (fmtdesc.pixelformat == V4L2_PIX_FMT_NV12) {
				(void) strncpy(fmtdesc.description, "NV12",
				    sizeof (fmtdesc.description));
			} else {
				(void) strncpy(fmtdesc.description,
				    "Unknown format",
				    sizeof (fmtdesc.description));
			}

			break;
		default:
			fmtdesc.flags = 0;
			(void) strncpy(fmtdesc.description, "Unknown format",
			    sizeof (fmtdesc.description));
		}

		mutex_exit(&usbvcp->usbvc_mutex);
		USBVC_COPYOUT(fmtdesc);

		break;
	}
	case VIDIOC_S_FMT:
	{
		struct v4l2_format	fmt;
		usbvc_stream_if_t	*strm_if;

		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: VIDIOC_S_FMT");
		mutex_enter(&usbvcp->usbvc_mutex);
		strm_if = usbvcp->usbvc_curr_strm;

		/* If data I/O is in progress */
		if (strm_if->start_polling == 1) {
			rv = EBUSY;
			mutex_exit(&usbvcp->usbvc_mutex);

			break;
		}
		mutex_exit(&usbvcp->usbvc_mutex);

		USBVC_COPYIN(fmt);
		if (usbvc_v4l2_set_format(usbvcp, &fmt) != USB_SUCCESS) {
			rv = EFAULT;
			USB_DPRINTF_L2(PRINT_MASK_IOCTL,
			    usbvcp->usbvc_log_handle,
			    "V4L2 ioctl VIDIOC_S_FMT fail");
		}
		USBVC_COPYOUT(fmt);

		break;
	}
	case VIDIOC_G_FMT:
	{
		struct v4l2_format	fmt;

		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: VIDIOC_G_FMT");
		USBVC_COPYIN(fmt);

		if ((rv = usbvc_v4l2_get_format(usbvcp, &fmt)) != 0) {

			break;
		}

		USBVC_COPYOUT(fmt);

		break;
	}
	case VIDIOC_REQBUFS: /* for memory mapping IO method */
	{
		struct v4l2_requestbuffers	reqbuf;
		uint_t				bufsize;
		usbvc_stream_if_t		*strm_if;

		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: VIDIOC_REQBUFS");
		USBVC_COPYIN(reqbuf);
		if (reqbuf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE ||
		    reqbuf.memory != V4L2_MEMORY_MMAP) {
			rv = EINVAL;

			break;
		}
		mutex_enter(&usbvcp->usbvc_mutex);
		strm_if = usbvcp->usbvc_curr_strm;
		if (!strm_if) {
			mutex_exit(&usbvcp->usbvc_mutex);
			rv = EINVAL;

			break;
		}
		if (reqbuf.count > USBVC_MAX_MAP_BUF_NUM) {
			mutex_exit(&usbvcp->usbvc_mutex);
			USB_DPRINTF_L2(PRINT_MASK_IOCTL,
			    usbvcp->usbvc_log_handle,
			    "V4L2 ioctl: req too many buffers, fail");
			rv = EINVAL;

			break;
		}

		/* If some bufs were already allocated */
		if (strm_if->buf_map.buf_cnt) {
			/*
			 * According to v4l2 spec, application can change the
			 * buffer number and also free all buffers if set
			 * count to 0
			 */
			if (reqbuf.count == 0) {
				if (strm_if->start_polling == 1) {
					mutex_exit(&usbvcp->usbvc_mutex);
					usb_pipe_stop_isoc_polling(
					    strm_if->datain_ph,
					    USB_FLAGS_SLEEP);
					mutex_enter(&usbvcp->usbvc_mutex);
					strm_if->start_polling = 0;
				}
				usbvc_free_map_bufs(usbvcp, strm_if);
				mutex_exit(&usbvcp->usbvc_mutex);

				break;
			}
			if (reqbuf.count == strm_if->buf_map.buf_cnt) {
				mutex_exit(&usbvcp->usbvc_mutex);
				USB_DPRINTF_L2(PRINT_MASK_IOCTL,
				    usbvcp->usbvc_log_handle,
				    "v4l2 ioctls: req the same buffers"
				    " as we already have, just return success");

				break;
			} else {
				/*
				 * req different number of bufs, according to
				 * v4l2 spec, this is not allowed when there
				 * are some bufs still mapped.
				 */
				mutex_exit(&usbvcp->usbvc_mutex);
				USB_DPRINTF_L2(PRINT_MASK_IOCTL,
				    usbvcp->usbvc_log_handle,
				    "v4l2 ioctls: req different number bufs"
				    "than the exist ones, fail");
				rv = EINVAL;

				break;
			}
		}

		if (reqbuf.count == 0) {
			mutex_exit(&usbvcp->usbvc_mutex);
			rv = EINVAL;

			break;
		}
		LE_TO_UINT32(strm_if->ctrl_pc.dwMaxVideoFrameSize, 0, bufsize);
		if ((reqbuf.count =
		    (uint32_t)usbvc_alloc_map_bufs(usbvcp, strm_if,
		    reqbuf.count, bufsize)) == 0) {
			mutex_exit(&usbvcp->usbvc_mutex);
			USB_DPRINTF_L2(PRINT_MASK_IOCTL,
			    usbvcp->usbvc_log_handle,
			    "V4L2 ioctl: VIDIOC_REQBUFS: alloc fail");
			rv = EINVAL;

			break;
		}
		mutex_exit(&usbvcp->usbvc_mutex);

		/*
		 * return buf number that acctually allocated to application
		 */
		USBVC_COPYOUT(reqbuf);

		break;
	}
	case VIDIOC_QUERYBUF: /* for memory mapping IO method */
	{
		struct v4l2_buffer	buf;
		usbvc_buf_grp_t		*usbvc_bufg;

		USBVC_COPYIN(buf);
		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: VIDIOC_QUERYBUF: idx=%d", buf.index);
		mutex_enter(&usbvcp->usbvc_mutex);
		usbvc_bufg = &usbvcp->usbvc_curr_strm->buf_map;
		if ((buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE) ||
		    (buf.index >= usbvc_bufg->buf_cnt)) {
			mutex_exit(&usbvcp->usbvc_mutex);
			rv = EINVAL;

			break;
		}

		USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: VIDIOC_QUERYBUF: len=%d",
		    usbvc_bufg->buf_head[buf.index].v4l2_buf.length);

		usbvc_v4l2_query_buf(usbvcp, &usbvc_bufg->buf_head[buf.index],
		    &buf);
		mutex_exit(&usbvcp->usbvc_mutex);
		USBVC_COPYOUT(buf);
		USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: VIDIOC_QUERYBUF,(index=%d)len=%d",
		    buf.index, buf.length);

		break;
	}
	case VIDIOC_QBUF:
	{
		struct v4l2_buffer	buf;
		usbvc_buf_grp_t		*usbvc_bufg;

		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: VIDIOC_QBUF");
		USBVC_COPYIN(buf);
		mutex_enter(&usbvcp->usbvc_mutex);
		usbvc_bufg = &usbvcp->usbvc_curr_strm->buf_map;

		if ((buf.type != V4L2_BUF_TYPE_VIDEO_CAPTURE) ||
		    (buf.index >= usbvc_bufg->buf_cnt) ||
		    (buf.memory != V4L2_MEMORY_MMAP)) {
			mutex_exit(&usbvcp->usbvc_mutex);
			USB_DPRINTF_L2(PRINT_MASK_IOCTL,
			    usbvcp->usbvc_log_handle,  "V4L2 ioctl: "
			    "VIDIOC_QBUF error:index=%d,type=%d,memory=%d",
			    buf.index, buf.type, buf.memory);
			rv = EINVAL;

			break;
		}
		rv = usbvc_v4l2_enqueue_buf(usbvcp,
		    &usbvc_bufg->buf_head[buf.index], &buf);
		if (rv < 0) {
			mutex_exit(&usbvcp->usbvc_mutex);

			break;
		}
		mutex_exit(&usbvcp->usbvc_mutex);
		USBVC_COPYOUT(buf);

		break;
	}

	case VIDIOC_DQBUF:
	{
		struct v4l2_buffer	buf;

		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: VIDIOC_DQBUF");
		USBVC_COPYIN(buf);
		mutex_enter(&usbvcp->usbvc_mutex);
		if ((rv = usbvc_v4l2_dequeue_buffer(usbvcp, &buf, mode)) != 0) {
			mutex_exit(&usbvcp->usbvc_mutex);
			USB_DPRINTF_L2(PRINT_MASK_IOCTL,
			    usbvcp->usbvc_log_handle, "V4L2 ioctl: "
			    "VIDIOC_DQBUF: fail, rv=%d", rv);

			break;
		}
		mutex_exit(&usbvcp->usbvc_mutex);
		USBVC_COPYOUT(buf);

		break;
	}

	case VIDIOC_STREAMON:
	{
		int			type; /* v4l2_buf_type */
		usbvc_stream_if_t	*strm_if;

		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: VIDIOC_STREAMON");
		USBVC_COPYIN(type);
		mutex_enter(&usbvcp->usbvc_mutex);
		strm_if = usbvcp->usbvc_curr_strm;
		if (!strm_if) {
			mutex_exit(&usbvcp->usbvc_mutex);
			rv = EINVAL;

			break;
		}
		if (type != V4L2_BUF_TYPE_VIDEO_CAPTURE) {
			mutex_exit(&usbvcp->usbvc_mutex);
			USB_DPRINTF_L2(PRINT_MASK_IOCTL,
			    usbvcp->usbvc_log_handle, "V4L2 ioctl: "
			    "VIDIOC_STREAMON: fail. Only capture type is"
			    " supported by now.");
			rv = EINVAL;

			break;
		}
		/* if the first read, open isoc pipe */
		if (!strm_if->datain_ph) {
			if (usbvc_open_isoc_pipe(usbvcp, strm_if) !=
			    USB_SUCCESS) {
				mutex_exit(&usbvcp->usbvc_mutex);
				USB_DPRINTF_L2(PRINT_MASK_IOCTL,
				    usbvcp->usbvc_log_handle, "V4L2 ioctl:"
				    " first read, open pipe fail");
				rv = EINVAL;

				break;
			}
		}
		/* If it is already started */
		if (strm_if->start_polling == 1) {
			mutex_exit(&usbvcp->usbvc_mutex);

			break;
		}
		/* At present, VIDIOC_STREAMON supports mmap io only. */
		if (usbvc_start_isoc_polling(usbvcp, strm_if,
		    V4L2_MEMORY_MMAP) != USB_SUCCESS) {
			rv = EFAULT;
			mutex_exit(&usbvcp->usbvc_mutex);

			break;
		}
		strm_if->start_polling = 1;
		strm_if->stream_on = 1; /* the only place to set this value */

		mutex_exit(&usbvcp->usbvc_mutex);

		break;
	}

	case VIDIOC_STREAMOFF:
	{
		int			type;	/* v4l2_buf_type */
		usbvc_stream_if_t	*strm_if;

		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: VIDIOC_STREAMOFF");
		USBVC_COPYIN(type);
		mutex_enter(&usbvcp->usbvc_mutex);
		strm_if = usbvcp->usbvc_curr_strm;
		if (!strm_if) {
			mutex_exit(&usbvcp->usbvc_mutex);
			rv = EINVAL;

			break;
		}
		if (type != V4L2_BUF_TYPE_VIDEO_CAPTURE) {
			mutex_exit(&usbvcp->usbvc_mutex);
			USB_DPRINTF_L2(PRINT_MASK_IOCTL,
			    usbvcp->usbvc_log_handle, "V4L2 ioctl: "
			    "VIDIOC_STREAMON: fail. Only capture type is "
			    "supported by now.");
			rv = EINVAL;

			break;
		}

		/* Need close the isoc data pipe if any reads are performed. */
		strm_if = usbvcp->usbvc_curr_strm;
		if (strm_if->start_polling == 1) {
			mutex_exit(&usbvcp->usbvc_mutex);
			usb_pipe_stop_isoc_polling(strm_if->datain_ph,
			    USB_FLAGS_SLEEP);
			mutex_enter(&usbvcp->usbvc_mutex);
			strm_if->start_polling = 0;
		}
		strm_if->stream_on = 0;
		mutex_exit(&usbvcp->usbvc_mutex);

		break;
	}

	case VIDIOC_ENUMINPUT:
	{
		struct v4l2_input input;

		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: ENUMINPUT");
		USBVC_COPYIN(input);

		if (input.index != 0) { /* Support only one INPUT now */
			rv = EINVAL;

			break;
		}
		(void) strncpy((char *)input.name, "Camera Terminal",
		    sizeof (input.name));
		input.type = V4L2_INPUT_TYPE_CAMERA;
		USBVC_COPYOUT(input);

		break;
	}

	case VIDIOC_G_INPUT:
	{
		int input_idx = 0;	/* Support only one input now */

		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: G_INPUT");
		USBVC_COPYOUT(input_idx);

		break;
	}

	case VIDIOC_S_INPUT:
	{
		int input_idx;

		USBVC_COPYIN(input_idx);
		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: S_INPUT");
		if (input_idx != 0) {	/* Support only one input now */
			rv = EINVAL;
		}

		break;
	}

	/* Query the device that what kinds of video ctrls are supported */
	case VIDIOC_QUERYCTRL:
	{
		struct v4l2_queryctrl queryctrl;

		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: QUERYCTRL");
		USBVC_COPYIN(queryctrl);

		if (usbvc_v4l2_query_ctrl(usbvcp, &queryctrl) != USB_SUCCESS) {
			rv = EINVAL;

			break;
		}

		USBVC_COPYOUT(queryctrl);

		break;
	}
	case VIDIOC_G_CTRL:
	{
		struct v4l2_control ctrl;

		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: G_CTRL");
		USBVC_COPYIN(ctrl);
		if (usbvc_v4l2_get_ctrl(usbvcp, &ctrl) != USB_SUCCESS) {
			rv = EINVAL;

			break;
		}

		USBVC_COPYOUT(ctrl);

		break;
	}
	case VIDIOC_S_CTRL:
	{
		struct v4l2_control ctrl;

		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: S_CTRL");
		USBVC_COPYIN(ctrl);
		if (usbvc_v4l2_set_ctrl(usbvcp, &ctrl) != USB_SUCCESS) {
			rv = EINVAL;

			break;
		}

		USBVC_COPYOUT(ctrl);

		break;
	}
	case VIDIOC_S_PARM:
	{
		struct v4l2_streamparm	parm;
		usbvc_stream_if_t	*strm_if;

		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: VIDIOC_S_PARM");
		mutex_enter(&usbvcp->usbvc_mutex);
		strm_if = usbvcp->usbvc_curr_strm;

		/* If data I/O is in progress */
		if (strm_if->start_polling == 1) {
			rv = EBUSY;
			mutex_exit(&usbvcp->usbvc_mutex);

			break;
		}
		mutex_exit(&usbvcp->usbvc_mutex);

		USBVC_COPYIN(parm);

		/* Support capture only, so far. */
		if (parm.type != V4L2_BUF_TYPE_VIDEO_CAPTURE) {
			rv = EINVAL;

			break;
		}

		if (usbvc_v4l2_set_parm(usbvcp, &parm) != USB_SUCCESS) {
			rv = EINVAL;
			USB_DPRINTF_L2(PRINT_MASK_IOCTL,
			    usbvcp->usbvc_log_handle,
			    "V4L2 ioctl VIDIOC_S_PARM fail");
		}
		USBVC_COPYOUT(parm);

		break;
	}
	case VIDIOC_G_PARM:
	{
		struct v4l2_streamparm	parm;

		USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "V4L2 ioctl: VIDIOC_G_PARM");
		USBVC_COPYIN(parm);

		/* Support capture only, so far. */
		if (parm.type != V4L2_BUF_TYPE_VIDEO_CAPTURE) {
			rv = EINVAL;

			break;
		}

		if ((rv = usbvc_v4l2_get_parm(usbvcp, &parm)) != USB_SUCCESS) {

			break;
		}

		USBVC_COPYOUT(parm);

		break;
	}
	/* These ioctls are for analog video standards. */
	case VIDIOC_G_STD:
	case VIDIOC_S_STD:
	case VIDIOC_ENUMSTD:
	case VIDIOC_QUERYSTD:
		rv = EINVAL;
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_ioctl: not a supported cmd, cmd=%x", cmd);

		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_ioctl: not a valid cmd value, cmd=%x", cmd);
		rv = ENOTTY;
	}

	USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "usbvc_v4l2_ioctl: exit, rv=%d", rv);

	return (rv);

}


/*
 * Convert GUID in uncompressed format descriptor to the pixelformat element
 * in struct v4l2_pix_format
 */
uint32_t
usbvc_v4l2_guid2fcc(uint8_t *guid)
{
	uint32_t ret;

	uint8_t y[16] = USBVC_FORMAT_GUID_YUY2;
	uint8_t n[16] = USBVC_FORMAT_GUID_NV12;
	if (!memcmp((void *)guid, (void *) &y[0], 16)) {
		ret = V4L2_PIX_FMT_YUYV;

		return (ret);
	}
	if (!memcmp((void *)guid, (void *) &n, 16)) {
		ret = V4L2_PIX_FMT_NV12;

		return (ret);
	}

	return (0);
}


/*
 * Find a frame which has the closest image size as the input args
 * (width, height)
 */
static usbvc_frames_t *
usbvc_match_image_size(uint32_t width, uint32_t height,
    usbvc_format_group_t *fmtgrp)
{
	uint32_t w, h, diff, sz, i;
	usbvc_frames_t *frame = NULL;
	usbvc_frame_descr_t *descr;

	diff = 0xffffffff;

	for (i = 0; i < fmtgrp->frame_cnt; i++) {

		descr = fmtgrp->frames[i].descr;
		if (descr == NULL) {

			continue;
		}
		LE_TO_UINT16(descr->wWidth, 0, w);
		LE_TO_UINT16(descr->wHeight, 0, h);

		sz = min(w, width) * min(h, height);
		sz = (w * h + width * height - sz * 2);
		if (sz < diff) {
			frame = &fmtgrp->frames[i];
			diff = sz;
		}

		if (diff == 0) {

			return (frame);
		}
	}

	return (frame);
}


/* Implement ioctl VIDIOC_S_FMT, set a video format */
static int
usbvc_v4l2_set_format(usbvc_state_t *usbvcp, struct v4l2_format *format)
{
	usbvc_vs_probe_commit_t	ctrl, ctrl_max, ctrl_min, ctrl_curr;
	usbvc_stream_if_t	*strm_if;
	usbvc_format_group_t	*fmtgrp;
	usbvc_frames_t		*frame;
	uint32_t		w, h, interval, bandwidth;
	uint8_t			type, i;

	mutex_enter(&usbvcp->usbvc_mutex);

	/*
	 * Get the first stream interface. Todo: deal with multi stream
	 * interfaces.
	 */
	strm_if = usbvcp->usbvc_curr_strm;

	USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "usbvc_v4l2_set_format: strm_if->fmtgrp_cnt=%d",
	    strm_if->fmtgrp_cnt);

	/* Find the proper format group according to compress type and guid */
	for (i = 0; i < strm_if->fmtgrp_cnt; i++) {
		fmtgrp = &strm_if->format_group[i];

		/*
		 * If v4l2_pixelformat is NULL, then that means there is not
		 * a parsed format in format_group[i].
		 */
		if (!fmtgrp->v4l2_pixelformat || fmtgrp->frame_cnt == 0) {
			USB_DPRINTF_L3(PRINT_MASK_DEVCTRL,
			    usbvcp->usbvc_log_handle,
			    "usbvc_set_default_stream_fmt: no frame, fail");

			continue;
		}
		type = fmtgrp->format->bDescriptorSubType;
		USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_set_format: type =%x, i =%d", type, i);

		if ((type == VS_FORMAT_MJPEG) ||
		    (type == VS_FORMAT_UNCOMPRESSED)) {
			if (format->fmt.pix.pixelformat ==
			    fmtgrp->v4l2_pixelformat) {

				break;
			}
		}
	}

	if (i >= strm_if->fmtgrp_cnt) {
		mutex_exit(&usbvcp->usbvc_mutex);
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_set_format: can't find a proper format, "
		    "pixelformat=%x", format->fmt.pix.pixelformat);

		return (USB_FAILURE);
	}

	fmtgrp = &strm_if->format_group[i];

	frame = usbvc_match_image_size(format->fmt.pix.width,
	    format->fmt.pix.height, fmtgrp);

	if (frame == NULL) {
		mutex_exit(&usbvcp->usbvc_mutex);
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_set_format: can't find a proper frame, rw=%d, "
		    "rh=%d", format->fmt.pix.width, format->fmt.pix.height);

		return (USB_FAILURE);
	}

	/* frame interval */
	LE_TO_UINT32(frame->descr->dwDefaultFrameInterval, 0, interval);
	USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "usbvc_v4l2_set_format: Default Frame Interval=%x", interval);

	/*
	 * Begin negotiate formats.
	 */
	bzero((void *)&ctrl, sizeof (usbvc_vs_probe_commit_t));

	/* dwFrameInterval is fixed */
	ctrl.bmHint[0] = 1;

	ctrl.bFormatIndex = fmtgrp->format->bFormatIndex;
	ctrl.bFrameIndex = frame->descr->bFrameIndex;
	UINT32_TO_LE(interval, 0, ctrl.dwFrameInterval);

	mutex_exit(&usbvcp->usbvc_mutex);

	/* Probe, just a test before the real try */
	if (usbvc_vs_set_probe_commit(usbvcp, strm_if, &ctrl, VS_PROBE_CONTROL)
	    != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_set_format: set probe failed");

		return (USB_FAILURE);
	}

	/* Get max values */
	if (usbvc_vs_get_probe(usbvcp, strm_if, &ctrl_max, GET_MAX) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_set_format: get probe MAX failed");

		return (USB_FAILURE);
	}

	/* Use the best quality first */
	bcopy(&ctrl_max.wCompQuality, &ctrl.wCompQuality, 2);

	/*
	 * By now, we've get some parametres of ctrl req, next try to set ctrl.
	 */
	for (i = 0; i < 2; i++) {

		/* Probe */
		if (usbvc_vs_set_probe_commit(usbvcp, strm_if, &ctrl,
		    VS_PROBE_CONTROL) != USB_SUCCESS) {

			return (USB_FAILURE);
		}

		/* Get current value after probe */
		if (usbvc_vs_get_probe(usbvcp, strm_if, &ctrl_curr, GET_CUR)
		    != USB_SUCCESS) {

			return (USB_FAILURE);
		}
		LE_TO_UINT32(ctrl_curr.dwMaxPayloadTransferSize, 0, bandwidth);
		USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_set_format: bandwidth=%x", bandwidth);

		/*
		 * If the bandwidth does not exceed the max value of all the
		 * alternatives in this interface, we done.
		 */
		if (bandwidth <= strm_if->max_isoc_payload) {

			break;
		}
		if (i >= 1) {

			return (USB_FAILURE);
		}

		/* Get minimum values since the bandwidth is not enough */
		if (usbvc_vs_get_probe(usbvcp, strm_if, &ctrl_min, GET_MIN) !=
		    USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_IOCTL,
			    usbvcp->usbvc_log_handle,
			    "usbvc_v4l2_set_format: get probe MIN failed");

			return (USB_FAILURE);
		}

		/* To keep simple, just use some minimum values to try again */
		bcopy(&ctrl_min.wKeyFrameRate, &ctrl_curr.wKeyFrameRate, 2);
		bcopy(&ctrl_min.wPFrameRate, &ctrl_curr.wPFrameRate, 2);
		bcopy(&ctrl_min.wCompWindowSize, &ctrl_curr.wCompWindowSize, 2);
		bcopy(&ctrl_max.wCompQuality, &ctrl_curr.wCompQuality, 2);

		bcopy(&ctrl_curr, &ctrl,
		    sizeof (usbvc_vs_probe_commit_t));
	}

	bcopy(&ctrl_curr, &ctrl, sizeof (usbvc_vs_probe_commit_t));

	/* commit the values we negotiated above */
	if (usbvc_vs_set_probe_commit(usbvcp, strm_if, &ctrl,
	    VS_COMMIT_CONTROL) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_set_format: set probe failed, i=%d", i);

		return (USB_FAILURE);
	}
	mutex_enter(&usbvcp->usbvc_mutex);

	/*
	 * It's good to check index here before use it. bFormatIndex is based
	 * on 1, and format_group[i] is based on 0, so minus 1
	 */
	i = ctrl.bFormatIndex - 1;
	if (i < strm_if->fmtgrp_cnt) {
		strm_if->cur_format_group = &strm_if->format_group[i];
	} else {
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_set_format: format index out of range");
		mutex_exit(&usbvcp->usbvc_mutex);

		return (USB_FAILURE);
	}

	/* bFrameIndex is based on 1, and frames[i] is based on 0, so minus 1 */
	i = ctrl.bFrameIndex -1;
	if (i < strm_if->cur_format_group->frame_cnt) {
		strm_if->cur_format_group->cur_frame =
		    &strm_if->cur_format_group->frames[i];
	} else {
		mutex_exit(&usbvcp->usbvc_mutex);
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_set_format: frame index out of range");

		return (USB_FAILURE);
	}

	/*
	 * by now, the video format is set successfully. record the current
	 * setting to strm_if->ctrl_pc
	 */
	bcopy(&ctrl_curr, &strm_if->ctrl_pc, sizeof (usbvc_vs_probe_commit_t));

	format->fmt.pix.colorspace = fmtgrp->v4l2_color;
	format->fmt.pix.field = V4L2_FIELD_NONE;
	format->fmt.pix.priv = 0;

	LE_TO_UINT16(frame->descr->wWidth, 0, w);
	LE_TO_UINT16(frame->descr->wHeight, 0, h);
	format->fmt.pix.width = w;
	format->fmt.pix.height = h;
	format->fmt.pix.bytesperline = fmtgrp->v4l2_bpp * w;
	LE_TO_UINT32(strm_if->ctrl_pc.dwMaxVideoFrameSize, 0,
	    format->fmt.pix.sizeimage);

	mutex_exit(&usbvcp->usbvc_mutex);

	USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "usbvc_v4l2_set_format: dwMaxVideoFrameSize=%x, w=%x, h=%x",
	    format->fmt.pix.sizeimage, w, h);

	return (USB_SUCCESS);
}


/* Implement ioctl VIDIOC_G_FMT, get the current video format */
static int
usbvc_v4l2_get_format(usbvc_state_t *usbvcp, struct v4l2_format *format)
{
	usbvc_stream_if_t	*strm_if;
	usbvc_format_group_t	*fmtgrp;
	uint16_t		w, h;

	if (format->type != V4L2_BUF_TYPE_VIDEO_CAPTURE) {

		return (EINVAL);
	}
	mutex_enter(&usbvcp->usbvc_mutex);

	/* get the current interface. */
	strm_if = usbvcp->usbvc_curr_strm;
	fmtgrp = strm_if->cur_format_group;

	if (!fmtgrp || !fmtgrp->cur_frame) {
		mutex_exit(&usbvcp->usbvc_mutex);
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_get_format: fail, no current format or frame,"
		    "fmtgrp=%p", (void *)fmtgrp);

		return (EINVAL);
	}
	format->fmt.pix.colorspace = fmtgrp->v4l2_color;
	format->fmt.pix.priv = 0;
	format->fmt.pix.pixelformat = fmtgrp->v4l2_pixelformat;

	LE_TO_UINT16(fmtgrp->cur_frame->descr->wWidth, 0, w);
	LE_TO_UINT16(fmtgrp->cur_frame->descr->wHeight, 0, h);
	USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "v4l2 ioctl get format ");
	format->fmt.pix.width = w;
	format->fmt.pix.height = h;

	format->fmt.pix.field = V4L2_FIELD_NONE;
	format->fmt.pix.bytesperline = fmtgrp->v4l2_bpp * w;

	LE_TO_UINT32(strm_if->ctrl_pc.dwMaxVideoFrameSize, 0,
	    format->fmt.pix.sizeimage);

	mutex_exit(&usbvcp->usbvc_mutex);

	return (0);
}


/*
 * Convert color space descriptor's bColorPrimaries to the colorspace element
 * in struct v4l2_pix_format
 */
uint8_t
usbvc_v4l2_colorspace(uint8_t color_prim)
{

	if (color_prim < NELEM(color_primaries)) {

		return (color_primaries[color_prim]);
	}

	return (0);
}


/* Implement ioctl VIDIOC_QUERYBUF, get the buf status */
static void
usbvc_v4l2_query_buf(usbvc_state_t *usbvcp, usbvc_buf_t *usbvc_buf,
	struct v4l2_buffer *v4l2_buf)
{
	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));

	bcopy(&(usbvc_buf->v4l2_buf), v4l2_buf, sizeof (struct v4l2_buffer));
	USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "usbvc_v4l2_query_buf: uv_buf_len=%d, len=%d",
	    usbvc_buf->v4l2_buf.length, v4l2_buf->length);

	if (usbvc_buf->status >= USBVC_BUF_MAPPED) {
		v4l2_buf->flags |= V4L2_BUF_FLAG_MAPPED;
	}

	switch (usbvc_buf->status) {
	case USBVC_BUF_DONE:
	case USBVC_BUF_ERR:
		v4l2_buf->flags |= V4L2_BUF_FLAG_DONE;

		break;
	case USBVC_BUF_EMPTY:
		v4l2_buf->flags |= V4L2_BUF_FLAG_QUEUED;

		break;
	case USBVC_BUF_INIT:
	default:

		break;
	}
}


/* Implement ioctl VIDIOC_QBUF, queue a empty buf to the free list */
static int
usbvc_v4l2_enqueue_buf(usbvc_state_t *usbvcp, usbvc_buf_t *usbvc_buf,
	struct v4l2_buffer *buf)
{
	usbvc_buf_t	*donebuf;
	boolean_t	queued = B_FALSE;
	usbvc_buf_grp_t	*bufgrp;

	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));

	bufgrp = &usbvcp->usbvc_curr_strm->buf_map;

	if (usbvc_buf == bufgrp->buf_filling) {
		USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "enqueue_buffer(%d) , want to queue buf_filling, "
		    "just return success", buf->index);

		return (0);
	}

	if (!list_is_empty(&bufgrp->uv_buf_done)) {
		donebuf = (usbvc_buf_t *)list_head(&bufgrp->uv_buf_done);
		while (donebuf) {

			if (donebuf == &(bufgrp->buf_head[buf->index])) {
				queued = B_TRUE;

				break;
			}
			donebuf = (usbvc_buf_t *)list_next(&bufgrp->uv_buf_done,
			    donebuf);
		}
	}
	if (queued) {
		USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "enqueue_buffer(%d), still in done list, don't insert to"
		    " free list", buf->index);

		return (0);
	}

	if (usbvc_buf->status == USBVC_BUF_EMPTY) {
		USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "enqueue buffer(%d), already queued.", buf->index);

		return (0);

	}
	if (usbvc_buf->status < USBVC_BUF_MAPPED) {
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "enqueue buffer(%d), state error, not mapped.", buf->index);

		return (EINVAL);
	}

	/*
	 * The buf is put to the buf free list when allocated, so, if the buf
	 * is the first time to enqueue, just change the state to empty is
	 * enough.
	 */
	if (usbvc_buf->status == USBVC_BUF_MAPPED) {
		USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "queue_buffer(%d), 1st time queue this buf", buf->index);

		usbvc_buf->status = USBVC_BUF_EMPTY;

	} else {
		USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "enqueue_buffer(%d) , USBVC_BUF_EMPTY", buf->index);

		usbvc_buf->status = USBVC_BUF_EMPTY;
		usbvc_buf->v4l2_buf.bytesused = 0;
		list_insert_tail(&bufgrp->uv_buf_free, usbvc_buf);
	}
	buf->flags &= ~V4L2_BUF_FLAG_DONE;
	buf->flags |= V4L2_BUF_FLAG_MAPPED | V4L2_BUF_FLAG_QUEUED;

	return (0);
}


/* Implement ioctl VIDIOC_DQBUF, pick a buf from done list */
static int
usbvc_v4l2_dequeue_buffer(usbvc_state_t *usbvcp, struct v4l2_buffer *buf,
	int mode)
{
	usbvc_buf_t *buf_done;

	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));
	USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "usbvc_v4l2_dequeue_buffer: idx=%x", buf->index);

	/* v4l2 spec: app just set type and memory field */
	if ((buf->type != V4L2_BUF_TYPE_VIDEO_CAPTURE) ||
	    (buf->memory != V4L2_MEMORY_MMAP)) {

		return (EINVAL);
	}
	if ((mode & (O_NDELAY|O_NONBLOCK)) &&
	    (list_is_empty(&usbvcp->usbvc_curr_strm->buf_map.uv_buf_done))) {

		/* non-blocking */
		return (EAGAIN);
	}

	/* no available buffers, block here */
	while (list_is_empty(&usbvcp->usbvc_curr_strm->buf_map.uv_buf_done)) {
		USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_dequeue_buffer: wait for done buf");
		if (cv_wait_sig(&usbvcp->usbvc_mapio_cv, &usbvcp->usbvc_mutex)
		    <= 0) {

			/* no done buf and is signaled */
			return (EINTR);
		}
		if (usbvcp->usbvc_dev_state != USB_DEV_ONLINE) {

			/* Device is disconnected. */
			return (EINTR);
		}
	}

	buf_done = list_head(&usbvcp->usbvc_curr_strm->buf_map.uv_buf_done);

	list_remove(&usbvcp->usbvc_curr_strm->buf_map.uv_buf_done, buf_done);

	/*
	 * just copy the v4l2_buf structure because app need only the index
	 * value to locate the mapped memory
	 */
	bcopy(&buf_done->v4l2_buf, buf, sizeof (struct v4l2_buffer));
	buf->flags |= V4L2_BUF_FLAG_DONE | V4L2_BUF_FLAG_MAPPED;
	buf->bytesused = buf_done->filled;
	USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "usbvc_v4l2_dequeue_buffer: bytesused=%d, idx=%x, status=%d",
	    buf->bytesused, buf->index, buf_done->status);

	return (0);
}


/*
 * Check if a ctrl_id is supported by the device, if yes, find the
 * corresponding processing unit and fill usbvc_v4l2_ctrl_t
 */
static int
usbvc_v4l2_match_ctrl(usbvc_state_t *usbvcp, usbvc_v4l2_ctrl_t *ctrl,
    uint32_t ctrl_id)
{
	uint8_t		idx;
	usbvc_units_t	*unit;
	uchar_t		bit;

	USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "usbvc_v4l2_match_ctrl: ctrl_id=%x", ctrl_id);
	if (ctrl_id >= V4L2_CID_PRIVATE_BASE) {

		return (USB_FAILURE);
	}
	if (ctrl_id < V4L2_CID_BASE) {

		return (USB_FAILURE);
	}

	/* get the idx of ctrl array usbvc_v4l2_ctrl */
	idx = ctrl_id - V4L2_CID_BASE;
	if (ctrl_id == V4L2_CID_GAMMA) {

		/* The 4th one is for Gamma ctrl */
		bit = usbvc_v4l2_ctrls[4].bit;
	} else if ((ctrl_id >= V4L2_CID_BRIGHTNESS) &&
	    (ctrl_id <= V4L2_CID_HUE)) {

		/* The idxth one is for this ctrl */
		bit = usbvc_v4l2_ctrls[idx].bit;
	} else {

		return (USB_FAILURE);
	}
	unit = (usbvc_units_t *)list_head(&usbvcp->usbvc_unit_list);

	/*
	 * Check if there is a processing unit supportting this ctrl.
	 * Todo: check if the ctrl and the unit is really for the right
	 * stream interface in case of multi stream interfaces.
	 */
	while (unit != NULL) {

		if (unit->descr->bDescriptorSubType == VC_PROCESSING_UNIT) {

			if (bit >=
			    (unit->descr->unit.processing.bControlSize * 8)) {

				/*
				 * If this unit's bmControls size is smaller
				 * than bit, then next
				 */
				unit = (usbvc_units_t *)
				    list_next(&usbvcp->usbvc_unit_list, unit);

				continue;
			} else {

				/*
				 * The first two bytes of bmControls are
				 * for ctrls
				 */
				if ((bit < 8) &&
				    unit->bmControls[0] & (0x1 << bit)) {

					break;
				}
				if ((bit >= 8 && bit < 16) &&
				    unit->bmControls[1] & (0x1 << bit)) {

					break;
				}
			}
		}
		unit = (usbvc_units_t *)list_next(&usbvcp->usbvc_unit_list,
		    unit);
	}
	if (unit == NULL) {

		return (USB_FAILURE);
	}
	ctrl->entity_id = unit->descr->bUnitID;
	if (ctrl_id == V4L2_CID_GAMMA) {
		ctrl->ctrl_map = &usbvc_v4l2_ctrls[4];
	} else {
		ctrl->ctrl_map = &usbvc_v4l2_ctrls[idx];
	}

	return (USB_SUCCESS);
}


/*
 * Implement ioctl VIDIOC_QUERYCTRL, query the ctrl types that the device
 * supports
 */
static int
usbvc_v4l2_query_ctrl(usbvc_state_t *usbvcp, struct v4l2_queryctrl *queryctrl)
{
	usbvc_v4l2_ctrl_t	ctrl;
	mblk_t			*data;
	char			req[16];

	if (usbvc_v4l2_match_ctrl(usbvcp, &ctrl, queryctrl->id) !=
	    USB_SUCCESS) {

		return (USB_FAILURE);
	}
	if ((data = allocb(ctrl.ctrl_map->len, BPRI_LO)) == NULL) {

		return (USB_FAILURE);
	}

	if (usbvc_vc_get_ctrl(usbvcp, GET_MIN, ctrl.entity_id,
	    ctrl.ctrl_map->selector, ctrl.ctrl_map->len, data) !=
	    USB_SUCCESS) {
		(void) strncpy(&req[0], "GET_MIN", sizeof (req));

		goto fail;
	}
	LE_TO_UINT16(data->b_rptr, 0, queryctrl->minimum);
	if (usbvc_vc_get_ctrl(usbvcp, GET_MAX, ctrl.entity_id,
	    ctrl.ctrl_map->selector, ctrl.ctrl_map->len, data) != USB_SUCCESS) {
		(void) strncpy(&req[0], "GET_MAX", sizeof (req));

		goto fail;
	}
	LE_TO_UINT16(data->b_rptr, 0, queryctrl->maximum);

	if (usbvc_vc_get_ctrl(usbvcp, GET_RES, ctrl.entity_id,
	    ctrl.ctrl_map->selector, ctrl.ctrl_map->len, data) != USB_SUCCESS) {
		(void) strncpy(&req[0], "GET_RES", sizeof (req));

		goto fail;
	}
	LE_TO_UINT16(data->b_rptr, 0, queryctrl->step);

	if (usbvc_vc_get_ctrl(usbvcp, GET_DEF, ctrl.entity_id,
	    ctrl.ctrl_map->selector, ctrl.ctrl_map->len, data) != USB_SUCCESS) {
		(void) strncpy(&req[0], "GET_DEF", sizeof (req));

		goto fail;
	}
	LE_TO_UINT16(data->b_rptr, 0, queryctrl->default_value);

	(void) strncpy(queryctrl->name, ctrl.ctrl_map->name,
	    sizeof (queryctrl->name));
	queryctrl->type = ctrl.ctrl_map->type;
	queryctrl->flags = 0;

	if (data) {
		freemsg(data);
	}

	return (USB_SUCCESS);

fail:
	if (data) {
		freemsg(data);
	}
	USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "usbvc_v4l2_query_ctrl: fail when %s", req);

	return (USB_FAILURE);

}


/* Implement ioctl VIDIOC_G_CTRL, get current ctrl */
static int
usbvc_v4l2_get_ctrl(usbvc_state_t *usbvcp, struct v4l2_control *v4l2_ctrl)
{
	usbvc_v4l2_ctrl_t	ctrl;
	mblk_t			*data;

	if (usbvc_v4l2_match_ctrl(usbvcp, &ctrl, v4l2_ctrl->id) !=
	    USB_SUCCESS) {

		return (USB_FAILURE);
	}
	if ((data = allocb(ctrl.ctrl_map->len, BPRI_LO)) == NULL) {

		return (USB_FAILURE);
	}

	if (usbvc_vc_get_ctrl(usbvcp, GET_CUR, ctrl.entity_id,
	    ctrl.ctrl_map->selector, ctrl.ctrl_map->len, data) != USB_SUCCESS) {
		if (data) {
			freemsg(data);
		}
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_get_ctrl: fail");

		return (USB_FAILURE);
	}
	LE_TO_UINT16(data->b_rptr, 0, v4l2_ctrl->value);

	if (data) {
		freemsg(data);
	}

	return (USB_SUCCESS);
}


/* Implement ioctl VIDIOC_S_CTRL */
static int
usbvc_v4l2_set_ctrl(usbvc_state_t *usbvcp, struct v4l2_control *v4l2_ctrl)
{
	usbvc_v4l2_ctrl_t	ctrl;
	mblk_t			*data;

	if (usbvc_v4l2_match_ctrl(usbvcp, &ctrl, v4l2_ctrl->id) !=
	    USB_SUCCESS) {

		return (USB_FAILURE);
	}
	if ((data = allocb(ctrl.ctrl_map->len, BPRI_LO)) == NULL) {

		return (USB_FAILURE);
	}

	UINT16_TO_LE(v4l2_ctrl->value, 0, data->b_wptr);
	data->b_wptr += 2;
	if (usbvc_vc_set_ctrl(usbvcp, SET_CUR, ctrl.entity_id,
	    ctrl.ctrl_map->selector, ctrl.ctrl_map->len, data) !=
	    USB_SUCCESS) {
		if (data) {
			freemsg(data);
		}
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_set_ctrl: fail");

		return (USB_FAILURE);
	}
	if (data) {
		freemsg(data);
	}

	return (USB_SUCCESS);
}

/* For the given interval, find the closest frame interval to it. */
static uint32_t
usbvc_find_interval(usbvc_frames_t *frame, uint32_t interval)
{
	uint32_t step, i, closest, index, approx1, approx2;


	/*
	 * for continuous case, there is a min and a max, and also a step
	 * value. The available intervals are those between min and max
	 * values.
	 */
	if (!frame->descr->bFrameIntervalType) {
		step = frame->dwFrameIntervalStep;

		if (step == 0) {
		/* a malfunction device */

			return (0);
		} else if (interval <= frame->dwMinFrameInterval) {
		/* return the most possible interval we can handle */

			return (frame->dwMinFrameInterval);
		} else if (interval >= frame->dwMaxFrameInterval) {
		/* return the most possible interval we can handle */

			return (frame->dwMaxFrameInterval);
		}

		approx1 = (interval / step) * step;
		approx2 = approx1 + step;
		closest = ((interval - approx1) < (approx2 - interval)) ?
		    approx1 : approx2;

		return (closest);
	}

	/*
	 * for discrete case, search all the available intervals, find the
	 * closest one.
	 */
	closest = 0;
	approx2 = (uint32_t)-1;
	for (index = 0; index < frame->descr->bFrameIntervalType; index++) {
		LE_TO_UINT32(frame->dwFrameInterval, index * 4, i);
		approx1 = (i > interval) ? (i - interval) : (interval - i);

		if (approx1 == 0) {
		/* find the matched one, return it immediately */
			return (i);
		}

		if (approx1 < approx2) {
			approx2 = approx1;
			closest = i;
		}
	}

	return (closest);
}

/* Implement ioctl VIDIOC_S_PARM. Support capture only, so far. */
static int
usbvc_v4l2_set_parm(usbvc_state_t *usbvcp, struct v4l2_streamparm *parm)
{
	usbvc_stream_if_t	*strm_if;
	usbvc_format_group_t	*cur_fmt;
	usbvc_frames_t			*cur_frame;
	uint32_t n, d, c, i;
	usbvc_vs_probe_commit_t	ctrl;

	mutex_enter(&usbvcp->usbvc_mutex);
	strm_if = usbvcp->usbvc_curr_strm;

	if (!strm_if->cur_format_group ||
	    !strm_if->cur_format_group->cur_frame) {
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_set_parm: current format or"
		    " frame is not set. cur_fmt=%p",
		    (void *)strm_if->cur_format_group);

		mutex_exit(&usbvcp->usbvc_mutex);

		return (USB_FAILURE);
	}

	cur_fmt = strm_if->cur_format_group;
	cur_frame = cur_fmt->cur_frame;

	mutex_exit(&usbvcp->usbvc_mutex);
	if (parm->parm.capture.readbuffers > USBVC_MAX_READ_BUF_NUM) {
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_set_parm: ask too many read buffers,"
		    " readbuffers=%d",
		    parm->parm.capture.readbuffers);

		return (USB_FAILURE);
	}

	n = parm->parm.capture.timeperframe.numerator;
	d = parm->parm.capture.timeperframe.denominator;

	/* check the values passed in, in case of zero devide */
	if (d == 0) {
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_set_parm: invalid denominator=%d", d);

		return (USB_FAILURE);
	}

	/*
	 * UVC frame intervals are in 100ns units, need convert from
	 * 1s unit to 100ns unit
	 */
	c = USBVC_FRAME_INTERVAL_DENOMINATOR;

	/* check the values passed in, in case of overflow */
	if (n / d >= ((uint32_t)-1) / c) {
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_set_parm: overflow, numerator=%d,"
		    " denominator=%d", n, d);

		return (USB_FAILURE);
	}

	USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "usbvc_v4l2_set_parm: numerator=%d, denominator=%d", n, d);

	/* compute the interval in 100ns unit */
	if (n <= ((uint32_t)-1) / c) {
		i = (n * c) / d;
	} else {
		do {
			n >>= 1;
			d >>= 1;
		/* decrease both n and d, in case overflow */
		} while (n && d && n > ((uint32_t)-1) / c);

		if (!d) {
			USB_DPRINTF_L2(PRINT_MASK_IOCTL,
			    usbvcp->usbvc_log_handle,
			    "usbvc_v4l2_set_parm: can't compute interval,"
			    " denominator=%d", d);

			return (USB_FAILURE);
		}
		i = (n * c) / d;
	}

	USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "usbvc_v4l2_set_parm: want interval=%d, n=%d, d=%d, c=%d",
	    i, n, d, c);

	/*
	 * Begin negotiate frame intervals.
	 */
	bcopy(&strm_if->ctrl_pc, &ctrl, sizeof (usbvc_vs_probe_commit_t));
	i = usbvc_find_interval(cur_frame, i);

	if (i == 0) {
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_set_parm: can not find an proper interval."
		    " i=%d, n=%d, d=%d", i, n, d);

		return (USB_FAILURE);
	}

	USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "usbvc_v4l2_set_parm: get interval=%d", i);

	UINT32_TO_LE(i, 0, ctrl.dwFrameInterval);

	/* Probe, just a test before the real try */
	if (usbvc_vs_set_probe_commit(usbvcp, strm_if, &ctrl, VS_PROBE_CONTROL)
	    != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_set_parm: set probe failed");

		return (USB_FAILURE);
	}

	/* Commit the frame interval. */
	if (usbvc_vs_set_probe_commit(usbvcp, strm_if, &ctrl, VS_COMMIT_CONTROL)
	    != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_v4l2_set_parm: set commit failed");

		return (USB_FAILURE);
	}

	bcopy(&ctrl, &strm_if->ctrl_pc, sizeof (usbvc_vs_probe_commit_t));

	LE_TO_UINT32(ctrl.dwFrameInterval, 0, i);
	parm->parm.capture.timeperframe.numerator = i;
	parm->parm.capture.timeperframe.denominator = c;

	mutex_enter(&usbvcp->usbvc_mutex);
	/*
	 * According to ioctl VIDIOC_S_PARM, zero value of readbuffers will not
	 * be set. And the current value is expected to return to application.
	 */
	if (parm->parm.capture.readbuffers != 0) {
		strm_if->buf_read_num = parm->parm.capture.readbuffers;
	} else {
		parm->parm.capture.readbuffers = strm_if->buf_read_num;
	}
	mutex_exit(&usbvcp->usbvc_mutex);

	return (USB_SUCCESS);
}

/* Implement ioctl VIDIOC_G_PARM. */
static int
usbvc_v4l2_get_parm(usbvc_state_t *usbvcp, struct v4l2_streamparm *parm)
{
	usbvc_stream_if_t	*strm_if;
	uint32_t n, d;

	bzero(parm, sizeof (*parm));

	mutex_enter(&usbvcp->usbvc_mutex);
	strm_if = usbvcp->usbvc_curr_strm;

	/* return the actual number of buffers allocated for read() I/O */
	parm->parm.capture.readbuffers = strm_if->buf_read.buf_cnt;

	/* in 100ns units */
	LE_TO_UINT32(strm_if->ctrl_pc.dwFrameInterval, 0, n);
	mutex_exit(&usbvcp->usbvc_mutex);

	/*
	 * According to UVC payload specs, the dwFrameInterval in frame
	 * descriptors is in 100ns unit.
	 */
	d = USBVC_FRAME_INTERVAL_DENOMINATOR;
	parm->parm.capture.timeperframe.numerator = n;
	parm->parm.capture.timeperframe.denominator = d;

	/* Support capture only, so far. */
	parm->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	parm->parm.capture.capability = V4L2_CAP_TIMEPERFRAME;
	parm->parm.capture.capturemode = 0; /* no high quality imaging mode */
	parm->parm.capture.extendedmode = 0; /* no driver specific parameters */

	/* Always success for current support of this command */
	return (USB_SUCCESS);
}
