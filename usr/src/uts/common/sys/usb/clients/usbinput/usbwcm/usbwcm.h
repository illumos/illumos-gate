/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2007, 2008 Bartosz Fabianowski <freebsd@chillt.de>
 * All rights reserved.
 *
 * Financed by the "Irish Research Council for Science, Engineering and
 * Technology: funded by the National Development Plan"
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Lennart Augustsson (lennart@augustsson.net) at
 * Carlstedt Research & Technology.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SYS_USB_USBWCM_H
#define	_SYS_USB_USBWCM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ioccom.h>
#if defined(_LP64) || defined(_I32LPx)
#include <sys/types32.h>
#else
#include <sys/types.h>
#endif
#include <sys/time.h>

#define	EVTIOCGVERSION	_IOR('E', 0x1, int)
#define	EVTIOCGDEVID	_IOR('E', 0x2, struct event_dev_id)
#define	EVTIOCGBM(i, s)	_IORN('E', 0x20 + (i), (s))
#define	EVTIOCGABS(i)	_IOR('E', 0x40 + (i), struct event_abs_axis)
#define	EVTIOC		('E' << 8)

struct event_dev_id {
	uint16_t bus;
#define	ID_BUS_USB 3
	uint16_t vendor;
	uint16_t product;
	uint16_t version;
};

struct event_abs_axis {
	int32_t value;
	int32_t min;
	int32_t max;
	int32_t fuzz;
	int32_t flat;
};

struct event_input {
#if defined(_LP64) || defined(_I32LPx)
	struct timeval32 time;
#else
	struct timeval time;
#endif
	uint16_t type;
	uint16_t code;
	int32_t value;
};

#define	EVT_SYN				0x0000
#define	EVT_BTN				0x0001
#define	EVT_REL				0x0002
#define	EVT_ABS				0x0003
#define	EVT_MSC				0x0004
#define	EVT_USED			0x0005
#define	EVT_MAX				0x001f

#define	SYN_REPORT			0x0000

#define	BTN_MISC_0			0x0100
#define	BTN_MISC_1			0x0101
#define	BTN_MISC_2			0x0102
#define	BTN_MISC_3			0x0103
#define	BTN_MISC_4			0x0104
#define	BTN_MISC_5			0x0105
#define	BTN_MISC_6			0x0106
#define	BTN_MISC_7			0x0107
#define	BTN_MISC_8			0x0108

#define	BTN_LEFT			0x0110
#define	BTN_RIGHT			0x0111
#define	BTN_MIDDLE			0x0112
#define	BTN_SIDE			0x0113
#define	BTN_EXTRA			0x0114
#define	BTN_TOOL_PEN			0x0140
#define	BTN_TOOL_ERASER			0x0141
#define	BTN_TOOL_PAD			0x0145
#define	BTN_TOOL_MOUSE			0x0146
#define	BTN_TIP				0x014a
#define	BTN_STYLUS_1			0x014b
#define	BTN_STYLUS_2			0x014c
#define	BTN_USED			0x014d
#define	BTN_MISC_UND			0x01ff
#define	BTN_MAX				0x01ff

#define	REL_WHEEL			0x0008
#define	REL_MAX				0x000f

#define	ABS_X				0x0000
#define	ABS_Y				0x0001
#define	ABS_Z				0x0002
#define	ABS_RX				0x0003
#define	ABS_RY				0x0004
#define	ABS_RZ				0x0005

#define	ABS_WHEEL			0x0008
#define	ABS_PRESSURE			0x0018
#define	ABS_DISTANCE			0x0019
#define	ABS_TILT_X			0x001a
#define	ABS_TILT_Y			0x001b
#define	ABS_MISC			0x0028
#define	ABS_USED			0x0029
#define	ABS_MAX				0x003f

#define	MSC_SERIAL			0x0000
#define	MSC_MAX				0x0007

#ifdef _KERNEL
/* USB IDs */
#define	USB_VENDOR_WACOM			0x056a

#define	USB_PRODUCT_WACOM_GRAPHIRE		0x0010
#define	USB_PRODUCT_WACOM_GRAPHIRE2_4X5		0x0011
#define	USB_PRODUCT_WACOM_GRAPHIRE2_5X7		0x0012
#define	USB_PRODUCT_WACOM_GRAPHIRE3_4X5		0x0013
#define	USB_PRODUCT_WACOM_GRAPHIRE3_6X8		0x0014
#define	USB_PRODUCT_WACOM_GRAPHIRE4_4X5		0x0015
#define	USB_PRODUCT_WACOM_GRAPHIRE4_6X8		0x0016
#define	USB_PRODUCT_WACOM_BAMBOO_FUN_4X5	0x0017
#define	USB_PRODUCT_WACOM_BAMBOO_FUN_6X8	0x0018
#define	USB_PRODUCT_WACOM_BAMBOO_ONE_6X8	0x0019
#define	USB_PRODUCT_WACOM_CINTIQ_21UX		0x003f
#define	USB_PRODUCT_WACOM_VOLITO		0x0060
#define	USB_PRODUCT_WACOM_PENSTATION2		0x0061
#define	USB_PRODUCT_WACOM_VOLITO2_4X5		0x0062
#define	USB_PRODUCT_WACOM_VOLITO2_2X3		0x0063
#define	USB_PRODUCT_WACOM_PENPARTNER2		0x0064
#define	USB_PRODUCT_WACOM_BAMBOO		0x0065
#define	USB_PRODUCT_WACOM_BAMBOO_ONE_4X5	0x0069
#define	USB_PRODUCT_WACOM_INTUOS3_4X5		0x00b0
#define	USB_PRODUCT_WACOM_INTUOS3_6X8		0x00b1
#define	USB_PRODUCT_WACOM_INTUOS3_9X12		0x00b2
#define	USB_PRODUCT_WACOM_INTUOS3_12X12		0x00b3
#define	USB_PRODUCT_WACOM_INTUOS3_12X19		0x00b4
#define	USB_PRODUCT_WACOM_INTUOS3_6X11		0x00b5
#define	USB_PRODUCT_WACOM_INTUOS3_4X6		0x00b7

#define	USB_PRODUCT_WACOM_INTUOS4_4X6		0x00b8
#define	USB_PRODUCT_WACOM_INTUOS4_6X9		0x00b9
#define	USB_PRODUCT_WACOM_INTUOS4_8X13		0x00ba
#define	USB_PRODUCT_WACOM_INTUOS4_12X19		0x00bb

#define	TOOL_ID_PEN	0x0002
#define	TOOL_ID_MOUSE	0x0006
#define	TOOL_ID_ERASER	0x000a
#define	TOOL_ID_PAD	0x000f

#define	SERIAL_PAD_INTUOS	0xffffffff
#define	SERIAL_PAD_GRAPHIRE4	0x000000f0

#define	EUWACOMGETVERSION		0x01
#define	EUWACOMGETID			0x02
#define	EUWACOMGETBM			0x20
#define	EUWACOMGETABS			0x40

/* Protocols */
struct uwacom_protocol_type {
	int packet_size;
	int distance_max;
};

enum uwacom_protocol {
	/* Graphire family */
	GRAPHIRE = 0,
	GRAPHIRE4,
	MYOFFICE,

	/* Intuos family */
	INTUOS3S,
	INTUOS3L,
	INTUOS4S,
	INTUOS4L,
	CINTIQ
};

struct uwacom_id {
	uint16_t	vid;
	uint16_t	pid;
};

/* Models */
struct uwacom_type {
	struct uwacom_id	devno;
	enum uwacom_protocol	protocol;
	int			x_max;
	int			y_max;
	int			pressure_max;
};

static const struct uwacom_protocol_type uwacom_protocols[] = {
	{ 8, 63},
	{ 8, 63},
	{ 9, 63},
	{10, 63},
	{10, 63},
	{10, 63},
	{10, 63},
	{10, 63}
};

struct uwacom_softc {
	const struct uwacom_type	*sc_type;
	struct event_dev_id		sc_id;
	unsigned long			*sc_bm[EVT_USED];

	int				*sc_btn;
	struct event_abs_axis		*sc_abs;
	int				sc_tool[2];
	int				sc_tool_id[2];
	unsigned int			sc_serial[2];
	int				sc_sync;
};

typedef struct usbwcm_state {
	queue_t		*usbwcm_rq;	/* pointer to read queue */
	queue_t		*usbwcm_wq;	/* pointer to write queue */

	int32_t		usbwcm_flags;	/* open/qwait status */
#define	USBWCM_OPEN    0x00000001	/* opened for business */
#define	USBWCM_QWAIT   0x00000002	/* waiting for a response */

	/* software state */
	struct uwacom_softc	usbwcm_softc;

	/* device model data */
	hid_vid_pid_t	usbwcm_devid;

	/*
	 * Is an ioctl fails because an mblk wasn't
	 * available, the mlbk is saved here.
	 */
	mblk_t		*usbwcm_mioctl;
	bufcall_id_t	usbwcm_bufcall;	/* id returned by bufcall() */
} usbwcm_state_t;

#define	abs(x)		((x) < 0 ? -(x) : (x))

typedef struct usbwcm_copyin_s {
	caddr_t	addr;
	int	state;
#define	USBWCM_GETSTRUCT 1
#define	USBWCM_GETRESULT 2
} usbwcm_copyin_t;

static const struct uwacom_type uwacom_devs[] = {
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_GRAPHIRE},
		GRAPHIRE, 10206, 7422, 511
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_GRAPHIRE2_4X5},
		GRAPHIRE, 10206, 7422, 511
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_GRAPHIRE2_5X7},
		GRAPHIRE, 13918, 10206, 511
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_GRAPHIRE3_4X5},
		GRAPHIRE, 10208, 7424, 511
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_GRAPHIRE3_6X8},
		GRAPHIRE, 16704, 12064, 511
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_GRAPHIRE4_4X5},
		GRAPHIRE4, 10208, 7424, 511
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_GRAPHIRE4_6X8},
		GRAPHIRE4, 16704, 12064, 511
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_BAMBOO_FUN_4X5},
		MYOFFICE, 14760, 9225, 511
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_BAMBOO_FUN_6X8},
		MYOFFICE, 21648, 13530, 511
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_BAMBOO_ONE_6X8},
		GRAPHIRE, 16704, 12064, 511
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_CINTIQ_21UX},
		CINTIQ, 87200, 65600, 1023
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_VOLITO},
		GRAPHIRE, 5104, 3712, 511
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_PENSTATION2},
		GRAPHIRE, 3250, 2320, 255
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_VOLITO2_4X5},
		GRAPHIRE, 5104, 3712, 511
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_VOLITO2_2X3},
		GRAPHIRE, 3248, 2320, 511
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_PENPARTNER2},
		GRAPHIRE, 3250, 2320, 511
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_BAMBOO},
		MYOFFICE, 14760, 9225, 511
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_BAMBOO_ONE_4X5},
		GRAPHIRE, 5104, 3712, 511
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_INTUOS3_4X5},
		INTUOS3S, 25400, 20320, 1023
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_INTUOS3_6X8},
		INTUOS3L, 40640, 30480, 1023
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_INTUOS3_9X12},
		INTUOS3L, 60960, 45720, 1023
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_INTUOS3_12X12},
		INTUOS3L, 60960, 60960, 1023
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_INTUOS3_12X19},
		INTUOS3L, 97536, 60960, 1023
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_INTUOS3_6X11},
		INTUOS3L, 54204, 31750, 1023
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_INTUOS3_4X6},
		INTUOS3S, 31496, 19685, 1023
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_INTUOS4_4X6},
		INTUOS4S, 31496, 19685, 2047
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_INTUOS4_6X9},
		INTUOS4L, 44704, 27940, 2047
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_INTUOS4_8X13},
		INTUOS4L, 65024, 40640, 2047
	},
	{
		{USB_VENDOR_WACOM, USB_PRODUCT_WACOM_INTUOS4_12X19},
		INTUOS4L, 97536, 60960, 2047
	},
	{{0, 0},    0,  0, 0, 0}
};

#define	PACKET_BIT(b, s)		((packet[b] >> (s)) & 1)
#define	PACKET_BITS(b, s, n) \
	((((s) + (n) > 32 ? ((packet[(b) - 4]) << (32 - (s))) : 0) | \
	((s) + (n) > 24 ? ((packet[(b) - 3]) << (24 - (s))) : 0) | \
	((s) + (n) > 16 ? ((packet[(b) - 2]) << (16 - (s))) : 0) | \
	((s) + (n) >  8 ? ((packet[(b) - 1]) << (8 - (s))) : 0) | \
	((packet[(b)]) >> (s))) & \
	((n) == 32 ? 0xffffffff : (1 << (n)) - 1))

#define	BM_SIZE(x) \
	(((x) / (sizeof (long) * 8) + 1) * sizeof (long))
#define	BM_SET_BIT(x, y) \
	((x)[(y) / (sizeof (long) * 8)] |= (1ul << ((y) % (sizeof (long) * 8))))

static const size_t bm_size[EVT_USED] = {
	BM_SIZE(EVT_MAX),
	BM_SIZE(BTN_MAX),
	BM_SIZE(REL_MAX),
	BM_SIZE(ABS_MAX),
	BM_SIZE(MSC_MAX),
};

#define	PRINT_MASK_ALL	0xFFFFFFFF

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_USBWCM_H */
