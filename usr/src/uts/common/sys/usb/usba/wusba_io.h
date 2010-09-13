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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_USB_WUSBA_IO_H
#define	_SYS_USB_WUSBA_IO_H

#ifdef	__cplusplus
extern "C" {
#endif

/* ioctl commands between wusb host and the wusbadm tool */
#define	WUSB_HC_IOC		('W' << 8)

/* get the state of a device corresponding to cdid */
#define	WUSB_HC_GET_DSTATE	(WUSB_HC_IOC | 0x01)

#define	MAX_USB_NODENAME	256
/* for WUSB_HC_GET_DSTATE ioctl */
typedef struct wusb_hc_get_dstate {
	uint8_t		cdid[16];		/* IN arg */
	uint16_t	state;			/* OUT arg - device state */
	char		path[MAXPATHLEN];	/* OUT arg - device apid */

	/* OUT arg - driver name XXX: need to find MAX nodename len */
	char		nodename[MAX_USB_NODENAME];
} wusb_hc_get_dstate_t;

/* device state, refer to WUSB 1.0 spec - Figure 7.1 */
enum wusb_device_state {
	WUSB_STATE_UNCONNTED = 0,
	WUSB_STATE_CONNTING,		/* sent connection notification */
	WUSB_STATE_UNAUTHENTICATED,	/* got connect ACK from host */
	WUSB_STATE_DEFAULT,		/* authenticated and usb addr = 0 */
	WUSB_STATE_ADDRESSED,		/* non-zero usb addr is assigned */
	WUSB_STATE_CONFIGURED,		/* configuration is set */
	WUSB_STATE_SLEEPING,
	WUSB_STATE_RECONNTING
};

/* get host 48-bit MAC addr */
#define	WUSB_HC_GET_MAC_ADDR	(WUSB_HC_IOC | 0x02)

/* load CC to host and update chid when cc list is null */
#define	WUSB_HC_ADD_CC		(WUSB_HC_IOC | 0x03)

/* remove CC from host */
#define	WUSB_HC_REM_CC		(WUSB_HC_IOC | 0x04)

/* CC structure for WUSB_HC_ADD_CC and WUSB_HC_REM_CC ioctl */
typedef struct wusb_cc {
	uint8_t		CHID[16];
	uint8_t		CDID[16];
	uint8_t		CK[16];
} wusb_cc_t;

/* set host beaconing channel number */
#define	WUSB_HC_SET_CHANNEL	(WUSB_HC_IOC | 0x05)

/* start host to accept device connections and transfers */
#define	WUSB_HC_START		(WUSB_HC_IOC | 0x06)

/*
 * start flag bitmap for WUSB_HC_START ioctl:
 * INITIAL_START and CHANNEL_START are exclusive
 */
#define	WUSB_HC_INITIAL_START		0x00000001 /* fully start host */
#define	WUSB_HC_CHANNEL_START		0x00000002 /* partially start host */

/* stop host functioning */
#define	WUSB_HC_STOP		(WUSB_HC_IOC | 0x07)

/*
 * stop flag bitmap for WUSB_HC_STOP ioctl:
 * FINAL_STOP and CHANNEL_STOP are exclusive, and there must be one
 * REM_ALL_CC is optional
 */
#define	WUSB_HC_FINAL_STOP		0x00000001 /* fully stop host */
#define	WUSB_HC_CHANNEL_STOP		0x00000002 /* partially stop host */
#define	WUSB_HC_REM_ALL_CC		0x00000004 /* remove all cc'es */

/* start host to accept new device connections */
#define	WUSB_HC_START_NA	(WUSB_HC_IOC | 0x08)

/* stop host from accepting new device connections */
#define	WUSB_HC_STOP_NA		(WUSB_HC_IOC | 0x09)

/* get host state */
#define	WUSB_HC_GET_HSTATE	(WUSB_HC_IOC | 0x0a)

/* host state for WUSB_HC_GET_HSTATE ioctl */
enum wusb_host_state {
	WUSB_HC_DISCONNTED = 0,
	WUSB_HC_STOPPED,	/* default or WUSB_HC_FINAL_STOP is called */
	WUSB_HC_STARTED,	/* WUSB_HC_INITIAL_START is called */
	WUSB_HC_CH_STOPPED	/* WUSB_HC_CHANNEL_STOP is called */
};

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_WUSBA_IO_H */
