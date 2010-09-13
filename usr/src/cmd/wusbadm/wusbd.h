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

#ifndef	_WUSBD_H
#define	_WUSBD_H


#ifdef	__cplusplus
extern "C" {
#endif

#define	WUSB_HOST_PATH		"/dev/usb"
#define	WUSB_HOST_NAME		"whost"
#define	WUSB_HWA_HOST_NODE	"hwa-host"

#define	DOOR_FILE		"/var/run/wusbd/wusb_door"
#define	PID_FILE		"/var/run/wusbd/wusb.pid"
#define	WUSB_CC			"/etc/usb/wusbcc"

/* door server commands */
enum {
	WUSB_DCMD_LIST_DATA = 0,
	WUSB_DCMD_ASSOCIATE,
	WUSB_DCMD_REMOVE_DEV,
	WUSB_DCMD_REMOVE_HOST,
	WUSB_DCMD_ENABLE_HOST,
	WUSB_DCMD_DISABLE_HOST
};

enum {
	WUSBADM_OK = 0,
	WUSBADM_AUTH_FAILURE, 		/* authorization check failure */
	WUSBADM_NO_HOST, 		/* host id does not exist */
	WUSBADM_NO_DEVICE,		/* failure */
	WUSBADM_CCSTORE_ACC,		/* fail to access CC store */
	WUSBADM_NO_SUPPORT,		/* failure */
	WUSBADM_INVAL_HOSTID,		/* host-id not exist */
	WUSBADM_INVAL_DEVID,		/* dev-id not exist */
	WUSBADM_HOST_NOT_ATTACH,	/* the device file not exist */
	WUSBADM_FAILURE			/* other kind of failure */
};

#define	WUSB_AUTH_READ		"solaris.admin.wusb.read"
#define	WUSB_AUTH_MODIFY	"solaris.admin.wusb.modify"
#define	WUSB_AUTH_HOST		"solaris.admin.wusb.host"

#define	WUSB_BUF_LEN		1024


/* return values */
#define	WUSBA_SUCCESS			0
#define	WUSBA_FAILURE			-1

typedef	struct wusbd_door_call {
	uint16_t	cmdss;			/* cmd/status */
	char		buf[WUSB_BUF_LEN];	/* args/return */
} wusb_door_call_t;

/* association type */
#define	ASSO_TYPE_NUMERIC	0x01
#define	ASSO_TYPE_CABLE		0x02

/* assocation data */
typedef struct wusb_asso_ctrl {
    uint8_t host;			/* host id */
    uint8_t type;			/* c/n */
    uint8_t onetime;			/* onetime/always */
    char path[MAXPATHLEN];		/* device path */
} wusb_asso_ctrl_t;

/* host/dev contrl data */
typedef struct wusb_dev_ctrl {
    uint8_t host;			/* host id */
    uint16_t dev;			/* device id */
} wusb_dev_ctrl_t;

void daemonize();

#ifdef __cplusplus
}
#endif

#endif	/* _WUSBD_H */
