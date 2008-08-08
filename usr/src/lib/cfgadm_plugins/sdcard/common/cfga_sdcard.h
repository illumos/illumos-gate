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

#ifndef _CFGA_SDCARD_H
#define	_CFGA_SDCARD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <strings.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <libintl.h>
#include <libdevice.h>
#include <sys/varargs.h>

#include <libdevinfo.h>
#include <libdevice.h>
#include <librcm.h>
#include <synch.h>
#include <thread.h>
#include <assert.h>
#include <sys/sdcard/sda_ioctl.h>

#define	CFGA_PLUGIN_LIB
#include <config_admin.h>

/* Misc text strings */
#define	CFGA_DEV_DIR			"/dev/cfg"
#define	DYN_SEP				"::"
#define	CFGA_DEVCTL_NODE  		":devctl"
#define	MINOR_SEP 			':'
#define	PATH_SEP 			'/'

#define	RESET_SLOT		"sdcard_reset_slot"

/* for confirm operation */
#define	SDCARD_CONFIRM_1 \
	"This operation will suspend activity on the SD card device\nContinue"
#define	SDCARD_CONFIRM_2 \
	"This operation will disrupt activity on the SD card device\nContinue"

#define	GET_DYN(a)		(((a) != NULL) ? \
				strstr((a), DYN_SEP) : (void *)0)


/* Messages */

typedef struct msgcvt {
	int		intl;		/* Flag: if 1, internationalize */
	cfga_err_t	cfga_err;	/* Error code libcfgadm understands */
	const char	*msgstr;
} msgcvt_t;

#define	NO_CVT	0
#define	CVT	1

#define	MSG_TBL_SZ(table)	(sizeof ((table)) / sizeof (msgcvt_t))

/* Messages */


/* Error message ids (and indices into sdcard_error_msgs) */
typedef enum {
	CFGA_SDCARD_OK = 0,
	CFGA_SDCARD_NACK,
	CFGA_SDCARD_UNKNOWN,
	CFGA_SDCARD_PRIV,
	CFGA_SDCARD_DYNAMIC_AP,
	CFGA_SDCARD_INTERNAL_ERROR,
	CFGA_SDCARD_ALLOC_FAIL,
	CFGA_SDCARD_IOCTL,
	CFGA_SDCARD_DEVCTL,
	CFGA_SDCARD_AP,
	CFGA_SDCARD_BUSY,
	CFGA_SDCARD_DEVLINK,
	CFGA_SDCARD_INVALID_DEVNAME,
	CFGA_SDCARD_DATA_ERROR,
	CFGA_SDCARD_DEV_CONFIGURE,
	CFGA_SDCARD_DEV_UNCONFIGURE,
	CFGA_SDCARD_NOT_CONNECTED,
	CFGA_SDCARD_DISCONNECTED,
	CFGA_SDCARD_NOT_CONFIGURED,
	CFGA_SDCARD_ALREADY_CONNECTED,
	CFGA_SDCARD_ALREADY_CONFIGURED,
	CFGA_SDCARD_DEVICE_UNCONFIGURED,
	CFGA_SDCARD_OPNOTSUPP,
	CFGA_SDCARD_HWOPNOTSUPP,
	CFGA_SDCARD_OPTIONS,
	CFGA_SDCARD_STATE,
	CFGA_SDCARD_OPEN,
	CFGA_SDCARD_RCM_HANDLE,
	CFGA_SDCARD_RCM_OFFLINE,
	CFGA_SDCARD_RCM_REMOVE,
	CFGA_SDCARD_RCM_ONLINE,
	CFGA_SDCARD_CONFIRM_RESET,
	CFGA_SDCARD_CONFIRM_UNCONFIGURE,
	CFGA_SDCARD_CONFIRM_DISCONNECT
} cfga_sdcard_ret_t;

/*
 * Given an error msg index, look up the associated string, and
 * convert it to the current locale if required.
 */
#define	ERR_STR(msg_idx) \
	(get_msg((msg_idx), sdcard_msgs, MSG_TBL_SZ(sdcard_msgs)))

#ifdef __cplusplus
}
#endif

#endif	/* _CFGA_SDCARD_H */
