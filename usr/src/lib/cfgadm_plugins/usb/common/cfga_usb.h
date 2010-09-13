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

#ifndef _CFGA_USB_H
#define	_CFGA_USB_H


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
#include <sys/usb/usba.h>
#include <sys/usb/hubd/hub.h>
#include <sys/usb/hubd/hubd_impl.h>
#include <libdevinfo.h>
#include <libdevice.h>
#include <librcm.h>
#include <synch.h>
#include <thread.h>
#include <assert.h>

#define	CFGA_PLUGIN_LIB
#include <config_admin.h>


/*
 * Debug stuff.
 */
#ifdef	DEBUG
#define	DPRINTF	(void) printf
#else
#define	DPRINTF 0 &&
#endif /* DEBUG */


/* for walking links */
typedef struct walk_link {
	char *path;
	char len;
	char **linkpp;
} walk_link_t;


/*
 * Stuff carried over for the routines borrowed from cfgadm/SCSI.
 */
typedef enum {
	UCFGA_TERMINATE = 0,
	UCFGA_CONTINUE
} ucfga_recur_t;

/* Structures for tree walking code */
typedef struct {
	char *phys;
	char *log;
	int ret;
	int match_minor;
	int l_errno;
} pathm_t;


#define	MATCH_MINOR_NAME	1
#define	S_FREE(x)	(((x) != NULL) ? (free(x), (x) = NULL) : (void *)0)
#define	GET_DYN(a)	(((a) != NULL) ? strstr((a), DYN_SEP) : (void *)0)


/* Location of USB configuration file */
#define	USBCONF_FILE	"/etc/usb/config_map.conf"

/* Hardware options */
#define	OPT_DISABLE_RCM		"disable_rcm"
#define	FLAG_DISABLE_RCM	0x00000001	/* flags */

/* Return/error codes */
typedef enum {
	UCFGA_ERR = -2,
	UCFGA_LIB_ERR,
	UCFGA_OK,
	UCFGA_BUSY,
	UCFGA_NO_REC
} ucfga_ret_t;



/* Messages */

typedef struct {
	int		intl;		/* Flag: if 1, internationalize */
	cfga_err_t	cfga_err;	/* Error code libcfgadm understands */
	const char	*msgstr;
} msgcvt_t;
#define	NO_CVT			0
#define	CVT			1

#define	MSG_TBL_SZ(table)	(sizeof ((table)) / sizeof (msgcvt_t))


/* Error message ids (and indices into usb_error_msgs) */
typedef enum {

	CFGA_USB_OK = 0,
	CFGA_USB_UNKNOWN,
	CFGA_USB_INTERNAL_ERROR,
	CFGA_USB_OPTIONS,
	CFGA_USB_DYNAMIC_AP,
	CFGA_USB_AP,
	CFGA_USB_PORT,
	CFGA_USB_DEVCTL,
	CFGA_USB_NOT_CONNECTED,
	CFGA_USB_NOT_CONFIGURED,
	CFGA_USB_ALREADY_CONNECTED,
	CFGA_USB_ALREADY_CONFIGURED,
	CFGA_USB_OPEN,
	CFGA_USB_IOCTL,
	CFGA_USB_BUSY,
	CFGA_USB_ALLOC_FAIL,
	CFGA_USB_OPNOTSUPP,
	CFGA_USB_DEVLINK,
	CFGA_USB_STATE,
	CFGA_USB_CONFIG_INVAL,
	CFGA_USB_PRIV,
	CFGA_USB_NVLIST,
	CFGA_USB_ZEROLEN,
	CFGA_USB_CONFIG_FILE,
	CFGA_USB_LOCK_FILE,
	CFGA_USB_UNLOCK_FILE,
	CFGA_USB_ONE_CONFIG,

	/* RCM Errors */
	CFGA_USB_RCM_HANDLE,
	CFGA_USB_RCM_ONLINE,
	CFGA_USB_RCM_OFFLINE,
	CFGA_USB_RCM_INFO

} cfga_usb_ret_t;


/*
 * Given an error msg index, look up the associated string, and
 * convert it to the current locale if required.
 */
#define	ERR_STR(msg_idx) \
		(get_msg((msg_idx), usb_error_msgs, MSG_TBL_SZ(usb_error_msgs)))


/* Misc text strings */
#define	CFGA_DEV_DIR			"/dev/cfg"
#define	DYN_SEP				"::"
#define	MINOR_SEP			":"
#define	PORT				"port"
#define	PORT_SEPERATOR			"."
#define	USB				"usb"
#define	USB_CFGADM_DEFAULT_AP_TYPE	"unknown"

/* these set of defines are -lav listing */
#define	USB_UNDEF_STR			"<undef>"
#define	USB_NO_CFG_STR			"<no cfg str descr>"

/* -x commands */
#define	RESET_DEVICE			"usb_reset"	/* with -x option */
#define	USB_CONFIG			"usb_config"	/* with -x option */
#define	SET_CONFIG			"config="	/* with -o option */
#define	SET_DRIVER			"drv="		/* with -op option */

/* for confirm operation */
#define	USB_CONFIRM_0	"the device: "
#define	USB_CONFIRM_1 \
	"This operation will suspend activity on the USB device\nContinue"

/* Prototypes */
extern int		add_entry(char *, int, int, int, char *, char *, char *,
			    char **);
extern cfga_usb_ret_t	do_control_ioctl(const char *, uint_t, uint_t,
			    void **, size_t *);


#ifdef __cplusplus
}
#endif

#endif /* _CFGA_USB_H */
