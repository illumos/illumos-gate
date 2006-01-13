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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _CFGA_SATA_H
#define	_CFGA_SATA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#include <sys/sata/sata_cfgadm.h>

#include <libdevinfo.h>
#include <libdevice.h>
#include <librcm.h>
#include <synch.h>
#include <thread.h>
#include <assert.h>

#define	CFGA_PLUGIN_LIB
#include <config_admin.h>

/*
 * Debug stuff
 */
#ifdef	DEBUG
#define	DPRINTF printf
#else
#define	DPRINTF 0 &&
#endif /* DEBUG */

typedef enum {
	CFGA_SATA_TERMINATE = 0,
	CFGA_SATA_CONTINUE
} sata_cfga_recur_t;

/* for walking links */
typedef struct walk_link {
	char *path;
	char len;
	char **linkpp;
} walk_link_t;

#define	MATCH_MINOR_NAME	1

/* Misc text strings */
#define	CFGA_DEV_DIR			"/dev/cfg"
#define	MINOR_SEP 			":"
#define	DYN_SEP				"::"
#define	PORT				"port"
#define	PORT_SEPARATOR			"."
#define	SATA				"sata"
#define	CFGA_DEVCTL_NODE  		":devctl"
#define	SATA_CFGADM_DEFAULT_AP_TYPE	"unknown"
#define	SLICE				"s"
#define	PARTITION			"p"
#define	PATH_SEP 			"/"

/* these set of defines are -lav listing */
#define	SATA_UNDEF_STR			"<undef>"
#define	SATA_NO_CFG_STR			"<no cfg str descr>"

/* -x commands */
#define	SATA_RESET_ALL			"sata_reset_all"
#define	SATA_RESET_PORT			"sata_reset_port"
#define	SATA_RESET_DEVICE		"sata_reset_device"
#define	SATA_PORT_DEACTIVATE		"sata_port_deactivate"
#define	SATA_PORT_ACTIVATE		"sata_port_activate"
#define	SATA_PORT_SELF_TEST		"sata_port_self_test"

/* -t command */
#define	SATA_CNTRL_SELF_TEST		"sata_cntrl_self_test"

/* for confirm operation */
#define	SATA_CONFIRM_DEVICE	"the device at: "
#define	SATA_CONFIRM_DEVICE_SUSPEND \
	"This operation will suspend activity on the SATA device\nContinue"
#define	SATA_CONFIRM_DEVICE_ABORT \
	"This operation will arbitrarily abort all commands " \
	"on SATA device\nContinue"
#define	SATA_CONFIRM_CONTROLLER  "the controller: "
#define	SATA_CONFIRM_CONTROLLER_ABORT \
	"This operation will arbitrarirly abort all commands " \
	"on the SATA controller\nContinue"
#define	SATA_CONFIRM_PORT	"the port: "
#define	SATA_CONFIRM_PORT_DISABLE \
	"This operation will disable activity on the SATA port\nContinue"
#define	SATA_CONFIRM_PORT_ENABLE \
	"This operation will enable activity on the SATA port\nContinue"

#define	S_FREE(x)		(((x) != NULL) ? \
				(free(x), (x) = NULL) : (void *)0)

#define	GET_DYN(a)		(((a) != NULL) ? \
				strstr((a), DYN_SEP) : (void *)0)

typedef struct sata_apid {
	char		*hba_phys;
	char		*dyncomp;
	char		*path;
	uint_t		flags;
} sata_apid_t;


/* Messages */

typedef struct msgcvt {
	int		intl;		/* Flag: if 1, internationalize */
	cfga_err_t	cfga_err;	/* Error code libcfgadm understands */
	const char	*msgstr;
} msgcvt_t;

#define	NO_CVT	0
#define	CVT	1

#define	MSG_TBL_SZ(table)	(sizeof ((table)) / sizeof (msgcvt_t))

typedef enum {
	SATA_CFGA_ERR = -2,
	SATA_CFGA_LIB_ERR,
	SATA_CFGA_OK,
	SATA_CFGA_BUSY,
	SATA_CFGA_NO_REC
} sata_cfga_ret_t;

/* Messages */


/* Error message ids (and indices into sata_error_msgs) */
typedef enum {
	CFGA_SATA_OK = 0,
	CFGA_SATA_NACK,
	CFGA_SATA_DEVICE_UNCONFIGURED,
	CFGA_SATA_UNKNOWN,
	CFGA_SATA_INTERNAL_ERROR,
	CFGA_SATA_DATA_ERROR,
	CFGA_SATA_OPTIONS,
	CFGA_SATA_HWOPNOTSUPP,
	CFGA_SATA_DYNAMIC_AP,
	CFGA_SATA_AP,
	CFGA_SATA_PORT,
	CFGA_SATA_DEVCTL,
	CFGA_SATA_DEV_CONFIGURE,
	CFGA_SATA_DEV_UNCONFIGURE,
	CFGA_SATA_DISCONNECTED,
	CFGA_SATA_NOT_CONNECTED,
	CFGA_SATA_NOT_CONFIGURED,
	CFGA_SATA_ALREADY_CONNECTED,
	CFGA_SATA_ALREADY_CONFIGURED,
	CFGA_SATA_INVALID_DEVNAME,
	CFGA_SATA_OPEN,
	CFGA_SATA_IOCTL,
	CFGA_SATA_BUSY,
	CFGA_SATA_ALLOC_FAIL,
	CFGA_SATA_OPNOTSUPP,
	CFGA_SATA_DEVLINK,
	CFGA_SATA_STATE,
	CFGA_SATA_PRIV,
	CFGA_SATA_NVLIST,
	CFGA_SATA_ZEROLEN,

	/* RCM Errors */
	CFGA_SATA_RCM_HANDLE,
	CFGA_SATA_RCM_ONLINE,
	CFGA_SATA_RCM_OFFLINE,
	CFGA_SATA_RCM_INFO

} cfga_sata_ret_t;

/*
 * Given an error msg index, look up the associated string, and
 * convert it to the current locale if required.
 */
#define	ERR_STR(msg_idx) \
	(get_msg((msg_idx), sata_msgs, MSG_TBL_SZ(sata_msgs)))

/* Prototypes */

cfga_err_t	sata_err_msg(char **, cfga_sata_ret_t, const char *, int);
cfga_sata_ret_t	sata_rcm_offline(const char *, char **, char *, cfga_flags_t);
cfga_sata_ret_t sata_rcm_online(const char *, char **, char *, cfga_flags_t);
cfga_sata_ret_t sata_rcm_remove(const char *, char **, char *, cfga_flags_t);


#ifdef __cplusplus
}
#endif

#endif	/* _CFGA_SATA_H */
