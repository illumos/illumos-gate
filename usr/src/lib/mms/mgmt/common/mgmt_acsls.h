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
#ifndef _MMS_MGMT_ACSLS_H
#define	_MMS_MGMT_ACSLS_H


#include <stdio.h>
#include <sys/nvpair.h>

#include "mms.h"
#include "mgmt_util.h"
#include "acssys.h"
#include "acsapi.h"

/*
 * Comunication with the library and media that are controlled by the STK ACSLS
 * software is done via the ACSAPI interface. ACSAPI procedures communicate via
 * IPC with the SSI process running on the client machine. Each client can send
 * multiple requests to the ACS Library Manager via this SSI. The SSI receives
 * requests from one or more clients, places them on a queue, and sends these
 * requests to the CSI to relay them to the ACS Library Manager. Multiple
 * heterogeneous clients can communicate and manage the ACSLS Library via the
 * same SSI. The SSI also relays the responses back to the appropriate client
 * application. The CSI and SSI talk to each other via RPC. The same RPC program
 * number is used for all instances of SSI and CSI connections. So there is a
 * limitation that a client cannot connect to multiple ACSLS.
 *
 * The client code has to be compiled with the ACS header files and linked with
 * -lapi
 */

/*
 * ----------------------------------------------------------------------------
 * STK ACSLS PROCESS COMMUNICATION
 * ----------------------------------------------------------------------------
 */

/*
 * acs_start_ssi()
 *
 * Parameters:
 *	- acs_host	host:port on which the ACSLS software is installed
 *	- ssiport	optional, specify the local port for the SSI daemon
 *			to listen on for requests.
 *
 * This function starts the STK ACSLS daemon (ssi) to communicate remotely with
 * the ACSLS software that is controlling the library and media
 */
int acs_start_ssi(char *acs_host, char *ssiport);

/*
 * ----------------------------------------------------------------------------
 * STK ACSLS DISPLAY CONFIGURATION AND STATUS
 * ----------------------------------------------------------------------------
 */
typedef enum {
	ACS_DISPLAY_CAP			= 0,
	ACS_DISPLAY_CELL		= 1,
	ACS_DISPLAY_DRIVE		= 2,
	ACS_DISPLAY_LOCK		= 3,
	ACS_DISPLAY_LSM			= 4,
	ACS_DISPLAY_PANEL		= 5,
	ACS_DISPLAY_POOL		= 6,
	ACS_DISPLAY_VOL			= 7,
	ACS_DISPLAY_VOL_BY_MEDIA	= 8,
	ACS_DISPLAY_VOL_CLEANING	= 9,
	ACS_DISPLAY_VOL_ACCESSED	= 10,
	ACS_DISPLAY_VOL_ENTERED		= 11,
	ACS_DISPLAY_UNSUPPORTED		= 12
} acs_query_type_t;

#define	ACS_XMLREQ_CAP		"<request type='DISPLAY'><display>" \
	"<token>display</token><token>cap</token><token>%s</token>" \
	"<token>-f</token><token>acs</token><token>lsm</token>" \
	"<token>cap</token>" \
	"</display></request>"

#define	ACS_XMLREQ_CELL		"<request type='DISPLAY'><display>" \
	"<token>display</token><token>cell</token><token>%s</token>" \
	"<token>-f</token><token>status</token>" \
	"</display></request>"

#define	ACS_XMLREQ_DRIVE	"<request type='DISPLAY'><display>" \
	"<token>display</token><token>drive</token><token>%s</token>" \
	"<token>-f</token><token>status</token><token>state</token>" \
	"<token>volume</token><token>type</token><token>lock</token>" \
	"<token>serial_num</token><token>condition</token>" \
	"</display></request>"

#define	ACS_XMLREQ_LOCK		"<request type='DISPLAY'><display>" \
	"<token>display</token><token>lock</token><token>%s</token>" \
	"</display></request>"

#define	ACS_XMLREQ_LSM		"<request type='DISPLAY'><display>" \
	"<token>display</token><token>lsm</token><token>%s</token>" \
	"<token>-f</token><token>status</token><token>state</token>" \
	"<token>serial_num</token><token>type</token>" \
	"</display></request>"

#define	ACS_XMLREQ_PANEL	"<request type='DISPLAY'><display>" \
	"<token>display</token><token>panel</token><token>%s</token>" \
	"</display></request>"

#define	ACS_XMLREQ_POOL		"<request type='DISPLAY'><display>" \
	"<token>display</token><token>pool</token><token>%s</token>" \
	"</display></request>"

#define	ACS_XMLREQ_VOL		"<request type='DISPLAY'><display>" \
	"<token>display</token><token>volume</token><token>%s</token>" \
	"<token>-f</token><token>vol_id</token><token>acs</token>" \
	"<token>lsm</token><token>drive</token><token>type</token>" \
	"<token>media</token><token>status</token><token>access_date</token>" \
	"</display></request>"

#define	ACS_XMLREQ_VOL_BY_MEDIA	"<request type='DISPLAY'><display>" \
	"<token>display</token><token>volume</token><token>*</token>" \
	"<token>-media</token><token>%s</token>" \
	"</display></request>"

#define	ACS_XMLREQ_VOL_CLEANING	"<request type='DISPLAY'><display>" \
	"<token>display</token><token>volume</token><token>%s</token>" \
	"<token>-clean</token>" \
	"</display></request>"

#define	ACS_XMLREQ_VOL_ACCESSED	"<request type='DISPLAY'><display>" \
	"<token>display</token><token>volume</token><token>*</token>" \
	"<token>-access</token><token>%s</token>" \
	"</display></request>"

#define	ACS_XMLREQ_VOL_ENTERED	"<request type='DISPLAY'><display>" \
	"<token>display</token><token>volume</token><token>*</token>" \
	"<token>-entry</token><token>%s</token>" \
	"</display></request>"

typedef struct acs_query_cmdresp_s {
	int query_type;
	char *xmlreq;
	int (*parse_resp)(void *, mms_list_t *);
} acs_query_cmdresp_t;


typedef struct acs_param {
	char	hostname[MAXHOSTNAMELEN];
	int32_t	port;
	char	user[MAXNAMELEN];
	char	ssi_hostname[MAXHOSTNAMELEN];
	int32_t	ssi_port;
	char	csi_hostname[MAXHOSTNAMELEN];
	int32_t	csi_port;
	int32_t	id;	/* acs number */
} acs_param_t;

int
get_acs_library_cfg(char *acshost, boolean_t get_drives, mms_list_t *lib_list);

int
get_acs_volumes(char *acshost, char *in_vols, mms_list_t *vol_list);

#endif	/* _MMS_MGMT_ACSLS_H */
