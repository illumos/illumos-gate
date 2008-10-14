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

#ifndef _FCINFO_H
#define	_FCINFO_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <hbaapi.h>
#include <hbaapi-sun.h>
#include <unistd.h>
#include <sys/scsi/scsi.h>
#include <sys/fibre-channel/fcio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <cmdparse.h>

#ifdef _BIG_ENDIAN
#define	htonll(x)   (x)
#define	ntohll(x)   (x)
#else
#define	htonll(x)   ((((unsigned long long)htonl(x)) << 32) + htonl(x >> 32))
#define	ntohll(x)   ((((unsigned long long)ntohl(x)) << 32) + ntohl(x >> 32))
#endif

/* DEFINES */

/* SCSI TARGET TYPES */
#define	SCSI_TARGET_TYPE_UNKNOWN    0
#define	SCSI_TARGET_TYPE_NO	    1
#define	SCSI_TARGET_TYPE_YES	    2

#define	DEFAULT_LUN_COUNT	    1024
#define	LUN_SIZE		    8
#define	LUN_HEADER_SIZE		    8
#define	LUN_LENGTH		    LUN_SIZE + LUN_HEADER_SIZE
#define	DEFAULT_LUN_LENGTH	    DEFAULT_LUN_COUNT	* \
				    LUN_SIZE		+ \
				    LUN_HEADER_SIZE

#define	HBA_MAX_RETRIES		20
#define	PORT_LIST_ALLOC		100
#define	NPIV_PORT_LIST_LENGTH	255

#define	NPIV_ADD		0
#define	NPIV_REMOVE		1

#define	NPIV_SUCCESS			0
#define	NPIV_ERROR			1
#define	NPIV_ERROR_NOT_FOUND		2
#define	NPIV_ERROR_EXISTS		3
#define	NPIV_ERROR_SERVICE_NOT_FOUND	4
#define	NPIV_ERROR_NOMEM		5
#define	NPIV_ERROR_MEMBER_NOT_FOUND	6
#define	NPIV_ERROR_BUSY			7

#define	NPIV_SERVICE	"network/npiv_config"
#define	NPIV_PG_NAME	"npiv-port-list"
#define	NPIV_PORT_LIST	"port_list"

/* flags that are needed to be passed into processHBA */
#define	PRINT_LINKSTAT	    0x00000001	/* print link statistics information */
#define	PRINT_SCSI_TARGET   0x00000010	/* print Scsi target information */
#define	PRINT_INITIATOR	    0x00000100	/* print intiator port information */
#define	PRINT_TARGET	    0x00001000	/* print target port information */

/* flags for Adpater/port mode */
#define	INITIATOR_MODE	    0x00000001
#define	TARGET_MODE	    0x00000010

typedef struct _tgtPortWWNList {
	HBA_WWN portWWN;
	HBA_UINT32	scsiOSLun;
	struct _tgtPortWWNList *next;
} tgtPortWWNList;

typedef struct _portWWNList {
	HBA_WWN	portWWN;
	tgtPortWWNList *tgtPortWWN;
	struct _portWWNList *next;
} portWWNList;

/* Discovered ports structure */
typedef struct _discoveredDevice {
	char	OSDeviceName[MAXPATHLEN];
	portWWNList *HBAPortWWN;
	char    VID[8];
	char    PID[16];
	boolean_t   inqSuccess;
	uchar_t	dType;
	struct  _discoveredDevice *next;
} discoveredDevice;

/* globals */
static char *cmdName;

/* print helper functions */
void printHBAPortInfo(HBA_PORTATTRIBUTES *port,
    HBA_ADAPTERATTRIBUTES *attrs, int mode);
void printDiscoPortInfo(HBA_PORTATTRIBUTES *discoPort, int scsiTargetType);
void printLUNInfo(struct scsi_inquiry *inq, HBA_UINT32 scsiLUN, char *devpath);
void printPortStat(fc_rls_acc_t *rls_payload);
void printScsiTarget(HBA_WWN);
void printStatus(HBA_STATUS status);
void printOSDeviceNameInfo(discoveredDevice *devListWalk, boolean_t verbose);
uint64_t wwnConversion(uchar_t *wwn);

int fc_util_list_hbaport(int wwnCount, char **wwn_argv, cmdOptions_t *options);
int fc_util_list_remoteport(int wwnCount, char **argv, cmdOptions_t *options);
int fc_util_list_logicalunit(int pathCount, char **argv, cmdOptions_t *options);
int fc_util_delete_npivport(int wwnCount, char **argv, cmdOptions_t *options);
int fc_util_create_npivport(int wwnCount, char **argv, cmdOptions_t *options);
int fc_util_create_portlist();

#ifdef	__cplusplus
}
#endif

#endif /* _FCINFO_H */
