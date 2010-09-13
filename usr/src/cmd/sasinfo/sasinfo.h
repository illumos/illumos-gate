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

#ifndef _SASINFO_H
#define	_SASINFO_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <smhbaapi.h>
#include <sys/types.h>
#include <sys/scsi/scsi.h>
#include <inttypes.h>
#include <cmdparse.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <locale.h>

#ifdef _BIG_ENDIAN
#define	htonll(x)   (x)
#define	ntohll(x)   (x)
#else
#define	htonll(x)   ((((unsigned long long)htonl(x)) << 32) + htonl(x >> 32))
#define	ntohll(x)   ((((unsigned long long)ntohl(x)) << 32) + ntohl(x >> 32))
#endif

/* DEFINES */
#define	DEFAULT_LUN_COUNT	1024
#define	LUN_SIZE		8
#define	LUN_HEADER_SIZE		8
#define	LUN_LENGTH		LUN_SIZE + LUN_HEADER_SIZE
#define	DEFAULT_LUN_LENGTH	DEFAULT_LUN_COUNT  * \
				LUN_SIZE	   + \
				LUN_HEADER_SIZE

/* flags that are needed to be passed into porcessHBA */
#define	PRINT_VERBOSE		0x00000001
#define	PRINT_PHY		0x00000002 /* print phy addresses */
#define	PRINT_PHY_LINKSTAT	0x00000004 /* print phy link statistics */
#define	PRINT_TARGET_PORT	0x00000008 /* print target os deivce info */
#define	PRINT_CHILD		0x00000010 /* print descendant nodes */
#define	PRINT_TARGET_SCSI	0x00000020 /* print descendant nodes */

#define	HBA_MAX_RETRIES		20

typedef struct _tgtPortWWNList {
	HBA_WWN portWWN;
	HBA_UINT32	scsiOSLun;
	struct _tgtPortWWNList *next;
} tgtPortWWNList;

typedef struct _portList {
	char		portName[MAXPATHLEN];
	tgtPortWWNList	*tgtPortWWN;
	struct _portList	*next;
} portList;

/* Discovered LU structure */
typedef struct _discoveredDevice {
	boolean_t	inquiryFailed;
	char 		OSDeviceName[MAXPATHLEN];
	portList	*HBAPortList;
	char		VID[8];
	char		PID[16];
	uchar_t		dType;
	struct _discoveredDevice *next;
} discoveredDevice;

typedef struct targetPortMappingData {
	boolean_t	mappingExist;
	boolean_t	inquiryFailed;
	HBA_UINT32	osLUN;
	SMHBA_SCSILUN	reportLUN;
	char		osDeviceName[256];
	uchar_t		inq_vid[8];
	uchar_t		inq_pid[16];
	uchar_t		inq_dtype;
	struct targetPortMappingData   *next;
} targetPortMappingData_t;

typedef struct targetPortConfig {
	char 		hbaPortName[256];
	HBA_WWN		expanderSASAddr;
	int 		expanderValid;
	boolean_t   	reportLUNsFailed;
	struct 		targetPortMappingData    *map;
	struct 		targetPortConfig    *next;
} targetPortConfig_t;

typedef struct targetPortList {
	SMHBA_PORTATTRIBUTES	targetattr;
	SMHBA_SAS_PORT		sasattr;
	struct targetPortConfig *configEntry;
	struct targetPortList	*next;
} targetPortList_t;

int sas_util_list_hba(int hbaCount, char **hba_argv, cmdOptions_t *options);
int sas_util_list_hbaport(int wwnCount, char **wwn_argv, cmdOptions_t *options);
int sas_util_list_expander(int wwnCount, char **wwn_argv,
    cmdOptions_t *options);
int sas_util_list_targetport(int tpCount, char **tpArgv, cmdOptions_t *options);
int sas_util_list_remoteport(int wwnCount, char **wwn_argv,
    cmdOptions_t *options);
int
sas_util_list_logicalunit(int luCount, char **luArgv, cmdOptions_t *options);

#ifdef	__cplusplus
}
#endif

#endif /* _SASINFO_H */
