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

#ifndef	_PRINTATTRS_H
#define	_PRINTATTRS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sasinfo.h>

typedef enum {
	PHY_STATE,
	PHY_SPEED
} phystat_type;

typedef struct state_string {
	int	key;
	char	*value;
} SAS_STATE;

extern SAS_STATE porttype_string[];
extern SAS_STATE portstate_string[];

#define	MAXINDENT	64

char *getHBAStatus(HBA_STATUS hbaStatus);
uint64_t wwnConversion(uchar_t *wwn);
void printHBAInfo(SMHBA_ADAPTERATTRIBUTES *attrs, int pflag, int numberOfPorts,
    const char *adapterName);
void printHBAPortInfo(SMHBA_PORTATTRIBUTES *port,
    SMHBA_ADAPTERATTRIBUTES *attrs, int pflag);
void printHBAPortPhyInfo(SMHBA_SAS_PHY *phyinfo);
void printHBAPortPhyStatistics(SMHBA_SASPHYSTATISTICS *phystat);
extern void
printLogicalUnit(int pflag, SMHBA_TARGETMAPPING *map);
extern int
printOSDeviceNameInfo(discoveredDevice *devListWalk, boolean_t verbose);
extern int
printTargetPortInfo(targetPortList_t *TPListWalk, int pflag);
extern char *getStateString(HBA_UINT32 key, SAS_STATE *stat_string);
extern char *getIndentSpaces(int number);
extern char *getDTypeString(uchar_t dType);

#ifdef __cplusplus
}
#endif

#endif /* _PRINTATTRS_H */
