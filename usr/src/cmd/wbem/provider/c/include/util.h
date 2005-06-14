/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_UTIL_H
#define	_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <netdb.h>
#include <cimapi.h>
#include <cimomhandle.h>
#include <cimprovider.h>
#include <cimauthcheck.h>
#include <cimlogsvc.h>

#include "providerNames.h"
#include "messageStrings.h"

#define	MAXFAILSTRINGLEN	256

void 	util_handleError(char *, CIMErrorReason, char *, CCIMException *,
	    int *);
void	*util_getKeyValue(CCIMPropertyList *, CIMType, char *, int *);
void	util_doReferenceProperty(cimchar *, CCIMObjectPath *, CIMBool,
	    CCIMInstance *, int *);
void	util_doProperty(cimchar *, CIMType, cimchar *, CIMBool,
	    CCIMInstance *, int *);
FILE 	*util_openFile(char *, char *);
int	util_closeFile(FILE *, char *);
void	util_removeFile(char *);
char	*util_routineFailureMessage(char *);
char	*util_routineStartDaemonMessage(char *);

char	hostName[MAXHOSTNAMELEN];

#define	DISK_DOMAIN	"libWBEMdisk"
#define	DISK_PROVIDER	"libWBEMdisk"

#ifdef	__cplusplus
}
#endif

#endif	/* _UTIL_H */
