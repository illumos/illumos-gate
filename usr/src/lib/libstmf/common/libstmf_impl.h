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

#ifndef	_LIBSTMF_IMPL_H
#define	_LIBSTMF_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <libstmf.h>

typedef struct _luResourceImpl {
	uint16_t type;
	void *resource;
} luResourceImpl;


typedef struct _diskResource {
	boolean_t   luDataFileNameValid;
	char	    luDataFileName[MAXPATHLEN];
	boolean_t   luMetaFileNameValid;
	char	    luMetaFileName[MAXPATHLEN];
	boolean_t   luSizeValid;
	uint64_t    luSize;
	boolean_t   blkSizeValid;
	uint16_t    blkSize;
	boolean_t   luGuidValid;
	uint8_t	    luGuid[16];
	boolean_t   serialNumValid;
	char	    serialNum[253];
	boolean_t   companyIdValid;
	uint32_t    companyId;
	boolean_t   luAliasValid;
	char	    luAlias[256];
	boolean_t   luMgmtUrlValid;
	char	    luMgmtUrl[1024];
	boolean_t   vidValid;
	char	    vid[8];
	boolean_t   pidValid;
	char	    pid[16];
	boolean_t   revValid;
	char	    rev[4];
	boolean_t   writeProtectEnableValid;
	boolean_t   writeProtectEnable;
	boolean_t   writebackCacheDisableValid;
	boolean_t   writebackCacheDisable;
	uint16_t    accessState;
	uint32_t    hostId;
	boolean_t   hostIdValid;
} diskResource;


#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSTMF_IMPL_H */
