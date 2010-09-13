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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _CLASS_CACHE_H
#define	_CLASS_CACHE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <jni.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
	DCR_CLASS, DTR_CLASS, NET_CLASS, MAC_CLASS, OPT_CLASS, DS_CLASS,
	CFG_CLASS, RES_CLASS, IP_CLASS,	IPIF_CLASS
} CC_CLASSMAP_ID;
#define	CC_CLASSMAP_NUM		IPIF_CLASS + 1

typedef enum {
	DCR_CONS, DCR_GETCID, DCR_GETFLAG, DCR_GETCIP, DCR_GETSIP, DCR_GETEXP,
	DCR_GETSIG, DCR_GETMAC, DCR_GETCMT, DTR_GETKEY, DTR_GETFLAG,
	DTR_GETSIG, DTR_GETVAL, NET_CONS, MAC_CONS, OPT_CONS, DS_CONS,
	DS_GETRSRC, DS_GETLOC, DS_GETRSRCCFG, DS_GETVER, CFG_CONS, CFG_SET,
	CFG_GETALL, RES_GETKEY, RES_GETVAL, RES_ISCOM, IP_CONS, IPIF_CONS
} CC_METHODMAP_ID;
#define	CC_METHODMAP_NUM	IPIF_CONS + 1

extern void init_class_cache(void);
extern jclass find_class(JNIEnv *, CC_CLASSMAP_ID);
extern jmethodID get_methodID(JNIEnv *, jclass, CC_METHODMAP_ID);

#ifdef	__cplusplus
}
#endif

#endif	/* !_CLASS_CACHE_H */
