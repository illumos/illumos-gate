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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MDESCPLUGIN_H
#define	_MDESCPLUGIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <picl.h>
#include <picltree.h>
#include <picldefs.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <alloca.h>
#include <sys/stat.h>
#include <malloc.h>
#include <fcntl.h>
#include <syslog.h>
#include <mdesc.h>
#include <string.h>
#include <errno.h>
#include <libnvpair.h>
#include <syslog.h>
#include <sys/stat.h>
#include <dirent.h>
#include <config_admin.h>
#include <sys/param.h>
#include <libdevinfo.h>
#include <sys/systeminfo.h>
#include <sys/sysevent/dr.h>

#define	MAXSTRLEN 256
#define	ICACHE_FLAG 0x01
#define	DCACHE_FLAG 0x02
#define	CACHE_FLAG 0x03
#define	DISK_DISCOVERY_NAME "disk_discovery"
#define	CONFIGURED "configured"
#define	UNCONFIGURED "unconfigured"
#define	DEV_ADD		0
#define	DEV_REMOVE	1
#define	SUN4V_CPU_REGSIZE	4
#define	CFGHDL_TO_CPUID(x)	(x  & ~(0xful << 28))

#ifdef __cplusplus
}
#endif

#endif	/* _MDESCPLUGIN_H */
