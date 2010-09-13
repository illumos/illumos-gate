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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PRIPLUGIN_H
#define	_PRIPLUGIN_H

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
#include <thread.h>
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
#include <syslog.h>
#include <stdarg.h>

#ifndef PRI_DEBUG
#define	PRI_DEBUG 0
#endif

int add_mem_prop(picl_nodehdl_t node, void *args);
int pri_devinit(uint64_t *);
md_t *pri_bufinit(md_t *mdp);
void pri_devfini(md_t *mdp);
void pri_debug(int level, char *fmt, ...);
void add_md_prop(picl_nodehdl_t node, int size, char *name, void* value,
	int type);
void io_dev_addlabel(md_t *mdp);

#ifdef __cplusplus
}
#endif

#endif	/* _PRIPLUGIN_H */
