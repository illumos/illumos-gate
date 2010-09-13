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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MD_MONITORD_H
#define	_MD_MONITORD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	_REENTRANT
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <limits.h>
#include <locale.h>
#include <signal.h>
#include <strings.h>
#include <syslog.h>
#include <thread.h>
#include <unistd.h>
	/* #include <sys/types.h> */
#include <sys/stat.h>
	/* #include <sys/fcntl.h> */
#include <meta.h>
#include <sys/lvm/md_mddb.h>
#include <sys/lvm/md_notify.h>

#define	MD_FF_Q	"md_failfast_queue_01"
#define	MD_FF_TAG	1
#define	INTMAP(n)	{n, #n}
#define	CCNULL		((const char *)0)

enum boolean { True, False };
typedef enum boolean boolean_e;

typedef struct intmap {
	int	im_int;
	const char	*im_name;
} intmap_t;

extern boolean_e issue_ioctl;
extern mdsetname_t	*sp;
void monitord_exit(int status);
void monitord_print(int level, char *message, ...);
void probe_mirror_devs(boolean_e verbose);
void probe_raid_devs(boolean_e verbose);
void probe_trans_devs(boolean_e verbose);
void probe_hotspare_devs(boolean_e verbose);
#ifdef	__cplusplus
}
#endif

#endif	/* _MD_MONITORD_H */
