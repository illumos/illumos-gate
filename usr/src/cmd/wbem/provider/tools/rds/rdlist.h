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

#ifndef	_RDLIST_H
#define	_RDLIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/processor.h>
#include <sys/types.h>

#include "rdimpl.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <strings.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include "rdimpl.h"
#include "rdprot.h"
#include "rdutil.h"

#define	LTDB_TIMESTAMP "TIMESTAMP"
#define	LTDB_DECAYTIME 3600
/* The current DB file version */
#define	LTDB_VERSION_KEY  "VERSION"
#define	LTDB_VERSION	100

#ifdef	__cplusplus
extern "C" {
#endif

extern void list_print(list_t *list, int xid);
extern int list_write(int listt, int Po);
extern int list_store();
extern int list_restore();

extern list_t   users;		/* list of users */
extern list_t   projects;	/* list of projects */
extern list_t   processes;	/* list of processes */
extern list_t   lwps;
extern char 	errmsg[];
extern void	prtelement(FILE *fp, id_info_t *id);
extern lwp_info_t *
	list_add_lwp(list_t *list, pid_t pid, id_t lwpid);
extern void 	err_exit();
extern sys_info_t sys_info;

#ifdef	__cplusplus
}
#endif

#endif	/* _RDLIST_H */
