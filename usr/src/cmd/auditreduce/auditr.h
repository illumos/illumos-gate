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

#ifndef _AUDITR_H
#define	_AUDITR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stdio.h>
#include <sys/types.h>

#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <string.h>
#include <values.h>

#include <dirent.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <tzfile.h>
#include <sys/resource.h>
#include <netdb.h>
#include <unistd.h>
#include <libgen.h>
#include <stdlib.h>
#include <libscf_priv.h>

#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/libbsm.h>

#include <tsol/label.h>

#include "auditrt.h"

/*
 * Flags for on/off code.
 * The release setting would be 0 0 0 1.
 */
#define	AUDIT_PROC_TRACE	0	/* process trace code */
#define	AUDIT_FILE		0	/* file trace code (use -V also) */
#define	AUDIT_REC		0	/* record trace code (very verbose) */
#define	AUDIT_RENAME		1	/* rename output file w/time stamps */

#define	TRUE	1
#define	FALSE	0

#define	FM_ALLDIR	1	/* f_mode in o.c - all dirs in this dir */
#define	FM_ALLFILE	0	/* f_mode in o.c - all audit files in dir */

#define	MAXFILELEN	(MAXPATHLEN+MAXNAMLEN+1)

/*
 * Initial size of a record buffer.
 * Never smaller than (2 * sizeof (short)).
 * If a buffer is too small for the record being read then the
 * current buffer is freed and a large-enough one is allocated.
 */
#define	AUDITBUFSIZE	512	/* size of default record buffer */

/*
 * Controls size of audit_pcbs[] array.
 * INITSIZE is the initial allocation for the array.
 * INC is the growth jump when the array becomes too small.
 */
#define	PCB_INITSIZE	100
#define	PCB_INC		50


/*
 * Memory allocation functions.
 * audit calloc that checks for NULL return
 */
extern void	*a_calloc(int, size_t);

/*
 * Statistical reporting for error conditions.
 */
extern void	audit_stats(void);
extern int	errno;

#ifdef	__cplusplus
}
#endif

#endif /* _AUDITR_H */
