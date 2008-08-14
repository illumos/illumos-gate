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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MMS_CORES_H
#define	_MMS_CORES_H


#ifdef	__cplusplus
extern "C" {
#endif

#define	MMS_CORES_DIR "/var/mms/cores"
#define	MMS_CORE_AMT 10

extern int	mms_set_core(char *dir, char *proc);
extern int	mms_man_cores(char *dir, char *proc);

typedef struct corestat {
	char	*name;
	int	time;
} corestat_t;

/*
 * mms_trace location define
 */
#define	MMS_HERE _SrcFile, __LINE__

#ifdef	__cplusplus
}
#endif

#endif	/* _MMS_CORES_H */
