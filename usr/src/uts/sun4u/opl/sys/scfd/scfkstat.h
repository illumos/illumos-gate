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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#ifndef _SCFKSTAT_H
#define	_SCFKSTAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * kstat_create(9F) ID parameter
 *	 module = "scfd"
 *	 class = "misc"
 */
/* name = "??" */
#define	SCF_SYSTEM_KSTAT_NAME		"scf"

/*
 * kstat_named_init(9F) ID parameter
 */
/* name == "scf" */
#define	SCF_STATUS_KSTAT_NAMED		"status"
#define	SCF_BOOT_MODE_KSTAT_NAMED	"boot_mode"
#define	SCF_SECURE_MODE_KSTAT_NAMED	"secure_mode"
#define	SCF_EVENT_KSTAT_NAMED		"event"
#define	SCF_ALIVE_KSTAT_NAMED		"alive"

/*
 * "scf" KSTAT_TYPE_NAMED item
 */
/* named == "status" */
#define	SCF_STAT_STATUS_OFFLINE	0
#define	SCF_STAT_STATUS_ONLINE	1

/* named == "boot_mode" */
#define	SCF_STAT_MODE_OBP_STOP	0
#define	SCF_STAT_MODE_AUTO_BOOT	1

/* named == "secure_mode" */
#define	SCF_STAT_MODE_UNLOCK	0
#define	SCF_STAT_MODE_LOCK	1

/* named == "watch" */
#define	SCF_STAT_ALIVE_OFF	0
#define	SCF_STAT_ALIVE_ON	1


/*
 * SCF driver kstat entry point
 */
/* from scf_attach() */
void	scf_kstat_init();		/* DDI_ATTACH */

/* from scf_detach() */
void	scf_kstat_fini();		/* DDI_DETACH */

/*
 * private variables for kstat routine
 */
typedef struct scf_kstat_private {
	/* kstat_t */
	kstat_t		*ksp_scf;
} scf_kstat_private_t;

/* "scf" */
#define	SCF_KSTAT_SYS_NAMED_STATUS	0
#define	SCF_KSTAT_SYS_NAMED_BOOT_MODE	1
#define	SCF_KSTAT_SYS_NAMED_SECURE_MODE	2
#define	SCF_KSTAT_SYS_NAMED_EVENT	3
#define	SCF_KSTAT_SYS_NAMED_ALIVE	4

#define	SCF_KSTAT_SYS_NAMED_NDATA	5

#ifdef __cplusplus
}
#endif

#endif /* _SCFKSTAT_H */
