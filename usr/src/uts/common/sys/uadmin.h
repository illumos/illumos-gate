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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_UADMIN_H
#define	_SYS_UADMIN_H


#if !defined(_ASM)
#include <sys/types.h>
#include <sys/cred.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#define	A_REBOOT	1
#define	A_SHUTDOWN	2
#define	A_FREEZE	3	/* For freeze and thaw */
#define	A_REMOUNT	4
#define	A_DUMP		5
#define	A_FTRACE	15
#define	A_SWAPCTL	16
/*			17-21	   reserved for obsolete interface */
#define	A_SDTTEST	22	/* DTrace sdt:::test */
#define	A_CONFIG	23	/* For system configuration */

#define	AD_UNKNOWN	-1	/* no method */
#define	AD_HALT		0	/* halt the processor */
#define	AD_BOOT		1	/* multi-user reboot */
#define	AD_IBOOT	2	/* multi-user reboot, ask for name of file */
#define	AD_SBOOT	3	/* single-user reboot */
#define	AD_SIBOOT	4	/* single-user reboot, ask for name of file */
#define	AD_POWEROFF	6	/* software poweroff */
#define	AD_NOSYNC	7	/* do not sync filesystems on next A_DUMP */
#define	AD_FASTREBOOT	8	/* bypass firmware and boot loader */
#define	AD_FASTREBOOT_DRYRUN	9	/* Fast reboot Dry run */

/*
 * Functions reserved for A_FREEZE (may not be available on all platforms)
 * Note:  AD_COMPRESS, AD_CHECK and AD_FORCE are now obsolete
 *	The first two are succeeded by AD_SUSPEND_TO_DISK and
 *		AD_CHECK_SUSPEND_TO_DISK respectively.
 *	AD_FORCE should not be used by any new application
 *
 *	We maintain compatibility with the earlier interfaces:
 *	AD_COMPRESS and AD_CHECK, by preserving those values
 *	in the corresponding new interfaces
 */

#define	AD_COMPRESS	0	/* store state file compressed during CPR */
#define	AD_FORCE	1	/* force to do AD_COMPRESS */
#define	AD_CHECK	2	/* test if CPR module is available */
#define	AD_SUSPEND_TO_DISK	   AD_COMPRESS	/* A_FREEZE, CPR or ACPI S4 */
#define	AD_CHECK_SUSPEND_TO_DISK   AD_CHECK	/* A_FREEZE, CPR/S4 capable? */
#define	AD_SUSPEND_TO_RAM	   20		/* A_FREEZE, S3 */
#define	AD_CHECK_SUSPEND_TO_RAM	   21		/* A_FREEZE, S3 capable? */

/*
 * NOTE: the following defines comprise an Unstable interface.  Their semantics
 * may change or they may be removed completely in a later release
 */
#define	AD_REUSEINIT	3	/* prepare for AD_REUSABLE */
#define	AD_REUSABLE	4	/* create reusable statefile */
#define	AD_REUSEFINI	5	/* revert to normal CPR mode (not reusable) */

#define	AD_FTRACE_START	1
#define	AD_FTRACE_STOP	2

/*
 * Functions of A_CONFIG.  Unstable interface.
 */
#define	AD_UPDATE_BOOT_CONFIG	1	/* Update boot config variables */

/*
 * When 'mdep' (the second argument to uadmin(2)) is initialized for A_REBOOT,
 * A_SHUTDOWN or A_DUMP, it represents the boot arguments string of at most
 * 256 characters.
 */
#define	BOOTARGS_MAX	256

#if !defined(_KERNEL)
/*
 * FMRI for boot-config service.
 */
#define	FMRI_BOOT_CONFIG \
	"svc:/system/boot-config:default"

/*
 * Property group that contains all Fast Reboot configuration properties.
 */
#define	BOOT_CONFIG_PG_PARAMS		"config"

/*
 * Property group that contains all Fast Reboot blacklisting information.
 */
#define	BOOT_CONFIG_PG_FBBLACKLIST	"fastreboot_blacklist"

/*
 * Non-persistent property group which contains all the properties that
 * will override settings in the BOOT_CONFIG_PG_PARAMS property group.
 */
#define	BOOT_CONFIG_PG_OVR		"config_ovr"

#endif	/* _KERNEL */

/*
 * Flag representations of fastboot configuration.
 */
#define	UA_FASTREBOOT_DEFAULT	0x01
#define	UA_FASTREBOOT_ONPANIC	0x02

#define	FASTREBOOT_DEFAULT		"fastreboot_default"
#define	FASTREBOOT_ONPANIC		"fastreboot_onpanic"
#define	FASTREBOOT_ONPANIC_CMDLINE	"fastreboot_onpanic_cmdline"

#define	FASTREBOOT_ONPANIC_NOTSET(p)	\
	(strcmp((p), "false") == 0 ||	\
	strcmp((p), "no") == 0 ||	\
	strcmp((p), "0") == 0)

#define	FASTREBOOT_ONPANIC_ISSET(p)	\
	(strcmp((p), "true") == 0 ||	\
	strcmp((p), "yes") == 0 ||	\
	strcmp((p), "1") == 0)

#if !defined(_ASM)

#if defined(_KERNEL)
extern kmutex_t ualock;
extern void mdboot(int, int, char *, boolean_t);
extern void mdpreboot(int, int, char *);
extern int kadmin(int, int, void *, cred_t *);
extern void killall(zoneid_t);
#endif

extern int uadmin(int, int, uintptr_t);

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_UADMIN_H */
