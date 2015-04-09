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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

#ifndef	_DCONF_H
#define	_DCONF_H

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dumpconf {
	char dc_device[MAXPATHLEN];	/* Dump device path */
	char dc_savdir[MAXPATHLEN];	/* Savecore dir path */
	int dc_cflags;			/* Config flags (see <sys/dumpadm.h>) */
	int dc_enable;			/* Run savecore on boot? (see below) */
	int dc_csave;			/* Save dump compressed? (see below) */
	int dc_mode;			/* Mode flags (see below) */
	FILE *dc_conf_fp;		/* File pointer for config file */
	int dc_conf_fd;			/* File descriptor for config file */
	int dc_dump_fd;			/* File descriptor for dump device */
	boolean_t dc_readonly;		/* Readonly conf file */
} dumpconf_t;

/*
 * Values for dc_enable (run savecore on boot) property:
 */
#define	DC_OFF		0		/* Savecore disabled */
#define	DC_ON		1		/* Savecore enabled */

/*
 * Values for dc_csave (savecore compressed) property:
 */
#define	DC_UNCOMPRESSED	0		/* Savecore uncompresses the dump */
#define	DC_COMPRESSED	1		/* Savecore leaves dump compressed */

/*
 * Values for dconf_open mode:
 */
#define	DC_CURRENT	1		/* Kernel overrides file settings */
#define	DC_OVERRIDE	2		/* File+defaults override kernel */

extern int dconf_open(dumpconf_t *, const char *, const char *, int);
extern int dconf_getdev(dumpconf_t *);
extern int dconf_close(dumpconf_t *);
extern int dconf_write(dumpconf_t *);
extern int dconf_update(dumpconf_t *, int);
extern void dconf_print(dumpconf_t *, FILE *);
extern int dconf_write_uuid(dumpconf_t *);
extern int dconf_get_dumpsize(dumpconf_t *);

extern int dconf_str2device(dumpconf_t *, char *);
extern int dconf_str2savdir(dumpconf_t *, char *);
extern int dconf_str2content(dumpconf_t *, char *);
extern int dconf_str2enable(dumpconf_t *, char *);
extern int dconf_str2csave(dumpconf_t *, char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _DCONF_H */
