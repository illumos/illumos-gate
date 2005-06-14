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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_RTC_H
#define	_RTC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Global include file for the runtime configuration support.
 */
#include <time.h>
#include <machdep.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Configuration header.
 */
typedef struct {
	Word	ch_version;		/* version of config file */
	Word	ch_cnflags;		/* configuration flags */
	Word	ch_dlflags;		/* dldump() flags used */
	Word	ch_app;			/* application that this config file */
					/*	is specific to */
	Word	ch_hash;		/* hash table offset */
	Word	ch_obj;			/* object table offset */
	Word	ch_str;			/* string table offset */
	Word	ch_file;		/* file entries */
	Word	ch_dir;			/* directory entries */
	Word	ch_edlibpath;		/* ELF default library path offset */
	Word	ch_adlibpath;		/* AOUT default library path offset */
	Word	ch_eslibpath;		/* ELF secure library path offset */
	Word	ch_aslibpath;		/* AOUT secure library path offset */
	Lword	ch_resbgn;		/* memory reservation required to map */
	Lword	ch_resend;		/*	alternative objects defined */
					/*	by the configuration info */
	Word	ch_env;			/* environment variables */
	Word	ch_fltr;		/* filter table entries */
	Word	ch_flte;		/* filtee table entries */
} Rtc_head;

#define	RTC_HDR_IGNORE	0x0001		/* ignore config information */
#define	RTC_HDR_ALTER	0x0002		/* alternative objects are defined - */
					/*	these may exist without a */
					/*	memory reservation (see -a) */
#define	RTC_HDR_64	0x0004		/* 64-bit objects used */
#define	RTC_HDR_UPM	0x0008		/* includes unified process model */

/*
 * Object descriptor.
 */
typedef struct {
	Lword	co_info;		/* validation information */
	Word	co_name;		/* object name (directory or file) */
	Word	co_hash;		/* name hash value */
	Half	co_id;			/* directory identifier */
	Half	co_flags;		/* various flags */
	Word	co_alter;		/* alternative object file */
} Rtc_obj;

#define	RTC_OBJ_DIRENT	0x0001		/* object defines a directory */
#define	RTC_OBJ_ALLENTS	0x0002		/* directory was scanned for all */
					/*	containing objects */
#define	RTC_OBJ_NOEXIST	0x0004		/* object does not exist */
#define	RTC_OBJ_EXEC	0x0008		/* object identifies executable */
#define	RTC_OBJ_ALTER	0x0010		/* object has an alternate */
#define	RTC_OBJ_DUMP	0x0020		/* alternate created by dldump(3x) */
#define	RTC_OBJ_REALPTH	0x0040		/* object identifies real path */
#define	RTC_OBJ_NOALTER	0x0080		/* object can't have an alternate */
#define	RTC_OBJ_GROUP	0x0100		/* object was expanded as a group */
#define	RTC_OBJ_APP	0x0200		/* object indicates app which makes */
					/*	configuration file specific */
#define	RTC_OBJ_CMDLINE	0x0400		/* object specified from command line */
#define	RTC_OBJ_FILTER	0x0800		/* object identifies a filter */
#define	RTC_OBJ_FILTEE	0x1000		/* object identifies a filtee */
#define	RTC_OBJ_OPTINAL	0x2000		/* object alternative is optional */

/*
 * Directory and file descriptors.  The configuration cache (cd_dir) points to
 * an array of directory descriptors, this in turn point to their associated
 * arrays of file descriptors.  Both of these provide sequential access for
 * configuration file validation (directory, and possible file stat()'s).
 */
typedef struct {
	Word	cd_obj;			/* index to Rtc_obj */
	Word	cd_file;		/* index to Rtc_file[] */
} Rtc_dir;

typedef	struct {
	Word	cf_obj;			/* index to Rtc_obj */
} Rtc_file;


#define	RTC_VER_NONE	0
#define	RTC_VER_ONE	1		/* original version */
#define	RTC_VER_TWO	2		/* updated for -u use */
#define	RTC_VER_THREE	3		/* updated for -e/-E use */
#define	RTC_VER_FOUR	4		/* updated for filter/filtees */
#define	RTC_VER_CURRENT RTC_VER_FOUR
#define	RTC_VER_NUM	5

/*
 * Environment variable descriptor.  The configuration cache (ch_env) points to
 * an array of these descriptors.
 */
typedef struct {
	Word	env_str;		/* index into string table */
	Word	env_flags;		/* various flags */
} Rtc_env;

#define	RTC_ENV_REPLACE	0x0001		/* replaceable string definition */
#define	RTC_ENV_PERMANT	0x0002		/* permanent string definition */
#define	RTC_ENV_CONFIG	0x1000		/* string originates from config file */

/*
 * Filter descriptor.  The configuration cache (ch_flt) points to an array of
 * these descriptors.
 */
typedef struct {
	Word	fr_filter;		/* filter name, and filtee string */
	Word	fr_string;		/*	as indexs into string table */
	Word	fr_filtee;		/* index into filtee array */
} Rtc_fltr;

typedef struct {
	Word	fe_filtee;
} Rtc_flte;

#ifdef	__cplusplus
}
#endif

#endif	/* _RTC_H */
