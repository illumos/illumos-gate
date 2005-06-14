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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _METASSIST_H
#define	_METASSIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* Location of the volume-defaults.xml file */
#define	VOLUME_DEFAULTS_LOC	"/etc/default/metassist.xml"

/* Available/unavailable device list delimiters */
#define	DEVICELISTDELIM	", "

/* Command-line arguments */
#define	COMMON_SHORTOPT_HELP		'?'
#define	COMMON_SHORTOPT_VERBOSITY	'v'
#define	COMMON_SHORTOPT_VERSION		'V'
#define	CREATE_SHORTOPT_AVAILABLE	'a'
#define	CREATE_SHORTOPT_COMMANDFILE	'c'
#define	CREATE_SHORTOPT_DATAPATHS	'p'
#define	CREATE_SHORTOPT_DISKSET		's'
#define	CREATE_SHORTOPT_FAULTRECOVERY	'f'
#define	CREATE_SHORTOPT_INPUTFILE	'F'
#define	CREATE_SHORTOPT_NAME		'n'
#define	CREATE_SHORTOPT_REDUNDANCY	'r'
#define	CREATE_SHORTOPT_SIZE		'S'
#define	CREATE_SHORTOPT_CONFIGFILE	'd'
#define	CREATE_SHORTOPT_UNAVAILABLE	'u'
#define	CREATE_SHORTOPTS		"a:cdfF:n:p:r:s:S:u:v:V?"
#define	MAIN_SHORTOPTS			"-v:V?"
#define	MAIN_SUBCMD_CREATE		"create"

#define	SUBCMD_NONE	0
#define	SUBCMD_CREATE	1

/* Command action masks */
#define	ACTION_EXECUTE	1
#define	ACTION_OUTPUT_CONFIG	2
#define	ACTION_OUTPUT_COMMANDS	4

/* Verbose flag sent to generated shell script */
#define	COMMAND_VERBOSE_FLAG	"-v"

/* The name used to invoke the command */
extern char	*progname;

#ifdef __cplusplus
}
#endif

#endif /* _METASSIST_H */
