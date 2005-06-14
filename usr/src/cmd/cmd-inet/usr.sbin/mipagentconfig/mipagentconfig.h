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

#ifndef _MIPAGENTCONFIG_H
#define	_MIPAGENTCONFIG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * mipagentconfig.h -- Header file
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * These entries are used to build tables of actions to manipulate the config
 * file.  The tag is the entry the user would type.  Section is the section
 * in the config file that this entry will modify, and Label is the label
 * in the section of the config file to be modified.
 *
 * The functions are pointers to functions to be called to add, change,
 * delete, or get the value.
 */
typedef struct {
	char *tag;	/* Tag used on command line		*/
	char *Section;	/* Section in config file		*/
	char *Label;	/* Label in section in config file	*/
	int (*addFunc)(char *, char *, char *, int, int, char **);
	int (*changeFunc)(char *, char *, char *, int, int, char **);
	int (*deleteFunc)(char *, char *, char *, int, int, char **);
	int (*getFunc)(char *, char *, char *, int, int, char **);
} FuncEntry;

/*
 * Commands
 */
typedef enum c {
	Add = 0,
	Change,
	Delete,
	Get
} Command;

/*
 * This table is used to equate command codes with strings.
 */
typedef struct {
	char *string;
	Command command;
} CommandTable;

#ifdef __cplusplus
}
#endif

#endif /* _MIPAGENTCONFIG_H */
