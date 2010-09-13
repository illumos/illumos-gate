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
 *
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley
 * under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include "ypsym.h"
/* this is 14 less the space for temps pids and .pag more or less */

#ifdef DEBUG
#define	YPDBDIR		"/var/ypnew"
#define	ALIASLIST	"/var/ypnew/aliases"
#else
#define	YPDBDIR		"/var/yp"
#define	ALIASLIST	"/var/yp/aliases"
#endif
#define	issep(c) (c == ' ' || c == '\t')

#ifdef SYSVCONFIG
#define	isvar_sysv() (wasitsysv)

static int wasitsysv = TRUE;
static int first_time = TRUE;
static listofnames *list = NULL;
#endif

void sysv_exit();
extern listofnames *names();
extern void exit();
extern void free_listofnames();

/*
 * Setup alias file, check /var/yp filesystem type
 * Note: The *never* checks for aliases under Solaris, so there is no need
 *	 for this function.  As of 1.1 beta 4, I will ifdef it out (cause
 *	 you never know...).  Should go away completely soon.
 */

#ifdef SYSVCONFIG
void
sysvconfig(void)
{
	struct statvfs statbuf;

	sigset(SIGCHLD, SIG_IGN);
	/*
	 * if neccesary free previous list, then read in aliaslist
	 */

	if (!first_time)
		free_listofnames(list);
	else
		first_time = FALSE;

	list = names(ALIASLIST);

	/*
	 *	Check if YP database directory is in a system v filesystem
	 */

	if (statvfs(YPDBDIR, &statbuf) != 0) {
		fprintf(stderr, "Cannot stat %s\n", YPDBDIR);
		exit(-1);
	} else {
		/* if (strcmp(statbuf.f_basetype,"s5")) (doesn't work in k13) */
		if (statbuf.f_namemax == 14)
			wasitsysv = TRUE;
		else
			wasitsysv = FALSE;
	}
	sigset(SIGCHLD, (void (*)())sysvconfig);
}
#endif

/*
 * Match key to alias
 */
int
yp_getalias(key, key_alias, maxlen)
	char *key;
	char *key_alias;
	int maxlen;
{
	listofnames *entry;
	char *longname;
	char *alias;
	char name[256];

#ifndef SYSVCONFIG
	strcpy(key_alias, key);
	return (0);
#else
	/* sysvconfig must be run before this routine */
	if (key == NULL || first_time)
		return (-1);

	if (!isvar_sysv()) {
		strcpy(key_alias, key);
		return (0);
	}

	for (entry = list, strcpy(name, entry->name); entry;
		entry = entry->nextname, strcpy(name, entry->name)) {

		longname = strtok(name, " \t");
		alias = strtok(NULL, " \t\n");
		if (longname == NULL || alias == NULL) {
			continue;
		}
		if (strcmp(longname, key) == 0) {
			if ((int)strlen(alias) > (maxlen)) {
				strncpy(key_alias, alias, (maxlen));
				key_alias[maxlen] = '\0';
			} else {
				strcpy(key_alias, alias);
			}
			return (0);
		}
	}
	/* alias not found */
	return (-1);
#endif
}

/*
 * Match alias to key
 */
int
yp_getkey(key_alias, key, maxlen)
	char *key_alias;
	char *key;
	int maxlen;
{
	listofnames *entry;
	char *longname;
	char *alias;
	char name[256];

#ifndef SYSVCONFIG
	strcpy(key, key_alias);
	return (0);
#else
	if (key_alias == NULL || first_time) {
		return (-1);
	}

	if (!isvar_sysv()) {
		strcpy(key, key_alias);
		return (0);
	}

	for (entry = list, strcpy(name, entry->name);
		entry; entry = entry->nextname, strcpy(name, entry->name)) {

		longname = strtok(name, " \t");
		alias = strtok(NULL, " \t\n");
		if (alias == NULL || longname == NULL) {
			continue;
		}
		if ((strcmp(alias, key_alias) == 0) ||
		    (strncmp(alias, key_alias, maxlen) == 0)) {
			strcpy(key, longname);
			return (0);
		}
	}
	/* key not found */
	return (-1);
#endif
}
