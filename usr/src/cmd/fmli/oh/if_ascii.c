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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.11 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "wish.h"
#include "but.h"
#include "typetab.h"
#include "obj.h"
#include "retcds.h"
#include "procdefs.h"
#include "sizes.h"

char *ott_to_path(), *strcpy();
#define B_LEN 256		/* pulled out of air--80 seemed too small abs */

int
IF_acv(argv)
char *argv[];
{
	return(0);
}

/*ARGSUSED*/
int
IF_aed(argv)
char *argv[];
{
	char title[PATHSIZ];
	struct ott_entry *ott, *path_to_ott();
	char	*bsd_path_to_title();

	if (access(argv[0], 04) == FAIL) {
	    mess_temp(nstrcat("You do not have permission to access ",
			  bsd_path_to_title(argv[0], MESS_COLS-37), NULL));
	    return(FAIL);
	}
	strcpy(title, "Suspended ");
	strcat(title, bsd_path_to_title(argv[0], COLS - FIXED_COLS - 10));
	proc_open(PR_ERRPROMPT, title, NULL, "$EDITOR", argv[0], NULL);
	if ((ott = path_to_ott(argv[0])) != NULL)
		ott_mtime(ott);
	return(SUCCESS);
}

int
IF_apr(argv)
char *argv[];
{
	struct ott_entry *entry, *path_to_ott();
	struct stat buf;
	int ret;

	if ((entry = path_to_ott(argv[0])) == NULL)
		return(FAIL);

	if ((ret=stat(argv[0],&buf))== 0)
		if (buf.st_size == 0) {
			mess_temp("Cannot print zero length files");
			return(FAIL);
		}

	return(obj_print(entry, NULL, NULL));
}

int
obj_print(entry, draftstyle, prclass)
struct ott_entry *entry;
char *draftstyle;
char *prclass;
{
	FILE *pinfo;
	char prname[PATHSIZ];
	int i;
	char buf[PATHSIZ];
	char *command[10], objtypebuf[20], titlebuf[MAX_WIDTH];
	char draftbuf[20], pdefbuf[B_LEN];
	char jobclass[4];  /* might as well make it 4 since it gets aligned*/
	char *pdefs;

	struct ott_entry *name_to_ott();
	char *odi_getkey();
	static char Pdefaults[] = "PRINTOPTS";

	if (((pdefs = odi_getkey(entry, Pdefaults))) != NULL && *pdefs)
		sprintf(jobclass, "%c", *pdefs);
	else if (prclass != NULL)
		strcpy(jobclass, prclass);
	else if (entry->objmask & CL_DOC) {
		strcpy(jobclass, "d");
	} else if (entry->objmask & CL_MAIL)
		strcpy(jobclass, "m");
	else
		strcpy(jobclass, "d");

#ifdef _DEBUG
	_debug(stderr, "PDEFAULTS=%s jobclass=%s\n", pdefs, jobclass);
#endif

	i = 0;
	command[i++] = "$VMSYS/OBJECTS/Menu.print";
	if (pdefs && *pdefs) {
		sprintf(pdefbuf, "-u%s", pdefs);
		command[i++] = pdefbuf;
	}
/***********
	sprintf(jobclassbuf, "-j%s", jobclass);
	command[i++] = jobclassbuf;
***********/
	if (draftstyle) {
		sprintf(draftbuf, "-F%s", draftstyle);
		command[i++] = draftbuf;
	}
	sprintf(titlebuf, "-t%s", entry->dname);
	command[i++] = titlebuf;
	sprintf(objtypebuf, "-f%s", entry->objtype);
	command[i++] = objtypebuf;
	command[i++] = ott_to_path(entry);
	command[i++] = NULL;

	objopv("OPEN", "MENU", command);
	
	strcpy(prname, entry->dirpath);
	strcat(prname, "/.P");
	strcat(prname, entry->name);

	if ((pinfo = fopen(prname, "r")) != NULL) {
		if (fgets(buf, BUFSIZ, pinfo) != NULL) {
			buf[strlen(buf)-1] = '\0';
			ott_lock_dsk(entry->dirpath);
			if (entry = name_to_ott(entry->name)) {
#ifdef _DEBUG
				_debug(stderr, "putting new printer info:%s\n",buf);
#endif
				odi_putkey(entry, Pdefaults, buf);
				ott_dirty();
				ott_synch(FALSE);
			}
#ifdef _DEBUG
			_debug(stderr, "PRINTDEFS: %s\n", buf);
#endif
		}
		(void) fclose(pinfo);
		(void) unlink(prname);
	}
#ifdef _DEBUG
	 else
		_debug(stderr, "PRINT SAVE FAIL: jobclass=%s prname=%s\n", jobclass, prname);
#endif

	return(SUCCESS);
}
