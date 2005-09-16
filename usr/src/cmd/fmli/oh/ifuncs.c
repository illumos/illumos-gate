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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "wish.h"
#include "but.h"
#include "typetab.h"
#include "ifuncdefs.h"
#include "partabdefs.h"
#include "obj.h"
#include "optabdefs.h"
#include "retcds.h"
#include "windefs.h"
#include "var_arrays.h"
#include "terror.h"
#include "token.h"
#include "moremacros.h"
#include "message.h"
#include "sizes.h"

struct ott_entry *name_to_ott();
char Undel[] = "UNDELDIR";
static char *Arg;
struct ott_entry *Ott;
extern char nil[];


int (*Function[MAX_IFUNCS])();
void docv();
char *getepenv();
static token confirmW();
static token confirm();
static int mv_or_cp();

int
IF_badfunc()
{
	mess_temp("That operation is not available in FACE");
	return(FAIL);
}

int
IF_sh()
{
	return (0);
}

int
IF_rn(argv)
char *argv[];
{
	char msg[MESSIZ];
	char oldname[DNAMESIZ];
	struct ott_entry *entry, *path_to_ott();
	char	*bsd_path_to_title();

	if (path_isopen(argv[0], "rename", TRUE))
		return(FAIL);
	if (ckperms(parent(argv[0]), 02) == FAIL)
		return(FAIL);
	if ((entry = path_to_ott(argv[0])) == NULL)
		return(FAIL);
	strcpy(oldname, entry->name);
	if (ott_mv(entry, NULL, argv[1], TRUE) != FAIL) {
		sprintf(msg, "%s renamed to %s", bsd_path_to_title(oldname,(MESS_COLS - 12)/2), bsd_path_to_title(argv[1],(MESS_COLS - 12)/2));
		mess_temp(msg);
		return(SUCCESS);
	} else {
		sprintf(msg, "%s rename failed", bsd_path_to_title(oldname,MESS_COLS - 14));
		mess_temp(msg);
		return(FAIL);
	}
}

int
IF_cp(argv)
char *argv[];
{
	return(mv_or_cp(FALSE, argv));
}

int
IF_mv(argv)
char *argv[];
{
	return(mv_or_cp(TRUE, argv));
}

static int
mv_or_cp(mv, argv)
bool mv;
char *argv[];
{
    char msg[MESSIZ];
    char oldname[DNAMESIZ], newname[DNAMESIZ];
    char *display, path[PATHSIZ];
    struct ott_entry *entry, *path_to_ott();
    extern char *Wastebasket;
    char *filename();
    char	*bsd_path_to_title();
    int plen;

    working(TRUE);
    if (mv && path_isopen(argv[0], mv ? "move" : "copy", TRUE))
	return(FAIL);
    if (mv && ckperms(parent(argv[0]), 02) == FAIL) {
	return(FAIL);
    }
    if (! mv && ckperms(argv[0], 04) == FAIL) {
	return(FAIL);
    }
    if (ckperms(argv[1], 02) == FAIL) {
	return(FAIL);
    }
    if ((entry = path_to_ott(argv[1])) == NULL)
	return(FAIL);
    if (!(entry->objmask & CL_DIR)) {
	sprintf(msg, "%s is not a proper destination for %s",
		bsd_path_to_title(argv[1], MESS_COLS-37), mv ? "move" : "copy");
	mess_temp(msg);
	return(FAIL);
    }
    if ((entry = path_to_ott(argv[0])) == NULL)
	return(FAIL);
    display = strsave(entry->display);
    strcpy(oldname, entry->name);
    if (argv[2] == NULL)
	strcpy(newname, entry->name);
    else
	strcpy(newname, filename(argv[2]));
    if (ott_mv(entry, argv[1], newname, mv) != FAIL) {
	sprintf(path, "%s/%s", argv[1], newname);
	if ((entry = path_to_ott(path)) == NULL)
	    return(FAIL);
	entry->display = display;
	ott_chg_display(entry);
	if (strncmp(path, Wastebasket, strlen(Wastebasket)) == 0)
	    (void) odi_putkey(entry, Undel, parent(argv[0]));
	else if (strncmp(argv[0], Wastebasket, strlen(Wastebasket)) == 0)
	    (void) odi_putkey(entry, Undel, NULL);
	utime(path, NULL);	/* Touch the file */
	ott_mtime(entry);

	if ( strcmp(oldname, newname) == 0 ) {
	    sprintf(msg, "%s %sed to the ",
		bsd_path_to_title(oldname, (MESS_COLS-22)/2), mv ? "mov" : "copi");
	    plen = strlen(msg);
	    strcat(msg, bsd_path_to_title(argv[1],MESS_COLS - plen - 7));
	    strcat(msg, " folder");
	} else {
	    sprintf(msg, "%s %sed to the ",
		bsd_path_to_title(oldname, (MESS_COLS-33)/3), mv ? "mov" : "copi");
	    plen = strlen(msg);
	    strcat(msg, bsd_path_to_title(argv[1],MESS_COLS-plen-18-(MESS_COLS-33)/3));
	    strcat(msg, " folder and named ");
	    plen = strlen(msg);
	    strcat(msg, bsd_path_to_title(newname,MESS_COLS - plen));
	}

	mess_temp(msg);
	return(SUCCESS);
    } else {
	sprintf(msg, "%s %s failed to the ", 
	    bsd_path_to_title(oldname,(MESS_COLS-27)/2),
	    mv ? "move" : "copy");
	plen = strlen(msg);
	strcat(msg, bsd_path_to_title(argv[1],MESS_COLS - plen - 7));
	strcat(msg," folder");
	mess_temp(msg);
	return(FAIL);
    }
}

int
IF_sc(argv)
char *argv[];
{
	if (scram(argv[0]) == FAIL)
		return(FAIL);
	return(SUCCESS);
}

int
IF_unsc(argv)
char *argv[];
{
	if (unscram(argv[0]) == FAIL)
		return(FAIL);
	return(SUCCESS);
}

int
IF_rm(argv)
char *argv[];
{
	struct ott_entry *ott;
	struct ott_entry *path_to_ott();
	struct ott_tab *paths_ott;
	struct ott_tab *ott_get();
	char buf[BUFSIZ], *filename(), *bsd_path_to_title();
	extern char *Filecabinet, *Wastebasket;

	Arg=strsave(argv[0]);

	if ((ott = path_to_ott(argv[0])) == NULL)
		return(FAIL);

	if (strcmp(argv[0], Filecabinet) == 0) {
		mess_temp("You are not allowed to delete your Filecabinet");
		return(FAIL);
	}

	if (strcmp(argv[0], Wastebasket) == 0) {
		if (path_isopen(argv[0], "delete", FALSE))
			return(FAIL);
		sprintf(buf, "Press ENTER to empty your %s:", filename(argv[0]));
		mess_temp("WARNING: You are about to permanently remove all objects in your WASTEBASKET");
		get_string(confirmW, buf, "", 0, FALSE, "delete", "delete");
		return(SUCCESS);
	}

	if (path_isopen(argv[0], "delete", TRUE)) {
		return(FAIL);
	}

/*
 *   The following if statement reads,
 *		if the object we are deleting is a directory and
 *		   we can get an ott for it and
 *		   the directory is not empty.
 */
	if ((ott->objmask & CL_DIR) && 
	   ((paths_ott = ott_get(argv[0], OTT_SALPHA, 0, 0, 0)) != NULL) &&
	    array_len(paths_ott->parents))
		mess_temp("WARNING: The folder you are about to delete is not empty");

	sprintf(buf, "Press ENTER to delete %s:",
	    bsd_path_to_title(filename(argv[0]), MESS_COLS - 23));

	if (strncmp(argv[0], Wastebasket, strlen(Wastebasket)) == 0) {
		Ott=ott;
		get_string(confirm, buf, "", 0, FALSE, "delete", "delete");
		return(SUCCESS);
	}

	get_string(confirm, buf, "", 0, FALSE, "delete", "delete");
	return(SUCCESS);
}

int
blow_away(ott)
struct ott_entry *ott;
{
	char command[10*PATHSIZ + 30];
	struct ott_entry *ott_next_part();
	int len;

	len = sprintf(command, "/bin/rm -rf %s ", ott_to_path(ott));
	while (ott = ott_next_part(ott))
		len += sprintf(command+len, "%s ", ott_to_path(ott));
	(void) system(command);
	return (0);
}

int
IF_unrm(argv)
char *argv[];
{
	struct ott_entry *ott, *path_to_ott();
	char *path, *odi_getkey();
	int strncmp(), strlen();
	extern char *Wastebasket;

	if ( strncmp(argv[0], Wastebasket, strlen(Wastebasket)) ||
	     ! strcmp(argv[0], Wastebasket) ) {
		mess_temp("Undelete can only be used on objects in your WASTEBASKET");
		return(FAIL);
	}
	if ((ott = path_to_ott(argv[0])) == NULL)
		return(FAIL);

	if ( ! ((path = odi_getkey(ott, Undel)) && *path )) {
		mess_temp("Unable to find previous folder, use MOVE");
		return(FAIL);
	}

	return(objop("move", NULL, argv[0], path, NULL));
}

int
IF_vi(argv)
char *argv[];
{
	return (0);
}

#define MAX_DESCRIP	24

int
redescribe(argv)
char *argv[];
{
	register int i, len;
	struct ott_entry *entry;
	char newdesc[MAX_DESCRIP+1]; /* + 1 to allow for NULL in sprintf */
	struct ott_entry *path_to_ott();

	char  *filename(), *bsd_path_to_title();

	if ((entry = path_to_ott(argv[0])) == NULL)
		return(FAIL);
	for (i = 1, len = 0; argv[i] && len < MAX_DESCRIP-1; i++)
		len += sprintf(&newdesc[len], "%.*s ", MAX_DESCRIP-len-1, argv[i]);
	newdesc[len-1] = '\0';
	if (strchr(newdesc, '|')) {
		mess_temp("The character '|' is not allowed in description, try again");
		return(FAIL);
	}
	if (strcmp(newdesc,"") == 0) {
		mess_temp("Null strings are not allowed in description, try again");
		return(FAIL);
	}


	entry->display = strsave(newdesc);
	(void) ott_chg_display(entry);

	mess_temp(nstrcat(bsd_path_to_title(filename(argv[0]),
	    MESS_COLS - 17 - strlen(newdesc)),
	    " redescribed as ", newdesc, ".", NULL));
	return(SUCCESS);
}

static char *
permsg(mode)
mode_t mode;    	/* EFT abs k16 */
{
	switch (mode) {
	case 01:
		return("search");
	case 02:
		return("modify");
	case 04:
		return("read");
	default:
		return("access");
	}
}

int
ckperms(path, mode)
char *path;
mode_t mode;	/* EFT abs k16 */
{
    char	*bsd_path_to_title();

    if (access(path, 00) == FAIL) {
	mess_temp(nstrcat(bsd_path_to_title(path, MESS_COLS-15)," does not exist",
			  NULL));
	return(FAIL);
    }

    if (access(path, mode) == FAIL) {
	mess_temp(nstrcat("You do not have permission to ", permsg(mode), " ",
			  bsd_path_to_title(path, MESS_COLS-37), NULL));
	return(FAIL);
    }
    return(SUCCESS);
}

void
fcn_init()
{
	int IF_dvi(), IF_dir_open(), IF_dmv(), IF_dcp(), IF_drn();
	int	IF_sp();
	int IF_aed(), IF_acv(), IF_apr(), IF_aed();
	int IF_omopen();
	int IF_helpopen();
	int IF_ofopen();
	int IF_exec_open();

/* general purpose operations */

	Function[IF_VI] = IF_vi;
	Function[IF_SH] = IF_sh;
	Function[IF_CP] = IF_cp;
	Function[IF_RN] = IF_rn;
	Function[IF_MV] = IF_mv;
	Function[IF_RM] = IF_rm;
	Function[IF_UNRM] = IF_unrm;
	Function[IF_SC] = IF_sc;
	Function[IF_UNSC] = IF_unsc;

/* operations specific to ascii files */

	Function[IF_ACV] = IF_acv;
	Function[IF_AED] = IF_aed;
	Function[IF_APR] = IF_apr;

/* operations specific to menu objects */

	Function[IF_MENOPEN] = IF_omopen;

/* operations specific to help objects */

	Function[IF_HLPOPEN] = IF_helpopen;

/* operations specific to form objects */

	Function[IF_FRMOPEN] = IF_ofopen;

/* operations specific to file folders */

	Function[IF_DED] = IF_dir_open;
	Function[IF_DVI] = IF_dvi;
	Function[IF_DMV] = IF_dmv;
	Function[IF_DCP] = IF_dcp;
	Function[IF_DRN] = IF_drn;

/* operations specific to executables */

	Function[IF_EED] = IF_exec_open;

/* illegal function */

	Function[IF_BADFUNC] = IF_badfunc;

	return;
}

static token
confirm(s, t)
char *s;
token t;
{
	extern char *Wastebasket;
	char buf[BUFSIZ], *filename(), *bsd_path_to_title();

	sprintf(buf, "Press ENTER to delete %s:",
	    bsd_path_to_title(filename(Arg),MESS_COLS - 23));

	if (t == TOK_CANCEL)
		return TOK_NOP;

	if (t == TOK_SAVE && *s == NULL) {
		if (strncmp(Arg, Wastebasket, strlen(Wastebasket)) == 0) {
			blow_away(Ott);
			mess_temp(nstrcat("Object ", Ott->dname,
					" permanently removed from WASTEBASKET", NULL));
			ar_checkworld(TRUE);
			return TOK_NOP;
		}

		if (objop("move", NULL, Arg, Wastebasket, NULL) == FAIL) 
			return TOK_NOP;
		else
			ar_checkworld(TRUE);
	}
	else if (*s != NULL) {
		get_string(confirm, buf, "", 0, FALSE, "delete", "delete");
		mess_temp("Please re-enter value");
	}

	return TOK_NOP;
}

static token
confirmW(s, t)
char *s;
token t;
{
	extern char *Wastebasket;
	char buf[BUFSIZ], *filename();
	char command[PATHSIZ + 100];

	sprintf(buf, "Press ENTER to empty your %s:", filename(Arg));

	if (t == TOK_CANCEL)
		return TOK_NOP;

	if (t == TOK_SAVE && *s == NULL) {

		sprintf(command,"for i in %s/*; do /bin/rm -rf $i; done 1>/dev/null 2>/dev/null",Wastebasket);
		(void) system(command);
		mess_temp("All objects in WASTEBASKET have been permanently removed");
		ar_checkworld(TRUE);
	}
	else if (*s != NULL) {
		get_string(confirmW, buf, "", 0, FALSE, "delete", "delete");
		mess_temp("Please re-enter value");
	}

	return TOK_NOP;
}
