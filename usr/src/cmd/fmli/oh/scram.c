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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include <curses.h>
#define	_SYS_TERMIO_H		/* sys/termio.h is included by curses.h */
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "wish.h"
#include "vtdefs.h"
#include "token.h"
#include "obj.h"
#include "typetab.h"
#include "partabdefs.h"
#include "parse.h"
#include "retcds.h"
#include "exception.h"
#include "terror.h"
#include "winp.h"
#include "moremacros.h"
#include "sizes.h"

#define	KEYSIZE 101

extern char *Home;

static unsigned char Keycheck[KEYSIZE];
static char Passwd[20];
static char Keyprompt[35];
static char Srcfile[PATHSIZ];
static int cryptit(), mkencrypart();
static char	scram_string[] = "scramble";
static char	uscram_string[] = "unscramble";
static int check_key();
static int crypt_file();
static int pack();
static int unpack();
static int keysave();
static int keyvalid();
static void regetkey();

/*
 *	scram -- Scramble an object and pack all its parts into an OEU package
 */
int
scram(file)
register char *file;
{

	strcpy(Keyprompt, "Please enter scramble key: ");
	strcpy(Srcfile, file);
	get_string(regetkey, Keyprompt, "",
	    I_INVISIBLE, FALSE, scram_string, scram_string);
	return (0);
}

/*
 * unscram -- Unscramble an object which was packed into an OEU package before
 */
int
unscram(file)
register char *file;
{
	int keysave();

	strcpy(Keyprompt, "Please enter unscramble key: ");
	strcpy(Srcfile, file);
	get_string(keysave, Keyprompt, "",
	    I_INVISIBLE, FALSE, uscram_string, uscram_string);
	return (0);
}

static void
regetkey(s, t)
char *s;
token t;
{
	int keyvalid();

	if (t == TOK_CANCEL)
		return;

	strcpy(Passwd, s);
	get_string(keyvalid, "Please re-enter scramble key: ", "",
	    I_INVISIBLE, FALSE, scram_string, scram_string);
}

static int
keyvalid(s, t)
char *s;
token t;
{
	struct ott_entry *entry, *path_to_ott();
	struct stat buf;

	if (t == TOK_CANCEL)
		return (SUCCESS);

	if (strcmp(Passwd, s) != 0) {
		mess_temp("The two scramble keys are different.");
		get_string(regetkey, Keyprompt, "",
		    I_INVISIBLE, FALSE, scram_string, scram_string);
		return (SUCCESS);
	} else {
		stat(Srcfile, &buf);	/* return code check? */
		if ((entry = path_to_ott(Srcfile)) == NULL)
			return (FAIL);
		working(TRUE);
		if (mkencrypart() == FAIL ||
		    crypt_file(entry, buf, FALSE) == FAIL ||
		    pack(entry, buf) == FAIL)
			return (FAIL);
		else {
			ott_mark(entry, M_EN, TRUE);
			return (SUCCESS);
		}
	}
}

static int
keysave(s, t)
char *s;
token t;
{
	struct ott_entry *entry, *path_to_ott();
	char package[PATHSIZ];
	struct stat buf;
	int check_key();

	strcpy(Passwd, s);
	stat(Srcfile, &buf);	/* return code check? */
	if ((entry = path_to_ott(Srcfile)) == NULL)
		return (FAIL);
	working(TRUE);
	strcpy(package, Home);
	strcat(package, "/tmp/.TMPorigin");
	if (unpack(entry, package) == FAIL) {
		unlink(package);
		return (FAIL);
	}
	if (check_key(entry) == SUCCESS) {
		crypt_file(entry, buf, TRUE);
		unlink(package);
		ott_mark(entry, M_EN, FALSE);
	} else {
		(void) pack(entry, buf);
		unlink(Srcfile);
		if (movefile(package, Srcfile))
			unlink(package);
		/* get_string(keysave, Keyprompt, "", */
		/* I_INVISIBLE, FALSE, scram_string, scram_string); */
	}
	return (SUCCESS);
}

static int
unpack(entry, package)
struct ott_entry *entry;
char *package;
{
	struct opt_entry *part_ent, *obj_to_opt();
	struct one_part *opt_next_part();
	char *filename(), *nameptr;
	char path[PATHSIZ], action[(PATHSIZ * 2) + 20];
	char *part_match();
	FILE *pipeptr, *popen();

	part_ent = obj_to_opt(entry->objtype);
	if (!part_ent) {
		warn(MUNGED, NULL);
		return (FAIL);
	}
	nameptr = part_match(filename(Srcfile),
	    opt_next_part(part_ent)->part_template);
	movefile(Srcfile, package);
	sprintf(path, "%s/%s", entry->dirpath, nameptr);
	sprintf(action, "oeupkg -u -d %s -s %s", path, package);
	if ((pipeptr = popen(action, "r")) == NULL)
		fatal(NOPEN, action);
	/* abs:added cast */
	if (fgets((char *)Keycheck, KEYSIZE, pipeptr) == NULL)
		return (FAIL);
	Keycheck[KEYSIZE - 1] = 0;	/* ?? */
	pclose(pipeptr);
	return (SUCCESS);
}

static int
pack(entry, buf)
struct ott_entry *entry;
struct stat buf;
{
	char temp[PATHSIZ];
	char action[(PATHSIZ * 3) + 80];
	struct ott_entry *ptr, *ott_next_part(), *name_to_ott();

	strcpy(temp, Home);
	strcat(temp, "/tmp/.TMPscram");
	sprintf(action, "oeupkg -d %s -s %s -o %s -e %s",
		temp, Srcfile, entry->objtype, Keycheck);
	if (waitspawn(sysspawn(action)) != R_OK)
		return (FAIL);

	if (chmod(temp, buf.st_mode) == 0 &&
	    chown(temp, buf.st_uid, buf.st_gid) == 0) {
		unlink(Srcfile);
		movefile(temp, Srcfile);
	}
	/* remove OTHER parts after packing */
	ptr = ott_next_part(entry);
	while (ptr) {
		unlink(ott_to_path(ptr));
		ott_mark(name_to_ott(ptr->name), M_DL, TRUE);
		ptr = ott_next_part(ptr);
	}
	/* dereference children from parent */
	ptr = name_to_ott(entry->name);
	ptr->next_part = OTTNIL;
	return (SUCCESS);
}

/*
 * crypt_file -- encrypt or decrypt using the UNIX "crypt" command
 */
static int
crypt_file(entry, buf, create_entry)
struct ott_entry *entry;
struct stat buf;
int	create_entry;
{

	int i;
	char action[PATHSIZ + 40], temp[PATHSIZ];
	char path[PATHSIZ];
	char *part, *base;
	struct opt_entry *partab;
	struct ott_entry *orig_entry;
	extern struct one_part Parts[MAXPARTS];

	char *part_match(), *part_construct();
	struct opt_entry *obj_to_parts();
	struct ott_entry *ott_make_entry(), *name_to_ott();

	/* if either return NULL */
	if (!(partab = obj_to_parts(entry->objtype)) ||
	    !(base = part_match(entry->name,
	    Parts[partab->part_offset].part_template)))
		return (FAIL);

	for (i = 0, part = base; i < partab->numparts; i++,
		part = part_construct(base,
		    Parts[partab->part_offset+i].part_template)) {
		sprintf(path, "%s/%s", entry->dirpath, part);
		if (access(path, 0))
			continue;
		strcpy(temp, Home);
		strcat(temp, "/tmp/.TMPcrypt");
		(void) close(open(temp, O_EXCL | O_CREAT | O_TRUNC, 0600));
		sprintf(action, "crypt '%s' < '%s' > '%s'", Passwd, path, temp);
		if (waitspawn(sysspawn(action)) != 0) {
			mess_temp("Encryption software not available");
			return (FAIL);
		}
		if (chmod(temp, buf.st_mode) == 0 &&
			chown(temp, buf.st_uid, buf.st_gid) == 0) {
			unlink(path);
			link(temp, path);
		}
		unlink(temp);
		/* if need to create an entry (unscrambling)  */
		if (create_entry) {
			/* since calling other routines */
			part = strsave(part);
#ifdef _DEBUG
			_debug(stderr, "creating entry for %s\n", part);
#endif
			if ((i == 0) && (partab->numparts > 1)) {
		/* remake parent so can do children - IF children exist */
				orig_entry = name_to_ott(entry->name);
				orig_entry->objmask |= M_DL;
				entry = ott_make_entry(part,
				    entry->dname, entry->objtype,
				    entry->objmask, entry->odi, entry->mtime);
				/* dupped entry so don't need to & out ~M_DL */
			} else if (i != 0)	/* add child */
				ott_make_entry(part, NULL, NULL,
				    entry->objmask|partab->int_class,
				    NULL, entry->mtime);
			free(part);
		/* NOTE: part has been freed if anything is added after this */
		}
	}
	if (create_entry && (partab->numparts > 1))
		ott_synch(FALSE);
	return (SUCCESS);
}

static int
check_key(entry)
struct ott_entry *entry;
{
	int m, n;
	unsigned char buf[51];
	int left, right;
	char tempstr[3];

	tempstr[2] = '\0';
	for (m = 0; m < 50; m++)
	{
		n = m + m;
		tempstr[0] = Keycheck[n];
		tempstr[1] = Keycheck[n+1];
		buf[m] = (int)strtol(tempstr, NULL, 16);
	}

	if (cryptit(buf) == FAIL)
		return (FAIL);

	for (m = 0; m < 50; m++) {
		if (buf[m] > 0177) {
			char msg[PATHSIZ + 30];

			sprintf(msg, "Key does not unscramble %s",
			    entry->dname);
			mess_temp(msg);
			return (FAIL);	/* encrypted */
		}
	}
	return (SUCCESS);		/* not encrypted */
}

static int
mkencrypart()
{
	register int n, m;
	char tempstr[3];
	unsigned char buf[51];
	unsigned int left, right;
	time_t clock;	/* EFT abs k16 */

	clock = time((time_t *)0);	/* EFT abs k16 */
	right = clock & 0177;
	buf[0] = right;

	for (n = 1; n < 50; n++) {
		right = (right + n + (right & 0125)) & 0177;
		if (right == 0177) right = n;
		buf[n] = right;
	}

	if (cryptit(buf) == FAIL)
		return (FAIL);

	for (m = 0; m < 50; m++) {
		static char	hex[] = "0123456789abcdef";

		n = m * 2;
		Keycheck[n] = hex[(buf[m] >> 4) & 0xf];
		Keycheck[n+1] = hex[buf[m] & 0xf];
	}
	Keycheck[KEYSIZE - 1] = '\0';
	return (SUCCESS);
}

static int
cryptit(buf)
char *buf;
{
	int fd;
	char efile[20], dfile[20];
	char action[(2 * PATHSIZ) + 80];

	strcpy(dfile, "/tmp/.DECXXXXXX");
	strcpy(efile, "/tmp/.ENCXXXXXX");
	if ((fd = mkstemp(efile)) < 0)
		fatal(NOPEN, efile);
	write(fd, buf, 50);
	(void) close(fd);
	if ((fd = mkstemp(dfile)) < 0)
		fatal(NOPEN, dfile);
	(void) close(fd);
	sprintf(action, "crypt '%s' < %s > %s", Passwd,  efile, dfile);
	if (waitspawn(sysspawn(action)) != 0) {
		mess_temp("Encryption software not available");
		(void) unlink(efile);
		(void) unlink(dfile);
		return (FAIL);
	}
	unlink(efile);
	if ((fd = open(dfile, O_RDONLY)) < 0)
		fatal(NOPEN, dfile);
	read(fd, buf, 50);
	(void) close(fd);
	(void) unlink(dfile);
	return (SUCCESS);
}
