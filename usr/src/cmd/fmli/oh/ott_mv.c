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

/*	Copyright (c) 1984, 1985 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "wish.h"
#include "sizes.h"
#include "typetab.h"
#include "partabdefs.h"

extern struct ott_tab *Cur_ott;
extern struct ott_entry *Cur_entry;

static void recurrent();

int
ott_mv(entry, path, name, move)
struct ott_entry *entry;
char *path;
char *name;
bool move;
{
	struct ott_tab *oldtab;
	register int i;
	int numparts = 0;
	char newnames[MAXOBJPARTS][FILE_NAME_SIZ];
	struct ott_entry *entries[MAXOBJPARTS+1];
	struct opt_entry *optab, *obj_to_opt();
	char oldpath[PATHSIZ], dname[DNAMESIZ];
	int part_offset;
	int pathlen;
	char source[PATHSIZ], destination[PATHSIZ];
	struct ott_entry *name_to_ott(), *ott_next_part();
	extern struct one_part Parts[MAXPARTS];
	struct ott_entry *ott_dup();
	struct stat buffer, *buf;
	extern char *part_match(), *ott_to_path(); /* abs 9/12/88 */

#ifdef _DEBUG
	_debug(stderr, "IN OTT_MV(%s/%s, %s, %s, %d)\n", entry->dirpath, entry->name, path, name, move);
#endif

	if ((entry = name_to_ott(entry->name)) == NULL) {
		return(O_FAIL);
	}

	if (!name || !name[0] || strcmp(name, entry->name) == 0)
		strcpy(dname, entry->dname);
	else
		*dname = '\0';
	/** keep the current ott path for later restoration **/

	if (path == NULL || strcmp(path, Cur_ott->path) == 0)
		oldpath[0] = '\0';
	else
		strcpy(oldpath, Cur_ott->path);

	/* cannot copy to same directory if name is the same */

	if (oldpath[0] == '\0' && (name == NULL || strcmp(name, entry->name)==0)) {
#ifdef _DEBUG
		_debug(stderr, "ott_copy: cannot copy name to same dir\n");
#endif
		return(O_FAIL);
	}

	/** Because various routines could invalidate the pointers inside the
	 ** entry pionter, the first thing to do is to copy all the parts of
	 ** that object to a stable place.
	 **/

	do {
		entries[numparts++] = ott_dup(entry);
		entry = ott_next_part(entry);
	} while (entry);
	entries[numparts] = NULL;
	if (move) {	/* do stat on old file to redo ownership and group */
		buf = &buffer;
		if (stat(ott_to_path(entries[0]), buf) == -1)
			buf = NULL;
	}

	if (name && name[0]) {
		if (opt_rename(entries, name, newnames) == O_FAIL) {
#ifdef _DEBUG
			_debug(stderr, "Ott rename fail in ott_copy\n");
#endif
			return(O_FAIL);
		}
	} else {
		for (i=0; i < numparts; i++)
			strcpy(newnames[i], entries[i]->name);
	}
	if (path)
		strcpy(destination, path);
	else
		strcpy(destination, Cur_ott->path);
	pathlen = strlen(destination);
	destination[pathlen++] = '/';
	/* make sure all parts do not exist */
	for (i = 0; i < numparts; i++) {
		strcpy(destination + pathlen, newnames[i]);
#ifdef _DEBUG
		_debug(stderr, "access of destination %s checked\n", destination);
#endif
		if (access(destination, 04) != -1)
			return(O_FAIL);
	}

	/** get the destination ott if it is not the same as the current
	 ** ott.
	 **/

	if (oldpath[0]) {
		ott_lock_inc(NULL);	/* lock incore, we will restore later */
		make_current(path);
	}

	if ((optab = obj_to_opt(entries[0]->objtype)) == NULL) {
		recurrent(oldpath);
		return(O_FAIL);
	}
	part_offset = optab->part_offset;

	if (!(*dname))
		strcpy(dname, part_match(newnames[0], Parts[part_offset].part_template));
	if (name_to_ott(newnames[0]) != NULL)
		return(O_FAIL);
	ott_add_entry(NULL, newnames[0], dname,
		entries[0]->objtype, entries[0]->objmask,entries[0]->odi, NULL);
	for (i = 1; i < numparts; i++) {
		ott_add_entry(NULL, newnames[i],
			NULL, entries[i]->objtype, 
			entries[i]->objmask, entries[i]->odi, NULL);
	}
	ott_synch(FALSE);

	/* physically move the UNIX files */

	for (i = 0; i < numparts; i++) {
		/* this code can be enhanced to only strcpy the dest once */
		if (path)
			strcpy(destination, path);
		else
			strcpy(destination, entries[i]->dirpath);
		strcat(destination, "/");
		strcat(destination, newnames[i]);
		strcpy(source, ott_to_path(entries[i]));
		if (Parts[part_offset+i].part_flags & PRT_DIR) {
			if (path) {
				if (waitspawn(spawn("/bin/mkdir", "/bin/mkdir", destination, 0)) != 0) {
					recurrent(oldpath);
					return(O_FAIL);
				}
			} else {
				if (waitspawn(spawn("/bin/mv", "/bin/mv", "-f", source, destination, 0)) != 0) {
					recurrent(oldpath);
					return(O_FAIL);
				}
			}
		} else {
			if (move) {
				if (movefile(source, destination) != 0) {
					recurrent(oldpath);
					return(O_FAIL);
				}
			} else {
				if (copyfile(source, destination) != 0) {
					recurrent(oldpath);
					return(O_FAIL);
				}
			}
		}
	}
	/* must reget entry and DONT use old file owner and group of a copy */
	/* DO if a move (could have a dir as a part */
	if (path)
		strcpy(destination, path);
	else
		strcpy(destination, entries[0]->dirpath);
	strcat(destination, "/");
	strcat(destination, name);
	if (move && buf)
		change_owns(destination, NULL, &buf->st_uid, &buf->st_gid);
	else
		change_owns(destination, NULL, NULL, NULL);
	if (move) {
		for (i = 0; i < numparts; i++) {
			if ((Parts[part_offset+i].part_flags & PRT_DIR) && !path)
				waitspawn(spawn("/bin/rmdir", "/bin/rmdir", ott_to_path(entries[i])));
		}
	}

	recurrent(oldpath);

	for (i = 0; i < numparts; i++)
		ott_free(entries[i]);

	return(O_OK);
}

static void
recurrent(oldpath)
char *oldpath;
{
	if (!(*oldpath))
		return;
	Cur_ott->last_used -= 2;	/* swapping penalty */
	make_current(oldpath);
	ott_unlock_inc(NULL);
}

