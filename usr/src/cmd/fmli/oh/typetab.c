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
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
/*#include <sys/types.h>           included by dirent.h     abs */
#include <dirent.h>		/* changed from sys/dir.h   abs */
#include <sys/stat.h>
#include <sys/times.h>
#include <errno.h>
#include "mio.h"
#include "wish.h"
#include "sizes.h"
#include "typetab.h"
#include "partabdefs.h"
#include "var_arrays.h"
#include "moremacros.h"


/* This file contains a package of functions which manipulate object
 * type tables (ott's).  The ott's are files (one per Telesystem
 * directory) which contain information about all objects in that 
 * directory.
 *
 * See the liboh.a reference card for a description of the functions
 * in here.
 */

#define HSIZE	512		/* hash table size, must be power of 2! */
#define ODISIZ (2*PATHSIZ)
#define NULLSTR ""

/* some statics global to these internal routines */

struct ott_tab Otts[MAX_OTT];
struct ott_tab *Cur_ott;		/* pointer to current tab in Ott */
struct ott_entry *Cur_entry;	/* pointer to current entry in Cur_ott */
static int Creation_size = OTT_ENTRIES;	/* number of entrys to create */
static char Ott_version[] = "OTT V1.1\n"; /* file sys independent abs. */
static char Ott_name[] = "/.ott";
static int Ott_len = 5;	/* strlen of above string */
static int ott_use();
static int ott_write();
static int qhash();
clock_t times();	/* EFT abs k16 */
extern long a64l();	/* abs k16 */
char *estrtok();


static char *Scanenv;

int
scanbuf(buf, hold, max_len)
char *buf, *hold;
int max_len;
{
    register char *p = estrtok(&Scanenv, buf, "|\n");

    hold[0] = '\0';
    if (!p)
	return(O_FAIL);
    strncpy(hold, p, max_len-1);
    hold[max_len-1] = '\0';
    return(0);
}

int
scanhex(buf, var)
char *buf;
long *var;
{
	register char *p = estrtok(&Scanenv, buf, "|");
	long strtol();

	if (!p)
		return(O_FAIL);
	*var = strtol(p, NULL, 16);
	return(0);
}

static int
ott_read(path, readall)
char *path;
bool readall;		/* read the .ott as well as cross indexing directory */
{
    register int i, j, alldead;
    int size;
    bool convert = FALSE;
    FILE *ottfp;
    DIR  *dirfp;		/* abs */
    int recnum, result;
    char ottname[PATHSIZ], buf[BUFSIZ];
    char fname[FILE_NAME_SIZ];	/* abs */
    static char *found;
    short int qhtab[HSIZE];	/*quick hash table really kludgy but real easy*/
    struct ott_entry *name_to_ott();
    char *def_display();

    char name[FILE_NAME_SIZ], dname[DNAMESIZ], display[DISPSIZ],
    obtype[OTYPESIZ], odinfo[ODISIZ];
    long mask;
    time_t mtime; 	/* EFT abs k16 */
    int hindex, val;
    struct ott_entry *entry;
    struct stat sbuf, dirsbuf;
    struct dirent *dir_entry;	/* for reading in the directory structure */
    struct tms timebuf;		/* for keeping timing statistics */
    time_t stime, utime;	/* EFT abs k16 */
    static char *stray;		/* stray files, i.e. not in ott */
    times(&timebuf);
    stime = timebuf.tms_stime;
    utime = timebuf.tms_utime;
	
#ifdef _DEBUG
    _debug(stderr, "READING: %s\n", path);
#endif
    if ((dirfp = opendir(path)) == NULL || /* use fs independent funcs. abs */
	stat(path, &dirsbuf) == -1)
    {
#ifdef _DEBUG
	_debug(stderr, "DIR open failed %s errno=%d\n", path,errno);
#endif
/*	(void) fclose(dirfp); */
	return(O_FAIL);
    }

    memset(qhtab,0xff,HSIZE*sizeof(short int)); /* initialize hash table */

    if (found)		/* the found array will be used to cross index the ott*/
	array_trunc(found);
    else {
	found = (char *) array_create(sizeof(char), Creation_size);
	array_ctl(found, OTT_ENTRIES);
    }

    if (readall) {       /* is the following calculation valid??  <<<<<<<<<<<<< */
	Creation_size = dirsbuf.st_size/sizeof(struct dirent); /* <<<<<<<<<<<<< */
	ott_init();		/* get a new current ott */
	Cur_ott->dir_mtime = dirsbuf.st_mtime;

	if ((int)strlen(path) + Ott_len + 1 > PATHSIZ) { /* EFT abs k16 */
#ifdef _DEBUG
	    _debug(stderr, ".ott path too long for %s\n", path);
#endif
	    return(O_FAIL);
	}
	strcat(strcpy(ottname, path), Ott_name);
	Cur_ott->path = strsave(path);
	Cur_ott->modes = OTT_ACTIVE;
	Cur_ott->prefs = 0;
	Cur_ott->fmask = 0;

	ottfp = (FILE *)NULL;
	recnum = 0;
	if ((ottfp = fopen(ottname, "r")) != NULL &&
	    (fstat(fileno(ottfp), &sbuf) != -1) ) {
#ifdef _DEBUG
	    _debug(stderr, "Opened ott fd=%d\n", (int)fileno(ottfp));
#endif
	    Cur_ott->ott_mtime = sbuf.st_mtime;
	    if (fgets(buf, BUFSIZ, ottfp) && strcmp(buf, Ott_version) != 0) {
		Cur_ott->modes |= OTT_DIRTY;
		rewind(ottfp);
	    }
	    while (fgets(buf, BUFSIZ, ottfp) != NULL) {
		odinfo[0] = '\0';
#ifdef _DEBUG
		_debug(stderr, ".");
#endif
		if (scanbuf(buf, name, FILE_NAME_SIZ) ||
		    scanbuf(NULL, dname, DNAMESIZ)  ||
		    scanbuf(NULL, display, DISPSIZ) ||
		    scanbuf(NULL, obtype, OTYPESIZ) ||
		    scanhex(NULL, &mask) ||
		    scanhex(NULL, &mtime)) {

		    Cur_ott->modes |= OTT_DIRTY; /* force rewrite */
		    continue;
		}
		scanbuf(NULL, odinfo, ODISIZ); /* odi allowed to be null */

		Cur_entry = (struct ott_entry *) array_append(Cur_entry, NULL);
		Cur_ott->ott = Cur_entry;
		entry = Cur_entry + recnum;

		hindex = qhash(name);
		val = qhtab[hindex];
		if (val == -1)
		    qhtab[hindex] = recnum;
		else
		    qhtab[hindex] = recnum>val?val:recnum;

		/* the found array will be used later during the cross-index*/
		found = (char *) array_append(found, NULL);
		found[recnum] = 'n';

		strncpy(entry->name, name, FILE_NAME_SIZ);
		entry->name[FILE_NAME_SIZ - 1] = '\0';
		entry->dirpath = Cur_ott->path;
		if (obtype[0] == ' ')
		    entry->objtype = NULL;
		else
		    entry->objtype = strsave(obtype);
		entry->mtime = mtime;
		entry->next_part = OTTNIL;

		if (strcmp(dname, " ") == 0) {
		    entry->dname = NULL;
		    if (recnum > 0) {
			entry[-1].next_part = recnum;
		    } else {
#ifdef _DEBUG
			_debug(stderr, "Orphan\n");
#endif
			continue;
		    }
		} else {
		    if (strcmp(dname, ".") == 0)
			entry->dname = strsave(entry->name);
		    else {
			dname[DNAMESIZ - 1] = '\0';
			entry->dname = strsave(dname);
		    }
		}
		if (strcmp(display, " ") == 0)
		    entry->display = NULL;
		else if (strcmp(display, ".") == 0)
		    entry->display = def_display(obtype);
		else
		    entry->display = strsave(display);
		entry->objmask = mask;
		if (*odinfo) 
		    entry->odi = strsave(odinfo);
		else
		    entry->odi = NULL;
		recnum++;
	    }
	} else {
	    Cur_ott->modes |= OTT_DIRTY;
#ifdef _DEBUG
	    _debug(stderr, "creating ott\n");
#endif
	}
	Cur_ott->priority = recnum/15; /* favor bigger .ott's */

	if (ottfp)
	    (void) fclose(ottfp);
    } else {			/* ott already in core, just construct the cross-index array*/
	recnum = array_len(Cur_entry);

#ifdef _DEBUG
	_debug(stderr, "Only doing cross-index\n");
#endif
	Cur_ott->dir_mtime = dirsbuf.st_mtime;
	Cur_ott->fmask = 0;
	Cur_ott->prefs = 0;
	Cur_ott->modes = OTT_ACTIVE;
	for (i = 0; i < recnum; i++) {
	    Cur_entry[i].objmask &= ~M_DL; /* undelete it: refigure */
	    hindex = qhash(Cur_entry[i].name);
	    val = qhtab[hindex];
	    if (val == -1)
		qhtab[hindex] = i;
	    else
		qhtab[hindex] = i>val?val:i;

	    /* entry not found yet*/

	    found = (char *)array_append(found, NULL);
	    found[i] = 'n';
	}
    }

    if (Cur_ott->dir_mtime >= Cur_ott->ott_mtime) {
	/* Cross index the ott with the unix directory structure,
	 * putting anything that is not found in the stray array.
	 * The stray array will be passed to the heuristics program
	 * to determine the type of object.
	 */

	if (stray) 
            array_trunc(stray);                 /* just reset. */
        else                                    /* 1st time */
        {
            stray = (char *)array_create(FILE_NAME_SIZ, Creation_size/2 + 1);
            array_ctl(stray, OTT_ENTRIES/2);
        }
	
/*      skip . & ..
**	(void) fseek(dirfp,(long)(2*sizeof(struct direct)),0); 
**	while (fread(&dir, sizeof(dir), 1, dirfp) > 0) {
*/
	dir_entry = readdir(dirfp);	 /* skip "."    abs */
	dir_entry = readdir(dirfp);	 /* skip ".."   abs */
	while ((dir_entry = readdir(dirfp)) != NULL) /* abs */
	{
	    if (dir_entry->d_ino == 0)	/* file was deleted, skip it*/
		continue;
	    strncpy(fname, dir_entry->d_name, FILE_NAME_SIZ);
	    fname[FILE_NAME_SIZ -1] = '\0';

	    i = qhtab[qhash(fname)];
	    entry = NULL;
	    if (i != -1) {
		for (; i < recnum; i++)
		    if (strcmp(fname, Cur_entry[i].name) == 0) {
			entry = Cur_entry + i;
			break;
		    }
	    }
			
	    if (entry != NULL) {
		found[entry - Cur_entry] = 'y';
	    } else if (fname[0] != '.' ||
		       strcmp(fname, ".ott") == 0 ||
		       strcmp(fname, ".pref") == 0 ||
		       strncmp(fname, ".V", 2) == 0 ||
		       strncmp(fname, ".L", 2) == 0)  {

#ifdef _DEBUG
		_debug(stderr, "s");
#endif
		stray = (char *) array_append(stray, fname);
	    }
	}
	closedir(dirfp);	/* abs */

	/* delete any entries in the ott which have no counterpart in the
	 * directory.
	 */

	size = array_len(found);
	for (i = 0; i < size; i++) {
	    if (found[i] == 'n') { /* doesn't exist in unix dir, delete */

		/* skip parts that are in a subdirectory */
		if (strchr(Cur_entry[i].name, '/') && !Cur_entry[i].dname)
		    continue;
		Cur_ott->modes |= OTT_DIRTY;
		if (Cur_entry[i].dname)	{ /* parent, kill only if all kids dead*/
		    alldead = 1;
		    j = i+1;
		    while (j < recnum && ! Cur_entry[j].dname) {
			if (found[j] == 'y') {
			    alldead = 0;
			    break;
			}
			j++;
		    }
		    if (alldead) {
			do {
			    Cur_entry[i].name[0] = '\0';
			    Cur_entry[i++].objmask |= M_DL;
			} while (i < recnum && Cur_entry[i].dname == NULL);
			i--;
		    }
		} else {
		    Cur_entry[i].name[0] = '\0';
		    Cur_entry[i].objmask |= M_DL;
		    Cur_entry[i-1].next_part = Cur_entry[i].next_part;
		}
	    }
	}

	/* run heuristics on the stray entries */

	if (array_len(stray) != 0) {
#ifdef _DEBUG
	    _debug(stderr, "\nHeur: %d files\n\n", array_len(stray));
#endif
	    heuristics(path, stray);
	    Cur_ott->modes |= OTT_DIRTY;
	}
    } else {
#ifdef _DEBUG
	_debug(stderr, "ott older than dir - no cross index\n");
#endif
	closedir(dirfp);	/* abs */
    }

    times(&timebuf);
#ifdef _DEBUG
    _debug(stderr, "\nREAD TIME: %du + %ds = %d/100 secs ",
	   (timebuf.tms_utime-utime), (timebuf.tms_stime-stime),
	   (i = timebuf.tms_utime + timebuf.tms_stime - utime - stime));
    if ((readall && (j = array_len(Cur_entry))) || (j = array_len(stray)))
	_debug(stderr, "(%d/1000 per file)\n\n",(10*i)/j);
    else
	_debug(stderr, "\n");
#endif

    if (name_to_ott(".pref") != NULL) {
	char buf[BUFSIZ];
	/* add 1 - here if adding /.ott short enough & /.pref is 1 more */
	char pref[PATHSIZ + 1];
	FILE *fp;
	long strtol();

#ifdef _DEBUG
	_debug(stderr, "Reading .pref\n");
#endif
	sprintf(pref, "%s/.pref", path);
	if ((fp = fopen(pref, "r")) == NULL) {
#ifdef _DEBUG
	    _debug(stderr, "no .pref\n");
#endif
	    return(O_OK);
	}
	while (fgets(buf, BUFSIZ, fp) != NULL) {
	    if (strncmp(buf, "DISPMODE=", 9) == 0) {
		Cur_ott->prefs |= PREF_DIS;
		Cur_ott->modes |= strtol(buf+9, (char **)NULL, 16);
#ifdef _DEBUG
		_debug(stderr, "DISP=%s (%x)\n", buf+9, strtol(buf+9,NULL,16));
#endif
	    } else if (strncmp(buf, "SORTMODE=", 9) == 0) {
		Cur_ott->prefs |= PREF_SORT;
		Cur_ott->modes |= strtol(buf+9, (char **)NULL, 16);
#ifdef _DEBUG
		_debug(stderr, "SORT=%s (%x)\n", buf+9, strtol(buf+9,NULL,16));
#endif
	    } else if (strncmp(buf, "FMASK=", 6) == 0) {
		Cur_ott->fmask = strtol(buf+6, (char **)NULL, 10);
	    } else if (strncmp(buf, "MAX_AGE=", 8) == 0) {
		ott_del_old(strtol(buf + 8, (char **) NULL, 10));
	    } else if (strncmp(buf, "PRIORITY=", 9) == 0) {
		Cur_ott->priority = strtol(buf+9, (char **)NULL, 10);
	    }
	}
	fclose(fp);
    }
#ifdef _DEBUG
    else
	_debug(stderr, "No .pref\n");
#endif

    if (Cur_ott->modes & OTT_DIRTY) {
#ifdef _DEBUG
	_debug(stderr, "Writing ott\n");
#endif
	ott_write();
    }

    return(O_OK);
}

int
ott_del_old(age)
long age;
{
	int i;
	struct ott_entry *ent, *ott_next_part();
	time_t thetime;	      /* EFT abs k16 */
	int	lcv;

	if (age < 1 || age > 365)
		return (0);
	thetime = time(NULL) - 24 * 60 * 60 * age;
#ifdef _DEBUG
	_debug(stderr, "ctime(&thetime) = %s\n", ctime(&thetime));
#endif
	lcv = array_len(Cur_ott->ott);
	for (i = 0; i < lcv; i++) {
		ent = Cur_ott->ott + i;
/*
 * If we are doing a MAIL_OUT object, then we automatically age it
 */
		if (strcmp(ent->objtype, "MAIL_OUT") == 0)
			if (ent->mtime < thetime) {
				do {
					ent->objmask |= M_WB;
					Cur_ott->modes |= OTT_DIRTY;
					ent = ott_next_part(ent);
				} while (ent);
			}
	}
	return (0);
}

/* simple multiplicative hash function.  This hashing algorithm is
 * really great as long as there are less than about 100 files in a
 * directory.  It begins to degrade after that, and is about as
 * efficient as a linear search if the number of files goes beyond about
 * 300.  It never gets worse than linear search.  It is great because there
 * are no "buckets" a simple collision mechanism and quick search time.
 */

static int
qhash(str)
char *str;
{
	register int result = 511;	/* why 511? why not. */

	while (*str) {
		result *= *str++;
	}
	return( (result>>8) & (HSIZE-1) );	/* take the middle bits */
}

struct ott_entry *
ott_make_entry(name,dname,objtype,objmask,odi,mtime)
char *name, *dname, *objtype;
long objmask;
char *odi;
time_t mtime;	/* EFT abs k16 */
{
	struct ott_entry *entry;
	struct stat sbuf;
	char *def_display(), *def_objtype();

	Cur_entry = (struct ott_entry *)array_append(Cur_entry, NULL);
	Cur_ott->ott = Cur_entry;
	entry = Cur_entry + array_len(Cur_entry) - 1;

	strncpy(entry->name, name, FILE_NAME_SIZ);

	if (objtype && objtype[0]) {
		entry->objtype = def_objtype(objtype);
		entry->display = def_display(objtype);
	} else {
		entry->objtype = NULL;
		entry->display = NULL;
	}

	if ((int)strlen(dname) >= DNAMESIZ) /* EFT abs k16 */
		dname[DNAMESIZ-1] = '\0';
	if (dname && dname[0]) {
		entry->dname = strsave(dname);
	} else {
		entry->dname = NULL;
		entry[-1].next_part = entry - Cur_entry;
	}

	if (odi && odi[0])
		entry->odi = strsave(odi);
	else
		entry->odi = NULL;

	entry->next_part = OTTNIL;
	entry->objmask = objmask;

	if (mtime)
		entry->mtime = mtime;
	else {
		if (stat(name, &sbuf) != -1)
			entry->mtime = sbuf.st_mtime;
		else
			entry->mtime = time((time_t *) 0);
	}
	entry->dirpath = Cur_ott->path;

	Cur_ott->modes |= OTT_DIRTY;	/* needs writing */

	return(entry);
}

struct ott_entry *
ott_add_entry(ottpath, name, dname, objtype, mask, odi, mtime)
char *ottpath, *name, *dname, *objtype;
long mask;
char *odi;
time_t mtime;	/* EFT abs k16 */
{
	struct ott_entry *entry;
	struct ott_entry *name_to_ott();

	if (ottpath) {
		if (make_current(ottpath) == O_FAIL)
			return(NULL);
	}
	if (dname)
		ott_lock_dsk(Cur_ott->path);

	if (entry = name_to_ott(name)) {
#ifdef _DEBUG
		_debug(stderr, "ott_add_entry: deleting previous entry for %s\n", entry->name);
#endif
		entry->objmask |= M_DL;		/* remove if already in */
	}

	return(ott_make_entry(name, dname, objtype, mask, odi, mtime));
}

static int
ott_alphasort(el1, el2)
int *el1, *el2;
{
	int reverse = (Cur_ott->modes & OTT_SREV)?-1:1;

	return(reverse * strcmp(Cur_entry[*el1].dname, Cur_entry[*el2].dname));
}

static int
ott_obj_alphasort(el1, el2)
int *el1, *el2;
{
	int  comp1;
	int reverse = (Cur_ott->modes & OTT_SREV)?-1:1;

	if ((comp1 = strcmp(Cur_entry[*el1].display, Cur_entry[*el2].display)) == 0)
		return(ott_alphasort(el1, el2));
	else
		return(reverse * comp1);
}

static int
ott_timesort(el1, el2)
int *el1, *el2;
{
	time_t time1, time2;	/* EFT abs k16 */
	char *key, *odi_getkey();
	int reverse = (Cur_ott->modes & OTT_SREV)?-1:1;

	if (key = odi_getkey(Cur_entry + *el1, "DATE"))
		time1 = a64l(key);
	else
		time1 = Cur_entry[*el1].mtime;
	if (key = odi_getkey(Cur_entry + *el2, "DATE"))
		time2 = a64l(key);
	else
		time2 = Cur_entry[*el2].mtime;
	return(reverse * (time2 - time1));
}

int
ott_dirty()
{
	Cur_ott->modes |= OTT_DIRTY;
	return (0);
}

/*
 * Synchronize the current internal ott with the disk version.  The ott
 * should always be locked during internal changes, so there should be
 * no problems with contention.  This routine will sort the current ott,
 * then write it out to disk, then unlock it.
 */

struct ott_tab *
ott_synch(nosort)
bool nosort;		/* don't sort if not dirty */
{
	register int size = array_len(Cur_entry);
	int i;
	long objmask, amask, nmask, smask;

	if (nosort && !(Cur_ott->modes & OTT_DIRTY))
		return(Cur_ott);

	if (Cur_ott->modes & OTT_DIRTY) {
		ott_lock_dsk(Cur_ott->path);
#ifdef _DEBUG
		_debug(stderr, "ott_synch:  writing dirty ott %s\n", Cur_ott->path);
#endif
		ott_write();
		ott_unlock_dsk(Cur_ott->path);
	}

	/* scan the ott, keeping a list of parents */

	array_trunc(Cur_ott->parents);
	smask = Cur_ott->amask & Cur_ott->nmask;
	amask = Cur_ott->amask & ~smask;
	nmask = Cur_ott->nmask & ~smask;

	for (i = 0; i < size; i++) {
		objmask = Cur_entry[i].objmask;

		if (	Cur_entry[i].dname && Cur_entry[i].dname[0] && 
				Cur_entry[i].name[0] &&
				!(objmask & M_DL) &&
				((amask & objmask)==amask) &&
				!(nmask & objmask) &&
				((!smask) || (smask & objmask)) &&
				(Cur_entry[i].dname[0] != '.' || Cur_ott->modes & OTT_DALL))
			Cur_ott->parents = (int *)array_append(Cur_ott->parents, &i);
	}

	/* sort the array of parents */

#ifdef _DEBUG
	if (Cur_ott->modes & OTT_SREV)
		_debug(stderr, "reverse ");
#endif

	if (Cur_ott->modes & OTT_SALPHA) {
#ifdef _DEBUG
		_debug(stderr, "alpha sort\n");
#endif
		qsort((char *)Cur_ott->parents, array_len(Cur_ott->parents),
				sizeof(int), ott_alphasort);
	} else if (Cur_ott->modes & OTT_SMTIME) {
#ifdef _DEBUG
		_debug(stderr, "modtime sort\n");
#endif
		qsort((char *)Cur_ott->parents, array_len(Cur_ott->parents),
				sizeof(int), ott_timesort);
	} else if (Cur_ott->modes & OTT_SOBJ) {
#ifdef _DEBUG
		_debug(stderr, "objtype sort\n");
#endif
		qsort((char *)Cur_ott->parents, array_len(Cur_ott->parents),
				sizeof(int), ott_obj_alphasort);
	}
#ifdef _DEBUG
	else
		_debug(stderr, "no sort\n");
#endif

	if (Cur_ott->modes & OTT_DMAIL)
		Cur_ott->numpages = ((int)array_len(Cur_ott->parents)+5) / 6;
	else
		Cur_ott->numpages = ((int)array_len(Cur_ott->parents)+6) / 7;

	return(Cur_ott);
}

struct ott_tab *
ott_get_current()
{
	return(Cur_ott);
}

struct ott_tab *
ott_reget()
{
	return(ott_get(Cur_ott->path, Cur_ott->modes & SORTMODES, Cur_ott->modes & DISMODES, Cur_ott->amask, Cur_ott->nmask));
}

struct ott_tab *
ott_get(path, sortmode, dismode, amask, nmask)
char *path;
int sortmode, dismode;
long amask, nmask;
{
	bool needsort = FALSE;

	if (make_current(path) == O_FAIL)
		return(NULL);

	/* if being opened with different modes than current modes, then
	 * set and resort
	 */
	if (Cur_ott->nmask != nmask || Cur_ott->amask != amask) {
		Cur_ott->nmask = nmask;
		Cur_ott->amask = amask;
		needsort = TRUE;
	}
	if (!(Cur_ott->prefs & PREF_SORT) && 
		((Cur_ott->modes & SORTMODES) != sortmode)) {
		needsort = TRUE;
		Cur_ott->modes = (Cur_ott->modes & ~SORTMODES) | sortmode;
	}
	if (!(Cur_ott->prefs & PREF_DIS) && 
		((Cur_ott->modes & DISMODES) != dismode)) {
		needsort = TRUE;
		Cur_ott->modes = (Cur_ott->modes & ~DISMODES) | dismode;
	}
	if (Cur_ott->prefs != 0)
		needsort = TRUE;

	if (needsort)
		ott_synch(FALSE);
	Cur_ott->curpage = 0;
	Cur_ott->last_used = ott_use() + Cur_ott->priority;
#ifdef _DEBUG
	_debug(stderr, "Usetime: %d\n", Cur_ott->last_used);
#endif

	return(Cur_ott);
}

int
ott_in_core(path)
char *path;
{
	register int i;

	for (i = 0; i < MAX_OTT; i++)
		if ( Otts[i].path && (Otts[i].modes&OTT_ACTIVE) &&
				(strcmp(Otts[i].path, path) == 0) ) {
#ifdef _DEBUG
			_debug(stderr, "Found %s incore\n", path);
#endif
			return(i);
		}
	return(O_FAIL);
}

int
make_current(path)
char *path;
{
    register int i;
    struct stat sbuf, dirsbuf;
    struct ott_entry *prefent, *name_to_ott();
    char ottname[PATHSIZ];
    int retcode;
    bool readall = TRUE;
    static int hits, trys;

    trys++;
    for (i = 0; i < MAX_OTT; i++) {
	if (!(Otts[i].path))
	    continue;
	if ((Otts[i].modes & OTT_ACTIVE) && (strcmp(Otts[i].path, path) == 0)) {
#ifdef _DEBUG
	    _debug(stderr, "Found %s incore\n", path);
#endif
	    Cur_ott = Otts + i;
	    Cur_entry = Cur_ott->ott;
	    hits++;

	    if (stat(path, &dirsbuf) == -1)
		return(O_FAIL);
	    if ((int)strlen(Cur_ott->path) + Ott_len + 1 > PATHSIZ) /*EFT k16*/
	    {
#ifdef _DEBUG
		_debug(stderr, ".ott path too long for %s\n", Cur_ott->path);
#endif
		return(O_FAIL);
	    }
	    strcat(strcpy(ottname, Cur_ott->path), Ott_name);
	    if (stat(ottname, &sbuf) != -1 &&
		Cur_ott->ott_mtime < sbuf.st_mtime) {
#ifdef _DEBUG
		_debug(stderr, "Incore old (.ott)\n");
#endif
		Cur_ott->modes &= ~OTT_ACTIVE; /* deallocate */
		break;		/* go down and read */
	    } else if (Cur_ott->dir_mtime < dirsbuf.st_mtime) {
#ifdef _DEBUG
		_debug(stderr, "Incore old (dir)\n");
#endif
		readall = FALSE;
		break;
	    } else {
#ifdef _DEBUG
		_debug(stderr, "hit ratio: %d/%d (%d%%)\n",hits,trys,(100*hits)/trys);
#endif
		return(O_OK);
	    }
	}
    }

    /* not resident, so read it in */

    ott_lock_dsk(path);
    retcode = ott_read(path, readall);
    ott_unlock_dsk(path);

#ifdef _DEBUG
    _debug(stderr, "hit ratio: %d/%d (%d%)\n",hits,trys,(100*hits)/trys);
#endif
    return(retcode);
}

int
ott_lock_inc(optr)
struct ott_tab *optr;
{
#ifdef _DEBUG
	_debug(stderr, "%s: locked\n", Cur_ott->path);
#endif
	if (optr == NULL)
		Cur_ott->modes |= OTT_LOCKED;
	else
		optr->modes |= OTT_LOCKED;
	return (0);
}

int
ott_unlock_inc(optr)
struct ott_tab *optr;
{
#ifdef _DEBUG
	_debug(stderr, "%s: unlocked\n", Cur_ott->path);
#endif
	if (optr == NULL)
		Cur_ott->modes &= ~OTT_LOCKED;
	else
		optr->modes &= ~OTT_LOCKED;
	return (0);
}

int
ott_lock_dsk(path)
char *path;
{
	return(O_OK);
}

int
ott_unlock_dsk(path)
char *path;
{
	return(O_OK);
}

struct ott_entry *
name_to_ott(name)
char *name;
{
	register int i, j;
	register int size = array_len(Cur_entry);
	register int psize= array_len(Cur_ott->parents);

	for (i = 0; i < size; i++)
		if (!(Cur_entry[i].objmask & M_DL) && 
				strcmp(Cur_entry[i].name, name) == 0) {
			for (j = 0; j < psize; j++) {
				if (Cur_ott->parents[j] == i) {
					if (Cur_ott->modes & OTT_DMAIL)
						Cur_ott->curpage = j/6;
					else
						Cur_ott->curpage = j/7;
					break;
				}
			}
			if (Cur_ott->curpage > Cur_ott->numpages)
				Cur_ott->curpage = Cur_ott->numpages;
			return(Cur_entry + i);
		}

	Cur_ott->curpage = 0;
	return(NULL);
}

struct ott_entry *
dname_to_ott(name)
char *name;
{
	register int i;
	register int size = array_len(Cur_entry);

	for (i = 0; i < size; i++) {
		if (Cur_entry[i].dname == NULL)
			Cur_entry[i].dname = NULLSTR;
		if (!(Cur_entry[i].objmask & M_DL) &&
				strcmp(Cur_entry[i].dname, name) == 0)
			return(Cur_entry + i);
	}
	return(NULL);
}

static int
ott_write()
{
    register int i;
    char *dname, *display;
    FILE *ottfp;
    int ottfd;
    struct stat sbuf;
    char ottname[PATHSIZ];
    int size = array_len(Cur_entry);
    char *def_display();

    if ((int)strlen(Cur_ott->path) + Ott_len + 1 > PATHSIZ) /* EFT k16 */
    {
#ifdef _DEBUG
	_debug(stderr, ".ott path too long for %s\n", Cur_ott->path);
#endif
	return(O_FAIL);
    }
    strcat(strcpy(ottname, Cur_ott->path), Ott_name);

    if ((ottfd = open(ottname, O_CREAT|O_WRONLY|O_TRUNC,0666)) == -1 ||
	(ottfp = fdopen(ottfd, "w")) == NULL) {
#ifdef _DEBUG
	_debug(stderr, "Can't write ott (errno=%d)\n", errno);
#endif
	(void) close(ottfd);
	Cur_ott->ott_mtime = time(0); /* last time we tried to update is now*/
	return(O_FAIL);
    }

    fprintf(ottfp, Ott_version);
    for (i = 0; i < size; i++ ) {
	if (Cur_entry[i].name[0] == '.' &&
	    strcmp(Cur_entry[i].name, ".pref") != 0 &&
	    strcmp(Cur_entry[i].name, ".ott") != 0 && 
	    strncmp(Cur_entry[i].name, ".V", 2) != 0 &&
	    strncmp(Cur_entry[i].name, ".L", 2) != 0)
	    continue;
	if (!(Cur_entry[i].objmask & M_DL)) {
	    if (Cur_entry[i].dname && Cur_entry[i].dname[0]) {
		if (strcmp(Cur_entry[i].dname, Cur_entry[i].name) == 0)
		    dname = ".";
		else
		    dname = Cur_entry[i].dname;
	    } else
		dname = " ";
	    if (Cur_entry[i].display && Cur_entry[i].display[0] && 
		Cur_entry[i].objtype) {
		if (strcmp(Cur_entry[i].display,
			   def_display(Cur_entry[i].objtype)) == 0)
		    display = ".";
		else
		    display = Cur_entry[i].display;
	    } else
		display = " ";

	    fprintf(ottfp,"%s|%.*s|%s|%s|%lx|%lx|%.*s\n", 
		    Cur_entry[i].name,
		    DNAMESIZ,
		    dname,
		    display,
		    Cur_entry[i].objtype?Cur_entry[i].objtype:" ", 
		    Cur_entry[i].objmask, 
		    Cur_entry[i].mtime,
		    ODISIZ,
		    Cur_entry[i].odi?Cur_entry[i].odi:"");
	}
    }

    if (fstat(ottfd, &sbuf) != -1)
	Cur_ott->ott_mtime = sbuf.st_mtime;

    if (stat(Cur_ott->path, &sbuf) != -1)
	Cur_ott->dir_mtime = sbuf.st_mtime;

    chown(ottname, sbuf.st_uid, sbuf.st_gid); /* ott owned and group of dir*/
    (void) fclose(ottfp);
    (void) close(ottfd);
    Cur_ott->modes &= ~OTT_DIRTY;

    return(O_OK);
}

static struct ott_tab *
ott_lru()
{
	register int i;
	int oldest = 0; 	/* abs k16 */
	long oldusetime;

	/* first, look for one that is unused */

	for (i = 0; i < MAX_OTT; i++)
		if (!(Otts[i].modes & OTT_ACTIVE)) {
			Otts[i].modes |= OTT_ACTIVE;
			return(Otts+i);
		}

#ifdef _DEBUG
	_debug(stderr, "No Free Ott, dealloc\n");
#endif

	/* ok, so there is none free.  Now what?  Good question.
	 * So, we'll find the one that's been ott_get()'ed least recently.
	 */

	oldest = 0;
	oldusetime = Otts[oldest].last_used;

	for (i = 1; i < MAX_OTT; i++) {
		if (!(Otts[i].modes & OTT_LOCKED) && Otts[i].last_used < oldusetime) {
			oldest = i;
			oldusetime = Otts[i].last_used;
		}
	}

#ifdef _DEBUG
	_debug(stderr,"Selected %s for dealloc %d\n",Otts[oldest].path,oldusetime);
#endif
	Otts[oldest].modes |= OTT_ACTIVE;
	return(Otts + oldest);
}

int
ott_init()
{
	register int i, size;

	Cur_ott = ott_lru();

	if (Cur_ott->ott == NULL) {  /* first time using this ott */
		Cur_ott->ott = (struct ott_entry *)
						array_create(sizeof(struct ott_entry), Creation_size);
		Cur_entry = Cur_ott->ott;	
		array_ctl(Cur_entry, OTT_ENTRIES);
		Cur_ott->parents = (int *) array_create(sizeof(int), Creation_size);
	} else {
		size = array_len(Cur_ott->ott);
		for (i = 0; i < size; i++)
			ott_int_free(Cur_ott->ott + i);
		if (Cur_ott->path)
			free(Cur_ott->path);
		array_trunc(Cur_ott->ott);
		array_trunc(Cur_ott->parents);
		Cur_entry = Cur_ott->ott;
	}

	Cur_ott->curpage = Cur_ott->numpages = 0;
	Cur_ott->ott_mtime = (time_t)0;	 /* EFT abs k16 */
	Cur_ott->modes = 0L;
	return (0);
}

static int
ott_use()
{
	static int use;
	return(++use);
}

struct ott_entry *
ott_next_part(entry)
struct ott_entry *entry;
{
	if (entry->next_part != OTTNIL)
		return(Cur_ott->ott + entry->next_part);
	else
		return(NULL);
}
