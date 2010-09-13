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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	cscope - interactive C symbol cross-reference
 *
 *	directory searching functions
 */

#include <sys/types.h>	/* needed by stat.h */
#include <sys/stat.h>	/* stat */
#include "global.h"
#include "dirent.h"
#include "vp.h"		/* vpdirs and vpndirs */

#define	DIRSEPS	" ,:"	/* directory list separators */
#define	DIRINC	10	/* directory list size increment */
#define	HASHMOD	2003	/* must be a prime number */
#define	SRCINC	HASHMOD	/* source file list size increment */
			/* largest known database had 22049 files */

char	**incdirs;		/* #include directories */
char	**srcdirs;		/* source directories */
char	**srcfiles;		/* source files */
int	nincdirs;		/* number of #include directories */
int	mincdirs = DIRINC;	/* maximum number of #include directories */
int	nsrcdirs;		/* number of source directories */
int	msrcdirs = DIRINC;	/* maximum number of source directories */
int	nsrcfiles;		/* number of source files */
int	msrcfiles = SRCINC;	/* maximum number of source files */

static	struct	listitem {	/* source file table entry */
	char	*file;
	struct	listitem *next;
} *srcfiletable[HASHMOD];


static void getsrcfiles(char *vpdir, char *dir);
static BOOL issrcfile(char *file);

/* add a source directory to the list for each view path source directory */

void
sourcedir(char *dirlist)
{
	struct	stat	statstruct;
	char	*dir;

	/* don't change environment variable text */
	dirlist = stralloc(dirlist);

	/* parse the directory list */
	dir = strtok(dirlist, DIRSEPS);
	while (dir != NULL) {
		/*
		 * make sure it is a directory (must exist in current
		 * view path node)
		 */
		if (stat(compath(dir), &statstruct) == 0 &&
		    S_ISDIR(statstruct.st_mode)) {
			if (srcdirs == NULL) {
				srcdirs = mymalloc(msrcdirs * sizeof (char *));
			} else if (nsrcdirs == msrcdirs) {
				msrcdirs += DIRINC;
				srcdirs = myrealloc(srcdirs,
				    msrcdirs * sizeof (char *));
			}
			srcdirs[nsrcdirs++] = stralloc(dir);
		}
		dir = strtok((char *)NULL, DIRSEPS);
	}
}

/* add a #include directory to the list for each view path source directory */

void
includedir(char *dirlist)
{
	struct	stat	statstruct;
	char	*dir;

	/* don't change environment variable text */
	dirlist = stralloc(dirlist);

	/* parse the directory list */
	dir = strtok(dirlist, DIRSEPS);
	while (dir != NULL) {

		/*
		 * make sure it is a directory (must exist in current
		 * view path node)
		 */
		if (stat(compath(dir), &statstruct) == 0 &&
		    S_ISDIR(statstruct.st_mode)) {
			if (incdirs == NULL) {
				incdirs = mymalloc(mincdirs * sizeof (char *));
			} else if (nincdirs == mincdirs) {
				mincdirs += DIRINC;
				incdirs = myrealloc(incdirs,
				    mincdirs * sizeof (char *));
			}
			incdirs[nincdirs++] = stralloc(dir);
		}
		dir = strtok((char *)NULL, DIRSEPS);
	}
}

/* make the source file list */

void
makefilelist(void)
{
	static	BOOL	firstbuild = YES;	/* first time through */
	FILE	*names;			/* name file pointer */
	char	dir[PATHLEN + 1];
	char	path[PATHLEN + 1];
	struct	stat	statstruct;
	char	*file;
	char	*s;
	int	i, j;

	/* if there are source file arguments */
	if (fileargc > 0) {
		/* put them in a list that can be expanded */
		for (i = 0; i < fileargc; ++i) {
			file = fileargv[i];
			if (infilelist(file) == NO) {
				if (vpaccess(file, READ) == 0) {
					addsrcfile(file);
				} else {
					(void) fprintf(stderr,
					    "cscope: cannot find file %s\n",
					    file);
					errorsfound = YES;
				}
			}
		}
		return;
	}
	/* see if a file name file exists */
	if (namefile == NULL && vpaccess(NAMEFILE, READ) == 0) {
		namefile = NAMEFILE;
	}
	/* if there is a file of source file names */
	if (namefile != NULL) {
		if ((names = vpfopen(namefile, "r")) == NULL) {
			cannotopen(namefile);
			myexit(1);
		}
		/* get the names in the file */
		while (fscanf(names, "%s", path) == 1) {
			if (*path == '-') {	/* if an option */
				i = path[1];
				switch (i) {
				case 'q':	/* quick search */
					invertedindex = YES;
					break;
				case 'T':
					/* truncate symbols to 8 characters */
					truncatesyms = YES;
					break;
				case 'I':	/* #include file directory */
				case 'p':	/* file path components to */
						/* display */
					s = path + 2;	  /* for "-Ipath" */
					if (*s == '\0') { /* if "-I path" */
						(void) fscanf(names,
						    "%s", path);
						s = path;
					}
					switch (i) {
					case 'I': /* #include file directory */
						if (firstbuild == YES) {
							/* expand $ and ~ */
							shellpath(dir,
							    sizeof (dir), s);
							includedir(dir);
						}
						break;
					case 'p':
						/* file path components */
						/* to display */
						if (*s < '0' || *s > '9') {
							(void) fprintf(stderr,
							    "cscope: -p option "
							    "in file %s: "
							    "missing or "
							    "invalid numeric "
							    "value\n",
							    namefile);
						}
						dispcomponents = atoi(s);
						break;
					}
					break;
				default:
					(void) fprintf(stderr,
					    "cscope: only -I, -p, and -T "
					    "options can be in file %s\n",
					    namefile);
				}
			} else if (vpaccess(path, READ) == 0) {
				addsrcfile(path);
			} else {
				(void) fprintf(stderr,
				    "cscope: cannot find file %s\n",
				    path);
				errorsfound = YES;
			}
		}
		(void) fclose(names);
		firstbuild = NO;
		return;
	}
	/* make a list of all the source files in the directories */
	for (i = 0; i < nsrcdirs; ++i) {
		s = srcdirs[i];
		getsrcfiles(s, s);
		if (*s != '/') {	/* if it isn't a full path name */

			/* compute its path from any higher view path nodes */
			for (j = 1; j < vpndirs; ++j) {
				(void) sprintf(dir, "%s/%s", vpdirs[j], s);

				/* make sure it is a directory */
				if (stat(compath(dir), &statstruct) == 0 &&
				    S_ISDIR(statstruct.st_mode)) {
					getsrcfiles(dir, s);
				}
			}
		}
	}
}

/* get the source file names in this directory */

static void
getsrcfiles(char *vpdir, char *dir)
{
	DIR	*dirfile;	/* directory file descriptor */
	struct	dirent	*entry;	/* directory entry pointer */
	char	path[PATHLEN + 1];

	/* attempt to open the directory */
	if ((dirfile = opendir(vpdir)) != NULL) {

		/* read each entry in the directory */
		while ((entry = readdir(dirfile)) != NULL) {

			/* if it is a source file not already found */
			(void) sprintf(path, "%s/%s", dir, entry->d_name);
			if (entry->d_ino != 0 &&
			    issrcfile(path) && infilelist(path) == NO) {
				addsrcfile(path);	/* add it to the list */
			}
		}
		closedir(dirfile);
	}
}

/* see if this is a source file */

static BOOL
issrcfile(char *file)
{
	struct	stat	statstruct;
	char	*s;

	/* if there is a file suffix */
	if ((s = strrchr(file, '.')) != NULL && *++s != '\0') {

		/* if an SCCS or versioned file */
		if (file[1] == '.' && file + 2 != s) { /* 1 character prefix */
			switch (*file) {
			case 's':
			case 'S':
				return (NO);
			}
		}
		if (s[1] == '\0') {	/* 1 character suffix */
			switch (*s) {
			case 'c':
			case 'h':
			case 'l':
			case 'y':
			case 'C':
			case 'G':
			case 'H':
			case 'L':
				return (YES);
			}
		} else if (s[2] == '\0') {	/* 2 character suffix */
			if (*s == 'b' && s[1] == 'p' ||	/* breakpoint listing */
			    *s == 'q' &&
				(s[1] == 'c' || s[1] == 'h') || /* Ingres */
			    *s == 'p' && s[1] == 'r' ||	/* SDL */
			    *s == 's' && s[1] == 'd') {	/* SDL */

				/*
				 * some directories have 2 character
				 * suffixes so make sure it is a file
				 */
				if (vpstat(file, &statstruct) == 0 &&
				    S_ISREG(statstruct.st_mode)) {
					return (YES);
				}
			}
		}
	}
	return (NO);
}

/* add an include file to the source file list */

void
incfile(char *file, int type)
{
	char	path[PATHLEN + 1];
	int	i;

	/* see if the file is already in the source file list */
	if (infilelist(file) == YES) {
		return;
	}
	/* look in current directory if it was #include "file" */
	if (type == '"' && vpaccess(file, READ) == 0) {
		addsrcfile(file);
	} else {
		/* search for the file in the #include directory list */
		for (i = 0; i < nincdirs; ++i) {

			/* don't include the file from two directories */
			(void) sprintf(path, "%s/%s", incdirs[i], file);
			if (infilelist(path) == YES) {
				break;
			}
			/* make sure it exists and is readable */
			if (vpaccess(compath(path), READ) == 0) {
				addsrcfile(path);
				break;
			}
		}
	}
}

/* see if the file is already in the list */

BOOL
infilelist(char *file)
{
	struct	listitem *p;

	for (p = srcfiletable[hash(compath(file)) % HASHMOD];
	    p != NULL; p = p->next) {
		if (strequal(file, p->file)) {
			return (YES);
		}
	}
	return (NO);
}

/* add a source file to the list */

void
addsrcfile(char *path)
{
	struct	listitem *p;
	int	i;

	/* make sure there is room for the file */
	if (nsrcfiles == msrcfiles) {
		msrcfiles += SRCINC;
		srcfiles = myrealloc(srcfiles, msrcfiles * sizeof (char *));
	}
	/* add the file to the list */
	p = (struct listitem *)mymalloc(sizeof (struct listitem));
	p->file = stralloc(compath(path));
	i = hash(p->file) % HASHMOD;
	p->next = srcfiletable[i];
	srcfiletable[i] = p;
	srcfiles[nsrcfiles++] = p->file;
}

/* free the memory allocated for the source file list */

void
freefilelist(void)
{
	struct	listitem *p, *nextp;
	int	i;

	while (nsrcfiles > 0) {
		free(srcfiles[--nsrcfiles]);
	}
	for (i = 0; i < HASHMOD; ++i) {
		for (p = srcfiletable[i]; p != NULL; p = nextp) {
			nextp = p->next;
			free(p);
		}
		srcfiletable[i] = NULL;
	}
}
