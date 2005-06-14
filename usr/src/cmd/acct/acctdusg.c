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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.8	*/
/*
 *	acctdusg [-u file] [-p file] > dtmp-file
 *	-u	file for names of files not charged to anyone
 *	-p	get password info from file
 *	reads std input (normally from find / -print)
 *	and computes disk resource consumption by login
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <libcmdutils.h>

#include "acctdef.h"

struct	disk {
	struct disk *next;		/* next entry at same hash tbl index */
	uid_t	dsk_uid;		/* user id of login name */
	blkcnt_t	dsk_du;		/* disk usage */
	char	dsk_name[NSZ+1];	/* login name */
	char	validuser;		/* set if the uid exists */
};

static char	*pfile = NULL;
static FILE	*nchrg = NULL;
static avl_tree_t	*tree = NULL;

static struct disk *usglist[MAXUSERS];  /* holds data on disk usg by uid */
#define	HASHKEY(x)	((int)((unsigned int)(x) % MAXUSERS))

static struct disk *hash_insert(uid_t);
static struct disk *hash_find(uid_t);
static void openerr(char *);
static void output(void);
static void validate_entry(struct disk *, struct passwd *);
static void charge(char *);
#ifdef DEBUG
static void pdisk(void);
#endif

int
main(int argc, char **argv)
{
	char	fbuf[PATH_MAX+1], *fb;
	FILE	*pwf;
	int	c;
	struct passwd	*pw;
	struct disk	*entry;

	while ((c = getopt(argc, argv, "p:u:")) != EOF) {
		switch (c) {
		case 'u':
			if ((nchrg = fopen(optarg, "w")) == NULL)
				openerr(optarg);
			(void) chmod(optarg, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
			break;
		case 'p':
			pfile = optarg;
			break;
		default:
			exit(1);
		}
	}

	if (pfile) {
		if ((pwf = fopen(pfile, "r")) == NULL) {
			openerr(pfile);
		}
		/* fill usglist with the user's in the passwd file */
		while ((pw = fgetpwent(pwf)) != NULL) {
			if ((entry = hash_find(pw->pw_uid)) == NULL)
				entry = hash_insert(pw->pw_uid);
			validate_entry(entry, pw);
		}
		(void) fclose(pwf);
	}

	/* charge the files listed in names to users listed in the usglist */
	while (fgets(fbuf, sizeof (fbuf), stdin) != NULL) {
		if ((fb = strchr(fbuf, '\n')) != NULL) {
			/*
			 * replace the newline char at the end of the
			 * filename with a null character
			 */
			*fb = '\0';
		}
		charge(fbuf);
	}

	output();

	if (nchrg)
		(void) fclose(nchrg);
#ifdef DEBUG
	pdisk();
#endif
	return (0);
}

/*
 * create a new entry and insert.
 */
static struct disk *
hash_insert(uid_t uid)
{
	struct disk *curdisk;
	int key = HASHKEY(uid);

	if ((curdisk = malloc(sizeof (struct disk))) == NULL) {
		(void) fprintf(stderr, "acctdusg:  cannot allocate memory "
			"for hash table entry\n");
		exit(1);
	}
	curdisk->dsk_uid = uid;
	curdisk->dsk_du = 0;
	curdisk->validuser = 0;	/* initially invalid */
	curdisk->next = usglist[key];
	usglist[key] = curdisk;
	return (curdisk);
}

/*
 * return the disk entry for given uid. return NULL if not found.
 */
static struct disk *
hash_find(uid_t uid)
{
	struct disk *curdisk;

	for (curdisk = usglist[HASHKEY(uid)];
	    curdisk != NULL; curdisk = curdisk->next) {
		if (curdisk->dsk_uid == uid) {
			return (curdisk);
		}
	}
	return (NULL);
}

static void
openerr(char *file)
{
	(void) fprintf(stderr, "Cannot open %s\n", file);
	exit(1);
}

static void
output(void)
{
	int	index;
	struct disk *entry;

	for (index = 0; index < MAXUSERS; index++) {
		for (entry = usglist[index];
		    entry != NULL; entry = entry->next) {
			if (entry->dsk_du != 0) {
				(void) printf("%ld\t%s\t%lld\n",
				    entry->dsk_uid,
				    entry->dsk_name,
				    entry->dsk_du);
			}
		}
	}
}

/*
 * Initialize the disk entry for a valid passwd entry.
 */
static void
validate_entry(struct disk *entry, struct passwd *pw)
{
	(void) strlcpy(entry->dsk_name, pw->pw_name,
		sizeof (entry->dsk_name));
	entry->validuser = 1;
}

static void
charge(char *n)
{
	struct stat	statb;
	struct disk	*entry;
	struct passwd	*pw;

	if (lstat(n, &statb) == -1)
		return;

	/*
	 * do not count the duplicate entries.
	 */
	if (statb.st_nlink > 1) {
		switch (add_tnode(&tree, statb.st_dev, statb.st_ino)) {
		case 0:
			/* already exist */
			return;
		case 1:
			/* added */
			break;
		default:
			perror("acctdusg");
			exit(1);
		}
	}

	/*
	 * st_blocks is not defined for character/block special files.
	 */
	if (S_ISCHR(statb.st_mode) || S_ISBLK(statb.st_mode))
		statb.st_blocks = 0;

	/*
	 * If -p is given, we've all loaded the passwd entries.
	 * Files with unknown uid should go into nchrg. Otherwise
	 * (without -p), we try creating new entry for the uid.
	 */
	if ((entry = hash_find(statb.st_uid)) == NULL) {
		if (pfile == NULL) {
			pw = getpwuid(statb.st_uid);
			entry = hash_insert(statb.st_uid);
			if (pw != NULL) {
				validate_entry(entry, pw);
			}
		}
	}

	if (entry != NULL && entry->validuser) {
		entry->dsk_du += statb.st_blocks;
	} else if (nchrg) {
		(void) fprintf(nchrg, "%9ld\t%7llu\t%s\n",
			statb.st_uid, statb.st_blocks, n);
	}
}

#ifdef DEBUG
static void
pdisk()
{
	int	index;
	struct disk *entry;

	for (index = 0; index < MAXUSERS; index++) {
		for (entry = usglist[index];
		    entry != NULL; entry = entry->next) {
			(void) fprintf(stderr,  "%.8s\t%9ld\t%7llu\n",
			    entry->dsk_name,
			    entry->dsk_uid,
			    entry->dsk_du);
		}
	}

}
#endif
