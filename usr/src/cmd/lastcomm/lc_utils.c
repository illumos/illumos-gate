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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lastcomm.h"

/*
 * lc_utils contains utility functions used by both the basic and extended
 * accounting components of lastcomm.  getdev(), on its first call, builds
 * the set of tty device name to dev_t mappings.
 */

#define	N_DEVS		43		/* hash value for device names */
#define	NDEVS		500		/* max number of file names in /dev */

#define	HASH(d)	(((int)d) % N_DEVS)	/* hash function */

struct	devhash {
	dev_t	dev_dev;
	char	dev_name [PATHNAMLEN];
	struct	devhash *dev_nxt;
};

static struct devhash *dev_hash[N_DEVS];
static struct devhash *dev_chain;
static int ndevs = NDEVS;
static struct devhash *hashtab;

/*
 * Default search list, used if /etc/ttysrch unavailable or unparsable.
 */
static char *def_srch_dirs[] = {
	"/dev/term",
	"/dev/pts",
	"/dev/xt",
	NULL
};
static char *raw_sf;	/* buffer containing raw image of the search file */

#define	SRCH_FILE_NAME  "/etc/ttysrch"
/*
 * /etc/ttysrch tokens.
 */
#define	COMMENT_CHAR    '#'
#define	EOLN		'\n'
/*
 * /etc/ttysrch parser states.
 */
#define	START_STATE	1
#define	COMMENT_STATE   2
#define	DIRNAME_STATE   3

/*
 * The following 2 routines are modified version of get_pri_dirs
 * and srch_dir in ttyname.c.
 */
static char **
get_pri_dirs()
{
	int bcount = 0;
	int c;
	int sf_lines = 0;	/* number of lines in search file */
	int dirno = 0;
	int state;
	FILE *sf;
	char **pri_dirs;	/* priority search list */
	char *sfp;		/* pointer inside the raw image buffer */
	struct stat sfsb;	/* search file's stat structure buffer */


	if ((sf = fopen(SRCH_FILE_NAME, "r")) == NULL)
		return (def_srch_dirs);
	if (stat(SRCH_FILE_NAME, &sfsb) < 0) {
		(void) fclose(sf);
		return (def_srch_dirs);
	}
	raw_sf = malloc(sfsb.st_size + 1);
	sfp = raw_sf;
	while ((bcount++ < sfsb.st_size) && ((c = getc(sf)) != EOF)) {
		*sfp++ = (char)c;
		if (c == EOLN)
			sf_lines++;
	}
	(void) fclose(sf);
	*sfp = EOLN;
	pri_dirs = malloc(++sf_lines * sizeof (char *));

	sfp = raw_sf;
	state = START_STATE;
	while (--bcount) {
		switch (state) {
		case START_STATE:
			if (*sfp == COMMENT_CHAR) {
				state = COMMENT_STATE;
			} else if (!isspace(*sfp)) {
				state = DIRNAME_STATE;
				pri_dirs[dirno++] = sfp;
			}
			break;
		case COMMENT_STATE:
			if (*sfp == EOLN)
				state = START_STATE;
			break;
		case DIRNAME_STATE:
			if (*sfp == EOLN) {
				*sfp = '\0';
				state = START_STATE;
			} else if (isspace(*sfp)) {
				*sfp = '\0';
				state = COMMENT_STATE;
			}
			break;

		} /* switch */
		sfp++;
	}

	*sfp = '\0';
	pri_dirs[dirno] = NULL;
	return (pri_dirs);
}

/*
 * Build a chain of character devices in dev_chain, starting with the given
 * path.
 */
static int
srch_dir(char *path)
{
	DIR *dirp;
	struct dirent *direntp;
	struct stat st;
	char file_name[PATHNAMLEN];

	if ((dirp = opendir(path)) == NULL)
		return (0);

	if ((readdir(dirp) == NULL) || (readdir(dirp) == NULL))
		return (0);

	while ((direntp = readdir(dirp)) != NULL) {
		(void) strcpy(file_name, path);
		(void) strcat(file_name, "/");
		(void) strcat(file_name, direntp->d_name);
		if (stat((const char *)file_name, &st) < 0)
			continue;
		if ((st.st_mode & S_IFMT) == S_IFCHR) {
			(void) strcpy(hashtab->dev_name,
			    file_name + strlen("/dev/"));
			hashtab->dev_nxt = dev_chain;
			dev_chain = hashtab;
			hashtab++;
			if (--ndevs < 0)
				return (-1);
		}
	}
	(void) closedir(dirp);
	return (1);
}


static void
setupdevs()
{
	int dirno = 0;
	char **srch_dirs;

	hashtab = malloc(NDEVS * sizeof (struct devhash));
	if (hashtab == NULL) {
		(void) fprintf(stderr, gettext("No memory for device table\n"));
		return;
	}

	srch_dirs = get_pri_dirs();

	while (srch_dirs[dirno] != NULL) {
		if (srch_dir(srch_dirs[dirno]) < 0)
			return;
		dirno++;
	}

	dirno = 0;
	while (srch_dirs[dirno] != NULL) {
		if (strcmp("/dev", srch_dirs[dirno]) == 0)
			/*
			 * Don't search /dev twice.
			 */
			return;
		dirno++;
	}
}

char *
getdev(dev_t dev)
{
	struct devhash *hp, *nhp;
	struct stat statb;
	char name[PATHNAMLEN];
	static dev_t lastdev = (dev_t)-1;
	static char *lastname;
	static int init = 0;

	if (dev == NODEV)
		return ("__");
	if (dev == lastdev)
		return (lastname);
	if (!init) {
		setupdevs();
		init++;
	}

	for (hp = dev_hash[HASH(dev)]; hp; hp = hp->dev_nxt)
		if (hp->dev_dev == dev) {
			lastdev = dev;
			return (lastname = hp->dev_name);
		}

	for (hp = dev_chain; hp; hp = nhp) {
		nhp = hp->dev_nxt;
		(void) strcpy(name, "/dev/");
		(void) strcat(name, hp->dev_name);
		if (stat(name, &statb) < 0)	/* name truncated usually */
			continue;
		if ((statb.st_mode & S_IFMT) != S_IFCHR)
			continue;
		hp->dev_dev = statb.st_rdev;
		hp->dev_nxt = dev_hash[HASH(hp->dev_dev)];
		dev_hash[HASH(hp->dev_dev)] = hp;
		if (hp->dev_dev == dev) {
			dev_chain = nhp;
			lastdev = dev;
			return (lastname = hp->dev_name);
		}
	}
	dev_chain = NULL;
	return ("??");
}

char *
flagbits(int f)
{
	int i = 0;
	static char flags[20];

#define	BIT(flag, ch)	flags[i++] = (f & flag) ? ch : ' '
	BIT(ASU, 'S');
	BIT(AFORK, 'F');
	flags[i] = '\0';
	return (flags);
#undef	BIT
}

char *
getname(uid_t uid)
{
	struct passwd *pw;
	static char uidname[NMAX];

	if ((pw = getpwuid(uid)) == NULL) {
		(void) sprintf(uidname, "%u", uid);
		return (uidname);
	}
	return (pw->pw_name);
}
