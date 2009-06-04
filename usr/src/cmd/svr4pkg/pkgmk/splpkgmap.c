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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <pkgdev.h>
#include <pkgstrct.h>
#include <locale.h>
#include <libintl.h>
#include <pkglib.h>
#include <libadm.h>
#include <libinst.h>

extern struct pkgdev pkgdev;

#define	MALSIZ	500
#define	EFACTOR	128ULL	/* typical size of a single entry in a pkgmap file */

#define	WRN_LIMIT	"WARNING: -l limit (%llu blocks) exceeds device " \
			"capacity (%llu blocks)"
#define	ERR_MEMORY	"memory allocation failure, errno=%d"
#define	ERR_TOOBIG	"%s (%llu blocks) does not fit on a volume"
#define	ERR_INFOFIRST	"information file <%s> must appear on first part"
#define	ERR_INFOSPACE	"all install files must appear on first part"
#define	ERR_VOLBLKS	"Objects selected for part %d require %llu blocks, " \
			"limit=%llu."
#define	ERR_VOLFILES	"Objects selected for part %d require %llu files, " \
			"limit=%llu."
#define	ERR_FREE	"package does not fit space currently available in <%s>"

struct data {
	fsblkcnt_t	blks;
	struct cfent *ept;
};

struct class_type {
	char *name;
	int first;
	int last;
};

static fsblkcnt_t	btotal;	/* blocks stored on current part */
static fsblkcnt_t	bmax; 	/* maximum number of blocks on any part */

static fsfilcnt_t	ftotal;	/* files stored on current part */
static fsfilcnt_t	fmax;	/* maximum number of files on any part */
static fsblkcnt_t	bpkginfo; 	/* blocks used by pkginfo file */
static char	**dirlist;
static short	volno; 		/* current part */
static int	nparts = -1; 	/* total number of parts */
static int	nclass;
static fsblkcnt_t 	DIRSIZE;
static struct	class_type *cl;

static int	nodecount(char *path);
static int	store(struct data **, unsigned int, char *, fsblkcnt_t,
    fsblkcnt_t);
static void	addclass(char *aclass, int vol);
static void	allocnode(char *path);
static void	newvolume(struct data **, unsigned int, fsblkcnt_t limit,
    fsblkcnt_t);
static void	sortsize(struct data *f, struct data **sf, unsigned int eptnum);

int
splpkgmap(struct cfent **eptlist, unsigned int eptnum, char *order[],
    ulong_t bsize, ulong_t frsize, fsblkcnt_t *plimit, fsfilcnt_t *pilimit,
    fsblkcnt_t *pllimit)
{
	struct data	*f, **sf;
	struct cfent	*ept;
	register int	i, j;
	int		new_vol_set;
	short		new_vol;
	int		flag, errflg;
	fsblkcnt_t	total;
	fsblkcnt_t	btemp;
	fsfilcnt_t	ftemp;

	f = (struct data *)calloc(eptnum, sizeof (struct data));
	if (f == NULL) {
		progerr(gettext(ERR_MEMORY), errno);
		quit(99);
	}

	sf = (struct data **)calloc(eptnum, sizeof (struct data *));
	if (sf == NULL) {
		progerr(gettext(ERR_MEMORY), errno);
		quit(99);
	}

	nclass = 0;
	cl = (struct class_type *)calloc(MALSIZ, sizeof (struct class_type));
	if (cl == NULL) {
		progerr(gettext(ERR_MEMORY), errno);
		quit(99);
	}

	errflg = 0;

	/*
	 * The next bit of code checks to see if, when creating a package
	 * on a directory, there are enough free blocks and inodes before
	 * continuing.
	 */
	total = 0;
	/*
	 * DIRSIZE takes up 1 logical block, iff we have no frags, else
	 * it just takes a frag
	 */
	DIRSIZE = ((fsblkcnt_t)frsize > 0) ?
	    howmany(frsize, DEV_BSIZE) :
	    howmany(bsize, DEV_BSIZE);

	if (!pkgdev.mount) {
		allocnode(NULL);
		/*
		 * If we appear to have a valid value for free inodes
		 * and there's not enough for the package contents,
		 * then exit
		 */
		if ((*pilimit > 0) && (eptnum+1 > *pilimit)) {
			progerr(gettext(ERR_FREE), pkgdev.dirname);
			quit(1);
		}
		for (i = 0; i < eptnum; i++) {
			if (strchr("dxslcbp", eptlist[i]->ftype))
				continue;
			else {
				total +=
				    (nodecount(eptlist[i]->path) * DIRSIZE);
				total +=
				    nblk(eptlist[i]->cinfo.size, bsize, frsize);
				if (total > *plimit) {
					progerr(gettext(ERR_FREE),
						pkgdev.dirname);
					quit(1);
				}
				allocnode(eptlist[i]->path);
			}
		}
	}
	/*
	 * if there is a value in pllimit (-l specified limit), use that for
	 * the limit from now on.
	 */

	if (*pllimit != 0) {
		if (pkgdev.mount && *pllimit > *plimit)
			logerr(gettext(WRN_LIMIT), *pllimit, *plimit);
		*plimit = *pllimit;
	}
	/*
	 * calculate number of physical blocks used by each object
	 */
	for (i = 0; i < eptnum; i++) {
		f[i].ept = ept = eptlist[i];
		if (ept->volno > nparts)
			nparts = ept->volno;
		addclass(ept->pkg_class, 0);
		if (strchr("dxslcbp", ept->ftype))
			/*
			 * virtual object (no contents)
			 */
			f[i].blks = 0;
		else
			/*
			 * space consumers
			 *
			 * (directories are space consumers as well, but they
			 * get accounted for later).
			 *
			 */

			f[i].blks = nblk(ept->cinfo.size, bsize, frsize);

		if (!bpkginfo && (strcmp(f[i].ept->path, "pkginfo") == 0))
			bpkginfo = f[i].blks;
	}

	/*
	 * Make sure that items slated for a given 'part' do not exceed a single
	 * volume.
	 */
	for (i = 1; i <= nparts; i++) {
		btemp = (bpkginfo + 2LL);
		ftemp = 2LL;
		if (i == 1) {
			/*
			 * save room for install directory
			 */
			ftemp += 2;
			btemp += nblk(eptnum * EFACTOR, bsize, frsize);
			btemp += 2;
		}
		allocnode(NULL);
		for (j = 0; j < eptnum; j++) {
			if (i == 1 && f[j].ept->ftype == 'i' &&
			    (strcmp(f[j].ept->path, "pkginfo") == 0 ||
			    strcmp(f[j].ept->path, "pkgmap") == 0))
				continue;
			if (f[j].ept->volno == i ||
			    (f[j].ept->ftype == 'i' && i == 1)) {
				ftemp += nodecount(f[j].ept->path);
				btemp += f[j].blks;
				allocnode(f[j].ept->path);
			}
		}
		btemp += (ftemp * DIRSIZE);
		if (btemp > *plimit) {
			progerr(gettext(ERR_VOLBLKS), i, btemp, *plimit);
			errflg++;
		/* If we have a valid inode limit, ensure this part will fit */
		} else if ((*pilimit > 0) && (ftemp+1 > *pilimit)) {
			progerr(gettext(ERR_VOLFILES), i, ftemp + 1, *pilimit);
			errflg++;
		}
	}
	if (errflg)
		quit(1);

	/*
	 * "sf" - array sorted in decreasing file size order, based on "f".
	 */
	sortsize(f, sf, eptnum);

	/*
	 * initialize first volume
	 */
	newvolume(sf, eptnum, *plimit, *pilimit);

	/*
	 * reserve room on first volume for pkgmap
	 */
	btotal += nblk((fsblkcnt_t)(eptnum * EFACTOR), bsize, frsize);
	ftotal++;


	/*
	 * initialize directory info
	 */
	allocnode(NULL);

	/*
	 * place installation files on first volume!
	 */
	flag = 0;
	for (j = 0; j < eptnum; ++j) {
		if (f[j].ept->ftype != 'i')
			continue;
		else if (!flag++) {
			/*
			 * save room for install directory
			 */
			ftotal++;
			btotal += 2ULL;
		}
		if (!f[j].ept->volno) {
			f[j].ept->volno = 1;
			ftotal++;
			btotal += f[j].blks;
		} else if (f[j].ept->volno != 1) {
			progerr(gettext(ERR_INFOFIRST), f[j].ept->path);
			errflg++;
		}
	}

	if (errflg)
		quit(1);
	if (btotal > *plimit) {
		progerr(gettext(ERR_INFOSPACE));
		quit(1);
	}

	/*
	 * Make sure that any given file will fit on a single volume, this
	 * calculation has to take into account packaging overhead, otherwise
	 * the function store() will go into a severe recursive plunge.
	 */
	for (j = 0; j < eptnum; ++j) {
		/*
		 * directory overhead.
		 */
		btemp = nodecount(f[j].ept->path) * DIRSIZE;
		/*
		 * packaging overhead.
		 */
		btemp += (bpkginfo + 2L); 	/* from newvolume() */
		if ((f[j].blks + btemp) > *plimit) {
			errflg++;
			progerr(gettext(ERR_TOOBIG), f[j].ept->path, f[j].blks);
		}
	}
	if (errflg)
		quit(1);

	/*
	 * place classes listed on command line
	 */
	if (order) {
		for (i = 0; order[i]; ++i)  {
			while (store(sf, eptnum, order[i], *plimit, *pilimit))
				/* stay in loop until store is complete */
				/* void */;
		}
	}

	while (store(sf, eptnum, (char *)0, *plimit, *pilimit))
		/* stay in loop until store is complete */
		/* void */;

	/*
	 * place all virtual objects, e.g. links and spec devices
	 */
	for (i = 0; i < nclass; ++i) {
		/*
		 * if no objects were associated, attempt to
		 * distribute in order of class list
		 */
		if (cl[i].first == 0)
			cl[i].last = cl[i].first = (i ? cl[i-1].last : 1);
		for (j = 0; j < eptnum; j++) {
			if ((f[j].ept->volno == 0) &&
			    strcmp(f[j].ept->pkg_class, cl[i].name) == 0) {
				if (strchr("sl", f[j].ept->ftype))
					f[j].ept->volno = cl[i].last;
				else
					f[j].ept->volno = cl[i].first;
			}
		}
	}

	if (btotal)
		newvolume(sf, eptnum, *plimit, *pilimit);

	if (nparts > (volno - 1)) {
		new_vol = volno;
		for (i = volno; i <= nparts; i++) {
			new_vol_set = 0;
			for (j = 0; j < eptnum; j++) {
				if (f[j].ept->volno == i) {
					f[j].ept->volno = new_vol;
					new_vol_set = 1;
				}
			}
			new_vol += new_vol_set;
		}
		nparts = new_vol - 1;
	} else
		nparts = volno - 1;

	*plimit = bmax;
	*pilimit = fmax;

	/*
	 * free up dynamic space used by this module
	 */
	free(f);
	free(sf);
	for (i = 0; i < nclass; ++i)
		free(cl[i].name);
	free(cl);
	for (i = 0; dirlist[i]; i++)
		free(dirlist[i]);
	free(dirlist);

	return (errflg ? -1 : nparts);
}

static int
store(struct data **sf, unsigned int eptnum, char *aclass, fsblkcnt_t limit,
    fsfilcnt_t ilimit)
{
	int	i, svnodes, choice, select;
	long	ftemp;
	fsblkcnt_t	btemp;

	select = 0;
	choice = (-1);
	for (i = 0; i < eptnum; ++i) {
		if (sf[i]->ept->volno || strchr("sldxcbp", sf[i]->ept->ftype))
			continue; /* defer storage until class is selected */
		if (aclass && strcmp(aclass, sf[i]->ept->pkg_class))
			continue;
		select++; /* we need to place at least one object */
		ftemp = nodecount(sf[i]->ept->path);
		btemp = sf[i]->blks + (ftemp * DIRSIZE);
		if (((limit == 0) || ((btotal + btemp) <= limit)) &&
		    ((ilimit == 0) || ((ftotal + ftemp) < ilimit))) {
			/* largest object which fits on this volume */
			choice = i;
			svnodes = ftemp;
			break;
		}
	}
	if (!select)
		return (0); /* no more to objects to place */

	if (choice < 0) {
		newvolume(sf, eptnum, limit, ilimit);
		return (store(sf, eptnum, aclass, limit, ilimit));
	}
	sf[choice]->ept->volno = (char)volno;
	ftotal += svnodes + 1;
	btotal += sf[choice]->blks + (svnodes * DIRSIZE);
	allocnode(sf[i]->ept->path);
	addclass(sf[choice]->ept->pkg_class, volno);
	return (++choice); /* return non-zero if more work to do */
}

static void
allocnode(char *path)
{
	register int i;
	int	found;
	char	*pt;

	if (path == NULL) {
		if (dirlist) {
			/*
			 * free everything
			 */
			for (i = 0; dirlist[i]; i++)
				free(dirlist[i]);
			free(dirlist);
		}
		dirlist = (char **)calloc(MALSIZ, sizeof (char *));
		if (dirlist == NULL) {
			progerr(gettext(ERR_MEMORY), errno);
			quit(99);
		}
		return;
	}

	pt = path;
	if (*pt == '/')
		pt++;
	/*
	 * since the pathname supplied is never just a directory,
	 * we store only the dirname of of the path.
	 */
	while (pt = strchr(pt, '/')) {
		*pt = '\0';
		found = 0;
		for (i = 0; dirlist[i] != NULL; i++) {
			if (strcmp(path, dirlist[i]) == 0) {
				found++;
				break;
			}
		}
		if (!found) {
			/* insert this path in node list */
			dirlist[i] = qstrdup(path);
			if ((++i % MALSIZ) == 0) {
				dirlist = (char **)realloc(dirlist,
					(i+MALSIZ) * sizeof (char *));
				if (dirlist == NULL) {
					progerr(gettext(ERR_MEMORY), errno);
					quit(99);
				}
			}
			dirlist[i] = (char *)NULL;
		}
		*pt++ = '/';
	}
}

static int
nodecount(char *path)
{
	char	*pt;
	int	i, found, count;

	pt = path;
	if (*pt == '/')
		pt++;

	/*
	 * we want to count the number of path
	 * segments that need to be created, not
	 * including the basename of the path;
	 * this works only since we are never
	 * passed a pathname which itself is a
	 * directory
	 */
	count = 0;
	while (pt = strchr(pt, '/')) {
		*pt = '\0';
		found = 0;
		for (i = 0; dirlist[i]; i++) {
			if (strcmp(path, dirlist[i]) != 0) {
				found++;
				break;
			}
		}
		if (!found)
			count++;
		*pt++ = '/';
	}
	return (count);
}

static void
newvolume(struct data **sf, unsigned int eptnum, fsblkcnt_t limit,
    fsblkcnt_t ilimit)
{
	register int i;
	int	newnodes;

	if (volno) {
		(void) fprintf(stderr,
		    gettext("part %2d -- %llu blocks, %llu entries\n"),
		    volno, btotal, ftotal);
		if (btotal > bmax)
			bmax = btotal;
		if (ftotal > fmax)
			fmax = ftotal;
		btotal = bpkginfo + 2ULL;
		ftotal = 2;
	} else {
		btotal = 2ULL;
		ftotal = 1;
	}
	volno++;

	/*
	 * zero out directory storage
	 */
	allocnode((char *)0);

	/*
	 * force storage of files whose volume number has already been assigned
	 */
	for (i = 0; i < eptnum; i++) {
		if (sf[i]->ept->volno == volno) {
			newnodes = nodecount(sf[i]->ept->path);
			ftotal += newnodes + 1;
			btotal += sf[i]->blks + (newnodes * DIRSIZE);
			if (btotal > limit) {
				progerr(gettext(ERR_VOLBLKS), volno, btotal,
					limit);
				quit(1);
			} else if ((ilimit == 0) && (ftotal+1 > ilimit)) {
				progerr(gettext(ERR_VOLFILES), volno, ftotal+1,
				    ilimit);
				quit(1);
			}
		}
	}
}

static void
addclass(char *aclass, int vol)
{
	int i;

	for (i = 0; i < nclass; ++i) {
		if (strcmp(cl[i].name, aclass) == 0) {
			if (vol <= 0)
				return;
			if (!cl[i].first || (vol < cl[i].first))
				cl[i].first = vol;
			if (vol > cl[i].last)
				cl[i].last = vol;
			return;
		}
	}
	cl[nclass].name = qstrdup(aclass);
	cl[nclass].first = vol;
	cl[nclass].last = vol;
	if ((++nclass % MALSIZ) == 0) {
		cl = (struct class_type *)realloc((char *)cl,
			sizeof (struct class_type) * (nclass+MALSIZ));
		if (!cl) {
			progerr(gettext(ERR_MEMORY), errno);
			quit(99);
		}
	}
}

static void
sortsize(struct data *f, struct data **sf, unsigned int eptnum)
{
	int	nsf;
	int	j, k;
	unsigned int	i;

	nsf = 0;
	for (i = 0; i < eptnum; i++) {
		for (j = 0; j < nsf; ++j) {
			if (f[i].blks > sf[j]->blks) {
				for (k = nsf; k > j; k--) {
					sf[k] = sf[k-1];
				}
				break;
			}
		}
		sf[j] = &f[i];
		nsf++;
	}
}
