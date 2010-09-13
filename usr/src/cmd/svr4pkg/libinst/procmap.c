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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <pkgstrct.h>
#include <locale.h>
#include <libintl.h>
#include <pkglib.h>
#include <install.h>
#include <libinst.h>

#define	ERR_MEMORY	"memory allocation failure"
#define	ERR_DUPPATH	"duplicate pathname <%s>"

/* libpkg/gpkgmap */
extern int	getmapmode(void);

#define	EPTMALLOC	512

static struct cfent **eptlist;

static int	eptnum;
static int	errflg;
static int	nparts;
static int	space = -1;

static void	procinit(void);
static int	procassign(struct cfent *ept, char **server_local,
		    char **client_local, char **server_path,
		    char **client_path, char **map_path, int mapflag,
		    int nc);

static int	ckdup(struct cfent *ept1, struct cfent *ept2);
static int	sortentry(int index);

static void
procinit(void)
{
	errflg = nparts = eptnum = 0;

	if (space != -1) {
		ar_free(space);
		space = -1;
	}

	/*
	 * initialize dynamic memory used to store
	 * path information which is read in
	 */
	(void) pathdup((char *)0);
}

/*
 * This function assigns appropriate values based upon the pkgmap entry
 * in the cfent structure.
 */
static int
procassign(struct cfent *ept, char **server_local, char **client_local,
    char **server_path, char **client_path, char **map_path, int mapflag,
    int nc)
{
	int	path_duped = 0;
	int	local_duped = 0;
	char	source[PATH_MAX+1];

	if (nc >= 0 && ept->ftype != 'i')
		if ((ept->pkg_class_idx = cl_idx(ept->pkg_class)) == -1)
			return (1);

	if (ept->volno > nparts)
		nparts++;

	/*
	 * Generate local (delivered source) paths for files
	 * which need them so that the install routine will know
	 * where to get the file from the package. Note that we
	 * do not resolve path environment variables here since
	 * they won't be resolved in the reloc directory.
	 */
	if ((mapflag > 1) && strchr("fve", ept->ftype)) {
		if (ept->ainfo.local == NULL) {
			source[0] = '~';
			(void) strcpy(&source[1], ept->path);
			ept->ainfo.local = pathdup(source);
			*server_local = ept->ainfo.local;
			*client_local = ept->ainfo.local;

			local_duped = 1;
		}
	}

	/*
	 * Evaluate the destination path based upon available
	 * environment, then produce a client-relative and
	 * server-relative canonized path.
	 */
	if (mapflag && (ept->ftype != 'i')) {
		mappath(getmapmode(), ept->path); /* evaluate variables */
		canonize(ept->path);	/* Fix path as necessary. */

		(void) eval_path(server_path,
		    client_path,
		    map_path,
		    ept->path);
		path_duped = 1;	/* eval_path dup's it */
		ept->path = *server_path;	/* default */
	}

	/*
	 * Deal with source for hard and soft links.
	 */
	if (strchr("sl", ept->ftype)) {
		if (mapflag) {
			mappath(getmapmode(), ept->ainfo.local);
			if (!RELATIVE(ept->ainfo.local)) {
				canonize(ept->ainfo.local);

				/* check for hard link */
				if (ept->ftype == 'l') {
					(void) eval_path(
					    server_local,
					    client_local,
					    NULL,
					    ept->ainfo.local);
					local_duped = 1;

					/* Default to server. */
					ept->ainfo.local = *server_local;
				}
			}
		}
	}

	/*
	 * For the paths (both source and target) that were too mundane to
	 * have been copied into dup space yet, do that.
	 */
	if (!path_duped) {
		*server_path = pathdup(ept->path);
		*client_path = *server_path;
		ept->path = *server_path;

		path_duped = 1;
	}
	if (ept->ainfo.local != NULL)
		if (!local_duped) {
			*server_local = pathdup(ept->ainfo.local);
			ept->ainfo.local = *server_local;
			*client_local = ept->ainfo.local;

		local_duped = 1;
	}

	return (0);
}

/*
 * This function reads the prototype file and returns a pointer to a list of
 * struct cfent representing the contents of that file.
 */
/*ARGSUSED*/
struct cfent **
procmap(VFP_T *vfp, int mapflag, char *ir)
{
	struct cfent	*ept = (struct cfent *)NULL;
	struct cfent	map_entry;
	struct cfent	**ept_ptr;
	int	i;
	int	n;
	int	nc;
	static char *server_local, *client_local;
	static char *server_path, *client_path, *map_path;

	procinit();

	space = ar_create(EPTMALLOC, (unsigned)sizeof (struct cfent),
	    "prototype object");
	if (space == -1) {
		progerr(gettext(ERR_MEMORY));
		return (NULL);
	}

	nc = cl_getn();
	for (;;) {
		/* Clear the buffer. */
		(void) memset(&map_entry, '\000', sizeof (struct cfent));

		n = gpkgmapvfp(&map_entry, vfp);

		if (n == 0)
			break; /* no more entries in pkgmap */
		else if (n < 0) {
			char	*errstr = getErrstr();
			progerr(gettext("bad entry read in pkgmap"));
			logerr(gettext("pathname=%s"),
				(ept && ept->path && *ept->path) ?
				ept->path : "Unknown");
			logerr(gettext("problem=%s"),
			    (errstr && *errstr) ? errstr : "Unknown");
			return (NULL);
		}

		/*
		 * A valid entry was found in the map, so allocate an
		 * official record.
		 */
		ept_ptr = (struct cfent **)ar_next_avail(space);
		if (ept_ptr == NULL || *ept_ptr == NULL) {
			progerr(gettext(ERR_MEMORY));
			return (NULL);
		}

		ept = *ept_ptr;

		/* Transfer what we just read in. */
		(void) memcpy(ept, &map_entry, sizeof (struct cfent));

		if (procassign(ept, &server_local, &client_local,
		    &server_path, &client_path, &map_path,
		    mapflag, nc)) {
			/* It didn't take. */
			(void) ar_delete(space, eptnum);
			continue;
		}

		eptnum++;
	}

	/* setup a pointer array to point to malloc'd entries space */
	eptlist = (struct cfent **)ar_get_head(space);
	if (eptlist == NULL) {
		progerr(gettext(ERR_MEMORY));
		return (NULL);
	}

	(void) sortentry(-1);
	for (i = 0; i < eptnum; /* void */) {
		if (!sortentry(i))
			i++;
	}
	return (errflg ? NULL : eptlist);
}

/*
 * This function sorts the final list of cfent entries. If index = -1, the
 * function is initialized. index = 0 doesn't get us anywhere because this
 * sorts against index-1. Positive natural index values are compared and
 * sorted into the array appropriately. Yes, it does seem we should use a
 * quicksort on the whole array or something. The apparent reason for taking
 * this approach is that there are enough special considerations to be
 * applied to each package object that inserting them one-by-one doesn't cost
 * that much.
 */
static int
sortentry(int index)
{
	struct cfent *ept, *ept_i;
	static int last = 0;
	int	i, n, j;
	int	upper, lower;

	if (index == 0)
		return (0);
	else if (index < 0) {
		last = 0;
		return (0);
	}

	/*
	 * Based on the index, this is the package object we're going to
	 * review. It may stay where it is or it may be repositioned in the
	 * array.
	 */
	ept = eptlist[index];

	/* quick comparison optimization for pre-sorted arrays */
	if (strcmp(ept->path, eptlist[index-1]->path) > 0) {
		/* do nothing */
		last = index-1;
		return (0);
	}

	lower = 0;		/* lower bound of the unsorted elements */
	upper = index;		/* upper bound */
	i = last;
	do {
		/*
		 * NOTE: This does a binary sort on path. There are lots of
		 * other worthy items in the array, but path is the key into
		 * the package database.
		 */
		ept_i = eptlist[i];

		n = strcmp(ept->path, ept_i->path);
		if (n == 0) {
			if (!ckdup(ept, ept_i)) {
				progerr(gettext(ERR_DUPPATH),
				    ept->path);
				errflg++;
			}
			/* remove the entry at index */
			(void) ar_delete(space, index);

			eptnum--;
			return (1);	/* Use this index again. */
		} else if (n < 0) {
			/*
			 * The path of interest is smaller than the path
			 * under test. Move down array using the method of
			 * division
			 */
			upper = i;
			i = lower + (upper-lower)/2;
		} else {
			/* Move up array */
			lower = i+1;
			i = upper - (upper-lower)/2 - 1;
		}
	} while (upper != lower);
	last = i = upper;

	/* expand to insert at i */
	for (j = index; j > i; j--)
		eptlist[j] = eptlist[j-1];

	eptlist[i] = ept;

	return (0);
}

/*
 * Check duplicate entries in the package object list. If it's a directory,
 * this just merges them, if not, it returns a 0 to force further processing.
 */
static int
ckdup(struct cfent *ept1, struct cfent *ept2)
{
	/* ept2 will be modified to contain "merged" entries */

	if (!strchr("?dx", ept1->ftype))
		return (0);

	if (!strchr("?dx", ept2->ftype))
		return (0);

	if (ept2->ainfo.mode == BADMODE)
		ept2->ainfo.mode = ept1->ainfo.mode;
	if ((ept1->ainfo.mode != ept2->ainfo.mode) &&
	    (ept1->ainfo.mode != BADMODE))
		return (0);

	if (strcmp(ept2->ainfo.owner, "?") == 0)
		(void) strcpy(ept2->ainfo.owner, ept1->ainfo.owner);
	if (strcmp(ept1->ainfo.owner, ept2->ainfo.owner) &&
	    strcmp(ept1->ainfo.owner, "?"))
		return (0);

	if (strcmp(ept2->ainfo.group, "?") == 0)
		(void) strcpy(ept2->ainfo.group, ept1->ainfo.group);
	if (strcmp(ept1->ainfo.group, ept2->ainfo.group) &&
	    strcmp(ept1->ainfo.group, "?"))
		return (0);

	if (ept1->pinfo) {
		ept2->npkgs = ept1->npkgs;
		ept2->pinfo = ept1->pinfo;
	}

	return (1);
}
