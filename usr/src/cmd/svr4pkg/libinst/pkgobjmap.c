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

#define	WRN_NOPKGOBJ	"WARNING: no package objects found"

#define	ERR_MEMORY	"memory allocation failure"
#define	ERR_DUPPATH	"duplicate pathname <%s>"

/* libpkg/gpkgmap */
extern int	getmapmode(void);

#define	EPTMALLOC	512

static struct cfextra **extlist;

int	eptnum;
static int	array_preloaded = 0;
static int	errflg;
static int	nparts;
static int	xspace = -1;

void	pkgobjinit(void);
static int	pkgobjassign(struct cfent *ept, char **server_local,
		    char **client_local, char **server_path,
		    char **client_path, char **map_path, int mapflag,
		    int nc);

static int	ckdup(struct cfent *ept1, struct cfent *ept2);
static int	sortentry(int index);
static int	dup_merg(struct cfextra *ext1, struct cfextra *ext2);

void
pkgobjinit(void)
{
	if (array_preloaded)	/* Already done. */
		return;

	errflg = nparts = eptnum = 0;

	if (xspace != -1) {
		ar_free(xspace);
		xspace = -1;
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
pkgobjassign(struct cfent *ept, char **server_local, char **client_local,
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
			(void) strlcpy(&source[1], ept->path,
						sizeof (source)-1);
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

/* This initializes the package object array. */
int
init_pkgobjspace(void)
{
	if (array_preloaded)	/* Already done. */
		return (1);

	if (xspace == -1) {
		xspace = ar_create(EPTMALLOC, sizeof (struct cfextra),
		    "package object");
		if (xspace == -1) {
			progerr(gettext(ERR_MEMORY));
			return (0);
		}
	}

	return (1);
}

int
seed_pkgobjmap(struct cfextra *ext_entry, char *path, char *local)
{
	struct cfextra *ext, **ext_ptr;

	/* offsets for the various path images. */
	int client_path_os;
	int server_path_os;
	int map_path_os;
	int client_local_os;
	int server_local_os;

	ext_ptr = (struct cfextra **)ar_next_avail(xspace);

	if (ext_ptr == NULL || *ext_ptr == NULL) {
		progerr(gettext(ERR_MEMORY));
		return (0);
	}

	ext = *ext_ptr;

	(void) memcpy(ext, ext_entry, sizeof (struct cfextra));

	/* Figure out all of the offsets. */
	client_path_os = ((ptrdiff_t)ext->client_path -
			(ptrdiff_t)ext->cf_ent.path);
	server_path_os = ((ptrdiff_t)ext->server_path -
			(ptrdiff_t)ext->cf_ent.path);
	map_path_os = ((ptrdiff_t)ext->map_path -
			(ptrdiff_t)ext->cf_ent.path);
	client_local_os = ((ptrdiff_t)ext->client_local -
			(ptrdiff_t)ext->cf_ent.ainfo.local);
	server_local_os = ((ptrdiff_t)ext->server_local -
			(ptrdiff_t)ext->cf_ent.ainfo.local);

	/* Allocate and store the path name. */
	ext->cf_ent.path = pathdup(path);

	/* Assign the path substring pointers. */
	ext->client_path = (ext->cf_ent.path + client_path_os);
	ext->server_path = (ext->cf_ent.path + server_path_os);
	ext->map_path = (ext->cf_ent.path + map_path_os);

	/* If there's a local entry, allocate and store it as well. */
	if (local) {
		ext->cf_ent.ainfo.local = pathdup(local);

		ext->client_local = (ext->cf_ent.ainfo.local + client_local_os);
		ext->server_local = (ext->cf_ent.ainfo.local + server_local_os);
	} else {
		ext->cf_ent.ainfo.local = NULL;
		ext->client_local = NULL;
		ext->server_local = NULL;
	}

	eptnum++;
	array_preloaded = 1;

	return (0);
}

/*
 * This function reads the pkgmap (or any file similarly formatted) and
 * returns a pointer to a list of struct cfextra (each of which
 * contains a struct cfent) representing the contents of that file.
 */

/* ARGSUSED ir in pkgobjmap */
struct cfextra **
pkgobjmap(VFP_T *vfp, int mapflag, char *ir)
{
	struct	cfextra *ext, **ext_ptr;
	struct	cfent *ept, map_entry;
	int	i;
	int	n;
	int	nc;

	pkgobjinit();
	if (!init_pkgobjspace())
		quit(99);

	nc = cl_getn();
	for (;;) {
		/* Clear the buffer. */
		(void) memset(&map_entry, '\000', sizeof (struct cfent));

		/*
		 * Fill in a cfent structure in a very preliminary fashion.
		 * ept->path and ept->ainfo.local point to static memory
		 * areas of size PATH_MAX. These are manipulated and
		 * then provided their own allocations later in this function.
		 */
		n = gpkgmapvfp(&map_entry, vfp);

		if (n == 0)
			break; /* no more entries in pkgmap */
		else if (n < 0) {
			char	*errstr = getErrstr();
			progerr(gettext("bad entry read in pkgmap"));
			logerr(gettext("pathname=%s"),
			    (map_entry.path && *map_entry.path) ?
			    map_entry.path : "Unknown");
			logerr(gettext("problem=%s"),
			    (errstr && *errstr) ? errstr : "Unknown");
			return (NULL);
		}

		/*
		 * A valid entry was found in the map, so allocate an
		 * official record.
		 */
		ext_ptr = (struct cfextra **)ar_next_avail(xspace);
		if (ext_ptr == NULL || *ext_ptr == NULL) {
			progerr(gettext(ERR_MEMORY));
			return (NULL);
		}

		ext = *ext_ptr;
		ept = &(ext->cf_ent);

		/* Transfer what we just read in. */
		(void) memcpy(ept, &map_entry, sizeof (struct cfent));

		/* And process it into the cfextra structure. */
		if (pkgobjassign(ept,
		    &(ext->server_local),
		    &(ext->client_local),
		    &(ext->server_path),
		    &(ext->client_path),
		    &(ext->map_path),
		    mapflag, nc)) {
			/* It didn't take. */
			(void) ar_delete(xspace, eptnum);
			continue;
		}

		eptnum++;
		ext->fsys_value = BADFSYS;	/* No file system data yet */
		ext->fsys_base = BADFSYS;
	}

	if (eptnum == 0) {
		logerr(gettext(WRN_NOPKGOBJ));
		return (NULL);
	}

	/* setup a pointer array to point to malloc'd entries space */
	extlist = (struct cfextra **)ar_get_head(xspace);
	if (extlist == NULL) {
		progerr(gettext(ERR_MEMORY));
		return (NULL);
	}

	(void) sortentry(-1);
	for (i = 0; i < eptnum; /* void */) {
		if (!sortentry(i))
			i++;
	}

	return (errflg ? NULL : extlist);
}

/*
 * This function sorts the final list of cfextra entries. If index = -1, the
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
	struct cfextra *ext;
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
	ext = extlist[index];
	ept = &(ext->cf_ent);

	/* quick comparison optimization for pre-sorted arrays */
	if (strcmp(ept->path, extlist[index-1]->cf_ent.path) > 0) {
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
		ept_i = &(extlist[i]->cf_ent);

		n = strcmp(ept->path, ept_i->path);
		if (n == 0) {
			if (!ckdup(ept, ept_i)) {
				/*
				 * If the array was seeded then there are
				 * bound to be occasional duplicates.
				 * Otherwise, duplicates are definitely a
				 * sign of major damage.
				 */
				if (array_preloaded) {
					if (!dup_merg(ext, extlist[i])) {
						progerr(gettext(ERR_DUPPATH),
						    ept->path);
						errflg++;
					}
				} else {
					progerr(gettext(ERR_DUPPATH),
					    ept->path);
					errflg++;
				}
			}
			/* remove the entry at index */
			(void) ar_delete(xspace, index);

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
		extlist[j] = extlist[j-1];

	extlist[i] = ext;

	return (0);
}

/* Return the number of blocks required by the package object provided. */
static fsblkcnt_t
nblks(short fsys_entry, struct cfextra *ext)
{
	fsblkcnt_t blk;
	ulong_t block_size;
	ulong_t frag_size;

	block_size = (ulong_t)get_blk_size_n(fsys_entry);
	frag_size = (ulong_t)get_frag_size_n(fsys_entry);

	if (strchr("dxs", ext->cf_ent.ftype))
		blk =
		    nblk(block_size, block_size, frag_size);
	else if (ext->cf_ent.cinfo.size != BADCONT)
		blk = nblk(ext->cf_ent.cinfo.size, block_size,
		    frag_size);
	else
		blk = 0;

	return (blk);
}

/* Remove ext1 from the filesystem size calculations and add ext2. */
static void
size_xchng(struct cfextra *ext1, struct cfextra *ext2)
{
	fsblkcnt_t bused;
	ulong_t block_size;
	ulong_t frag_size;
	fsblkcnt_t	blks1, blks2;
	short	fsys_entry;

	/*
	 * Since these are on the same filesystem, either one will yield the
	 * correct block and fragment size.
	 */
	fsys_entry = ext1->fsys_base;
	block_size = (ulong_t)get_blk_size_n(fsys_entry);
	frag_size = (ulong_t)get_frag_size_n(fsys_entry);

	blks1 = nblk(ext1->cf_ent.cinfo.size, block_size, frag_size);
	blks2 = nblk(ext2->cf_ent.cinfo.size, block_size, frag_size);

	if (blks1 != blks2) {
		/* First, lose the old size, then add the new size. */
		bused = get_blk_used_n(fsys_entry);
		bused -= nblks(fsys_entry, ext1);
		bused += nblks(fsys_entry, ext2);

		set_blk_used_n(fsys_entry, bused);
	}
}

/*
 * This function merges duplicate non-directory entries resulting from a
 * dryrun or other procedure which preloads the extlist. It uses an odd
 * heuristic to determine which package object is newest: only package
 * objects from the dryrun file will have pinfo pointers. Therefore, the
 * object with a pinfo pointer is from the dryrun file and it will be
 * overwritten by the object being installed by this package.
 *
 * Assumptions:
 *	1. The newer object will be overwriting the older object.
 *	2. The two objects are close enough to the same size that
 *	   the sizing is still OK.
 *
 * The calling routine will overwrite ept1, so this must return ept2 with
 * the correct data to keep. There being only one logical outcome of a
 * failure, this returns 1 for OK and 0 for FAIL.
 */
static int
dup_merg(struct cfextra *ext1, struct cfextra *ext2)
{
	struct cfent *ept1, *ept2;

	ept1 = &(ext1->cf_ent);
	ept2 = &(ext2->cf_ent);

	if (strchr("?dx", ept1->ftype))
		return (0);

	if (strchr("?dx", ept2->ftype))
		return (0);

	/* First, which is the eldest? */
	if (ext2->mstat.preloaded) {
		/*
		 * While ept2 has the correct pinfo list (it was preloaded into
		 * the array before the pkgmap was read), ept1 has everything
		 * else. Here we copy the guts of ept1 into ept2.
		 *
		 * Start by grabbing the pointers to the ext2 items that we
		 * need to either restore or free.
		 */
		/* to free() */
		char *path = ept2->path;
		char *local = ept2->ainfo.local;

		/* to preserve */
		short npkgs = ept2->npkgs;
		struct pinfo *pinfo = ept2->pinfo;

		/* Copy everything from the new entry to the old */
		(void) memcpy(ept2, ept1, sizeof (struct cfent));

		/* Now restore the original stuff.. */
		ept2->path = path;
		ept2->ainfo.local = local;
		ept2->npkgs = npkgs;
		ept2->pinfo = pinfo;

		size_xchng(ext2, ext1);
	} else if (ext1->mstat.preloaded) {
		/*
		 * ept2 is already the one we will keep. All we have to do is
		 * copy over the pinfo pointer.
		 */
		ept2->pinfo = ept1->pinfo;
		size_xchng(ext1, ext2);
	} else
		return (0);

	return (1);
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
		(void) strlcpy(ept2->ainfo.owner, ept1->ainfo.owner,
			sizeof (ept2->ainfo.owner));
	if (strcmp(ept1->ainfo.owner, ept2->ainfo.owner) &&
	    strcmp(ept1->ainfo.owner, "?"))
		return (0);

	if (strcmp(ept2->ainfo.group, "?") == 0)
		(void) strlcpy(ept2->ainfo.group, ept1->ainfo.group,
			sizeof (ept2->ainfo.group));
	if (strcmp(ept1->ainfo.group, ept2->ainfo.group) &&
	    strcmp(ept1->ainfo.group, "?"))
		return (0);

	if (ept1->pinfo) {
		ept2->npkgs = ept1->npkgs;
		ept2->pinfo = ept1->pinfo;
	}

	return (1);
}

/*
 * Replace the old package database entry with the new one preserving the
 * data which remains constant across the replacement.
 *	copied directly:
 *		ftype, pkg_class
 *
 *	preserved from old:
 *		path, npkgs, pinfo
 */
void
repl_cfent(struct cfent *new, struct cfent *old)
{
	char *path = old->path;
	short npkgs = old->npkgs;
	struct pinfo *pinfo = old->pinfo;

	/* Copy everything from the new entry over */
	(void) memcpy(old, new, sizeof (struct cfent));

	if (strchr("sl", new->ftype) == NULL)
		old->ainfo.local = NULL;

	old->path = path;
	old->npkgs = npkgs;
	old->pinfo = pinfo;

	old->volno = 0;
}

/*
 * Copy critical portions of cf_ent (from the package database) and el_ent
 * (constructed from the pkgmap) into a merged cfent structure, tp. Then copy
 * that to the el_ent structure. The approach we take here is to copy over
 * everything from the package database entry, condition the paths based upon
 * the currently installed path and then insert the following entries from
 * the new structure :
 *	cfent.volno
 *	pkg_class
 *	pkg_class_idx
 *
 * The pinfo list is then copied from the cfent list. While
 * fsys_value is also copied over, it hasn't been set yet. This function
 * copies over whatever the default value is from the new structure.
 *
 * The copied entry is returned in the el_ent argument and the function
 * value is 1 on success, 0 on failure. There is no recovery plan for
 * failure.
 */
int
cp_cfent(struct cfent *cf_ent, struct cfextra *el_ent)
{
	struct cfextra	*tp;

	/* Allocate space for cfent copy */
	if ((tp = (struct cfextra *)calloc(1,
	    sizeof (struct cfextra))) == NULL) {
		progerr(gettext("cp_cfent: memory allocation error"));
		return (0);
	}

	/* Copy everything from the package database over */
	(void) memcpy(&(tp->cf_ent), cf_ent, sizeof (struct cfent));

	/* Now overlay new items from the pkgmap */
	tp->fsys_value = el_ent->fsys_value;
	tp->cf_ent.volno = el_ent->cf_ent.volno;
	(void) strlcpy(tp->cf_ent.pkg_class, el_ent->cf_ent.pkg_class,
			sizeof (tp->cf_ent.pkg_class));
	tp->cf_ent.pkg_class_idx = el_ent->cf_ent.pkg_class_idx;
	tp->cf_ent.pinfo = cf_ent->pinfo;

	/*
	 * The paths are identical, so we get them from the new entry.  These
	 * are pointing to a malloc'd section of memory containing a string
	 * that we aren't moving in this operation, so everybody points to
	 * the same thing during these transfers.
	 */
	tp->cf_ent.path = el_ent->client_path;
	tp->server_path = el_ent->server_path;
	tp->client_path = el_ent->client_path;
	tp->map_path = el_ent->map_path;

	/*
	 * Since instvol() expects to work with the *original* mstat data,
	 * mstat is just copied here. NOTE: mstat looks like a structure, but
	 * it's really a short bit array.
	 */
	tp->mstat = el_ent->mstat;

	/* Copy everything from the temporary structure to the new entry */
	(void) memcpy(el_ent, tp, sizeof (struct cfextra));
	free(tp);

	return (1);
}
