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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include	<sys/param.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/file.h>
#include	<sys/time.h>
#include	<sys/mnttab.h>
#include	<rpc/types.h>
#include	<rpc/auth.h>
#include	<rpc/auth_unix.h>
#include	<rpc/xdr.h>
#include	<sys/tiuser.h>
#include	<rpc/clnt.h>
#include	<netinet/in.h>
#include	<rpcsvc/nfs_prot.h>
#include	<locale.h>

#include	"vold.h"

struct internal_fh {
	/* must be 12 bytes! */
	u_longlong_t	fh_id;		/* "id" of the object */
	uchar_t		fh_none;	/* place holder */
	uchar_t		fh_otype;  	/* old type -- for parts */
	uchar_t		fh_dir;		/* dev, rdsk, dsk, rmt */
	uchar_t		fh_type;	/* block, character, etc */
};

static struct q fh_q_hash[FH_HASH_SIZE];

/* extern functions */
extern void	obj_free(obj_t *);

/*
 * Expose this node to partition.c to compensate
 * for poor method factoring in node_findlabel(), which
 * has been replaced by find_vvnode_in_db() in partition.c
 */

vvnode_t	*rdskroot;			/* top of rdsk */


/* local functions */
static void	fh_new(vvnode_t *);
static void	fh_free(vvnode_t *);
static void	node_dirmove(vvnode_t *vn, vvnode_t *tdvn);
static void	node_newdir(vvnode_t *dvn);
static void	node_updtime(vvnode_t *);

/* local variables */
static vvnode_t	*dskroot;			/* top of dsk */
static vvnode_t	*rmtroot;			/* top of rmt */
static vvnode_t	*mtroot;			/* top of mt */

/* global var */
vvnode_t	*root;				/* root of volmgt filesys */
vvnode_t	*devroot;			/* top of dev */

#define	TMPID_BASE	0x8000000000000000

static u_longlong_t	tmpid = TMPID_BASE+1;

/* default symlink attributes */
#define	DEFAULT_SYMLINK_UID	0
#define	DEFAULT_SYMLINK_GID	0
#define	DEFAULT_SYMLINK_MODE	0777

bool_t
node_tmpobj(obj_t *obj)
{
	int	res = FALSE;


	if (obj->o_id & TMPID_BASE) {
		res = TRUE;
	}
	return (res);
}

vvnode_t *
node_lookup(char *path)
{
	char		**sp;
	vvnode_t	*vn, *dvn;
	int		i;


	if (root == NULL) {
		db_root();
	}

	sp = path_split(path);

	dvn = root;
	for (i = 0; sp[i]; i++) {
		db_lookup(dvn);
		for (vn = dvn->vn_child; vn; vn = vn->vn_sib) {
			if (strcmp(vn->vn_name, sp[i]) == 0) {
				dvn = vn;
				break;
			}
		}
		if (vn == NULL) {
			break;
		}
	}
	path_freeps(sp);
	return (vn);
}


/*
 * make a name unique by adding a "#%d", with numbers starting from 1,
 * and going ... forever? XXX
 */
static void
node_uniqname(vvnode_t *dvn, obj_t *obj)
{
	char		newname[MAXNAMELEN+1];
	vvnode_t	*vn;
	int		iter = 1;
	bool_t		hit;


	/*CONSTCOND*/
	while (1) {

		(void) snprintf(newname, sizeof (newname),
			"%s#%d", obj->o_name, iter++);

		hit = FALSE;
		for (vn = dvn->vn_child; vn; vn = vn->vn_sib) {
			if (strcmp(newname, vn->vn_name) == 0) {
				hit = TRUE;
				break;
			}
		}

		/*
		 * The new name is a good one (none others like it),
		 * give it to the object.  Of course, this only applies
		 * to the "add" operation, because otherwise,  we'd have
		 * to do a change_name().
		 */
		if (hit == FALSE) {
			free(obj->o_name);
			obj->o_name = strdup(newname);
			return;
		}
	}
	/*NOTREACHED*/
}


/*
 * given a parent vvnode "dvn" and an object "obj", create a new vvnode
 *	based on the object
 */
vvnode_t *
node_mkobj(vvnode_t *dvn, obj_t *obj, uint_t flags, uint_t *err)
{
	vvnode_t 	*vn, *tvn;
	uint_t		nflags;
	char		buf[MAXPATHLEN+1];

	*err = 0;				/* initialize to "no error" */

	/*
	 * Give us the "directory" string.
	 */
	if (obj->o_dir == NULL) {
		if ((dvn != NULL) && (dvn != root)) {
			/* not under the volmgt root (e.g. "/vol") */
			(void) snprintf(buf, sizeof (buf), "%s/%s",
			    dvn->vn_obj->o_dir,
			    dvn->vn_obj->o_name);
			obj->o_dir = strdup(buf);
		} else {
			obj->o_dir = strdup("");
		}
	}

	if (flags & NODE_DBUP) {
		db_lookup(dvn);
	}

	for (vn = dvn->vn_child; vn; vn = vn->vn_sib) {
		if (strcmp(vn->vn_name, obj->o_name) == 0) {
			vn->vn_update++;
			*err = EEXIST;
			break;
		}
	}

	/*
	 * If the proposed name is already in the name space,
	 * and we've been asked to fix it, change the name.
	 */
	if ((*err == EEXIST) && (flags & NODE_FIXNAME)) {
		node_uniqname(dvn, obj);
		*err = 0;
	}

	if (*err) {
		return (vn);
	}

	if (flags & NODE_DBUP) {
		/*
		 * Adding into the database only fails if there is
		 * something already there.  This will only happen
		 * with networked databases where someone adds a name
		 * and we haven't seen it yet.
		 */
		if (db_add(obj) == FALSE) {
			*err = EEXIST;
			return (NULL);
		}
	}


	/*
	 * Allocate the vvnode and link it into the list.
	 */
	vn = (vvnode_t *)calloc(1, sizeof (vvnode_t));
	vn->vn_obj = obj;
	vn->vn_name = strdup(obj->o_name);
	vn->vn_dirtype = path_type(dvn);
	vn->vn_update = 1;
	vn->vn_parent = dvn;
	if (obj->o_type == VV_DIR) {
		vn->vn_nlinks = 2;
	} else {
		vn->vn_nlinks = 1;
	}

	vn->vn_sib = dvn->vn_child;
	dvn->vn_child = vn;
	dvn->vn_nlinks++;
	node_updtime(dvn);
	debug(10, "node_mkobj: added %s (0x%x) to %s (0x%x)\n",
	    vn->vn_name, vn, dvn->vn_name[0] ? dvn->vn_name : "/vol", dvn);

	switch (obj->o_type) {
	case VV_BLK:
	case VV_CHR:
		if (flags & NODE_BLK) {
			vn->vn_type = VV_BLK;
		} else if (flags & NODE_CHR) {
			vn->vn_type = VV_CHR;
		} else {
			if (vn->vn_dirtype == DIR_DSK ||
			    vn->vn_dirtype == DIR_MT) {
				vn->vn_type = VV_BLK;
			} else if (vn->vn_dirtype == DIR_RDSK ||
			    vn->vn_dirtype == DIR_RMT) {
				vn->vn_type = VV_CHR;
			} else {
				debug(1, "node_mkobj: %s improperly setup\n",
					vn->vn_name);
				vn->vn_type = VV_CHR;
			}

		}
		break;
	default:
		vn->vn_type = obj->o_type;
		break;
	}

	if (flags & NODE_TMPID && obj->o_id == 0) {
		obj->o_id = tmpid++;
	}

	/* twining code */
	if (dvn->vn_twin &&
	    !(flags & NODE_TWIN) &&
	    (vn->vn_type != VV_PART) &&
	    (vn->vn_type != VV_SYMLINK)) {
		nflags = flags;
		nflags &= ~(NODE_BLK|NODE_CHR);
		if (flags & NODE_BLK) {
			nflags |= NODE_CHR;
		}
		if (flags & NODE_CHR) {
			nflags |= NODE_BLK;
		}
		nflags |= NODE_TWIN;	/* note that we are twinning */
		nflags &= ~NODE_DBUP;	/* don't need to dbup scnd time */
		tvn = node_mkobj(dvn->vn_twin, obj, nflags, err);
		vn->vn_twin = tvn;
		tvn->vn_twin = vn;
	}

	/*
	 * We remember a few of the vvnodes to make some operations
	 * easier, and set up top level twins.
	 */
	if (root == dvn) {
		if (strcmp(vn->vn_name, DSKNAME) == 0) {
			dskroot = vn;
			if (rdskroot) {
				dskroot->vn_twin = rdskroot;
				rdskroot->vn_twin = dskroot;
			}
		} else if (strcmp(vn->vn_name, RDSKNAME) == 0) {
			rdskroot = vn;
			if (dskroot) {
				dskroot->vn_twin = rdskroot;
				rdskroot->vn_twin = dskroot;
			}
		} else if (strcmp(vn->vn_name, RMTNAME) == 0) {
			/*
			 * The mt/rmt twinning is set up just to make
			 * block tapes a no brainer in the future.
			 */
			rmtroot = vn;
			if (mtroot) {
				mtroot->vn_twin = rmtroot;
				rmtroot->vn_twin = mtroot;
			}
		} else if (strcmp(vn->vn_name, MTNAME) == 0) {
			mtroot = vn;
			if (rmtroot) {
				mtroot->vn_twin = rmtroot;
				rmtroot->vn_twin = mtroot;
			}
		} else if (strcmp(vn->vn_name, DEVNAME) == 0) {
			devroot = vn;
		}
	}

	/*
	 * partitions, what a joy.
	 */
	switch (obj->o_type) {
	case VV_BLK:
	case VV_CHR:
	case VV_LINK:
		if (flags & NODE_BLK) {
			vn->vn_otype = VV_BLK;
		}
		if (flags & NODE_CHR) {
			vn->vn_otype = VV_CHR;
		}
		break;
	default:
		break;
	}

	/*
	 * Give this vvnode a file handle
	 */

	fh_new(vn);
	return (vn);
}


/*
 * make a symlink, with parent "dvn", named "name", pointing to "to"
 */
vvnode_t *
node_symlink(vvnode_t *dvn, char *name, char *to, int flags, sattr *attr)
{
	symat_t		*sla;
	uint_t		err;
	vvnode_t	*vn;
	sattr		def_attrs;



	/* XXX: blow off size */

	/* create the "symlink" structure */
	sla = (symat_t *)calloc(1, sizeof (symat_t));

	/* if no attributes were passed in, create our own */
	if (attr == NULL) {
		attr = &def_attrs;
		attr->uid = DEFAULT_SYMLINK_UID;
		attr->gid = DEFAULT_SYMLINK_GID;
		attr->mode = DEFAULT_SYMLINK_MODE;
		attr->atime = *(struct nfstime *)&current_time;
		attr->mtime = *(struct nfstime *)&current_time;
	}

	if (attr->uid != (uid_t)-1) {
		sla->sla_obj.o_uid = attr->uid;
	} else {
		sla->sla_obj.o_uid = DEFAULT_SYMLINK_UID;
	}

	if (attr->gid != (gid_t)-1) {
		sla->sla_obj.o_gid = attr->gid;
	} else {
		sla->sla_obj.o_gid = DEFAULT_SYMLINK_GID;
	}

	if (attr->mode != (mode_t)-1) {
		sla->sla_obj.o_mode = attr->mode;
	} else {
		sla->sla_obj.o_mode = DEFAULT_SYMLINK_MODE;
	}

	/* copy atime/mtime from passed in attributes (if possible) */
	if (attr->atime.seconds != (uint_t)-1) {
		sla->sla_obj.o_atime = *(struct timeval *)&attr->atime;
	} else {
		sla->sla_obj.o_atime = current_time;
	}
	if (attr->mtime.seconds != (uint_t)-1) {
		sla->sla_obj.o_mtime = *(struct timeval *)&attr->mtime;
	} else {
		sla->sla_obj.o_mtime = current_time;
	}

	sla->sla_obj.o_ctime = current_time;
	sla->sla_obj.o_name = strdup(name);
	sla->sla_obj.o_type = VV_SYMLINK;
	sla->sla_obj.o_nlinks = 1;
	sla->sla_ptr = strdup(to);
	vn = node_mkobj(dvn, (obj_t *)sla, flags, &err);
	if (err) {
		return (NULL);
	}
	return (vn);
}


bool_t
node_hardlink(vvnode_t *dvn, char *to, vvnode_t *fvn)
{
	linkat_t	*la;
	uint_t		err;
	uint_t		flags;



	la = (linkat_t *)calloc(1, sizeof (linkat_t));
	la->la_obj.o_name = strdup(to);
	la->la_obj.o_type = VV_LINK;
	la->la_obj.o_uid = fvn->vn_obj->o_uid;
	la->la_obj.o_gid = fvn->vn_obj->o_gid;
	la->la_obj.o_mode = fvn->vn_obj->o_mode;
	la->la_obj.o_atime = fvn->vn_obj->o_atime;
	la->la_obj.o_mtime = fvn->vn_obj->o_mtime;
	la->la_obj.o_ctime = current_time;
	la->la_obj.o_nlinks = 1;
	la->la_id = fvn->vn_obj->o_id;
#ifdef notdef
	/* why is this not done ?? (wld) */
	change_nlinks(fvn->vn_obj, fvn->vn_obj->o_nlinks+1);
	(void) db_update(fvn->vn_obj);
#endif
	flags = NODE_DBUP;
	if (fvn->vn_type == VV_BLK) {
		flags |= NODE_BLK;
	} else if (fvn->vn_type == VV_CHR) {
		flags |= NODE_CHR;
	}

	(void) node_mkobj(dvn, (obj_t *)la, flags, &err);

	if (err) {
		free(la->la_obj.o_name);
		free(la);
		return (FALSE);
	}
	return (TRUE);
}


/*
 * This removes all flavors of an object from the hierarchy,
 * the file handle hash, and (optionally) from the database.
 */
void
node_remove(obj_t *obj, bool_t dbup, uint_t *err)
{
	struct vnwrap 	*vw;
	struct vnwrap 	*nvw;
	vvnode_t 	*vn;
	vvnode_t 	*vn_next;


	*err = 0;

	/* can't remove a volume thats in a drive */
	if ((obj->o_type == VV_CHR) || (obj->o_type == VV_BLK)) {
		vol_t	*v = (vol_t *)obj;
		if (v->v_confirmed) {
			*err = EBUSY;
			return;
		}
	}

	if (dbup) {
		if (db_remove(obj) == FALSE) {
			*err = EINVAL;
			return;
		}
	}
	vw = node_findnode(obj->o_id, FN_ANY, FN_ANY, FN_ANY);
	ASSERT(vw != NULL);

	for (nvw = vw; nvw; nvw = nvw->vw_next) {
		if (nvw->vw_node->vn_otype) {	/* vol with partitions */
			for (vn = nvw->vw_node->vn_child; vn != NULL;
			    vn = vn_next) {
				vn_next = vn->vn_sib;
				obj_free(vn->vn_obj);
				node_unlink(vn);
			}
		}
		node_unlink(nvw->vw_node);
	}
	node_findnode_free(vw);
}


/*
 * This just takes a vvnode off whatever list it might be
 * on and frees it.
 */
void
node_unlink(vvnode_t *vn)
{
	vvnode_t	*pvn;
	vvnode_t	*lvn;
	vvnode_t	*vn_next;


	if (vn->vn_otype != 0) {	/* we have partitions in us */
		/* get rid of these partitions */
		for (lvn = vn->vn_child; lvn != NULL; lvn = vn_next) {
			ASSERT(lvn->vn_type == VV_PART);
			vn_next = lvn->vn_sib;
			obj_free(lvn->vn_obj);
			node_unlink(lvn);
		}
	}

	pvn = vn->vn_parent;
	pvn->vn_nlinks--;
	node_updtime(pvn);

	/* remove this node from its parent's list */
	if (pvn->vn_child == vn) {
		/* it's the first node on it's parent list */
		pvn->vn_child = vn->vn_sib;
	} else {
		/* scan for where we are on our parent's list */
		for (lvn = pvn->vn_child; lvn; lvn = lvn->vn_sib) {
			if (lvn->vn_sib == vn) {
				/* found us */
				break;
			}
		}
		if (lvn) {
			ASSERT(lvn->vn_sib == vn);
			lvn->vn_sib = vn->vn_sib;
			vn->vn_sib = 0;		/* DEBUG */
		} else {
			/* we weren't on our parens list! */
			debug(1, "unlink: linked list broken\n");
			dbxtrap("unlink");
			return;
		}
	}
	fh_free(vn);
	free(vn->vn_name);
	free(vn);
}


/*
 * if we're changing directories
 *	update o_dir
 * if we're changing names
 *	change the name of the object
 * update the database
 * if we're changing directories
 *	unlink it from the current directory
 *	link it into the new directory
 * if we're changing names
 *	change it's name everywhere.
 */
bool_t
node_move(vvnode_t *vn, vvnode_t *tdvn, char *name)
{
	static void	node_rename(vvnode_t *, char *);
	extern void	dev_rename(vol_t *);
	char		*oname = NULL;
	char		*odir = NULL;
	char		namebuf[MAXPATHLEN+1];
	char		*special;
	char		*path;
	char		*tspecial = NULL;
	char		*specpath;

	path = path_make(vn);
	special = mnt_special_test(path);
	free(path);

	if (vn->vn_twin) {
		path = path_make(vn->vn_twin);
		tspecial = mnt_special_test(path);
		free(path);
	}

	if (vn->vn_parent != tdvn) {
		odir = strdup(vn->vn_obj->o_dir);
		(void) snprintf(namebuf, sizeof (namebuf), "%s/%s",
		    tdvn->vn_obj->o_dir,
		    tdvn->vn_obj->o_name);
		change_dir(vn->vn_obj, namebuf);
	}
	if (strcmp(vn->vn_obj->o_name, name)) {
		oname = strdup(vn->vn_obj->o_name);
		change_name(vn->vn_obj, name);
	}

	if (db_update(vn->vn_obj) == FALSE) {
		if (oname) {
			free(vn->vn_obj->o_name);
			vn->vn_obj->o_name = oname;
		}
		if (odir) {
			free(vn->vn_obj->o_dir);
			vn->vn_obj->o_dir = odir;
		}
		return (FALSE);
	}

	/*
	 * cool, the database is updated and all we have to do
	 * is move around the local data structures...
	 */

	/* changing the directory */
	if (odir) {
		node_dirmove(vn, tdvn);
		if (vn->vn_twin) {
			node_dirmove(vn->vn_twin, tdvn->vn_twin);
		}
		free(odir);
	}

	/* changing the name */
	if (oname) {
		node_rename(vn, name);
		if (vn->vn_type == VV_DIR) {
			node_newdir(vn);
		}
	}
	/*
	 * tell the dev stuff this has been renamed so
	 * aliases can be take care of (if necessary).
	 */
	if (vn->vn_obj->o_type == VV_BLK || vn->vn_obj->o_type == VV_CHR) {
		dev_rename(vn->vn_vol);
	}

	if (special != NULL) {
		path = path_make(vn);
		specpath = path_mntrename(special, path,
		    oname ? oname : vn->vn_name);
		mnt_special_rename(special, specpath);
		free(path);
		free(special);
		free(specpath);
	}

	if (tspecial != NULL) {
		path = path_make(vn->vn_twin);
		specpath = path_mntrename(tspecial, path,
		    oname ? oname : vn->vn_name);
		mnt_special_rename(tspecial, specpath);
		free(path);
		free(tspecial);
		free(specpath);
	}

	if (oname != NULL) {
		free(oname);
	}

	return (TRUE);
}


/*
 * Update the names of all children after we've moved a directory.
 */
static void
node_newdir(vvnode_t *dvn)
{
	vvnode_t	*vn;
	char		namebuf[MAXPATHLEN];

	(void) snprintf(namebuf, sizeof (namebuf), "%s/%s",
	    dvn->vn_obj->o_dir,
	    dvn->vn_obj->o_name);
	for (vn = dvn->vn_child; vn; vn = vn->vn_sib) {
		change_dir(vn->vn_obj, namebuf);
		(void) db_update(vn->vn_obj);
		if (vn->vn_type == VV_DIR) {
			node_newdir(vn);
		}
	}
}


/*
 * Move a vvnode from one directory to another.
 */
static void
node_dirmove(vvnode_t *vn, vvnode_t *tdvn)
{
	vvnode_t *pvn, *lvn;


	/* remove it from the old directory */
	pvn = vn->vn_parent;
	pvn->vn_nlinks--;
	node_updtime(pvn);
	if (pvn->vn_child == vn) {
		pvn->vn_child = vn->vn_sib;
	} else {
		for (lvn = pvn->vn_child; lvn; lvn = lvn->vn_sib) {
			if (lvn->vn_sib == vn) {
				break;
			}
		}
		if (lvn) {
			ASSERT(lvn->vn_sib == vn);
			lvn->vn_sib = vn->vn_sib;
		} else {
			debug(1, "dirmove: linked list broken\n");
			dbxtrap("dirmove");
			return;
		}
	}
	/* add it to the new directory */
	vn->vn_parent = tdvn;
	vn->vn_sib = tdvn->vn_child;
	tdvn->vn_child = vn;
	tdvn->vn_nlinks++;
	node_updtime(tdvn);
}



/*
 * This is when we are calling an object something different.  It
 * just changes the name.  It doesn't try to move it.
 */
static void
node_rename(vvnode_t *vn, char *name)
{
	struct vnwrap	*vw, *fvw;
	char		*path;
	char		*special;


	fvw = node_findnode(vn->vn_obj->o_id, FN_ANY, FN_ANY, FN_ANY);
	ASSERT(fvw != NULL);

	for (vw = fvw; vw; vw = vw->vw_next) {
		path = path_make(vw->vw_node);
		special = mnt_special_test(path);
		free(path);
		free(vw->vw_node->vn_name);
		vw->vw_node->vn_name = strdup(name);
		node_updtime(vw->vw_node->vn_parent);
		if (special) {
			path = path_make(vw->vw_node);
			mnt_special_rename(special, path);
			free(special);
			free(path);
		}
	}
	node_findnode_free(fvw);
}


nfsstat
node_nfslookup(vvnode_t *dvn, char *name, vvnode_t **pvn, struct fattr *fattr)
{
	vvnode_t	*vn;
	nfsstat		res = NFS_OK;

#ifdef	DEBUG_NFS
	debug(11, "node_nfslookup: entering (name=\"%s\", fattr=0x%x)\n",
	    name, (char *)fattr);
#endif
	if (strcmp(".", name) == 0) {
		if (fattr) {
			node_fattr(dvn, fattr);
		}
		*pvn = dvn;
		goto dun;
	}

	if (strcmp("..", name) == 0) {
		if (fattr) {
			node_fattr(dvn->vn_parent, fattr);
		}
		*pvn = dvn->vn_parent;
		goto dun;
	}

	db_lookup(dvn);

	for (vn = dvn->vn_child; vn; vn = vn->vn_sib) {
		if (strcmp(vn->vn_name, name) == 0) {
			if (fattr) {
				node_fattr(vn, fattr);
			}
			*pvn = vn;
			goto dun;
		}
	}
	res = NFSERR_NOENT;
dun:
#ifdef	DEBUG_NFS
	debug(11, "node_nfslookup: returning %d\n", (int)res);
#endif
	return (res);
}

static mode_t
node_mapmode(vol_t *v)
{
	if (dev_rdonly(v->v_basedev) || v->v_flags & V_RDONLY) {
		return (v->v_obj.o_mode & ~(S_IWUSR|S_IWGRP|S_IWOTH));
	}
	return (v->v_obj.o_mode);
}


/*
 * produce the file attributes for a given vnode.
 */
void
node_fattr(vvnode_t *vn, struct fattr *fat)
{
	if (vn->vn_parent) {
		db_lookup(vn->vn_parent);
	}
	(void) memset(fat, 0, sizeof (struct fattr));

	switch (vn->vn_type) {
	case VV_DIR:
		fat->type = NFDIR;
		fat->mode = (uint_t)vn->vn_obj->o_mode;
		fat->size = 512;
		break;

	case VV_BLK:
	case VV_CHR:
		if (vn->vn_type == VV_BLK) {
			fat->type = NFBLK;
		} else {
			fat->type = NFCHR;
		}

		fat->mode = (uint_t)node_mapmode(vn->vn_vol);
		if (vn->vn_vol->v_devmap == 0) {
#ifdef	DEBUG
			debug(11,
			    "node_fattr: calling dev_devmap for VV_CHR/BLK\n");
#endif
			dev_devmap(vn->vn_vol);
#ifdef	DEBUG
			debug(11, "node_fattr: dev_devmap returned\n");
#endif
		}
		if (vn->vn_vol->v_devmap == NULL)
			fat->rdev = NODEV;
		else {
			fat->rdev =
			    (uint_t)vn->vn_vol->v_devmap[vn->vn_num].dm_voldev;
			ASSERT(fat->rdev != 0);
			ASSERT(fat->rdev != NODEV);
		}
		break;

	case VV_PART:
		/*
		 * When a volume turns into a directory, we save the
		 * vn_type into vn_otype so that later we can come
		 * along and tell whether its a block or character.
		 */
		if (vn->vn_parent->vn_otype == VV_CHR) {
			fat->type = NFCHR;
		} else if (vn->vn_parent->vn_otype == VV_BLK) {
			fat->type = NFBLK;
		} else {
			fatal(gettext(
			    "node_fattr: partition in non-volume!!\n"));
		}
		fat->mode = (uint_t)node_mapmode(vn->vn_parent->vn_vol);
		if (vn->vn_parent->vn_vol->v_devmap == 0) {
			dev_devmap(vn->vn_parent->vn_vol);
		}
		if (vn->vn_parent->vn_vol->v_devmap == 0)
			fat->rdev = NODEV;
		else {
			fat->rdev = (uint_t)
			vn->vn_parent->vn_vol->v_devmap[vn->vn_num].dm_voldev;
		}
		break;

	case VV_SYMLINK:
		fat->mode = (uint_t)vn->vn_obj->o_mode;
		fat->type = NFLNK;
		fat->size = strlen(vn->vn_sym->sla_ptr);
		break;

	case VV_LINK: {
		struct vnwrap	*vw;

		vw = node_findnode(vn->vn_lnk->la_id, FN_ANY,
			FN_ANY, vn->vn_otype);
		if (vw == NULL) {
			/* for now, just return the links attrs... */
			break;
		}
		/* recurse on the new object */
		node_fattr(vw->vw_node, fat);
		node_findnode_free(vw);
		return;
	}

	default:
		debug(1, "db_fattr1 = 0x%x\n", vn->vn_type);
		break;
	}

	fat->uid = (uint_t)vn->vn_obj->o_uid;
	fat->gid = (uint_t)vn->vn_obj->o_gid;
	(void) memcpy(&fat->atime,  &vn->vn_obj->o_atime,
	    sizeof (struct nfstime));
	(void) memcpy(&fat->mtime, &vn->vn_obj->o_mtime,
	    sizeof (struct nfstime));
	(void) memcpy(&fat->ctime, &vn->vn_obj->o_ctime,
	    sizeof (struct nfstime));
	fat->fsid = 0;
	fat->fileid = node_fid(vn);
	fat->blocksize = 512;	/* what the heck */
	fat->nlink = vn->vn_nlinks;
}


void
node_startupdate(vvnode_t *dvn)
{
	vvnode_t	*vn;


	/*
	 * Clean all our update flags
	 */
	if (dvn == NULL) {
		return;
	}

	debug(15, "startupdate: %s\n", dvn->vn_name);
	for (vn = dvn->vn_child; vn; vn = vn->vn_sib) {
		vn->vn_update = 0;
	}
}


/*
 * This function marks all nodes from a particular database
 * as "seen".  Databases that do not provide consistency with
 * others will use this function on lookup.
 */
void
node_setupdated(vvnode_t *dvn, struct dbops *dops)
{
	vvnode_t	*vn;


	/*
	 * Set all the update flags for a particular database.
	 */
	ASSERT(dvn != NULL);

	debug(15, "setupdated: %s, db '%s'\n", dvn->vn_name, dops->dop_name);
	for (vn = dvn->vn_child; vn; vn = vn->vn_sib) {
		if (vn->vn_obj->o_dbops == dops) {
			vn->vn_update = 1;
		}
	}
}


void
node_endupdate(vvnode_t	*dvn)
{
	vvnode_t	*vn;
	vvnode_t	*vn_next;
	uint_t		err;


	ASSERT(dvn != NULL);
	/*
	 * Check all our update flags
	 */
	if (dvn->vn_dirtype == DIR_DEV) {
		return;
	}

	debug(15, "endupdate: %s\n", dvn->vn_name);

	for (vn = dvn->vn_child; vn != NULL; vn = vn_next) {

		vn_next = vn->vn_sib;

		/*
		 * if we didn't see it between startupdate and
		 * now, just axe it
		 */
		if (vn->vn_update == 0 && !node_tmpobj(vn->vn_obj)) {
			debug(5, "endupdate: removing %s from %s\n",
			    vn->vn_obj->o_name, vn->vn_obj->o_dir);
			node_remove(vn->vn_obj, FALSE, &err);
			/*
			 * We start over again because the act of
			 * doing a node_remove could waste several
			 * things.
			 */
			vn = dvn->vn_child;
		}
	}
}


vvnode_t *
node_findlabel(struct devs *dp, label *la)
{
	vol_t		*v;
	vvnode_t	*vn = NULL;
	struct vnwrap	*vw, *nvw;
	uint_t		err;
	char		namebuf[MAXPATHLEN];

	/* can we find an entry in the database ?? */
	v = db_findlabel(dp->dp_dsw->d_mtype, la);
	if (v == NULL) {
		/* no entry found -- make an entry and leave */
		v = vol_mkvol(dp, la);
		vn = node_mkobj(rdskroot, (obj_t *)v,
		    NODE_FIXNAME|NODE_DBUP|NODE_CHR, &err);
		goto dun;
	}

	/* see if we can find any already existing node */
	vw = node_findnode(v->v_obj.o_id, FN_ANY, FN_ANY, FN_ANY);
	if (vw == NULL) {
		/* XXX: why would node_findnode() fail above ?? */
		(void) snprintf(namebuf, sizeof (namebuf), "%s/%s",
		    v->v_obj.o_dir,
		    v->v_obj.o_name);
		(void) node_lookup(namebuf);
		vw = node_findnode(v->v_obj.o_id, FN_ANY, FN_ANY, FN_ANY);
		if (vw == NULL) {
			fatal(gettext("node_findlabel: database broken\n"));
		}
	}
	for (nvw = vw; nvw; nvw = nvw->vw_next) {
		if (nvw->vw_node->vn_dirtype == DIR_RDSK) {
			vn = nvw->vw_node;
			break;
		}
	}
	node_findnode_free(vw);

	/* check to see if this volume has already been seen */
	if (vn != NULL) {
		v = vn->vn_vol;
		if (v->v_confirmed) {
			noise("%s named %s already exists in a drive\n",
			    v->v_mtype, v->v_obj.o_name);
			/* returning null means the volume will get ejected */
			vn = NULL;
		}
	}
dun:
	return (vn);
}


dirat_t *
node_mkdirat(char *name, uid_t uid, gid_t gid, mode_t mode)
{
	dirat_t	*da;


	da = (dirat_t *)calloc(1, sizeof (dirat_t));
	da->da_obj.o_name = strdup(name);
	da->da_obj.o_type = VV_DIR;
	da->da_obj.o_uid = uid;
	da->da_obj.o_gid = gid;
	da->da_obj.o_mode = mode;
	da->da_obj.o_atime = current_time;
	da->da_obj.o_mtime = current_time;
	da->da_obj.o_ctime = current_time;
	da->da_obj.o_nlinks = 1;
	return (da);
}


/*
 * find a node with a specific "id",  "off",  and "dir".
 * If either dir or off == FN_ANY, they are treated as a wildcard,
 * and will match all dir's and off's.
 *
 * NOTE: argument "off" is not used (wld)
 */
/*ARGSUSED*/
struct vnwrap *
node_findnode(u_longlong_t nid, uchar_t off, uchar_t dir, uchar_t type)
{
	struct vvnode *vn;
	struct vnwrap *vw = NULL, *ovw;
	struct internal_fh *ifh;


	vn = HEAD(struct vvnode, fh_q_hash[nid % FH_HASH_SIZE]);

	while (vn) {
		/*LINTED: alignment ok*/
		ifh = (struct internal_fh *)(&vn->vn_fh);
		if ((nid == vn->vn_obj->o_id) &&
		    ((type == FN_ANY) || (type == ifh->fh_type)) &&
		    ((dir == FN_ANY) || (dir == ifh->fh_dir))) {
			ovw = vw;
			vw = (struct vnwrap *)calloc(1,
			    sizeof (struct vnwrap));
			vw->vw_next = ovw;
			vw->vw_node = vn;
		}
		vn = NEXT(struct vvnode, vn);
	}
	return (vw);
}


void
node_findnode_free(struct vnwrap *vw)
{
	struct vnwrap *vw_next;


	while (vw) {
		vw_next = vw->vw_next;
		free(vw);
		vw = vw_next;
	}
}


static void
fh_new(vvnode_t *vn)
{
	register struct internal_fh	*ifh =
		/*LINTED: alignment ok*/
		(struct internal_fh *)(&vn->vn_fh);
	static time_t			t;



	(void) memset(ifh, 0, sizeof (struct internal_fh));

	/*
	 * If the id is not the root directory (always id 1)
	 * Add in a random number to solve the restart
	 * problem.
	 */
	if ((vn->vn_obj->o_id & ~VOLID_TMP) > 1) {
		if (t == 0) {
			(void) time(&t);
		}
		ifh->fh_id = vn->vn_obj->o_id |
			(((u_longlong_t)t<<32) & ~VOLID_TMP);
	} else {
		ifh->fh_id = vn->vn_obj->o_id;
	}

	ifh->fh_dir = vn->vn_dirtype;
	ifh->fh_otype = vn->vn_otype;	/* massive hack for partitions */
	ifh->fh_type = vn->vn_type;

	INSQUE(fh_q_hash[ifh->fh_id % FH_HASH_SIZE], vn);
}


static void
fh_free(vvnode_t *vvnode)
{
	register struct internal_fh *ifh =
		/*LINTED: alignment ok*/
		(struct internal_fh *)(&vvnode->vn_fh);


	REMQUE(fh_q_hash[ifh->fh_id % FH_HASH_SIZE], vvnode);
	vvnode->q.q_next = NULL;	/* DEBUG */
	vvnode->q.q_prev = NULL;	/* DEBUG */
}


static void
stale(void)
{
	/* do nothing */
}


vvnode_t *
node_fhtovn(nfs_fh *fh)
{
	struct internal_fh	*vifh;
	/*LINTED: alignment ok*/
	struct internal_fh	*ifh = (struct internal_fh *)fh;
	struct vvnode		*vn;
	uint_t			hash_line;



	/* find out which hash line will this filehandle go in */
	hash_line = (uint_t)(ifh->fh_id % FH_HASH_SIZE);

	/* scan through hash list of vvnodes for match (for this hash line) */
	for (vn = HEAD(struct vvnode, fh_q_hash[hash_line]);
	    vn != NULL;
	    vn = NEXT(struct vvnode, vn)) {

		/*LINTED: alignment ok*/
		vifh = (struct internal_fh *)(&vn->vn_fh);

		if ((vifh->fh_id == ifh->fh_id) &&
		    (vifh->fh_dir == ifh->fh_dir) &&
		    (vifh->fh_otype == ifh->fh_otype) &&
		    (vifh->fh_type == ifh->fh_type)) {
			return (vn);		/* this vvnode matches */
		}
	}

#ifdef	DEBUG
	debug(11,
	    "node_fhtovn: ESTALE: fh=[0x%llx/%#o/%#o/%#o]\n",
	    ifh->fh_id, ifh->fh_dir, ifh->fh_otype, ifh->fh_type);
#endif
	stale();

	return ((struct vvnode *)0);
}


uint_t
node_fid(vvnode_t *vvnode)
{
	register struct internal_fh *ifh =
		/*LINTED: alignment ok*/
		(struct internal_fh *)(&vvnode->vn_fh);


	if (vvnode == NULL) {
		/*LINTED: alignment ok*/
		ifh = (struct internal_fh *)(&root->vn_fh);
	}
	if (ifh->fh_id > TMPID_BASE) {
		/*
		 * Ok, well this is a bit of a hack.  The file id
		 * isn't really useful to NFS, as it really uses
		 * the file handle.  The file id can only be 32
		 * bits, and our id's are 63 bits.  This hack just
		 * returns a fid that is probably different from
		 * other real allocated fids.
		 */
		return ((uint_t)(ifh->fh_id - TMPID_BASE)|0x80000000);
	}
	/* not a temp id */
	return ((uint_t)ifh->fh_id+1);
}


/*
 * If the "core" objects aren't set up by the database, it
 * means that we're blank.  Initialize the "core" objects.
 */
void
node_setup(void)
{
	dirat_t		*da;
	uint_t		err;

	da = node_mkdirat("", DEFAULT_TOP_UID,
	    DEFAULT_TOP_GID,  DEFAULT_ROOT_MODE);
	node_root(da);

	da = node_mkdirat("rdsk", DEFAULT_TOP_UID,
	    DEFAULT_TOP_GID,  DEFAULT_ROOT_MODE);
	(void) node_mkobj(root, (obj_t *)da, NODE_DBUP, &err);

	da = node_mkdirat("dsk", DEFAULT_TOP_UID,
	    DEFAULT_TOP_GID,  DEFAULT_ROOT_MODE);
	(void) node_mkobj(root, (obj_t *)da, NODE_DBUP, &err);

	da = node_mkdirat("rmt", DEFAULT_TOP_UID,
	    DEFAULT_TOP_GID,  DEFAULT_ROOT_MODE);
	(void) node_mkobj(root, (obj_t *)da, NODE_DBUP, &err);

	da = node_mkdirat("dev", DEFAULT_TOP_UID,
	    DEFAULT_TOP_GID,  DEFAULT_ROOT_MODE);
	(void) node_mkobj(root, (obj_t *)da, NODE_DBUP, &err);
}


void
node_root(dirat_t *da)
{
	vvnode_t	*vn;


	vn = (vvnode_t *)calloc(1, sizeof (vvnode_t));
	vn->vn_obj = (obj_t *)da;
	vn->vn_name = strdup("");
	vn->vn_type = VV_DIR;
	vn->vn_dirtype = 0;
	vn->vn_update = 1;
	vn->vn_parent = NULL;
	vn->vn_nlinks = 2;
	if (da->da_obj.o_id == 0) {
		da->da_obj.o_dir = strdup("");
		(void) db_add((obj_t *)da);
		/*
		 * We turn off the tmp bits here so that
		 * root can remain accessable even if we crashed.
		 */
		da->da_obj.o_id &= ~VOLID_TMP;
	}
	fh_new(vn);
	root = vn;
}


/*
 * update the times of the pointed-to node
 */
static void
node_updtime(vvnode_t *vn)
{
	vn->vn_obj->o_atime = current_time;
	vn->vn_obj->o_mtime = current_time;
	vn->vn_obj->o_ctime = current_time;
}
