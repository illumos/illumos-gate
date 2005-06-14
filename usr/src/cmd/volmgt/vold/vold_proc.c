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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<syslog.h>
#include	<string.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<rpc/types.h>
#include	<rpc/auth.h>
#include	<rpc/auth_unix.h>
#include	<rpc/xdr.h>
#include	<netinet/in.h>
#include	<rpcsvc/nfs_prot.h>

#include	"vold.h"

/*
 * These are the possible accesses that may be requested to an
 * object -- note that they map to the st_mode bits -- this is not
 * accidental.
 */
#define	PERM_READ	S_IRUSR
#define	PERM_WRITE	S_IWUSR
#define	PERM_EXEC	S_IXUSR
#define	PERM_STICKY	S_ISVTX

/* extern routines */
extern bool_t	node_hardlink(vvnode_t *, char *, vvnode_t *);

/* local routines */
static bool_t 	checkaccess(vvnode_t *, vvnode_t *,
			struct authsys_parms *, uint_t);
static bool_t	groupmember(gid_t, struct authsys_parms *);


/*
 * add up sizeof (valid + fileid + name + cookie) - strlen(name)
 */
#define	ENTRYSIZE (3 * BYTES_PER_XDR_UNIT + NFS_COOKIESIZE)

/*
 * sizeof (status + eof)
 */
#define	JUNKSIZE (2 * BYTES_PER_XDR_UNIT)



/*ARGSUSED*/
attrstat *
nfsproc_getattr_2_svc(nfs_fh *fh, struct svc_req *req)
{
	struct vvnode *vvnode;
	static attrstat astat;


	vvnode = node_fhtovn(fh);
	if (vvnode == NULL) {
		astat.status = NFSERR_STALE;
		return (&astat);
	}

	astat.status = NFS_OK;
	node_fattr(vvnode, &astat.attrstat_u.attributes);
	return (&astat);
}


attrstat *
nfsproc_setattr_2_svc(sattrargs *args, struct svc_req *req)
{
	static attrstat astat;
	struct vvnode *vn;
	struct authsys_parms *aup;


	vn = node_fhtovn(&args->file);
	if (vn == NULL) {
		astat.status = NFSERR_STALE;
		return (&astat);
	}

	/*LINTED: alignment ok*/
	aup = (struct authsys_parms *)(req->rq_clntcred);

	if (aup->aup_uid != vn->vn_obj->o_uid &&
	    vn->vn_obj->o_uid != default_uid &&
	    aup->aup_uid != 0) {
		astat.status = NFSERR_PERM;
		return (&astat);
	}


	if (args->attributes.uid != (uint_t)-1) {
		change_uid(vn->vn_obj, args->attributes.uid);
	}

	if (args->attributes.gid != (uint_t)-1) {
		change_gid(vn->vn_obj, args->attributes.gid);
	}

	if (args->attributes.mode != (uint_t)-1) {
		change_mode(vn->vn_obj, args->attributes.mode);
	}

	if (args->attributes.atime.seconds != (uint_t)-1) {
		change_atime(vn->vn_obj,
		    (struct timeval *)&args->attributes.atime);
	}

	if (args->attributes.mtime.seconds != (uint_t)-1) {
		change_mtime(vn->vn_obj,
		    (struct timeval *)&args->attributes.mtime);
	}

	if (db_update(vn->vn_obj) == FALSE) {
		debug(1, "nfsproc_sattr: db_update failed on %s\n",
			vn->vn_name);
	}
	astat.status = NFS_OK;
	node_fattr(vn, &astat.attrstat_u.attributes);
	return (&astat);
}


/*ARGSUSED*/
void *
nfsproc_root_2_svc(void *args, struct svc_req *req)
{
	return (NULL);
}


diropres *
nfsproc_lookup_2_svc(diropargs *args, struct svc_req *req)
{
	struct vvnode *vvnode, *cvn;
	static diropres res;
	nfsstat status;
	struct fattr fat;


	vvnode = node_fhtovn(&args->dir);
	if (vvnode == NULL) {
		res.status = NFSERR_STALE;
		return (&res);
	}

	if (vvnode->vn_type != VV_DIR) {
		res.status = NFSERR_NOTDIR;
		return (&res);
	}

	if (checkaccess(vvnode, NULL,
	    /*LINTED: alignment ok*/
	    (struct authsys_parms *)req->rq_clntcred, PERM_READ) == FALSE) {
		res.status = NFSERR_PERM;
		return (&res);
	}

	status = node_nfslookup(vvnode, args->name, &cvn, &fat);
	if (status != NFS_OK) {
		res.status = status;
		return (&res);
	}
	res.diropres_u.diropres.file = cvn->vn_fh;
	res.diropres_u.diropres.attributes = fat;
	res.status = NFS_OK;
	return (&res);
}


/*ARGSUSED*/
readlinkres *
nfsproc_readlink_2_svc(nfs_fh *fh, struct svc_req *req)
{
	static readlinkres 	res;
	struct vvnode		*vn;

	vn = node_fhtovn(fh);
	if (vn == NULL) {
		res.status = NFSERR_STALE;
		return (&res);
	}
	res.readlinkres_u.data = vn->vn_sym->sla_ptr;
	res.status = NFS_OK;
	return (&res);
}


/*ARGSUSED*/
readres *
nfsproc_read_2_svc(readargs *args, struct svc_req *req)
{
	static readres res;

	res.status = NFSERR_ISDIR;	/* XXX: should return better error */
	return (&res);
}


/*ARGSUSED*/
void *
nfsproc_writecache_2_svc(void *args, struct svc_req *req)
{
	return (NULL);
}


/*ARGSUSED*/
attrstat *
nfsproc_write_2_svc(writeargs *args, struct svc_req *req)
{
	static attrstat res;

	res.status = NFSERR_ROFS;	/* XXX: should return better error */
	return (&res);
}


/*ARGSUSED*/
diropres *
nfsproc_create_2_svc(createargs *args, struct svc_req *req)
{
	struct vvnode *vvnode, *cvn;
	static diropres res;
	nfsstat status;
	struct fattr fat;

	vvnode = node_fhtovn(&args->where.dir);
	if (vvnode == NULL) {
		res.status = NFSERR_STALE;
		return (&res);
	}
	if (vvnode->vn_type != VV_DIR) {
		res.status = NFSERR_NOTDIR;
		return (&res);
	}

	/*
	 * For our file system, create is just a lookup.  That's
	 * why we just check for read access.
	 */
	if (checkaccess(vvnode, NULL,
	    /*LINTED: alignment ok*/
	    (struct authsys_parms *)req->rq_clntcred, PERM_READ) == FALSE) {
		res.status = NFSERR_PERM;
		return (&res);
	}

	status = node_nfslookup(vvnode, args->where.name, &cvn, &fat);
	if (status != NFS_OK) {
		res.status = status;
		return (&res);
	}

	/*
	 * the file exists -- check to see if we have write permission
	 * if not, return EACCES
	 * this is done in accord with the man page of creat(2)
	 * (without this check anyone can open with O_CREAT a volume
	 * that belongs to someone else)
	 */
	if (checkaccess(cvn, NULL,
	    /*LINTED: alignment ok*/
	    (struct authsys_parms *)req->rq_clntcred, PERM_WRITE) == FALSE) {
		res.status = NFSERR_ACCES;

		debug(1, "nfsproc_create_2_svc: %s; NFSERR_PERM WRITE\n",
		    cvn->vn_obj->o_name);
		return (&res);
	}

	res.diropres_u.diropres.file = cvn->vn_fh;
	res.diropres_u.diropres.attributes = fat;
	res.status = NFS_OK;
	return (&res);
}


/*ARGSUSED*/
nfsstat *
nfsproc_rename_2_svc(renameargs *args, struct svc_req *req)
{
	extern bool_t	node_move(vvnode_t *, vvnode_t *, char *);
	static nfsstat	status;
	vvnode_t	*fdvn;
	vvnode_t	*tdvn;
	vvnode_t	*vn;



	fdvn = node_fhtovn(&args->from.dir);
	tdvn = node_fhtovn(&args->to.dir);

	if (fdvn == NULL || tdvn == NULL) {
		status = NFSERR_STALE;
		return (&status);
	}

	if (fdvn->vn_type != VV_DIR || tdvn->vn_type != VV_DIR) {
		status = NFSERR_NOTDIR;
		return (&status);
	}

	/* need write permission into the directory we are moving to */
	if (checkaccess(tdvn, NULL,
	    /*LINTED: alignment ok*/
	    (struct authsys_parms *)req->rq_clntcred, PERM_WRITE) == FALSE) {
		status = NFSERR_PERM;
		return (&status);
	}


	status = node_nfslookup(fdvn, args->from.name, &vn, NULL);
	if (status != NFS_OK) {
		return (&status);
	}

	/* need write permission in the directory we are moving from */
	if (checkaccess(fdvn, vn,
	    /*LINTED: alignment ok*/
	    (struct authsys_parms *)req->rq_clntcred,
	    PERM_STICKY|PERM_WRITE) == FALSE) {
		status = NFSERR_PERM;
		return (&status);
	}

	/*
	 * Tried to move something out of a "twinned" directory.
	 * We don't allow this.
	 */
	if (vn->vn_twin && !tdvn->vn_twin) {
		status = NFSERR_ACCES;
		return (&status);
	}

	/*
	 * Tried to rename a partition.  Sorry, not supported yet.
	 */
	if (vn->vn_type == VV_PART) {
		status = NFSERR_ACCES;
		return (&status);
	}

	if (node_move(vn, tdvn, args->to.name) == FALSE) {
		status = NFSERR_EXIST;
		return (&status);
	}

	status = NFS_OK;
	return (&status);
}


/*ARGSUSED*/
nfsstat *
nfsproc_link_2_svc(linkargs *args, struct svc_req *req)
{
	static nfsstat		status;
	vvnode_t		*dvn;
	vvnode_t		*fvn;
	struct authsys_parms	*aup;


	/*LINTED: alignment ok*/
	aup = (struct authsys_parms *)req->rq_clntcred;

	if ((dvn = node_fhtovn(&args->to.dir)) == NULL) {
		status = NFSERR_STALE;
		return (&status);
	}

	if ((fvn = node_fhtovn(&args->from)) == NULL) {
		status = NFSERR_STALE;
		return (&status);
	}

	if (aup->aup_uid != fvn->vn_obj->o_uid &&
	    fvn->vn_obj->o_uid != default_uid &&
	    aup->aup_uid != 0) {
		status = NFSERR_PERM;
		return (&status);
	}

	/*
	 * The names here are a bit confusing...  we're creating
	 * a new name (args->to.name) in dvn that points at "fvn".
	 */
	if (node_hardlink(dvn, args->to.name, fvn) == FALSE) {
		status = NFSERR_EXIST;
		return (&status);
	}
	status = NFS_OK;
	return (&status);
}


/*ARGSUSED*/
nfsstat *
nfsproc_symlink_2_svc(symlinkargs *args, struct svc_req *req)
{
	static nfsstat 	status;
	struct vvnode	*dvn;
	struct authunix_parms	*cred;


	if ((dvn = node_fhtovn(&args->from.dir)) == NULL) {
		status = NFSERR_STALE;
		return (&status);
	}

	if (checkaccess(dvn, NULL,
	    /*LINTED: alignment ok*/
	    (struct authsys_parms *)req->rq_clntcred, PERM_WRITE) == FALSE) {
		status = NFSERR_PERM;
		return (&status);
	}

	/*
	 * We do this because NFS doesn't seem to pass in the
	 * uid or gid as part of the attributes.
	 */
	/*LINTED: alignment ok*/
	cred = (struct authunix_parms *)req->rq_clntcred;

	if (args->attributes.uid == (uint_t)-1)
		args->attributes.uid = (uint_t)cred->aup_uid;
	if (args->attributes.gid == (uint_t)-1)
		args->attributes.gid = (uint_t)cred->aup_gid;

	if (node_symlink(dvn, args->from.name, args->to,
	    NODE_DBUP, &args->attributes) == NULL) {
		status = NFSERR_EXIST;
	} else {
		status = NFS_OK;
	}

	return (&status);
}


/*ARGSUSED*/
diropres *
nfsproc_mkdir_2_svc(createargs *args, struct svc_req *req)
{
	static diropres res;
	vvnode_t	*dvn, *vn;
	dirat_t		*da;
	uint_t		err;
	uid_t		uid;
	gid_t		gid;
	mode_t		mode;
	struct timeval	atime;
	struct timeval	mtime;
	struct authunix_parms	*cred;


	dvn = node_fhtovn(&args->where.dir);
	if (dvn == NULL) {
		res.status = NFSERR_STALE;
		return (&res);
	}

	if (checkaccess(dvn, NULL,
	    /*LINTED: alignment ok*/
	    (struct authsys_parms *)req->rq_clntcred, PERM_WRITE) == FALSE) {
		res.status = NFSERR_PERM;
		return (&res);
	}

	/*LINTED: alignment ok*/
	cred = (struct authunix_parms *)req->rq_clntcred;
	if (args->attributes.uid != (uint_t)-1) {
		uid = args->attributes.uid;
	} else {
		uid = cred->aup_uid;
	}

	if (args->attributes.gid != (uint_t)-1) {
		gid = args->attributes.gid;
	} else {
		gid = cred->aup_gid;
	}

	if (args->attributes.mode != (uint_t)-1) {
		mode = args->attributes.mode;
	} else {
		mode = DEFAULT_ROOT_MODE;
	}

	if (args->attributes.atime.seconds != (uint_t)-1) {
		atime = *(struct timeval *)&args->attributes.atime;
	} else {
		atime = current_time;
	}

	if (args->attributes.mtime.seconds != (uint_t)-1) {
		mtime = *(struct timeval *)&args->attributes.mtime;
	} else {
		mtime = current_time;
	}

	da = node_mkdirat(args->where.name, uid, gid, mode);
	da->da_obj.o_atime = atime;
	da->da_obj.o_mtime = mtime;
	vn = node_mkobj(dvn, (obj_t *)da, NODE_DBUP, &err);
	if (err) {
#ifdef notdef
		/* XXXXX: there's in mkobj where we can't do this yet */
		obj_free((obj_t *)da);
#endif

		/* only possibility here is that it is already there */
		res.status = NFSERR_EXIST;
		return (&res);
	}
	res.status = NFS_OK;
	res.diropres_u.diropres.file = vn->vn_fh;
	node_fattr(vn, &res.diropres_u.diropres.attributes);
	return (&res);
}


/*ARGSUSED*/
nfsstat *
nfsproc_rmdir_2_svc(diropargs *args, struct svc_req *req)
{
	static nfsstat	status;
	vvnode_t	*dvn;
	vvnode_t	*cvn;
	uint_t		err;


	dvn = node_fhtovn(&args->dir);

	if (dvn == NULL) {
		status = NFSERR_NOENT;
		return (&status);
	}


	if (dvn->vn_type != VV_DIR) {
		status = NFSERR_NOTDIR;
		return (&status);
	}

	status = node_nfslookup(dvn, args->name, &cvn, NULL);

	if (status != NFS_OK) {
		return (&status);
	}

	if (cvn->vn_type != VV_DIR) {
		status = NFSERR_NOTDIR;
		return (&status);
	}
	if (cvn->vn_child && cvn->vn_otype == 0) {
		status = NFSERR_NOTEMPTY;
		return (&status);
	}

	/*LINTED: alignment ok*/
	if (checkaccess(dvn, cvn, (struct authsys_parms *)req->rq_clntcred,
	    PERM_STICKY|PERM_WRITE) == FALSE) {
		status = NFSERR_PERM;
		return (&status);
	}

	node_remove(cvn->vn_obj, TRUE, &err);

	if (err) {
		status = NFSERR_NOTEMPTY;
		return (&status);
	}

	status = NFS_OK;
	return (&status);
}

/*ARGSUSED*/
nfsstat *
nfsproc_remove_2_svc(diropargs *args, struct svc_req *req)
{
	static nfsstat status;
	vvnode_t	*dvn, *cvn;
	uint_t		err;

	dvn = node_fhtovn(&args->dir);

	if (dvn == NULL) {
		status = NFSERR_NOENT;
		return (&status);
	}

	if (dvn->vn_type != VV_DIR) {
		status = NFSERR_NOTDIR;
		return (&status);
	}


	status = node_nfslookup(dvn, args->name, &cvn, NULL);
	if (status != NFS_OK) {
		return (&status);
	}

	if (cvn->vn_type == VV_DIR) {
		status = NFSERR_ISDIR;
		return (&status);
	}

	if (checkaccess(dvn, cvn,
	    /*LINTED: alignment ok*/
	    (struct authsys_parms *)req->rq_clntcred,
	    PERM_STICKY|PERM_WRITE) == FALSE) {
		status = NFSERR_PERM;
		return (&status);
	}

	node_remove(cvn->vn_obj, TRUE, &err);

	if (err) {
		status = NFSERR_NOTEMPTY;
		return (&status);
	}

	status = NFS_OK;
	return (&status);
}

readdirres *
nfsproc_readdir_2_svc(readdirargs *args, struct svc_req *req)
{
	static readdirres res;

	vvnode_t 	*vn, *dir;
	struct entry 	*e, *nexte, **entp;
	int 		count;
	int		entrycount;
	/*LINTED: alignment ok*/
	uint_t		cookie = *(uint_t *)args->cookie;


	/*
	 * Free up old stuff
	 */
	e = res.readdirres_u.reply.entries;
	while (e != NULL) {
		nexte = e->nextentry;
		free((char *)e);
		e = nexte;
	}
	res.readdirres_u.reply.entries = NULL;

	dir = node_fhtovn(&args->dir);
	if (dir == NULL) {
		res.status = NFSERR_STALE;
		return (&res);
	}
	if (dir->vn_type != VV_DIR) {
		res.status = NFSERR_NOTDIR;
		return (&res);
	}

	if (checkaccess(dir, NULL,
	    /*LINTED: alignment ok*/
	    (struct authsys_parms *)req->rq_clntcred, PERM_READ) == FALSE) {
		res.status = NFSERR_PERM;
		return (&res);
	}

	count = args->count - JUNKSIZE;

	entp = &res.readdirres_u.reply.entries;

	entrycount = 2;
	if (cookie == 0) {
		*entp = (struct entry *)malloc(sizeof (entry));
		(*entp)->fileid = node_fid(dir);
		(*entp)->name = ".";
		/*LINTED: alignment ok*/
		*(uint_t *)((*entp)->cookie) = ++(cookie);
		(*entp)->nextentry = NULL;
		entp = &(*entp)->nextentry;
		count -= (ENTRYSIZE + strlen("."));

		*entp = (struct entry *)malloc(sizeof (entry));
		(*entp)->fileid = node_fid(dir->vn_parent);
		(*entp)->name = "..";
		/*LINTED: alignment ok*/
		*(uint_t *)((*entp)->cookie) = ++(cookie);
		(*entp)->nextentry = NULL;
		entp = &(*entp)->nextentry;
		count -= (ENTRYSIZE + strlen(".."));
	}
	db_lookup(dir);	/* slurp up the latest */
	for (vn = dir->vn_child; vn; vn = vn->vn_sib) {
		if (count <= ENTRYSIZE) {
			break;	/* we are full */
		}
		if (entrycount++ < cookie) {
			continue;
		}
		*entp = (struct entry *)malloc(sizeof (entry));
		(*entp)->fileid = node_fid(vn);
		(*entp)->name = vn->vn_name;
		/*LINTED: alignment ok*/
		*(uint_t *)((*entp)->cookie) = ++(cookie);
		(*entp)->nextentry = NULL;
		entp = &(*entp)->nextentry;
		count -= (ENTRYSIZE + strlen(vn->vn_name));
	}
	if (count > ENTRYSIZE) {
		res.readdirres_u.reply.eof = TRUE;
	} else {
		res.readdirres_u.reply.eof = FALSE;
	}

	res.status = NFS_OK;
	return (&res);
}


/*ARGSUSED*/
statfsres *
nfsproc_statfs_2_svc(nfs_fh *fh, struct svc_req *req)
{
	static statfsres res;


	res.status = NFS_OK;
	res.statfsres_u.reply.tsize = 512;
	res.statfsres_u.reply.bsize = 512;
	res.statfsres_u.reply.blocks = 0;
	res.statfsres_u.reply.bfree = 0;
	res.statfsres_u.reply.bavail = 0;
	return (&res);
}


static bool_t
checkaccess(vvnode_t *dvn, vvnode_t *vn, struct authsys_parms *aup, uint_t acc)
{
	/* root can do anything */
	if (aup->aup_uid == 0) {
		return (TRUE);
	}

	/*
	 * This checks for "sticky" directories.
	 * The semantic being implemented is that users are allowed
	 * to create and remove their own things, but they can't
	 * remove things owned by other people.  PERM_STICKY is only
	 * specified by the "remove" and "move" functions.
	 */
	if ((acc & PERM_STICKY) &&
	    (dvn->vn_obj->o_mode & S_ISVTX)) {
		if ((vn->vn_obj->o_uid != aup->aup_uid) &&
		    (vn->vn_obj->o_uid != default_uid)) {
			return (FALSE);
		}
	}

	/*
	 * This algorighm is taken from UFS.  It assumes that
	 * the permissions for user are broadest, then group,
	 * then other.  In other words, if you are the owner
	 * of the file and it doesn't have read permission for
	 * owner, but does for group, you're out of luck.  I
	 * only do it this way, because UFS does...
	 */
	acc &= ~PERM_STICKY;
	if ((dvn->vn_obj->o_uid != aup->aup_uid) &&	/* same user */
	    (dvn->vn_obj->o_uid != default_uid)) {	/* nobody */
		acc >>= 3;
		if (!groupmember(dvn->vn_obj->o_gid, aup)) {
			acc >>= 3;
		}
	}
	if ((dvn->vn_obj->o_mode & acc) == acc) {
		return (TRUE);
	}
	return (FALSE);
}


static bool_t
groupmember(gid_t gid, struct authsys_parms *aup)
{
	int	i;

	for (i = 0; i < aup->aup_len; i++)
		if (aup->aup_gids[i] == gid)
			return (TRUE);

	return (FALSE);
}
