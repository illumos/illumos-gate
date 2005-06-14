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
 * Copyright (c) 1992 by Sun Microsystems, Inc.
 */

#ifndef __NODE_H
#define	__NODE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* types of a vvnode */
#define	VV_DIR		1
#define	VV_BLK		2
#define	VV_CHR		3
#define	VV_LINK		4
#define	VV_SYMLINK	5
#define	VV_PART		6

typedef struct vvnode {
	struct	q	q;
	char		*vn_name;	/* name of the vvnode */
	u_int		vn_type;	/* type of this vvnode */
	u_int		vn_otype;	/* bit of a hack... for parts */
	u_int		vn_num;		/* offset into devmap (if partat_t) */
	union {
		vol_t		*vn_u_vol;	/* volume data */
		dirat_t		*vn_u_dir;	/* directory data */
		symat_t		*vn_u_sym;	/* symlink data */
		linkat_t	*vn_u_lnk;	/* hardlink data */
		partat_t	*vn_u_part;	/* partition data */
		obj_t		*vn_u_obj;	/* object ref */
	} vv_u;
	struct vvnode	*vn_parent;	/* parent */
	struct vvnode	*vn_sib;	/* list of siblings */
	struct vvnode	*vn_twin;	/* twin, for dsk/rdsk mirror */
	struct vvnode	*vn_child;	/* for directories */
	u_int		vn_nlinks;	/* number of links */
	nfs_fh		vn_fh;		/* fhandle */
	char		vn_update;	/* marker */
	char		vn_dirtype;	/* type of dir this lives in */
} vvnode_t;

#define	vn_vol	vv_u.vn_u_vol
#define	vn_dir	vv_u.vn_u_dir
#define	vn_lnk	vv_u.vn_u_lnk
#define	vn_sym	vv_u.vn_u_sym
#define	vn_obj	vv_u.vn_u_obj
#define	vn_part vv_u.vn_u_part

#define	NODE_TWIN	0x01
#define	NODE_DBUP	0x02
#define	NODE_BLK	0x04
#define	NODE_CHR	0x08
#define	NODE_TMPID	0x10
#define	NODE_FIXNAME	0x20

/* for vn_dirtype */
#define	DIR_UNKNOWN	0
#define	DIR_DSK		1
#define	DIR_RDSK	2
#define	DIR_RMT		3
#define	DIR_MT		4
#define	DIR_DEV		5

#define	DEVNAME		"dev"
#define	RDSKNAME	"rdsk"
#define	DSKNAME		"dsk"
#define	RMTNAME		"rmt"
#define	MTNAME		"mt"


#define	FN_ANY	255

struct vnwrap {
	struct vnwrap	*vw_next;
	struct vvnode	*vw_node;
};


extern struct timeval 	current_time;	/* last time time(2) was called */
extern int		never_writeback; /* never to autowrite back of label */
extern vvnode_t		*root;		/* root of the filesystem */

/*
 * name space manipulation functions.
 */
vvnode_t 	*node_lookup(char *path);
vvnode_t	*node_mkobj(vvnode_t *, obj_t *, u_int, u_int *);
dirat_t		*node_mkdirat(char *, uid_t, gid_t, mode_t);
void		node_remove(obj_t *, bool_t, u_int *);
void 		node_unlink(vvnode_t *vn);
void		node_fattr(vvnode_t *, struct fattr *);
struct vnwrap 	*node_findnode(u_longlong_t, u_char, u_char, u_char);
void		node_findnode_free(struct vnwrap *vw);
void		node_startupdate(vvnode_t *dvn);
void		node_endupdate(vvnode_t	*dvn);
vvnode_t	*node_findlabel(struct devs *, label *);
nfsstat		node_nfslookup(vvnode_t *, char *,
			vvnode_t **, struct fattr *);
void		node_setup();
vvnode_t * 	node_symlink(vvnode_t *, char *, char *, int, sattr *);
void		node_root(dirat_t *);

/*
 * File handle functions
 */
vvnode_t	*node_fhtovn(nfs_fh *);
u_int		node_fid(vvnode_t *);

#define	FH_HASH_SIZE	8
#define	MNTTYPE_NFS	"nfs"
#define	NFSCLIENT
typedef nfs_fh fhandle_t;

#ifdef	__cplusplus
}
#endif

#endif /* __NODE_H */
