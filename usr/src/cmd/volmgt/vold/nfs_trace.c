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
 * Copyright 1992 Sun Microsystems, Inc.  All rights reserved.
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
#include	<string.h>
#include	<sys/types.h>
#include	<rpc/types.h>
#include	<rpcsvc/nfs_prot.h>


extern void	nfstrace(const char *fmt, ...);


static void
p_void(void)
{
}

static struct statent {
	nfsstat	val;
	char	*str;
} stattab[] = {
	{ NFS_OK,		"NFS_OK"		},
	{ NFSERR_PERM,		"NFSERR_PERM"		},
	{ NFSERR_NOENT,		"NFSERR_NOENT"		},
	{ NFSERR_IO,		"NFSERR_IO"		},
	{ NFSERR_NXIO,		"NFSERR_NXIO"		},
	{ NFSERR_ACCES,		"NFSERR_ACCES"		},
	{ NFSERR_EXIST,		"NFSERR_EXIST"		},
	{ NFSERR_NODEV,		"NFSERR_NODEV"		},
	{ NFSERR_NOTDIR,	"NFSERR_NOTDIR"		},
	{ NFSERR_ISDIR,		"NFSERR_ISDIR"		},
	{ NFSERR_FBIG,		"NFSERR_FBIG"		},
	{ NFSERR_NOSPC,		"NFSERR_NOSPC"		},
	{ NFSERR_ROFS,		"NFSERR_ROFS"		},
	{ NFSERR_NAMETOOLONG,	"NFSERR_NAMETOOLONG"	},
	{ NFSERR_NOTEMPTY,	"NFSERR_NOTEMPTY"	},
	{ NFSERR_DQUOT,		"NFSERR_DQUOT"		},
	{ NFSERR_STALE,		"NFSERR_STALE"		},
	{ NFSERR_WFLUSH,	"NFSERR_WFLUSH"		},
};
#define	STATTABSIZE (sizeof (stattab) / sizeof (struct statent))


static void
p_nfsstat(nfsstat *status)
{
	int i;

	for (i = 0; i < STATTABSIZE; i++) {
		if (stattab[i].val == *status) {
			(void) nfstrace("stat=%s", stattab[i].str);
			return;
		}
	}
	(void) nfstrace("stat=%d", *status);
}

#ifdef	DEBUG
struct internal_fh {
	/* must be 12 bytes! */
	u_longlong_t	fh_id;		/* "id" of the object */
	u_char		fh_none;	/* place holder */
	u_char		fh_otype;  	/* old type -- for parts */
	u_char		fh_dir;		/* dev, rdsk, dsk, rmt */
	u_char		fh_type;	/* block, character, etc */
};
#endif

static void
p_fhandle(nfs_fh *fh)
{
#ifdef	DEBUG
	/*LINTED: alignment ok*/
	struct internal_fh	*ifh = (struct internal_fh *)fh;


	(void) nfstrace("fh=[0x%llx/%#o/%#o/%#o]",
	    ifh->fh_id, ifh->fh_dir, ifh->fh_otype, ifh->fh_type);
#else	/* DEBUG */
	/*LINTED: alignment ok*/
	register int		*ip = (int *)fh;

	(void) nfstrace("fh=[0x%x, 0x%x, 0x%x]", ip[0], ip[1], ip[2]);
#endif	/* DEBUG */
}

static void
p_diropargs(diropargs *d)
{
	p_fhandle(&d->dir);
	(void) nfstrace(", name=%s", d->name);
}

static void
p_nfstime(nfstime *t)
{
	char *s;

	/*LINTED: alignment ok*/
	s = ctime((time_t *)&t->seconds);
	s[strlen(s) - 1] = 0;
	(void) nfstrace("%s", s);
}

static void
p_fattr(fattr *f)
{
	(void) nfstrace("type = %u, mode = %o, nlink = %u, uid = %u, \
gid = %u, size = %u, blocksize = %u, rdev = %u, blocks = %u, \
fsid = %u, fileid = %u",
		f->type, f->mode, f->nlink, f->uid, f->gid, f->size,
		f->blocksize, f->rdev, f->blocks, f->fsid, f->fileid);
	(void) nfstrace(", atime=");
	p_nfstime(&f->atime);
	(void) nfstrace(", mtime=");
	p_nfstime(&f->mtime);
	(void) nfstrace(", ctime=");
	p_nfstime(&f->ctime);
}

static void
p_sattr(sattr *s)
{
	(void) nfstrace("mode=%o, uid=%u, gid=%u, size=%u",
		s->mode, s->uid, s->gid, s->size);
	(void) nfstrace(", atime=");
	p_nfstime(&s->atime);
	(void) nfstrace(", mtime=");
	p_nfstime(&s->mtime);
}

static void
p_diropres(diropres *d)
{
	p_nfsstat(&d->status);
	if (d->status == NFS_OK) {
		(void) nfstrace(", ");
		p_fhandle(&d->diropres_u.diropres.file);
		(void) nfstrace(", ");
		p_fattr(&d->diropres_u.diropres.attributes);
	}
}

static void
p_sattrargs(sattrargs *sa)
{
	p_fhandle(&sa->file);
	(void) nfstrace(", ");
	p_sattr(&sa->attributes);
}

static void
p_attrstat(attrstat *as)
{
	p_nfsstat(&as->status);
	if (as->status == NFS_OK) {
		(void) nfstrace(", ");
		p_fattr(&as->attrstat_u.attributes);
	}
}

static void
p_readlinkres(readlinkres *r)
{
	p_nfsstat(&r->status);
	if (r->status == NFS_OK) {
		(void) nfstrace(", data=%s", r->readlinkres_u.data);
	}
}

static void
p_readargs(readargs *r)
{
	p_fhandle(&r->file);
	(void) nfstrace(", offset=%u, count=%u", r->offset, r->count);
}

static void
p_readres(readres *r)
{
	p_nfsstat(&r->status);
	if (r->status == NFS_OK) {
		(void) nfstrace(", ");
		p_fattr(&r->readres_u.reply.attributes);
		(void) nfstrace(", len=%u, data=(data)",
			r->readres_u.reply.data.data_len);
	}
}

static void
p_writeargs(writeargs *w)
{
	p_fhandle(&w->file);
	(void) nfstrace(", offset=%u, len=%u, data=(data)",
		w->offset, w->data.data_len);
}

static void
p_createargs(createargs *c)
{
	p_diropargs(&c->where);
	(void) nfstrace(", ");
	p_sattr(&c->attributes);
}

static void
p_renameargs(renameargs *r)
{
	p_diropargs(&r->from);
	(void) nfstrace(", ");
	p_diropargs(&r->to);
}

static void
p_linkargs(linkargs *args)
{
	p_fhandle(&args->from);
	(void) nfstrace(", ");
	p_diropargs(&args->to);
}

static void
p_symlinkargs(symlinkargs *args)
{
	p_diropargs(&args->from);
	(void) nfstrace(", to=%s, ", args->to);
	p_sattr(&args->attributes);
}

static void
p_statfsres(statfsres *res)
{
	p_nfsstat(&res->status);
	if (res->status == NFS_OK) {
		(void) nfstrace(
		", tsize=%d, bsize=%d, blocks=%d, bfree=%d, bavail=%d",
			res->statfsres_u.reply.tsize,
			res->statfsres_u.reply.bsize,
			res->statfsres_u.reply.blocks,
			res->statfsres_u.reply.bfree,
			res->statfsres_u.reply.bavail);
	}
}

static void
p_readdirargs(readdirargs *args)
{
	p_fhandle(&args->dir);
	(void) nfstrace(", cookie=%d, count=%d",
	    /*LINTED: alignment ok*/
	    *((long *)args->cookie), args->count);
}

static void
p_entryp(entry *p)
{
	while (p != NULL) {
		(void) nfstrace("(fileid=%u, name=%s, cookie=%u), ",
		    /*LINTED: alignment ok*/
		    p->fileid, p->name, *((long *)p->cookie));
		p = p->nextentry;
	}
}

static void
p_readdirres(readdirres *res)
{
	p_nfsstat(&res->status);
	if (res->status == NFS_OK) {
		p_entryp(res->readdirres_u.reply.entries);
		(void) nfstrace(", eof=%d", res->readdirres_u.reply.eof);
	}
}

static struct procinfo {
	char *name;
	void (*pargs)();
	void (*pres)();
} procs[] = {
	{ "NULL",		p_void,		p_void		},
	{ "GETATTR",		p_fhandle,	p_attrstat	},
	{ "SETATTR",		p_sattrargs, 	p_attrstat	},
	{ "ROOT",		p_void,		p_void		},
	{ "LOOKUP",		p_diropargs,	p_diropres	},
	{ "READLINK",		p_fhandle,	p_readlinkres	},
	{ "READ",		p_readargs,	p_readres	},
	{ "WRITECACHE",		p_void,		p_void		},
	{ "WRITE",		p_writeargs,	p_attrstat	},
	{ "CREATE",		p_createargs,	p_diropres	},
	{ "REMOVE",		p_diropargs,	p_nfsstat	},
	{ "RENAME",		p_renameargs,	p_nfsstat	},
	{ "LINK",		p_linkargs,	p_nfsstat	},
	{ "SYMLINK",		p_symlinkargs,	p_nfsstat	},
	{ "MKDIR",		p_createargs,	p_nfsstat	},
	{ "RMDIR",		p_diropargs,	p_nfsstat	},
	{ "READDIR",		p_readdirargs,	p_readdirres	},
	{ "STATFS",		p_fhandle,	p_statfsres	},
};

void
trace_call(u_long procnum, char *args)
{
	(void) nfstrace("%s call(", procs[procnum].name);
	(*procs[procnum].pargs)(args);
	(void) nfstrace(")\n");
}

void
trace_return(u_long procnum, char *res)
{
	(void) nfstrace("%s return (", procs[procnum].name);
	(*procs[procnum].pres)(res);
	(void) nfstrace(")\n");
}
