/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/*
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

#include <sys/mdb_modapi.h>
#include <mdb/mdb_types.h>
#include <sys/refstr.h>
#include <sys/kstat.h>
#include <sys/refstr_impl.h>
#include <nfs/nfs4_clnt.h>
#include <nfs/nfs_clnt.h>
#include <nfs/nfs4_db_impl.h>
#include <nfs/nfs4.h>
#include <nfs/rnode.h>
#include <nfs/rnode4.h>
#include <rpc/clnt.h>
#include <nfs/nfs4_idmap_impl.h>
#include <mdb/mdb_ks.h>

#include "svc.h"
#include "rfs4.h"
#include "nfssrv.h"
#include "idmap.h"
#include "nfs_clnt.h"

typedef struct nfs_rnode_cbdata {
	int printed_hdr;
	uintptr_t vfs_addr;	/* for nfs_rnode4find */
} nfs_rnode_cbdata_t;

static const mdb_bitmask_t vfs_flags[] = {
	{ "VFS_RDONLY",   VFS_RDONLY,   VFS_RDONLY },
	{ "VFS_NOMNTTAB", VFS_NOMNTTAB, VFS_NOMNTTAB },
	{ "VFS_NOSETUID", VFS_NOSETUID, VFS_NOSETUID },
	{ "VFS_REMOUNT",  VFS_REMOUNT,  VFS_REMOUNT },
	{ "VFS_NOTRUNC",  VFS_NOTRUNC,  VFS_NOTRUNC },
	{ "VFS_PXFS",	  VFS_PXFS,	VFS_PXFS },
	{ "VFS_NBMAND",   VFS_NBMAND,   VFS_NBMAND },
	{ "VFS_XATTR",    VFS_XATTR,    VFS_XATTR },
	{ "VFS_NOEXEC",   VFS_NOEXEC,   VFS_NOEXEC },
	{ "VFS_STATS",    VFS_STATS,    VFS_STATS },
	{ "VFS_XID",	  VFS_XID,	VFS_XID },
	{ "VFS_UNLINKABLE", VFS_UNLINKABLE, VFS_UNLINKABLE },
	{ "VFS_UNMOUNTED",  VFS_UNMOUNTED,  VFS_UNMOUNTED },
	{ NULL, 0, 0 }
};

static const mdb_bitmask_t nfs_mi4_flags[] = {
	{ "MI4_HARD",	  MI4_HARD,	MI4_HARD },
	{ "MI4_PRINTED",  MI4_PRINTED,  MI4_PRINTED },
	{ "MI4_INT",	  MI4_INT,	MI4_INT },
	{ "MI4_DOWN",	  MI4_DOWN,	MI4_DOWN },
	{ "MI4_NOAC",	  MI4_NOAC,	MI4_NOAC },
	{ "MI4_NOCTO",    MI4_NOCTO,    MI4_NOCTO },
	{ "MI4_LLOCK",    MI4_LLOCK,    MI4_LLOCK },
	{ "MI4_GRPID",    MI4_GRPID,    MI4_GRPID },
	{ "MI4_SHUTDOWN", MI4_SHUTDOWN, MI4_SHUTDOWN },
	{ "MI4_LINK",	  MI4_LINK,	MI4_LINK },
	{ "MI4_SYMLINK",  MI4_SYMLINK,  MI4_SYMLINK },
	{ "MI4_ACL",	  MI4_ACL,	MI4_ACL },
	{ "MI4_REFERRAL", MI4_REFERRAL, MI4_REFERRAL },
	{ "MI4_NOPRINT",  MI4_NOPRINT,  MI4_NOPRINT },
	{ "MI4_DIRECTIO", MI4_DIRECTIO, MI4_DIRECTIO },
	{ "MI4_PUBLIC",   MI4_PUBLIC,   MI4_PUBLIC },
	{ "MI4_MOUNTING", MI4_MOUNTING, MI4_MOUNTING },
	{ "MI4_DEAD",	  MI4_DEAD,	MI4_DEAD },
	{ "MI4_TIMEDOUT", MI4_TIMEDOUT, MI4_TIMEDOUT },
	{ "MI4_MIRRORMOUNT",  MI4_MIRRORMOUNT, MI4_MIRRORMOUNT },
	{ "MI4_RECOV_ACTIV",  MI4_RECOV_ACTIV, MI4_RECOV_ACTIV },
	{ "MI4_RECOV_FAIL",   MI4_RECOV_FAIL,  MI4_RECOV_FAIL },
	{ "MI4_POSIX_LOCK",   MI4_POSIX_LOCK,  MI4_POSIX_LOCK },
	{ "MI4_LOCK_DEBUG",   MI4_LOCK_DEBUG,  MI4_LOCK_DEBUG },
	{ "MI4_INACTIVE_IDLE",  MI4_INACTIVE_IDLE,  MI4_INACTIVE_IDLE },
	{ "MI4_BADOWNER_DEBUG", MI4_BADOWNER_DEBUG, MI4_BADOWNER_DEBUG },
	{ "MI4_ASYNC_MGR_STOP", MI4_ASYNC_MGR_STOP, MI4_ASYNC_MGR_STOP },
	{ "MI4_EPHEMERAL",	MI4_EPHEMERAL,	    MI4_EPHEMERAL },
	{ "MI4_REMOVE_ON_LAST_CLOSE", MI4_REMOVE_ON_LAST_CLOSE,
	    MI4_REMOVE_ON_LAST_CLOSE },
	{ NULL, 0, 0 }
};

static const mdb_bitmask_t nfs_mi4_recover[] = {
	{ "MI4R_NEED_CLIENTID", MI4R_NEED_CLIENTID, MI4R_NEED_CLIENTID },
	{ "MI4R_REOPEN_FILES",  MI4R_REOPEN_FILES,  MI4R_REOPEN_FILES },
	{ "MI4R_NEED_SECINFO",  MI4R_NEED_SECINFO,  MI4R_NEED_SECINFO },
	{ "MI4R_REOPEN_FILES",  MI4R_REOPEN_FILES,  MI4R_REOPEN_FILES },
	{ "MI4R_SRV_REBOOT",    MI4R_SRV_REBOOT,    MI4R_SRV_REBOOT },
	{ "MI4R_LOST_STATE",    MI4R_LOST_STATE,    MI4R_LOST_STATE },
	{ "MI4R_BAD_SEQID",	MI4R_BAD_SEQID,	    MI4R_BAD_SEQID },
	{ "MI4R_MOVED",		MI4R_MOVED,	    MI4R_MOVED },
	{ "MI4R_NEED_NEW_SERVER", MI4R_NEED_NEW_SERVER, MI4R_NEED_NEW_SERVER },
	{ NULL, 0, 0 }
};

static const char *
nfs4_tag_str(int tag)
{
	switch (tag) {
	case TAG_NONE:
		return ("TAG_NONE");
	case TAG_ACCESS:
		return ("TAG_ACCESS");
	case TAG_CLOSE:
		return ("TAG_CLOSE");
	case TAG_CLOSE_LOST:
		return ("TAG_CLOSE_LOST");
	case TAG_CLOSE_UNDO:
		return ("TAG_CLOSE_UNDO");
	case TAG_COMMIT:
		return ("TAG_COMMIT");
	case TAG_DELEGRETURN:
		return ("TAG_DELEGRETURN");
	case TAG_FSINFO:
		return ("TAG_FSINFO");
	case TAG_GET_SYMLINK:
		return ("TAG_GET_SYMLINK");
	case TAG_GETATTR:
		return ("TAG_GETATTR");
	case TAG_GETATTR_FSLOCATION:
		return ("TAG_GETATTR_FSLOCATION");
	case TAG_INACTIVE:
		return ("TAG_INACTIVE");
	case TAG_LINK:
		return ("TAG_LINK");
	case TAG_LOCK:
		return ("TAG_LOCK");
	case TAG_LOCK_RECLAIM:
		return ("TAG_LOCK_RECLAIM");
	case TAG_LOCK_RESEND:
		return ("TAG_LOCK_RESEND");
	case TAG_LOCK_REINSTATE:
		return ("TAG_LOCK_REINSTATE");
	case TAG_LOCK_UNKNOWN:
		return ("TAG_LOCK_UNKNOWN");
	case TAG_LOCKT:
		return ("TAG_LOCKT");
	case TAG_LOCKU:
		return ("TAG_LOCKU");
	case TAG_LOCKU_RESEND:
		return ("TAG_LOCKU_RESEND");
	case TAG_LOCKU_REINSTATE:
		return ("TAG_LOCKU_REINSTATE");
	case TAG_LOOKUP:
		return ("TAG_LOOKUP");
	case TAG_LOOKUP_PARENT:
		return ("TAG_LOOKUP_PARENT");
	case TAG_LOOKUP_VALID:
		return ("TAG_LOOKUP_VALID");
	case TAG_LOOKUP_VPARENT:
		return ("TAG_LOOKUP_VPARENT");
	case TAG_MKDIR:
		return ("TAG_MKDIR");
	case TAG_MKNOD:
		return ("TAG_MKNOD");
	case TAG_MOUNT:
		return ("TAG_MOUNT");
	case TAG_OPEN:
		return ("TAG_OPEN");
	case TAG_OPEN_CONFIRM:
		return ("TAG_OPEN_CONFIRM");
	case TAG_OPEN_CONFIRM_LOST:
		return ("TAG_OPEN_CONFIRM_LOST");
	case TAG_OPEN_DG:
		return ("TAG_OPEN_DG");
	case TAG_OPEN_DG_LOST:
		return ("TAG_OPEN_DG_LOST");
	case TAG_OPEN_LOST:
		return ("TAG_OPEN_LOST");
	case TAG_OPENATTR:
		return ("TAG_OPENATTR");
	case TAG_PATHCONF:
		return ("TAG_PATHCONF");
	case TAG_PUTROOTFH:
		return ("TAG_PUTROOTFH");
	case TAG_READ:
		return ("TAG_READ");
	case TAG_READAHEAD:
		return ("TAG_READAHEAD");
	case TAG_READDIR:
		return ("TAG_READDIR");
	case TAG_READLINK:
		return ("TAG_READLINK");
	case TAG_RELOCK:
		return ("TAG_RELOCK");
	case TAG_REMAP_LOOKUP:
		return ("TAG_REMAP_LOOKUP");
	case TAG_REMAP_LOOKUP_AD:
		return ("TAG_REMAP_LOOKUP_AD");
	case TAG_REMAP_LOOKUP_NA:
		return ("TAG_REMAP_LOOKUP_NA");
	case TAG_REMAP_MOUNT:
		return ("TAG_REMAP_MOUNT");
	case TAG_RMDIR:
		return ("TAG_RMDIR");
	case TAG_REMOVE:
		return ("TAG_REMOVE");
	case TAG_RENAME:
		return ("TAG_RENAME");
	case TAG_RENAME_VFH:
		return ("TAG_RENAME_VFH");
	case TAG_RENEW:
		return ("TAG_RENEW");
	case TAG_REOPEN:
		return ("TAG_REOPEN");
	case TAG_REOPEN_LOST:
		return ("TAG_REOPEN_LOST");
	case TAG_SECINFO:
		return ("TAG_SECINFO");
	case TAG_SETATTR:
		return ("TAG_SETATTR");
	case TAG_SETCLIENTID:
		return ("TAG_SETCLIENTID");
	case TAG_SETCLIENTID_CF:
		return ("TAG_SETCLIENTID_CF");
	case TAG_SYMLINK:
		return ("TAG_SYMLINK");
	case TAG_WRITE:
		return ("TAG_WRITE");
	default:
		return ("Undefined");
	}
}

/*
 * Return stringified NFS4 error.
 * Note, it may return pointer to static buffer (in case of unknown error)
 */
static const char *
nfs4_stat_str(nfsstat4 err)
{
	static char str[64];

	switch (err) {
	case NFS4_OK:
		return ("NFS4_OK");
	case NFS4ERR_PERM:
		return ("NFS4ERR_PERM");
	case NFS4ERR_NOENT:
		return ("NFS4ERR_NOENT");
	case NFS4ERR_IO:
		return ("NFS4ERR_IO");
	case NFS4ERR_NXIO:
		return ("NFS4ERR_NXIO");
	case NFS4ERR_ACCESS:
		return ("NFS4ERR_ACCESS");
	case NFS4ERR_EXIST:
		return ("NFS4ERR_EXIST");
	case NFS4ERR_XDEV:
		return ("NFS4ERR_XDEV");
	case NFS4ERR_NOTDIR:
		return ("NFS4ERR_NOTDIR");
	case NFS4ERR_ISDIR:
		return ("NFS4ERR_ISDIR");
	case NFS4ERR_INVAL:
		return ("NFS4ERR_INVAL");
	case NFS4ERR_FBIG:
		return ("NFS4ERR_FBIG");
	case NFS4ERR_NOSPC:
		return ("NFS4ERR_NOSPC");
	case NFS4ERR_ROFS:
		return ("NFS4ERR_ROFS");
	case NFS4ERR_MLINK:
		return ("NFS4ERR_MLINK");
	case NFS4ERR_NAMETOOLONG:
		return ("NFS4ERR_NAMETOOLONG");
	case NFS4ERR_NOTEMPTY:
		return ("NFS4ERR_NOTEMPTY");
	case NFS4ERR_DQUOT:
		return ("NFS4ERR_DQUOT");
	case NFS4ERR_STALE:
		return ("NFS4ERR_STALE");
	case NFS4ERR_BADHANDLE:
		return ("NFS4ERR_BADHANDLE");
	case NFS4ERR_BAD_COOKIE:
		return ("NFS4ERR_BAD_COOKIE");
	case NFS4ERR_NOTSUPP:
		return ("NFS4ERR_NOTSUPP");
	case NFS4ERR_TOOSMALL:
		return ("NFS4ERR_TOOSMALL");
	case NFS4ERR_SERVERFAULT:
		return ("NFS4ERR_SERVERFAULT");
	case NFS4ERR_BADTYPE:
		return ("NFS4ERR_BADTYPE");
	case NFS4ERR_DELAY:
		return ("NFS4ERR_DELAY");
	case NFS4ERR_SAME:
		return ("NFS4ERR_SAME");
	case NFS4ERR_DENIED:
		return ("NFS4ERR_DENIED");
	case NFS4ERR_EXPIRED:
		return ("NFS4ERR_EXPIRED");
	case NFS4ERR_LOCKED:
		return ("NFS4ERR_LOCKED");
	case NFS4ERR_GRACE:
		return ("NFS4ERR_GRACE");
	case NFS4ERR_FHEXPIRED:
		return ("NFS4ERR_FHEXPIRED");
	case NFS4ERR_SHARE_DENIED:
		return ("NFS4ERR_SHARE_DENIED");
	case NFS4ERR_WRONGSEC:
		return ("NFS4ERR_WRONGSEC");
	case NFS4ERR_CLID_INUSE:
		return ("NFS4ERR_CLID_INUSE");
	case NFS4ERR_RESOURCE:
		return ("NFS4ERR_RESOURCE");
	case NFS4ERR_MOVED:
		return ("NFS4ERR_MOVED");
	case NFS4ERR_NOFILEHANDLE:
		return ("NFS4ERR_NOFILEHANDLE");
	case NFS4ERR_MINOR_VERS_MISMATCH:
		return ("NFS4ERR_MINOR_VERS_MISMATCH");
	case NFS4ERR_STALE_CLIENTID:
		return ("NFS4ERR_STALE_CLIENTID");
	case NFS4ERR_STALE_STATEID:
		return ("NFS4ERR_STALE_STATEID");
	case NFS4ERR_OLD_STATEID:
		return ("NFS4ERR_OLD_STATEID");
	case NFS4ERR_BAD_STATEID:
		return ("NFS4ERR_BAD_STATEID");
	case NFS4ERR_BAD_SEQID:
		return ("NFS4ERR_BAD_SEQID");
	case NFS4ERR_NOT_SAME:
		return ("NFS4ERR_NOT_SAME");
	case NFS4ERR_LOCK_RANGE:
		return ("NFS4ERR_LOCK_RANGE");
	case NFS4ERR_SYMLINK:
		return ("NFS4ERR_SYMLINK");
	case NFS4ERR_RESTOREFH:
		return ("NFS4ERR_RESTOREFH");
	case NFS4ERR_LEASE_MOVED:
		return ("NFS4ERR_LEASE_MOVED");
	case NFS4ERR_ATTRNOTSUPP:
		return ("NFS4ERR_ATTRNOTSUPP");
	case NFS4ERR_NO_GRACE:
		return ("NFS4ERR_NO_GRACE");
	case NFS4ERR_RECLAIM_BAD:
		return ("NFS4ERR_RECLAIM_BAD");
	case NFS4ERR_RECLAIM_CONFLICT:
		return ("NFS4ERR_RECLAIM_CONFLICT");
	case NFS4ERR_BADXDR:
		return ("NFS4ERR_BADXDR");
	case NFS4ERR_LOCKS_HELD:
		return ("NFS4ERR_LOCKS_HELD");
	case NFS4ERR_OPENMODE:
		return ("NFS4ERR_OPENMODE");
	case NFS4ERR_BADOWNER:
		return ("NFS4ERR_BADOWNER");
	case NFS4ERR_BADCHAR:
		return ("NFS4ERR_BADCHAR");
	case NFS4ERR_BADNAME:
		return ("NFS4ERR_BADNAME");
	case NFS4ERR_BAD_RANGE:
		return ("NFS4ERR_BAD_RANGE");
	case NFS4ERR_LOCK_NOTSUPP:
		return ("NFS4ERR_LOCK_NOTSUPP");
	case NFS4ERR_OP_ILLEGAL:
		return ("NFS4ERR_OP_ILLEGAL");
	case NFS4ERR_DEADLOCK:
		return ("NFS4ERR_DEADLOCK");
	case NFS4ERR_FILE_OPEN:
		return ("NFS4ERR_FILE_OPEN");
	case NFS4ERR_ADMIN_REVOKED:
		return ("NFS4ERR_ADMIN_REVOKED");
	case NFS4ERR_CB_PATH_DOWN:
		return ("NFS4ERR_CB_PATH_DOWN");
	default:
		mdb_snprintf(str, sizeof (str), "Unknown %d", err);
		return (str);
	}
}

static const char *
nfs4_op_str(uint_t op)
{
	switch (op) {
	case OP_ACCESS:
		return ("OP_ACCESS");
	case OP_CLOSE:
		return ("OP_CLOSE");
	case OP_COMMIT:
		return ("OP_COMMIT");
	case OP_CREATE:
		return ("OP_CREATE");
	case OP_DELEGPURGE:
		return ("OP_DELEGPURGE");
	case OP_DELEGRETURN:
		return ("OP_DELEGRETURN");
	case OP_GETATTR:
		return ("OP_GETATTR");
	case OP_GETFH:
		return ("OP_GETFH");
	case OP_LINK:
		return ("OP_LINK");
	case OP_LOCK:
		return ("OP_LOCK");
	case OP_LOCKT:
		return ("OP_LOCKT");
	case OP_LOCKU:
		return ("OP_LOCKU");
	case OP_LOOKUP:
		return ("OP_LOOKUP");
	case OP_LOOKUPP:
		return ("OP_LOOKUPP");
	case OP_NVERIFY:
		return ("OP_NVERIFY");
	case OP_OPEN:
		return ("OP_OPEN");
	case OP_OPENATTR:
		return ("OP_OPENATTR");
	case OP_OPEN_CONFIRM:
		return ("OP_OPEN_CONFIRM");
	case OP_OPEN_DOWNGRADE:
		return ("OP_OPEN_DOWNGRADE");
	case OP_PUTFH:
		return ("OP_PUTFH");
	case OP_PUTPUBFH:
		return ("OP_PUTPUBFH");
	case OP_PUTROOTFH:
		return ("OP_PUTROOTFH");
	case OP_READ:
		return ("OP_READ");
	case OP_READDIR:
		return ("OP_READDIR");
	case OP_READLINK:
		return ("OP_READLINK");
	case OP_REMOVE:
		return ("OP_REMOVE");
	case OP_RENAME:
		return ("OP_RENAME");
	case OP_RENEW:
		return ("OP_RENEW");
	case OP_RESTOREFH:
		return ("OP_RESTOREFH");
	case OP_SAVEFH:
		return ("OP_SAVEFH");
	case OP_SECINFO:
		return ("OP_SECINFO");
	case OP_SETATTR:
		return ("OP_SETATTR");
	case OP_SETCLIENTID:
		return ("OP_SETCLIENTID");
	case OP_SETCLIENTID_CONFIRM:
		return ("OP_SETCLIENTID_CONFIRM");
	case OP_VERIFY:
		return ("OP_VERIFY");
	case OP_WRITE:
		return ("OP_WRITE");
	case OP_RELEASE_LOCKOWNER:
		return ("OP_RELEASE_LOCKOWNER");
	case OP_ILLEGAL:
		return ("OP_ILLEGAL");
	default:
		return ("Unknown");
	}
}

static const char *
nfs4_recov_str(uint_t act)
{
	switch (act) {
	case NR_UNUSED:
		return ("NR_UNUSED");
	case NR_STALE:
		return ("NR_STALE");
	case NR_FAILOVER:
		return ("NR_FAILOVER");
	case NR_CLIENTID:
		return ("NR_CLIENTID");
	case NR_OPENFILES:
		return ("NR_OPENFILES");
	case NR_WRONGSEC:
		return ("NR_WRONGSEC");
	case NR_EXPIRED:
		return ("NR_EXPIRED");
	case NR_BAD_STATEID:
		return ("NR_BAD_STATEID");
	case NR_FHEXPIRED:
		return ("NR_FHEXPIRED");
	case NR_BADHANDLE:
		return ("NR_BADHANDLE");
	case NR_BAD_SEQID:
		return ("NR_BAD_SEQID");
	case NR_OLDSTATEID:
		return ("NR_OLDSTATEID");
	case NR_GRACE:
		return ("NR_GRACE");
	case NR_DELAY:
		return ("NR_DELAY");
	case NR_LOST_LOCK:
		return ("NR_LOST_LOCK");
	case NR_LOST_STATE_RQST:
		return ("NR_LOST_STATE_RQST");
	case NR_MOVED:
		return ("NR_MOVED");
	default:
		return ("Unknown");
	}
}

static void
nfs_addr_by_conf(uintptr_t knconf, struct netbuf *addr,
    char *s, size_t nbytes)
{
	struct knetconfig conf;
	char buf[16];

	if (mdb_vread(&conf, sizeof (conf), knconf) == -1) {
		mdb_warn("can't read sv_knconf");
		return;
	}

	if (mdb_readstr(buf, sizeof (buf),
	    (uintptr_t)conf.knc_protofmly) == -1) {
		mdb_warn("can't read knc_protofmly");
		return;
	}
	/* Support only IPv4 addresses */
	if (strcmp(NC_INET, buf) == 0) {
		struct sockaddr_in *in;

		in = mdb_alloc(addr->len + 1, UM_SLEEP | UM_GC);
		if (mdb_vread(in, addr->len, (uintptr_t)addr->buf) == -1)
			return;

		mdb_nhconvert(&in->sin_port, &in->sin_port,
		    sizeof (in->sin_port));

		(void) mdb_snprintf(s, nbytes, "%I:%d", in->sin_addr.s_addr,
		    in->sin_port);
	}
}

/*
 * Get IPv4 string address by servinfo4_t
 *
 * in case of error does not modify 's'
 */
static void
nfs_addr_by_servinfo4(uintptr_t addr, char *s, size_t nbytes)
{
	struct servinfo4 *si;

	si = mdb_alloc(sizeof (*si), UM_SLEEP | UM_GC);
	if (mdb_vread(si, sizeof (*si), addr) == -1) {
		mdb_warn("can't read servinfo4");
		return;
	}

	nfs_addr_by_conf((uintptr_t)si->sv_knconf, &si->sv_addr,
	    s, nbytes);
}


/*
 * Get IPv4 string address by servinfo_t
 *
 * in case of error does not modify 's'
 */
static void
nfs_addr_by_servinfo(uintptr_t addr, char *s, size_t nbytes)
{
	struct servinfo *si;

	si = mdb_alloc(sizeof (*si), UM_SLEEP | UM_GC);
	if (mdb_vread(si, sizeof (*si), addr) == -1) {
		mdb_warn("can't read servinfo");
		return;
	}

	nfs_addr_by_conf((uintptr_t)si->sv_knconf, &si->sv_addr,
	    s, nbytes);
}

static void
nfs_queue_show_event(const nfs4_debug_msg_t *msg)
{
	const nfs4_revent_t *re;
	time_t time;
	char *re_char1 = "<unknown>", *re_char2 = "<unknown>";

	re = &msg->rmsg_u.msg_event;
	time = msg->msg_time.tv_sec;

	if (re->re_char1 != NULL) {
		char *s;

		s = mdb_alloc(MAXPATHLEN, UM_SLEEP | UM_GC);
		if (mdb_readstr(s, MAXPATHLEN, (uintptr_t)re->re_char1) != -1)
			re_char1 = s;
		else
			mdb_warn("can't read re_char1");
	}

	if (re->re_char2 != NULL) {
		char *s;

		s = mdb_alloc(MAXPATHLEN, UM_SLEEP | UM_GC);

		if (mdb_readstr(s, MAXPATHLEN, (uintptr_t)re->re_char2) != -1)
			re_char2 = s;
		else
			mdb_warn("can't read re_char2");
	}

	switch (re->re_type) {
	case RE_BAD_SEQID:
		mdb_printf("[NFS4]%Y: Op %s for file %s rnode_pt %p\n"
		    "pid %d using seqid %d got %s. Last good seqid was %d "
		    "for operation %s\n",
		    time, nfs4_tag_str(re->re_tag1), re->re_char1, re->re_rp1,
		    re->re_pid, re->re_seqid1, nfs4_stat_str(re->re_stat4),
		    re->re_seqid2, nfs4_tag_str(re->re_tag2));
		break;
	case RE_BADHANDLE:
		mdb_printf("[NFS4]%Y: server said filehandle was "
		    "invalid for file: %s rnode_pt 0x%p\n", time,
		    re_char1, re->re_rp1);
		break;
	case RE_CLIENTID:
		mdb_printf("[NFS4]%Y: Can't recover clientid on mountpoint %s\n"
		    "mi %p due to error %d (%s). Marking file system "
		    "as unusable\n", time, msg->msg_mntpt,
		    re->re_mi, re->re_uint, nfs4_stat_str(re->re_stat4));
		break;
	case RE_DEAD_FILE:
		mdb_printf("[NFS4]%Y: File: %s rnode_pt: %p was closed on NFS\n"
		    "recovery error [%s %s]\n", time, re_char1, re->re_rp1,
		    re_char2, nfs4_stat_str(re->re_stat4));
		break;
	case RE_END:
		mdb_printf("[NFS4]%Y: NFS Recovery done for mi %p "
		    "rnode_pt1 %s (%p), rnode_pt2 %s (%p)\n", time, re->re_mi,
		    re_char1, re->re_rp1, re_char2, re->re_rp2);
		break;

	case RE_FAIL_RELOCK:
		mdb_printf("[NFS4]%Y: Couldn't reclaim lock for pid %d for\n"
		    "file %s (rnode_pt %p) error %d\n", time, re->re_pid,
		    re_char1, re->re_rp1,
		    re->re_uint ? re->re_uint : re->re_stat4);
		break;
	case RE_FAIL_REMAP_LEN:
		mdb_printf("[NFS4]%Y: remap_lookup: returned bad\n"
		    "fhandle length %d\n", time, re->re_uint);
		break;
	case RE_FAIL_REMAP_OP:
		mdb_printf("[NFS4]%Y: remap_lookup: didn't get expected "
		    " OP_GETFH\n", time);
		break;
	case RE_FAILOVER:
		mdb_printf("[NFS4]%Y: failing over to %s\n", time, re_char1);
		break;

	case RE_FILE_DIFF:
		mdb_printf("[NFS4]%Y: File %s rnode_pt: %p was closed\n"
		    "and failed attempted failover since its is different\n"
		    "than the original file\n", time, re_char1, re->re_rp1);
		break;

	case RE_LOST_STATE:
		mdb_printf("[NFS4]%Y: Lost %s request file %s\n"
		    "rnode_pt: %p, dir %s (%p)\n", time,
		    nfs4_op_str(re->re_uint), re_char1,
		    re->re_rp1, re_char2, re->re_rp2);
		break;
	case RE_OPENS_CHANGED:
		mdb_printf("[NFS4]%Y: The number of open files to reopen\n"
		    "changed for mount %s mi %p old %d, new %d\n", time,
		    msg->msg_mntpt, re->re_mi, re->re_uint, re->re_pid);
		break;
	case RE_SIGLOST:
	case RE_SIGLOST_NO_DUMP:
		mdb_printf("[NFS4]%Y: Process %d lost its locks on file %s\n"
		    "rnode_pt: %p due to NFS recovery error (%d:%s)\n",
		    time, re->re_pid, re_char1,
		    re->re_rp1, re->re_uint, nfs4_stat_str(re->re_stat4));
		break;
	case RE_START:
		mdb_printf("[NFS4]%Y: NFS Starting recovery for\n"
		    "mi %p mi_recovflags [0x%x] rnode_pt1 %s %p "
		    "rnode_pt2 %s %p\n", time,
		    re->re_mi, re->re_uint, re_char1, re->re_rp1,
		    re_char2, re->re_rp2);
		break;
	case RE_UNEXPECTED_ACTION:
		mdb_printf("[NFS4]%Y: NFS recovery: unexpected action %s\n",
		    time, nfs4_recov_str(re->re_uint));
		break;
	case RE_UNEXPECTED_ERRNO:
		mdb_printf("[NFS4]%Y: NFS recovery: unexpected errno %d\n",
		    time, re->re_uint);
		break;
	case RE_UNEXPECTED_STATUS:
		mdb_printf("[NFS4]%Y: NFS recovery: unexpected status"
		    "code (%s)\n", time, nfs4_stat_str(re->re_stat4));
		break;
	case RE_WRONGSEC:
		mdb_printf("[NFS4]%Y: NFS can't recover from NFS4ERR_WRONGSEC\n"
		    "error %d rnode_pt1 %s (%p) rnode_pt2 %s (0x%p)\n", time,
		    re->re_uint, re_char1, re->re_rp1, re_char2, re->re_rp2);
		break;
	case RE_LOST_STATE_BAD_OP:
		mdb_printf("[NFS4]%Y: NFS lost state with unrecognized op %d\n"
		    "fs %s, pid %d, file %s (rnode_pt: %p) dir %s (%p)\n",
		    time, re->re_uint, msg->msg_mntpt, re->re_pid, re_char1,
		    re->re_rp1, re_char2, re->re_rp2);
		break;
	case RE_REFERRAL:
		mdb_printf("[NFS4]%Y: being referred to %s\n",
		    time, re_char1);
		break;
	default:
		mdb_printf("illegal event %d\n", re->re_type);
		break;
	}
}

static void
nfs_queue_show_fact(const nfs4_debug_msg_t *msg)
{
	time_t time;
	const nfs4_rfact_t *rf;
	char *rf_char1 = "<unknown>";

	rf = &msg->rmsg_u.msg_fact;
	time = msg->msg_time.tv_sec;

	if (rf->rf_char1 != NULL) {
		char *s;

		s = mdb_alloc(MAXPATHLEN, UM_SLEEP | UM_GC);
		if (mdb_readstr(s, MAXPATHLEN, (uintptr_t)rf->rf_char1) != -1)
			rf_char1 = s;
		else
			mdb_warn("can't read rf_char1");
	}

	switch (rf->rf_type) {
	case RF_ERR:
		mdb_printf("[NFS4]%Y: NFS op %s got "
		    "error %s:%d causing recovery action %s.%s\n",
		    time, nfs4_op_str(rf->rf_op),
		    rf->rf_error ? "" : nfs4_stat_str(rf->rf_stat4),
		    rf->rf_error,
		    nfs4_recov_str(rf->rf_action),
		    rf->rf_reboot ?
		    "  Client also suspects that the server rebooted,"
		    " or experienced a network partition." : "");
		break;
	case RF_RENEW_EXPIRED:
		mdb_printf("[NFS4]%Y: NFS4 renew thread detected client's "
		    "lease has expired. Current open files/locks/IO may fail\n",
		    time);
		break;
	case RF_SRV_NOT_RESPOND:
		mdb_printf("[NFS4]%Y: NFS server not responding;"
		    "still trying\n", time);
		break;
	case RF_SRV_OK:
		mdb_printf("[NFS4]%Y: NFS server ok\n", time);
		break;
	case RF_SRVS_NOT_RESPOND:
		mdb_printf("[NFS4]%Y: NFS servers not responding; "
		    "still trying\n", time);
		break;
	case RF_SRVS_OK:
		mdb_printf("[NFS4]%Y: NFS servers ok\n", time);
		break;
	case RF_DELMAP_CB_ERR:
		mdb_printf("[NFS4]%Y: NFS op %s got error %s when executing "
		    "delmap on file %s rnode_pt %p\n", time,
		    nfs4_op_str(rf->rf_op), nfs4_stat_str(rf->rf_stat4),
		    rf_char1, rf->rf_rp1);
		break;
	case RF_SENDQ_FULL:
		mdb_printf("[NFS4]%Y: sending queue to NFS server is full; "
		    "still trying\n", time);
		break;

	default:
		mdb_printf("queue_print_fact: illegal fact %d\n", rf->rf_type);
	}
}

static int
nfs4_show_message(uintptr_t addr, const void *arg, void *data)
{
	nfs4_debug_msg_t msg;
	if (mdb_vread(&msg, sizeof (msg), addr) == -1) {
		mdb_warn("failed to read nfs4_debug_msg_t at %p", addr);
		return (WALK_ERR);
	}

	if (msg.msg_type == RM_EVENT)
		nfs_queue_show_event(&msg);
	else if (msg.msg_type == RM_FACT)
		nfs_queue_show_fact(&msg);
	else
		mdb_printf("Wrong msg_type %d\n", msg.msg_type);
	return (WALK_NEXT);
}

static void
nfs4_print_messages(uintptr_t head)
{
	mdb_printf("-----------------------------\n");
	mdb_printf("Messages queued:\n");
	mdb_inc_indent(2);
	mdb_pwalk("list", nfs4_show_message, NULL, (uintptr_t)head);
	mdb_dec_indent(2);
	mdb_printf("-----------------------------\n");
}


static void
nfs_print_mi4(uintptr_t miaddr, int verbose)
{
	mntinfo4_t *mi;
	char str[INET6_ADDRSTRLEN] = "";

	mi = mdb_alloc(sizeof (*mi), UM_SLEEP | UM_GC);
	if (mdb_vread(mi, sizeof (*mi), miaddr) == -1) {
		mdb_warn("can't read mntinfo");
		return;
	}

	mdb_printf("mntinfo4_t:    %p\n", miaddr);
	mdb_printf("NFS Version:   4\n");
	mdb_printf("mi_flags:      %b\n", mi->mi_flags, nfs_mi4_flags);
	mdb_printf("mi_error:      %x\n", mi->mi_error);
	mdb_printf("mi_open_files: %d\n", mi->mi_open_files);
	mdb_printf("mi_msg_count:  %d\n", mi->mi_msg_count);
	mdb_printf("mi_recovflags: %b\n", mi->mi_recovflags,
	    nfs_mi4_recover);
	mdb_printf("mi_recovthread: %p\n", mi->mi_recovthread);
	mdb_printf("mi_in_recovery: %d\n", mi->mi_in_recovery);

	if (verbose == 0)
		return;

	mdb_printf("mi_zone:     %p\n", mi->mi_zone);
	mdb_printf("mi_curread:  %d\n", mi->mi_curread);
	mdb_printf("mi_curwrite: %d\n", mi->mi_curwrite);
	mdb_printf("mi_retrans:  %d\n", mi->mi_retrans);
	mdb_printf("mi_timeo:    %d\n", mi->mi_timeo);
	mdb_printf("mi_acregmin: %llu\n", mi->mi_acregmin);
	mdb_printf("mi_acregmax: %llu\n", mi->mi_acregmax);
	mdb_printf("mi_acdirmin: %llu\n", mi->mi_acdirmin);
	mdb_printf("mi_acdirmax: %llu\n", mi->mi_acdirmax);
	mdb_printf("mi_count:    %u\n", mi->mi_count);
	mdb_printf("\nServer list: %p\n", mi->mi_servers);
	nfs_addr_by_servinfo4((uintptr_t)mi->mi_curr_serv, str, sizeof (str));
	mdb_printf("Curr Server: %p %s\n", mi->mi_curr_serv, str);
	mdb_printf("Total:\n");
	mdb_inc_indent(2);
	mdb_printf("Server Non-responses: %u\n", mi->mi_noresponse);
	mdb_printf("Server Failovers:     %u\n\n", mi->mi_failover);
	mdb_dec_indent(2);

	mdb_printf("\nAsync Request queue:\n");
	mdb_inc_indent(2);
	mdb_printf("max threads:     %u\n", mi->mi_max_threads);
	mdb_printf("active threads:  %u\n", mi->mi_threads[NFS_ASYNC_QUEUE]);
	mdb_dec_indent(2);

	nfs4_print_messages(miaddr + OFFSETOF(mntinfo4_t, mi_msg_list));
}

static void
nfs_print_mi(uintptr_t miaddr, uint_t vers)
{
	mntinfo_t *mi;
	char str[INET6_ADDRSTRLEN] = "";

	mi = mdb_alloc(sizeof (*mi), UM_SLEEP | UM_GC);
	if (mdb_vread(mi, sizeof (*mi), miaddr) == -1) {
		mdb_warn("can't read mntinfo");
		return;
	}

	mdb_printf("\nServer list: %p\n", mi->mi_servers);
	nfs_addr_by_servinfo((uintptr_t)mi->mi_curr_serv, str, sizeof (str));
	mdb_printf("Curr Server: %p %s\n", mi->mi_curr_serv, str);
	mdb_printf("Total:\n");
	mdb_inc_indent(2);
	mdb_printf("Server Non-responses: %u\n", mi->mi_noresponse);
	mdb_printf("Server Failovers:     %u\n\n", mi->mi_failover);
	mdb_dec_indent(2);

	mdb_printf("\nAsync Request queue:\n");
	mdb_inc_indent(2);
	mdb_printf("max threads:     %u\n", mi->mi_max_threads);
	mdb_printf("active threads:  %u\n", mi->mi_threads[NFS_ASYNC_QUEUE]);
	mdb_dec_indent(2);
}

static int
nfs_vfs_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	vfs_t *vfs;
	char buf[MAXNAMELEN];
	int verbose = 0;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		if (mdb_walk_dcmd("nfs_vfs", "nfs_vfs", argc, argv) == -1) {
			mdb_warn("failed to walk nfs_vfs");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	vfs = mdb_alloc(sizeof (*vfs), UM_SLEEP | UM_GC);

	if (mdb_vread(vfs, sizeof (*vfs), addr) == -1) {
		mdb_warn("failed to read vfs");
		return (DCMD_ERR);
	}

	mdb_printf("vfs_t->%p, data = %p, ops = %p\n",
	    addr, vfs->vfs_data, vfs->vfs_op);

	/* do not need do vread for vfs_mntpt because take address */
	if (mdb_readstr(buf, MAXNAMELEN,
	    (uintptr_t)&vfs->vfs_mntpt->rs_string) == -1)
		return (DCMD_ERR);

	mdb_inc_indent(2);

	mdb_printf("mount point: %s\n", buf);
	if (mdb_readstr(buf, MAXNAMELEN,
	    (uintptr_t)&vfs->vfs_resource->rs_string) == -1) {
		mdb_warn("can't read rs_string");
		goto err;
	}
	mdb_printf("mount  from: %s\n", buf);

	if (verbose) {
		uintptr_t nfs4_ops;
		mntopt_t m;
		uint_t i;

		mdb_printf("vfs_flags:  %b\n", vfs->vfs_flag, vfs_flags);
		mdb_printf("mount opts: ");
		for (i = 0; i < vfs->vfs_mntopts.mo_count; i++) {
			uintptr_t a = (uintptr_t)(vfs->vfs_mntopts.mo_list + i);

			if (mdb_vread(&m, sizeof (m), a) == -1) {
				mdb_warn("can't read mntopt");
				continue;
			}
			if (m.mo_flags & MO_EMPTY)
				continue;

			if (mdb_readstr(buf, sizeof (buf),
			    (uintptr_t)m.mo_name) == -1) {
				mdb_warn("can't read mo_name");
				continue;
			}
			if (m.mo_flags & MO_HASVALUE) {
				char val[64];

				if (mdb_readstr(val, sizeof (val),
				    (uintptr_t)m.mo_arg) == -1) {
					mdb_warn("can't read mo_arg");
					continue;
				}
				mdb_printf("%s(%s), ", buf, val);
			} else
				mdb_printf("%s, ", buf);
		}
		mdb_printf("\n+--------------------------------------+\n");

		if (mdb_readvar(&nfs4_ops, "nfs4_vfsops") == -1) {
			mdb_warn("failed read %s", "nfs4_vfsops");
			goto err;
		}
		if (nfs4_ops == (uintptr_t)vfs->vfs_op) {
			nfs_print_mi4((uintptr_t)VFTOMI4(vfs), 1);
		} else {
			int vers = 3;
			uintptr_t nfs3_ops;

			if (mdb_readvar(&nfs3_ops, "nfs3_vfsops") == -1) {
				mdb_warn("failed read %s", "nfs3_vfsops");
				goto err;
			}
			if (nfs3_ops != (uintptr_t)vfs->vfs_op)
				vers = 2;

			nfs_print_mi((uintptr_t)VFTOMI(vfs), vers);
		}
	}
	mdb_dec_indent(2);
	mdb_printf("\n");
	return (DCMD_OK);
err:
	mdb_dec_indent(2);
	mdb_printf("\n");
	return (DCMD_ERR);
}


static int
nfs4_diag_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	mntinfo4_t *mi;
	vfs_t *vfs;
	char buf[MAXNAMELEN];

	if ((flags & DCMD_ADDRSPEC) == 0) {
		if (mdb_walk_dcmd("nfs4_mnt", "nfs4_diag", argc,
		    argv) == -1) {
			mdb_warn("failed to walk nfs4_mnt");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	mi = mdb_alloc(sizeof (*mi), UM_SLEEP | UM_GC);
	if (mdb_vread(mi, sizeof (*mi), addr) == -1) {
		mdb_warn("can't read mntinfo4");
		return (WALK_ERR);
	}

	vfs = mdb_alloc(sizeof (*vfs), UM_SLEEP | UM_GC);
	if (mdb_vread(vfs, sizeof (*vfs), (uintptr_t)mi->mi_vfsp) == -1) {
		mdb_warn("failed to read vfs");
		return (DCMD_ERR);
	}

	mdb_printf("****************************************\n");
	mdb_printf("vfs: %-16p mi: %-16p\n", mi->mi_vfsp, addr);

	if (mdb_readstr(buf, MAXNAMELEN,
	    (uintptr_t)&vfs->vfs_mntpt->rs_string) == -1)
		return (DCMD_ERR);

	mdb_inc_indent(2);
	mdb_printf("mount point:   %s\n", buf);
	if (mdb_readstr(buf, MAXNAMELEN,
	    (uintptr_t)&vfs->vfs_resource->rs_string) == -1) {
		mdb_warn("can't read rs_string");
		mdb_dec_indent(2);
		return (DCMD_ERR);
	}
	mdb_printf("mount  from:   %s\n", buf);
	nfs4_print_messages(addr + OFFSETOF(mntinfo4_t, mi_msg_list));
	mdb_dec_indent(2);
	mdb_printf("\n");
	return (DCMD_OK);
}

static void
nfs4_diag_help(void)
{
	mdb_printf(" <mntinfo4_t>::nfs4_diag <-s>\n"
	    "      -> assumes client is an illumos NFSv4 client\n");
}

static int
nfs_rnode4_cb(uintptr_t addr, const void *data, void *arg)
{
	const rnode4_t *rp = data;
	nfs_rnode_cbdata_t *cbd = arg;
	vnode_t *vp;

	if (addr == 0)
		return (WALK_DONE);

	vp = mdb_alloc(sizeof (*vp), UM_SLEEP | UM_GC);
	if (mdb_vread(vp, sizeof (*vp), (uintptr_t)rp->r_vnode) == -1) {
		mdb_warn("can't read vnode_t %p", (uintptr_t)rp->r_vnode);
		return (WALK_ERR);
	}

	if (cbd->vfs_addr != 0 &&
	    cbd->vfs_addr != (uintptr_t)vp->v_vfsp)
		return (WALK_NEXT);

	if (cbd->printed_hdr == 0) {
		mdb_printf("%-16s %-16s %-16s %-8s\n"
		    "%-16s %-8s %-8s %s\n",
		    "Address", "r_vnode", "vfsp", "r_fh",
		    "r_server", "r_error", "r_flags", "r_count");
		cbd->printed_hdr = 1;
	}

	mdb_printf("%-?p %-8p %-8p %-8p\n"
	    "%-16p %-8u %-8x  %u\n",
	    addr, rp->r_vnode, vp->v_vfsp, rp->r_fh,
	    rp->r_server, (int)rp->r_error, rp->r_flags, rp->r_count);

	return (WALK_NEXT);
}

static int
nfs_rnode4_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	nfs_rnode_cbdata_t *cbd;
	rnode4_t *rp;

	cbd = mdb_zalloc(sizeof (*cbd),  UM_SLEEP | UM_GC);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		if (mdb_walk("nfs_rtable4", nfs_rnode4_cb, cbd) == -1) {
			mdb_warn("failed to walk nfs_rnode4");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	/* address was specified */
	rp = mdb_alloc(sizeof (*rp), UM_SLEEP | UM_GC);
	if (mdb_vread(rp, sizeof (*rp), addr) == -1) {
		mdb_warn("can't read rnode4_t");
		return (DCMD_ERR);
	}

	nfs_rnode4_cb(addr, rp, cbd);
	return (DCMD_OK);
}

static void
nfs_rnode4_help(void)
{
	mdb_printf("<rnode4 addr>::nfs_rnode4\n\n"
	    "This prints NFSv4 rnode at address specified. If address\n"
	    "is not specified, walks entire NFSv4 rnode table.\n");
}

static int
nfs_rnode4find_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	nfs_rnode_cbdata_t *cbd;

	cbd = mdb_zalloc(sizeof (*cbd),  UM_SLEEP | UM_GC);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_printf("requires address of vfs_t\n");
		return (DCMD_USAGE);
	}

	cbd->vfs_addr = addr;
	if (mdb_walk("nfs_rtable4", nfs_rnode4_cb, cbd) == -1) {
		mdb_warn("failed to walk nfs_rnode4");
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}

static void
nfs_rnode4find_help(void)
{
	mdb_printf("<vfs addr>::nfs_rnode4find\n\n"
	    "This prints all NFSv4 rnodes that belong to\n"
	    "the VFS address specified\n");
}

static int nfs_help_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);

extern int nfs_stat_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);

static const mdb_dcmd_t dcmds[] = {
	/* svc */
	{
		"svc_pool", "?[-v] [poolid ...]",
		"display SVCPOOL information\n"
		"\t\t\t(Optional address of SVCPOOL)",
		svc_pool_dcmd, svc_pool_help
	},
	{
		"svc_mxprt", ":[-w]",
		"display master xprt info given SVCMASTERXPRT",
		svc_mxprt_dcmd, svc_mxprt_help
	},
	/* rfs4 */
	{
		"rfs4_db", "?",
		"dump NFSv4 server database\n"
		"\t\t\t(Optional address of zone_t)",
		rfs4_db_dcmd
	},
	{
		"rfs4_tbl", ":[-vw]",
		"dump NFSv4 server table given rfs4_table_t",
		rfs4_tbl_dcmd, rfs4_tbl_help
	},
	{
		"rfs4_idx", ":[-w]",
		"dump NFSv4 server index given rfs4_index_t",
		rfs4_idx_dcmd, rfs4_idx_help
	},
	{
		"rfs4_bkt", ":",
		"dump NFSv4 server index buckets given rfs4_index_t",
		rfs4_bkt_dcmd
	},
	{
		"rfs4_oo", "?",
		"dump NFSv4 rfs4_openowner_t structures from bucket data\n"
		"\t\t\t(Optional address of rfs4_openowner_t)",
		rfs4_oo_dcmd
	},
	{
		"rfs4_osid", "?[-v]",
		"dump NFSv4 rfs4_state_t structures from bucket data\n"
		"\t\t\t(Optional address of rfs4_state_t)",
		rfs4_osid_dcmd
	},
	{
		"rfs4_file", "?[-v]",
		"dump NFSv4 rfs4_file_t structures from bucket data\n"
		"\t\t\t(Optional address of rfs4_file_t)",
		rfs4_file_dcmd
	},
	{
		"rfs4_deleg", "?[-v]",
		"dump NFSv4 rfs4_deleg_state_t structures from bucket data\n"
		"\t\t\t(Optional address of rfs4_deleg_state_t)",
		rfs4_deleg_dcmd
	},
	{
		"rfs4_lo", "?",
		"dump NFSv4 rfs4_lockowner_t structures from bucket data\n"
		"\t\t\t(Optional address of rfs4_lockowner_t)",
		rfs4_lo_dcmd
	},
	{
		"rfs4_lsid", "?[-v]",
		"dump NFSv4 rfs4_lo_state_t structures from bucket data\n"
		"\t\t\t(Optional address of rfs4_lo_state_t)",
		rfs4_lsid_dcmd
	},
	{
		"rfs4_client", "?[-c <clientid>]",
		"dump NFSv4 rfs4_client_t structures from bucket data\n"
		"\t\t\t(Optional address of rfs4_client_t)",
		rfs4_client_dcmd, rfs4_client_help
	},
	/* NFS server */
	{
		"nfs_expvis", ":",
		"dump exp_visible_t structure",
		nfs_expvis_dcmd
	},
	{
		"nfs_expinfo", ":",
		"dump struct exportinfo",
		nfs_expinfo_dcmd
	},
	{
		"nfs_exptable", "?",
		"dump exportinfo structures for a zone\n"
		"\t\t\t(Optional address of zone_t)",
		nfs_exptable_dcmd
	},
	{
		"nfs_exptable_path", "?",
		"dump exportinfo structures for a zone\n"
		"\t\t\t(Optional address of zone_t)",
		nfs_exptable_path_dcmd
	},
	{
		"nfs_nstree", "?[-v]",
		"dump NFS server pseudo namespace tree for a zone\n"
		"\t\t\t(Optional address of zone_t)",
		nfs_nstree_dcmd, nfs_nstree_help
	},
	{
		"nfs_fid_hashdist", ":[-v]",
		"show fid hash distribution of the exportinfo table",
		nfs_fid_hashdist_dcmd, nfs_hashdist_help
	},
	{
		"nfs_path_hashdist", "[-v]",
		"show path hash distribution of the exportinfo table",
		nfs_path_hashdist_dcmd, nfs_hashdist_help
	},
	/* NFSv4 idmap */
	{
		"nfs4_idmap", ":",
		"dump nfsidmap_t",
		nfs4_idmap_dcmd
	},
	{
		"nfs4_idmap_info", "?[u2s | g2s | s2u | s2g ...]",
		"dump NFSv4 idmap information\n"
		"\t\t\t(Optional address of zone_t)",
		nfs4_idmap_info_dcmd, nfs4_idmap_info_help
	},
	/* NFS client */
	{
		"nfs_mntinfo", "?[-v]",
		"print mntinfo_t information\n"
		"\t\t\t(Optional address of mntinfo_t)",
		nfs_mntinfo_dcmd, nfs_mntinfo_help
	},
	{
		"nfs_servinfo", ":[-v]",
		"print servinfo_t information",
		nfs_servinfo_dcmd, nfs_servinfo_help
	},
	/* WIP */
	{
		"nfs4_mntinfo", "?[-mv]",
		"print mntinfo4_t information\n"
		"\t\t\t(Optional address of mntinfo4_t)",
		nfs4_mntinfo_dcmd, nfs4_mntinfo_help
	},
	{
		"nfs4_servinfo", ":[-v]",
		"print servinfo4_t information",
		nfs4_servinfo_dcmd, nfs4_servinfo_help
	},
	{
		"nfs4_server_info", "?[-cs]",
		"print nfs4_server_t information",
		nfs4_server_info_dcmd, nfs4_server_info_help
	},
	/* WIP */
	{
		"nfs4_mimsg", ":[-s]",
		"print queued messages for given address of mi_msg_list",
		nfs4_mimsg_dcmd, nfs4_mimsg_help
	},
	{
		"nfs4_fname", ":",
		"print path name of nfs4_fname_t specified",
		nfs4_fname_dcmd
	},
	{
		"nfs4_svnode", ":",
		"print svnode_t info at specified address",
		nfs4_svnode_dcmd
	},


/* NFSv2/3/4 clnt */
	{
		"nfs_vfs", "?[-v]",
		"print all nfs vfs struct (-v for mntinfo)\n"
		"\t\t\t(Optional address of vfs_t)",
		nfs_vfs_dcmd
	},


/* NFSv4 clnt */
	{
		"nfs_rnode4", "?",
		"dump NFSv4 rnodes\n"
		"\t\t\t(Optional address of rnode4_t)",
		nfs_rnode4_dcmd, nfs_rnode4_help
	},
	{
		"nfs4_diag", "?[-s]",
		"print queued recovery messages for NFSv4 client\n"
		"\t\t\t(Optional address of mntinfo4_t)",
		nfs4_diag_dcmd, nfs4_diag_help
	},
	{
		"nfs_rnode4find", ":",
		"dump NFSv4 rnodes for given vfs_t",
		nfs_rnode4find_dcmd, nfs_rnode4find_help
	},
	{
		"nfs4_foo", ":[-v]",
		"dump free open owners for NFSv4 client",
		nfs4_foo_dcmd
	},
	{
		"nfs4_oob", ":[-v]",
		"dump open owners for NFSv4 client",
		nfs4_oob_dcmd
	},
	{
		"nfs4_os", "?[-v]",
		"dump open streams for NFSv4 Client\n"
		"\t\t\t(Optional address of rnode4_t)",
		nfs4_os_dcmd
	},

/* generic commands */
	{
		"nfs_stat", "?[-csb][-234][-anr] | $[count]",
		"Print NFS statistics for zone\n"
		"\t\t\t(Optional address of zone_t)",
		nfs_stat_dcmd
	},
	{
		"nfs_help", "[-dw]",
		"Show nfs commands",
		nfs_help_dcmd
	},

	{NULL, NULL, NULL, NULL}
};

static const mdb_walker_t walkers[] = {
	/* svc */
	{
		"svc_pool", "walk SVCPOOL structs for given zone",
		svc_pool_walk_init, svc_pool_walk_step
	},
	{
		"svc_mxprt", "walk master xprts",
		svc_mxprt_walk_init, svc_mxprt_walk_step
	},
	/* rfs4 */
	{
		"rfs4_db_tbl", "walk NFSv4 server rfs4_table_t structs",
		rfs4_db_tbl_walk_init, rfs4_db_tbl_walk_step
	},
	{
		"rfs4_db_idx", "walk NFSv4 server rfs4_index_t structs",
		rfs4_db_idx_walk_init, rfs4_db_idx_walk_step
	},
	{
		"rfs4_db_bkt", "walk NFSv4 server buckets for given index",
		rfs4_db_bkt_walk_init, rfs4_db_bkt_walk_step,
		rfs4_db_bkt_walk_fini
	},
	/* NFS server */
	{
		"nfs_expinfo", "walk exportinfo structures from the exptable",
		nfs_expinfo_walk_init, hash_table_walk_step,
		nfs_expinfo_walk_fini, &nfs_expinfo_arg
	},
	{
		"nfs_expinfo_path",
		"walk exportinfo structures from the exptable_path_hash",
		nfs_expinfo_walk_init, hash_table_walk_step,
		nfs_expinfo_walk_fini, &nfs_expinfo_path_arg
	},
	{
		"nfs_expvis", "walk list of exp_visible structs",
		nfs_expvis_walk_init, nfs_expvis_walk_step
	},
	{
		"nfssrv_globals", "walk list of zones NFS globals",
		nfssrv_globals_walk_init, nfssrv_globals_walk_step
	},
	/* NFSv4 idmap */
	{
		"nfs4_u2s", "walk uid-to-string idmap cache for given zone",
		nfs4_idmap_walk_init, hash_table_walk_step,
		nfs4_idmap_walk_fini,
		(void *)OFFSETOF(struct nfsidmap_globals, u2s_ci)
	},
	{
		"nfs4_s2u", "walk string-to-uid idmap cache for given zone",
		nfs4_idmap_walk_init, hash_table_walk_step,
		nfs4_idmap_walk_fini,
		(void *)OFFSETOF(struct nfsidmap_globals, s2u_ci)
	},
	{
		"nfs4_g2s", "walk gid-to-string idmap cache for given zone",
		nfs4_idmap_walk_init, hash_table_walk_step,
		nfs4_idmap_walk_fini,
		(void *)OFFSETOF(struct nfsidmap_globals, g2s_ci)
	},
	{
		"nfs4_s2g", "walk string-to-gid idmap cache for given zone",
		nfs4_idmap_walk_init, hash_table_walk_step,
		nfs4_idmap_walk_fini,
		(void *)OFFSETOF(struct nfsidmap_globals, s2g_ci)
	},
	/* NFS client */
	{
		"nfs_rtable", "walk rnodes in rtable cache",
		nfs_rtable_walk_init, hash_table_walk_step,
		hash_table_walk_fini, &nfs_rtable_arg
	},
	{
		"nfs_rtable4", "walk rnode4s in rtable4 cache",
		nfs_rtable4_walk_init, hash_table_walk_step,
		hash_table_walk_fini, &nfs_rtable4_arg
	},
	{
		"nfs_vfs", "walk NFS-mounted vfs structs",
		nfs_vfs_walk_init, nfs_vfs_walk_step, nfs_vfs_walk_fini
	},
	{
		"nfs_mnt", "walk NFSv2/3-mounted vfs structs, pass mntinfo",
		nfs_mnt_walk_init, nfs_mnt_walk_step, nfs_mnt_walk_fini
	},
	{
		"nfs4_mnt", "walk NFSv4-mounted vfs structs, pass mntinfo4",
		nfs4_mnt_walk_init, nfs4_mnt_walk_step, nfs4_mnt_walk_fini
	},
	{
		"nfs_serv", "walk linkedlist of servinfo structs",
		nfs_serv_walk_init, nfs_serv_walk_step
	},
	{
		"nfs4_serv", "walk linkedlist of servinfo4 structs",
		nfs4_serv_walk_init, nfs4_serv_walk_step
	},
	{
		"nfs4_svnode", "walk svnode list at given svnode address",
		nfs4_svnode_walk_init, nfs4_svnode_walk_step
	},
	{
		"nfs4_server", "walk nfs4_server_t structs",
		nfs4_server_walk_init, nfs4_server_walk_step
	},
	{
		"nfs_async", "walk list of async requests",
		nfs_async_walk_init, nfs_async_walk_step
	},
	{
		"nfs4_async", "walk list of NFSv4 async requests",
		nfs4_async_walk_init, nfs4_async_walk_step
	},
	{
		"nfs_acache_rnode", "walk acache entries for a given rnode",
		nfs_acache_rnode_walk_init, nfs_acache_rnode_walk_step
	},
	{
		"nfs_acache", "walk entire nfs_access_cache",
		nfs_acache_walk_init, hash_table_walk_step, nfs_acache_walk_fini
	},
	{
		"nfs_acache4_rnode",
		"walk acache4 entries for a given NFSv4 rnode",
		nfs_acache4_rnode_walk_init, nfs_acache4_rnode_walk_step
	},
	{
		"nfs_acache4", "walk entire nfs4_access_cache",
		nfs_acache4_walk_init, hash_table_walk_step,
		nfs_acache4_walk_fini
	},

	{NULL, NULL, NULL, NULL}
};


static int
nfs_help_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int i = 0;
	uint_t opt_d = FALSE;
	uint_t opt_w = FALSE;

	if ((flags & DCMD_ADDRSPEC) != 0)
		return (DCMD_USAGE);

	if (argc == 0) {
		mdb_printf("::nfs_help -w -d\n");
		mdb_printf("       -w     Will show nfs specific walkers\n");
		mdb_printf("       -d     Will show nfs specific dcmds\n");
		return (DCMD_ERR);
	}

	if (mdb_getopts(argc, argv,
	    'd', MDB_OPT_SETBITS, TRUE, &opt_d,
	    'w', MDB_OPT_SETBITS, TRUE, &opt_w, NULL) != argc)
		return (DCMD_USAGE);

	if (opt_d) {
		for (i = 0; dcmds[i].dc_name != NULL; i++)
			mdb_printf("%-20s %s\n", dcmds[i].dc_name,
			    dcmds[i].dc_descr);
	}
	if (opt_w) {
		for (i = 0; walkers[i].walk_name != NULL; i++)
			mdb_printf("%-20s %s\n", walkers[i].walk_name,
			    walkers[i].walk_descr);
	}
	return (DCMD_OK);

}

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION,
	dcmds,
	walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
