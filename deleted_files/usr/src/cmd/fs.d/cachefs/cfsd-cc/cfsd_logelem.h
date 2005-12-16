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
// ------------------------------------------------------------
//
//			cfsd_logelem.h
//
// Include file for the logelem class.
//

#pragma ident	"%Z%%M%	%I%	%E% SMI"
// Copyright (c) 1994 by Sun Microsystems, Inc.

#ifndef CFSD_LOGELEM
#define	CFSD_LOGELEM


// Abstract base class used by the other logelem classes.
class cfsd_logelem {
private:
protected:
	cfsd_maptbl	*i_tblp;
	cfsd_logfile	*i_lfp;
	cfsd_kmod	*i_kmodp;
	RWCString	*i_messagep;		// string for messages
	char		 i_fidbuf[1024];	// debugging, for formatted fid
	cfs_dlog_entry	*i_entp;
	off_t		 i_offset;

	void i_print_cred(cred_t *credp);
	void i_print_attr(vattr_t *vp);
	void i_format_fid(fid_t *fidp);
	int i_lostfound(cfs_cid_t *cidp, cfs_cid_t *pcidp, const char *namep,
	    cred_t *cr);
	void i_problem(const char *, ...);
	void i_resolution(const char *, ...);
	void i_message(const char *, const char *, va_list ap);

public:
	cfsd_logelem(cfsd_maptbl *tblp, cfsd_logfile *lfp,
	    cfsd_kmod *kmodp);
	virtual ~cfsd_logelem();
	virtual int logelem_roll(u_long *seqp) = 0;
	virtual void logelem_dump() = 0;
	const char *logelem_message();
};

// setattr
class cfsd_logelem_setattr : public cfsd_logelem {
private:
	struct cfs_dlog_setattr	*i_up;

public:
	cfsd_logelem_setattr(cfsd_maptbl *tblp, cfsd_logfile *lfp,
	    cfsd_kmod *kmodp);
	~cfsd_logelem_setattr();
	int logelem_roll(u_long *seqp);
	void logelem_dump();
};

// setsecattr
class cfsd_logelem_setsecattr : public cfsd_logelem {
private:
	struct cfs_dlog_setsecattr	*i_up;
	const aclent_t			*i_acl;

public:
	cfsd_logelem_setsecattr(cfsd_maptbl *tblp, cfsd_logfile *lfp,
	    cfsd_kmod *kmodp);
	~cfsd_logelem_setsecattr();
	int logelem_roll(u_long *seqp);
	void logelem_dump();
};

// create
class cfsd_logelem_create : public cfsd_logelem {
private:
	struct cfs_dlog_create	*i_up;
	const char		*i_namep;	// name of file to create

public:
	cfsd_logelem_create(cfsd_maptbl *tblp, cfsd_logfile *lfp,
	    cfsd_kmod *kmodp);
	~cfsd_logelem_create();
	int logelem_roll(u_long *seqp);
	void logelem_dump();
};

// remove
class cfsd_logelem_remove : public cfsd_logelem {
private:
	struct cfs_dlog_remove	*i_up;
	const char		*i_namep;	// name of file to remove

public:
	cfsd_logelem_remove(cfsd_maptbl *tblp, cfsd_logfile *lfp,
	    cfsd_kmod *kmodp);
	~cfsd_logelem_remove();
	int logelem_roll(u_long *seqp);
	void logelem_dump();
};

// rmdir
class cfsd_logelem_rmdir : public cfsd_logelem {
private:
	struct cfs_dlog_rmdir	*i_up;
	const char		*i_namep;	// name of dir to rmdir

public:
	cfsd_logelem_rmdir(cfsd_maptbl *tblp, cfsd_logfile *lfp,
	    cfsd_kmod *kmodp);
	~cfsd_logelem_rmdir();
	int logelem_roll(u_long *seqp);
	void logelem_dump();
};

// mkdir
class cfsd_logelem_mkdir : public cfsd_logelem {
private:
	struct cfs_dlog_mkdir	*i_up;
	const char		*i_namep;	// name of dir to mkdir

public:
	cfsd_logelem_mkdir(cfsd_maptbl *tblp, cfsd_logfile *lfp,
	    cfsd_kmod *kmodp);
	~cfsd_logelem_mkdir();
	int logelem_roll(u_long *seqp);
	void logelem_dump();
};

// link
class cfsd_logelem_link : public cfsd_logelem {
private:
	struct cfs_dlog_link	*i_up;
	const char		*i_namep;	// name of link

public:
	cfsd_logelem_link(cfsd_maptbl *tblp, cfsd_logfile *lfp,
	    cfsd_kmod *kmodp);
	~cfsd_logelem_link();
	int logelem_roll(u_long *seqp);
	void logelem_dump();
};

// symlink
class cfsd_logelem_symlink : public cfsd_logelem {
private:
	struct cfs_dlog_symlink	*i_up;
	const char		*i_namep;	// name of symlink
	const char		*i_contentsp;	// contents of symlink

public:
	cfsd_logelem_symlink(cfsd_maptbl *tblp, cfsd_logfile *lfp,
	    cfsd_kmod *kmodp);
	~cfsd_logelem_symlink();
	int logelem_roll(u_long *seqp);
	void logelem_dump();
};

// rename
class cfsd_logelem_rename : public cfsd_logelem {
private:
	struct cfs_dlog_rename	*i_up;
	const char		*i_orignamep;	// original name
	const char		*i_newnamep;	// new name

public:
	cfsd_logelem_rename(cfsd_maptbl *tblp, cfsd_logfile *lfp,
	    cfsd_kmod *kmodp);
	~cfsd_logelem_rename();
	int logelem_roll(u_long *seqp);
	void logelem_dump();
};

// modify
class cfsd_logelem_modified : public cfsd_logelem {
private:
	struct cfs_dlog_modify	*i_up;

public:
	cfsd_logelem_modified(cfsd_maptbl *tblp, cfsd_logfile *lfp,
	    cfsd_kmod *kmodp);
	~cfsd_logelem_modified();
	int logelem_roll(u_long *seqp);
	void logelem_dump();
};

// mapfid
class cfsd_logelem_mapfid : public cfsd_logelem {
private:
	struct cfs_dlog_mapfid	*i_up;

public:
	cfsd_logelem_mapfid(cfsd_maptbl *tblp, cfsd_logfile *lfp,
	    cfsd_kmod *kmodp);
	~cfsd_logelem_mapfid();
	int logelem_roll(u_long *seqp);
	void logelem_dump();
};

#endif /* CFSD_LOGELEM */
