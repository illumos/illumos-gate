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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <syslog.h>
#include <thread.h>
#include <synch.h>
#include <grp.h>
#include <assert.h>
#include <libintl.h>
#include <smbsrv/libsmb.h>

#define	SMB_LGRP_LOCAL_IDX	0
#define	SMB_LGRP_BUILTIN_IDX	1

#define	SMB_LGRP_DB_NAME	"/var/smb/smbgroup.db"
#define	SMB_LGRP_DB_TIMEOUT	3000		/* in millisecond */
#define	SMB_LGRP_DB_VERMAJOR	1
#define	SMB_LGRP_DB_VERMINOR	0
#define	SMB_LGRP_DB_MAGIC	0x4C475250	/* LGRP */

#define	SMB_LGRP_DB_ORD		1		/* open read-only */
#define	SMB_LGRP_DB_ORW		2		/* open read/write */

#define	SMB_LGRP_DB_ADDMEMBER	1
#define	SMB_LGRP_DB_DELMEMBER	2

/*
 * members column of the groups table is an array of
 * member structure smb_lgmid_t defined below.
 *
 * privs column of the groups table is an array of bytes
 * where each byte is the id of an enable privilege
 */
#define	SMB_LGRP_DB_SQL \
	"CREATE TABLE db_info ("				\
	"	ver_major INTEGER,"				\
	"	ver_minor INTEGER,"				\
	"	magic     INTEGER"				\
	");"							\
	""							\
	"CREATE TABLE domains ("				\
	"	dom_idx INTEGER PRIMARY KEY,"			\
	"	dom_sid TEXT UNIQUE,"				\
	"       dom_cnt INTEGER"				\
	");"							\
	""							\
	"CREATE UNIQUE INDEX domsid_idx ON domains (dom_sid);"	\
	""							\
	"CREATE TABLE groups ("					\
	"	name      TEXT PRIMARY KEY,"			\
	"	sid_idx   INTEGER,"				\
	"	sid_rid   INTEGER,"				\
	"	sid_type  INTEGER,"				\
	"	sid_attrs INTEGER,"				\
	"	comment   TEXT,"				\
	"	n_privs   INTEGER,"				\
	"	privs     BLOB,"				\
	"	n_members INTEGER,"				\
	"	members   BLOB"					\
	");"							\
	""							\
	"CREATE INDEX grprid_idx ON groups (sid_rid);"

/*
 * Number of groups table columns
 */
#define	SMB_LGRP_GTBL_NCOL	10

#define	SMB_LGRP_GTBL_NAME	0
#define	SMB_LGRP_GTBL_SIDIDX	1
#define	SMB_LGRP_GTBL_SIDRID	2
#define	SMB_LGRP_GTBL_SIDTYP	3
#define	SMB_LGRP_GTBL_SIDATR	4
#define	SMB_LGRP_GTBL_CMNT	5
#define	SMB_LGRP_GTBL_NPRIVS	6
#define	SMB_LGRP_GTBL_PRIVS	7
#define	SMB_LGRP_GTBL_NMEMBS	8
#define	SMB_LGRP_GTBL_MEMBS	9

#define	SMB_LGRP_INFO_NONE	0x00
#define	SMB_LGRP_INFO_NAME	0x01
#define	SMB_LGRP_INFO_CMNT	0x02
#define	SMB_LGRP_INFO_SID	0x04
#define	SMB_LGRP_INFO_PRIV	0x08
#define	SMB_LGRP_INFO_MEMB	0x10
#define	SMB_LGRP_INFO_ALL	0x1F

#define	NULL_MSGCHK(msg)	((msg) ? (msg) : "NULL")

/* Member ID */
typedef struct smb_lgmid {
	uint32_t m_idx;
	uint32_t m_rid;
	uint16_t m_type;
} smb_lgmid_t;

#define	SMB_LGRP_MID_HEXSZ	32

/* Member list */
typedef struct smb_lgmlist {
	uint32_t	m_cnt;
	char		*m_ids;
} smb_lgmlist_t;

/* Privilege ID */
typedef uint8_t smb_lgpid_t;

/* Privilege list */
typedef struct smb_lgplist {
	uint32_t	p_cnt;
	smb_lgpid_t	*p_ids;
} smb_lgplist_t;

static mutex_t smb_lgrp_lsid_mtx;
static nt_sid_t *smb_lgrp_lsid;

static int smb_lgrp_db_init(void);
static sqlite *smb_lgrp_db_open(int);
static void smb_lgrp_db_close(sqlite *);
static int smb_lgrp_db_setinfo(sqlite *);

static boolean_t smb_lgrp_gtbl_exists(sqlite *, char *);
static int smb_lgrp_gtbl_lookup(sqlite *, int, smb_group_t *, int, ...);
static int smb_lgrp_gtbl_insert(sqlite *, smb_group_t *);
static int smb_lgrp_gtbl_update(sqlite *, char *, smb_group_t *, int);
static int smb_lgrp_gtbl_delete(sqlite *, char *);
static int smb_lgrp_gtbl_update_mlist(sqlite *, char *, smb_gsid_t *, int);
static int smb_lgrp_gtbl_update_plist(sqlite *, char *, uint8_t, boolean_t);
static int smb_lgrp_gtbl_count(sqlite *, int, int *);

static int smb_lgrp_dtbl_insert(sqlite *, char *, uint32_t *);
static int smb_lgrp_dtbl_getidx(sqlite *, nt_sid_t *, uint16_t,
    uint32_t *, uint32_t *);
static int smb_lgrp_dtbl_getsid(sqlite *, uint32_t, nt_sid_t **);

static int smb_lgrp_mlist_add(smb_lgmlist_t *, smb_lgmid_t *, smb_lgmlist_t *);
static int smb_lgrp_mlist_del(smb_lgmlist_t *, smb_lgmid_t *, smb_lgmlist_t *);

static int smb_lgrp_plist_add(smb_lgplist_t *, smb_lgpid_t, smb_lgplist_t *);
static int smb_lgrp_plist_del(smb_lgplist_t *, smb_lgpid_t, smb_lgplist_t *);

static void smb_lgrp_encode_privset(smb_group_t *, smb_lgplist_t *);

static int smb_lgrp_decode(smb_group_t *, char **, int, sqlite *);
static int smb_lgrp_decode_privset(smb_group_t *, char *, char *);
static int smb_lgrp_decode_members(smb_group_t *, char *, char *, sqlite *);

static void smb_lgrp_set_default_privs(smb_group_t *);
static boolean_t smb_lgrp_chkname(char *);
static boolean_t smb_lgrp_chkmember(uint16_t);
static int smb_lgrp_getsid(int, uint32_t *, uint16_t, sqlite *, nt_sid_t **);

#ifdef _LP64
/*
 * We cannot make 64-bit version of libsqlite because the code
 * has some problems.
 */

/*ARGSUSED*/
sqlite *
sqlite_open(const char *filename, int mode, char **errmsg)
{
	return (NULL);
}

/*ARGSUSED*/
void
sqlite_close(sqlite *db)
{
}

/*ARGSUSED*/
char *
sqlite_mprintf(const char *fmt, ...)
{
	return (NULL);
}

/*ARGSUSED*/
void
sqlite_freemem(void *p)
{
}

/*ARGSUSED*/
int
sqlite_compile(sqlite *db, const char *zSql, const char **pzTail,
    sqlite_vm **ppVm, char **pzErrmsg)
{
	return (SQLITE_ERROR);
}

/*ARGSUSED*/
void
sqlite_free_table(char **res)
{
}

/*ARGSUSED*/
int
sqlite_last_insert_rowid(sqlite *db)
{
	return (-1);
}

/*ARGSUSED*/
void
sqlite_busy_timeout(sqlite *db, int ms)
{
}

/*ARGSUSED*/
int
sqlite_get_table(sqlite *db, const char *zSql, char ***pazResult, int *pnRow,
    int *pnColumn, char **pzErrMsg)
{
	return (SQLITE_ERROR);
}

/*ARGSUSED*/
int
sqlite_step(sqlite_vm *pVm, int *pN, const char ***pazValue,
    const char ***pazColName)
{
	return (SQLITE_ERROR);
}

/*ARGSUSED*/
int
sqlite_exec(sqlite *db, const char *zSql, sqlite_callback xCallback, void *pArg,
    char **pzErrMsg)
{
	return (SQLITE_ERROR);
}

/*ARGSUSED*/
int
sqlite_finalize(sqlite_vm *pVm, char **pzErrMsg)
{
	return (SQLITE_ERROR);
}
#endif /* _LP64 */

/*
 * smb_lgrp_add
 *
 * Create a local group with the given name and comment.
 * This new group doesn't have any members and no enabled
 * privileges.
 *
 * No well-known accounts can be added other than Administators,
 * Backup Operators and Power Users. These built-in groups
 * won't have any members when created but a set of default
 * privileges will be enabled for them.
 */
int
smb_lgrp_add(char *gname, char *cmnt)
{
	well_known_account_t *wk_acct;
	struct group *pxgrp;
	smb_group_t grp;
	nt_sid_t *sid = NULL;
	sqlite *db;
	int rc;

	(void) trim_whitespace(gname);
	if (!smb_lgrp_chkname(gname))
		return (SMB_LGRP_INVALID_NAME);

	if (cmnt && (strlen(cmnt) > SMB_LGRP_COMMENT_MAX))
		return (SMB_LGRP_INVALID_ARG);

	bzero(&grp, sizeof (grp));
	grp.sg_name = utf8_strlwr(gname);
	grp.sg_cmnt = cmnt;

	wk_acct = nt_builtin_lookup(gname);
	if (wk_acct == NULL) {
		if ((pxgrp = getgrnam(gname)) == NULL)
			return (SMB_LGRP_NOT_FOUND);

		/*
		 * Make sure a local SID can be obtained
		 */
		if (smb_idmap_getsid(pxgrp->gr_gid, SMB_IDMAP_GROUP, &sid)
		    != IDMAP_SUCCESS)
			return (SMB_LGRP_NO_SID);

		if (!nt_sid_is_indomain(smb_lgrp_lsid, sid)) {
			free(sid);
			return (SMB_LGRP_SID_NOTLOCAL);
		}

		grp.sg_id.gs_type = SidTypeAlias;
		grp.sg_domain = SMB_LGRP_LOCAL;
		grp.sg_rid = pxgrp->gr_gid;
	} else {
		if (wk_acct->flags & LGF_HIDDEN) {
			/* cannot add well-known accounts */
			return (SMB_LGRP_WKSID);
		}

		grp.sg_id.gs_type = wk_acct->sid_name_use;
		if ((sid = nt_sid_strtosid(wk_acct->sid)) == NULL)
			return (SMB_LGRP_NO_MEMORY);
		(void) nt_sid_get_rid(sid, &grp.sg_rid);
		free(sid);
		grp.sg_domain = SMB_LGRP_BUILTIN;

		grp.sg_privs = smb_privset_new();
		smb_lgrp_set_default_privs(&grp);
	}


	grp.sg_attr = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT |
	    SE_GROUP_ENABLED;

	db = smb_lgrp_db_open(SMB_LGRP_DB_ORW);
	rc = smb_lgrp_gtbl_insert(db, &grp);
	smb_lgrp_db_close(db);

	smb_privset_free(grp.sg_privs);
	return (rc);
}

/*
 * smb_lgrp_rename
 *
 * Renames the given group
 */
int
smb_lgrp_rename(char *gname, char *new_gname)
{
	smb_group_t grp;
	sqlite *db;
	int rc;

	(void) trim_whitespace(gname);
	if (!smb_lgrp_chkname(gname))
		return (SMB_LGRP_INVALID_NAME);

	(void) trim_whitespace(new_gname);
	if (!smb_lgrp_chkname(gname))
		return (SMB_LGRP_INVALID_NAME);

	if (utf8_strcasecmp(gname, new_gname) == 0)
		return (SMB_LGRP_SUCCESS);

	/* Cannot rename well-known groups */
	if (nt_builtin_is_wellknown(gname))
		return (SMB_LGRP_WKSID);

	/* Cannot rename to a well-known groups */
	if (nt_builtin_is_wellknown(new_gname))
		return (SMB_LGRP_WKSID);

	grp.sg_name = new_gname;

	db = smb_lgrp_db_open(SMB_LGRP_DB_ORW);
	rc = smb_lgrp_gtbl_update(db, gname, &grp, SMB_LGRP_GTBL_NAME);
	smb_lgrp_db_close(db);

	return (rc);
}

/*
 * smb_lgrp_delete
 *
 * Deletes the specified local group.
 */
int
smb_lgrp_delete(char *gname)
{
	sqlite *db;
	int rc;

	(void) trim_whitespace(gname);
	if (!smb_lgrp_chkname(gname))
		return (SMB_LGRP_INVALID_NAME);

	/* Cannot remove a built-in group */
	if (nt_builtin_is_wellknown(gname))
		return (SMB_LGRP_WKSID);

	db = smb_lgrp_db_open(SMB_LGRP_DB_ORW);
	rc = smb_lgrp_gtbl_delete(db, gname);
	smb_lgrp_db_close(db);

	return (rc);
}

/*
 * smb_lgrp_setcmnt
 *
 * Sets the description for the given group
 */
int
smb_lgrp_setcmnt(char *gname, char *cmnt)
{
	smb_group_t grp;
	sqlite *db;
	int rc;

	(void) trim_whitespace(gname);
	if (!smb_lgrp_chkname(gname))
		return (SMB_LGRP_INVALID_NAME);

	if (cmnt && (strlen(cmnt) > SMB_LGRP_COMMENT_MAX))
		return (SMB_LGRP_INVALID_ARG);

	grp.sg_cmnt = cmnt;

	db = smb_lgrp_db_open(SMB_LGRP_DB_ORW);
	rc = smb_lgrp_gtbl_update(db, gname, &grp, SMB_LGRP_GTBL_CMNT);
	smb_lgrp_db_close(db);

	return (rc);
}

/*
 * smb_lgrp_getcmnt
 *
 * Obtain the description of the specified group
 */
int
smb_lgrp_getcmnt(char *gname, char **cmnt)
{
	smb_group_t grp;
	sqlite *db;
	int rc;

	(void) trim_whitespace(gname);
	if (!smb_lgrp_chkname(gname))
		return (SMB_LGRP_INVALID_NAME);

	if (cmnt == NULL)
		return (SMB_LGRP_INVALID_ARG);

	db = smb_lgrp_db_open(SMB_LGRP_DB_ORD);
	rc = smb_lgrp_gtbl_lookup(db, SMB_LGRP_GTBL_NAME, &grp,
	    SMB_LGRP_INFO_CMNT, gname);
	smb_lgrp_db_close(db);

	if (rc == SMB_LGRP_SUCCESS) {
		*cmnt = grp.sg_cmnt;
		grp.sg_cmnt = NULL;
		smb_lgrp_free(&grp);
	}

	return (rc);
}


/*
 * smb_lgrp_setpriv
 *
 * Enable/disable the specified privilge for the group
 */
int
smb_lgrp_setpriv(char *gname, uint8_t priv_lid, boolean_t enable)
{
	sqlite *db;
	int rc;

	(void) trim_whitespace(gname);
	if (!smb_lgrp_chkname(gname))
		return (SMB_LGRP_INVALID_NAME);

	if ((priv_lid < SE_MIN_LUID) || (priv_lid > SE_MAX_LUID))
		return (SMB_LGRP_NO_SUCH_PRIV);

	db = smb_lgrp_db_open(SMB_LGRP_DB_ORW);
	rc = smb_lgrp_gtbl_update_plist(db, gname, priv_lid, enable);
	smb_lgrp_db_close(db);

	if (enable) {
		if (rc == SMB_LGRP_PRIV_HELD)
			rc = SMB_LGRP_SUCCESS;
	} else {
		if (rc == SMB_LGRP_PRIV_NOT_HELD)
			rc = SMB_LGRP_SUCCESS;
	}

	return (rc);
}

/*
 * smb_lgrp_getpriv
 *
 * Obtain the status of the specified privilge for the group
 */
int
smb_lgrp_getpriv(char *gname, uint8_t priv_lid, boolean_t *enable)
{
	sqlite *db;
	smb_group_t grp;
	int rc;

	(void) trim_whitespace(gname);
	if (!smb_lgrp_chkname(gname))
		return (SMB_LGRP_INVALID_NAME);

	if ((priv_lid < SE_MIN_LUID) || (priv_lid > SE_MAX_LUID))
		return (SMB_LGRP_NO_SUCH_PRIV);

	db = smb_lgrp_db_open(SMB_LGRP_DB_ORD);
	rc = smb_lgrp_gtbl_lookup(db, SMB_LGRP_GTBL_NAME, &grp,
	    SMB_LGRP_INFO_PRIV, gname);
	smb_lgrp_db_close(db);

	if (rc == SMB_LGRP_SUCCESS) {
		*enable = (smb_privset_query(grp.sg_privs, priv_lid) == 1);
		smb_lgrp_free(&grp);
	}

	return (rc);
}

/*
 * smb_lgrp_add_member
 *
 * Add the given account to the specified group as its member.
 */
int
smb_lgrp_add_member(char *gname, nt_sid_t *msid, uint16_t sid_type)
{
	sqlite *db;
	smb_gsid_t mid;
	int rc;

	(void) trim_whitespace(gname);
	if (!smb_lgrp_chkname(gname))
		return (SMB_LGRP_INVALID_NAME);

	if (!nt_sid_is_valid(msid))
		return (SMB_LGRP_INVALID_ARG);

	if (!smb_lgrp_chkmember(sid_type))
		return (SMB_LGRP_INVALID_MEMBER);

	mid.gs_sid = msid;
	mid.gs_type = sid_type;

	db = smb_lgrp_db_open(SMB_LGRP_DB_ORW);
	rc = smb_lgrp_gtbl_update_mlist(db, gname, &mid, SMB_LGRP_DB_ADDMEMBER);
	smb_lgrp_db_close(db);

	return (rc);
}

/*
 * smb_lgrp_del_member
 *
 * Delete the specified member from the given group.
 */
int
smb_lgrp_del_member(char *gname, nt_sid_t *msid, uint16_t sid_type)
{
	sqlite *db;
	smb_gsid_t mid;
	int rc;

	(void) trim_whitespace(gname);
	if (!smb_lgrp_chkname(gname))
		return (SMB_LGRP_INVALID_NAME);

	if (!nt_sid_is_valid(msid))
		return (SMB_LGRP_INVALID_ARG);

	mid.gs_sid = msid;
	mid.gs_type = sid_type;

	db = smb_lgrp_db_open(SMB_LGRP_DB_ORW);
	rc = smb_lgrp_gtbl_update_mlist(db, gname, &mid, SMB_LGRP_DB_DELMEMBER);
	smb_lgrp_db_close(db);

	return (rc);
}

/*
 * smb_lgrp_getbyname
 *
 * Retrieves the information of the group specified by
 * the given name.
 *
 * Note that this function doesn't allocate the group
 * structure itself only the fields, so the given grp
 * pointer has to point to a group structure.
 * Caller must free the allocated memories for the fields
 * by calling smb_lgrp_free().
 */
int
smb_lgrp_getbyname(char *gname, smb_group_t *grp)
{
	sqlite *db;
	int rc;

	(void) trim_whitespace(gname);
	if (!smb_lgrp_chkname(gname))
		return (SMB_LGRP_INVALID_NAME);

	db = smb_lgrp_db_open(SMB_LGRP_DB_ORD);
	rc = smb_lgrp_gtbl_lookup(db, SMB_LGRP_GTBL_NAME, grp,
	    SMB_LGRP_INFO_ALL, gname);
	smb_lgrp_db_close(db);

	return (rc);
}

/*
 * smb_lgrp_getbyrid
 *
 * Retrieves the information of the group specified by
 * the given RID and domain type.
 *
 * Note that this function doesn't allocate the group
 * structure itself only the fields, so the given grp
 * pointer has to point to a group structure.
 * Caller must free the allocated memories for the fields
 * by calling smb_lgrp_free().
 *
 * If grp is NULL no information would be returned. The
 * return value of SMB_LGRP_SUCCESS will indicate that a
 * group with the given information exists.
 */
int
smb_lgrp_getbyrid(uint32_t rid, smb_gdomain_t domtype, smb_group_t *grp)
{
	smb_group_t tmpgrp;
	sqlite *db;
	int infolvl = SMB_LGRP_INFO_ALL;
	int rc;

	if (grp == NULL) {
		grp = &tmpgrp;
		infolvl = SMB_LGRP_INFO_NONE;
	}

	db = smb_lgrp_db_open(SMB_LGRP_DB_ORD);
	rc = smb_lgrp_gtbl_lookup(db, SMB_LGRP_GTBL_SIDRID, grp, infolvl,
	    rid, domtype);
	smb_lgrp_db_close(db);

	return (rc);
}

/*
 * smb_lgrp_numbydomain
 *
 * Returns the number of groups in the given domain in the
 * arg 'count'
 */
int
smb_lgrp_numbydomain(smb_gdomain_t dom_type, int *count)
{
	sqlite *db;
	int dom_idx;
	int rc;

	switch (dom_type) {
	case SMB_LGRP_LOCAL:
		dom_idx = SMB_LGRP_LOCAL_IDX;
		break;
	case SMB_LGRP_BUILTIN:
		dom_idx = SMB_LGRP_BUILTIN_IDX;
		break;
	default:
		*count = 0;
		return (SMB_LGRP_INVALID_ARG);
	}

	db = smb_lgrp_db_open(SMB_LGRP_DB_ORD);
	rc = smb_lgrp_gtbl_count(db, dom_idx, count);
	smb_lgrp_db_close(db);

	return (rc);
}

/*
 * smb_lgrp_numbydomain
 *
 * Returns the number of groups which have the given SID
 * as a member.
 */
int
smb_lgrp_numbymember(nt_sid_t *msid, int *count)
{
	smb_giter_t gi;
	smb_group_t grp;
	int rc;

	*count = 0;
	rc = smb_lgrp_iteropen(&gi);
	if (rc != SMB_LGRP_SUCCESS)
		return (rc);

	while (smb_lgrp_iterate(&gi, &grp) == SMB_LGRP_SUCCESS) {
		if (smb_lgrp_is_member(&grp, msid))
			(*count)++;
		smb_lgrp_free(&grp);
	}
	smb_lgrp_iterclose(&gi);
	return (SMB_LGRP_SUCCESS);
}

/*
 * smb_lgrp_free
 *
 * Frees the allocated memory for the fields of the given
 * group structure. Note that this function doesn't free
 * the group itself.
 */
void
smb_lgrp_free(smb_group_t *grp)
{
	int i;

	if (grp == NULL)
		return;

	free(grp->sg_name);
	free(grp->sg_cmnt);
	free(grp->sg_id.gs_sid);
	smb_privset_free(grp->sg_privs);

	for (i = 0; i < grp->sg_nmembers; i++)
		free(grp->sg_members[i].gs_sid);
	free(grp->sg_members);
}

/*
 * smb_lgrp_iteropen
 *
 * Initializes the given group iterator by opening
 * the group database and creating a virtual machine
 * for iteration.
 */
int
smb_lgrp_iteropen(smb_giter_t *iter)
{
	char *sql;
	char *errmsg = NULL;
	int rc = SMB_LGRP_SUCCESS;

	assert(iter);

	bzero(iter, sizeof (smb_giter_t));

	sql = sqlite_mprintf("SELECT * FROM groups");
	if (sql == NULL)
		return (SMB_LGRP_NO_MEMORY);

	iter->sgi_db = smb_lgrp_db_open(SMB_LGRP_DB_ORD);
	if (iter->sgi_db == NULL) {
		sqlite_freemem(sql);
		return (SMB_LGRP_DBOPEN_FAILED);
	}

	rc = sqlite_compile(iter->sgi_db, sql, NULL, &iter->sgi_vm, &errmsg);
	sqlite_freemem(sql);

	if (rc != SQLITE_OK) {
		syslog(LOG_DEBUG, "failed to create a VM (%s)",
		    NULL_MSGCHK(errmsg));
		rc = SMB_LGRP_DB_ERROR;
	}

	return (rc);
}

/*
 * smb_lgrp_iterclose
 *
 * Closes the given group iterator.
 */
void
smb_lgrp_iterclose(smb_giter_t *iter)
{
	char *errmsg = NULL;
	int rc;

	assert(iter);

	rc = sqlite_finalize(iter->sgi_vm, &errmsg);
	if (rc != SQLITE_OK) {
		syslog(LOG_DEBUG, "failed to destroy a VM (%s)",
		    NULL_MSGCHK(errmsg));
	}

	smb_lgrp_db_close(iter->sgi_db);
}

/*
 * smb_lgrp_iterate
 *
 * Iterate through group database
 * Group information is returned in provided group structure.
 *
 * Note that this function doesn't allocate the group
 * structure itself only the fields, so the given grp
 * pointer has to point to a group structure.
 * Caller must free the allocated memories for the fields
 * by calling smb_lgrp_free().
 */
int
smb_lgrp_iterate(smb_giter_t *iter, smb_group_t *grp)
{
	const char **values;
	int ncol;
	int rc;
	int i;

	if (iter->sgi_vm == NULL || iter->sgi_db == NULL)
		return (SMB_LGRP_INVALID_ARG);

	bzero(grp, sizeof (smb_group_t));
	rc = sqlite_step(iter->sgi_vm, &ncol, &values, NULL);
	if (rc == SQLITE_DONE)
		return (SMB_LGRP_NO_MORE);

	if (rc != SQLITE_ROW)
		return (SMB_LGRP_DBEXEC_FAILED);

	if (ncol != SMB_LGRP_GTBL_NCOL)
		return (SMB_LGRP_DB_ERROR);

	for (i = 0; i < ncol; i++) {
		if (values[i] == NULL)
			return (SMB_LGRP_DB_ERROR);
	}

	return (smb_lgrp_decode(grp, (char **)values, SMB_LGRP_INFO_ALL,
	    iter->sgi_db));
}

/*
 * smb_lgrp_is_member
 *
 * Check to see if the specified account is a member of
 * the given group.
 */
boolean_t
smb_lgrp_is_member(smb_group_t *grp, nt_sid_t *sid)
{
	int i;

	if (grp == NULL || grp->sg_members == NULL || sid == NULL)
		return (B_FALSE);

	for (i = 0; i < grp->sg_nmembers; i++) {
		if (nt_sid_is_equal(grp->sg_members[i].gs_sid, sid))
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * smb_lgrp_strerror
 *
 * Returns a text for the given group error code.
 */
char *
smb_lgrp_strerror(int errno)
{
	switch (errno) {
	case SMB_LGRP_SUCCESS:
		return (dgettext(TEXT_DOMAIN, "success"));
	case SMB_LGRP_INVALID_ARG:
		return (dgettext(TEXT_DOMAIN, "invalid argument"));
	case SMB_LGRP_INVALID_MEMBER:
		return (dgettext(TEXT_DOMAIN, "invalid member type"));
	case SMB_LGRP_INVALID_NAME:
		return (dgettext(TEXT_DOMAIN, "invalid name"));
	case SMB_LGRP_NOT_FOUND:
		return (dgettext(TEXT_DOMAIN, "group not found"));
	case SMB_LGRP_EXISTS:
		return (dgettext(TEXT_DOMAIN, "group exists"));
	case SMB_LGRP_NO_SID:
		return (dgettext(TEXT_DOMAIN, "cannot obtain a SID"));
	case SMB_LGRP_NO_LOCAL_SID:
		return (dgettext(TEXT_DOMAIN, "cannot get the machine SID"));
	case SMB_LGRP_SID_NOTLOCAL:
		return (dgettext(TEXT_DOMAIN, "not a local SID"));
	case SMB_LGRP_WKSID:
		return (dgettext(TEXT_DOMAIN,
		    "operation not permitted on well-known accounts"));
	case SMB_LGRP_NO_MEMORY:
		return (dgettext(TEXT_DOMAIN, "not enough memory"));
	case SMB_LGRP_DB_ERROR:
		return (dgettext(TEXT_DOMAIN, "database operation error"));
	case SMB_LGRP_DBINIT_ERROR:
		return (dgettext(TEXT_DOMAIN, "database initialization error"));
	case SMB_LGRP_INTERNAL_ERROR:
		return (dgettext(TEXT_DOMAIN, "internal error"));
	case SMB_LGRP_MEMBER_IN_GROUP:
		return (dgettext(TEXT_DOMAIN, "member already in the group"));
	case SMB_LGRP_MEMBER_NOT_IN_GROUP:
		return (dgettext(TEXT_DOMAIN, "not a member"));
	case SMB_LGRP_NO_SUCH_PRIV:
		return (dgettext(TEXT_DOMAIN, "no such privilege"));
	case SMB_LGRP_NO_SUCH_DOMAIN:
		return (dgettext(TEXT_DOMAIN, "no such domain SID"));
	case SMB_LGRP_PRIV_HELD:
		return (dgettext(TEXT_DOMAIN, "already holds the privilege"));
	case SMB_LGRP_PRIV_NOT_HELD:
		return (dgettext(TEXT_DOMAIN, "privilege not held"));
	case SMB_LGRP_BAD_DATA:
		return (dgettext(TEXT_DOMAIN, "bad data"));
	case SMB_LGRP_NO_MORE:
		return (dgettext(TEXT_DOMAIN, "no more groups"));
	case SMB_LGRP_DBOPEN_FAILED:
		return (dgettext(TEXT_DOMAIN, "failed openning database"));
	case SMB_LGRP_DBEXEC_FAILED:
		return (dgettext(TEXT_DOMAIN,
		    "failed executing database operation"));
	case SMB_LGRP_DBINIT_FAILED:
		return (dgettext(TEXT_DOMAIN, "failed initializing database"));
	case SMB_LGRP_DOMLKP_FAILED:
		return (dgettext(TEXT_DOMAIN, "failed getting the domain SID"));
	case SMB_LGRP_DOMINS_FAILED:
		return (dgettext(TEXT_DOMAIN,
		    "failed inserting the domain SID"));
	case SMB_LGRP_INSERT_FAILED:
		return (dgettext(TEXT_DOMAIN, "failed inserting the group"));
	case SMB_LGRP_DELETE_FAILED:
		return (dgettext(TEXT_DOMAIN, "failed deleting the group"));
	case SMB_LGRP_UPDATE_FAILED:
		return (dgettext(TEXT_DOMAIN, "failed updating the group"));
	case SMB_LGRP_LOOKUP_FAILED:
		return (dgettext(TEXT_DOMAIN, "failed looking up the group"));
	}

	return (dgettext(TEXT_DOMAIN, "unknown error code"));
}

/*
 * smb_lgrp_chkmember
 *
 * Determines valid account types for being member of
 * a local group.
 *
 * Currently, we just support users as valid members.
 */
static boolean_t
smb_lgrp_chkmember(uint16_t sid_type)
{
	return (sid_type == SidTypeUser);
}

/*
 * smb_lgrp_start
 *
 * Initializes the library private global variables.
 * If the database doesn't exist, it'll create it and adds the
 * predefined builtin groups.
 */
int
smb_lgrp_start(void)
{
	char *supported_bg[] =
	    {"Administrators", "Backup Operators", "Power Users"};
	well_known_account_t *wka;
	int rc, i, ngrp;
	char *lsid_str;

	(void) mutex_init(&smb_lgrp_lsid_mtx, USYNC_THREAD, NULL);
	(void) mutex_lock(&smb_lgrp_lsid_mtx);
	lsid_str = smb_config_get_localsid();
	if (lsid_str == NULL) {
		(void) mutex_unlock(&smb_lgrp_lsid_mtx);
		return (SMB_LGRP_NO_LOCAL_SID);
	}

	smb_lgrp_lsid = nt_sid_strtosid(lsid_str);
	free(lsid_str);
	if (!nt_sid_is_valid(smb_lgrp_lsid)) {
		free(smb_lgrp_lsid);
		smb_lgrp_lsid = NULL;
		(void) mutex_unlock(&smb_lgrp_lsid_mtx);
		return (SMB_LGRP_NO_LOCAL_SID);
	}

	rc = smb_lgrp_db_init();
	if (rc != SMB_LGRP_SUCCESS) {
		free(smb_lgrp_lsid);
		smb_lgrp_lsid = NULL;
		(void) mutex_unlock(&smb_lgrp_lsid_mtx);
		return (rc);
	}
	(void) mutex_unlock(&smb_lgrp_lsid_mtx);

	ngrp = sizeof (supported_bg) / sizeof (supported_bg[0]);
	for (i = 0; i < ngrp; i++) {
		wka = nt_builtin_lookup(supported_bg[i]);
		if (wka == NULL)
			continue;
		rc = smb_lgrp_add(wka->name, wka->desc);
		if (rc != SMB_LGRP_SUCCESS)
			syslog(LOG_DEBUG, "failed to add %s", wka->name);
	}

	return (SMB_LGRP_SUCCESS);
}

/*
 * smb_lgrp_stop
 *
 * Unintialize the library global private variables.
 */
void
smb_lgrp_stop(void)
{
	(void) mutex_lock(&smb_lgrp_lsid_mtx);
	free(smb_lgrp_lsid);
	smb_lgrp_lsid = NULL;
	(void) mutex_unlock(&smb_lgrp_lsid_mtx);
	(void) mutex_destroy(&smb_lgrp_lsid_mtx);
}

/*
 * smb_lgrp_db_open
 *
 * Opens group database with the given mode.
 */
static sqlite *
smb_lgrp_db_open(int mode)
{
	sqlite *db;
	char *errmsg = NULL;

	db = sqlite_open(SMB_LGRP_DB_NAME, mode, &errmsg);
	if (db == NULL) {
		syslog(LOG_ERR, "failed to open group database (%s)",
		    NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
	}

	return (db);
}

/*
 * smb_lgrp_db_close
 *
 * Closes the given database handle
 */
static void
smb_lgrp_db_close(sqlite *db)
{
	if (db) {
		sqlite_close(db);
	}
}

/*
 * smb_lgrp_db_init
 *
 * Creates the group database based on the defined SQL statement.
 * It also initializes db_info and domain tables.
 */
static int
smb_lgrp_db_init(void)
{
	int dbrc = SQLITE_OK;
	int rc = SMB_LGRP_SUCCESS;
	sqlite *db = NULL;
	char *errmsg = NULL;

	db = sqlite_open(SMB_LGRP_DB_NAME, 0600, &errmsg);
	if (db == NULL) {
		syslog(LOG_ERR, "failed to create group database (%s)",
		    NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
		return (SMB_LGRP_DBOPEN_FAILED);
	}

	sqlite_busy_timeout(db, SMB_LGRP_DB_TIMEOUT);
	dbrc = sqlite_exec(db, "BEGIN TRANSACTION;", NULL, NULL, &errmsg);
	if (dbrc != SQLITE_OK) {
		syslog(LOG_DEBUG, "failed to begin database transaction (%s)",
		    NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
		sqlite_close(db);
		return (SMB_LGRP_DBEXEC_FAILED);
	}

	switch (sqlite_exec(db, SMB_LGRP_DB_SQL, NULL, NULL, &errmsg)) {
	case SQLITE_ERROR:
		/*
		 * This is the normal situation: CREATE probably failed because
		 * tables already exist. It may indicate an error in SQL as well
		 * but we cannot tell.
		 */
		sqlite_freemem(errmsg);
		dbrc = sqlite_exec(db, "ROLLBACK TRANSACTION", NULL, NULL,
		    &errmsg);
		rc = SMB_LGRP_SUCCESS;
		break;

	case SQLITE_OK:
		dbrc = sqlite_exec(db, "COMMIT TRANSACTION", NULL, NULL,
		    &errmsg);
		if (dbrc != SQLITE_OK)
			break;
		rc = smb_lgrp_dtbl_insert(db, NT_BUILTIN_DOMAIN_SIDSTR,
		    NULL);
		if (rc == SMB_LGRP_SUCCESS)
			rc = smb_lgrp_db_setinfo(db);
		if (rc != SMB_LGRP_SUCCESS) {
			(void) sqlite_close(db);
			(void) unlink(SMB_LGRP_DB_NAME);
			return (rc);
		}
		break;

	default:
		syslog(LOG_ERR,
		    "failed to initialize group database (%s)", errmsg);
		sqlite_freemem(errmsg);
		dbrc = sqlite_exec(db, "ROLLBACK TRANSACTION", NULL, NULL,
		    &errmsg);
		rc = SMB_LGRP_DBINIT_FAILED;
		break;
	}

	if (dbrc != SQLITE_OK) {
		/* this is bad - database may be left in a locked state */
		syslog(LOG_DEBUG, "failed to close a transaction (%s)",
		    NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
	}

	(void) sqlite_close(db);
	return (rc);
}

/*
 * smb_lgrp_gtbl_lookup
 *
 * This is a flexible lookup function for the group database.
 * The key type can be specified by the 'key' arg and the actual key
 * values can be passed after the 'infolvl' arg. 'infolvl' arg specifies
 * what information items for the specified group is needed.
 *
 * Note that the function assumes the given key is unique and only
 * specifies one or 0 group. The keys that are supported now are
 * the group name and the group SID
 *
 * Note that this function doesn't allocate the group
 * structure itself only the fields, so the given grp
 * pointer has to point to a group structure.
 * Caller must free the allocated memories for the fields
 * by calling smb_lgrp_free().
 */
static int
smb_lgrp_gtbl_lookup(sqlite *db, int key, smb_group_t *grp, int infolvl, ...)
{
	char *errmsg = NULL;
	char *sql;
	char **result;
	int nrow, ncol;
	int rc, dom_idx;
	smb_group_t kgrp;
	va_list ap;

	if (db == NULL)
		return (SMB_LGRP_DBOPEN_FAILED);

	bzero(grp, sizeof (smb_group_t));
	va_start(ap, infolvl);

	switch (key) {
	case SMB_LGRP_GTBL_NAME:
		kgrp.sg_name = va_arg(ap, char *);
		sql = sqlite_mprintf("SELECT * FROM groups WHERE name = '%s'",
		    kgrp.sg_name);
		break;

	case SMB_LGRP_GTBL_SIDRID:
		kgrp.sg_rid = va_arg(ap, uint32_t);
		kgrp.sg_domain = va_arg(ap, smb_gdomain_t);
		dom_idx = (kgrp.sg_domain == SMB_LGRP_LOCAL)
		    ? SMB_LGRP_LOCAL_IDX : SMB_LGRP_BUILTIN_IDX;
		sql = sqlite_mprintf("SELECT * FROM groups"
		    "WHERE (sid_idx = %d) AND (sid_rid = %u)",
		    dom_idx, kgrp.sg_rid);
		break;

	default:
		va_end(ap);
		return (SMB_LGRP_INVALID_ARG);
	}

	va_end(ap);
	if (sql == NULL)
		return (SMB_LGRP_NO_MEMORY);

	rc = sqlite_get_table(db, sql, &result, &nrow, &ncol, &errmsg);
	sqlite_freemem(sql);

	if (rc != SQLITE_OK) {
		syslog(LOG_DEBUG, "failed to lookup (%s)", NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
		return (SMB_LGRP_LOOKUP_FAILED);
	}

	if (nrow == 0)  {
		/* group not found */
		sqlite_free_table(result);
		return (SMB_LGRP_NOT_FOUND);
	}

	if (nrow != 1 || ncol != SMB_LGRP_GTBL_NCOL) {
		sqlite_free_table(result);
		return (SMB_LGRP_DB_ERROR);
	}

	rc = smb_lgrp_decode(grp, &result[SMB_LGRP_GTBL_NCOL], infolvl, db);
	sqlite_free_table(result);
	return (rc);
}

/*
 * smb_lgrp_gtbl_exists
 *
 * Checks to see if the given group exists or not.
 */
static boolean_t
smb_lgrp_gtbl_exists(sqlite *db, char *gname)
{
	char *errmsg = NULL;
	char *sql;
	char **result;
	int nrow, ncol;
	int rc;

	if (db == NULL)
		return (NULL);

	sql = sqlite_mprintf("SELECT name FROM groups WHERE name = '%s'",
	    gname);
	rc = sqlite_get_table(db, sql, &result, &nrow, &ncol, &errmsg);
	sqlite_freemem(sql);

	if (rc != SQLITE_OK) {
		syslog(LOG_DEBUG, "failed to lookup %s (%s)",
		    gname, NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
		return (B_FALSE);
	}

	sqlite_free_table(result);
	return (nrow != 0);
}

/*
 * smb_lgrp_gtbl_count
 *
 * Counts the number of groups in the domain specified by
 * 'dom_idx'
 */
static int
smb_lgrp_gtbl_count(sqlite *db, int dom_idx, int *count)
{
	char *errmsg = NULL;
	char *sql;
	char **result;
	int nrow, ncol;
	int rc;

	*count = 0;
	if (db == NULL)
		return (SMB_LGRP_DBOPEN_FAILED);

	sql = sqlite_mprintf("SELECT sid_idx FROM groups WHERE sid_idx = %d",
	    dom_idx);
	rc = sqlite_get_table(db, sql, &result, &nrow, &ncol, &errmsg);
	sqlite_freemem(sql);

	if (rc != SQLITE_OK) {
		syslog(LOG_DEBUG, "failed to count (%s)", NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
		return (SMB_LGRP_LOOKUP_FAILED);
	}

	sqlite_free_table(result);
	if (ncol != 1)
		return (SMB_LGRP_DB_ERROR);

	*count = nrow;
	return (SMB_LGRP_SUCCESS);
}

/*
 * smb_lgrp_gtbl_insert
 *
 * Insert a record for the given group in the group database.
 *
 * NOTE: this function assumes that this group has no members
 * at this time.
 */
static int
smb_lgrp_gtbl_insert(sqlite *db, smb_group_t *grp)
{
	smb_lgpid_t privs[SE_MAX_LUID + 1];
	smb_lgplist_t plist;
	char *errmsg = NULL;
	char *sql;
	int dom_idx;
	int rc;

	if (db == NULL)
		return (SMB_LGRP_DBOPEN_FAILED);

	dom_idx = (grp->sg_domain == SMB_LGRP_LOCAL)
	    ? SMB_LGRP_LOCAL_IDX : SMB_LGRP_BUILTIN_IDX;

	plist.p_cnt = SE_MAX_LUID;
	plist.p_ids = privs;
	smb_lgrp_encode_privset(grp, &plist);

	sql = sqlite_mprintf("INSERT INTO groups"
	    "(name, sid_idx, sid_rid, sid_type, sid_attrs, comment, "
	    "n_privs, privs, n_members, members) "
	    "VALUES('%s', %u, %u, %u, %u, '%q', %u, '%q', %u, '%q')",
	    grp->sg_name, dom_idx, grp->sg_rid, grp->sg_id.gs_type,
	    grp->sg_attr, (grp->sg_cmnt) ? grp->sg_cmnt : "",
	    plist.p_cnt, (char *)plist.p_ids, 0, "");

	if (sql == NULL)
		return (SMB_LGRP_NO_MEMORY);

	rc = sqlite_exec(db, sql, NULL, NULL, &errmsg);
	sqlite_freemem(sql);

	if (rc != SQLITE_OK) {
		syslog(LOG_DEBUG, "failed to insert %s (%s)",
		    grp->sg_name, NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
		rc = SMB_LGRP_INSERT_FAILED;
	} else {
		rc = SMB_LGRP_SUCCESS;
	}

	return (rc);
}

/*
 * smb_lgrp_gtbl_delete
 *
 * Removes the specified group from the database
 */
static int
smb_lgrp_gtbl_delete(sqlite *db, char *gname)
{
	char *errmsg = NULL;
	char *sql;
	int rc;

	if (db == NULL)
		return (SMB_LGRP_DBOPEN_FAILED);

	sql = sqlite_mprintf("DELETE FROM groups WHERE name = '%s'", gname);
	if (sql == NULL)
		return (SMB_LGRP_NO_MEMORY);

	rc = sqlite_exec(db, sql, NULL, NULL, &errmsg);
	sqlite_freemem(sql);

	if (rc != SQLITE_OK) {
		syslog(LOG_DEBUG, "failed to delete %s (%s)",
		    gname, NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
		rc = SMB_LGRP_DELETE_FAILED;
	} else {
		rc = SMB_LGRP_SUCCESS;
	}

	return (rc);
}

/*
 * smb_lgrp_gtbl_update
 *
 * Updates the specified group information, the supported items
 * are group name and comment
 */
static int
smb_lgrp_gtbl_update(sqlite *db, char *gname, smb_group_t *grp, int col_id)
{
	char *errmsg = NULL;
	char *sql;
	int rc;

	if (db == NULL)
		return (SMB_LGRP_DBOPEN_FAILED);

	/* UPDATE doesn't fail if gname doesn't exist */
	if (!smb_lgrp_gtbl_exists(db, gname))
		return (SMB_LGRP_NOT_FOUND);

	switch (col_id) {
	case SMB_LGRP_GTBL_NAME:
		if (smb_lgrp_gtbl_exists(db, grp->sg_name))
			return (SMB_LGRP_EXISTS);
		sql = sqlite_mprintf("UPDATE groups SET name = '%s' "
		    "WHERE name = '%s'", grp->sg_name, gname);
		break;

	case SMB_LGRP_GTBL_CMNT:
		sql = sqlite_mprintf("UPDATE groups SET comment = '%q' "
		"WHERE name = '%s'", grp->sg_cmnt, gname);
		break;

	default:
		return (SMB_LGRP_INVALID_ARG);
	}

	if (sql == NULL)
		return (SMB_LGRP_NO_MEMORY);

	rc = sqlite_exec(db, sql, NULL, NULL, &errmsg);
	sqlite_freemem(sql);

	if (rc != SQLITE_OK) {
		syslog(LOG_DEBUG, "failed to update %s (%s)",
		    gname, NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
		rc = SMB_LGRP_UPDATE_FAILED;
	} else {
		rc = SMB_LGRP_SUCCESS;
	}

	return (rc);
}

/*
 * smb_lgrp_gtbl_update_mlist
 *
 * Adds/removes the specified member from the member list of the
 * given group
 */
static int
smb_lgrp_gtbl_update_mlist(sqlite *db, char *gname, smb_gsid_t *member,
    int flags)
{
	smb_lgmlist_t new_members;
	smb_lgmlist_t members;
	smb_lgmid_t mid;
	char *errmsg = NULL;
	char *sql;
	char **result;
	int nrow, ncol;
	int rc;

	if (db == NULL)
		return (SMB_LGRP_DBOPEN_FAILED);

	sql = sqlite_mprintf("SELECT n_members, members FROM groups "
	    "WHERE name = '%s'", gname);

	if (sql == NULL)
		return (SMB_LGRP_NO_MEMORY);

	rc = sqlite_get_table(db, sql, &result, &nrow, &ncol, &errmsg);
	sqlite_freemem(sql);

	if (rc != SQLITE_OK) {
		syslog(LOG_DEBUG, "failed to lookup %s (%s)",
		    gname, NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
		return (SMB_LGRP_LOOKUP_FAILED);
	}

	if (nrow == 0)  {
		/* group not found */
		sqlite_free_table(result);
		return (SMB_LGRP_NOT_FOUND);
	}

	if (nrow != 1 || ncol != 2) {
		sqlite_free_table(result);
		return (SMB_LGRP_DB_ERROR);
	}

	bzero(&mid, sizeof (mid));
	mid.m_type = member->gs_type;
	rc = smb_lgrp_dtbl_getidx(db, member->gs_sid, mid.m_type,
	    &mid.m_idx, &mid.m_rid);
	if (rc != SMB_LGRP_SUCCESS) {
		sqlite_free_table(result);
		return (rc);
	}

	members.m_cnt = atoi(result[2]);
	members.m_ids = result[3];

	switch (flags) {
	case SMB_LGRP_DB_ADDMEMBER:
		rc = smb_lgrp_mlist_add(&members, &mid, &new_members);
		break;
	case SMB_LGRP_DB_DELMEMBER:
		rc = smb_lgrp_mlist_del(&members, &mid, &new_members);
		break;
	default:
		rc = SMB_LGRP_INVALID_ARG;
	}

	sqlite_free_table(result);
	if (rc != SMB_LGRP_SUCCESS)
		return (rc);

	sql = sqlite_mprintf("UPDATE groups SET n_members = %u, members = '%s'"
	    " WHERE name = '%s'", new_members.m_cnt, new_members.m_ids, gname);

	free(new_members.m_ids);

	if (sql == NULL)
		return (SMB_LGRP_NO_MEMORY);

	rc = sqlite_exec(db, sql, NULL, NULL, &errmsg);
	sqlite_freemem(sql);

	if (rc != SQLITE_OK) {
		syslog(LOG_DEBUG, "failed to update %s (%s)", gname,
		    NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
		rc = SMB_LGRP_UPDATE_FAILED;
	} else {
		rc = SMB_LGRP_SUCCESS;
	}

	return (rc);
}

/*
 * smb_lgrp_gtbl_update_plist
 *
 * Adds/removes the specified privilege from the privilege list of the
 * given group
 */
static int
smb_lgrp_gtbl_update_plist(sqlite *db, char *gname, uint8_t priv_id,
    boolean_t enable)
{
	char *sql;
	char *errmsg = NULL;
	char **result;
	int nrow, ncol;
	int rc;
	smb_lgplist_t privs;
	smb_lgplist_t new_privs;

	if (db == NULL)
		return (SMB_LGRP_DBOPEN_FAILED);

	sql = sqlite_mprintf("SELECT n_privs, privs FROM groups "
	    "WHERE name = '%s'", gname);

	if (sql == NULL)
		return (SMB_LGRP_NO_MEMORY);

	rc = sqlite_get_table(db, sql, &result, &nrow, &ncol, &errmsg);
	sqlite_freemem(sql);

	if (rc != SQLITE_OK) {
		syslog(LOG_DEBUG, "failed to lookup %s (%s)",
		    gname, NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
		return (SMB_LGRP_LOOKUP_FAILED);
	}

	if (nrow == 0)  {
		/* group not found */
		sqlite_free_table(result);
		return (SMB_LGRP_NOT_FOUND);
	}

	if (nrow != 1 || ncol != 2) {
		sqlite_free_table(result);
		return (SMB_LGRP_DB_ERROR);
	}

	privs.p_cnt = atoi(result[2]);
	privs.p_ids = (smb_lgpid_t *)result[3];

	if (enable)
		rc = smb_lgrp_plist_add(&privs, priv_id, &new_privs);
	else
		rc = smb_lgrp_plist_del(&privs, priv_id, &new_privs);

	sqlite_free_table(result);
	if (rc != SMB_LGRP_SUCCESS)
		return (rc);

	sql = sqlite_mprintf("UPDATE groups SET n_privs = %u, privs = '%q'"
	    " WHERE name = '%s'", new_privs.p_cnt, (char *)new_privs.p_ids,
	    gname);

	free(new_privs.p_ids);

	if (sql == NULL)
		return (SMB_LGRP_NO_MEMORY);

	rc = sqlite_exec(db, sql, NULL, NULL, &errmsg);
	sqlite_freemem(sql);

	if (rc != SQLITE_OK) {
		syslog(LOG_DEBUG, "failed to update %s (%s)",
		    gname, NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
		rc = SMB_LGRP_UPDATE_FAILED;
	} else {
		rc = SMB_LGRP_SUCCESS;
	}

	return (rc);
}

/*
 * smb_lgrp_dtbl_insert
 *
 * Inserts the specified domain SID in the dmain table.
 * Upon successful insert the index will be returned in
 * 'dom_idx' arg.
 */
static int
smb_lgrp_dtbl_insert(sqlite *db, char *dom_sid, uint32_t *dom_idx)
{
	char *errmsg = NULL;
	char *sql;
	int rc;

	sql = sqlite_mprintf("INSERT INTO domains (dom_sid, dom_cnt)"
	    " VALUES('%s', 1);", dom_sid);
	if (sql == NULL)
		return (SMB_LGRP_NO_MEMORY);

	rc = sqlite_exec(db, sql, NULL, NULL, &errmsg);
	sqlite_freemem(sql);

	if (rc != SQLITE_OK) {
		syslog(LOG_DEBUG, "failed to insert domain SID (%s)",
		    NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
		return (SMB_LGRP_DOMINS_FAILED);
	}

	if (dom_idx)
		*dom_idx = sqlite_last_insert_rowid(db);
	return (SMB_LGRP_SUCCESS);
}

/*
 * smb_lgrp_dtbl_getidx
 *
 * Searches the domain table for the domain SID of the
 * given member SID. If it finds the domain SID it'll
 * return the index and the RID, otherwise it'll insert
 * it in the domain table as a new SID.
 */
static int
smb_lgrp_dtbl_getidx(sqlite *db, nt_sid_t *sid, uint16_t sid_type,
    uint32_t *dom_idx, uint32_t *rid)
{
	char sidstr[NT_SID_FMTBUF_SIZE];
	nt_sid_t *dom_sid;
	char **result;
	int nrow, ncol;
	char *errmsg = NULL;
	char *sql;
	int rc;

	if (nt_sid_is_indomain(smb_lgrp_lsid, sid)) {
		/* This is a local SID */
		int id_type = (sid_type == SidTypeUser)
		    ? SMB_IDMAP_USER : SMB_IDMAP_GROUP;
		*dom_idx = SMB_LGRP_LOCAL_IDX;
		if (smb_idmap_getid(sid, rid, &id_type) != IDMAP_SUCCESS)
			return (SMB_LGRP_INTERNAL_ERROR);
	}

	dom_sid = nt_sid_dup(sid);
	if (dom_sid == NULL)
		return (SMB_LGRP_NO_MEMORY);

	(void) nt_sid_split(dom_sid, rid);
	nt_sid_format2(dom_sid, sidstr);
	free(dom_sid);

	sql = sqlite_mprintf("SELECT dom_idx FROM domains WHERE dom_sid = '%s'",
	    sidstr);
	if (sql == NULL)
		return (SMB_LGRP_NO_MEMORY);

	rc = sqlite_get_table(db, sql, &result, &nrow, &ncol, &errmsg);
	sqlite_freemem(sql);

	if (rc != SQLITE_OK) {
		syslog(LOG_DEBUG, "failed to lookup domain SID (%s)",
		    NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
		return (SMB_LGRP_DOMLKP_FAILED);
	}

	switch (nrow) {
	case 0:
		/* new domain SID; insert it into the domains table */
		sqlite_free_table(result);
		return (smb_lgrp_dtbl_insert(db, sidstr, dom_idx));

	case 1:
		*dom_idx = atoi(result[1]);
		sqlite_free_table(result);
		return (SMB_LGRP_SUCCESS);
	}

	sqlite_free_table(result);
	return (SMB_LGRP_DB_ERROR);
}

/*
 * smb_lgrp_dtbl_getsid
 *
 * Searchs the domain table for the given domain index.
 * Converts the found domain SID to binary format and
 * returns it in the 'sid' arg.
 *
 * Caller must free the returned SID by calling free().
 */
static int
smb_lgrp_dtbl_getsid(sqlite *db, uint32_t dom_idx, nt_sid_t **sid)
{
	char **result;
	int nrow, ncol;
	char *errmsg = NULL;
	char *sql;
	int rc;

	sql = sqlite_mprintf("SELECT dom_sid FROM domains WHERE dom_idx = %u",
	    dom_idx);
	if (sql == NULL)
		return (SMB_LGRP_NO_MEMORY);

	rc = sqlite_get_table(db, sql, &result, &nrow, &ncol, &errmsg);
	sqlite_freemem(sql);

	if (rc != SQLITE_OK) {
		syslog(LOG_DEBUG, "failed to lookup domain index (%s)",
		    NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
		return (SMB_LGRP_DOMLKP_FAILED);
	}

	switch (nrow) {
	case 0:
		rc = SMB_LGRP_NO_SUCH_DOMAIN;
		break;

	case 1:
		*sid = nt_sid_strtosid(result[1]);
		rc = (*sid == NULL)
		    ? SMB_LGRP_INTERNAL_ERROR : SMB_LGRP_SUCCESS;
		break;

	default:
		rc = SMB_LGRP_DB_ERROR;
		break;
	}

	sqlite_free_table(result);
	return (rc);
}

/*
 * smb_lgrp_db_setinfo
 *
 * Initializes the db_info table upon database creation.
 */
static int
smb_lgrp_db_setinfo(sqlite *db)
{
	char *errmsg = NULL;
	char *sql;
	int rc;

	sql = sqlite_mprintf("INSERT INTO db_info (ver_major, ver_minor,"
	    " magic) VALUES (%d, %d, %u)", SMB_LGRP_DB_VERMAJOR,
	    SMB_LGRP_DB_VERMINOR, SMB_LGRP_DB_MAGIC);

	if (sql == NULL)
		return (SMB_LGRP_NO_MEMORY);

	rc = sqlite_exec(db, sql, NULL, NULL, &errmsg);
	sqlite_freemem(sql);
	if (rc != SQLITE_OK) {
		syslog(LOG_DEBUG, "failed to insert database information (%s)",
		    NULL_MSGCHK(errmsg));
		sqlite_freemem(errmsg);
		rc = SMB_LGRP_DBINIT_ERROR;
	} else {
		rc = SMB_LGRP_SUCCESS;
	}

	return (rc);
}

/*
 * smb_lgrp_mlist_add
 *
 * Adds the given member (newm) to the input member list (in_members)
 * if it's not already there. The result list will be returned in
 * out_members. The caller must free the allocated memory for
 * out_members by calling free().
 *
 * in_members and out_members are hex strings.
 */
static int
smb_lgrp_mlist_add(smb_lgmlist_t *in_members, smb_lgmid_t *newm,
    smb_lgmlist_t *out_members)
{
	char mid_hex[SMB_LGRP_MID_HEXSZ];
	char *in_list;
	char *out_list;
	int in_size;
	int out_size;
	int mid_hexsz;
	int i;

	out_members->m_cnt = 0;
	out_members->m_ids = NULL;

	bzero(mid_hex, sizeof (mid_hex));
	mid_hexsz = bintohex((const char *)newm, sizeof (smb_lgmid_t),
	    mid_hex, sizeof (mid_hex));

	/*
	 * Check to see if this is already a group member
	 */
	in_list = in_members->m_ids;
	for (i = 0; i < in_members->m_cnt; i++) {
		if (strncmp(in_list, mid_hex, mid_hexsz) == 0)
			return (SMB_LGRP_MEMBER_IN_GROUP);
		in_list += mid_hexsz;
	}

	in_size = (in_members->m_ids) ? strlen(in_members->m_ids) : 0;
	out_size = in_size + sizeof (mid_hex) + 1;
	out_list = malloc(out_size);
	if (out_list == NULL)
		return (SMB_LGRP_NO_MEMORY);

	bzero(out_list, out_size);
	if (in_members->m_ids)
		(void) strlcpy(out_list, in_members->m_ids, out_size);
	(void) strcat(out_list, mid_hex);

	out_members->m_cnt = in_members->m_cnt + 1;
	out_members->m_ids = out_list;

	return (SMB_LGRP_SUCCESS);
}

/*
 * smb_lgrp_mlist_del
 *
 * Removes the given member (msid) from the input member list
 * (in_members) if it's already there. The result list will b
 * returned in out_members. The caller must free the allocated
 * memory for out_members by calling free().
 *
 * in_members and out_members are hex strings.
 */
static int
smb_lgrp_mlist_del(smb_lgmlist_t *in_members, smb_lgmid_t *mid,
    smb_lgmlist_t *out_members)
{
	char mid_hex[SMB_LGRP_MID_HEXSZ];
	char *in_list;
	char *out_list;
	int in_size;
	int out_size;
	int mid_hexsz;
	int out_cnt;
	int i;

	out_members->m_cnt = 0;
	out_members->m_ids = NULL;

	if ((in_members == NULL) || (in_members->m_cnt == 0))
		return (SMB_LGRP_MEMBER_NOT_IN_GROUP);

	in_size = strlen(in_members->m_ids);
	out_size = in_size + sizeof (mid_hex) + 1;
	out_list = malloc(out_size);
	if (out_list == NULL)
		return (SMB_LGRP_NO_MEMORY);

	*out_list = '\0';

	bzero(mid_hex, sizeof (mid_hex));
	mid_hexsz = bintohex((const char *)mid, sizeof (smb_lgmid_t),
	    mid_hex, sizeof (mid_hex));

	in_list = in_members->m_ids;
	for (i = 0, out_cnt = 0; i < in_members->m_cnt; i++) {
		if (strncmp(in_list, mid_hex, mid_hexsz)) {
			(void) strncat(out_list, in_list, mid_hexsz);
			out_cnt++;
		}
		in_list += mid_hexsz;
	}

	if (out_cnt == in_members->m_cnt) {
		free(out_list);
		return (SMB_LGRP_MEMBER_NOT_IN_GROUP);
	}

	out_members->m_cnt = out_cnt;
	out_members->m_ids = out_list;
	return (SMB_LGRP_SUCCESS);
}

/*
 * smb_lgrp_plist_add
 *
 * Adds the given privilege to the input list (in_privs)
 * if it's not already there. The result list is returned
 * in out_privs. The caller must free the allocated memory
 * for out_privs by calling free().
 */
static int
smb_lgrp_plist_add(smb_lgplist_t *in_privs, smb_lgpid_t priv_id,
    smb_lgplist_t *out_privs)
{
	int i, size;
	smb_lgpid_t *pbuf;

	out_privs->p_cnt = 0;
	out_privs->p_ids = NULL;

	for (i = 0; i < in_privs->p_cnt; i++) {
		if (in_privs->p_ids[i] == priv_id)
			return (SMB_LGRP_PRIV_HELD);
	}

	size = (in_privs->p_cnt + 1) * sizeof (smb_lgpid_t) + 1;
	pbuf = malloc(size);
	if (pbuf == NULL)
		return (SMB_LGRP_NO_MEMORY);

	bzero(pbuf, size);
	bcopy(in_privs->p_ids, pbuf, in_privs->p_cnt * sizeof (smb_lgpid_t));
	pbuf[in_privs->p_cnt] = priv_id;

	out_privs->p_cnt = in_privs->p_cnt + 1;
	out_privs->p_ids = pbuf;

	return (SMB_LGRP_SUCCESS);
}

/*
 * smb_lgrp_plist_del
 *
 * Removes the given privilege from the input list (in_privs)
 * if it's already there. The result list is returned
 * in out_privs. The caller must free the allocated memory
 * for out_privs by calling free().
 */
static int
smb_lgrp_plist_del(smb_lgplist_t *in_privs, smb_lgpid_t priv_id,
    smb_lgplist_t *out_privs)
{
	int i, size;

	out_privs->p_cnt = 0;
	out_privs->p_ids = NULL;

	if ((in_privs == NULL) || (in_privs->p_cnt == 0))
		return (SMB_LGRP_PRIV_NOT_HELD);

	size = (in_privs->p_cnt - 1) * sizeof (smb_lgpid_t) + 1;
	out_privs->p_ids = malloc(size);
	if (out_privs->p_ids == NULL)
		return (SMB_LGRP_NO_MEMORY);

	bzero(out_privs->p_ids, size);

	for (i = 0; i < in_privs->p_cnt; i++) {
		if (in_privs->p_ids[i] != priv_id)
			out_privs->p_ids[out_privs->p_cnt++] =
			    in_privs->p_ids[i];
	}

	if (out_privs->p_cnt == in_privs->p_cnt) {
		free(out_privs->p_ids);
		out_privs->p_cnt = 0;
		out_privs->p_ids = NULL;
		return (SMB_LGRP_PRIV_NOT_HELD);
	}

	return (SMB_LGRP_SUCCESS);
}

/*
 * smb_lgrp_encode_privset
 *
 * Encodes given privilege set into a buffer to be stored in the group
 * database. Each entry of the encoded buffer contains the privilege ID
 * of an enable privilege. The returned buffer is null-terminated.
 */
static void
smb_lgrp_encode_privset(smb_group_t *grp, smb_lgplist_t *plist)
{
	smb_privset_t *privs;
	uint32_t pcnt = plist->p_cnt;
	int i;

	bzero(plist->p_ids, sizeof (smb_lgpid_t) * plist->p_cnt);
	plist->p_cnt = 0;

	privs = grp->sg_privs;
	if ((privs == NULL) || (privs->priv_cnt == 0))
		return;

	if (pcnt < privs->priv_cnt) {
		assert(0);
	}

	for (i = 0; i < privs->priv_cnt; i++) {
		if (privs->priv[i].attrs == SE_PRIVILEGE_ENABLED) {
			plist->p_ids[plist->p_cnt++] =
			    (uint8_t)privs->priv[i].luid.lo_part;
		}
	}
}

/*
 * smb_lgrp_decode_privset
 *
 * Decodes the privilege information read from group table
 * (nprivs, privs) into a binray format specified by the
 * privilege field of smb_group_t
 */
static int
smb_lgrp_decode_privset(smb_group_t *grp, char *nprivs, char *privs)
{
	smb_lgplist_t plist;
	int i;

	plist.p_cnt = atoi(nprivs);
	if (strlen(privs) != plist.p_cnt)
		return (SMB_LGRP_BAD_DATA);

	plist.p_ids = (smb_lgpid_t *)privs;
	grp->sg_privs = smb_privset_new();
	if (grp->sg_privs == NULL)
		return (SMB_LGRP_NO_MEMORY);

	for (i = 0; i < plist.p_cnt; i++)
		smb_privset_enable(grp->sg_privs, plist.p_ids[i]);

	return (SMB_LGRP_SUCCESS);
}

/*
 * smb_lgrp_decode_members
 *
 * Decodes the members information read from group table
 * (nmembers, members) into a binray format specified by the
 * member fields of smb_group_t
 */
static int
smb_lgrp_decode_members(smb_group_t *grp, char *nmembers, char *members,
    sqlite *db)
{
	smb_lgmid_t *m_ids;
	smb_lgmid_t *mid;
	smb_gsid_t *member;
	int mids_size;
	int i, rc;

	grp->sg_nmembers = atoi(nmembers);
	mids_size = grp->sg_nmembers * sizeof (smb_lgmid_t);
	m_ids = malloc(mids_size);
	if (m_ids == NULL)
		return (SMB_LGRP_NO_MEMORY);

	grp->sg_members = malloc(grp->sg_nmembers * sizeof (smb_gsid_t));
	if (grp->sg_members == NULL) {
		free(m_ids);
		return (SMB_LGRP_NO_MEMORY);
	}

	(void) hextobin(members, strlen(members), (char *)m_ids, mids_size);

	mid = m_ids;
	member = grp->sg_members;
	for (i = 0; i < grp->sg_nmembers; i++, mid++, member++) {
		rc = smb_lgrp_getsid(mid->m_idx, &mid->m_rid, mid->m_type, db,
		    &member->gs_sid);
		if (rc != SMB_LGRP_SUCCESS) {
			free(m_ids);
			return (SMB_LGRP_DB_ERROR);
		}

		member->gs_type = mid->m_type;
	}

	free(m_ids);
	return (SMB_LGRP_SUCCESS);
}

/*
 * smb_lgrp_decode
 *
 * Fills out the fields of the given group (grp) based in the
 * string information read from the group table. infolvl determines
 * which fields are requested and need to be decoded.
 *
 * Allocated memories must be freed by calling smb_lgrp_free()
 * upon successful return.
 */
static int
smb_lgrp_decode(smb_group_t *grp, char **values, int infolvl, sqlite *db)
{
	uint32_t sid_idx;
	int rc;

	if (infolvl == SMB_LGRP_INFO_NONE)
		return (SMB_LGRP_SUCCESS);

	if (infolvl & SMB_LGRP_INFO_NAME) {
		grp->sg_name = strdup(values[SMB_LGRP_GTBL_NAME]);
		if (grp->sg_name == NULL)
			return (SMB_LGRP_NO_MEMORY);
	}

	if (infolvl & SMB_LGRP_INFO_CMNT) {
		grp->sg_cmnt = strdup(values[SMB_LGRP_GTBL_CMNT]);
		if (grp->sg_cmnt == NULL) {
			smb_lgrp_free(grp);
			return (SMB_LGRP_NO_MEMORY);
		}
	}


	if (infolvl & SMB_LGRP_INFO_SID) {
		sid_idx = atoi(values[SMB_LGRP_GTBL_SIDIDX]);
		grp->sg_rid = atoi(values[SMB_LGRP_GTBL_SIDRID]);
		grp->sg_attr = atoi(values[SMB_LGRP_GTBL_SIDATR]);
		grp->sg_id.gs_type = atoi(values[SMB_LGRP_GTBL_SIDTYP]);
		rc = smb_lgrp_getsid(sid_idx, &grp->sg_rid, grp->sg_id.gs_type,
		    db, &grp->sg_id.gs_sid);
		if (rc != SMB_LGRP_SUCCESS) {
			smb_lgrp_free(grp);
			return (SMB_LGRP_NO_MEMORY);
		}
		grp->sg_domain = (sid_idx == SMB_LGRP_LOCAL_IDX)
		    ? SMB_LGRP_LOCAL : SMB_LGRP_BUILTIN;
	}

	if (infolvl & SMB_LGRP_INFO_PRIV) {
		rc = smb_lgrp_decode_privset(grp, values[SMB_LGRP_GTBL_NPRIVS],
		    values[SMB_LGRP_GTBL_PRIVS]);

		if (rc != SMB_LGRP_SUCCESS) {
			smb_lgrp_free(grp);
			return (rc);
		}
	}

	if (infolvl & SMB_LGRP_INFO_MEMB) {
		rc = smb_lgrp_decode_members(grp, values[SMB_LGRP_GTBL_NMEMBS],
		    values[SMB_LGRP_GTBL_MEMBS], db);
		if (rc != SMB_LGRP_SUCCESS) {
			smb_lgrp_free(grp);
			return (rc);
		}
	}

	return (SMB_LGRP_SUCCESS);
}

/*
 * smb_lgrp_chkname
 *
 * User account names are limited to 20 characters and group names are
 * limited to 256 characters. In addition, account names cannot be terminated
 * by a period and they cannot include commas or any of the following printable
 * characters: ", /, \, [, ], :, |, <, >, +, =, ;, ?, *.
 * Names also cannot include characters in the range 1-31, which are
 * nonprintable.
 *
 * Source: MSDN, description of NetLocalGroupAdd function.
 */
static boolean_t
smb_lgrp_chkname(char *name)
{
	static char *invalid_chars =
	    "\001\002\003\004\005\006\007\010\011\012\013\014\015\016\017"
	    "\020\021\022\023\024\025\026\027\030\031"
	    "\"/\\[]:|<>+=;,*?";
	int len, i;

	if (name == NULL || *name == '\0')
		return (B_FALSE);

	len = strlen(name);
	if (len > SMB_LGRP_NAME_MAX)
		return (B_FALSE);

	if (name[len - 1] == '.')
		return (B_FALSE);

	for (i = 0; i < len; i++)
		if (strchr(invalid_chars, name[i]))
			return (B_FALSE);

	(void) utf8_strlwr(name);
	return (B_TRUE);
}

/*
 * smb_lgrp_set_default_privs
 *
 * set default privileges for Administrators and Backup Operators
 */
static void
smb_lgrp_set_default_privs(smb_group_t *grp)
{
	if (utf8_strcasecmp(grp->sg_name, "Administrators") == 0) {
		smb_privset_enable(grp->sg_privs, SE_TAKE_OWNERSHIP_LUID);
		return;
	}

	if (utf8_strcasecmp(grp->sg_name, "Backup Operators") == 0) {
		smb_privset_enable(grp->sg_privs, SE_BACKUP_LUID);
		smb_privset_enable(grp->sg_privs, SE_RESTORE_LUID);
		return;
	}
}

/*
 * smb_lgrp_getsid
 *
 * Returns a SID based on the provided information
 * If dom_idx is 0, it means 'rid' contains a UID/GID and the
 * returned SID will be a local SID. If dom_idx is not 0 then
 * the domain SID will be fetched from the domain table.
 */
static int
smb_lgrp_getsid(int dom_idx, uint32_t *rid, uint16_t sid_type,
    sqlite *db, nt_sid_t **sid)
{
	nt_sid_t *dom_sid = NULL;
	nt_sid_t *res_sid = NULL;
	int id_type;
	int rc;

	*sid = NULL;
	if (dom_idx == SMB_LGRP_LOCAL_IDX) {
		id_type = (sid_type == SidTypeUser)
		    ? SMB_IDMAP_USER : SMB_IDMAP_GROUP;
		if (smb_idmap_getsid(*rid, id_type, &res_sid) != IDMAP_SUCCESS)
			return (SMB_LGRP_NO_SID);

		/*
		 * Make sure the returned SID is local
		 */
		if (!nt_sid_is_indomain(smb_lgrp_lsid, res_sid)) {
			free(res_sid);
			return (SMB_LGRP_SID_NOTLOCAL);
		}

		(void) nt_sid_get_rid(res_sid, rid);
		*sid = res_sid;
		return (SMB_LGRP_SUCCESS);
	}

	rc = smb_lgrp_dtbl_getsid(db, dom_idx, &dom_sid);
	if (rc != SMB_LGRP_SUCCESS)
		return (SMB_LGRP_DB_ERROR);

	res_sid = nt_sid_splice(dom_sid, *rid);
	free(dom_sid);
	if (res_sid == NULL)
		return (SMB_LGRP_NO_MEMORY);

	*sid = res_sid;
	return (SMB_LGRP_SUCCESS);
}
