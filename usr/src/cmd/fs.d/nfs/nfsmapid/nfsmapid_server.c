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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Door server routines for nfsmapid daemon
 * Translate NFSv4 users and groups between numeric and string values
 */
#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <signal.h>
#include <libintl.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <memory.h>
#include <pwd.h>
#include <grp.h>
#include <door.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <deflt.h>
#include <nfs/nfs4.h>
#include <nfs/nfssys.h>
#include <nfs/nfsid_map.h>
#include "nfsmapid_resolv.h"

/*
 * We cannot use the backend nscd as it may make syscalls that may
 * cause further nfsmapid upcalls introducing deadlock.
 * Use the internal uncached versions of get*_r.
 */
extern struct group *_uncached_getgrgid_r(gid_t, struct group *, char *, int);
extern struct group *_uncached_getgrnam_r(const char *, struct group *,
    char *, int);
extern struct passwd *_uncached_getpwuid_r(uid_t, struct passwd *, char *, int);
extern struct passwd *_uncached_getpwnam_r(const char *, struct passwd *,
    char *, int);

/*
 * is timestamp a == b?
 */
#define	TIMESTRUC_EQ(a, b) \
	(((a).tv_sec == (b).tv_sec) && ((a).tv_nsec == (b).tv_nsec))

#define	UID_MAX_STR_LEN	11	/* Digits in UID_MAX + 1 */

/*
 * domain*: describe nfsmapid domain currently in use
 * nfs_*  : describe nfsmapid domain specified by /etc/default/nfs
 * dns_*  : describe nfsmapid domain speficied by /etc/resolv.conf
 *
 * domain_cfg_lock: rwlock used to serialize access/changes to the
 * vars listed above (between nfsmapid service threads).
 *
 * Each nfsmapid thread holds the rdlock and stats the config files.
 * If the mtime is different, then they get the writelock and update
 * the cached info.
 *
 * If the domain is set via /etc/default/nfs, then we don't have
 * to look at resolv.conf.
 */
timestruc_t	nfs_mtime = {0};
uint32_t	nfs_domain_len = 0;
char		nfs_domain[NS_MAXCDNAME + 1] = {0};

timestruc_t	dns_mtime = {0};
uint32_t	dns_domain_len = 0;
char		dns_domain[NS_MAXCDNAME + 1] = {0};

uint32_t	cur_domain_len = 0;
char		cur_domain[NS_MAXCDNAME + 1] = {0};
#define		CUR_DOMAIN_NULL()		cur_domain[0] == '\0'

timestruc_t	zapped_mtime = {0};

#define		ZAP_DOMAIN(which) {		\
		which##_domain[0] = '\0';	\
		which##_domain_len = 0;		\
		which##_mtime = zapped_mtime;	\
}

rwlock_t	domain_cfg_lock = DEFAULTRWLOCK;

/*
 * Diags
 */
#define	DIAG_FILE	"/var/run/nfs4_domain"
FILE		*n4_fp;

extern size_t	pwd_buflen;
extern size_t	grp_buflen;
extern thread_t	sig_thread;

/*
 * Prototypes
 */
extern void	check_domain(int);
extern void	idmap_kcall(int);
extern int	standard_domain_str(const char *);
extern int	_nfssys(int, void *);
static int	valid_domain(const char *);
static int	validate_id_str(const char *);
static int	get_mtime(char *, timestruc_t *);
static void	get_nfs_domain(void);
static void	get_dns_domain(void);
static int	extract_domain(char *, char **, char **);
extern void	update_diag_file(char *);

static void
nfsmapid_str_uid(struct mapid_arg *argp, size_t arg_size)
{
	struct mapid_res result;
	struct passwd	 pwd;
	char		*pwd_buf;
	char		*user;
	char		*domain;

	if (argp->u_arg.len <= 0 || arg_size < MAPID_ARG_LEN(argp->u_arg.len)) {
		result.status = NFSMAPID_INVALID;
		result.u_res.uid = UID_NOBODY;
		goto done;
	}

	if (!extract_domain(argp->str, &user, &domain)) {
		long id;

		/*
		 * Invalid "user@dns_domain" string. Still, the user
		 * part might be an encoded uid, so do a final check.
		 * Remember, domain part of string was not set since
		 * not a valid string.
		 */
		if (!validate_id_str(user)) {
			result.status = NFSMAPID_UNMAPPABLE;
			result.u_res.uid = UID_NOBODY;
			goto done;
		}

		/*
		 * Since atoi() does not return proper errors for
		 * invalid translation, use strtol() instead.
		 */
		errno = 0;
		id = strtol(user, (char **)NULL, 10);

		if (errno || id < 0 || id > UID_MAX) {
			result.status = NFSMAPID_UNMAPPABLE;
			result.u_res.uid = UID_NOBODY;
			goto done;
		}

		result.u_res.uid = (uid_t)id;
		result.status = NFSMAPID_NUMSTR;
		goto done;
	}

	/*
	 * String properly constructed. Now we check for domain and
	 * group validity. Note that we only look at the domain iff
	 * the local domain is configured.
	 */
	if (!CUR_DOMAIN_NULL() && !valid_domain(domain)) {
		result.status = NFSMAPID_BADDOMAIN;
		result.u_res.uid = UID_NOBODY;
		goto done;
	}

	if ((pwd_buf = malloc(pwd_buflen)) == NULL ||
	    _uncached_getpwnam_r(user, &pwd, pwd_buf, pwd_buflen) == NULL) {

		if (pwd_buf == NULL)
			result.status = NFSMAPID_INTERNAL;
		else {
			/*
			 * Not a valid user
			 */
			result.status = NFSMAPID_NOTFOUND;
			free(pwd_buf);
		}
		result.u_res.uid = UID_NOBODY;
		goto done;
	}

	/*
	 * Valid user entry
	 */
	result.u_res.uid = pwd.pw_uid;
	result.status = NFSMAPID_OK;
	free(pwd_buf);
done:
	(void) door_return((char *)&result, sizeof (struct mapid_res), NULL, 0);
}

/* ARGSUSED1 */
static void
nfsmapid_uid_str(struct mapid_arg *argp, size_t arg_size)
{
	struct mapid_res	 result;
	struct mapid_res	*resp;
	struct passwd		 pwd;
	int			 pwd_len;
	char			*pwd_buf;
	uid_t			 uid = argp->u_arg.uid;
	size_t			 uid_str_len;
	char			*pw_str;
	size_t			 pw_str_len;
	char			*at_str;
	size_t			 at_str_len;
	char			 dom_str[NS_MAXCDNAME + 1];
	size_t			 dom_str_len;

	if (uid < 0 || uid > UID_MAX) {
		/*
		 * Negative uid or greater than UID_MAX
		 */
		resp = &result;
		resp->status = NFSMAPID_BADID;
		resp->u_res.len = 0;
		goto done;
	}

	/*
	 * Make local copy of domain for further manipuation
	 */
	(void) rw_rdlock(&domain_cfg_lock);
	if (CUR_DOMAIN_NULL()) {
		dom_str_len = 0;
		dom_str[0] = '\0';
	} else {
		dom_str_len = cur_domain_len;
		bcopy(cur_domain, dom_str, cur_domain_len);
		dom_str[dom_str_len] = '\0';
	}
	(void) rw_unlock(&domain_cfg_lock);

	/*
	 * We want to encode the uid into a literal string... :
	 *
	 *	- upon failure to allocate space from the heap
	 *	- if there is no current domain configured
	 *	- if there is no such uid in the passwd DB's
	 */
	if ((pwd_buf = malloc(pwd_buflen)) == NULL || dom_str_len == 0 ||
	    _uncached_getpwuid_r(uid, &pwd, pwd_buf, pwd_buflen) == NULL) {

		/*
		 * If we could not allocate from the heap, try
		 * allocating from the stack as a last resort.
		 */
		if (pwd_buf == NULL && (pwd_buf =
		    alloca(MAPID_RES_LEN(UID_MAX_STR_LEN))) == NULL) {
			resp = &result;
			resp->status = NFSMAPID_INTERNAL;
			resp->u_res.len = 0;
			goto done;
		}

		/*
		 * Constructing literal string without '@' so that
		 * we'll know that it's not a user, but rather a
		 * uid encoded string. Can't overflow because we
		 * already checked UID_MAX.
		 */
		pw_str = pwd_buf;
		(void) sprintf(pw_str, "%d", (int)uid);
		pw_str_len = strlen(pw_str);
		at_str_len = dom_str_len = 0;
		at_str = "";
		dom_str[0] = '\0';
	} else {
		/*
		 * Otherwise, we construct the "user@domain" string
		 */
		pw_str = pwd.pw_name;
		pw_str_len = strlen(pw_str);
		at_str = "@";
		at_str_len = 1;
	}

	uid_str_len = pw_str_len + at_str_len + dom_str_len;
	if ((resp = alloca(MAPID_RES_LEN(UID_MAX_STR_LEN))) == NULL) {
		resp = &result;
		resp->status = NFSMAPID_INTERNAL;
		resp->u_res.len = 0;
		goto done;
	}
	/* LINTED format argument to sprintf */
	(void) sprintf(resp->str, "%s%s%s", pw_str, at_str, dom_str);
	resp->u_res.len = uid_str_len;
	free(pwd_buf);
	resp->status = NFSMAPID_OK;

done:
	/*
	 * There is a chance that the door_return will fail because the
	 * resulting string is too large, try to indicate that if possible
	 */
	if (door_return((char *)resp,
	    MAPID_RES_LEN(resp->u_res.len), NULL, 0) == -1) {
		resp->status = NFSMAPID_INTERNAL;
		resp->u_res.len = 0;
		(void) door_return((char *)&result, sizeof (struct mapid_res),
							NULL, 0);
	}
}

static void
nfsmapid_str_gid(struct mapid_arg *argp, size_t arg_size)
{
	struct mapid_res	result;
	struct group		grp;
	char			*grp_buf;
	char			*group;
	char			*domain;

	if (argp->u_arg.len <= 0 ||
				arg_size < MAPID_ARG_LEN(argp->u_arg.len)) {
		result.status = NFSMAPID_INVALID;
		result.u_res.gid = GID_NOBODY;
		goto done;
	}

	if (!extract_domain(argp->str, &group, &domain)) {
		long id;

		/*
		 * Invalid "group@dns_domain" string. Still, the
		 * group part might be an encoded gid, so do a
		 * final check. Remember, domain part of string
		 * was not set since not a valid string.
		 */
		if (!validate_id_str(group)) {
			result.status = NFSMAPID_UNMAPPABLE;
			result.u_res.gid = GID_NOBODY;
			goto done;
		}

		/*
		 * Since atoi() does not return proper errors for
		 * invalid translation, use strtol() instead.
		 */
		errno = 0;
		id = strtol(group, (char **)NULL, 10);

		if (errno || id < 0 || id > UID_MAX) {
			result.status = NFSMAPID_UNMAPPABLE;
			result.u_res.gid = GID_NOBODY;
			goto done;
		}

		result.u_res.gid = (gid_t)id;
		result.status = NFSMAPID_NUMSTR;
		goto done;
	}

	/*
	 * String properly constructed. Now we check for domain and
	 * group validity. Note that we only look at the domain iff
	 * the local domain is configured.
	 */
	if (!CUR_DOMAIN_NULL() && !valid_domain(domain)) {
		result.status = NFSMAPID_BADDOMAIN;
		result.u_res.gid = GID_NOBODY;
		goto done;
	}

	if ((grp_buf = malloc(grp_buflen)) == NULL ||
	    _uncached_getgrnam_r(group, &grp, grp_buf, grp_buflen) == NULL) {

		if (grp_buf == NULL)
			result.status = NFSMAPID_INTERNAL;
		else {
			/*
			 * Not a valid group
			 */
			result.status = NFSMAPID_NOTFOUND;
			free(grp_buf);
		}
		result.u_res.gid = GID_NOBODY;
		goto done;
	}

	/*
	 * Valid group entry
	 */
	result.status = NFSMAPID_OK;
	result.u_res.gid = grp.gr_gid;
	free(grp_buf);
done:
	(void) door_return((char *)&result, sizeof (struct mapid_res), NULL, 0);
}

/* ARGSUSED1 */
static void
nfsmapid_gid_str(struct mapid_arg *argp, size_t arg_size)
{
	struct mapid_res	 result;
	struct mapid_res	*resp;
	struct group		 grp;
	char			*grp_buf;
	gid_t			 gid = argp->u_arg.gid;
	size_t			 gid_str_len;
	char			*gr_str;
	size_t			 gr_str_len;
	char			*at_str;
	size_t			 at_str_len;
	char			 dom_str[NS_MAXCDNAME + 1];
	size_t			 dom_str_len;

	if (gid < 0 || gid > UID_MAX) {
		/*
		 * Negative gid or greater than UID_MAX
		 */
		resp = &result;
		resp->status = NFSMAPID_BADID;
		resp->u_res.len = 0;
		goto done;
	}

	/*
	 * Make local copy of domain for further manipuation
	 */
	(void) rw_rdlock(&domain_cfg_lock);
	if (CUR_DOMAIN_NULL()) {
		dom_str_len = 0;
		dom_str[0] = '\0';
	} else {
		dom_str_len = cur_domain_len;
		bcopy(cur_domain, dom_str, cur_domain_len);
		dom_str[dom_str_len] = '\0';
	}
	(void) rw_unlock(&domain_cfg_lock);

	/*
	 * We want to encode the gid into a literal string... :
	 *
	 *	- upon failure to allocate space from the heap
	 *	- if there is no current domain configured
	 *	- if there is no such gid in the group DB's
	 */
	if ((grp_buf = malloc(grp_buflen)) == NULL || dom_str_len == 0 ||
	    _uncached_getgrgid_r(gid, &grp, grp_buf, grp_buflen) == NULL) {

		/*
		 * If we could not allocate from the heap, try
		 * allocating from the stack as a last resort.
		 */
		if (grp_buf == NULL && (grp_buf =
		    alloca(MAPID_RES_LEN(UID_MAX_STR_LEN))) == NULL) {
			resp = &result;
			resp->status = NFSMAPID_INTERNAL;
			resp->u_res.len = 0;
			goto done;
		}

		/*
		 * Constructing literal string without '@' so that
		 * we'll know that it's not a group, but rather a
		 * gid encoded string. Can't overflow because we
		 * already checked UID_MAX.
		 */
		gr_str = grp_buf;
		(void) sprintf(gr_str, "%d", (int)gid);
		gr_str_len = strlen(gr_str);
		at_str_len = dom_str_len = 0;
		at_str = "";
		dom_str[0] = '\0';
	} else {
		/*
		 * Otherwise, we construct the "group@domain" string
		 */
		gr_str = grp.gr_name;
		gr_str_len = strlen(gr_str);
		at_str = "@";
		at_str_len = 1;
	}

	gid_str_len = gr_str_len + at_str_len + dom_str_len;
	if ((resp = alloca(MAPID_RES_LEN(UID_MAX_STR_LEN))) == NULL) {
		resp = &result;
		resp->status = NFSMAPID_INTERNAL;
		resp->u_res.len = 0;
		goto done;
	}
	/* LINTED format argument to sprintf */
	(void) sprintf(resp->str, "%s%s%s", gr_str, at_str, dom_str);
	resp->u_res.len = gid_str_len;
	free(grp_buf);
	resp->status = NFSMAPID_OK;

done:
	/*
	 * There is a chance that the door_return will fail because the
	 * resulting string is too large, try to indicate that if possible
	 */
	if (door_return((char *)resp,
	    MAPID_RES_LEN(resp->u_res.len), NULL, 0) == -1) {
		resp->status = NFSMAPID_INTERNAL;
		resp->u_res.len = 0;
		(void) door_return((char *)&result, sizeof (struct mapid_res),
							NULL, 0);
	}
}

/* ARGSUSED */
void
nfsmapid_func(void *cookie, char *argp, size_t arg_size,
						door_desc_t *dp, uint_t n_desc)
{
	struct mapid_arg	*mapargp;
	struct mapid_res	mapres;

	/*
	 * Make sure we have a valid argument
	 */
	if (arg_size < sizeof (struct mapid_arg)) {
		mapres.status = NFSMAPID_INVALID;
		mapres.u_res.len = 0;
		(void) door_return((char *)&mapres, sizeof (struct mapid_res),
								NULL, 0);
		return;
	}

	/* LINTED pointer cast */
	mapargp = (struct mapid_arg *)argp;
	switch (mapargp->cmd) {
	case NFSMAPID_STR_UID:
		nfsmapid_str_uid(mapargp, arg_size);
		return;
	case NFSMAPID_UID_STR:
		nfsmapid_uid_str(mapargp, arg_size);
		return;
	case NFSMAPID_STR_GID:
		nfsmapid_str_gid(mapargp, arg_size);
		return;
	case NFSMAPID_GID_STR:
		nfsmapid_gid_str(mapargp, arg_size);
		return;
	default:
		break;
	}
	mapres.status = NFSMAPID_INVALID;
	mapres.u_res.len = 0;
	(void) door_return((char *)&mapres, sizeof (struct mapid_res), NULL, 0);
}

static int
extract_domain(char *cp, char **upp, char **dpp)
{
	/*
	 * Caller must insure that the string is valid
	 */
	*upp = cp;

	if ((*dpp = strchr(cp, '@')) == NULL)
		return (0);
	*(*dpp)++ = '\0';
	return (1);
}

static int
valid_domain(const char *dom)
{
	const char	*whoami = "valid_domain";

	if (!standard_domain_str(dom)) {
		syslog(LOG_ERR, gettext("%s: Invalid domain name %s. Check "
			"configuration file and restart daemon."), whoami, dom);
		return (0);
	}

	(void) rw_rdlock(&domain_cfg_lock);
	if (strcasecmp(dom, cur_domain) == 0) {
		(void) rw_unlock(&domain_cfg_lock);
		return (1);
	}
	(void) rw_unlock(&domain_cfg_lock);
	return (0);
}

static int
validate_id_str(const char *id)
{
	while (*id) {
		if (!isdigit(*id++))
			return (0);
	}
	return (1);
}

static int
get_mtime(char *fname, timestruc_t *mtim)
{
	struct stat st;
	int err;

	if ((err = stat(fname, &st)) != 0)
		return (err);

	*mtim = st.st_mtim;
	return (0);
}

static void
get_nfs_domain(void)
{
	const char	*whoami = "get_nfs_domain";
	char		*ndomain;
	timestruc_t	 ntime;

	/*
	 * If we can't get stats for the config file, then
	 * zap the NFS domain info.  If mtime hasn't changed,
	 * then there's no work to do, so just return.
	 */
	if (get_mtime(NFSADMIN, &ntime) != 0) {
		ZAP_DOMAIN(nfs);
		return;
	}

	if (TIMESTRUC_EQ(ntime, nfs_mtime))
		return;

	/*
	 * Get NFSMAPID_DOMAIN value from /etc/default/nfs for now.
	 * Note: defread() returns a ptr to TSD.
	 */
	if (defopen(NFSADMIN) == 0) {
		ndomain = (char *)defread("NFSMAPID_DOMAIN=");

		/* close default file */
		(void) defopen(NULL);

		/*
		 * NFSMAPID_DOMAIN was set so its time for validation.
		 * If its okay, then update NFS domain and return.  If not,
		 * complain about invalid domain.
		 */
		if (ndomain) {
			if (standard_domain_str(ndomain)) {
				nfs_domain_len = strlen(ndomain);
				(void) strncpy(nfs_domain, ndomain,
								NS_MAXCDNAME);
				nfs_mtime = ntime;
				return;
			}

			syslog(LOG_ERR, gettext("%s: Invalid domain name %s. "
				"Check configuration file and restart daemon."),
				whoami, ndomain);
		}
	}

	/*
	 * So the NFS config file changed but it couldn't be opened or
	 * it didn't specify NFSMAPID_DOMAIN or it specified an invalid
	 * NFSMAPID_DOMAIN.  Time to zap current NFS domain info.
	 */
	ZAP_DOMAIN(nfs);
}

static void
get_dns_domain(void)
{
#ifdef DEBUG
	const char	*whoami = "get_dns_domain";
#endif
	timestruc_t	 ntime = {0};

	/*
	 * If we can't get stats for the config file, then
	 * zap the DNS domain info.  If mtime hasn't changed,
	 * then there's no work to do, so just return.
	 */
	errno = 0;
	if (get_mtime(_PATH_RESCONF, &ntime) != 0) {
		switch (errno) {
			case ENOENT:
				/*
				 * The resolver defaults to obtaining the
				 * domain off of the NIS domainname(1M) if
				 * /etc/resolv.conf does not exist, so we
				 * move forward.
				 */
				IDMAP_DBG("%s: no %s file", whoami,
				    _PATH_RESCONF);
				break;

			default:
				ZAP_DOMAIN(dns);
				return;
		}
	} else if (TIMESTRUC_EQ(ntime, dns_mtime)) {
		IDMAP_DBG("%s: no mtime changes in %s", whoami, _PATH_RESCONF);
		return;
	}

	/*
	 * Re-initialize resolver to zap DNS domain from previous
	 * resolv_init() calls.
	 */
	(void) resolv_init();

	/*
	 * Update cached DNS domain.  No need for validation since
	 * domain comes from resolver.  If resolver doesn't return the
	 * domain, then zap the DNS domain.  This shouldn't ever happen,
	 * and if it does, the machine has bigger problems (so no need
	 * to generating a message that says DNS appears to be broken).
	 */
	(void) rw_rdlock(&dns_data_lock);
	if (sysdns_domain[0] != '\0') {
		(void) strncpy(dns_domain, sysdns_domain, NS_MAXCDNAME);
		dns_mtime = ntime;
		dns_domain_len = strlen(sysdns_domain);
		(void) rw_unlock(&dns_data_lock);
		return;
	}
	(void) rw_unlock(&dns_data_lock);

	ZAP_DOMAIN(dns);
}

void
idmap_kcall(int did)
{
	struct nfsidmap_args args;

	if (did >= 0) {
		args.state = 1;
		args.did = did;
	} else {
		args.state = 0;
		args.did = 0;
	}

	(void) _nfssys(NFS_IDMAP, &args);
}

/*
 * Get the current NFS domain.
 *
 * If NFSMAPID_DOMAIN is set in /etc/default/nfs, then it is the NFS domain;
 * otherwise, the DNS domain is used.
 */
void
check_domain(int flush)
{
	const char	*whoami = "check_domain";
	char		*new_domain;
	int		 new_dlen = 0;
	static int	 setup_done = 0;

	get_nfs_domain();
	if (nfs_domain_len != 0) {
		new_domain = nfs_domain;
		new_dlen = nfs_domain_len;
		IDMAP_DBG("%s: NFS File Domain: %s", whoami, nfs_domain);
		goto dname_chkd;
	}

	/*
	 * If called in response to a SIGHUP,
	 * reset any cached DNS TXT RR state.
	 */
	get_dns_txt_domain(flush);
	if (dns_txt_domain_len != 0) {
		new_domain = dns_txt_domain;
		new_dlen = dns_txt_domain_len;
		IDMAP_DBG("%s: DNS TXT Record: %s", whoami, dns_txt_domain);
	} else {
		/*
		 * We're either here because:
		 *
		 *  . NFSMAPID_DOMAIN was not set in /etc/default/nfs
		 *  . No suitable DNS TXT resource record exists
		 *  . DNS server is not responding to requests
		 *
		 * in either case, we want to default to using the
		 * system configured DNS domain. If this fails, then
		 * dns_domain will be empty and dns_domain_len will
		 * be 0.
		 */
		get_dns_domain();
		new_domain = dns_domain;
		new_dlen = dns_domain_len;
		IDMAP_DBG("%s: Default DNS Domain: %s", whoami, dns_domain);
	}

dname_chkd:
	/*
	 * Update cur_domain if new_domain is different.  Set flush
	 * to guarantee that kernel idmapping caches are flushed.
	 */
	if (strncasecmp(new_domain, cur_domain, NS_MAXCDNAME)) {
		(void) rw_wrlock(&domain_cfg_lock);
		(void) strncpy(cur_domain, new_domain, NS_MAXCDNAME);
		cur_domain_len = new_dlen;
		update_diag_file(new_domain);
		DTRACE_PROBE1(nfsmapid, daemon__domain, cur_domain);
		(void) rw_unlock(&domain_cfg_lock);
		flush = 1;
	}

	/*
	 * Restart the signal handler thread if we're still setting up
	 */
	if (!setup_done) {
		setup_done = 1;
		IDMAP_DBG("%s: Initial setup done !", whoami, NULL);
		if (thr_continue(sig_thread)) {
			syslog(LOG_ERR, gettext("%s: Fatal error: signal "
			    "handler thread could not be restarted."), whoami);
			exit(6);
		}

		/*
		 * We force bail here so we don't end up flushing kernel
		 * caches until we _know_ we're up.
		 */
		return;
	}

	/*
	 * If caller requested flush or if domain has changed, then
	 * flush kernel idmapping caches.
	 */
	if (flush)
		idmap_kcall(-1);
}


/*
 * Based on the recommendations from
 *	RFC1033  DOMAIN ADMINISTRATORS OPERATIONS GUIDE
 *	RFC1035  DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
 * check if a given domain name string is valid.
 */
int
standard_domain_str(const char *ds)
{
	int	i;

	for (i = 0; *ds && i < NS_MAXCDNAME; i++, ds++) {
		if (!isalpha(*ds) && !isdigit(*ds) && (*ds != '.') &&
				(*ds != '-') && (*ds != '_'))
			return (0);
	}
	if (i == NS_MAXCDNAME)
		return (0);
	return (1);
}

/*
 * Need to be able to open the DIAG_FILE before nfsmapid(1m)
 * releases it's root priviledges. The DIAG_FILE then remains
 * open for the duration of this nfsmapid instance via n4_fp.
 */
void
open_diag_file()
{
	static int	msg_done = 0;

	if ((n4_fp = fopen(DIAG_FILE, "w+")) != NULL)
		return;

	if (msg_done)
		return;

	syslog(LOG_ERR, "Failed to create %s. Enable syslog "
			"daemon.debug for more info", DIAG_FILE);
	msg_done = 1;
}

/*
 * When a new domain name is configured, save to DIAG_FILE
 * and log to syslog, with LOG_DEBUG level (if configured).
 */
void
update_diag_file(char *new)
{
	rewind(n4_fp);
	ftruncate(fileno(n4_fp), 0);
	fprintf(n4_fp, "%.*s\n", NS_MAXCDNAME, new);
	fflush(n4_fp);

	syslog(LOG_DEBUG, "nfsmapid domain = %s", new);
}
