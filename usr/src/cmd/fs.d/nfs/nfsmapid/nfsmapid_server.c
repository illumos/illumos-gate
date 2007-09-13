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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
#include <nfs/mapid.h>
#include <sys/sdt.h>
#include <sys/idmap.h>
#include <idmap.h>

#define		UID_MAX_STR_LEN		11	/* Digits in UID_MAX + 1 */
#define		DIAG_FILE		"/var/run/nfs4_domain"

/*
 * idmap_kcall() takes a door descriptor as it's argument when we
 * need to (re)establish the in-kernel door handles. When we only
 * want to flush the id kernel caches, we don't redo the door setup.
 */
#define		FLUSH_KCACHES_ONLY	(int)-1

FILE		*n4_fp;
int		 n4_fd;

extern size_t	pwd_buflen;
extern size_t	grp_buflen;
extern thread_t	sig_thread;

/*
 * Prototypes
 */
extern void	 check_domain(int);
extern void	 idmap_kcall(int);
extern int	 _nfssys(int, void *);
extern int	 valid_domain(const char *);
extern int	 validate_id_str(const char *);
extern int	 extract_domain(char *, char **, char **);
extern void	 update_diag_file(char *);
extern void	*cb_update_domain(void *);
extern int	 cur_domain_null(void);

void
nfsmapid_str_uid(struct mapid_arg *argp, size_t arg_size)
{
	struct mapid_res result;
	struct passwd	 pwd;
	struct passwd	*pwd_ptr;
	int		 pwd_rc;
	char		*pwd_buf;
	char		*user;
	char		*domain;
	idmap_stat	 rc;

	if (argp->u_arg.len <= 0 || arg_size < MAPID_ARG_LEN(argp->u_arg.len)) {
		result.status = NFSMAPID_INVALID;
		result.u_res.uid = UID_NOBODY;
		goto done;
	}

	if (!extract_domain(argp->str, &user, &domain)) {
		unsigned long id;

		/*
		 * Invalid "user@domain" string. Still, the user
		 * part might be an encoded uid, so do a final check.
		 * Remember, domain part of string was not set since
		 * not a valid string.
		 */
		if (!validate_id_str(user)) {
			result.status = NFSMAPID_UNMAPPABLE;
			result.u_res.uid = UID_NOBODY;
			goto done;
		}

		errno = 0;
		id = strtoul(user, (char **)NULL, 10);

		/*
		 * We don't accept ephemeral ids from the wire.
		 */
		if (errno || id > UID_MAX) {
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
	 * group validity.
	 */
	if (!cur_domain_null() && !valid_domain(domain)) {
		/*
		 * If the domain part of the string does not
		 * match the NFS domain, try to map it using
		 * idmap service.
		 */
		rc = idmap_getuidbywinname(user, domain, &result.u_res.uid);
		if (rc != IDMAP_SUCCESS) {
			result.status = NFSMAPID_BADDOMAIN;
			result.u_res.uid = UID_NOBODY;
			goto done;
		}
		result.status = NFSMAPID_OK;
		goto done;
	}

	if ((pwd_buf = malloc(pwd_buflen)) == NULL ||
	    (pwd_rc = getpwnam_r(user, &pwd, pwd_buf, pwd_buflen, &pwd_ptr))
	    != 0 || pwd_ptr == NULL) {

		if (pwd_buf == NULL || pwd_rc != 0)
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
void
nfsmapid_uid_str(struct mapid_arg *argp, size_t arg_size)
{
	struct mapid_res	 result;
	struct mapid_res	*resp;
	struct passwd		 pwd;
	struct passwd		 *pwd_ptr;
	char			*pwd_buf = NULL;
	char			*idmap_buf = NULL;
	uid_t			 uid = argp->u_arg.uid;
	size_t			 uid_str_len;
	char			*pw_str;
	size_t			 pw_str_len;
	char			*at_str;
	size_t			 at_str_len;
	char			 dom_str[DNAMEMAX];
	size_t			 dom_str_len;
	idmap_stat		 rc;

	if (uid == (uid_t)-1) {
		/*
		 * Sentinel uid is not a valid id
		 */
		resp = &result;
		resp->status = NFSMAPID_BADID;
		resp->u_res.len = 0;
		goto done;
	}

	/*
	 * Make local copy of domain for further manipuation
	 * NOTE: mapid_get_domain() returns a ptr to TSD.
	 */
	if (cur_domain_null()) {
		dom_str_len = 0;
		dom_str[0] = '\0';
	} else {
		dom_str_len = strlcpy(dom_str, mapid_get_domain(), DNAMEMAX);
	}

	/*
	 * If uid is ephemeral then resolve it using idmap service
	 */
	if (uid > UID_MAX) {
		rc = idmap_getwinnamebyuid(uid, &idmap_buf, NULL);
		if (rc != IDMAP_SUCCESS) {
			/*
			 * We don't put stringified ephemeral uids on
			 * the wire.
			 */
			resp = &result;
			resp->status = NFSMAPID_UNMAPPABLE;
			resp->u_res.len = 0;
			goto done;
		}

		/*
		 * idmap_buf is already in the desired form i.e. name@domain
		 */
		pw_str = idmap_buf;
		pw_str_len = strlen(pw_str);
		at_str_len = dom_str_len = 0;
		at_str = "";
		dom_str[0] = '\0';
		goto gen_result;
	}

	/*
	 * Handling non-ephemeral uids
	 *
	 * We want to encode the uid into a literal string... :
	 *
	 *	- upon failure to allocate space from the heap
	 *	- if there is no current domain configured
	 *	- if there is no such uid in the passwd DB's
	 */
	if ((pwd_buf = malloc(pwd_buflen)) == NULL || dom_str_len == 0 ||
	    getpwuid_r(uid, &pwd, pwd_buf, pwd_buflen, &pwd_ptr) != 0 ||
	    pwd_ptr == NULL) {

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
		 * uid encoded string.
		 */
		pw_str = pwd_buf;
		(void) sprintf(pw_str, "%u", uid);
		pw_str_len = strlen(pw_str);
		at_str_len = dom_str_len = 0;
		at_str = "";
		dom_str[0] = '\0';
	} else {
		/*
		 * Otherwise, we construct the "user@domain" string if
		 * it's not already in that form.
		 */
		pw_str = pwd.pw_name;
		pw_str_len = strlen(pw_str);
		if (strchr(pw_str, '@') == NULL) {
			at_str = "@";
			at_str_len = 1;
		} else {
			at_str_len = dom_str_len = 0;
			at_str = "";
			dom_str[0] = '\0';
		}
	}

gen_result:
	uid_str_len = pw_str_len + at_str_len + dom_str_len;
	if ((resp = alloca(MAPID_RES_LEN(uid_str_len))) == NULL) {
		resp = &result;
		resp->status = NFSMAPID_INTERNAL;
		resp->u_res.len = 0;
		goto done;
	}
	/* LINTED format argument to sprintf */
	(void) sprintf(resp->str, "%s%s%s", pw_str, at_str, dom_str);
	resp->u_res.len = uid_str_len;
	if (pwd_buf)
		free(pwd_buf);
	if (idmap_buf)
		idmap_free(idmap_buf);
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

void
nfsmapid_str_gid(struct mapid_arg *argp, size_t arg_size)
{
	struct mapid_res	result;
	struct group		grp;
	struct group		*grp_ptr;
	int			grp_rc;
	char			*grp_buf;
	char			*group;
	char			*domain;
	idmap_stat		rc;

	if (argp->u_arg.len <= 0 ||
	    arg_size < MAPID_ARG_LEN(argp->u_arg.len)) {
		result.status = NFSMAPID_INVALID;
		result.u_res.gid = GID_NOBODY;
		goto done;
	}

	if (!extract_domain(argp->str, &group, &domain)) {
		unsigned long id;

		/*
		 * Invalid "group@domain" string. Still, the
		 * group part might be an encoded gid, so do a
		 * final check. Remember, domain part of string
		 * was not set since not a valid string.
		 */
		if (!validate_id_str(group)) {
			result.status = NFSMAPID_UNMAPPABLE;
			result.u_res.gid = GID_NOBODY;
			goto done;
		}

		errno = 0;
		id = strtoul(group, (char **)NULL, 10);

		/*
		 * We don't accept ephemeral ids from the wire.
		 */
		if (errno || id > UID_MAX) {
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
	 * group validity.
	 */
	if (!cur_domain_null() && !valid_domain(domain)) {
		/*
		 * If the domain part of the string does not
		 * match the NFS domain, try to map it using
		 * idmap service.
		 */
		rc = idmap_getgidbywinname(group, domain, &result.u_res.gid);
		if (rc != IDMAP_SUCCESS) {
			result.status = NFSMAPID_BADDOMAIN;
			result.u_res.gid = GID_NOBODY;
			goto done;
		}
		result.status = NFSMAPID_OK;
		goto done;
	}

	if ((grp_buf = malloc(grp_buflen)) == NULL ||
	    (grp_rc = getgrnam_r(group, &grp, grp_buf, grp_buflen, &grp_ptr))
	    != 0 || grp_ptr == NULL) {

		if (grp_buf == NULL || grp_rc != 0)
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
void
nfsmapid_gid_str(struct mapid_arg *argp, size_t arg_size)
{
	struct mapid_res	 result;
	struct mapid_res	*resp;
	struct group		 grp;
	struct group		*grp_ptr;
	char			*grp_buf = NULL;
	char			*idmap_buf = NULL;
	idmap_stat		 rc;
	gid_t			 gid = argp->u_arg.gid;
	size_t			 gid_str_len;
	char			*gr_str;
	size_t			 gr_str_len;
	char			*at_str;
	size_t			 at_str_len;
	char			 dom_str[DNAMEMAX];
	size_t			 dom_str_len;

	if (gid == (gid_t)-1) {
		/*
		 * Sentinel gid is not a valid id
		 */
		resp = &result;
		resp->status = NFSMAPID_BADID;
		resp->u_res.len = 0;
		goto done;
	}

	/*
	 * Make local copy of domain for further manipuation
	 * NOTE: mapid_get_domain() returns a ptr to TSD.
	 */
	if (cur_domain_null()) {
		dom_str_len = 0;
		dom_str[0] = '\0';
	} else {
		dom_str_len = strlen(mapid_get_domain());
		bcopy(mapid_get_domain(), dom_str, dom_str_len);
		dom_str[dom_str_len] = '\0';
	}

	/*
	 * If gid is ephemeral then resolve it using idmap service
	 */
	if (gid > UID_MAX) {
		rc = idmap_getwinnamebygid(gid, &idmap_buf, NULL);
		if (rc != IDMAP_SUCCESS) {
			/*
			 * We don't put stringified ephemeral gids on
			 * the wire.
			 */
			resp = &result;
			resp->status = NFSMAPID_UNMAPPABLE;
			resp->u_res.len = 0;
			goto done;
		}

		/*
		 * idmap_buf is already in the desired form i.e. name@domain
		 */
		gr_str = idmap_buf;
		gr_str_len = strlen(gr_str);
		at_str_len = dom_str_len = 0;
		at_str = "";
		dom_str[0] = '\0';
		goto gen_result;
	}

	/*
	 * Handling non-ephemeral gids
	 *
	 * We want to encode the gid into a literal string... :
	 *
	 *	- upon failure to allocate space from the heap
	 *	- if there is no current domain configured
	 *	- if there is no such gid in the group DB's
	 */
	if ((grp_buf = malloc(grp_buflen)) == NULL || dom_str_len == 0 ||
	    getgrgid_r(gid, &grp, grp_buf, grp_buflen, &grp_ptr) != 0 ||
	    grp_ptr == NULL) {

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
		 * gid encoded string.
		 */
		gr_str = grp_buf;
		(void) sprintf(gr_str, "%u", gid);
		gr_str_len = strlen(gr_str);
		at_str_len = dom_str_len = 0;
		at_str = "";
		dom_str[0] = '\0';
	} else {
		/*
		 * Otherwise, we construct the "group@domain" string if
		 * it's not already in that form.
		 */
		gr_str = grp.gr_name;
		gr_str_len = strlen(gr_str);
		if (strchr(gr_str, '@') == NULL) {
			at_str = "@";
			at_str_len = 1;
		} else {
			at_str_len = dom_str_len = 0;
			at_str = "";
			dom_str[0] = '\0';
		}
	}

gen_result:
	gid_str_len = gr_str_len + at_str_len + dom_str_len;
	if ((resp = alloca(MAPID_RES_LEN(gid_str_len))) == NULL) {
		resp = &result;
		resp->status = NFSMAPID_INTERNAL;
		resp->u_res.len = 0;
		goto done;
	}
	/* LINTED format argument to sprintf */
	(void) sprintf(resp->str, "%s%s%s", gr_str, at_str, dom_str);
	resp->u_res.len = gid_str_len;
	if (grp_buf)
		free(grp_buf);
	if (idmap_buf)
		idmap_free(idmap_buf);
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

/*
 * mapid_get_domain() always returns a ptr to TSD, so the
 * check for a NULL domain is not a simple comparison with
 * NULL but we need to check the contents of the TSD data.
 */
int
cur_domain_null(void)
{
	char	*p;

	if ((p = mapid_get_domain()) == NULL)
		return (1);

	return (p[0] == '\0');
}

int
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

int
valid_domain(const char *dom)
{
	const char	*whoami = "valid_domain";

	if (!mapid_stdchk_domain(dom)) {
		syslog(LOG_ERR, gettext("%s: Invalid inbound domain name %s."),
		    whoami, dom);
		return (0);
	}

	/*
	 * NOTE: mapid_get_domain() returns a ptr to TSD.
	 */
	return (strcasecmp(dom, mapid_get_domain()) == 0);
}

int
validate_id_str(const char *id)
{
	while (*id) {
		if (!isdigit(*id++))
			return (0);
	}
	return (1);
}

void
idmap_kcall(int door_id)
{
	struct nfsidmap_args args;

	if (door_id >= 0) {
		args.state = 1;
		args.did = door_id;
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
check_domain(int sighup)
{
	const char	*whoami = "check_domain";
	static int	 setup_done = 0;
	static cb_t	 cb;

	/*
	 * Construct the arguments to be passed to libmapid interface
	 * If called in response to a SIGHUP, reset any cached DNS TXT
	 * RR state.
	 */
	cb.fcn = cb_update_domain;
	cb.signal = sighup;
	mapid_reeval_domain(&cb);

	/*
	 * Restart the signal handler thread if we're still setting up
	 */
	if (!setup_done) {
		setup_done = 1;
		if (thr_continue(sig_thread)) {
			syslog(LOG_ERR, gettext("%s: Fatal error: signal "
			    "handler thread could not be restarted."), whoami);
			exit(6);
		}
	}
}

/*
 * Need to be able to open the DIAG_FILE before nfsmapid(1m)
 * releases it's root priviledges. The DIAG_FILE then remains
 * open for the duration of this nfsmapid instance via n4_fd.
 */
void
open_diag_file()
{
	static int	msg_done = 0;

	if ((n4_fp = fopen(DIAG_FILE, "w+")) != NULL) {
		n4_fd = fileno(n4_fp);
		return;
	}

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
	char	buf[DNAMEMAX];
	ssize_t	n;
	size_t	len;

	(void) lseek(n4_fd, (off_t)0, SEEK_SET);
	(void) ftruncate(n4_fd, 0);
	(void) snprintf(buf, DNAMEMAX, "%s\n", new);

	len = strlen(buf);
	n = write(n4_fd, buf, len);
	if (n < 0 || n < len)
		syslog(LOG_DEBUG, "Could not write %s to diag file", new);
	(void) fsync(n4_fd);

	syslog(LOG_DEBUG, "nfsmapid domain = %s", new);
}

/*
 * Callback function for libmapid. This will be called
 * by the lib, everytime the nfsmapid(1m) domain changes.
 */
void *
cb_update_domain(void *arg)
{
	char	*new_dname = (char *)arg;

	DTRACE_PROBE1(nfsmapid, daemon__domain, new_dname);
	update_diag_file(new_dname);
	idmap_kcall(FLUSH_KCACHES_ONLY);

	return (NULL);
}
