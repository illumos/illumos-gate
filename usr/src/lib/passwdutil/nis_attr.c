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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <pwd.h>
#include <unistd.h>
#include <syslog.h>

#include <netdb.h>

#include <rpc/rpc.h>
#include <rpcsvc/yppasswd.h>
#include <rpcsvc/ypclnt.h>
#include <rpcsvc/yp_prot.h>

#include "passwdutil.h"

int nis_getattr(const char *name, attrlist *item, pwu_repository_t *rep);
int nis_getpwnam(const char *name, attrlist *items, pwu_repository_t *rep,
    void **buf);
int nis_update(attrlist *items, pwu_repository_t *rep, void *buf);
int nis_putpwnam(const char *name, const char *oldpw, pwu_repository_t *rep,
    void *buf);
int nis_user_to_authenticate(const char *user, pwu_repository_t *rep,
	char **auth_user, int *privileged);

/*
 * nis function pointer table, used by passwdutil_init to initialize
 * the global Repository-OPerations table "rops"
 */
struct repops nis_repops = {
	NULL,	/* checkhistory */
	nis_getattr,
	nis_getpwnam,
	nis_update,
	nis_putpwnam,
	nis_user_to_authenticate,
	NULL,	/* lock */
	NULL	/* unlock */
};

/*
 * structure used to keep state between get/update/put calls
 */
typedef struct {
	char *domain;
	char *master;
	char *scratch;
	int scratchlen;
	char *c2scratch;
	int c2scratchlen;
	struct passwd *pwd;
} nisbuf_t;

/*
 * Are we a 'privileged' process? Yes if we are running on the
 * NIS server AND we are root...
 */
int
nis_privileged(nisbuf_t *nisbuf)
{
	char thishost[MAXHOSTNAMELEN];
	if (gethostname(thishost, sizeof (thishost)) == -1) {
		syslog(LOG_ERR, "passwdutil.so: Can't get hostname");
		return (0);
	}

	if (strcmp(nisbuf->master, thishost) != 0)
		return (0);

	/* We're running on the NIS server. */
	return (getuid() == 0);
}

/*
 * nis_to_pwd()
 *
 * convert password-entry-line to "struct passwd"
 */
void
nis_to_pwd(char *nis, struct passwd *pwd)
{
	pwd->pw_name = strsep(&nis, ":");
	pwd->pw_passwd = strsep(&nis, ":");
	pwd->pw_uid = atoi(strsep(&nis, ":"));
	pwd->pw_gid = atoi(strsep(&nis, ":"));
	pwd->pw_gecos = strsep(&nis, ":");
	pwd->pw_dir = strsep(&nis, ":");
	pwd->pw_shell = nis;
	if (pwd->pw_shell[0])
		pwd->pw_shell[strlen(pwd->pw_shell)-1] = '\0';
}

/*
 * nis_user_to_authenticate(name, rep, auth_user, privileged)
 *
 */
/*ARGSUSED*/
int
nis_user_to_authenticate(const char *user, pwu_repository_t *rep,
	char **auth_user, int *privileged)
{
	nisbuf_t *buf = NULL;
	int res;
	attrlist attr_tmp[1];
	uid_t uid;

	/*
	 * special NIS case: don't bother to get "root" from NIS
	 */
	if (strcmp(user, "root") == 0)
		return (PWU_NOT_FOUND);

	attr_tmp[0].type = ATTR_UID;
	attr_tmp[0].next = NULL;

	res = nis_getpwnam(user, &attr_tmp[0], rep, (void **)&buf);

	if (res != PWU_SUCCESS)
		return (res);

	if (nis_privileged(buf)) {
		*privileged = 1;
		*auth_user = NULL;
		res = PWU_SUCCESS;
	} else {
		uid = getuid();

		*privileged = (uid == (uid_t)0);

		/* root, or user herself can change attributes */
		if (uid == 0 || uid == buf->pwd->pw_uid) {
			*auth_user = strdup(user);
			res = PWU_SUCCESS;
		} else {
			res = PWU_DENIED;
		}
	}

	/*
	 * Do not release buf->domain.
	 * It's been set by yp_get_default_domain()
	 * and must not be freed.
	 * See man page yp_get_default_domain(3NSL)
	 * for details.
	 */
	if (buf->master)
		free(buf->master);
	if (buf->scratch)
		free(buf->scratch);
	if (buf->c2scratch)
		free(buf->c2scratch);
	free(buf->pwd);
	free(buf);

	return (res);
}


/*
 * nis_getattr(name, items, rep)
 *
 * get account attributes specified in 'items'
 */
int
nis_getattr(const char *name, attrlist *items, pwu_repository_t *rep)
{
	nisbuf_t *nisbuf = NULL;
	struct passwd *pw;
	attrlist *w;
	int res;

	res = nis_getpwnam(name, items, rep, (void **)&nisbuf);
	if (res != PWU_SUCCESS)
		return (res);

	pw = nisbuf->pwd;

	for (w = items; w != NULL; w = w->next) {
		switch (w->type) {
		case ATTR_NAME:
			if ((w->data.val_s = strdup(pw->pw_name)) == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_COMMENT:
			if ((w->data.val_s = strdup(pw->pw_comment)) == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_GECOS:
			if ((w->data.val_s = strdup(pw->pw_gecos)) == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_HOMEDIR:
			if ((w->data.val_s = strdup(pw->pw_dir)) == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_SHELL:
			if ((w->data.val_s = strdup(pw->pw_shell)) == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_PASSWD:
		case ATTR_PASSWD_SERVER_POLICY:
			if ((w->data.val_s = strdup(pw->pw_passwd)) == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_REP_NAME:
			if ((w->data.val_s = strdup("nis")) == NULL)
				res = PWU_NOMEM;
			break;

		/* integer values */
		case ATTR_UID:
			w->data.val_i = nisbuf->pwd->pw_uid;
			break;
		case ATTR_GID:
			w->data.val_i = nisbuf->pwd->pw_gid;
			break;
		case ATTR_LSTCHG:
		case ATTR_MIN:
		case ATTR_MAX:
		case ATTR_WARN:
		case ATTR_INACT:
		case ATTR_EXPIRE:
		case ATTR_FLAG:
		case ATTR_AGE:
			w->data.val_i = -1;	/* not used for NIS */
			break;
		default:
			break;
		}
	}

	/*
	 * Do not release nisbuf->domain.
	 * It's been set by yp_get_default_domain()
	 * and must not be freed.
	 * See man page yp_get_default_domain(3NSL)
	 * for details.
	 */
	if (nisbuf->master)
		free(nisbuf->master);
	if (nisbuf->scratch)
		free(nisbuf->scratch);
	if (nisbuf->c2scratch)
		free(nisbuf->c2scratch);
	free(nisbuf->pwd);
	free(nisbuf);

	return (res);
}

/*
 * nis_getpwnam(name, items, rep)
 *
 * Get the account information of user 'name'
 */
/*ARGSUSED*/
int
nis_getpwnam(const char *name, attrlist *items, pwu_repository_t *rep,
    void **buf)
{
	nisbuf_t *nisbuf;
	int nisresult;
	char *ncname;

	nisbuf = calloc(sizeof (*nisbuf), 1);
	if (nisbuf == NULL)
		return (PWU_NOMEM);

	nisbuf->pwd = malloc(sizeof (struct passwd));
	if (nisbuf->pwd == NULL) {
		free(nisbuf);
		return (PWU_NOMEM);
	}

	/*
	 * Do not release nisbuf->domain.
	 * It is going to be set by yp_get_default_domain()
	 * and must not be freed.
	 * See man page yp_get_default_domain(3NSL)
	 * for details.
	 */
	if (yp_get_default_domain(&nisbuf->domain) != 0) {
		syslog(LOG_ERR, "passwdutil.so: can't get domain");
		free(nisbuf->pwd);
		free(nisbuf);
		return (PWU_SERVER_ERROR);
	}

	if (yp_master(nisbuf->domain, "passwd.byname", &nisbuf->master) != 0) {
		syslog(LOG_ERR,
		    "passwdutil.so: can't get master for passwd map");
		free(nisbuf->master);
		free(nisbuf->pwd);
		free(nisbuf);
		return (PWU_SERVER_ERROR);
	}

	ncname = strdup(name);
	if (ncname == NULL) {
		free(nisbuf->master);
		free(nisbuf->pwd);
		free(nisbuf);
		return (PWU_NOMEM);
	}

	nisresult = yp_match(nisbuf->domain, "passwd.byname", ncname,
	    strlen(ncname), &(nisbuf->scratch),
	    &(nisbuf->scratchlen));
	free(ncname);
	if (nisresult != 0) {
		free(nisbuf->pwd);
		free(nisbuf->scratch);
		free(nisbuf->master);
		free(nisbuf);
		return (PWU_NOT_FOUND);
	}

	nis_to_pwd(nisbuf->scratch, nisbuf->pwd);

	/*
	 * check for the C2 security flag "##" in the passwd field.
	 * If the first 2 chars in the passwd field is "##", get
	 * the user's passwd from passwd.adjunct.byname map.
	 * The lookup to this passwd.adjunct.byname map will only
	 * succeed if the caller's uid is 0 because only root user
	 * can use privilege port.
	 */
	if (nisbuf->pwd->pw_passwd[0] == '#' &&
	    nisbuf->pwd->pw_passwd[1] == '#') {
		char *key = &nisbuf->pwd->pw_passwd[2];
		int keylen;
		char *p;

		keylen = strlen(key);

		nisresult = yp_match(nisbuf->domain, "passwd.adjunct.byname",
		    key, keylen, &(nisbuf->c2scratch),
		    &(nisbuf->c2scratchlen));

		if (nisresult == 0 && nisbuf->c2scratch != NULL) {
			/* Skip username (first field), and pick up password */
			p = nisbuf->c2scratch;
			(void) strsep(&p, ":");
			nisbuf->pwd->pw_passwd = strsep(&p, ":");
		}
	}

	*buf = (void *)nisbuf;

	return (PWU_SUCCESS);
}

/*
 * nis_update(items, rep, buf)
 *
 * update the information in "buf" with the attribute/values
 * specified in "items".
 */
/*ARGSUSED*/
int
nis_update(attrlist *items, pwu_repository_t *rep, void *buf)
{
	attrlist *p;
	nisbuf_t *nisbuf = (nisbuf_t *)buf;
	char *salt;

	for (p = items; p != NULL; p = p->next) {
		switch (p->type) {
		case ATTR_NAME:
			break;
		/*
		 * Nothing special needs to be done for
		 * server policy
		 */
		case ATTR_PASSWD:
		case ATTR_PASSWD_SERVER_POLICY:
			salt = crypt_gensalt(
			    nisbuf->pwd->pw_passwd, nisbuf->pwd);

			if (salt == NULL) {
				if (errno == ENOMEM)
					return (PWU_NOMEM);
				else {
					/* algorithm problem? */
					syslog(LOG_AUTH | LOG_ALERT,
					    "passwdutil: crypt_gensalt "
					    "%m");
					return (PWU_UPDATE_FAILED);
				}
			}
			nisbuf->pwd->pw_passwd = crypt(p->data.val_s, salt);
			free(salt);
			break;
		case ATTR_UID:
			nisbuf->pwd->pw_uid = (uid_t)p->data.val_i;
			break;
		case ATTR_GID:
			nisbuf->pwd->pw_gid = (gid_t)p->data.val_i;
			break;
		case ATTR_AGE:
			nisbuf->pwd->pw_age = p->data.val_s;
			break;
		case ATTR_COMMENT:
			nisbuf->pwd->pw_comment = p->data.val_s;
			break;
		case ATTR_GECOS:
			nisbuf->pwd->pw_gecos = p->data.val_s;
			break;
		case ATTR_HOMEDIR:
			nisbuf->pwd->pw_dir = p->data.val_s;
			break;
		case ATTR_SHELL:
			nisbuf->pwd->pw_shell = p->data.val_s;
			break;
		case ATTR_LSTCHG:
		case ATTR_MIN:
		case ATTR_MAX:
		case ATTR_WARN:
		case ATTR_INACT:
		case ATTR_EXPIRE:
		case ATTR_FLAG:
		default:
			break;
		}
	}
	return (PWU_SUCCESS);
}

/*
 * nis_putpwnam(name, oldpw, rep, buf)
 *
 * Update the NIS server. The passwd structure in buf will be sent to
 * the server for user "name" authenticating with password "oldpw".
 */
/*ARGSUSED*/
int
nis_putpwnam(const char *name, const char *oldpw, pwu_repository_t *rep,
	void *buf)
{
	nisbuf_t *nisbuf = (nisbuf_t *)buf;
	struct yppasswd yppasswd;
	struct netconfig *nconf;
	int ok;
	enum clnt_stat ans;
	CLIENT *client;
	struct timeval timeout;
	char *oldpass;

	if (strcmp(name, "root") == 0)
		return (PWU_NOT_FOUND);

	oldpass = yppasswd.oldpass = strdup(oldpw != NULL ? oldpw : "");
	if (oldpass == NULL)
		return (PWU_NOMEM);
	yppasswd.newpw = *nisbuf->pwd;

	/*
	 * If we are privileged, we create a ticlts connection to the
	 * NIS server so that it can check our credentials
	 */
	if (nis_privileged(nisbuf)) {
		nconf = getnetconfigent("ticlts");
		if (!nconf) {
			free(oldpass);
			syslog(LOG_ERR,
			    "passwdutil.so: Couldn't get netconfig entry");
			return (PWU_SYSTEM_ERROR);
		}
		client = clnt_tp_create(nisbuf->master, YPPASSWDPROG,
		    YPPASSWDVERS, nconf);
		freenetconfigent(nconf);
	} else {
		/* Try IPv6 first */
		client = clnt_create(nisbuf->master, YPPASSWDPROG,
		    YPPASSWDVERS, "udp6");
		if (client == NULL)
			client = clnt_create(nisbuf->master, YPPASSWDPROG,
			    YPPASSWDVERS, "udp");
	}

	if (client == NULL) {
		free(oldpass);
		syslog(LOG_ERR,
		    "passwdutil.so: couldn't create client to YP master");
		return (PWU_SERVER_ERROR);
	}

	timeout.tv_usec = 0;
	timeout.tv_sec = 55;	/* ndp uses 55 seconds */

	ans = CLNT_CALL(client, YPPASSWDPROC_UPDATE, xdr_yppasswd,
	    (char *)&yppasswd, xdr_int, (char *)&ok, timeout);

	free(oldpass);
	free(nisbuf->pwd);
	free(nisbuf->master);
	free(nisbuf->scratch);
	free(nisbuf->c2scratch);

	(void) clnt_destroy(client);

	if (ans != RPC_SUCCESS) {
		return (PWU_UPDATE_FAILED);
	}

	/* These errors are obtained from the yppasswdd.c code */
	switch (ok) {
		case 2: return (PWU_DENIED);
		case 8: return (PWU_BUSY);
		case 9: return (PWU_SERVER_ERROR);
		case 4: return (PWU_NOT_FOUND);
		case 3: return (PWU_NO_CHANGE);
		case 7: return (PWU_DENIED);
		case 0: return (PWU_SUCCESS);
		default: return (PWU_SYSTEM_ERROR);
	}
}
