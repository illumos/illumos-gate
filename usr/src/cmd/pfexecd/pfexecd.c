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
 *
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015, Joyent, Inc.
 */

#define	_POSIX_PTHREAD_SEMANTICS 1

#include <sys/param.h>
#include <sys/klpd.h>
#include <sys/syscall.h>
#include <sys/systeminfo.h>

#include <alloca.h>
#include <ctype.h>
#include <deflt.h>
#include <door.h>
#include <errno.h>
#include <grp.h>
#include <priv.h>
#include <pwd.h>
#include <regex.h>
#include <secdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <auth_attr.h>
#include <exec_attr.h>
#include <prof_attr.h>
#include <user_attr.h>

static int doorfd = -1;

static size_t repsz, setsz;

static uid_t get_uid(const char *, boolean_t *, char *);
static gid_t get_gid(const char *, boolean_t *, char *);
static priv_set_t *get_privset(const char *, boolean_t *, char *);
static priv_set_t *get_granted_privs(uid_t);

/*
 * Remove the isaexec path of an executable if we can't find the
 * executable at the first attempt.
 */

static regex_t regc;
static boolean_t cansplice = B_TRUE;

static void
init_isa_regex(void)
{
	char *isalist;
	size_t isalen = 255;		/* wild guess */
	size_t len;
	long ret;
	char *regexpr;
	char *p;

	/*
	 * Extract the isalist(5) for userland from the kernel.
	 */
	isalist = malloc(isalen);
	do {
		ret = sysinfo(SI_ISALIST, isalist, isalen);
		if (ret == -1l) {
			free(isalist);
			return;
		}
		if (ret > isalen) {
			isalen = ret;
			isalist = realloc(isalist, isalen);
		} else
			break;
	} while (isalist != NULL);


	if (isalist == NULL)
		return;

	/* allocate room for the regex + (/())/[^/]*$ + needed \\. */
#define	LEFT	"(/("
#define	RIGHT	"))/[^/]*$"

	regexpr = alloca(ret * 2 + sizeof (LEFT RIGHT));
	(void) strcpy(regexpr, LEFT);
	len = strlen(regexpr);

	for (p = isalist; *p; p++) {
		switch (*p) {
		case '+':
		case '|':
		case '*':
		case '[':
		case ']':
		case '{':
		case '}':
		case '\\':
			regexpr[len++] = '\\';
			/* FALLTHROUGH */
		default:
			regexpr[len++] = *p;
			break;
		case ' ':
		case '\t':
			regexpr[len++] = '|';
			break;
		}
	}

	free(isalist);
	regexpr[len] = '\0';
	(void) strcat(regexpr, RIGHT);

	if (regcomp(&regc, regexpr, REG_EXTENDED) != 0)
		return;

	cansplice = B_TRUE;
}

#define	NMATCH	2

static boolean_t
removeisapath(char *path)
{
	regmatch_t match[NMATCH];

	if (!cansplice || regexec(&regc, path, NMATCH, match, 0) != 0)
		return (B_FALSE);

	/*
	 * The first match includes the whole matched expression including the
	 * end of the string.  The second match includes the "/" + "isa" and
	 * that is the part we need to remove.
	 */

	if (match[1].rm_so == -1)
		return (B_FALSE);

	/* match[0].rm_eo == strlen(path) */
	(void) memmove(path + match[1].rm_so, path + match[1].rm_eo,
	    match[0].rm_eo - match[1].rm_eo + 1);

	return (B_TRUE);
}

static int
register_pfexec(int fd)
{
	int ret = syscall(SYS_privsys, PRIVSYS_PFEXEC_REG, fd);

	return (ret);
}

/* ARGSUSED */
static void
unregister_pfexec(int sig)
{
	if (doorfd != -1)
		(void) syscall(SYS_privsys, PRIVSYS_PFEXEC_UNREG, doorfd);
	_exit(0);
}

static int
alldigits(const char *s)
{
	int c;

	if (*s == '\0')
		return (0);

	while ((c = *s++) != '\0') {
		if (!isdigit(c)) {
			return (0);
		}
	}

	return (1);
}

static uid_t
get_uid(const char *v, boolean_t *ok, char *path)
{
	struct passwd *pwd, pwdm;
	char buf[1024];

	if (getpwnam_r(v, &pwdm, buf, sizeof (buf), &pwd) == 0 && pwd != NULL)
		return (pwd->pw_uid);

	if (alldigits(v))
		return (atoi(v));

	*ok = B_FALSE;
	syslog(LOG_ERR, "%s: %s: unknown username\n", path, v);
	return ((uid_t)-1);
}

static uid_t
get_gid(const char *v, boolean_t *ok, char *path)
{
	struct group *grp, grpm;
	char buf[1024];

	if (getgrnam_r(v, &grpm, buf, sizeof (buf), &grp) == 0 && grp != NULL)
		return (grp->gr_gid);

	if (alldigits(v))
		return (atoi(v));

	*ok = B_FALSE;
	syslog(LOG_ERR, "%s: %s: unknown groupname\n", path, v);
	return ((gid_t)-1);
}

static priv_set_t *
get_privset(const char *s, boolean_t *ok, char *path)
{
	priv_set_t *res;

	if ((res = priv_str_to_set(s, ",", NULL)) == NULL) {
		syslog(LOG_ERR, "%s: %s: bad privilege set\n", path, s);
		if (ok != NULL)
			*ok = B_FALSE;
	}
	return (res);
}

/*ARGSUSED*/
static int
ggp_callback(const char *prof, kva_t *attr, void *ctxt, void *vres)
{
	priv_set_t *res = vres;
	char *privs;

	if (attr == NULL)
		return (0);

	/* get privs from this profile */
	privs = kva_match(attr, PROFATTR_PRIVS_KW);
	if (privs != NULL) {
		priv_set_t *tmp = priv_str_to_set(privs, ",", NULL);
		if (tmp != NULL) {
			priv_union(tmp, res);
			priv_freeset(tmp);
		}
	}

	return (0);
}

/*
 * This routine exists on failure and returns NULL if no granted privileges
 * are set.
 */
static priv_set_t *
get_granted_privs(uid_t uid)
{
	priv_set_t *res;
	struct passwd *pwd, pwdm;
	char buf[1024];

	if (getpwuid_r(uid, &pwdm, buf, sizeof (buf), &pwd) != 0 || pwd == NULL)
		return (NULL);

	res = priv_allocset();
	if (res == NULL)
		return (NULL);

	priv_emptyset(res);

	(void) _enum_profs(pwd->pw_name, ggp_callback, NULL, res);

	return (res);
}

static void
callback_forced_privs(pfexec_arg_t *pap)
{
	execattr_t *exec;
	char *value;
	priv_set_t *fset;
	void *res = alloca(setsz);

	/* Empty set signifies no forced privileges. */
	priv_emptyset(res);

	exec = getexecprof("Forced Privilege", KV_COMMAND, pap->pfa_path,
	    GET_ONE);

	if (exec == NULL && removeisapath(pap->pfa_path)) {
		exec = getexecprof("Forced Privilege", KV_COMMAND,
		    pap->pfa_path, GET_ONE);
	}

	if (exec == NULL) {
		(void) door_return(res, setsz, NULL, 0);
		return;
	}

	if ((value = kva_match(exec->attr, EXECATTR_IPRIV_KW)) == NULL ||
	    (fset = get_privset(value, NULL, pap->pfa_path)) == NULL) {
		free_execattr(exec);
		(void) door_return(res, setsz, NULL, 0);
		return;
	}

	priv_copyset(fset, res);
	priv_freeset(fset);

	free_execattr(exec);
	(void) door_return(res, setsz, NULL, 0);
}

static void
callback_user_privs(pfexec_arg_t *pap)
{
	priv_set_t *gset, *wset;
	uint32_t res;

	wset = (priv_set_t *)&pap->pfa_buf;
	gset = get_granted_privs(pap->pfa_uid);

	res = priv_issubset(wset, gset);
	priv_freeset(gset);

	(void) door_return((char *)&res, sizeof (res), NULL, 0);
}

static void
callback_pfexec(pfexec_arg_t *pap)
{
	pfexec_reply_t *res = alloca(repsz);
	uid_t uid, euid, uuid;
	gid_t gid, egid;
	struct passwd pw, *pwd;
	char buf[1024];
	execattr_t *exec = NULL;
	char *value;
	priv_set_t *lset, *iset;
	size_t mysz = repsz - 2 * setsz;
	char *path = pap->pfa_path;

	/*
	 * Initialize the pfexec_reply_t to a sane state.
	 */
	res->pfr_vers = pap->pfa_vers;
	res->pfr_len = 0;
	res->pfr_ruid = PFEXEC_NOTSET;
	res->pfr_euid = PFEXEC_NOTSET;
	res->pfr_rgid = PFEXEC_NOTSET;
	res->pfr_egid = PFEXEC_NOTSET;
	res->pfr_setcred = B_FALSE;
	res->pfr_scrubenv = B_TRUE;
	res->pfr_allowed = B_FALSE;
	res->pfr_ioff = 0;
	res->pfr_loff = 0;

	uuid = pap->pfa_uid;

	if (getpwuid_r(uuid, &pw, buf, sizeof (buf), &pwd) != 0 || pwd == NULL)
		goto stdexec;

	exec = getexecuser(pwd->pw_name, KV_COMMAND, path, GET_ONE);

	if ((exec == NULL || exec->attr == NULL) && removeisapath(path)) {
		free_execattr(exec);
		exec = getexecuser(pwd->pw_name, KV_COMMAND, path, GET_ONE);
	}

	if (exec == NULL) {
		res->pfr_allowed = B_FALSE;
		goto ret;
	}

	if (exec->attr == NULL)
		goto stdexec;

	/* Found in execattr, so clearly we can use it */
	res->pfr_allowed = B_TRUE;

	uid = euid = (uid_t)-1;
	gid = egid = (gid_t)-1;
	lset = iset = NULL;

	/*
	 * If there's an error in parsing uid, gid, privs, then return
	 * failure.
	 */
	if ((value = kva_match(exec->attr, EXECATTR_UID_KW)) != NULL)
		euid = uid = get_uid(value, &res->pfr_allowed, path);

	if ((value = kva_match(exec->attr, EXECATTR_GID_KW)) != NULL)
		egid = gid = get_gid(value, &res->pfr_allowed, path);

	if ((value = kva_match(exec->attr, EXECATTR_EUID_KW)) != NULL)
		euid = get_uid(value, &res->pfr_allowed, path);

	if ((value = kva_match(exec->attr, EXECATTR_EGID_KW)) != NULL)
		egid = get_gid(value, &res->pfr_allowed, path);

	if ((value = kva_match(exec->attr, EXECATTR_LPRIV_KW)) != NULL)
		lset = get_privset(value, &res->pfr_allowed, path);

	if ((value = kva_match(exec->attr, EXECATTR_IPRIV_KW)) != NULL)
		iset = get_privset(value, &res->pfr_allowed, path);

	/*
	 * Remove LD_* variables in the kernel when the runtime linker might
	 * use them later on because the uids are equal.
	 */
	res->pfr_scrubenv = (uid != (uid_t)-1 && euid == uid) ||
	    (gid != (gid_t)-1 && egid == gid) || iset != NULL;

	res->pfr_euid = euid;
	res->pfr_ruid = uid;
	res->pfr_egid = egid;
	res->pfr_rgid = gid;

	/* Now add the privilege sets */
	res->pfr_ioff = res->pfr_loff = 0;
	if (iset != NULL) {
		res->pfr_ioff = mysz;
		priv_copyset(iset, PFEXEC_REPLY_IPRIV(res));
		mysz += setsz;
		priv_freeset(iset);
	}
	if (lset != NULL) {
		res->pfr_loff = mysz;
		priv_copyset(lset, PFEXEC_REPLY_LPRIV(res));
		mysz += setsz;
		priv_freeset(lset);
	}

	res->pfr_setcred = uid != (uid_t)-1 || euid != (uid_t)-1 ||
	    egid != (gid_t)-1 || gid != (gid_t)-1 || iset != NULL ||
	    lset != NULL;

	/* If the real uid changes, we stop running under a profile shell */
	res->pfr_clearflag = uid != (uid_t)-1 && uid != uuid;
	free_execattr(exec);
ret:
	(void) door_return((char *)res, mysz, NULL, 0);
	return;

stdexec:
	free_execattr(exec);

	res->pfr_scrubenv = B_FALSE;
	res->pfr_setcred = B_FALSE;
	res->pfr_allowed = B_TRUE;

	(void) door_return((char *)res, mysz, NULL, 0);
}

/* ARGSUSED */
static void
callback(void *cookie, char *argp, size_t asz, door_desc_t *dp, uint_t ndesc)
{
	/* LINTED ALIGNMENT */
	pfexec_arg_t *pap = (pfexec_arg_t *)argp;

	if (asz < sizeof (pfexec_arg_t) || pap->pfa_vers != PFEXEC_ARG_VERS) {
		(void) door_return(NULL, 0, NULL, 0);
		return;
	}

	switch (pap->pfa_call) {
	case PFEXEC_EXEC_ATTRS:
		callback_pfexec(pap);
		break;
	case PFEXEC_FORCED_PRIVS:
		callback_forced_privs(pap);
		break;
	case PFEXEC_USER_PRIVS:
		callback_user_privs(pap);
		break;
	default:
		syslog(LOG_ERR, "Bad Call: %d\n", pap->pfa_call);
		break;
	}

	/*
	 * If the door_return(ptr, size, NULL, 0) fails, make sure we
	 * don't lose server threads.
	 */
	(void) door_return(NULL, 0, NULL, 0);
}

int
main(void)
{
	const priv_impl_info_t *info;

	(void) signal(SIGINT, unregister_pfexec);
	(void) signal(SIGQUIT, unregister_pfexec);
	(void) signal(SIGTERM, unregister_pfexec);
	(void) signal(SIGHUP, unregister_pfexec);

	info = getprivimplinfo();
	if (info == NULL)
		exit(1);

	if (fork() > 0)
		_exit(0);

	openlog("pfexecd", LOG_PID, LOG_DAEMON);
	setsz = info->priv_setsize * sizeof (priv_chunk_t);
	repsz = 2 * setsz + sizeof (pfexec_reply_t);

	init_isa_regex();

	doorfd = door_create(callback, NULL, DOOR_REFUSE_DESC);

	if (doorfd == -1 || register_pfexec(doorfd) != 0) {
		perror("doorfd");
		exit(1);
	}

	/* LINTED CONSTCOND */
	while (1)
		(void) sigpause(SIGINT);

	return (0);
}
