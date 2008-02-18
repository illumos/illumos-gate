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
#include <unistd.h>
#include <limits.h>
#include <strings.h>
#include <synch.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <thread.h>
#include <pwd.h>
#include <dlfcn.h>
#include <link.h>
#include <smbsrv/libsmb.h>

#define	SMB_PASSWD	"/var/smb/smbpasswd"
#define	SMB_OPASSWD	"/var/smb/osmbpasswd"
#define	SMB_PASSTEMP	"/var/smb/ptmp"
#define	SMB_PASSLCK	"/var/smb/.pwd.lock"
#define	SMB_LIBPALT	"/usr/lib/smbsrv"
#define	SMB_LIBNALT	"libsmb_pwd.so"
#define	SMB_LIB_ALT	SMB_LIBPALT "/" SMB_LIBNALT

#define	SMB_PWD_DISABLE	"*DIS*"
#define	SMB_PWD_BUFSIZE 256

#define	S_WAITTIME	15

typedef enum {
	SMB_PWD_NAME = 0,
	SMB_PWD_UID,
	SMB_PWD_LMHASH,
	SMB_PWD_NTHASH,
	SMB_PWD_NARG
} smb_pwdarg_t;

static struct flock flock =	{
			0,	/* l_type */
			0,	/* l_whence */
			0,	/* l_start */
			0,	/* l_len */
			0,	/* l_sysid */
			0	/* l_pid */
			};

static pid_t lck_pid = 0;	/* process's pid at last lock */
static thread_t lck_tid = 0;	/* thread that holds the lock */
static int fildes = -1;
static mutex_t lck_lock = DEFAULTMUTEX;
static void *smb_pwd_hdl = NULL;

typedef struct smb_pwbuf {
	char *pw_name;
	smb_passwd_t *pw_pwd;
} smb_pwbuf_t;

static struct {
	smb_passwd_t *(*smb_pwd_getpasswd)(const char *name,
						smb_passwd_t *smbpw);
	int (*smb_pwd_setcntl)(const char *name, int control);
	int (*smb_pwd_setpasswd)(const char *name, const char *password);
} smb_pwd_ops;

static int smb_pwd_lock(void);
static int smb_pwd_unlock(void);
static int smb_pwd_flck(void);
static int smb_pwd_fulck(void);

static smb_pwbuf_t *smb_pwd_fgetent(FILE *, smb_pwbuf_t *, char *, size_t);
static int smb_pwd_fputent(FILE *, smb_pwbuf_t *);
static int smb_pwd_chgpwent(smb_passwd_t *, const char *, int);
static int smb_pwd_update(const char *, const char *, int);

void
smb_pwd_init(void)
{
	smb_pwd_hdl = dlopen(SMB_LIB_ALT, RTLD_NOW | RTLD_LOCAL);

	if (smb_pwd_hdl == NULL)
		return; /* interposition library not found */

	bzero((void *)&smb_pwd_ops, sizeof (smb_pwd_ops));

	smb_pwd_ops.smb_pwd_getpasswd =
	    (smb_passwd_t *(*)())dlsym(smb_pwd_hdl, "smb_pwd_getpasswd");

	smb_pwd_ops.smb_pwd_setcntl =
	    (int (*)())dlsym(smb_pwd_hdl, "smb_pwd_setcntl");

	smb_pwd_ops.smb_pwd_setpasswd =
	    (int (*)())dlsym(smb_pwd_hdl, "smb_pwd_setpasswd");

	if (smb_pwd_ops.smb_pwd_getpasswd == NULL ||
	    smb_pwd_ops.smb_pwd_setcntl == NULL ||
	    smb_pwd_ops.smb_pwd_setpasswd == NULL) {
		(void) dlclose(smb_pwd_hdl);
		smb_pwd_hdl = NULL;

		/* If error or function(s) are missing, use original lib */
		bzero((void *)&smb_pwd_ops, sizeof (smb_pwd_ops));
	}
}

void
smb_pwd_fini(void)
{
	if (smb_pwd_hdl) {
		(void) dlclose(smb_pwd_hdl);
		smb_pwd_hdl = NULL;
	}
}

/*
 * smb_pwd_get
 *
 * Returns a smb password structure for the given user name.
 * smbpw is a pointer to a buffer allocated by the caller.
 *
 * Returns NULL upon failure.
 */
smb_passwd_t *
smb_pwd_getpasswd(const char *name, smb_passwd_t *smbpw)
{
	char buf[SMB_PWD_BUFSIZE];
	boolean_t found = B_FALSE;
	smb_pwbuf_t pwbuf;
	int err;
	FILE *fp;

	if (smb_pwd_ops.smb_pwd_getpasswd != NULL)
		return (smb_pwd_ops.smb_pwd_getpasswd(name, smbpw));

	err = smb_pwd_lock();
	if (err != SMB_PWE_SUCCESS)
		return (NULL);

	if ((fp = fopen(SMB_PASSWD, "rF")) == NULL) {
		(void) smb_pwd_unlock();
		return (NULL);
	}

	pwbuf.pw_name = NULL;
	pwbuf.pw_pwd = smbpw;

	while (smb_pwd_fgetent(fp, &pwbuf, buf, sizeof (buf)) != NULL) {
		if (strcmp(name, pwbuf.pw_name) == 0) {
			if ((smbpw->pw_flags & (SMB_PWF_LM | SMB_PWF_NT)))
				found = B_TRUE;
			break;
		}
	}

	(void) fclose(fp);
	(void) smb_pwd_unlock();

	if (!found) {
		bzero(smbpw, sizeof (smb_passwd_t));
		return (NULL);
	}

	return (smbpw);
}

/*
 * smb_pwd_set
 *
 * Update/add the given user to the smbpasswd file.
 */
int
smb_pwd_setpasswd(const char *name, const char *password)
{
	if (smb_pwd_ops.smb_pwd_setpasswd != NULL)
		return (smb_pwd_ops.smb_pwd_setpasswd(name, password));

	return (smb_pwd_update(name, password, 0));
}

/*
 * smb_pwd_setcntl
 *
 * Change the account state. This can be making the account
 * disable/enable or removing its LM hash.
 */
int
smb_pwd_setcntl(const char *name, int control)
{
	if (smb_pwd_ops.smb_pwd_setcntl != NULL)
		return (smb_pwd_ops.smb_pwd_setcntl(name, control));

	if (control == 0)
		return (SMB_PWE_SUCCESS);

	return (smb_pwd_update(name, NULL, control));
}

static int
smb_pwd_update(const char *name, const char *password, int control)
{
	struct stat64 stbuf;
	FILE *src, *dst;
	int tempfd;
	char buf[SMB_PWD_BUFSIZE];
	int err = SMB_PWE_SUCCESS;
	smb_pwbuf_t pwbuf;
	smb_passwd_t smbpw;
	boolean_t newent = B_TRUE;
	boolean_t user_disable = B_FALSE;
	char uxbuf[1024];
	struct passwd uxpw;
	int64_t lm_level;

	err = smb_pwd_lock();
	if (err != SMB_PWE_SUCCESS)
		return (err);

	if (stat64(SMB_PASSWD, &stbuf) < 0) {
		err = SMB_PWE_STAT_FAILED;
		goto passwd_exit;
	}

	if ((tempfd = open(SMB_PASSTEMP, O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0) {
		err = SMB_PWE_OPEN_FAILED;
		goto passwd_exit;
	}

	if ((dst = fdopen(tempfd, "wF")) == NULL) {
		err = SMB_PWE_OPEN_FAILED;
		goto passwd_exit;
	}

	if ((src = fopen(SMB_PASSWD, "rF")) == NULL) {
		err = SMB_PWE_OPEN_FAILED;
		(void) fclose(dst);
		(void) unlink(SMB_PASSTEMP);
		goto passwd_exit;
	}

	if (smb_config_getnum(SMB_CI_LM_LEVEL, &lm_level) != SMBD_SMF_OK)
		lm_level = 4;

	if (lm_level >= 4)
		control |= SMB_PWC_NOLM;

	/*
	 * copy old password entries to temporary file while replacing
	 * the entry that matches "name"
	 */
	pwbuf.pw_name = NULL;
	pwbuf.pw_pwd = &smbpw;

	while (smb_pwd_fgetent(src, &pwbuf, buf, sizeof (buf)) != NULL) {
		if (strcmp(pwbuf.pw_name, name) == 0) {
			err = smb_pwd_chgpwent(&smbpw, password, control);
			if (err == SMB_PWE_USER_DISABLE)
				user_disable = B_TRUE;
			err = smb_pwd_fputent(dst, &pwbuf);
			newent = B_FALSE;
		} else {
			err = smb_pwd_fputent(dst, &pwbuf);
		}

		if (err != SMB_PWE_SUCCESS) {
			(void) fclose(src);
			(void) fclose(dst);
			goto passwd_exit;
		}
	}

	if (newent) {
		if (getpwnam_r(name, &uxpw, uxbuf, sizeof (uxbuf))) {
			pwbuf.pw_name = uxpw.pw_name;
			smbpw.pw_flags = 0;
			smbpw.pw_uid = uxpw.pw_uid;
			(void) smb_pwd_chgpwent(&smbpw, password, control);
			err = smb_pwd_fputent(dst, &pwbuf);
		} else {
			err = SMB_PWE_USER_UNKNOWN;
		}

		if (err != SMB_PWE_SUCCESS) {
			(void) fclose(src);
			(void) fclose(dst);
			goto passwd_exit;
		}
	}

	(void) fclose(src);
	if (fclose(dst) != 0) {
		err = SMB_PWE_CLOSE_FAILED;
		goto passwd_exit; /* Don't trust the temporary file */
	}

	/* Rename temp to passwd */
	if (unlink(SMB_OPASSWD) && access(SMB_OPASSWD, 0) == 0) {
		err = SMB_PWE_UPDATE_FAILED;
		(void) unlink(SMB_PASSTEMP);
		goto passwd_exit;
	}

	if (link(SMB_PASSWD, SMB_OPASSWD) == -1) {
		err = SMB_PWE_UPDATE_FAILED;
		(void) unlink(SMB_PASSTEMP);
		goto passwd_exit;
	}

	if (rename(SMB_PASSTEMP, SMB_PASSWD) == -1) {
		err = SMB_PWE_UPDATE_FAILED;
		(void) unlink(SMB_PASSTEMP);
		goto passwd_exit;
	}

	(void) chmod(SMB_PASSWD, 0400);

passwd_exit:
	(void) smb_pwd_unlock();
	if ((err == SMB_PWE_SUCCESS) && user_disable)
		err = SMB_PWE_USER_DISABLE;

	return (err);
}

/*
 * smb_getpwent
 *
 * Parse the buffer in the passed pwbuf and fill in the
 * smb password structure to point to the parsed information.
 * The entry format is:
 *
 *	<user-name>:<user-id>:<LM hash>:<NTLM hash>
 *
 * Returns a pointer to the password structure on success,
 * otherwise returns NULL.
 */
static smb_pwbuf_t *
smb_pwd_fgetent(FILE *fp, smb_pwbuf_t *pwbuf, char *buf, size_t bufsize)
{
	char *argv[SMB_PWD_NARG];
	smb_passwd_t *pw;
	smb_pwdarg_t i;
	int lm_len, nt_len;

	if (fgets(buf, bufsize, fp) == NULL)
		return (NULL);
	(void) trim_whitespace(buf);

	for (i = 0; i < SMB_PWD_NARG; ++i) {
		if ((argv[i] = strsep((char **)&buf, ":")) == 0) {
			return (NULL);
		}
	}

	if ((*argv[SMB_PWD_NAME] == '\0') || (*argv[SMB_PWD_UID] == '\0'))
		return (NULL);

	pwbuf->pw_name = argv[SMB_PWD_NAME];
	pw = pwbuf->pw_pwd;
	bzero(pw, sizeof (smb_passwd_t));
	pw->pw_uid = strtoul(argv[SMB_PWD_UID], 0, 10);

	if (strcmp(argv[SMB_PWD_LMHASH], SMB_PWD_DISABLE) == 0) {
		pw->pw_flags |= SMB_PWF_DISABLE;
		(void) strcpy((char *)pw->pw_lmhash, SMB_PWD_DISABLE);
		(void) strcpy((char *)pw->pw_nthash, SMB_PWD_DISABLE);
		return (pwbuf);
	}

	lm_len = strlen(argv[SMB_PWD_LMHASH]);
	if (lm_len == SMBAUTH_HEXHASH_SZ) {
		(void) hextobin(argv[SMB_PWD_LMHASH], SMBAUTH_HEXHASH_SZ,
		    (char *)pw->pw_lmhash, SMBAUTH_HASH_SZ);

		pw->pw_flags |= SMB_PWF_LM;
	} else if (lm_len != 0) {
		return (NULL);
	}

	nt_len = strlen(argv[SMB_PWD_NTHASH]);
	if (nt_len == SMBAUTH_HEXHASH_SZ) {
		(void) hextobin(argv[SMB_PWD_NTHASH], SMBAUTH_HEXHASH_SZ,
		    (char *)pw->pw_nthash, SMBAUTH_HASH_SZ);

		pw->pw_flags |= SMB_PWF_NT;
	} else if (nt_len != 0) {
		return (NULL);
	}

	return (pwbuf);
}

static int
smb_pwd_chgpwent(smb_passwd_t *smbpw, const char *password, int control)
{
	if (control & SMB_PWC_DISABLE) {
		smbpw->pw_flags |= SMB_PWF_DISABLE;
		(void) strcpy((char *)smbpw->pw_lmhash, SMB_PWD_DISABLE);
		(void) strcpy((char *)smbpw->pw_nthash, SMB_PWD_DISABLE);
		smbpw->pw_flags &= ~(SMB_PWF_LM | SMB_PWF_NT);
		return (SMB_PWE_SUCCESS);
	} else if ((control & SMB_PWC_ENABLE) &&
	    (smbpw->pw_flags & SMB_PWF_DISABLE)) {
		*smbpw->pw_lmhash = '\0';
		*smbpw->pw_nthash = '\0';
		smbpw->pw_flags &= ~(SMB_PWF_LM | SMB_PWF_NT);
		return (SMB_PWE_SUCCESS);
	}

	/* No password update if account is disabled */
	if (smbpw->pw_flags & SMB_PWF_DISABLE)
		return (SMB_PWE_USER_DISABLE);

	if (control & SMB_PWC_NOLM) {
		smbpw->pw_flags &= ~SMB_PWF_LM;
		*smbpw->pw_lmhash = '\0';
	} else {
		smbpw->pw_flags |= SMB_PWF_LM;
		(void) smb_auth_lm_hash((char *)password, smbpw->pw_lmhash);
	}

	smbpw->pw_flags |= SMB_PWF_NT;
	(void) smb_auth_ntlm_hash((char *)password, smbpw->pw_nthash);
	return (SMB_PWE_SUCCESS);
}

/*
 * smb_putpwent
 *
 * Creates LM and NTLM hash from the given plain text password
 * and write them along with user's name and Id to the smbpasswd
 * file.
 */
static int
smb_pwd_fputent(FILE *fp, smb_pwbuf_t *pwbuf)
{
	smb_passwd_t *pw = pwbuf->pw_pwd;
	char hex_nthash[SMBAUTH_HEXHASH_SZ+1];
	char hex_lmhash[SMBAUTH_HEXHASH_SZ+1];
	int rc;

	if ((pw->pw_flags & SMB_PWF_LM) == SMB_PWF_LM) {
		(void) bintohex((char *)pw->pw_lmhash, SMBAUTH_HASH_SZ,
		    hex_lmhash, SMBAUTH_HEXHASH_SZ);
		hex_lmhash[SMBAUTH_HEXHASH_SZ] = '\0';
	} else {
		(void) strcpy(hex_lmhash, (char *)pw->pw_lmhash);
	}

	if ((pw->pw_flags & SMB_PWF_NT) == SMB_PWF_NT) {
		(void) bintohex((char *)pw->pw_nthash, SMBAUTH_HASH_SZ,
		    hex_nthash, SMBAUTH_HEXHASH_SZ);
		hex_nthash[SMBAUTH_HEXHASH_SZ] = '\0';
	} else {
		(void) strcpy(hex_nthash, (char *)pw->pw_nthash);
	}

	rc = fprintf(fp, "%s:%d:%s:%s\n", pwbuf->pw_name, pw->pw_uid,
	    hex_lmhash, hex_nthash);

	if (rc <= 0)
		return (SMB_PWE_WRITE_FAILED);

	return (SMB_PWE_SUCCESS);
}

static int
smb_pwd_lock(void)
{
	int res;

	if (smb_pwd_flck()) {
		switch (errno) {
		case EINTR:
			res = SMB_PWE_BUSY;
			break;
		case EACCES:
			res = SMB_PWE_DENIED;
			break;
		case 0:
			res = SMB_PWE_SUCCESS;
			break;
		}
	} else
		res = SMB_PWE_SUCCESS;

	return (res);
}

static int
smb_pwd_unlock(void)
{
	if (smb_pwd_fulck())
		return (SMB_PWE_SYSTEM_ERROR);

	return (SMB_PWE_SUCCESS);
}

static int
smb_pwd_flck(void)
{
	int seconds = 0;

	(void) mutex_lock(&lck_lock);
	for (;;) {
		if (lck_pid != 0 && lck_pid != getpid()) {
			/* somebody forked */
			lck_pid = 0;
			lck_tid = 0;
		}

		if (lck_tid == 0) {
			if ((fildes = creat(SMB_PASSLCK, 0600)) == -1)
				break;
			flock.l_type = F_WRLCK;
			if (fcntl(fildes, F_SETLK, &flock) != -1) {
				lck_pid = getpid();
				lck_tid = thr_self();
				(void) mutex_unlock(&lck_lock);
				return (0);
			}
			(void) close(fildes);
			fildes = -1;
		}

		if (seconds++ >= S_WAITTIME) {
			/*
			 * For compatibility with the past, pretend
			 * that we were interrupted by SIGALRM.
			 */
			errno = EINTR;
			break;
		}

		(void) mutex_unlock(&lck_lock);
		(void) sleep(1);
		(void) mutex_lock(&lck_lock);
	}
	(void) mutex_unlock(&lck_lock);

	return (-1);
}

static int
smb_pwd_fulck(void)
{
	(void) mutex_lock(&lck_lock);
	if (lck_tid == thr_self() && fildes >= 0) {
		flock.l_type = F_UNLCK;
		(void) fcntl(fildes, F_SETLK, &flock);
		(void) close(fildes);
		fildes = -1;
		lck_pid = 0;
		lck_tid = 0;
		(void) mutex_unlock(&lck_lock);
		return (0);
	}
	(void) mutex_unlock(&lck_lock);
	return (-1);
}
