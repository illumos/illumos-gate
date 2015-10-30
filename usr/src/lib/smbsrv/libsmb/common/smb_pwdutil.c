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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <strings.h>
#include <synch.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/avl.h>
#include <fcntl.h>
#include <thread.h>
#include <pwd.h>
#include <dlfcn.h>
#include <link.h>
#include <assert.h>
#include <smbsrv/libsmb.h>

#define	SMB_PASSWD	"/var/smb/smbpasswd"
#define	SMB_OPASSWD	"/var/smb/osmbpasswd"
#define	SMB_PASSTEMP	"/var/smb/ptmp"
#define	SMB_PASSLCK	"/var/smb/.pwd.lock"

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

static struct flock flock = { 0, 0, 0, 0, 0, 0 };
static pid_t lck_pid = 0;	/* process's pid at last lock */
static thread_t lck_tid = 0;	/* thread that holds the lock */
static int fildes = -1;
static mutex_t lck_lock = DEFAULTMUTEX;
static void *smb_pwd_hdl = NULL;

static struct {
	smb_passwd_t *(*pwop_getpwnam)(const char *, smb_passwd_t *);
	smb_passwd_t *(*pwop_getpwuid)(uid_t, smb_passwd_t *);
	int (*pwop_setcntl)(const char *, int);
	int (*pwop_setpasswd)(const char *, const char *);
	int (*pwop_num)(void);
	int (*pwop_iteropen)(smb_pwditer_t *);
	smb_luser_t *(*pwop_iterate)(smb_pwditer_t *);
	void (*pwop_iterclose)(smb_pwditer_t *);
} smb_pwd_ops;

static int smb_pwd_lock(void);
static int smb_pwd_unlock(void);
static int smb_pwd_flck(void);
static int smb_pwd_fulck(void);

/*
 * buffer structure used by smb_pwd_fgetent/smb_pwd_fputent
 */
typedef struct smb_pwbuf {
	char		pw_buf[SMB_PWD_BUFSIZE];
	smb_passwd_t	*pw_pwd;
} smb_pwbuf_t;

/*
 * flag values used with smb_pwd_fgetent
 */
#define	SMB_PWD_GETF_ALL	1	/* get all the account info */
#define	SMB_PWD_GETF_NOPWD	2	/* password is not needed */

static smb_pwbuf_t *smb_pwd_fgetent(FILE *, smb_pwbuf_t *, uint32_t);
static int smb_pwd_fputent(FILE *, const smb_pwbuf_t *);
static int smb_pwd_chgpwent(smb_passwd_t *, const char *, int);
static int smb_pwd_update(const char *, const char *, int);

/*
 * Local Users Cache
 *
 * Simplifying assumptions
 *
 * 	o smbpasswd is a service private file and shouldn't be edited manually
 * 	o accounts are only added/modified via passwd and/or smbadm CLIs
 * 	o accounts are not removed but disabled using smbadm CLI
 * 	o editing smbpasswd manually might result in cache inconsistency
 *
 * Cache is created and populated upon service startup.
 * Cache is updated each time users list is requested if there's been
 * any change in smbpasswd file. The change criteria is smbpasswd's
 * modification timestamp.
 */

/*
 * User cache handle
 */
typedef struct smb_uchandle {
	avl_tree_t	uc_cache;
	rwlock_t	uc_cache_lck;
	timestruc_t	uc_timestamp;
	uint32_t	uc_refcnt;
	uint32_t	uc_state;
	mutex_t		uc_mtx;
	cond_t		uc_cv;
} smb_uchandle_t;

#define	SMB_UCHS_NOCACHE	0
#define	SMB_UCHS_CREATED	1
#define	SMB_UCHS_UPDATING	2
#define	SMB_UCHS_UPDATED	3
#define	SMB_UCHS_DESTROYING	4

/*
 * User cache node
 */
typedef struct smb_ucnode {
	smb_luser_t	cn_user;
	avl_node_t	cn_link;
} smb_ucnode_t;

static void smb_lucache_create(void);
static void smb_lucache_destroy(void);
static void smb_lucache_update(void);
static int smb_lucache_num(void);
static int smb_lucache_lock(void);
static void smb_lucache_unlock(void);
static int smb_lucache_do_update(void);
static void smb_lucache_flush(void);

static smb_uchandle_t smb_uch;

/*
 * smb_pwd_init
 *
 * Initializes the cache if requested.
 * Checks to see if a password management utility library
 * is interposed. If yes then it'll initializes smb_pwd_ops
 * structure with function pointers from this library.
 */
void
smb_pwd_init(boolean_t create_cache)
{
	if (create_cache) {
		smb_lucache_create();
#if 0
		/*
		 * This pre-loading of the cache results in idmapd requests.
		 * With the change to allow idmapd to call into libsmb to
		 * map names and SIDs, this creates a circular startup
		 * dependency.  This call has been temporarily disabled to
		 * avoid this issue.  It can be enabled when the name/SID
		 * lookup can be done directly on the LSA service.
		 */
		smb_lucache_update();
#endif
	}

	smb_pwd_hdl = smb_dlopen();
	if (smb_pwd_hdl == NULL)
		return;

	bzero((void *)&smb_pwd_ops, sizeof (smb_pwd_ops));

	smb_pwd_ops.pwop_getpwnam =
	    (smb_passwd_t *(*)())dlsym(smb_pwd_hdl, "smb_pwd_getpwnam");

	smb_pwd_ops.pwop_getpwuid =
	    (smb_passwd_t *(*)())dlsym(smb_pwd_hdl, "smb_pwd_getpwuid");

	smb_pwd_ops.pwop_setcntl =
	    (int (*)())dlsym(smb_pwd_hdl, "smb_pwd_setcntl");

	smb_pwd_ops.pwop_setpasswd =
	    (int (*)())dlsym(smb_pwd_hdl, "smb_pwd_setpasswd");

	smb_pwd_ops.pwop_num =
	    (int (*)())dlsym(smb_pwd_hdl, "smb_pwd_num");

	smb_pwd_ops.pwop_iteropen =
	    (int (*)())dlsym(smb_pwd_hdl, "smb_pwd_iteropen");

	smb_pwd_ops.pwop_iterclose =
	    (void (*)())dlsym(smb_pwd_hdl, "smb_pwd_iterclose");

	smb_pwd_ops.pwop_iterate =
	    (smb_luser_t *(*)())dlsym(smb_pwd_hdl, "smb_pwd_iterate");

	if (smb_pwd_ops.pwop_getpwnam == NULL ||
	    smb_pwd_ops.pwop_getpwuid == NULL ||
	    smb_pwd_ops.pwop_setcntl == NULL ||
	    smb_pwd_ops.pwop_setpasswd == NULL ||
	    smb_pwd_ops.pwop_num == NULL ||
	    smb_pwd_ops.pwop_iteropen == NULL ||
	    smb_pwd_ops.pwop_iterclose == NULL ||
	    smb_pwd_ops.pwop_iterate == NULL) {
		smb_dlclose(smb_pwd_hdl);
		smb_pwd_hdl = NULL;

		/* If error or function(s) are missing, use original lib */
		bzero((void *)&smb_pwd_ops, sizeof (smb_pwd_ops));
	}
}

/*
 * smb_pwd_fini
 *
 * Destroys the cache.
 * Closes interposed library.
 */
void
smb_pwd_fini(void)
{
	smb_lucache_destroy();
	smb_dlclose(smb_pwd_hdl);
	smb_pwd_hdl = NULL;
	bzero((void *)&smb_pwd_ops, sizeof (smb_pwd_ops));
}

/*
 * smb_pwd_getpwnam
 *
 * Returns a smb password structure for the given user name.
 * smbpw is a pointer to a buffer allocated by the caller.
 *
 * Returns NULL upon failure.
 */
smb_passwd_t *
smb_pwd_getpwnam(const char *name, smb_passwd_t *smbpw)
{
	boolean_t found = B_FALSE;
	smb_pwbuf_t pwbuf;
	FILE *fp;
	int err;

	if (smb_pwd_ops.pwop_getpwnam != NULL)
		return (smb_pwd_ops.pwop_getpwnam(name, smbpw));

	err = smb_pwd_lock();
	if (err != SMB_PWE_SUCCESS) {
		syslog(LOG_WARNING, "smb_pwdutil: lock failed, err=%d", err);
		return (NULL);
	}

	if ((fp = fopen(SMB_PASSWD, "rF")) == NULL) {
		syslog(LOG_WARNING, "smb_pwdutil: open failed, %m");
		(void) smb_pwd_unlock();
		return (NULL);
	}

	pwbuf.pw_pwd = smbpw;

	while (smb_pwd_fgetent(fp, &pwbuf, SMB_PWD_GETF_ALL) != NULL) {
		if (strcmp(name, smbpw->pw_name) == 0) {
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
 * smb_pwd_getpwuid
 *
 * Returns a smb password structure for the given UID
 * smbpw is a pointer to a buffer allocated by the caller.
 *
 * Returns NULL upon failure.
 */
smb_passwd_t *
smb_pwd_getpwuid(uid_t uid, smb_passwd_t *smbpw)
{
	boolean_t found = B_FALSE;
	smb_pwbuf_t pwbuf;
	FILE *fp;
	int err;

	if (smb_pwd_ops.pwop_getpwuid != NULL)
		return (smb_pwd_ops.pwop_getpwuid(uid, smbpw));

	err = smb_pwd_lock();
	if (err != SMB_PWE_SUCCESS) {
		syslog(LOG_WARNING, "smb_pwdutil: lock failed, err=%d", err);
		return (NULL);
	}

	if ((fp = fopen(SMB_PASSWD, "rF")) == NULL) {
		syslog(LOG_WARNING, "smb_pwdutil: open failed, %m");
		(void) smb_pwd_unlock();
		return (NULL);
	}

	pwbuf.pw_pwd = smbpw;

	while (smb_pwd_fgetent(fp, &pwbuf, SMB_PWD_GETF_ALL) != NULL) {
		if (uid == smbpw->pw_uid) {
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
 * smb_pwd_setpasswd
 *
 * Update/add the given user to the smbpasswd file.
 */
int
smb_pwd_setpasswd(const char *name, const char *password)
{
	if (smb_pwd_ops.pwop_setpasswd != NULL)
		return (smb_pwd_ops.pwop_setpasswd(name, password));

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
	if (smb_pwd_ops.pwop_setcntl != NULL)
		return (smb_pwd_ops.pwop_setcntl(name, control));

	if (control == 0)
		return (SMB_PWE_SUCCESS);

	return (smb_pwd_update(name, NULL, control));
}

/*
 * smb_pwd_num
 *
 * Returns the number of cached local users
 */
int
smb_pwd_num(void)
{
	if (smb_pwd_ops.pwop_num != NULL)
		return (smb_pwd_ops.pwop_num());

	smb_lucache_update();

	return (smb_lucache_num());
}

/*
 * smb_pwd_iteropen
 *
 * Initalizes the given iterator handle.
 * This handle will be used to iterate the users cache
 * by the caller. The cache will be locked for read and it
 * will remain locked until smb_pwd_iterclose() is called.
 */
int
smb_pwd_iteropen(smb_pwditer_t *iter)
{
	if (iter == NULL)
		return (SMB_PWE_INVALID_PARAM);

	if (smb_pwd_ops.pwop_iteropen != NULL)
		return (smb_pwd_ops.pwop_iteropen(iter));

	iter->spi_next = NULL;

	smb_lucache_update();

	return (smb_lucache_lock());
}

/*
 * smb_pwd_iterate
 *
 * Scans through users cache using the given iterator
 */
smb_luser_t *
smb_pwd_iterate(smb_pwditer_t *iter)
{
	smb_ucnode_t *ucnode;

	if (iter == NULL)
		return (NULL);

	if (smb_pwd_ops.pwop_iterate != NULL)
		return (smb_pwd_ops.pwop_iterate(iter));

	if (iter->spi_next == NULL)
		ucnode = avl_first(&smb_uch.uc_cache);
	else
		ucnode = AVL_NEXT(&smb_uch.uc_cache, iter->spi_next);

	if ((iter->spi_next = ucnode) != NULL)
		return (&ucnode->cn_user);

	return (NULL);
}

/*
 * smb_pwd_iterclose
 *
 * Closes the given iterator. Effectively it only unlocks the cache
 */
void
smb_pwd_iterclose(smb_pwditer_t *iter)
{
	if (smb_pwd_ops.pwop_iterclose != NULL) {
		smb_pwd_ops.pwop_iterclose(iter);
		return;
	}

	if (iter != NULL)
		smb_lucache_unlock();
}

/*
 * smb_pwd_update
 *
 * Updates the password entry of the given user if the user already
 * has an entry, otherwise it'll add an entry for the user with
 * given password and control information.
 */
static int
smb_pwd_update(const char *name, const char *password, int control)
{
	struct stat64 stbuf;
	FILE *src, *dst;
	int tempfd;
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

	pwbuf.pw_pwd = &smbpw;

	/*
	 * copy old password entries to temporary file while replacing
	 * the entry that matches "name"
	 */
	while (smb_pwd_fgetent(src, &pwbuf, SMB_PWD_GETF_ALL) != NULL) {
		if (strcmp(smbpw.pw_name, name) == 0) {
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
			bzero(&smbpw, sizeof (smb_passwd_t));
			(void) strlcpy(smbpw.pw_name, uxpw.pw_name,
			    sizeof (smbpw.pw_name));
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
 * smb_pwd_fgetent
 *
 * Parse the buffer in the passed pwbuf and fill in the
 * smb password structure to point to the parsed information.
 * The entry format is:
 *
 *	<user-name>:<user-id>:<LM hash>:<NTLM hash>
 *
 * Returns a pointer to the passed pwbuf structure on success,
 * otherwise returns NULL.
 */
static smb_pwbuf_t *
smb_pwd_fgetent(FILE *fp, smb_pwbuf_t *pwbuf, uint32_t flags)
{
	char *argv[SMB_PWD_NARG];
	char *pwentry;
	smb_passwd_t *pw;
	smb_pwdarg_t i;
	int lm_len, nt_len;

	pwentry = pwbuf->pw_buf;
	if (fgets(pwentry, SMB_PWD_BUFSIZE, fp) == NULL)
		return (NULL);
	(void) trim_whitespace(pwentry);

	for (i = 0; i < SMB_PWD_NARG; ++i) {
		if ((argv[i] = strsep((char **)&pwentry, ":")) == NULL)
			return (NULL);
	}

	if ((*argv[SMB_PWD_NAME] == '\0') || (*argv[SMB_PWD_UID] == '\0'))
		return (NULL);

	pw = pwbuf->pw_pwd;
	bzero(pw, sizeof (smb_passwd_t));
	pw->pw_uid = strtoul(argv[SMB_PWD_UID], 0, 10);
	(void) strlcpy(pw->pw_name, argv[SMB_PWD_NAME], sizeof (pw->pw_name));

	if (strcmp(argv[SMB_PWD_LMHASH], SMB_PWD_DISABLE) == 0) {
		pw->pw_flags |= SMB_PWF_DISABLE;
		if (flags != SMB_PWD_GETF_NOPWD) {
			(void) strcpy((char *)pw->pw_lmhash, SMB_PWD_DISABLE);
			(void) strcpy((char *)pw->pw_nthash, SMB_PWD_DISABLE);
		}
		return (pwbuf);
	}

	if (flags == SMB_PWD_GETF_NOPWD)
		return (pwbuf);

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

/*
 * smb_pwd_chgpwent
 *
 * Updates the given smb_passwd_t structure with given password and
 * control information.
 */
static int
smb_pwd_chgpwent(smb_passwd_t *smbpw, const char *password, int control)
{
	if (control & SMB_PWC_DISABLE) {
		/* disable the user */
		smbpw->pw_flags |= SMB_PWF_DISABLE;
		(void) strcpy((char *)smbpw->pw_lmhash, SMB_PWD_DISABLE);
		(void) strcpy((char *)smbpw->pw_nthash, SMB_PWD_DISABLE);
		smbpw->pw_flags &= ~(SMB_PWF_LM | SMB_PWF_NT);
		return (SMB_PWE_SUCCESS);
	}

	if ((control & SMB_PWC_ENABLE) && (smbpw->pw_flags & SMB_PWF_DISABLE)) {
		/* enable the user if it's been disabled */
		*smbpw->pw_lmhash = '\0';
		*smbpw->pw_nthash = '\0';
		smbpw->pw_flags &= ~(SMB_PWF_LM | SMB_PWF_NT);
		return (SMB_PWE_SUCCESS);
	}

	/* No password update if account is disabled */
	if (smbpw->pw_flags & SMB_PWF_DISABLE)
		return (SMB_PWE_USER_DISABLE);

	/* This call was just to update the control flags */
	if (password == NULL)
		return (SMB_PWE_SUCCESS);

	if (control & SMB_PWC_NOLM) {
		/* LM hash should not be present */
		smbpw->pw_flags &= ~SMB_PWF_LM;
		*smbpw->pw_lmhash = '\0';
	} else {
		smbpw->pw_flags |= SMB_PWF_LM;
		(void) smb_auth_lm_hash(password, smbpw->pw_lmhash);
	}

	smbpw->pw_flags |= SMB_PWF_NT;
	(void) smb_auth_ntlm_hash(password, smbpw->pw_nthash);
	return (SMB_PWE_SUCCESS);
}

/*
 * smb_pwd_fputent
 *
 * If LM/NTLM hash are present, converts them to hex string
 * and write them along with user's name and Id to the smbpasswd
 * file.
 */
static int
smb_pwd_fputent(FILE *fp, const smb_pwbuf_t *pwbuf)
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

	rc = fprintf(fp, "%s:%u:%s:%s\n", pw->pw_name, pw->pw_uid,
	    hex_lmhash, hex_nthash);

	if (rc <= 0)
		return (SMB_PWE_WRITE_FAILED);

	return (SMB_PWE_SUCCESS);
}

/*
 * smb_pwd_lock
 *
 * A wrapper around smb_pwd_flck() which locks smb password
 * file so that only one thread at a time is operational.
 */
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

/*
 * smb_pwd_unlock
 *
 * A wrapper around smb_pwd_fulck() which unlocks
 * smb password file.
 */
static int
smb_pwd_unlock(void)
{
	if (smb_pwd_fulck())
		return (SMB_PWE_SYSTEM_ERROR);

	return (SMB_PWE_SUCCESS);
}

/*
 * smb_pwd_flck
 *
 * Creates a lock file and grabs an exclusive (write) lock on it.
 */
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

/*
 * smb_pwd_fulck
 *
 * Unlocks smb password file for operations done via
 * this library APIs.
 */
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

/*
 * Local User Cache Functions
 *
 * Local user cache is implemented using AVL tree
 */

/*
 * smb_lucache_cmp
 *
 * AVL compare function, the key is username.
 */
static int
smb_lucache_cmp(const void *p1, const void *p2)
{
	smb_ucnode_t *u1 = (smb_ucnode_t *)p1;
	smb_ucnode_t *u2 = (smb_ucnode_t *)p2;
	int rc;

	rc = strcmp(u1->cn_user.su_name, u2->cn_user.su_name);

	if (rc < 0)
		return (-1);

	if (rc > 0)
		return (1);

	return (0);
}

/*
 * smb_lucache_update
 *
 * Updates the cache if needed. Whether an update is needed
 * is determined based on smbpasswd file modification timestamp
 */
static void
smb_lucache_update(void)
{
	struct stat64 stbuf;
	int rc;

	(void) mutex_lock(&smb_uch.uc_mtx);
	switch (smb_uch.uc_state) {
	default:
	case SMB_UCHS_NOCACHE:
		assert(0);
		(void) mutex_unlock(&smb_uch.uc_mtx);
		return;

	case SMB_UCHS_CREATED:
	case SMB_UCHS_UPDATED:
		break;

	case SMB_UCHS_UPDATING:
		/* Want only one thread executing this function at a time */
		(void) mutex_unlock(&smb_uch.uc_mtx);
		return;

	case SMB_UCHS_DESTROYING:
		(void) mutex_unlock(&smb_uch.uc_mtx);
		return;
	}

	/*
	 * smb_pwd_lock() is not called here so it can
	 * be checked quickly whether an updated is needed
	 */
	if (stat64(SMB_PASSWD, &stbuf) < 0) {
		(void) mutex_unlock(&smb_uch.uc_mtx);
		if (errno != ENOENT)
			return;

		/* no smbpasswd file; empty the cache */
		smb_lucache_flush();
		return;
	}

	if (stbuf.st_size == 0) {
		(void) mutex_unlock(&smb_uch.uc_mtx);

		/* empty smbpasswd file; empty the cache */
		smb_lucache_flush();
		return;
	}

	if ((smb_uch.uc_timestamp.tv_sec == stbuf.st_mtim.tv_sec) &&
	    (smb_uch.uc_timestamp.tv_nsec == stbuf.st_mtim.tv_nsec)) {
		(void) mutex_unlock(&smb_uch.uc_mtx);
		/* No changes since the last cache update */
		return;
	}

	smb_uch.uc_state = SMB_UCHS_UPDATING;
	smb_uch.uc_refcnt++;
	(void) mutex_unlock(&smb_uch.uc_mtx);

	rc = smb_lucache_do_update();

	(void) mutex_lock(&smb_uch.uc_mtx);
	if ((rc == SMB_PWE_SUCCESS) && (stat64(SMB_PASSWD, &stbuf) == 0))
		smb_uch.uc_timestamp = stbuf.st_mtim;
	smb_uch.uc_state = SMB_UCHS_UPDATED;
	smb_uch.uc_refcnt--;
	(void) cond_broadcast(&smb_uch.uc_cv);
	(void) mutex_unlock(&smb_uch.uc_mtx);
}

/*
 * smb_lucache_do_update
 *
 * This function takes care of updating the AVL tree.
 * If an entry has been updated, it'll be modified in place.
 *
 * New entries will be added to a temporary AVL tree then
 * passwod file is unlocked and all the new entries will
 * be transferred to the main cache from the temporary tree.
 *
 * This function MUST NOT be called directly
 */
static int
smb_lucache_do_update(void)
{
	avl_tree_t tmp_cache;
	smb_pwbuf_t pwbuf;
	smb_passwd_t smbpw;
	smb_ucnode_t uc_node;
	smb_ucnode_t *uc_newnode;
	smb_luser_t *user;
	smb_sid_t *sid;
	idmap_stat idm_stat;
	int rc = SMB_PWE_SUCCESS;
	void *cookie = NULL;
	FILE *fp;

	if ((rc = smb_pwd_lock()) != SMB_PWE_SUCCESS) {
		syslog(LOG_WARNING, "smb_pwdutil: lock failed, err=%d", rc);
		return (rc);
	}

	if ((fp = fopen(SMB_PASSWD, "rF")) == NULL) {
		syslog(LOG_WARNING, "smb_pwdutil: open failed, %m");
		(void) smb_pwd_unlock();
		return (SMB_PWE_OPEN_FAILED);
	}

	avl_create(&tmp_cache, smb_lucache_cmp,
	    sizeof (smb_ucnode_t), offsetof(smb_ucnode_t, cn_link));

	bzero(&pwbuf, sizeof (smb_pwbuf_t));
	pwbuf.pw_pwd = &smbpw;

	(void) rw_rdlock(&smb_uch.uc_cache_lck);

	while (smb_pwd_fgetent(fp, &pwbuf, SMB_PWD_GETF_NOPWD) != NULL) {
		uc_node.cn_user.su_name = smbpw.pw_name;
		uc_newnode = avl_find(&smb_uch.uc_cache, &uc_node, NULL);
		if (uc_newnode) {
			/* update the node info */
			uc_newnode->cn_user.su_ctrl = smbpw.pw_flags;
			continue;
		}

		/* create a new node */
		if ((uc_newnode = malloc(sizeof (smb_ucnode_t))) == NULL) {
			rc = SMB_PWE_NO_MEMORY;
			break;
		}

		bzero(uc_newnode, sizeof (smb_ucnode_t));
		user = &uc_newnode->cn_user;
		user->su_ctrl = smbpw.pw_flags;

		idm_stat = smb_idmap_getsid(smbpw.pw_uid, SMB_IDMAP_USER, &sid);
		if (idm_stat != IDMAP_SUCCESS) {
			syslog(LOG_WARNING, "smb_pwdutil: couldn't obtain SID "
			    "for uid=%u (%d)", smbpw.pw_uid, idm_stat);
			free(uc_newnode);
			continue;
		}
		(void) smb_sid_getrid(sid, &user->su_rid);
		smb_sid_free(sid);

		user->su_name = strdup(smbpw.pw_name);
		if (user->su_name == NULL) {
			rc = SMB_PWE_NO_MEMORY;
			free(uc_newnode);
			break;
		}

		avl_add(&tmp_cache, uc_newnode);
	}

	(void) rw_unlock(&smb_uch.uc_cache_lck);
	(void) fclose(fp);
	(void) smb_pwd_unlock();

	/* Destroy the temporary list */
	(void) rw_wrlock(&smb_uch.uc_cache_lck);
	while ((uc_newnode = avl_destroy_nodes(&tmp_cache, &cookie)) != NULL) {
		avl_add(&smb_uch.uc_cache, uc_newnode);
	}
	(void) rw_unlock(&smb_uch.uc_cache_lck);

	avl_destroy(&tmp_cache);

	return (rc);
}

/*
 * smb_lucache_create
 *
 * Creates the AVL tree and initializes the global user cache handle.
 * This function doesn't populate the cache.
 * User cache is only created by smbd at startup
 */
static void
smb_lucache_create(void)
{
	(void) mutex_lock(&smb_uch.uc_mtx);
	if (smb_uch.uc_state != SMB_UCHS_NOCACHE) {
		(void) mutex_unlock(&smb_uch.uc_mtx);
		return;
	}

	avl_create(&smb_uch.uc_cache, smb_lucache_cmp,
	    sizeof (smb_ucnode_t), offsetof(smb_ucnode_t, cn_link));

	smb_uch.uc_state = SMB_UCHS_CREATED;
	bzero(&smb_uch.uc_timestamp, sizeof (timestruc_t));
	smb_uch.uc_refcnt = 0;
	(void) mutex_unlock(&smb_uch.uc_mtx);
}

/*
 * smb_lucache_flush
 *
 * Removes and frees all the cache entries
 */
static void
smb_lucache_flush(void)
{
	void *cookie = NULL;
	smb_ucnode_t *ucnode;

	(void) rw_wrlock(&smb_uch.uc_cache_lck);
	while ((ucnode = avl_destroy_nodes(&smb_uch.uc_cache, &cookie))
	    != NULL) {
		free(ucnode->cn_user.su_name);
		free(ucnode->cn_user.su_fullname);
		free(ucnode->cn_user.su_desc);
		free(ucnode);
	}
	(void) rw_unlock(&smb_uch.uc_cache_lck);
}

/*
 * smb_lucache_destroy
 *
 * Destroys the cache.
 * This function is only called in smb_pwd_fini()
 * User cache is only destroyed by smbd upon shutdown
 */
static void
smb_lucache_destroy(void)
{
	(void) mutex_lock(&smb_uch.uc_mtx);
	switch (smb_uch.uc_state) {
	case SMB_UCHS_NOCACHE:
	case SMB_UCHS_DESTROYING:
		(void) mutex_unlock(&smb_uch.uc_mtx);
		return;

	default:
		break;
	}

	smb_uch.uc_state = SMB_UCHS_DESTROYING;

	while (smb_uch.uc_refcnt > 0)
		(void) cond_wait(&smb_uch.uc_cv, &smb_uch.uc_mtx);

	smb_lucache_flush();

	avl_destroy(&smb_uch.uc_cache);
	smb_uch.uc_state = SMB_UCHS_NOCACHE;
	(void) mutex_unlock(&smb_uch.uc_mtx);
}

/*
 * smb_lucache_lock
 *
 * Locks the user cache for reading and also
 * increment the handle reference count.
 */
static int
smb_lucache_lock(void)
{
	(void) mutex_lock(&smb_uch.uc_mtx);
	switch (smb_uch.uc_state) {
	case SMB_UCHS_NOCACHE:
		assert(0);
		(void) mutex_unlock(&smb_uch.uc_mtx);
		return (SMB_PWE_DENIED);

	case SMB_UCHS_DESTROYING:
		(void) mutex_unlock(&smb_uch.uc_mtx);
		return (SMB_PWE_DENIED);
	}
	smb_uch.uc_refcnt++;
	(void) mutex_unlock(&smb_uch.uc_mtx);

	(void) rw_rdlock(&smb_uch.uc_cache_lck);
	return (SMB_PWE_SUCCESS);
}

/*
 * smb_lucache_unlock
 *
 * Unlock the cache
 */
static void
smb_lucache_unlock(void)
{
	(void) rw_unlock(&smb_uch.uc_cache_lck);

	(void) mutex_lock(&smb_uch.uc_mtx);
	smb_uch.uc_refcnt--;
	(void) cond_broadcast(&smb_uch.uc_cv);
	(void) mutex_unlock(&smb_uch.uc_mtx);
}

/*
 * smb_lucache_num
 *
 * Returns the number of cache entries
 */
static int
smb_lucache_num(void)
{
	int num;

	(void) mutex_lock(&smb_uch.uc_mtx);
	switch (smb_uch.uc_state) {
	case SMB_UCHS_NOCACHE:
		assert(0);
		(void) mutex_unlock(&smb_uch.uc_mtx);
		return (0);

	case SMB_UCHS_DESTROYING:
		(void) mutex_unlock(&smb_uch.uc_mtx);
		return (0);
	}
	(void) mutex_unlock(&smb_uch.uc_mtx);

	(void) rw_rdlock(&smb_uch.uc_cache_lck);
	num = (int)avl_numnodes(&smb_uch.uc_cache);
	(void) rw_unlock(&smb_uch.uc_cache_lck);

	return (num);
}
