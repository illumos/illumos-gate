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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018, Joyent, Inc.
 */

/*
 * Functions used for manipulating the keystore
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>
#include <libgen.h>
#include <strings.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>
#include "softGlobal.h"
#include "softObject.h"
#include "softSession.h"
#include "softKeystore.h"
#include "softKeystoreUtil.h"

#define	MAXPATHLEN	1024
#define	SUNW_PATH	".sunw"		/* top level Sun directory */
#define	KEYSTORE_PATH	"pkcs11_softtoken"	/* keystore directory */
#define	PUB_OBJ_DIR	"public"	/* directory for public objects */
#define	PRI_OBJ_DIR	"private"	/* directory for private objects */
#define	DS_FILE		"objstore_info"	/* keystore description file */
#define	TMP_DS_FILE	"t_info"	/* temp name for keystore desc. file */
#define	OBJ_PREFIX	"obj"	/* prefix of the keystore object file names */
#define	OBJ_PREFIX_LEN	sizeof (OBJ_PREFIX) - 1	/* length of prefix */
#define	TMP_OBJ_PREFIX	"t_o"	/* prefix of the temp object file names */

/*
 * KEYSTORE DESCRIPTION FILE:
 *
 * The following describes the content of the keystore description file
 *
 * The order AND data type of the fields are very important.
 * All the code in this file assume that they are in the order specified
 * below.  If either order of the fields or their data type changed,
 * you must make sure the ALL the pre-define values are still valid
 *
 * 1) PKCS#11 release number.  It's 2.20 in this release (uchar_t[32])
 * 2) keystore version number: used for synchronizing when different
 *    processes access the keystore at the same time.  It is incremented
 *    when there is a change to the keystore. (uint_32)
 * 3) monotonic-counter: last counter value for name of token object file.
 *    used for assigning unique name to each token (uint_32)
 * 4) salt used for generating encryption key (uint_16)
 * 5) salt used for generating key used for doing HMAC (uint_16)
 * 6) Length of salt used for generating hashed pin (length of salt
 *    is variable)
 * 7) Salt used for generating hashed pin.
 * 8) Hashed pin len (length of hashed pin could be variable, the offset of
 *    where this value lives in the file is calculated at run time)
 * 9) Hashed pin
 *
 */

/* Keystore description file pre-defined values */
#define	KS_PKCS11_VER		"2.20"
#define	KS_PKCS11_OFFSET	0
#define	KS_PKCS11_VER_SIZE	32

#define	KS_VER_OFFSET		(KS_PKCS11_OFFSET + KS_PKCS11_VER_SIZE)
#define	KS_VER_SIZE	4	/* size in bytes of keystore version value */

#define	KS_COUNTER_OFFSET	(KS_VER_OFFSET + KS_VER_SIZE)
#define	KS_COUNTER_SIZE	4	/* size in bytes of the monotonic counter */

#define	KS_KEY_SALT_OFFSET	(KS_COUNTER_OFFSET + KS_COUNTER_SIZE)
#define	KS_KEY_SALT_SIZE	PBKD2_SALT_SIZE

#define	KS_HMAC_SALT_OFFSET	(KS_KEY_SALT_OFFSET + KS_KEY_SALT_SIZE)
#define	KS_HMAC_SALT_SIZE	PBKD2_SALT_SIZE

/* Salt for hashed pin */
#define	KS_HASHED_PIN_SALT_LEN_OFFSET (KS_HMAC_SALT_OFFSET + KS_HMAC_SALT_SIZE)
#define	KS_HASHED_PIN_SALT_LEN_SIZE 8 /* stores length of hashed pin salt */

#define	KS_HASHED_PIN_SALT_OFFSET \
		(KS_HASHED_PIN_SALT_LEN_OFFSET + KS_HASHED_PIN_SALT_LEN_SIZE)

/*
 * hashed pin
 *
 * hashed_pin length offset will be calculated at run time since
 * there's the hashed pin salt size is variable.
 *
 * The offset will be calculated at run time by calling the
 * function calculate_hashed_pin_offset()
 */
static off_t	ks_hashed_pinlen_offset = -1;
#define	KS_HASHED_PINLEN_SIZE	8

/* End of Keystore description file pre-defined values */

/*
 * Metadata for each object
 *
 * The order AND data type of all the fields is very important.
 * All the code in this file assume that they are in the order specified
 * below.  If either order of the fields or their data type is changed,
 * you must make sure the following pre-define value is still valid
 * Each object will have the meta data at the beginning of the object file.
 *
 * 1) object_version: used by softtoken to see if the object
 *    has been modified since it last reads it. (uint_32)
 * 2) iv: initialization vector for encrypted data in the object.  This
 *    value will be 0 for public objects.  (uchar_t[16])
 * 3) obj_hmac: keyed hash as verifier to detect private object
 *    being tampered this value will be 0 for public objects (uchar_t[16])
 */

/* Object metadata pre-defined values */
#define	OBJ_VER_OFFSET	0
#define	OBJ_VER_SIZE	4	/* size of object version in bytes */
#define	OBJ_IV_OFFSET	(OBJ_VER_OFFSET + OBJ_VER_SIZE)
#define	OBJ_IV_SIZE	16
#define	OBJ_HMAC_OFFSET	(OBJ_IV_OFFSET + OBJ_IV_SIZE)
#define	OBJ_HMAC_SIZE	16	/* MD5 HMAC keyed hash */
#define	OBJ_DATA_OFFSET	(OBJ_HMAC_OFFSET + OBJ_HMAC_SIZE)
/* End of object metadata pre-defined values */

#define	ALTERNATE_KEYSTORE_PATH	"SOFTTOKEN_DIR"

static soft_object_t	*enc_key = NULL;
static soft_object_t	*hmac_key = NULL;
static char		keystore_path[MAXPATHLEN];
static boolean_t	keystore_path_initialized = B_FALSE;
static int		desc_fd = 0;

static char *
get_keystore_path()
{
	char *home = getenv("HOME");
	char *alt = getenv(ALTERNATE_KEYSTORE_PATH);

	if (keystore_path_initialized) {
		return (keystore_path);
	}

	bzero(keystore_path, sizeof (keystore_path));
	/*
	 * If it isn't set or is set to the empty string use the
	 * default location.  We need to check for the empty string
	 * because some users "unset" environment variables by giving
	 * them no value, this isn't the same thing as removing it
	 * from the environment.
	 *
	 * We don't want that to attempt to open /.sunw/pkcs11_sofftoken
	 */
	if ((alt != NULL) && (strcmp(alt, "") != 0)) {
		(void) snprintf(keystore_path, MAXPATHLEN, "%s/%s",
		    alt, KEYSTORE_PATH);
		keystore_path_initialized = B_TRUE;
	} else if ((home != NULL) && (strcmp(home, "") != 0)) {
		/* alternate path not specified, try user's home dir */
		(void) snprintf(keystore_path, MAXPATHLEN, "%s/%s/%s",
		    home, SUNW_PATH, KEYSTORE_PATH);
		keystore_path_initialized = B_TRUE;
	}
	return (keystore_path);
}

static char *
get_pub_obj_path(char *name)
{
	bzero(name, sizeof (name));
	(void) snprintf(name, MAXPATHLEN, "%s/%s",
	    get_keystore_path(), PUB_OBJ_DIR);
	return (name);
}

static char *
get_pri_obj_path(char *name)
{
	bzero(name, sizeof (name));
	(void) snprintf(name, MAXPATHLEN, "%s/%s",
	    get_keystore_path(), PRI_OBJ_DIR);
	return (name);
}

static char *
get_desc_file_path(char *name)
{
	bzero(name, sizeof (name));
	(void) snprintf(name, MAXPATHLEN, "%s/%s",
	    get_keystore_path(), DS_FILE);
	return (name);
}

static char *
get_tmp_desc_file_path(char *name)
{
	bzero(name, sizeof (name));
	(void) snprintf(name, MAXPATHLEN, "%s/%s",
	    get_keystore_path(), TMP_DS_FILE);
	return (name);
}

/*
 * Calculates the offset for hashed_pin length and hashed pin
 *
 * Returns 0 if successful, -1 if there's any error.
 *
 * If successful, global variables "ks_hashed_pinlen_offset" will be set.
 *
 */
static int
calculate_hashed_pin_offset(int fd)
{
	uint64_t salt_length;

	if (lseek(fd, KS_HASHED_PIN_SALT_LEN_OFFSET, SEEK_SET)
	    != KS_HASHED_PIN_SALT_LEN_OFFSET) {
		return (-1);
	}

	if (readn_nointr(fd, (char *)&salt_length,
	    KS_HASHED_PIN_SALT_LEN_SIZE) != KS_HASHED_PIN_SALT_LEN_SIZE) {
		return (-1);
	}
	salt_length = SWAP64(salt_length);

	ks_hashed_pinlen_offset = KS_HASHED_PIN_SALT_LEN_OFFSET
	    + KS_HASHED_PIN_SALT_LEN_SIZE + salt_length;

	return (0);

}

/*
 * acquire or release read/write lock on a specific file
 *
 * read_lock: true for read lock; false for write lock
 * set_lock:  true to set a lock; false to release a lock
 */
static int
lock_file(int fd, boolean_t read_lock, boolean_t set_lock)
{

	flock_t lock_info;
	int r;

	lock_info.l_whence = SEEK_SET;
	lock_info.l_start = 0;
	lock_info.l_len = 0; /* l_len == 0 means until end of  file */

	if (read_lock) {
		lock_info.l_type = F_RDLCK;
	} else {
		lock_info.l_type = F_WRLCK;
	}

	if (set_lock) {
		while ((r = fcntl(fd, F_SETLKW, &lock_info)) == -1) {
			if (errno != EINTR)
				break;
		}
		if (r == -1) {
			return (-1);
		}
	} else {
		lock_info.l_type = F_UNLCK;
		while ((r = fcntl(fd, F_SETLKW, &lock_info)) == -1) {
			if (errno != EINTR)
				break;
		}
		if (r == -1) {
			return (-1);
		}
	}

	return (0);
}

int
create_keystore()
{
	int fd, buf;
	uint64_t hashed_pin_len, hashed_pin_salt_len, ulong_buf;
	uchar_t ver_buf[KS_PKCS11_VER_SIZE];
	char pub_obj_path[MAXPATHLEN], pri_obj_path[MAXPATHLEN],
	    ks_desc_file[MAXPATHLEN];
	CK_BYTE salt[KS_KEY_SALT_SIZE];
	char *hashed_pin = NULL, *hashed_pin_salt = NULL;
	char *alt;

	/* keystore doesn't exist, create keystore directory */
	if (mkdir(get_keystore_path(), S_IRUSR|S_IWUSR|S_IXUSR) < 0) {
		if (errno == EEXIST) {
			return (0);
		}

		if (errno == EACCES) {
			return (-1);
		}

		/* can't create keystore directory */
		if (errno == ENOENT) { /* part of the path doesn't exist */
			char keystore[MAXPATHLEN];
			/*
			 * try to create $HOME/.sunw/pkcs11_softtoken if it
			 * doesn't exist.  If it is a alternate path provided
			 * by the user, it should have existed.  Will not
			 * create for them.
			 */
			alt = getenv(ALTERNATE_KEYSTORE_PATH);
			if ((alt == NULL) || (strcmp(alt, "") == 0)) {
				char *home = getenv("HOME");

				if (home == NULL || strcmp(home, "") == 0) {
					return (-1);
				}
				/* create $HOME/.sunw/pkcs11_softtoken */
				(void) snprintf(keystore, sizeof (keystore),
				    "%s/%s/%s", home, SUNW_PATH, KEYSTORE_PATH);
				if (mkdirp(keystore,
				    S_IRUSR|S_IWUSR|S_IXUSR) < 0) {
					return (-1);
				}
			} else {
				return (-1);
			}
		}
	}

	/* create keystore description file */
	fd = open_nointr(get_desc_file_path(ks_desc_file),
	    O_RDWR|O_CREAT|O_EXCL|O_NONBLOCK, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		if (errno == EEXIST) {
			return (0);
		} else {
			/* can't create keystore description file */
			(void) rmdir(get_keystore_path());
			return (-1);
		}
	}

	if (lock_file(fd, B_FALSE, B_TRUE) != 0) {
		(void) unlink(ks_desc_file);
		(void) close(fd);
		(void) rmdir(get_keystore_path());
		return (-1);
	}

	if (mkdir(get_pub_obj_path(pub_obj_path),
	    S_IRUSR|S_IWUSR|S_IXUSR) < 0) {
		/* can't create directory for public objects */
		(void) lock_file(fd, B_FALSE, B_FALSE);
		(void) unlink(ks_desc_file);
		(void) close(fd);
		(void) rmdir(get_keystore_path());
		return (-1);
	}

	if (mkdir(get_pri_obj_path(pri_obj_path),
	    S_IRUSR|S_IWUSR|S_IXUSR) < 0) {
		/* can't create directory for private objects */
		(void) lock_file(fd, B_FALSE, B_FALSE);
		(void) unlink(ks_desc_file);
		(void) close(fd);
		(void) rmdir(get_keystore_path());
		(void) rmdir(pub_obj_path);
		return (-1);
	}


	/* write file format release number */
	bzero(ver_buf, sizeof (ver_buf));
	(void) strcpy((char *)ver_buf, KS_PKCS11_VER);
	if ((writen_nointr(fd, (char *)ver_buf, sizeof (ver_buf)))
	    != sizeof (ver_buf)) {
		goto cleanup;
	}

	/* write version number, version = 0 since keystore just created */
	buf = SWAP32(0);
	if (writen_nointr(fd, (void *)&buf, KS_VER_SIZE) != KS_VER_SIZE) {
		goto cleanup;
	}

	/* write monotonic-counter.  Counter for keystore objects start at 1 */
	buf = SWAP32(1);
	if (writen_nointr(fd, (void *)&buf, KS_COUNTER_SIZE)
	    != KS_COUNTER_SIZE) {
		goto cleanup;
	}

	/* initial encryption key salt should be all NULL */
	bzero(salt, sizeof (salt));
	if (writen_nointr(fd, (void *)salt, KS_KEY_SALT_SIZE)
	    != KS_KEY_SALT_SIZE) {
		goto cleanup;
	}

	/* initial HMAC key salt should also be all NULL */
	if (writen_nointr(fd, (void *)salt, KS_HMAC_SALT_SIZE)
	    != KS_HMAC_SALT_SIZE) {
		goto cleanup;
	}

	/* generate the hashed pin salt, and MD5 hashed pin of default pin */
	if (soft_gen_hashed_pin((CK_CHAR_PTR)SOFT_DEFAULT_PIN, &hashed_pin,
	    &hashed_pin_salt) < 0) {
		goto cleanup;
	}

	if ((hashed_pin_salt == NULL) || (hashed_pin == NULL)) {
		goto cleanup;
	}

	hashed_pin_salt_len = (uint64_t)strlen(hashed_pin_salt);
	hashed_pin_len = (uint64_t)strlen(hashed_pin);

	/* write hashed pin salt length */
	ulong_buf = SWAP64(hashed_pin_salt_len);
	if (writen_nointr(fd, (void *)&ulong_buf, KS_HASHED_PIN_SALT_LEN_SIZE)
	    != KS_HASHED_PIN_SALT_LEN_SIZE) {
		goto cleanup;
	}

	if (writen_nointr(fd, (void *)hashed_pin_salt,
	    hashed_pin_salt_len) != hashed_pin_salt_len) {
		goto cleanup;
	}

	/* write MD5 hashed pin of the default pin */
	ulong_buf = SWAP64(hashed_pin_len);
	if (writen_nointr(fd, (void *)&ulong_buf, KS_HASHED_PINLEN_SIZE)
	    != KS_HASHED_PINLEN_SIZE) {
		goto cleanup;
	}

	if (writen_nointr(fd, (void *)hashed_pin, hashed_pin_len)
	    != hashed_pin_len) {
		goto cleanup;
	}

	(void) lock_file(fd, B_FALSE, B_FALSE);

	(void) close(fd);
	freezero(hashed_pin_salt, hashed_pin_salt_len);
	return (0);

cleanup:
	(void) lock_file(fd, B_FALSE, B_FALSE);
	(void) unlink(ks_desc_file);
	(void) close(fd);
	(void) rmdir(get_keystore_path());
	(void) rmdir(pub_obj_path);
	(void) rmdir(pri_obj_path);
	return (-1);
}

/*
 * Determines if the file referenced by "fd" has the same
 * inode as the file referenced by "fname".
 *
 * The argument "same" contains the result of determining
 * if the inode is the same or not
 *
 * Returns 0 if there's no error.
 * Returns 1 if there's any error with opening the file.
 *
 *
 */
static int
is_inode_same(int fd, char *fname, boolean_t *same)
{
	struct stat fn_stat, fd_stat;

	if (fstat(fd, &fd_stat) != 0) {
		return (-1);
	}

	if (stat(fname, &fn_stat) != 0) {
		return (-1);
	}

	/* It's the same file if both st_ino and st_dev match */
	if ((fd_stat.st_ino == fn_stat.st_ino) &&
	    (fd_stat.st_dev == fn_stat.st_dev)) {
		*same = B_TRUE;
	} else {
		*same = B_FALSE;
	}
	return (0);
}

static int
acquire_file_lock(int *fd, char *fname, mode_t mode)
{
	boolean_t read_lock = B_TRUE, same_inode;

	if ((mode == O_RDWR) || (mode == O_WRONLY)) {
		read_lock = B_FALSE;
	}

	if (lock_file(*fd, read_lock, B_TRUE) != 0) {
		return (-1);
	}

	/*
	 * make sure another process did not modify the file
	 * while we were trying to get the lock
	 */
	if (is_inode_same(*fd, fname, &same_inode) != 0) {
		(void) lock_file(*fd, B_TRUE, B_FALSE); /* unlock file */
		return (-1);
	}

	while (!same_inode) {
		/*
		 * need to unlock file, close, re-open the file,
		 * and re-acquire the lock
		 */

		/* unlock file */
		if (lock_file(*fd, B_TRUE, B_FALSE) != 0) {
			return (-1);
		}

		(void) close(*fd);

		/* re-open */
		*fd = open_nointr(fname, mode|O_NONBLOCK);
		if (*fd < 0) {
			return (-1);
		}

		/* acquire lock again */
		if (lock_file(*fd, read_lock, B_TRUE) != 0) {
			return (-1);
		}

		if (is_inode_same(*fd, fname, &same_inode) != 0) {
			(void) lock_file(*fd, B_TRUE, B_FALSE); /* unlock */
			return (-1);
		}

	}

	return (0);
}

/*
 * Open the keystore description file in the specified mode.
 * If the keystore doesn't exist, the "do_create_keystore"
 * argument determines if the keystore should be created
 */
static int
open_and_lock_keystore_desc(mode_t mode, boolean_t do_create_keystore,
    boolean_t lock_held)
{

	int fd;
	char *fname, ks_desc_file[MAXPATHLEN];

	/* open the keystore description file in requested mode */
	fname = get_desc_file_path(ks_desc_file);
	fd = open_nointr(fname, mode|O_NONBLOCK);
	if (fd < 0) {
		if ((errno == ENOENT) && (do_create_keystore)) {
			if (create_keystore() < 0) {
				goto done;
			}
			fd = open_nointr(fname, mode|O_NONBLOCK);
			if (fd < 0) {
				goto done;
			}
		} else {
			goto done;
		}
	}

	if (lock_held) {
		/* already hold the lock */
		return (fd);
	}

	if (acquire_file_lock(&fd, fname, mode) != 0) {
		if (fd > 0) {
			(void) close(fd);
		}
		return (-1);
	}

done:
	return (fd);
}


/*
 * Set or remove read or write lock on keystore description file
 *
 * read_lock: true for read lock, false for write lock
 * set_lock: true for set a lock, false to remove a lock
 */
static int
lock_desc_file(boolean_t read_lock, boolean_t set_lock)
{

	char ks_desc_file[MAXPATHLEN];

	if (set_lock) {
		int oflag;

		/*
		 * make sure desc_fd is not already used.  If used, it means
		 * some other lock is already set on the file
		 */
		if (desc_fd > 0) {
			return (-1);
		}

		(void) get_desc_file_path(ks_desc_file);

		if (read_lock) {
			oflag = O_RDONLY;
		} else {
			oflag = O_WRONLY;
		}
		if ((desc_fd = open_and_lock_keystore_desc(oflag,
		    B_FALSE, B_FALSE)) < 0) {
			return (-1);
		}
	} else {
		/* make sure we have a valid fd */
		if (desc_fd <= 0) {
			return (-1);
		}

		if (lock_file(desc_fd, read_lock, B_FALSE) == 1) {
			return (-1);
		}

		(void) close(desc_fd);
		desc_fd = 0;

	}
	return (0);
}

static int
open_and_lock_object_file(ks_obj_handle_t *ks_handle, int oflag,
    boolean_t lock_held)
{
	char obj_fname[MAXPATHLEN];
	int fd;

	if (ks_handle->public) {
		char pub_obj_path[MAXPATHLEN];
		(void) snprintf(obj_fname, MAXPATHLEN, "%s/%s",
		    get_pub_obj_path(pub_obj_path), ks_handle->name);
	} else {
		char pri_obj_path[MAXPATHLEN];
		(void) snprintf(obj_fname, MAXPATHLEN, "%s/%s",
		    get_pri_obj_path(pri_obj_path), ks_handle->name);
	}

	fd = open_nointr(obj_fname, oflag|O_NONBLOCK);
	if (fd < 0) {
		return (-1);
	}

	if (lock_held) {
		/* already hold the lock */
		return (fd);
	}

	if (acquire_file_lock(&fd, obj_fname, oflag) != 0) {
		if (fd > 0) {
			(void) close(fd);
		}
		return (-1);
	}


	return (fd);
}


/*
 * Update file version number in a temporary file that's
 * a copy of the keystore description file.
 * The update is NOT made to the original keystore description
 * file.  It makes the update in a tempoary file.
 *
 * Name of the temporary file is assumed to be provided, but
 * the file is assumed to not exist.
 *
 * return 0 if creating temp file is successful, returns -1 otherwise
 */
static int
create_updated_keystore_version(int fd, char *tmp_fname)
{
	int version, tmp_fd;
	char buf[BUFSIZ];
	size_t nread;

	/* first, create the tempoary file */
	tmp_fd = open_nointr(tmp_fname,
	    O_WRONLY|O_CREAT|O_EXCL|O_NONBLOCK, S_IRUSR|S_IWUSR);
	if (tmp_fd < 0) {
		return (-1);
	}

	/*
	 * copy everything from keystore version to temp file except
	 * the keystore version.  Keystore version is updated
	 *
	 */

	/* pkcs11 version */
	if (readn_nointr(fd, buf, KS_PKCS11_VER_SIZE) != KS_PKCS11_VER_SIZE) {
		goto cleanup;
	}

	if (writen_nointr(tmp_fd, buf, KS_PKCS11_VER_SIZE) !=
	    KS_PKCS11_VER_SIZE) {
		goto cleanup;
	}

	/* version number, it needs to be updated */

	/* read the current version number */
	if (readn_nointr(fd, &version, KS_VER_SIZE) != KS_VER_SIZE) {
		goto cleanup;
	}

	version = SWAP32(version);
	version++;
	version = SWAP32(version);

	/* write the updated value to the tmp file */
	if (writen_nointr(tmp_fd, (void *)&version, KS_VER_SIZE)
	    != KS_VER_SIZE) {
		goto cleanup;
	}

	/* read rest of information, nothing needs to be updated */
	nread = readn_nointr(fd, buf, BUFSIZ);
	while (nread > 0) {
		if (writen_nointr(tmp_fd, buf, nread) != nread) {
			goto cleanup;
		}
		nread = readn_nointr(fd, buf, BUFSIZ);
	}

	(void) close(tmp_fd);
	return (0);	/* no error */

cleanup:
	(void) close(tmp_fd);
	(void) remove(tmp_fname);
	return (-1);
}

static CK_RV
get_all_objs_in_dir(DIR *dirp, ks_obj_handle_t *ks_handle,
    ks_obj_t **result_obj_list, boolean_t lock_held)
{
	struct dirent *dp;
	ks_obj_t *obj;
	CK_RV rv;

	while ((dp = readdir(dirp)) != NULL) {

		if (strncmp(dp->d_name, OBJ_PREFIX, OBJ_PREFIX_LEN) != 0)
			continue;

		(void) strcpy((char *)ks_handle->name, dp->d_name);
		rv = soft_keystore_get_single_obj(ks_handle, &obj, lock_held);
		if (rv != CKR_OK) {
			return (rv);
		}
		if (obj != NULL) {
			if (*result_obj_list == NULL) {
				*result_obj_list = obj;
			} else {
				obj->next = *result_obj_list;
				*result_obj_list = obj;
			}
		}
	}
	return (CKR_OK);
}

/*
 * This function prepares the obj data for encryption by prepending
 * the FULL path of the file that will be used for storing
 * the object.  Having full path of the file as part of
 * of the data for the object will prevent an attacker from
 * copying a "bad" object into the keystore undetected.
 *
 * This function will always allocate:
 *	MAXPATHLEN + buf_len
 * amount of data.  If the full path of the filename doesn't occupy
 * the whole MAXPATHLEN, the rest of the space will just be empty.
 * It is the caller's responsibility to free the buffer allocated here.
 *
 * The allocated buffer is returned in the variable "prepared_buf"
 * if there's no error.
 *
 * Returns 0 if there's no error, -1 otherwise.
 */
static int
prepare_data_for_encrypt(char *obj_path, unsigned char *buf, CK_ULONG buf_len,
    unsigned char **prepared_buf, CK_ULONG *prepared_len)
{
	*prepared_len = MAXPATHLEN + buf_len;
	*prepared_buf = malloc(*prepared_len);
	if (*prepared_buf == NULL) {
		return (-1);
	}

	/*
	 * only zero out the space for the path name.  I could zero out
	 * the whole buffer, but that will be a waste of processing
	 * cycle since the rest of the buffer will be 100% filled all
	 * the time
	 */
	bzero(*prepared_buf, MAXPATHLEN);
	(void) memcpy(*prepared_buf, obj_path, strlen(obj_path));
	(void) memcpy(*prepared_buf + MAXPATHLEN, buf, buf_len);
	return (0);
}

/*
 * retrieves the hashed pin from the keystore
 */
static CK_RV
get_hashed_pin(int fd, char **hashed_pin)
{
	uint64_t hashed_pin_size;

	if (ks_hashed_pinlen_offset == -1) {
		if (calculate_hashed_pin_offset(fd) != 0) {
			return (CKR_FUNCTION_FAILED);
		}
	}

	/* first, get size of the hashed pin */
	if (lseek(fd, ks_hashed_pinlen_offset, SEEK_SET)
	    != ks_hashed_pinlen_offset) {
		return (CKR_FUNCTION_FAILED);
	}

	if (readn_nointr(fd, (char *)&hashed_pin_size,
	    KS_HASHED_PINLEN_SIZE) != KS_HASHED_PINLEN_SIZE) {
		return (CKR_FUNCTION_FAILED);
	}

	hashed_pin_size = SWAP64(hashed_pin_size);

	*hashed_pin = malloc(hashed_pin_size + 1);
	if (*hashed_pin == NULL) {
		return (CKR_HOST_MEMORY);
	}

	if ((readn_nointr(fd, *hashed_pin, hashed_pin_size))
	    != (ssize_t)hashed_pin_size) {
		freezero(*hashed_pin, hashed_pin_size + 1);
		*hashed_pin = NULL;
		return (CKR_FUNCTION_FAILED);
	}
	(*hashed_pin)[hashed_pin_size] = '\0';
	return (CKR_OK);
}


/*
 *	FUNCTION: soft_keystore_lock
 *
 *	ARGUMENTS:
 *		set_lock: TRUE to set readlock on the keystore object file,
 *		          FALSE to remove readlock on keystore object file.
 *
 *	RETURN VALUE:
 *
 *		0: success
 *		-1: failure
 *
 *	DESCRIPTION:
 *
 *		set or remove readlock on the keystore description file.
 */
int
soft_keystore_readlock(boolean_t set_lock)
{

	return (lock_desc_file(B_TRUE, set_lock));
}


/*
 *	FUNCTION: soft_keystore_writelock
 *
 *	ARGUMENTS:
 *		set_lock: TRUE to set writelock on the keystore description file
 *			FALSE to remove write lock on keystore description file.
 *
 *	RETURN VALUE:
 *
 *		0: no error
 *		1: some error occurred
 *
 *	DESCRIPTION:
 *		set/reset writelock on the keystore description file.
 */
int
soft_keystore_writelock(boolean_t set_lock)
{
	return (lock_desc_file(B_FALSE, set_lock));

}

/*
 *
 *	FUNCTION: soft_keystore_lock_object
 *
 *	ARGUMENTS:
 *
 *		ks_handle: handle of the keystore object file to be accessed.
 *		read_lock: TRUE to set readlock on the keystore object file,
 *			  FALSE to set writelock on keystore object file.
 *
 *	RETURN VALUE:
 *
 *		If no error, file descriptor of locked file will be returned
 *		-1: some error occurred
 *
 *	DESCRIPTION:
 *
 *		set readlock or writelock on the keystore object file.
 */
int
soft_keystore_lock_object(ks_obj_handle_t *ks_handle, boolean_t read_lock)
{
	int fd;
	int oflag;

	if (read_lock) {
		oflag = O_RDONLY;
	} else {
		oflag = O_WRONLY;
	}

	if ((fd = open_and_lock_object_file(ks_handle, oflag, B_FALSE)) < 0) {
		return (-1);
	}

	return (fd);
}

/*
 *	FUNCTION: soft_keystore_unlock_object
 *
 *	ARGUMENTS:
 *		fd: file descriptor returned from soft_keystore_lock_object
 *
 *	RETURN VALUE:
 *		0: no error
 *		1: some error occurred while getting the pin
 *
 *	DESCRIPTION:
 *		set/reset writelock on the keystore object file.
 */
int
soft_keystore_unlock_object(int fd)
{
	if (lock_file(fd, B_TRUE, B_FALSE) != 0) {
		return (1);
	}

	(void) close(fd);
	return (0);
}



/*
 *	FUNCTION: soft_keystore_get_version
 *
 *	ARGUMENTS:
 *		version: pointer to caller allocated memory for storing
 *			 the version of the keystore.
 *		lock_held: TRUE if the lock is held by caller.
 *
 *	RETURN VALUE:
 *
 *		0: no error
 *		-1: some error occurred while getting the version number
 *
 *	DESCRIPTION:
 *		get the version number of the keystore from keystore
 *		description file.
 */
int
soft_keystore_get_version(uint_t *version, boolean_t lock_held)
{
	int fd, ret_val = 0;
	uint_t buf;

	if ((fd = open_and_lock_keystore_desc(O_RDONLY,
	    B_FALSE, lock_held)) < 0) {
		return (-1);
	}

	if (lseek(fd, KS_VER_OFFSET, SEEK_SET) != KS_VER_OFFSET) {
		ret_val = -1;
		goto cleanup;
	}

	if (readn_nointr(fd, (char *)&buf, KS_VER_SIZE) != KS_VER_SIZE) {
		ret_val = -1;
		goto cleanup;
	}
	*version = SWAP32(buf);

cleanup:

	if (!lock_held) {
		if (lock_file(fd, B_TRUE, B_FALSE) < 0) {
			ret_val = -1;
		}
	}

	(void) close(fd);
	return (ret_val);
}

/*
 *	FUNCTION: soft_keystore_get_object_version
 *
 *	ARGUMENTS:
 *
 *		ks_handle: handle of the key store object to be accessed.
 *		version:
 *			pointer to caller allocated memory for storing
 *			the version of the object.
 *		lock_held: TRUE if the lock is held by caller.
 *
 *	RETURN VALUE:
 *
 *		0: no error
 *		-1: some error occurred while getting the pin
 *
 *	DESCRIPTION:
 *		get the version number of the specified token object.
 */
int
soft_keystore_get_object_version(ks_obj_handle_t *ks_handle,
    uint_t *version, boolean_t lock_held)
{
	int fd, ret_val = 0;
	uint_t tmp;

	if ((fd = open_and_lock_object_file(ks_handle, O_RDONLY,
	    lock_held)) < 0) {
		return (-1);
	}

	/*
	 * read version.  Version is always first item in object file
	 * so, no need to do lseek
	 */
	if (readn_nointr(fd, (char *)&tmp, OBJ_VER_SIZE) != OBJ_VER_SIZE) {
		ret_val = -1;
		goto cleanup;
	}

	*version = SWAP32(tmp);

cleanup:
	if (!lock_held) {
		if (lock_file(fd, B_TRUE, B_FALSE) < 0) {
			ret_val = -1;
		}
	}


	(void) close(fd);
	return (ret_val);
}

/*
 *		FUNCTION: soft_keystore_getpin
 *
 *		ARGUMENTS:
 *			hashed_pin: pointer to caller allocated memory
 *				for storing the pin to be returned.
 *			lock_held: TRUE if the lock is held by caller.
 *
 *		RETURN VALUE:
 *
 *			0: no error
 *			-1: some error occurred while getting the pin
 *
 *		DESCRIPTION:
 *
 *			Reads the MD5 hash from the keystore description
 *			file and return it to the caller in the provided
 *			buffer. If there is no PIN in the description file
 *			because the file is just created, this function
 *			will get a MD5 digest of the string "changeme",
 *			store it in the file, and also return this
 *			string to the caller.
 */
int
soft_keystore_getpin(char **hashed_pin, boolean_t lock_held)
{
	int fd, ret_val = -1;
	CK_RV rv;

	if ((fd = open_and_lock_keystore_desc(O_RDONLY, B_FALSE,
	    lock_held)) < 0) {
		return (-1);
	}

	rv = get_hashed_pin(fd, hashed_pin);
	if (rv == CKR_OK) {
		ret_val = 0;
	}

cleanup:
	if (!lock_held) {
		if (lock_file(fd, B_TRUE, B_FALSE) < 0) {
			ret_val = -1;
		}
	}

	(void) close(fd);
	return (ret_val);
}


/*
 * Generate a 16-byte Initialization Vector (IV).
 */
CK_RV
soft_gen_iv(CK_BYTE *iv)
{
	return (pkcs11_get_nzero_urandom(iv, 16) < 0 ?
	    CKR_DEVICE_ERROR : CKR_OK);
}


/*
 * This function reads all the data until the end of the file, and
 * put the data into the "buf" in argument.  Memory for buf will
 * be allocated in this function.  It is the caller's responsibility
 * to free it.  The number of bytes read will be returned
 * in the argument "bytes_read"
 *
 * returns CKR_OK if no error.  Other CKR error codes if there's an error
 */
static CK_RV
read_obj_data(int old_fd, char **buf, ssize_t *bytes_read)
{

	ssize_t nread, loop_count;
	char *buf1 = NULL;

	*buf = malloc(BUFSIZ);
	if (*buf == NULL) {
		return (CKR_HOST_MEMORY);
	}

	nread = readn_nointr(old_fd, *buf, BUFSIZ);
	if (nread < 0) {
		free(*buf);
		return (CKR_FUNCTION_FAILED);
	}
	loop_count = 1;
	while (nread == (loop_count * BUFSIZ)) {
		ssize_t nread_tmp;

		loop_count++;
		/* more than BUFSIZ of data */
		buf1 = realloc(*buf, loop_count * BUFSIZ);
		if (buf1 == NULL) {
			free(*buf);
			return (CKR_HOST_MEMORY);
		}
		*buf = buf1;
		nread_tmp = readn_nointr(old_fd,
		    *buf + ((loop_count - 1) * BUFSIZ), BUFSIZ);
		if (nread_tmp < 0) {
			free(*buf);
			return (CKR_FUNCTION_FAILED);
		}
		nread += nread_tmp;
	}
	*bytes_read = nread;
	return (CKR_OK);
}

/*
 * Re-encrypt an object using the provided new_enc_key.  The new HMAC
 * is calculated using the new_hmac_key.  The global static variables
 * enc_key, and hmac_key will be used for decrypting the original
 * object, and verifying its signature.
 *
 * The re-encrypted object will be stored in the file named
 * in the "new_obj_name" variable.  The content of the "original"
 * file named in "orig_obj_name" is not disturbed.
 *
 * Returns 0 if there's no error, returns -1 otherwise.
 *
 */
static int
reencrypt_obj(soft_object_t *new_enc_key, soft_object_t *new_hmac_key,
    char *orig_obj_name, char *new_obj_name)
{
	int old_fd, new_fd, version, ret_val = -1;
	CK_BYTE iv[OBJ_IV_SIZE], old_iv[OBJ_IV_SIZE];
	ssize_t nread;
	CK_ULONG decrypted_len, encrypted_len, hmac_len;
	CK_BYTE hmac[OBJ_HMAC_SIZE], *decrypted_buf = NULL, *buf = NULL;

	old_fd = open_nointr(orig_obj_name, O_RDONLY|O_NONBLOCK);
	if (old_fd < 0) {
		return (-1);
	}

	if (acquire_file_lock(&old_fd, orig_obj_name, O_RDONLY) != 0) {
		if (old_fd > 0) {
			(void) close(old_fd);
		}
		return (-1);
	}

	new_fd = open_nointr(new_obj_name,
	    O_WRONLY|O_CREAT|O_EXCL|O_NONBLOCK, S_IRUSR|S_IWUSR);
	if (new_fd < 0) {
		(void) close(old_fd);
		return (-1);
	}

	if (lock_file(new_fd, B_FALSE, B_TRUE) != 0) {
		/* unlock old file */
		(void) lock_file(old_fd, B_TRUE, B_FALSE);
		(void) close(old_fd);
		(void) close(new_fd);
		return (-1);
	}

	/* read version, increment, and write to tmp file */
	if (readn_nointr(old_fd, (char *)&version, OBJ_VER_SIZE)
	    != OBJ_VER_SIZE) {
		goto cleanup;
	}

	version = SWAP32(version);
	version++;
	version = SWAP32(version);

	if (writen_nointr(new_fd, (char *)&version, OBJ_VER_SIZE)
	    != OBJ_VER_SIZE) {
		goto cleanup;
	}

	/* read old iv */
	if (readn_nointr(old_fd, (char *)old_iv, OBJ_IV_SIZE) != OBJ_IV_SIZE) {
		goto cleanup;
	}

	/* generate new IV */
	if (soft_gen_iv(iv) != CKR_OK) {
		goto cleanup;
	}

	if (writen_nointr(new_fd, (char *)iv, OBJ_IV_SIZE) != OBJ_IV_SIZE) {
		goto cleanup;
	}

	/* seek to the original encrypted data, and read all of them */
	if (lseek(old_fd, OBJ_DATA_OFFSET, SEEK_SET) != OBJ_DATA_OFFSET) {
		goto cleanup;
	}

	if (read_obj_data(old_fd, (char **)&buf, &nread) != CKR_OK) {
		goto cleanup;
	}

	/* decrypt data using old key */
	decrypted_len = 0;
	if (soft_keystore_crypt(enc_key, old_iv, B_FALSE, buf, nread,
	    NULL, &decrypted_len) != CKR_OK) {
		freezero(buf, nread);
		goto cleanup;
	}

	decrypted_buf = malloc(decrypted_len);
	if (decrypted_buf == NULL) {
		freezero(buf, nread);
		goto cleanup;
	}

	if (soft_keystore_crypt(enc_key, old_iv, B_FALSE, buf, nread,
	    decrypted_buf, &decrypted_len) != CKR_OK) {
		freezero(buf, nread);
		freezero(decrypted_buf, decrypted_len);
	}

	freezero(buf, nread);

	/* re-encrypt with new key */
	encrypted_len = 0;
	if (soft_keystore_crypt(new_enc_key, iv, B_TRUE, decrypted_buf,
	    decrypted_len, NULL, &encrypted_len) != CKR_OK) {
		freezero(decrypted_buf, decrypted_len);
		goto cleanup;
	}

	buf = malloc(encrypted_len);
	if (buf == NULL) {
		freezero(decrypted_buf, decrypted_len);
		goto cleanup;
	}

	if (soft_keystore_crypt(new_enc_key, iv, B_TRUE, decrypted_buf,
	    decrypted_len, buf, &encrypted_len) != CKR_OK) {
		freezero(buf, encrypted_len);
		freezero(buf, decrypted_len);
		goto cleanup;
	}

	freezero(decrypted_buf, decrypted_len);

	/* calculate hmac on re-encrypted data using new hmac key */
	hmac_len = OBJ_HMAC_SIZE;
	if (soft_keystore_hmac(new_hmac_key, B_TRUE, buf,
	    encrypted_len, hmac, &hmac_len) != CKR_OK) {
		freezero(buf, encrypted_len);
		goto cleanup;
	}

	/* just for sanity check */
	if (hmac_len != OBJ_HMAC_SIZE) {
		freezero(buf, encrypted_len);
		goto cleanup;
	}

	/* write new hmac */
	if (writen_nointr(new_fd, (char *)hmac, OBJ_HMAC_SIZE)
	    != OBJ_HMAC_SIZE) {
		freezero(buf, encrypted_len);
		goto cleanup;
	}

	/* write re-encrypted buffer to temp file */
	if (writen_nointr(new_fd, (void *)buf, encrypted_len)
	    != encrypted_len) {
		freezero(buf, encrypted_len);
		goto cleanup;
	}
	freezero(buf, encrypted_len);
	ret_val = 0;

cleanup:
	/* unlock the files */
	(void) lock_file(old_fd, B_TRUE, B_FALSE);
	(void) lock_file(new_fd, B_FALSE, B_FALSE);

	(void) close(old_fd);
	(void) close(new_fd);
	if (ret_val != 0) {
		(void) remove(new_obj_name);
	}
	return (ret_val);
}

/*
 *	FUNCTION: soft_keystore_setpin
 *
 *	ARGUMENTS:
 *		newpin: new pin entered by the user.
 *		lock_held: TRUE if the lock is held by caller.
 *
 *	RETURN VALUE:
 *		0: no error
 *		-1: failure
 *
 *	DESCRIPTION:
 *
 *		This function does the following:
 *
 *		1) Generates crypted value of newpin and store it
 *		   in keystore description file.
 *		2) Dervies the new encryption key from the newpin.  This key
 *		   will be used to re-encrypt the private token objects.
 *		3) Re-encrypt all of this user's existing private token
 *		   objects (if any).
 *		4) Increments the keystore version number.
 */
int
soft_keystore_setpin(uchar_t *oldpin, uchar_t *newpin, boolean_t lock_held)
{
	int fd, tmp_ks_fd, version, ret_val = -1;
	soft_object_t *new_crypt_key = NULL, *new_hmac_key = NULL;
	char filebuf[BUFSIZ];
	DIR	*pri_dirp;
	struct dirent *pri_ent;
	char pri_obj_path[MAXPATHLEN], ks_desc_file[MAXPATHLEN],
	    tmp_ks_desc_name[MAXPATHLEN];
	typedef struct priobjs {
		char orig_name[MAXPATHLEN];
		char tmp_name[MAXPATHLEN];
		struct priobjs *next;
	} priobjs_t;
	priobjs_t *pri_objs = NULL, *tmp;
	CK_BYTE *crypt_salt = NULL, *hmac_salt = NULL;
	boolean_t pin_never_set = B_FALSE, user_logged_in;
	char *new_hashed_pin = NULL;
	uint64_t hashed_pin_salt_length, new_hashed_pin_len, swaped_val;
	char *hashed_pin_salt = NULL;
	priobjs_t *obj;

	if ((enc_key == NULL) ||
	    (enc_key->magic_marker != SOFTTOKEN_OBJECT_MAGIC)) {
		user_logged_in = B_FALSE;
	} else {
		user_logged_in = B_TRUE;
	}

	if ((fd = open_and_lock_keystore_desc(O_RDWR, B_TRUE,
	    lock_held)) < 0) {
		return (-1);
	}

	(void) get_desc_file_path(ks_desc_file);
	(void) get_tmp_desc_file_path(tmp_ks_desc_name);

	/*
	 * create a tempoary file for the keystore description
	 * file for updating version and counter information
	 */
	tmp_ks_fd = open_nointr(tmp_ks_desc_name,
	    O_RDWR|O_CREAT|O_EXCL|O_NONBLOCK, S_IRUSR|S_IWUSR);
	if (tmp_ks_fd < 0) {
		(void) close(fd);
		return (-1);
	}

	/* read and write PKCS version to temp file */
	if (readn_nointr(fd, filebuf, KS_PKCS11_VER_SIZE)
	    != KS_PKCS11_VER_SIZE) {
		goto cleanup;
	}

	if (writen_nointr(tmp_ks_fd, filebuf, KS_PKCS11_VER_SIZE)
	    != KS_PKCS11_VER_SIZE) {
		goto cleanup;
	}

	/* get version number, and write updated number to temp file */
	if (readn_nointr(fd, &version, KS_VER_SIZE) != KS_VER_SIZE) {
		goto cleanup;
	}

	version = SWAP32(version);
	version++;
	version = SWAP32(version);

	if (writen_nointr(tmp_ks_fd, (void *)&version, KS_VER_SIZE)
	    != KS_VER_SIZE) {
		goto cleanup;
	}


	/* read and write counter, no modification necessary */
	if (readn_nointr(fd, filebuf, KS_COUNTER_SIZE) != KS_COUNTER_SIZE) {
		goto cleanup;
	}

	if (writen_nointr(tmp_ks_fd, filebuf, KS_COUNTER_SIZE)
	    != KS_COUNTER_SIZE) {
		goto cleanup;
	}

	/* read old encryption salt */
	crypt_salt = malloc(KS_KEY_SALT_SIZE);
	if (crypt_salt == NULL) {
		goto cleanup;
	}
	if (readn_nointr(fd, (char *)crypt_salt, KS_KEY_SALT_SIZE)
	    != KS_KEY_SALT_SIZE) {
		goto cleanup;
	}

	/* read old hmac salt */
	hmac_salt = malloc(KS_HMAC_SALT_SIZE);
	if (hmac_salt == NULL) {
		goto cleanup;
	}
	if (readn_nointr(fd, (char *)hmac_salt, KS_HMAC_SALT_SIZE)
	    != KS_HMAC_SALT_SIZE) {
		goto cleanup;
	}

	/* just create some empty bytes */
	bzero(filebuf, sizeof (filebuf));

	if (memcmp(crypt_salt, filebuf, KS_KEY_SALT_SIZE) == 0) {
		/* PIN as never been set */
		CK_BYTE *new_crypt_salt = NULL, *new_hmac_salt = NULL;

		pin_never_set = B_TRUE;
		if (soft_gen_crypt_key(newpin, &new_crypt_key, &new_crypt_salt)
		    != CKR_OK) {
			goto cleanup;
		}
		if (writen_nointr(tmp_ks_fd, (void *)new_crypt_salt,
		    KS_KEY_SALT_SIZE) != KS_KEY_SALT_SIZE) {
			freezero(new_crypt_salt,
			    KS_KEY_SALT_SIZE);
			(void) soft_cleanup_object(new_crypt_key);
			goto cleanup;
		}
		freezero(new_crypt_salt, KS_KEY_SALT_SIZE);

		if (soft_gen_hmac_key(newpin, &new_hmac_key, &new_hmac_salt)
		    != CKR_OK) {
			(void) soft_cleanup_object(new_crypt_key);
			goto cleanup;
		}
		if (writen_nointr(tmp_ks_fd, (void *)new_hmac_salt,
		    KS_HMAC_SALT_SIZE) != KS_HMAC_SALT_SIZE) {
			freezero(new_hmac_salt,
			    KS_HMAC_SALT_SIZE);
			goto cleanup3;
		}
		freezero(new_hmac_salt, KS_HMAC_SALT_SIZE);
	} else {
		if (soft_gen_crypt_key(newpin, &new_crypt_key,
		    (CK_BYTE **)&crypt_salt) != CKR_OK) {
			goto cleanup;
		}
		/* no change to the encryption salt */
		if (writen_nointr(tmp_ks_fd, (void *)crypt_salt,
		    KS_KEY_SALT_SIZE) != KS_KEY_SALT_SIZE) {
			(void) soft_cleanup_object(new_crypt_key);
			goto cleanup;
		}

		if (soft_gen_hmac_key(newpin, &new_hmac_key,
		    (CK_BYTE **)&hmac_salt) != CKR_OK) {
			(void) soft_cleanup_object(new_crypt_key);
			goto cleanup;
		}

		/* no change to the hmac salt */
		if (writen_nointr(tmp_ks_fd, (void *)hmac_salt,
		    KS_HMAC_SALT_SIZE) != KS_HMAC_SALT_SIZE) {
			goto cleanup3;
		}
	}

	/*
	 * read hashed pin salt, and write to updated keystore description
	 * file unmodified.
	 */
	if (readn_nointr(fd, (char *)&hashed_pin_salt_length,
	    KS_HASHED_PIN_SALT_LEN_SIZE) != KS_HASHED_PIN_SALT_LEN_SIZE) {
		goto cleanup3;
	}

	if (writen_nointr(tmp_ks_fd, (void *)&hashed_pin_salt_length,
	    KS_HASHED_PIN_SALT_LEN_SIZE) != KS_HASHED_PIN_SALT_LEN_SIZE) {
		goto cleanup3;
	}

	hashed_pin_salt_length = SWAP64(hashed_pin_salt_length);

	hashed_pin_salt = malloc(hashed_pin_salt_length + 1);
	if (hashed_pin_salt == NULL) {
		goto cleanup3;
	}

	if ((readn_nointr(fd, hashed_pin_salt, hashed_pin_salt_length)) !=
	    (ssize_t)hashed_pin_salt_length) {
		freezero(hashed_pin_salt,
		    hashed_pin_salt_length + 1);
		goto cleanup3;
	}

	if ((writen_nointr(tmp_ks_fd, hashed_pin_salt, hashed_pin_salt_length))
	    != (ssize_t)hashed_pin_salt_length) {
		freezero(hashed_pin_salt,
		    hashed_pin_salt_length + 1);
		goto cleanup3;
	}

	hashed_pin_salt[hashed_pin_salt_length] = '\0';

	/* old hashed pin length and value can be ignored, generate new one */
	if (soft_gen_hashed_pin(newpin, &new_hashed_pin,
	    &hashed_pin_salt) < 0) {
		freezero(hashed_pin_salt,
		    hashed_pin_salt_length + 1);
		goto cleanup3;
	}

	freezero(hashed_pin_salt, hashed_pin_salt_length + 1);

	if (new_hashed_pin == NULL) {
		goto cleanup3;
	}

	new_hashed_pin_len = strlen(new_hashed_pin);

	/* write new hashed pin length to file */
	swaped_val = SWAP64(new_hashed_pin_len);
	if (writen_nointr(tmp_ks_fd, (void *)&swaped_val,
	    KS_HASHED_PINLEN_SIZE) != KS_HASHED_PINLEN_SIZE) {
		goto cleanup3;
	}

	if (writen_nointr(tmp_ks_fd, (void *)new_hashed_pin,
	    new_hashed_pin_len) != (ssize_t)new_hashed_pin_len) {
		goto cleanup3;
	}

	if (pin_never_set) {
		/* there was no private object, no need to re-encrypt them */
		goto rename_desc_file;
	}

	/* re-encrypt all the private objects */
	pri_dirp = opendir(get_pri_obj_path(pri_obj_path));
	if (pri_dirp == NULL) {
		/*
		 * this directory should exist, even if it doesn't contain
		 * any objects.  Don't want to update the pin if the
		 * keystore is somehow messed up.
		 */

		goto cleanup3;
	}

	/* if user did not login, need to set the old pin */
	if (!user_logged_in) {
		if (soft_keystore_authpin(oldpin) != 0) {
			goto cleanup3;
		}
	}

	while ((pri_ent = readdir(pri_dirp)) != NULL) {

		if ((strcmp(pri_ent->d_name, ".") == 0) ||
		    (strcmp(pri_ent->d_name, "..") == 0) ||
		    (strncmp(pri_ent->d_name, TMP_OBJ_PREFIX,
		    strlen(TMP_OBJ_PREFIX)) == 0)) {
			continue;
		}

		obj = malloc(sizeof (priobjs_t));
		if (obj == NULL) {
			goto cleanup2;
		}
		(void) snprintf(obj->orig_name, MAXPATHLEN,
		    "%s/%s", pri_obj_path, pri_ent->d_name);
		(void) snprintf(obj->tmp_name, MAXPATHLEN, "%s/%s%s",
		    pri_obj_path, TMP_OBJ_PREFIX,
		    (pri_ent->d_name) + OBJ_PREFIX_LEN);
		if (reencrypt_obj(new_crypt_key, new_hmac_key,
		    obj->orig_name, obj->tmp_name) != 0) {
			free(obj);
			goto cleanup2;
		}

		/* insert into list of file to be renamed */
		if (pri_objs == NULL) {
			obj->next = NULL;
			pri_objs = obj;
		} else {
			obj->next = pri_objs;
			pri_objs = obj;
		}
	}

	/* rename all the private objects */
	tmp = pri_objs;
	while (tmp) {
		(void) rename(tmp->tmp_name, tmp->orig_name);
		tmp = tmp->next;
	}

rename_desc_file:

	/* destroy the old encryption key, and hmac key */
	if ((!pin_never_set) && (user_logged_in)) {
		(void) soft_cleanup_object(enc_key);
		(void) soft_cleanup_object(hmac_key);
	}

	if (user_logged_in) {
		enc_key = new_crypt_key;
		hmac_key = new_hmac_key;
	}
	(void) rename(tmp_ks_desc_name, ks_desc_file);

	ret_val = 0;

cleanup2:
	if (pri_objs != NULL) {
		priobjs_t *p = pri_objs;
		while (p) {
			tmp = p->next;
			free(p);
			p = tmp;
		}
	}
	if (!pin_never_set) {
		(void) closedir(pri_dirp);
	}

	if ((!user_logged_in) && (!pin_never_set)) {
		(void) soft_cleanup_object(enc_key);
		(void) soft_cleanup_object(hmac_key);
		enc_key = NULL;
		hmac_key = NULL;
	}
cleanup3:
	if ((ret_val != 0) || (!user_logged_in)) {
		(void) soft_cleanup_object(new_crypt_key);
		(void) soft_cleanup_object(new_hmac_key);
	}

cleanup:
	if (!lock_held) {
		if (lock_file(fd, B_FALSE, B_FALSE) < 0) {
			ret_val = 1;
		}
	}
	freezero(crypt_salt, KS_KEY_SALT_SIZE);
	freezero(hmac_salt, KS_HMAC_SALT_SIZE);
	(void) close(fd);
	(void) close(tmp_ks_fd);
	if (ret_val != 0) {
		(void) remove(tmp_ks_desc_name);
	}
	return (ret_val);
}

/*
 *	FUNCTION: soft_keystore_authpin
 *
 *	ARGUMENTS:
 *		pin: pin specified by the user for logging into
 *		     the keystore.
 *
 *	RETURN VALUE:
 *		0: if no error
 *		-1: if there is any error
 *
 *	DESCRIPTION:
 *
 *		This function takes the pin specified in the argument
 *		and generates an encryption key based on the pin.
 *		The generated encryption key will be used for
 *		all future encryption and decryption for private
 *		objects.  Before this function is called, none
 *		of the keystore related interfaces is able
 *		to decrypt/encrypt any private object.
 */
int
soft_keystore_authpin(uchar_t  *pin)
{
	int fd;
	int ret_val = -1;
	CK_BYTE *crypt_salt = NULL, *hmac_salt;

	/* get the salt from the keystore description file */
	if ((fd = open_and_lock_keystore_desc(O_RDONLY,
	    B_FALSE, B_FALSE)) < 0) {
		return (-1);
	}

	crypt_salt = malloc(KS_KEY_SALT_SIZE);
	if (crypt_salt == NULL) {
		goto cleanup;
	}

	if (lseek(fd, KS_KEY_SALT_OFFSET, SEEK_SET) != KS_KEY_SALT_OFFSET) {
		goto cleanup;
	}

	if (readn_nointr(fd, (char *)crypt_salt, KS_KEY_SALT_SIZE)
	    != KS_KEY_SALT_SIZE) {
		goto cleanup;
	}

	if (soft_gen_crypt_key(pin, &enc_key, (CK_BYTE **)&crypt_salt)
	    != CKR_OK) {
		goto cleanup;
	}

	hmac_salt = malloc(KS_HMAC_SALT_SIZE);
	if (hmac_salt == NULL) {
		goto cleanup;
	}

	if (lseek(fd, KS_HMAC_SALT_OFFSET, SEEK_SET) != KS_HMAC_SALT_OFFSET) {
		goto cleanup;
	}

	if (readn_nointr(fd, (char *)hmac_salt, KS_HMAC_SALT_SIZE)
	    != KS_HMAC_SALT_SIZE) {
		goto cleanup;
	}

	if (soft_gen_hmac_key(pin, &hmac_key, (CK_BYTE **)&hmac_salt)
	    != CKR_OK) {
		goto cleanup;
	}

	ret_val = 0;

cleanup:
	/* unlock the file */
	(void) lock_file(fd, B_TRUE, B_FALSE);
	(void) close(fd);
	freezero(crypt_salt, KS_KEY_SALT_SIZE);
	freezero(hmac_salt, KS_HMAC_SALT_SIZE);
	return (ret_val);
}

/*
 *	FUNCTION: soft_keystore_get_objs
 *
 *	ARGUMENTS:
 *
 *		search_type: Specify type of objects to return.
 *		lock_held: TRUE if the lock is held by caller.
 *
 *
 *	RETURN VALUE:
 *
 *		NULL: if there are no object in the database.
 *
 *		Otherwise, linked list of objects as requested
 *		in search type.
 *
 *		The linked list returned will need to be freed
 *		by the caller.
 *
 *	DESCRIPTION:
 *
 *		Returns objects as requested.
 *
 *		If private objects is requested, and the caller
 *		has not previously passed in the pin or if the pin
 *		passed in is wrong, private objects will not
 *		be returned.
 *
 *		The buffers returned for private objects are already
 *		decrypted.
 */
CK_RV
soft_keystore_get_objs(ks_search_type_t search_type,
    ks_obj_t **result_obj_list, boolean_t lock_held)
{
	DIR *dirp;
	ks_obj_handle_t ks_handle;
	CK_RV rv;
	ks_obj_t *tmp;
	int ks_fd;

	*result_obj_list = NULL;

	/*
	 * lock the keystore description file in "read" mode so that
	 * objects won't get added/deleted/modified while we are
	 * doing the search
	 */
	if ((ks_fd = open_and_lock_keystore_desc(O_RDONLY, B_FALSE,
	    B_FALSE)) < 0) {
		return (CKR_FUNCTION_FAILED);
	}

	if ((search_type == ALL_TOKENOBJS) || (search_type == PUB_TOKENOBJS)) {

		char pub_obj_path[MAXPATHLEN];

		ks_handle.public = B_TRUE;

		if ((dirp = opendir(get_pub_obj_path(pub_obj_path))) == NULL) {
			(void) lock_file(ks_fd, B_TRUE, B_FALSE);
			(void) close(ks_fd);
			return (CKR_FUNCTION_FAILED);
		}
		rv = get_all_objs_in_dir(dirp, &ks_handle, result_obj_list,
		    lock_held);
		if (rv != CKR_OK) {
			(void) closedir(dirp);
			goto cleanup;
		}

		(void) closedir(dirp);
	}

	if ((search_type == ALL_TOKENOBJS) || (search_type == PRI_TOKENOBJS)) {

		char pri_obj_path[MAXPATHLEN];

		if ((enc_key == NULL) ||
		    (enc_key->magic_marker != SOFTTOKEN_OBJECT_MAGIC)) {
			/* has not login - no need to go any further */
			(void) lock_file(ks_fd, B_TRUE, B_FALSE);
			(void) close(ks_fd);
			return (CKR_OK);
		}

		ks_handle.public = B_FALSE;

		if ((dirp = opendir(get_pri_obj_path(pri_obj_path))) == NULL) {
			(void) lock_file(ks_fd, B_TRUE, B_FALSE);
			(void) close(ks_fd);
			return (CKR_OK);
		}
		rv = get_all_objs_in_dir(dirp, &ks_handle, result_obj_list,
		    lock_held);
		if (rv != CKR_OK) {
			(void) closedir(dirp);
			goto cleanup;
		}

		(void) closedir(dirp);
	}
	/* close the keystore description file */
	(void) lock_file(ks_fd, B_TRUE, B_FALSE);
	(void) close(ks_fd);
	return (CKR_OK);
cleanup:

	/* close the keystore description file */
	(void) lock_file(ks_fd, B_TRUE, B_FALSE);
	(void) close(ks_fd);

	/* free all the objects found before hitting the error */
	tmp = *result_obj_list;
	while (tmp) {
		*result_obj_list = tmp->next;
		freezero(tmp->buf, tmp->size);
		free(tmp);
		tmp = *result_obj_list;
	}
	*result_obj_list = NULL;
	return (rv);
}


/*
 *	FUNCTION: soft_keystore_get_single_obj
 *
 *	ARGUMENTS:
 *		ks_handle: handle of the key store object to be accessed
 *		lock_held: TRUE if the lock is held by caller.
 *
 *	RETURN VALUE:
 *
 *		NULL: if handle doesn't match any object
 *
 *		Otherwise, the object is returned in
 *		the same structure used in soft_keystore_get_objs().
 *		The structure need to be freed by the caller.
 *
 *	DESCRIPTION:
 *
 *		Retrieves the object specified by the object
 *		handle to the caller.
 *
 *		If a private object is requested, and the caller
 *		has not previously passed in the pin or if the pin
 *		passed in is wrong, the requested private object will not
 *		be returned.
 *
 *		The buffer returned for the requested private object
 *		is already decrypted.
 */
CK_RV
soft_keystore_get_single_obj(ks_obj_handle_t *ks_handle,
    ks_obj_t **return_obj, boolean_t lock_held)
{

	ks_obj_t *obj;
	uchar_t iv[OBJ_IV_SIZE], obj_hmac[OBJ_HMAC_SIZE];
	uchar_t *buf, *decrypted_buf;
	int fd;
	ssize_t nread;
	CK_RV rv = CKR_FUNCTION_FAILED;

	if (!(ks_handle->public)) {
		if ((enc_key == NULL) ||
		    (enc_key->magic_marker != SOFTTOKEN_OBJECT_MAGIC)) {
			return (CKR_FUNCTION_FAILED);
		}
	}

	if ((fd = open_and_lock_object_file(ks_handle, O_RDONLY,
	    lock_held)) < 0) {
		return (CKR_FUNCTION_FAILED);
	}

	obj = malloc(sizeof (ks_obj_t));
	if (obj == NULL) {
		return (CKR_HOST_MEMORY);
	}

	obj->next = NULL;

	(void) strcpy((char *)((obj->ks_handle).name),
	    (char *)ks_handle->name);
	(obj->ks_handle).public = ks_handle->public;

	/* 1st get the version */
	if (readn_nointr(fd, &(obj->obj_version), OBJ_VER_SIZE)
	    != OBJ_VER_SIZE) {
		goto cleanup;
	}
	obj->obj_version = SWAP32(obj->obj_version);

	/* Then, read the IV */
	if (readn_nointr(fd, iv, OBJ_IV_SIZE) != OBJ_IV_SIZE) {
		goto cleanup;
	}

	/* Then, read the HMAC */
	if (readn_nointr(fd, obj_hmac, OBJ_HMAC_SIZE) != OBJ_HMAC_SIZE) {
		goto cleanup;
	}

	/* read the object */
	rv = read_obj_data(fd, (char **)&buf, &nread);
	if (rv != CKR_OK) {
		goto cleanup;
	}

	if (ks_handle->public) {
		obj->size = nread;
		obj->buf = buf;
		*return_obj = obj;
	} else {

		CK_ULONG out_len = 0, hmac_size;

		/* verify HMAC of the object, make sure it matches */
		hmac_size = OBJ_HMAC_SIZE;
		if (soft_keystore_hmac(hmac_key, B_FALSE, buf,
		    nread, obj_hmac, &hmac_size) != CKR_OK) {
			freezero(buf, nread);
			rv = CKR_FUNCTION_FAILED;
			goto cleanup;
		}

		/* decrypt object */
		if (soft_keystore_crypt(enc_key, iv, B_FALSE, buf, nread,
		    NULL, &out_len) != CKR_OK) {
			freezero(buf, nread);
			rv = CKR_FUNCTION_FAILED;
			goto cleanup;
		}

		decrypted_buf = malloc(sizeof (uchar_t) * out_len);
		if (decrypted_buf == NULL) {
			freezero(buf, nread);
			rv = CKR_HOST_MEMORY;
			goto cleanup;
		}

		if (soft_keystore_crypt(enc_key, iv, B_FALSE, buf, nread,
		    decrypted_buf, &out_len) != CKR_OK) {
			freezero(buf, nread);
			freezero(decrypted_buf, out_len);
			rv = CKR_FUNCTION_FAILED;
			goto cleanup;
		}

		obj->size = out_len - MAXPATHLEN;

		/*
		 * decrypted buf here actually contains full path name of
		 * object plus the actual data.  so, need to skip the
		 * full pathname.
		 * See prepare_data_for_encrypt() function in the file
		 * to understand how and why the pathname is added.
		 */
		obj->buf = malloc(sizeof (uchar_t) * (out_len - MAXPATHLEN));
		if (obj->buf == NULL) {
			freezero(buf, nread);
			freezero(decrypted_buf, out_len);
			rv = CKR_HOST_MEMORY;
			goto cleanup;
		}
		(void) memcpy(obj->buf, decrypted_buf + MAXPATHLEN, obj->size);
		freezero(buf, nread);
		freezero(decrypted_buf, out_len);
		*return_obj = obj;
	}

cleanup:

	if (rv != CKR_OK) {
		free(obj);
	}

	/* unlock the file after reading */
	if (!lock_held) {
		(void) lock_file(fd, B_TRUE, B_FALSE);
	}

	(void) close(fd);

	return (rv);
}


/*
 *	FUNCTION: soft_keystore_put_new_obj
 *
 *	ARGUMENTS:
 *		buf: buffer containing un-encrypted data
 *		     to be stored in keystore.
 *		len: length of data
 *		public:  TRUE if it is a public object,
 *			 FALSE if it is private obj
 *		lock_held: TRUE if the lock is held by caller.
 *		keyhandle: pointer to object handle to
 *			   receive keyhandle for new object
 *
 *	RETURN VALUE:
 *		0: object successfully stored in file
 *		-1: some error occurred, object is not stored in file.
 *
 *	DESCRIPTION:
 *		This API is used to write a newly created token object
 *		to keystore.
 *
 *		This function does the following:
 *
 *		1) Creates a token object file based on "public" parameter.
 *		2) Generates a new IV and stores it in obj_meta_data_t if it is
 *		   private object.
 *		3) Set object version number to 1.
 *		4) If it is a private object, it will be encrypted before
 *		   being written to the newly created keystore token object
 *		   file.
 *		5) Calculates the obj_chksum in obj_meta_data_t.
 *		6) Calculates the pin_chksum in obj_meta_data_t.
 *		7) Increments the keystore version number.
 */
int
soft_keystore_put_new_obj(uchar_t *buf, size_t len, boolean_t public,
    boolean_t lock_held, ks_obj_handle_t *keyhandle)
{

	int fd, tmp_ks_fd, obj_fd;
	unsigned int counter, version;
	uchar_t obj_hmac[OBJ_HMAC_SIZE];
	CK_BYTE iv[OBJ_IV_SIZE];
	char obj_name[MAXPATHLEN], tmp_ks_desc_name[MAXPATHLEN];
	char filebuf[BUFSIZ];
	char pub_obj_path[MAXPATHLEN], pri_obj_path[MAXPATHLEN],
	    ks_desc_file[MAXPATHLEN];
	CK_ULONG hmac_size;
	ssize_t nread;

	if (keyhandle == NULL) {
		return (-1);
	}

	/* if it is private object, make sure we have the key */
	if (!public) {
		if ((enc_key == NULL) ||
		    (enc_key->magic_marker != SOFTTOKEN_OBJECT_MAGIC)) {
			return (-1);
		}
	}

	/* open keystore, and set write lock */
	if ((fd = open_and_lock_keystore_desc(O_RDWR, B_FALSE,
	    lock_held)) < 0) {
		return (-1);
	}

	(void) get_desc_file_path(ks_desc_file);
	(void) get_tmp_desc_file_path(tmp_ks_desc_name);

	/*
	 * create a tempoary file for the keystore description
	 * file for updating version and counter information
	 */
	tmp_ks_fd = open_nointr(tmp_ks_desc_name,
	    O_RDWR|O_CREAT|O_EXCL|O_NONBLOCK, S_IRUSR|S_IWUSR);
	if (tmp_ks_fd < 0) {
		(void) close(fd);
		return (-1);
	}

	/* read and write pkcs11 version */
	if (readn_nointr(fd, filebuf, KS_PKCS11_VER_SIZE)
	    != KS_PKCS11_VER_SIZE) {
		goto cleanup;
	}

	if (writen_nointr(tmp_ks_fd, filebuf, KS_PKCS11_VER_SIZE)
	    != KS_PKCS11_VER_SIZE) {
		goto cleanup;
	}

	/* get version number, and write updated number to temp file */
	if (readn_nointr(fd, &version, KS_VER_SIZE) != KS_VER_SIZE) {
		goto cleanup;
	}

	version = SWAP32(version);
	version++;
	version = SWAP32(version);

	if (writen_nointr(tmp_ks_fd, (void *)&version,
	    KS_VER_SIZE) != KS_VER_SIZE) {
		goto cleanup;
	}

	/* get object count value */
	if (readn_nointr(fd, &counter, KS_COUNTER_SIZE) != KS_COUNTER_SIZE) {
		goto cleanup;
	}
	counter = SWAP32(counter);

	bzero(obj_name, sizeof (obj_name));
	if (public) {
		(void) snprintf(obj_name, MAXPATHLEN,  "%s/%s%d",
		    get_pub_obj_path(pub_obj_path), OBJ_PREFIX, counter);
	} else {
		(void) snprintf(obj_name, MAXPATHLEN,  "%s/%s%d",
		    get_pri_obj_path(pri_obj_path), OBJ_PREFIX, counter);
	}

	/* create object file */
	obj_fd = open_nointr(obj_name,
	    O_WRONLY|O_CREAT|O_EXCL|O_NONBLOCK, S_IRUSR|S_IWUSR);
	if (obj_fd < 0) {
		/* can't create object file */
		goto cleanup;
	}

	/* lock object file for writing */
	if (lock_file(obj_fd, B_FALSE, B_TRUE) != 0) {
		(void) close(obj_fd);
		goto cleanup2;
	}

	/* write object meta data */
	version = SWAP32(1);
	if (writen_nointr(obj_fd, (void *)&version, sizeof (version))
	    != sizeof (version)) {
		goto cleanup2;
	}

	if (public) {
		bzero(iv, sizeof (iv));
	} else {
		/* generate an IV */
		if (soft_gen_iv(iv) != CKR_OK) {
			goto cleanup2;
		}

	}

	if (writen_nointr(obj_fd, (void *)iv, sizeof (iv)) != sizeof (iv)) {
		goto cleanup2;
	}

	if (public) {

		bzero(obj_hmac, sizeof (obj_hmac));
		if (writen_nointr(obj_fd, (void *)obj_hmac,
		    sizeof (obj_hmac)) != sizeof (obj_hmac)) {
			goto cleanup2;
		}

		if (writen_nointr(obj_fd, (char *)buf, len) != len) {
			goto cleanup2;
		}

	} else {

		uchar_t *encrypted_buf, *prepared_buf;
		CK_ULONG out_len = 0, prepared_len;

		if (prepare_data_for_encrypt(obj_name, buf, len,
		    &prepared_buf, &prepared_len) != 0) {
			goto cleanup2;
		}

		if (soft_keystore_crypt(enc_key, iv,
		    B_TRUE, prepared_buf, prepared_len,
		    NULL, &out_len) != CKR_OK) {
			freezero(prepared_buf, prepared_len);
			goto cleanup2;
		}

		encrypted_buf = malloc(out_len * sizeof (char));
		if (encrypted_buf == NULL) {
			freezero(prepared_buf, prepared_len);
			goto cleanup2;
		}

		if (soft_keystore_crypt(enc_key, iv,
		    B_TRUE, prepared_buf, prepared_len,
		    encrypted_buf, &out_len) != CKR_OK) {
			freezero(encrypted_buf, out_len);
			freezero(prepared_buf, prepared_len);
			goto cleanup2;
		}
		freezero(prepared_buf, prepared_len);

		/* calculate HMAC of encrypted object */
		hmac_size = OBJ_HMAC_SIZE;
		if (soft_keystore_hmac(hmac_key, B_TRUE, encrypted_buf,
		    out_len, obj_hmac, &hmac_size) != CKR_OK) {
			freezero(encrypted_buf, out_len);
			goto cleanup2;
		}

		if (hmac_size != OBJ_HMAC_SIZE) {
			freezero(encrypted_buf, out_len);
			goto cleanup2;
		}

		/* write hmac */
		if (writen_nointr(obj_fd, (void *)obj_hmac,
		    sizeof (obj_hmac)) != sizeof (obj_hmac)) {
			freezero(encrypted_buf, out_len);
			goto cleanup2;
		}

		/* write encrypted object */
		if (writen_nointr(obj_fd, (void *)encrypted_buf, out_len)
		    != out_len) {
			freezero(encrypted_buf, out_len);
			goto cleanup2;
		}

		freezero(encrypted_buf, out_len);
	}


	(void) close(obj_fd);
	(void) snprintf((char *)keyhandle->name, sizeof (keyhandle->name),
	    "obj%d", counter);
	keyhandle->public = public;

	/*
	 * store new counter to temp keystore description file.
	 */
	counter++;
	counter = SWAP32(counter);
	if (writen_nointr(tmp_ks_fd, (void *)&counter,
	    sizeof (counter)) != sizeof (counter)) {
		goto cleanup2;
	}

	/* read rest of keystore description file and store into temp file */
	nread = readn_nointr(fd, filebuf, sizeof (filebuf));
	while (nread > 0) {
		if (writen_nointr(tmp_ks_fd, filebuf, nread) != nread) {
			goto cleanup2;
		}
		nread = readn_nointr(fd, filebuf, sizeof (filebuf));
	}

	(void) close(tmp_ks_fd);
	(void) rename(tmp_ks_desc_name, ks_desc_file);

	if (!lock_held) {
		/* release lock on description file */
		if (lock_file(fd, B_FALSE, B_FALSE) != 0) {
			(void) close(fd);
			return (-1);
		}
	}
	(void) close(fd);
	explicit_bzero(obj_hmac, sizeof (obj_hmac));
	explicit_bzero(iv, sizeof (iv));
	return (0);

cleanup2:

	/* remove object file.  No need to remove lock first */
	(void) unlink(obj_name);

cleanup:

	(void) close(tmp_ks_fd);
	(void) remove(tmp_ks_desc_name);
	if (!lock_held) {
		/* release lock on description file */
		(void) lock_file(fd, B_FALSE, B_FALSE);
	}

	(void) close(fd);
	explicit_bzero(obj_hmac, sizeof (obj_hmac));
	explicit_bzero(iv, sizeof (iv));
	return (-1);
}

/*
 *	FUNCTION: soft_keystore_modify_obj
 *
 *	ARGUMENTS:
 *		ks_handle: handle of the key store object to be modified
 *		buf: buffer containing un-encrypted data
 *		     to be modified in keystore.
 *		len: length of data
 *		lock_held: TRUE if the lock is held by caller.
 *
 *	RETURN VALUE:
 *		-1: if any error occurred.
 *		Otherwise, 0 is returned.
 *
 *	DESCRIPTION:
 *
 *		This API is used to write a modified token object back
 *		to keystore.   This function will do the following:
 *
 *		1) If it is a private object, it will be encrypted before
 *		   being written to the corresponding keystore token
 *		   object file.
 *		2) Record incremented object version number.
 *		3) Record incremented keystore version number.
 */
int
soft_keystore_modify_obj(ks_obj_handle_t *ks_handle, uchar_t *buf,
    size_t len, boolean_t lock_held)
{
	int fd, ks_fd, tmp_fd, version;
	char orig_name[MAXPATHLEN], tmp_name[MAXPATHLEN],
	    tmp_ks_name[MAXPATHLEN];
	uchar_t iv[OBJ_IV_SIZE], obj_hmac[OBJ_HMAC_SIZE];
	char pub_obj_path[MAXPATHLEN], pri_obj_path[MAXPATHLEN],
	    ks_desc_file[MAXPATHLEN];
	CK_ULONG hmac_size;

	/* if it is private object, make sure we have the key */
	if (!(ks_handle->public)) {
		if ((enc_key == NULL) ||
		    (enc_key->magic_marker != SOFTTOKEN_OBJECT_MAGIC)) {
			return (-1);
		}
	}

	/* open and lock keystore description file */
	if ((ks_fd = open_and_lock_keystore_desc(O_RDWR, B_FALSE,
	    B_FALSE)) < 0) {
		return (-1);
	}

	(void) get_desc_file_path(ks_desc_file);

	/* update the version of for keystore file in tempoary file */
	(void) get_tmp_desc_file_path(tmp_ks_name);
	if (create_updated_keystore_version(ks_fd, tmp_ks_name) != 0) {
		/* unlock keystore description file */
		(void) lock_file(ks_fd, B_FALSE, B_FALSE);
		(void) close(ks_fd);
		return (-1);
	}

	/* open object file */
	if ((fd = open_and_lock_object_file(ks_handle, O_RDWR,
	    lock_held)) < 0) {
		goto cleanup;
	}

	/*
	 * make the change in a temporary file.  Create the temp
	 * file in the same directory as the token object.  That
	 * way, the "rename" later will be an atomic operation
	 */
	if (ks_handle->public) {
		(void) snprintf(orig_name, MAXPATHLEN, "%s/%s",
		    get_pub_obj_path(pub_obj_path), ks_handle->name);
		(void) snprintf(tmp_name, MAXPATHLEN, "%s/%s%s",
		    pub_obj_path, TMP_OBJ_PREFIX,
		    (ks_handle->name) + OBJ_PREFIX_LEN);
	} else {
		(void) snprintf(orig_name, MAXPATHLEN, "%s/%s",
		    get_pri_obj_path(pri_obj_path), ks_handle->name);
		(void) snprintf(tmp_name, MAXPATHLEN, "%s/%s%s",
		    pri_obj_path, TMP_OBJ_PREFIX,
		    (ks_handle->name) + OBJ_PREFIX_LEN);
	}

	tmp_fd = open_nointr(tmp_name,
	    O_WRONLY|O_CREAT|O_EXCL|O_NONBLOCK, S_IRUSR|S_IWUSR);
	if (tmp_fd < 0) {
		/* can't create tmp object file */
		goto cleanup1;
	}

	/* read version, increment, and write to tmp file */
	if (readn_nointr(fd, (char *)&version, OBJ_VER_SIZE) != OBJ_VER_SIZE) {
		goto cleanup2;
	}

	version = SWAP32(version);
	version++;
	version = SWAP32(version);

	if (writen_nointr(tmp_fd, (char *)&version, OBJ_VER_SIZE)
	    != OBJ_VER_SIZE) {
		goto cleanup2;
	}

	/* generate a new IV for the object, old one can be ignored */
	if (soft_gen_iv(iv) != CKR_OK) {
		goto cleanup2;
	}

	if (writen_nointr(tmp_fd, (char *)iv, OBJ_IV_SIZE) != OBJ_IV_SIZE) {
		goto cleanup2;
	}

	if (ks_handle->public) {

		/* hmac is always NULL for public objects */
		bzero(obj_hmac, sizeof (obj_hmac));
		if (writen_nointr(tmp_fd, (char *)obj_hmac, OBJ_HMAC_SIZE)
		    != OBJ_HMAC_SIZE) {
			goto cleanup2;
		}

		/* write updated object */
		if (writen_nointr(tmp_fd, (char *)buf, len) != len) {
			goto cleanup2;
		}

	} else {

		uchar_t *encrypted_buf, *prepared_buf;
		CK_ULONG out_len = 0, prepared_len;

		if (prepare_data_for_encrypt(orig_name, buf, len,
		    &prepared_buf, &prepared_len) != 0) {
			goto cleanup2;
		}

		/* encrypt the data */
		if (soft_keystore_crypt(enc_key, iv, B_TRUE, prepared_buf,
		    prepared_len, NULL, &out_len) != CKR_OK) {
			free(prepared_buf);
			goto cleanup2;
		}

		encrypted_buf = malloc(out_len * sizeof (char));
		if (encrypted_buf == NULL) {
			freezero(prepared_buf, prepared_len);
			goto cleanup2;
		}

		if (soft_keystore_crypt(enc_key, iv, B_TRUE, prepared_buf,
		    prepared_len, encrypted_buf, &out_len) != CKR_OK) {
			freezero(prepared_buf, prepared_len);
			freezero(encrypted_buf, out_len);
			goto cleanup2;
		}

		freezero(prepared_buf, prepared_len);

		/* calculate hmac on encrypted buf */
		hmac_size = OBJ_HMAC_SIZE;
		if (soft_keystore_hmac(hmac_key, B_TRUE, encrypted_buf,
		    out_len, obj_hmac, &hmac_size) != CKR_OK) {
			freezero(encrypted_buf, out_len);
			goto cleanup2;
		}

		if (hmac_size != OBJ_HMAC_SIZE) {
			freezero(encrypted_buf, out_len);
			goto cleanup2;
		}

		if (writen_nointr(tmp_fd, (char *)obj_hmac, OBJ_HMAC_SIZE)
		    != OBJ_HMAC_SIZE) {
			freezero(encrypted_buf, out_len);
			goto cleanup2;
		}

		if (writen_nointr(tmp_fd, (void *)encrypted_buf, out_len)
		    != out_len) {
			freezero(encrypted_buf, out_len);
			goto cleanup2;
		}
		freezero(encrypted_buf, out_len);
	}
	(void) close(tmp_fd);

	/* rename updated temporary object file */
	if (rename(tmp_name, orig_name) != 0) {
		(void) unlink(tmp_name);
		return (-1);
	}

	/* rename updated keystore description file */
	if (rename(tmp_ks_name, ks_desc_file) != 0) {
		(void) unlink(tmp_name);
		(void) unlink(tmp_ks_name);
		return (-1);
	}

	/* determine need to unlock file or not */
	if (!lock_held) {
		if (lock_file(fd, B_FALSE, B_FALSE) < 0) {
			(void) close(fd);
			(void) unlink(tmp_name);
			return (-1);
		}
	}

	/* unlock keystore description file */
	if (lock_file(ks_fd, B_FALSE, B_FALSE) != 0) {
		(void) close(ks_fd);
		(void) close(fd);
		return (-1);
	}

	(void) close(ks_fd);

	(void) close(fd);

	explicit_bzero(iv, sizeof (iv));
	explicit_bzero(obj_hmac, sizeof (obj_hmac));
	return (0); /* All operations completed successfully */

cleanup2:
	(void) close(tmp_fd);
	(void) remove(tmp_name);

cleanup1:
	(void) close(fd);

cleanup:
	/* unlock keystore description file */
	(void) lock_file(ks_fd, B_FALSE, B_FALSE);
	(void) close(ks_fd);
	(void) remove(tmp_ks_name);
	explicit_bzero(iv, sizeof (iv));
	explicit_bzero(obj_hmac, sizeof (obj_hmac));
	return (-1);
}

/*
 *	FUNCTION: soft_keystore_del_obj
 *
 *	ARGUMENTS:
 *		ks_handle: handle of the key store object to be deleted
 *		lock_held: TRUE if the lock is held by caller.
 *
 *	RETURN VALUE:
 *		-1: if any error occurred.
 *		0: object successfully deleted from keystore.
 *
 *	DESCRIPTION:
 *		This API is used to delete a particular token object from
 *		the keystore.  The corresponding token object file will be
 *		removed from the file system.
 *		Any future reference to the deleted file will
 *		return an CKR_OBJECT_HANDLE_INVALID error.
 */
int
soft_keystore_del_obj(ks_obj_handle_t *ks_handle, boolean_t lock_held)
{
	char objname[MAXPATHLEN], tmp_ks_name[MAXPATHLEN];
	int fd;
	char pub_obj_path[MAXPATHLEN], pri_obj_path[MAXPATHLEN],
	    ks_desc_file[MAXPATHLEN];
	int ret_val = -1;
	int obj_fd;

	if ((fd = open_and_lock_keystore_desc(O_RDWR, B_FALSE,
	    lock_held)) < 0) {
		return (-1);
	}

	(void) get_desc_file_path(ks_desc_file);
	(void) get_tmp_desc_file_path(tmp_ks_name);
	if (create_updated_keystore_version(fd, tmp_ks_name) != 0) {
		goto cleanup;
	}

	if (ks_handle->public) {
		(void) snprintf(objname, MAXPATHLEN, "%s/%s",
		    get_pub_obj_path(pub_obj_path), ks_handle->name);
	} else {
		(void) snprintf(objname, MAXPATHLEN, "%s/%s",
		    get_pri_obj_path(pri_obj_path), ks_handle->name);
	}

	/*
	 * make sure no other process is reading/writing the file
	 * by acquiring the lock on the file
	 */
	if ((obj_fd = open_and_lock_object_file(ks_handle, O_WRONLY,
	    B_FALSE)) < 0) {
		return (-1);
	}

	if (unlink(objname) != 0) {
		(void) lock_file(obj_fd, B_FALSE, B_FALSE);
		(void) close(obj_fd);
		goto cleanup;
	}

	(void) lock_file(obj_fd, B_FALSE, B_FALSE);
	(void) close(obj_fd);

	if (rename(tmp_ks_name, ks_desc_file) != 0) {
		goto cleanup;
	}
	ret_val = 0;

cleanup:
	/* unlock keystore description file */
	if (!lock_held) {
		if (lock_file(fd, B_FALSE, B_FALSE) != 0) {
			(void) close(fd);
			return (-1);
		}
	}

	(void) close(fd);
	return (ret_val);
}

/*
 * Get the salt used for generating hashed pin from the
 * keystore description file.
 *
 * The result will be stored in the provided buffer "salt" passed
 * in as an argument.
 *
 * Return 0 if no error, return -1 if there's any error.
 */
int
soft_keystore_get_pin_salt(char **salt)
{
	int fd, ret_val = -1;
	uint64_t hashed_pin_salt_size;

	if ((fd = open_and_lock_keystore_desc(O_RDONLY, B_FALSE,
	    B_FALSE)) < 0) {
		return (-1);
	}

	if (lseek(fd, KS_HASHED_PIN_SALT_LEN_OFFSET, SEEK_SET)
	    != KS_HASHED_PIN_SALT_LEN_OFFSET) {
		goto cleanup;
	}

	if (readn_nointr(fd, (char *)&hashed_pin_salt_size,
	    KS_HASHED_PIN_SALT_LEN_SIZE) != KS_HASHED_PIN_SALT_LEN_SIZE) {
		goto cleanup;
	}
	hashed_pin_salt_size = SWAP64(hashed_pin_salt_size);

	*salt = malloc(hashed_pin_salt_size + 1);
	if (*salt == NULL) {
		goto cleanup;
	}

	if ((readn_nointr(fd, *salt, hashed_pin_salt_size))
	    != (ssize_t)hashed_pin_salt_size) {
		freezero(*salt, hashed_pin_salt_size + 1);
		goto cleanup;
	}
	(*salt)[hashed_pin_salt_size] = '\0';

	ret_val = 0;

cleanup:
	if (lock_file(fd, B_TRUE, B_FALSE) < 0) {
		ret_val = -1;
	}

	(void) close(fd);
	return (ret_val);
}

/*
 *	FUNCTION: soft_keystore_pin_initialized
 *
 *	ARGUMENTS:
 *		initialized: This value will be set to true if keystore is
 *			     initialized, and false otherwise.
 *		hashed_pin: If the keystore is initialized, this will contain
 *			    the hashed pin.  It will be NULL if the keystore
 *			    pin is not initialized.  Memory allocated
 *			    for the hashed pin needs to be freed by
 *			    the caller.
 *		lock_held: TRUE if the lock is held by caller.
 *
 *	RETURN VALUE:
 *		CKR_OK: No error
 *		any other appropriate CKR_value
 *
 *	DESCRIPTION:
 *		This API is used to determine if the PIN in the keystore
 *		has been initialized or not.
 *		It makes the determination using the salt for generating the
 *		encryption key.  The salt is stored in the keystore
 *		descryption file.  The salt should be all zero if
 *		the keystore pin has not been initialized.
 *		If the pin has been initialized, it is returned in the
 *		hashed_pin argument.
 */
CK_RV
soft_keystore_pin_initialized(boolean_t *initialized, char **hashed_pin,
    boolean_t lock_held)
{
	int fd;
	CK_BYTE crypt_salt[KS_KEY_SALT_SIZE], tmp_buf[KS_KEY_SALT_SIZE];
	CK_RV ret_val = CKR_OK;

	if ((fd = open_and_lock_keystore_desc(O_RDONLY, B_FALSE,
	    lock_held)) < 0) {
		return (CKR_FUNCTION_FAILED);
	}

	if (lseek(fd, KS_KEY_SALT_OFFSET, SEEK_SET) != KS_KEY_SALT_OFFSET) {
		ret_val = CKR_FUNCTION_FAILED;
		goto cleanup;
	}

	if (readn_nointr(fd, (char *)crypt_salt, KS_KEY_SALT_SIZE)
	    != KS_KEY_SALT_SIZE) {
		ret_val = CKR_FUNCTION_FAILED;
		goto cleanup;
	}

	(void) bzero(tmp_buf, KS_KEY_SALT_SIZE);

	if (memcmp(crypt_salt, tmp_buf, KS_KEY_SALT_SIZE) == 0) {
		*initialized = B_FALSE;
		hashed_pin = NULL;
	} else {
		*initialized = B_TRUE;
		ret_val = get_hashed_pin(fd, hashed_pin);
	}

cleanup:

	if (!lock_held) {
		if (lock_file(fd, B_TRUE, B_FALSE) < 0) {
			ret_val = CKR_FUNCTION_FAILED;
		}
	}

	(void) close(fd);
	return (ret_val);
}

/*
 * This checks if the keystore file exists
 */

static int
soft_keystore_exists()
{
	int ret;
	struct stat fn_stat;
	char *fname, ks_desc_file[MAXPATHLEN];

	fname = get_desc_file_path(ks_desc_file);
	ret = stat(fname, &fn_stat);
	if (ret == 0)
		return (0);
	return (errno);
}

/*
 *	FUNCTION: soft_keystore_init
 *
 *	ARGUMENTS:
 *		desired_state:  The keystore state the caller would like
 *				it to be.
 *
 *	RETURN VALUE:
 *		Returns the state the function is in.  If it succeeded, it
 *		will be the same as the desired, if not it will be
 *		KEYSTORE_UNAVAILABLE.
 *
 *	DESCRIPTION:
 *		This function will only load as much keystore data as is
 *		requested at that time. This is for performace by delaying the
 *		reading of token objects until they are needed or never at
 *		all if they are not used.
 *
 *		Primary use is from C_InitToken().
 *		It is also called by soft_keystore_status() when the
 *		"desired_state" is not the the current load state of keystore.
 *
 */
int
soft_keystore_init(int desired_state)
{
	int ret;

	(void) pthread_mutex_lock(&soft_slot.keystore_mutex);

	/*
	 * If more than one session tries to initialize the keystore, the
	 * second and other following sessions that were waiting for the lock
	 * will quickly exit if their requirements are satisfied.
	 */
	if (desired_state <= soft_slot.keystore_load_status) {
		(void) pthread_mutex_unlock(&soft_slot.keystore_mutex);
		return (soft_slot.keystore_load_status);
	}

	/*
	 * With 'keystore_load_status' giving the current state of the
	 * process, this switch will bring it up to the desired state if
	 * possible.
	 */

	switch (soft_slot.keystore_load_status) {
	case KEYSTORE_UNINITIALIZED:
		ret = soft_keystore_exists();
		if (ret == 0)
			soft_slot.keystore_load_status = KEYSTORE_PRESENT;
		else if (ret == ENOENT)
			if (create_keystore() == 0)
				soft_slot.keystore_load_status =
				    KEYSTORE_PRESENT;
			else {
				soft_slot.keystore_load_status =
				    KEYSTORE_UNAVAILABLE;
				cryptoerror(LOG_DEBUG,
				    "pkcs11_softtoken: "
				    "Cannot create keystore.");
				break;
			}

		if (desired_state <= KEYSTORE_PRESENT)
			break;

	/* FALLTHRU */
	case KEYSTORE_PRESENT:
		if (soft_keystore_get_version(&soft_slot.ks_version, B_FALSE)
		    != 0) {
			soft_slot.keystore_load_status = KEYSTORE_UNAVAILABLE;
			cryptoerror(LOG_DEBUG,
			    "pkcs11_softtoken: Keystore access failed.");
			break;
		}

		soft_slot.keystore_load_status = KEYSTORE_LOAD;
		if (desired_state <= KEYSTORE_LOAD)
			break;

	/* FALLTHRU */
	case KEYSTORE_LOAD:
		/* Load all the public token objects from keystore */
		if (soft_get_token_objects_from_keystore(PUB_TOKENOBJS)
		    != CKR_OK) {
			(void) soft_destroy_token_session();
			soft_slot.keystore_load_status = KEYSTORE_UNAVAILABLE;
			cryptoerror(LOG_DEBUG,
			    "pkcs11_softtoken: Cannot initialize keystore.");
			break;
		}

		soft_slot.keystore_load_status = KEYSTORE_INITIALIZED;
	};

	(void) pthread_mutex_unlock(&soft_slot.keystore_mutex);
	return (soft_slot.keystore_load_status);
}

/*
 *	FUNCTION: soft_keystore_status
 *
 *	ARGUMENTS:
 *		desired_state:  The keystore state the caller would like
 *				it to be.
 *
 *	RETURN VALUE:
 *		B_TRUE if keystore is ready and at the desired state.
 *		B_FALSE if keystore had an error and is not available.
 *
 *	DESCRIPTION:
 *		The calling function wants to make sure the keystore load
 *		status to in a state it requires.  If it is not at that
 *		state it will call the load function.
 *		If keystore is at the desired state or has just been
 *		loaded to that state, it will return TRUE.  If there has been
 *		load failure, it will return FALSE.
 *
 */
boolean_t
soft_keystore_status(int desired_state)
{

	if (soft_slot.keystore_load_status == KEYSTORE_UNAVAILABLE)
		return (B_FALSE);

	return ((desired_state <= soft_slot.keystore_load_status) ||
	    (soft_keystore_init(desired_state) == desired_state));
}
