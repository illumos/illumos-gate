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
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 * Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <thread.h>
#include <sys/auxv.h>
#include <sys/brand.h>
#include <sys/inttypes.h>
#include <sys/lwp.h>
#include <sys/syscall.h>
#include <sys/systm.h>
#include <sys/utsname.h>
#include <sys/sysconfig.h>
#include <sys/systeminfo.h>
#include <sys/zone.h>
#include <sys/stat.h>
#include <sys/mntent.h>
#include <sys/ctfs.h>
#include <sys/priv.h>
#include <sys/acctctl.h>
#include <libgen.h>
#include <bsm/audit.h>
#include <sys/crypto/ioctl.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_ioctl.h>
#include <sys/ucontext.h>
#include <sys/mntio.h>
#include <sys/mnttab.h>
#include <sys/attr.h>
#include <sys/lofi.h>
#include <atomic.h>
#include <sys/acl.h>
#include <sys/socket.h>

#include <s10_brand.h>
#include <brand_misc.h>
#include <s10_misc.h>
#include <s10_signal.h>

/*
 * See usr/src/lib/brand/shared/brand/common/brand_util.c for general
 * emulation notes.
 */

static zoneid_t zoneid;
static boolean_t emul_global_zone = B_FALSE;
static s10_emul_bitmap_t emul_bitmap;
pid_t zone_init_pid;

/*
 * S10_FEATURE_IS_PRESENT is a macro that helps facilitate conditional
 * emulation.  For each constant N defined in the s10_emulated_features
 * enumeration in usr/src/uts/common/brand/solaris10/s10_brand.h,
 * S10_FEATURE_IS_PRESENT(N) is true iff the feature/backport represented by N
 * is present in the Solaris 10 image hosted within the zone.  In other words,
 * S10_FEATURE_IS_PRESENT(N) is true iff the file /usr/lib/brand/solaris10/M,
 * where M is the enum value of N, was present in the zone when the zone booted.
 *
 *
 * *** Sample Usage
 *
 * Suppose that you need to backport a fix to Solaris 10 and there is
 * emulation in place for the fix.  Suppose further that the emulation won't be
 * needed if the fix is backported (i.e., if the fix is present in the hosted
 * Solaris 10 environment, then the brand won't need the emulation).  Then if
 * you add a constant named "S10_FEATURE_X" to the end of the
 * s10_emulated_features enumeration that represents the backported fix and
 * S10_FEATURE_X evaluates to four, then you should create a file named
 * /usr/lib/brand/solaris10/4 as part of your backport.  Additionally, you
 * should retain the aforementioned emulation but modify it so that it's
 * performed only when S10_FEATURE_IS_PRESENT(S10_FEATURE_X) is false.  Thus the
 * emulation function should look something like the following:
 *
 *	static int
 *	my_emul_function(sysret_t *rv, ...)
 *	{
 *		if (S10_FEATURE_IS_PRESENT(S10_FEATURE_X)) {
 *			// Don't emulate
 *			return (__systemcall(rv, ...));
 *		} else {
 *			// Emulate whatever needs to be emulated when the
 *			// backport isn't present in the Solaris 10 image.
 *		}
 *	}
 */
#define	S10_FEATURE_IS_PRESENT(s10_emulated_features_constant)	\
	((emul_bitmap[(s10_emulated_features_constant) >> 3] &	\
	(1 << ((s10_emulated_features_constant) & 0x7))) != 0)

brand_sysent_table_t brand_sysent_table[];

#define	S10_UTS_RELEASE	"5.10"
#define	S10_UTS_VERSION	"Generic_Virtual"

/*
 * If the ioctl fd's major doesn't match "major", then pass through the
 * ioctl, since it is not the expected device.  major should be a
 * pointer to a static dev_t initialized to -1, and devname should be
 * the path of the device.
 *
 * Returns 1 if the ioctl was handled (in which case *err contains the
 * error code), or 0 if it still needs handling.
 */
static int
passthru_otherdev_ioctl(dev_t *majordev, const char *devname, int *err,
    sysret_t *rval, int fdes, int cmd, intptr_t arg)
{
	struct stat sbuf;

	if (*majordev == (dev_t)-1) {
		if ((*err = __systemcall(rval, SYS_fstatat + 1024,
		    AT_FDCWD, devname, &sbuf, 0) != 0) != 0)
			goto doioctl;

		*majordev = major(sbuf.st_rdev);
	}

	if ((*err = __systemcall(rval, SYS_fstatat + 1024, fdes,
	    NULL, &sbuf, 0)) != 0)
		goto doioctl;

	if (major(sbuf.st_rdev) == *majordev)
		return (0);

doioctl:
	*err = (__systemcall(rval, SYS_ioctl + 1024, fdes, cmd, arg));
	return (1);
}

/*
 * Figures out the PID of init for the zone.  Also returns a boolean
 * indicating whether this process currently has that pid: if so,
 * then at this moment, we are init.
 */
static boolean_t
get_initpid_info(void)
{
	pid_t pid;
	sysret_t rval;
	int err;

	/*
	 * Determine the current process PID and the PID of the zone's init.
	 * We use care not to call getpid() here, because we're not supposed
	 * to call getpid() until after the program is fully linked-- the
	 * first call to getpid() is a signal from the linker to debuggers
	 * that linking has been completed.
	 */
	if ((err = __systemcall(&rval, SYS_brand,
	    B_S10_PIDINFO, &pid, &zone_init_pid)) != 0) {
		brand_abort(err, "Failed to get init's pid");
	}

	/*
	 * Note that we need to be cautious with the pid we get back--
	 * it should not be stashed and used in place of getpid(), since
	 * we might fork(2).  So we keep zone_init_pid and toss the pid
	 * we otherwise got.
	 */
	if (pid == zone_init_pid)
		return (B_TRUE);

	return (B_FALSE);
}

/* Free the thread-local storage provided by mntfs_get_mntentbuf(). */
static void
mntfs_free_mntentbuf(void *arg)
{
	struct mntentbuf *embufp = arg;

	if (embufp == NULL)
		return;
	if (embufp->mbuf_emp)
		free(embufp->mbuf_emp);
	if (embufp->mbuf_buf)
		free(embufp->mbuf_buf);
	bzero(embufp, sizeof (struct mntentbuf));
	free(embufp);
}

/* Provide the thread-local storage required by mntfs_ioctl(). */
static struct mntentbuf *
mntfs_get_mntentbuf(size_t size)
{
	static mutex_t keylock;
	static thread_key_t key;
	static int once_per_keyname = 0;
	void *tsd = NULL;
	struct mntentbuf *embufp;

	/* Create the key. */
	if (!once_per_keyname) {
		(void) mutex_lock(&keylock);
		if (!once_per_keyname) {
			if (thr_keycreate(&key, mntfs_free_mntentbuf)) {
				(void) mutex_unlock(&keylock);
				return (NULL);
			} else {
				once_per_keyname++;
			}
		}
		(void) mutex_unlock(&keylock);
	}

	/*
	 * The thread-specific datum for this key is the address of a struct
	 * mntentbuf. If this is the first time here then we allocate the struct
	 * and its contents, and associate its address with the thread; if there
	 * are any problems then we abort.
	 */
	if (thr_getspecific(key, &tsd))
		return (NULL);
	if (tsd == NULL) {
		if (!(embufp = calloc(1, sizeof (struct mntentbuf))) ||
		    !(embufp->mbuf_emp = malloc(sizeof (struct extmnttab))) ||
		    thr_setspecific(key, embufp)) {
			mntfs_free_mntentbuf(embufp);
			return (NULL);
		}
	} else {
		embufp = tsd;
	}

	/* Return the buffer, resizing it if necessary. */
	if (size > embufp->mbuf_bufsize) {
		if (embufp->mbuf_buf)
			free(embufp->mbuf_buf);
		if ((embufp->mbuf_buf = malloc(size)) == NULL) {
			embufp->mbuf_bufsize = 0;
			return (NULL);
		} else {
			embufp->mbuf_bufsize = size;
		}
	}
	return (embufp);
}

/*
 * The MNTIOC_GETMNTENT command in this release differs from that in early
 * versions of Solaris 10.
 *
 * Previously, the command would copy a pointer to a struct extmnttab to an
 * address provided as an argument. The pointer would be somewhere within a
 * mapping already present within the user's address space. In addition, the
 * text to which the struct's members pointed would also be within a
 * pre-existing mapping. Now, the user is required to allocate memory for both
 * the struct and the text buffer, and to pass the address of each within a
 * struct mntentbuf. In order to conceal these details from a Solaris 10 client
 * we allocate some thread-local storage in which to create the necessary data
 * structures; this is static, thread-safe memory that will be cleaned up
 * without the caller's intervention.
 *
 * MNTIOC_GETEXTMNTENT and MNTIOC_GETMNTANY are new in this release; they should
 * not work for older clients.
 */
int
mntfs_ioctl(sysret_t *rval, int fdes, int cmd, intptr_t arg)
{
	int err;
	struct stat statbuf;
	struct mntentbuf *embufp;
	static size_t bufsize = MNT_LINE_MAX;

	/* Do not emulate mntfs commands from up-to-date clients. */
	if (S10_FEATURE_IS_PRESENT(S10_FEATURE_ALTERED_MNTFS_IOCTL))
		return (__systemcall(rval, SYS_ioctl + 1024, fdes, cmd, arg));

	/* Do not emulate mntfs commands directed at other file systems. */
	if ((err = __systemcall(rval, SYS_fstatat + 1024,
	    fdes, NULL, &statbuf, 0)) != 0)
		return (err);
	if (strcmp(statbuf.st_fstype, MNTTYPE_MNTFS) != 0)
		return (__systemcall(rval, SYS_ioctl + 1024, fdes, cmd, arg));

	if (cmd == MNTIOC_GETEXTMNTENT || cmd == MNTIOC_GETMNTANY)
		return (EINVAL);

	if ((embufp = mntfs_get_mntentbuf(bufsize)) == NULL)
		return (ENOMEM);

	/*
	 * MNTIOC_GETEXTMNTENT advances the file pointer once it has
	 * successfully copied out the result to the address provided. We
	 * therefore need to check the user-supplied address now since the
	 * one we'll be providing is guaranteed to work.
	 */
	if (brand_uucopy(&embufp->mbuf_emp, (void *)arg, sizeof (void *)) != 0)
		return (EFAULT);

	/*
	 * Keep retrying for as long as we fail for want of a large enough
	 * buffer.
	 */
	for (;;) {
		if ((err = __systemcall(rval, SYS_ioctl + 1024, fdes,
		    MNTIOC_GETEXTMNTENT, embufp)) != 0)
			return (err);

		if (rval->sys_rval1 == MNTFS_TOOLONG) {
			/* The buffer wasn't large enough. */
			(void) atomic_swap_ulong((unsigned long *)&bufsize,
			    2 * embufp->mbuf_bufsize);
			if ((embufp = mntfs_get_mntentbuf(bufsize)) == NULL)
				return (ENOMEM);
		} else {
			break;
		}
	}

	if (brand_uucopy(&embufp->mbuf_emp, (void *)arg, sizeof (void *)) != 0)
		return (EFAULT);

	return (0);
}

/*
 * Assign the structure member value from the s (source) structure to the
 * d (dest) structure.
 */
#define	struct_assign(d, s, val)	(((d).val) = ((s).val))

/*
 * The CRYPTO_GET_FUNCTION_LIST parameter structure crypto_function_list_t
 * changed between S10 and Nevada, so we have to emulate the old S10
 * crypto_function_list_t structure when interposing on the ioctl syscall.
 */
typedef struct s10_crypto_function_list {
	boolean_t fl_digest_init;
	boolean_t fl_digest;
	boolean_t fl_digest_update;
	boolean_t fl_digest_key;
	boolean_t fl_digest_final;

	boolean_t fl_encrypt_init;
	boolean_t fl_encrypt;
	boolean_t fl_encrypt_update;
	boolean_t fl_encrypt_final;

	boolean_t fl_decrypt_init;
	boolean_t fl_decrypt;
	boolean_t fl_decrypt_update;
	boolean_t fl_decrypt_final;

	boolean_t fl_mac_init;
	boolean_t fl_mac;
	boolean_t fl_mac_update;
	boolean_t fl_mac_final;

	boolean_t fl_sign_init;
	boolean_t fl_sign;
	boolean_t fl_sign_update;
	boolean_t fl_sign_final;
	boolean_t fl_sign_recover_init;
	boolean_t fl_sign_recover;

	boolean_t fl_verify_init;
	boolean_t fl_verify;
	boolean_t fl_verify_update;
	boolean_t fl_verify_final;
	boolean_t fl_verify_recover_init;
	boolean_t fl_verify_recover;

	boolean_t fl_digest_encrypt_update;
	boolean_t fl_decrypt_digest_update;
	boolean_t fl_sign_encrypt_update;
	boolean_t fl_decrypt_verify_update;

	boolean_t fl_seed_random;
	boolean_t fl_generate_random;

	boolean_t fl_session_open;
	boolean_t fl_session_close;
	boolean_t fl_session_login;
	boolean_t fl_session_logout;

	boolean_t fl_object_create;
	boolean_t fl_object_copy;
	boolean_t fl_object_destroy;
	boolean_t fl_object_get_size;
	boolean_t fl_object_get_attribute_value;
	boolean_t fl_object_set_attribute_value;
	boolean_t fl_object_find_init;
	boolean_t fl_object_find;
	boolean_t fl_object_find_final;

	boolean_t fl_key_generate;
	boolean_t fl_key_generate_pair;
	boolean_t fl_key_wrap;
	boolean_t fl_key_unwrap;
	boolean_t fl_key_derive;

	boolean_t fl_init_token;
	boolean_t fl_init_pin;
	boolean_t fl_set_pin;

	boolean_t prov_is_hash_limited;
	uint32_t prov_hash_threshold;
	uint32_t prov_hash_limit;
} s10_crypto_function_list_t;

typedef struct s10_crypto_get_function_list {
	uint_t				fl_return_value;
	crypto_provider_id_t		fl_provider_id;
	s10_crypto_function_list_t	fl_list;
} s10_crypto_get_function_list_t;

/*
 * The structure returned by the CRYPTO_GET_FUNCTION_LIST ioctl on /dev/crypto
 * increased in size due to:
 *	6482533 Threshold for HW offload via PKCS11 interface
 * between S10 and Nevada.  This is a relatively simple process of filling
 * in the S10 structure fields with the Nevada data.
 *
 * We stat the device to make sure that the ioctl is meant for /dev/crypto.
 *
 */
static int
crypto_ioctl(sysret_t *rval, int fdes, int cmd, intptr_t arg)
{
	int				err;
	s10_crypto_get_function_list_t	s10_param;
	crypto_get_function_list_t	native_param;
	static dev_t			crypto_dev = (dev_t)-1;

	if (passthru_otherdev_ioctl(&crypto_dev, "/dev/crypto", &err,
	    rval, fdes, cmd, arg) == 1)
		return (err);

	if (brand_uucopy((const void *)arg, &s10_param, sizeof (s10_param))
	    != 0)
		return (EFAULT);
	struct_assign(native_param, s10_param, fl_provider_id);
	if ((err = __systemcall(rval, SYS_ioctl + 1024, fdes, cmd,
	    &native_param)) != 0)
		return (err);

	struct_assign(s10_param, native_param, fl_return_value);
	struct_assign(s10_param, native_param, fl_provider_id);

	struct_assign(s10_param, native_param, fl_list.fl_digest_init);
	struct_assign(s10_param, native_param, fl_list.fl_digest);
	struct_assign(s10_param, native_param, fl_list.fl_digest_update);
	struct_assign(s10_param, native_param, fl_list.fl_digest_key);
	struct_assign(s10_param, native_param, fl_list.fl_digest_final);

	struct_assign(s10_param, native_param, fl_list.fl_encrypt_init);
	struct_assign(s10_param, native_param, fl_list.fl_encrypt);
	struct_assign(s10_param, native_param, fl_list.fl_encrypt_update);
	struct_assign(s10_param, native_param, fl_list.fl_encrypt_final);

	struct_assign(s10_param, native_param, fl_list.fl_decrypt_init);
	struct_assign(s10_param, native_param, fl_list.fl_decrypt);
	struct_assign(s10_param, native_param, fl_list.fl_decrypt_update);
	struct_assign(s10_param, native_param, fl_list.fl_decrypt_final);

	struct_assign(s10_param, native_param, fl_list.fl_mac_init);
	struct_assign(s10_param, native_param, fl_list.fl_mac);
	struct_assign(s10_param, native_param, fl_list.fl_mac_update);
	struct_assign(s10_param, native_param, fl_list.fl_mac_final);

	struct_assign(s10_param, native_param, fl_list.fl_sign_init);
	struct_assign(s10_param, native_param, fl_list.fl_sign);
	struct_assign(s10_param, native_param, fl_list.fl_sign_update);
	struct_assign(s10_param, native_param, fl_list.fl_sign_final);
	struct_assign(s10_param, native_param, fl_list.fl_sign_recover_init);
	struct_assign(s10_param, native_param, fl_list.fl_sign_recover);

	struct_assign(s10_param, native_param, fl_list.fl_verify_init);
	struct_assign(s10_param, native_param, fl_list.fl_verify);
	struct_assign(s10_param, native_param, fl_list.fl_verify_update);
	struct_assign(s10_param, native_param, fl_list.fl_verify_final);
	struct_assign(s10_param, native_param, fl_list.fl_verify_recover_init);
	struct_assign(s10_param, native_param, fl_list.fl_verify_recover);

	struct_assign(s10_param, native_param,
	    fl_list.fl_digest_encrypt_update);
	struct_assign(s10_param, native_param,
	    fl_list.fl_decrypt_digest_update);
	struct_assign(s10_param, native_param, fl_list.fl_sign_encrypt_update);
	struct_assign(s10_param, native_param,
	    fl_list.fl_decrypt_verify_update);

	struct_assign(s10_param, native_param, fl_list.fl_seed_random);
	struct_assign(s10_param, native_param, fl_list.fl_generate_random);

	struct_assign(s10_param, native_param, fl_list.fl_session_open);
	struct_assign(s10_param, native_param, fl_list.fl_session_close);
	struct_assign(s10_param, native_param, fl_list.fl_session_login);
	struct_assign(s10_param, native_param, fl_list.fl_session_logout);

	struct_assign(s10_param, native_param, fl_list.fl_object_create);
	struct_assign(s10_param, native_param, fl_list.fl_object_copy);
	struct_assign(s10_param, native_param, fl_list.fl_object_destroy);
	struct_assign(s10_param, native_param, fl_list.fl_object_get_size);
	struct_assign(s10_param, native_param,
	    fl_list.fl_object_get_attribute_value);
	struct_assign(s10_param, native_param,
	    fl_list.fl_object_set_attribute_value);
	struct_assign(s10_param, native_param, fl_list.fl_object_find_init);
	struct_assign(s10_param, native_param, fl_list.fl_object_find);
	struct_assign(s10_param, native_param, fl_list.fl_object_find_final);

	struct_assign(s10_param, native_param, fl_list.fl_key_generate);
	struct_assign(s10_param, native_param, fl_list.fl_key_generate_pair);
	struct_assign(s10_param, native_param, fl_list.fl_key_wrap);
	struct_assign(s10_param, native_param, fl_list.fl_key_unwrap);
	struct_assign(s10_param, native_param, fl_list.fl_key_derive);

	struct_assign(s10_param, native_param, fl_list.fl_init_token);
	struct_assign(s10_param, native_param, fl_list.fl_init_pin);
	struct_assign(s10_param, native_param, fl_list.fl_set_pin);

	struct_assign(s10_param, native_param, fl_list.prov_is_hash_limited);
	struct_assign(s10_param, native_param, fl_list.prov_hash_threshold);
	struct_assign(s10_param, native_param, fl_list.prov_hash_limit);

	return (brand_uucopy(&s10_param, (void *)arg, sizeof (s10_param)));
}

/*
 * The process contract CT_TGET and CT_TSET parameter structure ct_param_t
 * changed between S10 and Nevada, so we have to emulate the old S10
 * ct_param_t structure when interposing on the ioctl syscall.
 */
typedef struct s10_ct_param {
	uint32_t ctpm_id;
	uint32_t ctpm_pad;
	uint64_t ctpm_value;
} s10_ct_param_t;

/*
 * We have to emulate process contract ioctls for init(1M) because the
 * ioctl parameter structure changed between S10 and Nevada.  This is
 * a relatively simple process of filling Nevada structure fields,
 * shuffling values, and initiating a native system call.
 *
 * For now, we'll assume that all consumers of CT_TGET and CT_TSET will
 * need emulation.  We'll issue a stat to make sure that the ioctl
 * is meant for the contract file system.
 *
 */
static int
ctfs_ioctl(sysret_t *rval, int fdes, int cmd, intptr_t arg)
{
	int err;
	s10_ct_param_t s10param;
	ct_param_t param;
	struct stat statbuf;

	if ((err = __systemcall(rval, SYS_fstatat + 1024,
	    fdes, NULL, &statbuf, 0)) != 0)
		return (err);
	if (strcmp(statbuf.st_fstype, MNTTYPE_CTFS) != 0)
		return (__systemcall(rval, SYS_ioctl + 1024, fdes, cmd, arg));

	if (brand_uucopy((const void *)arg, &s10param, sizeof (s10param)) != 0)
		return (EFAULT);
	param.ctpm_id = s10param.ctpm_id;
	param.ctpm_size = sizeof (uint64_t);
	param.ctpm_value = &s10param.ctpm_value;
	if ((err = __systemcall(rval, SYS_ioctl + 1024, fdes, cmd, &param))
	    != 0)
		return (err);

	if (cmd == CT_TGET)
		return (brand_uucopy(&s10param, (void *)arg,
		    sizeof (s10param)));

	return (0);
}

/*
 * ZFS ioctls have changed in each Solaris 10 (S10) release as well as in
 * Solaris Next.  The brand wraps ZFS commands so that the native commands
 * are used, but we want to be sure no command sneaks in that uses ZFS
 * without our knowledge.  We'll abort the process if we see a ZFS ioctl.
 */
static int
zfs_ioctl(sysret_t *rval, int fdes, int cmd, intptr_t arg)
{
	static dev_t zfs_dev = (dev_t)-1;
	int err;

	if (passthru_otherdev_ioctl(&zfs_dev, ZFS_DEV, &err,
	    rval, fdes, cmd, arg) == 1)
		return (err);

	brand_abort(0, "ZFS ioctl!");
	/*NOTREACHED*/
	return (0);
}

struct s10_lofi_ioctl {
	uint32_t li_id;
	boolean_t li_force;
	char li_filename[MAXPATHLEN + 1];
};

static int
lofi_ioctl(sysret_t *rval, int fdes, int cmd, intptr_t arg)
{
	static dev_t lofi_dev = (dev_t)-1;
	struct s10_lofi_ioctl s10_param;
	struct lofi_ioctl native_param;
	int err;

	if (passthru_otherdev_ioctl(&lofi_dev, "/dev/lofictl", &err,
	    rval, fdes, cmd, arg) == 1)
		return (err);

	if (brand_uucopy((const void *)arg, &s10_param,
	    sizeof (s10_param)) != 0)
		return (EFAULT);

	/*
	 * Somewhat weirdly, EIO is what the S10 lofi driver would
	 * return for unrecognised cmds.
	 */
	if (cmd >= LOFI_CHECK_COMPRESSED)
		return (EIO);

	bzero(&native_param, sizeof (native_param));

	struct_assign(native_param, s10_param, li_id);
	struct_assign(native_param, s10_param, li_force);

	/*
	 * Careful here, this has changed from [MAXPATHLEN + 1] to
	 * [MAXPATHLEN].
	 */
	bcopy(s10_param.li_filename, native_param.li_filename,
	    sizeof (native_param.li_filename));
	native_param.li_filename[MAXPATHLEN - 1] = '\0';

	err = __systemcall(rval, SYS_ioctl + 1024, fdes, cmd, &native_param);

	struct_assign(s10_param, native_param, li_id);
	/* li_force is input-only */

	bcopy(native_param.li_filename, s10_param.li_filename,
	    sizeof (native_param.li_filename));

	(void) brand_uucopy(&s10_param, (void *)arg, sizeof (s10_param));
	return (err);
}

int
s10_ioctl(sysret_t *rval, int fdes, int cmd, intptr_t arg)
{
	switch (cmd) {
	case CRYPTO_GET_FUNCTION_LIST:
		return (crypto_ioctl(rval, fdes, cmd, arg));
	case CT_TGET:
		/*FALLTHRU*/
	case CT_TSET:
		return (ctfs_ioctl(rval, fdes, cmd, arg));
	case MNTIOC_GETMNTENT:
		/*FALLTHRU*/
	case MNTIOC_GETEXTMNTENT:
		/*FALLTHRU*/
	case MNTIOC_GETMNTANY:
		return (mntfs_ioctl(rval, fdes, cmd, arg));
	}

	switch (cmd & ~0xff) {
	case ZFS_IOC:
		return (zfs_ioctl(rval, fdes, cmd, arg));

	case LOFI_IOC_BASE:
		return (lofi_ioctl(rval, fdes, cmd, arg));

	default:
		break;
	}

	return (__systemcall(rval, SYS_ioctl + 1024, fdes, cmd, arg));
}

/*
 * Unfortunately, pwrite()'s behavior differs between S10 and Nevada when
 * applied to files opened with O_APPEND.  The offset argument is ignored and
 * the buffer is appended to the target file in S10, whereas the current file
 * position is ignored in Nevada (i.e., pwrite() acts as though the target file
 * wasn't opened with O_APPEND).  This is a result of the fix for CR 6655660
 * (pwrite() must ignore the O_APPEND/FAPPEND flag).
 *
 * We emulate the old S10 pwrite() behavior by checking whether the target file
 * was opened with O_APPEND.  If it was, then invoke the write() system call
 * instead of pwrite(); otherwise, invoke the pwrite() system call as usual.
 */
static int
s10_pwrite(sysret_t *rval, int fd, const void *bufferp, size_t num_bytes,
    off_t offset)
{
	int err;

	if ((err = __systemcall(rval, SYS_fcntl + 1024, fd, F_GETFL)) != 0)
		return (err);
	if (rval->sys_rval1 & O_APPEND)
		return (__systemcall(rval, SYS_write + 1024, fd, bufferp,
		    num_bytes));
	return (__systemcall(rval, SYS_pwrite + 1024, fd, bufferp, num_bytes,
	    offset));
}

#if !defined(_LP64)
/*
 * This is the large file version of the pwrite() system call for 32-bit
 * processes.  This exists for the same reason that s10_pwrite() exists; see
 * the comment above s10_pwrite().
 */
static int
s10_pwrite64(sysret_t *rval, int fd, const void *bufferp, size32_t num_bytes,
    uint32_t offset_1, uint32_t offset_2)
{
	int err;

	if ((err = __systemcall(rval, SYS_fcntl + 1024, fd, F_GETFL)) != 0)
		return (err);
	if (rval->sys_rval1 & O_APPEND)
		return (__systemcall(rval, SYS_write + 1024, fd, bufferp,
		    num_bytes));
	return (__systemcall(rval, SYS_pwrite64 + 1024, fd, bufferp,
	    num_bytes, offset_1, offset_2));
}
#endif	/* !_LP64 */

/*
 * These are convenience macros that s10_getdents_common() uses.  Both treat
 * their arguments, which should be character pointers, as dirent pointers or
 * dirent64 pointers and yield their d_name and d_reclen fields.  These
 * macros shouldn't be used outside of s10_getdents_common().
 */
#define	dirent_name(charptr)	((charptr) + name_offset)
#define	dirent_reclen(charptr)	\
	(*(unsigned short *)(uintptr_t)((charptr) + reclen_offset))

/*
 * This function contains code that is common to both s10_getdents() and
 * s10_getdents64().  See the comment above s10_getdents() for details.
 *
 * rval, fd, buf, and nbyte should be passed unmodified from s10_getdents()
 * and s10_getdents64().  getdents_syscall_id should be either SYS_getdents
 * or SYS_getdents64.  name_offset should be the the byte offset of
 * the d_name field in the dirent structures passed to the kernel via the
 * syscall represented by getdents_syscall_id.  reclen_offset should be
 * the byte offset of the d_reclen field in the aforementioned dirent
 * structures.
 */
static int
s10_getdents_common(sysret_t *rval, int fd, char *buf, size_t nbyte,
    int getdents_syscall_id, size_t name_offset, size_t reclen_offset)
{
	int err;
	size_t buf_size;
	char *local_buf;
	char *buf_current;

	/*
	 * Use a special brand operation, B_S10_ISFDXATTRDIR, to determine
	 * whether the specified file descriptor refers to an extended file
	 * attribute directory.  If it doesn't, then SYS_getdents won't
	 * reveal extended file attributes, in which case we can simply
	 * hand the syscall to the native kernel.
	 */
	if ((err = __systemcall(rval, SYS_brand + 1024, B_S10_ISFDXATTRDIR,
	    fd)) != 0)
		return (err);
	if (rval->sys_rval1 == 0)
		return (__systemcall(rval, getdents_syscall_id + 1024, fd, buf,
		    nbyte));

	/*
	 * The file descriptor refers to an extended file attributes directory.
	 * We need to create a dirent buffer that's as large as buf into which
	 * the native SYS_getdents will store the special extended file
	 * attribute directory's entries.  We can't dereference buf because
	 * it might be an invalid pointer!
	 */
	if (nbyte > MAXGETDENTS_SIZE)
		nbyte = MAXGETDENTS_SIZE;
	local_buf = (char *)malloc(nbyte);
	if (local_buf == NULL) {
		/*
		 * getdents(2) doesn't return an error code indicating a memory
		 * allocation error and it doesn't make sense to return any of
		 * its documented error codes for a malloc(3C) failure.  We'll
		 * use ENOMEM even though getdents(2) doesn't use it because it
		 * best describes the failure.
		 */
		(void) B_TRUSS_POINT_3(rval, getdents_syscall_id, ENOMEM, fd,
		    buf, nbyte);
		rval->sys_rval1 = -1;
		rval->sys_rval2 = 0;
		return (EIO);
	}

	/*
	 * Issue a native SYS_getdents syscall but use our local dirent buffer
	 * instead of buf.  This will allow us to examine the returned dirent
	 * structures immediately and copy them to buf later.  That way the
	 * calling process won't be able to see the dirent structures until
	 * we finish examining them.
	 */
	if ((err = __systemcall(rval, getdents_syscall_id + 1024, fd, local_buf,
	    nbyte)) != 0) {
		free(local_buf);
		return (err);
	}
	buf_size = rval->sys_rval1;
	if (buf_size == 0) {
		free(local_buf);
		return (0);
	}

	/*
	 * Look for SUNWattr_ro (VIEW_READONLY) and SUNWattr_rw
	 * (VIEW_READWRITE) in the directory entries and remove them
	 * from the dirent buffer.
	 */
	for (buf_current = local_buf;
	    (size_t)(buf_current - local_buf) < buf_size; /* cstyle */) {
		if (strcmp(dirent_name(buf_current), VIEW_READONLY) != 0 &&
		    strcmp(dirent_name(buf_current), VIEW_READWRITE) != 0) {
			/*
			 * The dirent refers to an attribute that should
			 * be visible to Solaris 10 processes.  Keep it
			 * and examine the next entry in the buffer.
			 */
			buf_current += dirent_reclen(buf_current);
		} else {
			/*
			 * We found either SUNWattr_ro (VIEW_READONLY)
			 * or SUNWattr_rw (VIEW_READWRITE).  Remove it
			 * from the dirent buffer by decrementing
			 * buf_size by the size of the entry and
			 * overwriting the entry with the remaining
			 * entries.
			 */
			buf_size -= dirent_reclen(buf_current);
			(void) memmove(buf_current, buf_current +
			    dirent_reclen(buf_current), buf_size -
			    (size_t)(buf_current - local_buf));
		}
	}

	/*
	 * Copy local_buf into buf so that the calling process can see
	 * the results.
	 */
	if ((err = brand_uucopy(local_buf, buf, buf_size)) != 0) {
		free(local_buf);
		rval->sys_rval1 = -1;
		rval->sys_rval2 = 0;
		return (err);
	}
	rval->sys_rval1 = buf_size;
	free(local_buf);
	return (0);
}

/*
 * Solaris Next added two special extended file attributes, SUNWattr_ro and
 * SUNWattr_rw, which are called "extended system attributes".  They have
 * special semantics (e.g., a process cannot unlink SUNWattr_ro) and should
 * not appear in solaris10-branded zones because no Solaris 10 applications,
 * including system commands such as tar(1), are coded to correctly handle these
 * special attributes.
 *
 * This emulation function solves the aforementioned problem by emulating
 * the getdents(2) syscall and filtering both system attributes out of resulting
 * directory entry lists.  The emulation function only filters results when
 * the given file descriptor refers to an extended file attribute directory.
 * Filtering getdents(2) results is expensive because it requires dynamic
 * memory allocation; however, the performance cost is tolerable because
 * we don't expect Solaris 10 processes to frequently examine extended file
 * attribute directories.
 *
 * The brand's emulation library needs two getdents(2) emulation functions
 * because getdents(2) comes in two flavors: non-largefile-aware getdents(2)
 * and largefile-aware getdents64(2).  s10_getdents() handles the non-largefile-
 * aware case for 32-bit processes and all getdents(2) syscalls for 64-bit
 * processes (64-bit processes use largefile-aware interfaces by default).
 * See s10_getdents64() below for the largefile-aware getdents64(2) emulation
 * function for 32-bit processes.
 */
static int
s10_getdents(sysret_t *rval, int fd, struct dirent *buf, size_t nbyte)
{
	return (s10_getdents_common(rval, fd, (char *)buf, nbyte, SYS_getdents,
	    offsetof(struct dirent, d_name),
	    offsetof(struct dirent, d_reclen)));
}

#ifndef	_LP64
/*
 * This is the largefile-aware version of getdents(2) for 32-bit processes.
 * This exists for the same reason that s10_getdents() exists.  See the comment
 * above s10_getdents().
 */
static int
s10_getdents64(sysret_t *rval, int fd, struct dirent64 *buf, size_t nbyte)
{
	return (s10_getdents_common(rval, fd, (char *)buf, nbyte,
	    SYS_getdents64, offsetof(struct dirent64, d_name),
	    offsetof(struct dirent64, d_reclen)));
}
#endif	/* !_LP64 */

#define	S10_TRIVIAL_ACL_CNT	6
#define	NATIVE_TRIVIAL_ACL_CNT	3

/*
 * Check if the ACL qualifies as a trivial ACL based on the native
 * interpretation.
 */
static boolean_t
has_trivial_native_acl(int cmd, int cnt, const char *fname, int fd)
{
	int i, err;
	sysret_t rval;
	ace_t buf[NATIVE_TRIVIAL_ACL_CNT];

	if (fname != NULL)
		err = __systemcall(&rval, SYS_pathconf + 1024, fname,
		    _PC_ACL_ENABLED);
	else
		err = __systemcall(&rval, SYS_fpathconf + 1024, fd,
		    _PC_ACL_ENABLED);
	if (err != 0 || rval.sys_rval1 != _ACL_ACE_ENABLED)
		return (B_FALSE);

	/*
	 * If we just got the ACL cnt, we don't need to get it again, its
	 * passed in as the cnt arg.
	 */
	if (cmd != ACE_GETACLCNT) {
		if (fname != NULL) {
			if (__systemcall(&rval, SYS_acl + 1024, fname,
			    ACE_GETACLCNT, 0, NULL) != 0)
				return (B_FALSE);
		} else {
			if (__systemcall(&rval, SYS_facl + 1024, fd,
			    ACE_GETACLCNT, 0, NULL) != 0)
				return (B_FALSE);
		}
		cnt = rval.sys_rval1;
	}

	if (cnt != NATIVE_TRIVIAL_ACL_CNT)
		return (B_FALSE);

	if (fname != NULL) {
		if (__systemcall(&rval, SYS_acl + 1024, fname, ACE_GETACL, cnt,
		    buf) != 0)
			return (B_FALSE);
	} else {
		if (__systemcall(&rval, SYS_facl + 1024, fd, ACE_GETACL, cnt,
		    buf) != 0)
			return (B_FALSE);
	}

	/*
	 * The following is based on the logic from the native OS
	 * ace_trivial_common() to determine if the native ACL is trivial.
	 */
	for (i = 0; i < cnt; i++) {
		switch (buf[i].a_flags & ACE_TYPE_FLAGS) {
		case ACE_OWNER:
		case ACE_GROUP|ACE_IDENTIFIER_GROUP:
		case ACE_EVERYONE:
			break;
		default:
			return (B_FALSE);
		}

		if (buf[i].a_flags & (ACE_FILE_INHERIT_ACE|
		    ACE_DIRECTORY_INHERIT_ACE|ACE_NO_PROPAGATE_INHERIT_ACE|
		    ACE_INHERIT_ONLY_ACE))
			return (B_FALSE);

		/*
		 * Special check for some special bits
		 *
		 * Don't allow anybody to deny reading basic
		 * attributes or a files ACL.
		 */
		if (buf[i].a_access_mask & (ACE_READ_ACL|ACE_READ_ATTRIBUTES) &&
		    buf[i].a_type == ACE_ACCESS_DENIED_ACE_TYPE)
			return (B_FALSE);

		/*
		 * Delete permissions are never set by default
		 */
		if (buf[i].a_access_mask & (ACE_DELETE|ACE_DELETE_CHILD))
			return (B_FALSE);
		/*
		 * only allow owner@ to have
		 * write_acl/write_owner/write_attributes/write_xattr/
		 */
		if (buf[i].a_type == ACE_ACCESS_ALLOWED_ACE_TYPE &&
		    (!(buf[i].a_flags & ACE_OWNER) && (buf[i].a_access_mask &
		    (ACE_WRITE_OWNER|ACE_WRITE_ACL| ACE_WRITE_ATTRIBUTES|
		    ACE_WRITE_NAMED_ATTRS))))
			return (B_FALSE);

	}

	return (B_TRUE);
}

/*
 * The following logic is based on the S10 adjust_ace_pair_common() code.
 */
static void
s10_adjust_ace_mask(void *pair, size_t access_off, size_t pairsize, mode_t mode)
{
	char *datap = (char *)pair;
	uint32_t *amask0 = (uint32_t *)(uintptr_t)(datap + access_off);
	uint32_t *amask1 = (uint32_t *)(uintptr_t)(datap + pairsize +
	    access_off);

	if (mode & S_IROTH)
		*amask1 |= ACE_READ_DATA;
	else
		*amask0 |= ACE_READ_DATA;
	if (mode & S_IWOTH)
		*amask1 |= ACE_WRITE_DATA|ACE_APPEND_DATA;
	else
		*amask0 |= ACE_WRITE_DATA|ACE_APPEND_DATA;
	if (mode & S_IXOTH)
		*amask1 |= ACE_EXECUTE;
	else
		*amask0 |= ACE_EXECUTE;
}

/*
 * Construct a trivial S10 style ACL.
 */
static int
make_trivial_s10_acl(const char *fname, int fd, ace_t *bp)
{
	int err;
	sysret_t rval;
	struct stat64 buf;
	ace_t trivial_s10_acl[] = {
		{(uint_t)-1, 0, ACE_OWNER, ACE_ACCESS_DENIED_ACE_TYPE},
		{(uint_t)-1, ACE_WRITE_ACL|ACE_WRITE_OWNER|ACE_WRITE_ATTRIBUTES|
		    ACE_WRITE_NAMED_ATTRS, ACE_OWNER,
		    ACE_ACCESS_ALLOWED_ACE_TYPE},
		{(uint_t)-1, 0, ACE_GROUP|ACE_IDENTIFIER_GROUP,
		    ACE_ACCESS_DENIED_ACE_TYPE},
		{(uint_t)-1, 0, ACE_GROUP|ACE_IDENTIFIER_GROUP,
		    ACE_ACCESS_ALLOWED_ACE_TYPE},
		{(uint_t)-1, ACE_WRITE_ACL|ACE_WRITE_OWNER|ACE_WRITE_ATTRIBUTES|
		    ACE_WRITE_NAMED_ATTRS, ACE_EVERYONE,
		    ACE_ACCESS_DENIED_ACE_TYPE},
		{(uint_t)-1, ACE_READ_ACL|ACE_READ_ATTRIBUTES|
		    ACE_READ_NAMED_ATTRS|ACE_SYNCHRONIZE, ACE_EVERYONE,
		    ACE_ACCESS_ALLOWED_ACE_TYPE}
	};

	if (fname != NULL) {
		if ((err = __systemcall(&rval, SYS_fstatat64 + 1024, AT_FDCWD,
		    fname, &buf, 0)) != 0)
			return (err);
	} else {
		if ((err = __systemcall(&rval, SYS_fstatat64 + 1024, fd,
		    NULL, &buf, 0)) != 0)
			return (err);
	}

	s10_adjust_ace_mask(&trivial_s10_acl[0], offsetof(ace_t, a_access_mask),
	    sizeof (ace_t), (buf.st_mode & 0700) >> 6);
	s10_adjust_ace_mask(&trivial_s10_acl[2], offsetof(ace_t, a_access_mask),
	    sizeof (ace_t), (buf.st_mode & 0070) >> 3);
	s10_adjust_ace_mask(&trivial_s10_acl[4], offsetof(ace_t, a_access_mask),
	    sizeof (ace_t), buf.st_mode & 0007);

	if (brand_uucopy(&trivial_s10_acl, bp, sizeof (trivial_s10_acl)) != 0)
		return (EFAULT);

	return (0);
}

/*
 * The definition of a trivial ace-style ACL (used by ZFS and NFSv4) has been
 * simplified since S10.  Instead of 6 entries on a trivial S10 ACE ACL we now
 * have 3 streamlined entries.  The new, simpler trivial style confuses S10
 * commands such as 'ls -v' or 'cp -p' which don't see the expected S10 trivial
 * ACL entries and thus assume that there is a complex ACL on the file.
 *
 * See: PSARC/2010/029 Improved ACL interoperability
 *
 * Note that the trival ACL detection code is implemented in acl_trival() in
 * lib/libsec/common/aclutils.c.  It always uses the acl() syscall (not the
 * facl syscall) to determine if an ACL is trivial.  However, we emulate both
 * acl() and facl() so that the two provide consistent results.
 *
 * We don't currently try to emulate setting of ACLs since the primary
 * consumer of this feature is SMB or NFSv4 servers, neither of which are
 * supported in solaris10-branded zones.  If ACLs are used they must be set on
 * files using the native OS interpretation.
 */
int
s10_acl(sysret_t *rval, const char *fname, int cmd, int nentries, void *aclbufp)
{
	int res;

	res = __systemcall(rval, SYS_acl + 1024, fname, cmd, nentries, aclbufp);

	switch (cmd) {
	case ACE_GETACLCNT:
		if (res == 0 && has_trivial_native_acl(ACE_GETACLCNT,
		    rval->sys_rval1, fname, 0)) {
			rval->sys_rval1 = S10_TRIVIAL_ACL_CNT;
		}
		break;
	case ACE_GETACL:
		if (res == 0 &&
		    has_trivial_native_acl(ACE_GETACL, 0, fname, 0) &&
		    nentries >= S10_TRIVIAL_ACL_CNT) {
			res = make_trivial_s10_acl(fname, 0, aclbufp);
			rval->sys_rval1 = S10_TRIVIAL_ACL_CNT;
		}
		break;
	}

	return (res);
}

int
s10_facl(sysret_t *rval, int fdes, int cmd, int nentries, void *aclbufp)
{
	int res;

	res = __systemcall(rval, SYS_facl + 1024, fdes, cmd, nentries, aclbufp);

	switch (cmd) {
	case ACE_GETACLCNT:
		if (res == 0 && has_trivial_native_acl(ACE_GETACLCNT,
		    rval->sys_rval1, NULL, fdes)) {
			rval->sys_rval1 = S10_TRIVIAL_ACL_CNT;
		}
		break;
	case ACE_GETACL:
		if (res == 0 &&
		    has_trivial_native_acl(ACE_GETACL, 0, NULL, fdes) &&
		    nentries >= S10_TRIVIAL_ACL_CNT) {
			res = make_trivial_s10_acl(NULL, fdes, aclbufp);
			rval->sys_rval1 = S10_TRIVIAL_ACL_CNT;
		}
		break;
	}

	return (res);
}

#define	S10_AC_PROC		(0x1 << 28)
#define	S10_AC_TASK		(0x2 << 28)
#define	S10_AC_FLOW		(0x4 << 28)
#define	S10_AC_MODE(x)		((x) & 0xf0000000)
#define	S10_AC_OPTION(x)	((x) & 0x0fffffff)

/*
 * The mode shift, mode mask and option mask for acctctl have changed.  The
 * mode is currently the top full byte and the option is the lower 3 full bytes.
 */
int
s10_acctctl(sysret_t *rval, int cmd, void *buf, size_t bufsz)
{
	int mode = S10_AC_MODE(cmd);
	int option = S10_AC_OPTION(cmd);

	switch (mode) {
	case S10_AC_PROC:
		mode = AC_PROC;
		break;
	case S10_AC_TASK:
		mode = AC_TASK;
		break;
	case S10_AC_FLOW:
		mode = AC_FLOW;
		break;
	default:
		return (B_TRUSS_POINT_3(rval, SYS_acctctl, EINVAL, cmd, buf,
		    bufsz));
	}

	return (__systemcall(rval, SYS_acctctl + 1024, mode | option, buf,
	    bufsz));
}

/*
 * The Audit Policy parameters have changed due to:
 *    6466722 audituser and AUDIT_USER are defined, unused, undocumented and
 *            should be removed.
 *
 * In S10 we had the following flag:
 *	#define AUDIT_USER 0x0040
 * which doesn't exist in Solaris Next where the subsequent flags are shifted
 * down.  For example, in S10 we had:
 *	#define AUDIT_GROUP     0x0080
 * but on Solaris Next we have:
 *	#define AUDIT_GROUP     0x0040
 * AUDIT_GROUP has the value AUDIT_USER had in S10 and all of the subsequent
 * bits are also shifted one place.
 *
 * When we're getting or setting the Audit Policy parameters we need to
 * shift the outgoing or incoming bits into their proper positions.  Since
 * S10_AUDIT_USER was always unused, we always clear that bit on A_GETPOLICY.
 *
 * The command we care about, BSM_AUDITCTL, passes the most parameters (3),
 * so declare this function to take up to 4 args and just pass them on.
 * The number of parameters for s10_auditsys needs to be equal to the BSM_*
 * subcommand that has the most parameters, since we want to pass all
 * parameters through, regardless of which subcommands we interpose on.
 *
 * Note that the auditsys system call uses the SYSENT_AP macro wrapper instead
 * of the more common SYSENT_CI macro.  This means the return value is a
 * SE_64RVAL so the syscall table uses RV_64RVAL.
 */

#define	S10_AUDIT_HMASK	0xffffffc0
#define	S10_AUDIT_LMASK	0x3f
#define	S10_AUC_NOSPACE	0x3

int
s10_auditsys(sysret_t *rval, int bsmcmd, intptr_t a0, intptr_t a1, intptr_t a2)
{
	int	    err;
	uint32_t    m;

	if (bsmcmd != BSM_AUDITCTL)
		return (__systemcall(rval, SYS_auditsys + 1024, bsmcmd, a0, a1,
		    a2));

	if ((int)a0 == A_GETPOLICY) {
		if ((err = __systemcall(rval, SYS_auditsys + 1024, bsmcmd, a0,
		    &m, a2)) != 0)
			return (err);
		m = ((m & S10_AUDIT_HMASK) << 1) | (m & S10_AUDIT_LMASK);
		if (brand_uucopy(&m, (void *)a1, sizeof (m)) != 0)
			return (EFAULT);
		return (0);

	} else if ((int)a0 == A_SETPOLICY) {
		if (brand_uucopy((const void *)a1, &m, sizeof (m)) != 0)
			return (EFAULT);
		m = ((m >> 1) & S10_AUDIT_HMASK) | (m & S10_AUDIT_LMASK);
		return (__systemcall(rval, SYS_auditsys + 1024, bsmcmd, a0, &m,
		    a2));
	} else if ((int)a0 == A_GETCOND) {
		if ((err = __systemcall(rval, SYS_auditsys + 1024, bsmcmd, a0,
		    &m, a2)) != 0)
			return (err);
		if (m == AUC_NOSPACE)
			m = S10_AUC_NOSPACE;
		if (brand_uucopy(&m, (void *)a1, sizeof (m)) != 0)
			return (EFAULT);
		return (0);
	} else if ((int)a0 == A_SETCOND) {
		if (brand_uucopy((const void *)a1, &m, sizeof (m)) != 0)
			return (EFAULT);
		if (m == S10_AUC_NOSPACE)
			m = AUC_NOSPACE;
		return (__systemcall(rval, SYS_auditsys + 1024, bsmcmd, a0, &m,
		    a2));
	}

	return (__systemcall(rval, SYS_auditsys + 1024, bsmcmd, a0, a1, a2));
}

/*
 * Determine whether the executable passed to SYS_exec or SYS_execve is a
 * native executable.  The s10_npreload.so invokes the B_S10_NATIVE brand
 * operation which patches up the processes exec info to eliminate any trace
 * of the wrapper.  That will make pgrep and other commands that examine
 * process' executable names and command-line parameters work properly.
 */
static int
s10_exec_native(sysret_t *rval, const char *fname, const char **argp,
    const char **envp)
{
	const char *filename = fname;
	char path[64];
	int err;

	/* Get a copy of the executable we're trying to run */
	path[0] = '\0';
	(void) brand_uucopystr(filename, path, sizeof (path));

	/* Check if we're trying to run a native binary */
	if (strncmp(path, "/.SUNWnative/usr/lib/brand/solaris10/s10_native",
	    sizeof (path)) != 0)
		return (0);

	/* Skip the first element in the argv array */
	argp++;

	/*
	 * The the path of the dynamic linker is the second parameter
	 * of s10_native_exec().
	 */
	if (brand_uucopy(argp, &filename, sizeof (char *)) != 0)
		return (EFAULT);

	/* If an exec call succeeds, it never returns */
	err = __systemcall(rval, SYS_brand + 1024, B_EXEC_NATIVE, filename,
	    argp, envp, NULL, NULL, NULL);
	brand_assert(err != 0);
	return (err);
}

/*
 * Interpose on the SYS_exec syscall to detect native wrappers.
 */
int
s10_exec(sysret_t *rval, const char *fname, const char **argp)
{
	int err;

	if ((err = s10_exec_native(rval, fname, argp, NULL)) != 0)
		return (err);

	/* If an exec call succeeds, it never returns */
	err = __systemcall(rval, SYS_execve + 1024, fname, argp, NULL);
	brand_assert(err != 0);
	return (err);
}

/*
 * Interpose on the SYS_execve syscall to detect native wrappers.
 */
int
s10_execve(sysret_t *rval, const char *fname, const char **argp,
    const char **envp)
{
	int err;

	if ((err = s10_exec_native(rval, fname, argp, envp)) != 0)
		return (err);

	/* If an exec call succeeds, it never returns */
	err = __systemcall(rval, SYS_execve + 1024, fname, argp, envp);
	brand_assert(err != 0);
	return (err);
}

/*
 * S10's issetugid() syscall is now a subcode to privsys().
 */
static int
s10_issetugid(sysret_t *rval)
{
	return (__systemcall(rval, SYS_privsys + 1024, PRIVSYS_ISSETUGID,
	    0, 0, 0, 0, 0));
}

/*
 * S10's socket() syscall does not split type and flags
 */
static int
s10_so_socket(sysret_t *rval, int domain, int type, int protocol,
    char *devpath, int version)
{
	if ((type & ~SOCK_TYPE_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	return (__systemcall(rval, SYS_so_socket + 1024, domain, type,
	    protocol, devpath, version));
}

/*
 * S10's pipe() syscall has a different calling convention
 */
static int
s10_pipe(sysret_t *rval)
{
	int fds[2], err;
	if ((err = __systemcall(rval, SYS_pipe + 1024, fds, 0)) != 0)
		return (err);

	rval->sys_rval1 = fds[0];
	rval->sys_rval2 = fds[1];
	return (0);
}

/*
 * S10's accept() syscall takes three arguments
 */
static int
s10_accept(sysret_t *rval, int sock, struct sockaddr *addr, uint_t *addrlen,
    int version)
{
	return (__systemcall(rval, SYS_accept + 1024, sock, addr, addrlen,
	    version, 0));
}

static long
s10_uname(sysret_t *rv, uintptr_t p1)
{
	struct utsname un, *unp = (struct utsname *)p1;
	int rev, err;

	if ((err = __systemcall(rv, SYS_uname + 1024, &un)) != 0)
		return (err);

	rev = atoi(&un.release[2]);
	brand_assert(rev >= 11);
	bzero(un.release, _SYS_NMLN);
	(void) strlcpy(un.release, S10_UTS_RELEASE, _SYS_NMLN);
	bzero(un.version, _SYS_NMLN);
	(void) strlcpy(un.version, S10_UTS_VERSION, _SYS_NMLN);

	/* copy out the modified uname info */
	return (brand_uucopy(&un, unp, sizeof (un)));
}

int
s10_sysconfig(sysret_t *rv, int which)
{
	long value;

	/*
	 * We must interpose on the sysconfig(2) requests
	 * that deal with the realtime signal number range.
	 * All others get passed to the native sysconfig(2).
	 */
	switch (which) {
	case _CONFIG_RTSIG_MAX:
		value = S10_SIGRTMAX - S10_SIGRTMIN + 1;
		break;
	case _CONFIG_SIGRT_MIN:
		value = S10_SIGRTMIN;
		break;
	case _CONFIG_SIGRT_MAX:
		value = S10_SIGRTMAX;
		break;
	default:
		return (__systemcall(rv, SYS_sysconfig + 1024, which));
	}

	(void) B_TRUSS_POINT_1(rv, SYS_sysconfig, 0, which);
	rv->sys_rval1 = value;
	rv->sys_rval2 = 0;

	return (0);
}

int
s10_sysinfo(sysret_t *rv, int command, char *buf, long count)
{
	char *value;
	int len;

	/*
	 * We must interpose on the sysinfo(2) commands SI_RELEASE and
	 * SI_VERSION; all others get passed to the native sysinfo(2)
	 * command.
	 */
	switch (command) {
		case SI_RELEASE:
			value = S10_UTS_RELEASE;
			break;

		case SI_VERSION:
			value = S10_UTS_VERSION;
			break;

		default:
			/*
			 * The default action is to pass the command to the
			 * native sysinfo(2) syscall.
			 */
			return (__systemcall(rv, SYS_systeminfo + 1024,
			    command, buf, count));
	}

	len = strlen(value) + 1;
	if (count > 0) {
		if (brand_uucopystr(value, buf, count) != 0)
			return (EFAULT);

		/*
		 * Assure NULL termination of buf as brand_uucopystr() doesn't.
		 */
		if (len > count && brand_uucopy("\0", buf + (count - 1), 1)
		    != 0)
			return (EFAULT);
	}

	/*
	 * On success, sysinfo(2) returns the size of buffer required to hold
	 * the complete value plus its terminating NULL byte.
	 */
	(void) B_TRUSS_POINT_3(rv, SYS_systeminfo, 0, command, buf, count);
	rv->sys_rval1 = len;
	rv->sys_rval2 = 0;
	return (0);
}

#if defined(__x86)
#if defined(__amd64)
/*
 * 64-bit x86 LWPs created by SYS_lwp_create start here if they need to set
 * their %fs registers to the legacy Solaris 10 selector value.
 *
 * This function does three things:
 *
 *	1.  Trap to the kernel so that it can set %fs to the legacy Solaris 10
 *	    selector value.
 *	2.  Read the LWP's true entry point (the entry point supplied by libc
 *	    when SYS_lwp_create was invoked) from %r14.
 *	3.  Eliminate this function's stack frame and pass control to the LWP's
 *	    true entry point.
 *
 * See the comment above s10_lwp_create_correct_fs() (see below) for the reason
 * why this function exists.
 */
/*ARGSUSED*/
static void
s10_lwp_create_entry_point(void *ulwp_structp)
{
	sysret_t rval;

	/*
	 * The new LWP's %fs register is initially zero, but libc won't
	 * function correctly when %fs is zero.  Change the LWP's %fs register
	 * via SYS_brand.
	 */
	(void) __systemcall(&rval, SYS_brand + 1024, B_S10_FSREGCORRECTION);

	/*
	 * Jump to the true entry point, which is stored in %r14.
	 * Remove our stack frame before jumping so that
	 * s10_lwp_create_entry_point() won't be seen in stack traces.
	 *
	 * NOTE: s10_lwp_create_entry_point() pushes %r12 onto its stack frame
	 * so that it can use it as a temporary register.  We don't restore %r12
	 * in this assembly block because we don't care about its value (and
	 * neither does _lwp_start()).  Besides, the System V ABI AMD64
	 * Actirecture Processor Supplement doesn't specify that %r12 should
	 * have a special value when LWPs start, so we can ignore its value when
	 * we jump to the true entry point.  Furthermore, %r12 is a callee-saved
	 * register, so the true entry point should push %r12 onto its stack
	 * before using the register.  We ignore %r14 after we read it for
	 * similar reasons.
	 *
	 * NOTE: The compiler will generate a function epilogue for this
	 * function despite the fact that the LWP will never execute it.
	 * We could hand-code this entire function in assembly to eliminate
	 * the epilogue, but the epilogue is only three or four instructions,
	 * so we wouldn't save much space.  Besides, why would we want
	 * to create yet another ugly, hard-to-maintain assembly function when
	 * we could write most of it in C?
	 */
	__asm__ __volatile__(
	    "movq %0, %%rdi\n\t"	/* pass ulwp_structp as arg1 */
	    "movq %%rbp, %%rsp\n\t"	/* eliminate the stack frame */
	    "popq %%rbp\n\t"
	    "jmp *%%r14\n\t"		/* jump to the true entry point */
	    : : "r" (ulwp_structp));
	/*NOTREACHED*/
}

/*
 * The S10 libc expects that %fs will be nonzero for new 64-bit x86 LWPs but the
 * Nevada kernel clears %fs for such LWPs.  Unforunately, new LWPs do not issue
 * SYS_lwp_private (see s10_lwp_private() below) after they are created, so
 * we must ensure that new LWPs invoke a brand operation that sets %fs to a
 * nonzero value immediately after their creation.
 *
 * The easiest way to do this is to make new LWPs start at a special function,
 * s10_lwp_create_entry_point() (see its definition above), that invokes the
 * brand operation that corrects %fs.  We'll store the entry points of new LWPs
 * in their %r14 registers so that s10_lwp_create_entry_point() can find and
 * call them after invoking the special brand operation.  %r14 is a callee-saved
 * register; therefore, any functions invoked by s10_lwp_create_entry_point()
 * and all functions dealing with signals (e.g., sigacthandler()) will preserve
 * %r14 for s10_lwp_create_entry_point().
 *
 * The Nevada kernel can safely work with nonzero %fs values because the kernel
 * configures per-thread %fs segment descriptors so that the legacy %fs selector
 * value will still work.  See the comment in lwp_load() regarding %fs and
 * %fsbase in 64-bit x86 processes.
 *
 * This emulation exists thanks to CRs 6467491 and 6501650.
 */
static int
s10_lwp_create_correct_fs(sysret_t *rval, ucontext_t *ucp, int flags,
    id_t *new_lwp)
{
	ucontext_t s10_uc;

	/*
	 * Copy the supplied ucontext_t structure to the local stack
	 * frame and store the new LWP's entry point (the value of %rip
	 * stored in the ucontext_t) in the new LWP's %r14 register.
	 * Then make s10_lwp_create_entry_point() the new LWP's entry
	 * point.
	 */
	if (brand_uucopy(ucp, &s10_uc, sizeof (s10_uc)) != 0)
		return (EFAULT);

	s10_uc.uc_mcontext.gregs[REG_R14] = s10_uc.uc_mcontext.gregs[REG_RIP];
	s10_uc.uc_mcontext.gregs[REG_RIP] = (greg_t)s10_lwp_create_entry_point;

	/*  fix up the signal mask */
	if (s10_uc.uc_flags & UC_SIGMASK)
		(void) s10sigset_to_native(&s10_uc.uc_sigmask,
		    &s10_uc.uc_sigmask);

	/*
	 * Issue SYS_lwp_create to create the new LWP.  We pass the
	 * modified ucontext_t to make sure that the new LWP starts at
	 * s10_lwp_create_entry_point().
	 */
	return (__systemcall(rval, SYS_lwp_create + 1024, &s10_uc,
	    flags, new_lwp));
}
#endif	/* __amd64 */

/*
 * SYS_lwp_private is issued by libc_init() to set %fsbase in 64-bit x86
 * processes.  The Nevada kernel sets %fs to zero but the S10 libc expects
 * %fs to be nonzero.  We'll pass the issued system call to the kernel untouched
 * and invoke a brand operation to set %fs to the legacy S10 selector value.
 *
 * This emulation exists thanks to CRs 6467491 and 6501650.
 */
static int
s10_lwp_private(sysret_t *rval, int cmd, int which, uintptr_t base)
{
#if defined(__amd64)
	int err;

	/*
	 * The current LWP's %fs register should be zero.  Determine whether the
	 * Solaris 10 libc with which we're working functions correctly when %fs
	 * is zero by calling thr_main() after issuing the SYS_lwp_private
	 * syscall.  If thr_main() barfs (returns -1), then change the LWP's %fs
	 * register via SYS_brand and patch brand_sysent_table so that issuing
	 * SYS_lwp_create executes s10_lwp_create_correct_fs() rather than the
	 * default s10_lwp_create().  s10_lwp_create_correct_fs() will
	 * guarantee that new LWPs will have correct %fs values.
	 */
	if ((err = __systemcall(rval, SYS_lwp_private + 1024, cmd, which,
	    base)) != 0)
		return (err);
	if (thr_main() == -1) {
		/*
		 * SYS_lwp_private is only issued by libc_init(), which is
		 * executed when libc is first loaded by ld.so.1.  Thus we
		 * are guaranteed to be single-threaded at this point.  Even
		 * if we were multithreaded at this point, writing a 64-bit
		 * value to the st_callc field of a brand_sysent_table
		 * entry is guaranteed to be atomic on 64-bit x86 chips
		 * as long as the field is not split across cache lines
		 * (It shouldn't be.).  See chapter 8, section 1.1 of
		 * "The Intel 64 and IA32 Architectures Software Developer's
		 * Manual," Volume 3A for more details.
		 */
		brand_sysent_table[SYS_lwp_create].st_callc =
		    (sysent_cb_t)s10_lwp_create_correct_fs;
		return (__systemcall(rval, SYS_brand + 1024,
		    B_S10_FSREGCORRECTION));
	}
	return (0);
#else	/* !__amd64 */
	return (__systemcall(rval, SYS_lwp_private + 1024, cmd, which, base));
#endif	/* !__amd64 */
}
#endif	/* __x86 */

/*
 * The Opensolaris versions of lwp_mutex_timedlock() and lwp_mutex_trylock()
 * add an extra argument to the interfaces, a uintptr_t value for the mutex's
 * mutex_owner field.  The Solaris 10 libc assigns the mutex_owner field at
 * user-level, so we just make the extra argument be zero in both syscalls.
 */

static int
s10_lwp_mutex_timedlock(sysret_t *rval, lwp_mutex_t *lp, timespec_t *tsp)
{
	return (__systemcall(rval, SYS_lwp_mutex_timedlock + 1024, lp, tsp, 0));
}

static int
s10_lwp_mutex_trylock(sysret_t *rval, lwp_mutex_t *lp)
{
	return (__systemcall(rval, SYS_lwp_mutex_trylock + 1024, lp, 0));
}

/*
 * If the emul_global_zone flag is set then emulate some aspects of the
 * zone system call.  In particular, emulate the global zone ID on the
 * ZONE_LOOKUP subcommand and emulate some of the global zone attributes
 * on the ZONE_GETATTR subcommand.  If the flag is not set or we're performing
 * some other operation, simply pass the calls through.
 */
int
s10_zone(sysret_t *rval, int cmd, void *arg1, void *arg2, void *arg3,
    void *arg4)
{
	char		*aval;
	int		len;
	zoneid_t	zid;
	int		attr;
	char		*buf;
	size_t		bufsize;

	/*
	 * We only emulate the zone syscall for a subset of specific commands,
	 * otherwise we just pass the call through.
	 */
	if (!emul_global_zone)
		return (__systemcall(rval, SYS_zone + 1024, cmd, arg1, arg2,
		    arg3, arg4));

	switch (cmd) {
	case ZONE_LOOKUP:
		(void) B_TRUSS_POINT_1(rval, SYS_zone, 0, cmd);
		rval->sys_rval1 = GLOBAL_ZONEID;
		rval->sys_rval2 = 0;
		return (0);

	case ZONE_GETATTR:
		zid = (zoneid_t)(uintptr_t)arg1;
		attr = (int)(uintptr_t)arg2;
		buf = (char *)arg3;
		bufsize = (size_t)arg4;

		/*
		 * If the request is for the global zone then we're emulating
		 * that, otherwise pass this thru.
		 */
		if (zid != GLOBAL_ZONEID)
			goto passthru;

		switch (attr) {
		case ZONE_ATTR_NAME:
			aval = GLOBAL_ZONENAME;
			break;

		case ZONE_ATTR_BRAND:
			aval = NATIVE_BRAND_NAME;
			break;
		default:
			/*
			 * We only emulate a subset of the attrs, use the
			 * real zone id to pass thru the rest.
			 */
			arg1 = (void *)(uintptr_t)zoneid;
			goto passthru;
		}

		(void) B_TRUSS_POINT_5(rval, SYS_zone, 0, cmd, zid, attr,
		    buf, bufsize);

		len = strlen(aval) + 1;
		if (len > bufsize)
			return (ENAMETOOLONG);

		if (buf != NULL) {
			if (len == 1) {
				if (brand_uucopy("\0", buf, 1) != 0)
					return (EFAULT);
			} else {
				if (brand_uucopystr(aval, buf, len) != 0)
					return (EFAULT);

				/*
				 * Assure NULL termination of "buf" as
				 * brand_uucopystr() does NOT.
				 */
				if (brand_uucopy("\0", buf + (len - 1), 1) != 0)
					return (EFAULT);
			}
		}

		rval->sys_rval1 = len;
		rval->sys_rval2 = 0;
		return (0);

	default:
		break;
	}

passthru:
	return (__systemcall(rval, SYS_zone + 1024, cmd, arg1, arg2, arg3,
	    arg4));
}

/*ARGSUSED*/
int
brand_init(int argc, char *argv[], char *envp[])
{
	sysret_t		rval;
	ulong_t			ldentry;
	int			err;
	char			*bname;

	brand_pre_init();

	/*
	 * Cache the pid of the zone's init process and determine if
	 * we're init(1m) for the zone.  Remember: we might be init
	 * now, but as soon as we fork(2) we won't be.
	 */
	(void) get_initpid_info();

	/* get the current zoneid */
	err = __systemcall(&rval, SYS_zone, ZONE_LOOKUP, NULL);
	brand_assert(err == 0);
	zoneid = (zoneid_t)rval.sys_rval1;

	/* Get the zone's emulation bitmap. */
	if ((err = __systemcall(&rval, SYS_zone, ZONE_GETATTR, zoneid,
	    S10_EMUL_BITMAP, emul_bitmap, sizeof (emul_bitmap))) != 0) {
		brand_abort(err, "The zone's patch level is unsupported");
		/*NOTREACHED*/
	}

	bname = basename(argv[0]);

	/*
	 * In general we want the S10 commands that are zone-aware to continue
	 * to behave as they normally do within a zone.  Since these commands
	 * are zone-aware, they should continue to "do the right thing".
	 * However, some zone-aware commands aren't going to work the way
	 * we expect them to inside the branded zone.  In particular, the pkg
	 * and patch commands will not properly manage all pkgs/patches
	 * unless the commands think they are running in the global zone.  For
	 * these commands we want to emulate the global zone.
	 *
	 * We don't do any emulation for pkgcond since it is typically used
	 * in pkg/patch postinstall scripts and we want those scripts to do
	 * the right thing inside a zone.
	 *
	 * One issue is the handling of hollow pkgs.  Since the pkgs are
	 * hollow, they won't use pkgcond in their postinstall scripts.  These
	 * pkgs typically are installing drivers so we handle that by
	 * replacing add_drv and rem_drv in the s10_boot script.
	 */
	if (strcmp("pkgadd", bname) == 0 || strcmp("pkgrm", bname) == 0 ||
	    strcmp("patchadd", bname) == 0 || strcmp("patchrm", bname) == 0)
		emul_global_zone = B_TRUE;

	ldentry = brand_post_init(S10_VERSION, argc, argv, envp);

	brand_runexe(argv, ldentry);
	/*NOTREACHED*/
	brand_abort(0, "brand_runexe() returned");
	return (-1);
}

/*
 * This table must have at least NSYSCALL entries in it.
 *
 * The second parameter of each entry in the brand_sysent_table
 * contains the number of parameters and flags that describe the
 * syscall return value encoding.  See the block comments at the
 * top of this file for more information about the syscall return
 * value flags and when they should be used.
 */
brand_sysent_table_t brand_sysent_table[] = {
#if defined(__sparc) && !defined(__sparcv9)
	EMULATE(brand_indir, 9 | RV_64RVAL),	/*  0 */
#else
	NOSYS,					/*  0 */
#endif
	NOSYS,					/*   1 */
	EMULATE(s10_forkall, 0 | RV_32RVAL2),	/*   2 */
	NOSYS,					/*   3 */
	NOSYS,					/*   4 */
	EMULATE(s10_open, 3 | RV_DEFAULT),	/*   5 */
	NOSYS,					/*   6 */
	EMULATE(s10_wait, 0 | RV_32RVAL2),	/*   7 */
	EMULATE(s10_creat, 2 | RV_DEFAULT),	/*   8 */
	EMULATE(s10_link, 2 | RV_DEFAULT),	/*   9 */
	EMULATE(s10_unlink, 1 | RV_DEFAULT),	/*  10 */
	EMULATE(s10_exec, 2 | RV_DEFAULT),	/*  11 */
	NOSYS,					/*  12 */
	NOSYS,					/*  13 */
	EMULATE(s10_mknod, 3 | RV_DEFAULT),	/*  14 */
	EMULATE(s10_chmod, 2 | RV_DEFAULT),	/*  15 */
	EMULATE(s10_chown, 3 | RV_DEFAULT),	/*  16 */
	NOSYS,					/*  17 */
	EMULATE(s10_stat, 2 | RV_DEFAULT),	/*  18 */
	NOSYS,					/*  19 */
	NOSYS,					/*  20 */
	NOSYS,					/*  21 */
	EMULATE(s10_umount, 1 | RV_DEFAULT),	/*  22 */
	NOSYS,					/*  23 */
	NOSYS,					/*  24 */
	NOSYS,					/*  25 */
	NOSYS,					/*  26 */
	NOSYS,					/*  27 */
	EMULATE(s10_fstat, 2 | RV_DEFAULT),	/*  28 */
	NOSYS,					/*  29 */
	EMULATE(s10_utime, 2 | RV_DEFAULT),	/*  30 */
	NOSYS,					/*  31 */
	NOSYS,					/*  32 */
	EMULATE(s10_access, 2 | RV_DEFAULT),	/*  33 */
	NOSYS,					/*  34 */
	NOSYS,					/*  35 */
	NOSYS,					/*  36 */
	EMULATE(s10_kill, 2 | RV_DEFAULT),	/*  37 */
	NOSYS,					/*  38 */
	NOSYS,					/*  39 */
	NOSYS,					/*  40 */
	EMULATE(s10_dup, 1 | RV_DEFAULT),	/*  41 */
	EMULATE(s10_pipe, 0 | RV_32RVAL2),	/*  42 */
	NOSYS,					/*  43 */
	NOSYS,					/*  44 */
	NOSYS,					/*  45 */
	NOSYS,					/*  46 */
	NOSYS,					/*  47 */
	NOSYS,					/*  48 */
	NOSYS,					/*  49 */
	NOSYS,					/*  50 */
	NOSYS,					/*  51 */
	NOSYS,					/*  52 */
	NOSYS,					/*  53 */
	EMULATE(s10_ioctl, 3 | RV_DEFAULT),	/*  54 */
	NOSYS,					/*  55 */
	NOSYS,					/*  56 */
	NOSYS,					/*  57 */
	NOSYS,					/*  58 */
	EMULATE(s10_execve, 3 | RV_DEFAULT),	/*  59 */
	NOSYS,					/*  60 */
	NOSYS,					/*  61 */
	NOSYS,					/*  62 */
	NOSYS,					/*  63 */
	NOSYS,					/*  64 */
	NOSYS,					/*  65 */
	NOSYS,					/*  66 */
	NOSYS,					/*  67 */
	NOSYS,					/*  68 */
	NOSYS,					/*  69 */
	NOSYS,					/*  70 */
	EMULATE(s10_acctctl, 3 | RV_DEFAULT),	/*  71 */
	NOSYS,					/*  72 */
	NOSYS,					/*  73 */
	NOSYS,					/*  74 */
	EMULATE(s10_issetugid, 0 | RV_DEFAULT),	/*  75 */
	EMULATE(s10_fsat, 6 | RV_DEFAULT),	/*  76 */
	NOSYS,					/*  77 */
	NOSYS,					/*  78 */
	EMULATE(s10_rmdir, 1 | RV_DEFAULT),	/*  79 */
	EMULATE(s10_mkdir, 2 | RV_DEFAULT),	/*  80 */
	EMULATE(s10_getdents, 3 | RV_DEFAULT),	/*  81 */
	NOSYS,					/*  82 */
	NOSYS,					/*  83 */
	NOSYS,					/*  84 */
	NOSYS,					/*  85 */
	NOSYS,					/*  86 */
	EMULATE(s10_poll, 3 | RV_DEFAULT),	/*  87 */
	EMULATE(s10_lstat, 2 | RV_DEFAULT),	/*  88 */
	EMULATE(s10_symlink, 2 | RV_DEFAULT),	/*  89 */
	EMULATE(s10_readlink, 3 | RV_DEFAULT),	/*  90 */
	NOSYS,					/*  91 */
	NOSYS,					/*  92 */
	EMULATE(s10_fchmod, 2 | RV_DEFAULT),	/*  93 */
	EMULATE(s10_fchown, 3 | RV_DEFAULT),	/*  94 */
	EMULATE(s10_sigprocmask, 3 | RV_DEFAULT), /*  95 */
	EMULATE(s10_sigsuspend, 1 | RV_DEFAULT), /*  96 */
	NOSYS,					/*  97 */
	EMULATE(s10_sigaction, 3 | RV_DEFAULT),	/*  98 */
	EMULATE(s10_sigpending, 2 | RV_DEFAULT), /*  99 */
	NOSYS,					/* 100 */
	NOSYS,					/* 101 */
	NOSYS,					/* 102 */
	NOSYS,					/* 103 */
	NOSYS,					/* 104 */
	NOSYS,					/* 105 */
	NOSYS,					/* 106 */
	EMULATE(s10_waitid, 4 | RV_DEFAULT),	/* 107 */
	EMULATE(s10_sigsendsys, 2 | RV_DEFAULT), /* 108 */
	NOSYS,					/* 109 */
	NOSYS,					/* 110 */
	NOSYS,					/* 111 */
	NOSYS,					/* 112 */
	NOSYS,					/* 113 */
	NOSYS,					/* 114 */
	NOSYS,					/* 115 */
	NOSYS,					/* 116 */
	NOSYS,					/* 117 */
	NOSYS,					/* 118 */
	NOSYS,					/* 119 */
	NOSYS,					/* 120 */
	NOSYS,					/* 121 */
	NOSYS,					/* 122 */
#if defined(__x86)
	EMULATE(s10_xstat, 3 | RV_DEFAULT),	/* 123 */
	EMULATE(s10_lxstat, 3 | RV_DEFAULT),	/* 124 */
	EMULATE(s10_fxstat, 3 | RV_DEFAULT),	/* 125 */
	EMULATE(s10_xmknod, 4 | RV_DEFAULT),	/* 126 */
#else
	NOSYS,					/* 123 */
	NOSYS,					/* 124 */
	NOSYS,					/* 125 */
	NOSYS,					/* 126 */
#endif
	NOSYS,					/* 127 */
	NOSYS,					/* 128 */
	NOSYS,					/* 129 */
	EMULATE(s10_lchown, 3 | RV_DEFAULT),	/* 130 */
	NOSYS,					/* 131 */
	NOSYS,					/* 132 */
	NOSYS,					/* 133 */
	EMULATE(s10_rename, 2 | RV_DEFAULT),	/* 134 */
	EMULATE(s10_uname, 1 | RV_DEFAULT),	/* 135 */
	NOSYS,					/* 136 */
	EMULATE(s10_sysconfig, 1 | RV_DEFAULT),	/* 137 */
	NOSYS,					/* 138 */
	EMULATE(s10_sysinfo, 3 | RV_DEFAULT),	/* 139 */
	NOSYS,					/* 140 */
	NOSYS,					/* 141 */
	NOSYS,					/* 142 */
	EMULATE(s10_fork1, 0 | RV_32RVAL2),	/* 143 */
	EMULATE(s10_sigtimedwait, 3 | RV_DEFAULT), /* 144 */
	NOSYS,					/* 145 */
	NOSYS,					/* 146 */
	EMULATE(s10_lwp_sema_wait, 1 | RV_DEFAULT), /* 147 */
	NOSYS,					/* 148 */
	NOSYS,					/* 149 */
	NOSYS,					/* 150 */
	NOSYS,					/* 151 */
	NOSYS,					/* 152 */
	NOSYS,					/* 153 */
	EMULATE(s10_utimes, 2 | RV_DEFAULT),	/* 154 */
	NOSYS,					/* 155 */
	NOSYS,					/* 156 */
	NOSYS,					/* 157 */
	NOSYS,					/* 158 */
	EMULATE(s10_lwp_create, 3 | RV_DEFAULT), /* 159 */
	NOSYS,					/* 160 */
	NOSYS,					/* 161 */
	NOSYS,					/* 162 */
	EMULATE(s10_lwp_kill, 2 | RV_DEFAULT),	/* 163 */
	NOSYS,					/* 164 */
	EMULATE(s10_lwp_sigmask, 3 | RV_32RVAL2), /* 165 */
#if defined(__x86)
	EMULATE(s10_lwp_private, 3 | RV_DEFAULT), /* 166 */
#else
	NOSYS,					/* 166 */
#endif
	NOSYS,					/* 167 */
	NOSYS,					/* 168 */
	EMULATE(s10_lwp_mutex_lock, 1 | RV_DEFAULT), /* 169 */
	NOSYS,					/* 170 */
	NOSYS,					/* 171 */
	NOSYS,					/* 172 */
	NOSYS,					/* 173 */
	EMULATE(s10_pwrite, 4 | RV_DEFAULT),	/* 174 */
	NOSYS,					/* 175 */
	NOSYS,					/* 176 */
	NOSYS,					/* 177 */
	NOSYS,					/* 178 */
	NOSYS,					/* 179 */
	NOSYS,					/* 180 */
	NOSYS,					/* 181 */
	NOSYS,					/* 182 */
	NOSYS,					/* 183 */
	NOSYS,					/* 184 */
	EMULATE(s10_acl, 4 | RV_DEFAULT),	/* 185 */
	EMULATE(s10_auditsys, 4 | RV_64RVAL),	/* 186 */
	NOSYS,					/* 187 */
	NOSYS,					/* 188 */
	NOSYS,					/* 189 */
	EMULATE(s10_sigqueue, 4 | RV_DEFAULT),	/* 190 */
	NOSYS,					/* 191 */
	NOSYS,					/* 192 */
	NOSYS,					/* 193 */
	NOSYS,					/* 194 */
	NOSYS,					/* 195 */
	NOSYS,					/* 196 */
	NOSYS,					/* 197 */
	NOSYS,					/* 198 */
	NOSYS,					/* 199 */
	EMULATE(s10_facl, 4 | RV_DEFAULT),	/* 200 */
	NOSYS,					/* 201 */
	NOSYS,					/* 202 */
	NOSYS,					/* 203 */
	NOSYS,					/* 204 */
	EMULATE(s10_signotify, 3 | RV_DEFAULT),	/* 205 */
	NOSYS,					/* 206 */
	NOSYS,					/* 207 */
	NOSYS,					/* 208 */
	NOSYS,					/* 209 */
	EMULATE(s10_lwp_mutex_timedlock, 2 | RV_DEFAULT), /* 210 */
	NOSYS,					/* 211 */
	NOSYS,					/* 212 */
#if defined(_LP64)
	NOSYS,					/* 213 */
#else
	EMULATE(s10_getdents64, 3 | RV_DEFAULT), /* 213 */
#endif
	NOSYS,					/* 214 */
#if defined(_LP64)
	NOSYS,					/* 215 */
	NOSYS,					/* 216 */
	NOSYS,					/* 217 */
#else
	EMULATE(s10_stat64, 2 | RV_DEFAULT),	/* 215 */
	EMULATE(s10_lstat64, 2 | RV_DEFAULT),	/* 216 */
	EMULATE(s10_fstat64, 2 | RV_DEFAULT),	/* 217 */
#endif
	NOSYS,					/* 218 */
	NOSYS,					/* 219 */
	NOSYS,					/* 220 */
	NOSYS,					/* 221 */
	NOSYS,					/* 222 */
#if defined(_LP64)
	NOSYS,					/* 223 */
	NOSYS,					/* 224 */
	NOSYS,					/* 225 */
#else
	EMULATE(s10_pwrite64, 5 | RV_DEFAULT),	/* 223 */
	EMULATE(s10_creat64, 2 | RV_DEFAULT),	/* 224 */
	EMULATE(s10_open64, 3 | RV_DEFAULT),	/* 225 */
#endif
	NOSYS,					/* 226 */
	EMULATE(s10_zone, 5 | RV_DEFAULT),	/* 227 */
	NOSYS,					/* 228 */
	NOSYS,					/* 229 */
	EMULATE(s10_so_socket, 5 | RV_DEFAULT),	/* 230 */
	NOSYS,					/* 231 */
	NOSYS,					/* 232 */
	NOSYS,					/* 233 */
	EMULATE(s10_accept, 4 | RV_DEFAULT),	/* 234 */
	NOSYS,					/* 235 */
	NOSYS,					/* 236 */
	NOSYS,					/* 237 */
	NOSYS,					/* 238 */
	NOSYS,					/* 239 */
	NOSYS,					/* 240 */
	NOSYS,					/* 241 */
	NOSYS,					/* 242 */
	NOSYS,					/* 243 */
	NOSYS,					/* 244 */
	NOSYS,					/* 245 */
	NOSYS,					/* 246 */
	NOSYS,					/* 247 */
	NOSYS,					/* 248 */
	NOSYS,					/* 249 */
	NOSYS,					/* 250 */
	EMULATE(s10_lwp_mutex_trylock, 1 | RV_DEFAULT), /* 251 */
	NOSYS,					/* 252 */
	NOSYS,					/* 253 */
	NOSYS,					/* 254 */
	NOSYS					/* 255 */
};
