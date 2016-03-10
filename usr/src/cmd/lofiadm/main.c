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
 * Copyright 2012 Joyent, Inc.  All rights reserved.
 *
 * Copyright 2013 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2014 Gary Mills
 * Copyright (c) 2016 Andrey Sokolov
 */

/*
 * lofiadm - administer lofi(7d). Very simple, add and remove file<->device
 * associations, and display status. All the ioctls are private between
 * lofi and lofiadm, and so are very simple - device information is
 * communicated via a minor number.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/lofi.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>
#include <stdio.h>
#include <fcntl.h>
#include <locale.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <libdevinfo.h>
#include <libgen.h>
#include <ctype.h>
#include <dlfcn.h>
#include <limits.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>
#include <sys/crypto/ioctl.h>
#include <sys/crypto/ioctladmin.h>
#include "utils.h"
#include <LzmaEnc.h>

/* Only need the IV len #defines out of these files, nothing else. */
#include <aes/aes_impl.h>
#include <des/des_impl.h>
#include <blowfish/blowfish_impl.h>

static const char USAGE[] =
	"Usage: %s [-r] -a file [ device ]\n"
	"       %s [-r] -c crypto_algorithm -a file [device]\n"
	"       %s [-r] -c crypto_algorithm -k raw_key_file -a file [device]\n"
	"       %s [-r] -c crypto_algorithm -T [token]:[manuf]:[serial]:key "
	"-a file [device]\n"
	"       %s [-r] -c crypto_algorithm -T [token]:[manuf]:[serial]:key "
	"-k wrapped_key_file -a file [device]\n"
	"       %s [-r] -c crypto_algorithm -e -a file [device]\n"
	"       %s -d file | device\n"
	"       %s -C [gzip|gzip-6|gzip-9|lzma] [-s segment_size] file\n"
	"       %s -U file\n"
	"       %s [ file | device ]\n";

typedef struct token_spec {
	char	*name;
	char	*mfr;
	char	*serno;
	char	*key;
} token_spec_t;

typedef struct mech_alias {
	char	*alias;
	CK_MECHANISM_TYPE type;
	char	*name;		/* for ioctl */
	char	*iv_name;	/* for ioctl */
	size_t	iv_len;		/* for ioctl */
	iv_method_t iv_type;	/* for ioctl */
	size_t	min_keysize;	/* in bytes */
	size_t	max_keysize;	/* in bytes */
	token_spec_t *token;
	CK_SLOT_ID slot;
} mech_alias_t;

static mech_alias_t mech_aliases[] = {
	/* Preferred one should always be listed first. */
	{ "aes-256-cbc", CKM_AES_CBC, "CKM_AES_CBC", "CKM_AES_ECB", AES_IV_LEN,
	    IVM_ENC_BLKNO, ULONG_MAX, 0L, NULL, (CK_SLOT_ID) -1 },
	{ "aes-192-cbc", CKM_AES_CBC, "CKM_AES_CBC", "CKM_AES_ECB", AES_IV_LEN,
	    IVM_ENC_BLKNO, ULONG_MAX, 0L, NULL, (CK_SLOT_ID) -1 },
	{ "aes-128-cbc", CKM_AES_CBC, "CKM_AES_CBC", "CKM_AES_ECB", AES_IV_LEN,
	    IVM_ENC_BLKNO, ULONG_MAX, 0L, NULL, (CK_SLOT_ID) -1 },
	{ "des3-cbc", CKM_DES3_CBC, "CKM_DES3_CBC", "CKM_DES3_ECB", DES_IV_LEN,
	    IVM_ENC_BLKNO, ULONG_MAX, 0L, NULL, (CK_SLOT_ID)-1 },
	{ "blowfish-cbc", CKM_BLOWFISH_CBC, "CKM_BLOWFISH_CBC",
	    "CKM_BLOWFISH_ECB", BLOWFISH_IV_LEN, IVM_ENC_BLKNO, ULONG_MAX,
	    0L, NULL, (CK_SLOT_ID)-1 }
	/*
	 * A cipher without an iv requirement would look like this:
	 * { "aes-xex", CKM_AES_XEX, "CKM_AES_XEX", NULL, 0,
	 *    IVM_NONE, ULONG_MAX, 0L, NULL, (CK_SLOT_ID)-1 }
	 */
};

int	mech_aliases_count = (sizeof (mech_aliases) / sizeof (mech_alias_t));

/* Preferred cipher, if one isn't specified on command line. */
#define	DEFAULT_CIPHER	(&mech_aliases[0])

#define	DEFAULT_CIPHER_NUM	64	/* guess # kernel ciphers available */
#define	DEFAULT_MECHINFO_NUM	16	/* guess # kernel mechs available */
#define	MIN_PASSLEN		8	/* min acceptable passphrase size */

static int gzip_compress(void *src, size_t srclen, void *dst,
	size_t *destlen, int level);
static int lzma_compress(void *src, size_t srclen, void *dst,
	size_t *destlen, int level);

lofi_compress_info_t lofi_compress_table[LOFI_COMPRESS_FUNCTIONS] = {
	{NULL,  		gzip_compress,  6,	"gzip"}, /* default */
	{NULL,			gzip_compress,	6,	"gzip-6"},
	{NULL,			gzip_compress,	9, 	"gzip-9"},
	{NULL,  		lzma_compress, 	0, 	"lzma"}
};

/* For displaying lofi mappings */
#define	FORMAT 			"%-20s     %-30s	%s\n"

#define	COMPRESS_ALGORITHM	"gzip"
#define	COMPRESS_THRESHOLD	2048
#define	SEGSIZE			131072
#define	BLOCK_SIZE		512
#define	KILOBYTE		1024
#define	MEGABYTE		(KILOBYTE * KILOBYTE)
#define	GIGABYTE		(KILOBYTE * MEGABYTE)
#define	LIBZ			"libz.so.1"

const char lofi_crypto_magic[6] = LOFI_CRYPTO_MAGIC;

static void
usage(const char *pname)
{
	(void) fprintf(stderr, gettext(USAGE), pname, pname, pname,
	    pname, pname, pname, pname, pname, pname, pname);
	exit(E_USAGE);
}

static int
gzip_compress(void *src, size_t srclen, void *dst, size_t *dstlen, int level)
{
	static int (*compress2p)(void *, ulong_t *, void *, size_t, int) = NULL;
	void *libz_hdl = NULL;

	/*
	 * The first time we are called, attempt to dlopen()
	 * libz.so.1 and get a pointer to the compress2() function
	 */
	if (compress2p == NULL) {
		if ((libz_hdl = openlib(LIBZ)) == NULL)
			die(gettext("could not find %s. "
			    "gzip compression unavailable\n"), LIBZ);

		if ((compress2p =
		    (int (*)(void *, ulong_t *, void *, size_t, int))
		    dlsym(libz_hdl, "compress2")) == NULL) {
			closelib();
			die(gettext("could not find the correct %s. "
			    "gzip compression unavailable\n"), LIBZ);
		}
	}

	if ((*compress2p)(dst, (ulong_t *)dstlen, src, srclen, level) != 0)
		return (-1);
	return (0);
}

/*ARGSUSED*/
static void
*SzAlloc(void *p, size_t size)
{
	return (malloc(size));
}

/*ARGSUSED*/
static void
SzFree(void *p, void *address, size_t size)
{
	free(address);
}

static ISzAlloc g_Alloc = {
	SzAlloc,
	SzFree
};

#define	LZMA_UNCOMPRESSED_SIZE	8
#define	LZMA_HEADER_SIZE (LZMA_PROPS_SIZE + LZMA_UNCOMPRESSED_SIZE)

/*ARGSUSED*/
static int
lzma_compress(void *src, size_t srclen, void *dst,
	size_t *dstlen, int level)
{
	CLzmaEncProps props;
	size_t outsize2;
	size_t outsizeprocessed;
	size_t outpropssize = LZMA_PROPS_SIZE;
	uint64_t t = 0;
	SRes res;
	Byte *dstp;
	int i;

	outsize2 = *dstlen;

	LzmaEncProps_Init(&props);

	/*
	 * The LZMA compressed file format is as follows -
	 *
	 * Offset Size(bytes) Description
	 * 0		1	LZMA properties (lc, lp, lp (encoded))
	 * 1		4	Dictionary size (little endian)
	 * 5		8	Uncompressed size (little endian)
	 * 13			Compressed data
	 */

	/* set the dictionary size to be 8MB */
	props.dictSize = 1 << 23;

	if (*dstlen < LZMA_HEADER_SIZE)
		return (SZ_ERROR_OUTPUT_EOF);

	dstp = (Byte *)dst;
	t = srclen;
	/*
	 * Set the uncompressed size in the LZMA header
	 * The LZMA properties (specified in 'props')
	 * will be set by the call to LzmaEncode()
	 */
	for (i = 0; i < LZMA_UNCOMPRESSED_SIZE; i++, t >>= 8) {
		dstp[LZMA_PROPS_SIZE + i] = (Byte)t;
	}

	outsizeprocessed = outsize2 - LZMA_HEADER_SIZE;
	res = LzmaEncode(dstp + LZMA_HEADER_SIZE, &outsizeprocessed,
	    src, srclen, &props, dstp, &outpropssize, 0, NULL,
	    &g_Alloc, &g_Alloc);

	if (res != 0)
		return (-1);

	*dstlen = outsizeprocessed + LZMA_HEADER_SIZE;
	return (0);
}

/*
 * Translate a lofi device name to a minor number. We might be asked
 * to do this when there is no association (such as when the user specifies
 * a particular device), so we can only look at the string.
 */
static int
name_to_minor(const char *devicename)
{
	int	minor;

	if (sscanf(devicename, "/dev/" LOFI_BLOCK_NAME "/%d", &minor) == 1) {
		return (minor);
	}
	if (sscanf(devicename, "/dev/" LOFI_CHAR_NAME "/%d", &minor) == 1) {
		return (minor);
	}
	return (0);
}

/*
 * This might be the first time we've used this minor number. If so,
 * it might also be that the /dev links are in the process of being created
 * by devfsadmd (or that they'll be created "soon"). We cannot return
 * until they're there or the invoker of lofiadm might try to use them
 * and not find them. This can happen if a shell script is running on
 * an MP.
 */
static int sleeptime = 2;	/* number of seconds to sleep between stat's */
static int maxsleep = 120;	/* maximum number of seconds to sleep */

static void
wait_until_dev_complete(int minor)
{
	struct stat64 buf;
	int	cursleep;
	char	blkpath[MAXPATHLEN];
	char	charpath[MAXPATHLEN];
	di_devlink_handle_t hdl;

	(void) snprintf(blkpath, sizeof (blkpath), "/dev/%s/%d",
	    LOFI_BLOCK_NAME, minor);
	(void) snprintf(charpath, sizeof (charpath), "/dev/%s/%d",
	    LOFI_CHAR_NAME, minor);

	/* Check if links already present */
	if (stat64(blkpath, &buf) == 0 && stat64(charpath, &buf) == 0)
		return;

	/* First use di_devlink_init() */
	if (hdl = di_devlink_init("lofi", DI_MAKE_LINK)) {
		(void) di_devlink_fini(&hdl);
		goto out;
	}

	/*
	 * Under normal conditions, di_devlink_init(DI_MAKE_LINK) above will
	 * only fail if the caller is non-root. In that case, wait for
	 * link creation via sysevents.
	 */
	for (cursleep = 0; cursleep < maxsleep; cursleep += sleeptime) {
		if (stat64(blkpath, &buf) == 0 && stat64(charpath, &buf) == 0)
			return;
		(void) sleep(sleeptime);
	}

	/* one last try */
out:
	if (stat64(blkpath, &buf) == -1) {
		die(gettext("%s was not created"), blkpath);
	}
	if (stat64(charpath, &buf) == -1) {
		die(gettext("%s was not created"), charpath);
	}
}

/*
 * Map the file and return the minor number the driver picked for the file
 * DO NOT use this function if the filename is actually the device name.
 */
static int
lofi_map_file(int lfd, struct lofi_ioctl li, const char *filename)
{
	int	minor;

	li.li_minor = 0;
	(void) strlcpy(li.li_filename, filename, sizeof (li.li_filename));
	minor = ioctl(lfd, LOFI_MAP_FILE, &li);
	if (minor == -1) {
		if (errno == ENOTSUP)
			warn(gettext("encrypting compressed files is "
			    "unsupported"));
		die(gettext("could not map file %s"), filename);
	}
	wait_until_dev_complete(minor);
	return (minor);
}

/*
 * Add a device association. If devicename is NULL, let the driver
 * pick a device.
 */
static void
add_mapping(int lfd, const char *devicename, const char *filename,
    mech_alias_t *cipher, const char *rkey, size_t rksz, boolean_t rdonly)
{
	struct lofi_ioctl li;

	li.li_readonly = rdonly;

	li.li_crypto_enabled = B_FALSE;
	if (cipher != NULL) {
		/* set up encryption for mapped file */
		li.li_crypto_enabled = B_TRUE;
		(void) strlcpy(li.li_cipher, cipher->name,
		    sizeof (li.li_cipher));
		if (rksz > sizeof (li.li_key)) {
			die(gettext("key too large"));
		}
		bcopy(rkey, li.li_key, rksz);
		li.li_key_len = rksz << 3;	/* convert to bits */

		li.li_iv_type = cipher->iv_type;
		li.li_iv_len = cipher->iv_len;	/* 0 when no iv needed */
		switch (cipher->iv_type) {
		case IVM_ENC_BLKNO:
			(void) strlcpy(li.li_iv_cipher, cipher->iv_name,
			    sizeof (li.li_iv_cipher));
			break;
		case IVM_NONE:
			/* FALLTHROUGH */
		default:
			break;
		}
	}

	if (devicename == NULL) {
		int	minor;

		/* pick one via the driver */
		minor = lofi_map_file(lfd, li, filename);
		/* if mapping succeeds, print the one picked */
		(void) printf("/dev/%s/%d\n", LOFI_BLOCK_NAME, minor);
		return;
	}

	/* use device we were given */
	li.li_minor = name_to_minor(devicename);
	if (li.li_minor == 0) {
		die(gettext("malformed device name %s\n"), devicename);
	}
	(void) strlcpy(li.li_filename, filename, sizeof (li.li_filename));

	/* if device is already in use li.li_minor won't change */
	if (ioctl(lfd, LOFI_MAP_FILE_MINOR, &li) == -1) {
		if (errno == ENOTSUP)
			warn(gettext("encrypting compressed files is "
			    "unsupported"));
		die(gettext("could not map file %s to %s"), filename,
		    devicename);
	}
	wait_until_dev_complete(li.li_minor);
}

/*
 * Remove an association. Delete by device name if non-NULL, or by
 * filename otherwise.
 */
static void
delete_mapping(int lfd, const char *devicename, const char *filename,
    boolean_t force)
{
	struct lofi_ioctl li;

	li.li_force = force;
	li.li_cleanup = B_FALSE;

	if (devicename == NULL) {
		/* delete by filename */
		(void) strlcpy(li.li_filename, filename,
		    sizeof (li.li_filename));
		li.li_minor = 0;
		if (ioctl(lfd, LOFI_UNMAP_FILE, &li) == -1) {
			die(gettext("could not unmap file %s"), filename);
		}
		return;
	}

	/* delete by device */
	li.li_minor = name_to_minor(devicename);
	if (li.li_minor == 0) {
		die(gettext("malformed device name %s\n"), devicename);
	}
	if (ioctl(lfd, LOFI_UNMAP_FILE_MINOR, &li) == -1) {
		die(gettext("could not unmap device %s"), devicename);
	}
}

/*
 * Show filename given devicename, or devicename given filename.
 */
static void
print_one_mapping(int lfd, const char *devicename, const char *filename)
{
	struct lofi_ioctl li;

	if (devicename == NULL) {
		/* given filename, print devicename */
		li.li_minor = 0;
		(void) strlcpy(li.li_filename, filename,
		    sizeof (li.li_filename));
		if (ioctl(lfd, LOFI_GET_MINOR, &li) == -1) {
			die(gettext("could not find device for %s"), filename);
		}
		(void) printf("/dev/%s/%d\n", LOFI_BLOCK_NAME, li.li_minor);
		return;
	}

	/* given devicename, print filename */
	li.li_minor = name_to_minor(devicename);
	if (li.li_minor == 0) {
		die(gettext("malformed device name %s\n"), devicename);
	}
	if (ioctl(lfd, LOFI_GET_FILENAME, &li) == -1) {
		die(gettext("could not find filename for %s"), devicename);
	}
	(void) printf("%s\n", li.li_filename);
}

/*
 * Print the list of all the mappings, including a header.
 */
static void
print_mappings(int fd)
{
	struct lofi_ioctl li;
	int	minor;
	int	maxminor;
	char	path[MAXPATHLEN];
	char	options[MAXPATHLEN] = { 0 };

	li.li_minor = 0;
	if (ioctl(fd, LOFI_GET_MAXMINOR, &li) == -1) {
		die("ioctl");
	}
	maxminor = li.li_minor;

	(void) printf(FORMAT, gettext("Block Device"), gettext("File"),
	    gettext("Options"));
	for (minor = 1; minor <= maxminor; minor++) {
		li.li_minor = minor;
		if (ioctl(fd, LOFI_GET_FILENAME, &li) == -1) {
			if (errno == ENXIO)
				continue;
			warn("ioctl");
			break;
		}
		(void) snprintf(path, sizeof (path), "/dev/%s/%d",
		    LOFI_BLOCK_NAME, minor);

		options[0] = '\0';

		/*
		 * Encrypted lofi and compressed lofi are mutually exclusive.
		 */
		if (li.li_crypto_enabled)
			(void) snprintf(options, sizeof (options),
			    gettext("Encrypted"));
		else if (li.li_algorithm[0] != '\0')
			(void) snprintf(options, sizeof (options),
			    gettext("Compressed(%s)"), li.li_algorithm);
		if (li.li_readonly) {
			if (strlen(options) != 0) {
				(void) strlcat(options, ",", sizeof (options));
				(void) strlcat(options, "Readonly",
				    sizeof (options));
			} else {
				(void) snprintf(options, sizeof (options),
				    gettext("Readonly"));
			}
		}
		if (strlen(options) == 0)
			(void) snprintf(options, sizeof (options), "-");

		(void) printf(FORMAT, path, li.li_filename, options);
	}
}

/*
 * Verify the cipher selected by user.
 */
static mech_alias_t *
ciph2mech(const char *alias)
{
	int	i;

	for (i = 0; i < mech_aliases_count; i++) {
		if (strcasecmp(alias, mech_aliases[i].alias) == 0)
			return (&mech_aliases[i]);
	}
	return (NULL);
}

/*
 * Verify user selected cipher is also available in kernel.
 *
 * While traversing kernel list of mechs, if the cipher is supported in the
 * kernel for both encryption and decryption, it also picks up the min/max
 * key size.
 */
static boolean_t
kernel_cipher_check(mech_alias_t *cipher)
{
	boolean_t ciph_ok = B_FALSE;
	boolean_t iv_ok = B_FALSE;
	int	i;
	int	count;
	crypto_get_mechanism_list_t *kciphers = NULL;
	crypto_get_all_mechanism_info_t *kinfo = NULL;
	int	fd = -1;
	size_t	keymin;
	size_t	keymax;

	/* if cipher doesn't need iv generating mech, bypass that check now */
	if (cipher->iv_name == NULL)
		iv_ok = B_TRUE;

	/* allocate some space for the list of kernel ciphers */
	count = DEFAULT_CIPHER_NUM;
	kciphers = malloc(sizeof (crypto_get_mechanism_list_t) +
	    sizeof (crypto_mech_name_t) * (count - 1));
	if (kciphers == NULL)
		die(gettext("failed to allocate memory for list of "
		    "kernel mechanisms"));
	kciphers->ml_count = count;

	/* query crypto device to get list of kernel ciphers */
	if ((fd = open("/dev/crypto", O_RDWR)) == -1) {
		warn(gettext("failed to open %s"), "/dev/crypto");
		goto kcc_out;
	}

	if (ioctl(fd, CRYPTO_GET_MECHANISM_LIST, kciphers) == -1) {
		warn(gettext("CRYPTO_GET_MECHANISM_LIST ioctl failed"));
		goto kcc_out;
	}

	if (kciphers->ml_return_value == CRYPTO_BUFFER_TOO_SMALL) {
		count = kciphers->ml_count;
		free(kciphers);
		kciphers = malloc(sizeof (crypto_get_mechanism_list_t) +
		    sizeof (crypto_mech_name_t) * (count - 1));
		if (kciphers == NULL) {
			warn(gettext("failed to allocate memory for list of "
			    "kernel mechanisms"));
			goto kcc_out;
		}
		kciphers->ml_count = count;

		if (ioctl(fd, CRYPTO_GET_MECHANISM_LIST, kciphers) == -1) {
			warn(gettext("CRYPTO_GET_MECHANISM_LIST ioctl failed"));
			goto kcc_out;
		}
	}

	if (kciphers->ml_return_value != CRYPTO_SUCCESS) {
		warn(gettext(
		    "CRYPTO_GET_MECHANISM_LIST ioctl return value = %d\n"),
		    kciphers->ml_return_value);
		goto kcc_out;
	}

	/*
	 * scan list of kernel ciphers looking for the selected one and if
	 * it needs an iv generated using another cipher, also look for that
	 * additional cipher to be used for generating the iv
	 */
	count = kciphers->ml_count;
	for (i = 0; i < count && !(ciph_ok && iv_ok); i++) {
		if (!ciph_ok &&
		    strcasecmp(cipher->name, kciphers->ml_list[i]) == 0)
			ciph_ok = B_TRUE;
		if (!iv_ok &&
		    strcasecmp(cipher->iv_name, kciphers->ml_list[i]) == 0)
			iv_ok = B_TRUE;
	}
	free(kciphers);
	kciphers = NULL;

	if (!ciph_ok)
		warn(gettext("%s mechanism not supported in kernel\n"),
		    cipher->name);
	if (!iv_ok)
		warn(gettext("%s mechanism not supported in kernel\n"),
		    cipher->iv_name);

	if (ciph_ok) {
		/* Get the details about the user selected cipher */
		count = DEFAULT_MECHINFO_NUM;
		kinfo = malloc(sizeof (crypto_get_all_mechanism_info_t) +
		    sizeof (crypto_mechanism_info_t) * (count - 1));
		if (kinfo == NULL) {
			warn(gettext("failed to allocate memory for "
			    "kernel mechanism info"));
			goto kcc_out;
		}
		kinfo->mi_count = count;
		(void) strlcpy(kinfo->mi_mechanism_name, cipher->name,
		    CRYPTO_MAX_MECH_NAME);

		if (ioctl(fd, CRYPTO_GET_ALL_MECHANISM_INFO, kinfo) == -1) {
			warn(gettext(
			    "CRYPTO_GET_ALL_MECHANISM_INFO ioctl failed"));
			goto kcc_out;
		}

		if (kinfo->mi_return_value == CRYPTO_BUFFER_TOO_SMALL) {
			count = kinfo->mi_count;
			free(kinfo);
			kinfo = malloc(
			    sizeof (crypto_get_all_mechanism_info_t) +
			    sizeof (crypto_mechanism_info_t) * (count - 1));
			if (kinfo == NULL) {
				warn(gettext("failed to allocate memory for "
				    "kernel mechanism info"));
				goto kcc_out;
			}
			kinfo->mi_count = count;
			(void) strlcpy(kinfo->mi_mechanism_name, cipher->name,
			    CRYPTO_MAX_MECH_NAME);

			if (ioctl(fd, CRYPTO_GET_ALL_MECHANISM_INFO, kinfo) ==
			    -1) {
				warn(gettext("CRYPTO_GET_ALL_MECHANISM_INFO "
				    "ioctl failed"));
				goto kcc_out;
			}
		}

		if (kinfo->mi_return_value != CRYPTO_SUCCESS) {
			warn(gettext("CRYPTO_GET_ALL_MECHANISM_INFO ioctl "
			    "return value = %d\n"), kinfo->mi_return_value);
			goto kcc_out;
		}

		/* Set key min and max size */
		count = kinfo->mi_count;
		i = 0;
		if (i < count) {
			keymin = kinfo->mi_list[i].mi_min_key_size;
			keymax = kinfo->mi_list[i].mi_max_key_size;
			if (kinfo->mi_list[i].mi_keysize_unit &
			    CRYPTO_KEYSIZE_UNIT_IN_BITS) {
				keymin = CRYPTO_BITS2BYTES(keymin);
				keymax = CRYPTO_BITS2BYTES(keymax);

			}
			cipher->min_keysize = keymin;
			cipher->max_keysize = keymax;
		}
		free(kinfo);
		kinfo = NULL;

		if (i == count) {
			(void) close(fd);
			die(gettext(
			    "failed to find usable %s kernel mechanism, "
			    "use \"cryptoadm list -m\" to find available "
			    "mechanisms\n"),
			    cipher->name);
		}
	}

	/* Note: key min/max, unit size, usage for iv cipher are not checked. */

	return (ciph_ok && iv_ok);

kcc_out:
	if (kinfo != NULL)
		free(kinfo);
	if (kciphers != NULL)
		free(kciphers);
	if (fd != -1)
		(void) close(fd);
	return (B_FALSE);
}

/*
 * Break up token spec into its components (non-destructive)
 */
static token_spec_t *
parsetoken(char *spec)
{
#define	FLD_NAME	0
#define	FLD_MANUF	1
#define	FLD_SERIAL	2
#define	FLD_LABEL	3
#define	NFIELDS		4
#define	nullfield(i)	((field[(i)+1] - field[(i)]) <= 1)
#define	copyfield(fld, i)	\
		{							\
			int	n;					\
			(fld) = NULL;					\
			if ((n = (field[(i)+1] - field[(i)])) > 1) {	\
				if (((fld) = malloc(n)) != NULL) {	\
					(void) strncpy((fld), field[(i)], n); \
					((fld))[n - 1] = '\0';		\
				}					\
			}						\
		}

	int	i;
	char	*field[NFIELDS + 1];	/* +1 to catch extra delimiters */
	token_spec_t *ti = NULL;

	if (spec == NULL)
		return (NULL);

	/*
	 * Correct format is "[name]:[manuf]:[serial]:key". Can't use
	 * strtok because it treats ":::key" and "key:::" and "key" all
	 * as the same thing, and we can't have the :s compressed away.
	 */
	field[0] = spec;
	for (i = 1; i < NFIELDS + 1; i++) {
		field[i] = strchr(field[i-1], ':');
		if (field[i] == NULL)
			break;
		field[i]++;
	}
	if (i < NFIELDS)		/* not enough fields */
		return (NULL);
	if (field[NFIELDS] != NULL)	/* too many fields */
		return (NULL);
	field[NFIELDS] = strchr(field[NFIELDS-1], '\0') + 1;

	/* key label can't be empty */
	if (nullfield(FLD_LABEL))
		return (NULL);

	ti = malloc(sizeof (token_spec_t));
	if (ti == NULL)
		return (NULL);

	copyfield(ti->name, FLD_NAME);
	copyfield(ti->mfr, FLD_MANUF);
	copyfield(ti->serno, FLD_SERIAL);
	copyfield(ti->key, FLD_LABEL);

	/*
	 * If token specified and it only contains a key label, then
	 * search all tokens for the key, otherwise only those with
	 * matching name, mfr, and serno are used.
	 */
	/*
	 * That's how we'd like it to be, however, if only the key label
	 * is specified, default to using softtoken.  It's easier.
	 */
	if (ti->name == NULL && ti->mfr == NULL && ti->serno == NULL)
		ti->name = strdup(pkcs11_default_token());
	return (ti);
}

/*
 * PBE the passphrase into a raw key
 */
static void
getkeyfromuser(mech_alias_t *cipher, char **raw_key, size_t *raw_key_sz,
    boolean_t with_confirmation)
{
	CK_SESSION_HANDLE sess;
	CK_RV	rv;
	char	*pass = NULL;
	size_t	passlen = 0;
	void	*salt = NULL;	/* don't use NULL, see note on salt below */
	size_t	saltlen = 0;
	CK_KEY_TYPE ktype;
	void	*kvalue;
	size_t	klen;

	/* did init_crypto find a slot that supports this cipher? */
	if (cipher->slot == (CK_SLOT_ID)-1 || cipher->max_keysize == 0) {
		rv = CKR_MECHANISM_INVALID;
		goto cleanup;
	}

	rv = pkcs11_mech2keytype(cipher->type, &ktype);
	if (rv != CKR_OK)
		goto cleanup;

	/*
	 * use the passphrase to generate a PBE PKCS#5 secret key and
	 * retrieve the raw key data to eventually pass it to the kernel;
	 */
	rv = C_OpenSession(cipher->slot, CKF_SERIAL_SESSION, NULL, NULL, &sess);
	if (rv != CKR_OK)
		goto cleanup;

	/* get user passphrase with 8 byte minimum */
	if (pkcs11_get_pass(NULL, &pass, &passlen, MIN_PASSLEN,
	    with_confirmation) < 0) {
		die(gettext("passphrases do not match\n"));
	}

	/*
	 * salt should not be NULL, or else pkcs11_PasswdToKey() will
	 * complain about CKR_MECHANISM_PARAM_INVALID; the following is
	 * to make up for not having a salt until a proper one is used
	 */
	salt = pass;
	saltlen = passlen;

	klen = cipher->max_keysize;
	rv = pkcs11_PasswdToKey(sess, pass, passlen, salt, saltlen, ktype,
	    cipher->max_keysize, &kvalue, &klen);

	(void) C_CloseSession(sess);

	if (rv != CKR_OK) {
		goto cleanup;
	}

	/* assert(klen == cipher->max_keysize); */
	*raw_key_sz = klen;
	*raw_key = (char *)kvalue;
	return;

cleanup:
	die(gettext("failed to generate %s key from passphrase: %s"),
	    cipher->alias, pkcs11_strerror(rv));
}

/*
 * Read raw key from file; also handles ephemeral keys.
 */
void
getkeyfromfile(const char *pathname, mech_alias_t *cipher, char **key,
    size_t *ksz)
{
	int	fd;
	struct stat sbuf;
	boolean_t notplain = B_FALSE;
	ssize_t	cursz;
	ssize_t	nread;

	/* ephemeral keys are just random data */
	if (pathname == NULL) {
		*ksz = cipher->max_keysize;
		*key = malloc(*ksz);
		if (*key == NULL)
			die(gettext("failed to allocate memory for"
			    " ephemeral key"));
		if (pkcs11_get_urandom(*key, *ksz) < 0) {
			free(*key);
			die(gettext("failed to get enough random data"));
		}
		return;
	}

	/*
	 * If the remaining section of code didn't also check for secure keyfile
	 * permissions and whether the key is within cipher min and max lengths,
	 * (or, if those things moved out of this block), we could have had:
	 *	if (pkcs11_read_data(pathname, key, ksz) < 0)
	 *		handle_error();
	 */

	if ((fd = open(pathname, O_RDONLY, 0)) == -1)
		die(gettext("open of keyfile (%s) failed"), pathname);

	if (fstat(fd, &sbuf) == -1)
		die(gettext("fstat of keyfile (%s) failed"), pathname);

	if (S_ISREG(sbuf.st_mode)) {
		if ((sbuf.st_mode & (S_IWGRP | S_IWOTH)) != 0)
			die(gettext("insecure permissions on keyfile %s\n"),
			    pathname);

		*ksz = sbuf.st_size;
		if (*ksz < cipher->min_keysize || cipher->max_keysize < *ksz) {
			warn(gettext("%s: invalid keysize: %d\n"),
			    pathname, (int)*ksz);
			die(gettext("\t%d <= keysize <= %d\n"),
			    cipher->min_keysize, cipher->max_keysize);
		}
	} else {
		*ksz = cipher->max_keysize;
		notplain = B_TRUE;
	}

	*key = malloc(*ksz);
	if (*key == NULL)
		die(gettext("failed to allocate memory for key from file"));

	for (cursz = 0, nread = 0; cursz < *ksz; cursz += nread) {
		nread = read(fd, *key, *ksz);
		if (nread > 0)
			continue;
		/*
		 * nread == 0.  If it's not a regular file we were trying to
		 * get the maximum keysize of data possible for this cipher.
		 * But if we've got at least the minimum keysize of data,
		 * round down to the nearest keysize unit and call it good.
		 * If we haven't met the minimum keysize, that's an error.
		 * If it's a regular file, nread = 0 is also an error.
		 */
		if (nread == 0 && notplain && cursz >= cipher->min_keysize) {
			*ksz = (cursz / cipher->min_keysize) *
			    cipher->min_keysize;
			break;
		}
		die(gettext("%s: can't read all keybytes"), pathname);
	}
	(void) close(fd);
}

/*
 * Read the raw key from token, or from a file that was wrapped with a
 * key from token
 */
void
getkeyfromtoken(CK_SESSION_HANDLE sess,
    token_spec_t *token, const char *keyfile, mech_alias_t *cipher,
    char **raw_key, size_t *raw_key_sz)
{
	CK_RV	rv = CKR_OK;
	CK_BBOOL trueval = B_TRUE;
	CK_OBJECT_CLASS kclass;		/* secret key or RSA private key */
	CK_KEY_TYPE ktype;		/* from selected cipher or CKK_RSA */
	CK_KEY_TYPE raw_ktype;		/* from selected cipher */
	CK_ATTRIBUTE	key_tmpl[] = {
		{ CKA_CLASS, NULL, 0 },	/* re-used for token key and unwrap */
		{ CKA_KEY_TYPE, NULL, 0 },	/* ditto */
		{ CKA_LABEL, NULL, 0 },
		{ CKA_TOKEN, NULL, 0 },
		{ CKA_PRIVATE, NULL, 0 }
	    };
	CK_ULONG attrs = sizeof (key_tmpl) / sizeof (CK_ATTRIBUTE);
	int	i;
	char	*pass = NULL;
	size_t	passlen = 0;
	CK_OBJECT_HANDLE obj, rawobj;
	CK_ULONG num_objs = 1;		/* just want to find 1 token key */
	CK_MECHANISM unwrap = { CKM_RSA_PKCS, NULL, 0 };
	char	*rkey;
	size_t	rksz;

	if (token == NULL || token->key == NULL)
		return;

	/* did init_crypto find a slot that supports this cipher? */
	if (cipher->slot == (CK_SLOT_ID)-1 || cipher->max_keysize == 0) {
		die(gettext("failed to find any cryptographic provider, "
		    "use \"cryptoadm list -p\" to find providers: %s\n"),
		    pkcs11_strerror(CKR_MECHANISM_INVALID));
	}

	if (pkcs11_get_pass(token->name, &pass, &passlen, 0, B_FALSE) < 0)
		die(gettext("unable to get passphrase"));

	/* use passphrase to login to token */
	if (pass != NULL && passlen > 0) {
		rv = C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)pass, passlen);
		if (rv != CKR_OK) {
			die(gettext("cannot login to the token %s: %s\n"),
			    token->name, pkcs11_strerror(rv));
		}
	}

	rv = pkcs11_mech2keytype(cipher->type, &raw_ktype);
	if (rv != CKR_OK) {
		die(gettext("failed to get key type for cipher %s: %s\n"),
		    cipher->name, pkcs11_strerror(rv));
	}

	/*
	 * If no keyfile was given, then the token key is secret key to
	 * be used for encryption/decryption.  Otherwise, the keyfile
	 * contains a wrapped secret key, and the token is actually the
	 * unwrapping RSA private key.
	 */
	if (keyfile == NULL) {
		kclass = CKO_SECRET_KEY;
		ktype = raw_ktype;
	} else {
		kclass = CKO_PRIVATE_KEY;
		ktype = CKK_RSA;
	}

	/* Find the key in the token first */
	for (i = 0; i < attrs; i++) {
		switch (key_tmpl[i].type) {
		case CKA_CLASS:
			key_tmpl[i].pValue = &kclass;
			key_tmpl[i].ulValueLen = sizeof (kclass);
			break;
		case CKA_KEY_TYPE:
			key_tmpl[i].pValue = &ktype;
			key_tmpl[i].ulValueLen = sizeof (ktype);
			break;
		case CKA_LABEL:
			key_tmpl[i].pValue = token->key;
			key_tmpl[i].ulValueLen = strlen(token->key);
			break;
		case CKA_TOKEN:
			key_tmpl[i].pValue = &trueval;
			key_tmpl[i].ulValueLen = sizeof (trueval);
			break;
		case CKA_PRIVATE:
			key_tmpl[i].pValue = &trueval;
			key_tmpl[i].ulValueLen = sizeof (trueval);
			break;
		default:
			break;
		}
	}
	rv = C_FindObjectsInit(sess, key_tmpl, attrs);
	if (rv != CKR_OK)
		die(gettext("cannot find key %s: %s\n"), token->key,
		    pkcs11_strerror(rv));
	rv = C_FindObjects(sess, &obj, 1, &num_objs);
	(void) C_FindObjectsFinal(sess);

	if (num_objs == 0) {
		die(gettext("cannot find key %s\n"), token->key);
	} else if (rv != CKR_OK) {
		die(gettext("cannot find key %s: %s\n"), token->key,
		    pkcs11_strerror(rv));
	}

	/*
	 * No keyfile means when token key is found, convert it to raw key,
	 * and done.  Otherwise still need do an unwrap to create yet another
	 * obj and that needs to be converted to raw key before we're done.
	 */
	if (keyfile == NULL) {
		/* obj contains raw key, extract it */
		rv = pkcs11_ObjectToKey(sess, obj, (void **)&rkey, &rksz,
		    B_FALSE);
		if (rv != CKR_OK) {
			die(gettext("failed to get key value for %s"
			    " from token %s, %s\n"), token->key,
			    token->name, pkcs11_strerror(rv));
		}
	} else {
		getkeyfromfile(keyfile, cipher, &rkey, &rksz);

		/*
		 * Got the wrapping RSA obj and the wrapped key from file.
		 * Unwrap the key from file with RSA obj to get rawkey obj.
		 */

		/* re-use the first two attributes of key_tmpl */
		kclass = CKO_SECRET_KEY;
		ktype = raw_ktype;

		rv = C_UnwrapKey(sess, &unwrap, obj, (CK_BYTE_PTR)rkey,
		    rksz, key_tmpl, 2, &rawobj);
		if (rv != CKR_OK) {
			die(gettext("failed to unwrap key in keyfile %s,"
			    " %s\n"), keyfile, pkcs11_strerror(rv));
		}
		/* rawobj contains raw key, extract it */
		rv = pkcs11_ObjectToKey(sess, rawobj, (void **)&rkey, &rksz,
		    B_TRUE);
		if (rv != CKR_OK) {
			die(gettext("failed to get unwrapped key value for"
			    " key in keyfile %s, %s\n"), keyfile,
			    pkcs11_strerror(rv));
		}
	}

	/* validate raw key size */
	if (rksz < cipher->min_keysize || cipher->max_keysize < rksz) {
		warn(gettext("%s: invalid keysize: %d\n"), keyfile, (int)rksz);
		die(gettext("\t%d <= keysize <= %d\n"), cipher->min_keysize,
		    cipher->max_keysize);
	}

	*raw_key_sz = rksz;
	*raw_key = (char *)rkey;
}

/*
 * Set up cipher key limits and verify PKCS#11 can be done
 * match_token_cipher is the function pointer used by
 * pkcs11_GetCriteriaSession() init_crypto.
 */
boolean_t
match_token_cipher(CK_SLOT_ID slot_id, void *args, CK_RV *rv)
{
	token_spec_t *token;
	mech_alias_t *cipher;
	CK_TOKEN_INFO tokinfo;
	CK_MECHANISM_INFO mechinfo;
	boolean_t token_match;

	/*
	 * While traversing slot list, pick up the following info per slot:
	 * - if token specified, whether it matches this slot's token info
	 * - if the slot supports the PKCS#5 PBKD2 cipher
	 *
	 * If the user said on the command line
	 *	-T tok:mfr:ser:lab -k keyfile
	 *	-c cipher -T tok:mfr:ser:lab -k keyfile
	 * the given cipher or the default cipher apply to keyfile,
	 * If the user said instead
	 *	-T tok:mfr:ser:lab
	 *	-c cipher -T tok:mfr:ser:lab
	 * the key named "lab" may or may not agree with the given
	 * cipher or the default cipher.  In those cases, cipher will
	 * be overridden with the actual cipher type of the key "lab".
	 */
	*rv = CKR_FUNCTION_FAILED;

	if (args == NULL) {
		return (B_FALSE);
	}

	cipher = (mech_alias_t *)args;
	token = cipher->token;

	if (C_GetMechanismInfo(slot_id, cipher->type, &mechinfo) != CKR_OK) {
		return (B_FALSE);
	}

	if (token == NULL) {
		if (C_GetMechanismInfo(slot_id, CKM_PKCS5_PBKD2, &mechinfo) !=
		    CKR_OK) {
			return (B_FALSE);
		}
		goto foundit;
	}

	/* does the token match the token spec? */
	if (token->key == NULL || (C_GetTokenInfo(slot_id, &tokinfo) != CKR_OK))
		return (B_FALSE);

	token_match = B_TRUE;

	if (token->name != NULL && (token->name)[0] != '\0' &&
	    strncmp((char *)token->name, (char *)tokinfo.label,
	    TOKEN_LABEL_SIZE) != 0)
		token_match = B_FALSE;
	if (token->mfr != NULL && (token->mfr)[0] != '\0' &&
	    strncmp((char *)token->mfr, (char *)tokinfo.manufacturerID,
	    TOKEN_MANUFACTURER_SIZE) != 0)
		token_match = B_FALSE;
	if (token->serno != NULL && (token->serno)[0] != '\0' &&
	    strncmp((char *)token->serno, (char *)tokinfo.serialNumber,
	    TOKEN_SERIAL_SIZE) != 0)
		token_match = B_FALSE;

	if (!token_match)
		return (B_FALSE);

foundit:
	cipher->slot = slot_id;
	return (B_TRUE);
}

/*
 * Clean up crypto loose ends
 */
static void
end_crypto(CK_SESSION_HANDLE sess)
{
	(void) C_CloseSession(sess);
	(void) C_Finalize(NULL);
}

/*
 * Set up crypto, opening session on slot that matches token and cipher
 */
static void
init_crypto(token_spec_t *token, mech_alias_t *cipher,
    CK_SESSION_HANDLE_PTR sess)
{
	CK_RV	rv;

	cipher->token = token;

	/* Turn off Metaslot so that we can see actual tokens */
	if (setenv("METASLOT_ENABLED", "false", 1) < 0) {
		die(gettext("could not disable Metaslot"));
	}

	rv = pkcs11_GetCriteriaSession(match_token_cipher, (void *)cipher,
	    sess);
	if (rv != CKR_OK) {
		end_crypto(*sess);
		if (rv == CKR_HOST_MEMORY) {
			die("malloc");
		}
		die(gettext("failed to find any cryptographic provider, "
		    "use \"cryptoadm list -p\" to find providers: %s\n"),
		    pkcs11_strerror(rv));
	}
}

/*
 * Uncompress a file.
 *
 * First map the file in to establish a device
 * association, then read from it. On-the-fly
 * decompression will automatically uncompress
 * the file if it's compressed
 *
 * If the file is mapped and a device association
 * has been established, disallow uncompressing
 * the file until it is unmapped.
 */
static void
lofi_uncompress(int lfd, const char *filename)
{
	struct lofi_ioctl li;
	char buf[MAXBSIZE];
	char devicename[32];
	char tmpfilename[MAXPATHLEN];
	char *x;
	char *dir = NULL;
	char *file = NULL;
	int minor = 0;
	struct stat64 statbuf;
	int compfd = -1;
	int uncompfd = -1;
	ssize_t rbytes;

	/*
	 * Disallow uncompressing the file if it is
	 * already mapped.
	 */
	li.li_crypto_enabled = B_FALSE;
	li.li_minor = 0;
	(void) strlcpy(li.li_filename, filename, sizeof (li.li_filename));
	if (ioctl(lfd, LOFI_GET_MINOR, &li) != -1)
		die(gettext("%s must be unmapped before uncompressing"),
		    filename);

	/* Zero length files don't need to be uncompressed */
	if (stat64(filename, &statbuf) == -1)
		die(gettext("stat: %s"), filename);
	if (statbuf.st_size == 0)
		return;

	minor = lofi_map_file(lfd, li, filename);
	(void) snprintf(devicename, sizeof (devicename), "/dev/%s/%d",
	    LOFI_BLOCK_NAME, minor);

	/* If the file isn't compressed, we just return */
	if ((ioctl(lfd, LOFI_CHECK_COMPRESSED, &li) == -1) ||
	    (li.li_algorithm[0] == '\0')) {
		delete_mapping(lfd, devicename, filename, B_TRUE);
		die("%s is not compressed\n", filename);
	}

	if ((compfd = open64(devicename, O_RDONLY | O_NONBLOCK)) == -1) {
		delete_mapping(lfd, devicename, filename, B_TRUE);
		die(gettext("open: %s"), filename);
	}
	/* Create a temp file in the same directory */
	x = strdup(filename);
	dir = strdup(dirname(x));
	free(x);
	x = strdup(filename);
	file = strdup(basename(x));
	free(x);
	(void) snprintf(tmpfilename, sizeof (tmpfilename),
	    "%s/.%sXXXXXX", dir, file);
	free(dir);
	free(file);

	if ((uncompfd = mkstemp64(tmpfilename)) == -1) {
		(void) close(compfd);
		delete_mapping(lfd, devicename, filename, B_TRUE);
		die("%s could not be uncompressed\n", filename);
	}

	/*
	 * Set the mode bits and the owner of this temporary
	 * file to be that of the original uncompressed file
	 */
	(void) fchmod(uncompfd, statbuf.st_mode);

	if (fchown(uncompfd, statbuf.st_uid, statbuf.st_gid) == -1) {
		(void) close(compfd);
		(void) close(uncompfd);
		delete_mapping(lfd, devicename, filename, B_TRUE);
		die("%s could not be uncompressed\n", filename);
	}

	/* Now read from the device in MAXBSIZE-sized chunks */
	for (;;) {
		rbytes = read(compfd, buf, sizeof (buf));

		if (rbytes <= 0)
			break;

		if (write(uncompfd, buf, rbytes) != rbytes) {
			rbytes = -1;
			break;
		}
	}

	(void) close(compfd);
	(void) close(uncompfd);

	/* Delete the mapping */
	delete_mapping(lfd, devicename, filename, B_TRUE);

	/*
	 * If an error occured while reading or writing, rbytes will
	 * be negative
	 */
	if (rbytes < 0) {
		(void) unlink(tmpfilename);
		die(gettext("could not read from %s"), filename);
	}

	/* Rename the temp file to the actual file */
	if (rename(tmpfilename, filename) == -1)
		(void) unlink(tmpfilename);
}

/*
 * Compress a file
 */
static void
lofi_compress(int *lfd, const char *filename, int compress_index,
    uint32_t segsize)
{
	struct lofi_ioctl lic;
	lofi_compress_info_t *li;
	struct flock lock;
	char tmpfilename[MAXPATHLEN];
	char comp_filename[MAXPATHLEN];
	char algorithm[MAXALGLEN];
	char *x;
	char *dir = NULL, *file = NULL;
	uchar_t *uncompressed_seg = NULL;
	uchar_t *compressed_seg = NULL;
	uint32_t compressed_segsize;
	uint32_t len_compressed, count;
	uint32_t index_entries, index_sz;
	uint64_t *index = NULL;
	uint64_t offset;
	size_t real_segsize;
	struct stat64 statbuf;
	int compfd = -1, uncompfd = -1;
	int tfd = -1;
	ssize_t rbytes, wbytes, lastread;
	int i, type;

	/*
	 * Disallow compressing the file if it is
	 * already mapped
	 */
	lic.li_minor = 0;
	(void) strlcpy(lic.li_filename, filename, sizeof (lic.li_filename));
	if (ioctl(*lfd, LOFI_GET_MINOR, &lic) != -1)
		die(gettext("%s must be unmapped before compressing"),
		    filename);

	/*
	 * Close the control device so other operations
	 * can use it
	 */
	(void) close(*lfd);
	*lfd = -1;

	li = &lofi_compress_table[compress_index];

	/*
	 * The size of the buffer to hold compressed data must
	 * be slightly larger than the compressed segment size.
	 *
	 * The compress functions use part of the buffer as
	 * scratch space to do calculations.
	 * Ref: http://www.zlib.net/manual.html#compress2
	 */
	compressed_segsize = segsize + (segsize >> 6);
	compressed_seg = (uchar_t *)malloc(compressed_segsize + SEGHDR);
	uncompressed_seg = (uchar_t *)malloc(segsize);

	if (compressed_seg == NULL || uncompressed_seg == NULL)
		die(gettext("No memory"));

	if ((uncompfd = open64(filename, O_RDWR|O_LARGEFILE, 0)) == -1)
		die(gettext("open: %s"), filename);

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	/*
	 * Use an advisory lock to ensure that only a
	 * single lofiadm process compresses a given
	 * file at any given time
	 *
	 * A close on the file descriptor automatically
	 * closes all lock state on the file
	 */
	if (fcntl(uncompfd, F_SETLKW, &lock) == -1)
		die(gettext("fcntl: %s"), filename);

	if (fstat64(uncompfd, &statbuf) == -1) {
		(void) close(uncompfd);
		die(gettext("fstat: %s"), filename);
	}

	/* Zero length files don't need to be compressed */
	if (statbuf.st_size == 0) {
		(void) close(uncompfd);
		return;
	}

	/*
	 * Create temporary files in the same directory that
	 * will hold the intermediate data
	 */
	x = strdup(filename);
	dir = strdup(dirname(x));
	free(x);
	x = strdup(filename);
	file = strdup(basename(x));
	free(x);
	(void) snprintf(tmpfilename, sizeof (tmpfilename),
	    "%s/.%sXXXXXX", dir, file);
	(void) snprintf(comp_filename, sizeof (comp_filename),
	    "%s/.%sXXXXXX", dir, file);
	free(dir);
	free(file);

	if ((tfd = mkstemp64(tmpfilename)) == -1)
		goto cleanup;

	if ((compfd = mkstemp64(comp_filename)) == -1)
		goto cleanup;

	/*
	 * Set the mode bits and owner of the compressed
	 * file to be that of the original uncompressed file
	 */
	(void) fchmod(compfd, statbuf.st_mode);

	if (fchown(compfd, statbuf.st_uid, statbuf.st_gid) == -1)
		goto cleanup;

	/*
	 * Calculate the number of index entries required.
	 * index entries are stored as an array. adding
	 * a '2' here accounts for the fact that the last
	 * segment may not be a multiple of the segment size
	 */
	index_sz = (statbuf.st_size / segsize) + 2;
	index = malloc(sizeof (*index) * index_sz);

	if (index == NULL)
		goto cleanup;

	offset = 0;
	lastread = segsize;
	count = 0;

	/*
	 * Now read from the uncompressed file in 'segsize'
	 * sized chunks, compress what was read in and
	 * write it out to a temporary file
	 */
	for (;;) {
		rbytes = read(uncompfd, uncompressed_seg, segsize);

		if (rbytes <= 0)
			break;

		if (lastread < segsize)
			goto cleanup;

		/*
		 * Account for the first byte that
		 * indicates whether a segment is
		 * compressed or not
		 */
		real_segsize = segsize - 1;
		(void) li->l_compress(uncompressed_seg, rbytes,
		    compressed_seg + SEGHDR, &real_segsize, li->l_level);

		/*
		 * If the length of the compressed data is more
		 * than a threshold then there isn't any benefit
		 * to be had from compressing this segment - leave
		 * it uncompressed.
		 *
		 * NB. In case an error occurs during compression (above)
		 * the 'real_segsize' isn't changed. The logic below
		 * ensures that that segment is left uncompressed.
		 */
		len_compressed = real_segsize;
		if (segsize <= COMPRESS_THRESHOLD ||
		    real_segsize > (segsize - COMPRESS_THRESHOLD)) {
			(void) memcpy(compressed_seg + SEGHDR, uncompressed_seg,
			    rbytes);
			type = UNCOMPRESSED;
			len_compressed = rbytes;
		} else {
			type = COMPRESSED;
		}

		/*
		 * Set the first byte or the SEGHDR to
		 * indicate if it's compressed or not
		 */
		*compressed_seg = type;
		wbytes = write(tfd, compressed_seg, len_compressed + SEGHDR);
		if (wbytes != (len_compressed + SEGHDR)) {
			rbytes = -1;
			break;
		}

		index[count] = BE_64(offset);
		offset += wbytes;
		lastread = rbytes;
		count++;
	}

	(void) close(uncompfd);

	if (rbytes < 0)
		goto cleanup;
	/*
	 * The last index entry is a sentinel entry. It does not point to
	 * an actual compressed segment but helps in computing the size of
	 * the compressed segment. The size of each compressed segment is
	 * computed by subtracting the current index value from the next
	 * one (the compressed blocks are stored sequentially)
	 */
	index[count++] = BE_64(offset);

	/*
	 * Now write the compressed data along with the
	 * header information to this file which will
	 * later be renamed to the original uncompressed
	 * file name
	 *
	 * The header is as follows -
	 *
	 * Signature (name of the compression algorithm)
	 * Compression segment size (a multiple of 512)
	 * Number of index entries
	 * Size of the last block
	 * The array containing the index entries
	 *
	 * the header is always stored in network byte
	 * order
	 */
	(void) bzero(algorithm, sizeof (algorithm));
	(void) strlcpy(algorithm, li->l_name, sizeof (algorithm));
	if (write(compfd, algorithm, sizeof (algorithm))
	    != sizeof (algorithm))
		goto cleanup;

	segsize = htonl(segsize);
	if (write(compfd, &segsize, sizeof (segsize)) != sizeof (segsize))
		goto cleanup;

	index_entries = htonl(count);
	if (write(compfd, &index_entries, sizeof (index_entries)) !=
	    sizeof (index_entries))
		goto cleanup;

	lastread = htonl(lastread);
	if (write(compfd, &lastread, sizeof (lastread)) != sizeof (lastread))
		goto cleanup;

	for (i = 0; i < count; i++) {
		if (write(compfd, index + i, sizeof (*index)) !=
		    sizeof (*index))
			goto cleanup;
	}

	/* Header is written, now write the compressed data */
	if (lseek(tfd, 0, SEEK_SET) != 0)
		goto cleanup;

	rbytes = wbytes = 0;

	for (;;) {
		rbytes = read(tfd, compressed_seg, compressed_segsize + SEGHDR);

		if (rbytes <= 0)
			break;

		if (write(compfd, compressed_seg, rbytes) != rbytes)
			goto cleanup;
	}

	if (fstat64(compfd, &statbuf) == -1)
		goto cleanup;

	/*
	 * Round up the compressed file size to be a multiple of
	 * DEV_BSIZE. lofi(7D) likes it that way.
	 */
	if ((offset = statbuf.st_size % DEV_BSIZE) > 0) {

		offset = DEV_BSIZE - offset;

		for (i = 0; i < offset; i++)
			uncompressed_seg[i] = '\0';
		if (write(compfd, uncompressed_seg, offset) != offset)
			goto cleanup;
	}
	(void) close(compfd);
	(void) close(tfd);
	(void) unlink(tmpfilename);
cleanup:
	if (rbytes < 0) {
		if (tfd != -1)
			(void) unlink(tmpfilename);
		if (compfd != -1)
			(void) unlink(comp_filename);
		die(gettext("error compressing file %s"), filename);
	} else {
		/* Rename the compressed file to the actual file */
		if (rename(comp_filename, filename) == -1) {
			(void) unlink(comp_filename);
			die(gettext("error compressing file %s"), filename);
		}
	}
	if (compressed_seg != NULL)
		free(compressed_seg);
	if (uncompressed_seg != NULL)
		free(uncompressed_seg);
	if (index != NULL)
		free(index);
	if (compfd != -1)
		(void) close(compfd);
	if (uncompfd != -1)
		(void) close(uncompfd);
	if (tfd != -1)
		(void) close(tfd);
}

static int
lofi_compress_select(const char *algname)
{
	int i;

	for (i = 0; i < LOFI_COMPRESS_FUNCTIONS; i++) {
		if (strcmp(lofi_compress_table[i].l_name, algname) == 0)
			return (i);
	}
	return (-1);
}

static void
check_algorithm_validity(const char *algname, int *compress_index)
{
	*compress_index = lofi_compress_select(algname);
	if (*compress_index < 0)
		die(gettext("invalid algorithm name: %s\n"), algname);
}

static void
check_file_validity(const char *filename)
{
	struct stat64 buf;
	int 	error;
	int	fd;

	fd = open64(filename, O_RDONLY);
	if (fd == -1) {
		die(gettext("open: %s"), filename);
	}
	error = fstat64(fd, &buf);
	if (error == -1) {
		die(gettext("fstat: %s"), filename);
	} else if (!S_ISLOFIABLE(buf.st_mode)) {
		die(gettext("%s is not a regular file, "
		    "block, or character device\n"),
		    filename);
	} else if ((buf.st_size % DEV_BSIZE) != 0) {
		die(gettext("size of %s is not a multiple of %d\n"),
		    filename, DEV_BSIZE);
	}
	(void) close(fd);

	if (name_to_minor(filename) != 0) {
		die(gettext("cannot use %s on itself\n"), LOFI_DRIVER_NAME);
	}
}

static boolean_t
check_file_is_encrypted(const char *filename)
{
	int	fd;
	char    buf[sizeof (lofi_crypto_magic)];
	int	got;
	int	rest = sizeof (lofi_crypto_magic);

	fd = open64(filename, O_RDONLY);
	if (fd == -1)
		die(gettext("failed to open: %s"), filename);

	if (lseek(fd, CRYOFF, SEEK_SET) != CRYOFF)
		die(gettext("failed to seek to offset 0x%lx in file %s"),
		    CRYOFF, filename);

	do {
		got = read(fd, buf + sizeof (lofi_crypto_magic) - rest, rest);
		if ((got == 0) || ((got == -1) && (errno != EINTR)))
			die(gettext("failed to read crypto header"
			    " at offset 0x%lx in file %s"), CRYOFF, filename);

		if (got > 0)
			rest -= got;
	} while (rest > 0);

	while (close(fd) == -1) {
		if (errno != EINTR)
			die(gettext("failed to close file %s"), filename);
	}

	return (strncmp(buf, lofi_crypto_magic,
	    sizeof (lofi_crypto_magic)) == 0);
}

static uint32_t
convert_to_num(const char *str)
{
	int len;
	uint32_t segsize, mult = 1;

	len = strlen(str);
	if (len && isalpha(str[len - 1])) {
		switch (str[len - 1]) {
		case 'k':
		case 'K':
			mult = KILOBYTE;
			break;
		case 'b':
		case 'B':
			mult = BLOCK_SIZE;
			break;
		case 'm':
		case 'M':
			mult = MEGABYTE;
			break;
		case 'g':
		case 'G':
			mult = GIGABYTE;
			break;
		default:
			die(gettext("invalid segment size %s\n"), str);
		}
	}

	segsize = atol(str);
	segsize *= mult;

	return (segsize);
}

int
main(int argc, char *argv[])
{
	int	lfd;
	int	c;
	const char *devicename = NULL;
	const char *filename = NULL;
	const char *algname = COMPRESS_ALGORITHM;
	int	openflag;
	int	minor;
	int 	compress_index;
	uint32_t segsize = SEGSIZE;
	static char *lofictl = "/dev/" LOFI_CTL_NAME;
	boolean_t force = B_FALSE;
	const char *pname;
	boolean_t errflag = B_FALSE;
	boolean_t addflag = B_FALSE;
	boolean_t rdflag = B_FALSE;
	boolean_t deleteflag = B_FALSE;
	boolean_t ephflag = B_FALSE;
	boolean_t compressflag = B_FALSE;
	boolean_t uncompressflag = B_FALSE;
	/* the next two work together for -c, -k, -T, -e options only */
	boolean_t need_crypto = B_FALSE;	/* if any -c, -k, -T, -e */
	boolean_t cipher_only = B_TRUE;		/* if -c only */
	const char *keyfile = NULL;
	mech_alias_t *cipher = NULL;
	token_spec_t *token = NULL;
	char	*rkey = NULL;
	size_t	rksz = 0;
	char realfilename[MAXPATHLEN];

	pname = getpname(argv[0]);

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "a:c:Cd:efk:rs:T:U")) != EOF) {
		switch (c) {
		case 'a':
			addflag = B_TRUE;
			if ((filename = realpath(optarg, realfilename)) == NULL)
				die("%s", optarg);
			if (((argc - optind) > 0) && (*argv[optind] != '-')) {
				/* optional device */
				devicename = argv[optind];
				optind++;
			}
			break;
		case 'C':
			compressflag = B_TRUE;
			if (((argc - optind) > 1) && (*argv[optind] != '-')) {
				/* optional algorithm */
				algname = argv[optind];
				optind++;
			}
			check_algorithm_validity(algname, &compress_index);
			break;
		case 'c':
			/* is the chosen cipher allowed? */
			if ((cipher = ciph2mech(optarg)) == NULL) {
				errflag = B_TRUE;
				warn(gettext("cipher %s not allowed\n"),
				    optarg);
			}
			need_crypto = B_TRUE;
			/* cipher_only is already set */
			break;
		case 'd':
			deleteflag = B_TRUE;
			minor = name_to_minor(optarg);
			if (minor != 0)
				devicename = optarg;
			else {
				if ((filename = realpath(optarg,
				    realfilename)) == NULL)
					die("%s", optarg);
			}
			break;
		case 'e':
			ephflag = B_TRUE;
			need_crypto = B_TRUE;
			cipher_only = B_FALSE;	/* need to unset cipher_only */
			break;
		case 'f':
			force = B_TRUE;
			break;
		case 'k':
			keyfile = optarg;
			need_crypto = B_TRUE;
			cipher_only = B_FALSE;	/* need to unset cipher_only */
			break;
		case 'r':
			rdflag = B_TRUE;
			break;
		case 's':
			segsize = convert_to_num(optarg);
			if (segsize < DEV_BSIZE || !ISP2(segsize))
				die(gettext("segment size %s is invalid "
				    "or not a multiple of minimum block "
				    "size %ld\n"), optarg, DEV_BSIZE);
			break;
		case 'T':
			if ((token = parsetoken(optarg)) == NULL) {
				errflag = B_TRUE;
				warn(
				    gettext("invalid token key specifier %s\n"),
				    optarg);
			}
			need_crypto = B_TRUE;
			cipher_only = B_FALSE;	/* need to unset cipher_only */
			break;
		case 'U':
			uncompressflag = B_TRUE;
			break;
		case '?':
		default:
			errflag = B_TRUE;
			break;
		}
	}

	/* Check for mutually exclusive combinations of options */
	if (errflag ||
	    (addflag && deleteflag) ||
	    (rdflag && !addflag) ||
	    (!addflag && need_crypto) ||
	    ((compressflag || uncompressflag) && (addflag || deleteflag)))
		usage(pname);

	/* ephemeral key, and key from either file or token are incompatible */
	if (ephflag && (keyfile != NULL || token != NULL)) {
		die(gettext("ephemeral key cannot be used with keyfile"
		    " or token key\n"));
	}

	/*
	 * "-c" but no "-k", "-T", "-e", or "-T -k" means derive key from
	 * command line passphrase
	 */

	switch (argc - optind) {
	case 0: /* no more args */
		if (compressflag || uncompressflag)	/* needs filename */
			usage(pname);
		break;
	case 1:
		if (addflag || deleteflag)
			usage(pname);
		/* one arg means compress/uncompress the file ... */
		if (compressflag || uncompressflag) {
			if ((filename = realpath(argv[optind],
			    realfilename)) == NULL)
				die("%s", argv[optind]);
		/* ... or without options means print the association */
		} else {
			minor = name_to_minor(argv[optind]);
			if (minor != 0)
				devicename = argv[optind];
			else {
				if ((filename = realpath(argv[optind],
				    realfilename)) == NULL)
					die("%s", argv[optind]);
			}
		}
		break;
	default:
		usage(pname);
		break;
	}

	if (addflag || compressflag || uncompressflag)
		check_file_validity(filename);

	if (filename && !valid_abspath(filename))
		exit(E_ERROR);

	/*
	 * Here, we know the arguments are correct, the filename is an
	 * absolute path, it exists and is a regular file. We don't yet
	 * know that the device name is ok or not.
	 */

	openflag = O_EXCL;
	if (addflag || deleteflag || compressflag || uncompressflag)
		openflag |= O_RDWR;
	else
		openflag |= O_RDONLY;
	lfd = open(lofictl, openflag);
	if (lfd == -1) {
		if ((errno == EPERM) || (errno == EACCES)) {
			die(gettext("you do not have permission to perform "
			    "that operation.\n"));
		} else {
			die(gettext("open: %s"), lofictl);
		}
		/*NOTREACHED*/
	}

	/*
	 * No passphrase is needed for ephemeral key, or when key is
	 * in a file and not wrapped by another key from a token.
	 * However, a passphrase is needed in these cases:
	 * 1. cipher with no ephemeral key, key file, or token,
	 *    in which case the passphrase is used to build the key
	 * 2. token with an optional cipher or optional key file,
	 *    in which case the passphrase unlocks the token
	 * If only the cipher is specified, reconfirm the passphrase
	 * to ensure the user hasn't mis-entered it.  Otherwise, the
	 * token will enforce the token passphrase.
	 */
	if (need_crypto) {
		CK_SESSION_HANDLE	sess;

		/* pick a cipher if none specified */
		if (cipher == NULL)
			cipher = DEFAULT_CIPHER;

		if (!kernel_cipher_check(cipher))
			die(gettext(
			    "use \"cryptoadm list -m\" to find available "
			    "mechanisms\n"));

		init_crypto(token, cipher, &sess);

		if (cipher_only) {
			getkeyfromuser(cipher, &rkey, &rksz,
			    !check_file_is_encrypted(filename));
		} else if (token != NULL) {
			getkeyfromtoken(sess, token, keyfile, cipher,
			    &rkey, &rksz);
		} else {
			/* this also handles ephemeral keys */
			getkeyfromfile(keyfile, cipher, &rkey, &rksz);
		}

		end_crypto(sess);
	}

	/*
	 * Now to the real work.
	 */
	if (addflag)
		add_mapping(lfd, devicename, filename, cipher, rkey, rksz,
		    rdflag);
	else if (compressflag)
		lofi_compress(&lfd, filename, compress_index, segsize);
	else if (uncompressflag)
		lofi_uncompress(lfd, filename);
	else if (deleteflag)
		delete_mapping(lfd, devicename, filename, force);
	else if (filename || devicename)
		print_one_mapping(lfd, devicename, filename);
	else
		print_mappings(lfd);

	if (lfd != -1)
		(void) close(lfd);
	closelib();
	return (E_SUCCESS);
}
