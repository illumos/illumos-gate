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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <libintl.h>
#include <locale.h>
#include <sys/des.h>
#include <strings.h>
#include <errno.h>
#include <wanbootutil.h>
#include <sys/sysmacros.h>
#include <sys/wanboot_impl.h>

/* Return codes */
#define	ENCR_SUCCESS	0
#define	ENCR_NOKEY	1
#define	ENCR_ERROR	2

/* Private buffer length */
#define	ENCR_BUF_LEN		1024

/* Encryption algorithm suboption. */
#define	TYPE	0

static char *opts[] = { "type", NULL };

/*
 * This routine is used to parse the suboptions of '-o' option.
 *
 * The option should be of the form: type=<3des|aes>
 *
 * This routine will pass the value of the suboption back in the
 * supplied arguments, 'ka'.
 *
 * Returns:
 *	ENCR_SUCCESS or ENCR_ERROR.
 */
static int
process_option(char *arg, wbku_key_attr_t *ka)
{
	char *value;
	wbku_retcode_t ret;

	while (*arg != '\0') {
		switch (getsubopt(&arg, opts, &value)) {
		case TYPE:
			/*
			 * Key type.
			 */
			ret = wbku_str_to_keyattr(value, ka, WBKU_ENCR_KEY);
			if (ret != WBKU_SUCCESS) {
				wbku_printerr("%s\n", wbku_retmsg(ret));
				return (ENCR_ERROR);
			}
			break;
		default:
			wbku_printerr("Invalid option %s\n", value);
			return (ENCR_ERROR);
		}
	}

	return (ENCR_SUCCESS);
}

/*
 * This routine is used to find the key of type defined by 'ka' and
 * return it in 'key'. The key file should have been opened by the
 * caller and the handle passed in 'key_fp'.
 *
 * Returns:
 *	ENCR_SUCCESS, ENCR_ERROR or ENCR_NOKEY.
 */
static int
get_key(FILE *key_fp, wbku_key_attr_t *ka, uint8_t *key)
{
	wbku_retcode_t ret;

	/*
	 * Find the client key, if it exists.
	 */
	ret = wbku_find_key(key_fp, NULL, ka, key, B_FALSE);
	if (ret != WBKU_SUCCESS) {
		wbku_printerr("%s\n", wbku_retmsg(ret));
		if (ret == WBKU_NOKEY)
			return (ENCR_NOKEY);
		else
			return (ENCR_ERROR);
	}
	return (ENCR_SUCCESS);
}

/*
 * This routine is the common encryption routine used to encrypt data
 * using the CBC handle initialized by the calling routine.  The data
 * to be encrypted is read from stdin and the encrypted data is written to
 * stdout.
 *
 * Returns:
 *	ENCR_SUCCESS or ENCR_ERROR.
 */
static int
encr_gen(cbc_handle_t *ch)
{
	uint8_t iv[WANBOOT_MAXBLOCKLEN];
	uint8_t buf[ENCR_BUF_LEN];
	uint8_t *bufp;
	int read_size;
	ssize_t i, j, k;

	/*
	 * Use a random number as the IV
	 */
	if (wbio_nread_rand(iv, ch->blocklen) != 0) {
		wbku_printerr("Cannot generate initialization vector");
		return (ENCR_ERROR);
	}

	/*
	 * Output the IV to stdout.
	 */
	if (wbio_nwrite(STDOUT_FILENO, iv, ch->blocklen) != 0) {
		wbku_printerr("Write error encountered\n");
		return (ENCR_ERROR);
	}

	/*
	 * Try to read in multiple of block_size as CBC requires
	 * that data be encrypted in block_size chunks.
	 */
	read_size = ENCR_BUF_LEN / ch->blocklen * ch->blocklen;
	while ((i = read(STDIN_FILENO, buf, read_size)) > 0) {
		/*
		 * If data received is not a multiple of the block size,
		 * try to receive more.  If reach EOF, pad the rest with
		 * 0.
		 */
		if ((j = i % ch->blocklen) != 0) {
			/*
			 * Determine how more data need to be received to
			 * fill out the buffer so that it contains a
			 * multiple of block_size chunks.
			 */
			j = ch->blocklen - j;
			bufp = buf + i;
			k = j;

			/*
			 * Try to fill the gap.
			 *
			 */
			while ((j = read(STDIN_FILENO, bufp, j)) != k &&
			    j != 0) {
				bufp += j;
				k -= j;
				j = k;
			}

			/*
			 * This is the total length of the buffer.
			 */
			i = (i + ch->blocklen) - (i % ch->blocklen);

			if (j == 0) {
				/* EOF, do padding. */
				(void) memset(bufp, 0, k);
				(void) cbc_encrypt(ch, buf, i, iv);
			} else if (j > 0) {
				/* The gap has been filled in */
				(void) cbc_encrypt(ch, buf, i, iv);
			} else {
				/* Oops. */
				wbku_printerr("Input error");
				return (ENCR_ERROR);
			}
		} else {
			/* A multiple of the block size was received */
			(void) cbc_encrypt(ch, buf, i, iv);
		}
		if (wbio_nwrite(STDOUT_FILENO, buf, i) != 0) {
			wbku_printerr("Write error encountered\n");
			return (ENCR_ERROR);
		}
	}

	return (ENCR_SUCCESS);
}

/*
 * This routine initializes a CBC handle for 3DES and calls the
 * common encryption routine to encrypt data.
 *
 * Returns:
 *	ENCR_SUCCESS or ENCR_ERROR.
 */
static int
encr_gen_3des(const wbku_key_attr_t *ka, const uint8_t *key)
{
	cbc_handle_t ch;
	void *eh;
	int ret;

	/*
	 * Initialize a 3DES handle.
	 */
	if (des3_init(&eh) != 0) {
		return (ENCR_ERROR);
	}
	des3_key(eh, key);

	/*
	 * Initialize the CBC handle.
	 */
	cbc_makehandle(&ch, eh, ka->ka_len, DES3_BLOCK_SIZE,
	    DES3_IV_SIZE, des3_encrypt, des3_decrypt);

	/*
	 * Encrypt the data.
	 */
	ret = encr_gen(&ch);

	/*
	 *  Free the 3DES resources.
	 */
	des3_fini(eh);

	return (ret);
}

/*
 * This routine initializes a CBC handle for AES and calls the
 * common encryption routine to encrypt data.
 *
 * Returns:
 *	ENCR_SUCCESS or ENCR_ERROR.
 */
static int
encr_gen_aes(const wbku_key_attr_t *ka, const uint8_t *key)
{
	cbc_handle_t ch;
	void *eh;
	int ret;

	/*
	 * Initialize an AES handle.
	 */
	if (aes_init(&eh) != 0) {
		return (ENCR_ERROR);
	}
	aes_key(eh, key, ka->ka_len);

	/*
	 * Initialize the CBC handle.
	 */
	cbc_makehandle(&ch, eh, ka->ka_len, AES_BLOCK_SIZE,
	    AES_IV_SIZE, aes_encrypt, aes_decrypt);

	/*
	 * Encrypt the data.
	 */
	ret = encr_gen(&ch);

	/*
	 *  Free the AES resources.
	 */
	aes_fini(eh);

	return (ret);
}

/*
 * Prints usage().
 */
static void
usage(const char *cmd)
{
	(void) fprintf(stderr,
	    gettext("Usage: %s -o type=<%s|%s> -k key_file\n"),
	    cmd, WBKU_KW_3DES, WBKU_KW_AES_128);
}

/*
 * This program is used to encrypt data read from stdin and print it to
 * stdout. The path to the key file and the algorithm to use are
 * provided by the user.
 *
 * Returns:
 *	ENCR_SUCCESS, ENCR_ERROR or ENCR_NOKEY.
 */
int
main(int argc, char **argv)
{
	uint8_t key[WANBOOT_MAXKEYLEN];
	int c;
	char *keyfile_name = NULL;
	wbku_key_attr_t ka;
	FILE *key_fp;
	int ret;

	/*
	 * Do the necessary magic for localization support.
	 */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Initialize program name for use by wbku_printerr().
	 */
	wbku_errinit(argv[0]);

	/*
	 * Should be five arguments.
	 */
	if (argc < 5) {
		usage(argv[0]);
		return (ENCR_ERROR);
	}

	/*
	 * Parse the options.
	 */
	ka.ka_type = WBKU_KEY_UNKNOWN;
	while ((c = getopt(argc, argv, "o:k:")) != EOF) {
		switch (c) {
		case 'o':
			/*
			 * Suboptions.
			 */
			ret = process_option(optarg, &ka);
			if (ret != ENCR_SUCCESS) {
				usage(argv[0]);
				return (ret);
			}
			break;
		case 'k':
			/*
			 * Path to key file.
			 */
			keyfile_name = optarg;
			break;
		default:
			usage(argv[0]);
			return (ENCR_ERROR);
		}
	}

	/*
	 * Gotta have a key file.
	 */
	if (keyfile_name == NULL) {
		wbku_printerr("Must specify the key_file\n");
		return (ENCR_ERROR);
	}

	/*
	 * Gotta have a key type.
	 */
	if (ka.ka_type == WBKU_KEY_UNKNOWN) {
		wbku_printerr("Unsupported encryption algorithm\n");
		return (ENCR_ERROR);
	}

	/*
	 * Open the key file for reading.
	 */
	if ((key_fp = fopen(keyfile_name, "r")) == NULL) {
		wbku_printerr("Cannot open %s", keyfile_name);
		return (ENCR_ERROR);
	}

	/*
	 * Get the key from the key file and call the right
	 * encryption routine.
	 */
	ret = get_key(key_fp, &ka, key);
	if (ret == ENCR_SUCCESS) {
		switch (ka.ka_type) {
		case WBKU_KEY_3DES:
			ret = encr_gen_3des(&ka, key);
			break;
		case WBKU_KEY_AES_128:
			ret = encr_gen_aes(&ka, key);
			break;
		default:
			ret = ENCR_ERROR;	/* Internal error only */
		}
	}

	(void) fclose(key_fp);
	return (ret);
}
