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
#include <string.h>
#include <errno.h>
#include <wanbootutil.h>
#include <sys/wanboot_impl.h>

/* Return codes */
#define	HMAC_SUCCESS	0
#define	HMAC_NOKEY	1
#define	HMAC_ERROR	2

/* Private buffer length */
#define	HMAC_BUF_LEN	1024

/*
 * This routine is used to compute a hash digest for the file represented
 * by the file descirptor, 'fd'. The key, 'hmac_key', and key type, 'ka',
 * will be provided by the caller. The resulting hash digest will be
 * written to stdout.
 *
 * Returns:
 *	HMAC_SUCCESS or HMAC_ERROR.
 */
static int
hash_gen(int in_fd, const wbku_key_attr_t *ka, const uint8_t *hmac_key)
{
	SHA1_CTX ctx;
	uint8_t buf[HMAC_BUF_LEN];
	ssize_t i;
	uint8_t digest[HMAC_DIGEST_LEN];

	/*
	 * Initialize the computation.
	 */
	HMACInit(&ctx, hmac_key, ka->ka_len);

	/*
	 * Read the data to hash.
	 */
	while ((i = read(in_fd, buf, HMAC_BUF_LEN)) > 0) {
		HMACUpdate(&ctx, buf, i);
	}
	if (i < 0) {
		wbku_printerr("Cannot read input_file");
		return (HMAC_ERROR);
	}

	/*
	 * Finalize the digest.
	 */
	HMACFinal(&ctx, hmac_key, ka->ka_len, digest);

	/*
	 * Write the digest to stdout.
	 */
	if (wbio_nwrite(STDOUT_FILENO, digest, sizeof (digest)) != 0) {
		wbku_printerr("Cannot output digest");
		return (HMAC_ERROR);
	}

	/*
	 * Success.
	 */
	return (HMAC_SUCCESS);
}

/*
 * Prints usage().
 */
static void
usage(const char *cmd)
{
	(void) fprintf(stderr,
	    gettext("Usage: %s [-i input_file] -k key_file\n"), cmd);
}

/*
 * This program is used to compute a hash digest for data read in from
 * stdin or optionally, a file. The resulting hash digest will be written
 * to stdout.
 *
 * Returns:
 *	HMAC_SUCCESS, HMAC_ERROR or HMAC_NOKEY.
 */
int
main(int argc, char **argv)
{
	uint8_t hmac_key[WANBOOT_HMAC_KEY_SIZE];
	int c;
	char *infile_name = NULL;
	char *keyfile_name = NULL;
	int in_fd = -1;
	FILE *key_fp = NULL;
	wbku_key_attr_t ka;
	wbku_retcode_t wbkuret;
	int ret = HMAC_ERROR;

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
	 * Should be at least three arguments.
	 */
	if (argc < 3) {
		usage(argv[0]);
		return (HMAC_ERROR);
	}

	/*
	 * Parse the options.
	 */
	while ((c = getopt(argc, argv, "i:k:")) != EOF) {
		switch (c) {
		case 'i':
			/*
			 * Optional input file.
			 */
			infile_name = optarg;
			break;
		case 'k':
			/*
			 * Path to key file.
			 */
			keyfile_name = optarg;
			break;
		default:
			usage(argv[0]);
			return (HMAC_ERROR);
		}
	}

	/*
	 * A key file must be defined.
	 */
	if (keyfile_name == NULL) {
		wbku_printerr("Must specify the key_file\n");
		return (HMAC_ERROR);
	}

	/*
	 * If the user did not provide an input file for the data,
	 * then use stdin as the source.
	 */
	if (infile_name == NULL) {
		in_fd = STDIN_FILENO;
	} else {
		in_fd = open(infile_name, O_RDONLY);
		if (in_fd < 0) {
			wbku_printerr("Cannot open input_file");
			return (HMAC_ERROR);
		}
	}

	/*
	 * Open the key file for reading.
	 */
	if ((key_fp = fopen(keyfile_name, "r")) == NULL) {
		wbku_printerr("Cannot open %s", keyfile_name);
		goto out;
	}

	/*
	 * Create a SHA1 key attribute structure. It's the only hash
	 * type we support.
	 */
	wbkuret = wbku_str_to_keyattr(WBKU_KW_HMAC_SHA1, &ka, WBKU_HASH_KEY);
	if (wbkuret != WBKU_SUCCESS) {
		wbku_printerr("%s\n", wbku_retmsg(wbkuret));
		goto out;
	}

	/*
	 * Find the client key, if it exists.
	 */
	wbkuret = wbku_find_key(key_fp, NULL, &ka, hmac_key, B_FALSE);
	if (wbkuret != WBKU_SUCCESS) {
		wbku_printerr("%s\n", wbku_retmsg(wbkuret));
		ret = (wbkuret == WBKU_NOKEY) ? HMAC_NOKEY : HMAC_ERROR;
	} else {
		ret = hash_gen(in_fd, &ka, hmac_key);
	}
out:
	/*
	 * Cleanup.
	 */
	if (in_fd != -1) {
		(void) close(in_fd);
	}
	if (key_fp != NULL) {
		(void) fclose(key_fp);
	}

	return (ret);
}
