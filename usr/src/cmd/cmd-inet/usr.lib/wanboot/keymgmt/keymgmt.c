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
#include <alloca.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <libintl.h>
#include <locale.h>
#include <limits.h>
#include <libgen.h>
#include <errno.h>
#include <ctype.h>
#include <wanbootutil.h>
#include <sys/sysmacros.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wanboot_impl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Return codes */
#define	KEYMGMT_SUCCESS	0
#define	KEYMGMT_ERROR	1

/* Suboption. */
#define	TYPE	0

static char *opts[] = { "type", NULL };

/*
 * This routine is used to parse the suboptions of '-o' option.
 *
 * The option should be of the form: type=<3des|aes|sha1|rsa>
 *
 * This routine will pass the value of the suboption back in the
 * supplied arguments, 'ka'.
 *
 * Returns:
 *	KEYMGMT_SUCCESS or KEYMGMT_ERROR.
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
			ret = wbku_str_to_keyattr(value, ka, WBKU_ANY_KEY);
			if (ret != WBKU_SUCCESS) {
				wbku_printerr("%s\n", wbku_retmsg(ret));
				return (KEYMGMT_ERROR);
			}
			break;
		default:
			wbku_printerr("%s is not a valid option\n", value);
			return (KEYMGMT_ERROR);
		}
	}

	/*
	 * Success.
	 */
	return (KEYMGMT_SUCCESS);
}

/*
 * This routine extracts a key of type 'ka' from the keystore named
 * 'keystore_name' and writes it the the file identified by 'name'.
 *
 * Returns:
 *	KEYMGMT_SUCCESS or KEYMGMT_ERROR.
 */
static int
process_extract(const char *keystore_name, const char *name,
    wbku_key_attr_t *ka)
{
	size_t i;
	uint8_t ex_key[WANBOOT_MAXKEYLEN];
	FILE *keystore_fp;
	FILE *fp;
	wbku_retcode_t ret;

	/*
	 * Open the keystore for reading.
	 */
	if ((keystore_fp = fopen(keystore_name, "r")) == NULL) {
		wbku_printerr("Cannot open %s", keystore_name);
		return (KEYMGMT_ERROR);
	}

	/*
	 * Find the client key.
	 */
	ret = wbku_find_key(keystore_fp, NULL, ka, ex_key, B_FALSE);
	if (ret != WBKU_SUCCESS) {
		if (ret == WBKU_NOKEY) {
			wbku_printerr("The client %s key does not exist\n",
			    ka->ka_str);
		} else {
			wbku_printerr("%s\n", wbku_retmsg(ret));
		}
		(void) fclose(keystore_fp);
		return (KEYMGMT_ERROR);
	}
	(void) fclose(keystore_fp);

	/*
	 * Open the output file.
	 */
	if ((fp = fopen(name, "w")) == NULL) {
		wbku_printerr("Cannot open %s", name);
		(void) fclose(keystore_fp);
		return (KEYMGMT_ERROR);
	}

	/*
	 * Dump the key to the output file.
	 */
	i = fwrite(ex_key, sizeof (uint8_t), ka->ka_len, fp);
	if (i != ka->ka_len) {
		wbku_printerr("Error writing to %s", name);
		(void) fclose(fp);
		return (KEYMGMT_ERROR);
	}
	(void) fclose(fp);

	/*
	 * Success.
	 */
	return (KEYMGMT_SUCCESS);
}

/*
 * There is a key which needs to be removed from the keystore.  Given basic
 * information about the key to be deleted, go through the keystore and
 * remove it.  The steps are:
 *   1) create a temp file in the same directory as the keystore.
 *   2) copy the existing keystore to the temp file, omitting the key being
 *      removed.
 *   3) shuffle files.  Close the keystore and move it aside.  Close the
 *      temp file and move in to the keystore.
 *
 * Returns:
 *	B_TRUE on success
 *	B_FALSE on error
 */
static boolean_t
compress_keystore(const char *keystore_name, FILE *fp,
    const wbku_key_attr_t *ka)
{
	char *tmp_path;
	FILE *tmp_fp;
	int tmp_fd;
	int len;
	wbku_retcode_t ret;

	/*
	 * Allocate storage for the temporary path from the stack.
	 */
	len = strlen(keystore_name) + sizeof (".XXXXXX");
	tmp_path = alloca(len);
	(void) snprintf(tmp_path, len, "%s.XXXXXX", keystore_name);

	/*
	 * Make the temp working file where a new store will be created.
	 */
	if ((tmp_fd = mkstemp(tmp_path)) == -1) {
		wbku_printerr("Error creating %s\n", tmp_path);
		return (B_FALSE);
	}

	/*
	 * Need to reference this file as a stream.
	 */
	if ((tmp_fp = fdopen(tmp_fd, "w")) == NULL) {
		wbku_printerr("Error opening %s", tmp_path);
		(void) close(tmp_fd);
		(void) unlink(tmp_path);
		return (B_FALSE);
	}

	/*
	 * Copy the existing keystore to the temp one, omitting the
	 * key being deleted.
	 */
	ret = wbku_delete_key(fp, tmp_fp, ka);
	(void) fclose(tmp_fp);
	if (ret != WBKU_SUCCESS) {
		wbku_printerr("%s\n", wbku_retmsg(ret));
		(void) unlink(tmp_path);
		return (B_FALSE);
	}

	/*
	 * Shuffle files.
	 */
	if (rename(tmp_path, keystore_name) == -1) {
		wbku_printerr("Error moving new keystore file from %s to %s",
		    tmp_path, keystore_name);
		(void) unlink(tmp_path);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * This routine reads a key of type 'ka' from the file identified 'name' and
 * inserts it into the keystore named 'keystore_name'.
 *
 * Returns:
 *	KEYMGMT_SUCCESS or KEYMGMT_ERROR.
 */
static int
process_insert(const char *keystore_name, const char *name,
    wbku_key_attr_t *ka)
{
	int fd;
	FILE *keystore_fp = NULL;
	FILE *fp;
	fpos_t pos;
	uint8_t rd_key[WANBOOT_MAXKEYLEN];
	int inlen;
	boolean_t newfile = B_TRUE;
	wbku_retcode_t ret;

	/*
	 * If the file already exists, then open the file for update.
	 * Otherwise, create it and open it for writing.
	 */
	fd = open(keystore_name, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		if (errno == EEXIST) {
			keystore_fp = fopen(keystore_name, "r+");
			newfile = B_FALSE;
		}
	} else {
		if ((keystore_fp = fdopen(fd, "w")) == NULL) {
			(void) close(fd);
		}
	}

	if (keystore_fp == NULL) {
		wbku_printerr("Cannot open %s", keystore_name);
		return (KEYMGMT_ERROR);
	}

	/*
	 * Open the input file.
	 */
	fp = fopen(name, "r");
	if (fp == NULL) {
		wbku_printerr("Cannot open %s", name);
		(void) fclose(keystore_fp);
		return (KEYMGMT_ERROR);
	}

	/*
	 * Read the key from the file.
	 */
	inlen = fread(rd_key, sizeof (uint8_t), ka->ka_maxlen, fp);
	if (inlen == 0 && ferror(fp) != 0) {
		wbku_printerr("Error reading %s", name);
		(void) fclose(fp);
		(void) fclose(keystore_fp);
		return (KEYMGMT_ERROR);
	}
	(void) fclose(fp);

	if ((inlen < ka->ka_minlen) || (inlen > ka->ka_maxlen)) {
		wbku_printerr("Key length is not valid\n");
		(void) fclose(keystore_fp);
		return (KEYMGMT_ERROR);
	}

	/*
	 * If the keystore exists, search for a key of the type
	 * being inserted. If found, note its file position.
	 */
	ret = WBKU_NOKEY;
	if (!newfile) {
		ret = wbku_find_key(keystore_fp, &pos, ka, NULL, B_FALSE);
		if (ret != WBKU_SUCCESS && ret != WBKU_NOKEY) {
			wbku_printerr("%s\n", wbku_retmsg(ret));
			(void) fclose(keystore_fp);
			return (KEYMGMT_ERROR);
		}

		/*
		 * Unfortuantely, RSA keys have variable lengths. If
		 * the one being inserted is a different length than
		 * than the one that already exists in the file, then
		 * the key must be removed from the keystore and then
		 * readded.
		 */
		if (ret == WBKU_SUCCESS && inlen != ka->ka_len) {
			if (!compress_keystore(keystore_name,
			    keystore_fp, ka)) {
				wbku_printerr("Insertion required compression"
				    " of keystore, but compression failed\n"
				    "Key was not inserted\n");
				(void) fclose(keystore_fp);
				return (KEYMGMT_ERROR);
			}

			/*
			 * The original keystore is history. Close the
			 * stream and open a stream to the new keystore.
			 */
			(void) fclose(keystore_fp);
			keystore_fp = fopen(keystore_name, "r+");
			if (keystore_fp == NULL) {
				wbku_printerr("Cannot open %s", keystore_name);
				return (KEYMGMT_ERROR);
			}

			/* Force new key to end of file */
			ret = WBKU_NOKEY;
		}
	}
	ka->ka_len = inlen;

	/*
	 * If wbku_find_key() did not find the key position for us,
	 * then we should set position to the end of the file.
	 */
	if (ret == WBKU_NOKEY && (fseek(keystore_fp, 0, SEEK_END) != 0 ||
	    fgetpos(keystore_fp, &pos) != 0)) {
		wbku_printerr("Internal error");
		(void) fclose(keystore_fp);
		return (KEYMGMT_ERROR);
	}

	/*
	 * Write the key to the keystore.
	 */
	ret = wbku_write_key(keystore_fp, &pos, ka, rd_key, B_FALSE);
	(void) fclose(keystore_fp);
	if (ret != WBKU_SUCCESS) {
		wbku_printerr("%s\n", wbku_retmsg(ret));
		return (KEYMGMT_ERROR);
	}

	(void) printf(gettext("The client's %s key has been set\n"),
	    ka->ka_str);
	/*
	 * Success.
	 */
	return (KEYMGMT_SUCCESS);
}

/*
 * Prints usage().
 */
static void
usage(const char *cmd)
{
	(void) fprintf(stderr, gettext("Usage: %s"
	    " -i -k <key_file> -s <keystore> -o type=<%s|%s|%s|%s>\n"
	    "       %s -x -f <out_file> -s <keystore> -o"
	    " type=<%s|%s|%s|%s>\n"),
	    cmd, WBKU_KW_3DES, WBKU_KW_AES_128, WBKU_KW_HMAC_SHA1, WBKU_KW_RSA,
	    cmd, WBKU_KW_3DES, WBKU_KW_AES_128, WBKU_KW_HMAC_SHA1, WBKU_KW_RSA);
}

/*
 * This program is used to insert and extract WAN boot encryption and
 * hash keys into and from keystores. The paths to the keystores are
 * provided by the user as are the input and output files.
 *
 * Note:
 * 	This program assumes all keys being inserted or extracted
 *	are client keys. There is no way for a user to insert or
 *	extract a master key using this program.
 *
 *	We do not do any file locking scheme.  This means that if two
 *	keymgmt commands are run concurrently, results can be disastrous.
 *
 * Returns:
 *	KEYMGMT_SUCCESS or KEYMGMT_ERROR.
 */
int
main(int argc, char **argv)
{
	int c;
	boolean_t is_insert = B_FALSE;
	boolean_t is_extract = B_FALSE;
	char *keystore_name = NULL;
	char *filename = NULL;
	wbku_key_attr_t ka;
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
	 * At the very least, we'll need one arg.
	 */
	if (argc < 2) {
		usage(argv[0]);
		return (KEYMGMT_ERROR);
	}

	/*
	 * Parse the options.
	 */
	ka.ka_type = WBKU_KEY_UNKNOWN;
	while ((c = getopt(argc, argv, "ixf:k:s:o:")) != EOF) {
		switch (c) {
		case 'i':
			is_insert = B_TRUE;
			break;
		case 'x':
			is_extract = B_TRUE;
			break;
		case 'o':
			/*
			 * Suboptions.
			 */
			if (process_option(optarg, &ka) != KEYMGMT_SUCCESS) {
				usage(argv[0]);
				return (KEYMGMT_ERROR);
			}
			break;
		case 's':
			/*
			 * Keystore path.
			 */
			keystore_name = optarg;
			break;
		case 'f':
			/*
			 * Input file.
			 */
			if (is_insert || filename != NULL) {
				usage(argv[0]);
				return (KEYMGMT_ERROR);
			}
			filename = optarg;
			break;
		case 'k':
			/*
			 * Input file.
			 */
			if (is_extract || filename != NULL) {
				usage(argv[0]);
				return (KEYMGMT_ERROR);
			}
			filename = optarg;
			break;
		default:
			usage(argv[0]);
			return (KEYMGMT_ERROR);
		}
	}

	/*
	 * Must be inserting or extracting a key and we must have a
	 * key type, keystore filename and an input or output filename.
	 */
	if ((is_insert == is_extract) || keystore_name == NULL ||
	    filename == NULL || ka.ka_type == WBKU_KEY_UNKNOWN) {
		usage(argv[0]);
		return (KEYMGMT_ERROR);
	}

	/*
	 * Insert or extract the key.
	 */
	if (is_insert) {
		ret = process_insert(keystore_name, filename, &ka);
	} else {
		ret = process_extract(keystore_name, filename, &ka);
	}

	return (ret);
}
