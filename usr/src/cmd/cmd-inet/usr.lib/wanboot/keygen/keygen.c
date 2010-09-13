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
#include <ctype.h>
#include <unistd.h>
#include <strings.h>
#include <libintl.h>
#include <locale.h>
#include <limits.h>
#include <libgen.h>
#include <errno.h>
#include <assert.h>
#include <wanbootutil.h>
#include <sys/sysmacros.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wanboot_impl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Return codes */
#define	KEYGEN_SUCCESS	0
#define	KEYGEN_ERROR	1

/* Defaults */
static char default_net[] = "0.0.0.0";
static char default_cid[] = "00000000000000";

/* Suboption. */
#define	NET	0
#define	CID	1
#define	TYPE	2

static char *opts[] = { "net", "cid", "type", NULL };

/*
 * This routine is used to parse the suboptions of '-o' option.
 *
 * The option should be of the form:
 *              net=<addr>,cid=<cid>,type=<3des|aes|sha1|rsa>
 *
 * This routine will pass the values of each of the suboptions back in the
 * supplied arguments, 'net', 'cid' and 'ka'.
 *
 * Returns:
 *	KEYGEN_SUCCESS or KEYGEN_ERROR.
 */
static int
process_option(char *arg, char **net, char **cid, wbku_key_attr_t *ka)
{
	char *value;
	wbku_retcode_t ret;

	while (*arg != '\0') {
		switch (getsubopt(&arg, opts, &value)) {
		case NET:
			/*
			 * Network number.
			 */
			*net = value;
			break;
		case CID:
			/*
			 * Client ID.
			 */
			*cid = value;
			break;
		case TYPE:
			/*
			 * Key type.
			 */
			ret = wbku_str_to_keyattr(value, ka, WBKU_ANY_KEY);
			if (ret != WBKU_SUCCESS) {
				wbku_printerr("%s\n", wbku_retmsg(ret));
				return (KEYGEN_ERROR);
			}
			break;
		default:
			wbku_printerr("%s is not a valid option\n", value);
			return (KEYGEN_ERROR);
		}
	}

	/*
	 * Sanity checks
	 */
	if (*net != NULL && **net == '\0') {
		wbku_printerr("Missing net option value\n");
		return (KEYGEN_ERROR);
	}
	if (*cid != NULL && **cid == '\0') {
		wbku_printerr("Missing cid option value\n");
		return (KEYGEN_ERROR);
	}
	if (*cid != NULL && *net == NULL) {
		wbku_printerr(
		    "The cid option requires net option specification\n");
		return (KEYGEN_ERROR);
	}
	if (ka->ka_type == WBKU_KEY_UNKNOWN) {
		wbku_printerr("Missing key type option value\n");
		return (KEYGEN_ERROR);
	}

	return (KEYGEN_SUCCESS);
}

/*
 * This routine parses a buffer to determine whether or not it
 * contains a hexascii string. If the buffer contains any characters
 * that are not hexascii, then it is not a hexascii string. Since
 * this function is used to validate a CID value (which is then used
 * to identify a directory in the filesystem), no evaluation of the
 * string is performed. That is, hex strings are not padded (e.g. "A"
 * is not padded to "0A").
 *
 * Returns:
 *	B_TRUE or B_FALSE
 */
static boolean_t
isxstring(const char *buf)
{
	if ((strlen(buf) % 2) != 0) {
		return (B_FALSE);
	}

	for (; *buf != '\0'; ++buf) {
		if (!isxdigit(*buf)) {
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

/*
 * This routine uses the 'net' and the 'cid' to generate the client's
 * keystore filename and, if requested, creates the directory path to
 * the file if any of the directories do not exist. If directory path
 * creation is not requested and any of the directories do not exist,
 * then an error is returned.
 *
 * Returns:
 *	KEYGEN_SUCCESS or KEYGEN_ERROR.
 */
static int
create_client_filename(char *filename, size_t len, const char *net,
    const char *cid, boolean_t create)
{
	struct in_addr addr;
	size_t size;

	if (net == NULL) {
		size = snprintf(filename, len, "%s", CLIENT_KEY_DIR);
	} else if (inet_pton(AF_INET, net, &addr) != 1) {
		wbku_printerr("%s is not a valid network address\n", net);
		return (KEYGEN_ERROR);
	} else if (cid == NULL) {
		size = snprintf(filename, len, "%s/%s", CLIENT_KEY_DIR, net);
	} else if (!isxstring(cid)) {
		wbku_printerr(
		    "%s must be an even number of hexadecimal characters\n",
		    cid);
		return (KEYGEN_ERROR);
	} else {
		size = snprintf(filename, len, "%s/%s/%s", CLIENT_KEY_DIR,
		    net, cid);
	}

	/*
	 * Shouldn't be a problem, but make sure buffer was big enough.
	 */
	if (size >= len) {
		wbku_printerr("Keystore path too long\n");
		return (KEYGEN_ERROR);
	}

	/*
	 * If directory creation is allowed, then try to create it.
	 * If the directory already exists, then march on.
	 */
	if (create) {
		if (mkdirp(filename, S_IRWXU) == -1 && errno != EEXIST) {
			wbku_printerr("Cannot create client keystore");
			return (KEYGEN_ERROR);
		}
	}

	/*
	 * Append the filename.
	 */
	if (strlcat(filename, "/keystore", len) >= len) {
		wbku_printerr("Keystore path too long\n");
		return (KEYGEN_ERROR);
	}

	return (KEYGEN_SUCCESS);
}

/*
 * This routine generates a random key of the type defined by 'ka'.
 * The key value is returned in 'rand_key' and the buffer pointed to
 * by 'rand_key' is assumed to be of the correct size.
 *
 * Note:
 *	If 'ka' has a non-NULL keycheck value, then the routine will
 *	generate randon keys until a non-weak key is generated.
 *
 * Returns:
 *	KEYGEN_SUCCESS or KEYGEN_ERROR.
 */
static int
gen_key(const wbku_key_attr_t *ka, uint8_t *rand_key)
{
	/*
	 * Generate key, until non-weak key generated.
	 */
	for (;;) {
		if (wbio_nread_rand(rand_key, ka->ka_len) != 0) {
			wbku_printerr("Cannot generate random number");
			return (KEYGEN_ERROR);
		}

		if (ka->ka_keycheck == NULL || ka->ka_keycheck(rand_key)) {
			return (KEYGEN_SUCCESS);
		}
	}
}

/*
 * This routine generates a random master key of the type (currently only
 * HMAC SHA1 supported) defined by 'ka' and stores it in the master key
 * file.
 *
 * Returns:
 *	KEYGEN_SUCCESS or KEYGEN_ERROR.
 */
static int
master_gen_key(wbku_key_attr_t *ka)
{
	uint8_t mas_key[WANBOOT_HMAC_KEY_SIZE];
	int fd;
	FILE *fp = NULL;
	fpos_t pos;
	wbku_retcode_t ret;
	boolean_t exists = B_FALSE;

	/*
	 * If the file already exists (possibly via keymgmt), then open
	 * the file for update. Otherwise create it and open it for
	 * for writing.
	 */
	fd = open(MASTER_KEY_FILE, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		if (errno == EEXIST) {
			fp = fopen(MASTER_KEY_FILE, "r+");
			exists = B_TRUE;
		}
	} else {
		if ((fp = fdopen(fd, "w")) == NULL) {
			(void) close(fd);
		}
	}

	if (fp == NULL) {
		wbku_printerr("Cannot open master keystore", MASTER_KEY_FILE);
		return (KEYGEN_ERROR);
	}

	/*
	 * If the file already exists, then see if a master key already
	 * exists. We will not overwrite it if it does.
	 */
	ret = WBKU_NOKEY;
	if (exists) {
		ret = wbku_find_key(fp, NULL, ka, NULL, B_TRUE);
		if (ret != WBKU_NOKEY) {
			if (ret == WBKU_SUCCESS) {
				wbku_printerr("The master %s key already "
				    "exists and will not be overwritten\n",
				    ka->ka_str);
			} else {
				wbku_printerr("%s\n", wbku_retmsg(ret));
			}
			(void) fclose(fp);
			return (KEYGEN_ERROR);
		}
	}

	/*
	 * If wbku_find_key() did not find the key position for us
	 * (expected behavior), then we should set position to
	 * the end of the file.
	 */
	if (ret == WBKU_NOKEY &&
	    (fseek(fp, 0, SEEK_END) != 0 || fgetpos(fp, &pos) != 0)) {
		wbku_printerr("Internal error");
		(void) fclose(fp);
		return (KEYGEN_ERROR);
	}

	/*
	 * Generate a key and write it.
	 */
	if (gen_key(ka, mas_key) != KEYGEN_SUCCESS) {
		(void) fclose(fp);
		return (KEYGEN_ERROR);
	}

	ret = wbku_write_key(fp, &pos, ka, mas_key, B_TRUE);
	(void) fclose(fp);
	if (ret != WBKU_SUCCESS) {
		wbku_printerr("%s\n", wbku_retmsg(ret));
		return (KEYGEN_ERROR);
	}

	(void) printf(gettext("The master %s key has been generated\n"),
	    ka->ka_str);
	return (KEYGEN_SUCCESS);
}

/*
 * This routine generates a random client key of the type
 * defined by 'ka' and stores it in the client keystore.
 * file.
 *
 * Returns:
 *	KEYGEN_SUCCESS or KEYGEN_ERROR.
 */
static int
client_gen_key(const char *filename, wbku_key_attr_t *ka, const char *net,
    const char *cid)
{
	int fd;
	FILE *cli_fp = NULL;
	FILE *mas_fp;
	fpos_t pos;
	uint8_t cli_key[WANBOOT_MAXKEYLEN];
	uint8_t mas_key[WANBOOT_HMAC_KEY_SIZE];
	SHA1_CTX ctx;
	char cid_buf[PATH_MAX];
	boolean_t exists = B_FALSE;
	wbku_retcode_t ret;

	/*
	 * If the file already exists (possibly via keymgmt), then open
	 * the file for update. Otherwise create it and open it for
	 * for writing.
	 */
	fd = open(filename, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		if (errno == EEXIST) {
			cli_fp = fopen(filename, "r+");
			exists = B_TRUE;
		}
	} else {
		if ((cli_fp = fdopen(fd, "w")) == NULL) {
			(void) close(fd);
		}
	}

	if (cli_fp == NULL) {
		wbku_printerr("Cannot open client keystore");
		return (KEYGEN_ERROR);
	}

	/*
	 * Generate the key. Encryption keys can be generated by simply
	 * calling gen_key(). An HMAC SHA1 key will be generated by
	 * hashing the master key.
	 */
	switch (ka->ka_type) {
	case WBKU_KEY_3DES:
	case WBKU_KEY_AES_128:
		if (gen_key(ka, cli_key) != KEYGEN_SUCCESS) {
			(void) fclose(cli_fp);
			return (KEYGEN_ERROR);
		}
		break;
	case WBKU_KEY_HMAC_SHA1:
		/*
		 * Follow RFC 3118 Appendix A's algorithm to generate
		 * the HMAC/SHA1 client key.
		 */

		/*
		 * Open the master keystore for reading only.
		 */
		if ((mas_fp = fopen(MASTER_KEY_FILE, "r")) == NULL) {
			wbku_printerr("Cannot open master keystore");
			(void) fclose(cli_fp);
			return (KEYGEN_ERROR);
		}

		/*
		 * Find the master key.
		 */
		ret = wbku_find_key(mas_fp, NULL, ka, mas_key, B_TRUE);
		if (ret != WBKU_SUCCESS) {
			if (ret == WBKU_NOKEY) {
				wbku_printerr("Cannot create a client key "
				    "without first creating a master key\n");
			} else {
				wbku_printerr("%s\n", wbku_retmsg(ret));
			}
			(void) fclose(mas_fp);
			(void) fclose(cli_fp);
			return (KEYGEN_ERROR);
		}
		(void) fclose(mas_fp);

		/*
		 * Now generate the client's unique ID buffer.
		 */
		if (strlcpy(cid_buf, net, PATH_MAX) >= PATH_MAX ||
		    strlcat(cid_buf, cid, PATH_MAX) >= PATH_MAX) {
			wbku_printerr("Unique id for client is too big\n");
			(void) fclose(cli_fp);
			return (KEYGEN_ERROR);
		}

		/*
		 * Hash the buffer to create the client key.
		 */
		HMACInit(&ctx, mas_key, WANBOOT_HMAC_KEY_SIZE);
		HMACUpdate(&ctx, (uint8_t *)cid_buf, strlen(cid_buf));
		HMACFinal(&ctx, mas_key, WANBOOT_HMAC_KEY_SIZE, cli_key);

		break;
	case WBKU_KEY_RSA:
		wbku_printerr("Cannot generate RSA key using keygen\n");
		(void) fclose(cli_fp);
		return (KEYGEN_ERROR);
	default:
		wbku_printerr("Internal error\n");
		(void) fclose(cli_fp);
		return (KEYGEN_ERROR);
	}

	/*
	 * Look to see if a client key of this type exists and if
	 * it does note its position in the file.
	 */
	ret = WBKU_NOKEY;
	if (exists) {
		ret = wbku_find_key(cli_fp, &pos, ka, NULL, B_FALSE);
		if (ret != WBKU_SUCCESS && ret != WBKU_NOKEY) {
			wbku_printerr("%s\n", wbku_retmsg(ret));
			(void) fclose(cli_fp);
			return (KEYGEN_ERROR);
		}
	}

	/*
	 * If wbku_find_key() did not find the key position for us,
	 * then we should set position to the end of the file.
	 */
	if (ret == WBKU_NOKEY &&
	    (fseek(cli_fp, 0, SEEK_END) != 0 || fgetpos(cli_fp, &pos) != 0)) {
		wbku_printerr("Internal error");
		(void) fclose(cli_fp);
		return (KEYGEN_ERROR);
	}

	/*
	 * Write the key.
	 */
	ret = wbku_write_key(cli_fp, &pos, ka, cli_key, B_FALSE);
	if (ret != WBKU_SUCCESS) {
		wbku_printerr("%s\n", wbku_retmsg(ret));
		(void) fclose(cli_fp);
		return (KEYGEN_ERROR);
	}
	(void) fclose(cli_fp);

	(void) printf(gettext("A new client %s key has been generated\n"),
	    ka->ka_str);

	return (KEYGEN_SUCCESS);
}

/*
 * This routine is used to print a hexascii version of a key.
 * The hexascii version of the key will be twice the length
 * of 'datalen'.
 */
static void
keydump(const char *key, int keylen)
{
	uint16_t *p16;

	assert(IS_P2ALIGNED(key, sizeof (uint16_t)));
/*LINTED aligned*/
	for (p16 = (uint16_t *)key; keylen > 0; keylen -= 2) {
		(void) printf("%04x", htons(*p16++));
	}
	(void) printf("\n");
}

/*
 * This routine is used to print a key of the type
 * described by 'ka'. If 'master' is true, then the
 * key to display is the master key. Otherwise, it's a
 * client key.
 *
 * Returns:
 *	KEYGEN_SUCCESS or KEYGEN_ERROR.
 */
static int
display_key(const char *filename, wbku_key_attr_t *ka, boolean_t master)
{
	uint8_t key[WANBOOT_MAXKEYLEN];
	FILE *fp;
	wbku_retcode_t ret;

	/*
	 * Open the keystore for reading only.
	 */
	if ((fp = fopen(filename, "r")) == NULL) {
		wbku_printerr("Cannot open keystore");
		return (KEYGEN_ERROR);
	}

	/*
	 * Find the key.
	 */
	ret = wbku_find_key(fp, NULL, ka, key, master);
	if (ret != WBKU_SUCCESS) {
		if (ret == WBKU_NOKEY) {
			wbku_printerr("The %s %s key does not exist\n",
			    (master ? "master" : "client"), ka->ka_str);
		} else {
			wbku_printerr("%s\n", wbku_retmsg(ret));
		}
		(void) fclose(fp);
		return (KEYGEN_ERROR);
	}
	(void) fclose(fp);

	/*
	 * Dump the key in hex.
	 */
	keydump((char *)key, ka->ka_len);

	return (KEYGEN_SUCCESS);
}

/*
 * Prints usage().
 */
static void
usage(const char *cmd)
{
	(void) fprintf(stderr, gettext("Usage: %s [-m | -c "
	    "-o net=<addr>,cid=<cid>,type=<%s|%s|%s>]\n"
	    "       %s -d [-m | -c -o net=<addr>,cid=<cid>,"
	    "type=<%s|%s|%s|%s>]\n"),
	    cmd, WBKU_KW_3DES, WBKU_KW_AES_128, WBKU_KW_HMAC_SHA1,
	    cmd, WBKU_KW_3DES, WBKU_KW_AES_128, WBKU_KW_HMAC_SHA1, WBKU_KW_RSA);
}

/*
 * This program is used to generate and display WAN boot encryption and
 * hash keys. The paths to the keystores are predetermined. That is, the
 * master keystore (used to store a master HMAC SHA1 key) will always
 * reside in the default location, MASTER_KEY_FILE. The client keystores
 * will always reside in default locations that are computed using their
 * network number and cid values.
 *
 * Note:
 * 	The master keystore can store client keys too. This program
 *	cannot be used to insert client keys into the master keystore.
 *	However, it must not corrupt any client keystore inserted into
 *	the file by other means (keymgmt).
 *
 *	We do not do any file locking scheme.  This means that if two
 *	keygen commands are run concurrently, results can be disastrous.
 *
 * Returns:
 *	KEYGEN_SUCCESS or KEYGEN_ERROR.
 */
int
main(int argc, char **argv)
{
	char filename[PATH_MAX];
	char *filenamep;
	int c;
	boolean_t is_client = B_FALSE;
	boolean_t is_master = B_FALSE;
	boolean_t display = B_FALSE;
	char *net = NULL;
	char *cid = NULL;
	wbku_key_attr_t ka;
	wbku_retcode_t ret;

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
		return (KEYGEN_ERROR);
	}

	/*
	 * Parse the options.
	 */
	ka.ka_type = WBKU_KEY_UNKNOWN;
	while ((c = getopt(argc, argv, "dcmo:")) != EOF) {
		switch (c) {
		case 'd':
			/*
			 * Display a key.
			 */
			display = B_TRUE;
			break;
		case 'o':
			/*
			 * Suboptions.
			 */
			if (process_option(optarg, &net, &cid, &ka) != 0) {
				usage(argv[0]);
				return (KEYGEN_ERROR);
			}
			break;
		case 'c':
			is_client = B_TRUE;
			break;
		case 'm':
			is_master = B_TRUE;
			break;
		default:
			usage(argv[0]);
			return (KEYGEN_ERROR);
		}
	}

	/*
	 * Must be operating on a master or client key and if
	 * it's a client key, then type must have been given.
	 */
	if ((is_client == is_master) ||
	    (is_client && ka.ka_type == WBKU_KEY_UNKNOWN)) {
		usage(argv[0]);
		return (KEYGEN_ERROR);
	}

	/*
	 * If operating on the master key, then it is an HMAC SHA1
	 * key. Build the correct 'ka'. If we're working on a client
	 * key, the 'ka' was already built as part of option parsing.
	 */
	if (is_master) {
		ret = wbku_str_to_keyattr(WBKU_KW_HMAC_SHA1, &ka,
		    WBKU_HASH_KEY);
		if (ret != WBKU_SUCCESS) {
			wbku_printerr("Internal error\n");
			return (KEYGEN_ERROR);
		}
		filenamep = MASTER_KEY_FILE;
	} else {
		/*
		 * Build the path to the client keystore.
		 */
		if (create_client_filename(filename, sizeof (filename), net,
		    cid, !display) != KEYGEN_SUCCESS) {
			return (KEYGEN_ERROR);
		}
		filenamep = filename;
	}

	/*
	 * If display chosen, go do it.
	 */
	if (display) {
		return (display_key(filenamep, &ka, is_master));
	}

	/*
	 * Can't generate RSA key here.
	 */
	if (ka.ka_type == WBKU_KEY_RSA) {
		wbku_printerr("keygen cannot create RSA key\n");
		return (KEYGEN_ERROR);
	}

	/*
	 * If generating a master key, go do it.
	 */
	if (is_master) {
		return (master_gen_key(&ka));
	}

	/*
	 * Must be generating a client key, go do it.
	 */
	if (net == NULL) {
		net = default_net;
	}
	if (cid == NULL) {
		cid = default_cid;
	}
	if (client_gen_key(filename, &ka, net, cid) != KEYGEN_SUCCESS) {
		return (KEYGEN_ERROR);
	}

	return (KEYGEN_SUCCESS);
}
