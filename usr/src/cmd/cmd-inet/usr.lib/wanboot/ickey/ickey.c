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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/wanboot_impl.h>
#include <libinetutil.h>
#include <wanbootutil.h>
#include <libintl.h>
#include <locale.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <assert.h>
#include <sys/openpromio.h>

#define	TYPE	0
static char	*progopts[] = {
	"type",
	NULL
};

/*
 *	The key's handle is the name by which a user knows the key (i.e. the
 *	name specified on the command line.  The keyname is the name this
 *	utility uses to store the keys and the name OBP and wanboot use to
 *	retrieve them.
 */
static struct keylist {
	const char	*handle;
	const char	*keyname;
	const int	keysize;	/* size of hex string representation */
} keylist[] = {
	WBKU_KW_3DES, WANBOOT_DES3_KEY_NAME,
	    (DES3_KEY_SIZE * 2),
	WBKU_KW_AES_128, WANBOOT_AES_128_KEY_NAME,
	    (AES_128_KEY_SIZE * 2),
	WBKU_KW_HMAC_SHA1, WANBOOT_HMAC_SHA1_KEY_NAME,
	    (WANBOOT_HMAC_KEY_SIZE * 2)
};

static const struct keylist	*knownkeytype(char *);
static char			*getkey(const struct keylist *);
static void			deletekey(const struct keylist *);
static void			installkey(const struct keylist *);
static void			usage(const char *) __NORETURN;

static boolean_t	delete = B_FALSE;

int
main(int ac, char **av)
{
	int			i;
	const struct keylist	*k;
	char			*typestring = NULL;
	char			*options;
	char			*value;

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
	wbku_errinit(av[0]);

	while ((i = getopt(ac, av, "do:")) != -1)
		switch (i) {
			case 'd':
				delete	= B_TRUE;
				break;

			case 'o':
				options = optarg;
				while (*options != '\0') {
					switch (getsubopt(&options, progopts,
					    &value)) {
						case TYPE:
							typestring = value;
							break;

						default:
							/* unknown token */
							usage(*av);
							/* NOTREACHED */
					}
				}
				break;

			case '?':
				usage(*av);
				/* NOTREACHED */
		}

	if ((optind >= ac) && (typestring != NULL) &&
	    ((k = knownkeytype(typestring)) != NULL)) {
		if (delete == B_TRUE)
			deletekey(k);
		else
			installkey(k);
		return (0);
	} else {
		usage(*av);
		/* NOTREACHED */
	}
}

static const struct keylist *
knownkeytype(char *type)
{
	int	i;

	for (i = 0; i < sizeof (keylist)/sizeof (keylist[0]); i++) {
		if (strcmp(keylist[i].handle, type) == 0)
			return (&keylist[i]);
	}

	return (NULL);
}

static void
deletekey(const struct keylist *k)
{
	int			fd;
	struct wankeyio		wkio;
	struct openpromio	*oio;

	(void) strlcpy(wkio.wk_keyname, k->keyname, WANBOOT_MAXKEYNAMELEN);
	wkio.wk_keysize = 0;	/* zero key size indicates a deletion */

	oio = malloc(sizeof (struct openpromio) + sizeof (struct wankeyio));
	if (oio == NULL) {
		wbku_printerr("openpromio malloc (%d) failed\n",
		    sizeof (struct openpromio) +
		    sizeof (struct wankeyio));
		exit(1);
	}
	oio->oprom_size = sizeof (struct wankeyio);
	bcopy(&wkio, oio->oprom_array, sizeof (struct wankeyio));
	fd = open("/dev/openprom", O_RDWR);
	if (fd == -1) {
		wbku_printerr("open: /dev/openprom");
		exit(1);
	}

	if (ioctl(fd, WANBOOT_SETKEY, oio) == -1) {
		wbku_printerr("setkey: ioctl");
		exit(1);
	}

	(void) close(fd);
}

static void
installkey(const struct keylist *k)
{
	char			*keyptr;
	int			fd;
	struct wankeyio		wkio;
	struct openpromio	*oio;
	uint_t			rawkeysize;
	int			err;

	(void) strlcpy(wkio.wk_keyname, k->keyname, WANBOOT_MAXKEYNAMELEN);
	assert((k->keysize % 2) == 0);
	wkio.wk_keysize = k->keysize / 2;

	if ((keyptr = getkey(k)) != NULL) {
		rawkeysize = sizeof (wkio.wk_u);
		if ((err = hexascii_to_octet(keyptr, strlen(keyptr),
		    wkio.wk_u.key, &rawkeysize)) != 0) {
			wbku_printerr(
			    "internal error: hexascii_to_octet returned %d\n",
			    err);
			exit(1);
		} else if (rawkeysize != wkio.wk_keysize) {
			wbku_printerr("internal error:  key size mismatch\n");
			exit(1);
		}

		oio = malloc(sizeof (struct openpromio) +
		    sizeof (struct wankeyio));
		if (oio == NULL) {
			wbku_printerr("openpromio malloc (%d) failed\n",
			    sizeof (struct openpromio) +
			    sizeof (struct wankeyio));
			exit(1);
		}
		oio->oprom_size = sizeof (struct wankeyio);
		bcopy(&wkio, oio->oprom_array, sizeof (struct wankeyio));
		fd = open("/dev/openprom", O_RDWR);
		if (fd == -1) {
			wbku_printerr("open: /dev/openprom");
			exit(1);
		}

		if (ioctl(fd, WANBOOT_SETKEY, oio) == -1) {
			wbku_printerr("setkey: ioctl");
			exit(1);
		}

		(void) close(fd);
	} else {
		wbku_printerr("getpassphrase");	/* getpassphrase() failed */
		exit(1);
	}
}

static char *
getkey(const struct keylist *k)
{
	char	prompt[BUFSIZ];
	char	*p;
	char	*q;
	int	len;

	(void) snprintf(prompt, sizeof (prompt),
	    gettext("Enter %s key:  "), k->handle);
	p = getpassphrase(prompt);
	if (p) {
		/* skip over initial "0[xX]" */
		if ((p[0] == '0') && (p[1] == 'x' || p[1] == 'X'))
			p += 2;
		len = strlen(p);
		if (len != k->keysize) {
			wbku_printerr(
			    "key length mismatch (expected %d, got %d)\n",
			    k->keysize, len);
			exit(1);
		}
		for (q = p; q < p + len; q++)
			if (!isxdigit(*q)) {
				wbku_printerr(
				    "non-hexadecimal characters in key\n");
				exit(1);
			}
	}

	return (p);
}

static void
usage(const char *progname)
{
	int	i;

	(void) fprintf(stderr, gettext(
	    "usage:  %s [ -d ] -o type=keytype\nwhere keytype is one of "),
	    progname);
	for (i = 0; i < sizeof (keylist)/sizeof (keylist[0]); i++)
		(void) fprintf(stderr, "%s ", keylist[i].handle);
	(void) fputc('\n', stderr);
	exit(1);
}
