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
 */

#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <limits.h>
#include <libnvpair.h>
#include <locale.h>
#include <sys/stat.h>
#include <sys/fs_reparse.h>
#include <rp_plugin.h>
#include <uuid/uuid.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <priv.h>
#include <nfs/nfs4.h>
#include <rpcsvc/nfs4_prot.h>
#include "ref_subr.h"

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif /* TEXT_DOMAIN */

extern int errno;

void
usage()
{
	fprintf(stderr, gettext("Usage:\n"));
	fprintf(stderr,
	    gettext("\tnfsref [-t type] add path location [location ...]\n"));
	fprintf(stderr, gettext("\tnfsref [-t type] remove path\n"));
	fprintf(stderr, gettext("\tnfsref [-t type] lookup path\n"));
}

/*
 * Copy a string from source to destination, escaping space
 * with a backslash and escaping the escape character as well.
 */
int
add_escape(char *src, char *dest, int limit)
{
	char *sp, *dp;
	int destlen = 0;

	sp = src;
	dp = dest;

	while (*sp && destlen < limit) {
		if (*sp == '\\') {
			*dp++ = '\\';
			*dp++ = '\\';
			destlen++;
		} else if (*sp == ' ') {
			*dp++ = '\\';
			*dp++ = ' ';
			destlen++;
		} else
			*dp++ = *sp;
		destlen++;
		sp++;
	}
	if (limit <= 0)
		return (-1);
	return (destlen);
}

int
addref(char *sl_path, char *svc_type, int optind, int argc, char *argv[])
{
	int err, fd, i, len, oldlen, notfound = 0;
	char *text, *location;
	nvlist_t *nvl = NULL;
	char buf[SYMLINK_MAX];
	struct stat sbuf;

	/* Get an nvlist */
	nvl = reparse_init();
	if (nvl == NULL)
		return (ENOMEM);

	/* Get the reparse point data, if the RP exists */
	err = readlink(sl_path, buf, SYMLINK_MAX);
	if (err == -1) {
		if (errno == ENOENT) {
			notfound = 1;
			err = 0;
		} else {
			reparse_free(nvl);
			return (errno);
		}
	} else {
		buf[err] = '\0';
	}

	/* Get any data into nvlist */
	if (notfound == 0)
		err = reparse_parse(buf, nvl);
	if (err != 0) {
		reparse_free(nvl);
		return (err);
	}

	/*
	 * Accumulate multiple locations on the command line into 'buf'
	 */
	oldlen = len = 0;
	location = NULL;
	for (i = optind; i < argc; i++) {
		bzero(buf, sizeof (buf));
		len += add_escape(argv[i], buf, SYMLINK_MAX) + 2;
		location = realloc(location, len);
		location[oldlen] = '\0';
		oldlen = len;
		strlcat(location, buf, len);
		strlcat(location, " ", len);
	}
	location[len - 2] = '\0';

	/* Add to the list */
	err = reparse_add(nvl, svc_type, location);
	if (err) {
		reparse_free(nvl);
		return (err);
	}

	/* Get the new or modified symlink contents */
	err = reparse_unparse(nvl, &text);
	reparse_free(nvl);
	if (err)
		return (err);

	/* Delete first if found */
	if (notfound == 0) {
		err =  reparse_delete(sl_path);
		if (err) {
			free(text);
			return (err);
		}
	}

	/* Finally, write out the reparse point */
	err = reparse_create(sl_path, text);
	free(text);
	if (err)
		return (err);

	err = lstat(sl_path, &sbuf);
	if (err == 0 && strcasecmp(sbuf.st_fstype, "ZFS") != 0)
		printf(gettext(
		    "Warning: referrals do not work on this filesystem\n"));

	if (notfound)
		printf(gettext("Created reparse point %s\n"), sl_path);
	else
		printf(gettext("Added to reparse point %s\n"), sl_path);

	return (0);
}

int
delref(char *sl_path, char *svc_type)
{
	char *cp;
	char *svc_data;
	int err;
	nvlist_t *nvl;
	nvpair_t *curr;
	char buf[SYMLINK_MAX];
	int fd, fd2;
	FILE *fp, *fp2;
	char uuid[UUID_PRINTABLE_STRING_LENGTH], path[256], loc[2048];

	/* Get an nvlist */
	if (!(nvl = reparse_init()))
		return (ENOMEM);

	/* Get the symlink data (should be there) */
	err = readlink(sl_path, buf, SYMLINK_MAX);
	if (err == -1) {
		reparse_free(nvl);
		return (errno);
	}
	buf[err] = '\0';

	/* Get the records into the nvlist */
	err = reparse_parse(buf, nvl);
	if (err) {
		reparse_free(nvl);
		return (err);
	}

	/* Remove from nvlist */
	err = reparse_remove(nvl, svc_type);
	if (err) {
		reparse_free(nvl);
		return (err);
	}

	/* Any list entries left? If so, turn nvlist back to string. */
	curr = nvlist_next_nvpair(nvl, NULL);
	if (curr != NULL) {
		err = reparse_unparse(nvl, &cp);
		reparse_free(nvl);
		if (err)
			return (err);
	} else {
		reparse_free(nvl);
		cp = NULL;
	}

	/* Finally, delete and perhaps recreate the reparse point */
	err = reparse_delete(sl_path);
	if (err) {
		free(cp);
		return (err);
	}

	if (cp != NULL) {
		err = reparse_create(sl_path, cp);
		free(cp);
		if (err)
			return (err);
	}
	printf(gettext("Removed svc_type '%s' from %s\n"), svc_type, sl_path);
	return (err);
}

int
lookup(char *sl_path, char *svc_type, int type_set)
{
	int err;
	size_t bufsize;
	char buf[1024];
	char *type, *svc_data;
	nvlist_t *nvl;
	nvpair_t *curr;
	fs_locations4 fsl;
	XDR xdr;

	if (!(nvl = reparse_init()))
		return (-1);

	/* Get reparse point data */
	err = readlink(sl_path, buf, SYMLINK_MAX);
	if (err == -1)
		return (errno);
	buf[err] = '\0';

	/* Parse it to an nvlist */
	err = reparse_parse(buf, nvl);
	if (err) {
		reparse_free(nvl);
		return (err);
	}

	/* Look for entries of the requested service type */
	curr = NULL;
	while ((curr = nvlist_next_nvpair(nvl, curr)) != NULL) {
		type = nvpair_name(curr);
		if (type_set && strcasecmp(type, svc_type) == 0)
			break;
		if (!type_set && strncasecmp(type, "nfs", 3) == 0)
			break;
	}
	if (curr == NULL) {
		reparse_free(nvl);
		return (ENOENT);
	}

	/* Get the service data and look it up */
	nvpair_value_string(curr, &svc_data);

	bufsize = sizeof (buf);
	err = reparse_deref(type, svc_data, buf, &bufsize);
	reparse_free(nvl);
	if (err)
		return (err);

	xdrmem_create(&xdr, buf, bufsize, XDR_DECODE);
	err = xdr_fs_locations4(&xdr, &fsl);
	XDR_DESTROY(&xdr);
	if (err != TRUE)
		return (ENOENT);
	printf(gettext("%s points to: "), sl_path);
	print_referral_summary(&fsl);
	return (0);
}

extern char *optarg;
extern int optind, optopt;

int
main(int argc, char *argv[])
{
	char *command, *sl_path, *svc_type;
	int c, type_set, err;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	svc_type = "nfs-basic";		/* Default from SMF some day */
	type_set = 0;			/* Lookup any nfs type */

	/* Look for options (just the service type now) */
	while ((c = getopt(argc, argv, "t:")) != -1) {
		switch (c) {
		case 't':
			svc_type = optarg;
			type_set = 1;
			break;

		default:
			usage();
			exit(1);
		}
	}

	/* Make sure there's at least a command and one argument */
	if (optind + 1 >= argc) {
		usage();
		exit(1);
	}

	err = rp_plugin_init();
	switch (err) {
	case RP_OK:
		break;
	case RP_NO_PLUGIN_DIR:
		fprintf(stderr,
		    gettext("Warning: no plugin directory, continuing...\n"));
		break;
	case RP_NO_PLUGIN:
		fprintf(stderr,
		    gettext("Warning: no plugin found, continuing...\n"));
		break;
	case RP_NO_MEMORY:
		fprintf(stderr,
		    gettext("rp_plugin_init failed, no memory\n"));
		exit(0);
	default:
		fprintf(stderr,
		    gettext("rp_plugin_init failed, error %d\n"), err);
		exit(0);
	}

	command = argv[optind++];
	sl_path = argv[optind++];

	if (strcmp(command, "add") == 0) {

		if (optind >= argc) {
			usage();
			exit(1);
		}

		err = addref(sl_path, svc_type, optind, argc, argv);

	} else if (strcmp(command, "remove") == 0) {

		err = delref(sl_path, svc_type);

	} else if (strcmp(command, "lookup") == 0) {

		err = lookup(sl_path, svc_type, type_set);

	} else {
		usage();
		exit(1);
	}
	if (err != 0)
		fprintf(stderr, gettext("Command %s failed: %s\n"), command,
		    strerror(err));
	return (err);
}
