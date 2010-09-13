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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <limits.h>
#include <libnvpair.h>
#include <dlfcn.h>
#include <link.h>
#include <rp_plugin.h>
#include <fcntl.h>
#include <uuid/uuid.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include <sys/param.h>
#include <nfs/nfs4.h>
#include <rpcsvc/nfs4_prot.h>
#include "ref_subr.h"

extern int errno;

#define	SERVICE_TYPE	"nfs-basic"

char *nfs_basic_service_type(void);
boolean_t nfs_basic_supports_svc(const char *);
int nfs_basic_deref(const char *, const char *, char *, size_t *);
int nfs_basic_form(const char *, const char *, char *, size_t *);

struct rp_plugin_ops rp_plugin_ops = {
	RP_PLUGIN_V1,
	NULL,			/* rpo_init */
	NULL,			/* rpo_fini */
	nfs_basic_service_type,
	nfs_basic_supports_svc,
	nfs_basic_form,
	nfs_basic_deref
};

/*
 * What service type does this module support?
 */
char *
nfs_basic_service_type()
{
	return (SERVICE_TYPE);
}

/*
 * Does this module support a particular service type?
 */
boolean_t
nfs_basic_supports_svc(const char *svc_type)
{
	if (!svc_type)
		return (0);
	return (!strncasecmp(svc_type, SERVICE_TYPE, strlen(SERVICE_TYPE)));
}

/*
 * Take a string with a set of locations like this:
 *   host1:/path1 host2:/path2 host3:/path3
 * and convert it to an fs_locations4 for the deref routine.
 */
static fs_locations4 *
get_fs_locations(char *buf)
{
	fs_locations4 *result = NULL;
	fs_location4 *fsl_array;
	int i, gothost;
	int fsl_count = 0, escape = 0, delimiter = 0;
	int len;
	char *p, *sp, *dp, buf2[SYMLINK_MAX];

	if (buf == NULL)
		return (NULL);
#ifdef DEBUG
	printf("get_fs_locations: input %s\n", buf);
#endif
	/*
	 * Count fs_location entries by counting spaces.
	 * Remember that escaped spaces ("\ ") may exist.
	 * We mark the location boundaries with null bytes.
	 * Variable use:
	 *   escape -   set if we have found a backspace,
	 *		part of either "\ " or "\\"
	 *   delimiter - set if we have found a space and
	 *		 used to skip multiple spaces
	 */
	for (sp = buf; sp && *sp; sp++) {
		if (*sp == '\\') {
			escape = 1;
			delimiter = 0;
			continue;
		}
		if (*sp == ' ') {
			if (delimiter == 1)
				continue;
			if (escape == 0) {
				delimiter = 1;
				fsl_count++;
				*sp = '\0';
			} else
				escape = 0;
		} else
			delimiter = 0;
	}
	len = sp - buf;
	sp--;
	if (escape == 0 && *sp != '\0')
		fsl_count++;
#ifdef DEBUG
	printf("get_fs_locations: fsl_count %d\n", fsl_count);
#endif
	if (fsl_count == 0)
		goto out;

	/* Alloc space for everything */
	result = calloc(1, sizeof (fs_locations4));
	if (result == NULL)
		goto out;
	fsl_array = calloc(fsl_count, sizeof (fs_location4));
	if (fsl_array == NULL) {
		free(result);
		result = NULL;
		goto out;
	}
	result->locations.locations_len = fsl_count;
	result->locations.locations_val = fsl_array;
	result->fs_root.pathname4_len = 0;
	result->fs_root.pathname4_val = NULL;

	/*
	 * Copy input, removing escapes from host:/path/to/my\ files
	 */
	sp = buf;
	dp = buf2;
	bzero(buf2, sizeof (buf2));

	i = gothost = 0;
	while ((sp && *sp && (sp - buf < len)) || gothost) {

		if (!gothost) {
			/* Drop leading spaces */
			if (*sp == ' ') {
				sp++;
				continue;
			}

			/* Look for the rightmost colon for host */
			p = strrchr(sp, ':');
			if (!p) {
#ifdef DEBUG
				printf("get_fs_locations: skipping %s\n", sp);
#endif
				fsl_count--;
				sp += strlen(sp) + 1;
			} else {
				bcopy(sp, dp, p - sp);
				sp = p + 1;
#ifdef DEBUG
				printf("get_fs_locations: host %s\n", buf2);
#endif
				fsl_array[i].server.server_len = 1;
				fsl_array[i].server.server_val =
				    malloc(sizeof (utf8string));
				if (fsl_array[i].server.server_val == NULL) {
					int j;

					free(result);
					result = NULL;
					for (j = 0; j < i; j++)
						free(fsl_array[j].
						    server.server_val);
					free(fsl_array);
					goto out;
				}
				str_to_utf8(buf2,
				    fsl_array[i].server.server_val);
				gothost = 1;
				dp = buf2;
				bzero(buf2, sizeof (buf2));
			}
			continue;
		}

		/* End of string should mean a pathname */
		if (*sp == '\0' && gothost) {
#ifdef DEBUG
			printf("get_fs_locations: path %s\n", buf2);
#endif
			(void) make_pathname4(buf2, &fsl_array[i].rootpath);
			i++;
			gothost = 0;
			dp = buf2;
			bzero(buf2, sizeof (buf2));
			if (sp - buf < len)
				sp++;
			continue;
		}

		/* Skip a single escape character */
		if (*sp == '\\')
			sp++;

		/* Plain char, just copy it */
		*dp++ = *sp++;
	}

	/*
	 * If we're still expecting a path name, we don't have a
	 * server:/path pair and should discard the server and
	 * note that we got fewer locations than expected.
	 */
	if (gothost) {
		fsl_count--;
		free(fsl_array[i].server.server_val);
		fsl_array[i].server.server_val = NULL;
		fsl_array[i].server.server_len = 0;
	}

	/*
	 * If we have zero entries, we never got a whole server:/path
	 * pair, and so cannot have anything else allocated.
	 */
	if (fsl_count <= 0) {
		free(result);
		free(fsl_array);
		return (NULL);
	}

	/*
	 * Make sure we reflect the right number of locations.
	 */
	if (fsl_count < result->locations.locations_len)
		result->locations.locations_len = fsl_count;

out:
	return (result);
}

/*
 * Deref function for nfs-basic service type returns an fs_locations4.
 */
int
nfs_basic_deref(const char *svc_type, const char *svc_data, char *buf,
    size_t *bufsz)
{
	int slen, err;
	fs_locations4 *fsl;
	XDR xdr;

	if ((!svc_type) || (!svc_data) || (!buf) || (!bufsz) || (*bufsz == 0))
		return (EINVAL);

	if (strcasecmp(svc_type, SERVICE_TYPE))
		return (ENOTSUP);

	fsl = get_fs_locations((char *)svc_data);
	if (fsl == NULL)
		return (ENOENT);
#ifdef DEBUG
	printf("nfs_basic_deref: past get_fs_locations()\n");
#endif
	slen = xdr_sizeof(xdr_fs_locations4, (void *)fsl);
	if (slen > *bufsz) {
		*bufsz = slen;
		xdr_free(xdr_fs_locations4, (char *)fsl);
		return (EOVERFLOW);
	}
#ifdef DEBUG
	printf("nfs_basic_deref: past buffer check\n");
	print_referral_summary(fsl);
#endif
	xdrmem_create(&xdr, buf, *bufsz, XDR_ENCODE);
	err = xdr_fs_locations4(&xdr, fsl);
	XDR_DESTROY(&xdr);
	xdr_free(xdr_fs_locations4, (char *)fsl);
	if (err != TRUE)
		return (EINVAL);
	*bufsz = slen;
#ifdef DEBUG
	printf("nfs_basic_deref: past xdr_fs_locations4() and done\n");
#endif
	return (0);
}

/*
 * Form function for nfs-basic service type.
 */
int
nfs_basic_form(const char *svc_type, const char *svc_data, char *buf,
    size_t *bufsz)
{
	int slen;

	if ((!svc_type) || (!svc_data) || (!buf) || (*bufsz == 0))
		return (EINVAL);

	if (strcmp(svc_type, SERVICE_TYPE))
		return (ENOTSUP);

	slen = strlen(svc_data) + 1;
	if (slen > *bufsz) {
		*bufsz = slen;
		return (EOVERFLOW);
	}
	*bufsz = slen;
	strncpy(buf, svc_data, slen);
	return (0);
}
