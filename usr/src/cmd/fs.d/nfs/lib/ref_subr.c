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

/*
 * str_to_utf8 - converts a null-terminated C string to a utf8 string
 */
utf8string *
str_to_utf8(char *nm, utf8string *str)
{
	int len;

	if (str == NULL)
		return (NULL);

	if (nm == NULL || *nm == '\0') {
		str->utf8string_len = 0;
		str->utf8string_val = NULL;
		return (NULL);
	}

	len = strlen(nm);

	str->utf8string_val = malloc(len);
	if (str->utf8string_val == NULL) {
		str->utf8string_len = 0;
		return (NULL);
	}
	str->utf8string_len = len;
	bcopy(nm, str->utf8string_val, len);

	return (str);
}

/*
 * Converts a utf8 string to a C string.
 * kmem_allocs a new string if not supplied
 */
char *
utf8_to_str(utf8string *str, uint_t *lenp, char *s)
{
	char	*sp;
	char	*u8p;
	int	len;
	int	 i;

	if (str == NULL)
		return (NULL);

	u8p = str->utf8string_val;
	len = str->utf8string_len;
	if (len <= 0 || u8p == NULL) {
		if (s)
			*s = '\0';
		return (NULL);
	}

	sp = s;
	if (sp == NULL)
		sp = malloc(len + 1);
	if (sp == NULL)
		return (NULL);

	/*
	 * At least check for embedded nulls
	 */
	for (i = 0; i < len; i++) {
		sp[i] = u8p[i];
		if (u8p[i] == '\0') {
			if (s == NULL)
				free(sp);
			return (NULL);
		}
	}
	sp[len] = '\0';
	*lenp = len + 1;

	return (sp);
}

void
print_referral_summary(fs_locations4 *fsl)
{
	int i, j;
	uint_t l;
	char *s;
	fs_location4 *fs;

	if (fsl == NULL) {
		printf("NULL\n");
		return;
	}

	for (i = 0; i < fsl->locations.locations_len; i++) {
		if (i > 0)
			printf("\n");
		fs = &fsl->locations.locations_val[i];
		for (j = 0; j < fs->server.server_len; j++) {
			s = utf8_to_str(&fs->server.server_val[j], &l, NULL);
			if (j > 0)
				printf(",");
			printf("%s", s ? s : "");
			if (s)
				free(s);
		}
		printf(":");
		for (j = 0; j < fs->rootpath.pathname4_len; j++) {
			s = utf8_to_str(&fs->rootpath.pathname4_val[j],
			    &l, NULL);
			printf("/%s", s ? s : "");
			if (s)
				free(s);
		}
		if (fs->rootpath.pathname4_len == 0)
			printf("/");
	}
	printf("\n");
}

/*
 * There is a kernel copy of this routine in nfs4_srv.c.
 * Changes should be kept in sync.
 */
static int
nfs4_create_components(char *path, component4 *comp4)
{
	int slen, plen, ncomp;
	char *ori_path, *nxtc, buf[MAXNAMELEN];

	if (path == NULL)
		return (0);

	plen = strlen(path) + 1;	/* include the terminator */
	ori_path = path;
	ncomp = 0;

	/* count number of components in the path */
	for (nxtc = path; nxtc < ori_path + plen; nxtc++) {
		if (*nxtc == '/' || *nxtc == '\0' || *nxtc == '\n') {
			if ((slen = nxtc - path) == 0) {
				path = nxtc + 1;
				continue;
			}

			if (comp4 != NULL) {
				bcopy(path, buf, slen);
				buf[slen] = '\0';
				if (str_to_utf8(buf, &comp4[ncomp]) == NULL)
					return (0);
			}

			ncomp++;	/* 1 valid component */
			path = nxtc + 1;
		}
		if (*nxtc == '\0' || *nxtc == '\n')
			break;
	}

	return (ncomp);
}

/*
 * There is a kernel copy of this routine in nfs4_srv.c.
 * Changes should be kept in sync.
 */
int
make_pathname4(char *path, pathname4 *pathname)
{
	int ncomp;
	component4 *comp4;

	if (pathname == NULL)
		return (0);

	if (path == NULL) {
		pathname->pathname4_val = NULL;
		pathname->pathname4_len = 0;
		return (0);
	}

	/* count number of components to alloc buffer */
	if ((ncomp = nfs4_create_components(path, NULL)) == 0) {
		pathname->pathname4_val = NULL;
		pathname->pathname4_len = 0;
		return (0);
	}
	comp4 = calloc(ncomp * sizeof (component4), 1);
	if (comp4 == NULL) {
		pathname->pathname4_val = NULL;
		pathname->pathname4_len = 0;
		return (0);
	}

	/* copy components into allocated buffer */
	ncomp = nfs4_create_components(path, comp4);

	pathname->pathname4_val = comp4;
	pathname->pathname4_len = ncomp;

	return (ncomp);
}

bool_t
xdr_component4(register XDR *xdrs, component4 *objp)
{

	if (!xdr_utf8string(xdrs, objp))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_utf8string(register XDR *xdrs, utf8string *objp)
{

	if (xdrs->x_op != XDR_FREE)
		return (xdr_bytes(xdrs, (char **)&objp->utf8string_val,
		    (uint_t *)&objp->utf8string_len, NFS4_MAX_UTF8STRING));
	return (TRUE);
}

bool_t
xdr_pathname4(register XDR *xdrs, pathname4 *objp)
{

	if (!xdr_array(xdrs, (char **)&objp->pathname4_val,
	    (uint_t *)&objp->pathname4_len, NFS4_MAX_PATHNAME4,
	    sizeof (component4), (xdrproc_t)xdr_component4))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_fs_location4(register XDR *xdrs, fs_location4 *objp)
{

	if (xdrs->x_op == XDR_DECODE) {
		objp->server.server_val = NULL;
		objp->rootpath.pathname4_val = NULL;
	}
	if (!xdr_array(xdrs, (char **)&objp->server.server_val,
	    (uint_t *)&objp->server.server_len, ~0,
	    sizeof (utf8string), (xdrproc_t)xdr_utf8string))
		return (FALSE);
	if (!xdr_pathname4(xdrs, &objp->rootpath))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_fs_locations4(register XDR *xdrs, fs_locations4 *objp)
{

	if (xdrs->x_op == XDR_DECODE) {
		objp->fs_root.pathname4_len = 0;
		objp->fs_root.pathname4_val = NULL;
		objp->locations.locations_val = NULL;
	}
	if (!xdr_pathname4(xdrs, &objp->fs_root))
		return (FALSE);
	if (!xdr_array(xdrs, (char **)&objp->locations.locations_val,
	    (uint_t *)&objp->locations.locations_len, ~0,
	    sizeof (fs_location4), (xdrproc_t)xdr_fs_location4))
		return (FALSE);
	return (TRUE);
}
