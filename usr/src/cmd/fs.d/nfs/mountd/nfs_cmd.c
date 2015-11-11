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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <rpc/rpc.h>
#include <netconfig.h>
#include <netdir.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <libtsnet.h>
#include <nfs/nfssys.h>
#include <nfs/export.h>
#include <nfs/nfs_cmd.h>
#include <door.h>
#include <syslog.h>
#include <locale.h>
#include <strings.h>
#include <sharefs/share.h>
#include <stdlib.h>
#include "../lib/sharetab.h"
#include "mountd.h"

/*
 * The following codesets must match what is in libshare_nfs.c until we can
 * request them from the kernel.
 */
char *charopts[] = {
	"euc-cn",
	"euc-jp",
	"euc-jpms",
	"euc-kr",
	"euc-tw",
	"iso8859-1",
	"iso8859-2",
	"iso8859-5",
	"iso8859-6",
	"iso8859-7",
	"iso8859-8",
	"iso8859-9",
	"iso8859-13",
	"iso8859-15",
	"koi8-r",
	NULL
};

/*
 * nfscmd_err(dp, args, err)
 * Return an error for the door call.
 */

static void
nfscmd_err(door_desc_t *dp, nfscmd_arg_t *args, int err)
{
	nfscmd_res_t res;

	res.version = NFSCMD_VERS_1;
	res.cmd = NFSCMD_ERROR;
	res.error = err;
	(void) door_return((char *)&res, sizeof (nfscmd_res_t), NULL, 0);
	(void) door_return(NULL, 0, NULL, 0);
	/* NOTREACHED */

}

/*
 * charmap_search(netbuf, opts)
 *
 * Check to see if the address in the netbuf is found in
 * a character map spec in the opts option string. Returns the charset
 * name if found.
 */

static char *
charmap_search(struct netbuf *nbuf, char *opts)
{
	char *copts;
	char *next;
	char *name;
	char *result = NULL;
	char *netid;
	struct sockaddr *sa;

	struct cln cln;

	sa = (struct sockaddr *)nbuf->buf;

	switch (sa->sa_family) {
	case AF_INET:
		netid = "tcp";
		break;
	case AF_INET6:
		netid = "tcp6";
		break;
	default:
		return (NULL);
	}

	copts = strdup(opts);
	if (copts == NULL)
		return (NULL);

	cln_init_lazy(&cln, netid, nbuf);

	next = copts;
	while (*next != '\0') {
		char *val;
		name = next;
		if (getsubopt(&next, charopts, &val) >= 0) {
			char *cp;
			/*
			 * name will have the whole opt and val the value. Set
			 * the '=' to '\0' and we have the charmap in name and
			 * the access list in val.
			 */
			cp = strchr(name, '=');
			if (cp != NULL)
				*cp = '\0';
			if (in_access_list(&cln, val) > 0) {
				result = name;
				break;
			}
		}
	}

	if (result != NULL)
		result = strdup(result);

	cln_fini(&cln);
	free(copts);

	return (result);
}

/*
 * nfscmd_charmap_lookup(door, args)
 *
 * Check to see if there is a translation requested for the path
 * specified in the request. If there is, return the charset name.
 */

static void
nfscmd_charmap_lookup(door_desc_t *dp, nfscmd_arg_t *args)
{
	nfscmd_res_t res;
	struct netbuf nb;
	struct sockaddr sa;
	struct share *sh = NULL;
	char *name;

	memset(&res, '\0', sizeof (res));
	res.version = NFSCMD_VERS_1;
	res.cmd = NFSCMD_CHARMAP_LOOKUP;

	sh = findentry(args->arg.charmap.path);

	if (sh != NULL) {
		nb.len = nb.maxlen = sizeof (struct sockaddr);
		nb.buf = (char *)&sa;

		sa = args->arg.charmap.addr;

		name = charmap_search(&nb, sh->sh_opts);
		if (name != NULL) {
			strcpy(res.result.charmap.codeset, name);
			res.result.charmap.apply = B_TRUE;
			res.error = NFSCMD_ERR_SUCCESS;
			free(name);
		} else {
			res.result.charmap.apply = B_FALSE;
			res.error = NFSCMD_ERR_NOTFOUND;
		}
		sharefree(sh);
	} else {
		res.error = NFSCMD_ERR_NOTFOUND;
	}

	(void) door_return((char *)&res, sizeof (nfscmd_res_t), NULL, 0);
	(void) door_return(NULL, 0, NULL, 0);
	/* NOTREACHED */
}

/*
 * nfscmd_ver_1(door, args, size)
 *
 * Version 1 of the door command processor for nfs cmds.
 */

static void
nfscmd_vers_1(door_desc_t *dp, nfscmd_arg_t *args, size_t size)
{
	switch (args->cmd) {
	case NFSCMD_CHARMAP_LOOKUP:
		nfscmd_charmap_lookup(dp, args);
		break;
	default:
		nfscmd_err(dp, args, NFSCMD_ERR_BADCMD);
		break;
	}
}

/*
 * nfscmd_func(cookie, dataptr, size, door, ndesc)
 *
 * The function called by the door thread for processing
 * nfscmd type commands.
 */

void
nfscmd_func(void *cookie, char *dataptr, size_t arg_size,
	door_desc_t *dp, uint_t n_desc)
{
	nfscmd_arg_t	*args;

	args = (nfscmd_arg_t *)dataptr;

	switch (args->version) {
	case NFSCMD_VERS_1:
		nfscmd_vers_1(dp, args, arg_size);
		break;
	default:
		syslog(LOG_ERR, gettext("Invalid nfscmd version"));
		break;
	}

	(void) door_return((caddr_t)args, sizeof (nfscmd_res_t), NULL, 0);
	(void) door_return(NULL, 0, NULL, 0);
	/* NOTREACHED */

}
