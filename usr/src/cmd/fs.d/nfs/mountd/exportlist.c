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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/time.h>
#include <errno.h>
#include <rpcsvc/mount.h>
#include <sys/pathconf.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>
#include <signal.h>
#include <locale.h>
#include <unistd.h>
#include <thread.h>
#include <sharefs/share.h>
#include <sharefs/sharetab.h>
#include "../lib/sharetab.h"
#include "mountd.h"

static void freeexports(struct exportnode *);
static struct groupnode **newgroup(char *, struct groupnode **);
static struct exportnode **newexport(char *, struct groupnode *,
						struct exportnode **);

static char *optlist[] = {
#define	OPT_RO		0
	SHOPT_RO,
#define	OPT_RW		1
	SHOPT_RW,
	NULL
};

/*
 * Send current export list to a client
 */
void
export(struct svc_req *rqstp)
{
	SVCXPRT *transp;
	struct exportnode *exportlist;
	struct exportnode **tail;
	struct groupnode *groups;
	struct groupnode **grtail;
	struct share *sh;
	struct sh_list *shp;
	char *gr, *p, *opts, *val, *lasts;

	int export_to_everyone;

	transp = rqstp->rq_xprt;
	if (!svc_getargs(transp, xdr_void, NULL)) {
		svcerr_decode(transp);
		return;
	}

	check_sharetab();

	exportlist = NULL;
	tail = &exportlist;

	(void) rw_rdlock(&sharetab_lock);

	for (shp = share_list; shp; shp = shp->shl_next) {

		groups = NULL;
		grtail = &groups;

		sh = shp->shl_sh;

		/*
		 * Check for "ro" or "rw" list without argument values.  This
		 * indicates export to everyone.  Unfortunately, SunOS 4.x
		 * automounter uses this, and it is indicated indirectly with
		 * 'showmount -e'.
		 *
		 * If export_to_everyone is 1, then groups should be NULL to
		 * indicate export to everyone.
		 */

		opts = strdup(sh->sh_opts);
		p = opts;


		export_to_everyone = 0;
		while (*p) {
			switch (getsubopt(&p, optlist, &val)) {
			case OPT_RO:
			case OPT_RW:
				if (val == NULL)
					export_to_everyone = 1;
				break;
			}
		}

		free(opts);

		if (export_to_everyone == 0) {

			opts = strdup(sh->sh_opts);
			p = opts;

			/*
			 * Just concatenate all the hostnames/groups
			 * from the "ro" and "rw" lists for each flavor.
			 * This list is rather meaningless now, but
			 * that's what the protocol demands.
			 */
			while (*p) {
				switch (getsubopt(&p, optlist, &val)) {
				case OPT_RO:
				case OPT_RW:

					while ((gr = strtok_r(val, ":", &lasts))
					    != NULL) {
						val = NULL;
						grtail = newgroup(gr, grtail);
					}
					break;
				}
			}

			free(opts);
		}
		tail = newexport(sh->sh_path, groups, tail);
	}

	(void) rw_unlock(&sharetab_lock);

	errno = 0;
	if (!svc_sendreply(transp, xdr_exports, (char *)&exportlist))
		log_cant_reply(transp);

	freeexports(exportlist);
}


static void
freeexports(struct exportnode *ex)
{
	struct groupnode *groups, *tmpgroups;
	struct exportnode *tmpex;

	while (ex) {
		groups = ex->ex_groups;
		while (groups) {
			tmpgroups = groups->gr_next;
			free(groups->gr_name);
			free(groups);
			groups = tmpgroups;
		}
		tmpex = ex->ex_next;
		free(ex->ex_dir);
		free(ex);
		ex = tmpex;
	}
}


static struct groupnode **
newgroup(char *grname, struct groupnode **tail)
{
	struct groupnode *new;
	char *newname;

	new = exmalloc(sizeof (*new));
	newname = exmalloc(strlen(grname) + 1);
	(void) strcpy(newname, grname);

	new->gr_name = newname;
	new->gr_next = NULL;
	*tail = new;
	return (&new->gr_next);
}


static struct exportnode **
newexport(char *grname, struct groupnode *grplist, struct exportnode **tail)
{
	struct exportnode *new;
	char *newname;

	new = exmalloc(sizeof (*new));
	newname = exmalloc(strlen(grname) + 1);
	(void) strcpy(newname, grname);

	new->ex_dir = newname;
	new->ex_groups = grplist;
	new->ex_next = NULL;
	*tail = new;
	return (&new->ex_next);
}
