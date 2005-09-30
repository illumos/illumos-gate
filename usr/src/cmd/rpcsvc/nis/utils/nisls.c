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

/*
 * nisls.c
 *
 * Simple "ls" utility for nis directories.
 */

#include <stdio.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <stdlib.h>
#include <strings.h>

extern nis_result * __nis_list_localcb(nis_name, uint_t,
    int (*)(nis_name, nis_object *, void *), void *);


static char **nl = 0;
static int nlsize = 1024, nllen = 0;

static void
nlpush(name)
	char *name;
{
	if (nl == 0)
		nl = (char **)malloc(nlsize * sizeof (char *));
	if (nllen == nlsize) {
		nlsize += 1024;
		nl = (char **)realloc(nl, nlsize * sizeof (char *));
	}
	nl[nllen++] = name;
}

static char *
nlpop()
{
	if (nllen == 0)
		return (0);
	return (nl[--nllen]);
}


#define	F_LONG 1
#define	F_RECURSE 2
#define	F_MTIME 4
#define	F_GROUP 8
#define	F_DIR 16

static int flags = 0;

static int
ls_obj(tab, ent, udata)
	char		*tab;
	nis_object	*ent;
	void		*udata;
{
	zotypes	et;
	char fname[NIS_MAXNAMELEN];
	char *tms;

	if (udata)
		et = *(long *)(udata);
	else
		et = ntohl(*(long *)(ent->
			EN_data.en_cols.en_cols_val[0].ec_value.ec_value_val));

	(void) snprintf(fname, sizeof (fname), "%s.", ent->zo_name);
	if (*(ent->zo_domain) != '.')
		(void) strlcat(fname, ent->zo_domain, sizeof (fname));

	if ((flags & F_RECURSE) && (et == NIS_DIRECTORY_OBJ) &&
			!(flags & F_DIR))
		nlpush(strdup(fname));

	if (flags & F_LONG) {
		switch (et) {
		case NIS_BOGUS_OBJ:
			printf("* ");
			break;
		case NIS_DIRECTORY_OBJ:
			printf("D ");
			break;
		case NIS_GROUP_OBJ:
			printf("G ");
			break;
		case NIS_TABLE_OBJ:
			printf("T ");
			break;
		case NIS_ENTRY_OBJ:
			printf("E ");
			break;
		case NIS_LINK_OBJ:
			printf("L ");
			break;
		case NIS_PRIVATE_OBJ:
			printf("P ");
			break;
		default:
			printf("%d ", et);
			break;
		}
		nis_print_rights(ent->zo_access);
		if (flags & F_GROUP)
			printf(" %s ", ent->zo_group);
		else
			printf(" %s ", ent->zo_owner);
		if (flags & F_MTIME)
			tms = ctime((time_t *)&(ent->zo_oid.mtime));
		else
			tms = ctime((time_t *)&(ent->zo_oid.ctime));
		*(tms+strlen(tms)-1) = '\0';
		printf("%s ", tms);
	}

	printf("%s\n", (tab)?ent->zo_name:fname);

	return (0);
}


static void
usage()
{
	printf("usage: nisls [-LMlmgdR] [name ...]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int c;
	ulong_t flinks = 0, master = 0;
	nis_name *result;
	char *name;
	nis_result *res, *lres;
	char fname[NIS_MAXNAMELEN];
	int error = 0;

	while ((c = getopt(argc, argv, "LMlmgdR")) != -1)
		switch (c) {
		case 'L':
			flinks = FOLLOW_LINKS;
			break;
		case 'M':
			master = MASTER_ONLY;
			break;
		case 'l':
			flags |= F_LONG;
			break;
		case 'm':
			flags |= F_MTIME;
			break;
		case 'g':
			flags |= F_GROUP;
			break;
		case 'd':
			flags |= F_DIR;
			break;
		case 'R':
			flags |= F_RECURSE;
			break;
		default:
			usage();
		}

	/*
	 * push all of the names to ls onto a stack (in reverse order)
	 */
	if (argc - optind == 0) {
		result = nis_getnames("foo");
		nlpush(nis_domain_of(*result));
	} else while (argc - optind > 0)
		nlpush(argv[--argc]);

	/*
	 * keep popping names off the stack and ls'ing them.  if we're
	 * recursive, then subdirectories will get pushed on in ls_obj.
	 */
	while (name = nlpop()) {
		res = nis_lookup(name, flinks|master|EXPAND_NAME);
		/*
		 * Hack to get around non replicated root object bug.
		 */
		if (res->status == NIS_NOT_ME) {
			printf("%s:\n", name);

			lres = __nis_list_localcb(name, EXPAND_NAME|master,
								ls_obj, 0);
			if ((lres->status != NIS_CBRESULTS) &&
			    (lres->status != NIS_NOTFOUND)) {
				nis_perror(lres->status,
						"can't list directory");
				error = 1;
			}
			nis_freeresult(lres);

			if (nllen)
				printf("\n");
			goto loop;

		} else if (res->status != NIS_SUCCESS) {
			nis_perror(res->status, name);
			error = 1;
			goto loop;
		}

		if ((res->objects.objects_val[0].zo_data.zo_type !=
				NIS_DIRECTORY_OBJ) || (flags & F_DIR)) {
			ls_obj(0, res->objects.objects_val,
			    &(res->objects.objects_val[0].zo_data.zo_type));
			goto loop;
		}

		(void) snprintf(fname, sizeof (fname), "%s.",
			res->objects.objects_val[0].zo_name);
		if (*(res->objects.objects_val[0].zo_domain) != '.')
			(void) strlcat(fname,
				res->objects.objects_val[0].zo_domain,
				sizeof (fname));

		printf("%s:\n", fname);

		lres = __nis_list_localcb(fname, master, ls_obj, 0);
		if ((lres->status != NIS_CBRESULTS) &&
		    (lres->status != NIS_NOTFOUND)) {
			nis_perror(lres->status, "can't list directory");
			error = 1;
		}
		nis_freeresult(lres);

		if (nllen)
			printf("\n");

	loop:
		nis_freeresult(res);
	}

	return (error);
}
