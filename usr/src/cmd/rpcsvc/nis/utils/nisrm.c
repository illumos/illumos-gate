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
 * nisrm.c
 *
 * nis+ object removal utility
 */

#include <stdio.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>

extern nis_object nis_default_obj;

extern char *nisname_index();


void
usage()
{
	fprintf(stderr, "usage: nisrm [-if] name ...\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int		c;
	char 		ask_remove = 0, force_remove = 0;
	ulong_t		expand;
	char 		*name;
	int		error = 0;
	int		bad_name;
	nis_result 	*res, *rres;
	nis_object 	*obj;
	char 		fname[NIS_MAXNAMELEN], buf[BUFSIZ];

	while ((c = getopt(argc, argv, "if")) != -1) {
		switch (c) {
		case 'i':
			ask_remove = 1;
			break;
		case 'f' :
			force_remove = 1;
			break;
		default :
			usage();
		}
	}

	if (optind == argc)
		usage();

	while (optind < argc) {
		name = argv[optind++];

		if (name[strlen(name)-1] != '.')
			expand = EXPAND_NAME;
		else
			expand = 0;

		/*
		 * Get the object to remove.
		 */
		res = nis_lookup(name, expand|MASTER_ONLY);
		if (res->status != NIS_SUCCESS) {
			if (!force_remove) {
				nis_perror(res->status, name);
				error = 1;
			}
			goto loop;
		}

		bad_name = (snprintf(fname, sizeof (fname), "%s.",
			res->objects.objects_val[0].zo_name)
				>= sizeof (fname));
		if (!bad_name &&
		    *(res->objects.objects_val[0].zo_domain) != '.')
			bad_name = (strlcat(fname,
				res->objects.objects_val[0].zo_domain,
				sizeof (fname)) >= sizeof (fname));

		if (bad_name) {
			if (!force_remove) {
				nis_perror(NIS_BADNAME, name);
				error = 1;
			}
			goto loop;
		}

		if (res->objects.objects_val[0].zo_data.zo_type ==
				NIS_DIRECTORY_OBJ) {
			if (!force_remove) {
				fprintf(stderr, "\"%s\" is a directory!\n",
				    fname);
				error = 1;
			}
			goto loop;
		}

		if (ask_remove || expand) {
			printf("remove %s? ", fname);
			*buf = '\0';
			(void) fgets(buf, sizeof (buf), stdin);
			if (tolower(*buf) != 'y')
				goto loop;
		}

		obj = res->objects.objects_val;
		rres = nis_remove(fname, obj);
		if ((rres->status == NIS_PERMISSION) && force_remove) {
			obj->zo_access |= 0x08080808;
			nis_freeresult(rres);
			rres = nis_modify(fname, obj);
			if (rres->status == NIS_SUCCESS) {
				nis_freeresult(rres);
				rres = nis_remove(fname, NULL);
			}
		}
		if (rres->status != NIS_SUCCESS) {
			if (!force_remove) {
				nis_perror(rres->status, name);
				error = 1;
			}
		}
		nis_freeresult(rres);

	loop:
		nis_freeresult(res);
	}

	return (error);
}
