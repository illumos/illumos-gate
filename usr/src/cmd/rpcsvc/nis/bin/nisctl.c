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
 * nisctl.c
 *
 * This program is used to control the operation of NIS+ servers.
 * It may be used to turn debugging on and off, and to flush
 * various caches and print statistics.
 */

#include <stdio.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>

extern int optind;
extern char *optarg;

nis_tag	mytags[64];

static void
usage(s)
	char	*s;
{
	fprintf(stderr,
"usage: %s [-M] [-s] [-v on|off] [-f dgot [-n obj_name]] [-H host] [domain]\n",
		s);
	fprintf(stderr, "\t-M: heap memory\n");
	fprintf(stderr, "\t-s: statistics\n");
	fprintf(stderr, "\t-v: verbose mode\n");
	fprintf(stderr,
	"\t-f: flush cache (dir, group, object, table) [-n obj_name]\n");
	fprintf(stderr, "At least one of the above options must be "
		"specified\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int		c;
	int		i;
	nis_error 	error;
	nis_tag		*res;
	nis_result	*lres;
	nis_object	*obj;
	nis_server	**srvs, **x;
	nis_name	domain;
	char		dname[1024], *s;
	char		server[NIS_MAXNAMELEN];

	server[0] = NULL;
	i = 0;

	/* nisctl cannot be used without any options */
	if (argc == 1) {
		usage(argv[0]);
		exit(1);
	}

	while ((c = getopt(argc, argv, "Msv:n:f:H:")) != -1) {
		switch (c) {
			case 'M' :
				mytags[0].tag_val = "";
				mytags[0].tag_type = TAG_HEAP;
				i = 1;
				break;
			case 'f' :
				for (s = optarg; *s; s++) {
					mytags[i].tag_val = "flush";
					switch (*s) {
					    case 'g':
						mytags[i].tag_type =
							TAG_GCACHE_ALL;
						break;
					    case 'd':
						mytags[i].tag_type =
							TAG_DCACHE_ALL;
						break;
					    case 'o':
						mytags[i].tag_type =
							TAG_OCACHE;
						break;
					    case 't':
						mytags[i].tag_type =
							TAG_TCACHE_ALL;
						break;
					    default:
						usage(argv[0]);
					}
					i++;
				}
				break;
			case 'n':
				/* specifies a particular entry to flush */
				if (i == 0) {
					fprintf(stderr, "-f option required\n");
					usage(argv[0]);
				}
				if (i > 1) {
					fprintf(stderr,
						"only one option allowed\n");
					usage(argv[0]);
				}
				i = 0;	/* kludge - reset it */
				mytags[i].tag_val = optarg;
				switch (mytags[i].tag_type) {
				    case TAG_GCACHE_ALL:
					mytags[i].tag_type = TAG_GCACHE_ONE;
					break;
				    case TAG_TCACHE_ALL:
					mytags[i].tag_type = TAG_TCACHE_ONE;
					break;
				    case TAG_DCACHE_ALL:
					mytags[i].tag_type = TAG_DCACHE_ONE;
					break;
				    case TAG_OCACHE:
					fprintf(stderr,
					"Object flushing not supported\n");
					usage(argv[0]);
				    default:
					usage(argv[0]);
				}
				i = 1;	/* reset it back */
				break;
			case 'v' :
				if (strcmp(optarg, "1") == 0)
					mytags[i].tag_val = "on";
				else if (strcmp(optarg, "0") == 0)
					mytags[i].tag_val = "off";
				else
					mytags[i].tag_val = optarg;
				mytags[i++].tag_type = TAG_DEBUG;
				break;
			case 's' :
				mytags[i].tag_val = optarg;
				mytags[i++].tag_type = TAG_STATS;
				break;
			case 'H' :
				if (!optarg)
					usage(argv[0]);
				if (optarg[strlen(optarg) -1] == '.')
					strcpy(server, optarg);
				else
					sprintf(server, "%s.%s", optarg,
						nis_local_directory());
				break;
			default :
				usage(argv[0]);
				exit(1);
		}
	}
	if (optind < argc)
		domain = argv[optind];
	else
		domain = nis_local_directory();

	lres = nis_lookup(domain, EXPAND_NAME);
	if (lres->status != NIS_SUCCESS) {
		fprintf(stderr, "\"%s\" : %s\n", domain,
		    nis_sperrno(lres->status));
		exit(1);
	}
	obj = lres->objects.objects_val;
	sprintf(dname, "%s.%s", obj->zo_name, obj->zo_domain);
	srvs = (nis_server **)nis_getservlist(dname);
	if (! srvs) {
		fprintf(stderr,
		    "Unable to get list of servers serving \"%s\"\n", dname);
		exit(1);
	}

	for (x = srvs; *x; x++) {
		if (server[0] && nis_dir_cmp(server, (*x)->name) != SAME_NAME)
			continue;
		printf("Setting State on : '%s'\n", (*x)->name);
		error = nis_servstate(*x, mytags, i, &res);
		if (error == NIS_SUCCESS) {
			if (res == NULL) {
				fprintf(stderr, "Set server state failed\n");
				nis_freeservlist(srvs);
				exit(1);
			}
			printf("%s\n", res->tag_val);
		} else {
			fprintf(stderr, "Set server state failed : %s\n",
				nis_sperrno(error));
			nis_freeservlist(srvs);
			exit(1);
		}
		nis_freetags(res, i);
	}
	nis_freeservlist(srvs);
	return (0);
}
