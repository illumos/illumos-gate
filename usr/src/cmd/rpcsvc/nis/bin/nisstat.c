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
 *	nisstat.c
 *
 * This program will print out the various statistics being maintained by
 * the NIS+ server.
 */

#include <stdio.h>
#include <rpcsvc/nis.h>
#include <string.h>

static struct statlist {
	int	stat_type;
	char	*stat_name;
	char	stat_data[80];
} statlist[] = {
	{ TAG_ROOTSERVER, "root server", },
	{ TAG_NISCOMPAT, "NIS compat mode", },
	{ TAG_DNSFORWARDING, "DNS forwarding in NIS mode", },
	{ TAG_SECURITY_LEVEL, "security level", },
	{ TAG_DIRLIST,	"serves directories", },
	{ TAG_OPSTATS, "Operation Statistics", },
	{ TAG_S_DCACHE, "directory cache", },
	{ TAG_S_GCACHE, "group cache", },
	{ TAG_S_STORAGE, "static storage", },
	{ TAG_HEAP,	"dynamic storage", },
	{ TAG_UPTIME,    "up since", },
	{ 0, NULL, }};

extern int optind;
extern char *optarg;

static void
usage(s)
	char	*s;
{
	fprintf(stderr, "usage: %s [-H host] [directory]\n", s);
	exit(1);
}

/*
 * Print all the names of the directories served by this server
 * This list comes in a space separated buffer.
 */
static void
print_list_dir(header, dirlist)
	char	*header;
	char	*dirlist;
{
	char	*t, *tmp;

	tmp = strdup(dirlist);
	if (tmp == NULL) {
		fprintf(stderr, "No memory!\n");
		exit(1);
	}

	printf("Stat '%s':\n", header);
	/* we will print the list in the reverse order */
	while (t = strrchr(tmp, ' ')) {
		*t = NULL;
		printf("\t%s\n", t + sizeof (char));
	}
	printf("\t%s\n", tmp);
}

/*
 * Print all statistical information on this server.
 * This list comes in a "\n" separated buffer.
 */
static void
print_stats(header, statlist)
	char	*header;
	char	*statlist;
{
	char	*t, *tmp;
	bool_t	first = TRUE;

	tmp = strdup(statlist);
	if (tmp == NULL) {
		fprintf(stderr, "No memory!\n");
		exit(1);
	}

	printf("Stat '%s':\n", header);
	while (t = strchr(tmp, '\n')) {
		*t = NULL;
		if (first) {
			first = FALSE;
			if ((tmp[0] == NULL) || (strcmp(tmp, "stats:") == 0)) {
				/* dont print this */
				tmp = t + sizeof (char);
				continue;
			}
		}
		printf("\t%s\n", tmp);
		tmp = t + sizeof (char);
	}
	if (tmp && tmp[0])
		printf("\t%s\n", tmp);
}

static
int
match_host(char *host, char *target)
{
	int len = strlen(host);

	if (strncasecmp(host, target, len) == 0 &&
	    (target[len] == '.' || target[len] == '\0'))
		return (1);

	return (0);
}

int
main(int argc, char *argv[])
{
	nis_server	*servers;
	nis_error	status;
	nis_tag		tags[50], *res;
	int		j, i, maxtag, ns, c;
	nis_name	domain;
	char		dname[1024], *host = NULL;
	nis_result	*lres;
	nis_object	*obj;
	bool_t		print_once = FALSE;
	bool_t		nis_compat;

	while ((c = getopt(argc, argv, "H:")) != -1) {
		switch (c) {
			case 'H' :
				host = optarg;
				break;
			default :
				usage(argv[0]);
				break;
		}
	}
	if (argc - optind)
		domain = argv[optind];
	else
		domain = nis_local_directory();

	/* expand the name if not fully qualified */
	if (domain[strlen(domain) - 1] != '.')
		lres = nis_lookup(domain, EXPAND_NAME);
	else
		lres = nis_lookup(domain, 0);

	if (lres->status != NIS_SUCCESS) {
		fprintf(stderr, "\"%s\": %s\n",
		    domain, nis_sperrno(lres->status));
		exit(1);
	}
	obj = lres->objects.objects_val;
	sprintf(dname, "%s.%s", obj->zo_name, obj->zo_domain);
	if (__type_of(obj) != NIS_DIRECTORY_OBJ) {
		fprintf(stderr, "\"%s\": Not a directory.\n", dname);
		exit(1);
	}
	ns = obj->DI_data.do_servers.do_servers_len;
	servers = obj->DI_data.do_servers.do_servers_val;

	printf("Statistics for domain \"%s\" :\n\n", dname);
	memset(tags, 0, sizeof (nis_tag) * 50);
	for (i = 0; i < 50 && statlist[i].stat_type; i++) {
		tags[i].tag_type = statlist[i].stat_type;
		tags[i].tag_val = statlist[i].stat_data;
		if (tags[i].tag_type == TAG_OPSTATS)
			strcpy(tags[i].tag_val, "all");
	}
	maxtag = i;

	for (i = 0; i < ns; i++) {
		if (host && !match_host(host, servers[i].name))
			continue;
		if (print_once)
			printf("\n");
		else
			print_once = TRUE;
		status = nis_stats(&servers[i], tags, maxtag, &res);
		if (status != NIS_SUCCESS) {
			fprintf(stderr,
			    "nisstat: Error talking to host \"%s\": %s\n",
				servers[i].name, nis_sperrno(status));
			continue;
		}
		printf("Statistics from server : \"%s\"\n", servers[i].name);
		nis_compat = FALSE;
		for (j = 0; j < maxtag; j++) {
			if (strcmp(res[j].tag_val, "<Unknown Statistic>") == 0)
				/* Dont print this one */
				continue;
			switch (statlist[j].stat_type) {
			    case TAG_OPSTATS:
				print_stats(statlist[j].stat_name,
						res[j].tag_val);
				break;
			    case TAG_DIRLIST:
				print_list_dir(statlist[j].stat_name,
						res[j].tag_val);
				break;
			    case TAG_NISCOMPAT:
				if (strcmp(res[j].tag_val, "OFF") != 0)
					nis_compat = TRUE;
				printf("Stat '%s' = '%s'\n",
					statlist[j].stat_name, res[j].tag_val);
				break;
			    case TAG_DNSFORWARDING:
				/*
				 * Assume that the TAG_NISCOMPAT
				 * answer comes first
				 */
				if (nis_compat == FALSE)
					break;	/* Dont print this answer */
				/* else fall through */
			    default:
				printf("Stat '%s' = '%s'\n",
					statlist[j].stat_name, res[j].tag_val);
				break;
			}
		}
	}
	nis_freeresult(lres);
	return (0);
}
