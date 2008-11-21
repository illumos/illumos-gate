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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * nisupdkeys.c
 *
 * This function will read the list of servers from a directory object,
 * update them with the proper public keys and write the directory object
 * back.
 *
 */

#include <stdio.h>
#include <netdb.h>
#include <netdir.h>
#include <netconfig.h>
#include <netinet/in.h>
#include <rpc/key_prot.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nis_dhext.h>
#include <string.h>
#include <stdlib.h>

extern int optind;
extern char *optarg;

extern char *inet_ntoa();
extern int gethostname(char *name, int namelen);
extern nis_server *__nis_host2nis_server_g();
extern void	__nis_netconfig2ep(struct netconfig *, endpoint *);

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


void
usage(cmd)
	char	*cmd;
{
	fprintf(stderr, "usage: %s [-C | -a] [-H host] [directory]\n", cmd);
	fprintf(stderr, "usage: %s -s [-C | -a] [-H host]\n", cmd);
	exit(1);
}

int
clearkeydata(h, ns, srvs)
	char		*h;	/* host to act on 	*/
	int		ns;	/* number of servers	*/
	nis_server	*srvs;	/* array of servers	*/
{
	int		i, is_modified;

	for (i = 0, is_modified = 0; i < ns; i++) {
		if (h && !match_host(h, srvs[i].name))
			continue;
		if (srvs[i].key_type != NIS_PK_NONE) {
			printf("\tClearing server %s's key\n", srvs[i].name);
			srvs[i].key_type = NIS_PK_NONE;
			srvs[i].pkey.n_bytes = 0;
			srvs[i].pkey.n_len = 0;
			is_modified++;
		} else {
			printf("\tNo keys exist for the server \"%s\"\n",
				srvs[i].name);
		}
	}
	return (is_modified);
}

void
copyserv(nis_server *dst, nis_server *src, int *mod)
{
	dst->key_type = src->key_type;
	dst->pkey.n_len = src->pkey.n_len;
	dst->pkey.n_bytes = src->pkey.n_bytes;
	*mod  = *mod + 1;
}


int
updkeydata(h, ns, srvs)
	char		*h;	/* host to act on 	*/
	int		ns;	/* number of servers	*/
	nis_server	*srvs;	/* array of servers	*/
{
	int		i, is_modified;
	char		netname[MAXNETNAMELEN];
	nis_server	*newserver;
	int		errcode;

	for (i = 0, is_modified = 0; i < ns; i++) {
		if (h && !match_host(h, srvs[i].name))
			continue;
		if (! host2netname(netname, srvs[i].name, NULL)) {
			fprintf(stderr, "\tERROR: No netname for \"%s\"\n",
				srvs[i].name);
			continue;
		}
#ifdef DEBUG
		printf("\tFetching Public key for server %s ...\n",
			srvs[i].name);
		printf("\tnetname = '%s'\n", netname);
#endif

		/*
		 * Basically let __nis_host2nis_server do the magic of
		 * determining what kind of nis_server should be
		 * storred in the directory object.  All we need to do
		 * is preserve endpoint (address) information and
		 * print out the appropriate message.
		 *
		 * The new publickey should come from the master so
		 * that a stale key is not returned from a replica.
		 * However there is currently no way of doing this so
		 * replicas should be sync'd with the master.
		 */

		if (!(newserver =
			__nis_host2nis_server_g(h, TRUE, FALSE,
								&errcode))) {
			nis_perror(errcode, "nisupdkeys");
			fprintf(stderr, "No changes were made.\n");
			exit(1);
		}

		if (strcmp(srvs[i].name, newserver->name) != 0)
			continue;

		switch (srvs[i].key_type) {
		case NIS_PK_NONE:
			switch (newserver->key_type) {
			case NIS_PK_NONE:
				break;
			case NIS_PK_DH:
				printf(
			"\tInstalling %s's public key in this object\n",
			srvs[i].name);
				copyserv(&srvs[i], newserver, &is_modified);
				break;
			case NIS_PK_DHEXT:
				printf(
			"\tInstalling %s's public key(s) in this object\n",
					srvs[i].name);
				copyserv(&srvs[i], newserver, &is_modified);
				break;
			default:
				fprintf(stderr,
					"\tERROR! Unknown server type.\n");
				continue;
			}
			break;
		case NIS_PK_DH:
			switch (newserver->key_type) {
			case NIS_PK_NONE:
				printf(
				"\tRemoving %s's public key in this object\n",
					srvs[i].name);
				copyserv(&srvs[i], newserver, &is_modified);
				break;
			case NIS_PK_DH:
				printf(
				"\tUpdating %s's public key in this object\n",
					srvs[i].name);
				copyserv(&srvs[i], newserver, &is_modified);
				break;
			case NIS_PK_DHEXT:
				printf(
			"\tUpdating %s's public key(s) in this object\n",
					srvs[i].name);
				copyserv(&srvs[i], newserver, &is_modified);
				break;
			default:
				fprintf(stderr,
					"\tERROR! Unknown server type.\n");
				continue;
			}
			break;
		case NIS_PK_DHEXT:
			switch (newserver->key_type) {
			case NIS_PK_NONE:
				printf(
				"\tRemoving %s's public key in this object\n",
					srvs[i].name);
				copyserv(&srvs[i], newserver, &is_modified);
				break;
			case NIS_PK_DH:
				printf(
			"\tInstalling %s's public key in this object\n",
					srvs[i].name);
				copyserv(&srvs[i], newserver, &is_modified);
				break;
			case NIS_PK_DHEXT:
				printf(
			"\tUpdating %s's public key(s) in this object\n",
					srvs[i].name);
				copyserv(&srvs[i], newserver, &is_modified);
				break;
			default:
				fprintf(stderr,
					"\tERROR! Unknown server type.\n");
				continue;
			}
		default:
			switch (newserver->key_type) {
			case NIS_PK_NONE:
				break;
			case NIS_PK_DH:
				printf(
			"\tInstalling %s's public key in this object\n",
			srvs[i].name);
				copyserv(&srvs[i], newserver, &is_modified);
				break;
			case NIS_PK_DHEXT:
				printf(
			"\tInstalling %s's public key(s) in this object\n",
					srvs[i].name);
				copyserv(&srvs[i], newserver, &is_modified);
				break;
			default:
				fprintf(stderr,
					"\tERROR! Unknown server type.\n");
				continue;
			}
		}

	}
	return (is_modified);
}

/*
 * updaddrdata()
 *
 * For each server in the list, update its address information to be
 * current. If h is non-null only update information for that host.
 */
int
updaddrdata(h, ns, srvs)
	char		*h;	/* host to act on 	*/
	int		ns;	/* number of servers	*/
	nis_server	*srvs;	/* array of servers	*/
{
	register int	i, j, k;
	endpoint	*eps;	/* endpoints	*/
	int		nep;	/* num of eps	*/

	struct netconfig	*nc;	/* netconfig structure	*/
	void			*nch;	/* netconfig structure handle	*/
	struct nd_hostserv	hs;	/* netconfig database hostserv */
	struct nd_addrlist	*addrs; /* netconfig database addr list	*/

	/* XXX only update TCP/IP addresses at present */
	for (i = 0; i < ns; i++) {
		if (h && !match_host(h, srvs[i].name))
			continue;
		eps = srvs[i].ep.ep_val;
		nep = srvs[i].ep.ep_len;

		for (j = 0; j < nep; j++) {
		    free(eps[j].uaddr);
		    free(eps[j].family);
		    free(eps[j].proto);
		}

		/* setup params for netdir_getbyname() */
		hs.h_host = srvs[i].name;
		hs.h_serv = "rpcbind";

		/* count how many server entries we need */
		j = 0, nch = setnetconfig();
		while (nc = getnetconfig(nch)) {
			if (strcmp(nc->nc_protofmly, NC_LOOPBACK) == 0)
				continue;
			if (!netdir_getbyname(nc, &hs, &addrs)) {
				j += addrs->n_cnt;
				netdir_free((char *)addrs, ND_ADDRLIST);
			}
		}
		endnetconfig(nch);

		if (j == 0) {
			fprintf(stderr,
			    "nisupdkeys: Can't get address information for "
			    "host \"%s\"\n",
				srvs[i].name);
			exit(1);
		}

		/* got server count and allocate space */
		srvs[i].ep.ep_len = nep = j;
		if (!(srvs[i].ep.ep_val = eps =
			(endpoint*)malloc(nep*sizeof (struct endpoint)))) {
				return (0);
		}

		/* fill in new server address info */
		j = 0, nch = setnetconfig();

		/* keep going if we still have more interfaces */
		while (nc = getnetconfig(nch)) {
		    if (strcmp(nc->nc_protofmly, NC_LOOPBACK) == 0)
			    continue;
		    if (!netdir_getbyname(nc, &hs, &addrs)) {
			for (k = 0; k < addrs->n_cnt; k++) {
			    eps[j].uaddr  =
				taddr2uaddr(nc, &(addrs->n_addrs[k]));
			    __nis_netconfig2ep(nc, &(eps[j]));
			    /* if any of these returned NULL, bail */
			    if (!(eps[j].uaddr && eps[j].family &&
				eps[j].proto)) {
				    netdir_free((char *)addrs, ND_ADDRLIST);
				    endnetconfig(nch);
				    return (0);
			    }
			    j++;
			}
			netdir_free((char *)addrs, ND_ADDRLIST);
		    }
		}
		endnetconfig(nch);	/* free(3C)'s NC data structs	*/

		if (j == 0) {
			fprintf(stderr,
			    "nisupdkeys: Can't get address information for "
			    "host \"%s\"\n",
				srvs[i].name);
			exit(1);
		}
	}
	return (1);
}

#define	UPD_KEYS	0
#define	CLR_KEYS	1
#define	UPD_ADDR	2

int
main(int argc, char *argv[])
{
	char		dname[NIS_MAXNAMELEN];
	char		*server = NULL;
	nis_server	*srvlist;
	char		*dirlist[NIS_MAXREPLICAS], **curdir;
	int		ns, is_modified;
	nis_object	*obj;
	nis_result	*res, *mres;
	int		c;
	int		op = UPD_KEYS;
	int		i = 0;
	bool_t		hostupdate = FALSE;
	char		*hostname;

	while ((c = getopt(argc, argv, "CsaH:")) != -1) {
		switch (c) {
			case 'C' :
				op = CLR_KEYS;
				break;
			case 'a' :
				op = UPD_ADDR;
				break;
			case 'H' :
				server = optarg;
				break;
			case 's' :
				hostupdate = TRUE;
				break;
			case '?' :
			default :
				fprintf(stderr, "Unrecognized option.\n");
				usage(argv[0]);
				break;
		}
	}

	if (server)
		hostname = server;
	else
		hostname = nis_local_host();

	if (hostupdate == TRUE) {
		/*
		 * get the list of directories served by this server and
		 * update all those directory objects.
		 */
		nis_server	*nisserver;
		nis_tag		tags, *tagres;
		nis_error	status;
		char		*t, *dirname = NULL;

		if (argc > optind) {
			fprintf(stderr,
			    "No directories allowed with -s option\n");
			usage(argv[0]);
		}
		if (!(nisserver =
		    __nis_host2nis_server_g(hostname, TRUE,	FALSE, NULL)))
			exit(1);

		/* Get a list of directories served by this server */
		tags.tag_type = TAG_DIRLIST;
		tags.tag_val = "";
		status = nis_stats(nisserver, &tags, 1, &tagres);
		if (status != NIS_SUCCESS) {
			fprintf(stderr,
			    "nisupdkeys: Error talking to host \"%s\", "
			    "error was %s\n", hostname, nis_sperrno(status));
			exit(1);
		}
		if ((strcmp(tagres->tag_val, "<Unknown Statistic>") == 0) ||
		    (strcasecmp(tagres->tag_val, "<error>") == 0) ||
		    (strcmp(tagres->tag_val, " ") == 0)) {
			fprintf(stderr,
			    "Attributes for the server \"%s\" cannot be "
			    "updated by \"nisupdkeys -s\"\n", hostname);
			fprintf(stderr,
			    "Instead, use the following for all directories "
			    "served by \"%s\"\n",
			    hostname);
			fprintf(stderr, "\t%s [-a|-C] -H \"%s\" dir_name "
			    "... \n", argv[0], hostname);
			exit(1);
		}
		dirname = strdup(tagres->tag_val);
		if (dirname == NULL) {
			fprintf(stderr, "Cannot allocate buffer.");
			exit(1);
		}

		while (t = strchr(dirname, ' ')) {
			*t++ = NULL;
			dirlist[i++] = dirname;
			dirname = t;
		}
		dirlist[i++] = dirname;
	} else {
		while ((argc - optind) > 0)
			dirlist[i++] = argv[optind++];
		if (i == 0) {
			dirlist[0] = nis_local_directory();
			i++;
		}
	}
	dirlist[i] = NULL;

	res = NULL;
	for (curdir = dirlist; *curdir; curdir++) {
		is_modified = 0;

		/* if res != NULL its been used before */
		if (res)
			nis_freeresult(res);

		printf("Updating directory object \"%s\" ...\n", *curdir);
		res = nis_lookup(*curdir, MASTER_ONLY+EXPAND_NAME);
		if (res->status != NIS_SUCCESS) {
			fprintf(stderr,
			    "\tERROR: Unable to retrieve object.\n");
			nis_perror(res->status, *curdir);
			continue;
		}
		obj = res->objects.objects_val;
		sprintf(dname, "%s.%s", obj->zo_name, obj->zo_domain);
		if (__type_of(obj) != NIS_DIRECTORY_OBJ) {
			fprintf(stderr, "\tERROR: \"%s\" is not a directory.\n",
			    dname);
			continue;
		}
		ns = obj->DI_data.do_servers.do_servers_len;
		srvlist = obj->DI_data.do_servers.do_servers_val;
		/* if a specific host has been specified */
		if (server) {
			for (i = 0; i < ns; ++i) {
				if (match_host(server, srvlist[i].name))
					break;
			}
			if (i == ns) {
				fprintf(stderr,
				    "\tERROR: Host \"%s\" does not serve "
				    "directory \"%s\"\n", server, *curdir);
				fprintf(stderr,
				    "\tDirectory \"%s\" is not being "
				    "modified\n", *curdir);
				continue;
			}
		}
		switch (op) {
			case CLR_KEYS :
				is_modified = clearkeydata(server, ns, srvlist);
				break;
			case UPD_KEYS :
				is_modified = updkeydata(server, ns, srvlist);
				break;
			case UPD_ADDR :
				is_modified = updaddrdata(server, ns, srvlist);
				break;
			default:
				/* should not have happened */
				exit(1);
		}
		if (is_modified) {
			mres = nis_modify(dname, obj);
			if (mres->status != NIS_SUCCESS) {
				fprintf(stderr,
				    "\tERROR: Unable to modify directory "
				    "object \"%s\"\n", *curdir);
				nis_perror(mres->status, dname);
			}
			nis_freeresult(mres);
		}
	}
	if (res)
		nis_freeresult(res);
	return (0);
}
