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
 * nismkdir.c
 *
 * NIS+ directory and server create utility
 *
 */

#include <stdio.h>
#include <string.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <netdb.h>
#include <netdir.h>
#include <netconfig.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <rpc/key_prot.h>
#include <rpcsvc/nis_dhext.h>

#define	MAX_REPLICA 64
char *defstr = 0;
int  errcode = 0;

extern int 	optind;
extern char	*optarg;

extern nis_object nis_default_obj;

void
make_directory(char *name)
{
	nis_result *res, *ares;
	nis_object *obj;
	char *p, lname[NIS_MAXNAMELEN], *dname;
	nis_error s;

	/*
	 * Break name into leaf and domain components.
	 */
	if ((p = nis_leaf_of(name)) == 0) {
		nis_perror(NIS_BADNAME, name);
		exit(1);
	}
	strcpy(lname, p);
	dname = nis_domain_of(name);

	/*
	 * Get the parent directory object.
	 */
	res = nis_lookup(dname, MASTER_ONLY);
	if (res->status != NIS_SUCCESS) {
		nis_perror(res->status, dname);
		exit(1);
	}

	if (!nis_defaults_init(defstr))
		exit(1);

	/*
	 * Turn the parent directory object into the
	 * sub-directory object.  If we cared about memory
	 * leaks, we would save pointers to the fields that
	 * are being overwritten, and restore them and free
	 * the parent object when we are done.
	 */
	obj = &(NIS_RES_OBJECT(res)[0]);
	if (obj->zo_data.zo_type != NIS_DIRECTORY_OBJ) {
		fprintf(stderr, "\"%s\": not a directory\n", dname);
		exit(1);
	}
	obj->zo_owner = nis_default_obj.zo_owner;
	obj->zo_group = nis_default_obj.zo_group;
	obj->zo_access = nis_default_obj.zo_access;
	obj->zo_ttl = nis_default_obj.zo_ttl;
	obj->DI_data.do_name = name;

	/*
	 * Make the directory and add it to the namespace.
	 */
	ares = nis_add(name, obj);
	if (ares->status != NIS_SUCCESS) {
		nis_perror(ares->status, "can't add directory");
		exit(1);
	} else {
		s = nis_mkdir(name,
			&(obj->DI_data.do_servers.do_servers_val[0]));
		if (s != NIS_SUCCESS) {
			(void) nis_remove(name, 0);
			nis_perror(s, "can't make directory");
			exit(1);
		}
	}
	nis_freeresult(ares);
	/*
	 * do not free res because it contains pointers to structures
	 * it did not allocate.
	 */
}


static int
verify_server(nis_name host,		/* new server hostname	*/
		nis_name dir_to_serve,	/* directory to serve	*/
		int to_be_master)	/* will it be a master?	*/
{

	nis_error status;	/* status of nis_stats()	*/
	nis_name dom_of_host;	/* domain name of server host	*/
	nis_object *obj;	/* generic NIS+ object variable	*/
	nis_result *hres, *sres; /* status of nis_lookup()	*/
	nis_server *servers;	/* servers for host's domain	*/
	nis_tag tags, *tagres;	/* NIS+ tags and tags result	*/

	/* Try to lookup directory to serve... */
	sres = nis_lookup(dir_to_serve, 0);

	/* If it doesn't exist, we can't have a (replica) server for it! */
	if ((sres->status != NIS_SUCCESS) && !to_be_master) {
		fprintf(stderr, "\"%s\": %s\n",
		    dir_to_serve, nis_sperrno(sres->status));
		return (0);
	}

	/* It exists, but is it a directory object? */
	if (sres->status == NIS_SUCCESS) {
		obj = sres->objects.objects_val;
		if (__type_of(obj) != NIS_DIRECTORY_OBJ) {
			fprintf(stderr, "\"%s\": not a directory.\n",
			    dir_to_serve);
			return (0);
		}
	}

	nis_freeresult(sres);

	/* Try to lookup domain of host who wants to be a server... */
	dom_of_host = strdup(nis_domain_of(host));
	hres = nis_lookup(dom_of_host, 0);

	/* Can't get host domain, servers busy or domain name bogus... */
	if (hres->status != NIS_SUCCESS) {
		fprintf(stderr, "\"%s\": %s\n", dom_of_host,
		    nis_sperrno(hres->status));
		return (0);
	}

	/* It exists, but is it a directory object? */
	obj = hres->objects.objects_val;
	if (__type_of(obj) != NIS_DIRECTORY_OBJ) {
		fprintf(stderr, "\"%s\": not a directory.\n", dom_of_host);
		return (0);
	}

	servers = obj->DI_data.do_servers.do_servers_val;

	switch ((int)(nis_dir_cmp(dir_to_serve, dom_of_host))) {

	    case SAME_NAME:

		tags.tag_type = TAG_ROOTSERVER;
		tags.tag_val = "root server";

		if (!servers[0].name) {
		    fprintf(stderr, "nismkdir: invalid directory object\n");
		    return (0);
		}
		status = nis_stats(&servers[0], &tags, 1, &tagres);
		if (status != NIS_SUCCESS) {
			fprintf(stderr,
			    "nismkdir: can't contact root server for \"%s\""
			    ": %s\n", servers[0].name, dom_of_host,
			    nis_sperrno(status));
			return (0);
		}
		nis_freeresult(hres);

		/* If the server-to-be is in the root domain, it can serve. */
		if (strcmp(tagres[0].tag_val, "ON") == 0) {
		    return (1);
		} else {
		    fprintf(stderr,
			"nismkdir: host '%s' must be in a domain above '%s'\n",
			host, dir_to_serve);
		    return (0);
		}
	    case LOWER_NAME:
		/* directory is below domain of host in question... okay */
		return (1);

	    case HIGHER_NAME:
	    case NOT_SEQUENTIAL:
		fprintf(stderr,
		    "nismkdir: host '%s' must be in a domain above '%s'\n",
		    host, dir_to_serve);
		return (0);

	    case BAD_NAME:
	    default:
		fprintf(stderr,
		    "nismkdir: cannot parse either or both of '%s' and '%s'\n",
		    dir_to_serve, dom_of_host);
		return (0);
	}
}


void
make_directory_master(char *name, char *host)
{
	nis_result *res, *ares, *mres;
	nis_object *obj, dobj;
	nis_error s;
	nis_server *serv, sserv, *newserv;
	int nserv, i;

	/*
	 * Does the directory already exist?
	 */
	res = nis_lookup(name, MASTER_ONLY);
	if (res->status == NIS_SUCCESS) {
		obj = &(NIS_RES_OBJECT(res)[0]);
		if (obj->zo_data.zo_type != NIS_DIRECTORY_OBJ) {
			fprintf(stderr, "\"%s\": not a directory\n", name);
			exit(1);
		}
		nserv = obj->DI_data.do_servers.do_servers_len;

		newserv = __nis_host2nis_server_g(host, TRUE, TRUE, &errcode);
		if (newserv == NULL) {
			nis_perror(errcode, host);
			exit(1);
		}

		if (nis_dir_cmp(obj->DI_data.do_servers.do_servers_val[0].name,
				newserv->name) == SAME_NAME) {
			fprintf(stderr,
				"\"%s\" is already master for \"%s\"!\n",
				host, name);
			exit(1);
		}

		/*
		 * Verify server able to serve intended domain.
		 */
		if (!verify_server(newserv->name, name, 1))
			exit(1);

		/*
		 * Add master to list of servers and demote current
		 * master to the role of a slave.
		 */
		for (i = 1; i < nserv; i++)
			if (nis_dir_cmp(
			obj->DI_data.do_servers.do_servers_val[i].name,
					newserv->name) == SAME_NAME)
				break;
		if (i < nserv) {
			sserv =
			    obj->DI_data.do_servers.do_servers_val[i];
			obj->DI_data.do_servers.do_servers_val[i] =
			    obj->DI_data.do_servers.do_servers_val[0];
			obj->DI_data.do_servers.do_servers_val[0] =
								sserv;
		} else {
			if ((serv = (nis_server*)malloc(
				(nserv + 1)*sizeof (nis_server))) ==
								0) {
				nis_perror(NIS_NOMEMORY,
						"can't add master");
				exit(1);
			}

			for (i = 0; i < nserv; i++)
				serv[i+1] =
			    obj->DI_data.do_servers.do_servers_val[i];
			serv[0] = *newserv;
			obj->DI_data.do_servers.do_servers_len++;
			obj->DI_data.do_servers.do_servers_val = serv;
		}

		mres = nis_modify(name, obj);
		if (mres->status != NIS_SUCCESS) {
			nis_perror(mres->status, "can't add master");
			exit(1);
		}
		nis_freeresult(mres);
		/*
		 * do not free res because it contains pointers to
		 * structures it did not allocate.
		 */
	} else {
		if (!nis_defaults_init(defstr))
			exit(1);

		/*
		 * Construct the directory object.
		 */
		dobj = nis_default_obj;
		dobj.zo_data.zo_type = NIS_DIRECTORY_OBJ;
		dobj.DI_data.do_name = name;
		dobj.DI_data.do_type = NIS;
		dobj.DI_data.do_ttl = nis_default_obj.zo_ttl;
		dobj.DI_data.do_servers.do_servers_len = 1;
		dobj.DI_data.do_servers.do_servers_val =
			__nis_host2nis_server_g(host, TRUE, TRUE, &errcode);
		if (dobj.DI_data.do_servers.do_servers_val == NULL) {
			nis_perror(errcode, host);
			exit(1);
		}
		dobj.DI_data.do_armask.do_armask_len = 0;
		dobj.DI_data.do_armask.do_armask_val = 0;

		/*
		 * Make the directory and add it to the namespace.
		 */
		ares = nis_add(name, &dobj);
		if (ares->status != NIS_SUCCESS) {
			nis_perror(ares->status, "can't add directory");
			exit(1);
		} else {
			s = nis_mkdir(name,
				&(dobj.DI_data.do_servers.do_servers_val[0]));
			if (s != NIS_SUCCESS) {
				(void) nis_remove(name, 0);
				nis_perror(s, "can't make directory");
				exit(1);
			}
		}
		nis_freeresult(ares);
	}
}


void
make_directory_replica(char *name, char *host)
{
	nis_result *res, *mres;
	nis_object *obj;
	nis_server *serv, *newserv;
	int nserv, i;

	/*
	 * Get the directory object.
	 */
	res = nis_lookup(name, MASTER_ONLY);
	if (res->status != NIS_SUCCESS) {
		nis_perror(res->status, name);
		exit(1);
	}
	obj = &(NIS_RES_OBJECT(res)[0]);
	if (obj->zo_data.zo_type != NIS_DIRECTORY_OBJ) {
		fprintf(stderr, "\"%s\": not a directory\n", name);
		exit(1);
	}
	nserv = obj->DI_data.do_servers.do_servers_len;

	newserv = __nis_host2nis_server_g(host, TRUE, TRUE, &errcode);
	if (newserv == NULL) {
		nis_perror(errcode, host);
		exit(1);
	}

	for (i = 0; i < nserv; i++)
		if (nis_dir_cmp(
			obj->DI_data.do_servers.do_servers_val[i].name,
				newserv->name) == SAME_NAME)
			break;
	if (i < nserv) {
		fprintf(stderr, "\"%s\" already serves \"%s\"!\n",
			host, name);
		exit(1);
	}

	/*
	 * Verify server able to serve intended domain
	 */
	if (!verify_server(newserv->name, name, 0))
		exit(1);

	/*
	 * Add slave to the list of servers.
	 */
	if ((serv = (nis_server*)malloc(
			(nserv + 1)*sizeof (nis_server))) == 0) {
		nis_perror(NIS_NOMEMORY, "can't add replica");
		exit(1);
	}
	for (i = 0; i < nserv; i++)
		serv[i] = obj->DI_data.do_servers.do_servers_val[i];
	serv[i] = *newserv;
	obj->DI_data.do_servers.do_servers_len++;
	obj->DI_data.do_servers.do_servers_val = serv;

	mres = nis_modify(name, obj);
	if (mres->status != NIS_SUCCESS) {
		nis_perror(mres->status, "can't add replica");
		exit(1);
	}
	nis_freeresult(mres);
	/*
	 * do not free res because it contains pointers to structures
	 * it did not allocate.
	 */
}


void
usage()
{
	fprintf(stderr,
	"usage: nismkdir [-D defaults] [-m hostname] [-s hostname] dirname\n");
	exit(1);
}


int
main(int argc, char *argv[])
{
	int c;
	int i;
	char *host;
	char *name;
	int update_master = 0;
	char *replicas[MAX_REPLICA];
	int nreplicas = 0;

	while ((c = getopt(argc, argv, "D:m:s:")) != -1) {
		switch (c) {
		case 'D':
			defstr = optarg;
			break;
		case 'm':
			if (update_master) {
				fprintf(stderr,
					"only one master can be specified\n");
				exit(1);
			}
			update_master = 1;
			host = optarg;
			break;
		case 's':
			if (nreplicas >= MAX_REPLICA) {
				fprintf(stderr, "too many replicas\n");
				exit(1);
			}
			replicas[nreplicas++] = optarg;
			break;
		default:
			usage();
		}
	}

	if (argc - optind != 1)
		usage();

	name = argv[optind];
	if (name[strlen(name)-1] != '.') {
		fprintf(stderr, "dirname must be fully qualified.\n");
		exit(1);
	}

	/*
	 *  If no master or replica flag, just create directory.
	 *  The directory will have the same replication as its parent
	 *  directory.
	 */
	if (! update_master && nreplicas == 0)
		make_directory(name);
	else {
		if (update_master)
			make_directory_master(name, host);

		for (i = 0; i < nreplicas; i++)
			make_directory_replica(name, replicas[i]);
	}

	return (0);
}
