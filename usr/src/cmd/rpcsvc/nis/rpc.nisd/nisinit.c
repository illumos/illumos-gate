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
 * This module contains the nis initialization code. It is designed to
 * initialize a client or server. The server can be a master server or
 * a slave server (replicate). NOTE: This file defines what the "psuedo"
 * tables look like when defined by the server. This means that this
 * module and the nis_db.c module must track each other. This module
 * gets linked to nis_db.o and the database library.
 *
 * This is version 3 of this file, most of it has been taken over
 * by nismkdir and the service itself.
 * This is version 2 of this file, version 1 was a major hack this
 * is more structured but still pretty hackish.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <string.h>
#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <netdb.h>
#include <netdir.h>
#include <netconfig.h>
#include <nsswitch.h>
#include <sys/socket.h>
#include <rpcsvc/nis.h>
#include <netinet/in.h>
#include "nis_svc.h"
#include "nis_proc.h"

#define	COLDSTART "/var/nis/NIS_COLD_START"

extern void	__nis_netconfig2ep(struct netconfig *, endpoint *);

extern	int	errno;
extern int 	optind;		/* getopt counter	*/
extern char	*optarg;	/* getopt pointer 	*/

directory_obj	bc_dir;
char valid_dir_obj = 0;
char *local_dir;
char *secure_dir;

/*
 * get_server()
 *
 * This function constructs a local server description of the current
 * server and returns it as a nis_server structure. This is then added
 * to the list of servers who serve this directory.
 */
nis_server *
get_server(host)
	char	*host;
{
#define	INC_SIZE 512
	int			myaddr_size = INC_SIZE;
	endpoint  		*myaddr;
	static nis_server 	myself;
	char			hname[256];
	int			num_ep = 0, i;
	struct netconfig	*nc;
	void			*nch;
	struct nd_hostserv	hs;
	struct nd_addrlist	*addrs;

	myaddr = (endpoint *) calloc(myaddr_size, sizeof (endpoint));
	if (myaddr == NULL) {
		fprintf(stderr, "Error: out of memory\n");
		exit(1);
	}
	gethostname(hname, 256);
	hs.h_host = (host) ? host : hname;
	hs.h_serv = "rpcbind";
	nch = setnetconfig();
	while (nc = getnetconfig(nch)) {
		if (! netdir_getbyname(nc, &hs, &addrs)) {
			for (i = 0; i < addrs->n_cnt; i++, num_ep++) {
				if (num_ep == myaddr_size) {
					myaddr_size += INC_SIZE;
					myaddr = (endpoint *) realloc(
					    (void *)myaddr,
					    myaddr_size * sizeof (endpoint));
					if (myaddr == NULL) {
						fprintf(stderr,
						"Error: out of memory\n");
						exit(1);
					}
				}
				myaddr[num_ep].uaddr =
				taddr2uaddr(nc, &(addrs->n_addrs[i]));
				__nis_netconfig2ep(nc, &(myaddr[num_ep]));
			}
			netdir_free((char *)addrs, ND_ADDRLIST);
		}
	}
	endnetconfig(nch);

	if (! num_ep) {
		fprintf(stderr,
		    "\nError: Unable to construct an address from name '%s'\n",
								hs.h_host);
		fprintf(stderr,
		    "Please check that this hostname exists in /etc/hosts\n");
		exit(1);
	}
	myself.name = (host) ? strdup(host) : strdup(nis_local_host());
	myself.ep.ep_len = num_ep;
	myself.ep.ep_val = &myaddr[0];
	myself.key_type = NIS_PK_NONE;
	myself.pkey.n_bytes = NULL;
	myself.pkey.n_len = 0;
	return (&myself);
}

/*
 * This function initializes a directory object. It is used when
 * creating the object for master servers, and for creating a
 * prototype coldstart file which is then used to build the
 * real coldstart file. It returns false if it couldn't get
 * a nis_server structure for the passed hostname. If this
 * name is a null pointer it builds the directory object for
 * the local host and cannot fail.
 */
void
init_data(dd, host)
	directory_obj	*dd;	/* Directory data. 	*/
	char		*host;	/* Optional host	*/
{
	dd->do_type = NIS;
	dd->do_name = strdup(local_dir);
	dd->do_servers.do_servers_len = 1;
	dd->do_servers.do_servers_val = get_server(host);
	dd->do_ttl = 12*60*60; /* this should track the object */
	dd->do_armask.do_armask_len = 0;
	dd->do_armask.do_armask_val = NULL;
}

static
int
decode_dir(res)
	fd_result *res;
{
	int		stat;
	XDR		mem;

	if (res->status != NIS_SUCCESS)
		return (0);

	memset((char *)&bc_dir, 0, sizeof (bc_dir));
	xdrmem_create(&mem, res->dir_data.dir_data_val,
			    res->dir_data.dir_data_len, XDR_DECODE);
	stat = xdr_directory_obj(&mem, &bc_dir);
	if (! stat) {
		fprintf(stderr,
			"\nError: Couldn't decode returned object.\n");
		return (0);
	}
	if (nis_dir_cmp(local_dir, bc_dir.do_name) != SAME_NAME) {
		xdr_free(xdr_directory_obj, (char *)&bc_dir);
		return (0);
	}

	valid_dir_obj = 1;
	return (1);
}

/*
 * The bc_init_data() function is called by the callback function of
 * the RPC broadcast function.
 */
bool_t
bc_init_data(x, haddr, nc)
	caddr_t			x;
	struct netbuf		*haddr;	/* host that answered : UNUSED */
	struct netconfig	*nc;	/* its endpoint: UNUSED	*/
{
	fd_result	*res = (fd_result *) x;

	return (decode_dir(res));
}

static
int
check_coldstart(dir)
	char *dir;
{
	directory_obj dobj;

	if (!__readColdStartFile(&dobj))
		return (1);

	if (nis_dir_cmp(dobj.do_name, dir) != SAME_NAME) {
		return (0);
	}

	return (1);
}

void
usage(s)
	char	*s;
{
	fprintf(stderr,
		"usage: \t%s [-k key_domain] -c -H host|-B|-C coldstart\n", s);
	fprintf(stderr, "\t%s -r\n", s);
	fprintf(stderr, "\t%s -p Y|D|N parent_domain host ...\n", s);
	exit(1);
}

enum make_op {MAKE_NONE, MAKE_ROOT, MAKE_PARENT, MAKE_CLIENT };
enum obj_src {SRC_NONE, SRC_BCAST, SRC_MCAST, SRC_CSTART, SRC_HNAME };

int
main(int argc, char *argv[])
{
	enum clnt_stat	dummy;	/* rc for rpc_broadcast() */
	int		c;	/* Option character */
	enum name_pos	pos;
	uint32_t	exptime;
	struct stat	s;
	char		buf[1024];
	char		*directory = nis_local_directory(),
			*hostname = nis_local_host(),
			*coldstart = NULL;
	enum make_op 	op = MAKE_NONE;
	enum obj_src	src = SRC_NONE;
	nstype		ns_type = SUNYP;
	nis_object	d_obj, *n_obj;
	int		sfd, dfd, i, status, nhosts = 1;
	directory_obj	*d_data;
	nis_server	*srvs;
	unsigned char	a1, a2, a3, a4;
	struct hostent	*he;
	struct in6_addr	addr;
	nis_result	*res;
	fd_args		fdarg;
	fd_result	fdres;
	int		ss;
	char 		*tmpp;
	FILE		*fw;
	struct __nsw_switchconfig *conf;
	enum __nsw_parse_err perr;
	int print_warn = 0;
	int heerr;
	sa_family_t af;

	/*
	 *  Make sure that files created by stdio don't
	 *  have extra permission.  We allow group and world
	 *  read because the files and directories we create
	 *  need to be world readable.
	 */
	(void) umask(022);

	memset((char *)(&d_obj), 0, sizeof (nis_object));
	if (geteuid() != 0) {
		fprintf(stderr, "This program must be run as superuser.\n");
		exit(1);
	}

	local_dir = nis_local_directory();

	/*
	 * By default Solaris2.0/SunOS 5.0 is setup as an NIS (YP) client.
	 * In order to use NIS+, publickeys must be gotten from NIS+ if
	 * NIS+ is running in secure mode.
	 */
	conf = __nsw_getconfig("publickey", &perr);
	if ((conf == NULL) || (conf->lookups == NULL)) {
		fprintf(stderr,
			"Warning: There is no publickey entry in %s.\n",
							__NSW_CONFIG_FILE);
		fprintf(stderr,
		    "The default publickey policy is \"publickey: nis\".\n");
		print_warn = 1;
	} else if ((strcmp(conf->lookups->service_name, "nisplus") != 0) ||
		(conf->lookups->next != NULL)) {
		struct __nsw_lookup *look;

		fprintf(stderr,
			"Warning: The publickey entry in %s is \"publickey: ",
			__NSW_CONFIG_FILE);
		for (look = conf->lookups; look; look = look->next) {
			fprintf(stderr, "%s", look->service_name);
			if (look->next)
				fprintf(stderr, " ");
		}
		fprintf(stderr, "\"\n");
		print_warn = 1;
	}

	if (print_warn == 1) {
		fprintf(stderr,
	"In order to use NIS+, it should be \"publickey: nisplus\".\n");
		fprintf(stderr,
"For more information, see secure_rpc(3N), publickey(3N), & nisaddcred(1).\n");
	}

	op = MAKE_NONE;
	src = SRC_NONE;
	while ((c = getopt(argc, argv, "rck:p:C:BMH:")) != -1) {
		switch (c) {
			case 'k':
				secure_dir = optarg;
				break;
			case 'r' :
				if (op != MAKE_NONE)
					usage(argv[0]);
				op = MAKE_ROOT;
				break;
			case 'c':
				if (op != MAKE_NONE)
					usage(argv[0]);
				op = MAKE_CLIENT;
				break;
			case 'p' :
				if (op != MAKE_NONE)
					usage(argv[0]);
				if (*optarg == '-')	/* skip '-' character */
					optarg++;
				switch (*optarg) {
				case 'Y' :
					ns_type = SUNYP;
					break;
				case 'D' :
					ns_type = DNS;
					break;
				case 'N' :
					ns_type = NIS;
					break;
				default :
					fprintf(stderr,
			"unrecognized name service type, use one of:\n");
					fprintf(stderr,
			" Y = Sun YP\n D = Domain Name Service\n");
					fprintf(stderr,
			" N = Sun NIS+\n");
					usage(argv[0]);
				}
				op = MAKE_PARENT;
				break;
			case 'C' :
				if (src != SRC_NONE)
					usage(argv[0]);
				src = SRC_CSTART;
				coldstart = optarg;
				break;
			case 'H' :
				if (src != SRC_NONE)
					usage(argv[0]);
				src = SRC_HNAME;
				hostname = optarg;
				break;
			case 'B' :
				if (src != SRC_NONE)
					usage(argv[0]);
				src = SRC_BCAST;
				break;
#ifdef NIS_MCAST_SUPPORT
			case 'M' :
				if (src != SRC_NONE)
					usage(argv[0]);
				src = SRC_MCAST;
				break;
#endif
			case '?' :
			default :
				usage(argv[0]);
				break;
		}
	}

	if (op == MAKE_NONE) {
		fprintf(stderr, "One of -c, -r or -p must be specified.\n");
		usage(argv[0]);
	}

	/* Only making the parent requires extra data (host name) */
	if ((optind < argc) && (op != MAKE_PARENT)) {
		fprintf(stderr,
			"Error: Extra input at the end of the command.\n");
		usage(argv[0]);
	} else if ((optind <= argc) && (op == MAKE_PARENT)) {
		if ((argc - optind) < 2) {
			fprintf(stderr,
"Error: Make parent (-p) requires parent domain and at least one host.\n");
			usage(argv[0]);
		}
		directory = argv[optind++];
		nhosts = argc - optind;
	}

	/* /var/nis directory should exist.  If not, create it. */
	strcpy(buf, nis_data(NULL));
	tmpp = strrchr(buf, '/');
	*tmpp = NULL;
	ss = stat(buf, &s);
	if (ss == -1 && errno == ENOENT) {
		if (mkdir(buf, 0755)) {
			perror("mkdir");
			fprintf(stderr, "Error: Unable to create \"%s\"\n",
			    buf);
			exit(1);
		}
	} else if (ss == -1) {
		perror("stat");
		fprintf(stderr, "Error: Unable to stat \"%s\"\n", buf);
		exit(1);
	}

	/*
	 * For root and parent operations, the /var/nis directory should
	 * exist with the correct permissions.
	 */
	switch (op) {
	case MAKE_ROOT:
	case MAKE_PARENT:
		strcpy(buf, nis_data(NULL));
		ss = stat(buf, &s);
		if (ss == -1 && errno == ENOENT) {
			if (op == MAKE_PARENT) {
				fprintf(stderr,
"Error: Parent object cannot be created before creating a root object.\n");
				exit(1);
			}
			if (mkdir(buf, 0744)) {
				perror("mkdir");
				fprintf(stderr, "Error: Unable to create "
				    "\"%s\"\n", buf);
				exit(1);
			}
		} else if (ss == -1) {
			perror("stat");
			fprintf(stderr, "Error: Unable to stat \"%s\"\n", buf);
			exit(1);
		} else {
			if ((s.st_mode & 0777) != 0744) {
				fprintf(stderr,
		"Warning: Bad permissions (%o) on the %s directory.\n",
					s.st_mode & 0777, buf);
				fprintf(stderr, "Should have been 744\n\n");
			}
			if (op == MAKE_ROOT)
				/* Some data is already in this directory */
				fprintf(stderr,
				    "Warning: Old data exists under "
				    "the \"%s\" directory.\n\n", buf);
			else {
				/* make sure that the root_object is there */
				ss = stat(nis_data(ROOT_OBJ), &s);
				if (ss == -1 && errno == ENOENT) {
					fprintf(stderr,
"Error: Parent object cannot be created before creating a root object.\n");
					exit(1);
				} else if (ss == -1) {
					perror("stat");
					fprintf(stderr,
					    "Error: Unable to stat \"%s\"\n",
					    nis_data(ROOT_OBJ));
					exit(1);
				}
			}
		}
	}

	printf(
	    "This machine is in the \"%s\" NIS+ domain.\n", local_dir);
	switch (op) {
		case MAKE_ROOT :
			printf("Setting up root server ...\n");
			/*
			 * Step 0. See if we have the info we need.
			 */

			/*
			 * Step 1. Create Directory object
			 * Since we are the master server, the d_obj should
			 * not pre-exist.
			 */
			d_obj.zo_oid.ctime = time(0);
			d_obj.zo_name   = strdup(nis_leaf_of(directory));
			d_obj.zo_domain = nis_domain_of(directory);
			d_obj.zo_owner  = nis_local_principal();
			d_obj.zo_group  = nis_local_group();
			/* Make this object readable by nobody */
			d_obj.zo_access = DEFAULT_RIGHTS | (NIS_READ_ACC << 24);
			if (*d_obj.zo_group != NULL)
				d_obj.zo_access |= ((NIS_READ_ACC +
					NIS_MODIFY_ACC + NIS_CREATE_ACC +
					NIS_DESTROY_ACC) << 8);
			d_obj.zo_ttl    = 24 * 60 * 60;
			d_obj.zo_data.zo_type = NIS_DIRECTORY_OBJ;
			d_data = &(d_obj.DI_data);
			init_data(d_data, (char *)NULL);
			strcpy(buf, nis_data(ROOT_OBJ));
			status = nis_write_obj(buf, &d_obj);
			if (! status) {
				fprintf(stderr,
				    "\nError: Unable to write root object.\n");
				exit(1);
			}
			/* Write cold start file */
			__nis_CacheRestart();  /* in case cachemgr running */
			unlink(COLDSTART);
			writeColdStartFile(d_data);
			__nis_CacheRestart();

			/* Create the serving list file */
			strcpy(buf, nis_data("serving_list"));
			fw = fopen(buf, "a+");
			if (fw == NULL) {
				fprintf(stderr,
	"\nERROR: could not open file \"%s\" for storing directories served.\n",
					buf);
				exit(1);
			}
			fprintf(fw, "%s\n", directory);
			fclose(fw);

			break;
		case MAKE_PARENT :
			printf("Setting up parent object ...\n");
			/*
			 * Step 1. Create Directory object
			 * Since we are the master server, the d_obj should
			 * not pre-exist.
			 */
			strcpy(buf, nis_domain_of(local_dir));
			d_obj.zo_name   = strdup(nis_leaf_of(buf));
			d_obj.zo_domain = strdup(nis_domain_of(buf));
			d_obj.zo_owner  = strdup(nis_local_principal());
			d_obj.zo_group  = "";
			d_obj.zo_access = 0x01010101; /* r---r---r---r--- */
			d_obj.zo_ttl    = 7*24*3600;

			d_obj.zo_data.zo_type = NIS_DIRECTORY_OBJ;
			d_data = &(d_obj.DI_data);
			d_data->do_type = ns_type;
			d_data->do_name = directory;
			d_data->do_servers.do_servers_len = nhosts;
			d_data->do_servers.do_servers_val = (nis_server *)
					    calloc(nhosts, sizeof (nis_server));
			srvs = d_data->do_servers.do_servers_val;
			for (i = 0; i < nhosts; i++) {
				extern char *inet_ntoa(struct in_addr);
				srvs[i].name = strdup(argv[optind + i]);
				srvs[i].key_type = NIS_PK_NONE;
				srvs[i].ep.ep_len = 1;
				srvs[i].ep.ep_val = (endpoint *)
						calloc(1, sizeof (endpoint));
				he = getipnodebyname(srvs[i].name, AF_INET6,
						AI_DEFAULT, &heerr);
				if (! he) {
					fprintf(stderr,
		"\nError: Couldn't locate address information for \"%s\".\n",
								srvs[i].name);
					exit(1);
				}
				addr =
		((struct sockaddr_in6 *)(he->h_addr_list[0]))->sin6_addr;
				if (IN6_IS_ADDR_V4MAPPED(&addr)) {
					struct in_addr in4;
					af = AF_INET;
					IN6_V4MAPPED_TO_INADDR(&addr, &in4);
					strcpy(buf, inet_ntoa(in4));
				} else {
					af = AF_INET6;
					(void) inet_ntop(AF_INET6, &addr,
							buf, sizeof (buf));
				}
				switch (d_data->do_type) {
				case NIS:
				case SUNYP:
					strcat(buf, ".0.111");
					break;
				case DNS:
					strcat(buf, ".0.53");
					break;
				}
				srvs[i].ep.ep_val->uaddr = strdup(buf);
				srvs[i].ep.ep_val->family =
					(af == AF_INET6) ? NC_INET6 : NC_INET;
				if (d_data->do_type != NIS)
					srvs[i].ep.ep_val->proto =
					(af == AF_INET6) ? "udp6" : "udp";
				else
					srvs[i].ep.ep_val->proto =
					(af == AF_INET6) ? "tcp6" : "tcp";
			}
			d_data->do_ttl = d_obj.zo_ttl;
			d_data->do_armask.do_armask_len = 0;
			d_data->do_armask.do_armask_val = NULL;
			strcpy(buf, nis_data(PARENT_OBJ));
			status = nis_write_obj(buf, &d_obj);
			if (! status) {
				fprintf(stderr,
				"\nError: Unable to write parent object.\n");
				exit(1);
			}
			break;
		case MAKE_CLIENT :
			printf("Setting up NIS+ client ...\n");
			if (secure_dir == NULL) {
				if (!check_coldstart(local_dir)) {
					fprintf(stderr,
	    "\nError: system domain name doesn't match that stored in \"%s\"\n",
						COLDSTART);
					fprintf(stderr,
	    "       use the -k option to specify the domain where root's");
					fprintf(stderr,
						" key is stored.\n");
					exit(1);
				}
			} else {
				pos = nis_dir_cmp(local_dir, secure_dir);
				if (pos != SAME_NAME && pos != LOWER_NAME) {
					fprintf(stderr,
	"\nError: system domain name must be the same as or lower than the\n");
					fprintf(stderr,
	"       domain in which root's key is stored.\n");
					exit(1);
				}
				local_dir = secure_dir;
			}
			(void) unlink(COLDSTART); /* just in case */
			switch (src) {
			case SRC_NONE :
				fprintf(stderr,
				"\nError: Missing source for client setup.\n");
				usage(argv[0]);
				break;
			case SRC_HNAME :
				d_data = &(d_obj.DI_data);
				init_data(d_data, hostname);
				writeColdStartFile(d_data);
				break;
			case SRC_CSTART :
				sfd = open(coldstart, O_RDONLY, 0);
				if (sfd == -1) {
					fprintf(stderr,
					    "\nError: Can't open file \"%s\" "
					    "for reading.\n", coldstart);
					exit(1);
				}
				dfd = open(COLDSTART, O_WRONLY+O_CREAT, 0644);
				if (dfd == -1) {
					fprintf(stderr,
					    "\nError: Can't open file \"%s\" "
					    "for writing.\n", COLDSTART);
					exit(1);
				}
				while ((i = read(sfd, buf, 1024)) > 0)
					write(dfd, buf, i);
				close(dfd);
				close(sfd);
				break;
			case SRC_BCAST :
				fdarg.dir_name = local_dir;
				fdarg.requester = "broadcast";
				memset((char *)&fdres, 0, sizeof (fdres));
				dummy = rpc_broadcast(NIS_PROG, NIS_VERSION,
						NIS_FINDDIRECTORY,
						xdr_fd_args, (char *)&fdarg,
						xdr_fd_result, (char *)&fdres,
						(resultproc_t)bc_init_data,
									NULL);
				if ((fdres.status == NIS_SUCCESS) &&
				    (dummy == RPC_SUCCESS) &&
				    (valid_dir_obj))
					writeColdStartFile(&bc_dir);
				else {
					fprintf(stderr,
			"\nError: No servers responding, use -H option \n");
					exit(1);
				}
				break;
			case SRC_MCAST :
				break;
			default :
				break;
			}

			/*
			 * At this point there should be something of a
			 * coldstart file in the /var/nis directory. If
			 * not then we're hosed.
			 *
			 * We switch to a local cache so that there is
			 * no conflict if nis_cachemgr is still running
			 * with a copy of an old domain name.
			 */
			__nis_CacheLocalInit(&exptime);
			unlink(COLDSTART);
			res = nis_lookup(local_dir, NO_AUTHINFO);
			if (res->status != NIS_SUCCESS) {
				fprintf(stderr,
		"\nError: Could not create a valid NIS+ coldstart file\n");
				nis_perror(res->status, local_dir);
				exit(1);
			}
			n_obj = res->objects.objects_val;
			writeColdStartFile(&(n_obj->DI_data));
			__nis_CacheRestart();
			printf("All done.\n");
			exit(0);
		default :
			printf("\n");
			usage(argv[0]);
	}
	printf("All done.\n");
	return (0);
}
