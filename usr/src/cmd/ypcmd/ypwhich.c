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
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley
 * under license from the Regents of the University of
 * California.
 */

/*
 * This is a user command which tells which yp server is being used by a
 * given machine, or which yp server is the master for a named map.
 *
 * Usage is:
 *	ypwhich [-d domain] [-m [mname] [-t] | [-Vn] host]
 *	ypwhich -x
 * where:  the -d switch can be used to specify a domain other than the
 * default domain.  -m tells the master of that map.  mname is a mapname
 * If the -m option is used, ypwhich will act like a vanilla yp client,
 * and will not attempt to choose a particular yp server.  On the
 * other hand, if no -m switch is used, ypwhich will talk directly to the yp
 * bind process on the named host, or to the local ypbind process if no host
 * name is specified. -t switch inhibits nickname translation of map names.
 * -x is to dump the nickname translation table from file /var/yp/nicknames.
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <rpc/rpc.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#include "yp_b.h"
#include "ypv2_bind.h"
#include <string.h>
#include <netdir.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <netinet/ip6.h>
#include <sys/utsname.h>

#define	YPSLEEPTIME 5 /* between two tries of bind */

#define	TIMEOUT 30			/* Total seconds for timeout */
#define	INTER_TRY 10			/* Seconds between tries */

static int translate = TRUE;
static int dodump = FALSE;
static char *domain = NULL;
static char default_domain_name[YPMAXDOMAIN];
static char *host = NULL;
static int vers = YPBINDVERS;
static char default_host_name[256];
static bool get_master = FALSE;
static bool get_server = FALSE;
static char *map = NULL;
static char nm[YPMAXMAP+1];
static struct timeval timeout = {
		TIMEOUT,			/* Seconds */
		0				/* Microseconds */
};
static char nullstring[] = "\000";
static char err_usage[] =
"Usage:\n\
	ypwhich [-d domain] [[-t] -m [mname] | [-Vn] host]\n\
	ypwhich -x\n\
where\n\
	mname may be either a mapname or a nickname for a map.\n\
	host if specified, is the machine whose NIS server is to be found.\n\
	-t inhibits map nickname translation.\n\
	-Vn version of ypbind, V3 is default.\n\
	-x dumps the map nickname translation table.\n";
static char err_bad_args[] =
"ypwhich:  %s argument is bad.\n";
static char err_cant_get_kname[] =
"ypwhich:  can't get %s back from system call.\n";
static char err_null_kname[] =
"ypwhich:  the %s hasn't been set on this machine.\n";
static char err_bad_mapname[] = "mapname";
static char err_bad_domainname[] = "domainname";
static char err_bad_hostname[] = "hostname";

static void get_command_line_args();
static void getdomain();
static void getlochost();
static void get_server_name();
static int call_binder();
static void get_map_master();
extern void maketable();
extern int getmapname();
#ifdef DEBUG
static void dump_response();
#endif
static void dump_ypmaps();
static void dumpmaps();

static bool xdr_yp_inaddr();
static bool xdr_old_ypbind_resp();
static bool xdr_old_yp_binding();
static int old_call_binder();
static void print_server();

/* need these for call to (remote) V2 ypbind */
struct old_ypbind_binding {
	struct in_addr ypbind_binding_addr;	/* In network order */
	unsigned short int ypbind_binding_port;	/* In network order */
};

struct old_ypbind_resp {
	enum ypbind_resptype ypbind_status;
	union {
		unsigned long ypbind_error;
		struct old_ypbind_binding ypbind_bindinfo;
	} ypbind_respbody;
};

/*
 * This is the main line for the ypwhich process.
 */
int
main(int argc, char **argv)
{
	get_command_line_args(argc, argv);

	if (dodump) {
		maketable(dodump);
		exit(0);
	}

	if (!domain) {
		getdomain();
	}

	if (map && translate && (strchr(map, '.') == NULL) &&
		(getmapname(map, nm))) {
		map = nm;
	}

	if (get_server) {
		if (!host)
			getlochost();
		get_server_name();
	} else {
		if (map)
			get_map_master();
		else
			dump_ypmaps();
	}

	return (0);
}

/*
 * This does the command line argument processing.
 */
static void
get_command_line_args(argc, argv)
int argc;
char **argv;

{
	argv++;

	if (argc == 1) {
		get_server = TRUE;
		return;
	}

	while (--argc) {

		if ((*argv)[0] == '-') {

			switch ((*argv)[1]) {

			case 'V':

				vers = atoi(argv[0]+2);
				if (vers <  1) {
					(void) fprintf(stderr, err_usage);
					exit(1);
				}
				argv++;
				break;

			case 'm':
				get_master = TRUE;
				argv++;

				if (argc > 1) {

					if ((*(argv))[0] == '-') {
						break;
					}

					argc--;
					map = *argv;
					argv++;

					if ((int)strlen(map) > YPMAXMAP) {
				(void) fprintf(stderr, err_bad_args,
						    err_bad_mapname);
						exit(1);
					}

				}

				break;

			case 'd':

				if (argc > 1) {
					argv++;
					argc--;
					domain = *argv;
					argv++;

					if ((int)strlen(domain) > YPMAXDOMAIN) {
				(void) fprintf(stderr, err_bad_args,
				err_bad_domainname);
						exit(1);
					}

				} else {
					(void) fprintf(stderr, err_usage);
					exit(1);
				}

				break;

			case 't':
				translate = FALSE;
				argv++;
				break;

			case 'x':
				dodump = TRUE;
				argv++;
				break;

			default:
				(void) fprintf(stderr, err_usage);
				exit(1);
			}

		} else {

			if (get_server) {
				(void) fprintf(stderr, err_usage);
				exit(1);
			}

			get_server = TRUE;
			host = *argv;
			argv++;

			if ((int)strlen(host) > 256) {
				(void) fprintf(stderr,
			err_bad_args, err_bad_hostname);
				exit(1);
			}
		}
	}

	if (get_master && get_server) {
		(void) fprintf(stderr, err_usage);
		exit(1);
	}

	if (!get_master && !get_server) {
		get_server = TRUE;
	}
}

/*
 * This gets the local default domainname, and makes sure that it's set
 * to something reasonable.  domain is set here.
 */
static void
getdomain()
{
	if (!getdomainname(default_domain_name, YPMAXDOMAIN)) {
		domain = default_domain_name;
	} else {
		(void) fprintf(stderr, err_cant_get_kname, err_bad_domainname);
		exit(1);
	}

	if ((int)strlen(domain) == 0) {
		(void) fprintf(stderr, err_null_kname, err_bad_domainname);
		exit(1);
	}
}

/*
 * This gets the local hostname back from the kernel
 */
static void
getlochost()
{
	struct utsname utsname;

	if (uname(&utsname) != -1) {
		strcpy(default_host_name, utsname.nodename);
		host = default_host_name;
	} else {
		(void) fprintf(stderr, err_cant_get_kname, err_bad_hostname);
		exit(1);
	}

}

/*
 * This tries to find the name of the server to which the binder in question
 * is bound.  If one of the -Vx flags was specified, it will try only for
 * that protocol version, otherwise, it will start with the current version,
 * then drop back to the previous version.
 */
static void
get_server_name()
{
	char *notbound = "Domain %s not bound on %s.\n";

	if (vers >= 3) {
		if (!call_binder(vers))
			(void) fprintf(stderr, notbound, domain, host);
	} else {
		if (!old_call_binder(vers))
			(void) fprintf(stderr, notbound, domain, host);
	}
}

extern CLIENT *__clnt_create_loopback();

/*
 * This sends a message to the ypbind process on the node with
 * the host name
 */
static int
call_binder(vers)
int vers;
{
	CLIENT *client;
	struct ypbind_resp *response;
	struct ypbind_domain ypbd;
	char errstring[256];
	extern struct rpc_createerr rpc_createerr;
	int yperr = 0;
	struct utsname utsname;
	const char *str;

	/*
	 * CAUTION: Do not go to NIS if the host is the same as the local host
	 * XXX: Lots of special magic to distinguish between local and remote
	 * case. We want to make sure the local case doesn't hang.
	 */

	if ((uname(&utsname) != -1) &&
		(strcmp(host, utsname.nodename) == 0))
		client = __clnt_create_loopback(YPBINDPROG, vers, &yperr);
	else
		client = clnt_create(host, YPBINDPROG, vers, "netpath");
	if (client == NULL) {
		if (yperr)
			(void) fprintf(stderr,
				"ypwhich: %s\n", yperr_string(yperr));
		else {
			if (rpc_createerr.cf_stat == RPC_PROGNOTREGISTERED ||
				rpc_createerr.cf_stat == RPC_PROGUNAVAIL) {
				(void) fprintf(stderr,
			"ypwhich: %s is not running ypbind\n", host);
			} else if (rpc_createerr.cf_stat == RPC_PMAPFAILURE) {
				(void) fprintf(stderr,
			"ypwhich: %s is not running rpcbind\n",
					host);
			} else
				(void) clnt_pcreateerror("ypwhich: \
clnt_create error");
		}
		exit(1);
	}
	ypbd.ypbind_domainname = domain;
	ypbd.ypbind_vers = vers;
	response = ypbindproc_domain_3(&ypbd, client);

	if (response == NULL) {
		(void) sprintf(errstring,
		    "ypwhich: can't call ypbind on %s", host);
		(void) clnt_perror(client, errstring);
		exit(1);
	}

	clnt_destroy(client);

	if (response->ypbind_status != YPBIND_SUCC_VAL)  {
		return (FALSE);
	}

	if (response->ypbind_resp_u.ypbind_bindinfo) {
		char *server =
	response->ypbind_resp_u.ypbind_bindinfo->ypbind_servername;

		if (strcmp(server, nullstring) == 0) {
		/* depends on a hack in ypbind */
			struct nd_hostservlist *nhs = NULL;
			struct netconfig *nconf =
		response->ypbind_resp_u.ypbind_bindinfo->ypbind_nconf;
			struct netbuf *svcaddr =
		response->ypbind_resp_u.ypbind_bindinfo->ypbind_svcaddr;

			if (netdir_getbyaddr(nconf, &nhs, svcaddr) != ND_OK) {
				struct sockaddr_in	*sa4;
				struct sockaddr_in6	*sa6;
				char			buf[INET6_ADDRSTRLEN];
				char			xbuf[IPV6_ADDR_LEN];
				int			af;
				void			*addr;
				XDR			xdrs;

				sa4 = (struct sockaddr_in *)svcaddr->buf;
				af = ntohs(sa4->sin_family);
				if (af != sa4->sin_family) {
					xdrmem_create(&xdrs,
						(caddr_t)xbuf, IPV6_ADDR_LEN,
						XDR_DECODE);
					if (af == AF_INET6) {
						xdr_opaque(&xdrs,
							(caddr_t)svcaddr->buf,
							IPV6_ADDR_LEN);
						sa6 = (struct sockaddr_in6 *)
							xbuf;
						addr = &sa6->sin6_addr;
					} else {
						xdr_opaque(&xdrs,
							(caddr_t)svcaddr->buf,
							IPV4_ADDR_LEN);
						sa4 = (struct sockaddr_in *)
							xbuf;
						addr = &sa4->sin_addr;
					}
				} else {
					if (af == AF_INET6) {
						sa6 = (struct sockaddr_in6 *)
							svcaddr->buf;
						addr = &sa6->sin6_addr;
					} else {
						addr = &sa4->sin_addr;
					}
				}
				str = inet_ntop(af, addr, buf, sizeof (buf));
				if (str == NULL)
					perror("inet_ntop");
				else
					fprintf(stdout, "%s\n", str);
			} else {
				str = nhs->h_hostservs->h_host;
				if (str == NULL)
					str = "<unknown>";
				fprintf(stdout, "%s\n", str);
			}
			netdir_free((char *)nhs, ND_HOSTSERVLIST);
		} else {
			fprintf(stdout, "%s\n", server);
		}
	}
#ifdef DEBUG
	dump_response(response);
#endif
	return (TRUE);
}

/*
 * Serializes/deserializes an in_addr struct.
 *
 * Note:  There is a data coupling between the "definition" of a struct
 * in_addr implicit in this xdr routine, and the true data definition in
 * <netinet/in.h>.
 */
static bool xdr_yp_inaddr(xdrs, ps)
	XDR * xdrs;
	struct in_addr *ps;

{
	return (xdr_opaque(xdrs, (caddr_t)&ps->s_addr, 4));
}

/*
 * Serializes/deserializes an old ypbind_binding struct.
 */
static bool xdr_old_yp_binding(xdrs, ps)
	XDR * xdrs;
	struct old_ypbind_binding *ps;

{
	return (xdr_yp_inaddr(xdrs, &ps->ypbind_binding_addr) &&
	    xdr_opaque(xdrs, (caddr_t)&ps->ypbind_binding_port, 2));
}

/*
 * Serializes/deserializes a ypbind_resp structure.
 */
static bool xdr_old_ypbind_resp(xdrs, ps)
	XDR * xdrs;
	struct old_ypbind_resp *ps;

{
	if (!xdr_enum(xdrs, (enum_t *)&ps->ypbind_status)) {
		return (FALSE);
	}
	switch (ps->ypbind_status) {
	case YPBIND_SUCC_VAL:
		return (xdr_old_yp_binding(xdrs,
				&ps->ypbind_respbody.ypbind_bindinfo));
	case YPBIND_FAIL_VAL:
		return (xdr_u_long(xdrs,
				&ps->ypbind_respbody.ypbind_error));
	}
	return (FALSE);
}
/* This sends a message to the old ypbind process on host. */
static int old_call_binder(vers)
	int vers;
{
	CLIENT *client;
	struct hostent *hp;
	int sock = RPC_ANYSOCK;
	enum clnt_stat rpc_stat;
	struct old_ypbind_resp response;
	char errstring[256];
	extern struct rpc_createerr rpc_createerr;
	struct in_addr *server;

	if ((client = clnt_create(host, YPBINDPROG, vers, "udp")) == NULL) {
		if (rpc_createerr.cf_stat == RPC_PROGNOTREGISTERED) {
			(void) printf("ypwhich: %s is not running ypbind\n",
				host);
			exit(1);
		}
		if (rpc_createerr.cf_stat == RPC_PMAPFAILURE) {
		    (void) printf("ypwhich: %s is not running port mapper\n",
				host);
			exit(1);
		}
		(void) clnt_pcreateerror("ypwhich:  clnt_create error");
		exit(1);
	}

	rpc_stat = clnt_call(client, YPBINDPROC_DOMAIN,
			(xdrproc_t)xdr_ypdomain_wrap_string, (caddr_t)&domain,
			(xdrproc_t)xdr_old_ypbind_resp, (caddr_t)&response,
			timeout);

	if ((rpc_stat != RPC_SUCCESS) &&
	    (rpc_stat != RPC_PROGVERSMISMATCH)) {
		(void) sprintf(errstring,
		    "ypwhich: can't call ypbind on %s", host);
		(void) clnt_perror(client, errstring);
		exit(1);
	}

	clnt_destroy(client);
	close(sock);

	if ((rpc_stat != RPC_SUCCESS) ||
	    (response.ypbind_status != YPBIND_SUCC_VAL)) {
		return (FALSE);
	}

	server = &response.ypbind_respbody.ypbind_bindinfo.ypbind_binding_addr;
	print_server  (server);

	return (TRUE);
}

/*
 * For old version:
 * This translates a server address to a name and prints it.
 * We'll get a name by using the standard library routine.
 */
static void print_server(server)
	struct in_addr *server;
{
	char buf[256];
	struct hostent *hp;

	strcpy(buf, inet_ntoa(*server));
	hp = gethostbyaddr((char *)&server->s_addr,
			sizeof (struct in_addr), AF_INET);

	printf("%s\n", hp ? hp->h_name : buf);
}

#ifdef DEBUG
static void
dump_response(which)
ypbind_resp * which;
{
	struct netconfig *nc;
	struct netbuf *ua;
	ypbind_binding * b;

	int i;

	{
		b = which->ypbind_resp_u.ypbind_bindinfo;
		if (b == NULL)
			(void) fprintf(stderr, "???NO Binding information\n");
		else {
			(void) fprintf(stderr,
		"server=%s lovers=%ld hivers=%ld\n",
			    b->ypbind_servername,
				b->ypbind_lo_vers, b->ypbind_hi_vers);
			nc = b->ypbind_nconf;
			ua = b->ypbind_svcaddr;
			if (nc == NULL)
				(void) fprintf(stderr,
			"ypwhich: NO netconfig information\n");
			else {
				(void) fprintf(stderr,
		"ypwhich: id %s device %s flag %x protofmly %s proto %s\n",
		nc->nc_netid, nc->nc_device,
		(int)nc->nc_flag, nc->nc_protofmly,
		nc->nc_proto);
			}
			if (ua == NULL)
				(void) fprintf(stderr,
		"ypwhich: NO netbuf information available from binder\n");
			else {
				(void) fprintf(stderr,
			"maxlen=%d len=%d\naddr=", ua->maxlen, ua->len);
				for (i = 0; i < ua->len; i++) {
					if (i != (ua->len - 1))
						(void) fprintf(stderr,
					"%d.", ua->buf[i]);
					else
						(void) fprintf(stderr,
					"%d\n", ua->buf[i]);
				}
			}
		}
	}

}
#endif

/*
 * This translates a server address to a name and prints it.  If the address
 * is the same as the local address as returned by get_myaddress, the name
 * is that retrieved from the kernel.  If it's any other address (including
 * another ip address for the local machine), we'll get a name by using the
 * standard library routine (which calls the yp).
 */

/*
 * This asks any yp server for the map's master.
 */
static void
get_map_master()
{
	int err;
	char *master;

	err = __yp_master_rsvdport(domain, map, &master);

	if (err) {
		(void) fprintf(stderr,
		    "ypwhich:  Can't find the master of %s.  Reason: %s.\n",
		    map, yperr_string(err));
		exit(1);
	} else {
		(void) printf("%s\n", master);
	}
}

/*
 * This enumerates the entries within map "ypmaps" in the domain at global
 * "domain", and prints them out key and value per single line.  dump_ypmaps
 * just decides whether we are (probably) able to speak the new YP protocol,
 * and dispatches to the appropriate function.
 */
static void
dump_ypmaps()
{
	int err;
	struct dom_binding *binding;

	if (err = __yp_dobind(domain, &binding)) {
		(void) fprintf(stderr,
		    "dump_ypmaps: Can't bind for domain %s.  Reason: %s\n",
		    domain, yperr_string(err));
		return;
	}

	if (binding->dom_binding->ypbind_hi_vers  >= YPVERS) {
		dumpmaps(binding);
	}
}

static void
dumpmaps(binding)
struct dom_binding *binding;
{
	enum clnt_stat rpc_stat;
	int err;
	char *master;
	struct ypmaplist *pmpl;
	struct ypresp_maplist maplist;

	maplist.list = (struct ypmaplist *)NULL;

	rpc_stat = clnt_call(binding->dom_client, YPPROC_MAPLIST,
	    (xdrproc_t)xdr_ypdomain_wrap_string, (caddr_t)&domain,
	    (xdrproc_t)xdr_ypresp_maplist, (caddr_t)&maplist,
	    timeout);

	if (rpc_stat != RPC_SUCCESS) {
		(void) clnt_perror(binding->dom_client,
		    "ypwhich(dumpmaps): can't get maplist");
		__yp_rel_binding(binding);
		exit(1);
	}

	if (maplist.status != YP_TRUE) {
		(void) fprintf(stderr,
		    "ypwhich:  Can't get maplist.  Reason:  %s.\n",
		    yperr_string(ypprot_err(maplist.status)));
		exit(1);
	}
	__yp_rel_binding(binding);

	for (pmpl = maplist.list; pmpl; pmpl = pmpl->ypml_next) {
		(void) printf("%s ", pmpl->ypml_name);

		err = __yp_master_rsvdport(domain, pmpl->ypml_name, &master);

		if (err) {
			(void) printf("????????\n");
			(void) fprintf(stderr,
		"ypwhich:  Can't find the master of %s.  Reason: %s.\n",
		pmpl->ypml_name, yperr_string(err));
		} else {
			(void) printf("%s\n", master);
		}
	}
}
