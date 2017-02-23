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
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Subroutines that implement the bootparam services.
 */

#include <rpcsvc/bootparam_prot.h>
#include <netdb.h>
#include <nlist.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <nsswitch.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/socket.h>
#define	KERNEL		/* to get RTHASHSIZ */
#include <sys/stream.h>
#include <net/route.h>
#undef	KERNEL
#include <net/if.h>			/* for structs ifnet and ifaddr */
#include <netinet/in.h>
#include <netinet/in_var.h>		/* for struct in_ifaddr */
#include <arpa/inet.h>

#include "bootparam_private.h"

#define	LINESIZE	1024

extern int getdomainname(char *, int);
extern int bootparams_getbyname(char *, char *, int);

static char *wildcard = "*";
static char domainkey[] = "domain=";
static void getf_printres(bp_getfile_res *);
static void copydomain(char *, char *, int);

/*
 * Whoami turns a client address into a client name
 * and suggested route machine.
 */
/*ARGSUSED1*/
bp_whoami_res *
bootparamproc_whoami_1(bp_whoami_arg *argp, CLIENT *cl)
{
	static bp_whoami_res res;
	struct in_addr clnt_addr;
	struct in_addr route_addr;
	struct hostent *hp;
	static char clnt_entry[LINESIZE];
	static char domain[MAX_MACHINE_NAME];
	char *cp;

	if (argp->client_address.address_type != IP_ADDR_TYPE) {
		if (debug) {
			msgout("Whoami failed: unknown address type %d",
				argp->client_address.address_type);
		}
		return (NULL);
	}
	(void) memcpy(&clnt_addr, &argp->client_address.bp_address_u.ip_addr,
	    sizeof (clnt_addr));
	hp = gethostbyaddr((char *)&clnt_addr, sizeof (clnt_addr), AF_INET);
	if (hp == NULL) {
		if (debug) {
			msgout("Whoami failed: gethostbyaddr for %s.",
				inet_ntoa(clnt_addr));
		}
		return (NULL);
	}

	/*
	 * We only answer requests from clients listed in the database.
	 */
	if ((bootparams_getbyname(hp->h_name, clnt_entry,
	    sizeof (clnt_entry)) != __NSW_SUCCESS) &&
	    (bootparams_getbyname(wildcard, clnt_entry,
	    sizeof (clnt_entry)) != __NSW_SUCCESS))
		return (NULL);

	res.client_name = hp->h_name;

	/*
	 * The algorithm for determining the client's domain name is:
	 * 	1) look for "domain=" in the client's bootparams line.
	 *	   If found, use its value.
	 *	2) look for a "domain=" entry in the wildcard bootparams
	 *	   line (if any).  If found, use its value.  Otherwise,
	 * 	3) return the domain name of the server answering the
	 *	   request.
	 */
	if (cp = strstr(clnt_entry, domainkey)) {
		copydomain(cp + sizeof (domainkey) - 1, domain,
		    sizeof (domain));
	} else {
		/* "domain=" not found - try for wildcard */
		if ((bootparams_getbyname(wildcard, clnt_entry,
			sizeof (clnt_entry)) == __NSW_SUCCESS) &&
			(cp = strstr(clnt_entry, domainkey))) {
			copydomain(cp + sizeof (domainkey) - 1, domain,
			    sizeof (domain));
		} else {
			(void) getdomainname(domain, sizeof (domain));
		}
	}
	res.domain_name = domain;

	res.router_address.address_type = IP_ADDR_TYPE;
	route_addr.s_addr = get_ip_route(clnt_addr);
	(void) memcpy(&res.router_address.bp_address_u.ip_addr,
	    &route_addr,
	    sizeof (res.router_address.bp_address_u.ip_addr));

	if (debug) {
		struct in_addr	in;

		(void) memcpy(&in.s_addr,
		    &res.router_address.bp_address_u.ip_addr,
		    sizeof (in.s_addr));
		msgout("Whoami returning name = %s, router address = %s",
		    res.client_name,
		    inet_ntoa(in));
	}
	return (&res);
}

/*
 * Getfile gets the client name and the key and returns its server
 * and the pathname for that key.
 */
/*ARGSUSED1*/
bp_getfile_res *
bootparamproc_getfile_1(bp_getfile_arg *argp, CLIENT *cl)
{
	static bp_getfile_res res;
	static char clnt_entry[LINESIZE];
	struct hostent *hp;
	char *cp;
	char filekey[LINESIZE];
	char *server_hostname;
	char *path_on_server;
	int do_wildcard = 0;
	static char *zero_len_string = "";

	/*
	 * The bootparams_getbyname() library function looks up a
	 * "client entry" using using the client's hostname as the
	 * key.  A client entry consists of a string of "file entries"
	 * separated by white space.  Each file entry is of the form:
	 *
	 *	file_key=server_hostname:path_on_server
	 *
	 * In the getfile RPC call, the client gives us its hostname
	 * and a file_key.  We lookup its client entry, then locate a
	 * file entry matching that file_key.  We then parse out the
	 * server_hostname and path_on_server from the file entry, map
	 * the server_hostname to an IP address, and return both the
	 * IP address and path_on_server back to the client.
	 */

	/* make the client's file key int a string we can use for matching */
	(void) strncpy(filekey, argp->file_id, sizeof (filekey) - 2);
	filekey[sizeof (filekey) - 2] = '\0';
	(void) strcat(filekey, "=");

	if (bootparams_getbyname(argp->client_name, clnt_entry,
	    sizeof (clnt_entry)) == __NSW_SUCCESS) {
		/* locate the file_key in the client's entry */
		cp = strstr(clnt_entry, filekey);
		if (cp == NULL)
			do_wildcard++;

	} else
		do_wildcard++;

	if (do_wildcard) {
		if (bootparams_getbyname(wildcard, clnt_entry,
		    sizeof (clnt_entry)) != __NSW_SUCCESS)
			return (NULL);

		/* locate the file_key in the client's entry */
		cp = strstr(clnt_entry, filekey);
		if (cp == NULL)
			return (NULL);
	}

	/* locate the "data" part of file entry (r.h.s. of "=") */
	cp = strchr(cp, '=');
	if (cp == NULL)
		return (NULL);
	cp++;
	if (*cp == '\0')
		return (NULL);
	server_hostname = cp;

	/* null-terminate server_hostname and parse path_on_server */
	cp = strchr(server_hostname, ':');
	if (cp == NULL)
		return (NULL);
	*cp = '\0';
	cp++;
	/* strtok() will null-terminate path_on_server */
	path_on_server = strtok(cp, "\t\n ");
	if (path_on_server == NULL)
		path_on_server = zero_len_string;

	res.server_name = server_hostname;
	res.server_path = path_on_server;
	if (*res.server_name == 0) {
		res.server_address.address_type = IP_ADDR_TYPE;
		(void) memset(&res.server_address.bp_address_u.ip_addr, 0,
		    sizeof (res.server_address.bp_address_u.ip_addr));
	} else {
		in_addr_t addr;

		if ((hp = gethostbyname(server_hostname)) != NULL) {
			addr = find_best_server_int(hp->h_addr_list,
			    argp->client_name);
		} else {
			addr = inet_addr(server_hostname);
			if (addr == INADDR_BROADCAST) {
				if (debug) {
					msgout("getfile_1: gethostbyname(%s) "
					    "failed", res.server_name);
				}
				return (NULL);
			}
		}
		res.server_address.address_type = IP_ADDR_TYPE;
		(void) memcpy(&res.server_address.bp_address_u.ip_addr,
		    &addr, sizeof (res.server_address.bp_address_u.ip_addr));
	}
	if (debug) {
		getf_printres(&res);
	}
	return (&res);
}

void
getf_printres(bp_getfile_res *res)
{
	struct in_addr	in;

	(void) memcpy(&in.s_addr, &res->server_address.bp_address_u.ip_addr,
	    sizeof (in.s_addr));
	msgout("getfile_1: file is \"%s\" %s \"%s\"",
	    res->server_name,
	    inet_ntoa(in),
	    res->server_path);
}

/*
 * Used when we've found a "domain=" key, this function copies characters
 * from source to target until we come upon either a NULL or whitespace is
 * found in the source string, or we run out of room in the target.
 *
 */
void
copydomain(char *source, char *target, int len)
{
	int n;			/* number of characters copies */;

	len--;			/* leave room for terminating '\0' */
	if (source)
		for (n = 0; *source != '\0' && n < len; n++)
			if (isspace((int)*source))
				break;
			else
				*target++ = *source++;

	*target = '\0';
}
