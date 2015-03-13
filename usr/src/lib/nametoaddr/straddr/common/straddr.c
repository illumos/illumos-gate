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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	 All Rights Reserved 	*/

#include <ctype.h>
#include <stdio.h>
#include <tiuser.h>
#include <netdir.h>
#include <netconfig.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <string.h>
#include <stdlib.h>

/*
 *	The generic name to address mappings for any transport that
 *	has strings for address (e.g., ISO Starlan).
 *
 *	Address in ISO Starlan consist of arbitrary strings of
 *	characters.  Because of this, the following routines
 *	create an "address" based on two strings, one gotten
 *	from a "host" file and one gotten from a "services" file.
 *	The two strings are catenated together (with a "." between
 *	them).  The hosts file is /etc/net/starlan/hosts and
 *	contain lines of the form:
 *
 *		arbitrary_string	machname
 *
 *	To make things simple, the "arbitrary string" should be the
 *	machine name.
 *
 *	The services file is /etc/net/starlan/services and has lines
 *	of the form:
 *
 *		service_name	arbitrary_string
 *
 *	Again, to make things easer, the "arbitrary name" should be the
 *	service name.
 */

#define	HOSTFILE	"/etc/net/%s/hosts"
#define	SERVICEFILE	"/etc/net/%s/services"
#define	FIELD1		1
#define	FIELD2		2
#define	LOCALHOST	"localhost"

static int searchhost(struct netconfig *, char *, int, char *);
static int searchserv(struct netconfig *, char *, int, char *);

/*
 *	_netdir_getbyname() returns all of the addresses for
 *	a specified host and service.
 */

struct nd_addrlist *
_netdir_getbyname(struct netconfig *netconfigp,
    struct nd_hostserv *nd_hostservp)
{
	char   fulladdr[BUFSIZ];   /* holds the full address string	   */
	struct nd_addrlist *retp;  /* the return structure		   */
	struct netbuf *netbufp;    /* indexes through the addresses	   */

	/*
	 *	HOST_BROADCAST is not supported.
	 */

	if (strcmp(nd_hostservp->h_host, HOST_BROADCAST) == 0) {
		_nderror = ND_NOHOST;
		return (NULL);
	}

	if (searchhost(netconfigp, nd_hostservp->h_host, FIELD2,
	    fulladdr) == 0) {
		_nderror = ND_NOHOST;
		return (NULL);
	}

	/*
	 *	Now simply fill in the address by forming strings of the
	 *	form "string_from_hosts.string_from_services"
	 */

	if (nd_hostservp->h_serv &&
	    (strcmp(nd_hostservp->h_serv, "rpcbind") == 0)) {
		(void) strcat(fulladdr, ".");
		(void) strcat(fulladdr, "rpc");	/* hard coded */
	} else {
		/*
		 *	Get the address from the services file
		 */

		if (nd_hostservp->h_serv && (nd_hostservp->h_serv[0] != '\0')) {
			(void) strcat(fulladdr, ".");
			if (searchserv(netconfigp, nd_hostservp->h_serv, FIELD1,
			    fulladdr + strlen(fulladdr)) == 0) {
				_nderror = ND_NOSERV;
				return (NULL);
			}
		}
	}

	if ((retp = malloc(sizeof (struct nd_addrlist))) == NULL) {
		_nderror = ND_NOMEM;
		return (NULL);
	}

	/*
	 *	We do not worry about multiple addresses here.  Loopbacks
	 *	have only one interface.
	 */

	retp->n_cnt = 1;
	if ((retp->n_addrs = malloc(sizeof (struct netbuf))) == NULL) {
		free(retp);
		_nderror = ND_NOMEM;
		return (NULL);
	}

	netbufp = retp->n_addrs;

	/*
	 *	Don't include the terminating NULL character in the
	 *	length.
	 */

	netbufp->len = netbufp->maxlen = (int)strlen(fulladdr);
	if ((netbufp->buf = strdup(fulladdr)) == NULL) {
		free(netbufp);
		free(retp);
		_nderror = ND_NOMEM;
		return (NULL);
	}
	_nderror = ND_OK;
	return (retp);
}

/*
 *	_netdir_getbyaddr() takes an address (hopefully obtained from
 *	someone doing a _netdir_getbyname()) and returns all hosts with
 *	that address.
 */

struct nd_hostservlist *
_netdir_getbyaddr(struct netconfig *netconfigp, struct netbuf *netbufp)
{
	char   fulladdr[BUFSIZ];	  /* a copy of the address string   */
	char   servbuf[BUFSIZ];		  /* a buffer for service string    */
	char   hostbuf[BUFSIZ];		  /* points to list of host names   */
	char   *hostname;		  /* the "first" path of the string */
	char   *servname;		  /* the "second" part of string    */
	struct nd_hostservlist *retp;	  /* the return structure	    */
	char   *serv;			  /* resultant service name obtained */
	int    nhost;			  /* the number of hosts in hostpp  */
	struct nd_hostserv *nd_hostservp; /* traverses the host structures  */
	char   *nexttok;		  /* next token to process	    */

	/*
	 *	Separate the two parts of the address string.
	 */

	(void) strlcpy(fulladdr, netbufp->buf, sizeof (fulladdr));
	hostname = strtok_r(fulladdr, ".", &nexttok);
	if (hostname == NULL) {
		_nderror = ND_NOHOST;
		return (NULL);
	}
	servname = strtok_r(NULL, " \n\t", &nexttok);

	/*
	 *	Search for all the hosts associated with the
	 *	first part of the address string.
	 */

	nhost = searchhost(netconfigp, hostname, FIELD1, hostbuf);
	if (nhost == 0) {
		_nderror = ND_NOHOST;
		return (NULL);
	}

	/*
	 *	Search for the service associated with the second
	 *	path of the address string.
	 */

	if (servname == NULL) {
		_nderror = ND_NOSERV;
		return (NULL);
	}

	servbuf[0] = '\0';
	serv = servbuf;
	if (searchserv(netconfigp, servname, FIELD2, servbuf) == 0) {
		serv = _taddr2uaddr(netconfigp, netbufp);
		(void) strcpy(servbuf, serv);
		free(serv);
		serv = servbuf;
		while (*serv != '.')
			serv++;
	}

	/*
	 *	Allocate space to hold the return structure, set the number
	 *	of hosts, and allocate space to hold them.
	 */

	if ((retp = malloc(sizeof (struct nd_hostservlist))) == NULL) {
		_nderror = ND_NOMEM;
		return (NULL);
	}

	retp->h_cnt = nhost;
	retp->h_hostservs = calloc(nhost, sizeof (struct nd_hostserv));
	if (retp->h_hostservs == NULL) {
		free(retp);
		_nderror = ND_NOMEM;
		return (NULL);
	}

	/*
	 *	Loop through the host structues and fill them in with
	 *	each host name (and service name).
	 */

	nd_hostservp = retp->h_hostservs;
	hostname = strtok_r(hostbuf, ",", &nexttok);
	while (hostname && nhost--) {
		if (((nd_hostservp->h_host = strdup(hostname)) == NULL) ||
		    ((nd_hostservp->h_serv = strdup(serv)) == NULL)) {
			netdir_free(retp, ND_HOSTSERVLIST);
			_nderror = ND_NOMEM;
			return (NULL);
		}
		nd_hostservp++;
		hostname = strtok_r(NULL, ",", &nexttok);
	}

	_nderror = ND_OK;
	return (retp);
}

/*
 *	_taddr2uaddr() translates a address into a "universal" address.
 *	Since the address is a string, simply return the string as the
 *	universal address (but replace all non-printable characters with
 *	the \ddd form, where ddd is three octal digits).  The '\n' character
 *	is also replace by \ddd and the '\' character is placed as two
 *	'\' characters.
 */

/* ARGSUSED */
char *
_taddr2uaddr(struct netconfig *netconfigp, struct netbuf *netbufp)
{
	char *retp;	/* pointer the return string			*/
	char *to;	/* traverses and populates the return string	*/
	char *from;	/* traverses the string to be converted		*/
	int i;		/* indexes through the given string		*/

	/*
	 * BUFSIZ is perhaps too big for this one and there is a better
	 * way to optimize it, but for now we will just assume BUFSIZ
	 */
	if ((retp = malloc(BUFSIZ)) == NULL) {
		_nderror = ND_NOMEM;
		return (NULL);
	}
	to = retp;
	from = netbufp->buf;

	for (i = 0; i < netbufp->len; i++) {
		if (*from == '\\') {
			*to++ = '\\';
			*to++ = '\\';
		} else {
			if (*from == '\n' || !isprint((unsigned char)*from)) {
				(void) sprintf(to, "\\%.3o", *from & 0xff);
				to += 4;
			} else {
				*to++ = *from;
			}
		}
		from++;
	}
	*to = '\0';
	return (retp);
}

/*
 *	_uaddr2taddr() translates a universal address back into a
 *	netaddr structure.  Since the universal address is a string,
 *	put that into the TLI buffer (making sure to change all \ddd
 *	characters back and strip off the trailing \0 character).
 */

/* ARGSUSED */
struct netbuf *
_uaddr2taddr(struct netconfig *netconfigp, char *uaddr)
{
	struct netbuf *retp;	/* the return structure			   */
	char *holdp;		/* holds the converted address		   */
	char *to;		/* traverses and populates the new address */
	char *from;		/* traverses the universal address	   */

	holdp = malloc(strlen(uaddr) + 1);
	if (holdp == NULL) {
		_nderror = ND_NOMEM;
		return (NULL);
	}
	from = uaddr;
	to = holdp;

	while (*from) {
		if (*from == '\\') {
			if (*(from+1) == '\\') {
				*to = '\\';
				from += 2;
			} else {
				*to = ((*(from+1) - '0') << 6) +
				    ((*(from+2) - '0') << 3) +
				    (*(from+3) - '0');
				from += 4;
			}
		} else {
			*to = *from++;
		}
		to++;
	}
	*to = '\0';

	if ((retp = malloc(sizeof (struct netbuf))) == NULL) {
		free(holdp);
		_nderror = ND_NOMEM;
		return (NULL);
	}
	retp->maxlen = retp->len = (int)(to - holdp);
	retp->buf = holdp;
	return (retp);
}

/*
 *	_netdir_options() is a "catch-all" routine that does
 *	transport specific things.  The only thing that these
 *	routines have to worry about is ND_MERGEADDR.
 */

/* ARGSUSED */
int
_netdir_options(struct netconfig *netconfigp, int option, int fd, void *par)
{
	struct nd_mergearg *argp;  /* the argument for mergeaddr */

	switch (option) {
	case ND_MERGEADDR:
		/*
		 *	Translate the universal address into something that
		 *	makes sense to the caller.  This is a no-op in
		 *	loopback's case, so just return the universal address.
		 */
		argp = (struct nd_mergearg *)par;
		argp->m_uaddr = strdup(argp->s_uaddr);
		if (argp->m_uaddr == NULL) {
			_nderror = ND_NOMEM;
			return (-1);
		}
		return (0);
	default:
		_nderror = ND_NOCTRL;
		return (-1);
	}
}

/*
 *	searchhost() looks for the specified token in the host file.
 *	The "field" parameter signifies which field to compare the token
 *	on, and returns all comma separated values associated with the token.
 */

static int
searchhost(struct netconfig *netconfigp, char *token, int field, char *hostbuf)
{
	char searchfile[MAXPATHLEN];  /* the name of file to be opened	    */
	char buf[BUFSIZ];	/* holds each line of the file		    */
	char *fileaddr;		/* the first token in each line		    */
	char *filehost;		/* the second token in each line	    */
	char *cmpstr;		/* the string to compare token to	    */
	char *retstr;		/* the string to return if compare succeeds */
	char *nexttok;		/* next token to process		    */
	FILE *fp;		/* the opened searchfile		    */
	int   nelements = 0;	/* total number of elements found	    */
	struct utsname utsname;

	/*
	 *	Unless /etc/netconfig has been altered, the only transport that
	 *	will use straddr.so is loopback.  In this case, we always
	 *	return "localhost" if either our nodename, or "localhost", or
	 *	some of special-case host names were passed, or we fail.
	 */

	if ((strcmp(token, HOST_SELF_BIND) == 0) ||
	    (strcmp(token, HOST_SELF_CONNECT) == 0) ||
	    (strcmp(token, HOST_ANY) == 0) ||
	    (strcmp(token, LOCALHOST) == 0) ||
	    (uname(&utsname) >= 0 && strcmp(token, utsname.nodename) == 0)) {
		(void) strcpy(hostbuf, LOCALHOST);
		return (1);
	}

	if (strcmp(netconfigp->nc_protofmly, NC_LOOPBACK) == 0)
		return (0);

	/*
	 * 	We only get here if an administrator has modified
	 * 	/etc/netconfig to use straddr.so for a transport other than
	 * 	loopback (which is questionable but something we'll need to
	 * 	EOL at a later point in time).  In this case, we fallback to
	 * 	searching for the associated key in the appropriate hosts
	 * 	file (based on nc_netid).
	 */

	(void) snprintf(searchfile, sizeof (searchfile), HOSTFILE,
	    netconfigp->nc_netid);

	fp = fopen(searchfile, "rF");
	if (fp == NULL)
		return (0);

	/*
	 *	Loop through the file looking for the tokens and creating
	 *	the list of strings to be returned.
	 */

	while (fgets(buf, BUFSIZ, fp) != NULL) {

		/*
		 *	Ignore comments and bad lines.
		 */

		fileaddr = strtok_r(buf, " \t\n", &nexttok);
		if (fileaddr == NULL || *fileaddr == '#')
			continue;

		if ((filehost = strtok_r(NULL, " \t\n", &nexttok)) == NULL)
			continue;

		/*
		 *	determine which to compare the token to, then
		 *	compare it, and if they match, add the return
		 *	string to the list.
		 */

		cmpstr = (field == FIELD1)? fileaddr : filehost;
		retstr = (field == FIELD1)? filehost : fileaddr;

		if (strcmp(token, cmpstr) == 0) {
			nelements++;
			if (field == FIELD2) {
				/*
				 * called by _netdir_getbyname
				 */

				(void) strcpy(hostbuf, retstr);
				break;
			}
			if (nelements > 1) {
				/*
				 * Assuming that "," will never be a part
				 * of any host name.
				 */
				(void) strcat(hostbuf, ",");
			}
			(void) strcat(hostbuf, retstr);
		}
	}

	(void) fclose(fp);
	return (nelements);
}

/*
 *	searchserv() looks for the specified token in the service file.
 *	The "field" parameter signifies which field to compare the token
 *	on, and returns the string associated with the token in servname.
 */

static int
searchserv(struct netconfig *netconfigp, char *token, int field, char *servname)
{
	char searchfile[MAXPATHLEN];  /* the name of file to be opened  */
	char buf[BUFSIZ];	/* buffer space for lines in file	*/
	char *fileservice;	/* the first token in each line		*/
	char *fileport;		/* the second token in each line	*/
	char *cmpstr;		/* the string to compare the token to	*/
	char *retstr;		/* temporarily hold token in line of file */
	char *nexttok;		/* next token to process		*/
	FILE *fp;		/* the opened searchfile		*/

	(void) snprintf(searchfile, sizeof (searchfile), SERVICEFILE,
	    netconfigp->nc_netid);

	fp = fopen(searchfile, "rF");
	if (fp == NULL)
		return (0);

	/*
	 *	Loop through the services file looking for the token.
	 */

	while (fgets(buf, BUFSIZ, fp) != NULL) {
		/*
		 *	If comment or bad line, continue.
		 */
		fileservice = strtok_r(buf, " \t\n", &nexttok);
		if (fileservice == NULL || *fileservice == '#')
			continue;

		if ((fileport = strtok_r(NULL, " \t\n", &nexttok)) == NULL)
			continue;

		cmpstr = (field == FIELD1)? fileservice : fileport;
		retstr = (field == FIELD1)? fileport : fileservice;

		if (strcmp(token, cmpstr) == 0) {
			(void) strcpy(servname, retstr);
			(void) fclose(fp);
			return (1);
		}
	}

	(void) fclose(fp);
	return (0);
}
