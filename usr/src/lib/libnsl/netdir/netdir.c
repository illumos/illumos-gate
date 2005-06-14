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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * netdir.c
 *
 * This is the library routines that do the name to address
 * translation.
 */

#include "mt.h"
#include "../rpc/rpc_mt.h"		/* for MT declarations only */
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <tiuser.h>
#include <netdir.h>
#include <netconfig.h>
#include <string.h>
#include <sys/file.h>
#include <dlfcn.h>
#include <rpc/trace.h>
#include <malloc.h>
#include <syslog.h>
#include <nss_netdir.h>
#include <netinet/in.h>
#include <netdb.h>

/* messaging stuff. */

extern const char __nsl_dom[];
extern char *dgettext(const char *, const char *);

struct translator {
	struct nd_addrlist	*(*gbn)();	/* _netdir_getbyname	*/
	struct nd_hostservlist 	*(*gba)();	/* _netdir_getbyaddr	*/
	int			(*opt)();	/* _netdir_options	*/
	char			*(*t2u)();	/* _taddr2uaddr		*/
	struct netbuf		*(*u2t)();	/* _uaddr2taddr		*/
	void			*tr_fd;		/* dyn library handle	*/
	char			*tr_name;	/* Full path		*/
	struct translator	*next;
};

/*
 * xlate_lock protects xlate_list during updates only.  The xlate_list linked
 * list is pre-pended when new entries are added, so threads that are already
 * using the list will continue correctly to the end of the list.
 */
static struct translator *xlate_list = NULL;
static mutex_t xlate_lock = DEFAULTMUTEX;

static struct translator *load_xlate(char *);

/*
 * This is the common data (global data) that is exported
 * by public interfaces. It has been moved here from nd_comdata.c
 * which no longer exists. This fixes the problem for applications
 * that do not link directly with -lnsl but dlopen a shared object
 * that has a NEEDED dependency on -lnsl and uses the netdir
 * interface.
 */

#undef	_nderror

int	_nderror;

int *
__nderror()
{
	static pthread_key_t nderror_key = 0;
	int *ret;

	if (thr_main())
		return (&_nderror);
	ret = thr_get_storage(&nderror_key, sizeof (int), free);
	/* if thr_get_storage fails we return the address of _nderror */
	return (ret ? ret : &_nderror);
}

#define	_nderror	(*(__nderror()))

/*
 * Adds a translator library to the xlate_list, but first check to see if
 * it's already on the list.  Must be called while holding xlate_lock.
 * We have to be careful for the case of the same library being loaded
 * with different names (e.g., straddr.so and /usr/lib/straddr.so).
 * We check for this case by looking at the gbn and name fields.
 * If the gbn address is the same, but the names are different, then we
 * have accidentally reloaded the library.  We dlclose the new version,
 * and then update 'translate' with the old versions of the symbols.
 */
void
add_to_xlate_list(translate)
struct translator *translate;
{
	struct translator	*t;

	for (t = xlate_list; t; t = t->next) {
		if (strcmp(translate->tr_name, t->tr_name) == 0) {
			return;
		}
	}
	translate->next = xlate_list;
	xlate_list = translate;
}

/*
 * This routine is the main routine that resolves host/service/xprt triples
 * into a bunch of netbufs that should connect you to that particular
 * service. RPC uses it to contact the binder service (rpcbind).
 *
 * In the interest of consistency with the gethost/servbyYY() routines,
 * this routine calls a common interface _get_hostserv_inetnetdir_byname
 * if it's called with a netconfig with "inet" type transports and
 * an empty list of nametoaddr libs (i.e. a "-" in /etc/netconfig),
 * which indicates the use of the switch. For non-inet transports or
 * inet transports with nametoaddr libs specified, it simply calls
 * the SVr4-classic netdir_getbyname, which loops through the libs.
 *
 * After all, any problem can be solved by one more layer of abstraction..
 *
 * This routine when called with a netconfig with "inet6" type of transports
 * returns pure IPv6 addresses only and if no IPv6 address is found it
 * returns none - Bug Id. 4276329
 */
int
netdir_getbyname(tp, serv, addrs)
	struct netconfig	*tp;	/* The network config entry	*/
	struct nd_hostserv	*serv;	/* the service, host pair	*/
	struct nd_addrlist	**addrs; /* the answer			*/
{
	trace1(TR_netdir_getbyname, 0);
	if (tp == 0) {
		_nderror = ND_BADARG;
		trace1(TR_netdir_getbyname, 1);
		return (_nderror);
	}
	if ((strcmp(tp->nc_protofmly, NC_INET) == 0) &&
		(tp->nc_nlookups == 0)) {
		struct	nss_netdirbyname_in nssin;
		union	nss_netdirbyname_out nssout;

		nssin.op_t = NETDIR_BY;
		nssin.arg.nd_hs = serv;
		/*
		 * In code path of case NETDIR_BY,
		 * it also calls DOOR_GETIPNODEBYNAME_R.
		 * So af_family and flags are set to
		 * get V4 addresses only.
		 */
		nssin.arg.nss.host6.af_family = AF_INET;
		nssin.arg.nss.host6.flags = 0;
		nssout.nd_alist = addrs;
		return (_get_hostserv_inetnetdir_byname(tp, &nssin, &nssout));
	} else if ((strcmp(tp->nc_protofmly, NC_INET6) == 0) &&
		(tp->nc_nlookups == 0)) {
		struct	nss_netdirbyname_in nssin;
		union	nss_netdirbyname_out nssout;

		nssin.op_t = NETDIR_BY6;
		nssin.arg.nd_hs = serv;
		/* get both V4 & V6 addresses */
		nssin.arg.nss.host6.af_family = AF_INET6;
		nssin.arg.nss.host6.flags = (AI_ALL | AI_V4MAPPED);
		nssout.nd_alist = addrs;
		return (_get_hostserv_inetnetdir_byname(tp, &nssin, &nssout));
	} else {
		trace1(TR_netdir_getbyname, 1);
		return (__classic_netdir_getbyname(tp, serv, addrs));
	}
}

/*
 * This routine is the svr4_classic routine for resolving host/service/xprt
 * triples into a bunch of netbufs that should connect you to that particular
 * service. RPC uses it to contact the binder service (rpcbind).
 *
 * It's either called by the real netdir_getbyname() interface above
 * or by gethost/servbyname when nametoaddr libs are specified in
 * /etc/netconfig with an intent of bypassing the name service switch.
 */
int
__classic_netdir_getbyname(tp, serv, addrs)
	struct netconfig	*tp;	/* The network config entry	*/
	struct nd_hostserv	*serv;	/* the service, host pair	*/
	struct nd_addrlist	**addrs; /* the answer			*/
{
	struct translator	*t;	/* pointer to translator list	*/
	struct nd_addrlist	*nn;	/* the results			*/
	char			*lr;	/* routines to try		*/
	int			i;	/* counts the routines		*/

	trace1(TR_netdir_getbyname, 0);
	_nderror = ND_SYSTEM;
	for (i = 0; i < tp->nc_nlookups; i++) {
		lr = *((tp->nc_lookups) + i);
		for (t = xlate_list; t; t = t->next) {
			if (strcmp(lr, t->tr_name) == 0) {
				nn = (*(t->gbn))(tp, serv);
				if (nn) {
					*addrs = nn;
					trace1(TR_netdir_getbyname, 1);
					return (0);
				} else {
					if (_nderror < 0) {
						trace1(TR_netdir_getbyname, 1);
						return (_nderror);
					}
					break;
				}
			}
		}
		/* If we didn't find it try loading it */
		if (!t) {
			if ((t = load_xlate(lr)) != NULL) {
				/* add it to the list */
				mutex_lock(&xlate_lock);
				add_to_xlate_list(t);
				mutex_unlock(&xlate_lock);
				nn = (*(t->gbn))(tp, serv);
				if (nn) {
					*addrs = nn;
					trace1(TR_netdir_getbyname, 1);
					return (0);
				} else {
					if (_nderror < 0) {
						trace1(TR_netdir_getbyname, 1);
						return (_nderror);
					}
				}
			} else {
				if (_nderror == ND_SYSTEM) { /* retry cache */
					_nderror = ND_OK;
					i--;
					continue;
				}
			}
		}
	}
	trace1(TR_netdir_getbyname, 1);
	return (_nderror);	/* No one works */
}

/*
 * This routine is similar to the one above except that it tries to resolve
 * the name by the address passed.
 */
int
netdir_getbyaddr(tp, serv, addr)
	struct netconfig	*tp;	/* The netconfig entry		*/
	struct nd_hostservlist	**serv;	/* the answer(s)		*/
	struct netbuf		*addr;	/* the address we have		*/
{
	trace1(TR_netdir_getbyaddr, 0);
	if (tp == 0) {
		_nderror = ND_BADARG;
		trace1(TR_netdir_getbyaddr, 1);
		return (_nderror);
	}
	if ((strcmp(tp->nc_protofmly, NC_INET) == 0) &&
		(tp->nc_nlookups == 0)) {
		struct	nss_netdirbyaddr_in nssin;
		union	nss_netdirbyaddr_out nssout;

		nssin.op_t = NETDIR_BY;
		nssin.arg.nd_nbuf = addr;
		nssout.nd_hslist = serv;
		trace1(TR_netdir_getbyaddr, 1);
		return (_get_hostserv_inetnetdir_byaddr(tp, &nssin, &nssout));
	} else if ((strcmp(tp->nc_protofmly, NC_INET6) == 0) &&
		(tp->nc_nlookups == 0)) {
		struct	nss_netdirbyaddr_in nssin;
		union	nss_netdirbyaddr_out nssout;

		nssin.op_t = NETDIR_BY6;
		nssin.arg.nd_nbuf = addr;
		nssout.nd_hslist = serv;
		trace1(TR_netdir_getbyaddr, 1);
		return (_get_hostserv_inetnetdir_byaddr(tp, &nssin, &nssout));
	} else {
		trace1(TR_netdir_getbyaddr, 1);
		return (__classic_netdir_getbyaddr(tp, serv, addr));
	}
}
/*
 * This routine is similar to the one above except that it instructs the
 * _get_hostserv_inetnetdir_byaddr not to do a service lookup.
 */
int
__netdir_getbyaddr_nosrv(tp, serv, addr)
	struct netconfig	*tp;	/* The netconfig entry		*/
	struct nd_hostservlist	**serv;	/* the answer(s)		*/
	struct netbuf		*addr;	/* the address we have		*/
{
	trace1(TR_netdir_getbyaddr, 0);
	if (tp == 0) {
		_nderror = ND_BADARG;
		trace1(TR_netdir_getbyaddr, 1);
		return (_nderror);
	}
	if ((strcmp(tp->nc_protofmly, NC_INET) == 0) &&
		(tp->nc_nlookups == 0)) {
		struct	nss_netdirbyaddr_in nssin;
		union	nss_netdirbyaddr_out nssout;

		nssin.op_t = NETDIR_BY_NOSRV;
		nssin.arg.nd_nbuf = addr;
		nssout.nd_hslist = serv;
		trace1(TR_netdir_getbyaddr, 1);
		return (_get_hostserv_inetnetdir_byaddr(tp, &nssin, &nssout));
	} else if ((strcmp(tp->nc_protofmly, NC_INET6) == 0) &&
		(tp->nc_nlookups == 0)) {
		struct	nss_netdirbyaddr_in nssin;
		union	nss_netdirbyaddr_out nssout;

		nssin.op_t = NETDIR_BY_NOSRV6;
		nssin.arg.nd_nbuf = addr;
		nssout.nd_hslist = serv;
		trace1(TR_netdir_getbyaddr, 1);
		return (_get_hostserv_inetnetdir_byaddr(tp, &nssin, &nssout));
	} else {
		trace1(TR_netdir_getbyaddr, 1);
		return (__classic_netdir_getbyaddr(tp, serv, addr));
	}
}

/*
 * This routine is the svr4_classic routine for resolving a netbuf struct
 * into a bunch of host/service name pairs.
 *
 * It's either called by the real netdir_getbyaddr() interface above
 * or by gethost/servbyaddr when nametoaddr libs are specified in
 * /etc/netconfig with an intent of bypassing the name service switch.
 */
int
__classic_netdir_getbyaddr(tp, serv, addr)
	struct netconfig	*tp;	/* The netconfig entry		*/
	struct nd_hostservlist	**serv;	/* the answer(s)		*/
	struct netbuf		*addr;	/* the address we have		*/
{
	struct translator	*t;	/* pointer to translator list	*/
	struct nd_hostservlist	*hs;	/* the results			*/
	char			*lr;	/* routines to try		*/
	int			i;	/* counts the routines		*/

	trace1(TR_netdir_getbyaddr, 0);
	_nderror = ND_SYSTEM;
	for (i = 0; i < tp->nc_nlookups; i++) {
		lr = *((tp->nc_lookups) + i);
		for (t = xlate_list; t; t = t->next) {
			if (strcmp(lr, t->tr_name) == 0) {
				hs = (*(t->gba))(tp, addr);
				if (hs) {
					*serv = hs;
					trace1(TR_netdir_getbyaddr, 1);
					return (0);
				} else {
					if (_nderror < 0) {
						trace1(TR_netdir_getbyaddr, 1);
						return (_nderror);
					}
					break;
				}
			}
		}
		/* If we didn't find it try loading it */
		if (!t) {
			if ((t = load_xlate(lr)) != NULL) {
				/* add it to the list */
				mutex_lock(&xlate_lock);
				add_to_xlate_list(t);
				mutex_unlock(&xlate_lock);
				hs = (*(t->gba))(tp, addr);
				if (hs) {
					*serv = hs;
					trace1(TR_netdir_getbyaddr, 1);
					return (0);
				} else {
					if (_nderror < 0) {
						trace1(TR_netdir_getbyaddr, 1);
						return (_nderror);
					}
				}
			} else {
				if (_nderror == ND_SYSTEM) { /* retry cache */
					_nderror = ND_OK;
					i--;
					continue;
				}
			}
		}
	}
	trace1(TR_netdir_getbyaddr, 1);
	return (_nderror);	/* No one works */
}

/*
 * This is the library routine to do transport specific stuff.
 * The code is same as the other similar routines except that it does
 * not bother to try whole bunch of routines since if the first
 * libray cannot resolve the option, then no one can.
 *
 * If it gets a netconfig structure for inet transports with nametoddr libs,
 * it simply calls the inet-specific built in implementation.
 */
int
netdir_options(tp, option, fd, par)
	struct netconfig	*tp;	/* the netconfig entry		*/
	int			option;	/* option number		*/
	int			fd;	/* open file descriptor		*/
	char			*par;	/* parameters if any		*/
{
	struct translator	*t;	/* pointer to translator list	*/
	char			*lr;	/* routines to try		*/
	int			i;	/* counts the routines		*/

	trace3(TR_netdir_options, 0, option, fd);
	if (tp == 0) {
		_nderror = ND_BADARG;
		trace3(TR_netdir_options, 1, option, fd);
		return (_nderror);
	}

	if ((strcmp(tp->nc_protofmly, NC_INET) == 0 ||
		strcmp(tp->nc_protofmly, NC_INET6) == 0) &&
		(tp->nc_nlookups == 0)) {
		trace3(TR_netdir_options, 1, option, fd);
		return (__inet_netdir_options(tp, option, fd, par));
	}


	for (i = 0; i < tp->nc_nlookups; i++) {
		lr = *((tp->nc_lookups) + i);
		for (t = xlate_list; t; t = t->next) {
			if (strcmp(lr, t->tr_name) == 0) {
				trace3(TR_netdir_options, 1, option, fd);
				return ((*(t->opt))(tp, option, fd, par));
			}
		}
		/* If we didn't find it try loading it */
		if (!t) {
			if ((t = load_xlate(lr)) != NULL) {
				/* add it to the list */
				mutex_lock(&xlate_lock);
				add_to_xlate_list(t);
				mutex_unlock(&xlate_lock);
				trace3(TR_netdir_options, 1, option, fd);
				return ((*(t->opt))(tp, option, fd, par));
			} else {
				if (_nderror == ND_SYSTEM) { /* retry cache */
					_nderror = ND_OK;
					i--;
					continue;
				}
			}
		}
	}
	trace3(TR_netdir_options, 1, option, fd);
	return (_nderror);	/* No one works */
}

/*
 * This is the library routine for translating universal addresses to
 * transport specific addresses. Again it uses the same code as above
 * to search for the appropriate translation routine. Only it doesn't
 * bother trying a whole bunch of routines since either the transport
 * can translate it or it can't.
 */
struct netbuf *
uaddr2taddr(tp, addr)
	struct netconfig	*tp;	/* the netconfig entry		*/
	char			*addr;	/* The address in question	*/
{
	struct translator	*t;	/* pointer to translator list 	*/
	struct netbuf		*x;	/* the answer we want 		*/
	char			*lr;	/* routines to try		*/
	int			i;	/* counts the routines		*/

	trace1(TR_uaddr2taddr, 0);
	if (tp == 0) {
		_nderror = ND_BADARG;
		trace1(TR_uaddr2taddr, 1);
		return (0);
	}
	if ((strcmp(tp->nc_protofmly, NC_INET) == 0 ||
		strcmp(tp->nc_protofmly, NC_INET6) == 0) &&
		(tp->nc_nlookups == 0)) {
		trace1(TR_uaddr2taddr, 1);
		return (__inet_uaddr2taddr(tp, addr));
	}
	for (i = 0; i < tp->nc_nlookups; i++) {
		lr = *((tp->nc_lookups) + i);
		for (t = xlate_list; t; t = t->next) {
			if (strcmp(lr, t->tr_name) == 0) {
				x = (*(t->u2t))(tp, addr);
				if (x) {
					trace1(TR_uaddr2taddr, 1);
					return (x);
				}
				if (_nderror < 0) {
					trace1(TR_uaddr2taddr, 1);
					return (0);
				}
			}
		}
		/* If we didn't find it try loading it */
		if (!t) {
			if ((t = load_xlate(lr)) != NULL) {
				/* add it to the list */
				mutex_lock(&xlate_lock);
				add_to_xlate_list(t);
				mutex_unlock(&xlate_lock);
				x = (*(t->u2t))(tp, addr);
				if (x) {
					trace1(TR_uaddr2taddr, 1);
					return (x);
				}
				if (_nderror < 0) {
					trace1(TR_uaddr2taddr, 1);
					return (0);
				}
			} else {
				if (_nderror == ND_SYSTEM) { /* retry cache */
					_nderror = ND_OK;
					i--;
					continue;
				}
			}
		}
	}
	trace1(TR_uaddr2taddr, 1);
	return (0);	/* No one works */
}

/*
 * This is the library routine for translating transport specific
 * addresses to universal addresses. Again it uses the same code as above
 * to search for the appropriate translation routine. Only it doesn't
 * bother trying a whole bunch of routines since either the transport
 * can translate it or it can't.
 */
char *
taddr2uaddr(tp, addr)
	struct netconfig	*tp;	/* the netconfig entry		*/
	struct netbuf		*addr;	/* The address in question	*/
{
	struct translator	*t;	/* pointer to translator list	*/
	char			*lr;	/* routines to try		*/
	char			*x;	/* the answer			*/
	int			i;	/* counts the routines		*/

	trace1(TR_taddr2uaddr, 0);
	if (tp == 0) {
		_nderror = ND_BADARG;
		trace1(TR_taddr2uaddr, 1);
		return (0);
	}
	if ((strcmp(tp->nc_protofmly, NC_INET) == 0 ||
		strcmp(tp->nc_protofmly, NC_INET6) == 0) &&
		(tp->nc_nlookups == 0)) {
		trace1(TR_taddr2uaddr, 1);
		return (__inet_taddr2uaddr(tp, addr));
	}
	for (i = 0; i < tp->nc_nlookups; i++) {
		lr = *((tp->nc_lookups) + i);
		for (t = xlate_list; t; t = t->next) {
			if (strcmp(lr, t->tr_name) == 0) {
				x = (*(t->t2u))(tp, addr);
				if (x) {
					trace1(TR_taddr2uaddr, 1);
					return (x);
				}
				if (_nderror < 0) {
					trace1(TR_taddr2uaddr, 1);
					return (0);
				}
			}
		}
		/* If we didn't find it try loading it */
		if (!t) {
			if ((t = load_xlate(lr)) != NULL) {
				/* add it to the list */
				mutex_lock(&xlate_lock);
				add_to_xlate_list(t);
				mutex_unlock(&xlate_lock);
				x = (*(t->t2u))(tp, addr);
				if (x) {
					trace1(TR_taddr2uaddr, 1);
					return (x);
				}
				if (_nderror < 0) {
					trace1(TR_taddr2uaddr, 1);
					return (0);
				}
			} else {
				if (_nderror == ND_SYSTEM) { /* retry cache */
					_nderror = ND_OK;
					i--;
					continue;
				}
			}
		}
	}
	trace1(TR_taddr2uaddr, 1);
	return (0);	/* No one works */
}

/*
 * This is the routine that frees the objects that these routines allocate.
 */
void
netdir_free(ptr, type)
	void	*ptr;	/* generic pointer	*/
	int	type;	/* thing we are freeing */
{
	struct netbuf		*na;
	struct nd_addrlist	*nas;
	struct nd_hostserv	*hs;
	struct nd_hostservlist	*hss;
	int			i;

	trace2(TR_netdir_free, 0, type);
	if (ptr == NULL) {
		trace2(TR_netdir_free, 1, type);
		return;
	}
	switch (type) {
	case ND_ADDR :
		na = (struct netbuf *)ptr;
		if (na->buf)
			free(na->buf);
		free((char *)na);
		break;

	case ND_ADDRLIST :
		nas = (struct nd_addrlist *)ptr;
		/*
		 * XXX: We do NOT try to free all individual netbuf->buf
		 * pointers. Free only the first one since they are allocated
		 * using one calloc in
		 * libnsl/nss/netdir_inet.c:order_haddrlist().
		 * This potentially causes memory leaks if a nametoaddr
		 * implementation -- from a third party -- has a different
		 * allocation scheme.
		 */
		if (nas->n_addrs->buf)
			free(nas->n_addrs->buf);
		free((char *)nas->n_addrs);
		free((char *)nas);
		break;

	case ND_HOSTSERV :
		hs = (struct nd_hostserv *)ptr;
		if (hs->h_host)
			free(hs->h_host);
		if (hs->h_serv)
			free(hs->h_serv);
		free((char *)hs);
		break;

	case ND_HOSTSERVLIST :
		hss = (struct nd_hostservlist *)ptr;
		for (hs = hss->h_hostservs, i = 0; i < hss->h_cnt; i++, hs++) {
			if (hs->h_host)
				free(hs->h_host);
			if (hs->h_serv)
				free(hs->h_serv);
		}
		free((char *)hss->h_hostservs);
		free((char *)hss);
		break;

	default :
		_nderror = ND_UKNWN;
		break;
	}
	trace2(TR_netdir_free, 1, type);
}

/*
 * load_xlate is a routine that will attempt to dynamically link in the
 * file specified by the network configuration structure.
 */
static struct translator *
load_xlate(name)
	char	*name;		/* file name to load */
{
	struct translator	*t;
	static struct xlate_list {
		char *library;
		struct xlate_list *next;
	} *xlistp = NULL;
	struct xlate_list *xlp, **xlastp;
	static mutex_t xlist_lock = DEFAULTMUTEX;

	trace1(TR_load_xlate, 0);
	mutex_lock(&xlist_lock);
	/*
	 * We maintain a list of libraries we have loaded.  Loading a library
	 * twice is double-plus ungood!
	 */
	for (xlp = xlistp, xlastp = &xlistp; xlp != NULL;
			xlastp = &xlp->next, xlp = xlp->next) {
		if (xlp->library != NULL) {
			if (strcmp(xlp->library, name) == 0) {
				_nderror = ND_SYSTEM;	/* seen this lib */
				mutex_unlock(&xlist_lock);
				trace1(TR_load_xlate, 1);
				return (0);
			}
		}
	}
	t = (struct translator *)malloc(sizeof (struct translator));
	if (!t) {
		_nderror = ND_NOMEM;
		mutex_unlock(&xlist_lock);
		trace1(TR_load_xlate, 1);
		return (0);
	}
	t->tr_name = strdup(name);
	if (!t->tr_name) {
		_nderror = ND_NOMEM;
		free((char *)t);
		mutex_unlock(&xlist_lock);
		trace1(TR_load_xlate, 1);
		return (NULL);
	}

	t->tr_fd = dlopen(name, RTLD_LAZY);
	if (t->tr_fd == NULL) {
		_nderror = ND_OPEN;
		goto error;
	}

	/* Resolve the getbyname symbol */
	t->gbn = (struct nd_addrlist *(*)())dlsym(t->tr_fd,
				"_netdir_getbyname");
	if (!(t->gbn)) {
		_nderror = ND_NOSYM;
		goto error;
	}

	/* resolve the getbyaddr symbol */
	t->gba = (struct nd_hostservlist *(*)())dlsym(t->tr_fd,
				"_netdir_getbyaddr");
	if (!(t->gba)) {
		_nderror = ND_NOSYM;
		goto error;
	}

	/* resolve the taddr2uaddr symbol */
	t->t2u = (char *(*)())dlsym(t->tr_fd, "_taddr2uaddr");
	if (!(t->t2u)) {
		_nderror = ND_NOSYM;
		goto error;
	}

	/* resolve the uaddr2taddr symbol */
	t->u2t = (struct netbuf *(*)())dlsym(t->tr_fd, "_uaddr2taddr");
	if (!(t->u2t)) {
		_nderror = ND_NOSYM;
		goto error;
	}

	/* resolve the netdir_options symbol */
	t->opt = (int (*)())dlsym(t->tr_fd, "_netdir_options");
	if (!(t->opt)) {
		_nderror = ND_NOSYM;
		goto error;
	}
	/*
	 * Add this library to the list of loaded libraries.
	 */
	*xlastp = (struct xlate_list *)malloc(sizeof (struct xlate_list));
	if (*xlastp == NULL) {
		_nderror = ND_NOMEM;
		goto error;
	}
	(*xlastp)->library = strdup(name);
	if ((*xlastp)->library == NULL) {
		_nderror = ND_NOMEM;
		free(*xlastp);
		goto error;
	}
	(*xlastp)->next = NULL;
	mutex_unlock(&xlist_lock);
	trace1(TR_load_xlate, 1);
	return (t);
error:
	if (t->tr_fd != NULL)
		(void) dlclose(t->tr_fd);
	free(t->tr_name);
	free((char *)t);
	mutex_unlock(&xlist_lock);
	trace1(TR_load_xlate, 1);
	return (NULL);
}


#define	NDERR_BUFSZ	512

/*
 * This is a routine that returns a string related to the current
 * error in _nderror.
 */
char *
netdir_sperror()
{
	static pthread_key_t nderrbuf_key = 0;
	static char buf_main[NDERR_BUFSZ];
	char	*str;
	char *dlerrstr;

	trace1(TR_netdir_sperror, 0);
	str = thr_main()?
		buf_main :
		thr_get_storage(&nderrbuf_key, NDERR_BUFSZ, free);
	if (str == NULL) {
		trace1(TR_netdir_sperror, 1);
		return (NULL);
	}
	dlerrstr = dlerror();
	switch (_nderror) {
	case ND_NOMEM :
		(void) snprintf(str, NDERR_BUFSZ,
			dgettext(__nsl_dom, "n2a: memory allocation failed"));
		break;
	case ND_OK :
		(void) snprintf(str, NDERR_BUFSZ,
			dgettext(__nsl_dom, "n2a: successful completion"));
		break;
	case ND_NOHOST :
		(void) snprintf(str, NDERR_BUFSZ,
			dgettext(__nsl_dom, "n2a: hostname not found"));
		break;
	case ND_NOSERV :
		(void) snprintf(str, NDERR_BUFSZ,
			dgettext(__nsl_dom, "n2a: service name not found"));
		break;
	case ND_NOSYM :
		(void) snprintf(str, NDERR_BUFSZ, "%s : %s ",
			dgettext(__nsl_dom,
			"n2a: symbol missing in shared object"),
			dlerrstr ? dlerrstr : " ");
		break;
	case ND_OPEN :
		(void) snprintf(str, NDERR_BUFSZ, "%s - %s ",
			dgettext(__nsl_dom, "n2a: couldn't open shared object"),
			dlerrstr ? dlerrstr : " ");
		break;
	case ND_ACCESS :
		(void) snprintf(str, NDERR_BUFSZ,
			dgettext(__nsl_dom,
			"n2a: access denied for shared object"));
		break;
	case ND_UKNWN :
		(void) snprintf(str, NDERR_BUFSZ,
			dgettext(__nsl_dom,
			"n2a: attempt to free unknown object"));
		break;
	case ND_BADARG :
		(void) snprintf(str, NDERR_BUFSZ,
			dgettext(__nsl_dom,
			"n2a: bad arguments passed to routine"));
		break;
	case ND_NOCTRL:
		(void) snprintf(str, NDERR_BUFSZ,
			dgettext(__nsl_dom, "n2a: unknown option passed"));
		break;
	case ND_FAILCTRL:
		(void) snprintf(str, NDERR_BUFSZ,
			dgettext(__nsl_dom, "n2a: control operation failed"));
		break;
	case ND_SYSTEM:
		(void) snprintf(str, NDERR_BUFSZ, "%s: %s",
			dgettext(__nsl_dom, "n2a: system error"),
			strerror(errno));
		break;
	default :
		(void) snprintf(str, NDERR_BUFSZ, "%s#%d",
			dgettext(__nsl_dom, "n2a: unknown error "), _nderror);
		break;
	}
	trace1(TR_netdir_sperror, 1);
	return (str);
}

/*
 * This is a routine that prints out strings related to the current
 * error in _nderror. Like perror() it takes a string to print with a
 * colon first.
 */
void
netdir_perror(s)
	char	*s;
{
	char	*err;

	trace1(TR_netdir_perror, 0);
	err = netdir_sperror();
	(void) fprintf(stderr, "%s: %s\n", s, err ? err : "n2a: error");
	trace1(TR_netdir_perror, 1);
}
