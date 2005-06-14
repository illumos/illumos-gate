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
 * Copyright (c) 1986-1991,1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * rpcb_clnt.c
 * interface to rpcbind rpc service.
 */

#include <rpc/rpc.h>
#include <rpc/trace.h>
#include <rpc/rpcb_prot.h>
#include <netconfig.h>
#include <netdir.h>
#include <rpc/nettype.h>
#ifdef PORTMAP
#include <netinet/in.h>		/* FOR IPPROTO_TCP/UDP definitions */
#include <rpc/pmap_prot.h>
#endif
#ifdef ND_DEBUG
#include <stdio.h>
#endif
#include <sys/utsname.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <tiuser.h>

static struct timeval tottimeout = { 60, 0 };
static struct timeval rmttimeout = { 3, 0 };
static char nullstring[] = "\000";

#define	CACHESIZE 6

struct address_cache {
	char *ac_host;
	char *ac_netid;
	char *ac_uaddr;
	struct netbuf *ac_taddr;
	struct address_cache *ac_next;
};

static struct address_cache *front;
static int cachesize;


/*
 * This routine adjusts the timeout used for calls to the remote rpcbind.
 * This is a private routine that may not be provided in future releases.
 */
bool_t
__rpc_control(int request, void *info)
{
	switch (request) {
	case CLCR_GET_RPCB_TIMEOUT:
		*(struct timeval *)info = tottimeout;
		break;
	case CLCR_SET_RPCB_TIMEOUT:
		tottimeout = *(struct timeval *)info;
		break;
	default:
		return (FALSE);
	}
	return (TRUE);
}

/*
 * The routines check_cache(), add_cache(), delete_cache() manage the
 * cache of rpcbind addresses for (host, netid).
 */

static struct address_cache *
check_cache(const char *host, char *netid)
{
	struct address_cache *cptr;

	trace1(TR_check_cache, 0);
	for (cptr = front; cptr != NULL; cptr = cptr->ac_next) {
		if (strcmp(cptr->ac_host, host) == 0 &&
		    strcmp(cptr->ac_netid, netid) == 0) {
#ifdef ND_DEBUG
			fprintf(stderr, "Found cache entry for %s: %s\n",
				host, netid);
#endif
			trace1(TR_check_cache, 1);
			return (cptr);
		}
	}
	trace1(TR_check_cache, 1);
	return ((struct address_cache *)NULL);
}

static void
delete_cache(struct address_cache *ad_cache)
{
	struct address_cache *cptr, *prevptr = NULL;

	trace1(TR_delete_cache, 0);
	for (cptr = front; cptr != NULL; cptr = cptr->ac_next) {
		if (strcmp(cptr->ac_host, ad_cache->ac_host) == 0 &&
		    strcmp(cptr->ac_netid, ad_cache->ac_netid) == 0) {
			free(cptr->ac_host);
			free(cptr->ac_netid);
			free(cptr->ac_taddr->buf);
			free(cptr->ac_taddr);
			if (cptr->ac_uaddr)
				free(cptr->ac_uaddr);
			if (prevptr)
				prevptr->ac_next = cptr->ac_next;
			else
				front = cptr->ac_next;
			free(cptr);
			cachesize--;
			break;
		}
		prevptr = cptr;
	}
	trace1(TR_delete_cache, 1);
}

static void
add_cache(const char *host, char *netid, struct netbuf *taddr, char *uaddr)
{
	struct address_cache  *ad_cache, *cptr, *prevptr;

	trace1(TR_add_cache, 0);
	ad_cache = (struct address_cache *)
			malloc(sizeof (struct address_cache));
	if (!ad_cache) {
		trace1(TR_add_cache, 1);
		return;
	}
	ad_cache->ac_host = strdup(host);
	ad_cache->ac_netid = strdup(netid);
	ad_cache->ac_uaddr = uaddr ? strdup(uaddr) : NULL;
	ad_cache->ac_taddr = (struct netbuf *)malloc(sizeof (struct netbuf));
	if (!ad_cache->ac_host || !ad_cache->ac_netid || !ad_cache->ac_taddr ||
		(uaddr && !ad_cache->ac_uaddr)) {
		trace1(TR_add_cache, 1);
		return;
	}
	ad_cache->ac_taddr->len = ad_cache->ac_taddr->maxlen = taddr->len;
	ad_cache->ac_taddr->buf = (char *)malloc(taddr->len);
	if (ad_cache->ac_taddr->buf == NULL) {
		trace1(TR_add_cache, 1);
		return;
	}
	(void) memcpy(ad_cache->ac_taddr->buf, taddr->buf, taddr->len);
#ifdef ND_DEBUG
	fprintf(stderr, "Added to cache: %s : %s\n", host, netid);
#endif

	if (cachesize < CACHESIZE) {
		ad_cache->ac_next = front;
		front = ad_cache;
		cachesize++;
	} else {
		/* Free the last entry */
		cptr = front;
		prevptr = NULL;
		while (cptr->ac_next) {
			prevptr = cptr;
			cptr = cptr->ac_next;
		}

#ifdef ND_DEBUG
		fprintf(stderr, "Deleted from cache: %s : %s\n",
			cptr->ac_host, cptr->ac_netid);
#endif
		free(cptr->ac_host);
		free(cptr->ac_netid);
		free(cptr->ac_taddr->buf);
		free(cptr->ac_taddr);
		if (cptr->ac_uaddr)
			free(cptr->ac_uaddr);

		if (prevptr) {
			prevptr->ac_next = NULL;
			ad_cache->ac_next = front;
			front = ad_cache;
		} else {
			front = ad_cache;
			ad_cache->ac_next = NULL;
		}
		free(cptr);
	}
	trace1(TR_add_cache, 1);
}

/*
 * This routine will return a client handle that is connected to the
 * rpcbind. Returns NULL on error and free's everything.
 */
static CLIENT *
getclnthandle(const char *host, const struct netconfig *nconf, char **targaddr)
{
	register CLIENT *client;
	struct netbuf *addr;
	struct nd_addrlist *nas;
	struct nd_hostserv rpcbind_hs;
	struct address_cache *ad_cache;
	char *tmpaddr;

	trace1(TR_getclnthandle, 0);
	/* Get the address of the rpcbind.  Check cache first */
	ad_cache = check_cache(host, nconf->nc_netid);
	if (ad_cache != NULL) {
		addr = ad_cache->ac_taddr;
		client = clnt_tli_create(RPC_ANYFD, nconf, addr, RPCBPROG,
					RPCBVERS4, 0, 0);
		if (client != NULL) {
			if (targaddr)
				*targaddr = ad_cache->ac_uaddr;
			trace1(TR_getclnthandle, 1);
			return (client);
		}
		/*
		 * Assume this may be due to cache data being
		 *  outdated
		 */
		delete_cache(ad_cache);
	}
	rpcbind_hs.h_host = (char *)host;
	rpcbind_hs.h_serv = "rpcbind";
#ifdef ND_DEBUG
	fprintf(stderr, "rpcbind client routines: diagnostics :\n");
	fprintf(stderr, "\tGetting address for (%s, %s, %s) ... \n",
		rpcbind_hs.h_host, rpcbind_hs.h_serv, nconf->nc_netid);
#endif

	if (netdir_getbyname((struct netconfig *)nconf, &rpcbind_hs, &nas)) {
		rpc_createerr.cf_stat = RPC_N2AXLATEFAILURE;
		trace1(TR_getclnthandle, 1);
		return ((CLIENT *)NULL);
	}
	/* XXX nas should perhaps be cached for better performance */

#ifdef ND_DEBUG
{
	char *ua;

	ua = taddr2uaddr(nconf, nas->n_addrs);
	fprintf(stderr, "Got it [%s]\n", ua);
	free(ua);
}
#endif

	addr = nas->n_addrs;
#ifdef ND_DEBUG
{
	int i;

	fprintf(stderr, "\tnetbuf len = %d, maxlen = %d\n",
		addr->len, addr->maxlen);
	fprintf(stderr, "\tAddress is ");
	for (i = 0; i < addr->len; i++)
		fprintf(stderr, "%u.", addr->buf[i]);
	fprintf(stderr, "\n");
}
#endif
	client = clnt_tli_create(RPC_ANYFD, nconf, addr, RPCBPROG,
				RPCBVERS4, 0, 0);
#ifdef ND_DEBUG
	if (! client) {
		clnt_pcreateerror("rpcbind clnt interface");
	}
#endif

	if (client) {
		tmpaddr = targaddr ? taddr2uaddr((struct netconfig *)nconf,
								addr) : NULL;
		add_cache(host, nconf->nc_netid, addr, tmpaddr);
		if (targaddr)
			*targaddr = tmpaddr;
	}
	netdir_free((char *)nas, ND_ADDRLIST);
	trace1(TR_getclnthandle, 1);
	return (client);
}

/*
 * This routine will return a client handle that is connected to the local
 * rpcbind. Returns NULL on error and free's everything.
 */
static CLIENT *
local_rpcb()
{
	static CLIENT *client;
	static struct netconfig *loopnconf;
	static char *hostname;

	trace1(TR_local_rpcb, 0);
	if (loopnconf == NULL) {
		struct utsname utsname;
		struct netconfig *nconf, *tmpnconf = NULL;
		void *nc_handle;

		if (hostname == (char *)NULL) {
			if ((uname(&utsname) == -1) ||
			    ((hostname = strdup(utsname.nodename)) == NULL)) {
				rpc_createerr.cf_stat = RPC_UNKNOWNHOST;
				return ((CLIENT *)NULL);
			}
		}
		nc_handle = setnetconfig();
		if (nc_handle == NULL) {
			/* fails to open netconfig file */
			rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
			trace1(TR_local_rpcb, 1);
			return (NULL);
		}
		while (nconf = getnetconfig(nc_handle)) {
			if (strcmp(nconf->nc_protofmly, NC_LOOPBACK) == 0) {
				tmpnconf = nconf;
				if (nconf->nc_semantics == NC_TPI_COTS ||
					nconf->nc_semantics == NC_TPI_COTS_ORD)
						break;
			}
		}
		if (tmpnconf == NULL) {
			rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
			return (NULL);
		}
		loopnconf = getnetconfigent(tmpnconf->nc_netid);
		/* loopnconf is never freed */
		(void) endnetconfig(nc_handle);
	}
	client = getclnthandle(hostname, loopnconf, (char **)NULL);
	trace1(TR_local_rpcb, 1);
	return (client);
}

/*
 * Set a mapping between program, version and address.
 * Calls the rpcbind service to do the mapping.
 */
bool_t
rpcb_set(const rpcprog_t program, const rpcvers_t version,
    const struct netconfig *nconf, const struct netbuf *address)
{
	register CLIENT *client;
	bool_t rslt = FALSE;
	RPCB parms;
	char uidbuf[32];

	trace3(TR_rpcb_set, 0, program, version);
	/* parameter checking */
	if (nconf == (struct netconfig *)NULL) {
		rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
		trace3(TR_rpcb_set, 1, program, version);
		return (FALSE);
	}
	if (address == NULL) {
		rpc_createerr.cf_stat = RPC_UNKNOWNADDR;
		trace3(TR_rpcb_set, 1, program, version);
		return (FALSE);
	}
	client = local_rpcb();
	if (! client) {
		trace3(TR_rpcb_set, 1, program, version);
		return (FALSE);
	}

	parms.r_addr = taddr2uaddr((struct netconfig *)nconf, (struct netbuf
	*) address); /* convert to universal */
	if (!parms.r_addr) {
		rpc_createerr.cf_stat = RPC_N2AXLATEFAILURE;
		trace3(TR_rpcb_set, 1, program, version);
		return (FALSE); /* no universal address */
	}
	parms.r_prog = program;
	parms.r_vers = version;
	parms.r_netid = nconf->nc_netid;
	/*
	 * Though uid is not being used directly, we still send it for
	 * completeness.  For non-unix platforms, perhaps some other
	 * string or an empty string can be sent.
	 */
	(void) sprintf(uidbuf, "%d", (int)geteuid());
	parms.r_owner = uidbuf;

	CLNT_CALL(client, RPCBPROC_SET, (xdrproc_t)xdr_rpcb, (char *)&parms,
			(xdrproc_t)xdr_bool, (char *)&rslt, tottimeout);

	CLNT_DESTROY(client);
	free(parms.r_addr);
	trace3(TR_rpcb_set, 1, program, version);
	return (rslt);
}

/*
 * Remove the mapping between program, version and netbuf address.
 * Calls the rpcbind service to do the un-mapping.
 * If netbuf is NULL, unset for all the transports, otherwise unset
 * only for the given transport.
 */
bool_t
rpcb_unset(const rpcprog_t program, const rpcvers_t version,
    const struct netconfig *nconf)
{
	register CLIENT *client;
	bool_t rslt = FALSE;
	RPCB parms;
	char uidbuf[32];

	trace3(TR_rpcb_unset, 0, program, version);
	client = local_rpcb();
	if (! client) {
		trace3(TR_rpcb_unset, 1, program, version);
		return (FALSE);
	}

	parms.r_prog = program;
	parms.r_vers = version;
	if (nconf)
		parms.r_netid = nconf->nc_netid;
	else
		parms.r_netid = (char *)&nullstring[0]; /* unsets  all */
	parms.r_addr = (char *)&nullstring[0];
	(void) sprintf(uidbuf, "%d", (int)geteuid());
	parms.r_owner = uidbuf;

	CLNT_CALL(client, RPCBPROC_UNSET, (xdrproc_t)xdr_rpcb, (char *)&parms,
			(xdrproc_t)xdr_bool, (char *)&rslt, tottimeout);

	CLNT_DESTROY(client);
	trace3(TR_rpcb_unset, 1, program, version);
	return (rslt);
}

/*
 * From the merged list, find the appropriate entry
 */
static struct netbuf *
got_entry(rpcb_entry_list_ptr relp, const struct netconfig *nconf)
{
	struct netbuf *na = NULL;
	rpcb_entry_list_ptr sp;
	rpcb_entry *rmap;

	trace1(TR_got_entry, 0);
	for (sp = relp; sp != NULL; sp = sp->rpcb_entry_next) {
		rmap = &sp->rpcb_entry_map;
		if ((strcmp(nconf->nc_proto, rmap->r_nc_proto) == 0) &&
		    (strcmp(nconf->nc_protofmly, rmap->r_nc_protofmly) == 0) &&
		    (nconf->nc_semantics == rmap->r_nc_semantics) &&
		    (rmap->r_maddr != NULL) && (rmap->r_maddr[0] != NULL)) {
			na = uaddr2taddr((struct netconfig *)nconf,
								rmap->r_maddr);
#ifdef ND_DEBUG
			fprintf(stderr, "\tRemote address is [%s].\n",
				rmap->r_maddr);
			if (!na)
				fprintf(stderr,
				    "\tCouldn't resolve remote address!\n");
#endif
			break;
		}
	}
	trace1(TR_got_entry, 1);
	return (na);
}

/*
 * An internal function which optimizes rpcb_getaddr function.  It also
 * returns the client handle that it uses to contact the remote rpcbind.
 *
 * The algorithm used: If the transports is TCP or UDP, it first tries
 * version 2 (portmap), 4 and then 3 (svr4).  This order should be
 * changed in the next OS release to 4, 2 and 3.  We are assuming that by
 * that time, version 4 would be available on many machines on the network.
 * With this algorithm, we get performance as well as a plan for
 * obsoleting version 2.
 *
 * For all other transports, the algorithm remains as 4 and then 3.
 *
 * XXX: Due to some problems with t_connect(), we do not reuse the same client
 * handle for COTS cases and hence in these cases we do not return the
 * client handle.  This code will change if t_connect() ever
 * starts working properly.  Also look under clnt_vc.c.
 */
struct netbuf *
__rpcb_findaddr(rpcprog_t program, rpcvers_t version,
    const struct netconfig *nconf, const char *host, CLIENT **clpp)
{
	register CLIENT *client = NULL;
	RPCB parms;
	enum clnt_stat clnt_st;
	char *ua = NULL;
	uint_t vers;
	struct netbuf *address = NULL;
	uint_t start_vers = RPCBVERS4;

	trace3(TR_rpcb_findaddr, 0, program, version);
	/* parameter checking */
	if (nconf == (struct netconfig *)NULL) {
		rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
		trace3(TR_rpcb_findaddr, 1, program, version);
		return (NULL);
	}

	parms.r_addr = NULL;

#ifdef PORTMAP
	/* Try version 2 for TCP or UDP */
	if (strcmp(nconf->nc_protofmly, NC_INET) == 0) {
		ushort_t port = 0;
		struct netbuf remote;
		uint_t pmapvers = 2;
		struct pmap pmapparms;

		/*
		 * Try UDP only - there are some portmappers out
		 * there that use UDP only.
		 */
		if (strcmp(nconf->nc_proto, NC_TCP) == 0) {
			struct netconfig *newnconf;
			void *handle;

			if ((handle = __rpc_setconf("udp")) == NULL) {
				rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
				trace3(TR_rpcb_findaddr, 1, program, version);
				return (NULL);
			}
			if ((newnconf = __rpc_getconf(handle)) == NULL) {
				__rpc_endconf(handle);
				rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
				trace3(TR_rpcb_findaddr, 1, program, version);
				return (NULL);
			}
			client = getclnthandle(host, newnconf, &parms.r_addr);
			__rpc_endconf(handle);
		} else {
			client = getclnthandle(host, nconf, &parms.r_addr);
		}
		if (client == (CLIENT *)NULL) {
			trace3(TR_rpcb_findaddr, 1, program, version);
			return (NULL);
		}

		/* Set the version */
		CLNT_CONTROL(client, CLSET_VERS, (char *)&pmapvers);
		pmapparms.pm_prog = program;
		pmapparms.pm_vers = version;
		pmapparms.pm_prot = strcmp(nconf->nc_proto, NC_TCP) ?
					IPPROTO_UDP : IPPROTO_TCP;
		pmapparms.pm_port = 0;	/* not needed */
		clnt_st = CLNT_CALL(client, PMAPPROC_GETPORT,
			(xdrproc_t)xdr_pmap, (caddr_t)&pmapparms,
			(xdrproc_t)xdr_u_short, (caddr_t)&port,
			tottimeout);
		if (clnt_st != RPC_SUCCESS) {
			if ((clnt_st == RPC_PROGVERSMISMATCH) ||
				(clnt_st == RPC_PROGUNAVAIL))
				goto try_rpcbind; /* Try different versions */
			rpc_createerr.cf_stat = RPC_PMAPFAILURE;
			clnt_geterr(client, &rpc_createerr.cf_error);
			goto error;
		} else if (port == 0) {
			address = NULL;
			rpc_createerr.cf_stat = RPC_PROGNOTREGISTERED;
			goto error;
		}
		port = htons(port);
		CLNT_CONTROL(client, CLGET_SVC_ADDR, (char *)&remote);
		if (((address = (struct netbuf *)
			malloc(sizeof (struct netbuf))) == NULL) ||
		    ((address->buf = (char *)
			malloc(remote.len)) == NULL)) {
			rpc_createerr.cf_stat = RPC_SYSTEMERROR;
			clnt_geterr(client, &rpc_createerr.cf_error);
			if (address) {
				free(address);
				address = NULL;
			}
			goto error;
		}
		(void) memcpy(address->buf, remote.buf, remote.len);
		(void) memcpy((char *)&address->buf[sizeof (short)],
				(char *)&port, sizeof (short));
		address->len = address->maxlen = remote.len;
		goto done;
	}
#endif

try_rpcbind:
	/*
	 * Now we try version 4 and then 3.
	 * We also send the remote system the address we used to
	 * contact it in case it can help to connect back with us
	 */
	parms.r_prog = program;
	parms.r_vers = version;
	parms.r_owner = (char *)&nullstring[0];	/* not needed just for xdring */
	parms.r_netid = nconf->nc_netid; /* not really needed */

	/*
	 * If a COTS transport is being used, try getting address via CLTS
	 * transport.  This works only with version 4.
	 */
	if ((nconf->nc_semantics == NC_TPI_COTS_ORD ||
			nconf->nc_semantics == NC_TPI_COTS) &&
		(strcmp(nconf->nc_protofmly, NC_LOOPBACK) != 0)) {
		void *handle;
		struct netconfig *nconf_clts;
		rpcb_entry_list_ptr relp = NULL;

		if (client == NULL) {
			/* This did not go through the above PORTMAP/TCP code */
			if ((handle = __rpc_setconf("datagram_v")) != NULL) {
				while ((nconf_clts = __rpc_getconf(handle))
					!= NULL) {
					if (strcmp(nconf_clts->nc_protofmly,
						nconf->nc_protofmly) != 0) {
						continue;
					}
					client = getclnthandle(host, nconf_clts,
							&parms.r_addr);
					break;
				}
				__rpc_endconf(handle);
			}
			if (client == (CLIENT *)NULL)
				goto regular_rpcbind;	/* Go the regular way */
		} else {
			/* This is a UDP PORTMAP handle.  Change to version 4 */
			vers = RPCBVERS4;
			CLNT_CONTROL(client, CLSET_VERS, (char *)&vers);
		}
		/*
		 * We also send the remote system the address we used to
		 * contact it in case it can help it connect back with us
		 */
		if (parms.r_addr == NULL)
			parms.r_addr = (char *)&nullstring[0];  /* for XDRing */
		clnt_st = CLNT_CALL(client, RPCBPROC_GETADDRLIST,
				    (xdrproc_t)xdr_rpcb, (char *)&parms,
				    (xdrproc_t)xdr_rpcb_entry_list_ptr,
				    (char *)&relp, tottimeout);
		if (clnt_st == RPC_SUCCESS) {
			if (address = got_entry(relp, nconf)) {
				xdr_free((xdrproc_t)xdr_rpcb_entry_list_ptr,
					(char *)&relp);
				goto done;
			}
			/* Entry not found for this transport */
			xdr_free((xdrproc_t)xdr_rpcb_entry_list_ptr,
				(char *)&relp);
			/*
			 * XXX: should have perhaps returned with error but
			 * since the remote machine might not always be able
			 * to send the address on all transports, we try the
			 * regular way with regular_rpcbind
			 */
			goto regular_rpcbind;
		} else if ((clnt_st == RPC_PROGVERSMISMATCH) ||
			(clnt_st == RPC_PROGUNAVAIL)) {
			start_vers = RPCBVERS;	/* Try version 3 now */
			goto regular_rpcbind; /* Try different versions */
		} else {
			rpc_createerr.cf_stat = RPC_PMAPFAILURE;
			clnt_geterr(client, &rpc_createerr.cf_error);
			goto error;
		}
	}

regular_rpcbind:
	/* Now the same transport is to be used to get the address */
	if (client && ((nconf->nc_semantics == NC_TPI_COTS_ORD) ||
			(nconf->nc_semantics == NC_TPI_COTS))) {
		/* A CLTS type of client - destroy it */
		CLNT_DESTROY(client);
		client = NULL;
	}

	if (client == NULL) {
		client = getclnthandle(host, nconf, &parms.r_addr);
		if (client == NULL)
			goto error;
	}
	if (parms.r_addr == NULL)
		parms.r_addr = nullstring;

	/* First try from start_vers and then version 3 (RPCBVERS) */
	for (vers = start_vers;  vers >= RPCBVERS; vers--) {
		/* Set the version */
		CLNT_CONTROL(client, CLSET_VERS, (char *)&vers);
		clnt_st = CLNT_CALL(client, RPCBPROC_GETADDR,
				    (xdrproc_t)xdr_rpcb, (char *)&parms,
				    (xdrproc_t)xdr_wrapstring,
				    (char *)&ua, tottimeout);
		if (clnt_st == RPC_SUCCESS) {
			if ((ua == NULL) || (ua[0] == NULL)) {
				/* address unknown */
				rpc_createerr.cf_stat = RPC_PROGNOTREGISTERED;
				goto error;
			}
			address = uaddr2taddr((struct netconfig *)nconf, ua);
#ifdef ND_DEBUG
			fprintf(stderr, "\tRemote address is [%s]\n", ua);
			if (!address)
				fprintf(stderr,
					"\tCouldn't resolve remote address!\n");
#endif
			xdr_free((xdrproc_t)xdr_wrapstring, (char *)&ua);

			if (! address) {
				/* We don't know about your universal address */
				rpc_createerr.cf_stat = RPC_N2AXLATEFAILURE;
				goto error;
			}
			goto done;
		} else if (clnt_st == RPC_PROGVERSMISMATCH) {
			struct rpc_err rpcerr;

			clnt_geterr(client, &rpcerr);
			if (rpcerr.re_vers.low > RPCBVERS4)
				goto error;  /* a new version, can't handle */
		} else if (clnt_st != RPC_PROGUNAVAIL) {
			/* Cant handle this error */
			goto error;
		}
	}

	if ((address == NULL) || (address->len == 0)) {
		rpc_createerr.cf_stat = RPC_PROGNOTREGISTERED;
		clnt_geterr(client, &rpc_createerr.cf_error);
	}
error:
	if (client) {
		CLNT_DESTROY(client);
		client = NULL;
	}
done:
	if (nconf->nc_semantics != NC_TPI_CLTS) {
		/* This client is the connectionless one */
		if (client) {
			CLNT_DESTROY(client);
			client = NULL;
		}
	}
	if (clpp) {
		*clpp = client;
	} else if (client) {
		CLNT_DESTROY(client);
	}
	trace3(TR_rpcb_findaddr, 1, program, version);
	return (address);
}


/*
 * Find the mapped address for program, version.
 * Calls the rpcbind service remotely to do the lookup.
 * Uses the transport specified in nconf.
 * Returns FALSE (0) if no map exists, else returns 1.
 *
 * Assuming that the address is all properly allocated
 */
int
rpcb_getaddr(const rpcprog_t program, const rpcvers_t version,
    const struct netconfig *nconf, struct netbuf *address, const char *host)
{
	struct netbuf *na;

	trace3(TR_rpcb_getaddr, 0, program, version);
	if ((na = __rpcb_findaddr(program, version, (struct netconfig *)nconf,
				(char *)host, (CLIENT **) NULL)) == NULL)
		return (FALSE);

	if (na->len > address->maxlen) {
		/* Too long address */
		netdir_free((char *)na, ND_ADDR);
		rpc_createerr.cf_stat = RPC_FAILED;
		trace3(TR_rpcb_getaddr, 1, program, version);
		return (FALSE);
	}
	(void) memcpy(address->buf, na->buf, (int)na->len);
	address->len = na->len;
	netdir_free((char *)na, ND_ADDR);
	trace3(TR_rpcb_getaddr, 1, program, version);
	return (TRUE);
}

/*
 * Get a copy of the current maps.
 * Calls the rpcbind service remotely to get the maps.
 *
 * It returns only a list of the services
 * It returns NULL on failure.
 */
rpcblist *
rpcb_getmaps(const struct netconfig *nconf, const char *host)
{
	rpcblist_ptr head = (rpcblist_ptr)NULL;
	register CLIENT *client;
	enum clnt_stat clnt_st;
	int vers = 0;

	trace1(TR_rpcb_getmaps, 0);
	client = getclnthandle((char *)host, (struct netconfig *)nconf,
								(char **)NULL);
	if (client == (CLIENT *)NULL) {
		trace1(TR_rpcb_getmaps, 1);
		return (head);
	}
	clnt_st = CLNT_CALL(client, RPCBPROC_DUMP,
			(xdrproc_t)xdr_void, NULL,
			(xdrproc_t)xdr_rpcblist_ptr,
			(char *)&head, tottimeout);
	if (clnt_st == RPC_SUCCESS)
		goto done;

	if ((clnt_st != RPC_PROGVERSMISMATCH) &&
		    (clnt_st != RPC_PROGUNAVAIL)) {
		rpc_createerr.cf_stat = RPC_RPCBFAILURE;
		clnt_geterr(client, &rpc_createerr.cf_error);
		goto done;
	}

	/* fall back to earlier version */
	CLNT_CONTROL(client, CLGET_VERS, (char *)&vers);
	if (vers == RPCBVERS4) {
		vers = RPCBVERS;
		CLNT_CONTROL(client, CLSET_VERS, (char *)&vers);
		if (CLNT_CALL(client, RPCBPROC_DUMP,
			(xdrproc_t)xdr_void,
			(char *)NULL, (xdrproc_t)xdr_rpcblist_ptr,
			(char *)&head, tottimeout) == RPC_SUCCESS)
				goto done;
	}
	rpc_createerr.cf_stat = RPC_RPCBFAILURE;
	clnt_geterr(client, &rpc_createerr.cf_error);

done:
	CLNT_DESTROY(client);
	trace1(TR_rpcb_getmaps, 1);
	return (head);
}

/*
 * rpcbinder remote-call-service interface.
 * This routine is used to call the rpcbind remote call service
 * which will look up a service program in the address maps, and then
 * remotely call that routine with the given parameters. This allows
 * programs to do a lookup and call in one step.
 */
enum clnt_stat
rpcb_rmtcall(const struct netconfig *nconf, const char *host,
    const rpcprog_t prog, const rpcvers_t vers, const rpcproc_t proc,
    const xdrproc_t xdrargs, const caddr_t argsp, const xdrproc_t xdrres,
    const caddr_t resp, const struct timeval tout, struct netbuf *addr_ptr)
{
	register CLIENT *client;
	enum clnt_stat stat;
	struct r_rpcb_rmtcallargs a;
	struct r_rpcb_rmtcallres r;
	int rpcb_vers;

	trace4(TR_rpcb_rmtcall, 0, prog, vers, proc);

	client = getclnthandle((char *)host, (struct netconfig *)nconf,
								(char **)NULL);
	if (client == (CLIENT *)NULL) {
		trace4(TR_rpcb_rmtcall, 1, prog, vers, proc);
		return (RPC_FAILED);
	}
	CLNT_CONTROL(client, CLSET_RETRY_TIMEOUT, (char *)&rmttimeout);
	a.prog = prog;
	a.vers = vers;
	a.proc = proc;
	a.args.args_val = argsp;
	a.xdr_args = xdrargs;
	r.addr = NULL;
	r.results.results_val = resp;
	r.xdr_res = xdrres;

	for (rpcb_vers = RPCBVERS4; rpcb_vers >= RPCBVERS; rpcb_vers--) {
		CLNT_CONTROL(client, CLSET_VERS, (char *)&rpcb_vers);
		stat = CLNT_CALL(client, RPCBPROC_CALLIT,
			(xdrproc_t)xdr_rpcb_rmtcallargs, (char *)&a,
			(xdrproc_t)xdr_rpcb_rmtcallres, (char *)&r, tout);
		if ((stat == RPC_SUCCESS) && (addr_ptr != NULL)) {
			struct netbuf *na;

			na = uaddr2taddr((struct netconfig *)nconf, r.addr);
			if (! na) {
				stat = RPC_N2AXLATEFAILURE;
				((struct netbuf *)addr_ptr)->len = 0;
				goto error;
			}
			if (na->len > addr_ptr->maxlen) {
				/* Too long address */
				stat = RPC_FAILED; /* XXX A better error no */
				netdir_free((char *)na, ND_ADDR);
				((struct netbuf *)addr_ptr)->len = 0;
				goto error;
			}
			(void) memcpy(addr_ptr->buf, na->buf, (int)na->len);
			((struct netbuf *)addr_ptr)->len = na->len;
			netdir_free((char *)na, ND_ADDR);
			break;
		} else if ((stat != RPC_PROGVERSMISMATCH) &&
			    (stat != RPC_PROGUNAVAIL)) {
			goto error;
		}
	}
error:
	CLNT_DESTROY(client);
	if (r.addr)
		xdr_free((xdrproc_t)xdr_wrapstring, (char *)&r.addr);
	trace4(TR_rpcb_rmtcall, 1, prog, vers, proc);
	return (stat);
}

/*
 * Gets the time on the remote host.
 * Returns 1 if succeeds else 0.
 */
bool_t
rpcb_gettime(const char *host, time_t *timep)
{
	CLIENT *client = NULL;
	void *handle;
	struct netconfig *nconf;
	int vers;
	enum clnt_stat st;

	trace1(TR_rpcb_gettime, 0);

	if ((host == NULL) || (host[0] == NULL)) {
		(void) time(timep);
		trace1(TR_rpcb_gettime, 1);
		return (TRUE);
	}

	if ((handle = __rpc_setconf("netpath")) == NULL) {
		rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
		trace1(TR_rpcb_gettime, 1);
		return (FALSE);
	}
	rpc_createerr.cf_stat = RPC_SUCCESS;
	while (client == (CLIENT *)NULL) {
		if ((nconf = __rpc_getconf(handle)) == NULL) {
			if (rpc_createerr.cf_stat == RPC_SUCCESS)
				rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
			break;
		}
		client = getclnthandle((char *)host, nconf, (char **)NULL);
		if (client)
			break;
	}
	__rpc_endconf(handle);
	if (client == (CLIENT *)NULL) {
		trace1(TR_rpcb_gettime, 1);
		return (FALSE);
	}

	st = CLNT_CALL(client, RPCBPROC_GETTIME,
		(xdrproc_t)xdr_void, (char *)NULL,
		(xdrproc_t)xdr_int, (char *)timep, tottimeout);

	if ((st == RPC_PROGVERSMISMATCH) || (st == RPC_PROGUNAVAIL)) {
		CLNT_CONTROL(client, CLGET_VERS, (char *)&vers);
		if (vers == RPCBVERS4) {
			/* fall back to earlier version */
			vers = RPCBVERS;
			CLNT_CONTROL(client, CLSET_VERS, (char *)&vers);
			st = CLNT_CALL(client, RPCBPROC_GETTIME,
				(xdrproc_t)xdr_void, (char *)NULL,
				(xdrproc_t)xdr_int, (char *)timep,
				tottimeout);
		}
	}
	trace1(TR_rpcb_gettime, 1);
	CLNT_DESTROY(client);
	return (st == RPC_SUCCESS? TRUE: FALSE);
}

/*
 * Converts taddr to universal address.  This routine should never
 * really be called because local n2a libraries are always provided.
 */
char *
rpcb_taddr2uaddr(struct netconfig *nconf, struct netbuf *taddr)
{
	CLIENT *client;
	char *uaddr = NULL;

	trace1(TR_rpcb_taddr2uaddr, 0);

	/* parameter checking */
	if (nconf == (struct netconfig *)NULL) {
		rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
		trace1(TR_rpcb_taddr2uaddr, 1);
		return (NULL);
	}
	if (taddr == NULL) {
		rpc_createerr.cf_stat = RPC_UNKNOWNADDR;
		trace1(TR_rpcb_taddr2uaddr, 1);
		return (NULL);
	}
	client = local_rpcb();
	if (! client) {
		trace1(TR_rpcb_taddr2uaddr, 1);
		return (NULL);
	}

	CLNT_CALL(client, RPCBPROC_TADDR2UADDR, (xdrproc_t)xdr_netbuf,
		(char *)taddr, (xdrproc_t)xdr_wrapstring, (char *)&uaddr,
		tottimeout);
	CLNT_DESTROY(client);
	trace1(TR_rpcb_taddr2uaddr, 1);
	return (uaddr);
}

/*
 * Converts universal address to netbuf.  This routine should never
 * really be called because local n2a libraries are always provided.
 */
struct netbuf *
rpcb_uaddr2taddr(struct netconfig *nconf, char *uaddr)
{
	CLIENT *client;
	struct netbuf *taddr;

	trace1(TR_rpcb_uaddr2taddr, 0);

	/* parameter checking */
	if (nconf == (struct netconfig *)NULL) {
		rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
		trace1(TR_rpcb_uaddr2taddr, 1);
		return (NULL);
	}
	if (uaddr == NULL) {
		rpc_createerr.cf_stat = RPC_UNKNOWNADDR;
		trace1(TR_rpcb_uaddr2taddr, 1);
		return (NULL);
	}
	client = local_rpcb();
	if (! client) {
		trace1(TR_rpcb_uaddr2taddr, 1);
		return (NULL);
	}

	taddr = (struct netbuf *)calloc(1, sizeof (struct netbuf));
	if (taddr == NULL) {
		CLNT_DESTROY(client);
		trace1(TR_rpcb_uaddr2taddr, 1);
		return (NULL);
	}
	if (CLNT_CALL(client, RPCBPROC_UADDR2TADDR, (xdrproc_t)xdr_wrapstring,
		(char *)&uaddr, (xdrproc_t)xdr_netbuf, (char *)taddr,
		tottimeout) != RPC_SUCCESS) {
		free(taddr);
		taddr = NULL;
	}
	CLNT_DESTROY(client);
	trace1(TR_rpcb_uaddr2taddr, 1);
	return (taddr);
}
