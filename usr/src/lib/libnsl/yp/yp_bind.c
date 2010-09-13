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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley
 * under license from the Regents of the University of
 * California.
 */
#include "mt.h"
#include "../rpc/rpc_mt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <rpc/rpc.h>
#include <netconfig.h>
#include <netdir.h>
#include <syslog.h>
#include "yp_b.h"
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#include <sys/tiuser.h>

#define	BFSIZE	(YPMAXDOMAIN + 32)	/* size of binding file */
int	 __ypipbufsize = 8192;		/* size used for clnt_tli_create */

/* This should match the one in ypbind.c */

extern int getdomainname(char *, int);

static CLIENT *getclnt(rpcprog_t, rpcvers_t, struct netconfig *, int *);
static struct dom_binding *load_dom_binding(struct ypbind_resp *, char *,
    int *);
static ypbind_resp *get_cached_domain(char *);
static int get_cached_transport(struct netconfig *, int, char *, int);
static int ypbind_running(int, int);
static void set_rdev(struct dom_binding *);
static int check_rdev(struct dom_binding *);

static char nullstring[] = "";
/*
 * Time parameters when talking to the ypbind and pmap processes
 */

#define	YPSLEEPTIME	5		/* Time to sleep between tries */
unsigned int _ypsleeptime = YPSLEEPTIME;

/*
 * Time parameters when talking to the ypserv process
 */

#ifdef  DEBUG
#define	YPTIMEOUT	120		/* Total seconds for timeout */
#define	YPINTER_TRY	60		/* Seconds between tries */
#else
#define	YPTIMEOUT	20		/* Total seconds for timeout */
#define	YPINTER_TRY	5		/* Seconds between tries */
#endif

#define	MAX_TRIES_FOR_NEW_YP	1	/* Number of times we'll try to */
					/* get a new YP server before   */
					/* we'll settle for an old one. */
struct timeval _ypserv_timeout = {
	YPTIMEOUT,			/* Seconds */
	0				/* Microseconds */
	};

static mutex_t			default_domain_lock = DEFAULTMUTEX;
static char			*default_domain;

/*
 * The bound_domains_lock serializes all action in yp_unbind(), __yp_dobind(),
 *   newborn(), check_binding() and laod_dom_binding(), not just the direct
 *   manipulation of the bound_domains list.
 * It also protects all of the fields within a domain binding except
 *   the server_name field (which is protected by the server_name_lock).
 * A better implementation might try to serialize each domain separately,
 *   but normally we're only dealing with one domain (the default) anyway.
 * To avoid one thread freeing a domain binding while another is using
 *   the binding, we maintain a reference count for each binding.  The
 *   reference count is incremented in __yp_dobind.  The thread calls
 *   __yp_rel_binding() when it has finished using the binding (which
 *   decrements the reference count).  If the reference count is non-zero
 *   when a thread tries to free a binding, the need_free flag is set and
 *   the free is delayed.  The __yp_rel_binding() routine checks the flag
 *   and calls the free routine if the flag is set and the reference
 *   count is zero.
 */
static mutex_t			bound_domains_lock = DEFAULTMUTEX;
static struct dom_binding	*bound_domains; /* List of bound domains */


/*
 *  Must be called with bound_domains_lock held or with a dom_binding
 *  that cannot be referenced by another thread.
 */
void
free_dom_binding(struct dom_binding *p)
{
	if (p->ref_count != 0) {
		p->need_free = 1;
		return;
	}
	(void) check_rdev(p);
	clnt_destroy(p->dom_client);
	free(p->dom_domain);
	free(p);
}

/*
 * Attempts to find a dom_binding in the list at bound_domains having the
 * domain name field equal to the passed domain name, and removes it if found.
 * The domain-server binding will not exist after the call to this function.
 * All resources associated with the binding will be freed.
 *
 * yp_unbind is MT-safe because it serializes on bound_domains_lock.
 */

static void
__yp_unbind_nolock(char *domain)
{
	struct dom_binding *p;
	struct dom_binding **prev;

	if ((domain == NULL) || (strlen(domain) == 0)) {
		return;
	}

	/*
	 *  If we used a cache file to bind, then we will mark the
	 *  cache bad.  This will cause a subsequent call to __yp_dobind
	 *  to ignore the cache and talk to ypbind.  Otherwise, we
	 *  have already gotten a binding by talking to ypbind and
	 *  the binding is not good.
	 *
	 *  An optimization could be to check to see if the cache
	 *  file has changed (ypbind is pointing at a new server) and
	 *  reload the binding from it.  But that is too much work
	 *  for now.
	 */
	for (prev = &bound_domains;  (p = *prev) != 0;  prev = &p->dom_pnext) {

		if (strcmp(domain, p->dom_domain) == 0) {
			if (!p->cache_bad) {
				p->cache_bad = 1;
				break;
			}
			*prev = p->dom_pnext;
			free_dom_binding(p);
			break;
		}

	}
}


void
yp_unbind(char *domain)
{
	(void) mutex_lock(&bound_domains_lock);
	__yp_unbind_nolock(domain);
	(void) mutex_unlock(&bound_domains_lock);
}


/*
 * This checks to see if this is a new process incarnation which has
 * inherited bindings from a parent, and unbinds the world if so.
 *
 * MT-safe because it is only invoked from __yp_dobind(), which serializes
 * all requests.
 */
static void
newborn(void)
{
	static pid_t mypid;	/* Cached to detect forks */
	pid_t testpid;
	struct dom_binding *p, *q;

	if ((testpid = getpid()) != mypid) {

		mypid = testpid;

		for (p = bound_domains;  p != 0;  p = q) {
			q = p->dom_pnext;
			free_dom_binding(p);
		}
		bound_domains = 0;
	}
}

/*
 * This checks that the socket for a domain which has already been bound
 * hasn't been closed or changed under us.  If it has, unbind the domain
 * without closing the socket, which may be in use by some higher level
 * code.  This returns TRUE and points the binding parameter at the found
 * dom_binding if the binding is found and the socket looks OK, and FALSE
 * otherwise.
 *
 * MT-safe because it is only invoked from __yp_dobind(), which serializes
 * all requests.
 */
static bool
check_binding(char *domain, struct dom_binding **binding)
{
	struct dom_binding *pdomb;
	struct ypbind_resp *ypbind_resp;
	int status;

	for (pdomb = bound_domains; pdomb != NULL; pdomb = pdomb->dom_pnext) {

		if (strcmp(domain, pdomb->dom_domain) == 0) {
		/*
		 * XXX How do we really make sure the udp connection hasn't
		 * changes under us ? If it happens and we can't detect it,
		 * the appliction is doomed !
		 * POLICY: Let nobody do a yp_bind or __yp_dobind explicitly
		 * and forget to to yp_unbind it. All apps should go
		 * through the standard yp_match/first etc. functions.
		 */

			*binding = pdomb;
			return (TRUE);
		}
	}

	/*
	 *  We check to see if we can do a quick bind to ypserv.
	 *  If we can, then we load the binding (i.e., add it to our
	 *  cache of bindings) and then return it.
	 */
	if ((ypbind_resp = get_cached_domain(domain)) != 0) {
		pdomb = load_dom_binding(ypbind_resp, domain, &status);
		if (pdomb == 0)
			return (FALSE);
		*binding = pdomb;
		return (TRUE);
	}
	return (FALSE);
}

/*
 *  This routine adds a binding for a particular server to our
 *  list of bound domains.  We check to see if there is actually
 *  a yp server at the given address.  If not, or if there is
 *  any other error, we return 0.  We have to malloc the binding
 *  structure because that is what a call to ypbind returns and
 *  we are basically doing what a call to ypbind would do.
 */

#define	SOCKADDR_SIZE (sizeof (struct sockaddr_in6))
static int
__yp_add_binding_netid(char *domain, char *addr, char *netid)
{
	struct netconfig *nconf = 0;
	struct netbuf *svcaddr = 0;
	struct ypbind_binding *binding = 0;
	int status;
	struct ypbind_resp resp;
	struct dom_binding *pdomb;

	nconf = getnetconfigent(netid);
	if (nconf == 0)
		goto err;

	svcaddr = malloc(sizeof (struct netbuf));
	if (svcaddr == 0)
		goto err;

	svcaddr->maxlen = SOCKADDR_SIZE;
	svcaddr->buf = malloc(SOCKADDR_SIZE);
	if (svcaddr->buf == 0)
		goto err;

	if (!rpcb_getaddr(YPPROG, YPVERS, nconf, svcaddr, addr))
		goto err;

	binding = malloc(sizeof (struct ypbind_binding));
	if (binding == 0)
		goto err;

	binding->ypbind_hi_vers = YPVERS;
	binding->ypbind_lo_vers = YPVERS;
	binding->ypbind_nconf = nconf;
	binding->ypbind_svcaddr = svcaddr;
	binding->ypbind_servername = (char *)strdup(addr);
	if (binding->ypbind_servername == 0)
		goto err;

	resp.ypbind_status = YPBIND_SUCC_VAL;
	resp.ypbind_resp_u.ypbind_bindinfo = binding;

	(void) mutex_lock(&bound_domains_lock);
	newborn();
	pdomb = load_dom_binding(&resp, domain, &status);
	(void) mutex_unlock(&bound_domains_lock);

	return (pdomb != 0);

err:
	if (nconf)
		freenetconfigent(nconf);
	if (svcaddr) {
		if (svcaddr->buf)
			free(svcaddr->buf);
		free(svcaddr);
	}
	if (binding) {
		if (binding->ypbind_servername)
			free(binding->ypbind_servername);
		free(binding);
	}
	return (0);
}


int
__yp_add_binding(char *domain, char *addr) {

	int ret = __yp_add_binding_netid(domain, addr, "udp6");

	if (ret == 0)
		ret = __yp_add_binding_netid(domain, addr, "udp");

	return (ret);
}


/*
 * This allocates some memory for a domain binding, initialize it, and
 * returns a pointer to it.  Based on the program version we ended up
 * talking to ypbind with, fill out an opvector of appropriate protocol
 * modules.
 *
 * MT-safe because it is only invoked from __yp_dobind(), which serializes
 * all requests.
 */
static struct dom_binding *
load_dom_binding(struct ypbind_resp *ypbind_res, char *domain, int *err)
{
	int fd;
	struct dom_binding *pdomb;

	pdomb = NULL;

	if ((pdomb = malloc(sizeof (struct dom_binding))) == NULL) {
		syslog(LOG_ERR, "load_dom_binding:  malloc failure.");
		*err = YPERR_RESRC;
		return (NULL);
	}

	pdomb->dom_binding = ypbind_res->ypbind_resp_u.ypbind_bindinfo;
	/*
	 * Open up a path to the server, which will remain active globally.
	 */
	pdomb->dom_client = clnt_tli_create(RPC_ANYFD,
					    pdomb->dom_binding->ypbind_nconf,
					    pdomb->dom_binding->ypbind_svcaddr,
					    YPPROG, YPVERS, __ypipbufsize,
					    __ypipbufsize);
	if (pdomb->dom_client == NULL) {
		clnt_pcreateerror("yp_bind: clnt_tli_create");
		free(pdomb);
		*err = YPERR_RPC;
		return (NULL);
	}
#ifdef DEBUG
(void) printf("yp_bind: clnt_tli_create suceeded\n");
#endif

	pdomb->dom_pnext = bound_domains;	/* Link this to the list as */
	pdomb->dom_domain = malloc(strlen(domain) + (unsigned)1);
	if (pdomb->dom_domain == NULL) {
		clnt_destroy(pdomb->dom_client);
		free(pdomb);
		*err = YPERR_RESRC;
		return (NULL);
	}
	/*
	 *  We may not have loaded from a cache file, but we assume the
	 *  cache is good until we find out otherwise.
	 */
	pdomb->cache_bad = 0;
	set_rdev(pdomb);
	if (clnt_control(pdomb->dom_client, CLGET_FD, (char *)&fd))
		(void) fcntl(fd, F_SETFD, 1);  /* make it "close on exec" */

	(void) strcpy(pdomb->dom_domain, domain); /* Remember the domain name */
	pdomb->ref_count = 0;
	pdomb->need_free = 0;
	(void) mutex_init(&pdomb->server_name_lock, USYNC_THREAD, 0);
	bound_domains = pdomb;			/* ... the head entry */
	return (pdomb);
}

/*
 * XXX special code for handling C2 (passwd.adjunct) lookups when we need
 * a reserved port.
 */
static int
tli_open_rsvdport(struct netconfig *nconf)
{
	int fd;

	if (nconf == NULL)
		return (-1);

	fd = t_open(nconf->nc_device, O_RDWR, NULL);
	if (fd == -1)
		return (-1);

	if (netdir_options(nconf, ND_SET_RESERVEDPORT, fd, NULL) == -1) {
		if (t_bind(fd, NULL, NULL) == -1) {
			(void) t_close(fd);
			return (-1);
		}
	}
	return (fd);
}

/*
 * This allocates some memory for a domain binding, initialize it, and
 * returns a pointer to it.  Based on the program version we ended up
 * talking to ypbind with, fill out an opvector of appropriate protocol
 * modules.
 *
 * MT-safe because it is only invoked from __yp_dobind(), which serializes
 * all requests.
 *
 * XXX special version for handling C2 (passwd.adjunct) lookups when we need
 * a reserved port.
 *
 * Note that the binding is not cached. The caller has to free the binding
 * using free_dom_binding().
 */
static struct dom_binding *
load_dom_binding_rsvdport(struct ypbind_binding *dom_binding, char *domain,
								int *err)
{
	struct dom_binding *pdomb;
	int fd;

	pdomb = NULL;

	if ((pdomb = malloc(sizeof (struct dom_binding))) == NULL) {
		syslog(LOG_ERR, "load_dom_binding_rsvdport:  malloc failure.");
		*err = YPERR_RESRC;
		return (NULL);
	}

	pdomb->dom_binding = dom_binding;
	/*
	 * Open up a path to the server, which will remain active globally.
	 */
	fd = tli_open_rsvdport(pdomb->dom_binding->ypbind_nconf);
	if (fd < 0) {
		clnt_pcreateerror("yp_bind: tli_open_rsvdport");
		free(pdomb);
		*err = YPERR_RPC;
		return (NULL);
	}
	pdomb->dom_client = clnt_tli_create(fd,
					    pdomb->dom_binding->ypbind_nconf,
					    pdomb->dom_binding->ypbind_svcaddr,
					    YPPROG, YPVERS, __ypipbufsize,
					    __ypipbufsize);
	if (pdomb->dom_client == NULL) {
		clnt_pcreateerror("yp_bind: clnt_tli_create");
		free(pdomb);
		*err = YPERR_RPC;
		return (NULL);
	}
#ifdef DEBUG
(void) printf("yp_bind: clnt_tli_create suceeded\n");
#endif
	(void) CLNT_CONTROL(pdomb->dom_client, CLSET_FD_CLOSE, NULL);

	pdomb->dom_domain = malloc(strlen(domain) + (unsigned)1);
	if (pdomb->dom_domain == NULL) {
		clnt_destroy(pdomb->dom_client);
		free(pdomb);
		*err = YPERR_RESRC;
		return (NULL);
	}

	(void) strcpy(pdomb->dom_domain, domain); /* Remember the domain name */
	pdomb->ref_count = 0;
	pdomb->need_free = 0;
	set_rdev(pdomb);
	(void) mutex_init(&pdomb->server_name_lock, USYNC_THREAD, 0);
	return (pdomb);
}

/*
 * Attempts to locate a yellow pages server that serves a passed domain.  If
 * one is found, an entry is created on the static list of domain-server pairs
 * pointed to by cell bound_domains, a udp path to the server is created and
 * the function returns 0.  Otherwise, the function returns a defined errorcode
 * YPERR_xxxx.
 *
 * MT-safe because it serializes on bound_domains_lock.
 *
 * If hardlookup is set then loop forever until success, else try 4
 * times (each try is relatively short) max.
 */
int
__yp_dobind_cflookup(
	char *domain,
	struct dom_binding **binding,	/* if result==0, ptr to dom_binding */
	int hardlookup)

{
	struct dom_binding *pdomb;	/* Ptr to new domain binding */
	struct ypbind_resp *ypbind_resp; /* Response from local ypbinder */
	struct ypbind_domain ypbd;
	int status, err = YPERR_DOMAIN;
	int first_try = 1;
	CLIENT *tb = NULL;

	if ((domain == NULL) ||(strlen(domain) == 0))
		return (YPERR_BADARGS);

	(void) mutex_lock(&bound_domains_lock);
	/*
	 * ===>
	 * If someone managed to fork() while we were holding this lock,
	 *   we'll probably end up hanging on the lock.  Tant pis.
	 */
	newborn();

	if (check_binding(domain, binding)) {
		/*
		 *  If the cache is okay and if the underlying file
		 *  descriptor is okay (application did not close it).
		 *  then use the binding.
		 */
		if (!(*binding)->cache_bad && check_rdev(*binding)) {
			(*binding)->ref_count += 1;
			(void) mutex_unlock(&bound_domains_lock);
			return (0);		/* We are bound */
		}

		/*
		 *  If we get here, one of two things happened:  the
		 *  cache is bad, or the underlying file descriptor
		 *  had changed.
		 *
		 *  If the cache is bad, then we call yp_unbind to remove
		 *  the binding.
		 *
		 *  If the file descriptor has changed, then we call
		 *  yp_unbind to remove the binding (we set cache_bad
		 *  to force yp_unbind to do the remove), and then
		 *  call check_binding to reload the binding from the
		 *  cache again.
		 */
		if ((*binding)->cache_bad) {
			__yp_unbind_nolock(domain);
		} else {
			(*binding)->cache_bad = 1;
			(void) mutex_unlock(&bound_domains_lock);
			yp_unbind(domain);
			(void) mutex_lock(&bound_domains_lock);
			if (check_binding(domain, binding)) {
				(*binding)->ref_count += 1;
				(void) mutex_unlock(&bound_domains_lock);
				return (0);
			}
		}
	}

	do {
		if (first_try)
			first_try = 0;
		else {
			/*
			 * ===> sleep() -- Ugh.  And with the lock held, too.
			 */
			(void) sleep(_ypsleeptime);
		}
		tb = __clnt_create_loopback(YPBINDPROG, YPBINDVERS, &err);
		if (tb == NULL) {
			if (ypbind_running(err, rpc_createerr.cf_stat))
				continue;
			break;
		}
		ypbd.ypbind_domainname = domain;
		ypbd.ypbind_vers = YPVERS;
		/*
		 * The interface to ypbindproc_domain_3 is MT-unsafe, but we're
		 *   OK as long as we're the only ones who call it and we
		 *   serialize all requests (for all domains).  Otherwise,
		 *   change the interface (pass in the ypbind_resp struct).
		 */
		ypbind_resp = ypbindproc_domain_3(&ypbd, tb);
		/*
		 * Although we talk to ypbind on loopback,
		 * it gives us a udp address for the ypserv.
		 */
		if (ypbind_resp == NULL) {
			/* lost ypbind? */
			clnt_perror(tb,
				"ypbindproc_domain_3: can't contact ypbind");
			clnt_destroy(tb);
			tb = NULL;
			continue;
		}
		if (ypbind_resp->ypbind_status == YPBIND_SUCC_VAL) {
			/*
			 * Local ypbind has let us in on the ypserv's address,
			 * go get in touch with it !
			 */
			pdomb = load_dom_binding(ypbind_resp, domain, &status);
			if (pdomb == 0) {
				err = status;
				clnt_destroy(tb);
				tb = NULL;
				continue;
			}
			clnt_destroy(tb);
			pdomb->ref_count += 1;
			(void) mutex_unlock(&bound_domains_lock);
			*binding = pdomb; /* Return ptr to the binding entry */
			return (0);		/* This is the go path */
		}
		if (ypbind_resp->ypbind_resp_u.ypbind_error ==
		    YPBIND_ERR_NOSERV)
			err = YPERR_DOMAIN;
		else
			err = YPERR_YPBIND;
		clnt_destroy(tb);
		tb = NULL;
	} while (hardlookup);

	if (tb != NULL)
		clnt_destroy(tb);
	(void) mutex_unlock(&bound_domains_lock);
	if (err)
		return (err);
	return (YPERR_DOMAIN);
}

int
__yp_dobind(
	char *domain,
	struct dom_binding **binding)	/* if result == 0, ptr to dom_binding */
{
	/* traditional __yp_dobind loops forever so set hardlookup */
	return (__yp_dobind_cflookup(domain, binding, 1));
}

void
__yp_rel_binding(struct dom_binding *binding)
{
	(void) mutex_lock(&bound_domains_lock);
	binding->ref_count -= 1;
	if (binding->need_free && binding->ref_count == 0)
		free_dom_binding(binding);
	(void) mutex_unlock(&bound_domains_lock);
}

/*
 * Attempts to locate a yellow pages server that serves a passed domain.  If
 * one is found, an entry is created on the static list of domain-server pairs
 * pointed to by cell bound_domains, a udp path to the server is created and
 * the function returns 0.  Otherwise, the function returns a defined errorcode
 * YPERR_xxxx.
 *
 * MT-safe because it serializes on bound_domains_lock.
 *
 * XXX special version for handling C2 (passwd.adjunct) lookups when we need
 * a reserved port.
 * This returns an uncached binding which the caller has to free using
 * free_dom_binding().
 */
int
__yp_dobind_rsvdport_cflookup(
	char *domain,
	struct dom_binding **binding,	/* if result==0, ptr to dom_binding */
	int hardlookup)
{
	struct dom_binding *pdomb;	/* Ptr to new domain binding */
	struct ypbind_resp *ypbind_resp; /* Response from local ypbinder */
	struct ypbind_domain ypbd;
	int status,  err = YPERR_DOMAIN;
	int first_try = 1;
	CLIENT *tb = NULL;

	if ((domain == NULL) ||(strlen(domain) == 0))
		return (YPERR_BADARGS);

	(void) mutex_lock(&bound_domains_lock);
	/*
	 * ===>
	 * If someone managed to fork() while we were holding this lock,
	 *   we'll probably end up hanging on the lock.  Tant pis.
	 */
	newborn();

	/*
	 * Check for existing bindings and use the information in the binding
	 * to create a transport endpoint with a reserved port.
	 */
	if (check_binding(domain, binding)) {
		/*
		 * If the cache is bad, yp_unbind() the entry again and then
		 * talk to ypbind.
		 */
		if ((*binding)->cache_bad) {
			__yp_unbind_nolock(domain);
		} else {
			pdomb = load_dom_binding_rsvdport(
						(*binding)->dom_binding,
							domain, &status);
			if (pdomb == 0) {
				(void) mutex_unlock(&bound_domains_lock);
				return (status);
			}
			pdomb->ref_count += 1;
			(void) mutex_unlock(&bound_domains_lock);
			*binding = pdomb; /* Return ptr to the binding entry */
			return (0);
		}
	}

	do {
		if (first_try)
			first_try = 0;
		else {
			/*
			 * ===> sleep() -- Ugh.  And with the lock held, too.
			 */
			(void) sleep(_ypsleeptime);
		}
		tb = __clnt_create_loopback(YPBINDPROG, YPBINDVERS, &err);
		if (tb == NULL) {
			if (ypbind_running(err, rpc_createerr.cf_stat))
				continue;
			break;
		}
		ypbd.ypbind_domainname = domain;
		ypbd.ypbind_vers = YPVERS;
		/*
		 * The interface to ypbindproc_domain_3 is MT-unsafe, but we're
		 *   OK as long as we're the only ones who call it and we
		 *   serialize all requests (for all domains).  Otherwise,
		 *   change the interface (pass in the ypbind_resp struct).
		 */
		ypbind_resp = ypbindproc_domain_3(&ypbd, tb);
		/*
		 * Although we talk to ypbind on loopback,
		 * it gives us a udp address for the ypserv.
		 */
		if (ypbind_resp == NULL) {
			/* lost ypbind? */
			clnt_perror(tb,
				"ypbindproc_domain_3: can't contact ypbind");
			clnt_destroy(tb);
			tb = NULL;
			continue;
		}
		if (ypbind_resp->ypbind_status == YPBIND_SUCC_VAL) {
			/*
			 * Local ypbind has let us in on the ypserv's address,
			 * go get in touch with it !
			 */
			pdomb = load_dom_binding_rsvdport(
				    ypbind_resp->ypbind_resp_u.ypbind_bindinfo,
				    domain, &status);
			if (pdomb == 0) {
				err = status;
				clnt_destroy(tb);
				tb = NULL;
				continue;
			}
			clnt_destroy(tb);
			pdomb->ref_count += 1;
			(void) mutex_unlock(&bound_domains_lock);
			*binding = pdomb; /* Return ptr to the binding entry */
			return (0);		/* This is the go path */
		}
		if (ypbind_resp->ypbind_resp_u.ypbind_error ==
		    YPBIND_ERR_NOSERV)
			err = YPERR_DOMAIN;
		else
			err = YPERR_YPBIND;
		clnt_destroy(tb);
		tb = NULL;
	} while (hardlookup);

	if (tb != NULL)
		clnt_destroy(tb);
	(void) mutex_unlock(&bound_domains_lock);
	if (err)
		return (err);
	return (YPERR_DOMAIN);
}

int
__yp_dobind_rsvdport(
	char *domain,
	struct dom_binding **binding)	/* if result==0, ptr to dom_binding */
{
	/* traditional __yp_dobind_rsvdport loops forever so set hardlookup */
	return (__yp_dobind_rsvdport_cflookup(domain, binding, 1));
}

/*
 * This is a "wrapper" function for __yp_dobind for vanilla user-level
 * functions which neither know nor care about struct dom_bindings.
 */
int
yp_bind(char *domain)
{

	struct dom_binding *binding;
	int    res;

	res = __yp_dobind(domain, &binding);
	if (res == 0)
		__yp_rel_binding(binding);
	return (res);
}

static char *
__default_domain(void)
{
	char temp[256];

	(void) mutex_lock(&default_domain_lock);

	if (default_domain) {
		(void) mutex_unlock(&default_domain_lock);
		return (default_domain);
	}
	if (getdomainname(temp, sizeof (temp)) < 0) {
		(void) mutex_unlock(&default_domain_lock);
		return (0);
	}
	if (strlen(temp) > 0) {
		default_domain = malloc((strlen(temp) + 1));
		if (default_domain == 0) {
			(void) mutex_unlock(&default_domain_lock);
			return (0);
		}
		(void) strcpy(default_domain, temp);
		(void) mutex_unlock(&default_domain_lock);
		return (default_domain);
	}
	(void) mutex_unlock(&default_domain_lock);
	return (0);
}

/*
 * This is a wrapper for the system call getdomainname which returns a
 * ypclnt.h error code in the failure case.  It also checks to see that
 * the domain name is non-null, knowing that the null string is going to
 * get rejected elsewhere in the yp client package.
 */
int
yp_get_default_domain(char **domain)
{
	if ((*domain = __default_domain()) != 0)
		return (0);
	return (YPERR_YPERR);
}

/*
 * ===> Nobody uses this, do they?  Can we nuke it?
 */
int
usingypmap(char **ddn, char *map)
{
	char in, *outval = NULL;
	int outvallen, stat;
	char *domain;

	if ((domain = __default_domain()) == 0)
		return (FALSE);
	*ddn = domain;
	/* does the map exist ? */
	in = (char)0xff;
	stat = yp_match(domain, map, &in, 1, &outval, &outvallen);
	if (outval != NULL)
		free(outval);
	switch (stat) {

	case 0:  /* it actually succeeded! */
	case YPERR_KEY:  /* no such key in map */
	case YPERR_NOMORE:
	case YPERR_BUSY:
		return (TRUE);
	}
	return (FALSE);
}

/*
 * Creates a quick connection on a connection oriented loopback
 * transport. Fails quickly without timeout. Only naming service
 * it goes to is straddr.so.
 */
CLIENT *
__clnt_create_loopback(rpcprog_t prog, rpcvers_t vers, int *err)
{
	struct netconfig *nconf;
	CLIENT *clnt = NULL;
	void *nc_handle;	/* Net config handle */

	*err = 0;
	nc_handle = setnetconfig();
	if (nc_handle == NULL) {
		/* fails to open netconfig file */
		rpc_createerr.cf_stat = RPC_FAILED;
		*err = YPERR_RPC;
		return (NULL);
	}
	while (nconf = getnetconfig(nc_handle))
		/* Try only one connection oriented loopback transport */
		if ((strcmp(nconf->nc_protofmly, NC_LOOPBACK) == 0) &&
			((nconf->nc_semantics == NC_TPI_COTS) ||
			(nconf->nc_semantics == NC_TPI_COTS_ORD))) {
			clnt = getclnt(prog, vers, nconf, err);
			break;
		}
	(void) endnetconfig(nc_handle);

	if (clnt == NULL) {	/* no loopback transport available */
		if (rpc_createerr.cf_stat == 0)
			rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
		if (*err == 0) *err = YPERR_RPC;
	}
	return (clnt);
}

static CLIENT *
getclnt(rpcprog_t prog, rpcvers_t vers, struct netconfig *nconf, int *err)
{
	int fd;
	struct netbuf *svcaddr;			/* servers address */
	CLIENT *cl;
	struct nd_addrlist *nas;
	struct nd_hostserv rpcbind_hs;
	struct t_call sndcall;
	char uaddress[1024]; /* XXX maxlen ?? */
	RPCB parms;
	enum clnt_stat clnt_st;
	char *ua;
	struct timeval tv = { 30, 0 };

	if (nconf == NULL) {
		rpc_createerr.cf_stat = RPC_TLIERROR;
		*err = YPERR_RPC;
		return (NULL);
	}

	/*
	 *  The ypbind process might cache its transport address.
	 *  If we can get at it, then we will use it and avoid
	 *  wasting time talking to rpcbind.
	 */

	if (get_cached_transport(nconf, vers, uaddress, sizeof (uaddress))) {
		goto create_client;
	}

	/*
	 * Check to see if local rpcbind is up or not. If it
	 * isn't, it is best that the application should realize
	 * yp is not up and take a remedial action. This is to
	 * avoid the minute long timeout incurred by rpcbind_getaddr.
	 * Looks like the only way to accomplish this it is to unfold
	 * rpcb_getaddr and make a few changes. Alas !
	 */
	rpcbind_hs.h_host = HOST_SELF_CONNECT;
	rpcbind_hs.h_serv = "rpcbind";
	if (netdir_getbyname(nconf, &rpcbind_hs, &nas) != ND_OK) {
		rpc_createerr.cf_stat = RPC_N2AXLATEFAILURE;
		*err = YPERR_RPC;
		return (NULL);
	}
	if ((fd = t_open(nconf->nc_device, O_RDWR, NULL)) == -1) {
		rpc_createerr.cf_stat = RPC_TLIERROR;
		*err = YPERR_RPC;
		return (NULL);
	}
	if (t_bind(fd, NULL, NULL) == -1) {
		rpc_createerr.cf_stat = RPC_TLIERROR;
		*err = YPERR_RPC;
		(void) t_close(fd);
		return (NULL);
	}
	sndcall.addr = *(nas->n_addrs);
	sndcall.opt.len = 0;
	sndcall.udata.len = 0;
	if (t_connect(fd, &sndcall, NULL) == -1) {
		netdir_free((char *)nas, ND_ADDRLIST);
		rpc_createerr.cf_stat = RPC_TLIERROR;
		(void) t_close(fd);
		*err = YPERR_PMAP;
		return (NULL);
	}

	/*
	 * Get the address of the server
	 */
	cl = clnt_tli_create(fd, nconf, nas->n_addrs,
		RPCBPROG, RPCBVERS, __ypipbufsize, __ypipbufsize);
	netdir_free((char *)nas, ND_ADDRLIST);
	if (cl == NULL) {
		(void) t_close(fd);
		*err = YPERR_PMAP;
		return (NULL);
	}
	parms.r_prog = prog;
	parms.r_vers = vers;
	parms.r_netid = nconf->nc_netid;
	parms.r_addr = nullstring;
	parms.r_owner = nullstring;
	ua = uaddress;
	clnt_st = CLNT_CALL(cl, RPCBPROC_GETADDR, xdr_rpcb, (char *)&parms,
		xdr_wrapstring, (char *)&ua, tv);
	(void) t_close(fd);
	clnt_destroy(cl);
	if (clnt_st != RPC_SUCCESS) {
		*err = YPERR_YPBIND;
		return (NULL);
	}
	if (strlen(uaddress) == 0) {
		*err = YPERR_YPBIND;
		rpc_createerr.cf_stat = RPC_PROGNOTREGISTERED;
		return (NULL);
	}

create_client:
	svcaddr = uaddr2taddr(nconf, uaddress);
	cl = clnt_tli_create(RPC_ANYFD, nconf, svcaddr, prog, vers,
					__ypipbufsize, __ypipbufsize);
	netdir_free((char *)svcaddr, ND_ADDR);
	if (cl == NULL) {
		*err = YPERR_YPBIND;
		return (NULL);
	}
	/*
	 * The fd should be closed while destroying the handle.
	 */
	return (cl);
}

static int
get_cached_transport(struct netconfig *nconf, int vers, char *uaddress,
								int ulen)
{
	ssize_t st;
	int fd;

	(void) snprintf(uaddress, ulen,
		"%s/xprt.%s.%d", BINDING, nconf->nc_netid, vers);
	fd = open(uaddress, O_RDONLY);
	if (fd == -1)
		return (0);

	/* if first byte is not locked, then ypbind must not be running */
	st = lockf(fd, F_TEST, 1);
	if (st != -1 || (errno != EAGAIN && errno != EACCES)) {
		(void) close(fd);
		return (0);
	}

	st = read(fd, uaddress, ulen);
	if (st == -1) {
		(void) close(fd);
		return (0);
	}

	(void) close(fd);
	return (1);
}

static ypbind_resp *
get_cached_domain(char *domain)
{
	FILE *fp;
	int st;
	char filename[300];
	static ypbind_resp res;
	XDR xdrs;

	(void) snprintf(filename, sizeof (filename),
					"%s/%s/cache_binding", BINDING, domain);
	fp = fopen(filename, "rF");
	if (fp == 0)
		return (0);

	/* if first byte is not locked, then ypbind must not be running */
	st = lockf(fileno(fp), F_TEST, 1);
	if (st != -1 || (errno != EAGAIN && errno != EACCES)) {
		(void) fclose(fp);
		return (0);
	}

	xdrstdio_create(&xdrs, fp, XDR_DECODE);

	(void) memset((char *)&res, 0, sizeof (res));
	st = xdr_ypbind_resp(&xdrs, &res);

	xdr_destroy(&xdrs);
	(void) fclose(fp);

	if (st)
		return (&res);

	return (0);
}

static int
ypbind_running(int err, int status)
{
	char filename[300];
	int st;
	int fd;

	(void) snprintf(filename, sizeof (filename), "%s/ypbind.pid", BINDING);
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		if ((err == YPERR_YPBIND) && (status != RPC_PROGNOTREGISTERED))
			return (1);
		return (0);
	}

	/* if first byte is not locked, then ypbind must not be running */
	st = lockf(fd, F_TEST, 1);
	if (st != -1 || (errno != EAGAIN && errno != EACCES)) {
		(void) close(fd);
		return (0);
	}

	(void) close(fd);
	return (1);
}

static void
set_rdev(struct dom_binding *pdomb)
{
	int fd;
	struct stat stbuf;

	if (clnt_control(pdomb->dom_client, CLGET_FD, (char *)&fd) != TRUE ||
	    fstat(fd, &stbuf) == -1) {
		syslog(LOG_DEBUG, "ypbind client:  can't get rdev");
		pdomb->fd = -1;
		return;
	}
	pdomb->fd = fd;
	pdomb->rdev = stbuf.st_rdev;
}

static int
check_rdev(struct dom_binding *pdomb)
{
	struct stat stbuf;

	if (pdomb->fd == -1)
		return (1);    /* can't check it, assume it is okay */

	if (fstat(pdomb->fd, &stbuf) == -1) {
		syslog(LOG_DEBUG, "yp_bind client:  can't stat %d", pdomb->fd);
		/* could be because file descriptor was closed */
		/* it's not our file descriptor, so don't try to close it */
		clnt_control(pdomb->dom_client, CLSET_FD_NCLOSE, NULL);
		return (0);
	}
	if (pdomb->rdev != stbuf.st_rdev) {
		syslog(LOG_DEBUG,
		    "yp_bind client:  fd %d changed, old=0x%x, new=0x%x",
		    pdomb->fd, pdomb->rdev, stbuf.st_rdev);
		/* it's not our file descriptor, so don't try to close it */
		clnt_control(pdomb->dom_client, CLSET_FD_NCLOSE, NULL);
		return (0);
	}
	return (1);    /* fd is okay */
}
