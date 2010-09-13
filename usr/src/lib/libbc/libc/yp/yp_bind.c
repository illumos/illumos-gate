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
 * Copyright 1992 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI" 

#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#include <rpc/rpc.h>
#include <rpc/pmap_prot.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/syslog.h>
 
#include "yp_prot.h"
#include "ypv1_prot.h"
#include "ypclnt.h"

/*
 * This is the same as struct dom_binding used by the base __yp_dobind().
 * Named differently here to avoid name conflict with the compat
 * struct dom_binding.
 */

/* Copied from base <sys/netconfig.h> */

struct  netconfig {
	char		*nc_netid;	/* network identifier		*/
	unsigned long	nc_semantics;	/* defined below		*/
	unsigned long	nc_flag;	/* defined below		*/
	char		*nc_protofmly;	/* protocol family name		*/
	char		*nc_proto;	/* protocol name		*/
	char		*nc_device;	/* device name for network id	*/
	unsigned long	nc_nlookups;	/* # of entries in nc_lookups	*/
	char		**nc_lookups;	/* list of lookup directories	*/
	unsigned long	nc_unused[8];
};

/* Copied from base <sys/tiuser.h> */

struct netbuf {
	unsigned int maxlen;
	unsigned int len;
	char *buf;
};

struct s5_dom_binding {
	struct s5_dom_binding *dom_next;
	char *dom_domain;
	struct s5_ypbind_binding *dom_binding;
	CLIENT *dom_client;
};

struct s5_ypbind_binding {
	struct netconfig *ypbind_conf;
	struct netbuf *ypbind_svcaddr;
	char *ypbind_servername;
	long ypbind_hi_vers;
	long ypbind_lo_vers;
};

static void _yp_unbind();
static struct	dom_binding *load_dom_binding_cache();

static struct dom_binding *bound_domains; /* List of bound domains */

/*
 * This is a "wrapper" function that is implemented by the yp_bind()
 * function in base libnsl/yp.
 */
#ifdef NOTDEFINED
int
yp_bind(domain)
	char *domain;
{
	/* XXX */
	_yp_bind(domain);
}
#endif

/*
 * Attempts to find a dom_binding in the list at bound_domains having the
 * domain name field equal to the passed domain name, and removes it if found.
 * The domain-server binding will not exist after the call to this function.
 * All resources associated with the binding will be freed.
 */
#ifdef NOTDEFINED
void
yp_unbind (domain)
	char *domain;
{
	_yp_unbind(domain); /* clean our local cache */
	/* XXX */
	_yp_unbind(domain);
}
#endif

/*
 * This is a wrapper around the yp_get_default_domain()
 * function in base libnsl/yp.
 */
#ifdef NOTDEFINED
int
yp_get_default_domain(domain)
	char **domain;
{
	/* XXX */
	_yp_get_default_domain(domain);
}
#endif

/*
 * Attempts to locate a NIS server that serves a passed domain.
 * This is a wrapper around the __yp_dobind() function in base
 * libnsl/yp; it converts the libnsl [netbuf based] dom_binding structure into
 * the [sockaddr based] one that is expected by binary compat apps. Note that,
 * the wrapper must allocate memory resources in order to hold
 * the 
 */
int
_yp_dobind(domain, binding)
	char *domain;
	struct dom_binding **binding;	/* if result == 0, ptr to dom_binding */
{
	int retval;
	struct s5_dom_binding *dom_binding; /* Ptr to dom_binding from libnsl __yp_dobind() */
	int status;

	/* XXX */
	retval = __yp_dobind(domain, &dom_binding);
	if (retval != 0)
		return(retval);

	if ((*binding = load_dom_binding_cache(domain, dom_binding)) == NULL)
		return (YPERR_RESRC);		/* make sure it is in our cache */
	return (0);				/* This is the go path */
}


/*
 * This allocates some memory for a domain binding, initialize it, and
 * returns a pointer to it.  Based on the program version we ended up
 * talking to ypbind with, fill out an opvector of appropriate protocol
 * modules.
 */
static struct dom_binding *
load_dom_binding_cache(domain, dom_binding)
	char *domain;
	struct s5_dom_binding *dom_binding;
{
	struct dom_binding *pdomb = NULL;
	struct sockaddr_in *sa;	/* To get a port bound to socket */
	struct sockaddr_in local_name;
	int local_name_len = sizeof(struct sockaddr_in);


	for (pdomb = bound_domains; pdomb != NULL; pdomb = pdomb->dom_pnext) {
		if (strcmp(domain, pdomb->dom_domain) == 0)
				return (pdomb);
	}

	if ((pdomb = (struct dom_binding *) malloc(sizeof(struct dom_binding)))
		== NULL) {
		(void) syslog(LOG_ERR, "load_dom_binding_cache:  malloc failure.");
		return (struct dom_binding *) (NULL);
	}

	sa = (struct sockaddr_in *)dom_binding->dom_binding->ypbind_svcaddr->buf;
	pdomb->dom_server_addr.sin_family = sa->sin_family;
	pdomb->dom_server_addr.sin_port = sa->sin_port;
	pdomb->dom_server_addr.sin_addr.s_addr = sa->sin_addr.s_addr;
	bzero(pdomb->dom_server_addr.sin_zero, 8);
	pdomb->dom_server_port = sa->sin_port;
	pdomb->dom_socket = RPC_ANYSOCK;
	pdomb->dom_vers = dom_binding->dom_binding->ypbind_hi_vers;
	/* the claim is 5.0 CLIENT * can be used by a 4.x RPC user */
	pdomb->dom_client = dom_binding->dom_client;

	(void) strcpy(pdomb->dom_domain, domain);/* Remember the domain name */
	pdomb->dom_pnext = bound_domains;	/* Link this to the list as */
	bound_domains = pdomb;			/* ... the head entry */

	return (pdomb);
}

static void
_yp_unbind (domain)
	char *domain;
{
	struct dom_binding *pdomb;
	struct dom_binding *ptrail = 0;


	if ( (domain == NULL) ||(strlen(domain) == 0) ) {
		return;
	}

	for (pdomb = bound_domains; pdomb != NULL;
	    ptrail = pdomb, pdomb = pdomb->dom_pnext) {

		if (strcmp(domain, pdomb->dom_domain) == 0) {
			if (pdomb == bound_domains)
				bound_domains = pdomb->dom_pnext;
			else
				ptrail->dom_pnext = pdomb->dom_pnext;
			free((char *) pdomb);
			break;
		}
	}
}

int
yp_ismapthere(stat)
	int stat;
{

	switch (stat) {

	case 0:  /* it actually succeeded! */
	case YPERR_KEY:  /* no such key in map */
	case YPERR_NOMORE:
	case YPERR_BUSY:
		return (TRUE);
	}
	return (FALSE);
}
