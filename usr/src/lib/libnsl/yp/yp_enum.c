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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley
 * under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <stdlib.h>
#include <unistd.h>
#include <rpc/rpc.h>
#include <sys/types.h>
#include "yp_b.h"
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#include <string.h>

extern int __yp_dobind_cflookup(char *, struct dom_binding **, int);

static int dofirst(char *, char *, struct dom_binding *, struct timeval,
    char **, int  *, char **, int  *);

static int donext(char *, char *, char *, int, struct dom_binding *,
    struct timeval, char **, int *, char **val, int *);

/*
 * This requests the yp server associated with a given domain to return the
 * first key/value pair from the map data base.  The returned key should be
 * used as an input to the call to ypclnt_next.  This part does the parameter
 * checking, and the do-until-success loop if 'hardlookup' is set.
 */
int
__yp_first_cflookup(
	char *domain,
	char *map,
	char **key,		/* return: key array */
	int  *keylen,		/* return: bytes in key */
	char **val,		/* return: value array */
	int  *vallen,		/* return: bytes in val */
	int  hardlookup)
{
	size_t domlen;
	size_t maplen;
	struct dom_binding *pdomb;
	int reason;

	if ((map == NULL) || (domain == NULL))
		return (YPERR_BADARGS);

	domlen =  strlen(domain);
	maplen =  strlen(map);

	if ((domlen == 0) || (domlen > YPMAXDOMAIN) ||
	    (maplen == 0) || (maplen > YPMAXMAP))
		return (YPERR_BADARGS);

	for (;;) {

		if (reason = __yp_dobind_cflookup(domain, &pdomb, hardlookup))
			return (reason);

		if (pdomb->dom_binding->ypbind_hi_vers == YPVERS) {

			reason = dofirst(domain, map, pdomb, _ypserv_timeout,
			    key, keylen, val, vallen);

			__yp_rel_binding(pdomb);
			if (reason == YPERR_RPC || reason == YPERR_YPSERV ||
			    reason == YPERR_BUSY /* as if */) {
				yp_unbind(domain);
				if (hardlookup)
					(void) sleep(_ypsleeptime); /* retry */
				else
					return (reason);
			} else
				break;
		} else {
			__yp_rel_binding(pdomb);
			return (YPERR_VERS);
		}
	}
	return (reason);
}

int
yp_first(
	char *domain,
	char *map,
	char **key,		/* return: key array */
	int  *keylen,		/* return: bytes in key */
	char **val,		/* return: value array */
	int  *vallen)		/* return: bytes in val */
{
	/* traditional yp_firs loops forever until success */
	return (__yp_first_cflookup(domain, map, key, keylen, val, vallen, 1));
}

/*
 * This part of the "get first" interface talks to ypserv.
 */

static int
dofirst(domain, map, pdomb, timeout, key, keylen, val, vallen)
	char *domain;
	char *map;
	struct dom_binding *pdomb;
	struct timeval timeout;
	char **key;
	int  *keylen;
	char **val;
	int  *vallen;

{
	struct ypreq_nokey req;
	struct ypresp_key_val resp;
	unsigned int retval = 0;

	req.domain = domain;
	req.map = map;
	resp.keydat.dptr = resp.valdat.dptr = NULL;
	resp.keydat.dsize = resp.valdat.dsize = 0;

	/*
	 * Do the get first request.  If the rpc call failed, return with status
	 * from this point.
	 */

	(void) memset((char *)&resp, 0, sizeof (struct ypresp_key_val));

	switch (clnt_call(pdomb->dom_client, YPPROC_FIRST,
			(xdrproc_t)xdr_ypreq_nokey,
			(char *)&req, (xdrproc_t)xdr_ypresp_key_val,
			(char *)&resp, timeout)) {
	case RPC_SUCCESS:
		break;
	case RPC_TIMEDOUT:
		return (YPERR_YPSERV);
	default:
		return (YPERR_RPC);
	}

	/* See if the request succeeded */

	if (resp.status != YP_TRUE) {
		retval = ypprot_err(resp.status);
	}

	/* Get some memory which the user can get rid of as they like */

	if (!retval) {

		if ((*key = malloc((size_t)resp.keydat.dsize + 2)) != NULL) {

			if ((*val = malloc(
			    (size_t)resp.valdat.dsize + 2)) == NULL) {
				free(*key);
				retval = YPERR_RESRC;
			}

		} else {
			retval = YPERR_RESRC;
		}
	}

	/* Copy the returned key and value byte strings into the new memory */

	if (!retval) {
		*keylen = (int)resp.keydat.dsize;
		(void) memcpy(*key, resp.keydat.dptr,
		    (size_t)resp.keydat.dsize);
		(*key)[resp.keydat.dsize] = '\n';
		(*key)[resp.keydat.dsize + 1] = '\0';

		*vallen = (int)resp.valdat.dsize;
		(void) memcpy(*val, resp.valdat.dptr,
		    (size_t)resp.valdat.dsize);
		(*val)[resp.valdat.dsize] = '\n';
		(*val)[resp.valdat.dsize + 1] = '\0';
	}

	CLNT_FREERES(pdomb->dom_client,
		(xdrproc_t)xdr_ypresp_key_val, (char *)&resp);
	return (retval);
}

/*
 * This requests the yp server associated with a given domain to return the
 * "next" key/value pair from the map data base.  The input key should be
 * one returned by ypclnt_first or a previous call to ypclnt_next.  The
 * returned key should be used as an input to the next call to ypclnt_next.
 * This part does the parameter checking, and the do-until-success loop.
 * if 'hardlookup' is set.
 */
int
__yp_next_cflookup(
	char *domain,
	char *map,
	char *inkey,
	int  inkeylen,
	char **outkey,		/* return: key array associated with val */
	int  *outkeylen,	/* return: bytes in key */
	char **val,		/* return: value array associated with outkey */
	int  *vallen,		/* return: bytes in val */
	int  hardlookup)
{
	size_t domlen;
	size_t maplen;
	struct dom_binding *pdomb;
	int reason;


	if ((map == NULL) || (domain == NULL) || (inkey == NULL))
		return (YPERR_BADARGS);

	domlen =  strlen(domain);
	maplen =  strlen(map);

	if ((domlen == 0) || (domlen > YPMAXDOMAIN) ||
	    (maplen == 0) || (maplen > YPMAXMAP))
		return (YPERR_BADARGS);

	for (;;) {
		if (reason = __yp_dobind_cflookup(domain, &pdomb, hardlookup))
			return (reason);

		if (pdomb->dom_binding->ypbind_hi_vers == YPVERS) {

			reason = donext(domain, map, inkey, inkeylen, pdomb,
			    _ypserv_timeout, outkey, outkeylen, val, vallen);

			__yp_rel_binding(pdomb);

			if (reason == YPERR_RPC || reason == YPERR_YPSERV ||
			    reason == YPERR_BUSY /* as if */) {
				yp_unbind(domain);
				if (hardlookup)
					(void) sleep(_ypsleeptime); /* retry */
				else
					return (reason);
			} else
				break;
		} else {
			__yp_rel_binding(pdomb);
			return (YPERR_VERS);
		}
	}

	return (reason);
}

int
yp_next(
	char *domain,
	char *map,
	char *inkey,
	int  inkeylen,
	char **outkey,		/* return: key array associated with val */
	int  *outkeylen,	/* return: bytes in key */
	char **val,		/* return: value array associated with outkey */
	int  *vallen)		/* return: bytes in val */
{
	/* traditional yp_next loops forever until success */
	return (__yp_next_cflookup(domain, map, inkey, inkeylen, outkey,
				outkeylen, val, vallen, 1));
}


/*
 * This part of the "get next" interface talks to ypserv.
 */
static int
donext(domain, map, inkey, inkeylen, pdomb, timeout, outkey, outkeylen,
    val, vallen)
	char *domain;
	char *map;
	char *inkey;
	int  inkeylen;
	struct dom_binding *pdomb;
	struct timeval timeout;
	char **outkey;		/* return: key array associated with val */
	int  *outkeylen;	/* return: bytes in key */
	char **val;		/* return: value array associated with outkey */
	int  *vallen;		/* return: bytes in val */

{
	struct ypreq_key req;
	struct ypresp_key_val resp;
	unsigned int retval = 0;

	req.domain = domain;
	req.map = map;
	req.keydat.dptr = inkey;
	req.keydat.dsize = inkeylen;

	resp.keydat.dptr = resp.valdat.dptr = NULL;
	resp.keydat.dsize = resp.valdat.dsize = 0;

	/*
	 * Do the get next request.  If the rpc call failed, return with status
	 * from this point.
	 */

	switch (clnt_call(pdomb->dom_client,
			YPPROC_NEXT, (xdrproc_t)xdr_ypreq_key, (char *)&req,
			(xdrproc_t)xdr_ypresp_key_val, (char *)&resp,
			timeout)) {
	case RPC_SUCCESS:
		break;
	case RPC_TIMEDOUT:
		return (YPERR_YPSERV);
	default:
		return (YPERR_RPC);
	}

	/* See if the request succeeded */

	if (resp.status != YP_TRUE) {
		retval = ypprot_err(resp.status);
	}

	/* Get some memory which the user can get rid of as they like */

	if (!retval) {
		if ((*outkey = malloc((size_t)
		    resp.keydat.dsize + 2)) != NULL) {

			if ((*val = malloc((size_t)
			    resp.valdat.dsize + 2)) == NULL) {
				free(*outkey);
				retval = YPERR_RESRC;
			}

		} else {
			retval = YPERR_RESRC;
		}
	}

	/* Copy the returned key and value byte strings into the new memory */

	if (!retval) {
		*outkeylen = (int)resp.keydat.dsize;
		(void) memcpy(*outkey, resp.keydat.dptr,
		    (size_t)resp.keydat.dsize);
		(*outkey)[resp.keydat.dsize] = '\n';
		(*outkey)[resp.keydat.dsize + 1] = '\0';

		*vallen = (int)resp.valdat.dsize;
		(void) memcpy(*val, resp.valdat.dptr,
		    (size_t)resp.valdat.dsize);
		(*val)[resp.valdat.dsize] = '\n';
		(*val)[resp.valdat.dsize + 1] = '\0';
	}

	CLNT_FREERES(pdomb->dom_client, (xdrproc_t)xdr_ypresp_key_val,
		    (char *)&resp);
	return (retval);
}
