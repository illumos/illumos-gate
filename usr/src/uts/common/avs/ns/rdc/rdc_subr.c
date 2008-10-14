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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/errno.h>

#ifdef _SunOS_2_6
/*
 * on 2.6 both dki_lock.h and rpc/types.h define bool_t so we
 * define enum_t here as it is all we need from rpc/types.h
 * anyway and make it look like we included it. Yuck.
 */
#define	_RPC_TYPES_H
typedef int enum_t;
#else
#ifndef DS_DDICT
#include <rpc/types.h>
#endif
#endif /* _SunOS_2_6 */

#include <sys/nsc_thread.h>
#include <sys/nsctl/nsctl.h>
#include "rdc_io.h"
#include "rdc_ioctl.h"
#include "rdc_prot.h"

/*
 * Initialize a netbuf suitable for
 * describing an address
 */

void
init_rdc_netbuf(struct netbuf *nbuf)
{
	nbuf->buf = kmem_zalloc(RDC_MAXADDR, KM_SLEEP);
	nbuf->maxlen = RDC_MAXADDR;
	nbuf->len = 0;
}

/*
 * Free a netbuf
 */

void
free_rdc_netbuf(struct netbuf *nbuf)
{
	if (!(nbuf) || !(nbuf->buf)) {
#ifdef DEBUG
		cmn_err(CE_PANIC, "Null netbuf in free_rdc_netbuf");
#endif
		return;
	}
	kmem_free(nbuf->buf, nbuf->maxlen);
	nbuf->buf = NULL;
	nbuf->maxlen = 0;
	nbuf->len = 0;
}


/*
 * Duplicate a netbuf, must be followed by a free_rdc_netbuf().
 */
void
dup_rdc_netbuf(const struct netbuf *from, struct netbuf *to)
{
	init_rdc_netbuf(to);
	to->len = from->len;

	if (from->len > to->maxlen) {
		cmn_err(CE_WARN, "dup_rdc_netbuf: from->len %d, to->maxlen %d",
			from->len, to->maxlen);
	}

	bcopy(from->buf, to->buf, (size_t)from->len);
}


#ifdef DEBUG
void
rdc_print_svinfo(rdc_srv_t *svp, char *str)
{
	int i;

	if (svp == NULL)
		return;

	cmn_err(CE_NOTE, "rdc %s servinfo: %p\n", str, (void *) svp);

	if (svp->ri_knconf != NULL) {
		cmn_err(CE_NOTE, "knconf: semantics %d",
		    svp->ri_knconf->knc_semantics);
		cmn_err(CE_NOTE, "	protofmly %s",
		    svp->ri_knconf->knc_protofmly);
		cmn_err(CE_NOTE, "	proto	  %s",
		    svp->ri_knconf->knc_proto);
		cmn_err(CE_NOTE, "	rdev	  %lx",
		    svp->ri_knconf->knc_rdev);
	}

	for (i = 0; i < svp->ri_addr.len; i++)
		printf("%u ", svp->ri_addr.buf[i]);

	cmn_err(CE_NOTE, "\naddr:	len %d buf %p\n",
	    svp->ri_addr.len, (void *) svp->ri_addr.buf);
	cmn_err(CE_NOTE, "host:	%s\n", svp->ri_hostname);
}
#endif /* DEBUG */

/*
 * Initialize an rdc servinfo
 * Contains all the protocol we need to do a client rpc
 * A chain of rdc_srv_t indicates a one to many
 */

rdc_srv_t *
rdc_create_svinfo(char *host, struct netbuf *svaddr, struct knetconfig *conf)
{
	rdc_srv_t *nvp;
	int hlen = strlen(host) + 1;

	if (conf == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_create_svinfo: NULL knetconfig\n");
#endif
		return (NULL);
	}

	if (host == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_create_svinfo: NULL host\n");
#endif
		return (NULL);
	}

	nvp = kmem_zalloc(sizeof (*nvp), KM_SLEEP);
	nvp->ri_knconf = kmem_alloc(sizeof (*nvp->ri_knconf), KM_SLEEP);
	nvp->ri_hostname = kmem_zalloc(hlen, KM_SLEEP);

	if (nvp == NULL || nvp->ri_hostname == NULL || nvp->ri_knconf == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_create_svinfo: zalloc failed");
#endif
		rdc_destroy_svinfo(nvp);
		return (NULL);
	}

	nvp->ri_hostnamelen = hlen;

	bcopy((void *)conf, (void *)nvp->ri_knconf, sizeof (*nvp->ri_knconf));
	nvp->ri_knconf->knc_protofmly = kmem_zalloc(KNC_STRSIZE + 1, KM_SLEEP);
	nvp->ri_knconf->knc_proto = kmem_zalloc(KNC_STRSIZE + 1, KM_SLEEP);

	if (nvp->ri_knconf->knc_protofmly == NULL ||
	    nvp->ri_knconf->knc_proto == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_create_svinfo: out of memory\n");
#endif
		rdc_destroy_svinfo(nvp);
		return (NULL);

	}

	(void) strncpy(nvp->ri_knconf->knc_protofmly, conf->knc_protofmly,
		KNC_STRSIZE);
	(void) strncpy(nvp->ri_knconf->knc_proto, conf->knc_proto, KNC_STRSIZE);

	dup_rdc_netbuf(svaddr, &nvp->ri_addr);

	nvp->ri_secdata = NULL;		/* For now */
	(void) strncpy(nvp->ri_hostname, host, hlen);
#ifdef DEBUG_IP
	rdc_print_svinfo(nvp, "create");
#endif
	return (nvp);
}

void
rdc_destroy_svinfo(rdc_srv_t *svp)
{
	if (svp == NULL)
		return;

	if (svp->ri_addr.buf && svp->ri_addr.maxlen)
		free_rdc_netbuf(&(svp->ri_addr));

	if (svp->ri_knconf->knc_protofmly)
		kmem_free(svp->ri_knconf->knc_protofmly, KNC_STRSIZE + 1);

	if (svp->ri_knconf->knc_proto)
		kmem_free(svp->ri_knconf->knc_proto, KNC_STRSIZE + 1);

	if (svp->ri_knconf)
		kmem_free(svp->ri_knconf, sizeof (*svp->ri_knconf));

	kmem_free(svp, sizeof (*svp));
}

/*
 * rdc_netbuf_toint
 * Returns oldsytle ipv4 RDC ver 3 addresses for RPC protocol from netbuf
 * Note: This would never be called in the case of IPv6 and a program
 * mismatch ie ver 3 to ver 4
 */
int
rdc_netbuf_toint(struct netbuf *nb)
{
	int ret;
	if (nb->len > RDC_MAXADDR)
		cmn_err(CE_NOTE, "rdc_netbuf_toint: bad size %d", nb->len);

	switch (nb->len) {
		case 4:
			bcopy(nb->buf, (char *)&ret, sizeof (int));
			return (ret);

		case 8:
		case 16:
		case 32:
			bcopy(&nb->buf[4], (char *)&ret, sizeof (int));
			return (ret);

		default:
			cmn_err(CE_NOTE, " rdc_netbuf_toint: size %d", nb->len);
		}
	return (0);
}
