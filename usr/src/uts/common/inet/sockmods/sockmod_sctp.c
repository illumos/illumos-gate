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

#include <sys/sysmacros.h>
#include <sys/strsubr.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <netinet/sctp.h>
#include <fs/sockfs/sockcommon.h>
#include "socksctp.h"

struct sonode 	*socksctp_create(struct sockparams *, int, int, int,
			    int, int, int *, cred_t *);
void 		socksctp_destroy(struct sonode *);

static int 	socksctp_constructor(void *, void *, int);
static void 	socksctp_destructor(void *, void *);

static __smod_priv_t sosctp_priv = {
	socksctp_create,
	socksctp_destroy,
	NULL
};

static smod_reg_t sinfo = {
	SOCKMOD_VERSION,
	"socksctp",
	SOCK_UC_VERSION,
	SOCK_DC_VERSION,
	NULL,
	&sosctp_priv
};

kmem_cache_t *sosctp_assoccache;
static kmem_cache_t *sosctp_sockcache;

/*
 * Module linkage information for the kernel.
 */
static struct modlsockmod modlsockmod = {
	&mod_sockmodops, "SCTP socket module", &sinfo
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlsockmod,
	NULL
};

static int
socksctp_init(void)
{
	sosctp_sockcache = kmem_cache_create("sctpsock",
	    sizeof (struct sctp_sonode), 0, socksctp_constructor,
	    socksctp_destructor, NULL, NULL, NULL, 0);
	sosctp_assoccache = kmem_cache_create("sctp_assoc",
	    sizeof (struct sctp_soassoc), 0, NULL, NULL, NULL, NULL, NULL, 0);
	return (0);
}

static void
socksctp_fini(void)
{
	kmem_cache_destroy(sosctp_sockcache);
	kmem_cache_destroy(sosctp_assoccache);
}

/*ARGSUSED*/
static int
socksctp_constructor(void *buf, void *cdrarg, int kmflags)
{
	struct sctp_sonode *ss = buf;
	struct sonode *so = &ss->ss_so;

	ss->ss_type = SOSCTP_SOCKET;
	return (sonode_constructor((void *)so, cdrarg, kmflags));
}

/*ARGSUSED*/
static void
socksctp_destructor(void *buf, void *cdrarg)
{
	struct sctp_sonode *ss = buf;
	struct sonode *so = &ss->ss_so;

	sonode_destructor((void *)so, cdrarg);
}

/*
 * Creates a sctp socket data structure.
 */
/* ARGSUSED */
struct sonode *
socksctp_create(struct sockparams *sp, int family, int type, int protocol,
    int version, int sflags, int *errorp, cred_t *cr)
{
	struct sctp_sonode *ss;
	struct sonode *so;
	int kmflags = (sflags & SOCKET_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP;

	if (version == SOV_STREAM) {
		*errorp = EINVAL;
		return (NULL);
	}

	/*
	 * We only support two types of SCTP socket.  Let sotpi_create()
	 * handle all other cases, such as raw socket.
	 */
	if (!(family == AF_INET || family == AF_INET6) ||
	    !(type == SOCK_STREAM || type == SOCK_SEQPACKET)) {
		*errorp = EINVAL;
		return (NULL);
	}

	ss = kmem_cache_alloc(sosctp_sockcache, kmflags);
	if (ss == NULL) {
		*errorp = ENOMEM;
		return (NULL);
	}

	so = &ss->ss_so;

	ss->ss_maxassoc	= 0;
	ss->ss_assoccnt	= 0;
	ss->ss_assocs	= NULL;

	if (type == SOCK_STREAM) {
		sonode_init(so, sp, family, type, protocol,
		    &sosctp_sonodeops);
	} else {
		sonode_init(so, sp, family, type, protocol,
		    &sosctp_seq_sonodeops);
		ASSERT(type == SOCK_SEQPACKET);
		mutex_enter(&so->so_lock);
		(void) sosctp_aid_grow(ss, 1, kmflags);
		mutex_exit(&so->so_lock);
	}

	if (version == SOV_DEFAULT) {
		version = so_default_version;
	}
	so->so_version = (short)version;

	dprint(2, ("sosctp_create: %p domain %d type %d\n", (void *)so, family,
	    type));

	return (so);
}

/*
 * Free SCTP socket data structure.
 */
void
socksctp_destroy(struct sonode *so)
{
	struct sctp_sonode *ss;

	ASSERT((so->so_type == SOCK_STREAM || so->so_type == SOCK_SEQPACKET) &&
	    so->so_protocol == IPPROTO_SCTP);

	sosctp_fini(so, CRED());

	ss = SOTOSSO(so);
	kmem_cache_free(sosctp_sockcache, ss);
}

int
_init(void)
{
	int error = 0;

	(void) socksctp_init();

	if ((error = mod_install(&modlinkage)) != 0)
		socksctp_fini();

	return (error);
}

int
_fini(void)
{
	int error = 0;

	if ((error = mod_remove(&modlinkage)) == 0)
		socksctp_fini();

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
