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
#include <sys/tihdr.h>
#include <sys/vfs.h>
#include <fs/sockfs/nl7c.h>
#include <inet/kssl/ksslapi.h>
#include <inet/sdp_itf.h>
#include <fs/sockfs/sockcommon.h>
#include "socksdp.h"

struct sonode *socksdp_create(struct sockparams *, int, int, int,
    int, int, int *, cred_t *);
static void socksdp_destroy(struct sonode *);

static __smod_priv_t sosdp_priv = {
	socksdp_create,
	socksdp_destroy,
	NULL
};

static smod_reg_t sinfo = {
	SOCKMOD_VERSION,
	"socksdp",
	SOCK_UC_VERSION,
	SOCK_DC_VERSION,
	NULL,
	&sosdp_priv
};

/*
 * Module linkage information for the kernel
 */
static struct modlsockmod modlsockmod = {
	&mod_sockmodops, "SDP socket module", &sinfo
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlsockmod,
	NULL
};

/*
 * Creates a sdp socket data structure.
 */
/* ARGSUSED */
struct sonode *
socksdp_create(struct sockparams *sp, int family, int type, int protocol,
		    int version, int sflags, int *errorp, cred_t *cr)
{
	struct sonode *so;
	int kmflags = (sflags & SOCKET_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP;

	dprint(4, ("Inside sosdp_create: domain:%d proto:%d type:%d",
	    family, protocol, type));

	*errorp = 0;
	if (is_system_labeled()) {
		*errorp = EOPNOTSUPP;
		return (NULL);
	}

	if (version == SOV_STREAM) {
		*errorp = EINVAL;
		return (NULL);
	}

	/*
	 * We only support one type of SDP socket.  Let sotpi_create()
	 * handle all other cases, such as raw socket.
	 */
	if (!(family == AF_INET || family == AF_INET6) ||
	    !(type == SOCK_STREAM)) {
		*errorp = EINVAL;
		return (NULL);
	}

	so = kmem_cache_alloc(socket_cache, kmflags);
	if (so == NULL) {
		*errorp = ENOMEM;
		return (NULL);
	}

	sonode_init(so, sp, family, type, protocol, &sosdp_sonodeops);
	so->so_pollev |= SO_POLLEV_ALWAYS;

	dprint(2, ("sosdp_create: %p domain %d type %d\n", (void *)so, family,
	    type));

	if (version == SOV_DEFAULT) {
		version = so_default_version;
	}
	so->so_version = (short)version;

	return (so);
}

static void
socksdp_destroy(struct sonode *so)
{
	ASSERT(so->so_ops == &sosdp_sonodeops);

	sosdp_fini(so, CRED());

	kmem_cache_free(socket_cache, so);
}

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
