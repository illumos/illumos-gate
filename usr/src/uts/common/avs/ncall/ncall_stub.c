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
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/varargs.h>
#ifdef DS_DDICT
#include <sys/nsctl/contract.h>
#endif
#include "ncall.h"
#include "ncall_module.h"

static ncall_node_t nodeinfo;


/* ARGSUSED */
void
ncall_stub_register_svc(int svc_id, void (*func)(ncall_t *, int *))
{
	;
}

/* ARGSUSED */
void
ncall_stub_unregister_svc(int svc_id)
{
	;
}

/* ARGSUSED */
int
ncall_stub_nodeid(char *nodename)
{
	return (nodeinfo.nc_nodeid);
}

/* ARGSUSED */
char *
ncall_stub_nodename(int nodeid)
{
	if (nodeid == nodeinfo.nc_nodeid)
		return (nodeinfo.nc_nodename);
	else
		return ("");
}

/* ARGSUSED */
int
ncall_stub_mirror(int nodeid)
{
	return (-1);
}

/* ARGSUSED */
int
ncall_stub_self(void)
{
	return (nodeinfo.nc_nodeid);
}

/* ARGSUSED */
int
ncall_stub_alloc(int host_id, int flags, int net, ncall_t **ncall_p)
{
	return (ENOLINK);
}

/* ARGSUSED */
int
ncall_stub_timedsend(ncall_t *ncall, int flags, int svc_id,
    struct timeval *t, va_list ap)
{
	return (ENOLINK);
}

/* ARGSUSED */
int
ncall_stub_timedsendnotify(ncall_t *ncall, int flags, int svc_id,
    struct timeval *t, void (*ncall_callback)(ncall_t *, void *), void *vptr,
    va_list ap)
{
	return (ENOLINK);
}

/* ARGSUSED */
int
ncall_stub_broadcast(ncall_t *ncall, int flags, int svc_id,
    struct timeval *t, va_list ap)
{
	return (ENOLINK);
}

/* ARGSUSED */
int
ncall_stub_read_reply(ncall_t *ncall, int n, va_list ap)
{
	return (ENOLINK);
}

/* ARGSUSED */
void
ncall_stub_reset(ncall_t *ncall)
{
	;
}

/* ARGSUSED */
void
ncall_stub_free(ncall_t *ncall)
{
	;
}

/* ARGSUSED */
int
ncall_stub_put_data(ncall_t *ncall, void *data, int len)
{
	return (ENOLINK);
}

/* ARGSUSED */
int
ncall_stub_get_data(ncall_t *ncall, void *data, int len)
{
	return (ENOLINK);
}

/* ARGSUSED */
int
ncall_stub_sender(ncall_t *ncall)
{
	return (nodeinfo.nc_nodeid);
}

/* ARGSUSED */
void
ncall_stub_reply(ncall_t *ncall, va_list ap)
{
	;
}

/* ARGSUSED */
void
ncall_stub_pend(ncall_t *ncall)
{
	;
}

/* ARGSUSED */
void
ncall_stub_done(ncall_t *ncall)
{
	;
}

int
ncall_stub_ping(char *nodename, int *up)
{
	int rc = 0;

	if (strcmp(nodename, nodeinfo.nc_nodename) == 0) {
		*up = 1;
	} else {
		rc = EHOSTUNREACH;
		*up = 0;
	}

	return (rc);
}

/* ARGSUSED */
int
ncall_stub_maxnodes()
{
	return (0);
}


/* ARGSUSED */
int
ncall_stub_nextnode(void **vptr)
{
	return (0);
}

/* ARGSUSED */
int
ncall_stub_errcode(ncall_t *ncall, int *result)
{
	return (ENOLINK);
}




static int ncall_stub_stop(void);

static ncall_module_t ncall_stubinfo = {
	NCALL_MODULE_VER,
	"ncall stubs",
	ncall_stub_stop,
	ncall_stub_register_svc,
	ncall_stub_unregister_svc,
	ncall_stub_nodeid,
	ncall_stub_nodename,
	ncall_stub_mirror,
	ncall_stub_self,
	ncall_stub_alloc,
	ncall_stub_timedsend,
	ncall_stub_timedsendnotify,
	ncall_stub_broadcast,
	ncall_stub_read_reply,
	ncall_stub_reset,
	ncall_stub_free,
	ncall_stub_put_data,
	ncall_stub_get_data,
	ncall_stub_sender,
	ncall_stub_reply,
	ncall_stub_pend,
	ncall_stub_done,
	ncall_stub_ping,
	ncall_stub_maxnodes,
	ncall_stub_nextnode,
	ncall_stub_errcode
};


static int
ncall_stub_stop(void)
{
	bzero(&nodeinfo, sizeof (nodeinfo));
	return (ncall_unregister_module(&ncall_stubinfo));
}


void
ncall_init_stub(void)
{
	(void) ncall_register_module(&ncall_stubinfo, &nodeinfo);
}
