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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "priv_private.h"
#include "mtlib.h"
#include "libc.h"
#include <door.h>
#include <errno.h>
#include <priv.h>
#include <klpd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/klpd.h>
#include <sys/param.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <netinet/in.h>

typedef struct klpd_data {
	boolean_t	(*kd_callback)(void *, const priv_set_t *, void *);
	void		*kd_user_cookie;
	int		kd_doorfd;
} klpd_data_t;

typedef struct klpd_ctxt {
	klpd_data_t	*kc_data;
	char		*kc_path;
	int		kc_int;
	int		kc_type;
} klpd_ctxt_t;

/* ARGSUSED */
static void
klpd_door_callback(void *kd_cookie, char *argp, size_t arg_size,
    door_desc_t *dp, uint_t ndesc)
{
	klpd_data_t *p = kd_cookie;
	int res;
	klpd_ctxt_t ctx;
	klpd_head_t *klh;
	klpd_arg_t *ka;
	priv_set_t *pset;

	if (argp == DOOR_UNREF_DATA) {
		(void) p->kd_callback(p->kd_user_cookie, NULL, NULL);
		(void) door_return(NULL, 0, NULL, 0);
	}

	klh = (void *)argp;
	ka = KLH_ARG(klh);
	pset = KLH_PRIVSET(klh);

	ctx.kc_type = ka == NULL ? KLPDARG_NONE : ka->kla_type;

	switch (ctx.kc_type) {
	case KLPDARG_NONE:
		ctx.kc_path = NULL;
		ctx.kc_int = -1;
		break;
	case KLPDARG_VNODE:
		ctx.kc_path = ka->kla_str;
		ctx.kc_int = -1;
		break;
	default:
		ctx.kc_int = ka->kla_int;
		ctx.kc_path = NULL;
		break;
	}

	ctx.kc_data = p;

	if (p->kd_callback(p->kd_user_cookie, pset, &ctx))
		res = 0;
	else
		res = 1;

	(void) door_return((char *)&res, sizeof (res), NULL, 0);
}

void *
klpd_create(boolean_t (*callback)(void *, const priv_set_t *, void *),
    void *cookie)
{
	klpd_data_t *p = malloc(sizeof (klpd_data_t));

	if (p == NULL)
		return (NULL);

	p->kd_doorfd = door_create(klpd_door_callback, p,
	    DOOR_REFUSE_DESC | DOOR_UNREF);
	if (p->kd_doorfd == -1)
		goto out;

	p->kd_user_cookie = cookie;
	p->kd_callback = callback;

	return (p);

out:
	free(p);
	return (NULL);
}

int
klpd_register_id(const priv_set_t *set, void *handle, idtype_t type, id_t id)
{
	klpd_data_t *p = handle;
	priv_data_t *d;

	LOADPRIVDATA(d);

	/* We really need to have the privilege set as argument here */
	if (syscall(SYS_privsys, PRIVSYS_KLPD_REG, p->kd_doorfd, id,
	    set, d->pd_setsize, type) == -1)
		return (-1);

	/* Registration for the current process?  Then do the thing. */
	if (type == P_PID && (id == 0 || (pid_t)id == getpid())) {
		(void) setppriv(PRIV_OFF, PRIV_INHERITABLE, set);
		(void) setpflags(PRIV_XPOLICY, 1);
	}
	return (0);
}

int
klpd_register(const priv_set_t *set, void *handle)
{
	return (klpd_register_id(set, handle, P_PID, -1));
}

int
klpd_unregister_id(void *handle, idtype_t type, id_t id)
{
	klpd_data_t *p = handle;
	int err;

	err = syscall(SYS_privsys, PRIVSYS_KLPD_UNREG, p->kd_doorfd, id,
	    (void *)NULL, 0L, type);
	if (close(p->kd_doorfd) != 0)
		err = -1;
	free(p);
	return (err);
}

int
klpd_unregister(void *handle)
{
	return (klpd_unregister_id(handle, P_PID, -1));
}

const char *
klpd_getpath(void *context)
{
	klpd_ctxt_t *p = context;

	if (p->kc_type != KLPDARG_VNODE)
		errno = EINVAL;
	return (p->kc_path);
}

int
klpd_getport(void *context, int *proto)
{
	klpd_ctxt_t *p = context;

	switch (p->kc_type) {
	case KLPDARG_TCPPORT:
		*proto = IPPROTO_TCP;
		break;
	case KLPDARG_UDPPORT:
		*proto = IPPROTO_UDP;
		break;
	case KLPDARG_SCTPPORT:
		*proto = IPPROTO_SCTP;
		break;
	case KLPDARG_SDPPORT:
		*proto = PROTO_SDP;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}
	return (p->kc_int);
}

/*ARGSUSED*/
int
klpd_getucred(ucred_t **uc, void *context)
{
	return (door_ucred(uc));
}
