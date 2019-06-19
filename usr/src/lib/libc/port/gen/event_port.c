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

#include "lint.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/port_impl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/systm.h>
#include <libc.h>

/*
 * The second argument of _portfs(PORT_CREATE, 0,,,) represents the version
 * number of the event ports framework. The version number is required to
 * identify possible changes/extensions of the port_event_t structure. If an
 * extension is required the port_create() function will be mapped to a second
 * library create function like port_create_v1(PORT_CREATE, VERSION,,,)
 * VERSION will be a number > 0.
 * As long as such an extension is not required the second argument will be
 * set to 0 and no check will be done in the kernel interface.
 */
int
port_create()
{
	rval_t	r;
	r.r_vals = _portfs(PORT_CREATE | PORT_SYS_NOPORT, 0, 0, 0, 0, 0);
	return (r.r_val1);
}

int
port_associate(int port, int source, uintptr_t object, int events, void *user)
{
	rval_t	r;
	r.r_vals = _portfs(PORT_ASSOCIATE, port, source, object, events,
	    (uintptr_t)user);
	return (r.r_val1);
}


int
port_get(int port, port_event_t *pe, struct timespec *to)
{
	rval_t	r;
	if (to)
		r.r_vals = _portfs(PORT_GET, port, (uintptr_t)pe, to->tv_sec,
		    to->tv_nsec, (uintptr_t)to);
	else
		r.r_vals = _portfs(PORT_GET, port, (uintptr_t)pe, 0, 0, 0);
	return (r.r_val1);
}

int
port_getn(int port, port_event_t list[], uint_t max, uint_t *nget,
    struct timespec *timeout)
{
	rval_t	r;
	if (nget == NULL) {
		errno = EINVAL;
		return (-1);
	}
	r.r_vals = _portfs(PORT_GETN, port, (uintptr_t)list, max, *nget,
	    (uintptr_t)timeout);
	if (r.r_val1 == -1) {
		/* global error, errno is already set */
		return (-1);
	}
	*nget = r.r_val1;
	if (r.r_val2 == ETIME) {
		errno = ETIME;
		return (-1);
	}
	return (r.r_val2);
}

int
port_dissociate(int port, int source, uintptr_t object)
{
	rval_t	r;
	r.r_vals = _portfs(PORT_DISSOCIATE, port, source, object, 0, 0);
	return (r.r_val1);
}

int
port_send(int port, int events, void *user)
{
	rval_t	r;
	r.r_vals = _portfs(PORT_SEND, port, events, (uintptr_t)user, 0, 0);
	return (r.r_val1);
}

/*
 * _port_dispatch() will block if there are not resources available to
 * satisfy the request.
 */

int
_port_dispatch(int port, int flags, int source, int events, uintptr_t object,
    void *user)
{
	rval_t	r;
	if (flags & PORT_SHARE_EVENT)
		r.r_vals = _portfs(PORT_DISPATCH, port, source, events, object,
		    (uintptr_t)user);
	else
		r.r_vals = _portfs(PORT_DISPATCH | PORT_SYS_NOSHARE, port,
		    source, events, object, (uintptr_t)user);
	return (r.r_val1);
}

int
port_sendn(int ports[], int errors[], uint_t nent, int events, void *user)
{
	rval_t	r;
	uint_t	offset;
	uint_t	lnent;
	uint_t	nevents;
	if (nent <= PORT_MAX_LIST) {
		r.r_vals = _portfs(PORT_SENDN | PORT_SYS_NOPORT,
		    (uintptr_t)ports, (uintptr_t)errors, nent, events,
		    (uintptr_t)user);
		return (r.r_val1);
	}

	/* use chunks of max PORT_MAX_LIST elements per syscall */
	nevents = 0;
	for (offset = 0; offset < nent; ) {
		lnent = nent - offset;
		if (nent - offset > PORT_MAX_LIST)
			lnent = PORT_MAX_LIST;
		else
			lnent = nent - offset;
		r.r_vals = _portfs(PORT_SENDN | PORT_SYS_NOPORT,
		    (uintptr_t)&ports[offset], (uintptr_t)&errors[offset],
		    lnent, events, (uintptr_t)user);
		if (r.r_val2 == -1) {
			/* global error, return last no of events submitted */
			if (nevents)
				return (nevents);
			return (-1);
		}
		nevents += r.r_val1;
		offset += lnent;
	}
	/* list submitted */
	return (nevents);
}

int
port_alert(int port, int flags, int events, void *user)
{
	rval_t	r;
	r.r_vals = _portfs(PORT_ALERT, port, flags, events, (uintptr_t)user, 0);
	return (r.r_val1);
}
