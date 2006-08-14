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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	STATES_H
#define	STATES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/dhcp.h>
#include <libinetutil.h>

#include "interface.h"

/*
 * interfaces for state transition/action functions.  these functions
 * can be found in suitably named .c files, such as inform.c, select.c,
 * renew.c, etc.
 */

#ifdef	__cplusplus
extern "C" {
#endif

void		dhcp_acknak(iu_eh_t *, int, short, iu_event_id_t, void *);
int		dhcp_adopt(void);
int		dhcp_bound(struct ifslist *, PKT_LIST *);
void		dhcp_bound_complete(struct ifslist *);
int		dhcp_drop(struct ifslist *, const char *);
void		dhcp_expire(iu_tq_t *, void *);
int		dhcp_extending(struct ifslist *);
void		dhcp_inform(struct ifslist *);
void		dhcp_init_reboot(struct ifslist *);
void		dhcp_rebind(iu_tq_t *, void *);
int		dhcp_release(struct ifslist *, const char *);
void		dhcp_renew(iu_tq_t *, void *);
void		dhcp_requesting(iu_tq_t *, void *);
void		dhcp_restart(struct ifslist *);
void		dhcp_selecting(struct ifslist *);
void		dhcp_start(iu_tq_t *, void *);
void		send_decline(struct ifslist *, char *, struct in_addr *);

#ifdef	__cplusplus
}
#endif

#endif	/* STATES_H */
