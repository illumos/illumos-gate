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

#ifndef	_SMBSRV_SMB_INCL_H
#define	_SMBSRV_SMB_INCL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/list.h>
#include <sys/sunddi.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <sys/errno.h>
#include <sys/ioctl.h>

#include <smbsrv/alloc.h>
#include <smbsrv/ctype.h>
#include <smbsrv/string.h>

#include <smbsrv/ntstatus.h>
#include <smbsrv/nterror.h>
#include <smbsrv/doserror.h>
#include <smbsrv/cifs.h>
#include <smbsrv/ntaccess.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/smb.h>

#include <smbsrv/smbfmt.h>
#include <smbsrv/smb_kproto.h>

#define	QUEUE_INSERT_HEAD(q, e)			\
	{ 					\
	((e)->forw) = (void *)((q)->forw);	\
	((e)->back) = (void *)(q);		\
	((q)->forw->back) = (void *)(e);	\
	((q)->forw) = (void *)(e);		\
	}


#define	QUEUE_INSERT_TAIL(q, e)			\
	{					\
	((e)->back) = (void *)((q)->back);	\
	((e)->forw) = (void *)(q);		\
	((q)->back->forw) = (void *)(e);	\
	((q)->back) = (void *)(e);		\
	}

#define	QUEUE_INSERT_SORT(q, e, k, t)			\
	{ 						\
	(void *)(t) = (void *)((q)->forw);		\
	while (((t)->k) < ((e)->k)) {			\
		(void *)(t) = (void *)((t)->forw);	\
	}						\
	QUEUE_INSERT_TAIL(t, e);			\
	}

#define	QUEUE_CLIP(e)			\
	{ 				\
	(e)->forw->back = (e)->back;	\
	(e)->back->forw = (e)->forw;	\
	(e)->forw = 0;			\
	(e)->back = 0;			\
	}

/* These should be defined in system header files */

extern int	atoi(const char *);
extern int	getchar(void);

/*
 * PBSHORTCUT - remove this when we replace BYTE/WORD/DWORD to
 * uint8_t/uint16_t/uint32_t and <inet/ip.h> gets included by
 * files that invoke the following functions.
 */
extern char	*inet_ntop(int, const void *, char *, int);
extern int	inet_pton(int, char *, void *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SMBSRV_SMB_INCL_H */
