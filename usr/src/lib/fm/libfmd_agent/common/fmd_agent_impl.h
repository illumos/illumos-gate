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

#ifndef	_FMD_AGENT_IMPL_H
#define	_FMD_AGENT_IMPL_H

#include <inttypes.h>
#include <libnvpair.h>
#include <sys/types.h>
#include <sys/processor.h>
#include <fmd_agent.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct fmd_agent_hdl {
	int 	agent_devfd;
	int	agent_version;
	int	agent_errno;
	nvlist_t *agent_ioc_versions;
};

extern int fmd_agent_nvl_ioctl(fmd_agent_hdl_t *, int, uint32_t, nvlist_t *,
    nvlist_t **);
extern int fmd_agent_version(fmd_agent_hdl_t *, const char *, uint32_t *);
extern int fmd_agent_seterrno(fmd_agent_hdl_t *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_AGENT_IMPL_H */
