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
 * Copyright (c) 1996, by Sun Microsystems Inc.
 * All rights reserved.
 */

#ifndef	_SYS_DADA_DADA_TYPES_H
#define	_SYS_DADA_DADA_TYPES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The following are the types for the directly coupled disk subsystem.
 */

#include <sys/types.h>
#include <sys/param.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef  __STDC__
typedef void *ataopaque_t;
#else  /* __STDC__ */
typedef char *ataopaque_t;
#endif /* __STDC__ */


#ifdef  _KERNEL
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/devops.h>
#endif
/*
 * Each implementation will have it's own specific set
 * of types it wishes to define.
 */

/*
 * Generally useful files to include
 */

#include <sys/dada/dada_params.h>
#include <sys/dada/dada_address.h>
#include <sys/dada/dada_pkt.h>
#ifdef	_KERNEL
#include <sys/dada/conf/autoconf.h>
#include <sys/dada/conf/device.h>
#endif	/* _KERNEL */
#include <sys/dada/dada_ctl.h>
#include <sys/dada/dada_resource.h>

#ifdef  _KERNEL
#include <sys/dada/conf/autoconf.h>
#endif  /* _KERNEL */

/*
 * Sun dada type definitions
 */
#include <sys/dada/impl/types.h>
#include <sys/dada/impl/identify.h>


/*
 * For drivers which do not include these - must be last
 */
#ifdef  _KERNEL
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stat.h>
#endif  /* _KERNEL */

/*
 * Each implementation will have it's own specific set
 * of types it wishes to define.
 */

/*
 * Generally useful files to include
 */

#include <sys/dada/dada_params.h>
#include <sys/dada/dada_address.h>
#include <sys/dada/dada_pkt.h>
#ifdef  _KERNEL
#include <sys/dada/conf/device.h>
#endif  /* _KERNEL */

#include <sys/dada/dada_ctl.h>
#include <sys/dada/dada_resource.h>

#ifdef  _KERNEL
#include <sys/dada/conf/autoconf.h>
#endif  /* _KERNEL */

/*
 * XXX: To be defined as we progress along
 * #include <sys/dada/generic/commands.h>
 * #include <sys/dada/generic/status.h>
 * #include <sys/dada/generic/message.h>
 * #include <sys/dada/generic/mode.h>
 */

/*
 * For drivers which do not include these - must be last
 */
#ifdef  _KERNEL
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stat.h>
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DADA_DADA_TYPES_H */
