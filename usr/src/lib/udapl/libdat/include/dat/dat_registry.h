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
 * Copyright (c) 2002-2004, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DAT_REGISTRY_H_
#define	_DAT_REGISTRY_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * HEADER: dat_registry.h
 *
 * PURPOSE: DAT registration API signatures
 *
 * Description: Contains registration external reference signatures for
 * 		dat registry functions. This file is *only* included by
 *		providers, not consumers.
 *
 * 		Header file for "uDAPL: User Direct Access Programming
 *		Library, Version: 1.2"
 *
 * Mapping rules:
 * 	All global symbols are prepended with "DAT_" or "dat_"
 * 	All DAT objects have an 'api' tag which, such as 'ep' or 'lmr'
 * 	The method table is in the provider definition structure.
 *
 *
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_UDAT_H_)
#include <dat/udat_redirection.h>
#elif defined(_KDAT_H_)
#include <dat/kdat_redirection.h>
#else
#error Must include udat.h or kdat.h
#endif

/*
 * dat registration API.
 *
 * Technically the dat_ia_open is part of the registration API.  This
 * is so the registration module can map the device name to a provider
 * structure and then call the provider dat_ia_open function.
 * dat_is_close is also part of the registration API so that the
 * registration code can be aware when an ia is no longer in use.
 *
 */

extern DAT_RETURN dat_registry_add_provider(
	IN  DAT_PROVIDER*,			/* provider */
	IN  const DAT_PROVIDER_INFO*);		/* provider info */

extern DAT_RETURN dat_registry_remove_provider(
	IN  DAT_PROVIDER*, 			/* provider */
	IN  const DAT_PROVIDER_INFO*);		/* provider info */

/*
 * Provider initialization APIs.
 *
 * Providers that support being automatically loaded by the Registry must
 * implement these APIs and export them as public symbols.
 */

#define	DAT_PROVIDER_INIT_FUNC_NAME  dat_provider_init
#define	DAT_PROVIDER_FINI_FUNC_NAME  dat_provider_fini

#define	DAT_PROVIDER_INIT_FUNC_STR   "dat_provider_init"
#define	DAT_PROVIDER_FINI_FUNC_STR   "dat_provider_fini"

typedef void (*DAT_PROVIDER_INIT_FUNC)(
	IN const DAT_PROVIDER_INFO *,
	IN const char *);	/* instance data */

typedef void (*DAT_PROVIDER_FINI_FUNC)(
	IN const DAT_PROVIDER_INFO *);

#ifdef __cplusplus
}
#endif

#endif /* _DAT_REGISTRY_H_ */
