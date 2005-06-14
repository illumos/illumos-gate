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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#if !defined(lint) && !defined(NOID)
#ifdef SVR4
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#endif
#endif

#ifndef lint
#ifndef _release_h
#define _release_h

static char product_name[]="Product:Site/Domain/SunNet Manager" ;
#ifdef SVR4
#ifdef i386
static char release[]="Release:2.3 FCS - Solaris X86" ;
#else
static char release[]="Release:2.3 FCS - Solaris 2" ;
#endif
#else
static char release[]="Release:2.3 FCS - Solaris 1" ;
#endif
#endif /* _release_h */
#endif /* lint */
