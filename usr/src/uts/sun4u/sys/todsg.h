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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _TODSG_H
#define	_TODSG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Serengeti TOD (time of day) driver
 *
 * Serengeti does not have hardware TOD chip inside chassis. SC has
 * a hardware TOD chip and maintains virtual TOD information for
 * each domain. Domain accesses virtual TOD through SRAM on chosen
 * IO board.
 */

#include <sys/time_impl.h>

/*
 * IOSRAM used by virtual TOD
 *
 * +-------------------------------+
 * |       tod_magic               |
 * +-------------------------------+
 * |       tod_version		   |
 * +-------------------------------+
 * |       tod_get_value           |
 * +-------------------------------+
 * |       tod_domain_skew         |
 * +-------------------------------+
 * |       tod_reserved            |
 * +-------------------------------+
 * |       tod_i_am_alive          |
 * +-------------------------------+
 * |       tod_timeout_period      |
 * +-------------------------------+
 *
 * For every struct member in IOSRAM except tod_domain_skew and tod_reserved,
 * there are only one writer and one reader.
 * tod_reserved (was tod_set_flag) is for backwards compatibility.
 *
 *                      reader  read interval    writer  write interval
 * ------------------------------------------------------------------------
 * tod_get_value	Solaris 1 second         SC      twice per second
 * tod_domain_skew	Solaris 1 second         Solaris when needed
 * 			SC (see following NOTE)
 * tod_i_am_alive	SC      twice per second Solaris 1 second
 * tod_timeout_period	SC      twice per second Solaris when needed
 *
 * NOTE: SC reads tod_domain_skew twice per second, notices if it
 *       changes, and always keeps the last observed value preserved
 *       in non-volatile storage.
 */
typedef struct _tod_iosram {
	uint32_t tod_magic;	/* magic number, always TODSG_MAGIC	*/
	uint32_t tod_version;	/* version number			*/
	time_t tod_get_value;	/* SC updates and Solaris reads		*/
	time_t tod_domain_skew;	/* Solaris updates and read		*/
	uint32_t tod_reserved;	/* Was tod_set_flag. No use		*/
	uint32_t tod_i_am_alive;	/* I'm alive! a.k.a. heartbeat	*/
	uint32_t tod_timeout_period;	/* time period to decide hard hang */
} tod_iosram_t;

#define	TODSG_MAGIC	0x54443100	/* 'T','D', '1', \0 */
#define	TODSG_VERSION_1	1

extern int todsg_use_sc;

#ifdef __cplusplus
}
#endif

#endif /* _TODSG_H */
