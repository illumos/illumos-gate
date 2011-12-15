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

/* Copyright © 2003-2011 Emulex. All rights reserved.  */

/*
 * Driver Version
 */

#ifndef	_OCE_VERSION_H_
#define	_OCE_VERSION_H_

#ifdef	__cplusplus
extern "C" {
#endif

#define	OCE_MAJOR_VERSION	"1"
#define	OCE_MINOR_VERSION	"2"
#define	OCE_RELEASE_NUM		"0"
#define	OCE_PROTO_LEVEL		"e"

#define	OCE_VERSION		OCE_MAJOR_VERSION "." \
				OCE_MINOR_VERSION \
				OCE_RELEASE_NUM \
				OCE_PROTO_LEVEL

#define	OCE_REVISION		" Version " OCE_VERSION

#define	OCE_MOD_NAME		"oce"

#define	OCE_DESC_STRING	\
	"Emulex OneConnect 10 GBit Ethernet Adapter Driver"

#define	OCE_IDENT_STRING	"ELX 10G Ethernet GLDv3 v" OCE_VERSION

#ifdef	__cplusplus
}
#endif

#endif	/* _OCE_VERSION_H_ */
