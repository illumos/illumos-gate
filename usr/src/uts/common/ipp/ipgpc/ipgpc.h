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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_IPP_IPGPC_IPGPC_H
#define	_IPP_IPGPC_IPGPC_H

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/socket.h>
#include <netinet/ip6.h>
#include <net/if.h>
#include <inet/common.h>
#include <inet/ip.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Header file for IP Generic Packet Classifier (ipgpc) ipp kernel module */

/* names for single ipgpc action and module name */
#define	IPGPC_CLASSIFY		"ipgpc.classify"
#define	IPGPC_NAME		"ipgpc"

/* config names of name-value pairs and type */
#define	IPGPC_UID		"ipgpc.user" /* int32_t */
#define	IPGPC_PROJID		"ipgpc.projid" /* int32_t */
#define	IPGPC_IF_INDEX		"ipgpc.if_index" /* uint32_t */
#define	IPGPC_DIR		"ipgpc.direction" /* uint32_t */
#define	IPGPC_PROTO		"ipgpc.protocol" /* byte */
#define	IPGPC_DSFIELD		"ipgpc.dsfield"	/* byte */
#define	IPGPC_DSFIELD_MASK	"ipgpc.dsfield_mask" /* byte */
#define	IPGPC_SPORT		"ipgpc.sport" /* uint16_t */
#define	IPGPC_SPORT_MASK	"ipgpc.sport_mask" /* uint16_t */
#define	IPGPC_DPORT		"ipgpc.dport" /* uint16_t */
#define	IPGPC_DPORT_MASK	"ipgpc.dport_mask" /* uint16_t */
#define	IPGPC_SADDR		"ipgpc.saddr" /* uint32_t[4] */
#define	IPGPC_SADDR_MASK	"ipgpc.saddr_mask" /* uint32_t[4] */
#define	IPGPC_SADDR_HOSTNAME	"ipgpc.saddr_hostname" /* string */
#define	IPGPC_DADDR		"ipgpc.daddr" /* uint32_t[4] */
#define	IPGPC_DADDR_MASK	"ipgpc.daddr_mask" /* uint32_t[4] */
#define	IPGPC_DADDR_HOSTNAME	"ipgpc.daddr_hostname" /* string */
#define	IPGPC_PRECEDENCE	"ipgpc.precedence" /* uint32_t */
#define	IPGPC_PRIORITY		"ipgpc.priority" /* uint32_t */
#define	IPGPC_FILTER_TYPE	"ipgpc.filter_type" /* byte */
#define	IPGPC_FILTER_INSTANCE	"ipgpc.filter_instance"	/* int32_t */
#define	IPGPC_FILTER_PRIVATE	"ipgpc.filter_private" /* string */

/* Filter Types for IPGPC_FILTER_TYPE */
#define	IPGPC_GENERIC_FLTR	0
#define	IPGPC_V4_FLTR		1
#define	IPGPC_V6_FLTR		2

#ifdef	__cplusplus
}
#endif

#endif	/* _IPP_IPGPC_IPGPC_H */
