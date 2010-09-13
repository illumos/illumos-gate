/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef	_NDMPD_DOOR_H
#define	_NDMPD_DOOR_H

#include <rpc/types.h>
#include <libndmp.h>
#include <atomic.h>

#define	NDMP_DOOR_SVC		"/var/run/ndmp_door_svc"
#define	NDMP_DOOR_SIZE		(8 * 1024)
#define	NDMP_DOOR_SRV_SUCCESS	0
#define	NDMP_DOOR_SRV_ERROR	-1

#define	NDMP_SESSION_DATA	1
#define	NDMP_SESSION_NODATA	0

/* DOOR REQUESTS */
/* door status message */
#define	NDMP_GET_DOOR_STATUS		0

/* set subcommand messages */
#define	NDMP_SET_DEBUG_LEVEL		1
#define	NDMP_SET_DEBUG_PATH		2
#define	NDMP_SET_DUMP_PATHNODE		3
#define	NDMP_SET_TAR_PATHNODE		4
#define	NDMP_SET_IGNOR_CTIME		5
#define	NDMP_SET_MAXSEQ			6
#define	NDMP_SET_VERSION		7
#define	NDMP_SET_DAR			8
#define	NDMP_SET_BACKUP_QTN		9
#define	NDMP_SET_RESTORE_QTN		10
#define	NDMP_SET_OVERWRITE_QTN		11

/* get subcommand messages */
#define	NDMP_GET_DEBUG_LEVEL		20
#define	NDMP_GET_DEBUG_PATH		21
#define	NDMP_GET_DUMP_PATHNODE		22
#define	NDMP_GET_TAR_PATHNODE		23
#define	NDMP_GET_IGNOR_CTIME		24
#define	NDMP_GET_MAXSEQ			25
#define	NDMP_GET_VERSION		26
#define	NDMP_GET_DAR			27
#define	NDMP_GET_BACKUP_QTN		28
#define	NDMP_GET_RESTORE_QTN		29
#define	NDMP_GET_OVERWRITE_QTN		30
#define	NDMP_GET_ALL			31
#define	NDMP_GET_DEV_CNT		32

/* ndmpstat messages */
#define	NDMP_GET_STAT			33

/* device subcommand message */
#define	NDMP_DEVICES_GET_INFO		40

/* show subcommand messages */
#define	NDMP_SHOW			60

/* terminate subcommand messages */
#define	NDMP_TERMINATE_SESSION_ID	80
#define	NDMP_TERMINATE_SESSION_ALL	81

/*
 * NDMP statistics
 */
extern ndmp_stat_t	ndstat;
#define	NS_INC(s)	(atomic_inc_32((volatile uint32_t *)&ndstat.ns_##s))
#define	NS_DEC(s)	(atomic_dec_32((volatile uint32_t *)&ndstat.ns_##s))
#define	NS_ADD(s, d)	(atomic_add_64((volatile uint64_t *)&ndstat.ns_##s, \
	(uint64_t)d))
#define	NS_UPD(s, t)	{ \
	atomic_inc_32((volatile uint32_t *)&ndstat.ns_##s); \
	atomic_dec_32((volatile uint32_t *)&ndstat.ns_##t); \
	}
#endif /* _NDMPD_DOOR_H */
