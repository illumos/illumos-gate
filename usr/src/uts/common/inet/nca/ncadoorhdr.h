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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_INET_NCADOORHDR_H
#define	_INET_NCADOORHDR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _KERNEL
#include <stddef.h>
#endif /* _KERNEL */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define	ONE_KB				(1024)
#define	NCA_IO_MAX_SIZE			(256 * ONE_KB)
#define	NCA_IO_OFFSET			(sizeof (nca_io2_t))

#define	NCA_IO_TRUE			1
#define	NCA_IO_FALSE			0

/*
 * Defines the data structures used by NCA and Webservers.
 */

typedef enum {
	/*
	 * NCA-to-HTTP-server protocol operation values:
	 */
	http_op		= 100,	/* NCA<>HTTP normal request/response */
	error_op	= 101,	/* NCA<-HTTP server error */
	error_retry_op	= 102,	/* NCA<-HTTP server transient error */
	resource_op	= 120,	/* NCA->HTTP server release resources */
	timeout_op	= 150,	/* NCA<-HTTP server timed out */
	door_attach_op	= 160,	/* NCA->HTTP NCA supports door fattach */
	/*
	 * NCA-to-Logging-server protocol operation values:
	 */
	log_op		= 10000,	/* NCA->Logger normal request */
	log_ok_op	= 10001,	/* NCA<-Logger request ok */
	log_error_op	= 10002,	/* NCA<-Logger request error */
	log_op_fiov	= 10003		/* NCA<>Logger file i/o vector */
} nca_op_t;

typedef enum {
	NCA_HTTP_VERSION1 = 1001,	/* NCA-to-HTTP-server protocol */
	NCA_HTTP_VERSION2 = 1002,	/* NCA-to-HTTP-server protocol V2 */
	NCA_LOG_VERSION1 = 5001,	/* NCA-to-Logging-server protocol */
	NCA_LOG_VERSION2 = 5002		/* with in-kernel logging support */
	/*
	 * Note: Other version values are reserved for other client-to-server
	 * Solaris door base protocols and as these protocols may or may not
	 * be for use with NCA a new datatype (door_version_t ?) will be
	 * defined.
	 *
	 * Note: NCA_HTTP_VERSION1 has been deprecated, NCA_HTTP_VERSION2 must
	 * be used instead and is functionally a superset of (however, requires
	 * porting as some member names and symantics have changed).
	 */
} nca_version_t;

#define	HTTP_ERR	(-1)
#define	HTTP_0_0	0x00000
#define	HTTP_0_9	0x00009
#define	HTTP_1_0	0x10000
#define	HTTP_1_1	0x10001

typedef uint32_t	nca_tag_t;	/* Request id */
typedef uint32_t	nca_offset_t;	/* Offset */

/*
 * Use pack(4) to make sizeof(struct nca_direct_cd_s) the same
 * on x86 and amd64.
 */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

typedef struct nca_direct_cd_s {	/* Direct i/o connection descriptor */
	uint64_t	cid;		/* The connection id */
	nca_tag_t	tag;		/* The connect tag */
} nca_direct_cd_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

/*
 * nca_io2_t.advisory values:
 *
 *    NCA_IO_ADVISE - on cache miss upcall/return or preempted downcall
 *	advise that on susequent cache hit an advise upcall is required.
 *
 *    NCA_IO_ADVISE_REPLACE - on advisory upcall/return or unsolicited
 *	downcall (for a ctag'ed object) replace the object data with
 *	returned object data.
 *
 *    NCA_IO_ADVISE_FLUSH - on advisory upcall/return or unsolicited downcall
 *	(for a ctag'ed object) flush the object from the cache.
 *
 *    NCA_IO_ADVISE_TEMP - on advisory upcall/return use the returned object
 *	data instead of the cached object data, the cached object is unaltered.
 *
 *    NCA_IO_ADVISE_NONE - on cache miss upcall/return or preempted downcall
 *	no advise is needed and on advisory upcall/return no advise was needed.
 */
#define	NCA_IO_ADVISE		0x01
#define	NCA_IO_ADVISE_REPLACE	0x02
#define	NCA_IO_ADVISE_FLUSH	0x04
#define	NCA_IO_ADVISE_TEMP	0x08
#define	NCA_IO_ADVISE_NONE	0x00


/*
 * nca_io2_t.direct_type values:
 *
 *  For upcall or downcall/return:
 *
 *    NCA_IO_DIRECT_NONE - none, any data is delivered via the optional
 *	meta data specifiers data/data_len and/or trailer/trailer_len.
 *
 *    NCA_IO_DIRECT_FILENAME - file name, Invalid.
 *
 *    NCA_IO_DIRECT_SHMSEG - shared memory segment, Invalid.
 *
 *    NCA_IO_DIRECT_FILEDESC - file descriptor, Invalid.
 *
 *    NCA_IO_DIRECT_CTAG - cache tag(s), like NCA_IO_DIRECT_NONE any data
 *	is delivered via the meta data specifiers data/data_len, in addition
 *	the meta data specifiers direct/direct_len point to an array of ctag
 *	uint64_t value(s) of previously returned ctag'ed response(s) for URI
 *	relative pathnamed variant(s).
 *
 *    NCA_IO_DIRECT_SPLICE - splice of a connection is complete, on last
 *	transaction for a connection (i.e. when both the call and return
 *	nca_io2_t.more values are set to zero) indicates splice to the
 *	previously named preempted connection is complete.
 *
 *    NCA_IO_DIRECT_TEE - tee of a connection is complete, on last
 *	transaction for a connection (i.e. when both the call and return
 *	nca_io2_t.more values are set to zero) indicates tee to the
 *	previously named connection is complete.
 *
 *  For upcall/return or downcall:
 *
 *    NCA_IO_DIRECT_NONE - none, any data is delivered via the optional
 *	meta data specifiers data/data_len and/or trailer/trailer_len.
 *
 *    NCA_IO_DIRECT_FILENAME - file name, data is read from the named file,
 *	the meta data specifiers direct/direct_len point to a zero byte
 *	terminated string containing the path to the named file.
 *
 *    NCA_IO_DIRECT_SHMSEG - shared memory segment, not implemented.
 *
 *    NCA_IO_DIRECT_FILEDESC - file descriptor, not implemented.
 *
 *    NCA_IO_DIRECT_CTAG - cache tag, data is to be gotten from the named
 *	ctag value (a previously returned ctag'ed response).
 *
 *    NCA_IO_DIRECT_SPLICE - splice a connection, response data from the
 *	current connection is output to the named connection (previously
 *	preempted connection), the meta data specifiers direct/direct_len
 *	point to a nca_direct_cd_t (a cid/tag pair connection descriptor)
 *	used to specify the named connection. Note, no repsonse data is
 * 	delivered to the current connection.
 *
 *    NCA_IO_DIRECT_TEE - tee a connection, response data from the current
 *	connection is output to the named connection (previously preempted
 *	connection), the meta data specifiers direct/direct_len	point to a
 *	nca_direct_cd_t (a cid/tag pair connection descriptor) used to
 *	specify the named connection. Note, response data is delivered to
 *	the current connection as normal.
 */
#define	NCA_IO_DIRECT_NONE	0
#define	NCA_IO_DIRECT_FILENAME	1
#define	NCA_IO_DIRECT_SHMSEG	2
#define	NCA_IO_DIRECT_FILEDESC	3
#define	NCA_IO_DIRECT_CTAG	4
#define	NCA_IO_DIRECT_SPLICE	5
#define	NCA_IO_DIRECT_TEE	6
#define	NCA_IO_DIRECT_FILE_FD	7

/*
 * NCA_HTTP_VERSION2 nca_io definition:
 */
typedef struct nca_io2_s {

	nca_version_t	version;	/* version number */
	nca_op_t	op;		/* type of operation */
	nca_tag_t	tag;		/* connect tag */

	uint32_t	sid;		/* server instance id */
	uint64_t	ctag;		/* user cache tag */

	uint64_t	tid;		/* caller's thread id */
	uint64_t	cid;		/* connection id */

	uint8_t		more;		/* more chunks to follow */
	uint8_t		first;		/* first chunk for tag */

	uint8_t		advisory;	/* ask before using cache */
	uint8_t		nocache;	/* don't cache */

	uint8_t		preempt;	/* preempt subsequent upcall */
	uint8_t		direct_type;	/* direct specifier type */

	uint8_t		shadow;		/* flag used by kernel when copyin */
	uint8_t		pad2;		/* padd to 32 bit align */

	uint32_t	peer_len;	/* sockaddr of client */
	nca_offset_t	peer;		/* offset into meta data area */

	uint32_t	local_len;	/* sockaddr of NCA server */
	nca_offset_t	local;		/* offset into meta data area */

	uint32_t	data_len;	/* request/response data */
	nca_offset_t	data;		/* offset into meta data area */

	uint32_t	direct_len;	/* direct data specifier */
	nca_offset_t	direct;		/* offset into meta data area */

	uint32_t	trailer_len;	/* request/response trailer data */
	nca_offset_t	trailer;	/* offset into meta data area */

	/*
	 * Following this structure is optional meta data, peer and local
	 * sockaddr, (header) data, direct data, and trailer data.
	 *
	 * All nca_offset_t's above are byte offsets from the begining of
	 * this structure. A meta data length specifier of zero indicates
	 * no meta data.
	 *
	 * Request (i.e. in-bound) data is specified by the data_len/data
	 * members only.
	 *
	 * Response (i.e. out-bound) data is specified by the data_len/data,
	 * direct_type/direct_len/direct, trailer_len/trailer members and is
	 * processed in-order.
	 *
	 * Note: sockaddr meta data are IPv4 addresses, future revisions
	 * of the NCA-to-HTTP-server protocol will support IPv6.  So, the
	 * length of the sockaddr meta data must be honored as it will be
	 * increased for future IPv6 support.
	 */

} nca_io2_t;

#define	DOWNCALLINFO_MAGIC	0x19121969

typedef struct downcallinfo_s {
	uint32_t	dci_magic;
	nca_io2_t	*dci_iop;
	uio_t		*dci_uiop;
} downcallinfo_t;

typedef enum {
	NCA_UNKNOWN,
	NCA_OPTIONS,
	NCA_GET,
	NCA_HEAD,
	NCA_POST,
	NCA_PUT,
	NCA_DELETE,
	NCA_TRACE,

	NCA_RAW		/* Special case for active connections */
} nca_http_method_t;

typedef enum {
	HS_OK = 200,
	HS_CREATED = 201,
	HS_ACCEPTED = 202,
	HS_PARTIAL_CONTENT = 206,
	HS_MOVED_PERMANENT = 301,
	HS_MOVED = 302,
	HS_NOT_MODIFIED = 304,
	HS_BAD_REQUEST = 400,
	HS_AUTH_REQUIRED = 401,
	HS_FORBIDDEN = 403,
	HS_NOT_FOUND = 404,
	HS_PRECONDITION_FAILED = 412,
	HS_SERVER_ERROR = 500,
	HS_NOT_IMPLEMENTED = 501,
	HS_SERVICE_UNAVAILABLE = 503,
	HS_CONNECTION_CLOSED = 1000
} nca_http_status_code;

/* httpd (miss user space daemon) is attached to this door */
#define	MISS_DOOR_FILE	"/var/run/nca_httpd_1.door"

/* httpd downcall door server name */
#define	DOWNCALL_DOOR_FILE	"/var/run/nca_httpd_1.down_door"

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_NCADOORHDR_H */
