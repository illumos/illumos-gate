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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMBSRV_MLRPC_H
#define	_SMBSRV_MLRPC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * MSRPC Like RPC (MLRPC) is an MSRPC compatible implementation of OSF
 * DCE RPC.  DCE RPC is derived from the Apollo Network Computing
 * Architecture (NCA) RPC implementation.  This implementation is based
 * on the X/Open DCE: Remote Procedure Call specification.  The main
 * MSRPC compatibility issue is the use of Unicode strings.  This work
 * was originally based on the X/Open DCE Remote Procedure Call CAE
 * 1994 Specification.  The current DCE RPC specification is detailed
 * below.
 *
 * CAE Specification (1997)
 * DCE 1.1: Remote Procedure Call
 * Document Number: C706
 * The Open Group
 * ogspecs@opengroup.org
 */

/*
 * Layering
 *
 * This shows the software layers of the DCE RPC system compared against
 * ONC SUN RPC.
 *
 *	MLRPC Layers		Sun RPC Layers		Remark
 *	+---------------+	+---------------+	+---------------+
 *	+---------------+	+---------------+
 *	| Application	|	| Application	|	The application
 *	+---------------+	+---------------+
 *	| Hand coded    |	| RPCGEN gen'd  |	Where the real
 *	| client/server |	| client/server |	work happens
 *	| srvsvc.ndl	|	| *_svc.c *_clnt|
 *	| srvsvc.c	|	|               |
 *	+---------------+	+---------------+
 *	| RPC Library	|	| RPC Library   |	Calls/Return
 *	| mlrpc_*.c     |	|               |	Binding/PMAP
 *	+---------------+	+---------------+
 *	| RPC Protocol	|	| RPC Protocol  |	Headers, Auth,
 *	| mlrpcpdu.ndl  |	|               |
 *	+---------------+	+---------------+
 *	| IDL gen'd	|	| RPCGEN gen'd  |	Aggregate
 *	| NDR stubs	|	| XDR stubs     |	Composition
 *	| *__ndr.c      |	| *_xdr.c       |
 *	+---------------+	+---------------+
 *	| NDR Represen	|	| XDR Represen  |	Byte order, padding
 *	+---------------+	+---------------+
 *	| Packet Heaps  |	| Network Conn  |	BIG DIFF: DCERPC does
 *	| mlndo_*.c     |	| clnt_{tcp,udp}|	not talk directly to
 *	+---------------+	+---------------+	network.
 *
 * There are two major differences between the DCE RPC and ONC RPC:
 *
 * 1. MLRPC only generates or processes packets from buffers.  Other
 *    layers must take care of packet transmission and reception.
 *    The packet heaps are managed through a simple interface provided
 *    by the Network Data Representation (NDR) module, called struct
 *    mlndr_stream.  mlndo_*.c modules implement the different flavors
 *    (operations) of packet heaps.
 *
 *    ONC RPC communicates directly with the network.  You have to do
 *    something special for the RPC packet to be placed in a buffer
 *    rather than sent to the wire.
 *
 * 2. MLRPC uses application provided heaps to support operations.
 *    A heap is a single, monolithic chunk of memory that MLRPC manages
 *    as it allocates.  When the operation and its result are done, the
 *    heap is disposed of as a single item.  The mlrpc_xaction, which
 *    is the anchor of most operations, contains the necessary book-
 *    keeping for the heap.
 *
 *    ONC RPC uses malloc() liberally throughout its run-time system.
 *    To free results, ONC RPC supports an XDR_FREE operation that
 *    traverses data structures freeing memory as it goes, whether
 *    it was malloc'd or not.
 */

#include <smbsrv/ndl/rpcpdu.ndl>
#include <sys/uio.h>
#include <smbsrv/mlsvc.h>
#include <smbsrv/ndr.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Dispatch Return Code (DRC)
 *
 *	0x8000	15:01	Set to indicate a fault, clear indicates status
 *	0x7F00	08:07	Status/Fault specific
 *	0x00FF	00:08	MLRPC_PTYPE_... of PDU, 0xFF for header
 */
#define	MLRPC_DRC_MASK_FAULT			0x8000
#define	MLRPC_DRC_MASK_SPECIFIER		0xFF00
#define	MLRPC_DRC_MASK_PTYPE			0x00FF

/* Usual stuff */
#define	MLRPC_DRC_OK				0x0000

/* Fake PTYPEs for MLRPC_DRC */
#define	MLRPC_DRC_PTYPE_RPCHDR			0x00FF
#define	MLRPC_DRC_PTYPE_API			0x00AA

/* DRC Recognizers */
#define	MLRPC_DRC_IS_OK(DRC)	(((DRC)&MLRPC_DRC_MASK_SPECIFIER) == 0)
#define	MLRPC_DRC_IS_FAULT(DRC)	(((DRC)&MLRPC_DRC_MASK_FAULT) != 0)

/*
 * (Un)Marshalling category specifiers
 */
#define	MLRPC_DRC_FAULT_MODE_MISMATCH		0x8100
#define	MLRPC_DRC_RECEIVED			0x0200
#define	MLRPC_DRC_FAULT_RECEIVED_RUNT		0x8300
#define	MLRPC_DRC_FAULT_RECEIVED_MALFORMED	0x8400
#define	MLRPC_DRC_DECODED			0x0500
#define	MLRPC_DRC_FAULT_DECODE_FAILED		0x8600
#define	MLRPC_DRC_ENCODED			0x0700
#define	MLRPC_DRC_FAULT_ENCODE_FAILED		0x8800
#define	MLRPC_DRC_FAULT_ENCODE_TOO_BIG		0x8900
#define	MLRPC_DRC_SENT				0x0A00
#define	MLRPC_DRC_FAULT_SEND_FAILED		0x8B00

/*
 * Resource category specifier
 */
#define	MLRPC_DRC_FAULT_RESOURCE_1		0x9100
#define	MLRPC_DRC_FAULT_RESOURCE_2		0x9200

/*
 * Parameters. Usually #define'd with useful alias
 */
#define	MLRPC_DRC_FAULT_PARAM_0_INVALID		0xC000
#define	MLRPC_DRC_FAULT_PARAM_0_UNIMPLEMENTED	0xD000
#define	MLRPC_DRC_FAULT_PARAM_1_INVALID		0xC100
#define	MLRPC_DRC_FAULT_PARAM_1_UNIMPLEMENTED	0xD100
#define	MLRPC_DRC_FAULT_PARAM_2_INVALID		0xC200
#define	MLRPC_DRC_FAULT_PARAM_2_UNIMPLEMENTED	0xD200
#define	MLRPC_DRC_FAULT_PARAM_3_INVALID		0xC300
#define	MLRPC_DRC_FAULT_PARAM_3_UNIMPLEMENTED	0xD300

#define	MLRPC_DRC_FAULT_OUT_OF_MEMORY		0xF000

/* RPCHDR */
#define	MLRPC_DRC_FAULT_RPCHDR_PTYPE_INVALID	0xC0FF	/* PARAM_0_INVALID */
#define	MLRPC_DRC_FAULT_RPCHDR_PTYPE_UNIMPLEMENTED 0xD0FF /* PARAM_0_UNIMP */

/* Request */
#define	MLRPC_DRC_FAULT_REQUEST_PCONT_INVALID	0xC000	/* PARAM_0_INVALID */
#define	MLRPC_DRC_FAULT_REQUEST_OPNUM_INVALID	0xC100	/* PARAM_1_INVALID */

/* Bind */
#define	MLRPC_DRC_FAULT_BIND_PCONT_BUSY		0xC00B	/* PARAM_0_INVALID */
#define	MLRPC_DRC_FAULT_BIND_UNKNOWN_SERVICE	0xC10B	/* PARAM_1_INVALID */
#define	MLRPC_DRC_FAULT_BIND_NO_SLOTS		0x910B	/* RESOURCE_1 */
#define	MLRPC_DRC_BINDING_MADE			0x000B	/* OK */

/* API */
#define	MLRPC_DRC_FAULT_API_SERVICE_INVALID	0xC0AA	/* PARAM_0_INVALID */
#define	MLRPC_DRC_FAULT_API_BIND_NO_SLOTS	0x91AA	/* RESOURCE_1 */
#define	MLRPC_DRC_FAULT_API_OPNUM_INVALID	0xC1AA	/* PARAM_1_INVALID */

struct mlrpc_xaction;

typedef struct mlrpc_stub_table {
	int		(*func)(void *param, struct mlrpc_xaction *mreq);
	unsigned short	opnum;
} mlrpc_stub_table_t;

typedef struct mlrpc_service {
	char		*name;
	char		*desc;
	char		*endpoint;
	char		*sec_addr_port;
	char		*abstract_syntax_uuid;
	int		abstract_syntax_version;
	char		*transfer_syntax_uuid;
	int		transfer_syntax_version;
	unsigned	bind_instance_size;
	int		(*bind_req)();
	int		(*unbind_and_close)();
	int		(*call_stub)(struct mlrpc_xaction *mreq);
	struct ndr_typeinfo *interface_ti;
	struct mlrpc_stub_table *stub_table;
} mlrpc_service_t;

/*
 * The list of bindings is anchored at a connection.  Nothing in the
 * RPC mechanism allocates them.  Binding elements which have service==0
 * indicate free elements.  When a connection is instantiated, at least
 * one free binding entry should also be established.  Something like
 * this should suffice for most (all) situations:
 *
 *	struct connection {
 *		....
 *		struct mlrpc_binding *binding_list_head;
 *		struct mlrpc_binding binding_pool[N_BINDING_POOL];
 *		....
 *	};
 *
 *	init_connection(struct connection *conn) {
 *		....
 *		mlrpc_binding_pool_initialize(&conn->binding_list_head,
 *		    conn->binding_pool, N_BINDING_POOL);
 */
struct mlrpc_binding {
	struct mlrpc_binding 	*next;
	mlrpc_p_context_id_t	p_cont_id;
	unsigned char		which_side;
	void *			context;
	struct mlrpc_service 	*service;
	void 			*instance_specific;
};

#define	MLRPC_BIND_SIDE_CLIENT	1
#define	MLRPC_BIND_SIDE_SERVER	2

#define	MLRPC_BINDING_TO_SPECIFIC(BINDING, TYPE) \
	((TYPE *) (BINDING)->instance_specific)

/*
 * mlrpc_heap.c
 *
 * A number of heap areas are used during marshalling and unmarshalling.
 * Under some circumstances these areas can be discarded by the library
 * code, i.e. on the server side before returning to the client and on
 * completion of a client side bind.  In the case of a client side RPC
 * call, these areas must be preserved after an RPC returns to give the
 * caller time to take a copy of the data.  In this case the client must
 * call mlrpc_c_free_heap to free the memory.
 *
 * The heap management data definition looks a bit like this:
 *
 * heap -> +---------------+     +------------+
 *         | iovec[0].base | --> | data block |
 *         | iovec[0].len  |     +------------+
 *         +---------------+
 *                ::
 *                ::
 * iov  -> +---------------+     +------------+
 *         | iovec[n].base | --> | data block |
 *         | iovec[n].len  |     +------------+
 *         +---------------+     ^            ^
 *                               |            |
 *    next ----------------------+            |
 *    top  -----------------------------------+
 *
 */

/*
 * Setting MAXIOV to 384 will use ((8 * 384) + 16) = 3088 bytes
 * of the first heap block.
 */
#define	MLRPC_HEAP_MAXIOV		384
#define	MLRPC_HEAP_BLKSZ		4096

typedef struct mlrpc_heap {
	struct iovec iovec[MLRPC_HEAP_MAXIOV];
	struct iovec *iov;
	int iovcnt;
	char *top;
	char *next;
} mlrpc_heap_t;

/*
 * To support the client-side heap preserve functionality.
 */
#define	MLRPC_HRST_PRESERVED		1

typedef struct mlrpc_heapref {
	mlrpc_heap_t *heap;
	char *recv_pdu_buf;
	char *send_pdu_buf;
	unsigned int state;
} mlrpc_heapref_t;

/*
 * Alternate varying/conformant string definition
 * - for non-null-terminated strings.
 */
struct mlrpc_vcb {
	/*
	 * size_is (actually a copy of length_is) will
	 * be inserted here by the marshalling library.
	 */
	DWORD vc_first_is;
	DWORD vc_length_is;
	WORD buffer[ANY_SIZE_ARRAY];
};

typedef struct mlrpc_vcbuf {
	WORD wclen;
	WORD wcsize;
	struct mlrpc_vcb *vcb;
} mlrpc_vcbuf_t;

mlrpc_heap_t *mlrpc_heap_create(void);
void mlrpc_heap_destroy(mlrpc_heap_t *);
void *mlrpc_heap_malloc(mlrpc_heap_t *, unsigned);
void *mlrpc_heap_strsave(mlrpc_heap_t *, char *);
void mlrpc_heap_mkvcs(mlrpc_heap_t *, char *, mlrpc_vcbuf_t *);
int mlrpc_heap_used(mlrpc_heap_t *);
int mlrpc_heap_avail(mlrpc_heap_t *);

#define	MLRPC_HEAP_MALLOC(MXA, SIZE) \
	mlrpc_heap_malloc((MXA)->heap, SIZE)

#define	MLRPC_HEAP_NEW(MXA, TYPE) \
	mlrpc_heap_malloc((MXA)->heap, sizeof (TYPE))

#define	MLRPC_HEAP_NEWN(MXA, TYPE, N) \
	mlrpc_heap_malloc((MXA)->heap, sizeof (TYPE)*(N))

#define	MLRPC_HEAP_STRSAVE(MXA, STR) \
	mlrpc_heap_strsave((MXA)->heap, (STR))

struct mlrpc_xaction {
	unsigned short		ptype;		/* just handy, hi bits spcl */
	unsigned short		opnum;		/* for requests */
	struct mlndr_stream	recv_mlnds;
	mlrpcconn_hdr_t		recv_hdr;
	struct mlndr_stream	send_mlnds;
	mlrpcconn_hdr_t		send_hdr;
	struct mlrpc_binding	*binding;	/* what we're using */
	struct mlrpc_binding	*binding_list;	/* from connection */
	mlrpc_heap_t		*heap;
	struct mlsvc_rpc_context *context;
};

struct mlrpc_client {
	int (*xa_init)(struct mlrpc_client *, struct mlrpc_xaction *,
	    mlrpc_heap_t *);
	int (*xa_exchange)(struct mlrpc_client *, struct mlrpc_xaction *);
	int (*xa_read)(struct mlrpc_client *, struct mlrpc_xaction *);
	int (*xa_preserve)(struct mlrpc_client *, struct mlrpc_xaction *,
	    mlrpc_heapref_t *);
	int (*xa_destruct)(struct mlrpc_client *, struct mlrpc_xaction *);
	void (*xa_release)(struct mlrpc_client *, mlrpc_heapref_t *);

	void *context;
	struct mlrpc_binding *binding_list;
	uint32_t next_call_id;
	unsigned next_p_cont_id;
};

/* mlndo.c */
int mlnds_initialize(struct mlndr_stream *, unsigned, int, mlrpc_heap_t *);
void mlnds_destruct(struct mlndr_stream *);

/* mlrpc_client.c */
int mlrpc_c_bind(struct mlrpc_client *, char *, struct mlrpc_binding **);
int mlrpc_c_call(struct mlrpc_binding *, int, void *, mlrpc_heapref_t *);
int mlrpc_c_free_heap(struct mlrpc_binding *, mlrpc_heapref_t *);

/* mlrpc_encdec.c */
int mlrpc_encode_decode_common(struct mlrpc_xaction *, int, unsigned,
    struct ndr_typeinfo *, void *);
int mlrpc_decode_call(struct mlrpc_xaction *, void *);
int mlrpc_encode_return(struct mlrpc_xaction *, void *);
int mlrpc_encode_call(struct mlrpc_xaction *, void *);
int mlrpc_decode_return(struct mlrpc_xaction *, void *);
int mlrpc_decode_pdu_hdr(struct mlrpc_xaction *);
int mlrpc_encode_pdu_hdr(struct mlrpc_xaction *);
void mlrpc_decode_frag_hdr(struct mlndr_stream *, mlrpcconn_common_header_t *);
unsigned mlrpc_bind_ack_hdr_size(struct mlrpcconn_bind_ack_hdr *);

/* mlrpc_svc.c */
struct mlrpc_stub_table *mlrpc_find_stub_in_svc(struct mlrpc_service *, int);
struct mlrpc_service *mlrpc_find_service_by_name(const char *);
struct mlrpc_service *mlrpc_find_service_by_uuids(mlrpc_uuid_t *, int,
    mlrpc_uuid_t *, int);
int mlrpc_register_service(struct mlrpc_service *);
void mlrpc_unregister_service(struct mlrpc_service *);
void mlrpc_uuid_to_str(mlrpc_uuid_t *, char *);
int mlrpc_str_to_uuid(char *, mlrpc_uuid_t *);
void mlrpc_binding_pool_initialize(struct mlrpc_binding **,
    struct mlrpc_binding pool[], unsigned);
struct mlrpc_binding *mlrpc_find_binding(struct mlrpc_xaction *,
    mlrpc_p_context_id_t);
struct mlrpc_binding *mlrpc_new_binding(struct mlrpc_xaction *);

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_MLRPC_H */
