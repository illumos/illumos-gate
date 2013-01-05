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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_LIBMLRPC_H
#define	_LIBMLRPC_H

#include <sys/types.h>
#include <sys/uio.h>

#include <smb/wintypes.h>
#include <libmlrpc/ndr.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * An MSRPC compatible implementation of OSF DCE RPC.  DCE RPC is derived
 * from the Apollo Network Computing Architecture (NCA) RPC implementation.
 *
 * CAE Specification (1997)
 * DCE 1.1: Remote Procedure Call
 * Document Number: C706
 * The Open Group
 * ogspecs@opengroup.org
 *
 * This implementation is based on the DCE Remote Procedure Call spec with
 * enhancements to support Unicode strings.  The diagram below shows the
 * DCE RPC layers compared against ONC SUN RPC.
 *
 *	NDR RPC Layers		Sun RPC Layers		Remark
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
 *	| ndr_*.c       |	|               |	Binding/PMAP
 *	+---------------+	+---------------+
 *	| RPC Protocol	|	| RPC Protocol  |	Headers, Auth,
 *	| rpcpdu.ndl    |	|               |
 *	+---------------+	+---------------+
 *	| IDL gen'd	|	| RPCGEN gen'd  |	Aggregate
 *	| NDR stubs	|	| XDR stubs     |	Composition
 *	| *__ndr.c      |	| *_xdr.c       |
 *	+---------------+	+---------------+
 *	| NDR Represen	|	| XDR Represen  |	Byte order, padding
 *	+---------------+	+---------------+
 *	| Packet Heaps  |	| Network Conn  |	DCERPC does not talk
 *	| ndo_*.c       |	| clnt_{tcp,udp}|	directly to network.
 *	+---------------+	+---------------+
 *
 * There are two major differences between the DCE RPC and ONC RPC:
 *
 * 1. NDR RPC only generates or processes packets from buffers.  Other
 *    layers must take care of packet transmission and reception.
 *    The packet heaps are managed through a simple interface provided
 *    by the Network Data Representation (NDR) module called ndr_stream_t.
 *    ndo_*.c modules implement the different flavors (operations) of
 *    packet heaps.
 *
 *    ONC RPC communicates directly with the network.  You have to do
 *    something special for the RPC packet to be placed in a buffer
 *    rather than sent to the wire.
 *
 * 2. NDR RPC uses application provided heaps to support operations.
 *    A heap is a single, monolithic chunk of memory that NDR RPC manages
 *    as it allocates.  When the operation and its result are done, the
 *    heap is disposed of as a single item.  The transaction, which
 *    is the anchor of most operations, contains the necessary book-
 *    keeping for the heap.
 *
 *    ONC RPC uses malloc() liberally throughout its run-time system.
 *    To free results, ONC RPC supports an XDR_FREE operation that
 *    traverses data structures freeing memory as it goes, whether
 *    it was malloc'd or not.
 */

/*
 * Dispatch Return Code (DRC)
 *
 *	0x8000	15:01	Set to indicate a fault, clear indicates status
 *	0x7F00	08:07	Status/Fault specific
 *	0x00FF	00:08	PTYPE_... of PDU, 0xFF for header
 */
#define	NDR_DRC_OK				0x0000
#define	NDR_DRC_MASK_FAULT			0x8000
#define	NDR_DRC_MASK_SPECIFIER			0xFF00
#define	NDR_DRC_MASK_PTYPE			0x00FF

/* Fake PTYPE DRC discriminators */
#define	NDR_DRC_PTYPE_RPCHDR(DRC)		((DRC) | 0x00FF)
#define	NDR_DRC_PTYPE_API(DRC)			((DRC) | 0x00AA)

/* DRC Recognizers */
#define	NDR_DRC_IS_OK(DRC)	(((DRC) & NDR_DRC_MASK_SPECIFIER) == 0)
#define	NDR_DRC_IS_FAULT(DRC)	(((DRC) & NDR_DRC_MASK_FAULT) != 0)

/*
 * (Un)Marshalling category specifiers
 */
#define	NDR_DRC_FAULT_MODE_MISMATCH		0x8100
#define	NDR_DRC_RECEIVED			0x0200
#define	NDR_DRC_FAULT_RECEIVED_RUNT		0x8300
#define	NDR_DRC_FAULT_RECEIVED_MALFORMED	0x8400
#define	NDR_DRC_DECODED				0x0500
#define	NDR_DRC_FAULT_DECODE_FAILED		0x8600
#define	NDR_DRC_ENCODED				0x0700
#define	NDR_DRC_FAULT_ENCODE_FAILED		0x8800
#define	NDR_DRC_FAULT_ENCODE_TOO_BIG		0x8900
#define	NDR_DRC_SENT				0x0A00
#define	NDR_DRC_FAULT_SEND_FAILED		0x8B00

/*
 * Resource category specifier
 */
#define	NDR_DRC_FAULT_RESOURCE_1		0x9100
#define	NDR_DRC_FAULT_RESOURCE_2		0x9200

/*
 * Parameters. Usually #define'd with useful alias
 */
#define	NDR_DRC_FAULT_PARAM_0_INVALID		0xC000
#define	NDR_DRC_FAULT_PARAM_0_UNIMPLEMENTED	0xD000
#define	NDR_DRC_FAULT_PARAM_1_INVALID		0xC100
#define	NDR_DRC_FAULT_PARAM_1_UNIMPLEMENTED	0xD100
#define	NDR_DRC_FAULT_PARAM_2_INVALID		0xC200
#define	NDR_DRC_FAULT_PARAM_2_UNIMPLEMENTED	0xD200
#define	NDR_DRC_FAULT_PARAM_3_INVALID		0xC300
#define	NDR_DRC_FAULT_PARAM_3_UNIMPLEMENTED	0xD300

#define	NDR_DRC_FAULT_OUT_OF_MEMORY		0xF000

/* RPCHDR */
#define	NDR_DRC_FAULT_RPCHDR_MODE_MISMATCH	0x81FF
#define	NDR_DRC_FAULT_RPCHDR_RECEIVED_RUNT	0x83FF
#define	NDR_DRC_FAULT_RPCHDR_DECODE_FAILED	0x86FF
#define	NDR_DRC_FAULT_RPCHDR_PTYPE_INVALID	0xC0FF	/* PARAM_0_INVALID */
#define	NDR_DRC_FAULT_RPCHDR_PTYPE_UNIMPLEMENTED 0xD0FF	/* PARAM_0_UNIMP */

/* Request */
#define	NDR_DRC_FAULT_REQUEST_PCONT_INVALID	0xC000	/* PARAM_0_INVALID */
#define	NDR_DRC_FAULT_REQUEST_OPNUM_INVALID	0xC100	/* PARAM_1_INVALID */

/* Bind */
#define	NDR_DRC_BINDING_MADE			0x000B	/* OK */
#define	NDR_DRC_FAULT_BIND_PCONT_BUSY		0xC00B	/* PARAM_0_INVALID */
#define	NDR_DRC_FAULT_BIND_UNKNOWN_SERVICE	0xC10B	/* PARAM_1_INVALID */
#define	NDR_DRC_FAULT_BIND_NO_SLOTS		0x910B	/* RESOURCE_1 */

/* API */
#define	NDR_DRC_FAULT_API_SERVICE_INVALID	0xC0AA	/* PARAM_0_INVALID */
#define	NDR_DRC_FAULT_API_BIND_NO_SLOTS		0x91AA	/* RESOURCE_1 */
#define	NDR_DRC_FAULT_API_OPNUM_INVALID		0xC1AA	/* PARAM_1_INVALID */

struct ndr_xa;
struct ndr_client;

typedef struct ndr_stub_table {
	int		(*func)(void *, struct ndr_xa *);
	unsigned short	opnum;
} ndr_stub_table_t;

typedef struct ndr_service {
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
	int		(*call_stub)(struct ndr_xa *);
	ndr_typeinfo_t	*interface_ti;
	ndr_stub_table_t *stub_table;
} ndr_service_t;

/*
 * The list of bindings is anchored at a connection.  Nothing in the
 * RPC mechanism allocates them.  Binding elements which have service==0
 * indicate free elements.  When a connection is instantiated, at least
 * one free binding entry should also be established.  Something like
 * this should suffice for most (all) situations:
 *
 *	struct connection {
 *		....
 *		ndr_binding_t *binding_list_head;
 *		ndr_binding_t binding_pool[N_BINDING_POOL];
 *		....
 *	};
 *
 *	init_connection(struct connection *conn) {
 *		....
 *		ndr_svc_binding_pool_init(&conn->binding_list_head,
 *		    conn->binding_pool, N_BINDING_POOL);
 */
typedef struct ndr_binding {
	struct ndr_binding 	*next;
	ndr_p_context_id_t	p_cont_id;
	unsigned char		which_side;
	struct ndr_client	*clnt;
	ndr_service_t		*service;
	void 			*instance_specific;
} ndr_binding_t;

#define	NDR_BIND_SIDE_CLIENT	1
#define	NDR_BIND_SIDE_SERVER	2

#define	NDR_BINDING_TO_SPECIFIC(BINDING, TYPE) \
	((TYPE *) (BINDING)->instance_specific)

/*
 * The binding list space must be provided by the application library
 * for use by the underlying RPC library.  We need at least two binding
 * slots per connection.
 */
#define	NDR_N_BINDING_POOL	2

typedef struct ndr_pipe {
	void			*np_listener;
	const char		*np_endpoint;
	struct smb_netuserinfo	*np_user;
	int			(*np_send)(struct ndr_pipe *, void *, size_t);
	int			(*np_recv)(struct ndr_pipe *, void *, size_t);
	int			np_fid;
	uint16_t		np_max_xmit_frag;
	uint16_t		np_max_recv_frag;
	ndr_binding_t		*np_binding;
	ndr_binding_t		np_binding_pool[NDR_N_BINDING_POOL];
} ndr_pipe_t;

/*
 * Number of bytes required to align SIZE on the next dword/4-byte
 * boundary.
 */
#define	NDR_ALIGN4(SIZE)	((4 - (SIZE)) & 3);

/*
 * DCE RPC strings (CAE section 14.3.4) are represented as varying or varying
 * and conformant one-dimensional arrays. Characters can be single-byte
 * or multi-byte as long as all characters conform to a fixed element size,
 * i.e. UCS-2 is okay but UTF-8 is not a valid DCE RPC string format. The
 * string is terminated by a null character of the appropriate element size.
 *
 * MSRPC strings should always be varying/conformant and not null terminated.
 * This format uses the size_is, first_is and length_is attributes (CAE
 * section 4.2.18).
 *
 *	typedef struct string {
 *		DWORD size_is;
 *		DWORD first_is;
 *		DWORD length_is;
 *		wchar_t string[ANY_SIZE_ARRAY];
 *	} string_t;
 *
 * The size_is attribute is used to specify the number of data elements in
 * each dimension of an array.
 *
 * The first_is attribute is used to define the lower bound for significant
 * elements in each dimension of an array. For strings this is always 0.
 *
 * The length_is attribute is used to define the number of significant
 * elements in each dimension of an array. For strings this is typically
 * the same as size_is. Although it might be (size_is - 1) if the string
 * is null terminated.
 *
 *   4 bytes   4 bytes   4 bytes  2bytes 2bytes 2bytes 2bytes
 * +---------+---------+---------+------+------+------+------+
 * |size_is  |first_is |length_is| char | char | char | char |
 * +---------+---------+---------+------+------+------+------+
 *
 * Unfortunately, not all MSRPC Unicode strings are null terminated, which
 * means that the recipient has to manually null-terminate the string after
 * it has been unmarshalled.  There may be a wide-char pad following a
 * string, and it may sometimes contains zero, but it's not guaranteed.
 *
 * To deal with this, MSRPC sometimes uses an additional wrapper with two
 * more fields, as shown below.
 *	length: the array length in bytes excluding terminating null bytes
 *	maxlen: the array length in bytes including null terminator bytes
 *	LPTSTR: converted to a string_t by NDR
 *
 * typedef struct ms_string {
 *		WORD length;
 *		WORD maxlen;
 *		LPTSTR str;
 * } ms_string_t;
 */
typedef struct ndr_mstring {
	uint16_t length;
	uint16_t allosize;
	LPTSTR str;
} ndr_mstring_t;

/*
 * A number of heap areas are used during marshalling and unmarshalling.
 * Under some circumstances these areas can be discarded by the library
 * code, i.e. on the server side before returning to the client and on
 * completion of a client side bind.  In the case of a client side RPC
 * call, these areas must be preserved after an RPC returns to give the
 * caller time to take a copy of the data.  In this case the client must
 * call ndr_clnt_free_heap to free the memory.
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
#define	NDR_HEAP_MAXIOV		384
#define	NDR_HEAP_BLKSZ		8192

typedef struct ndr_heap {
	struct iovec iovec[NDR_HEAP_MAXIOV];
	struct iovec *iov;
	int iovcnt;
	char *top;
	char *next;
} ndr_heap_t;

/*
 * Alternate varying/conformant string definition
 * - for non-null-terminated strings.
 */
typedef struct ndr_vcs {
	/*
	 * size_is (actually a copy of length_is) will
	 * be inserted here by the marshalling library.
	 */
	uint32_t vc_first_is;
	uint32_t vc_length_is;
	uint16_t buffer[ANY_SIZE_ARRAY];
} ndr_vcs_t;

typedef struct ndr_vcstr {
	uint16_t wclen;
	uint16_t wcsize;
	ndr_vcs_t *vcs;
} ndr_vcstr_t;

typedef struct ndr_vcb {
	/*
	 * size_is (actually a copy of length_is) will
	 * be inserted here by the marshalling library.
	 */
	uint32_t vc_first_is;
	uint32_t vc_length_is;
	uint8_t buffer[ANY_SIZE_ARRAY];
} ndr_vcb_t;

typedef struct ndr_vcbuf {
	uint16_t len;
	uint16_t size;
	ndr_vcb_t *vcb;
} ndr_vcbuf_t;

ndr_heap_t *ndr_heap_create(void);
void ndr_heap_destroy(ndr_heap_t *);
void *ndr_heap_dupmem(ndr_heap_t *, const void *, size_t);
void *ndr_heap_malloc(ndr_heap_t *, unsigned);
void *ndr_heap_strdup(ndr_heap_t *, const char *);
int ndr_heap_mstring(ndr_heap_t *, const char *, ndr_mstring_t *);
void ndr_heap_mkvcs(ndr_heap_t *, char *, ndr_vcstr_t *);
void ndr_heap_mkvcb(ndr_heap_t *, uint8_t *, uint32_t, ndr_vcbuf_t *);
int ndr_heap_used(ndr_heap_t *);
int ndr_heap_avail(ndr_heap_t *);

#define	NDR_MALLOC(XA, SZ)	ndr_heap_malloc((XA)->heap, SZ)
#define	NDR_NEW(XA, T)		ndr_heap_malloc((XA)->heap, sizeof (T))
#define	NDR_NEWN(XA, T, N)	ndr_heap_malloc((XA)->heap, sizeof (T)*(N))
#define	NDR_STRDUP(XA, S)	ndr_heap_strdup((XA)->heap, (S))
#define	NDR_MSTRING(XA, S, OUT)	ndr_heap_mstring((XA)->heap, (S), (OUT))
#define	NDR_SIDDUP(XA, S)	ndr_heap_dupmem((XA)->heap, (S), smb_sid_len(S))

typedef struct ndr_xa {
	unsigned short		ptype;		/* high bits special */
	unsigned short		opnum;
	ndr_stream_t		recv_nds;
	ndr_hdr_t		recv_hdr;
	ndr_stream_t		send_nds;
	ndr_hdr_t		send_hdr;
	ndr_binding_t		*binding;	/* what we're using */
	ndr_binding_t		*binding_list;	/* from connection */
	ndr_heap_t		*heap;
	ndr_pipe_t		*pipe;
} ndr_xa_t;

/*
 * 20-byte opaque id used by various RPC services.
 */
CONTEXT_HANDLE(ndr_hdid) ndr_hdid_t;

typedef struct ndr_client {
	/* transport stuff (xa_* members) */
	int (*xa_init)(struct ndr_client *, ndr_xa_t *);
	int (*xa_exchange)(struct ndr_client *, ndr_xa_t *);
	int (*xa_read)(struct ndr_client *, ndr_xa_t *);
	void (*xa_preserve)(struct ndr_client *, ndr_xa_t *);
	void (*xa_destruct)(struct ndr_client *, ndr_xa_t *);
	void (*xa_release)(struct ndr_client *);
	void			*xa_private;
	int			xa_fd;

	ndr_hdid_t		*handle;
	ndr_binding_t		*binding;
	ndr_binding_t		*binding_list;
	ndr_binding_t		binding_pool[NDR_N_BINDING_POOL];

	boolean_t		nonull;
	boolean_t		heap_preserved;
	ndr_heap_t		*heap;
	ndr_stream_t		*recv_nds;
	ndr_stream_t		*send_nds;

	uint32_t		next_call_id;
	unsigned		next_p_cont_id;
} ndr_client_t;

typedef struct ndr_handle {
	ndr_hdid_t		nh_id;
	struct ndr_handle	*nh_next;
	ndr_pipe_t		*nh_pipe;
	const ndr_service_t	*nh_svc;
	ndr_client_t		*nh_clnt;
	void			*nh_data;
	void			(*nh_data_free)(void *);
} ndr_handle_t;

#define	NDR_PDU_SIZE_HINT_DEFAULT	(16*1024)
#define	NDR_BUF_MAGIC			0x4E425546	/* NBUF */

typedef struct ndr_buf {
	uint32_t		nb_magic;
	ndr_stream_t		nb_nds;
	ndr_heap_t		*nb_heap;
	ndr_typeinfo_t		*nb_ti;
} ndr_buf_t;

/* ndr_ops.c */
int nds_initialize(ndr_stream_t *, unsigned, int, ndr_heap_t *);
void nds_destruct(ndr_stream_t *);
void nds_show_state(ndr_stream_t *);

/* ndr_client.c */
int ndr_clnt_bind(ndr_client_t *, ndr_service_t *, ndr_binding_t **);
int ndr_clnt_call(ndr_binding_t *, int, void *);
void ndr_clnt_free_heap(ndr_client_t *);

/* ndr_marshal.c */
ndr_buf_t *ndr_buf_init(ndr_typeinfo_t *);
void ndr_buf_fini(ndr_buf_t *);
int ndr_buf_decode(ndr_buf_t *, unsigned, unsigned, const char *data, size_t,
    void *);
int ndr_decode_call(ndr_xa_t *, void *);
int ndr_encode_return(ndr_xa_t *, void *);
int ndr_encode_call(ndr_xa_t *, void *);
int ndr_decode_return(ndr_xa_t *, void *);
int ndr_decode_pdu_hdr(ndr_xa_t *);
int ndr_encode_pdu_hdr(ndr_xa_t *);
void ndr_decode_frag_hdr(ndr_stream_t *, ndr_common_header_t *);
void ndr_remove_frag_hdr(ndr_stream_t *);
void ndr_show_hdr(ndr_common_header_t *);
unsigned ndr_bind_ack_hdr_size(ndr_xa_t *);
unsigned ndr_alter_context_rsp_hdr_size(void);

/* ndr_server.c */
void ndr_pipe_worker(ndr_pipe_t *);

int ndr_generic_call_stub(ndr_xa_t *);

/* ndr_svc.c */
ndr_stub_table_t *ndr_svc_find_stub(ndr_service_t *, int);
ndr_service_t *ndr_svc_lookup_name(const char *);
ndr_service_t *ndr_svc_lookup_uuid(ndr_uuid_t *, int, ndr_uuid_t *, int);
int ndr_svc_register(ndr_service_t *);
void ndr_svc_unregister(ndr_service_t *);
void ndr_svc_binding_pool_init(ndr_binding_t **, ndr_binding_t pool[], int);
ndr_binding_t *ndr_svc_find_binding(ndr_xa_t *, ndr_p_context_id_t);
ndr_binding_t *ndr_svc_new_binding(ndr_xa_t *);

int ndr_uuid_parse(char *, ndr_uuid_t *);
void ndr_uuid_unparse(ndr_uuid_t *, char *);

ndr_hdid_t *ndr_hdalloc(const ndr_xa_t *, const void *);
void ndr_hdfree(const ndr_xa_t *, const ndr_hdid_t *);
ndr_handle_t *ndr_hdlookup(const ndr_xa_t *, const ndr_hdid_t *);
void ndr_hdclose(ndr_pipe_t *);

ssize_t ndr_uiomove(caddr_t, size_t, enum uio_rw, struct uio *);

/*
 * An ndr_client_t is created while binding a client connection to hold
 * the context for calls made using that connection.
 *
 * Handles are RPC call specific and we use an inheritance mechanism to
 * ensure that each handle has a pointer to the client_t.  When the top
 * level (bind) handle is released, we close the connection.
 *
 * There are some places in libmlsvc where the code assumes that the
 * handle member is first in this struct.  careful
 */
typedef struct mlrpc_handle {
	ndr_hdid_t	handle;		/* keep first */
	ndr_client_t	*clnt;
} mlrpc_handle_t;

int mlrpc_clh_create(mlrpc_handle_t *, void *);
uint32_t mlrpc_clh_bind(mlrpc_handle_t *, ndr_service_t *);
void mlrpc_clh_unbind(mlrpc_handle_t *);
void *mlrpc_clh_free(mlrpc_handle_t *);

int ndr_rpc_call(mlrpc_handle_t *, int, void *);
int ndr_rpc_get_ssnkey(mlrpc_handle_t *, unsigned char *, size_t);
void *ndr_rpc_malloc(mlrpc_handle_t *, size_t);
ndr_heap_t *ndr_rpc_get_heap(mlrpc_handle_t *);
void ndr_rpc_release(mlrpc_handle_t *);
void ndr_rpc_set_nonull(mlrpc_handle_t *);

boolean_t ndr_is_null_handle(mlrpc_handle_t *);
boolean_t ndr_is_bind_handle(mlrpc_handle_t *);
void ndr_inherit_handle(mlrpc_handle_t *, mlrpc_handle_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBMLRPC_H */
