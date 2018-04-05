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
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMBSRV_NDR_H
#define	_SMBSRV_NDR_H

/*
 * Network Data Representation (NDR) is a compatible subset of DCE RPC
 * and MSRPC NDR.  NDR is used to move parameters consisting of
 * complicated trees of data constructs between an RPC client and server.
 *
 * CAE Specification (1997)
 * DCE 1.1: Remote Procedure Call
 * Document Number: C706
 * The Open Group
 * ogspecs@opengroup.org
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <string.h>

#include <smb/wintypes.h>
#include <libmlrpc/ndrtypes.ndl>
#include <libmlrpc/rpcpdu.ndl>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Normal sequence:
 *	- Application calls client-side stub w/ TOP-MOST arg structure
 *	- client stub performs NDR_M_OP_MARSHALL+NDR_DIR_IN
 *	- PDU conveyed (request, aka call, aka query)
 *	- server stub performs NDR_M_OP_UNMARSHALL+NDR_DIR_IN
 *	- server function called w/ TOP-MOST arg structure
 *	- server function returns w/ TOP-MOST arg structure modified
 *	- server stub performs NDR_M_OP_MARSHALL+NDR_DIR_OUT
 *	- PDU conveyed (reply, aka result, aka response)
 *	- client stub performs NDR_M_OP_UNMARSHALL+NDR_DIR_OUT
 *	- return to Application w/ TOP-MOST arg structure modified
 *
 * An interface is a sequence of top-most constructs.  Each top-most
 * construct corresponds to one parameter, either argument or return
 * value.
 *
 * A top-most construct is a sequence of outer constructs.  The first
 * outer construct is the referent of the argument, and the subsequent
 * outer constructs are descendents referenced by pointers from prior
 * constructs.
 *
 * An outer construct is a sequence of variable-sized info, fixed-sized
 * data, and variable-sized data.
 */

/*
 * Terminology
 *
 * The ALL UPPER CASE terms recur in the DCE/RPC documentation.
 * The mixed-case names have been introduced as a reading aid.
 *
 * Size		The size of an array in elements. Think of this
 *		as the amount to malloc().
 *
 * Length	The number of elements of an array which are significant
 *		Think of this as the amount to bcopy().
 *
 * Known	Size/length is known at build time.
 *
 * Determined	Size/length is determined at run time.
 *
 * FIXED	The Size and Length are Known.
 *		Think of this as a string constant or a DOS 8.3 file name.
 *		char array[] = "A Constant Size/Length";
 *
 * CONFORMANT	The Size is Determined. Length is the same as Size.
 *		Think of this as strdup().
 *		char *array = strdup("Something");
 *
 * VARYING	The Size is Known. The Length is determined.
 *		Think of this as a strcpy() of a variable length string
 *		into a fixed length buffer:
 *		char array[100];
 *		strcpy(array, "very short string");
 *
 * VARYING/CONFORMANT
 *		The Size is Determined. The Length is separately Determined.
 *		Think of this like:
 *		char *array = malloc(size);
 *		strcpy(array, "short string");
 *
 * STRING	Strings can be CONFORMANT, VARYING, or CONFORMANT/VARYING.
 *		A string is fundamentally an array with the last
 *		significant element some sort of NULL.
 */

#define	NDR_F_NONE		0x0000	/* no flags */
#define	NDR_F_PARAMS_MASK	0x00FF
#define	NDR_F_SIZE_IS		0x0001	/* [size_is(X)] required/given */
#define	NDR_F_LENGTH_IS		0x0002	/* not implemented */
#define	NDR_F_SWITCH_IS		0x0004	/* [switch_is(X)] req./given */
#define	NDR_F_IS_STRING		0x0008	/* [string] req./given */
#define	NDR_F_IS_POINTER	0x0010	/* TYPE * ... req./given */
#define	NDR_F_IS_REFERENCE	0x0020	/* TYPE & ... req./given */
#define	NDR_F_DIMENSION_IS	0x0040	/* TYPE [N] req./given */

#define	NDR_F_WHENCE_MASK	0x00F0
#define	NDR_F_BACKPTR		0x0010	/* ref cause by pointer */
#define	NDR_F_OUTER		0x0020	/* ref caused by outer */
#define	NDR_F_TOPMOST		0x0040	/* ref caused by topmost */

#define	NDR_F_TYPEOP_MASK	0x0F00
#define	NDR_F_ARRAY		0x0100	/* type is array of somethings */
#define	NDR_F_POINTER		0x0200	/* type is pointer to something(s) */
#define	NDR_F_STRING		0x0300	/* type is string of somethings */
#define	NDR_F_UNION		0x0400	/* type is a union */
#define	NDR_F_STRUCT		0x0500	/* type is a structure */
#define	NDR_F_OPERATION		0x0600	/* type is a structure, special */
#define	NDR_F_INTERFACE		0x0700	/* type is a union, special */
#define	NDR_F_CONFORMANT	0x1000	/* struct conforming (var-size tail) */
#define	NDR_F_VARYING		0x2000	/* not implemented */

struct ndr_heap;
struct ndr_stream;
struct ndr_reference;

typedef uint16_t ndr_wchar_t;

typedef struct ndr_typeinfo {
	unsigned char		version;	/* sanity check */
	unsigned char		alignment;	/* mask */
	unsigned short		type_flags;	/* NDR_F_... */
	int			(*ndr_func)(struct ndr_reference *);
	unsigned short		pdu_size_fixed_part;
	unsigned short		pdu_size_variable_part;
	unsigned short		c_size_fixed_part;
	unsigned short		c_size_variable_part;
} ndr_typeinfo_t;

typedef struct ndr_reference {
	struct ndr_reference	*next;		/* queue list (outer only) */
	struct ndr_reference	*enclosing;	/* e.g. struct for this memb */
	struct ndr_stream	*stream;	/* root of NDR */
	ndr_typeinfo_t		*ti;		/* type of data referenced */
	char			*name;		/* name of this member */
	unsigned long		pdu_offset;	/* referent in stub data */
	char			*datum;		/* referent in local memory */
	char			**backptr;	/* referer to set */
	unsigned short		outer_flags;	/* XXX_is() from top level */
	unsigned short		inner_flags;	/* XXX_is() in encapsulated */
	unsigned short		type_flags;	/* "requires" */
	unsigned short		packed_alignment;
	unsigned long		size_is;	/* conforming constructs */
	unsigned long		strlen_is;	/* strings */
	unsigned long		switch_is;	/* union arg selector */
	unsigned long		dimension_is;	/* fixed-len array size */
	unsigned long		pdu_end_offset;	/* offset for limit of PDU */
} ndr_ref_t;

/*
 * For all operations, the ndr_stream, which is the root of NDR processing,
 * is the primary object.  When available, the appropriate ndr_ref_t
 * is passed, NULL otherwise.  Functions that return 'int' should return
 * TRUE (!0) or FALSE (0).  When functions return FALSE, including
 * ndo_malloc() returning NULL, they should set the stream->error to an
 * appropriate indicator of what went wrong.
 *
 * Functions ndo_get_pdu(), ndo_put_pdu(), and ndo_pad_pdu() must
 * never grow the PDU data.  A request for out-of-bounds data is an error.
 * The swap_bytes flag is 1 if NDR knows that the byte-order in the PDU
 * is different from the local system.  ndo_pad_pdu() advised that the
 * affected bytes should be zero filled.
 */
typedef struct ndr_stream_ops {
	char *(*ndo_malloc)(struct ndr_stream *, unsigned, ndr_ref_t *);
	int (*ndo_free)(struct ndr_stream *, char *, ndr_ref_t *);
	int (*ndo_grow_pdu)(struct ndr_stream *, unsigned long, ndr_ref_t *);
	int (*ndo_pad_pdu)(struct ndr_stream *, unsigned long,
	    unsigned long, ndr_ref_t *);
	int (*ndo_get_pdu)(struct ndr_stream *, unsigned long,
	    unsigned long, char *, int, ndr_ref_t *);
	int (*ndo_put_pdu)(struct ndr_stream *, unsigned long,
	    unsigned long, char *, int, ndr_ref_t *);
	void (*ndo_tattle)(struct ndr_stream *, char *, ndr_ref_t *);
	void (*ndo_tattle_error)(struct ndr_stream *, ndr_ref_t *);
	int (*ndo_reset)(struct ndr_stream *);
	void (*ndo_destruct)(struct ndr_stream *);
} ndr_stream_ops_t;

#define	NDS_MALLOC(NDS, LEN, REF) \
	(*(NDS)->ndo->ndo_malloc)(NDS, LEN, REF)
#define	NDS_GROW_PDU(NDS, WANT_END_OFF, REF) \
	(*(NDS)->ndo->ndo_grow_pdu)(NDS, WANT_END_OFF, REF)
#define	NDS_PAD_PDU(NDS, PDU_OFFSET, N_BYTES, REF) \
	(*(NDS)->ndo->ndo_pad_pdu)(NDS, PDU_OFFSET, N_BYTES, REF)
#define	NDS_GET_PDU(NDS, PDU_OFFSET, N_BYTES, BUF, SWAP, REF) \
	(*(NDS)->ndo->ndo_get_pdu)(NDS, PDU_OFFSET, N_BYTES, BUF, SWAP, REF)
#define	NDS_PUT_PDU(NDS, PDU_OFFSET, N_BYTES, BUF, SWAP, REF) \
	(*(NDS)->ndo->ndo_put_pdu)(NDS, PDU_OFFSET, N_BYTES, BUF, SWAP, REF)
#define	NDS_TATTLE(NDS, WHAT, REF) \
	(*(NDS)->ndo->ndo_tattle)(NDS, WHAT, REF)
#define	NDS_TATTLE_ERROR(NDS, WHAT, REF) \
	(*(NDS)->ndo->ndo_tattle_error)(NDS, REF)
#define	NDS_RESET(NDS)		(*(NDS)->ndo->ndo_reset)(NDS)
#define	NDS_DESTRUCT(NDS)	(*(NDS)->ndo->ndo_destruct)(NDS)

typedef struct ndr_stream {
	unsigned long		pdu_size;
	unsigned long		pdu_max_size;
	unsigned long		pdu_base_offset;
	unsigned long		pdu_scan_offset;
	unsigned char		*pdu_base_addr;

	ndr_stream_ops_t	*ndo;

	unsigned char		m_op;
	unsigned char		dir;
	unsigned char		swap;		/* native/net endian swap */
	unsigned char		flags;
	short			error;
	short			error_ref;

	ndr_ref_t *outer_queue_head;
	ndr_ref_t **outer_queue_tailp;
	ndr_ref_t *outer_current;
	struct ndr_heap *heap;
} ndr_stream_t;

#define	NDR_M_OP_NONE		0x00
#define	NDR_M_OP_MARSHALL	0x01	/* data moving from datum to PDU */
#define	NDR_M_OP_UNMARSHALL	0x02	/* data moving from PDU to datum */

#define	NDR_DIR_NONE		0x00
#define	NDR_DIR_IN		0x10	/* data moving from caller to callee */
#define	NDR_DIR_OUT		0x20	/* data moving from callee to caller */

#define	NDR_MODE_CALL_SEND	(NDR_M_OP_MARSHALL + NDR_DIR_IN)
#define	NDR_MODE_CALL_RECV	(NDR_M_OP_UNMARSHALL + NDR_DIR_IN)
#define	NDR_MODE_RETURN_SEND	(NDR_M_OP_MARSHALL + NDR_DIR_OUT)
#define	NDR_MODE_RETURN_RECV	(NDR_M_OP_UNMARSHALL + NDR_DIR_OUT)
#define	NDR_MODE_BUF_ENCODE	NDR_MODE_CALL_SEND
#define	NDR_MODE_BUF_DECODE	NDR_MODE_RETURN_RECV

#define	NDR_MODE_TO_M_OP(MODE)	((MODE) & 0x0F)
#define	NDR_MODE_TO_DIR(MODE)	((MODE) & 0xF0)
#define	NDR_M_OP_AND_DIR_TO_MODE(M_OP, DIR)	((M_OP)|(DIR))

#define	NDR_MODE_MATCH(NDS, MODE) \
	(NDR_M_OP_AND_DIR_TO_MODE((NDS)->m_op, (NDS)->dir) == (MODE))

#define	NDR_IS_FIRST_FRAG(F)	((F) & NDR_PFC_FIRST_FRAG)
#define	NDR_IS_LAST_FRAG(F)	((F) & NDR_PFC_LAST_FRAG)
#define	NDR_IS_SINGLE_FRAG(F)	\
	(NDR_IS_FIRST_FRAG((F)) && NDR_IS_LAST_FRAG((F)))

#define	NDS_F_NONE		0x00
#define	NDS_F_NOTERM		0x01	/* strings are not null terminated */
#define	NDS_F_NONULL		0x02	/* strings: no null on size_is */
#define	NDS_SETF(S, F)		((S)->flags |= (F))
#define	NDS_CLEARF(S, F)	((S)->flags &= ~(F))

#define	NDR_ERR_MALLOC_FAILED		-1
#define	NDR_ERR_M_OP_INVALID		-2
#define	NDR_ERR_UNDERFLOW		-3
#define	NDR_ERR_GROW_FAILED		-4	/* overflow */
#define	NDR_ERR_PAD_FAILED		-5	/* couldn't possibly happen */
#define	NDR_ERR_OUTER_HEADER_BAD	-6
#define	NDR_ERR_SWITCH_VALUE_ILLEGAL	-7
#define	NDR_ERR_SWITCH_VALUE_INVALID	-8
#define	NDR_ERR_SWITCH_VALUE_MISSING	-9
#define	NDR_ERR_SIZE_IS_MISMATCH_PDU	-10
#define	NDR_ERR_SIZE_IS_MISMATCH_AFTER	-11
#define	NDR_ERR_SIZE_IS_UNEXPECTED	-12
#define	NDR_ERR_SIZE_IS_DUPLICATED	-13
#define	NDR_ERR_OUTER_PARAMS_MISMATCH	-14
#define	NDR_ERR_ARRAY_VARLEN_ILLEGAL	-15
#define	NDR_ERR_ARRAY_UNION_ILLEGAL	-16
#define	NDR_ERR_OUTER_PARAMS_BAD	-17
#define	NDR_ERR_OUTER_UNION_ILLEGAL	-18
#define	NDR_ERR_TOPMOST_UNION_ILLEGAL	-19
#define	NDR_ERR_TOPMOST_VARLEN_ILLEGAL	-20
#define	NDR_ERR_INNER_PARAMS_BAD	-21
#define	NDR_ERR_UNIMPLEMENTED		-22
#define	NDR_ERR_NOT_AN_INTERFACE	-23
#define	NDR_ERR_STRLEN			-24
#define	NDR_ERR_STRING_SIZING		-25
#define	NDR_ERR_BOUNDS_CHECK		-26

#define	NDR_SET_ERROR(REF, ERROR)			\
	((REF)->stream->error = (ERROR),		\
	(REF)->stream->error_ref = __LINE__,		\
	NDS_TATTLE_ERROR((REF)->stream, 0, REF))

#define	NDR_TATTLE(REF, WHAT) \
	(*(REF)->stream->ndo->ndo_tattle)((REF)->stream, WHAT, REF)

#define	MEMBER_STR(MEMBER) #MEMBER

#define	NDR_DIR_IS_IN  (encl_ref->stream->dir == NDR_DIR_IN)
#define	NDR_DIR_IS_OUT (encl_ref->stream->dir == NDR_DIR_OUT)

#define	NDR_MEMBER_WITH_ARG(TYPE, MEMBER, OFFSET, \
		ARGFLAGS, ARGMEM, ARGVAL) { \
		myref.pdu_offset = encl_ref->pdu_offset + (OFFSET);	\
		myref.name = MEMBER_STR(MEMBER);			\
		myref.datum = (char *)&val->MEMBER;			\
		myref.inner_flags = ARGFLAGS;				\
		myref.ti = &ndt_##TYPE;					\
		myref.ARGMEM = ARGVAL;					\
		if (!ndr_inner(&myref))					\
			return (0);					\
	}

#define	NDR_MEMBER(TYPE, MEMBER, OFFSET) \
	NDR_MEMBER_WITH_ARG(TYPE, MEMBER, OFFSET, \
		NDR_F_NONE, size_is, 0)

#define	NDR_MEMBER_ARR_WITH_SIZE_IS(TYPE, MEMBER, OFFSET, SIZE_IS) \
	NDR_MEMBER_WITH_ARG(TYPE, MEMBER, OFFSET, \
		NDR_F_SIZE_IS, size_is, SIZE_IS)

#define	NDR_MEMBER_ARR_WITH_DIMENSION(TYPE, MEMBER, OFFSET, SIZE_IS) \
	NDR_MEMBER_WITH_ARG(TYPE, MEMBER, OFFSET, \
		NDR_F_DIMENSION_IS, dimension_is, SIZE_IS)

#define	NDR_MEMBER_PTR_WITH_SIZE_IS(TYPE, MEMBER, OFFSET, SIZE_IS) \
	NDR_MEMBER_WITH_ARG(TYPE, MEMBER, OFFSET, \
		NDR_F_SIZE_IS+NDR_F_IS_POINTER, size_is, SIZE_IS)

#define	NDR_MEMBER_PTR(TYPE, MEMBER, OFFSET)		\
	NDR_MEMBER_WITH_ARG(TYPE, MEMBER, OFFSET,	\
		NDR_F_IS_POINTER, size_is, 0)

#define	NDR_MEMBER_WITH_SWITCH_IS(TYPE, MEMBER, OFFSET, SWITCH_IS)	\
	NDR_MEMBER_WITH_ARG(TYPE, MEMBER, OFFSET,			\
		NDR_F_SWITCH_IS, switch_is, SWITCH_IS)


#define	NDR_TOPMOST_MEMBER_WITH_ARG(TYPE, MEMBER, \
		ARGFLAGS, ARGMEM, ARGVAL) { \
		myref.pdu_offset = -1;					\
		myref.name = MEMBER_STR(MEMBER);			\
		myref.datum = (char *)&val->MEMBER;			\
		myref.inner_flags = ARGFLAGS;				\
		myref.ti = &ndt_##TYPE;					\
		myref.ARGMEM = ARGVAL;					\
		if (!ndr_topmost(&myref))				\
			return (0);					\
	}

#define	NDR_TOPMOST_MEMBER(TYPE, MEMBER)	   			\
	NDR_TOPMOST_MEMBER_WITH_ARG(TYPE, MEMBER,			\
		NDR_F_NONE, size_is, 0)

#define	NDR_TOPMOST_MEMBER_ARR_WITH_SIZE_IS(TYPE, MEMBER, SIZE_IS)	\
	NDR_TOPMOST_MEMBER_WITH_ARG(TYPE, MEMBER,		    	\
		NDR_F_SIZE_IS, size_is, SIZE_IS)

#define	NDR_TOPMOST_MEMBER_ARR_WITH_DIMENSION(TYPE, MEMBER, SIZE_IS)	\
	NDR_TOPMOST_MEMBER_WITH_ARG(TYPE, MEMBER,		      	\
		NDR_F_DIMENSION_IS, dimension_is, SIZE_IS)

#define	NDR_TOPMOST_MEMBER_PTR_WITH_SIZE_IS(TYPE, MEMBER, SIZE_IS)	\
	NDR_TOPMOST_MEMBER_WITH_ARG(TYPE, MEMBER,			\
		NDR_F_SIZE_IS+NDR_F_IS_POINTER, size_is, SIZE_IS)

#define	NDR_TOPMOST_MEMBER_PTR(TYPE, MEMBER)		\
	NDR_TOPMOST_MEMBER_WITH_ARG(TYPE, MEMBER,	\
		NDR_F_IS_POINTER, size_is, 0)

#define	NDR_TOPMOST_MEMBER_REF(TYPE, MEMBER)		\
	NDR_TOPMOST_MEMBER_WITH_ARG(TYPE, MEMBER,	\
		NDR_F_IS_REFERENCE, size_is, 0)

#define	NDR_TOPMOST_MEMBER_REF_WITH_SIZE_IS(TYPE, MEMBER, SIZE_IS)	\
	NDR_TOPMOST_MEMBER_WITH_ARG(TYPE, MEMBER,			\
		NDR_F_SIZE_IS+NDR_F_IS_REFERENCE, size_is, SIZE_IS)

#define	NDR_TOPMOST_MEMBER_WITH_SWITCH_IS(TYPE, MEMBER, SWITCH_IS)	\
	NDR_TOPMOST_MEMBER_WITH_ARG(TYPE, MEMBER,			\
		NDR_F_SWITCH_IS, switch_is, SWITCH_IS)

/* this is assuming offset+0 */
#define	NDR_PARAMS_MEMBER_WITH_ARG(TYPE, MEMBER, ARGFLAGS, \
	ARGMEM, ARGVAL) { \
		myref.pdu_offset = encl_ref->pdu_offset;		\
		myref.name = MEMBER_STR(MEMBER);			\
		myref.datum = (char *)&val->MEMBER;			\
		myref.inner_flags = ARGFLAGS;				\
		myref.ti = &ndt_##TYPE;					\
		myref.ARGMEM = ARGVAL;					\
		if (!ndr_params(&myref))				\
			return (0);					\
	}

#define	NDR_PARAMS_MEMBER(TYPE, MEMBER)			\
	NDR_PARAMS_MEMBER_WITH_ARG(TYPE, MEMBER,	\
	NDR_F_NONE, size_is, 0)

#define	NDR_STRING_DIM		1
#define	NDR_ANYSIZE_DIM		1

int ndo_process(struct ndr_stream *, ndr_typeinfo_t *, char *);
int ndo_operation(struct ndr_stream *, ndr_typeinfo_t *, int opnum, char *);
void ndo_printf(struct ndr_stream *, ndr_ref_t *, const char *, ...);
void ndo_trace(const char *);
void ndo_fmt(struct ndr_stream *, ndr_ref_t *, char *);

int ndr_params(ndr_ref_t *);
int ndr_topmost(ndr_ref_t *);
int ndr_run_outer_queue(struct ndr_stream *);
int ndr_outer(ndr_ref_t *);
int ndr_outer_fixed(ndr_ref_t *);
int ndr_outer_fixed_array(ndr_ref_t *);
int ndr_outer_conformant_array(ndr_ref_t *);
int ndr_outer_conformant_construct(ndr_ref_t *);
int ndr_size_is(ndr_ref_t *);
int ndr_outer_string(ndr_ref_t *);
int ndr_outer_peek_sizing(ndr_ref_t *, unsigned, unsigned long *);
int ndr_outer_poke_sizing(ndr_ref_t *, unsigned, unsigned long *);
int ndr_outer_align(ndr_ref_t *);
int ndr_outer_grow(ndr_ref_t *, unsigned);
int ndr_inner(ndr_ref_t *);
int ndr_inner_pointer(ndr_ref_t *);
int ndr_inner_reference(ndr_ref_t *);
int ndr_inner_array(ndr_ref_t *);

size_t ndr_mbstowcs(struct ndr_stream *, ndr_wchar_t *, const char *, size_t);

void nds_bswap(void *src, void *dst, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_NDR_H */
