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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _CIS_H
#define	_CIS_H

/*
 * This is the Card Services Card Information Structure (CIS) interpreter
 *	header file.  CIS information in this file is based on the
 *	Release 2.01 PCMCIA standard.
 */


#ifdef	__cplusplus
extern "C" {
#endif


#if defined(DEBUG)
#define	CIS_DEBUG
#endif


/*
 * The CIS interpreter has a single entry point with a bunch of function
 *	id numbers.
 */
#define	CISP_CIS_SETUP		0x01	/* setup CS address in CIS */
#define	CISP_CIS_LIST_CREATE	0x02	/* create the CIS linked list */
#define	CISP_CIS_LIST_DESTROY	0x03	/* destroy the CIS linked list */
#define	CISP_CIS_GET_LTUPLE	0x04	/* get a tuple */
#define	CISP_CIS_PARSE_TUPLE	0x05	/* parse a tuple */
#define	CISP_CIS_CONV_DEVSPEED	0x06	/* convert devspeed to nS and back */
#define	CISP_CIS_CONV_DEVSIZE	0x07	/* convert device size */

/*
 * Make the  calls to CardServices look like function calls.
 */
#define	CIS_CARD_SERVICES	(*cis_card_services)

/*
 * define the tuples that we recognize
 *
 * Layer 1 - Basic Compatability TUples
 */
#define	CISTPL_NULL		0x000	/* null tuple - ignore */
#define	CISTPL_DEVICE		0x001	/* device information */
#define	CISTPL_LONGLINK_CB	0x002	/* longlink to next tuple chain */
#define	CISTPL_CONFIG_CB	0x004	/* configuration tuple */
#define	CISTPL_CFTABLE_ENTRY_CB	0x005	/* configuration table entry */
#define	CISTPL_LONGLINK_MFC	0x006	/* multi-function tuple */
#define	CISTPL_BAR		0x007	/* Base Address Register definition */
#define	CISTPL_CHECKSUM		0x010	/* checksum control */
#define	CISTPL_LONGLINK_A	0x011	/* long-link to AM */
#define	CISTPL_LONGLINK_C	0x012	/* long-link to CM */
#define	CISTPL_LINKTARGET	0x013	/* link-target control */
#define	CISTPL_NO_LINK		0x014	/* no-link control */
#define	CISTPL_VERS_1		0x015	/* level 1 version information */
#define	CISTPL_ALTSTR		0x016	/* alternate language string */
#define	CISTPL_DEVICE_A		0x017	/* AM device information */
#define	CISTPL_JEDEC_C		0x018	/* JEDEC programming info for CM */
#define	CISTPL_JEDEC_A		0x019	/* JEDEC programming info for AM */
#define	CISTPL_CONFIG		0x01a	/* configuration */
#define	CISTPL_CFTABLE_ENTRY	0x01b	/* configuration-table-entry */
#define	CISTPL_DEVICE_OC	0x01c	/* other op conditions CM device info */
#define	CISTPL_DEVICE_OA	0x01d	/* other op conditions AM device info */
#define	CISTPL_DEVICEGEO	0x01e	/* Common Memory device geometry */
#define	CISTPL_DEVICEGEO_A	0x01f	/* Attribute Memory device geometry */
#define	CISTPL_MANFID		0x020	/* manufacturer identification */
#define	CISTPL_FUNCID		0x021	/* function identification */
#define	CISTPL_FUNCE		0x022	/* function extension */

/*
 * Layer 2 - Data Recording Format Tuples
 */
#define	CISTPL_SWIL		0x023	/* software interleave */
#define	CISTPL_VERS_2		0x040	/* level 2 version information */
#define	CISTPL_FORMAT		0x041	/* Common Memory recording format */
#define	CISTPL_GEOMETRY		0x042	/* geometry */
#define	CISTPL_BYTEORDER	0x043	/* byte order */
#define	CISTPL_DATE		0x044	/* card initialization date */
#define	CISTPL_BATTERY		0x045	/* battery replacement date */
#define	CISTPL_FORMAT_A		0x047	/* Attribute Memory recording format */

/*
 * Layer 3 - Data Organization Tuples
 */
#define	CISTPL_ORG		0x046	/* organization */

/*
 * Layer 4 - System Specific Standard Tuples
 */
#define	CISTPL_VEND_SPEC_80	0x080	/* vendor-specific 0x80 */
#define	CISTPL_VEND_SPEC_81	0x081	/* vendor-specific 0x81 */
#define	CISTPL_VEND_SPEC_82	0x082	/* vendor-specific 0x82 */
#define	CISTPL_VEND_SPEC_83	0x083	/* vendor-specific 0x83 */
#define	CISTPL_VEND_SPEC_84	0x084	/* vendor-specific 0x84 */
#define	CISTPL_VEND_SPEC_85	0x085	/* vendor-specific 0x85 */
#define	CISTPL_VEND_SPEC_86	0x086	/* vendor-specific 0x86 */
#define	CISTPL_VEND_SPEC_87	0x087	/* vendor-specific 0x87 */
#define	CISTPL_VEND_SPEC_88	0x088	/* vendor-specific 0x88 */
#define	CISTPL_VEND_SPEC_89	0x089	/* vendor-specific 0x89 */
#define	CISTPL_VEND_SPEC_8a	0x08a	/* vendor-specific 0x8a */
#define	CISTPL_VEND_SPEC_8b	0x08b	/* vendor-specific 0x8b */
#define	CISTPL_VEND_SPEC_8c	0x08c	/* vendor-specific 0x8c */
#define	CISTPL_VEND_SPEC_8d	0x08d	/* vendor-specific 0x8d */
#define	CISTPL_VEND_SPEC_8e	0x08e	/* vendor-specific 0x8e */
#define	CISTPL_VEND_SPEC_8f	0x08f	/* vendor-specific 0x8f */
#define	CISTPL_SPCL		0x090	/* special-purpose tuple */
#define	CISTPL_END		0x0ff	/* end-of-list tuple */

/*
 * Macro to check if tuple is a vendor-specific tuple.
 */
#define	CISTPL_VENDSPEC_START	CISTPL_VEND_SPEC_80
#define	CISTPL_VENDSPEC_END	CISTPL_VEND_SPEC_8f
#define	CISTPL_IS_VENDOR_SPECIFIC(td)	(((td) >= CISTPL_VENDSPEC_START) &&   \
						((td) <= CISTPL_VENDSPEC_END))

/*
 * The GetFirstTuple and GetNextTuple Card Services function calls use
 *	the DesiredTuple member of the tuple_t structure to determine
 *	while tuple type to return; since the CIS parser doesn't ever
 *	return CISTPL_END tuples, we can never ask for those tuples,
 *	so we overload this tuple code to mean that we want the
 *	first (or next) tuple in the chain.
 * XXX - If we ever do return CISTPL_END tuples, we'll have to
 *	re-think this.
 */
#define	RETURN_FIRST_TUPLE	0x0ff	/* return first/next tuple */
#define	RETURN_NEXT_TUPLE	0x0ff	/* return first/next tuple */

/*
 * types for data in CIS and pointers into PC card's CIS space
 *
 * The "size" member is used by the NEXT_CIS_ADDR macro so that
 *	we don't run past the end of the mapped CIS address space.
 */
typedef uchar_t cisdata_t;

typedef struct cisptr_t {
    acc_handle_t	handle;	/* access handle of CIS space */
    uint32_t		size;	/* size of mapped area */
    uint32_t		offset;	/* byte offset into CIS space */
	/* see flag definitions for cistpl_t structure */
    uint32_t		flags;
} cisptr_t;

/*
 * This is the maximum length that the data portion of a tuple can be.
 *	We have to use this since the brain-damaged 2.01 PCMCIA spec
 *	specifies that you can end a CIS chain by putting a CISTPL_END
 *	in the link field of the last VALID tuple.
 */
#define	CIS_MAX_TUPLE_DATA_LEN	254

/*
 * This is the maximum size of the string used to describe the name
 *	of the tuple.
 */
#define	CIS_MAX_TUPLE_NAME_LEN	40

/*
 * CIS_MAX_FUNCTIONS defines the maximum number of functions that can
 *	exist on a card.
 */
#define	CIS_MAX_FUNCTIONS	8	/* max number of functions per card */

/*
 * Macros to manipulate addresses and data in various CIS spaces
 *
 * NEXT_CIS_ADDR(cisptr_t *) increments the offset to point to the
 *	next data element in the CIS, based on what space the CIS
 *	we are reading resides in.  If the resulting address would
 *	be past the end of the mapped-in area, we return NULL,
 *	otherwise the adjusted offset value is returned. Note that
 *	this only works if the "size" member specifies the maximum
 *	mapped in window size and an "offset" member value of zero
 *	refers to the first byte of the window.
 *
 * GET_CIS_DATA(ptr) returns the data byte at the current CIS location.
 *
 * GET_CIS_ADDR(tp,ptr) returns the virtual address that was saved by a
 *	call to STORE_CIS_ADDR.
 *
 * BAD_CIS_ADDR is a flag that should be returned by callers of NEXT_CIS_ADDR
 *	if that macro returns NULL.  Note that this flag shares the same bit
 *	field definitions as the tuple handler flags defined in cis_handlers.h
 *	so check that file if you make any changes to these flags.
 * XXX - not the best distribution of flags, I'm afraid
 */
#define	NEXT_CIS_ADDR(ptr)	\
			(((ptr->flags&CISTPLF_AM_SPACE)?(ptr->offset += 2): \
				(ptr->offset++)),	\
				((ptr->offset > ptr->size)?(0):ptr->offset))
#define	GET_CIS_DATA(ptr)	csx_Get8(ptr->handle, ptr->offset)
#define	GET_CIS_ADDR(tp)	((cisdata_t *)(uintptr_t)(tp)->offset)
#define	BAD_CIS_ADDR	0x080000000 /* read past end of mapped CIS error */

/*
 * CIS_MEM_ALLOC(len) is used to allocate memory for our local linked
 *	CIS list; we use a macro so that the same code can be used in
 *	the kernel as well as in user space
 *
 * CIS_MEM_FREE(ptr) - same comment as CIS_MEM_ALLOC
 */
#if !defined(_KERNEL)
#ifdef	CISMALLOC_DEBUG
#define	CIS_MEM_ALLOC(len)		cis_malloc((uint32_t)len)
#define	CIS_MEM_FREE(ptr)		cis_free(ptr)
#else
#define	CIS_MEM_ALLOC(len)		malloc((uint32_t)len)
#define	CIS_MEM_FREE(ptr)		free(ptr)
#endif	/* CISMALLOC_DEBUG */
#else
#define	CIS_MEM_ALLOC(len)		cis_malloc((uint32_t)len)
#define	CIS_MEM_FREE(ptr)		cis_free(ptr)
#endif

typedef struct cis_u_malloc_tag_t {
	caddr_t		addr;
	uint32_t	len;
} cis_u_malloc_tag_t;

/*
 * We keep the tuples in a locally-maintained linked list.  This allows
 *	us to return the tuple information at any time to a client for
 *	those cards that make their CIS inaccessible once the card is
 *	configured.
 */
typedef struct cistpl_t {
	cisdata_t	type;	/* type of tuple */
	cisdata_t	len;	/* length of tuple data */
	cisdata_t	*data;	/* data in tuple */
	union {
		cisdata_t	*byte;	/* read pointer for GET_BYTE macros */
		uint16_t	*sword;
	}		read;
	uint32_t	flags;	/* misc flags */
	uint32_t	offset;	/* CIS address offset of start of tuple */
	struct cistpl_t	*prev;	/* back pointer */
	struct cistpl_t	*next;	/* forward pointer */
} cistpl_t;

/*
 * Flags that are used in the cistpl_t and cisptr_t linked lists
 */
#define	CISTPLF_NOERROR		0x000000000 /* no error return from handler */
#define	CISTPLF_UNKNOWN		0x000000001 /* unknown tuple */
#define	CISTPLF_REGS		0x000000002 /* tuple contains registers */
#define	CISTPLF_COPYOK		0x000000004 /* OK to copy tuple data */
#define	CISTPLF_VALID		0x000000008 /* tuple is valid */
#define	CISTPLF_GLOBAL_CIS	0x000000010 /* tuple from global CIS */
#define	CISTPLF_MF_CIS		0x000000020 /* tuple from MF CIS chain */
#define	CISTPLF_FROM_AM		0x000000040 /* tuple read from AM space */
#define	CISTPLF_FROM_CM		0x000000080 /* tuple read from CM space */
#define	CISTPLF_IGNORE_TUPLE	0x000000100 /* ignore this tuple */
#define	CISTPLF_VENDOR_SPECIFIC	0x000000200 /* vnedor-specific tuple */
#define	CISTPLF_LINK_INVALID	0x001000000 /* tuple link is invalid */
#define	CISTPLF_PARAMS_INVALID	0x002000000 /* tuple body is invalid */
#define	CISTPLF_AM_SPACE	0x010000000 /* this tuple is in AM space */
#define	CISTPLF_CM_SPACE	0x020000000 /* this tuple is in CM space */
#define	CISTPLF_LM_SPACE	0x040000000 /* this tuple is in local memory */
#define	CISTPLF_MEM_ERR		0x080000000 /* GET_BYTE macros memory error */

/*
 * Some convienience macros
 */
#define	CISTPLF_SPACE_MASK	(CISTPLF_AM_SPACE | CISTPLF_CM_SPACE |	\
							CISTPLF_LM_SPACE)
#define	CISTPLF_FROM_MASK	(CISTPLF_FROM_AM | CISTPLF_FROM_CM)

/*
 * Values used internally on calls to cis_get_ltuple.
 *
 * The GET_XXX_LTUPLEF and FIND_XXX_XXX values are mutually exclusive,
 *	i.e. cis_get_ltuple can only do one of these operations per call.
 *
 * The other flags are bit flags and they share the flags parameter.
 *
 *    CIS_GET_LTUPLE_IGNORE - return tuples with CISTPLF_IGNORE_TUPLE
 *				set in cistpl_t->flags
 */
#define	GET_FIRST_LTUPLEF	0x000000001 /* return first tuple in list */
#define	GET_LAST_LTUPLEF	0x000000002 /* return last tuple in list */
#define	FIND_LTUPLE_FWDF	0x000000003 /* find tuple, fwd search from tp */
#define	FIND_LTUPLE_BACKF	0x000000004 /* find tuple, backward from tp */
#define	FIND_NEXT_LTUPLEF	0x000000005 /* find tuple, fwd from tp+1 */
#define	FIND_PREV_LTUPLEF	0x000000006 /* find tuple, backward from tp-1 */
#define	GET_NEXT_LTUPLEF	0x000000007 /* return next tuple in list */
#define	GET_PREV_LTUPLEF	0x000000008 /* return prev tuple in list */
#define	CIS_GET_LTUPLE_OPMASK	0x00000ffff /* mask for operation values */
#define	CIS_GET_LTUPLE_IGNORE	0x000010000 /* return ignored tuples */

/*
 * macros for getting various data types out of a tuple
 * Note that due to the modem tuple using a few big-endian values,
 * we have to support both big and little endian macros
 *
 * Common Memory Specific macros - these will also work for tuples in
 *	local memory
 */
#define	GET_CM_BYTE(tp)	(((size_t)(tp)->len >= \
				((uintptr_t)(tp)->read.byte - \
					(uintptr_t)(tp)->data)) ? \
			 *(tp)->read.byte++ : ((tp)->flags |= CISTPLF_MEM_ERR))
#define	GET_CM_LEN(tp)	((size_t)(tp)->len - \
				((uintptr_t)(tp)->read.byte - \
				(uintptr_t)(tp)->data))

/* Attribute Memory Specific macros */
#define	GET_AM_BYTE(tp)	(((size_t)(tp)->len >= \
				(((uintptr_t)(tp)->read.byte - \
					(uintptr_t)(tp)->data))>>1) ? \
			 *(cisdata_t *)(tp)->read.sword++ : \
				((tp)->flags |= CISTPLF_MEM_ERR))
#define	GET_AM_LEN(tp)	((size_t)(tp)->len - (((uintptr_t)(tp)->read.byte - \
				(uintptr_t)(tp)->data) >> 1))

/* generic macros */
#define	RESET_TP(tp)	(tp)->read.byte = (tp)->data
#define	LOOK_BYTE(tp)	*(tp)->read.byte
#define	GET_BYTE_ADDR(tp) (tp)->read.byte

#define	GET_BYTE(tp)	(((tp)->flags & CISTPLF_AM_SPACE) ? \
				GET_AM_BYTE(tp) : GET_CM_BYTE(tp))
#define	GET_SHORT(tp)		cis_get_short(tp)
#define	GET_BE_SHORT(tp)	cis_get_be_short(tp)
#define	GET_INT24(tp)		cis_get_int24(tp)
#define	GET_LONG(tp)		cis_get_long(tp)
#define	GET_LEN(tp)	(((tp)->flags & CISTPLF_AM_SPACE) ? \
				GET_AM_LEN(tp) : GET_CM_LEN(tp))

/*
 * cistpl_ignore_list_t - this structure describes tuples in the global
 *				CIS list that we want to ignore if they
 *				also show up in a function-specific CIS.
 */
typedef struct cistpl_ignore_list_t {
	cisdata_t	type;
} cistpl_ignore_list_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _CIS_H */
