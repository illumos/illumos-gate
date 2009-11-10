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

#ifndef	_LIBFRU_H
#define	_LIBFRU_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	LIBFRU_VERSION 1

/* fru errno return types */
typedef enum
{
	FRU_SUCCESS = 0,
	FRU_NODENOTFOUND,
	FRU_IOERROR,
	FRU_NOREGDEF,
	FRU_NOTCONTAINER,
	FRU_INVALHANDLE,
	FRU_INVALSEG,
	FRU_INVALPATH,
	FRU_INVALELEMENT,
	FRU_INVALDATASIZE,
	FRU_DUPSEG,
	FRU_NOTFIELD,
	FRU_NOSPACE,
	FRU_DATANOTFOUND,
	FRU_ITERFULL,
	FRU_INVALPERM,
	FRU_NOTSUP,
	FRU_ELEMNOTTAGGED,
	FRU_CONTFAILED,
	FRU_SEGCORRUPT,
	FRU_DATACORRUPT,
	FRU_FAILURE,
	FRU_WALK_TERMINATE,
	FRU_NORESPONSE

} fru_errno_t;

/*
 * Structures for libfru.c
 */

/* Fru Display Types */
typedef enum { FDISP_Binary = 0, FDISP_Octal, FDISP_Hex, FDISP_Decimal,
	FDISP_String, FDISP_Time, FDISP_MSGID, FDISP_UUID, FDISP_UNDEFINED
} fru_displaytype_t;

/* Fru Data Types */
typedef enum { FDTYPE_Binary = 0, FDTYPE_ByteArray, FDTYPE_ASCII,
		FDTYPE_Unicode, FDTYPE_Record, FDTYPE_Enumeration,
		FDTYPE_UNDEFINED
} fru_datatype_t;

/* Fru Which Type */
typedef enum { FRU_No = 0, FRU_Yes, FRU_WHICH_UNDEFINED } fru_which_t;

/* Fru Iteration Types */
typedef enum { FRU_FIFO = 0, FRU_Circular,
		FRU_Linear, FRU_LIFO, FRU_NOT_ITERATED } fru_itertype_t;

/* Fru Handle Type */
typedef uint64_t fru_nodehdl_t;

/* Node Types */
typedef enum
{
	FRU_NODE_UNKNOWN,
	FRU_NODE_LOCATION,
	FRU_NODE_FRU,
	FRU_NODE_CONTAINER
} fru_node_t;

/* Sting list */
typedef struct {
	unsigned int num;
	char **strs;
} fru_strlist_t;

#if defined(_LITTLE_ENDIAN)
typedef union
{
	uint32_t raw_data;
	struct
	{
		unsigned repair_perm : 3;
		unsigned engineering_perm : 3;
		unsigned operations_perm : 3;
		unsigned domain_perm : 3;
		unsigned field_perm : 3;
		unsigned unused : 13;
		unsigned fixed : 1;
		unsigned opaque : 1;
		unsigned ignore_checksum : 1;
		unsigned encrypted : 1;

	} field;
} fru_segdesc_t;
#else
typedef union
{
	uint32_t raw_data;
	struct
	{
		unsigned encrypted : 1;
		unsigned ignore_checksum : 1;
		unsigned opaque : 1;
		unsigned fixed : 1;
		unsigned unused : 13;
		unsigned field_perm : 3;
		unsigned domain_perm : 3;
		unsigned operations_perm : 3;
		unsigned engineering_perm : 3;
		unsigned repair_perm : 3;
	} field;
} fru_segdesc_t;
#endif

#define	FRU_SEGDESC_PERM_DELETE_MASK (1<<0)
#define	FRU_SEGDESC_PERM_WRITE_MASK (1<<1)
#define	FRU_SEGDESC_PERM_READ_MASK (1<<2)
#define	FRU_SEGDESC_PERM_RW_MASK ((1<<2) | (1<<1))
#define	FRU_SEGDESC_PERM_RD_MASK ((1<<2) | (1<<0))
#define	FRU_SEGDESC_PERM_WD_MASK ((1<<1) | (1<<0))
#define	FRU_SEGDESC_PERM_RWD_MASK ((1<<0) | (1<<1) | (1<<2))

#define	FRU_SEGDESC_ALL_RO_MASK 0x000036db

#define	FRU_SEGDESC_FIXED_MASK (1<<28)
#define	FRU_SEGDESC_OPAQUE_MASK (1<<29)
#define	FRU_SEGDESC_IGNORECHECKSUM_MASK (1<<30)
#define	FRU_SEGDESC_ENCRYPTED_MASK (1<<31)

/* segment descriptor field perm. */
#define	SEGMENT_READ	4
#define	SEGMENT_WRITE	2
#define	SEGMENT_DELETE	1

#if defined(_LITTLE_ENDIAN)
typedef union
{
	uint32_t all_bits;
	struct
	{
		unsigned : 8;
		unsigned : 8;
		unsigned : 8;
		unsigned : 7;
		uint32_t read_only : 1;

	} field;
} fru_seg_hwdesc_t;
#else
typedef union
{
	uint32_t all_bits;
	struct
	{
		uint32_t read_only : 1;
		unsigned : 7;
		unsigned : 8;
		unsigned : 8;
		unsigned : 8;
	} field;
} fru_seg_hwdesc_t;
#endif

#define	FRU_SEGNAMELEN 2
typedef struct {
	uint32_t version;
	char name[FRU_SEGNAMELEN + 1]; /* +1 to include '\0' byte. */
	fru_segdesc_t desc;
	uint32_t size;
	uint32_t address; /* used for fixed segments (0 otherwise) */
	fru_seg_hwdesc_t hw_desc;
} fru_segdef_t;

/* Fru enumerations */
typedef struct {
	uint64_t value;
	char *text;
} fru_enum_t;

/* Element/Field level operations */
#define	FRU_ELEMDEF_REV 1
typedef struct {
	uint32_t version;
	fru_datatype_t data_type;
	fru_which_t tagged;
	size_t data_length; /* in Bytes or Bits depending on data_type */
	fru_displaytype_t disp_type;
	fru_which_t purgeable;
	fru_which_t relocatable;
	unsigned int enum_count; /* number of enum values in table */
	fru_enum_t *enum_table; /* enum strings or sub-elements depending on */
					/* the data_type */
	unsigned int iteration_count;
	fru_itertype_t iteration_type;
	char *example_string;
} fru_elemdef_t;

/* Data Source operations */
fru_errno_t fru_open_data_source(const char *name, ...);
fru_errno_t fru_close_data_source(void);

/* Tree operations */
fru_errno_t fru_get_root(fru_nodehdl_t *handle);
fru_errno_t fru_get_child(fru_nodehdl_t handle, fru_nodehdl_t *child);
fru_errno_t fru_get_peer(fru_nodehdl_t handle, fru_nodehdl_t *peer);
fru_errno_t fru_get_parent(fru_nodehdl_t handle, fru_nodehdl_t *parent);

/* Node information functions */
fru_errno_t fru_get_name_from_hdl(fru_nodehdl_t handle, char **name);
fru_errno_t fru_get_node_type(fru_nodehdl_t handle, fru_node_t *type);

/* Segment Operations */
fru_errno_t fru_list_segments(fru_nodehdl_t container, fru_strlist_t *list);
fru_errno_t fru_create_segment(fru_nodehdl_t container, fru_segdef_t *def);
fru_errno_t fru_remove_segment(fru_nodehdl_t container, const char *seg_name);
fru_errno_t fru_get_segment_def(fru_nodehdl_t container, const char *seg_name,
				fru_segdef_t *definition);
fru_errno_t fru_list_elems_in(fru_nodehdl_t container, const char *seg_name,
				fru_strlist_t *list);

/* Data operations */
fru_errno_t fru_read_field(fru_nodehdl_t container,
			char **seg_name, /* IN/OUT */
			unsigned int   instance,
			const char *field_path,
			void **data,
			size_t *data_len,
			char **found_path);
fru_errno_t fru_update_field(fru_nodehdl_t container,
				char *seg_name,
				unsigned int instance,
				const char *field_path,
				void *data,
				size_t length);
fru_errno_t fru_get_num_iterations(fru_nodehdl_t container,
					char **seg_name, /* IN/OUT */
					unsigned int instance,
					const char *iter_path,
					int *num_there,
					char **found_path);

/* Tagged Element operations */
fru_errno_t fru_add_element(fru_nodehdl_t container, const char *seg_name,
				const char *element);
fru_errno_t fru_delete_element(fru_nodehdl_t container, const char *seg_name,
				unsigned int instance, const char *element);

/* General library support */
fru_errno_t fru_get_definition(const char *element_name,
				fru_elemdef_t *definition);
fru_errno_t fru_get_registry(fru_strlist_t *list);
fru_errno_t fru_get_tagged_parents(const char *elem_name,
				fru_strlist_t *parents);

/* Structure destroy functions */
fru_errno_t fru_destroy_strlist(fru_strlist_t *list);
fru_errno_t fru_destroy_elemdef(fru_elemdef_t *def);

/* Enum to String Conversions */
const char *fru_strerror(fru_errno_t errnum);
const char *get_displaytype_str(fru_displaytype_t e);
const char *get_datatype_str(fru_datatype_t e);
const char *get_which_str(fru_which_t e);
const char *get_itertype_str(fru_itertype_t e);

#ifdef	__cplusplus
}
#endif

#endif /* _LIBFRU_H */
