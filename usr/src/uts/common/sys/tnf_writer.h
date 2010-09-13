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
 * Copyright 1994,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_TNF_WRITER_H
#define	_SYS_TNF_WRITER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Public interface for writing predefined TNF types
 */
#include <sys/types.h>
#include <sys/tnf_com.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Defines
 */

#define	TNF_OFFSETOF(s, m) 	((size_t)(&(((s *)0)->m)))
#define	TNF_ALIGN(type)		TNF_OFFSETOF(struct { char _c; type _t; }, _t)

/*
 * Typedefs
 */

typedef char 		*tnf_record_p;	  /* trace buffer memory ptr */
typedef tnf_ref32_t	tnf_reference_t;  /* generic reference */

typedef struct _tnf_ops		tnf_ops_t; /* opaque */
typedef struct _tnf_tag_version	tnf_tag_version_t;
typedef struct _tnf_tag_data	tnf_tag_data_t;

/*
 * In-memory reader's classification of TNF types
 */

typedef enum {
	TNF_UNKNOWN	= 0,
	TNF_INT32,
	TNF_UINT32,
	TNF_INT64,
	TNF_UINT64,
	TNF_FLOAT32,
	TNF_FLOAT64,
	TNF_STRING,
	TNF_ARRAY,
	TNF_STRUCT,
	TNF_OPAQUE,
#ifdef _LP64
	TNF_ULONG = TNF_UINT64,
	TNF_LONG = TNF_INT64
#else
	TNF_ULONG = TNF_UINT32,
	TNF_LONG = TNF_INT32
#endif
} tnf_arg_kind_t;

/*
 * Structures
 */

struct _tnf_tag_version {
	size_t		version_size;	/* sizeof(tnf_tag_version_t) */
	size_t		tag_data_size;	/* sizeof(tnf_tag_data_t) */
};

struct _tnf_tag_data {
	tnf_tag_version_t *tag_version; /* TNF_TAG_VERSION */
	tnf_record_p	(*tag_desc)(tnf_ops_t *, tnf_tag_data_t *);
	tnf_record_p	tag_index;	/* trace buffer address */
	const char	*tag_name;	/* name */
	tnf_tag_data_t	****tag_props;	/* properties */
	size_t		tag_size;	/* type_size, header_size */
	size_t		tag_align;	/* alignment */
	size_t		tag_ref_size;	/* reference size */
	tnf_arg_kind_t	tag_kind;	/* type of object */
	tnf_tag_data_t	**tag_base;	/* element_type, derived_base */
	tnf_tag_data_t	***tag_slots;	/* slot_types, header_types */
	char		**tag_slot_names; /* slot_names */
};

/*
 * TNF tag version
 * A client can scan a binary's relocation table for data relocation
 * entries corresponding to __tnf_tag_version_1.  These identify
 * tags.  The actual version information is stored in an associated
 * structure called __tnf_tag_version_1_info
 */

extern tnf_tag_version_t __tnf_tag_version_1_info;

extern tnf_tag_version_t __tnf_tag_version_1;
#pragma weak __tnf_tag_version_1	/* placeholder: never defined */
#define	TNF_TAG_VERSION	&__tnf_tag_version_1

/*
 * TNF primitive types
 */

extern tnf_tag_data_t	*tnf_char_tag_data;
#define	tnf_char(ops, item, ref)	(item)

extern tnf_tag_data_t	*tnf_int8_tag_data;
#define	tnf_int8(ops, item, ref)	(item)

extern tnf_tag_data_t	*tnf_uint8_tag_data;
#define	tnf_uint8(ops, item, ref)	(item)

extern tnf_tag_data_t	*tnf_int16_tag_data;
#define	tnf_int16(ops, item, ref)	(item)

extern tnf_tag_data_t	*tnf_uint16_tag_data;
#define	tnf_uint16(ops, item, ref)	(item)

extern tnf_tag_data_t	*tnf_int32_tag_data;
#define	tnf_int32(ops, item, ref) 	(item)

extern tnf_tag_data_t	*tnf_uint32_tag_data;
#define	tnf_uint32(ops, item, ref)	(item)

extern tnf_tag_data_t	*tnf_int64_tag_data;
#define	tnf_int64(ops, item, ref)	(item)

extern tnf_tag_data_t	*tnf_uint64_tag_data;
#define	tnf_uint64(ops, item, ref)	(item)

extern tnf_tag_data_t	*tnf_float32_tag_data;
#define	tnf_float32(ops, item, ref)	(item)

extern tnf_tag_data_t	*tnf_float64_tag_data;
#define	tnf_float64(ops, item, ref)	(item)

/*
 * ``Portable'' primitive types
 * These are defined as the well-defined TNF types they map into.
 * XXX Machine-dependent
 */

typedef tnf_uint8_t			tnf_uchar_t;
#define	tnf_uchar(ops, item, ref)	tnf_uint8(ops, item, ref)
#define	tnf_uchar_tag_data		tnf_uint8_tag_data

typedef tnf_int16_t			tnf_short_t;
#define	tnf_short(ops, item, ref)	tnf_int16(ops, item, ref)
#define	tnf_short_tag_data		tnf_int16_tag_data

typedef tnf_uint16_t			tnf_ushort_t;
#define	tnf_ushort(ops, item, ref)	tnf_uint16(ops, item, ref)
#define	tnf_ushort_tag_data		tnf_uint16_tag_data

typedef tnf_int32_t			tnf_int_t;
#define	tnf_int(ops, item, ref)	tnf_int32(ops, item, ref)
#define	tnf_int_tag_data		tnf_int32_tag_data

typedef tnf_uint32_t			tnf_uint_t;
#define	tnf_uint(ops, item, ref)	tnf_uint32(ops, item, ref)
#define	tnf_uint_tag_data		tnf_uint32_tag_data

#if defined(_LP64)

typedef tnf_int64_t			tnf_long_t;
#define	tnf_long(ops, item, ref)	tnf_int64(ops, item, ref)
#define	tnf_long_tag_data		tnf_int64_tag_data

typedef tnf_uint64_t			tnf_ulong_t;
#define	tnf_ulong(ops, item, ref)	tnf_uint64(ops, item, ref)
#define	tnf_ulong_tag_data		tnf_uint64_tag_data

#else

typedef tnf_int32_t			tnf_long_t;
#define	tnf_long(ops, item, ref)	tnf_int32(ops, item, ref)
#define	tnf_long_tag_data		tnf_int32_tag_data

typedef tnf_uint32_t			tnf_ulong_t;
#define	tnf_ulong(ops, item, ref)	tnf_uint32(ops, item, ref)
#define	tnf_ulong_tag_data		tnf_uint32_tag_data

#endif /* defined(_LP64) */

typedef tnf_int64_t			tnf_longlong_t;
#define	tnf_longlong(ops, item, ref)	tnf_int64(ops, item, ref)
#define	tnf_longlong_tag_data		tnf_int64_tag_data

typedef tnf_uint64_t			tnf_ulonglong_t;
#define	tnf_ulonglong(ops, item, ref)	tnf_uint64(ops, item, ref)
#define	tnf_ulonglong_tag_data		tnf_uint64_tag_data

typedef tnf_float32_t			tnf_float_t;
#define	tnf_float(ops, item, ref)	tnf_float32(ops, item, ref)
#define	tnf_float_tag_data		tnf_float32_tag_data

typedef tnf_float64_t			tnf_double_t;
#define	tnf_double(ops, item, ref)	tnf_float64(ops, item, ref)
#define	tnf_double_tag_data		tnf_float64_tag_data

/*
 * Derived and aggregate TNF types
 */

/* Not explicitly represented in type system */
#define	tnf_ref32(ops, item, ref)	\
	tnf_ref32_1(ops, item, ref)

extern tnf_tag_data_t		*tnf_tag_tag_data;
typedef tnf_ref32_t		tnf_tag_t;
#define	tnf_tag(ops, item, ref) 	\
	(tnf_ref32(ops, item, ref) | TNF_REF32_T_TAG)

extern tnf_tag_data_t		*tnf_string_tag_data;
typedef tnf_reference_t		tnf_string_t;
#define	tnf_string(ops, item, ref)	\
	tnf_string_1(ops, item, ref, tnf_string_tag_data)

extern tnf_tag_data_t		*tnf_name_tag_data;
typedef tnf_string_t 		tnf_name_t;
#define	tnf_name(ops, item, ref) 	\
	tnf_string_1(ops, item, ref, tnf_name_tag_data)

extern tnf_tag_data_t		*tnf_size_tag_data;
typedef tnf_ulong_t		tnf_size_t;
#define	tnf_size(ops, item, ref) 	\
	tnf_ulong(ops, item, ref)

extern tnf_tag_data_t		*tnf_opaque_tag_data;

#if defined(_LP64)

typedef tnf_uint64_t			tnf_opaque_t;
#define	tnf_opaque(ops, item, ref)	\
	((tnf_uint64_t)(item))

#else

typedef tnf_uint32_t			tnf_opaque_t;
#define	tnf_opaque(ops, item, ref)	\
	((tnf_uint32_t)(item))

#endif /* defined(_LP64) */

/*
 * TNF types for tracing
 */

extern tnf_tag_data_t		*tnf_time_base_tag_data;
typedef tnf_int64_t		tnf_time_base_t;
#define	tnf_time_base(ops, item, ref) 	\
	tnf_int64(ops, item, ref)

extern tnf_tag_data_t		*tnf_time_delta_tag_data;
typedef tnf_uint32_t		tnf_time_delta_t;
#define	tnf_time_delta(ops, item, ref) 	\
	tnf_uint32(ops, item, ref)

extern tnf_tag_data_t		*tnf_probe_event_tag_data;
typedef tnf_ref32_t		tnf_probe_event_t;
#define	tnf_probe_event(ops, item, ref) \
	((tnf_ref32_t)(item) | TNF_REF32_T_PAIR)

/* process ID */
extern tnf_tag_data_t		*tnf_pid_tag_data;
typedef tnf_int32_t		tnf_pid_t;
#define	tnf_pid(ops, item, ref)		\
	tnf_int32(ops, item, ref)

/* LWP ID */
extern tnf_tag_data_t		*tnf_lwpid_tag_data;
typedef tnf_uint32_t		tnf_lwpid_t;
#define	tnf_lwpid(ops, item, ref)	\
	tnf_uint32(ops, item, ref)

#ifdef _KERNEL

/* kernel thread ID */
extern tnf_tag_data_t		*tnf_kthread_id_tag_data;
typedef tnf_opaque_t		tnf_kthread_id_t;
#define	tnf_kthread_id(ops, item, ref)	\
	tnf_opaque(ops, item, ref)

/* processor ID */
extern tnf_tag_data_t		*tnf_cpuid_tag_data;
typedef tnf_int32_t		tnf_cpuid_t;
#define	tnf_cpuid(ops, item, ref)	\
	tnf_int32(ops, item, ref)

/* device ID */
extern tnf_tag_data_t		*tnf_device_tag_data;
typedef tnf_ulong_t		tnf_device_t;
#define	tnf_device(ops, item, ref)	\
	tnf_ulong(ops, item, ref)

/* kernel symbol */
extern tnf_tag_data_t		*tnf_symbol_tag_data;
typedef	tnf_opaque_t		tnf_symbol_t;
#define	tnf_symbol(ops, item, ref)	\
	tnf_opaque(ops, item, ref)

/* array of symbols */
extern tnf_tag_data_t		*tnf_symbols_tag_data;
typedef tnf_ref32_t		tnf_symbols_t;

#if defined(__sparc)
#define	tnf_symbols(ops, item, ref)	\
	tnf_opaque32_array_1(ops, item, ref, tnf_symbols_tag_data)
#else /* defined(__sparc) */
#define	tnf_symbols(ops, item, ref)	\
	tnf_opaque_array_1(ops, item, ref, tnf_symbols_tag_data)
#endif /* defined(__sparc) */

/* system call number */
extern tnf_tag_data_t		*tnf_sysnum_tag_data;
typedef tnf_int16_t		tnf_sysnum_t;
#define	tnf_sysnum(ops, item, ref)	\
	tnf_int16(ops, item, ref)

/* thread microstate XXX enum */
/* XXX should have a new type tnf_enum of appropriate size to map C enum's */
/* XXX cast below is to avoid lint warnings */
extern tnf_tag_data_t		*tnf_microstate_tag_data;
typedef tnf_int32_t		tnf_microstate_t;
#define	tnf_microstate(ops, item, ref)	\
	tnf_int32(ops, (tnf_int32_t)(item), ref)

/* file offset */
extern tnf_tag_data_t		*tnf_offset_tag_data;
typedef tnf_int64_t		tnf_offset_t;
#define	tnf_offset(ops, item, ref)	\
	tnf_int64(ops, item, ref)

/* address fault type XXX enum */
/* XXX should have a new type tnf_enum of appropriate size to map C enum's */
/* XXX cast below is to avoid lint warnings */
extern tnf_tag_data_t		*tnf_fault_type_tag_data;
typedef tnf_int32_t		tnf_fault_type_t;
#define	tnf_fault_type(ops, item, ref)	\
	tnf_int32(ops, (tnf_int32_t)(item), ref)

/* segment access type XXX enum */
/* XXX should have a new type tnf_enum of appropriate size to map C enum's */
/* XXX cast below is to avoid lint warnings */
extern tnf_tag_data_t		*tnf_seg_access_tag_data;
typedef tnf_int32_t		tnf_seg_access_t;
#define	tnf_seg_access(ops, item, ref)	\
	tnf_int32(ops, (tnf_int32_t)(item), ref)

/* buffered I/O flags */
extern tnf_tag_data_t		*tnf_bioflags_tag_data;
typedef tnf_int32_t		tnf_bioflags_t;
#define	tnf_bioflags(ops, item, ref)	\
	tnf_int32(ops, item, ref)

/* disk block addresses */
extern tnf_tag_data_t		*tnf_diskaddr_tag_data;
typedef tnf_int64_t		tnf_diskaddr_t;
#define	tnf_diskaddr(ops, item, ref)	\
	tnf_int64(ops, item, ref)

#endif /* _KERNEL */

/*
 * Type extension interface
 */

extern tnf_tag_data_t	***tnf_user_struct_properties;

/*
 * Data encoders
 */

extern tnf_ref32_t	tnf_ref32_1(tnf_ops_t *,
					tnf_record_p,
					tnf_record_p);

extern tnf_reference_t 	tnf_string_1(tnf_ops_t *,
					const char *,
					tnf_record_p,
					tnf_tag_data_t *);

#ifdef _KERNEL

extern tnf_reference_t	tnf_opaque_array_1(tnf_ops_t *,
					tnf_opaque_t *,
					tnf_record_p,
					tnf_tag_data_t *);

#ifdef __sparc
extern tnf_reference_t	tnf_opaque32_array_1(tnf_ops_t *,
					tnf_uint32_t *,
					tnf_record_p,
					tnf_tag_data_t *);
#endif /* __sparc */

#endif /* _KERNEL */

/*
 * Tag descriptors
 */

extern tnf_record_p tnf_struct_tag_1(tnf_ops_t *, tnf_tag_data_t *);

/*
 * Buffer memory allocator
 */

extern void *tnf_allocate(tnf_ops_t *, size_t);

/*
 * Weak symbol definitions to allow unprobed operation
 */

#if !defined(_KERNEL) && !defined(_TNF_LIBRARY)

#pragma weak	__tnf_tag_version_1_info

#pragma weak	tnf_char_tag_data
#pragma	weak	tnf_int8_tag_data
#pragma	weak	tnf_uint8_tag_data
#pragma	weak	tnf_int16_tag_data
#pragma	weak	tnf_uint16_tag_data
#pragma weak	tnf_int32_tag_data
#pragma weak	tnf_uint32_tag_data
#pragma weak	tnf_int64_tag_data
#pragma weak	tnf_uint64_tag_data
#pragma weak	tnf_float32_tag_data
#pragma weak	tnf_float64_tag_data

#pragma weak	tnf_tag_tag_data
#pragma weak	tnf_string_tag_data
#pragma weak	tnf_name_tag_data
#pragma weak	tnf_opaque_tag_data
#pragma weak	tnf_size_tag_data

#pragma weak	tnf_probe_event_tag_data
#pragma weak	tnf_time_delta_tag_data

#pragma weak	tnf_user_struct_properties

#pragma weak	tnf_ref32_1
#pragma weak	tnf_string_1
#pragma weak	tnf_struct_tag_1
#pragma weak	tnf_allocate

#endif /* !defined(_KERNEL) || !defined(_TNF_LIBRARY) */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_TNF_WRITER_H */
