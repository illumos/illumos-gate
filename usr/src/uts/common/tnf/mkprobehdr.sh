#!/usr/bin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright (c) 1994-2000 by Sun Microsystems, Inc.
# All rights reserved.
#
#ident	"%Z%%M%	%I%	%E% SMI"

cat <<ENDSTR
/*
 *	Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#ifndef _SYS_TNF_PROBE_H
#define	_SYS_TNF_PROBE_H

#pragma ident	"%Z%tnf_probe.h	%I%	%E% SMI"

#include <sys/tnf_writer.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * These macros are used to convert the __LINE__ directive to a
 * string in the probe macros below.
 */

#define	TNF_STRINGIFY(x) #x
#define	TNF_STRINGVALUE(x) TNF_STRINGIFY(x)

/*
 * Alignment of tnf_ref32_t
 */

struct _tnf_ref32_align {
	char		c;
	tnf_ref32_t	t;
};
#define	TNF_REF32_ALIGN		TNF_OFFSETOF(struct _tnf_ref32_align, t)

/*
 * Probe versioning
 */

struct tnf_probe_version {
	size_t	version_size;		/* sizeof(struct tnf_probe_version) */
	size_t	probe_control_size;	/* sizeof(tnf_probe_control_t) */
};

extern struct tnf_probe_version __tnf_probe_version_1;
#pragma weak __tnf_probe_version_1

/*
 * Typedefs
 */

typedef struct tnf_probe_control tnf_probe_control_t;
typedef struct tnf_probe_setup tnf_probe_setup_t;

/* returns pointer to buffer */
typedef void * (*tnf_probe_test_func_t)(void *,
					tnf_probe_control_t *,
					tnf_probe_setup_t *);

/* returns buffer pointer */
typedef void * (*tnf_probe_alloc_func_t)(tnf_ops_t *,	/* tpd	*/
					tnf_probe_control_t *,
					tnf_probe_setup_t *);

typedef void (*tnf_probe_func_t)(tnf_probe_setup_t *);

/*
 * Probe argument block
 */

struct tnf_probe_setup {
	tnf_ops_t		*tpd_p;
	void			*buffer_p;
	tnf_probe_control_t	*probe_p;
};

/*
 * Probe control block
 */

struct tnf_probe_control {
	const struct tnf_probe_version	*version;
	tnf_probe_control_t	*next;
	tnf_probe_test_func_t	test_func;
	tnf_probe_alloc_func_t	alloc_func;
	tnf_probe_func_t	probe_func;
	tnf_probe_func_t	commit_func;
	tnf_uint32_t		index;
	const char		*attrs;
	tnf_tag_data_t		***slot_types;
	unsigned long		tnf_event_size;
};

#ifdef _KERNEL

#define	TNF_NEXT_INIT	0

#else

#define	TNF_NEXT_INIT	-1

#endif	/* _KERNEL */

/*
 * TNF Type extension
 */

#ifdef NPROBE

#define	TNF_DECLARE_RECORD(ctype, record)				\\
	typedef tnf_reference_t record##_t

#else

#define	TNF_DECLARE_RECORD(ctype, record)				\\
	typedef tnf_reference_t record##_t;				\\
	extern tnf_tag_data_t *record##_tag_data;			\\
	extern record##_t record(tnf_ops_t *, ctype *, tnf_reference_t)

#endif	/* NPROBE */

ENDSTR

#
# The following code generates the five type extension macros
#
for i in 1 2 3 4 5; do
  echo "#ifdef NPROBE\n"
  echo "/* CSTYLED */"
  echo "#define	TNF_DEFINE_RECORD_$i(ctype, ctype_record\c"
  j=1; while [ $j -le $i ]; do
    echo ", t$j, n$j\c"
    j=`expr $j + 1`
  done
  echo ")\n"
  echo "#else\n"
  echo "/* CSTYLED */"
  echo "#define	TNF_DEFINE_RECORD_$i(ctype, ctype_record\c"
  j=1; while [ $j -le $i ]; do
    echo ", t$j, n$j\c"
    j=`expr $j + 1`
  done
  echo ") \\"
  echo "typedef struct {						\\"
  echo "	tnf_tag_t	tag;					\\"
  j=1; while [ $j -le $i ]; do
    echo "	t$j##_t		data_$j;				\\"
    j=`expr $j + 1`
  done
  echo "} ctype_record##_prototype_t;					\\"
  echo "static tnf_tag_data_t **ctype_record##_type_slots[] = {		\\"
  echo "	&tnf_tag_tag_data,					\\"
  j=1; while [ $j -le $i ]; do
    echo "	&t$j##_tag_data,					\\"
    j=`expr $j + 1`
  done
  echo "	0 };							\\";
  echo "static char *ctype_record##_slot_names[] = {			\\";
  echo "	\"tnf_tag\",						\\"
  j=1; while [ $j -le $i ]; do
    echo "	\"\"#n$j,						\\"
    j=`expr $j + 1`
  done
  echo "	0 };							\\"
  echo "static tnf_tag_data_t ctype_record##_tag_data_rec = {		\\"
  echo "	TNF_TAG_VERSION, &tnf_struct_tag_1,			\\"
  echo "	0, #ctype_record, &tnf_user_struct_properties,		\\"
  echo "	sizeof (ctype_record##_prototype_t),			\\"
  echo "	TNF_REF32_ALIGN,					\\"
  echo "	sizeof (ctype_record##_t), TNF_STRUCT, 0,		\\"
  echo "	ctype_record##_type_slots, ctype_record##_slot_names	\\"
  echo "};								\\"
  echo "tnf_tag_data_t *ctype_record##_tag_data =			\\"
  echo "			&ctype_record##_tag_data_rec;		\\"
  echo "ctype_record##_t						\\"
  echo "ctype_record(tnf_ops_t *ops, ctype * the_ctype,			\\"
  echo "				tnf_reference_t reference)	\\"
  echo "{								\\"
  echo "	tnf_tag_data_t			*metatag_data;		\\"
  echo "	tnf_record_p			metatag_index;		\\"
  echo "	ctype_record##_prototype_t	*buffer;		\\"
  echo "								\\"
  echo "	if (the_ctype == NULL)					\\"
  echo "		return (0);					\\"
  echo "	buffer = (ctype_record##_prototype_t *) tnf_allocate(ops, \\"
  echo "			sizeof (ctype_record##_prototype_t));	\\"
  echo "	if (buffer == NULL)					\\"
  echo "		return (0);					\\"
  echo "								\\"
  echo "	metatag_data = ctype_record##_tag_data;			\\"
  echo "	metatag_index = metatag_data->tag_index ?		\\"
  echo "		metatag_data->tag_index:			\\"
  echo "		metatag_data->tag_desc(ops, metatag_data);	\\"
  echo "	buffer->tag = tnf_tag(ops, metatag_index,		\\"
  echo "		(tnf_reference_t) &buffer->tag);		\\"
  j=1; while [ $j -le $i ]; do
    echo "	buffer->data_$j = t$j(ops, the_ctype->n$j,		\\"
    echo "			(tnf_reference_t) &(buffer->data_$j));	\\"
    j=`expr $j + 1`
  done
  echo "	return (tnf_ref32(ops, (tnf_record_p) buffer, reference)); \\"
  echo "}\n"
  echo "#endif /* NPROBE */"
  echo ""
done

echo "/*"
echo " * Probe Macros"
echo " */"
echo ""

#
# The following code generates the six probe macros ...
#
for i in 0 1 2 3 4 5; do
  echo "#ifdef NPROBE\n"
  echo "/* CSTYLED */"
  echo "#define	TNF_PROBE_$i(namearg, keysarg, detail\c"
  j=1; while [ $j -le $i ]; do
    echo ", type_$j, namearg_$j, valarg_$j\c"
    j=`expr $j + 1`
  done
  echo ") \\"
  echo "\t\t((void)0)\n"
  echo "#else\n"
  echo "/* CSTYLED */"
  echo "#define	TNF_PROBE_$i(namearg, keysarg, detail\c"
  j=1; while [ $j -le $i ]; do
    echo ", type_$j, namearg_$j, valarg_$j\c";
    j=`expr $j + 1`
  done
  echo ")	\\"
  echo "{								\\"
  echo "	struct tnf_v_buf_$i {					\\"
  echo "		tnf_probe_event_t	probe_event;		\\"
  echo "		tnf_time_delta_t	time_delta;		\\"
  j=1; while [ $j -le $i ]; do
    echo "		type_$j##_t		data_$j;		\\"
    j=`expr $j + 1`
  done
  echo "	};							\\"
  echo "	static tnf_tag_data_t ** tnf_v_##namearg##_info[] = {		\\"
  echo "		&tnf_probe_event_tag_data,			\\"
  echo "		&tnf_time_delta_tag_data,			\\"
  j=1; while [ $j -le $i ]; do
    echo "		&type_$j##_tag_data,				\\"
    j=`expr $j + 1`
  done
  echo "		0 };						\\"
  echo "	static struct tnf_probe_control tnf_v_##namearg##_probe = {	\\"
  echo "		&__tnf_probe_version_1,				\\"
  echo "		(tnf_probe_control_t *) TNF_NEXT_INIT,		\\"
  echo "		(tnf_probe_test_func_t) 0,			\\"
  echo "		(tnf_probe_alloc_func_t) 0,			\\"
  echo "		(tnf_probe_func_t) 0,				\\"
  echo "		(tnf_probe_func_t) 0,				\\"
  echo "		(tnf_uint32_t) 0,				\\"
  echo "			/* attribute string */			\\"
  echo "			\"name \" TNF_STRINGVALUE(namearg) \";\" \\"
#  echo "			\"slots \"\c"
#  j=1; while [ $j -le $i ]; do
#    echo " #namearg_$j \" \"\c"
#    j=`expr $j + 1`
  echo "			\"slots \"				\\"
  j=1; while [ $j -le $i ]; do
    echo "			\"\"#namearg_$j\" \"			\\"
    j=`expr $j + 1`
  done
  echo "			\";\"					\\"
  echo "			\"keys \" keysarg \";\"			\\"
  echo "			\"file \" __FILE__ \";\"		\\"
  echo "			\"line \" TNF_STRINGVALUE(__LINE__) \";\" \\"
  echo "			detail,					\\"
  echo "		tnf_v_##namearg##_info,					\\"
  echo "		sizeof (struct tnf_v_buf_$i)			\\"
  echo "	};							\\"
  echo "	tnf_probe_control_t	*tnf_v_probe_p = &tnf_v_##namearg##_probe; \\"
  echo "	tnf_probe_test_func_t	tnf_v_probe_test = tnf_v_probe_p->test_func; \\"
  echo "	tnf_probe_setup_t	tnf_v_set_p;			\\"
  echo "	struct tnf_v_buf_$i	*tnf_v_probe_buffer;		\\"
  echo "								\\"
  echo "	if (tnf_v_probe_test) {					\\"
  echo "		tnf_v_probe_buffer = (struct tnf_v_buf_$i *)	\\"
  echo "		    tnf_v_probe_test(0, tnf_v_probe_p, &tnf_v_set_p); \\"
  echo "		if (tnf_v_probe_buffer) {			\\"
  j=1; while [ $j -le $i ]; do
    echo "		    tnf_v_probe_buffer->data_$j = type_$j(	\\"
    echo "			tnf_v_set_p.tpd_p, valarg_$j,		\\"
    echo "			(tnf_reference_t) &(tnf_v_probe_buffer->data_$j)); \\"
    j=`expr $j + 1`
  done
  echo "		    (tnf_v_probe_p->probe_func)(&tnf_v_set_p);	\\"
  echo "		}						\\"
  echo "	}							\\"
  echo "}\n"
  echo "#endif /* NPROBE */"
  echo ""
  done

echo "/*"
echo " * Debug Probe Macros (contain an additional \"debug\" attribute)"
echo " */"
echo ""

#
# The following code generates the six debug probe macros ...
#
for i in 0 1 2 3 4 5; do
  echo "#if defined(TNF_DEBUG)\n"
  echo "/* CSTYLED */"
  echo "#define	TNF_PROBE_${i}_DEBUG(namearg, keysarg, detail\c"
  j=1; while [ $j -le $i ]; do
    echo ", type_$j, namearg_$j, valarg_$j\c";
    j=`expr $j + 1`
  done
  echo ")\t\c"
  echo "TNF_PROBE_$i(namearg, keysarg, \"debug;\" detail\c"
  j=1; while [ $j -le $i ]; do
    echo ", type_$j, namearg_$j, valarg_$j\c"
    j=`expr $j + 1`
  done
  echo ")\n"
  echo "#else\n"
  echo "/* CSTYLED */"
  echo "#define	TNF_PROBE_${i}_DEBUG(namearg, keysarg, detail\c"
  j=1; while [ $j -le $i ]; do
    echo ", type_$j, namearg_$j, valarg_$j\c"
    j=`expr $j + 1`
  done
  echo ") \\"
  echo "\t\t((void)0)\n"
  echo "#endif /* defined(TNF_DEBUG) */"
  echo ""
  done

  echo "#ifdef __cplusplus"
  echo "}"
  echo "#endif"
  echo ""
  echo "#endif /* _SYS_TNF_PROBE_H */"
