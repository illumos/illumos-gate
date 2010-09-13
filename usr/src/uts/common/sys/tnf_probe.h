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
 *	Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#ifndef _SYS_TNF_PROBE_H
#define	_SYS_TNF_PROBE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
	uintptr_t		index;
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

#define	TNF_DECLARE_RECORD(ctype, record)				\
	typedef tnf_reference_t record##_t

#else

#define	TNF_DECLARE_RECORD(ctype, record)				\
	typedef tnf_reference_t record##_t;				\
	extern tnf_tag_data_t *record##_tag_data;			\
	extern record##_t record(tnf_ops_t *, ctype *, tnf_record_p)

#endif	/* NPROBE */

#ifdef NPROBE

/* CSTYLED */
#define	TNF_DEFINE_RECORD_1(ctype, ctype_record, t1, n1)

#else

/* CSTYLED */
#define	TNF_DEFINE_RECORD_1(ctype, ctype_record, t1, n1) \
typedef struct {						\
	tnf_tag_t	tag;					\
	t1##_t		data_1;				\
} ctype_record##_prototype_t;					\
static tnf_tag_data_t **ctype_record##_type_slots[] = {		\
	&tnf_tag_tag_data,					\
	&t1##_tag_data,					\
	0 };							\
static char *ctype_record##_slot_names[] = {			\
	"tnf_tag",						\
	""#n1,						\
	0 };							\
static tnf_tag_data_t ctype_record##_tag_data_rec = {		\
	TNF_TAG_VERSION, &tnf_struct_tag_1,			\
	0, #ctype_record, &tnf_user_struct_properties,		\
	sizeof (ctype_record##_prototype_t),			\
	TNF_REF32_ALIGN,					\
	sizeof (ctype_record##_t), TNF_STRUCT, 0,		\
	ctype_record##_type_slots, ctype_record##_slot_names	\
};								\
tnf_tag_data_t *ctype_record##_tag_data =			\
			&ctype_record##_tag_data_rec;		\
ctype_record##_t						\
ctype_record(tnf_ops_t *ops, ctype * the_ctype,			\
				tnf_record_p reference)	\
{								\
	tnf_tag_data_t			*metatag_data;		\
	tnf_record_p			metatag_index;		\
	ctype_record##_prototype_t	*buffer;		\
								\
	if (the_ctype == NULL)					\
		return (0);					\
	buffer = (ctype_record##_prototype_t *) tnf_allocate(ops, \
			sizeof (ctype_record##_prototype_t));	\
	if (buffer == NULL)					\
		return (0);					\
								\
	metatag_data = ctype_record##_tag_data;			\
	metatag_index = metatag_data->tag_index ?		\
		metatag_data->tag_index:			\
		metatag_data->tag_desc(ops, metatag_data);	\
	buffer->tag = tnf_tag(ops, metatag_index,		\
		(tnf_record_p) &buffer->tag);		\
	buffer->data_1 = t1(ops, the_ctype->n1,		\
			(tnf_record_p) &(buffer->data_1));	\
	return (tnf_ref32(ops, (tnf_record_p) buffer, reference)); \
}

#endif /* NPROBE */

#ifdef NPROBE

/* CSTYLED */
#define	TNF_DEFINE_RECORD_2(ctype, ctype_record, t1, n1, t2, n2)

#else

/* CSTYLED */
#define	TNF_DEFINE_RECORD_2(ctype, ctype_record, t1, n1, t2, n2) \
typedef struct {						\
	tnf_tag_t	tag;					\
	t1##_t		data_1;				\
	t2##_t		data_2;				\
} ctype_record##_prototype_t;					\
static tnf_tag_data_t **ctype_record##_type_slots[] = {		\
	&tnf_tag_tag_data,					\
	&t1##_tag_data,					\
	&t2##_tag_data,					\
	0 };							\
static char *ctype_record##_slot_names[] = {			\
	"tnf_tag",						\
	""#n1,						\
	""#n2,						\
	0 };							\
static tnf_tag_data_t ctype_record##_tag_data_rec = {		\
	TNF_TAG_VERSION, &tnf_struct_tag_1,			\
	0, #ctype_record, &tnf_user_struct_properties,		\
	sizeof (ctype_record##_prototype_t),			\
	TNF_REF32_ALIGN,					\
	sizeof (ctype_record##_t), TNF_STRUCT, 0,		\
	ctype_record##_type_slots, ctype_record##_slot_names	\
};								\
tnf_tag_data_t *ctype_record##_tag_data =			\
			&ctype_record##_tag_data_rec;		\
ctype_record##_t						\
ctype_record(tnf_ops_t *ops, ctype * the_ctype,			\
				tnf_record_p reference)	\
{								\
	tnf_tag_data_t			*metatag_data;		\
	tnf_record_p			metatag_index;		\
	ctype_record##_prototype_t	*buffer;		\
								\
	if (the_ctype == NULL)					\
		return (0);					\
	buffer = (ctype_record##_prototype_t *) tnf_allocate(ops, \
			sizeof (ctype_record##_prototype_t));	\
	if (buffer == NULL)					\
		return (0);					\
								\
	metatag_data = ctype_record##_tag_data;			\
	metatag_index = metatag_data->tag_index ?		\
		metatag_data->tag_index:			\
		metatag_data->tag_desc(ops, metatag_data);	\
	buffer->tag = tnf_tag(ops, metatag_index,		\
		(tnf_record_p) &buffer->tag);		\
	buffer->data_1 = t1(ops, the_ctype->n1,		\
			(tnf_record_p) &(buffer->data_1));	\
	buffer->data_2 = t2(ops, the_ctype->n2,		\
			(tnf_record_p) &(buffer->data_2));	\
	return (tnf_ref32(ops, (tnf_record_p) buffer, reference)); \
}

#endif /* NPROBE */

#ifdef NPROBE

/* CSTYLED */
#define	TNF_DEFINE_RECORD_3(ctype, ctype_record, t1, n1, t2, n2, t3, n3)

#else

/* CSTYLED */
#define	TNF_DEFINE_RECORD_3(ctype, ctype_record, t1, n1, t2, n2, t3, n3) \
typedef struct {						\
	tnf_tag_t	tag;					\
	t1##_t		data_1;				\
	t2##_t		data_2;				\
	t3##_t		data_3;				\
} ctype_record##_prototype_t;					\
static tnf_tag_data_t **ctype_record##_type_slots[] = {		\
	&tnf_tag_tag_data,					\
	&t1##_tag_data,					\
	&t2##_tag_data,					\
	&t3##_tag_data,					\
	0 };							\
static char *ctype_record##_slot_names[] = {			\
	"tnf_tag",						\
	""#n1,						\
	""#n2,						\
	""#n3,						\
	0 };							\
static tnf_tag_data_t ctype_record##_tag_data_rec = {		\
	TNF_TAG_VERSION, &tnf_struct_tag_1,			\
	0, #ctype_record, &tnf_user_struct_properties,		\
	sizeof (ctype_record##_prototype_t),			\
	TNF_REF32_ALIGN,					\
	sizeof (ctype_record##_t), TNF_STRUCT, 0,		\
	ctype_record##_type_slots, ctype_record##_slot_names	\
};								\
tnf_tag_data_t *ctype_record##_tag_data =			\
			&ctype_record##_tag_data_rec;		\
ctype_record##_t						\
ctype_record(tnf_ops_t *ops, ctype * the_ctype,			\
				tnf_record_p reference)	\
{								\
	tnf_tag_data_t			*metatag_data;		\
	tnf_record_p			metatag_index;		\
	ctype_record##_prototype_t	*buffer;		\
								\
	if (the_ctype == NULL)					\
		return (0);					\
	buffer = (ctype_record##_prototype_t *) tnf_allocate(ops, \
			sizeof (ctype_record##_prototype_t));	\
	if (buffer == NULL)					\
		return (0);					\
								\
	metatag_data = ctype_record##_tag_data;			\
	metatag_index = metatag_data->tag_index ?		\
		metatag_data->tag_index:			\
		metatag_data->tag_desc(ops, metatag_data);	\
	buffer->tag = tnf_tag(ops, metatag_index,		\
		(tnf_record_p) &buffer->tag);		\
	buffer->data_1 = t1(ops, the_ctype->n1,		\
			(tnf_record_p) &(buffer->data_1));	\
	buffer->data_2 = t2(ops, the_ctype->n2,		\
			(tnf_record_p) &(buffer->data_2));	\
	buffer->data_3 = t3(ops, the_ctype->n3,		\
			(tnf_record_p) &(buffer->data_3));	\
	return (tnf_ref32(ops, (tnf_record_p) buffer, reference)); \
}

#endif /* NPROBE */

#ifdef NPROBE

/* CSTYLED */
#define	TNF_DEFINE_RECORD_4(ctype, ctype_record, t1, n1, t2, n2, t3, n3, t4, n4)

#else

/* CSTYLED */
#define	TNF_DEFINE_RECORD_4(ctype, ctype_record, t1, n1, t2, n2, t3, n3, t4, n4) \
typedef struct {						\
	tnf_tag_t	tag;					\
	t1##_t		data_1;				\
	t2##_t		data_2;				\
	t3##_t		data_3;				\
	t4##_t		data_4;				\
} ctype_record##_prototype_t;					\
static tnf_tag_data_t **ctype_record##_type_slots[] = {		\
	&tnf_tag_tag_data,					\
	&t1##_tag_data,					\
	&t2##_tag_data,					\
	&t3##_tag_data,					\
	&t4##_tag_data,					\
	0 };							\
static char *ctype_record##_slot_names[] = {			\
	"tnf_tag",						\
	""#n1,						\
	""#n2,						\
	""#n3,						\
	""#n4,						\
	0 };							\
static tnf_tag_data_t ctype_record##_tag_data_rec = {		\
	TNF_TAG_VERSION, &tnf_struct_tag_1,			\
	0, #ctype_record, &tnf_user_struct_properties,		\
	sizeof (ctype_record##_prototype_t),			\
	TNF_REF32_ALIGN,					\
	sizeof (ctype_record##_t), TNF_STRUCT, 0,		\
	ctype_record##_type_slots, ctype_record##_slot_names	\
};								\
tnf_tag_data_t *ctype_record##_tag_data =			\
			&ctype_record##_tag_data_rec;		\
ctype_record##_t						\
ctype_record(tnf_ops_t *ops, ctype * the_ctype,			\
				tnf_record_p reference)	\
{								\
	tnf_tag_data_t			*metatag_data;		\
	tnf_record_p			metatag_index;		\
	ctype_record##_prototype_t	*buffer;		\
								\
	if (the_ctype == NULL)					\
		return (0);					\
	buffer = (ctype_record##_prototype_t *) tnf_allocate(ops, \
			sizeof (ctype_record##_prototype_t));	\
	if (buffer == NULL)					\
		return (0);					\
								\
	metatag_data = ctype_record##_tag_data;			\
	metatag_index = metatag_data->tag_index ?		\
		metatag_data->tag_index:			\
		metatag_data->tag_desc(ops, metatag_data);	\
	buffer->tag = tnf_tag(ops, metatag_index,		\
		(tnf_record_p) &buffer->tag);		\
	buffer->data_1 = t1(ops, the_ctype->n1,		\
			(tnf_record_p) &(buffer->data_1));	\
	buffer->data_2 = t2(ops, the_ctype->n2,		\
			(tnf_record_p) &(buffer->data_2));	\
	buffer->data_3 = t3(ops, the_ctype->n3,		\
			(tnf_record_p) &(buffer->data_3));	\
	buffer->data_4 = t4(ops, the_ctype->n4,		\
			(tnf_record_p) &(buffer->data_4));	\
	return (tnf_ref32(ops, (tnf_record_p) buffer, reference)); \
}

#endif /* NPROBE */

#ifdef NPROBE

/* CSTYLED */
#define	TNF_DEFINE_RECORD_5(ctype, ctype_record, t1, n1, t2, n2, t3, n3, t4, n4, t5, n5)

#else

/* CSTYLED */
#define	TNF_DEFINE_RECORD_5(ctype, ctype_record, t1, n1, t2, n2, t3, n3, t4, n4, t5, n5) \
typedef struct {						\
	tnf_tag_t	tag;					\
	t1##_t		data_1;				\
	t2##_t		data_2;				\
	t3##_t		data_3;				\
	t4##_t		data_4;				\
	t5##_t		data_5;				\
} ctype_record##_prototype_t;					\
static tnf_tag_data_t **ctype_record##_type_slots[] = {		\
	&tnf_tag_tag_data,					\
	&t1##_tag_data,					\
	&t2##_tag_data,					\
	&t3##_tag_data,					\
	&t4##_tag_data,					\
	&t5##_tag_data,					\
	0 };							\
static char *ctype_record##_slot_names[] = {			\
	"tnf_tag",						\
	""#n1,						\
	""#n2,						\
	""#n3,						\
	""#n4,						\
	""#n5,						\
	0 };							\
static tnf_tag_data_t ctype_record##_tag_data_rec = {		\
	TNF_TAG_VERSION, &tnf_struct_tag_1,			\
	0, #ctype_record, &tnf_user_struct_properties,		\
	sizeof (ctype_record##_prototype_t),			\
	TNF_REF32_ALIGN,					\
	sizeof (ctype_record##_t), TNF_STRUCT, 0,		\
	ctype_record##_type_slots, ctype_record##_slot_names	\
};								\
tnf_tag_data_t *ctype_record##_tag_data =			\
			&ctype_record##_tag_data_rec;		\
ctype_record##_t						\
ctype_record(tnf_ops_t *ops, ctype * the_ctype,			\
				tnf_record_p reference)	\
{								\
	tnf_tag_data_t			*metatag_data;		\
	tnf_record_p			metatag_index;		\
	ctype_record##_prototype_t	*buffer;		\
								\
	if (the_ctype == NULL)					\
		return (0);					\
	buffer = (ctype_record##_prototype_t *) tnf_allocate(ops, \
			sizeof (ctype_record##_prototype_t));	\
	if (buffer == NULL)					\
		return (0);					\
								\
	metatag_data = ctype_record##_tag_data;			\
	metatag_index = metatag_data->tag_index ?		\
		metatag_data->tag_index:			\
		metatag_data->tag_desc(ops, metatag_data);	\
	buffer->tag = tnf_tag(ops, metatag_index,		\
		(tnf_record_p) &buffer->tag);		\
	buffer->data_1 = t1(ops, the_ctype->n1,		\
			(tnf_record_p) &(buffer->data_1));	\
	buffer->data_2 = t2(ops, the_ctype->n2,		\
			(tnf_record_p) &(buffer->data_2));	\
	buffer->data_3 = t3(ops, the_ctype->n3,		\
			(tnf_record_p) &(buffer->data_3));	\
	buffer->data_4 = t4(ops, the_ctype->n4,		\
			(tnf_record_p) &(buffer->data_4));	\
	buffer->data_5 = t5(ops, the_ctype->n5,		\
			(tnf_record_p) &(buffer->data_5));	\
	return (tnf_ref32(ops, (tnf_record_p) buffer, reference)); \
}

#endif /* NPROBE */

/*
 * Probe Macros
 */

#ifdef NPROBE

/* CSTYLED */
#define	TNF_PROBE_0(namearg, keysarg, detail) \
		((void)0)

#else

/* CSTYLED */
#define	TNF_PROBE_0(namearg, keysarg, detail)	\
{								\
	struct tnf_v_buf_0 {					\
		tnf_probe_event_t	probe_event;		\
		tnf_time_delta_t	time_delta;		\
	};							\
	static tnf_tag_data_t ** tnf_v_##namearg##_info[] = {		\
		&tnf_probe_event_tag_data,			\
		&tnf_time_delta_tag_data,			\
		0 };						\
	static struct tnf_probe_control tnf_v_##namearg##_probe = {	\
		&__tnf_probe_version_1,				\
		(tnf_probe_control_t *) TNF_NEXT_INIT,		\
		(tnf_probe_test_func_t) 0,			\
		(tnf_probe_alloc_func_t) 0,			\
		(tnf_probe_func_t) 0,				\
		(tnf_probe_func_t) 0,				\
		(tnf_uint32_t) 0,				\
			/* attribute string */			\
			"name " TNF_STRINGVALUE(namearg) ";" \
			"slots "				\
			";"					\
			"keys " keysarg ";"			\
			"file " __FILE__ ";"		\
			"line " TNF_STRINGVALUE(__LINE__) ";" \
			detail,					\
		tnf_v_##namearg##_info,					\
		sizeof (struct tnf_v_buf_0)			\
	};							\
	tnf_probe_control_t	*tnf_v_probe_p = &tnf_v_##namearg##_probe; \
	tnf_probe_test_func_t	tnf_v_probe_test = tnf_v_probe_p->test_func; \
	tnf_probe_setup_t	tnf_v_set_p;			\
	struct tnf_v_buf_0	*tnf_v_probe_buffer;		\
								\
	if (tnf_v_probe_test) {					\
		tnf_v_probe_buffer = (struct tnf_v_buf_0 *)	\
		    tnf_v_probe_test(0, tnf_v_probe_p, &tnf_v_set_p); \
		if (tnf_v_probe_buffer) {			\
		    (tnf_v_probe_p->probe_func)(&tnf_v_set_p);	\
		}						\
	}							\
}

#endif /* NPROBE */

#ifdef NPROBE

/* CSTYLED */
#define	TNF_PROBE_1(namearg, keysarg, detail, type_1, namearg_1, valarg_1) \
		((void)0)

#else

/* CSTYLED */
#define	TNF_PROBE_1(namearg, keysarg, detail, type_1, namearg_1, valarg_1)	\
{								\
	struct tnf_v_buf_1 {					\
		tnf_probe_event_t	probe_event;		\
		tnf_time_delta_t	time_delta;		\
		type_1##_t		data_1;		\
	};							\
	static tnf_tag_data_t ** tnf_v_##namearg##_info[] = {		\
		&tnf_probe_event_tag_data,			\
		&tnf_time_delta_tag_data,			\
		&type_1##_tag_data,				\
		0 };						\
	static struct tnf_probe_control tnf_v_##namearg##_probe = {	\
		&__tnf_probe_version_1,				\
		(tnf_probe_control_t *) TNF_NEXT_INIT,		\
		(tnf_probe_test_func_t) 0,			\
		(tnf_probe_alloc_func_t) 0,			\
		(tnf_probe_func_t) 0,				\
		(tnf_probe_func_t) 0,				\
		(tnf_uint32_t) 0,				\
			/* attribute string */			\
			"name " TNF_STRINGVALUE(namearg) ";" \
			"slots "				\
			""#namearg_1" "			\
			";"					\
			"keys " keysarg ";"			\
			"file " __FILE__ ";"		\
			"line " TNF_STRINGVALUE(__LINE__) ";" \
			detail,					\
		tnf_v_##namearg##_info,					\
		sizeof (struct tnf_v_buf_1)			\
	};							\
	tnf_probe_control_t	*tnf_v_probe_p = &tnf_v_##namearg##_probe; \
	tnf_probe_test_func_t	tnf_v_probe_test = tnf_v_probe_p->test_func; \
	tnf_probe_setup_t	tnf_v_set_p;			\
	struct tnf_v_buf_1	*tnf_v_probe_buffer;		\
								\
	if (tnf_v_probe_test) {					\
		tnf_v_probe_buffer = (struct tnf_v_buf_1 *)	\
		    tnf_v_probe_test(0, tnf_v_probe_p, &tnf_v_set_p); \
		if (tnf_v_probe_buffer) {			\
		    tnf_v_probe_buffer->data_1 = type_1(	\
			tnf_v_set_p.tpd_p, valarg_1,		\
			(tnf_record_p) &(tnf_v_probe_buffer->data_1)); \
		    (tnf_v_probe_p->probe_func)(&tnf_v_set_p);	\
		}						\
	}							\
}

#endif /* NPROBE */

#ifdef NPROBE

/* CSTYLED */
#define	TNF_PROBE_2(namearg, keysarg, detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2) \
		((void)0)

#else

/* CSTYLED */
#define	TNF_PROBE_2(namearg, keysarg, detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2)	\
{								\
	struct tnf_v_buf_2 {					\
		tnf_probe_event_t	probe_event;		\
		tnf_time_delta_t	time_delta;		\
		type_1##_t		data_1;		\
		type_2##_t		data_2;		\
	};							\
	static tnf_tag_data_t ** tnf_v_##namearg##_info[] = {		\
		&tnf_probe_event_tag_data,			\
		&tnf_time_delta_tag_data,			\
		&type_1##_tag_data,				\
		&type_2##_tag_data,				\
		0 };						\
	static struct tnf_probe_control tnf_v_##namearg##_probe = {	\
		&__tnf_probe_version_1,				\
		(tnf_probe_control_t *) TNF_NEXT_INIT,		\
		(tnf_probe_test_func_t) 0,			\
		(tnf_probe_alloc_func_t) 0,			\
		(tnf_probe_func_t) 0,				\
		(tnf_probe_func_t) 0,				\
		(tnf_uint32_t) 0,				\
			/* attribute string */			\
			"name " TNF_STRINGVALUE(namearg) ";" \
			"slots "				\
			""#namearg_1" "			\
			""#namearg_2" "			\
			";"					\
			"keys " keysarg ";"			\
			"file " __FILE__ ";"		\
			"line " TNF_STRINGVALUE(__LINE__) ";" \
			detail,					\
		tnf_v_##namearg##_info,					\
		sizeof (struct tnf_v_buf_2)			\
	};							\
	tnf_probe_control_t	*tnf_v_probe_p = &tnf_v_##namearg##_probe; \
	tnf_probe_test_func_t	tnf_v_probe_test = tnf_v_probe_p->test_func; \
	tnf_probe_setup_t	tnf_v_set_p;			\
	struct tnf_v_buf_2	*tnf_v_probe_buffer;		\
								\
	if (tnf_v_probe_test) {					\
		tnf_v_probe_buffer = (struct tnf_v_buf_2 *)	\
		    tnf_v_probe_test(0, tnf_v_probe_p, &tnf_v_set_p); \
		if (tnf_v_probe_buffer) {			\
		    tnf_v_probe_buffer->data_1 = type_1(	\
			tnf_v_set_p.tpd_p, valarg_1,		\
			(tnf_record_p) &(tnf_v_probe_buffer->data_1)); \
		    tnf_v_probe_buffer->data_2 = type_2(	\
			tnf_v_set_p.tpd_p, valarg_2,		\
			(tnf_record_p) &(tnf_v_probe_buffer->data_2)); \
		    (tnf_v_probe_p->probe_func)(&tnf_v_set_p);	\
		}						\
	}							\
}

#endif /* NPROBE */

#ifdef NPROBE

/* CSTYLED */
#define	TNF_PROBE_3(namearg, keysarg, detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2, type_3, namearg_3, valarg_3) \
		((void)0)

#else

/* CSTYLED */
#define	TNF_PROBE_3(namearg, keysarg, detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2, type_3, namearg_3, valarg_3)	\
{								\
	struct tnf_v_buf_3 {					\
		tnf_probe_event_t	probe_event;		\
		tnf_time_delta_t	time_delta;		\
		type_1##_t		data_1;		\
		type_2##_t		data_2;		\
		type_3##_t		data_3;		\
	};							\
	static tnf_tag_data_t ** tnf_v_##namearg##_info[] = {		\
		&tnf_probe_event_tag_data,			\
		&tnf_time_delta_tag_data,			\
		&type_1##_tag_data,				\
		&type_2##_tag_data,				\
		&type_3##_tag_data,				\
		0 };						\
	static struct tnf_probe_control tnf_v_##namearg##_probe = {	\
		&__tnf_probe_version_1,				\
		(tnf_probe_control_t *) TNF_NEXT_INIT,		\
		(tnf_probe_test_func_t) 0,			\
		(tnf_probe_alloc_func_t) 0,			\
		(tnf_probe_func_t) 0,				\
		(tnf_probe_func_t) 0,				\
		(tnf_uint32_t) 0,				\
			/* attribute string */			\
			"name " TNF_STRINGVALUE(namearg) ";" \
			"slots "				\
			""#namearg_1" "			\
			""#namearg_2" "			\
			""#namearg_3" "			\
			";"					\
			"keys " keysarg ";"			\
			"file " __FILE__ ";"		\
			"line " TNF_STRINGVALUE(__LINE__) ";" \
			detail,					\
		tnf_v_##namearg##_info,					\
		sizeof (struct tnf_v_buf_3)			\
	};							\
	tnf_probe_control_t	*tnf_v_probe_p = &tnf_v_##namearg##_probe; \
	tnf_probe_test_func_t	tnf_v_probe_test = tnf_v_probe_p->test_func; \
	tnf_probe_setup_t	tnf_v_set_p;			\
	struct tnf_v_buf_3	*tnf_v_probe_buffer;		\
								\
	if (tnf_v_probe_test) {					\
		tnf_v_probe_buffer = (struct tnf_v_buf_3 *)	\
		    tnf_v_probe_test(0, tnf_v_probe_p, &tnf_v_set_p); \
		if (tnf_v_probe_buffer) {			\
		    tnf_v_probe_buffer->data_1 = type_1(	\
			tnf_v_set_p.tpd_p, valarg_1,		\
			(tnf_record_p) &(tnf_v_probe_buffer->data_1)); \
		    tnf_v_probe_buffer->data_2 = type_2(	\
			tnf_v_set_p.tpd_p, valarg_2,		\
			(tnf_record_p) &(tnf_v_probe_buffer->data_2)); \
		    tnf_v_probe_buffer->data_3 = type_3(	\
			tnf_v_set_p.tpd_p, valarg_3,		\
			(tnf_record_p) &(tnf_v_probe_buffer->data_3)); \
		    (tnf_v_probe_p->probe_func)(&tnf_v_set_p);	\
		}						\
	}							\
}

#endif /* NPROBE */

#ifdef NPROBE

/* CSTYLED */
#define	TNF_PROBE_4(namearg, keysarg, detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2, type_3, namearg_3, valarg_3, type_4, namearg_4, valarg_4) \
		((void)0)

#else

/* CSTYLED */
#define	TNF_PROBE_4(namearg, keysarg, detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2, type_3, namearg_3, valarg_3, type_4, namearg_4, valarg_4)	\
{								\
	struct tnf_v_buf_4 {					\
		tnf_probe_event_t	probe_event;		\
		tnf_time_delta_t	time_delta;		\
		type_1##_t		data_1;		\
		type_2##_t		data_2;		\
		type_3##_t		data_3;		\
		type_4##_t		data_4;		\
	};							\
	static tnf_tag_data_t ** tnf_v_##namearg##_info[] = {		\
		&tnf_probe_event_tag_data,			\
		&tnf_time_delta_tag_data,			\
		&type_1##_tag_data,				\
		&type_2##_tag_data,				\
		&type_3##_tag_data,				\
		&type_4##_tag_data,				\
		0 };						\
	static struct tnf_probe_control tnf_v_##namearg##_probe = {	\
		&__tnf_probe_version_1,				\
		(tnf_probe_control_t *) TNF_NEXT_INIT,		\
		(tnf_probe_test_func_t) 0,			\
		(tnf_probe_alloc_func_t) 0,			\
		(tnf_probe_func_t) 0,				\
		(tnf_probe_func_t) 0,				\
		(tnf_uint32_t) 0,				\
			/* attribute string */			\
			"name " TNF_STRINGVALUE(namearg) ";" \
			"slots "				\
			""#namearg_1" "			\
			""#namearg_2" "			\
			""#namearg_3" "			\
			""#namearg_4" "			\
			";"					\
			"keys " keysarg ";"			\
			"file " __FILE__ ";"		\
			"line " TNF_STRINGVALUE(__LINE__) ";" \
			detail,					\
		tnf_v_##namearg##_info,					\
		sizeof (struct tnf_v_buf_4)			\
	};							\
	tnf_probe_control_t	*tnf_v_probe_p = &tnf_v_##namearg##_probe; \
	tnf_probe_test_func_t	tnf_v_probe_test = tnf_v_probe_p->test_func; \
	tnf_probe_setup_t	tnf_v_set_p;			\
	struct tnf_v_buf_4	*tnf_v_probe_buffer;		\
								\
	if (tnf_v_probe_test) {					\
		tnf_v_probe_buffer = (struct tnf_v_buf_4 *)	\
		    tnf_v_probe_test(0, tnf_v_probe_p, &tnf_v_set_p); \
		if (tnf_v_probe_buffer) {			\
		    tnf_v_probe_buffer->data_1 = type_1(	\
			tnf_v_set_p.tpd_p, valarg_1,		\
			(tnf_record_p) &(tnf_v_probe_buffer->data_1)); \
		    tnf_v_probe_buffer->data_2 = type_2(	\
			tnf_v_set_p.tpd_p, valarg_2,		\
			(tnf_record_p) &(tnf_v_probe_buffer->data_2)); \
		    tnf_v_probe_buffer->data_3 = type_3(	\
			tnf_v_set_p.tpd_p, valarg_3,		\
			(tnf_record_p) &(tnf_v_probe_buffer->data_3)); \
		    tnf_v_probe_buffer->data_4 = type_4(	\
			tnf_v_set_p.tpd_p, valarg_4,		\
			(tnf_record_p) &(tnf_v_probe_buffer->data_4)); \
		    (tnf_v_probe_p->probe_func)(&tnf_v_set_p);	\
		}						\
	}							\
}

#endif /* NPROBE */

#ifdef NPROBE

/* CSTYLED */
#define	TNF_PROBE_5(namearg, keysarg, detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2, type_3, namearg_3, valarg_3, type_4, namearg_4, valarg_4, type_5, namearg_5, valarg_5) \
		((void)0)

#else

/* CSTYLED */
#define	TNF_PROBE_5(namearg, keysarg, detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2, type_3, namearg_3, valarg_3, type_4, namearg_4, valarg_4, type_5, namearg_5, valarg_5)	\
{								\
	struct tnf_v_buf_5 {					\
		tnf_probe_event_t	probe_event;		\
		tnf_time_delta_t	time_delta;		\
		type_1##_t		data_1;		\
		type_2##_t		data_2;		\
		type_3##_t		data_3;		\
		type_4##_t		data_4;		\
		type_5##_t		data_5;		\
	};							\
	static tnf_tag_data_t ** tnf_v_##namearg##_info[] = {		\
		&tnf_probe_event_tag_data,			\
		&tnf_time_delta_tag_data,			\
		&type_1##_tag_data,				\
		&type_2##_tag_data,				\
		&type_3##_tag_data,				\
		&type_4##_tag_data,				\
		&type_5##_tag_data,				\
		0 };						\
	static struct tnf_probe_control tnf_v_##namearg##_probe = {	\
		&__tnf_probe_version_1,				\
		(tnf_probe_control_t *) TNF_NEXT_INIT,		\
		(tnf_probe_test_func_t) 0,			\
		(tnf_probe_alloc_func_t) 0,			\
		(tnf_probe_func_t) 0,				\
		(tnf_probe_func_t) 0,				\
		(tnf_uint32_t) 0,				\
			/* attribute string */			\
			"name " TNF_STRINGVALUE(namearg) ";" \
			"slots "				\
			""#namearg_1" "			\
			""#namearg_2" "			\
			""#namearg_3" "			\
			""#namearg_4" "			\
			""#namearg_5" "			\
			";"					\
			"keys " keysarg ";"			\
			"file " __FILE__ ";"		\
			"line " TNF_STRINGVALUE(__LINE__) ";" \
			detail,					\
		tnf_v_##namearg##_info,					\
		sizeof (struct tnf_v_buf_5)			\
	};							\
	tnf_probe_control_t	*tnf_v_probe_p = &tnf_v_##namearg##_probe; \
	tnf_probe_test_func_t	tnf_v_probe_test = tnf_v_probe_p->test_func; \
	tnf_probe_setup_t	tnf_v_set_p;			\
	struct tnf_v_buf_5	*tnf_v_probe_buffer;		\
								\
	if (tnf_v_probe_test) {					\
		tnf_v_probe_buffer = (struct tnf_v_buf_5 *)	\
		    tnf_v_probe_test(0, tnf_v_probe_p, &tnf_v_set_p); \
		if (tnf_v_probe_buffer) {			\
		    tnf_v_probe_buffer->data_1 = type_1(	\
			tnf_v_set_p.tpd_p, valarg_1,		\
			(tnf_record_p) &(tnf_v_probe_buffer->data_1)); \
		    tnf_v_probe_buffer->data_2 = type_2(	\
			tnf_v_set_p.tpd_p, valarg_2,		\
			(tnf_record_p) &(tnf_v_probe_buffer->data_2)); \
		    tnf_v_probe_buffer->data_3 = type_3(	\
			tnf_v_set_p.tpd_p, valarg_3,		\
			(tnf_record_p) &(tnf_v_probe_buffer->data_3)); \
		    tnf_v_probe_buffer->data_4 = type_4(	\
			tnf_v_set_p.tpd_p, valarg_4,		\
			(tnf_record_p) &(tnf_v_probe_buffer->data_4)); \
		    tnf_v_probe_buffer->data_5 = type_5(	\
			tnf_v_set_p.tpd_p, valarg_5,		\
			(tnf_record_p) &(tnf_v_probe_buffer->data_5)); \
		    (tnf_v_probe_p->probe_func)(&tnf_v_set_p);	\
		}						\
	}							\
}

#endif /* NPROBE */

/*
 * Debug Probe Macros (contain an additional "debug" attribute)
 */

#if defined(TNF_DEBUG)

/* CSTYLED */
#define	TNF_PROBE_0_DEBUG(namearg, keysarg, detail)	TNF_PROBE_0(namearg, keysarg, "debug;" detail)

#else

/* CSTYLED */
#define	TNF_PROBE_0_DEBUG(namearg, keysarg, detail) \
		((void)0)

#endif /* defined(TNF_DEBUG) */

#if defined(TNF_DEBUG)

/* CSTYLED */
#define	TNF_PROBE_1_DEBUG(namearg, keysarg, detail, type_1, namearg_1, valarg_1)	TNF_PROBE_1(namearg, keysarg, "debug;" detail, type_1, namearg_1, valarg_1)

#else

/* CSTYLED */
#define	TNF_PROBE_1_DEBUG(namearg, keysarg, detail, type_1, namearg_1, valarg_1) \
		((void)0)

#endif /* defined(TNF_DEBUG) */

#if defined(TNF_DEBUG)

/* CSTYLED */
#define	TNF_PROBE_2_DEBUG(namearg, keysarg, detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2)	TNF_PROBE_2(namearg, keysarg, "debug;" detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2)

#else

/* CSTYLED */
#define	TNF_PROBE_2_DEBUG(namearg, keysarg, detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2) \
		((void)0)

#endif /* defined(TNF_DEBUG) */

#if defined(TNF_DEBUG)

/* CSTYLED */
#define	TNF_PROBE_3_DEBUG(namearg, keysarg, detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2, type_3, namearg_3, valarg_3)	TNF_PROBE_3(namearg, keysarg, "debug;" detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2, type_3, namearg_3, valarg_3)

#else

/* CSTYLED */
#define	TNF_PROBE_3_DEBUG(namearg, keysarg, detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2, type_3, namearg_3, valarg_3) \
		((void)0)

#endif /* defined(TNF_DEBUG) */

#if defined(TNF_DEBUG)

/* CSTYLED */
#define	TNF_PROBE_4_DEBUG(namearg, keysarg, detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2, type_3, namearg_3, valarg_3, type_4, namearg_4, valarg_4)	TNF_PROBE_4(namearg, keysarg, "debug;" detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2, type_3, namearg_3, valarg_3, type_4, namearg_4, valarg_4)

#else

/* CSTYLED */
#define	TNF_PROBE_4_DEBUG(namearg, keysarg, detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2, type_3, namearg_3, valarg_3, type_4, namearg_4, valarg_4) \
		((void)0)

#endif /* defined(TNF_DEBUG) */

#if defined(TNF_DEBUG)

/* CSTYLED */
#define	TNF_PROBE_5_DEBUG(namearg, keysarg, detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2, type_3, namearg_3, valarg_3, type_4, namearg_4, valarg_4, type_5, namearg_5, valarg_5)	TNF_PROBE_5(namearg, keysarg, "debug;" detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2, type_3, namearg_3, valarg_3, type_4, namearg_4, valarg_4, type_5, namearg_5, valarg_5)

#else

/* CSTYLED */
#define	TNF_PROBE_5_DEBUG(namearg, keysarg, detail, type_1, namearg_1, valarg_1, type_2, namearg_2, valarg_2, type_3, namearg_3, valarg_3, type_4, namearg_4, valarg_4, type_5, namearg_5, valarg_5) \
		((void)0)

#endif /* defined(TNF_DEBUG) */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_TNF_PROBE_H */
