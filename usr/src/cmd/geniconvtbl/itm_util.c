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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 * Copyright 2015 PALO, Richard.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <libintl.h>
#include <strings.h>
#include "iconv_tm.h"
#include "itmcomp.h"
#include "itm_util.h"
#include "hash.h"
#include "maptype.h"


static size_t	map_table_resultlen(itmc_map_t *);
static int	data_pair_compare(itmc_data_pair_t **, itmc_data_pair_t **);
static long	data_to_long(itm_data_t *);

static itm_tbl_hdr_t	*map_table_indexed_fixed(itmc_data_pair_t **,
				itm_size_t, itm_data_t *, long, itm_num_t);
static itm_tbl_hdr_t	*map_table_dense_encoding(itmc_data_pair_t **,
				itm_size_t, itm_data_t *, unsigned long,
				unsigned char *, unsigned char *, long,
				itm_num_t);
static itm_tbl_hdr_t	*map_table_lookup_fixed(itmc_data_pair_t **,
				itm_size_t, itm_data_t *, long, itm_size_t);
static itm_tbl_hdr_t	*map_table_hash(itmc_data_pair_t **, itm_size_t,
				itm_data_t *, long, long, itm_size_t,
				itm_num_t);
static itm_tbl_hdr_t	*map_table_lookup_var();
static void		put_dense_encoding_default(char *, unsigned char *,
			unsigned char *, unsigned char *, long, long, long);
static size_t		map_table_resultlen(itmc_map_t *);
static void		map_range_adjust_byte_seq(unsigned char *,
				unsigned char *, long, itmc_data_pair_t *);
static void		map_range_make_result(char *, itm_size_t, itm_size_t,
				char *, itm_size_t);
static size_t		map_table_num_range(itmc_data_pair_t *);
static itmc_map_type_t	check_map_type(itmc_map_attr_t *);


static itmc_name_t	*name_lookup(itm_data_t *, itm_type_t);
static itmc_name_t	*name_refer(itm_data_t *, itm_type_t, itmc_ref_t *);
static itmc_name_t	*name_register(itm_data_t *, itm_type_t, itmc_ref_t *);
static void		op_hirarchy(itm_tbl_hdr_t *, itmc_obj_t *);
static obj_array_t	obj_list_to_array(itm_size_t, itmc_obj_t *, itm_size_t);


void
itm_def_process(itm_data_t	*itm_name)
{
	itm_hdr_t	*itm_hdr;
	long		len;

	TRACE_MESSAGE('y', ("itm_def_process\n"));


	itm_hdr = malloc_vital(sizeof (itm_hdr_t));
	(void) memset(itm_hdr, 0, sizeof (itm_hdr_t));

	if ((NULL != cmd_opt.interpreter) &&
	    (0 < (len = strlen(cmd_opt.interpreter)))) {
		itm_hdr->interpreter = *(str_to_data(len, cmd_opt.interpreter));
	}
	if ((sizeof (itm_place_t)) < itm_hdr->interpreter.size) {
		(void) obj_register(ITMC_OBJ_STRING, NULL,
		    (void *)itm_hdr->interpreter.place.itm_ptr,
		    itm_hdr->interpreter.size,
		    &(itm_hdr->interpreter.place),
		    OBJ_REG_HEAD);
	}

	itm_hdr->type_id = *itm_name;
	if ((sizeof (itm_place_t)) < itm_hdr->type_id.size) {
		(void) obj_register(ITMC_OBJ_STRING, NULL,
		    (void *)itm_hdr->type_id.place.itm_ptr,
		    itm_hdr->type_id.size,
		    &(itm_hdr->type_id.place),
		    OBJ_REG_HEAD);
	}

	(void) assemble(itm_hdr);
}



itmc_obj_t *
direction_unit(
	itmc_ref_t	*cond,
	itm_data_t	*cond_name,
	itmc_action_t	*act,
	itm_data_t	*act_name)
{
	itmc_obj_t	*du;
	itm_direc_t	*direc;

	du = malloc_vital(sizeof (itmc_obj_t));
	du->type = ITMC_OBJ_DIREC;
	du->name = NULL;
	du->obj = direc = malloc_vital(sizeof (itm_direc_t));

	if (NULL != cond) {
		direc->condition.itm_ptr = (uintptr_t)NULL;
		cond->referencer = &(direc->condition);
		du->ref[0] = cond;
	} else if (NULL != cond_name) {
		direc->condition.itm_ptr = (itm_place2_t)(cond_name);
		du->ref[0] = obj_register(ITMC_OBJ_COND, cond_name, NULL, 0,
		    &(direc->condition), OBJ_REG_TAIL);
	} else {
		direc->condition.itm_ptr = 0;
		du->ref[0] = NULL;
	}


	if (NULL != act_name) {
		direc->action.itm_ptr = (itm_place2_t)(act_name);
		du->ref[1] = obj_register(ITMC_OBJ_ACTION, act_name, NULL, 0,
		    &(direc->action), OBJ_REG_TAIL);
	} else if (NULL != act && act->tbl_hdr != NULL) {
		direc->action.itm_ptr = (itm_place2_t)(act->tbl_hdr);
		du->ref[1] = obj_register(act->type,
		    (itm_data_t *)(act->tbl_hdr->name.itm_ptr),
		    act->tbl_hdr, act->tbl_hdr->size,
		    &(direc->action), OBJ_REG_TAIL);
	} else {
		return (NULL);
	}

	du->ref[2] = NULL;
	return	(du);
}



itm_tbl_hdr_t *
obj_table(itm_type_t	tbl_type,
	itm_data_t	*name,
	itmc_obj_t	*obj_list,
	itm_size_t	obj_size)
{
	itm_tbl_hdr_t	*tbl;
	obj_array_t	obj_array;

	obj_array = obj_list_to_array(sizeof (itm_tbl_hdr_t),
	    obj_list, obj_size);
	tbl = obj_array.obj;

	tbl->type = tbl_type;
	if (name) {
#if !defined(_LP64)
		tbl->name.itm_pad = 0;
#endif
		tbl->name.itm_ptr = (itm_place2_t)name;
	} else {
#if !defined(_LP64)
		tbl->name.itm_pad = 0;
#endif
		tbl->name.itm_ptr = (uintptr_t)NULL;
	}
	tbl->size = (sizeof (itm_tbl_hdr_t)) + (obj_array.num	*obj_size);
	tbl->number = obj_array.num;

	if ((ITM_TBL_MASK&tbl->type) == ITM_TBL_OP) {
		op_hirarchy(tbl, obj_list);
	}
	return	(tbl);
}

/*
 *
 */
static obj_array_t
obj_list_to_array(itm_size_t hdr_size, itmc_obj_t	*obj_list,
			itm_size_t size)
{
	obj_array_t	obj_array;
	itm_size_t	offset;
	itmc_obj_t	*ol;

	for (obj_array.num = 0, ol = obj_list;
	    ol; obj_array.num += 1, ol = ol->next) {
		/* NOP */;
	}

	obj_array.obj = malloc_vital(hdr_size + (size * obj_array.num));

	if (obj_array.num == 0)
		return	(obj_array);

	for (offset = hdr_size, ol = obj_list;
	    ol; offset += size, ol = ol->next) {
		(void) memcpy((char *)(obj_array.obj) + offset, ol->obj, size);
		if (ol->ref[0]) {
			ol->ref[0]->referencer =
			    (void *)((char *)(ol->ref[0]->referencer) +
			    ((char *)(obj_array.obj) -
			    (char *)(ol->obj) + offset));
		}
		if (ol->ref[1]) {
			ol->ref[1]->referencer =
			    (void *)((char *)(ol->ref[1]->referencer) +
			    ((char *)(obj_array.obj) -
			    (char *)(ol->obj) + offset));
		}
		if (ol->ref[2]) {
			ol->ref[2]->referencer =
			    (void *)((char *)(ol->ref[2]->referencer) +
			    ((char *)(obj_array.obj) -
			    (char *)(ol->obj) + offset));
		}
	}

	return	(obj_array);
}

static void
op_hirarchy(itm_tbl_hdr_t	*optbl,
	itmc_obj_t		*obj_list)
{
	itm_op_outer_t	*o;
	itm_op_inner_t	*in;
	itmc_obj_t	*ol;

	TRACE_MESSAGE('l', ("op_hirarchy (optbl=%x)\n", optbl));
	o = malloc_vital(sizeof (itm_op_outer_t));
	o->link = itm_op_outer;
	itm_op_outer = o;
	o->in = NULL;
	o->optbl = optbl;

	for (ol = obj_list; ol != NULL; ol = ol->next) {
		if ((ol->type == ITMC_OBJ_OP) &&
		    (((itm_op_t *)ol->obj)->type == ITM_OP_OPERATION)) {
			in = malloc_vital(sizeof (itm_op_inner_t));
			in->in = o->in;
			o->in = in;
			TRACE_MESSAGE('L', ("o->in(%x) in->in(%x)\n",
			    o->in, in->in));
			in->ref = ol->ref[0];
		}
	}

#ifdef ENABLE_TRACE
	for (in = o->in; in != NULL; in = in->in) {
		TRACE_MESSAGE('L', ("o=%x in=%x in->in=%x\n",
		    o, in, in->in));
		TRACE_MESSAGE('L', ("o(table)%x->in(ref)=%x\n",
		    o->optbl, in->ref));
	}
#endif

}

itmc_obj_t *
obj_list_append(itmc_obj_t	*obj_list, itmc_obj_t	*obj)
{
	if (0 == obj) {
		return	(obj_list);
	}

	obj->next = NULL;
	obj->last = obj;

	if (obj_list) {
		obj_list->last->next = obj;
		obj_list->last = obj;
		return	(obj_list);
	} else {
		return	(obj);
	}
}


itmc_ref_t *
obj_register(itm_type_t type, itm_data_t	*name,
		void	*obj, size_t size, itm_place_t	*ref,
		itm_type_t reg_place)
{
	itmc_ref_t	*refp;

	TRACE_MESSAGE('O', ("obj_register: %6ld %08p %08p %08ld %08p %ld\n",
	    type, name, obj, size, ref, reg_place));

	refp = malloc_vital(sizeof (itmc_ref_t));
	refp->name = NULL;
	refp->referencee = obj;
#if !defined(_LP64)
	refp->reloc.itm_pad = 0;
#endif
	refp->reloc.itm_ptr = 0;
	refp->size = size;
	refp->referencer = ref;
	refp->next = NULL;

	if (NULL == obj) { /* reference to named object */
		if (NULL == name) {
			if (0 == error_deferred) {
				/* should never happen */
				itm_error(
				    gettext("internal error: "
				    "obj_register: (NULL == obj) "
				    "&& (NULL == name)\n"));
				exit(ITMC_STATUS_SYS2);
			}
			return (NULL);
		}
		refp->name = name_refer(name, type, refp);
		return	(refp);
	} else if ((NULL != name) && (0 < name->size)) {
		/* definition of named object */
		refp->name = name_register(name, type, refp);
	}

	if ((ITMC_OBJ_FIRST <= type) && (type <= ITMC_OBJ_LAST)) {
		switch (reg_place) {
		case OBJ_REG_HEAD:
			refp->next = ref_first[type];
			ref_first[type] = refp;
			if (NULL == ref_last[type]) {
				ref_last[type] = refp;
			}
			break;
		case OBJ_REG_TAIL:
			if (ref_first[type]) {
				ref_last[type]->next = refp;
			} else {
				ref_first[type] = refp;
			}
			ref_last[type] = refp;
			break;
		}
	} else {
		itm_error(gettext("obj_register: illegal object type\n"));
		exit(ITMC_STATUS_SYS2);
	}

	return	(refp);
}


itm_tbl_hdr_t *
range_table(itm_data_t		*name, itmc_obj_t	*obj_list)
{
	itm_num_t		num;
	itmc_obj_t		*ol;
	itmc_data_pair_t	*rp;
	itm_range_hdr_t		*rh;
	itm_tbl_hdr_t		*table;
	itm_size_t		length = 0;
	itm_num_t		i;
	char			*p;
	itm_size_t		table_size;

	/* count range, determine length */
	for (num = 0, ol = obj_list; ol; ol = ol->next, num++) {
		rp = (itmc_data_pair_t *)(ol->obj);
		if (length == 0) {
			if (rp->data0.size == 0) {
				itm_error(gettext("between has null range\n"));
				error_deferred += 1;
				return	(NULL);
			}
			length = rp->data0.size;
		}
		if ((rp->data0.size != length) ||
		    (rp->data1.size != length)) {
			itm_error(gettext(
			    "length of source sequences must be the same\n"));
			error_deferred += 1;
			return	(NULL);
		}
	}
	if (num == 0) {
		itm_error(gettext("between has no ranges\n"));
		error_deferred += 1;
		return	(NULL);
	}
	table_size = ((sizeof (itm_tbl_hdr_t)) +
	    (sizeof (itm_range_hdr_t)) + (length * num) * 2);
	table_size = ITMROUNDUP(table_size);

	table = malloc_vital(table_size);
	table->type = ITM_TBL_RANGE;
	if (NULL != name)
		table->name.itm_ptr = (itm_place2_t)name;
	table->size = table_size;
	table->number = num;

	rh = (itm_range_hdr_t *)(table + 1);
	rh->len = length;

	p = (char *)(rh + 1);
	for (ol = obj_list, i = 0; ol; ol = ol->next, i++) {
		rp = (itmc_data_pair_t *)(ol->obj);
		(void) memcpy(p, (NSPTR(&(rp->data0))), length);
		p += length;
		(void) memcpy(p, (NSPTR(&(rp->data1))), length);
		p += length;
	}

	return	(table);
}

/*
 *	escape sequence table for stateful code set sequence
 */
itm_tbl_hdr_t *
escseq_table(itm_data_t		*name, itmc_obj_t	*obj_list)
{
	itm_num_t		num;
	itmc_obj_t		*ol;
	itm_data_t		*ep;
	itm_escapeseq_hdr_t	*eh;
	itm_tbl_hdr_t		*table;
	itm_size_t		len_max = 0;
	itm_size_t		len_min;
	itm_num_t		i;
	itm_size_t		table_size;

	ol = obj_list;
	len_min = ((itm_data_t *)(ol->obj))->size;
	for (num = 0; NULL != ol; ol = ol->next, num++) {
		ep = (itm_data_t *)(ol->obj);
		if (ep->size < len_min)	 len_min = ep->size;
		if (ep->size > len_max)	 len_max = ep->size;
	}
	if (num == 0) {
		itm_error(gettext
		    ("escape sequence is defined without sequence\n"));
		error_deferred += 1;
		return	(NULL);
	} else if (0 == len_min) {
		itm_error(gettext("null sequence\n"));
		error_deferred += 1;
		return	(NULL);
	}

	table_size = ((sizeof (itm_tbl_hdr_t)) +
	    (sizeof (itm_escapeseq_hdr_t)) +
	    (sizeof (itm_data_t) * num));
	table_size = ITMROUNDUP(table_size);
	table = malloc_vital(table_size);
	table->type = ITM_TBL_ESCAPESEQ;
	if (NULL != name)
		table->name.itm_ptr = (itm_place2_t)name;
	table->size = table_size;
	table->number = num;

	eh = (itm_escapeseq_hdr_t *)(table + 1);
	eh->len_max = len_max;
	eh->len_min = len_min;

	for (ol = obj_list, ep = (itm_data_t *)(eh + 1);
	    ol != NULL;
	    ol = ol->next, ep++) {
		*ep = *((itm_data_t *)(ol->obj));
		if ((sizeof (itm_place_t)) < ep->size) {
			(void) obj_register(ITMC_OBJ_DATA, NULL,
			    (void *)(ep->place.itm_ptr), ep->size,
			    &(ep->place), OBJ_REG_TAIL);
		}
	}
	(void) qsort((itm_data_t *)(eh + 1), num, sizeof (itm_data_t),
	    (int (*)(const void *, const void *))data_compare);

	for (i = 0, ep = (itm_data_t *)(eh + 1);
	    i < num - 1;
	    i++, ep++) {
		if (0 <= data_compare(ep, (ep + 1))) {
			itm_error(
			    gettext(
			    "same escape sequences are defined: "
			    "0x%1$s 0x%2$s\n"),
			    data_to_hexadecimal(ep),
			    data_to_hexadecimal(ep + 1));
			error_deferred += 1;
			return	(NULL);
		}
	}
	return	(table);
}




itm_tbl_hdr_t *
map_table(itm_data_t	*name, itmc_map_t	*map_list,
		itmc_map_attr_t *attr)
{
	itm_size_t		num;
	itm_size_t		num2;
	itmc_map_t		*ml;
	itmc_data_pair_t	**tpp;
	itm_tbl_hdr_t		*table;
	long			source_len = 0;
	long			result_len = 0;
	long			source_fixed_len = 1;
	long			pass_through = 0;
	long			default_count = 0;
	itm_data_t		*default_data = NULL;
	long			error_deferred_local = 0;
	unsigned long		dense_encoded_map_ent;
	unsigned long		simple_indexed_map_ent;
	itm_size_t		source_start;
	itm_size_t		source_end;
	unsigned long		u;
	unsigned char		*byte_seq_min;
	unsigned char		*byte_seq_max;
	unsigned char		*p;
	long			i;
	itmc_map_type_t		map_type = ITMC_MAP_UNKNOWN;
	itmc_map_name_type_t	*map_name_type;
	long			hash_factor;
	long			result_len_specfied = 0;
	size_t			j;
	long			n;
	itmc_data_pair_t	**dp1;
	itm_num_t		error_count = 0;

	if (attr != NULL) {
		map_type = check_map_type(attr);
	}
	if (ITMC_MAP_UNKNOWN == map_type) {
		map_type = ITMC_MAP_AUTOMATIC;
	}
	hash_factor = ((NULL != attr) && (attr->hash_factor != 0)) ?
	    attr->hash_factor :
	    200;

	map_name_type = cmd_opt.map_name_type;
	for (; map_name_type; map_name_type = map_name_type->next) {
		if ('\0' == *(map_name_type->name)) {
			map_type = map_name_type->type;
			hash_factor = map_name_type->hash_factor;
			break;
		}
	}
	map_name_type = cmd_opt.map_name_type;
	if ((NULL != name) && (NULL != cmd_opt.map_name_type)) {
		p = NSPTR(name);
		for (; map_name_type; map_name_type = map_name_type->next) {
			if (0 == strcmp(map_name_type->name, (char *)p)) {
				map_type = map_name_type->type;
				hash_factor = map_name_type->hash_factor;
				break;
			}
		}
	}

	if (NULL != attr) {
		if (MAXSEQUENCE < attr->resultlen) {
			itm_error(
			gettext("output_byte_length must be less than %1$d\n"),
			    MAXSEQUENCE);
			error_deferred += 1;
			return	(NULL);
		}
		result_len_specfied = attr->resultlen;
	} else {
		result_len_specfied = 0;
	}

	for (num = 0, ml = map_list; ml; ml = ml->next, num++) {

		/* default */
		if (0 == ml->data_pair.data0.size) {
			if (0 == ml->data_pair.data1.size) {
				pass_through += 1;
				default_data = (itm_data_t *)(-1);
			} else {
				default_count += 1;
				default_data = &(ml->data_pair.data1);
			}
			--num;


		} else if (0 == ml->data_pair.data1.size) {
			/* error source sequence */
			continue;
		}

		/* fixed length */
		if ((0 < source_len) &&
		    (0 < ml->data_pair.data0.size) &&
		    (source_len != ml->data_pair.data0.size)) {
			source_fixed_len = 0;
		}

		/* maximum length */
		if (source_len < ml->data_pair.data0.size) {
			source_len = ml->data_pair.data0.size;
		}
		if (result_len < ml->data_pair.data1.size) {
			result_len = ml->data_pair.data1.size;
		}

		/* map source has range */
		if (0 < ml->data_pair.range.size) {
			if (ml->data_pair.range.size !=
			    ml->data_pair.data0.size) {
				itm_error(
				    gettext("length of source range must be "
				    "the same: 0x%1$s 0x%2$s\n"),
				    data_to_hexadecimal(&(ml->data_pair.data0)),
				    data_to_hexadecimal(
				    &(ml->data_pair.range)));
				error_deferred += 1;
				return	(NULL);
			}
			if (0 <= data_compare(&(ml->data_pair.data0),
			    &((ml->data_pair.range)))) {
				itm_error(
				gettext("source range error: 0x%1$s 0x%2$s\n"),
				    data_to_hexadecimal(
				    &(ml->data_pair.data0)),
				    data_to_hexadecimal(
				    &(ml->data_pair.range)));
				error_deferred += 1;
				return	(NULL);
			}
			j = map_table_resultlen(ml);
			if (result_len < j) {
				result_len = j;
			}
		}
	}
	if (num == 0) {
		itm_error(
		    gettext("no mapping pair\n"));
		error_deferred += 1;
		return	(NULL);
	}

	if (0 != result_len_specfied) {
		if (result_len > result_len_specfied) {
			itm_error(
			    gettext("result value length is "
			    "over specifed output_byte_length(%1$ld)\n"),
			    result_len_specfied);
			error_deferred += 1;
			return	(NULL);
		}
		result_len = result_len_specfied;
	}
	byte_seq_min = malloc_vital((sizeof (unsigned char)) * source_len);
	byte_seq_max = malloc_vital((sizeof (unsigned char)) * source_len);
	for (num = 0, ml = map_list; ml; ml = ml->next, num++) {
		if (0 == ml->data_pair.data0.size) {
			continue;
		}

		p = (unsigned char *)(NSPTR(&((ml->data_pair).data0)));
		for (i = 0; i < source_len; i++) {
			*(byte_seq_min + i) = *(p + i);
			*(byte_seq_max + i) = *(p + i);
		}
		break;
	}
	for (num = 0, ml = map_list; ml; ml = ml->next, num++) {
		if (0 == ml->data_pair.data0.size) {
			num--;
			continue;
		}
		if (ml->data_pair.range.size > 0) {
			map_range_adjust_byte_seq(byte_seq_min, byte_seq_max,
			    source_len, &(ml->data_pair));
		} else {
			p = (unsigned char *)(NSPTR(&((ml->data_pair).data0)));
			for (i = 0; i < source_len; i++) {
				if (*(p + i) < *(byte_seq_min + i)) {
					*(byte_seq_min + i) = *(p + i);
				}
				if (*(byte_seq_max + i) < *(p + i)) {
					*(byte_seq_max + i) = *(p + i);
				}
			}
		}
	}
	for (dense_encoded_map_ent = 1, i = 0; i < source_len; i++) {
		u = dense_encoded_map_ent;
		dense_encoded_map_ent *=
		    (*(byte_seq_max + i) - *(byte_seq_min + i) + 1);
		if (dense_encoded_map_ent < u) {
			dense_encoded_map_ent = (ulong_t)(~0);
			break;
		}
	}
#if defined(DEBUG)
	if (TRACE('m')) {
		int	i;
		TRACE_MESSAGE('m', ("map_table: ent=%lu num=%lu	",
		    dense_encoded_map_ent, num));
		TRACE_MESSAGE('m', ("byte_seq_min=0x"));
		for (i = 0; i < source_len; i++) {
			TRACE_MESSAGE('m', ("%02x", *(byte_seq_min + i)));
		}
		TRACE_MESSAGE('m', ("  byte_seq_max=0x"));
		for (i = 0; i < source_len; i++) {
			TRACE_MESSAGE('m', ("%02x", *(byte_seq_max + i)));
		}
		TRACE_MESSAGE('m', ("\n"));
	}
#endif /* DEBUG */

	tpp = malloc_vital((sizeof (itmc_data_pair_t *)) * num);
	for (num = 0, num2 = 0, ml = map_list; ml; ml = ml->next) {
		if (0 < ml->data_pair.data0.size) {
			itm_num_t range_num;
			*(tpp + num) = &(ml->data_pair);
			num++;
			range_num = 1;
			if (ml->data_pair.range.size > 0) {
				range_num +=
				    map_table_num_range(&(ml->data_pair));
			}
			num2 += range_num;
			if (0 == ml->data_pair.data1.size) {
				/* specified error sequence */
				error_count += range_num;
			}
		}
	}
	(void) qsort(tpp, num, sizeof (itmc_data_pair_t *),
	    (int (*)(const void *, const void *))data_pair_compare);

	/* check if map_pair range and next map_pair are overrapped */
	for (n = 0, dp1 = tpp; n < (num-1); n++, dp1++) {
		if (((*(dp1+0))->range.size != 0) &&
		    (0 <= data_compare(&((*(dp1+0))->range),
		    &((*(dp1+1))->data0)))) {
			itm_error(
			    gettext("ranges of source sequences "
			    "overrapped: %1$s %2$s\n"),
			    data_to_hexadecimal(&((*(dp1+0))->range)),
			    data_to_hexadecimal(&((*(dp1+1))->data0)));
			error_deferred += 1;
			return	(NULL);
		}
	}

	if (1 < default_count) {
		itm_error(
		    gettext("default is specified %1$d times in a map\n"),
		    default_count);
		error_deferred_local += 1;
	}
	if ((1 == default_count) && (!source_fixed_len)) {
		itm_error(
		    gettext("default is specified,"
		    " but length of source data is not fixed\n"));
		error_deferred_local += 1;
	}
	if ((1 <= pass_through) && (source_len != result_len)) {
		itm_error(
		    gettext("\"default no_change_copy\" is "
		    "specified, but size does not match\n"));
		error_deferred_local += 1;
	}

	if (error_deferred_local) {
		error_deferred += error_deferred_local;
		return	(NULL);
	}

	if (source_fixed_len) {
		source_start = data_to_long(&((*(tpp + 0))->data0));
		source_end = data_to_long(&((*(tpp + num - 1))->data0));
		if (0 < (*(tpp + num - 1))->range.size) {
			source_end = data_to_long(&((*(tpp + num - 1))->range));
		}

		simple_indexed_map_ent = source_end - source_start + 1;

		TRACE_MESSAGE('m', ("map_table: simple_indexed_map_ent=%lu\n",
		    simple_indexed_map_ent));

		switch (map_type) {
		case ITMC_MAP_AUTOMATIC:
			if ((source_len <= 2) &&
			    (((ulong_t)(~0) == dense_encoded_map_ent) ||
			    (simple_indexed_map_ent <
			    (dense_encoded_map_ent * 2)))) {
				/*
				 * for small source sequence,
				 * if dense table is not so large
				 * compared with simple table,
				 * use simple.
				 */
				map_type = ITMC_MAP_SIMPLE_INDEX;
			} else if (cmd_opt.large_table) {
				if ((sizeof (long)) < source_len) {
					itm_error(
					gettext("length of source is too long "
					    "for large table: %ld\n"),
					    source_len);
					error_deferred += 1;
					return	(NULL);
				}
				map_type = ITMC_MAP_SIMPLE_INDEX;
			} else if (((ulong_t)(~0) == dense_encoded_map_ent) ||
			    ((0xffff < dense_encoded_map_ent) &&
			    ((num2 * 8) < dense_encoded_map_ent))) {
				/*
				 * if dense can be used and not too large
				 * ( less than (hash table entry * 8),
				 * use dense.
				 */
				map_type = ITMC_MAP_SIMPLE_HASH;
			} else {
				map_type = ITMC_MAP_DENSE_ENCODING;
			}
			break;
		case ITMC_MAP_SIMPLE_INDEX:
			if ((sizeof (long)) < source_len) {
				itm_error(
				gettext("length of source is too long "
				    "for index lookup: %ld\n"),
				    source_len);
				error_deferred += 1;
				return	(NULL);
			}
			break;
		case ITMC_MAP_SIMPLE_HASH:
			for (i = 2, u = 256; i < (sizeof (long)); i++) {
				u *= 256;
			}
			if (u < num2) {
				itm_error(
				gettext("map is too large for hashing: %lu\n"),
				    num2);
				error_deferred += 1;
				return	(NULL);
			}
			break;
		case ITMC_MAP_DENSE_ENCODING:
			for (i = 2, u = 256; i < (sizeof (long)); i++) {
				u *= 256;
			}
			if (u < dense_encoded_map_ent) {
				itm_error(
				    gettext(
				    "map is too large for dense encoding: "
				    "%lu\n"),
				    dense_encoded_map_ent);
				error_deferred += 1;
				return	(NULL);
			}
			break;
		case ITMC_MAP_BINARY_SEARCH:
			for (i = 2, u = 256; i < (sizeof (long)); i++) {
				u *= 256;
			}
			if (u < num2) {
				itm_error(
				gettext("length of source is too long for "
				    "binary search: %ld\n"),
				    source_len);
				error_deferred += 1;
				return	(NULL);
			}
			break;
		default:
			break;
		}
		switch (map_type) {
		case ITMC_MAP_SIMPLE_INDEX:
			table = map_table_indexed_fixed(
			    tpp, num, default_data,
			    result_len, error_count);
			break;
		case ITMC_MAP_SIMPLE_HASH:
			table = map_table_hash(tpp, num, default_data,
			    hash_factor, result_len, num2,
			    error_count);
			break;
		case ITMC_MAP_DENSE_ENCODING:
			table = map_table_dense_encoding(tpp, num,
			    default_data,
			    dense_encoded_map_ent,
			    byte_seq_min, byte_seq_max,
			    result_len, error_count);
			break;
		case ITMC_MAP_BINARY_SEARCH:
			table = map_table_lookup_fixed(tpp, num,
			    default_data,
			    result_len, num2);
			break;
		}
	} else {
		table = map_table_lookup_var();
	}

	if ((NULL != name) && (NULL != table)) {
		table->name.itm_ptr = (itm_place2_t)name;
	}

	return	(table);
}


static itmc_map_type_t
check_map_type(itmc_map_attr_t *attr)
{
	int i;

	if (NULL == attr->type) {
		return (0);
	}
	for (i = 0; NULL != map_type_name[i].name; i++) {
		if (0 == strncmp(((char *)&(attr->type->place)),
		    map_type_name[i].name, attr->type->size)) {
			return (map_type_name[i].type);
		}
	}
	return (0);
}


static itm_tbl_hdr_t *
map_table_indexed_fixed(
	itmc_data_pair_t	**tpp,
	itm_size_t		num,
	itm_data_t		*default_data,
	long			resultlen,
	itm_num_t		error_count)
{
	itm_tbl_hdr_t		*header;
	itm_map_idx_fix_hdr_t	*sub_hdr;
	char			*table;
	char			*error_table;
	itm_size_t		source_start;
	itm_size_t		source_end;
	itm_size_t		entry_num;
	itm_size_t		table_size;
	itm_size_t		j;
	itm_size_t		i;
	itm_size_t		k;
	char			*p;
	itm_data_t		*source;

	TRACE_MESSAGE('m', ("map_table_range : %ld\n", num));

	source = &((*(tpp + 0))->data0);
	assert((sizeof (itm_place_t)) >= source->size);

	if ((1 == source->size) &&
	    (1 == resultlen)) {
		source_start = 0;
		source_end = 255;
	} else {
		source_start = data_to_long(&((*(tpp + 0))->data0));
		source_end = data_to_long(&((*(tpp + num - 1))->data0));
		if (0 < (*(tpp + num - 1))->range.size)
			source_end = data_to_long(&((*(tpp + num - 1))->range));
	}

	entry_num = source_end - source_start + 1;

	table_size = ((sizeof (itm_tbl_hdr_t)) +
	    (sizeof (itm_map_idx_fix_hdr_t)) +
	    (resultlen * entry_num));
	if (0 < error_count) {
		table_size += entry_num;
	}
	if (NULL == default_data) {
		if ((num < entry_num) ||
		    (error_count <= 0)) {
			table_size += entry_num;
		}
	} else if ((itm_data_t *)(-1) != default_data) {
		table_size += resultlen;
	}

	table_size = ITMROUNDUP(table_size);
	header = malloc_vital(table_size);
	sub_hdr = (itm_map_idx_fix_hdr_t *)(header + 1);
	table = (char *)(sub_hdr + 1);

	if ((1 == (*tpp)->data0.size) &&
	    (1 == (*tpp)->data1.size)) {
		header->type = ITM_TBL_MAP_INDEX_FIXED_1_1;
	} else {
		header->type = ITM_TBL_MAP_INDEX_FIXED;
	}
	header->name.itm_ptr = 0;
	header->size = table_size;
	header->number = entry_num;

	sub_hdr->source_len = (*tpp)->data0.size;
	sub_hdr->result_len = resultlen;
	sub_hdr->start.itm_ptr = source_start;
	sub_hdr->end.itm_ptr = source_end;
	sub_hdr->error_num = error_count; /* > 0; so pad4 = 0 */

	if (NULL != default_data) {
		if ((itm_data_t *)(-1) == default_data) {
			sub_hdr->default_error = -1;
#if !defined(_LP64)
			sub_hdr->pad3_num = (pad_t)(~0);
#endif
		} else {
			sub_hdr->default_error = 0;
		}
	} else {
		if (num < entry_num) {
			sub_hdr->default_error = 1;
		} else {
			sub_hdr->default_error = 2;
		}
	}

	error_table = (table + (resultlen * entry_num));
	if (-1 == sub_hdr->default_error) {
		if (source->size != resultlen) {
			itm_error(
			    gettext("\"default no_change_copy\" is "
			    "specified, but size does not match\n"));
			exit(ITMC_STATUS_BT);
		}

		for (i = 0, j = 0;
		    i < (entry_num);
		    i++, j += resultlen) {
			for (k = 0; k < resultlen; k++) {
				*(table + j + k) =
				    (((source_start + i) >>
				    ((resultlen - k - 1) * 8)) &
				    0x00ff);
			}
		}
	} else if (0 == sub_hdr->default_error) {
		error_table += resultlen;
		if (default_data->size <= (sizeof (itm_place_t))) {
			for (i = 0, j = 0;
			    i < (entry_num + 1); /* last one is for default */
			    i++, j += resultlen) {
				(void) memcpy(table + j +
				    (resultlen - default_data->size),
				    (void *)(&(default_data->place.itm_64d)),
				    default_data->size);
			}
		} else {
			for (i = 0, j = 0;
			    i < (entry_num + 1); /* last one is for default */
			    i++, j += resultlen) {
				(void) memcpy(table + j +
				    (resultlen - default_data->size),
				    (void *)(default_data->place.itm_ptr),
				    default_data->size);
			}
		}
	}
	if (1 == sub_hdr->default_error) {
		(void) memset(error_table, 1, entry_num);
		for (i = 0; i < num; i++) {
			if (0 == (*(tpp + i))->data1.size) {
				continue; /* error sequence */
			}
			j = data_to_long(&((*(tpp + i))->data0)) -
			    source_start;
			k = ((*(tpp + i))->range.size) == 0 ? j :
			    data_to_long(&((*(tpp + i))->range)) -
			    source_start;
			for (; j <= k; j++) {
				*(error_table + j) = 0;
			}
		}
	} else if (0 < error_count) {
		(void) memset(error_table, 0, entry_num);
		for (i = 0; i < num; i++) {
			if (0 == (*(tpp + i))->data1.size) {
				/* error sequence */
				j = data_to_long(&((*(tpp + i))->data0)) -
				    source_start;
				k = ((*(tpp + i))->range.size) == 0 ? j :
				    data_to_long(&((*(tpp + i))->range)) -
				    source_start;
				for (; j <= k; j++) {
					*(error_table + j) = 1;
				}
			}
		}
	}

	p = malloc_vital(sizeof (uchar_t *) * resultlen);
	for (i = 0; i < num; i++) {
		j = data_to_long(&((*(tpp + i))->data0)) - source_start;
		if (0 != (*(tpp + i))->range.size)
			k = data_to_long(&((*(tpp + i))->range)) -
			    source_start;
		else
			k = j;
		(void) memset(p, 0, sizeof (uchar_t *) * resultlen);
		(void) memcpy(p + (resultlen  - (*(tpp + i))->data1.size),
		    ((caddr_t)NSPTR(&((*(tpp + i))->data1))),
		    (*(tpp + i))->data1.size);
		map_range_make_result(table, j, k, p, resultlen);
	}
	free(p);

	return	(header);
}




static itm_tbl_hdr_t *
map_table_lookup_fixed(
	itmc_data_pair_t	**tpp,
	itm_size_t		num,
	itm_data_t		*default_data,
	long			resultlen,
	itm_size_t		num2)
{
	itm_tbl_hdr_t		*header;
	itm_map_lookup_hdr_t	*sub_hdr;
	char			*table;
	itm_size_t		table_size;
	itm_size_t		j;
	itm_size_t		i;
	itm_size_t		k;
	itm_size_t		h;
	itm_data_t		*source;
	uchar_t			*source_data;
	uchar_t			*result_data;

	TRACE_MESSAGE('m', ("map_table_lookup_fixed : %ld(%ld) 0x%lx\n",
	    num, num2, default_data));

	source = &((*(tpp + 0))->data0);

	table_size = ((sizeof (itm_tbl_hdr_t)) +
	    (sizeof (itm_map_idx_fix_hdr_t)) +
	    ((source->size + 1 + resultlen) * num2));
	if ((NULL != default_data) &&
	    (((itm_data_t *)(-1)) != default_data)) {
		table_size += (source->size + 1 + resultlen);
	}
	table_size = ITMROUNDUP(table_size);
	header = malloc_vital(table_size);
	sub_hdr = (itm_map_lookup_hdr_t *)(header + 1);
	table = (char *)(sub_hdr + 1);

	header->type = ITM_TBL_MAP_LOOKUP;
	header->name.itm_ptr = 0;
	header->size = table_size;
	header->number = num2;
	if (NULL != default_data) {
		if ((itm_data_t *)(-1) == default_data) {
#if !defined(_LP64)
			sub_hdr->pad3_num = (pad_t)(~0);
#endif
			sub_hdr->default_error = -1;
		} else {
			sub_hdr->default_error = 0;
		}
	} else {
		sub_hdr->default_error = 2;
	}

	sub_hdr->source_len = source->size;
	sub_hdr->result_len = resultlen;

	/* specified map */
	source_data = malloc_vital(source->size);
	result_data = malloc_vital(resultlen);
	for (i = 0, j = 0; i < num; i++) {
		(void) memcpy(table + j,
		    NSPTR(&((*(tpp + i))->data0)), source->size);
		j += source->size;
		if (0 == (*(tpp + i))->data1.size) {
			*(table + j) = 1; /* specified error */
			j += 1;
		} else {
			/* *(table + j) = 0; ** valid */
			j += 1;
			(void) memcpy(table + j +
			    (resultlen  - (*(tpp + i))->data1.size),
			    NSPTR(&((*(tpp + i))->data1)),
			    (*(tpp + i))->data1.size);
		}
		j += resultlen;

		if ((*(tpp + i))->range.size != 0) {
			(void) memcpy(source_data,
			    NSPTR(&((*(tpp + i))->data0)),
			    source->size);
			(void) memset(result_data, 0, resultlen);
			(void) memcpy(result_data +
			    (resultlen  - (*(tpp + i))->data1.size),
			    NSPTR(&((*(tpp + i))->data1)),
			    (*(tpp + i))->data1.size);
			h = map_table_num_range((*(tpp + i)));
			for (k = 0; k < h; k++) {
				uchar_t		*dp;
				itm_size_t	m;

				for (m = 0,
				    dp = (uchar_t *)
				    (source_data + source->size - 1);
				    m < source->size;
				    m++, dp--) {
					if (0xff != *dp) {
						(*dp) += (char)1;
						for (++dp; m > 0; m--, dp++) {
							(*dp) = 0x00;
						}
						break;
					}
				}
				(void) memcpy(table + j,
				    source_data, source->size);
				j += source->size;

				if (0 == (*(tpp + i))->data1.size) {
					*(table + j) = 1; /* specified error */
					j += 1;
				} else {
					/* *(table + j) = 0; ** valid */
					j += 1;
					for (m = 0, dp = (uchar_t *)
					    (result_data + resultlen - 1);
					    m < resultlen;
					    m++, dp--) {
						if (0xff != *dp) {
							(*dp) += 1;
							for (++dp;
							    m > 0;
							    m--, dp++) {
								(*dp) = 0x00;
							}
							break;
						}
					}
					(void) memcpy(table + j, result_data,
					    resultlen);
				}
				j += resultlen;
			}
		}
	}
	free(source_data);
	free(result_data);

	/* default */
	if ((NULL != default_data) &&
	    (((itm_data_t *)(-1)) != default_data)) {
		(void) memset(table + j, 0, source->size + 1 + resultlen);
		(void) memcpy(table + j + source->size + 1 +
		    (resultlen  - default_data->size),
		    NSPTR(default_data), default_data->size);
	}
	return	(header);
}




static itm_tbl_hdr_t *
map_table_hash(
	itmc_data_pair_t	**tpp,
	itm_size_t		num,
	itm_data_t		*default_data,
	long			hash_factor,
	long			resultlen,
	itm_size_t		num2,
	itm_num_t		error_count)
{
	itm_tbl_hdr_t		*header;
	itm_map_hash_hdr_t	*sub_hdr;
	itm_size_t		table_size;
	char			*error_table;
	char			*hash_table;
	itm_size_t		hash_table_num;
	char			*of_table;
	itm_size_t		of_table_num;
	itm_size_t		pair_size;
	itm_size_t		i;
	itm_size_t		j;
	itm_size_t		k;
	char			*p;
	itm_data_t		*source;
	long			hash_value;
#if defined(DEBUG)
	long			hash_none;
	long			hash_one;
	long			hash_conflict;
#endif /* DEBUG */
	uchar_t			*source_data;
	uchar_t			*result_data;
	uchar_t			*dp;
	itm_size_t		m;
	itm_size_t		n;
	itm_size_t		h;

	TRACE_MESSAGE('m', ("map_table_hash : %ld(%ld) 0x%lx\n",
	    num, num2, default_data));
	source = &((*(tpp + 0))->data0);
	pair_size = (source->size + 1 + resultlen);

	if (100 <= hash_factor) {
		hash_table_num = (num2 * (hash_factor / 100.0));
	} else {
		hash_table_num = (num2 * 2);
	}
	if (hash_table_num < 256) {
		hash_table_num = 256;
	}
	source_data = malloc_vital(source->size);
	result_data = malloc_vital(resultlen);

	hash_table = malloc_vital(hash_table_num);
	for (i = 0, of_table_num = 0; i < num; i++) {
		hash_value = hash(NSPTR(&((*(tpp + i))->data0)),
		    (*(tpp + i))->data0.size,
		    hash_table_num);
		if (0 == *(hash_table + hash_value)) {
			*(hash_table + hash_value) = 1;
		} else {
			*(hash_table + hash_value) = 2;
			of_table_num += 1;
		}

		if ((*(tpp + i))->range.size != 0) {
			(void) memcpy(source_data,
			    NSPTR(&((*(tpp + i))->data0)),
			    source->size);
			h = map_table_num_range((*(tpp + i)));
			for (n = 0; n < h; n++) {
				for (m = 0,
				    dp = (uchar_t *)
				    (source_data + source->size - 1);
				    m < source->size;
				    m++, dp--) {
					if (0xff != *dp) {
						(*dp) += 1;
						for (++dp; m > 0; m--, dp++) {
							(*dp) = 0x00;
						}
						break;
					}
				}
				hash_value = hash((char *)source_data,
				    source->size,
				    hash_table_num);

				if (0 == *(hash_table + hash_value)) {
					*(hash_table + hash_value) = 1;
				} else {
					*(hash_table + hash_value) = 2;
					of_table_num += 1;
				}
			}
		}
	}

#if defined(DEBUG)
	if (TRACE('s')) {
		hash_none = 0;
		hash_one = 0;
		hash_conflict = 0;
		j = 0;
		for (i = 0; i < hash_table_num; i++) {
			if (2 == *(hash_table + i)) {
				(void) putchar('2');
				hash_conflict += 1;
			} else if (1 == *(hash_table + i)) {
				(void) putchar('1');
				hash_one += 1;
			} else if (0 == *(hash_table + i)) {
				(void) putchar('-');
				hash_none += 1;
			} else {
				(void) putchar('*');
			}
			if (63 <= j) {
				j = 0;
				(void) putchar('\n');
			} else {
				j += 1;
			}
		}
		(void) putchar('\n');
		(void) printf("null=%ld one=%ld conflict=%ld\n",
		    hash_none, hash_one, hash_conflict);
	}
#endif /* DEBUG */

	free(hash_table);
	table_size = ((sizeof (itm_tbl_hdr_t)) +
	    (sizeof (itm_map_hash_hdr_t)) +
	    (hash_table_num) +
	    (pair_size * hash_table_num) +
	    (pair_size * of_table_num));
	if ((NULL != default_data) &&
	    (((itm_data_t *)(-1)) != default_data)) {
		table_size += pair_size;
	}
	table_size = ITMROUNDUP(table_size);
	header = malloc_vital(table_size);
	sub_hdr = (itm_map_hash_hdr_t *)(header + 1);
	error_table = (char *)(sub_hdr + 1);
	hash_table = error_table + hash_table_num;
	of_table = hash_table + (pair_size * hash_table_num);

	header->type = ITM_TBL_MAP_HASH;
	header->name.itm_ptr = 0;
	header->size = table_size;
	header->number = num2;
	if (NULL != default_data) {
		if ((itm_data_t *)(-1) == default_data) {
			sub_hdr->default_error = -1;
#if !defined(_LP64)
			sub_hdr->pad7_num = (pad_t)(~0);
#endif
		} else {
			sub_hdr->default_error = 0;
		}
	} else {
		sub_hdr->default_error = 2;
	}

	sub_hdr->source_len = source->size;
	sub_hdr->result_len = resultlen;
	sub_hdr->hash_tbl_size = (pair_size * hash_table_num);
	sub_hdr->hash_tbl_num = hash_table_num;
	sub_hdr->hash_of_size =
	    (pair_size * of_table_num);
	sub_hdr->hash_of_num = of_table_num;
	sub_hdr->error_num = error_count; /* > 0; so pad4 = 0 */

	/* specified map */
	for (i = 0, j = 0, k = 0; i < num; i++) {
		hash_value = hash(NSPTR(&((*(tpp + i))->data0)),
		    (*(tpp + i))->data0.size,
		    hash_table_num);
		p = error_table + hash_value;
		if (*p) {	/* conflict */
			if (*p < 63) {
				*p += 1;
			}
			p = of_table + k;
			k += pair_size;
		} else {
			*p = 1;
			p = hash_table + (pair_size * hash_value);
		}

		(void) memcpy(p, NSPTR(&((*(tpp + i))->data0)), source->size);
		p += source->size;
		if (0 == (*(tpp + i))->data1.size) {
			(*p) = 1; /* specified error */
			p++;
		} else {
			/* (*p) = 0; ** valid */
			p++;
			(void) memset(p, 0,
			    (resultlen - (*(tpp + i))->data1.size));
			(void) memcpy(p +
			    (resultlen - (*(tpp + i))->data1.size),
			    NSPTR(&((*(tpp + i))->data1)),
			    (*(tpp + i))->data1.size);
		}

		if ((*(tpp + i))->range.size != 0) {
			(void) memcpy(source_data,
			    NSPTR(&((*(tpp + i))->data0)),
			    source->size);
			(void) memset(result_data, 0,
			    (resultlen  - (*(tpp + i))->data1.size));
			(void) memcpy(result_data +
			    (resultlen  - (*(tpp + i))->data1.size),
			    NSPTR(&((*(tpp + i))->data1)),
			    (*(tpp + i))->data1.size);
			h = map_table_num_range((*(tpp + i)));
			for (n = 0; n < h; n++) {
				for (m = 0,
				    dp = (uchar_t *)
				    (source_data + source->size - 1);
				    m < source->size;
				    m++, dp--) {
					if (0xff != *dp) {
						(*dp) += 1;
						for (++dp; m > 0; m--, dp++) {
							(*dp) = 0x00;
						}
						break;
					}
				}

				hash_value = hash((char *)source_data,
				    source->size,
				    hash_table_num);
				p = error_table + hash_value;
				if (*p) {	/* conflict */
					if (*p < 63) {
						*p += 1;
					}
					p = of_table + k;
					k += pair_size;
				} else {
					*p = 1;
					p = hash_table +
					    (pair_size * hash_value);
				}
				(void) memcpy(p, source_data, source->size);
				p += source->size;

				if (0 == (*(tpp + i))->data1.size) {
					(*p) = 1; /* specified error */
					p += 1;
				} else {
					/* (*p) = 0; ** valid */
					p += 1;
					for (m = 0, dp = (uchar_t *)
					    (result_data + resultlen - 1);
					    m < resultlen;
					    m++, dp--) {
						if (0xff != *dp) {
							(*dp) += 1;
							for (++dp; m > 0;
							    m--, dp++) {
								(*dp) = 0x00;
							}
							break;
						}
					}
					(void) memcpy(p,
					    result_data, resultlen);
				}
			}
		}
	}
	free(source_data);
	free(result_data);

	/* default */
	if ((NULL != default_data) &&
	    (((itm_data_t *)(-1)) != default_data)) {
		j = ((pair_size * hash_table_num) +
		    (pair_size * of_table_num));
		(void) memcpy(hash_table + j + (resultlen - default_data->size),
		    NSPTR(default_data), default_data->size);
	}
#if defined(ENABLE_TRACE)
	for (i = 0, p = of_table; i < of_table_num; i++, p += 5) {
		(void) printf("0x%02x%02x%02x%02x	0x%02x\n",
		    ((unsigned char)(*(p + 0))),
		    ((unsigned char)(*(p + 1))),
		    ((unsigned char)(*(p + 2))),
		    ((unsigned char)(*(p + 3))),
		    ((unsigned char)(*(p + 4))));
	}
#endif
	return	(header);
}




static itm_tbl_hdr_t *
map_table_dense_encoding(
	itmc_data_pair_t	**tpp,
	itm_size_t		num,
	itm_data_t		*default_data,
	unsigned long		entry_num,
	unsigned char		*byte_seq_min,
	unsigned char		*byte_seq_max,
	long			resultlen,
	itm_num_t		error_count)
{

	itm_tbl_hdr_t		*header;
	itm_map_dense_enc_hdr_t	*sub_hdr;
	char			*table;
	char			*error_table;
	itm_size_t		table_size;
	itm_size_t		j;
	itm_size_t		i;
	itm_size_t		k;
	char			*p;
	itm_data_t		*source;
	unsigned char		*byte_seq_def;

	TRACE_MESSAGE('m', ("map_table_dense_encoding : %ld\n", num));

	source = &((*(tpp + 0))->data0);


	table_size = ((sizeof (itm_tbl_hdr_t)) +
	    (sizeof (itm_map_dense_enc_hdr_t)) +
	    (source->size + source->size) +
	    (resultlen * entry_num));
	if (0 < error_count) {
		table_size += entry_num;
	}
	if (NULL == default_data) {
		if ((num < entry_num) ||
		    (error_count <= 0)) {
			table_size += entry_num;
		}
	} else if ((itm_data_t *)(-1) != default_data) {
		table_size += resultlen;
	}

	table_size = ITMROUNDUP(table_size);
	header = malloc_vital(table_size);
	sub_hdr = (itm_map_dense_enc_hdr_t *)(header + 1);
	table = (char *)(sub_hdr + 1) + source->size + source->size;

	header->type = ITM_TBL_MAP_DENSE_ENC;
	header->name.itm_ptr = 0;
	header->size = table_size;
	header->number = entry_num;

	sub_hdr->source_len = (*tpp)->data0.size;
	sub_hdr->result_len = resultlen;
	sub_hdr->error_num = error_count; /* > 0; so pad4 = 0 */

	if (NULL != default_data) {
		if ((itm_data_t *)(-1) == default_data) {
			sub_hdr->default_error = -1;
#if !defined(_LP64)
			sub_hdr->pad3_num = (pad_t)(~0);
#endif

		} else {
			sub_hdr->default_error = 0;
		}
	} else {
		if (num < entry_num) {
			sub_hdr->default_error = 1;
		} else {
			sub_hdr->default_error = 2;
		}
	}

	(void) memcpy((char *)(sub_hdr + 1), byte_seq_min, source->size);
	(void) memcpy((char *)(sub_hdr + 1) + source->size,
	    byte_seq_max, source->size);

	if (-1 == sub_hdr->default_error) {
		byte_seq_def = malloc_vital((sizeof (unsigned char *)) *
		    resultlen);
		if (source->size != resultlen) {
			itm_error(
			gettext("\"default no_change_copy\" is "
			    "specified, but size does not match\n"));
			exit(ITMC_STATUS_BT);
		}
		put_dense_encoding_default(
		    table, byte_seq_min, byte_seq_max, byte_seq_def,
		    resultlen - 1, 0, 0);
		free(byte_seq_def);
	} else if (0 == sub_hdr->default_error) {
		if (default_data->size <= (sizeof (itm_place_t))) {
			for (i = 0, j = 0;
			    i < (entry_num + 1); /* 1:default data */
			    i++, j += resultlen) {
				(void) memcpy(table + j +
				    (resultlen - default_data->size),
				    (void *)(&(default_data->place.itm_64d)),
				    default_data->size);
			}
		} else {
			for (i = 0, j = 0;
			    i < (entry_num + 1);  /* 1:default data */
			    i++, j += resultlen) {
				(void) memcpy(table + j +
				    (resultlen - default_data->size),
				    (void *)(default_data->place.itm_ptr),
				    default_data->size);
			}
		}
	}
	if (1 == sub_hdr->default_error) {
		(void) memset(table + (resultlen * entry_num), 1, entry_num);
		error_table = (table + (resultlen * entry_num));
		for (i = 0; i < num; i++) {
			if (0 == (*(tpp + i))->data1.size) {
				continue; /* error sequence */
			}
			j = hash_dense_encoding(NSPTR(&((*(tpp + i))->data0)),
			    (*(tpp + i))->data0.size,
			    byte_seq_min, byte_seq_max);
			k = ((*(tpp + i))->range.size) == 0 ? j :
			    hash_dense_encoding(NSPTR(&((*(tpp + i))->range)),
			    (*(tpp + i))->data0.size,
			    byte_seq_min, byte_seq_max);
			for (; j <= k; j++) {
				*(error_table + j) = 0;
			}
		}
	} else if (0 < error_count) {
		error_table = (table + (resultlen * entry_num));
		if (0 == sub_hdr->default_error) {
			error_table += resultlen;
		}
		(void) memset(error_table, 0, entry_num);
		for (i = 0; i < num; i++) {
			if (0 == (*(tpp + i))->data1.size) {
				j = hash_dense_encoding(
				    NSPTR(&((*(tpp + i))->data0)),
				    (*(tpp + i))->data0.size,
				    byte_seq_min, byte_seq_max);
				k = ((*(tpp + i))->range.size) == 0 ? j :
				    hash_dense_encoding(
				    NSPTR(&((*(tpp + i))->range)),
				    (*(tpp + i))->data0.size,
				    byte_seq_min, byte_seq_max);
				for (; j <= k; j++) {
					*(error_table + j) = 1; /* specified */
				}
			}
		}
	}


	p = malloc_vital(resultlen);
	for (i = 0; i < num; i++) {
		j = hash_dense_encoding(NSPTR(&((*(tpp + i))->data0)),
		    (*(tpp + i))->data0.size,
		    byte_seq_min, byte_seq_max);

		if (0 != (*(tpp + i))->range.size)
			k = hash_dense_encoding(
			    NSPTR(&((*(tpp + i))->range)),
			    (*(tpp + i))->range.size,
			    byte_seq_min, byte_seq_max);
		else
			k = j;
		(void) memset(p, 0, (resultlen	 - (*(tpp + i))->data1.size));
		(void) memcpy(p + (resultlen  - (*(tpp + i))->data1.size),
		    ((caddr_t)NSPTR(&((*(tpp + i))->data1))),
		    (*(tpp + i))->data1.size);
		map_range_make_result(table, j, k, p, resultlen);
	}
	free(p);

	return	(header);
}


static void
put_dense_encoding_default(
	char	*table,
	unsigned char	*byte_seq_min,
	unsigned char	*byte_seq_max,
	unsigned char	*byte_seq_def,
	long		pos_max,
	long		position,
	long		dense_encoded_value)
{
	uchar_t	i;

	if (position < pos_max) {
		for (i = *(byte_seq_min + position);
		    i <= *(byte_seq_max + position); i++) {
			*(byte_seq_def + position) = i;
			put_dense_encoding_default(
			    table,
			    byte_seq_min, byte_seq_max,
			    byte_seq_def,
			    pos_max, position + 1,
			    ((dense_encoded_value + i) *
			    (*(byte_seq_max + position) -
			    *(byte_seq_min + position) + 1)));
		}
		return;
	}

	for (i = *(byte_seq_min + position);
	    i <= *(byte_seq_max + position); i++) {
		*(byte_seq_def + position) = i;
		(void) memcpy(table +
		    ((pos_max + 1) * (dense_encoded_value + i - 1)),
		    byte_seq_def, pos_max + 1);
	}
}


char *
dense_enc_index_to_byte_seq(
	long		value,
	long		length,
	unsigned char	*byte_seq_min,
	unsigned char	*byte_seq_max)
{
	static char	*buf;
	static long	buf_len;
	char		*p;
	int		i;
	int		l;
	int		residue;

	if (buf_len < (2 + (length * 2) + 1)) {
		free(buf);
		buf_len = (2 + (length * 2) + 1) + 16;
		buf = malloc_vital(buf_len);
	}

	*(buf + (length * 2)) = '\0';
	*(buf + 0) = '0';
	*(buf + 1) = 'x';
	p = buf + 2;
	for (i = length - 1; 0 <= i; --i) {
		residue = value % (*(byte_seq_max + i) -
		    *(byte_seq_min + i) + 1);
		value /= (*(byte_seq_max + i) -
		    *(byte_seq_min + i) + 1);

		residue += *(byte_seq_min + i);
		l = ((0xf0 & residue) >> 4);
		if (l < 10) {
			*(p + (i * 2)) = ('0' + l);
		} else {
			*(p + (i * 2)) = ('a' + l - 10);
		}
		l = (0x0f & residue);
		if (l < 10) {
			*(p + (i * 2) + 1) = ('0' + l);
		} else {
			*(p + (i * 2) + 1) = ('a' + l - 10);
		}
	}
	return	(buf);
}


itm_tbl_hdr_t *
map_table_lookup_var()
{
	itm_error(gettext(
	    "length of all source sequences must be the same\n"));
	error_deferred += 1;
	return	(NULL);
}



static void
map_range_adjust_byte_seq(
	unsigned char		*byte_seq_min,
	unsigned char		*byte_seq_max,
	long			source_len,
	itmc_data_pair_t	*pair)
{
	unsigned char		*p, *p2;
	int			i;
	int			flag;

	p  = (unsigned char *)(NSPTR(&((pair)->data0)));
	p2 = (unsigned char *)(NSPTR(&((pair)->range)));
	flag = 0;
	for (i = 0; i < source_len; i++) {
		if (flag != 0) {
			break;
		}
		if (*(p + i) != *(p2 + i))
			flag = 1;
		if (*(p + i) < *(byte_seq_min + i)) {
			*(byte_seq_min + i) = *(p + i);
		}
		if (*(byte_seq_max + i) < *(p2 + i)) {
			*(byte_seq_max + i) = *(p2 + i);
		}
	}
	for (; i < source_len; i++) {
		*(byte_seq_min + i) = 0x00;
		*(byte_seq_max + i) = 0xff;
	}
}

/*
 *	result value + (source range value - source base value)
 *	and just caluculate its length
 */
static size_t
map_table_resultlen(itmc_map_t		*ml)
{
	size_t	j;
	size_t	len;
	int	m;
	uchar_t *c1;
	uchar_t *c2;
	uchar_t *c3;

	j = ml->data_pair.data0.size;
	if (j < ml->data_pair.data1.size) j = ml->data_pair.data1.size;
	if (j < ml->data_pair.range.size) j = ml->data_pair.range.size;
	c1 = (uchar_t *)(NSPTR(&((ml->data_pair).data0))) +
	    ml->data_pair.data0.size - 1;
	c2 = (uchar_t *)(NSPTR(&((ml->data_pair).data1))) +
	    ml->data_pair.data1.size - 1;
	c3 = (uchar_t *)(NSPTR(&((ml->data_pair.range)))) +
	    ml->data_pair.range.size - 1;
	m = 0;
	for (len = 0; len < j; len++, c1--, c2--, c3--) {
		if (len < ml->data_pair.data0.size) m -= *c1;
		if (len < ml->data_pair.data1.size) m += *c2;
		if (len < ml->data_pair.range.size) m += *c3;
		m >>= 8;
	}
	if (m > 0) {
		len += 1;
	}
	TRACE_MESSAGE('g', ("map_table_resutlen: source(0x%s..0x%s), "
	    "result(0x%s.... len= %ld)\n",
	    data_to_hexadecimal(&(ml->data_pair.data0)),
	    data_to_hexadecimal(&(ml->data_pair.range)),
	    data_to_hexadecimal(&(ml->data_pair.data1)),
	    len));
	return (len);
}

/*
 *
 */
static void
map_range_make_result(
	char		*table,
	itm_size_t	range_start,
	itm_size_t	range_end,
	char		*result_data,
	itm_size_t	result_size)
{
	itm_size_t	i;
	itm_size_t	j;
	itm_size_t	p;
	uchar_t		*dp; /* unsigned for ++ operation */

	for (i = range_start, p = i * result_size;
	    i <= range_end; i++, p += result_size) {
		(void) memcpy(table + p, result_data, result_size);
		for (j = 0, dp = (uchar_t *)(result_data + result_size - 1);
		    j < result_size;
		    j++, dp--) {
			if (0xff != *dp) {
				(*dp) += 1;
				for (++dp; j > 0; j--, dp++) {
					(*dp) = 0x00;
				}
				break;
			}
		}
	}
}

/*
 *
 */
static size_t
map_table_num_range(itmc_data_pair_t	*pair)
{
	size_t		i, j;
	itm_num_t	num;
	itm_num_t	num2;
	uchar_t		*c1;
	uchar_t		*c2;

	assert(0 < pair->range.size);
	j = pair->data0.size;
	if (j < pair->range.size)
		j = pair->range.size;
	c1 = ((uchar_t *)(NSPTR(&(pair->data0)))) + pair->data0.size - 1;
	c2 = ((uchar_t *)(NSPTR(&(pair->range)))) + pair->range.size - 1;
	num = 0;
	for (i = 0; i < j; i++, c1--, c2--) {
		if (i < pair->range.size) num2 = *c2;
		if (i < pair->data0.size) num2 -= *c1;
		TRACE_MESSAGE('G', (" num += %d(=%d-%d)\n ",
		    *c2 - *c1, *c2, *c1));
		num2 <<= (i*8);
		num += num2;
	}
	TRACE_MESSAGE('g', ("map_table_num_range: source(0x%s..0x%s), "
	    "num= %ld\n",
	    data_to_hexadecimal(&(pair->data0)),
	    data_to_hexadecimal(&(pair->range)),
	    num));
	return (num);
}

/*
 *
 */
itmc_map_t *
map_list_append(itmc_map_t	*map_list, itmc_map_t	*map_pair)
{
	if (0 == map_pair) {
		return	(map_list);
	}

	map_pair->next = NULL;
	map_pair->last = map_pair;

	if (map_list) {
		map_list->last->next = map_pair;
		map_list->last = map_pair;
		return	(map_list);
	} else {
		return	(map_pair);
	}
}



itmc_obj_t *
op_self(itm_op_type_t type)
{
	return (op_unit(type, NULL, 0, NULL, 0, NULL, 0));
}


itmc_obj_t *
op_unary(itm_op_type_t type, void	*data, size_t data_size)
{
	return (op_unit(type, data, data_size, NULL, 0, NULL, 0));
}

itmc_obj_t *
op_unit(itm_op_type_t	type,
	void	*data0, size_t data0_size,
	void	*data1, size_t data1_size,
	void	*data2, size_t data2_size)
{
	itm_op_t	*op;
	itmc_obj_t	*obj;

	op = malloc_vital(sizeof (itm_op_t));
	op->type = type;
	op->data.operand[0].itm_ptr = (itm_place2_t)(data0);
	op->data.operand[1].itm_ptr = (itm_place2_t)(data1);
	op->data.operand[2].itm_ptr = (itm_place2_t)(data2);

	obj = malloc_vital(sizeof (itmc_obj_t));
	obj->type = ITMC_OBJ_OP;
	obj->name = NULL;
	obj->obj = op;
	obj->ref[0] = obj->ref[1] = obj->ref[2] = NULL;
	if (NULL != data0) {
		obj->ref[0] = obj_register(ITMC_OBJ_EXPR, NULL,
		    data0, data0_size,
		    &(op->data.operand[0]),
		    OBJ_REG_TAIL);
	}
	if (NULL != data1) {
		obj->ref[1] = obj_register(ITMC_OBJ_EXPR, NULL,
		    data1, data1_size,
		    &(op->data.operand[1]),
		    OBJ_REG_TAIL);
	}
	if (NULL != data2) {
		obj->ref[2] = obj_register(ITMC_OBJ_EXPR, NULL,
		    data2, data2_size,
		    &(op->data.operand[2]),
		    OBJ_REG_TAIL);
	}
	obj->next = NULL;
	obj->last = NULL;

	return	(obj);
}


itmc_obj_t *
op_self_num(itm_op_type_t type, itm_num_t data)
{
	itm_op_t	*op;
	itmc_obj_t	*obj;

	op = malloc_vital(sizeof (itm_op_t));
	op->type = type;
	op->data.itm_opnum = data;
#if !defined(_LP64)
	op->data.itm_oppad = (data < 0) ? (pad_t)(~0) : 0;
#endif
	obj = malloc_vital(sizeof (itmc_obj_t));
	obj->type = ITMC_OBJ_OP;
	obj->name = NULL;
	obj->obj = op;
	obj->ref[0] = obj->ref[1] = obj->ref[2] = NULL;

	return	(obj);
}


itm_expr_t *
expr_self_num(itm_expr_type_t type, itm_num_t data)
{
	itm_expr_t	*expr;

	expr = malloc_vital(sizeof (itm_expr_t));
	expr->type = type;
	expr->data.itm_exnum = data;
#if !defined(_LP64)
	expr->data.itm_expad = (data < 0) ? (pad_t)(~0) : 0;
#endif
	return	(expr);
}


itm_expr_t *
expr_self(itm_expr_type_t type, itm_data_t	*data)
{
	itm_expr_t	*expr;
	itmc_name_t	*name;

	expr = malloc_vital(sizeof (itm_expr_t));
	expr->type = type;
	if (NULL == data) {
		expr->data.value.size = 0;
		expr->data.value.place.itm_ptr = 0;
	} else {
		expr->data.value = *(data);
	}

	switch (type) {
	case ITM_EXPR_NAME: /* register */
		name = name_lookup(data, ITMC_OBJ_REGISTER);
		if (&name_lookup_error == name) {
			return	(NULL);
		} else if (NULL == name) {
			if (reg_id >= MAXREGID) {
				itm_error(
				    gettext(
				    "more than %d variables are used\n"),
				    MAXREGID);
				exit(ITMC_STATUS_BT2);
			}
			name = name_register(data, ITMC_OBJ_REGISTER, NULL);
			name->reg_id = (reg_id++);
		}
		expr->type = ITM_EXPR_REG;
		expr->data.itm_exnum = name->reg_id;
#if !defined(_LP64)
		expr->data.itm_expad =
		    (expr->data.itm_exnum < 0) ? (pad_t)(~0) : 0;
#endif
		break;
	case ITM_EXPR_SEQ:
		if ((sizeof (itm_place_t)) < data->size) {
			(void) obj_register(ITMC_OBJ_DATA, NULL,
			    (void *)(data->place.itm_ptr), data->size,
			    &(expr->data.value.place), OBJ_REG_TAIL);
		}
		break;
	}
	return	(expr);
}


itm_expr_t *
expr_unary(itm_expr_type_t type, itm_expr_t *data0)
{
	itm_expr_t	*expr;

	expr = malloc_vital(sizeof (itm_expr_t));
	expr->type = type;
	expr->data.operand[0].itm_ptr = (itm_place2_t)(data0);
	(void) obj_register(ITMC_OBJ_EXPR, NULL,
	    data0, sizeof (itm_expr_t),
	    &(expr->data.operand[0]), OBJ_REG_TAIL);

	return	(expr);
}


itm_expr_t *
expr_binary(itm_expr_type_t type,
	    itm_expr_t		*data0, itm_expr_t	*data1)
{
	itm_expr_t	*expr;
	itm_num_t	num;
	unsigned char	*p;
	int		i;

	expr = malloc_vital(sizeof (itm_expr_t));
	expr->type = type;

	if (ITM_EXPR_SEQ == data0->type) {
		p = (unsigned char *)NSPTR(&(data0->data.value));
		for (i = 0, num = 0; i < data0->data.value.size; i++, p++) {
			num = ((num << 8) | *p);
		}
		data0 = expr_self_num(ITM_EXPR_INT, num);
	}
	if (ITM_EXPR_SEQ == data1->type) {
		p = (unsigned char *)NSPTR(&(data1->data.value));
		for (i = 0, num = 0; i < data1->data.value.size; i++, p++) {
			num = ((num << 8) | *p);
		}
		data1 = expr_self_num(ITM_EXPR_INT, num);
	}

	expr->data.operand[0].itm_ptr = (itm_place2_t)(data0);
	expr->data.operand[1].itm_ptr = (itm_place2_t)(data1);

	(void) obj_register(ITMC_OBJ_EXPR, NULL,
	    data0, sizeof (itm_expr_t),
	    &(expr->data.operand[0]), OBJ_REG_TAIL);
	(void) obj_register(ITMC_OBJ_EXPR, NULL,
	    data1, sizeof (itm_expr_t),
	    &(expr->data.operand[1]), OBJ_REG_TAIL);

	return	(expr);
}


itm_expr_t *
expr_binary2(itm_expr_type_t type,
		itm_expr_t *data0, itm_expr_t *data1)
{
	itm_expr_t	*expr;
	itm_num_t	num;
	unsigned char	*p;
	int		i;

	if ((NULL == data0) || (NULL == data1)) {
		return (NULL);
	}
	expr = malloc_vital(sizeof (itm_expr_t));
	expr->type = type;

	switch (data0->type) {
	case ITM_EXPR_SEQ:
		p = (unsigned char *)NSPTR(&(data0->data.value));
		for (i = 0, num = 0; i < data0->data.value.size; i++, p++) {
			num = ((num << 8) | *p);
		}
		data0 = expr_self_num(ITM_EXPR_INT, num);
		expr->data.operand[0].itm_ptr = (itm_place2_t)(data0);
		(void) obj_register(ITMC_OBJ_EXPR, NULL,
		    data0, sizeof (itm_expr_t),
		    &(expr->data.operand[0]), OBJ_REG_TAIL);
		break;
	case ITM_EXPR_INT:
	case ITM_EXPR_REG:
	case ITM_EXPR_IN_VECTOR_D:
		expr->data.operand[0] = data0->data.operand[0];
		break;
	default:
		expr->data.operand[0].itm_ptr = (itm_place2_t)(data0);
		(void) obj_register(ITMC_OBJ_EXPR, NULL,
		    data0, sizeof (itm_expr_t),
		    &(expr->data.operand[0]), OBJ_REG_TAIL);
		break;
	}

	switch (data1->type) {
	case ITM_EXPR_SEQ:
		p = (unsigned char *)NSPTR(&(data1->data.value));
		for (i = 0, num = 0; i < data1->data.value.size; i++, p++) {
			num = ((num << 8) | *p);
		}
		data1 = expr_self_num(ITM_EXPR_INT, num);
		expr->data.operand[1].itm_ptr = (itm_place2_t)(data1);
		(void) obj_register(ITMC_OBJ_EXPR, NULL,
		    data1, sizeof (itm_expr_t),
		    &(expr->data.operand[1]), OBJ_REG_TAIL);
		break;
	case ITM_EXPR_INT:
	case ITM_EXPR_REG:
	case ITM_EXPR_IN_VECTOR_D:
		expr->data.operand[1] = data1->data.operand[0];
		break;
	default:
		expr->data.operand[1].itm_ptr = (itm_place2_t)(data1);
		(void) obj_register(ITMC_OBJ_EXPR, NULL,
		    data1, sizeof (itm_expr_t),
		    &(expr->data.operand[1]), OBJ_REG_TAIL);
		break;
	}
	return	(expr);
}


itm_expr_t *
expr_assign(itm_expr_type_t type,
	    itm_data_t		*data0, itm_expr_t	*data1)
{
	itm_expr_t	*expr;
	itmc_name_t	*name;

	expr = malloc_vital(sizeof (itm_expr_t));
	expr->type = type;
	expr->data.operand[1].itm_ptr = (itm_place2_t)(data1);

	name = name_lookup(data0, ITMC_OBJ_REGISTER);
	if (&name_lookup_error == name) {
		free(expr);
		exit(ITMC_STATUS_BT);
	} else if (NULL == name) {
		name = name_register(data0, ITMC_OBJ_REGISTER, NULL);
		name->reg_id = (reg_id++);
	}
	expr->data.operand[0].itm_ptr = name->reg_id;

	(void) obj_register(ITMC_OBJ_EXPR, NULL,
	    data1, sizeof (itm_expr_t),
	    &(expr->data.operand[1]), OBJ_REG_TAIL);
	return	(expr);
}


itm_expr_t *
expr_seq_to_int(itm_expr_t	*expr)
{
	itm_num_t	num;
	unsigned char	*p;
	int		i;

	if (ITM_EXPR_SEQ == expr->type) {
		if ((sizeof (itm_place_t)) < expr->data.value.size) {
			p = (unsigned char *)(expr->data.value.place.itm_ptr);
		} else {
			p = (unsigned char *)&(expr->data.value.place.itm_64d);
		}
		for (i = 0, num = 0;
		    i < expr->data.value.size;
		    i++, p++) {
			num = ((num << 8) | *p);
		}
		free(expr);
		expr = expr_self_num(ITM_EXPR_INT, num);
	}
	return	(expr);
}


itmc_name_t *
name_lookup(itm_data_t		*name, itm_type_t type)
{
	itmc_name_t	*p;

	TRACE_MESSAGE('N', ("name_lookup\t: \"%-16s\" %2ld %2ld %2ld\n",
	    name_to_str(name), name->size, type, name_id));

	if (0 == name->size)
		return	(NULL);
	for (p = name_first; p; p = p->next) {
		if ((name->size != p->name.size) ||
		    (memcmp(NSPTR(name), NSPTR(&(p->name)), name->size))) {
			continue;
		}
		if ((type != p->type) &&
		    (((ITMC_OBJ_ACTION	!= type) &&
		    (ITMC_OBJ_ACTION	!= p->type)) ||
		    ((ITMC_OBJ_ACTION	== type) &&
		    (ITMC_OBJ_DIREC	!= p->type) &&
		    (ITMC_OBJ_OP	!= p->type) &&
		    (ITMC_OBJ_MAP	!= p->type)) ||
		    ((ITMC_OBJ_ACTION	== p->type) &&
		    (ITMC_OBJ_DIREC	!= type) &&
		    (ITMC_OBJ_OP	!= type) &&
		    (ITMC_OBJ_MAP	!= type)))) {
			itm_error(
			    gettext("name type conflict: \"%1$s\" "
			    "%2$s %3$s\n"),
			    name_to_str(name),
			    itm_name_type_name[type],
			    itm_name_type_name[p->type]);
			error_deferred += 1;
			return (&name_lookup_error);
		} else {
			return	(p);
		}
	}
	return	(NULL);
}


itmc_name_t *
name_refer(itm_data_t	*name, itm_type_t type, itmc_ref_t	*refp)
{
	itmc_name_t		*p;
	itmc_ref_link_t		*rl;

	p = name_lookup(name, type);

	TRACE_MESSAGE('N', ("name_refer\t: \"%-16s\" %2ld %2ld %08p %2d %08p\n",
	    name_to_str(name), name->size, type, refp, name_id, p));

	if (&name_lookup_error == p) {
		return	(NULL);
	}

	rl = malloc_vital(sizeof (itmc_ref_link_t));

	rl->ref = refp;
	rl->next = NULL;

	if (NULL != p) {
		if (p->ref_last) {
			p->ref_last->next = rl;
		} else {
			p->ref_first = rl;
		}
		p->ref_last = rl;
	} else {
		p = malloc_vital(sizeof (itmc_name_t));
		p->id = (name_id++);
		p->reg_id = 0;
		p->name = *name;
		p->type = type;
#if !defined(_LP64)
		p->reloc.itm_pad = 0;
#endif
		p->reloc.itm_ptr = 0;
		p->ref_first = rl;
		p->ref_last = rl;
		p->next = NULL;

		if (name_last) {
			name_last->next = p;
		} else {
			name_first = p;
		}
		name_last = p;
	}
	return	(p);
}


itmc_name_t *
name_register(itm_data_t	*name, itm_type_t type, itmc_ref_t	*refp)
{
	itmc_name_t	*p;

	TRACE_MESSAGE('N', ("name_register\t: \"%-16s\" %2ld %2ld %08p %2ld\n",
	    name_to_str(name), name->size, type, refp, name_id));


	p = name_lookup(name, type);
	if (&name_lookup_error == p) {
		return	(NULL);
	}
	if (NULL != p) {
		if (NULL != p->object) {
			itm_error(gettext(
			    "same names are specified: %1$s\n"),
			    name_to_str(name));
			error_deferred += 1;
			return (NULL);
		}
		p->object = refp;
	} else {
		p = malloc_vital(sizeof (itmc_name_t));
		p->id = (name_id++);
		p->reg_id = 0;
		p->name = *name;
		p->type = type;
		p->object = refp;
		p->reloc.itm_ptr = 0;
#if !defined(_LP64)
		p->reloc.itm_pad = 0;
#endif
		p->ref_first = NULL;
		p->ref_last = NULL;
		p->next = NULL;

		if (name_last) {
			name_last->next = p;
		} else {
			name_first = p;
		}
		name_last = p;
	}

	return	(p);
}


int
data_compare(const itm_data_t	*d0, const itm_data_t	*d1)
{
	if (d0->size < d1->size) {
		if (memcmp(NSPTR(d0), NSPTR(d1), d0->size) < 0) {
			return (-1);
		} else {
			return	(1);
		}
	} else if (d0->size == d1->size) {
		return (memcmp(NSPTR(d0), NSPTR(d1), d0->size));
	} else /* (d0->size > d1->size) */ {
		if (memcmp(NSPTR(d0), NSPTR(d1), d1->size) <= 0) {
			return (-1);
		} else {
			return	(1);
		}
	}
}

int
data_pair_compare(itmc_data_pair_t	**p0, itmc_data_pair_t	**p1)
{
	int		r;
	itm_data_t	*d0;
	itm_data_t	*d1;
	uchar_t		*c0;
	uchar_t		*c1;
	size_t		s;
	int		i;

	d0 = &((*p0)->data0);
	d1 = &((*p1)->data0);
	c0 = NSPTR(d0);
	c1 = NSPTR(d1);
	if (d0->size == d1->size) {
		s = d0->size;
	} else if (d0->size < d1->size) {
		s = d1->size - d0->size;
		for (i = 0; i < s; i++, c1++) {
			if (0x00 != *c1) {
				return (-1);
			}
		}
		s = d0->size;
	} else {
		assert(d0->size > d1->size);
		s = d0->size - d1->size;
		for (i = 0; i < s; i++, c0++) {
			if (0x00 != *c0) {
				return	(1);
			}
		}
		s = d1->size;
	}
	r = memcmp(c0, c1, s);
	if (0 == r) {
		itm_data_t	*d;
		if (c0 == NSPTR(d0)) {
			d = d0;
		} else {
			assert(c1 == NSPTR(d0));
			d = d1;
		}
		itm_error(gettext(
		    "distinct source values are specified: 0x%1$s\n"),
		    data_to_hexadecimal(d));
		error_deferred += 1;
	}
	return	(r);
}


static long
data_to_long(itm_data_t		*data)
{
	long		l;
	int		i;
	unsigned char	*p;

	if ((sizeof (itm_place_t)) < data->size) {
		return (0);
	}
	for (l = 0, i = 0, p = (unsigned char *)&(data->place);
	    i < data->size;
	    i++, p++) {
		l <<= 8;
		l |= *p;
	}
	return	(l);
}
