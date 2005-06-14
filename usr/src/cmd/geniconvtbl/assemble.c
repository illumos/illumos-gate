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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libintl.h>

#include "itmcomp.h"

struct itm_opt_outer *itm_op_outer = NULL;

#if defined(ENABLE_TRACE)
static char	*itmc_obj_names[] = {
	"ITMC_OBJ_NONE(0)",
	"ITMC_OBJ_ITM(1)",
	"ITMC_OBJ_STRING(2)",
	"ITMC_OBJ_DIREC(3)",
	"ITMC_OBJ_COND(4)",
	"ITMC_OBJ_MAP(5)",
	"ITMC_OBJ_OP(6)",
	"ITMC_OBJ_EXPR(7)",
	"ITMC_OBJ_DATA(8)",
	"ITMC_OBJ_ACTION(9)",
	"ITMC_OBJ_RANGE(10)",
	"ITMC_OBJ_RAGISTER(11)",
	"ITMC_OBJ_ESCAPESEQ(12)"
};
#endif

#define	TRACE_FMT(comment) \
comment ## " size=%4ld(0x%4lx); 64d=0x%16" PRIx64 "; ptr=%4p(%c...)\n"
#define	TRACE_DT(data, refer) \
	data.size, data.size, data.place.itm_64d, \
	data.place.itm_ptr,\
	(((refer) == 0) ? (not_refer): \
	(((sizeof (itm_place_t) < data.size))? \
	 *((char *)(((char *)itm_header) + data.place.itm_ptr)): \
	(not_refer)))
enum {
	NOREFER = 0,
	REFER  = 1
};
#define	NAMETRACE(comment) \
	{	itmc_name_t	*name;\
		TRACE_MESSAGE('p', (#comment "\n")); \
		for (name = name_first; name; name = name->next) {\
			TRACE_MESSAGE('p', \
				(TRACE_FMT(" "),\
				TRACE_DT(name->name, NOREFER)));\
		}\
	}

/* static int not_refer = (~0); */



static void	relocation_I(itm_hdr_t *, itm_info_hdr_t *);
static void	relocation_II(itm_hdr_t *, itm_info_hdr_t *);

static void	fix_itmc_ref_reloc(itmc_ref_t *, itm_place2_t);
static void	analysis(itm_info_hdr_t	*);
static void	analysis2(void);
static void	output(itm_hdr_t *, itm_info_hdr_t *);




/*
 * Assemble main function
 */

int
assemble(itm_hdr_t	*itm_header)
{
	int		i;
	int		j;
	itmc_ref_t	*ref;
	itm_info_hdr_t	*info_header;
	union {
		long	longval;
		char	charval[8];
	}		mach_spec;

	if (0 < error_deferred) {
		itm_error(gettext("number of deferred error: %d\n"),
			error_deferred);
		exit(ITMC_STATUS_BT);
	}

	itm_header->ident[0] = ITM_IDENT_0;
	itm_header->ident[1] = ITM_IDENT_1;
	itm_header->ident[2] = ITM_IDENT_2;
	itm_header->ident[3] = ITM_IDENT_3;

	itm_header->spec[0] = ITM_SPEC_0;
	itm_header->spec[1] = ITM_SPEC_1;
	itm_header->spec[2] = ITM_SPEC_2;
	mach_spec.longval = 1;
	switch (sizeof (long)) {
	case 4:
		if (0 == mach_spec.charval[0]) {
			itm_header->spec[3] = ITM_SPEC_3_32_BIG_ENDIAN;
		} else {
			itm_header->spec[3] = ITM_SPEC_3_32_LITTLE_ENDIAN;
		}
		break;
	case 8:
		if (0 == mach_spec.charval[0]) {
			itm_header->spec[3] = ITM_SPEC_3_64_BIG_ENDIAN;
		} else {
			itm_header->spec[3] = ITM_SPEC_3_64_LITTLE_ENDIAN;
		}
		break;
	}

	itm_header->version[0] = ITM_VER_0;
	itm_header->version[1] = ITM_VER_1;
	itm_header->version[2] = ITM_VER_2;
	itm_header->version[3] = ITM_VER_3;

	itm_header->itm_size.itm_ptr = 0;

	itm_header->reg_num = reg_id;

	itm_header->itm_hdr_size = (sizeof (itm_hdr_t));

	info_header = malloc_vital(sizeof (itm_info_hdr_t));
	(void) memset(info_header, 0, sizeof (itm_info_hdr_t));

	relocation_I(itm_header, info_header);
	relocation_II(itm_header, info_header);

	TRACE_MESSAGE('r',
			("	  ref	 name	 referencee reloc(10)"
			"size(10) referencer next\n"));
	for (i = ITMC_OBJ_FIRST; i <= ITMC_OBJ_LAST; i++) {
		TRACE_MESSAGE('r', ("%s\n", itmc_obj_names[i]));
		for (ref = ref_first[i], j = 0; ref; ref = ref->next, j++) {
			TRACE_MESSAGE('r',
			("	 %2d:%08p:%08p:%08p:%8p:%8ld:%08p:%08p\n",
			j, ref,
			ref->name, ref->referencee,
			ref->reloc.itm_ptr, ref->size,
			ref->referencer, ref->next));
		}
	}

	analysis(info_header);
	analysis2();
	if (0 < error_deferred) {
		itm_error(gettext("number of deferred error: %d\n"),
			error_deferred);
		exit(ITMC_STATUS_BT);
	}

	output(itm_header, info_header);
	return (0);
}


/*
 * Fix reloc of itmc_ref_t, and fix reloc of itmc_name_t
 */

static void
relocation_I(itm_hdr_t		*itm_header, itm_info_hdr_t	*info_header)
{
	itmc_ref_t	*ref;
	itmc_name_t	*name;
	itm_num_t	sec_num;
	itm_num_t	sec_num2;
	itm_size_t	sec_size;

	/*
	 * determin section size
	 */

	/* string section */
	for (sec_num = 0, sec_size = 0, ref = ref_first[ITMC_OBJ_STRING];
	    ref; sec_num += 1, sec_size += ref->size, ref = ref->next) {}
	sec_size = ITMROUNDUP(sec_size);
	info_header->str_plc_tbl.size = ((sizeof (itm_data_t)) * sec_num);
	info_header->str_plc_tbl.number = sec_num;
	info_header->str_sec.size = sec_size;
	info_header->str_sec.number = sec_num;

	/* direction */
	for (sec_num = 0, sec_size = 0, ref = ref_first[ITMC_OBJ_DIREC];
	    ref; sec_num += 1, sec_size += ref->size, ref = ref->next) {}
	sec_size = ITMROUNDUP(sec_size);
	info_header->direc_plc_tbl.size = sec_num * (sizeof (itm_place_t));
	info_header->direc_plc_tbl.number = sec_num;
	info_header->direc_tbl_sec.size = sec_size;
	info_header->direc_tbl_sec.number = sec_num;

	/* condition */
	for (sec_num = 0, sec_size = 0, ref = ref_first[ITMC_OBJ_COND];
	    ref; sec_num += 1, sec_size += ref->size, ref = ref->next) {}
	sec_size = ITMROUNDUP(sec_size);
	info_header->cond_plc_tbl.size = sec_num * (sizeof (itm_place_t));
	info_header->cond_plc_tbl.number = sec_num;
	info_header->cond_tbl_sec.size = sec_size;
	info_header->cond_tbl_sec.number = sec_num;

	/* map */
	for (sec_num = 0, sec_size = 0, ref = ref_first[ITMC_OBJ_MAP];
	    ref; sec_num += 1, sec_size += ref->size, ref = ref->next) {
	}
	sec_size = ITMROUNDUP(sec_size);
	info_header->map_plc_tbl.size = sec_num * (sizeof (itm_place_t));
	info_header->map_plc_tbl.number = sec_num;
	info_header->map_tbl_sec.size = sec_size;
	info_header->map_tbl_sec.number = sec_num;

	/* operation */
	for (sec_num = 0, sec_size = 0, ref = ref_first[ITMC_OBJ_OP];
	    ref; sec_num += 1, sec_size += ref->size, ref = ref->next) {
	}
	sec_size = ITMROUNDUP(sec_size);
	info_header->op_plc_tbl.size = sec_num * (sizeof (itm_place_t));
	info_header->op_plc_tbl.number = sec_num;
	info_header->op_tbl_sec.size = sec_size;
	info_header->op_tbl_sec.number = sec_num;

	/* range section */
	for (sec_num = 0, sec_size = 0, ref = ref_first[ITMC_OBJ_RANGE];
	    ref; sec_num += 1, sec_size += ref->size, ref = ref->next) {}
	sec_size = ITMROUNDUP(sec_size);
	info_header->range_plc_tbl.size = sec_num * (sizeof (itm_place_t));
	info_header->range_plc_tbl.number = sec_num;
	info_header->range_tbl_sec.size = sec_size;
	info_header->range_tbl_sec.number = sec_num;

	/* escapeseq section */
	for (sec_num = 0, sec_size = 0, ref = ref_first[ITMC_OBJ_ESCAPESEQ];
	    ref; sec_num += 1, sec_size += ref->size, ref = ref->next) {}
	sec_size = ITMROUNDUP(sec_size);
	info_header->escapeseq_plc_tbl.size = sec_num * (sizeof (itm_place_t));
	info_header->escapeseq_plc_tbl.number = sec_num;
	info_header->escapeseq_tbl_sec.size = sec_size;
	info_header->escapeseq_tbl_sec.number = sec_num;

	/* data section */
	for (sec_num = 0, sec_size = 0, ref = ref_first[ITMC_OBJ_DATA];
	    ref; sec_num += 1, sec_size += ref->size, ref = ref->next) {}
	for (ref = ref_first[ITMC_OBJ_EXPR];
	    ref; sec_num += 1, sec_size += ref->size, ref = ref->next) {}
	sec_size = ITMROUNDUP(sec_size);
	info_header->data_plc_tbl.size = ((sizeof (itm_place_t)) * sec_num);
	info_header->data_plc_tbl.number = sec_num;
	info_header->data_sec.size = sec_size;
	info_header->data_sec.number = sec_num;


	/* name section */
	sec_num2 = 0;
	for (sec_num = 0, sec_size = 0, name = name_first;
	    name; name = name->next) {
		if ((ITMC_OBJ_REGISTER != name->type) &&
		    (0 != name->name.size)) {
			if ((sizeof (itm_place_t)) < name->name.size) {
				sec_size += name->name.size;
				sec_num2 += 1;
			}
			sec_num += 1;
		}
	}
	info_header->name_plc_tbl.size = ((sizeof (itm_data_t))	* sec_num);
	info_header->name_plc_tbl.number = sec_num;

	for (sec_num = 0, name = name_first; name; name = name->next) {
		if ((ITMC_OBJ_REGISTER == name->type) &&
		    (0 != name->name.size)) {
			if ((sizeof (itm_place_t)) < name->name.size) {
				sec_size += name->name.size;
				sec_num2 += 1;
			}
			sec_num += 1;
		}
	}
	sec_size = ITMROUNDUP(sec_size);
	info_header->reg_plc_tbl.size =
		((sizeof (itm_data_t)) * (itm_header->reg_num));
	info_header->reg_plc_tbl.number = itm_header->reg_num;

	info_header->name_sec.size = sec_size;
	info_header->name_sec.number = sec_num2;

	/*
	 * adjust place
	 */
	info_header->str_sec.place.itm_ptr =
		0 +
		(sizeof (itm_hdr_t));
	info_header->direc_tbl_sec.place.itm_ptr =
		info_header->str_sec.place.itm_ptr +
		info_header->str_sec.size;
	info_header->cond_tbl_sec.place.itm_ptr =
		info_header->direc_tbl_sec.place.itm_ptr +
		info_header->direc_tbl_sec.size;
	info_header->map_tbl_sec.place.itm_ptr =
		info_header->cond_tbl_sec.place.itm_ptr +
		info_header->cond_tbl_sec.size;
	info_header->op_tbl_sec.place.itm_ptr =
		info_header->map_tbl_sec.place.itm_ptr +
		info_header->map_tbl_sec.size;

	info_header->range_tbl_sec.place.itm_ptr =
		info_header->op_tbl_sec.place.itm_ptr +
		info_header->op_tbl_sec.size;

	info_header->escapeseq_tbl_sec.place.itm_ptr =
		info_header->range_tbl_sec.place.itm_ptr +
		info_header->range_tbl_sec.size;

	info_header->data_sec.place.itm_ptr =
		info_header->escapeseq_tbl_sec.place.itm_ptr +
		info_header->escapeseq_tbl_sec.size;

	/*
	 * adjust place: optional
	 */

	if (0 == cmd_opt.strip) {
		itm_header->info_hdr.itm_ptr =
			info_header->data_sec.place.itm_ptr +
			info_header->data_sec.size;

		info_header->direc_plc_tbl.place.itm_ptr =
			itm_header->info_hdr.itm_ptr +
			(sizeof (itm_info_hdr_t));
		info_header->cond_plc_tbl.place.itm_ptr =
			info_header->direc_plc_tbl.place.itm_ptr +
			info_header->direc_plc_tbl.size;
		info_header->map_plc_tbl.place.itm_ptr =
			info_header->cond_plc_tbl.place.itm_ptr +
			info_header->cond_plc_tbl.size;
		info_header->op_plc_tbl.place.itm_ptr =
			info_header->map_plc_tbl.place.itm_ptr +
			info_header->map_plc_tbl.size;

		info_header->str_plc_tbl.place.itm_ptr =
			info_header->op_plc_tbl.place.itm_ptr +
			info_header->op_plc_tbl.size;
		info_header->range_plc_tbl.place.itm_ptr =
			info_header->str_plc_tbl.place.itm_ptr +
			info_header->str_plc_tbl.size;
		info_header->escapeseq_plc_tbl.place.itm_ptr =
			info_header->range_plc_tbl.place.itm_ptr +
			info_header->range_plc_tbl.size;
		info_header->data_plc_tbl.place.itm_ptr =
			info_header->escapeseq_plc_tbl.place.itm_ptr +
			info_header->escapeseq_plc_tbl.size;
		info_header->name_plc_tbl.place.itm_ptr =
			info_header->data_plc_tbl.place.itm_ptr +
			info_header->data_plc_tbl.size;
		info_header->reg_plc_tbl.place.itm_ptr =
			info_header->name_plc_tbl.place.itm_ptr +
			info_header->name_plc_tbl.size;

		/* name SECTION */
		info_header->name_sec.place.itm_ptr =
			info_header->reg_plc_tbl.place.itm_ptr +
			info_header->reg_plc_tbl.size;
	}

	/*
	 * size of ITM
	 */

	if (0 == cmd_opt.strip) {
		itm_header->itm_size.itm_ptr =
			info_header->name_sec.place.itm_ptr +
			info_header->name_sec.size;
	} else {
		itm_header->itm_size.itm_ptr =
			info_header->data_sec.place.itm_ptr +
			info_header->data_sec.size;
	}


	/*
	 * trace
	 */

#if defined(ENABLE_TRACE)
	dump_itm_header(itm_header, info_header);
#endif
}


/*
 * Fix referencer of itmc_ref_t
 */

static void
relocation_II(itm_hdr_t	*itm_header, itm_info_hdr_t	*info_header)
{
	itmc_ref_t	*ref;
	itmc_name_t	*name;
	itmc_ref_link_t	*rl;
	itm_place2_t	place;
	itm_place2_t	n_plc;

	/*
	 * reloc
	 */

	/* string section */
	TRACE_MESSAGE('3', ("string section\n"));
	place = info_header->str_sec.place.itm_ptr;
	for (ref = ref_first[ITMC_OBJ_STRING];
	    ref; place += ref->size, ref = ref->next) {
		fix_itmc_ref_reloc(ref, place);
	}

	/* direction */
	TRACE_MESSAGE('3', ("direction\n"));
	place = info_header->direc_tbl_sec.place.itm_ptr;
	for (ref = ref_first[ITMC_OBJ_DIREC];
	    ref; place += ref->size, ref = ref->next) {
		fix_itmc_ref_reloc(ref, place);
	}

	/* condition */
	TRACE_MESSAGE('3', ("condition\n"));
	place = info_header->cond_tbl_sec.place.itm_ptr;
	for (ref = ref_first[ITMC_OBJ_COND];
	    ref; place += ref->size, ref = ref->next) {
		fix_itmc_ref_reloc(ref, place);
	}

	/* map */
	TRACE_MESSAGE('3', ("map\n"));
	place = info_header->map_tbl_sec.place.itm_ptr;
	for (ref = ref_first[ITMC_OBJ_MAP];
	    ref; place += ref->size, ref = ref->next) {
		fix_itmc_ref_reloc(ref, place);
	}

	/* operation */
	TRACE_MESSAGE('3', ("operation\n"));
	place = info_header->op_tbl_sec.place.itm_ptr;
	for (ref = ref_first[ITMC_OBJ_OP];
	    ref; place += ref->size, ref = ref->next) {
		fix_itmc_ref_reloc(ref, place);
	}

	/* range */
	place = info_header->range_tbl_sec.place.itm_ptr;
	for (ref = ref_first[ITMC_OBJ_RANGE];
	    ref; place += ref->size, ref = ref->next) {
		fix_itmc_ref_reloc(ref, place);
	}

	/* escape sequence */
	place = info_header->escapeseq_tbl_sec.place.itm_ptr;
	for (ref = ref_first[ITMC_OBJ_ESCAPESEQ];
	    ref; place += ref->size, ref = ref->next) {
		fix_itmc_ref_reloc(ref, place);
	}
	/* data section */
	TRACE_MESSAGE('3', ("data section\n"));
	place = info_header->data_sec.place.itm_ptr;
	for (ref = ref_first[ITMC_OBJ_DATA];
	    ref; place += ref->size, ref = ref->next) {
		fix_itmc_ref_reloc(ref, place);
	}
	for (ref = ref_first[ITMC_OBJ_EXPR];
	    ref; place += ref->size, ref = ref->next) {
		fix_itmc_ref_reloc(ref, place);
	}

	/* name section */
	TRACE_MESSAGE('3', ("name section\n"));
	place = info_header->name_plc_tbl.place.itm_ptr;
	n_plc = info_header->name_sec.place.itm_ptr;
	for (name = name_first; name; name = name->next) {
		if ((NULL == name->object) ||
		    (ITMC_OBJ_REGISTER == name->type) ||
		    (0 == name->name.size)) {
			continue;
		}
		if ((sizeof (itm_place_t)) < name->name.size) {
			name->reloc.itm_ptr = n_plc;
			n_plc += name->name.size;
		}
		if (name->object->referencee) {
			((itm_tbl_hdr_t *)(name->object->referencee))->
			name.itm_ptr = place;
		}
		place += (intptr_t)(sizeof (itm_data_t));
	}
	place = info_header->reg_plc_tbl.place.itm_ptr;
	for (name = name_first; name; name = name->next) {
		if ((ITMC_OBJ_REGISTER != name->type) ||
		    (0 == name->name.size)) {
			continue;
		}
		if ((sizeof (itm_place_t)) < name->name.size) {
#if !defined(_LP64)
			name->reloc.itm_pad = 0;
#endif
			name->reloc.itm_ptr = n_plc;
			n_plc += name->name.size;
		}
		place += (sizeof (itm_data_t));
	}
	for (name = name_first; name; name = name->next) {
		if (ITMC_OBJ_REGISTER == name->type) {
			assert(NULL == name->object);
			continue;
		}
		if (NULL == name->object) {
			itm_error(
			gettext(
			"reference to %1$s \"%2$s\" is not resolved\n"),
			itm_name_type_name[name->type],
			name_to_str(&(name->name)));
			error_deferred += 1;
			continue;
		} /* else */
		assert(0 != name->name.size);
		for (rl = name->ref_first; rl; rl = rl->next) {
			fix_itmc_ref_reloc(rl->ref,
					name->object->reloc.itm_ptr);
		}
		if (NULL == name->object->referencee) {
			itm_error(
				gettext(
				"reference to %1$s \"%2$s\" is not resolved\n"),
				itm_name_type_name[name->type],
				name_to_str(&(name->name)));
			error_deferred += 1;
		}
		if (((ITMC_OBJ_REGISTER != name->type) &&
		    (ITMC_OBJ_DIREC != name->type) &&
		    ((ITMC_OBJ_MAP != name->type) ||
		    (NULL != ref_first[ITMC_OBJ_DIREC]))) &&
		    (NULL == name->ref_first)) {
			itm_error(
				gettext(
				"%1$s \"%2$s\" is defined, but not referred\n"),
					itm_name_type_name[name->type],
					name_to_str(&(name->name)));
				error_deferred += 1;
		}
	}


	/*
	 * initial direction table
	 */
	TRACE_MESSAGE('3', ("initial direction table\n"));
	if (NULL != ref_first[ITMC_OBJ_DIREC]) {
		itm_header->direc_init_tbl = ref_first[ITMC_OBJ_DIREC]->reloc;
	} else if (NULL != ref_first[ITMC_OBJ_MAP]) {
		itm_header->direc_init_tbl = ref_first[ITMC_OBJ_MAP]->reloc;
	} else {
		itm_error(gettext("No direction nor map\n"));
		exit(ITMC_STATUS_BT);
	}

	/*
	 * init operation and reset operation
	 */
	for (ref = ref_first[ITMC_OBJ_OP];
	    ref; place += ref->size, ref = ref->next) {
		switch (((itm_tbl_hdr_t *)(ref->referencee))->type) {
		case ITM_TBL_OP_INIT:
			itm_header->op_init_tbl = ref->reloc;
			break;
		case ITM_TBL_OP_RESET:
			itm_header->op_reset_tbl = ref->reloc;
			break;
		default:
			break;
		}
	}
}


/*
 * Fix reloc and referencer
 */
static void
fix_itmc_ref_reloc(itmc_ref_t	*ref, itm_place2_t place)
{
	itmc_ref_link_t		*rl;

	ref->reloc.itm_ptr = place;
#if !defined(_LP64)
	ref->reloc.itm_pad = 0;
#endif

	if (NULL != ref->referencer) {
		ref->referencer->itm_ptr = place;
	}

	TRACE_MESSAGE('f', ("fix_itmc_ref_reloc: 0x%08p 0x%08p %p\n",
			ref, ref->referencer, place));
	TRACE_MESSAGE('F', ("fix_itmc_ref_reloc: \"%s\"\n",
			name_to_str(ref->name ? &(ref->name->name) : NULL)));

	if (NULL != ref->name) {
		for (rl = ref->name->ref_first; rl; rl = rl->next) {
			if ((NULL != rl->ref) &&
			    (NULL != rl->ref->referencer)) {
				rl->ref->referencer->itm_ptr = place;
				TRACE_MESSAGE('f',
						("fix_itmc_ref_reloc: "
						"0x%08p 0x%08p\n",
						rl->ref, rl->ref->referencer));
				TRACE_MESSAGE('F',
						("fix_itmc_ref_reloc: \"%s\"\n",
						name_to_str(ref->name ?
							&(ref->name->name) :
							NULL)));
			}
		}
	}
}

/*
 * Analysis
 */
static void
analysis(itm_info_hdr_t	*info_header)
{
	itmc_ref_t	*ref;
	itm_place2_t	place;
	itm_type_t	obj_type;
	enum { ONEMAP, ZEROMAP}	onemap = ZEROMAP;

	TRACE_MESSAGE('4', ("Analysis\n"));

	place = info_header->str_sec.place.itm_ptr;
	for (obj_type = ITMC_OBJ_FIRST; obj_type <= ITMC_OBJ_LAST; obj_type++) {
		if (ITMC_OBJ_DIREC == obj_type) {
			continue;
		}

		for (ref = ref_first[obj_type];
		    ref; place += ref->size, ref = ref->next) {
			if ((NULL == ref->name) &&
			    (NULL == ref->referencer)) {
				itm_tbl_hdr_t	*tbl_hdr;
				char		*tbl_type;
				tbl_hdr = (itm_tbl_hdr_t *)(ref->referencee);
				if ((ITM_TBL_OP_RESET == tbl_hdr->type) ||
				    (ITM_TBL_OP_INIT == tbl_hdr->type)) {
					continue;
				} else if ((ITM_TBL_MAP ==
					(ITM_TBL_MASK & tbl_hdr->type)) &&
					(NULL == ref_first[ITMC_OBJ_DIREC])) {
					if (ZEROMAP == onemap) {
						onemap = ONEMAP;
						continue;
					} else {
						itm_error(
						gettext("multiple unamed map's "
							"defined\n"));
						error_deferred += 1;
						continue;
					}
				}
				switch (ITM_TBL_MASK & tbl_hdr->type) {
				case ITM_TBL_ITM:
					tbl_type =
					itm_name_type_name[ITMC_OBJ_ITM];
					break;
				case ITM_TBL_DIREC:
					tbl_type =
					itm_name_type_name[ITMC_OBJ_DIREC];
					break;
				case ITM_TBL_COND:
					tbl_type =
					itm_name_type_name[ITMC_OBJ_COND];
					break;
				case ITM_TBL_OP:
					tbl_type =
					itm_name_type_name[ITMC_OBJ_OP];
					break;
				case ITM_TBL_MAP:
					tbl_type =
					itm_name_type_name[ITMC_OBJ_MAP];
					break;
				case ITM_TBL_RANGE:
					tbl_type =
					itm_name_type_name[ITMC_OBJ_RANGE];
					break;
				case ITM_TBL_ESCAPESEQ:
					tbl_type =
					itm_name_type_name[ITMC_OBJ_ESCAPESEQ];
					break;
				default:
					tbl_type =
					itm_name_type_name[ITMC_OBJ_NONE];
					break;
				}
				itm_error(
					gettext("unnamed %1$s-type object is "
					"defined, but not referenced\n"),
					tbl_type);
				error_deferred += 1;
			}
		}
	}
}

/*
 * Analysis2 (check #nest of operation)
 */
#define	NIL -1
static void
analysis2(void)
{
	int			i, j, k, n_op;
	itmc_ref_t		*ref;
	itm_op_outer_t		*o, *o_prev;
	itm_op_inner_t		*in, *in_prev;
	int			indegree_zero;
	struct op_nest_vertex {
		itmc_ref_t	*ref; /* corresponding object's ref */
		int		indegree; /* indegree */
		struct op_nest_edge *e; /* link of edge list */
		int		z_link; /* index of indegree zero */
		int		n_nest;
	};
	struct op_nest_edge {
		struct op_nest_edge *e; /* link of edge list */
		int		index;	/* index of edge */
	};
	struct op_nest_vertex	*vertexes;
	struct op_nest_edge	*e, *e_prev;

	TRACE_MESSAGE('5', ("Analysis2\n"));

#ifdef ENABLE_TRACE
	for (o = itm_op_outer; o != NULL; o = o->link) {
		TRACE_MESSAGE('L', ("op(table)%x\n", o->optbl));
	}
#endif
	i = 0;
	for (o = itm_op_outer; o != NULL; o = o->link) {
		for (ref = ref_first[ITMC_OBJ_OP]; ref != NULL;
			ref = ref->next) {
			if (o->optbl == ref->referencee) {
				if (ref->name != NULL) {
					o->ref = ref->name->object;
				} else {
					o->ref = ref;
				}
				TRACE_MESSAGE('l', ("op(table)%x<-ref(%x)\n",
					o->optbl, o->ref));
				o->ref->vertex_index = i;
				i++;
				break;
			}
		}
	}

	n_op = i;
	if (n_op == 0)
		return;
	vertexes = (struct op_nest_vertex *)(malloc_vital(
		sizeof (struct op_nest_vertex) * n_op));

	for (o = itm_op_outer; o != NULL; o = o->link) {
		if (o->ref == NULL) {
			continue;
		}
		vertexes[o->ref->vertex_index].ref = o->ref;
		vertexes[o->ref->vertex_index].e = NULL;
	}

	for (o = itm_op_outer; o != NULL; o_prev = o,
		o = o->link, free(o_prev)) {
		if (o->ref == NULL) {
			continue;
		}
		TRACE_MESSAGE('l', ("vertexes[%d].ref=%x (optbl=%x(%s))\n",
			o->ref->vertex_index, o->ref, o->ref->referencee,
			name_to_str(o->ref->name == NULL ? NULL :
			&(o->ref->name->name))));
		for (in = o->in; in != NULL;
			in_prev = in, in = in->in, free(in_prev)) {
			/* make edge */
			i = o->ref->vertex_index;
			j = in->ref->name->object->vertex_index;
			e = malloc_vital(sizeof (struct op_nest_edge));
			e->index = j;
			e->e = vertexes[i].e;
			vertexes[i].e = e;
			vertexes[j].indegree++;
			TRACE_MESSAGE('l',
				(" edge: vertexes[%d]:(%s) ->vertex[%d]:(%s)\n",
				i,
				name_to_str(
				(vertexes[i].ref->name == NULL) ? NULL :
				&(vertexes[i].ref->name->name)),
				j,
				name_to_str(
				(vertexes[j].ref->name == NULL) ? NULL :
				&(vertexes[j].ref->name->name))));
		}
	}

	indegree_zero = NIL;
	for (i = 0; i < n_op; i++) {
		if (vertexes[i].indegree == 0) {
			vertexes[i].z_link = indegree_zero;
			indegree_zero = i;
		}
	}

	for (i = 0; i < n_op; i++) {
		if (indegree_zero == NIL) {
			itm_error(
				gettext("operation loop detected\n"));
			exit(ITMC_STATUS_BT2);
		}
		k = indegree_zero;
		indegree_zero = vertexes[indegree_zero].z_link;

		if (vertexes[k].n_nest > MAXOPNEST) {
			itm_error(
				gettext("operation nested more than %d\n"),
				MAXOPNEST);
			exit(ITMC_STATUS_BT2);
		}
		TRACE_MESSAGE('l',
			("take out first vertex: vertexes[%d] (i.e.%s) "
			"#depth=%d\n", k, name_to_str(
			(vertexes[k].ref->name == NULL) ? NULL :
			&(vertexes[k].ref->name->name)),
			vertexes[k].n_nest));

		for (e = vertexes[k].e; e != NULL;
			e_prev = e, e = e->e, free(e_prev)) {
			j = e->index;
			if (vertexes[j].n_nest < vertexes[k].n_nest + 1) {
				vertexes[j].n_nest =
					vertexes[k].n_nest + 1;
			}
			TRACE_MESSAGE('l', ("	+->vertexes[%d]:(%s) "
				"(#indegree=%d,#depth = %d)\n",
				j, name_to_str(&(vertexes[j].ref->name->name)),
				vertexes[j].indegree, vertexes[j].n_nest));
			vertexes[j].indegree--;
			if (vertexes[j].indegree == 0) {
				vertexes[j].z_link = indegree_zero;
				indegree_zero = j;
			}
		}
	}
	free(vertexes);
}
#undef NIL

/*
 * Output ITM compiled data
 */
void
output(itm_hdr_t	*itm_header, itm_info_hdr_t	*info_header)
{
	itmc_ref_t	*ref;
	itmc_name_t	*name;
	itm_size_t	sec_size;
	struct stat	st_buf;
	int		fd;
	FILE		*fp;

	if (cmd_opt.no_output) {
		return;
	} else if (NULL == itm_output_file) {
		fd = 1;
		TRACE_MESSAGE('o', ("file=(stdout)\n"));
	} else {
		TRACE_MESSAGE('o', ("file=%s\n", itm_output_file));
		switch (stat(itm_output_file, &st_buf)) {
		case 0:
			if (0 == cmd_opt.force_overwrite) {
				itm_error(
					gettext("target file exists\n"));
				exit(ITMC_STATUS_CMD2);
			}
			break;
		case -1:
			if (ENOENT != errno) {
				PERROR(gettext("stat"));
				exit(ITMC_STATUS_CMD2);
			}
			break;
		default:
			PERROR(gettext("stat"));
			exit(ITMC_STATUS_SYS);
			break;
		}

		fd = open(itm_output_file, O_CREAT|O_WRONLY|O_TRUNC, 0666);
		if (fd == -1) {
			PERROR(gettext("open"));
			exit(ITMC_STATUS_SYS);
		}
	}
	fp = fdopen(fd, "w");
	if (NULL == fp) {
		PERROR(gettext("fdopen"));
		exit(ITMC_STATUS_SYS);
	}

	if (1 == cmd_opt.strip) {
		itm_header->info_hdr.itm_ptr = 0;
	}

	/* ITM header */
	(void) fseek(fp, 0, SEEK_SET);
	(void) fwrite(itm_header, sizeof (itm_hdr_t), 1, fp);

	/* string section */
	(void) fseek(fp, info_header->str_sec.place.itm_ptr, SEEK_SET);
	TRACE_MESSAGE('P', ("str_sec.place.place=%p:\n",
		info_header->str_sec.place.itm_ptr));
	for (ref = ref_first[ITMC_OBJ_STRING]; ref; ref = ref->next) {
		(void) fwrite((void *)(ref->referencee), 1, ref->size, fp);
	}

	/* direction */
	(void) fseek(fp, info_header->direc_tbl_sec.place.itm_ptr, SEEK_SET);
	TRACE_MESSAGE('P', ("direc_tbl_sec.place=%p:\n",
		info_header->direc_tbl_sec.place.itm_ptr));
	for (ref = ref_first[ITMC_OBJ_DIREC]; ref; ref = ref->next) {
		(void) fwrite((void *)(ref->referencee), ref->size, 1, fp);
	}

	/* condition */
	(void) fseek(fp, info_header->cond_tbl_sec.place.itm_ptr, SEEK_SET);
	TRACE_MESSAGE('P', ("cond_tbl_sec.place=%p:\n",
		info_header->cond_tbl_sec.place.itm_ptr));
	for (ref = ref_first[ITMC_OBJ_COND]; ref; ref = ref->next) {
		(void) fwrite((void *)(ref->referencee), ref->size, 1, fp);
	}

	/* map */
	(void) fseek(fp, info_header->map_tbl_sec.place.itm_ptr, SEEK_SET);
	TRACE_MESSAGE('P', ("map_tbl_sec.place=%p:\n",
		info_header->map_tbl_sec.place.itm_ptr));
	for (ref = ref_first[ITMC_OBJ_MAP]; ref; ref = ref->next) {
		(void) fwrite((void *)(ref->referencee), ref->size, 1, fp);
	}

	/* operation */
	(void) fseek(fp, info_header->op_tbl_sec.place.itm_ptr, SEEK_SET);
	TRACE_MESSAGE('P', ("op_tbl_sec.place=%p:\n",
		info_header->op_tbl_sec.place.itm_ptr));
	for (ref = ref_first[ITMC_OBJ_OP]; ref; ref = ref->next) {
		(void) fwrite((void *)(ref->referencee), ref->size, 1, fp);
	}

	/* range */
	(void) fseek(fp, info_header->range_tbl_sec.place.itm_ptr, SEEK_SET);
	TRACE_MESSAGE('P', ("range_tbl_sec.place=%p:\n",
		info_header->range_tbl_sec.place.itm_ptr));
	for (ref = ref_first[ITMC_OBJ_RANGE]; ref; ref = ref->next) {
		(void) fwrite((void *)(ref->referencee), ref->size, 1, fp);
	}

	/* escape sequence */
	(void) fseek(fp, info_header->escapeseq_tbl_sec.place.itm_ptr,
		SEEK_SET);
	TRACE_MESSAGE('P', ("escapeseq_tbl_sec.place=%p:\n",
		info_header->escapeseq_tbl_sec.place.itm_ptr));
	for (ref = ref_first[ITMC_OBJ_ESCAPESEQ]; ref; ref = ref->next) {
		(void) fwrite((void *)(ref->referencee), ref->size, 1, fp);
	}

	/* data section */
	sec_size = 0;
	(void) fseek(fp, info_header->data_sec.place.itm_ptr, SEEK_SET);
	TRACE_MESSAGE('P', ("data_sec.place=%p:\n",
		info_header->data_sec.place.itm_ptr));
	for (ref = ref_first[ITMC_OBJ_DATA]; ref; ref = ref->next) {
		(void) fwrite((void *)(ref->referencee), ref->size, 1, fp);
		sec_size += ref->size;
	}
	for (ref = ref_first[ITMC_OBJ_EXPR]; ref; ref = ref->next) {
		(void) fwrite((void *)(ref->referencee), ref->size, 1, fp);
		sec_size += ref->size;
	}
	if (0 != cmd_opt.strip) {
		if (sec_size < info_header->data_sec.size) {
			(void) fwrite("\0\0\0\0", 1,
				info_header->data_sec.size - sec_size, fp);
		}
	} else {

		/* ITM Info header */
		(void) fseek(fp, itm_header->info_hdr.itm_ptr, SEEK_SET);
		TRACE_MESSAGE('P', ("info_hdr=%p:\n",
			itm_header->info_hdr.itm_ptr));
		(void) fwrite(info_header, sizeof (itm_info_hdr_t), 1, fp);

		(void) fseek(fp, info_header->direc_plc_tbl.place.itm_ptr,
			SEEK_SET);
		TRACE_MESSAGE('P', ("direc_plc_tbl.place=%p:\n",
			info_header->direc_plc_tbl.place.itm_ptr));
		for (ref = ref_first[ITMC_OBJ_DIREC]; ref; ref = ref->next) {
			(void) fwrite(&(ref->reloc),
				sizeof (itm_place_t), 1, fp);
		}

		(void) fseek(fp, info_header->cond_plc_tbl.place.itm_ptr,
			SEEK_SET);
		TRACE_MESSAGE('P', ("cond_plc_tbl.place=%p:\n",
			info_header->cond_plc_tbl.place.itm_ptr));

		for (ref = ref_first[ITMC_OBJ_COND]; ref; ref = ref->next) {
			(void) fwrite(&(ref->reloc),
				sizeof (itm_place_t), 1, fp);
		}

		(void) fseek(fp, info_header->map_plc_tbl.place.itm_ptr,
			SEEK_SET);
		TRACE_MESSAGE('P', ("map_plc_tbl.place=%p:\n",
			info_header->map_plc_tbl.place.itm_ptr));

		for (ref = ref_first[ITMC_OBJ_MAP]; ref; ref = ref->next) {
			(void) fwrite(&(ref->reloc),
				sizeof (itm_place_t), 1, fp);
		}

		(void) fseek(fp, info_header->op_plc_tbl.place.itm_ptr,
			SEEK_SET);
		TRACE_MESSAGE('P', ("op_plc_tbl.place=%p:\n",
			info_header->op_plc_tbl.place.itm_ptr));
		for (ref = ref_first[ITMC_OBJ_OP]; ref; ref = ref->next) {
			(void) fwrite(&(ref->reloc),
				sizeof (itm_place_t), 1, fp);
		}

		(void) fseek(fp, info_header->str_plc_tbl.place.itm_ptr,
			SEEK_SET);
		TRACE_MESSAGE('P', ("str_plc_tbl.place=%p:\n",
			info_header->str_plc_tbl.place.itm_ptr));

		for (ref = ref_first[ITMC_OBJ_STRING]; ref; ref = ref->next) {
			itm_data_t	data;
#if !defined(_LP64)
			data.place.itm_pad = 0;
			data.pad = 0;
#endif
			data.place = ref->reloc;
			data.size = ref->size;
			(void) fwrite(&data, sizeof (itm_data_t), 1, fp);
		}

		(void) fseek(fp, info_header->range_plc_tbl.place.itm_ptr,
			SEEK_SET);
		TRACE_MESSAGE('P', ("range_plc_tbl.place=%p:\n",
			info_header->range_plc_tbl.place.itm_ptr));
		for (ref = ref_first[ITMC_OBJ_RANGE]; ref; ref = ref->next) {
			(void) fwrite(&(ref->reloc),
				sizeof (itm_place_t), 1, fp);
		}
		(void) fseek(fp, info_header->escapeseq_plc_tbl.place.itm_ptr,
			SEEK_SET);
		TRACE_MESSAGE('P', ("escapeseq_plc_tbl.place=%p:\n",
			info_header->escapeseq_plc_tbl.place.itm_ptr));
		for (ref = ref_first[ITMC_OBJ_ESCAPESEQ];
		    ref; ref = ref->next) {
			(void) fwrite(&(ref->reloc),
				sizeof (itm_place_t), 1, fp);
		}

		(void) fseek(fp, info_header->data_plc_tbl.place.itm_ptr,
			SEEK_SET);
		TRACE_MESSAGE('P', ("data_plc_tbl.place=%p:\n",
			info_header->data_plc_tbl.place.itm_ptr));
		for (ref = ref_first[ITMC_OBJ_DATA]; ref; ref = ref->next) {
			(void) fwrite(&(ref->reloc),
				sizeof (itm_place_t), 1, fp);
		}
		for (ref = ref_first[ITMC_OBJ_EXPR]; ref; ref = ref->next) {
			(void) fwrite(&(ref->reloc),
				sizeof (itm_place_t), 1, fp);
		}

		(void) fseek(fp, info_header->name_plc_tbl.place.itm_ptr,
			SEEK_SET);
		TRACE_MESSAGE('P', ("name_plc_tbl.place=%p:\n",
			info_header->name_plc_tbl.place.itm_ptr));
		for (name = name_first, sec_size = 0;
		    name; name = name->next) {
			itm_data_t	data;
			if ((ITMC_OBJ_REGISTER == name->type) ||
			    (0 == name->name.size)) {
				continue;
			}
			data.size = name->name.size;
#if !defined(_LP64)
			data.pad = 0;
#endif
			if ((sizeof (itm_place_t)) < data.size) {
#if !defined(_LP64)
				data.place.itm_pad = 0;
#endif
				data.place.itm_ptr = name->reloc.itm_ptr;
			} else {
				data.place = name->name.place;
			}
			(void) fwrite(&data, sizeof (itm_data_t), 1, fp);
		}

		(void) fseek(fp, info_header->reg_plc_tbl.place.itm_ptr,
			SEEK_SET);
		TRACE_MESSAGE('P', ("reg_plc_tbl.place=%p:\n",
			info_header->reg_plc_tbl.place.itm_ptr));

		for (name = name_first;
		    name; name = name->next) {
			itm_data_t	data;
			if ((ITMC_OBJ_REGISTER != name->type) ||
			    (0 == name->name.size)) {
				continue;
			}
#if !defined(_LP64)
			data.pad = 0;
#endif
			data.size = name->name.size;
			if ((sizeof (itm_place_t)) < data.size) {
#if !defined(_LP64)
				data.place.itm_pad = 0;
#endif
				data.place.itm_ptr = name->reloc.itm_ptr;
			} else {
				data.place = name->name.place;
			}
			(void) fwrite(&data, sizeof (itm_data_t), 1, fp);
		}

		/* Name section */
		(void) fseek(fp, info_header->name_sec.place.itm_ptr, SEEK_SET);
		TRACE_MESSAGE('P', ("name_sec.place=%p:\n",
			info_header->name_sec.place.itm_ptr));
		for (name = name_first, sec_size = 0;
		    name; name = name->next) {
			if ((ITMC_OBJ_REGISTER == name->type) ||
			    (name->name.size <= (sizeof (itm_place_t)))) {
				continue;
			}
			(void) fwrite(NSPTR(&(name->name)), 1,
				name->name.size, fp);
			sec_size += name->name.size;
		}
		for (name = name_first; name; name = name->next) {
			if ((ITMC_OBJ_REGISTER != name->type) ||
			    (name->name.size <= (sizeof (itm_place_t)))) {
				continue;
			}
			(void) fwrite(NSPTR(&(name->name)), 1,
				name->name.size, fp);
			sec_size += name->name.size;
		}
		if (sec_size < info_header->name_sec.size) {
			(void) fwrite("\0\0\0\0", 1,
				info_header->name_sec.size - sec_size, fp);
		}
	}
	(void) fclose(fp);
}
