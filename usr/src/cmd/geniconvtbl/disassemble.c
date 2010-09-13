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


#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <libintl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include "iconv_tm.h"
#include "itm_util.h"

/*
 * function prototype
 */

static itm_hdr_t	*itm_attach(const char *);
static void	dump_tables(itm_hdr_t *, itm_info_hdr_t *);
static void	dump_direc_tbl(itm_hdr_t *, itm_place_t);
static void	dump_map(itm_hdr_t *, itm_place_t, int);
static void	dump_map_i_f(itm_hdr_t *, itm_place_t, int);
static void	dump_map_l_f(itm_hdr_t *, itm_place_t, int);
static void	dump_map_hash(itm_hdr_t *, itm_place_t, int);
static void	dump_map_dense_enc(itm_hdr_t *, itm_place_t, int);
static void	dump_cond_tbl(itm_hdr_t *, itm_place_t, int);
static void	dump_op_tbl(itm_hdr_t *, itm_place_t, int);
static void	dump_op(itm_hdr_t *, itm_place2_t);
static void	dump_expr(itm_hdr_t *, itm_place_t);
static void	dump_range(itm_hdr_t *, itm_place_t);
static void	dump_escapeseq(itm_hdr_t *, itm_place_t);

static char	*tbl_name(itm_hdr_t *, itm_tbl_hdr_t *);
static char	*reg_name(itm_hdr_t	*itm_hdr, itm_place_t op);

static void	printi(int, char *, ...);


/*
 * macro definition
 */

#define	ADDR(place)	((void *)(((char *)(itm_hdr)) + \
			((itm_place2_t)((place).itm_ptr))))
#define	DADDR(n)	(((n)->size <= (sizeof ((n)->place))) ?	\
				((char *)(&((n)->place))) :\
				((char *)(ADDR((n)->place))))
#define	ADDR2(place2)	((void *)(((char *)(itm_hdr)) + \
			((itm_place2_t)(place2))))
#define	INFO_HDR(pa)	((void *)(((char *)pa) + \
			((itm_hdr_t *)(pa))->info_hdr.itm_ptr))


#if defined(RESERVED_NAME_PREFIX)
#define	RNPREF		RESERVED_NAME_PREFIX
#else /* !defined(RESERVED_NAME_PREFIX) */
#define	RNPREF		/* null strings */
#endif /* !defined(RESERVED_NAME_PREFIX) */


void
disassemble(char	*file)
{
	itm_hdr_t	*itm_hdr;
	itm_info_hdr_t	*info_hdr;
	itm_data_t	type_id;

	TRACE_MESSAGE('d', ("disassemble %s\n", file));

	itm_hdr = itm_attach(file);

	if (NULL == itm_hdr) {
		exit(3);
	}

	if (0 == itm_hdr->info_hdr.itm_ptr) {
		itm_error(gettext("binarytable is stripped\n"));
		exit(4);
	}

	if (0 == itm_hdr->info_hdr.itm_ptr) {
		info_hdr = malloc_vital(sizeof (itm_info_hdr_t));
		(void) memset(info_hdr, 0, sizeof (itm_info_hdr_t));
	} else {
		info_hdr = INFO_HDR(itm_hdr);
	}

#if defined(ENABLE_TRACE)
	dump_itm_header(itm_hdr, info_hdr);
#endif
	printi(0, "//\n", file);
	printi(0, "// %s\n", file);
	printi(0, "//\n", file);

	type_id = itm_hdr->type_id;
	if ((NULL != cmd_opt.disassemble) &&
	    ((sizeof (itm_place_t)) < type_id.size)) {
		type_id.place.itm_ptr += (itm_place2_t)itm_hdr;
	}
	printi(1, "%s {\n", name_to_str(&type_id));
	dump_tables(itm_hdr, info_hdr);
	printi(-1, "}\n");
}

#if defined(ENABLE_TRACE)
void
dump_itm_header(itm_hdr_t	*itm_header, itm_info_hdr_t	*info_header)
{
	char	*str_type_id;
	char	*str_interpreter;

	itm_data_t	type_id;
	itm_data_t	interpreter;

	type_id = itm_header->type_id;
	str_type_id = malloc_vital(itm_header->type_id.size + 1);
	if ((NULL != cmd_opt.disassemble) &&
	    ((sizeof (itm_place_t)) < type_id.size)) {
		type_id.place.itm_ptr += (itm_place2_t)itm_header;
	}
	(void) memcpy(str_type_id, name_to_str(&type_id), type_id.size + 1);

	interpreter = itm_header->interpreter;
	str_interpreter = malloc_vital(itm_header->interpreter.size + 1);
	if ((NULL != cmd_opt.disassemble) &&
	    ((sizeof (itm_place_t)) < interpreter.size)) {
		interpreter.place.itm_ptr += (itm_place2_t)itm_header;
	}
	(void) memcpy(str_interpreter, name_to_str(&interpreter),
		interpreter.size + 1);

	TRACE_MESSAGE('D',
			("\n"
			"------\n"
			"Sizeof Data Structures \n"
			" sizeof(int)		    = %ld\n"
			" sizeof(long)		    = %ld\n"
			" sizeof(uintptr_t)	    = %ld\n"
			" sizeof(struct itm_place_t)  = %ld\n"
			" sizeof(struct itm_data_t)   = %ld\n"
			" sizeof(struct itm_hdr_t)    = %ld\n"
			" sizeof(struct itm_place_tbl_info_t)  = %ld\n"
			" sizeof(struct itm_section_info_t)    = %ld\n"
			" sizeof(struct itm_action_type_t)     = %ld\n"
			" sizeof(struct itm_direct_t)	= %ld\n"
			" sizeof(struct itm_cond_t)	= %ld\n"
			" sizeof(struct itm_range_hdr_t)       = %ld\n"
			" sizeof(struct itm_escapeseq_hdr_t)   = %ld\n"
			" sizeof(struct itm_map_idx_fix_hdr_t) = %ld\n"
			" sizeof(struct itm_map_lookup_hdr_t)  = %ld\n"
			" sizeof(struct itm_map_hash_hdr_t)    = %ld\n"
			" sizeof(struct itm_map_dense_enc_hdr_t) = %ld\n"
			" sizeof(struct itm_expr_t)   = %ld\n"
			" sizeof(enum itm_op_type_t)  = %ld\n"
			" sizeof(struct itm_op_t)     u= %ld\n"
			" sizeof(enum itm_expr_type_t)= %ld\n"
			"\n",

			sizeof (int),
			sizeof (long),
			sizeof (uintptr_t),
			sizeof (itm_place_t),
			sizeof (itm_data_t),
			sizeof (itm_hdr_t),
			sizeof (itm_place_tbl_info_t),
			sizeof (itm_section_info_t),
			sizeof (itm_action_type_t),
			sizeof (itm_direc_t),
			sizeof (itm_cond_t),
			sizeof (itm_range_hdr_t),
			sizeof (itm_escapeseq_hdr_t),
			sizeof (itm_map_idx_fix_hdr_t),
			sizeof (itm_map_lookup_hdr_t),
			sizeof (itm_map_hash_hdr_t),
			sizeof (itm_map_dense_enc_hdr_t),
			sizeof (itm_expr_t),
			sizeof (itm_op_type_t),
			sizeof (itm_op_t),
			sizeof (itm_expr_type_t)));

	TRACE_MESSAGE('H',
			("ident		= %c%c%c\n"
			"spec		= %02x%02x%02x%02x\n"
			"version	= %02x%02x%02x%02x\n"
			"itm_size	= %ld\n"
			"type_id	= %s\n"
			"interpreter	= %s\n"
			"op_init_tbl	= %ld\n"
			"op_reset_tbl	= %ld\n"
			"direc_init_tbl = %ld\n"
			"reg_num	= %ld\n"
			"itm_hdr_size	= %ld\n"
			"info_hdr	= %ld\n"
			"info_hdr_size	= %ld\n",

			itm_header->ident[0],
			itm_header->ident[1],
			itm_header->ident[2],
			/* itm_header->ident[3], */
			itm_header->spec[0],
			itm_header->spec[1],
			itm_header->spec[2],
			itm_header->spec[3],
			itm_header->version[0],
			itm_header->version[1],
			itm_header->version[2],
			itm_header->version[3],
			itm_header->itm_size.itm_ptr,
			str_type_id,
			str_interpreter,
			itm_header->op_init_tbl.itm_ptr,
			itm_header->op_reset_tbl.itm_ptr,
			itm_header->direc_init_tbl.itm_ptr,
			itm_header->reg_num,
			itm_header->itm_hdr_size,
			itm_header->info_hdr.itm_ptr,
			(sizeof (itm_info_hdr_t))));

	TRACE_MESSAGE('H',
			("  str_sec     = (%4ld %4ld %4ld)	"
			"  str_plc_tbl = (%4ld %4ld %4ld)\n"
			"direc_sec_tbl = (%4ld %4ld %4ld)	"
			"direc_plc_tbl = (%4ld %4ld %4ld)\n"
			" cond_sec_tbl = (%4ld %4ld %4ld)	"
			" cond_plc_tbl = (%4ld %4ld %4ld)\n"
			"  map_sec_tbl = (%4ld %4ld %4ld)	"
			"  map_plc_tbl = (%4ld %4ld %4ld)\n"
			"   op_sec_tbl = (%4ld %4ld %4ld)	"
			"   op_plc_tbl = (%4ld %4ld %4ld)\n"
			"range_sec_tbl = (%4ld %4ld %4ld)	"
			"range_plc_tbl = (%4ld %4ld %4ld)\n"
			"escsq_sec_tbl = (%4ld %4ld %4ld)	"
			"escsq_plc_tbl = (%4ld %4ld %4ld)\n"
			" data_sec     = (%4ld %4ld %4ld)	"
			" data_plc_tbl = (%4ld %4ld %4ld)\n"
			" name_sec     = (%4ld %4ld %4ld)	"
			" name_plc_tbl = (%4ld %4ld %4ld)\n"
			"					"
			"  reg_plc_tbl = (%4ld %4ld %4ld)\n"
			"%s\n",
			info_header->str_sec.place.itm_ptr,
			info_header->str_sec.size,
			info_header->str_sec.number,
			info_header->str_plc_tbl.place.itm_ptr,
			info_header->str_plc_tbl.size,
			info_header->str_plc_tbl.number,
			info_header->direc_tbl_sec.place.itm_ptr,
			info_header->direc_tbl_sec.size,
			info_header->direc_tbl_sec.number,
			info_header->direc_plc_tbl.place.itm_ptr,
			info_header->direc_plc_tbl.size,
			info_header->direc_plc_tbl.number,
			info_header->cond_tbl_sec.place.itm_ptr,
			info_header->cond_tbl_sec.size,
			info_header->cond_tbl_sec.number,
			info_header->cond_plc_tbl.place.itm_ptr,
			info_header->cond_plc_tbl.size,
			info_header->cond_plc_tbl.number,
			info_header->map_tbl_sec.place.itm_ptr,
			info_header->map_tbl_sec.size,
			info_header->map_tbl_sec.number,
			info_header->map_plc_tbl.place.itm_ptr,
			info_header->map_plc_tbl.size,
			info_header->map_plc_tbl.number,
			info_header->op_tbl_sec.place.itm_ptr,
			info_header->op_tbl_sec.size,
			info_header->op_tbl_sec.number,
			info_header->op_plc_tbl.place.itm_ptr,
			info_header->op_plc_tbl.size,
			info_header->op_plc_tbl.number,
			info_header->range_tbl_sec.place.itm_ptr,
			info_header->range_tbl_sec.size,
			info_header->range_tbl_sec.number,
			info_header->range_plc_tbl.place.itm_ptr,
			info_header->range_plc_tbl.size,
			info_header->range_plc_tbl.number,
			info_header->escapeseq_tbl_sec.place.itm_ptr,
			info_header->escapeseq_tbl_sec.size,
			info_header->escapeseq_tbl_sec.number,
			info_header->escapeseq_plc_tbl.place.itm_ptr,
			info_header->escapeseq_plc_tbl.size,
			info_header->escapeseq_plc_tbl.number,
			info_header->data_sec.place.itm_ptr,
			info_header->data_sec.size,
			info_header->data_sec.number,
			info_header->data_plc_tbl.place.itm_ptr,
			info_header->data_plc_tbl.size,
			info_header->data_plc_tbl.number,
			info_header->name_sec.place.itm_ptr,
			info_header->name_sec.size,
			info_header->name_sec.number,
			info_header->name_plc_tbl.place.itm_ptr,
			info_header->name_plc_tbl.size,
			info_header->name_plc_tbl.number,
			info_header->reg_plc_tbl.place.itm_ptr,
			info_header->reg_plc_tbl.size,
			info_header->reg_plc_tbl.number,
			"--------"));
}
#endif

/*
 * Dump tables
 */
static void
dump_tables(itm_hdr_t	*itm_hdr, itm_info_hdr_t	*info_hdr)
{
	itm_num_t	n;
	itm_data_t	*data;
	itm_place_t	*place;
	itm_place2_t	place2;
	itm_data_t	d;

	data = (itm_data_t *)(ADDR(info_hdr->reg_plc_tbl.place));
	for (n = 0; n < info_hdr->reg_plc_tbl.number; n++, data += 1) {
		d = *(data);
		if ((sizeof (itm_place_t)) < d.size) {
			d.place.itm_ptr = (itm_place2_t)ADDR(d.place);
		}
		printi(0, "// register: %s\n", name_to_str(&d));
	}

	data = (itm_data_t *)(ADDR(info_hdr->name_plc_tbl.place));
	for (n = 0, place2 = info_hdr->name_plc_tbl.place.itm_ptr;
	    n < info_hdr->name_plc_tbl.number;
	    n++, data += 1, place2 += sizeof (itm_data_t)) {
		d = *(data);

		if ((sizeof (itm_place_t)) < d.size) {
			d.place.itm_ptr = (itm_place2_t)ADDR(d.place);
		}
		TRACE_MESSAGE('p', ("(*)name=%ld",
				((sizeof (itm_place_t)) < d.size) ?
				d.place.itm_ptr:
				(place2 + offsetof(itm_data_t, place))));
		printi(0, "// name: %s\n", name_to_str(&d));

	}

	place = (itm_place_t *)(ADDR(info_hdr->cond_plc_tbl.place));
	for (n = 0; n < info_hdr->cond_plc_tbl.number; n++, place += 1) {
		dump_cond_tbl(itm_hdr, *place, 1);
	}
	place = (itm_place_t *)(ADDR(info_hdr->map_plc_tbl.place));
	for (n = 0; n < info_hdr->map_plc_tbl.number;
	    n++, place += 1) {
		dump_map(itm_hdr, *place, 1);
	}
	place = (itm_place_t *)(ADDR(info_hdr->op_plc_tbl.place));
	for (n = 0; n < info_hdr->op_plc_tbl.number;
	    n++, place += 1) {
		dump_op_tbl(itm_hdr, *place, 1);
	}
	place = (itm_place_t *)(ADDR(info_hdr->direc_plc_tbl.place));
	for (n = 0; n < info_hdr->direc_plc_tbl.number; n++, place += 1) {
		dump_direc_tbl(itm_hdr, *place);
	}
}


/*
 * Dump direction
 */
static void
dump_direc_tbl(itm_hdr_t	*itm_hdr, itm_place_t direc_place)
{
	itm_tbl_hdr_t	*direc_hdr;
	itm_direc_t	*direc;
	itm_type_t	type;
	long		i;
	char		*name;

	direc_hdr = (itm_tbl_hdr_t *)ADDR(direc_place);
	direc = (itm_direc_t *)(direc_hdr + 1);

	TRACE_MESSAGE('p', ("(&)direc=%ld ", direc_place.itm_ptr));

	printi(1, RNPREF "direction");
	if (0 != direc_hdr->name.itm_ptr) {
		name = tbl_name(itm_hdr, direc_hdr);
		if (NULL != name) {
			printi(0, " %s", name);
		}
	}
	printi(0, " {\n");

	for (i = 0; i < direc_hdr->number; i++, direc++) {
		dump_cond_tbl(itm_hdr, direc->condition, 0);

		printi(0, "\t");

		type = (ITM_TBL_MASK &
			(((itm_tbl_hdr_t *)(ADDR(direc->action)))->type));

		if (ITM_TBL_OP == type) {
			dump_op_tbl(itm_hdr, direc->action, 0);
		} else if (ITM_TBL_DIREC == type) {
			printi(0, "direction: action: %ld\n",
				direc->action.itm_ptr);
		} else if (ITM_TBL_MAP == type) {
			dump_map(itm_hdr, direc->action, 0);
		} else {
			printi(0, RNPREF
				"error ELIBBAD // unknown operation (%lx)\n",
				type);
		}
	}

	printi(-1, "};\n");
}


static void
dump_map(itm_hdr_t	*itm_hdr, itm_place_t map_place, int standalone)
{
	itm_tbl_hdr_t	*tbl_hdr;

	tbl_hdr = (itm_tbl_hdr_t *)ADDR(map_place);

	switch (tbl_hdr->type) {
	case ITM_TBL_MAP_INDEX_FIXED_1_1:
	case ITM_TBL_MAP_INDEX_FIXED:
		dump_map_i_f(itm_hdr, map_place, standalone);
		break;
	case ITM_TBL_MAP_LOOKUP:
		dump_map_l_f(itm_hdr, map_place, standalone);
		break;
	case ITM_TBL_MAP_HASH:
		dump_map_hash(itm_hdr, map_place, standalone);
		break;
	case ITM_TBL_MAP_DENSE_ENC:
		dump_map_dense_enc(itm_hdr, map_place, standalone);
		break;
	default:
		break;
	}
}


/*
 * Dump map-indexed-fixed
 */
static void
dump_map_i_f(itm_hdr_t		*itm_hdr, itm_place_t map_place, int standalone)
{
	itm_tbl_hdr_t		*tbl_hdr;
	itm_map_idx_fix_hdr_t	*map_hdr;
	itm_num_t		i;
	itm_num_t		j;
	unsigned char		*p;
	unsigned char		*map_error;
	char			*name;
	int			error_flag;

	TRACE_MESSAGE('d', ("dump_map_i_f\n"));

	tbl_hdr = (itm_tbl_hdr_t *)ADDR(map_place);
	map_hdr = (itm_map_idx_fix_hdr_t *)(tbl_hdr + 1);

	if (0 < map_hdr->error_num) {
		p = (unsigned char *)(map_hdr + 1);
		map_error = p + (map_hdr->result_len * (tbl_hdr->number));
		if (0 == map_hdr->default_error) {
			map_error += map_hdr->result_len;
		}
	} else if (1 == map_hdr->default_error) {
		p = (unsigned char *)(map_hdr + 1);
		map_error = p + (map_hdr->result_len * (tbl_hdr->number));
	} else {
		map_error = NULL;
	}

	if ((standalone) &&
	    (0 == tbl_hdr->name.itm_ptr) &&
	    (map_place.itm_ptr != itm_hdr->direc_init_tbl.itm_ptr)) {
		return;
	}

	TRACE_MESSAGE('p', ("(&)map=%ld ", map_place.itm_ptr));

	if (0 == tbl_hdr->name.itm_ptr) {
		name = NULL;
	} else {
		name = tbl_name(itm_hdr, tbl_hdr);
	}

	if ((0 == standalone) && (0 != tbl_hdr->name.itm_ptr)) {
		if (NULL != name) {
			printi(0, "%s;\n", name);
		} else {
			printi(0, RNPREF "unknown;\n", name);
		}
		return;
	} else {
		printi(1, RNPREF "map");
		if (NULL != name) {
			printi(0, " %s", name);
		}
		printi(0, " {\n");
	}

	printi(0, "//  simple indexed map\n");
	printi(0, "//  source_len=%ld result_len=%ld\n",
		map_hdr->source_len, map_hdr->result_len);
	printi(0, "//  start=0x%p end=0x%p\n", /* DO NOT CHANGE to %ld */
		map_hdr->start.itm_ptr, map_hdr->end.itm_ptr);
	if (0 < map_hdr->error_num) {
		printi(0, "//  error_num=%ld\n",
			map_hdr->error_num);
	}
	if (0 == map_hdr->default_error) {
		p = (((unsigned char *)(map_hdr + 1)) +
			(map_hdr->result_len *
			(map_hdr->end.itm_ptr - map_hdr->start.itm_ptr + 1)));
		printi(0, RNPREF "default 0x");
		for (j = 0; j < map_hdr->result_len; j++) {
			printi(0, "%02x", *(p + j));
		}
		printi(0, "\n");
	} else if (-1 == map_hdr->default_error) {
		printi(0, RNPREF "default\t" RNPREF "default\n");
	}
	error_flag = 0;
	for (i = 0; i <= (map_hdr->end.itm_ptr - map_hdr->start.itm_ptr); i++) {
		p = (((unsigned char *)(map_hdr + 1)) +
			(map_hdr->result_len * i));
		if ((NULL == map_error) ||
		    (0 == *(map_error + i))) {
			printi(0, "0x%0*p\t",
			(map_hdr->source_len * 2), i + map_hdr->start.itm_ptr);
			printi(0, "0x");
			for (j = 0; j < map_hdr->result_len; j++) {
				printi(0, "%02x", *(p + j));
			}
			error_flag = 0;
			printi(0, "\n");
		} else	if (0 >= map_hdr->default_error) {
			if (0 == error_flag) {
				printi(0, "0x%0*p\t",
				(map_hdr->source_len * 2),
				i + map_hdr->start.itm_ptr);
				printi(0, "error\n");
				error_flag = 1;
			} else if (error_flag == 1) {
				printi(0, " :\t:\n");
				error_flag = 2;
			}
		}
	}
	printi(-1, "};\n");
}


/*
 * Dump map-lookup-fixed
 */
static void
dump_map_l_f(itm_hdr_t		*itm_hdr, itm_place_t map_place, int standalone)
{
	itm_tbl_hdr_t		*tbl_hdr;
	itm_map_lookup_hdr_t	*map_hdr;
	itm_num_t		i;
	itm_num_t		j;
	unsigned char		*p;
	char			*name;

	TRACE_MESSAGE('d', ("dump_map_l_f\n"));

	tbl_hdr = (itm_tbl_hdr_t *)ADDR(map_place);
	map_hdr = (itm_map_lookup_hdr_t *)(tbl_hdr + 1);

	if ((standalone) &&
	    (0 == tbl_hdr->name.itm_ptr) &&
	    (map_place.itm_ptr != itm_hdr->direc_init_tbl.itm_ptr)) {
		return;
	}

	TRACE_MESSAGE('p', ("(&)map=%ld ", map_place.itm_ptr));

	if (0 == tbl_hdr->name.itm_ptr) {
		name = NULL;
	} else {
		name = tbl_name(itm_hdr, tbl_hdr);
	}

	if ((0 == standalone) && (0 != tbl_hdr->name.itm_ptr)) {
		if (NULL != name) {
			printi(0, "%s;\n", name);
		} else {
			printi(0, RNPREF "unknown;\n", name);
		}
		return;
	} else {
		printi(1, RNPREF "map");
		if (NULL != name) {
			printi(0, " %s", name);
		}
		printi(0, " {\n");
	}

	printi(0, "//  binary search map\n");
	printi(0, "//  source_len=%ld result_len=%ld\n",
		map_hdr->source_len, map_hdr->result_len);
	if (0 < map_hdr->error_num) {
		printi(0, "//  error_num=%ld\n",
			map_hdr->error_num);
	}

	if (0 == map_hdr->default_error) {
		printi(0, RNPREF "default\t0x");
		p = ((unsigned char *)(map_hdr + 1) +
			(tbl_hdr->number *
			(map_hdr->source_len + map_hdr->result_len + 1)) +
			map_hdr->source_len + 1);
		for (j = 0; j < map_hdr->result_len; j++, p++) {
			printi(0, "%02x", *p);
		}
		printi(0, "\n");
	} else if (-1 == map_hdr->default_error) {
		printi(0, RNPREF "default\t" RNPREF "default\n");
	}
	p = (unsigned char *)(map_hdr + 1);
	for (i = 0; i < tbl_hdr->number; i++) {
		printi(0, "0x");
		for (j = 0; j < map_hdr->source_len; j++, p++) {
			printi(0, "%02x", *p);
		}

		if (0 != (*p)) {
			p += map_hdr->result_len + 1;
			printi(0, "\terror");
		} else {
			p++;
			printi(0, "\t0x");
			for (j = 0; j < map_hdr->result_len; j++, p++) {
				printi(0, "%02x", *p);
			}
		}
		printi(0, "\n");
	}
	printi(-1, "};\n");
}

/*
 * Dump map-hash
 */
static void
dump_map_hash(itm_hdr_t		*itm_hdr, itm_place_t map_place, int standalone)
{
	itm_tbl_hdr_t		*tbl_hdr;
	itm_map_hash_hdr_t	*map_hdr;
	itm_num_t		i;
	itm_num_t		j;
	unsigned char		*p;
	unsigned char		*map_hash;
	unsigned char		*map_error;
	char			*name;

	TRACE_MESSAGE('d', ("dump_map_hash\n"));

	tbl_hdr = (itm_tbl_hdr_t *)ADDR(map_place);
	map_hdr = (itm_map_hash_hdr_t *)(tbl_hdr + 1);
	map_error = (unsigned char *)(map_hdr + 1);
	map_hash = (map_error + map_hdr->hash_tbl_num);

	if ((standalone) &&
	    (0 == tbl_hdr->name.itm_ptr) &&
	    (map_place.itm_ptr != itm_hdr->direc_init_tbl.itm_ptr)) {
		return;
	}

	TRACE_MESSAGE('p', ("(&)map=%ld ", map_place.itm_ptr));

	if (0 == tbl_hdr->name.itm_ptr) {
		name = NULL;
	} else {
		name = tbl_name(itm_hdr, tbl_hdr);
	}

	if ((0 == standalone) && (0 != tbl_hdr->name.itm_ptr)) {
		if (NULL != name) {
			printi(0, "%s;\n", name);
		} else {
			printi(0, RNPREF "unknown;\n", name);
		}
		return;
	} else {
		printi(1, RNPREF "map");
		if (NULL != name) {
			printi(0, " %s", name);
		}
		printi(0, " {\n");
	}

	printi(0, "//  hashed map\n");
	printi(0, "//  number=%ld\n",
		tbl_hdr->number);
	printi(0, "//  source_len=%ld result_len=%ld\n",
		map_hdr->source_len, map_hdr->result_len);
	printi(0, "//  hash_tbl_size=%ld hash_of_size=%ld hash_of_num=%ld\n",
		map_hdr->hash_tbl_size,
		map_hdr->hash_of_size, map_hdr->hash_of_num);
	if (0 < map_hdr->error_num) {
		printi(0, "//  error_num=%ld\n",
			map_hdr->error_num);
	}


	if (0 == map_hdr->default_error) {
		printi(0, RNPREF "default\t0x");
		p = map_hash + map_hdr->hash_tbl_size +
			map_hdr->hash_of_size;
		for (j = 0; j < map_hdr->result_len; j++, p++) {
			printi(0, "%02x", *p);
		}
		printi(0, "\n");
	} else if (-1 == map_hdr->default_error) {
		printi(0, RNPREF "default\t" RNPREF "default\n");
	}
	p = map_hash;
	TRACE_MESSAGE('d', ("dump_map_hash: %ld %ld\n",
			tbl_hdr->number, map_hdr->hash_of_num));
	for (i = 0; i < map_hdr->hash_tbl_num; i++) {
		TRACE_MESSAGE('d', ("dump_map_hash: %x (0x%08p)\n", *p, p));
		if (0 == *(map_error + i)) {
			p += (map_hdr->source_len + 1 + map_hdr->result_len);
			continue;
		}
		printi(0, "0x");
		for (j = 0; j < map_hdr->source_len; j++, p++) {
			printi(0, "%02x", *p);
		}

		if (0 != (*p)) {
			p += map_hdr->result_len + 1;
			printi(0, "\terror");
		} else {
			p++;
			printi(0, "\t0x");
			for (j = 0; j < map_hdr->result_len; j++, p++) {
				printi(0, "%02x", *p);
			}
		}
		printi(0, "\n");
	}
	printi(0, "// of table\n");
	for (i = 0; i < map_hdr->hash_of_num; i++) {
		printi(0, "0x");
		for (j = 0; j < map_hdr->source_len; j++, p++) {
			printi(0, "%02x", *p);
		}
		if (0 != (*p)) {
			p += map_hdr->result_len + 1;
			printi(0, "\terror\n");
		} else {
			p++;
			printi(0, "\t0x");
			for (j = 0; j < map_hdr->result_len; j++, p++) {
				printi(0, "%02x", *p);
			}
			printi(0, "\n");
		}
	}
	printi(-1, "};\n");
}


/*
 * Dump map-dense-encoding
 */
static void
dump_map_dense_enc(itm_hdr_t	*itm_hdr, itm_place_t map_place, int standalone)
{
	itm_tbl_hdr_t			*tbl_hdr;
	itm_map_dense_enc_hdr_t		*map_hdr;
	itm_num_t			i;
	itm_num_t			j;
	unsigned char			*p;
	unsigned char			*map_ptr;
	unsigned char			*map_error;
	unsigned char			*byte_seq_min;
	unsigned char			*byte_seq_max;
	char				*name;
	int				error_flag;

	TRACE_MESSAGE('d', ("dump_map_dense_enc\n"));

	tbl_hdr = (itm_tbl_hdr_t *)ADDR(map_place);
	map_hdr = (itm_map_dense_enc_hdr_t *)(tbl_hdr + 1);
	map_ptr = ((unsigned char *)(map_hdr + 1) +
			map_hdr->source_len + map_hdr->source_len);

	if (0 < map_hdr->error_num) {
		map_error = (map_ptr +
			(tbl_hdr->number * map_hdr->result_len));
		if (0 == map_hdr->default_error) {
			map_error += map_hdr->result_len;
		}
	} else if (1 == map_hdr->default_error) {
		map_error = (map_ptr +
			(tbl_hdr->number * map_hdr->result_len));
	} else {
		map_error = NULL;
	}
	byte_seq_min = (unsigned char *)(map_hdr + 1);
	byte_seq_max = byte_seq_min + map_hdr->source_len;

	if ((standalone) &&
	    (0 == tbl_hdr->name.itm_ptr) &&
	    (map_place.itm_ptr != itm_hdr->direc_init_tbl.itm_ptr)) {
		return;
	}

	TRACE_MESSAGE('p', ("(&)map=%ld ", map_place.itm_ptr));

	if (0 == tbl_hdr->name.itm_ptr) {
		name = NULL;
	} else {
		name = tbl_name(itm_hdr, tbl_hdr);
	}

	if ((0 == standalone) && (0 != tbl_hdr->name.itm_ptr)) {
		if (NULL != name) {
			printi(0, "%s;\n", name);
		} else {
			printi(0, RNPREF "unknown;\n", name);
		}
		return;
	} else {
		printi(1, RNPREF "map");
		if (NULL != name) {
			printi(0, " %s", name);
		}
		printi(0, " {\n");
	}

	printi(0, "//  dense encoded map\n");
	printi(0, "//  entry_number=%ld\n", tbl_hdr->number);
	printi(0, "//  source_len=%ld result_len=%ld\n",
		map_hdr->source_len, map_hdr->result_len);
	printi(0, "//  byte_seq_min=0x");
	p = byte_seq_min;
	for (i = 0; i < map_hdr->source_len; i++, p++) {
		printi(0, "%02x", *p);
	}
	printi(0, "\n");
	printi(0, "//  byte_seq_max=0x");
	p = byte_seq_max;
	for (i = 0; i < map_hdr->source_len; i++, p++) {
		printi(0, "%02x", *p);
	}
	printi(0, "\n");
	if (0 < map_hdr->error_num) {
		printi(0, "//  error_num=%ld\n",
			map_hdr->error_num);
	}
	if (0 == map_hdr->default_error) {
		p = (map_ptr + (tbl_hdr->number * map_hdr->result_len));
		printi(0, RNPREF "default 0x");
		for (j = 0; j < map_hdr->result_len; j++) {
			printi(0, "%02x", *(p + j));
		}
		printi(0, "\n");
	} else if (-1 == map_hdr->default_error) {
		printi(0, RNPREF "default\t" RNPREF "default\n");
	}

	error_flag = 0;
	for (i = 0, p = map_ptr; i < tbl_hdr->number;
	    i++, p += map_hdr->result_len) {
		if ((NULL == map_error) || (0 == *(map_error + i))) {
			printi(0, "%s\t",
				dense_enc_index_to_byte_seq(
					i, map_hdr->source_len,
					byte_seq_min, byte_seq_max));
			printi(0, "0x");
			for (j = 0; j < map_hdr->result_len; j++) {
				printi(0, "%02x", *(p + j));
			}
			printi(0, "\n");
			error_flag = 0;
		} else	if (0 >= map_hdr->default_error) {
			if (0 == error_flag) {
				printi(0, "%s\t",
					dense_enc_index_to_byte_seq(
					i, map_hdr->source_len,
					byte_seq_min, byte_seq_max));
				printi(0, "error\n");
				error_flag = 1;
			} else if (error_flag == 1) {
				printi(0, " :\t:\n");
				error_flag = 2;
			}
		}
	}
	printi(-1, "};\n");
}


/*
 * Evaluate condition table
 */
static void
dump_cond_tbl(itm_hdr_t *itm_hdr, itm_place_t cond_place, int standalone)
{
	itm_tbl_hdr_t	*cond_hdr;
	itm_cond_t	*cond;
	long		i;
	char		*name;

	TRACE_MESSAGE('p', ("(&)cond_tbl=%ld ", cond_place.itm_ptr));
	cond_hdr = (itm_tbl_hdr_t *)(ADDR(cond_place));
	cond = (itm_cond_t *)(cond_hdr + 1);

	if ((standalone) && (0 == cond_hdr->name.itm_ptr)) {
		TRACE_MESSAGE('t', ("skip condition(%d, %ld)\n",
		standalone, cond_hdr->name.itm_ptr));
		return;
	}

	if (0 == cond_place.itm_ptr) {
		printi(0, RNPREF "true");
		return;
	}

	if (0 == cond_hdr->name.itm_ptr) {
		name = NULL;
	} else {
		name = tbl_name(itm_hdr, cond_hdr);
	}

	if ((0 == standalone) && (0 != cond_hdr->name.itm_ptr)) {
		if (NULL != name) {
			printi(0, "%s", name);
		} else {
			printi(0, RNPREF "unknown");
		}
		return;
	} else {
		printi(1, RNPREF "condition");
		if (NULL != name) {
			printi(0, " %s", name);
		}
		printi(0, " {\n");
	}

	for (i = 0; i < cond_hdr->number; i++, cond++) {
		switch (cond->type) {
		case ITM_COND_BETWEEN:
			dump_range(itm_hdr, cond->operand.place);
			break;
		case ITM_COND_EXPR:
			dump_expr(itm_hdr, cond->operand.place);
			printi(0, ";\n");
			break;
		case ITM_COND_ESCAPESEQ:
			dump_escapeseq(itm_hdr, cond->operand.place);
			break;
		default:
			printi(0, "// unknown %d\n", cond->type);
			break;
		}
	}

	if (standalone) {
		printi(-1, "};\n");
	} else {
		printi(-1, "}");
	}
}


/*
 * Dump operation table
 */
static void
dump_op_tbl(itm_hdr_t	*itm_hdr, itm_place_t op_tbl_place, int standalone)
{
	itm_tbl_hdr_t	*op_hdr;
	itm_op_t	*operation;
	itm_place2_t	op_place;
	long		i;
	char		*name;
	static int	op_tbl_level;

	op_hdr = (itm_tbl_hdr_t *)(ADDR(op_tbl_place));
	operation = (itm_op_t *)(op_hdr + 1);
	TRACE_MESSAGE('p', ("(&)op_tbl=%ld ", op_tbl_place));

	name = tbl_name(itm_hdr, op_hdr);

	if ((standalone) && (NULL == name))
		return;

	if (0 == op_tbl_level) {
		if ((0 == standalone) && (0 != op_hdr->name.itm_ptr)) {
			if (NULL != name) {
				printi(0, "%s;\n", name);
			} else {
				printi(0, RNPREF "unknown;", name);
			}
			return;
		} else {
			printi(1, RNPREF "operation");
			if (NULL != name) {
				printi(0, " %s", name);
			}
			printi(0, " {\n");
		}
	}

	op_tbl_level += 1;

	op_place = op_tbl_place.itm_ptr + (sizeof (itm_tbl_hdr_t));
	for (i = 0; i < op_hdr->number;
	    i++, operation++, op_place += (sizeof (itm_op_t))) {
		dump_op(itm_hdr, op_place);
	}

	op_tbl_level -= 1;

	if (0 == op_tbl_level) {
		printi(-1, "};\n");
	}
}


/*
 * Evaluate single operation
 */
static void
dump_op(itm_hdr_t	*itm_hdr, itm_place2_t op_place)
{
	itm_op_t	*operation;
	itm_tbl_hdr_t	*op_hdr;

	operation = (itm_op_t *)ADDR2(op_place);
	TRACE_MESSAGE('p', ("(&)op=%ld ", op_place));

	switch (operation->type) {
	case ITM_OP_EXPR:
		dump_expr(itm_hdr, operation->data.operand[0]);
		printi(0, ";\n");
		break;
	case ITM_OP_ERROR:
		printi(0, RNPREF "error ");
		dump_expr(itm_hdr, operation->data.operand[0]);
		printi(0, ";\n");
		break;
	case ITM_OP_ERROR_D:
		printi(0, RNPREF "error %d;",
			operation->data.operand[0].itm_ptr);
		printi(0, "\n");
		break;
	case ITM_OP_DISCARD:
		printi(0, RNPREF "discard ");
		dump_expr(itm_hdr, operation->data.operand[0]);
		printi(0, ";\n");
		break;
	case ITM_OP_DISCARD_D:
		printi(0, RNPREF "discard %ld;\n",
			operation->data.operand[0].itm_ptr);
		break;
	case ITM_OP_OUT:
	case ITM_OP_OUT_D:
	case ITM_OP_OUT_R:
	case ITM_OP_OUT_S:
	case ITM_OP_OUT_INVD:
		printi(0, RNPREF "out = ");
		dump_expr(itm_hdr, operation->data.operand[0]);
		printi(0, ";\n");
		break;
	case ITM_OP_IF:
		printi(0, RNPREF "if ");
		dump_expr(itm_hdr, operation->data.operand[0]);
		printi(1, " {\n");
		dump_op_tbl(itm_hdr, operation->data.operand[1], 0);
		printi(-1, "}\n");
		break;
	case ITM_OP_IF_ELSE:
		printi(0, RNPREF "if ");
		dump_expr(itm_hdr, operation->data.operand[0]);
		printi(1, " {\n");
		dump_op_tbl(itm_hdr, operation->data.operand[1], 0);
		printi(-1, "} ");
		op_hdr = ADDR(operation->data.operand[2]);
		if ((1 == op_hdr->number) &&
		    ((ITM_OP_IF_ELSE == ((itm_op_t *)(op_hdr + 1))->type) ||
		    (ITM_OP_IF == ((itm_op_t *)(op_hdr + 1))->type))) {
			printi(0, RNPREF "else ");
			dump_op_tbl(itm_hdr, operation->data.operand[2], 0);
		} else {
			printi(1, RNPREF "else {\n");
			dump_op_tbl(itm_hdr, operation->data.operand[2], 0);
			printi(-1, "}\n");
		}
		break;
	case ITM_OP_DIRECTION: /* switch direction */
		printi(0, RNPREF "direction %1$s;\n", tbl_name(itm_hdr,
			(itm_tbl_hdr_t *)ADDR(operation->data.operand[0])));
		break;
	case ITM_OP_MAP:	/* use map */
		printi(0, RNPREF "map %1$s", tbl_name(itm_hdr,
			(itm_tbl_hdr_t *)ADDR(operation->data.operand[0])));
		if (0 != operation->data.operand[1].itm_ptr) {
			printi(0, " ");
			dump_expr(itm_hdr, operation->data.operand[1]);
		}
		printi(0, ";\n");
		break;
	case ITM_OP_OPERATION: /* invoke operation */
		printi(0, RNPREF "operation %1$s;\n",
			tbl_name(itm_hdr,
			(itm_tbl_hdr_t *)ADDR(operation->data.operand[0])));
		break;
	case ITM_OP_INIT: /* invoke init operation */
		printi(0, RNPREF "operation " RNPREF "init;\n");
		break;
	case ITM_OP_RESET: /* invoke reset operation */
		printi(0, RNPREF "operation " RNPREF "reset;\n");
		break;
	case ITM_OP_BREAK: /* break */
		printi(0, RNPREF "break;\n");
		break;
	case ITM_OP_RETURN: /* return */
		printi(0, RNPREF "return;\n");
		break;
	case ITM_OP_PRINTCHR:
		printi(0, RNPREF "printchr ");
		dump_expr(itm_hdr, operation->data.operand[0]);
		printi(0, ";\n");
		break;
	case ITM_OP_PRINTHD:
		printi(0, RNPREF "printhd ");
		dump_expr(itm_hdr, operation->data.operand[0]);
		printi(0, ";\n");
		break;
	case ITM_OP_PRINTINT:
		printi(0, RNPREF "printint ");
		dump_expr(itm_hdr, operation->data.operand[0]);
		printi(0, ";\n");
		break;
	default:
		printi(0, "// unknown operation: %lx\n", operation->type);
		break;
	}
}


/*
 * Dump expression
 */
static void
dump_expr(itm_hdr_t	*itm_hdr, itm_place_t expr_place)
{
	itm_expr_t	*expr;
	itm_data_t	data;

	expr = (itm_expr_t *)ADDR(expr_place);
	TRACE_MESSAGE('p', ("(*)ex=%ld ", expr_place.itm_ptr));

	switch (expr->type) {
	case ITM_EXPR_NONE:		/* not used */
		printi(0, "none");
		break;
	case ITM_EXPR_NOP:		/* not used */
		printi(0, "NOP");
		break;
	case ITM_EXPR_NAME:		/* not used */
		printi(0, "NAME");
		break;
	case ITM_EXPR_INT:		/* integer */
		printi(0, "%ld", expr->data.itm_exnum);
		break;
	case ITM_EXPR_SEQ:		/* byte sequence */
		data = expr->data.value;
		if ((sizeof (itm_place_t)) < data.size) {
			data.place.itm_ptr = (itm_place2_t)ADDR(data.place);
		}
		printi(0, "0x%s", data_to_hexadecimal(&data));
		break;
	case ITM_EXPR_REG:		/* register */
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		break;
	case ITM_EXPR_IN_VECTOR:	/* in[expr] */
		printi(0, RNPREF "in[");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, "]");
		break;
	case ITM_EXPR_IN_VECTOR_D:	/* in[num] */
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		if (0 == expr->data.operand[0].itm_ptr) {
			printi(0, " // inputsize");
		}
		break;
	case ITM_EXPR_OUT:		/* out */
		printi(0, RNPREF "out");
		break;
	case ITM_EXPR_TRUE:		/* true */
		printi(0, RNPREF "true");
		break;
	case ITM_EXPR_FALSE:		/* false */
		printi(0, RNPREF "false");
		break;
	case ITM_EXPR_UMINUS:		/* unary minus */
		printi(0, "-");
		dump_expr(itm_hdr, expr->data.operand[0]);
		break;
	case ITM_EXPR_PLUS:		/* A  + B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " + ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_PLUS_E_D:		/* exprA + B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " + ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_PLUS_E_R:		/* exprA + varB */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " + ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_PLUS_E_INVD:	/* exprA + in[B] */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " + ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_PLUS_D_E:		/* intA + exprB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " + ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_PLUS_D_D:		/* intA + B */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " + ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_PLUS_D_R:		/* intA + varB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " + ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_PLUS_D_INVD:	/* intA + in[B] */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " + ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_PLUS_R_E:		/* varA + exprB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " + ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_PLUS_R_D:		/* varA + B */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " + ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_PLUS_R_R:		/* varA + varB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " + ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_PLUS_R_INVD:	/* varA + in[B] */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " + ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_PLUS_INVD_E:	/* in[A] + exprB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " + ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_PLUS_INVD_D:	/* in[A] + B */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " + ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_PLUS_INVD_R:	/* in[A] + varB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " + ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_PLUS_INVD_INVD:	/* in[A] + in[B] */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " + ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MINUS:		/* A  - B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " - ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_MINUS_E_D:		/* exprA - B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " - ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MINUS_E_R:		/* exprA - varB */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " - ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_MINUS_E_INVD:	/* exprA - in[B] */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " - ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MINUS_D_E:		/* intA - exprB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " - ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_MINUS_D_D:		/* intA - B */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " - ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MINUS_D_R:		/* intA - varB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " - ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_MINUS_D_INVD:	/* intA - in[B] */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " - ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MINUS_R_E:		/* varA - exprB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " - ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_MINUS_R_D:		/* varA - B */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " - ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MINUS_R_R:		/* varA - varB */
		printi(0, "(");
		printi(0, " - ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, ")");
		break;
	case ITM_EXPR_MINUS_R_INVD:	/* varA - in[B] */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " - ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MINUS_INVD_E:	/* in[A] - exprB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " - ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_MINUS_INVD_D:	/* in[A] - B */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " - ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MINUS_INVD_R:	/* in[A] - varB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " - ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_MINUS_INVD_INVD:	/* in[A] - in[B] */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " - ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MUL:		/* A  * B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " * ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_MUL_E_D:		/* exprA * B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " * ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MUL_E_R:		/* exprA * varB */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " * ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_MUL_E_INVD:	/* exprA * in[B] */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " * ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MUL_D_E:		/* intA * exprB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " * ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_MUL_D_D:		/* intA * B */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " * ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MUL_D_R:		/* intA * varB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " * ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_MUL_D_INVD:	/* intA * in[B] */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " * ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MUL_R_E:		/* varA * exprB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " * ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_MUL_R_D:		/* varA * B */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " * ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MUL_R_R:		/* varA * varB */
		printi(0, "(");
		printi(0, " * ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, ")");
		break;
	case ITM_EXPR_MUL_R_INVD:	/* varA * in[B] */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " * ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MUL_INVD_E:	/* in[A] * exprB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " * ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_MUL_INVD_D:	/* in[A] * B */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " * ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MUL_INVD_R:	/* in[A] * varB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " * ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_MUL_INVD_INVD:	/* in[A] * in[B] */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " * ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_DIV:		/* A  / B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " / ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_DIV_E_D:		/* exprA / B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " / ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_DIV_E_R:		/* exprA / varB */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " / ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_DIV_E_INVD:	/* exprA / in[B] */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " / ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_DIV_D_E:		/* intA / exprB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " / ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_DIV_D_D:		/* intA / B */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " / ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_DIV_D_R:		/* intA / varB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " / ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_DIV_D_INVD:	/* intA / in[B] */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " / ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_DIV_R_E:		/* varA / exprB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " / ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_DIV_R_D:		/* varA / B */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " / ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_DIV_R_R:		/* varA / varB */
		printi(0, "(");
		printi(0, " / ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, ")");
		break;
	case ITM_EXPR_DIV_R_INVD:	/* varA / in[B] */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " / ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_DIV_INVD_E:	/* in[A] / exprB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " / ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_DIV_INVD_D:	/* in[A] / B */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " / ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_DIV_INVD_R:	/* in[A] / varB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " / ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_DIV_INVD_INVD:	/* in[A] / in[B] */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " / ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MOD:		/* A  % B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " %% ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_MOD_E_D:		/* exprA % B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " %% ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MOD_E_R:		/* exprA % varB */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " %% ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_MOD_E_INVD:	/* exprA % in[B] */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " %% ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MOD_D_E:		/* intA % exprB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " %% ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_MOD_D_D:		/* intA % B */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " %% ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MOD_D_R:		/* intA % varB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " %% ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_MOD_D_INVD:	/* intA % in[B] */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " %% ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MOD_R_E:		/* varA % exprB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " %% ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_MOD_R_D:		/* varA % B */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " %% ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MOD_R_R:		/* varA % varB */
		printi(0, "(");
		printi(0, " %% ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, ")");
		break;
	case ITM_EXPR_MOD_R_INVD:	/* varA % in[B] */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " %% ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MOD_INVD_E:	/* in[A] % exprB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " %% ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_MOD_INVD_D:	/* in[A] % B */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " %% ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_MOD_INVD_R:	/* in[A] % varB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " %% ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_MOD_INVD_INVD:	/* in[A] % in[B] */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " %% ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_L:		/* A << B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " << ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_L_E_D:		/* exprA << B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " << ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_L_E_R:		/* exprA << varB */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " << ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_L_E_INVD:	/* exprA << in[B] */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " << ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_L_D_E:		/* intA << exprB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " << ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_L_D_D:		/* intA << B */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " << ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_L_D_R:		/* intA << varB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " << ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_L_D_INVD:	/* intA << in[B] */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " << ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_L_R_E:		/* varA << exprB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " << ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_L_R_D:		/* varA << B */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " << ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_L_R_R:		/* varA << varB */
		printi(0, "(");
		printi(0, " << ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_L_R_INVD:	/* varA << in[B] */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " << ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_L_INVD_E:	/* in[A] << exprB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " << ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_L_INVD_D:	/* in[A] << B */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " << ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_L_INVD_R:	/* in[A] << varB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " << ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_L_INVD_INVD:	/* in[A] << in[B] */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " << ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_R:		/* A >> B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " >> ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_R_E_D:		/* exprA >> B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " >> ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_R_E_R:		/* exprA >> varB */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " >> ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_R_E_INVD:	/* exprA >> in[B] */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " >> ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_R_D_E:		/* intA >> exprB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " >> ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_R_D_D:		/* intA >> B */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " >> ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_R_D_R:		/* intA >> varB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " >> ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_R_D_INVD:	/* intA >> in[B] */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " >> ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_R_R_E:		/* varA >> exprB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " >> ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_R_R_D:		/* varA >> B */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " >> ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_R_R_R:		/* varA >> varB */
		printi(0, "(");
		printi(0, " >> ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_R_R_INVD:	/* varA >> in[B] */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " >> ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_R_INVD_E:	/* in[A] >> exprB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " >> ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_R_INVD_D:	/* in[A] >> B */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " >> ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_R_INVD_R:	/* in[A] >> varB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " >> ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_SHIFT_R_INVD_INVD:	/* in[A] >> in[B] */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " >> ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_OR:		/* A  | B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " | ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_OR_E_D:		/* exprA | B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " | ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_OR_E_R:		/* exprA | varB */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " | ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_OR_E_INVD:	/* exprA | in[B] */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " | ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_OR_D_E:		/* intA | exprB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " | ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_OR_D_D:		/* intA | B */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " | ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_OR_D_R:		/* intA | varB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " | ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_OR_D_INVD:	/* intA | in[B] */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " | ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_OR_R_E:		/* varA | exprB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " | ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_OR_R_D:		/* varA | B */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " | ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_OR_R_R:		/* varA | varB */
		printi(0, "(");
		printi(0, " | ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, ")");
		break;
	case ITM_EXPR_OR_R_INVD:	/* varA | in[B] */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " | ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_OR_INVD_E:	/* in[A] | exprB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " | ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_OR_INVD_D:	/* in[A] | B */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " | ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_OR_INVD_R:	/* in[A] | varB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " | ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_OR_INVD_INVD:	/* in[A] | in[B] */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " | ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_XOR:		/* A  ^ B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " ^ ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_XOR_E_D:		/* exprA ^ B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " ^ ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_XOR_E_R:		/* exprA ^ varB */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " ^ ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_XOR_E_INVD:	/* exprA ^ in[B] */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " ^ ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_XOR_D_E:		/* intA ^ exprB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " ^ ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_XOR_D_D:		/* intA ^ B */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " ^ ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_XOR_D_R:		/* intA ^ varB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " ^ ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_XOR_D_INVD:	/* intA ^ in[B] */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " ^ ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_XOR_R_E:		/* varA ^ exprB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " ^ ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_XOR_R_D:		/* varA ^ B */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " ^ ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_XOR_R_R:		/* varA ^ varB */
		printi(0, "(");
		printi(0, " ^ ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, ")");
		break;
	case ITM_EXPR_XOR_R_INVD:	/* varA ^ in[B] */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " ^ ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_XOR_INVD_E:	/* in[A] ^ exprB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " ^ ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_XOR_INVD_D:	/* in[A] ^ B */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " ^ ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_XOR_INVD_R:	/* in[A] ^ varB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " ^ ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_XOR_INVD_INVD:	/* in[A] ^ in[B] */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " ^ ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_AND:		/* A  & B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " & ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_AND_E_D:		/* exprA & B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " & ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_AND_E_R:		/* exprA & varB */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " & ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_AND_E_INVD:	/* exprA & in[B] */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " & ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_AND_D_E:		/* intA & exprB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " & ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_AND_D_D:		/* intA & B */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " & ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_AND_D_R:		/* intA & varB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " & ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_AND_D_INVD:	/* intA & in[B] */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " & ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_AND_R_E:		/* varA & exprB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " & ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_AND_R_D:		/* varA & B */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " & ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_AND_R_R:		/* varA & varB */
		printi(0, "(");
		printi(0, " & ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, ")");
		break;
	case ITM_EXPR_AND_R_INVD:	/* varA & in[B] */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " & ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_AND_INVD_E:	/* in[A] & exprB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " & ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_AND_INVD_D:	/* in[A] & B */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " & ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_AND_INVD_R:	/* in[A] & varB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " & ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_AND_INVD_INVD:	/* in[A] & in[B] */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " & ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_EQ:		/* A == B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " == ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_EQ_E_D:		/* exprA == B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " == ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_EQ_E_R:		/* exprA == varB */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " == ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_EQ_E_INVD:	/* exprA == in[B] */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " == ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_EQ_D_E:		/* intA == exprB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " == ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_EQ_D_D:		/* intA == B */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " == ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_EQ_D_R:		/* intA == varB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " == ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_EQ_D_INVD:	/* intA == in[B] */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " == ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_EQ_R_E:		/* varA == exprB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " == ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_EQ_R_D:		/* varA == B */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " == ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_EQ_R_R:		/* varA == varB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " == ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_EQ_R_INVD:	/* varA == in[B] */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " == ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_EQ_INVD_E:	/* in[A] == exprB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " == ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_EQ_INVD_D:	/* in[A] == B */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " == ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_EQ_INVD_R:	/* in[A] == varB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " == ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_EQ_INVD_INVD:	/* in[A] == in[B] */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " == ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_NE:		/* A != B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " != ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_NE_E_D:		/* exprA != B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " != ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_NE_E_R:		/* exprA != varB */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " != ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_NE_E_INVD:	/* exprA != in[B] */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " != ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_NE_D_E:		/* intA != exprB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " != ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_NE_D_D:		/* intA != B */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " != ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_NE_D_R:		/* intA != varB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " != ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_NE_D_INVD:	/* intA != in[B] */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " != ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_NE_R_E:		/* varA != exprB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " != ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_NE_R_D:		/* varA != B */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " != ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_NE_R_R:		/* varA != varB */
		printi(0, "(");
		printi(0, " != ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, ")");
		break;
	case ITM_EXPR_NE_R_INVD:	/* varA != in[B] */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " != ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_NE_INVD_E:	/* in[A] != exprB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " != ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_NE_INVD_D:	/* in[A] != B */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " != ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_NE_INVD_R:	/* in[A] != varB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " != ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_NE_INVD_INVD:	/* in[A] != in[B] */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " != ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_GT:		/* A  > B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " > ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_GT_E_D:		/* exprA > B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " > ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_GT_E_R:		/* exprA > varB */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " > ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_GT_E_INVD:	/* exprA > in[B] */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " > ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_GT_D_E:		/* intA > exprB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " > ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_GT_D_D:		/* intA > B */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " > ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_GT_D_R:		/* intA > varB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " > ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_GT_D_INVD:	/* intA > in[B] */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " > ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_GT_R_E:		/* varA > exprB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " > ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_GT_R_D:		/* varA > B */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " > ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_GT_R_R:		/* varA > varB */
		printi(0, "(");
		printi(0, " > ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, ")");
		break;
	case ITM_EXPR_GT_R_INVD:	/* varA > in[B] */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " > ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_GT_INVD_E:	/* in[A] > exprB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " > ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_GT_INVD_D:	/* in[A] > B */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " > ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_GT_INVD_R:	/* in[A] > varB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " > ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_GT_INVD_INVD:	/* in[A] > in[B] */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " > ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_GE:		/* A >= B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " >= ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_GE_E_D:		/* exprA >= B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " >= ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_GE_E_R:		/* exprA >= varB */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " >= ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_GE_E_INVD:	/* exprA >= in[B] */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " >= ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_GE_D_E:		/* intA >= exprB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " >= ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_GE_D_D:		/* intA >= B */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " >= ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_GE_D_R:		/* intA >= varB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " >= ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_GE_D_INVD:	/* intA >= in[B] */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " >= ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_GE_R_E:		/* varA >= exprB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " >= ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_GE_R_D:		/* varA >= B */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " >= ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_GE_R_R:		/* varA >= varB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " >= ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_GE_R_INVD:	/* varA >= in[B] */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " >= ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_GE_INVD_E:	/* in[A] >= exprB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " >= ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_GE_INVD_D:	/* in[A] >= B */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " >= ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_GE_INVD_R:	/* in[A] >= varB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " >= ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_GE_INVD_INVD:	/* in[A] >= in[B] */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " >= ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_LT:		/* A  < B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " < ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_LT_E_D:		/* exprA < B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " < ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_LT_E_R:		/* exprA < varB */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " < ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_LT_E_INVD:	/* exprA < in[B] */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " < ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_LT_D_E:		/* intA < exprB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " < ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_LT_D_D:		/* intA < B */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " < ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_LT_D_R:		/* intA < varB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " < ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_LT_D_INVD:	/* intA < in[B] */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " < ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_LT_R_E:		/* varA < exprB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " < ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_LT_R_D:		/* varA < B */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " < ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_LT_R_R:		/* varA < varB */
		printi(0, "(");
		printi(0, " < ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, ")");
		break;
	case ITM_EXPR_LT_R_INVD:	/* varA < in[B] */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " < ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_LT_INVD_E:	/* in[A] < exprB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " < ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_LT_INVD_D:	/* in[A] < B */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " < ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_LT_INVD_R:	/* in[A] < varB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " < ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_LT_INVD_INVD:	/* in[A] < in[B] */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " < ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_LE:		/* A <= B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " <= ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_LE_E_D:		/* exprA <= B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " <= ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_LE_E_R:		/* exprA <= varB */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " <= ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_LE_E_INVD:	/* exprA <= in[B] */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " <= ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_LE_D_E:		/* intA <= exprB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " <= ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_LE_D_D:		/* intA <= B */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " <= ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_LE_D_R:		/* intA <= varB */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " <= ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_LE_D_INVD:	/* intA <= in[B] */
		printi(0, "(");
		printi(0, "%ld", expr->data.operand[0].itm_ptr);
		printi(0, " <= ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_LE_R_E:		/* varA <= exprB */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " <= ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_LE_R_D:		/* varA <= B */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " <= ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_LE_R_R:		/* varA <= varB */
		printi(0, "(");
		printi(0, " <= ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, ")");
		break;
	case ITM_EXPR_LE_R_INVD:	/* varA <= in[B] */
		printi(0, "(");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[0]));
		printi(0, " <= ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_LE_INVD_E:	/* in[A] <= exprB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " <= ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_LE_INVD_D:	/* in[A] <= B */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " <= ");
		printi(0, "%ld", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_LE_INVD_R:	/* in[A] <= varB */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " <= ");
		printi(0, "%s", reg_name(itm_hdr, expr->data.operand[1]));
		printi(0, ")");
		break;
	case ITM_EXPR_LE_INVD_INVD:	/* in[A] <= in[B] */
		printi(0, "(");
		printi(0, RNPREF "in[%ld]", expr->data.operand[0].itm_ptr);
		printi(0, " <= ");
		printi(0, RNPREF "in[%ld]", expr->data.operand[1].itm_ptr);
		printi(0, ")");
		break;
	case ITM_EXPR_NOT:		/*   !A	  */
		printi(0, "(");
		printi(0, "!");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, ")");
		break;
	case ITM_EXPR_NEG:		/*   ~A	  */
		printi(0, "(");
		printi(0, " ~");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, ")");
		break;
	case ITM_EXPR_LOR:		/* A || B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " || ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_LAND:		/* A && B */
		printi(0, "(");
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, " && ");
		dump_expr(itm_hdr, expr->data.operand[1]);
		printi(0, ")");
		break;
	case ITM_EXPR_ASSIGN:		/* A  = B */
		printi(0, "%s = ", reg_name(itm_hdr, expr->data.operand[0]));
		dump_expr(itm_hdr, expr->data.operand[1]);
		break;
	case ITM_EXPR_IN_EQ:		/* in == A */
		printi(0, "(" RNPREF "in == ", 0);
		dump_expr(itm_hdr, expr->data.operand[0]);
		printi(0, ")");
		break;
	default:
		break;
	}
}


/*
 * Dump range (between)
 */
static void
dump_range(itm_hdr_t	*itm_hdr, itm_place_t range_place)
{
	itm_tbl_hdr_t	*rth;
	itm_range_hdr_t	*rtsh;
	unsigned char	*p;
	long		i;
	long		j;

	rth = (itm_tbl_hdr_t *)(ADDR(range_place));
	rtsh = (itm_range_hdr_t *)(rth + 1);
	p = (unsigned char *)(rtsh + 1);

	TRACE_MESSAGE('p', ("(&)between=%ld ", range_place.itm_ptr));
	printi(0, RNPREF "between ");
	for (i = 0; i < rth->number; i++) {
		if (0 != i)	printi(0, "\t ");
		printi(0, "0x");
		for (j = 0; j < rtsh->len; j++) {
			printi(0, "%02x", *(p++));
		}
		printi(0, " - ");
		printi(0, "0x");
		for (j = 0; j < rtsh->len; j++) {
			printi(0, "%02x", *(p++));
		}
		if (i < (rth->number - 1)) {
			printi(0, ",\n");
		} else {
			printi(0, ";\n");
		}
	}
}


/*
 * Dump escape sequence
 */
static void
dump_escapeseq(itm_hdr_t	*itm_hdr, itm_place_t escapeseq_place)
{
	itm_tbl_hdr_t		*eth;
	itm_escapeseq_hdr_t	*eh;
	itm_data_t		*d;
	itm_data_t		data;

	long			i;


	eth = (itm_tbl_hdr_t *)(ADDR(escapeseq_place));
	eh = (itm_escapeseq_hdr_t *)(eth + 1);
	d = (itm_data_t *)(eh + 1);
	TRACE_MESSAGE('p', ("(&)escseq=%ld ", escapeseq_place.itm_ptr));
	printi(1, RNPREF "escapceseq {");

	for (i = 0; i < eth->number; i++, d++) {
		if (0 != i)	printi(0, " ");
		data = *d;
		if ((sizeof (itm_place_t)) < data.size) {
			data.place.itm_ptr = (itm_place2_t)ADDR(d->place);
		}
		printi(0, "0x%s;", data_to_hexadecimal(&data));
	}
	printi(-1, "}\n");
}


static void
printi(int c, char	*format, ...)
{
	static int	indent_level;
	static int	new_line = 1;
	int		i;
	va_list		ap;
	va_start(ap, format);

	if (c < 0) {
		indent_level += c;
		if (indent_level < 0) {
			indent_level = 0;
		}
	}
	if (new_line) {
		for (i = indent_level; 0 < i; i -= 1) {
			(void) putchar('\t');
		}
	}
	if (0 < c) {
		indent_level += c;
		if (indent_level < 0) {
			indent_level = 0;
		}
	}

	if (NULL == strchr(format, '\n')) {
		new_line = 0;
	} else {
		new_line = 1;
	}

	(void) vfprintf(stdout, format, ap);

	va_end(ap);
}


static char *
name_place_to_str(itm_hdr_t	*itm_hdr, itm_place2_t place)
{
	itm_data_t	d;

	if (0 != place) {
		d = *((itm_data_t *)ADDR2(place));
		if ((sizeof (itm_place_t)) < d.size) {
			d.place.itm_ptr = (itm_place2_t)ADDR(d.place);
		}
	} else {
		d.size = 0;
		d.place.itm_ptr = 0;
	}
	return (name_to_str(&d));
}

static char *
tbl_name(itm_hdr_t	*itm_hdr, itm_tbl_hdr_t		*tbl_hdr)
{
	if (ITM_TBL_OP_INIT == tbl_hdr->type) {
		return (RNPREF "init");
	} else if (ITM_TBL_OP_RESET == tbl_hdr->type) {
		return (RNPREF "reset");
	} else if (tbl_hdr->name.itm_ptr) {
		return (name_place_to_str(itm_hdr, tbl_hdr->name.itm_ptr));
	} else {
		return (NULL);
	}
}


static char *
reg_name(itm_hdr_t	*itm_hdr, itm_place_t op)
{
	itm_info_hdr_t		*info_hdr;
	static char		sbuf[32];
	itm_num_t		reg_num;

	reg_num = (itm_num_t)(op.itm_ptr);
	if (0 == itm_hdr->info_hdr.itm_ptr) {
		(void) sprintf(sbuf, "reg%ld\n", reg_num);
		return (sbuf);
	} else {
		info_hdr = INFO_HDR(itm_hdr);
		return (name_place_to_str(
			itm_hdr,
			info_hdr->reg_plc_tbl.place.itm_ptr +
			(reg_num	*sizeof (itm_data_t))));
	}
}

static itm_hdr_t *
itm_attach(const char	*itm_file)
{
	itm_hdr_t	*itm_hdr;
	struct stat	st;
	int		fd;

	fd = open(itm_file, O_RDONLY, 0);
	if (fd == -1) {
		PERROR(gettext("open()"));
		return	(NULL);
	}

	if (fstat(fd, &st) == -1) {
		PERROR(gettext("fstat()"));
		return	(NULL);
	}
	itm_hdr = (void *) mmap(NULL, st.st_size,
				    PROT_READ, MAP_SHARED, fd, 0);
	if (MAP_FAILED == itm_hdr) {
		PERROR(gettext("mmap()"));
		return	(NULL);
	}

	(void) close(fd);

	if ((itm_hdr->ident[0] != ITM_IDENT_0) ||
	    (itm_hdr->ident[1] != ITM_IDENT_1) ||
	    (itm_hdr->ident[2] != ITM_IDENT_2) ||
	    (itm_hdr->ident[3] != ITM_IDENT_3)) {
		itm_error(gettext("magic number error\n"));
		return	(NULL);
	}
	if ((itm_hdr->version[0] != ITM_VER_0) ||
	    (itm_hdr->version[1] != ITM_VER_1) ||
	    (itm_hdr->version[2] != ITM_VER_2) ||
#if defined(_LITTLE_ENDIAN)
#if defined(_LP64)
	    ((itm_hdr->spec[3] != ITM_SPEC_3_32_LITTLE_ENDIAN) &&
	    (itm_hdr->spec[3] != ITM_SPEC_3_64_LITTLE_ENDIAN))) {
#else
	    (itm_hdr->spec[3] != ITM_SPEC_3_32_LITTLE_ENDIAN)) {
#endif
#else
#if defined(_LP64)
	    ((itm_hdr->spec[3] != ITM_SPEC_3_32_BIG_ENDIAN) &&
	    (itm_hdr->spec[3] != ITM_SPEC_3_64_BIG_ENDIAN))) {
#else
	    (itm_hdr->spec[3] != ITM_SPEC_3_32_BIG_ENDIAN)) {
#endif
#endif
		itm_error(gettext("version number error\n"));
		return	(NULL);
	}
	if (itm_hdr->itm_size.itm_ptr != st.st_size) {
		itm_error(gettext(
			"size error: expected=%1$d current=%2$d\n"),
			(size_t)(itm_hdr->itm_size.itm_ptr), st.st_size);
		return (NULL);
	}

	return (itm_hdr);
}
