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


#ifndef	_ITMCOMP_H
#define	_ITMCOMP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include "iconv_tm.h"


#define	ITMC_STATUS_SUCCESS	(0)
#define	ITMC_STATUS_CMD		(1)
#define	ITMC_STATUS_CMD2	(2)
#define	ITMC_STATUS_BT		(3)
#define	ITMC_STATUS_BT2		(4)
#define	ITMC_STATUS_SYS		(5)
#define	ITMC_STATUS_SYS2	(6)

#define	MAXOPNEST 16

/*
 * exit status:
 * ITMC_STATUS_SUCCESS
 * ITMC_STATUS_CMD	specified options are wrong
 * ITMC_STATUS_CMD2	cannot access specified file
 * ITMC_STATUS_BT	Binary Table format error
 * ITMC_STATUS_BT2	Binary Table against limitation
 * ITMC_STATUS_SYS	resource shortage (e.g.: malloc )
 * ITMC_STATUS_SYS2	internal error: never happen
 */

/*
 * used later
 */

struct _itmc_ref;


/*
 * command line option
 */

typedef	enum {
	ITMC_MAP_UNKNOWN = 0,
	ITMC_MAP_AUTOMATIC,
	ITMC_MAP_SIMPLE_INDEX,
	ITMC_MAP_SIMPLE_HASH,
	ITMC_MAP_BINARY_SEARCH,
	ITMC_MAP_DENSE_ENCODING
} itmc_map_type_t;



typedef struct _itmc_map_name_type {
	char	*name;
	itmc_map_type_t			type;
	int				hash_factor;
	struct _itmc_map_name_type	*next;
}	itmc_map_name_type_t;


typedef struct {
	char		*my_name;
	char		**input_file;
	int		input_file_num;
	char		*output_file;
	char		*interpreter;
	char		**cpp_opt;
	int		cpp_opt_num;
	int		cpp_opt_reserved;
	char		*preprocess_default;
	char		*preprocess_specified;
	char		*preprocess;
	char		*disassemble;
	int		binary_search;
	itmc_map_name_type_t *
			map_name_type;
	int		large_table;
	int		force_overwrite;
	int		strip;
	int		quiet;
	int		no_output;
	char		*trace;
} cmd_opt_t;


/*
 * data list
 */

typedef struct {
	void		*obj;
	itm_num_t	num;
} obj_array_t;

typedef struct _itmc_obj {
	itm_type_t		type;
	itm_data_t		*name;
	void			*obj;
	struct _itmc_ref	*ref[3];
	struct _itmc_obj	*next;
	struct _itmc_obj	*last;
} itmc_obj_t;


/*
 * data pair: used for map and range
 */

typedef itm_data_t itmc_map_range_t;
typedef struct {
	itm_data_t	data0;
	itm_data_t	data1;
	itmc_map_range_t	range;
} itmc_data_pair_t;


/*
 * map pair list
 */
typedef struct _itmc_map {
	itmc_data_pair_t	data_pair;
	struct _itmc_map	*next;
	struct _itmc_map	*last;
} itmc_map_t;


/*
 * cross reference: used for relocation
 */

typedef struct _itmc_ref_link {
	struct _itmc_ref	*ref;
	struct _itmc_ref_link	*next;
} itmc_ref_link_t;

typedef struct _itmc_name {
	itm_num_t		id;
	itm_num_t		reg_id;
	itm_data_t		name;
	itm_type_t		type;
	struct _itmc_ref	*object;
	itm_place_t		reloc;
	itmc_ref_link_t		*ref_first;
	itmc_ref_link_t		*ref_last;
	struct _itmc_name	*next;
} itmc_name_t;

typedef struct _itmc_ref {
	itmc_name_t		*name;
	void			*referencee;
	itm_place_t		reloc;
	itm_size_t		size;
	itm_place_t		*referencer;
	struct _itmc_ref	*next;
	int			vertex_index;
} itmc_ref_t;


/*
 * action
 */
typedef struct {
	itm_type_t	type;
	itm_tbl_hdr_t	*tbl_hdr;
} itmc_action_t;

/*
 * map attribute
 */
typedef struct {
	itm_size_t	resultlen;
	itm_data_t	*type;
	int		hash_factor;
} itmc_map_attr_t;


/*
 *	operation hierarchy
 */
typedef struct itm_opt_outer {
	struct itm_opt_outer	*link;
	struct itm_opt_inner	*in;
	itm_tbl_hdr_t		*optbl; /* operation object address */
	itmc_ref_t		*ref; /* corresponding object's ref */
} itm_op_outer_t;
typedef struct itm_opt_inner {
	struct itm_opt_inner	*in;
	itmc_ref_t		*ref; /* corresponding object's ref */
} itm_op_inner_t;


/*
 * itm compiler object type
 */

#define	ITMC_OBJ_NONE		(0)
#define	ITMC_OBJ_FIRST		(1)
#define	ITMC_OBJ_ITM		(1)
#define	ITMC_OBJ_STRING		(2)
#define	ITMC_OBJ_DIREC		(3)
#define	ITMC_OBJ_COND		(4)
#define	ITMC_OBJ_MAP		(5)
#define	ITMC_OBJ_OP		(6)
#define	ITMC_OBJ_EXPR		(7)
#define	ITMC_OBJ_DATA		(8)
#define	ITMC_OBJ_ACTION		(9)
#define	ITMC_OBJ_RANGE		(10)
#define	ITMC_OBJ_REGISTER	(11)
#define	ITMC_OBJ_ESCAPESEQ	(12)
#define	ITMC_OBJ_LAST		(12)


/*
 * global variable
 */

extern itmc_ref_t	*ref_first[ITMC_OBJ_LAST + 1];
extern itmc_ref_t	*ref_last[ITMC_OBJ_LAST + 1];

extern itmc_name_t	*name_first;
extern itmc_name_t	*name_last;

extern itm_num_t	name_id;
extern itm_num_t	reg_id;

extern itmc_name_t	name_lookup_error;
extern int		error_deferred;

extern cmd_opt_t	cmd_opt;
extern char		*itm_input_file;
extern char		*itm_output_file;

extern struct itm_opt_outer *itm_op_outer;
/*
 * macro definition
 */

#define	NSPTR(n)	(((n)->size <= (sizeof ((n)->place))) ?	\
				((void *)(&((n)->place.itm_64d))) : \
				((void *)((n)->place.itm_ptr)))
#if !defined(ROUNDUP)
#define	 ROUNDUP(a, n)	 (((a) + ((n) - 1)) & ~((n) - 1))
#endif
#define	ITMROUNDUP(i)	ROUNDUP(i, sizeof (uint64_t))


/*
 * trace
 */

#if defined(ENABLE_TRACE)
#define	TRACE(c)	((cmd_opt.trace != 0) && \
			(0 != *(cmd_opt.trace + (c & 0x007f))))
#define	TRACE_MESSAGE(c, args)	((TRACE(c))? trace_message args: (void)0)
#else
#define	TRACE(c)
#define	TRACE_MESSAGE(c, args)
#endif

/*
 * error
 */
#define	PERROR(s)	if (cmd_opt.quiet == 0) perror(s)

/*
 * function prototype
 */

extern int	assemble(itm_hdr_t *);
extern void	disassemble(char *);

extern void	*malloc_vital(size_t);

extern char	*name_to_str(itm_data_t *);
extern char	*data_to_hexadecimal(itm_data_t *);
extern itm_data_t	*str_to_data(int, char *);

#if defined(ENABLE_TRACE)
extern void	dump_itm_header(itm_hdr_t *, itm_info_hdr_t *);

extern void	trace_message(char *, ...);
#endif

extern char	*itm_name_type_name[];
extern void	itm_error(char *format, ...);
#ifdef	__cplusplus
}
#endif

#endif /* !_ITMCOMP_H */
