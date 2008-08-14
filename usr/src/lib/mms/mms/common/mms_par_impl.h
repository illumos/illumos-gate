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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef	__MMS_PAR_IMPL_H
#define	__MMS_PAR_IMPL_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <thread.h>
#include <synch.h>
#include <mms_sym.h>
#include <mms_parser.h>

typedef	union {
	char		*str;
	mms_par_node_t	*nodep;
	mms_list_t		*listp;
}	mms_stype_t;

#define	MMS_PAR_MAX_CMDSIZE		(1024*8)
#define	MMS_PW_MAX_LEVEL	20
#define	MMS_PAR_REC_ERR_MAX		5
#define	MMS_PE_MAX		(MMS_PAR_REC_ERR_MAX * 3)
#define	MMS_PAR_MAX_TOKEN		2000

#define	MMS_PAR_ALLOC_NODE(s, val, type) {				\
		(s) = mms_par_alloc_node(type, val);			\
		if ((s) == NULL) {					\
			mms_pwka->par_wka_error = MMS_PE_NOMEM;		\
			YYERROR;					\
		}							\
		mms_pwka->par_wka_cur_node = (s);			\
		if (mms_par_cmd_node == NULL) {				\
			mms_par_cmd_node = (s);				\
		} else {						\
			mms_list_insert_tail(&mms_par_cmd_node->pn_memlist, \
			    (s));					\
		}							\
	}

#define	MMS_PAR_ALLOC_LIST(s) {						\
		mms_par_node_t	*node;					\
		node = mms_par_alloc_node(MMS_PN_LIST, "mem_list"); \
		if (node == NULL) {					\
			mms_pwka->par_wka_error = MMS_PE_NOMEM;		\
			YYERROR;					\
		}							\
		mms_list_insert_tail(&mms_par_cmd_node->pn_memlist, node); \
		(s) = &node->pn_arglist;				\
	}

#define	MMS_PAR_FLAG_BYTE(x)	((x - TOKEN_MIN) / 8)
#define	MMS_PAR_FLAG_SHIFT(x)	((x - TOKEN_MIN) % 8)
#define	MMS_PAR_FLAG(x)		(1 << MMS_PAR_FLAG_SHIFT(x))
#define	MMS_PAR_SET_FLAG(x) 						\
	(mms_pwka->par_wka_token_flags[MMS_PAR_FLAG_BYTE(x)] |=		\
	    MMS_PAR_FLAG(x))
#define	MMS_PAR_UNSET_FLAG(x)						\
	(mms_pwka->par_wka_token_flags[MMS_PAR_FLAG_BYTE(x)] &=		\
	    ~MMS_PAR_FLAG(x))
#define	MMS_PAR_CHK_FLAG(x)						\
	((mms_pwka->par_wka_token_flags[MMS_PAR_FLAG_BYTE(x)] &		\
	    MMS_PAR_FLAG(x)) != 0 ? 1 : 0)
#define	MMS_PAR_CHK_DUP(x) {						\
		if (MMS_PAR_CHK_FLAG(x)) {				\
			yyerror("Only one " #x " is allowed");		\
		} else {						\
			MMS_PAR_SET_FLAG(x);				\
		}							\
	}

typedef	struct	mms_pw {
	uint32_t	par_wka_flags;
	int		par_wka_scanner_offset;
	struct mms_par_node	**par_wka_cmd_node;
	struct mms_par_node	*par_wka_cur_node;
	int		par_wka_line;
	int		par_wka_col;
	int		par_wka_err_count;
	int		par_wka_err_type;
	int		par_wka_err_col;
	uchar_t		*par_wka_token_flags;
	mms_list_t		*par_wka_err_list;
	int		par_wka_rec_err;
	int		par_wka_error;			/* Set this before */
							/* calling yyerror */
	mms_sym_t		*par_wka_symtab;
	int		par_wka_num_syms;
	mms_sym_t		*par_wka_symtab_depend;
	int		par_wka_num_syms_depend;
	mutex_t		*par_wka_lock;
	int		par_wka_token_index;
	char		*par_wka_token[2];
	char		par_wka_parser[40];
}	mms_pw_t;

#define	MMS_PW_NOTREE		0x01
#define	MMS_PW_KEYWORD		0x02		/* want keyword name */
#define	MMS_PW_DEPEND		0x04		/* Look in depend tbl first */
#define	MMS_PW_ATTR		0x08
#define	MMS_PW_EOF		0x10
#define	MMS_PW_ERROR		0x20
#define	MMS_PW_ERROR_CODE	0x40		/* Looking for error code */

#define	mms_pwka			((mms_pw_t *)wka)
#define	mms_par_cmd_node	(*(mms_pwka->par_wka_cmd_node))

void mms_pe_free(mms_par_err_t *err);
void mms_par_error(mms_pw_t *wka, char *msg);

mms_par_node_t *mms_par_alloc_node(enum mms_pn_type type, char *str);
mms_sym_t *mms_par_lookup_sym(char *mms_sym, mms_pw_t *wka);

mms_pw_t *
mms_par_init_wka(mms_par_node_t **cmd_node,
    mms_list_t *msg_list,
    mms_sym_t *depend_symtab, int num_depend_syms,
    int *depend_symtab_initialized);

void mms_par_list_insert_tail(mms_list_t *list, void *node);
char *mms_par_char_to_xml_escape(char *src);
char *mms_par_xml_escape_to_char(char *src);

#undef	MMS_YY_INPUT

#ifdef	__cplusplus
}
#endif

#endif	/* __MMS_PAR_IMPL_H */
