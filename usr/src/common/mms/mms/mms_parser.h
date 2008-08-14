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


#ifndef	__MMS_PARSER_H__
#define	__MMS_PARSER_H__

#include <mms_list.h>

enum	mms_pn_type {
	MMS_PN_NONE		= 0x0001,
	MMS_PN_CMD		= 0x0002,
	MMS_PN_CLAUSE		= 0x0004,
	MMS_PN_OPS		= 0x0008,
	MMS_PN_OBJ		= 0x0010,
	MMS_PN_ATTR		= 0x0020,
	MMS_PN_STRING		= 0x0040,
	MMS_PN_KEYWORD	= 0x0080,
	MMS_PN_NUMERIC	= 0x0100,
	MMS_PN_RANGE		= 0x0200,
	MMS_PN_NULLSTR	= 0x0400,
	MMS_PN_CONFIG		= 0x1000,
	MMS_PN_SECTION	= 0x2000,
	MMS_PN_OPTION		= 0x4000,
	MMS_PN_MSGCAT		= 0x8000,
	MMS_PN_LIST		= 0x010000,
	MMS_PN_REGEX		= 0x020000
};

typedef	struct	mms_par_node {
	mms_list_node_t	pn_next;		/* doubly linked list */
	mms_list_node_t	pn_memnext;
	int		pn_flags;
	mms_list_t		pn_arglist;	/* list of args of this node */
	mms_list_t		pn_attrlist;	/* Used by msg_parse only */
	mms_list_t		pn_memlist;	/* mem list, used by CMD only */
	uint64_t	pn_type;
	int		pn_seq;
	char		*pn_string;
	struct mms_par_node	*pn_nonterm;	/* Only used in yparse* */
	struct mms_par_node	*pn_list;	/* list this node is on */
}	mms_par_node_t;

#define	MMS_PN_MULTIOPS	0x01
#define	MMS_PN_UNARYOPS	0x02
#define	MMS_PN_ATTR_LIST	0x04		/* in attr list */
#define	MMS_PN_ARG_LIST	0x08		/* in arg list */

typedef	struct	mms_par_err {
	mms_list_node_t	pe_next;
	int		pe_code;
	int		pe_line;
	int		pe_col;
	char		*pe_token;
	char		*pe_msg;
}	mms_par_err_t;

#define	MMS_PE_NOMEM		1
#define	MMS_PE_SYNTAX		2
#define	MMS_PE_MAX_LEVEL	3
#define	MMS_PE_INVAL_CALLBACK	4
#define	MMS_PE_USERABORT	5

#define	mms_pn_token(node)	(node->pn_string)

#define	mms_pn_type(node)	(node->pn_type)

#define	MMS_PN_LOOKUP(result, node, str, type, work) {		\
		result = mms_pn_lookup(node, str, type, work);	\
		if (result == NULL)					\
			goto not_found;					\
	}


typedef	void	(*par_input_func)(char *, int *, int, void *);

char	*mms_par_text_sub(char *template, char *arg, char *text);
char	*mms_pn_build_cmd_xml(mms_par_node_t *cmd);
int	mms_pn_len_xml(mms_par_node_t *node, int level);
int	mms_pn_cmd_len_xml(mms_par_node_t *top);
char	*mms_pn_build_cmd_text(mms_par_node_t *top);
int	mms_pn_build_cmd_text_aux(mms_par_node_t *top, char *buf, int len);
int	mms_pn_cmd_len_text(mms_par_node_t *top);
int	mms_pn_len_text(mms_par_node_t *node);
void	mms_pe_destroy(mms_list_t *err);
void	mms_pe_msg(char *);
void	mms_pn_destroy(mms_par_node_t *node);
void	mms_par_input(char *buf, int *result, int max, void *data);

mms_par_node_t *mms_pn_lookup(mms_par_node_t *top, char *str, int type,
			    mms_par_node_t **prev);
mms_par_node_t *mms_pn_lookup_arg(mms_par_node_t *top, char *str, int type,
				mms_par_node_t **prev);
void	mms_pn_fini(mms_par_node_t *node);


int	mms_mmp_parse(mms_par_node_t **cmd_node,
		mms_list_t *msg_list,
		char *buf);

int	mms_dmpm_parse(mms_par_node_t **cmd_node,
		mms_list_t *msg_list,
		char *buf);

int	mms_dmpd_parse(mms_par_node_t **cmd_node,
		mms_list_t *msg_list,
		char *buf);

int	mms_lmpm_parse(mms_par_node_t **cmd_node,
		mms_list_t *msg_list,
		char *buf);

int	mms_lmpl_parse(mms_par_node_t **cmd_node,
		mms_list_t *msg_list,
		char *buf);

int	mms_config_parse(mms_par_node_t **cmd_node,
		mms_list_t *msg_list,
		char *buf);

void	mms_mmsp_scan_string(char *);
void	mms_mmsp_delete_buffer();

void	mms_cfg_scan_string(char *);
void	mms_cfg_delete_buffer();

#endif	/* __MMS_PARSER_H__ */
