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


#include <thread.h>
#include <synch.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/int_types.h>
#include <mmsp_yacc.h>
#include <mms_list.h>
#include <mms_sym.h>
#include <mms_parser.h>
#include <mms_par_impl.h>
#include <mmsp_yacc.h>
#include <mms_sym.h>




#define		yyparse mms_mmsp_parse
int		yyparse(mms_pw_t *);

int	mms_mmsp_debug;
extern int	mms_mmsp__flex_debug;
extern	uchar_t	*mms_token_flags;

/*
 * The symbol table will be sorted in ascending order when the parser
 * is initialized. There is no need to add new symbols in any particular order.
 */

extern	mms_sym_t	*mms_symtab;
extern	int	mms_num_syms;
static int	mms_symtab_initialized = 0;
static mutex_t	mms_symtab_mutex = DEFAULTMUTEX;
static mutex_t	mmsp_mutex = DEFAULTMUTEX;

mms_pw_t	*
mms_par_init_wka(mms_par_node_t **cmd_node,
    mms_list_t *msg_list,
    mms_sym_t *depend_symtab, int num_depend_syms,
    int *depend_symtab_initialized)
{
	mms_pw_t	*wka;

	mms_list_create(msg_list, sizeof (mms_par_err_t),
	    offsetof(mms_par_err_t, pe_next));
	*cmd_node = NULL;
	wka = (mms_pw_t *)malloc(sizeof (mms_pw_t));
	if (wka == NULL) {
		/* Can't get mem for wka */
		return (NULL);
	}
	(void) memset(wka, 0, sizeof (mms_pw_t));
	wka->par_wka_token[0] = malloc(MMS_PAR_MAX_TOKEN + 1);
	if (wka->par_wka_token[0] == NULL) {
		free(wka);
		return (NULL);
	}
	wka->par_wka_token[1] = malloc(MMS_PAR_MAX_TOKEN + 1);
	if (wka->par_wka_token[1] == NULL) {
		free(wka->par_wka_token[0]);
		free(wka);
		return (NULL);
	}
	wka->par_wka_token_index = 1;

	wka->par_wka_token_flags = mms_token_flags;

	wka->par_wka_line = 1;
	wka->par_wka_col = 1;
	wka->par_wka_err_list = msg_list;
	wka->par_wka_cmd_node = cmd_node;

	wka->par_wka_symtab = mms_symtab;
	wka->par_wka_num_syms = mms_num_syms;
	wka->par_wka_symtab_depend = depend_symtab;
	wka->par_wka_num_syms_depend = num_depend_syms;
	*cmd_node = NULL;
	(void) mutex_lock(&mms_symtab_mutex);
	if (!mms_symtab_initialized) {
		mms_sort_sym_token(wka->par_wka_symtab, wka->par_wka_num_syms);
		mms_symtab_initialized = 1;
	}
	if (!(*depend_symtab_initialized)) {
		mms_sort_sym_token(wka->par_wka_symtab_depend,
		    wka->par_wka_num_syms_depend);
		*depend_symtab_initialized = 1;
	}
	(void) mutex_unlock(&mms_symtab_mutex);
	return (wka);
}

/*
 * The following is the symbols for all the MMP commands.
 */
extern	mms_sym_t	*mms_mmp_symtab;
extern	int	mms_num_mmsp_syms;
static	int	mms_mmp_symtab_initialized = 0;

/*
 *
 * mmp_parse_buf(), dmpm_parse_buf(), dmpd_parse_buf(), lmpm_parse_buf()
 * lmpl_parse_buf()
 *
 * Parameters:
 *	cmd_node	Ptr to the generated parse tree of XML cmd string
 *	msg_list	List needed by parser routine if errors encountered
 *	buf		XML cmd string that needs to be parsed.
 *
 * These functions are less specific version of the functions less the _buf
 * These routines use the generic mms_par_input routine as the input routine
 * used by the parser, thus if a user has a character string, they can
 * use these routines instead of having to generate their own input routine
 * and data structure that retains an index into the cmd string as the
 * parser parses the cmd.
 *
 * Return Value:
 *	0 	If cmd parsed without errors.
 *	1	If cmd parsed with errors.
 *	-1	If unable to allocate enough memory for parse tree.
 *
 */

int
mms_mmp_parse(mms_par_node_t **cmd_node, mms_list_t *msg_list, char *buf)
{

	mms_pw_t	*wka;
	int		rc = 0;

	(void) memset(msg_list, 0, sizeof (mms_list_t));
	mms_mmsp__flex_debug = 0;
	mms_mmsp_debug = 0;
	wka = mms_par_init_wka(cmd_node, msg_list,
	    mms_mmp_symtab, mms_num_mmsp_syms,
	    &mms_mmp_symtab_initialized);
	(void) strlcpy(wka->par_wka_parser, "mms_mmp_parse",
	    sizeof (wka->par_wka_parser));
	if (wka == NULL) {
		return (-1);
	}
	wka->par_wka_flags |= MMS_PW_DEPEND;	/* Look in depend tab 1st */
	wka->par_wka_lock = &mmsp_mutex;
	(void) mutex_lock(wka->par_wka_lock);
	mms_mmsp_scan_string(buf);
	/* LINTED assignment */
	if ((rc = yyparse(wka)) || wka->par_wka_err_count) {
		rc = 1;
	}
	mms_mmsp_delete_buffer();
	if (*cmd_node != NULL) {
		mms_pn_fini(*cmd_node);
	}
	(void) mutex_unlock(wka->par_wka_lock);
	free(wka->par_wka_token[0]);
	free(wka->par_wka_token[1]);
	free(wka);

	return (rc);
}

/*
 * These are the DMPM commands
 */
extern mms_sym_t	*mms_dmpm_symtab;
extern int	mms_num_dmpm_syms;
static int	mms_dmpm_symtab_initialized = 0;

int
mms_dmpm_parse(mms_par_node_t **cmd_node, mms_list_t *msg_list, char *buf)
{
	mms_pw_t	*wka;
	int		rc = 0;

	(void) memset(msg_list, 0, sizeof (mms_list_t));

	mms_mmsp__flex_debug = 0;
	mms_mmsp_debug = 0;
	wka = mms_par_init_wka(cmd_node, msg_list,
	    mms_dmpm_symtab, mms_num_dmpm_syms,
	    &mms_dmpm_symtab_initialized);
	(void) strlcpy(wka->par_wka_parser, "mms_dmpm_parse",
	    sizeof (wka->par_wka_parser));
	if (wka == NULL) {
		return (-1);
	}
	wka->par_wka_flags |= MMS_PW_DEPEND;	/* Look in depend tab 1st */
	wka->par_wka_lock = &mmsp_mutex;
	(void) mutex_lock(wka->par_wka_lock);
	mms_mmsp_scan_string(buf);
	if (yyparse(wka) || wka->par_wka_err_count) {
		rc = 1;
	}
	mms_mmsp_delete_buffer();
	mms_pn_fini(*cmd_node);
	(void) mutex_unlock(wka->par_wka_lock);
	free(wka->par_wka_token[0]);
	free(wka->par_wka_token[1]);
	free(wka);
	return (rc);
}

/*
 * These are the DMPD commands
 */
extern	mms_sym_t	*mms_dmpd_symtab;

extern	int	mms_num_dmpd_syms;
static int	mms_dmpd_symtab_initialized = 0;

int
mms_dmpd_parse(mms_par_node_t **cmd_node, mms_list_t *msg_list, char *buf)
{
	mms_pw_t	*wka;
	int		rc = 0;

	(void) memset(msg_list, 0, sizeof (mms_list_t));

	mms_mmsp__flex_debug = 0;
	mms_mmsp_debug = 0;
	wka = mms_par_init_wka(cmd_node, msg_list,
	    mms_dmpd_symtab, mms_num_dmpd_syms,
	    &mms_dmpd_symtab_initialized);
	(void) strlcpy(wka->par_wka_parser, "mms_dmpd_parse",
	    sizeof (wka->par_wka_parser));
	if (wka == NULL) {
		return (-1);
	}
	wka->par_wka_flags |= MMS_PW_DEPEND;	/* Look in depend tab 1st */
	wka->par_wka_lock = &mmsp_mutex;
	(void) mutex_lock(wka->par_wka_lock);
	mms_mmsp_scan_string(buf);
	if (yyparse(wka) || wka->par_wka_err_count) {
		rc = 1;
	}
	mms_mmsp_delete_buffer();
	mms_pn_fini(*cmd_node);
	(void) mutex_unlock(wka->par_wka_lock);
	free(wka->par_wka_token[0]);
	free(wka->par_wka_token[1]);
	free(wka);
	return (rc);
}

/*
 * These are the LMPM commands
 */
extern mms_sym_t	*mms_lmpm_symtab;
extern	int	mms_num_lmpm_syms;
static int	mms_lmpm_symtab_initialized = 0;

int
mms_lmpm_parse(mms_par_node_t **cmd_node, mms_list_t *msg_list, char *buf)
{
	mms_pw_t	*wka;
	int		rc = 0;

	(void) memset(msg_list, 0, sizeof (mms_list_t));
	mms_mmsp__flex_debug = 0;
	mms_mmsp_debug = 0;
	wka = mms_par_init_wka(cmd_node, msg_list,
	    mms_lmpm_symtab, mms_num_lmpm_syms,
	    &mms_lmpm_symtab_initialized);
	(void) strlcpy(wka->par_wka_parser, "mms_lmpm_parse",
	    sizeof (wka->par_wka_parser));
	if (wka == NULL) {
		return (-1);
	}
	wka->par_wka_flags |= MMS_PW_DEPEND;	/* Look in depend tab 1st */
	wka->par_wka_lock = &mmsp_mutex;
	(void) mutex_lock(wka->par_wka_lock);
	mms_mmsp_scan_string(buf);
	if (yyparse(wka) || wka->par_wka_err_count) {
		rc = 1;
	}
	mms_mmsp_delete_buffer();
	mms_pn_fini(*cmd_node);
	(void) mutex_unlock(wka->par_wka_lock);
	free(wka->par_wka_token[0]);
	free(wka->par_wka_token[1]);
	free(wka);
	return (rc);
}

/*
 * These are the LMPD commands
 */
extern mms_sym_t	*mms_lmpl_symtab;
extern	int	mms_num_lmpl_syms;
static int	mms_lmpl_symtab_initialized = 0;

int
mms_lmpl_parse(mms_par_node_t **cmd_node, mms_list_t *msg_list, char *buf)
{
	mms_pw_t	*wka;
	int		rc = 0;

	(void) memset(msg_list, 0, sizeof (mms_list_t));
	mms_mmsp__flex_debug = 0;
	mms_mmsp_debug = 0;
	wka = mms_par_init_wka(cmd_node, msg_list,
	    mms_lmpl_symtab, mms_num_lmpl_syms,
	    &mms_lmpl_symtab_initialized);
	(void) strlcpy(wka->par_wka_parser, "mms_lmpl_parse",
	    sizeof (wka->par_wka_parser));
	if (wka == NULL) {
		return (-1);
	}
	wka->par_wka_flags |= MMS_PW_DEPEND;	/* Look in depend tab 1st */
	wka->par_wka_lock = &mmsp_mutex;
	(void) mutex_lock(wka->par_wka_lock);
	mms_mmsp_scan_string(buf);
	if (yyparse(wka) || wka->par_wka_err_count) {
		rc = 1;
	}
	mms_mmsp_delete_buffer();
	mms_pn_fini(*cmd_node);
	(void) mutex_unlock(wka->par_wka_lock);
	free(wka->par_wka_token[0]);
	free(wka->par_wka_token[1]);
	free(wka);
	return (rc);
}
