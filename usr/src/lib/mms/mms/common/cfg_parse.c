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
#include <mms_list.h>
#include <mms_sym.h>
#include <mms_parser.h>
#include <mms_par_impl.h>
#include <cfg_yacc.h>

#define	yyparse mms_cfg_parse
int	yyparse(mms_pw_t *);

int	mms_cfg_debug;
extern	int	mms_cfg__flex_debug;

/*
 * Parse the config files
 */
extern	mms_sym_t	*mms_config_symtab;
extern	int	mms_num_config_syms;
static	mutex_t	mms_config_mutex = DEFAULTMUTEX;
static	int	mms_config_symtab_initialized = 0;

/*
 *
 * config_parse_buf()
 *
 * Parameters:
 *	cfg_node	Ptr to the generated parse tree of XML cfg string
 *	msg_list	List needed by parser routine if errors encountered
 *	buf		XML cmd string that needs to be parsed.
 *
 * This function is a generic version of mms_config_parse.
 * It is designed so that
 * a user does not have to create a input routine. The only requirement is
 * that the XML string they need parsed be a character string.
 *
 * Return Values:
 *	0	If config parsed without errors.
 *	1	If config parsed with errors.
 *	-1	If unable to allocate enough memory for parse tree.
 *
 */

int
mms_config_parse(mms_par_node_t **cfg_node, mms_list_t *msg_list, char *buf)
{
	mms_pw_t	*wka;
	int		rc = 0;

	mms_cfg__flex_debug = 0;
	mms_cfg_debug = 0;
	wka = mms_par_init_wka(cfg_node, msg_list,
	    mms_config_symtab, mms_num_config_syms,
	    &mms_config_symtab_initialized);
	strlcpy(wka->par_wka_parser, "mms_config_parse",
	    sizeof (wka->par_wka_parser));
	if (wka == NULL) {
		return (-1);
	}
	wka->par_wka_symtab = NULL;
	wka->par_wka_num_syms = 0;
	wka->par_wka_lock = &mms_config_mutex;
	mutex_lock(wka->par_wka_lock);
	mms_cfg_scan_string(buf);
	if (yyparse(wka) || wka->par_wka_err_count) {
		rc = 1;
	}
	mms_cfg_delete_buffer();
	mms_pn_fini(*cfg_node);
	mutex_unlock(wka->par_wka_lock);
	free(wka->par_wka_token[0]);
	free(wka->par_wka_token[1]);
	free(wka);
	return (rc);
}
