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
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* LINTLIBRARY */
/* PROTOLIB1 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Supplemental Pseudo-code to get lint to consider these symbols used.
 */
#include	<msg.h>
#include	<debug.h>
#include	<elfedit.h>

/*
 * Lint doesn't understand that both elfedit{32|64}_init_obj_state()
 * gets built, because it doesn't know that elfedit_machelf.c gets
 * compiled twice. The difference between this case and the others
 * is that we don't use macros to give them both the same name,
 * because elfedit.c needs to know about both explictly. So,
 * supply the "missing" one here, for lint's benefit.
 *
 * This dummy routine eliminates the "name used but not defined"
 * errors that otherwise result.
 */
#ifdef _ELF64
/*ARGSUSED*/
void
elfedit32_init_obj_state(const char *file, int fd, Elf *elf)
{
}
#else
/*ARGSUSED*/
void
elfedit64_init_obj_state(const char *file, int fd, Elf *elf)
{
}
#endif


void
foo()
{
	dbg_print(NULL, NULL, 0);

	elfedit_array_elts_delete(NULL, NULL, 0, 0, 0, 0);
	elfedit_array_elts_move(NULL, NULL, 0, 0, 0, 0, 0, NULL);

	(void) _elfedit_msg((Msg)&__elfedit_msg[0]);

	(void) elfedit_atoi(NULL, NULL);
	(void) elfedit_atoui(NULL, NULL);
	(void) elfedit_atoconst(NULL, 0);

	(void) elfedit_atoi2(NULL, NULL, NULL);
	(void) elfedit_atoui2(NULL, NULL, NULL);
	(void) elfedit_atoconst2(NULL, 0, NULL);

	(void) elfedit_atoi_range(NULL, NULL, 0, 0, NULL);
	(void) elfedit_atoui_range(NULL, NULL, 0, 0, NULL);
	(void) elfedit_atoconst_range(NULL, NULL, 0, 0, 0);

	(void) elfedit_atoi_range2(NULL, 0, 0, NULL, NULL);
	(void) elfedit_atoui_range2(NULL, 0, 0, NULL, NULL);
	(void) elfedit_atoconst_range2(NULL, 0, 0, 0, NULL);

	(void) elfedit_atoi_value_to_str(NULL, 0, 0);
	(void) elfedit_atoui_value_to_str(NULL, 0, 0);
	(void) elfedit_atoconst_value_to_str(0, 0, 0);

	(void) elfedit_atoshndx(NULL, 0);

	(void) elfedit_cpl_atoi(NULL, NULL);
	(void) elfedit_cpl_atoui(NULL, NULL);
	(void) elfedit_cpl_atoconst(NULL, 0);
	(void) elfedit_cpl_ndx(NULL, 0);

	(void) elfedit_dyn_offset_to_str(NULL, NULL);
	(void) elfedit_dynstr_insert(NULL, NULL, NULL, NULL);
	(void) elfedit_flags();
	(void) elfedit_modified_ehdr(NULL);
	(void) elfedit_modified_phdr(NULL);
	(void) elfedit_modified_shdr(NULL);
	(void) elfedit_mach_sunw_hw1_to_atoui(0);
	(void) elfedit_name_to_shndx(NULL, NULL);
	(void) elfedit_name_to_symndx(NULL, NULL, NULL, ELFEDIT_MSG_ERR, NULL);
	(void) elfedit_outstyle();
	(void) elfedit_sec_get(NULL, NULL);
	(void) elfedit_sec_getcap(NULL, NULL, NULL);
	(void) elfedit_sec_getdyn(NULL, NULL, NULL);
	(void) elfedit_sec_getstr(NULL, 0, 0);
	(void) elfedit_sec_getsyminfo(NULL, NULL, NULL);
	(void) elfedit_sec_getsymtab(NULL, 0, 0, NULL, NULL, NULL, NULL);
	(void) elfedit_sec_getversym(NULL, NULL, NULL, NULL);
	(void) elfedit_sec_getxshndx(NULL, NULL, NULL, NULL);
	(void) elfedit_sec_msgprefix(NULL);
	(void) elfedit_shndx_to_name(NULL, NULL);
	elfedit_str_to_c_literal(NULL, NULL);
	(void) elfedit_strtab_insert(NULL, NULL, NULL, NULL);
	(void) elfedit_strtab_insert_test(NULL, NULL, NULL, NULL);
	(void) elfedit_type_to_shndx(NULL, 0);
}
