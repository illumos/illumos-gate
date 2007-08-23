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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <cmd_mem.h>
#include <cmd_bank.h>
#include <cmd_dimm.h>
#include <cmd.h>

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/mem.h>
#include <sys/nvpair.h>

void
cmd_bank_add_dimm(fmd_hdl_t *hdl, cmd_bank_t *bank, cmd_dimm_t *dimm)
{
	cmd_bank_memb_t *bm;

	fmd_hdl_debug(hdl, "attaching dimm %s to bank %s\n", dimm->dimm_unum,
	    bank->bank_unum);

	dimm->dimm_bank = bank;

	bm = fmd_hdl_zalloc(hdl, sizeof (cmd_bank_memb_t), FMD_SLEEP);
	bm->bm_dimm = dimm;
	cmd_list_append(&bank->bank_dimms, bm);
}

void
cmd_bank_remove_dimm(fmd_hdl_t *hdl, cmd_bank_t *bank, cmd_dimm_t *dimm)
{
	cmd_bank_memb_t *bm;

	fmd_hdl_debug(hdl, "detaching dimm %s from bank %s\n", dimm->dimm_unum,
	    bank->bank_unum);

	for (bm = cmd_list_next(&bank->bank_dimms); bm != NULL;
	    bm = cmd_list_next(bm)) {
		if (bm->bm_dimm != dimm)
			continue;

		cmd_list_delete(&bank->bank_dimms, bm);
		dimm->dimm_bank = NULL;
		fmd_hdl_free(hdl, bm, sizeof (cmd_bank_memb_t));
		return;
	}

	fmd_hdl_abort(hdl, "attempt to disconnect dimm from non-parent bank\n");
}

static void
bank_dimmlist_create(fmd_hdl_t *hdl, cmd_bank_t *bank)
{
	cmd_dimm_t *dimm;

	for (dimm = cmd_list_next(&cmd.cmd_dimms); dimm != NULL;
	    dimm = cmd_list_next(dimm)) {
		if (fmd_nvl_fmri_contains(hdl, bank->bank_asru_nvl,
		    dimm->dimm_asru_nvl))
			cmd_bank_add_dimm(hdl, bank, dimm);
	}
}

static void
bank_dimmlist_free(fmd_hdl_t *hdl, cmd_bank_t *bank)
{
	cmd_bank_memb_t *bm;

	while ((bm = cmd_list_next(&bank->bank_dimms)) != NULL) {
		cmd_list_delete(&bank->bank_dimms, bm);
		bm->bm_dimm->dimm_bank = NULL;
		fmd_hdl_free(hdl, bm, sizeof (cmd_bank_memb_t));
	}
}

nvlist_t *
cmd_bank_fru(cmd_bank_t *bank)
{
	return (bank->bank_asru_nvl);
}

nvlist_t *
cmd_bank_create_fault(fmd_hdl_t *hdl, cmd_bank_t *bank, const char *fltnm,
    uint_t cert)
{
	return (cmd_nvl_create_fault(hdl, fltnm, cert, bank->bank_asru_nvl,
	    bank->bank_asru_nvl, NULL));
}

static void
bank_free(fmd_hdl_t *hdl, cmd_bank_t *bank, int destroy)
{
	if (bank->bank_case.cc_cp != NULL)
		cmd_case_fini(hdl, bank->bank_case.cc_cp, destroy);

	bank_dimmlist_free(hdl, bank);
	cmd_fmri_fini(hdl, &bank->bank_asru, destroy);

	if (destroy)
		fmd_buf_destroy(hdl, NULL, bank->bank_bufname);
	cmd_list_delete(&cmd.cmd_banks, bank);
	fmd_hdl_free(hdl, bank, sizeof (cmd_bank_t));
}

void
cmd_bank_destroy(fmd_hdl_t *hdl, cmd_bank_t *bank)
{
	fmd_stat_destroy(hdl, 1, &(bank->bank_retstat));
	bank_free(hdl, bank, FMD_B_TRUE);
}

static cmd_bank_t *
bank_lookup_by_unum(const char *unum)
{
	cmd_bank_t *bank;

	for (bank = cmd_list_next(&cmd.cmd_banks); bank != NULL;
	    bank = cmd_list_next(bank)) {
		if (strcmp(bank->bank_unum, unum) == 0)
			return (bank);
	}

	return (NULL);
}

cmd_bank_t *
cmd_bank_create(fmd_hdl_t *hdl, nvlist_t *asru)
{
	cmd_bank_t *bank;
	const char *unum;

	if (!fmd_nvl_fmri_present(hdl, asru)) {
		fmd_hdl_debug(hdl, "dimm_lookup: discarding old ereport\n");
		return (NULL);
	}

	if ((unum = cmd_fmri_get_unum(asru)) == NULL) {
		CMD_STAT_BUMP(bad_mem_asru);
		return (NULL);
	}

	fmd_hdl_debug(hdl, "bank_create: creating new bank %s\n", unum);
	CMD_STAT_BUMP(bank_creat);

	bank = fmd_hdl_zalloc(hdl, sizeof (cmd_bank_t), FMD_SLEEP);
	bank->bank_nodetype = CMD_NT_BANK;
	bank->bank_version = CMD_BANK_VERSION;

	cmd_bufname(bank->bank_bufname, sizeof (bank->bank_bufname), "bank_%s",
	    unum);
	cmd_fmri_init(hdl, &bank->bank_asru, asru, "bank_asru_%s", unum);

	(void) nvlist_lookup_string(bank->bank_asru_nvl, FM_FMRI_MEM_UNUM,
	    (char **)&bank->bank_unum);

	bank_dimmlist_create(hdl, bank);

	cmd_mem_retirestat_create(hdl, &bank->bank_retstat, bank->bank_unum, 0,
	    CMD_BANK_STAT_PREFIX);

	cmd_list_append(&cmd.cmd_banks, bank);
	cmd_bank_dirty(hdl, bank);

	return (bank);
}

cmd_bank_t *
cmd_bank_lookup(fmd_hdl_t *hdl, nvlist_t *asru)
{
	cmd_bank_t *bank;
	const char *unum;

	if ((unum = cmd_fmri_get_unum(asru)) == NULL) {
		CMD_STAT_BUMP(bad_mem_asru);
		return (NULL);
	}

	bank = bank_lookup_by_unum(unum);

	if (bank != NULL && !fmd_nvl_fmri_present(hdl, bank->bank_asru_nvl)) {
		fmd_hdl_debug(hdl, "bank_lookup: discarding old bank\n");
		cmd_bank_destroy(hdl, bank);
		return (NULL);
	}

	return (bank);
}

static cmd_bank_t *
bank_v0tov1(fmd_hdl_t *hdl, cmd_bank_0_t *old, size_t oldsz)
{
	cmd_bank_t *new;

	if (oldsz != sizeof (cmd_bank_0_t)) {
		fmd_hdl_abort(hdl, "size of state doesn't match size of "
		    "version 0 state (%u bytes).\n", sizeof (cmd_bank_0_t));
	}

	new = fmd_hdl_zalloc(hdl, sizeof (cmd_bank_t), FMD_SLEEP);
	new->bank_header = old->bank0_header;
	new->bank_version = CMD_BANK_VERSION;
	new->bank_asru = old->bank0_asru;
	new->bank_nretired = old->bank0_nretired;

	fmd_hdl_free(hdl, old, oldsz);
	return (new);
}

static cmd_bank_t *
bank_wrapv1(fmd_hdl_t *hdl, cmd_bank_pers_t *pers, size_t psz)
{
	cmd_bank_t *bank;

	if (psz != sizeof (cmd_bank_pers_t)) {
		fmd_hdl_abort(hdl, "size of state doesn't match size of "
		    "version 1 state (%u bytes).\n", sizeof (cmd_bank_pers_t));
	}

	bank = fmd_hdl_zalloc(hdl, sizeof (cmd_bank_t), FMD_SLEEP);
	bcopy(pers, bank, sizeof (cmd_bank_pers_t));
	fmd_hdl_free(hdl, pers, psz);
	return (bank);
}

void *
cmd_bank_restore(fmd_hdl_t *hdl, fmd_case_t *cp, cmd_case_ptr_t *ptr)
{
	cmd_bank_t *bank;

	for (bank = cmd_list_next(&cmd.cmd_banks); bank != NULL;
	    bank = cmd_list_next(bank)) {
		if (strcmp(bank->bank_bufname, ptr->ptr_name) == 0)
			break;
	}

	if (bank == NULL) {
		int migrated = 0;
		size_t banksz;

		fmd_hdl_debug(hdl, "restoring bank from %s\n", ptr->ptr_name);

		if ((banksz = fmd_buf_size(hdl, NULL, ptr->ptr_name)) == 0) {
			fmd_hdl_abort(hdl, "bank referenced by case %s does "
			    "not exist in saved state\n",
			    fmd_case_uuid(hdl, cp));
		} else if (banksz > CMD_BANK_MAXSIZE ||
		    banksz < CMD_BANK_MINSIZE) {
			fmd_hdl_abort(hdl, "bank buffer referenced by case %s "
			    "is out of bounds (is %u bytes, max %u, min %u)\n",
			    fmd_case_uuid(hdl, cp), banksz,
			    CMD_BANK_MAXSIZE, CMD_BANK_MAXSIZE);
		}

		if ((bank = cmd_buf_read(hdl, NULL, ptr->ptr_name,
		    banksz)) == NULL) {
			fmd_hdl_abort(hdl, "failed to read bank buf %s",
			    ptr->ptr_name);
		}

		fmd_hdl_debug(hdl, "found %d in version field\n",
		    bank->bank_version);

		if (CMD_BANK_VERSIONED(bank)) {
			switch (bank->bank_version) {
			case CMD_BANK_VERSION_1:
				bank = bank_wrapv1(hdl, (cmd_bank_pers_t *)bank,
				    banksz);
				break;
			default:
				fmd_hdl_abort(hdl, "unknown version (found %d) "
				    "for bank state referenced by case %s.\n",
				    bank->bank_version, fmd_case_uuid(hdl, cp));
				break;
			}
		} else {
			bank = bank_v0tov1(hdl, (cmd_bank_0_t *)bank, banksz);
			migrated = 1;
		}

		if (migrated) {
			CMD_STAT_BUMP(bank_migrat);
			cmd_bank_dirty(hdl, bank);
		}

		cmd_fmri_restore(hdl, &bank->bank_asru);

		if ((errno = nvlist_lookup_string(bank->bank_asru_nvl,
		    FM_FMRI_MEM_UNUM, (char **)&bank->bank_unum)) != 0)
			fmd_hdl_abort(hdl, "failed to retrieve nuum from asru");

		bank_dimmlist_create(hdl, bank);

		cmd_mem_retirestat_create(hdl, &bank->bank_retstat,
		    bank->bank_unum, bank->bank_nretired, CMD_BANK_STAT_PREFIX);

		cmd_list_append(&cmd.cmd_banks, bank);
	}

	switch (ptr->ptr_subtype) {
	case BUG_PTR_BANK_CASE:
		fmd_hdl_debug(hdl, "recovering from out of order page ptr\n");
		cmd_case_redirect(hdl, cp, CMD_PTR_BANK_CASE);
		/*FALLTHROUGH*/
	case CMD_PTR_BANK_CASE:
		cmd_mem_case_restore(hdl, &bank->bank_case, cp, "bank",
		    bank->bank_unum);
		break;
	default:
		fmd_hdl_abort(hdl, "invalid %s subtype %d\n",
		    ptr->ptr_name, ptr->ptr_subtype);
	}

	return (bank);
}

void
cmd_bank_validate(fmd_hdl_t *hdl)
{
	cmd_bank_t *bank, *next;

	for (bank = cmd_list_next(&cmd.cmd_banks); bank != NULL; bank = next) {
		next = cmd_list_next(bank);

		if (!fmd_nvl_fmri_present(hdl, bank->bank_asru_nvl))
			cmd_bank_destroy(hdl, bank);
	}
}

void
cmd_bank_dirty(fmd_hdl_t *hdl, cmd_bank_t *bank)
{
	if (fmd_buf_size(hdl, NULL, bank->bank_bufname) !=
	    sizeof (cmd_bank_pers_t))
		fmd_buf_destroy(hdl, NULL, bank->bank_bufname);

	/* No need to rewrite the FMRIs in the bank - they don't change */
	fmd_buf_write(hdl, NULL, bank->bank_bufname, &bank->bank_pers,
	    sizeof (cmd_bank_pers_t));
}

void
cmd_bank_gc(fmd_hdl_t *hdl)
{
	cmd_bank_validate(hdl);
}

void
cmd_bank_fini(fmd_hdl_t *hdl)
{
	cmd_bank_t *bank;

	while ((bank = cmd_list_next(&cmd.cmd_banks)) != NULL)
		bank_free(hdl, bank, FMD_B_FALSE);
}
