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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <strings.h>
#include <stdlib.h>
#include <assert.h>

#include <dt_impl.h>
#include <dt_parser.h>
#include <dt_as.h>

void
dt_irlist_create(dt_irlist_t *dlp)
{
	bzero(dlp, sizeof (dt_irlist_t));
	dlp->dl_label = 1;
}

void
dt_irlist_destroy(dt_irlist_t *dlp)
{
	dt_irnode_t *dip, *nip;

	for (dip = dlp->dl_list; dip != NULL; dip = nip) {
		nip = dip->di_next;
		free(dip);
	}
}

void
dt_irlist_append(dt_irlist_t *dlp, dt_irnode_t *dip)
{
	if (dlp->dl_last != NULL)
		dlp->dl_last->di_next = dip;
	else
		dlp->dl_list = dip;

	dlp->dl_last = dip;

	if (dip->di_label == DT_LBL_NONE || dip->di_instr != DIF_INSTR_NOP)
		dlp->dl_len++; /* don't count forward refs in instr count */
}

uint_t
dt_irlist_label(dt_irlist_t *dlp)
{
	return (dlp->dl_label++);
}

/*ARGSUSED*/
static int
dt_countvar(dt_idhash_t *dhp, dt_ident_t *idp, void *data)
{
	size_t *np = data;

	if (idp->di_flags & (DT_IDFLG_DIFR | DT_IDFLG_DIFW))
		(*np)++; /* include variable in vartab */

	return (0);
}

/*ARGSUSED*/
static int
dt_copyvar(dt_idhash_t *dhp, dt_ident_t *idp, void *data)
{
	dt_pcb_t *pcb = data;
	dtrace_difv_t *dvp;
	ssize_t stroff;
	dt_node_t dn;

	if (!(idp->di_flags & (DT_IDFLG_DIFR | DT_IDFLG_DIFW)))
		return (0); /* omit variable from vartab */

	dvp = &pcb->pcb_difo->dtdo_vartab[pcb->pcb_asvidx++];
	stroff = dt_strtab_insert(pcb->pcb_strtab, idp->di_name);

	if (stroff == -1L)
		longjmp(pcb->pcb_jmpbuf, EDT_NOMEM);
	if (stroff > DIF_STROFF_MAX)
		longjmp(pcb->pcb_jmpbuf, EDT_STR2BIG);

	dvp->dtdv_name = (uint_t)stroff;
	dvp->dtdv_id = idp->di_id;
	dvp->dtdv_flags = 0;

	dvp->dtdv_kind = (idp->di_kind == DT_IDENT_ARRAY) ?
	    DIFV_KIND_ARRAY : DIFV_KIND_SCALAR;

	if (idp->di_flags & DT_IDFLG_LOCAL)
		dvp->dtdv_scope = DIFV_SCOPE_LOCAL;
	else if (idp->di_flags & DT_IDFLG_TLS)
		dvp->dtdv_scope = DIFV_SCOPE_THREAD;
	else
		dvp->dtdv_scope = DIFV_SCOPE_GLOBAL;

	if (idp->di_flags & DT_IDFLG_DIFR)
		dvp->dtdv_flags |= DIFV_F_REF;
	if (idp->di_flags & DT_IDFLG_DIFW)
		dvp->dtdv_flags |= DIFV_F_MOD;

	bzero(&dn, sizeof (dn));
	dt_node_type_assign(&dn, idp->di_ctfp, idp->di_type);
	dt_node_diftype(&dn, &dvp->dtdv_type);

	idp->di_flags &= ~(DT_IDFLG_DIFR | DT_IDFLG_DIFW);
	return (0);
}

static ssize_t
dt_copystr(const char *s, size_t n, size_t off, dt_pcb_t *pcb)
{
	bcopy(s, pcb->pcb_difo->dtdo_strtab + off, n);
	return (n);
}

static void
dt_as_undef(const dt_ident_t *idp, uint_t offset)
{
	const char *kind, *mark = (idp->di_flags & DT_IDFLG_USER) ? "``" : "`";
	const dtrace_syminfo_t *dts = idp->di_data;

	if (idp->di_flags & DT_IDFLG_USER)
		kind = "user";
	else if (idp->di_flags & DT_IDFLG_PRIM)
		kind = "primary kernel";
	else
		kind = "loadable kernel";

	yylineno = idp->di_lineno;

	xyerror(D_ASRELO, "relocation remains against %s symbol %s%s%s (offset "
	    "0x%x)\n", kind, dts->dts_object, mark, dts->dts_name, offset);
}

dtrace_difo_t *
dt_as(dt_pcb_t *pcb)
{
	dtrace_hdl_t *dtp = pcb->pcb_hdl;
	dt_irlist_t *dlp = &pcb->pcb_ir;
	uint_t *labels = NULL;
	dt_irnode_t *dip;
	dtrace_difo_t *dp;
	dt_ident_t *idp;

	size_t n = 0;
	uint_t i;

	uint_t kmask, kbits, umask, ubits;
	uint_t krel = 0, urel = 0;

	/*
	 * Select bitmasks based upon the desired symbol linking policy.  We
	 * test (di_ident->di_flags & xmask) == xbits to determine if the
	 * symbol should have a relocation entry generated in the loop below.
	 *
	 * DT_LINK_KERNEL = kernel symbols static, user symbols dynamic
	 * DT_LINK_PRIMARY = primary kernel symbols static, others dynamic
	 * DT_LINK_DYNAMIC = all symbols dynamic
	 * DT_LINK_STATIC = all symbols static
	 *
	 * By 'static' we mean that we use the symbol's value at compile-time
	 * in the final DIF.  By 'dynamic' we mean that we create a relocation
	 * table entry for the symbol's value so it can be relocated later.
	 */
	switch (dtp->dt_linkmode) {
	case DT_LINK_KERNEL:
		kmask = 0;
		kbits = -1u;
		umask = DT_IDFLG_USER;
		ubits = DT_IDFLG_USER;
		break;
	case DT_LINK_PRIMARY:
		kmask = DT_IDFLG_USER | DT_IDFLG_PRIM;
		kbits = 0;
		umask = DT_IDFLG_USER;
		ubits = DT_IDFLG_USER;
		break;
	case DT_LINK_DYNAMIC:
		kmask = DT_IDFLG_USER;
		kbits = 0;
		umask = DT_IDFLG_USER;
		ubits = DT_IDFLG_USER;
		break;
	case DT_LINK_STATIC:
		kmask = umask = 0;
		kbits = ubits = -1u;
		break;
	default:
		xyerror(D_UNKNOWN, "internal error -- invalid link mode %u\n",
		    dtp->dt_linkmode);
	}

	if ((dp = malloc(sizeof (dtrace_difo_t))) == NULL)
		longjmp(pcb->pcb_jmpbuf, EDT_NOMEM);

	assert(yypcb->pcb_difo == NULL);
	yypcb->pcb_difo = dp;

	bzero(dp, sizeof (dtrace_difo_t));
	dp->dtdo_refcnt = 1;
	dp->dtdo_buf = malloc(sizeof (dif_instr_t) * dlp->dl_len);

	if (dp->dtdo_buf == NULL)
		longjmp(pcb->pcb_jmpbuf, EDT_NOMEM);

	if ((labels = malloc(sizeof (uint_t) * dlp->dl_label)) == NULL)
		longjmp(pcb->pcb_jmpbuf, EDT_NOMEM);

	/*
	 * Make an initial pass through the instruction list, filling in the
	 * instruction buffer with valid instructions and skipping labeled nops.
	 * While doing this, we also fill in our labels[] translation table
	 * and we count up the number of relocation table entries we will need.
	 */
	for (i = 0, dip = dlp->dl_list; dip != NULL; dip = dip->di_next) {
		if (dip->di_label != DT_LBL_NONE)
			labels[dip->di_label] = i;

		if (dip->di_label == DT_LBL_NONE ||
		    dip->di_instr != DIF_INSTR_NOP)
			dp->dtdo_buf[i++] = dip->di_instr;

		if ((idp = dip->di_ident) == NULL)
			continue; /* no relocation entry needed */

		if ((idp->di_flags & kmask) == kbits)
			krel++;
		else if ((idp->di_flags & umask) == ubits)
			urel++;
	}

	assert(i == dlp->dl_len);
	dp->dtdo_len = dlp->dl_len;

	/*
	 * Make a second pass through the instructions, relocating each branch
	 * label to the index of the final instruction in the buffer and noting
	 * any other instruction-specific DIFO flags such as dtdo_destructive.
	 */
	for (i = 0; i < dp->dtdo_len; i++) {
		dif_instr_t instr = dp->dtdo_buf[i];
		uint_t op = DIF_INSTR_OP(instr);

		if (op == DIF_OP_CALL) {
			if (DIF_INSTR_SUBR(instr) == DIF_SUBR_COPYOUT ||
			    DIF_INSTR_SUBR(instr) == DIF_SUBR_COPYOUTSTR)
				dp->dtdo_destructive = 1;
			continue;
		}

		if (op >= DIF_OP_BA && op <= DIF_OP_BLEU) {
			assert(DIF_INSTR_LABEL(instr) < dlp->dl_label);
			dp->dtdo_buf[i] = DIF_INSTR_BRANCH(op,
			    labels[DIF_INSTR_LABEL(instr)]);
		}
	}

	free(labels);
	yypcb->pcb_asvidx = 0;

	/*
	 * Allocate memory for the appropriate number of variable records and
	 * then fill in each variable record.  As we populate the variable
	 * table we insert the corresponding variable names into the strtab.
	 */
	(void) dt_idhash_iter(dtp->dt_tls, dt_countvar, &n);
	(void) dt_idhash_iter(dtp->dt_globals, dt_countvar, &n);
	(void) dt_idhash_iter(pcb->pcb_locals, dt_countvar, &n);

	if (n != 0) {
		dp->dtdo_vartab = malloc(n * sizeof (dtrace_difv_t));
		dp->dtdo_varlen = (uint32_t)n;

		if (dp->dtdo_vartab == NULL)
			longjmp(pcb->pcb_jmpbuf, EDT_NOMEM);

		(void) dt_idhash_iter(dtp->dt_tls, dt_copyvar, pcb);
		(void) dt_idhash_iter(dtp->dt_globals, dt_copyvar, pcb);
		(void) dt_idhash_iter(pcb->pcb_locals, dt_copyvar, pcb);
	}

	/*
	 * Allocate memory for the appropriate number of relocation table
	 * entries based upon our kernel and user counts from the first pass.
	 */
	if (krel != 0) {
		dp->dtdo_kreltab = malloc(krel * sizeof (dof_relodesc_t));
		dp->dtdo_krelen = krel;

		if (dp->dtdo_kreltab == NULL)
			longjmp(pcb->pcb_jmpbuf, EDT_NOMEM);
	}

	if (urel != 0) {
		dp->dtdo_ureltab = malloc(urel * sizeof (dof_relodesc_t));
		dp->dtdo_urelen = urel;

		if (dp->dtdo_ureltab == NULL)
			longjmp(pcb->pcb_jmpbuf, EDT_NOMEM);
	}

	/*
	 * If any relocations are needed, make another pass through the
	 * instruction list and fill in the relocation table entries.
	 */
	if (krel + urel != 0) {
		uint_t knodef = pcb->pcb_cflags & DTRACE_C_KNODEF;
		uint_t unodef = pcb->pcb_cflags & DTRACE_C_UNODEF;

		dof_relodesc_t *krp = dp->dtdo_kreltab;
		dof_relodesc_t *urp = dp->dtdo_ureltab;

		i = 0; /* dtdo_buf[] index */

		for (dip = dlp->dl_list; dip != NULL; dip = dip->di_next) {
			dof_relodesc_t *rp;
			ssize_t soff;
			uint_t nodef;

			if (dip->di_label != DT_LBL_NONE &&
			    dip->di_instr == DIF_INSTR_NOP)
				continue; /* skip label declarations */

			i++; /* advance dtdo_buf[] index */

			if ((idp = dip->di_ident) == NULL)
				continue; /* no relocation entry needed */

			if ((idp->di_flags & kmask) == kbits) {
				nodef = knodef;
				rp = krp++;
			} else if ((idp->di_flags & umask) == ubits) {
				nodef = unodef;
				rp = urp++;
			} else
				continue;

			if (!nodef)
				dt_as_undef(idp, i);

			assert(DIF_INSTR_OP(dip->di_instr) == DIF_OP_SETX);
			soff = dt_strtab_insert(pcb->pcb_strtab, idp->di_name);

			if (soff == -1L)
				longjmp(pcb->pcb_jmpbuf, EDT_NOMEM);
			if (soff > DIF_STROFF_MAX)
				longjmp(pcb->pcb_jmpbuf, EDT_STR2BIG);

			rp->dofr_name = (dof_stridx_t)soff;
			rp->dofr_type = DOF_RELO_SETX;
			rp->dofr_offset = DIF_INSTR_INTEGER(dip->di_instr) *
			    sizeof (uint64_t);
			rp->dofr_data = 0;
		}

		assert(krp == dp->dtdo_kreltab + dp->dtdo_krelen);
		assert(urp == dp->dtdo_ureltab + dp->dtdo_urelen);
		assert(i == dp->dtdo_len);
	}

	/*
	 * Allocate memory for the compiled string table and then copy the
	 * chunks from the string table into the final string buffer.
	 */
	if ((n = dt_strtab_size(pcb->pcb_strtab)) != 0) {
		if ((dp->dtdo_strtab = malloc(n)) == NULL)
			longjmp(pcb->pcb_jmpbuf, EDT_NOMEM);

		(void) dt_strtab_write(pcb->pcb_strtab,
		    (dt_strtab_write_f *)dt_copystr, pcb);
		dp->dtdo_strlen = (uint32_t)n;
	}

	/*
	 * Allocate memory for the compiled integer table and then copy the
	 * integer constants from the table into the final integer buffer.
	 */
	if ((n = dt_inttab_size(pcb->pcb_inttab)) != 0) {
		if ((dp->dtdo_inttab = malloc(n * sizeof (uint64_t))) == NULL)
			longjmp(pcb->pcb_jmpbuf, EDT_NOMEM);

		dt_inttab_write(pcb->pcb_inttab, dp->dtdo_inttab);
		dp->dtdo_intlen = (uint32_t)n;
	}

	/*
	 * Fill in the DIFO return type from the type associated with the
	 * node saved in pcb_dret, and then clear pcb_difo and pcb_dret
	 * now that the assembler has completed successfully.
	 */
	dt_node_diftype(pcb->pcb_dret, &dp->dtdo_rtype);
	pcb->pcb_difo = NULL;
	pcb->pcb_dret = NULL;

	if (pcb->pcb_cflags & DTRACE_C_DIFV)
		dtrace_difo_print(dp, stderr);

	return (dp);
}
