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

#include <strings.h>
#include <stdlib.h>

#include <dt_xlator.h>
#include <dt_impl.h>

dt_xlator_t *
dt_xlator_create(dtrace_hdl_t *dtp,
    const dtrace_typeinfo_t *src, const dtrace_typeinfo_t *dst,
    const char *name, dt_node_t *members, dt_node_t *nodes)
{
	dt_xlator_t *dxp = malloc(sizeof (dt_xlator_t));
	dtrace_typeinfo_t ptr = *dst;

	if (dxp == NULL)
		return (NULL);

	if (dt_type_pointer(&ptr) == -1) {
		ptr.dtt_ctfp = NULL;
		ptr.dtt_type = CTF_ERR;
	}

	bzero(dxp, sizeof (dt_xlator_t));
	dt_list_append(&dtp->dt_xlators, dxp);
	dxp->dx_locals = dt_idhash_create("translator", NULL, 0, 0);

	if (dxp->dx_locals == NULL)
		goto err; /* no memory for identifier hash */

	dxp->dx_ident = dt_idhash_insert(dxp->dx_locals, name,
	    DT_IDENT_SCALAR, DT_IDFLG_REF, 0, _dtrace_defattr, 0,
	    &dt_idops_thaw, NULL, dtp->dt_gen);

	if (dxp->dx_ident == NULL)
		goto err; /* no memory for identifier */

	dxp->dx_ident->di_ctfp = src->dtt_ctfp;
	dxp->dx_ident->di_type = src->dtt_type;

	dxp->dx_souid.di_name = "translator";
	dxp->dx_souid.di_kind = DT_IDENT_XLSOU;
	dxp->dx_souid.di_flags = DT_IDFLG_REF;
	dxp->dx_souid.di_attr = _dtrace_defattr;
	dxp->dx_souid.di_ops = &dt_idops_thaw;
	dxp->dx_souid.di_data = dxp;
	dxp->dx_souid.di_ctfp = dst->dtt_ctfp;
	dxp->dx_souid.di_type = dst->dtt_type;
	dxp->dx_souid.di_gen = dtp->dt_gen;

	dxp->dx_ptrid.di_name = "translator";
	dxp->dx_ptrid.di_kind = DT_IDENT_XLPTR;
	dxp->dx_ptrid.di_flags = DT_IDFLG_REF;
	dxp->dx_ptrid.di_attr = _dtrace_defattr;
	dxp->dx_ptrid.di_ops = &dt_idops_thaw;
	dxp->dx_ptrid.di_data = dxp;
	dxp->dx_ptrid.di_ctfp = ptr.dtt_ctfp;
	dxp->dx_ptrid.di_type = ptr.dtt_type;
	dxp->dx_ptrid.di_gen = dtp->dt_gen;

	/*
	 * If a deferred pragma is pending on the keyword "translator", run all
	 * the deferred pragmas on dx_souid and then copy results to dx_ptrid.
	 * See the code in dt_pragma.c for details on deferred ident pragmas.
	 */
	if (dtp->dt_globals->dh_defer != NULL && yypcb->pcb_pragmas != NULL &&
	    dt_idhash_lookup(yypcb->pcb_pragmas, "translator") != NULL) {
		dtp->dt_globals->dh_defer(dtp->dt_globals, &dxp->dx_souid);
		dxp->dx_ptrid.di_attr = dxp->dx_souid.di_attr;
		dxp->dx_ptrid.di_vers = dxp->dx_souid.di_vers;
	}

	dxp->dx_src_ctfp = src->dtt_ctfp;
	dxp->dx_src_type = src->dtt_type;
	dxp->dx_src_base = ctf_type_resolve(src->dtt_ctfp, src->dtt_type);

	dxp->dx_dst_ctfp = dst->dtt_ctfp;
	dxp->dx_dst_type = dst->dtt_type;
	dxp->dx_dst_base = ctf_type_resolve(dst->dtt_ctfp, dst->dtt_type);

	dxp->dx_members = members;
	dxp->dx_nodes = nodes;
	dxp->dx_gen = dtp->dt_gen;

	return (dxp);

err:
	dt_xlator_destroy(dtp, dxp);
	return (NULL);
}

void
dt_xlator_destroy(dtrace_hdl_t *dtp, dt_xlator_t *dxp)
{
	dt_node_link_free(&dxp->dx_nodes);
	dt_idhash_destroy(dxp->dx_locals);
	dt_list_delete(&dtp->dt_xlators, dxp);
	free(dxp);
}

dt_xlator_t *
dt_xlator_lookup(dtrace_hdl_t *dtp, dt_node_t *src, dt_node_t *dst, int flag)
{
	ctf_file_t *src_ctfp = src->dn_ctfp;
	ctf_id_t src_type = src->dn_type;
	ctf_id_t src_base = ctf_type_resolve(src_ctfp, src_type);

	ctf_file_t *dst_ctfp = dst->dn_ctfp;
	ctf_id_t dst_type = dst->dn_type;
	ctf_id_t dst_base = ctf_type_resolve(dst_ctfp, dst_type);

	int ptr = ctf_type_kind(dst_ctfp, dst_base) == CTF_K_POINTER;
	dt_node_t xn = { 0 };
	dt_xlator_t *dxp;

	if (src_base == CTF_ERR || dst_base == CTF_ERR)
		return (NULL); /* fail if these are unresolvable types */

	/*
	 * Translators are always defined using a struct or union type, so if
	 * we are attempting to translate to type "T *", we internally look
	 * for a translation to type "T" by following the pointer reference.
	 */
	if (ptr) {
		dst_type = ctf_type_reference(dst_ctfp, dst_type);
		dst_base = ctf_type_resolve(dst_ctfp, dst_type);
	}

	/*
	 * In order to find a matching translator, we iterate over the set of
	 * available translators in three passes.  First, we look for a
	 * translation from the exact source type to the resolved destination.
	 * Second, we look for a translation from the resolved source type to
	 * the resolved destination.  Third, we look for a translation from a
	 * compatible source type (using the same rules as parameter formals)
	 * to the resolved destination.  If all passes fail, return NULL.
	 */
	for (dxp = dt_list_next(&dtp->dt_xlators); dxp != NULL;
	    dxp = dt_list_next(dxp)) {
		if (ctf_type_compat(dxp->dx_src_ctfp, dxp->dx_src_type,
		    src_ctfp, src_type) &&
		    ctf_type_compat(dxp->dx_dst_ctfp, dxp->dx_dst_base,
		    dst_ctfp, dst_base))
			goto out;
	}

	if (flag == DT_XLATE_EXACT)
		goto out; /* skip remaining passes if exact match required */

	for (dxp = dt_list_next(&dtp->dt_xlators); dxp != NULL;
	    dxp = dt_list_next(dxp)) {
		if (ctf_type_compat(dxp->dx_src_ctfp, dxp->dx_src_base,
		    src_ctfp, src_type) &&
		    ctf_type_compat(dxp->dx_dst_ctfp, dxp->dx_dst_base,
		    dst_ctfp, dst_base))
			goto out;
	}

	for (dxp = dt_list_next(&dtp->dt_xlators); dxp != NULL;
	    dxp = dt_list_next(dxp)) {
		dt_node_type_assign(&xn, dxp->dx_src_ctfp, dxp->dx_src_type);
		if (ctf_type_compat(dxp->dx_dst_ctfp, dxp->dx_dst_base,
		    dst_ctfp, dst_base) && dt_node_is_argcompat(src, &xn))
			goto out;
	}

out:
	if (ptr && dxp != NULL && dxp->dx_ptrid.di_type == CTF_ERR)
		return (NULL); /* no translation available to pointer type */

	return (dxp);
}

dt_ident_t *
dt_xlator_ident(dt_xlator_t *dxp, ctf_file_t *ctfp, ctf_id_t type)
{
	if (ctf_type_kind(ctfp, ctf_type_resolve(ctfp, type)) == CTF_K_POINTER)
		return (&dxp->dx_ptrid);
	else
		return (&dxp->dx_souid);
}

dt_node_t *
dt_xlator_member(dt_xlator_t *dxp, const char *name)
{
	dt_node_t *dnp;

	for (dnp = dxp->dx_members; dnp != NULL; dnp = dnp->dn_list) {
		if (strcmp(dnp->dn_membname, name) == 0)
			return (dnp);
	}

	return (NULL);
}
