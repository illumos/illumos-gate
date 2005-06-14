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
#include <sys/sysmacros.h>

#include <strings.h>
#include <alloca.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#include <dt_impl.h>
#include <dt_strtab.h>
#include <dt_provider.h>
#include <dt_dof.h>

void
dt_dof_init(dtrace_hdl_t *dtp)
{
	dt_dof_t *ddo = &dtp->dt_dof;

	ddo->ddo_hdl = dtp;
	ddo->ddo_nsecs = 0;
	ddo->ddo_strsec = DOF_SECIDX_NONE;

	dt_buf_create(dtp, &ddo->ddo_secs, "section headers", 0);
	dt_buf_create(dtp, &ddo->ddo_strs, "string table", 0);
	dt_buf_create(dtp, &ddo->ddo_ldata, "loadable data", 0);
	dt_buf_create(dtp, &ddo->ddo_udata, "unloadable data", 0);

	dt_buf_create(dtp, &ddo->ddo_probes, "probe data", 0);
	dt_buf_create(dtp, &ddo->ddo_args, "probe args", 0);
	dt_buf_create(dtp, &ddo->ddo_offs, "probe offs", 0);
	dt_buf_create(dtp, &ddo->ddo_rels, "probe rels", 0);
}

void
dt_dof_fini(dtrace_hdl_t *dtp)
{
	dt_dof_t *ddo = &dtp->dt_dof;

	dt_buf_destroy(dtp, &ddo->ddo_secs);
	dt_buf_destroy(dtp, &ddo->ddo_strs);
	dt_buf_destroy(dtp, &ddo->ddo_ldata);
	dt_buf_destroy(dtp, &ddo->ddo_udata);

	dt_buf_destroy(dtp, &ddo->ddo_probes);
	dt_buf_destroy(dtp, &ddo->ddo_args);
	dt_buf_destroy(dtp, &ddo->ddo_offs);
	dt_buf_destroy(dtp, &ddo->ddo_rels);
}

void
dt_dof_reset(dtrace_hdl_t *dtp)
{
	dt_dof_t *ddo = &dtp->dt_dof;

	ddo->ddo_nsecs = 0;
	ddo->ddo_strsec = DOF_SECIDX_NONE;

	dt_buf_reset(dtp, &ddo->ddo_secs);
	dt_buf_reset(dtp, &ddo->ddo_strs);
	dt_buf_reset(dtp, &ddo->ddo_ldata);
	dt_buf_reset(dtp, &ddo->ddo_udata);

	dt_buf_reset(dtp, &ddo->ddo_probes);
	dt_buf_reset(dtp, &ddo->ddo_args);
	dt_buf_reset(dtp, &ddo->ddo_offs);
	dt_buf_reset(dtp, &ddo->ddo_rels);
}

/*
 * Add a loadable DOF section to the file using the specified data buffer and
 * the specified DOF section attributes.  DOF_SECF_LOAD must be set in flags.
 * If 'data' is NULL, the caller is responsible for manipulating the ldata buf.
 */
static dof_secidx_t
dof_add_lsect(dt_dof_t *ddo, const void *data, uint32_t type,
    uint32_t align, uint32_t flags, uint32_t entsize, uint64_t size)
{
	dtrace_hdl_t *dtp = ddo->ddo_hdl;
	dof_sec_t s;

	s.dofs_type = type;
	s.dofs_align = align;
	s.dofs_flags = flags | DOF_SECF_LOAD;
	s.dofs_entsize = entsize;
	s.dofs_offset = dt_buf_offset(&ddo->ddo_ldata, align);
	s.dofs_size = size;

	dt_buf_write(dtp, &ddo->ddo_secs, &s, sizeof (s), sizeof (uint64_t));

	if (data != NULL)
		dt_buf_write(dtp, &ddo->ddo_ldata, data, size, align);

	return (ddo->ddo_nsecs++);
}

/*
 * Add an unloadable DOF section to the file using the specified data buffer
 * and DOF section attributes.  DOF_SECF_LOAD must *not* be set in flags.
 * If 'data' is NULL, the caller is responsible for manipulating the udata buf.
 */
static dof_secidx_t
dof_add_usect(dt_dof_t *ddo, const void *data, uint32_t type,
    uint32_t align, uint32_t flags, uint32_t entsize, uint64_t size)
{
	dtrace_hdl_t *dtp = ddo->ddo_hdl;
	dof_sec_t s;

	s.dofs_type = type;
	s.dofs_align = align;
	s.dofs_flags = flags & ~DOF_SECF_LOAD;
	s.dofs_entsize = entsize;
	s.dofs_offset = dt_buf_offset(&ddo->ddo_udata, align);
	s.dofs_size = size;

	dt_buf_write(dtp, &ddo->ddo_secs, &s, sizeof (s), sizeof (uint64_t));

	if (data != NULL)
		dt_buf_write(dtp, &ddo->ddo_udata, data, size, align);

	return (ddo->ddo_nsecs++);
}

/*
 * Add a string to the global string table associated with the DOF.  The offset
 * of the string is returned as an index into the string table.
 */
static dof_stridx_t
dof_add_string(dt_dof_t *ddo, const char *s)
{
	dt_buf_t *bp = &ddo->ddo_strs;
	dof_stridx_t i = dt_buf_len(bp);

	if (i != 0 && (s == NULL || *s == '\0'))
		return (0); /* string table has \0 at offset 0 */

	dt_buf_write(ddo->ddo_hdl, bp, s, strlen(s) + 1, sizeof (char));
	return (i);
}

static dof_attr_t
dof_attr(const dtrace_attribute_t *ap)
{
	return (DOF_ATTR(ap->dtat_name, ap->dtat_data, ap->dtat_class));
}

static dof_secidx_t
dof_add_difo(dt_dof_t *ddo, const dtrace_difo_t *dp)
{
	dof_secidx_t dsecs[4]; /* enough for all possible DIFO sections */
	uint_t nsecs = 0;

	dof_difohdr_t *dofd;
	dof_relohdr_t dofr;
	dof_secidx_t relsec;

	dof_secidx_t strsec = DOF_SECIDX_NONE;
	dof_secidx_t intsec = DOF_SECIDX_NONE;
	dof_secidx_t hdrsec = DOF_SECIDX_NONE;

	if (dp->dtdo_buf != NULL) {
		dsecs[nsecs++] = dof_add_lsect(ddo, dp->dtdo_buf,
		    DOF_SECT_DIF, sizeof (dif_instr_t), 0,
		    sizeof (dif_instr_t), sizeof (dif_instr_t) * dp->dtdo_len);
	}

	if (dp->dtdo_inttab != NULL) {
		dsecs[nsecs++] = intsec = dof_add_lsect(ddo, dp->dtdo_inttab,
		    DOF_SECT_INTTAB, sizeof (uint64_t), 0,
		    sizeof (uint64_t), sizeof (uint64_t) * dp->dtdo_intlen);
	}

	if (dp->dtdo_strtab != NULL) {
		dsecs[nsecs++] = strsec = dof_add_lsect(ddo, dp->dtdo_strtab,
		    DOF_SECT_STRTAB, sizeof (char), 0, 0, dp->dtdo_strlen);
	}

	if (dp->dtdo_vartab != NULL) {
		dsecs[nsecs++] = dof_add_lsect(ddo, dp->dtdo_vartab,
		    DOF_SECT_VARTAB, sizeof (uint_t), 0, sizeof (dtrace_difv_t),
		    sizeof (dtrace_difv_t) * dp->dtdo_varlen);
	}

	/*
	 * Copy the return type and the array of section indices that form the
	 * DIFO into a single dof_difohdr_t and then add DOF_SECT_DIFOHDR.
	 */
	assert(nsecs <= sizeof (dsecs) / sizeof (dsecs[0]));
	dofd = alloca(sizeof (dtrace_diftype_t) + sizeof (dsecs));
	bcopy(&dp->dtdo_rtype, &dofd->dofd_rtype, sizeof (dtrace_diftype_t));
	bcopy(dsecs, &dofd->dofd_links, sizeof (dof_secidx_t) * nsecs);

	hdrsec = dof_add_lsect(ddo, dofd, DOF_SECT_DIFOHDR,
	    sizeof (dof_secidx_t), 0, 0,
	    sizeof (dtrace_diftype_t) + sizeof (dof_secidx_t) * nsecs);

	/*
	 * Add any other sections related to dtrace_difo_t.  These are not
	 * referenced in dof_difohdr_t because they are not used by emulation.
	 */
	if (dp->dtdo_kreltab != NULL) {
		relsec = dof_add_lsect(ddo, dp->dtdo_kreltab, DOF_SECT_RELTAB,
		    sizeof (uint64_t), 0, sizeof (dof_relodesc_t),
		    sizeof (dof_relodesc_t) * dp->dtdo_krelen);

		/*
		 * This code assumes the target of all relocations is the
		 * integer table 'intsec' (DOF_SECT_INTTAB).  If other sections
		 * need relocation in the future this will need to change.
		 */
		dofr.dofr_strtab = strsec;
		dofr.dofr_relsec = relsec;
		dofr.dofr_tgtsec = intsec;

		(void) dof_add_lsect(ddo, &dofr, DOF_SECT_KRELHDR,
		    sizeof (dof_secidx_t), 0, 0, sizeof (dof_relohdr_t));
	}

	if (dp->dtdo_ureltab != NULL) {
		relsec = dof_add_lsect(ddo, dp->dtdo_ureltab, DOF_SECT_RELTAB,
		    sizeof (uint64_t), 0, sizeof (dof_relodesc_t),
		    sizeof (dof_relodesc_t) * dp->dtdo_urelen);

		/*
		 * This code assumes the target of all relocations is the
		 * integer table 'intsec' (DOF_SECT_INTTAB).  If other sections
		 * need relocation in the future this will need to change.
		 */
		dofr.dofr_strtab = strsec;
		dofr.dofr_relsec = relsec;
		dofr.dofr_tgtsec = intsec;

		(void) dof_add_lsect(ddo, &dofr, DOF_SECT_URELHDR,
		    sizeof (dof_secidx_t), 0, 0, sizeof (dof_relohdr_t));
	}

	return (hdrsec);
}

/*ARGSUSED*/
static int
dof_add_probe(dt_idhash_t *dhp, dt_ident_t *idp, void *data)
{
	dt_dof_t *ddo = data;
	dtrace_hdl_t *dtp = ddo->ddo_hdl;
	dt_probe_t *prp = idp->di_data;

	dof_probe_t dofpr;
	dof_relodesc_t dofr;
	dt_probe_instance_t *pip;
	dt_node_t *dnp;

	char buf[DT_TYPE_NAMELEN];
	uint_t i;

	dofpr.dofpr_addr = 0;
	dofpr.dofpr_name = dof_add_string(ddo, prp->pr_name);
	dofpr.dofpr_nargv = dt_buf_len(&ddo->ddo_strs);

	for (dnp = prp->pr_nargs; dnp != NULL; dnp = dnp->dn_list) {
		(void) dof_add_string(ddo, ctf_type_name(dnp->dn_ctfp,
		    dnp->dn_type, buf, sizeof (buf)));
	}

	dofpr.dofpr_xargv = dt_buf_len(&ddo->ddo_strs);

	for (dnp = prp->pr_xargs; dnp != NULL; dnp = dnp->dn_list) {
		(void) dof_add_string(ddo, ctf_type_name(dnp->dn_ctfp,
		    dnp->dn_type, buf, sizeof (buf)));
	}

	dofpr.dofpr_argidx = dt_buf_len(&ddo->ddo_args) / sizeof (uint8_t);

	for (i = 0; i < prp->pr_xargc; i++) {
		dt_buf_write(dtp, &ddo->ddo_args, &prp->pr_mapping[i],
		    sizeof (uint8_t), sizeof (uint8_t));
	}

	dofpr.dofpr_nargc = prp->pr_nargc;
	dofpr.dofpr_xargc = prp->pr_xargc;
	dofpr.dofpr_pad = 0;

	for (pip = prp->pr_inst; pip != NULL; pip = pip->pi_next) {
		dofpr.dofpr_func = dof_add_string(ddo, pip->pi_fname);
		dofpr.dofpr_offidx =
		    dt_buf_len(&ddo->ddo_offs) / sizeof (uint32_t);
		dofpr.dofpr_noffs = pip->pi_noffs;

		dt_buf_write(dtp, &ddo->ddo_offs, pip->pi_offs,
		    pip->pi_noffs * sizeof (uint32_t), sizeof (uint32_t));

		dofr.dofr_name = dofpr.dofpr_func;
		dofr.dofr_type = DOF_RELO_SETX;
		dofr.dofr_offset = dt_buf_len(&ddo->ddo_probes);
		dofr.dofr_data = 0;

		dt_buf_write(dtp, &ddo->ddo_rels, &dofr,
		    sizeof (dofr), sizeof (uint64_t));

		dt_buf_write(dtp, &ddo->ddo_probes, &dofpr,
		    sizeof (dofpr), sizeof (uint64_t));
	}

	return (0);
}

static void
dof_add_provider(dt_dof_t *ddo, const dt_provider_t *pvp)
{
	dtrace_hdl_t *dtp = ddo->ddo_hdl;
	dof_provider_t dofpv;
	dof_relohdr_t dofr;

	if (pvp->pv_flags & DT_PROVIDER_IMPL)
		return; /* ignore providers that are exported by dtrace(7D) */

	dt_buf_reset(dtp, &ddo->ddo_probes);
	dt_buf_reset(dtp, &ddo->ddo_args);
	dt_buf_reset(dtp, &ddo->ddo_offs);
	dt_buf_reset(dtp, &ddo->ddo_rels);

	(void) dt_idhash_iter(pvp->pv_probes, dof_add_probe, ddo);

	dofpv.dofpv_probes = dof_add_lsect(ddo, NULL, DOF_SECT_PROBES,
	    sizeof (uint64_t), 0, sizeof (dof_probe_t),
	    dt_buf_len(&ddo->ddo_probes));

	dt_buf_concat(dtp, &ddo->ddo_ldata,
	    &ddo->ddo_probes, sizeof (uint64_t));

	dofpv.dofpv_prargs = dof_add_lsect(ddo, NULL, DOF_SECT_PRARGS,
	    sizeof (uint8_t), 0, sizeof (uint8_t), dt_buf_len(&ddo->ddo_args));

	dt_buf_concat(dtp, &ddo->ddo_ldata, &ddo->ddo_args, sizeof (uint8_t));

	dofpv.dofpv_proffs = dof_add_lsect(ddo, NULL, DOF_SECT_PROFFS,
	    sizeof (uint_t), 0, sizeof (uint_t), dt_buf_len(&ddo->ddo_offs));

	dt_buf_concat(dtp, &ddo->ddo_ldata, &ddo->ddo_offs, sizeof (uint_t));

	dofpv.dofpv_strtab = ddo->ddo_strsec;
	dofpv.dofpv_name = dof_add_string(ddo, pvp->pv_desc.dtvd_name);

	dofpv.dofpv_provattr = dof_attr(&pvp->pv_desc.dtvd_attr.dtpa_provider);
	dofpv.dofpv_modattr = dof_attr(&pvp->pv_desc.dtvd_attr.dtpa_mod);
	dofpv.dofpv_funcattr = dof_attr(&pvp->pv_desc.dtvd_attr.dtpa_func);
	dofpv.dofpv_nameattr = dof_attr(&pvp->pv_desc.dtvd_attr.dtpa_name);
	dofpv.dofpv_argsattr = dof_attr(&pvp->pv_desc.dtvd_attr.dtpa_args);

	(void) dof_add_lsect(ddo, &dofpv, DOF_SECT_PROVIDER,
	    sizeof (dof_secidx_t), 0, 0, sizeof (dof_provider_t));

	dofr.dofr_strtab = dofpv.dofpv_strtab;
	dofr.dofr_tgtsec = dofpv.dofpv_probes;
	dofr.dofr_relsec = dof_add_lsect(ddo, NULL, DOF_SECT_RELTAB,
	    sizeof (uint64_t), 0, sizeof (dof_relodesc_t),
	    dt_buf_len(&ddo->ddo_rels));

	dt_buf_concat(dtp, &ddo->ddo_ldata, &ddo->ddo_rels, sizeof (uint64_t));

	(void) dof_add_lsect(ddo, &dofr, DOF_SECT_URELHDR,
	    sizeof (dof_secidx_t), 0, 0, sizeof (dof_relohdr_t));
}

static int
dof_hdr(dtrace_hdl_t *dtp, dof_hdr_t *hp)
{
	/*
	 * If our config values cannot fit in a uint8_t, we can't generate a
	 * DOF header since the values won't fit.  This can only happen if the
	 * user forcibly compiles a program with an artificial configuration.
	 */
	if (dtp->dt_conf.dtc_difversion > UINT8_MAX ||
	    dtp->dt_conf.dtc_difintregs > UINT8_MAX ||
	    dtp->dt_conf.dtc_diftupregs > UINT8_MAX)
		return (dt_set_errno(dtp, EOVERFLOW));

	bzero(hp, sizeof (dof_hdr_t));

	hp->dofh_ident[DOF_ID_MAG0] = DOF_MAG_MAG0;
	hp->dofh_ident[DOF_ID_MAG1] = DOF_MAG_MAG1;
	hp->dofh_ident[DOF_ID_MAG2] = DOF_MAG_MAG2;
	hp->dofh_ident[DOF_ID_MAG3] = DOF_MAG_MAG3;

	if (dtp->dt_conf.dtc_ctfmodel == CTF_MODEL_LP64)
		hp->dofh_ident[DOF_ID_MODEL] = DOF_MODEL_LP64;
	else
		hp->dofh_ident[DOF_ID_MODEL] = DOF_MODEL_ILP32;

	hp->dofh_ident[DOF_ID_ENCODING] = DOF_ENCODE_NATIVE;
	hp->dofh_ident[DOF_ID_VERSION] = DOF_VERSION_1;
	hp->dofh_ident[DOF_ID_DIFVERS] = dtp->dt_conf.dtc_difversion;
	hp->dofh_ident[DOF_ID_DIFIREG] = dtp->dt_conf.dtc_difintregs;
	hp->dofh_ident[DOF_ID_DIFTREG] = dtp->dt_conf.dtc_diftupregs;

	hp->dofh_hdrsize = sizeof (dof_hdr_t);
	hp->dofh_secsize = sizeof (dof_sec_t);
	hp->dofh_secoff = sizeof (dof_hdr_t);

	return (0);
}

void *
dtrace_dof_create(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, uint_t flags)
{
	dt_dof_t *ddo = &dtp->dt_dof;

	const dtrace_ecbdesc_t *edp, *last;
	const dtrace_probedesc_t *pdp;
	const dtrace_actdesc_t *ap;
	const dt_stmt_t *stp;

	uint_t maxacts = 0;
	uint_t maxfmt = 0;

	dt_provider_t *pvp;
	dof_actdesc_t *dofa;
	dof_sec_t *sp;
	size_t ssize, lsize;
	dof_hdr_t h;

	dt_buf_t dof;
	char *fmt;
	uint_t i;

	if (flags & ~DTRACE_D_MASK) {
		(void) dt_set_errno(dtp, EINVAL);
		return (NULL);
	}

	flags |= dtp->dt_dflags;

	if (dof_hdr(dtp, &h) != 0)
		return (NULL);

	assert(ddo->ddo_hdl == dtp);
	dt_dof_reset(dtp);

	/*
	 * Iterate through the statement list computing the maximum number of
	 * actions and the maximum format string for allocating local buffers.
	 */
	for (last = NULL, stp = dt_list_next(&pgp->dp_stmts);
	    stp != NULL; stp = dt_list_next(stp), last = edp) {

		dtrace_stmtdesc_t *sdp = stp->ds_desc;
		dtrace_actdesc_t *ap = sdp->dtsd_action;

		if (sdp->dtsd_fmtdata != NULL) {
			i = dtrace_printf_format(dtp,
			    sdp->dtsd_fmtdata, NULL, 0);
			maxfmt = MAX(maxfmt, i);
		}

		if ((edp = sdp->dtsd_ecbdesc) == last)
			continue; /* same ecb as previous statement */

		for (i = 0, ap = edp->dted_action; ap; ap = ap->dtad_next)
			i++;

		maxacts = MAX(maxacts, i);
	}

	dofa = alloca(sizeof (dof_actdesc_t) * maxacts);
	fmt = alloca(maxfmt + 1);

	ddo->ddo_strsec = dof_add_lsect(ddo, NULL, DOF_SECT_STRTAB, 1, 0, 0, 0);
	(void) dof_add_string(ddo, "");

	/*
	 * Now iterate through the statement list, creating the DOF section
	 * headers and data for each one and adding them to our buffers.
	 */
	for (last = NULL, stp = dt_list_next(&pgp->dp_stmts);
	    stp != NULL; stp = dt_list_next(stp), last = edp) {

		dof_secidx_t probesec = DOF_SECIDX_NONE;
		dof_secidx_t prdsec = DOF_SECIDX_NONE;
		dof_secidx_t actsec = DOF_SECIDX_NONE;

		const dt_stmt_t *next = stp;
		dtrace_stmtdesc_t *sdp = stp->ds_desc;
		dof_stridx_t strndx = 0;
		dof_probedesc_t dofp;
		dof_ecbdesc_t dofe;
		uint_t i;

		if ((edp = stp->ds_desc->dtsd_ecbdesc) == last)
			continue; /* same ecb as previous statement */

		pdp = &edp->dted_probe;

		/*
		 * Add a DOF_SECT_PROBEDESC for the ECB's probe description,
		 * and copy the probe description strings into the string table.
		 */
		dofp.dofp_strtab = ddo->ddo_strsec;
		dofp.dofp_provider = dof_add_string(ddo, pdp->dtpd_provider);
		dofp.dofp_mod = dof_add_string(ddo, pdp->dtpd_mod);
		dofp.dofp_func = dof_add_string(ddo, pdp->dtpd_func);
		dofp.dofp_name = dof_add_string(ddo, pdp->dtpd_name);
		dofp.dofp_id = pdp->dtpd_id;

		probesec = dof_add_lsect(ddo, &dofp, DOF_SECT_PROBEDESC,
		    sizeof (dof_secidx_t), 0,
		    sizeof (dof_probedesc_t), sizeof (dof_probedesc_t));

		/*
		 * If there is a predicate DIFO associated with the ecbdesc,
		 * write out the DIFO sections and save the DIFO section index.
		 */
		if (edp->dted_pred.dtpdd_difo != NULL)
			prdsec = dof_add_difo(ddo, edp->dted_pred.dtpdd_difo);

		/*
		 * Now iterate through the action list generating DIFOs as
		 * referenced therein and adding action descriptions to 'dofa'.
		 */
		for (i = 0, ap = edp->dted_action;
		    ap != NULL; ap = ap->dtad_next, i++) {

			if (ap->dtad_difo != NULL) {
				dofa[i].dofa_difo =
				    dof_add_difo(ddo, ap->dtad_difo);
			} else
				dofa[i].dofa_difo = DOF_SECIDX_NONE;

			/*
			 * If the first action in a statement has format data,
			 * add the format string to the global string table.
			 */
			if (sdp != NULL && ap == sdp->dtsd_action) {
				if (sdp->dtsd_fmtdata != NULL) {
					(void) dtrace_printf_format(dtp,
					    sdp->dtsd_fmtdata, fmt, maxfmt + 1);
					strndx = dof_add_string(ddo, fmt);
				} else
					strndx = 0; /* use dtad_arg instead */

				if ((next = dt_list_next(next)) != NULL)
					sdp = next->ds_desc;
				else
					sdp = NULL;
			}

			if (strndx != 0) {
				dofa[i].dofa_arg = strndx;
				dofa[i].dofa_strtab = ddo->ddo_strsec;
			} else {
				dofa[i].dofa_arg = ap->dtad_arg;
				dofa[i].dofa_strtab = DOF_SECIDX_NONE;
			}

			dofa[i].dofa_kind = ap->dtad_kind;
			dofa[i].dofa_ntuple = ap->dtad_ntuple;
			dofa[i].dofa_uarg = ap->dtad_uarg;
		}

		if (i > 0) {
			actsec = dof_add_lsect(ddo, dofa, DOF_SECT_ACTDESC,
			    sizeof (uint64_t), 0, sizeof (dof_actdesc_t),
			    sizeof (dof_actdesc_t) * i);
		}

		/*
		 * Now finally, add the DOF_SECT_ECBDESC referencing all the
		 * previously created sub-sections.
		 */
		dofe.dofe_probes = probesec;
		dofe.dofe_pred = prdsec;
		dofe.dofe_actions = actsec;
		dofe.dofe_pad = 0;
		dofe.dofe_uarg = edp->dted_uarg;

		(void) dof_add_lsect(ddo, &dofe, DOF_SECT_ECBDESC,
		    sizeof (uint64_t), 0, 0, sizeof (dof_ecbdesc_t));
	}

	/*
	 * If any providers are user-defined, output DOF sections corresponding
	 * to the providers and the probes and arguments that they define.
	 */
	if (flags & DTRACE_D_PROBES) {
		for (pvp = dt_list_next(&dtp->dt_provlist);
		    pvp != NULL; pvp = dt_list_next(pvp))
			dof_add_provider(ddo, pvp);
	}

	/*
	 * If we're not stripping unloadable sections, generate compiler
	 * comments and any other unloadable miscellany.
	 */
	if (!(flags & DTRACE_D_STRIP)) {
		(void) dof_add_usect(ddo, _dtrace_version, DOF_SECT_COMMENTS,
		    sizeof (char), 0, 0, strlen(_dtrace_version) + 1);
		(void) dof_add_usect(ddo, &dtp->dt_uts, DOF_SECT_UTSNAME,
		    sizeof (char), 0, 0, sizeof (struct utsname));
	}

	/*
	 * Compute and fill in the appropriate values for the dof_hdr_t's
	 * dofh_secnum, dofh_loadsz, and dofh_filez values.
	 */
	h.dofh_secnum = ddo->ddo_nsecs;
	ssize = sizeof (h) + dt_buf_len(&ddo->ddo_secs);
	assert(ssize == sizeof (h) + sizeof (dof_sec_t) * ddo->ddo_nsecs);

	h.dofh_loadsz = ssize +
	    dt_buf_len(&ddo->ddo_ldata) +
	    dt_buf_len(&ddo->ddo_strs);

	if (dt_buf_len(&ddo->ddo_udata) != 0) {
		lsize = roundup(h.dofh_loadsz, sizeof (uint64_t));
		h.dofh_filesz = lsize + dt_buf_len(&ddo->ddo_udata);
	} else {
		lsize = h.dofh_loadsz;
		h.dofh_filesz = lsize;
	}

	/*
	 * Set the global DOF_SECT_STRTAB's offset to be after the header,
	 * section headers, and other loadable data.  Since we're going to
	 * iterate over the buffer data directly, we must check for errors.
	 */
	if ((i = dt_buf_error(&ddo->ddo_secs)) != 0) {
		(void) dt_set_errno(dtp, i);
		return (NULL);
	}

	sp = dt_buf_ptr(&ddo->ddo_secs);
	assert(sp[ddo->ddo_strsec].dofs_type == DOF_SECT_STRTAB);

	sp[ddo->ddo_strsec].dofs_offset = ssize + dt_buf_len(&ddo->ddo_ldata);
	sp[ddo->ddo_strsec].dofs_size = dt_buf_len(&ddo->ddo_strs);

	/*
	 * Now relocate all the other section headers by adding the appropriate
	 * delta to their respective dofs_offset values.
	 */
	for (i = 0; i < ddo->ddo_nsecs; i++, sp++) {
		if (i == ddo->ddo_strsec)
			continue; /* already relocated above */

		if (sp->dofs_flags & DOF_SECF_LOAD)
			sp->dofs_offset += ssize;
		else
			sp->dofs_offset += lsize;
	}

	/*
	 * Finally, assemble the complete in-memory DOF buffer by writing the
	 * header and then concatenating all our buffers.  dt_buf_concat() will
	 * propagate any errors and cause dt_buf_claim() to return NULL.
	 */
	dt_buf_create(dtp, &dof, "dof", h.dofh_filesz);

	dt_buf_write(dtp, &dof, &h, sizeof (h), sizeof (uint64_t));
	dt_buf_concat(dtp, &dof, &ddo->ddo_secs, sizeof (uint64_t));
	dt_buf_concat(dtp, &dof, &ddo->ddo_ldata, sizeof (uint64_t));
	dt_buf_concat(dtp, &dof, &ddo->ddo_strs, sizeof (char));
	dt_buf_concat(dtp, &dof, &ddo->ddo_udata, sizeof (uint64_t));

	return (dt_buf_claim(dtp, &dof));
}

void
dtrace_dof_destroy(dtrace_hdl_t *dtp, void *dof)
{
	dt_free(dtp, dof);
}

void *
dtrace_getopt_dof(dtrace_hdl_t *dtp)
{
	dof_hdr_t *dof;
	dof_sec_t *sec;
	dof_optdesc_t *dofo;
	int i, nopts = 0, len = sizeof (dof_hdr_t) +
	    roundup(sizeof (dof_sec_t), sizeof (uint64_t));

	for (i = 0; i < DTRACEOPT_MAX; i++) {
		if (dtp->dt_options[i] != DTRACEOPT_UNSET)
			nopts++;
	}

	len += sizeof (dof_optdesc_t) * nopts;

	if ((dof = dt_zalloc(dtp, len)) == NULL || dof_hdr(dtp, dof) != 0) {
		dt_free(dtp, dof);
		return (NULL);
	}

	dof->dofh_secnum = 1;	/* only DOF_SECT_OPTDESC */
	dof->dofh_loadsz = len;
	dof->dofh_filesz = len;

	/*
	 * Fill in the option section header...
	 */
	sec = (dof_sec_t *)((uintptr_t)dof + sizeof (dof_hdr_t));
	sec->dofs_type = DOF_SECT_OPTDESC;
	sec->dofs_align = sizeof (uint64_t);
	sec->dofs_flags = DOF_SECF_LOAD;
	sec->dofs_entsize = sizeof (dof_optdesc_t);

	dofo = (dof_optdesc_t *)((uintptr_t)sec +
	    roundup(sizeof (dof_sec_t), sizeof (uint64_t)));

	sec->dofs_offset = (uintptr_t)dofo - (uintptr_t)dof;
	sec->dofs_size = sizeof (dof_optdesc_t) * nopts;

	for (i = 0; i < DTRACEOPT_MAX; i++) {
		if (dtp->dt_options[i] == DTRACEOPT_UNSET)
			continue;

		dofo->dofo_option = i;
		dofo->dofo_strtab = DOF_SECIDX_NONE;
		dofo->dofo_value = dtp->dt_options[i];
		dofo++;
	}

	return (dof);
}

void *
dtrace_geterr_dof(dtrace_hdl_t *dtp)
{
	if (dtp->dt_errprog != NULL)
		return (dtrace_dof_create(dtp, dtp->dt_errprog, 0));

	(void) dt_set_errno(dtp, EDT_BADERROR);
	return (NULL);
}
