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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Create Base Board (MB) topology node from SMBIOS Type 2 structure
 */

#include <sys/types.h>
#include <strings.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <sys/systeminfo.h>
#include <sys/smbios_impl.h>
#include <sys/smbios.h>
#include <x86pi_impl.h>

/* base baoed type values to hc-canonical-name */
static const struct x86pi_bb_name {
	int type;
	const char *name;
} x86pi_bb_names[] = {
	{ SMB_BBT_SBLADE,	"systemboard" },
	{ SMB_BBT_PROC,		"cpuboard" },
	{ SMB_BBT_IO,		"ioboard" },
	{ SMB_BBT_MEM,		"memboard" },
	{ SMB_BBT_DAUGHTER,	"systemboard" },
	{ SMB_BBT_MOTHER,	"motherboard" },
	{ SMB_BBT_PROCMEM,	"systemboard" },
	{ SMB_BBT_PROCIO,	"systemboard" },
	{ SMB_BBT_INTER,	"systemboard" },
	{ 0x00 }
};

tnode_t *
x86pi_gen_bboard(topo_mod_t *mod, tnode_t *t_parent, smbios_hdl_t *shp,
    int smb_id, int instance, int psmb_id)
{
	int		rv;
	smbios_info_t	ip;
	smbios_bboard_t	bb;
	smbios_struct_t	sp;
	x86pi_hcfmri_t	bb_hcfmri;
	tnode_t		*bb_node;
	const struct x86pi_bb_name *bbnp;
	static int	cpuboard = 0;
	static int	memboard = 0;
	static int	ioboard = 0;
	static int	systemboard = 0;
	static int	motherboard = 0;
	char		*f = "x86pi_gen_bboard";

	topo_mod_dprintf(mod, "%s\n", f);

	/* SMBIOS Base Board struct */
	rv = smbios_info_bboard(shp, smb_id, &bb);
	if (rv != 0) {
		topo_mod_dprintf(mod, "%s: smbios_info_bboard() failed\n", f);
		return (NULL);
	}
	(void) smbios_lookup_id(shp, psmb_id, &sp);
	if (sp.smbstr_type == SMB_TYPE_CHASSIS &&
	    bb.smbb_chassis != psmb_id) {
		topo_mod_dprintf(mod, "%s: base board (%d) does not belong to "
		    "chassis (%d)\n", f, smb_id, psmb_id);
		return (NULL);
	}

	/* SMBIOS Base Board strings */
	rv = smbios_info_common(shp, smb_id, &ip);
	if (rv != 0) {
		return (NULL);
	}

	/*
	 * populate string entries
	 *
	 * We don't set "product" because it may contain characters
	 * unacceptable by fmri.   topo_mod_auth() will set the product-id
	 * for us and call topo_cleanup_auth_str() when necessary.
	 */
	bb_hcfmri.serial_number = x86pi_cleanup_smbios_str(mod,
	    ip.smbi_serial, 0);
	bb_hcfmri.version = x86pi_cleanup_smbios_str(mod, ip.smbi_version, 0);
	/* asset tag string contains the part number */
	bb_hcfmri.part_number = x86pi_cleanup_smbios_str(mod,
	    ip.smbi_asset, 0);
	bb_hcfmri.location = x86pi_cleanup_smbios_str(mod, ip.smbi_location, 0);

	/* determine the hc-name */
	for (bbnp = x86pi_bb_names; bbnp->type != 0x00; bbnp++) {
		if (bbnp->type == bb.smbb_type) {
			switch (bbnp->type) {
				case SMB_BBT_PROC :
					instance = cpuboard++;
					break;
				case SMB_BBT_IO :
					instance = ioboard++;
					break;
				case SMB_BBT_MEM :
					instance = memboard++;
					break;
				case SMB_BBT_MOTHER :
					instance = motherboard++;
					break;
				default :
					/*
					 * Enumerate any other baseboard type
					 * as systemboard.
					 *
					 * SMB_BBT_UNKNOWN
					 * SMB_BBT_OTHER
					 * SMB_BBT_SBLADE
					 * SMB_BBT_CSWITCH
					 * SMB_BBT_SMM
					 * SMB_BBT_DAUGHTER
					 * SMB_BBT_PROCMEM
					 * SMB_BBT_PROCIO
					 * SMB_BBT_INTER
					 */
					instance = systemboard++;
					break;
			}
			break;
		}
	}

	bb_hcfmri.instance = instance;
	if (bbnp->type != 0x00)
		bb_hcfmri.hc_name = topo_mod_strdup(mod, bbnp->name);
	else
		bb_hcfmri.hc_name = topo_mod_strdup(mod, "NULL");

	topo_mod_dprintf(mod, "%s: S/N (%s)\n", f, bb_hcfmri.serial_number);
	topo_mod_dprintf(mod, "%s: version/N (%s)\n", f, bb_hcfmri.version);
	topo_mod_dprintf(mod, "%s: Part/N (%s)\n", f, bb_hcfmri.part_number);
	topo_mod_dprintf(mod, "%s: location (%s)\n", f, bb_hcfmri.location);
	topo_mod_dprintf(mod, "%s: instance (%d)\n", f, bb_hcfmri.instance);
	topo_mod_dprintf(mod, "%s: hc_name (%s)\n", f, bb_hcfmri.hc_name);

	rv = x86pi_enum_generic(mod, &bb_hcfmri, t_parent, t_parent, &bb_node,
	    X86PI_ENUM_FRU);
	if (rv != 0) {
		topo_mod_dprintf(mod, "%s: failed to create tnode %d\n", f,
		    instance);
		bb_node = NULL;
	}

	/* free up strings */
	if (bb_hcfmri.hc_name != NULL) {
		topo_mod_strfree(mod, (char *)bb_hcfmri.hc_name);
	}
	if (bb_hcfmri.part_number != NULL) {
		topo_mod_strfree(mod, (char *)bb_hcfmri.part_number);
	}
	if (bb_hcfmri.serial_number != NULL) {
		topo_mod_strfree(mod, (char *)bb_hcfmri.serial_number);
	}
	if (bb_hcfmri.version != NULL) {
		topo_mod_strfree(mod, (char *)bb_hcfmri.version);
	}
	if (bb_hcfmri.location != NULL) {
		topo_mod_strfree(mod, (char *)bb_hcfmri.location);
	}

	return (bb_node);
}


int
x86pi_bb_getchips(topo_mod_t *mod, smbios_hdl_t *shp, int index, int nboards)
{
	id_t		*cid;
	int		count;
	int		ncmp = 0;
	smbios_struct_t	sp;
	smbs_cnt_t	*smbc = NULL;

	cid = stypes[SMB_TYPE_BASEBOARD].ids[index].con_ids;
	count = stypes[SMB_TYPE_BASEBOARD].ids[index].con_cnt;

	for (int i = 0; i < count; i++) {
		(void) smbios_lookup_id(shp, cid[i], &sp);
		if (sp.smbstr_type == SMB_TYPE_PROCESSOR) {
			ncmp++;
		}
	}

	/*
	 * If there are missing SMB_TYPE_PROCESSOR structures
	 * contained within SMB_TYPE_BASEBOARD, and if the
	 * system has only one baseboard we enumerate
	 * all processors under it.
	 */
	smbc = &stypes[SMB_TYPE_PROCESSOR];
	smbc->type = SMB_TYPE_PROCESSOR;
	x86pi_smb_strcnt(shp, smbc);

	if (nboards == 1) {
		if (ncmp != stypes[SMB_TYPE_PROCESSOR].count)
			ncmp = stypes[SMB_TYPE_PROCESSOR].count;
	} else {
		if (ncmp == 0) {
			topo_mod_dprintf(mod, "failed to get processors"
			    " (or) no processors are contained"
			    " within baseboard instance %d, unable to"
			    " enumerate chips\n", index);
		}
	}

	return (ncmp);
}


id_t
x86pi_bb_topparent(smbios_hdl_t *shp, int index, tnode_t **pnode, id_t *psmbid)
{

	id_t	top_bb_smbid = -1;
	id_t	smb_id;
	int	bb_count, ch_count;
	smbios_struct_t	sp;

	smb_id = stypes[SMB_TYPE_BASEBOARD].ids[index].con_by_id;
	(void) smbios_lookup_id(shp, smb_id, &sp);

	if (sp.smbstr_type == SMB_TYPE_CHASSIS) {
		top_bb_smbid = stypes[SMB_TYPE_BASEBOARD].ids[index].id;
		*psmbid = smb_id;
		ch_count = stypes[SMB_TYPE_CHASSIS].count;
		for (int i = 0; i < ch_count; i++)
			if (stypes[SMB_TYPE_CHASSIS].ids[i].id == *psmbid)
				*pnode = stypes[SMB_TYPE_CHASSIS].ids[i].node;

		return (top_bb_smbid);

	} else if (sp.smbstr_type == SMB_TYPE_BASEBOARD) {
		bb_count = stypes[SMB_TYPE_BASEBOARD].count;
		for (int i = 0; i < bb_count; i++) {
			if (stypes[SMB_TYPE_BASEBOARD].ids[i].id == smb_id) {
				if (stypes[SMB_TYPE_BASEBOARD].ids[i].visited
				    == X86PI_VISITED) {
					top_bb_smbid =
					    stypes[SMB_TYPE_BASEBOARD].\
					    ids[index].id;
					*pnode =
					    stypes[SMB_TYPE_BASEBOARD].ids[i].\
					    node;
					*psmbid =
					    stypes[SMB_TYPE_BASEBOARD].ids[i].\
					    id;
					break;
				}
				top_bb_smbid = x86pi_bb_topparent(shp,
				    i, pnode, psmbid);
				break;
			}
		}
	}

	return (top_bb_smbid);
}


id_t
x86pi_bb_chassis(smbios_hdl_t *shp, id_t bb_smbid)
{
	smbios_bboard_t	bb;
	int		rv;

	rv = smbios_info_bboard(shp, bb_smbid, &bb);
	if (rv != 0)
		return (-1);

	return (bb.smbb_chassis);
}


int
x86pi_bb_contains(topo_mod_t *mod, smbios_hdl_t *shp)
{
	int		rv;
	id_t		smb_id;
	smbios_bboard_t	bb;
	int		bb_count = 0;
	uint_t		cont_cnt = 0;
	smbios_struct_t	sp;

	bb_count = stypes[SMB_TYPE_BASEBOARD].count;
	for (int i = 0; i < bb_count; i++) {
		smb_id = stypes[SMB_TYPE_BASEBOARD].ids[i].id;
		/* SMBIOS Base Board struct */
		rv = smbios_info_bboard(shp, smb_id, &bb);
		if (rv != 0)
			return (-1);
		/* Set Baseboard - Chassis Relationship */
		if (stypes[SMB_TYPE_BASEBOARD].ids[i].con_by_id == 0) {
			stypes[SMB_TYPE_BASEBOARD].ids[i].con_by_id =
			    rv = x86pi_bb_chassis(shp, smb_id);
			if (rv == -1) {
				topo_mod_dprintf(mod, " failed to get"
				    " the chassis handle\n");
				return (rv);
			}
		}

		/* SMBIOS contained object handles */
		cont_cnt = bb.smbb_contn;
		if (cont_cnt > 0) {
			id_t *cont_hdl;
			uint16_t hdl;

			/* allocate space for and get contained handles */
			cont_hdl = topo_mod_alloc(mod, cont_cnt *
			    sizeof (id_t));
			rv = smbios_info_contains(shp, smb_id, cont_cnt,
			    cont_hdl);
			if (rv > SMB_CONT_MAX) {
				topo_mod_free(mod, cont_hdl, cont_cnt *
				    sizeof (id_t));
				return (-1);
			}
			cont_cnt = MIN(rv, cont_cnt);

			/* attach contained handles */
			stypes[SMB_TYPE_BASEBOARD].ids[i].con_cnt = cont_cnt;
			for (int j = 0; j < cont_cnt; j++) {
				hdl = (uint16_t)cont_hdl[j];
				topo_mod_dprintf(mod, "id %d contained handle"
				    " %d: %d\n", i, j, hdl);
				stypes[SMB_TYPE_BASEBOARD].ids[i].\
				    con_ids[j] = hdl;
				(void) smbios_lookup_id(shp, hdl, &sp);
				if (sp.smbstr_type == SMB_TYPE_BASEBOARD) {
					for (int k = 0; k < bb_count; k++)
						if (stypes[SMB_TYPE_BASEBOARD].\
						    ids[k].id == hdl)
							stypes[\
							    SMB_TYPE_BASEBOARD\
							    ].ids[k].con_by_id =
							    smb_id;
				}
			}
			topo_mod_free(mod, cont_hdl, cont_cnt * sizeof (id_t));
		}
	}
	return (0);
}
