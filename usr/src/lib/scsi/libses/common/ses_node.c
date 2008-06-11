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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <scsi/libses.h>
#include "ses_impl.h"

#define	NEXT_ED(eip)	\
	((ses2_ed_impl_t *)((uint8_t *)(eip) + 	\
	    ((eip)->st_hdr.sehi_ed_len + sizeof (ses2_ed_hdr_impl_t))))

static ses_node_t *
ses_find_enclosure(ses_snap_t *sp, uint64_t number)
{
	ses_node_t *np;

	for (np = sp->ss_root->sn_first_child; np != NULL;
	    np = np->sn_next_sibling) {
		ASSERT(np->sn_type == SES_NODE_ENCLOSURE);
		if (np->sn_enc_num == number)
			return ((ses_node_t *)np);
	}

	return (NULL);
}

/*
 * ses_snap_primary_enclosure() finds the primary enclosure for
 * the supplied ses_snap_t.
 */
ses_node_t *
ses_snap_primary_enclosure(ses_snap_t *sp)
{
	return (ses_find_enclosure(sp, 0));
}

void
ses_node_teardown(ses_node_t *np)
{
	ses_node_t *rp;

	if (np == NULL)
		return;

	for (; np != NULL; np = rp) {
		ses_node_teardown(np->sn_first_child);
		rp = np->sn_next_sibling;
		nvlist_free(np->sn_props);
		ses_free(np);
	}
}

static ses_node_t *
ses_node_alloc(ses_snap_t *sp, ses_node_t *pnp)
{
	ses_node_t *np;

	np = ses_zalloc(sizeof (ses_node_t));
	if (np == NULL)
		goto fail;
	if (nvlist_alloc(&np->sn_props, NV_UNIQUE_NAME, 0) != 0)
		goto fail;

	np->sn_snapshot = sp;
	np->sn_id = sp->ss_n_nodes++;

	if (pnp == NULL) {
		ASSERT(sp->ss_root == NULL);
		sp->ss_root = np;
	} else {
		np->sn_parent = pnp;
		np->sn_prev_sibling = pnp->sn_last_child;

		if (pnp->sn_first_child == NULL)
			pnp->sn_first_child = np;
		else
			pnp->sn_last_child->sn_next_sibling = np;

		pnp->sn_last_child = np;
	}

	return (np);

fail:
	ses_free(np);
	ses_node_teardown(sp->ss_root);
	sp->ss_root = NULL;
	return (NULL);
}

/*
 * Parse element type descriptor.
 */
static int
elem_parse_td(ses2_td_hdr_impl_t *tip, const char *tp, nvlist_t *nvl)
{
	int nverr;

	if (tp != NULL)
		SES_NV_ADD(fixed_string, nverr, nvl, SES_PROP_CLASS_DESCRIPTION,
		    tp, tip->sthi_text_len);

	return (0);
}


/*
 * Build a skeleton tree of nodes in the given snapshot.  This is the heart of
 * libses, and is responsible for parsing the config page into a tree and
 * populating nodes with data from the config page.
 */
static int
ses_build_snap_skel(ses_snap_t *sp)
{
	ses2_ed_impl_t *eip;
	ses2_td_hdr_impl_t *tip, *ftip;
	ses_node_t *np, *pnp, *cnp, *root;
	ses_snap_page_t *pp;
	ses2_config_page_impl_t *pip;
	int i, j, n_etds = 0;
	off_t toff;
	char *tp, *text;
	int err;
	uint64_t idx;

	pp = ses_snap_find_page(sp, SES2_DIAGPAGE_CONFIG, B_FALSE);
	if (pp == NULL)
		return (ses_error(ESES_BAD_RESPONSE, "target does not support "
		    "configuration diagnostic page"));
	pip = (ses2_config_page_impl_t *)pp->ssp_page;

	if (pp->ssp_len < offsetof(ses2_config_page_impl_t, scpi_data))
		return (ses_error(ESES_BAD_RESPONSE, "no enclosure "
		    "descriptors found"));

	/*
	 * Start with the root of the tree, which is a target node, containing
	 * just the SCSI inquiry properties.
	 */
	if ((root = ses_node_alloc(sp, sp->ss_root)) == NULL)
		return (-1);

	root->sn_type = SES_NODE_TARGET;
	SES_NV_ADD(string, err, root->sn_props, SCSI_PROP_VENDOR,
	    libscsi_vendor(sp->ss_target->st_target));
	SES_NV_ADD(string, err, root->sn_props, SCSI_PROP_PRODUCT,
	    libscsi_product(sp->ss_target->st_target));
	SES_NV_ADD(string, err, root->sn_props, SCSI_PROP_REVISION,
	    libscsi_revision(sp->ss_target->st_target));

	for (eip = (ses2_ed_impl_t *)pip->scpi_data, i = 0;
	    i < pip->scpi_n_subenclosures + 1;
	    i++, eip = NEXT_ED(eip)) {
		if (!SES_WITHIN_PAGE_STRUCT(eip, pp->ssp_page, pp->ssp_len))
			break;

		n_etds += eip->st_hdr.sehi_n_etd_hdrs;
	}
	ftip = (ses2_td_hdr_impl_t *)eip;

	/*
	 * There should really be only one Enclosure element possible for a
	 * give subenclosure ID.  The standard never comes out and says this,
	 * but it does describe this element as "managing the enclosure itself"
	 * which implies rather strongly that the subenclosure ID field is that
	 * of, well, the enclosure itself.  Since an enclosure can't contain
	 * itself, it follows logically that each subenclosure has at most one
	 * Enclosure type descriptor elements matching its ID.  Of course, some
	 * enclosure firmware is buggy, so this may not always work out; in
	 * this case we just ignore all but the first Enclosure-type element
	 * with our subenclosure ID.
	 */
	for (eip = (ses2_ed_impl_t *)pip->scpi_data, i = 0;
	    i < pip->scpi_n_subenclosures + 1;
	    i++, eip = NEXT_ED(eip)) {
		if (!SES_WITHIN_PAGE_STRUCT(eip, pp->ssp_page, pp->ssp_len))
			break;

		if ((np = ses_node_alloc(sp, root)) == NULL)
			return (-1);

		np->sn_type = SES_NODE_ENCLOSURE;
		np->sn_enc_num = eip->st_hdr.sehi_subenclosure_id;

		if (!SES_WITHIN_PAGE(eip, eip->st_hdr.sehi_ed_len +
		    sizeof (ses2_ed_hdr_impl_t),
		    pp->ssp_page, pp->ssp_len))
			break;

		if (enc_parse_ed(eip, np->sn_props) != 0)
			return (-1);
	}

	if (root->sn_first_child == NULL)
		return (ses_error(ESES_BAD_RESPONSE, "no enclosure "
		    "descriptors found"));

	tp = (char *)(ftip + n_etds);

	for (i = 0, toff = 0, idx = 0; i < n_etds; i++) {
		tip = ftip + i;

		if (!SES_WITHIN_PAGE_STRUCT(tip, pp->ssp_page, pp->ssp_len))
			break;

		pnp = ses_find_enclosure(sp,
		    tip->sthi_subenclosure_id);
		if (pnp == NULL) {
			idx += tip->sthi_max_elements + 1;
			toff += tip->sthi_text_len;
			continue;
		}

		if (tip->sthi_element_type == SES_ET_ENCLOSURE) {
			if (tip->sthi_max_elements == 0) {
				SES_NV_ADD(uint64, err, pnp->sn_props,
				    SES_PROP_ELEMENT_INDEX, idx);
				pnp->sn_rootidx = idx;
			} else {
				SES_NV_ADD(uint64, err, pnp->sn_props,
				    SES_PROP_ELEMENT_INDEX, idx + 1);
				pnp->sn_rootidx = idx + 1;
			}

			if (tip->sthi_text_len > 0 &&
			    SES_WITHIN_PAGE(tp + toff, tip->sthi_text_len,
			    pp->ssp_page, pp->ssp_len)) {
				text = tp + toff;
				toff += tip->sthi_text_len;
			} else {
				text = NULL;
			}

			SES_NV_ADD(uint64, err, pnp->sn_props,
			    SES_PROP_ELEMENT_TYPE, SES_ET_ENCLOSURE);
			if (enc_parse_td(tip, text, pnp->sn_props) != 0)
				return (-1);

			idx += tip->sthi_max_elements + 1;
			continue;
		}

		if ((np = ses_node_alloc(sp, pnp)) == NULL)
			return (-1);

		np->sn_type = SES_NODE_AGGREGATE;
		np->sn_enc_num = tip->sthi_subenclosure_id;
		np->sn_parent = pnp;
		np->sn_rootidx = idx;

		SES_NV_ADD(uint64, err, np->sn_props,
		    SES_PROP_ELEMENT_INDEX, idx);
		SES_NV_ADD(uint64, err, np->sn_props,
		    SES_PROP_ELEMENT_TYPE, tip->sthi_element_type);

		if (tip->sthi_text_len > 0 &&
		    SES_WITHIN_PAGE(tp + toff, tip->sthi_text_len,
		    pp->ssp_page, pp->ssp_len)) {
			text = tp + toff;
			toff += tip->sthi_text_len;
		} else {
			text = NULL;
		}

		if (elem_parse_td(tip, text, np->sn_props) != 0)
			return (-1);

		idx += tip->sthi_max_elements + 1;

		if (tip->sthi_max_elements == 0)
			continue;

		for (j = 0; j < tip->sthi_max_elements; j++) {
			cnp = ses_node_alloc(sp, np);
			if (cnp == NULL)
				return (-1);

			cnp->sn_type = SES_NODE_ELEMENT;
			SES_NV_ADD(uint64, err, cnp->sn_props,
			    SES_PROP_ELEMENT_INDEX, np->sn_rootidx + j + 1);
			SES_NV_ADD(uint64, err, cnp->sn_props,
			    SES_PROP_ELEMENT_CLASS_INDEX, j);
			SES_NV_ADD(uint64, err, cnp->sn_props,
			    SES_PROP_ELEMENT_TYPE, tip->sthi_element_type);
		}
	}

	np->sn_snapshot->ss_n_elem = idx;

	return (0);
}

static int
ses_fill_tree(ses_node_t *np)
{
	if (np == NULL)
		return (0);

	for (; np != NULL; np = np->sn_next_sibling) {
		if (ses_fill_node(np) != 0)
			return (-1);
		if (ses_fill_tree(np->sn_first_child) != 0)
			return (-1);
	}

	return (0);
}

int
ses_fill_snap(ses_snap_t *sp)
{
	if (ses_build_snap_skel(sp) != 0)
		return (-1);

	if (ses_fill_tree(sp->ss_root) != 0)
		return (-1);

	return (0);
}

ses_node_t *
ses_root_node(ses_snap_t *sp)
{
	return (sp->ss_root);
}

ses_node_t *
ses_node_sibling(ses_node_t *np)
{
	return (np->sn_next_sibling);
}

ses_node_t *
ses_node_prev_sibling(ses_node_t *np)
{
	return (np->sn_prev_sibling);
}

ses_node_t *
ses_node_parent(ses_node_t *np)
{
	return (np->sn_parent);
}

ses_node_t *
ses_node_child(ses_node_t *np)
{
	return (np->sn_first_child);
}

ses_node_type_t
ses_node_type(ses_node_t *np)
{
	return (np->sn_type);
}

ses_snap_t *
ses_node_snapshot(ses_node_t *np)
{
	return ((ses_snap_t *)np->sn_snapshot);
}

ses_target_t *
ses_node_target(ses_node_t *np)
{
	return (np->sn_snapshot->ss_target);
}

nvlist_t *
ses_node_props(ses_node_t *np)
{
	return (np->sn_props);
}

/*
 * A node identifier is a (generation, index) tuple that can be used to lookup a
 * node within this target at a later point.  This will be valid across
 * snapshots, though it will return failure if the generation count has changed.
 */
uint64_t
ses_node_id(ses_node_t *np)
{
	return (((uint64_t)np->sn_snapshot->ss_generation << 32) |
	    np->sn_id);
}
