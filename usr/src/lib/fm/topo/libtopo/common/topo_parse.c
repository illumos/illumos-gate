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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <libxml/parser.h>
#include <fm/libtopo.h>
#include <topo_alloc.h>
#include <topo_error.h>
#include <topo_parse.h>
#include <topo_subr.h>

tf_info_t *
tf_info_new(topo_mod_t *mp, xmlDocPtr doc, xmlChar *scheme)
{
	tf_info_t *r;

	if ((r = topo_mod_zalloc(mp, sizeof (tf_info_t))) == NULL)
		return (NULL);
	r->tf_flags = TF_LIVE;
	if ((r->tf_scheme = topo_mod_strdup(mp, (char *)scheme)) == NULL) {
		tf_info_free(mp, r);
		return (NULL);
	}
	r->tf_xdoc = doc;
	return (r);
}

void
tf_info_free(topo_mod_t *mp, tf_info_t *p)
{
	if (p->tf_xdoc != NULL)
		xmlFreeDoc(p->tf_xdoc);
	if (p->tf_scheme != NULL)
		topo_mod_strfree(mp, p->tf_scheme);
	tf_rdata_free(mp, p->tf_rd);
	topo_mod_free(mp, p, sizeof (tf_info_t));
}

tf_rdata_t *
tf_rdata_new(topo_mod_t *mp, tf_info_t *xinfo, xmlNodePtr n, tnode_t *troot)
{
	tf_rdata_t *r;
	uint64_t ui;
	xmlChar *name = NULL;

	topo_dprintf(mp->tm_hdl, TOPO_DBG_XML, "new rdata\n");
	if ((r = topo_mod_zalloc(mp, sizeof (tf_rdata_t))) == NULL) {
		(void) topo_mod_seterrno(mp, ETOPO_NOMEM);
		return (NULL);
	}
	r->rd_pn = troot;
	if ((name = xmlGetProp(n, (xmlChar *)Name)) == NULL) {
		(void) topo_mod_seterrno(mp, ETOPO_PRSR_NOATTR);
		goto rdata_nogood;
	}
	if ((r->rd_name = topo_mod_strdup(mp, (char *)name)) == NULL) {
		(void) topo_mod_seterrno(mp, ETOPO_NOMEM);
		goto rdata_nogood;
	}
	if (xmlattr_to_int(mp, n, Min, &ui) < 0)
		goto rdata_nogood;
	r->rd_min = (int)ui;
	if (xmlattr_to_int(mp, n, Max, &ui) < 0)
		goto rdata_nogood;
	r->rd_max = (int)ui;
	if (r->rd_min < 0 || r->rd_max < 0 || r->rd_max < r->rd_min) {
		(void) topo_mod_seterrno(mp, ETOPO_PRSR_BADRNG);
		goto rdata_nogood;
	}
	r->rd_finfo = xinfo;
	r->rd_mod = mp;

	if (topo_xml_range_process(mp, n, r) < 0)
		goto rdata_nogood;

	xmlFree(name);
	return (r);

rdata_nogood:
	if (name != NULL)
		xmlFree(name);
	tf_rdata_free(mp, r);
	return (NULL);
}

void
tf_rdata_free(topo_mod_t *mp, tf_rdata_t *p)
{
	if (p == NULL)
		return;
	tf_rdata_free(mp, p->rd_next);
	if (p->rd_name != NULL)
		topo_mod_strfree(mp, p->rd_name);
	tf_edata_free(mp, p->rd_einfo);
	tf_idata_free(mp, p->rd_instances);
	tf_pad_free(mp, p->rd_pad);
	topo_mod_free(mp, p, sizeof (tf_rdata_t));
}

tf_idata_t *
tf_idata_new(topo_mod_t *mp, topo_instance_t i, tnode_t *tn)
{
	tf_idata_t *r;

	topo_dprintf(mp->tm_hdl, TOPO_DBG_XML, "new idata %d\n", i);
	if ((r = topo_mod_zalloc(mp, sizeof (tf_idata_t))) == NULL)
		return (NULL);
	r->ti_tn = tn;
	r->ti_i = i;
	return (r);
}

void
tf_idata_free(topo_mod_t *mp, tf_idata_t *p)
{
	if (p == NULL)
		return;
	tf_idata_free(mp, p->ti_next);
	tf_pad_free(mp, p->ti_pad);
	topo_mod_free(mp, p, sizeof (tf_idata_t));
}

int
tf_idata_insert(tf_idata_t **head, tf_idata_t *ni)
{
	tf_idata_t *l, *p;

	p = NULL;
	for (l = *head; l != NULL; l = l->ti_next) {
		if (ni->ti_i < l->ti_i)
			break;
		p = l;
	}
	ni->ti_next = l;
	if (p == NULL)
		*head = ni;
	else
		p->ti_next = ni;
	return (0);
}

tf_idata_t *
tf_idata_lookup(tf_idata_t *head, topo_instance_t i)
{
	tf_idata_t *f;
	for (f = head; f != NULL; f = f->ti_next)
		if (i == f->ti_i)
			break;
	return (f);
}

tf_pad_t *
tf_pad_new(topo_mod_t *mp, int pcnt, int dcnt)
{
	tf_pad_t *r;

	topo_dprintf(mp->tm_hdl, TOPO_DBG_XML, "new pad p=%d, d=%d\n",
	    pcnt, dcnt);
	if ((r = topo_mod_zalloc(mp, sizeof (tf_pad_t))) == NULL)
		return (NULL);
	r->tpad_pgcnt = pcnt;
	r->tpad_dcnt = dcnt;
	return (r);
}

void
tf_pad_free(topo_mod_t *mp, tf_pad_t *p)
{
	int n;
	if (p == NULL)
		return;
	if (p->tpad_pgs != NULL) {
		for (n = 0; n < p->tpad_pgcnt; n++)
			nvlist_free(p->tpad_pgs[n]);
		topo_mod_free(mp,
		    p->tpad_pgs, p->tpad_pgcnt * sizeof (nvlist_t *));
	}
	tf_rdata_free(mp, p->tpad_child);
	tf_rdata_free(mp, p->tpad_sibs);
	topo_mod_free(mp, p, sizeof (tf_pad_t));
}

void
tf_edata_free(topo_mod_t *mp, tf_edata_t *p)
{
	if (p == NULL)
		return;
	if (p->te_name != NULL)
		xmlFree(p->te_name);
	topo_mod_free(mp, p, sizeof (tf_edata_t));
}
