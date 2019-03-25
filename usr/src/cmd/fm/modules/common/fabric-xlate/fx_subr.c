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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 */
#include <strings.h>
#include <fm/topo_hc.h>
#include <sys/fm/util.h>
#include <libxml/xpath.h>
#include <libxml/parser.h>
#include <libxml/xpathInternals.h>
#include <libxml/tree.h>

#include "fabric-xlate.h"

#define	HAS_PROP(node, name) xmlHasProp(node, (const xmlChar *)name)
#define	GET_PROP(node, name) ((char *)xmlGetProp(node, (const xmlChar *)name))
#define	FREE_PROP(prop) xmlFree((xmlChar *)prop)

extern xmlXPathContextPtr fab_xpathCtx;

/* ARGSUSED */
int
fab_prep_basic_erpt(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *erpt,
    boolean_t isRC)
{
	uint64_t	*now;
	uint64_t	ena;
	uint_t		nelem;
	nvlist_t	*detector, *new_detector;
	char		rcpath[255];
	int		err = 0;

	/* Grab the tod, ena and detector(FMRI) */
	err |= nvlist_lookup_uint64_array(nvl, "__tod", &now, &nelem);
	err |= nvlist_lookup_uint64(nvl, "ena", &ena);
	err |= nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR, &detector);
	if (err)
		return (err);

	/* Make a copy of the detector */
	err = nvlist_dup(detector, &new_detector, NV_UNIQUE_NAME);
	if (err)
		return (err);

	/* Copy the tod and ena to erpt */
	(void) nvlist_add_uint64(erpt, FM_EREPORT_ENA, ena);
	(void) nvlist_add_uint64_array(erpt, "__tod", now, nelem);

	/*
	 * Create the correct ROOT FMRI from PCIe leaf fabric ereports.	 Used
	 * only by fab_prep_fake_rc_erpt.  See the fab_pciex_fake_rc_erpt_tbl
	 * comments for more information.
	 */
	if (isRC && fab_get_rcpath(hdl, nvl, rcpath)) {
		/* Create the correct PCIe RC new_detector aka FMRI */
		(void) nvlist_remove(new_detector, FM_FMRI_DEV_PATH,
		    DATA_TYPE_STRING);
		(void) nvlist_add_string(new_detector, FM_FMRI_DEV_PATH,
		    rcpath);
	}

	/* Copy the FMRI to erpt */
	(void) nvlist_add_nvlist(erpt, FM_EREPORT_DETECTOR, new_detector);

	nvlist_free(new_detector);
	return (err);
}

void
fab_send_tgt_erpt(fmd_hdl_t *hdl, fab_data_t *data, const char *class,
    boolean_t isPrimary)
{
	nvlist_t	*nvl = data->nvl;
	nvlist_t	*erpt;
	char		*fmri = NULL;
	uint32_t	tgt_trans;
	uint64_t	tgt_addr;
	uint16_t	tgt_bdf;

	if (isPrimary) {
		tgt_trans = data->pcie_ue_tgt_trans;
		tgt_addr = data->pcie_ue_tgt_addr;
		tgt_bdf = data->pcie_ue_tgt_bdf;
	} else {
		tgt_trans = data->pcie_sue_tgt_trans;
		tgt_addr = data->pcie_sue_tgt_addr;
		tgt_bdf = data->pcie_sue_tgt_bdf;
	}

	fmd_hdl_debug(hdl, "Sending Target Ereport: "
	    "type 0x%x addr 0x%llx fltbdf 0x%x\n",
	    tgt_trans, tgt_addr, tgt_bdf);

	if (!tgt_trans)
		return;

	if ((tgt_trans == PF_ADDR_PIO) && tgt_addr)
		fmri = fab_find_addr(hdl, nvl, tgt_addr);
	else if ((tgt_trans == PF_ADDR_CFG || (tgt_trans == PF_ADDR_DMA)) &&
	    tgt_bdf)
		fmri = fab_find_bdf(hdl, nvl, tgt_bdf);

	if (fmri) {
		uint64_t	*now;
		uint64_t	ena;
		uint_t		nelem;
		nvlist_t	*detector;
		int		err = 0;

		/* Allocate space for new erpt */
		if (nvlist_alloc(&erpt, NV_UNIQUE_NAME, 0) != 0)
			goto done;

		/* Generate the target ereport class */
		(void) snprintf(fab_buf, FM_MAX_CLASS, "ereport.io.%s.%s",
		    PCI_ERROR_SUBCLASS, class);
		(void) nvlist_add_string(erpt, FM_CLASS, fab_buf);

		/* Grab the tod, ena and detector(FMRI) */
		err |= nvlist_lookup_uint64_array(nvl, "__tod", &now, &nelem);
		err |= nvlist_lookup_uint64(nvl, "ena", &ena);

		/* Copy the tod and ena to erpt */
		(void) nvlist_add_uint64(erpt, FM_EREPORT_ENA, ena);
		(void) nvlist_add_uint64_array(erpt, "__tod", now, nelem);

		/* Create the correct FMRI */
		if (nvlist_alloc(&detector, NV_UNIQUE_NAME, 0) != 0) {
			nvlist_free(erpt);
			goto done;
		}
		(void) nvlist_add_uint8(detector, FM_VERSION,
		    FM_DEV_SCHEME_VERSION);
		(void) nvlist_add_string(detector, FM_FMRI_SCHEME,
		    FM_FMRI_SCHEME_DEV);
		(void) nvlist_add_string(detector, FM_FMRI_DEV_PATH, fmri);
		(void) nvlist_add_nvlist(erpt, FM_EREPORT_DETECTOR, detector);
		nvlist_free(detector);

		/* Add the address payload */
		(void) nvlist_add_uint64(erpt, PCI_PA, tgt_addr);

		fmd_hdl_debug(hdl, "Sending target ereport: %s 0x%x\n",
		    fab_buf, tgt_addr);
		fmd_xprt_post(hdl, fab_fmd_xprt, erpt, 0);
		if (fmd_xprt_error(hdl, fab_fmd_xprt))
			goto done;
		fmd_hdl_strfree(hdl, fmri);
	} else {
		fmd_hdl_debug(hdl,
		    "Cannot find Target FMRI addr:0x%llx bdf 0x%x\n",
		    tgt_addr, tgt_bdf);
	}

	return;
done:
	if (fmri)
		xmlFree(fmri);
	fmd_hdl_debug(hdl, "Failed to send Target PCI ereport\n");
}

void
fab_send_erpt(fmd_hdl_t *hdl, fab_data_t *data, fab_err_tbl_t *tbl)
{
	fab_erpt_tbl_t	*erpt_tbl, *entry;
	nvlist_t	*erpt;
	uint32_t	reg;
	int		err;

	erpt_tbl = tbl->erpt_tbl;
	if (tbl->reg_size == 16) {
		reg = (uint32_t)*((uint16_t *)
		    ((uint32_t)data + tbl->reg_offset));
	} else {
		reg = *((uint32_t *)((uint32_t)data + tbl->reg_offset));
	}

	for (entry = erpt_tbl; entry->err_class; entry++) {
		if (!(reg & entry->reg_bit))
			continue;

		if (nvlist_alloc(&erpt, NV_UNIQUE_NAME, 0) != 0)
			goto done;

		err = tbl->fab_prep(hdl, data, erpt, entry);
		if (err != 0 && err != PF_EREPORT_IGNORE) {
			fmd_hdl_debug(hdl, "Prepping ereport failed: "
			    "class = %s\n", entry->err_class);
			nvlist_free(erpt);
			continue;
		}

		if (data->pcie_rp_send_all) {
			fab_send_erpt_all_rps(hdl, erpt);
			nvlist_free(erpt);
			return;
		}

		fmd_hdl_debug(hdl, "Sending ereport: %s 0x%x\n", fab_buf, reg);
		fmd_xprt_post(hdl, fab_fmd_xprt, erpt, 0);
		if (fmd_xprt_error(hdl, fab_fmd_xprt)) {
			fmd_hdl_debug(hdl, "Failed to send PCI ereport\n");
			return;
		}
	}

	return;
done:
	fmd_hdl_debug(hdl, "Failed  to send PCI ereport\n");
}

char *
fab_xpath_query(fmd_hdl_t *hdl, const char *query)
{
	xmlXPathObjectPtr xpathObj;
	xmlNodeSetPtr nodes;
	char *temp, *res;

	fmd_hdl_debug(hdl, "xpathObj query %s\n", query);

	xpathObj = xmlXPathEvalExpression((const xmlChar *)query,
	    fab_xpathCtx);

	if (xpathObj == NULL)
		return (NULL);

	fmd_hdl_debug(hdl, "xpathObj 0x%p type %d\n", xpathObj,
	    xpathObj->type);
	nodes = xpathObj->nodesetval;

	if (nodes) {
		temp = (char *)xmlNodeGetContent(nodes->nodeTab[0]);
		fmd_hdl_debug(hdl, "query result: %s\n", temp);
		res = fmd_hdl_strdup(hdl, temp, FMD_SLEEP);
		xmlFree(temp);
		xmlXPathFreeObject(xpathObj);
		return (res);
	}
	xmlXPathFreeObject(xpathObj);
	return (NULL);
}

#define	FAB_HC2DEV_QUERY_SIZE_MIN 160
#define	FAB_HC2DEV_QUERY_SIZE(sz) \
	((sz + FAB_HC2DEV_QUERY_SIZE_MIN) * sizeof (char))

/*
 * hc_path is in form of "/motherboard=0/hostbridge=0/pciexrc=0"
 */
boolean_t
fab_hc2dev(fmd_hdl_t *hdl, const char *hc_path, char **dev_path)
{
	char *query;
	uint_t len = FAB_HC2DEV_QUERY_SIZE_MIN + strlen(hc_path);

	query = fmd_hdl_alloc(hdl, len, FMD_SLEEP);
	(void) snprintf(query, len, "//propval[@name='resource' and contains("
	    "substring(@value, string-length(@value) - %d + 1), '%s')]"
	    "/parent::*/following-sibling::*/propval[@name='dev']/@value",
	    strlen(hc_path) + 1, hc_path);

	*dev_path = fab_xpath_query(hdl, query);

	fmd_hdl_free(hdl, query, len);

	return (*dev_path != NULL);
}

static boolean_t
fab_hc_path(fmd_hdl_t *hdl, nvlist_t *detector, char **hcpath, size_t *lenp)
{
	char c, *name, *id, *buf;
	uint_t i, size;
	nvlist_t **hcl;
	size_t len = 0, buf_size = 0;

	if (nvlist_lookup_nvlist_array(detector, FM_FMRI_HC_LIST, &hcl,
	    &size) != 0)
		return (B_FALSE);

	for (i = 0; i < size; i++) {
		if (nvlist_lookup_string(hcl[i], FM_FMRI_HC_NAME, &name) != 0)
			return (B_FALSE);
		if (nvlist_lookup_string(hcl[i], FM_FMRI_HC_ID, &id) != 0)
			return (B_FALSE);
		buf_size += snprintf(&c, 1, "/%s=%s", name, id);
	}

	buf_size++;
	buf = fmd_hdl_alloc(hdl, buf_size, FMD_SLEEP);

	for (i = 0; i < size; i++) {
		(void) nvlist_lookup_string(hcl[i], FM_FMRI_HC_NAME, &name);
		(void) nvlist_lookup_string(hcl[i], FM_FMRI_HC_ID, &id);
		len += snprintf(buf + len, buf_size - len, "/%s=%s", name, id);
	}

	*hcpath = buf;
	*lenp = buf_size;

	return (B_TRUE);
}

boolean_t
fab_hc2dev_nvl(fmd_hdl_t *hdl, nvlist_t *detector, char **dev_path)
{
	char *hcl;
	size_t len;

	if (! fab_hc_path(hdl, detector, &hcl, &len))
		return (B_FALSE);

	(void) fab_hc2dev(hdl, hcl, dev_path);

	fmd_hdl_free(hdl, hcl, len);

	return (*dev_path != NULL);
}

boolean_t
fab_get_hcpath(fmd_hdl_t *hdl, nvlist_t *nvl, char **hcpath, size_t *len)
{
	nvlist_t *detector;
	char *scheme;

	if (nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR, &detector) != 0 ||
	    nvlist_lookup_string(detector, FM_FMRI_SCHEME, &scheme) != 0 ||
	    ! STRCMP(scheme, FM_FMRI_SCHEME_HC))
		return (B_FALSE);

	return (fab_hc_path(hdl, detector, hcpath, len));
}

char *
fab_find_rppath_by_df(fmd_hdl_t *hdl, nvlist_t *nvl, uint8_t df)
{
	char	query[500];
	char	str[10];
	char	*hcpath;
	size_t	len;

	(void) snprintf(str, sizeof (str), "%0hhx", df);

	/*
	 * get the string form of the hc detector, eg
	 * /chassis=0/motherboard=0/hostbridge=0
	 */
	if (!fab_get_hcpath(hdl, nvl, &hcpath, &len))
		return (NULL);

	/*
	 * Explanation of the XSL XPATH Query
	 * Line 1: Look at all nodes with the node name "propval"
	 * Line 2: See if the "BDF" of the node matches DF
	 * Line 3-4: See if the the node is pciexrc
	 * Line 5-6: See if the "ASRU" contains root complex
	 * Line 7-8: Go up one level and get prop value of io/dev
	 */
	(void) snprintf(query, sizeof (query), "//propval["
	    "@name='BDF' and contains(substring(@value, "
	    "string-length(@value) - 1), '%s')]"
	    "/parent::*/parent::*/propgroup[@name='pci']/propval"
	    "[@name='extended-capabilities' and @value='%s']"
	    "/parent::*/parent::*/propgroup[@name='protocol']"
	    "/propval[@name='resource' and contains(@value, '%s')]"
	    "/parent::*/parent::*/propgroup[@name='io']"
	    "/propval[@name='dev']/@value", str, PCIEX_ROOT, hcpath);

	fmd_hdl_free(hdl, hcpath, len);

	return (fab_xpath_query(hdl, query));
}

char *
fab_find_rppath_by_devbdf(fmd_hdl_t *hdl, nvlist_t *nvl, pcie_req_id_t bdf)
{
	xmlXPathObjectPtr xpathObj;
	xmlNodeSetPtr nodes;
	xmlNodePtr devNode;
	char	*retval, *temp;
	char	query[500];
	int	i, size, bus, dev, fn;
	char	*hcpath;
	size_t	len;

	if (bdf != (uint16_t)-1) {
		bus = (bdf & PCIE_REQ_ID_BUS_MASK) >> PCIE_REQ_ID_BUS_SHIFT;
		dev = (bdf & PCIE_REQ_ID_DEV_MASK) >> PCIE_REQ_ID_DEV_SHIFT;
		fn = (bdf & PCIE_REQ_ID_FUNC_MASK) >> PCIE_REQ_ID_FUNC_SHIFT;
	}

	/*
	 * get the string form of the hc detector, eg
	 * /chassis=0/motherboard=0/hostbridge=0
	 */
	if (!fab_get_hcpath(hdl, nvl, &hcpath, &len))
		goto fail;

	/*
	 * Explanation of the XSL XPATH Query
	 * Line 1: Look at all nodes with the node name "propval"
	 * Line 2-3: See if the "value" of the node ends with correct PCIEx BDF
	 * Line 4-5: See if the "value" of the node ends with correct PCI BDF
	 * Line 6: Go up one level to the parent of the current node
	 * Line 7: See if child node contains "ASRU" with the same PCIe Root
	 * Line 8: Go up see all the ancestors
	 */
	(void) snprintf(query, sizeof (query), "//propval["
	    "contains(substring(@value, string-length(@value) - 34), "
	    "'pciexbus=%d/pciexdev=%d/pciexfn=%d') or "
	    "contains(substring(@value, string-length(@value) - 28), "
	    "'pcibus=%d/pcidev=%d/pcifn=%d')"
	    "]/parent::"
	    "*/propval[@name='resource' and contains(@value, '%s')]"
	    "/ancestor::*",
	    bus, dev, fn, bus, dev, fn, hcpath);

	fmd_hdl_free(hdl, hcpath, len);

	fmd_hdl_debug(hdl, "xpathObj query %s\n", query);

	xpathObj = xmlXPathEvalExpression((const xmlChar *)query, fab_xpathCtx);

	if (xpathObj == NULL)
		goto fail;

	nodes = xpathObj->nodesetval;
	size = (nodes) ? nodes->nodeNr : 0;

	fmd_hdl_debug(hdl, "xpathObj 0x%p type %d size %d\n",
	    xpathObj, xpathObj->type, size);

	for (i = 0; i < size; i++) {
		devNode = nodes->nodeTab[i];
		if (STRCMP(devNode->name, "range") &&
		    HAS_PROP(devNode, "name")) {
			char *tprop = GET_PROP(devNode, "name");

			/* find "range name='pciexrc'" in ancestors */
			if (STRCMP(tprop, PCIEX_ROOT)) {
				/* go down to the pciexrc instance node */
				FREE_PROP(tprop);
				devNode = nodes->nodeTab[i+1];
				goto found;
			}
			FREE_PROP(tprop);
		}
	}
	goto fail;

found:
	/* Traverse down the xml tree to find the right propgroup */
	for (devNode = devNode->children; devNode; devNode = devNode->next) {
		if (STRCMP(devNode->name, "propgroup")) {
			char *tprop = GET_PROP(devNode, "name");

			if (STRCMP(tprop, "io")) {
				FREE_PROP(tprop);
				goto propgroup;
			}
			FREE_PROP(tprop);
		}
	}
	goto fail;

propgroup:
	/* Retrive the "dev" propval and return */
	for (devNode = devNode->children; devNode; devNode = devNode->next) {
		if (STRCMP(devNode->name, "propval")) {
			char *tprop = GET_PROP(devNode, "name");

			if (STRCMP(tprop, "dev")) {
				temp = GET_PROP(devNode, "value");
				retval = fmd_hdl_strdup(hdl, temp, FMD_SLEEP);
				fmd_hdl_debug(hdl, "RP Path: %s\n", retval);
				xmlFree(temp);
				xmlXPathFreeObject(xpathObj);
			}
			FREE_PROP(tprop);

			return (retval);
		}
	}
fail:
	if (xpathObj != NULL)
		xmlXPathFreeObject(xpathObj);
	return (NULL);
}

char *
fab_find_rppath_by_devpath(fmd_hdl_t *hdl, const char *devpath)
{
	char	query[500];

	/*
	 * Explanation of the XSL XPATH Query
	 * Line 1: Look at all nodes with the node name "propval"
	 * Line 2: See if the node is pciexrc
	 * Line 3: Go up to the io pgroup
	 * Line 4: See if the "dev" prop is parent of devpath
	 * Line 5: Get the 'dev' prop
	 */
	(void) snprintf(query, sizeof (query), "//propval"
	    "[@name='extended-capabilities' and @value='%s']"
	    "/parent::*/parent::*/propgroup[@name='io']"
	    "/propval[@name='dev' and starts-with('%s', concat(@value, '/'))]"
	    "/@value", PCIEX_ROOT, devpath);

	return (fab_xpath_query(hdl, query));
}

/* ARGSUSED */
boolean_t
fab_get_rcpath(fmd_hdl_t *hdl, nvlist_t *nvl, char *rcpath)
{
	nvlist_t	*detector;
	char		*path, *scheme;

	if (nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR, &detector) != 0)
		goto fail;
	if (nvlist_lookup_string(detector, FM_FMRI_SCHEME, &scheme) != 0)
		goto fail;

	if (STRCMP(scheme, FM_FMRI_SCHEME_DEV)) {
		if (nvlist_lookup_string(detector, FM_FMRI_DEV_PATH,
		    &path) != 0)
			goto fail;
		(void) strncpy(rcpath, path, FM_MAX_CLASS);
	} else if (STRCMP(scheme, FM_FMRI_SCHEME_HC)) {
		/*
		 * This should only occur for ereports that come from the RC
		 * itself.  In this case convert HC scheme to dev path.
		 */
		if (fab_hc2dev_nvl(hdl, detector, &path)) {
			(void) strncpy(rcpath, path, FM_MAX_CLASS);
			fmd_hdl_strfree(hdl, path);
		} else {
			goto fail;
		}
	} else {
		return (B_FALSE);
	}

	/*
	 * Extract the RC path by taking the first device in the dev path
	 *
	 * /pci@0,0/pci8086,3605@2/pci8086,3500@0/pci8086,3514@1/pci8086,105e@0
	 * - to -
	 * /pci@0,0
	 */
	path = strchr(rcpath + 1, '/');
	if (path)
		path[0] = '\0';

	return (B_TRUE);
fail:
	return (B_FALSE);
}

char *
fab_find_bdf(fmd_hdl_t *hdl, nvlist_t *nvl, pcie_req_id_t bdf)
{
	char	*retval;
	char	query[500];
	int	bus, dev, fn;
	char	rcpath[255];

	if (bdf != (uint16_t)-1) {
		bus = (bdf & PCIE_REQ_ID_BUS_MASK) >> PCIE_REQ_ID_BUS_SHIFT;
		dev = (bdf & PCIE_REQ_ID_DEV_MASK) >> PCIE_REQ_ID_DEV_SHIFT;
		fn = (bdf & PCIE_REQ_ID_FUNC_MASK) >> PCIE_REQ_ID_FUNC_SHIFT;
	}

	if (!fab_get_rcpath(hdl, nvl, rcpath))
		goto fail;

	/*
	 * Explanation of the XSL XPATH Query
	 * Line 1: Look at all nodes with the node name "propval"
	 * Line 2-3: See if the "value" of the node ends with correct PCIEx BDF
	 * Line 4-5: See if the "value" of the node ends with correct PCI BDF
	 * Line 6: Go up one level to the parent of the current node
	 * Line 7: See if child node contains "ASRU" with the same PCIe Root
	 * Line 8: Traverse up the parent and the other siblings and look for
	 *	   the io "propgroup" and get the value of the dev "propval"
	 */
	(void) snprintf(query, sizeof (query), "//propval["
	    "contains(substring(@value, string-length(@value) - 34), "
	    "'pciexbus=%d/pciexdev=%d/pciexfn=%d') or "
	    "contains(substring(@value, string-length(@value) - 28), "
	    "'pcibus=%d/pcidev=%d/pcifn=%d')"
	    "]/parent::"
	    "*/propval[@name='ASRU' and contains(@value, '%s')]"
	    "/parent::*/following-sibling::*[@name='io']/propval[@name='dev']/"
	    "@value", bus, dev, fn, bus, dev, fn, rcpath);

	retval = fab_xpath_query(hdl, query);
	if (retval) {
		fmd_hdl_debug(hdl, "BDF Dev Path: %s\n", retval);
		return (retval);
	}
fail:
	return (NULL);
}

char *
fab_find_addr(fmd_hdl_t *hdl, nvlist_t *nvl, uint64_t addr)
{
	xmlXPathObjectPtr xpathObj;
	xmlNodeSetPtr nodes;
	xmlNodePtr devNode;
	char *retval, *temp;
	char query[500];
	int size, i, j;
	uint32_t prop[50];
	char *token;
	pci_regspec_t *assign_p;
	uint64_t low, hi;
	char rcpath[255];

	if (!fab_get_rcpath(hdl, nvl, rcpath))
		goto fail;

	(void) snprintf(query, sizeof (query), "//propval["
	    "@name='ASRU' and contains(@value, '%s')]/"
	    "parent::*/following-sibling::*[@name='pci']/"
	    "propval[@name='assigned-addresses']", rcpath);

	fmd_hdl_debug(hdl, "xpathObj query %s\n", query);

	xpathObj = xmlXPathEvalExpression((const xmlChar *)query, fab_xpathCtx);

	if (xpathObj == NULL)
		goto fail;

	fmd_hdl_debug(hdl, "xpathObj 0x%p type %d\n", xpathObj, xpathObj->type);

	nodes = xpathObj->nodesetval;
	size = (nodes) ? nodes->nodeNr : 0;

	/* Decode the list of assigned addresses xml nodes for each device */
	for (i = 0; i < size; i++) {
		char *tprop;

		devNode = nodes->nodeTab[i];
		if (!HAS_PROP(devNode, "value"))
			continue;

		/* Convert "string" assigned-addresses to pci_regspec_t */
		j = 0;
		tprop = GET_PROP(devNode, "value");
		for (token = strtok(tprop, " "); token;
		    token = strtok(NULL, " ")) {
			prop[j++] = strtoul(token, (char **)NULL, 16);
		}
		prop[j] = (uint32_t)-1;
		FREE_PROP(tprop);

		/* Check if address belongs to this device */
		for (assign_p = (pci_regspec_t *)prop;
		    assign_p->pci_phys_hi != (uint_t)-1; assign_p++) {
			low = assign_p->pci_phys_low;
			hi = low + assign_p->pci_size_low;
			if ((addr < hi) && (addr >= low)) {
				fmd_hdl_debug(hdl, "Found Address\n");
				goto found;
			}
		}
	}
	goto fail;

found:
	/* Traverse up the xml tree and back down to find the right propgroup */
	for (devNode = devNode->parent->parent->children;
	    devNode; devNode = devNode->next) {
		char	*tprop;

		tprop = GET_PROP(devNode, "name");
		if (STRCMP(devNode->name, "propgroup") &&
		    STRCMP(tprop, "io")) {
			FREE_PROP(tprop);
			goto propgroup;
		}
		FREE_PROP(tprop);
	}
	goto fail;

propgroup:
	/* Retrive the "dev" propval and return */
	for (devNode = devNode->children; devNode; devNode = devNode->next) {
		char	*tprop;

		tprop = GET_PROP(devNode, "name");
		if (STRCMP(devNode->name, "propval") &&
		    STRCMP(tprop, "dev")) {
			FREE_PROP(tprop);
			temp = GET_PROP(devNode, "value");
			retval = fmd_hdl_strdup(hdl, temp, FMD_SLEEP);
			fmd_hdl_debug(hdl, "Addr Dev Path: %s\n", retval);
			xmlFree(temp);
			xmlXPathFreeObject(xpathObj);
			return (retval);
		}
		FREE_PROP(tprop);
	}
fail:
	if (xpathObj != NULL)
		xmlXPathFreeObject(xpathObj);
	return (NULL);
}

void
fab_pr(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl)
{
	nvpair_t *nvp;

	for (nvp = nvlist_next_nvpair(nvl, NULL);
	    nvp != NULL;
	    nvp = nvlist_next_nvpair(nvl, nvp)) {

		data_type_t type = nvpair_type(nvp);
		const char *name = nvpair_name(nvp);

		boolean_t b;
		uint8_t i8;
		uint16_t i16;
		uint32_t i32;
		uint64_t i64;
		char *str;
		nvlist_t *cnv;

		nvlist_t **nvlarr;
		uint_t arrsize;
		int arri;


		if (STRCMP(name, FM_CLASS))
			continue; /* already printed by caller */

		fmd_hdl_debug(hdl, " %s=", name);

		switch (type) {
		case DATA_TYPE_BOOLEAN:
			fmd_hdl_debug(hdl, "DATA_TYPE_BOOLEAN 1");
			break;

		case DATA_TYPE_BOOLEAN_VALUE:
			(void) nvpair_value_boolean_value(nvp, &b);
			fmd_hdl_debug(hdl, "DATA_TYPE_BOOLEAN_VALUE %d",
			    b ? "1" : "0");
			break;

		case DATA_TYPE_BYTE:
			(void) nvpair_value_byte(nvp, &i8);
			fmd_hdl_debug(hdl, "DATA_TYPE_BYTE 0x%x", i8);
			break;

		case DATA_TYPE_INT8:
			(void) nvpair_value_int8(nvp, (void *)&i8);
			fmd_hdl_debug(hdl, "DATA_TYPE_INT8 0x%x", i8);
			break;

		case DATA_TYPE_UINT8:
			(void) nvpair_value_uint8(nvp, &i8);
			fmd_hdl_debug(hdl, "DATA_TYPE_UINT8 0x%x", i8);
			break;

		case DATA_TYPE_INT16:
			(void) nvpair_value_int16(nvp, (void *)&i16);
			fmd_hdl_debug(hdl, "DATA_TYPE_INT16 0x%x", i16);
			break;

		case DATA_TYPE_UINT16:
			(void) nvpair_value_uint16(nvp, &i16);
			fmd_hdl_debug(hdl, "DATA_TYPE_UINT16 0x%x", i16);
			break;

		case DATA_TYPE_INT32:
			(void) nvpair_value_int32(nvp, (void *)&i32);
			fmd_hdl_debug(hdl, "DATA_TYPE_INT32 0x%x", i32);
			break;

		case DATA_TYPE_UINT32:
			(void) nvpair_value_uint32(nvp, &i32);
			fmd_hdl_debug(hdl, "DATA_TYPE_UINT32 0x%x", i32);
			break;

		case DATA_TYPE_INT64:
			(void) nvpair_value_int64(nvp, (void *)&i64);
			fmd_hdl_debug(hdl, "DATA_TYPE_INT64 0x%llx",
			    (u_longlong_t)i64);
			break;

		case DATA_TYPE_UINT64:
			(void) nvpair_value_uint64(nvp, &i64);
			fmd_hdl_debug(hdl, "DATA_TYPE_UINT64 0x%llx",
			    (u_longlong_t)i64);
			break;

		case DATA_TYPE_HRTIME:
			(void) nvpair_value_hrtime(nvp, (void *)&i64);
			fmd_hdl_debug(hdl, "DATA_TYPE_HRTIME 0x%llx",
			    (u_longlong_t)i64);
			break;

		case DATA_TYPE_STRING:
			(void) nvpair_value_string(nvp, &str);
			fmd_hdl_debug(hdl, "DATA_TYPE_STRING \"%s\"",
			    str ? str : "<NULL>");
			break;

		case DATA_TYPE_NVLIST:
			fmd_hdl_debug(hdl, "[");
			(void) nvpair_value_nvlist(nvp, &cnv);
			fab_pr(hdl, NULL, cnv);
			fmd_hdl_debug(hdl, " ]");
			break;

		case DATA_TYPE_BOOLEAN_ARRAY:
		case DATA_TYPE_BYTE_ARRAY:
		case DATA_TYPE_INT8_ARRAY:
		case DATA_TYPE_UINT8_ARRAY:
		case DATA_TYPE_INT16_ARRAY:
		case DATA_TYPE_UINT16_ARRAY:
		case DATA_TYPE_INT32_ARRAY:
		case DATA_TYPE_UINT32_ARRAY:
		case DATA_TYPE_INT64_ARRAY:
		case DATA_TYPE_UINT64_ARRAY:
		case DATA_TYPE_STRING_ARRAY:
			fmd_hdl_debug(hdl, "[...]");
			break;
		case DATA_TYPE_NVLIST_ARRAY:
			arrsize = 0;
			(void) nvpair_value_nvlist_array(nvp, &nvlarr,
			    &arrsize);

			for (arri = 0; arri < arrsize; arri++) {
				fab_pr(hdl, ep, nvlarr[arri]);
			}

			break;
		case DATA_TYPE_UNKNOWN:
			fmd_hdl_debug(hdl, "<unknown>");
			break;
		}
	}
}

char *
fab_get_rpdev(fmd_hdl_t *hdl)
{
	char	*retval;
	char	query[500];

	(void) snprintf(query, sizeof (query), "//propval["
	    "@name='extended-capabilities' and contains(@value, '%s')]"
	    "/parent::*/parent::*/propgroup[@name='io']"
	    "/propval[@name='dev']/@value", PCIEX_ROOT);

	retval = fab_xpath_query(hdl, query);
	if (retval) {
		fmd_hdl_debug(hdl, "Root port path is %s\n", retval);
		return (retval);
	}

	return (NULL);
}

void
fab_send_erpt_all_rps(fmd_hdl_t *hdl, nvlist_t *erpt)
{
	xmlXPathObjectPtr xpathObj;
	xmlNodeSetPtr nodes;
	char	*rppath, *hbpath;
	char	query[600];
	nvlist_t *detector, *nvl;
	uint_t	i, size;
	size_t len;

	/* get hostbridge's path */
	if (!fab_get_hcpath(hdl, erpt, &hbpath, &len)) {
		fmd_hdl_debug(hdl,
		    "fab_send_erpt_on_all_rps: fab_get_hcpath() failed.\n");
		return;
	}

	(void) snprintf(query, sizeof (query), "//propval["
	    "@name='extended-capabilities' and contains(@value, '%s')]"
	    "/parent::*/parent::*/propgroup[@name='protocol']"
	    "/propval[@name='resource' and contains(@value, '%s/')"
	    "]/parent::*/parent::*/propgroup[@name='io']"
	    "/propval[@name='dev']/@value", PCIEX_ROOT, hbpath);

	fmd_hdl_free(hdl, hbpath, len);

	fmd_hdl_debug(hdl, "xpathObj query %s\n", query);

	xpathObj = xmlXPathEvalExpression((const xmlChar *)query, fab_xpathCtx);

	if (xpathObj == NULL)
		return;

	nodes = xpathObj->nodesetval;
	size = (nodes) ? nodes->nodeNr : 0;

	fmd_hdl_debug(hdl, "xpathObj 0x%p type %d size %d\n",
	    xpathObj, xpathObj->type, size);

	for (i = 0; i < size; i++) {
		rppath = (char *)xmlNodeGetContent(nodes->nodeTab[i]);
		fmd_hdl_debug(hdl, "query result: %s\n", rppath);

		nvl = detector = NULL;
		if (nvlist_dup(erpt, &nvl, NV_UNIQUE_NAME) != 0 ||
		    nvlist_alloc(&detector, NV_UNIQUE_NAME, 0) != 0) {
			xmlFree(rppath);
			nvlist_free(nvl);
			continue;
		}

		/*
		 * set the detector in the original ereport to the root port
		 */
		(void) nvlist_add_string(detector, FM_VERSION,
		    FM_DEV_SCHEME_VERSION);
		(void) nvlist_add_string(detector, FM_FMRI_SCHEME,
		    FM_FMRI_SCHEME_DEV);
		(void) nvlist_add_string(detector, FM_FMRI_DEV_PATH,
		    rppath);
		(void) nvlist_remove_all(nvl, FM_EREPORT_DETECTOR);
		(void) nvlist_add_nvlist(nvl, FM_EREPORT_DETECTOR,
		    detector);
		nvlist_free(detector);
		xmlFree(rppath);

		fmd_hdl_debug(hdl, "Sending ereport: %s\n", fab_buf);
		fmd_xprt_post(hdl, fab_fmd_xprt, nvl, 0);
		if (fmd_xprt_error(hdl, fab_fmd_xprt))
			fmd_hdl_debug(hdl,
			    "Failed to send PCI ereport\n");
	}

	xmlXPathFreeObject(xpathObj);
}
