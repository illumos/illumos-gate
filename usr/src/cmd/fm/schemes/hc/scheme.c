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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <strings.h>
#include <fm/fmd_fmri.h>
#include <fm/libtopo.h>
#include <fm/topo_mod.h>

int
fmd_fmri_init(void)
{
	return (0);
}

void
fmd_fmri_fini(void)
{
}

ssize_t
fmd_fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	int err;
	uint8_t version;
	ssize_t len;
	topo_hdl_t *thp;
	char *str;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_HC_SCHEME_VERSION)
		return (fmd_fmri_set_errno(EINVAL));

	if ((thp = fmd_fmri_topo_hold(TOPO_VERSION)) == NULL)
		return (fmd_fmri_set_errno(EINVAL));
	if (topo_fmri_nvl2str(thp, nvl, &str, &err) != 0) {
		fmd_fmri_topo_rele(thp);
		return (fmd_fmri_set_errno(EINVAL));
	}

	if (buf != NULL)
		len = snprintf(buf, buflen, "%s", str);
	else
		len = strlen(str);

	topo_hdl_strfree(thp, str);
	fmd_fmri_topo_rele(thp);

	return (len);
}

int
fmd_fmri_present(nvlist_t *nvl)
{
	int err, present;
	topo_hdl_t *thp;
	nvlist_t **hcprs;
	char *nm;
	uint_t hcnprs;

	err = nvlist_lookup_nvlist_array(nvl, FM_FMRI_HC_LIST, &hcprs, &hcnprs);
	if (err != 0)
		return (fmd_fmri_set_errno(EINVAL));
	err = nvlist_lookup_string(hcprs[0], FM_FMRI_HC_NAME, &nm);
	if (err != 0)
		return (fmd_fmri_set_errno(EINVAL));

	if ((thp = fmd_fmri_topo_hold(TOPO_VERSION)) == NULL)
		return (fmd_fmri_set_errno(EINVAL));
	present = topo_fmri_present(thp, nvl, &err);
	fmd_fmri_topo_rele(thp);

	return (present);
}

int
fmd_fmri_replaced(nvlist_t *nvl)
{
	int err, replaced;
	topo_hdl_t *thp;
	nvlist_t **hcprs;
	char *nm;
	uint_t hcnprs;

	err = nvlist_lookup_nvlist_array(nvl, FM_FMRI_HC_LIST, &hcprs, &hcnprs);
	if (err != 0)
		return (fmd_fmri_set_errno(EINVAL));
	err = nvlist_lookup_string(hcprs[0], FM_FMRI_HC_NAME, &nm);
	if (err != 0)
		return (fmd_fmri_set_errno(EINVAL));

	if ((thp = fmd_fmri_topo_hold(TOPO_VERSION)) == NULL)
		return (fmd_fmri_set_errno(EINVAL));
	replaced = topo_fmri_replaced(thp, nvl, &err);
	fmd_fmri_topo_rele(thp);

	return (replaced);
}

int
fmd_fmri_unusable(nvlist_t *nvl)
{
	int err, unusable;
	topo_hdl_t *thp;
	nvlist_t **hcprs;
	char *nm;
	uint_t hcnprs;

	if (nvlist_lookup_nvlist_array(nvl, FM_FMRI_HC_LIST,
	    &hcprs, &hcnprs) != 0 ||
	    nvlist_lookup_string(hcprs[0], FM_FMRI_HC_NAME, &nm) != 0)
		return (0);

	if ((thp = fmd_fmri_topo_hold(TOPO_VERSION)) == NULL)
		return (fmd_fmri_set_errno(EINVAL));
	unusable = topo_fmri_unusable(thp, nvl, &err);
	fmd_fmri_topo_rele(thp);

	return (unusable == 1 ? 1 : 0);
}

static int
auth_compare(nvlist_t *nvl1, nvlist_t *nvl2)
{
	const char *names[] = {
		FM_FMRI_AUTH_PRODUCT,
		FM_FMRI_AUTH_PRODUCT_SN,
		FM_FMRI_AUTH_CHASSIS,
		FM_FMRI_AUTH_SERVER,
		FM_FMRI_AUTH_DOMAIN,
		FM_FMRI_AUTH_HOST,
		NULL
	};
	const char **namep;
	nvlist_t *auth1 = NULL, *auth2 = NULL;

	(void) nvlist_lookup_nvlist(nvl1, FM_FMRI_AUTHORITY, &auth1);
	(void) nvlist_lookup_nvlist(nvl2, FM_FMRI_AUTHORITY, &auth2);
	if (auth1 == NULL && auth2 == NULL)
		return (0);
	if (auth1 == NULL || auth2 == NULL)
		return (1);

	for (namep = names; *namep != NULL; namep++) {
		char *val1 = NULL, *val2 = NULL;

		(void) nvlist_lookup_string(auth1, *namep, &val1);
		(void) nvlist_lookup_string(auth2, *namep, &val2);
		if (val1 == NULL && val2 == NULL)
			continue;
		if (val1 == NULL || val2 == NULL || strcmp(val1, val2) != 0)
			return (1);
	}

	return (0);
}

static int
hclist_contains(nvlist_t **erhcl, uint_t erhclsz, nvlist_t **eehcl,
    uint_t eehclsz)
{
	uint_t i;
	char *erval, *eeval;

	if (erhclsz > eehclsz || erhcl == NULL || eehcl == NULL)
		return (0);

	for (i = 0; i < erhclsz; i++) {
		(void) nvlist_lookup_string(erhcl[i], FM_FMRI_HC_NAME,
		    &erval);
		(void) nvlist_lookup_string(eehcl[i], FM_FMRI_HC_NAME,
		    &eeval);
		if (strcmp(erval, eeval) != 0)
			return (0);
		(void) nvlist_lookup_string(erhcl[i], FM_FMRI_HC_ID,
		    &erval);
		(void) nvlist_lookup_string(eehcl[i], FM_FMRI_HC_ID,
		    &eeval);
		if (strcmp(erval, eeval) != 0)
			return (0);
	}

	return (1);
}

static int
fru_compare(nvlist_t *r1, nvlist_t *r2)
{
	topo_hdl_t *thp;
	nvlist_t *f1 = NULL, *f2 = NULL;
	nvlist_t **h1 = NULL, **h2 = NULL;
	uint_t h1sz, h2sz;
	int err, rc = 1;

	if ((thp = fmd_fmri_topo_hold(TOPO_VERSION)) == NULL)
		return (fmd_fmri_set_errno(EINVAL));

	(void) topo_fmri_fru(thp, r1, &f1, &err);
	(void) topo_fmri_fru(thp, r2, &f2, &err);
	if (f1 != NULL && f2 != NULL) {
		(void) nvlist_lookup_nvlist_array(f1, FM_FMRI_HC_LIST, &h1,
		    &h1sz);
		(void) nvlist_lookup_nvlist_array(f2, FM_FMRI_HC_LIST, &h2,
		    &h2sz);
		if (h1sz == h2sz && hclist_contains(h1, h1sz, h2, h2sz) == 1)
			rc = 0;
	}

	fmd_fmri_topo_rele(thp);
	nvlist_free(f1);
	nvlist_free(f2);
	return (rc);
}

int
fmd_fmri_contains(nvlist_t *er, nvlist_t *ee)
{
	nvlist_t **erhcl, **eehcl;
	uint_t erhclsz, eehclsz;
	nvlist_t *hcsp;
	uint64_t eroff, eeoff;

	if (nvlist_lookup_nvlist_array(er, FM_FMRI_HC_LIST, &erhcl,
	    &erhclsz) != 0 || nvlist_lookup_nvlist_array(ee,
	    FM_FMRI_HC_LIST, &eehcl, &eehclsz) != 0)
		return (fmd_fmri_set_errno(EINVAL));

	/*
	 * Check ee is further down the hc tree than er; er and ee have
	 * the same auth and are on the same fru.
	 */
	if (hclist_contains(erhcl, erhclsz, eehcl, eehclsz) == 0 ||
	    auth_compare(er, ee) != 0 || fru_compare(er, ee) != 0)
		return (0);

	/*
	 * return true if er is parent of ee, or er is not a page
	 */
	if (erhclsz < eehclsz || nvlist_lookup_nvlist(er,
	    FM_FMRI_HC_SPECIFIC, &hcsp) != 0 || (nvlist_lookup_uint64(hcsp,
	    FM_FMRI_HC_SPECIFIC_OFFSET, &eroff) != 0 &&
	    nvlist_lookup_uint64(hcsp, "asru-" FM_FMRI_HC_SPECIFIC_OFFSET,
	    &eroff) != 0))
		return (1);

	/*
	 * special case for page fmri: return true if ee is the same page
	 */
	if (nvlist_lookup_nvlist(ee, FM_FMRI_HC_SPECIFIC, &hcsp) == 0 &&
	    (nvlist_lookup_uint64(hcsp, FM_FMRI_HC_SPECIFIC_OFFSET,
	    &eeoff) == 0 || nvlist_lookup_uint64(hcsp, "asru-"
	    FM_FMRI_HC_SPECIFIC_OFFSET, &eeoff) == 0) && eroff == eeoff)
		return (1);

	return (0);
}

int
fmd_fmri_service_state(nvlist_t *nvl)
{
	uint8_t version;
	int err, service_state;
	topo_hdl_t *thp;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_DEV_SCHEME_VERSION)
		return (fmd_fmri_set_errno(EINVAL));

	if ((thp = fmd_fmri_topo_hold(TOPO_VERSION)) == NULL)
		return (fmd_fmri_set_errno(EINVAL));
	err = 0;
	service_state = topo_fmri_service_state(thp, nvl, &err);
	fmd_fmri_topo_rele(thp);

	if (err != 0)
		return (FMD_SERVICE_STATE_UNKNOWN);
	else
		return (service_state);
}
