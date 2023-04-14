/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

#include <fm/fmd_fmri.h>
#include <fm/libtopo.h>
#include <strings.h>

ssize_t
fmd_fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	int err;
	ssize_t len;
	topo_hdl_t *thp;
	char *str;

	if ((thp = fmd_fmri_topo_hold(TOPO_VERSION)) == NULL)
		return (fmd_fmri_set_errno(EINVAL));

	if (topo_fmri_nvl2str(thp, nvl, &str, &err) != 0) {
		fmd_fmri_topo_rele(thp);
		return (fmd_fmri_set_errno(EINVAL));
	}

	len = snprintf(buf, buflen, "%s", str);

	topo_hdl_strfree(thp, str);
	fmd_fmri_topo_rele(thp);

	return (len);
}

/*
 * fmd_fmri_present() is called by fmadm to determine if a faulty resource
 * is still present in the system. We just return true for now, but could
 * extend this in the future to look at PCI configuration space.
 */
int
fmd_fmri_present(nvlist_t *nvl)
{
	return (1);
}

/*
 * fmd_fmri_replaced() is called by fmadm to determine if a resource has been
 * replaced. We always return unknown for now but this should be extended in
 * the future as it is possible to determine if devices have been replaced by,
 * for instance, checking the serial number.
 */
int
fmd_fmri_replaced(nvlist_t *nvl)
{
	return (FMD_OBJ_STATE_UNKNOWN);
}

/*
 * fmd_fmri_unusable() is called by fmadm to determine if a faulty ASRU
 * is unusable.
 */
int
fmd_fmri_unusable(nvlist_t *nvl)
{
	topo_hdl_t *thp;
	int unusable, err;

	if ((thp = fmd_fmri_topo_hold(TOPO_VERSION)) == NULL)
		return (fmd_fmri_set_errno(EINVAL));
	unusable = topo_fmri_unusable(thp, nvl, &err);
	fmd_fmri_topo_rele(thp);

	if (err == ETOPO_METHOD_NOTSUP)
		return (0);

	return (unusable);
}

int
fmd_fmri_init(void)
{
	return (0);
}

void
fmd_fmri_fini(void)
{
}
