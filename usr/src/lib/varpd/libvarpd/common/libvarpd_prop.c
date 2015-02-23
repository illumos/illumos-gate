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
 * Copyright 2019 Joyent, Inc.
 */

/*
 * varpd property management
 */

#include <libvarpd_impl.h>
#include <errno.h>
#include <strings.h>
#include <sys/mac.h>
#include <umem.h>

typedef struct varpd_prop_info {
	varpd_impl_t		*vprop_vip;
	varpd_instance_t	*vprop_instance;
	uint_t			vprop_type;
	uint_t			vprop_prot;
	uint32_t		vprop_defsize;
	uint32_t		vprop_psize;
	char			vprop_name[LIBVARPD_PROP_NAMELEN];
	uint8_t			vprop_default[LIBVARPD_PROP_SIZEMAX];
	uint8_t			vprop_poss[LIBVARPD_PROP_SIZEMAX];
} varpd_prop_info_t;

/* Internal Properties */
static int varpd_nintprops = 1;
static const char *varpd_intprops[] = {
	"search"
};

static int
libvarpd_prop_get_search(varpd_prop_info_t *infop, void *buf, uint32_t *sizep)
{
	varpd_plugin_t *vpp = infop->vprop_instance->vri_plugin;
	size_t nlen;

	nlen = strlen(vpp->vpp_name) + 1;
	if (nlen > *sizep)
		return (EOVERFLOW);
	*sizep = nlen;
	(void) strlcpy(buf, vpp->vpp_name, *sizep);
	return (0);
}

void
libvarpd_prop_set_name(varpd_prop_handle_t *phdl, const char *name)
{
	varpd_prop_info_t *infop = (varpd_prop_info_t *)phdl;
	(void) strlcpy(infop->vprop_name, name, OVERLAY_PROP_NAMELEN);
}

void
libvarpd_prop_set_prot(varpd_prop_handle_t *phdl, overlay_prop_prot_t perm)
{
	varpd_prop_info_t *infop = (varpd_prop_info_t *)phdl;
	infop->vprop_prot = perm;
}

void
libvarpd_prop_set_type(varpd_prop_handle_t *phdl, overlay_prop_type_t type)
{
	varpd_prop_info_t *infop = (varpd_prop_info_t *)phdl;
	infop->vprop_type = type;
}

int
libvarpd_prop_set_default(varpd_prop_handle_t *phdl, void *buf, ssize_t len)
{
	varpd_prop_info_t *infop = (varpd_prop_info_t *)phdl;

	if (len > LIBVARPD_PROP_SIZEMAX)
		return (E2BIG);

	if (len < 0)
		return (EOVERFLOW);

	bcopy(buf, infop->vprop_default, len);
	infop->vprop_defsize = len;
	return (0);
}

void
libvarpd_prop_set_nodefault(varpd_prop_handle_t *phdl)
{
	varpd_prop_info_t *infop = (varpd_prop_info_t *)phdl;

	infop->vprop_default[0] = '\0';
	infop->vprop_defsize = 0;
}

void
libvarpd_prop_set_range_uint32(varpd_prop_handle_t *phdl, uint32_t min,
    uint32_t max)
{
	varpd_prop_info_t *infop = (varpd_prop_info_t *)phdl;
	mac_propval_range_t *rangep = (mac_propval_range_t *)infop->vprop_poss;

	if (rangep->mpr_count != 0 && rangep->mpr_type != MAC_PROPVAL_UINT32)
		return;

	if (infop->vprop_psize + sizeof (mac_propval_uint32_range_t) >
	    sizeof (infop->vprop_poss))
		return;

	infop->vprop_psize += sizeof (mac_propval_uint32_range_t);
	rangep->mpr_count++;
	rangep->mpr_type = MAC_PROPVAL_UINT32;
	rangep->u.mpr_uint32[rangep->mpr_count-1].mpur_min = min;
	rangep->u.mpr_uint32[rangep->mpr_count-1].mpur_max = max;
}

void
libvarpd_prop_set_range_str(varpd_prop_handle_t *phdl, const char *str)
{
	varpd_prop_info_t *infop = (varpd_prop_info_t *)phdl;
	size_t len = strlen(str) + 1; /* Account for a null terminator */
	mac_propval_range_t *rangep = (mac_propval_range_t *)infop->vprop_poss;
	mac_propval_str_range_t *pstr = &rangep->u.mpr_str;

	if (rangep->mpr_count != 0 && rangep->mpr_type != MAC_PROPVAL_STR)
		return;

	if (infop->vprop_psize + len > sizeof (infop->vprop_poss))
		return;

	rangep->mpr_count++;
	rangep->mpr_type = MAC_PROPVAL_STR;
	(void) strlcpy((char *)&pstr->mpur_data[pstr->mpur_nextbyte], str,
	    sizeof (infop->vprop_poss) - infop->vprop_psize);
	pstr->mpur_nextbyte += len;
	infop->vprop_psize += len;
}

int
libvarpd_prop_handle_alloc(varpd_handle_t *vph, varpd_instance_handle_t *inst,
    varpd_prop_handle_t **phdlp)
{
	varpd_prop_info_t *infop;

	infop = umem_alloc(sizeof (varpd_prop_info_t), UMEM_DEFAULT);
	if (infop == NULL)
		return (ENOMEM);

	bzero(infop, sizeof (varpd_prop_info_t));
	infop->vprop_vip = (varpd_impl_t *)vph;
	infop->vprop_instance = (varpd_instance_t *)inst;

	*phdlp = (varpd_prop_handle_t *)infop;
	return (0);
}

void
libvarpd_prop_handle_free(varpd_prop_handle_t *phdl)
{
	umem_free(phdl, sizeof (varpd_prop_info_t));
}

int
libvarpd_prop_nprops(varpd_instance_handle_t *ihdl, uint_t *np)
{
	int ret;
	varpd_instance_t *instp = (varpd_instance_t *)ihdl;

	ret = instp->vri_plugin->vpp_ops->vpo_nprops(instp->vri_private, np);
	if (ret != 0)
		return (ret);
	*np += varpd_nintprops;
	return (0);
}

static int
libvarpd_prop_info_fill_int_cb(varpd_handle_t *handle, const char *name,
    void *arg)
{
	varpd_prop_handle_t *vph = arg;
	libvarpd_prop_set_range_str(vph, name);
	return (0);
}

static int
libvarpd_prop_info_fill_int(varpd_prop_handle_t *vph, uint_t propid)
{
	varpd_prop_info_t *infop = (varpd_prop_info_t *)vph;
	if (propid >= varpd_nintprops)
		abort();
	libvarpd_prop_set_name(vph, varpd_intprops[0]);
	libvarpd_prop_set_prot(vph, OVERLAY_PROP_PERM_READ);
	libvarpd_prop_set_type(vph, OVERLAY_PROP_T_STRING);
	libvarpd_prop_set_nodefault(vph);
	(void) libvarpd_plugin_walk(
	    (varpd_handle_t *)infop->vprop_instance->vri_impl,
	    libvarpd_prop_info_fill_int_cb, vph);
	return (0);
}

int
libvarpd_prop_info_fill(varpd_prop_handle_t *phdl, uint_t propid)
{
	varpd_prop_info_t *infop = (varpd_prop_info_t *)phdl;
	varpd_instance_t *instp = infop->vprop_instance;
	mac_propval_range_t *rangep = (mac_propval_range_t *)infop->vprop_poss;

	infop->vprop_psize = sizeof (mac_propval_range_t);

	bzero(rangep, sizeof (mac_propval_range_t));
	if (propid < varpd_nintprops) {
		return (libvarpd_prop_info_fill_int(phdl, propid));
	} else {
		varpd_plugin_t *vpp = instp->vri_plugin;
		return (vpp->vpp_ops->vpo_propinfo(instp->vri_private,
		    propid - varpd_nintprops, phdl));
	}
}

int
libvarpd_prop_info(varpd_prop_handle_t *phdl, const char **namep,
    uint_t *typep, uint_t *protp, const void **defp, uint32_t *sizep,
    const mac_propval_range_t **possp)
{
	varpd_prop_info_t *infop = (varpd_prop_info_t *)phdl;
	if (namep != NULL)
		*namep = infop->vprop_name;
	if (typep != NULL)
		*typep = infop->vprop_type;
	if (protp != NULL)
		*protp = infop->vprop_prot;
	if (defp != NULL)
		*defp = infop->vprop_default;
	if (sizep != NULL)
		*sizep = infop->vprop_psize;
	if (possp != NULL)
		*possp = (mac_propval_range_t *)infop->vprop_poss;
	return (0);
}

int
libvarpd_prop_get(varpd_prop_handle_t *phdl, void *buf, uint32_t *sizep)
{
	varpd_prop_info_t *infop = (varpd_prop_info_t *)phdl;
	varpd_instance_t *instp = infop->vprop_instance;

	if (infop->vprop_name[0] == '\0')
		return (EINVAL);

	if (strcmp(varpd_intprops[0], infop->vprop_name) == 0) {
		/* search property */
		return (libvarpd_prop_get_search(infop, buf, sizep));
	}

	return (instp->vri_plugin->vpp_ops->vpo_getprop(instp->vri_private,
	    infop->vprop_name, buf, sizep));
}

int
libvarpd_prop_set(varpd_prop_handle_t *phdl, const void *buf, uint32_t size)
{
	int i;
	varpd_prop_info_t *infop = (varpd_prop_info_t *)phdl;
	varpd_instance_t *instp = infop->vprop_instance;

	if (infop->vprop_name[0] == '\0')
		return (EINVAL);

	for (i = 0; i < varpd_nintprops; i++) {
		if (strcmp(infop->vprop_name, varpd_intprops[i]) == 0) {
			return (EPERM);
		}
	}

	return (instp->vri_plugin->vpp_ops->vpo_setprop(instp->vri_private,
	    infop->vprop_name, buf, size));
}

void
libvarpd_prop_door_convert(const varpd_prop_handle_t *phdl,
    varpd_client_propinfo_arg_t *vcfap)
{
	const varpd_prop_info_t *infop = (const varpd_prop_info_t *)phdl;

	vcfap->vcfa_type = infop->vprop_type;
	vcfap->vcfa_prot = infop->vprop_prot;
	vcfap->vcfa_defsize = infop->vprop_defsize;
	vcfap->vcfa_psize = infop->vprop_psize;
	bcopy(infop->vprop_name, vcfap->vcfa_name, LIBVARPD_PROP_NAMELEN);
	bcopy(infop->vprop_default, vcfap->vcfa_default, LIBVARPD_PROP_SIZEMAX);
	bcopy(infop->vprop_poss, vcfap->vcfa_poss, LIBVARPD_PROP_SIZEMAX);
}
