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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *  Subroutines used by the i86pc Generic Topology Enumerator
 */

#include <sys/types.h>
#include <strings.h>
#include <deflt.h>
#include <fcntl.h>
#include <unistd.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <sys/devfm.h>
#include <sys/pci.h>
#include <sys/systeminfo.h>
#include <sys/fm/protocol.h>
#include <sys/utsname.h>
#include <sys/smbios.h>
#include <sys/smbios_impl.h>
#include <x86pi_impl.h>


static const topo_pgroup_info_t sys_pgroup = {
	TOPO_PGROUP_SYSTEM,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t auth_pgroup = {
	FM_FMRI_AUTHORITY,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};


/*
 * Free hcfmri strings.
 */
void
x86pi_hcfmri_info_fini(topo_mod_t *mod, x86pi_hcfmri_t *hc)
{
	if (hc->hc_name != NULL)
		topo_mod_strfree(mod, (char *)hc->hc_name);
	if (hc->manufacturer != NULL)
		topo_mod_strfree(mod, (char *)hc->manufacturer);
	if (hc->product != NULL)
		topo_mod_strfree(mod, (char *)hc->product);
	if (hc->version != NULL)
		topo_mod_strfree(mod, (char *)hc->version);
	if (hc->serial_number != NULL)
		topo_mod_strfree(mod, (char *)hc->serial_number);
	if (hc->asset_tag != NULL)
		topo_mod_strfree(mod, (char *)hc->asset_tag);
	if (hc->location != NULL)
		topo_mod_strfree(mod, (char *)hc->location);
	if (hc->part_number != NULL)
		topo_mod_strfree(mod, (char *)hc->part_number);
}


/*
 * Get the server hostname (the ID as far as the topo authority is
 * concerned) from sysinfo and return a copy to the caller.
 *
 * The string must be freed with topo_mod_strfree()
 */
char *
x86pi_get_serverid(topo_mod_t *mod)
{
	int result;
	char hostname[MAXNAMELEN];

	topo_mod_dprintf(mod, "x86pi_get_serverid\n");

	result = sysinfo(SI_HOSTNAME, hostname, sizeof (hostname));
	/* Everything is freed up and it's time to return the platform-id */
	if (result == -1) {
		return (NULL);
	}
	topo_mod_dprintf(mod, "x86pi_get_serverid: hostname = %s\n", hostname);

	return (topo_mod_strdup(mod, hostname));
}


/*
 * Get copy of SMBIOS.
 */
smbios_hdl_t *
x86pi_smb_open(topo_mod_t *mod)
{
	smbios_hdl_t *smb_hdl;
	char *f = "x86pi_smb_open";

	topo_mod_dprintf(mod, "%s\n", f);

	smb_hdl = topo_mod_smbios(mod);
	if (smb_hdl == NULL) {
		topo_mod_dprintf(mod, "%s: failed to load SMBIOS\n", f);
		return (NULL);
	}

	return (smb_hdl);
}


/*
 * Go through the smbios structures looking for a type. Fill in
 * the structure count as well as the id(s) of the struct types.
 */
void
x86pi_smb_strcnt(smbios_hdl_t *shp, smbs_cnt_t *stype)
{
	const smb_struct_t *sp = shp->sh_structs;
	int nstructs = shp->sh_nstructs;
	int i, cnt;

	for (i = 0, cnt = 0; i < nstructs; i++, sp++) {
		if (sp->smbst_hdr->smbh_type == stype->type) {
			stype->ids[cnt].node = NULL;
			stype->ids[cnt].id = sp->smbst_hdr->smbh_hdl;
			cnt++;
		}
	}

	stype->count = cnt;
}


/*
 * Calculate the authority information for a node.  Inherit the data if
 * possible, but always create an appropriate property group.
 */
int
x86pi_set_auth(topo_mod_t *mod, x86pi_hcfmri_t *hcfmri, tnode_t *t_parent,
    tnode_t *t_node)
{
	int 		result;
	int		err;
	int		is_chassis = 0;
	int		chassis_instance = 0;
	nvlist_t	*auth;
	char		*val = NULL;
	char		*prod = NULL;
	char		*psn = NULL;
	char		*csn = NULL;
	char		*server = NULL;
	char		*f = "x86pi_set_auth";

	if (mod == NULL || t_parent == NULL || t_node == NULL) {
		return (-1);
	}

	result = topo_pgroup_create(t_node, &auth_pgroup, &err);
	if (result != 0 && err != ETOPO_PROP_DEFD) {
		/*
		 * We failed to create the property group and it was not
		 * already defined.  Set the err code and return failure.
		 */
		(void) topo_mod_seterrno(mod, err);
		return (-1);
	}

	/* Get the authority information already available from the parent */
	auth = topo_mod_auth(mod, t_parent);

	/* Determnine if this is a chassis node and set it's instance */
	if ((strlen(hcfmri->hc_name) == strlen(CHASSIS)) &&
	    strncmp(hcfmri->hc_name, CHASSIS, strlen(CHASSIS)) == 0) {
		is_chassis = 1;
		chassis_instance = hcfmri->instance;
	}

	/*
	 * Set the authority data, inheriting it if possible, but creating it
	 * if necessary.
	 */

	/* product-id */
	result = topo_prop_inherit(t_node, FM_FMRI_AUTHORITY,
	    FM_FMRI_AUTH_PRODUCT, &err);
	if (result != 0 && err != ETOPO_PROP_DEFD) {
		result = nvlist_lookup_string(auth, FM_FMRI_AUTH_PRODUCT,
		    &prod);
		if (result != 0 || prod == NULL) {
			/*
			 * No product information in the parent node or auth
			 * list. Use the product information in the hcfrmi
			 * struct.
			 */
			prod = (char *)hcfmri->product;
			if (prod == NULL) {
				topo_mod_dprintf(mod, "%s: product name not "
				    "found for %s node\n", f, hcfmri->hc_name);
			}
		}

		/*
		 * We continue even if the product information is not available
		 * to enumerate as much as possible.
		 */
		if (prod != NULL) {
			result = topo_prop_set_string(t_node, FM_FMRI_AUTHORITY,
			    FM_FMRI_AUTH_PRODUCT, TOPO_PROP_IMMUTABLE, prod,
			    &err);
			if (result != 0) {
				/* Preserve the error and continue */
				(void) topo_mod_seterrno(mod, err);
				topo_mod_dprintf(mod, "%s: failed to set "
				    "property %s (%d) : %s\n", f,
				    FM_FMRI_AUTH_PRODUCT, err,
				    topo_strerror(err));
			}
		}
	}

	/* product-sn */
	result = topo_prop_inherit(t_node, FM_FMRI_AUTHORITY,
	    FM_FMRI_AUTH_PRODUCT_SN, &err);
	if (result != 0 && err != ETOPO_PROP_DEFD) {
		result = nvlist_lookup_string(auth, FM_FMRI_AUTH_PRODUCT_SN,
		    &psn);
		if (result != 0 || psn == NULL) {
			/*
			 * No product-sn information in the parent node or auth
			 * list.
			 */
			topo_mod_dprintf(mod, "%s: psn not found\n", f);
		} else {
			/*
			 * We continue even if the product-sn information is
			 * not available to enumerate as much as possible.
			 */
			result = topo_prop_set_string(t_node, FM_FMRI_AUTHORITY,
			    FM_FMRI_AUTH_PRODUCT_SN, TOPO_PROP_IMMUTABLE, psn,
			    &err);
			if (result != 0) {
				/* Preserve the error and continue */
				(void) topo_mod_seterrno(mod, err);
				topo_mod_dprintf(mod, "%s: failed to "
				    "set property %s (%d) : %s\n", f,
				    FM_FMRI_AUTH_PRODUCT_SN, err,
				    topo_strerror(err));
			}
		}
	}

	/* chassis-id */
	if (is_chassis == 0 || (is_chassis == 1 && chassis_instance == 0)) {
		/* either not a chassis node, or chassis #0 */
		result = topo_prop_inherit(t_node, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_CHASSIS, &err);
	} else {
		/* chassis 'n' in a >1 chassis system */
		result = err = -1;
	}
	if (result != 0 && err != ETOPO_PROP_DEFD) {
		if (is_chassis == 0) {
			result = nvlist_lookup_string(auth,
			    FM_FMRI_AUTH_CHASSIS, &csn);
			if (result != 0 || csn == NULL) {
				/*
				 * No chassis information in the parent
				 * node or auth list.
				 */
				topo_mod_dprintf(mod,
				    "%s: csn name not found\n", f);
			}
		} else {
			/*
			 * So as not to blindly set the chassis-id to
			 * chassis #0's serial number.
			 */
			csn = val = topo_mod_strdup(mod, hcfmri->serial_number);
		}

		/*
		 * We continue even if the chassis information is not available
		 * to enumerate as much as possible.
		 */
		if (csn != NULL) {
			if (is_chassis == 1)
				result = topo_prop_set_string(t_node,
				    FM_FMRI_AUTHORITY, FM_FMRI_AUTH_CHASSIS,
				    TOPO_PROP_MUTABLE, csn, &err);
			else
				result = topo_prop_set_string(t_node,
				    FM_FMRI_AUTHORITY, FM_FMRI_AUTH_CHASSIS,
				    TOPO_PROP_IMMUTABLE, csn, &err);

			if (result != 0) {
				/* Preserve the error and continue */
				(void) topo_mod_seterrno(mod, err);
				topo_mod_dprintf(mod, "%s: failed to "
				    "set property %s (%d) : %s\n", f,
				    FM_FMRI_AUTH_CHASSIS, err,
				    topo_strerror(err));
			}
		}

		if (val != NULL) {
			topo_mod_strfree(mod, val);
			val = NULL;
		}
	}

	/* server-id */
	result = topo_prop_inherit(t_node, FM_FMRI_AUTHORITY,
	    FM_FMRI_AUTH_SERVER, &err);
	if (result != 0 && err != ETOPO_PROP_DEFD) {
		result = nvlist_lookup_string(auth, FM_FMRI_AUTH_SERVER,
		    &server);
		if (result != 0 || server == NULL) {
			/*
			 * No server information in the parent node or auth
			 * list.  Find the server information in hostname.
			 */
			server = val = x86pi_get_serverid(mod);
			if (server == NULL) {
				topo_mod_dprintf(mod, "%s: server "
				    "name not found for %s node\n", f,
				    hcfmri->hc_name);
			}
		}

		/*
		 * We continue even if the server information is not available
		 * to enumerate as much as possible.
		 */
		if (server != NULL) {
			result = topo_prop_set_string(t_node, FM_FMRI_AUTHORITY,
			    FM_FMRI_AUTH_SERVER, TOPO_PROP_IMMUTABLE, server,
			    &err);
			if (result != 0) {
				/* Preserve the error and continue */
				(void) topo_mod_seterrno(mod, err);
				topo_mod_dprintf(mod, "%s: failed to "
				    "set property %s (%d) : %s\n", f,
				    FM_FMRI_AUTH_SERVER, err,
				    topo_strerror(err));
			}
		}

		if (val != NULL)
			topo_mod_strfree(mod, val);
	}

	nvlist_free(auth);

	return (0);
}


/*
 * Calculate a generic FRU for the given node.  If the node is not a FRU,
 * then inherit the FRU data from the nodes parent.
 */
int
x86pi_set_frufmri(topo_mod_t *mod, x86pi_hcfmri_t *hcfmri, tnode_t *t_parent,
    tnode_t *t_node, int flag)
{
	int		result;
	int		err;

	nvlist_t	*auth = NULL;
	nvlist_t	*frufmri = NULL;

	if (t_node == NULL || mod == NULL) {
		return (-1);
	}

	/*
	 * Determine if this node is a FRU
	 */
	if (!(flag & X86PI_ENUM_FRU)) {
		/* This node is not a FRU.  Inherit from parent and return */
		(void) topo_node_fru_set(t_node, NULL, 0, &result);
		return (0);
	}

	/*
	 * This node is a FRU.  Create an FMRI.
	 */
	auth	= topo_mod_auth(mod, t_parent);
	frufmri	= topo_mod_hcfmri(mod, t_parent, FM_HC_SCHEME_VERSION,
	    hcfmri->hc_name, hcfmri->instance, NULL, auth,
	    hcfmri->part_number, hcfmri->version, hcfmri->serial_number);
	if (frufmri == NULL) {
		topo_mod_dprintf(mod, "failed to create FRU: %s\n",
		    topo_strerror(topo_mod_errno(mod)));
	}
	nvlist_free(auth);

	/* Set the FRU, whether NULL or not */
	result = topo_node_fru_set(t_node, frufmri, 0, &err);
	if (result != 0)  {
		(void) topo_mod_seterrno(mod, err);
	}
	nvlist_free(frufmri);

	return (result);
}


/*
 * Set the label for a topo node.
 */
int
x86pi_set_label(topo_mod_t *mod, const char *label, const char *name,
    tnode_t *t_node)
{
	int	result;
	int	err;

	if (mod == NULL) {
		return (-1);
	}

	/*
	 * Set the label for this topology node.
	 * Note that a NULL label will inherit the label from topology
	 * node's parent.
	 */
	result = topo_node_label_set(t_node, (char *)label, &err);
	if (result != 0) {
		(void) topo_mod_seterrno(mod, err);
		topo_mod_dprintf(mod, "x86pi_set_label: failed with label %s "
		    "on %s node: %s\n", (label == NULL ? "NULL" : label),
		    name, topo_strerror(err));
	}

	return (result);
}


/*
 * Calculate the system information for a node.  Inherit the data if
 * possible, but always create an appropriate property group.
 */
int
x86pi_set_system(topo_mod_t *mod, tnode_t *t_node)
{
	int		result;
	int		err;
	struct utsname	uts;
	char		isa[MAXNAMELEN];

	if (mod == NULL || t_node == NULL) {
		return (-1);
	}

	result = topo_pgroup_create(t_node, &sys_pgroup, &err);
	if (result != 0 && err != ETOPO_PROP_DEFD) {
		/*
		 * We failed to create the property group and it was not
		 * already defined.  Set the err code and return failure.
		 */
		(void) topo_mod_seterrno(mod, err);
		return (-1);
	}

	result = topo_prop_inherit(t_node, TOPO_PGROUP_SYSTEM, TOPO_PROP_ISA,
	    &err);
	if (result != 0 && err != ETOPO_PROP_DEFD) {
		isa[0] = '\0';
		result = sysinfo(SI_ARCHITECTURE, isa, sizeof (isa));
		if (result == -1) {
			/* Preserve the error and continue */
			topo_mod_dprintf(mod, "x86pi_set_system: failed to "
			    "read SI_ARCHITECTURE: %d\n", errno);
		}
		if (strnlen(isa, MAXNAMELEN) > 0) {
			result = topo_prop_set_string(t_node,
			    TOPO_PGROUP_SYSTEM, TOPO_PROP_ISA,
			    TOPO_PROP_IMMUTABLE, isa, &err);
			if (result != 0) {
				/* Preserve the error and continue */
				(void) topo_mod_seterrno(mod, err);
				topo_mod_dprintf(mod,
				    "x86pi_set_auth: failed to "
				    "set property %s (%d) : %s\n",
				    TOPO_PROP_ISA, err, topo_strerror(err));
			}
		}
	}

	result = topo_prop_inherit(t_node, TOPO_PGROUP_SYSTEM,
	    TOPO_PROP_MACHINE, &err);
	if (result != 0 && err != ETOPO_PROP_DEFD) {
		result = uname(&uts);
		if (result == -1) {
			/* Preserve the error and continue */
			(void) topo_mod_seterrno(mod, errno);
			topo_mod_dprintf(mod, "x86pi_set_system: failed to "
			    "read uname: %d\n", errno);
		}
		if (strnlen(uts.machine, sizeof (uts.machine)) > 0) {
			result = topo_prop_set_string(t_node,
			    TOPO_PGROUP_SYSTEM, TOPO_PROP_MACHINE,
			    TOPO_PROP_IMMUTABLE, uts.machine, &err);
			if (result != 0) {
				/* Preserve the error and continue */
				(void) topo_mod_seterrno(mod, err);
				topo_mod_dprintf(mod,
				    "x86pi_set_auth: failed to "
				    "set property %s (%d) : %s\n",
				    TOPO_PROP_MACHINE, err, topo_strerror(err));
			}
		}
	}

	return (0);
}

/*
 * All the checks for compatibility are done within the kernel where the
 * ereport generators are. They'll determine first if there's a problem
 * and the topo enum will follow suit. The /dev/fm ioclt returns the value
 * of the x86gentopo_legacy kernel variable which determines if this platform
 * will provide an x86 generic topo or legacy topo enumeration.
 */
/* ARGSUSED */
int
x86pi_check_comp(topo_mod_t *mod, smbios_hdl_t *shp)
{
	int rv;
	int fd;
	int32_t legacy;
	nvlist_t *nvl = NULL;
	fm_ioc_data_t fid;
	char *ibuf = NULL, *obuf = NULL;
	size_t insz = 0, outsz = 0;
	char *f = "x86pi_check_comp";

	/* open /dev/fm */
	fd = open("/dev/fm", O_RDONLY);
	if (fd < 0) {
		topo_mod_dprintf(mod, "%s: failed to open /dev/fm.\n", f);
		return (X86PI_NONE);
	}

	/* set up buffers and ioctl data structure */
	outsz = FM_IOC_MAXBUFSZ;
	obuf = topo_mod_alloc(mod, outsz);
	if (obuf == NULL) {
		perror("umem_alloc");
		return (X86PI_NONE);
	}

	fid.fid_version = 1;
	fid.fid_insz = insz;
	fid.fid_inbuf = ibuf;
	fid.fid_outsz = outsz;
	fid.fid_outbuf = obuf;

	/* send the ioctl to /dev/fm to retrieve legacy variable */
	rv = ioctl(fd, FM_IOC_GENTOPO_LEGACY, &fid);
	if (rv < 0) {
		topo_mod_dprintf(mod, "%s: ioctl to /dev/fm failed", f);
		perror("fm_ioctl");
		(void) close(fd);
		return (X86PI_NONE);
	}
	(void) close(fd);

	(void) nvlist_unpack(fid.fid_outbuf, fid.fid_outsz, &nvl, 0);
	(void) nvlist_lookup_int32(nvl, FM_GENTOPO_LEGACY, &legacy);

	nvlist_free(nvl);
	topo_mod_free(mod, obuf, outsz);

	if (legacy == 1) {
		/* legacy kernel variable set; will do the same */
		return (X86PI_NONE);
	}

	/* legacy kernel variable not set; generic topo enum */
	return (X86PI_FULL);
}

const char *
x86pi_cleanup_smbios_str(topo_mod_t *mod, const char *begin, int str_type)
{
	char buf[MAXNAMELEN];
	const char *end, *cp;
	char *pp;
	char c;
	int i;

	end = begin + strlen(begin);

	while (begin < end && isspace(*begin))
		begin++;
	while (begin < end && isspace(*(end - 1)))
		end--;

	if (begin >= end)
		return (NULL);

	cp = begin;
	for (i = 0; i < MAXNAMELEN - 1; i++) {
		if (cp >= end)
			break;
		c = *cp;
		if (str_type == LABEL) {
			if (!isprint(c))
				buf[i] = '-';
			else
				buf[i] = c;
		} else {
			if (c == ':' || c == '=' || c == '/' ||
			    isspace(c) || !isprint(c))
				buf[i] = '-';
			else
				buf[i] = c;
		}
		cp++;
	}
	buf[i] = 0;

	pp = topo_mod_strdup(mod, buf);

	if (str_type == LABEL)
		topo_mod_strfree(mod, (char *)begin);

	return (pp);
}

/*
 * Return Bus/Dev/Func from "reg" devinfo property.
 */
uint16_t
x86pi_bdf(topo_mod_t *mod, di_node_t node)
{
	int *val;

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "reg", &val) < 0) {
		topo_mod_dprintf(mod, "couldn't get \"reg\" prop: %s.\n",
		    strerror(errno));
		return ((uint16_t)-1);
	}

	return (uint16_t)((*val & PCI_REG_BDFR_M) >> PCI_REG_FUNC_SHIFT);
}

/*
 * Return PHY from "sata-phy" devinfo proporty.
 */
int
x86pi_phy(topo_mod_t *mod, di_node_t node)
{
	int *phy;

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "sata-phy", &phy) < 0) {
		topo_mod_dprintf(mod, "couldn't get \"sata-phy\" prop: %s.\n",
		    strerror(errno));
		return (-1);
	}

	return (*phy);
}
