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
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>

#include <sys/ib/clients/eoib/eib_impl.h>

/*
 * Definitions private to this file
 */
ib_gid_t eib_reserved_gid;

uint8_t eib_zero_mac[] = {
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0
};

uint8_t eib_broadcast_mac[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

int eib_setbit_mod67[] = {
	-1,  0,  1, 39,  2, 15, 40, 23,
	3,  12, 16, 59, 41, 19, 24, 54,
	4,  -1, 13, 10, 17, 62, 60, 28,
	42, 30, 20, 51, 25, 44, 55, 47,
	5,  32, -1, 38, 14, 22, 11, 58,
	18, 53, 63,  9, 61, 27, 29, 50,
	43, 46, 31, 37, 21, 57, 52,  8,
	26, 49, 45, 36, 56,  7, 48, 35,
	6,  34, 33
};

char *eib_pvt_props[] = {
	EIB_DLPROP_GW_EPORT_STATE,
	EIB_DLPROP_HCA_GUID,
	EIB_DLPROP_PORT_GUID,
	NULL
};

#define	eib_prop_get_and_test(inst, dp, propname, propval)		\
{                                                                       \
	(propval) = ddi_prop_get_int(DDI_DEV_T_ANY, (dp),               \
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, (propname), -1);      \
	if ((propval) == -1) {                                          \
		EIB_DPRINTF_WARN((inst), "eib_get_props: "		\
		    "ddi_prop_get_int() could not find "		\
		    "property '%s'", (propname));			\
		goto get_props_fail;                                    \
	}                                                               \
}

#define	eib_prop64_get_and_test(inst, dp, propname, propval)		\
{                                                                       \
	(propval) = ddi_prop_get_int64(DDI_DEV_T_ANY, (dp),             \
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, (propname), -1);      \
	if ((propval) == -1) {                                          \
		EIB_DPRINTF_WARN((inst), "eib_get_props: "		\
		    "ddi_prop_get_int64() could not find "		\
		    "property '%s'", (propname));			\
		goto get_props_fail;                                    \
	}                                                               \
}

#define	eib_propstr_get_and_test(inst, dp, propname, propval_p)		\
{                                                                       \
	int rv;                                                         \
									\
	*(propval_p) = NULL;                                            \
									\
	rv = ddi_prop_lookup_string(DDI_DEV_T_ANY, (dp),                \
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, (propname),           \
	    (propval_p));                                               \
	if (rv != DDI_PROP_SUCCESS) {                                   \
		EIB_DPRINTF_WARN((inst), "eib_get_props: "		\
		    "ddi_prop_lookup_string() could not find "		\
		    "property '%s'", (propname));			\
		goto get_props_fail;                                    \
	}                                                               \
}

/*
 * HW/FW workarounds
 */

/*
 * 1. Verification of descriptor list length in the received packets is
 *    disabled, since experimentation shows that BX does not set the desc
 *    list length correctly. True for EoIB nexus as well.
 */
int eib_wa_no_desc_list_len = 1;

/*
 * 2. LSO/Checksum_Offload for EoIB packets does not seem to be supported
 *    currently, so we'll disable both temporarily.
 */
int eib_wa_no_cksum_offload = 1;
int eib_wa_no_lso = 1;

/*
 * 3. The "multicast entry" types are not clearly defined in the spec
 *    at the moment.  The current BX software/firmware appears to ignore
 *    the type of the context table entries, so we will treat these
 *    addresses just like regular vnic addresses.
 */
int eib_wa_no_mcast_entries = 1;

/*
 * 4. VHUB updates from the gateways provide us with destination LIDs,
 *    and we will hand-create these address vectors.
 */
int eib_wa_no_av_discover = 1;

/*
 * 5. The older BX software does not seem to set the VP flag correctly
 *    in the login acknowledgements even when it successfully allocates
 *    a vlan, so we will ignore it for now.
 */
int eib_wa_no_good_vp_flag = 1;

/*
 * 6. Each vhub table is expected to carry a checksum at the end to
 *    verify the contents of the received vhub table. The current BX
 *    software/firmware does not seem to fill this field with the
 *    correct value (and/or the spec description is ambiguous). We
 *    will ignore the vhub table checksum verification for now.
 */
int eib_wa_no_good_vhub_cksum = 1;

int
eib_get_props(eib_t *ss)
{
	int val;
	int64_t val64;
	char *str;
	clock_t gw_ka_usecs;
	clock_t vnic_ka_usecs;

	ss->ei_gw_props = kmem_zalloc(sizeof (eib_gw_props_t), KM_SLEEP);
	ss->ei_props = kmem_zalloc(sizeof (eib_props_t), KM_SLEEP);

	mutex_init(&ss->ei_gw_props->pp_gw_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * The interface speed is currently set to 10Gb/s, since we don't
	 * have a way yet to figure this virtual-wire specific data from
	 * the gateway.  The rest of the properties are handed over to us
	 * by the EoIB nexus.
	 */
	ss->ei_props->ep_ifspeed = 10000000000;

	eib_prop64_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_HCA_GUID, val64);
	ss->ei_props->ep_hca_guid = (ib_guid_t)val64;

	eib_prop64_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_GW_SYS_GUID, val64);
	ss->ei_gw_props->pp_gw_system_guid = (ib_guid_t)val64;

	eib_prop64_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_GW_GUID, val64);
	ss->ei_gw_props->pp_gw_guid = (ib_guid_t)val64;

	eib_prop64_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_GW_SN_PREFIX, val64);
	ss->ei_gw_props->pp_gw_sn_prefix = (ib_sn_prefix_t)val64;

	eib_prop_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_GW_ADV_PERIOD, val);
	ss->ei_gw_props->pp_gw_adv_period = (uint_t)val;

	eib_prop_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_GW_KA_PERIOD, val);
	ss->ei_gw_props->pp_gw_ka_period = (uint_t)val;

	gw_ka_usecs = ss->ei_gw_props->pp_gw_ka_period * 1000;
	gw_ka_usecs = ((gw_ka_usecs << 2) + gw_ka_usecs) >> 1;
	ss->ei_gw_props->pp_gw_ka_ticks = drv_usectohz(gw_ka_usecs);

	eib_prop_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_VNIC_KA_PERIOD, val);
	ss->ei_gw_props->pp_vnic_ka_period = (uint_t)val;

	vnic_ka_usecs = ss->ei_gw_props->pp_vnic_ka_period * 1000;
	ss->ei_gw_props->pp_vnic_ka_ticks = drv_usectohz(vnic_ka_usecs);

	eib_prop_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_GW_CTRL_QPN, val);
	ss->ei_gw_props->pp_gw_ctrl_qpn = (ib_qpn_t)val;

	eib_prop_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_GW_LID, val);
	ss->ei_gw_props->pp_gw_lid = (ib_lid_t)val;

	eib_prop_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_GW_PORTID, val);
	ss->ei_gw_props->pp_gw_portid = (uint16_t)val;

	eib_prop_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_GW_NUM_NET_VNICS, val);
	ss->ei_gw_props->pp_gw_num_net_vnics = (uint16_t)val;

	eib_prop_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_GW_AVAILABLE, val);
	ss->ei_gw_props->pp_gw_flag_available = (uint8_t)val;

	eib_prop_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_GW_HOST_VNICS, val);
	ss->ei_gw_props->pp_gw_is_host_adm_vnics = (uint8_t)val;

	eib_prop_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_GW_SL, val);
	ss->ei_gw_props->pp_gw_sl = (uint8_t)val;

	eib_prop_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_GW_N_RSS_QPN, val);
	ss->ei_gw_props->pp_gw_n_rss_qpn = (uint8_t)val;

	eib_prop_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_HCA_PORTNUM, val);
	ss->ei_props->ep_port_num = (uint8_t)val;

	eib_propstr_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_GW_SYS_NAME, &str);
	ss->ei_gw_props->pp_gw_system_name = (uint8_t *)str;

	eib_propstr_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_GW_PORT_NAME, &str);
	ss->ei_gw_props->pp_gw_port_name = (uint8_t *)str;

	eib_propstr_get_and_test(ss->ei_instance, ss->ei_dip,
	    EIB_PROP_GW_VENDOR_ID, &str);
	ss->ei_gw_props->pp_gw_vendor_id = (uint8_t *)str;

	return (EIB_E_SUCCESS);

get_props_fail:
	eib_rb_get_props(ss);
	return (EIB_E_FAILURE);
}

void
eib_update_props(eib_t *ss, eib_gw_info_t *new_gw_info)
{
	eib_gw_props_t *gwp = ss->ei_gw_props;
	dev_info_t *dip = ss->ei_dip;
	char *str;

	ASSERT(gwp != NULL && dip != NULL);

	mutex_enter(&gwp->pp_gw_lock);

	gwp->pp_gw_system_guid = new_gw_info->gi_system_guid;
	(void) ddi_prop_update_int64(DDI_DEV_T_NONE, dip, EIB_PROP_GW_SYS_GUID,
	    gwp->pp_gw_system_guid);

	gwp->pp_gw_guid = new_gw_info->gi_guid;
	(void) ddi_prop_update_int64(DDI_DEV_T_NONE, dip, EIB_PROP_GW_GUID,
	    gwp->pp_gw_guid);

	gwp->pp_gw_sn_prefix = new_gw_info->gi_sn_prefix;
	(void) ddi_prop_update_int64(DDI_DEV_T_NONE, dip, EIB_PROP_GW_SN_PREFIX,
	    gwp->pp_gw_sn_prefix);

	gwp->pp_gw_adv_period = new_gw_info->gi_adv_period;
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_ADV_PERIOD,
	    gwp->pp_gw_adv_period);

	gwp->pp_gw_ka_period = new_gw_info->gi_ka_period;
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_KA_PERIOD,
	    gwp->pp_gw_ka_period);

	gwp->pp_vnic_ka_period = new_gw_info->gi_vnic_ka_period;
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_VNIC_KA_PERIOD,
	    gwp->pp_vnic_ka_period);

	gwp->pp_gw_ctrl_qpn = new_gw_info->gi_ctrl_qpn;
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_CTRL_QPN,
	    gwp->pp_gw_ctrl_qpn);

	gwp->pp_gw_lid = new_gw_info->gi_lid;
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_LID,
	    gwp->pp_gw_lid);

	gwp->pp_gw_portid = new_gw_info->gi_portid;
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_PORTID,
	    gwp->pp_gw_portid);

	gwp->pp_gw_num_net_vnics = new_gw_info->gi_num_net_vnics;
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip,
	    EIB_PROP_GW_NUM_NET_VNICS, gwp->pp_gw_num_net_vnics);

	gwp->pp_gw_flag_available = new_gw_info->gi_flag_available;
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_AVAILABLE,
	    gwp->pp_gw_flag_available);

	gwp->pp_gw_is_host_adm_vnics = new_gw_info->gi_is_host_adm_vnics;
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_HOST_VNICS,
	    gwp->pp_gw_is_host_adm_vnics);

	gwp->pp_gw_sl = new_gw_info->gi_sl;
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_SL,
	    gwp->pp_gw_sl);

	gwp->pp_gw_n_rss_qpn = new_gw_info->gi_n_rss_qpn;
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_N_RSS_QPN,
	    gwp->pp_gw_n_rss_qpn);

	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    EIB_PROP_GW_SYS_NAME, (char *)(new_gw_info->gi_system_name));
	(void) ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, EIB_PROP_GW_SYS_NAME, &str);
	if (gwp->pp_gw_system_name) {
		ddi_prop_free(gwp->pp_gw_system_name);
	}
	gwp->pp_gw_system_name = (uint8_t *)str;

	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    EIB_PROP_GW_PORT_NAME, (char *)(new_gw_info->gi_port_name));
	(void) ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, EIB_PROP_GW_PORT_NAME, &str);
	if (gwp->pp_gw_port_name) {
		ddi_prop_free(gwp->pp_gw_port_name);
	}
	gwp->pp_gw_port_name = (uint8_t *)str;

	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    EIB_PROP_GW_VENDOR_ID, (char *)(new_gw_info->gi_vendor_id));
	(void) ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, EIB_PROP_GW_VENDOR_ID, &str);
	if (gwp->pp_gw_vendor_id) {
		ddi_prop_free(gwp->pp_gw_vendor_id);
	}
	gwp->pp_gw_vendor_id = (uint8_t *)str;

	mutex_exit(&gwp->pp_gw_lock);
}

void
eib_rb_get_props(eib_t *ss)
{
	/*
	 * Free any allocations
	 */
	if (ss->ei_gw_props->pp_gw_vendor_id) {
		ddi_prop_free(ss->ei_gw_props->pp_gw_vendor_id);
		ss->ei_gw_props->pp_gw_vendor_id = NULL;
	}
	if (ss->ei_gw_props->pp_gw_port_name) {
		ddi_prop_free(ss->ei_gw_props->pp_gw_port_name);
		ss->ei_gw_props->pp_gw_port_name = NULL;
	}
	if (ss->ei_gw_props->pp_gw_system_name) {
		ddi_prop_free(ss->ei_gw_props->pp_gw_system_name);
		ss->ei_gw_props->pp_gw_system_name = NULL;
	}

	mutex_destroy(&ss->ei_gw_props->pp_gw_lock);

	/*
	 * Free space allocated for holding the props
	 */
	kmem_free(ss->ei_props, sizeof (eib_props_t));
	kmem_free(ss->ei_gw_props, sizeof (eib_gw_props_t));

	ss->ei_props = NULL;
	ss->ei_gw_props = NULL;
}
