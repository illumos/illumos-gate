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

#include <hxge_impl.h>
#include <inet/common.h>
#include <inet/mi.h>
#include <inet/nd.h>

extern uint64_t hpi_debug_level;

#define	HXGE_PARAM_MAC_RW \
	HXGE_PARAM_RW | HXGE_PARAM_MAC | \
	HXGE_PARAM_NDD_WR_OK | HXGE_PARAM_READ_PROP

#define	HXGE_PARAM_RXDMA_RW	HXGE_PARAM_RWP | HXGE_PARAM_RXDMA | \
	HXGE_PARAM_NDD_WR_OK | HXGE_PARAM_READ_PROP

#define	HXGE_PARAM_L2CLASS_CFG	\
	HXGE_PARAM_RW | HXGE_PARAM_PROP_ARR32 | \
	HXGE_PARAM_READ_PROP | HXGE_PARAM_NDD_WR_OK

#define	HXGE_PARAM_CLASS_RWS \
	HXGE_PARAM_RWS | HXGE_PARAM_READ_PROP

#define	HXGE_PARAM_ARRAY_INIT_SIZE	0x20ULL

#define	BASE_ANY	0
#define	BASE_BINARY	2
#define	BASE_HEX	16
#define	BASE_DECIMAL	10
#define	ALL_FF_64	0xFFFFFFFFFFFFFFFFULL
#define	ALL_FF_32	0xFFFFFFFFUL

#define	HXGE_NDD_INFODUMP_BUFF_SIZE	2048	/* is 2k enough? */
#define	HXGE_NDD_INFODUMP_BUFF_8K	8192
#define	HXGE_NDD_INFODUMP_BUFF_16K	0x2000
#define	HXGE_NDD_INFODUMP_BUFF_64K	0x8000

#define	PARAM_OUTOF_RANGE(vptr, eptr, rval, pa)	\
	((vptr == eptr) || (rval < pa->minimum) || (rval > pa->maximum))

#define	ADVANCE_PRINT_BUFFER(pmp, plen, rlen) { \
	((mblk_t *)pmp)->b_wptr += plen; \
	rlen -= plen; \
}

int hxge_param_rx_intr_pkts(p_hxge_t hxgep, queue_t *,
	mblk_t *, char *, caddr_t);
int hxge_param_rx_intr_time(p_hxge_t hxgep, queue_t *,
	mblk_t *, char *, caddr_t);
static int hxge_param_set_mac(p_hxge_t, queue_t *,
	mblk_t *, char *, caddr_t);
static int hxge_param_set_ether_usr(p_hxge_t hxgep, queue_t *, mblk_t *,
	char *, caddr_t);
int hxge_param_set_ip_opt(p_hxge_t hxgep,
	queue_t *, mblk_t *, char *, caddr_t);
static int hxge_param_pfc_hash_init(p_hxge_t hxgep,
	queue_t *, mblk_t *, char *, caddr_t);
static int hxge_param_tcam_enable(p_hxge_t hxgep, queue_t *,
	mblk_t *, char *, caddr_t);
static int hxge_param_get_rxdma_info(p_hxge_t hxgep, queue_t *q,
	p_mblk_t mp, caddr_t cp);
static int hxge_param_set_vlan_ids(p_hxge_t hxgep, queue_t *q,
	mblk_t *mp, char *value, caddr_t cp);
static int hxge_param_get_vlan_ids(p_hxge_t hxgep, queue_t *q,
	p_mblk_t mp, caddr_t cp);
int hxge_param_get_ip_opt(p_hxge_t hxgep,
	queue_t *, mblk_t *, caddr_t);
static int hxge_param_get_mac(p_hxge_t hxgep, queue_t *q, p_mblk_t mp,
	caddr_t cp);
static int hxge_param_get_debug_flag(p_hxge_t hxgep, queue_t *q,
	p_mblk_t mp, caddr_t cp);
static int hxge_param_set_hxge_debug_flag(p_hxge_t hxgep,
	queue_t *, mblk_t *, char *, caddr_t);
static int hxge_param_set_hpi_debug_flag(p_hxge_t hxgep,
	queue_t *, mblk_t *, char *, caddr_t);
static int hxge_param_dump_ptrs(p_hxge_t hxgep, queue_t *q,
	p_mblk_t mp, caddr_t cp);

/*
 * Global array of Hydra changable parameters.
 * This array is initialized to correspond to the default
 * Hydra configuration. This array would be copied
 * into the parameter structure and modifed per
 * fcode and hxge.conf configuration. Later, the parameters are
 * exported to ndd to display and run-time configuration (at least
 * some of them).
 */

static hxge_param_t hxge_param_arr[] = {
	/* min	max	value	old	hw-name 	conf-name	*/
	{hxge_param_get_generic, NULL, HXGE_PARAM_READ,
		0, 999, 1000, 0, "instance", "instance"},

	/* MTU cannot be propagated to the stack from here, so don't show it */
	{hxge_param_get_mac, hxge_param_set_mac,
		HXGE_PARAM_MAC_RW | HXGE_PARAM_DONT_SHOW,
		0, 1, 0, 0, "accept-jumbo", "accept_jumbo"},

	{hxge_param_get_rxdma_info, NULL,
		HXGE_PARAM_READ | HXGE_PARAM_DONT_SHOW,
		HXGE_RBR_RBB_MIN, HXGE_RBR_RBB_MAX, HXGE_RBR_RBB_DEFAULT, 0,
		"rx-rbr-size", "rx_rbr_size"},

	{hxge_param_get_rxdma_info, NULL,
		HXGE_PARAM_READ | HXGE_PARAM_DONT_SHOW,
		HXGE_RCR_MIN, HXGE_RCR_MAX, HXGE_RCR_DEFAULT, 0,
		"rx-rcr-size", "rx_rcr_size"},

	{hxge_param_get_generic, hxge_param_rx_intr_time,
		HXGE_PARAM_RXDMA_RW,
		HXGE_RDC_RCR_TIMEOUT_MIN, HXGE_RDC_RCR_TIMEOUT_MAX,
		RXDMA_RCR_TO_DEFAULT, 0, "rxdma-intr-time", "rxdma_intr_time"},

	{hxge_param_get_generic, hxge_param_rx_intr_pkts,
		HXGE_PARAM_RXDMA_RW,
		HXGE_RDC_RCR_THRESHOLD_MIN, HXGE_RDC_RCR_THRESHOLD_MAX,
		RXDMA_RCR_PTHRES_DEFAULT, 0,
		"rxdma-intr-pkts", "rxdma_intr_pkts"},

	/* Hardware VLAN is not used currently, so don't show it */
	{hxge_param_get_vlan_ids, hxge_param_set_vlan_ids,
		HXGE_PARAM_L2CLASS_CFG | HXGE_PARAM_DONT_SHOW,
		VLAN_ID_MIN, VLAN_ID_MAX, 0, 0, "vlan-ids", "vlan_ids"},

	/* Hardware VLAN is not used currently, so don't show it */
	{hxge_param_get_generic, hxge_param_set_generic,
		HXGE_PARAM_CLASS_RWS | HXGE_PARAM_DONT_SHOW,
		VLAN_ID_MIN, VLAN_ID_MAX, VLAN_ID_IMPLICIT, VLAN_ID_IMPLICIT,
		"implicit-vlan-id", "implicit_vlan_id"},

	{hxge_param_get_generic, hxge_param_tcam_enable,
		HXGE_PARAM_CLASS_RWS | HXGE_PARAM_DONT_SHOW,
		0, 0x1, 0x0, 0, "tcam-enable", "tcam_enable"},

	{hxge_param_get_generic, hxge_param_pfc_hash_init,
		HXGE_PARAM_CLASS_RWS | HXGE_PARAM_DONT_SHOW,
		0, ALL_FF_32, ALL_FF_32, 0,
		"hash-init-value", "hash_init_value"},

	{hxge_param_get_generic, hxge_param_set_ether_usr,
		HXGE_PARAM_CLASS_RWS | HXGE_PARAM_DONT_SHOW,
		0, ALL_FF_32, 0x0, 0,
		"class-cfg-ether-usr1", "class_cfg_ether_usr1"},

	{hxge_param_get_generic, hxge_param_set_ether_usr,
		HXGE_PARAM_CLASS_RWS | HXGE_PARAM_DONT_SHOW,
		0, ALL_FF_32, 0x0, 0,
		"class-cfg-ether-usr2", "class_cfg_ether_usr2"},

	{hxge_param_get_ip_opt, hxge_param_set_ip_opt, HXGE_PARAM_CLASS_RWS,
		0, ALL_FF_32, HXGE_CLASS_TCAM_LOOKUP, 0,
		"class-opt-ipv4-tcp", "class_opt_ipv4_tcp"},

	{hxge_param_get_ip_opt, hxge_param_set_ip_opt, HXGE_PARAM_CLASS_RWS,
		0, ALL_FF_32, HXGE_CLASS_TCAM_LOOKUP, 0,
		"class-opt-ipv4-udp", "class_opt_ipv4_udp"},

	{hxge_param_get_ip_opt, hxge_param_set_ip_opt, HXGE_PARAM_CLASS_RWS,
		0, ALL_FF_32, HXGE_CLASS_TCAM_LOOKUP, 0,
		"class-opt-ipv4-ah", "class_opt_ipv4_ah"},

	{hxge_param_get_ip_opt, hxge_param_set_ip_opt, HXGE_PARAM_CLASS_RWS,
		0, ALL_FF_32, HXGE_CLASS_TCAM_LOOKUP, 0,
		"class-opt-ipv4-sctp", "class_opt_ipv4_sctp"},

	{hxge_param_get_ip_opt, hxge_param_set_ip_opt, HXGE_PARAM_CLASS_RWS,
		0, ALL_FF_32, HXGE_CLASS_TCAM_LOOKUP, 0,
		"class-opt-ipv6-tcp", "class_opt_ipv6_tcp"},

	{hxge_param_get_ip_opt, hxge_param_set_ip_opt, HXGE_PARAM_CLASS_RWS,
		0, ALL_FF_32, HXGE_CLASS_TCAM_LOOKUP, 0,
		"class-opt-ipv6-udp", "class_opt_ipv6_udp"},

	{hxge_param_get_ip_opt, hxge_param_set_ip_opt, HXGE_PARAM_CLASS_RWS,
		0, ALL_FF_32, HXGE_CLASS_TCAM_LOOKUP, 0,
		"class-opt-ipv6-ah", "class_opt_ipv6_ah"},

	{hxge_param_get_ip_opt, hxge_param_set_ip_opt, HXGE_PARAM_CLASS_RWS,
		0, ALL_FF_32, HXGE_CLASS_TCAM_LOOKUP, 0,
		"class-opt-ipv6-sctp", "class_opt_ipv6_sctp"},

	{hxge_param_get_debug_flag, hxge_param_set_hxge_debug_flag,
		HXGE_PARAM_RW | HXGE_PARAM_DONT_SHOW,
		0ULL, ALL_FF_64, 0ULL, 0ULL,
		"hxge-debug-flag", "hxge_debug_flag"},

	{hxge_param_get_debug_flag, hxge_param_set_hpi_debug_flag,
		HXGE_PARAM_RW | HXGE_PARAM_DONT_SHOW,
		0ULL, ALL_FF_64, 0ULL, 0ULL,
		"hpi-debug-flag", "hpi_debug_flag"},

	{hxge_param_dump_ptrs, NULL, HXGE_PARAM_READ | HXGE_PARAM_DONT_SHOW,
		0, 0x0fffffff, 0x0fffffff, 0, "dump-ptrs", "dump_ptrs"},

	{NULL, NULL, HXGE_PARAM_READ | HXGE_PARAM_DONT_SHOW,
		0, 0x0fffffff, 0x0fffffff, 0, "end", "end"},
};

extern void *hxge_list;

/*
 * Update the NDD array from the soft properties.
 */
void
hxge_get_param_soft_properties(p_hxge_t hxgep)
{
	p_hxge_param_t	param_arr;
	uint_t		prop_len;
	int		i, j;
	uint32_t	param_count;
	uint32_t	*int_prop_val;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, " ==> hxge_get_param_soft_properties"));

	param_arr = hxgep->param_arr;
	param_count = hxgep->param_count;
	for (i = 0; i < param_count; i++) {

		if ((param_arr[i].type & HXGE_PARAM_READ_PROP) == 0)
			continue;

		if ((param_arr[i].type & HXGE_PARAM_PROP_STR))
			continue;

		if ((param_arr[i].type & HXGE_PARAM_PROP_ARR32) ||
		    (param_arr[i].type & HXGE_PARAM_PROP_ARR64)) {

			if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY,
			    hxgep->dip, 0, param_arr[i].fcode_name,
			    (int **)&int_prop_val, (uint_t *)&prop_len) ==
			    DDI_PROP_SUCCESS) {
				uint64_t *cfg_value;
				uint64_t prop_count;

				if (prop_len > HXGE_PARAM_ARRAY_INIT_SIZE)
					prop_len = HXGE_PARAM_ARRAY_INIT_SIZE;
#if defined(__i386)
				cfg_value =
				    (uint64_t *)(int32_t)param_arr[i].value;
#else
				cfg_value = (uint64_t *)param_arr[i].value;
#endif
				for (j = 0; j < prop_len; j++) {
					cfg_value[j] = int_prop_val[j];
				}
				prop_count = prop_len;
				param_arr[i].type |=
				    (prop_count << HXGE_PARAM_ARRAY_CNT_SHIFT);

				ddi_prop_free(int_prop_val);
			}
			continue;
		}
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, hxgep->dip, 0,
		    param_arr[i].fcode_name, (int **)&int_prop_val,
		    &prop_len) == DDI_PROP_SUCCESS) {
			if ((*int_prop_val >= param_arr[i].minimum) &&
			    (*int_prop_val <= param_arr[i].maximum))
				param_arr[i].value = *int_prop_val;
			ddi_prop_free(int_prop_val);
		}
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, hxgep->dip, 0,
		    param_arr[i].name, (int **)&int_prop_val, &prop_len) ==
		    DDI_PROP_SUCCESS) {
			if ((*int_prop_val >= param_arr[i].minimum) &&
			    (*int_prop_val <= param_arr[i].maximum))
				param_arr[i].value = *int_prop_val;
			ddi_prop_free(int_prop_val);
		}
	}
}

static int
hxge_private_param_register(p_hxge_t hxgep, p_hxge_param_t param_arr)
{
	int		status = B_TRUE;
	int		channel;
	char		*prop_name;
	char		*end;
	uint32_t	name_chars;

	HXGE_DEBUG_MSG((hxgep, NDD2_CTL, " hxge_private_param_register %s",
	    param_arr->name));

	if ((param_arr->type & HXGE_PARAM_PRIV) != HXGE_PARAM_PRIV)
		return (B_TRUE);
	prop_name = param_arr->name;
	if (param_arr->type & HXGE_PARAM_RXDMA) {
		if (strncmp("rxdma_intr", prop_name, 10) == 0)
			return (B_TRUE);
		else
			return (B_FALSE);
	}

	if (param_arr->type & HXGE_PARAM_TXDMA) {
		name_chars = strlen("txdma");
		if (strncmp("txdma", prop_name, name_chars) == 0) {
			prop_name += name_chars;
			channel = mi_strtol(prop_name, &end, 10);
			/* now check if this rdc is in config */
			HXGE_DEBUG_MSG((hxgep, NDD2_CTL,
			    " hxge_private_param_register: %d", channel));
			return (hxge_check_txdma_port_member(hxgep, channel));
		}
		return (B_FALSE);
	}

	status = B_FALSE;
	HXGE_DEBUG_MSG((hxgep, NDD2_CTL, "<== hxge_private_param_register"));

	return (status);
}

void
hxge_setup_param(p_hxge_t hxgep)
{
	p_hxge_param_t	param_arr;
	int		i;
	pfi_t		set_pfi;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "==> hxge_setup_param"));
	/*
	 * Make sure the param_instance is set to a valid device instance.
	 */
	if (hxge_param_arr[param_instance].value == 1000)
		hxge_param_arr[param_instance].value = hxgep->instance;

	param_arr = hxgep->param_arr;
	param_arr[param_instance].value = hxgep->instance;

	for (i = 0; i < hxgep->param_count; i++) {
		if ((param_arr[i].type & HXGE_PARAM_PRIV) &&
		    (hxge_private_param_register(hxgep, &param_arr[i]) ==
		    B_FALSE)) {
			param_arr[i].setf = NULL;
			param_arr[i].getf = NULL;
		}
		if (param_arr[i].type & HXGE_PARAM_CMPLX)
			param_arr[i].setf = NULL;

		if (param_arr[i].type & HXGE_PARAM_DONT_SHOW) {
			param_arr[i].setf = NULL;
			param_arr[i].getf = NULL;
		}
		set_pfi = (pfi_t)param_arr[i].setf;

		if ((set_pfi) && (param_arr[i].type & HXGE_PARAM_INIT_ONLY)) {
			set_pfi = NULL;
		}
		if (!hxge_nd_load(&hxgep->param_list, param_arr[i].name,
		    (pfi_t)param_arr[i].getf, set_pfi,
		    (caddr_t)&param_arr[i])) {
			(void) hxge_nd_free(&hxgep->param_list);
			break;
		}
	}

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "<== hxge_setup_param"));
}

/*
 * Called from the attached function, it allocates memory for
 * the parameter array and some members.
 */
void
hxge_init_param(p_hxge_t hxgep)
{
	p_hxge_param_t	param_arr;
	int		i, alloc_size;
	uint64_t	alloc_count;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_init_param"));
	/*
	 * Make sure the param_instance is set to a valid device instance.
	 */
	if (hxge_param_arr[param_instance].value == 1000)
		hxge_param_arr[param_instance].value = hxgep->instance;

	param_arr = hxgep->param_arr;
	if (param_arr == NULL) {
		param_arr = (p_hxge_param_t)KMEM_ZALLOC(
		    sizeof (hxge_param_arr), KM_SLEEP);
	}
	for (i = 0; i < sizeof (hxge_param_arr) / sizeof (hxge_param_t); i++) {
		param_arr[i] = hxge_param_arr[i];
		if ((param_arr[i].type & HXGE_PARAM_PROP_ARR32) ||
		    (param_arr[i].type & HXGE_PARAM_PROP_ARR64)) {
			alloc_count = HXGE_PARAM_ARRAY_INIT_SIZE;
			alloc_size = alloc_count * sizeof (uint64_t);
#if defined(__i386)
			param_arr[i].value =
			    (uint64_t)(uint32_t)KMEM_ZALLOC(alloc_size,
			    KM_SLEEP);
			param_arr[i].old_value =
			    (uint64_t)(uint32_t)KMEM_ZALLOC(alloc_size,
			    KM_SLEEP);
#else
			param_arr[i].value =
			    (uint64_t)KMEM_ZALLOC(alloc_size, KM_SLEEP);
			param_arr[i].old_value =
			    (uint64_t)KMEM_ZALLOC(alloc_size, KM_SLEEP);
#endif
			param_arr[i].type |=
			    (alloc_count << HXGE_PARAM_ARRAY_ALLOC_SHIFT);
		}
	}

	hxgep->param_arr = param_arr;
	hxgep->param_count = sizeof (hxge_param_arr) / sizeof (hxge_param_t);
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_init_param: count %d",
	    hxgep->param_count));
}

/*
 * Called from the attached functions, it frees memory for the parameter array
 */
void
hxge_destroy_param(p_hxge_t hxgep)
{
	int		i;
	uint64_t	free_size, free_count;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_destroy_param"));
	/*
	 * Make sure the param_instance is set to a valid device instance.
	 */
	if (hxge_param_arr[param_instance].value == hxgep->instance) {
		for (i = 0; i <= hxge_param_arr[param_instance].maximum; i++) {
			if ((ddi_get_soft_state(hxge_list, i) != NULL) &&
			    (i != hxgep->instance))
				break;
		}
		hxge_param_arr[param_instance].value = i;
	}
	if (hxgep->param_list)
		hxge_nd_free(&hxgep->param_list);
	for (i = 0; i < hxgep->param_count; i++) {
		if ((hxgep->param_arr[i].type & HXGE_PARAM_PROP_ARR32) ||
		    (hxgep->param_arr[i].type & HXGE_PARAM_PROP_ARR64)) {
			free_count = ((hxgep->param_arr[i].type &
			    HXGE_PARAM_ARRAY_ALLOC_MASK) >>
			    HXGE_PARAM_ARRAY_ALLOC_SHIFT);
			free_count = HXGE_PARAM_ARRAY_INIT_SIZE;
			free_size = sizeof (uint64_t) * free_count;
#if defined(__i386)
			KMEM_FREE((void *)(uint32_t)
			    hxgep->param_arr[i].value, free_size);
			KMEM_FREE((void *)(uint32_t)
			    hxgep->param_arr[i].old_value, free_size);
#else
			KMEM_FREE((void *) hxgep->param_arr[i].value,
			    free_size);
			KMEM_FREE((void *) hxgep->param_arr[i].old_value,
			    free_size);
#endif
		}
	}

	KMEM_FREE(hxgep->param_arr, sizeof (hxge_param_arr));
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_destroy_param"));
}

/*
 * Extracts the value from the 'hxge' parameter array and prints the
 * parameter value. cp points to the required parameter.
 */
/* ARGSUSED */
int
hxge_param_get_generic(p_hxge_t hxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	p_hxge_param_t pa = (p_hxge_param_t)cp;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, " ==> hxge_param_get_generic name %s ",
	    pa->name));

	if (pa->value > 0xffffffff)
		(void) mi_mpprintf(mp, "%x%x", (int)(pa->value >> 32),
		    (int)(pa->value & 0xffffffff));
	else
		(void) mi_mpprintf(mp, "%x", (int)pa->value);

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "<== hxge_param_get_generic"));
	return (0);
}

/* ARGSUSED */
static int
hxge_param_get_mac(p_hxge_t hxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	p_hxge_param_t pa = (p_hxge_param_t)cp;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "==> hxge_param_get_mac"));

	(void) mi_mpprintf(mp, "%d", (uint32_t)pa->value);
	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "<== hxge_param_get_mac"));
	return (0);
}

/* ARGSUSED */
int
hxge_param_get_rxdma_info(p_hxge_t hxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	uint_t			print_len, buf_len;
	p_mblk_t		np;
	int			rdc;
	p_hxge_dma_pt_cfg_t	p_dma_cfgp;
	p_hxge_hw_pt_cfg_t	p_cfgp;
	int			buff_alloc_size = HXGE_NDD_INFODUMP_BUFF_SIZE;

	p_rx_rcr_rings_t rx_rcr_rings;
	p_rx_rcr_ring_t *rcr_rings;
	p_rx_rbr_rings_t rx_rbr_rings;
	p_rx_rbr_ring_t *rbr_rings;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "==> hxge_param_get_rxdma_info"));

	(void) mi_mpprintf(mp, "RXDMA Information\n");

	if ((np = allocb(buff_alloc_size, BPRI_HI)) == NULL) {
		/* The following may work even if we cannot get a large buf. */
		(void) mi_mpprintf(mp, "%s\n", "out of buffer");
		return (0);
	}
	buf_len = buff_alloc_size;

	mp->b_cont = np;

	p_dma_cfgp = (p_hxge_dma_pt_cfg_t)&hxgep->pt_config;
	p_cfgp = (p_hxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	rx_rcr_rings = hxgep->rx_rcr_rings;
	rcr_rings = rx_rcr_rings->rcr_rings;
	rx_rbr_rings = hxgep->rx_rbr_rings;
	rbr_rings = rx_rbr_rings->rbr_rings;

	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "Total RDCs\t %d\n", p_cfgp->max_rdcs);
	((mblk_t *)np)->b_wptr += print_len;
	buf_len -= print_len;
	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "RDC\t HW RDC\t Timeout\t Packets RBR ptr \t"
	    "chunks\t RCR ptr\n");
	((mblk_t *)np)->b_wptr += print_len;
	buf_len -= print_len;
	for (rdc = 0; rdc < p_cfgp->max_rdcs; rdc++) {
		print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
		    " %d\t  %d\t $%p\t 0x%x\t $%p\n",
		    rdc, hxgep->rdc[rdc], (void *)rbr_rings[rdc],
		    rbr_rings[rdc]->num_blocks, (void *)rcr_rings[rdc]);
		((mblk_t *)np)->b_wptr += print_len;
		buf_len -= print_len;
	}
	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "<== hxge_param_get_rxdma_info"));
	return (0);
}

int
hxge_mk_mblk_tail_space(p_mblk_t mp, p_mblk_t *nmp, size_t size)
{
	p_mblk_t tmp;

	tmp = mp;
	while (tmp->b_cont)
		tmp = tmp->b_cont;
	if ((tmp->b_wptr + size) >= tmp->b_datap->db_lim) {
		tmp->b_cont = allocb(1024, BPRI_HI);
		tmp = tmp->b_cont;
		if (!tmp)
			return (ENOMEM);
	}
	*nmp = tmp;
	return (0);
}

/*
 * Sets the ge parameter to the value in the hxge_param_register using
 * hxge_nd_load().
 */
/* ARGSUSED */
int
hxge_param_set_generic(p_hxge_t hxgep, queue_t *q, mblk_t *mp,
	char *value, caddr_t cp)
{
	char		*end;
	uint32_t	new_value;
	p_hxge_param_t	pa = (p_hxge_param_t)cp;

	HXGE_DEBUG_MSG((hxgep, IOC_CTL, " ==> hxge_param_set_generic"));
	new_value = (uint32_t)mi_strtol(value, &end, 10);
	if (end == value || new_value < pa->minimum ||
	    new_value > pa->maximum) {
		return (EINVAL);
	}
	pa->value = new_value;
	HXGE_DEBUG_MSG((hxgep, IOC_CTL, " <== hxge_param_set_generic"));
	return (0);
}

/* ARGSUSED */
int
hxge_param_set_mac(p_hxge_t hxgep, queue_t *q, mblk_t *mp,
	char *value, caddr_t cp)
{
	char		*end;
	uint32_t	new_value;
	int		status = 0;
	p_hxge_param_t	pa = (p_hxge_param_t)cp;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "==> hxge_param_set_mac"));
	new_value = (uint32_t)mi_strtol(value, &end, BASE_DECIMAL);
	if (PARAM_OUTOF_RANGE(value, end, new_value, pa)) {
		return (EINVAL);
	}

	if (pa->value != new_value) {
		pa->old_value = pa->value;
		pa->value = new_value;
	}

	if (pa->value != pa->old_value) {
		RW_ENTER_WRITER(&hxgep->filter_lock);
		(void) hxge_rx_vmac_disable(hxgep);
		(void) hxge_tx_vmac_disable(hxgep);

		/*
		 * Apply the new jumbo parameter here.
		 * The order of the following two calls is important.
		 */
		(void) hxge_tx_vmac_enable(hxgep);
		(void) hxge_rx_vmac_enable(hxgep);
		RW_EXIT(&hxgep->filter_lock);
	}

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "<== hxge_param_set_mac"));
	return (status);
}

/* ARGSUSED */
int
hxge_param_rx_intr_pkts(p_hxge_t hxgep, queue_t *q,
	mblk_t *mp, char *value, caddr_t cp)
{
	char		*end;
	uint32_t	cfg_value;
	p_hxge_param_t	pa = (p_hxge_param_t)cp;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "==> hxge_param_rx_intr_pkts"));

	if (strncasecmp(value, "0x", 2) == 0)
		value += 2;

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_HEX);

	if ((cfg_value > HXGE_RDC_RCR_THRESHOLD_MAX) ||
	    (cfg_value < HXGE_RDC_RCR_THRESHOLD_MIN)) {
		return (EINVAL);
	}

	if ((pa->value != cfg_value)) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		hxgep->intr_threshold = pa->value;
	}

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "<== hxge_param_rx_intr_pkts"));
	return (0);
}

/* ARGSUSED */
int
hxge_param_rx_intr_time(p_hxge_t hxgep, queue_t *q,
	mblk_t *mp, char *value, caddr_t cp)
{
	char		*end;
	uint32_t	cfg_value;
	p_hxge_param_t	pa = (p_hxge_param_t)cp;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "==> hxge_param_rx_intr_time"));

	if (strncasecmp(value, "0x", 2) == 0)
		value += 2;

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_HEX);

	if ((cfg_value > HXGE_RDC_RCR_TIMEOUT_MAX) ||
	    (cfg_value < HXGE_RDC_RCR_TIMEOUT_MIN)) {
		return (EINVAL);
	}

	if ((pa->value != cfg_value)) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		hxgep->intr_timeout = pa->value;
	}

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "<== hxge_param_rx_intr_time"));
	return (0);
}

/* ARGSUSED */
static int
hxge_param_set_vlan_ids(p_hxge_t hxgep, queue_t *q, mblk_t *mp, char *value,
    caddr_t cp)
{
	char			*end;
	uint32_t		status = 0, cfg_value;
	p_hxge_param_t		pa = (p_hxge_param_t)cp;
	uint32_t		cfg_it = B_FALSE;
	uint32_t		*val_ptr, *old_val_ptr;
	hxge_param_map_t	*vmap, *old_map;
	p_hxge_class_pt_cfg_t 	p_class_cfgp;
	uint64_t		cfgd_vlans;
	int			i, inc = 0, cfg_position;
	hxge_mv_cfg_t		*vlan_tbl;
	hpi_handle_t		handle;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "==> hxge_param_set_vlan_ids "));

	p_class_cfgp = (p_hxge_class_pt_cfg_t)&hxgep->class_config;
	vlan_tbl = (hxge_mv_cfg_t *)&p_class_cfgp->vlan_tbl[0];
	handle = hxgep->hpi_reg_handle;

	if (strncasecmp(value, "0x", 2) == 0)
		value += 2;

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_HEX);

	/* now do decoding */
	cfgd_vlans = ((pa->type & HXGE_PARAM_ARRAY_CNT_MASK) >>
	    HXGE_PARAM_ARRAY_CNT_SHIFT);

	if (cfgd_vlans >= HXGE_PARAM_ARRAY_INIT_SIZE) {
		/*
		 * for now, we process only upto HXGE_PARAM_ARRAY_INIT_SIZE
		 * parameters In the future, we may want to expand
		 * the storage array and continue
		 */
		return (EINVAL);
	}

	vmap = (hxge_param_map_t *)&cfg_value;
	if ((vmap->param_id == 0) || (vmap->param_id > VLAN_ID_MAX)) {
		return (EINVAL);
	}

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, " hxge_param_set_vlan_ids id %d",
	    vmap->param_id));
#if defined(__i386)
	val_ptr = (uint32_t *)(uint32_t)pa->value;
	old_val_ptr = (uint32_t *)(uint32_t)pa->old_value;
#else
	val_ptr = (uint32_t *)pa->value;
	old_val_ptr = (uint32_t *)pa->old_value;
#endif

	/* Search to see if this vlan id is already configured */
	for (i = 0; i < cfgd_vlans; i++) {
		old_map = (hxge_param_map_t *)&val_ptr[i];
		if ((old_map->param_id == 0) ||
		    (vmap->param_id == old_map->param_id) ||
		    (vlan_tbl[vmap->param_id].flag)) {
			cfg_position = i;
			break;
		}
	}

	if (cfgd_vlans == 0) {
		cfg_position = 0;
		inc++;
	}

	if (i == cfgd_vlans) {
		cfg_position = i;
		inc++;
	}

	HXGE_DEBUG_MSG((hxgep, NDD2_CTL,
	    " set_vlan_ids mapping i %d cfgd_vlans %llx position %d ",
	    i, cfgd_vlans, cfg_position));

	if (val_ptr[cfg_position] != cfg_value) {
		old_val_ptr[cfg_position] = val_ptr[cfg_position];
		val_ptr[cfg_position] = cfg_value;
		vlan_tbl[vmap->param_id].flag = 1;
		cfg_it = B_TRUE;
		if (inc) {
			cfgd_vlans++;
			pa->type &= ~HXGE_PARAM_ARRAY_CNT_MASK;
			pa->type |= (cfgd_vlans << HXGE_PARAM_ARRAY_CNT_SHIFT);

		}

		HXGE_DEBUG_MSG((hxgep, NDD2_CTL,
		    " after: param_set_vlan_ids cfg_vlans %llx position %d \n",
		    cfgd_vlans, cfg_position));
	}

	if (cfg_it == B_TRUE) {
		status = hpi_pfc_cfg_vlan_table_entry_set(handle,
		    (vlan_id_t)vmap->param_id);
		if (status != HPI_SUCCESS)
			return (EINVAL);
	}

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "<== hxge_param_set_vlan_ids"));

	return (0);
}


/* ARGSUSED */
static int
hxge_param_get_vlan_ids(p_hxge_t hxgep, queue_t *q, mblk_t *mp, caddr_t cp)
{
	uint_t			print_len, buf_len;
	p_mblk_t		np;
	int			i;
	uint32_t		*val_ptr;
	hxge_param_map_t	*vmap;
	p_hxge_param_t		pa = (p_hxge_param_t)cp;
	p_hxge_class_pt_cfg_t 	p_class_cfgp;
	uint64_t		cfgd_vlans = 0;
	int buff_alloc_size = HXGE_NDD_INFODUMP_BUFF_SIZE * 32;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "==> hxge_param_set_vlan_ids "));
	(void) mi_mpprintf(mp, "VLAN Information\n");

	if ((np = allocb(buff_alloc_size, BPRI_HI)) == NULL) {
		(void) mi_mpprintf(mp, "%s\n", "out of buffer");
		return (0);
	}

	buf_len = buff_alloc_size;
	mp->b_cont = np;
	cfgd_vlans = (pa->type & HXGE_PARAM_ARRAY_CNT_MASK) >>
	    HXGE_PARAM_ARRAY_CNT_SHIFT;

	i = (int)cfgd_vlans;
	p_class_cfgp = (p_hxge_class_pt_cfg_t)&hxgep->class_config;
	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "Configured VLANs %d\n VLAN ID\n", i);
	((mblk_t *)np)->b_wptr += print_len;
	buf_len -= print_len;

#if defined(__i386)
	val_ptr = (uint32_t *)(uint32_t)pa->value;
#else
	val_ptr = (uint32_t *)pa->value;
#endif

	for (i = 0; i < cfgd_vlans; i++) {
		vmap = (hxge_param_map_t *)&val_ptr[i];
		if (p_class_cfgp->vlan_tbl[vmap->param_id].flag) {
			print_len = snprintf((char *)((mblk_t *)np)->b_wptr,
			    buf_len, "  %d\n", vmap->param_id);
			((mblk_t *)np)->b_wptr += print_len;
			buf_len -= print_len;
		}
	}

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "<== hxge_param_get_vlan_ids"));

	return (0);
}

/* ARGSUSED */
static int
hxge_param_tcam_enable(p_hxge_t hxgep, queue_t *q,
	mblk_t *mp, char *value, caddr_t cp)
{
	uint32_t	status = 0, cfg_value;
	p_hxge_param_t	pa = (p_hxge_param_t)cp;
	uint32_t	cfg_it = B_FALSE;
	char		*end;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "==> hxge_param_tcam_enable"));

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_BINARY);
	if (pa->value != cfg_value) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		cfg_it = B_TRUE;
	}
	if (cfg_it == B_TRUE) {
		if (pa->value)
			status = hxge_pfc_config_tcam_enable(hxgep);
		else
			status = hxge_pfc_config_tcam_disable(hxgep);
		if (status != HXGE_OK)
			return (EINVAL);
	}
	HXGE_DEBUG_MSG((hxgep, NDD_CTL, " <== hxge_param_tcam_enable"));
	return (0);
}

/* ARGSUSED */
static int
hxge_param_set_ether_usr(p_hxge_t hxgep, queue_t *q,
	mblk_t *mp, char *value, caddr_t cp)
{
	char		*end;
	uint32_t	status = 0, cfg_value;
	p_hxge_param_t	pa = (p_hxge_param_t)cp;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "==> hxge_param_set_ether_usr"));

	if (strncasecmp(value, "0x", 2) == 0)
		value += 2;

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_HEX);
	if (PARAM_OUTOF_RANGE(value, end, cfg_value, pa)) {
		return (EINVAL);
	}
	if (pa->value != cfg_value) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
	}

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "<== hxge_param_set_ether_usr"));
	return (status);
}

static int
hxge_class_name_2value(p_hxge_t hxgep, char *name)
{
	int		i;
	int		class_instance = param_class_opt_ipv4_tcp;
	p_hxge_param_t	param_arr;

	param_arr = hxgep->param_arr;
	for (i = TCAM_CLASS_TCP_IPV4; i <= TCAM_CLASS_SCTP_IPV6; i++) {
		if (strcmp(param_arr[class_instance].name, name) == 0)
			return (i);
		class_instance++;
	}
	return (-1);
}

/* ARGSUSED */
int
hxge_param_set_ip_opt(p_hxge_t hxgep, queue_t *q,
	mblk_t *mp, char *value, caddr_t cp)
{
	char		*end;
	uint32_t	status, cfg_value;
	p_hxge_param_t	pa = (p_hxge_param_t)cp;
	tcam_class_t	class;
	uint32_t	cfg_it = B_FALSE;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "==> hxge_param_set_ip_opt"));

	if (strncasecmp(value, "0x", 2) == 0)
		value += 2;

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_HEX);
	if (PARAM_OUTOF_RANGE(value, end, cfg_value, pa)) {
		return (EINVAL);
	}
	if (pa->value != cfg_value) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		cfg_it = B_TRUE;
	}
	if (cfg_it == B_TRUE) {
		/* do the actual hw setup  */
		class = hxge_class_name_2value(hxgep, pa->name);
		if (class == -1)
			return (EINVAL);

		status = hxge_pfc_ip_class_config(hxgep, class, pa->value);
		if (status != HXGE_OK)
			return (EINVAL);
	}
	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "<== hxge_param_set_ip_opt"));
	return (0);
}

/* ARGSUSED */
int
hxge_param_get_ip_opt(p_hxge_t hxgep, queue_t *q, mblk_t *mp, caddr_t cp)
{
	uint32_t	status, cfg_value;
	p_hxge_param_t	pa = (p_hxge_param_t)cp;
	tcam_class_t	class;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "==> hxge_param_get_ip_opt"));

	/* do the actual hw setup  */
	class = hxge_class_name_2value(hxgep, pa->name);
	if (class == -1)
		return (EINVAL);
	cfg_value = 0;
	status = hxge_pfc_ip_class_config_get(hxgep, class, &cfg_value);
	if (status != HXGE_OK)
		return (EINVAL);
	HXGE_DEBUG_MSG((hxgep, NDD_CTL,
	    "hxge_param_get_ip_opt_get %x ", cfg_value));
	pa->value = cfg_value;

	if (mp != NULL)
		(void) mi_mpprintf(mp, "%x", cfg_value);

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "<== hxge_param_get_ip_opt status "));
	return (0);
}

/* ARGSUSED */
static int
hxge_param_pfc_hash_init(p_hxge_t hxgep, queue_t *q, mblk_t *mp,
	char *value, caddr_t cp)
{
	char		*end;
	uint32_t	status, cfg_value;
	p_hxge_param_t	pa = (p_hxge_param_t)cp;
	uint32_t	cfg_it = B_FALSE;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "==> hxge_param_pfc_hash_init"));

	if (strncasecmp(value, "0x", 2) == 0)
		value += 2;

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_HEX);
	if (PARAM_OUTOF_RANGE(value, end, cfg_value, pa)) {
		return (EINVAL);
	}

	HXGE_DEBUG_MSG((hxgep, NDD_CTL,
	    " hxge_param_pfc_hash_init value %x", cfg_value));
	if (pa->value != cfg_value) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		cfg_it = B_TRUE;
	}

	if (cfg_it == B_TRUE) {
		status = hxge_pfc_set_hash(hxgep, (uint32_t)pa->value);
		if (status != HXGE_OK)
			return (EINVAL);
	}
	HXGE_DEBUG_MSG((hxgep, NDD_CTL, " <== hxge_param_pfc_hash_init"));
	return (0);
}

/* ARGSUSED */
static int
hxge_param_set_hxge_debug_flag(p_hxge_t hxgep, queue_t *q,
	mblk_t *mp, char *value, caddr_t cp)
{
	char		*end;
	uint32_t	status = 0;
	uint64_t	cfg_value = 0;
	p_hxge_param_t	pa = (p_hxge_param_t)cp;
	uint32_t	cfg_it = B_FALSE;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "==> hxge_param_set_hxge_debug_flag"));

	if (strncasecmp(value, "0x", 2) == 0)
		value += 2;

	cfg_value = mi_strtol(value, &end, BASE_HEX);

	if (PARAM_OUTOF_RANGE(value, end, cfg_value, pa)) {
		HXGE_DEBUG_MSG((hxgep, NDD_CTL,
		    " hxge_param_set_hxge_debug_flag"
		    " outof range %llx", cfg_value));
		return (EINVAL);
	}
	if (pa->value != cfg_value) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		cfg_it = B_TRUE;
	}
	if (cfg_it == B_TRUE)
		hxgep->hxge_debug_level = pa->value;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "<== hxge_param_set_hxge_debug_flag"));
	return (status);
}

/* ARGSUSED */
static int
hxge_param_get_debug_flag(p_hxge_t hxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	int		status = 0;
	p_hxge_param_t	pa = (p_hxge_param_t)cp;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "==> hxge_param_get_debug_flag"));

	if (pa->value > 0xffffffff)
		(void) mi_mpprintf(mp, "%x%x", (int)(pa->value >> 32),
		    (int)(pa->value & 0xffffffff));
	else
		(void) mi_mpprintf(mp, "%x", (int)pa->value);


	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "<== hxge_param_get_debug_flag"));
	return (status);
}

/* ARGSUSED */
static int
hxge_param_set_hpi_debug_flag(p_hxge_t hxgep, queue_t *q,
	mblk_t *mp, char *value, caddr_t cp)
{
	char		*end;
	uint32_t	status = 0;
	uint64_t	cfg_value = 0;
	p_hxge_param_t	pa = (p_hxge_param_t)cp;
	uint32_t	cfg_it = B_FALSE;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "==> hxge_param_set_hpi_debug_flag"));

	if (strncasecmp(value, "0x", 2) == 0)
		value += 2;

	cfg_value = mi_strtol(value, &end, BASE_HEX);

	if (PARAM_OUTOF_RANGE(value, end, cfg_value, pa)) {
		HXGE_DEBUG_MSG((hxgep, NDD_CTL, " hxge_param_set_hpi_debug_flag"
		    " outof range %llx", cfg_value));
		return (EINVAL);
	}
	if (pa->value != cfg_value) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		cfg_it = B_TRUE;
	}
	if (cfg_it == B_TRUE) {
		hpi_debug_level = pa->value;
	}
	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "<== hxge_param_set_debug_flag"));
	return (status);
}

typedef struct block_info {
	char *name;
	uint32_t offset;
} block_info_t;

block_info_t reg_block[] = {
	{"PIO", PIO_BASE_ADDR},
	{"PIO_LDSV", PIO_LDSV_BASE_ADDR},
	{"PIO_LDMASK", PIO_LDMASK_BASE_ADDR},
	{"PFC", PFC_BASE_ADDR},
	{"RDC", RDC_BASE_ADDR},
	{"TDC", TDC_BASE_ADDR},
	{"VMAC", VMAC_BASE_ADDR},
	{"END", ALL_FF_32},
};

/* ARGSUSED */
static int
hxge_param_dump_ptrs(p_hxge_t hxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	uint_t			print_len, buf_len;
	p_mblk_t		np;
	int			rdc, tdc, block;
	uint64_t		base;
	p_hxge_dma_pt_cfg_t	p_dma_cfgp;
	p_hxge_hw_pt_cfg_t	p_cfgp;
	int			buff_alloc_size = HXGE_NDD_INFODUMP_BUFF_8K;
	p_tx_ring_t		*tx_rings;
	p_rx_rcr_rings_t	rx_rcr_rings;
	p_rx_rcr_ring_t		*rcr_rings;
	p_rx_rbr_rings_t	rx_rbr_rings;
	p_rx_rbr_ring_t		*rbr_rings;

	HXGE_DEBUG_MSG((hxgep, IOC_CTL, "==> hxge_param_dump_ptrs"));

	(void) mi_mpprintf(mp, "ptr information\n");

	if ((np = allocb(buff_alloc_size, BPRI_HI)) == NULL) {
		/* The following may work even if we cannot get a large buf. */
		(void) mi_mpprintf(mp, "%s\n", "out of buffer");
		return (0);
	}
	buf_len = buff_alloc_size;

	mp->b_cont = np;
	p_dma_cfgp = (p_hxge_dma_pt_cfg_t)&hxgep->pt_config;
	p_cfgp = (p_hxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	rx_rcr_rings = hxgep->rx_rcr_rings;
	rcr_rings = rx_rcr_rings->rcr_rings;
	rx_rbr_rings = hxgep->rx_rbr_rings;
	rbr_rings = rx_rbr_rings->rbr_rings;
	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "hxgep (hxge_t) $%p\n dev_regs (dev_regs_t) $%p\n",
	    (void *)hxgep, (void *)hxgep->dev_regs);

	ADVANCE_PRINT_BUFFER(np, print_len, buf_len);
	/* do register pointers */
	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "reg base (hpi_reg_ptr_t) $%p\t pci reg (hpi_reg_ptr_t) $%p\n",
	    (void *)hxgep->dev_regs->hxge_regp,
	    (void *)hxgep->dev_regs->hxge_pciregp);

	ADVANCE_PRINT_BUFFER(np, print_len, buf_len);

	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "\nBlock \t Offset \n");

	ADVANCE_PRINT_BUFFER(np, print_len, buf_len);
	block = 0;
#if defined(__i386)
	base = (uint64_t)(uint32_t)hxgep->dev_regs->hxge_regp;
#else
	base = (uint64_t)hxgep->dev_regs->hxge_regp;
#endif
	while (reg_block[block].offset != ALL_FF_32) {
		print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
		    "%9s\t 0x%llx\n", reg_block[block].name,
		    (unsigned long long) (reg_block[block].offset + base));
		ADVANCE_PRINT_BUFFER(np, print_len, buf_len);
		block++;
	}

	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "\nRDC\t rcrp (rx_rcr_ring_t)\t rbrp (rx_rbr_ring_t)\n");

	ADVANCE_PRINT_BUFFER(np, print_len, buf_len);

	for (rdc = 0; rdc < p_cfgp->max_rdcs; rdc++) {
		print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
		    " %d\t  $%p\t\t   $%p\n",
		    rdc, (void *)rcr_rings[rdc], (void *)rbr_rings[rdc]);
		ADVANCE_PRINT_BUFFER(np, print_len, buf_len);
	}

	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "\nTDC\t tdcp (tx_ring_t)\n");

	ADVANCE_PRINT_BUFFER(np, print_len, buf_len);
	tx_rings = hxgep->tx_rings->rings;
	for (tdc = 0; tdc < p_cfgp->max_tdcs; tdc++) {
		print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
		    " %d\t  $%p\n", tdc, (void *)tx_rings[tdc]);
		ADVANCE_PRINT_BUFFER(np, print_len, buf_len);
	}

	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len, "\n\n");

	ADVANCE_PRINT_BUFFER(np, print_len, buf_len);
	HXGE_DEBUG_MSG((hxgep, IOC_CTL, "<== hxge_param_dump_ptrs"));
	return (0);
}

/*
 * Load 'name' into the named dispatch table pointed to by 'ndp'.
 * 'ndp' should be the address of a char pointer cell.  If the table
 * does not exist (*ndp == 0), a new table is allocated and 'ndp'
 * is stuffed.  If there is not enough space in the table for a new
 * entry, more space is allocated.
 */
boolean_t
hxge_nd_load(caddr_t *pparam, char *name,
	pfi_t get_pfi, pfi_t set_pfi, caddr_t data)
{
	ND	*nd;
	NDE	*nde;

	HXGE_DEBUG_MSG((NULL, NDD2_CTL, " ==> hxge_nd_load: %s", name));
	if (!pparam)
		return (B_FALSE);
	if ((nd = (ND *) * pparam) == NULL) {
		if ((nd = (ND *) KMEM_ZALLOC(sizeof (ND), KM_NOSLEEP)) == NULL)
			return (B_FALSE);
		*pparam = (caddr_t)nd;
	}
	if (nd->nd_tbl) {
		for (nde = nd->nd_tbl; nde->nde_name; nde++) {
			if (strcmp(name, nde->nde_name) == 0)
				goto fill_it;
		}
	}
	if (nd->nd_free_count <= 1) {
		if ((nde = (NDE *) KMEM_ZALLOC(nd->nd_size +
		    NDE_ALLOC_SIZE, KM_NOSLEEP)) == NULL)
			return (B_FALSE);
		nd->nd_free_count += NDE_ALLOC_COUNT;
		if (nd->nd_tbl) {
			bcopy((char *)nd->nd_tbl, (char *)nde, nd->nd_size);
			KMEM_FREE((char *)nd->nd_tbl, nd->nd_size);
		} else {
			nd->nd_free_count--;
			nde->nde_name = "?";
			nde->nde_get_pfi = hxge_nd_get_names;
			nde->nde_set_pfi = hxge_set_default;
		}
		nde->nde_data = (caddr_t)nd;
		nd->nd_tbl = nde;
		nd->nd_size += NDE_ALLOC_SIZE;
	}
	for (nde = nd->nd_tbl; nde->nde_name; nde++)
		noop;
	nd->nd_free_count--;
fill_it:
	nde->nde_name = name;
	nde->nde_get_pfi = get_pfi;
	nde->nde_set_pfi = set_pfi;
	nde->nde_data = data;
	HXGE_DEBUG_MSG((NULL, NDD2_CTL, " <== hxge_nd_load"));

	return (B_TRUE);
}

/*
 * Free the table pointed to by 'pparam'
 */
void
hxge_nd_free(caddr_t *pparam)
{
	ND *nd;

	if ((nd = (ND *)*pparam) != NULL) {
		if (nd->nd_tbl)
			KMEM_FREE((char *)nd->nd_tbl, nd->nd_size);
		KMEM_FREE((char *)nd, sizeof (ND));
		*pparam = nil(caddr_t);
	}
}

int
hxge_nd_getset(p_hxge_t hxgep, queue_t *q, caddr_t param, p_mblk_t mp)
{
	int		err;
	IOCP		iocp;
	p_mblk_t	mp1, mp2;
	ND		*nd;
	NDE		*nde;
	char		*valp;

	size_t		avail;

	if (!param) {
		return (B_FALSE);
	}
	nd = (ND *) param;
	iocp = (IOCP) mp->b_rptr;
	if ((iocp->ioc_count == 0) || !(mp1 = mp->b_cont)) {
		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_count = 0;
		iocp->ioc_error = EINVAL;
		return (B_FALSE);
	}
	/*
	 * NOTE - logic throughout nd_xxx assumes single data block for ioctl.
	 * However, existing code sends in some big buffers.
	 */
	avail = iocp->ioc_count;
	if (mp1->b_cont) {
		freemsg(mp1->b_cont);
		mp1->b_cont = NULL;
	}
	mp1->b_datap->db_lim[-1] = '\0';	/* Force null termination */
	for (valp = (char *)mp1->b_rptr; *valp != '\0'; valp++) {
		if (*valp == '-')
			*valp = '_';
	}

	valp = (char *)mp1->b_rptr;

	for (nde = nd->nd_tbl; /* */; nde++) {
		if (!nde->nde_name)
			return (B_FALSE);
		if (strcmp(nde->nde_name, valp) == 0)
			break;
	}
	err = EINVAL;
	while (*valp++)
		noop;
	if (!*valp || valp >= (char *)mp1->b_wptr)
		valp = nilp(char);
	switch (iocp->ioc_cmd) {
	case ND_GET:
		if (*nde->nde_get_pfi == NULL)
			return (B_FALSE);

		/*
		 * (temporary) hack: "*valp" is size of user buffer for
		 * copyout. If result of action routine is too big, free excess
		 * and return ioc_rval as buffer size needed. Return as many
		 * mblocks as will fit, free the rest.  For backward
		 * compatibility, assume size of original ioctl buffer if
		 * "*valp" bad or not given.
		 */
		if (valp)
			avail = mi_strtol(valp, (char **)0, 10);
		/*
		 * We overwrite the name/value with the reply data
		 */
		mp2 = mp1;
		while (mp2) {
			mp2->b_wptr = mp2->b_rptr;
			mp2 = mp2->b_cont;
		}

		err = (*nde->nde_get_pfi) (hxgep, q, mp1, nde->nde_data);

		if (!err) {
			size_t size_out = 0;
			ssize_t excess;

			iocp->ioc_rval = 0;

			/* Tack on the null */
			err = hxge_mk_mblk_tail_space(mp1, &mp2, 1);
			if (!err) {
				*mp2->b_wptr++ = '\0';
				size_out = msgdsize(mp1);
				excess = size_out - avail;
				if (excess > 0) {
					iocp->ioc_rval = (int)size_out;
					size_out -= excess;
					(void) adjmsg(mp1, -(excess + 1));
					err = hxge_mk_mblk_tail_space(
					    mp1, &mp2, 1);
					if (!err)
						*mp2->b_wptr++ = '\0';
					else
						size_out = 0;
				}
			} else
				size_out = 0;
			iocp->ioc_count = size_out;
		}
		break;

	case ND_SET:
		if (valp) {
			if (nde->nde_set_pfi) {
				err = (*nde->nde_set_pfi) (hxgep, q, mp1, valp,
				    nde->nde_data);
				iocp->ioc_count = 0;
				freemsg(mp1);
				mp->b_cont = NULL;
			}
		}
		break;

	default:
		break;
	}
	iocp->ioc_error = err;
	mp->b_datap->db_type = M_IOCACK;
	return (B_TRUE);
}

/* ARGSUSED */
int
hxge_nd_get_names(p_hxge_t hxgep, queue_t *q, p_mblk_t mp, caddr_t param)
{
	ND		*nd;
	NDE		*nde;
	char		*rwtag;
	boolean_t	get_ok, set_ok;
	size_t		param_len;
	int		status = 0;

	nd = (ND *) param;
	if (!nd)
		return (ENOENT);

	for (nde = nd->nd_tbl; nde->nde_name; nde++) {
		get_ok = (nde->nde_get_pfi != hxge_get_default) &&
		    (nde->nde_get_pfi != NULL);
		set_ok = (nde->nde_set_pfi != hxge_set_default) &&
		    (nde->nde_set_pfi != NULL);
		if (get_ok) {
			if (set_ok)
				rwtag = "read and write";
			else
				rwtag = "read only";
		} else if (set_ok)
			rwtag = "write only";
		else {
			continue;
		}
		param_len = strlen(rwtag);
		param_len += strlen(nde->nde_name);
		param_len += 4;

		(void) mi_mpprintf(mp, "%s (%s)", nde->nde_name, rwtag);
	}
	return (status);
}

/* ARGSUSED */
int
hxge_get_default(p_hxge_t hxgep, queue_t *q, p_mblk_t mp, caddr_t data)
{
	return (EACCES);
}

/* ARGSUSED */
int
hxge_set_default(p_hxge_t hxgep, queue_t *q, p_mblk_t mp, char *value,
	caddr_t data)
{
	return (EACCES);
}

void
hxge_param_ioctl(p_hxge_t hxgep, queue_t *wq, mblk_t *mp, struct iocblk *iocp)
{
	int cmd;
	int status = B_FALSE;

	HXGE_DEBUG_MSG((hxgep, IOC_CTL, "==> hxge_param_ioctl"));
	cmd = iocp->ioc_cmd;
	switch (cmd) {
	default:
		HXGE_DEBUG_MSG((hxgep, IOC_CTL,
		    "hxge_param_ioctl: bad cmd 0x%0x", cmd));
		break;

	case ND_GET:
	case ND_SET:
		HXGE_DEBUG_MSG((hxgep, IOC_CTL,
		    "hxge_param_ioctl: cmd 0x%0x", cmd));
		if (!hxge_nd_getset(hxgep, wq, hxgep->param_list, mp)) {
			HXGE_DEBUG_MSG((hxgep, IOC_CTL,
			    "false ret from hxge_nd_getset"));
			break;
		}
		status = B_TRUE;
		break;
	}

	if (status) {
		qreply(wq, mp);
	} else {
		miocnak(wq, mp, 0, EINVAL);
	}
	HXGE_DEBUG_MSG((hxgep, IOC_CTL, "<== hxge_param_ioctl"));
}
