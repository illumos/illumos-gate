/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/


#include "qede.h"

qede_link_props_t qede_def_link_props  = 
{
	GLDM_FIBER,
	B_TRUE,
	B_TRUE,
	B_TRUE,
	B_TRUE,
	B_TRUE,
	B_TRUE,
	B_TRUE,
	B_TRUE,
	B_FALSE
};
static void 
qede_cfg_get_val(qede_t  *qede,
    char *        pName,
    void *        pVal,
    int           defaultVal,
    boolean_t     boolVal)
{
	int val;
#define		QEDE_CFG_NAME_LEN_MAX 		128

	char name[QEDE_CFG_NAME_LEN_MAX];

	/* first check if the hardcoded default has been overridden */

	snprintf(name, QEDE_CFG_NAME_LEN_MAX, "default_%s", pName);

	val = ddi_prop_get_int(DDI_DEV_T_ANY,
		qede->dip,
		(DDI_PROP_NOTPROM | DDI_PROP_DONTPASS),
		name,
		defaultVal);
	/* now check for a config for this specific instance */

	snprintf(name, QEDE_CFG_NAME_LEN_MAX, "qede%d_%s", qede->instance, 
	    pName);

	val = ddi_prop_get_int(DDI_DEV_T_ANY,
		qede->dip,
		(DDI_PROP_NOTPROM | DDI_PROP_DONTPASS),
		name,
		val);

	if (boolVal) {
		*((boolean_t *)pVal) = (val) ? B_TRUE : B_FALSE;
	} else {
		*((int *)pVal) = val;
	}
}

void 
qede_cfg_init(qede_t *qede)
{

	int option;

	qede->checksum = DEFAULT_CKSUM_OFFLOAD;
	qede->enabled_offloads = QEDE_OFFLOAD_NONE;
	qede->mtu = DEFAULT_MTU;
	qede->num_fp = DEFAULT_FASTPATH_COUNT;
	qede->rx_ring_size = DEFAULT_RX_RING_SIZE;
	qede->tx_ring_size = DEFAULT_TX_RING_SIZE;
	qede->tx_recycle_threshold = DEFAULT_TX_RECYCLE_THRESHOLD;
	qede->rx_copy_threshold = DEFAULT_RX_COPY_THRESHOLD;
	qede->tx_bcopy_threshold = DEFAULT_TX_COPY_THRESHOLD;
	qede->lso_enable = B_TRUE;
	qede->lro_enable = B_TRUE;
	qede->log_enable = B_TRUE;
	qede->ecore_debug_level = DEFAULT_ECORE_DEBUG_LEVEL;
	qede->ecore_debug_module = DEFAULT_ECORE_DEBUG_MODULE;

	qede_cfg_get_val(qede, "checksum", 
			  &qede->checksum,
			  qede->checksum,
			  B_FALSE);
	switch(qede->checksum) {
	case USER_OPTION_CKSUM_L3:
	case USER_OPTION_CKSUM_L3_L4:
		qede->checksum = DEFAULT_CKSUM_OFFLOAD;
		break;
	}

	qede_cfg_get_val(qede, "mtu", &option,
	    qede->mtu,
	    B_FALSE);

	if (option != DEFAULT_JUMBO_MTU &&
	    option != DEFAULT_MTU) {
		qede->mtu = DEFAULT_MTU;
		qede->jumbo_enable = B_FALSE;
	} else {
		if (qede->mtu != option) {
		qede->mtu = option;
		}
		if (option == DEFAULT_JUMBO_MTU) {
		    qede->jumbo_enable = B_TRUE;
		}
	}

	qede_cfg_get_val(qede, "num_fp", &option,
	    qede->num_fp,
	    B_FALSE);
	qede->num_fp = (option < MIN_FASTPATH_COUNT) ?
	    MIN_FASTPATH_COUNT :
	    (option > MAX_FASTPATH_COUNT) ?
	    MAX_FASTPATH_COUNT :
	    option;

	qede_cfg_get_val(qede, "rx_ring_size", &option,
	    qede->rx_ring_size,
	    B_FALSE);
	qede->rx_ring_size = (option < MIN_RX_RING_SIZE) ?
	    MIN_RX_RING_SIZE :
	    (option > MAX_RX_RING_SIZE) ?
	    MAX_RX_RING_SIZE :
	    option;
	qede_cfg_get_val(qede, "tx_ring_size", &option,
	    qede->tx_ring_size,
	    B_FALSE);
	qede->tx_ring_size = (option < MIN_TX_RING_SIZE) ?
	    MIN_TX_RING_SIZE :
	    (option > MAX_TX_RING_SIZE) ?
	    MAX_TX_RING_SIZE :
	    option;
	qede_cfg_get_val(qede, "rx_copy_threshold", &option,
	    qede->rx_copy_threshold,
	    B_FALSE);
	qede_cfg_get_val(qede, "tx_copy_threshold", &option,
	    qede->tx_bcopy_threshold,
	    B_FALSE);
	qede_cfg_get_val(qede, "tx_recycle_threshold", &option,
	    qede->tx_bcopy_threshold,
	    B_FALSE);
	qede->tx_recycle_threshold =
	    (option < 0) ? 0:
	    (option > qede->tx_ring_size) ?
	    qede->tx_ring_size : option;
	qede_cfg_get_val(qede, "lso_enable", &option,
	    qede->lso_enable,
	    B_TRUE);
	qede->lso_enable = option;
	qede_cfg_get_val(qede, "lro_enable", &option,
	    qede->lro_enable,
	    B_TRUE);
	qede->lro_enable = option;

	if(qede->checksum != DEFAULT_CKSUM_OFFLOAD) {
		qede->lso_enable = B_FALSE;
		qede->lro_enable = B_FALSE;
	}

	qede_cfg_get_val(qede, "log_enable", &option,
	    qede->log_enable,
	    B_TRUE);
	qede_cfg_get_val(qede, "debug_level", &option,
	    qede->ecore_debug_level,
	    B_FALSE);
	qede->ecore_debug_level =  (uint32_t)((option < 0) ? 0 : option);

	qede_cfg_get_val(qede, "debug_module", &option,
	    qede->ecore_debug_module,
	    B_FALSE);
	qede->ecore_debug_module = (uint32_t)((option < 0) ? 0 : option);
}


void 
qede_cfg_reset(qede_t *qede)
{
	qede->params.link_state = 0;
	/* reset the link status */
	qede->props.link_speed = 0;
	qede->props.link_duplex = B_FALSE;
	qede->props.tx_pause = B_FALSE;
	qede->props.rx_pause = B_FALSE;
	qede->props.uptime = 0;

}

