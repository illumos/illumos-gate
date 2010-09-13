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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_CONTRACT_DEVICE_IMPL_H
#define	_SYS_CONTRACT_DEVICE_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/contract_impl.h>
#include <sys/dditypes.h>
#include <sys/contract/device.h>
#include <sys/fs/snode.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Result of negotiation end: event successfully occurred or not
 */
#define	CT_EV_SUCCESS	150
#define	CT_EV_FAILURE	151

struct ctmpl_device {
	ct_template_t	ctd_ctmpl;
	uint_t		ctd_aset;
	uint_t		ctd_noneg;
	char		*ctd_minor;
};

struct cont_device {
	contract_t	cond_contract;	/* common contract data */
	char		*cond_minor;  /* minor node resource in contract */
	dev_info_t	*cond_dip;	/* dip for minor node */
	dev_t		cond_devt;	/* dev_t of minor node */
	uint_t		cond_spec;	/* spec type of minor node */
	uint_t		cond_aset;	/* acceptable state set */
	uint_t		cond_noneg;	/* no negotiation if set */
	uint_t		cond_state;	/* current state of device */
	uint_t		cond_neg;	/* contract undergoing negotiation */
	uint64_t	cond_currev_id;	/* id of event being negotiated */
	uint_t		cond_currev_type;  /* type of event being negotiated */
	uint_t		cond_currev_ack; /* ack/nack status of ev negotiation */
	list_node_t	cond_next;	/* linkage - devinfo's contracts */
};

/*
 * Kernel APIs
 */
extern ct_type_t *device_type;
/*
 * struct proc;
 */
void contract_device_init(void);
ct_ack_t contract_device_offline(dev_info_t *dip, dev_t dev, int spec_type);
void contract_device_degrade(dev_info_t *dip, dev_t dev, int spec_type);
void contract_device_undegrade(dev_info_t *dip, dev_t dev, int spec_type);
int contract_device_open(dev_t dev, int spec_type, contract_t **ctpp);
void contract_device_remove_dip(dev_info_t *dip);
ct_ack_t contract_device_negotiate(dev_info_t *dip, dev_t dev, int spec_type,
    uint_t evtype);
void contract_device_finalize(dev_info_t *dip, dev_t dev, int spec_type,
    uint_t evtype, int ct_result);
void contract_device_negend(dev_info_t *dip, dev_t dev, int spec_type,
    int result);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CONTRACT_DEVICE_IMPL_H */
