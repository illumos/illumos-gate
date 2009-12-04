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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/pci_cfgacc.h>

#define	PCI_CFGACC_FILLREQ(r, d, b, o, s, w, v)				\
	{(r).rcdip = (d); (r).bdf = (b); (r).offset = (o);		\
	(r).size = (s); (r).write = w; (r).ioacc = B_FALSE; 		\
	VAL64(&(r)) = (v); }

/*
 * Common interfaces for accessing pci config space
 */

/*
 * This pointer should be initialized before using, here doesn't check it.
 * For x86:
 * 	initialized at the end of pci_check();
 * For Sparc:
 *  initialized in the px_attach().
 */
void (*pci_cfgacc_acc_p)(pci_cfgacc_req_t *req);

uint8_t
pci_cfgacc_get8(dev_info_t *rcdip, uint16_t bdf, uint16_t off)
{
	pci_cfgacc_req_t req;

	PCI_CFGACC_FILLREQ(req, rcdip, bdf, off, 1, B_FALSE, 0);
	(*pci_cfgacc_acc_p)(&req);
	return (VAL8(&req));
}

void
pci_cfgacc_put8(dev_info_t *rcdip, uint16_t bdf, uint16_t off, uint8_t data)
{
	pci_cfgacc_req_t req;

	PCI_CFGACC_FILLREQ(req, rcdip, bdf, off, 1, B_TRUE, data);
	(*pci_cfgacc_acc_p)(&req);
}

uint16_t
pci_cfgacc_get16(dev_info_t *rcdip, uint16_t bdf, uint16_t off)
{
	pci_cfgacc_req_t req;

	PCI_CFGACC_FILLREQ(req, rcdip, bdf, off, 2, B_FALSE, 0);
	(*pci_cfgacc_acc_p)(&req);
	return (VAL16(&req));
}

void
pci_cfgacc_put16(dev_info_t *rcdip, uint16_t bdf, uint16_t off, uint16_t data)
{
	pci_cfgacc_req_t req;

	PCI_CFGACC_FILLREQ(req, rcdip, bdf, off, 2, B_TRUE, data);
	(*pci_cfgacc_acc_p)(&req);
}

uint32_t
pci_cfgacc_get32(dev_info_t *rcdip, uint16_t bdf, uint16_t off)
{
	pci_cfgacc_req_t req;

	PCI_CFGACC_FILLREQ(req, rcdip, bdf, off, 4, B_FALSE, 0);
	(*pci_cfgacc_acc_p)(&req);
	return (VAL32(&req));
}

void
pci_cfgacc_put32(dev_info_t *rcdip, uint16_t bdf, uint16_t off, uint32_t data)
{
	pci_cfgacc_req_t req;

	PCI_CFGACC_FILLREQ(req, rcdip, bdf, off, 4, B_TRUE, data);
	(*pci_cfgacc_acc_p)(&req);
}

uint64_t
pci_cfgacc_get64(dev_info_t *rcdip, uint16_t bdf, uint16_t off)
{
	pci_cfgacc_req_t req;

	PCI_CFGACC_FILLREQ(req, rcdip, bdf, off, 8, B_FALSE, 0);
	(*pci_cfgacc_acc_p)(&req);
	return (VAL64(&req));
}

void
pci_cfgacc_put64(dev_info_t *rcdip, uint16_t bdf, uint16_t off, uint64_t data)
{
	pci_cfgacc_req_t req;

	PCI_CFGACC_FILLREQ(req, rcdip, bdf, off, 8, B_TRUE, data);
	(*pci_cfgacc_acc_p)(&req);
}
