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
 *
 * Copyright 2016, Joyent, Inc.
 */
/*
 * Copyright (c) 2009-2010, Intel Corporation.
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>
#include <sys/acpidev_rsc.h>
#include <sys/acpidev_impl.h>

#define	ACPIDEV_RES_INIT_ITEMS		8
#define	ACPIDEV_RES_INCR_ITEMS		8

/* Data structure to hold parsed resources during walking. */
struct acpidev_resource_handle {
	boolean_t			acpidev_consumer;
	int				acpidev_reg_count;
	int				acpidev_reg_max;
	acpidev_phys_spec_t		*acpidev_regp;
	acpidev_phys_spec_t		acpidev_regs[ACPIDEV_RES_INIT_ITEMS];
	int				acpidev_range_count;
	int				acpidev_range_max;
	acpidev_ranges_t		*acpidev_rangep;
	acpidev_ranges_t		acpidev_ranges[ACPIDEV_RES_INIT_ITEMS];
	int				acpidev_bus_count;
	int				acpidev_bus_max;
	acpidev_bus_range_t		*acpidev_busp;
	acpidev_bus_range_t		acpidev_buses[ACPIDEV_RES_INIT_ITEMS];
	int				acpidev_irq_count;
	int				acpidev_irqp[ACPIDEV_RES_IRQ_MAX];
	int				acpidev_dma_count;
	int				acpidev_dmap[ACPIDEV_RES_DMA_MAX];
};

acpidev_resource_handle_t
acpidev_resource_handle_alloc(boolean_t consumer)
{
	acpidev_resource_handle_t rhdl;

	rhdl = kmem_zalloc(sizeof (*rhdl), KM_SLEEP);
	rhdl->acpidev_consumer = consumer;
	rhdl->acpidev_reg_max = ACPIDEV_RES_INIT_ITEMS;
	rhdl->acpidev_regp = rhdl->acpidev_regs;
	rhdl->acpidev_range_max = ACPIDEV_RES_INIT_ITEMS;
	rhdl->acpidev_rangep = rhdl->acpidev_ranges;
	rhdl->acpidev_bus_max = ACPIDEV_RES_INIT_ITEMS;
	rhdl->acpidev_busp = rhdl->acpidev_buses;

	return (rhdl);
}

void
acpidev_resource_handle_free(acpidev_resource_handle_t rhdl)
{
	size_t sz;

	ASSERT(rhdl != NULL);
	if (rhdl != NULL) {
		if (rhdl->acpidev_regp != rhdl->acpidev_regs) {
			sz = sizeof (acpidev_phys_spec_t) *
			    rhdl->acpidev_reg_max;
			kmem_free(rhdl->acpidev_regp, sz);
		}
		if (rhdl->acpidev_rangep != rhdl->acpidev_ranges) {
			sz = sizeof (acpidev_ranges_t) *
			    rhdl->acpidev_range_max;
			kmem_free(rhdl->acpidev_rangep, sz);
		}
		if (rhdl->acpidev_busp != rhdl->acpidev_buses) {
			sz = sizeof (acpidev_bus_range_t) *
			    rhdl->acpidev_bus_max;
			kmem_free(rhdl->acpidev_busp, sz);
		}
		kmem_free(rhdl, sizeof (struct acpidev_resource_handle));
	}
}

static void
acpidev_resource_handle_grow(acpidev_resource_handle_t rhdl)
{
	size_t sz;

	if (rhdl->acpidev_reg_count == rhdl->acpidev_reg_max) {
		acpidev_phys_spec_t *regp;

		/* Prefer linear incremental here. */
		rhdl->acpidev_reg_max += ACPIDEV_RES_INCR_ITEMS;
		sz = sizeof (*regp) * rhdl->acpidev_reg_max;
		regp = kmem_zalloc(sz, KM_SLEEP);
		sz = sizeof (*regp) * rhdl->acpidev_reg_count;
		bcopy(rhdl->acpidev_regp, regp, sz);
		if (rhdl->acpidev_regp != rhdl->acpidev_regs) {
			kmem_free(rhdl->acpidev_regp, sz);
		}
		rhdl->acpidev_regp = regp;
	}

	if (rhdl->acpidev_range_count == rhdl->acpidev_range_max) {
		acpidev_ranges_t *rngp;

		/* Prefer linear incremental here. */
		rhdl->acpidev_range_max += ACPIDEV_RES_INCR_ITEMS;
		sz = sizeof (*rngp) * rhdl->acpidev_range_max;
		rngp = kmem_zalloc(sz, KM_SLEEP);
		sz = sizeof (*rngp) * rhdl->acpidev_range_count;
		bcopy(rhdl->acpidev_rangep, rngp, sz);
		if (rhdl->acpidev_rangep != rhdl->acpidev_ranges) {
			kmem_free(rhdl->acpidev_rangep, sz);
		}
		rhdl->acpidev_rangep = rngp;
	}

	if (rhdl->acpidev_bus_count == rhdl->acpidev_bus_max) {
		acpidev_bus_range_t *busp;

		/* Prefer linear incremental here. */
		rhdl->acpidev_bus_max += ACPIDEV_RES_INCR_ITEMS;
		sz = sizeof (*busp) * rhdl->acpidev_bus_max;
		busp = kmem_zalloc(sz, KM_SLEEP);
		sz = sizeof (*busp) * rhdl->acpidev_bus_count;
		bcopy(rhdl->acpidev_busp, busp, sz);
		if (rhdl->acpidev_busp != rhdl->acpidev_buses) {
			kmem_free(rhdl->acpidev_busp, sz);
		}
		rhdl->acpidev_busp = busp;
	}
}

ACPI_STATUS
acpidev_resource_insert_reg(acpidev_resource_handle_t rhdl,
    acpidev_regspec_t *regp)
{
	ASSERT(rhdl != NULL);
	ASSERT(regp != NULL);
	if (rhdl->acpidev_reg_count >= rhdl->acpidev_reg_max) {
		acpidev_resource_handle_grow(rhdl);
	}
	ASSERT(rhdl->acpidev_reg_count < rhdl->acpidev_reg_max);
	rhdl->acpidev_regp[rhdl->acpidev_reg_count] = *regp;
	rhdl->acpidev_reg_count++;

	return (AE_OK);
}

ACPI_STATUS
acpidev_resource_get_regs(acpidev_resource_handle_t rhdl,
    uint_t mask, uint_t value, acpidev_regspec_t *regp, uint_t *cntp)
{
	uint_t i, j;

	ASSERT(rhdl != NULL);
	ASSERT(cntp != NULL);
	if (rhdl == NULL || cntp == NULL || (regp == NULL && *cntp != 0)) {
		return (AE_BAD_PARAMETER);
	}
	for (i = 0, j = 0; i < rhdl->acpidev_reg_count; i++) {
		if ((rhdl->acpidev_regp[i].phys_hi & mask) == value) {
			if (j < *cntp) {
				regp[j] = rhdl->acpidev_regp[i];
			}
			j++;
		}
	}
	if (j >= *cntp) {
		*cntp = j;
		return (AE_LIMIT);
	} else {
		*cntp = j;
		return (AE_OK);
	}
}

uint_t
acpidev_resource_get_reg_count(acpidev_resource_handle_t rhdl,
    uint_t mask, uint_t value)
{
	uint_t i, j;

	ASSERT(rhdl != NULL);
	for (i = 0, j = 0; i < rhdl->acpidev_reg_count; i++) {
		if ((rhdl->acpidev_regp[i].phys_hi & mask) == value) {
			j++;
		}
	}

	return (j);
}

ACPI_STATUS
acpidev_resource_insert_range(acpidev_resource_handle_t rhdl,
    acpidev_ranges_t *rangep)
{
	ASSERT(rhdl != NULL);
	ASSERT(rangep != NULL);
	if (rhdl->acpidev_range_count >= rhdl->acpidev_range_max) {
		acpidev_resource_handle_grow(rhdl);
	}
	ASSERT(rhdl->acpidev_range_count < rhdl->acpidev_range_max);
	rhdl->acpidev_rangep[rhdl->acpidev_range_count] = *rangep;
	rhdl->acpidev_range_count++;

	return (AE_OK);
}

ACPI_STATUS
acpidev_resource_get_ranges(acpidev_resource_handle_t rhdl,
    uint_t mask, uint_t value, acpidev_ranges_t *rangep, uint_t *cntp)
{
	uint_t i, j;

	ASSERT(rhdl != NULL);
	ASSERT(cntp != NULL);
	if (rhdl == NULL || cntp == NULL || (rangep == NULL && *cntp != 0)) {
		return (AE_BAD_PARAMETER);
	}
	for (i = 0, j = 0; i < rhdl->acpidev_range_count; i++) {
		if ((rhdl->acpidev_rangep[i].child_hi & mask) == value) {
			if (j < *cntp) {
				rangep[j] = rhdl->acpidev_rangep[i];
			}
			j++;
		}
	}
	if (j >= *cntp) {
		*cntp = j;
		return (AE_LIMIT);
	} else {
		*cntp = j;
		return (AE_OK);
	}
}

uint_t
acpidev_resource_get_range_count(acpidev_resource_handle_t rhdl,
    uint_t mask, uint_t value)
{
	uint_t i, j;

	ASSERT(rhdl != NULL);
	for (i = 0, j = 0; i < rhdl->acpidev_range_count; i++) {
		if ((rhdl->acpidev_rangep[i].child_hi & mask) == value) {
			j++;
		}
	}

	return (j);
}

ACPI_STATUS
acpidev_resource_insert_bus(acpidev_resource_handle_t rhdl,
    acpidev_bus_range_t *busp)
{
	ASSERT(rhdl != NULL);
	ASSERT(busp != NULL);
	if (rhdl->acpidev_bus_count >= rhdl->acpidev_bus_max) {
		acpidev_resource_handle_grow(rhdl);
	}
	ASSERT(rhdl->acpidev_bus_count < rhdl->acpidev_bus_max);
	rhdl->acpidev_busp[rhdl->acpidev_bus_count] = *busp;
	rhdl->acpidev_bus_count++;

	return (AE_OK);
}

ACPI_STATUS
acpidev_resource_get_buses(acpidev_resource_handle_t rhdl,
    acpidev_bus_range_t *busp, uint_t *cntp)
{
	uint_t i, j;

	ASSERT(rhdl != NULL);
	ASSERT(cntp != NULL);
	if (rhdl == NULL || cntp == NULL || (busp == NULL && *cntp != 0)) {
		return (AE_BAD_PARAMETER);
	}
	for (i = 0, j = 0; i < rhdl->acpidev_bus_count; i++) {
		if (j < *cntp) {
			busp[j] = rhdl->acpidev_busp[i];
		}
		j++;
	}
	if (j >= *cntp) {
		*cntp = j;
		return (AE_LIMIT);
	} else {
		*cntp = j;
		return (AE_OK);
	}
}

uint_t
acpidev_resource_get_bus_count(acpidev_resource_handle_t rhdl)
{
	ASSERT(rhdl != NULL);
	return (rhdl->acpidev_bus_count);
}

ACPI_STATUS
acpidev_resource_insert_dma(acpidev_resource_handle_t rhdl, int dma)
{
	ASSERT(rhdl != NULL);
	if (rhdl->acpidev_dma_count >= ACPIDEV_RES_DMA_MAX) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: too many DMA resources, max %u.",
		    ACPIDEV_RES_DMA_MAX);
		return (AE_LIMIT);
	}
	rhdl->acpidev_dmap[rhdl->acpidev_dma_count] = dma;
	rhdl->acpidev_dma_count++;

	return (AE_OK);
}

ACPI_STATUS
acpidev_resource_get_dmas(acpidev_resource_handle_t rhdl,
    uint_t *dmap, uint_t *cntp)
{
	uint_t i, j;

	ASSERT(rhdl != NULL);
	ASSERT(cntp != NULL);
	if (rhdl == NULL || cntp == NULL || (dmap == NULL && *cntp != 0)) {
		return (AE_BAD_PARAMETER);
	}
	for (i = 0, j = 0; i < rhdl->acpidev_dma_count; i++) {
		if (j < *cntp) {
			dmap[j] = rhdl->acpidev_dmap[i];
		}
		j++;
	}
	if (j >= *cntp) {
		*cntp = j;
		return (AE_LIMIT);
	} else {
		*cntp = j;
		return (AE_OK);
	}
}

uint_t
acpidev_resource_get_dma_count(acpidev_resource_handle_t rhdl)
{
	ASSERT(rhdl != NULL);
	return (rhdl->acpidev_dma_count);
}

ACPI_STATUS
acpidev_resource_insert_irq(acpidev_resource_handle_t rhdl, int irq)
{
	ASSERT(rhdl != NULL);
	if (rhdl->acpidev_irq_count >= ACPIDEV_RES_IRQ_MAX) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: too many IRQ resources, max %u.",
		    ACPIDEV_RES_IRQ_MAX);
		return (AE_LIMIT);
	}
	rhdl->acpidev_irqp[rhdl->acpidev_irq_count] = irq;
	rhdl->acpidev_irq_count++;

	return (AE_OK);
}

ACPI_STATUS
acpidev_resource_get_irqs(acpidev_resource_handle_t rhdl,
    uint_t *irqp, uint_t *cntp)
{
	uint_t i, j;

	ASSERT(rhdl != NULL);
	ASSERT(cntp != NULL);
	if (rhdl == NULL || cntp == NULL || (irqp == NULL && *cntp != 0)) {
		return (AE_BAD_PARAMETER);
	}
	for (i = 0, j = 0; i < rhdl->acpidev_irq_count; i++) {
		if (j < *cntp) {
			irqp[j] = rhdl->acpidev_irqp[i];
		}
		j++;
	}
	if (j >= *cntp) {
		*cntp = j;
		return (AE_LIMIT);
	} else {
		*cntp = j;
		return (AE_OK);
	}
}

uint_t
acpidev_resource_get_irq_count(acpidev_resource_handle_t rhdl)
{
	ASSERT(rhdl != NULL);
	return (rhdl->acpidev_irq_count);
}

static ACPI_STATUS
acpidev_resource_address64(acpidev_resource_handle_t rhdl,
    ACPI_RESOURCE_ADDRESS64 *addrp)
{
	ACPI_STATUS rc = AE_OK;
	uint_t high;

	ASSERT(addrp != NULL && rhdl != NULL);
	if (addrp->Address.AddressLength == 0) {
		return (AE_OK);
	}

	switch (addrp->ResourceType) {
	case ACPI_MEMORY_RANGE:
		high = ACPIDEV_REG_TYPE_MEMORY;
		if (addrp->Decode == ACPI_SUB_DECODE) {
			high |= ACPIDEV_REG_SUB_DEC;
		}
		if (addrp->Info.Mem.Translation) {
			high |= ACPIDEV_REG_TRANSLATED;
		}
		if (addrp->Info.Mem.Caching == ACPI_NON_CACHEABLE_MEMORY) {
			high |= ACPIDEV_REG_MEM_COHERENT_NC;
		} else if (addrp->Info.Mem.Caching == ACPI_CACHABLE_MEMORY) {
			high |= ACPIDEV_REG_MEM_COHERENT_CA;
		} else if (addrp->Info.Mem.Caching ==
		    ACPI_WRITE_COMBINING_MEMORY) {
			high |= ACPIDEV_REG_MEM_COHERENT_WC;
		} else if (addrp->Info.Mem.Caching ==
		    ACPI_PREFETCHABLE_MEMORY) {
			high |= ACPIDEV_REG_MEM_COHERENT_PF;
		} else {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: unknown memory caching type %u.",
			    addrp->Info.Mem.Caching);
			rc = AE_ERROR;
			break;
		}
		if (addrp->Info.Mem.WriteProtect == ACPI_READ_WRITE_MEMORY) {
			high |= ACPIDEV_REG_MEM_WRITABLE;
		}

		/* Generate 'reg' for producer. */
		if (addrp->ProducerConsumer == ACPI_CONSUMER &&
		    rhdl->acpidev_consumer == B_TRUE) {
			acpidev_regspec_t reg;

			reg.phys_hi = high;
			reg.phys_mid = addrp->Address.Minimum >> 32;
			reg.phys_low = addrp->Address.Minimum & 0xFFFFFFFF;
			reg.size_hi = addrp->Address.AddressLength >> 32;
			reg.size_low = addrp->Address.AddressLength &
			    0xFFFFFFFF;
			rc = acpidev_resource_insert_reg(rhdl, &reg);
			if (ACPI_FAILURE(rc)) {
				ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to "
				    "insert regspec into resource handle.");
			}
		/* Generate 'ranges' for producer. */
		} else if (addrp->ProducerConsumer == ACPI_PRODUCER &&
		    rhdl->acpidev_consumer == B_FALSE) {
			uint64_t paddr;
			acpidev_ranges_t range;

			range.child_hi = high;
			range.child_mid = addrp->Address.Minimum >> 32;
			range.child_low = addrp->Address.Minimum & 0xFFFFFFFF;
			/* It's IO on parent side if Translation is true. */
			if (addrp->Info.Mem.Translation) {
				range.parent_hi = ACPIDEV_REG_TYPE_IO;
			} else {
				range.parent_hi = high;
			}
			paddr = addrp->Address.Minimum +
			    addrp->Address.TranslationOffset;
			range.parent_mid = paddr >> 32;
			range.parent_low = paddr & 0xFFFFFFFF;
			range.size_hi = addrp->Address.AddressLength >> 32;
			range.size_low = addrp->Address.AddressLength &
			    0xFFFFFFFF;
			rc = acpidev_resource_insert_range(rhdl, &range);
			if (ACPI_FAILURE(rc)) {
				ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to "
				    "insert range into resource handle.");
			}
		}
		break;

	case ACPI_IO_RANGE:
		high = ACPIDEV_REG_TYPE_IO;
		if (addrp->Decode == ACPI_SUB_DECODE) {
			high |= ACPIDEV_REG_SUB_DEC;
		}
		if (addrp->Info.Io.Translation) {
			high |= ACPIDEV_REG_TRANSLATED;
		}
		if (addrp->Info.Io.RangeType == ACPI_NON_ISA_ONLY_RANGES) {
			high |= ACPIDEV_REG_IO_RANGE_NONISA;
		} else if (addrp->Info.Io.RangeType == ACPI_ISA_ONLY_RANGES) {
			high |= ACPIDEV_REG_IO_RANGE_ISA;
		} else if (addrp->Info.Io.RangeType == ACPI_ENTIRE_RANGE) {
			high |= ACPIDEV_REG_IO_RANGE_FULL;
		} else {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: unknown IO range type %u.",
			    addrp->Info.Io.RangeType);
			rc = AE_ERROR;
			break;
		}
		if (addrp->Info.Io.TranslationType == ACPI_SPARSE_TRANSLATION) {
			high |= ACPIDEV_REG_IO_SPARSE;
		}

		/* Generate 'reg' for producer. */
		if (addrp->ProducerConsumer == ACPI_CONSUMER &&
		    rhdl->acpidev_consumer == B_TRUE) {
			acpidev_regspec_t reg;

			reg.phys_hi = high;
			reg.phys_mid = addrp->Address.Minimum >> 32;
			reg.phys_low = addrp->Address.Minimum & 0xFFFFFFFF;
			reg.size_hi = addrp->Address.AddressLength >> 32;
			reg.size_low = addrp->Address.AddressLength &
			    0xFFFFFFFF;
			rc = acpidev_resource_insert_reg(rhdl, &reg);
			if (ACPI_FAILURE(rc)) {
				ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to "
				    "insert regspec into resource handle.");
			}
		/* Generate 'ranges' for producer. */
		} else if (addrp->ProducerConsumer == ACPI_PRODUCER &&
		    rhdl->acpidev_consumer == B_FALSE) {
			uint64_t paddr;
			acpidev_ranges_t range;

			range.child_hi = high;
			range.child_mid = addrp->Address.Minimum >> 32;
			range.child_low = addrp->Address.Minimum & 0xFFFFFFFF;
			/* It's Memory on parent side if Translation is true. */
			if (addrp->Info.Io.Translation) {
				range.parent_hi = ACPIDEV_REG_TYPE_MEMORY;
			} else {
				range.parent_hi = high;
			}
			paddr = addrp->Address.Minimum +
			    addrp->Address.TranslationOffset;
			range.parent_mid = paddr >> 32;
			range.parent_low = paddr & 0xFFFFFFFF;
			range.size_hi = addrp->Address.AddressLength >> 32;
			range.size_low = addrp->Address.AddressLength &
			    0xFFFFFFFF;
			rc = acpidev_resource_insert_range(rhdl, &range);
			if (ACPI_FAILURE(rc)) {
				ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to "
				    "insert range into resource handle.");
			}
		}
		break;

	case ACPI_BUS_NUMBER_RANGE:
		/* Only support producer of BUS. */
		if (addrp->ProducerConsumer == ACPI_PRODUCER &&
		    rhdl->acpidev_consumer == B_FALSE) {
			uint64_t end;
			acpidev_bus_range_t bus;

			end = addrp->Address.Minimum +
			    addrp->Address.AddressLength;
			if (end < addrp->Address.Minimum || end > UINT_MAX) {
				ACPIDEV_DEBUG(CE_WARN, "!acpidev: bus range "
				    "in ADDRESS64 is invalid.");
				rc = AE_ERROR;
				break;
			}
			bus.bus_start = addrp->Address.Minimum & 0xFFFFFFFF;
			bus.bus_end = end & 0xFFFFFFFF;
			ASSERT(bus.bus_start <= bus.bus_end);
			rc = acpidev_resource_insert_bus(rhdl, &bus);
			if (ACPI_FAILURE(rc)) {
				ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to "
				    "insert bus range into resource handle.");
			}
		}
		break;

	default:
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: unknown resource type %u in ADDRESS64.",
		    addrp->ResourceType);
		rc = AE_BAD_PARAMETER;
	}

	return (rc);
}

static ACPI_STATUS
acpidev_resource_walk_producer(ACPI_RESOURCE *rscp, void *ctxp)
{
	ACPI_STATUS rc = AE_OK;
	acpidev_resource_handle_t rhdl;

	ASSERT(ctxp != NULL);
	rhdl = (acpidev_resource_handle_t)ctxp;
	ASSERT(rhdl->acpidev_consumer == B_FALSE);

	switch (rscp->Type) {
	case ACPI_RESOURCE_TYPE_DMA:
	case ACPI_RESOURCE_TYPE_IRQ:
	case ACPI_RESOURCE_TYPE_EXTENDED_IRQ:
	case ACPI_RESOURCE_TYPE_FIXED_IO:
	case ACPI_RESOURCE_TYPE_MEMORY24:
	case ACPI_RESOURCE_TYPE_MEMORY32:
	case ACPI_RESOURCE_TYPE_FIXED_MEMORY32:
	case ACPI_RESOURCE_TYPE_GENERIC_REGISTER:
	case ACPI_RESOURCE_TYPE_VENDOR:
		ACPIDEV_DEBUG(CE_NOTE,
		    "!acpidev: unsupported producer resource type %u, ignored.",
		    rscp->Type);
		break;

	case ACPI_RESOURCE_TYPE_IO:
	{
		acpidev_ranges_t range;

		range.child_hi = ACPIDEV_REG_TYPE_IO;
		range.child_hi |= ACPIDEV_REG_IO_RANGE_FULL;
		if (rscp->Data.Io.IoDecode == ACPI_DECODE_16) {
			range.child_hi |= ACPIDEV_REG_IO_DECODE16;
		}
		range.parent_hi = range.child_hi;
		range.parent_mid = range.child_mid = 0;
		range.parent_low = range.child_low = rscp->Data.Io.Minimum;
		range.size_hi = 0;
		range.size_low = rscp->Data.Io.AddressLength;
		if ((uint64_t)range.child_low + range.size_low > UINT16_MAX) {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid IO record, "
			    "IO max is out of range.");
			rc = AE_ERROR;
		} else if (range.size_low != 0) {
			rc = acpidev_resource_insert_range(rhdl, &range);
			if (ACPI_FAILURE(rc)) {
				ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to "
				    "insert range into resource handle.");
			}
		}
		break;
	}

	case ACPI_RESOURCE_TYPE_ADDRESS16:
	case ACPI_RESOURCE_TYPE_ADDRESS32:
	case ACPI_RESOURCE_TYPE_ADDRESS64:
	{
		ACPI_RESOURCE_ADDRESS64 addr64;

		if (rscp->Data.Address.ProducerConsumer != ACPI_PRODUCER) {
			ACPIDEV_DEBUG(CE_NOTE, "!acpidev: producer encountered "
			    "a CONSUMER resource, ignored.");
		} else if (ACPI_FAILURE(AcpiResourceToAddress64(rscp,
		    &addr64))) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: failed to convert resource to ADDR64.");
		} else if (ACPI_FAILURE(rc = acpidev_resource_address64(rhdl,
		    &addr64))) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: failed to handle ADDRESS resource.");
		}
		break;
	}

	case ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64:
	{
		ACPI_RESOURCE_ADDRESS64 addr64;

		if (rscp->Data.ExtAddress64.ProducerConsumer != ACPI_PRODUCER) {
			ACPIDEV_DEBUG(CE_NOTE, "!acpidev: producer encountered "
			    "a CONSUMER resource, ignored.");
			break;
		}

		*(ACPI_RESOURCE_ADDRESS *)&addr64 = rscp->Data.Address;
		addr64.Address.Granularity =
		    rscp->Data.ExtAddress64.Address.Granularity;
		addr64.Address.Minimum =
		    rscp->Data.ExtAddress64.Address.Minimum;
		addr64.Address.Maximum =
		    rscp->Data.ExtAddress64.Address.Maximum;
		addr64.Address.TranslationOffset =
		    rscp->Data.ExtAddress64.Address.TranslationOffset;
		addr64.Address.AddressLength =
		    rscp->Data.ExtAddress64.Address.AddressLength;
		if (ACPI_FAILURE(rc = acpidev_resource_address64(rhdl,
		    &addr64))) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: failed to handle EXTADDRESS resource.");
		}
		break;
	}

	case ACPI_RESOURCE_TYPE_START_DEPENDENT:
	case ACPI_RESOURCE_TYPE_END_DEPENDENT:
		ACPIDEV_DEBUG(CE_NOTE, "!acpidev: producer encountered "
		    "START_DEPENDENT or END_DEPENDENT tag, ignored.");
		break;

	case ACPI_RESOURCE_TYPE_END_TAG:
		/* Finish walking when we encounter END_TAG. */
		rc = AE_CTRL_TERMINATE;
		break;

	default:
		ACPIDEV_DEBUG(CE_NOTE,
		    "!acpidev: unknown ACPI resource type %u, ignored.",
		    rscp->Type);
		break;
	}

	return (rc);
}

static ACPI_STATUS
acpidev_resource_walk_consumer(ACPI_RESOURCE *rscp, void *ctxp)
{
	ACPI_STATUS rc = AE_OK;
	acpidev_resource_handle_t rhdl;

	ASSERT(ctxp != NULL);
	rhdl = (acpidev_resource_handle_t)ctxp;
	ASSERT(rhdl->acpidev_consumer == B_TRUE);

	switch (rscp->Type) {
	case ACPI_RESOURCE_TYPE_MEMORY24:
	case ACPI_RESOURCE_TYPE_GENERIC_REGISTER:
	case ACPI_RESOURCE_TYPE_VENDOR:
		ACPIDEV_DEBUG(CE_NOTE,
		    "!acpidev: unsupported consumer resource type %u, ignored.",
		    rscp->Type);
		break;

	case ACPI_RESOURCE_TYPE_EXTENDED_IRQ:
	{
		int i;

		if (rscp->Data.ExtendedIrq.ProducerConsumer != ACPI_CONSUMER) {
			ACPIDEV_DEBUG(CE_NOTE, "!acpidev: consumer encountered "
			    "a PRODUCER resource, ignored.");
			break;
		}
		for (i = 0; i < rscp->Data.ExtendedIrq.InterruptCount; i++) {
			if (ACPI_SUCCESS(acpidev_resource_insert_irq(rhdl,
			    rscp->Data.ExtendedIrq.Interrupts[i]))) {
				continue;
			}
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to insert"
			    "Extended IRQ into resource handle.");
			rc = AE_ERROR;
			break;
		}
		break;
	}

	case ACPI_RESOURCE_TYPE_IRQ:
	{
		int i;

		for (i = 0; i < rscp->Data.Irq.InterruptCount; i++) {
			if (ACPI_SUCCESS(acpidev_resource_insert_irq(rhdl,
			    rscp->Data.Irq.Interrupts[i]))) {
				continue;
			}
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to insert"
			    "IRQ into resource handle.");
			rc = AE_ERROR;
			break;
		}
		break;
	}

	case ACPI_RESOURCE_TYPE_DMA:
	{
		int i;

		for (i = 0; i < rscp->Data.Dma.ChannelCount; i++) {
			if (ACPI_SUCCESS(acpidev_resource_insert_dma(rhdl,
			    rscp->Data.Dma.Channels[i]))) {
				continue;
			}
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to insert"
			    "dma into resource handle.");
			rc = AE_ERROR;
			break;
		}
		break;
	}

	case ACPI_RESOURCE_TYPE_IO:
	case ACPI_RESOURCE_TYPE_FIXED_IO:
	{
		acpidev_regspec_t reg;

		reg.phys_hi = ACPIDEV_REG_TYPE_IO;
		reg.phys_hi |= ACPIDEV_REG_IO_RANGE_FULL;
		if (rscp->Type == ACPI_RESOURCE_TYPE_IO) {
			if (rscp->Data.Io.IoDecode == ACPI_DECODE_16) {
				reg.phys_hi |= ACPIDEV_REG_IO_DECODE16;
			}
			reg.phys_low = rscp->Data.Io.Minimum;
			reg.size_low = rscp->Data.Io.AddressLength;
		} else {
			reg.phys_hi |= ACPIDEV_REG_IO_DECODE16;
			reg.phys_low = rscp->Data.FixedIo.Address;
			reg.size_low = rscp->Data.FixedIo.AddressLength;
		}
		reg.phys_mid = 0;
		reg.size_hi = 0;
		if ((uint64_t)reg.phys_low + reg.size_low > UINT16_MAX) {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid IO/FIXEDIO "
			    "record, IO max is out of range.");
			rc = AE_ERROR;
		} else if (reg.size_low != 0) {
			rc = acpidev_resource_insert_reg(rhdl, &reg);
			if (ACPI_FAILURE(rc)) {
				ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to "
				    "insert reg into resource handle.");
			}
		}
		break;
	}

	case ACPI_RESOURCE_TYPE_MEMORY32:
	case ACPI_RESOURCE_TYPE_FIXED_MEMORY32:
	{
		acpidev_regspec_t reg;

		reg.phys_hi = ACPIDEV_REG_TYPE_MEMORY;
		reg.phys_hi |= ACPIDEV_REG_MEM_COHERENT_CA;
		if (rscp->Type == ACPI_RESOURCE_TYPE_MEMORY32) {
			if (rscp->Data.Memory32.WriteProtect ==
			    ACPI_READ_WRITE_MEMORY) {
				reg.phys_hi |= ACPIDEV_REG_MEM_WRITABLE;
			}
			reg.phys_low = rscp->Data.Memory32.Minimum;
			reg.size_low = rscp->Data.Memory32.AddressLength;
		} else {
			if (rscp->Data.FixedMemory32.WriteProtect ==
			    ACPI_READ_WRITE_MEMORY) {
				reg.phys_hi |= ACPIDEV_REG_MEM_WRITABLE;
			}
			reg.phys_low = rscp->Data.FixedMemory32.Address;
			reg.size_low = rscp->Data.FixedMemory32.AddressLength;
		}
		reg.phys_mid = 0;
		reg.size_hi = 0;
		if ((uint64_t)reg.phys_low + reg.size_low > UINT32_MAX) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: invalid MEMORY32/FIXEDMEMORY32 record, "
			    "memory max is out of range.");
			rc = AE_ERROR;
		} else if (reg.size_low != 0) {
			rc = acpidev_resource_insert_reg(rhdl, &reg);
			if (ACPI_FAILURE(rc)) {
				ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to "
				    "insert reg into resource handle.");
			}
		}
		break;
	}

	case ACPI_RESOURCE_TYPE_ADDRESS16:
	case ACPI_RESOURCE_TYPE_ADDRESS32:
	case ACPI_RESOURCE_TYPE_ADDRESS64:
	{
		ACPI_RESOURCE_ADDRESS64 addr64;

		if (rscp->Data.Address.ProducerConsumer != ACPI_CONSUMER) {
			ACPIDEV_DEBUG(CE_NOTE, "!acpidev: consumer encountered "
			    "a PRODUCER resource, ignored.");
		} else if (ACPI_FAILURE(AcpiResourceToAddress64(rscp,
		    &addr64))) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: failed to convert resource to ADDR64.");
		} else if (ACPI_FAILURE(rc = acpidev_resource_address64(rhdl,
		    &addr64))) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: failed to handle ADDRESS resource.");
		}
		break;
	}

	case ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64:
	{
		ACPI_RESOURCE_ADDRESS64 addr64;

		if (rscp->Data.ExtAddress64.ProducerConsumer != ACPI_CONSUMER) {
			ACPIDEV_DEBUG(CE_NOTE, "!acpidev: consumer encountered "
			    "a PRODUCER resource, ignored.");
			break;
		}

		*(ACPI_RESOURCE_ADDRESS *)&addr64 = rscp->Data.Address;
		addr64.Address.Granularity =
		    rscp->Data.ExtAddress64.Address.Granularity;
		addr64.Address.Minimum =
		    rscp->Data.ExtAddress64.Address.Minimum;
		addr64.Address.Maximum =
		    rscp->Data.ExtAddress64.Address.Maximum;
		addr64.Address.TranslationOffset =
		    rscp->Data.ExtAddress64.Address.TranslationOffset;
		addr64.Address.AddressLength =
		    rscp->Data.ExtAddress64.Address.AddressLength;
		if (ACPI_FAILURE(rc = acpidev_resource_address64(rhdl,
		    &addr64))) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: failed to handle EXTADDRESS resource.");
		}
		break;
	}

	case ACPI_RESOURCE_TYPE_START_DEPENDENT:
	case ACPI_RESOURCE_TYPE_END_DEPENDENT:
		ACPIDEV_DEBUG(CE_NOTE, "!acpidev: consumer encountered "
		    "START_DEPENDENT or END_DEPENDENT tag, ignored.");
		break;

	case ACPI_RESOURCE_TYPE_END_TAG:
		/* Finish walking when we encounter END_TAG. */
		rc = AE_CTRL_TERMINATE;
		break;

	default:
		ACPIDEV_DEBUG(CE_NOTE,
		    "!acpidev: unknown ACPI resource type %u, ignored.",
		    rscp->Type);
		break;
	}

	return (rc);
}

ACPI_STATUS
acpidev_resource_walk(ACPI_HANDLE hdl, char *method,
    boolean_t consumer, acpidev_resource_handle_t *rhdlp)
{
	ACPI_STATUS rc = AE_OK;
	ACPI_HANDLE mhdl = NULL;
	acpidev_resource_handle_t rhdl = NULL;

	ASSERT(hdl != NULL);
	ASSERT(method != NULL);
	ASSERT(rhdlp != NULL);
	if (hdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: hdl is NULL in acpidev_resource_walk().");
		return (AE_BAD_PARAMETER);
	} else if (method == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: method is NULL in acpidev_resource_walk().");
		return (AE_BAD_PARAMETER);
	} else if (rhdlp == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: resource handle ptr is NULL "
		    "in acpidev_resource_walk().");
		return (AE_BAD_PARAMETER);
	}

	/* Check whether method exists under object. */
	if (ACPI_FAILURE(AcpiGetHandle(hdl, method, &mhdl))) {
		char *objname = acpidev_get_object_name(hdl);
		ACPIDEV_DEBUG(CE_NOTE,
		    "!acpidev: method %s doesn't exist under %s",
		    method, objname);
		acpidev_free_object_name(objname);
		return (AE_NOT_FOUND);
	}

	/* Walk all resources. */
	rhdl = acpidev_resource_handle_alloc(consumer);
	if (consumer) {
		rc = AcpiWalkResources(hdl, method,
		    acpidev_resource_walk_consumer, rhdl);
	} else {
		rc = AcpiWalkResources(hdl, method,
		    acpidev_resource_walk_producer, rhdl);
	}
	if (ACPI_SUCCESS(rc)) {
		*rhdlp = rhdl;
	} else {
		acpidev_resource_handle_free(rhdl);
	}
	if (ACPI_FAILURE(rc)) {
		char *objname = acpidev_get_object_name(hdl);
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to walk resource from "
		    "method %s under %s.", method, objname);
		acpidev_free_object_name(objname);
	}

	return (rc);
}

ACPI_STATUS
acpidev_resource_process(acpidev_walk_info_t *infop, boolean_t consumer)
{
	ACPI_STATUS rc;
	char path[MAXPATHLEN];
	acpidev_resource_handle_t rhdl = NULL;

	ASSERT(infop != NULL);
	if (infop == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameter "
		    "in acpidev_resource_process().");
		return (AE_BAD_PARAMETER);
	}

	/* Walk all resources. */
	(void) ddi_pathname(infop->awi_dip, path);
	rc = acpidev_resource_walk(infop->awi_hdl, METHOD_NAME__CRS,
	    consumer, &rhdl);
	if (ACPI_FAILURE(rc)) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to walk ACPI resources of %s(%s).",
		    path, infop->awi_name);
		return (rc);
	}

	if (consumer) {
		/* Create device properties for consumer. */

		/* Create 'reg' and 'assigned-addresses' properties. */
		if (rhdl->acpidev_reg_count > 0 &&
		    ndi_prop_update_int_array(DDI_DEV_T_NONE, infop->awi_dip,
		    "reg", (int *)rhdl->acpidev_regp,
		    rhdl->acpidev_reg_count * sizeof (acpidev_regspec_t) /
		    sizeof (int)) != NDI_SUCCESS) {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to set "
			    "'reg' property for %s.", path);
			rc = AE_ERROR;
			goto out;
		}
		if (rhdl->acpidev_reg_count > 0 &&
		    ndi_prop_update_int_array(DDI_DEV_T_NONE, infop->awi_dip,
		    "assigned-addresses", (int *)rhdl->acpidev_regp,
		    rhdl->acpidev_reg_count * sizeof (acpidev_regspec_t) /
		    sizeof (int)) != NDI_SUCCESS) {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to set "
			    "'assigned-addresses' property for %s.", path);
			rc = AE_ERROR;
			goto out;
		}

		/* Create 'interrupts' property. */
		if (rhdl->acpidev_irq_count > 0 &&
		    ndi_prop_update_int_array(DDI_DEV_T_NONE, infop->awi_dip,
		    "interrupts", (int *)rhdl->acpidev_irqp,
		    rhdl->acpidev_irq_count) != NDI_SUCCESS) {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to set "
			    "'interrupts' property for %s.", path);
			rc = AE_ERROR;
			goto out;
		}

		/* Create 'dma-channels' property. */
		if (rhdl->acpidev_dma_count > 0 &&
		    ndi_prop_update_int_array(DDI_DEV_T_NONE, infop->awi_dip,
		    "dma-channels", (int *)rhdl->acpidev_dmap,
		    rhdl->acpidev_dma_count) != NDI_SUCCESS) {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to set "
			    "'dma-channels' property for %s.", path);
			rc = AE_ERROR;
			goto out;
		}

	} else {
		/* Create device properties for producer. */

		/* Create 'ranges' property. */
		if (rhdl->acpidev_range_count > 0 &&
		    ndi_prop_update_int_array(DDI_DEV_T_NONE, infop->awi_dip,
		    "ranges", (int *)rhdl->acpidev_rangep,
		    rhdl->acpidev_range_count * sizeof (acpidev_ranges_t) /
		    sizeof (int)) != NDI_SUCCESS) {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to set "
			    "'ranges' property for %s.", path);
			rc = AE_ERROR;
			goto out;
		}

		/* Create 'bus-range' property. */
		if (rhdl->acpidev_bus_count > 0 &&
		    ndi_prop_update_int_array(DDI_DEV_T_NONE, infop->awi_dip,
		    "bus-range", (int *)rhdl->acpidev_busp,
		    rhdl->acpidev_bus_count * sizeof (acpidev_bus_range_t) /
		    sizeof (int)) != NDI_SUCCESS) {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to set "
			    "'bus-range' property for %s.", path);
			rc = AE_ERROR;
			goto out;
		}
	}

out:
	/* Free resources allocated by acpidev_resource_walk. */
	acpidev_resource_handle_free(rhdl);

	return (rc);
}
