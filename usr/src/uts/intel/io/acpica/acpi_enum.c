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
 * Copyright (c) 2012 Gary Mills
 * Copyright 2018, Joyent, Inc.
 * Copyright 2021 Racktop Systems, Inc.
 */

/*
 * ACPI enumerator
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/note.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <util/sscanf.h>
#include <util/qsort.h>

/*
 * Used to track the interrupts used by a resource, as well as the set of
 * interrupts used overall. The IRQ values are ints for historical purposes
 * (the "interrupts" property has traditionally been an array of ints) even
 * though negative IRQ values do not make much sense.
 */
typedef struct intrs {
	int	*i_intrs;
	uint_t	i_num;
	uint_t	i_alloc;
} intrs_t;

static uint32_t acpi_enum_debug = 0x00;
#define	PARSE_RESOURCES_DEBUG	0x0001
#define	ISAPNP_LOOKUP_DEBUG	0x0002
#define	DEVICES_NOT_ENUMED	0x0004
#define	PARSE_RES_IRQ		0x0008
#define	PARSE_RES_DMA		0x0010
#define	PARSE_RES_MEMORY	0x0020
#define	PARSE_RES_IO		0x0040
#define	PARSE_RES_ADDRESS	0x0080
#define	ISA_DEVICE_ENUM		0x1000
#define	PROCESS_CIDS		0x2000

static dev_info_t *usedrdip = NULL;
static intrs_t used_interrupts;
static unsigned short used_dmas = 0;
typedef struct used_io_mem {
	unsigned int start_addr;
	unsigned int length;
	struct used_io_mem *next;
} used_io_mem_t;
static used_io_mem_t *used_io_head = NULL;
static used_io_mem_t *used_mem_head = NULL;
static int used_io_count = 0;
static int used_mem_count = 0;

#define	MAX_PARSED_ACPI_RESOURCES	255
#define	ACPI_ISA_LIMIT	16
static int dma[ACPI_ISA_LIMIT];
#define	ACPI_ELEMENT_PACKAGE_LIMIT	32
#define	EISA_ID_SIZE	7

static void
add_interrupt(intrs_t *intrs, int irq)
{
	/* We only want to add the value once */
	for (uint_t i = 0; i < intrs->i_num; i++) {
		if (intrs->i_intrs[i] == irq)
			return;
	}

	/*
	 * Initially, i_num and i_alloc will be 0, and we allocate
	 * i_intrs to hold ACPI_ISA_LIMIT values on the initial add attempt.
	 * Since ISA buses could only use at most ACPI_ISA_LIMIT (16)
	 * interrupts, this seems like a reasonable size. The extended IRQ
	 * resource however exists explicitly to support IRQ values beyond
	 * 16. That suggests it may be possible on some hardware to exceed
	 * the initial allocation. If we do exceed the initial allocation, we
	 * grow i_intrs in chunks of ACPI_ISA_LIMIT since that's as good an
	 * amount as any.
	 */
	if (intrs->i_num == intrs->i_alloc) {
		uint_t newlen = intrs->i_alloc + ACPI_ISA_LIMIT;
		size_t newsz = newlen * sizeof (int);
		size_t oldsz = intrs->i_alloc * sizeof (int);
		int *newar = kmem_alloc(newsz, KM_SLEEP);

		if (intrs->i_num > 0) {
			bcopy(intrs->i_intrs, newar, oldsz);
			kmem_free(intrs->i_intrs, oldsz);
		}

		intrs->i_intrs = newar;
		intrs->i_alloc = newlen;
	}

	intrs->i_intrs[intrs->i_num++] = irq;
}

/*
 * insert used io/mem in increasing order
 */
static void
insert_used_resource(used_io_mem_t *used, int *used_count, used_io_mem_t **head)
{
	used_io_mem_t *curr, *prev;

	(*used_count)++;
	if (*head == NULL) {
		*head = used;
		return;
	}
	curr = prev = *head;
	/* find a place to insert */
	while ((curr != NULL) &&
	    (curr->start_addr < used->start_addr)) {
		prev = curr;
		curr = curr->next;
	}
	if (prev == curr) {
		/* head */
		*head = used;
		used->next = curr;
		return;
	} else {
		prev->next = used;
	}
	used->next = curr;
}

static void
add_used_io_mem(struct regspec *io, int io_count)
{
	int i;
	used_io_mem_t *used;

	for (i = 0; i < io_count; i++) {
		used = kmem_zalloc(sizeof (used_io_mem_t),
		    KM_SLEEP);
		used->start_addr = io[i].regspec_addr;
		used->length = io[i].regspec_size;
		if (io[i].regspec_bustype == 1) {
			insert_used_resource(used, &used_io_count,
			    &used_io_head);
		} else {
			insert_used_resource(used, &used_mem_count,
			    &used_mem_head);
		}
	}
}

static void
parse_resources_irq(ACPI_RESOURCE *resource_ptr, intrs_t *intrs)
{
	uint_t i;

	for (i = 0; i < resource_ptr->Data.Irq.InterruptCount; i++) {
		uint8_t irq = resource_ptr->Data.Irq.Interrupts[i];

		add_interrupt(intrs, irq);
		add_interrupt(&used_interrupts, irq);

		if (acpi_enum_debug & PARSE_RES_IRQ) {
			cmn_err(CE_NOTE, "!%s() IRQ num %u, intr # = %u",
			    __func__, i, irq);
		}
	}
}

static void
parse_resources_extended_irq(ACPI_RESOURCE *resource_ptr, intrs_t *intrs)
{
	uint_t i;

	for (i = 0; i < resource_ptr->Data.ExtendedIrq.InterruptCount; i++) {
		uint32_t irq = resource_ptr->Data.ExtendedIrq.Interrupts[i];

		/*
		 * As noted in the definition of intrs_t above, traditionally
		 * the "interrupts" property is an array of ints. This is
		 * more precautionary than anything since it seems unlikely
		 * that anything will have an irq value > 2^31 anytime soon.
		 */
		if (irq > INT32_MAX) {
			if (acpi_enum_debug & PARSE_RES_IRQ) {
				cmn_err(CE_NOTE,
				    "!%s() intr # = %u out of range",
				    __func__, irq);
			}
			continue;
		}

		add_interrupt(intrs, irq);
		add_interrupt(&used_interrupts, irq);

		if (acpi_enum_debug & PARSE_RES_IRQ) {
			cmn_err(CE_NOTE, "!%s() IRQ num %u, intr # = %u",
			    __func__, i, irq);
		}
	}
}

static void
parse_resources_dma(ACPI_RESOURCE *resource_ptr, int *dma_count)
{
	int i;

	for (i = 0; i < resource_ptr->Data.Dma.ChannelCount; i++) {
		dma[(*dma_count)++] = resource_ptr->Data.Dma.Channels[i];
		used_dmas |= 1 << resource_ptr->Data.Dma.Channels[i];
		if (acpi_enum_debug & PARSE_RES_DMA) {
			cmn_err(CE_NOTE, "!parse_resources() "\
			    "DMA num %u, channel # = %u",
			    i, resource_ptr->Data.Dma.Channels[i]);
		}
	}
}

static void
parse_resources_io(ACPI_RESOURCE *resource_ptr, struct regspec *io,
    int *io_count)
{
	ACPI_RESOURCE_IO acpi_io = resource_ptr->Data.Io;

	if (acpi_io.AddressLength == 0)
		return;

	io[*io_count].regspec_bustype = 1; /* io */
	io[*io_count].regspec_size = acpi_io.AddressLength;
	io[*io_count].regspec_addr = acpi_io.Minimum;
	if (acpi_enum_debug & PARSE_RES_IO) {
		cmn_err(CE_NOTE, "!parse_resources() "\
		    "IO min 0x%X, max 0x%X, length: 0x%X",
		    acpi_io.Minimum,
		    acpi_io.Maximum,
		    acpi_io.AddressLength);
	}
	(*io_count)++;
}

static void
parse_resources_fixed_io(ACPI_RESOURCE *resource_ptr, struct regspec *io,
    int *io_count)
{
	ACPI_RESOURCE_FIXED_IO fixed_io = resource_ptr->Data.FixedIo;

	if (fixed_io.AddressLength == 0)
		return;

	io[*io_count].regspec_bustype = 1; /* io */
	io[*io_count].regspec_addr = fixed_io.Address;
	io[*io_count].regspec_size = fixed_io.AddressLength;
	if (acpi_enum_debug & PARSE_RES_IO) {
		cmn_err(CE_NOTE, "!parse_resources() "\
		    "Fixed IO 0x%X, length: 0x%X",
		    fixed_io.Address, fixed_io.AddressLength);
	}
	(*io_count)++;
}

static void
parse_resources_fixed_mem32(ACPI_RESOURCE *resource_ptr, struct regspec *io,
    int *io_count)
{
	ACPI_RESOURCE_FIXED_MEMORY32 fixed_mem32 =
	    resource_ptr->Data.FixedMemory32;

	if (fixed_mem32.AddressLength == 0)
		return;

	io[*io_count].regspec_bustype = 0; /* memory */
	io[*io_count].regspec_addr = fixed_mem32.Address;
	io[*io_count].regspec_size = fixed_mem32.AddressLength;
	if (acpi_enum_debug & PARSE_RES_MEMORY) {
		cmn_err(CE_NOTE, "!parse_resources() "\
		    "Fixed Mem 32 %ul, length: %ul",
		    fixed_mem32.Address, fixed_mem32.AddressLength);
	}
	(*io_count)++;
}

static void
parse_resources_mem32(ACPI_RESOURCE *resource_ptr, struct regspec *io,
    int *io_count)
{
	ACPI_RESOURCE_MEMORY32 mem32 = resource_ptr->Data.Memory32;

	if (mem32.AddressLength == 0)
		return;

	if (resource_ptr->Data.Memory32.Minimum ==
	    resource_ptr->Data.Memory32.Maximum) {
		io[*io_count].regspec_bustype = 0; /* memory */
		io[*io_count].regspec_addr = mem32.Minimum;
		io[*io_count].regspec_size = mem32.AddressLength;
		(*io_count)++;
		if (acpi_enum_debug & PARSE_RES_MEMORY) {
			cmn_err(CE_NOTE, "!parse_resources() "\
			    "Mem 32 0x%X, length: 0x%X",
			    mem32.Minimum, mem32.AddressLength);
		}
		return;
	}
	if (acpi_enum_debug & PARSE_RES_MEMORY) {
		cmn_err(CE_NOTE, "!parse_resources() "\
		    "MEM32 Min Max not equal!");
		cmn_err(CE_NOTE, "!parse_resources() "\
		    "Mem 32 Minimum 0x%X, Maximum: 0x%X",
		    mem32.Minimum, mem32.Maximum);
	}
}

static void
parse_resources_addr16(ACPI_RESOURCE *resource_ptr, struct regspec *io,
    int *io_count)
{
	ACPI_RESOURCE_ADDRESS16 addr16 =
	    resource_ptr->Data.Address16;

	if (addr16.Address.AddressLength == 0)
		return;

	if (acpi_enum_debug & PARSE_RES_ADDRESS) {
		if (addr16.ResourceType == ACPI_MEMORY_RANGE) {
			cmn_err(CE_NOTE, "!parse_resources() "\
			    "ADDRESS 16 MEMORY RANGE");
		} else
		if (addr16.ResourceType == ACPI_IO_RANGE) {
			cmn_err(CE_NOTE, "!parse_resources() "\
			    "ADDRESS 16 IO RANGE");
		} else {
			cmn_err(CE_NOTE, "!parse_resources() "\
			    "ADDRESS 16 OTHER");
		}
		cmn_err(CE_NOTE, "!parse_resources() "\
		    "%s "\
		    "MinAddressFixed 0x%X, "\
		    "MaxAddressFixed 0x%X, "\
		    "Minimum 0x%X, "\
		    "Maximum 0x%X, "\
		    "length: 0x%X\n",
		    addr16.ProducerConsumer == ACPI_CONSUMER ?
		    "CONSUMER" : "PRODUCER",
		    addr16.MinAddressFixed,
		    addr16.MaxAddressFixed,
		    addr16.Address.Minimum,
		    addr16.Address.Maximum,
		    addr16.Address.AddressLength);
	}
	if (addr16.ProducerConsumer == ACPI_PRODUCER ||
	    (addr16.ResourceType != ACPI_MEMORY_RANGE &&
	    addr16.ResourceType != ACPI_IO_RANGE)) {
		return;
	}
	if (addr16.Address.AddressLength > 0) {
		if (addr16.ResourceType == ACPI_MEMORY_RANGE) {
			/* memory */
			io[*io_count].regspec_bustype = 0;
		} else {
			/* io */
			io[*io_count].regspec_bustype = 1;
		}
		io[*io_count].regspec_addr = addr16.Address.Minimum;
		io[*io_count].regspec_size = addr16.Address.AddressLength;
		(*io_count)++;
	}
}

static void
parse_resources_addr32(ACPI_RESOURCE *resource_ptr, struct regspec *io,
    int *io_count)
{
	ACPI_RESOURCE_ADDRESS32 addr32 =
	    resource_ptr->Data.Address32;

	if (addr32.Address.AddressLength == 0)
		return;

	if (acpi_enum_debug & PARSE_RES_ADDRESS) {
		if (addr32.ResourceType == ACPI_MEMORY_RANGE) {
			cmn_err(CE_NOTE, "!parse_resources() "\
			    "ADDRESS 32 MEMORY RANGE");
		} else
		if (addr32.ResourceType == ACPI_IO_RANGE) {
			cmn_err(CE_NOTE, "!parse_resources() "\
			    "ADDRESS 32 IO RANGE");
		} else {
			cmn_err(CE_NOTE, "!parse_resources() "\
			    "ADDRESS 32 OTHER");
		}
		cmn_err(CE_NOTE, "!parse_resources() "\
		    "%s "\
		    "MinAddressFixed 0x%X, "\
		    "MaxAddressFixed 0x%X, "\
		    "Minimum 0x%X, "\
		    "Maximum 0x%X, "\
		    "length: 0x%X\n",
		    addr32.ProducerConsumer == ACPI_CONSUMER ?
		    "CONSUMER" : "PRODUCER",
		    addr32.MinAddressFixed,
		    addr32.MaxAddressFixed,
		    addr32.Address.Minimum,
		    addr32.Address.Maximum,
		    addr32.Address.AddressLength);
	}
	if (addr32.ProducerConsumer == ACPI_PRODUCER ||
	    (addr32.ResourceType != ACPI_MEMORY_RANGE &&
	    addr32.ResourceType != ACPI_IO_RANGE)) {
		return;
	}
	if (addr32.Address.AddressLength > 0) {
		if (addr32.ResourceType == ACPI_MEMORY_RANGE) {
			/* memory */
			io[*io_count].regspec_bustype = 0;
		} else {
			/* io */
			io[*io_count].regspec_bustype = 1;
		}
		io[*io_count].regspec_addr = addr32.Address.Minimum;
		io[*io_count].regspec_size = addr32.Address.AddressLength;
		(*io_count)++;
	}
}

static void
parse_resources_addr64(ACPI_RESOURCE *resource_ptr, struct regspec *io,
    int *io_count)
{
	ACPI_RESOURCE_ADDRESS64 addr64 =
	    resource_ptr->Data.Address64;

	if (addr64.Address.AddressLength == 0)
		return;

	if (acpi_enum_debug & PARSE_RES_ADDRESS) {
		if (addr64.ResourceType == ACPI_MEMORY_RANGE) {
			cmn_err(CE_NOTE, "!parse_resources() "\
			    "ADDRESS 64 MEMORY RANGE");
		} else
		if (addr64.ResourceType == ACPI_IO_RANGE) {
			cmn_err(CE_NOTE, "!parse_resources() "\
			    "ADDRESS 64 IO RANGE");
		} else {
			cmn_err(CE_NOTE, "!parse_resources() "\
			    "ADDRESS 64 OTHER");
		}
#ifdef _LP64
		cmn_err(CE_NOTE, "!parse_resources() "\
		    "%s "\
		    "MinAddressFixed 0x%X, "\
		    "MaxAddressFixed 0x%X, "\
		    "Minimum 0x%lX, "\
		    "Maximum 0x%lX, "\
		    "length: 0x%lX\n",
		    addr64.ProducerConsumer == ACPI_CONSUMER ?
		    "CONSUMER" : "PRODUCER",
		    addr64.MinAddressFixed,
		    addr64.MaxAddressFixed,
		    addr64.Address.Minimum,
		    addr64.Address.Maximum,
		    addr64.Address.AddressLength);
#else
		cmn_err(CE_NOTE, "!parse_resources() "\
		    "%s "\
		    "MinAddressFixed 0x%X, "\
		    "MaxAddressFixed 0x%X, "\
		    "Minimum 0x%llX, "\
		    "Maximum 0x%llX, "\
		    "length: 0x%llX\n",
		    addr64.ProducerConsumer == ACPI_CONSUMER ?
		    "CONSUMER" : "PRODUCER",
		    addr64.MinAddressFixed,
		    addr64.MaxAddressFixed,
		    addr64.Address.Minimum,
		    addr64.Address.Maximum,
		    addr64.Address.AddressLength);
#endif
	}
	if (addr64.ProducerConsumer == ACPI_PRODUCER ||
	    (addr64.ResourceType != ACPI_MEMORY_RANGE &&
	    addr64.ResourceType != ACPI_IO_RANGE)) {
		return;
	}
	if (addr64.Address.AddressLength > 0) {
		if (addr64.ResourceType == ACPI_MEMORY_RANGE) {
			/* memory */
			io[*io_count].regspec_bustype = 0;
		} else {
			/* io */
			io[*io_count].regspec_bustype = 1;
		}
		io[*io_count].regspec_addr = addr64.Address.Minimum;
		io[*io_count].regspec_size = addr64.Address.AddressLength;
		(*io_count)++;
	}
}

static ACPI_STATUS
parse_resources(ACPI_HANDLE handle, dev_info_t *xdip, char *path)
{
	ACPI_BUFFER	buf;
	ACPI_RESOURCE	*resource_ptr;
	ACPI_STATUS	status;
	char		*current_ptr, *last_ptr;
	struct		regspec *io;
	intrs_t		intrs = { 0 };
	int		io_count = 0, dma_count = 0;
	int		i;

	buf.Length = ACPI_ALLOCATE_BUFFER;
	status = AcpiGetCurrentResources(handle, &buf);
	switch (status) {
	case AE_OK:
		break;
	case AE_NOT_FOUND:
		/*
		 * Workaround for faulty DSDT tables that omit the _CRS
		 * method for the UAR3 device but have a valid _PRS method
		 * for that device.
		 */
		status = AcpiGetPossibleResources(handle, &buf);
		if (status != AE_OK) {
			return (status);
		}
		break;
	default:
		cmn_err(CE_WARN,
		    "!AcpiGetCurrentResources failed for %s, exception: %s",
		    path, AcpiFormatException(status));
		return (status);
		break;
	}
	io = kmem_zalloc(sizeof (struct regspec) *
	    MAX_PARSED_ACPI_RESOURCES, KM_SLEEP);
	current_ptr = buf.Pointer;
	last_ptr = (char *)buf.Pointer + buf.Length;
	while (current_ptr < last_ptr) {
		if (io_count >= MAX_PARSED_ACPI_RESOURCES) {
			break;
		}
		resource_ptr = (ACPI_RESOURCE *)current_ptr;
		current_ptr += resource_ptr->Length;
		switch (resource_ptr->Type) {
		case ACPI_RESOURCE_TYPE_END_TAG:
			current_ptr = last_ptr;
			break;
		case ACPI_RESOURCE_TYPE_IO:
			parse_resources_io(resource_ptr, io, &io_count);
			break;
		case ACPI_RESOURCE_TYPE_FIXED_IO:
			parse_resources_fixed_io(resource_ptr, io, &io_count);
			break;
		case ACPI_RESOURCE_TYPE_FIXED_MEMORY32:
			parse_resources_fixed_mem32(resource_ptr, io,
			    &io_count);
			break;
		case ACPI_RESOURCE_TYPE_MEMORY32:
			parse_resources_mem32(resource_ptr, io, &io_count);
			break;
		case ACPI_RESOURCE_TYPE_ADDRESS16:
			parse_resources_addr16(resource_ptr, io, &io_count);
			break;
		case ACPI_RESOURCE_TYPE_ADDRESS32:
			parse_resources_addr32(resource_ptr, io, &io_count);
			break;
		case ACPI_RESOURCE_TYPE_ADDRESS64:
			parse_resources_addr64(resource_ptr, io, &io_count);
			break;
		case ACPI_RESOURCE_TYPE_IRQ:
			parse_resources_irq(resource_ptr, &intrs);
			break;
		case ACPI_RESOURCE_TYPE_DMA:
			parse_resources_dma(resource_ptr, &dma_count);
			break;
		case ACPI_RESOURCE_TYPE_START_DEPENDENT:
			cmn_err(CE_NOTE,
			    "!ACPI source type"
			    " ACPI_RESOURCE_TYPE_START_DEPENDENT"
			    " not supported");
			break;
		case ACPI_RESOURCE_TYPE_END_DEPENDENT:
			cmn_err(CE_NOTE,
			    "!ACPI source type"
			    " ACPI_RESOURCE_TYPE_END_DEPENDENT"
			    " not supported");
			break;
		case ACPI_RESOURCE_TYPE_VENDOR:
			cmn_err(CE_NOTE,
			    "!ACPI source type"
			    " ACPI_RESOURCE_TYPE_VENDOR"
			    " not supported");
			break;
		case ACPI_RESOURCE_TYPE_MEMORY24:
			cmn_err(CE_NOTE,
			    "!ACPI source type"
			    " ACPI_RESOURCE_TYPE_MEMORY24"
			    " not supported");
			break;
		case ACPI_RESOURCE_TYPE_EXTENDED_IRQ:
			parse_resources_extended_irq(resource_ptr, &intrs);
			break;
		default:
		/* Some types are not yet implemented (See CA 6.4) */
			cmn_err(CE_NOTE,
			    "!ACPI resource type (0X%X) not yet supported",
			    resource_ptr->Type);
			break;
		}
	}

	if (io_count) {
		/*
		 * on LX50, you get interrupts of mouse and keyboard
		 * from separate PNP id...
		 */
		if (io_count == 2) {
			if ((io[0].regspec_addr == 0x60 &&
			    io[1].regspec_addr == 0x64) ||
			    (io[0].regspec_addr == 0x64 &&
			    io[1].regspec_addr == 0x60)) {
				intrs.i_num = 0;
				add_interrupt(&intrs, 0x1);
				add_interrupt(&intrs, 0xc);
				add_interrupt(&used_interrupts, 0x1);
				add_interrupt(&used_interrupts, 0xc);
			}
		}
		add_used_io_mem(io, io_count);
		if (xdip != NULL) {
			(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, xdip,
			    "reg", (int *)io, 3*io_count);
		}
	}
	if (intrs.i_num > 0) {
		if (xdip != NULL) {
			(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, xdip,
			    "interrupts", intrs.i_intrs, intrs.i_num);
		}
		kmem_free(intrs.i_intrs, intrs.i_alloc * sizeof (int));
	}
	if (dma_count && (xdip != NULL)) {
		(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, xdip,
		    "dma-channels", (int *)dma, dma_count);
	}
	AcpiOsFree(buf.Pointer);
	kmem_free(io, sizeof (struct regspec) * MAX_PARSED_ACPI_RESOURCES);
	return (status);
}

/* keyboard mouse is under i8042, everything else under isa */
static dev_info_t *
get_bus_dip(const char *nodename, dev_info_t *isa_dip)
{
	static dev_info_t *i8042_dip = NULL;
	struct regspec i8042_regs[] = {
		{1, 0x60, 0x1},
		{1, 0x64, 0x1}
	};
	int i8042_intrs[] = {0x1, 0xc};

	if (strcmp(nodename, "keyboard") != 0 &&
	    strcmp(nodename, "mouse") != 0)
		return (isa_dip);

	if (i8042_dip)
		return (i8042_dip);

	ndi_devi_alloc_sleep(isa_dip, "i8042", (pnode_t)DEVI_SID_NODEID,
	    &i8042_dip);
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, i8042_dip,
	    "reg", (int *)i8042_regs, 6);
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, i8042_dip,
	    "interrupts", (int *)i8042_intrs, 2);
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, i8042_dip,
	    "unit-address", "1,60");
	(void) ndi_devi_bind_driver(i8042_dip, 0);
	return (i8042_dip);
}

void
eisa_to_str(ACPI_INTEGER id, char *np)
{
	static const char hextab[] = "0123456789ABCDEF";

	/*
	 *  Expand an EISA device name:
	 *
	 * This routine converts a 32-bit EISA device "id" to a
	 * 7-byte ASCII device name, which is stored at "np".
	 */

	*np++ = '@' + ((id >> 2)  & 0x1F);
	*np++ = '@' + ((id << 3)  & 0x18) + ((id >> 13) & 0x07);
	*np++ = '@' + ((id >> 8)  & 0x1F);
	*np++ = hextab[(id >> 20) & 0x0F];
	*np++ = hextab[(id >> 16) & 0x0F];
	*np++ = hextab[(id >> 28) & 0x0F];
	*np++ = hextab[(id >> 24) & 0x0F];
	*np = 0;
}

/*
 * process_cids() -- process multiple CIDs in a package
 */
static void
process_cids(ACPI_OBJECT *rv, device_id_t **dd)
{
	device_id_t *d;
	char tmp_cidstr[8];	/* 7-character EISA ID */
	int i;

	if ((rv->Package.Count == 0) || rv->Package.Elements == NULL)
		return; /* empty package */

	/*
	 * Work the package 'backwards' so the resulting list is
	 * in original order of preference.
	 */
	for (i = rv->Package.Count - 1; i >= 0; i--) {
		/* get the actual acpi_object */
		ACPI_OBJECT obj = rv->Package.Elements[i];
		switch (obj.Type) {
		case ACPI_TYPE_INTEGER:
			eisa_to_str(obj.Integer.Value, tmp_cidstr);
			d = kmem_zalloc(sizeof (device_id_t), KM_SLEEP);
			d->id = strdup(tmp_cidstr);
			d->next = *dd;
			*dd = d;
			break;
		case ACPI_TYPE_STRING:
			d = kmem_zalloc(sizeof (device_id_t), KM_SLEEP);
			d->id = strdup(obj.String.Pointer);
			d->next = *dd;
			*dd = d;
			break;
		default:
			if (acpi_enum_debug & PROCESS_CIDS) {
				cmn_err(CE_NOTE, "!unexpected CID type: %d",
				    obj.Type);
			}
			break;
		}
	}
}

/*
 * Convert "raw" PNP and ACPI IDs to IEEE 1275-compliant form.
 * Some liberty is taken here, treating "ACPI" as a special form
 * of PNP vendor ID.  strsize specifies size of buffer.
 */
static void
convert_to_pnp1275(char *pnpid, char *str, int strsize)
{
	char	vendor[5];
	uint_t	id;

	if (strncmp(pnpid, "ACPI", 4) == 0) {
		/* Assume ACPI ID: ACPIxxxx */
		sscanf(pnpid, "%4s%x", vendor, &id);
	} else {
		/* Assume PNP ID: aaaxxxx */
		sscanf(pnpid, "%3s%x", vendor, &id);
	}

	snprintf(str, strsize, "pnp%s,%x", vendor, id);
}

/*
 * Given a list of device ID elements in most-to-least-specific
 * order, create a "compatible" property.
 */
static void
create_compatible_property(dev_info_t *dip, device_id_t *ids)
{
	char		**strs;
	int		list_len, i;
	device_id_t	*d;

	/* count list length */
	list_len = 0;
	d = ids;
	while (d != NULL) {
		list_len++;
		d = d->next;
	}

	strs = kmem_zalloc(list_len * sizeof (char *), KM_SLEEP);
	i = 0;
	d = ids;
	while (d != NULL) {
		/* strlen("pnpXXXX,xxxx") + 1 = 13 */
		strs[i] = kmem_zalloc(13, KM_SLEEP);
		convert_to_pnp1275(d->id, strs[i++], 13);
		d = d->next;
	}

	/* update property */
	(void) ndi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    "compatible", strs, list_len);


	/* free memory */
	for (i = 0; i < list_len; i++)
		kmem_free(strs[i], 13);

	kmem_free(strs, list_len * sizeof (char *));
}

/*
 * isa_acpi_callback()
 */
static ACPI_STATUS
isa_acpi_callback(ACPI_HANDLE ObjHandle, uint32_t NestingLevel, void *a,
    void **b)
{
	_NOTE(ARGUNUSED(NestingLevel, b))

	ACPI_BUFFER		rb;
	ACPI_DEVICE_INFO	*info = NULL;
	char			*path = NULL;
	char			*hidstr = NULL;
	char			tmp_cidstr[8];	/* EISAID size */
	dev_info_t		*dip = (dev_info_t *)a;
	dev_info_t		*xdip = NULL;
	device_id_t		*d, *device_ids = NULL;
	const isapnp_desc_t	*m;
	int			status;

	/*
	 * get full ACPI pathname for object
	 */
	rb.Length = ACPI_ALLOCATE_BUFFER;
	rb.Pointer = NULL;
	if (AcpiGetName(ObjHandle, ACPI_FULL_PATHNAME, &rb) != AE_OK) {
		cmn_err(CE_WARN, "!acpi_enum: could not get pathname");
		goto done;
	}
	path = (char *)rb.Pointer;

	/*
	 * Get device info object
	 */
	if (AcpiGetObjectInfo(ObjHandle, &info) != AE_OK) {
		cmn_err(CE_WARN, "!acpi_enum: could not get device"
		    " info for %s", path);
		goto done;
	}

	/*
	 * If device isn't present, we don't enumerate
	 * NEEDSWORK: what about docking bays and the like?
	 */
	if (ACPI_FAILURE(acpica_get_object_status(ObjHandle, &status))) {
		cmn_err(CE_WARN, "!acpi_enum: no _STA for %s", path);
		goto done;
	}

	/*
	 * CA 6.3.6 _STA method
	 * Bit 0 -- device is present
	 * Bit 1 -- device is enabled
	 * Bit 2 -- device is shown in UI
	 */
	if ((status & 0x7) != 0x7) {
		if (acpi_enum_debug & DEVICES_NOT_ENUMED) {
			cmn_err(CE_NOTE, "!parse_resources() "
			    "Bad status 0x%x for %s",
			    status, path);
		}
		goto done;
	}

	/*
	 * Keep track of _HID value
	 */
	if (!(info->Valid & ACPI_VALID_HID)) {
		/* No _HID, we skip this node */
		if (acpi_enum_debug & DEVICES_NOT_ENUMED) {
			cmn_err(CE_NOTE, "!parse_resources() "
			    "No _HID for %s", path);
		}
		goto done;
	}
	hidstr = info->HardwareId.String;

	/*
	 * Attempt to get _CID value
	 */
	rb.Length = ACPI_ALLOCATE_BUFFER;
	rb.Pointer = NULL;
	if (AcpiEvaluateObject(ObjHandle, "_CID", NULL, &rb) == AE_OK &&
	    rb.Length != 0) {
		ACPI_OBJECT *rv = rb.Pointer;

		switch (rv->Type) {
		case ACPI_TYPE_INTEGER:
			eisa_to_str(rv->Integer.Value, tmp_cidstr);
			d = kmem_zalloc(sizeof (device_id_t), KM_SLEEP);
			d->id = strdup(tmp_cidstr);
			d->next = device_ids;
			device_ids = d;
			break;
		case ACPI_TYPE_STRING:
			d = kmem_zalloc(sizeof (device_id_t), KM_SLEEP);
			d->id = strdup(rv->String.Pointer);
			d->next = device_ids;
			device_ids = d;
			break;
		case ACPI_TYPE_PACKAGE:
			process_cids(rv, &device_ids);
			break;
		default:
			break;
		}
		AcpiOsFree(rb.Pointer);
	}

	/*
	 * Add _HID last so it's at the head of the list
	 */
	d = kmem_zalloc(sizeof (device_id_t), KM_SLEEP);
	d->id = strdup(hidstr);
	d->next = device_ids;
	device_ids = d;

	/*
	 * isapnp_desc_lookup() expects _HID first in device_ids
	 */
	if ((m = isapnp_desc_lookup(device_ids)) !=  NULL) {
		/* PNP description found in isapnp table */
		if (!(strncmp(hidstr, "ACPI", 4))) {
			dip = ddi_root_node();
		} else {
			dip = get_bus_dip(m->ipnp_name, dip);
		}
		ndi_devi_alloc_sleep(dip, m->ipnp_name,
		    (pnode_t)DEVI_SID_NODEID, &xdip);
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, xdip,
		    "model", (char *)m->ipnp_model);

		if (m->ipnp_compat != NULL) {
			(void) ndi_prop_update_string(DDI_DEV_T_NONE, xdip,
			    "compatible", (char *)m->ipnp_compat);
		}
	} else {
		(void) parse_resources(ObjHandle, xdip, path);
		goto done;
	}

	(void) ndi_prop_update_string(DDI_DEV_T_NONE, xdip, "acpi-namespace",
	    path);

	(void) parse_resources(ObjHandle, xdip, path);

	/* Special processing for mouse and keyboard devices per IEEE 1275 */
	if (strcmp(m->ipnp_name, "keyboard") == 0) {
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, xdip, "reg", 0);
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, xdip,
		    "device-type", "keyboard");
	} else if (strcmp(m->ipnp_name, "mouse") == 0) {
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, xdip, "reg", 1);
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, xdip,
		    "device-type", "mouse");
	}

	/*
	 * Create default "compatible" property if required
	 */
	if (!ddi_prop_exists(DDI_DEV_T_ANY, xdip,
	    DDI_PROP_DONTPASS, "compatible"))
		create_compatible_property(xdip, device_ids);

	(void) ndi_devi_bind_driver(xdip, 0);

done:
	/* discard _HID/_CID list */
	d = device_ids;
	while (d != NULL) {
		device_id_t *next;

		next = d->next;
		if (d->id != NULL)
			strfree(d->id);

		kmem_free(d, sizeof (device_id_t));
		d = next;
	}

	if (path != NULL)
		AcpiOsFree(path);
	if (info != NULL)
		AcpiOsFree(info);

	return (AE_OK);
}

static int
irq_cmp(const void *a, const void *b)
{
	const int *l = a;
	const int *r = b;

	if (*l < *r)
		return (-1);
	if (*l > *r)
		return (1);
	return (0);
}

static void
used_res_interrupts(void)
{
	if (used_interrupts.i_num == 0)
		return;

	/*
	 * add_known_used_resources() in usr/src/uts/i86pc.io/isa.c (used
	 * when ACPI enumeration is disabled) states that the interrupt values
	 * in the interrupts property of usedrdip should be in increasing order.
	 * It does not state the reason for the requirement, however out of
	 * an abundance of caution, we ensure the interrupt values are also
	 * stored in the interrupts property in increasing order.
	 */
	qsort(used_interrupts.i_intrs, used_interrupts.i_num, sizeof (int),
	    irq_cmp);

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, usedrdip,
	    "interrupts", used_interrupts.i_intrs, used_interrupts.i_num);

	kmem_free(used_interrupts.i_intrs,
	    used_interrupts.i_alloc * sizeof (int));
	bzero(&used_interrupts, sizeof (used_interrupts));
}

static void
used_res_dmas(void)
{
	int dma[ACPI_ISA_LIMIT];
	int count = 0;
	int i;

	for (i = 0; i < ACPI_ISA_LIMIT; i++) {
		if ((used_dmas >> i) & 1) {
			dma[count++] = i;
		}
	}
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, usedrdip,
	    "dma-channels", (int *)dma, count);
}

static void
used_res_io_mem(char *nodename, int *count, used_io_mem_t **head)
{
	int *io;
	used_io_mem_t *used = *head;
	int i;

	*count *= 2;
	io = kmem_zalloc(sizeof (int)*(*count), KM_SLEEP);
	for (i = 0; i < *count; i += 2) {
		used_io_mem_t *prev;
		if (used != NULL) {
			io[i] = used->start_addr;
			io[i+1] = used->length;
			prev = used;
			used = used->next;
			kmem_free(prev, sizeof (used_io_mem_t));
		}
	}
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, usedrdip,
	    nodename, (int *)io, *count);
	kmem_free(io, sizeof (int) * (*count));
	*head = NULL;
}

/*
 * acpi_isa_device_enum() -- call from isa nexus driver
 * returns 1 if deviced enumeration is successful
 *         0 if deviced enumeration fails
 */
int
acpi_isa_device_enum(dev_info_t *isa_dip)
{
	char *acpi_prop;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "acpi_enum_debug", &acpi_prop) ==
	    DDI_PROP_SUCCESS) {
		unsigned long data;
		if (ddi_strtoul(acpi_prop, NULL, 0, &data) == 0) {
			acpi_enum_debug = (uint32_t)data;
			e_ddi_prop_remove(DDI_DEV_T_NONE, ddi_root_node(),
			    "acpi_enum_debug");
			e_ddi_prop_update_int(DDI_DEV_T_NONE,
			    ddi_root_node(), "acpi_enum_debug", data);
		}
		ddi_prop_free(acpi_prop);
	}

	if (acpi_enum_debug & ISA_DEVICE_ENUM) {
		cmn_err(CE_NOTE, "!acpi_isa_device_enum() called");
	}

	if (acpica_init() != AE_OK) {
		cmn_err(CE_WARN, "!acpi_isa_device_enum: init failed");
		/*
		 * Note: `acpi-enum` is a private boolean property that is
		 * respected both as a user-set property (by the isa nexus
		 * which calls us), and set by us on failure (here) to
		 * communicate to the i8042 nexus that ACPI enumeration has
		 * not taken place and that it must enumerate.
		 */
		(void) e_ddi_prop_update_string(DDI_DEV_T_NONE,
		    ddi_root_node(), "acpi-enum", "off");
		return (0);
	}

	usedrdip = ddi_find_devinfo("used-resources", -1, 0);
	if (usedrdip == NULL) {
		ndi_devi_alloc_sleep(ddi_root_node(), "used-resources",
		    (pnode_t)DEVI_SID_NODEID, &usedrdip);

	}

	/*
	 * Do the actual enumeration.  Avoid AcpiGetDevices because it
	 * has an unnecessary internal callback that duplicates
	 * determining if the device is present.
	 */
	(void) AcpiWalkNamespace(ACPI_TYPE_DEVICE, ACPI_ROOT_OBJECT,
	    UINT32_MAX, isa_acpi_callback, NULL, isa_dip, NULL);

	used_res_interrupts();
	used_res_dmas();
	used_res_io_mem("device-memory", &used_mem_count, &used_mem_head);
	used_res_io_mem("io-space", &used_io_count, &used_io_head);
	(void) ndi_devi_bind_driver(usedrdip, 0);

	return (1);
}
