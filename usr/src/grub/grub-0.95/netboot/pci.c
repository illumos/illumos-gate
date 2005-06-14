
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2, or (at
 * your option) any later version.
 */

#include "grub.h"
#include "pci.h"

unsigned long virt_offset = 0;
unsigned long virt_to_phys(volatile const void *virt_addr)
{
	return ((unsigned long)virt_addr) + virt_offset;
}

void *phys_to_virt(unsigned long phys_addr)
{
	return (void *)(phys_addr - virt_offset);
}

#ifdef INCLUDE_3C595
extern struct pci_driver t595_driver;
#endif /* INCLUDE_3C595 */

#ifdef INCLUDE_3C90X
extern struct pci_driver a3c90x_driver;
#endif /* INCLUDE_3C90X */

#ifdef INCLUDE_DAVICOM
extern struct pci_driver davicom_driver;
#endif /* INCLUDE_DAVICOM */

#ifdef INCLUDE_E1000
extern struct pci_driver e1000_driver;
#endif /* INCLUDE_E1000 */

#ifdef INCLUDE_EEPRO100
extern struct pci_driver eepro100_driver;
#endif /* INCLUDE_EEPRO100 */

#ifdef INCLUDE_EPIC100
extern struct pci_driver epic100_driver;
#endif /* INCLUDE_EPIC100 */

#ifdef INCLUDE_FORCEDETH
extern struct pci_driver forcedeth_driver;
#endif /* INCLUDE_FORCEDETH */

#ifdef INCLUDE_NATSEMI
extern struct pci_driver natsemi_driver;
#endif /* INCLUDE_NATSEMI */

#ifdef INCLUDE_NS83820
extern struct pci_driver ns83820_driver;
#endif /* INCLUDE_NS83820 */

#ifdef INCLUDE_NS8390
extern struct pci_driver nepci_driver;
#endif /* INCLUDE_NS8390 */

#ifdef INCLUDE_PCNET32
extern struct pci_driver pcnet32_driver;
#endif /* INCLUDE_PCNET32 */

#ifdef INCLUDE_PNIC
extern struct pci_driver pnic_driver;
#endif /* INCLUDE_PNIC */

#ifdef INCLUDE_RTL8139
extern struct pci_driver rtl8139_driver;
#endif /* INCLUDE_RTL8139 */

#ifdef INCLUDE_SIS900
extern struct pci_driver sis900_driver;
extern struct pci_driver sis_bridge_driver;
#endif /* INCLUDE_SIS900 */

#ifdef INCLUDE_SUNDANCE
extern struct pci_driver sundance_driver;
#endif	/* INCLUDE_SUNDANCE */

#ifdef INCLUDE_TG3
extern struct pci_driver  tg3_driver;
#endif /* INCLUDE_TG3 */

#ifdef INCLUDE_TLAN
extern struct pci_driver tlan_driver;
#endif /* INCLUDE_TLAN */

#ifdef INCLUDE_TULIP
extern struct pci_driver tulip_driver;
#endif /* INCLUDE_TULIP */

#ifdef INCLUDE_UNDI
extern struct pci_driver undi_driver;
#endif /* INCLUDE_UNDI */

#ifdef INCLUDE_VIA_RHINE
extern struct pci_driver rhine_driver;
#endif/* INCLUDE_VIA_RHINE */

#ifdef INCLUDE_W89C840
extern struct pci_driver w89c840_driver;
#endif /* INCLUDE_W89C840 */

#ifdef INCLUDE_R8169
extern struct pci_driver r8169_driver;
#endif /* INCLUDE_R8169 */

static const struct pci_driver *pci_drivers[] = {

#ifdef INCLUDE_3C595
	&t595_driver,
#endif /* INCLUDE_3C595 */

#ifdef INCLUDE_3C90X
	&a3c90x_driver,
#endif /* INCLUDE_3C90X */

#ifdef INCLUDE_DAVICOM
	&davicom_driver,
#endif /* INCLUDE_DAVICOM */

#ifdef INCLUDE_E1000
	&e1000_driver,
#endif /* INCLUDE_E1000 */

#ifdef INCLUDE_EEPRO100
	&eepro100_driver,
#endif /* INCLUDE_EEPRO100 */

#ifdef INCLUDE_EPIC100
	&epic100_driver,
#endif /* INCLUDE_EPIC100 */

#ifdef INCLUDE_FORCEDETH
	&forcedeth_driver,
#endif /* INCLUDE_FORCEDETH */

#ifdef INCLUDE_NATSEMI
	&natsemi_driver,
#endif /* INCLUDE_NATSEMI */

#ifdef INCLUDE_NS83820
	&ns83820_driver,
#endif /* INCLUDE_NS83820 */

#ifdef INCLUDE_NS8390
	&nepci_driver,
#endif /* INCLUDE_NS8390 */

#ifdef INCLUDE_PCNET32
	&pcnet32_driver,
#endif /* INCLUDE_PCNET32 */

#ifdef INCLUDE_PNIC
	&pnic_driver,
#endif /* INCLUDE_PNIC */

#ifdef INCLUDE_RTL8139
	&rtl8139_driver,
#endif /* INCLUDE_RTL8139 */

#ifdef INCLUDE_SIS900
	&sis900_driver,
	&sis_bridge_driver,
#endif /* INCLUDE_SIS900 */

#ifdef INCLUDE_SUNDANCE
	&sundance_driver,
#endif /* INCLUDE_SUNDANCE */

#ifdef INCLUDE_TG3
	& tg3_driver,
#endif /* INCLUDE_TG3 */

#ifdef INCLUDE_TLAN
	&tlan_driver,
#endif /* INCLUDE_TLAN */

#ifdef INCLUDE_TULIP
	& tulip_driver,
#endif /* INCLUDE_TULIP */

#ifdef INCLUDE_VIA_RHINE
	&rhine_driver,
#endif/* INCLUDE_VIA_RHINE */

#ifdef INCLUDE_W89C840
	&w89c840_driver,
#endif /* INCLUDE_W89C840 */

#ifdef INCLUDE_R8169
	&r8169_driver,
#endif /* INCLUDE_R8169 */

/* We must be the last one */
#ifdef INCLUDE_UNDI
	&undi_driver,
#endif /* INCLUDE_UNDI */

	0
};

static void scan_drivers(
	int type, 
	uint32_t class, uint16_t vendor, uint16_t device,
	const struct pci_driver *last_driver, struct pci_device *dev)
{
	const struct pci_driver *skip_driver = last_driver;
	/* Assume there is only one match of the correct type */
	const struct pci_driver *driver;
	int i, j;
	
	for(j = 0; pci_drivers[j] != 0; j++){
		driver = pci_drivers[j];
		if (driver->type != type)
			continue;
		if (skip_driver) {
			if (skip_driver == driver) 
				skip_driver = 0;
			continue;
		}
		for(i = 0; i < driver->id_count; i++) {
			if ((vendor == driver->ids[i].vendor) &&
			    (device == driver->ids[i].dev_id)) {
				
				dev->driver = driver;
				dev->name   = driver->ids[i].name;

				goto out;
			}
		}
	}
	if (!class) {
		goto out;
	}
	for(j = 0; pci_drivers[j] != 0; j++){
		driver = pci_drivers[j];
		if (driver->type != type)
			continue;
		if (skip_driver) {
			if (skip_driver == driver)
				skip_driver = 0;
			continue;
		}
		if (last_driver == driver)
			continue;
		if ((class >> 8) == driver->class) {
			dev->driver = driver;
			dev->name   = driver->name;
			goto out;
		}
	}
 out:
	return;
}

void scan_pci_bus(int type, struct pci_device *dev)
{
	unsigned int first_bus, first_devfn;
	const struct pci_driver *first_driver;
	unsigned int devfn, bus, buses;
	unsigned char hdr_type = 0;
	uint32_t class;
	uint16_t vendor, device;
	uint32_t l, membase, ioaddr, romaddr;
	int reg;

	EnterFunction("scan_pci_bus");
	first_bus    = 0;
	first_devfn  = 0;
	first_driver = 0;
	if (dev->driver) {
		first_driver = dev->driver;
		first_bus    = dev->bus;
		first_devfn  = dev->devfn;
		/* Re read the header type on a restart */
		pcibios_read_config_byte(first_bus, first_devfn & ~0x7, 
			PCI_HEADER_TYPE, &hdr_type);
		dev->driver  = 0;
		dev->bus     = 0;
		dev->devfn   = 0;
	}
		
	/* Scan all PCI buses, until we find our card.
	 * We could be smart only scan the required buses but that
	 * is error prone, and tricky.
	 * By scanning all possible pci buses in order we should find
	 * our card eventually. 
	 */
	buses=256;
	for (bus = first_bus; bus < buses; ++bus) {
		for (devfn = first_devfn; devfn < 0xff; ++devfn, first_driver = 0) {
			if (PCI_FUNC (devfn) == 0)
				pcibios_read_config_byte(bus, devfn, PCI_HEADER_TYPE, &hdr_type);
			else if (!(hdr_type & 0x80))	/* not a multi-function device */
				continue;
			pcibios_read_config_dword(bus, devfn, PCI_VENDOR_ID, &l);
			/* some broken boards return 0 if a slot is empty: */
			if (l == 0xffffffff || l == 0x00000000) {
				continue;
			}
			vendor = l & 0xffff;
			device = (l >> 16) & 0xffff;

			pcibios_read_config_dword(bus, devfn, PCI_REVISION, &l);
			class = (l >> 8) & 0xffffff;
#if	DEBUG
		{
			int i;
			printf("%hhx:%hhx.%hhx [%hX/%hX] ---- ",
				bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
				vendor, device);
#if	DEBUG > 1
			for(i = 0; i < 256; i++) {
				unsigned char byte;
				if ((i & 0xf) == 0) {
					printf("%hhx: ", i);
				}
				pcibios_read_config_byte(bus, devfn, i, &byte);
				printf("%hhx ", byte);
				if ((i & 0xf) == 0xf) {
					printf("\n");
				}
			}
#endif

		}
#endif
			scan_drivers(type, class, vendor, device, first_driver, dev);
			if (!dev->driver){
#if DEBUG
				printf("No driver fit.\n");
#endif
				continue;
			}
#if DEBUG
			printf("Get Driver:\n");
#endif
			dev->devfn = devfn;
			dev->bus = bus;
			dev->class = class;
			dev->vendor = vendor;
			dev->dev_id = device;
			
			
			/* Get the ROM base address */
			pcibios_read_config_dword(bus, devfn, 
				PCI_ROM_ADDRESS, &romaddr);
			romaddr >>= 10;
			dev->romaddr = romaddr;
			
			/* Get the ``membase'' */
			pcibios_read_config_dword(bus, devfn,
				PCI_BASE_ADDRESS_1, &membase);
			dev->membase = membase;
				
			/* Get the ``ioaddr'' */
			for (reg = PCI_BASE_ADDRESS_0; reg <= PCI_BASE_ADDRESS_5; reg += 4) {
				pcibios_read_config_dword(bus, devfn, reg, &ioaddr);
				if ((ioaddr & PCI_BASE_ADDRESS_IO_MASK) == 0 || (ioaddr & PCI_BASE_ADDRESS_SPACE_IO) == 0)
					continue;
				
				
				/* Strip the I/O address out of the returned value */
				ioaddr &= PCI_BASE_ADDRESS_IO_MASK;
				
				/* Take the first one or the one that matches in boot ROM address */
				dev->ioaddr = ioaddr;
			}
#if DEBUG > 2
			printf("Found %s ROM address %#hx\n",
				dev->name, romaddr);
#endif
			LeaveFunction("scan_pci_bus");
			return;
		}
		first_devfn = 0;
	}
	first_bus = 0;
	LeaveFunction("scan_pci_bus");
}



/*
 *	Set device to be a busmaster in case BIOS neglected to do so.
 *	Also adjust PCI latency timer to a reasonable value, 32.
 */
void adjust_pci_device(struct pci_device *p)
{
	unsigned short	new_command, pci_command;
	unsigned char	pci_latency;

	pcibios_read_config_word(p->bus, p->devfn, PCI_COMMAND, &pci_command);
	new_command = pci_command | PCI_COMMAND_MASTER|PCI_COMMAND_IO;
	if (pci_command != new_command) {
#if DEBUG > 0
		printf(
			"The PCI BIOS has not enabled this device!\n"
			"Updating PCI command %hX->%hX. pci_bus %hhX pci_device_fn %hhX\n",
			   pci_command, new_command, p->bus, p->devfn);
#endif
		pcibios_write_config_word(p->bus, p->devfn, PCI_COMMAND, new_command);
	}
	pcibios_read_config_byte(p->bus, p->devfn, PCI_LATENCY_TIMER, &pci_latency);
	if (pci_latency < 32) {
#if DEBUG > 0
		printf("PCI latency timer (CFLT) is unreasonably low at %d. Setting to 32 clocks.\n", 
			pci_latency);
#endif
		pcibios_write_config_byte(p->bus, p->devfn, PCI_LATENCY_TIMER, 32);
	}
}

/*
 * Find the start of a pci resource.
 */
unsigned long pci_bar_start(struct pci_device *dev, unsigned int index)
{
	uint32_t lo, hi;
	unsigned long bar;
	pci_read_config_dword(dev, index, &lo);
	if (lo & PCI_BASE_ADDRESS_SPACE_IO) {
		bar = lo & PCI_BASE_ADDRESS_IO_MASK;
	} else {
		bar = 0;
		if ((lo & PCI_BASE_ADDRESS_MEM_TYPE_MASK) == PCI_BASE_ADDRESS_MEM_TYPE_64) {
			pci_read_config_dword(dev, index + 4, &hi);
			if (hi) {
				if (sizeof(unsigned long) > sizeof(uint32_t)) {
					/* It's REALLY interesting:-) */
					bar = (uint64_t)hi << 32;
				}
				else {
					printf("Unhandled 64bit BAR\n");
					return -1UL;
				}
			}
		}
		bar |= lo & PCI_BASE_ADDRESS_MEM_MASK;
	}
	return bar + pcibios_bus_base(dev->bus);
}

/*
 * Find the size of a pci resource.
 */
unsigned long pci_bar_size(struct pci_device *dev, unsigned int bar)
{
	uint32_t start, size;
	/* Save the original bar */
	pci_read_config_dword(dev, bar, &start);
	/* Compute which bits can be set */
	pci_write_config_dword(dev, bar, ~0);
	pci_read_config_dword(dev, bar, &size);
	/* Restore the original size */
	pci_write_config_dword(dev, bar, start);
	/* Find the significant bits */
	if (start & PCI_BASE_ADDRESS_SPACE_IO) {
		size &= PCI_BASE_ADDRESS_IO_MASK;
	} else {
		size &= PCI_BASE_ADDRESS_MEM_MASK;
	}
	/* Find the lowest bit set */
	size = size & ~(size - 1);
	return size;
}

/**
 * pci_find_capability - query for devices' capabilities 
 * @dev: PCI device to query
 * @cap: capability code
 *
 * Tell if a device supports a given PCI capability.
 * Returns the address of the requested capability structure within the
 * device's PCI configuration space or 0 in case the device does not
 * support it.  Possible values for @cap:
 *
 *  %PCI_CAP_ID_PM           Power Management 
 *
 *  %PCI_CAP_ID_AGP          Accelerated Graphics Port 
 *
 *  %PCI_CAP_ID_VPD          Vital Product Data 
 *
 *  %PCI_CAP_ID_SLOTID       Slot Identification 
 *
 *  %PCI_CAP_ID_MSI          Message Signalled Interrupts
 *
 *  %PCI_CAP_ID_CHSWP        CompactPCI HotSwap 
 */
int pci_find_capability(struct pci_device *dev, int cap)
{
	uint16_t status;
	uint8_t pos, id;
	uint8_t hdr_type;
	int ttl = 48;

	pci_read_config_word(dev, PCI_STATUS, &status);
	if (!(status & PCI_STATUS_CAP_LIST))
		return 0;
	pci_read_config_byte(dev, PCI_HEADER_TYPE, &hdr_type);
	switch (hdr_type & 0x7F) {
	case PCI_HEADER_TYPE_NORMAL:
	case PCI_HEADER_TYPE_BRIDGE:
	default:
		pci_read_config_byte(dev, PCI_CAPABILITY_LIST, &pos);
		break;
	case PCI_HEADER_TYPE_CARDBUS:
		pci_read_config_byte(dev, PCI_CB_CAPABILITY_LIST, &pos);
		break;
	}
	while (ttl-- && pos >= 0x40) {
		pos &= ~3;
		pci_read_config_byte(dev, pos + PCI_CAP_LIST_ID, &id);
#if	DEBUG > 0
		printf("Capability: %d\n", id);
#endif
		if (id == 0xff)
			break;
		if (id == cap)
			return pos;
		pci_read_config_byte(dev, pos + PCI_CAP_LIST_NEXT, &pos);
	}
	return 0;
}

