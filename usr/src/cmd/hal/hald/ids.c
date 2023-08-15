/***************************************************************************
 * CVSID: $Id$
 *
 * ids.c : Lookup names from hardware identifiers
 *
 * Copyright (C) 2004 David Zeuthen, <david@fubar.dk>
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

#include "logger.h"

#include "ids.h"

/** Pointer to where the pci.ids file is loaded */
static char *pci_ids = NULL;

/** Length of data store at at pci_ids */
static unsigned int pci_ids_len;

/** Iterator position into pci_ids */
static unsigned int pci_ids_iter_pos;

/** Initialize the pci.ids line iterator to the beginning of the file */
static void
pci_ids_line_iter_init ()
{
	pci_ids_iter_pos = 0;
}

/** Maximum length of lines in pci.ids */
#define PCI_IDS_MAX_LINE_LEN 512

/** Get the next line from pci.ids
 *
 *  @param  line_len            Pointer to where number of bytes in line will
 *                              be stored
 *  @return                     Pointer to the line; only valid until the
 *                              next invocation of this function
 */
static char *
pci_ids_line_iter_get_line (unsigned int *line_len)
{
	unsigned int i;
	static char line[PCI_IDS_MAX_LINE_LEN];

	for (i = 0;
	     pci_ids_iter_pos < pci_ids_len &&
	     i < PCI_IDS_MAX_LINE_LEN - 1 &&
	     pci_ids[pci_ids_iter_pos] != '\n'; i++, pci_ids_iter_pos++) {
		line[i] = pci_ids[pci_ids_iter_pos];
	}

	line[i] = '\0';
	if (line_len != NULL)
		*line_len = i;

	pci_ids_iter_pos++;

	return line;
}

/** See if there are more lines to process in pci.ids
 *
 *  @return                     #TRUE iff there are more lines to process
 */
static dbus_bool_t
pci_ids_line_iter_has_more ()
{
	return pci_ids_iter_pos < pci_ids_len;
}


/** Find the names for a PCI device.
 *
 *  The pointers returned are only valid until the next invocation of this
 *  function.
 *
 *  @param  vendor_id           PCI vendor id or 0 if unknown
 *  @param  product_id          PCI product id or 0 if unknown
 *  @param  subsys_vendor_id    PCI subsystem vendor id or 0 if unknown
 *  @param  subsys_product_id   PCI subsystem product id or 0 if unknown
 *  @param  vendor_name         Set to pointer of result or NULL
 *  @param  product_name        Set to pointer of result or NULL
 *  @param  subsys_vendor_name  Set to pointer of result or NULL
 *  @param  subsys_product_name Set to pointer of result or NULL
 */
void
ids_find_pci (int vendor_id, int product_id,
	      int subsys_vendor_id, int subsys_product_id,
	      char **vendor_name, char **product_name,
	      char **subsys_vendor_name, char **subsys_product_name)
{
	char *line;
	unsigned int i;
	unsigned int line_len;
	unsigned int num_tabs;
	char rep_vi[8];
	char rep_pi[8];
	char rep_svi[8];
	char rep_spi[8];
	dbus_bool_t vendor_matched = FALSE;
	dbus_bool_t product_matched = FALSE;
	static char store_vn[PCI_IDS_MAX_LINE_LEN];
	static char store_pn[PCI_IDS_MAX_LINE_LEN];
	static char store_svn[PCI_IDS_MAX_LINE_LEN];
	static char store_spn[PCI_IDS_MAX_LINE_LEN];

	snprintf (rep_vi, 8, "%04x", vendor_id);
	snprintf (rep_pi, 8, "%04x", product_id);
	snprintf (rep_svi, 8, "%04x", subsys_vendor_id);
	snprintf (rep_spi, 8, "%04x", subsys_product_id);

	*vendor_name = NULL;
	*product_name = NULL;
	*subsys_vendor_name = NULL;
	*subsys_product_name = NULL;

	for (pci_ids_line_iter_init (); pci_ids_line_iter_has_more ();) {
		line = pci_ids_line_iter_get_line (&line_len);

		/* skip lines with no content */
		if (line_len < 4)
			continue;

		/* skip comments */
		if (line[0] == '#')
			continue;

		/* count number of tabs */
		num_tabs = 0;
		for (i = 0; i < line_len; i++) {
			if (line[i] != '\t')
				break;
			num_tabs++;
		}

		switch (num_tabs) {
		case 0:
			/* vendor names */
			vendor_matched = FALSE;

			/* first check subsys_vendor_id, if haven't done
			 * already */
			if (*subsys_vendor_name == NULL
			    && subsys_vendor_id != 0) {
				if ((*((dbus_uint32_t *) line)) ==
				    (*((dbus_uint32_t *) rep_svi))) {
					/* found it */
					for (i = 4; i < line_len; i++) {
						if (!isspace (line[i]))
							break;
					}
					strncpy (store_svn, line + i,
						 PCI_IDS_MAX_LINE_LEN);
					*subsys_vendor_name = store_svn;
				}
			}

			/* check vendor_id */
			if (vendor_id != 0) {
				if (memcmp (line, rep_vi, 4) == 0) {
					/* found it */
					vendor_matched = TRUE;

					for (i = 4; i < line_len; i++) {
						if (!isspace (line[i]))
							break;
					}
					strncpy (store_vn, line + i,
						 PCI_IDS_MAX_LINE_LEN);
					*vendor_name = store_vn;
				}
			}

			break;

		case 1:
			product_matched = FALSE;

			/* product names */
			if (!vendor_matched)
				continue;

			/* check product_id */
			if (product_id != 0) {
				if (memcmp (line + 1, rep_pi, 4) == 0) {
					/* found it */

					product_matched = TRUE;

					for (i = 5; i < line_len; i++) {
						if (!isspace (line[i]))
							break;
					}
					strncpy (store_pn, line + i,
						 PCI_IDS_MAX_LINE_LEN);
					*product_name = store_pn;
				}
			}
			break;

		case 2:
			/* subsystem_vendor subsystem_product */
			if (!vendor_matched || !product_matched)
				continue;

			/* check product_id */
			if (subsys_vendor_id != 0
			    && subsys_product_id != 0) {
				if (memcmp (line + 2, rep_svi, 4) == 0
				    && memcmp (line + 7, rep_spi,
					       4) == 0) {
					/* found it */
					for (i = 11; i < line_len; i++) {
						if (!isspace (line[i]))
							break;
					}
					strncpy (store_spn, line + i,
						 PCI_IDS_MAX_LINE_LEN);
					*subsys_product_name = store_spn;
				}
			}

			break;

		default:
			break;
		}

	}
}

/** Free resources used by to store the PCI database
 *
 *  @param                      #FALSE if the PCI database wasn't loaded
 */
static dbus_bool_t
pci_ids_free ()
{
	if (pci_ids != NULL) {
		free (pci_ids);
		pci_ids = NULL;
		return TRUE;
	}
	return FALSE;
}

/** Load the PCI database used for mapping vendor, product, subsys_vendor
 *  and subsys_product numbers into names.
 *
 *  @param  path                Path of the pci.ids file, e.g.
 *                              /usr/share/hwdata/pci.ids
 *  @return                     #TRUE if the file was succesfully loaded
 */
static dbus_bool_t
pci_ids_load (const char *path)
{
	FILE *fp;
	unsigned int num_read;

	fp = fopen (path, "r");
	if (fp == NULL) {
		HAL_ERROR (("couldn't open PCI database at %s,", path));
		return FALSE;
	}

	fseek (fp, 0, SEEK_END);
	pci_ids_len = ftell (fp);
	fseek (fp, 0, SEEK_SET);

	pci_ids = malloc (pci_ids_len);
	if (pci_ids == NULL) {
		DIE (("Couldn't allocate %d bytes for PCI database file\n",
		      pci_ids_len));
	}

	num_read = fread (pci_ids, sizeof (char), pci_ids_len, fp);
	if (pci_ids_len != num_read) {
		HAL_ERROR (("Error loading PCI database file"));
		pci_ids_free();
		fclose(fp);
		return FALSE;
	}

	fclose(fp);
	return TRUE;
}

/*==========================================================================*/

/** Pointer to where the usb.ids file is loaded */
static char *usb_ids = NULL;

/** Length of data store at at usb_ids */
static unsigned int usb_ids_len;

/** Iterator position into usb_ids */
static unsigned int usb_ids_iter_pos;

/** Initialize the usb.ids line iterator to the beginning of the file */
static void
usb_ids_line_iter_init ()
{
	usb_ids_iter_pos = 0;
}

/** Maximum length of lines in usb.ids */
#define USB_IDS_MAX_LINE_LEN 512

/** Get the next line from usb.ids
 *
 *  @param  line_len            Pointer to where number of bytes in line will
 *                              be stored
 *  @return                     Pointer to the line; only valid until the
 *                              next invocation of this function
 */
static char *
usb_ids_line_iter_get_line (unsigned int *line_len)
{
	unsigned int i;
	static char line[USB_IDS_MAX_LINE_LEN];

	for (i = 0;
	     usb_ids_iter_pos < usb_ids_len &&
	     i < USB_IDS_MAX_LINE_LEN - 1 &&
	     usb_ids[usb_ids_iter_pos] != '\n'; i++, usb_ids_iter_pos++) {
		line[i] = usb_ids[usb_ids_iter_pos];
	}

	line[i] = '\0';
	if (line_len != NULL)
		*line_len = i;

	usb_ids_iter_pos++;

	return line;
}

/** See if there are more lines to process in usb.ids
 *
 *  @return                     #TRUE iff there are more lines to process
 */
static dbus_bool_t
usb_ids_line_iter_has_more ()
{
	return usb_ids_iter_pos < usb_ids_len;
}

/** Find the names for a USB device.
 *
 *  The pointers returned are only valid until the next invocation of this
 *  function.
 *
 *  @param  vendor_id           USB vendor id or 0 if unknown
 *  @param  product_id          USB product id or 0 if unknown
 *  @param  vendor_name         Set to pointer of result or NULL
 *  @param  product_name        Set to pointer of result or NULL
 */
void
ids_find_usb (int vendor_id, int product_id,
	      char **vendor_name, char **product_name)
{
	char *line;
	unsigned int i;
	unsigned int line_len;
	unsigned int num_tabs;
	char rep_vi[8];
	char rep_pi[8];
	static char store_vn[USB_IDS_MAX_LINE_LEN];
	static char store_pn[USB_IDS_MAX_LINE_LEN];
	dbus_bool_t vendor_matched = FALSE;

	snprintf (rep_vi, 8, "%04x", vendor_id);
	snprintf (rep_pi, 8, "%04x", product_id);

	*vendor_name = NULL;
	*product_name = NULL;

	for (usb_ids_line_iter_init (); usb_ids_line_iter_has_more ();) {
		line = usb_ids_line_iter_get_line (&line_len);

		/* skip lines with no content */
		if (line_len < 4)
			continue;

		/* skip comments */
		if (line[0] == '#')
			continue;

		/* count number of tabs */
		num_tabs = 0;
		for (i = 0; i < line_len; i++) {
			if (line[i] != '\t')
				break;
			num_tabs++;
		}

		switch (num_tabs) {
		case 0:
			/* vendor names */
			vendor_matched = FALSE;

			/* check vendor_id */
			if (vendor_id != 0) {
				if (memcmp (line, rep_vi, 4) == 0) {
					/* found it */
					vendor_matched = TRUE;

					for (i = 4; i < line_len; i++) {
						if (!isspace (line[i]))
							break;
					}
					strncpy (store_vn, line + i,
						 USB_IDS_MAX_LINE_LEN);
					*vendor_name = store_vn;
				}
			}
			break;

		case 1:
			/* product names */
			if (!vendor_matched)
				continue;

			/* check product_id */
			if (product_id != 0) {
				if (memcmp (line + 1, rep_pi, 4) == 0) {
					/* found it */
					for (i = 5; i < line_len; i++) {
						if (!isspace (line[i]))
							break;
					}
					strncpy (store_pn, line + i,
						 USB_IDS_MAX_LINE_LEN);
					*product_name = store_pn;

					/* no need to continue the search */
					return;
				}
			}
			break;

		default:
			break;
		}

	}
}

/** Free resources used by to store the USB database
 *
 *  @param                      #FALSE if the USB database wasn't loaded
 */
static dbus_bool_t
usb_ids_free ()
{
	if (usb_ids != NULL) {
		free (usb_ids);
		usb_ids = NULL;
		return TRUE;
	}
	return FALSE;
}

/** Load the USB database used for mapping vendor, product, subsys_vendor
 *  and subsys_product numbers into names.
 *
 *  @param  path                Path of the usb.ids file, e.g.
 *                              /usr/share/hwdata/usb.ids
 *  @return                     #TRUE if the file was succesfully loaded
 */
static dbus_bool_t
usb_ids_load (const char *path)
{
	FILE *fp;
	unsigned int num_read;

	fp = fopen (path, "r");
	if (fp == NULL) {
		printf ("couldn't open USB database at %s,", path);
		return FALSE;
	}

	fseek (fp, 0, SEEK_END);
	usb_ids_len = ftell (fp);
	fseek (fp, 0, SEEK_SET);

	usb_ids = malloc (usb_ids_len);
	if (usb_ids == NULL) {
		printf
		    ("Couldn't allocate %d bytes for USB database file\n",
		     usb_ids_len);
		fclose(fp);
		return FALSE;
	}

	num_read = fread (usb_ids, sizeof (char), usb_ids_len, fp);
	if (usb_ids_len != num_read) {
		printf ("Error loading USB database file\n");
		usb_ids_free ();
		fclose(fp);
		return FALSE;
	}

	fclose(fp);
	return TRUE;
}


void
ids_init (void)
{
	/* Load /usr/share/hwdata/pci.ids */
	pci_ids_load (HWDATA_DIR "/pci.ids");

	/* Load /usr/share/hwdata/usb.ids */
	usb_ids_load (HWDATA_DIR "/usb.ids");
}


/* This, somewhat incomplete, list is from this sources:
 * http://www.plasma-online.de/english/identify/serial/pnp_id_pnp.html
 * http://www-pc.uni-regensburg.de/hardware/TECHNIK/PCI_PNP/pnpid.txt
 *
 * Keep this sorted!
 */
struct pnp_id {
	char *id;
   	char *desc;
} static pnp_ids_list[] = {
	/* Crystal Semiconductor devices */
	{"CSC0000", "Crystal Semiconductor CS423x sound -- SB/WSS/OPL3 emulation"},
	{"CSC0001", "Crystal Semiconductor CS423x sound -- joystick"},
	{"CSC0003", "Crystal Semiconductor CS423x sound -- MPU401"},
	{"CSC0010", "Crystal Semiconductor CS423x sound -- control"},
	/* IBM devices */
	{"IBM0071", "IBM infrared communications device"},
	{"IBM3760", "IBM DSP"},
	{"IBM3780", "IBM pointing device"},
        /* FinePoint devices */
        {"FPI2004", "FinePoint Innovations Tablet"},
        /* Fujitsu (Siemens Computers) devices */
        {"FUJ02E5", "Wacom Serial Pen HID Tablet"},
        {"FUJ02E6", "Fujitsu Serial TouchScreen"},
	/* interrupt controllers */
	{"PNP0000", "AT Interrupt Controller"},
	{"PNP0001", "EISA Interrupt Controller"},
	{"PNP0002", "MCA Interrupt Controller"},
	{"PNP0003", "APIC"},
	{"PNP0004", "Cyrix SLiC MP interrupt controller"},
	/* timers */
	{"PNP0100", "AT Timer"},
	{"PNP0101", "EISA Timer"},
	{"PNP0102", "MCA Timer"},
	/* DMA controllers */
	{"PNP0200", "AT DMA Controller"},
	{"PNP0201", "EISA DMA Controller"},
	{"PNP0202", "MCA DMA Controller"},
	/* keyboards */
	{"PNP0300", "IBM PC/XT keyboard controller (83-key)"},
	{"PNP0301", "IBM PC/AT keyboard controller (86-key)"},
	{"PNP0302", "IBM PC/XT keyboard controller (84-key)"},
	{"PNP0303", "IBM Enhanced (101/102-key, PS/2 mouse support)"},
	{"PNP0304", "Olivetti Keyboard (83-key)"},
	{"PNP0305", "Olivetti Keyboard (102-key)"},
	{"PNP0306", "Olivetti Keyboard (86-key)"},
	{"PNP0307", "Microsoft Windows(R) Keyboard"},
	{"PNP0308", "General Input Device Emulation Interface (GIDEI) legacy"},
	{"PNP0309", "Olivetti Keyboard (A101/102 key)"},
	{"PNP030A", "AT&T 302 keyboard"},
	{"PNP030B", "Reserved by Microsoft"},
	{"PNP0320", "Japanese 101-key keyboard"},
	{"PNP0321", "Japanese AX keyboard"},
	{"PNP0322", "Japanese 106-key keyboard A01"},
	{"PNP0323", "Japanese 106-key keyboard 002/003"},
	{"PNP0324", "Japanese 106-key keyboard 001"},
	{"PNP0325", "Japanese Toshiba Desktop keyboard"},
	{"PNP0326", "Japanese Toshiba Laptop keyboard"},
	{"PNP0327", "Japanese Toshiba Notebook keyboard"},
	{"PNP0340", "Korean 84-key keyboard"},
	{"PNP0341", "Korean 86-key keyboard"},
	{"PNP0342", "Korean Enhanced keyboard"},
	{"PNP0343", "Korean Enhanced keyboard 101b"},
	{"PNP0343", "Korean Enhanced keyboard 101c"},
	{"PNP0344", "Korean Enhanced keyboard 103"},
	/* parallel ports */
	{"PNP0400", "Standard LPT printer port"},
	{"PNP0401", "ECP printer port"},
	/* serial ports */
	{"PNP0500", "Standard PC COM port"},
	{"PNP0501", "16550A-compatible COM port"},
	{"PNP0502", "Multiport serial device (non-intelligent 16550)"},
	{"PNP0510", "Generic IRDA-compatible device"},
	{"PNP0511", "Generic IRDA-compatible device"},
	/* IDE controller */
	{"PNP0600", "Generic ESDI/IDE/ATA compatible hard disk controller"},
	{"PNP0601", "Plus Hardcard II"},
	{"PNP0602", "Plus Hardcard IIXL/EZ"},
	{"PNP0603", "Generic IDE supporting Microsoft Device Bay Specification"},
	{"PNP0604", "PC standard floppy disk controller"},
	{"PNP0605", "HP Omnibook floppy disk controller"},
	{"PNP0680", "Bus Master E-IDE controller"},
	{"PNP0700", "PC standard floppy disk controller"},
	{"PNP0701", "Standard floppy controller supporting MS Device Bay Spec"},
	/* system devices */
	{"PNP0800", "AT-style speaker sound"},
	/* obsolete devices */
	{"PNP0802", "Microsoft Sound System compatible device (obsolete, use PNPB0xx instead)"},
	/* display adapters / graphic cards */
	{"PNP0900", "VGA Compatible"},
	{"PNP0901", "Video Seven VRAM/VRAM II/1024i"},
	{"PNP0902", "IBM 8514/A Compatible"},
	{"PNP0903", "Trident VGA"},
	{"PNP0904", "Cirrus Logic Laptop VGA"},
	{"PNP0905", "Cirrus Logic VGA"},
	{"PNP0906", "Tseng Labs ET4000"},
	{"PNP0907", "Western Digital VGA"},
	{"PNP0908", "Western Digital Laptop VGA"},
	{"PNP0909", "S3 Inc. 911/924"},
	{"PNP090A", "ATI Ultra Pro/Plus (Mach 32)"},
	{"PNP090B", "ATI Ultra (Mach 8)"},
	{"PNP090C", "IBM XGA Compatible"},
	{"PNP090D", "ATI VGA Wonder"},
	{"PNP090E", "Weitek P9000 Graphics Adapter"},
	{"PNP090F", "Oak Technology VGA"},
	{"PNP0910", "Compaq QVision"},
	{"PNP0911", "IBM XGA/2"},
	{"PNP0912", "Tseng Labs ET4000 W32/W32i/W32p"},
	{"PNP0913", "S3 Inc. 801/928/964"},
	{"PNP0914", "Cirrus Logic 5429/5434 (memory mapped)"},
	{"PNP0915", "Compaq Advanced VGA (AVGA)"},
	{"PNP0916", "ATI Ultra Pro Turbo (Mach64)"},
	{"PNP0917", "Reserved by Microsoft"},
	{"PNP0918", "Matrox MGA"},
	{"PNP0919", "Compaq QVision 2000"},
	{"PNP091A", "Tseng Labs W128"},
	{"PNP0930", "Chips & Technologies Super VGA"},
	{"PNP0931", "Chips & Technologies Accelerator"},
	{"PNP0940", "NCR 77c22e Super VGA"},
	{"PNP0941", "NCR 77c32blt"},
	{"PNP09FF", "Plug and Play Monitors (VESA DDC)"},
	/* peripheral buses */
	{"PNP0A00", "ISA Bus"},
	{"PNP0A01", "EISA Bus"},
	{"PNP0A02", "MCA Bus"},
	{"PNP0A03", "PCI Bus"},
	{"PNP0A04", "VESA/VL Bus"},
	{"PNP0A05", "Generic ACPI Bus"},
	{"PNP0A06", "Generic ACPI Extended-IO Bus (EIO bus)"},
	/* system devices */
	{"PNP0B00", "AT Real-Time Clock"},
	{"PNP0C00", "Plug and Play BIOS (only created by the root enumerator)"},
	{"PNP0C01", "System Board"},
	{"PNP0C02", "General ID for reserving resources required by PnP motherboard registers. (Not device specific.)"},
	{"PNP0C03", "Plug and Play BIOS Event Notification Interrupt"},
	{"PNP0C04", "Math Coprocessor"},
	{"PNP0C05", "APM BIOS (Version independent)"},
	{"PNP0C06", "Reserved for identification of early Plug and Play BIOS implementation"},
	{"PNP0C07", "Reserved for identification of early Plug and Play BIOS implementation"},
	{"PNP0C08", "ACPI system board hardware"},
	{"PNP0C09", "ACPI Embedded Controller"},
	{"PNP0C0A", "ACPI Control Method Battery"},
	{"PNP0C0B", "ACPI Fan"},
	{"PNP0C0C", "ACPI power button device"},
	{"PNP0C0D", "ACPI lid device"},
	{"PNP0C0E", "ACPI sleep button device"},
	{"PNP0C0F", "PCI interrupt link device"},
	{"PNP0C10", "ACPI system indicator device"},
	{"PNP0C11", "ACPI thermal zone"},
	{"PNP0C12", "Device Bay Controller"},
	{"PNP0C13", "Plug and Play BIOS (used when ACPI mode cannot be used)"},
	{"PNP0CF0", "Compaq LTE Lite Support"},
	{"PNP0CF1", "Compaq LTE Elite Support"},
	/* PCMCIA controllers */
	{"PNP0E00", "Intel 82365-Compatible PCMCIA Controller"},
	{"PNP0E01", "Cirrus Logic CL-PD6720 PCMCIA Controller"},
	{"PNP0E02", "VLSI VL82C146 PCMCIA Controller"},
	{"PNP0E03", "Intel 82365-compatible CardBus controller"},
	/* mice */
	{"PNP0F00", "Microsoft Bus Mouse"},
	{"PNP0F01", "Microsoft Serial Mouse"},
	{"PNP0F02", "Microsoft InPort Mouse"},
	{"PNP0F03", "Microsoft PS/2-style Mouse"},
	{"PNP0F04", "Mouse Systems Mouse"},
	{"PNP0F05", "Mouse Systems 3-Button Mouse (COM2)"},
	{"PNP0F06", "Genius Mouse (COM1)"},
	{"PNP0F07", "Genius Mouse (COM2)"},
	{"PNP0F08", "Logitech Serial Mouse"},
	{"PNP0F09", "Microsoft BallPoint Serial Mouse"},
	{"PNP0F0A", "Microsoft Plug and Play Mouse"},
	{"PNP0F0B", "Microsoft Plug and Play BallPoint Mouse"},
	{"PNP0F0C", "Microsoft-compatible Serial Mouse"},
	{"PNP0F0D", "Microsoft-compatible InPort-compatible Mouse"},
	{"PNP0F0E", "Microsoft-compatible PS/2-style Mouse"},
	{"PNP0F0F", "Microsoft-compatible Serial BallPoint-compatible Mouse"},
	{"PNP0F10", "Texas Instruments QuickPort Mouse"},
	{"PNP0F11", "Microsoft-compatible Bus Mouse"},
	{"PNP0F12", "Logitech PS/2-style Mouse"},
	{"PNP0F13", "PS/2 Port for PS/2-style Mice"},
	{"PNP0F14", "Microsoft Kids Mouse"},
	{"PNP0F15", "Logitech bus mouse"},
	{"PNP0F16", "Logitech SWIFT device"},
	{"PNP0F17", "Logitech-compatible serial mouse"},
	{"PNP0F18", "Logitech-compatible bus mouse"},
	{"PNP0F19", "Logitech-compatible PS/2-style Mouse"},
	{"PNP0F1A", "Logitech-compatible SWIFT Device"},
	{"PNP0F1B", "HP Omnibook Mouse"},
	{"PNP0F1C", "Compaq LTE Trackball PS/2-style Mouse"},
	{"PNP0F1D", "Compaq LTE Trackball Serial Mouse"},
	{"PNP0F1E", "Microsoft Kids Trackball Mouse"},
	{"PNP0F1F", "Reserved by Microsoft Input Device Group"},
	{"PNP0F20", "Reserved by Microsoft Input Device Group"},
	{"PNP0F21", "Reserved by Microsoft Input Device Group"},
	{"PNP0F22", "Reserved by Microsoft Input Device Group"},
	{"PNP0F23", "Reserved by Microsoft Input Device Group"},
	{"PNP0FFF", "Reserved by Microsoft Systems"},
	{"PNP0XXX", "Unknown System Device"},
	/* network cards */
	{"PNP8000", "Network Adapter"},
	{"PNP8001", "Novell/Anthem NE3200"},
	{"PNP8004", "Compaq NE3200"},
	{"PNP8006", "Intel EtherExpress/32"},
	{"PNP8008", "HP EtherTwist EISA LAN Adapter/32 (HP27248A)"},
	{"PNP8065", "Ungermann-Bass NIUps or NIUps/EOTP"},
	{"PNP8072", "DEC (DE211) EtherWorks MC/TP"},
	{"PNP8073", "DEC (DE212) EtherWorks MC/TP_BNC"},
	{"PNP8074", "HP MC LAN Adapter/16 TP (PC27246)"},
	{"PNP8078", "DCA 10 Mb MCA"},
	{"PNP807F", "Racal NI9210"},
	{"PNP8081", "Pure Data Ethernet"},
	{"PNP8096", "Thomas-Conrad TC4046"},
	{"PNP80C9", "IBM Token Ring"},
	{"PNP80CA", "IBM Token Ring II"},
	{"PNP80CB", "IBM Token Ring II/Short"},
	{"PNP80CC", "IBM Token Ring 4/16Mbs"},
	{"PNP80D3", "Novell/Anthem NE1000"},
	{"PNP80D4", "Novell/Anthem NE2000"},
	{"PNP80D5", "NE1000 Compatible"},
	{"PNP80D6", "NE2000 Compatible"},
	{"PNP80D7", "Novell/Anthem NE1500T"},
	{"PNP80D8", "Novell/Anthem NE2100"},
	{"PNP80D9", "NE2000 Plus"},
	{"PNP80DD", "SMC ARCNETPC"},
	{"PNP80DE", "SMC ARCNET PC100, PC200"},
	{"PNP80DF", "SMC ARCNET PC110, PC210, PC250"},
	{"PNP80E0", "SMC ARCNET PC130/E"},
	{"PNP80E1", "SMC ARCNET PC120, PC220, PC260"},
	{"PNP80E2", "SMC ARCNET PC270/E"},
	{"PNP80E5", "SMC ARCNET PC600W, PC650W"},
	{"PNP80E7", "DEC DEPCA"},
	{"PNP80E8", "DEC (DE100) EtherWorks LC"},
	{"PNP80E9", "DEC (DE200) EtherWorks Turbo"},
	{"PNP80EA", "DEC (DE101) EtherWorks LC/TP"},
	{"PNP80EB", "DEC (DE201) EtherWorks Turbo/TP"},
	{"PNP80EC", "DEC (DE202) EtherWorks Turbo/TP_BNC"},
	{"PNP80ED", "DEC (DE102) EtherWorks LC/TP_BNC"},
	{"PNP80EE", "DEC EE101 (Built-In)"},
	{"PNP80EF", "DEC PC 433 WS (Built-In)"},
	{"PNP80F1", "3Com EtherLink Plus"},
	{"PNP80F3", "3Com EtherLink II or IITP (8 or 16-bit)"},
	{"PNP80F4", "3Com TokenLink"},
	{"PNP80F6", "3Com EtherLink 16"},
	{"PNP80F7", "3Com EtherLink III"},
	{"PNP80F8", "3Com Generic Etherlink Plug and Play Device"},
	{"PNP80FB", "Thomas Conrad TC6045"},
	{"PNP80FC", "Thomas Conrad TC6042"},
	{"PNP80FD", "Thomas Conrad TC6142"},
	{"PNP80FE", "Thomas Conrad TC6145"},
	{"PNP80FF", "Thomas Conrad TC6242"},
	{"PNP8100", "Thomas Conrad TC6245"},
	{"PNP8101", "Thomas-Conrad TC4045"},
	{"PNP8104", "Thomas-Conrad TC4035"},
	{"PNP8105", "DCA 10 MB"},
	{"PNP8106", "DCA 10 MB Fiber Optic"},
	{"PNP8107", "DCA 10 MB Twisted Pair"},
	{"PNP8113", "Racal NI6510"},
	{"PNP8114", "Racal NI5210/8 or NI5210/16"},
	{"PNP8119", "Ungermann-Bass pcNIU"},
	{"PNP811A", "Ungermann-Bass pcNIU/ex 128K"},
	{"PNP811B", "Ungermann-Bass pcNIU/ex 512K"},
	{"PNP811C", "Ungermann-Bass NIUpc"},
	{"PNP811D", "Ungermann-Bass NIUpc/3270"},
	{"PNP8120", "Ungermann-Bass NIUpc/EOTP"},
	{"PNP8123", "SMC StarCard PLUS (WD/8003S)"},
	{"PNP8124", "SMC StarCard PLUS With On Board Hub (WD/8003SH)"},
	{"PNP8125", "SMC EtherCard PLUS (WD/8003E)"},
	{"PNP8126", "SMC EtherCard PLUS With Boot ROM Socket (WD/8003EBT)"},
	{"PNP8127", "SMC EtherCard PLUS With Boot ROM Socket (WD/8003EB)"},
	{"PNP8128", "SMC EtherCard PLUS TP (WD/8003WT)"},
	{"PNP812A", "SMC EtherCard PLUS 16 With Boot ROM Socket (WD/8013EBT)"},
	{"PNP812D", "Intel EtherExpress 16 or 16TP"},
	{"PNP812F", "Intel TokenExpress 16/4"},
	{"PNP8130", "Intel TokenExpress MCA 16/4"},
	{"PNP8132", "Intel EtherExpress 16 (MCA)"},
	{"PNP8133", "Compaq Ethernet 16E"},
	{"PNP8137", "Artisoft AE-1"},
	{"PNP8138", "Artisoft AE-2 or AE-3"},
	{"PNP8141", "Amplicard AC 210/XT"},
	{"PNP8142", "Amplicard AC 210/AT"},
	{"PNP814B", "Everex SpeedLink /PC16 (EV2027)"},
	{"PNP8155", "HP PC LAN Adapter/8 TP (HP27245)"},
	{"PNP8156", "HP PC LAN Adapter/16 TP (HP27247A)"},
	{"PNP8157", "HP PC LAN Adapter/8 TL (HP27250)"},
	{"PNP8158", "HP PC LAN Adapter/16 TP Plus (HP27247B)"},
	{"PNP8159", "HP PC LAN Adapter/16 TL Plus (HP27252)"},
	{"PNP815F", "National Semiconductor Ethernode *16AT"},
	{"PNP8160", "National Semiconductor AT/LANTIC EtherNODE 16-AT3"},
	{"PNP8169", "NCR StarCard"},
	{"PNP816A", "NCR Token-Ring 4 Mbs ISA"},
	{"PNP816B", "NCR WaveLAN AT"},
	{"PNP816C", "NCR WaveLan MC"},
	{"PNP816D", "NCR Token-Ring 16/4 Mbs ISA"},
	{"PNP8191", "Olicom 16/4 Token-Ring Adapter"},
	{"PNP81A5", "Research Machines Ethernet"},
	{"PNP81B9", "ToshibaLAN (internal)"},
	{"PNP81C3", "SMC EtherCard PLUS Elite (WD/8003EP)"},
	{"PNP81C4", "SMC EtherCard PLUS 10T (WD/8003W)"},
	{"PNP81C5", "SMC EtherCard PLUS Elite 16 (WD/8013EP)"},
	{"PNP81C6", "SMC EtherCard PLUS Elite 16T (WD/8013W)"},
	{"PNP81C7", "SMC EtherCard PLUS Elite 16 Combo (WD/8013EW or 8013EWC)"},
	{"PNP81C8", "SMC EtherElite Ultra 16"},
	{"PNP81C9", "SMC TigerCard (8216L, 8216LC, 8216LT)"},
	{"PNP81CA", "SMC EtherEZ (8416)"},
	{"PNP81D7", "Madge Smart 16/4 PC Ringnode"},
	{"PNP81D8", "Madge Smart 16/4 Ringnode ISA"},
	{"PNP81E4", "Pure Data PDI9025-32 (Token Ring)"},
	{"PNP81E6", "Pure Data PDI508+ (ArcNet)"},
	{"PNP81E7", "Pure Data PDI516+ (ArcNet)"},
	{"PNP81EB", "Proteon Token Ring (P1390)"},
	{"PNP81EC", "Proteon Token Ring (P1392)"},
	{"PNP81ED", "Proteon Token Ring ISA (P1340)"},
	{"PNP81EE", "Proteon Token Ring ISA (P1342)"},
	{"PNP81EF", "Proteon Token Ring ISA (P1346)"},
	{"PNP81F0", "Proteon Token Ring ISA (P1347)"},
	{"PNP81FF", "Cabletron E2000 Series DNI"},
	{"PNP8200", "Cabletron E2100 Series DNI"},
	{"PNP8201", "Cabletron T2015 4/16 Mbit/s DNI"},
	{"PNP8209", "Zenith Data Systems Z-Note"},
	{"PNP820A", "Zenith Data Systems NE2000-Compatible"},
	{"PNP8213", "Xircom Pocket Ethernet II"},
	{"PNP8214", "Xircom Pocket Ethernet I"},
	{"PNP8215", "Xircom Pocket Ethernet III Adapter"},
	{"PNP821D", "RadiSys EXM-10"},
	{"PNP8227", "SMC 3000 Series"},
	{"PNP8228", "SMC 91C2 controller"},
	{"PNP8231", "AMD AM2100/AM1500T"},
	{"PNP824F", "RCE 10Base-T (16 bit)"},
	{"PNP8250", "RCE 10Base-T (8 bit)"},
	{"PNP8263", "Tulip NCC-16"},
	{"PNP8277", "Exos 105"},
	{"PNP828A", "Intel '595 based Ethernet"},
	{"PNP828B", "TI2000-style Token Ring"},
	{"PNP828C", "AMD PCNet Family cards"},
	{"PNP828D", "AMD PCNet32 (VL version)"},
	{"PNP8294", "IrDA Infrared NDIS driver (Microsoft-supplied)"},
	{"PNP82BD", "IBM PCMCIA-NIC"},
	{"PNP82C0", "Eagle Technology NE200T"},
	{"PNP82C2", "Xircom CE10"},
	{"PNP82C3", "Xircom CEM2"},
	{"PNP82C4", "Xircom CE2"},
	{"PNP8321", "DEC Ethernet (All Types)"},
	{"PNP8323", "SMC EtherCard (All Types except 8013/A)"},
	{"PNP8324", "ARCNET Compatible"},
	{"PNP8325", "SMC TokenCard PLUS (8115T)"},
	{"PNP8326", "Thomas Conrad (All Arcnet Types)"},
	{"PNP8327", "IBM Token Ring (All Types)"},
	{"PNP8328", "Ungermann-Bass NIU"},
	{"PNP8329", "Proteon ProNET-4/16 ISA Token Ring (P1392+,P1392,1390)"},
	{"PNP8385", "Remote Network Access [RNA] Driver"},
	{"PNP8387", "Remote Network Access [RNA] PPP Driver"},
	{"PNP8388", "Reserved for Microsoft Networking components"},
	{"PNP8389", "Peer IrLAN infrared driver (Microsoft-supplied)"},
	{"PNP8390", "Generic network adapter"},
	{"PNP8XXX", "Unknown Network Adapter"},
	/* modems */
	{"PNP9000", "Modem"},
	/* CD controller */
	{"PNPA000", "Adaptec 154x compatible SCSI controller"},
	{"PNPA001", "Adaptec 174x compatible SCSI controller"},
	{"PNPA002", "Future Domain 16-700 compatible controller"},
	{"PNPA003", "Mitsumi CD-ROM adapter (Panasonic spec., used on SBPro/SB16)"},
	{"PNPA01B", "Trantor 128 SCSI Controller"},
	{"PNPA01D", "Trantor T160 SCSI Controller"},
	{"PNPA01E", "Trantor T338 Parallel SCSI controller"},
	{"PNPA01F", "Trantor T348 Parallel SCSI controller"},
	{"PNPA020", "Trantor Media Vision SCSI controller"},
	{"PNPA022", "Always IN-2000 SCSI controller"},
	{"PNPA02B", "Sony proprietary CD-ROM controller"},
	{"PNPA02D", "Trantor T13b 8-bit SCSI controller"},
	{"PNPA02F", "Trantor T358 Parallel SCSI controller"},
	{"PNPA030", "Mitsumi LU-005 Single Speed CD-ROM controller + drive"},
	{"PNPA031", "Mitsumi FX-001 Single Speed CD-ROM controller + drive"},
	{"PNPA032", "Mitsumi FX-001 Double Speed CD-ROM controller + drive"},
	{"PNPAXXX", "Unknown SCSI, Proprietary CD Adapter"},
	/* multimedia devices */
	{"PNPB000", "Creative Labs Sound Blaster 1.5 (or compatible sound device)"},
	{"PNPB001", "Creative Labs Sound Blaster 2.0 (or compatible sound device)"},
	{"PNPB002", "Creative Labs Sound Blaster Pro (or compatible sound device)"},
	{"PNPB003", "Creative Labs Sound Blaster 16 (or compatible sound device)"},
	{"PNPB004", "MediaVision Thunderboard (or compatible sound device)"},
	{"PNPB005", "Adlib-compatible FM synthesizer device"},
	{"PNPB006", "MPU401 compatible"},
	{"PNPB007", "Microsoft Windows Sound System-compatible sound device"},
	{"PNPB008", "Compaq Business Audio"},
	{"PNPB009", "Plug and Play Microsoft Windows Sound System Device"},
	{"PNPB00A", "MediaVision Pro Audio Spectrum (Trantor SCSI enabled, Thunder Chip Disabled)"},
	{"PNPB00B", "MediaVision Pro Audio 3D"},
	{"PNPB00C", "MusicQuest MQX-32M"},
	{"PNPB00D", "MediaVision Pro Audio Spectrum Basic (No Trantor SCSI, Thunder Chip Enabled)"},
	{"PNPB00E", "MediaVision Pro Audio Spectrum (Trantor SCSI enabled, Thunder Chip Disabled)"},
	{"PNPB00F", "MediaVision Jazz-16 chipset (OEM Versions)"},
	{"PNPB010", "Orchid Videola - Auravision VxP500 chipset"},
	{"PNPB018", "MediaVision Pro Audio Spectrum 8-bit"},
	{"PNPB019", "MediaVision Pro Audio Spectrum Basic (No Trantor SCSI, Thunder Chip Enabled)"},
	{"PNPB020", "Yamaha OPL3-compatible FM synthesizer device"},
	{"PNPB02F", "Joystick/Game port"},
	{"PNPB077", "OAK Mozart Sound System"},
	{"PNPB078", "OAK Mozart Sound System MPU-401"},
	{"PNPBXXX", "Unknown Multimedia Device"},
	/* modems */
	{"PNPC000", "Compaq 14400 Modem (TBD)"},
	{"PNPC001", "Compaq 2400/9600 Modem (TBD)"},
	{"PNPCXXX", "Unknown Modem"},
	/* some other network cards */
	{"PNPD300", "SK-NET TR4/16+ Token-Ring"},
	{"PNPE000", "SK-NET G16, G16/TP Ethernet"},
	{"PNPF000", "SK-NET FDDI-FI FDDI LAN"},
	/* Toshiba devices */
	{"TOS6200", "Toshiba Notebook Extra HCI driver"},
	{"TOS6202", "Toshiba Notebook Extra HCI driver"},
	{"TOS6207", "Toshiba Notebook Extra HCI driver"},
	{"TOS7400", "Toshiba AcuPoint"},
	/* Wacom devices */
	{"WACf004", "Wacom Serial Tablet PC Pen Tablet/Digitizer"},
	{"WACf005", "Wacom Serial Tablet PC Pen Tablet/Digitizer"},
	{"WACf006", "Wacom Serial Tablet PC Pen Tablet/Digitizer"}
};

static int
ids_comp_pnp(const void *id1, const void *id2) {
        struct pnp_id *pnp_id1 = (struct pnp_id *) id1;
        struct pnp_id *pnp_id2 = (struct pnp_id *) id2;
        return strcasecmp(pnp_id1->id, pnp_id2->id);
}

void
ids_find_pnp (const char *pnp_id, char **pnp_description)
{
	static gboolean sorted = FALSE;
	struct pnp_id search, *res;

	if (!sorted) {
		/* sort the list, to be sure that all is in correc order */
		qsort(pnp_ids_list, sizeof(pnp_ids_list)/sizeof(pnp_ids_list[0]),
		      sizeof(struct pnp_id), ids_comp_pnp);
		sorted = TRUE;
	}

        search.id = (char *) pnp_id;
        res = bsearch(&search, pnp_ids_list, sizeof(pnp_ids_list)/sizeof(pnp_ids_list[0]),
		      sizeof(struct pnp_id), ids_comp_pnp);

        if (res != NULL)
        	*pnp_description = res->desc;
	else
        	*pnp_description = NULL;
        return;
}
