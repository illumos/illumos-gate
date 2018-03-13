/*
 * Copyright (c) 2008-2010 Rui Paulo
 * Copyright (c) 2006 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <sys/disk.h>
#include <sys/param.h>
#include <sys/reboot.h>
#include <sys/boot.h>
#include <stand.h>
#include <inttypes.h>
#include <string.h>
#include <setjmp.h>
#include <disk.h>

#include <efi.h>
#include <efilib.h>
#include <efigpt.h>

#include <uuid.h>

#include <bootstrap.h>
#include <smbios.h>

#include <libzfs.h>
#include <efizfs.h>

#include "loader_efi.h"

extern char bootprog_info[];

struct arch_switch archsw;	/* MI/MD interface boundary */

EFI_GUID devid = DEVICE_PATH_PROTOCOL;
EFI_GUID imgid = LOADED_IMAGE_PROTOCOL;
EFI_GUID smbios = SMBIOS_TABLE_GUID;
EFI_GUID smbios3 = SMBIOS3_TABLE_GUID;
EFI_GUID inputid = SIMPLE_TEXT_INPUT_PROTOCOL;

extern void acpi_detect(void);
extern void efi_getsmap(void);

static EFI_LOADED_IMAGE *img;

bool
efi_zfs_is_preferred(EFI_HANDLE *h)
{
	return (h == img->DeviceHandle);
}

static int
has_keyboard(void)
{
	EFI_STATUS status;
	EFI_DEVICE_PATH *path;
	EFI_HANDLE *hin, *hin_end, *walker;
	UINTN sz;
	int retval = 0;

	/*
	 * Find all the handles that support the SIMPLE_TEXT_INPUT_PROTOCOL and
	 * do the typical dance to get the right sized buffer.
	 */
	sz = 0;
	hin = NULL;
	status = BS->LocateHandle(ByProtocol, &inputid, 0, &sz, 0);
	if (status == EFI_BUFFER_TOO_SMALL) {
		hin = (EFI_HANDLE *)malloc(sz);
		status = BS->LocateHandle(ByProtocol, &inputid, 0, &sz,
		    hin);
		if (EFI_ERROR(status))
			free(hin);
	}
	if (EFI_ERROR(status))
		return retval;

	/*
	 * Look at each of the handles. If it supports the device path protocol,
	 * use it to get the device path for this handle. Then see if that
	 * device path matches either the USB device path for keyboards or the
	 * legacy device path for keyboards.
	 */
	hin_end = &hin[sz / sizeof(*hin)];
	for (walker = hin; walker < hin_end; walker++) {
		status = BS->HandleProtocol(*walker, &devid, (VOID **)&path);
		if (EFI_ERROR(status))
			continue;

		while (!IsDevicePathEnd(path)) {
			/*
			 * Check for the ACPI keyboard node. All PNP3xx nodes
			 * are keyboards of different flavors. Note: It is
			 * unclear of there's always a keyboard node when
			 * there's a keyboard controller, or if there's only one
			 * when a keyboard is detected at boot.
			 */
			if (DevicePathType(path) == ACPI_DEVICE_PATH &&
			    (DevicePathSubType(path) == ACPI_DP ||
				DevicePathSubType(path) == ACPI_EXTENDED_DP)) {
				ACPI_HID_DEVICE_PATH  *acpi;

				acpi = (ACPI_HID_DEVICE_PATH *)(void *)path;
				if ((EISA_ID_TO_NUM(acpi->HID) & 0xff00) == 0x300 &&
				    (acpi->HID & 0xffff) == PNP_EISA_ID_CONST) {
					retval = 1;
					goto out;
				}
			/*
			 * Check for USB keyboard node, if present. Unlike a
			 * PS/2 keyboard, these definitely only appear when
			 * connected to the system.
			 */
			} else if (DevicePathType(path) == MESSAGING_DEVICE_PATH &&
			    DevicePathSubType(path) == MSG_USB_CLASS_DP) {
				USB_CLASS_DEVICE_PATH *usb;
       
				usb = (USB_CLASS_DEVICE_PATH *)(void *)path;
				if (usb->DeviceClass == 3 && /* HID */
				    usb->DeviceSubClass == 1 && /* Boot devices */
				    usb->DeviceProtocol == 1) { /* Boot keyboards */
					retval = 1;
					goto out;
				}
			}
			path = NextDevicePathNode(path);
		}
	}
out:
	free(hin);
	return retval;
}

static void
set_devdesc_currdev(struct devsw *dev, int unit)
{
	struct devdesc currdev;
	char *devname;

	currdev.d_dev = dev;
	currdev.d_type = currdev.d_dev->dv_type;
	currdev.d_unit = unit;
	devname = efi_fmtdev(&currdev);

	env_setenv("currdev", EV_VOLATILE, devname, efi_setcurrdev,
	    env_nounset);
	env_setenv("loaddev", EV_VOLATILE, devname, env_noset, env_nounset);
}

static int
find_currdev(EFI_LOADED_IMAGE *img)
{
	pdinfo_list_t *pdi_list;
	pdinfo_t *dp, *pp;
	EFI_DEVICE_PATH *devpath, *copy;
	EFI_HANDLE h;
	char *devname;
	struct devsw *dev;
	int unit;
	uint64_t extra;

	/* Did efi_zfs_probe() detect the boot pool? */
	if (pool_guid != 0) {
		struct zfs_devdesc currdev;

		currdev.dd.d_dev = &zfs_dev;
		currdev.dd.d_unit = 0;
		currdev.dd.d_type = currdev.dd.d_dev->dv_type;
		currdev.pool_guid = pool_guid;
		currdev.root_guid = 0;
		devname = efi_fmtdev(&currdev);

		env_setenv("currdev", EV_VOLATILE, devname, efi_setcurrdev,
		    env_nounset);
		env_setenv("loaddev", EV_VOLATILE, devname, env_noset,
		    env_nounset);
		return (0);
	}

	/* We have device lists for hd, cd, fd, walk them all. */
	pdi_list = efiblk_get_pdinfo_list(&efipart_hddev);
	STAILQ_FOREACH(dp, pdi_list, pd_link) {
		struct disk_devdesc currdev;

		currdev.dd.d_dev = &efipart_hddev;
		currdev.dd.d_type = currdev.dd.d_dev->dv_type;
		currdev.dd.d_unit = dp->pd_unit;
		currdev.d_slice = -1;
		currdev.d_partition = -1;

		if (dp->pd_handle == img->DeviceHandle) {
			devname = efi_fmtdev(&currdev);

			env_setenv("currdev", EV_VOLATILE, devname,
			    efi_setcurrdev, env_nounset);
			env_setenv("loaddev", EV_VOLATILE, devname,
			    env_noset, env_nounset);
			return (0);
		}
		/* Assuming GPT partitioning. */
		STAILQ_FOREACH(pp, &dp->pd_part, pd_link) {
			if (pp->pd_handle == img->DeviceHandle) {
				currdev.d_slice = pp->pd_unit;
				currdev.d_partition = 255;
				devname = efi_fmtdev(&currdev);

				env_setenv("currdev", EV_VOLATILE, devname,
				    efi_setcurrdev, env_nounset);
				env_setenv("loaddev", EV_VOLATILE, devname,
				    env_noset, env_nounset);
				return (0);
			}
		}
	}

	pdi_list = efiblk_get_pdinfo_list(&efipart_cddev);
	STAILQ_FOREACH(dp, pdi_list, pd_link) {
		if (dp->pd_handle == img->DeviceHandle ||
		    dp->pd_alias == img->DeviceHandle) {
			set_devdesc_currdev(&efipart_cddev, dp->pd_unit);
			return (0);
		}
	}

	pdi_list = efiblk_get_pdinfo_list(&efipart_fddev);
	STAILQ_FOREACH(dp, pdi_list, pd_link) {
		if (dp->pd_handle == img->DeviceHandle) {
			set_devdesc_currdev(&efipart_fddev, dp->pd_unit);
			return (0);
		}
	}

	/*
	 * Try the device handle from our loaded image first.  If that
	 * fails, use the device path from the loaded image and see if
	 * any of the nodes in that path match one of the enumerated
	 * handles.
	 */
	if (efi_handle_lookup(img->DeviceHandle, &dev, &unit, &extra) == 0) {
		set_devdesc_currdev(dev, unit);
		return (0);
	}

	copy = NULL;
	devpath = efi_lookup_image_devpath(IH);
	while (devpath != NULL) {
		h = efi_devpath_handle(devpath);
		if (h == NULL)
			break;

		free(copy);
		copy = NULL;

		if (efi_handle_lookup(h, &dev, &unit, &extra) == 0) {
			set_devdesc_currdev(dev, unit);
			return (0);
		}

		devpath = efi_lookup_devpath(h);
		if (devpath != NULL) {
			copy = efi_devpath_trim(devpath);
			devpath = copy;
		}
	}
	free(copy);

	return (ENOENT);
}

EFI_STATUS
main(int argc, CHAR16 *argv[])
{
	char var[128];
	EFI_GUID *guid;
	int i, j, vargood, howto;
	void *ptr;
	UINTN k;
	int has_kbd;

	archsw.arch_autoload = efi_autoload;
	archsw.arch_getdev = efi_getdev;
	archsw.arch_copyin = efi_copyin;
	archsw.arch_copyout = efi_copyout;
	archsw.arch_readin = efi_readin;
	archsw.arch_loadaddr = efi_loadaddr;
	archsw.arch_free_loadaddr = efi_free_loadaddr;
	/* Note this needs to be set before ZFS init. */
	archsw.arch_zfs_probe = efi_zfs_probe;

	/* Get our loaded image protocol interface structure. */
	BS->HandleProtocol(IH, &imgid, (VOID**)&img);

	/* Init the time source */
	efi_time_init();

	has_kbd = has_keyboard();

	/*
	 * XXX Chicken-and-egg problem; we want to have console output
	 * early, but some console attributes may depend on reading from
	 * eg. the boot device, which we can't do yet.  We can use
	 * printf() etc. once this is done.
	 */
	cons_probe();
	efi_getsmap();

	/*
	 * Initialise the block cache. Set the upper limit.
	 */
	bcache_init(32768, 512);

	/*
	 * Parse the args to set the console settings, etc
	 * boot1.efi passes these in, if it can read /boot.config or /boot/config
	 * or iPXE may be setup to pass these in.
	 *
	 * Loop through the args, and for each one that contains an '=' that is
	 * not the first character, add it to the environment.  This allows
	 * loader and kernel env vars to be passed on the command line.  Convert
	 * args from UCS-2 to ASCII (16 to 8 bit) as they are copied.
	 */
	howto = 0;
	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			for (j = 1; argv[i][j] != 0; j++) {
				int ch;

				ch = argv[i][j];
				switch (ch) {
				case 'a':
					howto |= RB_ASKNAME;
					break;
				case 'd':
					howto |= RB_KDB;
					break;
				case 'D':
					howto |= RB_MULTIPLE;
					break;
				case 'h':
					howto |= RB_SERIAL;
					break;
				case 'm':
					howto |= RB_MUTE;
					break;
				case 'p':
					howto |= RB_PAUSE;
					break;
				case 'P':
					if (!has_kbd)
						howto |= RB_SERIAL | RB_MULTIPLE;
					break;
				case 'r':
					howto |= RB_DFLTROOT;
					break;
				case 's':
					howto |= RB_SINGLE;
					break;
				case 'S':
					if (argv[i][j + 1] == 0) {
						if (i + 1 == argc) {
							strncpy(var, "115200",
							    sizeof(var));
						} else {
							CHAR16 *ptr;
							ptr = &argv[i + 1][0];
							cpy16to8(ptr, var,
							    sizeof(var));
						}
						i++;
					} else {
						cpy16to8(&argv[i][j + 1], var,
						    sizeof(var));
					}
					strncat(var, ",8,n,1,-", sizeof(var));
					setenv("ttya-mode", var, 1);
					break;
				case 'v':
					howto |= RB_VERBOSE;
					break;
				}
			}
		} else {
			vargood = 0;
			for (j = 0; argv[i][j] != 0; j++) {
				if (j == sizeof(var)) {
					vargood = 0;
					break;
				}
				if (j > 0 && argv[i][j] == '=')
					vargood = 1;
				var[j] = (char)argv[i][j];
			}
			if (vargood) {
				var[j] = 0;
				putenv(var);
			}
		}
	}
	for (i = 0; howto_names[i].ev != NULL; i++)
		if (howto & howto_names[i].mask)
			setenv(howto_names[i].ev, "YES", 1);
	if (howto & RB_MULTIPLE) {
		if (howto & RB_SERIAL)
			setenv("console", "ttya text" , 1);
		else
			setenv("console", "text ttya" , 1);
	} else if (howto & RB_SERIAL) {
		setenv("console", "ttya" , 1);
	}

	/*
	 * Scan the BLOCK IO MEDIA handles then
	 * march through the device switch probing for things.
	 */
	if ((i = efipart_inithandles()) == 0) {
		for (i = 0; devsw[i] != NULL; i++)
			if (devsw[i]->dv_init != NULL)
				(devsw[i]->dv_init)();
	} else
		printf("efipart_inithandles failed %d, expect failures", i);

	printf("Command line arguments:");
	for (i = 0; i < argc; i++) {
		printf(" %S", argv[i]);
	}
	printf("\n");

	printf("Image base: 0x%lx\n", (u_long)img->ImageBase);
	printf("EFI version: %d.%02d\n", ST->Hdr.Revision >> 16,
	    ST->Hdr.Revision & 0xffff);
	printf("EFI Firmware: %S (rev %d.%02d)\n", ST->FirmwareVendor,
	    ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);

	printf("\n%s", bootprog_info);

	/*
	 * Disable the watchdog timer. By default the boot manager sets
	 * the timer to 5 minutes before invoking a boot option. If we
	 * want to return to the boot manager, we have to disable the
	 * watchdog timer and since we're an interactive program, we don't
	 * want to wait until the user types "quit". The timer may have
	 * fired by then. We don't care if this fails. It does not prevent
	 * normal functioning in any way...
	 */
	BS->SetWatchdogTimer(0, 0, 0, NULL);

	if (find_currdev(img) != 0)
		return (EFI_NOT_FOUND);

	efi_init_environment();
	setenv("ISADIR", "amd64", 1);	/* we only build 64bit */
	acpi_detect();

	if ((ptr = efi_get_table(&smbios3)) == NULL)
		ptr = efi_get_table(&smbios);
	smbios_detect(ptr);

	interact(NULL);			/* doesn't return */

	return (EFI_SUCCESS);		/* keep compiler happy */
}

COMMAND_SET(reboot, "reboot", "reboot the system", command_reboot);

static int
command_reboot(int argc __unused, char *argv[] __unused)
{
	int i;

	for (i = 0; devsw[i] != NULL; ++i)
		if (devsw[i]->dv_cleanup != NULL)
			(devsw[i]->dv_cleanup)();

	RS->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);

	/* NOTREACHED */
	return (CMD_ERROR);
}

COMMAND_SET(memmap, "memmap", "print memory map", command_memmap);

static int
command_memmap(int argc __unused, char *argv[] __unused)
{
	UINTN sz;
	EFI_MEMORY_DESCRIPTOR *map, *p;
	UINTN key, dsz;
	UINT32 dver;
	EFI_STATUS status;
	int i, ndesc;
	int rv = 0;
	char line[80];

	sz = 0;
	status = BS->GetMemoryMap(&sz, 0, &key, &dsz, &dver);
	if (status != EFI_BUFFER_TOO_SMALL) {
		printf("Can't determine memory map size\n");
		return (CMD_ERROR);
	}
	map = malloc(sz);
	status = BS->GetMemoryMap(&sz, map, &key, &dsz, &dver);
	if (EFI_ERROR(status)) {
		printf("Can't read memory map\n");
		return (CMD_ERROR);
	}

	ndesc = sz / dsz;
	snprintf(line, 80, "%23s %12s %12s %8s %4s\n",
	       "Type", "Physical", "Virtual", "#Pages", "Attr");
	pager_open();
	rv = pager_output(line);
	if (rv) {
		pager_close();
		return (CMD_OK);
	}

	for (i = 0, p = map; i < ndesc;
	     i++, p = NextMemoryDescriptor(p, dsz)) {
		snprintf(line, 80, "%23s %012lx %012lx %08lx ",
		    efi_memory_type(p->Type),
		    p->PhysicalStart,
		    p->VirtualStart,
		    p->NumberOfPages);
		rv = pager_output(line);
		if (rv)
			break;

		if (p->Attribute & EFI_MEMORY_UC)
			printf("UC ");
		if (p->Attribute & EFI_MEMORY_WC)
			printf("WC ");
		if (p->Attribute & EFI_MEMORY_WT)
			printf("WT ");
		if (p->Attribute & EFI_MEMORY_WB)
			printf("WB ");
		if (p->Attribute & EFI_MEMORY_UCE)
			printf("UCE ");
		if (p->Attribute & EFI_MEMORY_WP)
			printf("WP ");
		if (p->Attribute & EFI_MEMORY_RP)
			printf("RP ");
		if (p->Attribute & EFI_MEMORY_XP)
			printf("XP ");
		if (p->Attribute & EFI_MEMORY_NV)
			printf("NV ");
		if (p->Attribute & EFI_MEMORY_MORE_RELIABLE)
			printf("MR ");
		if (p->Attribute & EFI_MEMORY_RO)
			printf("RO ");
		rv = pager_output("\n");
		if (rv)
			break;
	}

	pager_close();
	return (CMD_OK);
}

COMMAND_SET(configuration, "configuration", "print configuration tables",
    command_configuration);

static int
command_configuration(int argc __unused, char *argv[] __unused)
{
	UINTN i;
	char *name;

	printf("NumberOfTableEntries=%lu\n",
		(unsigned long)ST->NumberOfTableEntries);
	for (i = 0; i < ST->NumberOfTableEntries; i++) {
		EFI_GUID *guid;

		printf("  ");
		guid = &ST->ConfigurationTable[i].VendorGuid;

		if (efi_guid_to_name(guid, &name) == true) {
			printf(name);
			free(name);
		} else {
			printf("Error while translating UUID to name");
		}
		printf(" at %p\n", ST->ConfigurationTable[i].VendorTable);
	}

	return (CMD_OK);
}


COMMAND_SET(mode, "mode", "change or display EFI text modes", command_mode);

static int
command_mode(int argc, char *argv[])
{
	UINTN cols, rows;
	unsigned int mode;
	int i;
	char *cp;
	char rowenv[8];
	EFI_STATUS status;
	SIMPLE_TEXT_OUTPUT_INTERFACE *conout;
	extern void HO(void);

	conout = ST->ConOut;

	if (argc > 1) {
		mode = strtol(argv[1], &cp, 0);
		if (cp[0] != '\0') {
			printf("Invalid mode\n");
			return (CMD_ERROR);
		}
		status = conout->QueryMode(conout, mode, &cols, &rows);
		if (EFI_ERROR(status)) {
			printf("invalid mode %d\n", mode);
			return (CMD_ERROR);
		}
		status = conout->SetMode(conout, mode);
		if (EFI_ERROR(status)) {
			printf("couldn't set mode %d\n", mode);
			return (CMD_ERROR);
		}
		sprintf(rowenv, "%u", (unsigned)rows);
		setenv("LINES", rowenv, 1);
		sprintf(rowenv, "%u", (unsigned)cols);
		setenv("COLUMNS", rowenv, 1);
		HO();		/* set cursor */
		return (CMD_OK);
	}

	printf("Current mode: %d\n", conout->Mode->Mode);
	for (i = 0; i <= conout->Mode->MaxMode; i++) {
		status = conout->QueryMode(conout, i, &cols, &rows);
		if (EFI_ERROR(status))
			continue;
		printf("Mode %d: %u columns, %u rows\n", i, (unsigned)cols,
		    (unsigned)rows);
	}

	if (i != 0)
		printf("Select a mode with the command \"mode <number>\"\n");

	return (CMD_OK);
}

COMMAND_SET(lsefi, "lsefi", "list EFI handles", command_lsefi);

static int
command_lsefi(int argc __unused, char *argv[] __unused)
{
	char *name;
	EFI_HANDLE *buffer = NULL;
	EFI_HANDLE handle;
	UINTN bufsz = 0, i, j;
	EFI_STATUS status;
	int ret;

	status = BS->LocateHandle(AllHandles, NULL, NULL, &bufsz, buffer);
	if (status != EFI_BUFFER_TOO_SMALL) {
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "unexpected error: %lld", (long long)status);
		return (CMD_ERROR);
	}
	if ((buffer = malloc(bufsz)) == NULL) {
		sprintf(command_errbuf, "out of memory");
		return (CMD_ERROR);
	}

	status = BS->LocateHandle(AllHandles, NULL, NULL, &bufsz, buffer);
	if (EFI_ERROR(status)) {
		free(buffer);
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "LocateHandle() error: %lld", (long long)status);
		return (CMD_ERROR);
	}

	pager_open();
	for (i = 0; i < (bufsz / sizeof (EFI_HANDLE)); i++) {
		UINTN nproto = 0;
		EFI_GUID **protocols = NULL;

		handle = buffer[i];
		printf("Handle %p", handle);
		if (pager_output("\n"))
			break;
		/* device path */

		status = BS->ProtocolsPerHandle(handle, &protocols, &nproto);
		if (EFI_ERROR(status)) {
			snprintf(command_errbuf, sizeof (command_errbuf),
			    "ProtocolsPerHandle() error: %lld",
			    (long long)status);
			continue;
		}

		for (j = 0; j < nproto; j++) {
			if (efi_guid_to_name(protocols[j], &name) == true) {
				printf("  %s", name);
				free(name);
			} else {
				printf("Error while translating UUID to name");
			}
			if ((ret = pager_output("\n")) != 0)
				break;
		}
		BS->FreePool(protocols);
		if (ret != 0)
			break;
	}
	pager_close();
	free(buffer);
	return (CMD_OK);
}

COMMAND_SET(lszfs, "lszfs", "list child datasets of a zfs dataset",
    command_lszfs);

static int
command_lszfs(int argc, char *argv[])
{
	int err;

	if (argc != 2) {
		command_errmsg = "wrong number of arguments";
		return (CMD_ERROR);
	}

	err = zfs_list(argv[1]);
	if (err != 0) {
		command_errmsg = strerror(err);
		return (CMD_ERROR);
	}
	return (CMD_OK);
}

#ifdef __FreeBSD__
COMMAND_SET(reloadbe, "reloadbe", "refresh the list of ZFS Boot Environments",
	    command_reloadbe);

static int
command_reloadbe(int argc, char *argv[])
{
	int err;
	char *root;

	if (argc > 2) {
		command_errmsg = "wrong number of arguments";
		return (CMD_ERROR);
	}

	if (argc == 2) {
		err = zfs_bootenv(argv[1]);
	} else {
		root = getenv("zfs_be_root");
		if (root == NULL) {
			return (CMD_OK);
		}
		err = zfs_bootenv(root);
	}

	if (err != 0) {
		command_errmsg = strerror(err);
		return (CMD_ERROR);
	}

	return (CMD_OK);
}
#endif /* __FreeBSD__ */

#ifdef LOADER_FDT_SUPPORT
extern int command_fdt_internal(int argc, char *argv[]);

/*
 * Since proper fdt command handling function is defined in fdt_loader_cmd.c,
 * and declaring it as extern is in contradiction with COMMAND_SET() macro
 * (which uses static pointer), we're defining wrapper function, which
 * calls the proper fdt handling routine.
 */
static int
command_fdt(int argc, char *argv[])
{
	return (command_fdt_internal(argc, argv));
}

COMMAND_SET(fdt, "fdt", "flattened device tree handling", command_fdt);
#endif

/*
 * Chain load another efi loader.
 */
static int
command_chain(int argc, char *argv[])
{
	EFI_GUID LoadedImageGUID = LOADED_IMAGE_PROTOCOL;
	EFI_HANDLE loaderhandle;
	EFI_LOADED_IMAGE *loaded_image;
	EFI_STATUS status;
	struct stat st;
	struct devdesc *dev;
	char *name, *path;
	void *buf;
	int fd;

	if (argc < 2) {
		command_errmsg = "wrong number of arguments";
		return (CMD_ERROR);
	}

	name = argv[1];

	if ((fd = open(name, O_RDONLY)) < 0) {
		command_errmsg = "no such file";
		return (CMD_ERROR);
	}

	if (fstat(fd, &st) < -1) {
		command_errmsg = "stat failed";
		close(fd);
		return (CMD_ERROR);
	}

	status = BS->AllocatePool(EfiLoaderCode, (UINTN)st.st_size, &buf);
	if (status != EFI_SUCCESS) {
		command_errmsg = "failed to allocate buffer";
		close(fd);
		return (CMD_ERROR);
	}
	if (read(fd, buf, st.st_size) != st.st_size) {
		command_errmsg = "error while reading the file";
		(void)BS->FreePool(buf);
		close(fd);
		return (CMD_ERROR);
	}
	close(fd);
	status = BS->LoadImage(FALSE, IH, NULL, buf, st.st_size, &loaderhandle);
	(void)BS->FreePool(buf);
	if (status != EFI_SUCCESS) {
		command_errmsg = "LoadImage failed";
		return (CMD_ERROR);
	}
	status = BS->HandleProtocol(loaderhandle, &LoadedImageGUID,
	    (void **)&loaded_image);

	if (argc > 2) {
		int i, len = 0;
		CHAR16 *argp;

		for (i = 2; i < argc; i++)
			len += strlen(argv[i]) + 1;

		len *= sizeof (*argp);
		loaded_image->LoadOptions = argp = malloc (len);
		if (loaded_image->LoadOptions == NULL) {
			(void) BS->UnloadImage(loaded_image);
			return (CMD_ERROR);
		}
		loaded_image->LoadOptionsSize = len;
		for (i = 2; i < argc; i++) {
			char *ptr = argv[i];
			while (*ptr)
				*(argp++) = *(ptr++);
			*(argp++) = ' ';
		}
		*(--argv) = 0;
	}

	if (efi_getdev((void **)&dev, name, (const char **)&path) == 0) {
		struct zfs_devdesc *z_dev;
		struct disk_devdesc *d_dev;
		pdinfo_t *hd, *pd;

		switch (dev->d_type) {
		case DEVT_ZFS:
			z_dev = (struct zfs_devdesc *)dev;
			loaded_image->DeviceHandle =
			    efizfs_get_handle_by_guid(z_dev->pool_guid);
			break;
		case DEVT_NET:
			loaded_image->DeviceHandle =
			    efi_find_handle(dev->d_dev, dev->d_unit);
			break;
		default:
			hd = efiblk_get_pdinfo(dev);
			if (STAILQ_EMPTY(&hd->pd_part)) {
				loaded_image->DeviceHandle = hd->pd_handle;
				break;
			}
			d_dev = (struct disk_devdesc *)dev;
			STAILQ_FOREACH(pd, &hd->pd_part, pd_link) {
				/*
				 * d_partition should be 255
				 */
				if (pd->pd_unit == d_dev->d_slice) {
					loaded_image->DeviceHandle =
					    pd->pd_handle;
					break;
				}
			}
			break;
		}
	}

	dev_cleanup();
	status = BS->StartImage(loaderhandle, NULL, NULL);
	if (status != EFI_SUCCESS) {
		command_errmsg = "StartImage failed";
		free(loaded_image->LoadOptions);
		loaded_image->LoadOptions = NULL;
		status = BS->UnloadImage(loaded_image);
		return (CMD_ERROR);
	}

	return (CMD_ERROR);	/* not reached */
}

COMMAND_SET(chain, "chain", "chain load file", command_chain);
