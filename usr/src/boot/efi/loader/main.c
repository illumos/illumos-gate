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
#include <sys/consplat.h>
#include <sys/zfs_bootenv.h>
#include <stand.h>
#include <inttypes.h>
#include <string.h>
#include <setjmp.h>
#include <disk.h>

#include <efi.h>
#include <efilib.h>
#include <efichar.h>
#include <eficonsctl.h>
#include <efidevp.h>
#include <Guid/SmBios.h>
#include <Protocol/DevicePath.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SerialIo.h>
#include <Protocol/SimpleTextIn.h>
#include <Uefi/UefiGpt.h>

#include <uuid.h>

#include <bootstrap.h>
#include <gfx_fb.h>
#include <smbios.h>

#include <libzfs.h>
#include <efizfs.h>

#include "loader_efi.h"

struct arch_switch archsw;	/* MI/MD interface boundary */

EFI_GUID gEfiLoadedImageProtocolGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
EFI_GUID gEfiSmbiosTableGuid = SMBIOS_TABLE_GUID;
EFI_GUID gEfiSmbios3TableGuid = SMBIOS3_TABLE_GUID;

extern void acpi_detect(void);
extern void efi_getsmap(void);

/*
 * Number of seconds to wait for a keystroke before exiting with failure
 * in the event no currdev is found. -2 means always break, -1 means
 * never break, 0 means poll once and then reboot, > 0 means wait for
 * that many seconds. "fail_timeout" can be set in the environment as
 * well.
 */
static int fail_timeout = 5;

bool
efi_zfs_is_preferred(EFI_HANDLE *h)
{
	EFI_DEVICE_PATH *devpath, *dp, *node;
	HARDDRIVE_DEVICE_PATH *hd;
	bool ret;
	extern UINT64 start_sector;	/* from mb_header.S */

	/* This check is true for chainloader case. */
	if (h == boot_img->DeviceHandle)
		return (true);

	/*
	 * Make sure the image was loaded from the hard disk.
	 */
	devpath = efi_lookup_devpath(boot_img->DeviceHandle);
	if (devpath == NULL)
		return (false);
	node = efi_devpath_last_node(devpath);
	if (node == NULL)
		return (false);
	if (DevicePathType(node) != MEDIA_DEVICE_PATH ||
	    (DevicePathSubType(node) != MEDIA_FILEPATH_DP &&
	    DevicePathSubType(node) != MEDIA_HARDDRIVE_DP)) {
		return (false);
	}

	/*
	 * XXX We ignore the MEDIA_FILEPATH_DP here for now as it is
	 * used on arm and we do not support arm.
	 */
	ret = false;
	dp = efi_devpath_trim(devpath);
	devpath = NULL;
	if (dp == NULL)
		goto done;

	devpath = efi_lookup_devpath(h);
	if (devpath == NULL)
		goto done;
	hd = (HARDDRIVE_DEVICE_PATH *)efi_devpath_last_node(devpath);
	if (hd == NULL) {
		devpath = NULL;
		goto done;
	}
	devpath = efi_devpath_trim(devpath);
	if (devpath == NULL)
		goto done;

	if (!efi_devpath_match(dp, devpath))
		goto done;

	/* It is the same disk, do we have partition start? */
	if (start_sector == 0)
		ret = true;
	else if (start_sector == hd->PartitionStart)
		ret = true;

done:
	free(dp);
	free(devpath);
	return (ret);
}

static bool
has_keyboard(void)
{
	EFI_STATUS status;
	EFI_DEVICE_PATH *path;
	EFI_HANDLE *hin;
	uint_t i, nhandles;
	bool retval = false;

	/*
	 * Find all the handles that support the SIMPLE_TEXT_INPUT_PROTOCOL and
	 * do the typical dance to get the right sized buffer.
	 */
	status = efi_get_protocol_handles(&gEfiSimpleTextInProtocolGuid,
	    &nhandles, &hin);
	if (EFI_ERROR(status))
		return (retval);

	/*
	 * Look at each of the handles. If it supports the device path protocol,
	 * use it to get the device path for this handle. Then see if that
	 * device path matches either the USB device path for keyboards or the
	 * legacy device path for keyboards.
	 */
	for (i = 0; i < nhandles; i++) {
		status = OpenProtocolByHandle(hin[i],
		    &gEfiDevicePathProtocolGuid, (void **)&path);
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
				if ((EISA_ID_TO_NUM(acpi->HID) & 0xff00) ==
				    0x300 &&
				    (acpi->HID & 0xffff) == PNP_EISA_ID_CONST) {
					retval = true;
					goto out;
				}
			/*
			 * Check for USB keyboard node, if present. Unlike a
			 * PS/2 keyboard, these definitely only appear when
			 * connected to the system.
			 */
			} else if (DevicePathType(path) ==
			    MESSAGING_DEVICE_PATH &&
			    DevicePathSubType(path) == MSG_USB_CLASS_DP) {
				USB_CLASS_DEVICE_PATH *usb;

				/*
				 * Check for:
				 * DeviceClass: HID
				 * DeviceSubClass: Boot devices
				 * DeviceProtocol: Boot keyboards
				 */
				usb = (USB_CLASS_DEVICE_PATH *)(void *)path;
				if (usb->DeviceClass == 3 &&
				    usb->DeviceSubClass == 1 &&
				    usb->DeviceProtocol == 1) {
					retval = true;
					goto out;
				}
			}
			path = NextDevicePathNode(path);
		}
	}
out:
	free(hin);
	return (retval);
}

static void
set_currdev(const char *devname)
{

	/*
	 * Don't execute hooks here; we may need to try setting these more than
	 * once here if we're probing for the ZFS pool we're supposed to boot.
	 * The currdev hook is intended to just validate user input anyways,
	 * while the loaddev hook makes it immutable once we've determined what
	 * the proper currdev is.
	 */
	env_setenv("currdev", EV_VOLATILE | EV_NOHOOK, devname, efi_setcurrdev,
	    env_nounset);
	env_setenv("loaddev", EV_VOLATILE | EV_NOHOOK, devname, env_noset,
	    env_nounset);
}

static void
set_currdev_devdesc(struct devdesc *currdev)
{
	char *devname;

	devname = efi_fmtdev(currdev);

	printf("Setting currdev to %s\n", devname);
	set_currdev(devname);
}

static void
set_currdev_devsw(struct devsw *dev, int unit)
{
	struct devdesc currdev;

	currdev.d_dev = dev;
	currdev.d_unit = unit;

	set_currdev_devdesc(&currdev);
}

static void
set_currdev_pdinfo(pdinfo_t *dp)
{

	/*
	 * Disks are special: they have partitions. if the parent
	 * pointer is non-null, we're a partition not a full disk
	 * and we need to adjust currdev appropriately.
	 */
	if (dp->pd_devsw->dv_type == DEVT_DISK) {
		struct disk_devdesc currdev;

		currdev.dd.d_dev = dp->pd_devsw;
		if (dp->pd_parent == NULL) {
			currdev.dd.d_unit = dp->pd_unit;
			currdev.d_slice = D_SLICENONE;
			currdev.d_partition = D_PARTNONE;
		} else {
			currdev.dd.d_unit = dp->pd_parent->pd_unit;
			currdev.d_slice = dp->pd_unit;
			currdev.d_partition = D_PARTISGPT; /* Assumes GPT */
		}
		set_currdev_devdesc((struct devdesc *)&currdev);
	} else {
		set_currdev_devsw(dp->pd_devsw, dp->pd_unit);
	}
}

static bool
sanity_check_currdev(void)
{
	struct stat st;

	return (stat("/boot/defaults/loader.conf", &st) == 0);
}

static bool
probe_zfs_currdev(uint64_t guid)
{
	struct zfs_devdesc currdev;
	char *bootonce;
	bool rv;

	currdev.dd.d_dev = &zfs_dev;
	currdev.dd.d_unit = 0;
	currdev.pool_guid = guid;
	currdev.root_guid = 0;
	set_currdev_devdesc((struct devdesc *)&currdev);

	rv = sanity_check_currdev();
	if (rv) {
		bootonce = malloc(VDEV_PAD_SIZE);
		if (bootonce != NULL) {
			if (zfs_get_bootonce(&currdev, OS_BOOTONCE, bootonce,
			    VDEV_PAD_SIZE) == 0) {
				printf("zfs bootonce: %s\n", bootonce);
				set_currdev(bootonce);
				setenv("zfs-bootonce", bootonce, 1);
			}
			free(bootonce);
			(void) zfs_attach_nvstore(&currdev);
		} else {
			printf("Failed to process bootonce data: %s\n",
			    strerror(errno));
		}
	}
	return (rv);
}

static bool
try_as_currdev(pdinfo_t *pp)
{
	uint64_t guid;

	/*
	 * If there's a zpool on this device, try it as a ZFS
	 * filesystem, which has somewhat different setup than all
	 * other types of fs due to imperfect loader integration.
	 * This all stems from ZFS being both a device (zpool) and
	 * a filesystem, plus the boot env feature.
	 */
	if (efizfs_get_guid_by_handle(pp->pd_handle, &guid))
		return (probe_zfs_currdev(guid));

	/*
	 * All other filesystems just need the pdinfo
	 * initialized in the standard way.
	 */
	set_currdev_pdinfo(pp);
	return (sanity_check_currdev());
}

static bool
find_currdev(EFI_LOADED_IMAGE_PROTOCOL *img)
{
	pdinfo_t *dp, *pp;
	EFI_DEVICE_PATH *devpath, *copy;
	EFI_HANDLE h;
	CHAR16 *text;
	struct devsw *dev;
	int unit;
	uint64_t extra;

	/*
	 * Did efi_zfs_probe() detect the boot pool? If so, use the zpool
	 * it found, if it's sane. ZFS is the only thing that looks for
	 * disks and pools to boot.
	 */
	if (pool_guid != 0) {
		printf("Trying ZFS pool\n");
		if (probe_zfs_currdev(pool_guid))
			return (true);
	}

	/*
	 * Try to find the block device by its handle based on the
	 * image we're booting. If we can't find a sane partition,
	 * search all the other partitions of the disk. We do not
	 * search other disks because it's a violation of the UEFI
	 * boot protocol to do so. We fail and let UEFI go on to
	 * the next candidate.
	 */
	dp = efiblk_get_pdinfo_by_handle(img->DeviceHandle);
	if (dp != NULL) {
		text = efi_devpath_name(dp->pd_devpath);
		if (text != NULL) {
			printf("Trying ESP: %S\n", text);
			efi_free_devpath_name(text);
		}
		set_currdev_pdinfo(dp);
		if (sanity_check_currdev())
			return (true);
		if (dp->pd_parent != NULL) {
			dp = dp->pd_parent;
			STAILQ_FOREACH(pp, &dp->pd_part, pd_link) {
				text = efi_devpath_name(pp->pd_devpath);
				if (text != NULL) {
					printf("And now the part: %S\n", text);
					efi_free_devpath_name(text);
				}
				/*
				 * Roll up the ZFS special case
				 * for those partitions that have
				 * zpools on them
				 */
				if (try_as_currdev(pp))
					return (true);
			}
		}
	}

	/*
	 * Try the device handle from our loaded image first.  If that
	 * fails, use the device path from the loaded image and see if
	 * any of the nodes in that path match one of the enumerated
	 * handles. Currently, this handle list is only for netboot.
	 */
	if (efi_handle_lookup(img->DeviceHandle, &dev, &unit, &extra) == 0) {
		set_currdev_devsw(dev, unit);
		if (sanity_check_currdev())
			return (true);
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
			set_currdev_devsw(dev, unit);
			if (sanity_check_currdev())
				return (true);
		}

		devpath = efi_lookup_devpath(h);
		if (devpath != NULL) {
			copy = efi_devpath_trim(devpath);
			devpath = copy;
		}
	}
	free(copy);

	return (false);
}

static bool
interactive_interrupt(const char *msg)
{
	time_t now, then, last;

	last = 0;
	now = then = getsecs();
	printf("%s\n", msg);
	if (fail_timeout == -2)			/* Always break to OK */
		return (true);
	if (fail_timeout == -1)			/* Never break to OK */
		return (false);
	do {
		if (last != now) {
			printf("press any key to interrupt reboot "
			    "in %d seconds\r",
			    fail_timeout - (int)(now - then));
			last = now;
		}

		/* XXX no pause or timeout wait for char */
		if (ischar())
			return (true);
		now = getsecs();
	} while (now - then < fail_timeout);
	return (false);
}

static void
setenv_int(const char *key, int val)
{
	char buf[20];

	(void) snprintf(buf, sizeof (buf), "%d", val);
	(void) setenv(key, buf, 1);
}

/*
 * Parse ConOut (the list of consoles active) and see if we can find a
 * serial port and/or a video port. It would be nice to also walk the
 * ACPI name space to map the UID for the serial port to a port. The
 * latter is especially hard.
 */
static int
parse_uefi_con_out(void)
{
	int how, rv;
	int vid_seen = 0, com_seen = 0, seen = 0;
	size_t sz;
	char buf[4096], *ep;
	EFI_DEVICE_PATH *node;
	ACPI_HID_DEVICE_PATH *acpi;
	UART_DEVICE_PATH *uart;
	bool pci_pending = false;

	how = 0;
	sz = sizeof (buf);
	rv = efi_global_getenv("ConOut", buf, &sz);
	if (rv != EFI_SUCCESS)
		rv = efi_global_getenv("ConOutDev", buf, &sz);
	if (rv != EFI_SUCCESS) {
		/*
		 * If we don't have any ConOut default to video.
		 * non-server systems may not have serial.
		 */
		goto out;
	}
	ep = buf + sz;
	node = (EFI_DEVICE_PATH *)buf;
	while ((char *)node < ep) {
		if (IsDevicePathEndType(node)) {
			if (pci_pending && vid_seen == 0)
				vid_seen = ++seen;
		}
		pci_pending = false;
		if (DevicePathType(node) == ACPI_DEVICE_PATH &&
		    (DevicePathSubType(node) == ACPI_DP ||
		    DevicePathSubType(node) == ACPI_EXTENDED_DP)) {
			/* Check for Serial node */
			acpi = (void *)node;
			if (EISA_ID_TO_NUM(acpi->HID) == 0x501) {
				setenv_int("efi_8250_uid", acpi->UID);
				com_seen = ++seen;
			}
		} else if (DevicePathType(node) == MESSAGING_DEVICE_PATH &&
		    DevicePathSubType(node) == MSG_UART_DP) {
			com_seen = ++seen;
			uart = (void *)node;
			setenv_int("efi_com_speed", uart->BaudRate);
		} else if (DevicePathType(node) == ACPI_DEVICE_PATH &&
		    DevicePathSubType(node) == ACPI_ADR_DP) {
			/* Check for AcpiAdr() Node for video */
			vid_seen = ++seen;
		} else if (DevicePathType(node) == HARDWARE_DEVICE_PATH &&
		    DevicePathSubType(node) == HW_PCI_DP) {
			/*
			 * Note, vmware fusion has a funky console device
			 *	PciRoot(0x0)/Pci(0xf,0x0)
			 * which we can only detect at the end since we also
			 * have to cope with:
			 *	PciRoot(0x0)/Pci(0x1f,0x0)/Serial(0x1)
			 * so only match it if it's last.
			 */
			pci_pending = true;
		}
		node = NextDevicePathNode(node); /* Skip the end node */
	}

	/*
	 * Truth table for RB_MULTIPLE | RB_SERIAL
	 * Value		Result
	 * 0			Use only video console
	 * RB_SERIAL		Use only serial console
	 * RB_MULTIPLE		Use both video and serial console
	 *			(but video is primary so gets rc messages)
	 * both			Use both video and serial console
	 *			(but serial is primary so gets rc messages)
	 *
	 * Try to honor this as best we can. If only one of serial / video
	 * found, then use that. Otherwise, use the first one we found.
	 * This also implies if we found nothing, default to video.
	 */
	how = 0;
	if (vid_seen && com_seen) {
		how |= RB_MULTIPLE;
		if (com_seen < vid_seen)
			how |= RB_SERIAL;
	} else if (com_seen)
		how |= RB_SERIAL;
out:
	return (how);
}

caddr_t
ptov(uintptr_t x)
{
	return ((caddr_t)x);
}

static int
efi_serial_get_uid(EFI_DEVICE_PATH *devpath)
{
	ACPI_HID_DEVICE_PATH  *acpi;

	while (!IsDevicePathEnd(devpath)) {
		if (DevicePathType(devpath) == ACPI_DEVICE_PATH &&
		    (DevicePathSubType(devpath) == ACPI_DP ||
		    DevicePathSubType(devpath) == ACPI_EXTENDED_DP)) {
			acpi = (ACPI_HID_DEVICE_PATH *)devpath;
			if (EISA_ID_TO_NUM(acpi->HID) == 0x501) {
				return (acpi->UID);
			}
		}

		devpath = NextDevicePathNode(devpath);
	}
	return (-1);
}

/*
 * Walk serialio protocol handle array and find index for serial console
 * device. The problem is, we check for acpi UID value, but we can not be sure,
 * if it will start from 0 or 1.
 */
static const char *
uefi_serial_console(void)
{
	EFI_STATUS status;
	EFI_HANDLE *handles;
	uint_t i, nhandles;
	unsigned long uid, lowest;
	char *env, *ep;

	env = getenv("efi_8250_uid");
	if (env == NULL)
		return (NULL);
	(void) unsetenv("efi_8250_uid");
	errno = 0;
	uid = strtoul(env, &ep, 10);
	if (errno != 0 || *ep != '\0')
		return (NULL);

	/* if uid is 0, this is first serial port */
	if (uid == 0)
		return ("ttya");

	status = efi_get_protocol_handles(&gEfiSerialIoProtocolGuid,
	    &nhandles, &handles);
	if (EFI_ERROR(status)) {
		return (NULL);
	}

	lowest = 255;	/* high enough value */
	for (i = 0; i < nhandles; i++) {
		EFI_DEVICE_PATH *devpath;
		unsigned long _uid;

		devpath = efi_lookup_devpath(handles[i]);
		_uid = efi_serial_get_uid(devpath);
		if (_uid < lowest)
			lowest = _uid;
	}
	free(handles);
	switch (uid - lowest) {
	case 0:
		return ("ttya");
	case 1:
		return ("ttyb");
	case 2:
		return ("ttyc");
	case 3:
		return ("ttyd");
	}
	return (NULL);
}

EFI_STATUS
main(int argc, CHAR16 *argv[])
{
	char var[128];
	int i, j, howto;
	bool vargood;
	void *ptr;
	bool has_kbd;
	char *s;
	const char *serial;
	EFI_DEVICE_PATH *imgpath;
	CHAR16 *text;
	EFI_STATUS status;
	UINT16 boot_current;
	size_t sz;
	UINT16 boot_order[100];

	archsw.arch_autoload = efi_autoload;
	archsw.arch_getdev = efi_getdev;
	archsw.arch_copyin = efi_copyin;
	archsw.arch_copyout = efi_copyout;
	archsw.arch_readin = efi_readin;
	archsw.arch_loadaddr = efi_loadaddr;
	archsw.arch_free_loadaddr = efi_free_loadaddr;
#if defined(__amd64) || defined(__i386)
	archsw.arch_hypervisor = x86_hypervisor;
#endif
	/* Note this needs to be set before ZFS init. */
	archsw.arch_zfs_probe = efi_zfs_probe;

	/*
	 * XXX Chicken-and-egg problem; we want to have console output
	 * early, but some console attributes may depend on reading from
	 * eg. the boot device, which we can't do yet.  We can use
	 * printf() etc. once this is done.
	 */
	setenv("console", "text", 1);
	howto = parse_uefi_con_out();
	serial = uefi_serial_console();
	cons_probe();
	efi_getsmap();

	if ((s = getenv("efi_com_speed")) != NULL) {
		char *name;

		(void) snprintf(var, sizeof (var), "%s,8,n,1,-", s);
		if (asprintf(&name, "%s-mode", serial) > 0) {
			(void) setenv(name, var, 1);
			free(name);
		}
		if (asprintf(&name, "%s-spcr-mode", serial) > 0) {
			(void) setenv(name, var, 1);
			free(name);
		}
		(void) unsetenv("efi_com_speed");
	}

	/* Init the time source */
	efi_time_init();

	/*
	 * Initialise the block cache. Set the upper limit.
	 */
	bcache_init(32768, 512);

	has_kbd = has_keyboard();

	/*
	 * Parse the args to set the console settings, etc
	 * iPXE may be setup to pass these in. Or the optional argument in the
	 * boot environment was used to pass these arguments in (in which case
	 * neither /boot.config nor /boot/config are consulted).
	 *
	 * Loop through the args, and for each one that contains an '=' that is
	 * not the first character, add it to the environment.  This allows
	 * loader and kernel env vars to be passed on the command line.  Convert
	 * args from UCS-2 to ASCII (16 to 8 bit) as they are copied (though
	 * this method is flawed for non-ASCII characters).
	 */
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
					if (!has_kbd) {
						howto |= RB_SERIAL;
						howto |= RB_MULTIPLE;
					}
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
							    sizeof (var));
						} else {
							CHAR16 *ptr;
							ptr = &argv[i + 1][0];
							cpy16to8(ptr, var,
							    sizeof (var));
						}
						i++;
					} else {
						cpy16to8(&argv[i][j + 1], var,
						    sizeof (var));
					}
					strncat(var, ",8,n,1,-", sizeof (var));
					setenv("ttya-mode", var, 1);
					break;
				case 'v':
					howto |= RB_VERBOSE;
					break;
				}
			}
		} else {
			vargood = false;
			for (j = 0; argv[i][j] != 0; j++) {
				if (j == sizeof (var)) {
					vargood = false;
					break;
				}
				if (j > 0 && argv[i][j] == '=')
					vargood = true;
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

	/*
	 * XXX we need fallback to this stuff after looking at the ConIn,
	 * ConOut and ConErr variables.
	 */
	if (howto & RB_MULTIPLE) {
		if (howto & RB_SERIAL)
			(void) snprintf(var, sizeof (var), "%s text", serial);
		else
			(void) snprintf(var, sizeof (var), "text %s", serial);
	} else if (howto & RB_SERIAL) {
		(void) snprintf(var, sizeof (var), "%s", serial);
	} else {
		(void) snprintf(var, sizeof (var), "text");
	}
	(void) setenv("console", var, 1);

	if ((s = getenv("fail_timeout")) != NULL)
		fail_timeout = strtol(s, NULL, 10);

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

	printf("Image base: 0x%lx\n", (unsigned long)boot_img->ImageBase);
	printf("EFI version: %d.%02d\n", ST->Hdr.Revision >> 16,
	    ST->Hdr.Revision & 0xffff);
	printf("EFI Firmware: %S (rev %d.%02d)\n", ST->FirmwareVendor,
	    ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);

	printf("\n%s", bootprog_info);

	/* Determine the devpath of our image so we can prefer it. */
	text = efi_devpath_name(boot_img->FilePath);
	if (text != NULL) {
		printf("   Load Path: %S\n", text);
		efi_setenv_illumos_wcs("LoaderPath", text);
		efi_free_devpath_name(text);
	}

	status = OpenProtocolByHandle(boot_img->DeviceHandle,
	    &gEfiDevicePathProtocolGuid, (void **)&imgpath);
	if (status == EFI_SUCCESS) {
		text = efi_devpath_name(imgpath);
		if (text != NULL) {
			printf("   Load Device: %S\n", text);
			efi_setenv_illumos_wcs("LoaderDev", text);
			efi_free_devpath_name(text);
		}
	}

	boot_current = 0;
	sz = sizeof (boot_current);
	efi_global_getenv("BootCurrent", &boot_current, &sz);
	printf("   BootCurrent: %04x\n", boot_current);

	sz = sizeof (boot_order);
	efi_global_getenv("BootOrder", &boot_order, &sz);
	printf("   BootOrder:");
	for (i = 0; i < sz / sizeof (boot_order[0]); i++)
		printf(" %04x%s", boot_order[i],
		    boot_order[i] == boot_current ? "[*]" : "");
	printf("\n");

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

	/*
	 * Try and find a good currdev based on the image that was booted.
	 * It might be desirable here to have a short pause to allow falling
	 * through to the boot loader instead of returning instantly to follow
	 * the boot protocol and also allow an escape hatch for users wishing
	 * to try something different.
	 */
	if (!find_currdev(boot_img))
		if (!interactive_interrupt("Failed to find bootable partition"))
			return (EFI_NOT_FOUND);

	autoload_font(false);		/* Set up the font list for console. */
	efi_init_environment();
	bi_isadir();			/* set ISADIR */
	acpi_detect();

	if ((ptr = efi_get_table(&gEfiSmbios3TableGuid)) == NULL)
		ptr = efi_get_table(&gEfiSmbiosTableGuid);
	smbios_detect(ptr);

	interact(NULL);			/* doesn't return */

	return (EFI_SUCCESS);		/* keep compiler happy */
}

COMMAND_SET(reboot, "reboot", "reboot the system", command_reboot);

static void
fw_setup(void)
{
	uint64_t os_indications;
	size_t size;
	EFI_STATUS status;

	size = sizeof (os_indications);
	status = efi_global_getenv("OsIndicationsSupported",
	    &os_indications, &size);
	if (EFI_ERROR(status) || size != sizeof (os_indications) ||
	    (os_indications & EFI_OS_INDICATIONS_BOOT_TO_FW_UI) == 0) {
		printf("Booting to Firmware UI is not supported in "
		    "this system.");
		for (int i = 0; i < 3; i++) {
			delay(1000 * 1000); /* 1 second */
			if (ischar())
				break;
		}
		return;
	}

	os_indications = EFI_OS_INDICATIONS_BOOT_TO_FW_UI;

	status = efi_global_setenv("OsIndications", &os_indications,
	    sizeof (os_indications));
}

static int
command_reboot(int argc, char *argv[])
{
	int i, ch;
	bool fw = false;

	optind = 1;
	optreset = 1;

	while ((ch = getopt(argc, argv, "fh")) != -1) {
		switch (ch) {
		case 'f':
			fw = true;
			break;
		case 'h':
			printf("Usage: reboot [-f]\n");
			return (CMD_OK);
		case '?':
		default:
			return (CMD_OK);
		}
	}

	if (fw || getenv("BOOT_TO_FW_UI") != NULL)
		fw_setup();

	for (i = 0; devsw[i] != NULL; ++i)
		if (devsw[i]->dv_cleanup != NULL)
			(devsw[i]->dv_cleanup)();

	RS->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);

	/* NOTREACHED */
	return (CMD_ERROR);
}

COMMAND_SET(poweroff, "poweroff", "power off the system", command_poweroff);

static int
command_poweroff(int argc __unused, char *argv[] __unused)
{
	int i;

	for (i = 0; devsw[i] != NULL; ++i)
		if (devsw[i]->dv_cleanup != NULL)
			(devsw[i]->dv_cleanup)();

	RS->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);

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
		snprintf(line, 80, "%23s %012jx %012jx %08jx ",
		    efi_memory_type(p->Type), p->PhysicalStart,
		    p->VirtualStart, p->NumberOfPages);
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
	EFI_STATUS status;
	SIMPLE_TEXT_OUTPUT_INTERFACE *conout;
	EFI_CONSOLE_CONTROL_SCREEN_MODE sm;

	if (plat_stdout_is_framebuffer())
		sm = EfiConsoleControlScreenGraphics;
	else
		sm = EfiConsoleControlScreenText;

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
		plat_cons_update_mode(sm);
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
	int ret = 0;

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
		EFI_DEVICE_PATH *dp;
		CHAR16 *text;

		handle = buffer[i];
		printf("Handle %p", handle);
		if (pager_output("\n"))
			break;

		ret = 0;
		dp = efi_lookup_devpath(handle);
		if (dp != NULL) {
			text = efi_devpath_name(dp);
			if (text != NULL) {
				printf("  %S", text);
				efi_free_devpath_name(text);
				ret = pager_output("\n");
			}
			efi_close_devpath(handle);
		}
		if (ret != 0)
			break;

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
	EFI_HANDLE loaderhandle;
	EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
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
		(void) BS->FreePool(buf);
		close(fd);
		return (CMD_ERROR);
	}
	close(fd);
	status = BS->LoadImage(FALSE, IH, NULL, buf, st.st_size, &loaderhandle);
	(void) BS->FreePool(buf);
	if (status != EFI_SUCCESS) {
		printf("LoadImage failed: status code: %lu\n",
		    DECODE_ERROR(status));
		return (CMD_ERROR);
	}
	status = OpenProtocolByHandle(loaderhandle,
	    &gEfiLoadedImageProtocolGuid, (void **)&loaded_image);

	if (argc > 2) {
		int i, len = 0;
		CHAR16 *argp;

		for (i = 2; i < argc; i++)
			len += strlen(argv[i]) + 1;

		len *= sizeof (*argp);
		loaded_image->LoadOptions = argp = malloc(len);
		if (loaded_image->LoadOptions == NULL) {
			command_errmsg = "Adding LoadOptions: out of memory";
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

		switch (dev->d_dev->dv_type) {
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
		printf("StartImage failed: status code: %lu\n",
		    DECODE_ERROR(status));
		free(loaded_image->LoadOptions);
		loaded_image->LoadOptions = NULL;
		status = BS->UnloadImage(loaded_image);
		return (CMD_ERROR);
	}

	return (CMD_ERROR);
}

COMMAND_SET(chain, "chain", "chain load file", command_chain);
