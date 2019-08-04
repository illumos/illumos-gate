/*
 * Copyright (c) 2013 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Benno Rice under sponsorship from
 * the FreeBSD Foundation.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <stand.h>
#include <bootstrap.h>
#include <sys/endian.h>
#include <sys/consplat.h>

#include <efi.h>
#include <efilib.h>
#include <efiuga.h>
#include <efipciio.h>
#include <Protocol/EdidActive.h>
#include <Protocol/EdidDiscovered.h>
#include <machine/metadata.h>

#include "gfx_fb.h"
#include "framebuffer.h"

EFI_GUID gop_guid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
static EFI_GUID pciio_guid = EFI_PCI_IO_PROTOCOL_GUID;
EFI_GUID uga_guid = EFI_UGA_DRAW_PROTOCOL_GUID;
static EFI_GUID active_edid_guid = EFI_EDID_ACTIVE_PROTOCOL_GUID;
static EFI_GUID discovered_edid_guid = EFI_EDID_DISCOVERED_PROTOCOL_GUID;

/* Saved initial GOP mode. */
static uint32_t default_mode = (uint32_t)-1;

static uint32_t gop_default_mode(void);
static int efifb_set_mode(EFI_GRAPHICS_OUTPUT *, u_int);

static uint_t
efifb_color_depth(struct efi_fb *efifb)
{
	uint32_t mask;
	uint_t depth;

	mask = efifb->fb_mask_red | efifb->fb_mask_green |
	    efifb->fb_mask_blue | efifb->fb_mask_reserved;
	if (mask == 0)
		return (0);
	for (depth = 1; mask != 1; depth++)
		mask >>= 1;
	return (depth);
}

static int
efifb_mask_from_pixfmt(struct efi_fb *efifb, EFI_GRAPHICS_PIXEL_FORMAT pixfmt,
    EFI_PIXEL_BITMASK *pixinfo)
{
	int result;

	result = 0;
	switch (pixfmt) {
	case PixelRedGreenBlueReserved8BitPerColor:
		efifb->fb_mask_red = 0x000000ff;
		efifb->fb_mask_green = 0x0000ff00;
		efifb->fb_mask_blue = 0x00ff0000;
		efifb->fb_mask_reserved = 0xff000000;
		break;
	case PixelBlueGreenRedReserved8BitPerColor:
		efifb->fb_mask_red = 0x00ff0000;
		efifb->fb_mask_green = 0x0000ff00;
		efifb->fb_mask_blue = 0x000000ff;
		efifb->fb_mask_reserved = 0xff000000;
		break;
	case PixelBitMask:
		efifb->fb_mask_red = pixinfo->RedMask;
		efifb->fb_mask_green = pixinfo->GreenMask;
		efifb->fb_mask_blue = pixinfo->BlueMask;
		efifb->fb_mask_reserved = pixinfo->ReservedMask;
		break;
	default:
		result = 1;
		break;
	}
	return (result);
}

static int
efifb_from_gop(struct efi_fb *efifb, EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *mode,
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info)
{
	int result;

	efifb->fb_addr = mode->FrameBufferBase;
	efifb->fb_size = mode->FrameBufferSize;
	efifb->fb_height = info->VerticalResolution;
	efifb->fb_width = info->HorizontalResolution;
	efifb->fb_stride = info->PixelsPerScanLine;
	result = efifb_mask_from_pixfmt(efifb, info->PixelFormat,
	    &info->PixelInformation);
	if (efifb->fb_addr == 0)
		result = 1;
	return (result);
}

static ssize_t
efifb_uga_find_pixel(EFI_UGA_DRAW_PROTOCOL *uga, u_int line,
    EFI_PCI_IO_PROTOCOL *pciio, uint64_t addr, uint64_t size)
{
	EFI_UGA_PIXEL pix0, pix1;
	uint8_t *data1, *data2;
	size_t count, maxcount = 1024;
	ssize_t ofs;
	EFI_STATUS status;
	u_int idx;

	status = uga->Blt(uga, &pix0, EfiUgaVideoToBltBuffer,
	    0, line, 0, 0, 1, 1, 0);
	if (EFI_ERROR(status)) {
		printf("UGA BLT operation failed (video->buffer)");
		return (-1);
	}
	pix1.Red = ~pix0.Red;
	pix1.Green = ~pix0.Green;
	pix1.Blue = ~pix0.Blue;
	pix1.Reserved = 0;

	data1 = calloc(maxcount, 2);
	if (data1 == NULL) {
		printf("Unable to allocate memory");
		return (-1);
	}
	data2 = data1 + maxcount;

	ofs = 0;
	while (size > 0) {
		count = min(size, maxcount);

		status = pciio->Mem.Read(pciio, EfiPciIoWidthUint32,
		    EFI_PCI_IO_PASS_THROUGH_BAR, addr + ofs, count >> 2,
		    data1);
		if (EFI_ERROR(status)) {
			printf("Error reading frame buffer (before)");
			goto fail;
		}
		status = uga->Blt(uga, &pix1, EfiUgaBltBufferToVideo,
		    0, 0, 0, line, 1, 1, 0);
		if (EFI_ERROR(status)) {
			printf("UGA BLT operation failed (modify)");
			goto fail;
		}
		status = pciio->Mem.Read(pciio, EfiPciIoWidthUint32,
		    EFI_PCI_IO_PASS_THROUGH_BAR, addr + ofs, count >> 2,
		    data2);
		if (EFI_ERROR(status)) {
			printf("Error reading frame buffer (after)");
			goto fail;
		}
		status = uga->Blt(uga, &pix0, EfiUgaBltBufferToVideo,
		    0, 0, 0, line, 1, 1, 0);
		if (EFI_ERROR(status)) {
			printf("UGA BLT operation failed (restore)");
			goto fail;
		}
		for (idx = 0; idx < count; idx++) {
			if (data1[idx] != data2[idx]) {
				free(data1);
				return (ofs + (idx & ~3));
			}
		}
		ofs += count;
		size -= count;
	}
	printf("No change detected in frame buffer");

 fail:
	printf(" -- error %lu\n", EFI_ERROR_CODE(status));
	free(data1);
	return (-1);
}

static EFI_PCI_IO_PROTOCOL *
efifb_uga_get_pciio(void)
{
	EFI_PCI_IO_PROTOCOL *pciio;
	EFI_HANDLE *buf, *hp;
	EFI_STATUS status;
	UINTN bufsz;

	/* Get all handles that support the UGA protocol. */
	bufsz = 0;
	status = BS->LocateHandle(ByProtocol, &uga_guid, NULL, &bufsz, NULL);
	if (status != EFI_BUFFER_TOO_SMALL)
		return (NULL);
	buf = malloc(bufsz);
	status = BS->LocateHandle(ByProtocol, &uga_guid, NULL, &bufsz, buf);
	if (status != EFI_SUCCESS) {
		free(buf);
		return (NULL);
	}
	bufsz /= sizeof(EFI_HANDLE);

	/* Get the PCI I/O interface of the first handle that supports it. */
	pciio = NULL;
	for (hp = buf; hp < buf + bufsz; hp++) {
		status = OpenProtocolByHandle(*hp, &pciio_guid,
		    (void **)&pciio);
		if (status == EFI_SUCCESS) {
			free(buf);
			return (pciio);
		}
	}
	free(buf);
	return (NULL);
}

static EFI_STATUS
efifb_uga_locate_framebuffer(EFI_PCI_IO_PROTOCOL *pciio, uint64_t *addrp,
    uint64_t *sizep)
{
	uint8_t *resattr;
	uint64_t addr, size;
	EFI_STATUS status;
	u_int bar;

	if (pciio == NULL)
		return (EFI_DEVICE_ERROR);

	/* Attempt to get the frame buffer address (imprecise). */
	*addrp = 0;
	*sizep = 0;
	for (bar = 0; bar < 6; bar++) {
		status = pciio->GetBarAttributes(pciio, bar, NULL,
		    (void **)&resattr);
		if (status != EFI_SUCCESS)
			continue;
		/* XXX magic offsets and constants. */
		if (resattr[0] == 0x87 && resattr[3] == 0) {
			/* 32-bit address space descriptor (MEMIO) */
			addr = le32dec(resattr + 10);
			size = le32dec(resattr + 22);
		} else if (resattr[0] == 0x8a && resattr[3] == 0) {
			/* 64-bit address space descriptor (MEMIO) */
			addr = le64dec(resattr + 14);
			size = le64dec(resattr + 38);
		} else {
			addr = 0;
			size = 0;
		}
		BS->FreePool(resattr);
		if (addr == 0 || size == 0)
			continue;

		/* We assume the largest BAR is the frame buffer. */
		if (size > *sizep) {
			*addrp = addr;
			*sizep = size;
		}
	}
	return ((*addrp == 0 || *sizep == 0) ? EFI_DEVICE_ERROR : 0);
}

static int
efifb_from_uga(struct efi_fb *efifb, EFI_UGA_DRAW_PROTOCOL *uga)
{
	EFI_PCI_IO_PROTOCOL *pciio;
	char *ev, *p;
	EFI_STATUS status;
	ssize_t offset;
	uint64_t fbaddr;
	uint32_t horiz, vert, stride;
	uint32_t np, depth, refresh;

	status = uga->GetMode(uga, &horiz, &vert, &depth, &refresh);
	if (EFI_ERROR(status))
		return (1);
	efifb->fb_height = vert;
	efifb->fb_width = horiz;
	/* Paranoia... */
	if (efifb->fb_height == 0 || efifb->fb_width == 0)
		return (1);

	/* The color masks are fixed AFAICT. */
	efifb_mask_from_pixfmt(efifb, PixelBlueGreenRedReserved8BitPerColor,
	    NULL);

	/* pciio can be NULL on return! */
	pciio = efifb_uga_get_pciio();

	/* Try to find the frame buffer. */
	status = efifb_uga_locate_framebuffer(pciio, &efifb->fb_addr,
	    &efifb->fb_size);
	if (EFI_ERROR(status)) {
		efifb->fb_addr = 0;
		efifb->fb_size = 0;
	}

	/*
	 * There's no reliable way to detect the frame buffer or the
	 * offset within the frame buffer of the visible region, nor
	 * the stride. Our only option is to look at the system and
	 * fill in the blanks based on that. Luckily, UGA was mostly
	 * only used on Apple hardware.
	 */
	offset = -1;
	ev = getenv("smbios.system.maker");
	if (ev != NULL && !strcmp(ev, "Apple Inc.")) {
		ev = getenv("smbios.system.product");
		if (ev != NULL && !strcmp(ev, "iMac7,1")) {
			/* These are the expected values we should have. */
			horiz = 1680;
			vert = 1050;
			fbaddr = 0xc0000000;
			/* These are the missing bits. */
			offset = 0x10000;
			stride = 1728;
		} else if (ev != NULL && !strcmp(ev, "MacBook3,1")) {
			/* These are the expected values we should have. */
			horiz = 1280;
			vert = 800;
			fbaddr = 0xc0000000;
			/* These are the missing bits. */
			offset = 0x0;
			stride = 2048;
		}
	}

	/*
	 * If this is hardware we know, make sure that it looks familiar
	 * before we accept our hardcoded values.
	 */
	if (offset >= 0 && efifb->fb_width == horiz &&
	    efifb->fb_height == vert && efifb->fb_addr == fbaddr) {
		efifb->fb_addr += offset;
		efifb->fb_size -= offset;
		efifb->fb_stride = stride;
		return (0);
	} else if (offset >= 0) {
		printf("Hardware make/model known, but graphics not "
		    "as expected.\n");
		printf("Console may not work!\n");
	}

	/*
	 * The stride is equal or larger to the width. Often it's the
	 * next larger power of two. We'll start with that...
	 */
	efifb->fb_stride = efifb->fb_width;
	do {
		np = efifb->fb_stride & (efifb->fb_stride - 1);
		if (np) {
			efifb->fb_stride |= (np - 1);
			efifb->fb_stride++;
		}
	} while (np);

	ev = getenv("hw.efifb.address");
	if (ev == NULL) {
		if (efifb->fb_addr == 0) {
			printf("Please set hw.efifb.address and "
			    "hw.efifb.stride.\n");
			return (1);
		}

		/*
		 * The visible part of the frame buffer may not start at
		 * offset 0, so try to detect it. Note that we may not
		 * always be able to read from the frame buffer, which
		 * means that we may not be able to detect anything. In
		 * that case, we would take a long time scanning for a
		 * pixel change in the frame buffer, which would have it
		 * appear that we're hanging, so we limit the scan to
		 * 1/256th of the frame buffer. This number is mostly
		 * based on PR 202730 and the fact that on a MacBoook,
		 * where we can't read from the frame buffer the offset
		 * of the visible region is 0. In short: we want to scan
		 * enough to handle all adapters that have an offset
		 * larger than 0 and we want to scan as little as we can
		 * to not appear to hang when we can't read from the
		 * frame buffer.
		 */
		offset = efifb_uga_find_pixel(uga, 0, pciio, efifb->fb_addr,
		    efifb->fb_size >> 8);
		if (offset == -1) {
			printf("Unable to reliably detect frame buffer.\n");
		} else if (offset > 0) {
			efifb->fb_addr += offset;
			efifb->fb_size -= offset;
		}
	} else {
		offset = 0;
		efifb->fb_size = efifb->fb_height * efifb->fb_stride * 4;
		efifb->fb_addr = strtoul(ev, &p, 0);
		if (*p != '\0')
			return (1);
	}

	ev = getenv("hw.efifb.stride");
	if (ev == NULL) {
		if (pciio != NULL && offset != -1) {
			/* Determine the stride. */
			offset = efifb_uga_find_pixel(uga, 1, pciio,
			    efifb->fb_addr, horiz * 8);
			if (offset != -1)
				efifb->fb_stride = offset >> 2;
		} else {
			printf("Unable to reliably detect the stride.\n");
		}
	} else {
		efifb->fb_stride = strtoul(ev, &p, 0);
		if (*p != '\0')
			return (1);
	}

	/*
	 * We finalized on the stride, so recalculate the size of the
	 * frame buffer.
	 */
	efifb->fb_size = efifb->fb_height * efifb->fb_stride * 4;
	if (efifb->fb_addr == 0)
		return (1);
	return (0);
}

/*
 * Fetch EDID info. Caller must free the buffer.
 */
static struct vesa_edid_info *
efifb_gop_get_edid(EFI_HANDLE gop)
{
	const uint8_t magic[] = EDID_MAGIC;
	EFI_EDID_ACTIVE_PROTOCOL *edid;
	struct vesa_edid_info *edid_info;
	EFI_GUID *guid;
	EFI_STATUS status;
	size_t size;

	edid_info = calloc(1, sizeof (*edid_info));
	if (edid_info == NULL)
		return (NULL);

	guid = &active_edid_guid;
	status = BS->OpenProtocol(gop, guid, (void **)&edid, IH, NULL,
	    EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (status != EFI_SUCCESS) {
		guid = &discovered_edid_guid;
		status = BS->OpenProtocol(gop, guid, (void **)&edid, IH, NULL,
		    EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	}
	if (status != EFI_SUCCESS)
		goto error;

	size = edid->SizeOfEdid;
	if (size > sizeof (*edid_info))
		size = sizeof (*edid_info);

	memcpy(edid_info, edid->Edid, size);
	status = BS->CloseProtocol(gop, guid, IH, NULL);

	/* Validate EDID */
	if (memcmp(edid_info, magic, sizeof(magic)) != 0)
		goto error;

	if (edid_info->header.version == 1 &&
	    (edid_info->display.supported_features
	    & EDID_FEATURE_PREFERRED_TIMING_MODE) &&
	    edid_info->detailed_timings[0].pixel_clock) {
		return (edid_info);
	}

error:
	free(edid_info);
	return (NULL);
}

static int
efifb_get_edid(UINT32 *pwidth, UINT32 *pheight)
{
	extern EFI_GRAPHICS_OUTPUT *gop;
	struct vesa_edid_info *edid_info;
	int rv = 1;

	edid_info = efifb_gop_get_edid(gop);
	if (edid_info != NULL) {
		*pwidth = GET_EDID_INFO_WIDTH(edid_info, 0);
		*pheight = GET_EDID_INFO_HEIGHT(edid_info, 0);
		rv = 0;
	}
	free(edid_info);
	return (rv);
}

int
efi_find_framebuffer(struct efi_fb *efifb)
{
	extern EFI_GRAPHICS_OUTPUT *gop;
	extern EFI_UGA_DRAW_PROTOCOL *uga;
	EFI_STATUS status;
	uint32_t mode;

	if (gop != NULL)
		return (efifb_from_gop(efifb, gop->Mode, gop->Mode->Info));

	status = BS->LocateProtocol(&gop_guid, NULL, (VOID **)&gop);
	if (status == EFI_SUCCESS) {
		/* Save default mode. */
		if (default_mode == (uint32_t)-1) {
			default_mode = gop->Mode->Mode;
		}
		mode = gop_default_mode();
		if (mode != gop->Mode->Mode)
			efifb_set_mode(gop, mode);
		return (efifb_from_gop(efifb, gop->Mode, gop->Mode->Info));
	}

	if (uga != NULL)
		return (efifb_from_uga(efifb, uga));

	status = BS->LocateProtocol(&uga_guid, NULL, (VOID **)&uga);
	if (status == EFI_SUCCESS)
		return (efifb_from_uga(efifb, uga));

	return (1);
}

static void
print_efifb(int mode, struct efi_fb *efifb, int verbose)
{
	uint_t depth;
	UINT32 width, height;

	if (verbose == 1) {
		printf("Framebuffer mode: %s\n",
		    plat_stdout_is_framebuffer() ? "on" : "off");
		if (efifb_get_edid(&width, &height) == 0)
			printf("EDID mode: %dx%d\n\n", width, height);
	}

	if (mode >= 0) {
		if (verbose == 1)
			printf("GOP ");
		printf("mode %d: ", mode);
	}
	depth = efifb_color_depth(efifb);
	printf("%ux%ux%u", efifb->fb_width, efifb->fb_height, depth);
	if (verbose)
		printf(", stride=%u", efifb->fb_stride);
	if (verbose) {
		printf("\n    frame buffer: address=%jx, size=%jx",
		    (uintmax_t)efifb->fb_addr, (uintmax_t)efifb->fb_size);
		printf("\n    color mask: R=%08x, G=%08x, B=%08x\n",
		    efifb->fb_mask_red, efifb->fb_mask_green,
		    efifb->fb_mask_blue);
		if (efifb->fb_addr == 0) {
			printf("Warning: this mode is not implementing the "
			    "linear framebuffer. The illumos\n\tconsole is "
			    "not available with this mode and will default to "
			    "ttya\n");
		}
	}
}

static int
efifb_set_mode(EFI_GRAPHICS_OUTPUT *gop, u_int mode)
{
	EFI_STATUS status;

	status = gop->SetMode(gop, mode);
	if (EFI_ERROR(status)) {
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "Unable to set mode to %u (error=%lu)",
		    mode, EFI_ERROR_CODE(status));
		return (CMD_ERROR);
	}
	return (CMD_OK);
}

/*
 * Verify existance of mode number or find mode by
 * dimensions. If depth is not given, walk values 32, 24, 16, 8.
 * Return MaxMode if mode is not found.
 */
static int
efifb_find_mode_xydm(UINT32 x, UINT32 y, int depth, int m)
{
	extern EFI_GRAPHICS_OUTPUT *gop;
	EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info;
	EFI_STATUS status;
	UINTN infosz;
	struct efi_fb fb;
	UINT32 mode;
        uint_t d, i;

        if (m != -1)
                i = 8;
        else if (depth == -1)
                i = 32;
        else
                i = depth;

        while (i > 0) {
		for (mode = 0; mode < gop->Mode->MaxMode; mode++) {
			status = gop->QueryMode(gop, mode, &infosz, &info);
			if (EFI_ERROR(status))
				continue;

			if (m != -1) {
				if ((UINT32)m == mode)
					return (mode);
				else
					continue;
			}

			efifb_from_gop(&fb, gop->Mode, info);
			d = efifb_color_depth(&fb);
			if (x == fb.fb_width && y == fb.fb_height && d == i)
				return (mode);
		}

		if (depth != -1)
			break;

		i -= 8;
	}

	return (gop->Mode->MaxMode);
}

static int
efifb_find_mode(char *str)
{
	extern EFI_GRAPHICS_OUTPUT *gop;
	int x, y, depth;

	if (!gfx_parse_mode_str(str, &x, &y, &depth))
		return (gop->Mode->MaxMode);

	return (efifb_find_mode_xydm(x, y, depth, -1));
}

/*
 * gop_default_mode(). Try to set mode based on EDID.
 */
static uint32_t
gop_default_mode(void)
{
	extern EFI_GRAPHICS_OUTPUT *gop;
	UINT32 mode, width = 0, height = 0;

	mode = gop->Mode->MaxMode;
	if (efifb_get_edid(&width, &height) == 0)
		mode = efifb_find_mode_xydm(width, height, -1, -1);

	if (mode == gop->Mode->MaxMode)
		mode = default_mode;

	return (mode);
}

COMMAND_SET(framebuffer, "framebuffer", "framebuffer mode management",
    command_gop);

static int
command_gop(int argc, char *argv[])
{
	extern struct efi_fb efifb;
	extern EFI_GRAPHICS_OUTPUT *gop;
	struct efi_fb fb;
	EFI_STATUS status;
	char *arg, *cp;
	u_int mode;

	if (gop == NULL) {
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "%s: Graphics Output Protocol not present", argv[0]);
		return (CMD_ERROR);
	}

	if (argc < 2)
		goto usage;

	/*
	 * Note we can not turn the GOP itself off, but instead we instruct
	 * tem to use text mode.
	 */
	if (strcmp(argv[1], "off") == 0) {
		if (argc != 2)
			goto usage;

		plat_cons_update_mode(EfiConsoleControlScreenText);
		return (CMD_OK);
	}

	/*
	 * Set GOP to use default mode, then notify tem.
	 */
	if (strcmp(argv[1], "on") == 0) {
		if (argc != 2)
			goto usage;

		mode = gop_default_mode();
		if (mode != gop->Mode->Mode)
			efifb_set_mode(gop, mode);

		plat_cons_update_mode(EfiConsoleControlScreenGraphics);
		return (CMD_OK);
	}

	if (!strcmp(argv[1], "set")) {
		int rv;

		if (argc != 3)
			goto usage;

		arg = argv[2];
		if (strchr(arg, 'x') == NULL) {
			errno = 0;
			mode = strtoul(arg, &cp, 0);
			if (errno != 0 || *arg == '\0' || cp[0] != '\0') {
				snprintf(command_errbuf,
				    sizeof (command_errbuf),
				    "mode should be an integer");
				return (CMD_ERROR);
			}
			mode = efifb_find_mode_xydm(0, 0, 0, mode);
		} else {
			mode = efifb_find_mode(arg);
		}

		if (mode == gop->Mode->MaxMode)
			mode = gop->Mode->Mode;

		rv = efifb_set_mode(gop, mode);
		plat_cons_update_mode(EfiConsoleControlScreenGraphics);
		return (rv);
	}

	if (!strcmp(argv[1], "get")) {
		if (argc != 2)
			goto usage;

		print_efifb(gop->Mode->Mode, &efifb, 1);
		printf("\n");
		return (CMD_OK);
	}

	if (!strcmp(argv[1], "list")) {
		EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info;
		UINTN infosz;
		int depth, d = -1;

		if (argc != 2 && argc != 3)
			goto usage;

		if (argc == 3) {
			arg = argv[2];
			errno = 0;
			d = strtoul(arg, &cp, 0);
			if (errno != 0 || *arg == '\0' || cp[0] != '\0') {
				snprintf(command_errbuf,
				    sizeof (command_errbuf),
				    "depth should be an integer");
				return (CMD_ERROR);
			}
		}
		pager_open();
		for (mode = 0; mode < gop->Mode->MaxMode; mode++) {
			status = gop->QueryMode(gop, mode, &infosz, &info);
			if (EFI_ERROR(status))
				continue;
			efifb_from_gop(&fb, gop->Mode, info);
			depth = efifb_color_depth(&fb);
			if (d != -1 && d != depth)
				continue;
			print_efifb(mode, &fb, 0);
			if (pager_output("\n"))
				break;
		}
		pager_close();
		return (CMD_OK);
	}

usage:
	snprintf(command_errbuf, sizeof (command_errbuf),
	    "usage: %s on | off | get | list [depth] | "
	    "set <display or GOP mode number>", argv[0]);
	return (CMD_ERROR);
}

COMMAND_SET(uga, "uga", "universal graphics adapter", command_uga);

static int
command_uga(int argc, char *argv[])
{
	extern struct efi_fb efifb;
	extern EFI_UGA_DRAW_PROTOCOL *uga;

	if (uga == NULL) {
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "%s: UGA Protocol not present", argv[0]);
		return (CMD_ERROR);
	}

	if (argc != 1)
		goto usage;

	if (efifb.fb_addr == 0) {
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "%s: Unable to get UGA information", argv[0]);
		return (CMD_ERROR);
	}

	print_efifb(-1, &efifb, 1);
	printf("\n");
	return (CMD_OK);

 usage:
	snprintf(command_errbuf, sizeof (command_errbuf), "usage: %s", argv[0]);
	return (CMD_ERROR);
}
