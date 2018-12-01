/*
 * Copyright (c) 2009 Jared D. McNeill <jmcneill@invisible.ca>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * VESA BIOS Extensions routines
 */

#include <stand.h>
#include <stdbool.h>
#include <bootstrap.h>
#include <machine/bootinfo.h>
#include <machine/metadata.h>
#include <sys/multiboot2.h>
#include <btxv86.h>
#include "libi386.h"
#include "gfx_fb.h"	/* for EDID */
#include "vbe.h"
#include <sys/vgareg.h>
#include <sys/vgasubr.h>

multiboot_tag_vbe_t vbestate;
static struct vbeinfoblock *vbe =
    (struct vbeinfoblock *) &vbestate.vbe_control_info;
static struct modeinfoblock *vbe_mode =
    (struct modeinfoblock *) &vbestate.vbe_mode_info;
multiboot_color_t cmap[16];

/* Actually assuming mode 3. */
void
bios_set_text_mode(int mode)
{
	int atr;

	v86.ctl = V86_FLAGS;
	v86.addr = 0x10;
	v86.eax = mode;				/* set VGA text mode */
	v86int();
	atr = vga_get_atr(VGA_REG_ADDR, VGA_ATR_MODE);
	atr &= ~VGA_ATR_MODE_BLINK;
	atr &= ~VGA_ATR_MODE_9WIDE;
	vga_set_atr(VGA_REG_ADDR, VGA_ATR_MODE, atr);

	vbestate.vbe_mode = 0;			/* vbe is disabled */
	gfx_fb.framebuffer_common.framebuffer_type =
	    MULTIBOOT_FRAMEBUFFER_TYPE_EGA_TEXT;
	/* 16 bits per character */
	gfx_fb.framebuffer_common.framebuffer_bpp = 16;
	gfx_fb.framebuffer_common.framebuffer_addr =
	    VGA_MEM_ADDR + VGA_COLOR_BASE;
	gfx_fb.framebuffer_common.framebuffer_width = TEXT_COLS;
	gfx_fb.framebuffer_common.framebuffer_height = TEXT_ROWS;
	gfx_fb.framebuffer_common.framebuffer_pitch = TEXT_COLS * 2;
}

/* Function 00h - Return VBE Controller Information */
static int
biosvbe_info(struct vbeinfoblock *vbe)
{
	v86.ctl = V86_FLAGS;
	v86.addr = 0x10;
	v86.eax = 0x4f00;
	v86.es = VTOPSEG(vbe);
	v86.edi = VTOPOFF(vbe);
	v86int();
	return (v86.eax & 0xffff);
}

/* Function 01h - Return VBE Mode Information */
static int
biosvbe_get_mode_info(int mode, struct modeinfoblock *mi)
{
	v86.ctl = V86_FLAGS;
	v86.addr = 0x10;
	v86.eax = 0x4f01;
	v86.ecx = mode;
	v86.es = VTOPSEG(mi);
	v86.edi = VTOPOFF(mi);
	v86int();
	return (v86.eax & 0xffff);
}

/* Function 02h - Set VBE Mode */
static int
biosvbe_set_mode(int mode, struct crtciinfoblock *ci)
{
	v86.ctl = V86_FLAGS;
	v86.addr = 0x10;
	v86.eax = 0x4f02;
	v86.ebx = mode | 0x4000;	/* set linear FB bit */
	v86.es = VTOPSEG(ci);
	v86.edi = VTOPOFF(ci);
	v86int();
	return (v86.eax & 0xffff);
}

/* Function 03h - Get VBE Mode */
static int
biosvbe_get_mode(int *mode)
{
	v86.ctl = V86_FLAGS;
	v86.addr = 0x10;
	v86.eax = 0x4f03;
	v86int();
	*mode = v86.ebx & 0xffff;
	return (v86.eax & 0xffff);
}

/* Function 08h - Set/Get DAC Palette Format */
int
biosvbe_palette_format(int *format)
{
	v86.ctl = V86_FLAGS;
	v86.addr = 0x10;
	v86.eax = 0x4f08;
	v86.ebx = *format;
	v86int();
	*format = v86.ebx & 0xffff;
	return (v86.eax & 0xffff);
}

/* Function 09h - Set/Get Palette Data */
static int
biosvbe_palette_data(int mode, int reg, struct paletteentry *pe)
{
	v86.ctl = V86_FLAGS;
	v86.addr = 0x10;
	v86.eax = 0x4f09;
	v86.ebx = mode;
	v86.edx = reg;
	v86.ecx = 1;
	v86.es = VTOPSEG(pe);
	v86.edi = VTOPOFF(pe);
	v86int();
	return (v86.eax & 0xffff);
}

/*
 * Function 15h BL=00h - Report VBE/DDC Capabilities
 *
 * int biosvbe_ddc_caps(void)
 * return: VBE/DDC capabilities
 */
static int
biosvbe_ddc_caps(void)
{
	v86.ctl = V86_FLAGS;
	v86.addr = 0x10;
	v86.eax = 0x4f15;	/* display identification extensions */
	v86.ebx = 0;		/* report DDC capabilities */
	v86.ecx = 0;		/* controller unit number (00h = primary) */
	v86.es = 0;
	v86.edi = 0;
	v86int();
	if (VBE_ERROR(v86.eax & 0xffff))
		return (0);
	return (v86.ebx & 0xffff);
}

/* Function 15h BL=01h - Read EDID */
static int
biosvbe_ddc_read_edid(int blockno, void *buf)
{
	v86.ctl = V86_FLAGS;
	v86.addr = 0x10;
	v86.eax = 0x4f15;	/* display identification extensions */
	v86.ebx = 1;		/* read EDID */
	v86.ecx = 0;		/* controller unit number (00h = primary) */
	v86.edx = blockno;
	v86.es = VTOPSEG(buf);
	v86.edi = VTOPOFF(buf);
	v86int();
	return (v86.eax & 0xffff);
}

static int
vbe_mode_is_supported(struct modeinfoblock *mi)
{
	if ((mi->ModeAttributes & 0x01) == 0)
		return 0;	/* mode not supported by hardware */
	if ((mi->ModeAttributes & 0x08) == 0)
		return 0;	/* linear fb not available */
	if ((mi->ModeAttributes & 0x10) == 0)
		return 0;	/* text mode */
	if (mi->NumberOfPlanes != 1)
		return 0;	/* planar mode not supported */
	if (mi->MemoryModel != 0x04 /* Packed pixel */ &&
	    mi->MemoryModel != 0x06 /* Direct Color */)
		return 0;	/* unsupported pixel format */
	return 1;
}

static int
vbe_check(void)
{
	if (vbestate.mb_type != MULTIBOOT_TAG_TYPE_VBE) {
		printf("VBE not available\n");
		return (0);
	}
	return (1);
}

void
vbe_init(void)
{
	/* First set FB for text mode. */
	gfx_fb.framebuffer_common.mb_type = MULTIBOOT_TAG_TYPE_FRAMEBUFFER;
	gfx_fb.framebuffer_common.framebuffer_type =
	    MULTIBOOT_FRAMEBUFFER_TYPE_EGA_TEXT;
	/* 16 bits per character */
	gfx_fb.framebuffer_common.framebuffer_bpp = 16;
	gfx_fb.framebuffer_common.framebuffer_addr =
	    VGA_MEM_ADDR + VGA_COLOR_BASE;
	gfx_fb.framebuffer_common.framebuffer_width = TEXT_COLS;
	gfx_fb.framebuffer_common.framebuffer_height = TEXT_ROWS;
	gfx_fb.framebuffer_common.framebuffer_pitch = TEXT_COLS * 2;

	/* Now check if we have vesa. */
	memset(vbe, 0, sizeof(*vbe));
	memcpy(vbe->VbeSignature, "VBE2", 4);
	if (biosvbe_info(vbe) != VBE_SUCCESS)
		return;
	if (memcmp(vbe->VbeSignature, "VESA", 4) != 0)
		return;

	vbestate.mb_type = MULTIBOOT_TAG_TYPE_VBE;
	vbestate.mb_size = sizeof (vbestate);
	vbestate.vbe_mode = 0;
	/* vbe_set_mode() will set up the rest. */
}

int
vbe_available(void)
{
	return vbestate.mb_type;
}

int
vbe_set_palette(const struct paletteentry *entry, size_t slot)
{
	struct paletteentry pe;
	int ret;

	if (!vbe_check())
		return (1);

	if (gfx_fb.framebuffer_common.framebuffer_type !=
	    MULTIBOOT_FRAMEBUFFER_TYPE_INDEXED) {
		return (1);
	}

	pe.Blue = entry->Blue;
	pe.Green = entry->Green;
	pe.Red = entry->Red;
	pe.Alignment = entry->Alignment;

	ret = biosvbe_palette_data(0x00, slot, &pe);
	if (ret == VBE_SUCCESS && slot < sizeof (cmap)) {
		cmap[slot].mb_red = entry->Red;
		cmap[slot].mb_green = entry->Green;
		cmap[slot].mb_blue = entry->Blue;
	}

	return (ret == VBE_SUCCESS ? 0 : 1);
}

int
vbe_get_mode(void)
{
	return vbestate.vbe_mode;
}

int
vbe_set_mode(int modenum)
{
	struct modeinfoblock mi;
	int ret;

	if (!vbe_check())
		return (1);

	ret = biosvbe_get_mode_info(modenum, &mi);
	if (VBE_ERROR(ret)) {
		printf("mode 0x%x invalid\n", modenum);
		return (1);
	}

	if (!vbe_mode_is_supported(&mi)) {
		printf("mode 0x%x not supported\n", modenum);
		return (1);
	}

	/* calculate bytes per pixel */
	switch (mi.BitsPerPixel) {
	case 32:
	case 24:
	case 16:
	case 15:
	case 8:
		break;
	default:
		printf("BitsPerPixel %d is not supported\n", mi.BitsPerPixel);
		return (1);
	}

	ret = biosvbe_set_mode(modenum, NULL);
	if (VBE_ERROR(ret)) {
		printf("mode 0x%x could not be set\n", modenum);
		return (1);
	}

	/* make sure we have current MI in vbestate */
	memcpy(vbe_mode, &mi, sizeof (*vbe_mode));
	vbestate.vbe_mode = modenum;

	gfx_fb.framebuffer_common.framebuffer_addr =
	    (uint64_t)mi.PhysBasePtr & 0xffffffff;
	gfx_fb.framebuffer_common.framebuffer_width = mi.XResolution;
	gfx_fb.framebuffer_common.framebuffer_height = mi.YResolution;
	gfx_fb.framebuffer_common.framebuffer_bpp = mi.BitsPerPixel;

	/* vbe_mode_is_supported() excludes the rest */
	switch (mi.MemoryModel) {
	case 0x4:
		gfx_fb.framebuffer_common.framebuffer_type =
		    MULTIBOOT_FRAMEBUFFER_TYPE_INDEXED;
		if (vbe->VbeVersion >= 0x300) {
			gfx_fb.framebuffer_common.framebuffer_pitch =
			    mi.LinBytesPerScanLine;
		} else {
			gfx_fb.framebuffer_common.framebuffer_pitch =
			    mi.BytesPerScanLine;
		}
		gfx_fb.u.fb1.framebuffer_palette_num_colors = 16;
		return (0);	/* done */
	case 0x6:
		gfx_fb.framebuffer_common.framebuffer_type =
		    MULTIBOOT_FRAMEBUFFER_TYPE_RGB;
		break;
	}

	if (vbe->VbeVersion >= 0x300) {
		gfx_fb.framebuffer_common.framebuffer_pitch =
		    mi.LinBytesPerScanLine;
		gfx_fb.u.fb2.framebuffer_red_field_position =
		    mi.LinRedFieldPosition;
		gfx_fb.u.fb2.framebuffer_red_mask_size = mi.LinRedMaskSize;
		gfx_fb.u.fb2.framebuffer_green_field_position =
		    mi.LinGreenFieldPosition;
		gfx_fb.u.fb2.framebuffer_green_mask_size = mi.LinGreenMaskSize;
		gfx_fb.u.fb2.framebuffer_blue_field_position =
		    mi.LinBlueFieldPosition;
		gfx_fb.u.fb2.framebuffer_blue_mask_size = mi.LinBlueMaskSize;
	} else {
		gfx_fb.framebuffer_common.framebuffer_pitch =
		    mi.BytesPerScanLine;
		gfx_fb.u.fb2.framebuffer_red_field_position =
		    mi.RedFieldPosition;
		gfx_fb.u.fb2.framebuffer_red_mask_size = mi.RedMaskSize;
		gfx_fb.u.fb2.framebuffer_green_field_position =
		    mi.GreenFieldPosition;
		gfx_fb.u.fb2.framebuffer_green_mask_size = mi.GreenMaskSize;
		gfx_fb.u.fb2.framebuffer_blue_field_position =
		    mi.BlueFieldPosition;
		gfx_fb.u.fb2.framebuffer_blue_mask_size = mi.BlueMaskSize;
	}

	return (0);
}

static void *
vbe_farptr(uint32_t farptr)
{
	return PTOV((((farptr & 0xffff0000) >> 12) + (farptr & 0xffff)));
}

/*
 * Verify existance of mode number or find mode by
 * dimensions. If depth is not given, walk values 32, 24, 16, 8.
 */
static int
vbe_find_mode_xydm(int x, int y, int depth, int m)
{
	struct modeinfoblock mi;
	uint32_t farptr;
	uint16_t mode;
	int safety = 0, i;

	memset(vbe, 0, sizeof(vbe));
	memcpy(vbe->VbeSignature, "VBE2", 4);
	if (biosvbe_info(vbe) != VBE_SUCCESS)
		return (0);
	if (memcmp(vbe->VbeSignature, "VESA", 4) != 0)
		return (0);
	farptr = vbe->VideoModePtr;
	if (farptr == 0)
		return (0);

	if (m != -1)
		i = 8;
	else if (depth == -1)
		i = 32;
	else
		i = depth;

	while (i > 0) {
		while ((mode = *(uint16_t *)vbe_farptr(farptr)) != 0xffff) {
			safety++;
			farptr += 2;
			if (safety == 100)
				return 0;
			if (biosvbe_get_mode_info(mode, &mi) != VBE_SUCCESS) {
				continue;
			}
			/* we only care about linear modes here */
			if (vbe_mode_is_supported(&mi) == 0)
				continue;
			safety = 0;

			if (m != -1) {
				if (m == mode)
					return (mode);
				else
					continue;
			}

			if (mi.XResolution == x &&
			    mi.YResolution == y &&
			    mi.BitsPerPixel == i)
				return mode;
		}
		if (depth != -1)
			break;

		i -= 8;
	}

	return (0);
}

static int
vbe_find_mode(char *str)
{
	int x, y, depth;

	if (!gfx_parse_mode_str(str, &x, &y, &depth))
		return (0);

	return (vbe_find_mode_xydm(x, y, depth, -1));
}

static void
vbe_dump_mode(int modenum, struct modeinfoblock *mi)
{
	printf("0x%x=%dx%dx%d", modenum,
	    mi->XResolution, mi->YResolution, mi->BitsPerPixel);
}

static bool
vbe_get_edid(uint_t *pwidth, uint_t *pheight)
{
	struct vesa_edid_info edid_info;
	const uint8_t magic[] = EDID_MAGIC;
	int ddc_caps, ret;

	ddc_caps = biosvbe_ddc_caps();
	if (ddc_caps == 0) {
		return (false);
	}

	ret = biosvbe_ddc_read_edid(0, &edid_info);
	if (VBE_ERROR(ret))
		return (false);

	if (memcmp(&edid_info, magic, sizeof (magic)) != 0)
		return (false);

	if (!(edid_info.header.version == 1 &&
	    (edid_info.display.supported_features
	    & EDID_FEATURE_PREFERRED_TIMING_MODE) &&
	    edid_info.detailed_timings[0].pixel_clock))
		return (false);

	*pwidth = edid_info.detailed_timings[0].horizontal_active_lo |
	    (((uint_t)edid_info.detailed_timings[0].horizontal_hi & 0xf0) << 4);
	*pheight = edid_info.detailed_timings[0].vertical_active_lo |
	    (((uint_t)edid_info.detailed_timings[0].vertical_hi & 0xf0) << 4);

	return (true);
}

static void
vbe_print_vbe_info(struct vbeinfoblock *vbep)
{
	char *oemstring = "";
	char *oemvendor = "", *oemproductname = "", *oemproductrev = "";

	if (vbep->OemStringPtr != 0)
		oemstring = vbe_farptr(vbep->OemStringPtr);

	if (vbep->OemVendorNamePtr != 0)
		oemvendor = vbe_farptr(vbep->OemVendorNamePtr);

	if (vbep->OemProductNamePtr != 0)
		oemproductname = vbe_farptr(vbep->OemProductNamePtr);

	if (vbep->OemProductRevPtr != 0)
		oemproductrev = vbe_farptr(vbep->OemProductRevPtr);

	printf("VESA VBE Version %d.%d\n%s\n", vbep->VbeVersion >> 8,
	    vbep->VbeVersion & 0xF, oemstring);

	if (vbep->OemSoftwareRev != 0) {
		printf("OEM Version %d.%d, %s (%s, %s)\n",
		    vbep->OemSoftwareRev >> 8, vbep->OemSoftwareRev & 0xF,
			oemvendor, oemproductname, oemproductrev);
	}
}

/* List available modes, filter by depth. If depth is -1, list all. */
void
vbe_modelist(int depth)
{
	struct modeinfoblock mi;
	uint32_t farptr;
	uint16_t mode;
	int nmodes = 0, safety = 0;
	int ddc_caps;
	uint_t edid_width, edid_height;

	if (!vbe_check())
		return;

	ddc_caps = biosvbe_ddc_caps();
	if (ddc_caps & 3) {
		printf("DDC");
		if (ddc_caps & 1)
			printf(" [DDC1]");
		if (ddc_caps & 2)
			printf(" [DDC2]");

		if (vbe_get_edid(&edid_width, &edid_height))
			printf(": EDID %dx%d\n", edid_width, edid_height);
		else
			printf(": no EDID information\n");
	}

	memset(vbe, 0, sizeof(vbe));
	memcpy(vbe->VbeSignature, "VBE2", 4);
	if (biosvbe_info(vbe) != VBE_SUCCESS)
		goto done;
	if (memcmp(vbe->VbeSignature, "VESA", 4) != 0)
		goto done;

	vbe_print_vbe_info(vbe);
	printf("Modes: ");

	farptr = vbe->VideoModePtr;
	if (farptr == 0)
		goto done;

	while ((mode = *(uint16_t *)vbe_farptr(farptr)) != 0xffff) {
		safety++;
		farptr += 2;
		if (safety == 100) {
			printf("[?] ");
			break;
		}
		if (biosvbe_get_mode_info(mode, &mi) != VBE_SUCCESS)
			continue;
		/* we only care about linear modes here */
		if (vbe_mode_is_supported(&mi) == 0)
			continue;

		/* we found some mode so reset safety counter */
		safety = 0;

		/* apply requested filter */
		if (depth != -1 && mi.BitsPerPixel != depth)
			continue;

		if (nmodes % 4 == 0)
			printf("\n");
		else
			printf("  ");

		vbe_dump_mode(mode, &mi);
		nmodes++;
	}

done:
	if (nmodes == 0)
		printf("none found");
	printf("\n");
}

static void
vbe_print_mode(void)
{
	int mode, i, rc;
	struct paletteentry pe;

	memset(vbe, 0, sizeof(vbe));
	memcpy(vbe->VbeSignature, "VBE2", 4);
	if (biosvbe_info(vbe) != VBE_SUCCESS)
		return;

	if (memcmp(vbe->VbeSignature, "VESA", 4) != 0)
		return;

	vbe_print_vbe_info(vbe);

	if (biosvbe_get_mode(&mode) != VBE_SUCCESS) {
		printf("Error getting current VBE mode\n");
		return;
	}

	if (biosvbe_get_mode_info(mode, vbe_mode) != VBE_SUCCESS ||
	    vbe_mode_is_supported(vbe_mode) == 0) {
		printf("VBE mode (0x%x) is not framebuffer mode\n", mode);
		return;
	}

	printf("\nCurrent VBE mode: ");
	vbe_dump_mode(mode, vbe_mode);
	printf("\n");

	printf("%ux%ux%u, stride=%u",
	    gfx_fb.framebuffer_common.framebuffer_width,
	    gfx_fb.framebuffer_common.framebuffer_height,
	    gfx_fb.framebuffer_common.framebuffer_bpp,
            (gfx_fb.framebuffer_common.framebuffer_pitch << 3) /
	    gfx_fb.framebuffer_common.framebuffer_bpp);
	printf("\n    frame buffer: address=%jx, size=%jx",
	    (uintmax_t) gfx_fb.framebuffer_common.framebuffer_addr,
	    (uintmax_t) gfx_fb.framebuffer_common.framebuffer_height *
	    gfx_fb.framebuffer_common.framebuffer_pitch);

	if (vbe_mode->MemoryModel == 0x6) {
		printf("\n    color mask: R=%08x, G=%08x, B=%08x\n",
		    ((1 << gfx_fb.u.fb2.framebuffer_red_mask_size) - 1) <<
		    gfx_fb.u.fb2.framebuffer_red_field_position,
		    ((1 << gfx_fb.u.fb2.framebuffer_green_mask_size) - 1) <<
		    gfx_fb.u.fb2.framebuffer_green_field_position,
		    ((1 << gfx_fb.u.fb2.framebuffer_blue_mask_size) - 1) <<
		    gfx_fb.u.fb2.framebuffer_blue_field_position);
		return;
	}

	mode = 1;	/* get DAC palette width */
	rc = biosvbe_palette_format(&mode);
	if (rc != VBE_SUCCESS)
		return;

	printf("    palette format: %x bits per primary\n", mode >> 8);
	for (i = 0; i < 16; i++) {
		rc = biosvbe_palette_data(1, i, &pe);
		if (rc != VBE_SUCCESS)
			break;

		printf("%d: R=%02x, G=%02x, B=%02x\n", i,
		    pe.Red, pe.Green, pe.Blue);
	}
}

int
vbe_default_mode(void)
{
	int modenum;
	uint_t edid_width, edid_height;

	if (vbe_get_edid(&edid_width, &edid_height)) {
		modenum = vbe_find_mode_xydm(edid_width, edid_height, -1, -1);
		if (modenum == 0)
			modenum = vbe_find_mode(VBE_DEFAULT_MODE);
	} else {
		modenum = vbe_find_mode(VBE_DEFAULT_MODE);
	}
	return (modenum);
}

COMMAND_SET(framebuffer, "framebuffer", "framebuffer mode management",
    command_vesa);

int
command_vesa(int argc, char *argv[])
{
	char *arg, *cp;
	int modenum = -1, n;

	if (!vbe_check())
		return (CMD_OK);

	if (argc < 2)
		goto usage;

	if (strcmp(argv[1], "list") == 0) {
		n = -1;
		if (argc != 2 && argc != 3)
			goto usage;

		if (argc == 3) {
			arg = argv[2];
			errno = 0;
			n = strtoul(arg, &cp, 0);
			if (errno != 0 || *arg == '\0' || cp[0] != '\0') {
				snprintf(command_errbuf,
				    sizeof (command_errbuf),
				    "depth should be an integer");
				return (CMD_ERROR);
			}
		}
		vbe_modelist(n);
		return (CMD_OK);
	}

	if (strcmp(argv[1], "get") == 0) {
		if (argc != 2)
			goto usage;

		vbe_print_mode();
		return (CMD_OK);
	}

	if (strcmp(argv[1], "off") == 0) {
		if (argc != 2)
			goto usage;

		if (vbestate.vbe_mode == 0)
			return (CMD_OK);

		bios_set_text_mode(VGA_TEXT_MODE);
		plat_cons_update_mode(0);
		return (CMD_OK);
	}

	if (strcmp(argv[1], "on") == 0) {
		if (argc != 2)
			goto usage;

		modenum = vbe_default_mode();
		if (modenum == 0) {
			snprintf(command_errbuf, sizeof (command_errbuf),
			    "%s: no suitable VBE mode number found", argv[0]);
			return (CMD_ERROR);
		}
	} else if (strcmp(argv[1], "set") == 0) {
		if (argc != 3)
			goto usage;

		if (strncmp(argv[2], "0x", 2) == 0) {
			arg = argv[2];
			errno = 0;
			n = strtoul(arg, &cp, 0);
			if (errno != 0 || *arg == '\0' || cp[0] != '\0') {
				snprintf(command_errbuf,
				    sizeof (command_errbuf),
				    "mode should be an integer");
				return (CMD_ERROR);
			}
			modenum = vbe_find_mode_xydm(0, 0, 0, n);
		} else if (strchr(argv[2], 'x') != NULL) {
			modenum = vbe_find_mode(argv[2]);
		}
	}

	if (modenum == 0) {
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "%s: mode %s not supported by firmware\n",
		    argv[0], argv[2]);
		return (CMD_ERROR);
	}

	if (modenum >= 0x100) {
		if (vbestate.vbe_mode != modenum) {
			vbe_set_mode(modenum);
			plat_cons_update_mode(1);
		}
		return (CMD_OK);
	} else {
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "%s: mode %s is not framebuffer mode\n", argv[0], argv[2]);
		return (CMD_ERROR);
	}

usage:
	snprintf(command_errbuf, sizeof (command_errbuf),
	    "usage: %s on | off | get | list [depth] | "
	    "set <display or VBE mode number>", argv[0]);
	return (CMD_ERROR);
}
