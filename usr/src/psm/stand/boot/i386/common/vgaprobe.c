/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/controlregs.h>
#include <sys/bootconf.h>
#include <sys/bootvfs.h>
#include <sys/psw.h>
#include "multiboot.h"
#include "bootprop.h"
#include "biosint.h"
#include "machine.h"
#include "standalloc.h"
#include "console.h"
#include "util.h"
#include "debug.h"

#define	FP_SEG(fp)	((((unsigned long)(fp)) >> 16) & 0xffff)
#define	FP_OFF(fp)	(((unsigned long)(fp)) & 0xffff)

#define	VESABIOS_SUPP_FUNC		0x4f
#define	VESABIOS_DISPLAY_ID_EXT		0x15

#pragma pack(1)
/*
 * Structure returned by monitors that support VESA DDC
 */
struct EDIFinfo {
	unsigned char hdr[8];
	unsigned short mfname; /* EISA style compressed id */
	unsigned short pid;
	unsigned long serialno;
	char mfweek;
	unsigned char mfyear;
	unsigned char edidver;
	unsigned char edidrev;
	unsigned char vidindef;
	unsigned char maxHimagesz; /* cm */
	unsigned char maxVimagesz; /* cm */
	unsigned char displayxferchar;
	unsigned char DPMSfeat;
	unsigned char RGlowbits;
	unsigned char BWlowbits;
	unsigned char redx;
	unsigned char redy;
	unsigned char greenx;
	unsigned char greeny;
	unsigned char bluex;
	unsigned char bluey;
	unsigned char whitex;
	unsigned char whitey;
	unsigned char esttimings1;
	unsigned char esttimings2;
	unsigned char rsvdtimings;
	short stdtimingid1;
	short stdtimingid2;
	short stdtimingid3;
	short stdtimingid4;
	short stdtimingid5;
	short stdtimingid6;
	short stdtimingid7;
	short stdtimingid8;
	unsigned char dettimingdesc1[18];
	unsigned char dettimingdesc2[18];
	unsigned char dettimingdesc3[18];
	unsigned char dettimingdesc4[18];
	unsigned char extflg;
	unsigned char chksum;
};
#pragma pack()

/*
 * Address at which we can read/write a structure
 * in common with the bios.
 *
 * Current memory layout:
 *	1mb:	multiboot
 *	0x6000: our scratch memory
 *	0x5000:	stack, grows downward
 *	0x2000: biosint
 *	0x1000: bios
 */
#define	LOMEM_SCRATCH_ADDR	0x6000


#define	dprintf	if (debug & D_BIOS) printf

int (*bios_doint)(int, struct int_pb *);


static const char hextab[] = "0123456789ABCDEF";

static void
DecompressName(unsigned long id, char *np)
{
	/*
	 * Expand an EISA device name
	 *
	 * This  converts a 32-bit EISA device "id" to a
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

void
vga_probe(void)
{
	int ret;
	struct int_pb ic = {0};
	char *fp;
	char name[8];
	struct EDIFinfo *edifp = (struct EDIFinfo *)LOMEM_SCRATCH_ADDR;

	/*
	 * See what level of VESA DDC is supported (if any)
	 */
	ic.ax = (VESABIOS_SUPP_FUNC << 8) | VESABIOS_DISPLAY_ID_EXT;
	ic.bx = 0x00; 	/* Report DDC Capcbilities */
	ic.cx = 0;
	ic.dx = 0;
	ic.es = 0;
	ic.dx = 0;
	ret = bios_doint(0x10, &ic);
	dprintf("vga probe report ddc: ret=%0x ax=0x%x dx=0x%x\n",
		ret, ic.ax, ic.dx);
	if (!(ret & PS_C) && (ic.ax & 0xff) == VESABIOS_SUPP_FUNC) {
		/*
		 * BIOS supports VBE/DDC extension
		 */
		if (ic.bx & 0x03)	{ /* DDC1 or DDC2 supported */
			unsigned long mfn, compid;

			/*
			 * Get VESA DDC EDIF info
			 */
			edifp->edidver = 0;
			ic.ax = (VESABIOS_SUPP_FUNC << 8) |
					VESABIOS_DISPLAY_ID_EXT;
			ic.bx = 0x01;	/* Read EDID */
			ic.cx = 0;
			ic.dx = 0;
			fp = (char *)edifp;
			ic.es = FP_SEG(fp);
			ic.di = FP_OFF(fp);
			dprintf("addr 0x%p, seg 0x%lx, off 0x%lx\n",
				(void *)fp, FP_SEG(fp), FP_OFF(fp));

			ret = bios_doint(0x10, &ic);
			dprintf(
			    "vga probe read edid: ret=%0x ax=0x%x dx=0x%x\n",
			    ret, ic.ax, ic.dx);
			if (!(ret & PS_C) && edifp->edidver != 0) {
				dprintf("display-edif-block: len %d\n",
				    sizeof (struct EDIFinfo));
				(void) bsetprop(NULL, "display-edif-block",
				    edifp, sizeof (struct EDIFinfo));
				/*
				 * Set edif id as a property
				 */
				mfn = (long)edifp->mfname;
				compid = (long)edifp->pid << 24 | mfn |
					((long)(edifp->pid & 0xff00) << 8);
				DecompressName(compid, name);
				dprintf("display-edif-id: %s\n", name);
				(void) bsetprop(NULL, "display-edif-id",
					name, strlen(name) + 1);
			}
		}
	}
}
