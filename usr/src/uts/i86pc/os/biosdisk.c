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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/controlregs.h>
#include <sys/bootconf.h>
#include <sys/bootvfs.h>
#include <sys/bootregs.h>
#include <sys/bootconf.h>
#include <sys/conf.h>
#include <sys/promif.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/biosdisk.h>
#include <sys/psw.h>
#if defined(__xpv)
#include <sys/hypervisor.h>
#endif

extern int prom_debug;

/* hard code realmode memory address for now */
#define	BIOS_RES_BUFFER_ADDR		0x7000

#define	BIOSDEV_NUM	8
#define	STARTING_DRVNUM	0x80
#define	FP_OFF(fp) (((uintptr_t)(fp)) & 0xFFFF)
#define	FP_SEG(fp) ((((uintptr_t)(fp)) >> 16) & 0xFFFF)

#ifdef DEBUG
int biosdebug = 0;
#define	dprintf(fmt) \
	if (biosdebug) \
		prom_printf fmt
#else
#define	dprintf(fmt)
#endif

biosdev_data_t biosdev_info[BIOSDEV_NUM]; /* from 0x80 to 0x87 */
int dobiosdev = 1;


static int bios_check_extension_present(uchar_t);
static int get_dev_params(uchar_t);
static int read_firstblock(uchar_t drivenum);
static int drive_present(uchar_t drivenum);
static void reset_disk(uchar_t drivenum);
static int is_eltorito(uchar_t drivenum);

#if !defined(__xpv)
void
startup_bios_disk()
{
	uchar_t drivenum;
	int got_devparams = 0;
	int got_first_block = 0;
	uchar_t	name[20];
	dev_info_t	*devi;
	int extensions;

	if (dobiosdev == 0)
		return;

	for (drivenum = 0x80; drivenum < (0x80 + BIOSDEV_NUM); drivenum++) {

		if (!drive_present(drivenum))
			continue;

		extensions = bios_check_extension_present(drivenum);

		/*
		 * If we're booting from an Eltorito CD/DVD image, there's
		 * no need to get the device parameters or read the first block
		 * because we'll never install onto this device.
		 */
		if (extensions && is_eltorito(drivenum))
			continue;

		if (extensions && get_dev_params(drivenum))
			got_devparams = 1;
		else
			got_devparams = 0;

		if ((got_first_block = read_firstblock(drivenum)) == 0) {
			/* retry */
			got_first_block = read_firstblock(drivenum);
		}

		if (got_devparams || got_first_block) {
			(void) sprintf((char *)name, "biosdev-0x%x", drivenum);
			devi = ddi_root_node();
			(void) e_ddi_prop_update_byte_array(DDI_DEV_T_NONE,
			    devi, (char *)name,
			    (uchar_t *)&biosdev_info[drivenum - 0x80],
			    sizeof (biosdev_data_t));
		}
	}
}
#endif

static int
bios_check_extension_present(uchar_t drivenum)
{
	struct bop_regs rp = {0};
	extern struct bootops		*bootops;

	rp.eax.word.ax = 0x4100;
	rp.ebx.word.bx = 0x55AA;
	rp.edx.word.dx = drivenum;

	/* make sure we have extension support */
	BOP_DOINT(bootops, 0x13, &rp);

	if (((rp.eflags & PS_C) != 0) || (rp.ebx.word.bx != 0xAA55)) {
		dprintf(("bios_check_extension_present int13 fn 41 "
		    "failed %d bx = %x\n", rp.eflags, rp.ebx.word.bx));
		return (0);
	}

	if ((rp.ecx.word.cx & 0x7) == 0) {
		dprintf(("bios_check_extension_present get device parameters "
		    "not supported cx = %x\n", rp.ecx.word.cx));
		return (0);
	}

	return (1);
}

static int
get_dev_params(uchar_t drivenum)
{
	struct bop_regs rp = {0};
	fn48_t	 *bufp;
	extern struct bootops		*bootops;
	int i;
	int index;
	uchar_t *tmp;

	dprintf(("In get_dev_params\n"));

	bufp = (fn48_t *)BIOS_RES_BUFFER_ADDR;

	/*
	 * We cannot use bzero here as we're initializing data
	 * at an address below kernel base.
	 */
	for (i = 0; i < sizeof (*bufp); i++)
		((uchar_t *)bufp)[i] = 0;

	bufp->buflen = sizeof (*bufp);
	rp.eax.word.ax = 0x4800;
	rp.edx.byte.dl = drivenum;

	rp.esi.word.si = (uint16_t)FP_OFF((uint_t)(uintptr_t)bufp);
	rp.ds = FP_SEG((uint_t)(uintptr_t)bufp);

	BOP_DOINT(bootops, 0x13, &rp);

	if ((rp.eflags & PS_C) != 0) {
		dprintf(("EDD FAILED on drive eflag = %x ah= %x\n",
		    rp.eflags, rp.eax.byte.ah));
		return (0);
	}

	index = drivenum - 0x80;
	biosdev_info[index].edd_valid = 1;

	/*
	 * Some compilers turn a structure copy into a call
	 * to memcpy.  Since we are copying data below kernel
	 * base intentionally, and memcpy asserts that's not
	 * the case, we do the copy manually here.
	 */
	tmp = (uchar_t *)&biosdev_info[index].fn48_dev_params;
	for (i = 0; i < sizeof (*bufp); i++)
		tmp[i] = ((uchar_t *)bufp)[i];

	return (1);
}

static int
drive_present(uchar_t drivenum)
{
	struct bop_regs rp = {0};

	rp.eax.byte.ah = 0x8;	/* get params */
	rp.edx.byte.dl = drivenum;

	BOP_DOINT(bootops, 0x13, &rp);

	if (((rp.eflags & PS_C) != 0) || rp.eax.byte.ah != 0) {
		dprintf(("drive not present drivenum %x eflag %x ah %x\n",
		    drivenum, rp.eflags, rp.eax.byte.ah));
		return (0);
	}

	dprintf(("drive-present %x\n", drivenum));
	return (1);
}

static void
reset_disk(uchar_t drivenum)
{
	struct bop_regs rp = {0};
	int status;

	rp.eax.byte.ah = 0x0;   /* reset disk */
	rp.edx.byte.dl = drivenum;

	BOP_DOINT(bootops, 0x13, &rp);

	status = rp.eax.byte.ah;

	if (((rp.eflags & PS_C) != 0) || status != 0)
		dprintf(("Bad disk reset driv %x, status %x\n", drivenum,
		    status));
}

/* Get first block */
static int
read_firstblock(uchar_t drivenum)
{

	struct bop_regs rp = {0};
	caddr_t	 bufp;
	uchar_t status;
	int i, index;


	reset_disk(drivenum);
	bufp = (caddr_t)BIOS_RES_BUFFER_ADDR;


	rp.eax.byte.ah = 0x2; 	/* Read disk */
	rp.eax.byte.al = 1;	/* nsect */
	rp.ecx.byte.ch = 0;	/* cyl & 0xff */
	rp.ecx.byte.cl = 1;	/* cyl >> 2 & 0xc0 (sector number) */
	rp.edx.byte.dh = 0;	/* head */
	rp.edx.byte.dl = drivenum;	/* drivenum */

	/* es:bx is buf address */
	rp.ebx.word.bx = (uint16_t)FP_OFF((uint_t)(uintptr_t)bufp);
	rp.es = FP_SEG((uint_t)(uintptr_t)bufp);

	BOP_DOINT(bootops, 0x13, &rp);

	status = rp.eax.byte.ah;
	if (((rp.eflags & PS_C) != 0) || status != 0) {
		dprintf(("read_firstblock AH not clear %x \n", status));
		return (0);
	}

	dprintf(("drivenum %x uid at 0x1b8 is %x\n", drivenum,
	    *(uint32_t *)(bufp +0x1b8)));

	index = drivenum - 0x80;

	biosdev_info[index].first_block_valid = 1;
	for (i = 0; i < 512; i++)
		biosdev_info[index].first_block[i] = *((uchar_t *)bufp + i);

	return (1);
}

static int
is_eltorito(uchar_t drivenum)
{
	struct bop_regs rp = {0};
	fn4b_t	 *bufp;
	extern struct bootops		*bootops;
	int i;

	dprintf(("In is_eltorito\n"));

	bufp = (fn4b_t *)BIOS_RES_BUFFER_ADDR;

	/*
	 * We cannot use bzero here as we're initializing data
	 * at an address below kernel base.
	 */
	for (i = 0; i < sizeof (*bufp); i++)
		((uchar_t *)bufp)[i] = 0;

	bufp->pkt_size = sizeof (*bufp);
	rp.eax.word.ax = 0x4b01;
	rp.edx.byte.dl = drivenum;

	rp.esi.word.si = (uint16_t)FP_OFF((uint_t)(uintptr_t)bufp);
	rp.ds = FP_SEG((uint_t)(uintptr_t)bufp);

	BOP_DOINT(bootops, 0x13, &rp);

	if ((rp.eflags & PS_C) != 0 || bufp->drivenum != drivenum) {
		dprintf(("fn 0x4b01 FAILED on drive "
		    "eflags=%x ah=%x drivenum=%x\n",
		    rp.eflags, rp.eax.byte.ah, bufp->drivenum));
		return (0);
	}

	if (prom_debug)
		prom_printf("INT13 FN4B01 mtype => %x", bufp->boot_mtype);

	return (1);
}
