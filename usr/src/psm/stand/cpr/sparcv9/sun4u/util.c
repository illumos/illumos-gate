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

#include <sys/cpr.h>
#include <sys/promimpl.h>
#include "cprboot.h"


static ihandle_t	cb_rih;
static pnode_t		chosen;

static int statefile_special;

static int reset_input = 0;
static char kbd_input[] = "keyboard input";
static char null_input[] = "\" /nulldev\" input";

/*
 * Ask prom to open a disk file given either the OBP device path, or the
 * device path representing the target drive/partition and the fs-relative
 * path of the file.  Handle file pathnames with or without leading '/'.
 * if fs points to a null char, it indicates that we are opening a device.
 */
int
cpr_statefile_open(char *path, char *fs_dev)
{
	int plen, dlen;
	int handle;
	char fs_pkg[OBP_MAXPATHLEN];
	char fs_name[OBP_MAXDRVNAME];

	/*
	 * instead of using specialstate, we use fs as the flag
	 */
	if (*fs_dev == '\0') {	/* device open */
		statefile_special = 1;
		handle = prom_open(path);
		/* IEEE1275 prom_open returns 0 on failure; we return -1 */
		return (handle ? handle : -1);
	}

	/*
	 * No cif for $open-package, so we have to use interpret
	 */
	if (prom_getprop(chosen, "fs-package", fs_pkg) == -1) {
		prom_printf("Missing fs-package name\n");
		return (-1);
	}
	plen = prom_strlen(fs_pkg);
	dlen = prom_strlen(fs_dev);
	prom_interpret("$open-package swap l!", plen, (uintptr_t)fs_pkg,
	    dlen, (uintptr_t)fs_dev, (uintptr_t)&cb_rih);
	if (cb_rih == OBP_BADNODE || cb_rih == 0) {
		prom_printf("Can't open %s\n", fs_pkg);
		return (-1);
	}

	if (volname) {
		return (cpr_fs_volopen(volname));
	}

	/*
	 * Prepend '/' if it's not there already
	 */
	if (*path != '/') {
		(void) prom_sprintf(fs_name, "/%s", path);
		return (cpr_fs_open(fs_name));
	} else
		return (cpr_fs_open(path));
}

/*
 * Mount root fs so we can read statefile, etc
 *
 * sets global
 *	cb_rih
 */
int
cb_mountroot()
{

	chosen = prom_chosennode();
	if (chosen == OBP_BADNODE) {
		prom_printf("Missing chosen node\n");
		return (ERR);
	}
	if (prom_getprop(chosen, "bootfs", (caddr_t)&cb_rih) == -1) {
		prom_printf("Missing bootfs ihandle\n");
		return (ERR);
	}
	return (0);
}

/*
 * Unmount root
 */
int
cb_unmountroot()
{
	(void) prom_close(cb_rih);
	cb_rih = OBP_BADNODE;
	return (0);
}

int
cpr_fs_volopen(char *path)
{

	CB_VENTRY(cpr_fs_volopen);

	if (cb_rih == OBP_BADNODE)
		return (-1);
	return (prom_volopen(cb_rih, path));
}

/*
 * Ask prom to open a disk file.
 */
int
cpr_fs_open(char *path)
{

	CB_VENTRY(cpr_fs_open);

	if (cb_rih == OBP_BADNODE)
		return (-1);
	return (prom_fopen(cb_rih, path));
}


/*
 * Direct read if using block special,
 * otherwise use fs read
 */
int
cpr_read(int fd, caddr_t buf, size_t len)
{
	if (!statefile_special || volname)
		return (cpr_fs_read(fd, buf, len));
	else
		return (prom_read(fd, buf, len, 0, 0));
}


int
cpr_fs_read(int fd, caddr_t buf, int len)
{
	if (cb_rih == OBP_BADNODE)
		return (-1);
	return (prom_fread(cb_rih, fd, buf, len));
}


int
cpr_fs_close(int fd)
{
	CB_VPRINTF(("cpr_fs_close 0x%x\n", fd));

	if (cb_rih == OBP_BADNODE)
		return (-1);
	prom_fclose(cb_rih, fd);
	return (0);
}

int
cpr_fs_seek(int fd, offset_t off)
{
	if (cb_rih == OBP_BADNODE)
		return (-1);
	return (prom_fseek(cb_rih, fd, off));
}


int
cpr_statefile_close(int fd)
{
	if (statefile_special) {
		statefile_special = 0;
		return (prom_close(fd));
	} else
		return (cpr_fs_close(fd));
}


void
cb_spin(void)
{
	static int spindex = 0;
	static char *spin_pairs[] = { "|\b", "/\b", "-\b", "\\\b" };
	const size_t nspin_pairs = sizeof (spin_pairs) / sizeof (spin_pairs[0]);

	prom_printf(spin_pairs[spindex]);
	spindex = (spindex + 1) % nspin_pairs;
}


/*
 * translate vaddr to phys page number
 */
pfn_t
cpr_vatopfn(caddr_t vaddr)
{
	physaddr_t paddr;
	int valid, mode;

	(void) prom_translate_virt(vaddr, &valid, &paddr, &mode);
	if (valid != -1)
		return (PFN_INVALID);
	return (paddr >> MMU_PAGESHIFT);
}


/*
 * unmap virt, then map virt to new phys;
 * see remap definition below
 */
int
prom_remap(size_t size, caddr_t virt, physaddr_t phys)
{
	ihandle_t immu;
	cell_t ci[8];
	int rv;

	immu = prom_mmu_ihandle();
	if (immu == (ihandle_t)-1)
		return (ERR);

	ci[0] = p1275_ptr2cell("call-method");	/* Service name */
	ci[1] = (cell_t)5;			/* #argument cells */
	ci[2] = (cell_t)0;			/* #result cells */
	ci[3] = p1275_ptr2cell("remap");	/* Arg1: Method name */
	ci[4] = p1275_ihandle2cell(immu);	/* Arg2: memory ihandle */
	ci[5] = p1275_size2cell(size);		/* remap arg0 */
	ci[6] = p1275_ptr2cell(virt);		/* remap arg1 */
	ci[7] = p1275_ull2cell_low(phys);	/* remap arg2 */

	promif_preprom();
	rv = p1275_cif_handler(ci);
	promif_postprom();

	if (rv)
		return (rv);		/* Service "call-method" failed */
	return (0);
}


/*
 * install remap definition in /virtual-memory node;
 * used for replacing a virt->phys mapping in one promif call;
 * this needs to be atomic from the client's perspective to
 * avoid faults while relocating client text.
 */
void
install_remap(void)
{
	static char remap_def[] =
	    "\" /virtual-memory\" find-device "
	    ": remap ( phys.lo virt size -- )"
	    "	2dup unmap ( phys.lo virt size )"
	    "	0 -rot -1 map ( ) ; "
	    "device-end";

	prom_interpret(remap_def, 0, 0, 0, 0, 0);
}


/*
 * allocate virt and phys space without any mapping;
 * stores virt and phys addrs at *vap and *pap
 */
int
cb_alloc(size_t size, uint_t align, caddr_t *vap, physaddr_t *pap)
{
	physaddr_t phys;
	caddr_t virt;

	virt = prom_allocate_virt(align, (size_t)align);
	if (virt == (caddr_t)-1)
		return (ERR);
	if (prom_allocate_phys(size, align, &phys) == -1) {
		prom_free_virt(size, virt);
		return (ERR);
	}

	*vap = virt;
	*pap = phys;
	return (0);
}


static int
get_intprop(pnode_t node, caddr_t prop, void *dst)
{
	int len, glen;

	len = sizeof (uint_t);
	glen = prom_getprop(node, prop, dst);
	if (glen != len)
		return (ERR);

	return (0);
}


/*
 * find cpu node for the boot processor
 *
 * sets globals:
 * 	cb_mid
 */
static pnode_t
get_cpu_node(void)
{
	static char *props[] = { "upa-portid", "portid", NULL };
	pnode_t node;
	char *str, *name, **propp;
	uint_t cpu_id;
	int err;

	str = "get_cpu_node";
	name = "cpu";

	cb_mid = getmid();
	for (node = prom_rootnode(); ; node = prom_nextnode(node)) {
		node = prom_findnode_bydevtype(node, name);
		if (node == OBP_NONODE) {
			prom_printf("\n%s: cant find node for devtype \"%s\"\n",
			    str, name);
			break;
		}

		cpu_id = (uint_t)-1;
		for (propp = props; *propp; propp++) {
			err = get_intprop(node, *propp, &cpu_id);
			CB_VPRINTF(("    cpu node 0x%x, "
			    "prop \"%s\", cpu_id %d\n",
			    node, *propp, (int)cpu_id));
			if (err == 0)
				break;
		}

		if (cpu_id == cb_mid)
			return (node);
	}

	return (OBP_NONODE);
}


/*
 * lookup prom properties
 *
 * sets globals:
 *	cb_dents
 *	cb_clock_freq
 *	cpu_delay
 */
int
cb_get_props(void)
{
	uint_t clock_mhz;
	pnode_t node;
	struct cb_props *cbp;
	static struct cb_props cpu_data[] = {
		"#dtlb-entries", &cb_dents,
		"clock-frequency", &cb_clock_freq,
		NULL, NULL,
	};

	CB_VENTRY(cb_get_props);

	node = get_cpu_node();
	if (node == OBP_NONODE)
		return (ERR);
	for (cbp = cpu_data; cbp->prop; cbp++) {
		if (get_intprop(node, cbp->prop, cbp->datap)) {
			prom_printf("\n%s: getprop error, "
			    "node 0x%x, prop \"%s\"\n",
			    prog, node, cbp->prop);
			return (ERR);
		}
		CB_VPRINTF(("    \"%s\" = 0x%x\n",
		    cbp->prop, *cbp->datap));
	}

	/*
	 * setup cpu_delay for cb_usec_wait
	 */
	clock_mhz = (cb_clock_freq + 500000) / 1000000;
	cpu_delay = clock_mhz - 7;
	CB_VPRINTF(("    clock_mhz %d, cpu_delay %d\n",
	    clock_mhz, cpu_delay));

	return (0);
}


/*
 * map-in data pages
 * size should fit tte_bit.sz
 * rw should be 0 or TTE_HWWR_INT
 */
void
cb_mapin(caddr_t vaddr, pfn_t ppn, uint_t size, uint_t rw, uint_t dtlb_index)
{
	tte_t tte;

	tte.tte_inthi = TTE_VALID_INT | TTE_SZ_INT(size) |
	    TTE_PFN_INTHI(ppn);
	tte.tte_intlo = TTE_PFN_INTLO(ppn) | TTE_LCK_INT |
	    TTE_CP_INT | TTE_CV_INT | TTE_PRIV_INT | rw;
	set_dtlb_entry(dtlb_index, vaddr, &tte);
}


static char *
prom_strstr(char *string, char *substr)
{
	char *strp, *subp, *tmp, c;

	if (substr == NULL || *substr == '\0')
		return (string);

	strp = string;
	subp = substr;
	c = *subp;

	while (*strp) {
		if (*strp++ == c) {
			tmp = strp;
			while ((c = *++subp) == *strp++ && c)
				;
			if (c == '\0')
				return (tmp - 1);
			strp = tmp;
			subp = substr;
			c = *subp;
		}
	}

	return (NULL);
}


static void
cb_set_idev(char *istr)
{
	if (reset_input) {
		prom_interpret(istr, 0, 0, 0, 0, 0);
		CB_VPRINTF(("\ncb_set_idev: reset with [%s]\n", istr));
	}
}


/*
 * workaround for USB keyboard:
 * USB DMA activity has been known to corrupt kernel pages while cprboot
 * is restoring them.  to quiesce the USB chip, we craft a "null" device
 * and temporarily use that as the prom's input device.  this effectively
 * disables the USB keyboard until the cpr module restores the original
 * prom and a kernel driver re-inits and takes-over control of USB.
 *
 * may set globals:
 *	reset_input
 */
int
cb_usb_setup(void)
{
	char sp[OBP_MAXPATHLEN];
	static char cb_nulldev[] =
		"\" /\" select-dev "
		"new-device "
		"\" nulldev\" device-name "
		": read 2drop -2 ; "
		": open true ; "
		": close ; "
		": install-abort ; "
		": remove-abort ; "
		": write 2drop 0 ; "
		": restore ; "
		"finish-device "
		"unselect-dev";

	CB_VENTRY(cb_usb_setup);

	bzero(sp, sizeof (sp));
	prom_interpret("stdin @ ihandle>devname swap -rot move",
	    (uintptr_t)sp, 0, 0, 0, 0);
	if (prom_strstr(sp, "usb") && prom_strstr(sp, "keyboard")) {
		prom_interpret(cb_nulldev, 0, 0, 0, 0, 0);
		reset_input = 1;
		cb_set_idev(null_input);
	}

	return (0);
}


/*
 * switch input to keyboard before entering the prom, and switch to the
 * crafted nulldev after returning from the prom.  this occurs only when
 * stdinpath is a USB keyboard; entering the prom is usually done only
 * for debugging purposes - see check_halt() and above DMA comment.
 */
void
cb_enter_mon(void)
{
	cb_set_idev(kbd_input);
	prom_enter_mon();
	cb_set_idev(null_input);
}


/*
 * similar to above before exiting to the prom
 */
void
cb_exit_to_mon(void)
{
	cb_set_idev(kbd_input);
	prom_exit_to_mon();
}
