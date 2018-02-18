/*-
 * Copyright (c) 1998 Robert Nordier
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are freely
 * permitted provided that the above copyright notice and this
 * paragraph and the following disclaimer are duplicated in all
 * such forms.
 *
 * This software is provided "AS IS" and without any express or
 * implied warranties, including, without limitation, the implied
 * warranties of merchantability and fitness for a particular
 * purpose.
 */

#include <sys/cdefs.h>
#include <stand.h>

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/diskmbr.h>
#include <sys/vtoc.h>
#include <sys/disk.h>
#include <sys/reboot.h>
#include <sys/queue.h>
#include <multiboot.h>

#include <machine/bootinfo.h>
#include <machine/elf.h>
#include <machine/pc/bios.h>

#include <stdarg.h>
#include <stddef.h>

#include <a.out.h>
#include "bootstrap.h"
#include "libi386.h"
#include <btxv86.h>

#include "lib.h"
#include "rbx.h"
#include "cons.h"
#include "bootargs.h"
#include "disk.h"
#include "part.h"
#include "paths.h"

#include "libzfs.h"

#define ARGS		0x900
#define NOPT		14
#define NDEV		3

#define BIOS_NUMDRIVES	0x475
#define DRV_HARD	0x80
#define DRV_MASK	0x7f

#define TYPE_AD		0
#define TYPE_DA		1
#define TYPE_MAXHARD	TYPE_DA
#define TYPE_FD		2

extern uint32_t _end;

/*
 * Fake multiboot header to provide versioning and to pass
 * partition start LBA. Partition is either GPT partition or
 * VTOC slice.
 */
extern const struct multiboot_header mb_header;
extern uint64_t start_sector;

static const char optstr[NOPT] = "DhaCcdgmnpqrsv"; /* Also 'P', 'S' */
static const unsigned char flags[NOPT] = {
    RBX_DUAL,
    RBX_SERIAL,
    RBX_ASKNAME,
    RBX_CDROM,
    RBX_CONFIG,
    RBX_KDB,
    RBX_GDB,
    RBX_MUTE,
    RBX_NOINTR,
    RBX_PAUSE,
    RBX_QUIET,
    RBX_DFLTROOT,
    RBX_SINGLE,
    RBX_VERBOSE
};
uint32_t opts;

static const unsigned char dev_maj[NDEV] = {30, 4, 2};

static struct i386_devdesc *bdev;
static char cmd[512];
static char cmddup[512];
static char kname[1024];
static int comspeed = SIOSPD;
static struct bootinfo bootinfo;
static uint32_t bootdev;
static struct zfs_boot_args zfsargs;

extern vm_offset_t high_heap_base;
extern uint32_t	bios_basemem, bios_extmem, high_heap_size;

static char *heap_top;
static char *heap_bottom;

static void i386_zfs_probe(void);
void exit(int);
static void load(void);
static int parse_cmd(void);

struct arch_switch archsw;	/* MI/MD interface boundary */
static char boot_devname[2 * ZFS_MAXNAMELEN + 8]; /* disk or pool:dataset */

struct devsw *devsw[] = {
	&biosdisk,
	&zfs_dev,
	NULL
};

struct fs_ops *file_system[] = {
	&zfs_fsops,
	&ufs_fsops,
	&dosfs_fsops,
	NULL
};

int
main(void)
{
    int auto_boot, i, fd;
    struct disk_devdesc devdesc;

    bios_getmem();

    if (high_heap_size > 0) {
	heap_top = PTOV(high_heap_base + high_heap_size);
	heap_bottom = PTOV(high_heap_base);
    } else {
	heap_bottom = (char *)
	    (roundup2(__base + (int32_t)&_end, 0x10000) - __base);
	heap_top = (char *) PTOV(bios_basemem);
    }
    setheap(heap_bottom, heap_top);

    /*
     * Initialise the block cache. Set the upper limit.
     */
    bcache_init(32768, 512);

    archsw.arch_autoload = NULL;
    archsw.arch_getdev = i386_getdev;
    archsw.arch_copyin = NULL;
    archsw.arch_copyout = NULL;
    archsw.arch_readin = NULL;
    archsw.arch_isainb = NULL;
    archsw.arch_isaoutb = NULL;
    archsw.arch_zfs_probe = i386_zfs_probe;

    bootinfo.bi_version = BOOTINFO_VERSION;
    bootinfo.bi_size = sizeof(bootinfo);
    bootinfo.bi_basemem = bios_basemem / 1024;
    bootinfo.bi_extmem = bios_extmem / 1024;
    bootinfo.bi_memsizes_valid++;
    bootinfo.bi_bios_dev = *(uint8_t *)PTOV(ARGS);

    /* Set up fall back device name. */
    snprintf(boot_devname, sizeof (boot_devname), "disk%d:",
	bd_bios2unit(bootinfo.bi_bios_dev));

    for (i = 0; devsw[i] != NULL; i++)
	if (devsw[i]->dv_init != NULL)
	    (devsw[i]->dv_init)();

    disk_parsedev(&devdesc, boot_devname+4, NULL);

    bootdev = MAKEBOOTDEV(dev_maj[devdesc.d_type], devdesc.d_slice + 1,
	devdesc.d_unit, devdesc.d_partition >= 0? devdesc.d_partition:0xff);

    /*
     * zfs_fmtdev() can be called only after dv_init
     */
    if (bdev != NULL && bdev->d_type == DEVT_ZFS) {
	/* set up proper device name string for ZFS */
	strncpy(boot_devname, zfs_fmtdev(bdev), sizeof (boot_devname));
    }

    /* now make sure we have bdev on all cases */
    if (bdev != NULL)
	free(bdev);
    i386_getdev((void **)&bdev, boot_devname, NULL);

    env_setenv("currdev", EV_VOLATILE, boot_devname, i386_setcurrdev,
	env_nounset);

    /* Process configuration file */
    setenv("LINES", "24", 1);
    auto_boot = 1;

    fd = open(PATH_CONFIG, O_RDONLY);
    if (fd == -1)
	fd = open(PATH_DOTCONFIG, O_RDONLY);

    if (fd != -1) {
	read(fd, cmd, sizeof(cmd));
	close(fd);
    }

    if (*cmd) {
	/*
	 * Note that parse_cmd() is destructive to cmd[] and we also want
	 * to honor RBX_QUIET option that could be present in cmd[].
	 */
	memcpy(cmddup, cmd, sizeof(cmd));
	if (parse_cmd())
	    auto_boot = 0;
	if (!OPT_CHECK(RBX_QUIET))
	    printf("%s: %s\n", PATH_CONFIG, cmddup);
	/* Do not process this command twice */
	*cmd = 0;
    }

    /*
     * Try to exec stage 3 boot loader. If interrupted by a keypress,
     * or in case of failure, switch off auto boot.
     */

    if (auto_boot && !*kname) {
	memcpy(kname, PATH_LOADER_ZFS, sizeof(PATH_LOADER_ZFS));
	if (!keyhit(3)) {
	    load();
	    auto_boot = 0;
	}
    }

    /* Present the user with the boot2 prompt. */

    for (;;) {
	if (!auto_boot || !OPT_CHECK(RBX_QUIET)) {
	    printf("\nillumos/x86 boot\n");
	    printf("Default: %s%s\nboot: ", boot_devname, kname);
	}
	if (ioctrl & IO_SERIAL)
	    sio_flush();
	if (!auto_boot || keyhit(5))
	    getstr(cmd, sizeof(cmd));
	else if (!auto_boot || !OPT_CHECK(RBX_QUIET))
	    putchar('\n');
	auto_boot = 0;
	if (parse_cmd())
	    putchar('\a');
	else
	    load();
    }
}

/* XXX - Needed for btxld to link the boot2 binary; do not remove. */
void
exit(int x)
{
}

static void
load(void)
{
    union {
	struct exec ex;
	Elf32_Ehdr eh;
    } hdr;
    static Elf32_Phdr ep[2];
    static Elf32_Shdr es[2];
    caddr_t p;
    uint32_t addr, x;
    int fd, fmt, i, j;

    if ((fd = open(kname, O_RDONLY)) == -1) {
	printf("\nCan't find %s\n", kname);
	return;
    }
    if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
	close(fd);
	return;
    }
    if (N_GETMAGIC(hdr.ex) == ZMAGIC)
	fmt = 0;
    else if (IS_ELF(hdr.eh))
	fmt = 1;
    else {
	printf("Invalid %s\n", "format");
	close(fd);
	return;
    }
    if (fmt == 0) {
	addr = hdr.ex.a_entry & 0xffffff;
	p = PTOV(addr);
	lseek(fd, PAGE_SIZE, SEEK_SET);
	if (read(fd, p, hdr.ex.a_text) != hdr.ex.a_text) {
	    close(fd);
	    return;
	}
	p += roundup2(hdr.ex.a_text, PAGE_SIZE);
	if (read(fd, p, hdr.ex.a_data) != hdr.ex.a_data) {
	    close(fd);
	    return;
	}
	p += hdr.ex.a_data + roundup2(hdr.ex.a_bss, PAGE_SIZE);
	bootinfo.bi_symtab = VTOP(p);
	memcpy(p, &hdr.ex.a_syms, sizeof(hdr.ex.a_syms));
	p += sizeof(hdr.ex.a_syms);
	if (hdr.ex.a_syms) {
	    if (read(fd, p, hdr.ex.a_syms) != hdr.ex.a_syms) {
		close(fd);
		return;
	    }
	    p += hdr.ex.a_syms;
	    if (read(fd, p, sizeof(int)) != sizeof(int)) {
		close(fd);
		return;
	    }
	    x = *(uint32_t *)p;
	    p += sizeof(int);
	    x -= sizeof(int);
	    if (read(fd, p, x) != x) {
		close(fd);
		return;
	    }
	    p += x;
	}
    } else {
	lseek(fd, hdr.eh.e_phoff, SEEK_SET);
	for (j = i = 0; i < hdr.eh.e_phnum && j < 2; i++) {
	    if (read(fd, ep + j, sizeof(ep[0])) != sizeof(ep[0])) {
		close(fd);
		return;
	    }
	    if (ep[j].p_type == PT_LOAD)
		j++;
	}
	for (i = 0; i < 2; i++) {
	    p = PTOV(ep[i].p_paddr & 0xffffff);
	    lseek(fd, ep[i].p_offset, SEEK_SET);
	    if (read(fd, p, ep[i].p_filesz) != ep[i].p_filesz) {
		close(fd);
		return;
	    }
	}
	p += roundup2(ep[1].p_memsz, PAGE_SIZE);
	bootinfo.bi_symtab = VTOP(p);
	if (hdr.eh.e_shnum == hdr.eh.e_shstrndx + 3) {
	    lseek(fd, hdr.eh.e_shoff + sizeof(es[0]) * (hdr.eh.e_shstrndx + 1),
		SEEK_SET);
	    if (read(fd, &es, sizeof(es)) != sizeof(es)) {
		close(fd);
		return;
	    }
	    for (i = 0; i < 2; i++) {
		memcpy(p, &es[i].sh_size, sizeof(es[i].sh_size));
		p += sizeof(es[i].sh_size);
		lseek(fd, es[i].sh_offset, SEEK_SET);
		if (read(fd, p, es[i].sh_size) != es[i].sh_size) {
		    close(fd);
		    return;
		}
		p += es[i].sh_size;
	    }
	}
	addr = hdr.eh.e_entry & 0xffffff;
    }
    close(fd);

    bootinfo.bi_esymtab = VTOP(p);
    bootinfo.bi_kernelname = VTOP(kname);

    if (bdev->d_type == DEVT_ZFS) {
	zfsargs.size = sizeof(zfsargs);
	zfsargs.pool = bdev->d_kind.zfs.pool_guid;
	zfsargs.root = bdev->d_kind.zfs.root_guid;
	__exec((caddr_t)addr, RB_BOOTINFO | (opts & RBX_MASK),
	    bootdev,
	    KARGS_FLAGS_ZFS | KARGS_FLAGS_EXTARG,
	    (uint32_t) bdev->d_kind.zfs.pool_guid,
	    (uint32_t) (bdev->d_kind.zfs.pool_guid >> 32),
	    VTOP(&bootinfo),
	    zfsargs);
    } else
	__exec((caddr_t)addr, RB_BOOTINFO | (opts & RBX_MASK),
	   bootdev, 0, 0, 0, VTOP(&bootinfo));
}

static int
mount_root(char *arg)
{
    char *root;
    struct i386_devdesc *ddesc;
    uint8_t part;

    root = malloc(strlen(arg) + 2);
    if (root == NULL)
	return (1);
    sprintf(root, "%s:", arg);
    if (i386_getdev((void **)&ddesc, root, NULL)) {
	free(root);
	return (1);
    }

    /* we should have new device descriptor, free old and replace it. */
    if (bdev != NULL)
	free(bdev);
    bdev = ddesc;
    if (bdev->d_type == DEVT_DISK) {
	if (bdev->d_kind.biosdisk.partition == -1)
	    part = 0xff;
	else
	    part = bdev->d_kind.biosdisk.partition;
	bootdev = MAKEBOOTDEV(dev_maj[bdev->d_type],
	    bdev->d_kind.biosdisk.slice + 1,
	    bdev->d_unit, part);
	bootinfo.bi_bios_dev = bd_unit2bios(bdev->d_unit);
    }
    setenv("currdev", root, 1);
    free(root);
    return (0);
}

static void
fs_list(char *arg)
{
	int fd;
	struct dirent *d;
	char line[80];

	fd = open(arg, O_RDONLY);
	if (fd < 0)
		return;
	pager_open();
	while ((d = readdirfd(fd)) != NULL) {
		sprintf(line, "%s\n", d->d_name);
		if (pager_output(line))
			break;
	}
	pager_close();
	close(fd);
}

static int
parse_cmd(void)
{
    char *arg = cmd;
    char *ep, *p, *q;
    const char *cp;
    char line[80];
    int c, i, j;

    while ((c = *arg++)) {
	if (c == ' ' || c == '\t' || c == '\n')
	    continue;
	for (p = arg; *p && *p != '\n' && *p != ' ' && *p != '\t'; p++);
	ep = p;
	if (*p)
	    *p++ = 0;
	if (c == '-') {
	    while ((c = *arg++)) {
		if (c == 'P') {
		    if (*(uint8_t *)PTOV(0x496) & 0x10) {
			cp = "yes";
		    } else {
			opts |= OPT_SET(RBX_DUAL) | OPT_SET(RBX_SERIAL);
			cp = "no";
		    }
		    printf("Keyboard: %s\n", cp);
		    continue;
		} else if (c == 'S') {
		    j = 0;
		    while ((unsigned int)(i = *arg++ - '0') <= 9)
			j = j * 10 + i;
		    if (j > 0 && i == -'0') {
			comspeed = j;
			break;
		    }
		    /* Fall through to error below ('S' not in optstr[]). */
		}
		for (i = 0; c != optstr[i]; i++)
		    if (i == NOPT - 1)
			return -1;
		opts ^= OPT_SET(flags[i]);
	    }
	    ioctrl = OPT_CHECK(RBX_DUAL) ? (IO_SERIAL|IO_KEYBOARD) :
		     OPT_CHECK(RBX_SERIAL) ? IO_SERIAL : IO_KEYBOARD;
	    if (ioctrl & IO_SERIAL) {
	        if (sio_init(115200 / comspeed) != 0)
		    ioctrl &= ~IO_SERIAL;
	    }
	} if (c == '?') {
	    printf("\n");
	    fs_list(arg);
	    zfs_list(arg);
	    return -1;
	} else {
	    arg--;

	    /*
	     * Report pool status if the comment is 'status'. Lets
	     * hope no-one wants to load /status as a kernel.
	     */
	    if (!strcmp(arg, "status")) {
		pager_open();
		for (i = 0; devsw[i] != NULL; i++) {
		    if (devsw[i]->dv_print != NULL) {
			if (devsw[i]->dv_print(1))
			    break;
		    } else {
			sprintf(line, "%s: (unknown)\n", devsw[i]->dv_name);
			if (pager_output(line))
			    break;
		    }
		}
		pager_close();
		return -1;
	    }

	    /*
	     * If there is a colon, switch pools.
	     */
	    if (strncmp(arg, "zfs:", 4) == 0)
		q = strchr(arg + 4, ':');
	    else
		q = strchr(arg, ':');
	    if (q) {
		*q++ = '\0';
		if (mount_root(arg) != 0)
		    return -1;
		arg = q;
	    }
	    if ((i = ep - arg)) {
		if ((size_t)i >= sizeof(kname))
		    return -1;
		memcpy(kname, arg, i + 1);
	    }
	}
	arg = p;
    }
    return 0;
}

/*
 * probe arguments for partition iterator (see below)
 */
struct probe_args {
	int		fd;
	char		*devname;
	u_int		secsz;
	uint64_t	offset;
};

/*
 * simple wrapper around read() to avoid using device specific
 * strategy() directly.
 */
static int
parttblread(void *arg, void *buf, size_t blocks, uint64_t offset)
{
	struct probe_args *ppa = arg;
	size_t size = ppa->secsz * blocks;

	lseek(ppa->fd, offset * ppa->secsz, SEEK_SET);
	if (read(ppa->fd, buf, size) == size)
		return (0);
	return (EIO);
}

/*
 * scan partition entries to find boot partition starting at start_sector.
 * in case of MBR partition type PART_SOLARIS2, read VTOC and recurse.
 */
static int
probe_partition(void *arg, const char *partname,
    const struct ptable_entry *part)
{
	struct probe_args pa, *ppa = arg;
	struct ptable *table;
	uint64_t *pool_guid_ptr = NULL;
	uint64_t pool_guid = 0;
	char devname[32];
	int len, ret = 0;

	len = strlen(ppa->devname);
	if (len > sizeof (devname))
		len = sizeof (devname);

	strncpy(devname, ppa->devname, len - 1);
	devname[len - 1] = '\0';
	snprintf(devname, sizeof (devname), "%s%s:", devname, partname);

	/* filter out partitions *not* used by zfs */
	switch (part->type) {
	case PART_RESERVED:	/* efi reserverd */
	case PART_VTOC_BOOT:	/* vtoc boot area */
	case PART_VTOC_SWAP:
		return (ret);
	default:
		break;
	}

	if (part->type == PART_SOLARIS2) {
		pa.offset = part->start;
		pa.fd = open(devname, O_RDONLY);
		if (pa.fd == -1)
			return (ret);
		pa.devname = devname;
		pa.secsz = ppa->secsz;
		table = ptable_open(&pa, part->end - part->start + 1,
		    ppa->secsz, parttblread);
		if (table != NULL) {
			if (ptable_gettype(table) == PTABLE_VTOC8) {
				ret = ptable_iterate(table, &pa,
				    probe_partition);
				ptable_close(table);
				close(pa.fd);
				return (ret);
			}
			ptable_close(table);
		}
		close(pa.fd);
	}

	if (ppa->offset + part->start == start_sector) {
		/* Ask zfs_probe_dev to provide guid. */
		pool_guid_ptr = &pool_guid;
		/* Set up boot device name for non-zfs case. */
		strncpy(boot_devname, devname, sizeof (boot_devname));
	}

	ret = zfs_probe_dev(devname, pool_guid_ptr);
	if (pool_guid != 0 && bdev == NULL) {
		bdev = malloc(sizeof (struct i386_devdesc));
		bzero(bdev, sizeof (struct i386_devdesc));
		bdev->d_type = DEVT_ZFS;
		bdev->d_dev = &zfs_dev;
		bdev->d_kind.zfs.pool_guid = pool_guid;

		/*
		 * We can not set up zfs boot device name yet, as the
		 * zfs dv_init() is not completed. We will set boot_devname
		 * in main, after devsw setup.
		 */
	}

	return (0);
}

/*
 * open partition table on disk and scan partition entries to find
 * boot partition starting at start_sector (recorded by installboot).
 */
static int
probe_disk(char *devname)
{
	struct ptable *table;
	struct probe_args pa;
	uint64_t mediasz;
	int ret;

	pa.offset = 0;
	pa.devname = devname;
	pa.fd = open(devname, O_RDONLY);
	if (pa.fd == -1) {
		return (ENXIO);
	}

	ret = ioctl(pa.fd, DIOCGMEDIASIZE, &mediasz);
	if (ret == 0)
		ret = ioctl(pa.fd, DIOCGSECTORSIZE, &pa.secsz);
	if (ret == 0) {
		table = ptable_open(&pa, mediasz / pa.secsz, pa.secsz,
                    parttblread);
		if (table != NULL) {
			ret = ptable_iterate(table, &pa, probe_partition);
			ptable_close(table);
		}
	}
	close(pa.fd);
	return (ret);
}

/*
 * Probe all disks to discover ZFS pools. The idea is to walk all possible
 * disk devices, however, we also need to identify possible boot pool.
 * For boot pool detection we have boot disk passed us from BIOS, recorded
 * in bootinfo.bi_bios_dev, and start_sector LBA recorded by installboot.
 *
 * To detect boot pool, we can not use generic zfs_probe_dev() on boot disk,
 * but we need to walk partitions, as we have no way to pass start_sector
 * to zfs_probe_dev(). Note we do need to detect the partition correcponding
 * to non-zfs case, so here we can set boot_devname for both cases.
 */
static void
i386_zfs_probe(void)
{
	char devname[32];
	int boot_unit, unit;

	/* Translate bios dev to our unit number. */
	boot_unit = bd_bios2unit(bootinfo.bi_bios_dev);

	/*
	 * Open all the disks we can find and see if we can reconstruct
	 * ZFS pools from them.
	 */
	for (unit = 0; unit < MAXBDDEV; unit++) {
		if (bd_unit2bios(unit) == -1)
			break;

		sprintf(devname, "disk%d:", unit);
		/* If this is not boot disk, use generic probe. */
		if (unit != boot_unit)
			zfs_probe_dev(devname, NULL);
		else
			probe_disk(devname);
	}
}

uint64_t
ldi_get_size(void *priv)
{
	int fd = (uintptr_t) priv;
	uint64_t size;

	ioctl(fd, DIOCGMEDIASIZE, &size);
	return (size);
}
