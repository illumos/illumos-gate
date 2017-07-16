/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Toomas Soome <tsoome@me.com>
 */

/*
 * Primitive linux loader, at the moment only intended to load memtest86+.bin.
 *
 * Note the linux kernel location conflicts with loader, so we need to
 * read in to temporary space and relocate on exec, when btx is stopped.
 */
#include <sys/cdefs.h>
#include <sys/stat.h>
#include <stand.h>
#include <machine/metadata.h>
#include <machine/pc/bios.h>

#include "linux.h"
#include "bootstrap.h"
#include "libi386.h"
#include "btxv86.h"

static int linux_loadkernel(char *, u_int64_t, struct preloaded_file **);
static int linux_loadinitrd(char *, u_int64_t, struct preloaded_file **);
static int linux_exec(struct preloaded_file *);
static int linux_execinitrd(struct preloaded_file *);

struct file_format linux = { linux_loadkernel, linux_exec };
struct file_format linux_initrd = { linux_loadinitrd, linux_execinitrd };

uint32_t linux_text_len;
uint32_t linux_data_tmp_addr;
uint32_t linux_data_real_addr;
static size_t max_cmdline_size;

static void
test_addr(uint64_t addr, uint64_t length, vm_offset_t *result)
{
	vm_offset_t candidate;

	if (addr + length >= 0xa0000)
		length = 0xa0000 - addr;

	candidate = addr + length - (LINUX_CL_OFFSET + max_cmdline_size);
	if (candidate > LINUX_OLD_REAL_MODE_ADDR)
		candidate = LINUX_OLD_REAL_MODE_ADDR;
	if (candidate < addr)
		return;

	if (candidate > *result || *result == (vm_offset_t)-1)
		*result = candidate;
}

static vm_offset_t
find_real_addr(struct preloaded_file *fp)
{
	struct bios_smap *smap;
	struct file_metadata *md;
	int entries, i;
	vm_offset_t candidate = -1;

	md = file_findmetadata(fp, MODINFOMD_SMAP);
	if (md == NULL) {
		printf("no memory smap\n");
		return (candidate);
	}
	entries = md->md_size / sizeof (struct bios_smap);
	smap = (struct bios_smap *)md->md_data;
	for (i = 0; i < entries; i++) {
		if (smap[i].type != SMAP_TYPE_MEMORY)
			continue;
		if (smap[i].base >= 0xa0000)
			continue;
		test_addr(smap[i].base, smap[i].length, &candidate);
	}
	return (candidate);
}

static int
linux_loadkernel(char *filename, uint64_t dest, struct preloaded_file **result)
{
	struct linux_kernel_header lh;
	struct preloaded_file *fp;
	struct stat sb;
	ssize_t n;
	int fd, error = 0;
	int setup_sects, linux_big;
	unsigned long data, text;
	vm_offset_t mem;

	if (filename == NULL)
		return (EFTYPE);

	/* is kernel already loaded? */
	fp = file_findfile(NULL, NULL);
	if (fp != NULL)
		return (EFTYPE);

	if ((fd = open(filename, O_RDONLY)) == -1)
		return (errno);

	if (fstat(fd, &sb) != 0) {
		printf("stat failed\n");
		error = errno;
		close(fd);
		return (error);
	}

	n = read(fd, &lh, sizeof (lh));
	if (n != sizeof (lh)) {
		printf("error reading kernel header\n");
		error = EIO;
		goto end;
	}

	if (lh.boot_flag != BOOTSEC_SIGNATURE) {
		printf("invalid magic number\n");
		error = EFTYPE;
		goto end;
	}

	setup_sects = lh.setup_sects;
	linux_big = 0;
	max_cmdline_size = 256;

	if (setup_sects > LINUX_MAX_SETUP_SECTS) {
		printf("too many setup sectors\n");
		error = EFTYPE;
		goto end;
	}

	fp = file_alloc();
	if (fp == NULL) {
		error = ENOMEM;
		goto end;
	}

	bios_addsmapdata(fp);

	if (lh.header == LINUX_MAGIC_SIGNATURE && lh.version >= 0x0200) {
		linux_big = lh.loadflags & LINUX_FLAG_BIG_KERNEL;
		lh.type_of_loader = LINUX_BOOT_LOADER_TYPE;

		if (lh.version >= 0x0206)
			max_cmdline_size = lh.cmdline_size + 1;

		linux_data_real_addr = find_real_addr(fp);
		if (linux_data_real_addr == -1) {
			printf("failed to detect suitable low memory\n");
			file_discard(fp);
			error = ENOMEM;
			goto end;
		}
		if (lh.version >= 0x0201) {
			lh.heap_end_ptr = LINUX_HEAP_END_OFFSET;
			lh.loadflags |= LINUX_FLAG_CAN_USE_HEAP;
		}
		if (lh.version >= 0x0202) {
			lh.cmd_line_ptr = linux_data_real_addr +
			    LINUX_CL_OFFSET;
		} else {
			lh.cl_magic = LINUX_CL_MAGIC;
			lh.cl_offset = LINUX_CL_OFFSET;
			lh.setup_move_size = LINUX_CL_OFFSET + max_cmdline_size;
		}
	} else {
		/* old kernel */
		lh.cl_magic = LINUX_CL_MAGIC;
		lh.cl_offset = LINUX_CL_OFFSET;
		setup_sects = LINUX_DEFAULT_SETUP_SECTS;
		linux_data_real_addr = LINUX_OLD_REAL_MODE_ADDR;
	}
	if (setup_sects == 0)
		setup_sects = LINUX_DEFAULT_SETUP_SECTS;

	data = setup_sects << 9;
	text = sb.st_size - data - 512;

	/* temporary location of real mode part */
	linux_data_tmp_addr = LINUX_BZIMAGE_ADDR + text;

	if (!linux_big && text > linux_data_real_addr - LINUX_ZIMAGE_ADDR) {
		printf("Linux zImage is too big, use bzImage instead\n");
		file_discard(fp);
		error = EFBIG;
		goto end;
	}
	printf("   [Linux-%s, setup=0x%x, size=0x%x]\n",
	    (linux_big ? "bzImage" : "zImage"), data, text);

	/* copy real mode part to place */
	i386_copyin(&lh, linux_data_tmp_addr, sizeof (lh));
	n = data + 512 - sizeof (lh);
	if (archsw.arch_readin(fd, linux_data_tmp_addr+sizeof (lh), n) != n) {
		printf("failed to read %s\n", filename);
		file_discard(fp);
		error = errno;
		goto end;
	}

	/* Clear the heap space. */
	if (lh.header != LINUX_MAGIC_SIGNATURE || lh.version < 0x0200) {
		memset(PTOV(linux_data_tmp_addr + ((setup_sects + 1) << 9)),
		    0, (LINUX_MAX_SETUP_SECTS - setup_sects - 1) << 9);
	}

	mem = LINUX_BZIMAGE_ADDR;

	if (archsw.arch_readin(fd, mem, text) != text) {
		printf("failed to read %s\n", filename);
		file_discard(fp);
		error = EIO;
		goto end;
	}

	fp->f_name = strdup(filename);
	if (linux_big)
		fp->f_type = strdup("Linux bzImage");
	else
		fp->f_type = strdup("Linux zImage");

	/*
	 * NOTE: f_addr and f_size is used here as hint for module
	 * allocation, as module location will be f_addr + f_size.
	 */
	fp->f_addr = linux_data_tmp_addr;
	fp->f_size = LINUX_SETUP_MOVE_SIZE;
	linux_text_len = text;

	/*
	 * relocater_data is space allocated in relocater_tramp.S
	 * There is space for 3 instances + terminating zero in case
	 * all 3 entries are used.
	 */
	if (linux_big == 0) {
		relocater_data[0].src = LINUX_BZIMAGE_ADDR;
		relocater_data[0].dest = LINUX_ZIMAGE_ADDR;
		relocater_data[0].size = text;
		relocater_data[1].src = linux_data_tmp_addr;
		relocater_data[1].dest = linux_data_real_addr;
		relocater_data[1].size = LINUX_SETUP_MOVE_SIZE;
		/* make sure the next entry is zeroed */
		relocater_data[2].src = 0;
		relocater_data[2].dest = 0;
		relocater_data[2].size = 0;
	} else {
		relocater_data[0].src = linux_data_tmp_addr;
		relocater_data[0].dest = linux_data_real_addr;
		relocater_data[0].size = LINUX_SETUP_MOVE_SIZE;
		/* make sure the next entry is zeroed */
		relocater_data[1].src = 0;
		relocater_data[1].dest = 0;
		relocater_data[1].size = 0;
	}

	*result = fp;
	setenv("kernelname", fp->f_name, 1);
end:
	close(fd);
	return (error);
}

static int
linux_exec(struct preloaded_file *fp)
{
	struct linux_kernel_header *lh = (struct linux_kernel_header *)
	    PTOV(linux_data_tmp_addr);
	struct preloaded_file *mfp = fp->f_next;
	char *arg, *vga;
	char *src, *dst;
	int linux_big;
	uint32_t moveto, max_addr;
	uint16_t segment;
	struct i386_devdesc *rootdev;

	if (strcmp(fp->f_type, "Linux bzImage") == 0)
		linux_big = 1;
	else if (strcmp(fp->f_type, "Linux zImage") == 0)
		linux_big = 0;
	else
		return (EFTYPE);

	i386_getdev((void **)(&rootdev), fp->f_name, NULL);
	if (rootdev != NULL)
		relocator_edx = bd_unit2bios(rootdev->d_unit);

	/*
	 * command line
	 * if not set in fp, read from boot-args env
	 */
	if (fp->f_args == NULL)
		fp->f_args = getenv("boot-args");
	arg = fp->f_args;		/* it can still be NULL */

	/* video mode selection */
	if (arg && (vga = strstr(arg, "vga=")) != NULL) {
		char *value = vga + 4;
		uint16_t vid_mode;

		if (strncmp(value, "normal", 6) < 1)
			vid_mode = LINUX_VID_MODE_NORMAL;
		else if (strncmp(value, "ext", 3) < 1)
			vid_mode = LINUX_VID_MODE_EXTENDED;
		else if (strncmp(value, "ask", 3) < 1)
			vid_mode = LINUX_VID_MODE_ASK;
		else {
			long mode;
			errno = 0;

			/*
			 * libstand sets ERANGE as only error case;
			 * however, the actual value is 16bit, so
			 * additional check is needed.
			 */
			mode = strtol(value, NULL, 0);
			if (errno != 0 || mode >> 16 != 0 || mode == 0) {
				printf("bad value for video mode\n");
				return (EINTR);
			}
			vid_mode = (uint16_t) mode;
		}
		lh->vid_mode = vid_mode;
	}

	src = arg;
	dst = (char *)PTOV(linux_data_tmp_addr + LINUX_CL_OFFSET);
	if (src != NULL) {
		while (*src != 0 && dst < (char *)
		    PTOV(linux_data_tmp_addr + LINUX_CL_END_OFFSET))
			*(dst++) = *(src++);
	}
	*dst = 0;

	/* set up module relocation */
	if (mfp != NULL) {
		moveto = (bios_extmem / 1024 + 0x400) << 10;
		moveto = (moveto - mfp->f_size) & 0xfffff000;
		max_addr = (lh->header == LINUX_MAGIC_SIGNATURE &&
		    lh->version >= 0x0203 ?
		    lh->initrd_addr_max : LINUX_INITRD_MAX_ADDRESS);
		if (moveto + mfp->f_size >= max_addr)
			moveto = (max_addr - mfp->f_size) & 0xfffff000;

		/*
		 * XXX: Linux 2.3.xx has a bug in the memory range check,
		 * so avoid the last page.
		 * XXX: Linux 2.2.xx has a bug in the memory range check,
		 * which is worse than that of Linux 2.3.xx, so avoid the
		 * last 64kb. *sigh*
		 */
		moveto -= 0x10000;

		/* need to relocate initrd first */
		if (linux_big == 0) {
			relocater_data[2].src = relocater_data[1].src;
			relocater_data[2].dest = relocater_data[1].dest;
			relocater_data[2].size = relocater_data[1].size;
			relocater_data[1].src = relocater_data[0].src;
			relocater_data[1].dest = relocater_data[0].dest;
			relocater_data[1].size = relocater_data[0].size;
			relocater_data[0].src = mfp->f_addr;
			relocater_data[0].dest = moveto;
			relocater_data[0].size = mfp->f_size;
		} else {
			relocater_data[1].src = relocater_data[0].src;
			relocater_data[1].dest = relocater_data[0].dest;
			relocater_data[1].size = relocater_data[0].size;
			relocater_data[0].src = mfp->f_addr;
			relocater_data[0].dest = moveto;
			relocater_data[0].size = mfp->f_size;
		}
		lh->ramdisk_image = moveto;
		lh->ramdisk_size = mfp->f_size;
	}

	segment = linux_data_real_addr >> 4;
	relocator_ds = segment;
	relocator_es = segment;
	relocator_fs = segment;
	relocator_gs = segment;
	relocator_ss = segment;
	relocator_sp = LINUX_ESP;
	relocator_ip = 0;
	relocator_cs = segment + 0x20;
	relocator_a20_enabled = 1;
	i386_copyin(relocater, 0x600, relocater_size);

	dev_cleanup();

	__exec((void *)0x600);

	panic("exec returned");

	return (EINTR);		/* not reached */
}

static int
linux_loadinitrd(char *filename, uint64_t dest, struct preloaded_file **result)
{
	struct preloaded_file *mfp;
	vm_offset_t mem;

	if (filename == NULL)
		return (EFTYPE);

	/* check if the kernel is loaded */
	mfp = file_findfile(NULL, "Linux bzImage");
	if (mfp == NULL)
		mfp = file_findfile(NULL, "Linux zImage");
	if (mfp == NULL)
		return (EFTYPE);

	mfp = file_loadraw(filename, "module", 0, NULL, 0);
	if (mfp == NULL)
		return (EFTYPE);
	*result = mfp;
	return (0);
}

static int linux_execinitrd(struct preloaded_file *pf)
{
	return (EFTYPE);
}
