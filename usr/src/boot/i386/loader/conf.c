/*
 * Copyright (c) 1998 Michael Smith <msmith@freebsd.org>
 * All rights reserved.
 * Copyright 2024 MNX Cloud, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
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
#include "libi386.h"
#include "libzfs.h"

/*
 * We could use linker sets for some or all of these, but
 * then we would have to control what ended up linked into
 * the bootstrap.  So it's easier to conditionalise things
 * here.
 *
 * XXX rename these arrays to be consistent and less namespace-hostile
 *
 * XXX as libi386 and biosboot merge, some of these can become linker sets.
 */

extern struct devsw vdisk_dev;

/* Exported for libstand */
struct devsw *devsw[] = {
	&biosfd,
	&bioscd,
	&bioshd,
	&pxedisk,
	&vdisk_dev,
	&zfs_dev,
	NULL
};

struct fs_ops *file_system[] = {
	&gzipfs_fsops,
	&zfs_fsops,
	&ufs_fsops,
	&dosfs_fsops,
	&cd9660_fsops,
	&tftp_fsops,
	&nfs_fsops,
	NULL
};

/* Exported for i386 only */
/*
 * Sort formats so that those that can detect based on arguments
 * rather than reading the file go first.
 */
extern struct file_format	i386_elf;
extern struct file_format	i386_elf_obj;
extern struct file_format	amd64_elf;
extern struct file_format	amd64_elf_obj;
extern struct file_format	multiboot;
extern struct file_format	multiboot_obj;
extern struct file_format	multiboot2;
extern struct file_format	linux;
extern struct file_format	linux_initrd;

struct file_format *file_formats[] = {
	&multiboot2,
	&multiboot,
	&multiboot_obj,
	&amd64_elf,
	&amd64_elf_obj,
	&i386_elf,
	&i386_elf_obj,
	&linux,
	&linux_initrd,
	NULL
};

/*
 * Consoles
 *
 * We don't prototype these in libi386.h because they require
 * data structures from bootstrap.h as well.
 */
extern struct console text;
extern struct console nullconsole;
extern struct console spinconsole;
extern void comc_ini(void);

struct console_template ct_list[] = {
	[0] = { .ct_dev = &text, .ct_init = NULL },
	[1] = { .ct_dev = NULL, .ct_init = comc_ini },
	[2] = { .ct_dev = &nullconsole, .ct_init = NULL },
	[3] = { .ct_dev = &spinconsole, .ct_init = NULL },
	[4] = { .ct_dev = NULL, .ct_init = NULL },
};

struct console **consoles;

extern struct pnphandler isapnphandler;
extern struct pnphandler biospnphandler;
extern struct pnphandler biospcihandler;

struct pnphandler *pnphandlers[] = {
	&biospnphandler, /* should go first, as it may set isapnp_readport */
	&isapnphandler,
	&biospcihandler,
	NULL
};
