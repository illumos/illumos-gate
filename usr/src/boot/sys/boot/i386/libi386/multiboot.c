/*-
 * Copyright (c) 2014 Roger Pau Monné <royger@FreeBSD.org>
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

/*
 * This multiboot implementation only implements a subset of the full
 * multiboot specification in order to be able to boot Xen and a
 * FreeBSD Dom0. Trying to use it to boot other multiboot compliant
 * kernels will most surely fail.
 *
 * The full multiboot specification can be found here:
 * http://www.gnu.org/software/grub/manual/multiboot/multiboot.html
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/exec.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/stdint.h>
#include <stdbool.h>
#define _MACHINE_ELF_WANT_32BIT
#include <machine/elf.h>
#include <machine/metadata.h>
#include <machine/pc/bios.h>
#include <string.h>
#include <stand.h>

#include "bootstrap.h"
#include "multiboot.h"
#include "pxe.h"
#include "../zfs/libzfs.h"
#include "../i386/libi386/libi386.h"
#include "../i386/btx/lib/btxv86.h"

#define MULTIBOOT_SUPPORTED_FLAGS \
	(MULTIBOOT_AOUT_KLUDGE|MULTIBOOT_PAGE_ALIGN|MULTIBOOT_MEMORY_INFO)
#define NUM_MODULES		2
#define METADATA_FIXED_SIZE	(PAGE_SIZE*4)
#define METADATA_MODULE_SIZE	PAGE_SIZE

#define METADATA_RESV_SIZE(mod_num) \
	roundup(METADATA_FIXED_SIZE + METADATA_MODULE_SIZE * mod_num, PAGE_SIZE)

/* MB data heap pointer */
static vm_offset_t last_addr;

extern int elf32_loadfile_raw(char *filename, u_int64_t dest,
    struct preloaded_file **result, int multiboot);
extern int elf64_load_modmetadata(struct preloaded_file *fp, u_int64_t dest);
extern int elf64_obj_loadfile(char *filename, u_int64_t dest,
    struct preloaded_file **result);

static int multiboot_loadfile(char *, u_int64_t, struct preloaded_file **);
static int multiboot_exec(struct preloaded_file *);

static int multiboot_obj_loadfile(char *, u_int64_t, struct preloaded_file **);
static int multiboot_obj_exec(struct preloaded_file *fp);

struct file_format multiboot = { multiboot_loadfile, multiboot_exec };
struct file_format multiboot_obj =
    { multiboot_obj_loadfile, multiboot_obj_exec };

extern void multiboot_tramp();

static const char mbl_name[] = "illumos Loader";

static int
num_modules(struct preloaded_file *kfp)
{
	struct kernel_module	*kmp;
	int			 mod_num = 0;

	for (kmp = kfp->f_modules; kmp != NULL; kmp = kmp->m_next)
		mod_num++;

	return (mod_num);
}

static vm_offset_t
max_addr(void)
{
	struct preloaded_file	*fp;
	vm_offset_t		 addr = 0;

	for (fp = file_findfile(NULL, NULL); fp != NULL; fp = fp->f_next) {
		if (addr < (fp->f_addr + fp->f_size))
			addr = fp->f_addr + fp->f_size;
	}

	return (addr);
}

static int
multiboot_loadfile(char *filename, u_int64_t dest,
    struct preloaded_file **result)
{
	uint32_t		*magic;
	int			 i, error;
	caddr_t			 header_search;
	ssize_t			 search_size;
	int			 fd;
	struct multiboot_header	*header;
	char			*cmdline;
	struct preloaded_file	*fp;

	if (filename == NULL)
		return (EFTYPE);

	/* is kernel already loaded? */
	fp = file_findfile(NULL, NULL);
	if (fp != NULL) {
		return (EFTYPE);
	}

	if ((fd = open(filename, O_RDONLY)) == -1)
		return (errno);

	/*
	 * Read MULTIBOOT_SEARCH size in order to search for the
	 * multiboot magic header.
	 */
	header_search = malloc(MULTIBOOT_SEARCH);
	if (header_search == NULL) {
		close(fd);
		return (ENOMEM);
	}

	search_size = read(fd, header_search, MULTIBOOT_SEARCH);
	magic = (uint32_t *)header_search;

	header = NULL;
	for (i = 0; i < (search_size / sizeof(uint32_t)); i++) {
		if (magic[i] == MULTIBOOT_HEADER_MAGIC) {
			header = (struct multiboot_header *)&magic[i];
			break;
		}
	}

	if (header == NULL) {
		error = EFTYPE;
		goto out;
	}

	/* Valid multiboot header has been found, validate checksum */
	if (header->magic + header->flags + header->checksum != 0) {
		printf(
	"Multiboot checksum failed, magic: 0x%x flags: 0x%x checksum: 0x%x\n",
	header->magic, header->flags, header->checksum);
		error = EFTYPE;
		goto out;
	}

	if ((header->flags & ~MULTIBOOT_SUPPORTED_FLAGS) != 0) {
		printf("Unsupported multiboot flags found: 0x%x\n",
		    header->flags);
		error = EFTYPE;
		goto out;
	}
	/* AOUT KLUDGE means we just load entire flat file as blob */
	if (header->flags & MULTIBOOT_AOUT_KLUDGE) {
		vm_offset_t laddr;
		int got;

		dest = header->load_addr;
		if (lseek(fd, 0, SEEK_SET) == -1) {
			printf("lseek failed\n");
			error = EIO;
			goto out;
		}
		laddr = dest;
		for (;;) {
			got = archsw.arch_readin(fd, laddr, 4096);
			if (got == 0)
				break;
			if (got < 0) {
				printf("error reading: %s", strerror(errno));
				error = EIO;
				goto out;
			}
			laddr += got;
		}

		fp = file_alloc();
		if (fp == NULL) {
			error = ENOMEM;
			goto out;
		}
		fp->f_name = strdup(filename);
		fp->f_type = strdup("aout multiboot kernel");
		fp->f_addr = header->entry_addr;
		fp->f_size = laddr - dest;
		if (fp->f_size == 0) {
			file_discard(fp);
			error = EIO;
			goto out;
		}
		fp->f_metadata = NULL;

		*result = fp;
		error = 0;
	} else {

		error = elf32_loadfile_raw(filename, dest, result, 1);
		if (error != 0) {
			printf("elf32_loadfile_raw failed: %d unable to "
			    "load multiboot kernel\n", error);
			goto out;
		}
	}

	setenv("kernelname", (*result)->f_name, 1);
	bios_addsmapdata(*result);
out:
	free(header_search);
	close(fd);
	return (error);
}

/*
 * returns allocated virtual address from MB info area
 */
static vm_offset_t
mb_malloc(size_t n)
{
	vm_offset_t ptr = last_addr;
	if (ptr + n >= high_heap_base)
		return (0);
	last_addr = roundup(last_addr + n, MULTIBOOT_INFO_ALIGN);
	return (ptr);
}

/*
 * Since for now we have no way to pass the environment to the kernel other than
 * through arguments, we need to take care of console setup.
 *
 * If the console is in mirror mode, set the kernel console from $os_console.
 * If it's unset, use first item from $console.
 * If $console is "ttyX", also pass $ttyX-mode, since it may have been set by
 * the user.
 *
 * In case of memory allocation errors, just return original command line,
 * so we have chance of booting.
 *
 * On success, cl will be freed and a new, allocated command line string is
 * returned.
 */
static char *
update_cmdline(char *cl)
{
	char *os_console = getenv("os_console");
	char *ttymode = NULL;
	char mode[10];
	char *tmp;
	int len;

	if (os_console == NULL) {
		tmp = strdup(getenv("console"));
		os_console = strsep(&tmp, ", ");
	} else
		os_console = strdup(os_console);

	if (os_console == NULL)
		return (cl);

	if (strncmp(os_console, "tty", 3) == 0) {
		snprintf(mode, sizeof (mode), "%s-mode", os_console);
		ttymode = getenv(mode);	/* never NULL */
	}

	if (strstr(cl, "-B") != NULL) {
		len = strlen(cl) + 1;
		/*
		 * if console is not present, add it
		 * if console is ttyX, add ttymode
		 */
		tmp = strstr(cl, "console");
		if (tmp == NULL) {
			len += 12;	/* " -B console=" */
			len += strlen(os_console);
			if (ttymode != NULL) {
				len += 13;	/* ",ttyX-mode=\"\"" */
				len += strlen(ttymode);
			}
			tmp = malloc(len);
			if (tmp == NULL) {
				free(os_console);
				return (cl);
			}
			if (ttymode != NULL)
				sprintf(tmp,
				    "%s -B console=%s,%s-mode=\"%s\"",
				    cl, os_console, os_console, ttymode);
			else
				sprintf(tmp, "%s -B console=%s",
				    cl, os_console);
		} else {
			/* console is set, do we need tty mode? */
			tmp += 8;
			if (strstr(tmp, "tty") == tmp) {
				strncpy(mode, tmp, 4);
				mode[4] = '\0';
				strcat(mode, "-mode");
				ttymode = getenv(mode);	/* never NULL */
			} else { /* nope */
				free(os_console);
				return (cl);
			}
			len = strlen(cl) + 1;
			len += 13;	/* ",ttyX-mode=\"\"" */
			len += strlen(ttymode);
			tmp = malloc(len);
			if (tmp == NULL) {
				free(os_console);
				return (cl);
			}
			sprintf(tmp, "%s,%s=\"%s\"", cl, mode, ttymode);
		}
	} else {
		/*
		 * no -B, so we need to add " -B console=%s[,ttyX-mode=\"%s\"]"
		 */
		len = strlen(cl) + 1;
		len += 12;		/* " -B console=" */
		len += strlen(os_console);
		if (ttymode != NULL) {
			len += 13;	/* ",ttyX-mode=\"\"" */
			len += strlen(ttymode);
		}
		tmp = malloc(len);
		if (tmp == NULL) {
			free(os_console);
			return (cl);
		}
		if (ttymode != NULL)
			sprintf(tmp, "%s -B console=%s,%s-mode=\"%s\"", cl,
			    os_console, os_console, ttymode);
		else
			sprintf(tmp, "%s -B console=%s", cl, os_console);
	}
	free(os_console);
	free(cl);
	return (tmp);
}

/*
 * Search the command line for named property.
 *
 * Return codes:
 *	0	The name is found, we return the data in value and len.
 *	ENOENT	The name is not found.
 *	EINVAL	The provided command line is badly formed.
 */
static int
find_property_value(const char *cmd, const char *name, const char **value,
    size_t *len)
{
	const char *namep, *valuep;
	size_t name_len, value_len;
	int quoted;

	*value = NULL;
	*len = 0;

	if (cmd == NULL)
		return (ENOENT);

	while (*cmd != '\0') {
		if (cmd[0] != '-' || cmd[1] != 'B') {
			cmd++;
			continue;
		}
		cmd += 2;	/* Skip -B */
		while (cmd[0] == ' ' || cmd[0] == '\t')
			cmd++;	/* Skip whitespaces. */
		while (*cmd != '\0' && cmd[0] != ' ' && cmd[0] != '\t') {
			namep = cmd;
			valuep = strchr(cmd, '=');
			if (valuep == NULL)
				break;
			name_len = valuep - namep;
			valuep++;
			value_len = 0;
			quoted = 0;
			for (; ; ++value_len) {
				if (valuep[value_len] == '\0')
					break;

				/* Is this value quoted? */
				if (value_len == 0 &&
				    (valuep[0] == '\'' || valuep[0] == '"')) {
					quoted = valuep[0];
					++value_len;
				}

				/*
				 * In the quote accept any character,
				 * but look for ending quote.
				 */
				if (quoted != 0) {
					if (valuep[value_len] == quoted)
						quoted = 0;
					continue;
				}

				/* A comma or white space ends the value. */
				if (valuep[value_len] == ',' ||
				    valuep[value_len] == ' ' ||
				    valuep[value_len] == '\t')
					break;
			}
			if (quoted != 0) {
				printf("Missing closing '%c' in \"%s\"\n",
				    quoted, valuep);
				return (EINVAL);
			}

			if (value_len != 0) {
				if (strncmp(namep, name, name_len) == 0) {
					*value = valuep;
					*len = value_len;
					return (0);
				}
			}
			cmd = valuep + value_len;
			while (*cmd == ',')
				cmd++;
		}
	}
	return (ENOENT);
}

static int
kernel_cmdline(struct preloaded_file *fp, struct i386_devdesc *rootdev,
    char **line)
{
	const char *fs = getenv("fstype");
	char *cmdline = NULL;
	size_t len;
	bool zfs_root = false;
	int rv = 0;

	if (rootdev->d_type == DEVT_ZFS)
		zfs_root = true;

	/* If we have fstype set in env, reset zfs_root if needed. */
	if (fs != NULL && strcmp(fs, "zfs") != 0)
		zfs_root = false;

	/*
	 * If we have fstype set on the command line,
	 * reset zfs_root if needed.
	 */
	rv = find_property_value(fp->f_args, "fstype", &fs, &len);
	switch (rv) {
	case EINVAL:		/* invalid command line */
		return (rv);
	case ENOENT:		/* fall through */
	case 0:
		break;
	}

	if (fs != NULL && strncmp(fs, "zfs", len) != 0)
		zfs_root = false;

	len = strlen(fp->f_name) + 1;

	if (fp->f_args != NULL)
		len += strlen(fp->f_args) + 1;

	if (zfs_root == true)
		len += 3 + strlen(zfs_bootfs(rootdev)) + 1;

	cmdline = malloc(len);
	if (cmdline == NULL)
		return (ENOMEM);

	if (zfs_root == true) {
		if (fp->f_args != NULL)
			snprintf(cmdline, len, "%s %s -B %s", fp->f_name,
			    fp->f_args, zfs_bootfs(rootdev));
		else
			snprintf(cmdline, len, "%s -B %s", fp->f_name,
			    zfs_bootfs(rootdev));
	} else if (fp->f_args != NULL)
		snprintf(cmdline, len, "%s %s", fp->f_name, fp->f_args);
	else
		snprintf(cmdline, len, "%s", fp->f_name);

	*line = update_cmdline(cmdline);
	return (0);
}

static int
multiboot_exec(struct preloaded_file *fp)
{
	struct preloaded_file		*mfp;
	vm_offset_t			 module_start, metadata_size;
	vm_offset_t			 modulep, kernend, entry;
	struct file_metadata		*md;
	Elf_Ehdr			*ehdr;
	struct multiboot_info		*mb_info = NULL;
	struct multiboot_mod_list	*mb_mod = NULL;
	multiboot_memory_map_t		*mmap;
	struct bios_smap		*smap;
	struct i386_devdesc		*rootdev;
	extern BOOTPLAYER		bootplayer; 	/* dhcp info */
	char				*cmdline = NULL;
	size_t				 len;
	int				 error, num, i;
	int				 rootfs = 0;	/* flag for rootfs */
	int				 xen = 0;	/* flag for xen */
	int				 kernel = 0;	/* flag for kernel */

	/* set up base for mb_malloc */
	for (mfp = fp; mfp->f_next != NULL; mfp = mfp->f_next);

	/* start info block from new page */
	last_addr = roundup(mfp->f_addr + mfp->f_size, MULTIBOOT_MOD_ALIGN);

	/* Allocate the multiboot struct and fill the basic details. */
	mb_info = (struct multiboot_info *)PTOV(mb_malloc(sizeof (*mb_info)));

	bzero(mb_info, sizeof(struct multiboot_info));
	mb_info->flags = MULTIBOOT_INFO_MEMORY|MULTIBOOT_INFO_BOOT_LOADER_NAME;
	mb_info->mem_lower = bios_basemem / 1024;
	mb_info->mem_upper = bios_extmem / 1024;
	mb_info->boot_loader_name = mb_malloc(strlen(mbl_name) + 1);

	i386_copyin(mbl_name, mb_info->boot_loader_name, strlen(mbl_name)+1);

	i386_getdev((void **)(&rootdev), NULL, NULL);
	if (rootdev == NULL) {
		printf("can't determine root device\n");
		error = EINVAL;
		goto error;
	}

	/*
	 * boot image command line. if args were not provided, we need to set
	 * args here, and that depends on image type...
	 * fortunately we only have following options:
	 * 64 or 32 bit unix or xen. so we just check if f_name has unix.
	 */
	/* do we boot xen? */
	if (strstr(fp->f_name, "unix") == NULL)
		xen = 1;

	entry = fp->f_addr;

	num = 0;
	for (mfp = fp->f_next; mfp != NULL; mfp = mfp->f_next) {
		num++;
		if (mfp->f_type != NULL && strcmp(mfp->f_type, "rootfs") == 0)
			rootfs++;
		if (mfp->f_type != NULL && strcmp(mfp->f_type, "kernel") == 0)
			kernel++;
	}

	if (num == 0 || rootfs == 0) {
		/* need at least one module - rootfs */
		printf("No rootfs module provided, aborting\n");
		error = EINVAL;
		goto error;
	}
	if (xen == 1 && kernel == 0) {
		printf("No kernel module provided for xen, aborting\n");
		error = EINVAL;
		goto error;
	}
	mb_mod = (struct multiboot_mod_list *) PTOV(last_addr);
	last_addr += roundup(sizeof(*mb_mod) * num, MULTIBOOT_INFO_ALIGN);

	bzero(mb_mod, sizeof(*mb_mod) * num);

	num = 0;
	for (mfp = fp->f_next; mfp != NULL; mfp = mfp->f_next) {
		mb_mod[num].mod_start = mfp->f_addr;
		mb_mod[num].mod_end = mfp->f_addr + mfp->f_size;

		if (strcmp(mfp->f_type, "kernel") == 0) {
			cmdline = NULL;
			error = kernel_cmdline(mfp, rootdev, &cmdline);
			if (error != 0)
				goto error;
		} else {
			len = strlen(mfp->f_name) + 1;
			len += strlen(mfp->f_type) + 5 + 1;
			if (mfp->f_args != NULL) {
				len += strlen(mfp->f_args) + 1;
			}
			cmdline = malloc(len);
			if (cmdline == NULL) {
				error = ENOMEM;
				goto error;
			}

			if (mfp->f_args != NULL)
				snprintf(cmdline, len, "%s type=%s %s",
				    mfp->f_name, mfp->f_type, mfp->f_args);
			else
				snprintf(cmdline, len, "%s type=%s",
				    mfp->f_name, mfp->f_type);
		}

		mb_mod[num].cmdline = mb_malloc(strlen(cmdline)+1);
		i386_copyin(cmdline, mb_mod[num].cmdline, strlen(cmdline)+1);
		free(cmdline);
		num++;
	}

	mb_info->mods_count = num;
	mb_info->mods_addr = VTOP(mb_mod);
	mb_info->flags |= MULTIBOOT_INFO_MODS;

	md = file_findmetadata(fp, MODINFOMD_SMAP);
	if (md == NULL) {
		printf("no memory smap\n");
		error = EINVAL;
		goto error;
	}

	num = md->md_size / sizeof(struct bios_smap); /* number of entries */
	mmap = (multiboot_memory_map_t *)PTOV(mb_malloc(sizeof(*mmap) * num));

	mb_info->mmap_length = num * sizeof(*mmap);
	smap = (struct bios_smap *)md->md_data;

	for (i = 0; i < num; i++) {
		mmap[i].size = sizeof(*smap);
		mmap[i].addr = smap[i].base;
		mmap[i].len = smap[i].length;
		mmap[i].type = smap[i].type;
	}
	mb_info->mmap_addr = VTOP(mmap);
	mb_info->flags |= MULTIBOOT_INFO_MEM_MAP;

	if (strstr(getenv("loaddev"), "pxe") != NULL) {
		mb_info->drives_length = sizeof (BOOTPLAYER);
		mb_info->drives_addr = mb_malloc(mb_info->drives_length);
		i386_copyin(&bootplayer, mb_info->drives_addr,
		    mb_info->drives_length);
		mb_info->flags &= ~MULTIBOOT_INFO_DRIVE_INFO;
	}
	/*
	 * Set the image command line. Need to do this as last thing,
	 * as Illumos kernel dboot_startkern will check cmdline
	 * address as last check to find first free address.
	 */
	if (fp->f_args == NULL) {
		if (xen)
			cmdline = getenv("xen_cmdline");
		else
			cmdline = getenv("boot-args");
		if (cmdline != NULL) {
			fp->f_args = strdup(cmdline);
			if (fp->f_args == NULL) {
				error = ENOMEM;
				goto error;
			}
		}
	}

	/*
	 * if image is xen, we just use f_name + f_args for commandline
	 * for unix, we need to add zfs-bootfs.
	 */
	if (xen) {
		len = strlen(fp->f_name) + 1;
		if (fp->f_args != NULL)
			len += strlen(fp->f_args) + 1;

		if (fp->f_args != NULL) {
			if((cmdline = malloc(len)) == NULL) {
				error = ENOMEM;
				goto error;
			}
			snprintf(cmdline, len, "%s %s", fp->f_name, fp->f_args);
		} else {
			cmdline = strdup(fp->f_name);
			if (cmdline == NULL) {
				error = ENOMEM;
				goto error;
			}
		}
	} else {
		cmdline = NULL;
		if ((error = kernel_cmdline(fp, rootdev, &cmdline)) != 0)
			goto error;
	}

	mb_info->cmdline = mb_malloc(strlen(cmdline)+1);
	i386_copyin(cmdline, mb_info->cmdline, strlen(cmdline)+1);
	mb_info->flags |= MULTIBOOT_INFO_CMDLINE;
	free(cmdline);
	cmdline = NULL;

	dev_cleanup();
	__exec((void *)VTOP(multiboot_tramp), (void *)entry,
	    (void *)VTOP(mb_info));

	panic("exec returned");

error:
	free(cmdline);
	return (error);
}

static int
multiboot_obj_loadfile(char *filename, u_int64_t dest,
    struct preloaded_file **result)
{
	struct preloaded_file	*mfp, *kfp, *rfp;
	struct kernel_module	*kmp;
	int			 error, mod_num;

	/* See if there's a aout multiboot kernel loaded */
	mfp = file_findfile(NULL, "aout multiboot kernel");
	if (mfp != NULL) {
		/* we have normal kernel loaded, add module */
		rfp = file_loadraw(filename, "module", 0, NULL, 0);
		if (rfp == NULL) {
			printf(
			"Unable to load %s as a multiboot payload module\n",
			filename);
			return (EINVAL);
		}
		rfp->f_size = roundup(rfp->f_size, PAGE_SIZE);
		*result = rfp;
		return (0);
	}

	/* See if there's a multiboot kernel loaded */
	mfp = file_findfile(NULL, "elf multiboot kernel");
	if (mfp == NULL) {
		return (EFTYPE);	/* this allows to check other methods */
	}

	/*
	 * We have a multiboot kernel loaded, see if there's a
	 * kernel loaded also.
	 */
	kfp = file_findfile(NULL, "elf kernel");
	if (kfp == NULL) {
		/*
		 * No kernel loaded, this must be it. The kernel has to
		 * be loaded as a raw file, it will be processed by
		 * Xen and correctly loaded as an ELF file.
		 */
		rfp = file_loadraw(filename, "elf kernel", 0, NULL, 0);
		if (rfp == NULL) {
			printf(
			"Unable to load %s as a multiboot payload kernel\n",
			filename);
			return (EINVAL);
		}

		/* Load kernel metadata... */
		setenv("kernelname", filename, 1);
		error = elf64_load_modmetadata(rfp, rfp->f_addr + rfp->f_size);
		if (error) {
			printf("Unable to load kernel %s metadata error: %d\n",
			    rfp->f_name, error);
			return (EINVAL);
		}

		/*
		 * Save space at the end of the kernel in order to place
		 * the metadata information. We do an approximation of the
		 * max metadata size, this is not optimal but it's probably
		 * the best we can do at this point. Once all modules are
		 * loaded and the size of the metadata is known this
		 * space will be recovered if not used.
		 */
		mod_num = num_modules(rfp);
		rfp->f_size = roundup(rfp->f_size, PAGE_SIZE);
		rfp->f_size += METADATA_RESV_SIZE(mod_num);
		*result = rfp;
	} else {
		/* The rest should be loaded as regular modules */
		error = elf64_obj_loadfile(filename, dest, result);
		if (error != 0) {
			printf("Unable to load %s as an object file, error: %d",
			    filename, error);
			return (error);
		}
	}

	return (0);
}

static int
multiboot_obj_exec(struct preloaded_file *fp)
{

	return (EFTYPE);
}
