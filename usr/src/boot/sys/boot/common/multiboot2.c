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
 * Copyright 2017 Toomas Soome <tsoome@me.com>
 */

/*
 * This module adds support for loading and booting illumos multiboot2
 * kernel. This code is only built to support the illumos kernel, it does
 * not support xen.
 */
#include <sys/cdefs.h>
#include <sys/stddef.h>

#include <sys/param.h>
#include <sys/exec.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/stdint.h>
#include <sys/multiboot2.h>
#include <stand.h>
#include <stdbool.h>
#include "libzfs.h"

#include "bootstrap.h"

#include <machine/metadata.h>
#include <machine/pc/bios.h>

#include "../i386/libi386/libi386.h"
#include "../i386/btx/lib/btxv86.h"
#include "pxe.h"

extern BOOTPLAYER bootplayer;	/* dhcp info */
extern void multiboot_tramp();

#include "platform/acfreebsd.h"
#include "acconfig.h"
#define ACPI_SYSTEM_XFACE
#include "actypes.h"
#include "actbl.h"

extern ACPI_TABLE_RSDP *rsdp;

/* MB data heap pointer. */
static vm_offset_t last_addr;
extern char bootprog_info[];

extern int elf32_loadfile_raw(char *filename, u_int64_t dest,
    struct preloaded_file **result, int multiboot);
static int multiboot2_loadfile(char *, u_int64_t, struct preloaded_file **);
static int multiboot2_exec(struct preloaded_file *);

struct file_format multiboot2 = { multiboot2_loadfile, multiboot2_exec };
static bool keep_bs = false;
static bool have_framebuffer = false;
static vm_offset_t load_addr;
static vm_offset_t entry_addr;

/*
 * Validate tags in info request. This function is provided just to
 * recognize the current tag list and only serves as a limited
 * safe guard against possibly corrupt information.
 */
static bool
is_info_request_valid(multiboot_header_tag_information_request_t *rtag)
{
	int i;

	/*
	 * If the tag is optional and we do not support it, we do not
	 * have to do anything special, so we skip optional tags.
	 */
	if (rtag->mbh_flags & MULTIBOOT_HEADER_TAG_OPTIONAL)
		return (true);

	for (i = 0; i < (rtag->mbh_size - sizeof (*rtag)) /
	    sizeof (rtag->mbh_requests[0]); i++)
		switch (rtag->mbh_requests[i]) {
		case MULTIBOOT_TAG_TYPE_END:
		case MULTIBOOT_TAG_TYPE_CMDLINE:
		case MULTIBOOT_TAG_TYPE_BOOT_LOADER_NAME:
		case MULTIBOOT_TAG_TYPE_MODULE:
		case MULTIBOOT_TAG_TYPE_BASIC_MEMINFO:
		case MULTIBOOT_TAG_TYPE_BOOTDEV:
		case MULTIBOOT_TAG_TYPE_MMAP:
		case MULTIBOOT_TAG_TYPE_FRAMEBUFFER:
		case MULTIBOOT_TAG_TYPE_VBE:
		case MULTIBOOT_TAG_TYPE_ELF_SECTIONS:
		case MULTIBOOT_TAG_TYPE_APM:
		case MULTIBOOT_TAG_TYPE_EFI32:
		case MULTIBOOT_TAG_TYPE_EFI64:
		case MULTIBOOT_TAG_TYPE_ACPI_OLD:
		case MULTIBOOT_TAG_TYPE_ACPI_NEW:
		case MULTIBOOT_TAG_TYPE_NETWORK:
		case MULTIBOOT_TAG_TYPE_EFI_MMAP:
		case MULTIBOOT_TAG_TYPE_EFI_BS:
		case MULTIBOOT_TAG_TYPE_EFI32_IH:
		case MULTIBOOT_TAG_TYPE_EFI64_IH:
		case MULTIBOOT_TAG_TYPE_LOAD_BASE_ADDR:
			break;
		default:
			printf("unsupported information tag: 0x%x\n",
			    rtag->mbh_requests[i]);
			return (false);
		}
	return (true);
}

static int
multiboot2_loadfile(char *filename, u_int64_t dest,
    struct preloaded_file **result)
{
	int fd, error;
	uint32_t i;
	struct stat st;
	caddr_t header_search;
	multiboot2_header_t *header;
	multiboot_header_tag_t *tag;
	multiboot_header_tag_address_t *addr_tag = NULL;
	multiboot_header_tag_entry_address_t *entry_tag = NULL;
	struct preloaded_file *fp;

	/* This allows to check other file formats from file_formats array. */
	error = EFTYPE;
	if (filename == NULL)
		return (error);

	/* is kernel already loaded? */
	fp = file_findfile(NULL, NULL);
	if (fp != NULL)
		return (error);

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

	if (read(fd, header_search, MULTIBOOT_SEARCH) != MULTIBOOT_SEARCH)
		goto out;

	header = NULL;
	for (i = 0; i <= (MULTIBOOT_SEARCH - sizeof (multiboot2_header_t));
	    i += MULTIBOOT_HEADER_ALIGN) {
		header = (multiboot2_header_t *)(header_search + i);

		/* Do we have match on magic? */
		if (header->mb2_magic != MULTIBOOT2_HEADER_MAGIC) {
			header = NULL;
			continue;
		}
		/*
		 * Validate checksum, the sum of magic + architecture +
		 * header_length + checksum must equal 0.
		 */
		if (header->mb2_magic + header->mb2_architecture +
		    header->mb2_header_length + header->mb2_checksum != 0) {
			header = NULL;
			continue;
		}
		/*
		 * Finally, the entire header must fit within MULTIBOOT_SEARCH.
		 */
		if (i + header->mb2_header_length > MULTIBOOT_SEARCH) {
			header = NULL;
			continue;
		}
		break;
	}

	if (header == NULL)
		goto out;

	for (tag = header->mb2_tags; tag->mbh_type != MULTIBOOT_TAG_TYPE_END;
	    tag = (multiboot_header_tag_t *)((uintptr_t)tag +
	    roundup2(tag->mbh_size, MULTIBOOT_TAG_ALIGN))) {
		switch (tag->mbh_type) {
		case MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST:
			if (is_info_request_valid((void*)tag) == false)
				goto out;
			break;
		case MULTIBOOT_HEADER_TAG_ADDRESS:
			addr_tag = (multiboot_header_tag_address_t *)tag;
			break;
		case MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS:
			entry_tag =
			    (multiboot_header_tag_entry_address_t *)tag;
			break;
		case MULTIBOOT_HEADER_TAG_CONSOLE_FLAGS:
			break;
		case MULTIBOOT_HEADER_TAG_FRAMEBUFFER:
			have_framebuffer = true;
			break;
		case MULTIBOOT_HEADER_TAG_MODULE_ALIGN:
			/* we always align modules */
			break;
		case MULTIBOOT_HEADER_TAG_EFI_BS:
			keep_bs = true;
			break;
		default:
			if (!(tag->mbh_flags & MULTIBOOT_HEADER_TAG_OPTIONAL)) {
				printf("unsupported tag: 0x%x\n",
				    tag->mbh_type);
				goto out;
			}
		}
	}

	/*
	 * We must have addr_tag and entry_tag to load a 64-bit kernel.
	 * If these tags are missing, we either have a 32-bit kernel, or
	 * this is not our kernel at all.
	 */
	if (addr_tag != NULL && entry_tag != NULL) {
		fp = file_alloc();
		if (fp == NULL) {
			error = ENOMEM;
			goto out;
		}
		if (lseek(fd, 0, SEEK_SET) == -1) {
			printf("lseek failed\n");
			error = EIO;
			file_discard(fp);
			goto out;
		}
		if (fstat(fd, &st) < 0) {
			printf("fstat failed\n");
			error = EIO;
			file_discard(fp);
			goto out;
		}

		load_addr = addr_tag->mbh_load_addr;
		entry_addr = entry_tag->mbh_entry_addr;
		fp->f_addr = archsw.arch_loadaddr(LOAD_KERN, filename,
		    addr_tag->mbh_load_addr);
		if (fp->f_addr == 0) {
			error = ENOMEM;
			file_discard(fp);
			goto out;
		}
		fp->f_size = archsw.arch_readin(fd, fp->f_addr, st.st_size);

		if (fp->f_size != st.st_size) {
			printf("error reading: %s", strerror(errno));
			file_discard(fp);
			error = EIO;
			goto out;
		}

		fp->f_name = strdup(filename);
		fp->f_type = strdup("aout multiboot2 kernel");
		if (fp->f_name == NULL || fp->f_type == NULL) {
			error = ENOMEM;
			file_discard(fp);
			goto out;
		}

		fp->f_metadata = NULL;
		error = 0;
	} else {
		/* elf32_loadfile_raw will fill the attributes in fp. */
		error = elf32_loadfile_raw(filename, dest, &fp, 2);
		if (error != 0) {
			printf("elf32_loadfile_raw failed: %d unable to "
			    "load multiboot2 kernel\n", error);
			goto out;
		}
		entry_addr = fp->f_addr;
		/*
		 * We want the load_addr to have some legal value,
		 * so we set it same as the entry_addr.
		 * The distinction is important with UEFI, but not
		 * with BIOS version, because BIOS version does not use
		 * staging area.
		 */
		load_addr = fp->f_addr;
	}

	setenv("kernelname", fp->f_name, 1);
	bios_addsmapdata(fp);
	*result = fp;
out:
	free(header_search);
	close(fd);
	return (error);
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

/*
 * If command line has " -B ", insert property after "-B ", otherwise
 * append to command line.
 */
static char *
insert_cmdline(const char *head, const char *prop)
{
	const char *prop_opt = " -B ";
	char *cmdline, *tail;
	int len = 0;

	tail = strstr(head, prop_opt);
	if (tail != NULL) {
		ptrdiff_t diff;
		tail += strlen(prop_opt);
		diff = tail - head;
		if (diff >= INT_MAX)
			return (NULL);
		len = (int)diff;
	}

	if (tail == NULL)
		asprintf(&cmdline, "%s%s%s", head, prop_opt, prop);
	else
		asprintf(&cmdline, "%.*s%s,%s", len, head, prop, tail);

	return (cmdline);
}

/*
 * Since we have no way to pass the environment to the mb1 kernel other than
 * through arguments, we need to take care of console setup.
 *
 * If the console is in mirror mode, set the kernel console from $os_console.
 * If it's unset, use first item from $console.
 * If $console is "ttyX", also pass $ttyX-mode, since it may have been set by
 * the user.
 *
 * In case of memory allocation errors, just return the original command line
 * so we have a chance of booting.
 *
 * On success, cl will be freed and a new, allocated command line string is
 * returned.
 *
 * For the mb2 kernel, we only set command line console if os_console is set.
 * We can not overwrite console in the environment, as it can disrupt the
 * loader console messages, and we do not want to deal with the os_console
 * in the kernel.
 */
static char *
update_cmdline(char *cl, bool mb2)
{
	char *os_console = getenv("os_console");
	char *ttymode = NULL;
	char mode[10];
	char *tmp;
	const char *prop;
	size_t plen;
	int rv;

	if (mb2 == true && os_console == NULL)
		return (cl);

	if (os_console == NULL) {
		tmp = strdup(getenv("console"));
		os_console = strsep(&tmp, ", ");
	} else {
		os_console = strdup(os_console);
	}

	if (os_console == NULL)
		return (cl);

	if (mb2 == false && strncmp(os_console, "tty", 3) == 0) {
		snprintf(mode, sizeof (mode), "%s-mode", os_console);
		/*
		 * The ttyX-mode variable is set by our serial console
		 * driver for ttya-ttyd. However, since the os_console
		 * values are not verified, it is possible we get bogus
		 * name and no mode variable. If so, we do not set console
		 * property and let the kernel use defaults.
		 */
		if ((ttymode = getenv(mode)) == NULL)
			return (cl);
	}

	rv = find_property_value(cl, "console", &prop, &plen);
	if (rv != 0 && rv != ENOENT) {
		free(os_console);
		return (cl);
	}

	/* If console is set and this is MB2 boot, we are done. */
	if (rv == 0 && mb2 == true) {
		free(os_console);
		return (cl);
	}

	/* If console is set, do we need to set tty mode? */
	if (rv == 0) {
		const char *ttyp = NULL;
		size_t ttylen;

		free(os_console);
		os_console = NULL;
		*mode = '\0';
		if (strncmp(prop, "tty", 3) == 0 && plen == 4) {
			strncpy(mode, prop, plen);
			mode[plen] = '\0';
			strncat(mode, "-mode", 5);
			find_property_value(cl, mode, &ttyp, &ttylen);
		}

		if (*mode != '\0' && ttyp == NULL)
			ttymode = getenv(mode);
		else
			return (cl);
	}

	/* Build updated command line. */
	if (os_console != NULL) {
		char *propstr;

		asprintf(&propstr, "console=%s", os_console);
		free(os_console);
		if (propstr == NULL) {
			return (cl);
		}

		tmp = insert_cmdline(cl, propstr);
                free(propstr);
                if (tmp == NULL)
			return (cl);

                free(cl);
                cl = tmp;
	}
	if (ttymode != NULL) {
		char *propstr;

		asprintf(&propstr, "%s=\"%s\"", mode, ttymode);
		if (propstr == NULL)
			return (cl);

		tmp = insert_cmdline(cl, propstr);
                free(propstr);
                if (tmp == NULL)
			return (cl);
                free(cl);
                cl = tmp;
	}

	return (cl);
}

/*
 * Build the kernel command line. Shared function between MB1 and MB2.
 *
 * In both cases, if fstype is set and is not zfs, we do not set up
 * zfs-bootfs property. But we set kernel file name and options.
 *
 * For the MB1, we only can pass properties on command line, so
 * we will set console, ttyX-mode (for serial console) and zfs-bootfs.
 *
 * For the MB2, we can pass properties in environment, but if os_console
 * is set in environment, we need to add console property on the kernel
 * command line.
 *
 * The console properties are managed in update_cmdline().
 */
int
mb_kernel_cmdline(struct preloaded_file *fp, struct devdesc *rootdev,
    char **line)
{
	const char *fs = getenv("fstype");
	char *cmdline;
	size_t len;
	bool zfs_root = false;
	bool mb2;
	int rv;

	/*
	 * 64-bit kernel has aout header, 32-bit kernel is elf, and the
	 * type strings are different. Lets just search for "multiboot2".
	 */
	if (strstr(fp->f_type, "multiboot2") == NULL)
		mb2 = false;
	else
		mb2 = true;

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
	if (rv != 0 && rv != ENOENT)
		return (rv);

	if (fs != NULL && strncmp(fs, "zfs", len) != 0)
		zfs_root = false;

	/* zfs_bootfs() will set the environment, it must be called. */
	if (zfs_root == true)
		fs = zfs_bootfs(rootdev);

	if (fp->f_args == NULL)
		cmdline = strdup(fp->f_name);
	else
		asprintf(&cmdline, "%s %s", fp->f_name, fp->f_args);

	if (cmdline == NULL)
		return (ENOMEM);

	/* Append zfs-bootfs for MB1 command line. */
	if (mb2 == false && zfs_root == true) {
		char *tmp;

		tmp = insert_cmdline(cmdline, fs);
		free(cmdline);
		if (tmp == NULL)
			return (ENOMEM);
		cmdline = tmp;
	}

	*line = update_cmdline(cmdline, mb2);
	return (0);
}

/*
 * Returns allocated virtual address from MB info area.
 */
static vm_offset_t
mb_malloc(size_t n)
{
	vm_offset_t ptr = last_addr;
	last_addr = roundup(last_addr + n, MULTIBOOT_TAG_ALIGN);
	return (ptr);
}

/*
 * Calculate size for module tag list.
 */
static size_t
module_size(struct preloaded_file *fp)
{
	size_t len, size;
	struct preloaded_file *mfp;

	size = 0;
	for (mfp = fp->f_next; mfp != NULL; mfp = mfp->f_next) {
		len = strlen(mfp->f_name) + 1;
		len += strlen(mfp->f_type) + 5 + 1; /* 5 is for "type=" */
		if (mfp->f_args != NULL)
			len += strlen(mfp->f_args) + 1;
		size += sizeof (multiboot_tag_module_t) + len;
		size = roundup(size, MULTIBOOT_TAG_ALIGN);
	}
	return (size);
}

/*
 * Calculate size for bios smap tag.
 */
static size_t
biossmap_size(struct preloaded_file *fp)
{
	int num;
	struct file_metadata *md;

	md = file_findmetadata(fp, MODINFOMD_SMAP);
	if (md == NULL)
		return (0);

	num = md->md_size / sizeof(struct bios_smap); /* number of entries */
	return (sizeof (multiboot_tag_mmap_t) +
	    num * sizeof (multiboot_mmap_entry_t));
}

static size_t
mbi_size(struct preloaded_file *fp, char *cmdline)
{
	size_t size;

	size = sizeof (uint32_t) * 2; /* first 2 fields from MBI header */
	size += sizeof (multiboot_tag_string_t) + strlen(cmdline) + 1;
	size = roundup2(size, MULTIBOOT_TAG_ALIGN);
	size += sizeof (multiboot_tag_string_t) + strlen(bootprog_info) + 1;
	size = roundup2(size, MULTIBOOT_TAG_ALIGN);
	size += sizeof (multiboot_tag_basic_meminfo_t);
	size = roundup2(size, MULTIBOOT_TAG_ALIGN);
	size += module_size(fp);
	size = roundup2(size, MULTIBOOT_TAG_ALIGN);
	size += biossmap_size(fp);
	size = roundup2(size, MULTIBOOT_TAG_ALIGN);

	if (strstr(getenv("loaddev"), "pxe") != NULL) {
		size += sizeof(multiboot_tag_network_t) + sizeof (BOOTPLAYER);
		size = roundup2(size, MULTIBOOT_TAG_ALIGN);
	}

	if (rsdp != NULL) {
		if (rsdp->Revision == 0) {
			size += sizeof (multiboot_tag_old_acpi_t) +
			    sizeof(ACPI_RSDP_COMMON);
		} else {
			size += sizeof (multiboot_tag_new_acpi_t) +
			    rsdp->Length;
		}
		size = roundup2(size, MULTIBOOT_TAG_ALIGN);
	}
	size += sizeof(multiboot_tag_t);

	return (size);
}

static int
multiboot2_exec(struct preloaded_file *fp)
{
	struct preloaded_file *mfp;
	multiboot2_info_header_t *mbi;
	char *cmdline = NULL;
	struct devdesc *rootdev;
	struct file_metadata *md;
	int i, error, num;
	int rootfs = 0;
	size_t size;
	struct bios_smap *smap;
	vm_offset_t tmp;
	i386_getdev((void **)(&rootdev), NULL, NULL);

	error = EINVAL;
	if (rootdev == NULL) {
		printf("can't determine root device\n");
		goto error;
	}

	/*
	 * Set the image command line.
	 */
	if (fp->f_args == NULL) {
		cmdline = getenv("boot-args");
		if (cmdline != NULL) {
			fp->f_args = strdup(cmdline);
			if (fp->f_args == NULL) {
				error = ENOMEM;
				goto error;
			}
		}
	}

	error = mb_kernel_cmdline(fp, rootdev, &cmdline);
	if (error != 0)
		goto error;

	/* mb_kernel_cmdline() updates the environment. */
	build_environment_module();

	size = mbi_size(fp, cmdline);	/* Get the size for MBI. */

	/* Set up the base for mb_malloc. */
	for (mfp = fp; mfp->f_next != NULL; mfp = mfp->f_next);

	/* Start info block from the new page. */
	last_addr = roundup(mfp->f_addr + mfp->f_size, MULTIBOOT_MOD_ALIGN);

	/* Do we have space for multiboot info? */
	if (last_addr + size >= memtop_copyin) {
		error = ENOMEM;
		goto error;
	}

	mbi = (multiboot2_info_header_t *)PTOV(last_addr);
	last_addr = (vm_offset_t)mbi->mbi_tags;

	{
		multiboot_tag_string_t *tag;
		i = sizeof (multiboot_tag_string_t) + strlen(cmdline) + 1;
		tag = (multiboot_tag_string_t *) mb_malloc(i);

		tag->mb_type = MULTIBOOT_TAG_TYPE_CMDLINE;
		tag->mb_size = i;
		memcpy(tag->mb_string, cmdline, strlen(cmdline) + 1);
		free(cmdline);
		cmdline = NULL;
	}

	{
		multiboot_tag_string_t *tag;
		i = sizeof (multiboot_tag_string_t) + strlen(bootprog_info) + 1;
		tag = (multiboot_tag_string_t *) mb_malloc(i);

		tag->mb_type = MULTIBOOT_TAG_TYPE_BOOT_LOADER_NAME;
		tag->mb_size = i;
		memcpy(tag->mb_string, bootprog_info,
		    strlen(bootprog_info) + 1);
	}

	{
		multiboot_tag_basic_meminfo_t *tag;
		tag = (multiboot_tag_basic_meminfo_t *)
		    mb_malloc(sizeof (*tag));

		tag->mb_type = MULTIBOOT_TAG_TYPE_BASIC_MEMINFO;
		tag->mb_size = sizeof (*tag);
		tag->mb_mem_lower = bios_basemem / 1024;
		tag->mb_mem_upper = bios_extmem / 1024;
	}

	num = 0;
	for (mfp = fp->f_next; mfp != NULL; mfp = mfp->f_next) {
		num++;
		if (mfp->f_type != NULL && strcmp(mfp->f_type, "rootfs") == 0)
			rootfs++;
	}

	if (num == 0 || rootfs == 0) {
		/* We need at least one module - rootfs. */
		printf("No rootfs module provided, aborting\n");
		error = EINVAL;
		goto error;
	}

	/*
	 * Set the stage for physical memory layout:
	 * - We have kernel at load_addr.
	 * - Modules are aligned to page boundary.
	 * - MBI is aligned to page boundary.
	 * - Set the tmp to point to physical address of the first module.
	 */
	tmp = roundup2(load_addr + fp->f_size, MULTIBOOT_MOD_ALIGN);

	for (mfp = fp->f_next; mfp != NULL; mfp = mfp->f_next) {
		multiboot_tag_module_t *tag;

		num = strlen(mfp->f_name) + 1;
		num += strlen(mfp->f_type) + 5 + 1;
		if (mfp->f_args != NULL) {
			num += strlen(mfp->f_args) + 1;
		}
		cmdline = malloc(num);
		if (cmdline == NULL) {
			error = ENOMEM;
			goto error;
		}

		if (mfp->f_args != NULL)
			snprintf(cmdline, num, "%s type=%s %s",
			    mfp->f_name, mfp->f_type, mfp->f_args);
		else
			snprintf(cmdline, num, "%s type=%s",
			    mfp->f_name, mfp->f_type);

		tag = (multiboot_tag_module_t *)mb_malloc(sizeof (*tag) + num);

		tag->mb_type = MULTIBOOT_TAG_TYPE_MODULE;
		tag->mb_size = sizeof (*tag) + num;
		tag->mb_mod_start = tmp;
		tag->mb_mod_end = tmp + mfp->f_size;
		tmp = roundup2(tag->mb_mod_end, MULTIBOOT_MOD_ALIGN);
		memcpy(tag->mb_cmdline, cmdline, num);
		free(cmdline);
		cmdline = NULL;
	}

	md = file_findmetadata(fp, MODINFOMD_SMAP);
	if (md == NULL) {
		printf("no memory smap\n");
		error = EINVAL;
		goto error;
	}

	smap = (struct bios_smap *)md->md_data;
	num = md->md_size / sizeof(struct bios_smap); /* number of entries */

	{
		multiboot_tag_mmap_t *tag;
		multiboot_mmap_entry_t *mmap_entry;

		tag = (multiboot_tag_mmap_t *)
		    mb_malloc(sizeof (*tag) +
		    num * sizeof (multiboot_mmap_entry_t));

		tag->mb_type = MULTIBOOT_TAG_TYPE_MMAP;
		tag->mb_size = sizeof (*tag) +
		    num * sizeof (multiboot_mmap_entry_t);
		tag->mb_entry_size = sizeof (multiboot_mmap_entry_t);
		tag->mb_entry_version = 0;
		mmap_entry = (multiboot_mmap_entry_t *)tag->mb_entries;

		for (i = 0; i < num; i++) {
			mmap_entry[i].mmap_addr = smap[i].base;
			mmap_entry[i].mmap_len = smap[i].length;
			mmap_entry[i].mmap_type = smap[i].type;
			mmap_entry[i].mmap_reserved = 0;
		}
	}

	if (strstr(getenv("loaddev"), "pxe") != NULL) {
		multiboot_tag_network_t *tag;
		tag = (multiboot_tag_network_t *)
		    mb_malloc(sizeof(*tag) + sizeof (BOOTPLAYER));

		tag->mb_type = MULTIBOOT_TAG_TYPE_NETWORK;
		tag->mb_size = sizeof(*tag) + sizeof (BOOTPLAYER);
		memcpy(tag->mb_dhcpack, &bootplayer, sizeof (BOOTPLAYER));
	}

	if (rsdp != NULL) {
		multiboot_tag_new_acpi_t *ntag;
		multiboot_tag_old_acpi_t *otag;
		uint32_t tsize;

		if (rsdp->Revision == 0) {
			tsize = sizeof (*otag) + sizeof (ACPI_RSDP_COMMON);
			otag = (multiboot_tag_old_acpi_t *)mb_malloc(tsize);
			otag->mb_type = MULTIBOOT_TAG_TYPE_ACPI_OLD;
			otag->mb_size = tsize;
			memcpy(otag->mb_rsdp, rsdp, sizeof (ACPI_RSDP_COMMON));
		} else {
			tsize = sizeof (*ntag) + rsdp->Length;
			ntag = (multiboot_tag_new_acpi_t *)mb_malloc(tsize);
			ntag->mb_type = MULTIBOOT_TAG_TYPE_ACPI_NEW;
			ntag->mb_size = tsize;
			memcpy(ntag->mb_rsdp, rsdp, rsdp->Length);
		}
	}

	/*
	 * MB tag list end marker.
	 */
	{
		multiboot_tag_t *tag = (multiboot_tag_t *)
		    mb_malloc(sizeof(*tag));
		tag->mb_type = MULTIBOOT_TAG_TYPE_END;
		tag->mb_size = sizeof(*tag);
	}

	mbi->mbi_total_size = last_addr - (vm_offset_t)mbi;
	mbi->mbi_reserved = 0;

	dev_cleanup();
	__exec((void *)VTOP(multiboot_tramp), MULTIBOOT2_BOOTLOADER_MAGIC,
	    (void *)entry_addr, (void *)VTOP(mbi));
	panic("exec returned");

error:
	if (cmdline != NULL)
		free(cmdline);
	return (error);
}
