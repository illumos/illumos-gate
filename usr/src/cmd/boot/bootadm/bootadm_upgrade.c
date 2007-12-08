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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>
#include <strings.h>

#include <sys/mman.h>
#include <sys/elf.h>
#include <sys/multiboot.h>

#include "message.h"
#include "bootadm.h"

direct_or_multi_t bam_direct = BAM_DIRECT_NOT_SET;
hv_t bam_is_hv = BAM_HV_UNKNOWN;

error_t
dboot_or_multiboot(const char *root)
{
	char fname[PATH_MAX];
	char *image;
	uchar_t *ident;
	int fd, m;
	multiboot_header_t *mbh;
	struct stat sb;

	if (!is_grub(root)) {
		/* there is no non dboot sparc new-boot */
		bam_direct = BAM_DIRECT_DBOOT;
		return (BAM_SUCCESS);
	}

	(void) snprintf(fname, PATH_MAX, "%s/%s", root,
	    "platform/i86pc/kernel/unix");
	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		bam_error(OPEN_FAIL, fname, strerror(errno));
		return (BAM_ERROR);
	}

	/*
	 * mmap the first 8K
	 */
	image = mmap(NULL, 8192, PROT_READ, MAP_SHARED, fd, 0);
	if (image == MAP_FAILED) {
		bam_error(MMAP_FAIL, fname, strerror(errno));
		return (BAM_ERROR);
	}

	ident = (uchar_t *)image;
	if (ident[EI_MAG0] != ELFMAG0 || ident[EI_MAG1] != ELFMAG1 ||
	    ident[EI_MAG2] != ELFMAG2 || ident[EI_MAG3] != ELFMAG3) {
		bam_error(NOT_ELF_FILE, fname);
		return (BAM_ERROR);
	}
	if (ident[EI_CLASS] != ELFCLASS32) {
		bam_error(WRONG_ELF_CLASS, fname, ident[EI_CLASS]);
		return (BAM_ERROR);
	}

	/*
	 * The GRUB multiboot header must be 32-bit aligned and completely
	 * contained in the 1st 8K of the file.  If the unix binary has
	 * a multiboot header, then it is a 'dboot' kernel.  Otherwise,
	 * this kernel must be booted via multiboot -- we call this a
	 * 'multiboot' kernel.
	 */
	bam_direct = BAM_DIRECT_MULTIBOOT;
	for (m = 0; m < 8192 - sizeof (multiboot_header_t); m += 4) {
		mbh = (void *)(image + m);
		if (mbh->magic == MB_HEADER_MAGIC) {
			bam_direct = BAM_DIRECT_DBOOT;
			break;
		}
	}
	(void) munmap(image, 8192);
	(void) close(fd);

	if (bam_direct == BAM_DIRECT_DBOOT) {
		(void) snprintf(fname, PATH_MAX, "%s/%s", root, XEN_32);
		if (stat(fname, &sb) == 0) {
			bam_is_hv = BAM_HV_PRESENT;
		} else {
			bam_is_hv = BAM_HV_NO;
		}
	}

	return (BAM_SUCCESS);
}

#define	INST_RELEASE	"var/sadm/system/admin/INST_RELEASE"

/*
 * Return true if root has been bfu'ed.  bfu will blow away
 * var/sadm/system/admin/INST_RELEASE, so if it's still there, we can
 * assume the system has not been bfu'ed.
 */
static int
is_bfu_system(const char *root)
{
	static int is_bfu = -1;
	char path[PATH_MAX];
	struct stat sb;

	if (is_bfu != -1)
		return (is_bfu);

	(void) snprintf(path, sizeof (path), "%s/%s", root, INST_RELEASE);
	if (stat(path, &sb) != 0) {
		is_bfu = 1;
	} else {
		is_bfu = 0;
	}
	return (is_bfu);
}

#define	MENU_URL(root)	(is_bfu_system(root) ?		\
	"http://www.sun.com/msg/SUNOS-8000-CF" :	\
	"http://www.sun.com/msg/SUNOS-8000-AK")

/*
 * Simply allocate a new line and copy in cmd + sep + arg
 */
void
update_line(line_t *linep)
{
	size_t size;

	free(linep->line);
	size = strlen(linep->cmd) + strlen(linep->sep) + strlen(linep->arg) + 1;
	linep->line = s_calloc(1, size);
	(void) snprintf(linep->line, size, "%s%s%s", linep->cmd, linep->sep,
	    linep->arg);
}

/*
 * The parse_kernel_line function examines a menu.lst kernel line.  For
 * multiboot, this is:
 *
 * kernel <multiboot path> <flags1> <kernel path> <flags2>
 *
 * <multiboot path> is either /platform/i86pc/multiboot or /boot/multiboot
 *
 * <kernel path> may be missing, or may be any full or relative path to unix.
 *	We check for it by looking for a word ending in "/unix".  If it ends
 *	in "kernel/unix", we upgrade it to a 32-bit entry.  If it ends in
 *	"kernel/amd64/unix", we upgrade it to the default entry.  Otherwise,
 *	it's a custom kernel, and we skip it.
 *
 * <flags*> are anything that doesn't fit either of the above - these will be
 *	copied over.
 *
 * For direct boot, the defaults are
 *
 * kernel$ <kernel path> <flags>
 *
 * <kernel path> is one of:
 *	/platform/i86pc/kernel/$ISADIR/unix
 *	/platform/i86pc/kernel/unix
 *	/platform/i86pc/kernel/amd64/unix
 *	/boot/platform/i86pc/kernel/unix
 *
 * If <kernel path> is any of the last three, the command may also be "kernel".
 *
 * <flags> is anything that isn't <kernel path>.
 *
 * This function is only called if it applies to our target boot environment.
 * If we can't make any sense of the kernel line, an error is printed and
 * BAM_ERROR is returned.
 *
 * The desired install type is given in the global variable bam_direct.
 * If the kernel line is of a different install type, we change it to the
 * preferred type.  If the kernel line is already of the correct install
 * type, we do nothing.  Either way, BAM_SUCCESS is returned.
 *
 * For safety, we do one more check: if the kernel path starts with /boot,
 * we verify that the new kernel exists before changing it.  This is mainly
 * done for bfu, as it may cause the failsafe archives to be a different
 * boot architecture from the newly bfu'ed system.
 */
static error_t
parse_kernel_line(line_t *linep, const char *root, uint8_t *flags)
{
	char path[PATH_MAX];
	int len, left, total_len;
	struct stat sb;
	char *new_ptr, *new_arg, *old_ptr;
	menu_cmd_t which;

	/* Used when changing a multiboot line to dboot */
	char *unix_ptr, *flags1_ptr, *flags2_ptr;

	/*
	 * Note that BAM_ENTRY_DBOOT refers to the entry we're looking at, not
	 * necessarily the system type.
	 */
	if (strncmp(linep->arg, DIRECT_BOOT_32,
	    sizeof (DIRECT_BOOT_32) - 1) == 0) {
		*flags |= BAM_ENTRY_DBOOT | BAM_ENTRY_32BIT;
	} else if ((strncmp(linep->arg, DIRECT_BOOT_KERNEL,
	    sizeof (DIRECT_BOOT_KERNEL) - 1) == 0) ||
	    (strncmp(linep->arg, DIRECT_BOOT_64,
	    sizeof (DIRECT_BOOT_64) - 1) == 0) ||
	    (strncmp(linep->arg, DIRECT_BOOT_FAILSAFE_KERNEL,
	    sizeof (DIRECT_BOOT_FAILSAFE_KERNEL) - 1) == 0)) {
		*flags |= BAM_ENTRY_DBOOT;
	} else if ((strncmp(linep->arg, MULTI_BOOT,
	    sizeof (MULTI_BOOT) - 1) == 0) ||
	    (strncmp(linep->arg, MULTI_BOOT_FAILSAFE,
	    sizeof (MULTI_BOOT_FAILSAFE) - 1) == 0)) {
		*flags &= ~BAM_ENTRY_DBOOT;
	} else {
		bam_error(NO_KERNEL_MATCH, linep->lineNum, MENU_URL(root));
		return (BAM_ERROR);
	}

	if (((*flags & BAM_ENTRY_DBOOT) && (bam_direct == BAM_DIRECT_DBOOT)) ||
	    (((*flags & BAM_ENTRY_DBOOT) == 0) &&
	    (bam_direct == BAM_DIRECT_MULTIBOOT))) {

		/* No action needed */
		return (BAM_SUCCESS);
	}

	if (*flags & BAM_ENTRY_MINIROOT) {
		/*
		 * We're changing boot architectures - make sure
		 * the multiboot failsafe still exists.
		 */
		(void) snprintf(path, PATH_MAX, "%s%s", root,
		    (*flags & BAM_ENTRY_DBOOT) ? MULTI_BOOT_FAILSAFE :
		    DIRECT_BOOT_FAILSAFE_KERNEL);
		if (stat(path, &sb) != 0) {
			if (bam_verbose) {
				bam_error(FAILSAFE_MISSING, linep->lineNum);
			}
			return (BAM_SUCCESS);
		}
	}

	/*
	 * Make sure we have the correct cmd - either kernel or kernel$
	 * The failsafe entry should always be KERNEL_CMD.
	 */
	which = ((bam_direct == BAM_DIRECT_MULTIBOOT) ||
	    (*flags & BAM_ENTRY_MINIROOT)) ? KERNEL_CMD : KERNEL_DOLLAR_CMD;
	free(linep->cmd);
	len = strlen(menu_cmds[which]) + 1;
	linep->cmd = s_calloc(1, len);
	(void) strncpy(linep->cmd, menu_cmds[which], len);

	/*
	 * Since all arguments are copied, the new arg string should be close
	 * in size to the old one.  Just add 32 to cover the difference in
	 * the boot path.
	 */
	total_len = strlen(linep->arg) + 32;
	new_arg = s_calloc(1, total_len);
	old_ptr = strchr(linep->arg, ' ');
	if (old_ptr != NULL)
		old_ptr++;

	/*
	 * Transitioning from dboot to multiboot is pretty simple.  We
	 * copy in multiboot and any args.
	 */
	if (bam_direct == BAM_DIRECT_MULTIBOOT) {
		if (old_ptr == NULL) {
			(void) snprintf(new_arg, total_len, "%s",
			    (*flags & BAM_ENTRY_MINIROOT) ?
			    MULTI_BOOT_FAILSAFE : MULTI_BOOT);
		} else {
			(void) snprintf(new_arg, total_len, "%s %s",
			    (*flags & BAM_ENTRY_MINIROOT) ?
			    MULTI_BOOT_FAILSAFE : MULTI_BOOT, old_ptr);
		}
		goto done;
	}

	/*
	 * Transitioning from multiboot to directboot is a bit more
	 * complicated, since we may have two sets of arguments to
	 * copy and a unix path to parse.
	 *
	 * First, figure out if there's a unix path.
	 */
	if ((old_ptr != NULL) &&
	    ((unix_ptr = strstr(old_ptr, "/unix")) != NULL)) {
		/* See if there's anything past unix */
		flags2_ptr = unix_ptr + sizeof ("/unix");
		if (*flags2_ptr == '\0') {
			flags2_ptr = NULL;
		}

		while ((unix_ptr > old_ptr) && (*unix_ptr != ' '))
			unix_ptr--;

		if (unix_ptr == old_ptr) {
			flags1_ptr = NULL;
		} else {
			flags1_ptr = old_ptr;
		}

		if (strstr(unix_ptr, "kernel/unix") != NULL) {
			*flags |= BAM_ENTRY_32BIT;
		} else if ((strstr(unix_ptr, "kernel/amd64/unix") == NULL) &&
		    (!bam_force)) {
			/*
			 * If the above strstr returns NULL, but bam_force is
			 * set, we'll be upgrading an Install kernel.  The
			 * result probably won't be what was intended, but we'll
			 * try it anyways.
			 */
			return (BAM_SKIP);
		}
	} else if (old_ptr != NULL) {
		flags1_ptr = old_ptr;
		unix_ptr = flags1_ptr + strlen(old_ptr);
		flags2_ptr = NULL;
	} else {
		unix_ptr = flags1_ptr = flags2_ptr = NULL;
	}

	if (*flags & BAM_ENTRY_MINIROOT) {
		(void) snprintf(new_arg, total_len, "%s",
		    DIRECT_BOOT_FAILSAFE_KERNEL);
	} else if (*flags & BAM_ENTRY_32BIT) {
		(void) snprintf(new_arg, total_len, "%s", DIRECT_BOOT_32);
	} else {
		(void) snprintf(new_arg, total_len, "%s", DIRECT_BOOT_KERNEL);
	}

	/*
	 * We now want to copy flags1_ptr through unix_ptr, and
	 * flags2_ptr through the end of the string
	 */
	if (flags1_ptr != NULL) {
		len = strlcat(new_arg, " ", total_len);
		left = total_len - len;
		new_ptr = new_arg + len;

		if ((unix_ptr - flags1_ptr) < left)
			left = (unix_ptr - flags1_ptr) + 1;
		(void) strlcpy(new_ptr, flags1_ptr, left);
	}
	if (flags2_ptr != NULL) {
		(void) strlcat(new_arg, " ", total_len);
		(void) strlcat(new_arg, flags2_ptr, total_len);
	}

done:
	free(linep->arg);
	linep->arg = new_arg;
	update_line(linep);
	return (BAM_SUCCESS);
}

/*
 * Similar to above, except this time we're looking at a module line,
 * which is quite a bit simpler.
 *
 * Under multiboot, the archive line is:
 *
 * module /platform/i86pc/boot_archive
 *
 * Under directboot, the archive line is:
 *
 * module$ /platform/i86pc/$ISADIR/boot_archive
 *
 * which may be specified exactly as either of:
 *
 * module /platform/i86pc/boot_archive
 * module /platform/i86pc/amd64/boot_archive
 *
 * For either dboot or multiboot, the failsafe is:
 *
 * module /boot/x86.miniroot-safe
 */
static error_t
parse_module_line(line_t *linep, const char *root, uint8_t flags)
{
	int len;
	menu_cmd_t which;
	char *new;

	/*
	 * If necessary, BAM_ENTRY_MINIROOT was already set in flags
	 * in upgrade_menu().  We re-check BAM_ENTRY_DBOOT here in here
	 * in case the kernel and module lines differ.
	 */
	if ((strcmp(linep->arg, DIRECT_BOOT_ARCHIVE) == 0) ||
	    (strcmp(linep->arg, DIRECT_BOOT_ARCHIVE_64) == 0)) {
		flags |= BAM_ENTRY_DBOOT;
	} else if ((strcmp(linep->arg, MULTI_BOOT_ARCHIVE) == 0) ||
	    (strcmp(linep->arg, MINIROOT) == 0)) {
		flags &= ~BAM_ENTRY_DBOOT;
	} else {
		bam_error(NO_MODULE_MATCH, linep->lineNum, MENU_URL(root));
		return (BAM_ERROR);
	}

	if (((flags & BAM_ENTRY_DBOOT) && (bam_direct == BAM_DIRECT_DBOOT)) ||
	    (((flags & BAM_ENTRY_DBOOT) == 0) &&
	    (bam_direct == BAM_DIRECT_MULTIBOOT)) ||
	    ((flags & BAM_ENTRY_MINIROOT) &&
	    (strcmp(linep->cmd, menu_cmds[MODULE_CMD]) == 0))) {

		/* No action needed */
		return (BAM_SUCCESS);
	}

	/*
	 * Make sure we have the correct cmd - either module or module$
	 * The failsafe entry should always be MODULE_CMD.
	 */
	which = ((bam_direct == BAM_DIRECT_MULTIBOOT) ||
	    (flags & BAM_ENTRY_MINIROOT)) ? MODULE_CMD : MODULE_DOLLAR_CMD;
	free(linep->cmd);
	len = strlen(menu_cmds[which]) + 1;
	linep->cmd = s_calloc(1, len);
	(void) strncpy(linep->cmd, menu_cmds[which], len);

	if (flags & BAM_ENTRY_MINIROOT) {
		new = MINIROOT;
	} else if ((bam_direct == BAM_DIRECT_DBOOT) &&
	    ((flags & BAM_ENTRY_32BIT) == 0)) {
		new = DIRECT_BOOT_ARCHIVE;
	} else {
		new = MULTI_BOOT_ARCHIVE;
	}

	free(linep->arg);
	len = strlen(new) + 1;
	linep->arg = s_calloc(1, len);
	(void) strncpy(linep->arg, new, len);
	update_line(linep);

	return (BAM_SUCCESS);
}

/*ARGSUSED*/
error_t
upgrade_menu(menu_t *mp, char *root, char *opt)
{
	entry_t	*cur_entry;
	line_t	*cur_line;
	int	i, skipit, num_entries, found_hv;
	int	*hand_entries = NULL;
	boolean_t found_kernel = B_FALSE;
	error_t	rv;
	char	*rootdev, *grubdisk = NULL;

	skipit = num_entries = found_hv = 0;

	rootdev = get_special(root);
	if (rootdev) {
		grubdisk = os_to_grubdisk(rootdev, strlen(root) == 1);
		free(rootdev);
		rootdev = NULL;
	}

	/* Loop through all OS entries in the menu.lst file */
	for (cur_entry = mp->entries; cur_entry != NULL;
	    cur_entry = cur_entry->next, skipit = 0) {

		if ((cur_entry->flags & BAM_ENTRY_CHAINLOADER) ||
		    ((cur_entry->flags & BAM_ENTRY_MINIROOT) && !bam_force))
			continue;

		/*
		 * We only change entries added by bootadm and live upgrade,
		 * and warn on the rest, unless the -f flag was passed.
		 */
		if ((!(cur_entry->flags & (BAM_ENTRY_BOOTADM|BAM_ENTRY_LU))) &&
		    !bam_force) {
			if (num_entries == 0) {
				hand_entries = s_calloc(1, sizeof (int));
			} else {
				hand_entries = s_realloc(hand_entries,
				    (num_entries + 1) * sizeof (int));
			}
			hand_entries[num_entries++] = cur_entry->entryNum;
			continue;
		}

		if (cur_entry->flags & BAM_ENTRY_HV) {
			found_hv = 1;
			continue;
		}

		/*
		 * We make two loops through the lines.  First, we check if
		 * there is a root entry, and if so, whether we should be
		 * checking this entry.
		 */
		if ((grubdisk != NULL) && (cur_entry->flags & BAM_ENTRY_ROOT)) {
			for (cur_line = cur_entry->start; cur_line != NULL;
			    cur_line = cur_line->next) {
				if ((cur_line->cmd == NULL) ||
				    (cur_line->arg == NULL))
					continue;

				if (strcmp(cur_line->cmd,
				    menu_cmds[ROOT_CMD]) == 0) {
					if (strcmp(cur_line->arg,
					    grubdisk) != 0) {
						/* A different slice */
						skipit = 1;
					}
					break;
				}
				if (cur_line == cur_entry->end)
					break;
			}
		}
		if (skipit)
			continue;

		for (cur_line = cur_entry->start; cur_line != NULL;
		    cur_line = cur_line->next) {

			/*
			 * We only compare for the length of KERNEL_CMD,
			 * so that KERNEL_DOLLAR_CMD will also match.
			 */
			if (strncmp(cur_line->cmd, menu_cmds[KERNEL_CMD],
			    strlen(menu_cmds[KERNEL_CMD])) == 0) {
				rv = parse_kernel_line(cur_line, root,
				    &(cur_entry->flags));
				if (rv == BAM_SKIP) {
					break;
				} else if (rv != BAM_SUCCESS) {
					return (rv);
				}
				found_kernel = B_TRUE;
			} else if (strncmp(cur_line->cmd,
			    menu_cmds[MODULE_CMD],
			    strlen(menu_cmds[MODULE_CMD])) == 0) {
				rv = parse_module_line(cur_line, root,
				    cur_entry->flags);
				if (rv != BAM_SUCCESS) {
					return (rv);
				}
			}
			if (cur_line == cur_entry->end)
				break;
		}
	}

	/*
	 * If we're upgrading to a virtualized kernel and there are no
	 * hv entries in menu.lst, we need to add one.
	 */
	if ((bam_is_hv == BAM_HV_PRESENT) && (found_hv == 0)) {
		(void) add_boot_entry(mp, NEW_HV_ENTRY, grubdisk,
		    XEN_MENU, KERNEL_MODULE_LINE, DIRECT_BOOT_ARCHIVE);
	}

	/*
	 * We only want to output one error, to avoid confusing a user.  We
	 * rank "No kernels changed" as a higher priority than "will not
	 * update hand-added entries", since the former implies the latter.
	 */
	if (found_kernel == B_FALSE) {
		bam_error(NO_KERNELS_FOUND, MENU_URL(root));
		return (BAM_ERROR);
	} else if (num_entries > 0) {
		bam_error(HAND_ADDED_ENTRY, MENU_URL(root));
		bam_print_stderr("Entry Number%s: ", (num_entries > 1) ?
		    "s" : "");
		for (i = 0; i < num_entries; i++) {
			bam_print_stderr("%d ", hand_entries[i]);
		}
		bam_print_stderr("\n");
	}
	return (BAM_WRITE);
}
