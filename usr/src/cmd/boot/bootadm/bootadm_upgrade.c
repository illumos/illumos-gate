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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

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

#include "bootadm.h"

direct_or_multi_t bam_direct = BAM_DIRECT_NOT_SET;
hv_t bam_is_hv = BAM_HV_UNKNOWN;
findroot_t bam_is_findroot = BAM_FINDROOT_UNKNOWN;

static void
get_findroot_cap(const char *osroot)
{
	FILE		*fp;
	char		path[PATH_MAX];
	char		buf[BAM_MAXLINE];
	struct stat	sb;
	int		dboot;
	int		error;
	int		ret;
	const char	*fcn = "get_findroot_cap()";

	(void) snprintf(path, sizeof (path), "%s/%s",
	    osroot, "boot/grub/capability");

	if (stat(path, &sb) == -1) {
		bam_is_findroot = BAM_FINDROOT_ABSENT;
		BAM_DPRINTF(("%s: findroot capability absent\n", fcn));
		return;
	}

	fp = fopen(path, "r");
	error = errno;
	INJECT_ERROR1("GET_CAP_FINDROOT_FOPEN", fp = NULL);
	if (fp == NULL) {
		bam_error(_("failed to open file: %s: %s\n"), path,
		    strerror(error));
		return;
	}

	dboot = 0;
	while (s_fgets(buf, sizeof (buf), fp) != NULL) {
		if (strcmp(buf, "findroot") == 0) {
			BAM_DPRINTF(("%s: findroot capability present\n", fcn));
			bam_is_findroot = BAM_FINDROOT_PRESENT;
		}
		if (strcmp(buf, "dboot") == 0) {
			BAM_DPRINTF(("%s: dboot capability present\n", fcn));
			dboot = 1;
		}
	}

	assert(dboot);

	if (bam_is_findroot == BAM_FINDROOT_UNKNOWN) {
		bam_is_findroot = BAM_FINDROOT_ABSENT;
		BAM_DPRINTF(("%s: findroot capability absent\n", fcn));
	}

	ret = fclose(fp);
	error = errno;
	INJECT_ERROR1("GET_CAP_FINDROOT_FCLOSE", ret = 1);
	if (ret != 0) {
		bam_error(_("failed to close file: %s: %s\n"),
		    path, strerror(error));
	}
}

error_t
get_boot_cap(const char *osroot)
{
	char		fname[PATH_MAX];
	char		*image;
	uchar_t		*ident;
	int		fd;
	int		m;
	multiboot_header_t *mbh;
	struct stat	sb;
	int		error;
	const char	*fcn = "get_boot_cap()";

	if (is_sparc()) {
		/* there is no non dboot sparc new-boot */
		bam_direct = BAM_DIRECT_DBOOT;
		BAM_DPRINTF(("%s: is sparc - always DBOOT\n", fcn));
		return (BAM_SUCCESS);
	}

	(void) snprintf(fname, PATH_MAX, "%s/%s", osroot,
	    "platform/i86pc/kernel/unix");
	fd = open(fname, O_RDONLY);
	error = errno;
	INJECT_ERROR1("GET_CAP_UNIX_OPEN", fd = -1);
	if (fd < 0) {
		bam_error(_("failed to open file: %s: %s\n"), fname,
		    strerror(error));
		return (BAM_ERROR);
	}

	/*
	 * Verify that this is a sane unix at least 8192 bytes in length
	 */
	if (fstat(fd, &sb) == -1 || sb.st_size < 8192) {
		(void) close(fd);
		bam_error(_("invalid or corrupted binary: %s\n"), fname);
		return (BAM_ERROR);
	}

	/*
	 * mmap the first 8K
	 */
	image = mmap(NULL, 8192, PROT_READ, MAP_SHARED, fd, 0);
	error = errno;
	INJECT_ERROR1("GET_CAP_MMAP", image = MAP_FAILED);
	if (image == MAP_FAILED) {
		bam_error(_("failed to mmap file: %s: %s\n"), fname,
		    strerror(error));
		return (BAM_ERROR);
	}

	ident = (uchar_t *)image;
	if (ident[EI_MAG0] != ELFMAG0 || ident[EI_MAG1] != ELFMAG1 ||
	    ident[EI_MAG2] != ELFMAG2 || ident[EI_MAG3] != ELFMAG3) {
		bam_error(_("%s is not an ELF file.\n"), fname);
		return (BAM_ERROR);
	}
	if (ident[EI_CLASS] != ELFCLASS32) {
		bam_error(_("%s is wrong ELF class 0x%x\n"), fname,
		    ident[EI_CLASS]);
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
			BAM_DPRINTF(("%s: is DBOOT unix\n", fcn));
			bam_direct = BAM_DIRECT_DBOOT;
			break;
		}
	}
	(void) munmap(image, 8192);
	(void) close(fd);

	INJECT_ERROR1("GET_CAP_MULTIBOOT", bam_direct = BAM_DIRECT_MULTIBOOT);
	if (bam_direct == BAM_DIRECT_DBOOT) {
		if (bam_is_hv == BAM_HV_PRESENT) {
			BAM_DPRINTF(("%s: is xVM system\n", fcn));
		} else {
			BAM_DPRINTF(("%s: is *NOT* xVM system\n", fcn));
		}
	} else {
		BAM_DPRINTF(("%s: is MULTIBOOT unix\n", fcn));
	}

	/* Not a fatal error if this fails */
	get_findroot_cap(osroot);

	BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
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
	static int		is_bfu = -1;
	char			path[PATH_MAX];
	struct stat		sb;
	const char		*fcn = "is_bfu_system()";

	if (is_bfu != -1) {
		BAM_DPRINTF(("%s: already done bfu test. bfu is %s present\n",
		    fcn, is_bfu ? "" : "NOT"));
		return (is_bfu);
	}

	(void) snprintf(path, sizeof (path), "%s/%s", root, INST_RELEASE);
	if (stat(path, &sb) != 0) {
		is_bfu = 1;
		BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
	} else {
		is_bfu = 0;
		BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
	}
	return (is_bfu);
}

#define	MENU_URL(root)	(is_bfu_system(root) ?		\
	"http://illumos.org/msg/SUNOS-8000-CF" :	\
	"http://illumos.org/msg/SUNOS-8000-AK")

/*
 * Simply allocate a new line and copy in cmd + sep + arg
 */
void
update_line(line_t *linep)
{
	size_t		size;
	const char	*fcn = "update_line()";

	BAM_DPRINTF(("%s: line before update: %s\n", fcn, linep->line));
	free(linep->line);
	size = strlen(linep->cmd) + strlen(linep->sep) + strlen(linep->arg) + 1;
	linep->line = s_calloc(1, size);
	(void) snprintf(linep->line, size, "%s%s%s", linep->cmd, linep->sep,
	    linep->arg);
	BAM_DPRINTF(("%s: line after update: %s\n", fcn, linep->line));
}

static char *
skip_wspace(char *ptr)
{
	const char		*fcn = "skip_wspace()";

	INJECT_ERROR1("SKIP_WSPACE", ptr = NULL);
	if (ptr == NULL) {
		BAM_DPRINTF(("%s: NULL ptr\n", fcn));
		return (NULL);
	}

	BAM_DPRINTF(("%s: ptr on entry: %s\n", fcn, ptr));
	for (; *ptr != '\0'; ptr++) {
		if ((*ptr != ' ') && (*ptr != '\t') &&
		    (*ptr != '\n'))
			break;
	}

	ptr = (*ptr == '\0' ? NULL : ptr);

	BAM_DPRINTF(("%s: ptr on exit: %s\n", fcn, ptr ? ptr : "NULL"));

	return (ptr);
}

static char *
rskip_bspace(char *bound, char *ptr)
{
	const char		*fcn = "rskip_bspace()";
	assert(bound);
	assert(ptr);
	assert(bound <= ptr);
	assert(*bound != ' ' && *bound != '\t' && *bound != '\n');

	BAM_DPRINTF(("%s: ptr on entry: %s\n", fcn, ptr));
	for (; ptr > bound; ptr--) {
		if (*ptr == ' ' || *ptr == '\t' || *ptr == '\n')
			break;
	}

	BAM_DPRINTF(("%s: ptr on exit: %s\n", fcn, ptr));
	return (ptr);
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
 *	/boot/platform/i86pc/kernel/$ISADIR/unix
 *	/platform/i86pc/kernel/unix
 *	/platform/i86pc/kernel/amd64/unix
 *	/boot/platform/i86pc/kernel/unix
 *	/boot/platform/i86pc/kernel/amd64/unix
 *
 * If <kernel path> is any of the last four, the command may also be "kernel".
 *
 * <flags> is anything that isn't <kernel path>.
 *
 * This function is only called to convert a multiboot entry to a dboot entry
 *
 * For safety, we do one more check: if the kernel path starts with /boot,
 * we verify that the new kernel exists before changing it.  This is mainly
 * done for bfu, as it may cause the failsafe archives to be a different
 * boot architecture from the newly bfu'ed system.
 */
static error_t
cvt_kernel_line(line_t *line, const char *osroot, entry_t *entry)
{
	char		path[PATH_MAX], path_64[PATH_MAX];
	char		linebuf[PATH_MAX];
	char		new_arg[PATH_MAX];
	struct stat	sb, sb_64;
	char		*old_ptr;
	char		*unix_ptr;
	char		*flags1_ptr;
	char		*flags2_ptr;
	const char	*fcn = "cvt_kernel_line()";

	BAM_DPRINTF(("%s: entered. args: %s %s\n", fcn, line->line, osroot));

	/*
	 * We only convert multiboot to dboot and nothing else.
	 */
	if (!(entry->flags & BAM_ENTRY_MULTIBOOT)) {
		BAM_DPRINTF(("%s: not MULTIBOOT, not converting\n", fcn));
		return (BAM_SUCCESS);
	}

	if (entry->flags & BAM_ENTRY_FAILSAFE) {
		/*
		 * We're attempting to change failsafe to dboot.
		 * In the bfu case, we may not have a dboot failsafe
		 * kernel i.e. a "unix" under the "/boot" hierarchy.
		 * If so, just emit a message in verbose mode and
		 * return success.
		 */
		BAM_DPRINTF(("%s: trying to convert failsafe to DBOOT\n", fcn));
		(void) snprintf(path, PATH_MAX, "%s%s", osroot,
		    DIRECT_BOOT_FAILSAFE_32);
		(void) snprintf(path_64, PATH_MAX, "%s%s", osroot,
		    DIRECT_BOOT_FAILSAFE_64);
		if (stat(path, &sb) != 0 && stat(path_64, &sb_64) != 0) {
			if (bam_verbose) {
				bam_error(_("bootadm -m upgrade run, but the "
				    "failsafe archives have not been\nupdated. "
				    "Not updating line %d\n"), line->lineNum);
			}
			BAM_DPRINTF(("%s: no FAILSAFE unix, not converting\n",
			    fcn));
			return (BAM_SUCCESS);
		}
	}

	/*
	 * Make sure we have the correct cmd
	 */

	free(line->cmd);
	line->cmd = s_strdup(menu_cmds[KERNEL_DOLLAR_CMD]);
	BAM_DPRINTF(("%s: converted kernel cmd to %s\n", fcn, line->cmd));

	assert(sizeof (linebuf) > strlen(line->arg) + 32);
	(void) strlcpy(linebuf, line->arg, sizeof (linebuf));

	old_ptr = strpbrk(linebuf, " \t\n");
	old_ptr = skip_wspace(old_ptr);
	if (old_ptr == NULL) {
		/*
		 * only multiboot and nothing else
		 * i.e. flags1 = unix = flags2 = NULL
		 */
		flags1_ptr = unix_ptr = flags2_ptr = NULL;
		BAM_DPRINTF(("%s: NULL flags1, unix, flags2\n", fcn))
		goto create;
	}

	/*
	 *
	 * old_ptr is either at "flags1" or "unix"
	 */
	if ((unix_ptr = strstr(old_ptr, "/unix")) != NULL) {

		/*
		 * There is a  unix.
		 */
		BAM_DPRINTF(("%s: unix present\n", fcn));

		/* See if there's a flags2 past unix */
		flags2_ptr = unix_ptr + strlen("/unix");
		flags2_ptr = skip_wspace(flags2_ptr);
		if (flags2_ptr) {
			BAM_DPRINTF(("%s: flags2 present: %s\n", fcn,
			    flags2_ptr));
		} else {
			BAM_DPRINTF(("%s: flags2 absent\n", fcn));
		}

		/* see if there is a flags1 before unix */
		unix_ptr = rskip_bspace(old_ptr, unix_ptr);

		if (unix_ptr == old_ptr) {
			flags1_ptr = NULL;
			BAM_DPRINTF(("%s: flags1 absent\n", fcn));
		} else {
			flags1_ptr = old_ptr;
			*unix_ptr = '\0';
			unix_ptr++;
			BAM_DPRINTF(("%s: flags1 present: %s\n", fcn,
			    flags1_ptr));
		}

	} else  {
		/* There is no unix, there is only a bunch of flags */
		flags1_ptr = old_ptr;
		unix_ptr = flags2_ptr = NULL;
		BAM_DPRINTF(("%s: flags1 present: %s, unix, flags2 absent\n",
		    fcn, flags1_ptr));
	}

	/*
	 * With dboot, unix is fixed and is at the beginning. We need to
	 * migrate flags1 and flags2
	 */
create:
	if (entry->flags & BAM_ENTRY_FAILSAFE) {
		(void) snprintf(new_arg, sizeof (new_arg), "%s",
		    DIRECT_BOOT_FAILSAFE_KERNEL);
	} else {
		(void) snprintf(new_arg, sizeof (new_arg), "%s",
		    DIRECT_BOOT_KERNEL);
	}
	BAM_DPRINTF(("%s: converted unix: %s\n", fcn, new_arg));

	if (flags1_ptr != NULL) {
		(void) strlcat(new_arg, " ", sizeof (new_arg));
		(void) strlcat(new_arg, flags1_ptr, sizeof (new_arg));
	}

	if (flags2_ptr != NULL) {
		(void) strlcat(new_arg, " ", sizeof (new_arg));
		(void) strlcat(new_arg, flags2_ptr, sizeof (new_arg));
	}

	BAM_DPRINTF(("%s: converted unix with flags : %s\n", fcn, new_arg));

	free(line->arg);
	line->arg = s_strdup(new_arg);
	update_line(line);
	BAM_DPRINTF(("%s: converted line is: %s\n", fcn, line->line));
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
 * Under multiboot, the failsafe is:
 *
 * module /boot/x86.miniroot-safe
 *
 * Under dboot, the failsafe is:
 *
 * module$ /boot/$ISADIR/x86.miniroot-safe
 *
 * which may be specified exactly as either of:
 *
 * module /boot/x86.miniroot-safe
 * module /boot/amd64/x86.miniroot-safe
 */
static error_t
cvt_module_line(line_t *line, entry_t *entry)
{
	const char		*fcn = "cvt_module_line()";

	BAM_DPRINTF(("%s: entered. arg: %s\n", fcn, line->line));

	/*
	 * We only convert multiboot to dboot and nothing else
	 */
	if (!(entry->flags & BAM_ENTRY_MULTIBOOT)) {
		BAM_DPRINTF(("%s: not MULTIBOOT, not converting\n", fcn));
		return (BAM_SUCCESS);
	}

	if (entry->flags & BAM_ENTRY_FAILSAFE) {
		if (strcmp(line->arg, FAILSAFE_ARCHIVE) == 0) {
			BAM_DPRINTF(("%s: failsafe module line needs no "
			    "conversion: %s\n", fcn, line->arg));
			BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
			return (BAM_SUCCESS);
		}
	} else if (strcmp(line->arg, MULTIBOOT_ARCHIVE) != 0) {
		bam_error(_("module command on line %d not recognized.\n"),
		    line->lineNum);
		BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
		return (BAM_MSG);
	}

	free(line->cmd);
	free(line->arg);
	line->cmd = s_strdup(menu_cmds[MODULE_DOLLAR_CMD]);

	line->arg = s_strdup(entry->flags & BAM_ENTRY_FAILSAFE ?
	    FAILSAFE_ARCHIVE : DIRECT_BOOT_ARCHIVE);

	update_line(line);
	BAM_DPRINTF(("%s: converted module line is: %s\n", fcn, line->line));
	BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
	return (BAM_SUCCESS);
}

static void
bam_warn_hand_entries(menu_t *mp, char *osroot)
{
	int		hand_num;
	int		hand_max;
	int		*hand_list;
	int		i;
	entry_t		*entry;
	const char	*fcn = "bam_warn_hand_entries()";

	if (bam_force) {
		/*
		 * No warning needed, we are automatically converting
		 * the "hand" entries
		 */
		BAM_DPRINTF(("%s: force specified, no warnings about hand "
		    "entries\n",  fcn));
		return;
	}

	hand_num = 0;
	hand_max = BAM_ENTRY_NUM;
	hand_list = s_calloc(1, hand_max);

	for (entry = mp->entries; entry; entry = entry->next) {
		if (entry->flags & (BAM_ENTRY_BOOTADM|BAM_ENTRY_LU))
			continue;
		BAM_DPRINTF(("%s: found hand entry #: %d\n", fcn,
		    entry->entryNum));
		if (++hand_num > hand_max) {
			hand_max *= 2;
			hand_list = s_realloc(hand_list,
			    hand_max * sizeof (int));
		}
		hand_list[hand_num - 1] = entry->entryNum;
	}

	bam_error(_("bootadm(1M) will only upgrade GRUB menu entries added "
	    "by \nbootadm(1M) or lu(1M). The following entries on %s will "
	    "not be upgraded.\nFor details on manually updating entries, "
	    "see %s\n"), osroot, MENU_URL(osroot));
	bam_print_stderr("Entry Number%s: ", (hand_num > 1) ?
	    "s" : "");
	for (i = 0; i < hand_num; i++) {
		bam_print_stderr("%d ", hand_list[i]);
	}
	bam_print_stderr("\n");
}

static entry_t *
find_matching_entry(
	entry_t *estart,
	char *grubsign,
	char *grubroot,
	int root_opt)
{
	entry_t		*entry;
	line_t		*line;
	char		opt[10];
	const char	*fcn = "find_matching_entry()";

	assert(grubsign);
	assert(root_opt == 0 || root_opt == 1);

	(void) snprintf(opt, sizeof (opt), "%d", root_opt);
	BAM_DPRINTF(("%s: entered. args: %s %s %s\n", fcn, grubsign,
	    grubroot, opt));

	for (entry = estart; entry; entry = entry->next) {

		if (!(entry->flags & (BAM_ENTRY_BOOTADM|BAM_ENTRY_LU)) &&
		    !bam_force) {
			BAM_DPRINTF(("%s: skipping hand entry #: %d\n",
			    fcn, entry->entryNum));
			continue;
		}

		if (entry->flags & BAM_ENTRY_ROOT) {
			for (line = entry->start; line; line = line->next) {
				if (line->cmd == NULL || line->arg == NULL) {
					if (line == entry->end) {
						BAM_DPRINTF(("%s: entry has "
						    "ended\n", fcn));
						break;
					} else {
						BAM_DPRINTF(("%s: skipping "
						    "NULL line\n", fcn));
						continue;
					}
				}
				if (strcmp(line->cmd, menu_cmds[ROOT_CMD])
				    == 0 && strcmp(line->arg, grubroot) == 0) {
					BAM_DPRINTF(("%s: found matching root "
					    "line: %s,%s\n", fcn,
					    line->line, grubsign));
					return (entry);
				}
				if (line == entry->end) {
					BAM_DPRINTF(("%s: entry has ended\n",
					    fcn));
					break;
				}
			}
		} else if (entry->flags & BAM_ENTRY_FINDROOT) {
			for (line = entry->start; line; line = line->next) {
				if (line->cmd == NULL || line->arg == NULL) {
					if (line == entry->end) {
						BAM_DPRINTF(("%s: entry has "
						    "ended\n", fcn));
						break;
					} else {
						BAM_DPRINTF(("%s: skipping "
						    "NULL line\n", fcn));
						continue;
					}
				}
				if (strcmp(line->cmd, menu_cmds[FINDROOT_CMD])
				    == 0 && strcmp(line->arg, grubsign) == 0) {
					BAM_DPRINTF(("%s: found matching "
					    "findroot line: %s,%s\n", fcn,
					    line->line, grubsign));
					return (entry);
				}
				if (line == entry->end) {
					BAM_DPRINTF(("%s: entry has ended\n",
					    fcn));
					break;
				}
			}
		} else if (root_opt) {
			/* Neither root nor findroot */
			BAM_DPRINTF(("%s: no root or findroot and root is "
			    "opt: %d\n", fcn, entry->entryNum));
			return (entry);
		}
	}

	BAM_DPRINTF(("%s: no matching entry found\n", fcn));
	return (NULL);
}

/*
 * The following is a set of routines that attempt to convert the
 * menu entries for the supplied osroot into a format compatible
 * with the GRUB installation on osroot.
 *
 * Each of these conversion routines make no assumptions about
 * the current state of the menu entry, it does its best to
 * convert the menu entry to the new state. In the process
 * we may either upgrade or downgrade.
 *
 * We don't make any heroic efforts at conversion. It is better
 * to be conservative and bail out at the first sign of error. We will
 * in such cases, point the user at the knowledge-base article
 * so that they can upgrade manually.
 */
static error_t
bam_add_findroot(menu_t *mp, char *grubsign, char *grubroot, int root_opt)
{
	entry_t		*entry;
	line_t		*line;
	line_t		*newlp;
	int		update_num;
	char		linebuf[PATH_MAX];
	const char	*fcn = "bam_add_findroot()";

	update_num = 0;

	bam_print(_("converting entries to findroot...\n"));

	entry = find_matching_entry(mp->entries, grubsign, grubroot, root_opt);
	while (entry != NULL) {
		if (entry->flags & BAM_ENTRY_FINDROOT) {
			/* already converted */
			BAM_DPRINTF(("%s: entry %d already converted to "
			    "findroot\n", fcn, entry->entryNum));
			entry = find_matching_entry(entry->next, grubsign,
			    grubroot, root_opt);
			continue;
		}
		for (line = entry->start; line; line = line->next) {
			if (line->cmd == NULL || line->arg == NULL) {
				if (line == entry->end) {
					BAM_DPRINTF(("%s: entry has ended\n",
					    fcn));
					break;
				} else {
					BAM_DPRINTF(("%s: skipping NULL line\n",
					    fcn));
					continue;
				}
			}
			if (strcmp(line->cmd, menu_cmds[TITLE_CMD]) == 0) {
				newlp = s_calloc(1, sizeof (line_t));
				newlp->cmd = s_strdup(menu_cmds[FINDROOT_CMD]);
				newlp->sep = s_strdup(" ");
				newlp->arg = s_strdup(grubsign);
				(void) snprintf(linebuf, sizeof (linebuf),
				    "%s%s%s", newlp->cmd, newlp->sep,
				    newlp->arg);
				newlp->line = s_strdup(linebuf);
				bam_add_line(mp, entry, line, newlp);
				update_num = 1;
				entry->flags &= ~BAM_ENTRY_ROOT;
				entry->flags |= BAM_ENTRY_FINDROOT;
				BAM_DPRINTF(("%s: added findroot line: %s\n",
				    fcn, newlp->line));
				line = newlp;
			}
			if (strcmp(line->cmd, menu_cmds[ROOT_CMD]) == 0) {
				BAM_DPRINTF(("%s: freeing root line: %s\n",
				    fcn, line->line));
				unlink_line(mp, line);
				line_free(line);
			}
			if (line == entry->end) {
				BAM_DPRINTF(("%s: entry has ended\n", fcn));
				break;
			}
		}
		entry = find_matching_entry(entry->next, grubsign, grubroot,
		    root_opt);
	}

	if (update_num) {
		BAM_DPRINTF(("%s: updated numbering\n", fcn));
		update_numbering(mp);
	}

	BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
	return (BAM_SUCCESS);
}

static error_t
bam_add_hv(menu_t *mp, char *grubsign, char *grubroot, int root_opt)
{
	entry_t		*entry;
	const char	*fcn = "bam_add_hv()";

	bam_print(_("adding xVM entries...\n"));

	entry = find_matching_entry(mp->entries, grubsign, grubroot, root_opt);
	while (entry != NULL) {
		if (entry->flags & BAM_ENTRY_HV) {
			BAM_DPRINTF(("%s: entry %d already converted to "
			    "xvm HV\n", fcn, entry->entryNum));
			return (BAM_SUCCESS);
		}
		entry = find_matching_entry(entry->next, grubsign, grubroot,
		    root_opt);
	}

	(void) add_boot_entry(mp, NEW_HV_ENTRY, grubsign, XEN_MENU,
	    XEN_KERNEL_MODULE_LINE, DIRECT_BOOT_ARCHIVE, NULL);

	BAM_DPRINTF(("%s: added xVM HV entry via add_boot_entry()\n", fcn));

	update_numbering(mp);

	BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));

	return (BAM_SUCCESS);
}

static error_t
bam_add_dboot(
	menu_t *mp,
	char *osroot,
	char *grubsign,
	char *grubroot,
	int root_opt)
{
	int		msg = 0;
	entry_t		*entry;
	line_t		*line;
	error_t		ret;
	const char 	*fcn = "bam_add_dboot()";

	bam_print(_("converting entries to dboot...\n"));

	entry = find_matching_entry(mp->entries, grubsign, grubroot, root_opt);
	while (entry != NULL) {
		for (line = entry->start; line; line = line->next) {
			if (line->cmd == NULL || line->arg == NULL) {
				if (line == entry->end) {
					BAM_DPRINTF(("%s: entry has ended\n",
					    fcn));
					break;
				} else {
					BAM_DPRINTF(("%s: skipping NULL line\n",
					    fcn));
					continue;
				}
			}

			/*
			 * If we have a kernel$ command, assume it
			 * is dboot already.  If it is not a dboot
			 * entry, something funny is going on and
			 * we will leave it alone
			 */
			if (strcmp(line->cmd, menu_cmds[KERNEL_CMD]) == 0) {
				ret = cvt_kernel_line(line, osroot, entry);
				INJECT_ERROR1("ADD_DBOOT_KERN_ERR",
				    ret = BAM_ERROR);
				INJECT_ERROR1("ADD_DBOOT_KERN_MSG",
				    ret = BAM_MSG);
				if (ret == BAM_ERROR) {
					BAM_DPRINTF(("%s: cvt_kernel_line() "
					    "failed\n", fcn));
					return (ret);
				} else if (ret == BAM_MSG) {
					msg = 1;
					BAM_DPRINTF(("%s: BAM_MSG returned "
					    "from cvt_kernel_line()\n", fcn));
				}
			}
			if (strcmp(line->cmd, menu_cmds[MODULE_CMD]) == 0) {
				ret = cvt_module_line(line, entry);
				INJECT_ERROR1("ADD_DBOOT_MOD_ERR",
				    ret = BAM_ERROR);
				INJECT_ERROR1("ADD_DBOOT_MOD_MSG",
				    ret = BAM_MSG);
				if (ret == BAM_ERROR) {
					BAM_DPRINTF(("%s: cvt_module_line() "
					    "failed\n", fcn));
					return (ret);
				} else if (ret == BAM_MSG) {
					BAM_DPRINTF(("%s: BAM_MSG returned "
					    "from cvt_module_line()\n", fcn));
					msg = 1;
				}
			}

			if (line == entry->end) {
				BAM_DPRINTF(("%s: entry has ended\n", fcn));
				break;
			}
		}
		entry = find_matching_entry(entry->next, grubsign, grubroot,
		    root_opt);
	}

	ret = msg ? BAM_MSG : BAM_SUCCESS;
	BAM_DPRINTF(("%s: returning ret = %d\n", fcn, ret));
	return (ret);
}

/*ARGSUSED*/
error_t
upgrade_menu(menu_t *mp, char *osroot, char *menu_root)
{
	char		*osdev;
	char		*grubsign;
	char		*grubroot;
	int		ret1;
	int		ret2;
	int		ret3;
	const char	*fcn = "upgrade_menu()";

	assert(osroot);
	assert(menu_root);

	BAM_DPRINTF(("%s: entered. args: %s %s\n", fcn, osroot, menu_root));

	/*
	 * We only support upgrades. Xen may not be present
	 * on smaller metaclusters so we don't check for that.
	 */
	if (bam_is_findroot != BAM_FINDROOT_PRESENT ||
	    bam_direct != BAM_DIRECT_DBOOT) {
		bam_error(_("automated downgrade of GRUB menu to older "
		    "version not supported.\n"));
		return (BAM_ERROR);
	}

	/*
	 * First get the GRUB signature
	 */
	osdev = get_special(osroot);
	INJECT_ERROR1("UPGRADE_OSDEV", osdev = NULL);
	if (osdev == NULL) {
		bam_error(_("cant find special file for mount-point %s\n"),
		    osroot);
		return (BAM_ERROR);
	}

	grubsign = get_grubsign(osroot, osdev);
	INJECT_ERROR1("UPGRADE_GRUBSIGN", grubsign = NULL);
	if (grubsign == NULL) {
		free(osdev);
		bam_error(_("cannot find GRUB signature for %s\n"), osroot);
		return (BAM_ERROR);
	}

	/* not fatal if we can't get grubroot */
	grubroot = get_grubroot(osroot, osdev, menu_root);
	INJECT_ERROR1("UPGRADE_GRUBROOT", grubroot = NULL);

	free(osdev);

	ret1 = bam_add_findroot(mp, grubsign,
	    grubroot, root_optional(osroot, menu_root));
	INJECT_ERROR1("UPGRADE_ADD_FINDROOT", ret1 = BAM_ERROR);
	if (ret1 == BAM_ERROR)
		goto abort;

	if (bam_is_hv == BAM_HV_PRESENT) {
		ret2 = bam_add_hv(mp, grubsign, grubroot,
		    root_optional(osroot, menu_root));
		INJECT_ERROR1("UPGRADE_ADD_HV", ret2 = BAM_ERROR);
		if (ret2 == BAM_ERROR)
			goto abort;
	} else
		ret2 = BAM_SUCCESS;

	ret3 = bam_add_dboot(mp, osroot, grubsign,
	    grubroot, root_optional(osroot, menu_root));
	INJECT_ERROR1("UPGRADE_ADD_DBOOT", ret3 = BAM_ERROR);
	if (ret3 == BAM_ERROR)
		goto abort;

	if (ret1 == BAM_MSG || ret2 == BAM_MSG || ret3 == BAM_MSG) {
		bam_error(_("one or more GRUB menu entries were not "
		    "automatically upgraded\nFor details on manually "
		    "updating entries, see %s\n"), MENU_URL(osroot));
	} else {
		bam_warn_hand_entries(mp, osroot);
	}

	free(grubsign);

	BAM_DPRINTF(("%s: returning ret = %d\n", fcn, BAM_WRITE));
	return (BAM_WRITE);

abort:
	free(grubsign);
	bam_error(_("error upgrading GRUB menu entries on %s. Aborting.\n"
	    "For details on manually updating entries, see %s\n"), osroot,
	    MENU_URL(osroot));
	return (BAM_ERROR);
}
