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
 */

/*
 * pcom: Print Comment
 *
 * This program demonstrates the use of the libelf interface to
 * read an ELF file.  pcom will open an ELF file using
 * elf_begin(ELF_C_READ) and examine search the ELF file
 * for a .comment section.  If a .comment section is found it's
 * contents will be displayed on stdout.
 */

#include <stdio.h>
#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>


static const char	*CommentStr = ".comment";

static void
print_comment(Elf *elf, const char *file)
{
	Elf_Scn		*scn = 0;
	GElf_Shdr	shdr;
	Elf_Data	*data;
	size_t		shstrndx;


	(void) printf("%s .comment:\n", file);

	if (elf_getshdrstrndx(elf, &shstrndx) == -1) {
		(void) fprintf(stderr, "%s: elf_getshdrstrndx() failed: %s\n",
		    file, elf_errmsg(0));
		return;
	}

	while ((scn = elf_nextscn(elf, scn)) != 0) {
		/*
		 * Do a string compare to examine each section header
		 * to see if it is a ".comment" section.  If it is then
		 * this is the section we want to process.
		 */
		if (gelf_getshdr(scn, &shdr) == 0) {
			(void) fprintf(stderr, "%s: elf_getshdr() failed: %s\n",
			    file, elf_errmsg(0));
			return;
		}
		if (strcmp(CommentStr, elf_strptr(elf, shstrndx,
		    shdr.sh_name)) == 0) {
			int	i;
			char	*ptr;

			/*
			 * Get the data associated with the .comment
			 * section.
			 */
			if ((data = elf_getdata(scn, 0)) == 0) {
				(void) fprintf(stderr,
				    "%s: elf_getdata() failed: %s\n",
				    file, elf_errmsg(0));
				return;
			}
			/*
			 * Data in a .comment section is a list of 'null'
			 * terminated strings.  The following will print
			 * one string per line.
			 */
			for (i = 0, ptr = (char *)data->d_buf;
			    i < data->d_size; i++)
				if (ptr[i]) {
					(void) puts(&ptr[i]);
					i += strlen(&ptr[i]);
				}
			(void) putchar('\n');
		}
	}

}


static void
process_elf(Elf *elf, char *file, int fd, int member)
{
	Elf_Cmd	cmd;
	Elf	*_elf;

	switch (elf_kind(elf)) {
	case ELF_K_ELF:
		/*
		 * This is an ELF file, now attempt to find it's
		 * .comment section and to display it.
		 */
		print_comment(elf, file);
		break;
	case ELF_K_AR:
		/*
		 * Archives contain multiple ELF files, which can each
		 * in turn be examined with libelf.
		 *
		 * The below loop will iterate over each member of the
		 * archive and recursivly call process_elf() for processing.
		 */
		cmd = ELF_C_READ;
		while ((_elf = elf_begin(fd, cmd, elf)) != 0) {
			Elf_Arhdr	*arhdr;
			char		buffer[1024];

			arhdr = elf_getarhdr(_elf);

			/*
			 * Build up file names based off of
			 * 'archivename(membername)'.
			 */
			(void) sprintf(buffer, "%s(%s)", file, arhdr->ar_name);

			/*
			 * recursivly process the ELF members.
			 */
			process_elf(_elf, buffer, fd, 1);
			cmd = elf_next(_elf);
			(void) elf_end(_elf);
		}
		break;
	default:
		if (!member)
			(void) fprintf(stderr,
			    "%s: unexpected elf_kind(): 0x%x\n",
			    file, elf_kind(elf));
		return;
	}
}

int
main(int argc, char **argv)
{
	int	i;


	if (argc < 2) {
		(void) printf("usage: %s elf_file ...\n", argv[0]);
		return (1);
	}

	/*
	 * Initialize the elf library, must be called before elf_begin()
	 * can be called.
	 */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) fprintf(stderr,
		    "elf_version() failed: %s\n", elf_errmsg(0));
		return (1);
	}

	for (i = 1; i < argc; i++) {
		int	fd;
		Elf	*elf;
		char	*elf_fname;

		elf_fname = argv[i];
		if ((fd = open(elf_fname, O_RDONLY)) == -1) {
			perror("open");
			continue;
		}

		/*
		 * Attempt to open an Elf descriptor Read/Write
		 * for each file.
		 */
		if ((elf = elf_begin(fd, ELF_C_READ, 0)) == NULL) {
			(void) fprintf(stderr, "elf_begin() failed: %s\n",
			    elf_errmsg(0));
			(void) close(fd);
			continue;
		}

		/*
		 * Process each elf descriptor.
		 */
		process_elf(elf, elf_fname, fd, 0);
		(void) elf_end(elf);
		(void) close(fd);
	}

	return (0);
}
