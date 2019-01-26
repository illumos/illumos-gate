/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <libintl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <kvm.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/tnf.h>
#include <sys/tnf_com.h>
#include <nlist.h>
#include <errno.h>

#define	TNFDEV		"/dev/tnfmap"

#define	MAXFWTRY	5

typedef struct {
	boolean_t	ever_read;
	tnf_uint32_t	generation;
	tnf_uint16_t	bytes_valid;
} BLOCK_STATUS;

static char *dumpfile;		/* Dump file if extracting from crashdump */
static char *namelist;		/* Symbol tbl. if extracting from crashdump */
static kvm_t *kvm_p;		/* Handle for kvm_open, kvm_read, ... */

static struct nlist kvm_syms[] = {
	{ "tnf_buf" },
	{ "tnf_trace_file_size" },
	{ NULL }
};

static uintptr_t dump_bufaddr;
static size_t tnf_bufsize;
static char *program_name;
static int input_fd;
static int output_fd;
static tnf_file_header_t *tnf_header;

/*
 * usage() - gives a description of the arguments, and exits
 */

static void
usage(char *argv[], const char *msg)
{
	if (msg)
		(void) fprintf(stderr,
			gettext("%s: %s\n"), argv[0], msg);

	(void) fprintf(stderr, gettext(
	    "usage: %s [-d <dumpfile> -n <symbolfile> ] "
	    "<output-filename>\n"), argv[0]);
	exit(1);
}				/* end usage */


/*
 * Write 'size' bytes at offset 'offset' from 'addr'
 * to the output file.  Bail out unceremoniously if anything goes wrong.
 */
static void
writeout(char *addr, int offset, int size)

{
	if (lseek(output_fd, offset, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}
	if (write(output_fd, addr, size) != size) {
		perror("write");
		exit(1);
	}
}


static void
dumpfile_init()

{
	kvm_p = kvm_open(namelist, dumpfile, NULL, O_RDONLY, program_name);
	if (kvm_p == NULL) {
		/* kvm_open prints an error message */
		exit(1);
	}
	if (kvm_nlist(kvm_p, kvm_syms) != 0) {
		(void) fprintf(stderr, gettext(
			"Symbol lookup error in %s\n"), namelist);
		exit(1);
	}
	if (kvm_read(kvm_p, kvm_syms[0].n_value, (char *) &dump_bufaddr,
	    sizeof (dump_bufaddr)) != sizeof (dump_bufaddr) ||
	    kvm_read(kvm_p, kvm_syms[1].n_value, (char *) &tnf_bufsize,
	    sizeof (tnf_bufsize)) != sizeof (tnf_bufsize)) {
		(void) fprintf(stderr, gettext(
			"kvm_read error in %s\n"), dumpfile);
		exit(1);
	}
	if (dump_bufaddr == (uintptr_t)NULL || tnf_bufsize == 0) {
		(void) fprintf(stderr, gettext(
			"No trace data available in the kernel.\n"));
		exit(1);
	}
}

static void
live_kernel_init()

{
	tifiocstate_t tstate;

	if ((input_fd = open(TNFDEV, O_RDWR)) < 0) {
		perror(TNFDEV);
		exit(1);
	}
	if (ioctl(input_fd, TIFIOCGSTATE, &tstate) < 0) {
		perror(gettext("Error getting trace system state"));
		exit(1);
	}
	if (tstate.buffer_state != TIFIOCBUF_OK) {
		(void) fprintf(stderr, gettext(
		    "No trace data available in the kernel.\n"));
		exit(1);
	}
	tnf_bufsize = tstate.buffer_size;
}

static void
read_tnf_header(char *addr)

{
	if (dumpfile != NULL) {
		if (kvm_read(kvm_p, dump_bufaddr, addr, 512) != 512) {
			(void) fprintf(stderr, gettext(
			    "Error reading tnf header from dump file.\n"));
			exit(1);
		}
	} else {
		if (ioctl(input_fd, TIFIOCGHEADER, addr) != 0) {
			perror(gettext("Error reading tnf header from kernel"));
			exit(1);
		}
	}
}

static int
read_tnf_block(tnf_block_header_t *addr, int block_num)

{
	int offset;
	tifiocgblock_t ioctl_arg;

	if (dumpfile != NULL) {
		offset = tnf_header->directory_size +
		    block_num * tnf_header->block_size;
		if (kvm_read(kvm_p, dump_bufaddr + offset, (char *) addr,
		    tnf_header->block_size) != tnf_header->block_size) {
			(void) fprintf(stderr, gettext(
			    "Error reading tnf block.\n"));
			exit(1);
		}
	} else {
		ioctl_arg.dst_addr = (char *) addr;
		ioctl_arg.block_num = block_num;
		if (ioctl(input_fd, TIFIOCGBLOCK, &ioctl_arg) < 0) {
			if (errno == EBUSY)
				return (EBUSY);
			perror(gettext("Error reading tnf block"));
			exit(1);
		}
	}
	return (0);
}

static void
read_tnf_fwzone(tnf_ref32_t *dest, int start, int slots)

{
	int offset;
	int len;
	tifiocgfw_t ioctl_arg;

	if (dumpfile != NULL) {
		/* LINTED assignment of 64-bit integer to 32-bit integer */
		offset = tnf_header->block_size + start * sizeof (tnf_ref32_t);
		/* LINTED assignment of 64-bit integer to 32-bit integer */
		len = slots * sizeof (tnf_ref32_t);
		if (kvm_read(kvm_p, dump_bufaddr + offset, (char *) dest,
		    len) != len) {
			(void) fprintf(stderr, gettext(
			    "Error reading tnf forwarding zone.\n"));
			exit(1);
		}
	} else {
		/* LINTED pointer cast may result in improper alignment */
		ioctl_arg.dst_addr = (long *) dest;
		ioctl_arg.start = start;
		ioctl_arg.slots = slots;
		if (ioctl(input_fd, TIFIOCGFWZONE, &ioctl_arg) < 0) {
			perror(gettext("Error reading tnf block"));
			exit(1);
		}
	}
}

int
main(int argc, char *argv[])
{
	const char *optstr = "d:n:";
	const char *outfile;
	char *local_buf;
	int c;
	tnf_uint32_t *magicp;
	tnf_block_header_t *block_base, *blockp;
	BLOCK_STATUS *block_stat, *bsp;
	int block_num;
	boolean_t any_unread, any_different, retry;
	tnf_ref32_t *fwzone;
	int fwzonesize;
	int i;
	int fwtries;
	int block_count;

	program_name = argv[0];
	while ((c = getopt(argc, argv, optstr)) != EOF) {
		switch (c) {
		case 'd':
		    dumpfile = optarg;
		    break;
		case 'n':
		    namelist = optarg;
		    break;
		case '?':
			usage(argv, gettext("unrecognized argument"));
		}
	}
	if (optind != argc - 1) {
		usage(argv, gettext("too many or too few arguments"));
	} else {
		outfile = argv[optind];
	}
	if ((dumpfile != NULL) ^ (namelist != NULL)) {
		usage(argv, gettext("must specify both or neither of the "
		    "-d and -n options"));
	}

	output_fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (output_fd < 0) {
		perror(outfile);
		exit(1);
	}
	if (dumpfile != NULL)
		dumpfile_init();
	else
		live_kernel_init();

	if ((local_buf = malloc(tnf_bufsize)) == NULL) {
		(void) fprintf(stderr,
		    gettext("tnfxtract memory allocation failure\n"));
		exit(1);
	}

	/* Read header, get block size, check for version mismatch */
	read_tnf_header(local_buf);
	/*LINTED pointer cast may result in improper alignment*/
	magicp = (tnf_uint32_t *) local_buf;
	/*LINTED pointer cast may result in improper alignment*/
	tnf_header = (tnf_file_header_t *)(local_buf + sizeof (*magicp));
	if (*magicp != TNF_MAGIC) {
		(void) fprintf(stderr, gettext(
		    "Buffer is not in TNF format.\n"));
		exit(1);
	}
	if (tnf_header->file_version != TNF_FILE_VERSION) {
		(void) fprintf(stderr,
		    gettext("Version mismatch (tnfxtract: %d; buffer: %d)\n"),
		    TNF_FILE_VERSION, tnf_header->file_version);
		exit(1);
	}
	writeout(local_buf, 0, tnf_header->block_size);
	/* LINTED pointer cast may result in improper alignment */
	block_base = (tnf_block_header_t *)
	    (local_buf + tnf_header->directory_size);
	block_count = tnf_header->block_count -
	    tnf_header->directory_size / tnf_header->block_size;
	fwzonesize = tnf_header->directory_size - tnf_header->block_size;

	block_stat = (BLOCK_STATUS *)
	    calloc(block_count, sizeof (BLOCK_STATUS));
	if (block_stat == NULL) {
		(void) fprintf(stderr,
		    gettext("tnfxtract memory allocation failure\n"));
		exit(1);
	}

	for (bsp = block_stat; bsp != block_stat + block_count; ++bsp)
		bsp->ever_read = B_FALSE;
	/*
	 * Make repeated passes until we've read every non-tag block.
	 */
	do {
		any_unread = B_FALSE;
		bsp = block_stat;
		block_num = 0;
		blockp = block_base;
		while (block_num != block_count) {
			if (!bsp->ever_read) {
				if (read_tnf_block(blockp, block_num) != 0)
					any_unread = B_TRUE;
				else {
					bsp->ever_read = B_TRUE;
					bsp->generation = blockp->generation;
					bsp->bytes_valid = blockp->bytes_valid;
					writeout((char *) blockp,
					/* LINTED cast 64 to 32 bit */
					(int)((char *) blockp - local_buf),
					    tnf_header->block_size);
				}
			}
			++bsp;
			++block_num;
		/* LINTED pointer cast may result in improper alignment */
			blockp = (tnf_block_header_t *)
			    ((char *) blockp + tnf_header->block_size);
		}
	} while (any_unread);

	/*
	 * Then read tag blocks only, until we have two consecutive,
	 * consistent reads.
	 */
	do {
		any_different = B_FALSE;
		bsp = block_stat;
		block_num = 0;
		blockp = block_base;
		while (block_num != block_count) {
			if (read_tnf_block(blockp, block_num) == 0 &&
			    blockp->generation == TNF_TAG_GENERATION_NUM &&
			    (bsp->generation != TNF_TAG_GENERATION_NUM ||
			    bsp->bytes_valid != blockp->bytes_valid)) {
				bsp->generation = TNF_TAG_GENERATION_NUM;
				bsp->bytes_valid = blockp->bytes_valid;
				writeout((char *) blockp,
				/* LINTED cast 64bit to 32 bit */
				    (int)((char *) blockp - local_buf),
				    tnf_header->block_size);
				any_different = B_TRUE;
			}
			++bsp;
			++block_num;
		/* LINTED pointer cast may result in improper alignment */
			blockp = (tnf_block_header_t *)
			    ((char *) blockp + tnf_header->block_size);
		}
	} while (any_different);

	/*
	 * Then read the forwarding pointers.  If any are -1:
	 * sleep briefly, then make another pass.
	 */
	/*LINTED pointer cast may result in improper alignment*/
	fwzone = (tnf_ref32_t *)(local_buf + tnf_header->block_size);

	read_tnf_fwzone(fwzone, 0,
		/* LINTED cast from 64-bit integer to 32-bit integer */
		(int)(fwzonesize / sizeof (fwzone[0])));
	fwtries = 0;
	while (fwtries != MAXFWTRY) {
		retry = B_FALSE;
		for (i = 0; i != fwzonesize / sizeof (fwzone[0]); ++i) {
			if (fwzone[i] == -1) {
				read_tnf_fwzone(&fwzone[i], i, 1);
				if (!retry) {
					retry = B_TRUE;
					++fwtries;
				}
			}
		}
		if (!retry)
			break;
		sleep(2);
	}
	if (fwtries == MAXFWTRY) {
		(void) fprintf(stderr, gettext(
		    "Warning:  forwarding pointers may "
		    "be invalid.\n"));
	}
	writeout((char *) fwzone, tnf_header->block_size, fwzonesize);
	return (0);
}
