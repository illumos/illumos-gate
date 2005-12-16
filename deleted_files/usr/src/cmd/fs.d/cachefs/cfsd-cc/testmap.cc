// CDDL HEADER START
//
// The contents of this file are subject to the terms of the
// Common Development and Distribution License, Version 1.0 only
// (the "License").  You may not use this file except in compliance
// with the License.
//
// You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
// or http://www.opensolaris.org/os/licensing.
// See the License for the specific language governing permissions
// and limitations under the License.
//
// When distributing Covered Code, include this CDDL HEADER in each
// file and include the License file at usr/src/OPENSOLARIS.LICENSE.
// If applicable, add the following below this CDDL HEADER, with the
// fields enclosed by brackets "[]" replaced with your own identifying
// information: Portions Copyright [yyyy] [name of copyright owner]
//
// CDDL HEADER END

//
// Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
// Use is subject to license terms.
//
#pragma ident	"%Z%%M%	%I%	%E% SMI"

// Simple test program to test the cfsd_maptbl class.

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <synch.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/cred.h>
#include <sys/attr.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <rw/cstring.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dlog.h>
#include <mdbug-cc/mdbug.h>
#include "cfsd_maptbl.h"

int
main(int argc, char **argv)
{
	dbug_enter("main");
	dbug_process("testmap");

	int xx;
	int c;
	const char *msgp;
	while ((c = getopt(argc, argv, "#:")) != EOF) {
		switch (c) {
		case '#':	/* dbug args */
			msgp = dbug_push(optarg);
			if (msgp) {
				printf("dbug_push failed \"%s\"\n", msgp);
				return (1);
			}
			break;

		default:
			printf("illegal switch\n");
			return (1);
		}
	}

	dbug_print("info", ("testmap started..."));

	// set up the mapping table
	cfsd_maptbl *mp = new cfsd_maptbl;
	mp->maptbl_setup("/export/tmp/xx");
	dbug_print("info", ("Filling Table"));
	int entries = mp->maptbl_entries();
	int max = entries * .8;

	// open the file with the inode numbers
	FILE *fin = fopen("./dataset", "r");
	if (fin == NULL) {
		dbug_print("error", ("cannot open dataset"));
		return (1);
	}

	// read the file and populate the table
	int index;
	char buf[100];
	for (index = 0; index < max; index++) {
		// read one line
		if (fgets(buf, sizeof (buf), fin) == NULL) {
			dbug_print("error", ("EOF, line %d", index+1));
			break;
		}

		// get the inode number from the input
		int num;
		if (sscanf(buf, "%d", &num) != 1) {
			dbug_print("error", ("bad input, line %d", index+1));
			break;
		}

		// put the inode in the table
		cfs_dlog_mapping_space item;
		item.ms_cid.cid_fileno = num;
		item.ms_fid = num + 1;
		item.ms_times = num + 2;
		xx = mp->maptbl_set(&item, 1);
		if (xx) {
			dbug_print("error", ("set failed %d, line %d",
			    xx, index+1));
			break;
		}
	}

	mp->maptbl_dumpstats();
	return (0);
	dbug_print("info", ("Examining Table"));

	// reread the file and compare against the table
	rewind(fin);
	for (index = 0; index < max; index++) {
		// read one line
		if (fgets(buf, sizeof (buf), fin) == NULL) {
			dbug_print("error", ("EOF, line %d", index+1));
			break;
		}

		// get the inode number from the input
		int num;
		if (sscanf(buf, "%d", &num) != 1) {
			dbug_print("error", ("bad input, line %d", index+1));
			break;
		}

		// get the entry from the table
		cfs_cid_t cid;
		cfs_dlog_mapping_space item;
		cid.cid_fileno = num;
		xx = mp->maptbl_get(cid, &item);
		if (xx) {
			dbug_print("error", ("get failed %d, line %d",
			    xx, index+1));
			break;
		}

		// make sure the data is what we put in
		if ((item.ms_cid.cid_fileno != num) ||
		    (item.ms_fid != num + 1) ||
		    (item.ms_times != num + 2)) {
			dbug_print("error", ("get data wrong %d, line %d",
			    xx, index+1));
			break;
		}
	}

	mp->maptbl_dumpstats();

	return (0);
}
