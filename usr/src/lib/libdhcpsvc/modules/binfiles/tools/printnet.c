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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Print SUNWbinfiles DHCP network containers.
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <sys/socket.h>
#include "../dhcp_network.h"

static void print_hashes(int, dn_header_t);

int
main(int argc, char **argv)
{
	int confd;
	dn_header_t header;
	char netmask[INET_ADDRSTRLEN], network[INET_ADDRSTRLEN];
	struct in_addr in_addr;
	unsigned int i;

	if (argc < 2) {
		(void) fprintf(stderr, "usage: %s container [container ...]\n",
		    argv[0]);
		return (EXIT_FAILURE);
	}

	for (i = 1; argv[i] != NULL; i++) {
		confd = open(argv[i], O_RDONLY);
		if (confd == -1) {
			(void) fprintf(stderr, "%s: cannot open container "
			    "`%s': %s\n", argv[0], argv[i], strerror(errno));
			continue;
		}

		if (read(confd, &header, sizeof (header)) != sizeof (header) ||
		    header.dnh_magic != DN_MAGIC) {
			(void) fprintf(stderr, "%s: container `%s' is not a "
			    "binfiles network container\n", argv[0], argv[i]);
			continue;
		}

		(void) printf("binfiles network container `%s':\n", argv[i]);

		in_addr.s_addr = header.dnh_network;
		(void) inet_ntop(AF_INET, &in_addr, network, INET_ADDRSTRLEN);
		in_addr.s_addr = header.dnh_netmask;
		(void) inet_ntop(AF_INET, &in_addr, netmask, INET_ADDRSTRLEN);

		(void) printf("%12s: %s\n", "network", network);
		(void) printf("%12s: %s\n", "netmask", netmask);
		(void) printf("%12s: %d\n", "dirtybit", header.dnh_dirty);
		(void) printf("%12s: %d\n", "version", header.dnh_version);
		(void) printf("%12s: %d\n", "active image", header.dnh_image);
		(void) printf("%12s: %d\n", "temp image", header.dnh_tempimage);
		(void) printf("%12s: %d\n", "checks", header.dnh_checks);
		(void) printf("%12s: %d\n", "errors", header.dnh_errors);
		print_hashes(confd, header);
		(void) close(confd);
	}

	return (EXIT_SUCCESS);
}

static void
print_hashes(int confd, dn_header_t header)
{
	dn_filerec_t rec;
	dn_recid_t recid;
	unsigned int image, hash;

	for (hash = 0; hash < DN_CIDHASHSZ; hash++) {
		for (image = 0; image < 2; image++) {
			if (header.dnh_cidhash[hash][image] == DN_NOREC)
				continue;

			(void) printf(" hash %4d/%d: ", hash, image);
			recid = header.dnh_cidhash[hash][image];
			for (; recid != DN_NOREC; recid = rec.rec_next[image]) {
				if (pread(confd, &rec, sizeof (dn_rec_t),
				    RECID2OFFSET(recid)) != sizeof (dn_rec_t)) {
					(void) fprintf(stderr, "cannot read "
					    "recid %d: %s", recid,
					    strerror(errno));
					break;
				}
				(void) printf("%d<-[%d]->%d ",
				    rec.rec_prev[image], recid,
				    rec.rec_next[image]);
			}
			(void) printf("\n");
		}
	}
}
