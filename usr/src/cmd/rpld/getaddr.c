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
 *
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/wd.h>

main(argc, argv)
     char *argv[];
{
  struct strioctl ioc;
  unsigned char oldaddr[6];
#if defined(DLPI_1)
   int fd = open(argc>1 ? argv[1] : "/dev/wd0", 2);
   if (fd < 0){
	perror("open");
	exit(1);
   }
   ioc.ic_cmd = DLGADDR;
   ioc.ic_dp = oldaddr;
   ioc.ic_len = 6;
   if (ioctl(fd, I_STR, &ioc)<0){
      perror("DLGADDR");
   }
   printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
	  oldaddr[0],
	  oldaddr[1],
	  oldaddr[2],
	  oldaddr[3],
	  oldaddr[4],
	  oldaddr[5]);
#else
  dl_info_t info;
  unsigned char *oaddr;
  fd = dl_open(argc>1 ? argv[1] : "/dev/wd0", 2, &info);
  oaddr = info->
#endif
   printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
	  oldaddr[0],
	  oldaddr[1],
	  oldaddr[2],
	  oldaddr[3],
	  oldaddr[4],
	  oldaddr[5]);
}
