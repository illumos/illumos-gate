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

#include "dluser.h"


struct dl_address *addr;
main( argc, argv )
	char *argv[];
{
   int i, fd;

   fd = dl_open(argc>1 ? argv[1] : "/dev/wd0", 2, 0);
   if (fd<0){
      perror("wd0");
      exit(1);
   }
   if (dl_bind(fd, 0x1111, 0, 0)<0){
      printf("error on bind\n");
      exit(2);
   }
   addr = (struct dl_address *)dl_allocaddr(fd, DL_ALL);
   for(i=0;;i++){
      char buff[2048];
      int len;
      len = 2048;
      if (dl_rcv(fd, buff, &len, addr)<0){
	 printf("an error on recv (%d)\n", dl_error(fd));
	 exit(1);
      }
      printf("[%2d] data len=%d\n", i, len);
      printaddress(addr->dla_daddr, addr->dla_dlen);
      printaddress(addr->dla_saddr, addr->dla_slen);
   }
}

printaddress(addr, len)
     unsigned char *addr;
{
   unsigned char paddr[6];
   int sap;
   unsigned char oi[4];
   int oitype;
   int i;

   printf("alen=%d",len);
   for (i=0; i<len; i++)printf(" %02X", addr[i]);printf("\n");
   dl_parseaddr(addr, len, paddr, &sap, oi, &oitype);
   for (i=0; i<6; i++)
     printf("%02X ", paddr[i]);
   printf("%04X\n", sap);
}
