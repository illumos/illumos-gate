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

#include <stdio.h>
#include "dluser.h"

unsigned char dest[6] = {0,0,0xc0, 0x21, 0x8f, 8};
struct dl_address *addr;
main( argc, argv )
	char *argv[];
{
   int i, fd;

   printf("opening %s\n", argc > 1 ? argv[1] : "/dev/le", 2, 0);
   fd = dl_open(argc>1 ? argv[1] : "/dev/le", 2, 0);
   if (fd<0){
      perror("wd0");
      exit(1);
   }
   if (dl_attach(fd, 3)<0){
	perror("error on dl_attach\n");
	exit(10);
   }
   if (dl_bind(fd, 0x40, 0, 0)<0){
      perror("error on bind\n");
      printf("dl error = %d\n", dl_error(fd));
      exit(2);
   }
   addr = dl_mkaddress(fd, dest, 0x40, NULL, NULL);


   for(i=0;;i++){
      char buff[2048];
      int len;
      for (len=0; len<1024; len++)
	buff[len] = i;
      len = 1024;
      if (dl_snd(fd, buff, len, addr, 0)<0){
	 printf("an error on send (%d)\n", dl_error(fd));
	 exit(1);
      }
      printf("sent packet %d\n", i);
      sleep(1);
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
