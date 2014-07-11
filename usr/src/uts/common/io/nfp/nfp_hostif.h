/*

nfp_hostif.h: nCipher PCI HSM host interface declarations

(C) Copyright nCipher Corporation Ltd 2002-2008 All rights reserved

Copyright (c) 2008-2013 Thales e-Security All rights reserved

Copyright (c) 2014 Thales UK All rights reserved

history

10/10/2001 jsh  Original

*/

#ifndef NFP_HOSTIF_H
#define NFP_HOSTIF_H

#include "nfdev-common.h"

struct nfp_dev;

/* common device structure */

typedef struct nfp_cdev {
  unsigned char *bar[6];
  void *extra[6];

  int busno;
  int slotno;

  void *cmdctx;

  char *iobuf;

  struct nfp_dev* dev;

  struct nfdev_stats_str stats;

} nfp_cdev;

/* callbacks from command drivers -------------------------------------- */

void nfp_read_complete(  struct nfp_dev *pdev, int ok);
void nfp_write_complete( struct nfp_dev *pdev, int ok);

#define NFP_READ_MAX (8 * 1024)
#define NFP_READBUF_SIZE (NFP_READ_MAX + 8)
#define NFP_TIMEOUT_SEC 10

#define NFP_DRVNAME "nCipher nFast PCI driver"

#endif
