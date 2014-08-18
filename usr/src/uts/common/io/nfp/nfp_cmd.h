/*

nfp_cmd.h: nCipher PCI HSM command driver decalrations

(C) Copyright nCipher Corporation Ltd 2002-2008 All rights reserved

Copyright (c) 2008-2013 Thales e-Security All rights reserved

Copyright (c) 2014 Thales UK All rights reserved

history

10/10/2001 jsh  Original

*/

#ifndef NFPCMD_H
#define NFPCMD_H

#include "nfp_hostif.h"
#include "nfp_error.h"

/* read and write called with userspace buffer */

typedef struct nfpcmd_dev {
  const char *name;
  unsigned short vendorid, deviceid,
                 sub_vendorid, sub_deviceid;
  unsigned int bar_sizes[6];    /* includes IO bit */
  unsigned int flags;
  nfp_err (*create)(struct nfp_cdev *pdev);
  nfp_err (*destroy)(void * ctx);
  nfp_err (*open)(void * ctx);
  nfp_err (*close)(void * ctx);
  nfp_err (*isr)(void *ctx, int *handled);
  nfp_err (*write_block)( const char *ublock, int len, void *ctx );
  nfp_err (*read_block)( char *ublock, int len, void *ctx, int *rcount);
  nfp_err (*channel_update)( char *data, int len, void *ctx);
  nfp_err (*ensure_reading)( unsigned int addr, int len, void *ctx );
  nfp_err (*debug)( int cmd, void *ctx);
} nfpcmd_dev;

#define NFP_CMD_FLG_NEED_IOBUF	0x1

/* list of all supported drivers ---------------------------------------- */

extern const nfpcmd_dev *nfp_drvlist[];

extern const nfpcmd_dev i21285_cmddev;
extern const nfpcmd_dev i21555_cmddev;
extern const nfpcmd_dev bcm5820_cmddev;

#ifndef PCI_BASE_ADDRESS_SPACE_IO
#define PCI_BASE_ADDRESS_SPACE_IO	0x1
#endif

#define NFP_MAXDEV	16


#define NFP_MEMBAR_MASK    ~0xf
#define NFP_IOBAR_MASK     ~0x3
/*
   This masks off the bottom bits of the PCI_CSR_BAR which signify that the
   BAR is an IO BAR rather than a MEM BAR 
*/ 

#endif

