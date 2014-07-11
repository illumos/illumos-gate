/*

i21285.c: nCipher PCI HSM intel/digital 21285 command driver

(C) Copyright nCipher Corporation Ltd 2002-2008 All rights reserved

Copyright (c) 2008-2013 Thales e-Security All rights reserved

Copyright (c) 2014 Thales UK All rights reserved


history

09/10/2001 jsh  Original

*/

#include "nfp_common.h"
#include "nfp_error.h"
#include "nfp_hostif.h"
#include "nfp_osif.h"
#include "i21285.h"
#include "nfp_cmd.h"
#include "nfpci.h"

/* create ------------------------------------------------------- */

static nfp_err i21285_create( nfp_cdev *pdev ) {
  unsigned int tmp32;

  nfp_log( NFP_DBG2, "i21285_create: entered");
  pdev->cmdctx= pdev;  /* set our context to just be a pointer to our nfp_cdev */

  nfp_log( NFP_DBG2, "i21285_create: enable doorbell");
  if(!pdev->bar[ IOBAR ]) {
    nfp_log( NFP_DBG1, "i21285_create: null BAR[%d]", IOBAR );
    return NFP_ENOMEM;
  }
  TO_LE32_IO( &tmp32, DOORBELL_ENABLE | POSTLIST_ENABLE);
  nfp_outl( pdev, IOBAR, I21285_OFFSET_INTERRUPT_MASK, tmp32 );

  return NFP_SUCCESS;
}

/* stop ------------------------------------------------------- */

static nfp_err i21285_destroy( void * ctx ) {
  nfp_cdev *pdev;
  unsigned int tmp32;

  nfp_log( NFP_DBG2, "i21285_destroy: entered");

  pdev= (nfp_cdev *)ctx;
  if(!pdev) {
    nfp_log( NFP_DBG1, "i21285_destroy: NULL pdev");
    return NFP_ENODEV;
  }
  if(!pdev->bar[ IOBAR ]) {
    nfp_log( NFP_DBG1, "i21285_destroy: null BAR[%d]", IOBAR );
    return NFP_ENOMEM;
  }
  TO_LE32_IO( &tmp32, DOORBELL_DISABLE | POSTLIST_DISABLE );
  nfp_outl( pdev, IOBAR, I21285_OFFSET_INTERRUPT_MASK, tmp32 );

  return NFP_SUCCESS;
}

/* open ------------------------------------------------------- */

/* ARGSUSED */
static nfp_err i21285_open( void * ctx ) {
  nfp_log( NFP_DBG2, "i21285_open: entered");

  return NFP_SUCCESS;
}

/* close ------------------------------------------------------- */

/* ARGSUSED */
static nfp_err i21285_close( void * ctx ) {
  nfp_log( NFP_DBG2, "i21285_close: entered");

  return NFP_SUCCESS;
}

/* isr ------------------------------------------------------- */

static nfp_err i21285_isr( void *ctx, int *handled ) {
  nfp_cdev *pdev;
  unsigned int doorbell;
  unsigned int tmp32;

  nfp_log( NFP_DBG3, "i21285_isr: entered");

  *handled= 0;
  pdev= (nfp_cdev *)ctx;
  if(!pdev) {
    nfp_log( NFP_DBG1, "i21285_isr: NULL pdev");
    return NFP_ENODEV;
  }

  doorbell= nfp_inl( pdev, IOBAR, I21285_OFFSET_DOORBELL);
  doorbell= FROM_LE32_IO(&doorbell) & 0xffff;
  while( doorbell && doorbell != 0xffff) {
    *handled= 1;
    /* service interrupts */
    if( doorbell & (NFAST_INT_DEVICE_WRITE_OK | NFAST_INT_DEVICE_WRITE_FAILED)) {
      TO_LE32_IO( &tmp32, NFAST_INT_DEVICE_WRITE_OK | NFAST_INT_DEVICE_WRITE_FAILED);
      nfp_outl( pdev, IOBAR, I21285_OFFSET_DOORBELL, tmp32 );

      nfp_log(NFP_DBG2, "i21285_isr: write done interrupt, ok = %d.", doorbell & NFAST_INT_DEVICE_WRITE_OK ? 1 : 0 );

      nfp_write_complete(pdev->dev, doorbell & NFAST_INT_DEVICE_WRITE_OK ? 1 : 0 );
    }

    if( doorbell & (NFAST_INT_DEVICE_READ_OK | NFAST_INT_DEVICE_READ_FAILED)) {
       TO_LE32_IO( &tmp32, NFAST_INT_DEVICE_READ_OK | NFAST_INT_DEVICE_READ_FAILED );
       nfp_outl( pdev, IOBAR, I21285_OFFSET_DOORBELL, tmp32 );

      nfp_log(NFP_DBG2, "i21285_isr: read ack interrupt, ok = %d.", doorbell & NFAST_INT_DEVICE_READ_OK ? 1 : 0 );
      nfp_read_complete( pdev->dev, doorbell & NFAST_INT_DEVICE_READ_OK ? 1 : 0);
    }

    if( doorbell & ~(NFAST_INT_DEVICE_READ_OK  | NFAST_INT_DEVICE_READ_FAILED |
                     NFAST_INT_DEVICE_WRITE_OK | NFAST_INT_DEVICE_WRITE_FAILED)) {
      nfp_log( NFP_DBG1, "i21285_isr: unexpected interrupt %x", doorbell );
      TO_LE32_IO( &tmp32, 0xffff & doorbell );
      nfp_outl( pdev, IOBAR, I21285_OFFSET_DOORBELL, tmp32 );
    }
    doorbell= nfp_inl( pdev, IOBAR, I21285_OFFSET_DOORBELL);
    doorbell= FROM_LE32_IO(&doorbell) & 0xffff;
  }
  return 0;
}

/* write ------------------------------------------------------- */

static nfp_err i21285_write( const char *block, int len, void *ctx ) {
  nfp_cdev *cdev;
  unsigned int hdr[2];
  nfp_err ne;
  unsigned int tmp32;

  nfp_log( NFP_DBG2, "i21285_write: entered");

  cdev= (nfp_cdev *)ctx;
  if(!cdev) {
    nfp_log( NFP_DBG1, "i21285_write: NULL pdev");
    return NFP_ENODEV;
  }

  nfp_log(NFP_DBG2, "i21285_write: pdev->bar[ MEMBAR ]= %x\n", cdev->bar[ MEMBAR ]);
  nfp_log(NFP_DBG2, "i21285_write: pdev->bar[ IOBAR ]= %x\n", cdev->bar[ IOBAR ]);
  if(!cdev->bar[ MEMBAR ]) {
    nfp_log( NFP_DBG1, "i21285_write: null BAR[%d]", MEMBAR );
    return NFP_ENOMEM;
  }
  ne= nfp_copy_from_user_to_dev( cdev, MEMBAR, NFPCI_JOBS_WR_DATA, block, len);
  if (ne) {
    nfp_log( NFP_DBG1, "i21285_write: nfp_copy_from_user_to_dev failed");
    return ne;
  }
  TO_LE32_MEM(&hdr[0], NFPCI_JOB_CONTROL);
  TO_LE32_MEM(&hdr[1], len);

  ne= nfp_copy_to_dev( cdev, MEMBAR, NFPCI_JOBS_WR_CONTROL, (const char *)hdr, 8);
  if (ne) {
    nfp_log( NFP_DBG1, "i21285_write: nfp_copy_to_dev failed");
    return ne;
  }

  ne= nfp_copy_from_dev( cdev, MEMBAR, NFPCI_JOBS_WR_LENGTH, (char *)hdr, 4);
  if (ne) {
    nfp_log( NFP_DBG1, "i21285_write: nfp_copy_from_dev failed");
    return ne;
  }
  
  TO_LE32_MEM( &tmp32, len );
  if ( hdr[0] != tmp32 ) {
    nfp_log( NFP_DBG1, "i21285_write: length not written");
    return NFP_EIO;
  }

  TO_LE32_IO( &tmp32, NFAST_INT_HOST_WRITE_REQUEST);

  nfp_outl( cdev, IOBAR, I21285_OFFSET_DOORBELL, tmp32 );

  nfp_log( NFP_DBG2, "i21285_write: done");
  return NFP_SUCCESS;
}

/* read ------------------------------------------------------- */

static nfp_err i21285_read( char *block, int len, void *ctx, int *rcount) {
  nfp_cdev *cdev;
  nfp_err ne;
  int count;

  nfp_log( NFP_DBG2, "i21285_read: entered, len %d", len);
  *rcount= 0;

  cdev= (nfp_cdev *)ctx;
  if(!cdev) {
    nfp_log( NFP_DBG1, "i21285_read: NULL pdev");
    return NFP_ENODEV;
  }

  if(!cdev->bar[ MEMBAR ]) {
    nfp_log( NFP_DBG1, "i21285_read: null BAR[%d]", MEMBAR );
    return NFP_ENOMEM;
  }
  ne= nfp_copy_from_dev( cdev, MEMBAR, NFPCI_JOBS_RD_LENGTH, (char *)&count, 4);
  if(ne) {
    nfp_log( NFP_DBG1, "i21285_read: nfp_copy_from_dev failed.");
    return ne;
  }
  count= FROM_LE32_MEM(&count);
  if(count<0 || count>len) {
    nfp_log( NFP_DBG1, "i21285_read: bad byte count (%d) from device", count);
    return NFP_EIO;
  }
  ne= nfp_copy_to_user_from_dev( cdev, MEMBAR, NFPCI_JOBS_RD_DATA, block, count);
  if( ne ) {
    nfp_log( NFP_DBG1, "i21285_read: nfp_copy_to_user_from_dev failed.");
    return ne;
  }
  nfp_log( NFP_DBG2, "i21285_read: done");
  *rcount= count;
  return NFP_SUCCESS;
}

/* chupdate  ------------------------------------------------------- */

/* ARGSUSED */
static nfp_err i21285_chupdate( char *data, int len, void *ctx ) {
  nfp_log( NFP_DBG1, "i21285_chupdate: NYI");
  return NFP_SUCCESS;
}

/* ensure reading -------------------------------------------------- */

static nfp_err i21285_ensure_reading( unsigned int addr, int len, void *ctx ) {
  nfp_cdev *cdev;
  unsigned int hdr[2];
  unsigned int tmp32;
  nfp_err ne;

  nfp_log( NFP_DBG2, "i21285_ensure_reading: entered");

  if(addr) {
    nfp_log( NFP_DBG2, "i21285_ensure_reading: bad addr");
    return -NFP_EINVAL;
  }

  cdev= (nfp_cdev *)ctx;
  if(!cdev) {
    nfp_log( NFP_DBG1, "i21285_ensure_reading: NULL pdev");
    return NFP_ENODEV;
  }

  if(!cdev->bar[ MEMBAR ]) {
    nfp_log( NFP_DBG1, "i21285_ensure_reading: null BAR[%d]", MEMBAR );
    return NFP_ENXIO;
  }
  nfp_log( NFP_DBG3, "i21285_ensure_reading: pdev->bar[ MEMBAR ]= %x", cdev->bar[ MEMBAR ]);
  nfp_log( NFP_DBG3, "i21285_ensure_reading: pdev->bar[ IOBAR ]= %x", cdev->bar[ IOBAR ]);
  TO_LE32_MEM( &hdr[0], NFPCI_JOB_CONTROL);
  TO_LE32_MEM( &hdr[1], len);
  ne= nfp_copy_to_dev( cdev, MEMBAR, NFPCI_JOBS_RD_CONTROL, (const char *)hdr, 8);
  if (ne) {
    nfp_log( NFP_DBG1, "i21285_ensure_reading: nfp_copy_to_dev failed");
    return ne;
  }
  ne= nfp_copy_from_dev( cdev, MEMBAR, NFPCI_JOBS_RD_LENGTH, (char *)hdr, 4);
  if (ne) {
    nfp_log( NFP_DBG1, "i21285_ensure_reading: nfp_copy_from_dev failed");
    return ne;
  }
  TO_LE32_MEM( &tmp32, len );
  if ( hdr[0] != tmp32 ) {
    nfp_log( NFP_DBG1, "i21285_ensure_reading: len not written");
    return NFP_EIO;
  };
  TO_LE32_IO( &tmp32, NFAST_INT_HOST_READ_REQUEST );
  nfp_outl( cdev, IOBAR, I21285_OFFSET_DOORBELL, tmp32 );

  return NFP_SUCCESS;
}

/* command device structure ------------------------------------- */


const nfpcmd_dev i21285_cmddev = {
  "nCipher Gen 1 PCI",
  PCI_VENDOR_ID_DEC, PCI_DEVICE_ID_DEC_21285,
  PCI_VENDOR_ID_NCIPHER, PCI_DEVICE_ID_NFAST_GEN1,
  { 0, IOSIZE | PCI_BASE_ADDRESS_SPACE_IO, NFPCI_RAM_MINSIZE, 0, 0, 0 },
  NFP_CMD_FLG_NEED_IOBUF,
  i21285_create,
  i21285_destroy,
  i21285_open,
  i21285_close,
  i21285_isr,
  i21285_write,
  i21285_read,
  i21285_chupdate,
  i21285_ensure_reading,
  0, /* no debug */
};
  
