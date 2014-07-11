/*

i21555.c: nCipher PCI HSM intel 21555 command driver

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
#include "i21555.h"
#include "nfp_cmd.h"
#include "nfpci.h"

/* started ------------------------------------------------------
 *
 * Check that device is ready to talk, by checking that
 * the i21555 has master enabled on its secondary interface
 */

static nfp_err i21555_started( nfp_cdev *pdev ) {
  unsigned int tmp32;
#ifdef CONFIGSPACE_DEBUG
  unsigned int reg32[64];
  int i;
#endif
  nfp_err ne;

  nfp_log( NFP_DBG2, "i21555_started: entered");

#ifdef CONFIGSPACE_DEBUG
  /* Suck up all the registers */
  for (i=0; i < 64; i++) {
    ne = nfp_config_inl( pdev, i*4, &reg32[i] );
  }

  for (i=0; i < 16; i++) {
    int j = i * 4;
    nfp_log( NFP_DBG3, "i21555 config reg %2x: %08x %08x %08x %08x", j*4,
        reg32[j], reg32[j+1], reg32[j+2], reg32[j+3]);
  }
#endif

  ne = nfp_config_inl( pdev, I21555_CFG_SEC_CMD_STATUS, &tmp32 );
  if (ne) {
    /* succeed if PCI config reads are not implemented */
    if (ne == NFP_EUNKNOWN)
      return NFP_SUCCESS;
    nfp_log( NFP_DBG1, "i21555_started: nfp_config_inl failed");
    return ne;
  }

  tmp32= FROM_LE32_IO(&tmp32) & 0xffff;

  if ( tmp32 & CFG_CMD_MASTER ) {
    nfp_log( NFP_DBG3, "i21555_started: Yes %x", tmp32);
    return NFP_SUCCESS;
  } else {
    nfp_log( NFP_DBG1, "i21555_started: device not started yet %x", tmp32);
    return NFP_ESTARTING;
  }
}

/* create ------------------------------------------------------- */

static nfp_err i21555_create( nfp_cdev *pdev ) {
  unsigned int tmp32;

  nfp_log( NFP_DBG2, "i21555_create: entered");
  pdev->cmdctx= pdev;  /* set our context to just be a pointer to our nfp_cdev */

  if(!pdev->bar[ IOBAR ]) {
    nfp_log( NFP_DBG1, "i21555_create: null BAR[%d]", IOBAR );
    return NFP_ENOMEM;
  }
  nfp_log( NFP_DBG2, "i21555_create: enable doorbell");
  TO_LE32_IO( &tmp32, I21555_DOORBELL_PRI_ENABLE );
  nfp_outl( pdev, IOBAR, I21555_OFFSET_DOORBELL_PRI_SET_MASK, tmp32 );
  nfp_outl( pdev, IOBAR, I21555_OFFSET_DOORBELL_PRI_CLEAR_MASK, tmp32 );
  return NFP_SUCCESS;
}

/* stop ------------------------------------------------------- */

static nfp_err i21555_destroy( void * ctx ) {
  nfp_cdev *pdev;
  unsigned int tmp32;

  nfp_log( NFP_DBG2, "i21555_destroy: entered");

  pdev= (nfp_cdev *)ctx;
  if(!pdev) {
    nfp_log( NFP_DBG1, "i21555_destroy: NULL pdev");
    return NFP_ENODEV;
  }
  if(!pdev->bar[ IOBAR ]) {
    nfp_log( NFP_DBG1, "i21555_destroy: null BAR[%d]", IOBAR );
    return NFP_ENOMEM;
  }
  TO_LE32_IO( &tmp32, I21555_DOORBELL_PRI_DISABLE );
  nfp_outl( pdev, IOBAR, I21555_OFFSET_DOORBELL_PRI_SET_MASK, tmp32 );
  nfp_outl( pdev, IOBAR, I21555_OFFSET_DOORBELL_PRI_CLEAR_MASK, tmp32 );

  return NFP_SUCCESS;
}

/* open ------------------------------------------------------- */

/* ARGSUSED */
static nfp_err i21555_open( void * ctx ) {

  nfp_log( NFP_DBG2, "i21555_open: entered");

  return NFP_SUCCESS;
}

/* close ------------------------------------------------------- */

/* ARGSUSED */
static nfp_err i21555_close( void * ctx ) {
  nfp_log( NFP_DBG2, "i21555_close: entered");

  return NFP_SUCCESS;
}

/* isr ------------------------------------------------------- */

static nfp_err i21555_isr( void *ctx, int *handled ) {
  nfp_cdev *pdev;
  nfp_err ne;
  unsigned short doorbell;
  unsigned short tmp16;

  nfp_log( NFP_DBG3, "i21555_isr: entered");

  *handled= 0;
  pdev= (nfp_cdev *)ctx;
  if(!pdev) {
    nfp_log( NFP_DBG1, "i21555_isr: NULL pdev");
    return NFP_ENODEV;
  }

  pdev->stats.isr++;

  if(!pdev->bar[ IOBAR ]) {
    nfp_log( NFP_DBG1, "i21555_isr: null BAR[%d]", IOBAR );
    return NFP_ENOMEM;
  }

  /* This interrupt may not be from our module, so check that it actually is
   * us before handling it.
   */
  ne = i21555_started( pdev );
  if (ne) {
    if (ne != NFP_ESTARTING) {
      nfp_log( NFP_DBG1, "i21555_isr: i21555_started failed");
    }
    return ne;
  }

  doorbell= nfp_inw( pdev, IOBAR, I21555_OFFSET_DOORBELL_PRI_SET);
  doorbell= FROM_LE16_IO(&doorbell);
  while( doorbell && doorbell != 0xffff) {
    *handled= 1;
    /* service interrupts */
    if( doorbell & (NFAST_INT_DEVICE_WRITE_OK | NFAST_INT_DEVICE_WRITE_FAILED)) {
      pdev->stats.isr_write++;
      TO_LE16_IO(&tmp16,NFAST_INT_DEVICE_WRITE_OK | NFAST_INT_DEVICE_WRITE_FAILED);
      nfp_outw( pdev, IOBAR, I21555_OFFSET_DOORBELL_PRI_CLEAR, tmp16 );

      nfp_log( NFP_DBG2, "i21555_isr: write done interrupt, ok = %d.", doorbell & NFAST_INT_DEVICE_WRITE_OK ? 1 : 0 );

      nfp_write_complete(pdev->dev, doorbell & NFAST_INT_DEVICE_WRITE_OK ? 1 : 0 );
    }

    if( doorbell & (NFAST_INT_DEVICE_READ_OK | NFAST_INT_DEVICE_READ_FAILED)) {
      pdev->stats.isr_read++;
      TO_LE16_IO(&tmp16,NFAST_INT_DEVICE_READ_OK | NFAST_INT_DEVICE_READ_FAILED);
      nfp_outw( pdev, IOBAR, I21555_OFFSET_DOORBELL_PRI_CLEAR, tmp16 );

      nfp_log( NFP_DBG2, "i21555_isr: read ack interrupt, ok = %d.", doorbell & NFAST_INT_DEVICE_READ_OK ? 1 : 0 );
      nfp_read_complete( pdev->dev, doorbell & NFAST_INT_DEVICE_READ_OK ? 1 : 0);
    }

    if( doorbell & ~(NFAST_INT_DEVICE_READ_OK  | NFAST_INT_DEVICE_READ_FAILED |
                     NFAST_INT_DEVICE_WRITE_OK | NFAST_INT_DEVICE_WRITE_FAILED)) {
      TO_LE16_IO(&tmp16,doorbell);
      nfp_outw( pdev, IOBAR, I21555_OFFSET_DOORBELL_PRI_CLEAR, tmp16 );
      nfp_log( NFP_DBG1, "i21555_isr: unexpected interrupt %x", doorbell );
    }
    doorbell= nfp_inw( pdev, IOBAR, I21555_OFFSET_DOORBELL_PRI_SET);
    doorbell= FROM_LE16_IO(&doorbell);
  }
  nfp_log( NFP_DBG3, "i21555_isr: exiting");
  return 0;
}

/* write ------------------------------------------------------- */

static nfp_err i21555_write( const char *block, int len, void *ctx) {
  nfp_cdev *cdev;
  unsigned int hdr[2];
  nfp_err ne;
  unsigned short tmp16;
  unsigned int tmp32;

  nfp_log( NFP_DBG2, "i21555_write: entered");

  cdev= (nfp_cdev *)ctx;
  if(!cdev) {
    nfp_log( NFP_DBG1, "i21555_write: NULL cdev");
    return NFP_ENODEV;
  }

  cdev->stats.write_fail++;

  if(!cdev->bar[ IOBAR ]) {
    nfp_log( NFP_DBG1, "i21555_write: null BAR[%d]", IOBAR );
    return NFP_ENOMEM;
  }

  ne = i21555_started( cdev );
  if (ne) {
    if (ne != NFP_ESTARTING) {
      nfp_log( NFP_DBG1, "i21555_write: i21555_started failed");
    }
    return ne;
  }

  nfp_log( NFP_DBG3, "i21555_write: cdev->bar[ MEMBAR ]= %x", cdev->bar[ MEMBAR ]);
  nfp_log( NFP_DBG3, "i21555_write: cdev->bar[ IOBAR ]= %x", cdev->bar[ IOBAR ]);
  nfp_log( NFP_DBG3, "i21555_write: block len %d", len ); 
  ne= nfp_copy_from_user_to_dev( cdev, MEMBAR, NFPCI_JOBS_WR_DATA, block, len);
  if (ne) {
    nfp_log( NFP_DBG1, "i21555_write: nfp_copy_from_user_to_dev failed");
    return ne;
  }
  TO_LE32_MEM(&hdr[0], NFPCI_JOB_CONTROL);
  TO_LE32_MEM(&hdr[1], len);
  ne= nfp_copy_to_dev( cdev, MEMBAR, NFPCI_JOBS_WR_CONTROL, (const char *)hdr, 8);
  if (ne) {
    nfp_log( NFP_DBG1, "i21555_write: nfp_copy_to_dev failed");
    return ne;
  }

  ne= nfp_copy_from_dev( cdev, MEMBAR, NFPCI_JOBS_WR_LENGTH, (char *)hdr, 4);
  if (ne) {
    nfp_log( NFP_DBG1, "i21555_write: nfp_copy_from_dev failed");
    return ne;
  }

  TO_LE32_MEM(&tmp32, len);
  if ( hdr[0] != tmp32 ) {
    nfp_log( NFP_DBG1, "i21555_write: length not written");
    return NFP_EIO;
  }
  TO_LE16_IO(&tmp16, NFAST_INT_HOST_WRITE_REQUEST >> 16);
  nfp_outw( cdev, IOBAR, I21555_OFFSET_DOORBELL_SEC_SET, tmp16);

  cdev->stats.write_fail--;
  cdev->stats.write_block++;
  cdev->stats.write_byte += len;

  nfp_log( NFP_DBG2, "i21555_write: done");
  return NFP_SUCCESS;
}

/* read ------------------------------------------------------- */

static nfp_err i21555_read( char *block, int len, void *ctx, int *rcount) {
  nfp_cdev *cdev;
  nfp_err ne;
  int count;

  nfp_log( NFP_DBG2, "i21555_read: entered");
  *rcount= 0;

  cdev= (nfp_cdev *)ctx;
  if(!cdev) {
    nfp_log( NFP_DBG1, "i21555_read: NULL pdev");
    return NFP_ENODEV;
  }

  cdev->stats.read_fail++;

  if(!cdev->bar[ IOBAR ]) {
    nfp_log( NFP_DBG1, "i21555_read: null BAR[%d]", IOBAR );
    return NFP_ENOMEM;
  }

  ne= nfp_copy_from_dev( cdev, MEMBAR, NFPCI_JOBS_RD_LENGTH, (char *)&count, 4);
  if (ne) {
    nfp_log( NFP_DBG1, "i21555_read: nfp_copy_from_dev failed.");
    return ne;
  }
  count= FROM_LE32_MEM(&count);
  if(count<0 || count>len) {
    nfp_log( NFP_DBG1, "i21555_read: bad byte count (%d) from device", count);
    return NFP_EIO;
  }
  ne= nfp_copy_to_user_from_dev( cdev, MEMBAR, NFPCI_JOBS_RD_DATA, block, count);
  if (ne) {
    nfp_log( NFP_DBG1, "i21555_read: nfp_copy_to_user failed.");
    return ne;
  }
  nfp_log( NFP_DBG2, "i21555_read: done");
  *rcount= count;
  cdev->stats.read_fail--;
  cdev->stats.read_block++;
  cdev->stats.read_byte += len;
  return NFP_SUCCESS;
}

/* chupdate  ------------------------------------------------------- */

/* ARGSUSED */
static nfp_err i21555_chupdate( char *data, int len, void *ctx ) {
  nfp_log( NFP_DBG1, "i21555_chupdate: NYI");
  return NFP_SUCCESS;
}

/* ensure reading -------------------------------------------------- */

static nfp_err i21555_ensure_reading( unsigned int addr, int len, void *ctx ) {
  nfp_cdev *cdev;
  unsigned int hdr[3];
  unsigned short tmp16;
  unsigned int tmp32;
  nfp_err ne;
  int hdr_len;

  nfp_log( NFP_DBG2, "i21555_ensure_reading: entered");

  cdev= (nfp_cdev *)ctx;
  if(!cdev) {
    nfp_log( NFP_DBG1, "i21555_ensure_reading: NULL pdev");
    return NFP_ENODEV;
  }

  cdev->stats.ensure_fail++;

  if(!cdev->bar[ IOBAR ]) {
    nfp_log( NFP_DBG1, "i21555_ensure_reading: null BAR[%d]", IOBAR );
    return NFP_ENOMEM;
  }

  ne = i21555_started( cdev );
  if (ne) {
    if (ne != NFP_ESTARTING) {
      nfp_log( NFP_DBG1, "i21555_ensure_reading: i21555_started failed");
    }
    return ne;
  }

  nfp_log( NFP_DBG3, "i21555_ensure_reading: pdev->bar[ MEMBAR ]= %x", cdev->bar[ MEMBAR ]);
  nfp_log( NFP_DBG3, "i21555_ensure_reading: pdev->bar[ IOBAR ]= %x", cdev->bar[ IOBAR ]);
  if(addr) {
    nfp_log( NFP_DBG3, "i21555_ensure_reading: new format, addr %x", addr);
    TO_LE32_MEM(&hdr[0], NFPCI_JOB_CONTROL_PCI_PUSH);
    TO_LE32_MEM(&hdr[1], len);
    TO_LE32_MEM(&hdr[2], addr);
    hdr_len= 12;
  } else {
    TO_LE32_MEM(&hdr[0], NFPCI_JOB_CONTROL);
    TO_LE32_MEM(&hdr[1], len);
    hdr_len= 8;
  }
  ne= nfp_copy_to_dev( cdev, MEMBAR, NFPCI_JOBS_RD_CONTROL, (const char *)hdr, hdr_len);
  if (ne) {
    nfp_log( NFP_DBG1, "i21555_ensure_reading: nfp_copy_to_dev failed");
    return ne;
  }

  ne= nfp_copy_from_dev( cdev, MEMBAR, NFPCI_JOBS_RD_LENGTH, (char *)hdr, 4);
  if (ne) {
    nfp_log( NFP_DBG1, "i21555_ensure_reading: nfp_copy_from_dev failed");
    return ne;
  }

  TO_LE32_MEM(&tmp32, len);

  if ( hdr[0] != tmp32 ) {
    nfp_log( NFP_DBG1, "i21555_ensure_reading: len not written");
    return NFP_EIO;
  }
  TO_LE16_IO( &tmp16, NFAST_INT_HOST_READ_REQUEST >> 16);
  nfp_outw( cdev, IOBAR, I21555_OFFSET_DOORBELL_SEC_SET, tmp16);

  cdev->stats.ensure_fail--;
  cdev->stats.ensure++;

  return NFP_SUCCESS;
}

/* command device structure ------------------------------------- */

const nfpcmd_dev i21555_cmddev = {
  "nCipher Gen 2 PCI",
  PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_21555,
  PCI_VENDOR_ID_NCIPHER, PCI_SUBSYSTEM_ID_NFAST_REV1,
  { 0, IOSIZE | PCI_BASE_ADDRESS_SPACE_IO, NFPCI_RAM_MINSIZE_JOBS, 0, 0, 0 },
  NFP_CMD_FLG_NEED_IOBUF,
  i21555_create,
  i21555_destroy,
  i21555_open,
  i21555_close,
  i21555_isr,
  i21555_write,
  i21555_read,
  i21555_chupdate,
  i21555_ensure_reading,
  i21555_debug,
};
