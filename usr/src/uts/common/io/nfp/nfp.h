/*

nfp.h: nFast PCI driver for Solaris 2.5, 2.6 and 2.7

(C) Copyright nCipher Corporation Ltd 2001-2008 All rights reserved

Copyright (c) 2008-2013 Thales e-Security All rights reserved

Copyright (c) 2014 Thales UK All rights reserved

history

06/05/1998 jsh  Original solaris 2.6
21/05/1999 jsh  added support for solaris 2.5
10/06/1999 jsh  added support for solaris 2.7 (32 and 64 bit)
16/10/2001 jsh  moved from nfast to new structure in nfdrv

*/

#ifndef NFP_H
#define NFP_H

#ifndef _KERNEL
#error Hello?  this is a driver, please compile with -D_KERNEL
#endif

#if ( CH_KERNELVER < 260 )
typedef int ioctlptr_t;
typedef unsigned short uint16_t;
#define DDI_GET32    ddi_getl
#define DDI_PUT32    ddi_putl
#define DDI_GET16    ddi_getw
#define DDI_PUT16    ddi_putw
#define DDI_REP_GET8 ddi_rep_getb
#define DDI_REP_PUT8 ddi_rep_putb
#define DDI_REP_GET32 ddi_rep_getl
#define DDI_REP_PUT32 ddi_rep_putl
#define PCI_CONFIG_GET16 pci_config_getw
#else /* ( CH_KERNELVER >= 260 ) */
typedef intptr_t ioctlptr_t;
#define DDI_GET32    ddi_get32
#define DDI_PUT32    ddi_put32
#define DDI_GET16    ddi_get16
#define DDI_PUT16    ddi_put16
#define DDI_REP_GET8 ddi_rep_get8
#define DDI_REP_PUT8 ddi_rep_put8
#define DDI_REP_GET32 ddi_rep_get32
#define DDI_REP_PUT32 ddi_rep_put32
#define PCI_CONFIG_GET16 pci_config_get16
#endif

#if ( CH_KERNELVER < 270 )
typedef int nfp_timeout_t;
#define EXTRA_CB_FLAGS 0
#define VSXPRINTF(s, n, format, ap) vsprintf (s, format, ap)
#else /* ( CH_KERNELVER >= 270 ) */
typedef timeout_id_t nfp_timeout_t;
#define EXTRA_CB_FLAGS D_64BIT
#define VSXPRINTF(s, n, format, ap) vsnprintf(s, n, format, ap)
#endif

typedef struct nfp_dev {
  int rd_ok;
  int wr_ok;

  int ifvers;

  /* for PCI push read interface */
  unsigned char *read_buf;
  ddi_dma_handle_t read_dma_handle;
  ddi_dma_cookie_t read_dma_cookie;

  ddi_acc_handle_t acchandle;

  int rd_dma_ok;

  nfp_timeout_t wrtimeout;
  nfp_timeout_t rdtimeout;

  struct buf *wr_bp;
  int wr_ready;
  int rd_ready;
  int rd_pending;
  int rd_outstanding;
  kcondvar_t rd_cv;

  struct pollhead pollhead;
  dev_info_t *dip;

  ddi_iblock_cookie_t high_iblock_cookie; /* for mutex */
  ddi_iblock_cookie_t low_iblock_cookie; /* for mutex */
  kmutex_t high_mutex;
  kmutex_t low_mutex;
  int high_intr;
  ddi_softintr_t soft_int_id;
  int high_read;
  int high_write;

  ddi_iblock_cookie_t iblock_cookie; /* for mutex */
  kmutex_t isr_mutex;

  kmutex_t busy_mutex;
  int busy;
 
  ddi_acc_handle_t conf_handle;

  nfp_cdev common;
  const nfpcmd_dev *cmddev;
} nfp_dev;

extern struct nfp_dev *nfp_dev_list[];

#endif /* NFP_H */
