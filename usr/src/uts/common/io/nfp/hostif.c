/*

hostif.c: nFast PCI driver for Solaris 2.5, 2.6, 2.7 and 2.8

(C) Copyright nCipher Corporation Ltd 2002-2008 All rights reserved

Copyright (c) 2008-2013 Thales e-Security All rights reserved

Copyright (c) 2014 Thales UK All rights reserved

history

06/05/1998 jsh  Original solaris 2.6
21/05/1999 jsh  added support for solaris 2.5
10/06/1999 jsh  added support for solaris 2.7 (32 and 64 bit)
??/??/2001 jsh  added support for solaris 2.8 (32 and 64 bit)
16/10/2001 jsh  moved from nfast to new structure in nfdrv
12/02/2002 jsh  added high level interrupt support

*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/map.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>

#include "nfp_common.h"
#include "nfp_hostif.h"
#include "nfp_osif.h"
#include "nfp_cmd.h"

#include "nfp.h"

/* mapped memory attributes, no-swap endianess (done in higher level) */
static struct ddi_device_acc_attr nosw_attr = {
  DDI_DEVICE_ATTR_V0,
  DDI_NEVERSWAP_ACC,
  DDI_STRICTORDER_ACC
};

/* dma attributes */
static ddi_dma_attr_t dma_attrs = {
  DMA_ATTR_V0,            /* version number */
  (uint64_t)0x0,          /* low address */
  (uint64_t)0xffffffff,   /* high address */
  (uint64_t)0xffffff,     /* DMA counter max */
  (uint64_t)0x1,          /* alignment */
  0x0c,                   /* burst sizes */
  0x1,                    /* minimum transfer size */
  (uint64_t)0x3ffffff,    /* maximum transfer size */
  (uint64_t)0x7fff,       /* maximum segment size */
  1,                      /* no scatter/gather lists */
  1,                      /* granularity */
  0                       /* DMA flags */
};

/*
 * Debug message control
 * Debug Levels:
 *  0 = no messages
 *  1 = Errors
 *  2 = Subroutine calls & control flow
 *  3 = I/O Data (verbose!)
 * Can be set with adb or in the /etc/system file with
 * "set nfp:nfp_debug=<value>"
 */

int nfp_debug= 1;

static void *state_head; /* opaque handle top of state structs */

static int nfp_open(dev_t *dev, int openflags, int otyp, cred_t *credp);
static int nfp_close(dev_t dev, int openflags, int otyp, cred_t *credp);
static int nfp_release_dev( dev_info_t *dip );

static int nfp_read(dev_t dev, struct uio *uiop, cred_t *credp);
static int nfp_write(dev_t dev, struct uio *uiop, cred_t *credp);
static int nfp_strategy(struct buf *bp);

static int nfp_ioctl(dev_t dev, int cmd, ioctlptr_t arg, int mode, cred_t *credp, int *rvalp);
static int nfp_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
                    struct pollhead **phpp);

static void nfp_wrtimeout (void *pdev);
static void nfp_rdtimeout (void *pdev);

static int nfp_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result);
static int nfp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int nfp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static void nfp_read_complete_final(nfp_dev *pdev, int ok);
static void nfp_write_complete_final(nfp_dev *pdev, int ok);

/* nfp file ops --------------------------------------------------- */

static struct cb_ops nfp_cb_ops = {
  nfp_open,
  nfp_close,
  nodev,                /* no nfp_strategy */
  nodev,                /* no print routine */
  nodev,                /* no dump routine */
  nfp_read,
  nfp_write,
  nfp_ioctl,
  nodev,                /* no devmap routine */
  nodev,                /* no mmap routine */
  nodev,                /* no segmap routine */
  nfp_chpoll,
  ddi_prop_op,
  0,            /* not a STREAMS driver, no cb_str routine */
  D_NEW | D_MP | EXTRA_CB_FLAGS, /* must be safe for multi-thread/multi-processor */
  CB_REV,
  nodev,                /* aread */
  nodev                 /* awrite */
};

static struct dev_ops nfp_ops = {
  DEVO_REV,               /* DEVO_REV indicated by manual */
  0,                      /* device reference count       */
  nfp_getinfo,
  nulldev,                /* identify */
  nulldev,                /* probe */
  nfp_attach,
  nfp_detach,
  nodev,                  /* device reset routine         */
  &nfp_cb_ops,
  (struct bus_ops *)0,    /* bus operations               */
};

extern struct mod_ops mod_driverops;
static struct modldrv modldrv = {
  &mod_driverops,
  NFP_DRVNAME,
  &nfp_ops,
};

static struct modlinkage modlinkage = {
  MODREV_1,               /* MODREV_1 indicated by manual */
  (void *)&modldrv,
  NULL,                   /* termination of list of linkage structures */
};

/* interface resource allocation */

int nfp_alloc_pci_push( nfp_dev *pdev ) {
  /* allocate resources needed for PCI Push,
   * if not already allocated.
   * return True if successful
   */
  nfp_err ret;
  uint_t cookie_count;
	size_t real_length;

  if(!pdev->read_buf) {
    /* allocate read buffer */
    pdev->read_buf = kmem_zalloc( NFP_READBUF_SIZE, KM_NOSLEEP );
  }
  if(!pdev->read_buf) {
    nfp_log( NFP_DBG1, "nfp_attach: kmem_zalloc read buffer failed");
    pdev->read_buf = NULL;
    return 0;
  }

  if(!pdev->rd_dma_ok) {
    /* allocate dma handle for read buffer */
    ret = ddi_dma_alloc_handle( pdev->dip,
                                &dma_attrs,
                                DDI_DMA_DONTWAIT,
                                NULL,
                                &pdev->read_dma_handle );
    if( ret != DDI_SUCCESS ) {
      nfp_log( NFP_DBG1,
               "nfp_alloc_pci_push: ddi_dma_alloc_handle failed (%d)",
               ret );
      return 0;
    }

    /* Allocate the memory for dma transfers */
    ret = ddi_dma_mem_alloc(pdev->read_dma_handle, NFP_READBUF_SIZE, &nosw_attr,
			    DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
			    (caddr_t*)&pdev->read_buf, &real_length, &pdev->acchandle);
    if (ret != DDI_SUCCESS) {
      nfp_log( NFP_DBG1, "nfp_alloc_pci_push: ddi_dma_mem_alloc failed (%d)", ret);
      ddi_dma_free_handle( &pdev->read_dma_handle );
      return 0;
    }

    ret = ddi_dma_addr_bind_handle( pdev->read_dma_handle,
                                    NULL, /* kernel address space */
                                    (caddr_t)pdev->read_buf, real_length,
                                    DDI_DMA_READ | DDI_DMA_CONSISTENT, /* dma flags */
                                    DDI_DMA_DONTWAIT, NULL,
                                    &pdev->read_dma_cookie, &cookie_count );
    if( ret != DDI_DMA_MAPPED ) {
      nfp_log( NFP_DBG1,
               "nfp_alloc_pci_push: ddi_dma_addr_bind_handle failed (%d)",
               ret);
      ddi_dma_mem_free(&pdev->acchandle);
      ddi_dma_free_handle( &pdev->read_dma_handle );
      return 0;
    }
    if( cookie_count > 1 ) {
      nfp_log( NFP_DBG1,
               "nfp_alloc_pci_push: error:"
               " ddi_dma_addr_bind_handle wants %d transfers",
               cookie_count);
      ddi_dma_mem_free(&pdev->acchandle);
      (void) ddi_dma_unbind_handle( pdev->read_dma_handle );
      ddi_dma_free_handle( &pdev->read_dma_handle );
      return 0;
    }
    pdev->rd_dma_ok = 1;
  }
  return pdev->rd_dma_ok;
}

void nfp_free_pci_push( nfp_dev *pdev ) {
  /* free resources allocated to PCI Push */
  if( pdev->rd_dma_ok ) {
    (void) ddi_dma_sync(pdev->read_dma_handle,0,0,DDI_DMA_SYNC_FORKERNEL);
    ddi_dma_mem_free(&pdev->acchandle);
    (void) ddi_dma_unbind_handle( pdev->read_dma_handle );
    ddi_dma_free_handle( &pdev->read_dma_handle );
    pdev->rd_dma_ok = 0;
  }
  if( pdev->read_buf ) {
    kmem_free( pdev->read_buf, NFP_READBUF_SIZE );
    pdev->read_buf = NULL;
  }
}

/* include definition of nfp_set_ifvers() */
#define nfp_ifvers NFDEV_IF_PCI_PUSH
#include "nfp_ifvers.c"
#undef nfp_ifvers

/*--------------------*/
/*  nfp_isr           */
/*--------------------*/

static u_int nfp_isr( char *pdev_in ) {
  /* LINTED: alignment */
  nfp_dev *pdev= (nfp_dev *)pdev_in;
  nfp_err ne;
  int handled;

  nfp_log( NFP_DBG3, "nfp_isr: entered");

  if( !pdev ) {
    nfp_log( NFP_DBG1, "nfp_isr: cannot find dev");
    return DDI_INTR_UNCLAIMED;
  }

  /* The isr needs to be mutex'ed - an SMP can call us while we're still
   * running!
   */
  mutex_enter(&pdev->low_mutex);
  ne= pdev->cmddev->isr( pdev->common.cmdctx, &handled );
  mutex_exit(&pdev->low_mutex);

  if( !ne && handled )
    return DDI_INTR_CLAIMED;
  if (ne)
    nfp_log( NFP_DBG1, "nfp_isr: failed");
  else
    nfp_log( NFP_DBG3, "nfp_isr: unclaimed");
  return DDI_INTR_UNCLAIMED;
}

static u_int nfp_soft_isr( char *pdev_in ) {
  /* LINTED: alignment */
  nfp_dev *pdev= (nfp_dev *)pdev_in;
  int rd, wr;

  nfp_log( NFP_DBG3, "nfp_soft_isr: entered");

  if( !pdev ) {
    nfp_log( NFP_DBG1, "nfp_soft_isr: cannot find dev");
    return DDI_INTR_UNCLAIMED;
  }
  rd= wr= 0;
  
  mutex_enter(&pdev->high_mutex);
  if(pdev->high_read) {
    pdev->high_read= 0;
    mutex_exit(&pdev->high_mutex);
    rd= 1;
  }
  if(pdev->high_write) {
    pdev->high_write= 0;
    wr= 1;
  }
  mutex_exit(&pdev->high_mutex);

  if(rd) {
    nfp_log( NFP_DBG3, "nfp_soft_isr: read done");
    nfp_read_complete_final(pdev, pdev->rd_ok);
  }
  if(wr) {
    nfp_log( NFP_DBG3, "nfp_soft_isr: write done");
    nfp_write_complete_final(pdev, pdev->wr_ok);
  }
  if( rd || wr )
    return DDI_INTR_CLAIMED;

  nfp_log( NFP_DBG2, "nfp_isr: unclaimed");
  return DDI_INTR_UNCLAIMED;
}


/*-------------------------*/
/*  nfp_read               */
/*-------------------------*/

void nfp_read_complete(nfp_dev *pdev, int ok) {
  nfp_log( NFP_DBG2,"nfp_read_complete: entering");

  if(pdev->high_intr) {
    nfp_log(NFP_DBG2, "nfp_read_complete: high_intr");
    mutex_enter(&pdev->high_mutex);
    nfp_log(NFP_DBG3, "nfp_read_complete: high_mutex entered");
    if(pdev->high_read)
      nfp_log(NFP_DBG1, "nfp_read_complete: high_read allread set!");
    pdev->high_read= 1;
    pdev->rd_ok= ok;
    nfp_log(NFP_DBG3, "nfp_read_complete: exiting high_mutex");
    mutex_exit(&pdev->high_mutex);
    ddi_trigger_softintr(pdev->soft_int_id);
  } else
    nfp_read_complete_final( pdev, ok );
  nfp_log( NFP_DBG2,"nfp_read_complete: exiting");
}

static void nfp_read_complete_final(nfp_dev *pdev, int ok) {
  nfp_log( NFP_DBG2,"nfp_read_complete_final: entering");
  if(pdev->rdtimeout)
    (void) untimeout(pdev->rdtimeout);
  if(!pdev->rd_outstanding) {
    nfp_log( NFP_DBG1,"nfp_read_complete_final: !pdev->rd_outstanding");
  }
  nfp_log( NFP_DBG2,"nfp_read_complete_final: pdev->rd_outstanding=0, ok %d", ok);
  mutex_enter(&pdev->isr_mutex);
  pdev->rd_outstanding= 0;
  pdev->rd_ready= 1;
  pdev->rd_ok= ok;
  cv_broadcast(&pdev->rd_cv);
  mutex_exit(&pdev->isr_mutex);
  pollwakeup (&pdev->pollhead, POLLRDNORM);
  nfp_log( NFP_DBG2,"nfp_read_complete_final: exiting");
}

static void nfp_rdtimeout( void *pdev_in )
{
  nfp_dev *pdev= (nfp_dev *)pdev_in;

  nfp_log( NFP_DBG1, "nfp_rdtimeout: read timed out");

  if (!pdev) {
    nfp_log( NFP_DBG1, "nfp_rdtimeout: NULL pdev." );
    return;
  }
  pdev->rdtimeout= 0;
  nfp_read_complete_final(pdev, 0);
}

/* ARGSUSED */
static int nfp_read(dev_t dev, struct uio *uiop, cred_t *credp) {
  int ret;
  nfp_log( NFP_DBG2, "nfp_read: entered" );
  if (ddi_get_soft_state(state_head, getminor(dev)) != NULL) {
    nfp_log( NFP_DBG1, "nfp_read: unable to get nfp_dev");
    return (ENODEV);
  }
  nfp_log( NFP_DBG2, "nfp_read: about to physio." );
  ret = physio(nfp_strategy, (struct buf *)0, dev, B_READ, minphys, uiop );
  if(ret)
    nfp_log( NFP_DBG1, "nfp_read: physio returned %x.", ret );
  return ret;
}

/*-------------------------*/
/*  nfp_write              */
/*-------------------------*/

void nfp_write_complete( nfp_dev *pdev, int ok) {
  nfp_log( NFP_DBG2,"nfp_write_complete: entering");

  if(pdev->high_intr) {
    mutex_enter(&pdev->high_mutex);
    if(pdev->high_write)
      nfp_log(NFP_DBG1, "nfp_write_complete: high_write allread set!");
    pdev->high_write= 1;
    pdev->wr_ok= ok;
    mutex_exit(&pdev->high_mutex);
    ddi_trigger_softintr(pdev->soft_int_id);
  } else
    nfp_write_complete_final( pdev, ok );
  nfp_log( NFP_DBG2,"nfp_write_complete: exiting");
}

static void nfp_write_complete_final( nfp_dev *pdev, int ok) {
  struct buf *local_wr_bp;
  nfp_log( NFP_DBG2,"nfp_write_complete_final: entering");
  if(pdev->wrtimeout)
    (void) untimeout(pdev->wrtimeout);

  if (!pdev->wr_bp) {
    nfp_log( NFP_DBG2, "nfp_write_complete_final: write: wr_bp == NULL." );
    return;
  }

  bp_mapout(pdev->wr_bp);
  pdev->wr_bp->b_resid = ok ? 0 : pdev->wr_bp->b_bcount;
  /* Make sure we set wr_ready before calling biodone to avoid a race */
  pdev->wr_ready = 1;
  bioerror(pdev->wr_bp, ok ? 0 : ENXIO);
  local_wr_bp = pdev->wr_bp;
  pdev->wr_bp = 0;
  biodone(local_wr_bp);
  nfp_log( NFP_DBG2, "nfp_write_complete_final: isr_mutex extited");
  pollwakeup (&pdev->pollhead, POLLWRNORM);

  nfp_log( NFP_DBG2, "nfp_write_complete_final: leaving");
}

static void nfp_wrtimeout( void *pdev_in )
{
  nfp_dev *pdev= (nfp_dev *)pdev_in;

  nfp_log( NFP_DBG1, "nfp_wrtimeout: write timed out");

  if (!pdev) {
    nfp_log( NFP_DBG1, "nfp_wrtimeout: NULL pdev." );
    return;
  }
  pdev->wrtimeout= 0;
  nfp_write_complete_final(pdev, 0);
}

/* ARGSUSED */
static int nfp_write(dev_t dev, struct uio *uiop, cred_t *credp) {
  int ret;
  nfp_log( NFP_DBG2, "nfp_write: entered." );
  if (ddi_get_soft_state(state_head, getminor(dev)) == NULL) {
    nfp_log( NFP_DBG1, "nfp_chread: unable to get nfp_dev.");
    return (ENODEV);
  }
  nfp_log( NFP_DBG2, "nfp_write: about to physio." );
  ret = physio(nfp_strategy, (struct buf *)0, dev, B_WRITE, minphys, uiop );
  if(ret)
    nfp_log( NFP_DBG1, "nfp_write: physio returned %x.", ret );
  return ret;
}

/*-------------------------*/
/*  nfp_strategy           */
/*-------------------------*/

#define NFP_STRAT_ERR(thebp,err,txt) \
      nfp_log( NFP_DBG1, "nfp_strategy: " txt ".\n"); \
      (thebp)->b_resid = (thebp)->b_bcount; \
      bioerror ((thebp), err); \
      biodone ((thebp));

static int nfp_strategy(struct buf *bp) {
  register struct nfp_dev *pdev;
  nfp_err ne;
  
  nfp_log( NFP_DBG2, "nfp_strategy: entered." );
  if (!(pdev = ddi_get_soft_state(state_head, getminor(bp->b_edev)))) {
    NFP_STRAT_ERR (bp, ENXIO, "unable to get nfp_dev");
    return (0);
  }

  if (bp->b_flags & B_READ) {
    int count;
    /* read */
    if (!pdev->rd_ready) {
      NFP_STRAT_ERR (bp,ENXIO,"read called when not ready");
      return (0);
    }
    pdev->rd_ready=0;
    pdev->rd_pending = 0;
    if( !pdev->rd_ok) {
      NFP_STRAT_ERR (bp,ENXIO,"read failed");
      return (0);
    }
    /* copy data from module */
    if(pdev->ifvers >= NFDEV_IF_PCI_PUSH) {
      nfp_log( NFP_DBG3, "nfp_strategy: copying kernel read buffer");
      if( ddi_dma_sync(pdev->read_dma_handle,0,0,DDI_DMA_SYNC_FORKERNEL) != DDI_SUCCESS )
      {
        NFP_STRAT_ERR(bp,ENXIO,"ddi_dma_sync(read_dma_handle) failed");
        return (0);
      }
      /* LINTED: alignment */
      count= *(unsigned int *)(pdev->read_buf+4);
      count= FROM_LE32_MEM(&count);
      nfp_log( NFP_DBG3, "nfp_strategy: read count %d", count);
      if(count<0 || count>bp->b_bcount) {
        NFP_STRAT_ERR(bp,ENXIO,"bad read byte count from device");
        nfp_log( NFP_DBG1, "nfp_strategy: bad read byte count (%d) from device", count);
        return (0);
      }
      bp_mapin (bp);
      bcopy( pdev->read_buf + 8, bp->b_un.b_addr, count );
      bp_mapout (bp);
    } else {
      bp_mapin (bp);
      ne=  pdev->cmddev->read_block( bp->b_un.b_addr, bp->b_bcount, pdev->common.cmdctx, &count );
      bp_mapout (bp);
      if( ne != NFP_SUCCESS) {
        NFP_STRAT_ERR (bp,nfp_oserr(ne),"read_block failed");
        return (0);
      }
    }
    bioerror(bp, 0);
    bp->b_resid = 0;
    biodone (bp);
  } else {
    /* write */
    if (!pdev->wr_ready) {
      NFP_STRAT_ERR (bp,ENXIO,"write called when not ready");
      return (0);
    }
    if (pdev->wr_bp) {
      NFP_STRAT_ERR (bp,ENXIO,"wr_bp != NULL");
      return (0);
    }
    pdev->wrtimeout= timeout(nfp_wrtimeout, (caddr_t)pdev, NFP_TIMEOUT_SEC * drv_usectohz(1000000));
    pdev->wr_bp = bp;
    pdev->wr_ready = 0;
    bp_mapin (bp);
    ne= pdev->cmddev->write_block( bp->b_un.b_addr, bp->b_bcount,  pdev->common.cmdctx);
    if( ne != NFP_SUCCESS ) {
      bp_mapout (bp);
      (void) untimeout(pdev->wrtimeout);
      pdev->wr_bp = 0;
      pdev->wr_ready = 1;
      NFP_STRAT_ERR (bp,nfp_oserr(ne),"write failed");
      return (0);
    }
  }
  nfp_log( NFP_DBG2, "nfp_strategy: leaving");

  return (0);
}


/*--------------------*/
/*  poll / select     */
/*--------------------*/

static int nfp_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
                      struct pollhead **phpp) {
  nfp_dev *pdev;
  short revents;

  if (!(pdev = ddi_get_soft_state(state_head, getminor(dev)))) {
    nfp_log( NFP_DBG1, "nfp_chpoll: unable to get nfp_dev");
    *reventsp=0;
    return (0);
  }
  nfp_log( NFP_DBG2, "nfp_chpoll: entered %x", events);

  revents=0;
  if (events&POLLWRNORM) {
    if (pdev->wr_ready) {
      nfp_log( NFP_DBG2, "nfp_chpoll: write ready");
      revents|=POLLWRNORM;
    }
  }

  if (events&POLLRDNORM) {
    if (pdev->rd_ready) {
      nfp_log( NFP_DBG2, "nfp_chpoll: read ready");
      revents|=POLLRDNORM;
    }
  }

  if (!revents && !anyyet) {
    *phpp=&pdev->pollhead;
  }
  *reventsp=revents;

  nfp_log( NFP_DBG2, "nfp_chpoll: leaving");
  return (0);
}


/*--------------------*/
/*  ioctl             */
/*--------------------*/

/* ARGSUSED */
static int nfp_ioctl(dev_t dev, int cmd, ioctlptr_t arg, int mode, cred_t *credp, int *rvalp) {
  register struct nfp_dev *pdev;

  nfp_log( NFP_DBG2, "nfp_ioctl: entered." );

  if (!(pdev = ddi_get_soft_state(state_head, getminor(dev)))) {
    nfp_log( NFP_DBG1, "nfp_ioctl: unable to get nfp dev.");
    return (ENXIO);
  }

  switch (cmd) {
  case NFDEV_IOCTL_ENQUIRY:
    {
      long *outp;
      int outlen;
      nfdev_enquiry_str enq_data;

      enq_data.busno = (unsigned int)-1;
      enq_data.slotno = (unsigned char)-1;

      /* get our bus and slot num */
      if (ddi_getlongprop (DDI_DEV_T_NONE,
                           pdev->dip, 0, "reg",
                           (caddr_t)&outp, &outlen) != DDI_PROP_NOT_FOUND) {
        nfp_log( NFP_DBG2, "ddi_getlongprop('reg') ok." );
        if( outlen > 0 ) {
          enq_data.busno = ((*outp)>>16) & 0xff;
          enq_data.slotno = ((*outp)>>11) & 0x1f;
          nfp_log( NFP_DBG2, "busno %d, slotno %d.",
                   enq_data.busno, enq_data.slotno );
        }
      } else
        nfp_log( NFP_DBG1, "ddi_getlongprop('reg') failed." );

      if( ddi_copyout( (char *)&enq_data, (void *)arg, sizeof(enq_data), mode ) != 0 ) {
        nfp_log( NFP_DBG1, "ddi_copyout() failed." );
        return EFAULT;
      }
    }
    break;

  case NFDEV_IOCTL_ENSUREREADING:
    {
      unsigned int addr, len;
      nfp_err  ret;
      if( ddi_copyin( (void *)arg, (char *)&len, sizeof(unsigned int), mode ) != 0 ) {
        nfp_log( NFP_DBG1, "ddi_copyin() failed." );
        return (EFAULT);
      }
      /* signal a read to the module */
      nfp_log( NFP_DBG2, "nfp_ioctl: signalling read request to module, len = %x.", len );
      if (len>8192) {
        nfp_log( NFP_DBG1, "nfp_ioctl: len >8192 = %x.", len );
        return EINVAL;
      }
      if (pdev->rd_outstanding==1) {
        nfp_log( NFP_DBG1, "nfp_ioctl: not about to call read with read outstanding.");
        return EIO;
      }

      addr= 0;
      if(pdev->ifvers >= NFDEV_IF_PCI_PUSH) {
        if( len > NFP_READBUF_SIZE ) {
          nfp_log( NFP_DBG1, "nfp_ioctl: len > NFP_READBUF_SIZE = %x.", len );
          return EINVAL;
        }
        addr= pdev->read_dma_cookie.dmac_address;
      }

      pdev->rd_outstanding = 1;
      nfp_log( NFP_DBG2,"nfp_ioctl: pdev->rd_outstanding=1");

      /* setup timeout timer */
      pdev->rdtimeout= timeout(nfp_rdtimeout, (caddr_t)pdev, NFP_TIMEOUT_SEC * drv_usectohz(1000000));

      nfp_log( NFP_DBG2, "nfp_ioctl: read request");
      ret = pdev->cmddev->ensure_reading(addr, len, pdev->common.cmdctx);
      if ( ret != NFP_SUCCESS ) {
        (void) untimeout(pdev->rdtimeout);
        pdev->rdtimeout = 0;
        pdev->rd_outstanding = 0;
        nfp_log( NFP_DBG1, "nfp_ioctl : cmddev->ensure_reading failed ");
        return nfp_oserr( ret );
      }
    }
    break;

  case NFDEV_IOCTL_PCI_IFVERS:
    {
      int vers;

      nfp_log( NFP_DBG2, "nfp_ioctl: NFDEV_IOCTL_PCI_IFVERS");

      if( ddi_copyin( (void *)arg, (char *)&vers, sizeof(vers), mode ) != 0 ) {
        nfp_log( NFP_DBG1, "ddi_copyin() failed." );
        return (EFAULT);
      }

      if( pdev->rd_outstanding ) {
        nfp_log( NFP_DBG1, "nfp_ioctl: can't set ifvers %d as read outstanding", vers);
        return EIO;
      }

      nfp_set_ifvers(pdev, vers);
      if( pdev->ifvers != vers ) {
        nfp_log( NFP_DBG1, "nfp_ioctl: can't set ifvers %d", vers);
        return EIO;
      }
    }
    break;

  case NFDEV_IOCTL_STATS:
    {
      if( ddi_copyout( (char *)&(pdev->common.stats),
                       (void *)arg,
                       sizeof(nfdev_stats_str),
                       mode ) != 0 ) {
        nfp_log( NFP_DBG1, "ddi_copyout() failed." );
        return EFAULT;
      }
    }
    break;

  default:
    nfp_log( NFP_DBG1, "nfp_ioctl: unknown ioctl." );
    return EINVAL;
  }

  return 0;
}

/*-------------------------*/
/*  nfp_open               */
/*-------------------------*/

/* ARGSUSED */
int nfp_open(dev_t *dev, int openflags, int otyp, cred_t *credp)
{       
  nfp_err ret;
  register struct nfp_dev *pdev;
 
  nfp_log( NFP_DBG2, "entered nfp_open." );
      
  pdev = (nfp_dev *)ddi_get_soft_state(state_head, getminor(*dev));
  
  if( !pdev ) {
    nfp_log( NFP_DBG1, "nfp_open: unable to get nfp dev.");
    return (ENODEV);
  }     
        
  if( otyp != OTYP_CHR ) {
    nfp_log( NFP_DBG1, "nfp_open: not opened as character device");
    return (EINVAL);
  } 
    
  mutex_enter(&pdev->busy_mutex);
    
  if (pdev->busy) {
    mutex_exit(&pdev->busy_mutex);
    nfp_log( NFP_DBG1, "nfp_open: device busy");
    return EBUSY;
  } 
  pdev->busy= 1;
  mutex_exit(&pdev->busy_mutex);

  /* use oldest possible interface until told otherwise */
  pdev->ifvers= NFDEV_IF_STANDARD;
  nfp_log( NFP_DBG3, "nfp_open: setting ifvers %d", pdev->ifvers);
  pdev->rd_ready= 0; /* drop any old data */
 
  ret = pdev->cmddev->open(pdev->common.cmdctx);
  if( ret != NFP_SUCCESS ) {
    nfp_log( NFP_DBG1, "nfp_open : cmddev->open failed ");
    return nfp_oserr( ret );
  } 

  nfp_log( NFP_DBG2, "nfp_open: done");

  return 0;
}

/*--------------------*/
/*  nfp_close         */
/*--------------------*/

/* ARGSUSED */
static int nfp_close(dev_t dev, int openflags, int otyp, cred_t *credp) {
  nfp_dev *pdev;
  nfp_err ret;

  nfp_log( NFP_DBG2, "nfp_close: entered");

  pdev = (struct nfp_dev *)ddi_get_soft_state(state_head, getminor(dev));
  if( !pdev ) {
    nfp_log( NFP_DBG1, "nfp_close: cannot find dev.");
    return ENODEV;
  }

  mutex_enter(&pdev->isr_mutex);
  if(pdev->rd_outstanding) {
    int lbolt, err;
    nfp_get_lbolt(&lbolt, err);
    if(!err)
      (void) cv_timedwait(&pdev->rd_cv, &pdev->isr_mutex, lbolt + (NFP_TIMEOUT_SEC * drv_usectohz(1000000)) );
  }
  mutex_exit(&pdev->isr_mutex);
  ret = pdev->cmddev->close(pdev->common.cmdctx);
  if (ret != NFP_SUCCESS ) {
    nfp_log( NFP_DBG1, " nfp_close : cmddev->close failed");
    return nfp_oserr( ret );
  }

  mutex_enter(&pdev->busy_mutex);
  pdev->busy= 0;
  mutex_exit(&pdev->busy_mutex);

  return 0;
}

/****************************************************************************

  nfp driver config

 ****************************************************************************/

/*-------------------------*/
/*  nfp_getinfo            */
/*-------------------------*/

/* ARGSUSED */
static int nfp_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result) {
  int error;
  nfp_dev *pdev;

  nfp_log( NFP_DBG2, "nfp_getinfo: entered" );

  pdev = (struct nfp_dev *)ddi_get_soft_state(state_head, getminor((dev_t)arg));
  if( !pdev ) {
    nfp_log( NFP_DBG1, "nfp_close: cannot find dev.");
    return ENODEV;
  }

  switch (infocmd) {
  case DDI_INFO_DEVT2DEVINFO:
    if (pdev == NULL) {
      *result = NULL;
      error = DDI_FAILURE;
    } else {
      /*
       * don't need to use a MUTEX even though we are
       * accessing our instance structure; dev->dip
       * never changes.
       */
      *result = pdev->dip;
      error = DDI_SUCCESS;
    }
    break;
  case DDI_INFO_DEVT2INSTANCE:
    *result = (void *)(uintptr_t)getminor((dev_t)arg);
    error = DDI_SUCCESS;
    break;
  default:
    *result = NULL;
    error = DDI_FAILURE;
  }

  nfp_log( NFP_DBG2, "nfp_getinfo: leaving." );
  return (error);
}

/*-------------------------*/
/*  nfp_release            */
/*-------------------------*/

static int nfp_release_dev( dev_info_t *dip ) {
  nfp_dev *pdev;
  int instance, i;
  nfp_err ret;

  nfp_log( NFP_DBG2, "nfp_release_dev: entering" );

  instance = ddi_get_instance(dip);
  pdev = (struct nfp_dev *)ddi_get_soft_state(state_head, instance);
  if (pdev) {
    nfp_log( NFP_DBG3, "nfp_release_dev: removing device" );

    nfp_free_pci_push(pdev);

    if( pdev->cmddev ) {
      nfp_log( NFP_DBG3, "nfp_release_dev: destroying cmd dev" );
       ret = pdev->cmddev->destroy(pdev->common.cmdctx);
       if (ret != NFP_SUCCESS) {
         nfp_log( NFP_DBG1, " nfp_release_dev : cmddev->destroy failed ");
         return nfp_oserr( ret );
       }
    }

    if(pdev->high_iblock_cookie) {
      nfp_log( NFP_DBG3, "nfp_release_dev: removing high and soft irq" );
      ddi_remove_softintr(pdev->soft_int_id);
      ddi_remove_intr(pdev->dip, 0, pdev->high_iblock_cookie);
      mutex_destroy( &pdev->busy_mutex );
      cv_destroy( &pdev->rd_cv );
      mutex_destroy( &pdev->isr_mutex );
      mutex_destroy( &pdev->high_mutex );
    } else if(pdev->iblock_cookie) {
      nfp_log( NFP_DBG3, "nfp_release_dev: removing irq" );
      ddi_remove_intr(pdev->dip, 0, pdev->iblock_cookie);
      mutex_destroy( &pdev->busy_mutex );
      cv_destroy( &pdev->rd_cv );
      mutex_destroy( &pdev->isr_mutex );
    }
    if(pdev->low_iblock_cookie) {
      ddi_remove_intr(pdev->dip, 0, pdev->low_iblock_cookie);
      mutex_destroy( &pdev->low_mutex);
    }

    for(i=0;i<6;i++) {
      if( pdev->common.extra[i] ) {
        nfp_log( NFP_DBG3, "nfp_release_dev: unmapping BAR %d", i );
        ddi_regs_map_free ((ddi_acc_handle_t *)&pdev->common.extra[i]);
      }
    }

    ddi_remove_minor_node(dip, NULL);

    if (pdev->conf_handle)
      pci_config_teardown( &pdev->conf_handle );

    ddi_soft_state_free(state_head, instance);
  }
  nfp_log( NFP_DBG2, "nfp_release: finished" );

  return DDI_SUCCESS;
}


/*-------------------------*/
/*  nfp_attach             */
/*-------------------------*/

static int nfp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd) {
  int instance;
  nfp_dev *pdev = NULL;
  int intres;
  uint16_t device, vendor, sub_device, sub_vendor;
  long *outp;
  nfpcmd_dev const *cmddev;
  int index, i;
  nfp_err ret;

  nfp_log( NFP_DBG2, "nfp_attach: entered." );

  if (cmd != DDI_ATTACH) {
    nfp_log( NFP_DBG1, "nfp_attach: bad command." );
    goto bailout;
  }

  instance = ddi_get_instance(dip);

  if (ddi_soft_state_zalloc(state_head, instance) != 0) {
    nfp_log( NFP_DBG1, "nfp_attach: ddi_soft_state_zalloc() failed." );
    goto bailout;
  }

  pdev = (struct nfp_dev *)ddi_get_soft_state(state_head, instance);
  if( !pdev ) {
    nfp_log( NFP_DBG1, "nfp_attach: cannot find dev.");
    return ENODEV;
  }
  pdev->dip = dip;

  /* map in pci config registers */
  if (pci_config_setup(dip, &pdev->conf_handle)) {
    nfp_log( NFP_DBG1, "nfp_attach: pci_config_setup() failed." );
    goto bailout;
  }

  /* find out what we have got */
  vendor= PCI_CONFIG_GET16( pdev->conf_handle, PCI_CONF_VENID );
  device = PCI_CONFIG_GET16( pdev->conf_handle, PCI_CONF_DEVID );
  sub_vendor = PCI_CONFIG_GET16( pdev->conf_handle, PCI_CONF_SUBVENID );
  sub_device = PCI_CONFIG_GET16( pdev->conf_handle, PCI_CONF_SUBSYSID );

  index= 0;
  while( (cmddev = nfp_drvlist[index++]) != NULL ) {
    if( cmddev->vendorid == vendor &&
        cmddev->deviceid == device &&
        cmddev->sub_vendorid == sub_vendor &&
        cmddev->sub_deviceid == sub_device )
      break;
  }
  if( !cmddev ) {
    nfp_log( NFP_DBG1, "nfp_attach: unknonw device." );
    goto bailout;
  }

  /* map BARs */
  for( i=0; i<6; i++ ) {
    if( cmddev->bar_sizes[i] ) {
      off_t size;
      if( ddi_dev_regsize(dip, i+1, &size) != DDI_SUCCESS) {
        nfp_log( NFP_DBG1, "nfp_attach: ddi_dev_regsize() failed for BAR %d", i );
        goto bailout;
      }
      if( size < (cmddev->bar_sizes[i] & ~NFP_MEMBAR_MASK) ) { 
        nfp_log( NFP_DBG1, "nfp_attach: BAR %d too small %x (%x)", i, size, (cmddev->bar_sizes[i] & ~0xF) );
        goto bailout;
      }
      if (ddi_regs_map_setup(dip, i+1, (caddr_t *)&pdev->common.bar[i],
                         0, cmddev->bar_sizes[i] & ~NFP_MEMBAR_MASK, &nosw_attr, (ddi_acc_handle_t *)&pdev->common.extra[i] )) { 
        nfp_log( NFP_DBG1, "nfp_attach: ddi_regs_map_setup() failed for BAR %d", i );
        goto bailout;
      }
      nfp_log( NFP_DBG3, "nfp_attach: BAR[%d] mapped to %x (%x)", i, pdev->common.bar[i], size );
    }
  }
  
  pdev->read_buf = NULL;
  pdev->rd_dma_ok = 0;

  /* attach to minor node */
  if (ddi_create_minor_node(dip, "nfp", S_IFCHR, instance, (char *)cmddev->name, 0) == DDI_FAILURE) {
    ddi_remove_minor_node(dip, NULL);
    nfp_log( NFP_DBG1, "nfp_attach: ddi_create_minor_node() failed." );
    goto bailout;
  }
  
  pdev->wr_ready = 1;
  pdev->rd_ready = 0;
  pdev->rd_pending = 0;
  pdev->rd_outstanding = 0;
  pdev->busy=0; 
  pdev->cmddev= cmddev;
  
  ret = pdev->cmddev->create(&pdev->common);
  if( ret != NFP_SUCCESS) {
    nfp_log( NFP_DBG1, "nfp_attach: failed to create command device");
    goto bailout;
  }
  pdev->common.dev= pdev;

  if (ddi_intr_hilevel(dip, 0) != 0){
    nfp_log( NFP_DBG2, "nfp_attach: high-level interrupt");
    if( ddi_get_iblock_cookie(dip, 0, &pdev->high_iblock_cookie) ) {
      nfp_log( NFP_DBG1, "nfp_attach: ddi_get_iblock_cookie(high) failed." );
      goto bailout;
    } 
    if( ddi_get_iblock_cookie(dip, 0, &pdev->low_iblock_cookie) ) {
      nfp_log( NFP_DBG1, "nfp_attach: ddi_get_iblock_cookie(low) failed." );
      goto bailout;
    }
    mutex_init(&pdev->high_mutex, NULL, MUTEX_DRIVER,
                (void *)pdev->high_iblock_cookie);
    mutex_init(&pdev->low_mutex, NULL, MUTEX_DRIVER,
                (void *)pdev->low_iblock_cookie);
    if (ddi_add_intr(dip, 0, NULL,
                NULL, nfp_isr,
                (caddr_t)pdev) != DDI_SUCCESS) {
      nfp_log( NFP_DBG1, "nfp_attach: ddi_add_intr(high) failed." );
      goto bailout;
    }
    if( ddi_get_soft_iblock_cookie(dip, DDI_SOFTINT_HIGH,
                &pdev->iblock_cookie) ) {
      nfp_log( NFP_DBG1, "nfp_attach: ddi_get_iblock_cookie(soft) failed." );
      goto bailout;
    }
    mutex_init(&pdev->isr_mutex, NULL, MUTEX_DRIVER,
                (void *)pdev->iblock_cookie);
    if (ddi_add_softintr(dip, DDI_SOFTINT_HIGH, &pdev->soft_int_id,
                &pdev->iblock_cookie, NULL,
                nfp_soft_isr, (caddr_t)pdev) != DDI_SUCCESS)
                goto bailout;
    pdev->high_intr= 1;
  } else {
    nfp_log( NFP_DBG2, "nfp_attach: low-level interrupt");

    if (ddi_get_iblock_cookie (dip, 0, &pdev->iblock_cookie)) {
      nfp_log( NFP_DBG1, "nfp_attach: ddi_get_iblock_cookie() failed." );
      goto bailout;
    }
  
    mutex_init(&pdev->isr_mutex, "nfp isr mutex", MUTEX_DRIVER, (void *)pdev->iblock_cookie);
  
    if (ddi_add_intr(dip, 0, NULL,
                     (ddi_idevice_cookie_t *)NULL, nfp_isr,
                     (caddr_t)pdev) != DDI_SUCCESS) {
      nfp_log( NFP_DBG1, "nfp_attach: ddi_add_intr() failed." );
      goto bailout;
    }
  }
  mutex_init(&pdev->busy_mutex, "nfp busy mutex", MUTEX_DRIVER, NULL );
  cv_init(&pdev->rd_cv, "nfp read condvar", CV_DRIVER, NULL );

  /* get our bus and slot num */
  if (ddi_getlongprop (DDI_DEV_T_NONE, 
                       pdev->dip, 0, "reg",
                       (caddr_t)&outp, &intres) != DDI_PROP_NOT_FOUND) {
    nfp_log( NFP_DBG2, "nfp_attach: ddi_getlongprop('reg') ok." );
    if( intres > 0 ) {
      nfp_log( NFP_DBG1, "nfp_attach: found PCI nfast bus %x slot %x.",
               ((*outp)>>16) & 0xff, ((*outp)>>11) & 0x1f );
    }
  }
  
  nfp_log( NFP_DBG2, "nfp_attach: attach succeeded." );
  return DDI_SUCCESS;
  
bailout:
  (void) nfp_release_dev( dip );

  return DDI_FAILURE;
}

/*-------------------------*/
/*  nfp_detach             */
/*-------------------------*/

/* 
 * When our driver is unloaded, nfp_detach cleans up and frees the resources
 * we allocated in nfp_attach.
 */
static int nfp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd) {
  if (cmd != DDI_DETACH)
    return (DDI_FAILURE);

  (void) nfp_release_dev(dip);

  return (DDI_SUCCESS);
}

/*-------------------------*/
/*  _init                  */
/*-------------------------*/

int _init(void) {
  register int error;

  nfp_log( NFP_DBG2, "_init: entered" );

  if ((error = ddi_soft_state_init(&state_head, sizeof (struct nfp_dev), 1)) != 0) {
    nfp_log( NFP_DBG1, "_init: soft_state_init() failed" );
    return (error);
  }
  
  if ((error = mod_install(&modlinkage)) != 0) {
    nfp_log( NFP_DBG1, "_init: mod_install() failed" );
    ddi_soft_state_fini(&state_head);
  }
  
  nfp_log( NFP_DBG2, "_init: leaving" );
  return (error);
}

/*-------------------------*/
/*  _info                  */
/*-------------------------*/

int _info(struct modinfo *modinfop) { 
  nfp_log( NFP_DBG2, "_info: entered" );
  
  return (mod_info(&modlinkage, modinfop));
}

/*-------------------------*/
/*  _fini                  */
/*-------------------------*/

int _fini(void) {
  int status;
  
  nfp_log( NFP_DBG2, "_fini: entered" );
  
  if ((status = mod_remove(&modlinkage)) != 0) {
    nfp_log( NFP_DBG2, "_fini: mod_remove() failed." );
    return (status);
  }
  
  ddi_soft_state_fini(&state_head);
  
  nfp_log( NFP_DBG2, "_fini: leaving" );
  
  return (status);
}

