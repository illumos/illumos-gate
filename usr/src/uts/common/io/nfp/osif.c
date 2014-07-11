/*

(C) Copyright nCipher Corporation Ltd 2002-2008 All rights reserved

Copyright (c) 2008-2013 Thales e-Security All rights reserved

Copyright (c) 2014 Thales UK All rights reserved

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
#include "nfp_error.h"
#include "nfp_osif.h"
#include "nfp_cmd.h"
#include "nfp.h"
#include "autoversion.h"

/* config space access ---------------------------------- */

nfp_err nfp_config_inl( nfp_cdev *pdev, int offset, unsigned int *res ) {
  unsigned int tmp32;
  if ( !pdev || !pdev->dev || !pdev->dev->conf_handle )
    return NFP_ENODEV;

/* pci_config_get32() does byte swapping, so put back to LE */
  tmp32 = pci_config_get32( pdev->dev->conf_handle, offset );
  TO_LE32_IO(res, tmp32);

  return NFP_SUCCESS;
}

/* user space memory access ---------------------------------- */

nfp_err nfp_copy_from_user( char *kbuf, const char *ubuf, int len) {
  bcopy(ubuf, kbuf, len);
  return 0;
}

nfp_err nfp_copy_to_user( char *ubuf, const char *kbuf, int len) {
  bcopy(kbuf, ubuf, len);
  return 0;
}

nfp_err nfp_copy_from_user_to_dev( nfp_cdev *cdev, int bar, int offset, const char *ubuf, int len) {
  /* dirty hack on Solaris, as we are called from strategy we are, in fact, copying from kernel mem */
  return nfp_copy_to_dev( cdev, bar, offset, ubuf, len );
}

nfp_err nfp_copy_to_user_from_dev( nfp_cdev *cdev, int bar, int offset, char *ubuf, int len) {
  /* dirty hack on Solaris, as we are called from strategy we are, in fact, copying to kernel mem */
  return nfp_copy_from_dev( cdev, bar, offset, ubuf, len );
}

nfp_err nfp_copy_from_dev( nfp_cdev *cdev, int bar, int offset, char *kbuf, int len) {
  if( len & 0x3 || offset & 0x3 )
    DDI_REP_GET8( cdev->extra[bar], (unsigned char *)kbuf, cdev->bar[bar] + offset, len, DDI_DEV_AUTOINCR);
  else
    /* LINTED: alignment */
    DDI_REP_GET32( cdev->extra[bar], (unsigned int *)kbuf, (unsigned int *)(cdev->bar[bar] + offset), len / 4, DDI_DEV_AUTOINCR);
  return NFP_SUCCESS;
}

nfp_err nfp_copy_to_dev( nfp_cdev *cdev, int bar, int offset, const char *kbuf, int len) {
  if( len & 0x3 || offset & 0x3 )
    DDI_REP_PUT8( cdev->extra[bar], (unsigned char *)kbuf, cdev->bar[bar] + offset, len, DDI_DEV_AUTOINCR );
  else
    /* LINTED: alignment */
    DDI_REP_PUT32( cdev->extra[bar], (unsigned int *)kbuf, (unsigned int *)(cdev->bar[bar] + offset), len / 4, DDI_DEV_AUTOINCR );
  return NFP_SUCCESS;
}

/* pci io space access --------------------------------------- */

unsigned int nfp_inl( nfp_cdev *pdev, int bar, int offset ) {
  nfp_log( NFP_DBG3, "nfp_inl: addr %x", (uintptr_t) pdev->bar[bar] + offset);
  /* LINTED: alignment */
  return DDI_GET32( pdev->extra[bar], (uint32_t *)(pdev->bar[bar] + offset) );
}

unsigned short nfp_inw( nfp_cdev *pdev, int bar, int offset ) {
  nfp_log( NFP_DBG3, "nfp_inw: addr %x", (uintptr_t) pdev->bar[bar] + offset);
  /* LINTED: alignment */
  return DDI_GET16( pdev->extra[bar], (unsigned short *)(pdev->bar[ bar ] + offset) );
}

void nfp_outl( nfp_cdev *pdev, int bar, int offset, unsigned int data ) {
  nfp_log( NFP_DBG3, "nfp_outl: addr %x, data %x", (uintptr_t) pdev->bar[bar] + offset, data);
  /* LINTED: alignment */
  DDI_PUT32( pdev->extra[bar], (uint32_t *)(pdev->bar[ bar ] + offset), data ); 
}

void nfp_outw( nfp_cdev *pdev, int bar, int offset, unsigned short data ) {
  nfp_log( NFP_DBG3, "nfp_outl: addr %x, data %x", (uintptr_t) pdev->bar[bar] + offset, data);
  /* LINTED: alignment */
  DDI_PUT16( pdev->extra[bar], (unsigned short *)(pdev->bar[ bar ] + offset), data ); 
}

/* logging ---------------------------------------------------- */

void nfp_log( int level, const char *fmt, ...)
{
  auto char buf[256];
  va_list ap;

  switch (level) {
  case NFP_DBG4: if (nfp_debug < 4) break;
  /*FALLTHROUGH*/
  case NFP_DBG3: if (nfp_debug < 3) break;
  /*FALLTHROUGH*/
  case NFP_DBG2: if (nfp_debug < 2) break;
  /*FALLTHROUGH*/
  case NFP_DBG1: if (nfp_debug < 1) break;
  /*FALLTHROUGH*/
  default:
    va_start(ap, fmt);
    (void) vsnprintf(buf, 256, fmt, ap);
    va_end(ap);
    cmn_err(CE_CONT, "!" VERSION_COMPNAME " " VERSION_NO ": %s\n", buf);
    break;
  }
}

struct errstr {
  int oserr;
  nfp_err nferr;
};


static struct errstr errtab[] = {
  { EFAULT, NFP_EFAULT },
  { ENOMEM, NFP_ENOMEM },
  { EINVAL, NFP_EINVAL },
  { EIO,    NFP_EIO    },
  { ENXIO,  NFP_ENXIO  },
  { ENODEV, NFP_ENODEV  },
  { EINVAL, NFP_EUNKNOWN },
  { 0, 0 }
};

nfp_err nfp_error( int oserr )
{
  struct errstr *perr;
  if(!oserr)
    return 0;
  perr= errtab;
  while(perr->nferr) {
   if(perr->oserr == oserr)
     return perr->nferr;
   perr++;
  }
  return NFP_EUNKNOWN;
}

int nfp_oserr( nfp_err nferr )
{
  struct errstr *perr;
  if(nferr == NFP_SUCCESS)
    return 0;
  perr= errtab;
  while(perr->nferr) {
   if(perr->nferr == nferr)
     return perr->oserr;
   perr++;
  }
  return EIO;
}
