/*

nfp_error.h: nCipher PCI HSM error handling

(C) Copyright nCipher Corporation Ltd 2002-2008 All rights reserved

Copyright (c) 2008-2013 Thales e-Security All rights reserved

Copyright (c) 2014 Thales UK All rights reserved

history

05/12/2001 jsh  Original

*/

#ifndef NFP_ERROR_H
#define NFP_ERROR_H

#include "nfp_common.h"

#define NFP_SUCCESS	0x0
#define NFP_EFAULT      0x1
#define NFP_ENOMEM	0x2
#define NFP_EINVAL	0x3
#define NFP_EIO		0x4
#define NFP_ENXIO	0x5
#define NFP_ENODEV	0x6
#define NFP_EINTR	0x7
#define NFP_ESTARTING	0x8
#define NFP_EAGAIN	0x9
#define NFP_EUNKNOWN	0x100

typedef int nfp_err;

extern oserr_t nfp_oserr( nfp_err nerr );
extern nfp_err nfp_error( oserr_t oerr );

#define nfr( x) \
  return nfp_error((x))

#define nfer(x, fn, msg) \
  { oserr_t err=(x); if(err) { nfp_log( NFP_DBG1, #fn ": " msg); return nfp_error(err); } }

#define er(x, fn, msg ) \
{ nfp_err err=(x); if(err) { nfp_log( NFP_DBG1, #fn ": " msg); return err; } }

#endif
