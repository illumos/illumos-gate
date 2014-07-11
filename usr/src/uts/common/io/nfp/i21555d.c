/*

i21555d.c: nCipher PCI HSM intel 21555 debug ioctl

(C) Copyright nCipher Corporation Ltd 2002-2008 All rights reserved

Copyright (c) 2008-2013 Thales e-Security All rights reserved

Copyright (c) 2014 Thales UK All rights reserved


history

15/05/2002 jsh  Original, does nothing

*/

#include "nfp_common.h"
#include "nfp_error.h"
#include "nfp_osif.h"
#include "i21555.h"

/* ARGSUSED */
nfp_err i21555_debug( int cmd, void *ctx) {
  nfp_log( NFP_DBG1, "i21555_debug: entered");

  return NFP_EUNKNOWN;
}
