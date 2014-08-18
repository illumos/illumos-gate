/*

nfdev-solaris.h: nFast solaris specific device ioctl interface.

(C) Copyright nCipher Corporation Ltd 1998-2008 All rights reserved

Copyright (c) 2008-2013 Thales e-Security All rights reserved

Copyright (c) 2014 Thales UK All rights reserved

history

14/07/1998 jsh  Original

*/

#ifndef NFDEV_SOLARIS_H
#define NFDEV_SOLARIS_H

#include "nfdev-common.h"

#define NFDEV_IOCTL_TYPE ('n'<<8)

#define NFDEV_IOCTL_ENQUIRY		( NFDEV_IOCTL_TYPE | \
					  NFDEV_IOCTL_NUM_ENQUIRY )
#define NFDEV_IOCTL_ENSUREREADING	( NFDEV_IOCTL_TYPE | \
					  NFDEV_IOCTL_NUM_ENSUREREADING )
#define NFDEV_IOCTL_DEVCOUNT		( NFDEV_IOCTL_TYPE | \
					  NFDEV_IOCTL_NUM_DEVCOUNT )
#define NFDEV_IOCTL_DEBUG		( NFDEV_IOCTL_TYPE | \
					  NFDEV_IOCTL_NUM_DEBUG )
#define NFDEV_IOCTL_PCI_IFVERS		( NFDEV_IOCTL_TYPE | \
					  NFDEV_IOCTL_NUM_PCI_IFVERS )
#define NFDEV_IOCTL_STATS		( NFDEV_IOCTL_TYPE | \
					  NFDEV_IOCTL_NUM_STATS )

#endif /* NFDEV_SOLARIS_H */
