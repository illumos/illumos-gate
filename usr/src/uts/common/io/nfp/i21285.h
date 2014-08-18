/*

(C) Copyright nCipher Corporation Ltd 2002-2008 All rights reserved

Copyright (c) 2008-2013 Thales e-Security All rights reserved

Copyright (c) 2014 Thales UK All rights reserved

*/

#ifndef NFP_I21285_H
#define NFP_I21285_H

#ifndef PCI_VENDOR_ID_DEC
#define PCI_VENDOR_ID_DEC               0x1011
#endif
#ifndef PCI_DEVICE_ID_DEC_21285
#define PCI_DEVICE_ID_DEC_21285         0x1065
#endif
#ifndef PCI_VENDOR_ID_NCIPHER
#define PCI_VENDOR_ID_NCIPHER           0x0100
#endif

#ifndef PCI_DEVICE_ID_NFAST_GEN1
#define PCI_DEVICE_ID_NFAST_GEN1	0x0100
#endif

#define I21285_OFFSET_DOORBELL		0x60
#define I21285_OFFSET_INTERRUPT_MASK	0x34

#define DOORBELL_ENABLE 0x0
#define DOORBELL_DISABLE 0x4

#define POSTLIST_ENABLE 0x0
#define POSTLIST_DISABLE 0x8

#define IOBAR	1
#define MEMBAR	2

#define IOSIZE	0x80
#define MEMSIZE	0x100000

#endif
