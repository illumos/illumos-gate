/*

(C) Copyright nCipher Corporation Ltd 2002-2008 All rights reserved

Copyright (c) 2008-2013 Thales e-Security All rights reserved

Copyright (c) 2014 Thales UK All rights reserved

*/

#ifndef I21555_H
#define I21555_H

#ifndef PCI_VENDOR_ID_INTEL
#define PCI_VENDOR_ID_INTEL             0x8086
#endif

#ifndef PCI_DEVICE_ID_INTEL_21555
#define PCI_DEVICE_ID_INTEL_21555       0xb555
#endif

#ifndef PCI_VENDOR_ID_NCIPHER
#define PCI_VENDOR_ID_NCIPHER           0x0100
#endif

#ifndef PCI_SUBSYSTEM_ID_NFAST_REV1
#define PCI_SUBSYSTEM_ID_NFAST_REV1     0x0100
#endif

#define I21555_OFFSET_DOORBELL_PRI_SET		0x9C
#define I21555_OFFSET_DOORBELL_SEC_SET		0x9E
#define I21555_OFFSET_DOORBELL_PRI_CLEAR	0x98

#define I21555_OFFSET_DOORBELL_PRI_SET_MASK	0xA4
#define I21555_OFFSET_DOORBELL_PRI_CLEAR_MASK	0xA0

#define I21555_DOORBELL_PRI_ENABLE 0x0000
#define I21555_DOORBELL_PRI_DISABLE 0xFFFF

#define I21555_CFG_SEC_CMD_STATUS 0x44

#define CFG_CMD_MASTER 0x0004

#define IOBAR   1
#define MEMBAR  2

#define IOSIZE  0x100

extern nfp_err i21555_debug( int cmd, void *ctx );

#endif
