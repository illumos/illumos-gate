/*

(C) Copyright nCipher Corporation Ltd 2002-2008 All rights reserved

Copyright (c) 2008-2013 Thales e-Security All rights reserved

Copyright (c) 2014 Thales UK All rights reserved

*/

/*
 * nfp_ifervs.c  - common pci interface versioning
 *
 * uses:
 *
 * int pdev->ifvers
 *     device interface version
 *
 * int nfp_ifvers
 *     interface version limit
 * 
 * int nfp_alloc_pci_push( nfp_dev *pdev )
 *     allocates resources needed for PCI Push,
 *     if not already allocated, and return True if successful
 *
 * void nfp_free_pci_push( nfp_dev *pdev ) {
 *     frees any resources allocated to PCI Push
 */

void nfp_set_ifvers( nfp_dev *pdev, int vers ) {
  if( nfp_ifvers != 0 && vers > nfp_ifvers ) {
    nfp_log( NFP_DBG2,
             "nfp_set_ifvers: can't set ifvers %d"
             " as nfp_ifvers wants max ifvers %d",
             vers, nfp_ifvers);
    return;
  }
  if( vers >= NFDEV_IF_PCI_PUSH ) {
    if(!nfp_alloc_pci_push(pdev)) {
      nfp_log( NFP_DBG1,
               "nfp_set_ifvers: can't set ifvers %d"
               " as resources not available",
               vers);
      return;
    }
  } else {
    nfp_free_pci_push(pdev);
  }
  pdev->ifvers= vers;
  nfp_log( NFP_DBG3, "nfp_set_ifvers: setting ifvers %d", vers);
}
