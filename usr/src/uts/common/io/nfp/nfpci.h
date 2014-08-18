/*

(C) Copyright nCipher Corporation Ltd 2002-2008 All rights reserved

Copyright (c) 2008-2013 Thales e-Security All rights reserved

Copyright (c) 2014 Thales UK All rights reserved

*/

/*
*
*  NFPCI.H	- nFast PCI interface definition file
*
*
*
*  1998.06.09	IH	Started
*
* The interface presented by nFast PCI devices consists of:
*
* A region of shared RAM used for data transfer & control information
* A doorbell interrupt register, so both sides can give each other interrupts
* A number of DMA channels for transferring data
*/

#ifndef NFPCI_H
#define NFPCI_H

/* Sizes of some regions */
#define NFPCI_RAM_MINSIZE	0x00100000
/* This is the minimum size of shared RAM. In future it may be possible to
   negotiate larger sizes of shared RAM or auto-detect how big it is */
#define NFPCI_RAM_MINSIZE_JOBS	0x00020000 /* standard jobs only */
#define NFPCI_RAM_MINSIZE_KERN	0x00040000 /* standard and kernel jobs */

/* Offsets within shared memory space.
   The following main regions are:
     jobs input area
     jobs output area
     kernel jobs input area
     kernel output area
*/

#define NFPCI_OFFSET_JOBS		0x00000000
#define NFPCI_OFFSET_JOBS_WR		0x00000000
#define NFPCI_OFFSET_JOBS_RD		0x00010000
#define NFPCI_OFFSET_KERN		0x00020000
#define NFPCI_OFFSET_KERN_WR		0x00020000
#define NFPCI_OFFSET_KERN_RD		0x00030000

/* Interrupts, defined by bit position in doorbell register */

/* Interrupts from device to host */
#define NFAST_INT_DEVICE_WRITE_OK               0x00000001
#define NFAST_INT_DEVICE_WRITE_FAILED           0x00000002
#define NFAST_INT_DEVICE_READ_OK                0x00000004
#define NFAST_INT_DEVICE_READ_FAILED            0x00000008
#define NFAST_INT_DEVICE_KERN_WRITE_OK		0x00000010
#define NFAST_INT_DEVICE_KERN_WRITE_FAILED	0x00000020
#define NFAST_INT_DEVICE_KERN_READ_OK		0x00000040
#define NFAST_INT_DEVICE_KERN_READ_FAILED	0x00000080

/* Interrupts from host to device */
#define NFAST_INT_HOST_WRITE_REQUEST            0x00010000
#define NFAST_INT_HOST_READ_REQUEST             0x00020000
#define NFAST_INT_HOST_DEBUG                    0x00040000
#define NFAST_INT_HOST_KERN_WRITE_REQUEST	0x00080000
#define NFAST_INT_HOST_KERN_READ_REQUEST	0x00100000

/* Ordinary job submission ------------------------ */

/* The NFPCI_OFFSET_JOBS_WR and NFPCI_OFFSET_JOBS_RD regions are defined
   by the following (byte) address offsets... */

#define NFPCI_OFFSET_CONTROL	0x0
#define NFPCI_OFFSET_LENGTH	0x4
#define NFPCI_OFFSET_DATA	0x8
#define NFPCI_OFFSET_PUSH_ADDR	0x8

#define NFPCI_JOBS_WR_CONTROL	(NFPCI_OFFSET_JOBS_WR + NFPCI_OFFSET_CONTROL)
#define NFPCI_JOBS_WR_LENGTH	(NFPCI_OFFSET_JOBS_WR + NFPCI_OFFSET_LENGTH)
#define NFPCI_JOBS_WR_DATA	(NFPCI_OFFSET_JOBS_WR + NFPCI_OFFSET_DATA)
#define NFPCI_MAX_JOBS_WR_LEN		(0x0000FFF8)

#define NFPCI_JOBS_RD_CONTROL	(NFPCI_OFFSET_JOBS_RD + NFPCI_OFFSET_CONTROL)
#define NFPCI_JOBS_RD_LENGTH	(NFPCI_OFFSET_JOBS_RD + NFPCI_OFFSET_LENGTH)
#define NFPCI_JOBS_RD_DATA	(NFPCI_OFFSET_JOBS_RD + NFPCI_OFFSET_DATA)
/* address in PCI space of host buffer for NFPCI_JOB_CONTROL_PCI_PUSH */
#define NFPCI_JOBS_RD_PUSH_ADDR	(NFPCI_OFFSET_JOBS_RD + NFPCI_OFFSET_PUSH_ADDR)
#define NFPCI_MAX_JOBS_RD_LEN		(0x000FFF8)

/* Kernel inferface job submission ---------------- */

#define NFPCI_KERN_WR_CONTROL   (NFPCI_OFFSET_KERN_WR + NFPCI_OFFSET_CONTROL)
#define NFPCI_KERN_WR_LENGTH    (NFPCI_OFFSET_KERN_WR + NFPCI_OFFSET_LENGTH)
#define NFPCI_KERN_WR_DATA      (NFPCI_OFFSET_KERN_WR + NFPCI_OFFSET_DATA)
#define NFPCI_MAX_KERN_WR_LEN      (0x0000FFF8)

#define NFPCI_KERN_RD_CONTROL   (NFPCI_OFFSET_KERN_RD + NFPCI_OFFSET_CONTROL)
#define NFPCI_KERN_RD_LENGTH    (NFPCI_OFFSET_KERN_RD + NFPCI_OFFSET_LENGTH)
#define NFPCI_KERN_RD_DATA      (NFPCI_OFFSET_KERN_RD + NFPCI_OFFSET_DATA)
/* address in PCI space of host buffer for NFPCI_JOB_CONTROL_PCI_PUSH */
#define NFPCI_KERN_RD_ADDR      (NFPCI_OFFSET_KERN_RD + NFPCI_OFFSET_PUSH_ADDR)
#define NFPCI_MAX_KERN_RD_LEN		(0x000FFF8)

#ifdef DEFINE_NFPCI_PACKED_STRUCTS
typedef struct
{
  UINT32	controlword;
  UINT32	length;		/* length of data to follow */
  union {
    BYTE	data[1];
    UINT32	addr;
  } uu;
}
  NFPCI_JOBS_BLOCK;
#endif


#define NFPCI_JOB_CONTROL		0x00000001
#define NFPCI_JOB_CONTROL_PCI_PUSH	0x00000002
/*
   The 'Control' word is analogous to the SCSI read/write address;
   1 = standard push/pull IO
   2 = push/push IO

   To submit a block of job data, the host:
   - sets the (32-bit, little-endian) word at NFPCI_JOBS_WR_CONTROL to NFPCI_JOB_CONTROL
   - sets the word at NFPCI_JOBS_WR_LENGTH to the length of the data
   - copies the data to NFPCI_JOBS_WR_DATA
   - sets interrupt NFAST_INT_HOST_WRITE_REQUEST in the doorbell register
   - awaits the NFAST_INT_DEVICE_WRITE_OK (or _FAILED) interrupts back

   To read a block of jobs back, the host:
   - sets the word at NFPCI_JOBS_RD_CONTROL to NFPCI_JOB_CONTROL
   - sets the word at NFPCI_JOBS_RD_LENGTH to the max length for returned data
   - sets interrupt NFAST_INT_HOST_READ_REQUEST
   - awaits the NFAST_INT_DEVICE_READ_OK (or _FAILED) interrupt
   - reads the data from NFPCI_JOBS_RD_DATA; the module will set the word at
	NFPCI_JOBS_RD_LENGTH to its actual length.

   Optionally the host can request the PCI read data to be pushed to host PCI mapped ram:
   - allocates a contiguous PCI addressable buffer for a NFPCI_JOBS_BLOCK of max
        size NFPCI_MAX_JOBS_RD_LEN (or NFPCI_MAX_KERN_RD_LEN) + 8
   - sets the word at NFPCI_JOBS_RD_CONTROL to NFPCI_JOB_CONTROL_PCI_PUSH
   - sets the word at NFPCI_JOBS_RD_LENGTH to the max length for returned data
   - sets the word at NFPCI_JOBS_RD_PUSH_ADDR to be the host PCI address of
        the buffer
   - sets interrupt NFAST_INT_HOST_READ_REQUEST
   - awaits the NFAST_INT_DEVICE_READ_OK (or _FAILED) interrupt
   - reads the data from the buffer at NFPCI_OFFSET_DATA in the buffer.  The
        module will set NFPCI_OFFSET_LENGTH to the actual length.
*/

#define NFPCI_SCRATCH_CONTROL       0

#define NFPCI_SCRATCH_CONTROL_HOST_MOI   (1<<0)
#define NFPCI_SCRATCH_CONTROL_MODE_SHIFT 1
#define NFPCI_SCRATCH_CONTROL_MODE_MASK  (3<<NFPCI_SCRATCH_CONTROL_MODE_SHIFT)

#define NFPCI_SCRATCH_STATUS        1

#define NFPCI_SCRATCH_STATUS_MONITOR_MOI         (1<<0)
#define NFPCI_SCRATCH_STATUS_APPLICATION_MOI     (1<<1)
#define NFPCI_SCRATCH_STATUS_APPLICATION_RUNNING (1<<2)
#define NFPCI_SCRATCH_STATUS_ERROR               (1<<3)

#define NFPCI_SCRATCH_ERROR_LO      2
#define NFPCI_SCRATCH_ERROR_HI      3

#endif
