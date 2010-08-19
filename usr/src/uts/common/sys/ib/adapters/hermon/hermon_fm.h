/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_IB_ADAPTERS_HERMON_FM_H
#define	_SYS_IB_ADAPTERS_HERMON_FM_H

/*
 * hermon_fm.h
 */
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * HCA FMA compile note.
 *
 * FMA_TEST is used for HCA function tests, and
 * the macro can be on by changing Makefile.
 *
 * in case of DEBUG
 * 	FMA_TEST is on
 *
 * in case of non-DEBUG (DEBUG is off)
 * 	FMA_TEST is off
 */

/*
 * HCA FM common data structure
 */

/*
 * HCA FM Structure
 * This structure is used to catch HCA HW errors.
 */
struct i_hca_fm {
	uint32_t ref_cnt;	/* the number of instances referring to this */
	kmutex_t lock;		/* protection for last_err & polling thread */
	struct i_hca_acc_handle *hdl;	/* HCA FM acc handle structure */
	struct kmem_cache *fm_acc_cache; /* HCA acc handle cache */

};

/*
 * HCA FM acc handle structure
 * This structure is holding ddi_acc_handle_t and other members
 * to deal with HCA PIO FM.
 */
struct i_hca_acc_handle {
	struct i_hca_acc_handle *next;	/* next structure */
	ddi_acc_handle_t save_hdl;	/* acc handle */
	kmutex_t lock;			/* mutex lock for thread count */
	uint32_t thread_cnt;		/* number of threads issuing PIOs */
};
_NOTE(SCHEME_PROTECTS_DATA("safe sharing", i_hca_acc_handle::save_hdl))
#define	fm_acc_hdl(hdl)	(((struct i_hca_acc_handle *)(hdl))->save_hdl)
#define	FM_POLL_INTERVAL (10000000)	/* 10ms (nano) */

/*
 * HCA FM function test structure
 * This structure can be used to test the basic fm function test for HCA.
 * The test code is included if the FMA_TEST macro is defined.
 */
struct i_hca_fm_test {
	int num;		/* serial numner */
	int type;		/* PIO or Hermon specific errors */
#define	HCA_TEST_PIO	0x1
#define	HCA_TEST_IBA	0x2
	int trigger;		/* how to trigger a HW error */
#define	HCA_TEST_TRANSIENT		0x0001
#define	HCA_TEST_PERSISTENT		0x0002
#define	HCA_TEST_ATTACH			0x0010
#define	HCA_TEST_START			0x0100
#define	HCA_TEST_END			0x0200
	void (*pio_injection)(struct i_hca_fm_test *, ddi_fm_error_t *);
	int errcnt;		/* how many transient error occurs */
	int line_num;		/* line number in the source code */
	char *file_name;	/* source filename */
	char *hash_key;		/* hash table for test items */
	void *private;		/* private data */
};

/*
 * Hermon FM data structure
 */
typedef struct i_hca_fm hermon_hca_fm_t;
typedef struct i_hca_acc_handle hermon_acc_handle_t;
typedef struct i_hca_fm_test hermon_test_t;

/*
 * The following defines are to supplement device error reporting.
 * At each place where the planned FMA error matrix specifies that
 * an ereport will be generated, for now there is a HERMON_FMANOTE()
 * call generating an appropriate message string.
 *
 * This has been revised since it has been realized that FMA is only
 * to be used for hardware errors.  HERMON_FMANOTE() is used to report
 * errors that are likely to be hardware, but possibly are not.
 */
#define	HERMON_FMANOTE(state, string)					\
	cmn_err(CE_WARN, "hermon%d: Device Error: %s",			\
		(state)->hs_instance, string)

/* CQE Syndrome errors - see hermon_cq.c */

#define	HERMON_FMA_LOCLEN 	"CQE local length error"
#define	HERMON_FMA_LOCQPOP	"CQE local qp operation error"
#define	HERMON_FMA_LOCPROT	"CQE local protection error"
#define	HERMON_FMA_WQFLUSH	"CQE wqe flushed in error"
#define	HERMON_FMA_MWBIND	"CQE memory window bind error"
#define	HERMON_FMA_RESP		"CQE bad response"
#define	HERMON_FMA_LOCACC	"CQE local access error"
#define	HERMON_FMA_REMREQ	"CQE remote invalid request error"
#define	HERMON_FMA_REMACC	"CQE remote access error"
#define	HERMON_FMA_REMOP	"CQE remote operation error"
#define	HERMON_FMA_XPORTCNT	"CQE transport retry counter exceeded"
#define	HERMON_FMA_RNRCNT	"CQE RNR retry counter exceeded"
#define	HERMON_FMA_REMABRT	"CQE remote aborted error"
#define	HERMON_FMA_UNKN		"CQE unknown/reserved error returned"

/* event errors - see hermon_event.c */
#define	HERMON_FMA_OVERRUN	"EQE cq overrun or protection error"
#define	HERMON_FMA_LOCCAT	"EQE local work queue catastrophic error"
#define	HERMON_FMA_QPCAT	"EQE local queue pair catastrophic error"
#define	HERMON_FMA_PATHMIG	"EQE path migration failed"
#define	HERMON_FMA_LOCINV	"EQE invalid request - local work queue"
#define	HERMON_FMA_LOCACEQ	"EQE local access violation"
#define	HERMON_FMA_SRQCAT	"EQE shared received queue catastrophic"
#define	HERMON_FMA_INTERNAL	"EQE hca internal error"

/* HCR device failure returns - see hermon_cmd.c */
#define	HERMON_FMA_HCRINT	"HCR internal error processing command"
#define	HERMON_FMA_NVMEM	"HCR NVRAM checksum/CRC failure"
#define	HERMON_FMA_TOTOG	"HCR Timeout waiting for command toggle"
#define	HERMON_FMA_GOBIT	"HCR Timeout waiting for command go bit"
#define	HERMON_FMA_RSRC		"HCR Command insufficient resources"
#define	HERMON_FMA_CMDINV	"HCR Command invalid status returned"

/* HCA initialization errors - see hermon.c */
#define	HERMON_FMA_FWVER	"HCA firmware not at minimum version"
#define	HERMON_FMA_PCIID	"HCA PCIe devid not supported"
#define	HERMON_FMA_MAINT	"HCA device set to memory controller mode"
#define	HERMON_FMA_BADNVMEM	"HCR bad NVMEM error"

/*
 * HCA FM constants
 */

/* HCA FM state */
#define	HCA_NO_FM		0x0000	/* HCA FM is not supported */
/* HCA FM state flags */
#define	HCA_PIO_FM		0x0001	/* PIO is fma-protected */
#define	HCA_DMA_FM		0x0002	/* DMA is fma-protected */
#define	HCA_EREPORT_FM		0x0004	/* FMA ereport is available */
#define	HCA_ERRCB_FM		0x0010	/* FMA error callback is supported */

#define	HCA_ATTCH_FM		0x0100	/* HCA FM attach mode */
#define	HCA_RUNTM_FM		0x0200	/* HCA FM runtime mode */

/* HCA ererport type */
#define	HCA_SYS_ERR		0x001	/* HW error reported by Solaris FMA */
#define	HCA_IBA_ERR		0x002	/* IB specific HW error */

/* HCA ereport detail */
#define	HCA_ERR_TRANSIENT	0x010	/* HCA temporary error */
#define	HCA_ERR_NON_FATAL	0x020	/* HCA persistent error */
#define	HCA_ERR_SRV_LOST	0x040	/* HCA attach failure */
#define	HCA_ERR_DEGRADED	0x080	/* HCA maintenance mode */
#define	HCA_ERR_FATAL		0x100	/* HCA critical situation */
#define	HCA_ERR_IOCTL		0x200	/* EIO */

/* Ignore HCA HW error check */
#define	HCA_SKIP_HW_CHK		(-1)

/* HCA FM pio retry operation state */
#define	HCA_PIO_OK		(0)	/* No HW errors */
#define	HCA_PIO_TRANSIENT	(1)	/* transient error */
#define	HCA_PIO_PERSISTENT	(2)	/* persistent error */
#define	HCA_PIO_RETRY_CNT	(3)

/* HCA firmware faults */
#define	HCA_FW_MISC		0x1	/* firmware misc faults */
#define	HCA_FW_CORRUPT		0x2	/* firmware corruption */
#define	HCA_FW_MISMATCH		0x3	/* firmware version mismatch */

/*
 * Hermon FM macros
 */

#ifdef FMA_TEST
#define	TEST_DECLARE(tst)		hermon_test_t *tst;
#define	REGISTER_PIO_TEST(st, tst)					\
    tst = hermon_test_register(st, __FILE__, __LINE__, HCA_TEST_PIO)
#define	PIO_START(st, hdl, tst)		hermon_PIO_start(st, hdl, tst)
#define	PIO_END(st, hdl, cnt, tst)	hermon_PIO_end(st, hdl, &cnt, tst)
#else
#define	TEST_DECLARE(tst)
#define	REGISTER_PIO_TEST(st, tst)
#define	PIO_START(st, hdl, tst)		hermon_PIO_start(st, hdl, NULL)
#define	PIO_END(st, hdl, cnt, tst)	hermon_PIO_end(st, hdl, &cnt, NULL)
#endif /* FMA_TEST */

/*
 * hermon_pio_init() is a macro initializing variables.
 */
#define	hermon_pio_init(cnt, status, tst)				\
	TEST_DECLARE(tst)						\
	int	status = HCA_PIO_OK;					\
	int	cnt = HCA_PIO_RETRY_CNT

/*
 * hermon_pio_start() is one of a pair of macros checking HW errors
 * at PIO requests, which should be called before the requests are issued.
 */
#define	hermon_pio_start(st, hdl, label, cnt, status, tst)		\
	if (st->hs_fm_state & HCA_PIO_FM) {				\
		if (st->hs_fm_async_fatal) {				\
			hermon_fm_ereport(st, HCA_SYS_ERR,		\
			    HCA_ERR_NON_FATAL);				\
			goto label;					\
		} else {						\
			REGISTER_PIO_TEST(st, tst);			\
			cnt = HCA_PIO_RETRY_CNT;			\
			if (PIO_START(st, hdl, tst) ==			\
			    HCA_PIO_PERSISTENT) {			\
				goto label;				\
			}						\
		}							\
	} else {							\
		status = HCA_SKIP_HW_CHK;				\
	}								\
	do {

/*
 * hermon_pio_end() is the other of a pair of macros checking HW errors
 * at PIO requests, which should be called after the requests end.
 * If a HW error is detected and can be isolated well, these macros
 * retry the operation to determine if the error is persistent or not.
 */
#define	hermon_pio_end(st, hdl, label, cnt, status, tst)		\
	if (status != HCA_SKIP_HW_CHK) {				\
		if (st->hs_fm_async_fatal) {				\
			hermon_fm_ereport(st, HCA_SYS_ERR,		\
			    HCA_ERR_NON_FATAL);				\
			goto label;					\
		}							\
		if ((status = PIO_END(st, hdl, cnt, tst)) ==		\
		    HCA_PIO_PERSISTENT) {				\
			goto label;					\
		} else if (status == HCA_PIO_TRANSIENT) {		\
			hermon_fm_ereport(st, HCA_SYS_ERR,		\
			    HCA_ERR_TRANSIENT);				\
		}							\
	}								\
	} while (status == HCA_PIO_TRANSIENT)

extern void hermon_fm_init(hermon_state_t *);
extern void hermon_fm_fini(hermon_state_t *);
extern int hermon_fm_ereport_init(hermon_state_t *);
extern void hermon_fm_ereport_fini(hermon_state_t *);
extern int hermon_get_state(hermon_state_t *);
extern boolean_t hermon_init_failure(hermon_state_t *);
extern boolean_t hermon_cmd_retry_ok(hermon_cmd_post_t *, int);
extern void hermon_fm_ereport(hermon_state_t *, int, int);
extern int hermon_regs_map_setup(hermon_state_t *, uint_t, caddr_t *, offset_t,
    offset_t, ddi_device_acc_attr_t *, ddi_acc_handle_t *);
extern void hermon_regs_map_free(hermon_state_t *, ddi_acc_handle_t *);
extern int hermon_pci_config_setup(hermon_state_t *, ddi_acc_handle_t *);
extern void hermon_pci_config_teardown(hermon_state_t *, ddi_acc_handle_t *);
extern ushort_t hermon_devacc_attr_version(hermon_state_t *);
extern uchar_t hermon_devacc_attr_access(hermon_state_t *);
extern int hermon_PIO_start(hermon_state_t *, ddi_acc_handle_t,
    hermon_test_t *);
extern int hermon_PIO_end(hermon_state_t *, ddi_acc_handle_t, int *,
    hermon_test_t *);
extern ddi_acc_handle_t hermon_rsrc_alloc_uarhdl(hermon_state_t *);
extern ddi_acc_handle_t hermon_get_uarhdl(hermon_state_t *);
extern ddi_acc_handle_t hermon_get_cmdhdl(hermon_state_t *);
extern ddi_acc_handle_t hermon_get_msix_tblhdl(hermon_state_t *);
extern ddi_acc_handle_t hermon_get_msix_pbahdl(hermon_state_t *);
extern ddi_acc_handle_t hermon_get_pcihdl(hermon_state_t *);
extern void hermon_clr_state_nolock(hermon_state_t *, int);
extern void hermon_inter_err_chk(void *);

#ifdef FMA_TEST
extern hermon_test_t *hermon_test_register(hermon_state_t *, char *, int, int);
extern void hermon_test_deregister(void);
extern int hermon_test_num;
#endif /* FMA_TEST */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_HERMON_FM_H */
