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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SCSI_IMPL_TRANSPORT_H
#define	_SYS_SCSI_IMPL_TRANSPORT_H

/*
 * Include the loadable module wrapper.
 */
#include <sys/modctl.h>
#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/*
 * SCSI transport structures
 *
 *	As each Host Adapter makes itself known to the system,
 *	it will create and register with the library the structure
 *	described below. This is so that the library knows how to route
 *	packets, resource control requests, and capability requests
 *	for any particular host adapter. The 'a_hba_tran' field of a
 *	scsi_address structure made known to a Target driver will
 *	point to one of these transport structures.
 */

typedef struct scsi_hba_tran	scsi_hba_tran_t;

struct scsi_hba_tran {
	/*
	 * Ptr to the device info structure for this particular HBA.
	 */
	dev_info_t	*tran_hba_dip;

	/*
	 * Private fields for use by the HBA itself.
	 */
	void		*tran_hba_private;	/* HBA softstate */

	/*
	 * The following two fields are only used in the SCSI_HBA_TRAN_CLONE
	 * case. Consider using SCSI_HBA_ADDR_COMPLEX instead.
	 */
	void			*tran_tgt_private;
	struct scsi_device	*tran_sd;

	/*
	 * Vectors to point to specific HBA entry points
	 */
	int		(*tran_tgt_init)(
				dev_info_t		*hba_dip,
				dev_info_t		*tgt_dip,
				scsi_hba_tran_t		*tran,
				struct scsi_device	*sd);

	int		(*tran_tgt_probe)(
				struct scsi_device	*sd,
				int			(*callback)(
								void));
	void		(*tran_tgt_free)(
				dev_info_t		*hba_dip,
				dev_info_t		*tgt_dip,
				scsi_hba_tran_t		*tran,
				struct scsi_device	*sd);

	int		(*tran_start)(
				struct scsi_address	*ap,
				struct scsi_pkt		*pkt);

	int		(*tran_reset)(
				struct scsi_address	*ap,
				int			level);

	int		(*tran_abort)(
				struct scsi_address	*ap,
				struct scsi_pkt		*pkt);

	int		(*tran_getcap)(
				struct scsi_address	*ap,
				char			*cap,
				int			whom);

	int		(*tran_setcap)(
				struct scsi_address	*ap,
				char			*cap,
				int			value,
				int			whom);

	struct scsi_pkt	*(*tran_init_pkt)(
				struct scsi_address	*ap,
				struct scsi_pkt		*pkt,
				struct buf		*bp,
				int			cmdlen,
				int			statuslen,
				int			tgtlen,
				int			flags,
				int			(*callback)(
								caddr_t	arg),
				caddr_t			callback_arg);

	void		(*tran_destroy_pkt)(
				struct scsi_address	*ap,
				struct scsi_pkt		*pkt);

	void		(*tran_dmafree)(
				struct scsi_address	*ap,
				struct scsi_pkt		*pkt);

	void		(*tran_sync_pkt)(
				struct scsi_address	*ap,
				struct scsi_pkt		*pkt);

	int		(*tran_reset_notify)(
				struct scsi_address	*ap,
				int			flag,
				void			(*callback)(caddr_t),
				caddr_t			arg);

	int		(*tran_get_bus_addr)(
				struct scsi_device	*sd,
				char			*name,
				int			len);

	int		(*tran_get_name)(
				struct scsi_device	*sd,
				char			*name,
				int			len);

	int		(*tran_clear_aca)(
				struct scsi_address	*ap);

	int		(*tran_clear_task_set)(
				struct scsi_address	*ap);

	int		(*tran_terminate_task)(
				struct scsi_address	*ap,
				struct scsi_pkt		*pkt);

	int		(*tran_get_eventcookie)(
				dev_info_t		*hba_dip,
				dev_info_t		*tgt_dip,
				char			*name,
				ddi_eventcookie_t	*eventp);

	int		(*tran_add_eventcall)(
				dev_info_t		*hba_dip,
				dev_info_t		*tgt_dip,
				ddi_eventcookie_t	event,
				void			(*callback)(
						dev_info_t *tgt_dip,
						ddi_eventcookie_t event,
						void *arg,
						void *bus_impldata),
				void			*arg,
				ddi_callback_id_t *cb_id);

	int		(*tran_remove_eventcall)(dev_info_t *devi,
			ddi_callback_id_t cb_id);

	int		(*tran_post_event)(
				dev_info_t		*hba_dip,
				dev_info_t		*tgt_dip,
				ddi_eventcookie_t	event,
				void			*bus_impldata);

	int		(*tran_quiesce)(
				dev_info_t		*hba_dip);

	int		(*tran_unquiesce)(
				dev_info_t		*hba_dip);

	int		(*tran_bus_reset)(
				dev_info_t		*hba_dip,
				int			level);

	/*
	 * Implementation-private specifics.
	 * No HBA should refer to any of the fields below.
	 * This information can and will change.
	 */
	int			tran_hba_flags;		/* flag options */

	uint_t			tran_obs1;
	uchar_t			tran_obs2;
	uchar_t			tran_obs3;

	/*
	 * open_lock: protect tran_minor_isopen
	 * open_flag: bit field indicating which minor nodes are open.
	 *	0 = closed, 1 = shared open, all bits 1 = excl open.
	 *
	 * XXX Unused if hba driver chooses to implement own
	 *	xxopen(9e) entry point
	 */
	kmutex_t		tran_open_lock;
	uint64_t		tran_open_flag;

	/*
	 * bus_config vectors - ON Consolidation Private
	 * These interfaces are subject to change.
	 */
	int		(*tran_bus_config)(
				dev_info_t		*hba_dip,
				uint_t			flag,
				ddi_bus_config_op_t	op,
				void			*arg,
				dev_info_t		**tgt_dipp);

	int		(*tran_bus_unconfig)(
				dev_info_t		*hba_dip,
				uint_t			flag,
				ddi_bus_config_op_t	op,
				void			*arg);

	int		(*tran_bus_power)(
				dev_info_t		*dip,
				void			*impl_arg,
				pm_bus_power_op_t	op,
				void			*arg,
				void			*result);

	/*
	 * Inter-Connect type of trasnport as defined in
	 * usr/src/uts/common/sys/scsi/impl/services.h
	 */
	int		tran_interconnect_type;

	/* tran_setup_pkt(9E) related scsi_pkt fields */
	int		(*tran_pkt_constructor)(
				struct scsi_pkt		*pkt,
				scsi_hba_tran_t		*tran,
				int			kmflag);
	void		(*tran_pkt_destructor)(
				struct scsi_pkt		*pkt,
				scsi_hba_tran_t		*tran);
	kmem_cache_t	*tran_pkt_cache_ptr;
	uint_t		tran_hba_len;
	int		(*tran_setup_pkt)(
				struct scsi_pkt		*pkt,
				int			(*callback)(
								caddr_t	arg),
				caddr_t			callback_arg);
	void		(*tran_teardown_pkt)(
				struct scsi_pkt		*pkt);
	ddi_dma_attr_t	tran_dma_attr;

	void		*tran_extension;

	/*
	 * An fm_capable HBA driver can set tran_fm_capable prior to
	 * scsi_hba_attach_setup(). If not set, SCSA provides a default
	 * implementation.
	 */
	int		tran_fm_capable;

#ifdef	SCSI_SIZE_CLEAN_VERIFY
	/*
	 * Must be last: Building a driver with-and-without
	 * -DSCSI_SIZE_CLEAN_VERIFY, and checking driver modules for
	 * differences with a tools like 'wsdiff' allows a developer to verify
	 * that their driver has no dependencies on scsi*(9S) size.
	 */
	int		_pad[8];
#endif	/* SCSI_SIZE_CLEAN_VERIFY */
};
size_t	scsi_hba_tran_size();			/* private */

#ifdef __lock_lint
_NOTE(SCHEME_PROTECTS_DATA("stable data",
	scsi_hba_tran::tran_sd
	scsi_hba_tran::tran_hba_dip
	scsi_hba_tran::tran_hba_flags
	scsi_hba_tran::tran_open_flag
	scsi_hba_tran::tran_pkt_cache_ptr))
/*
 * we only modify the dma atributes (like dma_attr_granular) upon
 * attach and in response to a setcap. It is also up to the target
 * driver to not have any outstanding I/Os when it is changing the
 * capabilities of the transport.
 */
_NOTE(SCHEME_PROTECTS_DATA("serialized by target driver", \
	scsi_hba_tran::tran_dma_attr.dma_attr_granular))
#endif

/*
 * Prototypes for SCSI HBA interface functions
 *
 * All these functions are public interfaces, with the
 * exception of:
 *	interface				called by
 *	scsi_initialize_hba_interface()		_init() of scsi module
 *	scsi_uninitialize_hba_interface()	_fini() of scsi module
 */

void		scsi_initialize_hba_interface(void);

#ifdef	NO_SCSI_FINI_YET
void		scsi_uninitialize_hba_interface(void);
#endif	/* NO_SCSI_FINI_YET */

int		scsi_hba_init(
				struct modlinkage	*modlp);

void		scsi_hba_fini(
				struct modlinkage	*modlp);

int		scsi_hba_attach(
				dev_info_t		*hba_dip,
				ddi_dma_lim_t		*hba_lim,
				scsi_hba_tran_t		*tran,
				int			flags,
				void			*hba_options);

int		scsi_hba_attach_setup(
				dev_info_t		*hba_dip,
				ddi_dma_attr_t		*hba_dma_attr,
				scsi_hba_tran_t		*tran,
				int			flags);

int		scsi_hba_detach(
				dev_info_t		*hba_dip);

scsi_hba_tran_t	*scsi_hba_tran_alloc(
				dev_info_t		*hba_dip,
				int			flags);

int		scsi_tran_ext_alloc(
				scsi_hba_tran_t		*tran,
				size_t			length,
				int			flags);

void		scsi_tran_ext_free(
				scsi_hba_tran_t		*tran,
				size_t			length);

void		scsi_hba_tran_free(
				scsi_hba_tran_t		*tran);

int		scsi_hba_probe(
				struct scsi_device	*sd,
				int			(*callback)(void));

char			*scsi_get_device_type_string(
				char			*prop_name,
				dev_info_t		*hba_dip,
				struct scsi_device	*sd);

int		scsi_get_scsi_maxluns(
				struct scsi_device	*sd);

int		scsi_get_scsi_options(
				struct scsi_device	*sd,
				int			default_scsi_options);

int		scsi_get_device_type_scsi_options(
				dev_info_t		*hba_dip,
				struct scsi_device	*sd,
				int			default_scsi_options);

struct scsi_pkt	*scsi_hba_pkt_alloc(
				dev_info_t		*hba_dip,
				struct scsi_address	*ap,
				int			cmdlen,
				int			statuslen,
				int			tgtlen,
				int			hbalen,
				int			(*callback)(caddr_t),
				caddr_t			arg);

void		scsi_hba_pkt_free(
				struct scsi_address	*ap,
				struct scsi_pkt		*pkt);


int		scsi_hba_lookup_capstr(
				char			*capstr);

int		scsi_hba_in_panic(void);

int		scsi_hba_open(
				dev_t			*devp,
				int			flags,
				int			otyp,
				cred_t			*credp);

int		scsi_hba_close(
				dev_t			dev,
				int			flag,
				int			otyp,
				cred_t			*credp);

int		scsi_hba_ioctl(
				dev_t			dev,
				int			cmd,
				intptr_t		arg,
				int			mode,
				cred_t			*credp,
				int			*rvalp);

void		scsi_hba_nodename_compatible_get(
				struct scsi_inquiry	*inq,
				char			*binding_set,
				int			dtype_node,
				char			*compat0,
				char			**nodenamep,
				char			***compatiblep,
				int			*ncompatiblep);

void		scsi_hba_nodename_compatible_free(
				char			*nodename,
				char			**compatible);


int		scsi_hba_prop_update_inqstring(
				struct scsi_device	*sd,
				char			*name,
				char			*data,
				size_t			len);

/*
 * Flags for scsi_hba_attach
 *
 * SCSI_HBA_ADDR_SPI		The host adapter driver wants the
 *				scsi_address(9S) structure to be maintained
 *				in legacy SPI 'a_target'/'a_lun' form (default).
 *
 * SCSI_HBA_ADDR_COMPLEX	The host adapter has a complex unit-address
 *				space, and the HBA driver wants to maintain
 *				per-scsi_device(9S) HBA private data using
 *				scsi_address_device(9F) and
 *				scsi_device_hba_private_[gs]et(9F).  The HBA
 *				driver must maintain a private representation
 *				of the scsi_device(9S) unit-address - typically
 *				established during tran_tgt_init(9F) based on
 *				property values.
 *
 * SCSI_HBA_TRAN_CLONE		Consider using SCSI_HBA_ADDR_COMPLEX instead.
 *				SCSI_HBA_TRAN_CLONE is a KLUDGE to address
 *				limitations of the scsi_address(9S) structure
 *				via duplication of scsi_hba_tran(9S) and
 *				use of tran_tgt_private.
 */
#define	SCSI_HBA_TRAN_CLONE	0x01		/* clone scsi_hba_tran(9S) */
						/* structure per scsi_device */
#define	SCSI_HBA_TRAN_ALLOC	0x02		/* set if scsi_hba_tran_alloc */
						/* is called */
#define	SCSI_HBA_TRAN_CDB	0x04		/* allocate cdb */
#define	SCSI_HBA_TRAN_SCB	0x08		/* allocate sense */
#define	SCSI_HBA_TRAN_FMSCSA	0x10		/* using common ddi_fm_* */

#define	SCSI_HBA_ADDR_SPI	0x20		/* scsi_address in SPI form */
#define	SCSI_HBA_ADDR_COMPLEX	0x40		/* scsi_address is COMPLEX */

/*
 * Flags for scsi_hba allocation functions
 */
#define	SCSI_HBA_CANSLEEP	0x01		/* can sleep */

/*
 * For minor nodes created by the SCSA framework, minor numbers are
 * formed by left-shifting instance by INST_MINOR_SHIFT and OR in a
 * number less than 64.
 *
 * - Numbers 0 - 31 are reserved by the framework, part of the range are
 *	in use, as defined below.
 *
 * - Numbers 32 - 63 are available for HBA driver use.
 */
#define	INST_MINOR_SHIFT	6
#define	TRAN_MINOR_MASK		((1 << INST_MINOR_SHIFT) - 1)
#define	TRAN_OPEN_EXCL		(uint64_t)-1

#define	DEVCTL_MINOR		0
#define	SCSI_MINOR		1

#define	INST2DEVCTL(x)		(((x) << INST_MINOR_SHIFT) | DEVCTL_MINOR)
#define	INST2SCSI(x)		(((x) << INST_MINOR_SHIFT) | SCSI_MINOR)
#define	MINOR2INST(x)		((x) >> INST_MINOR_SHIFT)

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_IMPL_TRANSPORT_H */
