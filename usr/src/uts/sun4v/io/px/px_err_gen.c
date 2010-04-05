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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * The file has been code generated.  Do NOT modify this file directly.  Please
 * use the sun4v PCIe FMA code generation tool.
 *
 * This file was generated for the following platforms:
 * - Fire
 * - N2PIU
 * - Rainbow Falls
 * - Victoria Falls
 */

#include <sys/pcie_impl.h>

/* ARGSUSED */
static int
px_cb_epkt_severity(dev_info_t *dip, ddi_fm_error_t *derr, px_rc_err_t *epkt,
    pf_data_t *pfd_p)
{
	int err = 0;

	/* STOP bit indicates a secondary error. Panic if it is set */
	if (epkt->rc_descr.STOP == 1)
		return (PX_PANIC);

	switch (epkt->rc_descr.op) {
	case OP_DMA:
		switch (epkt->rc_descr.phase) {
		case PH_ADDR:
			switch (epkt->rc_descr.cond) {
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_WRITE:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		case PH_DATA:
			switch (epkt->rc_descr.cond) {
			case CND_INT:
				switch (epkt->rc_descr.dir) {
				case DIR_READ:
					err = PX_PANIC;
					break;
				case DIR_RDWR:
					err = PX_PANIC;
					break;
				case DIR_UNKNOWN:
					err = PX_PANIC;
					break;
				case DIR_WRITE:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			case CND_TO:
				switch (epkt->rc_descr.dir) {
				case DIR_READ:
					err = PX_PANIC;
					break;
				case DIR_WRITE:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			case CND_UE:
				switch (epkt->rc_descr.dir) {
				case DIR_READ:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		case PH_UNKNOWN:
			switch (epkt->rc_descr.cond) {
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_READ:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			case CND_UNKNOWN:
				switch (epkt->rc_descr.dir) {
				case DIR_READ:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		} /* PH */
		break;
	case OP_PIO:
		switch (epkt->rc_descr.phase) {
		case PH_ADDR:
			switch (epkt->rc_descr.cond) {
			case CND_UNMAP:
				switch (epkt->rc_descr.dir) {
				case DIR_READ:
					err = PX_PANIC;
					break;
				case DIR_WRITE:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		case PH_DATA:
			switch (epkt->rc_descr.cond) {
			case CND_INT:
				switch (epkt->rc_descr.dir) {
				case DIR_RDWR:
					err = PX_PANIC;
					break;
				case DIR_UNKNOWN:
					err = PX_PANIC;
					break;
				case DIR_WRITE:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_WRITE:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		case PH_UNKNOWN:
			switch (epkt->rc_descr.cond) {
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_READ:
					err = PX_PANIC;
					break;
				case DIR_WRITE:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			case CND_TO:
				switch (epkt->rc_descr.dir) {
				case DIR_RDWR:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		} /* PH */
		break;
	case OP_UNKNOWN:
		switch (epkt->rc_descr.phase) {
		case PH_ADDR:
			switch (epkt->rc_descr.cond) {
			case CND_UNMAP:
				switch (epkt->rc_descr.dir) {
				case DIR_RDWR:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		case PH_DATA:
			switch (epkt->rc_descr.cond) {
			case CND_INT:
				switch (epkt->rc_descr.dir) {
				case DIR_UNKNOWN:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			case CND_UE:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		case PH_UNKNOWN:
			switch (epkt->rc_descr.cond) {
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = PX_PANIC;
					break;
				} /* DIR */
			} /* CND */
		} /* PH */
	} /* OP */

	return (err);
}


/* ARGSUSED */
static int
px_mmu_epkt_severity(dev_info_t *dip, ddi_fm_error_t *derr, px_rc_err_t *epkt,
    pf_data_t *pfd_p)
{
	int err = 0;

	/* STOP bit indicates a secondary error. Panic if it is set */
	if (epkt->rc_descr.STOP == 1)
		return (PX_PANIC);

	switch (epkt->rc_descr.op) {
	case OP_BYPASS:
		switch (epkt->rc_descr.phase) {
		case PH_ADDR:
			switch (epkt->rc_descr.cond) {
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_RDWR:
					err = PX_NO_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		case PH_UNKNOWN:
			switch (epkt->rc_descr.cond) {
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_UNKNOWN:
					err = PX_NO_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		} /* PH */
		break;
	case OP_TBW:
		switch (epkt->rc_descr.phase) {
		case PH_ADDR:
			switch (epkt->rc_descr.cond) {
			case CND_UNKNOWN:
				switch (epkt->rc_descr.dir) {
				case DIR_UNKNOWN:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			case CND_UNMAP:
				switch (epkt->rc_descr.dir) {
				case DIR_UNKNOWN:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		case PH_DATA:
			switch (epkt->rc_descr.cond) {
			case CND_INT:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		case PH_UNKNOWN:
			switch (epkt->rc_descr.cond) {
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			case CND_UNKNOWN:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = PX_PANIC;
					break;
				case DIR_UNKNOWN:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		} /* PH */
		break;
	case OP_XLAT:
		switch (epkt->rc_descr.phase) {
		case PH_ADDR:
			switch (epkt->rc_descr.cond) {
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_RDWR:
					err = PX_NO_PANIC;
					break;
				} /* DIR */
				break;
			case CND_IRR:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			case CND_PROT:
				switch (epkt->rc_descr.dir) {
				case DIR_RDWR:
					err = PX_NO_PANIC;
					break;
				} /* DIR */
				break;
			case CND_UNMAP:
				switch (epkt->rc_descr.dir) {
				case DIR_RDWR:
					err = PX_NO_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		case PH_DATA:
			switch (epkt->rc_descr.cond) {
			case CND_INT:
				switch (epkt->rc_descr.dir) {
				case DIR_UNKNOWN:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			case CND_INV:
				switch (epkt->rc_descr.dir) {
				case DIR_RDWR:
					err = PX_NO_PANIC;
					break;
				case DIR_UNKNOWN:
					err = PX_NO_PANIC;
					break;
				} /* DIR */
				break;
			case CND_IRR:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			case CND_PROT:
				switch (epkt->rc_descr.dir) {
				case DIR_RDWR:
					err = PX_NO_PANIC;
					break;
				case DIR_WRITE:
					err = PX_NO_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		case PH_UNKNOWN:
			switch (epkt->rc_descr.cond) {
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = PX_PANIC;
					break;
				} /* DIR */
			} /* CND */
		} /* PH */
	} /* OP */

	if (epkt->rc_descr.D && (err & (PX_PANIC | PX_PROTECTED)) &&
	    px_mmu_handle_lookup(dip, derr, epkt) == PF_HDL_FOUND)
		err = PX_NO_PANIC;

	return (err);
}


/* ARGSUSED */
static int
px_intr_epkt_severity(dev_info_t *dip, ddi_fm_error_t *derr, px_rc_err_t *epkt,
    pf_data_t *pfd_p)
{
	int err = 0;

	/* STOP bit indicates a secondary error. Panic if it is set */
	if (epkt->rc_descr.STOP == 1)
		return (PX_PANIC);

	switch (epkt->rc_descr.op) {
	case OP_FIXED:
		switch (epkt->rc_descr.phase) {
		case PH_UNKNOWN:
			switch (epkt->rc_descr.cond) {
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_INGRESS:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		} /* PH */
		break;
	case OP_MSI32:
		switch (epkt->rc_descr.phase) {
		case PH_DATA:
			switch (epkt->rc_descr.cond) {
			case CND_INT:
				switch (epkt->rc_descr.dir) {
				case DIR_UNKNOWN:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		case PH_UNKNOWN:
			switch (epkt->rc_descr.cond) {
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		} /* PH */
		break;
	case OP_MSI64:
		switch (epkt->rc_descr.phase) {
		case PH_DATA:
			switch (epkt->rc_descr.cond) {
			case CND_INT:
				switch (epkt->rc_descr.dir) {
				case DIR_UNKNOWN:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		case PH_UNKNOWN:
			switch (epkt->rc_descr.cond) {
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		} /* PH */
		break;
	case OP_MSIQ:
		switch (epkt->rc_descr.phase) {
		case PH_DATA:
			switch (epkt->rc_descr.cond) {
			case CND_INT:
				switch (epkt->rc_descr.dir) {
				case DIR_UNKNOWN:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		case PH_UNKNOWN:
			switch (epkt->rc_descr.cond) {
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			case CND_OV:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = px_intr_handle_errors(dip, derr,
					    epkt, pfd_p);
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		} /* PH */
		break;
	case OP_PCIEMSG:
		switch (epkt->rc_descr.phase) {
		case PH_UNKNOWN:
			switch (epkt->rc_descr.cond) {
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_INGRESS:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		} /* PH */
		break;
	case OP_UNKNOWN:
		switch (epkt->rc_descr.phase) {
		case PH_DATA:
			switch (epkt->rc_descr.cond) {
			case CND_INT:
				switch (epkt->rc_descr.dir) {
				case DIR_UNKNOWN:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		case PH_UNKNOWN:
			switch (epkt->rc_descr.cond) {
			case CND_ILL:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = PX_PANIC;
					break;
				} /* DIR */
			} /* CND */
		} /* PH */
	} /* OP */

	return (err);
}


/* ARGSUSED */
static int
px_port_epkt_severity(dev_info_t *dip, ddi_fm_error_t *derr, px_rc_err_t *epkt,
    pf_data_t *pfd_p)
{
	int err = 0;

	/* STOP bit indicates a secondary error. Panic if it is set */
	if (epkt->rc_descr.STOP == 1)
		return (PX_PANIC);

	switch (epkt->rc_descr.op) {
	case OP_DMA:
		switch (epkt->rc_descr.phase) {
		case PH_DATA:
			switch (epkt->rc_descr.cond) {
			case CND_INT:
				switch (epkt->rc_descr.dir) {
				case DIR_READ:
					err = PX_PANIC;
					PFD_SET_AFFECTED_FLAG(pfd_p,
					    PF_AFFECTED_BDF);
					PFD_SET_AFFECTED_BDF(pfd_p,
					    (uint16_t)epkt->reserved);
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		} /* PH */
		break;
	case OP_LINK:
		switch (epkt->rc_descr.phase) {
		case PH_FC:
			switch (epkt->rc_descr.cond) {
			case CND_TO:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = PX_PANIC;
					PFD_SET_AFFECTED_FLAG(pfd_p,
					    PF_AFFECTED_BDF);
					PFD_SET_AFFECTED_BDF(pfd_p,
					    (uint16_t)epkt->reserved);
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		} /* PH */
		break;
	case OP_PIO:
		switch (epkt->rc_descr.phase) {
		case PH_DATA:
			switch (epkt->rc_descr.cond) {
			case CND_INT:
				switch (epkt->rc_descr.dir) {
				case DIR_READ:
					err = PX_PANIC;
					PFD_SET_AFFECTED_FLAG(pfd_p,
					    PF_AFFECTED_BDF);
					PFD_SET_AFFECTED_BDF(pfd_p,
					    (uint16_t)epkt->reserved);
					break;
				case DIR_UNKNOWN:
					err = PX_PANIC;
					PFD_SET_AFFECTED_FLAG(pfd_p,
					    PF_AFFECTED_BDF);
					PFD_SET_AFFECTED_BDF(pfd_p,
					    (uint16_t)epkt->reserved);
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		case PH_IRR:
			switch (epkt->rc_descr.cond) {
			case CND_INV:
				switch (epkt->rc_descr.dir) {
				case DIR_RDWR:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			case CND_RCA:
				switch (epkt->rc_descr.dir) {
				case DIR_WRITE:
					err = px_port_handle_errors(dip, derr,
					    epkt, pfd_p);
					break;
				} /* DIR */
				break;
			case CND_RUR:
				switch (epkt->rc_descr.dir) {
				case DIR_WRITE:
					err = px_port_handle_errors(dip, derr,
					    epkt, pfd_p);
					break;
				} /* DIR */
				break;
			case CND_TO:
				switch (epkt->rc_descr.dir) {
				case DIR_WRITE:
					err = PX_PANIC;
					break;
				} /* DIR */
				break;
			case CND_UC:
				switch (epkt->rc_descr.dir) {
				case DIR_IRR:
					err = PX_NO_PANIC;
					break;
				} /* DIR */
				break;
			} /* CND */
			break;
		} /* PH */
		break;
	case OP_UNKNOWN:
		switch (epkt->rc_descr.phase) {
		case PH_DATA:
			switch (epkt->rc_descr.cond) {
			case CND_INT:
				switch (epkt->rc_descr.dir) {
				case DIR_UNKNOWN:
					err = PX_PANIC;
					PFD_SET_AFFECTED_FLAG(pfd_p,
					    PF_AFFECTED_BDF);
					PFD_SET_AFFECTED_BDF(pfd_p,
					    (uint16_t)epkt->reserved);
					break;
				} /* DIR */
			} /* CND */
		} /* PH */
	} /* OP */

	return (err);
}
