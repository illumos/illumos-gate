/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2016 Jakub Klama <jceel@FreeBSD.org>.
 * Copyright (c) 2018 Marcelo Araujo <araujo@FreeBSD.org>.
 * Copyright (c) 2026 Hans Rosenfeld
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/linker_set.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/queue.h>

#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <pthread_np.h>

#include <scsi/libscsi.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/impl/uscsi.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "pci_emul.h"
#include "virtio.h"
#include "iov.h"
#include "privileges.h"
#include "pci_virtio_scsi.h"

struct vtscsi_uscsi_backend {
	struct pci_vtscsi_backend	vub_backend;
	libscsi_hdl_t			*vub_scsi_hdl;
};

static int vtscsi_uscsi_init(struct pci_vtscsi_softc *,
    struct pci_vtscsi_backend *, nvlist_t *);
static int vtscsi_uscsi_open(struct pci_vtscsi_softc *, const char *, long);
static void vtscsi_uscsi_reset(struct pci_vtscsi_softc *);

static void *vtscsi_uscsi_req_alloc(struct pci_vtscsi_softc *);
static void vtscsi_uscsi_req_clear(void  *);
static void vtscsi_uscsi_req_free(void *);

static void vtscsi_uscsi_tmf_hdl(struct pci_vtscsi_softc *, int,
    struct pci_vtscsi_ctrl_tmf *);
static void vtscsi_uscsi_an_hdl(struct pci_vtscsi_softc *, int,
    struct pci_vtscsi_ctrl_an *);
static int vtscsi_uscsi_req_hdl(struct pci_vtscsi_softc *, int,
    struct pci_vtscsi_request *);

static void vtscsi_uscsi_make_check_condition(struct uscsi_cmd *, char, char,
    char);
static void vtscsi_uscsi_filter_post_report_luns(struct uscsi_cmd *);
static void vtscsi_uscsi_filter_post(struct uscsi_cmd *);


static int
vtscsi_uscsi_init(struct pci_vtscsi_softc *sc,
    struct pci_vtscsi_backend *backend, nvlist_t *nvl __unused)
{
	struct vtscsi_uscsi_backend *uscsi_backend;
	libscsi_errno_t serr;

	uscsi_backend = calloc(1, sizeof (struct vtscsi_uscsi_backend));
	if (uscsi_backend == NULL) {
		EPRINTLN("failed to allocate backend data: %s",
		    strerror(errno));
		return (-1);
	}

	uscsi_backend->vub_backend = *backend;

	uscsi_backend->vub_scsi_hdl = libscsi_init(LIBSCSI_VERSION, &serr);
	if (uscsi_backend->vub_scsi_hdl == NULL) {
		EPRINTLN("failed to initialize libscsi: %s",
		    libscsi_strerror(serr));
		free(uscsi_backend);
		return (-1);
	}

	sc->vss_backend = &uscsi_backend->vub_backend;

	return (0);
}

static int
vtscsi_uscsi_open(struct pci_vtscsi_softc *sc, const char *path, long target)
{
	struct pci_vtscsi_target *tgt = &sc->vss_targets[target];
	uscsi_xfer_t maxxfer = 0;

	/*
	 * Most SCSI target drivers require the SYS_DEVICES privilege to send
	 * USCSI commands.
	 */
	illumos_priv_add_min(PRIV_SYS_DEVICES, "scsi");

	/*
	 * Open the target.
	 */
	tgt->vst_fd = open(path, O_RDWR);
	if (tgt->vst_fd < 0)
		return (-1);

	/*
	 * Get the maximum transfer size of the backend device.
	 */
	if (ioctl(tgt->vst_fd, USCSIMAXXFER, &maxxfer) < 0) {
		int errno_save = errno;

		if (errno == ENOTTY) {
			/*
			 * The underlying device doesn't support this ioctl.
			 * Limit max_sectors to 128MB, which is as good as
			 * any other assumption.
			 */
			tgt->vst_max_sectors = 128 << (20 - 9);
			return (0);
		}

		WPRINTF("USCSIMAXXFER: unexpected error: errno=%d (%s)",
		    strerrorname_np(errno), strerror(errno));
		(void) close(tgt->vst_fd);
		tgt->vst_fd = -1;
		errno = errno_save;
		return (-1);
	}

	/*
	 * Even though the virtio spec isn't particularly verbose about what
	 * "max_sectors" actually means and what size a sector is, Linux seems
	 * to treat it as a number of 512b sectors.
	 *
	 * In any case, we need to limit maxxfer such that it fits into a signed
	 * 32bit int.
	 */
	if (maxxfer > INT32_MAX)
		maxxfer = INT32_MAX;

	tgt->vst_max_sectors = maxxfer >> 9;

	return (0);
}

static void
vtscsi_uscsi_reset(struct pci_vtscsi_softc *sc)
{
	size_t i;

	sc->vss_config.max_sectors = INT32_MAX;

	/*
	 * As we may be configured to use a variety of differing backend devices
	 * with varying maximum transfer sizes but virtio-scsi supports only one
	 * max_sectors limit per instance, we'll use the smallest maximum
	 * transfer size found.
	 */
	for (i = 0; i < sc->vss_num_target; i++) {
		struct pci_vtscsi_target *tgt = &sc->vss_targets[i];

		if (tgt->vst_max_sectors < sc->vss_config.max_sectors)
			sc->vss_config.max_sectors = tgt->vst_max_sectors;
	}
}

static void *
vtscsi_uscsi_req_alloc(struct pci_vtscsi_softc *sc)
{
	return (calloc(1, sizeof (struct uscsi_cmd)));
}

static void
vtscsi_uscsi_req_clear(void *io)
{
	bzero(io, sizeof (struct uscsi_cmd));
}

static void
vtscsi_uscsi_req_free(void *io)
{
	free(io);
}

static void
vtscsi_uscsi_tmf_hdl(struct pci_vtscsi_softc *sc __unused, int fd,
    struct pci_vtscsi_ctrl_tmf *tmf)
{
	struct uscsi_cmd cmd;
	int err;

	/* We currently support only LUN 0. */
	if (pci_vtscsi_get_lun(sc, tmf->lun) != 0) {
		tmf->response = VIRTIO_SCSI_S_BAD_TARGET;
		return;
	}

	tmf->response = VIRTIO_SCSI_S_FUNCTION_COMPLETE;

	memset(&cmd, 0, sizeof (cmd));
	cmd.uscsi_status = -1;
	cmd.uscsi_flags = USCSI_DIAGNOSE | USCSI_SILENT;


	/* The only TMF requests that we can handle here are RESETs. */
	switch (tmf->subtype) {
	case VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET:
		cmd.uscsi_flags |= USCSI_RESET_TARGET;
		break;

	case VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET:
		cmd.uscsi_flags |= USCSI_RESET_LUN;
		break;

	default:
		/*
		 * For all other TMF requests, return FUNCTION COMPLETE as
		 * there is nothing we can or need to do for them.
		 *
		 * See the comments in pci_vtscsi_tmf_handle() for additional
		 * information on how the common code and the backend-specific
		 * code interact for TMF requests.
		 */
		tmf->response = VIRTIO_SCSI_S_FUNCTION_COMPLETE;
		return;
	}

	err = ioctl(fd, USCSICMD, &cmd);

	if (err != 0) {
		WPRINTF("USCSICMD: unexpected TMF error, errno=%d (%s)",
		    strerrorname_np(errno), strerror(errno));
		tmf->response = VIRTIO_SCSI_S_FAILURE;
	}
}

static void
vtscsi_uscsi_an_hdl(struct pci_vtscsi_softc *sc __unused, int fd __unused,
    struct pci_vtscsi_ctrl_an *an)
{
	/* We currently support only LUN 0. */
	if (pci_vtscsi_get_lun(sc, an->lun) != 0) {
		an->response = VIRTIO_SCSI_S_BAD_TARGET;
		return;
	}

	an->response = VIRTIO_SCSI_S_FAILURE;
}

static int
vtscsi_uscsi_req_hdl(struct pci_vtscsi_softc *sc, int fd,
    struct pci_vtscsi_request *req)
{
	struct vtscsi_uscsi_backend *uscsi =
	    (struct vtscsi_uscsi_backend *)sc->vss_backend;
	struct uscsi_cmd *cmd = req->vsr_backend;
	void *ext_data = NULL;
	ssize_t ext_data_len = 0;
	int nxferred = 0;

	/* We currently support only LUN 0. */
	if (pci_vtscsi_get_lun(sc, req->vsr_cmd_rd->lun) != 0) {
		req->vsr_cmd_wr->response = VIRTIO_SCSI_S_BAD_TARGET;
		return (0);
	}

	if (req->vsr_data_niov_in > 0) {
		ext_data_len = iov_to_buf(req->vsr_data_iov_in,
		    req->vsr_data_niov_in, &ext_data);
		cmd->uscsi_flags |= USCSI_WRITE;
	} else if (req->vsr_data_niov_out > 0) {
		ext_data_len = count_iov(req->vsr_data_iov_out,
		    req->vsr_data_niov_out);
		ext_data = malloc(ext_data_len);
		cmd->uscsi_flags |= USCSI_READ;
	}

	/* Stop here if we failed to allocate ext_data. */
	if (ext_data == NULL && ext_data_len != 0) {
		WPRINTF("failed to allocate buffer for ext_data");
		req->vsr_cmd_wr->response = VIRTIO_SCSI_S_FAILURE;
		return (0);
	}

	cmd->uscsi_buflen = ext_data_len;
	cmd->uscsi_bufaddr = ext_data;

	cmd->uscsi_cdb = (caddr_t)req->vsr_cmd_rd->cdb;
	cmd->uscsi_cdblen = libscsi_cmd_cdblen(uscsi->vub_scsi_hdl,
	    req->vsr_cmd_rd->cdb[0]);

	cmd->uscsi_status = -1;

	/*
	 * We set an unreasonably large timeout here. The virtio spec doesn't
	 * provide a way for the guest driver to pass a I/O timeout value to
	 * the device, but if our timeout here is larger than any timeout the
	 * guest uses, we can expect them to abort the command before we would.
	 *
	 * INT16_MAX corresponds to a bit over 9 hours, which should be enough.
	 */
	cmd->uscsi_timeout = INT16_MAX;
	cmd->uscsi_flags |= USCSI_DIAGNOSE;
	cmd->uscsi_rqlen = sc->vss_config.sense_size;
	cmd->uscsi_rqbuf = (caddr_t)req->vsr_cmd_wr->sense;
	cmd->uscsi_flags |= USCSI_RQENABLE;

	switch (req->vsr_cmd_rd->task_attr) {
	case VIRTIO_SCSI_S_ORDERED:
		cmd->uscsi_flags |= USCSI_OTAG;
		break;
	case VIRTIO_SCSI_S_HEAD:
		cmd->uscsi_flags |= USCSI_HEAD|USCSI_HTAG;
		break;
	case VIRTIO_SCSI_S_SIMPLE:
		break;

	case VIRTIO_SCSI_S_ACA:
		/*
		 * I haven't found any indication in our code that would
		 * suggest that we support ACA in any way in illumos. In
		 * fact, scsi_transport() asserts that NACA isn't set in
		 * a packet, and scsi_uscsi_pktinit() warns about it and
		 * clears the flag if found set. There's a tunable to
		 * override that behaviour (scsi_pkt_allow_naca), but there
		 * really seems to be no code properly handling ACA or
		 * setting the ACA flag.
		 *
		 * I guess this makes sense since we're doing ARQ anyway,
		 * so let's just pretend no target is ever in ACA state
		 * and thus no packet will ever require this.
		 */
	default:
		WPRINTF("USCSICMD: unexpected task attr in request: 0x%x",
		    req->vsr_cmd_rd->task_attr);
		req->vsr_cmd_wr->response = VIRTIO_SCSI_S_FAILURE;
		return (0);
	}

	errno = 0;
	(void) ioctl(fd, USCSICMD, cmd);

	switch (errno) {
	case EIO:
		/*
		 * EIO may indicate that a SCSI error occured. If that's the
		 * case, uscsi_status should have been set to a valid value,
		 * and we want to continue to process the request normally.
		 */
		if (cmd->uscsi_status == -1) {
			req->vsr_cmd_wr->response = VIRTIO_SCSI_S_FAILURE;
			break;
		}

		/*FALLTHRU*/
	case 0:
		/*
		 * If the command completed successfully, apply any necessary
		 * post-completion filtering.
		 */
		if (cmd->uscsi_status == STATUS_GOOD)
			vtscsi_uscsi_filter_post(cmd);

		req->vsr_cmd_wr->sense_len =
		    sc->vss_config.sense_size - cmd->uscsi_rqresid;
		req->vsr_cmd_wr->residual = cmd->uscsi_resid;
		req->vsr_cmd_wr->status = cmd->uscsi_status;
		req->vsr_cmd_wr->response = VIRTIO_SCSI_S_OK;

		nxferred = ext_data_len - req->vsr_cmd_wr->residual;

		if (req->vsr_data_niov_out > 0) {
			(void) buf_to_iov(ext_data, nxferred,
			    req->vsr_data_iov_out, req->vsr_data_niov_out);
		}
		break;

	case EAGAIN:
		/*
		 * Despite not being documented in uscsi(4I), sd(4D) returns
		 * this when the device is busy formatting.
		 */
		req->vsr_cmd_wr->response = VIRTIO_SCSI_S_BUSY;
		break;

	case EINVAL:
		/*
		 * This may happen if packet allocation fails, which in turn
		 * may happen if we didn't honor USCSIMAXXFER.
		 */
		req->vsr_cmd_wr->response = VIRTIO_SCSI_S_OVERRUN;
		break;

	case EFAULT:
		/*
		 * EFAULT should never happen as we never send bogus memory
		 * addresses in our USCSI commands.
		 */

	case EPERM:
		/*
		 * EPERM should never happen as we have the SYS_DEVICES
		 * privilege.
		 */

	default:
		WPRINTF("USCSICMD: unexpected I/O error: errno=%d (%s)",
		    strerrorname_np(errno), strerror(errno));
		abort();
	}

	free(ext_data);

	return (nxferred);
}

/*
 * Return a CHECK CONDITION and fill in the sense data with the given sense key,
 * additional sense code, and additional sense qualifier.
 */
static void
vtscsi_uscsi_make_check_condition(struct uscsi_cmd *cmd, char key, char asc,
    char qual)
{
	cmd->uscsi_status = STATUS_CHECK;
	cmd->uscsi_resid = cmd->uscsi_buflen;
	cmd->uscsi_rqstatus = STATUS_GOOD;

	bzero(cmd->uscsi_rqbuf, cmd->uscsi_rqlen);

	if (cmd->uscsi_rqlen >= 1)
		cmd->uscsi_rqbuf[0] = 0x70;
	if (cmd->uscsi_rqlen >= 3)
		cmd->uscsi_rqbuf[2] = key;
	if (cmd->uscsi_rqlen >= 8)
		cmd->uscsi_rqbuf[7] = cmd->uscsi_rqlen - 8;
	if (cmd->uscsi_rqlen >= 13)
		cmd->uscsi_rqbuf[12] = asc;
	if (cmd->uscsi_rqlen >= 14)
		cmd->uscsi_rqbuf[13] = qual;
}

/*
 * We currently only support LUN 0. Make sure we never report anything else.
 *
 * We make no assumption about the buffer size. If it's large enough to hold the
 * LUN list length, we'll set the LUN list length to 8. The resid is adjusted if
 * the buffer size is larger than 16 bytes, which is the length needed to hold
 * one LUN address.
 */
static void
vtscsi_uscsi_filter_post_report_luns(struct uscsi_cmd *cmd)
{
	uint8_t report = (uint8_t)cmd->uscsi_cdb[2];

	bzero(cmd->uscsi_bufaddr, cmd->uscsi_buflen);

	switch (report) {
	case 0:
	case 2:
		/*
		 * We'll overwrite the output from the device to report just one
		 * LUN with an all-zero address:
		 * - LUN list length is 8
		 * - LUN 1 address is 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
		 */
		if (cmd->uscsi_buflen >= 4)
			cmd->uscsi_bufaddr[3] = 8;
		if (cmd->uscsi_buflen >= 16)
			cmd->uscsi_resid = cmd->uscsi_buflen - 16;
		break;
	case 1:
		/*
		 * We don't report any Well-Known LUNs either, because we have
		 * no way to address them anyway using USCSICMD.
		 */
		cmd->uscsi_resid = cmd->uscsi_buflen;
		break;
	default:
		/*
		 * All other values for "select report" are either invalid or
		 * vendor-specific and thus unsupported. Return the command with
		 * CHECK CONDITION, and fill in sense data to report a ILLEGAL
		 * REQUEST with INVALID FIELD IN CDB.
		 */
		vtscsi_uscsi_make_check_condition(cmd, KEY_ILLEGAL_REQUEST,
		    0x24, 0x00);
	}
}

static void
vtscsi_uscsi_filter_post(struct uscsi_cmd *cmd)
{
	switch ((uint8_t)cmd->uscsi_cdb[0]) {
	case SCMD_REPORT_LUNS:
		vtscsi_uscsi_filter_post_report_luns(cmd);
		break;

	default:
		break;
	}
}

static const struct pci_vtscsi_backend vtscsi_uscsi_backend = {
	.vsb_name = "uscsi",
	.vsb_init = vtscsi_uscsi_init,
	.vsb_open = vtscsi_uscsi_open,
	.vsb_reset = vtscsi_uscsi_reset,

	.vsb_req_alloc = vtscsi_uscsi_req_alloc,
	.vsb_req_clear = vtscsi_uscsi_req_clear,
	.vsb_req_free = vtscsi_uscsi_req_free,

	.vsb_tmf_hdl = vtscsi_uscsi_tmf_hdl,
	.vsb_an_hdl = vtscsi_uscsi_an_hdl,
	.vsb_req_hdl = vtscsi_uscsi_req_hdl
};
PCI_VTSCSI_BACKEND_SET(vtscsi_uscsi_backend);
