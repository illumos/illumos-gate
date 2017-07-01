/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019, Joyent, Inc.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fts.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <sys/debug.h>
#include <sys/filio.h>
#include <sys/usb/clients/ccid/uccid.h>

#include <winscard.h>

/*
 * Implementation of the PCSC library leveraging the uccid framework.
 */

/*
 * The library handle is basically unused today. We keep this around such that
 * consumers which expect to receive a non-NULL opaque handle have something
 * they can use.
 */
typedef struct pcsc_hdl {
	hrtime_t pcsc_create_time;
} pcsc_hdl_t;

typedef struct pcsc_card {
	int pcc_fd;
} pcsc_card_t;

/*
 * Required globals
 */
SCARD_IO_REQUEST g_rgSCardT0Pci = {
	SCARD_PROTOCOL_T0,
	0
};

SCARD_IO_REQUEST g_rgSCardT1Pci = {
	SCARD_PROTOCOL_T1,
	0
};

SCARD_IO_REQUEST g_rgSCardRawPci = {
	SCARD_PROTOCOL_RAW,
	0
};

const char *
pcsc_stringify_error(const LONG err)
{
	switch (err) {
	case SCARD_S_SUCCESS:
		return ("no error");
	case SCARD_F_INTERNAL_ERROR:
		return ("internal error");
	case SCARD_E_CANCELLED:
		return ("request cancelled");
	case SCARD_E_INVALID_HANDLE:
		return ("invalid handle");
	case SCARD_E_INVALID_PARAMETER:
		return ("invalid parameter");
	case SCARD_E_NO_MEMORY:
		return ("no memory");
	case SCARD_E_INSUFFICIENT_BUFFER:
		return ("buffer was insufficiently sized");
	case SCARD_E_INVALID_VALUE:
		return ("invalid value passed");
	case SCARD_E_UNKNOWN_READER:
		return ("unknown reader");
	case SCARD_E_TIMEOUT:
		return ("timeout occurred");
	case SCARD_E_SHARING_VIOLATION:
		return ("sharing violation");
	case SCARD_E_NO_SMARTCARD:
		return ("no smartcard present");
	case SCARD_E_UNKNOWN_CARD:
		return ("unknown ICC");
	case SCARD_E_PROTO_MISMATCH:
		return ("protocol mismatch");
	case SCARD_F_COMM_ERROR:
		return ("communication error");
	case SCARD_F_UNKNOWN_ERROR:
		return ("unknown error");
	case SCARD_E_READER_UNAVAILABLE:
		return ("reader unavailable");
	case SCARD_E_NO_SERVICE:
		return ("service error");
	case SCARD_E_UNSUPPORTED_FEATURE:
		return ("ICC requires unsupported feature");
	case SCARD_E_NO_READERS_AVAILABLE:
		return ("no readers avaiable");
	case SCARD_W_UNSUPPORTED_CARD:
		return ("ICC unsupported");
	case SCARD_W_UNPOWERED_CARD:
		return ("ICC is not powered");
	case SCARD_W_RESET_CARD:
		return ("ICC was reset");
	case SCARD_W_REMOVED_CARD:
		return ("ICC has been removed");
	default:
		return ("unknown error");
	}
}


/*
 * This is called when a caller wishes to open a new Library context.
 */
LONG
SCardEstablishContext(DWORD scope, LPCVOID unused0, LPCVOID unused1,
    LPSCARDCONTEXT outp)
{
	pcsc_hdl_t *hdl;

	if (outp == NULL) {
		return (SCARD_E_INVALID_PARAMETER);
	}

	if (scope != SCARD_SCOPE_SYSTEM) {
		return (SCARD_E_INVALID_VALUE);
	}

	hdl = calloc(1, sizeof (pcsc_hdl_t));
	if (hdl == NULL) {
		return (SCARD_E_NO_MEMORY);
	}

	hdl->pcsc_create_time = gethrtime();
	*outp = hdl;
	return (SCARD_S_SUCCESS);
}

/*
 * This is called to free a library context from a client.
 */
LONG
SCardReleaseContext(SCARDCONTEXT hdl)
{
	free(hdl);
	return (SCARD_S_SUCCESS);
}

/*
 * This is called to release memory allocated by the library. No, it doesn't
 * make sense to take a const pointer when being given memory to free. It just
 * means we have to cast it, but remember: this isn't our API.
 */
LONG
SCardFreeMemory(SCARDCONTEXT unused, LPCVOID mem)
{
	free((void *)mem);
	return (SCARD_S_SUCCESS);
}

/*
 * This is called by a caller to get a list of readers that exist in the system.
 * If lenp is set to SCARD_AUTOALLOCATE, then we are responsible for dealing
 * with this memory.
 */
LONG
SCardListReaders(SCARDCONTEXT unused, LPCSTR groups, LPSTR bufp, LPDWORD lenp)
{
	FTS *fts;
	FTSENT *ent;
	char *const root[] = { "/dev/ccid", NULL };
	char *ubuf;
	char **readers;
	uint32_t len, ulen, npaths, nalloc, off, i;
	int ret;

	if (groups != NULL || lenp == NULL) {
		return (SCARD_E_INVALID_PARAMETER);
	}

	fts = fts_open(root, FTS_LOGICAL | FTS_NOCHDIR, NULL);
	if (fts == NULL) {
		switch (errno) {
		case ENOENT:
		case ENOTDIR:
			return (SCARD_E_NO_READERS_AVAILABLE);
		case ENOMEM:
		case EAGAIN:
			return (SCARD_E_NO_MEMORY);
		default:
			return (SCARD_E_NO_SERVICE);
		}
	}

	npaths = nalloc = 0;
	/*
	 * Account for the NUL we'll have to place at the end of this.
	 */
	len = 1;
	readers = NULL;
	while ((ent = fts_read(fts)) != NULL) {
		size_t plen;

		if (ent->fts_level != 2 || ent->fts_info == FTS_DP)
			continue;

		if (ent->fts_info == FTS_ERR || ent->fts_info == FTS_NS)
			continue;

		if (S_ISCHR(ent->fts_statp->st_mode) == 0)
			continue;

		plen = strlen(ent->fts_path) + 1;
		if (UINT32_MAX - len <= plen) {
			/*
			 * I mean, it's true. But I wish I could just give you
			 * EOVERFLOW.
			 */
			ret = SCARD_E_INSUFFICIENT_BUFFER;
			goto out;
		}

		if (npaths == nalloc) {
			char **tmp;

			nalloc += 8;
			tmp = reallocarray(readers, nalloc, sizeof (char *));
			if (tmp == NULL) {
				ret = SCARD_E_NO_MEMORY;
				goto out;
			}
			readers = tmp;
		}
		readers[npaths] = strdup(ent->fts_path);
		npaths++;
		len += plen;
	}

	if (npaths == 0) {
		ret = SCARD_E_NO_READERS_AVAILABLE;
		goto out;
	}

	ulen = *lenp;
	*lenp = len;
	if (ulen != SCARD_AUTOALLOCATE) {
		if (bufp == NULL) {
			ret = SCARD_S_SUCCESS;
			goto out;
		}

		if (ulen < len) {
			ret = SCARD_E_INSUFFICIENT_BUFFER;
			goto out;
		}

		ubuf = bufp;
	} else {
		char **bufpp;
		if (bufp == NULL) {
			ret = SCARD_E_INVALID_PARAMETER;
			goto out;
		}

		ubuf = malloc(ulen);
		if (ubuf == NULL) {
			ret = SCARD_E_NO_MEMORY;
			goto out;
		}

		bufpp = (void *)bufp;
		*bufpp = ubuf;
	}
	ret = SCARD_S_SUCCESS;

	for (off = 0, i = 0; i < npaths; i++) {
		size_t slen = strlen(readers[i]) + 1;
		bcopy(readers[i], ubuf + off, slen);
		off += slen;
		VERIFY3U(off, <=, len);
	}
	VERIFY3U(off, ==, len - 1);
	ubuf[off] = '\0';
out:
	for (i = 0; i < npaths; i++) {
		free(readers[i]);
	}
	free(readers);
	(void) fts_close(fts);
	return (ret);
}

static LONG
uccid_status_helper(int fd, DWORD prots, uccid_cmd_status_t *ucs)
{
	/*
	 * Get the status of this slot and find out information about the slot.
	 * We need to see if there's an ICC present and if it matches the
	 * current protocol. If not, then we have to fail this.
	 */
	bzero(ucs, sizeof (uccid_cmd_status_t));
	ucs->ucs_version = UCCID_CURRENT_VERSION;
	if (ioctl(fd, UCCID_CMD_STATUS, ucs) != 0) {
		return (SCARD_F_UNKNOWN_ERROR);
	}

	if ((ucs->ucs_status & UCCID_STATUS_F_CARD_PRESENT) == 0) {
		return (SCARD_W_REMOVED_CARD);
	}

	if ((ucs->ucs_status & UCCID_STATUS_F_CARD_ACTIVE) == 0) {
		return (SCARD_W_UNPOWERED_CARD);
	}

	if ((ucs->ucs_status & UCCID_STATUS_F_PARAMS_VALID) == 0) {
		return (SCARD_W_UNSUPPORTED_CARD);
	}

	if ((ucs->ucs_prot & prots) == 0) {
		return (SCARD_E_PROTO_MISMATCH);
	}

	return (0);
}

LONG
SCardConnect(SCARDCONTEXT hdl, LPCSTR reader, DWORD mode, DWORD prots,
    LPSCARDHANDLE iccp, LPDWORD protp)
{
	LONG ret;
	uccid_cmd_status_t ucs;
	pcsc_card_t *card;

	if (reader == NULL) {
		return (SCARD_E_UNKNOWN_READER);
	}

	if (iccp == NULL || protp == NULL) {
		return (SCARD_E_INVALID_PARAMETER);
	}

	if (mode != SCARD_SHARE_SHARED) {
		return (SCARD_E_INVALID_VALUE);
	}

	if ((prots & ~(SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1 |
	    SCARD_PROTOCOL_RAW | SCARD_PROTOCOL_T15)) != 0) {
		return (SCARD_E_INVALID_VALUE);
	}

	if ((prots & (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)) == 0) {
		return (SCARD_E_UNSUPPORTED_FEATURE);
	}

	if ((card = malloc(sizeof (*card))) == NULL) {
		return (SCARD_E_NO_MEMORY);
	}

	if ((card->pcc_fd = open(reader, O_RDWR)) < 0) {
		free(card);
		switch (errno) {
		case ENOENT:
			return (SCARD_E_UNKNOWN_READER);
		default:
			return (SCARD_F_UNKNOWN_ERROR);
		}
	}

	if ((ret = uccid_status_helper(card->pcc_fd, prots, &ucs)) != 0)
		goto cleanup;

	*protp = ucs.ucs_prot;
	*iccp = card;
	return (SCARD_S_SUCCESS);
cleanup:
	(void) close(card->pcc_fd);
	free(card);
	return (ret);
}

LONG
SCardDisconnect(SCARDHANDLE arg, DWORD disposition)
{
	pcsc_card_t *card = arg;

	if (arg == NULL) {
		return (SCARD_E_INVALID_HANDLE);
	}

	if (disposition != SCARD_LEAVE_CARD) {
		return (SCARD_E_INVALID_VALUE);
	}

	if (close(card->pcc_fd) != 0) {
		return (SCARD_F_UNKNOWN_ERROR);
	}

	free(card);
	return (SCARD_S_SUCCESS);
}

LONG
SCardBeginTransaction(SCARDHANDLE arg)
{
	uccid_cmd_txn_begin_t txn;
	pcsc_card_t *card = arg;

	if (card == NULL) {
		return (SCARD_E_INVALID_HANDLE);
	}

	/*
	 * The semantics of pcsc are that this operation does not block, but
	 * instead fails if we cannot grab it immediately.
	 */
	bzero(&txn, sizeof (uccid_cmd_txn_begin_t));
	txn.uct_version = UCCID_CURRENT_VERSION;
	txn.uct_flags = UCCID_TXN_DONT_BLOCK;

	if (ioctl(card->pcc_fd, UCCID_CMD_TXN_BEGIN, &txn) != 0) {
		VERIFY3S(errno, !=, EFAULT);
		switch (errno) {
		case ENODEV:
			return (SCARD_E_READER_UNAVAILABLE);
		case EEXIST:
			/*
			 * This is an odd case. It's used to tell us that we
			 * already have it. For now, just treat it as success.
			 */
			return (SCARD_S_SUCCESS);
		case EBUSY:
			return (SCARD_E_SHARING_VIOLATION);
		/*
		 * EINPROGRESS is a weird case. It means that we were trying to
		 * grab a hold while another instance using the same handle was.
		 * For now, treat it as an unknown error.
		 */
		case EINPROGRESS:
		case EINTR:
		default:
			return (SCARD_F_UNKNOWN_ERROR);
		}
	}
	return (SCARD_S_SUCCESS);
}

LONG
SCardEndTransaction(SCARDHANDLE arg, DWORD state)
{
	uccid_cmd_txn_end_t txn;
	pcsc_card_t *card = arg;

	if (card == NULL) {
		return (SCARD_E_INVALID_HANDLE);
	}

	bzero(&txn, sizeof (uccid_cmd_txn_end_t));
	txn.uct_version = UCCID_CURRENT_VERSION;

	switch (state) {
	case SCARD_LEAVE_CARD:
		txn.uct_flags = UCCID_TXN_END_RELEASE;
		break;
	case SCARD_RESET_CARD:
		txn.uct_flags = UCCID_TXN_END_RESET;
		break;
	case SCARD_UNPOWER_CARD:
	case SCARD_EJECT_CARD:
	default:
		return (SCARD_E_INVALID_VALUE);
	}

	if (ioctl(card->pcc_fd, UCCID_CMD_TXN_END, &txn) != 0) {
		VERIFY3S(errno, !=, EFAULT);
		switch (errno) {
		case ENODEV:
			return (SCARD_E_READER_UNAVAILABLE);
		case ENXIO:
			return (SCARD_E_SHARING_VIOLATION);
		default:
			return (SCARD_F_UNKNOWN_ERROR);
		}
	}
	return (SCARD_S_SUCCESS);
}

LONG
SCardReconnect(SCARDHANDLE arg, DWORD mode, DWORD prots, DWORD init,
    LPDWORD protp)
{
	uccid_cmd_status_t ucs;
	pcsc_card_t *card = arg;
	LONG ret;

	if (card == NULL) {
		return (SCARD_E_INVALID_HANDLE);
	}

	if (protp == NULL) {
		return (SCARD_E_INVALID_PARAMETER);
	}

	if (mode != SCARD_SHARE_SHARED) {
		return (SCARD_E_INVALID_VALUE);
	}

	if ((prots & ~(SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1 |
	    SCARD_PROTOCOL_RAW | SCARD_PROTOCOL_T15)) != 0) {
		return (SCARD_E_INVALID_VALUE);
	}

	if ((prots & (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)) == 0) {
		return (SCARD_E_UNSUPPORTED_FEATURE);
	}

	if (init != SCARD_LEAVE_CARD) {
		return (SCARD_E_INVALID_VALUE);
	}

	if ((ret = uccid_status_helper(card->pcc_fd, prots, &ucs)) != 0)
		return (ret);

	*protp = ucs.ucs_prot;
	return (SCARD_S_SUCCESS);
}

LONG
SCardTransmit(SCARDHANDLE arg, const SCARD_IO_REQUEST *sendreq,
    LPCBYTE sendbuf, DWORD sendlen, SCARD_IO_REQUEST *recvreq, LPBYTE recvbuf,
    LPDWORD recvlenp)
{
	int len;
	ssize_t ret;
	pcsc_card_t *card = arg;

	if (card == NULL) {
		return (SCARD_E_INVALID_HANDLE);
	}

	/*
	 * Ignore sendreq / recvreq.
	 */
	if (sendbuf == NULL || recvbuf == NULL || recvlenp == NULL) {
		return (SCARD_E_INVALID_PARAMETER);
	}

	/*
	 * The CCID write will always consume all data or none.
	 */
	ret = write(card->pcc_fd, sendbuf, sendlen);
	if (ret == -1) {
		switch (errno) {
		case E2BIG:
			return (SCARD_E_INVALID_PARAMETER);
		case ENODEV:
			return (SCARD_E_READER_UNAVAILABLE);
		case EACCES:
		case EBUSY:
			return (SCARD_E_SHARING_VIOLATION);
		case ENXIO:
			return (SCARD_W_REMOVED_CARD);
		case EFAULT:
			return (SCARD_E_INVALID_PARAMETER);
		case ENOMEM:
		default:
			return (SCARD_F_UNKNOWN_ERROR);
		}
	}
	ASSERT3S(ret, ==, sendlen);

	/*
	 * Now, we should be able to block in read.
	 */
	ret = read(card->pcc_fd, recvbuf, *recvlenp);
	if (ret == -1) {
		switch (errno) {
		case EINVAL:
		case EOVERFLOW:
			/*
			 * This means that we need to update len with the real
			 * one.
			 */
			if (ioctl(card->pcc_fd, FIONREAD, &len) != 0) {
				return (SCARD_F_UNKNOWN_ERROR);
			}
			*recvlenp = len;
			return (SCARD_E_INSUFFICIENT_BUFFER);
		case ENODEV:
			return (SCARD_E_READER_UNAVAILABLE);
		case EACCES:
		case EBUSY:
			return (SCARD_E_SHARING_VIOLATION);
		case EFAULT:
			return (SCARD_E_INVALID_PARAMETER);
		case ENODATA:
		default:
			return (SCARD_F_UNKNOWN_ERROR);
		}
	}

	*recvlenp = ret;

	return (SCARD_S_SUCCESS);
}
