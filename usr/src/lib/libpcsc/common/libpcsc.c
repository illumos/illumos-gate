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
 * Copyright 2022 Oxide Computer Company
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/list.h>
#include <fcntl.h>
#include <fts.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <upanic.h>
#include <sys/debug.h>
#include <sys/filio.h>
#include <sys/usb/clients/ccid/uccid.h>

#include <winscard.h>

/*
 * Implementation of the PCSC library leveraging the uccid framework.
 */

typedef struct pcsc_hdl {
	hrtime_t pcsc_create_time;
	list_t pcsc_autoalloc;
	list_t pcsc_cards;
} pcsc_hdl_t;

typedef struct pcsc_card {
	list_node_t pcc_link;
	pcsc_hdl_t *pcc_hdl;
	int pcc_fd;
	char *pcc_name;
	size_t pcc_namelen;
} pcsc_card_t;

typedef struct pcsc_mem {
	list_node_t pcm_link;
	void *pcm_buf;
} pcsc_mem_t;

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
 * Allocate a buffer of size "len" for use with an SCARD_AUTOALLOCATE
 * parameter.  Each automatically allocated buffer must be appended to the
 * context buffer list so that it can be freed during the call to
 * SCardReleaseContext().
 */
static void *
pcsc_mem_alloc(pcsc_hdl_t *hdl, size_t len)
{
	pcsc_mem_t *mem;

	if ((mem = malloc(sizeof (*mem))) == NULL) {
		return (NULL);
	}

	if ((mem->pcm_buf = malloc(len)) == NULL) {
		free(mem);
		return (NULL);
	}
	list_link_init(&mem->pcm_link);

	/*
	 * Put the buffer on the per-context list:
	 */
	list_insert_tail(&hdl->pcsc_autoalloc, mem);

	return (mem->pcm_buf);
}

static void
pcsc_mem_free(pcsc_hdl_t *hdl, void *buf)
{
	for (pcsc_mem_t *mem = list_head(&hdl->pcsc_autoalloc); mem != NULL;
	    mem = list_next(&hdl->pcsc_autoalloc, mem)) {
		if (mem->pcm_buf == buf) {
			list_remove(&hdl->pcsc_autoalloc, mem);
			free(mem->pcm_buf);
			free(mem);
			return;
		}
	}

	char msg[512];
	(void) snprintf(msg, sizeof (msg), "freed buffer %p not in context %p",
	    buf, hdl);
	upanic(msg, strlen(msg));
}

static pcsc_card_t *
pcsc_card_alloc(pcsc_hdl_t *hdl, const char *reader)
{
	pcsc_card_t *card;

	if ((card = malloc(sizeof (*card))) == NULL) {
		return (NULL);
	}
	card->pcc_hdl = hdl;
	card->pcc_fd = -1;
	list_link_init(&card->pcc_link);

	/*
	 * The reader name is returned as a multi-string, which means we need
	 * the regular C string and then an additional null termination byte to
	 * end the list of strings:
	 */
	card->pcc_namelen = strlen(reader) + 2;
	if ((card->pcc_name = malloc(card->pcc_namelen)) == NULL) {
		free(card);
		return (NULL);
	}
	bcopy(reader, card->pcc_name, card->pcc_namelen - 1);
	card->pcc_name[card->pcc_namelen - 1] = '\0';

	/*
	 * Insert the card handle into the per-context list so that we can free
	 * them later during SCardReleaseContext().
	 */
	list_insert_tail(&hdl->pcsc_cards, card);

	return (card);
}

static void
pcsc_card_free(pcsc_card_t *card)
{
	if (card == NULL) {
		return;
	}

	if (card->pcc_fd >= 0) {
		(void) close(card->pcc_fd);
	}

	/*
	 * Remove the card handle from the per-context list:
	 */
	pcsc_hdl_t *hdl = card->pcc_hdl;
	list_remove(&hdl->pcsc_cards, card);

	free(card->pcc_name);
	free(card);
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
	list_create(&hdl->pcsc_autoalloc, sizeof (pcsc_mem_t),
	    offsetof(pcsc_mem_t, pcm_link));
	list_create(&hdl->pcsc_cards, sizeof (pcsc_card_t),
	    offsetof(pcsc_card_t, pcc_link));

	hdl->pcsc_create_time = gethrtime();
	*outp = hdl;
	return (SCARD_S_SUCCESS);
}

bool
pcsc_valid_context(SCARDCONTEXT hdl)
{
	/*
	 * On some other platforms, the context handle is a signed integer.
	 * Some software has been observed to use -1 as an invalid handle
	 * sentinel value, so we need to explicitly handle that here.
	 */
	return (hdl != NULL && (uintptr_t)hdl != UINTPTR_MAX);
}

LONG
SCardIsValidContext(SCARDCONTEXT hdl)
{
	if (!pcsc_valid_context(hdl)) {
		return (SCARD_E_INVALID_HANDLE);
	}

	return (SCARD_S_SUCCESS);
}

/*
 * This is called to free a library context from a client.
 */
LONG
SCardReleaseContext(SCARDCONTEXT arg)
{
	if (!pcsc_valid_context(arg)) {
		return (SCARD_E_INVALID_HANDLE);
	}

	/*
	 * Free any SCARD_AUTOALLOCATE memory now.
	 */
	pcsc_hdl_t *hdl = arg;
	pcsc_mem_t *mem;
	while ((mem = list_head(&hdl->pcsc_autoalloc)) != NULL) {
		pcsc_mem_free(hdl, mem->pcm_buf);
	}
	list_destroy(&hdl->pcsc_autoalloc);

	/*
	 * Free any card handles that were not explicitly freed:
	 */
	pcsc_card_t *card;
	while ((card = list_head(&hdl->pcsc_cards)) != NULL) {
		pcsc_card_free(card);
	}
	list_destroy(&hdl->pcsc_cards);

	free(hdl);
	return (SCARD_S_SUCCESS);
}

/*
 * This is called to release memory allocated by the library. No, it doesn't
 * make sense to take a const pointer when being given memory to free. It just
 * means we have to cast it, but remember: this isn't our API.
 */
LONG
SCardFreeMemory(SCARDCONTEXT hdl, LPCVOID mem)
{
	if (!pcsc_valid_context(hdl)) {
		return (SCARD_E_INVALID_HANDLE);
	}

	pcsc_mem_free(hdl, (void *)mem);
	return (SCARD_S_SUCCESS);
}

/*
 * This is called by a caller to get a list of readers that exist in the system.
 * If lenp is set to SCARD_AUTOALLOCATE, then we are responsible for dealing
 * with this memory.
 */
LONG
SCardListReaders(SCARDCONTEXT arg, LPCSTR groups, LPSTR bufp, LPDWORD lenp)
{
	pcsc_hdl_t *hdl = arg;
	FTS *fts;
	FTSENT *ent;
	char *const root[] = { "/dev/ccid", NULL };
	char *ubuf;
	char **readers;
	uint32_t len, ulen, npaths, nalloc, off, i;
	int ret;

	if (!pcsc_valid_context(hdl)) {
		return (SCARD_E_INVALID_HANDLE);
	}

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

		if ((ubuf = pcsc_mem_alloc(hdl, ulen)) == NULL) {
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

	if (!pcsc_valid_context(hdl)) {
		return (SCARD_E_INVALID_HANDLE);
	}

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

	if ((card = pcsc_card_alloc(hdl, reader)) == NULL) {
		pcsc_card_free(card);
		return (SCARD_E_NO_MEMORY);
	}

	if ((card->pcc_fd = open(reader, O_RDWR)) < 0) {
		pcsc_card_free(card);
		switch (errno) {
		case ENOENT:
			return (SCARD_E_UNKNOWN_READER);
		default:
			return (SCARD_F_UNKNOWN_ERROR);
		}
	}

	if ((ret = uccid_status_helper(card->pcc_fd, prots, &ucs)) != 0) {
		pcsc_card_free(card);
		return (ret);
	}

	*protp = ucs.ucs_prot;
	*iccp = card;
	return (SCARD_S_SUCCESS);
}

/*
 * The Windows documentation suggests that all of the input/output arguments
 * (other than the handle) are effectively optional.
 */
LONG
SCardStatus(SCARDHANDLE arg, LPSTR readerp, LPDWORD readerlenp,
    LPDWORD statep, LPDWORD protop, LPBYTE atrp, LPDWORD atrlenp)
{
	pcsc_card_t *card = arg;
	pcsc_hdl_t *hdl = card->pcc_hdl;
	LONG ret = SCARD_S_SUCCESS;

	if (statep == NULL && protop == NULL && atrlenp == NULL) {
		/*
		 * There is no need to perform the status ioctl.
		 */
		goto name;
	}

	uccid_cmd_status_t ucs = { .ucs_version = UCCID_CURRENT_VERSION };
	if (ioctl(card->pcc_fd, UCCID_CMD_STATUS, &ucs) != 0) {
		VERIFY3S(errno, ==, ENODEV);
		ret = SCARD_E_READER_UNAVAILABLE;
		goto out;
	}

	if (statep != NULL) {
		if (!(ucs.ucs_status & UCCID_STATUS_F_CARD_PRESENT)) {
			*statep = SCARD_ABSENT;
		} else if (ucs.ucs_status & UCCID_STATUS_F_CARD_ACTIVE) {
			if (ucs.ucs_status & UCCID_STATUS_F_PARAMS_VALID) {
				*statep = SCARD_SPECIFIC;
			} else {
				*statep = SCARD_POWERED;
			}
		} else {
			*statep = SCARD_PRESENT;
		}
	}

	if (protop != NULL) {
		if (ucs.ucs_status & UCCID_STATUS_F_PARAMS_VALID) {
			switch (ucs.ucs_prot) {
			case UCCID_PROT_T0:
				*protop = SCARD_PROTOCOL_T0;
				break;
			case UCCID_PROT_T1:
				*protop = SCARD_PROTOCOL_T1;
				break;
			default:
				*protop = SCARD_PROTOCOL_UNDEFINED;
				break;
			}
		} else {
			/*
			 * If SCARD_SPECIFIC is not returned as the card
			 * state, this value is not considered meaningful.
			 */
			*protop = SCARD_PROTOCOL_UNDEFINED;
		}
	}

	if (atrlenp != NULL) {
		uint8_t *ubuf;
		uint32_t len = *atrlenp;
		if (len != SCARD_AUTOALLOCATE) {
			if (len < ucs.ucs_atrlen) {
				*atrlenp = ucs.ucs_atrlen;
				ret = SCARD_E_INSUFFICIENT_BUFFER;
				goto out;
			}

			if (atrp == NULL) {
				ret = SCARD_E_INVALID_PARAMETER;
				goto out;
			}

			ubuf = atrp;
		} else {
			if ((ubuf = pcsc_mem_alloc(hdl, ucs.ucs_atrlen)) ==
			    NULL) {
				ret = SCARD_E_NO_MEMORY;
				goto out;
			}

			*((LPBYTE *)atrp) = ubuf;
		}

		bcopy(ucs.ucs_atr, ubuf, ucs.ucs_atrlen);
		*atrlenp = ucs.ucs_atrlen;
	}

name:
	if (readerlenp != NULL) {
		char *ubuf;
		uint32_t rlen = *readerlenp;
		if (rlen != SCARD_AUTOALLOCATE) {
			if (rlen < card->pcc_namelen) {
				*readerlenp = card->pcc_namelen;
				ret = SCARD_E_INSUFFICIENT_BUFFER;
				goto out;
			}

			if (readerp == NULL) {
				ret = SCARD_E_INVALID_PARAMETER;
				goto out;
			}

			ubuf = readerp;
		} else {
			if ((ubuf = pcsc_mem_alloc(hdl, card->pcc_namelen)) ==
			    NULL) {
				ret = SCARD_E_NO_MEMORY;
				goto out;
			}

			*((LPSTR *)readerp) = ubuf;
		}

		/*
		 * We stored the reader name as a multi-string in
		 * pcsc_card_alloc(), so we can just copy out the whole value
		 * here without further modification:
		 */
		bcopy(card->pcc_name, ubuf, card->pcc_namelen);
	}

out:
	return (ret);
}

LONG
SCardDisconnect(SCARDHANDLE arg, DWORD disposition)
{
	pcsc_card_t *card = arg;

	if (arg == NULL) {
		return (SCARD_E_INVALID_HANDLE);
	}

	switch (disposition) {
	case SCARD_RESET_CARD: {
		/*
		 * To reset the card, we first need to get exclusive access to
		 * the card.
		 */
		uccid_cmd_txn_begin_t txnbegin = {
			.uct_version = UCCID_CURRENT_VERSION,
		};
		if (ioctl(card->pcc_fd, UCCID_CMD_TXN_BEGIN, &txnbegin) != 0) {
			VERIFY3S(errno, !=, EFAULT);

			switch (errno) {
			case ENODEV:
				/*
				 * If the card is no longer present, we cannot
				 * reset it.
				 */
				goto close;
			case EEXIST:
				break;
			case EBUSY:
				return (SCARD_E_SHARING_VIOLATION);
			default:
				return (SCARD_F_UNKNOWN_ERROR);
			}
		}

		/*
		 * Once we have begun the transaction, we can end it
		 * immediately while requesting a reset before the next
		 * transaction.
		 */
		uccid_cmd_txn_end_t txnend = {
			.uct_version = UCCID_CURRENT_VERSION,
			.uct_flags = UCCID_TXN_END_RESET,
		};
		if (ioctl(card->pcc_fd, UCCID_CMD_TXN_END, &txnend) != 0) {
			VERIFY3S(errno, !=, EFAULT);

			switch (errno) {
			case ENODEV:
				goto close;
			default:
				return (SCARD_F_UNKNOWN_ERROR);
			}
		}
	}
	case SCARD_LEAVE_CARD:
		break;
	default:
		return (SCARD_E_INVALID_VALUE);
	}

close:
	if (close(card->pcc_fd) != 0) {
		return (SCARD_F_UNKNOWN_ERROR);
	}
	card->pcc_fd = -1;

	pcsc_card_free(card);
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
