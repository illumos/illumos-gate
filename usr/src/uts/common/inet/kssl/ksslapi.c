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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/kmem.h>
#include <sys/cpuvar.h>
#include <sys/atomic.h>
#include <sys/sysmacros.h>

#include <inet/common.h>
#include <inet/ip.h>

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/tihdr.h>

#include "ksslimpl.h"
#include "ksslproto.h"
#include "ksslapi.h"

static kssl_cmd_t kssl_handle_any_record(kssl_ctx_t ctx, mblk_t *mp,
    mblk_t **decrmp, kssl_callback_t cbfn, void *arg);
static boolean_t kssl_enqueue(kssl_chain_t **head, void *item);
static void kssl_dequeue(kssl_chain_t **head, void *item);
static kssl_status_t kssl_build_single_record(ssl_t *ssl, mblk_t *mp);

/*
 * The socket bind request is intercepted and re-routed here
 * to see is there is SSL relevant job to do, based on the kssl config
 * in the kssl_entry_tab.
 * Looks up the kernel SSL proxy table, to find an entry that matches the
 * same serveraddr, and has one of the following two criteria:
 * 1. in_port is an ssl_port. This endpoint can be used later as a fallback
 *    to complete connections that cannot be handled by the SSL kernel proxy
 *    (typically non supported ciphersuite). The cookie for the calling client
 *    is saved with the kssl_entry to be retrieved for the fallback.
 *    The function returns KSSL_HAS_PROXY.
 *
 * 2. in_port is a proxy port for another ssl port. The ssl port is then
 *    substituted to the in_port in the bind_req TPI structure, so that
 *    the bind falls through to the SSL port. At the end of this operation,
 *    all the packets arriving to the SSL port will be delivered to an
 *    accepted endpoint child of this bound socket.
 *    The  kssl_entry_t is returned in *ksslent, for later use by the
 *    lower modules' SSL hooks that handle the Handshake messages.
 *    The function returns KSSL_IS_PROXY.
 *
 * The function returns KSSL_NO_PROXY otherwise.
 */

kssl_endpt_type_t
kssl_check_proxy(struct sockaddr *addr, socklen_t len, void *cookie,
    kssl_ent_t *ksslent)
{
	int i;
	kssl_endpt_type_t ret;
	kssl_entry_t *ep;
	sin_t *sin;
	sin6_t *sin6;
	in6_addr_t mapped_v4addr;
	in6_addr_t *v6addr;
	in_port_t in_port;

	if (kssl_entry_tab_nentries == 0) {
		return (KSSL_NO_PROXY);
	}

	ret = KSSL_NO_PROXY;
	sin = (struct sockaddr_in *)addr;

	switch (len) {
	case sizeof (sin_t):
		in_port = ntohs(sin->sin_port);
		IN6_IPADDR_TO_V4MAPPED(sin->sin_addr.s_addr, &mapped_v4addr);
		v6addr = &mapped_v4addr;
		break;

	case sizeof (sin6_t):
		sin6 = (sin6_t *)sin;
		in_port = ntohs(sin6->sin6_port);
		v6addr = &sin6->sin6_addr;
		break;

	default:
		return (ret);
	}

	mutex_enter(&kssl_tab_mutex);

	for (i = 0; i < kssl_entry_tab_size; i++) {
		if ((ep = kssl_entry_tab[i]) == NULL)
			continue;

		if (IN6_ARE_ADDR_EQUAL(&ep->ke_laddr, v6addr) ||
		    IN6_IS_ADDR_UNSPECIFIED(&ep->ke_laddr)) {

			/* This is an SSL port to fallback to */
			if (ep->ke_ssl_port == in_port) {

				/*
				 * Let's see first if there's at least
				 * an endpoint for a proxy server.
				 * If there's none, then we return as we have
				 * no proxy, so that the bind() to the
				 * transport layer goes through.
				 * The calling module will ask for this
				 * cookie if it wants to fall back to it,
				 * so add this one to the list of fallback
				 * clients.
				 */
				if (!kssl_enqueue((kssl_chain_t **)
				    &(ep->ke_fallback_head), cookie)) {
					break;
				}

				KSSL_ENTRY_REFHOLD(ep);
				*ksslent = (kssl_ent_t)ep;

				ret = KSSL_HAS_PROXY;
				break;
			}

			/* This is a proxy port. */
			if (ep->ke_proxy_port == in_port) {
				/* Add the caller's cookie to proxies list */

				if (!kssl_enqueue((kssl_chain_t **)
				    &(ep->ke_proxy_head), cookie)) {
					break;
				}

				/*
				 * Make this look  like the SSL port to the
				 * transport below
				 */
				sin->sin_port = htons(ep->ke_ssl_port);

				KSSL_ENTRY_REFHOLD(ep);
				*ksslent = (kssl_ent_t)ep;

				ret = KSSL_IS_PROXY;
				break;
			}
		}
	}

	mutex_exit(&kssl_tab_mutex);
	return (ret);
}

/*
 * Retrieved an endpoint "bound" to the SSL entry.
 * Such endpoint has previously called kssl_check_proxy(), got itself
 * linked to the kssl_entry's ke_fallback_head list.
 * This routine returns the cookie from that SSL entry ke_fallback_head list.
 */
void *
kssl_find_fallback(kssl_ent_t ksslent)
{
	kssl_entry_t *kssl_entry = (kssl_entry_t *)ksslent;

	if (kssl_entry->ke_fallback_head != NULL)
		return (kssl_entry->ke_fallback_head->fallback_bound);

	KSSL_COUNTER(proxy_fallback_failed, 1);

	return (NULL);
}

/*
 * Re-usable code for adding and removing an element to/from a chain that
 * matches "item"
 * The chain is simple-linked and NULL ended.
 */

/*
 * This routine returns TRUE if the item was either successfully added to
 * the chain, or is already there. It returns FALSE otherwise.
 */
static boolean_t
kssl_enqueue(kssl_chain_t **head, void *item)
{
	kssl_chain_t *newchain, *cur;

	/* Lookup the existing entries to avoid duplicates */
	cur = *head;
	while (cur != NULL) {
		if (cur->item == item) {
			return (B_TRUE);
		}
		cur = cur->next;
	}

	newchain = kmem_alloc(sizeof (kssl_chain_t), KM_NOSLEEP);
	if (newchain == NULL) {
		return (B_FALSE);
	}

	newchain->item = item;
	newchain->next = *head;
	*head = newchain;
	return (B_TRUE);
}

static void
kssl_dequeue(kssl_chain_t **head, void *item)
{
	kssl_chain_t *prev, *cur;

	prev = cur = *head;
	while (cur != NULL) {
		if (cur->item == item) {
			if (cur == *head)
				*head = (*head)->next;
			else
				prev->next = cur->next;
			kmem_free(cur, sizeof (kssl_chain_t));
			return;
		}
		prev = cur;
		cur = cur->next;
	}
}

/*
 * Holds the kssl_entry
 */
void
kssl_hold_ent(kssl_ent_t ksslent)
{
	KSSL_ENTRY_REFHOLD((kssl_entry_t *)ksslent);
}

/*
 * Releases the kssl_entry
 * If the caller passes a cookie, then it should be removed from both
 * proxies and fallbacks chains.
 */
void
kssl_release_ent(kssl_ent_t ksslent, void *cookie, kssl_endpt_type_t endpt_type)
{
	kssl_entry_t *kssl_entry = (kssl_entry_t *)ksslent;

	if (cookie != NULL) {
		if (endpt_type == KSSL_IS_PROXY) {
			ASSERT(kssl_entry->ke_proxy_head != NULL);
			kssl_dequeue(
			    (kssl_chain_t **)&kssl_entry->ke_proxy_head,
			    cookie);
		}
		if (endpt_type == KSSL_HAS_PROXY) {
			ASSERT(kssl_entry->ke_fallback_head != NULL);
			kssl_dequeue(
			    (kssl_chain_t **)&kssl_entry->ke_fallback_head,
			    cookie);
		}
	}
	KSSL_ENTRY_REFRELE(kssl_entry);
}

/*
 * Releases the kssl_context
 */
void
kssl_release_ctx(kssl_ctx_t ksslctx)
{
	kssl_free_context((ssl_t *)ksslctx);
}

/*
 * Done with asynchronous processing
 */
void
kssl_async_done(kssl_ctx_t ksslctx)
{
	ssl_t *ssl = (ssl_t *)ksslctx;

	mutex_enter(&ssl->kssl_lock);
	if (--ssl->async_ops_pending == 0)
		cv_signal(&ssl->async_cv);
	mutex_exit(&ssl->kssl_lock);
}

/*
 * Packets are accumulated here, if there are packets already queued,
 * or if the context is active.
 * The context is active when an incoming record processing function
 * is already executing on a different thread.
 * Queued packets are handled either when an mblk arrived and completes
 * a record, or, when the active context processor finishes the task at
 * hand.
 * The caller has to keep calling this routine in a loop until it returns
 * B_FALSE in *more. The reason for this is SSL3: The protocol
 * allows the client to send its first application_data message right
 * after it had sent its Finished message, and not wait for the server
 * ChangeCipherSpec and Finished. This overlap means we can't batch up
 * a returned Handshake message to be sent on the wire
 * with a decrypted application_data to be delivered to the application.
 */
kssl_cmd_t
kssl_input(kssl_ctx_t ctx, mblk_t *mp, mblk_t **decrmp, boolean_t *more,
    kssl_callback_t cbfn, void *arg)
{
	mblk_t *recmp, *outmp = NULL;
	kssl_cmd_t kssl_cmd;
	ssl_t *ssl;
	uint8_t *rec_sz_p;
	int mplen;
	SSL3ContentType content_type;
	uint16_t rec_sz;

	ASSERT(ctx != NULL);

	if (mp != NULL) {
		ASSERT(mp->b_prev == NULL && mp->b_next == NULL);
	}

	ssl = (ssl_t *)(ctx);

	*decrmp = NULL;
	*more = B_FALSE;

	mutex_enter(&ssl->kssl_lock);

	if (ssl->close_notify_clnt == B_TRUE) {
		DTRACE_PROBE(kssl_err__close_notify);
		goto sendnewalert;
	}

	/* Whomever is currently processing this connection will get to this */
	if (ssl->activeinput) {
		if (mp != NULL) {
			KSSL_ENQUEUE_MP(ssl, mp);
		}
		mutex_exit(&ssl->kssl_lock);
		return (KSSL_CMD_NONE);
	}

	/*
	 * Fast path for complete incoming application_data records on an empty
	 * queue.
	 * This is by far the most frequently encountered case
	 */

	if ((!ssl->activeinput) && (ssl->rec_ass_head == NULL) &&
	    ((mp != NULL) && (mplen = MBLKL(mp)) > SSL3_HDR_LEN)) {

		DTRACE_PROBE1(kssl_mblk__fast_path, mblk_t *, mp);
		content_type = (SSL3ContentType)mp->b_rptr[0];

		if ((content_type == content_application_data) &&
		    (ssl->hs_waitstate == idle_handshake)) {
			rec_sz_p = SSL3_REC_SIZE(mp);
			rec_sz = BE16_TO_U16(rec_sz_p);

			if ((mp->b_cont == NULL) && (mplen == rec_sz)) {

				*decrmp = mp;
				mutex_exit(&ssl->kssl_lock);
				return (KSSL_CMD_DELIVER_PROXY);
			}
		}
	}

	ssl->activeinput = B_TRUE;
	/* Accumulate at least one record */
	if (mp != NULL) {
		KSSL_ENQUEUE_MP(ssl, mp);
		mp = NULL;
	}
	recmp = kssl_get_next_record(ssl);

	if (recmp == NULL) {
		ssl->activeinput = B_FALSE;
		if (ssl->alert_sendbuf != NULL) {
			DTRACE_PROBE(kssl_err__alert_to_send);
			goto sendalert;
		}
		/* Not even a complete header yet. wait for the rest */
		mutex_exit(&ssl->kssl_lock);
		return (KSSL_CMD_NONE);
	}

	do {
		DTRACE_PROBE1(kssl_mblk__kssl_input_cycle, mblk_t *, recmp);
		content_type = (SSL3ContentType)recmp->b_rptr[0];

		switch (content_type) {
		case content_application_data:
			/*
			 * application_data records are decrypted and
			 * MAC-verified by the stream head, and in the context
			 * a read()'ing thread. This avoids unfairly charging
			 * the cost of handling this record on the whole system,
			 * and prevents doing it while in the shared IP
			 * perimeter.
			 */
			ssl->activeinput = B_FALSE;
			if (ssl->hs_waitstate != idle_handshake) {
				DTRACE_PROBE(kssl_err__waitstate_not_idle);
				goto sendnewalert;
			}
			outmp = recmp;
			kssl_cmd = KSSL_CMD_DELIVER_PROXY;
			break;
		case content_change_cipher_spec:
		case content_alert:
		case content_handshake:
		case content_handshake_v2:
			/*
			 * If we're past the initial handshake, start letting
			 * the stream head process all records, in particular
			 * the close_notify.
			 * This is needed to avoid processing them out of
			 * sequence when previous application data packets are
			 * waiting to be decrypted/MAC'ed and delivered.
			 */
			if (ssl->hs_waitstate == idle_handshake) {
				ssl->activeinput = B_FALSE;
				outmp = recmp;
				kssl_cmd = KSSL_CMD_DELIVER_PROXY;
			} else {
				kssl_cmd = kssl_handle_any_record(ssl, recmp,
				    &outmp, cbfn, arg);
			}
			break;
		default:
			ssl->activeinput = B_FALSE;
			DTRACE_PROBE(kssl_err__invalid_content_type);
			goto sendnewalert;
		}

		/* Priority to Alert messages */
		if (ssl->alert_sendbuf != NULL) {
			DTRACE_PROBE(kssl_err__alert_to_send_cycle);
			goto sendalert;
		}

		/* Then handshake messages */
		if (ssl->handshake_sendbuf) {
			if (*decrmp != NULL) {
				linkb(*decrmp, ssl->handshake_sendbuf);
			} else {
				*decrmp = ssl->handshake_sendbuf;
			}
			ssl->handshake_sendbuf = NULL;

			*more = ((ssl->rec_ass_head != NULL) &&
			    (!ssl->activeinput));
			mutex_exit(&ssl->kssl_lock);
			return (kssl_cmd);
		}

		if (ssl->hs_waitstate == idle_handshake) {
			*more = ((ssl->rec_ass_head != NULL) &&
			    (!ssl->activeinput));
		}

		if (outmp != NULL) {
			*decrmp = outmp;
			/*
			 * Don't process any packet after an application_data.
			 * We could well receive the close_notify which should
			 * be handled separately.
			 */
			mutex_exit(&ssl->kssl_lock);
			return (kssl_cmd);
		}
		/*
		 * The current record isn't done yet. Don't start the next one
		 */
		if (ssl->activeinput) {
			mutex_exit(&ssl->kssl_lock);
			return (kssl_cmd);
		}
	} while ((recmp = kssl_get_next_record(ssl)) != NULL);

	mutex_exit(&ssl->kssl_lock);
	return (kssl_cmd);

sendnewalert:
	kssl_send_alert(ssl, alert_fatal, unexpected_message);
	if (mp != NULL) {
		freeb(mp);
	}

sendalert:
	*decrmp = ssl->alert_sendbuf;
	ssl->alert_sendbuf = NULL;
	mutex_exit(&ssl->kssl_lock);
	return (KSSL_CMD_SEND);
}

/*
 * Decrypt and verify the MAC of an incoming chain of application_data record.
 * Each block has exactly one SSL record.
 */
kssl_cmd_t
kssl_handle_mblk(kssl_ctx_t ctx, mblk_t **mpp, mblk_t **outmp)
{
	uchar_t *recend, *rec_sz_p;
	uchar_t *real_recend;
	mblk_t *prevmp = NULL, *nextmp, *firstmp, *mp, *copybp;
	int mac_sz;
	uchar_t version[2];
	uint16_t rec_sz;
	SSL3AlertDescription desc;
	SSL3ContentType content_type;
	ssl_t *ssl;
	KSSLCipherSpec *spec;
	int error, ret;
	kssl_cmd_t kssl_cmd = KSSL_CMD_DELIVER_PROXY;
	boolean_t deliverit = B_FALSE;
	crypto_data_t cipher_data;

	ASSERT(ctx != NULL);

	ssl = (ssl_t *)(ctx);

	mp = firstmp = *mpp;
	*outmp = NULL;
more:

	while (mp != NULL) {
		ASSERT(DB_TYPE(mp) == M_DATA);

		if (DB_REF(mp) > 1) {
			/*
			 * Fortunately copyb() preserves the offset,
			 * tail space and alignment so the copy is
			 * ready to be made an SSL record.
			 */
			if ((copybp = copyb(mp)) == NULL)
				return (KSSL_CMD_NOT_SUPPORTED);

			copybp->b_cont = mp->b_cont;
			if (mp == firstmp) {
				*mpp = copybp;
			} else if (prevmp != NULL) {
				prevmp->b_cont = copybp;
			}
			freeb(mp);
			mp = copybp;
		}

		DTRACE_PROBE1(kssl_mblk__handle_record_cycle, mblk_t *, mp);
		content_type = (SSL3ContentType)mp->b_rptr[0];

		switch (content_type) {
		case content_application_data:
			break;
		case content_change_cipher_spec:
		case content_alert:
		case content_handshake:
		case content_handshake_v2:
			nextmp = mp->b_cont;

			/* Remove this message */
			if (prevmp != NULL) {
				prevmp->b_cont = nextmp;

				/*
				 * If we had processed blocks that need to
				 * be delivered, then remember that error code
				 */
				if (kssl_cmd == KSSL_CMD_DELIVER_PROXY)
					deliverit = B_TRUE;
			}

			mutex_enter(&ssl->kssl_lock);
			/* NOTE: This routine could free mp. */
			kssl_cmd = kssl_handle_any_record(ssl, mp, outmp,
			    NULL, NULL);

			if (ssl->alert_sendbuf != NULL) {
				mp = nextmp;
				DTRACE_PROBE(kssl_err__alert_after_handle_any);
				goto sendalert;
			}
			mutex_exit(&ssl->kssl_lock);

			if (deliverit) {
				kssl_cmd = KSSL_CMD_DELIVER_PROXY;
			}

			mp = nextmp;
			continue;	/* to the while loop */
		default:
			desc = decode_error;
			KSSL_COUNTER(internal_errors, 1);
			DTRACE_PROBE(kssl_err__decode_error);
			goto makealert;
		}

		version[0] = mp->b_rptr[1];
		version[1] = mp->b_rptr[2];
		rec_sz_p = SSL3_REC_SIZE(mp);
		rec_sz = BE16_TO_U16(rec_sz_p);

		mp->b_rptr += SSL3_HDR_LEN;
		recend = mp->b_rptr + rec_sz;
		real_recend = recend;

		/*
		 * Check the assumption that each mblk contains exactly
		 * one complete SSL record. We bail out if the check fails.
		 */
		ASSERT(recend == mp->b_wptr);
		if (recend != mp->b_wptr) {
			desc = decode_error;
			KSSL_COUNTER(internal_errors, 1);
			DTRACE_PROBE(kssl_err__not_complete_record);
			goto makealert;
		}

		spec = &ssl->spec[KSSL_READ];
		mac_sz = spec->mac_hashsz;
		if (spec->cipher_ctx != 0) {

			/*
			 * The record length must be a multiple of the
			 * block size for block ciphers.
			 * The cipher_bsize is always a power of 2.
			 */
			if ((spec->cipher_type == type_block) &&
			    ((rec_sz & (spec->cipher_bsize - 1)) != 0)) {
				DTRACE_PROBE2(kssl_err__bad_record_size,
				    uint16_t, rec_sz,
				    int, spec->cipher_bsize);
				KSSL_COUNTER(record_decrypt_failure, 1);
				mp->b_rptr = recend;
				desc = decrypt_error;
				goto makealert;
			}

			cipher_data.cd_format = CRYPTO_DATA_RAW;
			cipher_data.cd_offset = 0;
			cipher_data.cd_length = rec_sz;
			cipher_data.cd_miscdata = NULL;
			cipher_data.cd_raw.iov_base = (char *)mp->b_rptr;
			cipher_data.cd_raw.iov_len = rec_sz;
			error = crypto_decrypt_update(spec->cipher_ctx,
			    &cipher_data, NULL, NULL);
			if (CRYPTO_ERR(error)) {
				DTRACE_PROBE1(
				    kssl_err__crypto_decrypt_update_failed,
				    int, error);
				KSSL_COUNTER(record_decrypt_failure, 1);
				mp->b_rptr = recend;
				desc = decrypt_error;
				goto makealert;
			}
		}
		if (spec->cipher_type == type_block) {
			uint_t pad_sz = recend[-1];
			pad_sz++;
			if (pad_sz + mac_sz > rec_sz) {
				DTRACE_PROBE(kssl_err__pad_mac_bigger);
				mp->b_rptr = recend;
				desc = bad_record_mac;
				goto makealert;
			}
			rec_sz -= pad_sz;
			recend -= pad_sz;
		}
		if (mac_sz != 0) {
			uchar_t hash[MAX_HASH_LEN];
			if (rec_sz < mac_sz) {
				DTRACE_PROBE(kssl_err__pad_smaller_mac);
				mp->b_rptr = real_recend;
				desc = bad_record_mac;
				goto makealert;
			}
			rec_sz -= mac_sz;
			recend -= mac_sz;
			ret = kssl_compute_record_mac(ssl, KSSL_READ,
			    ssl->seq_num[KSSL_READ], content_type,
			    version, mp->b_rptr, rec_sz, hash);
			if (ret != CRYPTO_SUCCESS ||
			    bcmp(hash, recend, mac_sz)) {
				DTRACE_PROBE1(kssl_mblk__MACmismatch_handlerec,
				    mblk_t *, mp);
				mp->b_rptr = real_recend;
				desc = bad_record_mac;
				DTRACE_PROBE(kssl_err__msg_MAC_mismatch);
				KSSL_COUNTER(verify_mac_failure, 1);
				goto makealert;
			}
			ssl->seq_num[KSSL_READ]++;
		}

		if (ssl->hs_waitstate != idle_handshake) {
			DTRACE_PROBE1(kssl_err__unexpected_msg,
			    SSL3WaitState, ssl->hs_waitstate);
			mp->b_rptr = real_recend;
			desc = unexpected_message;
			goto makealert;
		}
		mp->b_wptr = recend;

		DTRACE_PROBE1(kssl_mblk__dblk_cooked, mblk_t *, mp);
		KSSL_COUNTER(appdata_record_ins, 1);

		prevmp = mp;
		mp = mp->b_cont;
	}

	return (kssl_cmd);

makealert:
	nextmp = mp->b_cont;
	freeb(mp);
	mp = nextmp;
	mutex_enter(&ssl->kssl_lock);
	kssl_send_alert(ssl, alert_fatal, desc);

	if (ssl->alert_sendbuf == NULL) {
		/* internal memory allocation failure. just return. */
		DTRACE_PROBE(kssl_err__alert_msg_alloc_failed);
		mutex_exit(&ssl->kssl_lock);

		if (mp) {
			prevmp = NULL;
			goto more;
		}

		return (KSSL_CMD_NONE);
	}
	kssl_cmd = KSSL_CMD_SEND;
sendalert:
	if (*outmp == NULL) {
		*outmp = ssl->alert_sendbuf;
	} else {
		linkb(*outmp, ssl->alert_sendbuf);
	}
	ssl->alert_sendbuf = NULL;
	mutex_exit(&ssl->kssl_lock);

	if (mp) {
		prevmp = NULL;
		goto more;
	}

	return (kssl_cmd);
}
/*
 * This is the routine that handles incoming SSL records.
 * When called the first time, with a NULL context, this routine expects
 * a ClientHello SSL Handshake packet and shall allocate a context
 * of a new SSL connection.
 * During the rest of the handshake packets, the routine adjusts the
 * state of the context according to the record received.
 * After the ChangeCipherSpec message is received, the routine first
 * decrypts/authenticated the packet using the key materials in the
 * connection's context.
 * The return code tells the caller what to do with the returned packet.
 */
static kssl_cmd_t
kssl_handle_any_record(kssl_ctx_t ctx, mblk_t *mp, mblk_t **decrmp,
    kssl_callback_t cbfn, void *arg)
{
	uchar_t *recend, *rec_sz_p;
	uchar_t version[2];
	uchar_t *real_recend, *save_rptr, *save_wptr;
	int rhsz = SSL3_HDR_LEN;
	uint16_t rec_sz;
	int sz;
	int mac_sz;
	SSL3AlertDescription desc;
	SSL3AlertLevel level;
	SSL3ContentType content_type;
	ssl_t *ssl;
	KSSLCipherSpec *spec;
	int error = 0, ret;

	ASSERT(ctx != NULL);

	ssl = (ssl_t *)(ctx);

	*decrmp = NULL;

	save_rptr = mp->b_rptr;
	save_wptr = mp->b_wptr;

	ASSERT(MUTEX_HELD(&ssl->kssl_lock));

	content_type = (SSL3ContentType)mp->b_rptr[0];
	if (content_type == content_handshake_v2) {
		if (ssl->hs_waitstate == wait_client_hello) {
			/* V2 compatible ClientHello */
			if (mp->b_rptr[3] == 0x03 &&
			    (mp->b_rptr[4] == 0x01 ||
			    mp->b_rptr[4] == 0x00)) {
				ssl->major_version = version[0] = mp->b_rptr[3];
				ssl->minor_version = version[1] = mp->b_rptr[4];
			} else {
			/* We don't support "pure" SSLv2 */
				DTRACE_PROBE(kssl_err__no_SSLv2);
				ssl->major_version = mp->b_rptr[3];
				ssl->minor_version = mp->b_rptr[4];
				desc = protocol_version;
				goto sendalert;
			}
		}
		rec_sz = (uint16_t)mp->b_rptr[1];
		rhsz = 2;
	} else {
		ssl->major_version = version[0] = mp->b_rptr[1];
		ssl->minor_version = version[1] = mp->b_rptr[2];
		rec_sz_p = SSL3_REC_SIZE(mp);
		rec_sz = BE16_TO_U16(rec_sz_p);
	}

	mp->b_rptr += rhsz;
	recend = mp->b_rptr + rec_sz;
	real_recend = recend;

	/*
	 * Check the assumption that each mblk contains exactly
	 * one complete SSL record. We bail out if the check fails.
	 */
	ASSERT(recend == mp->b_wptr);
	if (recend != mp->b_wptr) {
		DTRACE_PROBE3(kssl_mblk__handle_any_record_recszerr,
		    mblk_t *, mp, int, rhsz, int, rec_sz);
		DTRACE_PROBE(kssl_err__record_size);
		desc = decode_error;
		KSSL_COUNTER(internal_errors, 1);
		goto sendalert;
	}

	spec = &ssl->spec[KSSL_READ];
	mac_sz = spec->mac_hashsz;
	if (spec->cipher_ctx != 0) {
		/*
		 * The record length must be a multiple of the
		 * block size for block ciphers.
		 */
		if ((spec->cipher_type == type_block) &&
		    ((rec_sz & (spec->cipher_bsize - 1)) != 0)) {
			DTRACE_PROBE2(kssl_err__bad_record_size,
			    uint16_t, rec_sz, int, spec->cipher_bsize);
			KSSL_COUNTER(record_decrypt_failure, 1);
			mp->b_rptr = recend;
			desc = decrypt_error;
			goto sendalert;
		}

		spec->cipher_data.cd_length = rec_sz;
		spec->cipher_data.cd_raw.iov_base = (char *)mp->b_rptr;
		spec->cipher_data.cd_raw.iov_len = rec_sz;
		error = crypto_decrypt_update(spec->cipher_ctx,
		    &spec->cipher_data, NULL, NULL);
		if (CRYPTO_ERR(error)) {
			DTRACE_PROBE1(kssl_err__crypto_decrypt_update_failed,
			    int, error);
			KSSL_COUNTER(record_decrypt_failure, 1);
			mp->b_rptr = recend;
			desc = decrypt_error;
			goto sendalert;
		}
	}
	if (spec->cipher_type == type_block) {
		uint_t pad_sz = recend[-1];
		pad_sz++;
		if (pad_sz + mac_sz > rec_sz) {
			DTRACE_PROBE2(kssl_err__pad_mac_mismatch,
			    int, pad_sz, int, mac_sz);
			mp->b_rptr = recend;
			desc = bad_record_mac;
			goto sendalert;
		}
		rec_sz -= pad_sz;
		recend -= pad_sz;
	}
	if (mac_sz != 0) {
		uchar_t hash[MAX_HASH_LEN];
		if (rec_sz < mac_sz) {
			DTRACE_PROBE1(kssl_err__mac_size_too_big,
			    int, mac_sz);
			mp->b_rptr = real_recend;
			desc = bad_record_mac;
			goto sendalert;
		}
		rec_sz -= mac_sz;
		recend -= mac_sz;
		ret = kssl_compute_record_mac(ssl, KSSL_READ,
		    ssl->seq_num[KSSL_READ], content_type,
		    version, mp->b_rptr, rec_sz, hash);
		if (ret != CRYPTO_SUCCESS ||
		    bcmp(hash, recend, mac_sz)) {
			DTRACE_PROBE1(kssl_mblk__MACmismatch_anyrecord,
			    mblk_t *, mp);
			mp->b_rptr = real_recend;
			desc = bad_record_mac;
			DTRACE_PROBE(kssl_err__msg_MAC_mismatch);
			KSSL_COUNTER(verify_mac_failure, 1);
			goto sendalert;
		}
		ssl->seq_num[KSSL_READ]++;
		DTRACE_PROBE1(kssl_mblk__after_compute_MAC,
		    mblk_t *, mp);
	}

	switch (content_type) {
	case content_handshake:
		do {
			DTRACE_PROBE1(kssl_mblk__content_handshake_cycle,
			    mblk_t *, mp);
			if (error != 0 ||
			    /* ignore client renegotiation for now */
			    ssl->hs_waitstate == idle_handshake) {
				mp->b_rptr = recend;
				DTRACE_PROBE(kssl_renegotiation_request);
			}
			if (mp->b_rptr == recend) {
				mp->b_rptr = real_recend;
				if (error != 0) {
					goto error;
				}
				freeb(mp);

				if (ssl->hs_waitstate == wait_client_key_done)
					return (KSSL_CMD_QUEUED);

				return ((ssl->handshake_sendbuf != NULL) ?
				    KSSL_CMD_SEND : KSSL_CMD_NONE);
			}
			if (ssl->msg.state < MSG_BODY) {
				if (ssl->msg.state == MSG_INIT) {
					ssl->msg.type =
					    (SSL3HandshakeType)*mp->b_rptr++;
					ssl->msg.state = MSG_INIT_LEN;
				}
				if (ssl->msg.state == MSG_INIT_LEN) {
					int msglenb =
					    ssl->msg.msglen_bytes;
					int msglen = ssl->msg.msglen;
					while (mp->b_rptr < recend &&
					    msglenb < 3) {
						msglen = (msglen << 8) +
						    (uint_t)(*mp->b_rptr++);
						msglenb++;
					}
					ssl->msg.msglen_bytes = msglenb;
					ssl->msg.msglen = msglen;
					if (msglenb == 3) {
						ssl->msg.state = MSG_BODY;
					}
				}
				if (mp->b_rptr == recend) {
					mp->b_rptr = real_recend;
					freeb(mp);
					return (KSSL_CMD_NONE);
				}
			}
			ASSERT(ssl->msg.state == MSG_BODY);

			sz = recend - mp->b_rptr;

			if (ssl->msg.head == NULL &&
			    ssl->msg.msglen <= sz) {
				continue;
			}
			if (ssl->msg.head != NULL) {
				sz += msgdsize(ssl->msg.head);
				if (ssl->msg.msglen <= sz) {
					ssl->msg.tail->b_cont = mp;
					mp = ssl->msg.head;
					ssl->sslcnt = 100;
					ssl->msg.head = NULL;
					ssl->msg.tail = NULL;
					if (pullupmsg(mp, -1)) {
						recend = mp->b_rptr + sz;
						ASSERT(recend <= mp->b_wptr);
						continue;
					}
					mp->b_rptr = real_recend;
					error = ENOMEM;
					KSSL_COUNTER(alloc_fails, 1);
					goto error;
				}
			}

			mp->b_wptr = recend;

			if (ssl->msg.head == NULL) {
				ssl->msg.head = mp;
				ssl->msg.tail = mp;
				return (KSSL_CMD_NONE);
			} else {
				ssl->msg.tail->b_cont = mp;
				ssl->msg.tail = mp;
				return (KSSL_CMD_NONE);
			}
		} while (kssl_handle_handshake_message(ssl, mp, &error, cbfn,
		    arg));
		if (error == SSL_MISS) {
			mp->b_rptr = save_rptr;
			mp->b_wptr = save_wptr;
			KSSL_COUNTER(fallback_connections, 1);
			return (KSSL_CMD_NOT_SUPPORTED);
		}
		if (ssl->hs_waitstate == wait_client_key_done) {
			return (KSSL_CMD_QUEUED);
		} else {
			return (KSSL_CMD_NONE);
		}
	case content_alert:
		DTRACE_PROBE1(kssl_mblk__content_alert, mblk_t *, mp);
		if (rec_sz != 2) {
			DTRACE_PROBE(kssl_err__illegal_param);
			mp->b_rptr = real_recend;
			desc = illegal_parameter;
			goto sendalert;
		} else {
			level = *mp->b_rptr++;
			desc = *mp->b_rptr++;
			mp->b_rptr = real_recend;
			if (level != alert_warning || desc != close_notify) {
				if (ssl->sid.cached == B_TRUE) {
					kssl_uncache_sid(&ssl->sid,
					    ssl->kssl_entry);
				}
				DTRACE_PROBE2(kssl_err__bad_content_alert,
				    SSL3AlertLevel, level,
				    SSL3AlertDescription, desc);
				ssl->fatal_alert = B_TRUE;
				error = EBADMSG;
				goto error;
			} else {
				ssl->close_notify_clnt = B_TRUE;
				ssl->activeinput = B_FALSE;
				freeb(mp);
				return (KSSL_CMD_NONE);
			}
		}
	case content_change_cipher_spec:
		DTRACE_PROBE1(kssl_mblk__change_cipher_spec,
		    mblk_t *, mp);
		if (ssl->hs_waitstate != wait_change_cipher) {
			desc = unexpected_message;
		} else if (rec_sz != 1 || *mp->b_rptr != 1) {
			desc = illegal_parameter;
		} else {
			mp->b_rptr = real_recend;
			ssl->hs_waitstate = wait_finished;
			ssl->seq_num[KSSL_READ] = 0;
			if ((error = kssl_spec_init(ssl, KSSL_READ)) != 0) {
				DTRACE_PROBE1(kssl_err__kssl_spec_init_error,
				    int, error);
				goto error;
			}
			ssl->activeinput = B_FALSE;
			freeb(mp);
			return (KSSL_CMD_NONE);
		}
		mp->b_rptr = real_recend;
		DTRACE_PROBE(kssl_err__change_cipher_spec);
		goto sendalert;

	case content_application_data:
		DTRACE_PROBE1(kssl_mblk__content_app_data,
		    mblk_t *, mp);
		if (ssl->hs_waitstate != idle_handshake) {
			DTRACE_PROBE(kssl_err__content_app_data);
			mp->b_rptr = real_recend;
			desc = unexpected_message;
			goto sendalert;
		}
		mp->b_wptr = recend;
		*decrmp = mp;
		ssl->activeinput = B_FALSE;
		return (KSSL_CMD_DELIVER_PROXY);

	case content_handshake_v2:
		DTRACE_PROBE1(kssl_mblk__content_handshake_v2,
		    mblk_t *, mp);
		error = kssl_handle_v2client_hello(ssl, mp, rec_sz);
		if (error == SSL_MISS) {
			mp->b_rptr = save_rptr;
			mp->b_wptr = save_wptr;
			KSSL_COUNTER(fallback_connections, 1);
			return (KSSL_CMD_NOT_SUPPORTED);
		} else if (error != 0) {
			DTRACE_PROBE(kssl_err__v2client_hello_failed);
			goto error;
		}
		freeb(mp);
		return (KSSL_CMD_SEND);
	default:
		DTRACE_PROBE1(kssl_mblk__unexpected_msg,
		    mblk_t *, mp);
		mp->b_rptr = real_recend;
		desc = unexpected_message;
		break;
	}

sendalert:
	kssl_send_alert(ssl, alert_fatal, desc);
	*decrmp = ssl->alert_sendbuf;
	ssl->alert_sendbuf = NULL;
	freeb(mp);
	return ((*decrmp != NULL) ? KSSL_CMD_SEND : KSSL_CMD_NONE);
error:
	freeb(mp);
	return (KSSL_CMD_NONE);
}

/*
 * Initialize the context of an SSL connection, coming to the specified
 * address. The ssl structure is returned held.
 */
kssl_status_t
kssl_init_context(kssl_ent_t kssl_ent, struct sockaddr *addr, int mss,
    kssl_ctx_t *kssl_ctxp)
{
	ssl_t *ssl = kmem_cache_alloc(kssl_cache, KM_NOSLEEP);
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;

	if (ssl == NULL) {
		return (KSSL_STS_ERR);
	}

	bzero(ssl, sizeof (ssl_t));

	ssl->kssl_entry = (kssl_entry_t *)kssl_ent;
	KSSL_ENTRY_REFHOLD(ssl->kssl_entry);

	if (sin->sin_family == AF_INET) {
		IN6_IPADDR_TO_V4MAPPED(sin->sin_addr.s_addr, &ssl->faddr);
	} else {
		/* struct assignment */
		ssl->faddr = ((struct sockaddr_in6 *)addr)->sin6_addr;
	}
	ssl->tcp_mss = mss;
	ssl->sendalert_level = alert_warning;
	ssl->sendalert_desc = close_notify;
	ssl->sid.cached = B_FALSE;

	*kssl_ctxp = (kssl_ctx_t)ssl;
	return (KSSL_STS_OK);
}

void
kssl_set_mss(kssl_ctx_t ctx, uint32_t mss)
{
	ssl_t *ssl = (ssl_t *)ctx;
	ssl->tcp_mss = mss;
}

/*
 * Builds SSL records out of the chain of mblks, and returns it.
 * Takes a copy of the message before encrypting it if it has another
 * reference.
 * In case of failure, NULL is returned, and the message will be
 * freed by the caller.
 * A NULL mp means a close_notify is requested.
 */
mblk_t *
kssl_build_record(kssl_ctx_t ctx, mblk_t *mp)
{
	ssl_t *ssl = (ssl_t *)ctx;
	mblk_t *retmp = mp, *bp = mp, *prevbp = mp, *copybp;

	ASSERT(ssl != NULL);

	/*
	 * Produce new close_notify message. This is necessary to perform
	 * proper cleanup w.r.t. SSL protocol spec by sending close_notify SSL
	 * alert record if running with KSSL proxy.
	 * This should be done prior to sending the FIN so the client side can
	 * attempt to do graceful cleanup. Ideally, we should wait for client's
	 * close_notify but not all clients send it which would hang the
	 * connection. This way of closing the SSL session (Incomplete Close)
	 * prevents truncation attacks for protocols without end-of-data
	 * markers (as opposed to the Premature Close).
	 * Checking the close_notify_srvr flag will prevent from sending the
	 * close_notify message twice in case of duplicate shutdown() calls.
	 */
	if (mp == NULL && !ssl->close_notify_srvr) {
		kssl_send_alert(ssl, alert_warning, close_notify);
		if (ssl->alert_sendbuf == NULL)
			return (NULL);
		mp = bp = retmp = prevbp = ssl->alert_sendbuf;
		ssl->alert_sendbuf = NULL;
		ssl->close_notify_srvr = B_TRUE;
	}

	ASSERT(mp != NULL);
	ASSERT(bp != NULL);

	do {
		if (DB_REF(bp) > 1) {
			/*
			 * Fortunately copyb() preserves the offset,
			 * tail space and alignment so the copy is
			 * ready to be made an SSL record.
			 */
			if ((copybp = copyb(bp)) == NULL)
				return (NULL);

			copybp->b_cont = bp->b_cont;
			if (bp == mp) {
				retmp = copybp;
			} else {
				prevbp->b_cont = copybp;
			}
			freeb(bp);
			bp = copybp;
		}

		if (kssl_build_single_record(ssl, bp) != KSSL_STS_OK)
			return (NULL);

		prevbp = bp;
		bp = bp->b_cont;
	} while (bp != NULL);

	return (retmp);
}

/*
 * Builds a single SSL record by prepending SSL header (optional) and performing
 * encryption and MAC. The encryption of the record is done in-line.
 * Expects an mblk with associated dblk's base to have space for the SSL header
 * or an mblk which already has the header present. In both cases it presumes
 * that the mblk's dblk limit has space for the MAC + padding.
 * If the close_notify_srvr flag is set it is presumed that the mblk already
 * contains SSL header in which case only the record length field will be
 * adjusted with the MAC/padding size.
 */
static kssl_status_t
kssl_build_single_record(ssl_t *ssl, mblk_t *mp)
{
	int len;
	int reclen;
	uchar_t *recstart, *versionp;
	KSSLCipherSpec *spec;
	int mac_sz;
	int pad_sz;

	spec = &ssl->spec[KSSL_WRITE];
	mac_sz = spec->mac_hashsz;

	ASSERT(DB_REF(mp) == 1);
	/* The dblk must always have space for the padding and MAC suffix. */
	ASSERT(mp->b_datap->db_lim - mp->b_wptr >= mac_sz + spec->cipher_bsize);

	/* kssl_send_alert() constructs the SSL header by itself. */
	if (!ssl->close_notify_srvr)
		len = MBLKL(mp) - SSL3_HDR_LEN;
	else
		len = MBLKL(mp);

	ASSERT(len > 0);

	mutex_enter(&ssl->kssl_lock);

	recstart = mp->b_rptr;
	if (!ssl->close_notify_srvr) {
		/* The dblk must have space for the SSL header prefix. */
		ASSERT(mp->b_rptr - mp->b_datap->db_base >= SSL3_HDR_LEN);
		recstart = mp->b_rptr = mp->b_rptr - SSL3_HDR_LEN;
		recstart[0] = content_application_data;
		recstart[1] = ssl->major_version;
		recstart[2] = ssl->minor_version;
	}
	versionp = &recstart[1];

	reclen = len + mac_sz;
	if (spec->cipher_type == type_block) {
		pad_sz = spec->cipher_bsize -
		    (reclen & (spec->cipher_bsize - 1));
		ASSERT(reclen + pad_sz <=
		    SSL3_MAX_RECORD_LENGTH);
		reclen += pad_sz;
	}
	recstart[3] = (reclen >> 8) & 0xff;
	recstart[4] = reclen & 0xff;

	if (kssl_mac_encrypt_record(ssl, recstart[0], versionp,
	    recstart, mp) != 0) {
		/* Do we need an internal_error Alert here? */
		mutex_exit(&ssl->kssl_lock);
		return (KSSL_STS_ERR);
	}

	/* Alert messages are accounted in kssl_send_alert(). */
	if (recstart[0] == content_application_data)
		KSSL_COUNTER(appdata_record_outs, 1);
	mutex_exit(&ssl->kssl_lock);
	return (KSSL_STS_OK);
}
