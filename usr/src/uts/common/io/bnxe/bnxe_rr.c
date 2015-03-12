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
 * Copyright 2014 QLogic Corporation
 * The contents of this file are subject to the terms of the
 * QLogic End User License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://www.qlogic.com/Resources/Documents/DriverDownloadHelp/
 * QLogic_End_User_Software_License.txt
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * Copyright (c) 2002, 2011, Oracle and/or its affiliates. All rights reserved.
 */

#include "bnxe.h"

int BnxeRouteTxRing(um_device_t * pUM,
                    mblk_t *      pMblk)
{
    u32_t     numRings = pUM->devParams.numRings;
    int       ring = 0;
    uint8_t * pHdr;
    mblk_t *  pTmpMblk;
    size_t    mblkLen;
    ushort_t  etype;
    size_t    eHdrSize;

    if (!numRings)
    {
        return 0;
    }

    /*
     * Need enough space to cover the ethernet header (+vlan), max ip header,
     * and the first 4 bytes of the TCP/IP header (src/dst ports).
     */
    size_t  hdrs_size;
    uint8_t hdrs_buf[sizeof(struct ether_vlan_header) +
                     IP_MAX_HDR_LENGTH +
                     sizeof(uint32_t)];

    switch (pUM->devParams.routeTxRingPolicy)
    {
    case BNXE_ROUTE_RING_TCPUDP:

        pHdr = pMblk->b_rptr;

        etype = ntohs(((struct ether_header *)pHdr)->ether_type);

        if (etype == ETHERTYPE_VLAN)
        {
            etype    = ntohs(((struct ether_vlan_header *)pHdr)->ether_type);
            eHdrSize = sizeof(struct ether_vlan_header);
        }
        else
        {
            eHdrSize = sizeof(struct ether_header);
        }

        if (etype == ETHERTYPE_IP)
        {
            mblkLen = MBLKL(pMblk);
            pHdr    = NULL;

            if (mblkLen > (eHdrSize + sizeof(uint8_t)))
            {
                pHdr     = (pMblk->b_rptr + eHdrSize);
                mblkLen -= eHdrSize;

                pHdr = (mblkLen > (((*pHdr & 0x0f) << 2) + sizeof(uint32_t))) ?
                           pMblk->b_rptr : NULL;
            }

            if (pHdr == NULL)
            {
                /* copy the header so it's contiguous in the local hdrs_buf */
                pTmpMblk  = pMblk;
                hdrs_size = 0;

                while (pTmpMblk && (hdrs_size < sizeof(hdrs_buf)))
                {
                    mblkLen = MBLKL(pTmpMblk);

                    if (mblkLen >= (sizeof(hdrs_buf) - hdrs_size))
                    {
                        mblkLen = (sizeof(hdrs_buf) - hdrs_size);
                    }

                    bcopy(pTmpMblk->b_rptr, &hdrs_buf[hdrs_size], mblkLen);

                    hdrs_size += mblkLen;
                    pTmpMblk   = pTmpMblk->b_cont;
                }

                pHdr = hdrs_buf;
            }

            pHdr += eHdrSize;

            if (!(pHdr[6] & 0x3f) && !(pHdr[7] & 0xff))
            {
                switch (pHdr[9])
                {
                case IPPROTO_TCP:
                case IPPROTO_UDP:
                case IPPROTO_ESP:

                    /* source and destination ports */
                    pHdr += (((*pHdr) & 0x0f) << 2);
                    ring  = ((u32_t)(pHdr[0] ^ pHdr[1] ^ pHdr[2] ^ pHdr[3]) %
                             numRings);
                    break;

                case IPPROTO_AH:

                    /* security parameters index */
                    pHdr += (((*pHdr) & 0x0f) << 2);
                    ring  = ((pHdr[4] ^ pHdr[5] ^ pHdr[6] ^ pHdr[7]) %
                             numRings);
                    break;

                default:

                    /* last byte of the destination IP address */
                    ring = (pHdr[19] % numRings);
                    break;
                }
            }
            else
            {
                /* fragmented packet */
                ring = (pHdr[19] % numRings);
            }
        }
        else
        {
            ring = (pMblk->b_band % numRings);
        }

        break;

    case BNXE_ROUTE_RING_DEST_MAC:

        /* last byte of dst mac addr */
        pHdr = pMblk->b_rptr;
        ring = (pHdr[5] % numRings);
        break;

    case BNXE_ROUTE_RING_MSG_PRIO:

        ring = (pMblk->b_band % numRings);
        break;

    case BNXE_ROUTE_RING_NONE:
    default:

        ring = 0;
        break;
    }

    return ring;
}

