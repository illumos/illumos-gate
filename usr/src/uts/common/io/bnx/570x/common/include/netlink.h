/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _netlink_h_
#define _netlink_h_

#include "bcmtype.h"

/* The values are defined to adapt the previous IMD firmware definitions */
#define NETLINK_STATUS_SUCCESS                     0
#define NETLINK_STATUS_DENY_PHY_ACCESS_FAILURE     0x10005
#define NETLINK_STATUS_PHY_FAILURE                 0x1000a
#define NETLINK_STATUS_WRONG_MEDIA_FAILURE         0x20006
#define NETLINK_STATUS_BAD_LINK_SETTING_FAILURE    0x20007
#define NETLINK_STATUS_PWR_MGMT_CONFLICT_FAILURE   0x20008
#define NETLINK_STATUS_INVALID_INPUT_FAILURE       0x20002
#define NETLINK_STATUS_NOT_SUPPORTED_FAILURE       0x2000b
#define NETLINK_STATUS_BAD_SPEED_FAILURE           0x80000001
#define NETLINK_STATUS_LINK_ALREADY_UP_FAILURE     0x80000002




/* Link status codes: definition based on what's in shmem.h */
#define NETLINK_GET_LINK_STATUS_INIT_VALUE                 0xffffffff
#define NETLINK_GET_LINK_STATUS_LINK_UP                    0x1
#define NETLINK_GET_LINK_STATUS_LINK_DOWN                  0x0
#define NETLINK_GET_LINK_STATUS_SPEED_MASK                 0x1e
#define NETLINK_GET_LINK_STATUS_AN_INCOMPLETE              (0<<1)

#define NETLINK_GET_LINK_STATUS_10HALF                     (1<<1)
#define NETLINK_GET_LINK_STATUS_10FULL                     (2<<1)
#define NETLINK_GET_LINK_STATUS_100HALF                    (3<<1)
#define NETLINK_GET_LINK_STATUS_100BASE_T4                 (4<<1)
#define NETLINK_GET_LINK_STATUS_100FULL                    (5<<1)
#define NETLINK_GET_LINK_STATUS_1000HALF                   (6<<1)
#define NETLINK_GET_LINK_STATUS_1000FULL                   (7<<1)
#define NETLINK_GET_LINK_STATUS_2500HALF                   (8<<1)

#define NETLINK_GET_LINK_STATUS_2500FULL                   (9<<1)

#define NETLINK_GET_LINK_STATUS_AN_ENABLED                 0x000020L
#define NETLINK_GET_LINK_STATUS_AN_COMPLETE                0x000040L
#define NETLINK_GET_LINK_STATUS_PARALLEL_DET               0x000080L
#define NETLINK_GET_LINK_STATUS_RESERVED                   0x000100L
#define NETLINK_GET_LINK_STATUS_PARTNER_AD_1000FULL        0x000200L
#define NETLINK_GET_LINK_STATUS_PARTNER_AD_1000HALF        0x000400L
#define NETLINK_GET_LINK_STATUS_PARTNER_AD_100BT4          0x000800L
#define NETLINK_GET_LINK_STATUS_PARTNER_AD_100FULL         0x001000L
#define NETLINK_GET_LINK_STATUS_PARTNER_AD_100HALF         0x002000L
#define NETLINK_GET_LINK_STATUS_PARTNER_AD_10FULL          0x004000L
#define NETLINK_GET_LINK_STATUS_PARTNER_AD_10HALF          0x008000L
#define NETLINK_GET_LINK_STATUS_TX_FC_ENABLED              0x010000L
#define NETLINK_GET_LINK_STATUS_RX_FC_ENABLED              0x020000L
#define NETLINK_GET_LINK_STATUS_PARTNER_SYM_PAUSE_CAP      0x040000L
#define NETLINK_GET_LINK_STATUS_PARTNER_ASYM_PAUSE_CAP     0x080000L
#define NETLINK_GET_LINK_STATUS_SERDES_LINK                0x100000L
#define NETLINK_GET_LINK_STATUS_PARTNER_AD_2500FULL        0x200000L
#define NETLINK_GET_LINK_STATUS_PARTNER_AD_2500HALF        0x400000L

#define NETLINK_GET_LINK_STATUS_NO_MEDIA_DETECTED          0x20000000L
#define NETLINK_GET_LINK_STATUS_CABLESENSE                 0x40000000L
#define NETLINK_GET_LINK_STATUS_SW_TIMER_EVENT             0x80000000L


/* netlink_get_link_status():
 * Input: A pointer to a u32_t type storage
 * Output: bit-wise OR'd of any NETLINK_GET_LINK_STATUS_* constants
 * Return: 0 for success, non-zero for failure (see NETLINK_CODE_* constants).
 */
typedef u32_t (* netlink_get_link_status_t)(u32_t *get_link_attrib);

u32_t netlink_get_link_status ( u32_t *get_link_attrib );



/* netlink_drv_set_link()
 * Input: A u32_t value indicating the desired link
 * Output: None, in fact, the link may not be effective right away
 *         (subject to the time needed to establish the link).
 * Return: 0 for success, non-zero for failure (see NETLINK_CODE_* constants).
 */
u32_t netlink_drv_set_link( u32_t drv_link_attrib );

#define NETLINK_DRV_SET_LINK_SPEED_10HALF        (1<<0)
#define NETLINK_DRV_SET_LINK_SPEED_10FULL        (1<<1)
#define NETLINK_DRV_SET_LINK_SPEED_100HALF       (1<<2)
#define NETLINK_DRV_SET_LINK_SPEED_100FULL       (1<<3)

#define NETLINK_DRV_SET_LINK_SPEED_1GHALF        (1<<4)
#define NETLINK_DRV_SET_LINK_SPEED_1GFULL        (1<<5)

#define NETLINK_DRV_SET_LINK_SPEED_2G5HALF       (1<<6)
#define NETLINK_DRV_SET_LINK_SPEED_2G5FULL       (1<<7)

#define NETLINK_DRV_SET_LINK_SPEED_10GHALF       (1<<8) // place holder for now.
#define NETLINK_DRV_SET_LINK_SPEED_10GFULL       (1<<9) // place holder for now.
#define NETLINK_DRV_SET_LINK_ENABLE_AUTONEG      (1<<10)
                        /* (vs Forced): If autoeng enabled, the speed
                         * bits above dictate what capability advertisement.
                         * Otherwise, only one of the applicable speed/duplex
                         * bits above can be set, and it will be used to
                         * establish the forced link.
                         */
#define NETLINK_DRV_SET_LINK_PHY_APP_MASK        (1<<11)
#define NETLINK_DRV_SET_LINK_PHY_APP_REMOTE      (1<<11)
#define NETLINK_DRV_SET_LINK_PHY_APP_LOCAL       (0<<11)

                        /* (Local vs Remote): The setting will be stored as
                         * driver preference. If the media type matches the
                         * current setup, the setting will also be applied
                         * immediately.
                         */

#define NETLINK_DRV_SET_LINK_FC_SYM_PAUSE        (1<<12)
#define NETLINK_DRV_SET_LINK_FC_ASYM_PAUSE       (1<<13)

#define NETLINK_DRV_SET_LINK_ETH_AT_WIRESPEED_ENABLE (1<<14)
#define NETLINK_DRV_SET_LINK_PHY_RESET           (1<<15)
                        /* Local serdes will be reset. If remote Cu PHY
                         * is present, MDIO write will be issued to the
                         * remote PHY to reset it. Then, whatever other
                         * settings will be applied.
                         */


/* This override bit tells the set_link() routine to set the link
 * again even if the link is already up at a desired speed */
#define NETLINK_SET_LINK_OVERRIDE              0x80000000

/* Setting this will advertise all capability that the power budget (e.g.
 * overdraw Vaux current in absence of main power) and design capability
 * (e.g. 2.5G) allow.
 * In case of the 5708 Serdes, fall back is assumed. */
#define NETLINK_SET_LINK_SPEED_AUTONEG         0x00

/* These speed values are used for forced speed unless selective autoneg
 * is selected. Do NOT try to bit-wise OR them. In the case of selective
 * autoneg, that speed will be advertised. */
#define NETLINK_SET_LINK_SPEED_UNKNOWN         0x00
#define NETLINK_SET_LINK_SPEED_10MBPS          0x01
#define NETLINK_SET_LINK_SPEED_100MBPS         0x02
#define NETLINK_SET_LINK_SPEED_1000MBPS        0x04
#define NETLINK_SET_LINK_SPEED_2500MBPS        0x08
#define NETLINK_SET_LINK_SPEED_MASK            0xff

#define NETLINK_SET_LINK_DUPLEX_HALF           0x0100
#define NETLINK_SET_LINK_DUPLEX_FULL           0x0000

#define NETLINK_SET_LINK_PAUSE_CAP             0x0200
#define NETLINK_SET_LINK_ASYM_PAUSE            0x0400

/* When selective autoneg is enabled, only one speed will be used for
 * capability advertisement. */
#define NETLINK_SET_LINK_SELECTIVE_AUTONEG     0x10000

/* netlink_set_link():
 * Input: bit-wise OR'd of any NETLINK_SET_LINK_* constants (except the speed)
 * Output: None.
 * Return: 0 for success, non-zero for failure (see NETLINK_CODE_* constants).
 *
 * Example 1: To set 100Full forced speed, the parameter would look like
 *                NETLINK_SET_LINK_SPEED_100MBPS |
 *                NETLINK_SET_LINK_DUPLEX_FULL.
 * Example 2: To set selective autoneg at 100Full with pause capability,
 *            the parameter would look like
 *                NETLINK_SET_LINK_SPEED_100MBPS |
 *                NETLINK_SET_LINK_PAUSE_CAP |
 *                NETLINK_SET_LINK_SELECTIVE_AUTONEG |
 *                NETLINK_SET_LINK_DUPLEX_FULL.
 *
 * Note 1: If caller passes any speed settings, and if the system is
 *         in OSPresent mode, no action will be taken, the actual speed
 *         advertisement will be done by OS Driver.
 * Note 2: If caller passes "NETLINK_SET_LINK_SPEED_AUTONEG" parameter,
 *         if the system is in OSAbsent mode and if the system has
 *         Vmain power the link speed 2500/1000/100/10 will be advertised.
 * Note 3: If caller passes "NETLINK_SET_LINK_SPEED_AUTONEG" parameter,
 *         if the system is in OSAbsent mode and if the system does
 *         not have Vmain power (Vaux power mode) and the "
 *         PowerOverDrawn" bit is set (OK to consume more power in
 *         order to acquire highest link speed), the link speed
 *         2500/1000/100/10 will be advertised.
 * Note 4: If caller passes "NETLINK_SET_LINK_SPEED_AUTONEG" parameter,
 *         if the system is in OSAbsent mode, and if the system does
 *         not have Vmain power (Vaux power mode) and the
 *         "PowerOverDrawn" bit is cleared (don't consume more power
 *         than necessary), the link speed 100/10 will be advertised.
 *
 */
typedef u32_t (* netlink_set_link_t)(u32_t set_link_attrib);

u32_t netlink_set_link ( u32_t set_link_attrib );


void netlink_serdes_fallback ( void );

#endif /* _netlink_h_ */
