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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/bootprops.h>
#include <sys/bootconf.h>
#include <sys/modctl.h>
#include <sys/mman.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/obpdefs.h>
#include <sys/promif.h>
#include <sys/iscsi_protocol.h>

#define	ISCSI_OBP_MAX_CHAP_USER_LEN	16
#define	ISCSI_OBP_MIN_CHAP_LEN		12
#define	ISCSI_OBP_MAX_CHAP_LEN		16

#define	OBP_GET_KEY_STATUS_OK		0
#define	OBP_GET_KEY_STATUS_NOT_EXIST	-3

ib_boot_prop_t boot_property;
extern ib_boot_prop_t *iscsiboot_prop;
static int inet_aton(char *ipstr, uchar_t *ip);
static boolean_t parse_lun_num(uchar_t *str_num, uchar_t *hex_num);
static void generate_iscsi_initiator_id(void);

static int
isdigit(int ch)
{
	return (ch >= '0' && ch <= '9');
}

static boolean_t
iscsiboot_tgt_prop_read(void)
{
	int		proplen;
	boolean_t	set		= B_FALSE;
	char		iscsi_target_ip[INET6_ADDRSTRLEN];
	uchar_t		iscsi_target_name[ISCSI_MAX_NAME_LEN];
	uchar_t		iscsi_par[8];
	char		chap_user[ISCSI_OBP_MAX_CHAP_USER_LEN]	= {0};
	char		chap_password[ISCSI_OBP_MAX_CHAP_LEN]	= {0};
	uchar_t		iscsi_port[8];
	uchar_t		iscsi_lun[8];
	uchar_t		iscsi_tpgt[8];
	long		iscsi_tpgtl;
	long		port;
	int		ret		= 0;
	int		status		= 0;
	int		chap_user_len	= 0;
	int		chap_pwd_len	= 0;

	/* Get iscsi target IP address */
	proplen = BOP_GETPROPLEN(bootops, BP_ISCSI_TARGET_IP);
	if (proplen > 0) {
		if (BOP_GETPROP(bootops, BP_ISCSI_TARGET_IP,
		    iscsi_target_ip) > 0) {
			if (inet_aton(iscsi_target_ip,
			    (uchar_t *)&boot_property.boot_tgt.tgt_ip_u) ==
			    0) {
				boot_property.boot_tgt.sin_family = AF_INET;
				set = B_TRUE;
			}
		}
	}
	if (set != B_TRUE) {
		return (B_FALSE);
	}

	/* Get iscsi target port number */
	set = B_FALSE;
	proplen = BOP_GETPROPLEN(bootops, BP_ISCSI_PORT);
	if (proplen > 0) {
		if (BOP_GETPROP(bootops, BP_ISCSI_PORT,
		    iscsi_port) > 0) {
			if (ddi_strtol((const char *)iscsi_port, NULL,
			    10, &port) == 0) {
				boot_property.boot_tgt.tgt_port =
				    (unsigned int)port;
				set = B_TRUE;
			}
		}
	}
	if (set != B_TRUE) {
		boot_property.boot_tgt.tgt_port = 3260;
	}

	/* Get iscsi target LUN number */
	set = B_FALSE;
	proplen = BOP_GETPROPLEN(bootops, BP_ISCSI_LUN);
	if (proplen > 0) {
		if (BOP_GETPROP(bootops, BP_ISCSI_LUN,
		    iscsi_lun) > 0) {
			if (parse_lun_num(iscsi_lun,
			    (uchar_t *)
			    (&boot_property.boot_tgt.tgt_boot_lun[0]))
			    == B_TRUE) {
				set = B_TRUE;
			}
		}
	}
	if (set != B_TRUE) {
		bzero((void *)boot_property.boot_tgt.tgt_boot_lun, 8);
	}

	/* Get iscsi target portal group tag */
	set = B_FALSE;
	proplen = BOP_GETPROPLEN(bootops, BP_ISCSI_TPGT);
	if (proplen > 0) {
		if (BOP_GETPROP(bootops, BP_ISCSI_TPGT,
		    iscsi_tpgt) > 0) {
			if (ddi_strtol((const char *)iscsi_tpgt, NULL, 10,
			    &iscsi_tpgtl) == 0) {
				boot_property.boot_tgt.tgt_tpgt =
				    (uint16_t)iscsi_tpgtl;
				set = B_TRUE;
			}
		}
	}
	if (set != B_TRUE) {
		boot_property.boot_tgt.tgt_tpgt = 1;
	}

	/* Get iscsi target node name */
	set = B_FALSE;
	boot_property.boot_tgt.tgt_name = NULL;
	proplen = BOP_GETPROPLEN(bootops, BP_ISCSI_TARGET_NAME);
	if (proplen > 0) {
		if (BOP_GETPROP(bootops, BP_ISCSI_TARGET_NAME,
		    iscsi_target_name) > 0) {
			boot_property.boot_tgt.tgt_name =
			    (uchar_t *)kmem_zalloc(proplen + 1, KM_SLEEP);
			boot_property.boot_tgt.tgt_name_len = proplen + 1;
			(void) snprintf((char *)boot_property.boot_tgt.tgt_name,
			    proplen + 1, "%s", iscsi_target_name);
			set = B_TRUE;
		}
	}
	if (set != B_TRUE) {
		if (boot_property.boot_tgt.tgt_name != NULL) {
			kmem_free(boot_property.boot_tgt.tgt_name,
			    boot_property.boot_tgt.tgt_name_len);
			boot_property.boot_tgt.tgt_name = NULL;
			boot_property.boot_tgt.tgt_name_len = 0;
		}
		return (B_FALSE);
	}

	/* Get iscsi target boot partition */
	set = B_FALSE;
	boot_property.boot_tgt.tgt_boot_par = NULL;
	boot_property.boot_tgt.tgt_boot_par_len = 0;
	proplen = BOP_GETPROPLEN(bootops, BP_ISCSI_PAR);
	if (proplen > 0) {
		if (BOP_GETPROP(bootops, BP_ISCSI_PAR, iscsi_par) > 0) {
			boot_property.boot_tgt.tgt_boot_par =
			    (uchar_t *)kmem_zalloc(proplen + 1, KM_SLEEP);
			boot_property.boot_tgt.tgt_boot_par_len = proplen + 1;
			(void) snprintf(
			    (char *)boot_property.boot_tgt.tgt_boot_par,
			    proplen + 1, "%s", iscsi_par);
			set = B_TRUE;
		}
	}
	if (set != B_TRUE) {
		boot_property.boot_tgt.tgt_boot_par =
		    (uchar_t *)kmem_zalloc(2, KM_SLEEP);
		boot_property.boot_tgt.tgt_boot_par_len = 2;
		boot_property.boot_tgt.tgt_boot_par[0] = 'a';
	}

	/* Get CHAP name and secret */
	ret = prom_get_security_key(BP_CHAP_USER, chap_user,
	    ISCSI_OBP_MAX_CHAP_USER_LEN, &chap_user_len, &status);
	if (ret != 0) {
		return (B_FALSE);
	}
	if (status == OBP_GET_KEY_STATUS_NOT_EXIST) {
		/* No chap name */
		return (B_TRUE);
	}
	if (status != OBP_GET_KEY_STATUS_OK ||
	    chap_user_len > ISCSI_OBP_MAX_CHAP_USER_LEN ||
	    chap_user_len <= 0) {
		return (B_FALSE);
	}

	ret = prom_get_security_key(BP_CHAP_PASSWORD, chap_password,
	    ISCSI_OBP_MAX_CHAP_LEN, &chap_pwd_len, &status);
	if (ret != 0) {
		return (B_FALSE);
	}

	if (status == OBP_GET_KEY_STATUS_NOT_EXIST) {
		/* No chap secret */
		return (B_TRUE);
	}
	if (status != OBP_GET_KEY_STATUS_OK ||
	    chap_pwd_len > ISCSI_OBP_MAX_CHAP_LEN ||
	    chap_pwd_len <= 0) {
		return (B_FALSE);
	}

	boot_property.boot_init.ini_chap_name =
	    (uchar_t *)kmem_zalloc(chap_user_len + 1, KM_SLEEP);
	boot_property.boot_init.ini_chap_name_len = chap_user_len + 1;
	(void) memcpy(boot_property.boot_init.ini_chap_name, chap_user,
	    chap_user_len);

	boot_property.boot_init.ini_chap_sec =
	    (uchar_t *)kmem_zalloc(chap_pwd_len + 1, KM_SLEEP);
	boot_property.boot_init.ini_chap_sec_len = chap_pwd_len + 1;
	(void) memcpy(boot_property.boot_init.ini_chap_sec, chap_password,
	    chap_pwd_len);

	return (B_TRUE);
}

static boolean_t
iscsiboot_init_prop_read(void)
{
	int	proplen;
	uchar_t	iscsi_initiator_id[ISCSI_MAX_NAME_LEN];
	boolean_t	set = B_FALSE;

	/* Get initiator node name */
	proplen = BOP_GETPROPLEN(bootops, BP_ISCSI_INITIATOR_ID);
	if (proplen > 0) {
		if (BOP_GETPROP(bootops, BP_ISCSI_INITIATOR_ID,
		    iscsi_initiator_id) > 0) {
			boot_property.boot_init.ini_name =
			    (uchar_t *)kmem_zalloc(proplen + 1, KM_SLEEP);
			boot_property.boot_init.ini_name_len = proplen + 1;
			(void) snprintf(
			    (char *)boot_property.boot_init.ini_name,
			    proplen + 1, "%s", iscsi_initiator_id);
			set = B_TRUE;
		}
	}
	if (set != B_TRUE) {
		generate_iscsi_initiator_id();
	}
	return (B_TRUE);
}

static boolean_t
iscsiboot_nic_prop_read(void)
{
	int	proplen;
	char	host_ip[INET6_ADDRSTRLEN];
	char	router_ip[INET6_ADDRSTRLEN];
	char	subnet_mask[INET6_ADDRSTRLEN];
	uchar_t	iscsi_network_path[MAXPATHLEN];
	char	host_mac[6];
	uchar_t	hex_netmask[4];
	pnode_t	nodeid;
	boolean_t	set = B_FALSE;

	/* Get host IP address */
	proplen = BOP_GETPROPLEN(bootops, BP_HOST_IP);
	if (proplen > 0) {
		if (BOP_GETPROP(bootops, BP_HOST_IP,
		    host_ip) > 0) {
			if (inet_aton(host_ip,
			    (uchar_t *)&boot_property.boot_nic.nic_ip_u) ==
			    0) {
				boot_property.boot_nic.sin_family = AF_INET;
				set = B_TRUE;
			}
		}
	}
	if (set != B_TRUE) {
		return (B_FALSE);
	}

	/* Get router IP address */
	proplen = BOP_GETPROPLEN(bootops, BP_ROUTER_IP);
	if (proplen > 0) {
		if (BOP_GETPROP(bootops, BP_ROUTER_IP,
		    router_ip) > 0) {
			(void) inet_aton(router_ip,
			    (uchar_t *)&boot_property.boot_nic.nic_gw_u);
		}
	}

	/* Get host netmask */
	set = B_FALSE;
	proplen = BOP_GETPROPLEN(bootops, BP_SUBNET_MASK);
	if (proplen > 0) {
		if (BOP_GETPROP(bootops, BP_SUBNET_MASK,
		    subnet_mask) > 0) {
			if (inet_aton(subnet_mask, hex_netmask) == 0) {
				int i = 0;
				uint32_t tmp = *((uint32_t *)hex_netmask);
				while (tmp) {
					i ++;
					tmp = tmp << 1;
				}
				boot_property.boot_nic.sub_mask_prefix = i;
				set = B_TRUE;
			}
		}
	}
	if (set != B_TRUE) {
		boot_property.boot_nic.sub_mask_prefix = 24;
	}

	/* Get iscsi boot NIC path in OBP */
	set = B_FALSE;
	proplen = BOP_GETPROPLEN(bootops, BP_ISCSI_NETWORK_BOOTPATH);
	if (proplen > 0) {
		if (BOP_GETPROP(bootops, BP_ISCSI_NETWORK_BOOTPATH,
		    iscsi_network_path) > 0) {
			nodeid = prom_finddevice((char *)iscsi_network_path);
			proplen = prom_getproplen(nodeid, BP_LOCAL_MAC_ADDRESS);
			if (proplen > 0) {
				if (prom_getprop(nodeid, BP_LOCAL_MAC_ADDRESS,
				    host_mac) > 0) {
					(void) memcpy(
					    boot_property.boot_nic.nic_mac,
					    host_mac, 6);
					set = B_TRUE;
				}
			}
		}
	}
	if (set != B_TRUE) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Manully construct iscsiboot_prop table based on
 * OBP '/chosen' properties related to iscsi boot
 */
void
ld_ib_prop()
{
	if (iscsiboot_prop != NULL)
		return;

	if ((iscsiboot_tgt_prop_read() == B_TRUE) &&
	    (iscsiboot_init_prop_read() == B_TRUE) &&
	    (iscsiboot_nic_prop_read() == B_TRUE)) {
		iscsiboot_prop = &boot_property;
	} else {
		iscsi_boot_prop_free();
	}
}

static boolean_t
parse_lun_num(uchar_t *str_num, uchar_t *hex_num)
{
	char *p, *buf;
	uint16_t *conv_num = (uint16_t *)hex_num;
	long tmp;
	int i = 0;

	if ((str_num == NULL) || (hex_num == NULL)) {
		return (B_FALSE);
	}
	bzero((void *)hex_num, 8);
	buf = (char *)str_num;

	for (i = 0; i < 4; i++) {
		p = NULL;
		p = strchr((const char *)buf, '-');
		if (p != NULL) {
			*p = '\0';
		}
		if (ddi_strtol((const char *)buf, NULL, 16, &tmp) != 0) {
			return (B_FALSE);
		}
		conv_num[i] = (uint16_t)tmp;
		if (p != NULL) {
			buf = p + 1;
		} else {
			break;
		}
	}

	return (B_TRUE);
}

static void
generate_iscsi_initiator_id(void)
{
	boot_property.boot_init.ini_name_len = 38;
	boot_property.boot_init.ini_name =
	    (uchar_t *)kmem_zalloc(boot_property.boot_init.ini_name_len,
	    KM_SLEEP);
	(void) snprintf((char *)boot_property.boot_init.ini_name,
	    38, "iqn.1986-03.com.sun:boot.%02x%02x%02x%02x%02x%02x",
	    boot_property.boot_nic.nic_mac[0],
	    boot_property.boot_nic.nic_mac[1],
	    boot_property.boot_nic.nic_mac[2],
	    boot_property.boot_nic.nic_mac[3],
	    boot_property.boot_nic.nic_mac[4],
	    boot_property.boot_nic.nic_mac[5]);
}


/* We only deal with a.b.c.d decimal format. ip points to 4 byte storage */
static int
inet_aton(char *ipstr, uchar_t *ip)
{
	int i = 0;
	uchar_t val[4] = {0};
	char c = *ipstr;

	for (;;) {
		if (!isdigit(c))
			return (-1);
		for (;;) {
			if (!isdigit(c))
				break;
			val[i] = val[i] * 10 + (c - '0');
			c = *++ipstr;
		}
		i++;
		if (i == 4)
			break;
		if (c != '.')
			return (-1);
		c = *++ipstr;
	}
	if (c != 0)
		return (-1);
	bcopy(val, ip, 4);
	return (0);
}
