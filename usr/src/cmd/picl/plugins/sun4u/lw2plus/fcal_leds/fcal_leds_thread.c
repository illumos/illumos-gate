/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <libintl.h>
#include <libdevinfo.h>
#include <syslog.h>
#include <sys/i2c/clients/i2c_client.h>
#include <poll.h>
#include "fcal_leds.h"

static char fcal_disk_unit[] = FCAL_PICL_DISK_UNIT;

static int update_picl(led_dtls_t *dtls, int disk);
static int get_drv_info(di_node_t node, led_dtls_t *dtls);
static int walk_disks(di_node_t node, led_dtls_t *dtls);
static int chk_minors(led_dtls_t *dtls);
static void set_led(int diskNo, token_t led_tok, led_dtls_t *dtls);
static int set_clr_led(int diskNo, token_t led_tok, led_dtls_t *dtls, int set);
void set_led(int diskNo, token_t led_tok, led_dtls_t *dtls);
void clr_led(int diskNo, token_t led_tok, led_dtls_t *dtls);
static void retry_led(led_dtls_t *dtls);
static void start_led_test(led_dtls_t *dtls, int disk);
static void end_led_test(led_dtls_t *dtls, int disk);
static int wait_a_while(void);

/*
 * variant of strerror() which guards against negative errno and null strings
 */
char *
mystrerror(int err)
{
	static char *unknown_errno = "unknown errno";
	char *ptr;

	if ((err < 0) || ((ptr = strerror(err)) == NULL)) {
		ptr = unknown_errno;
	}
	return (ptr);
}

void
delete_disk_unit(led_dtls_t *dtls, int disk)
{
	int			r;
	picl_nodehdl_t		slotndh;
	picl_nodehdl_t		diskndh;

	r = find_disk_slot(dtls, disk, &slotndh);
	if (r != PICL_SUCCESS)
		return;

	/*
	 * is there a disk-unit node here?
	 */
	r = ptree_find_node(slotndh, PICL_PROP_NAME,
	    PICL_PTYPE_CHARSTRING, fcal_disk_unit,
	    sizeof (fcal_disk_unit), &diskndh);
	if (r != PICL_SUCCESS)
		return;

	/*
	 * remove disk-unit node and its properties
	 */
	r = ptree_delete_node(diskndh);
	if (r != PICL_SUCCESS)
		return;
	(void) ptree_destroy_node(diskndh);
}

/*
 * update_picl
 * Called when disk goes off-line or goes to ready status.
 * In the case of disk ready, locate platform tree node for the disk
 * and add a target property (if missing).
 * (The target address is fixed for a given disk slot and is used to
 * tie the frutree disk-unit to the correct ssd node).
 * Returns EAGAIN for a retriable failure, otherwise 0.
 */
static int
update_picl(led_dtls_t *dtls, int disk)
{
	static char		trailer[] = ",0";
	picl_nodehdl_t		slotndh;
	picl_nodehdl_t		diskndh;
	ptree_propinfo_t	propinfo;
	int			r;

	if (dtls->disk_detected[disk] != 0) {
		picl_nodehdl_t		fpndh;
		picl_nodehdl_t		ssdndh;
		picl_prophdl_t		tbl_h;
		picl_prophdl_t		tbl_prop_h;
		picl_prophdl_t		row_props_h[FCAL_DEVTABLE_NCOLS];
		char			valbuf[80];
		char			addr[MAXPATHLEN];
		char			*ptrd;
		const uchar_t		*ptrs;
		int			len;
		int			addr_len;

		for (;;) {
			r = ptree_get_node_by_path(dtls->fcal_disk_parent,
			    &fpndh);
			if (r != PICL_SUCCESS) {
				return (0);
			}
			r = ptree_get_propval_by_name(fpndh,
			    PICL_PROP_CLASSNAME, (void *)valbuf,
			    sizeof (valbuf));
			if (r != PICL_SUCCESS) {
				return (0);
			} else if (strcmp(valbuf, "fp") == 0) {
				/*
				 * The node with class fp (if present) is a
				 * holding node representing no actual hardware.
				 * Its presence results in two nodes with the
				 * same effective address. (The fp class node is
				 * UnitAddress 0,0 and the other fp node [class
				 * devctl] has bus-addr 0,0). Locating the
				 * required fp node for dynamic reconfiguration
				 * then goes wrong. So, just remove it.
				 */
				SYSLOG(LOG_WARNING, EM_SPURIOUS_FP);
				r = ptree_delete_node(fpndh);
				if (r == PICL_SUCCESS) {
					(void) ptree_destroy_node(fpndh);
					continue;
				}
				return (0);
			} else {
				break;
			}
		}
		/*
		 * Got a good parent node. Look at its children for a node
		 * with this new port name.
		 *
		 * generate expected bus-addr property from the port-wwn
		 * Note: dtls->disk_port[disk] points to an array of uchar_t,
		 * the first character contains the length of the residue.
		 * The bus-addr property is formatted as follows:
		 *	wabcdef0123456789,0
		 * where the 16 hex-digits represent 8 bytes from disk_port[];
		 */
		ptrs = dtls->disk_port[disk];
		if (ptrs == NULL)
			return (0);
		len = *ptrs++;
		ptrd = addr;
		*ptrd++ = 'w';
		for (r = 0; r < len; r++, ptrd += 2) {
			(void) snprintf(ptrd, MAXPATHLEN - (ptrd - addr),
			    "%.2x", *ptrs++);
		}
		addr_len = 1 + strlcat(addr, trailer, MAXPATHLEN);
		if (addr_len > MAXPATHLEN)
			return (0);
		r = ptree_find_node(fpndh, FCAL_PICL_PROP_BUS_ADDR,
		    PICL_PTYPE_CHARSTRING, addr, addr_len, &ssdndh);
		/*
		 * If the disk node corresponding to the newly inserted disk
		 * cannot be found in the platform tree, we have probably
		 * got in too early - probably before it's up to speed. In
		 * this case, the WWN gleaned from devinfo may also be wrong.
		 * This case is worth retrying in later polls when it may
		 * succeed, so return EAGAIN. All other failures are probably
		 * terminal, so log a failure and quit.
		 */
		if (r == PICL_NODENOTFOUND)
			return (EAGAIN);
		if (r != PICL_SUCCESS) {
			SYSLOG(LOG_ERR, EM_NO_FP_NODE, disk);
			return (0);
		}

		/*
		 * Found platform entry for disk, add target prop
		 */
		r = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_INT, PICL_READ, sizeof (int),
		    FCAL_PICL_PROP_TARGET, NULL, NULL);
		if (r != PICL_SUCCESS)
			return (0);
		(void) ptree_create_and_add_prop(ssdndh, &propinfo, &disk,
		    NULL);

		/*
		 * Remove pre-existing disk-unit node and its
		 * properties - maybe its reference property is
		 * out-of-date.
		 */
		delete_disk_unit(dtls, disk);

		/*
		 * Add a disk-unit node in frutree
		 */
		r = find_disk_slot(dtls, disk, &slotndh);
		if (r != PICL_SUCCESS)
			return (0);
		r = ptree_create_and_add_node(slotndh, fcal_disk_unit,
		    PICL_CLASS_FRU, &diskndh);
		if (r != PICL_SUCCESS)
			return (0);
		r = create_Device_table(&tbl_h, &tbl_prop_h);
		if (r != PICL_SUCCESS)
			return (0);
		r = ptree_init_propinfo(&propinfo,
		    PTREE_PROPINFO_VERSION, PICL_PTYPE_CHARSTRING,
		    PICL_READ, sizeof (PICL_CLASS_BLOCK), PICL_PROP_CLASS,
		    NULL, NULL);
		if (r != PICL_SUCCESS)
			return (0);
		r = ptree_create_prop(&propinfo, PICL_CLASS_BLOCK,
		    &row_props_h[0]);
		if (r != PICL_SUCCESS)
			return (0);
		r = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_REFERENCE, PICL_READ, sizeof (picl_prophdl_t),
		    FCAL_PICL_BLOCK_REF, NULL, NULL);
		if (r != PICL_SUCCESS)
			return (0);
		r = ptree_create_prop(&propinfo, &ssdndh, &row_props_h[1]);
		if (r != PICL_SUCCESS)
			return (0);
		r = ptree_add_row_to_table(tbl_h, FCAL_DEVTABLE_NCOLS,
		    row_props_h);
		if (r != PICL_SUCCESS)
			return (0);
		(void) ptree_add_prop(diskndh, tbl_prop_h);
	} else {
		/*
		 * disk gone, remove disk_unit fru from frutree
		 */
		delete_disk_unit(dtls, disk);
	}
	return (0);
}

static int
get_drv_info(di_node_t node, led_dtls_t *dtls)
{
	int *target_data;
	uchar_t *port_data = NULL;
	di_minor_t min_node;
	int i, r;
	int t = -1;
	int *newStatus = malloc(dtls->n_disks * sizeof (int));
	if (newStatus == NULL)
		return (0);

	for (i = 0; i < dtls->n_disks; i++) {
		newStatus[i] = MINORS_UNKNOWN;
	}
	r = di_prop_lookup_ints(DDI_DEV_T_ANY, node, HW_PROP_TARGET,
	    &target_data);
	for (i = 0; i < r; i++) {
		t = target_data[i];
		if ((t >= 0) && (t < dtls->n_disks)) {
			/* set no minors until we know */
			newStatus[t] = NO_MINORS;
			break;			/* go with this node */
		}
	}
	if ((t >= 0) && (t < dtls->n_disks)) {
		r = di_prop_lookup_bytes(
		    DDI_DEV_T_ANY, node, HW_PROP_PORT, &port_data);
		/*
		 * The first byte of the array dtls->disk_port[t] contains
		 * the length of the residue. So 255 is the maximum length
		 * which can be handled. Limit the property data to this.
		 */
		if (r > 255) {
			r = 0;
		}
		if ((r > 0) && (port_data != NULL)) {
			if ((dtls->disk_port[t] != NULL) &&
			    (*(dtls->disk_port[t]) != r)) {
				/*
				 * existing data is of different length,
				 * free it and malloc a fresh array.
				 */
				free(dtls->disk_port[t]);
				dtls->disk_port[t] = NULL;
			}
			if (dtls->disk_port[t] == NULL) {
				dtls->disk_port[t] = malloc(r + 1);
			}
			if (dtls->disk_port[t] != NULL) {
				*(dtls->disk_port[t]) = (uchar_t)r;
				(void) memcpy(dtls->disk_port[t] + 1,
				    port_data, r);
			}
		}
		min_node = di_minor_next(node, DI_MINOR_NIL);
		if (min_node != DI_MINOR_NIL) {
			/*
			 * device has minor device node(s)
			 */
			newStatus[t] = HAS_MINORS;	/* got minor(s) */
		}
	}
	/*
	 * propagate attachment status and note changes
	 * don't propagate to absent disks, otherwise we may not detect a
	 * status change when they're replugged.
	 */
	r = 0;
	for (i = 0; i < dtls->n_disks; i++) {
		if ((newStatus[i] != MINORS_UNKNOWN) &&
		    dtls->disk_detected[i] &&
		    (dtls->disk_ready[i] != newStatus[i])) {
			dtls->disk_ready[i] = newStatus[i];
			r = 1;
		}
	}
	free(newStatus);
	return (r);
}

/*
 * Nodes belonging to the configured driver (dtls->fcal_driver) are
 * located in the device tree. A check is applied that any node found has
 * a physical address beginning with the configured search string
 * (dtls->fcal_disk_parent). For each suitable node found, get_drv_info()
 * is called to determine if a change of status has occurred.
 * Returns 1 if any status has changed - else 0.
 */
static int
walk_disks(di_node_t node, led_dtls_t *dtls)
{
	static char *sl_platform_sl = "/platform/";
	int r = 0;
	int len;
	/* find "/platform/" */
	char *ptr = strstr(dtls->fcal_disk_parent, sl_platform_sl);

	if (ptr == NULL)
		return (0);
	/* skip over "/platform" */
	ptr += strlen(sl_platform_sl) - 1;
	len = strlen(ptr);

	for (node = di_drv_first_node(dtls->fcal_driver, node);
	    node != DI_NODE_NIL;
	    node = di_drv_next_node(node)) {
		char *dev_path = di_devfs_path(node);

		if (dev_path == NULL) {
			/* no memory, just hope things get better */
			continue;
		}
		if (memcmp(dev_path, ptr, len) != 0) {
			/*
			 * path name doesn't start right, skip this one
			 */
			free(dev_path);
			continue;
		}
		free(dev_path);
		if (get_drv_info(node, dtls) != 0) {
			r = 1;	/* change observed */
		}
	}

	return (r);
}

static int
chk_minors(led_dtls_t *dtls)
{
	/*
	 * sets disk_ready flags for disks with minor devices (attached)
	 * returns 1 if any flags have changed else 0
	 */
	int err = 0;
	int r = 0;
	di_node_t tree = di_init("/", DINFOCPYALL);
	if (tree == DI_NODE_NIL) {
		err = errno;
		SYSLOG(LOG_ERR, EM_DI_INIT_FAIL, mystrerror(err));
	}
	if (err == 0)
		r = walk_disks(tree, dtls);
	if (tree != DI_NODE_NIL)
		di_fini(tree);
	return (r);
}

boolean_t
is_led_test(led_dtls_t *dtls)
{
	int disk;
	for (disk = 0; disk < dtls->n_disks; disk++) {
		if (dtls->led_test_end[disk] != 0)
			return (B_TRUE);
	}
	return (B_FALSE);
}

static int
set_clr_led(int diskNo, token_t led_tok, led_dtls_t *dtls, int set)
{
	int err, led, disk, led_bit;
	i2c_port_t port;
	int mask = 0;
	int fd = open(dtls->fcal_leds, O_RDWR);
	if (fd < 0)
		return (0);
	/*
	 * generate a mask for all controlled LEDs
	 */
	for (led = 0; led < FCAL_LED_CNT; led++) {
		for (disk = 0; disk < dtls->n_disks; disk++) {
			mask |= dtls->led_addr[led][disk];
		}
	}
	port.value = 0;
	port.direction = DIR_INPUT;
	port.dir_mask = (uint8_t)mask;
	/* read current light settings */
	err = ioctl(fd, I2C_GET_PORT, &port);
	if (err < 0) {
		(void) close(fd);
		return (EAGAIN);
	}
	mask = port.value;
	/*
	 * get bit setting for led to be changed
	 */
	led = led_tok - LED_PROPS_START - 1;
	led_bit = dtls->led_addr[led][diskNo];
	if (dtls->assert_led_on == 0) {
		if (set == 0)
			mask |= led_bit;
		else
			mask &= ~led_bit;
	} else {
		if (set == 0)
			mask &= ~led_bit;
		else
			mask |= led_bit;
	}

	/*
	 * re-write the leds
	 */
	port.value = (uint8_t)mask;
	err = ioctl(fd, I2C_SET_PORT, &port);
	(void) close(fd);
	if (err == 0)
		return (0);
	return (EAGAIN);
}

static void
set_led(int diskNo, token_t led_tok, led_dtls_t *dtls)
{
	if (set_clr_led(diskNo, led_tok, dtls, 1) != 0)
		dtls->led_retry = B_TRUE;
	dtls->led_state[led_tok - LED_PROPS_START - 1][diskNo] =
	    ((dtls->led_test_end[diskNo] != 0) ?
	    LED_STATE_TEST : LED_STATE_ON);
}

void
clr_led(int diskNo, token_t led_tok, led_dtls_t *dtls)
{
	if (set_clr_led(diskNo, led_tok, dtls, 0) != 0)
		dtls->led_retry = B_TRUE;
	dtls->led_state[led_tok - LED_PROPS_START - 1][diskNo] =
	    LED_STATE_OFF;
}

/*
 * have another go at getting the leds in step with required values
 */
static void
retry_led(led_dtls_t *dtls)
{
	int		r = 0;
	int		onFlag;
	int		diskNo;
	int		ledNo;
	led_state_t	state;

	for (diskNo = 0; diskNo < dtls->n_disks; diskNo++) {
		for (ledNo = 0; ledNo < FCAL_LED_CNT; ledNo++) {
			state = dtls->led_state[ledNo][diskNo];
			if ((state == LED_STATE_ON) ||
			    (state == LED_STATE_TEST))
				onFlag = 1;
			else
				onFlag = 0;
			r |= set_clr_led(diskNo, LED_PROPS_START + 1 + ledNo,
			    dtls, onFlag);
		}
	}

	dtls->led_retry = (r != 0);
}

static void
start_led_test(led_dtls_t *dtls, int disk)
{
	int			led_no;

	/*
	 * if the poll thread has failed, can't do led test
	 */
	if (!dtls->polling)
		return;

	/*
	 * set test interval - doubles as flag for LED-test in progress
	 */
	dtls->led_test_end[disk] = dtls->led_test_time;
	for (led_no = 1; led_no <= FCAL_LED_CNT; led_no++) {
		set_led(disk, LED_PROPS_START + led_no, dtls);
	}
}

static void
end_led_test(led_dtls_t *dtls, int disk)
{
	/*
	 * There is a problem with a disk coming on-line.
	 * All its leds are lit for 10 seconds to meet the led-test
	 * requirement. The true state for the fault led can be determined
	 * immediately, but determination of whether to light blue or green
	 * requires a response from libdevinfo. Device reconfiguration logic
	 * (likely to be active at this time) holds a long term
	 * lock preventing devinfo calls from completing. Rather than
	 * leave a contradictory led indication showing during this
	 * period, it is better to anticipate the green led result
	 * and correct it when the facts are known.
	 */
	clr_led(disk, FCAL_REMOK_LED, dtls);
	clr_led(disk, FCAL_FAULT_LED, dtls);
	dtls->led_state[FCAL_READY_LED - LED_PROPS_START - 1][disk] =
	    LED_STATE_ON;
}

/*
 * Evaluate required wait time and wait until that time or an event.
 * Returns 0 for a time-out, otherwise the pending event(s).
 * If the finish_now flag is becomes set, this routine acknowledges
 * the request and waits for it to go away,
 * i.e. no return while finish_now is set.
 */
static int
wait_a_while(void)
{
	int	r;
	int	events;
	boolean_t acksent = B_FALSE;

	do {
		r = pthread_mutex_lock(&g_mutex);
		if (r != 0) {
			SYSLOG(LOG_ERR, EM_MUTEX_FAIL, mystrerror(r));
			return (0);
		}
		if (g_finish_now && !acksent) {
			g_leds_thread_ack = B_TRUE;
			(void) pthread_cond_signal(&g_cv_ack);
			acksent = B_TRUE;
		}
		r = pthread_cond_wait(&g_cv, &g_mutex);
		if (r != 0) {
			SYSLOG(LOG_ERR, EM_CONDWAITFAIL, mystrerror(r));
			(void) pthread_mutex_unlock(&g_mutex);
			return (0);
		}
		/*
		 * whilst under the mutex, take a local copy of the events
		 * and clear those that we handle
		 */
		events = g_event_flag & (FCAL_EV_POLL | FCAL_EV_CONFIG);
		g_event_flag ^= events;
		(void) pthread_mutex_unlock(&g_mutex);
	} while (g_finish_now);

	return (events);
}

/*ARGSUSED*/
void *
fcal_leds_thread(void *args)
{
	led_dtls_t *dtls = g_led_dtls;
	int c, v;
	int err = 0;
	int events = 0;
	int fd_bkplane;
	i2c_port_t port;
	int lastVal = I2C_IOCTL_INIT;
	int ws;
	int mask;

	/*
	 * generate a mask for presence and fault status bits
	 */
	mask = 0;
	for (c = 0; c < dtls->n_disks; c++) {
		mask |= dtls->presence[c];
		mask |= dtls->faults[c];
	}

	/*
	 * enter poll loop
	 */
	for (;;) {
		/*
		 * see if a LED-test timer has expired
		 */
		for (c = 0; c < dtls->n_disks; c++) {
			if (dtls->led_test_end[c] > 0) {
				if (!dtls->polling) {
					/* poll thread failure, end led-test */
					dtls->led_test_end[c] = 0;
				} else if ((events & FCAL_EV_POLL) != 0) {
					dtls->led_test_end[c]--;
				}
				if (dtls->led_test_end[c] == 0) {
					/*
					 * clear blue and amber leds
					 */
					end_led_test(dtls, c);
					/* treat any status as a change */
					lastVal = I2C_IOCTL_INIT;
				}
			}
		}
		fd_bkplane = open(dtls->fcal_status, O_RDONLY);
		if (fd_bkplane < 0) {
			SYSLOG(LOG_ERR, EM_CANT_OPEN, dtls->fcal_status);
			err = errno;
			break;
		}
		port.value = 0;
		/*
		 * the direction and dir_mask fields are ignored,
		 * so one can only guess at their possible use
		 */
		port.direction = DIR_INPUT;
		port.dir_mask = (uint8_t)mask;
		c = ioctl(fd_bkplane, I2C_GET_PORT, &port);
		if (c < 0) {
			err = errno;
			(void) close(fd_bkplane);

			if (lastVal != I2C_IOCTL_FAIL) {
				SYSLOG(LOG_ERR, EM_I2C_GET_PORT,
				    mystrerror(err));
				lastVal = I2C_IOCTL_FAIL;
				events |= FCAL_EV_CONFIG;
			}
		} else {
			(void) close(fd_bkplane);
			ws = port.value & mask;
		}

		if ((c == 0) && (ws != lastVal)) {
			events |= FCAL_EV_CONFIG;
			lastVal = ws;
			for (c = 0; c < dtls->n_disks; c++) {
				/*
				 * first get the value of the relevant
				 * presence bit (as 0 or 1)
				 */
				v = ((lastVal & dtls->presence[c]) != 0);

				/* hold previous presence value */
				ws = dtls->disk_detected[c];

				/*
				 * the disk is present if the backplane
				 * status bit for this disk is equal to the
				 * configured assert_presence value
				 */
				dtls->disk_detected[c] =
				    (v == dtls->assert_presence);
				/*
				 * Don't add disk-unit node here for
				 * newly arrived disks. While the led
				 * test is running (and beyond)
				 * libdevinfo is locked out and we
				 * can't get port or target info.
				 */
				if ((!ws) && dtls->disk_detected[c]) {
					/*
					 * disk has just come on-line
					 */
					start_led_test(dtls, c);
				}
				/*
				 * clear leds and ready status
				 * for disks which have been removed
				 */
				if (ws && (!dtls->disk_detected[c])) {
					clr_led(c, FCAL_REMOK_LED, dtls);
					clr_led(c, FCAL_FAULT_LED, dtls);
					clr_led(c, FCAL_READY_LED, dtls);
					dtls->disk_ready[c] = NO_MINORS;
					dtls->disk_prev[c] = NO_MINORS;
					v = update_picl(dtls, c);
					/*
					 * set or clear retry flag
					 */
					dtls->picl_retry[c] = (v == EAGAIN);
				}
				/*
				 * for present disks which are not doing a
				 * led test, adjust fault LED
				 */
				if ((dtls->led_test_end[c] != 0) ||
				    (!dtls->disk_detected[c]))
					continue;
				v = ((lastVal & dtls->faults[c]) != 0);
				if (v == dtls->assert_fault)
					set_led(c, FCAL_FAULT_LED, dtls);
				else
					clr_led(c, FCAL_FAULT_LED, dtls);
			}
		}

		/*
		 * For detected disks whose status has changed, choose between
		 * ready and ok to remove.
		 * libdevinfo can be locked out for the entire duration of a
		 * disk spin-up. So it is best not to seek this info while
		 * a led-test is in progress. Otherwise the leds can be stuck
		 * on for about 40 seconds.
		 * Note that chk_minors() returns 0 unless a status change
		 * has occurred.
		 */
		if (!is_led_test(dtls) && chk_minors(dtls) != 0) {
			events = FCAL_EV_CONFIG;
			for (c = 0; c < dtls->n_disks; c++) {
				if (!dtls->disk_detected[c])
					continue;
				/*
				 * When disk_ready changes, disk_prev is set
				 * to its previous value. This allows the
				 * direction of the last transistion to be
				 * determined.
				 */
				if ((dtls->disk_prev[c] == HAS_MINORS) &&
				    (dtls->disk_ready[c] == NO_MINORS)) {
					clr_led(c, FCAL_READY_LED, dtls);
					set_led(c, FCAL_REMOK_LED, dtls);
				} else {
					set_led(c, FCAL_READY_LED, dtls);
					clr_led(c, FCAL_REMOK_LED, dtls);
				}
			}
		}
		/*
		 * Update PICL (disk-unit) for newly attached disks
		 * ** see note in header file for significance
		 *    of disk_prev and disk_ready flags.
		 */
		for (c = 0; c < dtls->n_disks; c++) {
			if ((dtls->disk_prev[c] == NO_MINORS) &&
			    (dtls->disk_ready[c] == HAS_MINORS)) {
				dtls->disk_prev[c] = HAS_MINORS;
				v = update_picl(dtls, c);
				/*
				 * set or clear retry flag
				 */
				dtls->picl_retry[c] = (v == EAGAIN);
			}
		}
		if ((events & FCAL_EV_CONFIG) != 0) {
			/*
			 * set fast polling
			 */
			dtls->fast_poll_end = dtls->relax_time_ticks;
		}
		/*
		 * if updating a led failed (e.g. I2C busy), try again
		 */
		if (dtls->led_retry)
			retry_led(dtls);

		events = wait_a_while();

		/*
		 * when picl is recycled, wait_a_while sleeps until the
		 * init routine has been called again.
		 * This is the moment when dtls may have become stale.
		 */
		if (dtls != g_led_dtls) {
			dtls = g_led_dtls;
			lastVal = I2C_IOCTL_INIT;

			/*
			 * re-generate the presence and fault status mask
			 * in case the .conf file has changed
			 */
			mask = 0;
			for (c = 0; c < dtls->n_disks; c++) {
				mask |= dtls->presence[c];
				mask |= dtls->faults[c];
			}
		}

		/*
		 * count down relaxation time counter if a poll event
		 */
		if ((events & FCAL_EV_POLL) != 0) {
			if (dtls->fast_poll_end > 0)
				dtls->fast_poll_end--;
		}

		/*
		 * if updating PICL needs retrying, try it now
		 */
		for (c = 0; c < dtls->n_disks; c++) {
			if (dtls->picl_retry[c]) {
				v = update_picl(dtls, c);
				dtls->picl_retry[c] = (v == EAGAIN);
			}
		}
	}

	return ((void *)err);
}
