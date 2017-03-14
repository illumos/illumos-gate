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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This module performs two functions.  First, it kicks off the driver loading
 * of the console devices during boot in dynamic_console_config().
 * The loading of the drivers for the console devices triggers the
 * additional device autoconfiguration to link the drivers into the keyboard
 * and mouse console streams.
 *
 * The second function of this module is to provide the dacf functions
 * to be called after a driver has attached and before it detaches.  For
 * example, a driver associated with the keyboard will have kb_config called
 * after the driver attaches and kb_unconfig before it detaches.  Similar
 * configuration actions are performed on behalf of minor nodes representing
 * mice.  The configuration functions for the attach case take a module
 * name as a parameter.  The module is pushed on top of the driver during
 * the configuration.
 *
 * Although the dacf framework is used to configure all keyboards and mice,
 * its primary function is to allow keyboard and mouse hotplugging.
 *
 * This module supports multiple keyboards and mice at the same time.
 *
 * From the kernel perspective, there are roughly three different possible
 * console configurations.  Across these three configurations, the following
 * elements are constant:
 * 	wsconsvp = IWSCN_PATH
 * 	rwsconsvp = WC_PATH
 * 	consms -> msdev
 *
 * The "->" syntax indicates that the streams device on the right is
 * linked under the streams device on the left.
 *
 * The following lists how the system is configured for different setups:
 *
 * stdin is a local keyboard.  use stdin and stdout as the console.
 * 	sp->cons_input_type = CONSOLE_LOCAL
 *	rconsvp = IWSCN_PATH
 *	wc -> conskbd -> kbddev
 *
 * stdin is not a keyboard and stdin is the same as stdout.
 * assume we running on a tip line and use stdin/stdout as the console.
 * 	sp->cons_input_type = CONSOLE_TIP
 *	rconsvp = (stdindev/stdoutdev)
 *	wc -> conskbd -> kbddev
 *
 * stdin is not a keyboard device and it's not the same as stdout.
 * assume we have a serial keyboard hooked up and use it along with
 * stdout as the console.
 * 	sp->cons_input_type = CONSOLE_SERIAL_KEYBOARD
 *	rconsvp = IWSCN_PATH
 *	wc -> stdindev
 *	conskbd -> kbddev
 *
 * CAVEAT:
 * 	The above is all true except for one possible Intel configuration.
 * 	If stdin is set to a local keyboard but stdout is set to something
 * 	other than the local display (a tip port for example) stdout will
 * 	still go to the local display.  This is an artifact of the console
 * 	implementation on intel.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>

#include <sys/consdev.h>
#include <sys/console.h>
#include <sys/wscons.h>
#include <sys/kbio.h>
#include <sys/debug.h>
#include <sys/reboot.h>
#include <sys/termios.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/modctl.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_implfuncs.h>
#include <sys/promif.h>
#include <sys/fs/snode.h>

#include <sys/errno.h>
#include <sys/devops.h>
#include <sys/note.h>

#include <sys/tem_impl.h>
#include <sys/polled_io.h>
#include <sys/kmem.h>
#include <sys/dacf.h>
#include <sys/consconfig_dacf.h>
#include <sys/consplat.h>
#include <sys/log.h>
#include <sys/disp.h>

/*
 * External global variables
 */
extern vnode_t		*rconsvp;
extern dev_t		rwsconsdev;

/*
 * External functions
 */
extern uintptr_t	space_fetch(char *key);
extern int		space_store(char *key, uintptr_t ptr);

/*
 * Tasks
 */
static int	kb_config(dacf_infohdl_t, dacf_arghdl_t, int);
static int	kb_unconfig(dacf_infohdl_t, dacf_arghdl_t, int);
static int	ms_config(dacf_infohdl_t, dacf_arghdl_t, int);
static int	ms_unconfig(dacf_infohdl_t, dacf_arghdl_t, int);

/*
 * Internal functions
 */
static int	consconfig_setmodes(dev_t dev, struct termios *termiosp);
static void	consconfig_check_phys_kbd(cons_state_t *);
static void	consconfig_rem_dev(cons_state_t *, dev_t);
static void	consconfig_add_dev(cons_state_t *, cons_prop_t *);
static cons_prop_t *consconfig_find_dev(cons_state_t *, dev_t);
static void	consconfig_free_prop(cons_prop_t *prop);
static void	flush_deferred_console_buf(void);


/*
 * On supported configurations, the firmware defines the keyboard and mouse
 * paths.  However, during USB development, it is useful to be able to use
 * the USB keyboard and mouse on machines without full USB firmware support.
 * These variables may be set in /etc/system according to a machine's
 * USB configuration.  This module will override the firmware's values
 * with these.
 *
 * NOTE:
 * The master copies of these variables in the misc/consconfig module.
 * The reason for this is historic.  In versions of solaris up to and
 * including solaris 9 the conscole configuration code was split into a
 * seperate sparc and intel version.  These variables were defined
 * in misc/consconfig on sparc and dacf/consconfig_dacf on intel.
 *
 * Unfortunatly the sparc variables were well documented.
 * So to aviod breaking either sparc or intel we'll declare the variables
 * in both modules.  This will allow any /etc/system entries that
 * users may have to continue working.
 *
 * The variables in misc/consconfig will take precedence over the variables
 * found in this file.  Since we eventually want to remove the variables
 * local to this this file, if the user set them we'll emmit an error
 * message telling them they need to set the variables in misc/consconfig
 * instead.
 */
static char *usb_kb_path = NULL;
static char *usb_ms_path = NULL;

/*
 * Access functions in the misc/consconfig module used to retrieve the
 * values of it local usb_kb_path and usb_ms_path variables
 */
extern char *consconfig_get_usb_kb_path();
extern char *consconfig_get_usb_ms_path();

/*
 * Local variables used to store the value of the usb_kb_path and
 * usb_ms_path variables found in misc/consconfig
 */
static char *consconfig_usb_kb_path = NULL;
static char *consconfig_usb_ms_path = NULL;

/*
 * Internal variables
 */
static dev_t		stdoutdev;
static cons_state_t	*consconfig_sp;

/*
 * consconfig_errlevel:  debug verbosity; smaller numbers are more
 * verbose.
 */
int consconfig_errlevel = DPRINT_L3;

/*
 * Baud rate table
 */
static struct speed {
	char *name;
	int code;
} speedtab[] = {
	{"0", B0},		{"50", B50},		{"75", B75},
	{"110", B110},		{"134", B134},		{"150", B150},
	{"200", B200},		{"300", B300},		{"600", B600},
	{"1200", B1200},	{"1800", B1800},	{"2400", B2400},
	{"4800", B4800},	{"9600", B9600},	{"19200", B19200},
	{"38400", B38400},	{"57600", B57600},	{"76800", B76800},
	{"115200", B115200},	{"153600", B153600},	{"230400", B230400},
	{"307200", B307200},	{"460800", B460800},	{"921600", B921600},
	{"", 0}
};

static const int MAX_SPEEDS = sizeof (speedtab) / sizeof (speedtab[0]);

static dacf_op_t kbconfig_op[] = {
	{ DACF_OPID_POSTATTACH,	kb_config },
	{ DACF_OPID_PREDETACH,	kb_unconfig },
	{ DACF_OPID_END,	NULL },
};

static dacf_op_t msconfig_op[] = {
	{ DACF_OPID_POSTATTACH,	ms_config },
	{ DACF_OPID_PREDETACH,	ms_unconfig },
	{ DACF_OPID_END,	NULL },
};

static dacf_opset_t opsets[] = {
	{ "kb_config",	kbconfig_op },
	{ "ms_config",	msconfig_op },
	{ NULL,		NULL }
};

struct dacfsw dacfsw = {
	DACF_MODREV_1,
	opsets,
};

static struct modldacf modldacf = {
	&mod_dacfops,   /* Type of module */
	"Consconfig DACF",
	&dacfsw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldacf, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	/*
	 * This modules state is held in the kernel by space.c
	 * allowing this module to be unloaded.
	 */
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*PRINTFLIKE2*/
static void consconfig_dprintf(int, const char *, ...)
    __KPRINTFLIKE(2);

static void
consconfig_dprintf(int l, const char *fmt, ...)
{
	va_list ap;

#ifndef DEBUG
	if (!l) {
		return;
	}
#endif /* DEBUG */
	if (l < consconfig_errlevel) {
		return;
	}

	va_start(ap, fmt);
	(void) vprintf(fmt, ap);
	va_end(ap);
}

/*
 * Return a property value for the specified alias in /aliases.
 */
char *
get_alias(char *alias, char *buf)
{
	pnode_t node;
	int len;

	/* The /aliases node only exists in OBP >= 2.4. */
	if ((node = prom_alias_node()) == OBP_BADNODE)
		return (NULL);

	if ((len = prom_getproplen(node, (caddr_t)alias)) <= 0)
		return (NULL);

	(void) prom_getprop(node, (caddr_t)alias, (caddr_t)buf);

	/*
	 * The IEEE 1275 standard specifies that /aliases string property
	 * values should be null-terminated.  Unfortunatly the reality
	 * is that most aren't and the OBP can't easily be modified to
	 * add null termination to these strings.  So we'll add the
	 * null termination here.  If the string already contains a
	 * null termination character then that's ok too because we'll
	 * just be adding a second one.
	 */
	buf[len] = '\0';

	prom_pathname(buf);
	return (buf);
}

/*
 * i_consconfig_createvp:
 *	This routine is a convenience routine that is passed a path and returns
 *	a vnode.
 */
static vnode_t *
i_consconfig_createvp(char *path)
{
	int error;
	vnode_t *vp;
	char *buf = NULL, *fullpath;

	DPRINTF(DPRINT_L0, "i_consconfig_createvp: %s\n", path);
	fullpath = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	if (strchr(path, ':') == NULL) {
		/* convert an OBP path to a /devices path */
		buf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		if (i_ddi_prompath_to_devfspath(path, buf) != DDI_SUCCESS) {
			kmem_free(buf, MAXPATHLEN);
			kmem_free(fullpath, MAXPATHLEN);
			return (NULL);
		}
		(void) snprintf(fullpath, MAXPATHLEN, "/devices%s", buf);
		kmem_free(buf, MAXPATHLEN);
	} else {
		/* convert a devfs path to a /devices path */
		(void) snprintf(fullpath, MAXPATHLEN, "/devices%s", path);
	}

	DPRINTF(DPRINT_L0, "lookupname(%s)\n", fullpath);
	error = lookupname(fullpath, UIO_SYSSPACE, FOLLOW, NULLVPP, &vp);
	kmem_free(fullpath, MAXPATHLEN);
	if (error)
		return (NULL);

	DPRINTF(DPRINT_L0, "create vnode = 0x%p - dev 0x%lx\n", vp, vp->v_rdev);
	ASSERT(vn_matchops(vp, spec_getvnodeops()));

	return (vp);
}

/*
 * consconfig_print_paths:
 *	Function to print out the various paths
 */
static void
consconfig_print_paths(void)
{
	char    *path;

	if (usb_kb_path != NULL)
		cmn_err(CE_WARN,
		    "consconfig_dacf:usb_kb_path has been deprecated, "
		    "use consconfig:usb_kb_path instead");

	if (usb_ms_path != NULL)
		cmn_err(CE_WARN,
		    "consconfig_dacf:usb_ms_path has been deprecated, "
		    "use consconfig:usb_ms_path instead");

	if (consconfig_errlevel > DPRINT_L0)
		return;

	path = NULL;
	if (consconfig_usb_kb_path != NULL)
		path = consconfig_usb_kb_path;
	else if (usb_kb_path != NULL)
		path = usb_kb_path;
	if (path != NULL)
		DPRINTF(DPRINT_L0, "usb keyboard path = %s\n", path);

	path = plat_kbdpath();
	if (path != NULL)
		DPRINTF(DPRINT_L0, "keyboard path = %s\n", path);

	path = NULL;
	if (consconfig_usb_ms_path != NULL)
		path = consconfig_usb_ms_path;
	else if (usb_ms_path != NULL)
		path = usb_ms_path;
	if (path != NULL)
		DPRINTF(DPRINT_L0, "usb mouse path = %s\n", path);

	path = plat_mousepath();
	if (path != NULL)
		DPRINTF(DPRINT_L0, "mouse path = %s\n", path);

	path = plat_stdinpath();
	if (path != NULL)
		DPRINTF(DPRINT_L0, "stdin path = %s\n", path);

	path = plat_stdoutpath();
	if (path != NULL)
		DPRINTF(DPRINT_L0, "stdout path = %s\n", path);

	path = plat_fbpath();
	if (path != NULL)
		DPRINTF(DPRINT_L0, "fb path = %s\n", path);
}

/*
 * consconfig_kbd_abort_enable:
 * 	Send the CONSSETABORTENABLE ioctl to the lower layers.  This ioctl
 * 	will only be sent to the device if it is the console device.
 * 	This ioctl tells the device to pay attention to abort sequences.
 * 	In the case of kbtrans, this would tell the driver to pay attention
 * 	to the two key abort sequences like STOP-A.  In the case of the
 * 	serial keyboard, it would be an abort sequence like a break.
 */
static int
consconfig_kbd_abort_enable(ldi_handle_t lh)
{
	int	err, rval;

	DPRINTF(DPRINT_L0, "consconfig_kbd_abort_enable\n");

	err = ldi_ioctl(lh, CONSSETABORTENABLE, (uintptr_t)B_TRUE,
	    FKIOCTL, kcred, &rval);
	return (err);
}

/*
 * consconfig_kbd_abort_disable:
 * 	Send CONSSETABORTENABLE ioctl to lower layers.  This ioctl
 * 	will only be sent to the device if it is the console device.
 * 	This ioctl tells the physical device to ignore abort sequences,
 * 	and send the sequences up to virtual keyboard(conskbd) so that
 * 	STOP and A (or F1 and A) can be combined.
 */
static int
consconfig_kbd_abort_disable(ldi_handle_t lh)
{
	int	err, rval;

	DPRINTF(DPRINT_L0, "consconfig_kbd_abort_disable\n");

	err = ldi_ioctl(lh, CONSSETABORTENABLE, (uintptr_t)B_FALSE,
	    FKIOCTL, kcred, &rval);
	return (err);
}

#ifdef _HAVE_TEM_FIRMWARE
static int
consconfig_tem_supported(cons_state_t *sp)
{
	dev_t			dev;
	dev_info_t		*dip;
	int			*int_array;
	uint_t			nint;
	int			rv = 0;

	if (sp->cons_fb_path == NULL)
		return (0);

	if ((dev = ddi_pathname_to_dev_t(sp->cons_fb_path)) == NODEV)
		return (0); /* warning printed later by common code */

	/*
	 * Here we hold the driver and check "tem-support" property.
	 * We're doing this with e_ddi_hold_devi_by_dev and
	 * ddi_prop_lookup_int_array without opening the driver since
	 * some video cards that don't support the kernel terminal
	 * emulator could hang or crash if opened too early during
	 * boot.
	 */
	if ((dip = e_ddi_hold_devi_by_dev(dev, 0)) == NULL) {
		cmn_err(CE_WARN, "consconfig: cannot hold fb dev %s",
		    sp->cons_fb_path);
		return (0);
	}

	/*
	 * Check that the tem-support property exists AND that
	 * it is equal to 1.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "tem-support", &int_array, &nint) ==
	    DDI_SUCCESS) {
		if (nint > 0)
			rv = int_array[0] == 1;
		ddi_prop_free(int_array);
	}

	ddi_release_devi(dip);

	return (rv);
}
#endif /* _HAVE_TEM_FIRMWARE */

/*
 * consconfig_get_polledio:
 * 	Query the console with the CONSPOLLEDIO ioctl.
 * 	The polled I/O routines are used by debuggers to perform I/O while
 * 	interrupts and normal kernel services are disabled.
 */
static cons_polledio_t *
consconfig_get_polledio(ldi_handle_t lh)
{
	int		err, rval;
	struct strioctl	strioc;
	cons_polledio_t	*polled_io;

	/*
	 * Setup the ioctl to be sent down to the lower driver.
	 */
	strioc.ic_cmd = CONSOPENPOLLEDIO;
	strioc.ic_timout = INFTIM;
	strioc.ic_len = sizeof (polled_io);
	strioc.ic_dp = (char *)&polled_io;

	/*
	 * Send the ioctl to the driver.  The ioctl will wait for
	 * the response to come back from wc.  wc has already issued
	 * the CONSOPENPOLLEDIO to the lower layer driver.
	 */
	err = ldi_ioctl(lh, I_STR, (intptr_t)&strioc, FKIOCTL, kcred, &rval);

	if (err != 0) {
		/*
		 * If the lower driver does not support polled I/O, then
		 * return NULL.  This will be the case if the driver does
		 * not handle polled I/O, or OBP is going to handle polled
		 * I/O for the device.
		 */

		return (NULL);
	}

	/*
	 * Return the polled I/O structure.
	 */
	return (polled_io);
}

/*
 * consconfig_setup_polledio:
 * 	This routine does the setup work for polled I/O.  First we get
 * 	the polled_io structure from the lower layers
 * 	and then we register the polled I/O
 * 	callbacks with the debugger that will be using them.
 */
static void
consconfig_setup_polledio(cons_state_t *sp, dev_t dev)
{
	cons_polledio_t		*polled_io;
	ldi_handle_t		lh;

	DPRINTF(DPRINT_L0, "consconfig_setup_polledio: start\n");


	if (ldi_open_by_dev(&dev, OTYP_CHR,
	    FREAD|FWRITE|FNOCTTY, kcred, &lh, sp->cons_li) != 0)
		return;


	/*
	 * Get the polled io routines so that we can use this
	 * device with the debuggers.
	 */
	polled_io = consconfig_get_polledio(lh);

	/*
	 * If the get polledio failed, then we do not want to throw
	 * the polled I/O switch.
	 */
	if (polled_io == NULL) {
		DPRINTF(DPRINT_L0,
		    "consconfig_setup_polledio: get_polledio failed\n");
		(void) ldi_close(lh, FREAD|FWRITE, kcred);
		return;
	}

	/* Initialize the polled input */
	polled_io_init();

	/* Register the callbacks */
	DPRINTF(DPRINT_L0,
	    "consconfig_setup_polledio: registering callbacks\n");
	(void) polled_io_register_callbacks(polled_io, 0);

	(void) ldi_close(lh, FREAD|FWRITE, kcred);

	DPRINTF(DPRINT_L0, "consconfig_setup_polledio: end\n");
}

static cons_state_t *
consconfig_state_init(void)
{
	cons_state_t	*sp;
	int		rval;

	/* Initialize console information */
	sp = kmem_zalloc(sizeof (cons_state_t), KM_SLEEP);
	sp->cons_keyboard_problem = B_FALSE;

	mutex_init(&sp->cons_lock, NULL, MUTEX_DRIVER, NULL);

	/* check if consconfig:usb_kb_path is set in /etc/system */
	consconfig_usb_kb_path = consconfig_get_usb_kb_path();

	/* check if consconfig:usb_ms_path is set in /etc/system */
	consconfig_usb_ms_path = consconfig_get_usb_ms_path();

	consconfig_print_paths();

	/* init external globals */
	stdoutdev = NODEV;

	/*
	 * Find keyboard, mouse, stdin and stdout devices, if they
	 * exist on this platform.
	 */

	if (consconfig_usb_kb_path != NULL) {
		sp->cons_keyboard_path = consconfig_usb_kb_path;
	} else if (usb_kb_path != NULL) {
		sp->cons_keyboard_path = usb_kb_path;
	} else {
		sp->cons_keyboard_path = plat_kbdpath();
	}

	if (consconfig_usb_ms_path != NULL) {
		sp->cons_mouse_path = consconfig_usb_ms_path;
	} else if (usb_ms_path != NULL) {
		sp->cons_mouse_path = usb_ms_path;
	} else {
		sp->cons_mouse_path = plat_mousepath();
	}

	/* Identify the stdout driver */
	sp->cons_stdout_path = plat_stdoutpath();
	sp->cons_stdout_is_fb = plat_stdout_is_framebuffer();

	sp->cons_stdin_is_kbd = plat_stdin_is_keyboard();

	if (sp->cons_stdin_is_kbd &&
	    (usb_kb_path != NULL || consconfig_usb_kb_path != NULL))  {
		sp->cons_stdin_path = sp->cons_keyboard_path;
	} else {
		/*
		 * The standard in device may or may not be the same as
		 * the keyboard. Even if the keyboard is not the
		 * standard input, the keyboard console stream will
		 * still be built if the keyboard alias provided by the
		 * firmware exists and is valid.
		 */
		sp->cons_stdin_path = plat_stdinpath();
	}

	if (sp->cons_stdout_is_fb) {
		sp->cons_fb_path = sp->cons_stdout_path;

#ifdef _HAVE_TEM_FIRMWARE
		sp->cons_tem_supported = consconfig_tem_supported(sp);

		/*
		 * Systems which offer a virtual console must use that
		 * as a fallback whenever the fb doesn't support tem.
		 * Such systems cannot render characters to the screen
		 * using OBP.
		 */
		if (!sp->cons_tem_supported) {
			char *path;

			if (plat_virtual_console_path(&path) >= 0) {
				sp->cons_stdin_is_kbd = 0;
				sp->cons_stdout_is_fb = 0;
				sp->cons_stdin_path = path;
				sp->cons_stdout_path = path;
				sp->cons_fb_path = plat_fbpath();

				cmn_err(CE_WARN,
				    "%s doesn't support terminal emulation "
				    "mode; switching to virtual console.",
				    sp->cons_fb_path);
			}
		}
#endif /* _HAVE_TEM_FIRMWARE */
	} else {
		sp->cons_fb_path = plat_fbpath();
#ifdef _HAVE_TEM_FIRMWARE
		sp->cons_tem_supported = consconfig_tem_supported(sp);
#endif /* _HAVE_TEM_FIRMWARE */
	}

	sp->cons_li = ldi_ident_from_anon();

	/* Save the pointer for retrieval by the dacf functions */
	rval = space_store("consconfig", (uintptr_t)sp);
	ASSERT(rval == 0);

	return (sp);
}

static int
consconfig_relink_wc(cons_state_t *sp, ldi_handle_t new_lh, int *muxid)
{
	int		err, rval;
	ldi_handle_t	wc_lh;
	dev_t		wc_dev;

	ASSERT(muxid != NULL);

	/*
	 * NOTE: we could be in a dacf callback context right now. normally
	 * it's not legal to call any ldi_open_*() function from this context
	 * because we're currently holding device tree locks and if the
	 * ldi_open_*() call could try to acquire other device tree locks
	 * (to attach the device we're trying to open.)  if this happens then
	 * we could deadlock.  To avoid this situation, during initialization
	 * we made sure to grab a hold on the dip of the device we plan to
	 * open so that it can never be detached.  Then we use
	 * ldi_open_by_dev() to actually open the device since it will see
	 * that the device is already attached and held and instead of
	 * acquire any locks it will only increase the reference count
	 * on the device.
	 */
	wc_dev = sp->cons_wc_vp->v_rdev;
	err = ldi_open_by_dev(&wc_dev, OTYP_CHR, FREAD|FWRITE|FNOCTTY,
	    kcred, &wc_lh, sp->cons_li);
	ASSERT(wc_dev == sp->cons_wc_vp->v_rdev);
	if (err) {
		cmn_err(CE_WARN, "consconfig_relink_wc: "
		    "unable to open wc device");
		return (err);
	}

	if (new_lh != NULL) {
		DPRINTF(DPRINT_L0, "linking stream under wc\n");

		err = ldi_ioctl(wc_lh, I_PLINK, (uintptr_t)new_lh,
		    FKIOCTL, kcred, muxid);
		if (err != 0) {
			cmn_err(CE_WARN, "consconfig_relink_wc: "
			    "wc link failed, error %d", err);
		}
	} else {
		DPRINTF(DPRINT_L0, "unlinking stream from under wc\n");

		err = ldi_ioctl(wc_lh, I_PUNLINK, *muxid,
		    FKIOCTL, kcred, &rval);
		if (err != 0) {
			cmn_err(CE_WARN, "consconfig_relink_wc: "
			    "wc unlink failed, error %d", err);
		} else {
			*muxid = -1;
		}
	}

	(void) ldi_close(wc_lh, FREAD|FWRITE, kcred);
	return (err);
}

static void
cons_build_upper_layer(cons_state_t *sp)
{
	ldi_handle_t		wc_lh;
	struct strioctl		strioc;
	int			rval;
	dev_t			dev;
	dev_t			wc_dev;

	/*
	 * Build the wc->conskbd portion of the keyboard console stream.
	 * Even if no keyboard is attached to the system, the upper
	 * layer of the stream will be built. If the user attaches
	 * a keyboard after the system is booted, the keyboard driver
	 * and module will be linked under conskbd.
	 *
	 * Errors are generally ignored here because conskbd and wc
	 * are pseudo drivers and should be present on the system.
	 */

	/* open the console keyboard device.  will never be closed */
	if (ldi_open_by_name(CONSKBD_PATH, FREAD|FWRITE|FNOCTTY,
	    kcred, &sp->conskbd_lh, sp->cons_li) != 0) {
		panic("consconfig: unable to open conskbd device");
		/*NOTREACHED*/
	}

	DPRINTF(DPRINT_L0, "conskbd_lh = %p\n", sp->conskbd_lh);

	/* open the console mouse device.  will never be closed */
	if (ldi_open_by_name(CONSMS_PATH, FREAD|FWRITE|FNOCTTY,
	    kcred, &sp->consms_lh, sp->cons_li) != 0) {
		panic("consconfig: unable to open consms device");
		/*NOTREACHED*/
	}

	DPRINTF(DPRINT_L0, "consms_lh = %p\n", sp->consms_lh);

	/*
	 * Get a vnode for the wc device and then grab a hold on the
	 * device dip so it can never detach.  We need to do this now
	 * because later we'll have to open the wc device in a context
	 * were it isn't safe to acquire any device tree locks (ie, during
	 * a dacf callback.)
	 */
	sp->cons_wc_vp = i_consconfig_createvp(WC_PATH);
	if (sp->cons_wc_vp == NULL)
		panic("consconfig: unable to find wc device");

	if (e_ddi_hold_devi_by_dev(sp->cons_wc_vp->v_rdev, 0) == NULL)
		panic("consconfig: unable to hold wc device");

	/*
	 * Build the wc->conskbd portion of the keyboard console stream.
	 * Even if no keyboard is attached to the system, the upper
	 * layer of the stream will be built. If the user attaches
	 * a keyboard after the system is booted, the keyboard driver
	 * and module will be linked under conskbd.
	 *
	 * The act of linking conskbd under wc will cause wc to
	 * query the lower layers about their polled I/O routines
	 * using CONSOPENPOLLEDIO.  This will fail on this link because
	 * there is not a physical keyboard linked under conskbd.
	 *
	 * Since conskbd and wc are pseudo drivers, errors are
	 * generally ignored when linking and unlinking them.
	 */
	(void) consconfig_relink_wc(sp, sp->conskbd_lh, &sp->conskbd_muxid);

	/*
	 * Get a vnode for the redirection device.  (It has the
	 * connection to the workstation console device wired into it,
	 * so that it's not necessary to establish the connection
	 * here.  If the redirection device is ever generalized to
	 * handle multiple client devices, it won't be able to
	 * establish the connection itself, and we'll have to do it
	 * here.)
	 */
	wsconsvp = i_consconfig_createvp(IWSCN_PATH);
	if (wsconsvp == NULL) {
		panic("consconfig: unable to find iwscn device");
		/*NOTREACHED*/
	}

	if (cons_tem_disable)
		return;

	if (sp->cons_fb_path == NULL) {
#if defined(__x86)
		if (sp->cons_stdout_is_fb)
			cmn_err(CE_WARN, "consconfig: no screen found");
#endif
		return;
	}

	/* make sure the frame buffer device exists */
	dev = ddi_pathname_to_dev_t(sp->cons_fb_path);
	if (dev == NODEV) {
		cmn_err(CE_WARN, "consconfig: "
		    "cannot find driver for screen device %s",
		    sp->cons_fb_path);
		return;
	}

#ifdef _HAVE_TEM_FIRMWARE
	/*
	 * If the underlying fb device doesn't support terminal emulation,
	 * we don't want to open the wc device (below) because it depends
	 * on features which aren't available (polled mode io).
	 */
	if (!sp->cons_tem_supported)
		return;
#endif /* _HAVE_TEM_FIRMWARE */

	/* tell wc to open the frame buffer device */
	wc_dev = sp->cons_wc_vp->v_rdev;
	if (ldi_open_by_dev(&wc_dev, OTYP_CHR, FREAD|FWRITE|FNOCTTY, kcred,
	    &wc_lh, sp->cons_li)) {
		cmn_err(CE_PANIC, "cons_build_upper_layer: "
		    "unable to open wc device");
		return;
	}
	ASSERT(wc_dev == sp->cons_wc_vp->v_rdev);

	strioc.ic_cmd = WC_OPEN_FB;
	strioc.ic_timout = INFTIM;
	strioc.ic_len = strlen(sp->cons_fb_path) + 1;
	strioc.ic_dp = sp->cons_fb_path;

	if (ldi_ioctl(wc_lh, I_STR, (intptr_t)&strioc,
	    FKIOCTL, kcred, &rval) == 0)
		consmode = CONS_KFB;
	else
		cmn_err(CE_WARN,
		    "consconfig: terminal emulator failed to initialize");
	(void) ldi_close(wc_lh, FREAD|FWRITE, kcred);
}

static void
consconfig_load_drivers(cons_state_t *sp)
{
	/*
	 * Calling ddi_pathname_to_dev_t may cause the USB Host Controller
	 * drivers to be loaded. Here we make sure that EHCI is loaded
	 * earlier than {U, O}HCI. The order here is important. As
	 * we have observed many systems on which hangs occur if the
	 * {U,O}HCI companion controllers take over control from the BIOS
	 * before EHCI does.  These hangs are also caused by BIOSes leaving
	 * interrupt-on-port-change enabled in the ehci controller, so that
	 * when uhci/ohci reset themselves, it induces a port change on
	 * the ehci companion controller.  Since there's no interrupt handler
	 * installed at the time, the moment that interrupt is unmasked, an
	 * interrupt storm will occur.	All this is averted when ehci is
	 * loaded first.  And now you know..... the REST of the story.
	 *
	 * Regardless of platform, ehci needs to initialize first to avoid
	 * unnecessary connects and disconnects on the companion controller
	 * when ehci sets up the routing.
	 *
	 * The same is generally true of xhci. Many platforms have routing
	 * between the xhci controller and the ehci controller. To avoid those
	 * same disconnects, we load xhci before ehci.
	 */
	(void) ddi_hold_installed_driver(ddi_name_to_major("xhci"));
	(void) ddi_hold_installed_driver(ddi_name_to_major("ehci"));
	(void) ddi_hold_installed_driver(ddi_name_to_major("uhci"));
	(void) ddi_hold_installed_driver(ddi_name_to_major("ohci"));

	/*
	 * The attaching of the drivers will cause the creation of the
	 * keyboard and mouse minor nodes, which will in turn trigger the
	 * dacf framework to call the keyboard and mouse configuration
	 * tasks.  See PSARC/1998/212 for more details about the dacf
	 * framework.
	 *
	 * on sparc, when the console is ttya, zs0 is stdin/stdout, and zs1
	 * is kb/mouse.  zs0 must be attached before zs1. The zs driver
	 * is written this way and the hardware may depend on this, too.
	 * It would be better to enforce this by attaching zs in sibling
	 * order with a driver property, such as ddi-attachall.
	 */
	if (sp->cons_stdin_path != NULL)
		stdindev = ddi_pathname_to_dev_t(sp->cons_stdin_path);
	if (stdindev == NODEV) {
		DPRINTF(DPRINT_L0,
		    "!fail to attach stdin: %s\n", sp->cons_stdin_path);
	}
	if (sp->cons_stdout_path != NULL)
		stdoutdev = ddi_pathname_to_dev_t(sp->cons_stdout_path);
	if (sp->cons_keyboard_path != NULL)
		kbddev = ddi_pathname_to_dev_t(sp->cons_keyboard_path);
	if (sp->cons_mouse_path != NULL)
		mousedev =  ddi_pathname_to_dev_t(sp->cons_mouse_path);

	/*
	 * On x86, make sure the fb driver is loaded even if we don't use it
	 * for the console. This will ensure that we create a /dev/fb link
	 * which is required to start Xorg.
	 */
#if defined(__x86)
	if (sp->cons_fb_path != NULL)
		fbdev = ddi_pathname_to_dev_t(sp->cons_fb_path);
#endif

	DPRINTF(DPRINT_L0, "stdindev %lx, stdoutdev %lx, kbddev %lx, "
	    "mousedev %lx\n", stdindev, stdoutdev, kbddev, mousedev);
}

#if !defined(__x86)
void
consconfig_virtual_console_vp(cons_state_t *sp)
{
	char    *virtual_cons_path;

	if (plat_virtual_console_path(&virtual_cons_path) < 0)
		return;

	DPRINTF(DPRINT_L0, "consconfig_virtual_console_vp: "
	    "virtual console device path %s\n", virtual_cons_path);

	ASSERT(sp->cons_stdout_path != NULL);
	if (strcmp(virtual_cons_path, sp->cons_stdout_path) == 0) {
		/* virtual console already in use */
		return;
	}

	vsconsvp = i_consconfig_createvp(virtual_cons_path);
	if (vsconsvp == NULL) {
		cmn_err(CE_WARN, "consconfig_virtual_console_vp: "
		    "unable to find serial virtual console device %s",
		    virtual_cons_path);
			return;
	}

	(void) e_ddi_hold_devi_by_dev(vsconsvp->v_rdev, 0);
}
#endif

static void
consconfig_init_framebuffer(cons_state_t *sp)
{
	if (!sp->cons_stdout_is_fb)
		return;

	DPRINTF(DPRINT_L0, "stdout is framebuffer\n");
	ASSERT(strcmp(sp->cons_fb_path, sp->cons_stdout_path) == 0);

	/*
	 * Console output is a framebuffer.
	 * Find the framebuffer driver if we can, and make
	 * ourselves a shadow vnode to track it with.
	 */
	fbdev = stdoutdev;
	if (fbdev == NODEV) {
		DPRINTF(DPRINT_L3,
		    "Can't find driver for console framebuffer\n");
	} else {
		/* stdoutdev is valid, of fbvp should exist */
		fbvp = i_consconfig_createvp(sp->cons_stdout_path);
		if (fbvp == NULL) {
			panic("consconfig_init_framebuffer: "
			    "unable to find frame buffer device");
			/*NOTREACHED*/
		}
		ASSERT(fbvp->v_rdev == fbdev);

		/* console device is never released */
		fbdip = e_ddi_hold_devi_by_dev(fbdev, 0);
	}
	pm_cfb_setup(sp->cons_stdout_path);
}

/*
 * consconfig_prepare_dev:
 * 	Flush the stream, push "pushmod" onto the stream.
 * 	for keyboard, issue the KIOCTRANSABLE ioctl, and
 *	possible enable abort.
 */
static void
consconfig_prepare_dev(
    ldi_handle_t	new_lh,
    const char		*pushmod,
    int			kbdtranslatable,
    int			input_type,
    int			dev_type)
{
	int err, rval;

	/* send a flush down the stream to the keyboard driver */
	(void) ldi_ioctl(new_lh, I_FLUSH, (intptr_t)FLUSHRW,
	    FKIOCTL, kcred, &rval);

	if (pushmod) {
		err = ldi_ioctl(new_lh, I_PUSH, (intptr_t)pushmod,
		    FKIOCTL, kcred, &rval);
		if (err) {
			cmn_err(CE_WARN, "consconfig_prepare_dev: "
			    "can't push streams module \"%s\", error %d",
			    pushmod, err);
		}
	}

	if (dev_type == CONS_MS)
		return;

	ASSERT(dev_type == CONS_KBD);

	err = ldi_ioctl(new_lh, KIOCTRANSABLE,
	    (intptr_t)&kbdtranslatable, FKIOCTL, kcred, &rval);
	if (err) {
		cmn_err(CE_WARN, "consconfig_prepare_dev: "
		    "KIOCTRANSABLE failed, error: %d", err);
	}

	/*
	 * During boot, dynamic_console_config() will call the
	 * function to enable abort on the console.  If the
	 * keyboard is hotplugged after boot, check to see if
	 * the keyboard is the console input.  If it is
	 * enable abort on it.
	 */
	if (input_type == CONSOLE_LOCAL)
		(void) consconfig_kbd_abort_enable(new_lh);
}

/*
 * consconfig_relink_conskbd:
 * 	If new_lh is not NULL it should represent a driver with a
 * 	keyboard module pushed on top of it. The driver is then linked
 * 	underneath conskbd.  the resulting stream will be
 *	wc->conskbd->"new_lh driver".
 *
 * 	If new_lh is NULL, then an unlink operation is done on conskbd
 * 	that attempts to unlink the stream specified by *muxid.
 *	the resulting stream will be wc->conskbd.
 */
static int
consconfig_relink_conskbd(cons_state_t *sp, ldi_handle_t new_lh, int *muxid)
{
	int		err, rval;
	int		conskbd_relink = 0;

	ASSERT(muxid != NULL);

	DPRINTF(DPRINT_L0, "consconfig_relink_conskbd: "
	    "conskbd_lh = %p, new_lh = %p,  muxid = %x\n",
	    sp->conskbd_lh, new_lh, *muxid);

	/*
	 * If conskbd is linked under wc then temporarily unlink it
	 * from under wc so that the new_lh stream may be linked under
	 * conskbd.  This has to be done because streams are built bottom
	 * up and linking a stream under conskbd isn't allowed when
	 * conskbd is linked under wc.
	 */
	if (sp->conskbd_muxid != -1) {
		DPRINTF(DPRINT_L0, "unlinking conskbd from under wc\n");
		conskbd_relink = 1;
		err = consconfig_relink_wc(sp, NULL, &sp->conskbd_muxid);
		if (err) {
			cmn_err(CE_WARN, "consconfig_relink_conskbd: "
			    "wc unlink failed, error %d", err);
			return (err);
		}
	}

	if (new_lh != NULL) {
		DPRINTF(DPRINT_L0, "linking keyboard under conskbd\n");

		/* Link the stream represented by new_lh under conskbd */
		err = ldi_ioctl(sp->conskbd_lh, I_PLINK, (uintptr_t)new_lh,
		    FKIOCTL, kcred, muxid);
		if (err != 0) {
			cmn_err(CE_WARN, "consconfig_relink_conskbd: "
			    "conskbd link failed, error %d", err);
			goto relink_failed;
		}
	} else {
		DPRINTF(DPRINT_L0, "unlinking keyboard from under conskbd\n");

		/*
		 * This will cause the keyboard driver to be closed,
		 * all modules to be popped, and the keyboard vnode released.
		 */
		err = ldi_ioctl(sp->conskbd_lh, I_PUNLINK, *muxid,
		    FKIOCTL, kcred, &rval);
		if (err != 0) {
			cmn_err(CE_WARN, "consconfig_relink_conskbd: "
			    "conskbd unlink failed, error %d", err);
			goto relink_failed;
		} else {
			*muxid = -1;
		}

		consconfig_check_phys_kbd(sp);
	}

	if (!conskbd_relink)
		return (err);

	/*
	 * Link consbkd back under wc.
	 *
	 * The act of linking conskbd back under wc will cause wc
	 * to query the lower lower layers about their polled I/O
	 * routines.  This time the request will succeed because there
	 * is a physical keyboard linked under conskbd.
	 */
	DPRINTF(DPRINT_L0, "re-linking conskbd under wc\n");
	err = consconfig_relink_wc(sp, sp->conskbd_lh, &sp->conskbd_muxid);
	if (err) {
		cmn_err(CE_WARN, "consconfig_relink_conskbd: "
		    "wc link failed, error %d", err);
	}
	return (err);

relink_failed:
	if (!conskbd_relink)
		return (err);

	/* something went wrong, try to reconnect conskbd back under wc */
	DPRINTF(DPRINT_L0, "re-linking conskbd under wc\n");
	(void) consconfig_relink_wc(sp, sp->conskbd_lh, &sp->conskbd_muxid);
	return (err);
}

/*
 * consconfig_relink_consms:
 * 	If new_lh is not NULL it should represent a driver with a
 * 	mouse module pushed on top of it. The driver is then linked
 * 	underneath consms.  the resulting stream will be
 *	consms->"new_lh driver".
 *
 * 	If new_lh is NULL, then an unlink operation is done on consms
 * 	that attempts to unlink the stream specified by *muxid.
 */
static int
consconfig_relink_consms(cons_state_t *sp, ldi_handle_t new_lh, int *muxid)
{
	int		err, rval;

	DPRINTF(DPRINT_L0, "consconfig_relink_consms: "
	    "consms_lh = %p, new_lh = %p,  muxid = %x\n",
	    (void *)sp->consms_lh, (void *)new_lh, *muxid);

	if (new_lh != NULL) {
		DPRINTF(DPRINT_L0, "linking mouse under consms\n");

		/* Link ms/usbms stream underneath consms multiplexor. */
		err = ldi_ioctl(sp->consms_lh, I_PLINK, (uintptr_t)new_lh,
		    FKIOCTL, kcred, muxid);
		if (err != 0) {
			cmn_err(CE_WARN, "consconfig_relink_consms: "
			    "mouse link failed, error %d", err);
		}
	} else {
		DPRINTF(DPRINT_L0, "unlinking mouse from under consms\n");

		/* Tear down the mouse stream */
		err = ldi_ioctl(sp->consms_lh, I_PUNLINK, *muxid,
		    FKIOCTL, kcred, &rval);
		if (err != 0) {
			cmn_err(CE_WARN, "consconfig_relink_consms: "
			    "mouse unlink failed, error %d", err);
		} else {
			*muxid = -1;
		}
	}
	return (err);
}

static int
cons_get_input_type(cons_state_t *sp)
{
	int type;

	/*
	 * Now that we know what all the devices are, we can figure out
	 * what kind of console we have.
	 */
	if (sp->cons_stdin_is_kbd)  {
		/* Stdin is from the system keyboard */
		type = CONSOLE_LOCAL;
	} else if ((stdindev != NODEV) && (stdindev == stdoutdev)) {
		/*
		 * A reliable indicator that we are doing a remote console
		 * is that stdin and stdout are the same.
		 * This is probably a tip line.
		 */
		type = CONSOLE_TIP;
	} else {
		type = CONSOLE_SERIAL_KEYBOARD;
	}

	return (type);
}

static void
consconfig_init_input(cons_state_t *sp)
{
	ldi_handle_t	new_lh;
	dev_t		cons_final_dev;
	int		err;

	cons_final_dev = NODEV;

	switch (sp->cons_input_type) {
	case CONSOLE_LOCAL:
		DPRINTF(DPRINT_L0, "stdin is keyboard\n");

		/*
		 * The machine is allowed to boot without a keyboard.
		 * If a user attaches a keyboard later, the keyboard
		 * will be hooked into the console stream with the dacf
		 * functions.
		 *
		 * The only drivers that look at kbbdev are the
		 * serial drivers, which looks at kbdev to see if
		 * they should allow abort on a break. In the absence
		 * of keyboard, the serial drivers won't be attached
		 * for any keyboard instance.
		 */
		if (kbddev == NODEV) {
			/*
			 * If there is a problem with the keyboard
			 * during the driver loading, then the polled
			 * input won't get setup properly if polled
			 * input is needed.  This means that if the
			 * keyboard is hotplugged, the keyboard would
			 * work normally, but going down to the
			 * debugger would not work if polled input is
			 * required.  This field is set here.  The next
			 * time a keyboard is plugged in, the field is
			 * checked in order to give the next keyboard a
			 * chance at being registered for console
			 * input.
			 *
			 * Although this code will rarely be needed,
			 * USB keyboards can be flaky, so this code
			 * will be useful on the occasion that the
			 * keyboard doesn't enumerate when the drivers
			 * are loaded.
			 */
			DPRINTF(DPRINT_L2, "Error with console keyboard\n");
			sp->cons_keyboard_problem = B_TRUE;
		}
		stdindev = kbddev;
		cons_final_dev = sp->cons_wc_vp->v_rdev;
		break;

	case CONSOLE_TIP:
		DPRINTF(DPRINT_L0, "console input is tty (%s)\n",
		    sp->cons_stdin_path);

		/*
		 * Console device drivers must be able to output
		 * after being closed.
		 */
		rconsvp = i_consconfig_createvp(sp->cons_stdin_path);
		if (rconsvp == NULL) {
			panic("consconfig_init_input: "
			    "unable to find stdin device (%s)",
			    sp->cons_stdin_path);
			/*NOTREACHED*/
		}
		rconsdev = rconsvp->v_rdev;

		ASSERT(rconsdev == stdindev);

		cons_final_dev = rconsdev;
		break;

	case CONSOLE_SERIAL_KEYBOARD:
		DPRINTF(DPRINT_L0, "stdin is serial keyboard\n");

		/*
		 * Non-keyboard input device, but not rconsdev.
		 * This is known as the "serial keyboard" case - the
		 * most likely use is someone has a keyboard attached
		 * to a serial port (tip) and still has output on a
		 * framebuffer.
		 *
		 * In this case, the serial driver must be linked
		 * directly beneath wc.  Since conskbd was linked
		 * underneath wc above, first we unlink conskbd.
		 */
		(void) consconfig_relink_wc(sp, NULL, &sp->conskbd_muxid);
		sp->conskbd_muxid = -1;

		/*
		 * Open the serial keyboard, configure it,
		 * and link it underneath wc.
		 */
		err = ldi_open_by_name(sp->cons_stdin_path,
		    FREAD|FWRITE|FNOCTTY, kcred, &new_lh, sp->cons_li);
		if (err == 0) {
			struct termios	termios;
			int		rval;
			int		stdin_muxid;

			consconfig_prepare_dev(new_lh,
			    "kb", TR_CANNOT, sp->cons_input_type, CONS_KBD);

			/* Re-set baud rate */
			(void) ldi_ioctl(new_lh, TCGETS, (intptr_t)&termios,
			    FKIOCTL, kcred, &rval);

			/* Set baud rate */
			if (consconfig_setmodes(stdindev, &termios) == 0) {
				err = ldi_ioctl(new_lh,
				    TCSETSF, (intptr_t)&termios,
				    FKIOCTL, kcred, &rval);
				if (err) {
					cmn_err(CE_WARN,
					    "consconfig_init_input: "
					    "TCSETSF failed, error %d", err);
				}
			}

			/*
			 * Now link the serial keyboard direcly under wc
			 * we don't save the returned muxid because we
			 * don't support changing/hotplugging the console
			 * keyboard when it is a serial keyboard.
			 */
			(void) consconfig_relink_wc(sp, new_lh, &stdin_muxid);

			(void) ldi_close(new_lh, FREAD|FWRITE, kcred);
		}

		cons_final_dev = sp->cons_wc_vp->v_rdev;
		break;

	default:
		panic("consconfig_init_input: "
		    "unsupported console input/output combination");
		/*NOTREACHED*/
	}

	/*
	 * Use the redirection device/workstation console pair as the "real"
	 * console if the latter hasn't already been set.
	 * The workstation console driver needs to see rwsconsvp, but
	 * all other access should be through the redirecting driver.
	 */
	if (rconsvp == NULL) {
		consconfig_dprintf(DPRINT_L0, "setup redirection driver\n");
		rconsvp = wsconsvp;
		rconsdev = wsconsvp->v_rdev;
	}

	ASSERT(cons_final_dev != NODEV);

	err = ldi_open_by_dev(&cons_final_dev, OTYP_CHR, FREAD|FWRITE|FNOCTTY,
	    kcred, &new_lh, sp->cons_li);
	if (err) {
		panic("consconfig_init_input: "
		    "unable to open console device");
		/*NOTREACHED*/
	}

	/* Enable abort on the console */
	(void) consconfig_kbd_abort_enable(new_lh);

	/* Now we must close it to make console logins happy */
	(void) ldi_close(new_lh, FREAD|FWRITE, kcred);

	/* Set up polled input if it is supported by the console device */
	if (plat_use_polled_debug()) {
		/*
		 * In the debug case, register the keyboard polled entry
		 * points, but don't throw the switch in the debugger.  This
		 * allows the polled entry points to be checked by hand
		 */
		consconfig_setup_polledio(sp, sp->cons_wc_vp->v_rdev);
	} else {
		consconfig_setup_polledio(sp, cons_final_dev);
	}

	kadb_uses_kernel();
}

/*
 * This function kicks off the console configuration.
 * Configure keyboard and mouse. Main entry here.
 */
void
dynamic_console_config(void)
{
	/* initialize space.c globals */
	stdindev = NODEV;
	mousedev = NODEV;
	kbddev = NODEV;
	fbdev = NODEV;
	fbvp = NULL;
	fbdip = NULL;
	wsconsvp = NULL;
	rwsconsvp = NULL;
	rwsconsdev = NODEV;
	rconsvp = NULL;
	rconsdev = NODEV;

	/* Initialize cons_state_t structure and console device paths */
	consconfig_sp = consconfig_state_init();
	ASSERT(consconfig_sp);

	/* Build upper layer of console stream */
	cons_build_upper_layer(consconfig_sp);

	/*
	 * Load keyboard/mouse drivers. The dacf routines will
	 * plumb the devices into the console stream
	 *
	 * At the conclusion of the ddi_pathname_to_dev_t calls, the keyboard
	 * and mouse drivers are linked into their respective console
	 * streams if the pathnames are valid.
	 */
	consconfig_load_drivers(consconfig_sp);
	consconfig_sp->cons_input_type = cons_get_input_type(consconfig_sp);

	/*
	 * This is legacy special case code for the "cool" virtual console
	 * for the Starfire project.  Starfire has a dummy "ssp-serial"
	 * node in the OBP device tree and cvc is a pseudo driver.
	 */
	if (consconfig_sp->cons_stdout_path != NULL && stdindev == NODEV &&
	    strstr(consconfig_sp->cons_stdout_path, "ssp-serial")) {
		/*
		 * Setup the virtual console driver for Starfire
		 * Note that console I/O will still go through prom for now
		 * (notice we don't open the driver here). The cvc driver
		 * will be activated when /dev/console is opened by init.
		 * During that time, a cvcd daemon will be started that
		 * will open the cvcredirection driver to facilitate
		 * the redirection of console I/O from cvc to cvcd.
		 */
		rconsvp = i_consconfig_createvp(CVC_PATH);
		if (rconsvp == NULL)
			goto done;
		rconsdev = rconsvp->v_rdev;
		goto done;
	}

	rwsconsvp = consconfig_sp->cons_wc_vp;
	rwsconsdev = consconfig_sp->cons_wc_vp->v_rdev;


	/* initialize framebuffer, console input, and redirection device  */
	consconfig_init_framebuffer(consconfig_sp);
	consconfig_init_input(consconfig_sp);

#if !defined(__x86)
	/* initialize virtual console vp for logging if needed */
	consconfig_virtual_console_vp(consconfig_sp);
#endif

	DPRINTF(DPRINT_L0,
	    "mousedev %lx, kbddev %lx, fbdev %lx, rconsdev %lx\n",
	    mousedev,  kbddev, fbdev, rconsdev);

	flush_deferred_console_buf();
done:
	consconfig_sp->cons_initialized = B_TRUE;
}


/*
 * Start of DACF interfaces
 */

/*
 * Do the real job for keyboard/mouse auto-configuration.
 */
static int
do_config(cons_state_t *sp, cons_prop_t *prop)
{
	ldi_handle_t	lh;
	dev_t		dev;
	int		error;

	ASSERT((prop->cp_type == CONS_KBD) || (prop->cp_type == CONS_MS));

	dev = prop->cp_dev;
	error = ldi_open_by_dev(&dev, OTYP_CHR,
	    FREAD|FWRITE|FNOCTTY, kcred, &lh, sp->cons_li);
	if (error) {
		return (DACF_FAILURE);
	}
	ASSERT(dev == prop->cp_dev);	/* clone not supported */

	/*
	 * Prepare the new keyboard/mouse driver
	 * to be linked under conskbd/consms.
	 */
	consconfig_prepare_dev(lh, prop->cp_pushmod, TR_CAN,
	    sp->cons_input_type, prop->cp_type);

	if (prop->cp_type == CONS_KBD) {
		/*
		 * Tell the physical keyboard driver to send
		 * the abort sequences up to the virtual keyboard
		 * driver so that STOP and A (or F1 and A)
		 * can be applied to different keyboards.
		 */
		(void) consconfig_kbd_abort_disable(lh);

		/* Link the stream underneath conskbd */
		error = consconfig_relink_conskbd(sp, lh, &prop->cp_muxid);
	} else {
		/* Link the stream underneath consms */
		error = consconfig_relink_consms(sp, lh, &prop->cp_muxid);
	}

	/*
	 * At this point, the stream is:
	 *	for keyboard:	wc->conskbd->["pushmod"->"kbd_vp driver"]
	 *	for mouse:	consms->["module_name"->]"mouse_avp driver"
	 */

	/* Close the driver stream, it will stay linked under conskbd */
	(void) ldi_close(lh, FREAD|FWRITE, kcred);

	if (error) {
		return (DACF_FAILURE);
	}

	return (DACF_SUCCESS);
}

static int
do_unconfig(cons_state_t *sp, cons_prop_t *prop)
{
	ASSERT((prop->cp_type == CONS_KBD) || (prop->cp_type == CONS_MS));

	if (prop->cp_type == CONS_KBD)
		return (consconfig_relink_conskbd(sp, NULL, &prop->cp_muxid));
	else
		return (consconfig_relink_consms(sp, NULL, &prop->cp_muxid));
}

static int
kb_ms_config(dacf_infohdl_t minor_hdl, dacf_arghdl_t arg_hdl, int type)
{
	major_t			major;
	minor_t			minor;
	dev_t			dev;
	dev_info_t		*dip;
	cons_state_t		*sp;
	cons_prop_t		*prop;
	const char		*pushmod;

	/*
	 * Retrieve the state information
	 * Some platforms may use the old-style "consconfig" to configure
	 * console stream modules but may also support devices that happen
	 * to match a rule in /etc/dacf.conf.  This will cause a problem
	 * since the console state structure will not be initialized.
	 * In that case, these entry points should silently fail and
	 * permit console to be plumbed later in boot.
	 */
	if ((sp = (cons_state_t *)space_fetch("consconfig")) == NULL)
		return (DACF_FAILURE);

	dip = dacf_devinfo_node(minor_hdl);
	major = ddi_driver_major(dip);
	ASSERT(major != DDI_MAJOR_T_NONE);
	minor = dacf_minor_number(minor_hdl);
	dev = makedevice(major, minor);
	ASSERT(dev != NODEV);

	DPRINTF(DPRINT_L0, "driver name = \"%s\", dev = 0x%lx, major = 0x%x\n",
	    (char *)dacf_driver_name(minor_hdl), dev, major);

	/* Access to the global variables is synchronized */
	mutex_enter(&sp->cons_lock);

	/*
	 * Check if the keyboard/mouse has already configured.
	 */
	if (consconfig_find_dev(sp, dev) != NULL) {
		mutex_exit(&sp->cons_lock);
		return (DACF_SUCCESS);
	}

	prop = kmem_zalloc(sizeof (cons_prop_t), KM_SLEEP);

	/* Config the new keyboard/mouse device */
	prop->cp_dev = dev;

	pushmod = dacf_get_arg(arg_hdl, "pushmod");
	prop->cp_pushmod = i_ddi_strdup((char *)pushmod, KM_SLEEP);

	prop->cp_type = type;
	if (do_config(sp, prop) != DACF_SUCCESS) {
		/*
		 * The keyboard/mouse node failed to open.
		 * Set the major and minor numbers to 0 so
		 * kb_unconfig/ms_unconfig won't unconfigure
		 * this node if it is detached.
		 */
		mutex_exit(&sp->cons_lock);
		consconfig_free_prop(prop);
		return (DACF_FAILURE);
	}

	consconfig_add_dev(sp, prop);

	/*
	 * See if there was a problem with the console keyboard during boot.
	 * If so, try to register polled input for this keyboard.
	 */
	if ((type == CONS_KBD) && (sp->cons_keyboard_problem)) {
		consconfig_setup_polledio(sp, sp->cons_wc_vp->v_rdev);
		sp->cons_keyboard_problem = B_FALSE;
	}

	/* Prevent autodetach due to memory pressure */
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, DDI_NO_AUTODETACH, 1);

	mutex_exit(&sp->cons_lock);

	return (DACF_SUCCESS);
}

static int
kb_ms_unconfig(dacf_infohdl_t minor_hdl, dacf_arghdl_t arg_hdl)
{
	_NOTE(ARGUNUSED(arg_hdl))

	major_t		major;
	minor_t		minor;
	dev_t		dev;
	dev_info_t	*dip;
	cons_state_t	*sp;
	cons_prop_t	*prop;

	/*
	 * Retrieve the state information
	 * So if there isn't a state available, then this entry point just
	 * returns.  See note in kb_config().
	 */
	if ((sp = (cons_state_t *)space_fetch("consconfig")) == NULL)
		return (DACF_SUCCESS);

	dip = dacf_devinfo_node(minor_hdl);
	major = ddi_driver_major(dip);
	ASSERT(major != DDI_MAJOR_T_NONE);
	minor = dacf_minor_number(minor_hdl);
	dev = makedevice(major, minor);
	ASSERT(dev != NODEV);

	/*
	 * Check if the keyboard/mouse that is being detached
	 * is the console keyboard/mouse or not.
	 */
	mutex_enter(&sp->cons_lock);
	if ((prop = consconfig_find_dev(sp, dev)) == NULL) {
		mutex_exit(&sp->cons_lock);
		return (DACF_SUCCESS);
	}

	/*
	 * This dev may be opened physically and then hotplugged out.
	 */
	if (prop->cp_muxid != -1) {
		(void) do_unconfig(sp, prop);
		consconfig_rem_dev(sp, dev);
	}

	mutex_exit(&sp->cons_lock);

	return (DACF_SUCCESS);
}

/*
 * This is the post-attach / pre-detach action function for the keyboard
 * and mouse. This function is associated with a node type in /etc/dacf.conf.
 */
static int
kb_config(dacf_infohdl_t minor_hdl, dacf_arghdl_t arg_hdl, int flags)
{
	_NOTE(ARGUNUSED(flags))

	return (kb_ms_config(minor_hdl, arg_hdl, CONS_KBD));
}

static int
ms_config(dacf_infohdl_t minor_hdl, dacf_arghdl_t arg_hdl, int flags)
{
	_NOTE(ARGUNUSED(flags))

	return (kb_ms_config(minor_hdl, arg_hdl, CONS_MS));
}

static int
kb_unconfig(dacf_infohdl_t minor_hdl, dacf_arghdl_t arg_hdl, int flags)
{
	_NOTE(ARGUNUSED(flags))

	return (kb_ms_unconfig(minor_hdl, arg_hdl));
}

static int
ms_unconfig(dacf_infohdl_t minor_hdl, dacf_arghdl_t arg_hdl, int flags)
{
	_NOTE(ARGUNUSED(flags))

	return (kb_ms_unconfig(minor_hdl, arg_hdl));
}

/*
 * consconfig_link and consconfig_unlink are provided to support
 * direct access to physical keyboard/mouse underlying conskbd/
 * consms.
 * When the keyboard/mouse is opened physically via its device
 * file, it will be unlinked from the virtual one, and when it
 * is closed physically, it will be linked back under the virtual
 * one.
 */
void
consconfig_link(major_t major, minor_t minor)
{
	char		buf[MAXPATHLEN];
	dev_t		dev;
	cons_state_t	*sp;
	cons_prop_t	*prop;

	if ((sp = (cons_state_t *)space_fetch("consconfig")) == NULL)
		return;

	dev = makedevice(major, minor);
	ASSERT(dev != NODEV);

	mutex_enter(&sp->cons_lock);
	if ((prop = consconfig_find_dev(sp, dev)) == NULL) {
		mutex_exit(&sp->cons_lock);
		return;
	}

	if (do_config(sp, prop) != DACF_SUCCESS) {
		(void) ddi_dev_pathname(dev, 0, buf);
		if (prop->cp_type == CONS_KBD)
			cmn_err(CE_WARN, "Failed to relink the keyboard "
			    "(%s) underneath virtual keyboard", buf);
		else
			cmn_err(CE_WARN, "Failed to relink the mouse "
			    "(%s) underneath virtual mouse", buf);
		consconfig_rem_dev(sp, dev);
	}

	mutex_exit(&sp->cons_lock);
}


int
consconfig_unlink(major_t major, minor_t minor)
{
	dev_t		dev;
	cons_state_t	*sp;
	cons_prop_t	*prop;
	int		error;

	if ((sp = (cons_state_t *)space_fetch("consconfig")) == NULL)
		return (DACF_SUCCESS);

	dev = makedevice(major, minor);
	ASSERT(dev != NODEV);

	mutex_enter(&sp->cons_lock);
	if ((prop = consconfig_find_dev(sp, dev)) == NULL) {
		mutex_exit(&sp->cons_lock);
		return (DACF_FAILURE);
	}

	error = do_unconfig(sp, prop);

	/*
	 * Keep this dev on the list, for this dev is still online.
	 */
	mutex_exit(&sp->cons_lock);

	return (error);
}

/*
 * Routine to set baud rate, bits-per-char, parity and stop bits
 * on the console line when necessary.
 */
static int
consconfig_setmodes(dev_t dev, struct termios *termiosp)
{
	char buf[MAXPATHLEN];
	int len = MAXPATHLEN;
	char name[16];
	int ppos, i;
	char *path;
	dev_t tdev;

	/*
	 * First, search for a devalias which matches this dev_t.
	 * Try all of ttya through ttyz until no such alias
	 */
	(void) strcpy(name, "ttya");
	for (i = 0; i < ('z'-'a'); i++) {
		name[3] = 'a' + i; /* increment device name */
		path = get_alias(name, buf);
		if (path == NULL)
			return (1);

		tdev = ddi_pathname_to_dev_t(path);
		if (tdev == dev)
			break;	/* Exit loop if found */
	}

	if (i >= ('z'-'a'))
		return (1);		/* If we didn't find it, return */

	/*
	 * Now that we know which "tty" this corresponds to, retrieve
	 * the "ttya-mode" options property, which tells us how to configure
	 * the line.
	 */
	(void) strcpy(name, "ttya-mode");	/* name of option we want */
	name[3] = 'a' + i;			/* Adjust to correct line */

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, ddi_root_node(), 0, name,
	    buf, &len) != DDI_PROP_SUCCESS)
		return (1);	/* if no such option, just return */

	/*
	 * The IEEE 1275 standard specifies that /aliases string property
	 * values should be null-terminated.  Unfortunately the reality
	 * is that most aren't and the OBP can't easily be modified to
	 * add null termination to these strings.  So we'll add the
	 * null termination here.  If the string already contains a
	 * null termination character then that's ok too because we'll
	 * just be adding a second one.
	 */
	buf[len] = '\0';

	/* Clear out options we will be setting */
	termiosp->c_cflag &=
	    ~(CSIZE | CBAUD | CBAUDEXT | PARODD | PARENB | CSTOPB);

	/* Clear options which potentially conflict with new settings */
	termiosp->c_cflag &= ~(CIBAUD | CIBAUDEXT);

	/*
	 * Now, parse the string. Wish I could use sscanf().
	 * Format 9600,8,n,1,-
	 * baud rate, bits-per-char, parity, stop-bits, ignored
	 */
	for (ppos = 0; ppos < (MAXPATHLEN-8); ppos++) { /* Find first comma */
		if ((buf[ppos] == 0) || (buf[ppos] == ','))
			break;
	}

	if (buf[ppos] != ',') {
		cmn_err(CE_WARN, "consconfig_setmodes: "
		    "invalid mode string %s", buf);
		return (1);
	}

	for (i = 0; i < MAX_SPEEDS; i++) {
		if (strncmp(buf, speedtab[i].name, ppos) == 0)
			break;
	}

	if (i >= MAX_SPEEDS) {
		cmn_err(CE_WARN,
		    "consconfig_setmodes: unrecognized speed in %s", buf);
		return (1);
	}

	/* Found the baud rate, set it */
	termiosp->c_cflag |= speedtab[i].code & CBAUD;
	if (speedtab[i].code > 16) 			/* cfsetospeed! */
		termiosp->c_cflag |= CBAUDEXT;

	/* Set bits per character */
	switch (buf[ppos+1]) {
	case '8':
		termiosp->c_cflag |= CS8;
		break;
	case '7':
		termiosp->c_cflag |= CS7;
		break;
	default:
		cmn_err(CE_WARN,
		    "consconfig_setmodes: illegal bits-per-char %s", buf);
		return (1);
	}

	/* Set parity */
	switch (buf[ppos+3]) {
	case 'o':
		termiosp->c_cflag |= PARENB | PARODD;
		break;
	case 'e':
		termiosp->c_cflag |= PARENB; /* enabled, not odd */
		break;
	case 'n':
		break;	/* not enabled. */
	default:
		cmn_err(CE_WARN, "consconfig_setmodes: illegal parity %s", buf);
		return (1);
	}

	/* Set stop bits */
	switch (buf[ppos+5]) {
	case '1':
		break;	/* No extra stop bit */
	case '2':
		termiosp->c_cflag |= CSTOPB; /* 1 extra stop bit */
		break;
	default:
		cmn_err(CE_WARN, "consconfig_setmodes: "
		    "illegal stop bits %s", buf);
		return (1);
	}

	return (0);
}

/*
 * Check to see if underlying keyboard devices are still online,
 * if any one is offline now, unlink it.
 */
static void
consconfig_check_phys_kbd(cons_state_t *sp)
{
	ldi_handle_t	kb_lh;
	cons_prop_t	*prop;
	int		error;
	int		rval;

	for (prop = sp->cons_km_prop; prop; prop = prop->cp_next) {
		if ((prop->cp_type != CONS_KBD) || (prop->cp_muxid == -1))
			continue;

		error = ldi_open_by_dev(&prop->cp_dev, OTYP_CHR,
		    FREAD|FWRITE|FNOCTTY, kcred, &kb_lh, sp->cons_li);

		if (error) {
			(void) ldi_ioctl(sp->conskbd_lh, I_PUNLINK,
			    prop->cp_muxid, FKIOCTL, kcred, &rval);
			prop->cp_dev = NODEV;
		} else {
			(void) ldi_close(kb_lh, FREAD|FWRITE, kcred);
		}
	}

	/*
	 * Remove all disconnected keyboards,
	 * whose dev is turned into NODEV above.
	 */
	consconfig_rem_dev(sp, NODEV);
}

/*
 * Remove devices according to dev, which may be NODEV
 */
static void
consconfig_rem_dev(cons_state_t *sp, dev_t dev)
{
	cons_prop_t *prop;
	cons_prop_t *prev_prop;
	cons_prop_t *tmp_prop;
	cons_prop_t *head_prop;

	head_prop = NULL;
	prev_prop = NULL;
	for (prop = sp->cons_km_prop; prop != NULL; ) {
		if (prop->cp_dev == dev) {
			tmp_prop = prop->cp_next;
			consconfig_free_prop(prop);
			prop = tmp_prop;
			if (prev_prop)
				prev_prop->cp_next = prop;
		} else {
			if (head_prop == NULL)
				head_prop = prop;
			prev_prop = prop;
			prop = prop->cp_next;
		}
	}
	sp->cons_km_prop = head_prop;
}

/*
 * Add a dev according to prop
 */
static void
consconfig_add_dev(cons_state_t *sp, cons_prop_t *prop)
{
	prop->cp_next = sp->cons_km_prop;
	sp->cons_km_prop = prop;
}

/*
 * Find a device from our list according to dev
 */
static cons_prop_t *
consconfig_find_dev(cons_state_t *sp, dev_t dev)
{
	cons_prop_t *prop;

	for (prop = sp->cons_km_prop; prop; prop = prop->cp_next) {
		if (prop->cp_dev == dev)
			break;
	}

	return (prop);
}

/*
 * Free a cons prop associated with a keyboard or mouse
 */
static void
consconfig_free_prop(cons_prop_t *prop)
{
	if (prop->cp_pushmod)
		kmem_free(prop->cp_pushmod, strlen(prop->cp_pushmod) + 1);
	kmem_free(prop, sizeof (cons_prop_t));
}

/*
 * The early boot code can't print to a usb serial device or the
 * graphical boot screen.
 *
 * The early boot messages are saved in a buffer at the address indicated
 * by "deferred-console-buf" This function flushes the message to the
 * current console now that it is set up.
 */
static void
flush_deferred_console_buf(void)
{
	int rval;
	vnode_t *vp;
	uint_t defcons_buf;
	char *kc, *bc, *defcons_kern_buf;

	/* defcons_buf is in low memory, so an int works here */
	defcons_buf = ddi_prop_get_int(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "deferred-console-buf", 0);

	if (defcons_buf == 0)
		return;

	/*
	 * After consconfig() and before userland opens /dev/sysmsg,
	 * console I/O is goes to polled I/O entry points.
	 *
	 * If usb-serial doesn't implement polled I/O, we need
	 * to open /dev/console now to get kernel console I/O to work.
	 * We also push ttcompat and ldterm explicitly to get the
	 * correct output format (autopush isn't set up yet). We
	 * ignore push errors because they are non-fatal.
	 * Note that opening /dev/console causes rconsvp to be
	 * opened as well.
	 */
	if (cons_polledio == NULL) {
		if (vn_open("/dev/console", UIO_SYSSPACE, FWRITE | FNOCTTY,
		    0, &vp, 0, 0) != 0)
			return;

		if (rconsvp) {
			(void) strioctl(rconsvp, __I_PUSH_NOCTTY,
			    (intptr_t)"ldterm", FKIOCTL, K_TO_K, kcred, &rval);
			(void) strioctl(rconsvp, __I_PUSH_NOCTTY,
			    (intptr_t)"ttcompat", FKIOCTL, K_TO_K,
			    kcred, &rval);
		}
	}

	/*
	 * Copy message to a kernel buffer. Various kernel routines
	 * expect buffer to be above kernelbase
	 */
	kc = defcons_kern_buf = kmem_zalloc(MMU_PAGESIZE, KM_SLEEP);
	bc = (char *)(uintptr_t)defcons_buf;
	while (*kc++ = *bc++)
		;
	console_printf("%s", defcons_kern_buf);

	kmem_free(defcons_kern_buf, MMU_PAGESIZE);
}

boolean_t
consconfig_console_is_tipline(void)
{
	cons_state_t	*sp;

	if ((sp = (cons_state_t *)space_fetch("consconfig")) == NULL)
		return (B_FALSE);

	if (sp->cons_input_type == CONSOLE_TIP)
		return (B_TRUE);

	return (B_FALSE);
}

boolean_t
consconfig_dacf_initialized(void)
{
	cons_state_t	*sp;

	if ((sp = (cons_state_t *)space_fetch("consconfig")) == NULL)
		return (B_FALSE);

	return (sp->cons_initialized);
}
