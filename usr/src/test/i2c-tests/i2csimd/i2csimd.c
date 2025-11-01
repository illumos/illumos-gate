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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * This daemon is the userland component to i2csim(4D). It has a built in notion
 * of I2C devices that it emulates to allow for better end-to-end testing.
 */

#include <stdlib.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <paths.h>
#include <sys/resource.h>
#include <sys/fork.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <priv.h>
#include <sys/debug.h>
#include <string.h>
#include <sys/sysmacros.h>

#include "i2csimd.h"

i2csimd_t i2csimd;

static const char *at24c_msg0 = "Three rings for Elven-kings, under the sky,";
static const char *at24c_msg1 = "Seven for the Dwarf-lords in their halls of "
	"stone,";
static const char *at24c_msg2 = "Nine for Moral Men, doomed to die,";
static const char *at24c_msg3 = "One for the dark Lord on his dark throne";
static const char *at24c_msg4 = "In the Land of Mordor where the Shadows lie.";
static const char *at24c_msg5 = "One ring to rule them all, One ring to find "
	"them,";
static const char *at24c_msg6 = "One ring to bring them all and in the "
	"darkness bind them.";
static const char *at24c_msg71 = "The Road goes ever on and on,\nDown from the "
	"door where it began.\nNow far ahead the Road has gone,\nAnd I must "
	"follow, if I can,\nPursuing it with eager feet,\nUntil it joins some "
	"larger way\nWhere many paths and errands meet.\nAnd whither then? I "
	"cannot say.";

/*
 * Initialize everything we need to answer and serve requests:
 *
 *  - The general fd to the i2csim device
 *  - All of the actual i2c devices that we have in our tree
 *
 * Tree for i2csim0
 *  at24c32: 0x10
 *  at24c16: 0x20
 *  pca9548: 0x70
 *    0: - pca9548 0x71
 *	0: at24c32: 0x72 - at24c_msg0
 *	1: at24c32: 0x72 - at24c_msg1
 *	2: at24c32: 0x72 - at24c_msg2
 *	3: at24c32: 0x72 - at24c_msg3
 *	4: at24c32: 0x72 - at24c_msg4
 *	5: at24c32: 0x72 - at24c_msg5
 *	6: at24c32: 0x72 - at24c_msg6
 *	7: at24c32: 0x72 - at24c_msg4
 *    1: - at24c32 0x71 - at24c_msg71
 *    2: - ts511x 0x71 - 71 C
 *    2: - ts511x 0x72 - 72.75 C
 *    3: - ts511x 0x71 - 169 C
 *    3: - ts511x 0x72 - -23.75 C
 */
static void
i2csimd_init(i2csimd_t *simd)
{
	i2csimd_port_t *mux0, *mux1;

	simd->simd_fd = open("/devices/pseudo/i2csim@0:ctrl", O_RDWR);
	if (simd->simd_fd < 0) {
		err(EXIT_FAILURE, "failed to open i2csim driver");
	}

	simd->simd_ports[0].port_ctrl = 0;
	simd->simd_ports[0].port_num = 0;
	simd->simd_ports[0].port_devs[0x10] = i2csimd_make_at24c32(0x10, NULL,
	    0);
	simd->simd_ports[0].port_devs[0x20] = i2csimd_make_at24cXX(0x20,
	    at24c_msg0, strlen(at24c_msg0));
	simd->simd_ports[0].port_devs[0x21] = i2csimd_make_at24cXX(0x21,
	    at24c_msg1, strlen(at24c_msg1));
	simd->simd_ports[0].port_devs[0x22] = i2csimd_make_at24cXX(0x22,
	    at24c_msg2, strlen(at24c_msg2));
	simd->simd_ports[0].port_devs[0x23] = i2csimd_make_at24cXX(0x23,
	    at24c_msg3, strlen(at24c_msg3));

	mux0 = calloc(8, sizeof (i2csimd_port_t));
	mux1 = calloc(8, sizeof (i2csimd_port_t));
	if (mux0 == NULL || mux1 == NULL) {
		err(EXIT_FAILURE, "failed to allocate mux ports");
	}

	for (uint32_t i = 0; i < 8; i++) {
		mux0[i].port_ctrl = 0;
		mux1[i].port_ctrl = 0;

		mux0[i].port_num = i;
		mux1[i].port_num = i;
	}

	mux1[0].port_devs[0x72] = i2csimd_make_at24c32(0x72, at24c_msg0,
	    strlen(at24c_msg0));
	mux1[1].port_devs[0x72] = i2csimd_make_at24c32(0x72, at24c_msg1,
	    strlen(at24c_msg1));
	mux1[2].port_devs[0x72] = i2csimd_make_at24c32(0x72, at24c_msg2,
	    strlen(at24c_msg2));
	mux1[3].port_devs[0x72] = i2csimd_make_at24c32(0x72, at24c_msg3,
	    strlen(at24c_msg3));
	mux1[4].port_devs[0x72] = i2csimd_make_at24c32(0x72, at24c_msg4,
	    strlen(at24c_msg4));
	mux1[5].port_devs[0x72] = i2csimd_make_at24c32(0x72, at24c_msg5,
	    strlen(at24c_msg5));
	mux1[6].port_devs[0x72] = i2csimd_make_at24c32(0x72, at24c_msg6,
	    strlen(at24c_msg6));
	mux1[7].port_devs[0x72] = i2csimd_make_at24c32(0x72, at24c_msg4,
	    strlen(at24c_msg4));

	mux0[0].port_devs[0x71] = i2csimd_make_pca9548(0x71,
	    &simd->simd_ports[0], mux1);
	mux0[1].port_devs[0x71] = i2csimd_make_at24c32(0x71, at24c_msg71,
	    strlen(at24c_msg71));
	mux0[2].port_devs[0x71] = i2csimd_make_ts5111(0x71, 0x0470);
	mux0[2].port_devs[0x72] = i2csimd_make_ts5111(0x72, 0x048c);
	mux0[3].port_devs[0x71] = i2csimd_make_ts5111(0x71, 0x0a90);
	mux0[3].port_devs[0x72] = i2csimd_make_ts5111(0x72, 0x1e84);

	simd->simd_ports[0].port_devs[0x70] = i2csimd_make_pca9548(0x70,
	    &simd->simd_ports[0], mux0);
}

static void
i2csimd_io_error(i2csimd_t *simd, i2c_errno_t err, i2c_ctrl_error_t ctrl)
{
	i2c_error_t *ep;

	if (simd->simd_req.i2csim_type == I2C_CTRL_TYPE_I2C) {
		ep = &simd->simd_req.i2csim_i2c.ir_error;
	} else {
		ep = &simd->simd_req.i2csim_smbus.smbr_error;
	}

	ep->i2c_error = err;
	ep->i2c_ctrl = ctrl;
}

static void
i2csimd_i2c(i2csimd_t *simd, i2csimd_dev_t *dev, i2c_req_t *req)
{
	if (req->ir_wlen > 0) {
		if (!dev->dev_ops->sop_write(dev->dev_arg, req->ir_wlen,
		    req->ir_wdata)) {
			i2csimd_io_error(simd, I2C_CORE_E_CONTROLLER,
			    I2C_CTRL_E_DATA_NACK);
			return;
		}
	}

	if (req->ir_rlen > 0) {
		if (!dev->dev_ops->sop_read(dev->dev_arg, req->ir_rlen,
		    req->ir_rdata)) {
			i2csimd_io_error(simd, I2C_CORE_E_CONTROLLER,
			    I2C_CTRL_E_DATA_NACK);
			return;
		}
	}

	i2csimd_io_error(simd, I2C_CORE_E_OK, I2C_CTRL_E_OK);
}

static void
i2csimd_smbus(i2csimd_t *simd, i2csimd_dev_t *dev, smbus_req_t *req)
{
	err(EXIT_FAILURE, "implement me");
}

static void
i2csimd_serve(i2csimd_t *simd)
{
	for (;;) {
		i2csimd_port_t *port = NULL;
		i2csim_req_t *req = &simd->simd_req;
		const i2c_addr_t *addr;

		if (ioctl(simd->simd_fd, I2CSIM_REQUEST, req) != 0) {
			err(EXIT_FAILURE, "failed to get I2C sim request");
		}

		switch (req->i2csim_type) {
		case I2C_CTRL_TYPE_I2C:
			addr = &req->i2csim_i2c.ir_addr;
			break;
		case I2C_CTRL_TYPE_SMBUS:
			addr = &req->i2csim_smbus.smbr_addr;
			break;
		default:
			i2csimd_io_error(simd, I2C_CORE_E_CONTROLLER,
			    I2C_CTRL_E_INTERNAL);
			goto reply;
		}

		/*
		 * Find the controller and port this corresponds to and see if
		 * there is a logical device there. If we don't know the port,
		 * fail with an internal controller error. If there's no device
		 * there NACK.
		 */
		for (size_t i = 0; i < ARRAY_SIZE(simd->simd_ports); i++) {
			if (simd->simd_ports[i].port_ctrl == req->i2csim_ctrl &&
			    simd->simd_ports[i].port_num == req->i2csim_port) {
				port = &simd->simd_ports[i];
				break;
			}
		}

		if (port == NULL) {
			i2csimd_io_error(simd, I2C_CORE_E_CONTROLLER,
			    I2C_CTRL_E_INTERNAL);
			goto reply;
		}

		if (addr->ia_type != I2C_ADDR_7BIT ||
		    addr->ia_addr >= 1 << 7) {
			i2csimd_io_error(simd, I2C_CORE_E_CONTROLLER,
			    I2C_CTRL_E_INTERNAL);
			goto reply;
		}

		i2csimd_dev_t *dev = port->port_devs[addr->ia_addr];
		if (dev == NULL) {
			i2csimd_io_error(simd, I2C_CORE_E_CONTROLLER,
			    I2C_CTRL_E_ADDR_NACK);
			goto reply;
		}

		/*
		 * We have found a device, send it the I/O request.
		 */
		if (req->i2csim_type == I2C_CTRL_TYPE_I2C) {
			i2csimd_i2c(simd, dev, &req->i2csim_i2c);
		} else {
			i2csimd_smbus(simd, dev, &req->i2csim_smbus);
		}

reply:
		if (ioctl(simd->simd_fd, I2CSIM_REPLY, req) != 0) {
			err(EXIT_FAILURE, "failed to submit I2C sim reply");
		}
	}
}

int
main(void)
{
	int dupfd, ret = 0;
	struct rlimit rlim;
	int pfds[2];
	pid_t child;
	priv_set_t *pset;

	/*
	 * Get all of our file descriptors to a reasonable state before we do
	 * anything.
	 */
	closefrom(STDERR_FILENO + 1);
	dupfd = open(_PATH_DEVNULL, O_RDONLY);
	if (dupfd < 0) {
		err(EXIT_FAILURE, "failed to open %s", _PATH_DEVNULL);
	}
	if (dup2(dupfd, STDIN_FILENO) == -1) {
		err(EXIT_FAILURE, "failed to dup out stdin");
	}
	VERIFY0(close(dupfd));


	i2csimd_init(&i2csimd);

	/*
	 * Now go ahead and do all the prep to daemonize.
	 */
	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;
	(void) setrlimit(RLIMIT_CORE, &rlim);

	if (chdir("/var/run") != 0) {
		err(EXIT_FAILURE, "failed to chdir to /var/run");
	}

	if (pipe(pfds) != 0) {
		err(EXIT_FAILURE, "failed to create pipes to daemonize");
	}

	child = forkx(FORK_NOSIGCHLD | FORK_WAITPID);
	if (child == -1) {
		err(EXIT_FAILURE, "failed to fork child");
	}

	if (child != 0) {
		int estatus;

		(void) close(pfds[1]);
		if (read(pfds[0], &estatus, sizeof (estatus)) ==
		    sizeof (estatus)) {
			_exit(estatus);
		}

		if (waitpid(child, &estatus, 0) == child &&
		    WIFEXITED(estatus)) {
			_exit(WEXITSTATUS(estatus));
		}

		_exit(EXIT_FAILURE);
	}

	VERIFY0(setgroups(0, NULL));
	VERIFY0(setgid(GID_NOBODY));
	VERIFY0(setuid(UID_NOBODY));

	if ((pset = priv_allocset()) == NULL) {
		err(EXIT_FAILURE, "failed to allocate privilege set");
	}

	priv_basicset(pset);
	if (priv_delset(pset, PRIV_PROC_EXEC) == -1 ||
	    priv_delset(pset, PRIV_PROC_FORK) == -1 ||
	    priv_delset(pset, PRIV_PROC_INFO) == -1 ||
	    priv_delset(pset, PRIV_PROC_SESSION) == -1 ||
	    priv_delset(pset, PRIV_FILE_LINK_ANY) == -1 ||
	    priv_delset(pset, PRIV_PROC_SECFLAGS) == -1 ||
	    priv_delset(pset, PRIV_NET_ACCESS) == -1) {
		err(EXIT_FAILURE, "failed to construct privilege set");
	}

	if (setppriv(PRIV_SET, PRIV_PERMITTED, pset) == -1) {
		err(EXIT_FAILURE, "failed to set permitted privileges");
	}

	if (setppriv(PRIV_SET, PRIV_PERMITTED, pset) == -1) {
		err(EXIT_FAILURE, "failed to set effective privileges");
	}

	priv_freeset(pset);

	VERIFY0(close(pfds[0]));
	VERIFY3U(setsid(), !=, (pid_t)-1);

	(void) write(pfds[1], &ret, sizeof (ret));
	VERIFY0(close(pfds[1]));

	i2csimd_serve(&i2csimd);
	return (EXIT_SUCCESS);
}
