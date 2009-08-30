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

#ifndef	_SYS_AC97_IMPL_H
#define	_SYS_AC97_IMPL_H

typedef void (*ac97_set_t)(ac97_ctrl_t *, uint64_t);

/*
 * Per control state
 */
struct ac97_ctrl {
	list_node_t		actrl_linkage;  /* For private cntrls list */
	struct ac97		*actrl_ac97;
	int			actrl_bits;	/* Port width */
	audio_ctrl_t		*actrl_ctrl;    /* control framework handle */
	ac97_set_t		actrl_write_fn; /* control write function */
	uint64_t		actrl_value;    /* current value in port */
	uint64_t		actrl_initval;  /* initial value in port */
	uint16_t		actrl_muteable; /* if muteable, bits for it */
	boolean_t		actrl_suppress;	/* if true, do not register */
	audio_ctrl_desc_t	actrl_desc;	/* ctrl desc structure */
#define	actrl_name		actrl_desc.acd_name
#define	actrl_minval		actrl_desc.acd_minvalue
#define	actrl_maxval		actrl_desc.acd_maxvalue
#define	actrl_type		actrl_desc.acd_type
#define	actrl_flags		actrl_desc.acd_flags
#define	actrl_enum		actrl_desc.acd_enum
};

/*
 * Function Type used on controls that are optional
 * This will return non-zero if the control should be
 * installed and configured.
 */
typedef int (*cp_probe_t)(ac97_t *ac);


/*
 * This is used to enumerate and probe all controls that are
 * supported and configurable on AC97 hardware
 */
typedef struct ac97_ctrl_probe {
	const char	*cp_name;	/* name of control */
	uint64_t	cp_initval;	/* Initial value for control */
	uint64_t	cp_minval;	/* MIN value for control */
	uint64_t	cp_maxval;	/* MAX value for control */
	uint32_t	cp_type;	/* Type of control */
	uint32_t	cp_flags;	/* control type flags */
	uint16_t	cp_muteable;	/* Mute bit mask */
	ac97_set_t	cp_write_fn;	/* control write function */
	cp_probe_t	cp_probe;	/* Probe if control exists */
	int		cp_bits;	/* Bits for volume controls */
	const char	**cp_enum;	/* Enumeration value */
} ac97_ctrl_probe_t;

/*
 * These are the flags for most of our controls
 */
#define	AC97_RW		(AUDIO_CTRL_FLAG_READABLE | AUDIO_CTRL_FLAG_WRITEABLE)
#define	AC97_FLAGS	(AC97_RW | AUDIO_CTRL_FLAG_POLL)

void ac_wr(ac97_t *, uint8_t, uint16_t);
uint16_t ac_rd(ac97_t *, uint8_t);
void ac_clr(ac97_t *, uint8_t, uint16_t);
void ac_set(ac97_t *, uint8_t, uint16_t);
void ac_add_control(ac97_t *, ac97_ctrl_probe_t *);
uint16_t ac_val_scale(int left, int right, int bits);
uint16_t ac_mono_scale(int val, int bits);
audio_dev_t *ac_get_dev(ac97_t *);
int ac_get_prop(ac97_t *, char *, int);

/* Codec specific initializations */

void ad1981a_init(ac97_t *);
void ad1981b_init(ac97_t *);

void alc650_init(ac97_t *);
void alc850_init(ac97_t *);

void cmi9738_init(ac97_t *);
void cmi9739_init(ac97_t *);
void cmi9761_init(ac97_t *);

#endif	/* _SYS_AC97_IMPL_H */
