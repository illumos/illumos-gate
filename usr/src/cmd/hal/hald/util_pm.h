/***************************************************************************
 * CVSID: $Id$
 *
 * util_pm.h - Various Powermanagement related  utilities
 *
 * Copyright (C) 2005 Richard Hughes <richard@hughsie.com>
 * Copyright (C) 2005 Danny Kukawka <danny.kukawka@web.de>
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/

#ifndef UTIL_PM_H
#define UTIL_PM_H

const char *util_get_battery_technology (const char *type);

int util_compute_time_remaining (const char *id, int chargeRate, int chargeLevel, int chargeLastFull,
				 gboolean isDischarging, gboolean isCharging, gboolean guessChargeRate);

int util_compute_percentage_charge (const char *id, int chargeLevel, int chargeLastFull);

#endif /* UTIL__PM_H */
