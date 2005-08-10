/* krb5/utils.c --- Kerberos 5 GSS-API helper functions.
 * Copyright (C) 2003, 2004  Simon Josefsson
 *
 * This file is part of the Generic Security Service (GSS).
 *
 * GSS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GSS is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GSS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

/* Get specification. */
#include "k5internal.h"

/* Return number of seconds left of ticket lifetime, or 0 if ticket
   has expired, or GSS_C_INDEFINITE if ticket is NULL. */
OM_uint32
gss_krb5_tktlifetime (Shishi_tkt * tkt)
{
  time_t now, end;

  if (!tkt)
    return GSS_C_INDEFINITE;

  if (!shishi_tkt_valid_now_p (tkt))
    return 0;

  now = time (NULL);
  end = shishi_tkt_endctime (tkt);

  return end - now;
}
