/* meta.c	Implementation of function selection depending on mechanism.
 * Copyright (C) 2003  Simon Josefsson
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
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

#include "internal.h"

#ifdef USE_KERBEROS5
#include "krb5.h"
#endif

OM_uint32 _gss_dummy (OM_uint32 minor_status, ...)
{
  fprintf (stderr, "warning: no suitable mechanism found\n");
  return GSS_S_BAD_MECH;
}

_gss_mech_api_desc _gss_mech_apis[] = {
#ifdef USE_KERBEROS5
  {
    &GSS_KRB5,
    gss_krb5_init_sec_context,
    gss_krb5_canonicalize_name,
    gss_krb5_wrap,
    gss_krb5_unwrap
  },
#endif
  {
    0,
    _gss_dummy,
    _gss_dummy,
    _gss_dummy,
    _gss_dummy
  }
};

_gss_mech_api_t
_gss_find_mech (gss_OID oid)
{
  int i;
  if (oid == GSS_C_NO_OID)
    return &_gss_mech_apis[0];
  for (i = 0; i < sizeof(_gss_mech_apis) / sizeof(_gss_mech_apis[0]); i++)
    if (_gss_mech_apis[i].mech && gss_oid_equal (oid, *_gss_mech_apis[i].mech))
      return &_gss_mech_apis[i];
  return &_gss_mech_apis[i-1];
}
