/* meta.c --- Implementation of function selection depending on mechanism.
 * Copyright (C) 2003-2011 Simon Josefsson
 *
 * This file is part of the Generic Security Service (GSS).
 *
 * GSS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GSS is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GSS; if not, see http://www.gnu.org/licenses or write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA.
 *
 */

#include "internal.h"
#include "meta.h"

#ifdef USE_KERBEROS5
# include <gss/krb5.h>
# include "krb5/protos.h"
#endif

static _gss_mech_api_desc _gss_mech_apis[] = {
#ifdef USE_KERBEROS5
  {
   &GSS_KRB5_static,
   "GS2-KRB5",
   "Kerberos V5",
   N_("Kerberos V5 GSS-API mechanism"),
   {
    /* Mandatory name-types. */
    &GSS_KRB5_NT_PRINCIPAL_NAME_static,
    &GSS_C_NT_HOSTBASED_SERVICE_static,
    &GSS_C_NT_EXPORT_NAME_static},
   gss_krb5_init_sec_context,
   gss_krb5_canonicalize_name,
   gss_krb5_export_name,
   gss_krb5_wrap,
   gss_krb5_unwrap,
   gss_krb5_get_mic,
   gss_krb5_verify_mic,
   gss_krb5_display_status,
   gss_krb5_acquire_cred,
   gss_krb5_release_cred,
   gss_krb5_accept_sec_context,
   gss_krb5_delete_sec_context,
   gss_krb5_context_time,
   gss_krb5_inquire_cred,
   gss_krb5_inquire_cred_by_mech},
#endif
  {
   NULL,
   NULL,
   NULL,
   NULL,
   {
    NULL,
    NULL,
    NULL},
   NULL,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL}
};

_gss_mech_api_t
_gss_find_mech_no_default (const gss_OID oid)
{
  size_t i;

  for (i = 0; _gss_mech_apis[i].mech; i++)
    if (gss_oid_equal (oid, _gss_mech_apis[i].mech))
      return &_gss_mech_apis[i];

  return NULL;
}

_gss_mech_api_t
_gss_find_mech (const gss_OID oid)
{
  _gss_mech_api_t p = _gss_find_mech_no_default (oid);

  if (!p && _gss_mech_apis[0].mech)
    /* FIXME.  When we support more than one mechanism, make it possible
       to configure the default mechanism. */
    return &_gss_mech_apis[0];

  return p;
}

_gss_mech_api_t
_gss_find_mech_by_saslname (const gss_buffer_t sasl_mech_name)
{
  size_t i;

  if (sasl_mech_name == NULL
      || sasl_mech_name->value == NULL || sasl_mech_name->length == 0)
    return NULL;

  for (i = 0; _gss_mech_apis[i].mech; i++)
    if (strlen (_gss_mech_apis[i].sasl_name) == sasl_mech_name->length &&
	memcmp (_gss_mech_apis[i].sasl_name, sasl_mech_name->value,
		sasl_mech_name->length) == 0)
      return &_gss_mech_apis[i];

  return NULL;
}

OM_uint32
_gss_indicate_mechs1 (OM_uint32 * minor_status, gss_OID_set * mech_set)
{
  OM_uint32 maj_stat;
  int i;

  for (i = 0; _gss_mech_apis[i].mech; i++)
    {
      maj_stat = gss_add_oid_set_member (minor_status,
					 _gss_mech_apis[i].mech, mech_set);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
    }

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}
