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

OM_uint32
_gss_dummy (OM_uint32 minor_status, ...)
{
  fprintf (stderr, "warning: no suitable mechanism found\n");
  return GSS_S_BAD_MECH;
}

OM_uint32
_gss_dummy_display_status (OM_uint32 * minor_status,
			   OM_uint32 status_value,
			   int status_type,
			   const gss_OID mech_type,
			   OM_uint32 * message_context,
			   gss_buffer_t status_string)
{
  status_string->value = strdup("No suitable mechanism supported");
  status_string->length = strlen(status_string->value);
  return GSS_S_COMPLETE;
}

_gss_mech_api_desc _gss_mech_apis[] = {
#ifdef USE_KERBEROS5
  {
    &GSS_KRB5_static,
    { &GSS_KRB5_NT_USER_NAME_static,
      &GSS_C_NT_HOSTBASED_SERVICE_static,
      &GSS_KRB5_NT_PRINCIPAL_NAME_static,
      &GSS_KRB5_NT_STRING_UID_NAME_static },
    gss_krb5_init_sec_context,
    gss_krb5_canonicalize_name,
    gss_krb5_wrap,
    gss_krb5_unwrap,
    _gss_dummy,
    _gss_dummy,
    gss_krb5_display_status
  },
#endif
  {
    0,
    { },
    _gss_dummy,
    _gss_dummy,
    _gss_dummy,
    _gss_dummy,
    _gss_dummy,
    _gss_dummy,
    _gss_dummy_display_status
  }
};

_gss_mech_api_t
_gss_find_mech (gss_OID oid)
{
  int i;
  if (oid == GSS_C_NO_OID)
    return &_gss_mech_apis[0];
  for (i = 0; i < sizeof(_gss_mech_apis) / sizeof(_gss_mech_apis[0]); i++)
    if (gss_oid_equal (oid, _gss_mech_apis[i].mech))
      return &_gss_mech_apis[i];
  return &_gss_mech_apis[i-1];
}

OM_uint32
gss_indicate_mechs (OM_uint32 * minor_status, gss_OID_set * mech_set)
{
  OM_uint32 maj_stat;
  gss_OID_set oids;
  int i;

  maj_stat = gss_create_empty_oid_set (minor_status, mech_set);
  if (maj_stat != GSS_S_COMPLETE)
    return maj_stat;

  for (i = 0; i < sizeof(_gss_mech_apis) / sizeof(_gss_mech_apis[0]) - 1; i++)
    {
      maj_stat = gss_add_oid_set_member (minor_status, _gss_mech_apis[i].mech,
					 mech_set);
      if (maj_stat != GSS_S_COMPLETE)
	{
	  gss_release_oid_set (minor_status, mech_set);
	  return maj_stat;
	}
    }

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

OM_uint32
gss_inquire_names_for_mech (OM_uint32 * minor_status,
			    const gss_OID mechanism, gss_OID_set * name_types)
{
  OM_uint32 maj_stat;
  _gss_mech_api_t mech;
  int i;

  mech = _gss_find_mech (mechanism);

  maj_stat = gss_create_empty_oid_set (minor_status, name_types);
  if (maj_stat != GSS_S_COMPLETE)
    return maj_stat;

  for (i = 0; mech->name_types[i]; i++)
    {
      maj_stat = gss_add_oid_set_member (minor_status, mech->name_types[i],
					 name_types);
      if (maj_stat != GSS_S_COMPLETE)
	{
	  gss_release_oid_set (minor_status, name_types);
	  return maj_stat;
	}
    }

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

static OM_uint32
_gss_inquire_mechs_for_name2 (OM_uint32 * minor_status,
			      _gss_mech_api_t mech,
			      gss_OID name_type,
			      gss_OID_set *mech_types)
{
  gss_OID_set oids;
  int supported;
  OM_uint32 maj_stat;

  maj_stat = gss_inquire_names_for_mech (minor_status, mech->mech, &oids);
  if (maj_stat != GSS_S_COMPLETE)
    return maj_stat;

  maj_stat = gss_test_oid_set_member (minor_status, name_type,
				      oids, &supported);
  if (maj_stat != GSS_S_COMPLETE)
    {
      gss_release_oid_set (minor_status, &oids);
      return maj_stat;
    }

  if (supported)
    {
      maj_stat = gss_add_oid_set_member (minor_status,
					 mech->mech,
					 mech_types);
      if (maj_stat != GSS_S_COMPLETE)
	{
	  gss_release_oid_set (minor_status, &oids);
	  return maj_stat;
	}
    }
  gss_release_oid_set (minor_status, &oids);

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

static OM_uint32
_gss_inquire_mechs_for_name1 (OM_uint32 * minor_status,
			      gss_OID name_type,
			      gss_OID_set *mech_types)
{
  OM_uint32 maj_stat;
  int i;

  for (i = 0; i < sizeof(_gss_mech_apis) / sizeof(_gss_mech_apis[0]) - 1; i++)
    {
      maj_stat = _gss_inquire_mechs_for_name2 (minor_status,
					       &_gss_mech_apis[i],
					       name_type,
					       mech_types);
      if (maj_stat != GSS_S_COMPLETE)
	return maj_stat;
    }

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

OM_uint32
gss_inquire_mechs_for_name (OM_uint32 * minor_status,
			    const gss_name_t input_name,
			    gss_OID_set * mech_types)
{
  int i;
  OM_uint32 maj_stat;

  maj_stat = gss_create_empty_oid_set (minor_status, mech_types);
  if (maj_stat != GSS_S_COMPLETE)
    return maj_stat;

  maj_stat = _gss_inquire_mechs_for_name1 (minor_status, input_name->type,
					   mech_types);
  if (maj_stat != GSS_S_COMPLETE)
    {
      gss_release_oid_set (minor_status, mech_types);
      return maj_stat;
    }

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}
