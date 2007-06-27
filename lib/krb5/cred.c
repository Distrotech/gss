/* krb5/cred.c --- Kerberos 5 GSS-API credential management functions.
 * Copyright (C) 2003, 2004, 2005, 2006, 2007  Simon Josefsson
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

/* Get specification. */
#include "k5internal.h"

static OM_uint32
acquire_cred1 (OM_uint32 * minor_status,
	       const gss_name_t desired_name,
	       OM_uint32 time_req,
	       const gss_OID_set desired_mechs,
	       gss_cred_usage_t cred_usage,
	       gss_cred_id_t * output_cred_handle,
	       gss_OID_set * actual_mechs, OM_uint32 * time_rec)
{
  gss_name_t name = desired_name;
  _gss_krb5_cred_t k5 = (*output_cred_handle)->krb5;
  OM_uint32 maj_stat;

  if (desired_name == GSS_C_NO_NAME)
    {
      gss_buffer_desc buf = { 4, "host" };

      maj_stat = gss_import_name (minor_status, &buf,
				  GSS_C_NT_HOSTBASED_SERVICE, &name);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
    }

  maj_stat = gss_krb5_canonicalize_name (minor_status, name,
					 GSS_KRB5, &k5->peerptr);
  if (GSS_ERROR (maj_stat))
    return maj_stat;

  if (desired_name == GSS_C_NO_NAME)
    {
      maj_stat = gss_release_name (minor_status, &name);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
    }

  if (shishi_init_server (&k5->sh) != SHISHI_OK)
    return GSS_S_FAILURE;

  {
    char *p;

    p = xmalloc (k5->peerptr->length + 1);
    memcpy (p, k5->peerptr->value, k5->peerptr->length);
    p[k5->peerptr->length] = 0;

    k5->key = shishi_hostkeys_for_serverrealm (k5->sh, p, NULL);

    free (p);
  }

  if (!k5->key)
    {
      if (minor_status)
	*minor_status = GSS_KRB5_S_KG_KEYTAB_NOMATCH;
      return GSS_S_NO_CRED;
    }

  if (time_rec)
    *time_rec = GSS_C_INDEFINITE;

  return GSS_S_COMPLETE;
}

OM_uint32
gss_krb5_acquire_cred (OM_uint32 * minor_status,
		       const gss_name_t desired_name,
		       OM_uint32 time_req,
		       const gss_OID_set desired_mechs,
		       gss_cred_usage_t cred_usage,
		       gss_cred_id_t * output_cred_handle,
		       gss_OID_set * actual_mechs, OM_uint32 * time_rec)
{
  OM_uint32 maj_stat;
  gss_cred_id_t p = *output_cred_handle;

  if (actual_mechs)
    {
      maj_stat = gss_create_empty_oid_set (minor_status, actual_mechs);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
      maj_stat = gss_add_oid_set_member (minor_status, GSS_KRB5,
					 actual_mechs);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
    }

  p->krb5 = xcalloc (sizeof (*p->krb5), 1);

  maj_stat = acquire_cred1 (minor_status, desired_name, time_req,
			    desired_mechs, cred_usage,
			    &p, actual_mechs, time_rec);
  if (GSS_ERROR (maj_stat))
    {
      if (actual_mechs)
	gss_release_oid_set (NULL, actual_mechs);
      free (p->krb5);

      return maj_stat;
    }

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

static OM_uint32
inquire_cred (OM_uint32 * minor_status,
	      const gss_cred_id_t cred_handle,
	      gss_name_t * name,
	      OM_uint32 * lifetime,
	      gss_cred_usage_t * cred_usage, gss_OID_set * mechanisms)
{
  OM_uint32 maj_stat;

  if (cred_handle == GSS_C_NO_CREDENTIAL)
    return GSS_S_NO_CRED;

  if (mechanisms)
    {
      maj_stat = gss_create_empty_oid_set (minor_status, mechanisms);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
      maj_stat = gss_add_oid_set_member (minor_status, GSS_KRB5, mechanisms);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
    }

  if (name)
    {
      maj_stat = gss_duplicate_name (minor_status, cred_handle->krb5->peerptr,
				     name);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
    }

  if (cred_usage)
    *cred_usage = GSS_C_BOTH;

  if (lifetime)
    *lifetime = GSS_C_INDEFINITE;

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

OM_uint32
gss_krb5_inquire_cred (OM_uint32 * minor_status,
		       const gss_cred_id_t cred_handle,
		       gss_name_t * name,
		       OM_uint32 * lifetime,
		       gss_cred_usage_t * cred_usage,
		       gss_OID_set * mechanisms)
{
  return inquire_cred (minor_status, cred_handle, name, lifetime,
		       cred_usage, mechanisms);
}

OM_uint32
gss_krb5_inquire_cred_by_mech (OM_uint32 * minor_status,
			       const gss_cred_id_t cred_handle,
			       const gss_OID mech_type,
			       gss_name_t * name,
			       OM_uint32 * initiator_lifetime,
			       OM_uint32 * acceptor_lifetime,
			       gss_cred_usage_t * cred_usage)
{
  OM_uint32 maj_stat;

  maj_stat = inquire_cred (minor_status, cred_handle, name,
			   initiator_lifetime, cred_usage, NULL);

  if (acceptor_lifetime)
    *acceptor_lifetime = *initiator_lifetime;

  return maj_stat;
}

OM_uint32
gss_krb5_release_cred (OM_uint32 * minor_status, gss_cred_id_t * cred_handle)
{
  _gss_krb5_cred_t k5 = (*cred_handle)->krb5;

  if (k5->peerptr != GSS_C_NO_NAME)
    gss_release_name (NULL, &k5->peerptr);

  shishi_key_done (k5->key);
  shishi_done (k5->sh);
  free (k5);

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}
