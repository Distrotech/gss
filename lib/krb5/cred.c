/* krb5/cred.c --- Kerberos 5 GSS-API credential management functions.
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
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

/* Get specification. */
#include "k5internal.h"

OM_uint32
gss_krb5_acquire_cred1 (OM_uint32 * minor_status,
			const gss_name_t desired_name,
			OM_uint32 time_req,
			const gss_OID_set desired_mechs,
			gss_cred_usage_t cred_usage,
			gss_cred_id_t * output_cred_handle,
			gss_OID_set * actual_mechs, OM_uint32 * time_rec)
{
  _gss_krb5_cred_t k5 = (*output_cred_handle)->krb5;
  OM_uint32 maj_stat;
  int rc;

  if (desired_name == GSS_C_NO_NAME)
    {
      gss_buffer_desc buf;

      buf.value = "host";
      buf.length = strlen (buf.value);
      maj_stat = gss_import_name (minor_status, &buf,
				  GSS_C_NT_HOSTBASED_SERVICE,
				  (gss_name_t *) & desired_name);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
    }

  if (gss_oid_equal (desired_name->type, GSS_KRB5_NT_PRINCIPAL_NAME))
    {
      maj_stat = gss_duplicate_name (minor_status, desired_name,
				     &k5->peerptr);
    }
  else
    {
      maj_stat = gss_krb5_canonicalize_name (minor_status, desired_name,
					     GSS_KRB5, &k5->peerptr);
    }
  if (GSS_ERROR (maj_stat))
    return maj_stat;

  if (shishi_init_server (&k5->sh) != SHISHI_OK)
    return GSS_S_FAILURE;

  {
    char *p;

    p = xmalloc (k5->peerptr->length + 1);
    memcpy (p, k5->peerptr->value, k5->peerptr->length);
    p[k5->peerptr->length] = 0;

    k5->key = shishi_hostkeys_for_serverrealm (k5->sh, p,
					       shishi_realm_default (k5->sh));
    free (p);
  }

  if (!k5->key)
    {
      if (minor_status)
	*minor_status = GSS_KRB5_S_KG_KEYTAB_NOMATCH;
      return GSS_S_FAILURE;
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
  gss_cred_id_t p;

  if (minor_status)
    *minor_status = 0;

  if (actual_mechs)
    {
      maj_stat = gss_create_empty_oid_set (minor_status, actual_mechs);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
      maj_stat =
	gss_add_oid_set_member (minor_status, GSS_KRB5, actual_mechs);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
    }

  p = xcalloc (sizeof (*p), 1);
  p->mech = GSS_KRB5;
  p->krb5 = xcalloc (sizeof (*p->krb5), 1);
  p->krb5->peerptr = &p->krb5->peer;

  maj_stat = gss_krb5_acquire_cred1 (minor_status, desired_name, time_req,
				     desired_mechs, cred_usage,
				     &p, actual_mechs, time_rec);
  if (GSS_ERROR (maj_stat))
    {
      OM_uint32 junk;

      gss_release_oid_set (&junk, actual_mechs);

      free (p->krb5);
      free (p);
      *output_cred_handle = NULL;

      return maj_stat;
    }

  *output_cred_handle = p;

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
  OM_uint32 maj_stat;

  if (minor_status)
    *minor_status = 0;

  if (cred_handle == GSS_C_NO_CREDENTIAL)
    {

    }

  if (name)
    {
      maj_stat = gss_duplicate_name (minor_status, cred_handle->krb5->peerptr,
				     name);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
    }

  if (lifetime)
    *lifetime = gss_krb5_tktlifetime (cred_handle->krb5->tkt);

  if (cred_usage)
    *cred_usage = GSS_C_BOTH;

  if (mechanisms)
    {
      maj_stat = gss_create_empty_oid_set (minor_status, mechanisms);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
      maj_stat = gss_add_oid_set_member (minor_status, GSS_KRB5, mechanisms);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
    }

  return GSS_S_COMPLETE;
}
