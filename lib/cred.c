/* cred.c	Implementation of GSS-API Credential Management functions.
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

OM_uint32
gss_acquire_cred (OM_uint32 * minor_status,
		  const gss_name_t desired_name,
		  OM_uint32 time_req,
		  const gss_OID_set desired_mechs,
		  gss_cred_usage_t cred_usage,
		  gss_cred_id_t * output_cred_handle,
		  gss_OID_set * actual_mechs, OM_uint32 * time_rec)
{
  OM_uint32 maj_stat;
  _gss_mech_api_t mech = NULL;

  if (desired_mechs != GSS_C_NO_OID_SET)
    {
      int i;
      int present;

      /* XXX this assumes GSS credentials are mutually exclusive.
         I.e., a credential for one mechanism cannot be used with
         another mechanism.  If at some point in time this GSS library
         support two different mechanisms that can use the same kind
         of credential, this logic has to be improved somehow. */

      for (i = 0; _gss_mech_apis[i].mech; i++)
	{
	  maj_stat = gss_test_oid_set_member (minor_status,
					      _gss_mech_apis[i].mech,
					      desired_mechs, &present);
	  if (!GSS_ERROR (maj_stat) && present)
	    {
	      mech = &_gss_mech_apis[i];
	      break;
	    }
	}
    }

  if (!mech)
    mech = _gss_find_mech (GSS_C_NO_OID);

  return mech->acquire_cred (minor_status,
			     desired_name,
			     time_req,
			     desired_mechs,
			     cred_usage,
			     output_cred_handle, actual_mechs, time_rec);
}

OM_uint32
gss_add_cred (OM_uint32 * minor_status,
	      const gss_cred_id_t input_cred_handle,
	      const gss_name_t desired_name,
	      const gss_OID desired_mech,
	      gss_cred_usage_t cred_usage,
	      OM_uint32 initiator_time_req,
	      OM_uint32 acceptor_time_req,
	      gss_cred_id_t * output_cred_handle,
	      gss_OID_set * actual_mechs,
	      OM_uint32 * initiator_time_rec, OM_uint32 * acceptor_time_rec)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_inquire_cred (OM_uint32 * minor_status,
		  const gss_cred_id_t cred_handle,
		  gss_name_t * name,
		  OM_uint32 * lifetime,
		  gss_cred_usage_t * cred_usage, gss_OID_set * mechanisms)
{
  _gss_mech_api_t mech;

  mech = cred_handle == GSS_C_NO_CREDENTIAL ?
    _gss_find_mech (GSS_C_NO_OID) : _gss_find_mech (cred_handle->mech);

  return mech->inquire_cred (minor_status,
			     cred_handle,
			     name, lifetime, cred_usage, mechanisms);
}

OM_uint32
gss_inquire_cred_by_mech (OM_uint32 * minor_status,
			  const gss_cred_id_t cred_handle,
			  const gss_OID mech_type,
			  gss_name_t * name,
			  OM_uint32 * initiator_lifetime,
			  OM_uint32 * acceptor_lifetime,
			  gss_cred_usage_t * cred_usage)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_release_cred (OM_uint32 * minor_status, gss_cred_id_t * cred_handle)
{
  if (minor_status)
    *minor_status = 0;

  if (cred_handle && *cred_handle)
    free (*cred_handle);

  /* XXX krb5 deallocate */

  *cred_handle = GSS_C_NO_CREDENTIAL;

  return GSS_S_COMPLETE;
}
