/* context.c	Implementation of GSS-API Context functions.
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
gss_init_sec_context (OM_uint32 * minor_status,
		      const gss_cred_id_t initiator_cred_handle,
		      gss_ctx_id_t * context_handle,
		      const gss_name_t target_name,
		      const gss_OID mech_type,
		      OM_uint32 req_flags,
		      OM_uint32 time_req,
		      const gss_channel_bindings_t input_chan_bindings,
		      const gss_buffer_t input_token,
		      gss_OID * actual_mech_type,
		      gss_buffer_t output_token,
		      OM_uint32 * ret_flags, OM_uint32 * time_rec)
{
  _gss_mech_api_t mech;

  mech = (*context_handle == GSS_C_NO_CONTEXT) ?
    _gss_find_mech (mech_type) :
    _gss_find_mech ((*context_handle)->mech);

  return mech->init_sec_context (minor_status,
				 initiator_cred_handle,
				 context_handle,
				 target_name,
				 mech_type,
				 req_flags,
				 time_req,
				 input_chan_bindings,
				 input_token,
				 actual_mech_type,
				 output_token,
				 ret_flags,
				 time_rec);
}

OM_uint32
gss_accept_sec_context (OM_uint32 * minor_status,
			gss_ctx_id_t * context_handle,
			const gss_cred_id_t acceptor_cred_handle,
			const gss_buffer_t input_token_buffer,
			const gss_channel_bindings_t input_chan_bindings,
			gss_name_t * src_name,
			gss_OID * mech_type,
			gss_buffer_t output_token,
			OM_uint32 * ret_flags,
			OM_uint32 * time_rec,
			gss_cred_id_t * delegated_cred_handle)
{
  _gss_mech_api_t mech;

  mech = (*context_handle == GSS_C_NO_CONTEXT) ?
    _gss_find_mech (mech_type ? *mech_type : GSS_C_NO_OID) :
    _gss_find_mech ((*context_handle)->mech);

  return mech->accept_sec_context (minor_status,
				   context_handle,
				   acceptor_cred_handle,
				   input_token_buffer,
				   input_chan_bindings,
				   src_name,
				   mech_type,
				   output_token,
				   ret_flags,
				   time_rec,
				   delegated_cred_handle);
}

OM_uint32
gss_delete_sec_context (OM_uint32 * minor_status,
			gss_ctx_id_t * context_handle,
			gss_buffer_t output_token)
{
  if (!context_handle || *context_handle == GSS_C_NO_CONTEXT)
    return GSS_S_NO_CONTEXT;

  if (output_token != GSS_C_NO_BUFFER)
    {
      output_token->length = 0;
      output_token->value = NULL;
    }

  /* XXX krb5 deallocate */

  free (*context_handle);
  *context_handle = GSS_C_NO_CONTEXT;

  return GSS_S_COMPLETE;
}

OM_uint32
gss_process_context_token (OM_uint32 * minor_status,
			   const gss_ctx_id_t context_handle,
			   const gss_buffer_t token_buffer)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_context_time (OM_uint32 * minor_status,
		  const gss_ctx_id_t context_handle, OM_uint32 * time_rec)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_inquire_context (OM_uint32 * minor_status,
		     const gss_ctx_id_t context_handle,
		     gss_name_t * src_name,
		     gss_name_t * targ_name,
		     OM_uint32 * lifetime_rec,
		     gss_OID * mech_type,
		     OM_uint32 * ctx_flags, int *locally_initiated, int *open)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_wrap_size_limit (OM_uint32 * minor_status,
		     const gss_ctx_id_t context_handle,
		     int conf_req_flag,
		     gss_qop_t qop_req,
		     OM_uint32 req_output_size, OM_uint32 * max_input_size)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_export_sec_context (OM_uint32 * minor_status,
			gss_ctx_id_t * context_handle,
			gss_buffer_t interprocess_token)
{
  return GSS_S_UNAVAILABLE;
}

OM_uint32
gss_import_sec_context (OM_uint32 * minor_status,
			const gss_buffer_t interprocess_token,
			gss_ctx_id_t * context_handle)
{
  return GSS_S_UNAVAILABLE;
}
