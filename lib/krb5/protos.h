/* protos.h --- Export Kerberos 5 GSS functions to core GSS library.
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

/* See context.c. */
extern OM_uint32
gss_krb5_init_sec_context (OM_uint32 * minor_status,
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
			   OM_uint32 * ret_flags, OM_uint32 * time_rec);
extern OM_uint32
gss_krb5_accept_sec_context (OM_uint32 * minor_status,
			     gss_ctx_id_t * context_handle,
			     const gss_cred_id_t acceptor_cred_handle,
			     const gss_buffer_t input_token_buffer,
			     const gss_channel_bindings_t input_chan_bindings,
			     gss_name_t * src_name,
			     gss_OID * mech_type,
			     gss_buffer_t output_token,
			     OM_uint32 * ret_flags,
			     OM_uint32 * time_rec,
			     gss_cred_id_t * delegated_cred_handle);
extern OM_uint32
gss_krb5_delete_sec_context (OM_uint32 * minor_status,
			     gss_ctx_id_t * context_handle,
			     gss_buffer_t output_token);
extern OM_uint32
gss_krb5_context_time (OM_uint32 * minor_status,
		       const gss_ctx_id_t context_handle,
		       OM_uint32 * time_rec);

/* See cred.c. */
extern OM_uint32
gss_krb5_acquire_cred (OM_uint32 * minor_status,
		       const gss_name_t desired_name,
		       OM_uint32 time_req,
		       const gss_OID_set desired_mechs,
		       gss_cred_usage_t cred_usage,
		       gss_cred_id_t * output_cred_handle,
		       gss_OID_set * actual_mechs, OM_uint32 * time_rec);
extern OM_uint32
gss_krb5_inquire_cred (OM_uint32 * minor_status,
		       const gss_cred_id_t cred_handle,
		       gss_name_t * name,
		       OM_uint32 * lifetime,
		       gss_cred_usage_t * cred_usage,
		       gss_OID_set * mechanisms);
extern OM_uint32
gss_krb5_release_cred (OM_uint32 * minor_status,
		       gss_cred_id_t * cred_handle);

/* See error.c. */
extern OM_uint32
gss_krb5_display_status (OM_uint32 * minor_status,
			 OM_uint32 status_value,
			 int status_type,
			 const gss_OID mech_type,
			 OM_uint32 * message_context,
			 gss_buffer_t status_string);

/* See msg.c. */
extern OM_uint32
gss_krb5_get_mic (OM_uint32 * minor_status,
		  const gss_ctx_id_t context_handle,
		  gss_qop_t qop_req,
		  const gss_buffer_t message_buffer,
		  gss_buffer_t message_token);
extern OM_uint32
gss_krb5_verify_mic (OM_uint32 * minor_status,
		     const gss_ctx_id_t context_handle,
		     const gss_buffer_t message_buffer,
		     const gss_buffer_t token_buffer,
		     gss_qop_t * qop_state);
extern OM_uint32
gss_krb5_unwrap (OM_uint32 * minor_status,
		 const gss_ctx_id_t context_handle,
		 const gss_buffer_t input_message_buffer,
		 gss_buffer_t output_message_buffer,
		 int *conf_state, gss_qop_t * qop_state);
extern OM_uint32
gss_krb5_wrap (OM_uint32 * minor_status,
	       const gss_ctx_id_t context_handle,
	       int conf_req_flag,
	       gss_qop_t qop_req,
	       const gss_buffer_t input_message_buffer,
	       int *conf_state, gss_buffer_t output_message_buffer);

/* See name.c. */
extern OM_uint32
gss_krb5_canonicalize_name (OM_uint32 * minor_status,
			    const gss_name_t input_name,
			    const gss_OID mech_type,
			    gss_name_t * output_name);
extern OM_uint32
gss_krb5_export_name (OM_uint32 * minor_status,
		      const gss_name_t input_name, gss_buffer_t exported_name);
