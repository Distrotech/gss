/* krb5.h	Header file for Kerberos 5 GSS-API mechanism.
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

#ifndef GSS_KRB5_H_
#define GSS_KRB5_H_

/*
 * To support ongoing experimentation, testing, and evolution of the
 * specification, the Kerberos V5 GSS-API mechanism as defined in this
 * and any successor memos will be identified with the following
 * Object Identifier, as defined in RFC-1510, until the specification
 * is advanced to the level of Proposed Standard RFC:
 *
 * {iso(1), org(3), dod(5), internet(1), security(5), kerberosv5(2)}
 *
 * Upon advancement to the level of Proposed Standard RFC, the
 * Kerberos V5 GSS-API mechanism will be identified by an Object
 * Identifier having the value:
 *
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) krb5(2)}
 */
extern gss_OID_desc GSS_KRB5_static;
extern gss_OID GSS_KRB5;

/*
 * This name form shall be represented by the Object Identifier
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) generic(1) user_name(1)}.  The recommended symbolic name
 * for this type is "GSS_KRB5_NT_USER_NAME".
 */
extern gss_OID_desc GSS_KRB5_NT_USER_NAME_static;
extern gss_OID GSS_KRB5_NT_USER_NAME;

/*
 * This name form shall be represented by the Object Identifier
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) generic(1) service_name(4)}.  The previously recommended
 * symbolic name for this type is
 * "GSS_KRB5_NT_HOSTBASED_SERVICE_NAME".  The currently preferred
 * symbolic name for this type is "GSS_C_NT_HOSTBASED_SERVICE".
 */
extern gss_OID_desc GSS_KRB5_NT_HOSTBASED_SERVICE_NAME_static;
extern gss_OID GSS_KRB5_NT_HOSTBASED_SERVICE_NAME;

/*
 * This name form shall be represented by the Object Identifier
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) krb5(2) krb5_name(1)}.  The recommended symbolic name for
 * this type is "GSS_KRB5_NT_PRINCIPAL_NAME".
 */
extern gss_OID_desc GSS_KRB5_NT_PRINCIPAL_NAME_static;
extern gss_OID GSS_KRB5_NT_PRINCIPAL_NAME;

/*
 * This name form shall be represented by the Object Identifier
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) generic(1) string_uid_name(3)}.  The recommended symbolic
 * name for this type is "GSS_KRB5_NT_STRING_UID_NAME".
 */
extern gss_OID_desc GSS_KRB5_NT_STRING_UID_NAME_static;
extern gss_OID GSS_KRB5_NT_STRING_UID_NAME;

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
gss_krb5_canonicalize_name (OM_uint32 * minor_status,
			    const gss_name_t input_name,
			    const gss_OID mech_type,
			    gss_name_t * output_name);

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

#endif /* GSS_KRB5_H_ */
