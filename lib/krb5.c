/* krb5.c	Implementation of Kerberos 5 GSS functions.
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

#define _GSS_KRB5_OID "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
#define _GSS_KRB5_OID_STRING "1.2.840.113554.1.2.2"

gss_OID_desc GSS_KRB5_NT_PRINCIPAL_NAME_static = {
  9, (void *) _GSS_KRB5_OID
};
gss_OID GSS_KRB5_NT_PRINCIPAL_NAME = &GSS_KRB5_NT_PRINCIPAL_NAME_static;

#define _GSS_KRB5_OID_DER "\x06\x09" _GSS_KRB5_OID
#define _GSS_KRB5_OID_LEN  strlen(_GSS_KRB5_OID_DER)

#define _GSS_KRB5_AP_REQ_DATA    _GSS_KRB5_OID_DER "\x01\x00"
#define _GSS_KRB5_AP_REQ_LEN     (_GSS_KRB5_OID_LEN+2)

#define _GSS_KRB5_AP_REP_DATA    _GSS_KRB5_OID_DER "\x02\x00"
#define _GSS_KRB5_AP_REP_LEN     (_GSS_KRB5_OID_LEN+2)

#define _GSS_KRB5_KRB_ERROR_DATA _GSS_KRB5_OID_DER "\x03\x00"
#define _GSS_KRB5_KRB_ERROR_LEN  (_GSS_KRB5_OID_LEN+2)

OM_uint32
krb5_gss_init_sec_context (OM_uint32 * minor_status,
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
  Shishi *h;
  Shishi_ap *ap;
  Shishi_tkt *tkt;
  char *data;
  size_t len;
  int rc;
  OM_uint32 maj_stat;

  /* Note: mech_type not tested */

  if (*context_handle == GSS_C_NO_CONTEXT)
    {
      gss_ctx_id_t ctx;

      ctx = malloc(sizeof(*context_handle));
      if (!ctx)
	return GSS_S_FAILURE;
      *context_handle = ctx;

      rc = shishi_init(&h);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;
      ctx->sh = h;

      ctx->peerptr = &ctx->peer;
      if (_gss_oid_equal (target_name->type, GSS_KRB5_NT_PRINCIPAL_NAME))
	{
	  maj_stat = gss_duplicate_name (minor_status, target_name,
					 &ctx->peerptr);
	}
      else
	{
	  maj_stat = krb5_gss_canonicalize_name (minor_status, target_name,
						 mech_type, &ctx->peerptr);
	}
      if (maj_stat != GSS_S_COMPLETE)
	return maj_stat;

      if (initiator_cred_handle)
	{
	  tkt = initiator_cred_handle->tkt;
	  printf("urk\n");
	  exit(0);
	}
      else
	{
	  Shishi_tkts_hint hint;

	  memset(&hint, 0, sizeof(hint));
	  hint.server = ctx->peer.value;

	  tkt = shishi_tkts_get (shishi_tkts_default (h), &hint);
	  if (!tkt)
	    return GSS_S_FAILURE;

	  /* XXX */
	  shishi_tkts_to_file (shishi_tkts_default (h),
			       shishi_tkts_default_file (h));
	}
      ctx->tkt = tkt;

      /*
       * The checksum value field's format is as follows:
       *
       * Byte    Name    Description
       * 0..3    Lgth    Number of bytes in Bnd field;
       *                 Currently contains hex 10 00 00 00
       *                 (16, represented in little-endian form)
       * 4..19   Bnd     MD5 hash of channel bindings, taken over all non-null
       *                 components of bindings, in order of declaration.
       *                 Integer fields within channel bindings are represented
       *                 in little-endian order for the purposes of the MD5
       *                 calculation.
       * 20..23  Flags   Bit vector of context-establishment flags,
       *                 with values consistent with RFC-1509, p. 41:
       *                         GSS_C_DELEG_FLAG:       1
       *                         GSS_C_MUTUAL_FLAG:      2
       *                         GSS_C_REPLAY_FLAG:      4
       *                         GSS_C_SEQUENCE_FLAG:    8
       *                         GSS_C_CONF_FLAG:        16
       *                         GSS_C_INTEG_FLAG:       32
       *                 The resulting bit vector is encoded into bytes 20..23
       *                 in little-endian form.
       * 24..25  DlgOpt  The Delegation Option identifier (=1) [optional]
       * 26..27  Dlgth   The length of the Deleg field. [optional]
       * 28..n   Deleg   A KRB_CRED message (n = Dlgth + 29) [optional]
       */

      data = malloc(24);
      memcpy(&data[0], "\x10\x00\x00\x00", 4);
      /* XXX we only support GSS_C_NO_BINDING for now */
      memset(&data[4], 0, 16);
      memset(&data[20], 0, 4);

      rc = shishi_ap_tktoptionsdata (h, &ap, tkt, 0, "a", 1);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;
      (*context_handle)->ap = ap;

      rc = shishi_ap_req_build (ap);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;

      rc = shishi_authenticator_set_cksum (h, shishi_ap_authenticator(ap),
					   0x8003, data, 24);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;

      rc = shishi_apreq_add_authenticator (h, shishi_ap_req(ap),
					   shishi_tkt_key (shishi_ap_tkt(ap)),
					   SHISHI_KEYUSAGE_APREQ_AUTHENTICATOR,
					   shishi_ap_authenticator(ap));
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;

      rc = shishi_new_a2d (h, shishi_ap_req(ap), &data, &len);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;

      rc = _gss_wrap_token(_GSS_KRB5_AP_REQ_DATA, _GSS_KRB5_AP_REQ_LEN,
			   data, len,
			   (void**)&(output_token->value),
			   &output_token->length);
      if (!rc)
	return GSS_S_FAILURE;

      {
	int i;
	for (i = 0; i < output_token->length; i++)
	  {
	    printf("%02x ", ((char*)output_token->value)[i] & 0xFF);
	    if ((i+1)%16 == 0)
	      printf("\n");
	  }
      }

    }

  return GSS_S_COMPLETE;
}

OM_uint32
krb5_gss_canonicalize_name (OM_uint32 * minor_status,
			    const gss_name_t input_name,
			    const gss_OID mech_type,
			    gss_name_t * output_name)
{
  if (_gss_oid_equal (input_name->type, GSS_C_NT_HOSTBASED_SERVICE))
    {
      char *p;

      /* XXX we don't do DNS name canoncalization */

      (*output_name)->value = strdup(input_name->value);
      (*output_name)->length = strlen((*output_name)->value);
      (*output_name)->type = GSS_KRB5_NT_PRINCIPAL_NAME;

      if ((p = strchr((*output_name)->value, '@')))
	{
	  *p = '/';
	}
      else
	{
	  /* XXX add "/gethostname()" to outputname->value */
	}
    }
  else
    return GSS_S_FAILURE;

  return GSS_S_COMPLETE;
}

#endif /* USE_KERBEROS5 */
