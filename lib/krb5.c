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

gss_OID_desc GSS_KRB5_MECH_OID_static = {
  9, (void *) _GSS_KRB5_OID
};
gss_OID GSS_KRB5_MECH_OID = &GSS_KRB5_MECH_OID_static;
gss_OID GSS_KRB5_NT_PRINCIPAL_NAME = &GSS_KRB5_MECH_OID_static;


#define _GSS_KRB5_OID_DER "\x06\x09" _GSS_KRB5_OID
#define _GSS_KRB5_OID_LEN  strlen(_GSS_KRB5_OID_DER)

#define _GSS_KRB5_AP_REQ_DATA    _GSS_KRB5_OID_DER "\x01\x00"
#define _GSS_KRB5_AP_REQ_LEN     (_GSS_KRB5_OID_LEN+2)

#define _GSS_KRB5_AP_REP_DATA    _GSS_KRB5_OID_DER "\x02\x00"
#define _GSS_KRB5_AP_REP_LEN     (_GSS_KRB5_OID_LEN+2)

#define _GSS_KRB5_KRB_ERROR_DATA _GSS_KRB5_OID_DER "\x03\x00"
#define _GSS_KRB5_KRB_ERROR_LEN  (_GSS_KRB5_OID_LEN+2)

#define _GSS_KRB5_WRAP_DATA _GSS_KRB5_OID_DER "\x02\x01"
#define _GSS_KRB5_WRAP_LEN  (_GSS_KRB5_OID_LEN+2)

#define _GSS_KRB5_TOK_MIC_DATA  "\x01\x01"
#define _GSS_KRB5_TOK_MIC_LEN   strlen(_GSS_KRB5_TOK_MIC_DATA)
#define _GSS_KRB5_TOK_WRAP_DATA "\x02\x01"
#define _GSS_KRB5_TOK_WRAP_LEN  strlen(_GSS_KRB5_TOK_WRAP_DATA)

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

  /* XXX mech_type not tested */

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

      rc = _gss_encapsulate_token(_GSS_KRB5_AP_REQ_DATA, _GSS_KRB5_AP_REQ_LEN,
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

OM_uint32
krb5_gss_wrap (OM_uint32 * minor_status,
	       const gss_ctx_id_t context_handle,
	       int conf_req_flag,
	       gss_qop_t qop_req,
	       const gss_buffer_t input_message_buffer,
	       int *conf_state, gss_buffer_t output_message_buffer)
{
  size_t padlength;
  char *data, *tmp;
  size_t len, tmplen;
  int rc;

  padlength = 8 - input_message_buffer->length % 8;

  puts("wrap:");
  {
    int i;
    for (i = 0; i < input_message_buffer->length; i++)
      {
	printf("%02x ", ((char*)input_message_buffer->value)[i] & 0xFF);
	if ((i+1)%16 == 0)
	  printf("\n");
      }
    puts("");
  }

  len = 8 + 8 + 20 + 8 + input_message_buffer->length + padlength;
  data = malloc(len);
  if (!data)
    return GSS_S_FAILURE;

  /* Compute checksum over header, random data, input string, and pad */

  /* TOK_ID: Wrap */
  memcpy (data, "\x02\x01", 2);
  /* SGN_ALG: 3DES */
  memcpy (data + 2, "\x04\x00", 2);
  /* SEAL_ALG: none */
  memcpy (data + 4, "\xFF\xFF", 2);
  /* filler */
  memcpy (data + 6, "\xFF\xFF", 2);
  /* XXX set 8..15 SND_SEQ random? */
  shishi_randomize(context_handle->sh, data + 8, 8);
  memcpy (data + 16, input_message_buffer->value,
	  input_message_buffer->length);
  memset (data + 16 + input_message_buffer->length, padlength, padlength);

  tmplen=1000;
  tmp = malloc(tmplen);

  puts("cksum:");
  {
    int i;
    for (i = 0; i < 16 + input_message_buffer->length + padlength; i++)
      {
	printf("%02x ", ((char*)data)[i] & 0xFF);
	if ((i+1)%16 == 0)
	  printf("\n");
      }
    puts("");
  }

  rc = shishi_checksum (context_handle->sh,
			shishi_tkt_key(context_handle->tkt),
			SHISHI_KEYUSAGE_GSS_R2, SHISHI_HMAC_SHA1_DES3_KD,
			data, 16 + input_message_buffer->length + padlength,
			tmp, &tmplen);
  if (rc != SHISHI_OK)
    return GSS_S_FAILURE;

  puts("cksumed:");
  {
    int i;
    for (i = 0; i < tmplen; i++)
      {
	printf("%02x ", ((char*)tmp)[i] & 0xFF);
	if ((i+1)%16 == 0)
	  printf("\n");
      }
    puts("");
  }

  memcpy(data + 16, tmp, tmplen);

  /* seq_nr */
  tmp[0] = 0;
  tmp[1] = 0;
  tmp[2] = 0;
  tmp[3] = 1;
  memset(tmp + 4, 0 /* XXX 0xFF? */, 4);

  tmplen = 1000;

  puts("encrypt:");
  {
    int i;
    for (i = 0; i < 8; i++)
      {
	printf("%02x ", ((char*)tmp)[i] & 0xFF);
	if ((i+1)%16 == 0)
	  printf("\n");
      }
    puts("");
  }

  rc = shishi_encrypt_iv(context_handle->sh,
			 shishi_tkt_key(context_handle->tkt),
			 SHISHI_KEYUSAGE_GSS_R3,
			 data + 16, 8,
			 tmp, 8, tmp, &tmplen);
  if (rc != SHISHI_OK)
    return GSS_S_FAILURE;

  puts("encrypted:");
  {
    int i;
    for (i = 0; i < tmplen; i++)
      {
	printf("%02x ", ((char*)tmp)[i] & 0xFF);
	if ((i+1)%16 == 0)
	  printf("\n");
      }
    puts("");
  }

  memcpy (data + 36, data + 8, 8);
  memcpy (data + 36 + 8, input_message_buffer->value,
	  input_message_buffer->length);
  memset (data + 36 + 8 + input_message_buffer->length, padlength, padlength);
  memcpy(data + 8, tmp + 8, 8);

  puts("data:");
  {
    int i;
    for (i = 0; i < len; i++)
      {
	printf("%02x ", ((char*)data)[i] & 0xFF);
	if ((i+1)%16 == 0)
	  printf("\n");
      }
    puts("");
  }

  rc = _gss_encapsulate_token(_GSS_KRB5_OID_DER, _GSS_KRB5_OID_LEN,
			      data, len,
			      (void**)&(output_message_buffer->value),
			      &output_message_buffer->length);
  if (!rc)
    return GSS_S_FAILURE;

  puts("wrapped:");
  {
    int i;
    for (i = 0; i < output_message_buffer->length; i++)
      {
	printf("%02x ", ((char*)output_message_buffer->value)[i] & 0xFF);
	if ((i+1)%16 == 0)
	  printf("\n");
      }
    puts("");
  }

  return GSS_S_COMPLETE;
}

OM_uint32
krb5_gss_unwrap (OM_uint32 * minor_status,
		 const gss_ctx_id_t context_handle,
		 const gss_buffer_t input_message_buffer,
		 gss_buffer_t output_message_buffer,
		 int *conf_state, gss_qop_t * qop_state)
{
  gss_OID_desc tokenoid;
  gss_buffer_desc data;
  OM_uint32 sgn_alg, seal_alg;
  size_t tmplen;
  int rc;

  rc = _gss_decapsulate_token (input_message_buffer, &tokenoid, &data);
  if (!rc)
    return GSS_S_BAD_MIC;

  puts("data:");
  {
    int i;
    for (i = 0; i < data.length; i++)
      {
	printf("%02x ", ((char*)data.value)[i] & 0xFF);
	if ((i+1)%16 == 0)
	  printf("\n");
      }
    puts("");
  }

  if (!_gss_oid_equal (&tokenoid, GSS_KRB5_MECH_OID))
    return GSS_S_BAD_MIC;

  if (data.length < 8 + 8 + 20 + 8 + 8)
    return GSS_S_BAD_MIC;

  if (memcmp(data.value, _GSS_KRB5_TOK_WRAP_DATA, _GSS_KRB5_TOK_WRAP_LEN) != 0)
    return GSS_S_BAD_MIC;

  sgn_alg = ((char*)data.value)[2] & 0xFF;
  sgn_alg |= ((char*)data.value)[3] << 8 & 0xFF00;

  seal_alg = ((char*)data.value)[4] & 0xFF;
  seal_alg |= ((char*)data.value)[5] << 8 & 0xFF00;

  if(conf_state != NULL)
    *conf_state = seal_alg == 0xFFFF;

  if (memcmp(data.value + 6, "\xFF\xFF", 2) != 0)
    return GSS_S_BAD_MIC;

  switch (sgn_alg)
    {
      /* XXX implement other checksums */

    case 4: /* 3DES */
      {
	size_t padlen;
	char *pad;
	char cksum[20]; /* HMAC-SHA1 checksum */
	size_t cksumlen = 20;
	int i;

	/* XXX decrypt data iff confidential option chosen */

	/* XXX verify seqnr */

	/* Check pad */
	padlen = ((char*)data.value)[data.length - 1];
	if (padlen > 8)
	  return GSS_S_BAD_MIC;
	for (i = 1; i <= padlen; i++)
	  if (((char*)data.value)[data.length - i] != padlen)
	    return GSS_S_BAD_MIC;

	/* Save a copy of incoming HMAC-SHA1 */
	memcpy(cksum, data.value + 8 + 8, 20);

	/* Write header next to confounder */
	memcpy(data.value + 8 + 20, data.value, 8);

	/* Checksum header + confounder + data + pad */
	tmplen = 20;
	rc = shishi_checksum (context_handle->sh,
			      shishi_tkt_key(context_handle->tkt),
			      SHISHI_KEYUSAGE_GSS_R2, SHISHI_HMAC_SHA1_DES3_KD,
			      data.value + 20 + 8, data.length - 20 - 8,
			      data.value + 8 + 8, &tmplen);
	if (rc != SHISHI_OK)
	  return GSS_S_FAILURE;

	/* Compare checksum */
	if (tmplen != 20 || memcmp (cksum, data.value + 8 + 8, 20) != 0)
	  return GSS_S_BAD_MIC;

	/* Copy output data */
	output_message_buffer->length = data.length - 8 - 20 - 8 - 8 - padlen;
	output_message_buffer->value = malloc(output_message_buffer->length);
	memcpy(output_message_buffer->value, data.value + 20 + 8 + 8 + 8,
	       data.length - 20 - 8 - 8 - 8 - padlen);
	break;
      }

    default:
      return GSS_S_FAILURE;
    }


  puts("unwrapped:");
  {
    int i;
    for (i = 0; i < output_message_buffer->length; i++)
      {
	printf("%02x ", ((char*)output_message_buffer->value)[i] & 0xFF);
	if ((i+1)%16 == 0)
	  printf("\n");
      }
    puts("");
  }

  return GSS_S_COMPLETE;
}

#endif /* USE_KERBEROS5 */
