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

#include <shishi.h>
#include "krb5.h"

typedef struct _gss_krb5_cred_struct
{
  Shishi_tkt *tkt;
} _gss_krb5_cred_desc, *_gss_krb5_cred_t;

typedef struct _gss_krb5_ctx_struct
{
  Shishi *sh;
  Shishi_ap *ap;
  Shishi_tkt *tkt;
  int acceptor;
  int acceptseqnr;
  int initseqnr;
  OM_uint32 flags;
  int repdone;
} _gss_krb5_ctx_desc, *_gss_krb5_ctx_t;

#define _GSS_KRB5_OID "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"

#define _GSS_KRB5_OID_DER "\x06\x09" _GSS_KRB5_OID
#define _GSS_KRB5_OID_LEN  strlen(_GSS_KRB5_OID_DER)

#define _GSS_KRB5_AP_REQ_DATA    _GSS_KRB5_OID_DER "\x01\x00"
#define _GSS_KRB5_AP_REQ_LEN     (_GSS_KRB5_OID_LEN+2)

#define _GSS_KRB5_TOK_AP_REQ_DATA "\x01\x00"
#define _GSS_KRB5_TOK_AP_REQ_LEN  2
#define _GSS_KRB5_TOK_AP_REP_DATA "\x02\x00"
#define _GSS_KRB5_TOK_AP_REP_LEN  2

#define _GSS_KRB5_TOK_MIC_DATA  "\x01\x01"
#define _GSS_KRB5_TOK_MIC_LEN   2
#define _GSS_KRB5_TOK_WRAP_DATA "\x02\x01"
#define _GSS_KRB5_TOK_WRAP_LEN  2


static void
hexprint (const unsigned char *str, int len)
{
  int i;

  if (!str || !len)
    return;

  printf ("\t ;; ");
  for (i = 0; i < len; i++)
    {
      printf ("%02x ", str[i]);
      if ((i + 1) % 8 == 0)
	printf (" ");
      if ((i + 1) % 16 == 0 && i + 1 < len)
	printf ("\n\t ;; ");
    }
  printf ("\n");
}

int
_gss_encapsulate_token_krb5 (char *oid, size_t oidlen,
			     char *type, size_t typelen,
			     char *in, size_t inlen,
			     char **out, size_t *outlen)
{
  char *p;
  int rc;

  p = malloc(typelen + inlen);
  if (!p)
    return 0;

  memcpy(p, type, typelen);
  memcpy(p + typelen, in, inlen);

  rc = _gss_encapsulate_token(oid, oidlen, p, typelen + inlen, out, outlen);

  free(p);

  return 1;
}

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
      gss_buffer_desc tmp;

      ctx = malloc(sizeof(*ctx));
      if (!ctx)
	return GSS_S_FAILURE;

      ctx->krb5 = malloc(sizeof(*ctx->krb5));
      if (!ctx->krb5)
	return GSS_S_FAILURE;
      memset(ctx->krb5, 0, sizeof(*ctx->krb5));

      *context_handle = ctx;

      rc = shishi_init(&h);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;
      ctx->krb5->sh = h;

      ctx->peerptr = &ctx->peer;
      if (gss_oid_equal (target_name->type, GSS_KRB5_NT_PRINCIPAL_NAME))
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
	  tkt = initiator_cred_handle->krb5->tkt;
	  /* XXX? */
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
      ctx->krb5->tkt = tkt;

      data = malloc(2 + 24);
      memcpy(&data[0], _GSS_KRB5_TOK_AP_REQ_DATA, _GSS_KRB5_TOK_AP_REQ_LEN);
      memcpy(&data[2], "\x10\x00\x00\x00", 4); /* length of Bnd */
      memset(&data[6], 0, 16); /* XXX we only support GSS_C_NO_BINDING */
      data[22] = req_flags & 0xFF;
      data[23] = (req_flags >> 8) & 0xFF;
      data[24] = (req_flags >> 16) & 0xFF;
      data[25] = (req_flags >> 24) & 0xFF;
      ctx->krb5->flags = req_flags;

      rc = shishi_ap_tktoptionsdata (h, &ap, tkt, 0, "a", 1);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;
      (*context_handle)->krb5->ap = ap;

      rc = shishi_ap_req_build (ap);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;

      rc = shishi_authenticator_set_cksum (h, shishi_ap_authenticator(ap),
					   0x8003, data + 2, 24);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;

      rc = shishi_apreq_add_authenticator (h, shishi_ap_req(ap),
					   shishi_tkt_key (shishi_ap_tkt(ap)),
					   SHISHI_KEYUSAGE_APREQ_AUTHENTICATOR,
					   shishi_ap_authenticator(ap));
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;

      free(data);

      rc = shishi_new_a2d (h, shishi_ap_req(ap), &data, &len);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;

      tmp.length = len + _GSS_KRB5_TOK_AP_REQ_LEN;
      tmp.value = malloc(tmp.length);
      if (!tmp.value)
	return GSS_S_FAILURE;
      memcpy(tmp.value, _GSS_KRB5_TOK_AP_REQ_DATA, _GSS_KRB5_TOK_AP_REQ_LEN);
      memcpy((char*)tmp.value + _GSS_KRB5_TOK_AP_REQ_LEN, data, len);

      rc = gss_encapsulate_token(&tmp, GSS_KRB5, output_token);
      if (!rc)
	return GSS_S_FAILURE;

      if (req_flags & GSS_C_MUTUAL_FLAG)
	return GSS_S_CONTINUE_NEEDED;
      else
	return GSS_S_COMPLETE;
    }
  else if (*context_handle && !(*context_handle)->krb5->repdone)
    {
      gss_ctx_id_t ctx = *context_handle;
      _gss_krb5_ctx_t k5 = ctx->krb5;
      gss_OID_desc tokenoid;
      gss_buffer_desc data;

      rc = gss_decapsulate_token (input_token, &tokenoid, &data);
      if (!rc)
	return GSS_S_BAD_MIC;

      if (!gss_oid_equal (&tokenoid, GSS_KRB5))
	return GSS_S_BAD_MIC;

      if (memcmp(data.value, _GSS_KRB5_TOK_AP_REP_DATA,
		 _GSS_KRB5_TOK_AP_REP_LEN) != 0)
	return GSS_S_BAD_MIC;

      rc = shishi_ap_rep_der_set (k5->ap, data.value + 2, data.length - 2);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;

      rc = shishi_ap_rep_verify (k5->ap);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;

      rc = shishi_encapreppart_seqnumber_get (k5->sh,
					      shishi_ap_encapreppart (k5->ap),
					      &k5->acceptseqnr);
      if (rc != SHISHI_OK)
	k5->acceptseqnr = 0;

      k5->repdone = 1;

      return GSS_S_COMPLETE;
    }

  return GSS_S_FAILURE;
}

OM_uint32
krb5_gss_canonicalize_name (OM_uint32 * minor_status,
			    const gss_name_t input_name,
			    const gss_OID mech_type,
			    gss_name_t * output_name)
{
  if (gss_oid_equal (input_name->type, GSS_C_NT_HOSTBASED_SERVICE))
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
  char *data;
  size_t len, tmplen;
  int rc;

  switch (shishi_key_type (shishi_tkt_key (context_handle->krb5->tkt)))
    {
      /* XXX implement other checksums */

    case SHISHI_DES3_CBC_HMAC_SHA1_KD:

      padlength = 8 - input_message_buffer->length % 8;
      len = 8 + 8 + 20 + 8 + input_message_buffer->length + padlength;
      data = malloc(len);
      if (!data)
	return GSS_S_FAILURE;

      /* XXX encrypt data iff confidential option chosen */

      /* Compute checksum over header, confounder, input string, and pad */

      memcpy (data, "\x02\x01", 2);      /* TOK_ID: Wrap */
      memcpy (data + 2, "\x04\x00", 2);  /* SGN_ALG: 3DES */
      memcpy (data + 4, "\xFF\xFF", 2);  /* SEAL_ALG: none */
      memcpy (data + 6, "\xFF\xFF", 2);  /* filler */
      rc = shishi_randomize(context_handle->krb5->sh, data + 8, 8);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;
      memcpy (data + 16, input_message_buffer->value,
	      input_message_buffer->length);
      memset (data + 16 + input_message_buffer->length, padlength, padlength);

      tmplen = 20;
      rc = shishi_checksum (context_handle->krb5->sh,
			    shishi_tkt_key(context_handle->krb5->tkt),
			    SHISHI_KEYUSAGE_GSS_R2, SHISHI_HMAC_SHA1_DES3_KD,
			    data,
			    16 + input_message_buffer->length + padlength,
			    data + 16, &tmplen);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;

      memcpy (data + 36, data + 8, 8);

      /* seq_nr */
      ((char*)data + 8)[0] = context_handle->krb5->initseqnr & 0xFF;
      ((char*)data + 8)[1] = context_handle->krb5->initseqnr >> 8 & 0xFF;
      ((char*)data + 8)[2] = context_handle->krb5->initseqnr >> 16 & 0xFF;
      ((char*)data + 8)[3] = context_handle->krb5->initseqnr >> 24 & 0xFF;
      memset(data + 8 + 4, context_handle->krb5->acceptor ? 0xFF : 0, 4);
      tmplen = 8;
      rc = shishi_encrypt_iv_etype(context_handle->krb5->sh,
				   shishi_tkt_key(context_handle->krb5->tkt),
				   0, SHISHI_DES3_CBC_NONE,
				   data + 16, 8, /* cksum */
				   data + 8, 8,
				   data + 8, &tmplen);
      if (rc != SHISHI_OK || tmplen != 8)
	return GSS_S_FAILURE;

      memcpy (data + 8 + 8 + 20 + 8, input_message_buffer->value,
	      input_message_buffer->length);
      memset (data + 8 + 8 + 20 + 8 + input_message_buffer->length,
	      padlength, padlength);

      rc = _gss_encapsulate_token(GSS_KRB5->elements, GSS_KRB5->length,
				  data, len,
				  (void**)&(output_message_buffer->value),
				  &output_message_buffer->length);
      if (!rc)
	return GSS_S_FAILURE;
      context_handle->krb5->initseqnr++;
      break;

    default:
      return GSS_S_FAILURE;
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
  _gss_krb5_ctx_t k5 = context_handle->krb5;
  gss_OID_desc tokenoid;
  gss_buffer_desc data;
  OM_uint32 sgn_alg, seal_alg;
  size_t tmplen;
  int rc;

  rc = gss_decapsulate_token (input_message_buffer, &tokenoid, &data);
  if (!rc)
    return GSS_S_BAD_MIC;

  if (!gss_oid_equal (&tokenoid, GSS_KRB5))
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
	unsigned char *p;
	char cksum[20];
	size_t cksumlen = 20;
	int i;

	memcpy(cksum, data.value + 8 + 8, 20);

	/* XXX decrypt data iff confidential option chosen */

	i=20;
	p = data.value + 8;
	rc = shishi_decrypt_iv_etype (k5->sh,
				      shishi_tkt_key(k5->tkt),
				      0, SHISHI_DES3_CBC_NONE,
				      cksum, 8,
				      p, 8,
				      p, &i);
	if (rc != SHISHI_OK)
	  return GSS_S_FAILURE;

	if (memcmp(p + 4, k5->acceptor ? "\x00\x00\x00\x00" :
		   "\xFF\xFF\xFF\xFF", 4) != 0)
	  return GSS_S_BAD_MIC;
	if ((p[0]|(p[1] << 8)|(p[2] << 16)|(p[3] << 24)) != k5->acceptseqnr)
	  return GSS_S_BAD_MIC;

	k5->acceptseqnr++;

	/* Check pad */
	padlen = ((char*)data.value)[data.length - 1];
	if (padlen > 8)
	  return GSS_S_BAD_MIC;
	for (i = 1; i <= padlen; i++)
	  if (((char*)data.value)[data.length - i] != padlen)
	    return GSS_S_BAD_MIC;

	/* Write header next to confounder */
	memcpy(data.value + 8 + 20, data.value, 8);

	/* Checksum header + confounder + data + pad */
	tmplen = 20;
	rc = shishi_checksum (k5->sh,
			      shishi_tkt_key(k5->tkt),
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

  return GSS_S_COMPLETE;
}

#endif /* USE_KERBEROS5 */
