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
#include "krb5.h"

#include "xgethostname.h"
#include <shishi.h>

typedef struct _gss_krb5_cred_struct
{
  Shishi *sh;
  gss_name_desc peer;
  gss_name_t peerptr;
  Shishi_tkt *tkt;
  Shishi_key *key;
} _gss_krb5_cred_desc, *_gss_krb5_cred_t;

typedef struct _gss_krb5_ctx_struct
{
  Shishi *sh;
  Shishi_ap *ap;
  Shishi_tkt *tkt;
  Shishi_key *key;
  int acceptor;
  int acceptseqnr;
  int initseqnr;
  OM_uint32 flags;
  int repdone;
} _gss_krb5_ctx_desc, *_gss_krb5_ctx_t;

#define TOK_LEN 2
#define TOK_AP_REQ "\x01\x00"
#define TOK_AP_REP "\x02\x00"
#define TOK_MIC    "\x01\x01"
#define TOK_WRAP   "\x02\x01"

#define C2I(buf) ((buf[0] & 0xFF) |		\
		  ((buf[1] & 0xFF) << 8) |	\
		  ((buf[2] & 0xFF) << 16) |	\
		  ((buf[3] & 0xFF) << 24))

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

OM_uint32
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
			   OM_uint32 * ret_flags, OM_uint32 * time_rec)
{
  Shishi *h;
  Shishi_ap *ap;
  Shishi_tkt *tkt;
  char *data;
  size_t len;
  int rc;
  OM_uint32 maj_stat;

  if (!context_handle)
    return GSS_S_FAILURE;

  if (!output_token)
    return GSS_S_FAILURE;

  if (actual_mech_type)
    (*actual_mech_type) = GSS_KRB5;

  /* XXX mech_type not tested */

  if (*context_handle == GSS_C_NO_CONTEXT)
    {
      gss_ctx_id_t ctx;
      gss_buffer_desc tmp;

      ctx = xcalloc(sizeof(*ctx), 1);
      ctx->mech = GSS_KRB5;
      ctx->krb5 = xcalloc(sizeof(*ctx->krb5), 1);

      *context_handle = ctx;

      if (initiator_cred_handle)
	h = initiator_cred_handle->krb5->sh;
      else
	{
	  rc = shishi_init(&h);
	  if (rc != SHISHI_OK)
	    return GSS_S_FAILURE;
	}
      ctx->krb5->sh = h;

      ctx->peerptr = &ctx->peer;
      if (gss_oid_equal (target_name->type, GSS_KRB5_NT_PRINCIPAL_NAME))
	{
	  maj_stat = gss_duplicate_name (minor_status, target_name,
					 &ctx->peerptr);
	}
      else
	{
	  maj_stat = gss_krb5_canonicalize_name (minor_status, target_name,
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
	  hint.server = malloc(ctx->peer.length + 1);
	  memcpy(hint.server, ctx->peer.value, ctx->peer.length);
	  hint.server[ctx->peer.length] = '\0';

	  tkt = shishi_tkts_get (shishi_tkts_default (h), &hint);
	  free(hint.server);
	  if (!tkt)
	    return GSS_S_FAILURE;

	  /* XXX */
	  shishi_tkts_to_file (shishi_tkts_default (h),
			       shishi_tkts_default_file (h));
	}
      ctx->krb5->tkt = tkt;

      data = xmalloc(2 + 24);
      memcpy(&data[0], TOK_AP_REQ, TOK_LEN);
      memcpy(&data[2], "\x10\x00\x00\x00", 4); /* length of Bnd */
      memset(&data[6], 0, 16); /* XXX we only support GSS_C_NO_BINDING */
      data[22] = req_flags & 0xFF;
      data[23] = (req_flags >> 8) & 0xFF;
      data[24] = (req_flags >> 16) & 0xFF;
      data[25] = (req_flags >> 24) & 0xFF;
      ctx->krb5->flags = req_flags;

      rc = shishi_ap_tktoptionsdata (h, &ap, tkt,
				     SHISHI_APOPTIONS_MUTUAL_REQUIRED, "a", 1);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;
      (*context_handle)->krb5->ap = ap;

      ctx->krb5->key = shishi_ap_key (ap);

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

      tmp.length = len + TOK_LEN;
      tmp.value = xmalloc(tmp.length);
      memcpy(tmp.value, TOK_AP_REQ, TOK_LEN);
      memcpy((char*)tmp.value + TOK_LEN, data, len);

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

      if (memcmp(data.value, TOK_AP_REP, TOK_LEN) != 0)
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
gss_krb5_canonicalize_name (OM_uint32 * minor_status,
			    const gss_name_t input_name,
			    const gss_OID mech_type,
			    gss_name_t * output_name)
{
  OM_uint32 maj_stat;

  if (minor_status)
    *minor_status = 0;

  if (gss_oid_equal (input_name->type, GSS_C_NT_HOSTBASED_SERVICE))
    {
      char *p;

      /* XXX we don't do DNS name canoncalization, it may be insecure */

      maj_stat = gss_duplicate_name (minor_status, input_name, output_name);
      if (GSS_ERROR(maj_stat))
	return maj_stat;
      (*output_name)->type = GSS_KRB5_NT_PRINCIPAL_NAME;

      if ((p = memchr((*output_name)->value, '@', (*output_name)->length)))
	{
	  *p = '/';
	}
      else
	{
	  char *hostname = xgethostname();
	  size_t hostlen = strlen(hostname);
	  size_t oldlen = (*output_name)->length;
	  size_t newlen = oldlen + 1 + hostlen;
	  (*output_name)->value = xrealloc((*output_name)->value, newlen);
	  (*output_name)->value[oldlen] = '/';
	  memcpy((*output_name)->value + 1 + oldlen, hostname, hostlen);
	  (*output_name)->length = newlen;
	}
    }
  else
    {
      *output_name = GSS_C_NO_NAME;
      return GSS_S_BAD_NAMETYPE;
    }

  return GSS_S_COMPLETE;
}

OM_uint32
gss_krb5_wrap (OM_uint32 * minor_status,
	       const gss_ctx_id_t context_handle,
	       int conf_req_flag,
	       gss_qop_t qop_req,
	       const gss_buffer_t input_message_buffer,
	       int *conf_state, gss_buffer_t output_message_buffer)
{
  _gss_krb5_ctx_t k5 = context_handle->krb5;
  size_t padlength;
  gss_buffer_desc data;
  size_t tmplen;
  int rc;

  switch (shishi_key_type (k5->key))
    {
      /* XXX implement other checksums */

    case SHISHI_DES_CBC_MD5:
      {
	char header[8];
	char encseqno[8];
	char seqno[8];
	char *eseqno;
	char *cksum;
	char confounder[8];
	char tmp[20];
	char *pt;

	/* Typical data:
	   ;; 02 01 00 00 ff ff ff ff  0c 22 1f 79 59 3d 00 cb
	   ;; d5 78 2f fb 50 d2 b8 59  fb b4 e0 9b d0 a2 fa dc
	   ;; 01 00 20 00 04 04 04 04
	   Translates into:
	   ;;   HEADER                 ENCRYPTED SEQ.NUMBER
	   ;;   DES-MAC-MD5 CKSUM      CONFOUNDER
	   ;;   PADDED DATA
	*/
	padlength = 8 - input_message_buffer->length % 8;
	data.length = 4*8 + input_message_buffer->length + padlength;
	data.value = xmalloc(data.length);

	/* XXX encrypt data iff confidential option chosen */

	/* Setup header and confounder */
	memcpy (header, TOK_WRAP, 2);	       /* TOK_ID: Wrap 0201 */
	memcpy (header + 2, "\x00\x00", 2);  /* SGN_ALG: DES-MAC-MD5 */
	memcpy (header + 4, "\xFF\xFF", 2);  /* SEAL_ALG: none */
	memcpy (header + 6, "\xFF\xFF", 2);  /* filler */
	rc = shishi_randomize(k5->sh, 0, confounder, 8);
	if (rc != SHISHI_OK)
	  return GSS_S_FAILURE;

	/* Compute checksum over header, confounder, input string, and pad */
	memcpy(data.value, header, 8);
	memcpy(data.value + 8, confounder, 8);
	memcpy (data.value + 16, input_message_buffer->value,
		input_message_buffer->length);
	memset (data.value + 16 + input_message_buffer->length,
		padlength, padlength);

	rc = shishi_checksum (k5->sh,
			      k5->key,
			      0, SHISHI_RSA_MD5_DES_GSS,
			      data.value,
			      16 + input_message_buffer->length + padlength,
			      &cksum, &tmplen);
	if (rc != SHISHI_OK || tmplen != 8)
	  return GSS_S_FAILURE;

	/* seq_nr */
	seqno[0] = k5->initseqnr & 0xFF;
	seqno[1] = k5->initseqnr >> 8 & 0xFF;
	seqno[2] = k5->initseqnr >> 16 & 0xFF;
	seqno[3] = k5->initseqnr >> 24 & 0xFF;
	memset(seqno + 4, k5->acceptor ? 0xFF : 0, 4);

	rc = shishi_encrypt_iv_etype(k5->sh,
				     k5->key,
				     0, SHISHI_DES_CBC_NONE,
				     cksum, 8, /* cksum */
				     seqno, 8,
				     &eseqno, &tmplen);
	if (rc != SHISHI_OK || tmplen != 8)
	  return GSS_S_FAILURE;

	/* put things in place */
	memcpy (data.value, header, 8);
	memcpy (data.value + 8, eseqno, 8);
	free (eseqno);
	memcpy (data.value + 16, cksum, 8);
	free (cksum);
	memcpy (data.value + 24, confounder, 8);
	memcpy (data.value + 32, input_message_buffer->value,
		input_message_buffer->length);
	memset (data.value + 32 + input_message_buffer->length,
		padlength, padlength);

	rc = gss_encapsulate_token(&data, GSS_KRB5, output_message_buffer);
	if (!rc)
	  return GSS_S_FAILURE;
	k5->initseqnr++;
      }
      break;

    case SHISHI_DES3_CBC_HMAC_SHA1_KD:
      {
	char *tmp;

	padlength = 8 - input_message_buffer->length % 8;
	data.length = 8 + 8 + 20 + 8 + input_message_buffer->length + padlength;
	data.value = xmalloc(data.length);

	/* XXX encrypt data iff confidential option chosen */

	/* Compute checksum over header, confounder, input string, and pad */

	memcpy (data.value, TOK_WRAP, 2);	       /* TOK_ID: Wrap */
	memcpy (data.value + 2, "\x04\x00", 2);  /* SGN_ALG: 3DES */
	memcpy (data.value + 4, "\xFF\xFF", 2);  /* SEAL_ALG: none */
	memcpy (data.value + 6, "\xFF\xFF", 2);  /* filler */
	rc = shishi_randomize(k5->sh, 0, data.value + 8, 8);
	if (rc != SHISHI_OK)
	  return GSS_S_FAILURE;
	memcpy (data.value + 16, input_message_buffer->value,
		input_message_buffer->length);
	memset (data.value + 16 + input_message_buffer->length,
		padlength, padlength);

	rc = shishi_checksum (k5->sh,
			      k5->key,
			      SHISHI_KEYUSAGE_GSS_R2, SHISHI_HMAC_SHA1_DES3_KD,
			      data.value,
			      16 + input_message_buffer->length + padlength,
			      &tmp, &tmplen);
	if (rc != SHISHI_OK || tmplen != 20)
	  return GSS_S_FAILURE;

	memcpy (data.value + 16, tmp, tmplen);
	memcpy (data.value + 36, data.value + 8, 8);

	/* seq_nr */
	((char*)data.value + 8)[0] = k5->initseqnr & 0xFF;
	((char*)data.value + 8)[1] = k5->initseqnr >> 8 & 0xFF;
	((char*)data.value + 8)[2] = k5->initseqnr >> 16 & 0xFF;
	((char*)data.value + 8)[3] = k5->initseqnr >> 24 & 0xFF;
	memset(data.value + 8 + 4, k5->acceptor ? 0xFF : 0, 4);

	rc = shishi_encrypt_iv_etype(k5->sh,
				     k5->key,
				     0, SHISHI_DES3_CBC_NONE,
				     data.value + 16, 8, /* cksum */
				     data.value + 8, 8,
				     &tmp, &tmplen);
	if (rc != SHISHI_OK || tmplen != 8)
	  return GSS_S_FAILURE;

	memcpy(data.value + 8, tmp, tmplen);
	free (tmp);
	memcpy (data.value + 8 + 8 + 20 + 8, input_message_buffer->value,
		input_message_buffer->length);
	memset (data.value + 8 + 8 + 20 + 8 + input_message_buffer->length,
		padlength, padlength);

	rc = gss_encapsulate_token(&data, GSS_KRB5, output_message_buffer);
	if (!rc)
	  return GSS_S_FAILURE;
	k5->initseqnr++;
	break;
      }

    default:
      return GSS_S_FAILURE;
    }

  return GSS_S_COMPLETE;
}

OM_uint32
gss_krb5_unwrap (OM_uint32 * minor_status,
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

  if (data.length < 8)
    return GSS_S_BAD_MIC;

  if (memcmp(data.value, TOK_WRAP, TOK_LEN) != 0)
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

    case 0: /* DES-MD5 */
      {
	size_t padlen;
	unsigned char *pt;
	char header[8];
	char encseqno[8];
	char seqno[8];
	char cksum[8];
	char confounder[8];
	char *tmp;
	size_t cksumlen = 8;
	int seqnr;
	int i;

	/* Typical data:
	   ;; 02 01 00 00 ff ff ff ff  0c 22 1f 79 59 3d 00 cb
	   ;; d5 78 2f fb 50 d2 b8 59  fb b4 e0 9b d0 a2 fa dc
	   ;; 01 00 20 00 04 04 04 04
	   Translates into:
	   ;;   HEADER                 ENCRYPTED SEQ.NUMBER
	   ;;   DES-MAC-MD5 CKSUM      CONFOUNDER
	   ;;   PADDED DATA
	*/

	if (data.length < 5*8)
	  return GSS_S_BAD_MIC;

	memcpy(header, data.value, 8);
	memcpy(encseqno, data.value + 8, 8);
	memcpy(cksum, data.value + 16, 8);
	memcpy(confounder, data.value + 24, 8);
	pt = data.value + 32;

	/* XXX decrypt data iff confidential option chosen */

	rc = shishi_decrypt_iv_etype (k5->sh,
				      k5->key,
				      0, SHISHI_DES_CBC_NONE,
				      cksum, 8,
				      encseqno, 8,
				      &tmp, &i);
	if (rc != SHISHI_OK)
	  return GSS_S_FAILURE;
	if (i != 8)
	  return GSS_S_BAD_MIC;
	memcpy(seqno, tmp, 8);
	free (tmp);

	if (memcmp(seqno + 4, k5->acceptor ? "\x00\x00\x00\x00" :
		   "\xFF\xFF\xFF\xFF", 4) != 0)
	  return GSS_S_BAD_MIC;

	seqnr = C2I(seqno);
	if (seqnr != k5->acceptseqnr)
	  return GSS_S_BAD_MIC;

	k5->acceptseqnr++;

	/* Check pad */
	padlen = ((char*)data.value)[data.length - 1];
	if (padlen > 8)
	  return GSS_S_BAD_MIC;
	for (i = 1; i <= padlen; i++)
	  if (((char*)data.value)[data.length - i] != padlen)
	    return GSS_S_BAD_MIC;

	/* Write header and confounder next to data */
	memcpy(data.value + 16, header, 8);
	memcpy(data.value + 24, confounder, 8);

	/* Checksum header + confounder + data + pad */
	rc = shishi_checksum (k5->sh,
			      k5->key,
			      0, SHISHI_RSA_MD5_DES_GSS,
			      data.value + 16, data.length - 16,
			      &tmp, &tmplen);
	if (rc != SHISHI_OK || tmplen != 8)
	  return GSS_S_FAILURE;

	memcpy (data.value + 8, tmp, tmplen);

	/* Compare checksum */
	if (tmplen != 8 || memcmp (cksum, data.value + 8, 8) != 0)
	  return GSS_S_BAD_MIC;

	/* Copy output data */
	output_message_buffer->length = data.length - 8 - 8 - 8 - 8 - padlen;
	output_message_buffer->value = xmalloc(output_message_buffer->length);
	memcpy(output_message_buffer->value, pt, data.length - 4*8 - padlen);
      }
      break;

    case 4: /* 3DES */
      {
	size_t padlen;
	unsigned char *p;
	char *t;
	char cksum[20];
	size_t cksumlen = 20;
	int i;

	if (data.length < 8 + 8 + 20 + 8 + 8)
	  return GSS_S_BAD_MIC;

	memcpy(cksum, data.value + 8 + 8, 20);

	/* XXX decrypt data iff confidential option chosen */

	p = data.value + 8;
	rc = shishi_decrypt_iv_etype (k5->sh,
				      k5->key,
				      0, SHISHI_DES3_CBC_NONE,
				      cksum, 8,
				      p, 8,
				      &t, &i);
	if (rc != SHISHI_OK || i != 20)
	  return GSS_S_FAILURE;

	memcpy(p, t, i);
	free (t);

	if (memcmp(p + 4, k5->acceptor ? "\x00\x00\x00\x00" :
		   "\xFF\xFF\xFF\xFF", 4) != 0)
	  return GSS_S_BAD_MIC;
	if (C2I(p) != k5->acceptseqnr)
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
	rc = shishi_checksum (k5->sh,
			      k5->key,
			      SHISHI_KEYUSAGE_GSS_R2, SHISHI_HMAC_SHA1_DES3_KD,
			      data.value + 20 + 8, data.length - 20 - 8,
			      &t, &tmplen);
	if (rc != SHISHI_OK || tmplen != 20)
	  return GSS_S_FAILURE;

	memcpy(data.value + 8 + 8, t, tmplen);
	free (t);

	/* Compare checksum */
	if (tmplen != 20 || memcmp (cksum, data.value + 8 + 8, 20) != 0)
	  return GSS_S_BAD_MIC;

	/* Copy output data */
	output_message_buffer->length = data.length - 8 - 20 - 8 - 8 - padlen;
	output_message_buffer->value = xmalloc(output_message_buffer->length);
	memcpy(output_message_buffer->value, data.value + 20 + 8 + 8 + 8,
	       data.length - 20 - 8 - 8 - 8 - padlen);
      }
      break;

    default:
      return GSS_S_FAILURE;
    }

  return GSS_S_COMPLETE;
}

struct gss_status_codes
{
  gss_uint32 err;
  char *name;
  char *text;
};

struct gss_status_codes gss_krb5_errors[] = {
  /* 4.1.1. Non-Kerberos-specific codes */
  {GSS_KRB5_S_G_BAD_SERVICE_NAME, "GSS_KRB5_S_G_BAD_SERVICE_NAME",
   N_ ("No @ in SERVICE-NAME name string")},
  {GSS_KRB5_S_G_BAD_STRING_UID, "GSS_KRB5_S_G_BAD_STRING_UID",
   N_ ("STRING-UID-NAME contains nondigits")},
  {GSS_KRB5_S_G_NOUSER, "GSS_KRB5_S_G_NOUSER",
   N_ ("UID does not resolve to username")},
  {GSS_KRB5_S_G_VALIDATE_FAILED, "GSS_KRB5_S_G_VALIDATE_FAILED",
   N_ ("Validation error")},
  {GSS_KRB5_S_G_BUFFER_ALLOC, "GSS_KRB5_S_G_BUFFER_ALLOC",
   N_ ("Couldn't allocate gss_buffer_t data")},
  {GSS_KRB5_S_G_BAD_MSG_CTX, "GSS_KRB5_S_G_BAD_MSG_CTX",
   N_ ("Message context invalid")},
  {GSS_KRB5_S_G_WRONG_SIZE, "GSS_KRB5_S_G_WRONG_SIZE",
   N_ ("Buffer is the wrong size")},
  {GSS_KRB5_S_G_BAD_USAGE, "GSS_KRB5_S_G_BAD_USAGE",
   N_ ("Credential usage type is unknown")},
  {GSS_KRB5_S_G_UNKNOWN_QOP, "GSS_KRB5_S_G_UNKNOWN_QOP",
   N_ ("Unknown quality of protection specified")},
  /* 4.1.2. Kerberos-specific-codes */
  {GSS_KRB5_S_KG_CCACHE_NOMATCH, "GSS_KRB5_S_KG_CCACHE_NOMATCH",
   N_ ("Principal in credential cache does not match desired name")},
  {GSS_KRB5_S_KG_KEYTAB_NOMATCH, "GSS_KRB5_S_KG_KEYTAB_NOMATCH",
   N_ ("No principal in keytab matches desired name")},
  {GSS_KRB5_S_KG_TGT_MISSING, "GSS_KRB5_S_KG_TGT_MISSING",
   N_ ("Credential cache has no TGT")},
  {GSS_KRB5_S_KG_NO_SUBKEY, "GSS_KRB5_S_KG_NO_SUBKEY",
   N_ ("Authenticator has no subkey")},
  {GSS_KRB5_S_KG_CONTEXT_ESTABLISHED, "GSS_KRB5_S_KG_CONTEXT_ESTABLISHED",
   N_ ("Context is already fully established")},
  {GSS_KRB5_S_KG_BAD_SIGN_TYPE, "GSS_KRB5_S_KG_BAD_SIGN_TYPE",
   N_ ("Unknown signature type in token")},
  {GSS_KRB5_S_KG_BAD_LENGTH, "GSS_KRB5_S_KG_BAD_LENGTH",
   N_ ("Invalid field length in token")},
  {GSS_KRB5_S_KG_CTX_INCOMPLETE, "GSS_KRB5_S_KG_CTX_INCOMPLETE",
   N_ ("Attempt to use incomplete security context")}
};

OM_uint32
gss_krb5_display_status (OM_uint32 * minor_status,
			 OM_uint32 status_value,
			 int status_type,
			 const gss_OID mech_type,
			 OM_uint32 * message_context,
			 gss_buffer_t status_string)
{
  if (minor_status)
    *minor_status = 0;

  switch (status_value)
    {
    case 0:
      status_string->value = xstrdup(_("No krb5 error"));
      status_string->length = strlen(status_string->value);
      break;

      /* 4.1.1. Non-Kerberos-specific codes */
    case GSS_KRB5_S_G_BAD_SERVICE_NAME:
    case GSS_KRB5_S_G_BAD_STRING_UID:
    case GSS_KRB5_S_G_NOUSER:
    case GSS_KRB5_S_G_VALIDATE_FAILED:
    case GSS_KRB5_S_G_BUFFER_ALLOC:
    case GSS_KRB5_S_G_BAD_MSG_CTX:
    case GSS_KRB5_S_G_WRONG_SIZE:
    case GSS_KRB5_S_G_BAD_USAGE:
    case GSS_KRB5_S_G_UNKNOWN_QOP:
      /* 4.1.2. Kerberos-specific-codes */
    case GSS_KRB5_S_KG_CCACHE_NOMATCH:
    case GSS_KRB5_S_KG_KEYTAB_NOMATCH:
    case GSS_KRB5_S_KG_TGT_MISSING:
    case GSS_KRB5_S_KG_NO_SUBKEY:
    case GSS_KRB5_S_KG_CONTEXT_ESTABLISHED:
    case GSS_KRB5_S_KG_BAD_SIGN_TYPE:
    case GSS_KRB5_S_KG_BAD_LENGTH:
    case GSS_KRB5_S_KG_CTX_INCOMPLETE:
      status_string->value = xstrdup(_(gss_krb5_errors[status_value-1].text));
      status_string->length = strlen(status_string->value);
      break;

    default:
      status_string->value = xstrdup(_("Unknown krb5 error"));
      status_string->length = strlen(status_string->value);
      break;
    }

  return GSS_S_COMPLETE;
}

OM_uint32
gss_krb5_acquire_cred1 (OM_uint32 * minor_status,
			const gss_name_t desired_name,
			OM_uint32 time_req,
			const gss_OID_set desired_mechs,
			gss_cred_usage_t cred_usage,
			gss_cred_id_t * output_cred_handle,
			gss_OID_set * actual_mechs,
			OM_uint32 * time_rec)
{
  _gss_krb5_cred_t k5 = (*output_cred_handle)->krb5;
  OM_uint32 maj_stat;
  int rc;

  if (desired_name == GSS_C_NO_NAME)
    {
      gss_buffer_desc buf;

      buf.value = "host";
      buf.length = strlen(buf.value);
      maj_stat = gss_import_name (minor_status, &buf,
				  GSS_C_NT_HOSTBASED_SERVICE,
				  (gss_name_t*)&desired_name);
      if (GSS_ERROR(maj_stat))
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
  if (GSS_ERROR(maj_stat))
    return maj_stat;

  if (shishi_init_server(&k5->sh) != SHISHI_OK)
    return GSS_S_FAILURE;

  {
    char *p;

    p = xmalloc(k5->peerptr->length + 1);
    memcpy(p, k5->peerptr->value, k5->peerptr->length);
    p[k5->peerptr->length] = 0;

    k5->key = shishi_hostkeys_for_serverrealm (k5->sh, p,
					       shishi_realm_default(k5->sh));
    free(p);
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
		       gss_OID_set * actual_mechs,
		       OM_uint32 * time_rec)
{
  OM_uint32 maj_stat;
  gss_cred_id_t p;

  if (minor_status)
    *minor_status = 0;

  if (actual_mechs)
    {
      maj_stat = gss_create_empty_oid_set (minor_status, actual_mechs);
      if (GSS_ERROR(maj_stat))
	return maj_stat;
      maj_stat = gss_add_oid_set_member (minor_status, GSS_KRB5, actual_mechs);
      if (GSS_ERROR(maj_stat))
	return maj_stat;
    }

  p = xcalloc(sizeof(*p), 1);
  p->mech = GSS_KRB5;
  p->krb5 = xcalloc(sizeof(*p->krb5), 1);
  p->krb5->peerptr = &p->krb5->peer;

  maj_stat = gss_krb5_acquire_cred1 (minor_status, desired_name, time_req,
				     desired_mechs, cred_usage,
				     &p, actual_mechs,
				     time_rec);
  if (GSS_ERROR(maj_stat))
    {
      OM_uint32 junk;

      gss_release_oid_set(&junk, actual_mechs);

      free(p->krb5);
      free(p);
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
    {
      if (cred_handle->krb5->tkt)
	{
	  time_t end = shishi_tkt_endctime (cred_handle->krb5->tkt);
	  time_t now = time(NULL);

	  if (shishi_tkt_valid_now_p (cred_handle->krb5->tkt))
	    *lifetime = (OM_uint32) difftime (now, end);
	  else
	    *lifetime = 0;
	}
      else
	*lifetime = GSS_C_INDEFINITE;
    }

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

OM_uint32
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
			     gss_cred_id_t * delegated_cred_handle)
{
  OM_uint32 maj_stat;
  int rc;

  if (minor_status)
    *minor_status = 0;

  if (mech_type)
    *mech_type = GSS_KRB5;

  if (ret_flags)
    *ret_flags = 0;

  if (!acceptor_cred_handle)
    /* XXX support GSS_C_NO_CREDENTIAL: acquire_cred() default server */
    return GSS_S_NO_CRED;

  if (input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS)
    /* XXX support channel bindings */
    return GSS_S_BAD_BINDINGS;

  if (!context_handle)
    return GSS_S_NO_CONTEXT;

  if (*context_handle)
    {
      printf("bad\n");
    }
  else
    {
      gss_OID_desc tokenoid;
      gss_buffer_desc data;
      gss_ctx_id_t cx;
      _gss_krb5_ctx_t cxk5;
      _gss_krb5_cred_t crk5;
      Shishi_asn1 *p;

      crk5 = acceptor_cred_handle->krb5;

      cx = xcalloc(sizeof(*cx), 1);
      cxk5 = xcalloc(sizeof(*cxk5), 1);
      cx->mech = GSS_KRB5;
      cx->krb5 = cxk5;
      /* XXX cx->peer?? */
      *context_handle = cx;

      cxk5->sh = crk5->sh;
      cxk5->key = crk5->key;
      cxk5->acceptor = 1;

      rc = shishi_ap(cxk5->sh, &cxk5->ap);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;

      rc = gss_decapsulate_token (input_token_buffer, &tokenoid, &data);
      if (!rc)
	return GSS_S_BAD_MIC;

      if (!gss_oid_equal (&tokenoid, GSS_KRB5))
	return GSS_S_BAD_MIC;

      if (memcmp(data.value, TOK_AP_REQ, TOK_LEN) != 0)
	return GSS_S_BAD_MIC;

      rc = shishi_ap_req_der_set(cxk5->ap, data.value + 2, data.length - 2);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;

      rc = shishi_ap_req_process (cxk5->ap, crk5->key);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;

      cxk5->tkt = shishi_ap_tkt(cxk5->ap);
      cxk5->key = shishi_tkt_key(cxk5->tkt);

      if (shishi_apreq_mutual_required_p (crk5->sh, shishi_ap_req(cxk5->ap)))
	{
	  Shishi_asn1 aprep;

	  rc = shishi_ap_rep_asn1(cxk5->ap, &aprep);
	  if (rc != SHISHI_OK)
	    {
	      printf ("Error creating AP-REP: %s\n", shishi_strerror (rc));
	      return GSS_S_FAILURE;
	    }

	  rc = shishi_new_a2d (crk5->sh, aprep,
			       (char**)&data.value, &data.length);
	  if (rc != SHISHI_OK)
	    {
	      printf ("Error der encoding aprep: %s\n", shishi_strerror (rc));
	      return GSS_S_FAILURE;
	    }

	  rc = gss_encapsulate_token_prefix(&data, TOK_AP_REP, TOK_LEN,
					    GSS_KRB5, output_token);
	  if (!rc)
	    return GSS_S_FAILURE;

	  if (ret_flags)
	    *ret_flags = GSS_C_MUTUAL_FLAG;
	}
      else
	{
	  output_token->value = NULL;
	  output_token->length = 0;
	}

      if (src_name)
	{
	  gss_name_t p;

	  p = xmalloc(sizeof(*p));
	  p->length = 1024; /* XXX */
	  p->value = xmalloc(p->length);

	  rc = shishi_encticketpart_cname_get
	    (cxk5->sh, shishi_tkt_encticketpart(cxk5->tkt),
	     p->value, &p->length);
	  if (rc != SHISHI_OK)
	    return GSS_S_FAILURE;

	  maj_stat = gss_duplicate_oid (minor_status,
					GSS_KRB5_NT_PRINCIPAL_NAME,
					&p->type);
	  if (GSS_ERROR(maj_stat))
	    return GSS_S_FAILURE;

	  *src_name = p;
	}
    }

  return GSS_S_COMPLETE;
}

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
gss_OID_desc GSS_KRB5_static = {
  9, (void *) "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
};
gss_OID GSS_KRB5 = &GSS_KRB5_static;

/*
 * This name form shall be represented by the Object Identifier
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) generic(1) user_name(1)}.  The recommended symbolic name
 * for this type is "GSS_KRB5_NT_USER_NAME".
 */
gss_OID_desc GSS_KRB5_NT_USER_NAME_static = {
  10, (void *) "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01"
};
gss_OID GSS_KRB5_NT_USER_NAME = &GSS_KRB5_NT_USER_NAME_static;

/*
 * This name form shall be represented by the Object Identifier
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) generic(1) service_name(4)}.  The previously recommended
 * symbolic name for this type is
 * "GSS_KRB5_NT_HOSTBASED_SERVICE_NAME".  The currently preferred
 * symbolic name for this type is "GSS_C_NT_HOSTBASED_SERVICE".
 */
gss_OID GSS_KRB5_NT_HOSTBASED_SERVICE_NAME =
  &GSS_C_NT_HOSTBASED_SERVICE_static;

/*
 * This name form shall be represented by the Object Identifier
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) krb5(2) krb5_name(1)}.  The recommended symbolic name for
 * this type is "GSS_KRB5_NT_PRINCIPAL_NAME".
 */
gss_OID_desc GSS_KRB5_NT_PRINCIPAL_NAME_static = {
  10, (void *) "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01"
};
gss_OID GSS_KRB5_NT_PRINCIPAL_NAME = &GSS_KRB5_NT_PRINCIPAL_NAME_static;

/*
 * This name form shall be represented by the Object Identifier
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) generic(1) string_uid_name(3)}.  The recommended symbolic
 * name for this type is "GSS_KRB5_NT_STRING_UID_NAME".
 */
gss_OID_desc GSS_KRB5_NT_STRING_UID_NAME_static = {
  10, (void *) "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03"
};
gss_OID GSS_KRB5_NT_STRING_UID_NAME = &GSS_KRB5_NT_STRING_UID_NAME_static;
