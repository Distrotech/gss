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

/*
 * From RFC 1964:
 *
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
 *
 */

#define _GSS_KRB5_OID "1.2.840.113554.1.2.2"

/*
 * From RFC 1964:
 *
 * 1.1. Context Establishment Tokens
 *
 *    Per RFC-1508, Appendix B, the initial context establishment token
 *    will be enclosed within framing as follows:
 *
 *    InitialContextToken ::=
 *    [APPLICATION 0] IMPLICIT SEQUENCE {
 *            thisMech        MechType
 *                    -- MechType is OBJECT IDENTIFIER
 *                    -- representing "Kerberos V5"
 *            innerContextToken ANY DEFINED BY thisMech
 *                    -- contents mechanism-specific;
 *                    -- ASN.1 usage within innerContextToken
 *                    -- is not required
 *            }
 *
 *    The innerContextToken of the initial context token will consist of a
 *    Kerberos V5 KRB_AP_REQ message, preceded by a two-byte token-id
 *    (TOK_ID) field, which shall contain the value 01 00.
 *
 *    The above GSS-API framing shall be applied to all tokens emitted by
 *    the Kerberos V5 GSS-API mechanism, including KRB_AP_REP, KRB_ERROR,
 *    context-deletion, and per-message tokens, not just to the initial
 *    token in a context establishment sequence.  While not required by
 *    RFC-1508, this enables implementations to perform enhanced error-
 *    checking. The innerContextToken field of context establishment tokens
 *    for the Kerberos V5 GSS-API mechanism will contain a Kerberos message
 *    (KRB_AP_REQ, KRB_AP_REP or KRB_ERROR), preceded by a 2-byte TOK_ID
 *    field containing 01 00 for KRB_AP_REQ messages, 02 00 for KRB_AP_REP
 *    messages and 03 00 for KRB_ERROR messages.
 *
 */

#define _GSS_KRB5_OID_DATA "\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
#define _GSS_KRB5_OID_LEN  strlen(_GSS_KRB5_OID_DATA)

#define _GSS_KRB5_AP_REQ_DATA    _GSS_KRB5_OID_DATA "\x01\x00"
#define _GSS_KRB5_AP_REQ_LEN     (_GSS_KRB5_OID_LEN+2)

#define _GSS_KRB5_AP_REP_DATA    _GSS_KRB5_OID_DATA "\x02\x00"
#define _GSS_KRB5_AP_REP_LEN     (_GSS_KRB5_OID_LEN+2)

#define _GSS_KRB5_KRB_ERROR_DATA _GSS_KRB5_OID_DATA "\x03\x00"
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

  target_name->value = "imap/latte-wlan.josefsson.org";

  /* Note: mech_type not tested */

  if (*context_handle == GSS_C_NO_CONTEXT)
    {
      *context_handle = malloc(sizeof(*context_handle));

      if (!*context_handle)
	return GSS_S_FAILURE;

      rc = shishi_init(&h);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;
      (*context_handle)->sh = h;

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
	  hint.server = target_name->value;

	  tkt = shishi_tkts_get (shishi_tkts_default (h), &hint);
	  if (!tkt)
	    return GSS_S_FAILURE;

	  /* XXX */
	  shishi_tkts_to_file (shishi_tkts_default (h),
			       shishi_tkts_default_file (h));
	}
      (*context_handle)->tkt = tkt;

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

      puts(target_name->value);
    }

  return GSS_S_COMPLETE;
}

#endif /* USE_KERBEROS5 */
