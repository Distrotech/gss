/* asn1.c	Wrapper around pseudo-ASN.1 token format.
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

/* RFC 2743:
 *
 * 3.1: Mechanism-Independent Token Format
 *
 *    This section specifies a mechanism-independent level of encapsulating
 *    representation for the initial token of a GSS-API context
 *    establishment sequence, incorporating an identifier of the mechanism
 *    type to be used on that context and enabling tokens to be interpreted
 *    unambiguously at GSS-API peers. Use of this format is required for
 *    initial context establishment tokens of Internet standards-track
 *    GSS-API mechanisms; use in non-initial tokens is optional.
 *
 *    The encoding format for the token tag is derived from ASN.1 and DER
 *    (per illustrative ASN.1 syntax included later within this
 *    subsection), but its concrete representation is defined directly in
 *    terms of octets rather than at the ASN.1 level in order to facilitate
 *    interoperable implementation without use of general ASN.1 processing
 *    code.  The token tag consists of the following elements, in order:
 *
 *       1. 0x60 -- Tag for [APPLICATION 0] SEQUENCE; indicates that
 *       -- constructed form, definite length encoding follows.
 *
 *       2. Token length octets, specifying length of subsequent data
 *       (i.e., the summed lengths of elements 3-5 in this list, and of the
 *       mechanism-defined token object following the tag).  This element
 *       comprises a variable number of octets:
 *
 *          2a. If the indicated value is less than 128, it shall be
 *          represented in a single octet with bit 8 (high order) set to
 *          "0" and the remaining bits representing the value.
 *
 *          2b. If the indicated value is 128 or more, it shall be
 *          represented in two or more octets, with bit 8 of the first
 *          octet set to "1" and the remaining bits of the first octet
 *          specifying the number of additional octets.  The subsequent
 *          octets carry the value, 8 bits per octet, most significant
 *          digit first.  The minimum number of octets shall be used to
 *          encode the length (i.e., no octets representing leading zeros
 *          shall be included within the length encoding).
 *
 *       3. 0x06 -- Tag for OBJECT IDENTIFIER
 *
 *       4. Object identifier length -- length (number of octets) of
 *       -- the encoded object identifier contained in element 5,
 *       -- encoded per rules as described in 2a. and 2b. above.
 *
 *       5. Object identifier octets -- variable number of octets,
 *       -- encoded per ASN.1 BER rules:
 *
 *          5a. The first octet contains the sum of two values: (1) the
 *          top-level object identifier component, multiplied by 40
 *          (decimal), and (2) the second-level object identifier
 *          component.  This special case is the only point within an
 *          object identifier encoding where a single octet represents
 *          contents of more than one component.
 *
 *          5b. Subsequent octets, if required, encode successively-lower
 *          components in the represented object identifier.  A component's
 *          encoding may span multiple octets, encoding 7 bits per octet
 *          (most significant bits first) and with bit 8 set to "1" on all
 *          but the final octet in the component's encoding.  The minimum
 *          number of octets shall be used to encode each component (i.e.,
 *          no octets representing leading zeros shall be included within a
 *          component's encoding).
 *
 *       (Note: In many implementations, elements 3-5 may be stored and
 *       referenced as a contiguous string constant.)
 *
 *    The token tag is immediately followed by a mechanism-defined token
 *    object.  Note that no independent size specifier intervenes following
 *    the object identifier value to indicate the size of the mechanism-
 *    defined token object.  While ASN.1 usage within mechanism-defined
 *    tokens is permitted, there is no requirement that the mechanism-
 *    specific innerContextToken, innerMsgToken, and sealedUserData data
 *    elements must employ ASN.1 BER/DER encoding conventions.
 *
 *    The following ASN.1 syntax is included for descriptive purposes only,
 *    to illustrate structural relationships among token and tag objects.
 *    For interoperability purposes, token and tag encoding shall be
 *    performed using the concrete encoding procedures described earlier in
 *    this subsection.
 *
 *       GSS-API DEFINITIONS ::=
 *
 *       BEGIN
 *
 *       MechType ::= OBJECT IDENTIFIER
 *       -- data structure definitions
 *       -- callers must be able to distinguish among
 *       -- InitialContextToken, SubsequentContextToken,
 *       -- PerMsgToken, and SealedMessage data elements
 *       -- based on the usage in which they occur
 *
 *       InitialContextToken ::=
 *       -- option indication (delegation, etc.) indicated within
 *       -- mechanism-specific token
 *       [APPLICATION 0] IMPLICIT SEQUENCE {
 *               thisMech MechType,
 *               innerContextToken ANY DEFINED BY thisMech
 *                  -- contents mechanism-specific
 *                  -- ASN.1 structure not required
 *               }
 *
 *       SubsequentContextToken ::= innerContextToken ANY
 *       -- interpretation based on predecessor InitialContextToken
 *       -- ASN.1 structure not required
 *
 *       PerMsgToken ::=
 *       -- as emitted by GSS_GetMIC and processed by GSS_VerifyMIC
 *       -- ASN.1 structure not required
 *               innerMsgToken ANY
 *
 *       SealedMessage ::=
 *       -- as emitted by GSS_Wrap and processed by GSS_Unwrap
 *       -- includes internal, mechanism-defined indicator
 *       -- of whether or not encrypted
 *       -- ASN.1 structure not required
 *               sealedUserData ANY
 *
 *       END
 */

/*
 * The following function borrowed from libtasn.1, under LGPL.
 * Copyright (C) 2002  Fabio Fiorina
 */
static void
_gss_asn1_length_der(size_t len, unsigned char *ans, size_t *ans_len)
{
  size_t k;
  unsigned char temp[sizeof(len)];

  if(len<128)
    {
      if(ans!=NULL) ans[0]=(unsigned char)len;
      *ans_len=1;
    }
  else
    {
      k=0;

      while(len)
	{
	  temp[k++]=len&0xFF;
	  len=len>>8;
	}

      *ans_len=k+1;

      if(ans!=NULL)
	{
	  ans[0]=((unsigned char)k&0x7F)+128;
	  while(k--)
	    ans[*ans_len-1-k]=temp[k];
	}
    }
}

int
_gss_wrap_token (char *oid, size_t oidlen,
		 char *in, size_t inlen,
		 char **out, size_t *outlen)
{
  size_t asn1len, asn1lenlen;
  int rc;

  asn1len = oidlen + inlen;
  _gss_asn1_length_der(asn1len, NULL, &asn1lenlen);

  *outlen = 1 + asn1lenlen + asn1len;
  *out = malloc(*outlen);
  if (!*out)
    return 0;

  **out = '\x60';
  _gss_asn1_length_der(asn1len, *out + 1, &asn1lenlen);
  memcpy(*out + 1 + asn1lenlen, oid, oidlen);
  memcpy(*out + 1 + asn1lenlen + oidlen, in, inlen);

  return 1;
}
