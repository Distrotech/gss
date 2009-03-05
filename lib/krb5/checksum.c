/* krb5/checksum.c --- (Un)pack checksum fields in Krb5 GSS contexts.
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2009  Simon Josefsson
 *
 * This file is part of the Generic Security Service (GSS).
 *
 * GSS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GSS is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GSS; if not, see http://www.gnu.org/licenses or write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA.
 *
 */

/* Get GSS API. */
#include "k5internal.h"

/* Get specification. */
#include "checksum.h"

/* Create the checksum value field from input parameters. */
OM_uint32
_gss_krb5_checksum_pack (OM_uint32 *minor_status,
			 const gss_cred_id_t initiator_cred_handle,
			 const gss_channel_bindings_t input_chan_bindings,
			 OM_uint32 req_flags, char **data, size_t * datalen)
{
  char *p;

  *datalen = 24;
  p = *data = malloc (*datalen);
  if (!p)
    {
      if (minor_status)
	*minor_status = ENOMEM;
      return GSS_S_FAILURE;
    }

  /*
   * RFC 1964 / gssapi-cfx:
   *
   * The checksum value field's format is as follows:
   *
   * Byte    Name    Description
   * 0..3    Lgth    Number of bytes in Bnd field;
   *                 Currently contains hex 10 00 00 00
   *                 (16, represented in little-endian form)
   */

  memcpy (&p[0], "\x10\x00\x00\x00", 4);	/* length of Bnd */

  /*
   * 4..19   Bnd     MD5 hash of channel bindings, taken over all non-null
   *                 components of bindings, in order of declaration.
   *                 Integer fields within channel bindings are represented
   *                 in little-endian order for the purposes of the MD5
   *                 calculation.
   *
   *   In computing the contents of the "Bnd" field, the following detailed
   *   points apply:
   *
   *   (1) Each integer field shall be formatted into four bytes, using
   *   little-endian byte ordering, for purposes of MD5 hash
   *   computation.
   *
   *   (2) All input length fields within gss_buffer_desc elements of a
   *   gss_channel_bindings_struct, even those which are zero-valued,
   *   shall be included in the hash calculation; the value elements of
   *   gss_buffer_desc elements shall be dereferenced, and the
   *   resulting data shall be included within the hash computation,
   *   only for the case of gss_buffer_desc elements having non-zero
   *   length specifiers.
   *
   *   (3) If the caller passes the value GSS_C_NO_BINDINGS instead of
   *   a valid channel bindings structure, the Bnd field shall be set
   *   to 16 zero-valued bytes.
   *
   */

  /* XXX We only support GSS_C_NO_CHANNEL_BINDINGS. */
  if (input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS)
    {
      free (p);
      return GSS_S_BAD_BINDINGS;
    }

  memset (&p[4], 0, 16);

  /*
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
   */

  req_flags &=			/* GSS_C_DELEG_FLAG | */
    GSS_C_MUTUAL_FLAG |
    GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG |
    GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG;

  p[20] = req_flags & 0xFF;
  p[21] = (req_flags >> 8) & 0xFF;
  p[22] = (req_flags >> 16) & 0xFF;
  p[23] = (req_flags >> 24) & 0xFF;

  /*
   *    24..25       DlgOpt  The delegation option identifier (=1) in
   *                 little-endian order [optional].  This field
   *                 and the next two fields are present if and
   *                 only if GSS_C_DELEG_FLAG is set as described
   *                 in section 4.1.1.1.
   *    26..27       Dlgth   The length of the Deleg field in little-
   *                 endian order [optional].
   *    28..(n-1)    Deleg   A KRB_CRED message (n = Dlgth + 28)
   *                 [optional].
   *    n..last      Exts    Extensions [optional].
   *
   */

  if (req_flags & GSS_C_DELEG_FLAG)
    {
      /* XXX We don't support credential delegation yet.  We should
         not fail here, as GSS_C_DELEG_FLAG is masked out above, and
         in context.c. */
    }

  return GSS_S_COMPLETE;
}
