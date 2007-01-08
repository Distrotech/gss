/* krb5/checksum.h --- (Un)pack checksum fields in Krb5 GSS contexts.
 * Copyright (C) 2003, 2004, 2005, 2006, 2007  Simon Josefsson
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
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

OM_uint32
_gss_krb5_checksum_pack (const gss_cred_id_t initiator_cred_handle,
			 const gss_channel_bindings_t input_chan_bindings,
			 OM_uint32 req_flags, char **data, size_t * datalen);
