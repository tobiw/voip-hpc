################################################################################
#
# Stand-alone VoIP honeypot client (preparation for Dionaea integration)
# Copyright (c) 2010 Tobias Wulff (twu200 at gmail)
#
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
# 
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
################################################################################

import urllib.parse

sessionDescriptionTypes = {
	"v": "protocol version",
	"o": "session owner",
	"s": "session name",
	"i": "session information",
	"u": "uri",
	"e": "email address",
	"p": "phone number",
	"c": "connection information",
	"b": "bandwidth information",
	"z": "time zone adjustment",
	"k": "encryption key",
	"t": "active time",
	"r": "repeat time",
	"a": "session attribute line"
}

mediaDescriptionTypes = {
	"m": "media name",
	"i": "media title",
	"c": "connection information",
	"b": "bandwidth information",
	"k": "encryption key",
	"a": "attribute line"
}

class SdpParsingError(Exception):
	"""Exception class for errors occuring during SDP message parsing"""

def parseSdpMessage(msg):
	"""Parses an SDP message (string), returns a tupel of dictionaries with
	{type: value} entries: (sessionDescription, mediaDescriptions)"""
	# Normalize line feed and carriage return to \n
	msg = msg.replace("\n\r", "\n")

	# Decode message (e.g. "%20" -> " ")
	msg = urllib.parse.unquote(msg)

	# Sanitize input: remove superfluous leading and trailing newlines and
	# spaces
	msg = msg.strip("\n\r\t ")

	# Split message into session description, and media description parts
	SEC_SESSION, SEC_MEDIA = range(2)
	curSection = SEC_SESSION
	sessionDescription = {}
	mediaDescriptions = []
	mediaDescriptionNumber = -1

	# Process each line individually
	if len(msg) > 0:
		lines = msg.split("\n")
		for line in lines:
			# Get first two characters of line and check for "type="
			if len(line) < 2:
				raise SdpParsingError("Line too short")
			elif line[1] != "=":
				raise SdpParsingError("Invalid SDP line")

			type = line[0]
			value = line[2:].strip("\n\r\t ")

			# Change current section if necessary
			# (session -> media -> media -> ...)
			if type == "m":
				curSection = SEC_MEDIA
				mediaDescriptionNumber += 1
				mediaDescriptions.append({})

			# Store the SDP values
			if curSection == SEC_SESSION:
				sessionDescription[type] = value
			elif curSection == SEC_MEDIA:
				mediaDescriptions[mediaDescriptionNumber][type] = value

	return (sessionDescription, mediaDescriptions)
