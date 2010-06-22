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

from nose.tools import assert_equals, raises

from sdp import parseSdpMessage, SdpParsingError

class TestSdpMessageParser:
	def test_correct_parsing(self):
		"""Test normal SDP message parsing for correctness"""
		msg = "v=0\no=Foo 123 456 IN IP4 1.1.1.1\ns=SDP test\n" + \
			"i=Just a unit test\nu=http://voiphpc.blogspot.com\n" + \
			"e=twu200@gmail.com\nt=112233 445566\n" + \
			"m=audio 12345 RTP/AVP 0\na=rtpmap:0 PCMU/8000"
		sessionDescription, mediaDescriptions = parseSdpMessage(msg)

		assert_equals(sessionDescription["v"], "0")
		assert_equals(sessionDescription["o"][:3], "Foo")
		assert_equals(sessionDescription["s"], "SDP test")
		assert_equals(sessionDescription["i"], "Just a unit test")
		assert_equals(sessionDescription["u"], "http://voiphpc.blogspot.com")
		assert_equals(sessionDescription["e"], "twu200@gmail.com")
		assert_equals(sessionDescription["t"], "112233 445566")
		assert_equals(mediaDescriptions[0]["m"], "audio 12345 RTP/AVP 0")
		assert_equals(mediaDescriptions[0]["a"], "rtpmap:0 PCMU/8000")
		assert_equals(len(mediaDescriptions), 1)

	def test_correct_parsing_empty_message(self):
		"""Test for correct handling of an empty SDP message"""
		sessionDescription, mediaDescriptions = parseSdpMessage("")
		assert_equals(len(sessionDescription), 0)
		assert_equals(len(mediaDescriptions), 0)

	def test_correct_parsing_only_whitespaces(self):
		"""Test for correct handling of an SDP message with whitespaces only"""
		sessionDescription, mediaDescriptions = parseSdpMessage(
			"  \n\r\n\r   \t\t   ")
		assert_equals(len(sessionDescription), 0)
		assert_equals(len(mediaDescriptions), 0)

	@raises(SdpParsingError)
	def test_parsing_malformed_message_line(self):
		"""Test SDP parsing of a malformed line (no '=')"""
		parseSdpMessage("\\" * 10)	

	def test_multiple_media_sections(self):
		"""Test for correct parsing of multiple media sections (valid)"""
		sessionDescription, mediaDescriptions = parseSdpMessage(
			"v=0\no=Foo\n" + \
			"m=audio 12345 RTP/AVP 0\na=audioattribute\n" + \
			"m=video 12346 RTP/AVP 0\na=videoattribute\n")

		assert_equals(sessionDescription["v"], "0")
		assert_equals(sessionDescription["o"], "Foo")
		assert_equals(len(mediaDescriptions), 2)
		assert_equals(mediaDescriptions[0]["m"][:5], "audio")
		assert_equals(mediaDescriptions[0]["a"], "audioattribute")
		assert_equals(mediaDescriptions[1]["m"][:5], "video")
		assert_equals(mediaDescriptions[1]["a"], "videoattribute")

	def test_multiple_lines_with_same_type(self):
		"""Test for correct parsing of multiple lines with same type"""
		sessionDescription, _ = parseSdpMessage(
			"v=0\no=foo1\ns=test\ni=test\no=foo2\nt=12345\n")
		assert_equals(sessionDescription["o"], "foo2")

	def test_stripping(self):
		"""Test for correct stripping of whitespaces from SDP lines"""
		sessionDescription, mediaDescriptions = parseSdpMessage(
			"v=0\n\t\t o=1 2 3 4 5 6\n   s=Subject  \t\ni= Info \n" + \
			" \t  m=audio 41000 RTP/AVP 0\t  \t")

		assert_equals(sessionDescription["v"], "0")
		assert_equals(sessionDescription["o"], "1 2 3 4 5 6")
		assert_equals(sessionDescription["s"], "Subject")
		assert_equals(sessionDescription["i"], "Info")
		assert_equals(mediaDescriptions[0]["m"], "audio 41000 RTP/AVP 0")
