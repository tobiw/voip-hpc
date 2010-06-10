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
#
# Some test cases were taken from the SIP protocol part of Twisted Core:
# http://twistedmatrix.com/trac/wiki/TwistedProjects
#
################################################################################

import socket
import time
from nose.tools import assert_equals

from sip import sip, parseSipMessage

class TestSipMessageParser:
	def test_correct_parsing(self):
		"""Test normal message parsing for correctness"""
		msgType, headers, body = parseSipMessage("""INVITE sip:foo SIP/2.0
			From: test
			To: foo
			Content-Length: 4

			1234""")

		assert_equals(msgType, "INVITE")
		assert_equals(headers["from"], "test")
		assert_equals(headers["to"], "foo")
		assert_equals(headers["content-length"], "4")
		assert_equals(body, "1234")

	def test_correct_parsing_short_headers(self):
		"""Test message parsing for correctness with short headers"""
		msgType, headers, body = parseSipMessage("""INVITE sip:foo SIP/2.0
			f: test
			t: foo
			l: 4

			1234""")

		assert_equals(msgType, "INVITE")
		assert_equals(headers["from"], "test")
		assert_equals(headers["to"], "foo")
		assert_equals(headers["content-length"], "4")
		assert_equals(body, "1234")

	def test_correct_parsing_empty_body(self):
		"""Test message parsing for correctness with an empty body"""
		msgType, headers, body = parseSipMessage("""INVITE sip:foo SIP/2.0
			f: test
			t: foo
			l: 0""")

		assert_equals(msgType, "INVITE")
		assert_equals(headers["from"], "test")
		assert_equals(headers["to"], "foo")
		assert_equals(headers["content-length"], "0")
		assert_equals(body, "")

	def test_mixed_short_and_long_headers(self):
		"""Test message parsing for correctness with mixed short and long
		headers"""
		msgType, headers, body = parseSipMessage("""INVITE sip:foo SIP/2.0
			From: test
			t: foo
			v: foobar
			content-length: 0""")

		assert_equals(msgType, "INVITE")
		assert_equals(headers["from"], "test")
		assert_equals(headers["to"], "foo")
		assert_equals(headers["via"], "foobar")
		assert_equals(headers["content-length"], "0")
		assert_equals(body, "")

	def test_long_header_line(self):
		"""Test message parsing with a very long header line"""
		msgType, headers, body = parseSipMessage("INVITE sip:foo SIP/2.0\n" + \
			"From: " + "x" * 1000)

		assert_equals(msgType, "INVITE")
		assert_equals(headers["from"], "x" * 1000)

	def test_header_decoding(self):
		"""Test message decoding of encoded characters in header"""
		msgType, headers, body = parseSipMessage("""INVITE sip:foo SIP/2.0
			From: %20foobar%20%20""")

		assert_equals(msgType, "INVITE")
		assert_equals(headers["from"], "foobar")

	def test_all_request_types(self):
		"""Test correct message parsing of all request types"""
		for t in ["INVITE", "ACK", "OPTIONS", "BYE", "CANCEL", "REGISTER"]:
			msgType, _, _ = parseSipMessage(t + " foo SIP/2.0\n")
			assert_equals(msgType, t)

#class TestSipConnection:
#	@classmethod
#	def setUpClass(self):
#		# Create socket to send messages to the SIP parser
#		self.sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#		self.sender.bind(('', 0))
#
#		# Create SIP parser which listens on port 1111
#		self.sip = sip()
#
#	@classmethod
#	def tearDownClass(self):
#		self.sender.close()
#
#	def sendMessage(self, msg):
#		self.sender.sendto(msg.encode('utf-8'), (('localhost', 1111)))
#
#	def test_request_with_random_newlines(self):
#		"""Test SIP connection with random CRLFs"""
#		self.sendMessage("\r\n\r\n\r\r\n\r\r\r" + """\
#			INVITE sip:foo SIP/2.0
#			From: test
#			To: foo
#			Content-Length: 4
#
#			1234""")
#
#	def test_short_request_with_random_newlines(self):
#		"""Test SIP connection with short headers and random CRLFs"""
#		self.sendMessage("\r\n\r\n\r\r\n\r\r\r" + """\
#			INVITE sip:foo SIP/2.0
#			f: test
#			t: foo
#			l: 4
#
#			1234""")
#
#	def test_request_without_contentlength(self):
#		"""Test SIP connection without Content-Length"""
#		self.sendMessage("""INVITE sip:foo SIP/2.0
#			f: test
#			t: foo
#
#			123456789""")
