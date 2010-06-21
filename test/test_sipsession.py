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

import socket
import logging

from nose.tools import assert_equals, raises

from sip import SipSession, RtpUdpStream, logger

# Set logger to _not_ print debug and info messages
logger.setLevel(logging.ERROR)

class TestSipSession:
	@classmethod
	def setUpClass(self):
		# Create main connection for sending data (mock for Sip class)
		self.__socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.__socket.bind(('localhost', 1111))
		SipSession.sipConnection = self.__socket

		# Create socket for receiving data
		self.__recvSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.__recvSocket.bind(('localhost', 1112))

	@classmethod
	def tearDownClass(self):
		self.__recvSocket.close()
		self.__socket.close()

	def test_handle_empty_ACK(self):
		"""Handling of SipSession and RtpUdpStream handling an empty ACK
		packet (empty apart from Call-ID)"""
		s = SipSession(('localhost', 1112), 123, 29999)
		s.handle_ACK([], "")

		# Close RTP stream so that the socket doesn't stay open after this test
		s._SipSession__rtpStream.close()

	def test_handle_BYE_without_session(self):
		"""Handling of SipSession and RtpUdpStream handling on BYE message
		without an established session"""
		s = SipSession(('localhost', 1112), 123, 29999)
		s.handle_BYE([], "")

		data, conInfo = self.__recvSocket.recvfrom(1024)
		assert_equals(conInfo[1], 1111)
		assert_equals(data.decode('utf-8'), "SIP/2.0 200 OK")
