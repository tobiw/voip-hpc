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

import threading
import asyncore
import socket
import sys
import os
from time import sleep
from random import randint

from nose.tools import assert_equals

# Make sure we're in the project's root directory
if os.path.split(os.path.abspath("."))[-1] == "test":
	sys.path.insert(0, os.path.abspath(".."))
else:
	sys.path.insert(0, os.path.abspath("."))

# Manually import module from parent directory
sip = __import__("sip")
config = __import__("config")
del sys.path[0]

class VoipClient:
	def __init__(self):
		self.__s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.__s.bind(('', 0))
		self.__port = self.__s.getsockname()[1]
		self.__callId = randint(1000, 9999)

	def send(self, msg):
		self.__s.sendto(msg.encode('utf-8'), ('localhost', 5060))

	def recv(self):
		data, _ = self.__s.recvfrom(1024)
		data = data.decode('utf-8')
		return data

	def invite(self):
		sdpMsg = """v=0
			o=socketHelper 5566 7788 IN IP4 1.2.3.4
			s=SDP Subject
			i=SDP information
			c=IN IP4 1.2.3.5
			t=0 0
			m=audio 30123 RTP/AVP 0"""

		sipMsg = """INVITE foo SIP/2.0
			Via: SIP/2.0/UDP 1.2.3.4
			From: sockerHelper
			To: foo bar
			Call-ID: {callId}
			CSeq: 1 INVITE
			Contact: socketHelper
			Content-Type: application/sdp
			Content-Length: {sdp}""".format(
				callId=self.__callId,
				sdp=len(sdpMsg))

		self.send(sipMsg + "\n\n" + sdpMsg)

	def ack(self):
		self.send("""ACK foo SIP/2.0
			Via: SIP/2.0/UDP 1.2.3.4
			From: sockerHelper
			To: foo bar
			Call-ID: {callId}
			CSeq: 1 ACK
			Contact: socketHelper""".format(
				callId=self.__callId))

	def bye(self):
		self.send("""BYE foo SIP/2.0
			Via: SIP/2.0/UDP 1.2.3.4
			From: sockerHelper
			To: foo bar
			Call-ID: {callId}
			CSeq: 1 BYE
			Contact: socketHelper""".format(
				callId=self.__callId))

	def getCallId(self): return self.__callId

class ClientThread(threading.Thread):
	def run(self):
		try:
			self.__run()
		except AssertionError as e:
			print("Functional test failed (assertion error)")
			print(e)
		except Exception as e:
			print("Function test failed (unhandled error)")
			print(e)
		else:
			print("Functional test finished successfully")

		print("Press Ctrl-C to exit the Honeypot")

	def __run(self):
		c = VoipClient()

		print("CLIENT: Sending INVITE")
		c.invite()

		# Expecting a 180 Ringing first
		data = c.recv()
		assert_equals(data.split('\n')[0], "SIP/2.0 180 Ringing")

		# Expecting a 200 OK with the server's SDP message
		data = c.recv()
		data = data.split('\n')
		assert_equals(data[0], "SIP/2.0 200 OK")
		assert_equals(data[4][:data[4].find('@')],
			"From: {0} <sip:{0}".format(
				config.g_config['modules']['python']['sip']['user']))
		assert_equals(data[5], "Call-ID: {}".format(c.getCallId()))

		print("CLIENT: Sending ACK")
		c.ack()

		# Active session goes here ...
		sleep(3)

		print("CLIENT: Sending BYE")
		c.bye()

		# Expecting a 200 OK
		data = c.recv()
		assert_equals(data.split('\n')[0], "SIP/2.0 200 OK")

		# Check if stream dump file has been created
		# This will raise an exception if path doesn't exist
		os.stat("stream_30123.rtpdump")

# Create Honeypot
s = sip.Sip()
s.bind(('localhost', 5060))

# Create client as a thread
ClientThread().start()

try:
	asyncore.loop()
except KeyboardInterrupt:
	print("Asyncore loop interrupted: exit")
except Exception as e:
	print("Unhandled exception")
	print(e)

s.close()
