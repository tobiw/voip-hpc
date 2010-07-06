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
import hashlib
from time import sleep
from random import randint
from glob import glob

from nose.tools import assert_equals

# Make sure we're in the project's root directory
if os.path.split(os.path.abspath("."))[-1] == "test":
	sys.path.insert(0, os.path.abspath(".."))
else:
	sys.path.insert(0, os.path.abspath("."))

# Manually import module from parent directory
sip = __import__("sip")
config = __import__("config")
parentDir = sys.path.pop(0)
testDir = parentDir + "/test/streams"

# Change to test/streams path
print("Changing directory to " + testDir)
os.chdir(testDir)

# Delete all stream files
for oldStreamFile in glob("stream_*_*.rtpdump"):
	os.remove(oldStreamFile)

def getHeader(data, header):
	for line in data.split('\n'):
		lineParts = line.split(':')
		if lineParts[0] == header:
			return lineParts[1].strip(' \t')

	return ""

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

	def invite(self, challengeResponse=None):
		sdpMsg = """v=0
			o=socketHelper 5566 7788 IN IP4 127.0.0.1
			s=SDP Subject
			i=SDP information
			c=IN IP4 127.0.0.1
			t=0 0
			m=audio 30123 RTP/AVP 0"""

		sipMsg = """INVITE foo SIP/2.0
			Via: SIP/2.0/UDP 127.0.0.1
			From: sockerHelper
			To: foo bar
			Call-ID: {callId}
			CSeq: 1 INVITE
			Contact: socketHelper
			Accept: application/sdp
			Content-Type: application/sdp
			Content-Length: {sdp}""".format(
				callId=self.__callId,
				sdp=len(sdpMsg))

		if challengeResponse:
			sipMsg += '\nAuthorization: Digest username="100", ' + \
				'realm="100@localhost", uri="sip:100@localhost", ' + \
				'response="{}"'.format(challengeResponse)

		self.send(sipMsg + "\n\n" + sdpMsg)

	def options(self):
		self.send("""OPTIONS foo SIP/2.0
			Via: SIP/2.0/UDP 127.0.0.1
			From: socketHelper
			To: foo bar
			Call-ID: {callId}
			CSeq: 1 OPTIONS
			Contact: socketHelper""")

	def ack(self, challengeResponse):
		sipMsg = """ACK foo SIP/2.0
			Via: SIP/2.0/UDP 127.0.0.1
			From: socketHelper
			To: foo bar
			Call-ID: {callId}
			CSeq: 1 ACK
			Contact: socketHelper""".format(callId=self.__callId)

		if challengeResponse:
			sipMsg += '\nAuthorization: Digest username="100", ' + \
				'realm="100@localhost", uri="sip:100@localhost", ' + \
				'response="{}"'.format(challengeResponse)

		self.send(sipMsg)

	def bye(self, challengeResponse):
		sipMsg = """BYE foo SIP/2.0
			Via: SIP/2.0/UDP 127.0.0.1
			From: sockerHelper
			To: foo bar
			Call-ID: {callId}
			CSeq: 1 BYE
			Contact: socketHelper""".format(callId=self.__callId)

		if challengeResponse:
			sipMsg += '\nAuthorization: Digest username="100", ' + \
				'realm="100@localhost", uri="sip:100@localhost", ' + \
				'response="{}"'.format(challengeResponse)

		self.send(sipMsg)

	def getCallId(self): return self.__callId

class ClientThread(threading.Thread):
	def run(self):
		try:
			self.__run()
		except AssertionError as e:
			print("Functional test failed (assertion error)")
			print(e)
		except Exception as e:
			print("Functional test failed (unhandled error)")
			print(e)
		else:
			print("Functional test finished successfully")

		print("Press Ctrl-C to exit the Honeypot")

	def __run(self):
		c = VoipClient()

		print("CLIENT: Sending OPTIONS")
		c.options()

		data = c.recv().split('\n')
		for d in data:
			d = d.split(':')
			if d[0] == "Allow":
				# Get individual arguments
				methods = [x.strip(' ') for x in d[1].split(',')]
				assert "INVITE" in methods
				assert "OPTIONS" in methods
				assert "ACK" in methods
				assert "CANCEL" in methods
				assert "BYE" in methods
				assert "REGISTER" not in methods

		print("CLIENT: Sending INVITE")
		c.invite()

		# Expecting a 401 Unauthorized
		data = c.recv()
		assert_equals(data.split('\n')[0], "SIP/2.0 401 Unauthorized")
		print("Received 401 Unauthorized")

		# Get nonce from received data
		nonce = ""
		auth = getHeader(data, 'WWW-Authenticate').strip(' \n\r\t')
		auth = auth.split(' ', 1)[1] # [0] has to be "Digest"
		authLineParts = [x.strip(' \t\r\n') for x in auth.split(',')]
		for x in authLineParts:
			k, v = x.split('=', 1)
			if k == "nonce":
				nonce = v.strip(' \n\r\t"\'')
		assert nonce

		# Create challenge response
		# The calculation of the expected response is taken from
		# Sipvicious (c) Sandro Gaucci
		def hash(s):
			return hashlib.md5(s.encode('utf-8')).hexdigest()
		
		a1 = hash("100:100@localhost:F2DS13G5")
		a2 = hash("INVITE:sip:100@localhost")
		challengeResponse = hash("{}:{}:{}".format(a1, nonce, a2))

		# Send INVITE again with authentication
		print("CLIENT: Sending INVITE with challenge response")
		c.invite(challengeResponse)

		# Expecting a 180 Ringing first
		data = c.recv()
		assert_equals(data.split('\n')[0], "SIP/2.0 180 Ringing")

		# Expecting a 200 OK with the server's SDP message
		data = c.recv().split('\n')
		assert_equals(data[0], "SIP/2.0 200 OK")
		assert_equals(data[4][:data[4].find('@')],
			"From: {0} <sip:{0}".format(
				config.g_config['modules']['python']['sip']['user']))
		assert_equals(data[5], "Call-ID: {}".format(c.getCallId()))

		print("CLIENT: Sending ACK")
		c.ack(challengeResponse)

		# Active session goes here ...
		sleep(3)

		# Active session ends
		print("CLIENT: Sending BYE")
		c.bye(challengeResponse)

		# Expecting a 200 OK
		data = c.recv()
		assert_equals(data.split('\n')[0], "SIP/2.0 200 OK")

		# Check if stream dump file has been created
		assert glob("stream_*_*.rtpdump")

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
