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
# Parts of the SIP response codes and a lot of SIP message parsing are taken
# from the Twisted Core: http://twistedmatrix.com/trac/wiki/TwistedProjects
#
################################################################################

import logging

from connection import connection
from sdp import parseSdpMessage, SdpParsingError

# Setup logging mechanism
logger = logging.getLogger('sip')
logger.setLevel(logging.DEBUG)
logConsole = logging.StreamHandler()
logConsole.setLevel(logging.DEBUG)
logConsole.setFormatter(logging.Formatter(
	"%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
logger.addHandler(logConsole)

TRYING                      = '100'
RINGING                     = '180'
CALL_FWD                    = '181'
QUEUED                      = '182'
PROGRESS                    = '183'
OK                          = '200'
ACCEPTED                    = '202'
MULTI_CHOICES               = '300'
MOVED_PERMANENTLY           = '301'
MOVED_TEMPORARILY           = '302'
SEE_OTHER					= '303'
USE_PROXY                   = '305'
ALT_SERVICE                 = '380'
BAD_REQUEST                 = '400'
UNAUTHORIZED                = '401'
PAYMENT_REQUIRED            = '402'
FORBIDDEN                   = '403'
NOT_FOUND                   = '404'
NOT_ALLOWED                 = '405'
NOT_ACCEPTABLE              = '406'
PROXY_AUTH_REQUIRED         = '407'
REQUEST_TIMEOUT             = '408'
CONFLICT                    = '409'
GONE                        = '410'
LENGTH_REQUIRED             = '411'
ENTITY_TOO_LARGE            = '413'
URI_TOO_LARGE               = '414'
UNSUPPORTED_MEDIA           = '415'
UNSUPPORTED_URI				= '416'
BAD_EXTENSION               = '420'
EXTENSION_REQUIRED			= '421'
INTERVAL_TOO_BRIEF			= '423'
NOT_AVAILABLE               = '480'
NO_TRANSACTION              = '481'
LOOP                        = '482'
TOO_MANY_HOPS               = '483'
ADDRESS_INCOMPLETE          = '484'
AMBIGUOUS                   = '485'
BUSY_HERE                   = '486'
CANCELLED                   = '487'
NOT_ACCEPTABLE_HERE         = '488'
REQUEST_PENDING				= '491'
UNDECIPHERABLE				= '493'
INTERNAL_ERROR              = '500'
NOT_IMPLEMENTED             = '501'
BAD_GATEWAY                 = '502'
UNAVAILABLE                 = '503'
GATEWAY_TIMEOUT             = '504'
SIP_VERSION_NOT_SUPPORTED   = '505'
MESSAGE_TOO_LARGE			= '513'
BUSY_EVERYWHERE             = '600'
DECLINE                     = '603'
DOES_NOT_EXIST              = '604'
NOT_ACCEPTABLE_6xx          = '606'

# SIP Responses from SIP Demystified by Gonzalo Camarillo
RESPONSE = { 
	# 1xx
	TRYING:                     '100 Trying',
	RINGING:                    '180 Ringing',
	CALL_FWD:                   '181 Call is being forwarded',
	QUEUED:                     '182 Queued',
	PROGRESS:                   '183 Session progress',

	# 2xx
	OK:                         '200 OK',
	ACCEPTED:                   '202 Accepted',

	# 3xx
	MULTI_CHOICES:              '300 Multiple choices',
	MOVED_PERMANENTLY:          '301 Moved permanently',
	MOVED_TEMPORARILY:          '302 Moved temporarily',
	SEE_OTHER:					'303 See other',
	USE_PROXY:                  '305 Use proxy',
	ALT_SERVICE:                '380 Alternative service',

	# 4xx
	BAD_REQUEST:                '400 Bad request',
	UNAUTHORIZED:               '401 Unauthorized',
	PAYMENT_REQUIRED:           '402 Payment required',
	FORBIDDEN:                  '403 Forbidden',
	NOT_FOUND:                  '404 Not found',
	NOT_ALLOWED:                '405 Method not allowed',
	NOT_ACCEPTABLE:             '406 Not acceptable',
	PROXY_AUTH_REQUIRED:        '407 Proxy authentication required',
	REQUEST_TIMEOUT:            '408 Request time-out',
	CONFLICT:                   '409 Conflict',
	GONE:                       '410 Gone',
	LENGTH_REQUIRED:            '411 Length required',
	ENTITY_TOO_LARGE:           '413 Request entity too large',
	URI_TOO_LARGE:              '414 Request-URI too large',
	UNSUPPORTED_MEDIA:          '415 Unsupported media type',
	UNSUPPORTED_URI:			'416 Unsupported URI scheme',
	BAD_EXTENSION:              '420 Bad extension',
	EXTENSION_REQUIRED:			'421 Extension required',
	INTERVAL_TOO_BRIEF:			'423 Interval too brief',
	NOT_AVAILABLE:              '480 Temporarily not available',
	NO_TRANSACTION:             '481 Call leg/transaction does not exist',
	LOOP:                       '482 Loop detected',
	TOO_MANY_HOPS:              '483 Too many hops',
	ADDRESS_INCOMPLETE:         '484 Address incomplete',
	AMBIGUOUS:                  '485 Ambiguous',
	BUSY_HERE:                  '486 Busy here',
	CANCELLED:                  '487 Request cancelled',
	NOT_ACCEPTABLE_HERE:        '488 Not acceptable here',
	REQUEST_PENDING:			'491 Request pending',
	UNDECIPHERABLE:				'493 Undecipherable',

	# 5xx
	INTERNAL_ERROR:             '500 Internal server error',
	NOT_IMPLEMENTED:            '501 Not implemented',
	BAD_GATEWAY:                '502 Bad gateway',
	UNAVAILABLE:                '503 Service unavailable',
	GATEWAY_TIMEOUT:            '504 Gateway time-out',
	SIP_VERSION_NOT_SUPPORTED:  '505 SIP version not supported',
	MESSAGE_TOO_LARGE:			'513 Message too large',

	# 6xx
	BUSY_EVERYWHERE:            '600 Busy everywhere',
	DECLINE:                    '603 Decline',
	DOES_NOT_EXIST:             '604 Does not exist anywhere',
	NOT_ACCEPTABLE_6xx:         '606 Not acceptable'
}

# SIP headers have short forms
shortHeaders = {"call-id": "i",
                "contact": "m",
                "content-encoding": "e",
                "content-length": "l",
                "content-type": "c",
                "from": "f",
                "subject": "s",
                "to": "t",
                "via": "v",
				"cseq": "cseq"
                }

longHeaders = {}
for k, v in shortHeaders.items():
    longHeaders[v] = k
del k, v

class SipParsingError(Exception):
	"""Exception class for errors occuring during SIP message parsing"""

def parseSipMessage(msg):
	"""Parses a SIP message (string), returns a tupel (type, firstLine, header,
	body)"""
	# Sanitize input: remove superfluous leading and trailing newlines and
	# spaces
	msg = msg.strip("\n\r\t ")

	# Split request/status line plus headers and body: we don't care about the
	# body in the SIP parser
	parts = msg.split("\n\n", 1)
	if len(parts) < 1:
		logger.error("Message too short")
		raise SipParsingError("Message too short")

	msg = parts[0]

	# Python way of doing a ? b : c
	body = len(parts) == 2 and parts[1] or ""

	# Normalize line feed and carriage return to \n
	msg = msg.replace("\n\r", "\n")

	# Split lines into a list, each item containing one line
	lines = msg.split('\n')

	# Get message type (first word, smallest possible one is "ACK" or "BYE")
	sep = lines[0].find(' ')
	if sep < 3:
		raise SipParsingError("Malformed request or status line")

	msgType = lines[0][:sep]
	firstLine = lines[0][sep+1:]

	# Done with first line: delete from list of lines
	del lines[0]

	# Parse header
	headers = {}
	for i in range(len(lines)):
		# Take first line and remove from list of lines
		line = lines.pop(0)

		# Strip each line of leading and trailing whitespaces
		line = line.strip("\n\r\t ")

		# Break on empty line (end of headers)
		if len(line.strip(' ')) == 0:
			break

		# Parse header lines
		sep = line.find(':')
		if sep < 1:
			raise SipParsingError("Malformed header line (no ':')")

		# Get header identifier (word before the ':')
		identifier = line[:sep]
		identifier = identifier.lower()

		# Check for valid header
		if identifier not in shortHeaders.keys() and \
			identifier not in longHeaders.keys():
			raise SipParsingError("Unknown header type: {}".format(identifier))

		# Get long header identifier if necessary
		if identifier in longHeaders.keys():
			identifier = longHeaders[identifier]

		# Get header value (line after ':')
		value = line[sep+1:].strip(' ')

		# The Via header can occur multiple times
		if identifier == "via":
			if identifier not in headers:
				headers["via"] = [value]
			else:
				headers["via"].append(value)

		# Assign any other header value directly to the header key
		else:
			headers[identifier] = value

	# Return message type, header dictionary, and body string
	return (msgType, firstLine, headers, body)

class RtpUdpStream(connection):
	"""RTP stream that can send data and writes the whole conversation to a
	file"""
	def __init__(self, address, port):
		connection.__init__(self, 'udp')

		# The address and port of the remote host
		self.__address = address
		self.__port = port

		# Send byte buffer
		self.__sendBuffer = b''

		# TODO: Using the remote RTP port number as an identifier might be a bad
		# idea
		streamDumpFile = "stream_{}.rtpdump".format(port)

		# Catch IO errors
		try:
			self.__streamDump = open(streamDumpFile, "wb")
		except IOError as e:
			logger.error("Could not open stream dump file: {}".format(e))
			self.__streamDump = None

		logger.debug("Created RTP channel on port {}".format(port))

	def writable(self):
		return len(self.__sendBuffer) > 0

	def handle_close(self):
		self.close()

	def handle_read(self):
		# Don't have to get address and port because they're already known since
		# __init__
		data, _ = self.recvfrom(1024)

		# Write data to disk
		# TODO: Make sure this cannot cause DoS
		if self.__streamDump:
			self.__streamDump.write(data)

	def handle_write(self):
		# Because of the writable function, handle_write will only be called if
		# there is data in the send buffer
		bytesSent = self.sendto(self.__sendBuffer)

		# Write the sent part of the buffer to the stream dump file
		# TODO: separate inbound and outbound traffic?
		if self.__streamDump:
			self.__streamDump.write(self.__sendBuffer[:bytesSend])

		# Shift sending window for next send or handle_write operation
		self.__sendBuffer = self.__sendBuffer[bytesSend:]

	def send(self, msg):
		# Append to send buffer, handle_write will take care of socket operation
		self.__sendBuffer += msg.encode('utf-8')

	def close(self):
		if self.__streamDump:
			self.__streamDump.close()

		connection.close()

class SipSession(object):
	"""Usually, a new SipSession instance is created when the SIP server
	receives an INVITE message"""
	NO_SESSION, SESSION_SETUP, ACTIVE_SESSION, SESSION_TEARDOWN = range(4)
	sipConnection = None

	def __init__(self, conInfo, callId, rtpPort):
		if not SipSession.sipConnection:
			logger.error("SIP connection class variable not set")

		# Store incoming information of the remote host
		self.__callId = callId
		self.__state = SipSession.SESSION_SETUP
		self.__remoteAddress = conInfo[0]
		self.__remoteSipPort = conInfo[1]
		self.__remoteRtpPort = rtpPort

		# Create RTP stream instance and pass address and port of listening
		# remote RTP host
		self.__rtpStream = RtpUdpStream(self.__remoteAddress,
			self.__remoteRtpPort)

		# Send our RTP port to the remote host as a 200 OK response to the
		# remote host's INVITE request
		localRtpPort = self.__rtpStream.getsockname()[1]
		self.send("SIP/2.0 200 OK\nContent-Type: application/sdp\n\n" +
			"v=0\no=Honeypot 0 0 IN IP4 localhost\nt=0 0\n" +
			"m=audio {} RTP/AVP 0".format(localRtpPort))

	def handle_ACK(self, headers, body):
		if self.__state == SipSession.SESSION_SETUP:
			logger.debug(
				"Waiting for ACK after INVITE -> got ACK -> active session")
			logger.info("Connection accepted (session {})".format(
				self.__callId))

			# Create RTP stream channel
			self.__rtpStream = RtpUdpStream(self.__remoteAddress,
				self.__remoteRtpPort)

			# Set current state to active (ready for multimedia stream)
			self.__state = SipSession.ACTIVE_SESSION

	def handle_BYE(self, headers, body):
		# Only close down RTP stream if session is active
		if self.__state == SipSession.ACTIVE_SESSION:
			self.__rtpStream.close()

		# A BYE ends the session immediately
		self.__state = SipSession.NO_SESSION

		# Send OK response to other client
		self.send("SIP/2.0 200 OK")

	def send(self, s):
		logger.debug("SIP session: sending to ({},{})".format(
			self.__address, self.__port))
		SipSession.sipConnection.sendto(s.encode('utf-8'),
				(self.__remoteAddress, self.__remoteSipPort))

class Sip(connection):
	"""Only UDP connections are supported at the moment"""
	def __init__(self):
		connection.__init__(self, 'udp')

		# Set SIP connection in session class variable
		SipSession.sipConnection = self

		# Dictionary with SIP sessions (key is call-id)
		self.__sessions = {}

	def handle_read(self):
		"""Callback for handling incoming SIP traffic"""
		# TODO: Handle long messages
		data, conInfo = self.recvfrom(1024)

		# Get byte data and decode to string
		data = data.decode("utf-8")

		# Parse SIP message
		try:
			msgType, firstLine, headers, body = parseSipMessage(data)
		except SipParsingError as e:
			logger.error(e)
			return

		if msgType == 'INVITE':
			self.sip_INVITE(conInfo, firstLine, headers, body)
		elif msgType == 'ACK':
			self.sip_ACK(firstLine, headers, body)
		elif msgType == 'OPTIONS':
			self.sip_OPTIONS(firstLine, headers, body)
		elif msgType == 'BYE':
			self.sip_BYE(firstLine, headers, body)
		elif msgType == 'CANCEL':
			self.sip_CANCEL(firstLine, headers, body)
		elif msgType == 'REGISTER':
			self.sip_REGISTER(firstLine, headers, body)
		elif msgType == 'SIP/2.0':
			self.sip_RESPONSE(firstLine, headers, body)
		elif msgType == 'Error':
			logger.error("Error on parsing SIP message")
		else:
			logger.error("Error: unknown header")

	# SIP message type handlers
	def sip_INVITE(self, conInfo, requestLine, headers, body):
		# Print SIP header
		logger.info("Received INVITE")
		for k, v in headers.items():
			logger.info("SIP header {}: {}".format(k, v))

		# Header has to define content-type: application/sdp if body contains
		# SDP message
		if "content-type" not in headers:
			if headers["contant-type"] != "application/sdp":
				logger.error("INVITE without SDP message: exit")
				return

		# Check for SDP body
		if not body:
			logger.error("INVITE without SDP message: exit")
			return

		# Parse SDP part of session invite
		try:
			sessionDescription, mediaDescriptions = parseSdpMessage(body)
		except SdpParsingError as e:
			logger.error(e)
			return

		# Check for all necessary fields
		sdpSessionOwnerParts = sessionDescription['o'].split(' ')
		if len(sdpSessionOwnerParts) < 6:
			logger.error("SDP session owner field to short: exit")
			return

		logger.debug("Parsed SDP message:")
		logger.debug(sessionDescription)
		logger.debug(mediaDescriptions)

		if "call-id" not in headers:
			logger.error("SIP headers have to include Call-ID: exit")
			return

		# Get RTP port from SDP media description
		if len(mediaDescriptions) < 1:
			logger.error("SDP message has to include a media description: exit")
			return
		
		mediaDescriptionParts = mediaDescriptions[0]['m'].split(' ')
		if mediaDescriptionParts[0] != 'audio':
			logger.error("SDP media description has to be of audio type: exit")
			return

		rtpPort = mediaDescriptionParts[1]

		# Establish a new SIP session
		callId = headers["call-id"]
		newSession = SipSession(conInfo, callId, rtpPort)

		# Store session object in sessions dictionary
		self.__sessions[callId] = newSession

	def sip_ACK(self, requestLine, headers, body):
		logger.info("Received ACK")

		if "call-id" not in headers:
			logger.error("SIP headers have to include Call-ID: exit")
			return

		# Get SIP session for given Call-ID
		try:
			s = self.__sessions[headers["call-id"]]
		except KeyError:
			logger.error("Given Call-ID does not belong to a session: exit")
			return
		
		# Handle incoming ACKs depending on current state
		s.handle_ACK(headers, body)

	def sip_OPTIONS(self, requestLine, headers, body):
		logger.info("Received OPTIONS")

	def sip_BYE(self, requestLine, headers, body):
		logger.info("Received BYE")

		if "call-id" not in headers:
			logger.error("SIP headers have to include Call-ID: exit")
			return

		# Get SIP session for given Call-ID
		try:
			s = self.__sessions[headers["call-id"]]
		except KeyError:
			logger.error("Given Call-ID does not belong to a session: exit")
			return
		
		# Handle incoming BYE request depending on current state
		s.handle_BYE(headers, body)

	def sip_CANCEL(self, requestLine, headers, body):
		logger.info("Received CANCEL")

	def sip_REGISTER(self, requestLine, headers, body):
		logger.info("Received REGISTER")

	def sip_RESPONSE(self, statusLine, headers, body):
		logger.info("Received a response")
