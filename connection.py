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
import asyncore
import time
import logging

# Setup logging mechanism
logger = logging.getLogger('connection')
logger.setLevel(logging.DEBUG)
logConsole = logging.StreamHandler()
logConsole.setLevel(logging.DEBUG)
logConsole.setFormatter(logging.Formatter(
	"%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
logger.addHandler(logConsole)

class connection(asyncore.dispatcher):
	"""Connection class mockup (from connection.pyx in dionaea src)"""

	def __init__(self, proto=None, sock=None):
		"""Creates a new connection with TCP as its default transport
		protocol"""
		asyncore.dispatcher.__init__(self, sock)

		if sock == None:
			# Use TCP by default, and UDP if stated
			type = socket.SOCK_STREAM
			if proto and proto.lower() == 'udp':
				type = socket.SOCK_DGRAM

			# Create non-blocking socket
			self.create_socket(socket.AF_INET, type)

	def handle_established(self):
		"""Callback for a newly established connection (client or server)"""
		logger.info('Session established')

	def handle_read(self):
		"""Callback for incoming data (dionaea: handle_io_in)"""
		pass

	def handle_write(self):
		"""Callback for outgoing data (dionaea: handle_io_out)"""
		pass

	def handle_connect(self):
		"""Callback for successful connect (client)"""
		self.handle_established()

	def handle_close(self):
		"""Callback for a closed connection"""
		self.close()
		logger.info('Session closed')

	def handle_accept(self):
		"""Callback for successful accept (server)"""
		self.__conn, self.__address = self.accept()
		self.handle_established()
