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

from connection import connection
from nose.tools import assert_equals, raises, timed, with_setup
#from nose.plugins.attrib import attr
#from mock import patch

def test_connection_tcp():
	"""Creation of a TCP (default) connection object"""
	c = connection()
	assert c

def test_connection_udp():
	"""Creation of a UDP connection object"""
	c = connection('UdP')
	assert c

def test_connection_from_socket():
	"""Creation of a connection object from an existing socket"""
	import socket
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	c = connection(sock=s)
	assert c

@raises(AttributeError)
def test_connection_from_socket_fail():
	"""Creation of connection object with invalid argument raises Exception"""
	import socket
	connection(sock=12345)
