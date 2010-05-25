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

class connection:
    """Connection class mockup (from connection.pyx in dionaea src)"""

    def __init__(self, proto=None):
        # Use TCP by default, and UDP if stated
        type = socket.SOCK_STREAM
        if proto and proto.lower() == 'udp':
            type = socket.SOCK_DGRAM

        # Create non-blocking socket
        self.__socket = socket.socket(socket.AF_INET, type)
        self.__socket.setblocking(0)

    def bind(self, addr, port, iface=u''):
        if isinstance(addr, unicode):
            addr_utf8 = addr.encode(u'UTF-8')
        else:
            raise ValueError(u'addr requires text input, got %s' % type(addr))

        if isinstance(iface, unicode):
            iface_utf8 = iface.encode(u'UTF-8')
        else:
            raise ValueError(u'iface requires text input, got %s' % type(iface))

        self.__socket.bind((addr_utf8, port))

    def connect(self, addr, port, iface=u''):
        if isinstance(addr, unicode):
            addr_utf8 = addr.encode(u'UTF-8')
        else:
            raise ValueError(u'addr requires text input, got %s' % type(addr))

        if isinstance(iface, unicode):
            iface_utf8 = iface.encode(u'UTF-8')
        else:
            raise ValueError(u'iface requires text input, got %s' % type(iface))

        self.__socket.connect((addr_utf8, port))

    def listen(self, size=20):
        self.__socket.listen(1)
        conn, addr = self.__socket.accept()

    def send(self, data):
        if isinstance(data, unicode):
            data_bytes = data.encode(u'UTF-8')
        elif isinstance(data, bytes):
            data_bytes = data
        else:
            raise ValueError(u'requires text/bytes input, got %s' % type(data))

        self.__socket.send(data)

    def close(self):
        self.__socket.close()
