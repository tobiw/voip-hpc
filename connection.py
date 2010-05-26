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

import socket, asyncore
import time

class connection(asyncore.dispatcher):
    """Connection class mockup (from connection.pyx in dionaea src)"""

    def __init__(self, proto=None):
        asyncore.dispatcher.__init__(self)

        # Use TCP by default, and UDP if stated
        type = socket.SOCK_STREAM
        if proto and proto.lower() == 'udp':
            type = socket.SOCK_DGRAM

        # Create non-blocking socket
        self.create_socket(socket.AF_INET, type)

    def handle_established(self):
        print('Session established')

    def handle_read(self):
        print(self.recv(1024))

    def handle_write(self):
        pass

    def handle_connect(self):
        self.handle_established()

    def handle_close(self):
        self.close()
        print('Session closed')

    def handle_accept(self):
        self.handle_established()

if __name__ == '__main__':
    c = connection()
    c.connect(('localhost', 1111))
    asyncore.loop()
