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

import connection

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
    BAD_EXTENSION:              '420 Bad extension',
    NOT_AVAILABLE:              '480 Temporarily not available',
    NO_TRANSACTION:             '481 Call leg/transaction does not exist',
    LOOP:                       '482 Loop detected',
    TOO_MANY_HOPS:              '483 Too many hops',
    ADDRESS_INCOMPLETE:         '484 Address incomplete',
    AMBIGUOUS:                  '485 Ambiguous',
    BUSY_HERE:                  '486 Busy here',
    CANCELLED:                  '487 Request cancelled',
    NOT_ACCEPTABLE_HERE:        '488 Not acceptable here',

    # 5xx
    INTERNAL_ERROR:             '500 Internal server error',
    NOT_IMPLEMENTED:            '501 Not implemented',
    BAD_GATEWAY:                '502 Bad gateway',
    UNAVAILABLE:                '503 Service unavailable',
    GATEWAY_TIMEOUT:            '504 Gateway time-out',
    SIP_VERSION_NOT_SUPPORTED:  '505 SIP version not supported',

    # 6xx
    BUSY_EVERYWHERE:            '600 Busy everywhere',
    DECLINE:                    '603 Decline',
    DOES_NOT_EXIST:             '604 Does not exist anywhere',
    NOT_ACCEPTABLE_6xx:         '606 Not acceptable'
}

class sip(connection):
    NO_SESSION, INVITED, IN_SESSION, CANCELLED, BYED = range(5)

    def __init__(self, proto='tcp'):
        connection.__init__(proto)
        self.__state = self.NO_SESSION
        self.__lastResponse = 0

    def handle_read(self):
        """Callback for handling incoming SIP traffic"""
        pass

    def handle_write(self):
        """Callback for handling outgoing SIP traffic"""
        pass

    ###########################
    # SIP message type handlers
    ###########################
    def sip_INVITE(self, header, body):
        print("SIP: Received INVITE")

    def sip_ACK(self):
        print("SIP: Received ACK")

    def sip_OPTIONS(self, header, body):
        print("SIP: Received OPTIONS")

    def sip_BYE(self, header, body):
        print("SIP: Received BYE")

    def sip_CANCEL(self, header, body):
        print("SIP: Received CANCEL")

    def sip_REGISTER(self, header, body):
        print("SIP: Received REGISTER")
