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
