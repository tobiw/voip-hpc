from sip import Sip
from nose.tools import assert_equals, raises, timed, with_setup

def test_sip_default():
	"""Creation of a default SIP connection object"""
	s = Sip()
	assert s
