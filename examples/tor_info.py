#!/usr/bin/env python

##
## Simple usage example of TorInfo. This class does some magic so that
## once it's set up, all the attributes it has (or appears to) are
## GETINFO ones, in a heirarchy. So where GETINFO specifies
## "net/listeners/dns" TorInfo will have a "net" attribute that
## contains at least "listeners", etcetera. The leaves are all methods
## which return a Deferred. If the corresponding GETINFO takes an
## argument, so does the leaf.
##
## Go straight to "setup_complete" for the goods -- this is called
## after TorInfo and the underlying TorControlProtocol are set up.
##
## If you want to issue multiple GETINFO calls in one network
## transaction, you'll have to use TorControlProtocol's get_info
## instead.
##

import os
import sys
import stat
import types

from twisted.python import log
from twisted.internet import reactor, defer
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.endpoints import UNIXClientEndpoint
from zope.interface import implements

from txtorcon import TorProtocolFactory, TorInfo
from txtorcon.torinfo import MagicContainer, ConfigMethod

def dump(x):
    print str(x)
def error(x):
    print "ERROR",x

def recursive_dump(indent, obj):
    print "RD",obj
    if callable(obj):
        print "%s %s()" % (indent, obj.info_key)
        if obj.takes_arg:
            return obj('an arg!').addCallback(dump).addErrback(error)
        return obj().addCallback(dump).addErrback(error)
    
    print indent,obj
    indent = indent + '  '
    d = None
    for x in obj:
        d2 = recursive_dump(indent, x)
        if d:
            d2.chainDeferred(d)
        d = d2
    print 'returning',d,dir(d)
    return d

def setup_complete(info):
    print "Got info object",info
    print "top-level things:",dir(info)

    if False:
        ## some examples of getting specific GETINFO callbacks
        info.version().addCallback(dump)
        info.ip_to_country('1.2.3.4').addCallback(dump)
        info.status.bootstrap_phase().addCallback(dump)
        info.ns.name('moria1').addCallback(dump)
        #info.features.names().addCallback(dump).addCallback(lambda x: reactor.stop())

    ## this will dump everything
    recursive_dump('', info).addCallback(lambda x: reactor.stop()).addErrback(error)

    
def setup_failed(arg):
    print "SETUP FAILED",arg
    reactor.stop()

def bootstrap(c):
    info = TorInfo(c)
    info.post_bootstrap.addCallback(setup_complete).addErrback(setup_failed)

point = None
try:
    ## FIXME more Pythonic to not check, and accept more exceptions
    if os.stat('/var/run/tor/control').st_mode & (stat.S_IRGRP | stat.S_IRUSR | stat.S_IROTH):
        print "using control socket"
        point = UNIXClientEndpoint(reactor, "/var/run/tor/control")
except OSError:
    pass

if point is None:
    point = TCP4ClientEndpoint(reactor, "localhost", 9051)
    
d = point.connect(TorProtocolFactory())
# do not use addCallbacks() here, in case bootstrap has an error
d.addCallback(bootstrap).addErrback(setup_failed)
reactor.run()
