
from twisted.python import log, failure
from twisted.internet import defer, process, error, protocol
from twisted.internet.interfaces import IProtocolFactory
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.protocols.basic import LineOnlyReceiver
from zope.interface import implements, Interface

## outside this module, you can do "from txtorcon import Stream" etc.
from txtorcon.stream import Stream, IStreamListener, IStreamAttacher
from txtorcon.circuit import Circuit, ICircuitListener, ICircuitContainer
from txtorcon.router import Router, IRouterContainer
from txtorcon.addrmap import AddrMap
from txtorcon.torcontrolprotocol import ITorControlProtocol, parse_keywords, DEFAULT_VALUE, TorProtocolFactory
from txtorcon.util import delete_file_or_tree

from spaghetti import FSM, State, Transition

import os
import sys
import string
import itertools
import types
import functools
import tempfile
from StringIO import StringIO
import shlex

DEBUG = False

def find_keywords(args):
    """FIXME: dup of the one in circuit, stream; move somewhere shared"""
    kw = {}
    for x in args:
        if '=' in x:
            (k,v) = x.split('=',1)
            kw[k] = v
    return kw

class TorProcessProtocol(protocol.ProcessProtocol):

    def __init__(self, connection_creator, progress_updates = None):
        """
        This will read the output from a tor process and attempt a
        connection to its control por when it sees any 'Bootstrapped'
        message on stdout. You probably don't need to use this
        directly; instead, see the launch_tor method.
        
        connection_creator is a callable that should return a Deferred
        that callbacks with a TorControlProtocol; see launch_tor for
        the default one which is a functools.partial that will call
        .connect(TorProtocolFactory()) on an appropriate
        TCP4ClientEndpoint
        """

        self.connection_creator = connection_creator
        self.progress_updates = progress_updates
        
        self.connected_cb = defer.Deferred()
        self.attempted_connect = False
        self.to_delete = []
        self.stderr = []
        self.stdout = []

    def outReceived(self, data):
        """
        ProcessProtocol API
        """

        self.stdout.append(data)
        
        ## minor hack: we can't try this in connectionMade because
        ## that's when the process first starts up so Tor hasn't
        ## opened any ports properly yet. So, we presume that after
        ## its first output we're good-to-go. If this fails, we'll
        ## reset and try again at the next output (see this class'
        ## tor_connection_failed)

        if DEBUG: print data
        if not self.attempted_connect and 'Bootstrap' in data:
            self.attempted_connect = True
            ## FIXME need arbitrary, random port
            ## FIXME use a factory method (or functool.partial) to do this so it's more-easily testable
            d = self.connection_creator()
            d.addCallback(self.tor_connected)
            d.addErrback(self.tor_connection_failed)

    def errReceived(self, data):
        """
        ProcessProtocol API
        """

        self.stderr.append(data)
        self.transport.loseConnection()
        raise RuntimeError("Received stderr output from slave Tor process: " + data)

    def cleanup(self):
        """
        Clean up my temporary files.
        """
        
        [delete_file_or_tree(f) for f in self.to_delete]
        self.to_delete = []

    def processEnded(self, status):
        """
        ProcessProtocol API
        """

        self.cleanup()
        
        if isinstance(status.value, error.ProcessDone):
            return
        
        raise RuntimeError('\n'.join(self.stdout) + "\n\nTor exited with error-code %d" % status.value.exitCode)

    def progress(self, percent, tag, summary):
        """
        Can be overridden or monkey-patched if you want to get
        progress updates yourself.
        """

        if self.progress_updates:
            self.progress_updates(percent, tag, summary)

    ## the below are all callbacks
        
    def tor_connection_failed(self, fail):
        ## FIXME more robust error-handling please, like a timeout so
        ## we don't just wait forever after 100% bootstrapped.
        self.attempted_connect = False
        return None

    def status_client(self, arg):
        args = shlex.split(arg)
        if args[1] != 'BOOTSTRAP':
            return
        
        kw = find_keywords(args)
        prog = int(kw['PROGRESS'])
        tag = kw['TAG']
        summary = kw['SUMMARY']
        self.progress(prog, tag, summary)
        
        if prog == 100:
            self.connected_cb.callback(self)

    def tor_connected(self, proto):
        if DEBUG: print "tor_connected",proto
        
        self.tor_protocol = proto
        self.tor_protocol.is_owned = self.transport.pid
        self.tor_protocol.post_bootstrap.addCallback(self.protocol_bootstrapped).addErrback(log.err)

    def protocol_bootstrapped(self, proto):
        if DEBUG: print "Protocol is bootstrapped"
        
        self.tor_protocol.add_event_listener('STATUS_CLIENT', self.status_client)

        ## FIXME: should really listen for these to complete as well
        ## as bootstrap etc. For now, we'll be optimistic.
        self.tor_protocol.queue_command('TAKEOWNERSHIP')
        self.tor_protocol.queue_command('RESETCONF __OwningControllerProcess')


def launch_tor(config, reactor,
               control_port=9052,
               data_directory=None,
               tor_binary='/usr/sbin/tor',
               progress_updates = None,
               connection_creator=None):
    """
    launches a new Tor process with the given config. Right after
    connecting, the config is validated against whatever metadata the
    Tor gave us and will kill the process and errback if there's a
    problem (i.e. if any of the given config values return False from
    their validate() method).

    If Tor prints anything on stderr, we kill off the process, close
    the TorControlProtocol and raise an exception.

    connection_creator is mostly available to ease testing, so you
    probably don't want to supply this. If supplied, it is a callable
    that should return a Deferred that delivers an IProtocol or
    ConnectError. See
    twisted.internet.interfaces.IStreamClientEndpoint.connect

    On success, the Deferred returned from this method is callback'd
    with a TorControlProtocol connected to the launched at
    bootstrapped Tor. The __OwningControllerProcess will be set and
    TAKEOWNERSHIP will have been called, so if you close the
    TorControlProtocol the Tor should exit also (see control-spec 3.23).
    FIXME? do we want to also return the IProcessProtocol?

    HACKS:

     1. It's hard to know when Tor has both (completely!) written its
        authentication cookie file AND is listening on the control
        port. It seems that waiting for the first 'bootstrap' message on
        stdout is sufficient. Seems fragile...and doesn't work 100% of
        the time, so FIXME look at Tor source.

    2. Writing the stub torrc seems sillier and sillier in some
       ways. I suppose all we're getting out of using SETCONF to set
       config instead of simply writing then all to a torrc first isn't
       much, because we have to write a torrc anyway AND tor will barf on
       startup anyway if the user-code which created the TorConfig did it
       wrong....so probably just write the torrc from the TorConfig given
       and try it.

    3. To implement 2. we have to override __OwningControllerProcess
       and CookieAuthentication at least so that our scheme works.
        
    """

    ## We have a slight problem with the approach: we need to pass a
    ## few minimum values to a torrc file so that Tor will start up
    ## enough that we may connect to it. Ideally, we'd be able to
    ## start a Tor up which doesn't really do anything except provide
    ## "AUTHENTICATE" and "GETINFO config/names" so we can do our
    ## config validation.

    ## the other option here is to simply write a torrc version of our
    ## config and get Tor to load that...which might be the best
    ## option anyway.

    if data_directory is None:
        data_directory = tempfile.mkdtemp(prefix='tortmp')
        
    (fd, torrc) = tempfile.mkstemp(prefix='tortmp')

    config.DataDirectory = data_directory
    config.ControlPort = control_port
    config.CookieAuthentication = 1
    config.SocksPort = 0
    config.__OwningControllerProcess = os.getpid()

    os.write(fd, config.create_torrc())
    os.close(fd)

    if DEBUG: print 'Running with config:\n',open(torrc, 'r').read()

    if connection_creator is None:
        connection_creator = functools.partial(TCP4ClientEndpoint(reactor, 'localhost', control_port).connect,
                                               TorProtocolFactory())
    process_protocol = TorProcessProtocol(connection_creator, progress_updates)

    # we do both because this process might be shut down way before
    # the reactor, but if the reactor bombs out without the subprocess
    # getting closed cleanly, we'll want the system shutdown events
    # triggered
    process_protocol.to_delete = [torrc, data_directory]
    reactor.addSystemEventTrigger('before', 'shutdown',
                                  functools.partial(delete_file_or_tree, torrc, data_directory))

    try:
        transport = reactor.spawnProcess(process_protocol, tor_binary,
                                         args=(tor_binary, '-f', torrc),
                                         env={'HOME': data_directory},
                                         path=data_directory)
        #FIXME? don't need rest of the args: uid, gid, usePTY, childFDs)
        transport.closeStdin()
        
    except RuntimeError, e:
        process_protocol.connected_cb.errback(e)

    return process_protocol.connected_cb

    

class TorConfigType(object):
    """
    Base class for all configuration types, which function as parsers
    and un-parsers.
    """
    
    def parse(self, s):
        """
        Given the string s, this should return a parsed representation
        of it.
        """
        return s
    
    def validate(self, s, instance, name):
        """
        If s is not a valid type for this object, an exception should
        be thrown. The validated object should be returned.
        """
        return s

class Boolean(TorConfigType):
    def parse(self, s):
        if int(s):
            return True
        return False

class Integer(TorConfigType):
    def parse(self, s):
        return int(s)

class Port(Integer):
    pass

class TimeInterval(Integer):
    pass

## not actually used?
class TimeMsecInterval(TorConfigType):
    pass

class DataSize(Integer):
    pass

class Float(TorConfigType):
    def parse(self, s):
        return float(s)

## unused also?
class Time(TorConfigType):
    pass

class CommaList(TorConfigType):
    def parse(self, s):
        return map(string.strip, s.split(','))

## FIXME: is this really a comma-list?
class RouterList(CommaList):
    pass

class String(TorConfigType):
    pass

class Filename(String):
    pass

class LineList(TorConfigType):
    def parse(self, s):
        if isinstance(s, types.ListType):
            return map(str, s)
        return map(string.strip, s.split('\n'))
    
    def validate(self, obj, instance, name):
        if not isinstance(obj, types.ListType):
            raise ValueError("Not valid for %s: %s" % (self.__class__, obj))
        return _ListWrapper(obj, functools.partial(instance.mark_unsaved, name))

config_types = [Boolean, LineList, Integer, Port, TimeInterval, TimeMsecInterval, DataSize, Float, Time, CommaList, String, LineList, Filename, RouterList]

def _wrapture(orig):
    """
    Returns a new method that wraps orig (the original method) with
    something that first calls on_modify from the
    instance. _ListWrapper uses this to wrap all methods that modify
    the list.
    """

#    @functools.wraps(orig)
    def foo(*args):
        obj = args[0]
        obj.on_modify()
        return orig(*args)
    return foo
        
class _ListWrapper(list):
    """
    Do some voodoo to wrap lists so that if you do anything to modify
    it, we mark the config as needing saving.

    FIXME: really worth it to preserve attribute-style access? seems
    to be okay from an exterior API perspective....
    """
    
    def __init__(self, thelist, on_modify_cb):
        list.__init__(self, thelist)
        self.on_modify = on_modify_cb

    __setitem__ = _wrapture(list.__setitem__)
    __setslice__ = _wrapture(list.__setslice__)
    append = _wrapture(list.append)
    extend = _wrapture(list.extend)
    insert = _wrapture(list.insert)
    remove = _wrapture(list.remove)
    pop = _wrapture(list.pop)

    def __repr__(self):
        return '_ListWrapper' + super(_ListWrapper, self).__repr__()

class HiddenService(object):
    """
    Because hidden service configuration is handled specially by Tor,
    we wrap the config in this class. This corresponds to the
    HiddenServiceDir, HiddenServicePort, HiddenServiceVersion and
    HiddenServiceAuthorizeClient lines from the config. If you want
    multiple HiddenServicePort lines, simply append more strings to
    the ports member.

    To create an additional hidden service, append a new instance of
    this class to the config (ignore the conf argument)::

    state.hiddenservices.append(HiddenService('/path/to/dir', ['80 127.0.0.1:1234']))
    """

    def __init__(self, config, thedir, ports, auth=None, ver=2):
        """
        config is the TorConfig to which this will belong (FIXME,
        can't we make this automatic somehow?), thedir corresponds to
        'HiddenServiceDir' and will ultimately contain a 'hostname'
        and 'private_key' file, ports is a list of lines corresponding
        to HiddenServicePort (like '80 127.0.0.1:1234' to advertise a
        hidden service at port 80 and redirect it internally on
        127.0.0.1:1234). auth corresponds to
        HiddenServiceAuthenticateClient line (FIXME: is that lines?) 
        and ver corresponds to HiddenServiceVersion and is always 2
        right now.
        """
        
        self.conf = config
        self.dir = thedir
        self.version = ver
        self.authorize_client = auth

        ## there are two magic attributes, "hostname" and "private_key"
        ## these are gotten from the dir if they're still None when
        ## accessed. Note that after a SETCONF has returned '250 OK'
        ## it seems from tor code that the keys will always have been
        ## created on disk by that point
        
        if not isinstance(ports, types.ListType):
            ports = [ports]
        self.ports = _ListWrapper(ports, functools.partial(self.conf.mark_unsaved, 'HiddenServices'))

    def __setattr__(self, name, value):
        """
        We override the default behavior so that we can mark
        HiddenServices as unsaved in our TorConfig object if anything
        is changed.
        """
        
        if name in ['dir', 'version', 'authorize_client', 'ports'] and self.conf:
            self.conf.mark_unsaved('HiddenServices')
        if isinstance(value, types.ListType):
            value = _ListWrapper(value, functools.partial(self.conf.mark_unsaved, 'HiddenServices'))
        self.__dict__[name] = value

    def __getattr__(self, name):
        if name in ['hostname', 'private_key']:
            self.__dict__[name] = open(os.path.join(self.dir, name)).read().strip()
        return self.__dict__[name]

    def config_attributes(self):
        """
        Helper method used by y TorConfig when generating a torrc file.
        """
    
        rtn = [('HiddenServiceDir', self.dir)]
        for x in self.ports:
            rtn.append(('HiddenServicePort', x))
        if self.version:
            rtn.append(('HiddenServiceVersion', self.version))
        if self.authorize_client:
            rtn.append(('HiddenServiceAuthorizeClient', self.authorize_client))
        return rtn

class TorConfig(object):
    """
    This class abstracts out Tor's config so that you don't have to
    realize things like: in order to successfully set multiple listen
    addresses, you must put them all (and the or-ports) in one SETCONF
    call. (FIXME: this isn't true yet)

    Also, it gives easy access to all the configuration options
    present. This is done with lazy caching: the first time you access
    a value, it asks the underlying Tor (via TorControlProtocol) and
    thereafter caches the value; if you change it, a SETCONF is
    issued.

    When setting configuration values, they are cached locally and DO
    NOT AFFECT the running Tor until you call save(). When getting
    config items they will reflect the current state of Tor
    (i.e. *not* what's been set since the last save())

    FIXME: It also listens on the CONF_CHANGED event to update the
    cached data in the event other controllers (etc) changed it. (Only
    exists in Git versions?)

    FIXME: when is CONF_CHANGED introduced in Tor? Can we do anything
    like it for prior versions?

    FIXME:
    
        - HiddenServiceOptions is special: GETCONF on it returns
        several (well, two) values. Besides adding the two keys 'by
        hand' do we need to do anything special? Can't we just depend
        on users doing 'conf.hiddenservicedir = foo' AND
        'conf.hiddenserviceport = bar' before a save() ?
        
        - once I determine a value is default, is there any way to
          actually get what this value is?
    """

    def __init__(self, control=None):
        if control is None:
            self.protocol = None
            self.__dict__['_slutty_'] = None
        else:
            self.protocol = ITorControlProtocol(control)

        self.config = {}
        '''Current configuration, by keys.'''
        
        self.unsaved = {}
        '''Configuration that has been changed since last save().'''
        
        self.parsers = {}
        '''Instances of the parser classes, subclasses of TorConfigType'''

        self.post_bootstrap = defer.Deferred()
        if self.protocol:
            if self.protocol.post_bootstrap:
                self.protocol.post_bootstrap.addCallback(self.bootstrap).addErrback(log.err)
            else:
                self.bootstrap()

        else:
            self.post_bootstrap.callback(self)

        self.__dict__['_setup_'] = None

    ## we override this so that we can provide direct attribute access
    ## to our config items, and move them into self.unsaved when
    ## they've been changed. hiddenservices have to be special
    ## unfortunately. the _setup_ thing is so that we can set up the
    ## attributes we need in the constructor without uusing __dict__
    ## all over the place.
        
    def __setattr__(self, name, value):
        if self.__dict__.has_key('_setup_'):
            name = self._find_real_name(name)
            if not self.__dict__.has_key('_slutty_') and name.lower() != 'hiddenservices':
                value = self.parsers[name].validate(value, self, name)
            if isinstance(value, types.ListType):
                value = _ListWrapper(value, functools.partial(self.mark_unsaved, name))

            name = self._find_real_name(name)
            self.unsaved[name] = value

        else:
            super(TorConfig, self).__setattr__(name, value)

    ## on purpose, we don't return self.saved if the key is in there
    ## because I want the config to represent the running Tor not
    ## "things which might get into the running Tor if save() were to
    ## be called"
            
    def __getattr__(self, name):
        return self.config[self._find_real_name(name)]

    def bootstrap(self, *args):
##        self.protocol.add_event_listener('CONF_CHANGED', self._conf_changed)
        return self.protocol.get_info_raw("config/names").addCallbacks(self._do_setup, log.err).addCallback(self.do_post_bootstrap).addErrback(log.err)

    def do_post_bootstrap(self, *args):
        self.post_bootstrap.callback(self)
        self.__dict__['post_bootstrap'] = None

    def needs_save(self):
        return len(self.unsaved) > 0

    def mark_unsaved(self, name):
        name = self._find_real_name(name)
        if self.config.has_key(name) and not self.unsaved.has_key(name):
            self.unsaved[name] = self.config[self._find_real_name(name)]

    def save(self):
        """
        Save any outstanding items. This returns a Deferred which will
        errback if Tor was unhappy with anything, or callback with
        this TorConfig object on success.
        """
        
        if not self.needs_save():
            d = defer.Deferred()
            d.callback(self)
            return d

        args = []
        for (key, value) in self.unsaved.items():
            if key == 'HiddenServices':
                self.config['HiddenServices'] = value
                for hs in value:
                    args.append('HiddenServiceDir')
                    args.append(hs.dir)
                    for p in hs.ports:
                        args.append('HiddenServicePort')
                        args.append(p)
                    if hs.version:
                        args.append('HiddenServiceVersion')
                        args.append(str(hs.version))
                    if hs.authorize_client:
                        args.append('HiddenServiceAuthorizeClient')
                        args.append(hs.authorize_client)
                continue
            
            if isinstance(value, types.ListType):
                for x in value:
                    args.append(key)
                    args.append(str(x))
                    
            else:
                args.append(key)
                args.append(value)

            # FIXME in future we should wait for CONF_CHANGED and
            # update then, right?
            self.config[self._find_real_name(key)] = value

        ## FIXME might want to re-think this, but currently there's no
        ## way to put things into a config and get them out again
        ## nicely...unless you just don't assign a protocol
        if self.protocol:
            d = self.protocol.set_conf(*args)
            d.addCallback(self._save_completed)
            d.addErrback(log.err)
            return d
        
        else:
            return defer.succeed(self)

    def _save_completed(self, foo):
        self.__dict__['unsaved'] = {}
        return self

    def _find_real_name(self, name):
        for x in self.__dict__['config'].keys():
            if x.lower() == name:
                return x
        return name

    @defer.inlineCallbacks
    def _do_setup(self, data):
        for line in data.split('\n'):
            if line == "config/names=" or line == "OK":
                continue

            (name, value) = line.split()
            if name == 'HiddenServiceOptions':
                ## set up the "special-case" hidden service stuff
                servicelines = yield self.protocol.get_conf_raw('HiddenServiceOptions')
                self._setup_hidden_services(servicelines)
                continue
            
            if value == 'Dependant':
                continue
            
            inst = None
            # FIXME: put parser classes in dict instead?
            for cls in config_types:
                if cls.__name__ == value:
                    inst = cls()
            if not inst:
                raise RuntimeError("Don't have a parser for: " + value)
            v = yield self.protocol.get_conf(name)
            v = v[name]
            
            self.parsers[name] = inst
            
            if value == 'LineList':
                ## FIXME should move to the parse() method, but it
                ## doesn't have access to conf object etc.
                self.config[self._find_real_name(name)] = _ListWrapper(self.parsers[name].parse(v), functools.partial(self.mark_unsaved, name))
                
            else:
                self.config[self._find_real_name(name)] = self.parsers[name].parse(v)

        # can't just return in @inlineCallbacks-decorated methods
        defer.returnValue(self)

    def _setup_hidden_services(self, servicelines):
        hs = []
        directory = None
        ports = []
        ver = None
        auth = None
        for line in servicelines.split('\n'):
            if not len(line.strip()):
                continue

            k, v = line.split('=')
            if k == 'HiddenServiceDir':
                if directory != None:
                    hs.append(HiddenService(self, directory, ports, auth, ver))
                directory = v
                ports = []
                ver = None
                auth = None

            elif k == 'HiddenServicePort':
                ports.append(v)

            elif k == 'HiddenServiceVersion':
                ver = int(v)

            elif k == 'HiddenServiceAuthorizeClient':
                auth = v

            else:
                raise RuntimeError("Can't parse HiddenServiceOptions: " + k)

        if directory is not None:
            hs.append(HiddenService(self, directory, ports, auth, ver))

        name = 'HiddenServices'
        self.config[name] = _ListWrapper(hs, functools.partial(self.mark_unsaved, name))

    def create_torrc(self):
        rtn = StringIO()

        for (k, v) in self.config.items() + self.unsaved.items():
            if type(v) is _ListWrapper:
                if k.lower() == 'hiddenservices':
                    for x in v:
                        for (kk, vv) in x.config_attributes():
                            rtn.write('%s %s\n' % (kk, vv))

                else:
                    for x in v:
                        rtn.write('%s %s\n' % (k, x))
                    
            else:
                rtn.write('%s %s\n' % (k, v))

        return rtn.getvalue()