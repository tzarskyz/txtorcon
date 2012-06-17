import functools
from twisted.internet import defer

from txtorcon.interface import ITorControlProtocol

class MagicContainer(object):
    """
    This merely contains 1 or more methods or further MagicContainer
    instances; see _do_setup in TorInfo.

    Once _setup_complete() is called, this behaves differently so that
    one can get nicer access to GETINFO things from TorInfo --
    specifically dir() and so forth pretend that there are only
    methods/attributes that pertain to actual Tor GETINFO keys.

    See TorInfo.
    """
    
    def __init__(self, n):
        self.name = n
        self.attrs = {}
        self._setup = False

    def _setup_complete(self):
        self._setup = True

    def _add_attribute(self, n, v):
        self.attrs[n] = v

    def __getattribute__(self, name):
        sup = super(MagicContainer, self)
        if sup.__getattribute__('_setup') == False:
            return sup.__getattribute__(name)

        attrs = sup.__getattribute__('attrs')
        if name == '__members__':
            return attrs.keys()

        else:
            try:
                return attrs[name]
            except KeyError:
                if name in ['dump']:
                    return object.__getattribute__(self, name)
                raise AttributeError(name)

    def dump(self, prefix):
        prefix = prefix + '.' + object.__getattribute__(self, 'name')
        for x in object.__getattribute__(self, 'attrs').values():
            x.dump(prefix)

class ConfigMethod(object):
    def __init__(self, info_key, protocol, takes_arg=False):
        self.info_key = info_key
        self.proto = protocol
        self.takes_arg = takes_arg

    def dump(self, prefix):
        n = self.info_key.replace('/', '.')
        n = n.replace('-','_')
        arg = ''
        if self.takes_arg:
            arg = 'arg'
        #print '%s(%s)' % (n, arg)
            
    def __call__(self, *args):
        if self.takes_arg:
            if len(args) != 1:
                raise TypeError('"%s" takes exactly one argument' % self.info_key)
            req = '%s/%s' % (self.info_key, str(args[0]))
            
        else:
            if len(args) != 0:
                raise TypeError('"%s" takes no arguments' % self.info_key)
            
            req = self.info_key

        def strip_dict(k, d):
            return d[k]
        
        return self.proto.get_info(req).addCallback(functools.partial(strip_dict, req))

class TorInfo(object):
    """
    Implements some attribute magic over top of TorControlProtocol so
    that all the available GETINFO values are available in a little
    easier fashion. Dashes are replaced by underscores (since dashes
    aren't valid in method/attribute names for Python). Some of the
    magic methods will take a single string argument if the
    corresponding Tor GETINFO would take one (in 'GETINFO info/names'
    it will end with '/*', and the same in torspec). In either case,
    the method returns a Deferred which will callback with the
    requested value, always a string.

    For example:

        cont = TorControlProtocol()
        #...
        def cb(arg):
            print arg
        info = TorInfo(cont)
        info.traffic.written().addCallback(cb)
        info.ip_to_country('8.8.8.8').addCallback(cb)

    For interactive use -- or even checking things progammatically -- TorInfo
    pretends it only has attributes that coorespond to valid GETINFO calls.
    So for example, dir(info) will only return all the currently valid top-level
    things. In the above example this might be ['traffic', 'ip_to_country'] (of
    course in practice this is a much longer list). And "dir(info.traffic)" might
    return ['read', 'written']

    For something like this for config (GETCONF, SETCONF) see
    TorConfig which is quite a lot more complicated (internally) since you can change
    config.
    """

    def __init__(self, control, errback=None):
        self._setup = False
        self.attrs = {}
        '''After _setup is True, these are all we show as attributes.'''
        
        self.protocol = ITorControlProtocol(control)
        if errback is None:
            self.errback = self._handle_error
        else:
            self.errback = errback

        self.post_bootstrap = defer.Deferred()
        if self.protocol.post_bootstrap:
            self.protocol.post_bootstrap.addCallback(self.bootstrap)

        else:
            self.bootstrap()

    def _add_attribute(self, n, v):
        self.attrs[n] = v

    def __getattribute__(self, name):
        sup = super(TorInfo, self)
        if sup.__getattribute__('_setup') == False:
            return sup.__getattribute__(name)

        attrs = sup.__getattribute__('attrs')
        if name == '__members__':
            return attrs.keys()

        else:
            try:
                return attrs[name]
            except KeyError:
                if name in ['dump']:
                    return object.__getattribute__(self, name)
                raise AttributeError(name)
            
    def _handle_error(self, f):
        '''FIXME: do we really need this?'''
        print "ERROR",f
        return f

    def bootstrap(self, *args):
        d = self.protocol.get_info_raw("info/names").addCallback(self._do_setup).addErrback(self.errback).addCallback(self.do_post_bootstrap).addCallback(self._setup_complete)
        return d


    def do_post_bootstrap(self, *args):
        self.post_bootstrap.callback(self)
        self.post_bootstrap = None

    def dump(self):
        for x in object.__getattribute__(self, 'attrs').values():
            x.dump('')

    def _do_setup(self, data):
        added_magic = []
        for line in data.split('\n'):
            if line == "info/names=" or line == "OK" or line.strip() == '':
                continue

            #print "LINE:",line
            (name, documentation) = line.split(' ', 1)
            ## FIXME think about this -- this is the only case where
            ## there's something that's a directory
            ## (i.e. MagicContainer) AND needs to be a ConfigMethod as
            ## well...but doesn't really see very useful. somewhat
            ## simpler to not support this case for now...
            if name == 'config/*':
                continue
            
            if name.endswith('/*'):
                ## this takes an arg, so make a method
                bits = name[:-2].split('/')
                takes_arg = True
                
            else:
                bits = name.split('/')
                takes_arg = False

            mine = self
            for bit in bits[:-1]:
                bit = bit.replace('-', '_')
                if mine.attrs.has_key(bit):
                    mine = mine.attrs[bit]
                    if not isinstance(mine, MagicContainer):
                        raise RuntimeError("Already had something: %s for %s" % (bit, name))
                    
                else:
                    c = MagicContainer(bit)
                    added_magic.append(c)
                    mine._add_attribute(bit, c)
                    mine = c
            n = bits[-1].replace('-', '_')
            if mine.attrs.has_key(n):
                raise RuntimeError("Already had something: %s for %s" % (n, name))
            mine._add_attribute(n, ConfigMethod('/'.join(bits), self.protocol, takes_arg))

        for c in added_magic:
            c._setup_complete()
        return None

    def _setup_complete(self, *args):
        self._setup = True
