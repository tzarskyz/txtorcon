
from twisted.internet import defer

from txtorcon.interface import ITorControlProtocol

class MagicContainer(object):
    """
    This merely contains 1 or more methods or further MagicContainer
    instances; see do_setup in TorInfo. This could be object except
    we're not allowed to set arbitrary instances on object.
    """
    def __init__(self, n):
        self.name = n

    def dump(self, prefix):
        prefix = prefix + '.' + self.name
        for x in dir(self):
            try:
                getattr(self, x).dump(prefix)
            except:
                pass

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
        print '%s(%s)' % (n, arg)
            
    def __call__(self, *args):
        if self.takes_arg:
            if len(args) != 1:
                raise TypeError('"%s" takes exactly one argument' % self.info_key)
            req = '%s/%s' % (self.info_key, str(args[0]))
            
        else:
            if len(args) != 0:
                raise TypeError('"%s" takes no arguments' % self.info_key)
            
            req = self.info_key
        
        return self.proto.get_info(req)

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
    requested value.

    For example:

        cont = TorControlProtocol()
        #...
        def cb(arg):
            print arg
        info = TorInfo(cont)
        info.traffic.written().addCallback(cb)
        info.ip_to_country('8.8.8.8').addCallback(cb)

    For something like this for config (GETCONF, SETCONF) see
    TorConfig which quite a lot more complicated since you can change
    config.
    """

    def __init__(self, control):
        self.protocol = ITorControlProtocol(control)

        self.post_bootstrap = defer.Deferred()
        if self.protocol.post_bootstrap:
            self.protocol.post_bootstrap.addCallback(self.bootstrap)
        else:
            self.bootstrap()

    def bootstrap(self, *args):
        return self.protocol.get_info_raw("info/names").addCallback(self._do_setup).addCallback(self.do_post_bootstrap)

    def do_post_bootstrap(self, *args):
        self.post_bootstrap.callback(self)
        self.post_bootstrap = None

    def dump(self):
        print "DUMP:"
        for x in dir(self):
            try:
                getattr(self, x).dump('')
            except:
                pass

    def _do_setup(self, data):
        print "ODSETUP"
        for line in data.split('\n'):
            if line == "info/names=" or line == "OK":
                continue

            (name, documentation) = line.split(' ', 1)
            print name, documentation
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
                if hasattr(mine, bit):
                    mine = getattr(mine, bit)
                    
                else:
                    if hasattr(mine, bit):
                        mine = getattr(mine, bit)
                        if not isinstance(MagicContainer, mine):
                            raise RuntimeError("Already had something: %s for %s" % (bit, name))

                    else:
                        c = MagicContainer(bit)
                        print "adding",bit
                        setattr(mine, bit, c)
                        mine = c
            #print "LEAF:",bits[-1],takes_arg
            setattr(mine, bits[-1].replace('-', '_'), ConfigMethod('/'.join(bits), self.protocol, takes_arg))
