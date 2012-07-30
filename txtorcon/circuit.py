import sys

from twisted.python import log
from interface import IRouterContainer

from txtorcon.util import find_keywords


class Circuit(object):
    """
    Used by :class:`txtorcon.TorState` to represent one of Tor's circuits.

    This is kept up-to-date by the :class`txtorcon.TorState` that owns it, and
    individual circuits can be listened to for updates (or listen to
    every one using :meth:`txtorcon.TorState.add_circuit_listener`)

    :ivar path:
        contains a list of :class:`txtorcon.Router` objects
        representing the path this Circuit takes. Mostly this will be
        3 or 4 routers long. Note that internally Tor uses single-hop
        paths for some things. See also the *purpose*
        instance-variable.

    :ivar streams:
        contains a list of Stream objects representing all streams
        currently attached to this circuit.

    :ivar state:
        contains a string from Tor describing the current state of the
        stream. From control-spec.txt section 4.1.2, these are:

            - NEW: New request to connect
            - NEWRESOLVE: New request to resolve an address
            - REMAP: Address re-mapped to another
            - SENTCONNECT: Sent a connect cell along a circuit
            - SENTRESOLVE: Sent a resolve cell along a circuit
            - SUCCEEDED: Received a reply; stream established
            - FAILED: Stream failed and not retriable
            - CLOSED: Stream closed
            - DETACHED: Detached from circuit; still retriable

    :ivar purpose:
        The reason this circuit was built. Values can currently be one
        of (but see control-spec.txt 4.1.1):

          - GENERAL
          - HS_CLIENT_INTRO
          - HS_CLIENT_REND
          - HS_SERVICE_INTRO
          - HS_SERVICE_REND
          - TESTING
          - CONTROLLER

        For most purposes, you'll want to look at GENERAL circuits only.

    :ivar id:
        The ID of this circuit, a number (or None if unset).
    """

    def __init__(self, routercontainer):
        """
        :param routercontainer: should implement
        :class:`txtorcon.interface.IRouterContainer`
        """
        self.listeners = []
        self.router_container = IRouterContainer(routercontainer)
        self.path = []
        self.streams = []
        self.purpose = None
        self.id = None
        self.state = 'UNKNOWN'

    def listen(self, listener):
        if listener not in self.listeners:
            self.listeners.append(listener)

    def unlisten(self, listener):
        self.listeners.remove(listener)

    def update(self, args):
        ##print "Circuit.update:",args
        if self.id is None:
            self.id = int(args[0])
            [x.circuit_new(self) for x in self.listeners]

        else:
            if int(args[0]) != self.id:
                raise RuntimeError("Update for wrong circuit.")
        self.state = args[1]

        kw = find_keywords(args)
        if 'PURPOSE' in kw:
            self.purpose = kw['PURPOSE']

        if self.state == 'LAUNCHED':
            self.path = []
            [x.circuit_launched(self) for x in self.listeners]
        else:
            if self.state != 'FAILED' and self.state != 'CLOSED' and len(args) > 2:
                self.update_path(args[2].split(','))

        if self.state == 'BUILT':
            [x.circuit_built(self) for x in self.listeners]

        elif self.state == 'CLOSED':
            if len(self.streams) > 0:
                log.err(RuntimeError("Circuit is %s but still has %d streams" %
                                     (self.state, len(self.streams))))
            [x.circuit_closed(self) for x in self.listeners]

        elif self.state == 'FAILED':
            if len(self.streams) > 0:
                log.err(RuntimeError("Circuit is %s but still has %d streams" %
                                     (self.state, len(self.streams))))
            reason = 'unknown'
            if 'REASON' in kw:
                reason = kw['REASON']
            [x.circuit_failed(self, reason) for x in self.listeners]

    def update_path(self, path):
        """
        Unfortunately, there are types of messages for EXTEND which
        have no path, but that are very hard to distinguish from a
        path update except by detecting that the router can't be
        found. FIXME should find a better solution. Can we integrate
        stems parser now, if it handles this
        """
        
        oldpath = self.path
        self.path = []
        for router in path:
            p = router[:41]
            try:
                router = self.router_container.router_from_id(p)
            except KeyError:
                log.err('Skipping path update because a router is missing from my router_container: %s' % str(path))
                return
            
            self.path.append(router)
            if len(self.path) > len(oldpath):
                [x.circuit_extend(self, router) for x in self.listeners]
                oldpath = self.path

    def __str__(self):
        return "<Circuit %d %s [%s] for %s>" % (self.id, self.state, ' '.join(map(lambda x: x.ip, self.path)), self.purpose)
