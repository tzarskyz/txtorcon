.. txtorcon documentation master file, created by
   sphinx-quickstart on Thu Jan 26 13:04:28 2012.

txtorcon
========

txtorcon is a `Twisted <https://twistedmatrix.com/>`_-based `Python
<http://python.org/>`_ asynchronous controller library for `Tor
<https://www.torproject.org/>`_, following `control-spec
<https://gitweb.torproject.org/torspec.git/blob/HEAD:/control-spec.txt>`_.
This would be of interest to anyone wishing to write event-based
software in Python that talks to a Tor program.

The main code is under 2000 lines according to ohcount, or 4500 lines
including tests. Some features and motivating examples:

 - :class:`txtorcon.TorControlProtocol` implements the control-spec protocol (only)
    - see :ref:`monitor.py` which listens for events (SETEVENT ones)

 - :class:`txtorcon.TorState` tracks state for you: all Routers, Streams and Circuits, with listeners
    - see :ref:`stream_circuit_logger.py` which logs all stream and circuit activity

 - :class:`txtorcon.TorConfig` tracks and allows updating of config with attribute-style acccess (including hidden services):
    - :samp:`print config.ORPort`
    - :samp:`config.HiddenServices.append(HiddenService(config, '/hidden/service/dir', ['80 127.0.0.1:1234']))`
    - :samp:`config.SocksPort = 9052`
    - see :ref:`dump_config.py`
    - see also :ref:`launch_tor_with_hiddenservice.py`

 - helpers to launch new slave Tor instances
    - uses TAKEOWNERSHIP and __OwningControllerProcess (killing connection causes Tor to exit)
    - see :ref:`launch_tor.py`
    - see :ref:`launch_tor_with_hiddenservice.py`

 - `txtorcon.TCPHiddenServiceEndpoint` to simplify hidden service listening into Twisteds endpoint paradigm.
    - see :ref:`launch_tor_endpoint.py`

The canonical URI is https://timaq4ygg2iegci7.onion
Code available at https://github.com/meejah/txtorcon

- meejah@meejah.ca (public key: `meejah.asc <meejah.asc>`_)
- ``torsocks git clone git://timaq4ygg2iegci7.onion/txtorcon.git``
- **``pip install txtorcon``**
- ``git clone git://github.com/meejah/txtorcon.git``

This documentation was generated |today|.

Known Users:
------------

 - `APAF <https://github.com/globaleaks/APAF>`_ anonymous Python application framework
 - `OONI <https://ooni.torproject.org/>`_ the Open Observatory of Network Interference

Get the Code:
-------------

.. toctree::
   :maxdepth: 2

   releases

Documentation
-------------

.. toctree::
   :maxdepth: 2

   introduction
   README
   examples

API Docs:
---------

.. toctree::
   :maxdepth: 3

   txtorcon

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

