import playground,sys,os
from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
from .protocol import CrapClient, CrapServer
sys.path.insert(1,'../crap/')
from ..poop.protocol import PoopClient, PoopServer

CrapClientFactory = StackingProtocolFactory.CreateFactoryType(PoopClient,CrapClient)
CrapServerFactory = StackingProtocolFactory.CreateFactoryType(PoopServer,CrapServer)

CrapConnector = playground.Connector(protocolStack=(
    CrapClientFactory(),
    CrapServerFactory()))

playground.setConnector('crap', CrapConnector)
