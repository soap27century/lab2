import playground
from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
from .protocol import PoopClient, PoopServer

PoopClientFactory = StackingProtocolFactory.CreateFactoryType(PoopClient)
PoopServerFactory = StackingProtocolFactory.CreateFactoryType(PoopServer)

connector = playground.Connector(
    protocolStack=(PoopClientFactory(), PoopServerFactory())
)

playground.setConnector('poop', connector)
