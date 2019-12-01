import playground,sys,os
from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
# sys.path.insert(1,'../crap/')
# from .protocol import CrapClient, CrapServer
from .protocol import CrapClient, CrapServer
sys.path.insert(1,'../crap/')
# print("director",os.getcwd())
from ..poop.protocol import PoopClient, PoopServer

CrapClientFactory = StackingProtocolFactory.CreateFactoryType(PoopClient,CrapClient)
CrapServerFactory = StackingProtocolFactory.CreateFactoryType(PoopServer,CrapServer)


# CrapClientFactory = StackingProtocolFactory.CreateFactoryType(PoopClient)
# CrapServerFactory = StackingProtocolFactory.CreateFactoryType(PoopServer)
# CrapClientFactory = StackingProtocolFactory.CreateFactoryType(CrapClient)
# CrapServerFactory = StackingProtocolFactory.CreateFactoryType(CrapServer)

CrapConnector = playground.Connector(protocolStack=(
    CrapClientFactory(),
    CrapServerFactory()))

# connector = playground.Connector(
#     protocolStack=(CrapClientFactory(), CrapServerFactory())
# )

playground.setConnector('crap', CrapConnector)
