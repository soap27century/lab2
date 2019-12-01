import numpy as np
import binascii
import logging
import asyncio
import queue
import time
import math
import sys

from itertools import chain
from playground.network.packet import PacketType, FIELD_NOT_SET
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.packet.fieldtypes import UINT8, UINT32, BUFFER
from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport

logger = logging.getLogger("playground.__connector__." + __name__)


################################
# Packet Definitions:
################################

class PoopPacketType(PacketType):
    DEFINITION_IDENTIFIER = "poop"
    DEFINITION_VERSION = "1.0"


class DataPacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.datapacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("seq", UINT32({Optional: True})),
        ("hash", UINT32),
        ("data", BUFFER({Optional: True})),
        ("ACK", UINT32({Optional: True})),
    ]


class HandshakePacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.handshakepacket"
    DEFINITION_VERSION = "1.0"

    NOT_STARTED = 0
    SUCCESS = 1
    ERROR = 2

    FIELDS = [("SYN", UINT32({Optional: True})),
              ("ACK", UINT32({Optional: True})), ("status", UINT8),
              ("hash", UINT32)]


class ShutdownPacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.shutdownpacket"
    DEFINITION_VERSION = "1.0"

    SUCCESS = 0
    ERROR = 1

    FIELDS = [("FIN", UINT32),("hash", UINT32)]


################################
# Utility functions
################################

def set_hash(packet, *args, **kwargs):
    return packet(
        hash=hashdata(packet(hash=0, *args, **kwargs).__serialize__()),
        *args,
        **kwargs,
    )


def hashdata(b):
    return binascii.crc32(b) & 0xffffffff


def chunk(data, chunk_size=15000):
    return [
        data[i * chunk_size:(i + 1) * chunk_size]
        for i in range(math.ceil(len(data) / chunk_size))
    ]


def good_hash(packet):
    packet_class = packet.__class__
    fields = {field[0] for field in packet_class.FIELDS} - {'hash'}
    kwargs = {field: getattr(packet, field) for field in fields}
    new_packet = set_hash(packet_class, **kwargs)
    return new_packet.hash == packet.hash


async def ensure_write(transport, data, timeout, stopq, timeoutq, wait=2, min_writes=1, seq=None):
    start = time.time()
    writes = 0
    while stopq.empty():
        if writes >= 1:
            print("PACKET resent ", seq, writes, "/", min_writes)
        transport.write(data)
        writes += 1

        if writes >= min_writes and time.time() - start > timeout:
            timeoutq.put('timeout')
            break

        await asyncio.sleep(min({wait, timeout}))



################################
# Transport Definition
################################


class PoopTransport(StackingTransport):
    def __init__(self, seq, timeout=1, *args, **kwargs):
        self.timeout = timeout
        self.initial_seq = seq
        self.seq = seq
        self.stop_qs = {}
        self.timeout_qs = {}
        self.acks = set()

        self.closed = False
        self.called_close = False

        super().__init__(*args, **kwargs)

    async def ensure_write(self, transport, data, timeout, stopq, timeoutq, wait=.2, min_writes=1, seq=None):
        """
        Has clause to check number of resends of datapackets. Is only used to send datapackets
        """
        start = time.time()
        writes = 0
        while stopq.empty():
            if writes >= 1:
                print("PACKET resent ", seq, writes, "/", min_writes)
            transport.write(data)
            writes += 1

            if writes >= min_writes and time.time() - start > timeout:
                timeoutq.put('timeout')
                break

            await asyncio.sleep(min({wait, timeout}))

    def write(self, data):
        print("WRITE", self.closed or self.called_close)
        if self.closed or self.called_close:
            return
        #print("chunk length: ", len(chunk(data)))

        for dchunk in chunk(data):

            self.stop_qs[self.seq] = queue.Queue()
            self.timeout_qs[self.seq] = queue.Queue()
            datapacket = set_hash(DataPacket, data=dchunk, seq=self.seq)
            print("PACKET sent ", self.seq)
            asyncio.ensure_future(
                self.ensure_write(
                    self.lowerTransport(),
                    datapacket.__serialize__(),
                    self.timeout,
                    self.stop_qs[self.seq],
                    self.timeout_qs[self.seq],
                    seq=self.seq
                )
            )
            self.seq = (self.seq + 1) % 2**32

    def close(self):
        print("CALLED CLOSE at ", self.seq)
        # can't close twice
        if self.called_close or self.closed:
            return
        self.called_close = True
        asyncio.ensure_future(self.ensure_close())

    async def ensure_close(self):
       # print("closing?")
        # wait for all outstanding writes to get timedout or acked
        timeouts = {seq for seq, q in self.timeout_qs.items() if not q.empty()}
        while len(set(self.stop_qs.keys()) - self.acks - timeouts) > 0:
           # print("here?")
            timeouts = {seq for seq, q in self.timeout_qs.items() if not q.empty()}
            if self.closed:  # other closed while we're waiting
                return
            await asyncio.sleep(.1)
       # print("here2?")
        # this will return once an ACK is received or the write times out
        self.stop_qs[self.seq] = queue.Queue()
        self.timeout_qs[self.seq] = queue.Queue()

        seq = self.seq
       # print("here3",seq)
        packet = set_hash(ShutdownPacket, FIN=seq)
        # wait for shutdown packet to get ACKed or time out
        print('SHUTDOWN About to write ', self.seq)
        await ensure_write(
            self.lowerTransport(),
            packet.__serialize__(),
            self.timeout * 3,  # 3 sends, timeout is 3 times as long
            self.stop_qs[self.seq],
            self.timeout_qs[self.seq],
            min_writes=3,
            seq=self.seq
        )

        #print('sent')
        self.closed = True
        print(self.closed)
        self.lowerTransport().close()

    def other_closed(self):
        print("LOWER TRANSPORT CLOSED")
        # no need to wait for anything - other agent isn't listening anymore
        self.closed = True
        self.lowerTransport().close()

    def received(self, seq):
        # TODO: this should always be True, but sometimes seems not to be
        self.stop_qs[seq].put('stop')
        self.acks.add(seq)


################################
# Protocol Definition
################################


class PoopProtocol(StackingProtocol):
    def __init__(self, mode, timeout=3):
        print('NEW', mode, 'MADE')
        super().__init__()
        self.timeout = timeout
        self.mode = mode

        self.handshake_stop = queue.Queue()
        self.handshake_timeout = queue.Queue()

        self.handshake = Handshaker()
        self.buffer = PoopPacketType.Deserializer()

        self.last_received = None
        self.received_data = {}

    async def ensure_write(self, transport, data, timeout, stopq, timeoutq, wait=2, min_writes=1, seq=None):
        """
        Has a clause to prevent sending after handshake is complete. Is only used to ensure writes of handshakes.

        """
        start = time.time()
        writes = 0
        while stopq.empty():
            #if self.handshake.complete:
             #   print("handshake complete, break")
              #  break
            if writes >= 1:
                print("PACKET resent ", seq, writes, "/", min_writes)
            transport.write(data)
            writes += 1

            if writes >= min_writes and time.time() - start > timeout:
                timeoutq.put('timeout')
                break

            await asyncio.sleep(min({wait, timeout}))

    def connection_made(self, transport):
        self.transport = transport
        print("ppop connection_made")
        if self.mode == "client":
            to_send = self.handshake.initialize()
            asyncio.ensure_future(
                self.ensure_write(
                    self.transport,
                    to_send.__serialize__(),
                    self.timeout * 3,  # send 3 times, 3 times timeout
                    self.handshake_stop,
                    self.handshake_timeout,
                    min_writes=3,
                    seq="HANDSHAKE CLIENT"
                )
            )

    def connection_lost(self, exc):
        # assume this gets called with close
        self.higherProtocol().connection_lost(exc)

    def data_received(self, data):
        print("poop received something")
        self.buffer.update(data)

        for packet in self.buffer.nextPackets():
            print(self.mode, 'handshake complete:', self.handshake.complete, packet.__class__)

            if not good_hash(packet):
                print("BAD HASH")
                print(self.mode, "Packet contained bad hash")
                break

            if isinstance(packet, HandshakePacket):
                print(packet.status)
            #     print(self.mode, "received handshakepacket")
            #     self.process_handshake(packet)

            if not self.handshake.complete and isinstance(packet, HandshakePacket):
                print(self.mode, "received handshakepacket")
                self.process_handshake(packet)

            elif self.handshake.complete and  isinstance(packet, DataPacket):
                self.process_data_packet(packet)

            elif self.handshake.complete and isinstance(packet, ShutdownPacket):
                print(self.mode, "received shutdownpacket")
                self.process_shutdown_packet(packet)

    def process_handshake(self, packet):
        to_send = self.handshake.process(packet)
        if to_send is not None and to_send.status != HandshakePacket.ERROR:
            if self.last_received is None and packet.SYN != FIELD_NOT_SET:
                self.last_received = packet.SYN - 1
                print('STARTING SEQ:', packet.SYN)

        if to_send is not None:
            print("Sending to send")
            asyncio.ensure_future(
                self.ensure_write(
                    self.transport,
                    to_send.__serialize__(),
                    self.timeout * 3,  # send 3 times, 3 times timeout
                    self.handshake_stop,
                    self.handshake_timeout,
                    min_writes=1,
                    seq="HANDSHAKE SERVER"
                )
            )

        if self.handshake.complete:
            print("calling connection maade to higher guy")
            self.higherProtocol().connection_made(
                PoopTransport(
                    timeout=self.timeout,
                    seq=self.handshake.syn,
                    lowerTransport=self.transport,
                ))
            print("Called higher guy")

    def process_data_packet(self, packet):
        print(self.mode, 'got data packet')
        if packet.ACK != FIELD_NOT_SET:
            if self.higherProtocol().transport.closed or self.higherProtocol().transport.called_close:
                if packet.ACK == self.higherProtocol().transport.seq:
                    # THIS WAS THE SECTION WE NEEDED
                    print("CORRECT SEQ FINAL DATAPACKET")
                    self.higherProtocol().transport.other_closed()

            else:
                print(self.mode, 'treating as ack')
                self.higherProtocol().transport.received(packet.ACK)
                print("PACKET ack received ", packet.ACK)

        if packet.data != FIELD_NOT_SET:
            print('treating as data')
            self.received_data[packet.seq] = packet.data
            print(packet.data)
            print("PACKET sending ack ", packet.seq)
            ack_packet = set_hash(DataPacket, ACK=packet.seq)
            self.transport.write(ack_packet.__serialize__())
            self.pass_on_data()
            print("done?")

    def pass_on_data(self):
        # pass available data on in order
        print(self.mode, '-------------------PROCESSING DATA--------------------')
        # print(self.received_data.pop(self.received_data))
        # print(self.received_data)
        while (self.last_received + 1) % 2**32 in self.received_data:
            self.last_received = (self.last_received + 1) % 2**32
            next_data = self.received_data.pop(self.last_received)
            print("pass data above?")
            self.higherProtocol().data_received(next_data)
       # print('LAST RECEIVED', self.last_received)
       # print('NOT YET SENT', set(self.received_data.keys()))

    def process_shutdown_packet(self, packet):
        if packet.FIN == (self.last_received + 1) % 2**32:
            print(self.mode, 'Received shutdown packet')
            to_send = set_hash(DataPacket, ACK=packet.FIN)
            self.transport.write(to_send.__serialize__())
            self.higherProtocol().transport.other_closed()

################################
# Handshaker Definition
################################


class Handshaker(object):
    def __init__(self):
        self.syn = np.random.randint(2**32)
        self.sent_ack = False
        self.complete = False
        self.received_init = False

    def initialize(self):
        print("poop initialize")
        return set_hash(
            HandshakePacket,
            SYN=self.syn,
            status=HandshakePacket.NOT_STARTED
        )

    def process(self, packet):
        print("poop process")
        is_init = (packet.status == packet.NOT_STARTED
                   and packet.SYN != FIELD_NOT_SET)

        is_ack = (packet.status == HandshakePacket.SUCCESS
                  and packet.ACK == (self.syn + 1) % 2**32)

        if is_init and not self.received_init:
            print('Received initial packet - sending acknowledgment & syn', self.syn)
            self.received_init = True
            return self.send_ack2(packet)

        elif is_ack:
            print("received ack: ",packet.ACK)
            print("packet syn: ",packet.SYN)
            print('Received acknowledgment')
            self.complete = True
            if not self.sent_ack:
                print('Sending acknowledgment')
                return self.send_ack1(packet)
        else:
            print('There has been an error. Sending error.')
            return set_hash(HandshakePacket, status=HandshakePacket.ERROR)

    def send_ack1(self, packet):
        self.sent_ack = True
        return set_hash(
            HandshakePacket,
            ACK=(packet.SYN + 1) % 2**32,
            SYN=(self.syn+1) % 2**32,
            status=HandshakePacket.SUCCESS,
        )

    def send_ack2(self, packet):
        self.sent_ack = True
        return set_hash(
            HandshakePacket,
            ACK=(packet.SYN + 1) % 2**32,
            SYN=(self.syn) % 2**32,
            status=HandshakePacket.SUCCESS,
        )


PoopClient= lambda: PoopProtocol(mode="client")
PoopServer = lambda: PoopProtocol(mode="server")
# PoopClientFactory = StackingProtocolFactory.CreateFactoryType(
#     lambda: PoopProtocol(mode="client"))

# PoopServerFactory = StackingProtocolFactory.CreateFactoryType(
#     lambda: PoopProtocol(mode="server"))
