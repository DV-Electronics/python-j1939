import logging

#log = logging.getLogger('py1939.node')
#log.debug('Loading J1939 node')

from can import Listener, CanError
from j1939.arbitrationid import ArbitrationID
from j1939.constants import *
from j1939.pdu import PDU
from j1939.pgn import PGN
from j1939.nodename import NodeName

logger = logging.getLogger(__name__)
logger.debug("loading ", __name__)



class J1939Error(CanError):
    pass


class DuplicateTransmissionError(J1939Error):
    pass


class InaccessibleDestinationError(J1939Error):
    pass


class Node(Listener):

    """
    A j1939.Node will claim an address when it sees a j1939 address claim
    and after address claim send any messages with its source address.

    :param :class:`can.Bus` bus:
    :param :class:`can.protocols.j1939.NodeName` name:
    :param list(int) address_list:
        A list of potential addresses that this Node will use when claiming
        an address.
    :param pdu_type:
        The pdu class to use when returning messages.
    """

    def __init__(self, bus, name, address_list, pdu_type=PDU):
        logger.debug("Node::__init__")
        self.bus = bus
        self.node_name = name
        self.address_list = address_list
        self._pdu_type = pdu_type
        self._current_address_index = 0
        self.known_node_addresses = {self.node_name.value: ADDRESS_UNCLAIMED}

    @property
    def address(self):
        return self.known_node_addresses[self.node_name.value]

    def start_address_claim(self):
        logger.debug("start_address_claim:")
        if self._current_address_index >= len(self.address_list):
            self.claim_address(DESTINATION_ADDRESS_NULL)
        else:
            self.claim_address(self.address_list[self._current_address_index])

    def claim_address(self, address):
        logger.debug("claim_address:")
        claimed_address_pdu = self._pdu_type()
        claimed_address_pdu.arbitration_id.pgn.value = PGN_AC_ADDRESS_CLAIMED
        claimed_address_pdu.arbitration_id.priority = 6
        claimed_address_pdu.arbitration_id.source_address = address
        claimed_address_pdu.arbitration_id.destination_address_value = DESTINATION_ADDRESS_GLOBAL

        claimed_address_pdu.data = self.node_name.bytes
        self.known_node_addresses[self.node_name.value] = address
        logger.info('MIL:')
        logger.info('claimed_address_pdu: %s' % claimed_address_pdu)
        self.bus.send(claimed_address_pdu)

    def on_message_received(self, inboundMessage):
        arbitration_id = ArbitrationID()
        arbitration_id.can_id = inboundMessage.arbitration_id
        incomingPDU = PDU(arbitration_id=arbitration_id, data=inboundMessage.data)
        incomingPGN = PGN.from_can_id(inboundMessage.arbitration_id)
        logger.debug('node got message from SA %X, PDU format %X, PDU specific %X'%(incomingPDU.source,incomingPGN.pdu_format,incomingPGN.pdu_specific))

        if incomingPGN.pdu_format == PGN_AC_ADDRESS_CLAIMED_PF:
            logger.debug('got PGN_AC_ADDRESS_CLAIMED pdu')
            # todo 
            #   - wait 250ms after address claim to allow other nodes to dispute address (if address not in 0..127, 248..253)
            
            if (incomingPDU.source == DESTINATION_ADDRESS_NULL) and (incomingPDU.destination == DESTINATION_ADDRESS_GLOBAL):
                logger.debug('handle Request for Address Claim query (SA 0xFE, DA 0xFF)')
                self.start_address_claim()
                return

            if incomingPDU.source != self.address:
                node_name = NodeName()
                node_name.bytes = incomingPDU.data
                self.known_node_addresses[node_name.value] = incomingPDU.source
            else:
                logger.debug('competing node trying to claim our CA')
                competing_node_name = NodeName()
                competing_node_name.bytes = incomingPDU.data
                if self.node_name.value > competing_node_name.value:
                    logger.debug('another node claimed our CA')
                    self.known_node_addresses[competing_node_name.value] = incomingPDU.source

                    self._current_address_index += 1

                    if self._current_address_index >= len(self.address_list):
                        logger.debug("we don't have any more alternative CAs")
                    else:
                        logger.debug('try to claim our next CA')

                    self.start_address_claim()
                else:
                    logger.debug("disputing competing node's address claim")
                    self.claim_address(self.address)

        elif incomingPDU.pgn == PGN_AC_COMMANDED_ADDRESS:
            logger.debug('got PGN_AC_COMMANDED_ADDRESS pdu')
            node_name = NodeName()
            node_name.bytes = incomingPDU.data[:8]
            new_address = incomingPDU.data[8]
            if node_name.value == self.node_name.value:
                # if we are the commanded node change our address
                self.claim_address(new_address)

        elif incomingPGN.pdu_format == PGN_REQUEST_FOR_PGN_PF:
            logger.debug('got PGN_REQUEST_FOR_PGN pdu')
            pgn = int("%.2X%.2X%.2X" % (incomingPDU.data[2], incomingPDU.data[1], incomingPDU.data[0]), 16)
            if incomingPDU.destination in (self.address, DESTINATION_ADDRESS_GLOBAL):
                if pgn == PGN_AC_ADDRESS_CLAIMED:
                    self.claim_address(self.known_node_addresses[self.node_name.value])
        else:
            logger.debug('node got unknown PGN: ' + str(incomingPDU.pgn))


    def send_parameter_group(self, pgn, data, destination_device_name=None):
        """
        :param int pgn:
            should be between [0, (2 ** 18) - 1]
        :param list data:
            should have less than 1785 elements
            Each element should be a int between 0 and 255
        :param destination_device_name:
            Should be None, or an int between 0 and (2 ** 64) - 1
        """
        logger.debug('send_parameter_group:')
        # if we are *allowed* to send data
        if self.known_node_addresses[self.node_name.value] not in (ADDRESS_UNCLAIMED, DESTINATION_ADDRESS_NULL):
            logger.debug('send_parameter_group: claimed address')
            pdu = self._pdu_type()
            pdu.arbitration_id.pgn.value = pgn
            pdu.arbitration_id.source_address = self.known_node_addresses[self.node_name.value]
            if pdu.arbitration_id.pgn.is_destination_specific:
                if destination_device_name is not None:
                    pdu.arbitration_id.pgn.pdu_specific = self.known_node_addresses[destination_device_name]
                    if pdu.arbitration_id.pgn.pdu_specific == DESTINATION_ADDRESS_NULL:
                        raise InaccessibleDestinationError
                else:
                    pdu.arbitration_id.pgn.pdu_specific = DESTINATION_ADDRESS_GLOBAL
            pdu.data = data
            self.bus.write(pdu)
