from j1939.pgn import PGN
from j1939.constants import *
import logging
logger = logging.getLogger(__name__)


class ArbitrationID(object):

    def __init__(self, priority=7, pgn=None, source_address=0, destination_address=None):
        """
        :param int priority:
            Between 0 and 7, where 0 is highest priority.

        :param :class:`can.protocols.j1939.PGN`/int pgn:
            The parameter group number.

        :param int source_address:
            Between 0 and 255.

        :param int destinaion_address:
            Between 0 and 255. Will trrow a ValueError if PGN does not allow a dest

        """
        self.priority = priority
        if pgn == None:
            pgn = PGN()

        if pgn and (not isinstance(pgn, PGN)):
            ValueError("pgn must have PGN type")
        self.pgn = pgn

        self.destination_address_value = None
        if pgn:
            if self.pgn.is_destination_specific:
                if destination_address is None:
                    self.destination_address_value = DESTINATION_ADDRESS_GLOBAL
                else:
                    if destination_address >= 0 and destination_address <= 255:
                        self.destination_address_value = destination_address
                        if  self.destination_address_value != pgn.pdu_specific:
                                logger.info("self.destination_address_value = %x, pgn.pdu_specific = %x" %
                                        (self.destination_address_value, pgn.pdu_specific))

                        assert( self.destination_address_value == pgn.pdu_specific)
                    else:
                        raise ValueError("desttiantion address must be in range (0-255)")

        self.source_address = source_address

    @property
    def can_id(self):
        logger.info("can_id property: ")

        if self.pgn.is_destination_specific:
            logger.info("can_id: self.pgn.is_destination_specific, dest=%x, pgn_value=%x, pdu_format=0x%x, pdu_specific=0x%x, pri=%x" %
                    (self.destination_address_value,
                    self.pgn.value,
                    self.pgn.pdu_format,
                    self.pgn.pdu_specific,
                    self.priority))

            retval = (self.source_address +
                     (self.pgn.value << 8) +
                     (self.priority << 26))
            logger.info("can_id: retval=0x%08x" % (retval))
            return retval
        else:
            logger.info("can_id: NOT! self.pgn.is_destination_specific")
            return (self.source_address + (self.pgn.value << 8) + (self.priority << 26))

    @can_id.setter
    def can_id(self, canid):
        """
        Int between 0 and (2**29) - 1
        """
        logger.info("can_id setter: canid=0x%08x" % (canid))
        self.priority = (canid & 0x1C000000) >> 26
        self.pgn = PGN().from_can_id(canid)
        self.source_address = canid & 0x000000FF
        if self.pgn.is_destination_specific:
            self.destination_address_value = (canid & 0x0000FF00) >> 8


        logger.info("can_id: canid=0x%08x, priority=%x, pdu_format=%x, pdu_specific=%x, src=%x" %
                (canid,
                self.priority,
                self.pgn.pdu_format,
                self.pgn.pdu_specific,
                self.source_address))
    @property
    def destination_address(self):
        if self.pgn.is_destination_specific:
            return self.destination_address_value
        else:
            return None

    @destination_address.setter
    def destination_address(self, addr):
        if not self.pgn.is_destination_specific:
            raise ValueError("PGN is not dest specific: {:04x}".format(self.pgn))
        else:
            self.destination_address_value = addr


    @property
    def pgn(self):
        return self._pgn

    @pgn.setter
    def pgn(self, other):
        if other is None:
            self._pgn = PGN()
        elif not isinstance(other, PGN):
            self._pgn = PGN.from_value(other)
        else:
            self._pgn = other

    def __str__(self):
        logger.info("arbitrationid.__str__: pri:%s, pgn:%s, dest:%s, src:%s" %
                (self.priority, self.pgn, self.destination_address_value, self.source_address))
        if self.pgn.is_destination_specific:
            retval = "PRI=%d PGN=%6s DST=0x%.2x SRC=0x%.2x" % (
                self.priority, self.pgn, self.destination_address_value, self.source_address)
        else:
            retval = "PRI=%d PGN=%6s          SRC=0x%.2x" % (self.priority, self.pgn, self.source_address)
        return retval
