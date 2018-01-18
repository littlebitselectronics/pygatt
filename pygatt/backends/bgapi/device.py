import logging
import time
from threading import Thread

from pygatt import BLEDevice, exceptions
from . import constants
from .bgapi import BGAPIError
from .error_codes import ErrorCode, get_return_message
from .packets import BGAPICommandPacketBuilder as CommandBuilder
from .bglib import EventPacketType, ResponsePacketType

log = logging.getLogger(__name__)


def connection_required(func):
    """Raise an exception if the device is not connected before calling the
    actual function.
    """
    def wrapper(self, *args, **kwargs):
        if self._handle is None:
            raise exceptions.NotConnectedError()
        return func(self, *args, **kwargs)
    return wrapper


class BGAPIBLEDevice(BLEDevice):
    def __init__(self, address, handle, backend):
        super(BGAPIBLEDevice, self).__init__(address)
        self._handle = handle
        self._backend = backend
        self.disconnected_cb = None

    def _disconnected(self):
        """
        Callback from adapter: This device has just been disconnected.
        Ensure it's marked as such, and inform the application if requested
        """
        self._handle = None
        log.debug("Device %s disconnected", self._address)
        if self.disconnected_cb is not None and \
                hasattr(self.disconnected_cb, '__call__'):
            # We're likely being called from the receiver thread context.
            # This is not a safe context for any application code:
            # Any functions that block on a response would deadlock here.
            # So execute this callback from a new thread.
            Thread(target=self.disconnected_cb, args=(self,)).start()

    @connection_required
    def bond(self, permanent=False):
        """
        Create a bond and encrypted connection with the device.
        """

        # Set to bondable mode so bonds are store permanently
        if permanent:
            self._backend.set_bondable(True)
        log.debug("Bonding to %s", self._address)
        self._backend.send_command(
            CommandBuilder.sm_encrypt_start(
                self._handle, constants.bonding['create_bonding']))
        self._backend.expect(ResponsePacketType.sm_encrypt_start)

        packet_type, response = self._backend.expect_any(
            [EventPacketType.connection_status,
             EventPacketType.sm_bonding_fail])
        if packet_type == EventPacketType.sm_bonding_fail:
            raise BGAPIError("Bonding failed")
        log.debug("Bonded to %s", self._address)

    @connection_required
    def get_rssi(self):
        """
        Get the receiver signal strength indicator (RSSI) value from the device.

        Returns the RSSI as in integer in dBm.
        """
        # The BGAPI has some strange behavior where it will return 25 for
        # the RSSI value sometimes... Try a maximum of 3 times.
        for i in range(0, 3):
            self._backend.send_command(
                CommandBuilder.connection_get_rssi(self._handle))
            _, response = self._backend.expect(
                ResponsePacketType.connection_get_rssi)
            rssi = response['rssi']
            if rssi != 25:
                return rssi
            time.sleep(0.1)
        raise BGAPIError("get rssi failed")

    @connection_required
    def char_read(self, uuid, timeout=None, long=False):
        return self.char_read_handle(self.get_handle(uuid),
                timeout=timeout, long=long)

    @connection_required
    def char_read_handle(self, handle, timeout=None, long=False):
        log.debug("Reading characteristic at handle %d", handle)
        if long:
            self._backend.send_command(
                CommandBuilder.attclient_read_long(
                    self._handle, handle))
            self._backend.expect(ResponsePacketType.attclient_read_long)
        else:
            self._backend.send_command(
                CommandBuilder.attclient_read_by_handle(
                    self._handle, handle))
            self._backend.expect(ResponsePacketType.attclient_read_by_handle)

        success = False
        ret = bytearray([])
        while not success:
            matched_packet_type, response = self._backend.expect_any(
                [EventPacketType.attclient_attribute_value,
                 EventPacketType.attclient_procedure_completed],
                timeout=timeout)
            # If this is a long read, there may be multiple "attribute_value" packets
            # so we should append any values emitted by "attribute_value" to ret
            if matched_packet_type == EventPacketType.attclient_attribute_value and\
                        response['atthandle'] == handle:
                if not long:
                    return bytearray(response['value'])
                ret.extend(bytearray(response['value']))
            # Then once the whole procedure is complete we can return it
            elif matched_packet_type == EventPacketType.attclient_procedure_completed:
                success = True
        return ret

    @connection_required
    def char_write_handle(self, char_handle, value, wait_for_response=False):

        while True:
            value_list = [b for b in value]
            if wait_for_response:
                self._backend.send_command(
                    CommandBuilder.attclient_attribute_write(
                        self._handle, char_handle, value_list))
                self._backend.expect(
                    ResponsePacketType.attclient_attribute_write)
                packet_type, response = self._backend.expect(
                    EventPacketType.attclient_procedure_completed)
            else:
                self._backend.send_command(
                    CommandBuilder.attclient_write_command(
                        self._handle, char_handle, value_list))
                packet_type, response = self._backend.expect(
                    ResponsePacketType.attclient_write_command)

            if (response['result'] !=
                    ErrorCode.insufficient_authentication.value):
                # Continue to retry until we are bonded
                if response['result']:
                    raise RuntimeError("Error on write 0x%04x: %s" % (
                        response['result'], get_return_message(response['result'])))
                break

    @connection_required
    def disconnect(self):
        log.debug("Disconnecting from %s", self._address)
        self._backend.send_command(
            CommandBuilder.connection_disconnect(self._handle))

        self._backend.expect(ResponsePacketType.connection_disconnect)
        log.info("Disconnected from %s", self._address)
        self._handle = None

    @connection_required
    def discover_characteristics(self):
        self._characteristics = self._backend.discover_characteristics(
            self._handle)
        return self._characteristics
