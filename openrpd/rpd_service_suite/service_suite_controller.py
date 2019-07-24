
import argparse
import sys

from rpd.it_api.it_api import ItApiClient
from rpd.gpb.it_api_msgs_pb2 import t_ItApiServiceSuiteMessage


class ServiceSuiteController(object):

    it_api_client = None

    # By default, we will start IPv4 and IPv6 services (dual stack)

    # Setting this to True will only start the IPv4 services
    ipv4_only = False

    # Note - We cannot currently do IPv6 only
    # Setting this to True will only start the IPv6 services (and any REQUIRED IPv4 services)
    # ipv6_only = False

    def __init__(self):
        self.it_api_client = ItApiClient(t_ItApiServiceSuiteMessage)

    def connect_to_it_api_client(self):
        connected = self.it_api_client.connect("127.0.0.1")
        if not connected:
            sys.stderr.write("Error opening the connection to the IT API Server\n")
        return connected

    def _enable_services(self, enable=True):
        connected = self.connect_to_it_api_client()
        if connected:
            # True -> enable service, False -> disable, None -> no change
            msg = t_ItApiServiceSuiteMessage()
            msg.MessageType = msg.IT_API_SERVICE_SUITE_CONFIGURE

            # Default behavior
            getattr(msg.ServiceConfigureMessage, "DHCPv4").enable = enable
            getattr(msg.ServiceConfigureMessage, "DHCPv6").enable = enable
            getattr(msg.ServiceConfigureMessage, "Tp").enable = enable
            # Note - CcapCoreV6 services both v4 and v6, so only start one of these
            getattr(msg.ServiceConfigureMessage, "CcapCoreV4").enable = False
            getattr(msg.ServiceConfigureMessage, "CcapCoreV6").enable = enable

            if (self.ipv4_only):
                sys.stderr.write("**************************************************\n")
                sys.stderr.write("*** WARNING - IPv6 services are DISABLED!\n")
                sys.stderr.write("**************************************************\n")
                getattr(msg.ServiceConfigureMessage, "DHCPv6").enable = False
                getattr(msg.ServiceConfigureMessage, "CcapCoreV6").enable = False
                getattr(msg.ServiceConfigureMessage, "CcapCoreV4").enable = enable
            # elif (self.ipv6_only):
            #     sys.stderr.write("**************************************************\n")
            #     sys.stderr.write("*** WARNING - IPv4 services are DISABLED!\n")
            #     sys.stderr.write("**************************************************\n")
            #     # Note - The DHCPv4 service is currently required in v6 mode,
            #     #  uncomment the following line when this is no longer the case
            #     # getattr(msg.ServiceConfigureMessage, "DHCPv4").enable = False
            #     # Note - CcapCoreV4 should be disabled by default, but make sure
            #     getattr(msg.ServiceConfigureMessage, "CcapCoreV4").enable = False

             # gpb_result = self.it_api_client.it_api_send_msg(msg)
            # sys.stdout.write("Result: %s\n" . format(gpb_result))
            self.it_api_client.it_api_send_msg(msg)

    def enable_services(self):
        self._enable_services(True)

    def disable_services(self):
        self._enable_services(False)

    def start_l2tp(self):
        connected = self.connect_to_it_api_client()
        if connected:
            msg = t_ItApiServiceSuiteMessage()
            msg.MessageType = msg.IT_API_SERVICE_SUITE_L2TP
            # gpb_result = self.it_api_client.it_api_send_msg(msg)
            # sys.stdout.write("Result: %s\n" . format(gpb_result))
            self.it_api_client.it_api_send_msg(msg)


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    # all of the following options are mutually exclusive, and one of them is required
    enable_opts = ["all", "ipv4only"]
    group.add_argument("-e", "--enable", help="enable services (default: all)",
                       nargs="?",
                       choices=enable_opts,
                       const=enable_opts[0],
                       action="store")
    group.add_argument("-d", "--disable", help="disable all services",
                       action="store_true")
    group.add_argument("-l", "--l2tp", help="start L2TP",
                       action="store_true")
    args = parser.parse_args()

    print(args)

    if len(sys.argv) > 0:
        controller = ServiceSuiteController()
        if args.enable == enable_opts[0]:
            controller.enable_services()
        elif args.enable == enable_opts[1]:
            controller.ipv4_only = True
            controller.enable_services()
        elif args.disable:
            controller.disable_services()
        elif args.l2tp:
            controller.start_l2tp()
        else:
            # if argparse works correctly, this should not happen
            parser.print_help()
            sys.exit(2)
        sys.exit(0)

    parser.print_help()
    sys.exit(1)

if __name__ == "__main__":
    main()
