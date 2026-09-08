import ipaddress
import unittest
from unittest.mock import patch

from bot.remote import _free_port, _free_subnet, config_path, container_name, interface_name


class RemoteSelectionTests(unittest.TestCase):
    @patch("bot.remote.run", return_value="UNCONN 0 0 0.0.0.0:50001 0.0.0.0:*")
    def test_port_is_in_required_range_and_not_used(self, _run):
        port = _free_port(object())
        self.assertGreaterEqual(port, 50000)
        self.assertLessEqual(port, 59999)
        self.assertNotEqual(port, 50001)

    @patch("bot.remote.sudo_run", return_value="172.16.0.0/12")
    @patch("bot.remote.run", return_value="10.0.0.0/8 dev eth0")
    def test_subnet_does_not_overlap_routes_or_docker(self, _run, _sudo):
        subnet = _free_subnet(object(), "password")
        self.assertTrue(subnet.subnet_of(ipaddress.ip_network("192.168.0.0/16")))

    def test_instance_paths_are_unique(self):
        server = {"remote_dir": "/opt/awg-bot/abcd", "container": "awg-bot-abcd", "interface": "awgabcd"}
        self.assertEqual(container_name(server), "awg-bot-abcd")
        self.assertEqual(interface_name(server), "awgabcd")
        self.assertEqual(config_path(server), "/opt/awg-bot/abcd/data/awgabcd.conf")


if __name__ == "__main__":
    unittest.main()
