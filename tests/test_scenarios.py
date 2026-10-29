#!/usr/bin/env python3
"""
Unit & Scenario Verification Tests for netdiag
ทดสอบจำลองเหตุการณ์สายแลนและระบบ Network มีปัญหาในแต่ละ Layer (L1 - L7) และโหมดเมนูทั้งหมด 11 สถานการณ์
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netdiag import CheckStatus, InterfaceDiagReport
from netdiag.analyzer import diagnose_interface, synthesize_root_cause
from netdiag.free_ip_finder import run_free_ip_and_dhcp_scope_checks
from netdiag.ip_conflict_scanner import run_ip_exhaustion_and_conflict_checks
from netdiag.layer1_physical import run_layer1_checks
from netdiag.layer3_network import run_layer3_checks
from netdiag.layer4_7_internet import run_layer4_7_checks
from netdiag.path_bottleneck import run_bottleneck_checks
from netdiag.rogue_dhcp_checker import run_dhcp_audit_checks
from netdiag.target_port_checker import run_target_and_port_checks


class TestNetworkScenarios(unittest.TestCase):
    def test_scenario_1_unplugged_cable_l1(self):
        """จำลองสถานการณ์ที่ 1: สายแลนหลุด หรือพอร์ต Switch ปิด (NO-CARRIER)"""
        rep = InterfaceDiagReport(interface="enp0s31f6", if_type="ethernet")
        with patch("netdiag.layer1_physical._read_sysfs") as mock_sys, patch(
            "netdiag.layer1_physical.get_ethtool_info"
        ) as mock_eth, patch("netdiag.layer1_physical.get_driver_info", return_value="e1000e"):
            mock_sys.side_effect = lambda iface, attr: {
                "address": "c8:5b:76:ac:7d:75",
                "flags": "0x1003",
                "operstate": "down",
                "carrier": "0",
            }.get(attr)
            mock_eth.return_value = {"Link detected": "no"}

            ok = run_layer1_checks(rep)
            synthesize_root_cause(rep)

            self.assertFalse(ok)
            self.assertEqual(rep.overall_status, CheckStatus.FAIL)
            self.assertTrue(any("NO-CARRIER" in rc for rc in rep.root_causes))

    def test_scenario_2_bad_cable_100mbps_half_duplex_and_crc(self):
        """จำลองสถานการณ์ที่ 2: สายแลนเข้าหัวไม่ดี วิ่ง Half-Duplex และมี CRC Error"""
        rep = InterfaceDiagReport(interface="enp0s31f6", if_type="ethernet")
        with patch("netdiag.layer1_physical._read_sysfs") as mock_sys, patch(
            "netdiag.layer1_physical.get_ethtool_info"
        ) as mock_eth, patch("netdiag.layer1_physical.get_driver_info", return_value="e1000e"), patch(
            "netdiag.layer1_physical.get_nic_error_stats"
        ) as mock_stats:
            mock_sys.side_effect = lambda iface, attr: {
                "address": "c8:5b:76:ac:7d:75",
                "flags": "0x1003",
                "operstate": "up",
                "carrier": "1",
            }.get(attr)
            mock_eth.return_value = {
                "Link detected": "yes",
                "Speed": "100Mb/s",
                "Duplex": "Half",
                "Auto-negotiation": "on",
            }
            mock_stats.return_value = {
                "rx_crc_errors": 45,
                "rx_frame_errors": 12,
                "rx_errors": 57,
                "tx_errors": 0,
                "tx_carrier_errors": 0,
                "collisions": 18,
                "carrier_changes": 5,
            }

            ok = run_layer1_checks(rep)
            synthesize_root_cause(rep)

            self.assertTrue(ok)
            self.assertEqual(rep.overall_status, CheckStatus.FAIL)
            self.assertTrue(any("Half-Duplex" in rc for rc in rep.root_causes))
            self.assertTrue(any("Physical Errors" in rc for rc in rep.root_causes))

    def test_scenario_3_dhcp_failure_apipa_l3(self):
        """จำลองสถานการณ์ที่ 3: เสียบสายติดแล้ว แต่ไม่ได้รับ IP จาก DHCP (ติด 169.254.x.x APIPA)"""
        rep = InterfaceDiagReport(interface="enp0s31f6", if_type="ethernet")
        with patch("netdiag.layer3_network.get_ip_addresses") as mock_ips:
            mock_ips.return_value = ([{"local": "169.254.10.25", "prefixlen": 16}], [])
            ok = run_layer3_checks(rep)
            synthesize_root_cause(rep)

            self.assertFalse(ok)
            self.assertEqual(rep.overall_status, CheckStatus.FAIL)
            self.assertTrue(any("APIPA" in rc for rc in rep.root_causes))

    def test_scenario_4_dns_broken_and_captive_portal_l7(self):
        """จำลองสถานการณ์ที่ 4: ออกเน็ตด้วย IP (1.1.1.1) ได้ แต่ DNS ล่ม และติดหน้า Captive Portal"""
        rep = InterfaceDiagReport(interface="enp0s31f6", if_type="ethernet")
        rep.raw_context["dns_servers"] = ["192.168.1.1"]

        with patch("netdiag.layer4_7_internet.ping_host") as mock_ping, patch(
            "netdiag.layer4_7_internet.check_path_mtu"
        ) as mock_mtu, patch("netdiag.layer4_7_internet.test_dns_server") as mock_dns, patch(
            "netdiag.layer4_7_internet.check_captive_portal_and_http"
        ) as mock_portal:
            mock_ping.return_value = {"reachable": True, "loss_pct": 0.0, "avg_ms": 12.3, "raw": ""}
            mock_mtu.return_value = {"ok": True, "max_mtu": 1500}
            mock_dns.side_effect = lambda domain, server=None, timeout_sec=2: (
                {"ok": False, "ips": [], "latency_ms": None}
                if server == "192.168.1.1"
                else {"ok": True, "ips": ["142.250.1.1"], "latency_ms": 15.0}
            )
            mock_portal.return_value = {
                "http_code": "302",
                "redirect_url": "http://10.0.0.1/login",
            }

            run_layer4_7_checks(rep)
            synthesize_root_cause(rep)

            self.assertEqual(rep.overall_status, CheckStatus.FAIL)
            self.assertTrue(any("DNS Server" in rc for rc in rep.root_causes))
            self.assertTrue(any("Captive Portal" in rc for rc in rep.root_causes))

    def test_scenario_5_same_subnet_conflict_and_ghost_connection(self):
        """จำลองสถานการณ์ที่ 5: Ghost Connection (มี DNS ค้างแต่ IPv4 หลุด) และ Same-Subnet Conflict"""
        rep = InterfaceDiagReport(interface="enp0s31f6", if_type="ethernet")
        rep.raw_context["nmcli"] = {
            "GENERAL.STATE": "100 (connected)",
            "IP4.DNS[1]": "10.8.1.254",
        }
        with patch("netdiag.layer3_network.get_ip_addresses") as mock_ips:
            mock_ips.return_value = ([], [{"local": "fe80::1", "scope": "link"}])
            ok = run_layer3_checks(rep)
            synthesize_root_cause(rep, mode="ip")

            self.assertFalse(ok)
            self.assertTrue(any("เคยเชื่อมต่อสำเร็จ" in rc for rc in rep.root_causes))

    def test_scenario_6_targeted_cable_mode_only_runs_l1(self):
        """จำลองสถานการณ์ที่ 6: เลือกเมนูเช็กเฉพาะสายแลน (mode='cable') ต้องเช็กเฉพาะ L1"""
        with patch("netdiag.analyzer.run_layer1_checks", return_value=True) as m1, patch(
            "netdiag.analyzer.run_layer2_checks"
        ) as m2, patch("netdiag.analyzer.run_layer3_checks") as m3:
            rep = diagnose_interface("enp0s31f6", mode="cable")
            m1.assert_called_once()
            m2.assert_not_called()
            m3.assert_not_called()
            self.assertEqual(rep.raw_context.get("diag_mode"), "cable")

    def test_scenario_7_ip_exhaustion_and_computers_fighting_over_ip(self):
        """จำลองสถานการณ์ที่ 7: ไอพีในวงแลนใกล้เต็ม (245/254 IPs) และมีคอมพิวเตอร์ 2 เครื่องแย่ง IP 10.8.70.50 กัน"""
        rep = InterfaceDiagReport(interface="wlp4s0", if_type="wifi", mac_address="34:f3:9a:ed:bb:33")
        with patch("netdiag.ip_conflict_scanner.get_ip_addresses") as mock_ips, patch(
            "netdiag.ip_conflict_scanner.scan_subnet_hosts"
        ) as mock_scan:
            mock_ips.return_value = ([{"local": "10.8.70.78", "prefixlen": 24}], [])
            mock_scan.return_value = {
                "subnet": "10.8.70.0/24",
                "total_usable": 254,
                "active_count": 245,
                "free_count": 9,
                "usage_pct": 96.5,
                "hosts": {
                    "10.8.70.50": ["aa:bb:cc:11:22:33", "dd:ee:ff:44:55:66"],
                    "10.8.70.78": ["34:f3:9a:ed:bb:33"],
                },
                "duplicate_ips": {
                    "10.8.70.50": ["aa:bb:cc:11:22:33", "dd:ee:ff:44:55:66"],
                },
                "multi_ip_macs": {},
            }

            run_ip_exhaustion_and_conflict_checks(rep)
            synthesize_root_cause(rep, mode="conflict")

            self.assertEqual(rep.overall_status, CheckStatus.FAIL)
            self.assertTrue(any("ใกล้เต็มวิกฤต" in rc for rc in rep.root_causes))
            self.assertTrue(any("แย่ง IP กัน" in rc for rc in rep.root_causes))

    def test_scenario_8_bottleneck_high_jitter_on_wan(self):
        """จำลองสถานการณ์ที่ 8: วงแลนและ Core ปกติ แต่ขาออกอินเทอร์เน็ต (Tier 3) Jitter พุ่งสูง (กระตุก)"""
        rep = InterfaceDiagReport(interface="wlp4s0", if_type="wifi")
        rep.raw_context["nmcli"] = {"IP4.GATEWAY": "10.8.70.1", "IP4.DNS[1]": "10.8.1.254"}
        with patch("netdiag.path_bottleneck.get_ip_addresses") as mock_ips, patch(
            "netdiag.path_bottleneck.get_interface_routes", return_value=[]
        ), patch("netdiag.path_bottleneck.measure_jitter_and_loss") as mock_jit, patch(
            "netdiag.path_bottleneck.run_hop_traceroute", return_value=[]
        ):
            mock_ips.return_value = ([{"local": "10.8.70.78", "prefixlen": 24}], [])
            mock_jit.side_effect = lambda target, iface=None, count=6: (
                {"target": target, "reachable": True, "loss_pct": 0.0, "min_ms": 2.0, "avg_ms": 3.0, "max_ms": 4.0, "jitter_ms": 0.8}
                if target != "1.1.1.1"
                else {"target": "1.1.1.1", "reachable": True, "loss_pct": 0.0, "min_ms": 15.0, "avg_ms": 120.0, "max_ms": 240.0, "jitter_ms": 45.0}
            )
            run_bottleneck_checks(rep)
            synthesize_root_cause(rep, mode="bottleneck")

            self.assertEqual(rep.overall_status, CheckStatus.WARN)
            self.assertTrue(any("ขาออกอินเทอร์เน็ตภายนอก" in rc for rc in rep.root_causes))

    def test_scenario_9_target_printer_port_9100_open(self):
        """จำลองสถานการณ์ที่ 9: ทดสอบเครื่องปริ้นเตอร์เครือข่าย เปิดพอร์ต 9100 และ 80"""
        rep = InterfaceDiagReport(interface="wlp4s0", if_type="wifi")
        with patch("netdiag.target_port_checker.ping_host") as mock_ping, patch(
            "netdiag.target_port_checker.get_arp_neighbors", return_value=[{"ip": "10.8.70.200", "mac": "aa:bb:cc:dd:ee:ff"}]
        ), patch("netdiag.target_port_checker.scan_target_ports") as mock_scan:
            mock_ping.return_value = {"reachable": True, "loss_pct": 0.0, "avg_ms": 2.5, "raw": ""}
            mock_scan.return_value = [
                {"port": 80, "service": "HTTP (Web Server)", "state": "OPEN", "latency_ms": 3.1},
                {"port": 9100, "service": "JetDirect (Network Printer)", "state": "OPEN", "latency_ms": 2.8},
            ]
            run_target_and_port_checks(rep, target_host="10.8.70.200", custom_ports=[80, 9100])
            synthesize_root_cause(rep, mode="target")

            self.assertEqual(rep.overall_status, CheckStatus.PASS)
            self.assertIn("เครื่องปริ้นเตอร์เครือข่าย", " ".join(rep.raw_context["target_scan"]["device_roles"]))

    def test_scenario_10_rogue_dhcp_detected(self):
        """จำลองสถานการณ์ที่ 10: ตรวจพบ DHCP Server เถื่อนตอบกลับซ้อนกัน 2 ตัวในวงแลน"""
        rep = InterfaceDiagReport(interface="wlp4s0", if_type="wifi")
        rep.raw_context["nmcli"] = {
            "DHCP4.OPTION[1]": "dhcp_server_identifier = 10.8.1.253",
            "DHCP4.OPTION[2]": "ip_address = 10.8.70.78",
            "DHCP4.OPTION[3]": "domain_name = medbuu.local",
            "DHCP4.OPTION[4]": "dhcp_lease_time = 691200",
        }
        with patch("netdiag.rogue_dhcp_checker.get_ip_addresses") as mock_ips, patch(
            "netdiag.rogue_dhcp_checker.ping_host"
        ) as mock_ping, patch("netdiag.rogue_dhcp_checker.probe_active_dhcp_servers_root") as mock_probe:
            mock_ips.return_value = ([{"local": "10.8.70.78", "prefixlen": 24}], [])
            mock_ping.return_value = {"reachable": True, "loss_pct": 0.0, "avg_ms": 3.2, "raw": ""}
            mock_probe.return_value = [
                {"server_id": "10.8.1.253", "ip_offered": "10.8.70.78"},
                {"server_id": "192.168.1.1", "ip_offered": "192.168.1.100"},
            ]
            run_dhcp_audit_checks(rep)
            synthesize_root_cause(rep, mode="dhcp")

            self.assertEqual(rep.overall_status, CheckStatus.FAIL)
            self.assertTrue(any("ตอบกลับซ้อนกัน 2 ตัว" in rc for rc in rep.root_causes))

    def test_scenario_11_free_ip_and_static_zone_list(self):
        """จำลองสถานการณ์ที่ 11: สแกนหา IP ว่างและแยกโซนปลอดภัยนอกช่วง DHCP (.2 - .18 และ .253 - .254)"""
        rep = InterfaceDiagReport(interface="wlp4s0", if_type="wifi", mac_address="34:f3:9a:ed:bb:33")
        rep.raw_context["nmcli"] = {
            "IP4.GATEWAY": "10.8.70.1",
            "DHCP4.OPTION[1]": "dhcp_server_identifier = 10.8.1.253",
        }
        with patch("netdiag.free_ip_finder.get_ip_addresses") as mock_ips, patch(
            "netdiag.free_ip_finder.get_interface_routes", return_value=[]
        ), patch("netdiag.free_ip_finder.scan_subnet_hosts") as mock_scan:
            mock_ips.return_value = ([{"local": "10.8.70.78", "prefixlen": 24, "dynamic": True}], [])
            mock_scan.return_value = {
                "subnet": "10.8.70.0/24",
                "total_usable": 254,
                "active_count": 3,
                "free_count": 251,
                "usage_pct": 1.2,
                "hosts": {
                    "10.8.70.1": ["94:24:e1:4c:97:c7"],
                    "10.8.70.19": ["d4:a2:cd:9c:cf:3f"],
                    "10.8.70.252": ["48:ea:63:85:95:6e"],
                },
                "duplicate_ips": {},
                "multi_ip_macs": {},
            }

            run_free_ip_and_dhcp_scope_checks(rep)
            synthesize_root_cause(rep, mode="freeip")

            self.assertEqual(rep.overall_status, CheckStatus.PASS)
            f_data = rep.raw_context["free_ip_data"]
            self.assertIn("10.8.70.2", f_data["free_static_zone_ips"])
            self.assertIn("10.8.70.18", f_data["free_static_zone_ips"])
            self.assertNotIn("10.8.70.19", f_data["free_static_zone_ips"])

    def test_scenario_12_htb_cyber_recon_radar(self) -> None:
        """จำลองสถานการณ์ที่ 12: เรดาร์สแกนทรัพย์สินเครือข่าย ชื่อเครื่อง NetBIOS และยี่ห้อ MAC Vendor"""
        from netdiag.cyber_recon import run_cyber_recon_checks

        rep = InterfaceDiagReport(interface="wlp4s0", if_type="wifi", mac_address="34:f3:9a:ed:bb:33")
        with patch("netdiag.cyber_recon.get_ip_addresses") as mock_ips, patch(
            "netdiag.cyber_recon.get_interface_routes", return_value=[{"dst": "default", "gateway": "10.8.70.1"}]
        ), patch("netdiag.cyber_recon.get_nmcli_device_info", return_value={}), patch(
            "netdiag.cyber_recon.scan_subnet_hosts"
        ) as mock_scan, patch(
            "netdiag.cyber_recon.run_nbtscan_lookup", return_value={"10.8.70.50": "FINANCE-PC01"}
        ), patch(
            "netdiag.cyber_recon.run_mdns_lookup", return_value={}
        ), patch(
            "netdiag.cyber_recon.run_reverse_dns_ptr", return_value=""
        ):
            mock_ips.return_value = ([{"local": "10.8.70.78", "prefixlen": 24}], [])
            mock_scan.return_value = {
                "subnet": "10.8.70.0/24",
                "total_usable": 254,
                "active_count": 2,
                "free_count": 252,
                "usage_pct": 0.8,
                "hosts": {
                    "10.8.70.1": ["00:00:0c:11:22:33"],
                    "10.8.70.50": ["34:f3:9a:11:22:33"],
                },
                "duplicate_ips": {},
                "multi_ip_macs": {},
            }
            run_cyber_recon_checks(rep)
            synthesize_root_cause(rep, mode="recon")
            self.assertEqual(rep.overall_status, CheckStatus.PASS)
            r_data = rep.raw_context["cyber_recon"]
            self.assertEqual(r_data["named_count"], 1)
            self.assertEqual(r_data["assets"][1]["hostname"], "FINANCE-PC01")

    def test_scenario_13_broadcast_storm_detected(self) -> None:
        """จำลองสถานการณ์ที่ 13: ตรวจพบ Broadcast Storm / Switching Loop ในสายแลน"""
        from netdiag.traffic_analyzer import run_traffic_and_storm_checks

        rep = InterfaceDiagReport(interface="enp0s31f6", if_type="ethernet")
        with patch("netdiag.traffic_analyzer.sample_interface_traffic") as mock_traffic:
            mock_traffic.return_value = {
                "interface": "enp0s31f6",
                "sample_sec": 2.0,
                "rx_kbps": 15400.0,
                "tx_kbps": 120.0,
                "rx_mbps": 15.4,
                "tx_mbps": 0.12,
                "rx_pps": 28500.0,
                "tx_pps": 45.0,
                "mcast_pps": 14200.0,
                "avg_rx_pkt_bytes": 64.0,
                "dropped_delta": 35,
                "total_rx_mb": 512.0,
                "total_tx_mb": 42.0,
                "total_mcast_pkts": 950000,
                "total_dropped_pkts": 120,
                "is_broadcast_storm": True,
                "socket_stats": {"tcp_estab": 8, "tcp_total": 15, "udp_total": 4},
                "protocols": [{"protocol": "ARP", "packets": 28000, "pct": 98.2}],
            }
            run_traffic_and_storm_checks(rep)
            synthesize_root_cause(rep, mode="traffic")
            self.assertEqual(rep.overall_status, CheckStatus.FAIL)
            self.assertTrue(any("Broadcast/Multicast พุ่งสูงผิดปกติ" in rc for rc in rep.root_causes))


if __name__ == "__main__":
    unittest.main(verbosity=2)
