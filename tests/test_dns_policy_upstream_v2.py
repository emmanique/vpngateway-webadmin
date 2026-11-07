"""Packet parser and routing trust boundaries for opt-in DNS policy upstream."""
import importlib.util
import ipaddress
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

SCRIPT=Path(__file__).resolve().parents[1]/"scripts/vpngw-dns-policy-upstream.py"
spec=importlib.util.spec_from_file_location("dns_route_qa", SCRIPT)
worker=importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


def packet(client="192.0.2.44", identifier=0xABCD, extra=b""):
    q = b"\x03www\x07example\x03org\x00\x00\x01\x00\x01"
    ecs = b"\x00\x08\x00\x08" + struct.pack("!HBB", 1, 32, 0) + ipaddress.IPv4Address(client).packed
    opt = b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00" + struct.pack("!H",len(ecs)+len(extra)) + ecs+extra
    return struct.pack("!HHHHHH",identifier,0x0100,1,0,0,1) + q + opt


class EdnsTests(unittest.TestCase):
    def test_parse_and_remove_client_address(self):
        pkt=packet()
        client,clean,question=worker.parse_and_strip_ecs(pkt)
        self.assertEqual(client,"192.0.2.44")
        self.assertNotIn(ipaddress.IPv4Address(client).packed,clean)
        self.assertEqual(struct.unpack_from("!H",clean,len(clean)-2)[0],0)
        self.assertTrue(question.endswith(b"\x00\x01\x00\x01"))

    def test_preserve_other_edns_extensions(self):
        other=b"\x00\x0c\x00\x02\x00\x00"
        client,clean,_=worker.parse_and_strip_ecs(packet(extra=other))
        self.assertEqual(client,"192.0.2.44")
        self.assertTrue(clean.endswith(other))

    def test_bad_or_missing_ecs_fails_closed(self):
        original=packet()
        options=[original[:-12],original.replace(b"\x00\x08\x00\x08",b"\x00\x07\x00\x08",1),
                 original.replace(b"\x00\x01\x20\x00",b"\x00\x01\x18\x00",1)]
        for malformed in options:
            with self.subTest(malformed=malformed[-16:]):
                with self.assertRaises(worker.QueryRejected):
                    worker.parse_and_strip_ecs(malformed)

    def test_dns_failure_refuses_default_fallback(self):
        with tempfile.TemporaryDirectory() as state_dir:
            answer=worker.resolve(packet(),state_dir)
            self.assertEqual(answer[:2],packet()[:2])
            self.assertEqual(answer[3]&0x0f,2)


class PolicySelectionTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path=Path(self.folder.name)

    def record(self,status="active",pending=False,destination="vpn-test",dns="10.2.0.1",interface="wgtest0"):
        d={"status":status,"plan":{"destination":destination,"host":"192.0.2.44","wan":"wlan0",
            "registered_mac":"02:00:00:00:00:44"},
            "vpn_runtime":{"interface":interface,"dns_ipv4":dns}}
        if pending: d["vpn_pending"]={"previous":"direct"}
        (self.path/"host-qa.json").write_text(json.dumps(d))

    def test_vpn_is_selected_without_direct_fallback(self):
        self.record()
        self.assertEqual(worker.trusted_policy("192.0.2.44",self.path),("wgtest0","10.2.0.1"))

    def test_direct_requires_explicit_public_resolver(self):
        self.record(destination="direct")
        with self.assertRaises((worker.QueryRejected,TypeError,ValueError)):
            worker.trusted_policy("192.0.2.44",self.path)
        self.assertEqual(worker.trusted_policy("192.0.2.44",self.path,"9.9.9.9"),("wlan0","9.9.9.9"))

    def test_pending_and_blocked_never_query_upstream(self):
        for spec in ({"pending":True},{"status":"error"},{"destination":"blocked"}):
            with self.subTest(spec=spec):
                self.record(**spec)
                with self.assertRaises(worker.QueryRejected):
                    worker.trusted_policy("192.0.2.44",self.path)

    def test_egress_device_binding_failure_never_attempts_send(self):
        from unittest.mock import MagicMock
        outbound=MagicMock()
        outbound.__enter__.return_value=outbound
        outbound.setsockopt.side_effect=OSError("bind denied")
        with patch.object(worker.socket,"socket",return_value=outbound):
            with self.assertRaises(OSError):
                worker.query_via_interface(packet(),"10.2.0.1","wgtest0")
            outbound.connect.assert_not_called()
            outbound.send.assert_not_called()

    def test_unknown_unmanaged_client_does_not_use_direct(self):
        self.record()
        with self.assertRaises(worker.QueryRejected):
            worker.trusted_policy("192.0.2.99",self.path,"1.1.1.1")

    def test_duplicate_policy_identity_is_rejected(self):
        self.record()
        (self.path/"other-qa.json").write_text((self.path/"host-qa.json").read_text())
        with self.assertRaises(worker.QueryRejected):
            worker.trusted_policy("192.0.2.44",self.path)

    def test_explicit_bind_to_device_per_request(self):
        self.record()
        query=packet()
        with patch.object(worker,"query_via_interface",return_value=query[:2]+b"\x81\x80"+query[4:]) as upstream:
            worker.resolve(query,self.path)
            self.assertEqual(upstream.call_args.args[1:],("10.2.0.1","wgtest0"))

if __name__=="__main__":
    unittest.main()


class DnsUpstreamPacketIntegration(unittest.TestCase):
    """Real UDP and TCP loopback packets without touching the gateway routing."""
    def setUp(self):
        import socket, threading
        self.socket = socket
        self.threading = threading
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        directory = Path(self.folder.name)
        (directory/"test-host.json").write_text(json.dumps({
            "status":"active",
            "plan":{"destination":"vpn-test","host":"192.0.2.44"},
            "vpn_runtime":{"interface":"wgtest0","dns_ipv4":"10.2.0.1"}
        }))
        self.folderpath = directory

    def server(self, server_class, handler):
        server=server_class(("127.0.0.1",0),handler)
        server.policy_dir = str(self.folderpath)
        server.direct_resolver = "1.1.1.1"
        server.trusted_peer = "127.0.0.1"
        runner=self.threading.Thread(target=server.serve_forever,daemon=True)
        runner.start()
        self.addCleanup(lambda: (server.shutdown(),server.server_close(),runner.join(2)))
        return server.server_address

    def test_real_udp_request_has_identity_stripped_before_egress(self):
        with patch.object(worker,"query_via_interface") as egress:
            def forward(data,dns,iface,tcp=False,timeout=3):
                self.assertNotIn(ipaddress.IPv4Address("192.0.2.44").packed,data)
                self.assertEqual((dns,iface),("10.2.0.1","wgtest0"))
                return data[:2]+b"\x81\x80"+data[4:]
            egress.side_effect=forward
            address=self.server(worker.DnsUDP,worker.UdpHandler)
            with self.socket.socket(self.socket.AF_INET,self.socket.SOCK_DGRAM) as c:
                c.settimeout(3)
                c.sendto(packet(),address)
                response,_=c.recvfrom(4096)
            self.assertEqual(response[:2],b"\xab\xcd")
            self.assertEqual(response[2],0x81)
            egress.assert_called_once()

    def test_real_tcp_request_uses_egress_policy(self):
        with patch.object(worker,"query_via_interface") as egress:
            egress.side_effect=lambda data,dns,iface,tcp=False,timeout=3: data[:2]+b"\x81\x80"+data[4:]
            address=self.server(worker.DnsTCP,worker.TcpHandler)
            with self.socket.create_connection(address,timeout=3) as c:
                c.settimeout(3)
                message=packet()
                c.sendall(struct.pack("!H",len(message))+message)
                length=struct.unpack("!H",c.recv(2))[0]
                answer=c.recv(length)
            self.assertEqual(answer[:2],b"\xab\xcd")
            self.assertEqual(answer[2],0x81)
            egress.assert_called_once()
