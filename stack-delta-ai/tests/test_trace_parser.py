import unittest

from stack_delta.trace_parser import parse_env_sensor, parse_strace


class TraceParserTests(unittest.TestCase):
    def test_parses_file_process_and_network(self):
        trace = """
1710000000.100000 openat(AT_FDCWD, "/home/sandbox/.ssh/id_rsa", O_RDONLY|O_CLOEXEC) = 3
1710000000.200000 execve("/usr/bin/node", ["node", "install.js"], 0x7fff) = 0
1710000000.300000 connect(12, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("198.51.100.10")}, 16) = -1 ENETUNREACH
1710000000.400000 openat(AT_FDCWD, "/home/sandbox/.bashrc", O_WRONLY|O_CREAT|O_APPEND, 0666) = 4
"""
        events = parse_strace(trace)
        pairs = {(item.capability, item.target, item.status) for item in events}
        self.assertIn(("file_read", "/home/sandbox/.ssh/id_rsa", "success"), pairs)
        self.assertIn(("process_spawn", "/usr/bin/node", "success"), pairs)
        self.assertIn(("network_connect", "198.51.100.10:443", "attempted"), pairs)
        self.assertIn(("file_write", "/home/sandbox/.bashrc", "success"), pairs)

    def test_env_sensor_redacts_values(self):
        events = parse_env_sensor('{"name":"CANARY_API_TOKEN","timestamp":1.2}\nnot-json')
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].target, "CANARY_API_TOKEN")
        self.assertNotIn("TOKEN_VALUE", events[0].detail)


if __name__ == "__main__":
    unittest.main()

