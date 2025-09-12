#!/usr/bin/env python3
import subprocess
import sys
import time
import dbus
import dbusmock
import pytest

from src import firewall

def test_firewalld_dbusmock():
    """
    CI-friendly integration test that uses python-dbusmock to emulate the
    minimal firewalld D-Bus surface used by src/firewall.py.

    This test does not rely on pytest plugin fixtures and starts a dbusmock
    server via the DBusTestCase helper.
    """
    # Use DBusTestCase helper to start a private system bus for testing.
    tc = dbusmock.DBusTestCase()
    tc.start_system_bus()

    p_mock = None
    try:
        # Spawn the mock D-Bus server on the (mocked) system bus and capture stdout.
        p_mock = tc.spawn_server(
            'org.fedoraproject.FirewallD1',
            '/org/fedoraproject/FirewallD1',
            'org.fedoraproject.FirewallD1',
            system_bus=True,
            stdout=subprocess.PIPE
        )

        # Get a proxy for the mock controller and add the minimal methods we need.
        dbus_firewall_mock = dbus.Interface(
            tc.get_dbus(True).get_object(
                'org.fedoraproject.FirewallD1',
                '/org/fedoraproject/FirewallD1'
            ),
            dbusmock.MOCK_IFACE
        )

        # Minimal implementations:
        dbus_firewall_mock.AddMethod('', 'getDefaultZone', '', 's', "ret = 'public'")
        dbus_firewall_mock.AddMethod('', 'getZones', '', 'as', "ret = ['public', 'knocker']")
        dbus_firewall_mock.AddMethod('', 'addRichRule', 'ss', '', "print('addRichRule', args); sys.stdout.flush()")
        dbus_firewall_mock.AddMethod('', 'removeRichRule', 'ss', '', "print('removeRichRule', args); sys.stdout.flush()")
        dbus_firewall_mock.AddMethod('', 'getRichRules', 's', 'as', "ret = []")

        # Prepare settings enabling firewall
        settings = {
            "firewall": {
                "enabled": True,
                "monitored_ports": ["80/tcp", "443/tcp", "22/tcp"]
            },
            "security": {"always_allowed_ips": []},
            "whitelist": {"storage_path": "/tmp/test_whitelist_dbusmock.json"}
        }

        # Ensure firewall module will reconnect to the (mocked) system bus
        firewall._firewalld_available = None
        firewall._fw = None

        # Initialize firewall -> should succeed because mock reports 'knocker' zone exists
        assert firewall.initialize_firewall(settings) is True

        # Add an IP and verify that our mock saw addRichRule calls via its stdout
        expiry = int(time.time()) + 3600
        assert firewall.add_ip_to_firewall("192.0.2.123", expiry, settings) is True

        # Read mock stdout for method call logs (dbusmock logs method calls to stdout)
        found_add = False
        deadline = time.time() + 5.0
        while time.time() < deadline:
            line = p_mock.stdout.readline()
            if not line:
                time.sleep(0.05)
                continue
            try:
                text = line.decode('utf-8', errors='ignore')
            except Exception:
                text = str(line)
            if 'addRichRule' in text:
                found_add = True
                break

        assert found_add, "dbusmock did not log addRichRule calls; expected firewall to call addRichRule"

    finally:
        # Clean up mock process and test bus
        if p_mock:
            try:
                p_mock.stdout.close()
            except Exception:
                pass
            try:
                p_mock.terminate()
                p_mock.wait(timeout=5)
            except Exception:
                pass
        try:
            tc.stop_system_bus()
        except Exception:
            pass