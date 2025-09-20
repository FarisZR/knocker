#!/usr/bin/env python3
import sys, types, os
import pytest
from src import fw_integration as firewall

def test_shadowed_firewall_module_does_not_crash_and_reports_reason():
    # Simulate a local 'firewall' module shadowing the system package.
    fake = types.ModuleType('firewall')
    # Point the fake module file into the project so fw_integration detects shadowing.
    fake.__file__ = os.path.join(os.path.dirname(firewall.__file__), 'firewall.py')
    sys.modules['firewall'] = fake

    try:
        # Reset cached state so availability check runs fresh.
        firewall._firewalld_available = None
        firewall._fw = None

        status = firewall.get_firewall_status()
        assert isinstance(status, dict)
        # When shadowed, availability should be False and reason should indicate shadowing.
        assert not status.get('available', False)
        reason = status.get('reason', '')
        assert 'SHADOWED' in reason or reason in (
            'SHADOWED_PREIMPORT', 'SHADOWED_IMPORT', 'SHADOWED_NO_SPEC'
        )
    finally:
        # Cleanup injected module and cached state
        try:
            del sys.modules['firewall']
        except KeyError:
            pass
        firewall._firewalld_available = None
        firewall._fw = None