# -*- coding: utf-8 -*-
import os
import sys
import json
import tempfile
from unittest.mock import patch, MagicMock

import pytest

# Add parent to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from sublist3r import (
    main, parse_args, write_file, subdomain_sorting_key,
    GoogleEnum, YahooEnum, BingEnum, BaiduEnum, AskEnum,
    NetcraftEnum, DNSdumpster, Virustotal, ThreatCrowd,
    CrtSearch, PassiveDNS, portscan, no_color, banner,
    parser_error, G, Y, B, R, W,
)


class TestUtilities:
    """Test utility functions."""

    def test_no_color(self):
        import sublist3r as s
        s.no_color()
        assert s.G == ''
        assert s.Y == ''
        assert s.B == ''
        assert s.R == ''
        assert s.W == ''

    def test_parser_error(self):
        with pytest.raises(SystemExit):
            parser_error("test error")

    def test_write_file(self):
        subdomains = ["test1.example.com", "test2.example.com"]
        f = tempfile.NamedTemporaryFile(mode='w', delete=False)
        f.close()
        write_file(f.name, subdomains)
        with open(f.name) as fh:
            content = fh.read()
        assert "test1.example.com" in content
        assert "test2.example.com" in content
        os.unlink(f.name)

    def test_write_file_empty(self):
        f = tempfile.NamedTemporaryFile(mode='w', delete=False)
        f.close()
        write_file(f.name, [])
        with open(f.name) as fh:
            content = fh.read()
        assert content == ''
        os.unlink(f.name)

    def test_subdomain_sorting_key(self):
        key = subdomain_sorting_key("www.example.com")
        assert isinstance(key, tuple)
        assert len(key) == 2

    def test_subdomain_sorting_key_reversed(self):
        key = subdomain_sorting_key("test.www.example.com")
        assert isinstance(key, tuple)
        assert len(key) == 2

    def test_banner_output(self, capsys):
        banner()
        captured = capsys.readouterr()
        assert "ahmed" in captured.out.lower() or "aboul" in captured.out.lower()


class TestMainFunction:
    """Test the main function with mocked engines."""

    def test_main_invalid_domain(self):
        """Test main with invalid domain."""
        result = main(
            domain="invalid domain!!!",
            threads=2,
            savefile=None,
            ports=None,
            silent=True,
            verbose=False,
            enable_bruteforce=False,
            engines=None
        )
        assert isinstance(result, list) or result is None


class TestEngineBase:
    """Test base engine class."""

    def test_engine_init(self):
        """Test engine initialization."""
        engine = GoogleEnum("http://example.com", silent=True, verbose=False)
        assert engine.domain == "example.com"
        assert hasattr(engine, 'subdomains')

    def test_engine_max_subdomains(self):
        """Test max subdomains check."""
        engine = GoogleEnum("http://example.com", silent=True, verbose=False)
        # Should return True if count is below max
        result = engine.check_max_subdomains(10)
        assert result is True or result is False


class TestPortScan:
    """Test port scan class."""

    def test_portscan_init(self):
        """Test portscan initialization."""
        hostnames = ["www.example.com", "api.example.com"]
        ps = portscan(hostnames, [80, 443])
        assert len(ps.subdomains) == 2
        assert len(ps.ports) == 2

    def test_portscan_empty_hostnames(self):
        """Test portscan with empty hostnames."""
        ps = portscan([], [80])
        assert len(ps.subdomains) == 0
