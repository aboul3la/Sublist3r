# -*- coding: utf-8 -*-
# GPLv2 section 2(a) notice: new test file added 2026-11-06 for the Sublist3r
# input-domain case-normalization fix (enumratorBase self.domain = netloc.lower()).
#
# The test drives real product objects only. Engines receive the scheme-qualified
# domain that main() builds. The ThreatCrowd instance I/O boundary is replaced by
# returning a valid JSON document from the instance req() method; no process,
# thread, resolver, CLI or live engine scan runs.
import io
import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import sublist3r


def _engine_for(domain, answers):
    """Build a real ThreatCrowd instance with a stubbed instance-level req."""
    engine = sublist3r.ThreatCrowd(domain, silent=True, verbose=False)
    calls = []

    def fake_req(url):
        calls.append(url)
        return json.dumps({'subdomains': answers, 'response_code': '1'})

    engine.req = fake_req
    return engine, calls


class DomainNormalizationTest(unittest.TestCase):

    def test_01_uppercase_input_keeps_valid_answers(self):
        answers = ['mail.example.com', 'vpn.example.com', 'example.com',
                   'mail.example.com']
        engine, calls = _engine_for('http://EXAMPLE.COM', answers)
        found = engine.enumerate()
        self.assertEqual(1, len(calls))
        self.assertEqual(['mail.example.com', 'vpn.example.com'], found)

    def test_02_mixed_case_scheme_qualified_input_keeps_answers(self):
        answers = ['a.example.com', 'b.example.com']
        engine, calls = _engine_for('HTTP://ExAmPlE.CoM', answers)
        found = engine.enumerate()
        self.assertEqual(1, len(calls))
        self.assertEqual(answers, found)

    def test_03_lowercase_control_matches_other_spellings(self):
        answers = ['api.example.com', 'dev.example.com', 'www.example.com']
        for spelling in ('http://example.com', 'http://EXAMPLE.COM',
                         'HTTP://ExAmPlE.CoM'):
            engine, calls = _engine_for(spelling, answers)
            found = engine.enumerate()
            self.assertEqual(1, len(calls))
            self.assertEqual(answers, found)

    def test_04_multiple_answers_dedupe_and_root_filter(self):
        answers = ['api.example.com', 'www.example.com', 'example.com',
                   'api.example.com', 'dev.example.com', 'mail.example.com']
        engine, calls = _engine_for('http://Example.Com', answers)
        found = engine.enumerate()
        self.assertEqual(1, len(calls))
        self.assertEqual(['api.example.com', 'www.example.com',
                          'dev.example.com', 'mail.example.com'], found)
        self.assertNotIn('example.com', found)

    def test_05_sorted_results_persist_through_write_file_readback(self):
        answers = ['mail.example.com', 'api.example.com', 'www.example.com',
                   'vpn.example.com', 'dev.example.com']
        engine, calls = _engine_for('http://EXAMPLE.COM', answers)
        found = engine.enumerate()
        self.assertEqual(1, len(calls))
        self.assertEqual(5, len(found))
        ordered = sorted(found, key=sublist3r.subdomain_sorting_key)
        self.assertEqual(['www.example.com', 'api.example.com',
                          'dev.example.com', 'mail.example.com',
                          'vpn.example.com'], ordered)

        control, calls2 = _engine_for('http://example.com', answers)
        found2 = control.enumerate()
        self.assertEqual(1, len(calls2))
        self.assertEqual(ordered,
                         sorted(found2, key=sublist3r.subdomain_sorting_key))

        fd, path = tempfile.mkstemp(suffix='.txt')
        os.close(fd)
        try:
            sublist3r.write_file(path, ordered)
            handle = io.open(path, 'r', encoding='utf-8')
            try:
                text = handle.read()
            finally:
                handle.close()
            # Blank lines are the separate open issue #284 (text-mode
            # os.linesep on Windows); this test is not about line endings.
            lines = [line for line in text.splitlines() if line]
            self.assertEqual(ordered, lines)
        finally:
            os.remove(path)

    def test_06_request_url_uses_case_folded_domain(self):
        engine, calls = _engine_for('http://EXAMPLE.COM', ['mail.example.com'])
        found = engine.enumerate()
        self.assertEqual(['mail.example.com'], found)
        self.assertEqual(
            'https://www.threatcrowd.org/searchApi/v2/domain/report/'
            '?domain=example.com', calls[0])
        self.assertNotIn('EXAMPLE', calls[0])


if __name__ == '__main__':
    unittest.main()
