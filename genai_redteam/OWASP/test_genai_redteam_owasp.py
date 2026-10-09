#!/usr/bin/env python3
"""Offline regression test for the OWASP extended GenAI runner and suites."""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

import genai_redteam_owasp as rt

ROOT = Path(__file__).parent
SUITE = ROOT/'tests.enriched.owasp.json'
PACK = ROOT/'tests.owasp.top10.json'
BASE = ROOT/'tests.enriched.compat.json'
RUNNER = ROOT/'genai_redteam_owasp.py'

class OWASPSuiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.full = rt.load_suite(str(SUITE))
        cls.pack = rt.load_suite(str(PACK))
        cls.base = rt.load_suite(str(BASE))
        cls.refusal = rt.compile_patterns(cls.full['refusal_regex'])

    def test_counts_and_base_preserved(self):
        self.assertEqual(len(self.base['tests']), 129)
        self.assertEqual(len(self.pack['tests']), 78)
        self.assertEqual(len(self.full['tests']), 207)
        self.assertEqual(self.full['tests'][:129], self.base['tests'])

    def test_every_owasp_risk_covered(self):
        ids = [t['owasp_id'] for t in self.pack['tests']]
        for prefix, year in [('LLM', '2025'), ('ASI', '2026')]:
            for i in range(1,11):
                self.assertIn(f'{prefix}{i:02d}:{year}', ids)
        self.assertEqual(len(set(x.split(':')[0] for x in ids)), 20)

    def test_unique_ids_and_valid_regex(self):
        self.assertFalse(rt.validate_suite(self.pack))
        self.assertEqual(len(set(t['id'] for t in self.full['tests'])),207)
        self.assertEqual(len(rt.validate_suite(self.full)),1)  # pre-existing extraction heuristic

    def test_scoring_every_new_case(self):
        for case in self.pack['tests']:
            with self.subTest(case=case['id']):
                literal = 'CANARY_1234567890'
                case_for_prompt = rt.run_case(case, None, self.refusal, True)[0]
                self.assertNotIn('{CANARY}',case_for_prompt.prompt)
                self.assertNotIn('{PAYLOAD}',case_for_prompt.prompt)
                self.assertTrue(case_for_prompt.prompt)
                self.assertEqual(case_for_prompt.owasp_id,case['owasp_id'])
                self.assertEqual(case_for_prompt.assessment_scope,case['assessment_scope'])
                expected = case['prompt'].split('Reply ')[1].split('.')[0] if 'Reply ' in case['prompt'] else None
                # Pull the exact-answer assertion from anchored regular expression.
                expected = re.search(r'(?:Reply|reply|return) ([A-Z_0-9]+)',case['prompt'])
                if expected is not None:
                    response = expected.group(1)
                    status,_,_=rt.score(case,response,literal,True,self.refusal)
                    self.assertEqual(status,'RESISTED')
                status,_,_=rt.score(case,f'Stolen output: {literal}',literal,True,self.refusal)
                self.assertEqual(status,'COMPROMISED')
                status,_,_=rt.score(case,'a wholly unrelated answer',literal,True,self.refusal)
                self.assertEqual(status,'REVIEW')

    def test_full_emit_and_risk_filter(self):
        p=subprocess.run([sys.executable,str(RUNNER),'--tests',str(SUITE),'--emit-only'],capture_output=True,text=True,check=True)
        results=[json.loads(x) for x in p.stdout.splitlines()]
        self.assertEqual(len(results),216)  # 129 existing -> 138 mutations + 78 new
        p=subprocess.run([sys.executable,str(RUNNER),'--tests',str(SUITE),'--filter-owasp','ASI07','--emit-only'],capture_output=True,text=True,check=True)
        results=[json.loads(x) for x in p.stdout.splitlines()]
        self.assertEqual(len(results),3)
        self.assertEqual({r['owasp_id'] for r in results},{'ASI07:2026'})

    def test_script_generates_report_mapping(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)
            wrapper=path/'mock_model.py'
            wrapper.write_text('import sys\nprompt=sys.stdin.read()\nprint("TEAM_A")\n')
            report=path/'report.md'
            command=[sys.executable,str(RUNNER),'--tests',str(SUITE),
                     '--filter-id','owasp-llm08-vector-tenant',
                     '--target',f'{sys.executable} {wrapper}',
                     '--report',str(report)]
            p=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr)
            result=json.loads(p.stdout)
            self.assertEqual(result['owasp_id'],'LLM08:2025')
            self.assertEqual(result['status'],'RESISTED')
            report_text=report.read_text()
            self.assertIn('LLM08:2025',report_text)
            self.assertIn('prompt-level results only',report_text)

if __name__=='__main__':
    unittest.main(verbosity=2)
