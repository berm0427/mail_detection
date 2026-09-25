import unittest
from email_analyzer.decision import combine_evidence
from email_analyzer.page_structure import inspect_structure
class HtmlDecisionTests(unittest.TestCase):
 def result(self,html,original='inconclusive'):
  return {'verdict':original,'risk_score':0,'rule_result':{'risk_score':0,'auth_summary':{'incomplete':True}},'engine_results':{'numerical_features':{'status':'ok'},'ml_baseline':{'status':'ok','score':.1},'razor':{'status':'ok','details':{'catalogue_match':False}}},'page_analysis':{'status':'complete','pages':[{'status':'ok','structure':inspect_structure(html,'https://site.example/')} ]}}
 def test_active_external(self):
  r=self.result('<form method=post action="https://other.example"><input type=password name=p></form>')
  self.assertEqual(combine_evidence(r)['verdict'],'suspicious');self.assertEqual(r['risk_score'],0)
 def test_disabled(self):
  r=self.result('<form action="http://other.example"><input type=password name=p disabled></form>')
  self.assertEqual(combine_evidence(r)['verdict'],'no_signal')
 def test_csp(self):
  r=self.result('''<head><meta http-equiv="Content-Security-Policy" content="form-action 'none'"></head><body><form action="http://other.example"><input type=password name=p></form></body>''')
  self.assertEqual(combine_evidence(r)['verdict'],'no_signal')
 def test_same_host_post(self):
  self.assertEqual(combine_evidence(self.result('<form method=post><input type=password name=p></form>'))['verdict'],'no_signal')
 def test_failed_page(self):
  r=self.result('');r['page_analysis']['pages']=[{'status':'error'}]
  self.assertEqual(combine_evidence(r)['verdict'],'no_signal')
 def test_preserve_danger_error(self):
  for v in ('dangerous','error'):
   self.assertEqual(combine_evidence(self.result('<form action="http://other.example"><input type=password name=p></form>',v))['verdict'],v)
 def test_override(self):
  r=self.result('<form method=post><input type=password name=p><button formaction="https://other.example">Send</button></form>')
  self.assertEqual(combine_evidence(r)['verdict'],'suspicious')
 def test_get(self):
  self.assertEqual(combine_evidence(self.result('<form><input type=password name=p></form>'))['verdict'],'suspicious')

 def test_optional_failure_does_not_hide_completed_inspection(self):
  r=self.result('<html><body>Test</body></html>')
  r['engine_results']['ml_baseline']={'status':'error'}
  d=combine_evidence(r)
  self.assertEqual(d['verdict'],'no_signal')
  self.assertEqual(d['unavailable_engines'],[])
 def test_partial_collection_keeps_insufficient_status(self):
  r=self.result('<html></html>');r['page_analysis']['omitted']=1
  self.assertEqual(combine_evidence(r)['verdict'],'no_signal')
