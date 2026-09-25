import unittest
from email_analyzer.page_structure import inspect_structure
class FormTests(unittest.TestCase):
 def form(self,h,csp=None):return inspect_structure(h,'https://site.example/',csp)['forms'][0]
 def test_disabled_and_name(self):
  f=self.form('<form><input type=password name=p disabled><input type=password><input type=password name=q></form>')
  self.assertEqual(f['submittable_password_fields'],1);self.assertEqual(f['disabled_password_fields'],1)
 def test_fieldset_legend_exception(self):
  f=self.form('<form><fieldset disabled><legend><input type=password name=a></legend><input type=password name=b></fieldset></form>')
  self.assertEqual(f['submittable_password_fields'],1)
 def test_external_association(self):
  f=self.form('<form id=f></form><input form=f type=password name=p><button form=f formaction="http://other.example" formmethod=post>Send</button>')
  self.assertEqual(f['submittable_password_fields'],1);self.assertTrue(f['routes'][1]['external_host']);self.assertTrue(f['routes'][1]['insecure_http'])
 def test_reassigned_field(self):
  f=self.form('<form><input form=missing type=password name=p></form>');self.assertEqual(f['password_fields'],0)
 def test_csp_header(self):
  f=self.form('<form><input type=password name=p></form>',"form-action 'none'")
  self.assertTrue(f['native_submission_blocked']);self.assertEqual(f['submittable_password_fields'],1)
 def test_csp_meta(self):
  f=self.form('''<head><meta http-equiv="Content-Security-Policy" content="form-action 'none'"></head><body><form></form></body>''')
  self.assertTrue(f['native_submission_blocked'])
 def test_late_meta_and_js_not_guarantee(self):
  f=self.form('''<form onsubmit="return false"></form><meta http-equiv="Content-Security-Policy" content="form-action 'none'">''')
  self.assertFalse(f['native_submission_blocked'])
 def test_default_src_not_form_action(self):
  self.assertFalse(self.form('<form></form>',"default-src 'none'")['native_submission_blocked'])
 def test_dialog_override(self):
  f=self.form('<form method=dialog><button formmethod=post>Send</button></form>')
  self.assertTrue(f['routes'][0]['native_submission_blocked']);self.assertFalse(f['routes'][1]['native_submission_blocked'])
