import unittest
from unittest.mock import patch
from email.message import EmailMessage
from email_analyzer.homepage_comparison import compare_homepages
class HomepageTests(unittest.TestCase):
 def setUp(self):
  self.m=EmailMessage();self.m['From']='x@official.example'
  self.page={'status':'ok','requested_host':'other.example','hops':[{'host':'official.example'}],'structure':{'tag_counts':{'html':1,'form':1},'password_fields':1}}
  self.reg={'status':'ok','domains':[{'domain':'official.example','organization':'Org','role':'official','source':'review'}]}
 def run_case(self,registry,page):
  with patch('email_analyzer.homepage_comparison.load_registry',return_value=registry),patch('email_analyzer.homepage_comparison.analyze_pages',return_value={'pages':[page]}):
   return compare_homepages(self.m,{'pages':[self.page]},{'links':[]})
 def test_verified_comparison(self):
  r=self.run_case(self.reg,self.page);self.assertEqual(r['status'],'compared');self.assertEqual(r['comparisons'][0]['tag_count_similarity'],1)
 def test_unverified_not_promoted(self):
  r=self.run_case({'status':'ok','domains':[]},self.page);self.assertEqual(r['status'],'basic_only');self.assertFalse(r['references'][0]['verified'])
 def test_fetch_failure(self):
  self.assertEqual(self.run_case(self.reg,{'status':'error'})['status'],'basic_only')
 def test_redirect_loses_verification(self):
  page={**self.page,'hops':[{'host':'outside.example'}]}
  self.assertEqual(self.run_case(self.reg,page)['status'],'basic_only')
 def test_disabled(self):
  with patch('email_analyzer.homepage_comparison.analyze_pages') as fetch:
   self.assertEqual(compare_homepages(self.m,{}, {},disabled=True)['status'],'disabled');fetch.assert_not_called()
