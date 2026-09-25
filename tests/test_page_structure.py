import unittest
from unittest.mock import patch,Mock
from email_analyzer.page_structure import inspect_structure,fetch_page,analyze_pages
class PageTests(unittest.TestCase):
 def test_http_error_has_status_code(self):
  response=Mock(status=404,headers={});pool=Mock();pool.urlopen.return_value=response
  with patch('socket.getaddrinfo',return_value=[(2,1,6,'',('8.8.8.8',443))]),patch('urllib3.HTTPSConnectionPool',return_value=pool):
   r=fetch_page('https://public.example/missing');self.assertEqual(r['reason'],'HTTP 404');self.assertEqual(r['status'],'http_error')
 def test_structure(self):
  r=inspect_structure('<form action="http://other.example/post"><input type="password"></form><script src="/x.js"></script><iframe></iframe>','https://site.example')
  self.assertEqual(r['password_fields'],1);self.assertTrue(r['forms'][0]['external_host']);self.assertTrue(r['forms'][0]['insecure_http']);self.assertEqual(r['iframe_count'],1)
 def test_internal_blocked(self):
  with patch('socket.getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',80))]):
   self.assertEqual(fetch_page('http://localhost')['status'],'blocked')
 def test_disabled_and_limit(self):
  with patch('email_analyzer.page_structure.fetch_page',return_value={'status':'ok'}) as f:
   self.assertEqual(analyze_pages(['https://a.example'],True)['status'],'disabled');f.assert_not_called()
   r=analyze_pages(['https://a.example','https://a.example','https://b.example'],limit=1)
   self.assertEqual(r['omitted'],1);self.assertEqual(f.call_count,1)
   self.assertEqual(r['duplicate_host_urls'],0)
 def test_different_paths_on_same_host_use_one_representative(self):
  with patch('email_analyzer.page_structure.fetch_page',return_value={'status':'ok'}) as f:
   r=analyze_pages(['https://track.example/a','https://track.example/b','https://other.example/'])
   self.assertEqual(f.call_count,2)
   self.assertEqual(r['duplicate_host_urls'],1)
   self.assertEqual(r['omitted'],0)
 def test_fetch_and_redirect_block(self):
  response=Mock(status=302,headers={'Location':'http://127.0.0.1/'})
  pool=Mock();pool.urlopen.return_value=response
  with patch('socket.getaddrinfo',side_effect=[[(2,1,6,'',('8.8.8.8',80))],[(2,1,6,'',('127.0.0.1',80))]]),patch('urllib3.HTTPConnectionPool',return_value=pool):
   self.assertEqual(fetch_page('http://public.example')['status'],'blocked')
   self.assertEqual(pool.urlopen.call_count,1)
 def test_html_response(self):
  response=Mock(status=200,headers={'Content-Type':'text/html'});response.read.return_value=b'<form><input type="password"></form>'
  pool=Mock();pool.urlopen.return_value=response
  with patch('socket.getaddrinfo',return_value=[(2,1,6,'',('8.8.8.8',443))]),patch('urllib3.HTTPSConnectionPool',return_value=pool) as factory:
   r=fetch_page('https://public.example/path');self.assertEqual(r['structure']['password_fields'],1)
   self.assertEqual(factory.call_args.kwargs['assert_hostname'],'public.example')
