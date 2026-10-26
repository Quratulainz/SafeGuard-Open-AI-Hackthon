import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
from engine import assess,safe_url,Extractor
class TestEngine(unittest.TestCase):
 def test_fee(self):
  r=assess('Pay registration fee within 24 hours')
  self.assertEqual(r['risk_level'],'elevated')
  self.assertEqual(len(r['verified_facts']),0)
 def test_no_fake_verified(self):
  self.assertIn('NOT independently verified',assess('hello')['status'])
 def test_private_blocked(self):
  for u in ['http://127.0.0.1','http://localhost','file:///etc/passwd','http://192.168.1.1','https://user:pw@example.com']:
   with self.subTest(u=u),self.assertRaises(ValueError):safe_url(u)
 def test_html_parser(self):
  p=Extractor();p.feed('<title>Job</title><script>evil</script><p>registration fee</p>');self.assertIn('registration fee',' '.join(p.text));self.assertNotIn('evil',' '.join(p.text))
if __name__=='__main__':unittest.main()
