import json
import subprocess
import sys
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path


class EvidenceTrainingTests(unittest.TestCase):
    def test_training_writes_only_a_gated_portable_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);rows=[]
            for split in ('train','validation','test'):
                for index in range(6):
                    for label in (0,1):
                        stem=f'{split}-{index}-{label}';message=EmailMessage()
                        message['From']='sender@example.org';message['To']='user@example.net'
                        message['Subject']=f'{"credential action" if label else "ordinary notice"} {stem}'
                        message.set_content(f'{"enter password at external site" if label else "meeting schedule information"} unique {stem}')
                        eml=root/f'{stem}.eml';eml.write_bytes(message.as_bytes())
                        result={'link_evidence':{'links':[{'risk_score':80 if label else 0}]},
                                'reference_evidence':{'official_link_mismatch_count':label},
                                'page_structure':{'summary':{'forms':label,'password_inputs':label,'external_actions':label}},
                                'attachments':[],'auth':{},'keyword_matches':[]}
                        result_path=root/f'{stem}.json';result_path.write_text(json.dumps(result),encoding='utf-8')
                        source={'analysis':result} if index == 0 else {'analysis_result':result_path.name}
                        rows.append({'eml':eml.name,**source,'label':label,'split':split,'group_id':stem})
            manifest=root/'manifest.jsonl'
            manifest.write_text('\n'.join(json.dumps(row) for row in rows),encoding='utf-8')
            output=root/'model.json'
            completed=subprocess.run([sys.executable,'-m','email_analyzer.train_evidence_ml',str(manifest),str(output),
                                      '--text-bins','64'],capture_output=True,text=True,timeout=30)
            self.assertEqual(completed.returncode,0,completed.stderr+completed.stdout)
            artifact=json.loads(output.read_text(encoding='utf-8'))
            self.assertTrue(artifact['validation_gate']['passed'])
            self.assertEqual(artifact['schema_version'],1)
            self.assertTrue(output.with_suffix('.metrics.json').is_file())

    def test_objective_only_model_has_no_text_dimensions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);rows=[]
            for split in ('train','validation','test'):
                for index in range(6):
                    for label in (0,1):
                        stem=f'{split}-{index}-{label}';message=EmailMessage()
                        message['Subject']=f'unique {stem}';message.set_content('neutral body')
                        eml=root/f'{stem}.eml';eml.write_bytes(message.as_bytes())
                        analysis={'url_analysis':{'total_urls':label,'risk_score':100*label,
                                                  'analyzed_urls':[{'risk_score':100}] if label else []}}
                        rows.append({'eml':eml.name,'analysis':analysis,'label':label,
                                     'split':split,'group_id':stem})
            manifest=root/'manifest.jsonl';manifest.write_text('\n'.join(json.dumps(r) for r in rows),encoding='utf-8')
            output=root/'model.json'
            completed=subprocess.run([sys.executable,'-m','email_analyzer.train_evidence_ml',str(manifest),str(output),
                                      '--objective-only'],capture_output=True,text=True,timeout=30)
            self.assertEqual(completed.returncode,0,completed.stderr+completed.stdout)
            artifact=json.loads(output.read_text(encoding='utf-8'))
            self.assertEqual(artifact['text_bins'],0)
            self.assertEqual(artifact['text_coef'],[])
            self.assertTrue(artifact['training_parameters']['objective_only'])


if __name__=='__main__':unittest.main()
