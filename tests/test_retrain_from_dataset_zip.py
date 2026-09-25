import io,json,tempfile,unittest,zipfile
from pathlib import Path
from tools.retrain_from_dataset_zip import prepare


class RetrainZipTests(unittest.TestCase):
    def make_zip(self, root, unsafe=False):
        metadata=[];inner_bytes=io.BytesIO()
        with zipfile.ZipFile(inner_bytes,'w') as inner:
            for split,index in (('train',1),('validation',2),('test',3)):
                for label in (0,1):
                    for copy in range(5):
                        stem=f'ko-email-{index:05d}-{label}-{copy}'
                        metadata.append({'id':stem,'label_id':label,'split':split,
                                         'scenario_id':f'{split}-{label}','urls':'[]',
                                         'from_address':'sender@example.org','reply_to':'sender@example.org'})
                        klass='phishing' if label else 'legitimate'
                        inner.writestr(f'eml/{split}/{klass}/{stem}.eml',f'Subject: {stem}\n\nbody {label} {copy}')
            if unsafe: inner.writestr('../escape.eml','bad')
        outer=root/'dataset.zip'
        with zipfile.ZipFile(outer,'w') as archive:
            archive.writestr('dataset/data.jsonl','\n'.join(json.dumps(x) for x in metadata))
            archive.writestr('dataset/_eml.zip',inner_bytes.getvalue())
        return outer

    def test_prepare_preserves_split_and_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);manifest,report=prepare(self.make_zip(root),root/'prepared')
            self.assertEqual(report['rows'],30)
            self.assertEqual(report['counts']['train_normal'],5)
            self.assertTrue((root/'prepared/test/phishing/ko-email-00003-1-0.eml').is_file())
            self.assertEqual(len(manifest.read_text(encoding='utf-8').splitlines()),30)
            first=json.loads(manifest.read_text(encoding='utf-8').splitlines()[0])
            self.assertEqual(first['analysis'],{})
            self.assertEqual(report['training_use'],'text_only')

    def test_synthetic_evidence_requires_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);manifest,report=prepare(self.make_zip(root),root/'prepared',True)
            first=json.loads(manifest.read_text(encoding='utf-8').splitlines()[0])
            self.assertIn('url_analysis',first['analysis'])
            self.assertEqual(report['training_use'],'synthetic_evidence_experiment')

    def test_rejects_unsafe_nested_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with self.assertRaises(ValueError): prepare(self.make_zip(root,unsafe=True),root/'prepared')


if __name__=='__main__':unittest.main()
