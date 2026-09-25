import unittest

import numpy as np

from email_analyzer.train_html_pair_ml import select_threshold


class TrainHtmlPairMLTests(unittest.TestCase):
    def test_threshold_respects_false_positive_limit(self):
        labels = np.asarray([0, 0, 0, 0, 1, 1, 1, 1])
        scores = np.asarray([0.1, 0.2, 0.3, 0.6, 0.65, 0.7, 0.9, 0.95])
        threshold, observed = select_threshold(labels, scores, max_fpr=0.10, min_recall=0.65)
        self.assertGreaterEqual(threshold, 0.65)
        self.assertLessEqual(observed['fpr'], 0.10)
        self.assertGreaterEqual(observed['recall'], 0.65)


if __name__ == '__main__':
    unittest.main()
