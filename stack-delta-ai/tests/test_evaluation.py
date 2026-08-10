import unittest

from stack_delta.evaluation import binary_metrics, unsafe_approval_rate


class EvaluationTests(unittest.TestCase):
    def test_binary_metrics(self):
        result = binary_metrics([True, True, False, False], [True, False, True, False])
        self.assertEqual((result.true_positive, result.false_positive, result.true_negative, result.false_negative), (1, 1, 1, 1))
        self.assertEqual(result.f1, 0.5)

    def test_unsafe_approval_rate(self):
        self.assertEqual(unsafe_approval_rate(2, 10), 0.2)


if __name__ == "__main__":
    unittest.main()

