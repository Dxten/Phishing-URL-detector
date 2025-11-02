import unittest
from backend.algorithms import levenshtein_distance, jaccard_similarity

class TestAlgorithms(unittest.TestCase):
    def test_levenshtein_distance_same_strings(self):
        self.assertEqual(levenshtein_distance("test", "test"), 0)
    
    def test_levenshtein_distance_different_strings(self):
        self.assertEqual(levenshtein_distance("kitten", "sitting"), 3)
    
    def test_levenshtein_distance_empty_string(self):
        self.assertEqual(levenshtein_distance("", "abc"), 3)
        self.assertEqual(levenshtein_distance("abc", ""), 3)
    
    def test_jaccard_similarity_identical_sets(self):
        set1 = set(["a", "b", "c"])
        set2 = set(["a", "b", "c"])
        self.assertEqual(jaccard_similarity(set1, set2), 1.0)
    
    def test_jaccard_similarity_no_overlap(self):
        set1 = set(["a", "b", "c"])
        set2 = set(["d", "e", "f"])
        self.assertEqual(jaccard_similarity(set1, set2), 0.0)
    
    def test_jaccard_similarity_partial_overlap(self):
        set1 = set(["a", "b", "c"])
        set2 = set(["b", "c", "d"])
        self.assertEqual(jaccard_similarity(set1, set2), 0.5)

if __name__ == '__main__':
    unittest.main()