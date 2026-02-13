"""Tests for the entropy scanner."""

import string

from gitsafe.scanner.entropy import extract_candidates, find_high_entropy, shannon_entropy


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char_repeated(self):
        # "aaaa" → entropy 0 (only one symbol)
        assert shannon_entropy("aaaa") == 0.0

    def test_two_equal_chars(self):
        # "ab" → entropy 1.0
        assert abs(shannon_entropy("ab") - 1.0) < 0.01

    def test_uniform_distribution(self):
        # All unique chars → max entropy for length
        s = string.ascii_lowercase[:16]  # 16 unique chars
        h = shannon_entropy(s)
        assert h > 3.9  # log2(16) = 4.0

    def test_hex_string(self):
        # Random-looking hex string
        h = shannon_entropy("a1b2c3d4e5f67890abcdef1234567890")
        assert h >= 3.5

    def test_base64_string(self):
        # Base64-encoded random bytes
        h = shannon_entropy("dGhpcyBpcyBhIHRlc3Qgc3RyaW5n")
        assert h >= 3.5

    def test_english_word(self):
        # English words have low entropy
        h = shannon_entropy("password")
        assert h < 3.5

    def test_known_entropy(self):
        # "abcd" has 4 symbols, each p=0.25, H = -4*(0.25*log2(0.25)) = 2.0
        assert abs(shannon_entropy("abcd") - 2.0) < 0.01


class TestCandidateExtraction:
    def test_basic_split(self):
        candidates = extract_candidates('key = "longValueHereForTesting"', min_length=10)
        assert any("longValueHereForTesting" in c for c in candidates)

    def test_min_length_filter(self):
        candidates = extract_candidates("a b c short", min_length=10)
        assert len(candidates) == 0

    def test_assignment_split(self):
        candidates = extract_candidates("TOKEN=abc123def456ghi789jkl", min_length=16)
        assert len(candidates) >= 1


class TestFindHighEntropy:
    def test_detects_random_hex(self):
        line = 'secret = "a1b2c3d4e5f67890abcdef1234567890"'
        hits = find_high_entropy(line, min_entropy=3.5, min_length=16)
        assert len(hits) >= 1

    def test_ignores_low_entropy(self):
        line = 'name = "aaaaaaaaaaaaaaaaaaaaaa"'
        hits = find_high_entropy(line, min_entropy=3.0, min_length=16)
        assert len(hits) == 0

    def test_respects_min_length(self):
        line = 'key = "short"'
        hits = find_high_entropy(line, min_entropy=2.0, min_length=16)
        assert len(hits) == 0
