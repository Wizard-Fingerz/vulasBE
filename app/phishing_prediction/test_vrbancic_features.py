"""
Tests for the lexical half of vrbancic_features.py -- the 111-feature
extractor feeding the resurrected phishing RandomForestClassifier.

Deliberately split from tests.py (which covers the heuristic detector and
the HTTP view) so these can run with zero network access: everything here
exercises extract_lexical_features()/segment_url(), never
extract_network_features(). Django's test runner picks up any
test*.py module, so this file needs no special registration.

Two of these are direct regression tests for real bugs found while
validating the resurrected model against dataset_full.csv (the public
dataset the model was trained on): well-known, obviously-legitimate sites
like https://github.com and https://www.google.com were being scored as
"Phishing" by the model, and both bugs traced back to lexical feature
encoding mismatches against the training data's own conventions, not to
the model itself. See segment_url()'s and extract_lexical_features()'s
docstrings/comments for the full data-driven justification.
"""
from django.test import SimpleTestCase

from .vrbancic_features import (
    FEATURE_ORDER,
    extract_lexical_features,
    segment_url,
    to_feature_vector,
)


class FeatureOrderTests(SimpleTestCase):
    def test_feature_order_has_111_unique_names(self):
        self.assertEqual(len(FEATURE_ORDER), 111)
        self.assertEqual(len(set(FEATURE_ORDER)), 111)

    def test_to_feature_vector_matches_order(self):
        features = {name: i for i, name in enumerate(FEATURE_ORDER)}
        vector = to_feature_vector(features)
        self.assertEqual(vector, list(range(111)))


class SegmentUrlTests(SimpleTestCase):
    def test_root_url_has_no_directory_or_file(self):
        domain, directory, file_part, params = segment_url('https://github.com')
        self.assertEqual(domain, 'github.com')
        self.assertIsNone(directory)
        self.assertIsNone(file_part)

    def test_root_url_with_trailing_slash_has_no_directory_or_file(self):
        domain, directory, file_part, params = segment_url('https://github.com/')
        self.assertIsNone(directory)
        self.assertIsNone(file_part)

    def test_single_segment_path_splits_into_directory_and_file(self):
        domain, directory, file_part, params = segment_url('https://example.com/index.html')
        self.assertEqual(directory, '/')
        self.assertEqual(file_part, 'index.html')

    def test_multi_segment_path_splits_on_last_slash(self):
        domain, directory, file_part, params = segment_url('https://example.com/a/b/c.html')
        self.assertEqual(directory, '/a/b/')
        self.assertEqual(file_part, 'c.html')

    def test_query_string_captured_as_params(self):
        _, _, _, params = segment_url('https://example.com/search?q=test&page=2')
        self.assertEqual(params, 'q=test&page=2')


class LexicalFeatureRegressionTests(SimpleTestCase):
    """
    Regression coverage for the two bugs found while comparing the
    resurrected model's predictions on well-known legitimate sites against
    the feature-value distributions in dataset_full.csv.
    """

    def test_root_url_directory_and_file_features_are_minus_one(self):
        # Bug 1: a root URL like "https://github.com" has no path at all.
        # The original dataset encodes "component doesn't exist" as -1
        # across every directory_*/file_* feature -- confirmed empirically
        # (~54% of all 88,647 training rows have directory_length == -1,
        # and it's the model's single most important feature). This
        # extractor used to return 0 (measuring an "empty" directory)
        # instead of -1 (recording "no directory"), which alone was enough
        # to push root-URL sites toward "Phishing".
        features = extract_lexical_features('https://github.com')
        self.assertEqual(features['directory_length'], -1)
        self.assertEqual(features['file_length'], -1)
        for name in ['qty_slash_directory', 'qty_dot_directory', 'qty_space_directory']:
            self.assertEqual(features[name], -1, name)
        for name in ['qty_slash_file', 'qty_dot_file', 'qty_at_file']:
            self.assertEqual(features[name], -1, name)

    def test_path_present_directory_and_file_features_are_not_sentinel(self):
        features = extract_lexical_features('https://example.com/a/b.html')
        self.assertEqual(features['directory_length'], 3)  # "/a/"
        self.assertEqual(features['file_length'], 6)  # "b.html"
        self.assertNotEqual(features['directory_length'], -1)

    def test_url_features_exclude_the_scheme(self):
        # Bug 2: length_url/qty_*_url are measured on the URL with its
        # "http://"/"https://" prefix stripped off -- confirmed
        # empirically (80% of the dataset's "Normal" class has
        # qty_slash_url == 0, and length_url has a minimum of 4, both
        # impossible if a scheme were included, since "https://" alone is
        # 8 characters and contributes 2 slashes). Measuring the raw URL
        # instead systematically inflated these for every top-level site.
        features = extract_lexical_features('https://github.com')
        self.assertEqual(features['length_url'], len('github.com'))
        self.assertEqual(features['qty_slash_url'], 0)

    def test_url_features_still_count_path_slashes_after_scheme_strip(self):
        features = extract_lexical_features('https://example.com/a/b/c')
        self.assertEqual(features['length_url'], len('example.com/a/b/c'))
        self.assertEqual(features['qty_slash_url'], 3)

    def test_scheme_stripping_does_not_touch_domain_or_directory_features(self):
        # domain_length/directory_length are computed from urlparse's
        # netloc/path, which never include the scheme in the first place --
        # only the raw-url-level features needed the fix.
        features = extract_lexical_features('https://example.com/a/b.html')
        self.assertEqual(features['domain_length'], len('example.com'))


class ParamsSentinelTests(SimpleTestCase):
    def test_no_query_string_uses_minus_one_sentinel(self):
        features = extract_lexical_features('https://example.com/page')
        self.assertEqual(features['qty_params'], -1)
        self.assertEqual(features['tld_present_params'], -1)

    def test_query_string_present_is_counted(self):
        features = extract_lexical_features('https://example.com/page?a=1&b=2')
        self.assertEqual(features['qty_params'], 2)


class MiscLexicalFeatureTests(SimpleTestCase):
    def test_ip_literal_host_is_flagged(self):
        features = extract_lexical_features('http://192.168.1.5/login.php')
        self.assertEqual(features['domain_in_ip'], 1)

    def test_normal_hostname_is_not_flagged_as_ip(self):
        features = extract_lexical_features('https://example.com')
        self.assertEqual(features['domain_in_ip'], 0)

    def test_email_in_url_detected(self):
        features = extract_lexical_features('https://example.com/?user=someone@example.com')
        self.assertEqual(features['email_in_url'], 1)

    def test_known_shortener_flagged(self):
        features = extract_lexical_features('https://bit.ly/3xyz')
        self.assertEqual(features['url_shortened'], 1)

    def test_ordinary_domain_not_flagged_as_shortener(self):
        features = extract_lexical_features('https://example.com/3xyz')
        self.assertEqual(features['url_shortened'], 0)
