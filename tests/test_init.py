import pytest
from cwe_calculator import palindrome

# TODO Replace with tests for your modules.
def test_palindrome():
    assert palindrome("racecar")
    assert not palindrome("vroom")
    assert palindrome("abba")
    assert palindrome("zzz")
    assert not palindrome("abcdef")
