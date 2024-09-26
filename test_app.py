import mock_test
import unittest

class TestHelloWorld(unittest.TestCase):

    def test_greeting_message(self):
        greeting = 'Teste pipeline devops - lambda auth!'
        print(greeting)
        self.assertEqual(mock_test.greet(), greeting)


if __name__ == '__main__':
    unittest.main()
