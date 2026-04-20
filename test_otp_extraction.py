import unittest

from otp import extract_verification_codes


class OtpExtractionTests(unittest.TestCase):
    def test_extracts_code_from_subject_and_body(self):
        subject = "42020 is your confirmation code"
        body = """
        Hi James,

        We got your request to create an account. Here's your confirmation code:

        42020

        Don't share this code with anyone.
        """
        result = extract_verification_codes(subject=subject, text_body=body)
        self.assertEqual(result["otp_digit"], "42020")

    def test_extracts_hyphenated_numeric_code(self):
        result = extract_verification_codes(
            text_body="Your verification code is 123-456. Do not share this code."
        )
        self.assertEqual(result["otp_digit"], "123456")

    def test_extracts_alphanumeric_code(self):
        result = extract_verification_codes(
            text_body="Use passcode AB12CD to finish signing in."
        )
        self.assertEqual(result["otp_mix"], "AB12CD")

    def test_ignores_plain_order_number_without_code_context(self):
        result = extract_verification_codes(
            subject="Order number 42020 shipped",
            text_body="Your order number 42020 has left the warehouse.",
        )
        self.assertIsNone(result["otp_digit"])

    def test_ignores_year_like_number_without_code_context(self):
        result = extract_verification_codes(
            subject="Welcome to 2026 planning",
            text_body="Our 2026 conference details are attached.",
        )
        self.assertIsNone(result["otp_digit"])

    def test_extracts_code_from_html_only(self):
        html = """
        <html><body>
        <p>Here is your security code:</p>
        <div><strong>998877</strong></div>
        <p>Do not share this code.</p>
        </body></html>
        """
        result = extract_verification_codes(html_body=html)
        self.assertEqual(result["otp_digit"], "998877")


if __name__ == "__main__":
    unittest.main()
