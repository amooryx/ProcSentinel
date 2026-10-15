import unittest

from runner import parse_csv


class ParseCsvTests(unittest.TestCase):
    def test_parses_quoted_commas_and_escaped_quotes(self):
        text = (
            "Volatility 3 Framework 2.26.0\n"
            "PID,ImageFileName,CommandLine\n"
            '42,cmd.exe,"cmd.exe /c echo one,two ""quoted"""\n'
        )

        self.assertEqual(
            parse_csv(text),
            [{
                "PID": "42",
                "ImageFileName": "cmd.exe",
                "CommandLine": 'cmd.exe /c echo one,two "quoted"',
            }],
        )

    def test_pads_short_rows_and_skips_rows_with_extra_fields(self):
        text = "PID,ImageFileName\n42,cmd.exe\n43\n44,broken,extra\n"

        self.assertEqual(
            parse_csv(text),
            [
                {"PID": "42", "ImageFileName": "cmd.exe"},
                {"PID": "43", "ImageFileName": ""},
            ],
        )

    def test_returns_empty_when_no_csv_header_is_found(self):
        self.assertEqual(parse_csv("Volatility 3 Framework output\nNo records\n"), [])


if __name__ == "__main__":
    unittest.main()
