"""Tests for scripts.lib.wrappers.kubectl"""
__import__("pkg_resources").declare_namespace("google")

from google.apputils import basetest
import kubectl


class KubectlTests(basetest.TestCase):

    def test_kubectl_runs_at_all(self):
        self.assertRegexpMatches(
            kubectl.check_output(["version", "--client", "--short"]),
            r"^Client Version: ")


if __name__ == '__main__':
    basetest.main()
