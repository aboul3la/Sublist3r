import os
import subprocess
import sys
import tempfile
import textwrap
import unittest


class SubbruteImportTest(unittest.TestCase):
    def test_import_uses_bundled_subbrute_when_external_package_shadows_it(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as temp_dir:
            shadow_package = os.path.join(temp_dir, "subbrute")
            os.mkdir(shadow_package)
            with open(os.path.join(shadow_package, "__init__.py"), "w", encoding="utf-8") as handle:
                handle.write("# external package without a subbrute module\n")

            command = textwrap.dedent(
                """
                import os
                import sublist3r

                bundled = os.path.join(os.path.dirname(sublist3r.__file__), "subbrute", "subbrute.py")
                assert os.path.abspath(sublist3r.subbrute.__file__) == os.path.abspath(bundled)
                """
            )
            env = os.environ.copy()
            env["PYTHONPATH"] = repo_root
            result = subprocess.run(
                [sys.executable, "-c", command],
                cwd=temp_dir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
