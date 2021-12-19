# This autograder script leverages the 'grade' package, which has command-line utilities
# to run the tests, assign scores, and print results. We're calling internal APIs
# instead and custom-printing the output. If you need output in a more specific format,
# such as for GradeScope, the grade command-line has output options in JSON (claimed
# compatible with GradeScope) and Markdown.

# Also, note that we're running mypy here and assigning it one point. Again, we're running
# mypy using its internal APIs rather than from the command-line. We could ostensibly do
# something more invasive, like calling `make lint`, which also does pylint and checks
# indentation with black, and would normally be required if you were submitting a PR to
# the "real" ElectionGuard repository. Probably unnecessary for pedagogic purposes.

# https://github.com/thoward27/grade

import time
import unittest
from datetime import datetime
from io import StringIO
from typing import List, Dict, Union

import mypy.main
from grade.result import Result
from grade.runners import GradedRunner

from electionguard.logs import log_file_only

good_mark = "✅ "
fail_mark = "❌ "
blank_line_header = "│"  # unicode: "BOX DRAWINGS LIGHT VERTICAL"

divider_line = "├" + "─" * 78
start_divider_line = "┌" + "─" * 78
end_divider_line = "└" + "─" * 78


def print_score_line(category: str, points: int, max_points: int) -> None:
    print(
        "%s %-65s: %2d/%2d %s"
        % (
            blank_line_header,
            category,
            points,
            max_points,
            good_mark if points == max_points else fail_mark,
        )
    )


def print_start_line() -> None:
    print(start_divider_line)


def print_end_line() -> None:
    print(end_divider_line)


def print_divider_line() -> None:
    print(divider_line)


# suppresses all logging to stdout; logs instead go to a file: electionguard.log
log_file_only()

print(
    "Autograder: starting at "
    + str(datetime.utcnow().replace(microsecond=0).isoformat())
)
print()
print("Autograder: running mypy")
mypy_stdout = StringIO()
mypy_stderr = StringIO()
mypy.main.main(
    script_path=".",
    stdout=mypy_stdout,
    stderr=mypy_stderr,
    args=["src", "stubs", "tests"],
)
output_lines = mypy_stdout.getvalue().splitlines()
mypy_success = len(output_lines) == 1 and output_lines[0].startswith("Success:")
mypy_points = 1 if mypy_success else 0
mypy_maxpoints = 1
mypy_str = "Mypy, " + "no errors" if mypy_success else "errors found"
print(mypy_str)
print()

print("Autograder: running unit tests")
start_time = time.perf_counter()
suite = unittest.defaultTestLoader.discover(start_dir=".", pattern="test*")
results: Result = GradedRunner(visibility="visible").run(suite)
end_time = time.perf_counter()

print()
print_start_line()

all_tests: List[Dict[str, Union[str, int]]] = results.data["tests"]
relevant_tests = sorted(
    [x for x in all_tests if int(x["max_score"]) > 0], key=lambda x: x["name"]
)

score_sum: Dict[str, int] = {}
score_max_sum: Dict[str, int] = {}

prev_test_part = ""
for t in relevant_tests:
    name = str(t["name"])
    score = int(t["score"])
    max_score = int(t["max_score"])
    test_part = name.split(".")[0]
    if prev_test_part != test_part:
        if prev_test_part != "":
            print_divider_line()
        prev_test_part = test_part

    print_score_line(name, score, max_score)
    if test_part not in score_sum:
        score_sum[test_part] = score
        score_max_sum[test_part] = max_score
    else:
        score_sum[test_part] += score
        score_max_sum[test_part] += max_score

print_divider_line()
print_score_line(mypy_str, mypy_points, mypy_maxpoints)
for k in sorted(score_sum.keys()):
    print_score_line(f"Subtotal: {k}", score_sum[k], score_max_sum[k])
print_divider_line()

total_score = sum(score_sum.values()) + mypy_points
total_max_score = sum(score_max_sum.values()) + mypy_maxpoints
print_score_line("TOTALS", total_score, total_max_score)
print_end_line()

print()
print("Running time: %.3f seconds" % (end_time - start_time))

if total_score == total_max_score:
    # successful exit tells the CI system to give us a green checkmark
    exit(0)
else:
    # unsuccessful exit tells the CI system to give us a red X
    print("To see full output from the unit tests, run `make test`.")
    exit(1)
