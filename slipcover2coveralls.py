#!/usr/bin/env python

from hashlib import md5
from json import dump, load
from sys import argv, stdin, stdout
from typing import Iterator, Union


def main(service_job_id, service_name) -> int:
    slipcover_data = load(stdin)
    digests = dict(digest_source_files(slipcover_data))
    dump(
        slipcover_to_coveralls(service_job_id, service_name, slipcover_data, digests),
        stdout,
    )
    return 0


def slipcover_to_coveralls(
    service_job_id: str, service_name: str, slipcover_data: dict, digests: dict
) -> dict:
    """
    Convert slipcover's coverage data format to coveralls' coverage data
    format.
    """
    # slipcover data looks like
    # {"files": {"filename": {"executed_lines": [ints], "missing_lines": [ints]}}}
    #
    # slipcover only measured covered/not-covered so there is no execution count information.
    # line numbers are 1-based

    # coveralls data looks like
    # {
    #   "service_job_id": "1234567890",
    #   "service_name": "travis-ci",
    #   "source_files": [
    #     {
    #       "name": "example.rb",
    #       "source_digest": "asdfasdf1234asfasdf2345",
    #       "coverage": [null, 1, null]
    #     },
    #     {
    #       "name": "lib/two.rb",
    #       "source_digest": "asdf1234asdfsdfggsfgd9423",
    #       "coverage": [null, 1, 0, null]
    #     }
    #   ]
    # }
    #
    # where each "coverage" list element corresponds to a source line number
    # of that element's index in the list + 1 and the values mean:
    #
    #  - null: not relevant
    #  - int: number of times executed
    return {
        "service_job_id": service_job_id,
        "service_name": service_name,
        "source_files": [
            _one_coveralls_entry(filename, digests[filename], coverage)
            for (filename, coverage) in slipcover_data["files"].items()
        ],
    }


def _one_coveralls_entry(filename: str, digest: str, slipcover_entry: dict) -> dict:
    return {
        "name": filename,
        "source_digest": digest,
        "coverage": _to_coveralls_coverage(
            set(slipcover_entry["executed_lines"]),
            set(slipcover_entry["missing_lines"]),
        ),
    }


def _to_coveralls_coverage(
    executed: set[int], missing: set[int]
) -> list[Union[int, None]]:
    max_line = max(max(executed, default=0), max(missing, default=0))
    # Start at line number 1 to match slipcover's 1-based numbering.  The
    # first result will land at index 0 in the result to match coveralls'
    # 0-based numbering.  End at maxline + 1 so we don't miss the last line.
    line_numbers = range(1, max_line + 2)
    return [
        0 if lineno in missing else 1 if lineno in executed else None
        for lineno in line_numbers
    ]


def digest_source_files(slipcover_data) -> Iterator[tuple[str, str]]:
    for filename in slipcover_data["files"]:
        digest = md5()
        with open(filename, "rb") as src:
            digest.update(src.read())
        yield (filename, digest.hexdigest())


if __name__ == "__main__":
    raise SystemExit(main(*argv[1:]))
