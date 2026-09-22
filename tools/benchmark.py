"""Run Ghostbytes benchmarks with colored terminal output."""

from __future__ import annotations

import argparse

from colorama import Fore, Style, init

from ghostbytes.crypto.config import (
    AVAIL_ALG,
    AVAIL_HASH_STR,
    AVAIL_RANDOM_STR,
    AVAIL_SIGN_ALG,
)
from ghostbytes.tools.benchmark import benchmark


init(autoreset=True)


def positive_int(value: str) -> int:
    """Parse a positive integer command-line argument."""
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def main() -> None:
    """Parse benchmark options and print results for every algorithm."""
    parser = argparse.ArgumentParser(description="Run Ghostbytes benchmarks")
    parser.add_argument(
        "-l",
        "--length",
        type=positive_int,
        default=32,
        help="benchmark input length in bytes",
    )
    parser.add_argument(
        "-r",
        "--rsa-keysize",
        type=positive_int,
        default=2048,
        help="RSA key size in bits",
    )
    args = parser.parse_args()

    print(Fore.CYAN + Style.BRIGHT + "Ghostbytes benchmark")
    print(Fore.WHITE + f"Input length: {args.length} bytes")
    print(Fore.WHITE + f"RSA key size: {args.rsa_keysize} bits")
    print()

    algorithms = (
        ("HASH ALGORITHMS", AVAIL_HASH_STR),
        ("CRYPTO ALGORITHMS", AVAIL_ALG),
        ("SIGNING ALGORITHMS", AVAIL_SIGN_ALG),
        ("RANDOM ALGORITHMS", AVAIL_RANDOM_STR),
    )

    for heading, available_algorithms in algorithms:
        print(Fore.CYAN + Style.BRIGHT + f"========== {heading} ==========")

        for algorithm in available_algorithms:
            try:
                result = benchmark(
                    algorithm,
                    args.length,
                    args.rsa_keysize,
                )

                if algorithm in AVAIL_ALG or algorithm in AVAIL_SIGN_ALG:
                    for benchmark_result in (*result[0], result[1]):
                        label, elapsed = benchmark_result
                        print(f"{Fore.YELLOW}{label:<24} {Fore.GREEN}{elapsed}")
                else:
                    label, elapsed = result
                    print(f"{Fore.YELLOW}{label:<24} {Fore.GREEN}{elapsed}")

            except Exception as error:  # pylint: disable=broad-exception-caught
                print(f"{Fore.YELLOW}{algorithm:<24} {Fore.RED}{error}")

        print()


if __name__ == "__main__":
    main()
