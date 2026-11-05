#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from typing import Final
from pathlib import Path

import semver

from list_crates import list_crates, Crate

TOPDIR: Final = Path(sys.argv[0]).absolute().parent.parent


CRATES_BY_NAME: Final[dict[str, Crate]] = {c.name: c for c in list_crates()}

PUBLISHED_CRATES: Final[tuple[Crate, ...]] = tuple(
    c for c in CRATES_BY_NAME.values() if c.publish
)


def get_changed_crates_to_publish(last_version: str) -> list[Crate]:
    names = subprocess.check_output(
        [f"{TOPDIR}/maint/changed-crates", "-v", f"arti-v{last_version}"],
        text=True,
        stderr=subprocess.DEVNULL,
    ).splitlines()
    crates = [CRATES_BY_NAME[n] for n in names]
    # changed-crates only returns crates that we publish
    for c in crates:
        assert c.publish, f"changed-crates returned non-publish crate {c.name}"
    return crates


def is_unstable_0x_tor_or_arti(crate: Crate) -> bool:
    if not (crate.name.startswith("tor-") or crate.name.startswith("arti-")):
        return False
    return crate.version.startswith("0.")


def main(last_version: str) -> None:
    print("## unstable 0.* tor-* and arti-*")
    print("")
    print("These are the version 0.* crates named tor-* and arti-*, that we publish.")
    print("They should all get a minor version bump, to the same version.")
    print("")

    # unstable (0.x) arti- and tor- crates get their minor version bumped
    # whether changed or not. They should all be at the same version.
    unstable_0x_tor_or_arti: Final[list[Crate]] = [
        c for c in PUBLISHED_CRATES if is_unstable_0x_tor_or_arti(c)
    ]
    for crate in unstable_0x_tor_or_arti:
        print(crate.name, crate.version)
    print()
    prev_unstable_version = unstable_0x_tor_or_arti[0].version
    next_unstable_version = semver.bump_minor(prev_unstable_version)
    for c in unstable_0x_tor_or_arti:
        assert c.version == prev_unstable_version, (
            f"crate {crate.name} unexpectedly has version {crate.version}"
            f" instead of {prev_unstable_version}"
        )
    print("to bump these:")
    print("")
    print(
        "for c in",
        " ".join((shlex.quote(c.name) for c in unstable_0x_tor_or_arti)),
        "; do",
    )
    print(f'  cargo set-version -p "$c" {shlex.quote(next_unstable_version)}')
    print("done")

    unstable_0x_tor_or_arti_names: Final[frozenset[str]] = frozenset(
        crate.name for crate in unstable_0x_tor_or_arti
    )

    print("")
    print("## other changed, published, packages to bump")

    changed_crates_to_publish: Final[tuple[Crate, ...]] = tuple(
        get_changed_crates_to_publish(last_version)
    )
    crates_left_to_bump: list[Crate] = [
        x
        for x in changed_crates_to_publish
        if x.name not in unstable_0x_tor_or_arti_names
    ]

    print("")
    print("See `doc/dev/Release.md` for guidelines on how to bump these:")
    print("")
    for crate in crates_left_to_bump:
        print(crate.name, crate.version)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="sort-bumps",
        description="list crates whose versions may need to be bumped",
    )
    parser.add_argument(
        "--from-version",
        required=True,
        help="arti semver version that we're bumping from",
    )
    args = parser.parse_args()
    main(args.from_version)
