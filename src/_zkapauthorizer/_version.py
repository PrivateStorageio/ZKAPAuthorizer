def get_version():
    """
    Return the version and revision of this package.

    Note: This only works when run from an tree generated
    by git-archive (such as a tarball from github) and returns
    ``("0+unknown", None)`` otherwise.
    """
    import re

    # This is what an unexpanded format marker starts with.
    # We write it with two strings here, so that it is not
    # interpreted by git.
    FORMAT_MARKER = "$" "Format"
    # This matches either an exact tag like `v0.1`
    # or a string like `v0.0-123-ga1b2c3d` as output by
    # git describe.
    DESCRIBE_RE = re.compile(
        r"^v(?P<tag>[\d.]+)(?:-(?P<number>\d+)-g(?P<short>[0-9a-f]+)|)$"
    )

    git_describe = "$Format:%(describe:match=v*)$"
    git_revision = "$Format:%H$"
    if git_revision.startswith(FORMAT_MARKER):
        git_revision = None
    if git_describe.startswith(FORMAT_MARKER):
        git_version = "0+unknown"
    else:
        import re

        matches = DESCRIBE_RE.match(git_describe)
        if matches:
            if matches.group("number") is not None:
                revision = git_revision or "unknown"
                git_version = "{tag}.{number}+git.{revision}".format(
                    revision=revision, **matches.groupdict()
                )
            else:
                git_version = matches.group("tag")
        else:
            git_version = "0+unknown"

    return git_version, git_revision


__version__, __revision__ = get_version()

del get_version

__all__ = ["__version__", "__revision__"]
