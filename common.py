import requests


def iter_values(obj) -> list[str]:
    """Return a list of all non-null values in a dict. Omits keys entirely.
    TODO: Rename this function lol."""

    def _deep_extract(obj):
        """Helper method to perform a deep extract of all values in a dict."""
        if isinstance(obj, dict):
            for value in obj.values():
                yield from iter_values(value)
        elif isinstance(obj, list):
            for item in obj:
                yield from iter_values(item)
        else:
            yield obj

    # Return non-null items.
    return [str(e) for e in list(_deep_extract(obj)) if e]


def cache_file_from_url(url, target_path):
    """
    Download hte contents of some URL to a target path.
    """
    resp = requests.get(url)
    resp.raise_for_status()

    with open(target_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)
