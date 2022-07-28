# SPDX-FileCopyrightText: 2021 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
"""Helpers for file access."""
from pathlib import Path
from typing import Union

from .models import FileStore
from mora import config
from mora import exceptions


def get_directory(file_store: FileStore) -> Path:
    """Get the configured export directory.

    Args:
        file_store: The file store to get a path for.

    Raises:
        E_DIR_NOT_FOUND: If the configured directory does not exist.

    Returns:
        A Path object pointing to the directory.
    """
    settings = config.get_settings()
    # Convert file_store enum to Path
    if file_store == FileStore.EXPORTS:
        directory = Path(settings.query_export_dir)
    elif file_store == FileStore.INSIGHTS:
        # Use direct configuration if available, otherwise fallback to old default
        if settings.query_insight_dir:
            directory = Path(settings.query_insight_dir)
        else:
            directory = Path(settings.query_export_dir) / "json_reports"
    else:
        raise exceptions.ErrorCodes.E_UNKNOWN("Unknown file store!")

    if not directory.is_dir():
        exceptions.ErrorCodes.E_DIR_NOT_FOUND(directory=str(directory))

    return directory


def list_files(file_store: FileStore) -> set[str]:
    """Set export files.

    Args:
        file_store: The file store to list files for.

    Raises:
        E_DIR_NOT_FOUND: If the configured directory does not exist.

    Returns:
        Set of filenames.
    """
    directory = get_directory(file_store)
    dir_contents = directory.iterdir()
    files = filter(lambda file: file.is_file(), dir_contents)
    filenames = set(map(lambda file: file.name, files))
    return filenames


def save_file(file_store: FileStore, file_name: str, data: bytes, force: bool) -> None:
    """Save an export file with a given name.

    Args:
        file_store: The file store to save files in.
        file_name: Name of the export file.
        data: The file contents.
        force: Whether to override existing file.

    Raises:
        E_DIR_NOT_FOUND: If the configured directory does not exist.
        E_ALREADY_EXISTS: If the file already exists, and force is not set.

    Returns:
        None
    """
    directory = get_directory(file_store)
    file_path = directory / file_name
    # Protection against "../" in file_name, whatever path we get should be an
    # immediate child of the directory
    if file_path.parent != directory:
        exceptions.ErrorCodes.E_INVALID_INPUT(filename=file_name)

    if file_path.is_file() and not force:
        exceptions.ErrorCodes.E_ALREADY_EXISTS(filename=file_name)

    with file_path.open("wb") as f:
        f.write(data)


def load_file(
    file_store: FileStore, file_name: str, binary: bool = False
) -> Union[str, bytes]:
    """Load an export file with a given name.

    Args:
        file_store: The file store to load files from.
        file_name: Name of the export file.
        binary: Whether to load the file as binary or text.

    Raises:
        E_DIR_NOT_FOUND: If the configured directory does not exist.
        E_NOT_FOUND: If the file does not exist.

    Returns:
        The file contents as bytes
    """
    # Ensure that file exists in listing
    # This protects against paths containing "../"
    if file_name not in list_files(file_store):
        exceptions.ErrorCodes.E_NOT_FOUND(filename=file_name)

    mode = "rb" if binary else "r"
    directory = get_directory(file_store)
    file_path = directory / file_name
    with file_path.open(mode) as f:
        return f.read()
