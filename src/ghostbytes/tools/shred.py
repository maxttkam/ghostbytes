"""
shred.py

This module provides utilities for securely overwriting files,
replacing their name, deleting them, and overwriting unused
space on a mounted partition.

Supported overwriting methods are listed in crypto/config.py

The shredding operations are intended to make recovery of deleted
file contents more difficult. Their effectiveness depends on the
filesystem, storage medium, wear-leveling, hardware behaviour, etc.
"""

from errno import ENOSPC
from os import O_CREAT, O_EXCL, O_WRONLY
import os.path
import string
from secrets import choice
from psutil import disk_partitions

from ghostbytes.tools.rand import random
from ghostbytes.crypto.config import AVAIL_RANDOM_STR
from ghostbytes.error import chunk_size_invalid, file_not_found, invalid_pattern, \
    invalid_repeat, not_a_file, partition_not_found, shred_option_not_supported, \
    temporary_filename_unavailable, temporary_write_failed

GUTMANN_PATTERN = [
    b'random', b'random', b'random', b'random',
    b'\x55\x55\x55', b'\xaa\xaa\xaa', b'\x92\x49\x24',
    b'\x49\x24\x92', b'\x24\x92\x49', b'\x00\x00\x00',
    b'\x11\x11\x11', b'\x22\x22\x22', b'\x33\x33\x33',
    b'\x44\x44\x44', b'\x55\x55\x55', b'\x66\x66\x66',
    b'\x77\x77\x77', b'\x88\x88\x88', b'\x99\x99\x99',
    b'\xaa\xaa\xaa', b'\xbb\xbb\xbb', b'\xcc\xcc\xcc',
    b'\xdd\xdd\xdd', b'\xee\xee\xee', b'\xff\xff\xff',
    b'\x92\x49\x24', b'\x49\x24\x92', b'\x24\x92\x49',
    b'\x6d\xb6\xdb', b'\xb6\xdb\x6d', b'\xdb\x6d\xb6',
    b'random', b'random', b'random', b'random'
]

FILENAME_CHARS = string.ascii_letters + string.digits


def shred_file(
    filename,
    method,
    zeroise,
    delete,
    chunksize,
    random_func=AVAIL_RANDOM_STR[0],
    repeat=1
):
    """
    Overwrite and optionally delete a file

    Args:
        filename: path to target file
        method: overwrite methods:
            - ``"random"``
            - ``"zero"``
            - ``"one"``
            - ``"gutmann"``
        zeroise: whether to perform a final zero-byte overwrite (will add one more pass)
        delete: whether to rename and delete the file after shredding
        chunksize: maxium number of bytes written per operation
        random_func: random-data sources used by random overwrites.
        repeat: number of times to apply the selected methods.

    Raises:
        chunk_size_invalid: if ``chunksize`` is not positive
        invalid_repeat: if ``repeat`` is not a positive integer
        shred_option_not_supported: if ``method`` is unknown
    """
    if chunksize <= 0:
        raise chunk_size_invalid()
    if not isinstance(repeat, int) or repeat < 1:
        raise invalid_repeat()
    for _ in range(repeat):
        match method:
            case 'random':
                overwrite_random(filename, chunksize, random_func)
            case 'zero':
                overwrite_pattern(filename, b'\x00', chunksize, random_func)
            case 'one':
                overwrite_pattern(filename, b'\xff', chunksize, random_func)
            case 'gutmann':
                overwrite_gutmann(filename, chunksize, random_func)
            case _:
                raise shred_option_not_supported()

    if zeroise:
        overwrite_pattern(filename, b'\x00', chunksize, random_func)
    if delete:
        shred_filename(filename)


def shred_filename(filename):
    """
    Rename a file repeatedly with random names and delete it.

    Args:
        filename: path to target file

    Raises:
        file_not_found: if the path does not exist
        not_a_file: if the path is a directory (folder)
    """

    if not os.path.exists(filename):
        raise file_not_found()
    if not os.path.isfile(filename):
        raise not_a_file()
    directory, basename = os.path.split(filename)
    if not basename:
        raise not_a_file()
    if len(basename) == 1:
        os.remove(filename)
        return

    old_name = basename
    while True:
        new_name = _random_filename(len(old_name) - 1)
        joined = os.path.join(directory, new_name)
        old_path = os.path.join(directory, old_name)
        os.rename(old_path, joined)
        old_name = new_name

        if len(old_name) <= 1:
            break

    os.remove(joined)


def zeroise_filename(filename):
    """
    Rename a file repeatedly using zeroes and delete it

    Args:
        filename: path to target file

    Raises:
        file_not_found: if the path does not exist
        not_a_file: if the path is a directory (folder)
    """
    if not os.path.exists(filename):
        raise file_not_found()
    if not os.path.isfile(filename):
        raise not_a_file()
    directory, basename = os.path.split(filename)
    if not basename:
        raise not_a_file()
    if len(basename) == 1:
        os.remove(filename)
        return

    old_name = basename
    while True:
        new_name = '0' * (len(old_name) - 1)
        joined = os.path.join(directory, new_name)
        old_path = os.path.join(directory, old_name)
        os.rename(old_path, joined)
        old_name = new_name

        if len(old_name) <= 1:
            break

    os.remove(joined)


def overwrite_random(filename, chunksize, random_func):
    """
    Overwrite a file with random data

    Args:
        filename: path to file
        chunksize: maximum number of bytes written per operation
        random_func: random-data source

    Raises:
        chunk_size_invalid: if ``chunksize`` is not positive
        file_not_found: if the path does not exist
        not_a_file: if the path is a directory (folder)
    """
    if chunksize <= 0:
        raise chunk_size_invalid()
    if not os.path.exists(filename):
        raise file_not_found()
    if not os.path.isfile(filename):
        raise not_a_file()

    with open(filename, 'br+') as file:
        remaining = os.fstat(file.fileno()).st_size
        while remaining > 0:
            current_chunk_sz = min(chunksize, remaining)
            file.write(random(random_func, current_chunk_sz))
            remaining -= current_chunk_sz
        file.flush()
        os.fsync(file.fileno())


def overwrite_filename(filename):
    """
    Rename a file to a random filename

    Args:
        filename: path to target file
    """
    directory, basename = os.path.split(filename)

    old_name = basename
    new_name = _random_filename(len(old_name))

    joined = os.path.join(directory, new_name)

    os.rename(filename, joined)
    return joined


def overwrite_gutmann(filename, chunksize, random_func):
    """
    Overwrite a file using Gutmann pattern sequence

    Args:
        filename: path to target file
        chunksize: maximum number of bytes written per sequence
        random_func: random-data source used for random passes

    Raises:
        chunk_size_invalid: if ``chunksize`` is not positive
        file_not_found: if the path does not exist
        not_a_file: if the path is a directory (folder)
    """
    if chunksize <= 0:
        raise chunk_size_invalid()
    if not os.path.exists(filename):
        raise file_not_found()
    if not os.path.isfile(filename):
        raise not_a_file()

    for pattern in GUTMANN_PATTERN:
        overwrite_pattern(filename, pattern, chunksize, random_func)


def overwrite_pattern(filename, pattern, chunksize, random_func):
    """
    Overwrite a file repeatedly with a byte pattern

    The pattern is repeated until the entire existing file length has been overwritten.
    A special pattern ``b"random"`` delegates to :func:`overwrite_random`.

    Args:
        filename: path to target file
        pattern: byte pattern to write
        chunksize: maximum number of bytes written per operation
        random_func: random-data source

    Raises:
        chunk_size_invalid: if ``chunksize`` is not positive
        file_not_found: if the path does not exist
        not_a_file: if the path is a directory (folder)
        invalid_pattern: if ``pattern`` is empty
    """
    if chunksize <= 0:
        raise chunk_size_invalid()
    if not os.path.exists(filename):
        raise file_not_found()
    if not os.path.isfile(filename):
        raise not_a_file()
    if not pattern:
        raise invalid_pattern()
    if pattern == b"random":
        return overwrite_random(filename, chunksize, random_func)

    with open(filename, 'br+') as file:
        remaining = os.fstat(file.fileno()).st_size
        while remaining > 0:
            current_chunk_sz = min(chunksize, remaining)
            chunk = pattern * (current_chunk_sz // len(pattern)) + \
                pattern[:current_chunk_sz % len(pattern)]
            file.write(chunk)
            remaining -= current_chunk_sz
        file.flush()
        os.fsync(file.fileno())

    return None


def wipe_free_space(
        device,
        chunksize,
        zeroise,
        random_func=AVAIL_RANDOM_STR[0]):
    """
    Fill unused space on a mounted partition until it is exhausted.

    A temporary file is created on the target partition and filled with either zero or random data.
    Once the filesystem reports  ``ENOSPC``, smaller writes are attempted to consume remaining
    available spaces. The temporary file is then closed and removed.

    Args:
        device: Device identifier returned by :func:`psutil.disk_partitions`
        chunksize: maximum number of bytes written per operation
        zeroise: whether to write zero bytes instead of random data.
        random_func: random-data sources to see when ``zeroise`` is ``False``.

    Raises:
        chunk_size_invalid: if ``chunksize`` is not positive
        partition_not_found: if ``device`` is not a mounted partition
        temporary_file_unavailable: if a unique temporary filename cannot be created
        temporary_write_failed: if a write operation makes no progress.
        OSError: if a filesystem error other than ``ENOSPC`` occurs.
    """

    if not isinstance(chunksize, int) or chunksize <= 0:
        raise chunk_size_invalid()
    partition = _get_sdiskpart(device)
    if partition is None:
        raise partition_not_found()

    target = partition.mountpoint
    tmp_name = _random_filename(30)

    attempts = 1
    joined = os.path.join(target, tmp_name)
    while os.path.exists(joined) and attempts < 50:
        tmp_name = _random_filename(40)
        joined = os.path.join(target, tmp_name)
        attempts += 1

    if os.path.exists(joined):
        raise temporary_filename_unavailable()

    descriptor = None
    try:
        descriptor = os.open(joined, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        while True:
            try:
                chunk = b'\x00' * \
                    chunksize if zeroise else random(random_func, chunksize)
                _write_all(descriptor, chunk)
            except OSError as e:
                if e.errno == ENOSPC:
                    break
                raise e
        dynamic_chunksize = chunksize
        while dynamic_chunksize >= 1:
            try:
                chunk = b'\x00' * dynamic_chunksize if zeroise \
                    else random(random_func, dynamic_chunksize)
                _write_all(descriptor, chunk)
            except OSError as e:
                if e.errno == ENOSPC:
                    dynamic_chunksize //= 2
                else:
                    raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if os.path.exists(joined):
            os.remove(joined)


def _write_all(descriptor, data):
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise temporary_write_failed()
        offset += written


def _get_sdiskpart(device):
    partitions = disk_partitions(True)
    for partition in partitions:
        if partition.device == device:
            return partition
    return None


def _random_filename(length):
    if length > 0:
        return "".join(choice(FILENAME_CHARS) for _ in range(length))
    return ""
