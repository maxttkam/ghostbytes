from os import PathLike
from subprocess import CompletedProcess
from typing import Union


PathValue = Union[str, bytes, PathLike[str], PathLike[bytes]]


# random.py
def random(algorithm: str, length: int) -> bytes: ...

def dd_random_to_file(
	is_secure: bool,
	outfile: PathValue,
	block_size: int,
	count: int,
) -> CompletedProcess[bytes]: ...


# benchmark.py
def benchmark(algorithm: str, length: int, rsa_keysize: int) -> tuple: ...

def benchmark_all(length: int, rsa_keysize: int) -> list: ...


# shred.py
def shred_file(
	filename: PathValue,
	method: str,
	zeroise: bool,
	delete: bool,
	chunk_size: int,
	random_func: str = ...,
	repeat: int = 1,
) -> None: ...

def shred_filename(filename: PathValue) -> None: ...

def zeroise_filename(filename: PathValue) -> None: ...

def overwrite_random(
	filename: PathValue,
	chunk_size: int,
	random_func: str,
) -> None: ...

def overwrite_filename(filename: PathValue) -> PathValue: ...

def overwrite_gutmann(
	filename: PathValue,
	chunk_size: int,
	random_func: str,
) -> None: ...

def overwrite_pattern(
	filename: PathValue,
	pattern: bytes,
	chunk_size: int,
	random_func: str,
) -> None: ...

def wipe_free_space(
	device: str,
	chunk_size: int,
	zeroise: bool,
	random_func: str = ...,
) -> None: ...
