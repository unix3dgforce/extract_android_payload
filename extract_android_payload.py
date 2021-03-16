from __future__ import annotations

import bz2
import re
import sys
from argparse import ArgumentParser
from dataclasses import dataclass
from lzma import decompress, FORMAT_XZ
from pathlib import Path
from struct import unpack, calcsize
from typing import Union, IO
from hashlib import sha256

import loguru
from loguru import logger

from proto.update_metadata_pb2 import DeltaArchiveManifest, Signatures, PartitionUpdate, InstallOperation

MAGIC_NUMBER = 0x43724155
BLOCK_SIZE = 4096
MAJOR_PAYLOAD_VERSION = 2

config = {
    "handlers": [
        {
            "sink": sys.stdout,
            "format": "<lvl>{message}</lvl>",
            "level": "DEBUG",
            "enqueue": True
        },
    ],
}

logger.remove()
logger.configure(**config)


class PayloadError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

    def __repr__(self):
        return self.message


class PayloadHeader:
    def __init__(self, buffer):
        self._fmt = '>I2QI'
        (
            self.magic,
            self.version,
            self.manifest_size,
            self.metadata_signature_size
        ) = unpack(self._fmt, buffer[0:self.header_size])

    @property
    def header_size(self):
        return calcsize(self._fmt)


@dataclass
class Payload:
    header: PayloadHeader
    fd: IO[bytes]
    manifest: DeltaArchiveManifest = DeltaArchiveManifest()
    data_offset: int = 0
    metadata_signature: Signatures = Signatures()
    metadata_size: int = 0

    def read_blob(self, offset, length):
        self.fd.seek(self.data_offset + offset)
        return self.fd.read(length)


class PayloadBinUnpack:
    def __init__(self, *, logger: loguru.Logger, **kwargs):
        action = {
            'list': self._list,
            'extract': self._unpack}
        self.logger = logger

        if 'OUTPUT_DIR' in kwargs:
            self.out_dir = Path(kwargs.get('OUTPUT_DIR'))
            self.out_dir.mkdir(parents=True, exist_ok=True)

        self.filter_partition = None

        if 'PARTITIONS' in kwargs:
            self.filter_partition = kwargs.get('PARTITIONS')

        self.payload: Payload = self._parse_header(self._open(Path(kwargs.get('PAYLOAD_IMAGE'))))
        action.get(kwargs.get('COMMAND'))()

    @staticmethod
    def _parse_header(fd: IO[bytes]) -> Payload:
        header = PayloadHeader(fd.read(24))

        if MAGIC_NUMBER != header.magic:
            raise PayloadError(f'Invalid magic value in header. Find magic value: 0x{header.magic:04X}')

        if MAJOR_PAYLOAD_VERSION != header.version:
            raise PayloadError(f'Unsupported header version. Version on header: {header.version} '
                               f'Support version: {MAJOR_PAYLOAD_VERSION}')

        payload = Payload(header=header, fd=fd)
        payload.manifest.ParseFromString(fd.read(header.manifest_size))

        metadata_signature_message = fd.read(header.metadata_signature_size)

        if metadata_signature_message:
            payload.metadata_signature.ParseFromString(metadata_signature_message)

        payload.metadata_size = header.header_size + header.manifest_size
        payload.data_offset = payload.metadata_size + header.metadata_signature_size

        return payload

    @staticmethod
    def _open(path_to_payload: Union[str, Path]) -> IO[bytes]:
        if isinstance(path_to_payload, str):
            path_to_payload = Path(path_to_payload)

        return open(path_to_payload, 'rb')

    def _extract(self, partition: PartitionUpdate):
        out_file = Path(self.out_dir / f'{partition.partition_name}.img')

        with open(out_file, 'wb') as out:
            for operation in partition.operations:
                data = self.payload.read_blob(operation.data_offset, operation.data_length)

                if sha256(data).digest() != operation.data_sha256_hash:
                    self.logger.error('Hash mismatch')

                out.seek(operation.dst_extents[0].start_block * BLOCK_SIZE)
                if operation.type == InstallOperation.REPLACE:
                    out.write(data)
                elif operation.type == InstallOperation.REPLACE_XZ:
                    out.write(decompress(data, FORMAT_XZ))
                elif operation.type == InstallOperation.REPLACE_BZ:
                    out.write(bz2.decompress(data))
                else:
                    raise PayloadError(f'Unhandled operation type ({operation.type}'
                                       f' - {InstallOperation.Type.Name(operation.type)})')

    def _unpack(self):
        for partition in self.payload.manifest.partitions:
            if self.filter_partition is not None:
                if partition.partition_name not in self.filter_partition:
                    continue

            self.logger.info(f'Extracting {partition.partition_name}.img')

            self._extract(partition)

        self.payload.fd.close()

    def _list(self):
        for partition in self.payload.manifest.partitions:
            self.logger.info(f'Partition name: {partition.partition_name}\n'
                             f'Partition size: {partition.new_partition_info.size}\n'
                             f'Partition hash: {partition.new_partition_info.hash.hex()}\n')


def create_parser():
    parser = ArgumentParser(description=f'{Path(sys.argv[0])}'
                                        f' - command-line tool for extracting partition images from payload.bin')

    commands_parser = parser.add_subparsers(
        dest='COMMAND',
        help='Actions'
    )

    extract_parsers = commands_parser.add_parser('extract')

    extract_parsers.add_argument(
        '-p',
        '--partitions',
        dest='PARTITIONS',
        type=lambda x: re.split("\W+", x),
        help='Extract the named partition. This can be specified multiple times or through the delimiter [","  ":"]'
    )

    extract_parsers.add_argument(
        'PAYLOAD_IMAGE',
        type=str
    )

    extract_parsers.add_argument(
        'OUTPUT_DIR',
        type=str
    )

    list_parser = commands_parser.add_parser('list')

    list_parser.add_argument(
        'PAYLOAD_IMAGE',
        type=str
    )

    return parser


if __name__ == '__main__':
    parser = create_parser()
    namespace = parser.parse_args()

    if len(sys.argv) >= 2:
        if not Path(namespace.PAYLOAD_IMAGE).exists():
            parser.print_help()
            sys.exit(72)
        try:
            PayloadBinUnpack(logger=logger, **vars(namespace))
        except PayloadError as e:
            logger.error(e.message)
            sys.exit(74)
    else:
        parser.print_usage()
        sys.exit(64)
