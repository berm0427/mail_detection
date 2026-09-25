"""Inspect a large HTTP ZIP with Range requests without downloading it all."""
from __future__ import annotations

import argparse
import io
import json
import re
import zipfile
from collections import Counter, OrderedDict
from pathlib import PurePosixPath

import requests


class RemoteRangeFile(io.RawIOBase):
    def __init__(self, url, chunk_size=4 * 1024 * 1024, cache_chunks=4):
        self.url = url
        self.chunk_size = chunk_size
        self.cache_chunks = cache_chunks
        self.session = requests.Session()
        response = self.session.head(url, allow_redirects=True, timeout=60)
        response.raise_for_status()
        self.size = int(response.headers.get('Content-Length', 0))
        if self.size < 22:
            probe = self.session.get(url, headers={'Range': 'bytes=0-0'}, timeout=60)
            probe.raise_for_status()
            match = re.search(r'/([0-9]+)$', probe.headers.get('Content-Range', ''))
            if not match:
                raise OSError('Server did not report the remote file size')
            self.size = int(match.group(1))
        self.position = 0
        self.cache = OrderedDict()

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.position

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_SET: position = offset
        elif whence == io.SEEK_CUR: position = self.position + offset
        elif whence == io.SEEK_END: position = self.size + offset
        else: raise ValueError('invalid whence')
        if position < 0: raise ValueError('negative seek')
        self.position = position
        return position

    def _chunk(self, index):
        if index in self.cache:
            self.cache.move_to_end(index)
            return self.cache[index]
        start = index * self.chunk_size
        end = min(self.size, start + self.chunk_size) - 1
        response = self.session.get(self.url, headers={'Range': f'bytes={start}-{end}'}, timeout=120)
        if response.status_code != 206:
            raise OSError(f'Range request failed: HTTP {response.status_code}')
        data = response.content
        self.cache[index] = data
        while len(self.cache) > self.cache_chunks:
            self.cache.popitem(last=False)
        return data

    def read(self, size=-1):
        if size is None or size < 0: size = self.size - self.position
        size = min(size, self.size - self.position)
        if size <= 0: return b''
        output = bytearray()
        while size:
            index, inner = divmod(self.position, self.chunk_size)
            chunk = self._chunk(index)
            take = min(size, len(chunk) - inner)
            if take <= 0: break
            output.extend(chunk[inner:inner + take])
            self.position += take
            size -= take
        return bytes(output)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('url')
    parser.add_argument('--sample', type=int, default=20)
    args = parser.parse_args()
    remote = RemoteRangeFile(args.url)
    with zipfile.ZipFile(remote) as archive:
        files = [entry for entry in archive.infolist() if not entry.is_dir()]
        extensions = Counter(PurePosixPath(entry.filename).suffix.casefold() or '<none>' for entry in files)
        basenames = Counter(PurePosixPath(entry.filename).name.casefold() for entry in files)
        selected = [entry for entry in files if PurePosixPath(entry.filename).name.casefold() in ('html.txt', 'info.txt')]
        largest = sorted(files, key=lambda entry: entry.file_size, reverse=True)[:args.sample]
        report = {
            'archive_bytes': remote.size,
            'files': len(files),
            'extensions': extensions.most_common(),
            'common_basenames': basenames.most_common(10),
            'html_info_files': len(selected),
            'html_info_uncompressed_bytes': sum(entry.file_size for entry in selected),
            'html_info_compressed_bytes': sum(entry.compress_size for entry in selected),
            'first_names': [entry.filename for entry in files[:args.sample]],
            'largest': [{'name': entry.filename, 'bytes': entry.file_size,
                         'compressed_bytes': entry.compress_size} for entry in largest],
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
