import argparse
from pathlib import Path
from fnmatch import fnmatch
from urllib.parse import urlsplit, unquote
from posixpath import basename as url_basename

from entry_file import EntryFile, EntryParseError

def parse_entries(cache_path):
    cache_path = Path(cache_path)

    # If only one file, just parse that
    if cache_path.is_dir():
        entry_files = cache_path.iterdir()
    else:
        entry_files = [cache_path]

    for file in entry_files:
        if file.is_file():
            entry_file = EntryFile()
            try:
                entry_file.parse_entry_file(file)
            except EntryParseError:
                print(f"Failed to parse {file}. Is it a cache file? Skipping")
            else:
                yield entry_file

# Partyly based on https://gist.github.com/zed/c2168b9c52b032b5fb7d
def entry_to_filename(entry):
    # heurstically determine the best filename of the entry
    url = entry.key_tags.cacheKey
    filename = url_basename(urlsplit(url).path)
    return filename

def main(args = None):
    parser = argparse.ArgumentParser(description = "Parse Firefox Cache2")
    parser.add_argument('cache_path', nargs = "+", type = Path,
                        help = "Path to Firefox Cache2 folder or specific entry files.")
    parser.add_argument('-x', '--extract', type = Path, default = None,
                        help = "Output directory to extracted files to. Otherwise, only information about the file is printed.")
    parser.add_argument('--dryrun', action = "store_true",
                        help = "Do not actually create directory, but list the files that would have been created. Assumes --extract")
    parser.add_argument('-f', '--filter', default = None,
                        help = "Specify a glob expression to choose which files to extract. "
                        "Filter is based on the filename of the extracted file.")
    # parser.add_argument('-i', '--index', action = 'store_true', help =
    #                     "Do not extract files. Just list information from the index file.")
    parser.add_argument('-d', '--details', action = 'store_true', help =
                        "Print details of the cache file. ")
    parser.add_argument('-v', '--verbose', action = 'store_true', help =
                        "Print the name of each file as it is extracted. "
                        "Also reports files ignore by filter.")

    args = parser.parse_args(args)

    if args.dryrun and not args.extract:
        parser.error("--dryrun specified, but no directory provided to extract to")

    for cache_path in args.cache_path:
        for entry in parse_entries(cache_path):
            filename = entry_to_filename(entry)

            if not filename:
                # If no filename, use original filename
                filename = entry.filename

            if args.filter and not fnmatch(filename, args.filter):
                # Skip files that don't match the filter
                if args.verbose:
                    print(f"Skipping filename {entry.filename!r} with name {filename!r}")
                continue

            if args.details:
                print(f"filename                    : {entry.filename!r}")
                # print(f"key                         : {entry.key}")
                print(f"cacheKey                    : {entry.key_tags.cacheKey!r}")
                print(f"idEnhance                   : {entry.key_tags.idEnhance!r}")
                print(f"isAnonymous                 : {entry.key_tags.isAnonymous!r}")
                print(f"deprecatedAppId             : {entry.key_tags.originAttribs.deprecatedAppId!r}")
                print(f"firstPartyDomain            : {entry.key_tags.originAttribs.firstPartyDomain!r}")
                print(f"geckoViewSessionContextId   : {entry.key_tags.originAttribs.geckoViewSessionContextId!r}")
                print(f"inIsolatedMozBrowser        : {entry.key_tags.originAttribs.inIsolatedMozBrowser!r}")
                print(f"partitionKey                : {entry.key_tags.originAttribs.partitionKey!r}")
                print(f"privateBrowsingId           : {entry.key_tags.originAttribs.privateBrowsingId!r}")
                print(f"userContextId               : {entry.key_tags.originAttribs.userContextId!r}")
                print(f"hash_expected               : 0x{entry.hash_expected:08x}")
                # print(f"hash_buf                    : {entry.hash_buf!r}")
                # print(f"hash_codes                  : {entry.hash_codes!r}")
                # print(f"elements                    : {entry.elements}")
                print(f"version                     : {entry.metadata_header.version}")
                print(f"fetch_count                 : {entry.metadata_header.fetch_count}")
                print(f"last_fetched                : {entry.metadata_header.last_fetched}")
                print(f"last_modified               : {entry.metadata_header.last_modified}")
                # print(f"frecency                    : {entry.metadata_header.frecency}")
                print(f"expire_time                 : {entry.metadata_header.expire_time}")
                print(f"key_size                    : {entry.metadata_header.key_size}")
                print(f"flags                       : {entry.metadata_header.flags}")
                print(f"data_size                   : {len(entry.data)}")

            if not args.details and not args.extract:
                # If not showing details or extracting, just list a single line about
                # each entry
                print(f"Entry {entry.filename} of file {filename}")

            if not args.extract:
                continue

            # Print where the file would be saved to
            filename = args.extract / filename

            if args.verbose:
                if args.dryrun:
                    print(f"Would extract {entry.filename!r} to {str(filename.absolute())!r}")
                else:
                    print(f"Extracting {entry.filename!r} to {str(filename.absolute())!r}")

            # Create the directory if it doesn't exist
            filename.parent.mkdir(exist_ok = True)

            # Write the file
            filename.write_bytes(entry.data)


if __name__ == '__main__':
    main()
