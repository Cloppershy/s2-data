import binascii
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
import logging
import multiprocessing

from .assets import KNOWN_ASSETS, AssetStore, EXTRACTED_DIR, OVERRIDES_DIR

DEFAULT_DIR = Path("Mods")
EXTRACTED_DIR = DEFAULT_DIR / EXTRACTED_DIR
OVERRIDES_DIR = DEFAULT_DIR / OVERRIDES_DIR

DIRS = [
    "Data/Fonts",
    "Data/Levels/Arena",
    "Data/Textures/OldTextures"
]


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Extract Spelunky 2 Assets.")
    parser.add_argument("exe", type=argparse.FileType("rb"), help="Path to Spel2.exe")

    args = parser.parse_args()

    logging.basicConfig(format="%(levelname)s - %(message)s", level=logging.INFO)

    asset_store = AssetStore.load_from_file(args.exe)
    seen = {}

    # Make all directories for extraction and overrides
    for dir_ in DIRS:
        (EXTRACTED_DIR / dir_).mkdir(parents=True, exist_ok=True)
        (EXTRACTED_DIR / ".compressed" / dir_).mkdir(parents=True, exist_ok=True)
        (OVERRIDES_DIR / dir_).mkdir(parents=True, exist_ok=True)
        (OVERRIDES_DIR / ".compressed" / dir_).mkdir(parents=True, exist_ok=True)

    for filename in KNOWN_ASSETS:
        asset = asset_store.find_asset(filename)
        name_hash = asset_store.filename_hash(filename)
        if asset is None:
            logging.warning("Asset %s not found with hash %s...",
                filename.decode(),
                binascii.hexlify(name_hash)
            )
            continue

        asset.filename = filename
        seen[asset.name_hash] = asset

        filepath = Path(filename.decode())

    def extract_single(lock, asset):
        try:
            # Loading the data from the exe has to be synchronized
            # because the exe file handle is a shared resource.
            with lock:
                asset.load_data(args.exe)

            logging.info("Extracting %s... ", asset.filename.decode())
            asset.extract(EXTRACTED_DIR, asset_store.key)
            return True
        except Exception as err:
            logging.warning("Failed to extract %s (%s: %s)", asset.filename.decode(), type(err).__name__, err)
            return False

    with ThreadPoolExecutor() as pool:
        lock = multiprocessing.Lock()
        extract_with_lock = partial(extract_single, lock)
        successes = list(pool.map(extract_with_lock, seen.values()))

    if not all(successes):
        logging.info("Retrying previously failed extractions in series")
        for success, asset in zip(successes, seen.values()):
            if success:
                continue  # Already extracted
            try:
                asset.load_data(args.exe)
                logging.info("Extracting %s... ", asset.filename.decode())
                asset.extract(EXTRACTED_DIR, asset_store.key)
            except Exception as err:
                logging.error("Failed to extract %s", asset.filename.decode())
                logging.exception(err)

    for asset in sorted(asset_store.assets, key=lambda a: a.offset):
        name_hash = asset_store.filename_hash(asset.filename)
        if asset.name_hash not in seen:
            logging.warning("Un-extracted Asset %s", asset)


if __name__ == '__main__':
    main()
