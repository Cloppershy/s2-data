from struct import pack, unpack
from PIL import Image
import binascii
import io
import os

from .chacha import Key, filename_hash, decompress_data, compress_data, decrypt_data, encrypt_data

START_OFFSET = 0x400
KNOWN_ASSETS = [
    b"Data/Fonts/fontdebug.fnb",
    b"Data/Fonts/fontfirasans.fnb",
    b"Data/Fonts/fontmono.fnb",
    b"Data/Fonts/fontyorkten.fnb",
    b"Data/Levels/abzu.lvl",
    b"Data/Levels/Arena/dm1-1.lvl",
    b"Data/Levels/Arena/dm1-2.lvl",
    b"Data/Levels/Arena/dm1-3.lvl",
    b"Data/Levels/Arena/dm1-4.lvl",
    b"Data/Levels/Arena/dm1-5.lvl",
    b"Data/Levels/Arena/dm2-1.lvl",
    b"Data/Levels/Arena/dm2-2.lvl",
    b"Data/Levels/Arena/dm2-3.lvl",
    b"Data/Levels/Arena/dm2-4.lvl",
    b"Data/Levels/Arena/dm2-5.lvl",
    b"Data/Levels/Arena/dm3-1.lvl",
    b"Data/Levels/Arena/dm3-2.lvl",
    b"Data/Levels/Arena/dm3-3.lvl",
    b"Data/Levels/Arena/dm3-4.lvl",
    b"Data/Levels/Arena/dm3-5.lvl",
    b"Data/Levels/Arena/dm4-1.lvl",
    b"Data/Levels/Arena/dm4-2.lvl",
    b"Data/Levels/Arena/dm4-3.lvl",
    b"Data/Levels/Arena/dm4-4.lvl",
    b"Data/Levels/Arena/dm4-5.lvl",
    b"Data/Levels/Arena/dm5-1.lvl",
    b"Data/Levels/Arena/dm5-2.lvl",
    b"Data/Levels/Arena/dm5-3.lvl",
    b"Data/Levels/Arena/dm5-4.lvl",
    b"Data/Levels/Arena/dm5-5.lvl",
    b"Data/Levels/Arena/dm6-1.lvl",
    b"Data/Levels/Arena/dm6-2.lvl",
    b"Data/Levels/Arena/dm6-3.lvl",
    b"Data/Levels/Arena/dm6-4.lvl",
    b"Data/Levels/Arena/dm6-5.lvl",
    b"Data/Levels/Arena/dm7-1.lvl",
    b"Data/Levels/Arena/dm7-2.lvl",
    b"Data/Levels/Arena/dm7-3.lvl",
    b"Data/Levels/Arena/dm7-4.lvl",
    b"Data/Levels/Arena/dm7-5.lvl",
    b"Data/Levels/Arena/dm8-1.lvl",
    b"Data/Levels/Arena/dm8-2.lvl",
    b"Data/Levels/Arena/dm8-3.lvl",
    b"Data/Levels/Arena/dm8-4.lvl",
    b"Data/Levels/Arena/dm8-5.lvl",
    b"Data/Levels/Arena/dmpreview.tok",
    b"Data/Levels/babylonarea.lvl",
    b"Data/Levels/basecamp_garden.lvl",
    b"Data/Levels/basecamp.lvl",
    b"Data/Levels/basecamp_shortcut_discovered.lvl",
    b"Data/Levels/basecamp_shortcut_undiscovered.lvl",
    b"Data/Levels/basecamp_shortcut_unlocked.lvl",
    b"Data/Levels/basecamp_surface.lvl",
    b"Data/Levels/basecamp_tutorial.lvl",
    b"Data/Levels/basecamp_tv_room_locked.lvl",
    b"Data/Levels/basecamp_tv_room_unlocked.lvl",
    b"Data/Levels/beehive.lvl",
    b"Data/Levels/blackmarket.lvl",
    b"Data/Levels/cavebossarea.lvl",
    b"Data/Levels/challenge_moon.lvl",
    b"Data/Levels/challenge_star.lvl",
    b"Data/Levels/challenge_sun.lvl",
    b"Data/Levels/cityofgold.lvl",
    b"Data/Levels/cosmicocean_babylon.lvl",
    b"Data/Levels/cosmicocean_dwelling.lvl",
    b"Data/Levels/cosmicocean_icecavesarea.lvl",
    b"Data/Levels/cosmicocean_jungle.lvl",
    b"Data/Levels/cosmicocean_sunkencity.lvl",
    b"Data/Levels/cosmicocean_temple.lvl",
    b"Data/Levels/cosmicocean_tidepool.lvl",
    b"Data/Levels/cosmicocean_volcano.lvl",
    b"Data/Levels/duat.lvl",
    b"Data/Levels/dwellingarea.lvl",
    b"Data/Levels/eggplantarea.lvl",
    b"Data/Levels/ending.lvl",
    b"Data/Levels/generic.lvl",
    b"Data/Levels/hallofushabti.lvl",
    b"Data/Levels/hundun.lvl",
    b"Data/Levels/icecavesarea.lvl",
    b"Data/Levels/junglearea.lvl",
    b"Data/Levels/lake.lvl",
    b"Data/Levels/lakeoffire.lvl",
    b"Data/Levels/olmecarea.lvl",
    b"Data/Levels/palaceofpleasure.lvl",
    b"Data/Levels/sunkencityarea.lvl",
    b"Data/Levels/templearea.lvl",
    b"Data/Levels/testingarea.lvl",
    b"Data/Levels/tiamat.lvl",
    b"Data/Levels/tidepoolarea.lvl",
    b"Data/Levels/vladscastle.lvl",
    b"Data/Levels/volcanoarea.lvl",
    b"Data/Textures/base_eggship2.png",
    b"Data/Textures/base_eggship3.png",
    b"Data/Textures/base_eggship.png",
    b"Data/Textures/base_skynight.png",
    b"Data/Textures/base_surface2.png",
    b"Data/Textures/base_surface.png",
    b"Data/Textures/bayer8.png",
    b"Data/Textures/bg_babylon.png",
    b"Data/Textures/bg_beehive.png",
    b"Data/Textures/bg_cave.png",
    b"Data/Textures/bg_duat2.png",
    b"Data/Textures/bg_duat.png",
    b"Data/Textures/bg_eggplant.png",
    b"Data/Textures/bg_gold.png",
    b"Data/Textures/bg_ice.png",
    b"Data/Textures/bg_jungle.png",
    b"Data/Textures/bg_mothership.png",
    b"Data/Textures/bg_stone.png",
    b"Data/Textures/bg_sunken.png",
    b"Data/Textures/bg_temple.png",
    b"Data/Textures/bg_tidepool.png",
    b"Data/Textures/bg_vlad.png",
    b"Data/Textures/bg_volcano.png",
    b"Data/Textures/border_main.png",
    b"Data/Textures/char_black.png",
    b"Data/Textures/char_blue.png",
    b"Data/Textures/char_cerulean.png",
    b"Data/Textures/char_cinnabar.png",
    b"Data/Textures/char_cyan.png",
    b"Data/Textures/char_eggchild.png",
    b"Data/Textures/char_gold.png",
    b"Data/Textures/char_gray.png",
    b"Data/Textures/char_green.png",
    b"Data/Textures/char_hired.png",
    b"Data/Textures/char_iris.png",
    b"Data/Textures/char_khaki.png",
    b"Data/Textures/char_lemon.png",
    b"Data/Textures/char_lime.png",
    b"Data/Textures/char_magenta.png",
    b"Data/Textures/char_olive.png",
    b"Data/Textures/char_orange.png",
    b"Data/Textures/char_pink.png",
    b"Data/Textures/char_red.png",
    b"Data/Textures/char_violet.png",
    b"Data/Textures/char_white.png",
    b"Data/Textures/char_yellow.png",
    b"Data/Textures/coffins.png",
    b"Data/Textures/credits.png",
    b"Data/Textures/deco_babylon.png",
    b"Data/Textures/deco_basecamp.png",
    b"Data/Textures/deco_cave.png",
    b"Data/Textures/deco_cosmic.png",
    b"Data/Textures/deco_eggplant.png",
    b"Data/Textures/deco_extra.png",
    b"Data/Textures/deco_gold.png",
    b"Data/Textures/deco_ice.png",
    b"Data/Textures/deco_jungle.png",
    b"Data/Textures/deco_sunken.png",
    b"Data/Textures/deco_temple.png",
    b"Data/Textures/deco_tidepool.png",
    b"Data/Textures/deco_tutorial.png",
    b"Data/Textures/deco_volcano.png",
    b"Data/Textures/floor_babylon.png",
    b"Data/Textures/floor_cave.png",
    b"Data/Textures/floor_eggplant.png",
    b"Data/Textures/floor_ice.png",
    b"Data/Textures/floor_jungle.png",
    b"Data/Textures/floormisc.png",
    b"Data/Textures/floorstyled_babylon.png",
    b"Data/Textures/floorstyled_beehive.png",
    b"Data/Textures/floorstyled_duat.png",
    b"Data/Textures/floorstyled_gold_normal.png",
    b"Data/Textures/floorstyled_gold.png",
    b"Data/Textures/floorstyled_guts.png",
    b"Data/Textures/floorstyled_mothership.png",
    b"Data/Textures/floorstyled_pagoda.png",
    b"Data/Textures/floorstyled_palace.png",
    b"Data/Textures/floorstyled_stone.png",
    b"Data/Textures/floorstyled_sunken.png",
    b"Data/Textures/floorstyled_temple.png",
    b"Data/Textures/floorstyled_vlad.png",
    b"Data/Textures/floorstyled_wood.png",
    b"Data/Textures/floor_sunken.png",
    b"Data/Textures/floor_surface.png",
    b"Data/Textures/floor_temple.png",
    b"Data/Textures/floor_tidepool.png",
    b"Data/Textures/floor_volcano.png",
    b"Data/Textures/fontdebug.png",
    b"Data/Textures/fontfirasans.png",
    b"Data/Textures/fontmono.png",
    b"Data/Textures/fontyorkten.png",
    b"Data/Textures/fx_ankh.png",
    b"Data/Textures/fx_big.png",
    b"Data/Textures/fx_explosion.png",
    b"Data/Textures/fx_rubble.png",
    b"Data/Textures/fx_small2.png",
    b"Data/Textures/fx_small3.png",
    b"Data/Textures/fx_small.png",
    b"Data/Textures/hud_controller_buttons.png",
    b"Data/Textures/hud.png",
    b"Data/Textures/hud_text.png",
    b"Data/Textures/items.png",
    b"Data/Textures/items_ushabti.png",
    b"Data/Textures/journal_back.png",
    b"Data/Textures/journal_elements.png",
    b"Data/Textures/journal_entry_bg.png",
    b"Data/Textures/journal_entry_items.png",
    b"Data/Textures/journal_entry_mons_big.png",
    b"Data/Textures/journal_entry_mons.png",
    b"Data/Textures/journal_entry_people.png",
    b"Data/Textures/journal_entry_place.png",
    b"Data/Textures/journal_entry_traps.png",
    b"Data/Textures/journal_pageflip.png",
    b"Data/Textures/journal_pagetorn.png",
    b"Data/Textures/journal_select.png",
    b"Data/Textures/journal_stickers.png",
    b"Data/Textures/journal_story.png",
    b"Data/Textures/journal_top_entry.png",
    b"Data/Textures/journal_top_gameover.png",
    b"Data/Textures/journal_top_main.png",
    b"Data/Textures/journal_top_profile.png",
    b"Data/Textures/loading.png",
    b"Data/Textures/lut_backlayer.png",
    b"Data/Textures/lut_blackmarket.png",
    b"Data/Textures/lut_icecaves.png",
    b"Data/Textures/lut_original.png",
    b"Data/Textures/lut_vlad.png",
    b"Data/Textures/main_body.png",
    b"Data/Textures/main_dirt.png",
    b"Data/Textures/main_doorback.png",
    b"Data/Textures/main_doorframe.png",
    b"Data/Textures/main_door.png",
    b"Data/Textures/main_fore1.png",
    b"Data/Textures/main_fore2.png",
    b"Data/Textures/main_head.png",
    b"Data/Textures/menu_basic.png",
    b"Data/Textures/menu_brick1.png",
    b"Data/Textures/menu_brick2.png",
    b"Data/Textures/menu_cave1.png",
    b"Data/Textures/menu_cave2.png",
    b"Data/Textures/menu_chardoor.png",
    b"Data/Textures/menu_charsel.png",
    b"Data/Textures/menu_deathmatch2.png",
    b"Data/Textures/menu_deathmatch3.png",
    b"Data/Textures/menu_deathmatch4.png",
    b"Data/Textures/menu_deathmatch5.png",
    b"Data/Textures/menu_deathmatch6.png",
    b"Data/Textures/menu_deathmatch.png",
    b"Data/Textures/menu_disp.png",
    b"Data/Textures/menu_generic.png",
    b"Data/Textures/menu_header.png",
    b"Data/Textures/menu_leader.png",
    b"Data/Textures/menu_online.png",
    b"Data/Textures/menu_titlegal.png",
    b"Data/Textures/menu_title.png",
    b"Data/Textures/menu_tunnel.png",
    b"Data/Textures/monsters01.png",
    b"Data/Textures/monsters02.png",
    b"Data/Textures/monsters03.png",
    b"Data/Textures/monstersbasic01.png",
    b"Data/Textures/monstersbasic02.png",
    b"Data/Textures/monstersbasic03.png",
    b"Data/Textures/monstersbig01.png",
    b"Data/Textures/monstersbig02.png",
    b"Data/Textures/monstersbig03.png",
    b"Data/Textures/monstersbig04.png",
    b"Data/Textures/monstersbig05.png",
    b"Data/Textures/monstersbig06.png",
    b"Data/Textures/monsters_ghost.png",
    b"Data/Textures/monsters_hundun.png",
    b"Data/Textures/monsters_olmec.png",
    b"Data/Textures/monsters_osiris.png",
    b"Data/Textures/monsters_pets.png",
    b"Data/Textures/monsters_tiamat.png",
    b"Data/Textures/monsters_yama.png",
    b"Data/Textures/mounts.png",
    b"Data/Textures/noise0.png",
    b"Data/Textures/noise1.png",
    b"Data/Textures/OldTextures/ai.png",
    b"Data/Textures/placeholder",
    b"Data/Textures/saving.png",
    b"Data/Textures/shadows.png",
    b"Data/Textures/shine.png",
    b"Data/Textures/splash0.png",
    b"Data/Textures/splash1.png",
    b"Data/Textures/splash2.png",
    b"shaders.hlsl",
    b"soundbank.bank",
    b"soundbank.strings.bank",
    b"strings00.str",
    b"strings01.str",
    b"strings02.str",
    b"strings03.str",
    b"strings04.str",
    b"strings05.str",
    b"strings06.str",
    b"strings07.str",
]


class Asset(object):
    def __init__(
        self, name_hash, name_len, asset_len, encrypted, offset, data_offset, data_size
    ):
        self.name_hash = name_hash
        self.name_len = name_len
        self.asset_len = asset_len
        self.encrypted = encrypted
        self.offset = offset
        self.data_offset = data_offset
        self.data_size = data_size
        self.filename = None
        self.path = None

    @property
    def total_size(self):
        return 8 + self.name_len + self.asset_len

    def __repr__(self):
        return (
            "Asset("
            "name_hash={!r}, name_len={!r}, filename={!r}, asset_len={!r}, encrypted={!r}, "
            "offset={}, data_offset={}, data_size={!r}"
            ")"
        ).format(
            binascii.hexlify(self.name_hash),
            self.name_len,
            self.filename,
            self.asset_len,
            self.encrypted,
            hex(self.offset),
            hex(self.data_offset),
            self.data_size,
        )

    def match_hash(self, hash):
        l = min(len(hash), self.name_len)
        return hash[:l] == self.name_hash[:l]

    def extract(self, filename, handle, key, return_compressed=False):
        handle.seek(self.data_offset)
        data = handle.read(self.data_size)
        compressed_data = None
        if self.encrypted:
            try:
                compressed_data = decrypt_data(filename, data, key)
                data = decompress_data(compressed_data)
            except Exception as exc:
                print(exc)
                if return_compressed:
                    return None, None
                else:
                    return None

        if filename.endswith(b".png"):
            width, height = unpack(b"<II", data[:8])
            image = Image.frombytes("RGBA", (width, height), data[8:], "raw")
            new_data = io.BytesIO()
            image.save(new_data, format="PNG")
            data = new_data.getvalue()

        if return_compressed:
            return data, compressed_data
        else:
            return data


class AssetStore(object):
    def __init__(self, exe_handle):
        self.assets = []
        self.exe_handle = exe_handle
        self.total_size = 0
        self._key = Key()
        self._load_assets()

    @property
    def key(self):
        return self._key.key

    def recalculate_key(self):
        new_key = Key()
        for asset in self.assets:
            new_key.update(asset.asset_len)
        self._key = new_key

    def find_asset(self, filename):
        if filename is None:
            return None
        name_hash = filename_hash(filename, self.key)
        for asset in self.assets:
            if asset.match_hash(name_hash):
                return asset
        return None

    def filename_hash(self, filename):
        if filename is None:
            return None
        return filename_hash(filename, self.key)

    def repackage(self, mod_dirs, original_dir, compression_level):
        sources = []
        if isinstance(mod_dirs, str):
            sources.append(bytes(mod_dirs, "utf-8"))
        else:
            sources.extend(bytes(dir, "utf-8") for dir in mod_dirs)
        original_dir = bytes(original_dir, "utf-8")
        sources.append(original_dir)

        print("Gathering assets for repackaging")
        # Prepare compressed files and calculate new sizes
        for asset in self.assets:
            if asset.filename is None:
                print("Skipping unknown asset with hash {!r}".format(binascii.hexlify(asset.name_hash)))
                continue

            for dir in sources:
                path = os.path.join(dir, asset.filename)
                compressed_path = path + b".zst"

                if asset.encrypted and os.path.exists(compressed_path):
                    # Use already compressed data for encrypted asset
                    asset.path = compressed_path
                    asset.data_size = os.path.getsize(compressed_path)
                elif os.path.exists(path):
                    if asset.encrypted:
                        # Compress data for encrypted asset
                        if path.endswith(b".png"):
                            img = Image.open(path).convert("RGBA")
                            data = pack("<II", img.width, img.height) + bytes(
                                [
                                    (
                                        byte if rgba[3] != 0 else 0
                                    )  # Hack to force all transparent pixels to be (0, 0, 0, 0) instead of (255, 255, 255, 0)
                                    for rgba in img.getdata()
                                    for byte in rgba
                                ]
                            )
                        else:
                            with open(path, "rb") as f:
                                data = f.read()
                        data = compress_data(data, compression_level)
                        with open(compressed_path, "wb") as f:
                            f.write(data)
                        asset.path = compressed_path
                        asset.data_size = len(data)
                    else:
                        # Use uncompressed data for unencrypted asset
                        asset.path = path
                        asset.data_size = os.path.getsize(path)
                else:
                    # Asset not found in this dir
                    continue
                
                # Asset was found in this dir, update asset_len and total size
                if dir != original_dir:
                    print('Using "{}" from {}'.format(asset.filename.decode(), asset.path.decode())) 
                asset.asset_len = asset.data_size + 1
                break
            else:
                # Asset wasn't found in any dir
                print("Didn't find extracted data for asset {}. Please run the extraction script first.".format(
                    asset.filename.decode()
                ))

        # Recalculate encryption key based on new asset_lens
        print("Calculating new encryption key")
        self.recalculate_key()
        print("New key is: 0x{:8x}".format(self.key))

        # Recalculate file hashes. If filename is unknown, we can't calculate it and just use the old one.
        new_total_size = 0
        print("Calculating new name hashes")
        offset = START_OFFSET
        for asset in self.assets:
            if asset.filename:
                old_hash = asset.name_hash
                asset.name_hash = filename_hash(asset.filename, self.key)

                if False:  # For game version < 1.13
                    # Hash was a null-terminated string, and mistakenly cut off early when the hash contained a null byte
                    for i, byte in enumerate(asset.name_hash):
                        if byte == 0:
                            asset.name_hash = asset.name_hash[:i+1]
                            break
                    else:
                        asset.name_hash += b"\x00"

                # The name hash of soundbank files is padded such that the data_offset is divisible by 32
                # Padding is between 1 and 32 bytes
                if asset.filename.endswith(b".bank"):
                    data_offset = offset + 8 + len(asset.name_hash) + 1
                    padding = 32 - data_offset % 32
                    asset.name_hash += b"\x00" * padding
                    print("Padded hash for {}: {!r}".format(asset.filename.decode(), binascii.hexlify(asset.name_hash)))

                asset.name_len = len(asset.name_hash)

            asset.offset = offset
            asset.data_offset = offset + 8 + asset.name_len + 1
            offset += asset.total_size
            new_total_size += asset.total_size

        # Verify that new assets fit into the exe
        size_diff = new_total_size - self.total_size
        if size_diff > 0:
            print(
                "New total size is greater than original asset size ({} bytes > {} bytes, +{} bytes), unable to pack new assets.".format(
                    new_total_size, self.total_size, size_diff
                )
            )
            return False
        self.total_size = new_total_size
        print("New total size is {} bytes, {} less than original assets".format(new_total_size, -size_diff))

        # Write new assets into file
        print("Writing new binary...")
        self.exe_handle.seek(START_OFFSET)
        for idx, asset in enumerate(self.assets):
            new_offset = self.exe_handle.tell()
            print("\r{:3d}/{:3d} assets written (old offset: 0x{:08x}, new offset: 0x{:08x}), encrypted: {}, {:50s}".format(
                idx + 1, len(self.assets), asset.offset, new_offset, asset.encrypted,
                asset.filename.decode() if asset.filename is not None else "[unknown]"
            ), end="")

            assert asset.offset == new_offset
            self.exe_handle.write(pack("<II", asset.asset_len, asset.name_len))

            self.exe_handle.write(asset.name_hash)
            self.exe_handle.write(b"\x01" if asset.encrypted else b"\x00")
            assert asset.data_offset == self.exe_handle.tell()

            if asset.path:
                with open(asset.path, "rb") as f:
                    data = f.read()
                if asset.encrypted:
                    data = encrypt_data(asset.filename, data, self.key)
                self.exe_handle.write(data)
            else:
                self.exe_handle.write(b"\x00" * asset.data_size)

        print("\nFinishing file")

        # End marker
        self.exe_handle.write(b"\x00" * 8)

        # Overwrite rest of old data with padding
        self.exe_handle.write(b"\xAA" * -size_diff)

    def _load_assets(self, offset=START_OFFSET):
        self.exe_handle.seek(offset)

        while True:
            offset = self.exe_handle.tell()
            asset_len, name_len = unpack(b"<II", self.exe_handle.read(8))
            if (asset_len, name_len) == (0, 0):
                break
            assert asset_len > 0

            name_hash = self.exe_handle.read(name_len)
            encrypted = self.exe_handle.read(1) == b"\x01"
            data_offset = self.exe_handle.tell()
            data_size = asset_len - 1

            self.exe_handle.seek(data_size, 1)
            self._key.update(asset_len)

            asset = Asset(
                name_hash=name_hash,
                name_len=name_len,
                asset_len=asset_len,
                encrypted=encrypted,
                offset=offset,
                data_offset=data_offset,
                data_size=data_size,
            )
            self.assets.append(asset)
            self.total_size += asset.total_size
