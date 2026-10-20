"""Decodes Android binary XML (the compiled AndroidManifest.xml inside an APK) into an ElementTree.

Attribute names use the "android:" prefix so the same checks work on source and compiled manifests.
"""

import struct
import xml.etree.ElementTree as ET

STRING_POOL, RESOURCE_MAP = 0x0001, 0x0180
START_ELEMENT, END_ELEMENT = 0x0102, 0x0103
UTF8_FLAG = 0x100
ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Framework attribute IDs, used when obfuscators blank out attribute names in the string pool.
ATTR_IDS = {
    0x01010003: "name", 0x01010006: "permission", 0x0101000F: "debuggable", 0x01010010: "exported",
    0x0101020C: "minSdkVersion", 0x01010270: "targetSdkVersion", 0x01010280: "allowBackup",
    0x010104EC: "usesCleartextTraffic", 0x01010527: "networkSecurityConfig", 0x0101001B: "readPermission",
    0x0101001C: "writePermission", 0x01010018: "authorities", 0x0101001F: "grantUriPermissions",
}


class AxmlError(ValueError):
    pass


def _read_strings(data: bytes, start: int) -> list[str]:
    count, _styles, flags, strings_start, _ = struct.unpack_from("<5I", data, start + 8)
    offsets = struct.unpack_from(f"<{count}I", data, start + 28)
    base = start + strings_start
    utf8 = flags & UTF8_FLAG
    strings = []
    for offset in offsets:
        pos = base + offset
        if utf8:
            pos += 2 if data[pos] & 0x80 else 1  # UTF-16 length (unused)
            length = data[pos]
            if length & 0x80:
                length = ((length & 0x7F) << 8) | data[pos + 1]
                pos += 2
            else:
                pos += 1
            strings.append(data[pos:pos + length].decode("utf-8", errors="replace"))
        else:
            length = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            if length & 0x8000:
                length = ((length & 0x7FFF) << 16) | struct.unpack_from("<H", data, pos)[0]
                pos += 2
            strings.append(data[pos:pos + length * 2].decode("utf-16-le", errors="replace"))
    return strings


def _value(strings: list[str], raw: int, data_type: int, value: int) -> str:
    if raw != 0xFFFFFFFF and raw < len(strings):
        return strings[raw]
    if data_type == 0x12:  # boolean
        return "true" if value else "false"
    if data_type == 0x03 and value < len(strings):
        return strings[value]
    if data_type in (0x01, 0x02):  # reference / attribute
        return f"@0x{value:08x}"
    if data_type == 0x11:
        return f"0x{value:x}"
    return str(value - (1 << 32) if value & 0x80000000 else value)


def decode(data: bytes) -> ET.Element:
    if len(data) < 8 or struct.unpack_from("<H", data, 0)[0] != 0x0003:
        raise AxmlError("not an Android binary XML file")
    strings: list[str] = []
    resource_ids: list[int] = []
    root = None
    stack: list[ET.Element] = []
    pos = struct.unpack_from("<H", data, 2)[0]
    try:
        while pos + 8 <= len(data):
            chunk_type, header_size, size = struct.unpack_from("<HHI", data, pos)
            if size < 8:
                break
            if chunk_type == STRING_POOL:
                strings = _read_strings(data, pos)
            elif chunk_type == RESOURCE_MAP:
                resource_ids = list(struct.unpack_from(f"<{(size - header_size) // 4}I", data, pos + header_size))
            elif chunk_type == START_ELEMENT:
                ext = pos + header_size
                _ns, name_idx, attr_start, attr_size, attr_count = struct.unpack_from("<IIHHH", data, ext)
                element = ET.Element(strings[name_idx] if name_idx < len(strings) else "?")
                for i in range(attr_count):
                    a = ext + attr_start + i * attr_size
                    ns, attr_name, raw, _sz, _res0, data_type, value = struct.unpack_from("<IIIHBBI", data, a)
                    name = strings[attr_name] if attr_name < len(strings) else ""
                    if not name and attr_name < len(resource_ids):
                        name = ATTR_IDS.get(resource_ids[attr_name], f"0x{resource_ids[attr_name]:08x}")
                    prefix = "android:" if ns != 0xFFFFFFFF and ns < len(strings) and strings[ns] == ANDROID_NS else ""
                    element.set(prefix + name, _value(strings, raw, data_type, value))
                if stack:
                    stack[-1].append(element)
                else:
                    root = element
                stack.append(element)
            elif chunk_type == END_ELEMENT and stack:
                stack.pop()
            pos += size
    except (struct.error, IndexError) as exc:
        raise AxmlError(f"malformed binary XML: {exc}")
    if root is None:
        raise AxmlError("no XML elements found")
    return root


def from_text(text: str) -> ET.Element:
    """Parse a source XML file, rewriting {android-ns}attr keys to android:attr."""
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise AxmlError("XML with DTDs/entities isn't parsed (entity-expansion protection)")
    root = ET.fromstring(text)
    for element in root.iter():
        for key in list(element.attrib):
            if key.startswith("{" + ANDROID_NS + "}"):
                element.set("android:" + key.split("}", 1)[1], element.attrib.pop(key))
    return root
