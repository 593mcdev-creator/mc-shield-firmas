#!/usr/bin/env python3
"""
Genera firmas.json para MC Shield Antivirus Pro.

Fuentes de firmas reales (se fusionan, sin duplicados):
  1) Lista curada (hashes verificados integrados en el antivirus).
  2) MalwareBazaar (bazaar.abuse.ch) - muestras recientes, SOLO si se define
     MB_API_KEY. Regístrate gratis en https://bazaar.abuse.ch/ para obtenerla.

Uso:
  python update_firmas.py                # solo lista curada (sin clave)
  MB_API_KEY=xxx python update_firmas.py # + muestras recientes de MalwareBazaar
"""

import datetime
import json
import os
import sys
import urllib.parse
import urllib.request

MB_API = "https://mb-api.abuse.ch/api/v1/"
MB_MAX_SAMPLES = 1200
MAX_HASHES = 50000

# Lista curada: hashes integrados en el antivirus (se mantienen en
# core/malware_hashes.py de MC_Shield_Windows). Formato:
#   "sha256": ["Nombre", "Tipo"]
CURATED = {
    # Ransomware
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa": ["WannaCry.Ransomware", "Ransomware"],
    "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c": ["WannaCry.Worm.b", "Ransomware"],
    "4a468603fdcb7a2eb5770705898cf9ef37aade532a7964642ecd705a74794b79": ["Petya.Ransomware", "Ransomware"],
    "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745": ["NotPetya.Ransomware", "Ransomware"],
    "43ced481e0f68fe57be3246cc5aede353c9d34f4e15d0afe443b5de9514d3ce4": ["LockBit.Ransomware", "Ransomware"],
    "ea5f8b184783979f3e32802b6942525b9f75cefae9d6e527c493a340cfc57c73": ["LockBit.Ransomware", "Ransomware"],
    "80e8defa5377018b093b5b90de0f2957f7062144c83a09a56bba1fe4eda932ce": ["LockBit.Ransomware", "Ransomware"],
    "7ea5afbc166c4e23498aa9747be81ceaf8dad90b8daa07a6e4644dc7c2277b82": ["LockBit.Ransomware", "Ransomware"],
    "180e93a091f8ab584a827da92c560c78f468c45f2539f73ab2deb308fb837b38": ["LockBit.Ransomware", "Ransomware"],
    "81b2bd4ea98c8db66554fbc8d7637a1a69a130f331feb732b75caab4c4868fd5": ["LockBit.Ransomware", "Ransomware"],
    # Troyanos / Backdoors
    "a04ac6d98ad989312783d4fe3456c53730b212c79a426fb215708b6c6daa3de3": ["Dridex.Trojan", "Trojan"],
    "85b936960fbe5100c170b777e1647ce9f0f01e3ab9742dfc23f37cb0825b30b5": ["Cobalt.Backdoor", "Backdoor"],
    "25d4b42c98e6fb6ea5f91393252a446e0141074765e955b3e561d8b56454a73a": ["Emotet.Trojan", "Trojan"],
    "1e8d9f532c2c5909ba3a8ec8d05fc8bed667dcc0c2592224827b614af7fa3ce1": ["Emotet.Trojan", "Trojan"],
    "aa4b22bf31692e70b63dfa0c93888e1795c2d861550f6926c720c3609df4c39a": ["Emotet.Trojan", "Trojan"],
    "2c7e18f64c2f229d03afc9b6231f950c0489b684ec0792e75baceb4a03833ff3": ["Emotet.Trojan", "Trojan"],
    "6b4808050c2a6b80fc9945acdecec07a843436ea707f63555f6557057834333e": ["CobaltStrike.Beacon", "Backdoor"],
    "56181f668b1bd40f2c72909e7ed346ae6fdf176863ac42c0724bef5bf14d57fd": ["CobaltStrike.Beacon", "Backdoor"],
    "b6262f4aa06d0bf045d95e3fcbc142f1d1d98f053da5714e3570482f0cf93b62": ["CobaltStrike.Beacon", "Backdoor"],
    "98e79f95cf8de8ace88bf223421db5dce303b112152d66ffdf27ebdfcdf967e9": ["Trojan.Dropper", "Trojan"],
    # Spyware / RAT
    "55f8718109829bf506b09d8af615b9f107a266671a6114a1b9bb28f7bb2b74ed": ["DarkComet.RAT", "Spyware"],
    # Prueba estándar (EICAR)
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": ["EICAR-Test-Signature", "Test-Virus"],
}


def _valid_hash(h):
    return isinstance(h, str) and len(h) == 64 and all(c in "0123456789abcdef" for c in h)


def fetch_malwarebazaar(api_key):
    """Últimas muestras de MalwareBazaar: {sha256: [nombre, tipo]}."""
    body = urllib.parse.urlencode({
        "query": "get_recent",
        "selector": "time",
        "limit": MB_MAX_SAMPLES,
    }).encode("utf-8")
    req = urllib.request.Request(MB_API, data=body, headers={
        "Auth-Key": api_key,
        "User-Agent": "MCShieldPro/2.1",
        "Content-Type": "application/x-www-form-urlencoded",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    samples = {}
    for s in (data.get("data") or []):
        h = (s.get("sha256_hash") or "").lower()
        if not _valid_hash(h):
            continue
        name = (s.get("signature") or "Malware.Sample")[:60]
        samples[h] = [name, "Malware"]
    return samples


def main():
    hashes = dict(CURATED)

    api_key = os.environ.get("MB_API_KEY", "").strip()
    if api_key:
        try:
            fresh = fetch_malwarebazaar(api_key)
            added = 0
            for h, info in fresh.items():
                if h not in hashes:
                    hashes[h] = info
                    added += 1
            print("MalwareBazaar: {} recientes, {} nuevas".format(len(fresh), added))
        except Exception as e:
            print("AVISO: no se pudo consultar MalwareBazaar: {}".format(e))
    else:
        print("MB_API_KEY no definida: se genera solo con la lista curada.")

    if len(hashes) > MAX_HASHES:
        hashes = dict(sorted(hashes.items())[:MAX_HASHES])

    today = datetime.date.today()
    bundle = {
        "version": int(today.strftime("%Y%m%d")),
        "date": today.isoformat(),
        "hashes": hashes,
    }
    with open("firmas.json", "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)
    print("firmas.json generado: {} firmas (version {})".format(len(hashes), bundle["version"]))


if __name__ == "__main__":
    sys.exit(main())
