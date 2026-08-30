#!/usr/bin/env python3
"""
build_isp_db.py — сборка ASN/ISP базы из открытых источников (без MaxMind/ipinfo).

Рабочий конвейер релиза XC_VM_Update: источник префиксов и ASN — уже скачанная в
CI `GeoLite2-ASN.mmdb`; обогащение — RIPE asn.txt (имена/страны), delegated-extended
5 RIR (страна/дата), PeeringDB (имя/домен/тип), bulk-whois RIPE/APNIC/AFRINIC (домены).

Выходы:
  --asn-json blocked_asns.json  ASN-справочник под таблицу blocked_asns панели:
                                {asn, isp, domain, country, num_ips, type, blocked}
  --mmdb-out GeoIP2-ISP.mmdb     свой IP->ISP mmdb (схема GeoIP2-ISP, 4 поля) —
                                бесплатная замена платной GeoIP2-ISP.mmdb.

Пример (как в CI):
    python3 build_isp_db.py --asn-mmdb GeoLite2-ASN.mmdb \\
        --asn-json blocked_asns.json --mmdb-out GeoIP2-ISP.mmdb
"""

import argparse
import gzip
import ipaddress
import json
import os
import re
import sys
import time
from collections import defaultdict

import requests

UA = "asn-db-builder/2.0 (self-hosted; open data)"

ASNAMES_URL = "https://ftp.ripe.net/ripe/asnames/asn.txt"

RIR_DELEGATED = {
    "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "arin":    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "apnic":   "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "lacnic":  "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}

# Bulk-whois дампы RIR (RPSL). ARIN и LACNIC отдают whois только по
# регистрации/AUP, поэтому их здесь нет. RIPE/APNIC — split-файлы, AFRINIC —
# единый дамп со всеми объектами.
WHOIS_BULK = {
    "ripe": ["https://ftp.ripe.net/ripe/dbase/split/ripe.db.aut-num.gz",
             "https://ftp.ripe.net/ripe/dbase/split/ripe.db.organisation.gz"],
    "apnic": ["https://ftp.apnic.net/apnic/whois/apnic.db.aut-num.gz",
              "https://ftp.apnic.net/apnic/whois/apnic.db.organisation.gz"],
    "afrinic": ["https://ftp.afrinic.net/dbase/afrinic.db.gz"],
}

PDB_TYPE_MAP = {
    "nsp": "isp",
    "cable/dsl/isp": "isp",
    "route server": "isp",
    "network services": "isp",
    "content": "hosting",
    "enterprise": "business",
    "non-profit": "business",
    "educational/research": "education",
    "government": "government",
}

HOSTING_HINTS = re.compile(
    r"\b(hosting|host|vps|vds|cloud|datacenter|data ?center|dedicated|server"
    r"|colocation|colo|cdn|webhost)\b", re.I)
ISP_HINTS = re.compile(
    r"\b(telecom|telekom|telecomunica\w*|communications?|broadband|mobile"
    r"|wireless|cellular|internet service|isp|provider)\b", re.I)
EDU_HINTS = re.compile(
    r"\b(universit\w*|universidad|universite|institut\w*|academ\w*|school"
    r"|college|research|\.edu\b|\.ac\.)", re.I)
GOV_HINTS = re.compile(
    r"\b(government|ministry|ministerio|municipal\w*|federal|state of"
    r"|\.gov\b|\.gob\b|\.gouv\b)", re.I)

FREEMAIL = {
    "gmail.com", "googlemail.com", "yandex.ru", "yandex.com", "mail.ru",
    "outlook.com", "hotmail.com", "live.com", "yahoo.com", "yahoo.co.jp",
    "protonmail.com", "proton.me", "icloud.com", "qq.com", "163.com",
    "126.com", "aol.com", "gmx.de", "gmx.net", "web.de", "list.ru",
    "bk.ru", "inbox.ru", "rambler.ru", "naver.com", "hanmail.net",
}

UINT_MAX = 4294967295


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def http_get(url, timeout=300, stream=False):
    return requests.get(url, timeout=timeout, stream=stream,
                        headers={"User-Agent": UA})


def download(url, path, max_age=86400):
    """Скачивает с кэшированием на диск. Возвращает путь к файлу."""
    if os.path.exists(path) and (time.time() - os.path.getmtime(path)) < max_age:
        log(f"кэш: {os.path.basename(path)}")
        return path
    log(f"качаю: {url}")
    r = http_get(url, stream=True)
    r.raise_for_status()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".part"
    with open(tmp, "wb") as f:
        for chunk in r.iter_content(1 << 16):
            f.write(chunk)
    os.replace(tmp, path)
    return path


def clean_domain(value, drop_freemail=False):
    """Нормализует URL или email в голый домен.

    drop_freemail=True нужен только для доменов из email (whois): там
    yandex.ru означает 'админ завёл почту на Яндексе', а не сайт оператора.
    Для website из PeeringDB фильтр не применяется.
    """
    if not value:
        return None
    v = str(value).strip().lower()
    if "@" in v:
        v = v.rsplit("@", 1)[-1]
    v = re.sub(r"^[a-z]+://", "", v)
    v = v.split("/")[0].split("?")[0].split(":")[0]
    v = re.sub(r"^www\d?\.", "", v).strip(". ")
    if not v or "." not in v or " " in v:
        return None
    if drop_freemail and v in FREEMAIL:
        return None
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,24}", v):
        return None
    return v


def guess_type(name, domain):
    blob = f"{name or ''} {domain or ''}"
    if GOV_HINTS.search(blob):
        return "government"
    if EDU_HINTS.search(blob):
        return "education"
    if HOSTING_HINTS.search(blob):
        return "hosting"
    if ISP_HINTS.search(blob):
        return "isp"
    return "business"


def pretty_name(raw):
    """'VDSKA-AS Vdska Hosting' -> 'Vdska Hosting'."""
    if not raw:
        return None
    n = re.sub(r"\s+", " ", str(raw).strip().strip(","))
    m = re.match(r"^([A-Z0-9-]{2,}?-AS\d*|AS-[A-Z0-9-]+)\s+(.{3,})$", n)
    if m:
        n = m.group(2)
    return n[:255] or None


# RIPE asn.txt формат «ХЕНДЛ - Полное имя»: 'GOOGLE - Google LLC',
# 'LEVEL3 - Level 3 Parent, LLC'. Хендл (заглавные/цифры/дефис) идёт в
# autonomous_system_organization, полное имя — в isp/name.
AS_HANDLE = re.compile(r"^([A-Z0-9][A-Z0-9-]{1,})\s+-\s+(.+)$")


def split_handle(raw):
    """'GOOGLE - Google LLC' -> ('GOOGLE', 'Google LLC').
    Если формата «ХЕНДЛ - имя» нет -> (None, raw)."""
    if not raw:
        return None, None
    s = re.sub(r"\s+", " ", str(raw).strip().strip(","))
    m = AS_HANDLE.match(s)
    if m:
        return m.group(1), m.group(2).strip()
    return None, s


# --------------------------------------------------------------------------- #
# 1. префиксы и имена AS: готовая GeoLite2-ASN.mmdb
# --------------------------------------------------------------------------- #

def iter_mmdb_networks(path):
    """Итерирует (network_str, record) по готовой mmdb."""
    try:
        import maxminddb
    except ImportError:
        sys.exit("нужен maxminddb: pip install maxminddb")
    with maxminddb.open_database(path) as reader:
        for network, record in reader:
            yield str(network), record


def count_cross_asn_overlaps(net2asn):
    """Считает вложенные префиксы, назначенные РАЗНЫМ ASN (контейнер + более
    специфичный). CIDR-префиксы либо вложены, либо не пересекаются, так что
    «пересечение» = вложенность. O(n log n) развёрткой по интервалам."""
    cnt = 0
    for version in (4, 6):
        ivs = [(int(n.network_address), int(n.broadcast_address), a)
               for n, a in net2asn.items() if n.version == version]
        ivs.sort(key=lambda t: (t[0], -t[1]))    # контейнер раньше вложенного
        stack = []                               # (end, asn) охватывающих интервалов
        for start, end, asn in ivs:
            while stack and stack[-1][0] < start:
                stack.pop()
            if stack and stack[-1][1] != asn:
                cnt += 1
            stack.append((end, asn))
    return cnt


def collapse_by_asn(net2asn, meta):
    """net->asn (уже без точных дублей и конфликтов) + метаданные ->
    (prefix_rows, per_asn).

    Схлопывает смежные/вложенные префиксы ОДНОГО ASN
    (ipaddress.collapse_addresses) и считает агрегаты по итоговому набору,
    поэтому num_ips/prefixes точны и не зависят от дублей в источнике.
    """
    overlaps = count_cross_asn_overlaps(net2asn)
    if overlaps:
        log(f"! меж-ASN вложенностей: {overlaps} (в mmdb победит более "
            f"специфичный префикс; в JSON-агрегатах контейнер их не вычитает)")

    by_asn = defaultdict(list)
    for net, asn in net2asn.items():
        by_asn[asn].append(net)

    prefix_rows = []
    per_asn = {}
    collapsed = 0
    for asn, nets in by_asn.items():
        cols = []
        for version in (4, 6):
            same = [n for n in nets if n.version == version]
            if same:
                cols.extend(ipaddress.collapse_addresses(same))
        collapsed += len(nets) - len(cols)
        m = meta.get(asn, {})
        e = {"name": m.get("name"), "country": m.get("country"), "num_ips": 0}
        for net in cols:
            prefix_rows.append((net, asn))
            if net.version == 4:
                e["num_ips"] += net.num_addresses
        per_asn[asn] = e

    if collapsed:
        log(f"схлопнуто смежных/вложенных префиксов одного ASN: {collapsed}")
    log(f"префиксов: {len(prefix_rows)}, ASN: {len(per_asn)}")
    return prefix_rows, per_asn


def read_asn_mmdb(path, with_v6=True):
    """Читает готовую MaxMind GeoLite2/GeoIP2-ASN базу как источник префиксов и
    имён AS: берёт autonomous_system_number -> префикс и
    autonomous_system_organization -> имя AS."""
    if not os.path.exists(path):
        sys.exit(f"нет ASN-базы: {path}")

    net2asn = {}
    meta = defaultdict(lambda: {"name": None, "country": None})
    skipped = 0

    log(f"читаю MaxMind ASN-базу: {os.path.basename(path)}")
    for network, record in iter_mmdb_networks(path):
        rec = record or {}
        asn = rec.get("autonomous_system_number")
        if not asn:
            skipped += 1
            continue
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError:
            continue
        if net.version == 6 and not with_v6:
            continue

        net2asn[net] = int(asn)                # одна запись на сеть, дублей нет
        org = (rec.get("autonomous_system_organization") or "").strip()
        e = meta[int(asn)]
        if not e["name"] and org:
            e["name"] = org

    if skipped:
        log(f"пропущено сетей без ASN: {skipped}")
    log(f"из ASN-базы: {len(net2asn)} сетей, {len(meta)} ASN")
    return collapse_by_asn(net2asn, meta)


# --------------------------------------------------------------------------- #
# 2. имена всех AS: RIPE asn.txt
# --------------------------------------------------------------------------- #

def read_asnames(cache_dir, max_age=86400):
    """'50053 VDSKA-AS Vdska Hosting, NL' -> имя + страна."""
    try:
        path = download(ASNAMES_URL, os.path.join(cache_dir, "asn.txt"),
                        max_age=max_age)
    except Exception as exc:
        log(f"! asn.txt недоступен ({exc}), продолжаю без него")
        return {}

    out = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or " " not in line:
                continue
            num, _, rest = line.partition(" ")
            if not num.isdigit():
                continue
            cc = None
            if "," in rest:
                head, _, tail = rest.rpartition(",")
                tail = tail.strip()
                if len(tail) == 2 and tail.isalpha():
                    cc = tail.upper()
                    rest = head
            handle, full = split_handle(rest)       # 'GOOGLE - Google LLC'
            name = pretty_name(full)
            if name and name.upper().strip("- ") in ("RESERVED", "UNALLOCATED", "NA"):
                name = handle = None
            out[int(num)] = {"name": name, "handle": handle,
                             "country": cc if cc != "ZZ" else None}
    log(f"asn.txt: {len(out)} ASN")
    return out


# --------------------------------------------------------------------------- #
# 3. delegated-extended
# --------------------------------------------------------------------------- #

def read_rir(cache_dir, max_age=86400):
    meta = {}
    for rir, url in RIR_DELEGATED.items():
        try:
            path = download(url, os.path.join(cache_dir, f"delegated-{rir}.txt"),
                            max_age=max_age)
        except Exception as exc:
            log(f"! {rir} недоступен ({exc}), пропускаю")
            continue

        added = 0
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line or line[0] == "#":
                    continue
                fl = line.rstrip("\n").split("|")
                if len(fl) < 7 or fl[2] != "asn":
                    continue
                if fl[6] not in ("allocated", "assigned"):
                    continue
                try:
                    start, count = int(fl[3]), int(fl[4])
                except ValueError:
                    continue
                cc = fl[1].upper() if len(fl[1]) == 2 else None
                for asn in range(start, start + count):
                    meta[asn] = {"country": cc}
                    added += 1
        log(f"{rir}: {added} ASN")
    return meta


# --------------------------------------------------------------------------- #
# 4. PeeringDB
# --------------------------------------------------------------------------- #

def read_peeringdb(cache_dir, api_key=None, max_age=604800):
    path = os.path.join(cache_dir, "peeringdb-net.json")
    if os.path.exists(path) and (time.time() - os.path.getmtime(path)) < max_age:
        log("кэш: peeringdb-net.json")
        data = json.load(open(path, encoding="utf-8"))
    else:
        log("качаю: peeringdb /api/net")
        headers = {"User-Agent": UA}
        if api_key:
            headers["Authorization"] = f"Api-Key {api_key}"
        try:
            r = requests.get("https://www.peeringdb.com/api/net",
                             timeout=300, headers=headers)
            r.raise_for_status()
            data = r.json()
            os.makedirs(cache_dir, exist_ok=True)
            json.dump(data, open(path, "w", encoding="utf-8"))
        except Exception as exc:
            log(f"! peeringdb недоступен ({exc}), продолжаю без него")
            return {}

    out = {}
    for n in data.get("data", []):
        asn = n.get("asn")
        if not asn:
            continue
        info = (n.get("info_type") or "").strip().lower()
        out[int(asn)] = {
            "name": (n.get("name") or "").strip() or None,
            "domain": clean_domain(n.get("website")),
            "type": PDB_TYPE_MAP.get(info),
        }
    log(f"peeringdb: {len(out)} ASN")
    return out


# --------------------------------------------------------------------------- #
# 5. bulk-whois RIR (RPSL) — домены
# --------------------------------------------------------------------------- #

def _parse_rpsl(path, asn2org, asn2dom, org2dom):
    """Стримит gz-дамп RPSL, разбивая на объекты по пустой строке. Из aut-num
    берёт asn -> org-handle и прямой e-mail/abuse-mailbox; из organisation
    берёт handle -> e-mail. Домен = домен из почты (freemail отбрасывается)."""
    kind = asn = org = handle = None
    dom = None

    def flush():
        nonlocal kind, asn, org, handle, dom
        if kind == "aut-num" and asn is not None:
            if org:
                asn2org[asn] = org
            if dom:
                asn2dom.setdefault(asn, dom)
        elif kind == "org" and handle and dom:
            org2dom.setdefault(handle, dom)
        kind = asn = org = handle = dom = None

    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():                         # конец объекта
                flush()
                continue
            key, _, val = line.partition(":")
            key = key.strip().lower()
            val = val.strip()
            if key == "aut-num":
                kind = "aut-num"
                m = re.match(r"AS(\d+)\b", val, re.I)
                if m:
                    asn = int(m.group(1))
            elif key == "organisation":
                kind = "org"
                handle = val
            elif key == "org":
                org = val
            elif key in ("e-mail", "abuse-mailbox") and not dom:
                dom = clean_domain(val, drop_freemail=True)
        flush()


def read_whois_bulk(cache_dir, max_age=86400):
    """ASN -> домен из bulk-whois RIPE/APNIC/AFRINIC. Один-два дампа на RIR
    вместо десятков тысяч RDAP-запросов."""
    asn2org, asn2dom, org2dom = {}, {}, {}
    for rir, urls in WHOIS_BULK.items():
        for url in urls:
            fname = f"whois-{rir}-{os.path.basename(url)}"
            try:
                path = download(url, os.path.join(cache_dir, fname), max_age=max_age)
            except Exception as exc:
                log(f"! whois {rir} недоступен ({exc}), пропускаю")
                continue
            log(f"разбираю whois: {fname}")
            _parse_rpsl(path, asn2org, asn2dom, org2dom)

    out = {}
    for asn in set(asn2dom) | set(asn2org):
        d = asn2dom.get(asn) or org2dom.get(asn2org.get(asn))
        if d:
            out[asn] = d
    log(f"whois-bulk: домен у {len(out)} ASN "
        f"(aut-num: {len(asn2dom)}, org: {len(org2dom)})")
    return out


# --------------------------------------------------------------------------- #
# сборка и вывод
# --------------------------------------------------------------------------- #

def merge(per_asn, asnames, rir_meta, pdb, extra_domains):
    rows = []
    for asn in sorted(per_asn):
        g = per_asn[asn]
        an = asnames.get(asn, {})
        r = rir_meta.get(asn, {})
        p = pdb.get(asn, {})

        # Полное имя оператора (isp/name): приоритет — RIPE полное имя
        # (после отделения хендла) -> имя из источника префиксов
        # (MaxMind org) -> PeeringDB.
        full = (pretty_name(an.get("name")) or pretty_name(g.get("name"))
                or p.get("name") or f"AS{asn}")
        # autonomous_system_organization: хендл AS из RIPE ("GOOGLE"),
        # иначе — то же полное имя.
        as_org = an.get("handle") or full
        isp = full
        # organization: в открытых данных нет отдельного per-block org -> = isp.
        organization = full
        domain = p.get("domain") or extra_domains.get(asn)
        country = r.get("country") or an.get("country") or g.get("country")
        atype = p.get("type") or guess_type(isp, domain)

        rows.append({
            "asn": asn,
            "as_org": as_org[:255],
            "isp": isp[:255],
            "organization": organization[:255],
            "domain": domain,
            "country": country,
            "num_ips": min(g["num_ips"], UINT_MAX),
            "type": atype,
        })
    return rows


def asn_extended(rows):
    """Расширенный ASN-справочник под таблицу blocked_asns панели. Одна запись
    на AS. Схема: {asn, isp, domain, country, num_ips, type, blocked}.
      id      — autoincrement на стороне БД, здесь не выводится;
      blocked — флаг, по умолчанию 0 (панель не импортирует это поле)."""
    return [{
        "asn": r["asn"],
        "isp": r["isp"],                            # имя оператора (колонка isp)
        "domain": r.get("domain"),
        "country": r.get("country"),
        "num_ips": r.get("num_ips"),
        "type": r.get("type"),
        "blocked": 0,
    } for r in rows]


def write_json(rows, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=1)
    log(f"записано: {path}")


def write_mmdb(prefix_rows, rows_by_asn, path):
    """Своя база IP->ISP в формате MaxMind DB (схема GeoIP2-ISP, 4 поля).
    Читается любым mmdb-клиентом — прямая замена платной GeoIP2-ISP.mmdb."""
    try:
        from mmdb_writer import MMDBWriter
        from netaddr import IPSet
    except ImportError:
        sys.exit("для --mmdb-out нужно: pip install mmdb_writer netaddr")

    log(f"собираю mmdb из {len(prefix_rows)} префиксов")
    w = MMDBWriter(ip_version=6, ipv4_compatible=True,
                   database_type="GeoIP2-ISP", languages=["en"],
                   description={"en": "self-built ISP database (open data)"})

    for net, asn in prefix_rows:
        r = rows_by_asn.get(asn) or {}
        as_org = r.get("as_org") or f"AS{asn}"
        isp = r.get("isp") or as_org
        w.insert_network(IPSet([str(net)]), {
            "autonomous_system_number": asn,
            "autonomous_system_organization": as_org,
            "isp": isp,
            "organization": r.get("organization") or isp,
        })

    w.to_db_file(path)
    log(f"записано: {path} ({os.path.getsize(path) / 1048576:.1f} МБ)")


# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(
        description="Сборка ASN/ISP базы из открытых источников (без MaxMind/ipinfo)")
    ap.add_argument("--asn-mmdb", dest="asn_mmdb", metavar="PATH", required=True,
                    help="источник префиксов и имён AS: готовая GeoLite2-ASN.mmdb")
    ap.add_argument("--asn-json", dest="asn_json", metavar="PATH",
                    help="ASN-справочник под таблицу blocked_asns: "
                         "{asn,isp,domain,country,num_ips,type,blocked}")
    ap.add_argument("--mmdb-out", dest="mmdb_out", metavar="PATH",
                    help="свой IP->ISP mmdb (замена GeoIP2-ISP.mmdb)")
    ap.add_argument("--cache-dir", default="./asn_cache",
                    help="каталог кэша скачанных источников")
    ap.add_argument("--pdb-key", help="API-ключ PeeringDB (опционально)")
    ap.add_argument("--no-v6", action="store_true", help="только IPv4")
    args = ap.parse_args()

    if not (args.asn_json or args.mmdb_out):
        ap.error("укажите хотя бы один выход: --asn-json / --mmdb-out")

    t0 = time.time()
    os.makedirs(args.cache_dir, exist_ok=True)

    prefix_rows, per_asn = read_asn_mmdb(args.asn_mmdb, with_v6=not args.no_v6)

    asnames = read_asnames(args.cache_dir)
    rir_meta = read_rir(args.cache_dir)
    pdb = read_peeringdb(args.cache_dir, args.pdb_key)
    whois_domains = read_whois_bulk(args.cache_dir)

    rows = merge(per_asn, asnames, rir_meta, pdb, whois_domains)

    n = len(rows) or 1

    def stat(k):
        return sum(1 for r in rows if r[k])

    log("-" * 52)
    log(f"ASN всего:  {len(rows)}")
    log(f"domain:     {stat('domain')} ({stat('domain') * 100 // n}%)")
    log(f"country:    {stat('country')} ({stat('country') * 100 // n}%)")
    log("-" * 52)

    if args.asn_json:
        write_json(asn_extended(rows), args.asn_json)
    if args.mmdb_out:
        write_mmdb(prefix_rows, {r["asn"]: r for r in rows}, args.mmdb_out)

    log(f"готово за {time.time() - t0:.1f} c")


if __name__ == "__main__":
    main()
