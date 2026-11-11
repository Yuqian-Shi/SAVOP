"""Read-only, loopback-only AS map explorer. No telemetry or external assets."""
import argparse
from contextlib import closing
import csv
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import sqlite3
from urllib.parse import parse_qs, urlsplit

from fetch_sources import sha256

LAYERS = ("ipv4", "ipv6", "historical")


def connect(path):
    db = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    return db


def rows(db, sql, params=()):
    return [dict(r) for r in db.execute(sql, params)]


def decode_edge(row):
    row = dict(row)
    for key in ("inferred_sources", "observed_sources"):
        row[key] = json.loads(row[key])
    return row


def incident(db, layer, asn):
    # Explicit UNION permits both endpoint indexes; the OR form may scan a layer
    # once per displayed node on SQLite, making 80-node views take seconds.
    found = [decode_edge(r) for r in db.execute("SELECT * FROM edges WHERE layer=? AND u=? UNION ALL SELECT * FROM edges WHERE layer=? AND v=?", (layer, asn, layer, asn))]
    # Sorting here prevents SQLite's ORDER BY planner choosing a layer-wide
    # primary-key scan for the v branch instead of the endpoint index.
    return sorted(found, key=lambda e: (e["u"], e["v"]))


def match(edge, evidence):
    return evidence == "all" or bool(edge["observed_sources"] if evidence == "observed" else edge["inferred_sources"])


def neighborhood(db, layer, asn, hops=1, limit=100, evidence="all"):
    if layer not in LAYERS or evidence not in ("all", "observed", "inferred"):
        raise ValueError("Unknown layer/evidence filter")
    if hops not in (1, 2) or not 2 <= limit <= 250:
        raise ValueError("hops must be 1 or 2; limit must be 2..250")
    if not db.execute("SELECT 1 FROM nodes WHERE layer=? AND asn=?", (layer, asn)).fetchone():
        raise LookupError(f"AS{asn} not present in this layer; absence is not proof of nonexistence")
    selected, frontier = {asn}, {asn}
    first_neighbors = set()
    truncated = False
    for hop in range(hops):
        candidates = set()
        for n in sorted(frontier):
            for e in incident(db, layer, n):
                if match(e, evidence):
                    candidates.add(e["v"] if n == e["u"] else e["u"])
        if hop == 0:
            first_neighbors = candidates - {asn}
        candidates -= selected
        room = limit - len(selected)
        # Stable ASN order is for display only, not experimental sampling.
        chosen = set(sorted(candidates)[:room])
        truncated |= len(chosen) < len(candidates)
        selected |= chosen
        frontier = chosen
        if truncated and len(selected) == limit:
            break
        if not frontier:
            break
    found, boundary = {}, set()
    for n in selected:
        for e in incident(db, layer, n):
            if not match(e, evidence):
                continue
            key = (e["u"], e["v"])
            if e["u"] in selected and e["v"] in selected:
                found[key] = e
            else:
                boundary.add(key)
    placeholders = ",".join("?" for _ in selected)
    nodes = rows(db, f"SELECT * FROM nodes WHERE layer=? AND asn IN ({placeholders}) ORDER BY asn", (layer, *sorted(selected)))
    return {"layer": layer, "center": asn, "hops_requested": hops, "display_limit": limit,
            "evidence_filter": evidence, "nodes": nodes, "edges": [found[k] for k in sorted(found)],
            "first_hop_total": len(first_neighbors), "truncated": truncated,
            "boundary_edges_not_drawn": len(boundary),
            "purpose": "bounded display, NOT an experiment sample",
            "source_note": "Each edge points to source IDs; /api/sources provides hashes/URLs/dates. No BGP/forwarding reachability is inferred."}


def handler(database):
    class Handler(BaseHTTPRequestHandler):
        def send(self, status, body, content_type="application/json; charset=utf-8", filename=None):
            if not isinstance(body, bytes):
                body = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'")
            if filename:
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            # Defend against DNS rebinding; this tool is intentionally not a LAN service.
            host = self.headers.get("Host", "").split(":")[0]
            if host not in ("127.0.0.1", "localhost"):
                self.send(403, {"error": "loopback host required"})
                return
            url = urlsplit(self.path)
            q = parse_qs(url.query)
            val = lambda key, default="": q.get(key, [default])[0]
            try:
                if url.path in ("/", "/app.js", "/style.css"):
                    name = "index.html" if url.path == "/" else url.path[1:]
                    ct = {"index.html": "text/html", "app.js": "text/javascript", "style.css": "text/css"}[name]
                    self.send(200, Path(__file__).with_name(name).read_bytes(), ct + "; charset=utf-8")
                    return
                with closing(connect(database)) as db:
                    layer = val("layer", "ipv4")
                    if layer not in LAYERS:
                        raise ValueError("Unknown layer")
                    if url.path == "/api/summary":
                        result = json.loads(db.execute("SELECT value FROM metadata WHERE key='quality'").fetchone()[0])
                        details = Path(database).with_name("quality-details.json")
                        if details.exists():
                            result["additional_diagnostics"] = json.loads(details.read_text(encoding="utf-8"))
                    elif url.path == "/api/sources":
                        result = [json.loads(r[0]) for r in db.execute("SELECT metadata FROM sources ORDER BY id")]
                    elif url.path == "/api/graph":
                        result = neighborhood(db, layer, int(val("asn")), int(val("hops", "1")), int(val("limit", "100")), val("evidence", "all"))
                    elif url.path == "/api/as":
                        asn = int(val("asn"))
                        nodes = rows(db, "SELECT * FROM nodes WHERE layer=? AND asn=?", (layer, asn))
                        if not nodes:
                            raise LookupError("ASN absent from selected dataset")
                        offset = int(val("offset", "0"))
                        if offset < 0:
                            raise ValueError("Negative offset")
                        neighbors = incident(db, layer, asn)
                        prefixes = rows(db, "SELECT prefix,source FROM prefixes WHERE layer=? AND asn=? ORDER BY prefix,source LIMIT 100", (layer, asn))
                        prefix_total = db.execute("SELECT COUNT(DISTINCT prefix) FROM prefixes WHERE layer=? AND asn=?", (layer, asn)).fetchone()[0]
                        result = {"node": nodes[0], "neighbors": neighbors[offset:offset + 100], "offset": offset,
                                  "neighbor_total": len(neighbors), "prefix_sample": prefixes,
                                  "unique_observed_prefixes": prefix_total,
                                  "prefix_sample_row_limit": 100, "prefix_note": "Observed origin, not ownership/authorization/forwarding proof."}
                    elif url.path == "/api/edge":
                        u, v = sorted((int(val("u")), int(val("v"))))
                        result = {"claims": rows(db, "SELECT * FROM claims WHERE layer=? AND u=? AND v=?", (layer, u, v)),
                                  "observations": rows(db, "SELECT * FROM observations WHERE layer=? AND u=? AND v=?", (layer, u, v))}
                    elif url.path == "/api/export":
                        buf = io.StringIO(newline="")
                        writer = csv.writer(buf)
                        writer.writerow(["layer", "asn1", "asn2", "relation", "provider_asn", "inferred_sources", "observed_sources"])
                        writer.writerows(db.execute("SELECT * FROM edges WHERE layer=? ORDER BY u,v", (layer,)))
                        self.send(200, buf.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8", f"as-map-{layer}-edges.csv")
                        return
                    else:
                        self.send(404, {"error": "not found"})
                        return
                self.send(200, result)
            except (ValueError, LookupError) as e:
                self.send(400, {"error": str(e)})
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--port", type=int, default=18765)
    args = ap.parse_args()
    manifest = json.loads((args.data / "manifest.json").read_text(encoding="utf-8"))
    if manifest["status"] != "complete" or sha256(args.data / "map.sqlite") != manifest["artifacts"]["map.sqlite"]:
        raise ValueError("Data not complete or hash differs")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler(args.data / "map.sqlite"))
    print(f"AS map: http://127.0.0.1:{args.port} (read-only; Ctrl+C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
