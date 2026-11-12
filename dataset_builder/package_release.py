"""Assemble the public dataset release (folder + zip) from the labelled train/eval runs.

Reads the runs named in release_docs/release_config.json, converts them into the release layout,
renders the documentation templates with computed statistics, writes checksums, and zips the
result. Nothing under dataset_builder/runs/ is modified.

Output: dataset_builder/release/<slug>-v<version>/ and dataset_builder/release/<slug>-v<version>.zip
"""
import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..'))
DOCS = os.path.join(HERE, 'release_docs')

CC_BY_NOTICE = """Creative Commons Attribution 4.0 International (CC BY 4.0)

Copyright (c) {year} {authors}

This dataset is licensed under the Creative Commons Attribution 4.0 International License.

You are free to:
  Share - copy and redistribute the material in any medium or format, for any purpose.
  Adapt - remix, transform, and build upon the material for any purpose, even commercially.

Under the following terms:
  Attribution - You must give appropriate credit, provide a link to the license, and indicate if
  changes were made. You may do so in any reasonable manner, but not in any way that suggests the
  licensor endorses you or your use.

  No additional restrictions - You may not apply legal terms or technological measures that legally
  restrict others from doing anything the license permits.

Full legal code: https://creativecommons.org/licenses/by/4.0/legalcode
"""


def real_commands(events):
    return [(e.get('input') or '').strip() for e in events
            if e.get('eventid') == 'cowrie.command.input' and (e.get('input') or '').strip() not in ('', 'exit')]


def read_jsonl(path):
    with open(path, 'r', encoding='utf-8') as f:
        return [json.loads(line) for line in f if line.strip()]


def build_split(name, run_dir, out_dir):
    """Write one split into the release and return its statistics."""
    split_out = os.path.join(out_dir, name)
    os.makedirs(split_out)
    labelled = os.path.join(run_dir, 'labelled')

    with open(os.path.join(labelled, 'behavior_features.csv'), newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    with open(os.path.join(labelled, 'sessions_labelled.json'), encoding='utf-8') as f:
        sessions = json.load(f)
    with open(os.path.join(labelled, 'label_report.json'), encoding='utf-8') as f:
        report = json.load(f)
    with open(os.path.join(run_dir, 'run_meta.json'), encoding='utf-8') as f:
        meta = json.load(f)
    manifest = read_jsonl(os.path.join(run_dir, 'manifest.jsonl'))

    ids = [r['session_id'] for r in rows]
    if set(ids) != set(sessions):
        raise SystemExit(f"{name}: features.csv and sessions_labelled.json describe different sessions.")
    if report.get('empty_dropped'):
        raise SystemExit(f"{name}: run was built with --cap-empty ({report['empty_dropped']} sessions "
                         f"dropped). Rebuild it without --cap-empty before packaging.")

    shutil.copyfile(os.path.join(labelled, 'behavior_features.csv'), os.path.join(split_out, 'features.csv'))

    categories, zero_cmd = {}, {}
    with open(os.path.join(split_out, 'sessions.jsonl'), 'w', encoding='utf-8') as f:
        for row in rows:  # same order as features.csv
            sid = row['session_id']
            events = sessions[sid]
            cmds = real_commands(events)
            record = {
                'session_id': sid,
                'attack_cat': row['attack_cat'],
                'label': int(row['label']),
                'auth_success': any(e.get('eventid') == 'cowrie.login.success' for e in events),
                'n_commands': len(cmds),
                'commands': cmds,
                # Labels live at the top level; strip the copies injected onto each event.
                'events': [{k: v for k, v in e.items() if k not in ('attack_cat', 'label')} for e in events],
            }
            f.write(json.dumps(record, ensure_ascii=False) + '\n')
            cat = row['attack_cat']
            categories[cat] = categories.get(cat, 0) + 1
            if not cmds:
                zero_cmd[cat] = zero_cmd.get(cat, 0) + 1

    shutil.copyfile(os.path.join(run_dir, 'manifest.jsonl'), os.path.join(split_out, 'generation_manifest.jsonl'))
    shutil.copyfile(os.path.join(run_dir, 'run_meta.json'), os.path.join(split_out, 'run_meta.json'))

    return {
        'sessions': len(rows),
        'generated_sessions': len(manifest),
        'generation_errors': sum(m['status'] != 'ok' for m in manifest),
        'seed': meta.get('seed'),
        'speed': meta.get('speed'),
        'include_held_out': meta.get('include_held_out'),
        'collected_from_utc': manifest[0]['start_utc'],
        'collected_to_utc': manifest[-1]['end_utc'],
        'categories': dict(sorted(categories.items(), key=lambda kv: -kv[1])),
        'zero_command_sessions': sum(zero_cmd.values()),
        'zero_command_by_category': zero_cmd,
        'matched_by_command': report.get('by_command'),
        'matched_by_time_no_command': report.get('by_time_nocmd'),
        'low_confidence_matches': report.get('low_confidence'),
        'out_of_window_dropped': report.get('out_of_window_dropped'),
    }


def write_categories(profiles, path):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['attack_cat', 'label', 'held_out', 'generation_profile', 'description'])
        for p in profiles:
            w.writerow([p['attack_cat'], p['label'], str(p.get('held_out', False)).lower(),
                        p['name'], p['description']])


def render(template_path, values, out_path):
    with open(template_path, encoding='utf-8') as f:
        text = f.read().format_map(values)
    leftover = re.findall(r'\{[a-z_]+\}', text)
    if leftover:
        raise SystemExit(f"Unfilled placeholders in {os.path.basename(template_path)}: {sorted(set(leftover))}")
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(text)


def tree(root):
    lines = [os.path.basename(root) + '/']
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        depth = os.path.relpath(dirpath, root).count(os.sep) + (0 if dirpath == root else 1)
        if dirpath != root:
            lines.append('    ' * depth + os.path.basename(dirpath) + '/')
        for name in sorted(filenames):
            lines.append('    ' * (depth + 1) + name)
    return '\n'.join(lines)


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description='Assemble the public dataset release.')
    parser.add_argument('--config', default=os.path.join(DOCS, 'release_config.json'))
    parser.add_argument('--out-root', default=os.path.join(HERE, 'release'))
    args = parser.parse_args()

    with open(args.config, encoding='utf-8') as f:
        cfg = json.load(f)
    with open(os.path.join(HERE, 'profiles_v2.json'), encoding='utf-8') as f:
        profiles = json.load(f)['profiles']

    name = f"{cfg['slug']}-v{cfg['version']}"
    out = os.path.join(args.out_root, name)
    if os.path.exists(out):
        shutil.rmtree(out)  # generated output only; the runs are never touched
    os.makedirs(out)

    print(f"Building {name}")
    stats = {'title': cfg['title'], 'version': cfg['version'], 'splits': {}}
    for split, run in cfg['splits'].items():
        print(f"  split {split} <- {run}")
        stats['splits'][split] = build_split(split, os.path.join(REPO_ROOT, run), out)

    train_ids = {json.loads(l)['session_id'] for l in open(os.path.join(out, 'train', 'sessions.jsonl'), encoding='utf-8')}
    eval_ids = {json.loads(l)['session_id'] for l in open(os.path.join(out, 'eval', 'sessions.jsonl'), encoding='utf-8')}
    stats['shared_session_ids_between_splits'] = len(train_ids & eval_ids)
    if stats['shared_session_ids_between_splits']:
        raise SystemExit("train and eval share session IDs; the splits are not independent.")

    meta_dir = os.path.join(out, 'metadata')
    os.makedirs(meta_dir)
    shutil.copyfile(os.path.join(DOCS, 'data_dictionary.csv'), os.path.join(meta_dir, 'data_dictionary.csv'))
    shutil.copyfile(os.path.join(HERE, 'profiles_v2.json'), os.path.join(meta_dir, 'generation_profiles.json'))
    shutil.copyfile(os.path.join(REPO_ROOT, 'cowrie', 'userdb.txt'), os.path.join(meta_dir, 'cowrie_userdb.txt'))
    write_categories(profiles, os.path.join(meta_dir, 'categories.csv'))
    with open(os.path.join(meta_dir, 'dataset_stats.json'), 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2)

    tr, ev = stats['splits']['train'], stats['splits']['eval']
    total = tr['sessions'] + ev['sessions']
    zero_total = tr['zero_command_sessions'] + ev['zero_command_sessions']
    cat_label = {p['attack_cat']: p['label'] for p in profiles}
    all_cats = sorted(set(tr['categories']) | set(ev['categories']),
                      key=lambda c: (cat_label.get(c, 1), -(tr['categories'].get(c, 0) + ev['categories'].get(c, 0))))
    held = {p['attack_cat'] for p in profiles if p.get('held_out')}

    def split_row(label, s):
        return (f"| {label} | {s['sessions']:,} | {s['sessions'] - s['zero_command_sessions']:,} | "
                f"{len(s['categories'])} | {s['generated_sessions']:,} generated sessions, seed {s['seed']} |")

    authors = cfg['authors']
    values = {
        'title': cfg['title'], 'version': cfg['version'], 'release_date': cfg['release_date'],
        'doi': cfg['doi'], 'repo_url': cfg['repo_url'], 'supervisor': cfg['supervisor'],
        'train_seed': tr['seed'], 'eval_seed': ev['seed'],
        'split_table': '\n'.join([split_row('train', tr), split_row('eval', ev)]),
        'category_table': '\n'.join(
            f"| `{c}`{' (held out)' if c in held else ''} | {cat_label.get(c, '?')} | "
            f"{tr['categories'].get(c, 0):,} | {ev['categories'].get(c, 0):,} |" for c in all_cats),
        'total_sessions': f"{total:,}", 'zero_cmd_total': f"{zero_total:,}",
        'zero_cmd_pct': f"{100 * zero_total / total:.0f}%",
        'authors_md': '\n'.join(f"- {a}" for a in authors),
        'citation_text': (f"{', '.join(authors)} ({cfg['release_date'][:4]}). *{cfg['title']}* "
                          f"(Version {cfg['version']}) [Data set]. Zenodo. {cfg['doi']}"),
        'cowrie_image_created': cfg.get('cowrie_image_created', 'unknown'),
        'cowrie_revision': cfg.get('cowrie_revision', 'unknown'),
        'runs_table': '\n'.join(
            f"| {split} | {s['seed']} | {s['generated_sessions']:,} | "
            f"{'included' if s['include_held_out'] else 'excluded'} | {s['speed']:g} | "
            f"{s['collected_from_utc'][:19].replace('T', ' ')} to {s['collected_to_utc'][11:19]} |"
            for split, s in stats['splits'].items()),
    }

    docs_out = os.path.join(out, 'docs')
    os.makedirs(docs_out)
    shutil.copyfile(os.path.join(DOCS, 'ANNOTATION_GUIDELINES.md'), os.path.join(docs_out, 'ANNOTATION_GUIDELINES.md'))
    render(os.path.join(DOCS, 'COLLECTION_PROTOCOL.md'), values, os.path.join(docs_out, 'COLLECTION_PROTOCOL.md'))

    with open(os.path.join(out, 'LICENSE'), 'w', encoding='utf-8') as f:
        f.write(CC_BY_NOTICE.format(year=cfg['release_date'][:4], authors=', '.join(authors)))

    with open(os.path.join(out, 'CHANGELOG.md'), 'w', encoding='utf-8') as f:
        f.write(f"# Changelog\n\n## {cfg['version']} - {cfg['release_date']}\n\n")
        f.writelines(f"- {c}\n" for c in cfg['changes'])
        f.write("- Generated from repository commit recorded in the Zenodo release notes.\n")

    with open(os.path.join(out, 'CITATION.cff'), 'w', encoding='utf-8') as f:
        f.write("cff-version: 1.2.0\n")
        f.write('message: "If you use this dataset, please cite it as below."\n')
        f.write("type: dataset\n")
        f.write(f'title: "{cfg["title"]}"\n')
        f.write(f'version: "{cfg["version"]}"\n')
        f.write(f"date-released: {cfg['release_date']}\n")
        f.write(f"license: {cfg['license']}\n")
        f.write(f'repository-code: "{cfg["repo_url"]}"\n')
        f.write("authors:\n")
        for a in authors:
            f.write(f'  - given-names: "{a}"\n    affiliation: "{cfg["affiliation"]}"\n')
        f.write("keywords:\n")
        f.writelines(f'  - "{k}"\n' for k in cfg['keywords'])
        if cfg['doi'].startswith('10.'):
            f.write(f'doi: "{cfg["doi"]}"\n')

    # README last but one, so its tree lists everything except the checksum file it precedes.
    open(os.path.join(out, 'README.md'), 'w').close()
    open(os.path.join(out, 'SHA256SUMS.txt'), 'w').close()
    values['tree'] = tree(out)
    render(os.path.join(DOCS, 'README.template.md'), values, os.path.join(out, 'README.md'))

    sums = []
    for dirpath, _, filenames in os.walk(out):
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, out).replace(os.sep, '/')
            if rel != 'SHA256SUMS.txt':
                sums.append(f"{sha256(path)}  {rel}")
    with open(os.path.join(out, 'SHA256SUMS.txt'), 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(sorted(sums, key=lambda s: s.split('  ', 1)[1])) + '\n')

    zip_path = out + '.zip'
    if os.path.exists(zip_path):
        os.remove(zip_path)
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
        for dirpath, _, filenames in os.walk(out):
            for fn in sorted(filenames):
                path = os.path.join(dirpath, fn)
                z.write(path, os.path.relpath(path, args.out_root))

    print(f"\nRelease folder: {out}")
    print(f"Release zip:    {zip_path} ({os.path.getsize(zip_path) / 1e6:.1f} MB)")
    print(f"train: {tr['sessions']:,} sessions | eval: {ev['sessions']:,} sessions | "
          f"zero-command: {zero_total:,} | shared IDs: {stats['shared_session_ids_between_splits']}")


if __name__ == '__main__':
    main()
