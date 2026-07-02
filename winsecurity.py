import json
import re
import time
import urllib.request
import urllib.error
from datetime import datetime, date, timezone

def fetch_with_retry(url, retries=3, delay=2):
    req = urllib.request.Request(url, headers={'Accept': 'application/json'})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise e
            print(f"-> HTTP Error {e.code} for {url}. Attempt {attempt + 1}/{retries}...")
        except Exception as e:
            print(f"-> Connection error: {e} for {url}. Attempt {attempt + 1}/{retries}...")
        
        if attempt < retries - 1:
            wait_time = delay * (attempt + 1)
            print(f"Waiting {wait_time}s before retry...")
            time.sleep(wait_time)
            
    raise Exception(f"Failed to fetch {url} after {retries} attempts")

# Generate last 12 months (oldest first, so newest overwrites in case of revisions)
today = date.today()
month_ids = []
MONTHS = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
for i in range(11, -1, -1):
    m = today.month - i
    y = today.year
    while m <= 0:
        m += 12
        y -= 1
    month_name = MONTHS[m]
    month_ids.append(f"{y}-{month_name}")

print("Generating data for months:", month_ids)

cves_map = {}
products_table = []
product_to_idx = {}

def get_product_idx(name):
    if not name:
        return None
    if name not in product_to_idx:
        idx = len(products_table)
        products_table.append(name)
        product_to_idx[name] = idx
        return idx
    return product_to_idx[name]

def walk(branch, product_map):
    """Recursively walk the ProductTree branches and populate product_map."""
    if not branch:
        return
    for p in branch.get('FullProductName', []):
        product_map[p['ProductID']] = p['Value']
    for b in branch.get('Branch', []):
        walk(b, product_map)

def get_url_score(url):
    """Return a priority score for a Microsoft URL (higher = more preferred)."""
    if not url:
        return 0
    u_l = url.lower()
    if 'catalog.update.microsoft.com' in u_l: return 4
    if 'support.microsoft.com' in u_l: return 3
    if 'microsoft.com' in u_l: return 2
    return 1

for month_id in month_ids:
    url = f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{month_id}"
    print(f"Fetching: {url} ...")
    
    try:
        raw = fetch_with_retry(url)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"-> Month {month_id} not published yet (404). Skipping.")
            continue
        else:
            print(f"-> HTTP Error {e.code} fetching {month_id}. Aborting.")
            raise e
    except Exception as e:
        print(f"-> Error fetching {month_id}: {e}. Aborting.")
        raise e

    product_map = {}
    walk(raw.get('ProductTree', {}), product_map)

    vulns = raw.get('Vulnerability', [])
    for v in vulns:
        cve_id = v.get('CVE', '')
        if not cve_id:
            continue

        title = ''
        if v.get('Title') and v['Title'].get('Value'):
            title = v['Title']['Value']

        severity = ''
        for t in v.get('Threats', []):
            if t.get('Type') == 3:
                severity = (t.get('Description') or {}).get('Value', '')
                if severity:
                    break
        if not severity:
            for t in v.get('Threats', []):
                if t.get('Type') == 0:
                    severity = (t.get('Description') or {}).get('Value', '')
                    if severity:
                        break

        cvss = None
        for s in v.get('CVSSScoreSets', []):
            if s.get('BaseScore') and ('3.1' in s.get('Vector','') or '3.0' in s.get('Vector','')):
                try:
                    cvss = float(s['BaseScore'])
                    break
                except ValueError:
                    pass
        if cvss is None:
            for s in v.get('CVSSScoreSets', []):
                if s.get('BaseScore'):
                    try:
                        cvss = float(s['BaseScore'])
                        break
                    except ValueError:
                        pass

        products = []
        for ps in v.get('ProductStatuses', []):
            for pid in ps.get('ProductID', []):
                pname = product_map.get(pid, '')
                if pname and pname not in products:
                    products.append(pname)

        product = products[0] if products else ''

        date_str = ''
        revs = v.get('RevisionHistory', [])
        if revs:
            date_str = revs[0].get('Date', '')[:10]

        exploited = False
        for t in v.get('Threats', []):
            if t.get('Type') == 1:
                desc = (t.get('Description') or {}).get('Value', '')
                if 'exploited:yes' in desc.lower().replace(' ', ''):
                    exploited = True
                    break

        kb_map = {}
        for r in v.get('Remediations', []):
            desc_val = (r.get('Description') or {}).get('Value', '').strip()
            subtype_val = r.get('SubType', '').strip()
            url_str = r.get('URL', '').strip()
            fixed = r.get('FixedBuild', '').strip()
            pids = r.get('ProductID', [])

            # Robustly extract KB number
            kb_num = None
            if desc_val.upper().startswith('KB') and desc_val[2:].isdigit():
                kb_num = desc_val[2:]
            elif desc_val.isdigit() and 6 <= len(desc_val) <= 8:
                kb_num = desc_val
            elif subtype_val.upper().startswith('KB') and subtype_val[2:].isdigit():
                kb_num = subtype_val[2:]
            elif subtype_val.isdigit() and 6 <= len(subtype_val) <= 8:
                kb_num = subtype_val
            else:
                m = re.search(r'\b(?:KB)?(\d{6,8})\b', desc_val, re.IGNORECASE)
                if m:
                    kb_num = m.group(1)
                else:
                    m = re.search(r'\b(?:KB)?(\d{6,8})\b', subtype_val, re.IGNORECASE)
                    if m:
                        kb_num = m.group(1)
                    elif url_str:
                        m = re.search(r'(?:help/|q=KB|q=)(\d{6,8})\b', url_str, re.IGNORECASE)
                        if m:
                            kb_num = m.group(1)
                        else:
                            m = re.search(r'\b(\d{6,8})\b', url_str)
                            if m:
                                kb_num = m.group(1)

            if not kb_num:
                continue

            kb_products = [product_map.get(pid, '') for pid in pids if product_map.get(pid, '')]

            if kb_num not in kb_map:
                kb_map[kb_num] = {
                    'kb': kb_num,
                    'url': url_str,
                    'fixed_build': fixed,
                    'subtype': subtype_val,
                    'products': kb_products
                }
            else:
                # Merge products
                for pname in kb_products:
                    if pname and pname not in kb_map[kb_num]['products']:
                        kb_map[kb_num]['products'].append(pname)
                # Update URL if higher score
                if get_url_score(url_str) > get_url_score(kb_map[kb_num]['url']):
                    kb_map[kb_num]['url'] = url_str
                # Update fixed build if empty
                if not kb_map[kb_num]['fixed_build'] and fixed:
                    kb_map[kb_num]['fixed_build'] = fixed
                # Update subtype if new is better
                if (not kb_map[kb_num]['subtype'] or kb_map[kb_num]['subtype'].isdigit()) and subtype_val and not subtype_val.isdigit():
                    kb_map[kb_num]['subtype'] = subtype_val

        # Finalize KB map
        kb_articles = []
        for kb_num, kb_info in kb_map.items():
            if not kb_info['url']:
                kb_info['url'] = f"https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB{kb_num}"
            if not kb_info['subtype'] or kb_info['subtype'].isdigit():
                kb_info['subtype'] = 'Security Update'
            kb_articles.append({
                'kb': kb_info['kb'],
                'url': kb_info['url'],
                'fixed_build': kb_info['fixed_build'],
                'subtype': kb_info['subtype'],
                'product_idxs': [get_product_idx(p) for p in kb_info['products'][:8] if p]
            })
        kb_articles.sort(key=lambda x: int(x['kb']) if x['kb'].isdigit() else 0)

        cves_map[cve_id] = {
            'cve_id':      cve_id,
            'title':       title,
            'severity':    severity,
            'cvss':        cvss,
            'product_idx': get_product_idx(product),
            'product_idxs': [get_product_idx(p) for p in products[:5] if p],
            'date':        date_str,
            'exploited':   exploited,
            'kb_articles': kb_articles,
            'kb_count':    len(kb_articles),
        }

parsed = list(cves_map.values())

sev_order = {'Critical':0, 'Important':1, 'Moderate':2, 'Low':3}
parsed.sort(key=lambda x: (
    0 if x['exploited'] else 1,
    sev_order.get(x['severity'], 4),
    -(x['cvss'] or 0),
    x['cve_id']
))

now = datetime.now(timezone.utc)
counts = {
    'total':      len(parsed),
    'critical':   sum(1 for x in parsed if x['severity'] == 'Critical'),
    'important':  sum(1 for x in parsed if x['severity'] == 'Important'),
    'moderate':   sum(1 for x in parsed if x['severity'] == 'Moderate'),
    'low':        sum(1 for x in parsed if x['severity'] == 'Low'),
    'exploited':  sum(1 for x in parsed if x['exploited']),
    'patched':    sum(1 for x in parsed if x['kb_count'] > 0),
    'updated_at': now.strftime('%Y-%m-%d %H:%M UTC'),
    'month':      "Past 12 Months"
}

output = {
    'meta': counts,
    'products': products_table,
    'cves': parsed
}

with open('data/msrc_cves.json', 'w', encoding='utf-8') as f:
    json.dump(output, f, ensure_ascii=False, indent=2)

print(f"Success: {counts['total']} CVEs consolidated. Critical: {counts['critical']} | Exploited: {counts['exploited']} | Patched: {counts['patched']}")
