import json
with open('/media/sf_shared/subset_data.json') as f:
    events = json.load(f)
with open('/media/sf_shared/subset_dir/subset_ndjson.json', 'w') as f:
    for event in events:
        f.write(json.dumps(event) + '\n')
print(f'Done. {len(events)} events converted.')