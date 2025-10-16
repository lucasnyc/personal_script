"""
The purpose of this is to process the raw auditbeat log files
During config of auditbeat, tags had been specified with -k flag this will parse the relevant events with
relevant tags only.
"""
import json
import argparse

def parse(filename):
    events = []
    custom_tags = {
        'exploit_start',
        'malicious_start',
        'malicious_file_activity',
        'malicious_dir_change',
        'malicious_file_delete',
        'malicious_network',
        'malicious_process_create',
    }

    print(f"Start: Parsing {filename}")

    try:
        with open(filename, 'r') as f:
            for line in f:
                if not line.strip():
                    continue

                try:
                    # each line is a separate json object
                    json_object = json.loads(line)

                    # filtering
                    if 'tags' in json_object and any(tag in custom_tags for tag in json_object['tags']):
                        parsed_event = {
                            'timestamp' : json_object.get('@timestamp'),
                            'tag' : json_object['tags'][0],
                            'pid' : json_object.get('process', {}).get('pid'),
							'ppid': json_object.get('process', {}).get('parent', {}).get('pid'),
                            'executable': json_object.get('process', {}).get('executable'),
                            'action': json_object.get('event', {}).get('action'),
                            'outcome': json_object.get('event', {}).get('outcome'),
                            'destination_ip': json_object.get('destination', {}).get('ip'),
                            'file_path': json_object.get('file', {}).get('path')
                        }
                        events.append(parsed_event)
                except Exception as e:
                    print(f"Caught error {e}")
                    continue

    except FileNotFoundError:
        print(f"Error: {filename} not found")
        return

    print(f"End: Completed parsing {filename}")
    return events

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Parse Auditbeat logs for a specific tags.")
    parser.add_argument("log_file", help="Path to the Auditbeat log file.")
    parser.add_argument("-o", "--output", help="Path to save the parsed JSON output file.")
    args = parser.parse_args()
    key_events = parse(args.log_file)

    if key_events:
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    json.dump(key_events, f, indent=2)
                print(f"Saved {len(key_events)} parsed events to '{args.output}'")
            except IOError as e:
                print(f"Error: writing to file: {e}")
