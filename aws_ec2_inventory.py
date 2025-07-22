# Author: Wayne Vassallo

import boto3
import botocore
import argparse
import sys
import csv
import os
import configparser


def get_available_profiles():
    config_path = os.path.expanduser("~/.aws/config")
    config = configparser.ConfigParser()
    config.read(config_path)

    profiles = []
    for section in config.sections():
        if section.startswith("profile "):
            profiles.append(section.split("profile ")[1])
    return profiles


def get_all_regions(session):
    ec2 = session.client("ec2")
    response = ec2.describe_regions(AllRegions=True)
    return [region['RegionName'] for region in response['Regions'] if region['OptInStatus'] in ['opt-in-not-required', 'opted-in']]


def main():
    parser = argparse.ArgumentParser(description="Generate AWS EC2 Instance inventory")
    parser.add_argument('--profiles', help="Comma-separated AWS profiles to use", dest='profiles',
                        default=None)
    parser.add_argument('--verbose', dest='verbose', action='store_true')
    parser.set_defaults(verbose=True)
    args = parser.parse_args()

    if args.profiles:
        profile_list = [p.strip() for p in args.profiles.split(',')]
    else:
        profile_list = get_available_profiles()

    if args.verbose:
        print(f"Using profiles: {profile_list}", file=sys.stderr)

    csv_lines = []
    csv_fields = ['aws_accountName', 'aws_accountId', 'region', 'instance_id', 'instance_type', 'state', 'name']

    for profile in profile_list:
        try:
            session = boto3.Session(profile_name=profile)
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            account_id = identity['Account']
            account_name = profile

            regions = get_all_regions(session)

            for region in regions:
                try:
                    if args.verbose:
                        print(f"Querying {profile} ({account_id}) in {region}", file=sys.stderr)

                    ec2 = session.client("ec2", region_name=region)
                    response = ec2.describe_instances()

                    for reservation in response['Reservations']:
                        for instance in reservation['Instances']:
                            name_tag = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), '')
                            entry = {
                                'aws_accountName': account_name,
                                'aws_accountId': account_id,
                                'region': region,
                                'instance_id': instance.get('InstanceId'),
                                'instance_type': instance.get('InstanceType'),
                                'state': instance['State']['Name'],
                                'name': name_tag
                            }
                            csv_lines.append(entry)
                except botocore.exceptions.ClientError as e:
                    print(f"[!] Error querying EC2 in {region} for profile {profile}: {e}", file=sys.stderr)

        except Exception as e:
            print(f"[!] Unexpected error with profile {profile}: {e}", file=sys.stderr)

    if csv_lines:
        filename = "aws_ec2_inventory.csv"
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_fields, dialect=csv.excel)
            writer.writeheader()
            writer.writerows(csv_lines)
        print(f"[+] CSV file '{filename}' created successfully.")
    else:
        print("[!] No EC2 instances found to report.")


if __name__ == "__main__":
    main()
