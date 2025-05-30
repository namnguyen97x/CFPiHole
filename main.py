import logging
import pathlib
from typing import List
import requests
import cloudflare
import configparser
import pandas as pd
import os
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class App:
    def __init__(self):        
        self.name_prefix = f"[CFPihole]"
        self.logger = logging.getLogger("main")
        self.whitelist = self.loadWhitelist()
        self.max_chunk_size = 5000  # Increased to 5000 domains per list (well below 10,000 limit)
        self.max_lists = 90  # Reduced to 90 to stay well below 100 lists per policy limit
        self.max_policies = 1  # Maximum number of policies to maintain

    def loadWhitelist(self):
        return open("whitelist.txt", "r").read().split("\n")

    def cleanup_old_lists(self, cf_lists):
        """Clean up old lists if we're approaching the limit"""
        if len(cf_lists) >= self.max_lists:
            self.logger.warning(f"Approaching list limit ({len(cf_lists)}/{self.max_lists}), cleaning up old lists")
            
            # Sort lists by creation date
            cf_lists.sort(key=lambda x: x.get('created_at', ''), reverse=True)
            
            # Keep only the most recent lists
            lists_to_keep = cf_lists[:self.max_lists - 10]  # Leave room for new lists
            lists_to_delete = cf_lists[self.max_lists - 10:]
            
            for l in lists_to_delete:
                try:
                    self.logger.info(f"Deleting old list {l['name']}")
                    cloudflare.delete_list(l["id"])
                except Exception as e:
                    self.logger.error(f"Error deleting list {l['name']}: {str(e)}")
            
            return lists_to_keep
        return cf_lists

    def run(self):
        try:
            config = configparser.ConfigParser()
            config.read('config.ini')

            #check tmp dir
            os.makedirs("./tmp", exist_ok=True)

            all_domains = []
            for list in config["Lists"]:
                print ("Setting list " +  list)
                name_prefix = f"[AdBlock-{list}]"

                self.download_file(config["Lists"][list], list)
                domains = self.convert_to_domain_list(list)
                all_domains = all_domains + domains

            unique_domains = pd.unique(all_domains)
            self.logger.info(f"Total unique domains: {len(unique_domains)}")

            # check if the list is already in Cloudflare
            cf_lists = cloudflare.get_lists(self.name_prefix)
            self.logger.info(f"Number of existing lists in Cloudflare: {len(cf_lists)}")

            # Clean up old lists if needed
            cf_lists = self.cleanup_old_lists(cf_lists)

            # compare the lists size
            if len(unique_domains) == sum([l["count"] for l in cf_lists]):
                self.logger.info("Lists are up to date, no changes needed")
                return

            #delete the policy
            cf_policies = cloudflare.get_firewall_policies(self.name_prefix)            
            if len(cf_policies)>0:
                cloudflare.delete_firewall_policy(cf_policies[0]["id"])

            # delete the lists
            for l in cf_lists:
                self.logger.info(f"Deleting list {l['name']}")
                cloudflare.delete_list(l["id"])

            cf_lists = []

            # chunk the domains into larger lists
            chunks = list(self.chunk_list(unique_domains, self.max_chunk_size))
            self.logger.info(f"Creating {len(chunks)} chunks of domains")

            for i, chunk in enumerate(chunks, 1):
                list_name = f"{self.name_prefix} {i}/{len(chunks)}"
                self.logger.info(f"Creating list {list_name} with {len(chunk)} domains")

                try:
                    _list = cloudflare.create_list(list_name, chunk)
                    cf_lists.append(_list)
                except Exception as e:
                    if "Maximum number of lists reached" in str(e):
                        self.logger.error("Maximum number of lists reached. Cleaning up and retrying...")
                        cf_lists = self.cleanup_old_lists(cf_lists)
                        # Retry creating the list
                        _list = cloudflare.create_list(list_name, chunk)
                        cf_lists.append(_list)
                    else:
                        raise

            # get the gateway policies
            cf_policies = cloudflare.get_firewall_policies(self.name_prefix)
            self.logger.info(f"Number of policies in Cloudflare: {len(cf_policies)}")

            # setup the gateway policy
            if len(cf_policies) == 0:
                self.logger.info("Creating firewall policy")
                cf_policies = cloudflare.create_gateway_policy(f"{self.name_prefix} Block Ads", [l["id"] for l in cf_lists])
            elif len(cf_policies) != 1:
                self.logger.error("More than one firewall policy found")
                raise Exception("More than one firewall policy found")
            else:
                self.logger.info("Updating firewall policy")
                cloudflare.update_gateway_policy(f"{self.name_prefix} Block Ads", cf_policies[0]["id"], [l["id"] for l in cf_lists])

            self.logger.info("Done")

        except Exception as e:
            self.logger.error(f"Error in run(): {str(e)}")
            raise

    def is_valid_hostname(self, hostname):
        import re
        if len(hostname) > 255:
            return False
        hostname = hostname.rstrip(".")
        allowed = re.compile(r'^[a-z0-9]([a-z0-9\-_]{0,61}[a-z0-9])?$', re.IGNORECASE)
        labels = hostname.split(".")
        
        # the TLD must not be all-numeric
        if re.match(r"^[0-9]+$", labels[-1]):
            return False
        
        return all(allowed.match(x) for x in labels)

    def download_file(self, url, name):
        self.logger.info(f"Downloading file from {url}")

        try:
            r = requests.get(url, allow_redirects=True, timeout=30)
            r.raise_for_status()  # Raise an exception for bad status codes

            path = pathlib.Path("tmp/" + name)
            open(path, "wb").write(r.content)

            self.logger.info(f"File size: {path.stat().st_size} bytes")
        except Exception as e:
            self.logger.error(f"Error downloading {url}: {str(e)}")
            raise

    def convert_to_domain_list(self, file_name: str):
        self.logger.info(f"Converting {file_name} to domain list")
        try:
            with open("tmp/"+file_name, "r", encoding="utf-8") as f:
                data = f.read()

            # check if the file is a hosts file or a list of domain
            is_hosts_file = False
            for ip in ["localhost", "127.0.0.1", "::1", "0.0.0.0"]:
                if ip in data:
                    is_hosts_file = True
                    break

            domains = []
            total_lines = len(data.splitlines())
            processed_lines = 0

            for line in data.splitlines():
                processed_lines += 1
                if processed_lines % 1000 == 0:
                    self.logger.info(f"Processing line {processed_lines}/{total_lines} of {file_name}")

                # skip comments and empty lines
                if line.startswith("#") or line.startswith(";") or line == "\n" or line.strip() == "":
                    continue

                if is_hosts_file:
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    domain = parts[1].rstrip()

                    # skip the localhost entry
                    if domain == "localhost":
                        continue
                else:
                    domain = line.rstrip()

                #Check whitelist và hợp lệ
                if domain in self.whitelist:
                    continue
                if not self.is_valid_hostname(domain):
                    continue
                domains.append(domain)

            self.logger.info(f"Found {len(domains)} valid domains in {file_name}")
            return domains
        except Exception as e:
            self.logger.error(f"Error processing {file_name}: {str(e)}")
            raise

    def chunk_list(self, _list: List[str], n: int):
        for i in range(0, len(_list), n):
            yield _list[i : i + n]


if __name__ == "__main__":


    app = App()
    app.run()


    
