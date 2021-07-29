import random
import string
import asyncio
import functools
import os
import uvloop
import aiodns
import click
import socket
import sys
from tqdm import tqdm
from aiodnsbrute.logger import ConsoleLogger


class aioDNSBrute(object):
    """aiodnsbrute implements fast domain name brute forcing using Python's asyncio module."""

    def __init__(self, verbosity=0, max_tasks=512):
        """Constructor.

        Args:
            verbosity: set output verbosity: 0 (default) is none, 3 is debug
            max_tasks: the maximum number of tasks asyncio will queue (default 512)
        """
        self.tasks = []
        self.errors = []
        self.fqdn = []
        self.ignore_hosts = []
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        self.loop = asyncio.get_event_loop()
        self.resolver = aiodns.DNSResolver(loop=self.loop, rotate=True)
        self.sem = asyncio.BoundedSemaphore(max_tasks)
        self.max_tasks = max_tasks
        self.verbosity = verbosity
        self.logger = ConsoleLogger(verbosity)

    async def _dns_lookup(self, name):
        """Performs a DNS request using aiodns, self.lookup_type is set by the run function.
        A query for A record returns <ares_query_a_result> which does not return metadata about
        when a CNAME was resolved (just host and ttl attributes) however it should be faster.
        The <ares_host_result> returned by gethostbyname contains name, aliases, and addresses, if
        name is different in response we can surmise that the original domain was a CNAME entry.

        Args:
            name: the domain name to resolve

        Returns:
            object: <ares_query_a_result> if query, <ares_host_result> if gethostbyname
        """
        if self.lookup_type == "query":
            return await self.resolver.query(name, "A")
        elif self.lookup_type == "gethostbyname":
            return await self.resolver.gethostbyname(name, socket.AF_INET)

    def _dns_result_callback(self, name, future):
        """Handles the pycares object passed by the _dns_lookup function. We expect an errror to
        be present in the returned object because most lookups will be for names that don't exist.
        c-ares errors are passed through directly, error types can be identified in ares_strerror.c

        Args:
            name: original lookup name (because the query_result object doesn't contain it)
            future: the completed future (pycares dns result)
        """
        # Record processed we can now release the lock
        self.sem.release()
        # Handle known exceptions, barf on other ones
        if future.exception() is not None:
            try:
                err_number = future.exception().args[0]
                err_text = future.exception().args[1]
            except IndexError:
                self.logger.error(f"Couldn't parse exception: {future.exception()}")
            # handle the DNS errors we expect to receive, show user unexpected errors
            if err_number == 4:
                # This is domain name not found, ignore it
                pass
           # elif err_number == 12:
                # Timeout from DNS server
                #self.logger.warn(f"Timeout for {name}")
            elif err_number == 1:
                # Server answered with no data
                pass
            #else:
                #self.logger.error(
                #    f"{name} generated an unexpected exception: {future.exception()}"
                #)
            # for debugging/troubleshoooting keep a list of errors
            # self.errors.append({'hostname': name, 'error': err_text})

        # parse and output and store results.
        else:
            if self.lookup_type == "query":
                ips = [ip.host for ip in future.result()]
                cname = False
                row = f"{name:<30}\t{ips}"
            elif self.lookup_type == "gethostbyname":
                r = future.result()
                ips = [ip for ip in r.addresses]
                if name == r.name:
                    cname = False
                    n = f"""{name:<30}\t{f"{'':<35}" if self.verbosity >= 2 else ""}"""
                else:
                    cname = True
                    # format the name based on verbosity - this is kluge
                    short_cname = f"{r.name[:28]}.." if len(r.name) > 30 else r.name
                    n = f'{name}{"**" if self.verbosity <= 1 else ""}'
                    n = f'''{n:<30}\t{f"CNAME {short_cname:<30}" if self.verbosity >= 2 else ""}'''
                row = f"{n:<30}\t{ips}"
            # store the result
            if set(ips) != set(self.ignore_hosts):
                #self.logger.success(row)
                dns_lookup_result = {"domain": name, "ip": ips}
                if self.lookup_type == "gethostbyname" and cname:
                    dns_lookup_result["cname"] = r.name
                    dns_lookup_result["aliases"] = r.aliases
                self.fqdn.append(dns_lookup_result)
            self.logger.debug(future.result())
        self.tasks.remove(future)
        if self.verbosity >= 1:
            self.pbar.update()
       

    async def _queue_lookups(self, wordlist, domain):
        """Takes a list of words and adds them to the async loop also passing the original
        lookup domain name; then attaches the processing callback to deal with the result.

        Args:
            wordlist: a list of names to perform lookups for
            domain: the base domain to perform brute force against
        """
        for word in wordlist:
            # Wait on the semaphore before adding more tasks
            await self.sem.acquire()
            host = f"{word.strip()}.{domain}"
            task = asyncio.ensure_future(self._dns_lookup(host))
            task.add_done_callback(functools.partial(self._dns_result_callback, host))
            self.tasks.append(task)
        await asyncio.gather(*self.tasks, return_exceptions=True)

    def bruteforce_domain(target, resolvers=None, wordlist="subdomains-top1million-110000.txt", wildcard=True, verify=True, found_subdomains=[], thread_count=7000, query=True):
        subdomains_list = []
        names_list = []
        verbosity=1
        if resolvers:
              resolverfile = open(resolvers,'r')
              lines = resolverfile.read().splitlines()
              resolvers = [x.strip() for x in lines if (x and not x.startswith("#"))]
        bf = aioDNSBrute(verbosity=verbosity, max_tasks=thread_count)
        subdomains_list = bf.run(wordlist, target, resolvers, wildcard, verify, query)
        resolverfile.close()
        for r in range(1, len(subdomains_list)):  
              names_list.append(subdomains_list[r]['domain'])

        return names_list

    def run(
        self, wordlist, domain, resolvers=None, wildcard=True, verify=True, query=True
    ):
        """
        Sets up the bruteforce job, does domain verification, sets resolvers, checks for wildcard
        response to lookups, and sets the query type to be used. After all this, open the wordlist
        file and start the brute force - with ^C handling to cleanup nicely.

        Args:
            wordlist: a string containing a path to a filename to be used as a wordlist
            domain: the base domain name to be used for lookups
            resolvers: a list of DNS resolvers to be used (default None, uses system resolvers)
            wildcard: bool, do wildcard dns detection (default true)
            verify: bool, check if domain exists (default true)
            query: bool, use query to do lookups (default true), false means gethostbyname is used.

        Returns:
            dict containing result of lookups
        """
        self.logger.info(
            f"Brute forcing {domain} with a maximum of {self.max_tasks} concurrent tasks..."
        )
        if verify:
            #self.logger.info(f"Using local resolver to verify {domain} exists.")
            try:
                socket.gethostbyname(domain)
            except socket.gaierror as err:
                self.logger.error(
                    f"Couldn't resolve {domain}, use the --no-verify switch to ignore this error."
                )
                raise SystemExit(
                    self.logger.error(f"Error from host lookup: {err}")
                )
        else:
            self.logger.warn("Skipping domain verification. YOLO!")
        if resolvers:
            self.resolver.nameservers = resolvers
        self.logger.info(
            f"Using recursive DNS with {len(self.resolver.nameservers)} nameservers"
        )

        if wildcard:
            # 63 chars is the max allowed segment length, there is practically no chance that it will be a legit record
            random_sld = (
                lambda: f'{"".join(random.choice(string.ascii_lowercase + string.digits) for i in range(63))}'
            )
            try:
                self.lookup_type = "query"
                wc_check = self.loop.run_until_complete(
                    self._dns_lookup(f"{random_sld()}.{domain}")
                )
            except aiodns.error.DNSError as err:
                # we expect that the record will not exist and error 4 will be thrown
                #self.logger.info(
                #    f"No wildcard response was detected for this domain."
                #)
                wc_check = None
            finally:
                if wc_check is not None:
                    self.ignore_hosts = [host.host for host in wc_check]
                    self.logger.warn(
                        f"Wildcard response detected, ignoring answers containing {self.ignore_hosts}"
                    )
        else:
            self.logger.warn("Wildcard detection is disabled")

        if query:
            #self.logger.info(
            #    "Using pycares `query` function to perform lookups, CNAMEs cannot be identified"
            #)
            self.lookup_type = "query"
        else:
            self.logger.info(
                "Using pycares `gethostbyname` function to perform lookups, CNAME data will be appended to results (** denotes CNAME, show actual name with -vv)"
            )
            self.lookup_type = "gethostbyname"

        with open(wordlist, encoding="utf-8", errors="ignore") as words:
            w = words.read().splitlines()
        self.logger.info(f"Wordlist loaded, proceeding with {len(w)} DNS requests")
        try:
            if self.verbosity >= 1:
                self.pbar = tqdm(
                    total=len(w), unit="rec", maxinterval=0.1, mininterval=0
                )
            self.loop.run_until_complete(self._queue_lookups(w, domain))
        except KeyboardInterrupt:
            self.logger.warn("Caught keyboard interrupt, cleaning up...")
            asyncio.gather(*asyncio.Task.all_tasks()).cancel()
            self.loop.stop()
        finally:
            self.loop.close()
            if self.verbosity >= 1:
                self.pbar.close()
            self.logger.info(f"Bruteforcing Complete")
        return self.fqdn


@click.command()
@click.option(
    "--wordlist",
    "-w",
    help="Wordlist to use for brute force.",
    default=f"{os.path.dirname(os.path.realpath(__file__))}/wordlists/bitquark_20160227_subdomains_popular_1000",
)
@click.option(
    "--max-tasks",
    "-t",
    default=512,
    help="Maximum number of tasks to run asynchronosly.",
)
@click.option(
    "--resolver-file",
    "-r",
    type=click.File("r"),
    default=None,
    help="A text file containing a list of DNS resolvers to use, one per line, comments start with #. Default: use system resolvers",
)
@click.option(
    "--verbosity", "-v", count=True, default=1, help="Increase output verbosity"
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["csv", "json", "off"]),
    default="off",
    help="Output results to DOMAIN.csv/json (extension automatically appended when not using -f).",
)
@click.option(
    "--outfile",
    "-f",
    type=click.File("w"),
    help="Output filename. Use '-f -' to send file output to stdout overriding normal output.",
)
@click.option(
    "--query/--gethostbyname",
    default=True,
    help="DNS lookup type to use query (default) should be faster, but won't return CNAME information.",
)
@click.option(
    "--wildcard/--no-wildcard",
    default=True,
    help="Wildcard detection, enabled by default",
)
@click.option(
    "--verify/--no-verify",
    default=True,
    help="Verify domain name is sane before beginning, enabled by default",
)
@click.version_option("0.3.2")
@click.argument("domain", required=True)
def main(**kwargs):
    """aiodnsbrute is a command line tool for brute forcing domain names utilizing Python's asyncio module.

    credit: blark (@markbaseggio)
    """
    output = kwargs.get("output")
    verbosity = kwargs.get("verbosity")
    resolvers = kwargs.get("resolver_file")
    if output != "off":
        outfile = kwargs.get("outfile")
        # turn off output if we want JSON/CSV to stdout, hacky
        if outfile.__class__.__name__ == "TextIOWrapper":
            verbosity = 0
        if outfile is None:
            # wasn't specified on command line
            outfile = open(f'{kwargs["domain"]}.{output}', "w")
    if resolvers:
        lines = resolvers.read().splitlines()
        resolvers = [x.strip() for x in lines if (x and not x.startswith("#"))]

    bf = aioDNSBrute(verbosity=verbosity, max_tasks=kwargs.get("max_tasks"))
    results = bf.run(
        wordlist=kwargs.get("wordlist"),
        domain=kwargs.get("domain"),
        resolvers=resolvers,
        wildcard=kwargs.get("wildcard"),
        verify=kwargs.get("verify"),
        query=kwargs.get("query"),
    )

    if output in ("json"):
        import json
        json.dump(results, outfile)

    if output in ("csv"):
        import csv
        writer = csv.writer(outfile)
        writer.writerow(["Hostname", "IPs", "CNAME", "Aliases"])
        [
            writer.writerow(
                [
                    r.get("domain"),
                    r.get("ip", [""])[0],
                    r.get("cname"),
                    r.get("aliases", [""])[0],
                ]
            )
            for r in results
        ]


if __name__ == "__main__":
    main()
