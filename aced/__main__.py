from impacket.examples.utils import parse_target
from impacket.examples import logger
import typer
from typing import Annotated, cast
from getpass import getpass
import logging
from aced.core import (
    init_ldap_session, 
    bofhound_logging, 
    magic, 
    SidsResolver
)

show_banner = r'''

          _____
         |A .  | _____
         | /.\ ||A ^  | _____
         |(_._)|| / \ ||A _  | _____
         |  |  || \ / || ( ) ||A_ _ |
         |____V||  .  ||(_'_)||( v )|
                |____V||  |  || \ / |
                       |____V||  .  |
                              |____V|
                                     v1.0

        Parse and log a target principal's DACL.
                                    @garrfoster
'''

app = typer.Typer(
    help="Tool to enumerate a single target's DACL in Active Directory",
    no_args_is_help=True
)

def validate_target(target: str) -> tuple[str, str, str, str]:
    """Parse and validate target format: [[domain/username[:password]@]<address>"""
    try:
        domain, username, password, address = parse_target(target)
        
        if username == "":
            raise typer.BadParameter("Username must be specified")
        
        if domain == "":
            raise typer.BadParameter(f"Domain of user '{username}' must be specified")
        
        if address == "":
            raise typer.BadParameter("Target address (hostname or IP) must be specified")
        
        return domain, username, password, address
    except Exception as e:
        raise typer.BadParameter(f"Invalid target format: {e}")

@app.command()
def main(
    target: Annotated[str, typer.Argument(help="Target in format [[domain/username[:password]@]<address>")],
    ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS instead of LDAP")] = False,
    dc_ip: Annotated[str | None, typer.Option("--dc-ip", help="IP address or FQDN of domain controller")] = None,
    kerberos: Annotated[bool, typer.Option("-k", "--kerberos", help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")] = False,
    no_pass: Annotated[bool, typer.Option("--no-pass", help="Don't ask for password (useful for -k)")] = False,
    hashes: Annotated[str | None, typer.Option("--hashes", help="LM and NT hashes, format is LMHASH:NTHASH")] = None,
    aes: Annotated[str | None, typer.Option("--aes", help="AES key to use for Kerberos Authentication (128 or 256 bits)")] = None,
    debug: Annotated[bool, typer.Option("--debug", help="Enable verbose logging")] = False,
    no_smb: Annotated[bool, typer.Option("--no-smb", help="Do not resolve DC hostname through SMB. Requires a FQDN with --dc-ip")] = False,
):
    """Parse and log a target principal's DACL in Active Directory."""
    
    print(show_banner)
    
    # Parse target
    userdomain, username, password, address = validate_target(target)
    
    # Parse hashes
    lmhash = ""
    nthash = ""
    if hashes:
        try:
            lmhash, nthash = hashes.split(':')
        except ValueError:
            raise typer.BadParameter("Invalid hash format. Use LMHASH:NTHASH")
    
    # Get password if needed
    if not (password or lmhash or nthash or aes or no_pass):
        password = getpass("Password:")
     
    # Set up logging
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
    
    logger.init()
    logs_dir = bofhound_logging()
    
    try:
        ldap_server, ldap_session = init_ldap_session(
            domain=userdomain,
            username=username,
            password=password,
            lmhash=lmhash,
            nthash=nthash,
            kerberos=kerberos,
            domain_controller=dc_ip,
            aesKey=aes,
            no_smb=no_smb,
            hashes=hashes,
            ldaps=ldaps
        )
    except Exception as e:
        if 'invalid server address' in str(e):
            typer.echo(f"Error: Invalid server address - {userdomain}", err=True)
        else:
            typer.echo(f"Error connecting to LDAP server: {e}", err=True)
        raise typer.Exit(1)
    
    domain = userdomain
    sids_resolver = SidsResolver(ldap_server, ldap_session, domain)
    ldapsearch = magic(ldap_server, ldap_session, domain, logs_dir)
    
    while True:
        build_filter: str = cast(str, typer.prompt("Enter target sAMAccountName or distinguishedName")).lower()
        
        if build_filter == "exit":
            logging.info("User entered exit. Stopping session.")
            logging.info(f"Results written to {logs_dir}")
            break
        
        if "dc=" in build_filter:
            search = f"(distinguishedName={build_filter})"
            ldap_filter = search
            logging.info(f'Searching for: {build_filter}')
        else:
            search = f"(sAMAccountName={build_filter})"
            ldap_filter = search
            logging.info(f'Searching for: {build_filter}')
        
        test = list(ldapsearch.fetch_users(ldap_session, ldap_filter, logs_dir))
        if not test:
            logging.info(f'Target {build_filter} not found.')
        else:
            for user in test:
                ldapsearch.print_user(user, sids_resolver)

if __name__ == '__main__':
    app()
