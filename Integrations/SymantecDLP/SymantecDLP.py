import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
from requests import Session
from zeep import Client
from zeep.transports import Transport
from requests.auth import AuthBase, HTTPBasicAuth
from zeep import helpers
from zeep.cache import SqliteCache
from datetime import datetime
from typing import Dict, Tuple, List, Optional, Union, AnyStr
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


class SymantecAuth(AuthBase):
    def __init__(self, user, password, host):
        self.basic = HTTPBasicAuth(user, password)
        self.host = host

    def __call__(self, r):
        if r.url.startswith(self.host):
            return self.basic(r)
        else:
            return r


''' HELPER FUNCTIONS '''


def incident_attributes_transformer(attributes: dict) -> dict:
    """
    This function transforms the demisto args entered by the user into a dict representing the attributes
    of the updated incidents
    :param attributes: the demisto args dict
    :return: the attributes dict by the API design
    """
    # TODO: Check for IncidentNote, CustomAttribute, DataOwner
    # TODO: Add available options for severity and remediation_status in yml
    return {
        'IncidentSeverity': attributes.get('severity'),
        'IncidentsStatus': attributes.get('status'),
        'IncidentNote': attributes.get('note'),
        'RemediationStatus': attributes.get('remediation_status'),
        'RemediationLocation': attributes.get('remediation_location')
    }


def parse_component(raw_components: list) -> list:
    components = list()
    for raw_component in raw_components:
        unfiltered_component: dict = {
            'ID': raw_component.get('componentId'),
            'Name': raw_component.get('name'),
            'TypeID': raw_component.get('componentTypeId'),
            'Content': raw_component.get('content'),
            'LongId': raw_component.get('componentLongId')
        }
        component: dict = {key: val for key, val in unfiltered_component.items() if val}
        if component:
            components.append(component)
    return components


''' CONTEXT STANDARDS GENERATORS '''


def incident_details_context_standards_output_generator(incident: dict) -> dict:
    """
    This function retrives the needed data from an incident according to the context standards.
    :param incident: the incident data
    :return: a dict with the context standards data
    """
    return {}


''' CONTEXT TRANSFORMERS '''


def incident_details_context_transformer(raw_incident: dict) -> dict:
    """
    This function retrives data from the raw incident into context path locations
    :param raw_incident: the dict representing the raw response of incident
    :return: a dict with context paths and their corresponding value
    """
    return {}


def incident_violations_context_transformer(raw_incident_violations: dict) -> dict:
    """
    This function retrives data from the raw incident violations into context path locations
    :param raw_incident_violations: the dict representing the raw response of incident violations
    :return: a dict with context paths and their corresponding value
    """
    return {}


def incident_binaries_context_transformer(raw_incident_binaries: dict) -> dict:
    """
    This function retrives data from the raw incident into context path locations
    :param raw_incident_binaries: the dict representing the raw response of incident binaries
    :return: a dict with context paths and their corresponding value
    """
    return {
        'ID': raw_incident_binaries.get('incidentId'),
        'OriginalMessage': raw_incident_binaries.get('originalMessage'),
        'Component': parse_component(raw_incident_binaries.get('Component')),
        'LongID': raw_incident_binaries.get('incidentLongId')
    }


''' HUMAN READABLE OUTPUT GENERATORS '''


def incident_details_human_readable_output_generator(incident: dict) -> str:
    """
    This function gets all relevant data for the human readable output of a specific incident.
    :param incident: the incident data
    :return: a markdown table of the outputs
    """
    headers = list()
    outputs = list()
    return tableToMarkdown('Symantec DLP incident {incident_id}', outputs, headers=headers, removeNull=True)


# TODO: Check if all fields are needed
def update_incidents_human_readable_output_generator(raw_response: dict) -> str:
    """
    This function creates relevant data for the human readable output of incidents update response.
    :param raw_response: the incidents update data
    :return: a markdown table of the outputs
    """
    headers: list = ['Batch ID', 'Inaccessible Incident Long ID', 'Inaccessible Incident ID', 'Status Code']
    outputs = {
        'Batch ID': raw_response.get('batchId'),
        'Inaccessible Incident Long ID': raw_response.get('InaccessibleIncidentLongId'),
        'Inaccessible Incident ID': raw_response.get('InaccessibleIncidentId'),
        'Status Code': raw_response.get('statusCode')
    }
    return tableToMarkdown('Symantec DLP incidents {incident_id} update', outputs, headers=headers, removeNull=True)


def incident_binaries_human_readable_output_generator(incident_binaries: dict) -> str:
    """
    This function gets all relevant data for the human readable output of a specific incident binaries.
    :param incident_binaries: the incident binaries data
    :return: a markdown table of the outputs
    """
    headers = list()
    outputs = list()
    return tableToMarkdown('Symantec DLP incident {incident_id} binaries', outputs, headers=headers,
                           removeNull=True)


def incident_violations_human_readable_output_generator(incident_violations: dict) -> str:
    """
    This function gets all relevant data for the human readable output of a specific incident violations.
    :param incident_violations: the incident violations data
    :return: a markdown table of the outputs
    """
    headers = list()
    outputs = list()
    return tableToMarkdown('Symantec DLP incident {incident_id} violations', outputs, headers=headers,
                           removeNull=True)


def myconverter(o):
    if isinstance(o, datetime):
        return o.__str__()


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    demisto.results('ok')


def get_incident_details_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    incident_id: str = args.get('incident_id', '')

    # TODO: Check for the LongId issue - if needs a param that check for the version and than decides
    raw_incident: Dict = client.service.incidentDetail(
        incidentId=incident_id,
        incidentLongId=incident_id,
        includeHistory=True,
        includeViolations=True
    )

    human_readable: str
    entry_context = dict()
    raw_response = dict()

    if raw_incident:
        serialized_incident = helpers.serialize_object(raw_incident[0])
        raw_response = serialized_incident
        incident: dict = {key: val for key, val in incident_details_context_transformer(serialized_incident).items() if val}
        human_readable: str = incident_details_human_readable_output_generator(incident)
        context_standard_outputs: dict = incident_details_context_standards_output_generator(incident)
        entry_context: dict = {
            'SymantecDLP': {
                'Incident(val.ID === obj.ID)': incident
            }
        }
        # merge the two dicts into one dict that outputs to context
        entry_context.update(context_standard_outputs)
    else:
        human_readable = 'No incident found.'

    return human_readable, entry_context, raw_response


def list_incidents_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    saved_report_id: str = demisto.params().get('saved_report_id', '')
    if not saved_report_id:
        raise ValueError('Missing saved report ID. Configure it in the integration instance settings.')

    creation_date: datetime = parse_date_range(args.get('creation_date', '1 day'))[0]

    raw_incidents = client.service.incidentList(
        savedReportId=saved_report_id,
        incidentCreationDateLaterThan=creation_date
    )

    human_readable: str
    entry_context = dict()
    raw_response = dict()

    if raw_incidents:
        serialized_incidents: Dict = helpers.serialize_object(raw_incidents)
        raw_response: Dict = serialized_incidents
        incidents = [{
            'ID': incident_id
        } for incident_id in serialized_incidents.get('incidentId', '')]
        human_readable: str = tableToMarkdown(f'Symantec DLP incidents', incidents, removeNull=True)
        entry_context: dict = {
            'SymantecDLP': {
                'Incident(val.ID === obj.ID)': incidents
            }
        }
    else:
        human_readable = 'No incidents found.'

    return human_readable, entry_context, raw_response


# TODO: Check multiple incidents issue
# TODO: Check if needs to output to context - I don't think it's needed
def update_incidents_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    incident_id: str = args.get('incident_id', '')
    incident_attributes: dict = {key: val for key, val in incident_attributes_transformer(args).items() if val}
    batch_id: str = args.get('batch_id', '')

    # TODO: Check what is incidents attributes - dict, list, tuple? for now I treat it as a dict
    # TODO: Check for the LongId issue - if needs a param that check for the version and than decides
    raw_incidents_update_response: dict = client.service.updateIncidents(
        incident_id=incident_id,
        incidentLongId=incident_id,
        incidentAttributes=incident_attributes
    )

    human_readable: str
    entry_context = dict()
    raw_response = dict()

    if raw_incidents_update_response:
        incidents_update_response = helpers.serialize_object(raw_incidents_update_response)
        human_readable: str = update_incidents_human_readable_output_generator(incidents_update_response)
    else:
        human_readable = 'Update was not successful'

    return human_readable, entry_context, raw_response


def incident_binaries_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    incident_id: str = args.get('incident_id', '')
    include_original_message: bool = bool(args.get('include_original_message')) if args.get('include_original_message')\
        else None
    include_all_components: bool = bool(args.get('include_all_components')) if args.get('include_all_components')\
        else None
    # TODO: Check for type of long in python
    try:
        component_long_id: int = int(args.get('component_long_id')) if args.get('component_long_id') else None
        component_id: int = int(args.get('component_id')) if args.get('component_id') else None
    except ValueError:
        raise DemistoException('This value must be an integer.')

    # TODO: What to do with all optional args
    # TODO: Check for the LongId issue - if needs a param that check for the version and than decides
    raw_incident_binaries: dict = client.service.incidentBinaries(
        incident_id=incident_id,
        incidentLongId=incident_id
    )

    human_readable: str
    entry_context = dict()
    raw_response = dict()

    if raw_incident_binaries:
        serialized_incident_binaries = helpers.serialize_object(raw_incident_binaries)
        raw_response = serialized_incident_binaries
        incident_binaries = {key: val for key, val in
                             incident_binaries_context_transformer(serialized_incident_binaries).items() if val}
        human_readable: str = incident_binaries_human_readable_output_generator(incident_binaries)
        entry_context: dict = {
            'SymantecDLP': {
                'Incident(val.ID === obj.ID)': incident_binaries
            }
        }
    else:
        human_readable = 'No incident found.'

    return human_readable, entry_context, raw_response


def list_custom_attributes_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    raw_custom_attributes_list: dict = client.service.listCustomAttributes()

    human_readable: str
    entry_context = dict()
    raw_response = dict()

    if raw_custom_attributes_list:
        custom_attributes_list = helpers.serialize_object()
        raw_response = custom_attributes_list
        human_readable = tableToMarkdown('Symantec DLP custom attributes', custom_attributes_list, removeNull=True)
    else:
        human_readable = 'No custom attributes found.'

    return human_readable, entry_context, raw_response


def list_incident_status_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    raw_incident_status_list: dict = client.service.listIncidentStatus()

    human_readable: str
    entry_context = dict()
    raw_response = dict()

    if raw_incident_status_list:
        incident_status_list = helpers.serialize_object()
        raw_response = incident_status_list
        human_readable = tableToMarkdown('Symantec DLP incident status', incident_status_list, removeNull=True)
    else:
        human_readable = 'No incident status found.'

    return human_readable, entry_context, raw_response


# TODO: Check if needs to output context standards
def incident_violations_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    incident_id: str = args.get('incident_id', '')
    include_image_violations: bool = bool(args.get('include_image_violations')) \
        if args.get('include_image_violations') else None

    # TODO: What to do with all optional args
    # TODO: Check for the LongId issue - if needs a param that check for the version and than decides
    raw_incident_violations = client.service.incidentViolations(
        incidentId=incident_id,
        incidentLongId=incident_id,
    )

    human_readable: str
    entry_context = dict()
    raw_response = dict()

    if raw_incident_violations:
        serialized_incident_violations = helpers.serialize_object(raw_incident_violations)
        raw_response = serialized_incident_violations
        incident_violations: dict = {key: val for key, val
                                     in incident_violations_context_transformer(serialized_incident_violations).items()
                                     if val}
        human_readable: str = incident_violations_human_readable_output_generator(incident_violations)
        entry_context: dict = {
            'SymantecDLP': {
                'Incident(val.ID === obj.ID)': incident_violations
            }
        }
    else:
        human_readable = 'No incident status found.'

    return human_readable, entry_context, raw_response


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    params: Dict = demisto.params()
    server: str = params.get('server', '').rstrip('/')
    credentials: Dict = params.get('credentials', {})
    username: str = credentials.get('identifier', '')
    password: str = credentials.get('password', '')
    verify_ssl = not params.get('insecure', False)
    # proxy = params.get('proxy')
    wsdl: str = f'{server}/ProtectManager/services/v2011/incidents?wsdl'
    session: Session = Session()
    session.auth = SymantecAuth(username, password, server)
    session.verify = verify_ssl
    cache: SqliteCache = SqliteCache(timeout=None)
    transport: Transport = Transport(session=session, cache=cache)
    client: Client = Client(wsdl=wsdl, transport=transport)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    commands = {
        # 'fetch-incidents': fetch_incidents,
        'symantec-dlp-get-incident-details': get_incident_details_command,
        'symantec-dlp-list-incidents': list_incidents_command,
        'symantec-dlp-update-incidents': update_incidents_command,
        'symantec-dlp-incident-binaries': incident_binaries_command,
        'symantec-dlp-list-custom-attributes': list_custom_attributes_command,
        'symantec-dlp-list-incident-status': list_incident_status_command,
        'symantec-dlp-incident-violations': incident_violations_command
    }
    try:
        if command == 'fetch-incidents':
            commands[command](client)
        elif command == 'test-module':
            test_module()
        elif command in commands:
            human_readable, context, raw_response = commands[command](client, demisto.args())
            return_outputs(human_readable, context, raw_response)
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in Symantec DLP integration: {str(e)}'
        return_error(err_msg, error=e)


if __name__ == 'builtins':
    main()
