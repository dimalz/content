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
from typing import Dict, Tuple
from dateutil.parser import parse
import urllib3
import random

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
    Transforms the demisto args entered by the user into a dict representing the attributes
    of the updated incidents
    :param attributes: the demisto args dict
    :return: the attributes dict by the API design
    """
    # TODO: Check for IncidentNote, CustomAttribute, DataOwner
    # TODO: Check if remediation status values are Capitalize or UpperCase

    # Verify Custom Attribute
    custom_attribute_name: str = attributes.get('custom_attribute_name', '')
    custom_attribute_value: str = attributes.get('custom_attribute_value', '')
    if custom_attribute_name and not custom_attribute_value or custom_attribute_value and not custom_attribute_name:
        raise DemistoException("If updating an incident's custom attribute,"
                               " both custom_attribute_name and custom_attribute_value must be provided.")

    # Verify Data Owner
    data_owner_name: str = attributes.get('data_owner_name', '')
    data_owner_email: str = attributes.get('data_owner_email', '')
    if data_owner_name and not data_owner_email or data_owner_email and not data_owner_name:
        raise DemistoException("If updating an incident's custom attribute,"
                               " both data_owner_name and data_owner_email must be provided.")

    # Verify Note
    note: str = attributes.get('note', '')
    note_time_str: str = attributes.get('note_time', '')
    note_time = None
    if note_time_str:
        note_time = parse(note_time_str)
    if note and not note_time or note_time and not note:
        raise DemistoException("If adding an incident's note, both note and note_time must be provided.")

    return {
        'IncidentSeverity': attributes.get('severity'),
        'IncidentsStatus': attributes.get('status'),
        'IncidentNode': {
            'dateAndTime': note_time,
            'note': note
        },
        'CustomAttribute': {
            f'{custom_attribute_name}': custom_attribute_value
        },
        'DataOwner': {
            f'{data_owner_name}': data_owner_email
        },
        'RemediationStatus': attributes.get('remediation_status'),
        'RemediationLocation': attributes.get('remediation_location')
    }


def parse_component(raw_components: list) -> list:
    """
    Parses a list of components into a list of context data
    :param raw_components: the components list before parsing
    :return: the parsed list
    """
    components: list = []
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


def datetime_to_iso_format(obj: any):
    """
    Converts a datetime object into an ISO string representation
    :param obj: Any type of object
    :return: If the object is of type datetime the return is it's ISO string representation
    """
    if isinstance(obj, datetime):
        return obj.isoformat()


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client: Client, saved_report_id: int):
    """
    Performs basic get request to get item samples
    """
    helpers.serialize_object(client.service.incidentList(
        savedReportId=saved_report_id,
        incidentCreationDateLaterThan=parse_date_range('1 year')
    ))
    demisto.results('ok')


def get_incident_details_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    incident_id: str = args.get('incident_id', '')

    raw_incident: Dict = client.service.incidentDetail(
        incidentId=incident_id,
        includeHistory=True,
        includeViolations=True
    )

    human_readable: str
    entry_context: dict = {}
    raw_response: dict = {}

    if raw_incident and isinstance(raw_incident, list):
        serialized_incident = helpers.serialize_object(raw_incident[0])
        raw_response = serialized_incident
        # TODO: Transform into context & filter empty values
        incident: dict = json.loads(json.dumps(serialized_incident, default=datetime_to_iso_format))
        # TODO: Add headers to tableToMarkdown
        human_readable = tableToMarkdown('Symantec DLP incident {incident_id}', incident, removeNull=True)
        # TODO: Transform into context standards & filter empty values
        context_standard_outputs: dict = incident
        entry_context = {
            'SymantecDLP': {
                'Incident(val.ID === obj.ID)': incident
            }
        }
        # merge the two dicts into one dict that outputs to context
        entry_context.update(context_standard_outputs)
    else:
        human_readable = 'No incident found.'

    return human_readable, entry_context, raw_response


def list_incidents_command(client: Client, args: Dict, saved_report_id: str) -> Tuple[str, Dict, Dict]:
    if not saved_report_id:
        raise ValueError('Missing saved report ID. Configure it in the integration instance settings.')

    creation_date = parse_date_range(args.get('creation_date', '1 day'))[0]

    raw_incidents = client.service.incidentList(
        savedReportId=saved_report_id,
        incidentCreationDateLaterThan=creation_date
    )

    human_readable: str
    entry_context: dict = {}
    raw_response: dict = {}

    if raw_incidents:
        serialized_incidents: Dict = helpers.serialize_object(raw_incidents)
        raw_response = serialized_incidents
        incidents = [{
            'ID': incident_id
        } for incident_id in serialized_incidents.get('incidentId', '')]
        human_readable = tableToMarkdown(f'Symantec DLP incidents', incidents, removeNull=True)
        entry_context = {
            'SymantecDLP': {
                'Incident(val.ID === obj.ID)': incidents
            }
        }
    else:
        human_readable = 'No incidents found.'

    return human_readable, entry_context, raw_response


def update_incidents_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    incident_id: str = args.get('incident_id', '')
    incident_attributes: dict = {key: val for key, val in incident_attributes_transformer(args).items() if val}

    # TODO: Check for the batch ID generation
    raw_incidents_update_response: dict = client.service.updateIncidents(
        updateBatch={
            'batchId': str(random.randint(11111, 99999)),
            'incidentIt': incident_id,
            'incidentAttributes': incident_attributes
        }
    )

    human_readable: str
    entry_context: dict = {}
    raw_response: dict = {}

    if raw_incidents_update_response:
        incidents_update_response = helpers.serialize_object(raw_incidents_update_response)
        headers: list = ['Batch ID', 'Inaccessible Incident Long ID', 'Inaccessible Incident ID', 'Status Code']
        outputs = {
            'Batch ID': incidents_update_response.get('batchId'),
            'Inaccessible Incident Long ID': incidents_update_response.get('InaccessibleIncidentLongId'),
            'Inaccessible Incident ID': incidents_update_response.get('InaccessibleIncidentId'),
            'Status Code': incidents_update_response.get('statusCode')
        }
        human_readable = tableToMarkdown('Symantec DLP incidents {incident_id} update', outputs, headers=headers,
                                         removeNull=True)
    else:
        human_readable = 'Update was not successful'

    return human_readable, entry_context, raw_response


# TODO: Check for the component issue
def incident_binaries_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    incident_id: str = args.get('incident_id', '')
    include_original_message: bool = bool(args.get('include_original_message', 'True'))
    include_all_components: bool = bool(args.get('include_all_components', 'True'))

    raw_incident_binaries = client.service.incidentBinaries(
        incidentId=incident_id,
        includeOriginalMessage=include_original_message,
        includeAllComponents=include_all_components,
    )

    human_readable: str
    entry_context: dict = {}
    raw_response: dict = {}

    if raw_incident_binaries:
        serialized_incident_binaries = helpers.serialize_object(raw_incident_binaries)
        raw_response = serialized_incident_binaries
        unfiltered_incident_binaries = {
            'ID': raw_incident_binaries.get('incidentId'),
            'OriginalMessage': raw_incident_binaries.get('originalMessage'),
            'Component': parse_component(raw_incident_binaries.get('Component')),  # type: ignore
            'LongID': raw_incident_binaries.get('incidentLongId')
        }
        incident_binaries = {key: val for key, val in unfiltered_incident_binaries.items() if val}

        # TODO: Check for component issue - if component is a list how will it be shown in war-room
        raw_headers = ['ID', 'OriginalMessage', 'Component', 'LongID']
        headers = ['ID', 'Original Message', 'Component', 'Long ID']
        incident_binaries_output: dict = {}
        for raw_header in raw_headers:
            if incident_binaries.get(raw_header):
                incident_binaries_output[headers[raw_headers.index(raw_header)]] = incident_binaries.get(raw_header)
        human_readable = tableToMarkdown('Symantec DLP incident {incident_id} binaries', incident_binaries_output,
                                         headers=headers, removeNull=True)

        # TODO: Check if needs to output context standards - data inside component
        entry_context = {
            'SymantecDLP': {
                'Incident(val.ID === obj.ID)': incident_binaries
            }
        }
    else:
        human_readable = 'No incident found.'

    return human_readable, entry_context, raw_response


def list_custom_attributes_command(client: Client) -> Tuple[str, Dict, Dict]:
    raw_custom_attributes_list: dict = client.service.listCustomAttributes()

    human_readable: str
    entry_context: dict = {}
    raw_response: dict = {}

    # TODO: Check how the output looks in war-room
    if raw_custom_attributes_list:
        custom_attributes_list = helpers.serialize_object(raw_custom_attributes_list)
        raw_response = custom_attributes_list
        human_readable = tableToMarkdown('Symantec DLP custom attributes',
                                         {'Custom Attributes': custom_attributes_list},
                                         headers=['Custom Attributes'], removeNull=True)
    else:
        human_readable = 'No custom attributes found.'

    return human_readable, entry_context, raw_response


def list_incident_status_command(client: Client) -> Tuple[str, Dict, Dict]:
    raw_incident_status_list: dict = client.service.listIncidentStatus()

    human_readable: str
    entry_context: dict = {}
    raw_response: dict = {}

    if raw_incident_status_list:
        incident_status_list = helpers.serialize_object(raw_incident_status_list)
        raw_response = incident_status_list
        human_readable = tableToMarkdown('Symantec DLP incident status', {'Incident Status': incident_status_list},
                                         headers=['Incident Status'], removeNull=True)
    else:
        human_readable = 'No incident status found.'

    return human_readable, entry_context, raw_response


def incident_violations_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    incident_id: str = args.get('incident_id', '')
    include_image_violations: bool = bool(args.get('include_image_violations', 'True'))

    raw_incident_violations = client.service.incidentViolations(
        incidentId=incident_id,
        includeImageViolations=include_image_violations
    )

    human_readable: str
    entry_context: dict = {}
    raw_response: dict = {}

    if raw_incident_violations:
        serialized_incident_violations = helpers.serialize_object(raw_incident_violations)
        raw_response = serialized_incident_violations
        # TODO: Transform into context & filter empty values
        incident_violations: dict = serialized_incident_violations
        # TODO: Add headers to tableToMarkdown
        human_readable = tableToMarkdown('Symantec DLP incident {incident_id} violations', incident_violations,
                                         removeNull=True)
        # TODO: Check if needs to output context standards
        entry_context = {
            'SymantecDLP': {
                'Incident(val.ID === obj.ID)': incident_violations
            }
        }
    else:
        human_readable = 'No incident status found.'

    return human_readable, entry_context, raw_response


def fetch_incidents(client: Client, fetch_time: str, fetch_limit: int, last_run: dict, saved_report_id: str):
    # We use parse to get out time in datetime format and not iso, that's what Symantec DLP is expecting to get
    if last_run and last_run.get('last_fetched_event_iso'):
        last_update_time = parse(last_run['last_fetched_event_iso'])
    else:
        last_update_time = parse_date_range(fetch_time)[0]

    incidents = []

    incidents_ids: list = helpers.serialize_object(client.service.incidentList(
        savedReportId=saved_report_id,
        incidentCreationDateLaterThan=last_update_time
    )).get('incidentId', '')

    if incidents_ids:
        for incident_id in incidents_ids:
            if fetch_limit == 0:
                break
            fetch_limit -= 1
            incidents.append({
                'rawJSON': str(incident_id),
                'name': f'Symantec DLP incident {incident_id}',
                'occurred': ''
            })
        # An API call to retrive the last incident details and from it retrive it's creation time
        # We assume that the incidents list is ordered by ID and bigger ID means bigger creation time
        last_incident_id = incidents_ids[-1]
        last_incident_time = json.loads(json.dumps(helpers.serialize_object(client.service.incidentDetail(
            incidentId=last_incident_id
        )[0]), default=datetime_to_iso_format)).get('incident', {}).get('incidentCreationDate')
        demisto.setLastRun({'last_fetched_event_iso': last_incident_time})

    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''


# TODO: Check for the long ID issue
def main():
    params: Dict = demisto.params()
    server: str = params.get('server', '').rstrip('/')
    credentials: Dict = params.get('credentials', {})
    username: str = credentials.get('identifier', '')
    password: str = credentials.get('password', '')
    fetch_time: str = params.get('fetch_time', '3 days').strip()
    try:
        fetch_limit: int = int(params.get('fetch_limit', '10'))
    except ValueError:
        raise DemistoException('Value for fetch_limit must be an integer.')
    saved_report_id: str = demisto.params().get('saved_report_id', '')
    last_run: dict = demisto.getLastRun()
    args: dict = demisto.args()
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
        'test-module': test_module,
        'fetch-incidents': fetch_incidents,
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
            commands[command](client, fetch_time, fetch_limit, last_run, saved_report_id)  # type: ignore
        elif command == 'test-module':
            commands[command](client, saved_report_id)  # type: ignore
        elif command == 'symantec-dlp-list-incidents':
            human_readable, context, raw_response = commands[command](client, args, saved_report_id)  # type: ignore
            return_outputs(human_readable, context, raw_response)
        elif command == 'symantec-dlp-list-incident-status' or command == 'symantec-dlp-list-custom-attributes':
            human_readable, context, raw_response = commands[command](client)  # type: ignore
            return_outputs(human_readable, context, raw_response)
        elif command in commands:
            human_readable, context, raw_response = commands[command](client, args)  # type: ignore
            return_outputs(human_readable, context, raw_response)
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in Symantec DLP integration: {str(e)}'
        return_error(err_msg, error=e)


if __name__ == 'builtins':
    main()
