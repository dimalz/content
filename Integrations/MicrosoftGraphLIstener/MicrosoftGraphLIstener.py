import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Union, Optional

''' IMPORTS '''
import requests
import base64
import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

WELL_KNOWN_FOLDERS = {
    'archive': 'archive',
    'conversation history': 'conversationhistory',
    'deleted items': 'deleteditems',
    'drafts': 'drafts',
    'inbox': 'inbox',
    'junk email': 'junkemail',
    'outbox': 'outbox',
    'sent items': 'sentitems',
}

EMAIL_DATA_MAPPING = {
    'id': 'ID',
    'createdDateTime': 'CreatedTime',
    'lastModifiedDateTime': 'ModifiedTime',
    'receivedDateTime': 'ReceivedTime',
    'sentDateTime': 'SentTime',
    'subject': 'Subject',
    'importance': 'Importance',
    'conversationId': 'ConversationID',
    'isRead': 'IsRead',
    'internetMessageId': 'MessageID'
}

''' HELPER FUNCTIONS '''


def epoch_seconds(d: datetime = None) -> int:
    """
    Return the number of seconds for given date. If no date, return current.

    Args:
        d (datetime): timestamp
    Returns:
         int: timestamp in epoch
    """
    if not d:
        d = datetime.utcnow()
    return int((d - datetime.utcfromtimestamp(0)).total_seconds())


def get_encrypted(content: str, key: str) -> str:
    """
    Args:
        content (str): content to encrypt. For a request to Demistobot for a new access token, content should be
            the tenant id
        key (str): encryption key from Demistobot

    Returns:
        encrypted timestamp:content
    """

    def create_nonce() -> bytes:
        return os.urandom(12)

    def encrypt(string: str, enc_key: str) -> bytes:
        """

        Args:
            enc_key (str):
            string (str):

        Returns:
            bytes:
        """
        # String to bytes
        enc_key = base64.b64decode(enc_key)
        # Create key
        aes_gcm = AESGCM(enc_key)
        # Create nonce
        nonce = create_nonce()
        # Create ciphered data
        data = string.encode()
        ct = aes_gcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ct)

    now = epoch_seconds()
    encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
    return encrypted


def get_now_utc():
    return datetime.utcnow().strftime(DATE_FORMAT)


def add_second_to_str_date(date_string, seconds=1):
    added_result = datetime.strptime(date_string, DATE_FORMAT) + timedelta(seconds=seconds)
    return datetime.strftime(added_result, DATE_FORMAT)


def upload_file(filename, content, attachents_list):
    file_result = fileResult(filename, content)

    if file_result['Type'] == entryTypes['error']:
        demisto.error(file_result['Contents'])
        raise Exception(file_result['Contents'])

    attachents_list.append({
        'path': file_result['FileID'],
        'name': file_result['File'],
    })


''' COMMANDS + REQUESTS FUNCTIONS '''


class MsGraphClient(BaseClient):
    ITEM_ATTACHMENT = '#microsoft.graph.itemAttachment'
    FILE_ATTACHMENT = '#microsoft.graph.fileAttachment'

    def __init__(self, tenant_id, auth_id, enc_key, token_retrieval_url, app_name, mailbox_to_fetch, folder_to_fetch,
                 first_fetch_interval, emails_fetch_limit, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._tenant_id = tenant_id
        self._auth_id = auth_id
        self._enc_key = enc_key
        self._token_retrieval_url = token_retrieval_url
        self._mailbox_to_fetch = mailbox_to_fetch
        self._folder_to_fetch = folder_to_fetch
        self._first_fetch_interval = first_fetch_interval
        self._app_name = app_name
        self._emails_fetch_limit = emails_fetch_limit

    def _get_access_token(self):
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get('access_token')
        valid_until = integration_context.get('valid_until')
        if access_token and valid_until:
            if epoch_seconds() < valid_until:
                return access_token

        dbot_response = requests.post(
            self._token_retrieval_url,
            headers={'Accept': 'application/json'},
            data=json.dumps({
                'app_name': self._app_name,
                'registration_id': self._auth_id,
                'encrypted_token': get_encrypted(self._tenant_id, self._enc_key)
            }),
            verify=self._verify
        )

        if dbot_response.status_code not in {200, 201}:
            msg = 'Error in authentication. Try checking the credentials you entered.'
            try:
                demisto.info('Authentication failure from server: {} {} {}'.format(
                    dbot_response.status_code, dbot_response.reason, dbot_response.text))
                err_response = dbot_response.json()
                server_msg = err_response.get('message')
                if not server_msg:
                    title = err_response.get('title')
                    detail = err_response.get('detail')
                    if title:
                        server_msg = f'{title}. {detail}'
                if server_msg:
                    msg += ' Server message: {}'.format(server_msg)
            except Exception as ex:
                demisto.error('Failed parsing error response - Exception: {}'.format(ex))
            raise Exception(msg)
        try:
            gcloud_function_exec_id = dbot_response.headers.get('Function-Execution-Id')
            demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
            parsed_response = dbot_response.json()
        except ValueError:
            raise Exception(
                'There was a problem in retrieving an updated access token.\n'
                'The response from the Demistobot server did not contain the expected content.'
            )
        access_token = parsed_response.get('access_token')
        expires_in = parsed_response.get('expires_in', 3595)
        time_now = epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer

        demisto.setIntegrationContext({
            'access_token': access_token,
            'valid_until': time_now + expires_in
        })
        return access_token

    def _http_request(self, *args, **kwargs):
        token = self._get_access_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        return super()._http_request(*args, headers=headers, **kwargs)

    def _get_root_folder_children(self, user_id):
        '''
        implement later
        :param user_id:
        :return:
        '''
        suffix_endpoint = f'users/{user_id}/mailFolders/msgfolderroot/childFolders?$top=250'
        root_folder_children = self._http_request('GET', suffix_endpoint).get('value', None)
        if not root_folder_children:
            return_error("No folders found under Top Of Information Store folder")

        return root_folder_children

    def _get_folder_children(self, user_id, folder_id):
        '''
        Implement later
        :param user_id:
        :param folder_id:
        :return:
        '''
        suffix_endpoint = f'users/{user_id}/mailFolders/{folder_id}/childFolders?$top=250'
        folder_children = self._http_request('GET', suffix_endpoint).get('value', [])
        return folder_children

    def _get_folder_info(self, user_id, folder_id):
        suffix_endpoint = f'users/{user_id}/mailFolders/{folder_id}'
        folder_info = self._http_request('GET', suffix_endpoint)
        if not folder_info:
            return_error(F"No info found for folder {folder_id}")
        return folder_info

    def _get_folder_by_path(self, user_id, folder_path):
        '''
        implement later
        :param user_id:
        :param folder_path:
        :return:
        '''
        folders_names = folder_path.replace('\\', '/').split('/')

        if folders_names[0].lower() in WELL_KNOWN_FOLDERS:
            folder_id = WELL_KNOWN_FOLDERS[folders_names[0].lower()]
            if len(folders_names) == 1:
                return self._get_folder_info(user_id, folder_id)
            else:
                current_directory_level_folders = self._get_folder_children(user_id, folder_id)
                folders_names.pop(0)
        else:
            current_directory_level_folders = self._get_root_folder_children(user_id)

        for index, folder_name in enumerate(folders_names):
            found_folder = [f for f in current_directory_level_folders if
                            f.get('displayName', '').lower() == folder_name.lower() or f.get('id', '') == folder_name]

            if not found_folder:
                return_error(f"No such folder exist: {folder_path}")
            found_folder = found_folder[0]

            if index == len(folders_names) - 1:
                return found_folder
            current_directory_level_folders = self._get_folder_children(user_id, found_folder.get('id', ''))

    def _fetch_last_emails(self, folder_id, last_fetch, exclude_ids):
        target_received_time = add_second_to_str_date(last_fetch)
        suffix_endpoint = (f"users/{self._mailbox_to_fetch}/mailFolders/{folder_id}/messages"
                           f"?$filter=receivedDateTime ge {target_received_time}"
                           f"&$orderby=ReceivedDateTime &$top={self._emails_fetch_limit}&select=*")
        # check if has next in the pagging and do not take value first
        fetched_emails = self._http_request('GET', suffix_endpoint).get('value', [])[:self._emails_fetch_limit]

        if exclude_ids:
            fetched_emails = [email for email in fetched_emails if email.get('id') not in exclude_ids]

        fetched_emails_ids = [email.get('id') for email in fetched_emails]
        return fetched_emails, fetched_emails_ids

    @staticmethod
    def _get_next_run_time(fetched_emails, start_time):
        next_run_time = fetched_emails[-1].get('receivedDateTime') if fetched_emails else start_time

        return next_run_time

    @staticmethod
    def _get_recipient_address(email_address):
        return email_address.get('emailAddress', {}).get('address', '')

    def _get_attachment_mime(self, attachment_id):
        suffix_endpoint = f'users/{self._mailbox_to_fetch}/messages/{attachment_id}/$value'
        mime_content = self._http_request('GET', suffix_endpoint, resp_type='text')

        return mime_content

    def _get_email_attachments(self, message_id):
        attachment_results = []
        suffix_endpoint = f'users/{self._mailbox_to_fetch}/messages/{message_id}/attachments'
        attachments = self._http_request('Get', suffix_endpoint).get('value', [])

        for attachment in attachments:
            attachment_type = attachment.get('@odata.type', '')
            attachment_name = attachment.get('name', 'untitled_attachment')
            if attachment_type == self.FILE_ATTACHMENT:
                try:
                    attachment_content = base64.b64decode(attachment.get('contentBytes', ''))
                except Exception as e:
                    # log the error/ add function try parse
                    continue
                upload_file(attachment_name, attachment_content, attachment_results)
            elif attachment_type == self.ITEM_ATTACHMENT:
                attachment_id = attachment.get('id', '')
                mime_content = self._get_attachment_mime(attachment_id)
                upload_file(f'{attachment_name}.eml', mime_content, attachment_results)

        return attachment_results

    def _parse_email_as_labels(self, parsed_email):
        labels = []

        for (key, value) in parsed_email.items():
            if key == 'Headers':
                headers_labels = [
                    {'type': 'Email/Header/{}'.format(header.get('name', '')), 'value': header.get('value', '')}
                    for header in value]
                labels.extend(headers_labels)
            elif key in ['To', 'Cc', 'Bcc']:
                recipients_labels = [{'type': f'Email/{key}', 'value': recipient} for recipient in value]
                labels.extend(recipients_labels)
            else:
                labels.append({'type': f'Email/{key}', 'value': f'{value}'})

        return labels

    def _parse_email_as_incident(self, email):
        parsed_email = {EMAIL_DATA_MAPPING[k]: v for (k, v) in email.items() if k in EMAIL_DATA_MAPPING}
        parsed_email['Headers'] = email.get('internetMessageHeaders', [])

        email_body = email.get('body', {}) or email.get('uniqueBody', {})
        parsed_email['Body'] = email_body.get('content', '')
        parsed_email['BodyType'] = email_body.get('contentType', '')

        parsed_email['Sender'] = MsGraphClient._get_recipient_address(email.get('sender', {}))
        parsed_email['From'] = MsGraphClient._get_recipient_address(email.get('from'))
        parsed_email['To'] = list(map(MsGraphClient._get_recipient_address, email.get('toRecipients', [])))
        parsed_email['Cc'] = list(map(MsGraphClient._get_recipient_address, email.get('ccRecipients', [])))
        parsed_email['Bcc'] = list(map(MsGraphClient._get_recipient_address, email.get('bccRecipients', [])))
        parsed_email['Type'] = 'MS-Graph-Mail'

        if email.get('hasAttachments', False):
            parsed_email['Attachments'] = self._get_email_attachments(message_id=email.get('id', ''))

        incident = {
            'type': parsed_email['Type'],
            'name': parsed_email['Subject'],
            'details': email.get('bodyPreview', '') or parsed_email['Body'],
            'labels': self._parse_email_as_labels(parsed_email),
            'occurred': parsed_email['ReceivedTime'],
            'attachment': parsed_email.get('Attachments', []),
            'rawJSON': json.dumps(parsed_email)
        }

        return incident

    def fetch_incidents(self, last_run):
        start_time = get_now_utc()
        last_fetch = last_run.get('LAST_RUN_TIME', None)
        exclude_ids = last_run.get('LAST_RUN_IDS', [])
        last_run_folder_id = last_run.get('LAST_RUN_FOLDER_ID')
        folder_id = self._get_folder_by_path(self._mailbox_to_fetch, self._folder_to_fetch).get('id', '')

        if not last_fetch or folder_id != last_run_folder_id:
            last_fetch, _ = parse_date_range(self._first_fetch_interval, date_format=DATE_FORMAT, utc=True)

        fetched_emails, fetched_emails_ids = self._fetch_last_emails(folder_id=folder_id, last_fetch=last_fetch,
                                                                     exclude_ids=exclude_ids)
        incidents = list(map(self._parse_email_as_incident, fetched_emails))
        next_run_time = MsGraphClient._get_next_run_time(fetched_emails, start_time)
        next_run = {'LAST_RUN_TIME': next_run_time, 'LAST_RUN_IDS': fetched_emails_ids, 'LAST_RUN_FOLDER_ID': folder_id}

        return next_run, incidents


def main():
    """ COMMANDS MANAGER / SWITCH PANEL """
    params = demisto.params()

    # params related to oproxy
    tenant_id = params.get('tenant_id')
    auth_and_token_url = params.get('auth_id', '').split('@')
    auth_id = auth_and_token_url[0]
    enc_key = params.get('enc_key')
    token_retrieval_url = 'https://oproxy.demisto.ninja/obtain-token' if len(auth_and_token_url) != 2 \
        else auth_and_token_url[1]
    app_name = 'ms-graph-mail'

    # params related to common instance configuration
    server = params.get('url', '').strip('/')
    base_url = f'{server}/v1.0/'
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    # params related to mailbox to fetch incidents
    mailbox_to_fetch = params.get('mailbox_to_fetch', '')
    folder_to_fetch = params.get('folder_to_fetch', 'Inbox')
    first_fetch_interval = params.get('first_fetch_interval', '15 minutes')
    emails_fetch_limit = int(params.get('emails_fetch_limit', '50'))

    # TODO add ok_codes to client
    client = MsGraphClient(tenant_id, auth_id, enc_key, token_retrieval_url, app_name, mailbox_to_fetch,
                           folder_to_fetch, first_fetch_interval, emails_fetch_limit, base_url=base_url, verify=verify,
                           proxy=proxy)

    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        if command == 'fetch-incidents':
            next_run, incidents = client.fetch_incidents(demisto.getLastRun())
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
    # Log exceptions
    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
