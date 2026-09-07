# -*- encoding: utf-8 -*-
"""
Copyright (c) 2025 - present by F6

This module contains poller for URP products.

"""
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from urllib.parse import urljoin, urlencode
from typing import Union, Optional, List, Dict, Any, Generator, Tuple, Literal

import requests
from requests import Response
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .exception import *
from .const import *
from .utils import Validator, ParserHelper


logger = logging.getLogger(__name__)


@dataclass(order=True)
class GeneratorInfo(object):
    collection_name: str
    session_type: str
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    query: Optional[str] = None
    limit: Union[str, int, None] = None
    keys: Optional[Dict[Any, str]] = None
    iocs_keys: Optional[Dict] = None
    ignore_validation: Optional[bool] = False

    def _validate_default_fields(self, collections_info=None) -> None:
        """
        Function for field validation. This function must always be called in __post_init__.
        """
        if self.ignore_validation:
            return

        Validator.validate_collection_name(self.collection_name, method=self.session_type)
        if self.date_from:
            Validator.validate_date_format(
                date=self.date_from,
                formats=collections_info.get(self.collection_name).get("date_formats")
            )
        if self.date_to:
            Validator.validate_date_format(
                date=self.date_to,
                formats=collections_info.get(self.collection_name).get("date_formats")
            )

        if self.limit:
            int(self.limit)

    def __post_init__(self) -> None:
        """
        This function is called after __init__ and is used to validate input data.
        """
        self._validate_default_fields()


@dataclass(order=True)
class TIGeneratorInfo(GeneratorInfo):
    apply_hunting_rules: Union[int, str, None] = None
    is_tailored: Union[int, str, None] = None
    parse_events: Optional[bool] = None
    params: Optional[Dict[str, Any]] = None

    def _validate_default_fields(self, collections_info=CollectionConsts.TI_COLLECTIONS_INFO):
        super()._validate_default_fields(collections_info=CollectionConsts.TI_COLLECTIONS_INFO)
        try:
            if self.collection_name in CollectionConsts.TI_DEPRECATED_COLLECTIONS.keys():
                raise DeprecationWarning
        except DeprecationWarning as e:
            logger.exception(("Collection '{}' is deprecated.".format(self.collection_name)))

        if self.apply_hunting_rules is not None:
            try:
                if self.apply_hunting_rules not in [0, 1]:
                    raise BaseException
            except BaseException as e:
                logger.exception("Wrong apply_hunting_rules input it should be '0' or '1'")

        if self.is_tailored is not None:
            try:
                if self.is_tailored not in [0, 1]:
                    raise ValueError
            except ValueError:
                logger.exception("Wrong is_tailored input, it should be '0' or '1'.")

        if self.params is not None:
            pass
        else:
            self.params = {}


@dataclass(order=True)
class DRPGeneratorInfo(GeneratorInfo):
    violationType: Optional[Union[List[int], List[str]]] = None
    section: Optional[Union[List[int], List[str]]] = None

    def _validate_default_fields(self, collections_info=CollectionConsts.DRP_COLLECTIONS_INFO):
        super()._validate_default_fields(collections_info=CollectionConsts.DRP_COLLECTIONS_INFO)


@dataclass(order=True)
class ASMGeneratorInfo(GeneratorInfo):
    company_id: Union[str, int, None] = None

    def _validate_default_fields(self, collections_info=CollectionConsts.ASM_COLLECTIONS_INFO):
        super()._validate_default_fields(collections_info=CollectionConsts.ASM_COLLECTIONS_INFO)


class Parser(object):
    """
    An object that handles raw JSON with various methods.
    """

    def __init__(self, chunk, keys, iocs_keys):
        # type: (Dict, Dict[Any, str], Dict[str, str]) -> None
        """
        :param chunk: data portion.
        :param keys: fields to find in the portion.
        :param iocs_keys: IOCs to find in the portion.
        """
        self.raw_dict = chunk
        self.raw_json = json.dumps(chunk)
        self.iocs_keys = iocs_keys
        self.keys = keys
        self.count = self.raw_dict.get('count', self.raw_dict.get('total', None))
        self.portion_size = len(self._return_items_list())
        self.sequpdate = self.raw_dict.get('seqUpdate', None)
        self._result_id = self.raw_dict.get('resultId', None)

    def _return_items_list(self):
        if self.count is not None:
            raw_dict = self.raw_dict.get('items', {})
        else:
            raw_dict = [self.raw_dict]
        return raw_dict

    def _keys_exist(self, feed, keys_road):
        # type: (Dict, List[str]) -> bool

        for k in keys_road:
            feed = feed.get(k, {})

        if feed:
            return True
        return False

    def _keys_found(self, feed, keys_road, check_list):
        # type: (Dict, List[str], List[str]) -> bool

        for k in keys_road:
            feed = feed.get(k, {})

        if isinstance(feed, list):
            raise ValueError("Value to check should be String not List.")

        if check_list:
            if feed in check_list:
                return True
        return False

    def parse_portion(
            self,
            keys=None,
            as_json=False,
            filter_map=None,
            ignore=False,
            check_existence=False,
            **kwargs
    ):
        # type: (Optional[Dict[Any, str]], Optional[bool], List[Tuple[str, List]], bool, bool, dict) -> Union[str, List[Dict[Any, Any]]]
        """
        Returns the parsed portion list of feeds using keys provided for the current collection.
        Every dict in the list is a single parsed feed.

        :param keys: if provided, override base keys set in the poller.
        :param as_json: if True returns a portion in JSON format.
        :param filter_map: filter to **ignore**/**accept-only** feeds which contain values in filter_map.
        Depends on the **ignore** flag.
        :param ignore: flag to ignore values in filter_map. By default, set to False.
        :param check_existence: flag to check the existence of a key in filter_map. By default, set to False.
        """

        if not self.keys and not keys:
            raise ParserException("You didn't provide any keys for parsing portion.")
        if keys:
            Validator.validate_set_keys_input(keys)
        parsed_portion = []
        raw_dict = self._return_items_list()
        for feed in raw_dict:

            scip_flag = False

            # Filter logic, which depends on args: filter_map, ignore and check_existence
            if filter_map:
                for _filter in filter_map:

                    _keys_road = _filter[0].split(".")
                    _check_list = _filter[1]

                    if ignore:
                        # if ignore flag is True -> ignore keys from check_list
                        if self._keys_found(feed=feed, keys_road=_keys_road, check_list=_check_list):
                            scip_flag = True
                            continue
                    elif check_existence:
                        # if check_existence flag is True -> accept only if key_road not null
                        if not self._keys_exist(feed=feed, keys_road=_keys_road):
                            scip_flag = True
                            continue
                    else:
                        # if ignore flag is False -> accept only keys from check_list
                        if not self._keys_found(feed=feed, keys_road=_keys_road, check_list=_check_list):
                            scip_flag = True
                            continue

                # scip feed if keys
                if scip_flag:
                    continue

            _keys = keys if keys else self.keys
            parsed_dict = ParserHelper.find_by_template(feed, _keys, **kwargs)
            parsed_portion.append(parsed_dict)

        if as_json:
            return json.dumps(parsed_portion)
        return parsed_portion

    def bulk_parse_portion(self, keys_list, as_json=False):
        # type: (List[Dict[Any, str]], Optional[bool]) -> Union[str, List[List[Dict[Any, Any]]]]
        """
        Parses feeds in the portion using every key's dict in the list.
        Every feed in the parsed portion will be presented as a list with parsed dicts for every key's dict.

        :param keys_list: list of keys dicts you want in return.
        :param as_json: if True returns the portion in JSON format.
        """
        parsed_portion = []
        for keys in keys_list:
            parsed_portion.append(self.parse_portion(keys=keys))
        parsed_portion = [list(a) for a in zip(*parsed_portion)]

        if as_json:
            return json.dumps(parsed_portion)
        return parsed_portion

    def get_iocs(
            self,
            keys=None,
            as_json=False,
            filter_map=None,
            ignore=False,
            check_existence=False
    ):
        # type: (Optional[Dict], Optional[bool], List[Tuple[str, List]], bool, bool) -> Union[str, Dict[str, List]]
        """
        Returns parsed portion dict of feeds using ioc_keys provided for the current collection.
        Keys are fields to search for the current collection; values are a list of gathered IOCs for the current portion.

        :param keys: if provided, override base iocs_keys set in poller.
        :param as_json: if True returns IOCs in JSON format.
        :param filter_map: filter to **ignore**/**accept-only** feeds which contain values in filter_map. Depends on the **ignore** flag.
        :param ignore: flag to ignore values in filter_map. By default, set to False.
        :param check_existence: flag to check the existence of a key in filter_map. By default, set to False.
        """
        if not self.iocs_keys and not keys:
            raise ParserException("You didn't provide any keys for getting IOCs.")
        if keys:
            Validator.validate_set_iocs_keys_input(keys)
            iocs_keys = keys
        else:
            iocs_keys = self.iocs_keys
        iocs_dict = {}
        raw_dict = self._return_items_list()
        for key, value in iocs_keys.items():
            iocs = []
            for feed in raw_dict:

                scip_flag = False

                # Filter logic, which depends on args: filter_map, ignore and check_existence
                if filter_map:
                    for _filter in filter_map:

                        _keys_road = _filter[0].split(".")
                        _check_list = _filter[1]

                        if ignore:
                            # if ignore flag is True -> ignore keys from check_list
                            if self._keys_found(feed=feed, keys_road=_keys_road, check_list=_check_list):
                                scip_flag = True
                                continue
                        elif check_existence:
                            # if check_existence flag is True -> accept only if key_road not null
                            if not self._keys_exist(feed=feed, keys_road=_keys_road):
                                scip_flag = True
                                continue
                        else:
                            # if ignore flag is False -> accept only keys from check_list
                            if not self._keys_found(feed=feed, keys_road=_keys_road, check_list=_check_list):
                                scip_flag = True
                                continue

                    # scip feed if keys
                    if scip_flag:
                        continue

                ioc = ParserHelper.find_element_by_key(obj=feed, key=value)
                iocs.extend(ParserHelper.unpack_iocs(ioc))

            iocs_dict[key] = iocs

        if as_json:
            return json.dumps(iocs_dict)
        return iocs_dict


class Poller(object):
    """
    Poller is used for requests to any Product.
    """
    def __init__(self, username, api_key, api_url, **kwargs):
        # type: (str, str, Optional[str], Any) -> None
        """
        :param username: Login for the chosen product (Portal).
        :param api_key: API key, generated in your product profile (Portal).
        :param api_url: URL for product API (Portal).
        """
        self._session = requests.Session()
        self.__username = username
        if kwargs.get("auth_type") == 'token':
            self._session.headers.update(RequestConsts.HEADERS)
            self._session.headers.update({"X-API-KEY": api_key})
        else:
            self._session.auth = HTTPBasicAuth(username, api_key)
            self._session.headers.update(RequestConsts.HEADERS)
        self._session.verify = False
        self._session.trust_env = False
        self._api_url = api_url
        self._keys = {}
        self._iocs_keys = {}
        self._mount_adapter_with_retries()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._session.close()

    def _mount_adapter_with_retries(
            self,
            retries=RequestConsts.RETRIES,
            backoff_factor=RequestConsts.BACKOFF_FACTOR,
            status_forcelist=RequestConsts.STATUS_CODE_FORCELIST
    ):
        # type: (int, int, list[int]) -> None
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist
        )
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount('http://', adapter)
        self._session.mount('https://', adapter)

    def _status_code_handler(self, response):
        # type: (Response) -> None
        status_code = response.status_code
        if status_code == 200:
            return
        elif status_code in RequestConsts.STATUS_CODE_MSGS:
            raise ConnectionException(
                f"Status code: {status_code}. Message: {RequestConsts.STATUS_CODE_MSGS[status_code]}"
            )
        else:
            raise ConnectionException(
                f"Something wrong. Status code: {status_code}. Response body: {response.text}."
            )

    def send_request(self, endpoint, params=None, method="GET", decode=True, **kwargs):
        # type: (str, Optional[dict], str, bool, Any) -> Any
        """
        Send request based on endpoint and custom params

        :param endpoint: the endpoint will be applied to the existing base URL (api_url) using the urljoin.
        :param params: dict-like object with params that will be set using the urlencode.
        :param method: HTTP method ('GET' or 'POST').
        :param decode: decode output in JSON (True) or leave as plain text (False). By default, set to True.
        """

        url = urljoin(self._api_url, endpoint)
        params = urlencode({k: v for k, v in (params or {}).items() if v or v == 0})
        try:
            if method in ["GET", "POST"]:
                response = self._session.get(
                    url,
                    params=params,
                    timeout=RequestConsts.TIMEOUT,
                    proxies=self._session.proxies,
                    **kwargs
                )
            else:
                raise InputException("HTTP method is not allowed")

            response_status_code = response.status_code
            response_headers = response.headers
            response_encoding = response.encoding

            self._status_code_handler(response)
            if decode:
                try:
                    return response.json()
                except requests.exceptions.JSONDecodeError as e:
                    logger.error(
                        f"""
                        An error occurred while decoding the json response to a request to {response.url} \n
                        Response Status Code: {response_status_code} \n
                        Response Headers: {response_headers} \n
                        Detected Encoding: {response_encoding} \n
                        The data obtained in the answer: {response.text} \n
                        """
                    )
                    raise ConnectionException(
                        f"""
                        An error occurred while decoding the json response to a request to {response.url} \n
                        Response Status Code: {response_status_code} \n
                        Response Headers: {response_headers} \n
                        Detected Encoding: {response_encoding} \n
                        The data obtained in the answer: {response.text} \n
                        """
                    )
            return response.content
        except requests.exceptions.Timeout as e:
            raise ConnectionException(f"Max retries reached. Exception message: {e}")

    def set_proxies(self, proxies):
        # type: (dict) -> None
        """
        Sets proxies for `Session` object.

        We'd recommend using the ProxyConfigurator class for proxies.

            Explore the next sample:

                >>> from pyf6.utils import ProxyConfigurator
                >>>
                >>> poller = Poller(username='...', api_key='...', api_url='...')
                >>> proxy_dict = ProxyConfigurator.get_proxies(proxy_ip='...', proxy_port='...', proxy_user='...', proxy_pass='...')
                >>> poller.set_proxies(proxy_dict)


        :param proxies: requests-like proxies.
        """
        self._session.proxies = proxies

    def set_verify(self, verify):
        # type: (Union[bool, str]) -> None
        """
        Sets the 'verify' parameter for a `Session` object.

        :param verify: Either a boolean or a path-like. It controls whether we verify
            the server's TLS certificate or a string. In the case of string, it must be a path
            to a CA bundle to use. Defaults to ``True``. When set to
            ``False``, requests will accept any TLS certificate presented by
            the server and will ignore hostname mismatches and/or expired
            certificates, which will make your application vulnerable to
            man-in-the-middle (MitM) attacks. Setting the 'verify' parameter to ``False``
            may be useful during local development or testing.
        """
        self._session.verify = verify

    def set_product(
            self,
            product_type="unknown",
            product_name="unknown",
            product_version="unknown",
            integration_name="unknown",
            integration_version="unknown"
    ):
        # type: (str, str, str, str, str) -> None
        """
        Sets `User-Agent` header to request.

        :param product_type: SIEM, SOAR, TIP, SCRIPT.
        :param product_name: QRadar, Splunk, MaxPatrol, etc.
        :param product_version: Product version.
        :param integration_name: App name of integration.
        :param integration_version: Integration version.
        """
        def _merge(name, version):
            return "{}_{}".format(name, version) if name else "unknown"

        self._session.headers["User-Agent"] = \
            "{product_type}/{product}/{integration}/{username}/{library}".format(
                product_type=product_type,
                product=_merge(product_name, product_version),
                integration=_merge(integration_name, integration_version),
                # default metadata
                username=self.__username,
                library=_merge(TechnicalConsts.library_name, TechnicalConsts.library_version)
            )

    def set_keys(self, collection_name, keys, ignore_validation=False):
        # type: (str, Dict[str, str], Optional[bool]) -> None
        """
        Sets `Keys` to search in the selected collection. It should be python dict where
            key - result name

            value - dot notation string with searchable keys

        Example:
                {"result_name": "searchable_key_1.searchable_key_2"}


        Parser search keys recursively in lists/dicts. If you want to set your own value in the result,
        then start with * before the name. You also can make a full template to nest data in the way you want.

        Explore the next sample:

            Your mapping dict:

                >>> {
                >>>     'network': {'ips': 'iocs.network.ip'},
                >>>     'url': 'iocs.network.url',
                >>>     'type': '*custom_network'
                >>> }

            Received feeds:

                >>> [
                >>>     {
                >>>         'iocs': {
                >>>             'network': [
                >>>                 {
                >>>                     'ip': [1, 2],
                >>>                     'url': 'url.com'
                >>>                 },
                >>>                 {
                >>>                     'ip': [3],
                >>>                     'url': ''
                >>>                 }
                >>>             ]
                >>>         }
                >>>     },
                >>>     {
                >>>         'iocs': {
                >>>             'network': [
                >>>                 {
                >>>                     'ip': [4, 5],
                >>>                     'url': 'new_url.com'
                >>>                 }
                >>>             ]
                >>>         }
                >>>     }
                >>> ]

            Resulted output:

                >>> [
                >>>     {
                >>>         'network': {'ips': [[1, 2], [3]]},
                >>>         'url': ['url.com', ''],
                >>>         'type': 'custom_network'
                >>>     },
                >>>     {
                >>>         'network': {'ips': [[4, 5]]},
                >>>         'url': ['new_url.com'],
                >>>         'type': 'custom_network'
                >>>     }
                >>> ]

        :param collection_name: name of the collection to set mapping keys for.
        :param keys: python dict with mapping keys to parse.
        :param ignore_validation: True or False
        """
        if not ignore_validation:
            Validator.validate_collection_name(collection_name)
            Validator.validate_set_keys_input(keys)
        self._keys[collection_name] = keys

    def set_iocs_keys(self, collection_name, keys, ignore_validation=False):
        # type: (str, Dict[str, str], Optional[bool]) -> None
        """
        Sets keys to search IOCs in the selected collection. `keys` should be the python dict in this format:
        {key_name_you_want_in_result_dict: data_you_want_to_find}. Parser finds keys recursively in lists/dicts,
        so set `data_you_want_to_find` using dot notation: ``firstkey.secondkey``.

        For example:
        Keys {'ips': 'iocs.network.ip', 'url': 'iocs.network.url'} for the list of feeds:

        [
            {
                'iocs': {
                    'network':
                        [{'ip': [1, 2], 'url': 'url.com'}, {'ip': [3], url: ""}]
                }
            },

            {
                'iocs': {
                    'network':
                        [{'ip': [4, 5], 'url': 'new_url.com'}]
                }
            }
        ]

        return this `{'ips': [1, 2, 3, 4, 5], 'url': ['url.com', 'new_url.com']}`.

        :param collection_name: name of the collection whose keys to set.
        :param keys: python dict with keys to get from parse.
        :param ignore_validation: True or False
        """
        if not ignore_validation:
            Validator.validate_collection_name(collection_name)
            Validator.validate_set_iocs_keys_input(keys)
        self._iocs_keys[collection_name] = keys

    def close_session(self):
        """
        Closes the poller session. Use this function to finish the polling process.
        """
        self._session.close()


class TIPoller(Poller):
    """
    Poller is used for requests to TI API.
    """
    def __init__(self, username, api_key, api_url=RequestConsts.API_URL, **kwargs):
        # type: (str, str, Optional[str], Any) -> None
        """
        :param username: Login for TI product (Portal).
        :param api_key: API key, generated in your TI profile (Portal).
        :param api_url: URL for TI product API (Portal).
        """
        super().__init__(username=username, api_key=api_key, api_url=api_url, **kwargs)

    def create_update_generator(
            self,
            collection_name,
            date_from=None,
            date_to=None,
            query=None,
            sequpdate=None,
            limit=None,
            apply_hunting_rules=None,
            is_tailored=None,
            ignore_validation=None,
            parse_events=False,
            params=None,
    ):
        # type: (str, Optional[str], Optional[str], Optional[str], Union[int, str], Union[int, str], Union[int, str], Union[int, str], Optional[bool], Optional[bool], Optional[Dict[str, Any]]) -> Generator[Parser, Any, None]
        """
        Creates a generator of :class:`Parser` class objects for an update session
        (feeds are sorted in ascending order) for `collection_name` with set parameters.
        `sequpdate` allows you to receive all relevant feeds. Such a request uses the sequpdate parameter,
        you will receive a portion of feeds that starts with the next `sequpdate` parameter for the current collection.
        For all feeds in the Threat Intelligence continuous numbering is carried out.
        For example, the `sequpdate` equal to 1999998 can be in the `compromised/accounts` collection,
        and a feed with sequpdate equal to 1999999 can be in the `attacks/ddos` collection.
        If item updates (for example, if new attacks were associated with existing APT by our specialists or tor node
        has been detected as active again), the item gets a new parameter, and it automatically rises in the database
        and "becomes relevant" again.

        .. warning:: Dates should be in one of these formats: "YYYY-MM-DD", "YYYY-MM-DDThh:mm:ssZ".
        For most collections, limits are set on the server and can't be exceeded.

        :param collection_name: collection to update.
        :param date_from: start date of the update session.
        :param date_to: end date of the update session.
        :param query: query to search during the update session.
        :param sequpdate: identification number from which to start the session.
        :param limit: size of the portion in iteration.
        :param apply_hunting_rules: apply or not client hunting rules to get only filtered data (applicable for public_leak, phishing_group and breached)
        :param is_tailored: apply or not individual reports, which are matching client hunting rules (applicable for apt/threat, hi/threat)
        :param ignore_validation: ignore keys and collections validation
        :param parse_events: used to parse events in the list for CSV table (if we have nested list data, base params will be copied on each row)
        :param params: used to add extra params to the request (ex: {"tags[filterSpam][]": 1})
        :rtype: Generator[:class:`Parser`]
        """
        session_type = "update"
        generator_info = TIGeneratorInfo(
            collection_name=collection_name,
            session_type=session_type,
            date_from=date_from,
            date_to=date_to,
            query=query,
            limit=limit,
            apply_hunting_rules=apply_hunting_rules,
            is_tailored=is_tailored,
            keys=self._keys.get(collection_name),
            iocs_keys=self._iocs_keys.get(collection_name),
            ignore_validation=ignore_validation,
            parse_events=parse_events,
            params=params,
        )
        generator_class = TIUpdateFeedGenerator(self, generator_info, sequpdate=sequpdate)
        return generator_class.create_generator()

    def create_search_generator(
            self,
            collection_name,
            date_from=None,
            date_to=None,
            query=None,
            limit=None,
            apply_hunting_rules=None,
            is_tailored=None,
            ignore_validation=None,
            parse_events=False,
            params=None,
    ):
        # type: (str, Optional[str], Optional[str], Optional[str], Union[int, str], Union[int, str], Union[int, str], Optional[bool], Optional[bool], Optional[Dict[str, Any]]) -> Generator
        """
        Creates a generator of :class:`Parser` class objects for the search session
        (feeds are sorted in descending order, **excluding compromised/breached and compromised/reaper**)
        for `collection_name` with set parameters.

        .. warning:: Dates should be in one of these formats: "YYYY-MM-DD", "YYYY-MM-DDThh:mm:ssZ".
        For most collections, limits are set on the server and can't be exceeded.

        :param collection_name: collection to search.
        :param date_from: start date of the search session.
        :param date_to: end date of the search session.
        :param query: query to search during the session.
        :param limit: size of the portion in the iteration.
        :param apply_hunting_rules: apply or not client hunting rules to get only filtered data (applicable for public_leak, phishing_group and breached)
        :param is_tailored: apply or not individual reports, which are matching client hunting rules (applicable for apt/threat, hi/threat)
        :param ignore_validation: ignore keys and collections validation
        :param parse_events: used to parse events in the list for CSV table (if we have nested list data, base params will be copied on each row)
        :param params: used to add extra params to the request (ex: {"tags[filterSpam][]": 1})
        :rtype: Generator[:class:`Parser`]
        """
        session_type = "search"
        generator_info = TIGeneratorInfo(
            collection_name=collection_name,
            session_type=session_type,
            date_from=date_from,
            date_to=date_to,
            query=query,
            limit=limit,
            apply_hunting_rules=apply_hunting_rules,
            is_tailored=is_tailored,
            keys=self._keys.get(collection_name),
            iocs_keys=self._iocs_keys.get(collection_name),
            ignore_validation=ignore_validation,
            parse_events=parse_events,
            params=params,
        )
        generator_class = TISearchFeedGenerator(self, generator_info)
        return generator_class.create_generator()

    def search_feed_by_id(self, collection_name, feed_id):
        # type: (str, str) -> Parser
        """
        WARNING: please check if the collection supports this feature before use it in production code.

        Searches for a feed with the `feed_id` in the collection with `collection_name`.

        :param collection_name: in what collection to search.
        :param feed_id: id of feed to search.
        :rtype: :class:`Parser`
        """
        Validator.validate_collection_name(collection_name)
        endpoint = f"{collection_name}/{feed_id}"
        chunk = self.send_request(endpoint=endpoint, params={})
        portion = Parser(chunk, self._keys.get(collection_name, []),
                         self._iocs_keys.get(collection_name, []))
        return portion

    def search_file_in_threats(self, collection_name, feed_id, file_id):
        # type: (str, str, str) -> bytes
        """
        Searches for a file with the `file_id` in the collection with `collection_name` in the feed with `feed_id`.

        .. warning:: `Collection_name` should be apt/threat or hi/threat.

        :param collection_name: in what collection to search.
        :param feed_id: id of feed with a file to search.
        :param file_id: if of file to search.
        """
        Validator.validate_collection_name(collection_name)
        endpoint = f"{collection_name}/{feed_id}/file/{file_id}"
        binary_file = self.send_request(endpoint=endpoint, params={}, decode=False)
        return binary_file

    def execute_action_by_id(self, collection_name, feed_id, action, request_params=None, decode=True):
        # type: (str, str, str, Optional[Dict], Optional[bool]) -> List[Dict[str, Any]]
        """
        Executes `action` for the feed with `feed_id` in collection `collection_name`.

        :param collection_name: in what collection to search.
        :param feed_id: id of feed to search.
        :param action: action to execute (part of REST resource after "action/")
        :param request_params: dict of params to send with this request (e.g.: {"url_id": "1342312"})
        :param decode: True to get data in JSON format, False to get raw content
        """
        Validator.validate_collection_name(collection_name)
        if action[0] == "/":
            action = action[1::]
        endpoint = f"{collection_name}/{feed_id}/action/{action}"
        response = self.send_request(endpoint=endpoint, params=request_params, decode=decode)
        return response

    def global_search(self, query):
        # type: (str) -> List[Dict[str, Any]]
        """
        Global search across all collections with a provided ` query `, returns dict
        with information about the collection, count, etc.

        :param query: query to search for.
        """
        endpoint = "search"
        response = self.send_request(endpoint=endpoint, params={"q": query})
        return response

    def graph_ip_search(self, query):
        # type: (str) -> List[Dict[str, Any]]
        """
        Graph IP search returns WHOIS information from Graph API

        :param query: query to search for.
        """

        endpoint = "utils/graph/ip"
        response = self.send_request(endpoint=endpoint, params={"ip": query})
        return response

    def graph_domain_search(self, query):
        # type: (str) -> List[Dict[str, Any]]
        """
        Graph domain search returns WHOIS information from Graph API

        :param query: query to search for.
        """

        endpoint = "utils/graph/domain"
        response = self.send_request(endpoint=endpoint, params={"domain": query})
        return response

    def get_seq_update_dict(self, date=None, collection=None, apply_hunting_rules=None):
        # type: (Optional[str], Optional[str], Union[int, str]) -> Dict[str, int]
        """
        Gets dict with `seqUpdate` key for each collection from the server based on the provided date, collection name or
        hunting rules. If the date is not provided, returns dict for the current day.

        .. warning:: Date should be in "YYYY-MM-DD" format.

        :param date: defines the start date to get seqUpdate.
        :param collection: filter by collection name
        :param apply_hunting_rules: apply or not client hunting rules to get only filtered data (applicable for public_leak, phishing_group and breached)
        :return: dict with collection names in keys and seq updates in values.
        """
        if date:
            Validator.validate_date_format(date=date, formats=["%Y-%m-%d"])

        endpoint = "sequence_list"
        if collection:
            Validator.validate_collection_name(collection_name=collection)
            params = {"date": date, "collection": collection, "apply_hunting_rules": apply_hunting_rules}
        else:
            params = {"date": date, "apply_hunting_rules": apply_hunting_rules}
        buffer_dict = self.send_request(endpoint=endpoint, params=params).get("list")
        seq_update_dict = {}
        for key in CollectionConsts.TI_COLLECTIONS_INFO.keys():
            if key in buffer_dict.keys():
                seq_update_dict[key] = buffer_dict[key]
        return seq_update_dict

    def get_available_collections(self):
        # type: () -> List[str]
        """
        Returns a list of available collections.
        """
        endpoint = 'user/granted_collections'
        collections_dict = self.send_request(endpoint=endpoint, params={})
        parsed_collections = ParserHelper.find_element_by_key(collections_dict, 'collection')

        collections_list = []
        for col in CollectionConsts.TI_COLLECTIONS_INFO.keys():
            if col in parsed_collections:
                collections_list.append(col)
        for col in CollectionConsts.ONLY_SEARCH_COLLECTIONS:
            if col in parsed_collections:
                collections_list.append(col)

        return collections_list

    def get_hunting_rules_collections(self):
        """
        Returns a list of collections with hunting rules.
        """
        endpoint = 'user/granted_collections'
        response = self.send_request(endpoint=endpoint, params={})
        filtered_collections = []
        for item in response:
            if item.get("huntingRulesUsed"):
                collection_name = item.get('collection')
                if collection_name in CollectionConsts.TI_COLLECTIONS_INFO.keys() or \
                        collection_name in CollectionConsts.ONLY_SEARCH_COLLECTIONS:
                    filtered_collections.append(collection_name)
        return filtered_collections


class DRPPoller(Poller):
    """
    Poller is used for requests to DRP API.
    """
    def __init__(self, username, api_key, api_url=RequestConsts.API_URL_DRP):
        # type: (str, str, str) -> None
        """
        :param username: Login.
        :param api_key: API key, generated in your DRP Portal profile.
        """
        super().__init__(username=username, api_key=api_key, api_url=api_url)

    def create_update_generator(
            self,
            collection_name,
            date_from=None,
            date_to=None,
            query=None,
            sequpdate=None,
            limit=None,
            violation_type=None,
            section=None,
            ignore_validation=None,
    ):
        # type: (str, Optional[str], Optional[str], Optional[str], Union[int, str], Union[int, str], Union[List[int], List[str]], Union[List[int], List[str]], Optional[bool]) -> Generator[Parser, Any, None]
        """
        Creates a generator of :class:`Parser` class objects for an update session
        (feeds are sorted in ascending order) for `collection_name` with set parameters.
        `sequpdate` allows you to receive all relevant feeds. Such a request uses the sequpdate parameter,
        you will receive a portion of feeds that starts with the next `sequpdate` parameter for the current collection.
        For all feeds in the Threat Intelligence continuous numbering is carried out.
        For example, the `sequpdate` equal to 1999998 can be in the `compromised/accounts` collection,
        and a feed with sequpdate equal to 1999999 can be in the `attacks/ddos` collection.
        If item updates (for example, if new attacks were associated with existing APT by our specialists or tor node
        has been detected as active again), the item gets a new parameter, and it automatically rises in the database
        and "becomes relevant" again.

        .. warning:: Dates should be in one of these formats: "YYYY-MM-DD", "YYYY-MM-DDThh:mm:ssZ".
        For most collections, limits are set on the server and can't be exceeded.

        :param violation_type: 1 - scam; 2 - counterfeit
        :param section: 1 - Web; 2 - Mobile apps; 3 - Marketplace; 4 - Social networks; 5 - Advertising; 6 - Instant messengers
        :param collection_name: collection to update.
        :param date_from: start date of the update session.
        :param date_to: end date of the update session.
        :param query: query to search during the update session.
        :param sequpdate: identification number from which to start the session.
        :param limit: size of the portion in iteration.
        :param ignore_validation: ignore keys and collections validation
        :rtype: Generator[:class:`Parser`]
        """
        session_type = "update"
        generator_info = DRPGeneratorInfo(
            collection_name=collection_name,
            session_type=session_type,
            date_from=date_from,
            date_to=date_to,
            query=query,
            limit=limit,
            keys=self._keys.get(collection_name),
            iocs_keys=self._iocs_keys.get(collection_name),
            ignore_validation=ignore_validation,
            violationType=violation_type,
            section=section,
        )
        generator_class = DPRUpdateFeedGenerator(self, generator_info, sequpdate=sequpdate)
        return generator_class.create_generator()

    def get_seq_update_dict(self, date=None, collection=None):
        # type: (Optional[str], Optional[str]) -> Dict[str, int]
        """
        Gets dict with `seqUpdate` key for each collection from the server based on the provided date, collection name or
        hunting rules. If a date is not provided, returns dict for the current day.

        .. warning:: Date should be in "YYYY-MM-DD" format.

        :param date: defines the start date to get seqUpdate.
        :param collection: filter by collection name
        :return: dict with collection names in keys and seq updates in values.
        """
        if date:
            Validator.validate_date_format(date=date, formats=["%Y-%m-%d"])

        # timestamp = datetime.fromisoformat(date).replace(tzinfo=timezone.utc).timestamp()
        # fmt_str = r"%Y-%m-%dT%H:%M:%S.%f"

        # replaces the fromisoformat, not available in python 3.6
        fmt_str = r"%Y-%m-%d"
        timestamp = datetime.strptime(date, fmt_str).replace(tzinfo=timezone.utc).timestamp()

        seconds = datetime.fromtimestamp(timestamp, tz=timezone.utc).timestamp()
        miliseconds = seconds * 1000
        microseconds = miliseconds * 1000
        seqUpdate = int(microseconds)

        seq_update_dict = {}
        for key in CollectionConsts.DRP_COLLECTIONS_INFO.keys():
            seq_update_dict[key] = seqUpdate
        return seq_update_dict

    def search_feed_by_id(self, collection_name, feed_id):
        # type: (str, str) -> Parser
        """
        WARNING: please check if the collection supports this feature before use it in production code.

        Searches for a feed with the `feed_id` in the collection with `collection_name`.

        :param collection_name: in what collection to search.
        :param feed_id: id of feed to search.
        :rtype: :class:`Parser`
        """
        Validator.validate_collection_name(collection_name)
        endpoint = f"{collection_name}/{feed_id}"
        chunk = self.send_request(endpoint=endpoint, params={})
        portion = Parser(chunk, self._keys.get(collection_name, []),
                         self._iocs_keys.get(collection_name, []))
        return portion

    def change_status(self, feed_id, status):
        # type: (str, Literal['approve', 'reject']) -> None
        collection_name = "violation"

        response = self.search_feed_by_id(collection_name=collection_name, feed_id=feed_id)
        if response.raw_dict.get('status') == 'detected' and response.raw_dict.get('approveState') == 'under_review':
            endpoint = 'violation/change-approve'
            body = {
                "violationId": feed_id,
                "approve": status
            }
            self.send_request(endpoint=endpoint, method="POST", body=body)
        else:
            logger.exception(AttributeError("Can not change the status of the selected feed"))


class ASMPoller(Poller):
    """
    Poller is used for requests to ASM API.
    """
    def __init__(self, username, api_key, api_url=RequestConsts.API_URL_ASM):
        # type: (str, str, str) -> None
        """
        :param username: Login.
        :param api_key: API key, generated in your ASM Portal profile.
        """
        super().__init__(username=username, api_key=api_key, api_url=api_url)
        # self._session.headers.update({'Host': 'client-api-test.dm-kuber.facct.dev'})

    def create_update_generator(
            self,
            collection_name,
            date_from=None,
            date_to=None,
            query=None,
            sequpdate=None,
            limit=None,
            company_id=None,
            ignore_validation=None,
    ):
        # type: (str, Optional[str], Optional[str], Optional[str], Union[int, str], Union[int, str], Union[str, int], Optional[bool]) -> Generator[Parser, Any, None]
        """
        Creates a generator of :class:`Parser` class objects for the search session
        (feeds are sorted in descending order, **excluding compromised/breached and compromised/reaper**)
        for `collection_name` with set parameters.

        .. warning:: Dates should be in one of these formats: "YYYY-MM-DD", "YYYY-MM-DDThh:mm:ssZ".
        For most collections, limits are set on the server and can't be exceeded.

        :param collection_name: collection to search.
        :param date_from: start date of the search session.
        :param date_to: end date of the search session.
        :param query: query to search during the session.
        :param sequpdate: identification number from which to start the session.
        :param limit: size of the portion in the iteration.
        :param company_id: company ID
        :param ignore_validation: ignore keys and collections validation
        :rtype: Generator[:class:`Parser`]
        """
        session_type = "update"
        generator_info = ASMGeneratorInfo(
            collection_name=collection_name,
            session_type=session_type,
            date_from=date_from,
            date_to=date_to,
            query=query,
            limit=limit,
            keys=self._keys.get(collection_name),
            iocs_keys=self._iocs_keys.get(collection_name),
            ignore_validation=ignore_validation,
            company_id=company_id
        )
        generator_class = ASMUpdateFeedGenerator(self, generator_info, sequpdate=sequpdate, company_id=company_id)
        return generator_class.create_generator()


    def get_seq_update_dict(
            self,
            date=None,
            collection=None,
    ):
        # type: (Optional[str], Optional[str]) -> Any[str, int]
        """
        Gets dict with `seqUpdate` key for each collection from the server based on the provided date, collection name or
        hunting rules. If a date is not provided, returns dict for the current day.

        .. warning:: Date should be in "YYYY-MM-DD" format.

        :param date: defines the start date to get seqUpdate.
        :param collection: filter by collection name
        :return: dict with collection names in keys and seq updates in values.
        """
        if date:
            Validator.validate_date_format(date=date, formats=["%Y-%m-%d"])

        # timestamp = datetime.fromisoformat(date).replace(tzinfo=timezone.utc).timestamp()
        # fmt_str = r"%Y-%m-%dT%H:%M:%S.%f"

        # replaces the fromisoformat, not available in python 3.6
        fmt_str = r"%Y-%m-%d"
        timestamp = datetime.strptime(date, fmt_str).replace(tzinfo=timezone.utc).timestamp()

        seconds = datetime.fromtimestamp(timestamp, tz=timezone.utc).timestamp()
        miliseconds = seconds * 1000
        seqUpdate = int(miliseconds)

        if collection:
            return seqUpdate
        else:
            seq_update_dict = {}
            for key in CollectionConsts.ASM_COLLECTIONS_INFO.keys():
                seq_update_dict[key] = seqUpdate
            return seq_update_dict




class FeedGenerator(object):
    """
    Base Feed Generator class
    """
    def __init__(self, poller_object, generator_info):
        # type: (Union[TIPoller, DRPPoller, ASMPoller], Union[TIGeneratorInfo, DRPGeneratorInfo, ASMGeneratorInfo]) -> None
        self.i = 0
        self.total_amount = 0
        self.poller_object = poller_object
        self.generator_info = generator_info
        self.endpoint = self.generator_info.collection_name

    def _get_params(self):
        return {
            'df': self.generator_info.date_from,
            'dt': self.generator_info.date_to,
            'q': self.generator_info.query,
            'limit': self.generator_info.limit,
            # 'apply_hunting_rules': self.generator_info.apply_hunting_rules
        }

    def _reset_params(self, portion):
        pass

    def create_generator(self):
        # type: () -> Generator[Parser, Any, None]
        logger.info(f"Starting {self.generator_info.session_type} "
                    f"session for {self.generator_info.collection_name} collection")

        while True:
            self.i += 1
            logger.info(f"Loading {self.i} portion")
            chunk = self.poller_object.send_request(endpoint=self.endpoint, params=self._get_params())
            portion = Parser(chunk, self.generator_info.keys, self.generator_info.iocs_keys)
            logger.info(f"{self.i} portion was loaded")
            if portion.portion_size == 0:
                logger.info(f"{self.generator_info.session_type} session for {self.generator_info.collection_name} "
                            f"collection was finished, loaded {self.total_amount} feeds")
                break
            self.total_amount += portion.portion_size
            self._reset_params(portion)
            yield portion


class TIUpdateFeedGenerator(FeedGenerator):
    def __init__(self, poller_object, generator_info, sequpdate):
        # type: (TIPoller, TIGeneratorInfo, Union[int, str, None]) -> None
        super().__init__(poller_object, generator_info)
        self.sequpdate = sequpdate
        self.endpoint = f"{self.generator_info.collection_name}/updated"

    def _get_params(self):
        return {
            **super()._get_params(),
            "seqUpdate": self.sequpdate,
            "apply_hunting_rules": self.generator_info.apply_hunting_rules,
            "is_tailored": self.generator_info.is_tailored,
            **self.generator_info.params,
        }

    def _reset_params(self, portion):
        self.sequpdate = portion.sequpdate
        self.generator_info.date_from = None

    def create_generator(self):
        # type: () -> Generator[Parser, Any, None]
        logger.info(f"Starting {self.generator_info.session_type} "
                    f"session for {self.generator_info.collection_name} collection")
        while True:
            self.i += 1
            logger.info(f"Loading {self.i} portion")
            chunk = self.poller_object.send_request(endpoint=self.endpoint, params=self._get_params())

            if self.generator_info.parse_events and Validator.validate_group_collections(self.generator_info.collection_name):
                expanded_data = {
                    "count": chunk.get("count"),
                    "seqUpdate": chunk.get("seqUpdate"),
                    "items": []
                }
                for item in chunk["items"]:
                    events = item.get("events", [])
                    if events:
                        for event in events:
                            expanded_event = dict(item)
                            expanded_event["events"] = [event]
                            expanded_data["items"].append(expanded_event)
                    else:
                        expanded_data["items"].append(item)
                chunk = expanded_data

            portion = Parser(chunk, self.generator_info.keys, self.generator_info.iocs_keys)
            logger.info(f"{self.i} portion was loaded")
            if portion.portion_size == 0:
                logger.info(f"{self.generator_info.session_type} session for {self.generator_info.collection_name} "
                            f"collection was finished, loaded {self.total_amount} feeds")
                break
            self.total_amount += portion.portion_size
            self._reset_params(portion)
            yield portion


class TISearchFeedGenerator(FeedGenerator):
    def __init__(self, poller_object, generator_info):
        # type: (TIPoller, TIGeneratorInfo) -> None
        super().__init__(poller_object, generator_info)
        self.result_id = None

    def _get_params(self):
        return {
            **super()._get_params(),
            "resultId": self.result_id,
            "apply_hunting_rules": self.generator_info.apply_hunting_rules,
            **self.generator_info.params,
        }

    def _reset_params(self, portion):
        self.result_id = portion._result_id
        self.generator_info.date_from, self.generator_info.date_to, self.generator_info.query = None, None, None

    def create_generator(self):
        # type: () -> Generator[Parser, Any, None]
        logger.info(f"Starting {self.generator_info.session_type} "
                    f"session for {self.generator_info.collection_name} collection")

        while True:
            self.i += 1
            logger.info(f"Loading {self.i} portion")
            chunk = self.poller_object.send_request(endpoint=self.endpoint, params=self._get_params())

            if self.generator_info.parse_events and Validator.validate_group_collections(self.generator_info.collection_name):
                expanded_data = {
                    "count": chunk.get("count"),
                    "resultId": chunk.get("resultId"),
                    "items": []
                }
                for item in chunk["items"]:
                    events = item.get("events", [])
                    if events:
                        for event in events:
                            expanded_event = dict(item)
                            expanded_event["events"] = [event]
                            expanded_data["items"].append(expanded_event)
                    else:
                        expanded_data["items"].append(item)
                chunk = expanded_data

            portion = Parser(chunk, self.generator_info.keys, self.generator_info.iocs_keys)
            logger.info(f"{self.i} portion was loaded")
            if portion.portion_size == 0:
                logger.info(f"{self.generator_info.session_type} session for {self.generator_info.collection_name} "
                            f"collection was finished, loaded {self.total_amount} feeds")
                break
            self.total_amount += portion.portion_size
            self._reset_params(portion)
            yield portion


class DPRUpdateFeedGenerator(FeedGenerator):

    def __init__(self, poller_object, generator_info, sequpdate):
        # type: (DRPPoller, DRPGeneratorInfo, Union[int, str, None]) -> None
        super().__init__(poller_object, generator_info)
        self.sequpdate = sequpdate
        self.endpoint = f"{self.generator_info.collection_name}"

    def _get_params(self):
        return {
            **super()._get_params(),
            "seqUpdate": self.sequpdate,
            "violationType[]": self.generator_info.violationType,
            "section[]": self.generator_info.section
        }

    def _reset_params(self, portion):
        self.sequpdate = portion.sequpdate
        self.generator_info.date_from = None


class ASMUpdateFeedGenerator(FeedGenerator):
    def __init__(self, poller_object, generator_info, sequpdate, company_id):
        # type: (ASMPoller, ASMGeneratorInfo, Union[int, str, None], Union[int, str, None]) -> None
        super().__init__(poller_object, generator_info)
        self.sequpdate = sequpdate
        self.company_id = company_id
        self.endpoint = f"{self.generator_info.collection_name}/updated"


    def create_generator(self):
        # type: () -> Generator[Parser, Any, None]
        logger.info(f"Starting {self.generator_info.session_type} "
                    f"session for {self.generator_info.collection_name} collection")

        while True:
            self.i += 1
            logger.info(f"Loading {self.i} portion")
            chunk = self.poller_object.send_request(endpoint=self.endpoint, body=self._get_data(), method='POST')
            portion = Parser(chunk, self.generator_info.keys, self.generator_info.iocs_keys)
            logger.info(f"{self.i} portion was loaded")
            if portion.portion_size == 0:
                logger.info(f"{self.generator_info.session_type} session for {self.generator_info.collection_name} "
                            f"collection was finished, loaded {self.total_amount} feeds")
                break
            self.total_amount += portion.portion_size
            self._reset_params(portion)
            yield portion

    def _get_data(self):
        return {
            "companyId": self.company_id,
            "limit": 100,
            "seqUpdate": self.sequpdate
            }

    def _reset_params(self, portion):
        self.sequpdate = portion.sequpdate
        self.generator_info.date_from = None

