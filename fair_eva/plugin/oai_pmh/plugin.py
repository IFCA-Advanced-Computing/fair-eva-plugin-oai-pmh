# SPDX-FileCopyrightText: Copyright contributors to the FAIR eva project
# SPDX-FileContributor: Fernando Aguilar <aguilarf@ifca.unican.es>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# coding: utf-8
from configparser import ConfigParser
import idutils
import logging
import pandas as pd
import requests
import sys
from types import NotImplementedType
from typing import Union
import urllib
import xml.etree.ElementTree as ET

from fair_eva.api.evaluator import EvaluatorBase
from pandas import DataFrame

logging.basicConfig(
    stream=sys.stdout, level=logging.DEBUG, format="'%(name)s:%(lineno)s' | %(message)s"
)
logger = logging.getLogger("api.plugin")


class Plugin(EvaluatorBase):
    """A class implements the RDA's FAIR indicators for the <oai-pmh> plugin.

    Essential FAIR indicators are pre-implemented in the parent EvaluatorBase class. The remainder
    shall be coded as methods within this class.
    """

    def __init__(
        self,
        item_id: str,
        api_endpoint: str = "https://zenodo.org/oai2d",
        lang: str = "en",
        config: ConfigParser = ConfigParser(),
        name: str = "oai-pmh",
    ):
        """
        :param item_id: (persistent or not) identifier of the dataset, e.g. DOI, Handle
        or internal.
        :type item_id: str
        :param api_endpoint: Endpoint from which the metadata is collected.
        :type api_endpoint: str
        :param lang: Two-letter language code.
        :type lang: str
        :param config: ConfigParser's object containing both plugin's and main configuration.
        :type config: ConfigParser
        :param name: FAIR-EVA's plugin name.
        :type name: str
        """
        logger.debug(f"Initiating FAIR-EVA's <{name}> plugin")

        # Parent __init__ call
        super().__init__(item_id, api_endpoint, lang, config, name)

        # Metadata gathering
        self.metadata = self.get_metadata()
        if self.metadata.empty:
            error_message = f"Problem accessing (meta)data from repository <{api_endpoint}>"
            logger.error(error_message)
            raise Exception(error_message)
        logger.debug(f"Successfuly obtained metadata from repository: {self.metadata}")

    def oai_check_record_url(self, oai_base, metadata_prefix, pid):
        endpoint_root = urllib.parse.urlparse(oai_base).netloc
        try:
            pid_type = idutils.detect_identifier_schemes(pid)[0]
        except Exception as e:
            pid_type = "internal"
            logging.error(e)
        if pid_type != "internal":
            oai_pid = idutils.normalize_pid(pid, pid_type)
        else:
            oai_pid = pid
        action = "?verb=GetRecord"

        test_id = "oai:%s:%s" % (endpoint_root, oai_pid)
        params = "&metadataPrefix=%s&identifier=%s" % (metadata_prefix, test_id)
        url_final = ""
        url = oai_base + action + params
        response = requests.get(url, verify=False, allow_redirects=True)
        logging.debug(
            "Trying ID v1: url: %s | status: %i" % (url, response.status_code)
        )
        error = 0
        for tags in ET.fromstring(response.text).findall(
            ".//{http://www.openarchives.org/OAI/2.0/}error"
        ):
            error = error + 1
        if error == 0:
            url_final = url

        test_id = "%s" % (oai_pid)
        params = "&metadataPrefix=%s&identifier=%s" % (metadata_prefix, test_id)

        url = oai_base + action + params
        logging.debug("Trying: " + url)
        response = requests.get(url, verify=False)
        error = 0
        for tags in ET.fromstring(response.text).findall(
            ".//{http://www.openarchives.org/OAI/2.0/}error"
        ):
            error = error + 1
        if error == 0:
            url_final = url

        test_id = "%s:%s" % (pid_type, oai_pid)
        params = "&metadataPrefix=%s&identifier=%s" % (metadata_prefix, test_id)

        url = oai_base + action + params
        logging.debug("Trying: " + url)
        response = requests.get(url, verify=False)
        error = 0
        for tags in ET.fromstring(response.text).findall(
            ".//{http://www.openarchives.org/OAI/2.0/}error"
        ):
            error = error + 1
        if error == 0:
            url_final = url

        test_id = "oai:%s:%s" % (
            endpoint_root,
            oai_pid[oai_pid.rfind(".") + 1 : len(oai_pid)],
        )
        params = "&metadataPrefix=%s&identifier=%s" % (metadata_prefix, test_id)

        url = oai_base + action + params
        logging.debug("Trying: " + url)
        response = requests.get(url, verify=False)
        error = 0
        for tags in ET.fromstring(response.text).findall(
            ".//{http://www.openarchives.org/OAI/2.0/}error"
        ):
            error = error + 1
        if error == 0:
            url_final = url

        test_id = "oai:%s:b2rec/%s" % (
            endpoint_root,
            oai_pid[oai_pid.rfind(".") + 1 : len(oai_pid)],
        )
        params = "&metadataPrefix=%s&identifier=%s" % (metadata_prefix, test_id)

        url = oai_base + action + params
        logging.debug("Trying: " + url)
        response = requests.get(url, verify=False)
        error = 0
        for tags in ET.fromstring(response.text).findall(
            ".//{http://www.openarchives.org/OAI/2.0/}error"
        ):
            error = error + 1
        if error == 0:
            url_final = url

        return url_final

    def oai_identify(self, oai_base):
        action = "?verb=Identify"
        return self.oai_request(oai_base, action)

    def oai_metadataFormats(self, oai_base):
        action = "?verb=ListMetadataFormats"
        xmlTree = self.oai_request(oai_base, action)
        metadataFormats = {}
        for e in xmlTree.findall(
            ".//{http://www.openarchives.org/OAI/2.0/}metadataFormat"
        ):
            metadataPrefix = e.find(
                "{http://www.openarchives.org/OAI/2.0/}metadataPrefix"
            ).text
            namespace = e.find(
                "{http://www.openarchives.org/OAI/2.0/}metadataNamespace"
            ).text
            metadataFormats[metadataPrefix] = namespace
        return metadataFormats

    def oai_get_metadata(self, url):
        logger.debug("Metadata from: %s" % url)
        oai = requests.get(url, verify=False, allow_redirects=True)
        try:
            xmlTree = ET.fromstring(oai.text)
        except Exception as e:
            logger.error("OAI_RQUEST: %s" % e)
            xmlTree = None
        return xmlTree

    def oai_request(self, oai_base, action):
        oai = requests.get(oai_base + action, verify=False)  # Peticion al servidor
        try:
            xmlTree = ET.fromstring(oai.text)
        except Exception as e:
            logging.error("OAI_RQUEST: %s" % e)
            xmlTree = ET.fromstring("<OAI-PMH></OAI-PMH>")
        return xmlTree

    def get_metadata(self) -> Union[DataFrame, NotImplementedType]:
        logger.debug("OAI_BASE IN evaluator: %s" % self.api_endpoint)
        if (
            self.api_endpoint is not None
            and self.api_endpoint != ""
            and self.metadata is None
        ):
            metadataFormats = self.oai_metadataFormats(self.api_endpoint)
            dc_prefix = ""
            for e in metadataFormats:
                if metadataFormats[e] == "http://www.openarchives.org/OAI/2.0/oai_dc/":
                    dc_prefix = e
            logger.debug("DC_PREFIX: %s" % dc_prefix)

            try:
                id_type = idutils.detect_identifier_schemes(self.item_id)[0]
            except Exception as e:
                id_type = "internal"

            logger.debug("Trying to get metadata")
            try:
                item_metadata = self.oai_get_metadata(
                    self.oai_check_record_url(
                        self.api_endpoint, dc_prefix, self.item_id
                    )
                ).find(".//{http://www.openarchives.org/OAI/2.0/}metadata")
            except Exception as e:
                logger.error("Problem getting metadata: %s" % e)
                item_metadata = ET.fromstring("<metadata></metadata>")
            data = []
            for tags in item_metadata.findall(".//"):
                metadata_schema = tags.tag[0 : tags.tag.rfind("}") + 1]
                element = tags.tag[tags.tag.rfind("}") + 1 : len(tags.tag)]
                text_value = tags.text
                qualifier = None
                data.append([metadata_schema, element, text_value, qualifier])

            df = pd.DataFrame(data, columns=["metadata_schema", "element", "text_value", "qualifier"])
            print(df)
        return df
