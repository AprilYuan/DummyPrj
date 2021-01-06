"""This module illustrates how to write your docstring in OpenAlea
and other projects related to OpenAlea.

:copyright: Nokia Networks
:author: Zhu Haofeng
:contact: haofeng.zhu@nokia-sbell.com
:maintainer: None
:contact: None
"""

__license__ = "Cecill-C"
__revision__ = " $Id: actor.py 1586 2009-01-30 15:56:25Z cokelaer $ "
__docformat__ = 'reStructuredText'

import re
import logging
import pyshark


class CapPacket(object):
    """This class docstring shows how to use sphinx and rst syntax

        The first line is brief explanation, which may be completed with
        a longer one. For instance to discuss about its methods. The only
        method here is :func:`function1`'s. The main idea is to document
        the class and methods's arguments with
    """
    def __init__(self):
        self._packets = None
        self._filtered_packets = []

    def read_cap(self, cap_file, **kwargs):
        """load wireshark file for checking fields

        :param cap_file: tcpdump cap file
        :param keep_packets: Whether to keep packets after reading them via next(). large caps (can only be used along with the "lazy" option!)
        :param display_filter: A display (wireshark) filter to apply on the cap before reading it.
        :param only_summaries: Only produce packet summaries, much faster but includes very little information.
        :param decryption_key: Optional key used to encrypt and decrypt captured traffic.
        :param encryption_type: Standard of encryption used in captured traffic (must be either 'WEP', 'WPA-PWD', or 'WPA-PWK'. Defaults to WPA-PWK).
        :param decode_as: A dictionary of {decode_criterion_string: decode_as_protocol} that are used to tell tshark
                to decode protocols in situations it wouldn't usually, for instance {'tcp.port==8888': 'http'} would make
                it attempt to decode any port 8888 traffic as HTTP. See tshark documentation for details.
        :param tshark_path: Path of the tshark binary
        :param override_prefs: A dictionary of tshark preferences to override, {PREFERENCE_NAME: PREFERENCE_VALUE}.
        :param disable_protocol: Tells tshark to remove a dissector for a specific protocol.
        :param use_json: Uses tshark in JSON mode (EXPERIMENTAL). It is a good deal faster than XML
                but also has less information. Available from Wireshark 2.2.0.
        :param X: <key>:<value> eXtension options, see the man page for details
        :return: NA
        """
        self._packets = FileCaptureEx(cap_file, **kwargs)

    def check_expression(self, condition_expression, log=True):
        """
        check if expression is matched in packets
        :param condition_expression: expression which you can get from wireshark tool filter
        :return: filtered packages, if check failed, will raise exception
        """
        expressions = self._split_expression(condition_expression)
        checked_packet_list = []
        self._filtered_packets = []
        for idx, packet in enumerate(self._packets):
            for expression_data in expressions:
                field_info, field_index, check_value = expression_data
                field_data_list = self._get_field_from_packet(packet, field_info)
                if field_index is not None and field_index < len(field_data_list):
                    field_data_list = [field_data_list[field_index]]
                checked_packet_list += [packet] if len(field_data_list) else []
                if not self._is_fields_value_matched(field_data_list, check_value):
                    break
            else:
                self._filtered_packets.append(packet)
        if self._filtered_packets:
            self._print_check_success(condition_expression)
            return self._filtered_packets
        self._print_check_failed_and_raise_exception(condition_expression, log)

    def _split_expression(self, expression_str):
        expression_str = expression_str.lower()
        splitted_exps = expression_str.split(" and ") if ' and ' in expression_str else expression_str.split(" && ")
        expressions = [each.strip() for each in splitted_exps]
        return [self._parse_expression(expression) for expression in expressions]

    def _parse_expression(self, expression):
        check_field_info, check_value = [expression.strip() for expression in expression.split('==')]
        expression_data = self._get_field_name_and_index(check_field_info)
        expression_data.append(check_value)
        return expression_data

    def _get_field_from_packet(self, packet, field_check_expression):
        field_expression = self._convert_to_pyshark_expression(field_check_expression)
        other_possible_expressions = self._get_possible_field_expressions(packet, field_expression)
        all_expressions = [field_expression] + other_possible_expressions
        fields_objs = []
        for expression in all_expressions:
            if not expression.startswith('frame_info'):
                layer_name, expression = expression.split('.', 1)
                layers = self._get_layers(packet, layer_name)
            else:
                layers = [packet]

            for layer in layers:
                try:
                    fields_objs += self._get_fields(layer, expression)
                except AttributeError:
                    continue
        return fields_objs

    def _get_layers(self, packet, layer_name):
        return packet.get_multiple_layers(layer_name)

    def _get_fields(self, layer, expression):
        attr_obj = layer
        for each_attr in expression.split('.') + ['fields']:
            attr_obj = getattr(attr_obj, each_attr)
        return attr_obj

    @staticmethod
    def _convert_to_pyshark_expression(filter_expression):
        elems = [each for each in filter_expression.split('.')]
        layer_name, field_info = elems[0], elems[1:]
        return "{layer}.{field_name}".format(layer=layer_name, field_name='_'.join(field_info))

    def _get_possible_field_expressions(self, packet, field_expression):
        layer_names = self._get_packet_layer_names(packet)
        field_name = field_expression.replace('.', '_')
        return [layer + '.' + field_name for layer in layer_names]

    @staticmethod
    def _get_packet_layer_names(packet):
        return [layer.layer_name for layer in packet.layers]

    def _get_field_name_and_index(self, name):
        expr_res = re.search(r"(?P<name>.+)\[(?P<index>\d+)\]$", name)
        if expr_res:
            res = expr_res.groupdict()
            return [res['name'], int(res['index'])]
        return [name, None]

    def _check_expression_in_packet(self, expression, packet):
        field_info, field_index, check_value = expression
        field_data_list = self._get_field_from_packet(packet, field_info)
        if field_index is not None and field_index < len(field_data_list):
            field_data_list = [field_data_list[field_index]]

        return self._is_fields_value_matched(field_data_list, check_value)

    def _is_fields_value_matched(self, filtered_data_list, check_value):
        if not filtered_data_list:
            return False

        return any(self._is_field_equal_to_check_value(filed_data.get_default_value(), check_value)
                   for filed_data in filtered_data_list)

    def _is_field_equal_to_check_value(self, field_value, check_value):
        if field_value == check_value:
            return True

        if self._is_number_value_str(field_value) and self._is_number_value_str(check_value):
            if self._convert_into_integer(field_value) == self._convert_into_integer(check_value):
                return True
        return False

    def _is_number_value_str(self, elem_value):
        return True if re.match(r'^(0x|0X){0,1}[\da-fA-F]+$', elem_value) else False

    def _convert_into_integer(self, num_str):
        return int(num_str, 16) if num_str.startswith('0x') or num_str.startswith('0X') else int(num_str)

    def _print_check_success(self, expression):
        logging.info("check successfully:" + expression)

    def _print_check_failed_and_raise_exception(self, expression, log=True):
        if log:
            logging.error('check failed:')
        raise CheckExpressionFailed(expression + ' check failed')

    def check_file(self, check_expression_file):
        """
        check if all expressions are matched in packets in file
        :param check_expression_file: check file name
        :return: NA, if check failed, will raise exception
        """
        with open(check_expression_file) as fh:
            for check_expression_str in fh:
                self.check_expression(check_expression_str.strip())

    def get_element_value(self, element_expression, element_idx=0, default_value=False, raw_data=True,
                          condition_expression=None):
        """get element value by element_expression(e.g., x2ap_5g18a_3_01.id) ,idx and condition_expression

        :paramelement_expression: field name of element
        :paramelement_idx: index of element, if one packet have multiple same element by field name, can use idx to specify one
        :paramdefault_value: default value in packet, if it is False, return raw value
        :paramraw_data: raw data in packet, if it is True, return decimal value string
        :paramcondition_expression: string condition to filter (e.g., x2ap_5g18a_3_01.id[0] == 111 and x2ap_5g18a_3_01.id[1] == 248)
        :return: list of values
        """
        elem_values = []
        if condition_expression:
            try:
                self.check_expression(condition_expression)
            except CheckExpressionFailed:
                return []
        else:
            self._filtered_packets = self._packets

        for packet in self._filtered_packets:
            elem = self._get_field_from_packet(packet, element_expression)
            if elem and isinstance(elem, list):
                elem = elem[element_idx]
                if default_value:
                    elem_values.append(self._get_default_value(elem))
                else:
                    elem_values.append(self._get_raw_hex(elem, raw_data))
        return elem_values

    def _get_default_value(self, elem):
        return elem.get_default_value()

    def _get_raw_hex(self, elem, raw_data):
        return elem.raw_value if raw_data else elem.hex_value

    def get_occurences_for_expression(self, condition_expression):
        """
        check if expression is matched in packets
        :condition_expression: expression which you can get from wireshark tool filter
        :return: NB of filtered packets matching condition expression
        """
        expressions = self._split_expression(condition_expression)
        checked_packet_list = []
        self._filtered_packets = []
        for idx, packet in enumerate(self._packets):
            for expression_data in expressions:
                field_info, field_index, check_value = expression_data
                field_data_list = self._get_field_from_packet(packet, field_info)
                if field_index is not None and field_index < len(field_data_list):
                    field_data_list = [field_data_list[field_index]]
                checked_packet_list += [packet] if len(field_data_list) else []
                if not self._is_fields_value_matched(field_data_list, check_value):
                    break
            else:
                self._filtered_packets.append(packet)
        return len(self._filtered_packets)


