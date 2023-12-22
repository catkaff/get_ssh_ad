#!/bin/env python3
# -*- coding: utf-8 -*-
from ldap3 import Connection, Server, ALL, Tls


import sys, logging, ssl
from python_freeipa import ClientMeta
from python_freeipa.exceptions import FreeIPAError
from pprint import pprint
from python_freeipa.exceptions import DuplicateEntry
from requests.exceptions import ConnectionError

from dotenv import load_dotenv
import os
import re
from pprint import pformat

#-----------------------------------------------------------
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Игнорировать предупреждения InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)
#___________________________________________________________

# AD connect
def ad_connect(ad_user, ad_user_password, ad_kds, adca):
        tlset = Tls(validate=ssl.CERT_OPTIONAL, version=ssl.PROTOCOL_TLSv1_2, ca_certs_file=adca)
        timeout = 10
        for ad_kd in ad_kds:
            try:
                server = Server(ad_kd, port=636, use_ssl=True, get_info=ALL, tls=tlset, connect_timeout=timeout)
                ad_connection = Connection(server, ad_user, ad_user_password, read_only=False, lazy=False)

                ad_connection.open()
                if ad_connection.bind():
                    logging.info(f'==> AD_KD_Server {ad_kd} connect_status: {ad_connection.result}\n')
                    return ad_connection
                else:
                    logging.info(f'==> AD_KD_Server {ad_kd} bind_failed: {ad_connection.result}')
            except Exception as e:
                logging.info(f'==> AD_KD_Server {ad_kd} ERROR: {e}')
        logging.error(f'All AD server connections failed: {ad_kds}')
        sys.exit(1)
#  END Connect

# FreeIPA connect
def connect_to_freeipa(servers, ver_ssl, username, password):
    for server in servers:
        try:
            ipaclient = ClientMeta(server, verify_ssl=ver_ssl)
            ipaclient.login(username, password)
            info = ipaclient.ping()
            logging.info(f'Successfully connected and logged in to FreeIPA server: {server}')
            logging.info(f'{info} => {ipaclient.version}')
            return ipaclient
        except (FreeIPAError, ConnectionError) as e:
            logging.error(f"Failed to connect to FreeIPA server {server}: {e}")
            continue
    logging.error("All FreeIPA servers are unreachable.")
    sys.exit(1)
# END FreeIPA connect

#  Search for all groups and all users in those groups
def ad_search_groups_with_users(ad_connection, ad_groups_dn):
    ad_connection.search(ad_groups_dn, '(objectclass=group)')
    ad_groups = ad_connection.entries
    ad_group_dict = {}
    for group in ad_groups:
#        print(f'=====================================>>> {group.entry_dn}')
        group_name = group.entry_dn.split(',')[0].split('=')[1]  # Имя группы
#        print(f'=====================================>>> {group_name}')

        # Получение списка пользователей для каждой группы
        ad_connection.search(group.entry_dn, search_filter='(objectClass=group)', search_scope='SUBTREE', attributes = ['member'])
        for entry in ad_connection.entries:
            ipausernames = set()
            dn_list = entry.member
#            print(f'=====================================>>> {dn_list}')
            for dn in dn_list:
                # Поиск userPrincipalName для каждого DN в dn_list
                ad_connection.search(dn, search_filter='(objectClass=user)', attributes=['userPrincipalName'])
                for user in ad_connection.entries:
                    ipausernames.add(user.userPrincipalName.value)
            ad_group_dict[group_name] = ipausernames
    return ad_group_dict

#  Search for all external groups and all users in those groups on Freeipa  server
def ipa_search_groups_with_users(ad_connection, ad_users_dn, ipaclient):
    ipa_group_dict = {}
    response = ipaclient.group_find(o_external=True)
    # Filter and print external groups
    for group in response['result']:
        ipa_user_list = set()
        sid_users_in_ipa_group = group.get('ipaexternalmember')
        if sid_users_in_ipa_group is not None:
            for sid_str in sid_users_in_ipa_group:
                ad_connection.search(ad_users_dn, f'(objectSid={sid_str})', attributes=['objectSid', 'sAMAccountName', 'userPrincipalName'])
                for user in ad_connection.entries:
                    ipa_user_list.add(user.userPrincipalName.value)
        else:
            ipa_user_list = set()
        ipa_group_dict[group['cn'][0]] = ipa_user_list
    return ipa_group_dict

# Добавление внешней и внутренней группы в FReeIPA
def ipa_add_groups(ipaclient, new_ipa_groups):
    for ipagrp in new_ipa_groups:
        try:
            ipaclient.group_add(a_cn=ipagrp, o_nonposix=True, o_external=True)
            logging.info(f'<<< <=:=> >>> Added EXTERNAL group {ipagrp}')

            internal_group = f'{ipagrp}_int'

            ipaclient.group_add(a_cn=internal_group)
            logging.info(f'<<< ::: >>> Added INTERNAL group {internal_group}')

            ipaclient.group_add_member(a_cn=internal_group, o_group=ipagrp)
            logging.info(f'<<< | >>> Added in INTERNAL group {internal_group}  an EXTERNAL group {ipagrp}')

        except DuplicateEntry:
            logging.warning(f'Group with name already exists: {DuplicateEntry}')

# Delete external and internal group in FreeIPA
def ipa_del_groups(ipaclient, del_ipa_groups):
    for del_group in del_ipa_groups:
        try:
            ipaclient.group_del(del_group)
            logging.info(f'* * * EXTERNAL group {del_group} is deleted in FreeIPA')

            internal_group = f'{del_group}_int'
            ipaclient.group_del(internal_group)
            logging.info(f'*** INTERNAL group {internal_group} is deleted in FreeIPA')
        except FreeIPAError as e:
            logging.error(f'Failed to delete group:  {e}')

# Add user in external IPA groups
def ipa_add_del_users_in_groups(ipaclient, ad_group_dict: dict, ipa_group_dict: dict):
    for ad_group in ad_group_dict.keys():
        try:
            users_in_ad_group = ad_group_dict[ad_group]
            users_in_ipa_group = ipa_group_dict[ad_group]
            # Для текущей внешней группы FreeIPA узнаем не хватает ли ей внешних АД пользователей
            new_ipa_users = users_in_ad_group - users_in_ipa_group

            # Для текущей внешней группы FreeIPA узнаем есть ли лишние пользователи, которых нет в АД группе
            del_ipa_users = users_in_ipa_group - users_in_ad_group

            # Добавляем внешних пользователей АД в текущую внешнюю группу FreeIPA
            if new_ipa_users:
                logging.info(f'{ad_group} = > users for adding {new_ipa_users}')
                for ipauser in new_ipa_users:
                    ipaclient.group_add_member(a_cn=ad_group, o_ipaexternalmember=ipauser)
                    logging.info(f'Add user {ipauser} in IPA external group {ad_group}')

            if del_ipa_users:
                logging.info(f'{ad_group} = > users for deleting: {del_ipa_users}')
                for ipauser in del_ipa_users:
                    ipaclient.group_remove_member(a_cn=ad_group, o_ipaexternalmember=ipauser)
                    logging.info(f'Delete user {ipauser} in IPA external group {ad_group}')

        except DuplicateEntry:
            logging.warning("User with name 'external_group_test' already exists")
    return 0

#-------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    load_dotenv('ad_ipa.conf')

    # Получение строки серверов из переменной окружения
    ipaservers = os.getenv('ipa_server')
    # Разделение строки на список серверов с использованием регулярных выражений
    ipa_servers = re.split(r'\s*,\s*', ipaservers.strip())
    ipaver_ssl = os.getenv('ipa_server_ca')
    ipausername = os.getenv('ipa_user_admin')
    ipapassword = os.getenv('ipa_user_admin_passwd')

    ad_groups_dn = os.getenv('ad_groups_dn')
    ad_users_dn = os.getenv('ad_users_dn')

    ad_kd = os.getenv('ad_server')
    ad_kds = re.split(r'\s*,\s*', ad_kd.strip())
    adca = os.getenv('ad_ca_sert')
    ad_user = os.getenv('ad_user')
    ad_user_password = os.getenv('ad_user_password')

    script_log_file = os.getenv('script_log_file')
    script_log_level = os.getenv('script_log_level')
    log_format = os.getenv('log_format')
    log_datefmt = os.getenv('log_datefmt')
    log_encoding = os.getenv('log_encoding')

    # Получим числовое значение уровня логирования
    level = logging.getLevelName(script_log_level)
# Настраиваем логгирование всех действий скрипта в файл
    logging.basicConfig(filename=script_log_file, level=level, format=log_format, datefmt=log_datefmt, encoding=log_encoding)

# define a Handler which writes INFO messages or higher to the sys.stderr
# Здесь настройка вывода выхлопа информационных сообщений скрипта еще и в консоль помимо записи лога файла
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    # add the handler to the root logger
    logging.getLogger('').addHandler(console)

# Соединяемся с АД согласно полученным кредам
    ad_connection = ad_connect(ad_user, ad_user_password, ad_kds, adca)

# Подключение к FreeIPA
    ipaclient = connect_to_freeipa(ipa_servers, ipaver_ssl, ipausername, ipapassword)

# Первый раз получаем словарь групп и множеств пользователей
    ad_group_dict = ad_search_groups_with_users(ad_connection, ad_groups_dn)


    ad_groups_formatted = pformat(ad_group_dict)
    logging.info(f'\nBEGIN: AD groups and users:\n{ad_groups_formatted}\n')

    ipa_group_dict = ipa_search_groups_with_users(ad_connection, ad_users_dn, ipaclient)
    ipa_groups_formatted = pformat(ipa_group_dict)
    logging.info(f'BEGIN: IPA groups and users:\n{ipa_groups_formatted}\n')

    newline = "\n"

    # Узнаем появились ли в АД новые группы
    new_ipa_groups = set(ad_group_dict.keys()) - set(ipa_group_dict.keys())
    # Есть ли в FreeIPA внешние группы, которых нет в АД для последующего их удаления
    delete_ipa_groups = set(ipa_group_dict.keys()) - set(ad_group_dict.keys())

    # Добавление новых групп в FreeIPA
    if new_ipa_groups:
        logging.info(f'Found new groups to add to the FreeIPA server: {newline.join(map(str, new_ipa_groups))}')
        ipa_add_groups(ipaclient, new_ipa_groups)
        ipa_group_dict = ipa_search_groups_with_users(ad_connection, ad_users_dn, ipaclient)

        ipa_group_dict_formatted = pformat(ipa_group_dict)
        logging.info(f'AFTER ADD GROUPS: IPA groups and users: \n{ipa_group_dict_formatted}\n')

    # Удаление групп из FreeIPA
    if delete_ipa_groups:
        logging.info(f'These groups are not found on the AD and require removal: {newline.join(map(str, delete_ipa_groups))}')
        ipa_del_groups(ipaclient, delete_ipa_groups)
        ipa_group_dict = ipa_search_groups_with_users(ad_connection, ad_users_dn, ipaclient)

        ipa_group_dict_formatted = pformat(ipa_group_dict)
        logging.info(f'AFTER DEL GROUPS: IPA groups and users: \n{ipa_group_dict_formatted}\n')

#Проходим по всем группам и их пользователям и синхронизируем АД с Фриипой
    ipa_add_del_users_in_groups(ipaclient, ad_group_dict, ipa_group_dict)
    ipa_group_dict = ipa_search_groups_with_users(ad_connection, ad_users_dn, ipaclient)

    ipa_group_dict_formatted = pformat(ipa_group_dict)
    logging.info(f'\nCurrent status of groups and users on FreeIPA server after performed operations: \n{ipa_group_dict_formatted}\n')


# END - закрываем соединение с АД и FreeIPA
    ad_connection.unbind()
    ipaclient.logout()
