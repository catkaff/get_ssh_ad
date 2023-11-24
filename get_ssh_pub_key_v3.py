#!/bin/env python3
# -*- coding: utf-8 -*-
from ldap3 import Connection, Server, ALL, Tls, SUBTREE
import sys, logging, ssl, os
from dotenv import load_dotenv

# проверяет, можно ли записать в файл логов. Если нет, она настраивает логирование в stderr. Это предотвращает прерывание скрипта из-за ошибок доступа к файлу логов.
def setup_logging(script_log_file, script_log_level, log_format, log_datefmt, log_encoding):
    try:
        if os.access(script_log_file, os.W_OK):
            logging.basicConfig(filename=script_log_file, level=script_log_level, format=log_format, datefmt=log_datefmt, encoding=log_encoding)
        else:
            logging.basicConfig(level=script_log_level, format=log_format, datefmt=log_datefmt)
            logging.warning("Logging to file is not possible. Logging to stderr instead.")
    except Exception as e:
        logging.basicConfig(level=script_log_level, format=log_format, datefmt=log_datefmt)
        logging.warning(f"Error setting up file logging: {e}. Logging to stderr instead.")

def format_username(username: str, ad_domain: str, ipa_domain: str) -> str:
    if '@dserver.cat' in username:
        return username.replace(ad_domain,'')
    elif '@kaff.cat' in username:
        return username.replace(ipa_domain, '')
    else:
        return username

# Функция соединения с АД по защищенному шифрованному соединению по 636 порту с использованием корневого сертификата домена.
# AD connect
def ad_connect(ad_user, ad_user_password, ad_kd, adca):
    try:
        tlset = Tls(validate=ssl.CERT_OPTIONAL, version=ssl.PROTOCOL_TLSv1_2, ca_certs_file=adca)
        adserv03 = Server(ad_kd, port=636, use_ssl=True, get_info=ALL, tls=tlset)
        logging.info(adserv03)
        ad_connection = Connection([adserv03], ad_user, ad_user_password, read_only=False, lazy=False)
        ad_connection.open()
        ad_connection.bind()
        logging.info(f'==> AD_Connect_status: {ad_connection.result}')
        return ad_connection
    except Exception as e:
        logging.error(f'==> AD_ERROR: {e}')
        sys.exit(1)
#  END Connect

def get_user_ad_key(ad_connection, username: str):
    base_dn = 'dc=dserver,dc=cat'
    search_filter = f'(sAMAccountName={username})'

    #ad_connection.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=['distinguishedName'])
    ad_connection.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE,
                         attributes=['altSecurityIdentities'])

    if ad_connection.entries:
        user = ad_connection.entries[0]
        altSecurityIdentities = user.entry_attributes_as_dict['altSecurityIdentities']

        return altSecurityIdentities
    else:
        return None

def read_local_public_key(user: str):
    home_dir = f"/home/{user}"
    auth_keys_path = os.path.join(home_dir, ".ssh", "authorized_keys")

    if os.path.isfile(auth_keys_path):
        with open(auth_keys_path, 'r') as f:
            keys = f.readlines()
        return keys
    else:
        return None

if __name__ == '__main__':

    try:
        load_dotenv('get_ssh_key.conf')
    except Exception as e:
        logging.error(f"Произошла ошибка: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        logging.error(f"Произошла ошибка: {e}")
        sys.exit(1)

    ipaserver = os.getenv('ipa_server')
    ipaver_ssl = os.getenv('ipa_server_ca')
    ipausername = os.getenv('ipa_user_admin')
    ipapassword = os.getenv('ipa_user_admin_passwd')

    ipa_domain = os.getenv('ipa_domain')

    ad_groups_dn = os.getenv('ad_groups_dn')
    ad_users_dn = os.getenv('ad_users_dn')

    ad_kd = os.getenv('ad_server')
    adca = os.getenv('ad_ca_sert')
    ad_user = os.getenv('ad_user')
    ad_user_password = os.getenv('ad_user_password')

    ad_domain = os.getenv('ad_domain')

    script_log_file = os.getenv('script_log_file')
    script_log_level = os.getenv('script_log_level')
    log_format = os.getenv('log_format')
    log_datefmt = os.getenv('log_datefmt')
    log_encoding = os.getenv('log_encoding')

    # Получим числовое значение уровня логирования
    level = logging.getLevelName(script_log_level)
    # Настраиваем логгирование всех действий скрипта в файл
    #logging.basicConfig(filename=script_log_file, level=level, format=log_format, datefmt=log_datefmt)
    setup_logging(os.getenv('script_log_file'), logging.getLevelName(os.getenv('script_log_level')),
                 os.getenv('log_format'), os.getenv('log_datefmt'), os.getenv('log_encoding'))

    # define a Handler which writes INFO messages or higher to the sys.stderr
    # Здесь настройка вывода выхлопа информационных сообщений скрипта еще и в консоль помимо записи лога файла
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    # add the handler to the root logger
    logging.getLogger('').addHandler(console)

    # Соединяемся с АД согласно полученным кредам
    ad_connection = ad_connect(ad_user, ad_user_password, ad_kd, adca)

    if len(sys.argv) > 1:  # проверяем, есть ли аргументы командной строки
        formatted_username = format_username(sys.argv[1], ad_domain, ipa_domain)
        user_ad_key = get_user_ad_key(ad_connection, formatted_username)
        local_keys = read_local_public_key(formatted_username)
        if user_ad_key:  # проверка, что dn_user не пустой и не None
            print(''.join(user_ad_key))
        if local_keys:
            for key in local_keys:
                print(key, end="")

# END - закрываем соединение с АД и FreeIPA
    ad_connection.unbind()
